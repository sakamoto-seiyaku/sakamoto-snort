/* SPDX-License-Identifier: Apache-2.0 */
/* Root's private complete-message/return Adapter. Included beside the shared
 * graph's protected snapshot and FlowOwner helpers; no second policy runtime.
 * VPN reuses its owner transaction, policy, socket and observation machinery;
 * its local HEV session and existing TUN return replace Root raw delivery. */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vlib/file.h>
#include "product_root_dns_tcp_mark.h"

#define ROOT_DNS_REPLIES 128U
#define ROOT_DNS_WATCHES (PRODUCT_DNS_PROXY_SOCKETS + PRODUCT_ROOT_DNS_TCP_CLIENTS + 2U)
#define ROOT_DNS_TCP_BINDINGS 128U
typedef struct {
  product_dns_proxy_input_t input;
  uint64_t deadline, session;
  uint32_t syn_sequence, trusted_uid;
  uint8_t trusted_uid_known;
  uint8_t active;
} root_dns_tcp_binding_t;
typedef struct {
  product_adapter_obligation_t obligation;
  product_dns_observation_record_t record;
  u32 buffer;
  u16 tcp_message; /* 1-based VPN TCP frame; zero is the existing UDP path. */
  u8 state; /* 1 graph-owned; 2 completion done; VPN 3 awaits owner export after free */
} root_dns_reply_t;
typedef struct {
  product_dns_observation_record_t record;
  u64 session, token;
  u32 packets;
  u8 active, done, acknowledged, failure_delivery;
} vpn_dns_tcp_delivery_t;
typedef struct {
  int fd;
  uword file;
  u64 cookie;
} root_dns_watch_t;
typedef struct {
  u64 cookie, epoch;
  u32 context;
  u8 known;
} root_dns_binding_t;
typedef struct {
  vlib_main_t *vm;
  u64 generation, route_revision, network_revision, socket_sequence, reply_sequence;
  u64 retry_at, raw_idle, current_upstream_session, last_reply_token;
  u64 intercepted, reply_admitted, reply_rejected, kernel_accepted, write_failed;
  u64 return_policy_drop, returned, stale, raw_opened, raw_closed;
  u32 owner, replies, high_water_replies, last_error;
  u8 ready, stopping, profile;
  root_dns_reply_t *vpn_reply;
  vpn_dns_tcp_delivery_t vpn_tcp[128];
  u8 vpn_message[SAKAMOTO_PRODUCT_VPN_TUN_MTU];
  root_dns_binding_t vpn_bindings[PRODUCT_DNS_PROXY_SOCKETS], current_binding;
  int raw4, raw6;
  product_dns_proxy_route_t route;
  product_dns_proxy_t *proxy;
  product_root_dns_io_t *io;
  product_root_dns_tcp_io_t *tcp_io;
  root_dns_tcp_binding_t tcp_bindings[ROOT_DNS_TCP_BINDINGS];
  u64 tcp_admission_failed, tcp_identity_rejected;
  const product_l4_policy_view_t *event_view;
  u64 event_revision;
  root_dns_watch_t watches[ROOT_DNS_WATCHES];
  root_dns_reply_t reply[ROOT_DNS_REPLIES];
} root_dns_owner_t;
static root_dns_owner_t root_dns_owners[PRODUCT_GRAPH_WORKERS];
static u32 root_dns_owner_count;
extern vlib_node_registration_t product_root_dns_node;

static u64 root_dns_now (vlib_main_t *vm)
{ return (u64) (vlib_time_now (vm) * 1000000.0); }

static void root_dns_publish_ready (root_dns_owner_t *owner)
{
  product_root_dns_io_status_t io = product_root_dns_io_status (owner->io);
  /* A clean idle close preserves this route's ability to reopen. Pending or
   * failed authorization never inherits a previous socket's availability. */
  /* Android's current initial network is revision zero until platform capture
   * starts. Current-view equality is checked by root_dns_owner_current. */
  int prepared = !owner->stopping && owner->route_revision &&
    (!owner->route.enabled || (owner->proxy && owner->io && (owner->profile==2 || product_root_dns_tcp_io_status(owner->tcp_io).accepting) &&
      (io.udp_state == PRODUCT_ROOT_DNS_UDP_AUTHORIZED || io.udp_state == PRODUCT_ROOT_DNS_UDP_IDLE)));
  __atomic_store_n (&owner->ready, prepared, __ATOMIC_RELEASE);
}

static const char *root_dns_udp_state (const root_dns_owner_t *owner,
  const product_root_dns_io_status_t *io)
{
  if (owner->stopping) return "stopped";
  if (!owner->route.enabled) return "disabled";
  switch (io->udp_state) {
    case PRODUCT_ROOT_DNS_UDP_AUTHORIZING: return "authorizing";
    case PRODUCT_ROOT_DNS_UDP_AUTHORIZED: return "authorized";
    case PRODUCT_ROOT_DNS_UDP_IDLE: return "idle";
    case PRODUCT_ROOT_DNS_UDP_FAILED: return "failed";
    default: return "unavailable";
  }
}

static int root_dns_configuration (product_dns_proxy_route_t *route, u64 *revision)
{
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_policy_snapshot_t snapshot;
  product_policy_snapshot_acquire (graph, &snapshot);
  int valid = snapshot.bank->generation == graph->generation && snapshot.bank->dns_revision;
  if (valid) { *route = snapshot.bank->dns; *revision = snapshot.bank->dns_revision; }
  product_policy_snapshot_release (graph, &snapshot);
  return valid;
}

/* Use the same authoritative view for global availability and each CLI row.
 * Worker preparation can remain cached while a new route/network is published. */
static int root_dns_owner_current (const root_dns_owner_t *owner, u64 revision, u64 network)
{
  return __atomic_load_n (&owner->ready, __ATOMIC_ACQUIRE) &&
    owner->generation == product_packet_graph_main.generation &&
    __atomic_load_n (&owner->route_revision, __ATOMIC_ACQUIRE) == revision &&
    __atomic_load_n (&owner->network_revision, __ATOMIC_ACQUIRE) == network;
}

static u64 root_dns_other_bytes (root_dns_owner_t *owner)
{
  return sizeof (*owner) + sizeof (product_dns_owner_t) + sizeof (product_dns_tcp_owner_t) +
    product_packet_graph_main.dns_tcp[owner->owner].allocated_bytes + product_root_dns_io_reservation () +
    (owner->profile == 2 ? product_vpn_flow_stack_driver_dns_reservation (owner->owner) : 0) +
    (owner->profile==1 ? PRODUCT_ROOT_DNS_TCP_WORK_BYTES : 0) +
    ROOT_DNS_REPLIES * (sizeof (vlib_buffer_t) + vlib_buffer_get_default_data_size (owner->vm));
}

static u64 root_dns_tcp_other_bytes (unsigned owner)
{
  if (owner >= root_dns_owner_count) return 0;
  return sizeof (root_dns_owner_t) +
    (root_dns_owners[owner].profile==1 ? PRODUCT_ROOT_DNS_TCP_WORK_BYTES : 0) +
    (root_dns_owners[owner].profile == 2 ? product_vpn_flow_stack_driver_dns_reservation (owner) : 0) +
    ROOT_DNS_REPLIES *
    (sizeof (vlib_buffer_t) + vlib_buffer_get_default_data_size (root_dns_owners[owner].vm)) +
    (root_dns_owners[owner].proxy ? product_dns_proxy_resources (root_dns_owners[owner].proxy).owned_bytes +
      product_root_dns_io_reservation () : 0);
}

static void root_dns_close_raw (root_dns_owner_t *owner)
{
  if (owner->replies) return;
  if (owner->raw4 >= 0) { close (owner->raw4); owner->raw4 = -1; ++owner->raw_closed; }
  if (owner->raw6 >= 0) { close (owner->raw6); owner->raw6 = -1; ++owner->raw_closed; }
  owner->raw_idle = 0;
}

static int root_dns_raw (root_dns_owner_t *owner, unsigned family)
{
  int *fd = family == 4 ? &owner->raw4 : &owner->raw6;
  if (*fd >= 0) return 1;
  *fd = socket (family == 4 ? AF_INET : AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_RAW);
  if (*fd < 0) { owner->last_error = errno; return 0; }
  int enabled = 1;
  if (setsockopt (*fd, SOL_SOCKET, SO_BINDTODEVICE, "lo", 3) ||
      setsockopt (*fd, family == 4 ? IPPROTO_IP : IPPROTO_IPV6,
        family == 4 ? IP_HDRINCL : IPV6_HDRINCL, &enabled, sizeof (enabled)))
    {
      owner->last_error = errno; close (*fd); *fd = -1; return 0;
    }
  ++owner->raw_opened;
  owner->raw_idle = root_dns_now (owner->vm) + PRODUCT_ROOT_DNS_IDLE_US;
  return 1;
}

static clib_error_t *root_dns_file_read (clib_file_t *);
static clib_error_t *root_dns_file_write (clib_file_t *);
static clib_error_t *root_dns_file_error (clib_file_t *);

static int root_dns_watch (void *opaque, int fd, unsigned events, uint64_t cookie)
{
  root_dns_owner_t *owner = opaque;
  root_dns_watch_t *watch = NULL;
  for (unsigned i = 0; i < ROOT_DNS_WATCHES; ++i)
    if (owner->watches[i].fd == fd) { watch = &owner->watches[i]; break; }
  if (!events)
    {
      for (unsigned i = 0; i < PRODUCT_DNS_PROXY_SOCKETS; ++i)
        if (owner->vpn_bindings[i].cookie == cookie)
          memset (&owner->vpn_bindings[i], 0, sizeof (owner->vpn_bindings[i]));
      if (watch)
        {
          clib_file_del_by_index (&file_main, watch->file);
          *watch = (root_dns_watch_t) {.fd = -1, .file = ~0};
        }
      return 1;
    }
  if (!watch)
    for (unsigned i = 0; i < ROOT_DNS_WATCHES; ++i)
      if (owner->watches[i].fd < 0) { watch = &owner->watches[i]; break; }
  if (!watch) return 0;
  if (watch->fd >= 0)
    {
      clib_file_set_data_available_to_write (&file_main, watch->file, !!(events & PRODUCT_ROOT_DNS_WRITE));
      return 1;
    }
  clib_file_t file = {
    .file_descriptor = fd, .polling_thread_index = vlib_get_worker_thread_index (owner->owner),
    /* The socket sequence survives generation changes. A stale readiness
     * event cannot acquire a reused fd's identity, and generation stays u64. */
    .private_data = ((u64) owner->owner << 42) | cookie,
    .read_function = root_dns_file_read, .write_function = root_dns_file_write,
    .error_function = root_dns_file_error, .dont_close = 1,
    .flags = ((events & PRODUCT_ROOT_DNS_WRITE) ? UNIX_FILE_DATA_AVAILABLE_TO_WRITE : 0) |
      ((events & PRODUCT_ROOT_DNS_TCP_EDGE) ? UNIX_FILE_EVENT_EDGE_TRIGGERED : 0),
    .description = format (0, "product-root-dns-%u-%llu%c", owner->owner,
      (unsigned long long) cookie, 0),
  };
  watch->fd = fd; watch->cookie = cookie;
  watch->file = clib_file_add (&file_main, &file);
  if(watch->file == ~0U) { *watch=(root_dns_watch_t){.fd=-1,.file=~0}; return 0; }
  return 1;
}

static int root_dns_send (void *opaque, const product_dns_proxy_key_t *key, unsigned transport,
  const uint8_t *wire, size_t length, uint64_t deadline)
{
  root_dns_owner_t *owner = opaque;
  int result = product_root_dns_io_send (owner->io, key, transport, wire, length, deadline, root_dns_now (owner->vm));
  root_dns_publish_ready (owner);
  return result;
}
static void root_dns_cancel (void *opaque, const product_dns_proxy_key_t *key)
{ root_dns_owner_t *owner = opaque; product_root_dns_io_cancel (owner->io, key); }

static int root_dns_policy_acquire (void *opaque, const product_dns_proxy_input_t *input,
  product_dns_proxy_snapshot_t *out)
{
  root_dns_owner_t *owner = opaque;
  product_packet_graph_main_t *graph = &product_packet_graph_main;
  product_policy_snapshot_t *snapshot = malloc (sizeof (*snapshot));
  if (!snapshot) return 0;
  product_policy_snapshot_acquire (graph, snapshot);
  owner->event_view = &snapshot->bank->view; owner->event_revision = snapshot->identity.revision;
  out->borrow = snapshot; out->view = &snapshot->bank->view;
  out->identity = (product_dns_policy_identity_t) {snapshot->identity.generation,
    snapshot->identity.revision, snapshot->identity.snapshot_hash, 0};
  out->network_revision = product_network_snapshot_current ()->revision;
  out->route_revision = snapshot->bank->dns_revision;
  out->context = input->context;
  out->context.domains = snapshot->bank->domains;
  out->context.domains_available = snapshot->bank->generation == graph->generation;
  product_l4_policy_packet_t *packet = &out->context.packet;
  memcpy (packet->source_address, input->context.packet.destination_address, 16);
  memcpy (packet->destination_address, input->context.packet.source_address, 16);
  packet->source_port = input->context.packet.destination_port;
  packet->destination_port = input->context.packet.source_port;
  packet->direction = PRODUCT_PACKET_DIRECTION_INPUT;
  if (owner->profile == 2 && owner->current_binding.known) {
    packet->network_context_id = owner->current_binding.context;
    packet->network_context_known = 1;
  }
  packet->ct_state_known = packet->flow_direction_known = packet->protocol_set_known = 0;
  packet->sni_result = 0;
  const product_flow_entry_t *entry = input->slot == UINT32_MAX ? NULL :
    product_flow_runtime_entry (graph->flow_pools[owner->owner], input->slot);
  if (entry && entry->linked && entry->policy_generation == input->identity.generation &&
      entry->incarnation == input->identity.incarnation)
    {
      if (packet->protocol == 17) {
      product_udp_state_t state = entry->protocol_state.udp;
      product_packet_facts_t facts = {.l3_status = PRODUCT_PACKET_L3_COMPLETE,
        .l4_status = PRODUCT_PACKET_L4_COMPLETE, .ip_family = packet->family, .protocol = 17};
      product_flow_direction_t direction = input->context.packet.flow_direction == PRODUCT_FLOW_DIRECTION_ORIG
        ? PRODUCT_FLOW_DIRECTION_REPLY : PRODUCT_FLOW_DIRECTION_ORIG;
      product_tracker_result_t tracker = product_udp_update (&state, &facts, direction);
      packet->ct_state = tracker.facts.state; packet->ct_state_known = 1;
      packet->flow_direction = tracker.facts.direction; packet->flow_direction_known = 1;
      } else {
        /* The message retains the last actual owner-observed TCP facts; do
         * not reinterpret TCP storage as a UDP tracker or synthesize a packet. */
        packet->ct_state = input->context.packet.ct_state;
        packet->ct_state_known = input->context.packet.ct_state_known;
        packet->flow_direction = input->context.packet.flow_direction == PRODUCT_FLOW_DIRECTION_ORIG
          ? PRODUCT_FLOW_DIRECTION_REPLY : PRODUCT_FLOW_DIRECTION_ORIG;
        packet->flow_direction_known = input->context.packet.flow_direction_known;
      }
      packet->protocol_set = entry->lpi.protocols; packet->protocol_set_known = entry->lpi.available;
      packet->sni_result = entry->sni.result;
    }
  return 1;
}
static void root_dns_policy_release (void *opaque, product_dns_proxy_snapshot_t *snapshot)
{
  root_dns_owner_t *owner = opaque;
  product_policy_snapshot_release (&product_packet_graph_main, snapshot->borrow);
  free (snapshot->borrow); snapshot->borrow = NULL;
  owner->event_view = NULL; owner->event_revision = 0;
}

static product_dns_observation_record_t root_dns_record (root_dns_owner_t *owner,
  const product_dns_proxy_event_t *event)
{
  const product_dns_query_t *query = &event->query;
  const product_l4_policy_packet_t *packet = &event->input.context.packet;
  int matched = event->match.evaluation == PRODUCT_L4_POLICY_EVALUATION_MATCH;
  u8 actual = matched ? event->match.actual_action : event->stage == 3 ? 0 : PRODUCT_L4_POLICY_ACTION_ALLOW;
  product_dns_observation_record_t record = {
    .generation = owner->generation, .token = event->input.token,
    .incarnation = event->input.identity.incarnation, .slot = event->input.slot,
    .policy_generation = event->policy.generation, .policy_revision = event->policy.revision,
    .policy_hash = event->policy.hash, .winner = matched ? event->match.rule_id : 0,
    .uid = packet->uid_known ? packet->uid : UINT32_MAX,
    .network = packet->network_context_known ? packet->network_context_id : UINT32_MAX,
    .ifindex = packet->ifindex_known ? packet->ifindex : 0,
    .codec_peak_bytes = query->codec_peak_bytes, .id = query->id, .query_flags = query->flags,
    .qtype = query->qtype, .qclass = query->qclass,
    .source_port = packet->source_port, .resolver_port = packet->destination_port,
    .name_length = query->name_length, .family = packet->family, .protocol = packet->protocol,
    .direction = event->stage == 2 ? 1 : 3,
    .availability = (packet->uid_known ? PRODUCT_PLATFORM_UID_KNOWN : 0) |
      (packet->network_context_known ? PRODUCT_PLATFORM_CONTEXT_KNOWN : 0) |
      (packet->ifindex_known ? PRODUCT_PLATFORM_IFINDEX_KNOWN : 0) |
      (query->caller == PRODUCT_DNS_CALLER_PLATFORM_APP ? PRODUCT_PLATFORM_DNS_APP_RELIABLE : 0),
    .caller = query->caller, .coverage = query->coverage,
    .declared_action = matched ? event->match.action : actual, .actual_action = actual,
    .mode = matched ? event->match.mode : 0, .domain_available = query->packet.domain_available,
    .stage = event->stage, .delivery = event->delivery == 1 ? (packet->protocol==6 ? PRODUCT_DNS_DELIVERY_SOCKET_QUEUED : PRODUCT_DNS_DELIVERY_GRAPH_ACCEPTED) :
      event->delivery == 2 ? PRODUCT_DNS_DELIVERY_ADMISSION_FAILED : 0,
    .network_revision = event->key.network_revision, .query_incarnation = event->key.incarnation,
    .query_token = event->stage == 1 ? 0 : event->input.token,
    .query_policy_generation = event->stage == 1 ? 0 : event->query_policy.generation,
    .query_policy_revision = event->stage == 1 ? 0 : event->query_policy.revision,
    .query_policy_hash = event->stage == 1 ? 0 : event->query_policy.hash,
    .query_winner = event->stage == 1 ? 0 : event->query_policy.winner,
    .domain_lists = query->packet.domain_lists, .adapter_profile = owner->profile,
    .packet_uid = event->input.capture_present ? event->input.capture_uid : packet->uid_known ? packet->uid : UINT32_MAX,
    .route_revision = event->key.route_revision, .request_attempt = event->key.attempt,
    .upstream_session = event->cached ? 0 : owner->current_upstream_session,
    .transport_session = event->input.identity.transport_session,
    .underlay_epoch = owner->profile == 2 ? owner->current_binding.epoch : event->input.identity.underlay_epoch,
    .upstream_port = event->route.port, .upstream_family = event->route.family,
    .upstream_transport = event->transport, .proxy_result = event->result,
    .reply_rcode = event->rcode, .client_udp_capacity = query->udp_capacity,
    .reply_capacity = event->client_capacity, .output_bytes = event->output_bytes,
    .proxy_flags = PRODUCT_DNS_PROXY_RECORD | (event->truncated ? PRODUCT_DNS_PROXY_TRUNCATED : 0) |
      (event->response ? (event->cached ? PRODUCT_DNS_PROXY_CACHE_ANSWER : PRODUCT_DNS_PROXY_UPSTREAM_ANSWER) : 0),
    .return_token = event->delivery == 1 && event->output_bytes ? owner->last_reply_token : 0,
  };
  record.packet_availability = event->input.capture_present ? event->input.capture_availability : record.availability;
  if (packet->protocol == 6) record.message_sequence = event->input.token;
  memcpy (record.source_address, packet->source_address, 16);
  memcpy (record.resolver_address, packet->destination_address, 16);
  memcpy (record.upstream_address, event->route.address, 16);
  memcpy (record.name, query->name, sizeof (record.name));
  if (matched && owner->event_view && owner->event_revision == event->policy.revision &&
      event->match.rule_index < owner->event_view->rule_count &&
      owner->event_view->rules[event->match.rule_index].source.rule_id == event->match.rule_id)
    memcpy (record.rule_name, owner->event_view->rules[event->match.rule_index].source.name, sizeof (record.rule_name));
  if (event->response)
    {
      record.query_flags = event->response->question.flags;
      record.rcode = event->response->rcode; record.correlation = event->response->correlation;
      record.matched_requests = 1; record.candidate_count = event->response->name_count;
      record.chain_status = event->response->chain_status;
      if (event->response->name_count)
        {
          record.domain_available = event->response->names[0].available;
          record.domain_lists = event->response->names[0].lists;
        }
    }
  return record;
}

static void root_dns_observe (void *opaque, const product_dns_proxy_event_t *event)
{
  root_dns_owner_t *owner = opaque;
  product_dns_observation_record_t record = root_dns_record (owner, event);
  unsigned count = event->response && event->response->name_count ? event->response->name_count : 1;
  for (unsigned i = 0; i < count; ++i)
    {
      if (event->response && event->response->name_count)
        {
          const product_dns_name_t *name = &event->response->names[i];
          record.name_index = i; record.name_source = name->source;
          record.domain_available = name->available; record.domain_lists = name->lists;
          record.name_length = name->length;
          memset (record.name, 0, sizeof (record.name)); memcpy (record.name, name->name, name->length);
        }
      product_observation_dns (owner->vm, &record);
    }
}

static u32 root_dns_sum (const u8 *data, size_t length, u32 sum)
{
  for (size_t i = 0; i + 1 < length; i += 2) sum += ((u32) data[i] << 8) | data[i + 1];
  if (length & 1) sum += (u32) data[length - 1] << 8;
  return sum;
}
static u16 root_dns_checksum (u32 sum)
{ while (sum >> 16) sum = (sum & 65535) + (sum >> 16); return (u16) ~sum; }
static void root_dns_put16 (u8 *wire, u16 value)
{ wire[0] = value >> 8; wire[1] = value; }

static size_t root_dns_packet (const product_l4_policy_packet_t *original,
  const u8 *message, size_t length, u8 *wire, size_t capacity)
{
  unsigned ip = original->family == 4 ? 20 : original->family == 6 ? 40 : 0;
  if (!ip || original->protocol != 17 || original->destination_port != 53 ||
      !original->source_port || !message || length > PRODUCT_DNS_PROXY_REPLY_BYTES ||
      capacity < ip + 8 + length) return 0;
  memset (wire, 0, ip + 8); memcpy (wire + ip + 8, message, length);
  u8 *udp = wire + ip; unsigned udp_length = length + 8;
  root_dns_put16 (udp, original->destination_port); root_dns_put16 (udp + 2, original->source_port);
  root_dns_put16 (udp + 4, udp_length);
  u32 sum;
  if (ip == 20)
    {
      wire[0] = 0x45; root_dns_put16 (wire + 2, ip + udp_length); wire[6] = 0x40;
      wire[8] = 1; wire[9] = 17;
      memcpy (wire + 12, original->destination_address, 4); memcpy (wire + 16, original->source_address, 4);
      root_dns_put16 (wire + 10, root_dns_checksum (root_dns_sum (wire, 20, 0)));
      sum = root_dns_sum (wire + 12, 8, 17 + udp_length);
    }
  else
    {
      wire[0] = 0x60; root_dns_put16 (wire + 4, udp_length); wire[6] = 17; wire[7] = 1;
      memcpy (wire + 8, original->destination_address, 16); memcpy (wire + 24, original->source_address, 16);
      sum = root_dns_sum (wire + 8, 32, 17 + udp_length);
    }
  u16 checksum = root_dns_checksum (root_dns_sum (udp, udp_length, sum));
  root_dns_put16 (udp + 6, checksum ? checksum : UINT16_MAX);
  /* Loopback binding plus TTL/hop-limit1 confines an obsolete address's
   * unsuccessful return to this host; no forwarded DNS answer can escape. */
  return ip + udp_length;
}

static void root_dns_return_fence (root_dns_owner_t *owner, const product_dns_observation_record_t *record)
{
  product_dns_query_t query = {.id = record->id, .qtype = record->qtype,
    .qclass = record->qclass, .name_length = record->name_length, .coverage = record->coverage,
    .packet = {.family = record->family, .protocol = 17, .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
      .source_port = record->source_port, .destination_port = record->resolver_port}};
  memcpy (query.packet.source_address, record->source_address, 16);
  memcpy (query.packet.destination_address, record->resolver_address, 16);
  memcpy (query.name, record->name, sizeof (query.name));
  product_dns_generated_return (&product_packet_graph_main.dns_requests[owner->owner], &query, root_dns_now (owner->vm));
}

static int root_dns_reply (void *opaque, const product_dns_proxy_event_t *event,
  const uint8_t *message, size_t length)
{
  root_dns_owner_t *owner = opaque; owner->last_reply_token = 0;
  if (owner->stopping || !product_packet_graph_accepting ()) return 0;
  if (owner->profile == 1 && event->input.context.packet.protocol == 6) {
    unsigned slot;
    for (slot=0; slot<ROOT_DNS_REPLIES && owner->reply[slot].state; ++slot) ;
    if (slot==ROOT_DNS_REPLIES) { ++owner->reply_rejected; return 0; }
    root_dns_reply_t *reply=&owner->reply[slot]; memset(reply,0,sizeof(*reply));
    reply->record=root_dns_record(owner,event);
    reply->record.query_token=event->input.token;
    reply->record.output_bytes=length;
    reply->record.query_flags=length>=4 ? ((u16)message[2]<<8)|message[3] : 0;
    reply->record.query_policy_generation=event->query_policy.generation;
    reply->record.query_policy_revision=event->query_policy.revision;
    reply->record.query_policy_hash=event->query_policy.hash;
    reply->record.query_winner=event->query_policy.winner;
    reply->record.return_token=event->input.token;
    /* Native socket write and subsequent kernel/NFQ INPUT policy are separate
     * facts. No VPP-generated-packet or return-policy identity is fabricated. */
    reply->record.return_packet_uid=geteuid();
    reply->state=4; ++owner->replies;
    if (!product_root_dns_tcp_io_reply(owner->tcp_io,event->input.identity.transport_session,
          event->input.token,message,length,root_dns_now(owner->vm))) {
      if (reply->state==4) { reply->state=0; --owner->replies; }
      ++owner->reply_rejected; return 0;
    }
    owner->last_reply_token=event->input.token; ++owner->reply_admitted;
    if(owner->replies>owner->high_water_replies)owner->high_water_replies=owner->replies;
    return 1;
  }
  if (owner->profile==2 && event->input.context.packet.protocol==6) {
    unsigned slot;
    for(slot=0;slot<128 && owner->vpn_tcp[slot].active;++slot) ;
    if(slot==128){++owner->reply_rejected;return 0;}
    vpn_dns_tcp_delivery_t *delivery=&owner->vpn_tcp[slot];
    *delivery=(vpn_dns_tcp_delivery_t){.record=root_dns_record(owner,event),
      .session=event->input.identity.transport_session,.token=event->input.token,.active=1};
    delivery->record.query_token=event->input.token;
    delivery->record.query_flags=length>=4?((u16)message[2]<<8)|message[3]:0;
    delivery->record.output_bytes=length;
    delivery->record.query_policy_generation=event->query_policy.generation;
    delivery->record.query_policy_revision=event->query_policy.revision;
    delivery->record.query_policy_hash=event->query_policy.hash;
    delivery->record.query_winner=event->query_policy.winner;
    delivery->record.return_provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
    delivery->record.return_token=event->input.token;
    delivery->record.return_packet_uid=UINT32_MAX;
    product_vpn_flow_stack_transport_t binding={.underlay_epoch=owner->current_binding.epoch,
      .network_context=owner->current_binding.context,.context_known=owner->current_binding.known};
    if(product_vpn_flow_stack_driver_tcp_reply(owner->vm,owner->generation,delivery->session,
         delivery->token,message,length,&binding)) {
      memset(delivery,0,sizeof(*delivery));++owner->reply_rejected;return 0;
    }
    owner->last_reply_token=event->input.token;++owner->reply_admitted;return 1;
  }
  if (owner->profile == 2) {
    unsigned slot;
    for (slot = 0; slot < ROOT_DNS_REPLIES &&
      __atomic_load_n (&owner->reply[slot].state, __ATOMIC_ACQUIRE); ++slot) ;
    if (slot == ROOT_DNS_REPLIES) { ++owner->reply_rejected; return 0; }
    root_dns_reply_t *reply = &owner->reply[slot];
    memset (reply, 0, sizeof (*reply));
    reply->record = root_dns_record (owner, event);
    reply->record.output_bytes = length;
    reply->record.query_token = event->input.token;
    reply->record.query_flags = ((u16) message[2] << 8) | message[3];
    reply->record.query_policy_generation = event->query_policy.generation;
    reply->record.query_policy_revision = event->query_policy.revision;
    reply->record.query_policy_hash = event->query_policy.hash;
    reply->record.query_winner = event->query_policy.winner;
    reply->record.return_provenance = PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
    reply->record.return_packet_uid = event->input.context.packet.uid_known
      ? event->input.context.packet.uid : UINT32_MAX;
    __atomic_add_fetch (&owner->replies, 1, __ATOMIC_RELAXED);
    if (owner->replies > owner->high_water_replies) owner->high_water_replies = owner->replies;
    owner->vpn_reply = reply;
    product_vpn_flow_stack_transport_t binding = {
      .underlay_epoch = owner->current_binding.epoch, .network_context = owner->current_binding.context,
      .context_known = owner->current_binding.known};
    int result = product_vpn_flow_stack_driver_local_reply_context (owner->vm, owner->generation,
      event->input.identity.transport_session, message, length, &binding);
    owner->vpn_reply = NULL;
    if (result || !reply->state) {
      __atomic_store_n (&reply->state, 0, __ATOMIC_RELEASE);
      __atomic_fetch_sub (&owner->replies, 1, __ATOMIC_RELAXED);
      owner->last_reply_token = 0; ++owner->reply_rejected; return 0;
    }
    ++owner->reply_admitted; return 1;
  }
  unsigned slot;
  for (slot = 0; slot < ROOT_DNS_REPLIES && __atomic_load_n (&owner->reply[slot].state, __ATOMIC_ACQUIRE); ++slot) ;
  if (slot == ROOT_DNS_REPLIES || owner->reply_sequence == UINT64_MAX ||
      !root_dns_raw (owner, event->input.context.packet.family))
    { ++owner->reply_rejected; return 0; }
  u32 bi;
  if (vlib_buffer_alloc (owner->vm, &bi, 1) != 1) { ++owner->reply_rejected; return 0; }
  vlib_buffer_t *buffer = vlib_get_buffer (owner->vm, bi);
  size_t packet = root_dns_packet (&event->input.context.packet, message, length,
    vlib_buffer_get_current (buffer), vlib_buffer_get_default_data_size (owner->vm));
  if (!packet) { vlib_buffer_free (owner->vm, &bi, 1); ++owner->reply_rejected; return 0; }
  buffer->current_length = packet;
  root_dns_reply_t *reply = &owner->reply[slot];
  reply->obligation = (product_adapter_obligation_t) {
    .token = ++owner->reply_sequence, .queue_generation = owner->generation,
    .packet_id = slot + 1, .origin_lane = owner->owner, .origin_worker = owner->owner,
    .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_DNS_REPLY,
  };
  reply->buffer = bi; reply->state = 1; ++owner->replies;
  if (owner->replies > owner->high_water_replies) owner->high_water_replies = owner->replies;
  owner->last_reply_token = reply->obligation.token;
  reply->record = root_dns_record (owner, event);
  reply->record.output_bytes = length; reply->record.return_token = reply->obligation.token;
  reply->record.query_flags = ((u16) message[2] << 8) | message[3];
  reply->record.query_token = event->input.token;
  reply->record.query_policy_generation = event->query_policy.generation;
  reply->record.query_policy_revision = event->query_policy.revision;
  reply->record.query_policy_hash = event->query_policy.hash;
  reply->record.query_winner = event->query_policy.winner;
  reply->record.return_provenance = PRODUCT_PACKET_PROVENANCE_ROOT_DNS_RETURN;
  reply->record.return_packet_uid = geteuid ();
  root_dns_return_fence (owner, &reply->record);
  const product_l4_policy_packet_t *packet_facts = &event->input.context.packet;
  product_platform_packet_facts_t platform = {
    .uid = packet_facts->uid_known ? packet_facts->uid : UINT32_MAX,
    .linux_ifindex = packet_facts->ifindex, .network_context_id = packet_facts->network_context_id,
    .availability = (packet_facts->uid_known ? PRODUCT_PLATFORM_UID_KNOWN : 0) |
      (packet_facts->ifindex_known ? PRODUCT_PLATFORM_IFINDEX_KNOWN : 0) |
      (packet_facts->network_context_known ? PRODUCT_PLATFORM_CONTEXT_KNOWN : 0),
    .direction = PRODUCT_PACKET_DIRECTION_INPUT, .provenance = PRODUCT_PACKET_PROVENANCE_ROOT_DNS_RETURN,
  };
  if (!product_packet_graph_submit_external (owner->vm, bi, &platform, &reply->obligation))
    {
      reply->state = 0; --owner->replies; ++owner->reply_rejected; owner->last_reply_token = 0;
      vlib_buffer_free (owner->vm, &bi, 1); return 0;
    }
  ++owner->reply_admitted;
  return 1;
}

static void root_dns_io_answer (void *opaque, const product_dns_proxy_key_t *key, unsigned transport,
  const uint8_t *wire, size_t length, uint64_t now)
{ root_dns_owner_t *owner = opaque; product_dns_proxy_answer (owner->proxy, key, transport, wire, length, now); }
static void root_dns_io_failed (void *opaque, const product_dns_proxy_key_t *key, uint64_t now)
{ root_dns_owner_t *owner = opaque; product_dns_proxy_fail (owner->proxy, key, now); }
static const product_dns_proxy_callbacks_t root_dns_proxy_callbacks = {
  .send = root_dns_send, .cancel = root_dns_cancel, .reply = root_dns_reply,
  .acquire = root_dns_policy_acquire, .release = root_dns_policy_release, .observe = root_dns_observe,
};

static int root_dns_authorize (void *opaque, int fd, uint64_t cookie)
{
  root_dns_owner_t *owner = opaque;
  unsigned slot;
  for (slot = 0; slot < PRODUCT_DNS_PROXY_SOCKETS && owner->vpn_bindings[slot].cookie; ++slot) ;
  if (slot == PRODUCT_DNS_PROXY_SOCKETS) return -1;
  if (product_vpn_flow_stack_driver_dns_authorize (owner->vm, owner->generation, cookie, fd)) return -1;
  owner->vpn_bindings[slot].cookie = cookie; return 0;
}

static int root_dns_tcp_accepted(void *opaque,u64 session,const product_root_dns_tcp_endpoint_t *endpoint)
{
  root_dns_owner_t *owner=opaque; u64 now=root_dns_now(owner->vm);
  if(owner->stopping || !endpoint->saved_syn || endpoint->resolver_port!=53)return 0;
  root_dns_tcp_binding_t *found=NULL;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i) {
    root_dns_tcp_binding_t *binding=&owner->tcp_bindings[i];
    const product_l4_policy_packet_t *packet=&binding->input.context.packet;
    if(!binding->active || binding->session || binding->deadline<=now ||
        binding->input.identity.generation!=owner->generation ||
        binding->input.identity.network_revision!=owner->network_revision ||
        binding->input.route_revision!=owner->route_revision ||
        binding->syn_sequence!=endpoint->syn_sequence || packet->family!=endpoint->family ||
        packet->source_port!=endpoint->source_port || packet->destination_port!=endpoint->resolver_port ||
        memcmp(packet->source_address,endpoint->source_address,16) ||
        memcmp(packet->destination_address,endpoint->resolver_address,16))continue;
    if(found) { ++owner->tcp_identity_rejected; return 0; }
    found=binding;
  }
  if(!found) { ++owner->tcp_identity_rejected; return 0; }
  found->session=session; found->input.identity.transport_session=session;
  found->deadline=UINT64_MAX; return 1;
}
static void root_dns_tcp_query(void *opaque,u64 session,u64 token,const u8 *wire,size_t length,u64 now)
{
  root_dns_owner_t *owner=opaque; root_dns_tcp_binding_t *binding=NULL;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i)
    if(owner->tcp_bindings[i].active && owner->tcp_bindings[i].session==session)
      { binding=&owner->tcp_bindings[i]; break; }
  if(!binding || !owner->proxy || owner->stopping)return;
  product_dns_proxy_input_t input=binding->input;
  input.token=token; input.identity.now_us=now;
  input.identity.network_revision=owner->network_revision;input.route_revision=owner->route_revision;
  product_policy_snapshot_t snapshot;
  product_policy_snapshot_acquire(&product_packet_graph_main,&snapshot);
  product_dns_proxy_snapshot_t current={.context=input.context,.view=&snapshot.bank->view,
    .identity={snapshot.identity.generation,snapshot.identity.revision,snapshot.identity.snapshot_hash,0},
    .network_revision=product_network_snapshot_current()->revision,.route_revision=snapshot.bank->dns_revision};
  current.context.domains=snapshot.bank->domains;
  current.context.domains_available=snapshot.bank->generation==owner->generation;
  owner->event_view=current.view; owner->event_revision=current.identity.revision;
  if(current.network_revision==input.identity.network_revision && current.route_revision==input.route_revision && snapshot.bank->dns.enabled)
    product_dns_proxy_submit(owner->proxy,&input,wire,length,&current);
  else product_dns_proxy_unavailable(&input,wire,length,&current,&owner->route,
    &root_dns_proxy_callbacks,owner,PRODUCT_DNS_PROXY_VIEW_CHANGED);
  owner->event_view=NULL; owner->event_revision=0;
  product_policy_snapshot_release(&product_packet_graph_main,&snapshot);
}
static void root_dns_tcp_delivered(void *opaque,u64 token,int success)
{
  root_dns_owner_t *owner=opaque;
  for(unsigned i=0;i<ROOT_DNS_REPLIES;++i) {
    root_dns_reply_t *reply=&owner->reply[i];
    if(reply->state!=4 || reply->record.token!=token)continue;
    reply->record.stage=4; reply->record.direction=reply->record.packet_direction=1;
    reply->record.delivery=success?PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED:PRODUCT_DNS_DELIVERY_WRITE_FAILED;
    product_observation_dns(owner->vm,&reply->record);
    reply->state=0; --owner->replies; ++owner->returned;
    if(success)++owner->kernel_accepted;else ++owner->write_failed;
    return;
  }
}
static void root_dns_tcp_ended(void *opaque,u64 session,u64 now)
{
  root_dns_owner_t *owner=opaque;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i)
    if(owner->tcp_bindings[i].active && owner->tcp_bindings[i].session==session)
      memset(&owner->tcp_bindings[i],0,sizeof(owner->tcp_bindings[i]));
  product_dns_proxy_session_end(owner->proxy,owner->generation,session,now);
}
static const product_root_dns_tcp_callbacks_t root_dns_tcp_callbacks={
  .watch=root_dns_watch,.accepted=root_dns_tcp_accepted,.query=root_dns_tcp_query,
  .delivered=root_dns_tcp_delivered,.ended=root_dns_tcp_ended,
};

static void root_dns_sync (root_dns_owner_t *owner, u64 now)
{
  if (owner->stopping || !product_packet_graph_enabled ()) return;
  if (owner->profile == 2 && !product_vpn_flow_stack_driver_ready ()) return;
  product_dns_proxy_route_t route; u64 revision;
  if (!root_dns_configuration (&route, &revision)) return;
  u64 network = product_network_snapshot_current ()->revision;
  int changed = owner->route_revision != revision || owner->network_revision != network;
  if (!changed && (owner->proxy || !route.enabled)) {
    if(owner->profile==1 && route.enabled && !owner->tcp_io)
      owner->tcp_io=product_root_dns_tcp_io_open(owner->generation,
        PRODUCT_ROOT_DNS_TCP_LISTEN_BASE+owner->owner,&owner->socket_sequence,
        &root_dns_tcp_callbacks,owner,now);
    if(owner->profile==1 && route.enabled && owner->tcp_io &&
        !product_root_dns_tcp_io_status(owner->tcp_io).accepting)
      product_root_dns_tcp_io_resume(owner->tcp_io,now);
    root_dns_publish_ready (owner);return;
  }
  if (!changed && owner->retry_at > now) return;
  __atomic_store_n (&owner->ready, 0, __ATOMIC_RELEASE);
  if (owner->proxy)
    {
      product_dns_proxy_advance (owner->proxy, now, network, revision);
      product_dns_proxy_close (owner->proxy); owner->proxy = NULL;
    }
  if(!route.enabled)product_root_dns_tcp_io_quiesce(owner->tcp_io,now);
  product_root_dns_io_close (owner->io); owner->io = NULL;
  owner->route = route;
  __atomic_store_n (&owner->route_revision, revision, __ATOMIC_RELEASE);
  __atomic_store_n (&owner->network_revision, network, __ATOMIC_RELEASE);
  owner->retry_at = 0;
  if (!route.enabled)
    { root_dns_close_raw (owner); root_dns_publish_ready (owner); return; }
  const product_root_dns_io_callbacks_t io_callbacks = {
    .watch = root_dns_watch, .answer = root_dns_io_answer, .failed = root_dns_io_failed,
    .authorize = owner->profile == 2 ? root_dns_authorize : NULL,
  };
  if (owner->profile == 2 || (root_dns_raw (owner, 4) && root_dns_raw (owner, 6)))
    owner->io = product_root_dns_io_open (owner->generation, &route, owner->profile == 2 ? 0 : PRODUCT_ROOT_DNS_SOCKET_MARK,
      &owner->socket_sequence, &io_callbacks, owner, now);
  if (owner->io) owner->proxy = product_dns_proxy_open (owner->generation, &route, &root_dns_proxy_callbacks, owner);
  if(owner->proxy && owner->profile==1 && !owner->tcp_io)
    owner->tcp_io=product_root_dns_tcp_io_open(owner->generation,
      PRODUCT_ROOT_DNS_TCP_LISTEN_BASE+owner->owner,&owner->socket_sequence,
      &root_dns_tcp_callbacks,owner,now);
  if(owner->profile==1 && owner->tcp_io && !product_root_dns_tcp_io_status(owner->tcp_io).accepting)
    product_root_dns_tcp_io_resume(owner->tcp_io,now);
  if (!owner->proxy || (owner->profile==1 && !owner->tcp_io))
    {
      owner->last_error = errno; product_dns_proxy_close(owner->proxy); owner->proxy=NULL; product_root_dns_io_close (owner->io); owner->io = NULL;
      root_dns_close_raw (owner); owner->retry_at = now + UINT64_C(5000000); return;
    }
  product_dns_proxy_other_bytes (owner->proxy, root_dns_other_bytes (owner));
  root_dns_publish_ready (owner);
}

static clib_error_t *root_dns_file_dispatch (clib_file_t *file, unsigned events)
{
  u64 identity = file->private_data;
  unsigned index = (identity >> 42) & 63;
  u64 cookie = identity & ((UINT64_C(1) << 42) - 1);
  int fd = file->file_descriptor;
  if (index >= root_dns_owner_count) return NULL;
  root_dns_owner_t *owner = &root_dns_owners[index];
  vlib_main_t *vm = vlib_get_main ();
  if (vm->thread_index != vlib_get_worker_thread_index (index) ||
      vm->thread_index != vlib_get_thread_index ()) { ++owner->stale; return NULL; }
  u64 now = root_dns_now (vm); root_dns_sync (owner, now);
  if (owner->stopping) return NULL;
  if(product_root_dns_tcp_io_ready(owner->tcp_io,owner->generation,cookie,fd,events,now)) {
    product_root_dns_adapter_expire(vm,now); product_flow_expiry_changed(vm); return NULL;
  }
  owner->current_upstream_session = cookie;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_SOCKETS; ++i)
    if (owner->vpn_bindings[i].cookie == cookie) owner->current_binding = owner->vpn_bindings[i];
  product_root_dns_io_ready (owner->io, owner->generation, cookie, fd, events, now);
  owner->current_upstream_session = 0;
  owner->current_binding = (root_dns_binding_t) {0};
  product_root_dns_adapter_expire (vm, now);
  product_flow_expiry_changed (vm);
  return NULL;
}
static clib_error_t *root_dns_file_read (clib_file_t *file)
{ return root_dns_file_dispatch (file, PRODUCT_ROOT_DNS_READ); }
static clib_error_t *root_dns_file_write (clib_file_t *file)
{ return root_dns_file_dispatch (file, PRODUCT_ROOT_DNS_WRITE); }
static clib_error_t *root_dns_file_error (clib_file_t *file)
{ return root_dns_file_dispatch (file, PRODUCT_ROOT_DNS_ERROR); }

int product_root_dns_adapter_start (vlib_main_t *vm, uint64_t generation, unsigned count)
{
  if (!vm || !generation || !count || count > PRODUCT_GRAPH_WORKERS || root_dns_owner_count)
    return 0;
  for (unsigned i = 0; i < count; ++i)
    {
      root_dns_owner_t *owner = &root_dns_owners[i];
      u64 socket_sequence = owner->socket_sequence;
      memset (owner, 0, sizeof (*owner)); owner->socket_sequence = socket_sequence;
      owner->vm = vlib_get_main_by_index (vlib_get_worker_thread_index (i));
      owner->generation = generation; owner->owner = i; owner->raw4 = owner->raw6 = -1;
      owner->profile = product_packet_graph_main.adapter_kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN ? 2 : 1;
      for (unsigned j = 0; j < ROOT_DNS_WATCHES; ++j)
        owner->watches[j] = (root_dns_watch_t) {.fd = -1, .file = ~0};
    }
  root_dns_owner_count = count; return 1;
}
void product_root_dns_adapter_changed (void)
{
  for (unsigned i = 0; i < root_dns_owner_count; ++i)
    vlib_node_set_interrupt_pending (root_dns_owners[i].vm, product_root_dns_node.index);
}
int product_root_dns_adapter_ready (void)
{
  if (!root_dns_owner_count) return 1;
  product_dns_proxy_route_t route; u64 revision;
  if (!root_dns_configuration (&route, &revision)) return 0;
  if (!route.enabled) return 1;
  u64 network = product_network_snapshot_current ()->revision;
  for (unsigned i = 0; i < root_dns_owner_count; ++i)
    if (!root_dns_owner_current (&root_dns_owners[i], revision, network)) return 0;
  return 1;
}

int product_root_dns_adapter_enabled (void)
{
  product_dns_proxy_route_t route;
  u64 revision;
  return root_dns_configuration (&route, &revision) && route.enabled;
}

void product_root_dns_adapter_admission_observe (vlib_main_t *vm, u64 token,
  const product_platform_packet_facts_t *platform,
  const product_root_dns_admission_facts_t *facts, u8 coverage, u8 delivery)
{
  if (!vm || !vm->thread_index || vm->thread_index > root_dns_owner_count
      || !token || !platform || !facts || !facts->family
      || facts->resolver_port != 53)
    return;
  root_dns_owner_t *owner = &root_dns_owners[vlib_get_worker_index (vm->thread_index)];
  product_dns_proxy_route_t route;
  u64 revision;
  if (owner->generation != product_packet_graph_main.generation
      || !root_dns_configuration (&route, &revision))
    return;
  product_dns_observation_record_t record = {
    .generation = owner->generation, .token = token, .slot = UINT32_MAX,
    .uid = (platform->availability & PRODUCT_PLATFORM_UID_KNOWN)
      ? platform->uid : UINT32_MAX,
    .network = (platform->availability & PRODUCT_PLATFORM_CONTEXT_KNOWN)
      ? platform->network_context_id : UINT32_MAX,
    .ifindex = (platform->availability & PRODUCT_PLATFORM_IFINDEX_KNOWN)
      ? platform->linux_ifindex : 0,
    .id = facts->id, .query_flags = facts->query_flags,
    .source_port = facts->source_port, .resolver_port = facts->resolver_port,
    .family = facts->family, .protocol = facts->protocol==6?6:17,
    .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
    .availability = platform->availability &
      (PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_IFINDEX_KNOWN |
       PRODUCT_PLATFORM_CONTEXT_KNOWN | PRODUCT_PLATFORM_DNS_APP_RELIABLE),
    .caller = (platform->availability & PRODUCT_PLATFORM_DNS_APP_RELIABLE)
      ? PRODUCT_DNS_CALLER_PLATFORM_APP : PRODUCT_DNS_CALLER_UNKNOWN,
    .coverage = coverage, .stage = 3, .delivery = delivery,
    .query_token = token, .route_revision = revision,
    .proxy_result = PRODUCT_DNS_PROXY_CAPACITY,
    .adapter_profile = 1,
    .packet_uid = (platform->availability & PRODUCT_PLATFORM_UID_KNOWN)
      ? platform->uid : UINT32_MAX,
    .packet_availability = platform->availability &
      (PRODUCT_PLATFORM_UID_KNOWN | PRODUCT_PLATFORM_IFINDEX_KNOWN |
       PRODUCT_PLATFORM_CONTEXT_KNOWN | PRODUCT_PLATFORM_DNS_APP_RELIABLE),
    .proxy_flags = PRODUCT_DNS_PROXY_RECORD |
      PRODUCT_DNS_PROXY_ADMISSION_RESOURCE,
  };
  memcpy (record.source_address, facts->source_address, 16);
  memcpy (record.resolver_address, facts->resolver_address, 16);
  product_observation_dns (vm, &record);
}
void product_root_dns_adapter_quiesce (vlib_main_t *vm)
{
  (void) vm;
  for (unsigned i = 0; i < root_dns_owner_count; ++i)
    {
      root_dns_owner_t *owner = &root_dns_owners[i]; owner->stopping = 1;
      __atomic_store_n (&owner->ready, 0, __ATOMIC_RELEASE);
      product_dns_proxy_resources_t before = product_dns_proxy_resources (owner->proxy);
      product_dns_proxy_stop (owner->proxy, root_dns_now (owner->vm));
      product_dns_proxy_resources_t after = product_dns_proxy_resources (owner->proxy);
      if (before.active) fprintf (stderr,
        "dns.proxy event=quiesce generation=%llu owner=%u active_before=%u cancelled_now=%llu\n",
        (unsigned long long) owner->generation, i, before.active,
        (unsigned long long) (after.cancelled - before.cancelled));
      product_root_dns_tcp_io_close(owner->tcp_io,root_dns_now(owner->vm)); owner->tcp_io=NULL;
      memset(owner->tcp_bindings,0,sizeof(owner->tcp_bindings));
      product_root_dns_io_close (owner->io); owner->io = NULL;
      root_dns_close_raw (owner);
    }
}
void product_root_dns_adapter_stop (vlib_main_t *vm)
{
  product_root_dns_adapter_quiesce (vm);
  for (unsigned i = 0; i < root_dns_owner_count; ++i)
    {
      root_dns_owner_t *owner = &root_dns_owners[i];
      if (owner->replies) clib_panic ("Root DNS stop before native return reclamation");
      product_dns_proxy_close (owner->proxy); owner->proxy = NULL;
      fprintf (stderr, "dns.proxy event=stop generation=%llu owner=%u transactions=0 upstream_sockets=0 cache_entries=0 cache_bytes=0 raw_sockets=%u replies=%u raw_opened=%llu raw_closed=%llu returned=%llu\n",
        (unsigned long long) owner->generation, i, (owner->raw4 >= 0) + (owner->raw6 >= 0), owner->replies,
        (unsigned long long) owner->raw_opened, (unsigned long long) owner->raw_closed, (unsigned long long) owner->returned);
    }
  root_dns_owner_count = 0;
}
uint64_t product_root_dns_adapter_deadline (unsigned index)
{
  if (index >= root_dns_owner_count || root_dns_owners[index].stopping) return UINT64_MAX;
  root_dns_owner_t *owner = &root_dns_owners[index];
  u64 next = product_dns_proxy_deadline (owner->proxy), io = product_root_dns_io_deadline (owner->io);
  u64 tcp=product_root_dns_tcp_io_deadline(owner->tcp_io); if(tcp<next)next=tcp;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i)
    if(owner->tcp_bindings[i].active && !owner->tcp_bindings[i].session && owner->tcp_bindings[i].deadline<next)
      next=owner->tcp_bindings[i].deadline;
  if (io < next) next = io;
  if (owner->retry_at && owner->retry_at < next) next = owner->retry_at;
  if (!owner->replies && owner->raw_idle && owner->raw_idle < next) next = owner->raw_idle;
  return next;
}
uint32_t product_root_dns_adapter_pending (unsigned index)
{
  return index < root_dns_owner_count
    ? __atomic_load_n (&root_dns_owners[index].replies, __ATOMIC_ACQUIRE) : 0;
}
static void vpn_dns_tcp_finish(root_dns_owner_t *owner,vpn_dns_tcp_delivery_t *message)
{
  if(!message->active || !message->done || message->packets)return;
  message->record.stage=4;
  message->record.direction=message->record.packet_direction=PRODUCT_PACKET_DIRECTION_INPUT;
  message->record.delivery=message->acknowledged?PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED:
    message->failure_delivery?message->failure_delivery:PRODUCT_DNS_DELIVERY_WRITE_FAILED;
  product_observation_dns(owner->vm,&message->record);
  if(message->acknowledged)++owner->returned;else ++owner->write_failed;
  memset(message,0,sizeof(*message));
}
static void root_dns_vpn_reclaim (root_dns_owner_t *owner)
{
  if (owner->profile != 2) return;
  for (unsigned i = 0; i < ROOT_DNS_REPLIES; ++i) {
    root_dns_reply_t *reply = &owner->reply[i];
    if (__atomic_load_n (&reply->state, __ATOMIC_ACQUIRE) != 3) continue;
    if(reply->tcp_message) {
      vpn_dns_tcp_delivery_t *message=&owner->vpn_tcp[reply->tcp_message-1];
      if(message->active && message->token==reply->record.query_token) {
        if(message->packets)--message->packets;
        if(reply->record.delivery!=PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED && !message->failure_delivery)
          message->failure_delivery=reply->record.delivery;
        /* Copy only actual return-policy/completion identity. The original
         * caller and query history remain the frame's immutable facts. */
        if(reply->record.delivery==PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED || !message->record.return_policy_revision) {
        message->record.return_token=reply->record.return_token;
        message->record.return_packet_uid=reply->record.return_packet_uid;
        message->record.return_policy_generation=reply->record.return_policy_generation;
        message->record.return_policy_revision=reply->record.return_policy_revision;
        message->record.return_policy_hash=reply->record.return_policy_hash;
        message->record.return_winner=reply->record.return_winner;
        message->record.return_declared_action=reply->record.return_declared_action;
        message->record.return_actual_action=reply->record.return_actual_action;
        message->record.return_mode=reply->record.return_mode;
        }
        vpn_dns_tcp_finish(owner,message);
      }
    } else { product_observation_dns(owner->vm,&reply->record);++owner->returned; }
    __atomic_fetch_sub (&owner->replies, 1, __ATOMIC_RELAXED);
    __atomic_store_n (&reply->state, 0, __ATOMIC_RELEASE);
  }
}
void product_root_dns_adapter_expire (vlib_main_t *vm, uint64_t now)
{
  if (!vm->thread_index || vm->thread_index > root_dns_owner_count) return;
  root_dns_owner_t *owner = &root_dns_owners[vlib_get_worker_index (vm->thread_index)];
  root_dns_vpn_reclaim (owner);
  root_dns_sync (owner, now);
  if (owner->proxy)
    {
      product_dns_proxy_other_bytes (owner->proxy, root_dns_other_bytes (owner));
      product_dns_proxy_advance (owner->proxy, now, owner->network_revision, owner->route_revision);
    }
  product_root_dns_io_expire (owner->io, now);
  product_root_dns_tcp_io_expire(owner->tcp_io,now);
  product_root_dns_tcp_status_t tcp_status=product_root_dns_tcp_io_status(owner->tcp_io);
  if(owner->tcp_io && !tcp_status.accepting && !tcp_status.clients) {
    product_root_dns_tcp_io_close(owner->tcp_io,now);owner->tcp_io=NULL;
  }
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i)
    if(owner->tcp_bindings[i].active && !owner->tcp_bindings[i].session && owner->tcp_bindings[i].deadline<=now)
      memset(&owner->tcp_bindings[i],0,sizeof(owner->tcp_bindings[i]));
  if (owner->raw_idle && owner->raw_idle <= now) root_dns_close_raw (owner);
  root_dns_publish_ready (owner);
}
VLIB_NODE_FN (product_root_dns_node) (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  (void) node; (void) frame;
  if (vm->thread_index && vm->thread_index <= root_dns_owner_count)
    {
      product_root_dns_adapter_expire (vm, root_dns_now (vm));
      product_flow_expiry_changed (vm);
    }
  return 0;
}
VLIB_REGISTER_NODE (product_root_dns_node) = {
  .name = "product-root-dns-events", .type = VLIB_NODE_TYPE_INPUT, .state = VLIB_NODE_STATE_INTERRUPT,
};

static int root_dns_intercept (vlib_main_t *vm, u32 buffer_index, product_packet_lease_t *lease,
  const product_policy_snapshot_t *snapshot, const product_flow_entry_observation_t *flow)
{
  if ((lease->platform.provenance != PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE &&
       lease->platform.provenance != PRODUCT_PACKET_PROVENANCE_VPN_TUN) ||
      lease->platform.direction != PRODUCT_PACKET_DIRECTION_OUTPUT || lease->facts.protocol != 17 ||
      lease->facts.destination_port != 53 || lease->facts.l4_status != PRODUCT_PACKET_L4_COMPLETE ||
      !lease->assignment.valid || !lease->policy_owner_ready ||
      (lease->terminal_intent != PRODUCT_PACKET_INTENT_NONE &&
       !(lease->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME && lease->runtime_drop_reason == PRODUCT_PACKET_DROP_POLICY_L4)))
    return 0;
  unsigned index = vlib_get_worker_index (vm->thread_index);
  if (index >= root_dns_owner_count) return 0;
  root_dns_owner_t *owner = &root_dns_owners[index]; u64 now = root_dns_now (vm);
  root_dns_sync (owner, now);
  if (!snapshot->bank->dns.enabled) return 0;
  product_dns_proxy_input_t input = {.identity = {.generation = owner->generation,
      .incarnation = flow->entry ? flow->entry->incarnation : 0,
      .network_revision = product_network_snapshot_current ()->revision, .now_us = now, .profile = owner->profile},
    .token = lease->origin_obligation_id, .route_revision = snapshot->bank->dns_revision,
    .slot = flow->entry ? flow->slot : UINT32_MAX};
  product_packet_graph_l4_packet_projection (lease, &input.context.packet);
  input.context.caller = (lease->platform.availability & PRODUCT_PLATFORM_DNS_APP_RELIABLE)
    ? PRODUCT_DNS_CALLER_PLATFORM_APP : PRODUCT_DNS_CALLER_UNKNOWN;
  input.context.packet.ct_state = flow->tracker.facts.state;
  input.context.packet.flow_direction = flow->tracker.facts.direction;
  input.context.packet.ct_state_known = flow->tracker.facts.state != 0;
  input.context.packet.flow_direction_known = flow->tracker.facts.direction != 0;
  if (flow->entry)
    {
      input.context.packet.protocol_set = flow->entry->lpi.protocols;
      input.context.packet.protocol_set_known = flow->entry->lpi.available;
      input.context.packet.sni_result = flow->entry->sni.result;
    }
  product_dns_proxy_snapshot_t current = {.context = input.context, .view = &snapshot->bank->view,
    .identity = {snapshot->identity.generation, snapshot->identity.revision, snapshot->identity.snapshot_hash, 0},
    .network_revision = input.identity.network_revision, .route_revision = input.route_revision};
  current.context.domains = snapshot->bank->domains; current.context.domains_available = 1;
  vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
  u32 offset = lease->facts.transport_offset + lease->facts.l4_header_length;
  u32 length = lease->facts.transport_length - lease->facts.l4_header_length;
  const u8 *wire = offset <= buffer->current_length && length <= buffer->current_length - offset
    ? (const u8 *) vlib_buffer_get_current (buffer) + offset : NULL;
  if (wire && length >= 4 && (wire[2] & 0x80)) return 0;
  if (owner->profile == 2) {
    size_t complete = 0; u64 session = 0;
    product_vpn_flow_stack_input_result_t admitted = product_vpn_flow_stack_driver_local_udp (
      vm, vlib_buffer_get_current (buffer), buffer->current_length, &lease->platform,
      owner->generation, input.identity.incarnation, &session,
      owner->vpn_message, sizeof (owner->vpn_message), &complete);
    input.identity.transport_session = session;
    wire = admitted == PRODUCT_VPN_FLOW_STACK_ACCEPTED ? owner->vpn_message : NULL;
    length = wire ? complete : 0;
  }
  owner->event_view = &snapshot->bank->view; owner->event_revision = snapshot->identity.revision;
  int same_view = owner->route_revision == input.route_revision && owner->network_revision == input.identity.network_revision;
  int intercepted = owner->proxy && same_view && !owner->stopping
    ? product_dns_proxy_submit (owner->proxy, &input, wire, wire ? length : 0, &current)
    : product_dns_proxy_unavailable (&input, wire, wire ? length : 0, &current, &snapshot->bank->dns,
        &root_dns_proxy_callbacks, owner, owner->stopping ? PRODUCT_DNS_PROXY_STOPPED :
          same_view ? PRODUCT_DNS_PROXY_SERVFAIL : PRODUCT_DNS_PROXY_VIEW_CHANGED);
  owner->event_view = NULL; owner->event_revision = 0;
  if (intercepted)
    {
      ++owner->intercepted;
      if (lease->terminal_intent == PRODUCT_PACKET_INTENT_NONE)
        {
          if (product_packet_set_terminal (lease, PRODUCT_PACKET_INTENT_DROP_RUNTIME) != PRODUCT_PACKET_OK)
            clib_panic ("Root DNS original terminal identity rejected");
          lease->runtime_drop_reason = PRODUCT_PACKET_DROP_DNS_TAKEOVER;
        }
    }
  return intercepted;
}

static int root_dns_tcp_same_tuple(const root_dns_tcp_binding_t *,const product_packet_lease_t *);
/* Replacement is fixed when this actual SYN is admitted. Existing Direct
 * sessions stay Direct; selected local sessions never fall back on disable. */
static int vpn_dns_tcp_capture(vlib_main_t *vm,u32 bi,product_packet_lease_t *lease,
  const product_policy_snapshot_t *snapshot,const product_flow_entry_observation_t *flow)
{
  if(lease->platform.provenance!=PRODUCT_PACKET_PROVENANCE_VPN_TUN ||
      lease->platform.direction!=PRODUCT_PACKET_DIRECTION_OUTPUT || lease->facts.protocol!=6 || lease->facts.destination_port!=53)return 0;
  int syn=(lease->facts.tcp_flags&0x17)==2;
  int taken=flow->entry && flow->entry->vpn_dns_tcp_taken;
  if(!taken && syn && flow->entry && !flow->entry->vpn_dns_tcp_decided && !snapshot->bank->dns.enabled) {
    product_flow_entry_select_vpn_dns_tcp(product_packet_graph_main.flow_pools[vlib_get_worker_index(vm->thread_index)],
      flow->slot,product_packet_graph_main.generation,flow->entry->incarnation,0);
    return 0;
  }
  if(!taken && (!(syn && snapshot->bank->dns.enabled) ||
      (flow->entry && flow->entry->vpn_dns_tcp_decided)))return 0;
  if(lease->terminal_intent!=PRODUCT_PACKET_INTENT_NONE)return 1;
  unsigned index=vlib_get_worker_index(vm->thread_index);
  if(index>=root_dns_owner_count)return 0;
  root_dns_owner_t *owner=&root_dns_owners[index];u64 now=root_dns_now(vm);
  root_dns_sync(owner,now);
  root_dns_tcp_binding_t *binding=NULL,*free_binding=NULL;
  if(!flow->entry || lease->facts.l4_status!=PRODUCT_PACKET_L4_COMPLETE || !lease->policy_owner_ready || owner->stopping)goto failed;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i) {
    root_dns_tcp_binding_t *candidate=&owner->tcp_bindings[i];
    if(!candidate->active && !free_binding)free_binding=candidate;
    if(candidate->active && candidate->input.identity.incarnation==flow->entry->incarnation &&
        root_dns_tcp_same_tuple(candidate,lease))binding=candidate;
  }
  if(!binding && syn)binding=free_binding;
  if(!binding)goto failed;
  int existing=binding->active;
  product_dns_proxy_input_t *input=&binding->input;
  if(existing && binding->trusted_uid_known && (lease->platform.availability&PRODUCT_PLATFORM_UID_KNOWN) &&
      binding->trusted_uid!=lease->platform.uid)goto failed;
  product_packet_graph_l4_packet_projection(lease,&input->context.packet);
  input->context.caller=(lease->platform.availability&PRODUCT_PLATFORM_DNS_APP_RELIABLE)
    ?PRODUCT_DNS_CALLER_PLATFORM_APP:PRODUCT_DNS_CALLER_UNKNOWN;
  if(input->context.caller==PRODUCT_DNS_CALLER_PLATFORM_APP) {
    binding->trusted_uid=input->context.packet.uid;binding->trusted_uid_known=1;
  }
  input->capture_present=1;input->capture_uid=(lease->platform.availability&PRODUCT_PLATFORM_UID_KNOWN)?lease->platform.uid:UINT32_MAX;
  input->capture_availability=lease->platform.availability;
  input->context.packet.ct_state=flow->tracker.facts.state;input->context.packet.ct_state_known=flow->tracker.facts.state!=0;
  input->context.packet.flow_direction=flow->tracker.facts.direction;input->context.packet.flow_direction_known=flow->tracker.facts.direction!=0;
  input->context.packet.protocol_set=flow->entry->lpi.protocols;input->context.packet.protocol_set_known=flow->entry->lpi.available;
  input->context.packet.sni_result=flow->entry->sni.result;input->slot=flow->slot;
  if(!existing) {
    input->identity=(product_dns_identity_t){.generation=owner->generation,.incarnation=flow->entry->incarnation,
      .network_revision=owner->network_revision,.now_us=now,.profile=2};
    input->route_revision=owner->route_revision;
  }
  if(!taken && !product_flow_entry_select_vpn_dns_tcp(product_packet_graph_main.flow_pools[index],flow->slot,
      owner->generation,flow->entry->incarnation,1))goto failed;
  binding->active=1;
  vlib_buffer_t *buffer=vlib_get_buffer(vm,bi);u64 session=0;
  product_vpn_flow_stack_input_result_t result=product_vpn_flow_stack_driver_local_tcp(vm,
    vlib_buffer_get_current(buffer),buffer->current_length,&lease->platform,
    owner->generation,flow->entry->incarnation,&session);
  if(result==PRODUCT_VPN_FLOW_STACK_ACCEPTED && session) {
    binding->session=session;input->identity.transport_session=session;++owner->intercepted;
    /* Drain at this packet's message-ready boundary before a later capture
     * can alter the mutable session's context. Each submit copies the facts. */
    product_vpn_flow_stack_driver_tcp_drain(vm);
  } else ++owner->tcp_admission_failed;
  if(product_packet_set_terminal(lease,PRODUCT_PACKET_INTENT_DROP_RUNTIME)!=PRODUCT_PACKET_OK)
    clib_panic("VPN local TCP original completion rejected");
  lease->runtime_drop_reason=PRODUCT_PACKET_DROP_DNS_TAKEOVER;
  return 1;
failed:
  ++owner->tcp_admission_failed;
  if(lease->terminal_intent==PRODUCT_PACKET_INTENT_NONE) {
    product_packet_set_terminal(lease,PRODUCT_PACKET_INTENT_DROP_RUNTIME);
    lease->runtime_drop_reason=PRODUCT_PACKET_DROP_DNS_TAKEOVER;
  }
  return 1;
}

/* The original TCP observer must not turn a single proxied QName refusal
 * into whole-stream DROP. Generic packet policy still runs on every packet. */
static int root_dns_tcp_selected(const product_packet_lease_t *lease,
  const product_policy_snapshot_t *snapshot)
{
  return lease->platform.provenance==PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE &&
    snapshot->bank->dns.enabled && lease->facts.protocol==6 &&
    ((lease->platform.direction==PRODUCT_PACKET_DIRECTION_OUTPUT && lease->facts.destination_port==53) ||
     (lease->platform.direction==PRODUCT_PACKET_DIRECTION_INPUT && lease->facts.source_port==53));
}
static int root_dns_tcp_same_tuple(const root_dns_tcp_binding_t *binding,
  const product_packet_lease_t *lease)
{
  const product_l4_policy_packet_t *packet=&binding->input.context.packet;
  return binding->active && packet->family==lease->facts.ip_family &&
    packet->source_port==lease->facts.source_port && packet->destination_port==lease->facts.destination_port &&
    !memcmp(packet->source_address,lease->facts.source_address+(packet->family==4?12:0),packet->family==4?4:16) &&
    !memcmp(packet->destination_address,lease->facts.destination_address+(packet->family==4?12:0),packet->family==4?4:16);
}
static int root_dns_tcp_capture(vlib_main_t *vm,u32 buffer_index,product_packet_lease_t *lease,
  const product_policy_snapshot_t *snapshot,const product_flow_entry_observation_t *flow)
{
  if(lease->platform.provenance!=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE ||
      lease->platform.direction!=PRODUCT_PACKET_DIRECTION_OUTPUT || lease->facts.protocol!=6 || lease->facts.destination_port!=53)return 0;
  int taken=flow->entry && flow->entry->root_dns_tcp_taken;
  if(!snapshot->bank->dns.enabled && !taken &&
      !(lease->platform.reserved&PRODUCT_PLATFORM_ADMISSION_DNS_REPLACEMENT_ACTIVE))return 0;
  if(lease->terminal_intent!=PRODUCT_PACKET_INTENT_NONE)return 1;
  unsigned index=vlib_get_worker_index(vm->thread_index);
  if(index>=root_dns_owner_count)return 0;
  root_dns_owner_t *owner=&root_dns_owners[index]; u64 now=root_dns_now(vm);
  root_dns_sync(owner,now);
  vlib_buffer_t *buffer=vlib_get_buffer(vm,buffer_index);
  int syn=(lease->facts.tcp_flags&0x17)==2;
  root_dns_tcp_binding_t *binding=NULL,*free_binding=NULL;
  if(!(lease->platform.reserved&PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID) ||
      !product_root_dns_tcp_packet_bytes(vlib_buffer_get_current(buffer),buffer->current_length))goto unavailable;
  u32 original_mark=product_root_dns_original_mark(buffer)&PRODUCT_ROOT_DNS_TCP_MARK_MASK;
  if(original_mark && (!taken || original_mark!=((index+1)<<PRODUCT_ROOT_DNS_TCP_MARK_SHIFT)))goto unavailable;
  if(taken && !snapshot->bank->dns.enabled) {
    lease->platform.reserved|=(index+1)<<PRODUCT_PLATFORM_ADMISSION_DNS_TCP_OWNER_SHIFT;
    product_packet_graph_set_platform_facts(buffer,&lease->platform,owner->generation);return 1;
  }
  if(lease->facts.l4_status!=PRODUCT_PACKET_L4_COMPLETE || !lease->assignment.valid ||
      !lease->policy_owner_ready || owner->stopping || !owner->tcp_io ||
      !product_root_dns_tcp_io_status(owner->tcp_io).accepting || !owner->proxy ||
      !flow->entry || owner->route_revision!=snapshot->bank->dns_revision ||
      owner->network_revision!=product_network_snapshot_current()->revision)goto unavailable;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i) {
    root_dns_tcp_binding_t *candidate=&owner->tcp_bindings[i];
    if(candidate->active && !candidate->session && candidate->deadline<=now)
      memset(candidate,0,sizeof(*candidate));
    if(!candidate->active && !free_binding)free_binding=candidate;
    if(root_dns_tcp_same_tuple(candidate,lease) &&
        candidate->input.identity.generation==owner->generation &&
        candidate->input.identity.incarnation==flow->entry->incarnation &&
        (!syn || candidate->syn_sequence==lease->facts.tcp_sequence)) {
      if(binding)goto unavailable;
      binding=candidate;
    }
  }
  if(syn) {
    if(!(lease->platform.reserved&PRODUCT_PLATFORM_ADMISSION_DNS_TCP_MARK_VALID) ||
        !product_root_dns_tcp_syn_bytes(vlib_buffer_get_current(buffer),buffer->current_length) ||
        (original_mark && !taken))goto unavailable;
    if(!binding)binding=free_binding;
    if(!binding)goto unavailable;
  } else if(!binding)goto unavailable;
  product_dns_proxy_input_t *input=&binding->input;
  int existing=binding->active;
  u32 caller_uid=input->context.packet.uid;u8 caller_known=input->context.packet.uid_known;
  product_dns_caller_t caller=input->context.caller;
  if(existing && caller_known && (lease->platform.availability&PRODUCT_PLATFORM_UID_KNOWN) && caller_uid!=lease->platform.uid)
    { ++owner->tcp_identity_rejected; goto unavailable; }
  product_packet_graph_l4_packet_projection(lease,&input->context.packet);
  if(existing) {
    input->context.packet.uid=caller_uid;input->context.packet.uid_known=caller_known;input->context.caller=caller;
  } else input->context.caller=(lease->platform.availability&PRODUCT_PLATFORM_DNS_APP_RELIABLE)
    ? PRODUCT_DNS_CALLER_PLATFORM_APP : PRODUCT_DNS_CALLER_UNKNOWN;
  input->capture_present=1;input->capture_uid=(lease->platform.availability&PRODUCT_PLATFORM_UID_KNOWN)?lease->platform.uid:UINT32_MAX;
  input->capture_availability=lease->platform.availability;
  input->context.packet.ct_state=flow->tracker.facts.state;
  input->context.packet.flow_direction=flow->tracker.facts.direction;
  input->context.packet.ct_state_known=flow->tracker.facts.state!=0;
  input->context.packet.flow_direction_known=flow->tracker.facts.direction!=0;
  input->context.packet.protocol_set=flow->entry->lpi.protocols;
  input->context.packet.protocol_set_known=flow->entry->lpi.available;
  input->context.packet.sni_result=flow->entry->sni.result;
  input->slot=flow->slot;input->route_revision=owner->route_revision;
  input->identity=(product_dns_identity_t){.generation=owner->generation,
    .incarnation=flow->entry->incarnation,.network_revision=owner->network_revision,.now_us=now,
    .profile=1,.transport_session=binding->session};
  input->token=lease->origin_obligation_id;
  if(syn && !taken && !product_flow_entry_take_root_dns_tcp(product_packet_graph_main.flow_pools[index],
       flow->slot,owner->generation,flow->entry->incarnation))goto unavailable;
  binding->active=1;
  if(syn) { binding->syn_sequence=lease->facts.tcp_sequence;
    if(!binding->session)binding->deadline=now+PRODUCT_DNS_REQUEST_US; }
  lease->platform.reserved|=(index+1)<<PRODUCT_PLATFORM_ADMISSION_DNS_TCP_OWNER_SHIFT;
  product_packet_graph_set_platform_facts(buffer,&lease->platform,owner->generation);
  return 1;
unavailable:
  ++owner->tcp_admission_failed;
  product_root_dns_admission_facts_t facts={.family=lease->facts.ip_family,.protocol=6,
    .source_port=lease->facts.source_port,.resolver_port=53,.packet_length=lease->facts.packet_length};
  memcpy(facts.source_address,lease->facts.source_address+(facts.family==4?12:0),facts.family==4?4:16);
  memcpy(facts.resolver_address,lease->facts.destination_address+(facts.family==4?12:0),facts.family==4?4:16);
  product_root_dns_adapter_admission_observe(vm,lease->origin_obligation_id,&lease->platform,&facts,
    PRODUCT_DNS_CAPACITY,PRODUCT_DNS_DELIVERY_RESOURCE_DROP);
  if(product_packet_set_terminal(lease,PRODUCT_PACKET_INTENT_DROP_RUNTIME)!=PRODUCT_PACKET_OK)
    clib_panic("Root TCP DNS admission terminal identity rejected");
  lease->runtime_drop_reason=PRODUCT_PACKET_DROP_DNS_TAKEOVER;
  return 1;
}

static root_dns_reply_t *root_dns_return (root_dns_owner_t *owner, u32 buffer,
  const product_adapter_obligation_t *obligation)
{
  if (owner->profile == 2) {
    if (obligation->kind != PRODUCT_ADAPTER_OBLIGATION_VPN_TUN ||
        obligation->queue_generation != owner->generation || obligation->packet_id != owner->owner + 1) return NULL;
    for (unsigned i = 0; i < ROOT_DNS_REPLIES; ++i) {
      root_dns_reply_t *reply = &owner->reply[i];
      if (__atomic_load_n (&reply->state, __ATOMIC_ACQUIRE) &&
          reply->buffer == buffer && reply->obligation.token == obligation->token) return reply;
    }
    return NULL;
  }
  if (obligation->kind != PRODUCT_ADAPTER_OBLIGATION_ROOT_DNS_REPLY ||
      obligation->queue_generation != owner->generation || obligation->origin_worker != owner->owner ||
      obligation->origin_lane != owner->owner || !obligation->packet_id || obligation->packet_id > ROOT_DNS_REPLIES)
    return NULL;
  root_dns_reply_t *reply = &owner->reply[obligation->packet_id - 1];
  return reply->buffer == buffer && reply->obligation.token == obligation->token ? reply : NULL;
}
static void root_dns_return_policy (vlib_main_t *vm, u32 buffer, const product_packet_lease_t *lease,
  const product_packet_graph_policy_evaluation_t *evaluation)
{
  if (lease->platform.provenance != PRODUCT_PACKET_PROVENANCE_ROOT_DNS_RETURN &&
      lease->platform.provenance != PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN) return;
  root_dns_owner_t *owner = &root_dns_owners[vlib_get_worker_index (vm->thread_index)];
  product_buffer_platform_metadata_t saved;
  memcpy (&saved, vlib_get_buffer (vm, buffer)->opaque, sizeof (saved));
  root_dns_reply_t *reply = root_dns_return (owner, buffer, &saved.obligation);
  if (!reply || reply->state != 1) return;
  reply->record.return_policy_generation = evaluation->generation;
  reply->record.return_policy_revision = evaluation->revision;
  reply->record.return_policy_hash = evaluation->snapshot_hash;
  reply->record.return_winner = evaluation->matched ? evaluation->rule_id : 0;
  reply->record.return_declared_action = evaluation->matched ? evaluation->declared_action : 1;
  reply->record.return_actual_action = evaluation->matched ? evaluation->actual_action : 1;
  reply->record.return_mode = evaluation->matched ? evaluation->mode : 0;
}
void product_root_dns_vpn_return_admit (vlib_main_t *vm, uint32_t buffer,
  const product_adapter_obligation_t *obligation, const product_platform_packet_facts_t *platform)
{
  unsigned index = vlib_get_worker_index (vm->thread_index);
  if (index >= root_dns_owner_count) return;
  root_dns_owner_t *owner = &root_dns_owners[index];
  root_dns_reply_t *reply = owner->vpn_reply;
  if (!reply || owner->profile != 2) return;
  reply->buffer = buffer; reply->obligation = *obligation;
  if(reply->tcp_message) {
    ++owner->vpn_tcp[reply->tcp_message-1].packets;
    __atomic_add_fetch(&owner->replies,1,__ATOMIC_RELAXED);
    if(owner->replies>owner->high_water_replies)owner->high_water_replies=owner->replies;
  }
  reply->record.return_token = obligation->token;
  reply->record.return_packet_uid = (platform->availability & PRODUCT_PLATFORM_UID_KNOWN) ? platform->uid : UINT32_MAX;
  owner->last_reply_token = obligation->token;
  __atomic_store_n (&reply->state, 1, __ATOMIC_RELEASE);
}
int product_root_dns_vpn_return_known (vlib_main_t *vm, uint32_t buffer)
{
  unsigned index = vlib_get_worker_index (vm->thread_index);
  if (index >= root_dns_owner_count || root_dns_owners[index].profile != 2) return 0;
  product_buffer_platform_metadata_t saved;
  memcpy (&saved, vlib_get_buffer (vm, buffer)->opaque, sizeof (saved));
  return root_dns_return (&root_dns_owners[index], buffer, &saved.obligation) != NULL;
}
void product_root_dns_vpn_reply_complete (vlib_main_t *vm, uint32_t buffer,
  const product_packet_completion_frame_t *completion, uint8_t delivery)
{
  unsigned index = completion->obligation.packet_id - 1;
  if (index >= root_dns_owner_count || root_dns_owners[index].profile != 2) return;
  root_dns_reply_t *reply = root_dns_return (&root_dns_owners[index], buffer, &completion->obligation);
  if (!reply || __atomic_load_n (&reply->state, __ATOMIC_ACQUIRE) != 1 ||
      (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)) return;
  (void) vm;
  reply->record.stage = 4;
  reply->record.direction = reply->record.packet_direction = PRODUCT_PACKET_DIRECTION_INPUT;
  reply->record.delivery = delivery;
  __atomic_store_n (&reply->state, 2, __ATOMIC_RELEASE);
}
void product_root_dns_vpn_reply_freed (vlib_main_t *vm, uint32_t buffer,
  const product_packet_completion_frame_t *completion)
{
  (void) vm;
  unsigned index = completion->obligation.packet_id - 1;
  if (index >= root_dns_owner_count || root_dns_owners[index].profile != 2) return;
  root_dns_owner_t *owner = &root_dns_owners[index];
  root_dns_reply_t *reply = root_dns_return (owner, buffer, &completion->obligation);
  if (!reply || (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)) return;
  if (__atomic_load_n (&reply->state, __ATOMIC_ACQUIRE) != 2) return;
  __atomic_store_n (&reply->state, 3, __ATOMIC_RELEASE);
  vlib_node_set_interrupt_pending (owner->vm, product_root_dns_node.index);
}
int product_root_dns_vpn_authorized (vlib_main_t *vm, uint64_t generation,
  uint64_t cookie, unsigned error, uint64_t epoch, uint32_t context, int known)
{
  unsigned index = vlib_get_worker_index (vm->thread_index);
  if (index >= root_dns_owner_count) return -1;
  root_dns_owner_t *owner = &root_dns_owners[index];
  if (owner->profile != 2 || generation != owner->generation || owner->stopping) return -1;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_SOCKETS; ++i)
    if (owner->vpn_bindings[i].cookie == cookie) {
      owner->vpn_bindings[i].epoch = error ? 0 : epoch;
      owner->vpn_bindings[i].context = context;
      owner->vpn_bindings[i].known = !error && known;
      owner->current_binding = owner->vpn_bindings[i];
      owner->current_upstream_session = cookie;
      int result = product_root_dns_io_authorized (owner->io, generation, cookie,
        !error && epoch, root_dns_now (vm));
      owner->current_upstream_session = 0;
      owner->current_binding = (root_dns_binding_t) {0};
      owner->last_error = error ? error : epoch ? 0 : EPROTO;
      root_dns_publish_ready (owner);
      return result;
    }
  ++owner->stale; return -1;
}
void product_root_dns_vpn_invalidate (vlib_main_t *vm, uint64_t generation, uint64_t epoch)
{
  unsigned index = vlib_get_worker_index (vm->thread_index);
  if (index >= root_dns_owner_count) return;
  root_dns_owner_t *owner = &root_dns_owners[index];
  if (owner->profile != 2 || generation != owner->generation || owner->stopping) return;
  for (unsigned i = 0; i < PRODUCT_DNS_PROXY_SOCKETS; ++i)
    if (owner->vpn_bindings[i].epoch == epoch) {
      product_dns_proxy_advance (owner->proxy, root_dns_now (vm), owner->network_revision + 1, owner->route_revision);
      product_dns_proxy_close (owner->proxy); owner->proxy = NULL;
      product_root_dns_io_close (owner->io); owner->io = NULL;
      __atomic_store_n (&owner->ready, 0, __ATOMIC_RELEASE); owner->retry_at = 0;
      product_root_dns_adapter_changed (); return;
    }
}
void product_root_dns_vpn_tcp_done(vlib_main_t *vm,uint64_t generation,uint64_t session,uint64_t token,int success)
{
  unsigned index=vlib_get_worker_index(vm->thread_index);
  if(index>=root_dns_owner_count)return;
  root_dns_owner_t *owner=&root_dns_owners[index];
  if(owner->generation!=generation || owner->profile!=2)return;
  for(unsigned i=0;i<128;++i) {
    vpn_dns_tcp_delivery_t *message=&owner->vpn_tcp[i];
    if(message->active && message->session==session && message->token==token) {
      message->done=1;message->acknowledged=!!success;vpn_dns_tcp_finish(owner,message);return;
    }
  }
}
int product_root_dns_vpn_tcp_output(vlib_main_t *vm,uint64_t generation,uint64_t session,uint64_t token,int begin)
{
  unsigned index=vlib_get_worker_index(vm->thread_index);
  if(index>=root_dns_owner_count)return 0;
  root_dns_owner_t *owner=&root_dns_owners[index];
  if(owner->generation!=generation || owner->profile!=2)return 0;
  if(!begin) {
    root_dns_reply_t *reply=owner->vpn_reply;owner->vpn_reply=NULL;
    if(reply && !reply->state)memset(reply,0,sizeof(*reply));
    return 1;
  }
  if(owner->stopping || owner->vpn_reply)return 0;
  unsigned message,slot;
  for(message=0;message<128;++message)
    if(owner->vpn_tcp[message].active && owner->vpn_tcp[message].session==session && owner->vpn_tcp[message].token==token)break;
  if(message==128)return 0;
  for(slot=0;slot<ROOT_DNS_REPLIES && owner->reply[slot].state;++slot) ;
  if(slot==ROOT_DNS_REPLIES)return 0;
  root_dns_reply_t *reply=&owner->reply[slot];memset(reply,0,sizeof(*reply));
  reply->record=owner->vpn_tcp[message].record;reply->tcp_message=message+1;
  owner->vpn_reply=reply;return 1;
}
void product_root_dns_vpn_tcp_query(vlib_main_t *vm,uint64_t generation,uint64_t session,
  uint64_t token,const uint8_t *wire,size_t length)
{
  unsigned index=vlib_get_worker_index(vm->thread_index);
  if(index>=root_dns_owner_count)return;
  root_dns_owner_t *owner=&root_dns_owners[index];
  if(owner->generation!=generation || owner->profile!=2 || owner->stopping)return;
  root_dns_tcp_binding_t *binding=NULL;
  for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i)
    if(owner->tcp_bindings[i].active && owner->tcp_bindings[i].session==session){binding=&owner->tcp_bindings[i];break;}
  if(!binding)return;
  u64 now=root_dns_now(vm);root_dns_sync(owner,now);
  product_dns_proxy_input_t input=binding->input;
  input.token=token;input.identity.transport_session=session;input.identity.now_us=now;
  /* Each complete message uses the current resolution view. The session's
   * caller/incarnation and already-submitted requests remain unchanged. */
  input.identity.network_revision=owner->network_revision;
  input.route_revision=owner->route_revision;
  product_policy_snapshot_t snapshot;product_policy_snapshot_acquire(&product_packet_graph_main,&snapshot);
  product_dns_proxy_snapshot_t current={.context=input.context,.view=&snapshot.bank->view,
    .identity={snapshot.identity.generation,snapshot.identity.revision,snapshot.identity.snapshot_hash,0},
    .network_revision=product_network_snapshot_current()->revision,.route_revision=snapshot.bank->dns_revision};
  current.context.domains=snapshot.bank->domains;current.context.domains_available=1;
  owner->event_view=&snapshot.bank->view;owner->event_revision=snapshot.identity.revision;
  if(owner->proxy && owner->route_revision==input.route_revision && owner->network_revision==input.identity.network_revision)
    product_dns_proxy_submit(owner->proxy,&input,wire,length,&current);
  else product_dns_proxy_unavailable(&input,wire,length,&current,&owner->route,&root_dns_proxy_callbacks,owner,PRODUCT_DNS_PROXY_VIEW_CHANGED);
  owner->event_view=NULL;owner->event_revision=0;
  product_policy_snapshot_release(&product_packet_graph_main,&snapshot);
}
void product_root_dns_vpn_session_end (vlib_main_t *vm, uint64_t generation, uint64_t session)
{
  unsigned index = vlib_get_worker_index (vm->thread_index);
  if (index < root_dns_owner_count) {
    root_dns_owner_t *owner=&root_dns_owners[index];
    product_dns_proxy_session_end(owner->proxy,generation,session,root_dns_now(vm));
    if(owner->profile==2 && generation==owner->generation)
      for(unsigned i=0;i<ROOT_DNS_TCP_BINDINGS;++i)
        if(owner->tcp_bindings[i].active && owner->tcp_bindings[i].session==session)
          memset(&owner->tcp_bindings[i],0,sizeof(owner->tcp_bindings[i]));
  }
}

void product_root_dns_reply_complete (vlib_main_t *vm, uint32_t buffer,
  const product_packet_completion_frame_t *completion)
{
  if (!vm->thread_index || vm->thread_index > root_dns_owner_count) return;
  root_dns_owner_t *owner = &root_dns_owners[vlib_get_worker_index (vm->thread_index)];
  root_dns_reply_t *reply = root_dns_return (owner, buffer, &completion->obligation);
  if (!reply || reply->state != 1 || (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE))
    { ++owner->stale; return; }
  reply->state = 2;
  product_dns_observation_record_t *record = &reply->record;
  record->stage = 4; record->direction = PRODUCT_PACKET_DIRECTION_INPUT; record->packet_direction = 1;
  if (completion->terminal_intent != PRODUCT_PACKET_INTENT_PASS_ADAPTER)
    {
      record->delivery = completion->runtime_drop_reason == PRODUCT_PACKET_DROP_POLICY_L4
        ? PRODUCT_DNS_DELIVERY_POLICY_DROP : PRODUCT_DNS_DELIVERY_ADMISSION_FAILED;
      owner->return_policy_drop += record->delivery == PRODUCT_DNS_DELIVERY_POLICY_DROP;
    }
  else
    {
      vlib_buffer_t *native = vlib_get_buffer (vm, buffer);
      struct sockaddr_storage destination = {0}; socklen_t destination_length;
      int fd;
      if (record->family == 4)
        {
          struct sockaddr_in *address = (struct sockaddr_in *) &destination;
          address->sin_family = AF_INET; memcpy (&address->sin_addr, record->source_address, 4);
          destination_length = sizeof (*address); fd = owner->raw4;
        }
      else
        {
          struct sockaddr_in6 *address = (struct sockaddr_in6 *) &destination;
          /* Route only through loopback; the complete IPv6 header still owns
           * the actual App destination. This avoids Android's bound-raw6
           * lookup failure for a wlan0 address without permitting an obsolete
           * generated reply to leave on an underlay. */
          address->sin6_family = AF_INET6; address->sin6_addr = in6addr_loopback;
          destination_length = sizeof (*address); fd = owner->raw6;
        }
      /* The graph may retain a reply beyond the request window. Refresh its
       * anonymous tombstone immediately before kernel exposure as well. */
      root_dns_return_fence (owner, record);
      ssize_t sent = sendto (fd, vlib_buffer_get_current (native), native->current_length,
        MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *) &destination, destination_length);
      record->delivery = sent == native->current_length
        ? PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED : PRODUCT_DNS_DELIVERY_WRITE_FAILED;
      owner->kernel_accepted += record->delivery == PRODUCT_DNS_DELIVERY_KERNEL_ACCEPTED;
      owner->write_failed += record->delivery == PRODUCT_DNS_DELIVERY_WRITE_FAILED;
      if (sent < 0) owner->last_error = errno;
      owner->raw_idle = root_dns_now (vm) + PRODUCT_ROOT_DNS_IDLE_US;
    }
  product_observation_dns (vm, record);
}
void product_root_dns_reply_freed (vlib_main_t *vm, uint32_t buffer,
  const product_packet_completion_frame_t *completion)
{
  if (!vm->thread_index || vm->thread_index > root_dns_owner_count) return;
  root_dns_owner_t *owner = &root_dns_owners[vlib_get_worker_index (vm->thread_index)];
  root_dns_reply_t *reply = root_dns_return (owner, buffer, &completion->obligation);
  if (!reply || reply->state != 2) return;
  reply->state = 0; --owner->replies; ++owner->returned;
  if (owner->stopping || !owner->route.enabled) root_dns_close_raw (owner);
}

static clib_error_t *root_dns_status_cli (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command)
{
  (void) input; (void) command;
  product_dns_proxy_route_t route; u64 revision;
  int valid = root_dns_configuration (&route, &revision);
  u64 network = product_network_snapshot_current ()->revision;
  for (unsigned i = 0; i < root_dns_owner_count; ++i)
    {
      root_dns_owner_t *owner = &root_dns_owners[i]; char address[INET6_ADDRSTRLEN] = "unselected";
      if (owner->route.family) inet_ntop (owner->route.family == 4 ? AF_INET : AF_INET6,
        owner->route.address, address, sizeof (address));
      product_dns_proxy_resources_t core = product_dns_proxy_resources (owner->proxy);
      vlib_cli_output(vm,"dns.cache owner=%u generation=%llu route_revision=%llu network_revision=%llu entries=%u entry_limit=512 high_water=%u bytes=%llu byte_limit=2097152 high_water_bytes=%llu hits=%llu misses=%llu evicted=%llu skipped=%llu",
        i,(unsigned long long)owner->generation,(unsigned long long)owner->route_revision,
        (unsigned long long)owner->network_revision,core.cache_entries,core.cache_high_water,
        (unsigned long long)core.cache_bytes,(unsigned long long)core.cache_high_water_bytes,
        (unsigned long long)core.cache_hits,(unsigned long long)core.cache_misses,
        (unsigned long long)core.cache_evictions,(unsigned long long)core.cache_skipped);
      product_root_dns_io_status_t io = product_root_dns_io_status (owner->io);
      product_root_dns_tcp_status_t tcp=product_root_dns_tcp_io_status(owner->tcp_io);
      if(owner->profile==2) {
        product_vpn_flow_stack_snapshot_t local=product_vpn_flow_stack_driver_tcp_status(i);
        vlib_cli_output(vm,"dns.vpn_tcp owner=%u generation=%llu ready=%u client_limit=8 clients=%u client_high_water=%u pending_limit=128 pending=%u pending_high_water=%u outputs=%u output_high_water=%u bytes=%llu byte_limit=2097152 high_water_bytes=%llu frames=%llu acknowledged=%llu failed=%llu local_sockets=0 reserved_bytes=%llu",
          i,(unsigned long long)owner->generation,valid && owner->route.enabled && root_dns_owner_current(owner,revision,network),
          local.local_tcp_sessions,local.local_tcp_peak,local.local_tcp_pending,local.local_tcp_pending_peak,
          local.local_tcp_outputs,local.local_tcp_output_peak,(unsigned long long)local.local_tcp_bytes,
          (unsigned long long)local.local_tcp_peak_bytes,(unsigned long long)local.local_tcp_frames,
          (unsigned long long)local.local_tcp_delivered,(unsigned long long)local.local_tcp_failed,
          (unsigned long long)product_vpn_flow_stack_driver_dns_reservation(i));
      } else
      vlib_cli_output(vm,"dns.proxy_tcp owner=%u generation=%llu ready=%u port=%u clients=%u client_limit=%u client_high_water=%u sockets=%u outputs=%u output_limit=%u pending=%u bytes=%llu byte_limit=%u frames=%llu delivered=%llu write_failed=%llu rejected=%llu identity_rejected=%llu admission_failed=%llu stale=%llu partial_expired=%llu error=%d",
        i,(unsigned long long)owner->generation,owner->tcp_io!=NULL,tcp.port,tcp.clients,PRODUCT_ROOT_DNS_TCP_CLIENTS,tcp.high_water_clients,
        tcp.sockets,tcp.outputs,PRODUCT_ROOT_DNS_TCP_OUTPUTS,tcp.pending,(unsigned long long)tcp.allocated_bytes,PRODUCT_ROOT_DNS_TCP_WORK_BYTES,
        (unsigned long long)tcp.frames,(unsigned long long)tcp.delivered,(unsigned long long)tcp.write_failed,
        (unsigned long long)tcp.rejected,(unsigned long long)owner->tcp_identity_rejected,(unsigned long long)owner->tcp_admission_failed,
        (unsigned long long)tcp.stale,(unsigned long long)tcp.partial_expired,tcp.last_error);
      vlib_cli_output (vm, "dns.proxy owner=%u generation=%llu enabled=%u socket_ready=%u route_ready=%u udp_state=%s stopping=%u route_revision=%llu network_revision=%llu upstream=%s port=%u transactions=%u transaction_high_water=%u transaction_limit=%u waiter_limit=%u sockets=%u socket_limit=%u raw_sockets=%u replies=%u reply_high_water=%u reply_limit=%u proxy_bytes=%llu socket_bytes=%llu owner_work_bound=%llu intercepted=%llu reply_admitted=%llu reply_rejected=%llu kernel_accepted=%llu write_failed=%llu return_policy_drop=%llu returned=%llu stale=%llu error=%u proxy_high_water_bytes=%llu socket_high_water_bytes=%llu upstream_socket_high_water=%u upstream_socket_limit=%u socket_byte_bound=%llu proxy_capacity=%llu socket_capacity=%llu socket_errors=%llu authorization_pending=%u authorized_udp=%u profile=%u",
        i, (unsigned long long) owner->generation, owner->route.enabled, io.udp_ready,
        valid && root_dns_owner_current (owner, revision, network),
        root_dns_udp_state (owner, &io), owner->stopping,
        (unsigned long long) owner->route_revision, (unsigned long long) owner->network_revision, address, owner->route.port,
        core.active, core.high_water, PRODUCT_DNS_PROXY_TRANSACTIONS, PRODUCT_DNS_PROXY_WAITERS,
        io.sockets + (owner->raw4 >= 0) + (owner->raw6 >= 0), PRODUCT_DNS_PROXY_SOCKETS,
        (owner->raw4 >= 0) + (owner->raw6 >= 0), owner->replies, owner->high_water_replies, ROOT_DNS_REPLIES,
        (unsigned long long) core.owned_bytes, (unsigned long long) io.allocated_bytes,
        (unsigned long long) PRODUCT_DNS_WORK_BYTES, (unsigned long long) owner->intercepted,
        (unsigned long long) owner->reply_admitted, (unsigned long long) owner->reply_rejected,
        (unsigned long long) owner->kernel_accepted, (unsigned long long) owner->write_failed,
        (unsigned long long) owner->return_policy_drop, (unsigned long long) owner->returned,
        (unsigned long long) (owner->stale + core.stale + io.stale), owner->last_error,
        (unsigned long long) core.high_water_bytes, (unsigned long long) io.high_water_bytes,
        io.high_water_sockets, 1U + PRODUCT_ROOT_DNS_TCP_SOCKETS,
        (unsigned long long) product_root_dns_io_reservation (), (unsigned long long) core.capacity,
        (unsigned long long) io.capacity, (unsigned long long) io.errors, io.authorizing, io.udp_ready, owner->profile);
    }
  return NULL;
}
VLIB_CLI_COMMAND (product_root_dns_status_command, static) = {
  .path = "show product dns proxy", .function = root_dns_status_cli,
  .short_help = "show product dns proxy: selected UDP/TCP routes, resources and delivery outcomes",
};
