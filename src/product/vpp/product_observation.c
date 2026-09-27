/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_observation.h"
#include "product_blocked_observation.h"
#include "product_flow_expiry.h"
#include <vlib/threads.h>
#include <vlib/file.h>
#include <vlib/unix/unix.h>
#include <vlibmemory/socket_api.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

#define NO_SLOT UINT32_MAX
#define FLUSH_US UINT64_C (1000000)
#define FLUSH_BUDGET 64
typedef struct {
  uint64_t incarnation, sequence, exported_packets, exported_bytes, due;
  uint64_t activity_utc_us, activity_mono_us;
  uint64_t packets[2], bytes[2];
  product_observation_attribution_t attribution[2];
  uint8_t last_direction, flow_direction;
  uint8_t clock_changed;
  uint32_t previous, next;
} observation_slot_t;
typedef struct {
  product_flow_runtime_t *runtime;
  observation_slot_t *slots;
  uint32_t capacity, head, tail;
  uint64_t generation;
} observation_owner_t;
static observation_owner_t owners[PRODUCT_OBSERVATION_OWNERS];
static product_blocked_observation_t *blocked[PRODUCT_OBSERVATION_OWNERS];
static uint32_t blocked_capacity;
static product_observation_transport_t *transport;
static u32 listener_file = ~0U, peer_file = ~0U, negotiation_file = ~0U;
static int negotiation_fd = -1;
static uid_t consumer_uid;
static int claimed;
static char socket_path[sizeof (((struct sockaddr_un *) 0)->sun_path)];

static void remove_pending (observation_owner_t *o, uint32_t slot) {
  observation_slot_t *s = &o->slots[slot];
  if (!s->due) return;
  if (s->previous != NO_SLOT) o->slots[s->previous].next = s->next;
  else o->head = s->next;
  if (s->next != NO_SLOT) o->slots[s->next].previous = s->previous;
  else o->tail = s->previous;
  s->due = 0;
}
static void export_record (unsigned owner, const product_flow_entry_t *entry,
                           uint32_t slot, uint8_t flags) {
  observation_owner_t *o = &owners[owner];
  if (!transport || !entry || slot >= o->capacity) return;
  observation_slot_t *s = &o->slots[slot];
  if (s->incarnation != entry->incarnation) {
    remove_pending (o, slot);
    *s = (observation_slot_t) { .incarnation = entry->incarnation };
    flags |= PRODUCT_OBSERVATION_CREATE;
  }
  if (s->sequence == UINT64_MAX) return; /* explicit lifetime cannot wrap */
  product_observation_record_t r = {
    .length = entry->key.ip_family == 4 ? 424 : 448,
    .version = PRODUCT_OBSERVATION_VERSION,
    .flags = flags | (s->clock_changed ? PRODUCT_OBSERVATION_CLOCK_CHANGED : 0),
    .owner = owner, .slot = slot, .uid = entry->uid,
    .generation = o->generation, .incarnation = entry->incarnation,
    .sequence = ++s->sequence, .first_seen = entry->first_seen, .last_seen = s->activity_mono_us,
    .policy_revision = entry->policy_revision, .winner = entry->winner_rule_id,
    .network = entry->network_context, .family = entry->key.ip_family,
    .protocol = entry->key.protocol, .origin_direction = entry->flow_origin_device_direction,
    .last_direction = s->last_direction, .flow_direction = s->flow_direction,
    .end_reason = entry->end_reason,
    .activity_utc_us = s->activity_utc_us,
  };
  memcpy (r.packets, s->packets, sizeof (r.packets));
  memcpy (r.bytes, s->bytes, sizeof (r.bytes));
  memcpy (r.attribution, s->attribution, sizeof (r.attribution));
  unsigned last_side = s->flow_direction == PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY;
  r.uid = s->attribution[last_side].uid; r.network = s->attribution[last_side].network;
  r.policy_revision = s->attribution[last_side].policy_revision;
  r.winner = s->attribution[last_side].winner;
  unsigned bytes = entry->key.ip_family == 4 ? 4 : 16;
  const uint8_t *orig = entry->origin_is_endpoint_a ? entry->key.address_a : entry->key.address_b;
  const uint8_t *reply = entry->origin_is_endpoint_a ? entry->key.address_b : entry->key.address_a;
  /* Canonical keys retain IPv4 in the final four bytes of the 16-byte field. */
  if (entry->key.ip_family == 4) { orig += 12; reply += 12; }
  memcpy (r.address, orig, bytes);
  memcpy (r.address + bytes, reply, bytes);
  if (entry->key.kind == PRODUCT_OWNER_KEY_L4_PORTS) {
    r.ports[0] = entry->origin_is_endpoint_a ? entry->key.transport.ports.a : entry->key.transport.ports.b;
    r.ports[1] = entry->origin_is_endpoint_a ? entry->key.transport.ports.b : entry->key.transport.ports.a;
  } else r.ports[0] = entry->key.transport.query.identifier;
  (void) product_observation_publish (transport, owner * 2, &r, r.length);
  /* A failed attempt is lost evidence, not a retry obligation. Later real
   * growth still carries the full cumulative value; loss remains in health. */
  s->exported_packets = s->packets[0] + s->packets[1];
  s->exported_bytes = s->bytes[0] + s->bytes[1];
  remove_pending (o, slot);
}
void product_observation_observed (vlib_main_t *vm, const product_flow_entry_t *entry,
                                   uint32_t slot,
                                   const product_observation_attribution_t *context) {
  unsigned owner = vlib_get_worker_index (vm->thread_index);
  if (owner >= PRODUCT_OBSERVATION_OWNERS || !entry || !transport || !context) return;
  observation_owner_t *o = &owners[owner];
  if (slot >= o->capacity) return;
  observation_slot_t *s = &o->slots[slot];
  int created = s->incarnation != entry->incarnation;
  if (created) {
    remove_pending (o, slot);
    *s = (observation_slot_t) { .incarnation = entry->incarnation };
  }
  unsigned side = entry->last_flow_direction == PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY;
  product_observation_attribution_t *a = &s->attribution[side];
  /* The Flow tracker already processed this packet to produce policy inputs.
   * Observation accounting is independent: export its exact previous cumulative
   * boundary before adding this packet under its final logical winner. */
  int changed = !a->segment || memcmp (&a->policy_generation, &context->policy_generation,
    sizeof (*a) - offsetof (product_observation_attribution_t, policy_generation));
  if (changed) {
    if (a->segment) export_record (owner, entry, slot, 0);
    uint64_t next = a->segment == UINT64_MAX ? UINT64_MAX : a->segment + 1;
    *a = *context;
    a->segment = next;
    a->start_packets = s->packets[side]; a->start_bytes = s->bytes[side];
    if (next == UINT64_MAX) a->valid = 0; /* no identifier reuse at exhaustion */
  }
  memcpy (s->packets, entry->side_packets, sizeof (s->packets));
  memcpy (s->bytes, entry->side_bytes, sizeof (s->bytes));
  s->last_direction = entry->last_device_direction;
  s->flow_direction = entry->last_flow_direction;
  /* Only real packet activity samples wall time. Pending flush and END retain
   * the sample even across a wall-clock step or a long idle timeout. */
  struct timespec wall;
  uint64_t utc = 0;
  if (!clock_gettime (CLOCK_REALTIME, &wall) && wall.tv_sec >= 0)
    utc = (uint64_t) wall.tv_sec * UINT64_C (1000000) + wall.tv_nsec / 1000;
  if (s->activity_utc_us && entry->last_seen >= s->activity_mono_us) {
    uint64_t expected = s->activity_utc_us + entry->last_seen - s->activity_mono_us;
    uint64_t difference = utc > expected ? utc - expected : expected - utc;
    if (difference > UINT64_C (1000000)) s->clock_changed = 1;
  }
  s->activity_utc_us = utc; s->activity_mono_us = entry->last_seen;
  a->activity_utc_us = utc;
  if (created || changed || entry->packets - s->exported_packets >= 32
      || entry->bytes - s->exported_bytes >= 65536) {
    export_record (owner, entry, slot, created ? PRODUCT_OBSERVATION_CREATE : 0);
  } else if (!s->due) {
    s->due = (uint64_t) (vlib_time_now (vm) * 1000000.0) + FLUSH_US;
    s->previous = o->tail; s->next = NO_SLOT;
    if (o->tail != NO_SLOT) o->slots[o->tail].next = slot;
    else o->head = slot;
    o->tail = slot;
  }
  product_flow_expiry_changed (vm);
}
void product_observation_end (vlib_main_t *vm, const product_flow_entry_t *entry,
                              uint32_t slot) {
  unsigned owner = vlib_get_worker_index (vm->thread_index);
  if (owner >= PRODUCT_OBSERVATION_OWNERS) return;
  export_record (owner, entry, slot, PRODUCT_OBSERVATION_END);
  product_flow_expiry_changed (vm);
}
static void blocked_emit (void *context, const product_observation_record_t *record) {
  unsigned owner = (unsigned) (uintptr_t) context;
  if (transport) (void) product_observation_publish (transport, owner * 2 + 1,
                                                     record, record->length);
}
void product_observation_blocked (vlib_main_t *vm,
  const product_owner_assignment_t *assignment, uint32_t uid, uint32_t network,
  uint8_t device_direction, uint32_t bytes,
  const product_observation_attribution_t *context) {
  unsigned owner = vlib_get_worker_index (vm->thread_index);
  if (owner >= PRODUCT_OBSERVATION_OWNERS || !transport || !blocked[owner]) return;
  uint64_t mono = (uint64_t) (vlib_time_now (vm) * 1000000.0);
  struct timespec wall;
  uint64_t utc = 0;
  if (!clock_gettime (CLOCK_REALTIME, &wall) && wall.tv_sec >= 0)
    utc = (uint64_t) wall.tv_sec * UINT64_C (1000000) + wall.tv_nsec / 1000;
  uint64_t old_misses = product_blocked_observation_misses (blocked[owner]);
  product_blocked_observation_observe (blocked[owner], assignment, uid, network,
                                      device_direction, bytes, mono, utc, context);
  if (product_blocked_observation_misses (blocked[owner]) != old_misses)
    product_observation_allocation_lost (transport, owner * 2 + 1);
  product_flow_expiry_changed (vm);
}
uint64_t product_observation_deadline (unsigned owner) {
  if (owner >= PRODUCT_OBSERVATION_OWNERS || !transport) return UINT64_MAX;
  uint64_t flow = owners[owner].head == NO_SLOT ? UINT64_MAX
    : owners[owner].slots[owners[owner].head].due;
  uint64_t early = product_blocked_observation_deadline (blocked[owner]);
  return flow < early ? flow : early;
}
void product_observation_flush_due (vlib_main_t *vm, uint64_t now) {
  unsigned owner = vlib_get_worker_index (vm->thread_index);
  if (owner >= PRODUCT_OBSERVATION_OWNERS || !transport) return;
  observation_owner_t *o = &owners[owner];
  for (unsigned i = 0; i < FLUSH_BUDGET && o->head != NO_SLOT; i++) {
    uint32_t slot = o->head;
    if (o->slots[slot].due > now) break;
    const product_flow_entry_t *entry = product_flow_runtime_entry (o->runtime, slot);
    if (entry && entry->linked && entry->incarnation == o->slots[slot].incarnation)
      export_record (owner, entry, slot, 0);
    else remove_pending (o, slot);
  }
  product_blocked_observation_flush_due (blocked[owner], now, FLUSH_BUDGET);
}
void product_observation_basic (vlib_main_t *vm, unsigned outcome, uint32_t bytes) {
  if (vm->thread_index)
    product_observation_account (transport, vlib_get_worker_index (vm->thread_index), outcome, bytes);
}
void product_observation_status (product_observation_status_t *status) {
  product_observation_transport_status (transport, status);
  status->blocked_capacity = blocked_capacity;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_OWNERS; i++) {
    status->blocked_active[i] = product_blocked_observation_active (blocked[i]);
    status->blocked_capacity_misses[i] = product_blocked_observation_misses (blocked[i]);
    status->blocked_retired[i] = product_blocked_observation_retired (blocked[i]);
  }
}

static void close_peer (void) {
  if (peer_file != ~0U) clib_file_del_by_index (&file_main, peer_file);
  peer_file = ~0U;
  struct itimerspec timer = {0};
  if (negotiation_fd >= 0) (void) timerfd_settime (negotiation_fd, 0, &timer, NULL);
}
static clib_error_t *negotiation_expired (clib_file_t *file) {
  uint64_t count;
  ssize_t received;
  do received = read (file->file_descriptor, &count, sizeof (count));
  while (received < 0 && errno == EINTR);
  if (received == sizeof (count) && !claimed) close_peer ();
  return NULL;
}

static clib_error_t *peer_ready (clib_file_t *file) {
  if (!claimed) {
    vlib_worker_thread_barrier_sync (vlib_get_main ());
    int result = product_observation_offer (transport, file->file_descriptor);
    vlib_worker_thread_barrier_release (vlib_get_main ());
    if (result > 0) return NULL;
    if (!result) {
      struct itimerspec timer = {0};
      (void) timerfd_settime (negotiation_fd, 0, &timer, NULL);
      claimed = 1; product_observation_connected (transport, 1); return NULL;
    }
  }
  product_observation_connected (transport, 0);
  close_peer ();
  return NULL;
}
static clib_error_t *accept_ready (clib_file_t *file) {
  int fd = accept4 (file->file_descriptor, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
  if (fd < 0) return NULL;
  struct ucred credential;
  socklen_t size = sizeof (credential);
  if (claimed || peer_file != ~0U || getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &credential, &size)
      || size != sizeof (credential) || credential.uid != consumer_uid) { close (fd); return NULL; }
  clib_file_t peer = { .file_descriptor = fd, .read_function = peer_ready,
    .error_function = peer_ready, .polling_thread_index = 0,
    .description = format (0, "product-observation-consumer%c", 0) };
  peer_file = clib_file_add (&file_main, &peer);
  /* Bound an authenticated but silent proposal without consuming the
   * generation's sole successful claim or involving packet workers. */
  struct itimerspec timer = { .it_value = { .tv_sec = 2 } };
  if (timerfd_settime (negotiation_fd, 0, &timer, NULL)) close_peer ();
  return NULL;
}
void product_observation_quiesce (void) {
  /* Graph lifecycle holds its worker barrier; consumer mapping is separately
   * owned by its memfd reference and is never reset or recycled here. */
  if (transport) product_observation_connected (transport, 0);
  close_peer ();
  if (negotiation_file != ~0U) clib_file_del_by_index (&file_main, negotiation_file);
  negotiation_file = ~0U; negotiation_fd = -1;
  if (listener_file != ~0U) clib_file_del_by_index (&file_main, listener_file);
  peer_file = listener_file = ~0U;
  if (socket_path[0]) unlink (socket_path);
  socket_path[0] = 0;
}
void product_observation_unbind (void) {
  product_observation_quiesce ();
  product_observation_transport_destroy (transport); transport = NULL;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_OWNERS; i++) {
    free (owners[i].slots); memset (&owners[i], 0, sizeof (owners[i]));
    owners[i].head = owners[i].tail = NO_SLOT;
    product_blocked_observation_destroy (blocked[i]); blocked[i] = NULL;
  }
  blocked_capacity = 0;
  claimed = 0;
}
int product_observation_bind (uint64_t generation, product_flow_runtime_t **runtimes) {
  product_observation_unbind ();
  if (!runtimes) return 1;
  uint32_t capacity = product_flow_runtime_snapshot (runtimes[0]).capacity;
  blocked_capacity = capacity < 1024 ? capacity : 1024;
  transport = product_observation_transport_create (generation, capacity);
  if (!transport) goto fail;
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_OWNERS; i++) {
    owners[i].runtime = runtimes[i]; owners[i].capacity = capacity; owners[i].generation = generation;
    owners[i].slots = calloc (capacity, sizeof (*owners[i].slots));
    blocked[i] = product_blocked_observation_create (
      blocked_capacity, generation, i, blocked_emit, (void *) (uintptr_t) i);
    if (!owners[i].slots || !blocked[i]
        || product_flow_runtime_snapshot (runtimes[i]).capacity != capacity) goto fail;
  }
  const char *api = (const char *) socket_main.socket_name;
  if (!api || strlen (api) + 4 >= sizeof (socket_path)) goto fail;
  char parent[sizeof (socket_path)];
  strcpy (parent, api);
  char *slash = strrchr (parent, '/');
  if (!slash || slash == parent) goto fail;
  *slash = 0;
  struct stat st;
  if (stat (parent, &st) || !S_ISDIR (st.st_mode) || (st.st_mode & 0022)) goto fail;
  consumer_uid = st.st_uid;
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  snprintf (address.sun_path, sizeof (address.sun_path), "%s.obs", api);
  int fd = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) goto fail;
  if (bind (fd, (struct sockaddr *) &address, sizeof (address))) { close (fd); goto fail; }
  strcpy (socket_path, address.sun_path);
  if ((geteuid () != consumer_uid && chown (socket_path, consumer_uid, st.st_gid))
      || chmod (socket_path, 0600) || listen (fd, 1)) { close (fd); goto fail; }
  clib_file_t listener = { .file_descriptor = fd, .read_function = accept_ready,
    .polling_thread_index = 0, .description = format (0, "product-observation-listener%c", 0) };
  listener_file = clib_file_add (&file_main, &listener);
  negotiation_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (negotiation_fd < 0) goto fail;
  clib_file_t deadline = { .file_descriptor = negotiation_fd,
    .read_function = negotiation_expired, .polling_thread_index = 0,
    .description = format (0, "product-observation-negotiation%c", 0) };
  negotiation_file = clib_file_add (&file_main, &deadline);
  return 1;
fail:
  product_observation_unbind ();
  return 0;
}

static clib_error_t *show_observation (vlib_main_t *vm, unformat_input_t *input,
                                      vlib_cli_command_t *command) {
  (void) input; (void) command;
  product_observation_status_t s;
  product_observation_status (&s);
  vlib_cli_output (vm, "observation.generation=%llu connected=%u bytes=%llu capacity=%u version=%u",
    (unsigned long long) s.generation, s.connected, (unsigned long long) s.mapping_bytes,
    s.flow_capacity, s.version);
  for (unsigned i = 0; i < PRODUCT_OBSERVATION_CHANNELS; i++) {
    product_observation_channel_status_t *c = &s.channels[i];
    vlib_cli_output (vm, "observation.channel=%u attempted=%llu published=%llu full=%llu consumed=%llu occupancy=%u capacity=%u allow_packets=%llu allow_bytes=%llu drop_packets=%llu drop_bytes=%llu runtime_packets=%llu runtime_bytes=%llu notifications=%llu notify_errors=%llu",
      i, (unsigned long long) c->attempted, (unsigned long long) c->published,
      (unsigned long long) c->full, (unsigned long long) c->consumed, c->occupancy, c->capacity,
      (unsigned long long) c->basic_packets[0], (unsigned long long) c->basic_bytes[0],
      (unsigned long long) c->basic_packets[1], (unsigned long long) c->basic_bytes[1],
      (unsigned long long) c->basic_packets[2], (unsigned long long) c->basic_bytes[2],
      (unsigned long long) c->notifications, (unsigned long long) c->notify_errors);
  }
  return NULL;
}
VLIB_CLI_COMMAND (product_observation_show, static) = {
  .path = "show product observation", .function = show_observation,
};
