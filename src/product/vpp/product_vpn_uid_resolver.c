/* SPDX-License-Identifier: Apache-2.0 */
#include "product_vpn_uid_resolver.h"
#include "product_vpn_tun_adapter.h"
#include "product_packet_graph.h"
#include <vlib/file.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define UID_OWNERS PRODUCT_VPN_RETURN_WORKERS
#define UID_CACHE_SLOTS 256U
#define UID_MAGIC 0x53323839U
#define UID_REQUEST 1U
#define UID_RESPONSE 2U
#define UID_PENDING_NS UINT64_C(2500000000)
#define UID_RETRY_NS UINT64_C(100000000)
#define UID_KNOWN_NS UINT64_C(2000000000)
#define UID_REFRESH_NS UINT64_C(250000000)
#define UID_OWNER_RATE_NS UINT64_C(10000000)

typedef struct {
  u8 family, protocol;
  u16 local_port, remote_port;
  u8 local[16], remote[16];
} uid_tuple_t;

typedef struct {
  uid_tuple_t tuple;
  product_owner_assignment_t assignment;
  u64 request, expires_ns, last_request_ns, incarnation;
  u32 uid;
  u8 state; /* 0 empty, 1 pending, 2 known, 3 unavailable */
  u8 request_pending;
} uid_cache_slot_t;

typedef struct {
  u64 generation, next_request, requests, completions, known, unknown;
  u64 next_send_ns;
  product_flow_runtime_t *pool;
  vlib_main_t *vm;
  int fd;
  u32 file;
  u8 ready;
  uid_cache_slot_t cache[UID_CACHE_SLOTS];
} uid_owner_t;

/* Fixed-size, big-endian SEQPACKET envelopes; no live packet bytes cross. */
typedef struct __attribute__((packed)) {
  u32 magic, kind;
  u64 generation, request;
  u8 family, protocol;
  u16 local_port, remote_port;
  u8 local[16], remote[16];
  u16 reserved;
} uid_request_t;
typedef struct __attribute__((packed)) {
  u32 magic, kind;
  u64 generation, request;
  u32 uid;
} uid_response_t;
_Static_assert(sizeof(uid_request_t) == 64, "UID request wire size");
_Static_assert(sizeof(uid_response_t) == 28, "UID response wire size");

static uid_owner_t owners[UID_OWNERS];
static u32 active_owner_count(void) { return product_packet_graph_worker_count(); }

static u64 now_ns (void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
  return (u64)value.tv_sec * UINT64_C(1000000000) + value.tv_nsec;
}

static u32 slot_index (const uid_tuple_t *key)
{
  const u8 *bytes = (const u8 *)key;
  u64 hash = UINT64_C(14695981039346656037);
  for (size_t i = 0; i < sizeof(*key); ++i)
    hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
  return (u32)(hash & (UID_CACHE_SLOTS - 1));
}

static void close_owner (uid_owner_t *owner)
{
  __atomic_store_n(&owner->ready, 0, __ATOMIC_RELEASE);
  if (owner->file != ~0U) clib_file_del_by_index(&file_main, owner->file);
  else if (owner->fd >= 0) close(owner->fd);
  owner->file = ~0U;
  owner->fd = -1;
}

static clib_error_t *read_ready (clib_file_t *file)
{
  u32 index = (u32)file->private_data;
  if (index >= active_owner_count()) return 0;
  uid_owner_t *owner = &owners[index];
  if (owner->fd != file->file_descriptor) return 0;
  for (u32 budget = 0; budget < 32; ++budget) {
    u8 bytes[sizeof(uid_response_t) + 1];
    ssize_t n = recv(owner->fd, bytes, sizeof(bytes), MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
    uid_response_t response;
    if (n == sizeof(response)) memcpy(&response, bytes, sizeof(response));
    if (n != sizeof(response) || ntohl(response.magic) != UID_MAGIC ||
        ntohl(response.kind) != UID_RESPONSE ||
        clib_net_to_host_u64(response.generation) != owner->generation) {
      close_owner(owner); return 0;
    }
    u64 request = clib_net_to_host_u64(response.request);
    uid_cache_slot_t *slot = &owner->cache[request & (UID_CACHE_SLOTS - 1)];
    if (!slot->request_pending || slot->request != request) continue;
    u64 timestamp_us = owner->vm ? (u64)(vlib_time_now(owner->vm) * 1000000.0) : 0;
    if (!timestamp_us || product_flow_entry_current_incarnation(owner->pool,
        &slot->assignment, owner->generation, timestamp_us) != slot->incarnation) {
      memset(slot, 0, sizeof(*slot));
      continue;
    }
    u32 uid = ntohl(response.uid);
    u64 now = now_ns();
    int resolved_known = uid != UINT32_MAX;
    int retired = 0;
    u32 tuple_hash = slot_index(&slot->tuple);
    slot->request_pending = 0;
    slot->state = resolved_known ? 2 : 3;
    slot->uid = uid;
    slot->expires_ns = now + (slot->state == 2 ? UID_KNOWN_NS : UID_RETRY_NS);
    if (slot->state == 2) {
      int enrichment = product_flow_entry_enrich_uid(owner->pool, &slot->assignment,
          owner->generation, slot->incarnation, uid, timestamp_us);
      if (enrichment == 2 || enrichment < 0) {
        /* This tuple now belongs to a different app. The old admitted flow
         * and its cached verdict end before any future packet can use it. */
        memset(slot, 0, sizeof(*slot));
        retired = 1;
      }
    }
    owner->completions++;
    if (resolved_known) owner->known++; else owner->unknown++;
    if (owner->completions <= 64)
      fprintf(stderr, "s289 event=uid_result owner=%u generation=%llu request=%llu tuple_hash=%u known=%u uid=%u retired=%u\n",
        index, (unsigned long long)owner->generation, (unsigned long long)request,
        tuple_hash, resolved_known, resolved_known ? uid : 0, retired);
  }
  return 0;
}

void product_vpn_uid_resolver_start (u64 generation)
{
  if (!active_owner_count() || active_owner_count() > UID_OWNERS) return;
  for (u32 i = 0; i < active_owner_count(); ++i) {
    owners[i] = (uid_owner_t){.generation = generation, .fd = -1, .file = ~0U};
  }
}

int product_vpn_uid_resolver_attach (int fd, u32 index)
{
  if (fd < 0 || index >= active_owner_count() || !product_vpn_tun_product_mode() ||
      !owners[index].generation || owners[index].fd >= 0) {
    if (fd >= 0) close(fd);
    return -1;
  }
  int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fd); return -1;
  }
  clib_file_t entry = {.file_descriptor = fd,
    .polling_thread_index = vlib_get_worker_thread_index(index),
    .private_data = index, .read_function = read_ready,
    .error_function = read_ready,
    .description = format(0, "product-vpn-uid-owner-%u%c", index, 0)};
  owners[index].file = clib_file_add(&file_main, &entry);
  if (owners[index].file == ~0U) { close(fd); return -1; }
  owners[index].fd = fd;
  __atomic_store_n(&owners[index].ready, 1, __ATOMIC_RELEASE);
  return 0;
}

int product_vpn_uid_resolver_ready (void)
{
  if (!product_vpn_tun_product_mode() || !active_owner_count()
      || active_owner_count() > UID_OWNERS) return 0;
  for (u32 i = 0; i < active_owner_count(); ++i)
    if (!__atomic_load_n(&owners[i].ready, __ATOMIC_ACQUIRE)) return 0;
  return 1;
}

static int owner_for (vlib_main_t *vm, product_flow_runtime_t *pool,
  const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, u64 generation, uid_owner_t **result)
{
  if (!vm || !pool || !assignment || !assignment->valid || !facts || !generation ||
      !product_vpn_uid_resolver_ready() || vm->thread_index == 0 ||
      facts->l4_status != PRODUCT_PACKET_L4_COMPLETE ||
      (facts->protocol != 6 && facts->protocol != 17) ||
      (facts->ip_family != 4 && facts->ip_family != 6)) return 0;
  u32 index = vlib_get_worker_index(vm->thread_index);
  if (index >= active_owner_count() || assignment->execution_owner != index) return 0;
  uid_owner_t *owner = &owners[index];
  if (owner->generation != generation) return 0;
  owner->pool = pool;
  owner->vm = vm;
  *result = owner;
  return 1;
}

static uid_tuple_t tuple_for (const product_packet_facts_t *facts)
{
  uid_tuple_t key = { .family = facts->ip_family, .protocol = facts->protocol,
    .local_port = facts->source_port, .remote_port = facts->destination_port };
  memcpy(key.local, facts->source_address, 16);
  memcpy(key.remote, facts->destination_address, 16);
  return key;
}

static void cached_identity (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, product_platform_packet_facts_t *platform,
  u64 generation)
{
  uid_owner_t *owner;
  if (!platform || platform->provenance != PRODUCT_PACKET_PROVENANCE_VPN_TUN) return;
  /* TUN ingress alone supplies no original DNS caller. Only this owner's
   * current Android tuple result may qualify a later packet; an old flag,
   * diagnostic UID or a system resolver socket must never qualify it. */
  platform->availability &= ~PRODUCT_PLATFORM_DNS_APP_RELIABLE;
  if (!owner_for(vm, pool, assignment, facts, generation, &owner)) return;
  uid_tuple_t key = tuple_for(facts);
  u32 index_in_cache = slot_index(&key);
  uid_cache_slot_t *slot = &owner->cache[index_in_cache];
  u64 now = now_ns();
  u64 incarnation = product_flow_entry_current_incarnation(pool, assignment,
      generation, (u64)(vlib_time_now(vm) * 1000000.0));
  /* A fresh TCP SYN starts a new candidate even if an old tuple still exists. */
  if (facts->protocol == 6 && (facts->tcp_flags & 0x02) &&
      !(facts->tcp_flags & 0x10)) return;
  if (slot->state && incarnation && slot->incarnation == incarnation &&
      !memcmp(&slot->tuple, &key, sizeof(key))) {
    if (slot->request_pending && now >= slot->last_request_ns + UID_PENDING_NS) {
      /* A broker timeout is unknown, never a reason to keep asserting the
       * previous application's UID or to destroy the still-live FlowEntry. */
      slot->request_pending = 0;
      slot->state = 3;
      slot->uid = UINT32_MAX;
      slot->expires_ns = now + UID_RETRY_NS;
    }
    if (slot->state == 2 && (facts->protocol == 6 ||
        (now < slot->expires_ns && !slot->request_pending))) {
      /* A live TCP incarnation survives an idle UID-cache interval. A new
       * SYN is handled above; UDP has no equivalent reuse signal. */
      platform->uid = slot->uid;
      platform->availability |= PRODUCT_PLATFORM_UID_KNOWN;
      /* Android's normal per-user App range identifies an app-owned socket.
       * System/netd UIDs identify only the delegate, not its IPC caller.
       * Isolated and other special UID ranges remain conservative Unknown. */
      if (slot->uid % 100000U >= 10000U && slot->uid % 100000U <= 19999U)
        platform->availability |= PRODUCT_PLATFORM_DNS_APP_RELIABLE;
    }
  }
}

static void request_identity (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, u64 generation, u64 incarnation)
{
  uid_owner_t *owner;
  if (!incarnation || !owner_for(vm, pool, assignment, facts, generation, &owner) ||
      product_flow_entry_current_incarnation(pool, assignment, generation,
        (u64)(vlib_time_now(vm) * 1000000.0)) != incarnation) return;
  uid_tuple_t key = tuple_for(facts);
  u32 index_in_cache = slot_index(&key);
  uid_cache_slot_t *slot = &owner->cache[index_in_cache];
  u64 now = now_ns();
  if (now < owner->next_send_ns) return;
  if (slot->state && slot->incarnation == incarnation &&
      !memcmp(&slot->tuple, &key, sizeof(key))) {
    if (slot->request_pending && now < slot->last_request_ns + UID_PENDING_NS) return;
    if (slot->state == 3 && now < slot->expires_ns) return;
    if (slot->state != 1 && now < slot->last_request_ns + UID_REFRESH_NS) return;
  }
  if (owner->next_request >= (UINT64_MAX >> 8)) return;
  u64 request = (++owner->next_request << 8) | index_in_cache;
  uid_request_t message = {.magic = htonl(UID_MAGIC), .kind = htonl(UID_REQUEST),
    .generation = clib_host_to_net_u64(generation),
    .request = clib_host_to_net_u64(request), .family = key.family,
    .protocol = key.protocol, .local_port = htons(key.local_port),
    .remote_port = htons(key.remote_port)};
  memcpy(message.local, key.local, 16);
  memcpy(message.remote, key.remote, 16);
  if (send(owner->fd, &message, sizeof(message), MSG_DONTWAIT | MSG_NOSIGNAL)
      != sizeof(message)) return;
  owner->next_send_ns = now + UID_OWNER_RATE_NS;
  if (slot->state && slot->incarnation == incarnation &&
      !memcmp(&slot->tuple, &key, sizeof(key)) && slot->state == 2) {
    slot->request = request;
    slot->last_request_ns = now;
    slot->request_pending = 1;
  } else {
    *slot = (uid_cache_slot_t){.tuple = key, .assignment = *assignment,
      .request = request, .expires_ns = now + UID_PENDING_NS,
      .last_request_ns = now, .incarnation = incarnation, .state = 1,
      .request_pending = 1};
  }
  owner->requests++;
}

int product_vpn_uid_resolver_identify (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, product_platform_packet_facts_t *platform,
  u64 generation)
{
  if (!vm || !platform || platform->provenance != PRODUCT_PACKET_PROVENANCE_VPN_TUN) return 0;
  /* Product mode identifies device-origin packets only; graph validation identifies every
   * TUN packet with its controlled UID. */
  if (product_vpn_tun_product_mode() && platform->direction != PRODUCT_PACKET_DIRECTION_OUTPUT) return 0;
  cached_identity(vm, pool, assignment, facts, platform, generation);
  /* A known UID, from this owner's Android result or a controlled provider, belongs to
   * the Flow incarnation that is current for this tuple now, never to a retired one. */
  if ((platform->availability & PRODUCT_PLATFORM_UID_KNOWN) && pool && assignment && assignment->valid) {
    u64 now_us = (u64)(vlib_time_now(vm) * 1000000.0);
    (void) product_flow_entry_enrich_uid(pool, assignment, generation,
      product_flow_entry_current_incarnation(pool, assignment, generation, now_us),
      platform->uid, now_us);
  }
  return 1;
}

void product_vpn_uid_resolver_flow_processed (vlib_main_t *vm,
  product_flow_runtime_t *pool, const product_owner_assignment_t *assignment,
  const product_packet_facts_t *facts, const product_platform_packet_facts_t *platform,
  u64 generation, u64 observed_incarnation)
{
  if (!vm || !pool || !platform || !assignment || !assignment->valid ||
      platform->provenance != PRODUCT_PACKET_PROVENANCE_VPN_TUN ||
      platform->direction != PRODUCT_PACKET_DIRECTION_OUTPUT) return;
  /* The packet's own Flow if it was observed, otherwise the current admitted Flow for the
   * tuple. A packet dropped before any Flow exists has none, and creates no query state. */
  u64 incarnation = observed_incarnation ? observed_incarnation
    : product_flow_entry_current_incarnation(pool, assignment, generation,
        (u64)(vlib_time_now(vm) * 1000000.0));
  request_identity(vm, pool, assignment, facts, generation, incarnation);
}

void product_vpn_uid_resolver_stop (void)
{
  for (u32 i = 0; i < UID_OWNERS; ++i) {
    /* Graph-validation VPN has no UID broker: start() was never called.
     * Zero-initialized file index 0 is not an owned clib_file_t. */
    if (!owners[i].generation) continue;
    close_owner(&owners[i]);
    owners[i].generation = 0;
    owners[i].pool = 0;
    owners[i].vm = 0;
    memset(owners[i].cache, 0, sizeof(owners[i].cache));
  }
}
