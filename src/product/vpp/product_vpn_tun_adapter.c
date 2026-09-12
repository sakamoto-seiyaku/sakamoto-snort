/* SPDX-License-Identifier: Apache-2.0 */
/* One native TUN lane. Transport uses the owner-local Flow Stack interface;
 * this lane alone performs TUN read/write and owns completion obligations. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "product_vpn_tun_adapter.h"
#include "product_packet_graph.h"
#include "product_network_snapshot.h"
#include "product_vpn_flow_stack_driver.h"
#include "product_vpn_return_credit.h"
#include <vlib/file.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define TUN_PENDING PRODUCT_VPN_TUN_CAPTURE_CAPACITY

static u64 trace_monotonic_ns(void)
{
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value)) return 0;
  return (u64)value.tv_sec * 1000000000 + value.tv_nsec;
}
#define TUN_CONTROL_SLOTS 4
#define TUN_CONTROL_MAGIC 0x53323133U
#define TUN_CONTROL_ATTACH 1U
#define TUN_CONTROL_STOP 2U
#define TUN_CONTROL_BROKER 3U
#define TUN_CONTROL_ATTACH_UNKNOWN 4U

typedef struct { u64 token; u32 buffer; u8 active; } tun_pending_t;
typedef struct { u32 file; int fd; } tun_control_t;
/* Producer-private counters and token sequence; only the credit scalar is
 * updated by the TUN completion lane. No return packet enters a slot table. */
typedef struct {
  product_vpn_return_credit_t credit;
  u64 next_token, packets, submitted, output_calls, copy_calls, copy_bytes;
  u64 fault_allocate_at, fault_reject_at, fault_stale_at;
} __attribute__((aligned(CLIB_CACHE_LINE_BYTES))) tun_return_owner_t;
static tun_return_owner_t returns[PRODUCT_VPN_RETURN_WORKERS];
/* Written only with workers at the control barrier; workers only read. */
static f64 return_hold_until[PRODUCT_VPN_RETURN_WORKERS];
static struct {
  vlib_main_t *vm;
  u64 generation, next_token, captured, submitted, completed;
  u64 policy_drops, runtime_drops, transport_unavailable, errors, rejected;
  u64 transport_unsupported;
  u64 tun_write_attempts, tun_writes, tun_write_failed;
  u64 stack_accepted_originals, stack_rejected_originals;
  u64 fault_write_at;
  u64 pregraph_returns, local, remote;
  u32 pending, test_uid, tun_file, listener_file, snapshot_interface;
  int tun_fd, listener_fd;
  u8 enabled, draining, test_uid_known;
  char path[sizeof (((struct sockaddr_un *)0)->sun_path)];
  tun_pending_t obligations[TUN_PENDING];
  tun_control_t controls[TUN_CONTROL_SLOTS];
} tun = { .tun_fd = -1, .listener_fd = -1,
          .tun_file = ~0U, .listener_file = ~0U };

int product_vpn_tun_validation_enabled (void) {
  const char *profile = getenv ("SAKAMOTO_RUNTIME_PROFILE");
  const char *validation = getenv ("SAKAMOTO_PRODUCT_VPN_GRAPH_VALIDATION");
  return profile && !strcmp (profile, "vpn") && validation && !strcmp (validation, "1");
}
u64 product_vpn_tun_attached (void) { return tun.tun_fd >= 0; }
u64 product_vpn_tun_captured (void) { return tun.captured; }

int product_vpn_tun_return_held(vlib_main_t *vm,
  const product_packet_completion_frame_t *completion)
{
  const product_adapter_obligation_t *o = &completion->obligation;
  return o->kind == PRODUCT_ADAPTER_OBLIGATION_VPN_TUN &&
    o->queue_generation == tun.generation && o->packet_id &&
    o->packet_id <= PRODUCT_VPN_RETURN_WORKERS &&
    (completion->flags & PRODUCT_COMPLETION_FLOW_STACK_RETURN) &&
    return_hold_until[o->packet_id - 1] > vlib_time_now(vm);
}

product_vpn_flow_stack_output_result_t product_vpn_tun_submit_return(
  vlib_main_t *vm, const product_vpn_flow_stack_span_t *spans, unsigned count,
  size_t total, const product_platform_packet_facts_t *platform,
  uint64_t generation, uint64_t serial, uint64_t epoch)
{
  if (!vm || !vm->thread_index ||
      vlib_get_worker_index(vm->thread_index) >= PRODUCT_VPN_RETURN_WORKERS)
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED;
  u32 owner_index = vlib_get_worker_index(vm->thread_index);
  tun_return_owner_t *owner = &returns[owner_index];
  if (++owner->output_calls == owner->fault_stale_at) {
    owner->fault_stale_at = 0;
    fprintf(stderr, "s237 event=fault_stale_output current_generation=%llu supplied_generation=%llu serial=%llu\n",
      (unsigned long long)generation, (unsigned long long)(generation - 1), (unsigned long long)serial);
    --generation;
  }
  if (__atomic_load_n(&tun.draining, __ATOMIC_ACQUIRE) ||
      tun.tun_fd < 0 || generation != tun.generation || !platform ||
      platform->provenance != PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN ||
      platform->direction != PRODUCT_PACKET_DIRECTION_INPUT || !spans ||
      !count || count > 64 || !total || total > vlib_buffer_get_default_data_size(vm))
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED;
  size_t length = 0;
  for (unsigned i = 0; i < count; ++i) {
    if (spans[i].length > total - length || (!spans[i].data && spans[i].length))
      return PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED;
    length += spans[i].length;
  }
  if (length != total) return PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED;
  ++owner->packets;
  if (owner->packets == owner->fault_allocate_at) {
    owner->fault_allocate_at = 0;
    fprintf(stderr, "s237 event=fault_output_allocation generation=%llu serial=%llu\n",
      (unsigned long long)generation, (unsigned long long)serial);
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY;
  }
  /* Disjoint token ranges make traces unambiguous without a global allocator.
   * packet_id is VPN-private credit-owner identity, not an NFQUEUE packet ID.
   * Origin placement remains the sole TUN lane, never the generating owner. */
  if (owner->next_token == ((1ULL << 62) - 1) ||
      !product_vpn_return_credit_take(&owner->credit, generation))
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY;
  u64 token = (1ULL << 63) | ((u64)owner_index << 62) | ++owner->next_token;
  u32 bi;
  if (vlib_buffer_alloc(vm, &bi, 1) != 1) {
    if (product_vpn_return_credit_release(&owner->credit, generation)) abort();
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY;
  }
  vlib_buffer_t *buffer = vlib_get_buffer(vm, bi);
  vlib_buffer_reset(buffer);
  clib_memset(buffer->opaque, 0, sizeof(buffer->opaque));
  clib_memset(buffer->opaque2, 0, sizeof(buffer->opaque2));
  u8 *bytes = vlib_buffer_get_current(buffer);
  size_t offset = 0;
  for (unsigned i = 0; i < count; ++i) {
    if (spans[i].length) clib_memcpy_fast(bytes + offset, spans[i].data, spans[i].length);
    offset += spans[i].length;
  }
  buffer->current_length = total;
  ++owner->copy_calls;
  owner->copy_bytes += total;
  product_adapter_obligation_t obligation = {.token = token,
    .queue_generation = generation, .kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN,
    .origin_worker = 0, .origin_lane = 0, .packet_id = owner_index + 1};
  if (serial <= product_packet_graph_trace_limit()) {
    fprintf(stderr, "s237 event=return_copy thread=%u tls=%u generation=%llu serial=%llu buffer=%u token=%llu spans=%u bytes=%zu uid=%u availability=%u context=%u epoch=%llu\n",
      vm->thread_index, vlib_get_thread_index(), (unsigned long long)generation,
      (unsigned long long)serial, bi, (unsigned long long)token, count, total,
      platform->uid, platform->availability, platform->network_context_id, (unsigned long long)epoch);
    /* Bounded validation witness, before native graph ownership transfers.
     * This reads the already-copied buffer; it adds no payload storage. */
    flockfile(stderr);
    fprintf(stderr, "s240 event=return_wire thread=%u tls=%u owner=%u generation=%llu serial=%llu buffer=%u token=%llu bytes=%zu mono_ns=%llu raw=",
      vm->thread_index, vlib_get_thread_index(), owner_index, (unsigned long long)generation,
      (unsigned long long)serial, bi, (unsigned long long)token, total,
      (unsigned long long)trace_monotonic_ns());
    for (size_t i = 0; i < total; ++i) fprintf(stderr, "%02x", bytes[i]);
    fprintf(stderr, "\n"); funlockfile(stderr);
  }
  int rejected = owner->packets == owner->fault_reject_at;
  if (rejected) {
    owner->fault_reject_at = 0;
    fprintf(stderr, "s237 event=fault_pre_accept generation=%llu serial=%llu buffer=%u token=%llu\n",
      (unsigned long long)generation, (unsigned long long)serial, bi, (unsigned long long)token);
  }
  if (rejected || !product_packet_graph_submit_external(vm, bi, platform, &obligation)) {
    vlib_buffer_free(vm, &bi, 1);
    if (product_vpn_return_credit_release(&owner->credit, generation)) abort();
    fprintf(stderr, "s237 event=return_rejected_free generation=%llu serial=%llu buffer=%u token=%llu\n",
      (unsigned long long)generation, (unsigned long long)serial, bi, (unsigned long long)token);
    return PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED;
  }
  /* Native scheduling now owns the independent buffer; never touch it again. */
  ++owner->submitted;
  return PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED;
}

int product_vpn_tun_complete_from_graph (vlib_main_t *vm, u32 bi,
                          const product_packet_completion_frame_t *frame) {
  const product_adapter_obligation_t *o = &frame->obligation;
  tun_pending_t *pending = &tun.obligations[o->token % TUN_PENDING];
  if (o->kind != PRODUCT_ADAPTER_OBLIGATION_VPN_TUN
      || o->queue_generation != tun.generation || o->origin_lane != 0
      || o->origin_worker != 0 || vm->thread_index != vlib_get_worker_thread_index (0)
      || (frame->flags & PRODUCT_COMPLETION_REPLAY_PROBE)) {
    tun.rejected++;
    return 0;
  }
  int returned = o->packet_id != 0;
  if (returned) {
    if (o->packet_id > PRODUCT_VPN_RETURN_WORKERS ||
        !(frame->flags & PRODUCT_COMPLETION_FLOW_STACK_RETURN) ||
        (o->token >> 62) != (2U + o->packet_id - 1) ||
        !product_vpn_return_credit_used(&returns[o->packet_id - 1].credit)) {
      ++tun.rejected;
      return 0;
    }
  } else {
    if ((frame->flags & PRODUCT_COMPLETION_FLOW_STACK_RETURN) ||
        !pending->active || pending->token != o->token || pending->buffer != bi) {
      ++tun.rejected;
      return 0;
    }
    pending->active = 0;
    tun.pending--;
  }
  tun.completed++;
  if (frame->producer_thread == vm->thread_index) tun.local++; else tun.remote++;
  int policy_drop = frame->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME
    && (frame->runtime_drop_reason == PRODUCT_PACKET_DROP_POLICY_GATE
        || frame->runtime_drop_reason == PRODUCT_PACKET_DROP_POLICY_L4);
  int unsupported = frame->terminal_intent == PRODUCT_PACKET_INTENT_PASS_ADAPTER
    && (frame->flags & PRODUCT_COMPLETION_TRANSPORT_UNSUPPORTED);
  int admitted = frame->flow_stack_result == PRODUCT_VPN_FLOW_STACK_ACCEPTED + 1;
  const char *outcome = "NOT_ATTEMPTED";
  if (policy_drop) tun.policy_drops++;
  else if (frame->terminal_intent == PRODUCT_PACKET_INTENT_DROP_RUNTIME) tun.runtime_drops++;
  else if (returned) {
    ++tun.tun_write_attempts;
    vlib_buffer_t *buffer = vlib_get_buffer(vm, bi);
    size_t write_length = buffer->current_length;
    if (tun.tun_write_attempts == tun.fault_write_at) {
      tun.fault_write_at = 0;
      write_length = 0; /* Real TUN syscall with deliberately invalid packet length. */
      fprintf(stderr, "s237 event=fault_tun_write generation=%llu token=%llu fd=%d\n",
        (unsigned long long)tun.generation, (unsigned long long)o->token, tun.tun_fd);
    }
    ssize_t written = tun.tun_fd >= 0
      ? write(tun.tun_fd, vlib_buffer_get_current(buffer), write_length) : -1;
    if (written == buffer->current_length) { ++tun.tun_writes; outcome = "TUN_WRITE_SUCCEEDED"; }
    else { ++tun.tun_write_failed; ++tun.errors; outcome = "TUN_WRITE_FAILED"; }
  } else if (admitted) { ++tun.stack_accepted_originals; outcome = "ADMITTED"; }
  else if (frame->flow_stack_result) { ++tun.stack_rejected_originals; outcome = "INPUT_REJECTED"; }
  else if (unsupported) { tun.transport_unsupported++; outcome = "UNSUPPORTED"; }
  else { tun.transport_unavailable++; outcome = "UNAVAILABLE"; }
  /* The shared origin consumer frees the VPP buffer after this callback. No
   * TUN write is a valid completion for an outbound TUN-origin packet. */
  if (frame->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s213 event=completion source=%s generation=%llu token=%llu buffer=%u thread=%u producer=%u intent=%u drop_reason=%u policy_drop=%u transport_unavailable=%u pending=%u flow_stack_result=%u transport_outcome=%s processing_bypass_reason=%u policy_verdict=%s\n",
      returned ? "FLOW_STACK_RETURN" : "TUN_CAPTURED",
      (unsigned long long) tun.generation, (unsigned long long) o->token, bi,
      vm->thread_index, frame->producer_thread, frame->terminal_intent,
      frame->runtime_drop_reason, policy_drop,
      !strcmp(outcome, "UNAVAILABLE"), tun.pending, frame->flow_stack_result, outcome,
      frame->processing_bypass_reason, policy_drop ? "DROP"
        : frame->terminal_intent == PRODUCT_PACKET_INTENT_PASS_ADAPTER ? "ALLOW" : "NOT_EVALUATED");
  return 1;
}

void product_vpn_tun_return_freed(vlib_main_t *vm, u32 bi,
                                  const product_packet_completion_frame_t *frame)
{
  const product_adapter_obligation_t *o = &frame->obligation;
  if (!o->packet_id) return; /* Original TUN capture uses its existing ledger. */
  if (vm->thread_index != vlib_get_worker_thread_index(0) ||
      o->packet_id > PRODUCT_VPN_RETURN_WORKERS ||
      (frame->flags & PRODUCT_COMPLETION_REPLAY_PROBE) ||
      product_vpn_return_credit_release(&returns[o->packet_id - 1].credit,
                                         o->queue_generation)) abort();
  if (frame->flags & PRODUCT_COMPLETION_TRACE)
    fprintf(stderr, "s239 event=return_credit_released owner=%u thread=%u generation=%llu token=%llu buffer=%u in_use=%u capacity=%u after_native_free=1\n",
      o->packet_id - 1, vm->thread_index, (unsigned long long)o->queue_generation,
      (unsigned long long)o->token, bi,
      product_vpn_return_credit_used(&returns[o->packet_id - 1].credit),
      PRODUCT_VPN_RETURN_CAPACITY);
}

static clib_error_t *tun_read_ready (clib_file_t *file) {
  vlib_main_t *vm = vlib_get_main ();
  if (vm->thread_index != vlib_get_worker_thread_index (0)
      || file->file_descriptor != (u32) tun.tun_fd) return clib_error_return (0, "TUN lane mismatch");
  if (__atomic_load_n(&tun.draining, __ATOMIC_ACQUIRE)) return 0;
  for (u32 budget = 0; budget < 64 && tun.pending < TUN_PENDING; ++budget) {
    u64 token = tun.next_token + 1;
    if (!token || token >= (1ULL << 63)) {
      __atomic_store_n(&tun.draining, 1, __ATOMIC_RELEASE); tun.errors++; return 0;
    }
    tun_pending_t *pending = &tun.obligations[token % TUN_PENDING];
    if (pending->active) return 0;
    u32 bi;
    if (vlib_buffer_alloc (vm, &bi, 1) != 1) return 0;
    vlib_buffer_t *buffer = vlib_get_buffer (vm, bi);
    vlib_buffer_reset (buffer);
    clib_memset (buffer->opaque, 0, sizeof (buffer->opaque));
    clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
    u32 capacity = vlib_buffer_get_default_data_size (vm);
    u8 *data = vlib_buffer_get_current (buffer);
    ssize_t length = read (tun.tun_fd, data, capacity);
    if (length <= 0) {
      int error = errno;
      vlib_buffer_free (vm, &bi, 1);
      if (length < 0 && (error == EAGAIN || error == EWOULDBLOCK || error == EINTR)) return 0;
      tun.errors++; __atomic_store_n(&tun.draining, 1, __ATOMIC_RELEASE); return 0;
    }
    tun.captured++;
    if ((u32) length >= capacity) {
      /* A full read buffer cannot establish absence of TUN truncation. */
      tun.pregraph_returns++; tun.transport_unavailable++;
      vlib_buffer_free (vm, &bi, 1); continue;
    }
    buffer->current_length = (u16) length;
    tun.next_token = token;
    *pending = (tun_pending_t){ .token = token, .buffer = bi, .active = 1 };
    tun.pending++;
    product_platform_packet_facts_t platform = {
      .uid = tun.test_uid,
      .availability = tun.test_uid_known ? PRODUCT_PLATFORM_UID_KNOWN : 0,
      .direction = PRODUCT_PACKET_DIRECTION_OUTPUT,
      .provenance = PRODUCT_PACKET_PROVENANCE_VPN_TUN,
    };
    /* The fd attachment identifies our interface outside the packet path.
     * Its event classification is independent of packet Linux ifindex, which
     * remains explicitly unavailable for VPN v1. No profile/TUN guess. */
    platform.network_context_id = product_network_snapshot_context (tun.snapshot_interface);
    if (platform.network_context_id) platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
    product_adapter_obligation_t obligation = {
      .token = token, .queue_generation = tun.generation,
      .kind = PRODUCT_ADAPTER_OBLIGATION_VPN_TUN, .origin_worker = 0, .origin_lane = 0,
    };
    if (tun.captured <= product_packet_graph_trace_limit ()) {
      const sakamoto_product_network_snapshot_t *snapshot = product_network_snapshot_current ();
      fprintf (stderr, "s218 event=packet_snapshot generation=%llu token=%llu revision=%llu event_elapsed_ns=%llu attachment_interface=%u ifindex=0 context=%u availability=%u\n",
        (unsigned long long) tun.generation, (unsigned long long) token,
        (unsigned long long) snapshot->revision, (unsigned long long) snapshot->event_elapsed_ns,
        tun.snapshot_interface, platform.network_context_id, platform.availability);
      flockfile (stderr);
      fprintf (stderr, "s213 event=capture source=TUN_CAPTURED generation=%llu token=%llu buffer=%u thread=%u tls=%u lane=0 bytes=%zd uid_source=CONTROLLED_TEST_PROVIDER uid=%u mono_ns=%llu raw=",
        (unsigned long long) tun.generation, (unsigned long long) token, bi,
        vm->thread_index, vlib_get_thread_index (), length, tun.test_uid,
        (unsigned long long)trace_monotonic_ns());
      for (ssize_t i = 0; i < length; ++i) fprintf (stderr, "%02x", data[i]);
      fprintf (stderr, "\n"); funlockfile (stderr);
    }
    if (!product_packet_graph_submit_external (vm, bi, &platform, &obligation)) {
      pending->active = 0; tun.pending--; tun.pregraph_returns++;
      tun.transport_unavailable++;
      vlib_buffer_free (vm, &bi, 1);
    } else tun.submitted++;
  }
  return 0;
}

static int tun_attach (int fd, u32 uid, int uid_known) {
  struct ifreq interface;
  clib_memset (&interface, 0, sizeof (interface));
  if (tun.tun_fd >= 0 || __atomic_load_n(&tun.draining, __ATOMIC_ACQUIRE) || uid == UINT32_MAX
      || (product_vpn_flow_stack_driver_enabled() && !product_vpn_flow_stack_driver_ready())
      || ioctl (fd, TUNGETIFF, &interface) < 0
      || !(interface.ifr_flags & IFF_TUN) || !(interface.ifr_flags & IFF_NO_PI)) return 0;
  int flags = fcntl (fd, F_GETFL);
  if (flags < 0 || fcntl (fd, F_SETFL, flags | O_NONBLOCK) < 0
      || fcntl (fd, F_SETFD, FD_CLOEXEC) < 0) return 0;
  tun.snapshot_interface = if_nametoindex (interface.ifr_name);
  tun.test_uid = uid_known ? uid : 0;
  tun.test_uid_known = uid_known;
  tun.tun_fd = fd;
  clib_file_t file = {0};
  file.read_function = tun_read_ready;
  file.polling_thread_index = vlib_get_worker_thread_index (0);
  file.file_descriptor = fd;
  file.description = format (0, "sakamoto-product-tun%c", 0);
  tun.tun_file = clib_file_add (&file_main, &file);
  fprintf (stderr, "s213 event=attach generation=%llu fd=%d interface=%s origin_thread=%u uid_source=CONTROLLED_TEST_PROVIDER uid=%u direct_egress_ready=0\n",
    (unsigned long long) tun.generation, fd, interface.ifr_name,
    vlib_get_worker_thread_index (0), uid);
  return 1;
}

static int tun_stop (void) {
  __atomic_store_n(&tun.draining, 1, __ATOMIC_RELEASE);
  clib_memset(return_hold_until, 0, sizeof(return_hold_until));
  product_vpn_flow_stack_driver_quiesce();
  product_packet_graph_quiesce_reassembly (tun.vm);
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i)
    if (product_vpn_return_credit_used(&returns[i].credit)) return 1;
  if (tun.pending || product_packet_graph_buffer_debt ()
      || product_packet_graph_obligation_debt ()
      || product_packet_graph_completion_frame_debt ()
      || !product_vpn_flow_stack_driver_stopped()) return 1;
  if (tun.tun_file != ~0U) clib_file_del_by_index (&file_main, tun.tun_file);
  tun.tun_file = ~0U; tun.tun_fd = -1;
  product_network_snapshot_stop ();
  tun.snapshot_interface = 0;
  product_packet_graph_stop_external (tun.vm);
  fprintf (stderr, "s213 event=stop generation=%llu pending=0 buffers=0 frames=0 obligations=0 tun_fd=-1 captured=%llu completed=%llu pregraph_returns=%llu\n",
    (unsigned long long) tun.generation, (unsigned long long) tun.captured,
    (unsigned long long) tun.completed, (unsigned long long) tun.pregraph_returns);
  return 0;
}

static clib_error_t *tun_control_read (clib_file_t *file) {
  tun_control_t *client = uword_to_pointer (file->private_data, tun_control_t *);
  u8 payload[20];
  union { struct cmsghdr align; u8 bytes[CMSG_SPACE (4 * sizeof (int))]; } control = {0};
  struct iovec iov = { .iov_base = payload, .iov_len = sizeof (payload) };
  struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
    .msg_control = control.bytes, .msg_controllen = sizeof (control.bytes) };
  ssize_t length = recvmsg (client->fd, &msg, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
  if (length < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return 0;
  int fds[4], n_fds = 0;
  if (length >= 0) for (struct cmsghdr *c = CMSG_FIRSTHDR (&msg); c; c = CMSG_NXTHDR (&msg, c)) {
    if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS || c->cmsg_len < CMSG_LEN (0)) continue;
    size_t count = (c->cmsg_len - CMSG_LEN (0)) / sizeof (int);
    for (size_t i = 0; i < count; ++i) {
      int fd; memcpy (&fd, (u8 *) CMSG_DATA (c) + i * sizeof (fd), sizeof (fd));
      if (n_fds < 4) fds[n_fds++] = fd; else close (fd);
    }
  }
  u32 magic = 0, command = 0, uid = 0; u64 generation = 0;
  if (length == sizeof (payload)) {
    memcpy (&magic, payload, 4); memcpy (&command, payload + 4, 4);
    memcpy (&generation, payload + 8, 8); memcpy (&uid, payload + 16, 4);
    magic = ntohl (magic); command = ntohl (command); uid = ntohl (uid);
    generation = clib_net_to_host_u64 (generation);
  }
  u32 result = 2;
  int reply_sent = 0;
  if (length == sizeof (payload) && !(msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))
      && magic == TUN_CONTROL_MAGIC && generation == tun.generation) {
    vlib_worker_thread_barrier_sync (tun.vm);
    if ((command == TUN_CONTROL_ATTACH || command == TUN_CONTROL_ATTACH_UNKNOWN)
        && n_fds == 1 && tun_attach (fds[0], uid, command == TUN_CONTROL_ATTACH)) {
      fds[0] = -1; result = 0;
    } else if (command == TUN_CONTROL_STOP && n_fds == 0) result = tun_stop ();
    else if (command == TUN_CONTROL_BROKER && n_fds == 0) {
      int duplicate = fcntl(client->fd, F_DUPFD_CLOEXEC, 0);
      if (duplicate >= 0 && !product_vpn_flow_stack_driver_attach(duplicate, uid)) result = 0;
      /* The retained channel cannot emit broker requests before this ACK. */
      u32 reply = htonl(result);
      (void)send(client->fd, &reply, sizeof(reply), MSG_DONTWAIT | MSG_NOSIGNAL);
      reply_sent = 1;
    }
    vlib_worker_thread_barrier_release (tun.vm);
  }
  for (int i = 0; i < n_fds; ++i) if (fds[i] >= 0) close (fds[i]);
  u32 reply = htonl (result);
  if (!reply_sent) (void) send (client->fd, &reply, sizeof (reply), MSG_DONTWAIT | MSG_NOSIGNAL);
  clib_file_del_by_index (&file_main, client->file);
  client->file = ~0U; client->fd = -1;
  return 0;
}

static clib_error_t *tun_control_accept (clib_file_t *file) {
  for (u32 budget = 0; budget < TUN_CONTROL_SLOTS; ++budget) {
    int fd = accept4 (file->file_descriptor, 0, 0, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (fd < 0) return 0;
    struct ucred peer; socklen_t size = sizeof (peer);
    if (getsockopt (fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) < 0 || peer.uid != geteuid ()) {
      close (fd); continue;
    }
    tun_control_t *client = 0;
    for (u32 i = 0; i < TUN_CONTROL_SLOTS; ++i) if (tun.controls[i].fd < 0) { client = &tun.controls[i]; break; }
    if (!client) { close (fd); continue; }
    client->fd = fd;
    clib_file_t entry = {0};
    entry.read_function = tun_control_read;
    entry.polling_thread_index = 0;
    entry.file_descriptor = fd;
    entry.private_data = pointer_to_uword (client);
    entry.description = format (0, "sakamoto-tun-control-client%c", 0);
    client->file = clib_file_add (&file_main, &entry);
  }
  return 0;
}

int product_vpn_tun_start (vlib_main_t *vm, u64 generation) {
  const char *runtime = getenv ("SAKAMOTO_VPP_RUNTIME_DIR");
  if (!product_vpn_tun_validation_enabled () || !runtime || tun.enabled || !generation) return 0;
  if (product_packet_graph_worker_count() != PRODUCT_VPN_RETURN_WORKERS) return 0;
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i)
    if (product_vpn_return_credit_init(&returns[i].credit, generation,
                                       PRODUCT_VPN_RETURN_CAPACITY)) return 0;
  int n = snprintf (tun.path, sizeof (tun.path), "%s/tun-control.sock", runtime);
  if (n <= 0 || (size_t) n >= sizeof (tun.path)) return 0;
  int fd = socket (AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0;
  struct sockaddr_un address = { .sun_family = AF_UNIX };
  memcpy (address.sun_path, tun.path, n + 1);
  if (bind (fd, (struct sockaddr *) &address, sizeof (address)) < 0 || listen (fd, 4) < 0) {
    close (fd); return 0;
  }
  if (!product_packet_graph_start_external (vm, generation)) {
    close (fd); unlink (tun.path); return 0;
  }
  if (!product_vpn_flow_stack_driver_start(vm, generation)) {
    product_packet_graph_stop_external(vm);
    close(fd); unlink(tun.path); return 0;
  }
  product_network_snapshot_start (generation);
  tun.vm = vm; tun.generation = generation; tun.enabled = 1; tun.listener_fd = fd;
  for (u32 i = 0; i < TUN_CONTROL_SLOTS; ++i) tun.controls[i] = (tun_control_t){ .file = ~0U, .fd = -1 };
  clib_file_t entry = {0};
  entry.read_function = tun_control_accept;
  entry.polling_thread_index = 0; entry.file_descriptor = fd;
  entry.description = format (0, "sakamoto-tun-control%c", 0);
  tun.listener_file = clib_file_add (&file_main, &entry);
  return 1;
}

static clib_error_t *tun_status (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *command) {
  (void) input; (void) command;
  u64 packets = 0, submitted = 0, copy_calls = 0, copy_bytes = 0;
  for (u32 i = 0; i < PRODUCT_VPN_RETURN_WORKERS; ++i) {
    tun_return_owner_t *owner = &returns[i];
    packets += owner->packets; submitted += owner->submitted;
    copy_calls += owner->copy_calls; copy_bytes += owner->copy_bytes;
    vlib_cli_output(vm, "tun.return owner=%u generation=%llu capacity=%u in_use=%u packets=%llu submitted=%llu",
      i, (unsigned long long)owner->credit.generation, owner->credit.capacity,
      product_vpn_return_credit_used(&owner->credit),
      (unsigned long long)owner->packets, (unsigned long long)owner->submitted);
  }
  vlib_cli_output (vm, "tun.transport unsupported=%llu unavailable=%llu",
    (unsigned long long) tun.transport_unsupported, (unsigned long long) tun.transport_unavailable);
  vlib_cli_output(vm, "tun.flow_stack enabled=%u ready=%u return_packets=%llu return_submitted=%llu write_attempts=%llu write_succeeded=%llu write_failed=%llu accepted_originals=%llu rejected_originals=%llu",
    product_vpn_flow_stack_driver_enabled(), product_vpn_flow_stack_driver_ready(),
    (unsigned long long)packets, (unsigned long long)submitted,
    (unsigned long long)tun.tun_write_attempts, (unsigned long long)tun.tun_writes,
    (unsigned long long)tun.tun_write_failed, (unsigned long long)tun.stack_accepted_originals,
    (unsigned long long)tun.stack_rejected_originals);
  vlib_cli_output(vm, "tun.copies calls=%llu bytes=%llu",
    (unsigned long long)copy_calls, (unsigned long long)copy_bytes);
  vlib_cli_output (vm, "tun.status generation=%llu enabled=%u attached=%u fd=%d origin_thread=%u draining=%u captured=%llu submitted=%llu completed=%llu pending=%u policy_drops=%llu runtime_drops=%llu transport_unavailable=%llu pregraph_returns=%llu errors=%llu rejected=%llu local=%llu remote=%llu frames=%llu buffers=%llu obligations=%llu tun_writes=%llu nfq_verdicts=0 direct_egress_ready=0",
    (unsigned long long) tun.generation, tun.enabled, tun.tun_fd >= 0, tun.tun_fd,
    vlib_get_worker_thread_index (0), __atomic_load_n(&tun.draining, __ATOMIC_ACQUIRE),
    (unsigned long long) tun.captured, (unsigned long long) tun.submitted,
    (unsigned long long) tun.completed, tun.pending,
    (unsigned long long) tun.policy_drops, (unsigned long long) tun.runtime_drops,
    (unsigned long long) tun.transport_unavailable, (unsigned long long) tun.pregraph_returns,
    (unsigned long long) tun.errors, (unsigned long long) tun.rejected,
    (unsigned long long) tun.local, (unsigned long long) tun.remote,
    (unsigned long long) product_packet_graph_completion_frame_debt (),
    (unsigned long long) product_packet_graph_buffer_debt (),
    (unsigned long long) product_packet_graph_obligation_debt (),
    (unsigned long long) tun.tun_writes);
  return 0;
}
VLIB_CLI_COMMAND (product_tun_status_command, static) = {
  .path = "show product tun", .function = tun_status,
};

static clib_error_t *tun_fault(vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  (void)command;
  u32 after = 0;
  u32 owner_index = 0;
  (void)unformat(input, "owner %u", &owner_index);
  if (owner_index >= PRODUCT_VPN_RETURN_WORKERS)
    return clib_error_return(0, "invalid return owner");
  tun_return_owner_t *owner = &returns[owner_index];
  u64 *target = NULL, current = 0;
  if (!product_vpn_tun_validation_enabled() || !product_vpn_flow_stack_driver_ready())
    return clib_error_return(0, "HEV validation must be active");
  if (unformat(input, "output-alloc %u", &after)) {
    target = &owner->fault_allocate_at; current = owner->packets;
  } else if (unformat(input, "pre-accept %u", &after)) {
    target = &owner->fault_reject_at; current = owner->packets;
  } else if (unformat(input, "write %u", &after)) {
    target = &tun.fault_write_at; current = tun.tun_write_attempts;
  } else if (unformat(input, "stale-output %u", &after)) {
    target = &owner->fault_stale_at; current = owner->output_calls;
  } else if (unformat(input, "input-reject %u", &after)) {
    if (unformat_check_input(input) != UNFORMAT_END_OF_INPUT ||
        product_vpn_flow_stack_driver_reject_after(owner_index, after))
      return clib_error_return(0, "invalid or already armed input fault");
    vlib_cli_output(vm, "tun.fault armed=input-reject after=%u", after);
    return NULL;
  }
  if (!target || !after || after > 64 || *target ||
      unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return(0, "expected output-alloc|pre-accept|write|input-reject|stale-output <1..64>");
  *target = current + after;
  vlib_cli_output(vm, "tun.fault armed=1 after=%u at=%llu", after, (unsigned long long)*target);
  return NULL;
}
VLIB_CLI_COMMAND(product_tun_fault_command, static) = {
  .path = "product tun fault", .function = tun_fault,
};

static clib_error_t *tun_return_hold(vlib_main_t *vm, unformat_input_t *input,
                                    vlib_cli_command_t *command)
{
  (void)command;
  u32 owner = ~0U, milliseconds = 0;
  if (!product_vpn_tun_validation_enabled() || !product_vpn_flow_stack_driver_ready() ||
      tun.draining || !unformat(input, "%u %u", &owner, &milliseconds) ||
      owner >= PRODUCT_VPN_RETURN_WORKERS || milliseconds > 10000 ||
      unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return(0, "expected active validation: <owner> <0..10000 ms>");
  return_hold_until[owner] = milliseconds ? vlib_time_now(vm) + milliseconds * .001 : 0;
  vlib_cli_output(vm, "tun.return_hold owner=%u milliseconds=%u generation=%llu",
    owner, milliseconds, (unsigned long long)tun.generation);
  return 0;
}
VLIB_CLI_COMMAND(product_tun_return_hold_command, static) = {
  .path = "product tun return-hold", .function = tun_return_hold,
};

static clib_error_t *tun_stop_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command) {
  (void) input; (void) command;
  if (!tun.enabled) return clib_error_return (0, "TUN validation is inactive");
  int result = tun_stop ();
  vlib_cli_output (vm, "tun.stop result=%d pending=%u fd=%d", result, tun.pending, tun.tun_fd);
  return 0;
}
VLIB_CLI_COMMAND (product_tun_stop_command, static) = {
  .path = "product tun stop", .function = tun_stop_cli,
};

static clib_error_t *tun_exit (vlib_main_t *vm) {
  (void) vm;
  if (!tun.enabled) return 0;
  if (tun.tun_file != ~0U) clib_file_del_by_index (&file_main, tun.tun_file);
  if (tun.listener_file != ~0U) clib_file_del_by_index (&file_main, tun.listener_file);
  for (u32 i = 0; i < TUN_CONTROL_SLOTS; ++i)
    if (tun.controls[i].file != ~0U) clib_file_del_by_index (&file_main, tun.controls[i].file);
  unlink (tun.path);
  return 0;
}
VLIB_MAIN_LOOP_EXIT_FUNCTION (tun_exit);
