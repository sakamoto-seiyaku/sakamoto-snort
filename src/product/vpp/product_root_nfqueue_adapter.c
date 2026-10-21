/* SPDX-License-Identifier: Apache-2.0 */

/*
 * VPP-native Root packet I/O. Dual-stack Q2 per family maps each family
 * lane 0/1 to worker 0/1. The shared graph parses and selects its
 * owner; the origin Completion Frame consumer alone completes admitted NFQ
 * obligations. Wider hooks/protocols and queue-pressure qualification remain
 * separate acceptance work.
 */

#include "product_root_nfqueue_adapter.h"
#include "product_network_snapshot.h"
#include "product_root_receive_pool.h"
#include "product_diagnostic_hex.h"

#include "product_packet_graph.h"
#include "product_packet_batch.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <unistd.h>

#include <vlib/file.h>

#define PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE 176
#define PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES 4
#define PRODUCT_ROOT_NFQUEUE_MAX_LANES PRODUCT_ROOT_COMPLETION_MAX_LANES
#define PRODUCT_ROOT_NFQUEUE_MAX_NETLINK 8192
#define PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY PRODUCT_ROOT_COMPLETION_CAPACITY
#define PRODUCT_ROOT_NFQUEUE_DEFAULT_MAXLEN PRODUCT_ROOT_DEFAULT_QUEUE_MAXLEN
#define PRODUCT_ROOT_NFQUEUE_READ_BUDGET PRODUCT_ROOT_READ_BUDGET_LIMIT
#define PRODUCT_ROOT_NFQUEUE_RCVBUF_REQUEST_LIMIT (1024U * 1024U)
#define PRODUCT_ROOT_NFQUEUE_FLAGS (NFQA_CFG_F_UID_GID | NFQA_CFG_F_FAIL_OPEN)
#ifndef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE
#define SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE 2
#endif
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE < 1 || SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE > 3
#error "Root verdict sender must be scalar(1), sendmmsg(2) or packed(3)"
#endif

typedef enum
{
  PRODUCT_ROOT_NFQUEUE_FAULT_NONE,
  PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY,
  PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN,
  PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE,
  PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN,
  PRODUCT_ROOT_NFQUEUE_FAULT_DUPLICATE_COMPLETION,
  PRODUCT_ROOT_NFQUEUE_FAULT_STALE_COMPLETION,
} product_root_nfqueue_fault_mode_t;

typedef struct
{
  u32 packet_id;
  u32 uid;
  u8 hook;
  u8 ip_family;
  u8 protocol;
  u8 uid_present;
  u8 identity_present;
  u8 indev_present, outdev_present;
  u32 indev, outdev;
  u32 skb_info, captured_length;
  u8 skb_info_present, captured_length_present;
  u8 *payload;
  u32 payload_length;
} product_root_nfqueue_packet_t;

/* Bounded adapter ledger only: no packet or platform facts. It remembers
 * completed identities until the slot is reused, preventing non-last replay. */
typedef struct
{
  product_packet_completion_frame_t completion;
  u32 buffer_index;
  u8 active;
  u8 receive_slot;
} product_root_nfqueue_pending_t;

_Static_assert (sizeof (product_root_nfqueue_pending_t) == 40, "bounded completion identity ledger");

typedef struct
{
  int fd;
  uword clib_file_index;
  u32 queue_id;
  u32 lane_index;
  u32 family_lane;
  u32 worker_index;
  u32 ip_family;
  u64 generation;
  u64 next_obligation_token;
  u32 pending_count;
  /* Two bounded 64-slot banks. The second bank is usable only when the
   * quiescent diagnostic also reserves 128 normal receive buffers. */
  u64 pending_active_slots, pending_displaced_slots;
  u64 pending_active_slots_high, pending_displaced_slots_high;
  u32 pending_high_water, loan_high_water;
  u8 draining;
  u8 receive_paused; /* Explicit CLI pressure probe; does not close verdict fd. */
  u8 identity_fault;
  u8 verdict_fault_next; /* CLI-only one-shot, real sendto(MSG_OOB) rejection. */
  u8 verdict_id_fault_next; /* CLI-only wrong middle ID in an eligible window. */
  u8 verdict_id_probe_expired; /* Sticky until this queue generation retires. */
  u8 listener_fault_after_submit; /* CLI-only: one real admitted packet. */
  u16 withheld_count;
  u16 withheld[PRODUCT_ROOT_RECEIVE_MAX_TOTAL];
  product_root_receive_pool_t receive_pool;
  u32 receive_allocated;
  u64 reserve_accepts, reserve_losses, identity_losses;
  u64 receive_datagrams, receive_returns, ingress_accepts;
  u64 pending_collisions, pending_full_rejections, pending_duplicate_rejections;
  u64 ingress_normal_exhausted, ingress_envelope_rejected;
  u64 ingress_completion_rejected, ingress_graph_rejected;
  u32 queue_flags, queue_maxlen;
  /* Diagnostic, generation-local tuning; no additional packet credit. */
  u32 read_budget, rcvbuf_requested, rcvbuf_effective;
  u64 read_callbacks, read_empty_callbacks, read_budget_exits;
  u64 read_callback_datagrams, read_callback_max;
  u64 recv_calls, recv_eagain, recv_eintr, recv_enobufs;
  u32 last_cpu, callback_thread, callback_tls;
  u32 last_packet_id, last_queue_id, last_uid, last_ip_family;
  u32 last_protocol, last_hook, last_uid_known;
  u64 packets_seen;
  u64 packets_submitted;
  u64 verdict_attempts;
  /* Origin graph syscall counters; ingress bypass/configuration are separate. */
  u64 graph_sendto_calls, graph_sendmmsg_calls, graph_sendmmsg_requested;
  u64 graph_sendmmsg_sent, graph_sendmmsg_partial_calls;
  u64 graph_verdict_windows, graph_verdict_window_messages;
  u64 graph_packed_calls, graph_packed_requested, graph_packed_sent;
  u64 graph_packed_bytes, graph_packed_mixed_calls;
  u32 graph_packed_max_messages;
  u64 control_replies, control_errors, control_malformed;
  u32 control_first_error, control_first_sequence;
  u32 control_last_error, control_last_sequence;
  u64 verdict_succeeded;
#ifdef SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS
  u64 policy_qualified_succeeded;
  u64 policy_qualified_matched_allow_succeeded;
  u64 policy_qualified_matched_drop_succeeded;
#endif
  u64 verdict_failed;
  u64 duplicate_completion_drops;
  u64 internal_settlements;
  u64 buffer_returns;
  u64 origin_local_completions;
  u64 origin_remote_completions;
  u64 receive_overruns;
  u32 last_verdict_packet_id;
  u8 verdict_packet_id_known;
  u8 socket_ready;
  u8 listener_ready;
  product_root_nfqueue_pending_t pending[2 * PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY];
} product_root_nfqueue_lane_t;

typedef struct
{
  vlib_main_t *vlib_main;
  u32 queue_id;
  u32 queue_last;
  u32 lane_count;
  u32 uid_owner;
  u64 generation;
  u32 pending_count;
  u32 replay_count;
  u64 packets_seen;
  u64 packets_submitted;
  u64 verdict_attempts;
  u64 verdict_succeeded;
  u64 verdict_failed;
  u64 internal_settlements;
  u64 buffer_returns;
  u64 origin_local_completions;
  u64 origin_remote_completions;
  u64 input_packets;
  u64 output_packets;
  u64 ipv4_packets;
  u64 ipv6_packets;
  u64 tcp_packets;
  u64 udp_packets;
  u64 uid_known_packets;
  u64 uid_unknown_packets;
  u64 verdict_failed_definite;
  u64 verdict_outcome_unknown;
  u64 ingress_identity_missing;
  u64 graph_submit_fail_opens;
  u64 non_owner_bypasses;
  u32 last_lane;
  u64 duplicate_completion_drops;
  u64 stale_completion_drops;
  u32 ready_lane_mask;
  product_root_nfqueue_fault_mode_t fault_mode;
  u32 facts_fault; /* Explicit CLI-only attribute fault; reset per generation. */
  u8 hook_ready;
  u8 available;
  u8 fault_latched;
  u8 fault_pending;
  u32 fault_retry_count;
  u32 fault_drain_steps;
  u32 fault_lane;
  int fault_errno;
  int fault_socket_fd;
  int fault_timer_fd;
  uword fault_timer_file;
  char fault_socket_path[sizeof (((struct sockaddr_un *) 0)->sun_path)];
  char fault_event[160];
  product_root_nfqueue_lane_t lanes[PRODUCT_ROOT_NFQUEUE_MAX_LANES];
} product_root_nfqueue_main_t;

static __thread int product_root_nfqueue_last_errno;
static __thread ssize_t product_root_nfqueue_last_send_result;

static product_root_nfqueue_main_t product_root_nfqueue_main = {
  .queue_id = PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE,
  .queue_last =
    PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE + PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES - 1,
  .lane_count = PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES,
  .uid_owner = UINT32_MAX,
  .fault_socket_fd = -1,
  .fault_timer_fd = -1,
  .fault_timer_file = ~0,
};

/* The fault socket is a one-way control signal, separate from lossy packet
 * observations. It is idle while Root is healthy. A failed nonblocking send
 * arms only a fault-time one-shot retry. */
static void
product_root_nfqueue_send_fault (product_root_nfqueue_main_t *nm)
{
  if (!__atomic_load_n (&nm->fault_pending, __ATOMIC_ACQUIRE))
    return;
  ssize_t sent = nm->fault_socket_fd >= 0
    ? send (nm->fault_socket_fd, nm->fault_event,
            strlen (nm->fault_event), MSG_DONTWAIT | MSG_NOSIGNAL) : -1;
  if (sent == (ssize_t) strlen (nm->fault_event))
    {
      __atomic_store_n (&nm->fault_pending, 0, __ATOMIC_RELEASE);
      return;
    }
  if (nm->fault_timer_fd >= 0)
    {
      struct itimerspec retry = { .it_value = { .tv_nsec = 100000000 } };
      (void) timerfd_settime (nm->fault_timer_fd, 0, &retry, 0);
    }
}

static clib_error_t *
product_root_nfqueue_fault_retry (clib_file_t *file)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u64 expirations;
  (void) read ((int) file->file_descriptor, &expirations, sizeof (expirations));
  if (file->private_data == nm->generation)
    {
      if (!__atomic_load_n (&nm->fault_pending, __ATOMIC_ACQUIRE)) return 0;
      if (nm->fault_retry_count++ < 30)
        product_root_nfqueue_send_fault (nm);
      else
        {
          /* A broken control receiver cannot leave a partial Root runtime
           * reporting protection forever. The main thread performs the same
           * bounded native quiesce as Java before an orderly process exit;
           * the existing exit monitor then audits OS-reclaimed resources. */
          vlib_main_t *vm = vlib_get_main ();
          vlib_worker_thread_barrier_sync (vm);
          int drained = product_root_nfqueue_adapter_stop_step (vm, nm->generation);
          vlib_worker_thread_barrier_release (vm);
          if (drained == 1 || ++nm->fault_drain_steps >= 20)
            {
              fprintf (stderr, "s296 event=root_fault_transport_failed generation=%llu lane=%u errno=%d native_drain=%d\n",
                (unsigned long long) nm->generation, nm->fault_lane,
                nm->fault_errno, drained);
              vlib_exit_with_status (vm, 70);
            }
          else if (nm->fault_timer_fd >= 0)
            {
              struct itimerspec retry = { .it_value = { .tv_nsec = 100000000 } };
              (void) timerfd_settime (nm->fault_timer_fd, 0, &retry, 0);
            }
        }
    }
  return 0;
}

static void
product_root_nfqueue_mark_lane_fault (product_root_nfqueue_main_t *nm,
                                      product_root_nfqueue_lane_t *lane,
                                      const char *reason, int fault_errno)
{
  if (!lane || lane->generation != nm->generation)
    return;
  u32 lane_index = lane->lane_index < nm->lane_count && lane->lane_index < 32
    ? lane->lane_index : 0;
  lane->draining = 1; /* Existing admitted obligations still use this FD. */
  if (lane->listener_ready && lane->clib_file_index != ~0)
    {
      /* Disable a level-triggered EPOLLERR without losing the verdict FD.
       * The bounded stop path closes it after admitted obligations settle. */
      clib_file_t *file = clib_file_get (&file_main, lane->clib_file_index);
      file->dont_close = 1;
      clib_file_del_by_index (&file_main, lane->clib_file_index);
      lane->clib_file_index = ~0;
      lane->listener_ready = 0;
    }
  if (lane->lane_index == lane_index)
    __atomic_fetch_and (&nm->ready_lane_mask, ~(1U << lane_index), __ATOMIC_RELEASE);
  else
    __atomic_store_n (&nm->ready_lane_mask, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->available, 0, __ATOMIC_RELEASE);
  if (__atomic_exchange_n (&nm->fault_latched, 1, __ATOMIC_ACQ_REL))
    return;
  nm->fault_lane = lane_index;
  nm->fault_errno = fault_errno;
  snprintf (nm->fault_event, sizeof (nm->fault_event),
            "SAKAMOTO_ROOT_FAULT_V1 generation=%llu lane=%u errno=%d reason=%s",
            (unsigned long long) nm->generation, lane_index,
            fault_errno, reason);
  __atomic_store_n (&nm->fault_pending, 1, __ATOMIC_RELEASE);
  product_root_nfqueue_send_fault (nm);
  fprintf (stderr, "s296 event=root_lane_fault %s\n", nm->fault_event);
}

static int
product_root_nfqueue_transient_errno (int value)
{
  return value == EAGAIN || value == EWOULDBLOCK || value == EINTR
         || value == ENOBUFS;
}

static u32
product_root_nfqueue_queue_from_env (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE");
  char *end = 0;
  unsigned long parsed;

  if (value == 0 || *value == '\0')
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE;

  errno = 0;
  parsed = strtoul (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0
      || parsed > UINT16_MAX)
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_QUEUE;
  return (u32) parsed;
}

static u32
product_root_nfqueue_lanes_from_env (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES");
  char *end = 0;
  unsigned long parsed;

  if (value == 0 || *value == '\0')
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES;

  errno = 0;
  parsed = strtoul (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed == 0
      || parsed > PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    return PRODUCT_ROOT_NFQUEUE_DEFAULT_LANES;
  return (u32) parsed;
}

static int
product_root_nfqueue_maxlen_from_env (u32 *maxlen)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_MAXLEN");
  char *end = 0;
  *maxlen = PRODUCT_ROOT_NFQUEUE_DEFAULT_MAXLEN;
  if (!value || !*value)
    return 1;
  errno = 0;
  unsigned long parsed = strtoul (value, &end, 10);
  if (errno || end == value || *end || *value == '-'
      || !parsed || parsed > 65536)
    return 0;
  *maxlen = (u32) parsed;
  return 1;
}

static int
product_root_nfqueue_uid_from_env (u32 *uid_owner)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID");
  char *end = 0;
  unsigned long parsed;

  if (uid_owner == 0 || value == 0 || *value == '\0')
    return 0;

  errno = 0;
  parsed = strtoul (value, &end, 10);
  /* UID zero is a real Linux endpoint identity; UINT32_MAX is unknown. */
  if (errno != 0 || end == value || *end != '\0' || *value == '-'
      || parsed >= UINT32_MAX)
    return 0;
  *uid_owner = (u32) parsed;
  return 1;
}

static product_root_nfqueue_fault_mode_t
product_root_nfqueue_fault_mode_from_env (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_ROOT_NFQUEUE_FAULT_MODE");

  if (value == 0 || *value == '\0' || strcmp (value, "none") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_NONE;
  if (strcmp (value, "missing_identity") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY;
  if (strcmp (value, "graph_submit_fail_open") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN;
  if (strcmp (value, "verdict_failed_definite") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE;
  if (strcmp (value, "verdict_outcome_unknown") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN;
  if (strcmp (value, "duplicate_completion") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_DUPLICATE_COMPLETION;
  if (strcmp (value, "stale_completion") == 0)
    return PRODUCT_ROOT_NFQUEUE_FAULT_STALE_COMPLETION;
  return PRODUCT_ROOT_NFQUEUE_FAULT_NONE;
}

static product_root_nfqueue_pending_t *
product_root_nfqueue_pending_find (product_root_nfqueue_lane_t *lane,
  u32 packet_id, u64 token, u64 generation)
{
  product_root_nfqueue_pending_t *found = 0;
  u32 capacity = lane->receive_pool.normal_capacity ?
    lane->receive_pool.normal_capacity : PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY;
  product_root_nfqueue_pending_t *home =
    &lane->pending[packet_id % capacity];
  if (home->completion.obligation.token &&
      home->completion.obligation.packet_id == packet_id &&
      home->completion.obligation.queue_generation == generation &&
      (!token || home->completion.obligation.token == token))
    {
      found = home;
      if (token) return found;
    }
  for (u32 bank = 0; bank < capacity / 64; ++bank)
    {
      u64 displaced = bank ? lane->pending_displaced_slots_high :
                             lane->pending_displaced_slots;
      while (displaced)
        {
          u32 slot = 64 * bank + (u32) __builtin_ctzll (displaced);
          displaced &= displaced - 1;
          product_root_nfqueue_pending_t *candidate = &lane->pending[slot];
          const product_adapter_obligation_t *identity =
            &candidate->completion.obligation;
          if (identity->packet_id == packet_id &&
              identity->queue_generation == generation && identity->token &&
              (!token || identity->token == token) &&
              (!found || identity->token > found->completion.obligation.token))
            {
              found = candidate;
              if (token) return found;
            }
        }
    }
  return found;
}

static void
product_root_nfqueue_pending_deactivate (product_root_nfqueue_main_t *nm,
  product_root_nfqueue_lane_t *lane, product_root_nfqueue_pending_t *pending)
{
  u32 slot = (u32) (pending - lane->pending);
  ASSERT (slot < 2 * PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY && pending->active);
  pending->active = 0;
  if (slot < 64) lane->pending_active_slots &= ~(UINT64_C (1) << slot);
  else lane->pending_active_slots_high &= ~(UINT64_C (1) << (slot - 64));
  lane->pending_count--;
  clib_atomic_fetch_sub_relax (&nm->pending_count, 1);
  /* Retain displaced identity history until this physical record is reused. */
}

static product_root_nfqueue_pending_t *
product_root_nfqueue_reserve (product_root_nfqueue_main_t *nm,
                              product_root_nfqueue_lane_t *lane,
                              u32 packet_id, u32 buffer_index, u16 receive_slot)
{
  _Static_assert (PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY == 64,
    "each ledger bank covers 64 completion identities");
  u32 capacity = lane->receive_pool.normal_capacity ?
    lane->receive_pool.normal_capacity : PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY;
  u32 home = packet_id % capacity;
  u32 slot = home;
  product_root_nfqueue_pending_t *pending = &lane->pending[home];
  if (lane->next_obligation_token >=
      (UINT64_MAX - PRODUCT_ROOT_NFQUEUE_MAX_LANES) / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    return 0;
  if (pending->active &&
      pending->completion.obligation.packet_id == packet_id)
    { lane->pending_duplicate_rejections++; return 0; }
  for (u32 bank = 0; bank < capacity / 64; ++bank)
    {
      u64 displaced = bank ?
        lane->pending_displaced_slots_high & lane->pending_active_slots_high :
        lane->pending_displaced_slots & lane->pending_active_slots;
      while (displaced)
        {
          u32 at = 64 * bank + (u32) __builtin_ctzll (displaced);
          displaced &= displaced - 1;
          if (lane->pending[at].completion.obligation.packet_id == packet_id)
            { lane->pending_duplicate_rejections++; return 0; }
        }
    }
  if (pending->active)
    {
      lane->pending_collisions++;
      u64 vacant = ~lane->pending_active_slots;
      if (vacant) slot = (u32) __builtin_ctzll (vacant);
      else if (capacity > 64 && (vacant = ~lane->pending_active_slots_high))
        slot = 64 + (u32) __builtin_ctzll (vacant);
      else { lane->pending_full_rejections++; return 0; }
      pending = &lane->pending[slot];
      ASSERT (!pending->active);
    }
  clib_memset (pending, 0, sizeof (*pending));
  pending->completion.obligation = (product_adapter_obligation_t) {
    .token = (++lane->next_obligation_token * PRODUCT_ROOT_NFQUEUE_MAX_LANES)
             + lane->lane_index,
    .queue_generation = lane->generation,
    .packet_id = packet_id,
    .origin_lane = lane->lane_index,
    .origin_worker = lane->worker_index,
    .kind = PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,
  };
  pending->buffer_index = buffer_index;
  pending->receive_slot = (u8) receive_slot;
  pending->active = 1;
  u64 bit = UINT64_C (1) << (slot % 64);
  u64 *active = slot < 64 ? &lane->pending_active_slots : &lane->pending_active_slots_high;
  u64 *displaced = slot < 64 ? &lane->pending_displaced_slots : &lane->pending_displaced_slots_high;
  *active |= bit;
  if (slot != home) *displaced |= bit;
  else *displaced &= ~bit;
  lane->pending_count++;
  if (lane->pending_count > lane->pending_high_water)
    lane->pending_high_water = lane->pending_count;
  if (lane->receive_pool.outstanding > lane->loan_high_water)
    lane->loan_high_water = lane->receive_pool.outstanding;
  clib_atomic_fetch_add_relax (&nm->pending_count, 1);
  return pending;
}

static u16
product_nfnl_type (u16 message_type)
{
  return (u16) ((NFNL_SUBSYS_QUEUE << 8) | message_type);
}

static int
product_nfnl_addattr (struct nlmsghdr *nlh, size_t message_size, u16 type,
                      const void *data, u16 data_length)
{
  u16 attr_length = (u16) NFA_LENGTH (data_length);
  u16 aligned_length = (u16) NFA_ALIGN (attr_length);
  struct nfattr *attr;

  if ((size_t) nlh->nlmsg_len + aligned_length > message_size)
    return 0;

  attr = (struct nfattr *) ((u8 *) nlh + nlh->nlmsg_len);
  attr->nfa_len = attr_length;
  attr->nfa_type = type;
  if (data_length != 0)
    clib_memcpy_fast (NFA_DATA (attr), data, data_length);
  if (aligned_length > attr_length)
    clib_memset ((u8 *) attr + attr_length, 0,
                 aligned_length - attr_length);
  nlh->nlmsg_len += aligned_length;
  return 1;
}

static int
product_nfnl_send (int fd, const struct nlmsghdr *nlh, int flags)
{
  struct sockaddr_nl kernel;
  ssize_t sent;

  clib_memset (&kernel, 0, sizeof (kernel));
  kernel.nl_family = AF_NETLINK;
  product_root_nfqueue_last_errno = 0;
  sent = sendto (fd, nlh, nlh->nlmsg_len, flags,
                 (const struct sockaddr *) &kernel, sizeof (kernel));
  product_root_nfqueue_last_send_result = sent;
  if (sent < 0)
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      return 0;
    }
  return 1;
}

static void
product_nfnl_fill_header (struct nlmsghdr *nlh, size_t message_size,
                          u16 message_type, u32 queue_id)
{
  struct nfgenmsg *nfgen;

  clib_memset (nlh, 0, message_size);
  nlh->nlmsg_len = NLMSG_LENGTH (sizeof (*nfgen));
  nlh->nlmsg_type = product_nfnl_type (message_type);
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  nfgen = (struct nfgenmsg *) NLMSG_DATA (nlh);
  nfgen->nfgen_family = AF_UNSPEC;
  nfgen->version = NFNETLINK_V0;
  nfgen->res_id = htons ((u16) queue_id);
}

static int
product_nfqueue_recv_ack (int fd)
{
  u8 buffer[512];
  int attempt;

  product_root_nfqueue_last_errno = 0;
  for (attempt = 0; attempt < 100; attempt++)
    {
      ssize_t received = recv (fd, buffer, sizeof (buffer), 0);
      struct nlmsghdr *nlh;
      int remaining;

      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
              usleep (1000);
              continue;
            }
          product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
          return 0;
        }
      if (received == 0)
        {
          product_root_nfqueue_last_errno = ECONNRESET;
          return 0;
        }

      remaining = (int) received;
      for (nlh = (struct nlmsghdr *) buffer; NLMSG_OK (nlh, remaining);
           nlh = NLMSG_NEXT (nlh, remaining))
        if (nlh->nlmsg_type == NLMSG_ERROR)
          {
            struct nlmsgerr *error = (struct nlmsgerr *) NLMSG_DATA (nlh);
            if (error->error != 0)
              product_root_nfqueue_last_errno = -error->error;
            return error->error == 0;
          }
    }
  product_root_nfqueue_last_errno = ETIMEDOUT;
  return 0;
}

static void
product_root_nfqueue_warn_errno (const char *step)
{
  int code =
    product_root_nfqueue_last_errno == 0 ? EIO : product_root_nfqueue_last_errno;
  clib_warning ("root nfqueue %s failed: errno=%d (%s)", step, code,
                strerror (code));
}

static int
product_nfqueue_send_config_command (int fd, u8 command, u32 queue_id,
                                     u16 pf)
{
  union
  {
    u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) +
             NFA_SPACE (sizeof (struct nfqnl_msg_config_cmd))];
    struct nlmsghdr nlh;
  } request;
  struct nfqnl_msg_config_cmd cmd;

  product_nfnl_fill_header (&request.nlh, sizeof (request),
                            NFQNL_MSG_CONFIG, queue_id);
  clib_memset (&cmd, 0, sizeof (cmd));
  cmd.command = command;
  cmd.pf = htons (pf);
  if (!product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_CMD,
                             &cmd, sizeof (cmd)))
    return 0;
  if (!product_nfnl_send (fd, &request.nlh, 0))
    return 0;
  return product_nfqueue_recv_ack (fd);
}

static int
product_nfqueue_send_copy_packet (int fd, u32 queue_id, u32 queue_maxlen)
{
  union
  {
    u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) +
             NFA_SPACE (sizeof (struct nfqnl_msg_config_params)) +
             3 * NFA_SPACE (sizeof (u32))];
    struct nlmsghdr nlh;
  } request;
  struct nfqnl_msg_config_params params;
  u32 queue_flags = htonl (PRODUCT_ROOT_NFQUEUE_FLAGS);
  u32 maxlen = htonl (queue_maxlen);

  product_nfnl_fill_header (&request.nlh, sizeof (request),
                            NFQNL_MSG_CONFIG, queue_id);
  clib_memset (&params, 0, sizeof (params));
  params.copy_range = htonl (UINT16_MAX);
  params.copy_mode = NFQNL_COPY_PACKET;
  if (!product_nfnl_addattr (&request.nlh, sizeof (request),
                             NFQA_CFG_PARAMS, &params, sizeof (params)))
    return 0;
  if (!product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_MASK,
                             &queue_flags, sizeof (queue_flags))
      || !product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_FLAGS,
                                &queue_flags, sizeof (queue_flags))
      || !product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_QUEUE_MAXLEN,
                                &maxlen, sizeof (maxlen)))
    return 0;
  if (!product_nfnl_send (fd, &request.nlh, 0))
    return 0;
  return product_nfqueue_recv_ack (fd);
}

static int
product_nfqueue_configure (int fd, u32 queue_id, u32 family, u32 queue_maxlen)
{
  if (!product_nfqueue_send_config_command (fd, NFQNL_CFG_CMD_PF_BIND, 0,
                                            family == 4 ? AF_INET : AF_INET6))
    {
      product_root_nfqueue_warn_errno ("PF_BIND");
      return 0;
    }
  if (!product_nfqueue_send_config_command (fd, NFQNL_CFG_CMD_BIND,
                                            queue_id, 0))
    {
      product_root_nfqueue_warn_errno ("BIND");
      return 0;
    }
  if (!product_nfqueue_send_copy_packet (fd, queue_id, queue_maxlen))
    {
      product_root_nfqueue_warn_errno ("COPY_PACKET");
      return 0;
    }
  return 1;
}

typedef union
{
  u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) +
           NFA_SPACE (sizeof (struct nfqnl_msg_verdict_hdr))];
  struct nlmsghdr nlh;
} product_nfqueue_verdict_request_t;

static int
product_nfqueue_fill_verdict (product_nfqueue_verdict_request_t *request,
  u32 queue_id, u32 packet_id, u32 verdict)
{
  struct nfqnl_msg_verdict_hdr verdict_header;
  product_nfnl_fill_header (&request->nlh, sizeof (*request),
                            NFQNL_MSG_VERDICT, queue_id);
  /* Verdict ACKs share the ingress fd; preserve the original no-ACK request. */
  request->nlh.nlmsg_flags = NLM_F_REQUEST;
  /* Correlation for bounded control-error diagnostics, never ID authority. */
  request->nlh.nlmsg_seq = packet_id;
  clib_memset (&verdict_header, 0, sizeof (verdict_header));
  verdict_header.verdict = htonl (verdict);
  verdict_header.id = htonl (packet_id);
  return product_nfnl_addattr (&request->nlh, sizeof (*request),
    NFQA_VERDICT_HDR, &verdict_header, sizeof (verdict_header));
}

static int
product_nfqueue_send_verdict (int fd, u32 queue_id, u32 packet_id,
                              u32 verdict, int flags)
{
  product_nfqueue_verdict_request_t request;
  if (!product_nfqueue_fill_verdict (&request, queue_id, packet_id, verdict))
    return 0;
  return product_nfnl_send (fd, &request.nlh, flags);
}

static void
product_root_nfqueue_record_verdict_attempt (
  product_root_nfqueue_main_t *nm, product_root_nfqueue_lane_t *lane,
  u32 packet_id)
{
  lane->verdict_attempts++;
  clib_atomic_fetch_add_relax (&nm->verdict_attempts, 1);
  lane->last_verdict_packet_id = packet_id;
  lane->verdict_packet_id_known = 1;
#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
  /* This diagnostic is confined to the initial low-ID portion of a fresh
   * generation. Once it expires, ID wrap cannot make it available again. */
  if (packet_id >= 4096 || lane->verdict_attempts >= 4096 ||
      lane->identity_losses || lane->reserve_losses || lane->receive_overruns)
    {
      lane->verdict_id_probe_expired = 1;
      lane->verdict_id_fault_next = 0;
    }
#endif
}

static int
product_root_nfqueue_send_counted_verdict (
  product_root_nfqueue_main_t *nm, product_root_nfqueue_lane_t *lane,
  u32 packet_id, u32 verdict)
{
  product_root_nfqueue_record_verdict_attempt (nm, lane, packet_id);
  if (product_nfqueue_send_verdict (lane->fd, lane->queue_id, packet_id,
                                    verdict, 0))
    {
      lane->verdict_succeeded++;
      clib_atomic_fetch_add_relax (&nm->verdict_succeeded, 1);
      return 1;
    }
  lane->verdict_failed++;
  clib_atomic_fetch_add_relax (&nm->verdict_failed, 1);
  clib_atomic_fetch_add_relax (&nm->verdict_failed_definite, 1);
  return 0;
}

static int
product_root_nfqueue_parse_packet (u8 *data, u32 length,
                                   product_root_nfqueue_packet_t *packet)
{
  struct nlmsghdr *nlh;
  int remaining = (int) length;

  clib_memset (packet, 0, sizeof (*packet));
  for (nlh = (struct nlmsghdr *) data; NLMSG_OK (nlh, remaining);
       nlh = NLMSG_NEXT (nlh, remaining))
    {
      struct nfgenmsg *nfgen;
      struct nfattr *attr;
      int attr_length;

      if (nlh->nlmsg_type == NLMSG_ERROR)
        return 0;
      if (NFNL_SUBSYS_ID (nlh->nlmsg_type) != NFNL_SUBSYS_QUEUE
          || NFNL_MSG_TYPE (nlh->nlmsg_type) != NFQNL_MSG_PACKET)
        continue;
      if (NLMSG_PAYLOAD (nlh, 0) < sizeof (*nfgen))
        return 0;

      nfgen = (struct nfgenmsg *) NLMSG_DATA (nlh);
      attr = NFM_NFA (nfgen);
      attr_length = NFM_PAYLOAD (nlh);
      for (; NFA_OK (attr, attr_length);
           attr = NFA_NEXT (attr, attr_length))
        {
          switch (NFA_TYPE (attr))
            {
            case NFQA_PACKET_HDR:
              if (NFA_PAYLOAD (attr) >=
                  (int) sizeof (struct nfqnl_msg_packet_hdr))
                {
                  const struct nfqnl_msg_packet_hdr *packet_header =
                    (const struct nfqnl_msg_packet_hdr *) NFA_DATA (attr);
                  packet->packet_id = ntohl (packet_header->packet_id);
                  packet->hook = packet_header->hook;
                  packet->identity_present = 1;
                }
              break;
            case NFQA_UID:
              if (NFA_PAYLOAD (attr) >= (int) sizeof (u32))
                {
                  u32 uid;
                  clib_memcpy_fast (&uid, NFA_DATA (attr), sizeof (uid));
                  packet->uid = ntohl (uid);
                  packet->uid_present = 1;
                }
              break;
            case NFQA_IFINDEX_INDEV:
            case NFQA_IFINDEX_OUTDEV:
              if (NFA_PAYLOAD (attr) >= (int) sizeof (u32))
                {
                  u32 ifindex;
                  clib_memcpy_fast (&ifindex, NFA_DATA (attr), sizeof (ifindex));
                  if (NFA_TYPE (attr) == NFQA_IFINDEX_INDEV)
                    { packet->indev = ntohl (ifindex); packet->indev_present = 1; }
                  else
                    { packet->outdev = ntohl (ifindex); packet->outdev_present = 1; }
                }
              break;
            case NFQA_PAYLOAD:
              packet->payload = (u8 *) NFA_DATA (attr);
              packet->payload_length = (u32) NFA_PAYLOAD (attr);
              break;
            case NFQA_SKB_INFO:
            case NFQA_CAP_LEN:
              if (NFA_PAYLOAD (attr) >= (int) sizeof (u32))
                {
                  u32 value;
                  clib_memcpy_fast (&value, NFA_DATA (attr), sizeof (value));
                  if (NFA_TYPE (attr) == NFQA_SKB_INFO)
                    { packet->skb_info = ntohl (value); packet->skb_info_present = 1; }
                  else
                    { packet->captured_length = ntohl (value); packet->captured_length_present = 1; }
                }
              break;
            default:
              break;
            }
        }
      if (packet->payload != 0 && packet->payload_length != 0)
        {
          u8 version = packet->payload[0] >> 4;
          if (version == 4)
            {
              packet->ip_family = 4;
              if (packet->payload_length >= 20)
                packet->protocol = packet->payload[9];
            }
          else if (version == 6)
            {
              packet->ip_family = 6;
              if (packet->payload_length >= 40)
                packet->protocol = packet->payload[6];
            }
        }
      /* The kernel's u32 packet sequence may wrap through zero. Presence of
       * a complete NFQA_PACKET_HDR, not the numeric ID, makes it obligatory. */
      return packet->identity_present
             && (packet->hook == NF_INET_LOCAL_OUT
                 || packet->hook == NF_INET_LOCAL_IN)
             && (packet->ip_family == 4 || packet->ip_family == 6)
             && packet->payload != 0 && packet->payload_length != 0;
    }
  return 0;
}

static void
product_root_nfqueue_return_receive (product_root_nfqueue_lane_t *lane,
                                     u16 slot, u32 buffer_index)
{
  if (PREDICT_FALSE (!product_root_receive_pool_return (
        &lane->receive_pool, lane->generation, slot, buffer_index)))
    clib_panic ("Root receive buffer returned without its lane-local loan");
  lane->receive_returns++;
}

static int
product_root_nfqueue_packet_id_seen (const u32 *packet_ids, u32 packet_count,
                                     u32 packet_id)
{
  u32 index;
  for (index = 0; index < packet_count; index++)
    if (packet_ids[index] == packet_id)
      return 1;
  return 0;
}

/* Pre-admission return on the origin worker, using the already materialized
 * native buffer. Even a truncated payload may contain a complete mandatory
 * identity; never invent one, retry a physical verdict, or admit a multi-
 * message datagram as independent carriers of the same buffer. */
static void
product_root_nfqueue_accept_unadmitted (product_root_nfqueue_main_t *nm,
                                       product_root_nfqueue_lane_t *lane,
                                       u8 *data, u32 length, const char *reason)
{
  u32 accepted_ids[64];
  u32 accepted_count = 0;
  for (u32 offset = 0; offset + NLMSG_HDRLEN <= length;)
    {
      struct nlmsghdr *nlh = (struct nlmsghdr *) (data + offset);
      struct nfgenmsg *nfgen;
      struct nfattr *attr;
      int attr_length;
      u32 packet_id = 0;
      int identity_present = 0;
      if (nlh->nlmsg_len < NLMSG_LENGTH (sizeof (*nfgen)))
        break;
      u32 visible = clib_min (nlh->nlmsg_len, length - offset);
      if (visible < NLMSG_LENGTH (sizeof (*nfgen)))
        break;
      u32 next = offset + NLMSG_ALIGN (visible);
      if (NFNL_SUBSYS_ID (nlh->nlmsg_type) != NFNL_SUBSYS_QUEUE
          || NFNL_MSG_TYPE (nlh->nlmsg_type) != NFQNL_MSG_PACKET)
        { offset = next; continue; }
      nfgen = (struct nfgenmsg *) NLMSG_DATA (nlh);
      if (ntohs (nfgen->res_id) != lane->queue_id
          || nfgen->version != NFNETLINK_V0)
        { offset = next; continue; }
      attr = NFM_NFA (nfgen);
      attr_length = (int) visible - NLMSG_LENGTH (sizeof (*nfgen));
      for (; NFA_OK (attr, attr_length);
           attr = NFA_NEXT (attr, attr_length))
        if (NFA_TYPE (attr) == NFQA_PACKET_HDR
            && NFA_PAYLOAD (attr)
                 >= (int) sizeof (struct nfqnl_msg_packet_hdr))
          {
            const struct nfqnl_msg_packet_hdr *packet_header =
              (const struct nfqnl_msg_packet_hdr *) NFA_DATA (attr);
            packet_id = ntohl (packet_header->packet_id);
            identity_present = 1;
            break;
          }
      offset = next;
      if (!identity_present || product_root_nfqueue_packet_id_seen (
            accepted_ids, accepted_count, packet_id))
        continue;
      if (accepted_count == ARRAY_LEN (accepted_ids))
        break;
      accepted_ids[accepted_count++] = packet_id;
      clib_atomic_fetch_add_relax (&nm->graph_submit_fail_opens, 1);
      lane->ingress_accepts++;
      if (strcmp (reason, "normal_exhausted") == 0) lane->ingress_normal_exhausted++;
      else if (strcmp (reason, "unadmitted_envelope") == 0) lane->ingress_envelope_rejected++;
      else if (strcmp (reason, "completion_capacity") == 0) lane->ingress_completion_rejected++;
      else if (strcmp (reason, "graph_submit_rejected") == 0) lane->ingress_graph_rejected++;
      int success = product_root_nfqueue_send_counted_verdict (
        nm, lane, packet_id, NF_ACCEPT);
      if (lane->ingress_accepts <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
        {
          flockfile (stderr);
          fprintf (stderr, "s233 event=ingress_verdict source=NFQ_CAPTURED generation=%llu thread=%u lane=%u queue=%u packet=%u reason=%s verdict=%u syscall_success=%u bytes=%u raw=",
            (unsigned long long) lane->generation, vlib_get_thread_index (),
            lane->lane_index, lane->queue_id, packet_id, reason, NF_ACCEPT,
            success, length);
          for (u32 i = 0; i < length; ++i)
            fprintf (stderr, "%02x", data[i]);
          fprintf (stderr, "\n");
          funlockfile (stderr);
        }
    }
  if (!accepted_count)
    {
      lane->identity_losses++;
      clib_atomic_fetch_add_relax (&nm->ingress_identity_missing, 1);
    }
}

#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
void
product_root_nfqueue_prefetch_completion (vlib_main_t *vm,
  const product_packet_completion_frame_t *completion)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  const product_adapter_obligation_t *obligation = &completion->obligation;
  if (obligation->kind != PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE ||
      obligation->queue_generation != nm->generation ||
      obligation->origin_lane >= nm->lane_count)
    return;
  product_root_nfqueue_lane_t *lane = &nm->lanes[obligation->origin_lane];
  if (vm->thread_index != vlib_get_worker_thread_index (lane->worker_index)) return;
  product_root_nfqueue_pending_t *pending = product_root_nfqueue_pending_find (
    lane, obligation->packet_id, obligation->token, obligation->queue_generation);
  if (pending) __builtin_prefetch (pending, 0, 1);
}
#endif

typedef struct
{
  vlib_main_t *vm;
  product_root_nfqueue_lane_t *lane;
  product_root_nfqueue_pending_t *pending;
  u32 buffer_index, verdict;
  int send_flags, capacity_bypass;
} product_root_verdict_work_t;

enum
{
  PRODUCT_VERDICT_SUCCEEDED,
  PRODUCT_VERDICT_FAILED_DEFINITE,
  PRODUCT_VERDICT_OUTCOME_UNKNOWN,
};

static int
product_root_nfqueue_prepare_completion (
  vlib_main_t *vm, u32 buffer_index,
  const product_packet_completion_frame_t *completion,
  product_root_verdict_work_t *work)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  const product_adapter_obligation_t *obligation = &completion->obligation;
  u32 lane_index = obligation->origin_lane;
  u32 packet_id = obligation->packet_id;
  product_root_nfqueue_lane_t *lane;
  product_root_nfqueue_pending_t *pending;
  const char *rejection = 0;
  int capacity_bypass =
    completion->terminal_intent == PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS
    && completion->runtime_drop_reason == PRODUCT_PACKET_DROP_NONE
    && (completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED
        || completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED
        || completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_REASSEMBLY_RESOURCE
        || completion->processing_bypass_reason == PRODUCT_PACKET_BYPASS_FLOW_CAPACITY);
  u32 verdict = completion->terminal_intent == PRODUCT_PACKET_INTENT_PASS_ADAPTER || capacity_bypass
                  ? NF_ACCEPT : NF_DROP;

  if (obligation->kind != PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE
      || obligation->queue_generation != nm->generation
      || lane_index >= nm->lane_count
      || obligation->origin_worker >= product_packet_graph_worker_count ())
    { rejection = "stale_generation_or_lane"; goto stale; }
  lane = &nm->lanes[lane_index];
  if (obligation->queue_generation != lane->generation
      || obligation->origin_worker != lane->worker_index
      || vm->thread_index != vlib_get_worker_thread_index (lane->worker_index))
    { rejection = "origin_worker_mismatch"; goto stale; }
  /* A fault removes ingress polling but retains the verdict descriptor until
   * every already-admitted obligation has settled. */
  if (!lane->socket_ready || lane->fd < 0)
    { rejection = "closed_lane"; goto stale; }
  pending = product_root_nfqueue_pending_find (
    lane, packet_id, obligation->token, obligation->queue_generation);
  if (!pending)
    { rejection = "stale_identity"; goto stale; }
  if (!pending->active)
    {
      lane->duplicate_completion_drops++;
      clib_atomic_fetch_add_relax (&nm->duplicate_completion_drops, 1);
      rejection = "duplicate";
      goto rejected;
    }
  if (pending->buffer_index != buffer_index
      || (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE)
      || (completion->terminal_intent != PRODUCT_PACKET_INTENT_PASS_ADAPTER
          && completion->terminal_intent != PRODUCT_PACKET_INTENT_DROP_RUNTIME
          && !capacity_bypass))
    { rejection = "stale_carrier_or_intent"; goto stale; }

  /* Commit identity consumption before the one native operation attempt. */
  product_root_nfqueue_pending_deactivate (nm, lane, pending);
  pending->completion = *completion;
  if (completion->producer_thread == vm->thread_index)
    { lane->origin_local_completions++; clib_atomic_fetch_add_relax (&nm->origin_local_completions, 1); }
  else
    { lane->origin_remote_completions++; clib_atomic_fetch_add_relax (&nm->origin_remote_completions, 1); }
  lane->buffer_returns++; clib_atomic_fetch_add_relax (&nm->buffer_returns, 1);
  lane->internal_settlements++; clib_atomic_fetch_add_relax (&nm->internal_settlements, 1);
  product_root_nfqueue_record_verdict_attempt (nm, lane, packet_id);
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s210 event=origin_completion thread=%u buffer=%u token=%llu generation=%llu packet=%u lane=%u intent=%u drop_reason=%u bypass_reason=%u verdict=%u\n",
      vm->thread_index, buffer_index, (unsigned long long) obligation->token,
      (unsigned long long) obligation->queue_generation, packet_id, lane_index,
      completion->terminal_intent, completion->runtime_drop_reason,
      completion->processing_bypass_reason, verdict);
  /* Linux rejects MSG_OOB on this same live netlink fd. This is a real
   * negative syscall result, not a fabricated attempt or a second socket.
   * Even failure consumes the original identity and never physically retries. */
  int send_flags = lane->verdict_fault_next
    || nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_FAILED_DEFINITE
      ? MSG_OOB : 0;
  lane->verdict_fault_next = 0;
  if (lane->internal_settlements <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    fprintf (stderr, "s203 event=verdict source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u obligation=%llu generation=%llu verdict=%u owner=%u\n",
      vm->thread_index, lane_index, lane->queue_id, packet_id,
      (unsigned long long) obligation->token, (unsigned long long) obligation->queue_generation,
      verdict, completion->producer_thread
        ? vlib_get_worker_index (completion->producer_thread)
        : PRODUCT_EXECUTION_OWNER_UNKNOWN);
  *work = (product_root_verdict_work_t) {
    .vm = vm, .lane = lane, .pending = pending, .buffer_index = buffer_index,
    .verdict = verdict, .send_flags = send_flags, .capacity_bypass = capacity_bypass,
  };
  return 1;

stale:
  clib_atomic_fetch_add_relax (&nm->stale_completion_drops, 1);
rejected:
  if (completion->flags & PRODUCT_COMPLETION_TRACE)
    fprintf (stderr, "s204 event=completion_reject source=%s thread=%u token=%llu generation=%llu packet=%u lane=%u reason=%s duplicate=%llu stale=%llu\n",
      (completion->flags & PRODUCT_COMPLETION_REPLAY_PROBE) ? "COMPLETION_REPLAY" : "NFQ_CAPTURED",
      vm->thread_index, (unsigned long long) obligation->token,
      (unsigned long long) obligation->queue_generation, packet_id, lane_index, rejection,
      (unsigned long long) nm->duplicate_completion_drops,
      (unsigned long long) nm->stale_completion_drops);
  return 0;
}

static void
product_root_nfqueue_finish_completion (product_root_verdict_work_t *work,
  u32 outcome, ssize_t result, int error)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  vlib_main_t *vm = work->vm;
  product_root_nfqueue_lane_t *lane = work->lane;
  product_root_nfqueue_pending_t *pending = work->pending;
  const product_packet_completion_frame_t *completion = &pending->completion;
  const product_adapter_obligation_t *obligation = &completion->obligation;
  u32 lane_index = obligation->origin_lane, packet_id = obligation->packet_id;
  u32 buffer_index = work->buffer_index, verdict = work->verdict;
  int send_flags = work->send_flags, capacity_bypass = work->capacity_bypass;
  if (outcome == PRODUCT_VERDICT_SUCCEEDED)
    {
      lane->verdict_succeeded++; clib_atomic_fetch_add_relax (&nm->verdict_succeeded, 1);
#ifdef SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS
      if ((completion->flags & PRODUCT_COMPLETION_POLICY_QUALIFIED) && !capacity_bypass &&
          !(completion->flags & PRODUCT_COMPLETION_FRAGMENT_MEMBER))
        {
          __atomic_fetch_add (&lane->policy_qualified_succeeded, 1, __ATOMIC_RELAXED);
          if (completion->flags & PRODUCT_COMPLETION_POLICY_QUALIFIED_MATCHED)
            {
              u64 *matched = verdict == NF_ACCEPT
                ? &lane->policy_qualified_matched_allow_succeeded
                : &lane->policy_qualified_matched_drop_succeeded;
              __atomic_fetch_add (matched, 1, __ATOMIC_RELAXED);
            }
        }
#endif
    }
  else
    {
      lane->verdict_failed++;
      clib_atomic_fetch_add_relax (&nm->verdict_failed, 1);
      if (outcome == PRODUCT_VERDICT_FAILED_DEFINITE)
        clib_atomic_fetch_add_relax (&nm->verdict_failed_definite, 1);
      else
        clib_atomic_fetch_add_relax (&nm->verdict_outcome_unknown, 1);
    }
  if (send_flags || (completion->flags & PRODUCT_COMPLETION_TRACE)
      || lane->internal_settlements <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    fprintf (stderr, "s242 event=verdict_syscall source=NFQ_CAPTURED generation=%llu thread=%u lane=%u fd=%d queue=%u packet=%u token=%llu verdict=%u flags=%d result=%lld errno=%d outcome=%u\n",
      (unsigned long long) obligation->queue_generation, vm->thread_index,
      lane_index, lane->fd, lane->queue_id, packet_id,
      (unsigned long long) obligation->token, verdict, send_flags,
      (long long) result, error, outcome);
  product_root_nfqueue_return_receive (lane, pending->receive_slot, buffer_index);
}

int
product_root_nfqueue_complete_from_graph (vlib_main_t *vm, u32 buffer_index,
  const product_packet_completion_frame_t *completion)
{
  product_root_verdict_work_t work;
  if (!product_root_nfqueue_prepare_completion (vm, buffer_index, completion, &work))
    return 0;
  work.lane->graph_sendto_calls++;
  int success = product_nfqueue_send_verdict (work.lane->fd, work.lane->queue_id,
    completion->obligation.packet_id, work.verdict, work.send_flags);
  product_root_nfqueue_finish_completion (&work,
    success ? PRODUCT_VERDICT_SUCCEEDED : PRODUCT_VERDICT_FAILED_DEFINITE,
    product_root_nfqueue_last_send_result, product_root_nfqueue_last_errno);
  return 1;
}

#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
/* One current origin window, one fd and one flags value. Every message remains
 * NFQNL_MSG_VERDICT for one exact ID, including mixed ACCEPT/DROP. No range
 * verdict, retained queue, future-packet wait or physical verdict retry. */
static void
product_root_nfqueue_send_verdict_window (product_root_verdict_work_t *work, u32 count)
{
  product_nfqueue_verdict_request_t requests[PRODUCT_PACKET_BATCH_SIZE];
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 2
  struct mmsghdr messages[PRODUCT_PACKET_BATCH_SIZE] = {0};
  struct iovec vectors[PRODUCT_PACKET_BATCH_SIZE];
#endif
  struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
  product_root_nfqueue_lane_t *lane = work[0].lane;
  ASSERT (count && count <= PRODUCT_PACKET_BATCH_SIZE);
  _Static_assert (sizeof (product_nfqueue_verdict_request_t) ==
    NLMSG_ALIGN (NLMSG_LENGTH (sizeof (struct nfgenmsg)) +
      NFA_SPACE (sizeof (struct nfqnl_msg_verdict_hdr))),
    "verdict array stride must equal its aligned wire message size");
  lane->graph_verdict_windows++;
  lane->graph_verdict_window_messages += count;
  for (u32 i = 0; i < count; ++i)
    {
      ASSERT (work[i].lane == lane && work[i].send_flags == work[0].send_flags);
      int filled = product_nfqueue_fill_verdict (&requests[i], lane->queue_id,
        work[i].pending->completion.obligation.packet_id, work[i].verdict);
      ASSERT (filled);
      /* The fixed request has room for the single fixed-size attribute. */
      if (!filled || requests[i].nlh.nlmsg_len != sizeof (requests[i]) ||
          NLMSG_ALIGN (requests[i].nlh.nlmsg_len) != sizeof (requests[i]))
        {
          for (u32 j = 0; j < count; ++j)
            product_root_nfqueue_finish_completion (&work[j],
              PRODUCT_VERDICT_FAILED_DEFINITE, -1, EINVAL);
          return;
        }
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 2
      vectors[i] = (struct iovec) { &requests[i], requests[i].nlh.nlmsg_len };
      messages[i].msg_hdr.msg_name = &kernel;
      messages[i].msg_hdr.msg_namelen = sizeof (kernel);
      messages[i].msg_hdr.msg_iov = &vectors[i];
      messages[i].msg_hdr.msg_iovlen = 1;
#endif
    }
  if (lane->verdict_id_fault_next && !lane->verdict_id_probe_expired &&
      !lane->identity_losses && !lane->reserve_losses && !lane->receive_overruns && count >= 3)
    {
      u32 at = count / 2;
      u32 original_id = work[at].pending->completion.obligation.packet_id;
      /* Only a newly created diagnostic generation with IDs far below wrap
       * can arm this CLI probe. The original obligation remains unchanged. */
      int filled = product_nfqueue_fill_verdict (&requests[at], lane->queue_id,
        UINT32_MAX, work[at].verdict);
      ASSERT (filled);
      lane->verdict_id_fault_next = 0;
      fprintf (stderr, "s297 event=verdict_id_fault generation=%llu lane=%u original=%u wire=%u position=%u count=%u\n",
        (unsigned long long) lane->generation, lane->lane_index, original_id,
        UINT32_MAX, at, count);
    }
#if SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 1
  /* Same prepared window and flush time as the other senders. */
  for (u32 i = 0; i < count; ++i)
    {
      lane->graph_sendto_calls++;
      errno = 0;
      ssize_t sent = sendto (lane->fd, &requests[i], sizeof (requests[i]),
        work[i].send_flags, (struct sockaddr *) &kernel, sizeof (kernel));
      int error = sent < 0 ? errno : 0;
      u32 outcome = sent == sizeof (requests[i]) ? PRODUCT_VERDICT_SUCCEEDED
        : sent < 0 ? PRODUCT_VERDICT_FAILED_DEFINITE : PRODUCT_VERDICT_OUTCOME_UNKNOWN;
      product_root_nfqueue_finish_completion (&work[i], outcome, sent, error);
    }
#elif SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 3
  /* A single contiguous command datagram, with each child length unchanged.
   * Native submit success does not confirm every NFQ handler or delivery.
   * In this kernel-port-0 path negative sendto returns precede dispatch;
   * an unexpected short return has no reliable per-ID successful prefix. */
  size_t bytes = count * sizeof (requests[0]);
  lane->graph_packed_calls++;
  lane->graph_packed_requested += count;
  lane->graph_packed_max_messages = clib_max (lane->graph_packed_max_messages, count);
  for (u32 i = 1; i < count; ++i)
    if (work[i].verdict != work[0].verdict)
      { lane->graph_packed_mixed_calls++; break; }
  errno = 0;
  ssize_t sent = sendto (lane->fd, requests, bytes, work[0].send_flags,
    (struct sockaddr *) &kernel, sizeof (kernel));
  int error = sent < 0 ? errno : 0;
  u32 outcome = sent == (ssize_t) bytes ? PRODUCT_VERDICT_SUCCEEDED
    : sent < 0 ? PRODUCT_VERDICT_FAILED_DEFINITE : PRODUCT_VERDICT_OUTCOME_UNKNOWN;
  if (sent > 0) lane->graph_packed_bytes += sent;
  if (outcome == PRODUCT_VERDICT_SUCCEEDED) lane->graph_packed_sent += count;
  for (u32 i = 0; i < count; ++i)
    product_root_nfqueue_finish_completion (&work[i], outcome, sent, error);
#else
  for (u32 first = 0; first < count;)
    {
      lane->graph_sendmmsg_calls++;
      lane->graph_sendmmsg_requested += count - first;
      errno = 0;
      int sent = sendmmsg (lane->fd, messages + first, count - first, work[first].send_flags);
      int error = sent < 0 ? errno : 0;
      u32 succeeded = sent > 0 ? (u32) sent : 0;
      ASSERT (succeeded <= count - first);
      lane->graph_sendmmsg_sent += succeeded;
      for (u32 i = 0; i < succeeded; ++i)
        {
          u32 at = first + i;
          int full = messages[at].msg_len == requests[at].nlh.nlmsg_len;
          product_root_nfqueue_finish_completion (&work[at],
            full ? PRODUCT_VERDICT_SUCCEEDED : PRODUCT_VERDICT_OUTCOME_UNKNOWN,
            messages[at].msg_len, 0);
        }
      first += succeeded;
      if (first == count) break;
      /* sendmmsg stops at the first unsuccessful operation. After a nonempty
       * prefix its errno is lost; a msg_len copy-out failure can also conceal
       * a send. Consume this boundary identity conservatively and NEVER send
       * it again. The untouched tail is still entitled to its first attempt. */
      lane->graph_sendmmsg_partial_calls += succeeded != 0;
      u32 outcome = succeeded || error == EFAULT || error == EINTR
        ? PRODUCT_VERDICT_OUTCOME_UNKNOWN : PRODUCT_VERDICT_FAILED_DEFINITE;
      product_root_nfqueue_finish_completion (&work[first], outcome, -1, error);
      ++first;
    }
#endif
}

void
product_root_nfqueue_complete_batch_from_graph (vlib_main_t *vm,
  const u32 *indices, const product_packet_completion_frame_t *completions,
  u32 count, u8 *returned)
{
  product_root_verdict_work_t work[PRODUCT_PACKET_BATCH_SIZE];
  u32 n_work = 0;
  clib_memset (returned, 0, count * sizeof (*returned));
  ASSERT (count <= PRODUCT_PACKET_BATCH_SIZE);
  if (count > PRODUCT_PACKET_BATCH_SIZE) return;
  for (u32 i = 0; i < count; ++i)
    {
      if (completions[i].obligation.kind != PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE)
        continue;
      product_root_verdict_work_t next;
      if (!product_root_nfqueue_prepare_completion (vm, indices[i], &completions[i], &next))
        continue;
      if (n_work && (work[0].lane != next.lane || work[0].send_flags != next.send_flags))
        {
          product_root_nfqueue_send_verdict_window (work, n_work);
          n_work = 0;
        }
      work[n_work++] = next;
      returned[i] = 1;
    }
  if (n_work) product_root_nfqueue_send_verdict_window (work, n_work);
}
#endif

#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
typedef struct
{
  product_packet_graph_external_item_t items[PRODUCT_ROOT_INPUT_BATCH_SIZE];
  u32 visible[PRODUCT_ROOT_INPUT_BATCH_SIZE];
  i16 envelope_offset[PRODUCT_ROOT_INPUT_BATCH_SIZE];
  u32 count;
} product_root_input_batch_t;

static u32
product_root_input_batch_flush (vlib_main_t *vm,
  product_root_nfqueue_main_t *nm, product_root_nfqueue_lane_t *lane,
  product_root_input_batch_t *batch)
{
  u8 accepted[PRODUCT_ROOT_INPUT_BATCH_SIZE] = {0};
  if (!batch->count) return 0;
  u32 submitted = product_packet_graph_submit_external_batch (
    vm, batch->items, batch->count, accepted);
  for (u32 i = 0; i < batch->count; ++i)
    {
      const product_packet_graph_external_item_t *item = &batch->items[i];
      const product_adapter_obligation_t *obligation = &item->obligation;
      if (accepted[i])
        {
          lane->packets_submitted++;
          clib_atomic_fetch_add_relax (&nm->packets_submitted, 1);
          if (lane->packets_submitted <=
                product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
            fprintf (stderr, "s203 event=frame_accept source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u buffer=%u obligation=%llu generation=%llu\n",
              vm->thread_index, lane->lane_index, lane->queue_id,
              obligation->packet_id, item->buffer_index,
              (unsigned long long) obligation->token,
              (unsigned long long) obligation->queue_generation);
          continue; /* Only copied identities are read after scheduling. */
        }
      product_root_nfqueue_pending_t *pending = product_root_nfqueue_pending_find (
        lane, obligation->packet_id, obligation->token, obligation->queue_generation);
      ASSERT (pending && pending->active && pending->buffer_index == item->buffer_index &&
              pending->completion.obligation.token == obligation->token);
      product_root_nfqueue_pending_deactivate (nm, lane, pending);
      vlib_buffer_t *buffer = vlib_get_buffer (vm, item->buffer_index);
      product_root_nfqueue_accept_unadmitted (nm, lane,
        buffer->data + batch->envelope_offset[i], batch->visible[i],
        "graph_submit_rejected");
      product_root_nfqueue_return_receive (lane, pending->receive_slot,
                                           item->buffer_index);
    }
  batch->count = 0;
  return submitted;
}
#endif

/* Control replies consume no packet obligation. Validate the whole envelope
 * before updating counters, so a mixed packet/control envelope stays on the
 * existing unadmitted path rather than silently discarding a packet identity. */
static int
product_root_nfqueue_consume_control (product_root_nfqueue_lane_t *lane,
  const u8 *data, u32 length)
{
  if (length < NLMSG_HDRLEN || ((const struct nlmsghdr *) data)->nlmsg_type != NLMSG_ERROR)
    return 0;
  u32 offset = 0;
  while (offset < length)
    {
      if (length - offset < NLMSG_HDRLEN) goto malformed;
      const struct nlmsghdr *nlh = (const struct nlmsghdr *) (data + offset);
      if (nlh->nlmsg_type != NLMSG_ERROR ||
          nlh->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr)) ||
          nlh->nlmsg_len > length - offset) goto malformed;
      const struct nlmsgerr *reply = NLMSG_DATA (nlh);
      if (reply->error > 0 || reply->error == INT32_MIN ||
          reply->msg.nlmsg_len < NLMSG_HDRLEN) goto malformed;
      u32 step = NLMSG_ALIGN (nlh->nlmsg_len);
      if (step > length - offset)
        { if (nlh->nlmsg_len != length - offset) goto malformed; step = length - offset; }
      offset += step;
    }
  for (offset = 0; offset < length;)
    {
      const struct nlmsghdr *nlh = (const struct nlmsghdr *) (data + offset);
      const struct nlmsgerr *reply = NLMSG_DATA (nlh);
      lane->control_replies++;
      if (reply->error < 0)
        {
          u32 error = (u32) -reply->error;
          if (!lane->control_errors)
            { lane->control_first_error = error; lane->control_first_sequence = nlh->nlmsg_seq; }
          lane->control_errors++;
          lane->control_last_error = error;
          lane->control_last_sequence = nlh->nlmsg_seq;
        }
      offset += clib_min (NLMSG_ALIGN (nlh->nlmsg_len), length - offset);
    }
  return 1;
malformed:
  lane->control_malformed++;
  return 0;
}

static clib_error_t *
product_root_nfqueue_read_dispatch (clib_file_t *file)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  product_root_nfqueue_lane_t *lane =
    uword_to_pointer (file->private_data, product_root_nfqueue_lane_t *);
  vlib_main_t *vm = vlib_get_main ();
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  product_root_input_batch_t batch = {0};
#endif

  if (lane && lane->draining) return 0;
  if (lane == 0 || lane->lane_index >= nm->lane_count
      || vm->thread_index != vlib_get_worker_thread_index (lane->worker_index)
      || file->file_descriptor != (u32) lane->fd)
    {
      product_root_nfqueue_mark_lane_fault (nm, lane, "identity", EINVAL);
      return clib_error_return (0, "Root NFQUEUE lane identity missing");
    }
  if (lane->draining || lane->receive_paused)
    return 0;

  lane->read_callbacks++;
  for (u32 budget = 0; budget < lane->read_budget; budget++)
    {
      u32 buffer_index;
      u16 receive_slot;
      int reserve_buffer = 0;
      vlib_buffer_t *buffer;
      u8 *base;
      u32 data_size;
      ssize_t received;
      product_root_nfqueue_packet_t packet;
      product_platform_packet_facts_t platform;
      const sakamoto_product_network_snapshot_t *network = product_network_snapshot_current ();
      product_root_nfqueue_pending_t *pending;
      u64 obligation_id;
      int submitted;

      receive_slot = product_root_receive_pool_take (
        &lane->receive_pool, lane->generation, 0);
      if (receive_slot == PRODUCT_ROOT_RECEIVE_NONE)
        {
          reserve_buffer = 1;
          receive_slot = product_root_receive_pool_take (
            &lane->receive_pool, lane->generation, 1);
        }
      if (receive_slot == PRODUCT_ROOT_RECEIVE_NONE)
        {
          /* No packet bytes are copied into a temporary heap/stack buffer.
           * Consuming without storage loses the mandatory identity. The
           * kernel obligation cannot be verdicted and survives until queue
           * teardown; later queue-full bypass is a separate kernel origin. */
          lane->recv_calls++;
          received = recv (lane->fd, 0, 0, MSG_DONTWAIT | MSG_TRUNC);
          if (received < 0)
            {
              int saved_errno = errno;
              if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) lane->recv_eagain++;
              else if (saved_errno == EINTR) lane->recv_eintr++;
              else if (saved_errno == ENOBUFS) lane->recv_enobufs++;
              if (product_root_nfqueue_transient_errno (saved_errno))
                {
                  if (saved_errno == ENOBUFS) lane->receive_overruns++;
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
                  product_root_input_batch_flush (vm, nm, lane, &batch);
#endif
                  return 0;
                }
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
              product_root_input_batch_flush (vm, nm, lane, &batch);
#endif
              product_root_nfqueue_mark_lane_fault (nm, lane, "discard", saved_errno);
              return clib_error_return_unix (0, "Root NFQUEUE discard");
            }
          lane->receive_datagrams++;
          lane->reserve_losses++;
          if (lane->reserve_losses <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
            fprintf (stderr, "s233 event=ingress_loss generation=%llu thread=%u lane=%u queue=%u reason=reserve_exhausted bytes=%lld verdict_attempted=0\n",
              (unsigned long long) lane->generation, vm->thread_index,
              lane->lane_index, lane->queue_id, (long long) received);
          continue;
        }
      buffer_index = lane->receive_pool.buffers[receive_slot];
      buffer = vlib_get_buffer (vm, buffer_index);
      if (PREDICT_FALSE (buffer->ref_count != 1
                        || (buffer->flags & VLIB_BUFFER_NEXT_PRESENT)))
        clib_panic ("Root receive buffer is not exclusively returned");
      buffer->template = vlib_get_buffer_pool (vm, buffer->buffer_pool_index)->buffer_template;
      buffer->trace_handle = buffer->total_length_not_including_first_buffer = 0;
      clib_memset (buffer->opaque2, 0, sizeof (buffer->opaque2));
      base = vlib_buffer_get_current (buffer);
      data_size = vlib_buffer_get_default_data_size (vm);
      lane->recv_calls++;
      received = recv ((int) file->file_descriptor, base, data_size,
                       MSG_DONTWAIT | MSG_TRUNC);
      if (received < 0)
        {
          int saved_errno = errno;
          if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) lane->recv_eagain++;
          else if (saved_errno == EINTR) lane->recv_eintr++;
          else if (saved_errno == ENOBUFS) lane->recv_enobufs++;
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
          if (product_root_nfqueue_transient_errno (saved_errno))
            {
              if (saved_errno == ENOBUFS) lane->receive_overruns++;
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
              product_root_input_batch_flush (vm, nm, lane, &batch);
#endif
              return 0;
            }
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
          product_root_input_batch_flush (vm, nm, lane, &batch);
#endif
          product_root_nfqueue_mark_lane_fault (nm, lane, "recv", saved_errno);
          return clib_error_return_unix (0, "Root NFQUEUE recv");
        }
      lane->receive_datagrams++;
      u32 visible = (u32) clib_min (received, (ssize_t) data_size);
      if (received <= (ssize_t) data_size &&
          product_root_nfqueue_consume_control (lane, base, visible))
        {
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
          continue;
        }
      if (lane->identity_fault
          || nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_MISSING_IDENTITY)
        {
          lane->identity_losses++;
          clib_atomic_fetch_add_relax (&nm->ingress_identity_missing, 1);
          if (lane->identity_losses <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
            fprintf (stderr, "s233 event=ingress_loss generation=%llu thread=%u lane=%u queue=%u reason=missing_identity bytes=%lld verdict_attempted=0\n",
              (unsigned long long) lane->generation, vm->thread_index,
              lane->lane_index, lane->queue_id, (long long) received);
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
          continue;
        }
      struct nlmsghdr *nlh = (struct nlmsghdr *) base;
      int single_packet = visible >= NLMSG_LENGTH (sizeof (struct nfgenmsg))
        && nlh->nlmsg_len <= visible && NLMSG_ALIGN (nlh->nlmsg_len) == NLMSG_ALIGN (visible)
        && NFNL_SUBSYS_ID (nlh->nlmsg_type) == NFNL_SUBSYS_QUEUE
        && NFNL_MSG_TYPE (nlh->nlmsg_type) == NFQNL_MSG_PACKET
        && ntohs (((struct nfgenmsg *) NLMSG_DATA (nlh))->res_id) == lane->queue_id;
      if (reserve_buffer || !single_packet || received > (ssize_t) data_size
          || !product_root_nfqueue_parse_packet (base, visible, &packet))
        {
          u64 attempts_before = lane->ingress_accepts;
          product_root_nfqueue_accept_unadmitted (nm, lane, base, visible,
            reserve_buffer ? "normal_exhausted" : "unadmitted_envelope");
          if (reserve_buffer)
            lane->reserve_accepts += lane->ingress_accepts - attempts_before;
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
          continue;
        }

      lane->callback_thread = vm->thread_index;
      lane->callback_tls = vlib_get_thread_index ();
      if (lane->packets_seen < product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
        {
          lane->last_cpu = UINT32_MAX;
          syscall (SYS_getcpu, &lane->last_cpu, 0, 0);
        }
      lane->packets_seen++;
      clib_atomic_fetch_add_relax (&nm->packets_seen, 1);
      product_root_nfqueue_packet_t observed = packet;
      /* Capture scope belongs to the supervisor's kernel rules. A configured
       * subject is not a packet identity, including across user namespaces.
       * Faults alter only parsed attribute evidence after real ingress.
       * Packet bytes and NFQUEUE completion identity are real.
       * They never run unless explicitly selected by the diagnostic CLI. */
      switch (nm->facts_fault)
        {
        case 1: packet.uid_present = 0; packet.uid = 0; break;
        case 2: packet.uid_present = 1; packet.uid = 0; break;
        case 3: packet.indev_present = packet.outdev_present = 0; break;
        case 4: packet.indev = packet.outdev = 0; break;
        case 5:
          if (packet.hook == NF_INET_LOCAL_OUT)
            { packet.indev_present = 1; packet.indev = 33333; }
          else if (packet.hook == NF_INET_LOCAL_IN)
            { packet.outdev_present = 1; packet.outdev = 33334; }
          break;
        case 6: packet.hook = UINT8_MAX; break;
        default: break;
        }
      if (packet.hook == NF_INET_LOCAL_IN)
        clib_atomic_fetch_add_relax (&nm->input_packets, 1);
      else if (packet.hook == NF_INET_LOCAL_OUT)
        clib_atomic_fetch_add_relax (&nm->output_packets, 1);
      if (packet.ip_family == 4)
        clib_atomic_fetch_add_relax (&nm->ipv4_packets, 1);
      else if (packet.ip_family == 6)
        clib_atomic_fetch_add_relax (&nm->ipv6_packets, 1);
      if (packet.protocol == IPPROTO_TCP)
        clib_atomic_fetch_add_relax (&nm->tcp_packets, 1);
      else if (packet.protocol == IPPROTO_UDP)
        clib_atomic_fetch_add_relax (&nm->udp_packets, 1);
      if (packet.uid_present)
        clib_atomic_fetch_add_relax (&nm->uid_known_packets, 1);
      else
        clib_atomic_fetch_add_relax (&nm->uid_unknown_packets, 1);
      lane->last_packet_id = packet.packet_id;
      lane->last_queue_id = lane->queue_id;
      lane->last_uid = packet.uid_present ? packet.uid : UINT32_MAX;
      lane->last_ip_family = packet.ip_family;
      lane->last_protocol = packet.protocol;
      lane->last_hook = packet.hook;
      lane->last_uid_known = packet.uid_present ? 1 : 0;
      clib_atomic_store_rel_n (&nm->last_lane, lane->lane_index);
      buffer->current_data =
        (i16) (buffer->current_data + (packet.payload - base));
      buffer->current_length = (u16) packet.payload_length;
      clib_memset (&platform, 0, sizeof (platform));
      platform.uid = packet.uid_present ? packet.uid : 0;
      platform.availability = packet.uid_present ? PRODUCT_PLATFORM_UID_KNOWN : 0;
      platform.provenance = PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE;
      platform.direction = packet.hook == NF_INET_LOCAL_OUT
        ? PRODUCT_PACKET_DIRECTION_OUTPUT : packet.hook == NF_INET_LOCAL_IN
        ? PRODUCT_PACKET_DIRECTION_INPUT : PRODUCT_PACKET_DIRECTION_UNKNOWN;
      if (packet.hook == NF_INET_LOCAL_OUT && packet.outdev_present
          && packet.outdev && packet.outdev <= INT32_MAX)
        {
          platform.linux_ifindex = packet.outdev;
          platform.availability |= PRODUCT_PLATFORM_IFINDEX_KNOWN;
        }
      else if (packet.hook == NF_INET_LOCAL_IN && packet.indev_present
               && packet.indev && packet.indev <= INT32_MAX)
        {
          platform.linux_ifindex = packet.indev;
          platform.availability |= PRODUCT_PLATFORM_IFINDEX_KNOWN;
        }
      if (platform.availability & PRODUCT_PLATFORM_IFINDEX_KNOWN)
        for (u32 i = 0; i < network->count; ++i)
          if (network->entries[i].linux_ifindex
              == platform.linux_ifindex)
            {
              platform.network_context_id =
                network->entries[i].context;
              platform.availability |= PRODUCT_PLATFORM_CONTEXT_KNOWN;
              break;
            }

      if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_GRAPH_SUBMIT_FAIL_OPEN)
        {
          product_root_nfqueue_accept_unadmitted (
            nm, lane, base, visible, "graph_submit_rejected");
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
          continue;
        }
      pending = product_root_nfqueue_reserve (
        nm, lane, packet.packet_id, buffer_index, receive_slot);
      if (!pending)
        {
          product_root_nfqueue_accept_unadmitted (
            nm, lane, base, visible, "completion_capacity");
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
          continue;
        }
      obligation_id = pending->completion.obligation.token;
      if (lane->packets_seen <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
        {
        fprintf (stderr, "s232 event=packet_snapshot generation=%llu token=%llu revision=%llu event_elapsed_ns=%llu ifindex=%u context=%u availability=%u\n",
          (unsigned long long) nm->generation, (unsigned long long) obligation_id,
          (unsigned long long) network->revision,
          (unsigned long long) network->event_elapsed_ns,
          platform.linux_ifindex, platform.network_context_id, platform.availability);
        fprintf (stderr, "s217 event=nfq_facts source=NFQ_CAPTURED thread=%u lane=%u token=%llu generation=%llu packet=%u fault=%u raw_hook=%u raw_uid_present=%u raw_uid=%u raw_indev_present=%u raw_indev=%u raw_outdev_present=%u raw_outdev=%u hook=%u uid_present=%u uid=%u indev_present=%u indev=%u outdev_present=%u outdev=%u normalized_uid=%u normalized_ifindex=%u availability=%u direction=%u context=%u provenance=%u\n",
          vm->thread_index, lane->lane_index, (unsigned long long) obligation_id,
          (unsigned long long) nm->generation, packet.packet_id, nm->facts_fault,
          observed.hook, observed.uid_present, observed.uid,
          observed.indev_present, observed.indev, observed.outdev_present, observed.outdev,
          packet.hook, packet.uid_present, packet.uid, packet.indev_present, packet.indev,
          packet.outdev_present, packet.outdev, platform.uid, platform.linux_ifindex,
          platform.availability, platform.direction, platform.network_context_id,
          platform.provenance);
        fprintf(stderr, "s203 event=capture source=NFQ_CAPTURED thread=%u tls=%u polling_thread=%u lane=%u queue=%u packet=%u buffer=%u obligation=%llu\n",
          vm->thread_index, vlib_get_thread_index(), file->polling_thread_index,
          lane->lane_index, lane->queue_id, packet.packet_id, buffer_index,
          (unsigned long long)obligation_id);
        /* Adapter observation only: preserve absent NFQA attributes as unknown.
         * Neither these fields nor this bounded wire trace classify packets. */
        flockfile (stderr);
        fprintf (stderr, "s217 event=netlink_message source=NFQ_CAPTURED thread=%u token=%llu generation=%llu bytes=%u raw=",
          vm->thread_index, (unsigned long long) obligation_id,
          (unsigned long long) nm->generation, (u32) received);
        product_diagnostic_write_hex (stderr, base, (u32) received);
        fprintf (stderr, "\n");
        fprintf (stderr, "s231 event=nfq_payload source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u buffer=%u token=%llu generation=%llu hook=%u family=%u payload_bytes=%u cap_len_known=%u cap_len=%u skb_info_known=%u skb_info=%u raw=",
          vm->thread_index, lane->lane_index, lane->queue_id, packet.packet_id,
          buffer_index, (unsigned long long) obligation_id,
          (unsigned long long) nm->generation, packet.hook, packet.ip_family,
          packet.payload_length, packet.captured_length_present,
          packet.captured_length, packet.skb_info_present, packet.skb_info);
        product_diagnostic_write_hex (stderr, packet.payload, packet.payload_length);
        fprintf (stderr, "\n");
        funlockfile (stderr);
        }
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
      u32 position = batch.count++;
      batch.items[position] = (product_packet_graph_external_item_t) {
        .buffer_index = buffer_index, .platform = platform,
        .obligation = pending->completion.obligation,
      };
      batch.visible[position] = visible;
      batch.envelope_offset[position] = (i16) (base - buffer->data);
      /* The listener fixture admits exactly one packet before the fault. */
      submitted = 0;
      if (batch.count == PRODUCT_ROOT_INPUT_BATCH_SIZE || lane->listener_fault_after_submit)
        submitted = product_root_input_batch_flush (vm, nm, lane, &batch) != 0;
      if (submitted && lane->listener_fault_after_submit)
        {
          lane->listener_fault_after_submit = 0;
          fprintf (stderr, "s296 event=inflight_fault_fixture generation=%llu lane=%u pending=%u packet=%u\n",
            (unsigned long long) nm->generation, lane->lane_index,
            lane->pending_count, packet.packet_id);
          product_root_nfqueue_mark_lane_fault (nm, lane, "epoll", EBADF);
          return clib_error_return (0, "Root listener fault fixture after submit");
        }
#else
      submitted = product_packet_graph_submit_external (
        vm, buffer_index, &platform,
        &pending->completion.obligation);
      if (!submitted)
        {
          product_root_nfqueue_pending_deactivate (nm, lane, pending);
          product_root_nfqueue_accept_unadmitted (
            nm, lane, base, visible, "graph_submit_rejected");
          product_root_nfqueue_return_receive (lane, receive_slot, buffer_index);
        }
      else
        {
          lane->packets_submitted++;
          clib_atomic_fetch_add_relax (&nm->packets_submitted, 1);
          if (lane->packets_submitted <= product_packet_graph_trace_limit () / PRODUCT_ROOT_NFQUEUE_MAX_LANES)
          fprintf(stderr, "s203 event=frame_accept source=NFQ_CAPTURED thread=%u lane=%u queue=%u packet=%u buffer=%u obligation=%llu generation=%llu\n",
            vm->thread_index, lane->lane_index, lane->queue_id, packet.packet_id,
            buffer_index, (unsigned long long)obligation_id,
            (unsigned long long)nm->generation);
          if (lane->listener_fault_after_submit)
            {
              lane->listener_fault_after_submit = 0;
              fprintf (stderr, "s296 event=inflight_fault_fixture generation=%llu lane=%u pending=%u packet=%u\n",
                (unsigned long long) nm->generation, lane->lane_index,
                lane->pending_count, packet.packet_id);
              product_root_nfqueue_mark_lane_fault (nm, lane, "epoll", EBADF);
              return clib_error_return (0, "Root listener fault fixture after submit");
            }
        }
#endif
    }
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  product_root_input_batch_flush (vm, nm, lane, &batch);
#endif
  return 0;
}

static clib_error_t *
product_root_nfqueue_read_ready (clib_file_t *file)
{
  product_root_nfqueue_lane_t *lane =
    uword_to_pointer (file->private_data, product_root_nfqueue_lane_t *);
  u64 calls = lane ? lane->read_callbacks : 0;
  u64 before = lane ? lane->receive_datagrams : 0;
  clib_error_t *error = product_root_nfqueue_read_dispatch (file);
  if (lane && lane->read_callbacks != calls)
    {
      u64 count = lane->receive_datagrams - before;
      lane->read_callback_datagrams += count;
      lane->read_callback_max = clib_max (lane->read_callback_max, count);
      lane->read_empty_callbacks += count == 0;
      lane->read_budget_exits += !error && count == lane->read_budget;
    }
  return error;
}

static clib_error_t *
product_root_nfqueue_handle_socket_error (product_root_nfqueue_main_t *nm,
                                           product_root_nfqueue_lane_t *lane,
                                           int fault_errno)
{
  if (product_root_nfqueue_transient_errno (fault_errno))
    {
      if (fault_errno == ENOBUFS) lane->receive_overruns++;
      return 0;
    }
  product_root_nfqueue_mark_lane_fault (nm, lane, "epoll", fault_errno);
  return clib_error_return (0, "Root NFQUEUE EPOLLERR lane %u errno %d",
                            lane->lane_index, fault_errno);
}

static clib_error_t *
product_root_nfqueue_error_ready (clib_file_t *file)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  product_root_nfqueue_lane_t *lane =
    uword_to_pointer (file->private_data, product_root_nfqueue_lane_t *);
  if (!lane || lane->generation != nm->generation || lane->draining)
    return 0;
  int fault_errno = 0;
  socklen_t length = sizeof (fault_errno);
  if (getsockopt ((int) file->file_descriptor, SOL_SOCKET, SO_ERROR,
                  &fault_errno, &length) < 0)
    fault_errno = errno;
  /* SO_ERROR=0 with EPOLLERR has no classified recoverable socket error.
   * Keep the verdict FD for bounded drain but withdraw capture readiness. */
  clib_error_t *error = product_root_nfqueue_handle_socket_error (nm, lane, fault_errno);
  /* Consuming SO_ERROR alone does not clear Netlink's congestion latch. A
   * bounded recv path reaches netlink_rcv_wake even when the queue is empty;
   * otherwise an overrun can leave a ready lane receiving no future packets. */
  if (!error && fault_errno == ENOBUFS)
    return product_root_nfqueue_read_ready (file);
  return error;
}

static void
product_root_nfqueue_reset_lane (product_root_nfqueue_lane_t *lane,
                                 u32 lane_index, u32 queue_id)
{
  clib_memset (lane, 0, sizeof (*lane));
  lane->fd = -1;
  lane->clib_file_index = ~0;
  lane->queue_id = queue_id;
  lane->lane_index = lane_index;
  lane->family_lane = lane_index % 2;
  lane->worker_index = lane->family_lane;
  lane->ip_family = lane_index < 2 ? 4 : 6;
  lane->last_uid = UINT32_MAX;
  lane->last_cpu = UINT32_MAX;
  lane->read_budget = PRODUCT_ROOT_DEFAULT_READ_BUDGET;
}

/* SO_RCVBUF is an ordinary, capped socket option. The returned value is the
 * kernel's accounting capacity (usually twice the request), never an inferred
 * packet count. No SO_RCVBUFFORCE or global sysctl is used. */
static int
product_root_nfqueue_read_rcvbuf (int fd, u32 *effective)
{
  int value = 0;
  socklen_t length = sizeof (value);
  if (getsockopt (fd, SOL_SOCKET, SO_RCVBUF, &value, &length) < 0)
    return 0;
  if (length != sizeof (value) || value <= 0)
    { errno = EIO; return 0; }
  *effective = (u32) value;
  return 1;
}

static int
product_root_nfqueue_apply_io_tuning (product_root_nfqueue_lane_t *lane,
                                      u32 budget, u32 rcvbuf_request)
{
  if (!lane || !lane->socket_ready || lane->draining || lane->fd < 0
      || !budget || budget > PRODUCT_ROOT_NFQUEUE_READ_BUDGET
      || rcvbuf_request > PRODUCT_ROOT_NFQUEUE_RCVBUF_REQUEST_LIMIT)
    { errno = EINVAL; return 0; }
  u32 effective;
  if (!product_root_nfqueue_read_rcvbuf (lane->fd, &effective)) return 0;
  if (rcvbuf_request)
    {
      int request = (int) rcvbuf_request;
      if (setsockopt (lane->fd, SOL_SOCKET, SO_RCVBUF, &request, sizeof (request)) < 0)
        return 0;
      /* The socket has changed even if the subsequent read fails. Expose
       * unknown effective capacity instead of retaining a stale value. */
      lane->rcvbuf_requested = rcvbuf_request;
      lane->rcvbuf_effective = 0;
      if (!product_root_nfqueue_read_rcvbuf (lane->fd, &effective)) return 0;
    }
  lane->rcvbuf_effective = effective;
  lane->read_budget = budget;
  return 1;
}

static int
product_root_nfqueue_open_lane (product_root_nfqueue_main_t *nm,
                                product_root_nfqueue_lane_t *lane)
{
  struct sockaddr_nl address;
  clib_file_t template = { 0 };
  int fd;

  fd = socket (AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
               NETLINK_NETFILTER);
  if (fd < 0)
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      product_root_nfqueue_warn_errno ("socket");
      return 0;
    }

  clib_memset (&address, 0, sizeof (address));
  address.nl_family = AF_NETLINK;
  if (bind (fd, (struct sockaddr *) &address, sizeof (address)) < 0)
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      product_root_nfqueue_warn_errno ("bind");
      close (fd);
      return 0;
    }
  lane->fd = fd;
  lane->socket_ready = 1;

  if (!product_root_nfqueue_apply_io_tuning (lane,
        PRODUCT_ROOT_DEFAULT_READ_BUDGET, PRODUCT_ROOT_DEFAULT_RCVBUF_REQUEST))
    {
      product_root_nfqueue_last_errno = errno == 0 ? EIO : errno;
      close (fd); lane->fd = -1; lane->socket_ready = 0;
      return 0;
    }

  if (!product_nfqueue_configure (fd, lane->queue_id, lane->ip_family,
                                  lane->queue_maxlen))
    {
      fprintf (stderr, "s242 event=lane_open_failed generation=%llu lane=%u family=%u queue=%u fd=%d stage=configure errno=%d\n",
        (unsigned long long) lane->generation, lane->lane_index, lane->ip_family,
        lane->queue_id, fd, product_root_nfqueue_last_errno);
      close (fd);
      lane->fd = -1;
      lane->socket_ready = 0;
      return 0;
    }
  lane->queue_flags = PRODUCT_ROOT_NFQUEUE_FLAGS;
  fprintf (stderr, "s233 event=queue_config generation=%llu lane=%u family=%u queue=%u flags=%u maxlen=%u ack=0\n",
    (unsigned long long) lane->generation, lane->lane_index, lane->ip_family,
    lane->queue_id, lane->queue_flags, lane->queue_maxlen);

  template.read_function = product_root_nfqueue_read_ready;
  template.error_function = product_root_nfqueue_error_ready;
  template.polling_thread_index = vlib_get_worker_thread_index (lane->worker_index);
  template.file_descriptor = (u32) fd;
  template.private_data = pointer_to_uword (lane);
  template.description =
    format (0, "sakamoto-root-nfqueue-%u%c", lane->queue_id, 0);
  lane->clib_file_index = clib_file_add (&file_main, &template);
  lane->listener_ready = 1;
  nm->ready_lane_mask |= 1U << lane->lane_index;
  return 1;
}

static void
product_root_nfqueue_restore_withheld (product_root_nfqueue_lane_t *lane)
{
  while (lane->withheld_count)
    {
      u16 slot = lane->withheld[--lane->withheld_count];
      if (!product_root_receive_pool_return (&lane->receive_pool,
            lane->generation, slot, lane->receive_pool.buffers[slot]))
        clib_panic ("Root withheld buffer identity mismatch");
    }
}

static void
product_root_nfqueue_release_pool (vlib_main_t *vm,
                                  product_root_nfqueue_lane_t *lane)
{
  product_root_nfqueue_restore_withheld (lane);
  if (PREDICT_FALSE (lane->receive_pool.outstanding))
    clib_panic ("Root receive pool released with live loans");
  if (lane->receive_allocated)
    vlib_buffer_free (vm, lane->receive_pool.buffers, lane->receive_allocated);
  lane->receive_allocated = 0;
  clib_memset (&lane->receive_pool, 0, sizeof (lane->receive_pool));
}

/* CLI worker barrier plus an empty generation is required. Allocate the new
 * bounded reservation before releasing the old one, preserving it on failure.
 * Ordinary startup still allocates only 64+8 buffers. No packet-path growth. */
static int
product_root_nfqueue_resize_empty_pool (vlib_main_t *vm,
  product_root_nfqueue_lane_t *lane, u32 normal)
{
  _Static_assert (PRODUCT_ROOT_RECEIVE_MAX_NORMAL == PRODUCT_ROOT_COMPLETION_MAX_CAPACITY,
                  "receive reservation and ledger banks have the same limit");
  _Static_assert (PRODUCT_ROOT_RECEIVE_MAX_TOTAL <= UINT8_MAX,
                  "completion receive slots fit their existing byte field");
  if (!vm || !lane || !lane->generation || !lane->socket_ready || lane->draining
      || lane->receive_paused || lane->pending_count || lane->withheld_count
      || lane->receive_pool.outstanding
      || (normal != PRODUCT_ROOT_RECEIVE_MIN_NORMAL && normal != PRODUCT_ROOT_RECEIVE_MAX_NORMAL))
    { errno = EINVAL; return 0; }
  if (normal == lane->receive_pool.normal_capacity) return 1;
  u32 buffers[PRODUCT_ROOT_RECEIVE_MAX_TOTAL];
  u32 total = normal + PRODUCT_ROOT_RECEIVE_RESERVE;
  u32 allocated = vlib_buffer_alloc (vm, buffers, total);
  if (allocated != total)
    {
      vlib_buffer_free (vm, buffers, allocated);
      errno = ENOMEM;
      return 0;
    }
  vlib_buffer_free (vm, lane->receive_pool.buffers, lane->receive_allocated);
  if (!product_root_receive_pool_init_capacity (
        &lane->receive_pool, lane->generation, buffers, (u16) normal))
    clib_panic ("Root empty receive reservation identity mismatch");
  lane->receive_allocated = total;
  clib_memset (lane->pending, 0, sizeof (lane->pending));
  lane->pending_active_slots = lane->pending_displaced_slots = 0;
  lane->pending_active_slots_high = lane->pending_displaced_slots_high = 0;
  return 1;
}

/* Diagnostic only, before the fixture produces traffic. ACK processing peeks
 * first and never consumes an unexpected packet envelope. If an ACK cannot be
 * established after submission, expose unknown maxlen rather than an old value. */
static int
product_root_nfqueue_apply_maxlen (product_root_nfqueue_lane_t *lane, u32 maxlen)
{
  if (!lane || !lane->socket_ready || lane->draining || lane->fd < 0
      || lane->pending_count || lane->receive_pool.outstanding || lane->withheld_count
      || !maxlen || maxlen > 65536)
    { errno = EINVAL; return 0; }
  u8 reply[512];
  ssize_t received = recv (lane->fd, reply, sizeof (reply), MSG_PEEK | MSG_DONTWAIT);
  if (received >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
    { if (received >= 0) errno = EBUSY; return 0; }
  union {
    u8 bytes[NLMSG_SPACE (sizeof (struct nfgenmsg)) + NFA_SPACE (sizeof (u32))];
    struct nlmsghdr nlh;
  } request;
  product_nfnl_fill_header (&request.nlh, sizeof (request), NFQNL_MSG_CONFIG, lane->queue_id);
  request.nlh.nlmsg_seq = UINT32_C (0xffff0000) | lane->queue_id;
  u32 value = htonl (maxlen);
  if (!product_nfnl_addattr (&request.nlh, sizeof (request), NFQA_CFG_QUEUE_MAXLEN,
                            &value, sizeof (value)))
    { errno = EINVAL; return 0; }
  if (!product_nfnl_send (lane->fd, &request.nlh, 0))
    { errno = product_root_nfqueue_last_errno; return 0; }
  lane->queue_maxlen = 0;
  for (u32 attempt = 0; attempt < 100; ++attempt)
    {
      received = recv (lane->fd, reply, sizeof (reply), MSG_PEEK | MSG_DONTWAIT);
      if (received < 0)
        {
          if (errno == EAGAIN || errno == EWOULDBLOCK) { usleep (1000); continue; }
          return 0;
        }
      struct nlmsghdr *nlh = (struct nlmsghdr *) reply;
      if (received < (ssize_t) NLMSG_LENGTH (sizeof (struct nlmsgerr))
          || nlh->nlmsg_type != NLMSG_ERROR || nlh->nlmsg_seq != request.nlh.nlmsg_seq
          || nlh->nlmsg_len < NLMSG_LENGTH (sizeof (struct nlmsgerr))
          || NLMSG_ALIGN (nlh->nlmsg_len) != (u32) received)
        { errno = EBUSY; return 0; }
      int error = ((struct nlmsgerr *) NLMSG_DATA (nlh))->error;
      if (recv (lane->fd, reply, sizeof (reply), MSG_DONTWAIT) != received)
        { errno = EIO; return 0; }
      if (error) { errno = -error; return 0; }
      lane->queue_maxlen = maxlen;
      return 1;
    }
  errno = ETIMEDOUT;
  return 0;
}

int
product_root_nfqueue_adapter_start (vlib_main_t *vm, u64 generation)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index, queue_maxlen;

  if (nm->available)
    return 1;
  if (vm == 0 || generation == 0)
    return 0;
  if (!product_root_nfqueue_maxlen_from_env (&queue_maxlen))
    {
      clib_warning ("Root NFQUEUE maxlen must be 1..65536");
      return 0;
    }

  nm->vlib_main = vm;
  nm->queue_id = product_root_nfqueue_queue_from_env ();
  nm->lane_count = product_root_nfqueue_lanes_from_env ();
  if (nm->lane_count != PRODUCT_ROOT_NFQUEUE_MAX_LANES
      || nm->queue_id > UINT16_MAX - (nm->lane_count - 1)
      || vlib_num_workers () != 2)
    return 0;
  nm->queue_last = nm->queue_id + nm->lane_count - 1;
  if (!product_root_nfqueue_uid_from_env (&nm->uid_owner))
    {
      clib_warning ("root nfqueue start failed: missing app uid owner");
      return 0;
    }
  nm->generation = generation;
  product_network_snapshot_start (generation);
  nm->last_lane = 0;
  nm->facts_fault = 0;
  nm->pending_count = 0;
  nm->replay_count = 0;
  nm->fault_mode = product_root_nfqueue_fault_mode_from_env ();
  if (nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_DUPLICATE_COMPLETION
      || nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_STALE_COMPLETION
      || nm->fault_mode == PRODUCT_ROOT_NFQUEUE_FAULT_VERDICT_OUTCOME_UNKNOWN)
    {
      /* No syscall observation means no successful/failed native attempt.
       * Process-death unknowns belong to the supervisor's OS-reclaim audit,
       * not a synthetic verdict counter. Replay uses a captured CLI identity. */
      clib_warning ("root nfqueue start rejected: unsupported synthetic completion fault");
      product_network_snapshot_stop ();
      return 0;
    }
  nm->packets_seen = 0;
  nm->packets_submitted = 0;
  nm->verdict_attempts = 0;
  nm->verdict_succeeded = 0;
  nm->verdict_failed = 0;
  nm->internal_settlements = 0;
  nm->buffer_returns = 0;
  nm->origin_local_completions = 0;
  nm->origin_remote_completions = 0;
  nm->input_packets = 0;
  nm->output_packets = 0;
  nm->ipv4_packets = 0;
  nm->ipv6_packets = 0;
  nm->tcp_packets = 0;
  nm->udp_packets = 0;
  nm->uid_known_packets = 0;
  nm->uid_unknown_packets = 0;
  nm->verdict_succeeded = 0;
  nm->verdict_failed_definite = 0;
  nm->verdict_outcome_unknown = 0;
  nm->ingress_identity_missing = 0;
  nm->graph_submit_fail_opens = 0;
  nm->non_owner_bypasses = 0;
  nm->duplicate_completion_drops = 0;
  nm->stale_completion_drops = 0;
  nm->ready_lane_mask = 0;
  nm->fault_latched = nm->fault_pending = 0;
  nm->fault_retry_count = nm->fault_drain_steps = 0;
  nm->fault_lane = UINT32_MAX;
  nm->fault_errno = 0;
  const char *fault_path = getenv ("SAKAMOTO_PRODUCT_ROOT_FAULT_SOCKET");
  nm->fault_socket_path[0] = 0;
  nm->fault_socket_fd = -1;
  nm->fault_timer_fd = timerfd_create (CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
  if (nm->fault_timer_fd < 0)
    {
      product_root_nfqueue_adapter_stop (vm);
      return 0;
    }
  clib_file_t timer = {
    .file_descriptor = (u32) nm->fault_timer_fd,
    .polling_thread_index = 0,
    .private_data = generation,
    .read_function = product_root_nfqueue_fault_retry,
    .error_function = product_root_nfqueue_fault_retry,
    .description = format (0, "sakamoto-root-fault-retry%c", 0),
  };
  nm->fault_timer_file = clib_file_add (&file_main, &timer);
  if (fault_path && fault_path[0])
    {
      if (strlen (fault_path) >= sizeof (nm->fault_socket_path))
        {
          product_root_nfqueue_adapter_stop (vm);
          return 0;
        }
      strcpy (nm->fault_socket_path, fault_path);
      nm->fault_socket_fd = socket (AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
      if (nm->fault_socket_fd < 0)
        {
          product_root_nfqueue_adapter_stop (vm);
          return 0;
        }
      struct sockaddr_un address = { .sun_family = AF_UNIX };
      strcpy (address.sun_path, nm->fault_socket_path);
      if (connect (nm->fault_socket_fd, (struct sockaddr *) &address,
                   sizeof (address)) < 0)
        {
          product_root_nfqueue_adapter_stop (vm);
          return 0;
        }
    }
  else nm->fault_retry_count = 30; /* Host has an external exit supervisor. */
  nm->hook_ready = 0;
  nm->available = 0;

  for (index = 0; index < PRODUCT_ROOT_NFQUEUE_MAX_LANES; index++)
    {
      product_root_nfqueue_reset_lane (&nm->lanes[index], index, nm->queue_id + index);
      nm->lanes[index].generation = generation;
      nm->lanes[index].queue_maxlen = queue_maxlen;
    }

  if (!product_packet_graph_start_external (vm, generation,
        PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE))
    {
      product_root_nfqueue_adapter_stop (vm);
      return 0;
    }

  /* All receive storage is reserved before any listener becomes available.
   * Existing VPP pools remain the physical allocator; no receive hot-path
   * allocation or cross-lane replenishment follows. */
  for (index = 0; index < nm->lane_count; index++)
    {
      product_root_nfqueue_lane_t *lane = &nm->lanes[index];
      u32 buffers[PRODUCT_ROOT_RECEIVE_TOTAL];
      u32 allocated = vlib_buffer_alloc (vm, buffers, ARRAY_LEN (buffers));
      if (allocated != ARRAY_LEN (buffers))
        {
          vlib_buffer_free (vm, buffers, allocated);
          product_root_nfqueue_adapter_stop (vm);
          return 0;
        }
      if (!product_root_receive_pool_init (&lane->receive_pool, generation, buffers))
        clib_panic ("Root receive pool startup identity mismatch");
      lane->receive_allocated = allocated;
    }
  for (index = 0; index < nm->lane_count; index++)
    if (!product_root_nfqueue_open_lane (nm, &nm->lanes[index]))
      {
        product_root_nfqueue_adapter_stop (vm);
        return 0;
      }
  if (__atomic_load_n (&nm->fault_latched, __ATOMIC_ACQUIRE))
    {
      product_root_nfqueue_adapter_stop (vm);
      return 0;
    }

  /*
   * Android Runtime Supervisor installs/removes the platform INPUT/OUTPUT
   * hooks under KernelSU before launching Product VPP. VPP owns only the
   * NFQUEUE netlink sockets, VPP file listeners, and Product Packet completion
   * path.
   */
  nm->hook_ready = 1;
  nm->available = 1;
  product_network_snapshot_linux_start (vm);
  return 1;
}

void
product_root_nfqueue_adapter_stop (vlib_main_t *vm)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) vm;

  nm->available = 0;
  nm->hook_ready = 0;
  for (u32 i = 0; i < nm->lane_count; i++) nm->lanes[i].draining = 1;
  /* Do not return fixed storage or close verdict descriptors while a graph
   * carrier still owns it. Normal CLI stop retries after bounded drain. */
  if (nm->pending_count || product_packet_graph_buffer_debt ()
      || product_packet_graph_obligation_debt ()
      || product_packet_graph_handoff_debt ()
      || product_packet_graph_completion_frame_debt ())
    return;
  product_packet_graph_stop_external (nm->vlib_main);
  for (u32 count = PRODUCT_ROOT_NFQUEUE_MAX_LANES; count; count--)
    {
      u32 index = count - 1;
      product_root_nfqueue_lane_t *lane = &nm->lanes[index];
      int had_resources = lane->socket_ready || lane->listener_ready || lane->receive_allocated;
      if (had_resources)
        fprintf (stderr, "s242 event=lane_retire generation=%llu lane=%u family=%u queue=%u fd=%d pending=%u allocated=%u loans=%u verdicts=%llu succeeded=%llu failed=%llu settlements=%llu returns=%llu\n",
          (unsigned long long) lane->generation, index, lane->ip_family,
          lane->queue_id, lane->fd, lane->pending_count, lane->receive_allocated,
          (u32) lane->receive_pool.outstanding - lane->withheld_count,
          (unsigned long long) lane->verdict_attempts,
          (unsigned long long) lane->verdict_succeeded,
          (unsigned long long) lane->verdict_failed,
          (unsigned long long) lane->internal_settlements,
          (unsigned long long) lane->buffer_returns);
      if (lane->listener_ready && lane->clib_file_index != ~0)
        {
          clib_file_del_by_index (&file_main, lane->clib_file_index);
          lane->clib_file_index = ~0;
        }
      else if (lane->fd >= 0 && lane->socket_ready)
        {
          close (lane->fd);
        }
      lane->fd = -1;
      lane->listener_ready = 0;
      lane->socket_ready = 0;
      product_root_nfqueue_release_pool (vm, lane);
      if (had_resources)
        fprintf (stderr, "s242 event=lane_closed generation=%llu lane=%u fd=%d pending=%u allocated=%u loans=%u listener=%u socket=%u\n",
          (unsigned long long) lane->generation, index, lane->fd,
          lane->pending_count, lane->receive_allocated,
          (u32) lane->receive_pool.outstanding, lane->listener_ready, lane->socket_ready);
    }
  nm->ready_lane_mask = 0;
  __atomic_store_n (&nm->fault_pending, 0, __ATOMIC_RELEASE);
  if (nm->fault_timer_file != ~0)
    clib_file_del_by_index (&file_main, nm->fault_timer_file);
  nm->fault_timer_file = ~0;
  nm->fault_timer_fd = -1;
  if (nm->fault_socket_fd >= 0) close (nm->fault_socket_fd);
  nm->fault_socket_fd = -1;
  nm->fault_socket_path[0] = 0;
  product_network_snapshot_stop ();
}

int
product_root_nfqueue_adapter_stop_step (vlib_main_t *vm, u64 generation)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  if (!vm || !generation || generation != nm->generation)
    return -1;
  /* Admission stops on every lane before fragment retirement can publish
   * completion work. Do not disable graph execution or close verdict fds
   * until all already-admitted carriers have returned. */
  for (u32 i = 0; i < nm->lane_count; i++)
    {
      product_root_nfqueue_lane_t *lane = &nm->lanes[i];
      if (!lane->draining)
        fprintf (stderr, "s242 event=quiesce generation=%llu lane=%u fd=%d queue=%u pending=%u\n",
          (unsigned long long) generation, i, lane->fd, lane->queue_id,
          lane->pending_count);
      lane->draining = 1;
    }
  nm->available = 0;
  product_packet_graph_quiesce (vm);
  if (nm->pending_count || product_packet_graph_buffer_debt ()
      || product_packet_graph_obligation_debt ()
      || product_packet_graph_handoff_debt ()
      || product_packet_graph_completion_frame_debt ())
    return 0;
  product_root_nfqueue_adapter_stop (vm);
  fprintf (stderr, "s242 event=stop_native_zero generation=%llu ready_mask=%u graph_enabled=%u graph_accepting=%u pending=%u buffers=%llu obligations=%llu handoffs=%llu completion_frames=%llu\n",
    (unsigned long long) generation, nm->ready_lane_mask,
    product_packet_graph_enabled (), product_packet_graph_accepting (), nm->pending_count,
    (unsigned long long) product_packet_graph_buffer_debt (),
    (unsigned long long) product_packet_graph_obligation_debt (),
    (unsigned long long) product_packet_graph_handoff_debt (),
    (unsigned long long) product_packet_graph_completion_frame_debt ());
  return nm->ready_lane_mask == 0;
}

int
product_root_nfqueue_adapter_available (void)
{
  const product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  /* A diagnostic lane closure degrades the ready mask without stopping the
   * independent listeners. The full Q2/W2 mask remains explicit in status. */
  return __atomic_load_n (&nm->available, __ATOMIC_ACQUIRE)
         && nm->lane_count > 0 && nm->lane_count <= PRODUCT_ROOT_NFQUEUE_MAX_LANES
         && __atomic_load_n (&nm->ready_lane_mask, __ATOMIC_ACQUIRE)
              == (1U << nm->lane_count) - 1
         && nm->hook_ready && !__atomic_load_n (&nm->fault_latched, __ATOMIC_ACQUIRE);
}

uint32_t
product_root_nfqueue_adapter_queue_id (void)
{
  return product_root_nfqueue_main.queue_id;
}

uint32_t
product_root_nfqueue_adapter_queue_last (void)
{
  return product_root_nfqueue_main.queue_last;
}

uint32_t
product_root_nfqueue_adapter_lane_count (void)
{
  return product_root_nfqueue_main.lane_count;
}

uint32_t
product_root_nfqueue_adapter_ready_lane_mask (void)
{
  return product_root_nfqueue_main.ready_lane_mask;
}

uint64_t
product_root_nfqueue_adapter_generation (void)
{
  return product_root_nfqueue_main.generation;
}

uint64_t
product_root_nfqueue_adapter_verdict_attempts (void)
{
  return product_root_nfqueue_main.verdict_attempts;
}

uint64_t
product_root_nfqueue_adapter_verdict_succeeded (void)
{
  return product_root_nfqueue_main.verdict_succeeded;
}

#ifdef SAKAMOTO_PRODUCT_POLICY_QUALIFICATION_COUNTERS
uint64_t
product_root_nfqueue_adapter_policy_qualified_succeeded (void)
{
  u64 result = 0;
  for (u32 i = 0; i < product_root_nfqueue_main.lane_count; ++i)
    result += __atomic_load_n (&product_root_nfqueue_main.lanes[i].policy_qualified_succeeded,
                               __ATOMIC_RELAXED);
  return result;
}

void
product_root_nfqueue_adapter_policy_qualified_matched_succeeded (
  uint64_t *allow, uint64_t *drop)
{
  *allow = *drop = 0;
  for (u32 i = 0; i < product_root_nfqueue_main.lane_count; ++i)
    {
      product_root_nfqueue_lane_t *lane = &product_root_nfqueue_main.lanes[i];
      *allow += __atomic_load_n (&lane->policy_qualified_matched_allow_succeeded,
                                 __ATOMIC_RELAXED);
      *drop += __atomic_load_n (&lane->policy_qualified_matched_drop_succeeded,
                                __ATOMIC_RELAXED);
    }
}
#endif

uint64_t
product_root_nfqueue_adapter_verdict_failed_definite (void)
{
  return product_root_nfqueue_main.verdict_failed_definite;
}

uint64_t
product_root_nfqueue_adapter_verdict_outcome_unknown (void)
{
  return product_root_nfqueue_main.verdict_outcome_unknown;
}

uint64_t
product_root_nfqueue_adapter_ingress_identity_missing (void)
{
  return product_root_nfqueue_main.ingress_identity_missing;
}

uint64_t
product_root_nfqueue_adapter_graph_submit_fail_opens (void)
{
  return product_root_nfqueue_main.graph_submit_fail_opens;
}

uint64_t
product_root_nfqueue_adapter_non_owner_bypasses (void)
{
  return product_root_nfqueue_main.non_owner_bypasses;
}

uint64_t
product_root_nfqueue_adapter_duplicate_completion_drops (void)
{
  return product_root_nfqueue_main.duplicate_completion_drops;
}

uint64_t
product_root_nfqueue_adapter_stale_completion_drops (void)
{
  return product_root_nfqueue_main.stale_completion_drops;
}

uint64_t
product_root_nfqueue_adapter_internal_settlements (void)
{
  return product_root_nfqueue_main.internal_settlements;
}

uint64_t
product_root_nfqueue_adapter_buffer_returns (void)
{
  return product_root_nfqueue_main.buffer_returns;
}

uint64_t
product_root_nfqueue_adapter_origin_local_completions (void)
{
  return product_root_nfqueue_main.origin_local_completions;
}

uint64_t
product_root_nfqueue_adapter_origin_remote_completions (void)
{
  return product_root_nfqueue_main.origin_remote_completions;
}

uint64_t
product_root_nfqueue_adapter_lane_verdict_attempts (uint32_t lane_index)
{
  if (lane_index >= product_root_nfqueue_main.lane_count
      || lane_index >= PRODUCT_ROOT_NFQUEUE_MAX_LANES)
    return 0;
  return product_root_nfqueue_main.lanes[lane_index].verdict_attempts;
}

uint64_t
product_root_nfqueue_adapter_input_packets (void)
{
  return product_root_nfqueue_main.input_packets;
}

uint64_t
product_root_nfqueue_adapter_output_packets (void)
{
  return product_root_nfqueue_main.output_packets;
}

uint64_t
product_root_nfqueue_adapter_ipv4_packets (void)
{
  return product_root_nfqueue_main.ipv4_packets;
}

uint64_t
product_root_nfqueue_adapter_ipv6_packets (void)
{
  return product_root_nfqueue_main.ipv6_packets;
}

uint64_t
product_root_nfqueue_adapter_tcp_packets (void)
{
  return product_root_nfqueue_main.tcp_packets;
}

uint64_t
product_root_nfqueue_adapter_udp_packets (void)
{
  return product_root_nfqueue_main.udp_packets;
}

uint64_t
product_root_nfqueue_adapter_uid_known_packets (void)
{
  return product_root_nfqueue_main.uid_known_packets;
}

uint64_t
product_root_nfqueue_adapter_uid_unknown_packets (void)
{
  return product_root_nfqueue_main.uid_unknown_packets;
}

uint32_t
product_root_nfqueue_adapter_last_ip_family (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_ip_family;
}

uint32_t
product_root_nfqueue_adapter_last_protocol (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_protocol;
}

uint32_t
product_root_nfqueue_adapter_last_hook (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_hook;
}

uint32_t
product_root_nfqueue_adapter_last_uid_known (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_uid_known;
}

uint32_t
product_root_nfqueue_adapter_last_uid (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_uid;
}

uint32_t
product_root_nfqueue_adapter_last_queue_id (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_queue_id;
}

uint32_t
product_root_nfqueue_adapter_last_packet_id (void)
{
  return product_root_nfqueue_main.lanes[product_root_nfqueue_main.last_lane].last_packet_id;
}

#ifndef SAKAMOTO_PRODUCT_HOST_EVIDENCE
/* Resource faults withhold real native slots from this lane's existing fixed
 * partition; clearing the fault returns the exact slots. No synthetic packet
 * or counterfeit completion enters the graph. A paused listener remains
 * bound so pressure exercises queue-full, not the no-listener flag. */
static clib_error_t *
product_root_receive_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index, mode;
  (void) command;
  if (!unformat (input, "%u %u", &index, &mode) || index >= nm->lane_count
      || mode > 4 || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !nm->available || nm->pending_count || product_packet_graph_buffer_debt ())
    return clib_error_return (0, "expected live lane and mode 0..4 on an empty graph");
  product_root_nfqueue_lane_t *lane = &nm->lanes[index];
  if (!lane->listener_ready || lane->draining)
    return clib_error_return (0, "Root receive lane is not active");
  product_root_nfqueue_restore_withheld (lane);
  lane->receive_paused = mode == 4;
  lane->identity_fault = mode == 3;
  if (mode == 1 || mode == 2)
    for (int reserve = 0; reserve <= (mode == 2); ++reserve)
      {
        u16 slot;
        while ((slot = product_root_receive_pool_take (
                  &lane->receive_pool, lane->generation, reserve))
               != PRODUCT_ROOT_RECEIVE_NONE)
          lane->withheld[lane->withheld_count++] = slot;
      }
  vlib_cli_output (vm, "root.receive_fault generation=%llu lane=%u mode=%u withheld=%u normal_free=%u reserve_free=%u paused=%u identity_fault=%u",
    (unsigned long long) lane->generation, index, mode, lane->withheld_count,
    lane->receive_pool.normal_free, lane->receive_pool.reserve_free,
    lane->receive_paused, lane->identity_fault);
  return 0;
}
VLIB_CLI_COMMAND (product_root_receive_fault_command, static) = {
  .path = "product root receive-fault", .function = product_root_receive_fault_cli,
  .short_help = "product root receive-fault <lane> <0 clear|1 hold-normal|2 hold-all|3 missing-identity|4 pause-consumer>",
};

/* Deterministic callback-path fixture: the same classifier used after a real
 * EPOLLERR/SO_ERROR, without closing the live descriptor. */
static clib_error_t *
product_root_listener_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index, fault_errno;
  (void) command;
  if (!unformat (input, "%u %u", &index, &fault_errno)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || index >= nm->lane_count || !nm->available
      || !nm->lanes[index].listener_ready || fault_errno > 4095)
    return clib_error_return (0, "expected live Root lane and errno 0..4095");
  clib_error_t *error = product_root_nfqueue_handle_socket_error (
    nm, &nm->lanes[index], (int) fault_errno);
  vlib_cli_output (vm, "root.listener_fault generation=%llu lane=%u errno=%u fatal=%u ready_mask=%u",
    (unsigned long long) nm->generation, index, fault_errno,
    nm->fault_latched, nm->ready_lane_mask);
  return error;
}
VLIB_CLI_COMMAND (product_root_listener_fault_command, static) = {
  .path = "product root listener-fault", .function = product_root_listener_fault_cli,
  .short_help = "product root listener-fault <lane> <errno>; callback classifier fixture",
};

static clib_error_t *
product_root_listener_fault_after_submit_cli (vlib_main_t *vm,
                                               unformat_input_t *input,
                                               vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index;
  (void) command;
  if (!unformat (input, "%u", &index)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || index >= nm->lane_count || !nm->available
      || !nm->lanes[index].listener_ready
      || nm->lanes[index].draining
      || nm->lanes[index].listener_fault_after_submit)
    return clib_error_return (0, "expected active Root lane with no armed fault");
  nm->lanes[index].listener_fault_after_submit = 1;
  vlib_cli_output (vm, "root.listener_fault_after_submit=armed generation=%llu lane=%u",
    (unsigned long long) nm->generation, index);
  return 0;
}
VLIB_CLI_COMMAND (product_root_listener_fault_after_submit_command, static) = {
  .path = "product root listener-fault-after-submit",
  .function = product_root_listener_fault_after_submit_cli,
  .short_help = "product root listener-fault-after-submit <lane>; one real admitted packet",
};

static clib_error_t *
product_root_io_tuning_cli (vlib_main_t *vm, unformat_input_t *input,
                            vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index, budget, request;
  (void) command;
  if (!unformat (input, "%u %u %u", &index, &budget, &request)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !nm->available || index >= nm->lane_count || nm->pending_count
      || product_packet_graph_buffer_debt ())
    return clib_error_return (0, "expected lane, read budget 1..64, RCVBUF request 0..1048576 on an active empty graph");
  product_root_nfqueue_lane_t *lane = &nm->lanes[index];
  if (!product_root_nfqueue_apply_io_tuning (lane, budget, request))
    return clib_error_return_unix (0, "Root IO tuning lane %u (effective RCVBUF %u)",
                                   index, lane->rcvbuf_effective);
  vlib_cli_output (vm, "root.io_tuning generation=%llu lane=%u read_budget=%u rcvbuf_requested=%u rcvbuf_effective=%u maxlen=%u",
    (unsigned long long) lane->generation, index, lane->read_budget,
    lane->rcvbuf_requested, lane->rcvbuf_effective, lane->queue_maxlen);
  return 0;
}
/* The ordinary CLI barrier confines mutation to a quiesced lane. Settings
 * reset on clean restart and are not saved into authoring configuration. */
VLIB_CLI_COMMAND (product_root_io_tuning_command, static) = {
  .path = "product root io-tuning", .function = product_root_io_tuning_cli,
  .short_help = "product root io-tuning <lane> <read-budget 1..64> <RCVBUF request bytes; 0 keeps current>",
};

static clib_error_t *
product_root_capacity_tuning_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index, normal;
  (void) command;
  if (!unformat (input, "%u %u", &index, &normal)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT || !nm->available
      || index >= nm->lane_count || nm->pending_count || product_packet_graph_buffer_debt ())
    return clib_error_return (0, "expected lane and normal slots 64|128 on an active empty graph");
  if (!product_root_nfqueue_resize_empty_pool (vm, &nm->lanes[index], normal))
    return clib_error_return_unix (0, "Root empty capacity tuning");
  vlib_cli_output (vm, "root.capacity_tuning generation=%llu lane=%u normal=%u allocated=%u",
    (unsigned long long) nm->generation, index, normal, nm->lanes[index].receive_allocated);
  return 0;
}
VLIB_CLI_COMMAND (product_root_capacity_tuning_command, static) = {
  .path = "product root capacity-tuning", .function = product_root_capacity_tuning_cli,
  .short_help = "product root capacity-tuning <lane> <normal slots 64|128>; empty graph only",
};

static clib_error_t *
product_root_maxlen_tuning_cli (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index, maxlen;
  (void) command;
  if (!unformat (input, "%u %u", &index, &maxlen)
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT || !nm->available
      || index >= nm->lane_count || nm->pending_count || product_packet_graph_buffer_debt ())
    return clib_error_return (0, "expected lane and maxlen 1..65536 on an active empty graph");
  if (!product_root_nfqueue_apply_maxlen (&nm->lanes[index], maxlen))
    return clib_error_return_unix (0, "Root maxlen tuning (known maxlen %u)", nm->lanes[index].queue_maxlen);
  vlib_cli_output (vm, "root.maxlen_tuning generation=%llu lane=%u maxlen=%u ack=1",
    (unsigned long long) nm->generation, index, maxlen);
  return 0;
}
VLIB_CLI_COMMAND (product_root_maxlen_tuning_command, static) = {
  .path = "product root maxlen-tuning", .function = product_root_maxlen_tuning_cli,
  .short_help = "product root maxlen-tuning <lane> <1..65536>; empty graph/socket only",
};

static clib_error_t *
product_root_receive_status_cli (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  for (u32 i = 0; i < nm->lane_count; ++i)
    {
      product_root_nfqueue_lane_t *lane = &nm->lanes[i];
      vlib_cli_output (vm, "root.capacity generation=%llu lane=%u normal_capacity=%u pending_capacity=%u pending_high_water=%u loan_high_water=%u",
        (unsigned long long) lane->generation, i, lane->receive_pool.normal_capacity,
        lane->receive_pool.normal_capacity, lane->pending_high_water, lane->loan_high_water);
      vlib_cli_output (vm, "root.receive generation=%llu lane=%u family=%u queue=%u flags=%u maxlen=%u allocated=%u normal_free=%u reserve_free=%u loans=%u withheld=%u paused=%u identity_fault=%u datagrams=%llu returns=%llu ingress_accepts=%llu reserve_accepts=%llu reserve_losses=%llu identity_losses=%llu pending_collisions=%llu pending_full=%llu pending_duplicate_ids=%llu ingress_normal=%llu ingress_envelope=%llu ingress_completion=%llu ingress_graph=%llu",
        (unsigned long long) lane->generation, i, lane->ip_family, lane->queue_id,
        lane->queue_flags, lane->queue_maxlen, lane->receive_allocated,
        lane->receive_pool.normal_free, lane->receive_pool.reserve_free,
        lane->receive_pool.outstanding, lane->withheld_count, lane->receive_paused,
        lane->identity_fault, (unsigned long long) lane->receive_datagrams,
        (unsigned long long) lane->receive_returns,
        (unsigned long long) lane->ingress_accepts,
        (unsigned long long) lane->reserve_accepts,
        (unsigned long long) lane->reserve_losses,
        (unsigned long long) lane->identity_losses,
        (unsigned long long) lane->pending_collisions,
        (unsigned long long) lane->pending_full_rejections,
        (unsigned long long) lane->pending_duplicate_rejections,
        (unsigned long long) lane->ingress_normal_exhausted,
        (unsigned long long) lane->ingress_envelope_rejected,
        (unsigned long long) lane->ingress_completion_rejected,
        (unsigned long long) lane->ingress_graph_rejected);
      vlib_cli_output (vm, "root.io generation=%llu lane=%u read_budget=%u rcvbuf_requested=%u rcvbuf_effective=%u callbacks=%llu empty_callbacks=%llu budget_exits=%llu callback_datagrams=%llu callback_max=%llu recv_calls=%llu recv_eagain=%llu recv_eintr=%llu recv_enobufs=%llu",
        (unsigned long long) lane->generation, i, lane->read_budget,
        lane->rcvbuf_requested, lane->rcvbuf_effective,
        (unsigned long long) lane->read_callbacks,
        (unsigned long long) lane->read_empty_callbacks,
        (unsigned long long) lane->read_budget_exits,
        (unsigned long long) lane->read_callback_datagrams,
        (unsigned long long) lane->read_callback_max,
        (unsigned long long) lane->recv_calls,
        (unsigned long long) lane->recv_eagain,
        (unsigned long long) lane->recv_eintr,
        (unsigned long long) lane->recv_enobufs);
    }
  return 0;
}
VLIB_CLI_COMMAND (product_root_receive_status_command, static) = {
  .path = "show product root receive", .function = product_root_receive_status_cli,
};

static clib_error_t *
product_root_facts_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 mode;
  (void) command;
  if (!unformat (input, "%u", &mode) || mode > 6
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !nm->available || nm->pending_count
      || product_packet_graph_buffer_debt ())
    return clib_error_return (0, "expected mode 0..6 on an active empty graph");
  nm->facts_fault = mode;
  vlib_cli_output (vm, "root.facts_fault=%u generation=%llu", mode,
                    (unsigned long long) nm->generation);
  return 0;
}
VLIB_CLI_COMMAND (product_root_facts_fault_command, static) = {
  .path = "product root facts-fault",
  .short_help = "product root facts-fault <0 off|1 missing-uid|2 uid-zero|3 missing-ifindex|4 zero-ifindex|5 opposite-ifindex|6 unknown-hook>",
  .function = product_root_facts_fault_cli,
};

/* Default CLI execution holds the VPP worker barrier. First request quiesces
 * ingress; the same lane keeps its fd until every admitted identity returns.
 * A busy response requires retry after workers resume, never a wait under the
 * barrier. Other lanes continue receiving throughout this bounded drain. */
static clib_error_t *
product_root_lane_close_cli (vlib_main_t *vm, unformat_input_t *input,
                             vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index;
  (void) command;
  if (!unformat (input, "%u", &index) || index >= nm->lane_count
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "expected configured global lane index");
  product_root_nfqueue_lane_t *lane = &nm->lanes[index];
  lane->draining = 1;
  if (lane->pending_count)
    {
      vlib_cli_output (vm, "root.lane_close lane=%u state=draining pending=%u",
                       index, lane->pending_count);
      return 0;
    }
  if (lane->listener_ready && lane->clib_file_index != ~0)
    clib_file_del_by_index (&file_main, lane->clib_file_index);
  else if (lane->socket_ready && lane->fd >= 0)
    close (lane->fd);
  lane->clib_file_index = ~0;
  lane->fd = -1;
  lane->listener_ready = lane->socket_ready = 0;
  nm->ready_lane_mask &= ~(1U << index);
  product_root_nfqueue_release_pool (vm, lane);
  product_root_nfqueue_mark_lane_fault (nm, lane, "diagnostic", 0);
  vlib_cli_output (vm, "root.lane_close lane=%u state=closed pending=0", index);
  return 0;
}
VLIB_CLI_COMMAND (product_root_lane_close_command, static) = {
  .path = "product root lane close", .function = product_root_lane_close_cli,
  .short_help = "product root lane close <global lane index>; retry if draining",
};

/* A nonblocking stop under the normal CLI worker barrier. Quiesce first;
 * retained obligations keep their origin descriptors until a later retry. */
static clib_error_t *
product_root_stop_cli (vlib_main_t *vm, unformat_input_t *input,
                       vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  int stopped = product_root_nfqueue_adapter_stop_step (vm, nm->generation);
  if (stopped < 0) return clib_error_return (0, "root generation unavailable");
  if (!stopped)
    {
      vlib_cli_output (vm, "root.stop=draining pending=%u", nm->pending_count);
      return 0;
    }
  vlib_cli_output (vm, "root.stop=ok queues=0 buffers=0 obligations=0");
  return 0;
}
VLIB_CLI_COMMAND (product_root_stop_command, static) = {
  .path = "product root stop", .function = product_root_stop_cli,
  .short_help = "product root stop; retry if draining",
};

static clib_error_t *
product_root_lanes_cli (vlib_main_t *vm, unformat_input_t *input,
                        vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  for (u32 index = 0; index < nm->lane_count; index++)
    {
      product_root_nfqueue_lane_t *lane = &nm->lanes[index];
      vlib_cli_output (vm, "root.lane lane=%u family=%u family_lane=%u worker=%u thread=%u callback_thread=%u callback_tls=%u cpu=%u queue=%u fd=%d generation=%llu ready=%u draining=%u pending=%u captured=%llu submitted=%llu verdicts=%llu succeeded=%llu failed=%llu local=%llu remote=%llu returns=%llu duplicate=%llu",
        index, lane->ip_family, lane->family_lane, lane->worker_index,
        vlib_get_worker_thread_index (lane->worker_index), lane->callback_thread,
        lane->callback_tls, lane->last_cpu, lane->queue_id, lane->fd,
        (unsigned long long) lane->generation, lane->listener_ready, lane->draining,
        lane->pending_count, (unsigned long long) lane->packets_seen,
        (unsigned long long) lane->packets_submitted,
        (unsigned long long) lane->verdict_attempts,
        (unsigned long long) lane->verdict_succeeded,
        (unsigned long long) lane->verdict_failed,
        (unsigned long long) lane->origin_local_completions,
        (unsigned long long) lane->origin_remote_completions,
        (unsigned long long) lane->buffer_returns,
        (unsigned long long) lane->duplicate_completion_drops);
      vlib_cli_output (vm, "root.verdict_io lane=%u sendto_calls=%llu sendmmsg_calls=%llu sendmmsg_requested=%llu sendmmsg_sent=%llu partial_calls=%llu windows=%llu window_messages=%llu packed_calls=%llu packed_requested=%llu packed_sent=%llu packed_bytes=%llu packed_mixed_calls=%llu packed_max_messages=%u",
        index, (unsigned long long) lane->graph_sendto_calls,
        (unsigned long long) lane->graph_sendmmsg_calls,
        (unsigned long long) lane->graph_sendmmsg_requested,
        (unsigned long long) lane->graph_sendmmsg_sent,
        (unsigned long long) lane->graph_sendmmsg_partial_calls,
        (unsigned long long) lane->graph_verdict_windows,
        (unsigned long long) lane->graph_verdict_window_messages,
        (unsigned long long) lane->graph_packed_calls,
        (unsigned long long) lane->graph_packed_requested,
        (unsigned long long) lane->graph_packed_sent,
        (unsigned long long) lane->graph_packed_bytes,
        (unsigned long long) lane->graph_packed_mixed_calls,
        lane->graph_packed_max_messages);
      vlib_cli_output (vm, "root.control lane=%u replies=%llu errors=%llu malformed=%llu first_error=%u first_sequence=%u last_error=%u last_sequence=%u",
        index, (unsigned long long) lane->control_replies,
        (unsigned long long) lane->control_errors,
        (unsigned long long) lane->control_malformed,
        lane->control_first_error, lane->control_first_sequence,
        lane->control_last_error, lane->control_last_sequence);
    }
#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
  vlib_cli_output (vm, "root.verdict_batch enabled=1 mode=%s window=%u",
    SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 1 ? "scalar" :
      SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE == 2 ? "sendmmsg" : "packed",
    PRODUCT_PACKET_BATCH_SIZE);
#else
  vlib_cli_output (vm, "root.verdict_batch enabled=0 mode=scalar window=1");
#endif
  return 0;
}
VLIB_CLI_COMMAND (product_root_lanes_command, static) = {
  .path = "show product root lanes", .function = product_root_lanes_cli,
};

#ifdef SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT
static clib_error_t *
product_root_verdict_id_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                                  vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index;
  (void) command;
  if (!unformat (input, "%u", &index) || index >= nm->lane_count ||
      unformat_check_input (input) != UNFORMAT_END_OF_INPUT || !nm->available ||
      nm->lanes[index].draining || !nm->lanes[index].socket_ready ||
      nm->lanes[index].verdict_id_fault_next ||
      nm->lanes[index].verdict_id_probe_expired ||
      nm->lanes[index].verdict_attempts >= 4096 ||
      nm->lanes[index].last_verdict_packet_id >= 4096 ||
      nm->lanes[index].identity_losses || nm->lanes[index].reserve_losses ||
      nm->lanes[index].receive_overruns)
    return clib_error_return (0, "expected a live diagnostic lane before packet-ID wrap");
  nm->lanes[index].verdict_id_fault_next = 1;
  vlib_cli_output (vm, "root.verdict_id_fault=armed generation=%llu lane=%u minimum_window=3 budget=1",
    (unsigned long long) nm->generation, index);
  return 0;
}
VLIB_CLI_COMMAND (product_root_verdict_id_fault_command, static) = {
  .path = "product root verdict-id-fault", .function = product_root_verdict_id_fault_cli,
  .short_help = "product root verdict-id-fault <lane>; one bad middle ID, diagnostic generation only",
};
#endif

static clib_error_t *
product_root_verdict_fault_cli (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 index;
  (void) command;
  if (!unformat (input, "%u", &index) || index >= nm->lane_count
      || unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || !nm->available || nm->lanes[index].draining
      || !nm->lanes[index].socket_ready || nm->lanes[index].verdict_fault_next)
    return clib_error_return (0, "expected available lane with no armed verdict fault");
  nm->lanes[index].verdict_fault_next = 1;
  vlib_cli_output (vm, "root.verdict_fault=armed generation=%llu lane=%u fd=%d flags=%d budget=1",
    (unsigned long long) nm->generation, index, nm->lanes[index].fd, MSG_OOB);
  return 0;
}
VLIB_CLI_COMMAND (product_root_verdict_fault_command, static) = {
  .path = "product root verdict-fault", .function = product_root_verdict_fault_cli,
  .short_help = "product root verdict-fault <global lane>; one real sendto(MSG_OOB)",
};

static clib_error_t *
product_completion_replay_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  u32 packet_id = 0, lane_index = 0;
  u64 old_generation = 0;
  u8 *mode = 0;
  (void) command;
  if (!unformat (input, "%u %s", &packet_id, &mode))
    { vec_free (mode); return clib_error_return (0, "completion replay rejected"); }
  (void) unformat (input, "lane %u", &lane_index);
  (void) unformat (input, "generation %llu", &old_generation);
  if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT
      || lane_index >= nm->lane_count || !nm->available || nm->replay_count >= 8)
    { vec_free (mode); return clib_error_return (0, "completion replay rejected"); }
  int stale = strcmp ((char *) mode, "stale") == 0;
  if (!stale && strcmp ((char *) mode, "duplicate") != 0)
    { vec_free (mode); return clib_error_return (0, "expected duplicate or stale"); }
  if (old_generation && (!stale || old_generation == nm->generation))
    { vec_free (mode); return clib_error_return (0, "expected different stale generation"); }
  product_root_nfqueue_pending_t *pending = product_root_nfqueue_pending_find (
    &nm->lanes[lane_index], packet_id, 0, nm->generation);
  if (!pending || pending->active || pending->completion.obligation.packet_id != packet_id
      || !pending->completion.obligation.token
      || pending->completion.terminal_intent == PRODUCT_PACKET_INTENT_NONE)
    { vec_free (mode); return clib_error_return (0, "completed identity unavailable"); }
  product_packet_completion_frame_t completion = pending->completion;
  completion.flags |= PRODUCT_COMPLETION_REPLAY_PROBE | PRODUCT_COMPLETION_TRACE;
  if (stale)
    completion.obligation.queue_generation = old_generation ? old_generation
      : completion.obligation.queue_generation ^ UINT64_C (0x100000000);
  if (!product_packet_graph_replay_completion (vm, &completion))
    { vec_free (mode); return clib_error_return (0, "completion replay enqueue rejected"); }
  clib_atomic_fetch_add_relax (&nm->replay_count, 1);
  vlib_cli_output (vm, "completion.replay=accepted source=COMPLETION_REPLAY mode=%s token=%llu packet=%u generation=%llu original_generation=%llu lane=%u",
    mode, (unsigned long long) completion.obligation.token, packet_id,
    (unsigned long long) completion.obligation.queue_generation,
    (unsigned long long) nm->generation, lane_index);
  vec_free (mode);
  return 0;
}
VLIB_CLI_COMMAND (product_completion_replay_command, static) = {
  .path = "product completion replay",
  .short_help = "product completion replay <completed packet ID> duplicate|stale [lane <index>] [generation <old generation>]",
  .function = product_completion_replay_cli,
};

static clib_error_t *
product_completion_status_cli (vlib_main_t *vm, unformat_input_t *input,
                               vlib_cli_command_t *command)
{
  product_root_nfqueue_main_t *nm = &product_root_nfqueue_main;
  (void) input; (void) command;
  u32 capacity = PRODUCT_ROOT_NFQUEUE_PENDING_CAPACITY;
  for (u32 i = 0; i < nm->lane_count; ++i)
    if (nm->lanes[i].receive_pool.normal_capacity > capacity)
      capacity = nm->lanes[i].receive_pool.normal_capacity;
  vlib_cli_output (vm, "completion.status generation=%llu pending=%u frames=%llu buffers=%llu obligations=%llu verdicts=%llu duplicate=%llu stale=%llu local=%llu remote=%llu frame_bytes=%u capacity=%u",
    (unsigned long long) nm->generation, clib_atomic_load_acq_n (&nm->pending_count),
    (unsigned long long) product_packet_graph_completion_frame_debt (),
    (unsigned long long) product_packet_graph_buffer_debt (),
    (unsigned long long) product_packet_graph_obligation_debt (),
    (unsigned long long) nm->verdict_attempts,
    (unsigned long long) nm->duplicate_completion_drops,
    (unsigned long long) nm->stale_completion_drops,
    (unsigned long long) nm->origin_local_completions,
    (unsigned long long) nm->origin_remote_completions,
    (u32) sizeof (product_packet_completion_frame_t), capacity);
  return 0;
}
VLIB_CLI_COMMAND (product_completion_status_command, static) = {
  .path = "show product completion", .function = product_completion_status_cli,
};
#endif

static clib_error_t *
product_root_nfqueue_exit (vlib_main_t *vm)
{
  product_root_nfqueue_adapter_stop (vm);
  return 0;
}

VLIB_MAIN_LOOP_EXIT_FUNCTION (product_root_nfqueue_exit);
