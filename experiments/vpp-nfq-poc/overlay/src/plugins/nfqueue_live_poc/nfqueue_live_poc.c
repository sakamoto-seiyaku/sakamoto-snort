/* SPDX-License-Identifier: Apache-2.0 */

/*
 * SAKAMOTO-73 — throwaway VPP-native NFQUEUE live-buffer closure probe.
 *
 * The netlink datagram is received straight into the VPP buffer's current
 * data span. libnetfilter_queue only projects pointers into that datagram;
 * the payload is never copied by this plugin. A worker frame queue moves the
 * buffer index. A fixed completion frame moves the index and full identity back
 * to the origin lane, which calls nfq_set_verdict and then returns the same
 * buffer through vlib_buffer_free_one(). Producers never issue a verdict or
 * free a buffer: bounded transport faults publish a terminal token through a
 * reserved origin-return ring, and the origin lane performs both operations.
 */

#include <nfqueue_live_poc/nfqueue_live_poc.h>

#include <vlib/file.h>
#include <vlib/threads.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <nfqueue_live_poc/nfqueue_live_envelope.h>

#define NFQUEUE_LIVE_RING_CAPACITY 128u
#define NFQUEUE_LIVE_MAX_OUTSTANDING (NFQUEUE_LIVE_RING_CAPACITY - 1u)
#define NFQUEUE_LIVE_DEFAULT_NORMAL_CAPACITY NFQUEUE_LIVE_MAX_OUTSTANDING
#define NFQUEUE_LIVE_ACCEPT NF_ACCEPT
#define NFQUEUE_LIVE_LOSS NF_DROP
#define NFQUEUE_LIVE_FLAG_UID_KNOWN (1u << 0)
#define NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN (1u << 1)
#define NFQUEUE_LIVE_FLAG_STATE_SHIFT 2
#define NFQUEUE_LIVE_FLAG_STATE_MASK (7u << NFQUEUE_LIVE_FLAG_STATE_SHIFT)
#define NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED (1u << 5)
#define NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN (1u << 6)
#define NFQUEUE_LIVE_FLAG_OUTCOME_FAILED (1u << 7)
#define NFQUEUE_LIVE_COMPLETION_REF_MASK 0x7fu
#define NFQUEUE_LIVE_LATE_RETURN_QUEUED 0x80u
/* Linux NF_INET_LOCAL_IN/LOCAL_OUT are the two device directions exercised
 * by the S75 runtime.  PRE_ROUTING/POST_ROUTING are normalized to the same
 * INPUT/OUTPUT vocabulary for completeness; the hook value remains the
 * platform hint and is never inferred from packet bytes. */
#define NFQUEUE_LIVE_DIRECTION_INPUT 1u
#define NFQUEUE_LIVE_DIRECTION_OUTPUT 2u
#define NFQUEUE_LIVE_OWNER_MODE_MIXED 0u
#define NFQUEUE_LIVE_OWNER_MODE_LOCAL 1u
#define NFQUEUE_LIVE_OWNER_MODE_REMOTE 2u
#define NFQUEUE_LIVE_HANDOFF_INITIAL 0u
#define NFQUEUE_LIVE_HANDOFF_CANONICAL (1u << 7)
#define NFQUEUE_LIVE_HANDOFF_SLOT_MASK 0x7fu
#define NFQUEUE_LIVE_META_CREDIT_BIT (1u << 7)

static_always_inline u8
nfqueue_live_device_direction (u8 hook)
{
  return (hook == NF_INET_LOCAL_OUT || hook == NF_INET_POST_ROUTING) ?
           NFQUEUE_LIVE_DIRECTION_OUTPUT : NFQUEUE_LIVE_DIRECTION_INPUT;
}

static_always_inline u8
nfqueue_live_meta_hook (const nfqueue_live_meta_t *meta)
{
  return meta->hook;
}

static_always_inline u8
nfqueue_live_meta_origin_lane (const nfqueue_live_meta_t *meta)
{
  return meta->origin_lane & ~NFQUEUE_LIVE_META_CREDIT_BIT;
}

static_always_inline void
nfqueue_live_meta_set_credit (nfqueue_live_meta_t *meta, u8 held)
{
  if (held)
    meta->origin_lane |= NFQUEUE_LIVE_META_CREDIT_BIT;
  else
    meta->origin_lane &= ~NFQUEUE_LIVE_META_CREDIT_BIT;
}

static_always_inline u8
nfqueue_live_meta_has_credit (const nfqueue_live_meta_t *meta)
{
  return (meta->origin_lane & NFQUEUE_LIVE_META_CREDIT_BIT) != 0;
}

/* These are compile-time proof obligations, not mutable per-packet state:
 * this probe has no packet-copy, scratch-buffer, or heap-obligation path. */
#define NFQUEUE_LIVE_PACKET_COPY_PATHS 0u
#define NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS 0u
#define NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS 0u
#define NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS 0u
_Static_assert (NFQUEUE_LIVE_PACKET_COPY_PATHS == 0u,
                "S73 packet-copy path must remain absent");
_Static_assert (NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS == 0u,
                "S73 full-packet memcpy path must remain absent");
_Static_assert (NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS == 0u,
                "S73 scratch-buffer path must remain absent");
_Static_assert (NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS == 0u,
                "S73 per-packet heap obligation must remain absent");

typedef enum
{
  NFQUEUE_LIVE_STATE_FREE = 0,
  NFQUEUE_LIVE_STATE_LIVE = 1,
  NFQUEUE_LIVE_STATE_COMPLETION = 2,
  NFQUEUE_LIVE_STATE_ATTEMPTED = 3,
  NFQUEUE_LIVE_STATE_RETURNED = 4,
} nfqueue_live_state_t;

typedef struct
{
  nfqueue_live_main_t *nm;
  nfqueue_live_lane_t *lane;
  u32 buffer_index;
  u8 *base;
  u32 parse_length;
  u32 datagram_length;
  u32 callback_count;
  u32 callback_identities;
  u32 callback_verdicts;
  u8 truncated;
  u8 candidate;
  u8 metadata_initialized;
  u8 ingress_identity_missing;
} nfqueue_live_datagram_t;

typedef enum
{
  NFQUEUE_LIVE_INGRESS_NORMAL = 0,
  NFQUEUE_LIVE_INGRESS_RESERVE,
  NFQUEUE_LIVE_INGRESS_LOSS,
  NFQUEUE_LIVE_INGRESS_NO_BUFFER,
} nfqueue_live_ingress_result_t;

typedef enum
{
  NFQUEUE_LIVE_DISCARD_NO_DATA = 0,
  NFQUEUE_LIVE_DISCARD_LOSS,
  NFQUEUE_LIVE_DISCARD_FAULT,
} nfqueue_live_discard_result_t;

nfqueue_live_main_t nfqueue_live_main = {
  .netlink_fd = -1,
  .completion_fd = -1,
  .netlink_file_index = ~0,
  .completion_file_index = ~0,
  .frame_queue_index = ~0,
  .worker_thread = 1,
  .teardown_state = NFQUEUE_LIVE_TEARDOWN_STOPPED,
  .teardown_drain_limit = 200,
};

extern vlib_node_registration_t nfqueue_live_ingress_process_node;
extern vlib_node_registration_t nfqueue_live_owner_node;

static u8 nfqueue_live_recover_packet_id (const u8 *base, u32 length,
                                          u32 *packet_id);
static u32 nfqueue_live_next_obligation_nonce (nfqueue_live_main_t *nm);
static void nfqueue_live_drain_ingress_queue (nfqueue_live_main_t *nm);
static void nfqueue_live_drain_held_obligation (nfqueue_live_main_t *nm);
static clib_error_t *nfqueue_live_ensure_frame_queue (
  nfqueue_live_main_t *nm, u32 max_worker_thread);

static const char *
nfqueue_live_teardown_state_name (nfqueue_live_teardown_state_t state)
{
  switch (state)
    {
    case NFQUEUE_LIVE_TEARDOWN_STOPPED:
      return "STOPPED";
    case NFQUEUE_LIVE_TEARDOWN_ACTIVE:
      return "ACTIVE";
    case NFQUEUE_LIVE_TEARDOWN_QUIESCING:
      return "QUIESCING";
    case NFQUEUE_LIVE_TEARDOWN_DRAINING:
      return "DRAINING";
    case NFQUEUE_LIVE_TEARDOWN_DEADLINE:
      return "DEADLINE";
    case NFQUEUE_LIVE_TEARDOWN_COMPLETION_CLOSED:
      return "COMPLETION_CLOSED";
    case NFQUEUE_LIVE_TEARDOWN_CHANNELS_CLOSED:
      return "CHANNELS_CLOSED";
    case NFQUEUE_LIVE_TEARDOWN_COMPLETE:
      return "COMPLETE";
    case NFQUEUE_LIVE_TEARDOWN_PROCESS_TERMINATED:
      return "PROCESS_TERMINATED";
    default:
      return "UNKNOWN";
    }
}

static const char *
nfqueue_live_teardown_event_name (nfqueue_live_teardown_event_t event)
{
  switch (event)
    {
    case NFQUEUE_LIVE_TEARDOWN_ENABLE:
      return "ENABLE";
    case NFQUEUE_LIVE_TEARDOWN_QUIESCE:
      return "QUIESCE";
    case NFQUEUE_LIVE_TEARDOWN_DRAIN:
      return "DRAIN";
    case NFQUEUE_LIVE_TEARDOWN_DRAIN_DEADLINE:
      return "DRAIN_DEADLINE";
    case NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION:
      return "CLOSE_COMPLETION";
    case NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS:
      return "CLOSE_CHANNELS";
    case NFQUEUE_LIVE_TEARDOWN_FINISH:
      return "FINISH";
    case NFQUEUE_LIVE_TEARDOWN_PROCESS_DEATH:
      return "PROCESS_DEATH";
    default:
      return "UNKNOWN";
    }
}

static nfqueue_live_teardown_state_t
nfqueue_live_teardown_state_load (const nfqueue_live_main_t *nm)
{
  return __atomic_load_n (&nm->teardown_state, __ATOMIC_ACQUIRE);
}

static u8
nfqueue_live_record_teardown_transition (
  nfqueue_live_main_t *nm, nfqueue_live_teardown_event_t event)
{
  nfqueue_live_teardown_state_t state = nfqueue_live_teardown_state_load (nm);
  if (!nfqueue_live_teardown_transition (&state, event))
    {
      (void) __atomic_fetch_add (&nm->teardown_transition_rejections, 1,
                                  __ATOMIC_RELAXED);
      return 0;
    }
  __atomic_store_n (&nm->teardown_state, state, __ATOMIC_RELEASE);
  if (nm->teardown_event_count < NFQUEUE_LIVE_TEARDOWN_MAX_TRANSITIONS)
    nm->teardown_events[nm->teardown_event_count++] = event;
  return 1;
}

static u8
nfqueue_live_teardown_ingress_allowed (const nfqueue_live_main_t *nm)
{
  return nfqueue_live_teardown_ingress_admission_allowed (
    nfqueue_live_teardown_state_load (nm));
}

static u8
nfqueue_live_teardown_completion_open (const nfqueue_live_main_t *nm)
{
  return nfqueue_live_teardown_completion_channel_open (
    nfqueue_live_teardown_state_load (nm));
}

static_always_inline nfqueue_live_meta_t *
nfqueue_live_meta (vlib_buffer_t *b)
{
  return (nfqueue_live_meta_t *) b->opaque;
}

static_always_inline void
nfqueue_live_set_generation (nfqueue_live_meta_t *meta, u64 generation)
{
  meta->generation_lo = (u32) generation;
  meta->generation_hi = (u32) (generation >> 32);
}

static_always_inline nfqueue_live_state_t
nfqueue_live_state (const nfqueue_live_meta_t *meta)
{
  return (nfqueue_live_state_t) ((meta->flags & NFQUEUE_LIVE_FLAG_STATE_MASK) >>
                                 NFQUEUE_LIVE_FLAG_STATE_SHIFT);
}

static_always_inline void
nfqueue_live_set_state (nfqueue_live_meta_t *meta, nfqueue_live_state_t state)
{
  meta->flags = (meta->flags & ~NFQUEUE_LIVE_FLAG_STATE_MASK) |
                ((u8) state << NFQUEUE_LIVE_FLAG_STATE_SHIFT);
}

static_always_inline u8
nfqueue_live_completion_ref_count (const nfqueue_live_meta_t *meta)
{
  return meta->completion_refs & NFQUEUE_LIVE_COMPLETION_REF_MASK;
}

static_always_inline u8
nfqueue_live_late_return_queued (const nfqueue_live_meta_t *meta)
{
  return (meta->completion_refs & NFQUEUE_LIVE_LATE_RETURN_QUEUED) != 0;
}

static_always_inline void
nfqueue_live_completion_ref_set (nfqueue_live_meta_t *meta, u8 count)
{
  meta->completion_refs = (meta->completion_refs & NFQUEUE_LIVE_LATE_RETURN_QUEUED) |
                          (count & NFQUEUE_LIVE_COMPLETION_REF_MASK);
}

static_always_inline void
nfqueue_live_completion_ref_inc (nfqueue_live_meta_t *meta)
{
  u8 count = nfqueue_live_completion_ref_count (meta);
  ASSERT (count < NFQUEUE_LIVE_COMPLETION_REF_MASK);
  nfqueue_live_completion_ref_set (meta, count + 1);
}

static_always_inline u8
nfqueue_live_completion_ref_dec (nfqueue_live_meta_t *meta)
{
  u8 count = nfqueue_live_completion_ref_count (meta);
  if (count == 0)
    return 0;
  nfqueue_live_completion_ref_set (meta, count - 1);
  return 1;
}

static_always_inline u8
nfqueue_live_index_push (nfqueue_live_index_ring_t *ring, u32 index)
{
  u32 tail = __atomic_load_n (&ring->tail, __ATOMIC_RELAXED);
  u32 next = (tail + 1) % NFQUEUE_LIVE_RING_CAPACITY;
  if (next == __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE))
    return 0;
  ring->indices[tail] = index;
  __atomic_store_n (&ring->tail, next, __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
nfqueue_live_index_pop (nfqueue_live_index_ring_t *ring, u32 *index)
{
  u32 head = __atomic_load_n (&ring->head, __ATOMIC_RELAXED);
  if (head == __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE))
    return 0;
  *index = ring->indices[head];
  __atomic_store_n (&ring->head, (head + 1) % NFQUEUE_LIVE_RING_CAPACITY,
                    __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
nfqueue_live_completion_push (nfqueue_live_completion_ring_t *ring,
                               const nfqueue_live_completion_t *entry)
{
  u32 tail = __atomic_load_n (&ring->tail, __ATOMIC_RELAXED);
  u32 next = (tail + 1) % NFQUEUE_LIVE_RING_CAPACITY;
  if (next == __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE))
    return 0;
  ring->entries[tail] = *entry;
  __atomic_store_n (&ring->tail, next, __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u8
nfqueue_live_completion_pop (nfqueue_live_completion_ring_t *ring,
                              nfqueue_live_completion_t *entry)
{
  u32 head = __atomic_load_n (&ring->head, __ATOMIC_RELAXED);
  if (head == __atomic_load_n (&ring->tail, __ATOMIC_ACQUIRE))
    return 0;
  *entry = ring->entries[head];
  __atomic_store_n (&ring->head, (head + 1) % NFQUEUE_LIVE_RING_CAPACITY,
                    __ATOMIC_RELEASE);
  return 1;
}

static_always_inline u32
nfqueue_live_completion_free_slots (nfqueue_live_completion_ring_t *ring)
{
  u32 head = __atomic_load_n (&ring->head, __ATOMIC_ACQUIRE);
  u32 tail = __atomic_load_n (&ring->tail, __ATOMIC_RELAXED);
  return (head + NFQUEUE_LIVE_RING_CAPACITY - tail - 1) %
         NFQUEUE_LIVE_RING_CAPACITY;
}

static_always_inline void
nfqueue_live_ring_lock (u32 *lock)
{
  while (__atomic_exchange_n (lock, 1,
                              __ATOMIC_ACQUIRE) != 0)
    ;
}

static_always_inline void
nfqueue_live_ring_unlock (u32 *lock)
{
  __atomic_store_n (lock, 0, __ATOMIC_RELEASE);
}

static_always_inline void
nfqueue_live_completion_lock (nfqueue_live_main_t *nm)
{
  nfqueue_live_ring_lock (&nm->completion_push_lock);
}

static_always_inline void
nfqueue_live_completion_unlock (nfqueue_live_main_t *nm)
{
  nfqueue_live_ring_unlock (&nm->completion_push_lock);
}

static_always_inline void
nfqueue_live_origin_return_lock (nfqueue_live_main_t *nm)
{
  nfqueue_live_ring_lock (&nm->origin_return_push_lock);
}

static_always_inline void
nfqueue_live_origin_return_unlock (nfqueue_live_main_t *nm)
{
  nfqueue_live_ring_unlock (&nm->origin_return_push_lock);
}

static_always_inline u32
nfqueue_live_outstanding_load (const nfqueue_live_main_t *nm)
{
  return __atomic_load_n (&nm->outstanding, __ATOMIC_ACQUIRE);
}

static_always_inline void
nfqueue_live_counter_inc (u64 *counter)
{
  (void) __atomic_fetch_add (counter, 1, __ATOMIC_RELAXED);
}

static_always_inline void
nfqueue_live_counter_add (u64 *counter, u64 value)
{
  (void) __atomic_fetch_add (counter, value, __ATOMIC_RELAXED);
}

static_always_inline void
nfqueue_live_counter_store (u64 *counter, u64 value)
{
  __atomic_store_n (counter, value, __ATOMIC_RELEASE);
}

static_always_inline u64
nfqueue_live_counter_load (const u64 *counter)
{
  return __atomic_load_n (counter, __ATOMIC_ACQUIRE);
}

static_always_inline u32
nfqueue_live_counter32_load (const u32 *counter)
{
  return __atomic_load_n (counter, __ATOMIC_ACQUIRE);
}

static_always_inline void
nfqueue_live_outstanding_inc (nfqueue_live_main_t *nm)
{
  (void) __atomic_fetch_add (&nm->outstanding, 1, __ATOMIC_RELEASE);
  (void) __atomic_fetch_add (&nm->completion_debt, 1, __ATOMIC_RELEASE);
  nfqueue_live_counter_inc (&nm->completion_debt_raised);
}

static_always_inline void
nfqueue_live_outstanding_dec (nfqueue_live_main_t *nm)
{
  u32 previous = __atomic_fetch_sub (&nm->outstanding, 1, __ATOMIC_ACQ_REL);
  ASSERT (previous != 0);
  previous = __atomic_fetch_sub (&nm->completion_debt, 1, __ATOMIC_ACQ_REL);
  ASSERT (previous != 0);
  nfqueue_live_counter_inc (&nm->completion_debt_settled);
}

static_always_inline u8
nfqueue_live_normal_capacity_exhausted (const nfqueue_live_main_t *nm)
{
  return nm->inject_normal_capacity_exhaustion ||
         (nm->arm_normal_capacity_exhaustion && nm->normal_capacity != 0 &&
          nm->normal_peak_occupancy >= nm->normal_capacity) ||
         nm->normal_capacity == 0 ||
         nm->normal_outstanding >= nm->normal_capacity;
}

static u8
nfqueue_live_reserve_take (nfqueue_live_main_t *nm,
                           nfqueue_live_lane_t *lane, u32 *buffer_index)
{
  if (!lane || lane->reserve_available == 0)
    return 0;
  /* The reader for a lane is its sole owner.  No lock or wait is permitted;
   * a missing entry is an explicit capacity loss. */
  lane->reserve_available--;
  *buffer_index = lane->reserve_indices[lane->reserve_available];
  lane->reserve_indices[lane->reserve_available] = ~0u;
  lane->reserve_inflight++;
  u32 used = lane->reserve_capacity - lane->reserve_available;
  if (used > lane->reserve_peak_occupancy)
    lane->reserve_peak_occupancy = used;
  if (lane->reserve_inflight > lane->reserve_peak_inflight)
    lane->reserve_peak_inflight = lane->reserve_inflight;
  if (used > nm->reserve_peak_occupancy)
    nm->reserve_peak_occupancy = used;
  if (lane->reserve_inflight > nm->reserve_peak_inflight)
    nm->reserve_peak_inflight = lane->reserve_inflight;
  nm->reserve_outstanding++;
  if (nm->reserve_outstanding > nm->reserve_peak_occupancy)
    nm->reserve_peak_occupancy = nm->reserve_outstanding;
  return 1;
}

static void
nfqueue_live_reserve_return (nfqueue_live_main_t *nm,
                             nfqueue_live_lane_t *lane, u32 buffer_index,
                             u8 direct_completion)
{
  if (lane && lane->reserve_inflight != 0)
    lane->reserve_inflight--;
  if (nm->reserve_outstanding != 0)
    nm->reserve_outstanding--;
  nm->reserve_native_returns++;
  nm->native_buffer_returns++;
  if (lane)
    {
      lane->reserve_native_returns++;
      lane->native_buffer_returns++;
    }
  if (direct_completion)
    {
      nm->reserve_direct_native_returns++;
      if (lane)
        lane->reserve_direct_native_returns++;
    }
  /* This is the native VPP return required by the Root Adapter contract.  The
   * one-shot POC reserve is intentionally not replenished after return: doing
   * so would be dynamic reserve growth and would hide exhaustion evidence. */
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static u8
nfqueue_live_reserve_loss_slot_take (nfqueue_live_lane_t *lane,
                                     u32 *buffer_index)
{
  if (!lane || !lane->reserve_loss_index_valid)
    return 0;
  *buffer_index = lane->reserve_loss_index;
  lane->reserve_loss_index = ~0u;
  lane->reserve_loss_index_valid = 0;
  return 1;
}

static void
nfqueue_live_record_reserve_loss_outcome (
  nfqueue_live_main_t *nm, nfqueue_live_lane_t *lane,
  nfqueue_live_completion_outcome_t outcome)
{
  switch (outcome)
    {
    case NFQUEUE_LIVE_OUTCOME_SUCCEEDED:
      /* Only a native NF_DROP whose operation returned success is evidence of
       * a native loss settlement.  It is never a policy or delivery claim. */
      nm->reserve_loss_native_drops++;
      if (lane)
        lane->reserve_loss_native_drops++;
      break;
    case NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE:
      nm->reserve_loss_outcome_failed_definite++;
      if (lane)
        lane->reserve_loss_outcome_failed_definite++;
      break;
    case NFQUEUE_LIVE_OUTCOME_UNKNOWN:
      nm->reserve_loss_outcome_unknown++;
      if (lane)
        lane->reserve_loss_outcome_unknown++;
      break;
    default:
      break;
    }
}

static_always_inline void
nfqueue_live_record_reserve_loss_materialization (nfqueue_live_main_t *nm,
                                                   nfqueue_live_lane_t *lane)
{
  nm->reserve_loss_materializations++;
  if (lane)
    lane->reserve_loss_materializations++;
}

static_always_inline void
nfqueue_live_record_reserve_loss_unmaterialized (nfqueue_live_main_t *nm,
                                                 nfqueue_live_lane_t *lane)
{
  nm->reserve_loss_unmaterialized++;
  nm->reserve_loss_identity_misses++;
  if (lane)
    {
      lane->reserve_loss_unmaterialized++;
      lane->reserve_loss_identity_misses++;
    }
}

static_always_inline void
nfqueue_live_record_reserve_loss (nfqueue_live_main_t *nm,
                                  nfqueue_live_lane_t *lane)
{
  nm->reserve_losses++;
  nm->reserve_degraded_health++;
  if (lane)
    lane->reserve_losses++;
}

static u8
nfqueue_live_netlink_data_ready (int netlink_fd)
{
  struct pollfd pollfd = {
    .fd = netlink_fd,
    .events = POLLIN,
  };
  return poll (&pollfd, 1, 0) == 1 && (pollfd.revents & POLLIN) != 0;
}

static nfqueue_live_ingress_result_t
nfqueue_live_acquire_ingress_buffer (nfqueue_live_main_t *nm,
                                     nfqueue_live_lane_t *lane,
                                     u32 *buffer_index)
{
  u8 normal_capacity_exhausted =
    nfqueue_live_normal_capacity_exhausted (nm);
  if (normal_capacity_exhausted)
    {
      /* Do not consume a reserve entry merely to discover EAGAIN at the end
       * of this callback.  Readiness is a zero-time check and does not copy,
       * wait, or change packet ownership. */
      if (!nfqueue_live_netlink_data_ready (lane->netlink_fd))
        return NFQUEUE_LIVE_INGRESS_NO_BUFFER;
    }
  else
    {
      if (vlib_buffer_alloc (nm->vm, buffer_index, 1) == 1)
        return NFQUEUE_LIVE_INGRESS_NORMAL;
      nm->ingress_alloc_failures++;
    }

  nm->normal_capacity_exhaustions++;
  nm->ingress_overload++;
  if (nm->reserve_enabled &&
      nfqueue_live_reserve_take (nm, lane, buffer_index))
    return NFQUEUE_LIVE_INGRESS_RESERVE;
  if (nm->reserve_enabled &&
      nfqueue_live_reserve_loss_slot_take (lane, buffer_index))
    {
      nm->reserve_exhaustions++;
      lane->reserve_exhaustions++;
      return NFQUEUE_LIVE_INGRESS_LOSS;
    }
  if (nm->reserve_enabled)
    {
      nm->reserve_exhaustions++;
      lane->reserve_exhaustions++;
    }
  return NFQUEUE_LIVE_INGRESS_NO_BUFFER;
}

static nfqueue_live_discard_result_t
nfqueue_live_discard_bounded_loss (nfqueue_live_main_t *nm,
                                   nfqueue_live_lane_t *lane)
{
  /* With no VPP buffer available, consume only one nonblocking datagram.
   * A non-transient receive fault is health evidence, not a packet loss or a
   * fabricated NFQUEUE outcome; return to the file callback immediately. */
  ssize_t discarded = recv (lane->netlink_fd, 0, 0,
                            MSG_DONTWAIT | MSG_TRUNC);
  if (discarded >= 0)
    {
      nfqueue_live_record_reserve_loss_unmaterialized (nm, lane);
      nfqueue_live_record_reserve_loss (nm, lane);
      return NFQUEUE_LIVE_DISCARD_LOSS;
    }
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
    return NFQUEUE_LIVE_DISCARD_NO_DATA;
  nm->reserve_receive_faults++;
  lane->reserve_receive_faults++;
  nm->reserve_degraded_health++;
  return NFQUEUE_LIVE_DISCARD_FAULT;
}

static void
nfqueue_live_disable_faulted_lane (nfqueue_live_main_t *nm,
                                   nfqueue_live_lane_t *lane)
{
  u32 file_index = lane->netlink_file_index;
  int netlink_fd = lane->netlink_fd;

  /* The callback owns this lane's file registration.  Mark the registration
   * non-owning before removing it: nfq_close remains the sole owner of the
   * netlink descriptor, and the normal close path can release the handle
   * exactly once.  Removing the registration also prevents a persistent
   * EPOLLIN/ERR event from re-entering a faulted callback. */
  if (file_index != ~0)
    {
      clib_file_t *file = clib_file_get (&file_main, file_index);
      if (file)
        {
          file->dont_close = 1;
          clib_file_del (&file_main, file);
        }
      lane->netlink_file_index = ~0;
      if (nm->netlink_file_index == file_index)
        nm->netlink_file_index = ~0;
    }
  lane->netlink_fd = -1;
  if (nm->netlink_fd == netlink_fd)
    nm->netlink_fd = -1;
  lane->enabled = 0;
}

static_always_inline u8
nfqueue_live_completion_credit_acquire (nfqueue_live_main_t *nm)
{
  u32 held = __atomic_load_n (&nm->completion_credits_held,
                              __ATOMIC_RELAXED);
  if (__atomic_exchange_n (&nm->inject_completion_credit_exhaustion, 0,
                           __ATOMIC_ACQ_REL))
    {
      nfqueue_live_counter_inc (&nm->completion_credit_exhausted);
      return 0;
    }
  while (held < nm->completion_credit_capacity)
    if (__atomic_compare_exchange_n (&nm->completion_credits_held, &held,
                                     held + 1, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_RELAXED))
      {
        nfqueue_live_counter_inc (&nm->completion_credit_acquired);
        return 1;
      }
  nfqueue_live_counter_inc (&nm->completion_credit_exhausted);
  return 0;
}

static_always_inline void
nfqueue_live_completion_credit_release (nfqueue_live_main_t *nm,
                                        nfqueue_live_meta_t *meta)
{
  if (!nfqueue_live_meta_has_credit (meta))
    return;
  nfqueue_live_meta_set_credit (meta, 0);
  u32 previous = __atomic_fetch_sub (&nm->completion_credits_held, 1,
                                     __ATOMIC_ACQ_REL);
  ASSERT (previous != 0);
  nfqueue_live_counter_inc (&nm->completion_credit_released);
}

static_always_inline u32
nfqueue_live_initial_worker (const nfqueue_live_main_t *nm, u8 origin_lane)
{
  if (nm->worker_count < 2)
    return nm->first_worker_thread;
  return (origin_lane & 1) ? nm->second_worker_thread : nm->first_worker_thread;
}

static_always_inline u32
nfqueue_live_other_worker (const nfqueue_live_main_t *nm, u32 worker)
{
  if (nm->worker_count < 2)
    return worker;
  return worker == nm->first_worker_thread ? nm->second_worker_thread :
                                               nm->first_worker_thread;
}

static_always_inline u32
nfqueue_live_canonical_worker (const nfqueue_live_main_t *nm,
                               const nfqueue_live_meta_t *meta)
{
  u8 owner_mode = __atomic_load_n (&nm->owner_mode, __ATOMIC_ACQUIRE);
  if (owner_mode == NFQUEUE_LIVE_OWNER_MODE_LOCAL)
    return meta->initial_worker;
  if (owner_mode == NFQUEUE_LIVE_OWNER_MODE_REMOTE)
    return nfqueue_live_other_worker (nm, meta->initial_worker);
  /* Mixed mode is deterministic from the inline identity.  This intentionally
   * avoids packet-byte parsing while producing both local and remote cases. */
  return ((meta->packet_id ^ meta->origin_lane) & 1) == 0 ?
           meta->initial_worker :
           nfqueue_live_other_worker (nm, meta->initial_worker);
}

static_always_inline u64
nfqueue_live_meta_generation (const nfqueue_live_meta_t *meta)
{
  return ((u64) meta->generation_hi << 32) | meta->generation_lo;
}

static u8
nfqueue_live_frame_queue_ready (u32 frame_queue_index, u32 max_worker_thread)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  vlib_frame_queue_main_t *fqm;

  if (frame_queue_index == ~0u ||
      frame_queue_index >= vec_len (tm->frame_queue_mains))
    return 0;
  fqm = vec_elt_at_index (tm->frame_queue_mains, frame_queue_index);
  if (fqm->node_index != nfqueue_live_owner_node.index ||
      max_worker_thread >= vec_len (fqm->vlib_frame_queues))
    return 0;
  for (u32 i = 1; i <= max_worker_thread; i++)
    if (fqm->vlib_frame_queues[i] == 0)
      return 0;
  return 1;
}

static clib_error_t *
nfqueue_live_ensure_frame_queue (nfqueue_live_main_t *nm,
                                 u32 max_worker_thread)
{
  if (!nfqueue_live_frame_queue_ready (nm->frame_queue_index,
                                       max_worker_thread))
    nm->frame_queue_index =
      vlib_frame_queue_main_init (nfqueue_live_owner_node.index, 0);

  if (!nfqueue_live_frame_queue_ready (nm->frame_queue_index,
                                       max_worker_thread))
    return clib_error_return (
      0, "nfqueue-live frame queue unavailable for worker thread %u",
      max_worker_thread);
  return 0;
}

static_always_inline void
nfqueue_live_handoff_sample_lock (nfqueue_live_handoff_sample_t *sample)
{
  nfqueue_live_ring_lock (&sample->lock);
}

static_always_inline void
nfqueue_live_handoff_sample_unlock (nfqueue_live_handoff_sample_t *sample)
{
  nfqueue_live_ring_unlock (&sample->lock);
}

static u8
nfqueue_live_handoff_sample_reserve (nfqueue_live_main_t *nm,
                                     u32 *slot_index)
{
  for (u32 i = 0; i < NFQUEUE_LIVE_MAX_HANDOFF_SAMPLES; i++)
    {
      nfqueue_live_handoff_sample_t *sample = &nm->handoff_samples[i];
      u32 expected = 0;
      if (!__atomic_compare_exchange_n (&sample->state, &expected, 1, 0,
                                        __ATOMIC_ACQ_REL,
                                        __ATOMIC_RELAXED))
        continue;
      nfqueue_live_handoff_sample_lock (sample);
      sample->before_valid = 0;
      sample->after_valid = 0;
      sample->before_buffer_index = ~0;
      sample->after_buffer_index = ~0;
      nfqueue_live_handoff_sample_unlock (sample);
      *slot_index = i;
      return 1;
    }
  return 0;
}

static_always_inline u8
nfqueue_live_handoff_stage_slot (const nfqueue_live_meta_t *meta,
                                 u32 *slot_index)
{
  if ((meta->handoff_stage & NFQUEUE_LIVE_HANDOFF_CANONICAL) == 0)
    return 0;
  u32 slot = meta->handoff_stage & NFQUEUE_LIVE_HANDOFF_SLOT_MASK;
  if (slot >= NFQUEUE_LIVE_MAX_HANDOFF_SAMPLES)
    return 0;
  *slot_index = slot;
  return 1;
}

static void
nfqueue_live_handoff_sample_release (nfqueue_live_main_t *nm, u32 slot_index)
{
  if (slot_index >= NFQUEUE_LIVE_MAX_HANDOFF_SAMPLES)
    return;
  __atomic_store_n (&nm->handoff_samples[slot_index].state, 0,
                    __ATOMIC_RELEASE);
}

static_always_inline void
nfqueue_live_handoff_sample_release_for_meta (nfqueue_live_main_t *nm,
                                              nfqueue_live_meta_t *meta)
{
  u32 slot_index;
  if (nfqueue_live_handoff_stage_slot (meta, &slot_index))
    {
      nfqueue_live_handoff_sample_release (nm, slot_index);
      /* Make release idempotent for this obligation.  A terminal fallback
       * may run after a proof failure; it must not clear a newly reserved
       * sample slot that reused the same index. */
      meta->handoff_stage = NFQUEUE_LIVE_HANDOFF_INITIAL;
    }
}

static void
nfqueue_live_record_handoff_before (nfqueue_live_main_t *nm,
                                    u32 slot_index, u32 worker_thread,
                                    u32 buffer_index,
                                    vlib_buffer_t *buffer,
                                    const nfqueue_live_meta_t *meta)
{
  nfqueue_live_handoff_sample_t *sample = &nm->handoff_samples[slot_index];
  nfqueue_live_handoff_sample_lock (sample);
  sample->before_valid = 1;
  sample->before_worker = worker_thread;
  sample->before_buffer_index = buffer_index;
  sample->before_buffer_base = (uword) vlib_buffer_get_current (buffer);
  sample->before_packet_id = meta->packet_id;
  sample->before_payload_offset = meta->payload_offset;
  sample->before_payload_length = meta->payload_length;
  sample->before_generation = nfqueue_live_meta_generation (meta);
  sample->before_origin_lane = nfqueue_live_meta_origin_lane (meta);
  sample->before_obligation_nonce = meta->obligation_nonce;
  sample->before_stage = meta->handoff_stage;
  nfqueue_live_handoff_sample_unlock (sample);
}

static u8
nfqueue_live_record_handoff_after (nfqueue_live_main_t *nm, u32 worker_thread,
                                   u32 buffer_index, vlib_buffer_t *buffer,
                                   nfqueue_live_meta_t *meta)
{
  /* Pair the source-owned full identity with locals read from this same live
   * buffer. The slot is lock-protected and named by inline handoff_stage; it
   * is released only after this comparison, never used as packet ownership. */
  uword buffer_base = (uword) vlib_buffer_get_current (buffer);
  u32 packet_id = meta->packet_id;
  u32 payload_offset = meta->payload_offset;
  u32 payload_length = meta->payload_length;
  u64 generation = nfqueue_live_meta_generation (meta);
  u32 origin_lane = nfqueue_live_meta_origin_lane (meta);
  u32 obligation_nonce = meta->obligation_nonce;
  u8 handoff_stage = meta->handoff_stage;
  u32 slot_index;
  u8 proof = 0;
  if (nfqueue_live_handoff_stage_slot (meta, &slot_index))
    {
      nfqueue_live_handoff_sample_t *sample = &nm->handoff_samples[slot_index];
      nfqueue_live_handoff_sample_lock (sample);
      proof = __atomic_load_n (&sample->state, __ATOMIC_ACQUIRE) == 1 &&
              sample->before_valid &&
              sample->before_worker == meta->initial_worker &&
              sample->before_buffer_index == buffer_index &&
              sample->before_buffer_base == buffer_base &&
              sample->before_packet_id == packet_id &&
              sample->before_payload_offset == payload_offset &&
              sample->before_payload_length == payload_length &&
              sample->before_generation == generation &&
              sample->before_origin_lane == origin_lane &&
              sample->before_obligation_nonce == obligation_nonce &&
              sample->before_stage == NFQUEUE_LIVE_HANDOFF_INITIAL &&
              worker_thread == meta->canonical_worker &&
              (handoff_stage & NFQUEUE_LIVE_HANDOFF_CANONICAL) != 0 &&
              (handoff_stage & NFQUEUE_LIVE_HANDOFF_SLOT_MASK) == slot_index;
      sample->after_valid = 1;
      sample->after_worker = worker_thread;
      sample->after_buffer_index = buffer_index;
      sample->after_buffer_base = buffer_base;
      sample->after_packet_id = packet_id;
      sample->after_payload_offset = payload_offset;
      sample->after_payload_length = payload_length;
      sample->after_generation = generation;
      sample->after_origin_lane = origin_lane;
      sample->after_obligation_nonce = obligation_nonce;
      sample->after_stage = handoff_stage;
      nfqueue_live_handoff_sample_unlock (sample);
      nfqueue_live_handoff_sample_release_for_meta (nm, meta);
    }
  nfqueue_live_counter_inc (&nm->identity_proof_checks);
  if (proof)
    {
      nfqueue_live_counter_inc (&nm->identity_proof_matches);
      return 1;
    }
  nfqueue_live_counter_inc (&nm->identity_proof_failures);
  return 0;
}

static void
nfqueue_live_handoff_sample_snapshot (nfqueue_live_main_t *nm, u32 slot_index,
                                      nfqueue_live_handoff_sample_t *snapshot)
{
  nfqueue_live_handoff_sample_t *sample = &nm->handoff_samples[slot_index];
  nfqueue_live_handoff_sample_lock (sample);
  /* state is reserved by CAS/store operations outside this evidence lock.
   * Do not copy the struct wholesale: an ordinary read of that field would
   * race those atomic accesses.  Every other field is protected by lock. */
  snapshot->lock = 0;
  snapshot->state = __atomic_load_n (&sample->state, __ATOMIC_ACQUIRE);
  snapshot->before_valid = sample->before_valid;
  snapshot->after_valid = sample->after_valid;
  snapshot->reserved = sample->reserved;
  snapshot->before_worker = sample->before_worker;
  snapshot->after_worker = sample->after_worker;
  snapshot->before_buffer_index = sample->before_buffer_index;
  snapshot->after_buffer_index = sample->after_buffer_index;
  snapshot->before_buffer_base = sample->before_buffer_base;
  snapshot->after_buffer_base = sample->after_buffer_base;
  snapshot->before_packet_id = sample->before_packet_id;
  snapshot->after_packet_id = sample->after_packet_id;
  snapshot->before_payload_offset = sample->before_payload_offset;
  snapshot->after_payload_offset = sample->after_payload_offset;
  snapshot->before_payload_length = sample->before_payload_length;
  snapshot->after_payload_length = sample->after_payload_length;
  snapshot->before_generation = sample->before_generation;
  snapshot->after_generation = sample->after_generation;
  snapshot->before_origin_lane = sample->before_origin_lane;
  snapshot->after_origin_lane = sample->after_origin_lane;
  snapshot->before_obligation_nonce = sample->before_obligation_nonce;
  snapshot->after_obligation_nonce = sample->after_obligation_nonce;
  snapshot->before_stage = sample->before_stage;
  snapshot->after_stage = sample->after_stage;
  nfqueue_live_handoff_sample_unlock (sample);
}

static void
nfqueue_live_wake_completion (nfqueue_live_main_t *nm)
{
  u64 one = 1;
  if (write (nm->completion_fd, &one, sizeof (one)) == (ssize_t) sizeof (one))
    nfqueue_live_counter_inc (&nm->completion_wake_writes);
  else if (errno != EAGAIN && errno != EWOULDBLOCK)
    nfqueue_live_counter_inc (&nm->completion_wake_errors);
}

static u8
nfqueue_live_recover_packet_id (const u8 *base, u32 length, u32 *packet_id)
{
  return nfqueue_live_envelope_recover_first_packet_id (
    base, length, packet_id);
}

static void
nfqueue_live_record_last (nfqueue_live_main_t *nm,
                           const nfqueue_live_meta_t *meta,
                           u32 buffer_index, u8 *base)
{
  nm->last_buffer_index = buffer_index;
  nm->last_buffer_base = (uword) base;
  nm->last_datagram_length = meta->datagram_length;
  nm->last_payload_offset = meta->payload_offset;
  nm->last_payload_length = meta->payload_length;
  nm->last_original_length = meta->original_length;
  nm->last_captured_length = meta->captured_length;
  nm->last_packet_id = meta->packet_id;
  nm->last_queue_generation =
    ((u64) meta->generation_hi << 32) | meta->generation_lo;
  nm->last_origin_lane = nfqueue_live_meta_origin_lane (meta);
  nm->last_hook = nfqueue_live_meta_hook (meta);
  nm->last_device_direction =
    nfqueue_live_device_direction ((u8) nm->last_hook);
  nm->last_uid = meta->uid;
  nm->last_uid_known = (meta->flags & NFQUEUE_LIVE_FLAG_UID_KNOWN) != 0;
  nm->last_ip_version = meta->ip_version;
}

static const char *
nfqueue_live_outcome_name (nfqueue_live_completion_outcome_t outcome)
{
  switch (outcome)
    {
    case NFQUEUE_LIVE_OUTCOME_SUCCEEDED:
      return "SUCCEEDED";
    case NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE:
      return "FAILED_DEFINITE";
    case NFQUEUE_LIVE_OUTCOME_UNKNOWN:
      return "OUTCOME_UNKNOWN";
    default:
      return "NONE";
    }
}

static_always_inline void
nfqueue_live_record_outcome (nfqueue_live_main_t *nm,
                             nfqueue_live_meta_t *meta,
                             nfqueue_live_completion_outcome_t outcome)
{
  meta->flags &= ~(NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN |
                   NFQUEUE_LIVE_FLAG_OUTCOME_FAILED);
  switch (outcome)
    {
    case NFQUEUE_LIVE_OUTCOME_SUCCEEDED:
      break;
    case NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE:
      meta->flags |= NFQUEUE_LIVE_FLAG_OUTCOME_FAILED;
      break;
    case NFQUEUE_LIVE_OUTCOME_UNKNOWN:
      meta->flags |= NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN;
      break;
    default:
      break;
    }
  nm->last_verdict_outcome = (u8) outcome;
}

static nfqueue_live_completion_outcome_t
nfqueue_live_send_verdict (nfqueue_live_main_t *nm,
                           nfqueue_live_lane_t *lane, u64 generation,
                           u32 packet_id, u32 origin_lane, u32 verdict)
{
  int result = 0;
  u8 force_failed = __atomic_exchange_n (&nm->inject_verdict_failed_definite,
                                         0, __ATOMIC_ACQ_REL);
  u8 force_unknown = __atomic_exchange_n (&nm->inject_verdict_outcome_unknown,
                                          0, __ATOMIC_ACQ_REL);
  nfqueue_live_completion_outcome_t outcome;

  /* This is the one physical operation for the completion identity.  A
   * definite rejection is an operation-level fault before the backend call;
   * it therefore cannot have been accepted by the receiver.  The ambiguity
   * seam deliberately withholds both the native operation and its result:
   * it models a completion boundary with no trustworthy terminal observation
   * and must not call nfq_set_verdict and then relabel its return. */
  nm->last_verdict_generation = generation;
  nm->last_verdict_packet_id = packet_id;
  nm->last_verdict_origin_lane = origin_lane;
  if (!lane || lane->generation != generation)
    {
      nm->verdict_identity_mismatches++;
      nm->last_verdict_outcome = NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE;
      nfqueue_live_counter_inc (&nm->completion_outcome_failed_definite);
      return NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE;
    }
  lane->verdict_attempts++;
  nm->verdict_attempts++;
  if (force_failed)
    {
      nm->verdict_fault_injections++;
      nm->verdict_send_failures++;
      nm->verdict_definite_rejections++;
      nm->last_verdict_errno = EIO;
      outcome = NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE;
    }
  else if (force_unknown)
    {
      nm->verdict_fault_injections++;
      nm->verdict_ambiguous_results++;
      outcome = NFQUEUE_LIVE_OUTCOME_UNKNOWN;
    }
  else
    {
      nm->native_verdict_calls++;
      result = nfq_set_verdict (lane->queue, packet_id, verdict, 0, 0);
      if (result < 0)
        {
          nm->verdict_send_failures++;
          nm->last_verdict_errno = errno;
          outcome = NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE;
        }
      else
        {
          nm->verdict_send_success++;
          outcome = NFQUEUE_LIVE_OUTCOME_SUCCEEDED;
        }
    }
  switch (outcome)
    {
    case NFQUEUE_LIVE_OUTCOME_SUCCEEDED:
      nfqueue_live_counter_inc (&nm->completion_outcome_succeeded);
      break;
    case NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE:
      nfqueue_live_counter_inc (&nm->completion_outcome_failed_definite);
      break;
    case NFQUEUE_LIVE_OUTCOME_UNKNOWN:
      nfqueue_live_counter_inc (&nm->completion_outcome_unknown);
      break;
    default:
      break;
    }
  return outcome;
}

static void
nfqueue_live_reserve_complete (nfqueue_live_main_t *nm,
                               nfqueue_live_lane_t *lane, u32 buffer_index,
                               u8 *base, u32 received)
{
  vlib_buffer_t *buffer = vlib_get_buffer (nm->vm, buffer_index);
  nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
  u32 packet_id = 0;
  u32 inspect_length = clib_min (
    received, vlib_buffer_get_default_data_size (nm->vm));

  /* Reserve materialization is intentionally narrower than normal ingress:
   * recover only the original NFQUEUE identity from the already-received
   * contiguous VPP span.  Do not call the shared envelope parser, NFQUEUE
   * callback parser, or any worker/policy graph on this bounded fault path. */
  if (!nfqueue_live_recover_packet_id (base, inspect_length, &packet_id))
    {
      /* No completion identity means no Adapter operation can be claimed. */
      nfqueue_live_record_reserve_loss_unmaterialized (nm, lane);
      nfqueue_live_record_reserve_loss (nm, lane);
      nfqueue_live_reserve_return (nm, lane, buffer_index, 0);
      return;
    }

  clib_memset (meta, 0, sizeof (*meta));
  nfqueue_live_set_generation (meta, lane->generation);
  meta->packet_id = packet_id;
  meta->obligation_nonce = nfqueue_live_next_obligation_nonce (nm);
  meta->datagram_length = (u16) clib_min (received, (u32) 0xffff);
  meta->hook = lane->hook;
  meta->origin_lane = lane->origin_lane;
  meta->ip_version = lane->family;
  /* Reserve ACCEPT carries identity only.  Payload facts remain unset because
   * this path deliberately bypasses parser/flow/policy materialization. */
  meta->payload_offset = 0;
  meta->payload_length = 0;
  meta->captured_length = 0;
  meta->original_length = 0;
  buffer->current_length = clib_min (
    received, vlib_buffer_get_default_data_size (nm->vm));

  nm->reserve_direct_obligations++;
  lane->reserve_direct_obligations++;
  nfqueue_live_completion_outcome_t outcome = nfqueue_live_send_verdict (
    nm, lane, lane->generation, packet_id, lane->origin_lane,
    NFQUEUE_LIVE_ACCEPT);
  nfqueue_live_record_outcome (nm, meta, outcome);
  nm->reserve_direct_completions++;
  lane->reserve_direct_completions++;
  nfqueue_live_reserve_return (nm, lane, buffer_index, 1);
}

static void
nfqueue_live_reserve_loss_complete (nfqueue_live_main_t *nm,
                                    nfqueue_live_lane_t *lane,
                                    u32 buffer_index, u8 *base, u32 received)
{
  u32 packet_id;
  u32 inspect_length = clib_min (
    received, vlib_buffer_get_default_data_size (nm->vm));
  if (nfqueue_live_recover_packet_id (base, inspect_length, &packet_id))
    {
      /* Reserve exhaustion is an infrastructure loss, not a policy DROP and
       * never a delivery-success claim.  The pre-reserved loss envelope lets
       * the bounded POC consume one packet and issue an explicit native DROP
       * without allocating or waiting. */
      nfqueue_live_completion_outcome_t outcome = nfqueue_live_send_verdict (
        nm, lane, lane->generation, packet_id, lane->origin_lane,
        NFQUEUE_LIVE_LOSS);
      nfqueue_live_record_reserve_loss_outcome (nm, lane, outcome);
      nfqueue_live_record_reserve_loss_materialization (nm, lane);
    }
  else
    nfqueue_live_record_reserve_loss_unmaterialized (nm, lane);
  nfqueue_live_record_reserve_loss (nm, lane);
  nm->native_buffer_returns++;
  lane->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static nfqueue_live_lane_t *
nfqueue_live_lane_for_meta (nfqueue_live_main_t *nm,
                            const nfqueue_live_meta_t *meta)
{
  u8 lane_index = nfqueue_live_meta_origin_lane (meta);
  if (lane_index >= nm->lane_count)
    return 0;
  return &nm->lanes[lane_index];
}

static void
nfqueue_live_return_buffer (nfqueue_live_main_t *nm, u32 buffer_index,
                            nfqueue_live_meta_t *meta)
{
  if (nfqueue_live_completion_ref_count (meta) != 0 ||
      nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
  nfqueue_live_outstanding_dec (nm);
  if (nm->normal_outstanding != 0)
    nm->normal_outstanding--;
  nfqueue_live_completion_credit_release (nm, meta);
  nm->native_buffer_returns++;
  for (u32 i = 0; i < nm->lane_count; i++)
    if (nm->lanes[i].origin_lane == nfqueue_live_meta_origin_lane (meta))
      {
        nm->lanes[i].native_buffer_returns++;
        break;
      }
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_release_unqueued (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  meta->completion_refs = 0;
  nfqueue_live_completion_credit_release (nm, meta);
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
  nm->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_free_unowned (nfqueue_live_main_t *nm, u32 buffer_index)
{
  nm->native_buffer_returns++;
  vlib_buffer_free_one (nm->vm, buffer_index);
}

static void
nfqueue_live_wake_late_return (nfqueue_live_main_t *nm)
{
  /* The completion eventfd is deliberately closed at the completion-close
   * edge.  Late worker ownership therefore wakes the always-live origin
   * process directly; no closed descriptor is touched. */
  vlib_process_signal_event (nm->vm, nfqueue_live_ingress_process_node.index,
                             0, 0);
}

static u8
nfqueue_live_publish_late_return (nfqueue_live_main_t *nm, u32 buffer_index,
                                  nfqueue_live_meta_t *meta)
{
  nfqueue_live_completion_t late;

  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED ||
      nfqueue_live_completion_ref_count (meta) == 0)
    return 0;
  if (nfqueue_live_late_return_queued (meta))
    return 1;

  nfqueue_live_handoff_sample_release_for_meta (nm, meta);
  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) == 0)
    {
      /* There is no open completion channel on this path.  Record the
       * identity-preserving outcome as unknown exactly once; the origin lane
       * still owns the one native buffer return and completion debt settle. */
      meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED |
                     NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN;
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
      nfqueue_live_record_outcome (nm, meta, NFQUEUE_LIVE_OUTCOME_UNKNOWN);
      nfqueue_live_counter_inc (&nm->completion_outcome_unknown);
    }
  meta->completion_refs |= NFQUEUE_LIVE_LATE_RETURN_QUEUED;
  late = (nfqueue_live_completion_t){
    .buffer_index = buffer_index,
    .generation_lo = meta->generation_lo,
    .generation_hi = meta->generation_hi,
    .packet_id = meta->packet_id,
    .obligation_nonce = meta->obligation_nonce,
    .origin_lane = nfqueue_live_meta_origin_lane (meta),
    .policy_verdict = NFQUEUE_LIVE_ACCEPT,
    .terminal_intent = 1,
    .outcome_hint = NFQUEUE_LIVE_OUTCOME_UNKNOWN,
    .reference_held = 1,
  };
  nfqueue_live_ring_lock (&nm->late_return_push_lock);
  u8 pushed = nfqueue_live_completion_push (&nm->late_return, &late);
  nfqueue_live_ring_unlock (&nm->late_return_push_lock);
  if (!pushed)
    {
      /* The late ring is bounded by the same 127-obligation admission cap.
       * A full ring is an internal bound violation, never a reason to hide
       * the still-live obligation. */
      meta->completion_refs &= ~NFQUEUE_LIVE_LATE_RETURN_QUEUED;
      nfqueue_live_counter_inc (&nm->teardown_obligation_residue);
      return 0;
    }
  nfqueue_live_counter_inc (&nm->teardown_late_completion);
  nfqueue_live_wake_late_return (nm);
  return 1;
}

static void
nfqueue_live_publish_terminal (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  if (!nfqueue_live_teardown_completion_open (nm))
    {
      /* The worker cannot settle a native buffer.  Transfer its one live
       * reference to the origin lane's late-return ring instead. */
      (void) nfqueue_live_publish_late_return (nm, buffer_index, meta);
      return;
    }
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  if (nfqueue_live_completion_ref_count (meta) == 0)
    return;
  /* A source-side queue fault or a destination-side invalid-state terminal
   * must release any reserved before/after evidence slot. */
  nfqueue_live_handoff_sample_release_for_meta (nm, meta);
  /* A terminal token is the only worker-side intent counted here.  Normal
   * completion frames do not imply a terminal/fail-open path. */
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
  nfqueue_live_counter_inc (&nm->owner_terminal_intents);
  nfqueue_live_completion_t terminal = {
    .buffer_index = buffer_index,
    .generation_lo = meta->generation_lo,
    .generation_hi = meta->generation_hi,
    .packet_id = meta->packet_id,
    .obligation_nonce = meta->obligation_nonce,
    .origin_lane = nfqueue_live_meta_origin_lane (meta),
    .policy_verdict = NFQUEUE_LIVE_ACCEPT,
    .terminal_intent = 1,
    .outcome_hint = NFQUEUE_LIVE_OUTCOME_NONE,
    .reference_held = 1,
  };
  nfqueue_live_origin_return_lock (nm);
  u8 pushed = nfqueue_live_completion_push (&nm->origin_return, &terminal);
  nfqueue_live_origin_return_unlock (nm);
  if (!pushed)
    {
      /* Admission is capped at the usable emergency-ring capacity, so this
       * is a violated internal bound rather than a legal producer fallback.
       * Keep the live obligation intact for the origin drain to diagnose. */
      nfqueue_live_counter_inc (&nm->origin_return_overflow);
      return;
    }
  nfqueue_live_wake_completion (nm);
}

static void
nfqueue_live_settle_on_origin (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  nfqueue_live_lane_t *lane = nfqueue_live_lane_for_meta (nm, meta);
  nfqueue_live_teardown_state_t teardown_state =
    nfqueue_live_teardown_state_load (nm);
  u64 generation = nfqueue_live_meta_generation (meta);
  u8 deadline = teardown_state == NFQUEUE_LIVE_TEARDOWN_DEADLINE;
  u8 identity_completable =
    lane && lane->queue && meta->packet_id != 0 && generation != 0 &&
    lane->generation == generation && nm->generation == generation;
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) == 0)
    {
      meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
      if (identity_completable)
        {
          nfqueue_live_completion_outcome_t outcome =
            nfqueue_live_send_verdict (
              nm, lane, generation, meta->packet_id,
              nfqueue_live_meta_origin_lane (meta), NFQUEUE_LIVE_ACCEPT);
          nfqueue_live_record_outcome (nm, meta, outcome);
          if (outcome == NFQUEUE_LIVE_OUTCOME_SUCCEEDED)
            {
              nm->fail_open_settlements++;
              if (deadline)
                nfqueue_live_counter_inc (&nm->teardown_deadline_accepts);
              else
                nfqueue_live_counter_inc (&nm->teardown_drain_accepts);
            }
          else if (outcome == NFQUEUE_LIVE_OUTCOME_FAILED_DEFINITE)
            nfqueue_live_counter_add (&nm->teardown_deadline_failed_definite,
                                       deadline);
          else if (outcome == NFQUEUE_LIVE_OUTCOME_UNKNOWN)
            nfqueue_live_counter_add (&nm->teardown_deadline_outcome_unknown,
                                       deadline);
        }
      else
        {
          /* A buffer that reached teardown without a usable queue generation
           * or packet id cannot be honestly called ACCEPTed.  It is settled
           * exactly once as an explicitly classified unknown obligation; no
           * stale-generation or guessed verdict is attempted. */
          nfqueue_live_counter_inc (&nm->teardown_identity_unrecoverable);
          nfqueue_live_counter_add (&nm->teardown_deadline_outcome_unknown,
                                    deadline);
          if (generation != nm->generation)
            nfqueue_live_counter_inc (&nm->completion_stale_generation);
          nfqueue_live_record_outcome (nm, meta,
                                       NFQUEUE_LIVE_OUTCOME_UNKNOWN);
          nfqueue_live_counter_inc (&nm->completion_outcome_unknown);
        }
    }
  nfqueue_live_completion_ref_set (meta, 0);
  nfqueue_live_return_buffer (nm, buffer_index, meta);
}

static_always_inline u8
nfqueue_live_completion_identity_matches (const nfqueue_live_meta_t *meta,
                                           const nfqueue_live_completion_t *entry)
{
  return entry->generation_lo == meta->generation_lo &&
         entry->generation_hi == meta->generation_hi &&
         entry->packet_id == meta->packet_id &&
         entry->obligation_nonce == meta->obligation_nonce &&
         entry->origin_lane == nfqueue_live_meta_origin_lane (meta);
}

static void
nfqueue_live_drain_late_return_queue (nfqueue_live_main_t *nm)
{
  nfqueue_live_completion_t entry;
  while (nfqueue_live_completion_pop (&nm->late_return, &entry))
    {
      vlib_buffer_t *buffer = vlib_get_buffer (nm->vm, entry.buffer_index);
      nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
      /* Never free a buffer that no longer proves the late entry's complete
       * identity.  A reused index is stale evidence, not permission to issue
       * a second verdict or native return; leave the obligation classified as
       * residue for the caller. */
      if (!nfqueue_live_completion_identity_matches (meta, &entry) ||
          !nfqueue_live_late_return_queued (meta) ||
          nfqueue_live_completion_ref_count (meta) == 0 ||
          nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
        {
          nfqueue_live_counter_inc (&nm->completion_stale);
          nfqueue_live_counter_inc (&nm->teardown_obligation_residue);
          continue;
        }
      /* The late token represents the still-live obligation, including any
       * duplicate worker references.  Clear the marker and settle once on
       * the origin lane; no verdict is retried because the outcome was
       * already attempted/recorded by the worker handoff above. */
      nfqueue_live_counter_inc (&nm->teardown_late_settlements);
      meta->completion_refs = 0;
      nfqueue_live_return_buffer (nm, entry.buffer_index, meta);
    }
}

static void
nfqueue_live_drop_completion_ref (nfqueue_live_main_t *nm, u32 buffer_index,
                                  nfqueue_live_meta_t *meta,
                                  const nfqueue_live_completion_t *entry)
{
  if (!entry->reference_held ||
      nfqueue_live_completion_ref_count (meta) == 0)
    return;
  nfqueue_live_completion_ref_dec (meta);
  if (nfqueue_live_completion_ref_count (meta) == 0)
    nfqueue_live_return_buffer (nm, buffer_index, meta);
}

static void
nfqueue_live_complete_one (nfqueue_live_main_t *nm,
                           const nfqueue_live_completion_t *entry)
{
  vlib_buffer_t *buffer;
  nfqueue_live_meta_t *meta;
  nfqueue_live_teardown_state_t teardown_state;
  u64 entry_generation;

  buffer = vlib_get_buffer (nm->vm, entry->buffer_index);
  meta = nfqueue_live_meta (buffer);
  teardown_state = nfqueue_live_teardown_state_load (nm);
  entry_generation = ((u64) entry->generation_hi << 32) |
                     entry->generation_lo;

  /* A completion arriving after CLOSE_COMPLETION is a lifecycle fault, not
   * permission to touch a fresh generation's buffer.  The old generation is
   * retained in the bounded stale ledger and never replayed. */
  if (!nfqueue_live_teardown_completion_generation_allowed (
        teardown_state, nm->generation, entry_generation))
    {
      nm->completion_stale++;
      if (entry_generation != nm->generation)
        nfqueue_live_counter_inc (&nm->completion_stale_generation);
      if (nfqueue_live_completion_identity_matches (meta, entry) &&
          nfqueue_live_completion_ref_count (meta) != 0 &&
          nfqueue_live_state (meta) != NFQUEUE_LIVE_STATE_RETURNED)
        (void) nfqueue_live_publish_late_return (nm, entry->buffer_index, meta);
      else
        nfqueue_live_counter_inc (&nm->teardown_late_completion);
      return;
    }

  /* Check the full completion identity before touching verdict or reference
   * state. Generation alone is insufficient when a packet id is reused. */
  if (!nfqueue_live_completion_identity_matches (meta, entry) ||
      nfqueue_live_state (meta) < NFQUEUE_LIVE_STATE_COMPLETION)
    {
      nm->completion_stale++;
      if (entry->generation_lo != meta->generation_lo ||
          entry->generation_hi != meta->generation_hi)
        nfqueue_live_counter_inc (&nm->completion_stale_generation);
      return;
    }

  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) != 0)
    {
      nm->completion_duplicate++;
      nfqueue_live_counter_inc (&nm->completion_duplicate_attempts);
      nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
      return;
    }

  meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
  if (entry->terminal_intent)
    nm->fail_open_settlements++;
  nfqueue_live_lane_t *lane = nfqueue_live_lane_for_meta (nm, meta);
  if (!lane || !lane->queue)
    {
      nm->missing_ingress_identity++;
      nm->missing_queue_generation++;
      nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
      return;
    }
  nfqueue_live_completion_outcome_t outcome = nfqueue_live_send_verdict (
    nm, lane, nfqueue_live_meta_generation (meta), meta->packet_id,
    nfqueue_live_meta_origin_lane (meta), entry->policy_verdict);
  nfqueue_live_record_outcome (nm, meta, outcome);

  nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
}

static void
nfqueue_live_drain_completion_queue (nfqueue_live_main_t *nm)
{
  u64 value;
  nfqueue_live_completion_t entry;

  while (nm->completion_fd >= 0 &&
         read (nm->completion_fd, &value, sizeof (value)) == (ssize_t) sizeof (value))
    ;
  while (nfqueue_live_completion_pop (&nm->origin_return, &entry))
    {
      nm->completion_frames++;
      nfqueue_live_complete_one (nm, &entry);
    }
  while (nfqueue_live_completion_pop (&nm->completion, &entry))
    {
      nm->completion_frames++;
      nfqueue_live_complete_one (nm, &entry);
    }
}

static clib_error_t *
nfqueue_live_completion_read_ready (clib_file_t *file)
{
  nfqueue_live_main_t *nm = (nfqueue_live_main_t *) file->private_data;
  if (!nfqueue_live_teardown_completion_open (nm))
    {
      nfqueue_live_counter_inc (&nm->teardown_late_completion);
      return 0;
    }
  nfqueue_live_drain_completion_queue (nm);
  return 0;
}

static void
nfqueue_live_direct_accept (nfqueue_live_main_t *nm,
                            struct nfq_q_handle *queue, u32 packet_id)
{
  nfqueue_live_lane_t *lane = 0;
  for (u32 i = 0; i < nm->lane_count; i++)
    if (nm->lanes[i].queue == queue)
      {
        lane = &nm->lanes[i];
        break;
      }
  nm->message_rejections++;
  (void) nfqueue_live_send_verdict (
    nm, lane, lane ? lane->generation : 0, packet_id,
    lane ? lane->origin_lane : 0, NFQUEUE_LIVE_ACCEPT);
}

static void
nfqueue_live_record_envelope (nfqueue_live_main_t *nm,
                              const nfqueue_live_envelope_t *envelope)
{
  nm->envelope_message_count += envelope->message_count;
  nm->envelope_valid_message_count += envelope->valid_message_count;
  nm->envelope_recoverable_message_count +=
    envelope->recoverable_message_count;
  nm->envelope_netlink_header_bytes += envelope->netlink_header_bytes;
  nm->envelope_attribute_bytes += envelope->attribute_bytes;
  nm->envelope_attribute_aligned_bytes +=
    envelope->attribute_aligned_bytes;
  nm->envelope_payload_offset = envelope->first_payload_offset;
  nm->envelope_usable_l3_bytes = envelope->usable_l3_bytes;
  nm->envelope_parsed_bytes = envelope->parsed_bytes;
  if (envelope->complete)
    {
      nm->envelope_boundary_passes++;
      if (envelope->parsed_bytes == envelope->data_capacity)
        nm->envelope_exact_boundary_passes++;
    }
}

/* Reject every recoverable identity in a datagram without calling
 * nfq_handle_packet. This is the only safe operation for a multi-message,
 * oversize, or malformed datagram: one received VPP buffer cannot carry
 * independent payload obligations without copying bytes. */
typedef struct
{
  nfqueue_live_main_t *nm;
  struct nfq_q_handle *queue;
  u32 recovered;
  u32 seen_count;
  u32 seen_packet_ids[512];
} nfqueue_live_envelope_reject_context_t;

static void
nfqueue_live_reject_envelope_packet_id (void *opaque, uint32_t packet_id)
{
  nfqueue_live_envelope_reject_context_t *context =
    (nfqueue_live_envelope_reject_context_t *) opaque;
  for (u32 i = 0; i < context->seen_count; i++)
    if (context->seen_packet_ids[i] == packet_id)
      return;
  if (context->seen_count <
      sizeof (context->seen_packet_ids) / sizeof (context->seen_packet_ids[0]))
    context->seen_packet_ids[context->seen_count++] = packet_id;
  nfqueue_live_direct_accept (context->nm, context->queue, packet_id);
  context->nm->envelope_rejected_messages++;
  context->recovered++;
}

static u32
nfqueue_live_reject_envelope_messages (nfqueue_live_main_t *nm,
                                       struct nfq_q_handle *queue,
                                       const u8 *base, u32 captured_bytes)
{
  nfqueue_live_envelope_reject_context_t context = {
    .nm = nm,
    .queue = queue,
  };
  (void) nfqueue_live_envelope_recover_packet_ids (
    base, captured_bytes, nfqueue_live_reject_envelope_packet_id, &context);
  return context.recovered;
}

static u32
nfqueue_live_next_obligation_nonce (nfqueue_live_main_t *nm)
{
  nm->next_obligation_nonce++;
  if (nm->next_obligation_nonce == 0)
    {
      nm->generation++;
      if (nm->generation == 0)
        nm->generation = 1;
      nm->next_obligation_nonce = 1;
    }
  return nm->next_obligation_nonce;
}

static int
nfqueue_live_packet_cb (struct nfq_q_handle *queue, struct nfgenmsg *message,
                        struct nfq_data *data, void *opaque)
{
  nfqueue_live_lane_t *lane = (nfqueue_live_lane_t *) opaque;
  nfqueue_live_main_t *nm = lane->nm;
  nfqueue_live_datagram_t *datagram = nm->active_datagram;
  struct nfqnl_msg_packet_hdr *header;
  nfqueue_live_meta_t *meta;
  unsigned char *payload = 0;
  int payload_length;
  u32 cap_len;
  u32 packet_id;
  uword payload_address;
  uword begin;
  uword end;
  vlib_buffer_t *buffer;
  (void) message;

  if (!datagram)
    return 0;
  datagram->callback_count++;
  lane->callbacks++;
  nm->callbacks++;
  header = nfq_get_msg_packet_hdr (data);
  if (!header)
    {
      datagram->ingress_identity_missing = 1;
      nm->missing_ingress_identity++;
      return 0;
    }
  if (nm->inject_missing_packet_id)
    {
      nm->inject_missing_packet_id = 0;
      nm->missing_packet_id++;
      nm->missing_ingress_identity++;
      datagram->ingress_identity_missing = 1;
      return 0;
    }
  packet_id = ntohl (header->packet_id);
  if (nm->inject_missing_generation || lane->generation == 0)
    {
      nm->inject_missing_generation = 0;
      nm->missing_queue_generation++;
      nm->missing_ingress_identity++;
      datagram->ingress_identity_missing = 1;
      return 0;
    }
  datagram->callback_identities++;
  if (datagram->callback_count != 1)
    {
      nm->multiple_message_rejects++;
      nfqueue_live_direct_accept (nm, lane->queue, packet_id);
      datagram->callback_verdicts++;
      return 0;
    }

  if (datagram->truncated)
    {
      nfqueue_live_direct_accept (nm, lane->queue, packet_id);
      datagram->callback_verdicts++;
      return 0;
    }

  payload_length = nfq_get_payload (data, &payload);
  if (payload_length <= 0 || !payload)
    {
      nm->malformed_payloads++;
      nfqueue_live_direct_accept (nm, lane->queue, packet_id);
      datagram->callback_verdicts++;
      return 0;
    }
  if (nfq_get_cap_len (data, &cap_len) < 0)
    {
      /* Some kernels omit NFQA_CAP_LEN for ordinary, non-GSO local traffic.
       * Keep the value sourced from libnetfilter_queue's captured payload
       * metadata; never inspect an L3 header to invent original_length. */
      nm->cap_len_missing++;
      cap_len = (u32) payload_length;
    }
  payload_address = (uword) payload;
  begin = (uword) datagram->base;
  end = begin + datagram->parse_length;
  if (payload_address < begin || payload_address > end ||
      (uword) payload_length > end - payload_address)
    {
      nm->malformed_payloads++;
      nfqueue_live_direct_accept (nm, lane->queue, packet_id);
      datagram->callback_verdicts++;
      return 0;
    }

  buffer = vlib_get_buffer (nm->vm, datagram->buffer_index);
  meta = nfqueue_live_meta (buffer);
  clib_memset (meta, 0, sizeof (*meta));
  datagram->metadata_initialized = 1;
  nfqueue_live_set_generation (meta, lane->generation);
  meta->packet_id = packet_id;
  meta->obligation_nonce = nfqueue_live_next_obligation_nonce (nm);
  meta->datagram_length = (u16) datagram->datagram_length;
  meta->payload_offset = (u16) (payload_address - begin);
  meta->payload_length = (u16) payload_length;
  meta->captured_length = (u16) payload_length;
  meta->original_length = cap_len;
  meta->hook = header->hook;
  meta->origin_lane = lane->origin_lane;
  meta->initial_worker =
    (u8) nfqueue_live_initial_worker (nm, meta->origin_lane);
  meta->canonical_worker =
    (u8) nfqueue_live_canonical_worker (nm, meta);
  nfqueue_live_completion_ref_set (meta, 1);
  if (nm->inject_uid_unknown)
    {
      nm->inject_uid_unknown = 0;
      meta->uid = 0;
      nm->uid_unknown_fast_path++;
    }
  else if (nfq_get_uid (data, &meta->uid))
    {
      meta->flags |= NFQUEUE_LIVE_FLAG_UID_KNOWN;
      nm->uid_known_packets++;
    }
  else
    nm->uid_unknown_fast_path++;
  meta->flags |= NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN;
  /* The Adapter normalizes the NFQUEUE family hint; it deliberately does not
   * inspect an L3 header or execute packet-policy parsing. */
  meta->ip_version = lane->family;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_LIVE);
  nm->inline_metadata_writes++;
  nfqueue_live_counter_inc (&nm->payload_span_checks);
  if (meta->payload_offset > meta->datagram_length ||
      meta->payload_length > meta->datagram_length - meta->payload_offset)
    {
      nfqueue_live_counter_inc (&nm->payload_span_failures);
      nfqueue_live_direct_accept (nm, lane->queue, packet_id);
      datagram->callback_verdicts++;
      return 0;
    }
  nm->payload_pointer_projections++;
  datagram->candidate = 1;
  return 0;
}

static clib_error_t *
nfqueue_live_netlink_read_ready (clib_file_t *file)
{
  nfqueue_live_reader_t *reader =
    (nfqueue_live_reader_t *) file->private_data;
  nfqueue_live_main_t *nm = reader->nm;
  nfqueue_live_lane_t *lane = &nm->lanes[reader->lane_index];
  u32 buffer_index;
  vlib_buffer_t *buffer;
  u8 *base;
  u32 capacity;
  int received;
  nfqueue_live_datagram_t datagram;
  nfqueue_live_envelope_t envelope;
  int envelope_status;
  u32 rejected_messages;
  int handled;
  nfqueue_live_ingress_result_t ingress_result;

  /* Queue readers are admission gates, not lifecycle owners.  Once the
   * quiesce edge is observed no new NFQUEUE obligation may be created, even
   * if a readiness callback was already queued by clib_file. */
  if (!nfqueue_live_teardown_ingress_allowed (nm) || !lane->enabled)
    return 0;

  while (1)
    {
      buffer_index = ~0u;
      ingress_result =
        nfqueue_live_acquire_ingress_buffer (nm, lane, &buffer_index);
      if (ingress_result == NFQUEUE_LIVE_INGRESS_NO_BUFFER)
        {
          nfqueue_live_discard_result_t discard =
            nfqueue_live_discard_bounded_loss (nm, lane);
          if (discard == NFQUEUE_LIVE_DISCARD_LOSS)
            continue;
          /* EAGAIN/EINTR and non-transient receive faults both leave the
           * callback without a buffer and must not spin in this loop. */
          if (discard == NFQUEUE_LIVE_DISCARD_FAULT)
            nfqueue_live_disable_faulted_lane (nm, lane);
          return 0;
        }
      buffer = vlib_get_buffer (nm->vm, buffer_index);
      base = vlib_buffer_get_current (buffer);
      capacity = vlib_buffer_get_default_data_size (nm->vm);
      if (__atomic_exchange_n (&nm->inject_receive_fault, 0,
                               __ATOMIC_ACQ_REL))
        {
          errno = EIO;
          received = -1;
        }
      else
        received = recv (lane->netlink_fd, base, capacity,
                         MSG_DONTWAIT | MSG_TRUNC);
      if (received < 0)
        {
          if (ingress_result == NFQUEUE_LIVE_INGRESS_RESERVE)
            nfqueue_live_reserve_return (nm, lane, buffer_index, 0);
          else
            vlib_buffer_free_one (nm->vm, buffer_index);
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
          /* The buffer was returned exactly once above.  A non-transient
           * receive fault is bounded health evidence: remove this lane's
           * reader and yield, rather than returning an error while leaving
           * an always-ready callback registered. */
          nm->reserve_receive_faults++;
          lane->reserve_receive_faults++;
          nm->reserve_degraded_health++;
          nfqueue_live_disable_faulted_lane (nm, lane);
          return 0;
        }
      if (received == 0)
        {
          if (ingress_result == NFQUEUE_LIVE_INGRESS_RESERVE)
            nfqueue_live_reserve_return (nm, lane, buffer_index, 0);
          else
            vlib_buffer_free_one (nm->vm, buffer_index);
          continue;
        }
      nm->live_buffer_receives++;
      lane->datagrams++;
      nm->datagrams++;
      if (ingress_result == NFQUEUE_LIVE_INGRESS_RESERVE)
        {
          nfqueue_live_reserve_complete (nm, lane, buffer_index, base,
                                         (u32) received);
          continue;
        }
      if (ingress_result == NFQUEUE_LIVE_INGRESS_LOSS)
        {
          nfqueue_live_reserve_loss_complete (nm, lane, buffer_index, base,
                                              (u32) received);
          continue;
        }
      if (received > (int) capacity)
        nm->truncated_datagrams++;
      envelope_status = nfqueue_live_measure_envelope (
        base, (u32) received, capacity, &envelope);
      nfqueue_live_record_envelope (nm, &envelope);
      if (envelope.multi_message)
        nm->multiple_message_datagrams++;
      buffer->current_length = clib_min ((u32) received, capacity);
      if (envelope_status != NFQUEUE_LIVE_ENVELOPE_COMPLETE)
        {
          if (envelope_status == NFQUEUE_LIVE_ENVELOPE_OVERSIZE)
            nm->envelope_oversize_rejects++;
          else
            nm->envelope_malformed_rejects++;
          nm->envelope_recovery_attempts++;
          rejected_messages = nfqueue_live_reject_envelope_messages (
            nm, lane->queue, base, clib_min ((u32) received, capacity));
          nm->envelope_recoveries += rejected_messages;
          if (rejected_messages == 0)
            nm->identity_unrecoverable++;
          nfqueue_live_free_unowned (nm, buffer_index);
          continue;
        }
      datagram.nm = nm;
      datagram.lane = lane;
      datagram.buffer_index = buffer_index;
      datagram.base = base;
      datagram.datagram_length = (u32) received;
      datagram.parse_length = clib_min ((u32) received, capacity);
      datagram.callback_count = 0;
      datagram.callback_identities = 0;
      datagram.callback_verdicts = 0;
      datagram.truncated = received > (int) capacity;
      datagram.candidate = 0;
      datagram.metadata_initialized = 0;
      datagram.ingress_identity_missing = 0;
      nm->active_datagram = &datagram;
      handled = nfq_handle_packet (lane->handle, (char *) base,
                                   (int) datagram.parse_length);
      nm->active_datagram = 0;
      if (datagram.callback_count > 1)
        {
          u32 unknown_callbacks =
            datagram.callback_count - datagram.callback_identities;
          nm->multiple_message_datagrams++;
          if (datagram.candidate)
            {
              nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
              /* Callback #1 remains a live candidate even when callback #2
               * already received a direct reject. Settle that identity too. */
              nfqueue_live_direct_accept (nm, lane->queue, meta->packet_id);
              datagram.callback_verdicts++;
              nfqueue_live_release_unqueued (nm, buffer_index, meta);
            }
          else if (datagram.metadata_initialized)
            nfqueue_live_release_unqueued (
              nm, buffer_index, nfqueue_live_meta (buffer));
          else
            nfqueue_live_free_unowned (nm, buffer_index);
          nm->identity_unrecoverable += unknown_callbacks;
        }
      else if (datagram.callback_count == 1 && datagram.candidate &&
               handled >= 0)
        {
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          if (!nfqueue_live_completion_credit_acquire (nm))
            {
              /* The credit ledger is independent of the live-obligation
               * ledger: no worker token is admitted without one bounded
               * completion credit. */
              nm->ingress_overload++;
              nfqueue_live_direct_accept (nm, lane->queue, meta->packet_id);
              datagram.callback_verdicts++;
              nfqueue_live_release_unqueued (nm, buffer_index, meta);
            }
          else
            {
              nfqueue_live_meta_set_credit (meta, 1);
              if (nfqueue_live_outstanding_load (nm) >=
                  NFQUEUE_LIVE_MAX_OUTSTANDING)
                {
                  /* Keep one complete origin-return ring available for every
                   * admitted obligation; reject additional candidates on the
                   * origin lane before they acquire a worker obligation. */
                  nm->ingress_overload++;
                  nfqueue_live_completion_credit_release (nm, meta);
                  nfqueue_live_direct_accept (nm, lane->queue,
                                              meta->packet_id);
                  datagram.callback_verdicts++;
                  nfqueue_live_release_unqueued (nm, buffer_index, meta);
                }
              else if (!nfqueue_live_index_push (&nm->ingress, buffer_index))
                {
                  nm->ingress_overload++;
                  nfqueue_live_counter_inc (&nm->ingress_queue_full);
                  nfqueue_live_completion_credit_release (nm, meta);
                  nfqueue_live_direct_accept (nm, lane->queue,
                                              meta->packet_id);
                  datagram.callback_verdicts++;
                  nfqueue_live_release_unqueued (nm, buffer_index, meta);
                }
              else
                {
                  nfqueue_live_outstanding_inc (nm);
                  nm->normal_outstanding++;
                  if (nm->normal_outstanding > nm->normal_peak_occupancy)
                    nm->normal_peak_occupancy = nm->normal_outstanding;
                  nm->message_obligations++;
                  lane->message_obligations++;
                  nfqueue_live_record_last (nm, meta, buffer_index, base);
                  vlib_process_signal_event (
                    nm->vm, nfqueue_live_ingress_process_node.index, 0, 0);
                }
            }
        }
      else if (datagram.callback_count == 1 && datagram.candidate)
        {
          /* nfq_handle_packet reported a parser failure after callback #1
           * projected the payload. The candidate is still an owed identity. */
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          nfqueue_live_direct_accept (nm, lane->queue, meta->packet_id);
          datagram.callback_verdicts++;
          nfqueue_live_release_unqueued (nm, buffer_index, meta);
        }
      else if (datagram.callback_count == 0)
        {
          u32 recovered_packet_id;
          if (nfqueue_live_recover_packet_id (base, datagram.parse_length,
                                               &recovered_packet_id))
            {
              /* MSG_TRUNC and parser failures still owe the kernel a verdict
               * whenever the packet id can be recovered from NFQA_PACKET_HDR. */
              nfqueue_live_direct_accept (nm, lane->queue, recovered_packet_id);
              datagram.callback_verdicts++;
            }
          else
            nm->identity_unrecoverable++;
          nfqueue_live_free_unowned (nm, buffer_index);
        }
      else
        {
          u32 recovered_packet_id;
          u32 unknown_callbacks =
            datagram.callback_count - datagram.callback_identities;
          /* A single callback can reject itself (missing CAP_LEN, malformed
           * payload, or span failure). If libnetfilter_queue omitted the
           * callback identity, recover one from the raw netlink span when
           * possible; otherwise account the unrecoverable obligation. */
          if (!datagram.ingress_identity_missing &&
              datagram.callback_verdicts == 0 &&
              datagram.callback_identities == 0 &&
              nfqueue_live_recover_packet_id (base, datagram.parse_length,
                                               &recovered_packet_id))
            {
              nfqueue_live_direct_accept (nm, lane->queue, recovered_packet_id);
              datagram.callback_verdicts++;
            }
          nm->identity_unrecoverable += unknown_callbacks;
          if (datagram.metadata_initialized)
            nfqueue_live_release_unqueued (
              nm, buffer_index, nfqueue_live_meta (buffer));
          else
            nfqueue_live_free_unowned (nm, buffer_index);
        }
    }
}

static u8
nfqueue_live_publish_completion (nfqueue_live_main_t *nm, u32 buffer_index,
                                 nfqueue_live_meta_t *meta)
{
  if (!nfqueue_live_teardown_completion_open (nm))
    {
      (void) nfqueue_live_publish_late_return (nm, buffer_index, meta);
      return 0;
    }
  nfqueue_live_completion_t completion = {
    .buffer_index = buffer_index,
    .generation_lo = meta->generation_lo,
    .generation_hi = meta->generation_hi,
    .packet_id = meta->packet_id,
    .obligation_nonce = meta->obligation_nonce,
    .origin_lane = nfqueue_live_meta_origin_lane (meta),
    .policy_verdict = NFQUEUE_LIVE_ACCEPT,
    .terminal_intent = 0,
    .outcome_hint = NFQUEUE_LIVE_OUTCOME_NONE,
    .reference_held = 1,
  };
  u8 stale_requested = __atomic_exchange_n (&nm->inject_stale, 0,
                                            __ATOMIC_ACQ_REL);
  u8 duplicate_requested = __atomic_exchange_n (&nm->inject_duplicate, 0,
                                                __ATOMIC_ACQ_REL);
  u32 required_slots = 1 + stale_requested + duplicate_requested;
  u8 primary_pushed;
  u8 stale_pushed = 1;
  u8 duplicate_pushed = 1;

  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED ||
      nfqueue_live_completion_ref_count (meta) == 0)
    return 0;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
  if (__atomic_exchange_n (&nm->inject_completion_overflow, 0,
                           __ATOMIC_ACQ_REL))
    {
      /* Reserve every free normal-ring slot with an exact duplicate. The
       * original reference stays reserved for the emergency origin token. */
      nfqueue_live_completion_lock (nm);
      while (nfqueue_live_completion_free_slots (&nm->completion) >
             required_slots)
        {
          nfqueue_live_completion_t filler = completion;
          if (!nfqueue_live_completion_push (&nm->completion, &filler))
            break;
          nfqueue_live_completion_ref_inc (meta);
        }
      nfqueue_live_completion_unlock (nm);
    }
  /* A stale token carries no reference; only an exact duplicate owns an
   * additional inline reference. */
  nfqueue_live_completion_lock (nm);
  if (nfqueue_live_completion_free_slots (&nm->completion) < required_slots)
    {
      nfqueue_live_completion_unlock (nm);
      nfqueue_live_counter_inc (&nm->completion_ring_overflow);
      nfqueue_live_publish_terminal (nm, buffer_index, meta);
      return 0;
    }
  if (duplicate_requested)
      nfqueue_live_completion_ref_inc (meta);
  primary_pushed = nfqueue_live_completion_push (&nm->completion, &completion);
  if (!primary_pushed)
    {
      if (duplicate_requested)
        nfqueue_live_completion_ref_dec (meta);
      nfqueue_live_completion_unlock (nm);
      nfqueue_live_counter_inc (&nm->completion_ring_overflow);
      nfqueue_live_publish_terminal (nm, buffer_index, meta);
      return 0;
    }
  if (stale_requested)
    {
      nfqueue_live_completion_t stale = completion;
      stale.reference_held = 0;
      /* S77's stale fault is specifically an old queue generation.  Keep
       * packet id and nonce unchanged so the generation guard is the only
       * reason this delayed token is rejected. */
      stale.generation_lo++;
      if (stale.generation_lo == 0)
        stale.generation_hi++;
      stale_pushed = nfqueue_live_completion_push (&nm->completion, &stale);
    }
  if (duplicate_requested)
    {
      nfqueue_live_completion_t duplicate = completion;
      duplicate_pushed =
        nfqueue_live_completion_push (&nm->completion, &duplicate);
      if (!duplicate_pushed)
        nfqueue_live_completion_ref_dec (meta);
    }
  nfqueue_live_completion_unlock (nm);
  if (!stale_pushed)
    nfqueue_live_counter_inc (&nm->completion_ring_overflow);
  if (!duplicate_pushed)
    nfqueue_live_counter_inc (&nm->completion_ring_overflow);
  nfqueue_live_wake_completion (nm);
  return 1;
}

VLIB_NODE_FN (nfqueue_live_owner_node) (vlib_main_t *vm,
                                        vlib_node_runtime_t *node,
                                        vlib_frame_t *frame)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;

  while (n_left != 0)
    {
      vlib_buffer_t *buffer = vlib_get_buffer (vm, from[0]);
      nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
      u32 buffer_index = from[0];
      u32 worker_thread = vlib_get_thread_index ();
      u16 target_thread;
      u32 enqueued;

      /* Test-only hold gate: admit one genuine current-generation packet,
       * retain its live VPP buffer/reference/debt, and stop before publishing
       * a completion.  The origin lane owns release at teardown. */
      if (__atomic_load_n (&nm->hold_obligation, __ATOMIC_ACQUIRE) &&
          nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_LIVE &&
          nfqueue_live_meta_generation (meta) == nm->generation)
        {
          u32 expected = ~0u;
          if (__atomic_compare_exchange_n (&nm->held_buffer_index, &expected,
                                           buffer_index, 0, __ATOMIC_ACQ_REL,
                                           __ATOMIC_ACQUIRE))
            {
              __atomic_store_n (&nm->hold_obligation, 0, __ATOMIC_RELEASE);
              __atomic_store_n (&nm->held_obligation, 1, __ATOMIC_RELEASE);
              from++;
              n_left--;
              continue;
            }
        }

      nfqueue_live_counter_inc (&nm->handoff_count);
      __atomic_store_n (&nm->last_worker_thread, worker_thread,
                        __ATOMIC_RELEASE);
      if (nfqueue_live_state (meta) != NFQUEUE_LIVE_STATE_LIVE)
        nfqueue_live_counter_inc (&nm->owner_invalid_state);
      nfqueue_live_counter_inc (&nm->payload_span_checks);
      if ((meta->flags & NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN) == 0 ||
          meta->payload_offset > meta->datagram_length ||
          meta->payload_length > meta->datagram_length - meta->payload_offset)
        {
          nfqueue_live_counter_inc (&nm->payload_span_failures);
          nfqueue_live_publish_terminal (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }

      if (meta->handoff_stage == NFQUEUE_LIVE_HANDOFF_INITIAL)
        {
          if (worker_thread != meta->initial_worker)
            {
              nfqueue_live_counter_inc (&nm->owner_invalid_state);
              nfqueue_live_publish_terminal (nm, buffer_index, meta);
              from++;
              n_left--;
              continue;
            }
          if (meta->canonical_worker != meta->initial_worker)
            {
              u32 sample_index;
              nfqueue_live_counter_inc (&nm->owner_mismatch_count);
              nfqueue_live_counter_inc (&nm->owner_remote_obligations);
              if (!nfqueue_live_handoff_sample_reserve (nm, &sample_index))
                {
                  /* The bounded proof evidence transport is itself a
                   * producer-side capacity fault; settle on origin without
                   * moving a buffer whose source identity was not recorded. */
                  nfqueue_live_counter_inc (&nm->owner_queue_full);
                  nfqueue_live_publish_terminal (nm, buffer_index, meta);
                  from++;
                  n_left--;
                  continue;
                }
              nfqueue_live_record_handoff_before (nm, sample_index,
                                                  worker_thread, buffer_index,
                                                  buffer, meta);
              target_thread = (u16) meta->canonical_worker;
              /* Publish the destination-stage marker before enqueue so the
               * receiving worker cannot observe a stale initial-stage value. */
              meta->handoff_stage =
                NFQUEUE_LIVE_HANDOFF_CANONICAL |
                sample_index;
              if (__atomic_exchange_n (&nm->inject_owner_queue_full, 0,
                                       __ATOMIC_ACQ_REL))
                {
                  enqueued = 0;
                }
              else
                enqueued = vlib_buffer_enqueue_to_thread (
                  vm, node, nm->frame_queue_index, &buffer_index,
                  &target_thread, 1, 1);
              if (enqueued != 1)
                {
                  nfqueue_live_counter_inc (&nm->owner_queue_full);
                  nfqueue_live_publish_terminal (nm, buffer_index, meta);
                }
              else
                {
                  nfqueue_live_counter_inc (&nm->owner_remote_handoffs);
                }
              from++;
              n_left--;
              continue;
            }
          nfqueue_live_counter_inc (&nm->owner_local_obligations);
          meta->handoff_stage =
            NFQUEUE_LIVE_HANDOFF_CANONICAL |
            NFQUEUE_LIVE_HANDOFF_SLOT_MASK;
          (void) nfqueue_live_publish_completion (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }

      if (worker_thread != meta->canonical_worker)
        {
          nfqueue_live_counter_inc (&nm->owner_invalid_state);
          nfqueue_live_publish_terminal (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }
      if (!nfqueue_live_record_handoff_after (nm, worker_thread, buffer_index,
                                              buffer, meta))
        {
          /* A failed identity proof is terminally settled without letting the
           * worker issue a verdict or free the live buffer. */
          nfqueue_live_publish_terminal (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }
      (void) nfqueue_live_publish_completion (nm, buffer_index, meta);
      from++;
      n_left--;
    }
  (void) node;
  return frame->n_vectors;
}

VLIB_REGISTER_NODE (nfqueue_live_owner_node) = {
  .name = "nfqueue-live-owner",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
};

VLIB_NODE_FN (nfqueue_live_ingress_process_node) (vlib_main_t *vm,
                                                   vlib_node_runtime_t *node,
                                                   vlib_frame_t *frame)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 from[VLIB_FRAME_SIZE];
  u16 threads[VLIB_FRAME_SIZE];
  u32 count;
  u32 enqueued;
  (void) frame;

  while (1)
    {
      (void) vlib_process_wait_for_event (vm);
      (void) vlib_process_get_events (vm, 0);
      nfqueue_live_drain_late_return_queue (nm);
      if (!nfqueue_live_teardown_ingress_allowed (nm))
        {
          /* No new obligations may enter the worker frame queue after the
           * quiesce edge.  Existing ingress tokens are completed by the
           * origin lane while the completion channel is still open. */
          nfqueue_live_drain_ingress_queue (nm);
          continue;
        }
      count = 0;
        while (count < VLIB_FRAME_SIZE &&
               nfqueue_live_index_pop (&nm->ingress, &from[count]))
        {
          vlib_buffer_t *buffer = vlib_get_buffer (vm, from[count]);
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          threads[count] = (u16) meta->initial_worker;
          count++;
        }
      if (count == 0)
        continue;
      enqueued = vlib_buffer_enqueue_to_thread (
        vm, node, nm->frame_queue_index, from, threads, count, 1);
      while (enqueued < count)
        {
          vlib_buffer_t *buffer = vlib_get_buffer (vm, from[enqueued]);
          nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
          nfqueue_live_counter_inc (&nm->ingress_queue_full);
          nfqueue_live_publish_terminal (nm, from[enqueued], meta);
          enqueued++;
        }
    }
}

VLIB_REGISTER_NODE (nfqueue_live_ingress_process_node) = {
  .name = "nfqueue-live-ingress-process",
  .type = VLIB_NODE_TYPE_PROCESS,
  .process_log2_n_stack_bytes = 16,
};

static void
nfqueue_live_reserve_release_startup (nfqueue_live_main_t *nm)
{
  for (u32 i = 0; i < nm->lane_count; i++)
    {
      nfqueue_live_lane_t *lane = &nm->lanes[i];
      for (u32 j = 0; j < NFQUEUE_LIVE_MAX_RESERVE_CAPACITY; j++)
        if (lane->reserve_indices[j] != ~0u)
          {
            u32 buffer_index = lane->reserve_indices[j];
            lane->reserve_indices[j] = ~0u;
            vlib_buffer_free_one (nm->vm, buffer_index);
          }
      if (lane->reserve_loss_index_valid)
        {
          u32 buffer_index = lane->reserve_loss_index;
          lane->reserve_loss_index = ~0u;
          lane->reserve_loss_index_valid = 0;
          vlib_buffer_free_one (nm->vm, buffer_index);
        }
      lane->reserve_available = 0;
      lane->reserve_inflight = 0;
    }
}

static clib_error_t *
nfqueue_live_reserve_startup (nfqueue_live_main_t *nm)
{
  if (nm->reserve_capacity == 0)
    {
      nm->reserve_enabled = 0;
      return 0;
    }
  if (nm->reserve_capacity > NFQUEUE_LIVE_MAX_RESERVE_CAPACITY)
    {
      nm->reserve_startup_failures++;
      return clib_error_return (
        0, "reserve capacity %u exceeds POC bound %u", nm->reserve_capacity,
        NFQUEUE_LIVE_MAX_RESERVE_CAPACITY);
    }

  nm->reserve_enabled = 1;
  nm->reserve_buffer_data_size =
    vlib_buffer_get_default_data_size (nm->vm);
  for (u32 i = 0; i < nm->lane_count; i++)
    {
      nfqueue_live_lane_t *lane = &nm->lanes[i];
      lane->reserve_capacity = nm->reserve_capacity;
      lane->reserve_available = nm->reserve_capacity;
      lane->reserve_loss_index = ~0u;
      lane->reserve_loss_index_valid = 0;
      for (u32 j = 0; j < NFQUEUE_LIVE_MAX_RESERVE_CAPACITY; j++)
        lane->reserve_indices[j] = ~0u;
      u32 reserved = vlib_buffer_alloc (
        nm->vm, lane->reserve_indices, nm->reserve_capacity);
      lane->reserve_available = reserved;
      if (reserved != nm->reserve_capacity)
        {
          nm->reserve_startup_failures++;
          nfqueue_live_reserve_release_startup (nm);
          return clib_error_return (
            0, "lane %u reserve startup allocation short: %u/%u", i,
            reserved, nm->reserve_capacity);
        }
      lane->reserve_startup_reservations = reserved;
      nm->reserve_startup_reservations += reserved;
      /* One fixed loss envelope bounds the exhaustion demonstration.  It is
       * not an ordinary reserve entry and is never borrowed by another lane. */
      if (vlib_buffer_alloc (nm->vm, &lane->reserve_loss_index, 1) != 1)
        {
          nm->reserve_startup_failures++;
          nfqueue_live_reserve_release_startup (nm);
          return clib_error_return (0,
                                    "lane %u reserve loss slot allocation", i);
        }
      lane->reserve_loss_index_valid = 1;
    }
  return 0;
}

static void
nfqueue_live_reset_runtime (nfqueue_live_main_t *nm)
{
  __atomic_store_n (&nm->teardown_state, NFQUEUE_LIVE_TEARDOWN_STOPPED,
                    __ATOMIC_RELEASE);
  nm->teardown_event_count = 0;
  nm->teardown_deadline_forced = 0;
  nm->teardown_deadline_reached = 0;
  nm->teardown_drain_attempts = 0;
  nm->teardown_drain_limit = 200;
  nfqueue_live_counter_store (&nm->teardown_transition_rejections, 0);
  nfqueue_live_counter_store (&nm->teardown_drain_accepts, 0);
  nfqueue_live_counter_store (&nm->teardown_deadline_accepts, 0);
  nfqueue_live_counter_store (&nm->teardown_deadline_failed_definite, 0);
  nfqueue_live_counter_store (&nm->teardown_deadline_outcome_unknown, 0);
  nfqueue_live_counter_store (&nm->teardown_identity_unrecoverable, 0);
  nfqueue_live_counter_store (&nm->teardown_obligation_residue, 0);
  nfqueue_live_counter_store (&nm->teardown_late_completion, 0);
  nfqueue_live_counter_store (&nm->teardown_late_settlements, 0);
  nfqueue_live_counter_store (&nm->teardown_completion_frames_at_close, 0);
  __atomic_store_n (&nm->held_buffer_index, ~0u, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->hold_obligation, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->held_obligation, 0, __ATOMIC_RELEASE);
  for (u32 i = 0; i < NFQUEUE_LIVE_TEARDOWN_MAX_TRANSITIONS; i++)
    nm->teardown_events[i] = 0;
  for (u32 i = 0; i < NFQUEUE_LIVE_MAX_LANES; i++)
    {
      nm->lanes[i].nm = nm;
      nm->lanes[i].lane_index = (u8) i;
      nm->lanes[i].netlink_fd = -1;
      nm->lanes[i].netlink_file_index = ~0;
      nm->lanes[i].handle = 0;
      nm->lanes[i].queue = 0;
      nm->lanes[i].enabled = 0;
      nm->lanes[i].datagrams = 0;
      nm->lanes[i].callbacks = 0;
      nm->lanes[i].message_obligations = 0;
      nm->lanes[i].verdict_attempts = 0;
      nm->lanes[i].native_buffer_returns = 0;
      for (u32 j = 0; j < NFQUEUE_LIVE_MAX_RESERVE_CAPACITY; j++)
        nm->lanes[i].reserve_indices[j] = ~0u;
      nm->lanes[i].reserve_capacity = 0;
      nm->lanes[i].reserve_available = 0;
      nm->lanes[i].reserve_inflight = 0;
      nm->lanes[i].reserve_peak_occupancy = 0;
      nm->lanes[i].reserve_peak_inflight = 0;
      nm->lanes[i].reserve_loss_index = ~0u;
      nm->lanes[i].reserve_loss_index_valid = 0;
      nm->lanes[i].reserve_startup_reservations = 0;
      nm->lanes[i].reserve_direct_obligations = 0;
      nm->lanes[i].reserve_direct_completions = 0;
      nm->lanes[i].reserve_direct_native_returns = 0;
      nm->lanes[i].reserve_native_returns = 0;
      nm->lanes[i].reserve_exhaustions = 0;
      nm->lanes[i].reserve_losses = 0;
      nm->lanes[i].reserve_loss_materializations = 0;
      nm->lanes[i].reserve_loss_unmaterialized = 0;
      nm->lanes[i].reserve_loss_native_drops = 0;
      nm->lanes[i].reserve_loss_outcome_failed_definite = 0;
      nm->lanes[i].reserve_loss_outcome_unknown = 0;
      nm->lanes[i].reserve_loss_identity_misses = 0;
      nm->lanes[i].reserve_receive_faults = 0;
      nm->readers[i].nm = nm;
      nm->readers[i].lane_index = (u8) i;
    }
  nm->ingress.head = 0;
  nm->ingress.tail = 0;
  nm->completion.head = 0;
  nm->completion.tail = 0;
  nm->origin_return.head = 0;
  nm->origin_return.tail = 0;
  nm->late_return.head = 0;
  nm->late_return.tail = 0;
  nm->completion_push_lock = 0;
  nm->origin_return_push_lock = 0;
  nm->late_return_push_lock = 0;
  __atomic_store_n (&nm->outstanding, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->completion_debt, 0, __ATOMIC_RELEASE);
  nm->reserve_enabled = 0;
  nm->reserve_capacity = 0;
  nm->reserve_buffer_data_size = 0;
  nm->normal_capacity = NFQUEUE_LIVE_DEFAULT_NORMAL_CAPACITY;
  nm->arm_normal_capacity_exhaustion = 0;
  nm->normal_outstanding = 0;
  nm->reserve_outstanding = 0;
  nm->normal_peak_occupancy = 0;
  nm->reserve_peak_occupancy = 0;
  nm->reserve_peak_inflight = 0;
  nm->normal_capacity_exhaustions = 0;
  nm->reserve_startup_reservations = 0;
  nm->reserve_startup_failures = 0;
  nm->reserve_direct_obligations = 0;
  nm->reserve_direct_completions = 0;
  nm->reserve_direct_native_returns = 0;
  nm->reserve_native_returns = 0;
  nm->reserve_exhaustions = 0;
  nm->reserve_losses = 0;
  nm->reserve_degraded_health = 0;
  nm->reserve_loss_materializations = 0;
  nm->reserve_loss_unmaterialized = 0;
  nm->reserve_loss_native_drops = 0;
  nm->reserve_loss_outcome_failed_definite = 0;
  nm->reserve_loss_outcome_unknown = 0;
  nm->reserve_loss_identity_misses = 0;
  nm->reserve_receive_faults = 0;
  nm->inject_receive_fault = 0;
  nm->reserve_dynamic_growth_attempts = 0;
  nm->reserve_cross_lane_borrows = 0;
  nm->reserve_blocking_waits = 0;
  nm->verdict_identity_mismatches = 0;
  nm->verdict_fault_injections = 0;
  nm->native_verdict_calls = 0;
  nm->verdict_definite_rejections = 0;
  nm->verdict_ambiguous_results = 0;
  nm->last_verdict_generation = 0;
  nm->last_verdict_packet_id = 0;
  nm->last_verdict_origin_lane = 0;
  nm->last_verdict_outcome = NFQUEUE_LIVE_OUTCOME_NONE;
  nm->last_verdict_errno = 0;
  nm->completion_outcome_succeeded = 0;
  nm->completion_outcome_failed_definite = 0;
  nm->completion_outcome_unknown = 0;
  nm->completion_duplicate_attempts = 0;
  nm->completion_stale_generation = 0;
  nm->completion_debt_raised = 0;
  nm->completion_debt_settled = 0;
  nm->retry_attempts = 0;
  nm->worker_reentries = 0;
  nm->policy_re_evaluations = 0;
  nm->replacement_payloads = 0;
  nm->terminal_intent_rewrites = 0;
  nm->policy_verdict_rewrites = 0;
  __atomic_store_n (&nm->completion_credits_held, 0, __ATOMIC_RELEASE);
  nm->completion_credit_capacity = NFQUEUE_LIVE_MAX_OUTSTANDING;
  __atomic_store_n (&nm->owner_local_obligations, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->owner_remote_obligations, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->owner_remote_handoffs, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->owner_queue_full, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->owner_terminal_intents, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->ingress_queue_full, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->completion_credit_acquired, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->completion_credit_released, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->completion_credit_exhausted, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->identity_proof_checks, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->identity_proof_matches, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->identity_proof_failures, 0, __ATOMIC_RELEASE);
  nm->next_obligation_nonce = 0;
  nm->last_buffer_index = ~0;
  nm->last_buffer_base = 0;
  __atomic_store_n (&nm->last_worker_thread, ~0u, __ATOMIC_RELEASE);
  for (u32 i = 0; i < NFQUEUE_LIVE_MAX_HANDOFF_SAMPLES; i++)
    {
      nm->handoff_samples[i].lock = 0;
      __atomic_store_n (&nm->handoff_samples[i].state, 0, __ATOMIC_RELEASE);
      nm->handoff_samples[i].before_valid = 0;
      nm->handoff_samples[i].after_valid = 0;
      nm->handoff_samples[i].before_buffer_index = ~0;
      nm->handoff_samples[i].after_buffer_index = ~0;
    }
}

static void
nfqueue_live_drain_ingress_queue (nfqueue_live_main_t *nm)
{
  u32 buffer_index;
  while (nfqueue_live_index_pop (&nm->ingress, &buffer_index))
    {
      vlib_buffer_t *buffer = vlib_get_buffer (nm->vm, buffer_index);
      nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
      /* Quiesce no longer admits new packets; any item still in the
       * transport ring is settled fail-open before teardown. */
      nfqueue_live_settle_on_origin (nm, buffer_index, meta);
    }
}

static void
nfqueue_live_drain_held_obligation (nfqueue_live_main_t *nm)
{
  u32 buffer_index = __atomic_exchange_n (&nm->held_buffer_index, ~0u,
                                          __ATOMIC_ACQ_REL);
  if (buffer_index == ~0u)
    return;
  __atomic_store_n (&nm->held_obligation, 0, __ATOMIC_RELEASE);
  vlib_buffer_t *buffer = vlib_get_buffer (nm->vm, buffer_index);
  nfqueue_live_meta_t *meta = nfqueue_live_meta (buffer);
  /* A held slot is admitted only for the current generation.  If an injected
   * fault has corrupted that proof, settle_on_origin records the explicit
   * unknown outcome and still performs the origin-only native return. */
  nfqueue_live_settle_on_origin (nm, buffer_index, meta);
}

static clib_error_t *
nfqueue_live_drain_bounded (nfqueue_live_main_t *nm)
{
  u32 attempt;
  u32 limit = nm->teardown_drain_limit == 0 ? 1 : nm->teardown_drain_limit;
  for (attempt = 0; attempt < limit; attempt++)
    {
      nm->teardown_drain_attempts = attempt + 1;
      if (nm->teardown_deadline_forced &&
          nfqueue_live_teardown_state_load (nm) ==
            NFQUEUE_LIVE_TEARDOWN_DRAINING)
        {
          if (!nfqueue_live_record_teardown_transition (
                nm, NFQUEUE_LIVE_TEARDOWN_DRAIN_DEADLINE))
            return clib_error_return (0,
                                      "nfqueue-live deadline transition");
          nm->teardown_deadline_reached = 1;
        }
      nfqueue_live_drain_ingress_queue (nm);
      nfqueue_live_drain_held_obligation (nm);
      nfqueue_live_drain_completion_queue (nm);
      nfqueue_live_drain_late_return_queue (nm);
      if (nfqueue_live_outstanding_load (nm) == 0)
        return 0;
      if (attempt + 1 == limit)
        {
          if (nfqueue_live_teardown_state_load (nm) ==
              NFQUEUE_LIVE_TEARDOWN_DRAINING)
            {
              if (!nfqueue_live_record_teardown_transition (
                    nm, NFQUEUE_LIVE_TEARDOWN_DRAIN_DEADLINE))
                return clib_error_return (0,
                                          "nfqueue-live deadline transition");
              nm->teardown_deadline_reached = 1;
            }
          /* The completion channel is still open in DEADLINE.  Give the
           * origin lane one final chance to classify every ring-backed
           * identity before refusing to close with live debt. */
          nfqueue_live_drain_ingress_queue (nm);
          nfqueue_live_drain_held_obligation (nm);
          nfqueue_live_drain_completion_queue (nm);
          nfqueue_live_drain_late_return_queue (nm);
          if (nfqueue_live_outstanding_load (nm) == 0)
            return 0;
          nfqueue_live_counter_store (&nm->teardown_obligation_residue,
                                      nfqueue_live_outstanding_load (nm));
          return clib_error_return (
            0, "nfqueue-live bounded drain deadline left %u obligations",
            (u32) nfqueue_live_counter_load (&nm->teardown_obligation_residue));
        }
      /* Workers continue to run while the origin lane polls the completion
       * transport. The bound makes teardown failure explicit. */
      usleep (1000);
    }
  return clib_error_return (0, "nfqueue-live bounded drain did not run");
}

static void
nfqueue_live_close_lane (nfqueue_live_lane_t *lane)
{
  if (lane->netlink_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, lane->netlink_file_index);
      lane->netlink_file_index = ~0;
    }
  if (lane->queue)
    {
      nfq_destroy_queue (lane->queue);
      lane->queue = 0;
    }
  if (lane->handle)
    {
      nfq_unbind_pf (lane->handle,
                     lane->family == 6 ? AF_INET6 : AF_INET);
      nfq_close (lane->handle);
      lane->handle = 0;
    }
  lane->netlink_fd = -1;
  lane->enabled = 0;
}

static void
nfqueue_live_close (nfqueue_live_main_t *nm)
{
  if (nm->reserve_enabled)
    {
      nfqueue_live_reserve_release_startup (nm);
      nm->reserve_enabled = 0;
    }
  for (u32 i = 0; i < nm->lane_count; i++)
    nfqueue_live_close_lane (&nm->lanes[i]);
  nm->netlink_file_index = ~0;
  if (nm->completion_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->completion_file_index);
      nm->completion_file_index = ~0;
    }
  nm->queue = 0;
  nm->handle = 0;
  if (nm->completion_fd >= 0)
    {
      close (nm->completion_fd);
      nm->completion_fd = -1;
    }
  nm->netlink_fd = -1;
  nm->enabled = 0;
  nm->quiescing = 0;
}

/* Completion closure is a distinct lifecycle edge.  It is intentionally
 * separated from queue/socket teardown so a bounded drain can continue to
 * consume worker frames and terminal intents until this function is called. */
static void
nfqueue_live_close_completion_channel (nfqueue_live_main_t *nm)
{
  if (nm->completion_file_index != ~0)
    {
      clib_file_del_by_index (&file_main, nm->completion_file_index);
      nm->completion_file_index = ~0;
    }
  if (nm->completion_fd >= 0)
    {
      close (nm->completion_fd);
      nm->completion_fd = -1;
    }
  nfqueue_live_counter_store (&nm->teardown_completion_frames_at_close,
                              nm->completion_frames);
}

/* Called only after completion closure has been recorded and all obligations
 * have reached a terminal outcome.  Reserve buffers, queue handles, and
 * netlink sockets therefore have no live completion dependency. */
static void
nfqueue_live_close_channels (nfqueue_live_main_t *nm)
{
  if (nm->reserve_enabled)
    {
      nfqueue_live_reserve_release_startup (nm);
      nm->reserve_enabled = 0;
    }
  for (u32 i = 0; i < nm->lane_count; i++)
    nfqueue_live_close_lane (&nm->lanes[i]);
  nm->netlink_file_index = ~0;
  nm->queue = 0;
  nm->handle = 0;
  nm->netlink_fd = -1;
  nm->enabled = 0;
}

static clib_error_t *
nfqueue_live_open_lane (nfqueue_live_main_t *nm, u32 lane_index,
                        u16 queue_num, u8 family, u8 hook)
{
  nfqueue_live_lane_t *lane = &nm->lanes[lane_index];
  clib_file_t file = { 0 };
  int af = family == 6 ? AF_INET6 : AF_INET;

  lane->nm = nm;
  lane->lane_index = (u8) lane_index;
  lane->family = family;
  lane->hook = hook;
  lane->queue_num = queue_num;
  lane->origin_lane = lane_index;
  lane->generation = nm->generation;
  lane->handle = nfq_open ();
  if (!lane->handle)
    return clib_error_return_unix (0, "nfq_open");
  if (nfq_bind_pf (lane->handle, af) < 0)
    {
      nfqueue_live_close_lane (lane);
      return clib_error_return_unix (0, "nfq_bind_pf");
    }
  lane->queue = nfq_create_queue (lane->handle, queue_num,
                                  nfqueue_live_packet_cb, lane);
  if (!lane->queue)
    {
      nfqueue_live_close_lane (lane);
      return clib_error_return_unix (0, "nfq_create_queue");
    }
  if (nfq_set_mode (lane->queue, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
      nfqueue_live_close_lane (lane);
      return clib_error_return_unix (0, "nfq_set_mode");
    }
  if (nfq_set_queue_flags (lane->queue, NFQA_CFG_F_UID_GID,
                           NFQA_CFG_F_UID_GID) < 0)
    {
      nfqueue_live_close_lane (lane);
      return clib_error_return (0, "nfq_set_queue_flags uid/gid");
    }
  lane->netlink_fd = nfq_fd (lane->handle);
  if (lane->netlink_fd < 0)
    {
      nfqueue_live_close_lane (lane);
      return clib_error_return_unix (0, "nfq_fd");
    }
  (void) fcntl (lane->netlink_fd, F_SETFL,
                fcntl (lane->netlink_fd, F_GETFL, 0) | O_NONBLOCK);
  nm->readers[lane_index].nm = nm;
  nm->readers[lane_index].lane_index = (u8) lane_index;
  file.read_function = nfqueue_live_netlink_read_ready;
  file.file_descriptor = lane->netlink_fd;
  file.private_data = (uword) &nm->readers[lane_index];
  file.description = format (0, "nfqueue-live-poc lane %u", lane_index);
  lane->netlink_file_index = clib_file_add (&file_main, &file);
  if (lane->netlink_file_index == ~0)
    {
      nfqueue_live_close_lane (lane);
      return clib_error_return (0, "clib_file_add nfqueue lane");
    }
  lane->enabled = 1;
  return 0;
}

static clib_error_t *
nfqueue_live_open_completion (nfqueue_live_main_t *nm)
{
  clib_file_t file = { 0 };
  nm->completion_fd = eventfd (0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (nm->completion_fd < 0)
    return clib_error_return_unix (0, "eventfd");
  file.read_function = nfqueue_live_completion_read_ready;
  file.file_descriptor = nm->completion_fd;
  file.private_data = (uword) nm;
  file.description = format (0, "nfqueue-live-poc completion frame");
  nm->completion_file_index = clib_file_add (&file_main, &file);
  if (nm->completion_file_index == ~0)
    return clib_error_return (0, "clib_file_add completion frame");
  return 0;
}

static clib_error_t *
nfqueue_live_enable (vlib_main_t *vm, u16 queue_num, u8 family,
                    u8 inject_stale, u8 inject_duplicate,
                    u8 inject_completion_overflow, u32 normal_capacity,
                    u32 reserve_capacity,
                    u8 inject_normal_capacity_exhaustion,
                    u8 arm_normal_capacity_exhaustion)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_error_t *error;

  if (nm->enabled)
    return clib_error_return (0, "nfqueue-live-poc already enabled");
  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "start VPP with at least one worker");
  nfqueue_live_reset_runtime (nm);
  nm->vm = vm;
  nm->worker_thread = 1;
  nm->worker_count = clib_min (vlib_num_workers (), 2u);
  nm->first_worker_thread = 1;
  nm->second_worker_thread = 2;
  /* Android brings up worker VLIB mains after plugin init.  Initializing the
   * frame queue from VLIB_INIT_FUNCTION therefore leaves only the main-thread
   * queue in some Android starts; the first worker handoff would index a
   * missing queue and fault.  Verify the current queue can address every
   * worker we will publish to, rebuilding stale/incomplete queue mains before
   * admitting any packet obligation. */
  error = nfqueue_live_ensure_frame_queue (nm, nm->worker_count < 2 ?
                                                 nm->first_worker_thread :
                                                 nm->second_worker_thread);
  if (error)
    return error;
  nm->queue_num = queue_num;
  nm->family = family;
  nm->origin_lane = 0;
  __atomic_store_n (&nm->owner_mode, NFQUEUE_LIVE_OWNER_MODE_MIXED,
                    __ATOMIC_RELEASE);
  __atomic_store_n (&nm->inject_stale, inject_stale, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->inject_duplicate, inject_duplicate, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->inject_completion_overflow, inject_completion_overflow,
                    __ATOMIC_RELEASE);
  nm->lane_count = 1;
  nm->dual_mode = 0;
  nm->normal_capacity = normal_capacity;
  nm->reserve_capacity = reserve_capacity;
  nm->inject_normal_capacity_exhaustion =
    inject_normal_capacity_exhaustion;
  nm->arm_normal_capacity_exhaustion = arm_normal_capacity_exhaustion;
  nm->generation++;
  if (nm->generation == 0)
    nm->generation = 1;
  error = nfqueue_live_open_lane (nm, 0, queue_num, family, 0);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  nm->handle = nm->lanes[0].handle;
  nm->queue = nm->lanes[0].queue;
  nm->netlink_fd = nm->lanes[0].netlink_fd;
  nm->netlink_file_index = nm->lanes[0].netlink_file_index;
  error = nfqueue_live_reserve_startup (nm);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  error = nfqueue_live_open_completion (nm);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  nm->enabled = 1;
  if (!nfqueue_live_record_teardown_transition (
        nm, NFQUEUE_LIVE_TEARDOWN_ENABLE))
    {
      nm->enabled = 0;
      nfqueue_live_close (nm);
      return clib_error_return (0, "nfqueue-live enable transition");
    }
  return 0;
}

static clib_error_t *
nfqueue_live_enable_dual (vlib_main_t *vm, u16 queue_base,
                          u8 inject_stale, u8 inject_duplicate,
                          u8 inject_completion_overflow,
                          u8 inject_uid_unknown, u8 require_two_workers,
                          u32 normal_capacity, u32 reserve_capacity,
                          u8 inject_normal_capacity_exhaustion,
                          u8 arm_normal_capacity_exhaustion)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_error_t *error;
  static const u8 families[NFQUEUE_LIVE_MAX_LANES] = { 4, 4, 6, 6 };
  static const u8 hooks[NFQUEUE_LIVE_MAX_LANES] = {
    NF_INET_LOCAL_OUT, NF_INET_LOCAL_IN, NF_INET_LOCAL_OUT,
    NF_INET_LOCAL_IN,
  };

  if (nm->enabled)
    return clib_error_return (0, "nfqueue-live-poc already enabled");
  if (require_two_workers && vlib_num_workers () < 2)
    return clib_error_return (0, "start VPP with at least two workers");
  nfqueue_live_reset_runtime (nm);
  nm->vm = vm;
  nm->worker_thread = 1;
  nm->worker_count = clib_min (vlib_num_workers (), 2u);
  nm->first_worker_thread = 1;
  nm->second_worker_thread = 2;
  /* See the single-lane enable path: defer queue-main construction until the
   * worker layout is available on Android, and reject an incomplete queue
   * rather than entering the remote-owner path with a null per-worker slot. */
  error = nfqueue_live_ensure_frame_queue (nm, require_two_workers ?
                                                 nm->second_worker_thread :
                                                 nm->first_worker_thread);
  if (error)
    return error;
  nm->queue_num = queue_base;
  nm->family = 0;
  nm->origin_lane = 0;
  __atomic_store_n (&nm->owner_mode, NFQUEUE_LIVE_OWNER_MODE_MIXED,
                    __ATOMIC_RELEASE);
  __atomic_store_n (&nm->inject_stale, inject_stale, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->inject_duplicate, inject_duplicate, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->inject_completion_overflow,
                    inject_completion_overflow,
                    __ATOMIC_RELEASE);
  nm->inject_uid_unknown = inject_uid_unknown;
  nm->lane_count = NFQUEUE_LIVE_MAX_LANES;
  nm->dual_mode = 1;
  nm->normal_capacity = normal_capacity;
  nm->reserve_capacity = reserve_capacity;
  nm->inject_normal_capacity_exhaustion =
    inject_normal_capacity_exhaustion;
  nm->arm_normal_capacity_exhaustion = arm_normal_capacity_exhaustion;
  nm->generation++;
  if (nm->generation == 0)
    nm->generation = 1;
  for (u32 i = 0; i < NFQUEUE_LIVE_MAX_LANES; i++)
    {
      error = nfqueue_live_open_lane (nm, i, (u16) (queue_base + i),
                                      families[i], hooks[i]);
      if (error)
        {
          nfqueue_live_close (nm);
          return error;
      }
    }
  error = nfqueue_live_reserve_startup (nm);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  error = nfqueue_live_open_completion (nm);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  nm->enabled = 1;
  if (!nfqueue_live_record_teardown_transition (
        nm, NFQUEUE_LIVE_TEARDOWN_ENABLE))
    {
      nm->enabled = 0;
      nfqueue_live_close (nm);
      return clib_error_return (0, "nfqueue-live enable transition");
    }
  return 0;
}

static clib_error_t *
nfqueue_live_disable (void)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_error_t *error;
  nfqueue_live_teardown_state_t state =
    nfqueue_live_teardown_state_load (nm);
  if (!nm->enabled &&
      (state == NFQUEUE_LIVE_TEARDOWN_STOPPED ||
       state == NFQUEUE_LIVE_TEARDOWN_COMPLETE))
    return 0;

  if (state == NFQUEUE_LIVE_TEARDOWN_ACTIVE)
    {
      if (!nfqueue_live_record_teardown_transition (
            nm, NFQUEUE_LIVE_TEARDOWN_QUIESCE))
        return clib_error_return (0, "nfqueue-live quiesce transition");
      nm->quiescing = 1;
      for (u32 i = 0; i < nm->lane_count; i++)
        if (nm->lanes[i].netlink_file_index != ~0)
          {
            /* Removing readiness is the quiesce edge, not socket teardown.
             * clib_file_del closes descriptors unless the registration is
             * explicitly made non-owning; keep each NFQUEUE handle alive so
             * the bounded drain can still issue identity-completable ACCEPTs.
             */
            clib_file_t *file = clib_file_get (
              &file_main, nm->lanes[i].netlink_file_index);
            if (file)
              file->dont_close = 1;
            clib_file_del_by_index (&file_main,
                                    nm->lanes[i].netlink_file_index);
            nm->lanes[i].netlink_file_index = ~0;
          }
      nm->netlink_file_index = ~0;
      state = NFQUEUE_LIVE_TEARDOWN_QUIESCING;
    }
  if (state == NFQUEUE_LIVE_TEARDOWN_QUIESCING)
    {
      if (!nfqueue_live_record_teardown_transition (
            nm, NFQUEUE_LIVE_TEARDOWN_DRAIN))
        return clib_error_return (0, "nfqueue-live drain transition");
    }
  state = nfqueue_live_teardown_state_load (nm);
  if (state != NFQUEUE_LIVE_TEARDOWN_DRAINING &&
      state != NFQUEUE_LIVE_TEARDOWN_DEADLINE)
    return clib_error_return (0, "nfqueue-live invalid teardown state %s",
                              nfqueue_live_teardown_state_name (state));
  error = nfqueue_live_drain_bounded (nm);
  if (error)
    return error;

  state = nfqueue_live_teardown_state_load (nm);
  if (state != NFQUEUE_LIVE_TEARDOWN_DRAINING &&
      state != NFQUEUE_LIVE_TEARDOWN_DEADLINE)
    return clib_error_return (0, "nfqueue-live drain closed unexpectedly");
  if (!nfqueue_live_record_teardown_transition (
        nm, NFQUEUE_LIVE_TEARDOWN_CLOSE_COMPLETION))
    return clib_error_return (0, "nfqueue-live completion close transition");
  nfqueue_live_close_completion_channel (nm);
  if (!nfqueue_live_record_teardown_transition (
        nm, NFQUEUE_LIVE_TEARDOWN_CLOSE_CHANNELS))
    return clib_error_return (0, "nfqueue-live channel close transition");
  nfqueue_live_close_channels (nm);
  if (!nfqueue_live_record_teardown_transition (
        nm, NFQUEUE_LIVE_TEARDOWN_FINISH))
    return clib_error_return (0, "nfqueue-live finish transition");
  nm->quiescing = 0;
  return 0;
}

static clib_error_t *
nfqueue_live_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                vlib_cli_command_t *cmd)
{
  u32 queue_num = 42;
  u8 family = 4;
  u8 stale = 0;
  u8 duplicate = 0;
  u8 completion_overflow = 0;
  u8 missing_packet_id = 0;
  u8 missing_generation = 0;
  u8 uid_unknown = 0;
  u8 owner_mode = NFQUEUE_LIVE_OWNER_MODE_MIXED;
  u8 owner_queue_full = 0;
  u8 credit_exhaustion = 0;
  u8 verdict_failed_definite = 0;
  u8 verdict_outcome_unknown = 0;
  u8 inject_receive_fault = 0;
  u8 hold_obligation = 0;
  u8 inject_normal_capacity_exhaustion = 0;
  u8 arm_normal_capacity_exhaustion = 0;
  u32 normal_capacity = NFQUEUE_LIVE_DEFAULT_NORMAL_CAPACITY;
  u32 reserve_capacity = 0;
  clib_error_t *error;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue %u", &queue_num))
        ;
      else if (unformat (input, "family ip4"))
        family = 4;
      else if (unformat (input, "family ip6") ||
               unformat (input, "family ipv6"))
        family = 6;
      else if (unformat (input, "inject-stale"))
        stale = 1;
      else if (unformat (input, "inject-duplicate"))
        duplicate = 1;
      else if (unformat (input, "inject-completion-overflow"))
        completion_overflow = 1;
      else if (unformat (input, "inject-missing-packet-id"))
        missing_packet_id = 1;
      else if (unformat (input, "inject-missing-generation"))
        missing_generation = 1;
      else if (unformat (input, "inject-uid-unknown"))
        uid_unknown = 1;
      else if (unformat (input, "owner-local"))
        owner_mode = NFQUEUE_LIVE_OWNER_MODE_LOCAL;
      else if (unformat (input, "owner-remote"))
        owner_mode = NFQUEUE_LIVE_OWNER_MODE_REMOTE;
      else if (unformat (input, "owner-mixed"))
        owner_mode = NFQUEUE_LIVE_OWNER_MODE_MIXED;
      else if (unformat (input, "inject-owner-queue-full"))
        owner_queue_full = 1;
      else if (unformat (input, "inject-completion-credit-exhaustion"))
        credit_exhaustion = 1;
      else if (unformat (input, "inject-verdict-failed-definite"))
        verdict_failed_definite = 1;
      else if (unformat (input, "inject-verdict-outcome-unknown"))
        verdict_outcome_unknown = 1;
      else if (unformat (input, "inject-receive-fault"))
        inject_receive_fault = 1;
      else if (unformat (input, "hold-obligation"))
        hold_obligation = 1;
      else if (unformat (input, "normal-capacity %u", &normal_capacity))
        ;
      else if (unformat (input, "reserve-capacity %u", &reserve_capacity))
        ;
      else if (unformat (input, "inject-normal-capacity-exhaustion"))
        inject_normal_capacity_exhaustion = 1;
      else if (unformat (input,
                         "arm-normal-capacity-exhaustion-after-fill"))
        arm_normal_capacity_exhaustion = 1;
      else
        return clib_error_return (0, "unknown nfqueue-live-poc option");
    }
  error = nfqueue_live_enable (vm, (u16) queue_num, family, stale, duplicate,
                               completion_overflow, normal_capacity,
                               reserve_capacity,
                               inject_normal_capacity_exhaustion,
                               arm_normal_capacity_exhaustion);
  if (!error)
    {
      nfqueue_live_main.inject_missing_packet_id = missing_packet_id;
      nfqueue_live_main.inject_missing_generation = missing_generation;
      nfqueue_live_main.inject_uid_unknown = uid_unknown;
      __atomic_store_n (&nfqueue_live_main.owner_mode, owner_mode,
                        __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_owner_queue_full,
                        owner_queue_full, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_completion_credit_exhaustion,
                        credit_exhaustion, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_verdict_failed_definite,
                        verdict_failed_definite, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_verdict_outcome_unknown,
                        verdict_outcome_unknown, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_receive_fault,
                        inject_receive_fault, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.hold_obligation, hold_obligation,
                        __ATOMIC_RELEASE);
    }
  return error;
}

VLIB_CLI_COMMAND (nfqueue_live_enable_command, static) = {
  .path = "nfqueue-live-poc enable",
  .short_help = "nfqueue-live-poc enable queue <n> [family ip4|ip6] "
                "[inject-stale] [inject-duplicate] "
                "[inject-completion-overflow] [inject-missing-packet-id] "
                "[inject-missing-generation] [inject-uid-unknown] "
                "[owner-local|owner-remote|owner-mixed] "
                "[inject-owner-queue-full] [inject-completion-credit-exhaustion] "
                "[inject-verdict-failed-definite|inject-verdict-outcome-unknown] "
                "[inject-receive-fault] [hold-obligation] "
                "[normal-capacity <n>] [reserve-capacity <n>] "
                "[inject-normal-capacity-exhaustion] "
                "[arm-normal-capacity-exhaustion-after-fill]",
  .function = nfqueue_live_enable_command_fn,
};

static clib_error_t *
nfqueue_live_enable_dual_command_fn (vlib_main_t *vm,
                                     unformat_input_t *input,
                                     vlib_cli_command_t *cmd)
{
  u32 queue_base = 42;
  u8 stale = 0;
  u8 duplicate = 0;
  u8 completion_overflow = 0;
  u8 missing_packet_id = 0;
  u8 missing_generation = 0;
  u8 uid_unknown = 0;
  u8 owner_mode = NFQUEUE_LIVE_OWNER_MODE_MIXED;
  u8 owner_queue_full = 0;
  u8 credit_exhaustion = 0;
  u8 verdict_failed_definite = 0;
  u8 verdict_outcome_unknown = 0;
  u8 inject_receive_fault = 0;
  u8 hold_obligation = 0;
  u8 require_two_workers = 0;
  u8 inject_normal_capacity_exhaustion = 0;
  u8 arm_normal_capacity_exhaustion = 0;
  u32 normal_capacity = NFQUEUE_LIVE_DEFAULT_NORMAL_CAPACITY;
  u32 reserve_capacity = 0;
  clib_error_t *error;
  (void) cmd;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "queue-base %u", &queue_base) ||
          unformat (input, "queue %u", &queue_base))
        ;
      else if (unformat (input, "inject-stale"))
        stale = 1;
      else if (unformat (input, "inject-duplicate"))
        duplicate = 1;
      else if (unformat (input, "inject-completion-overflow"))
        completion_overflow = 1;
      else if (unformat (input, "inject-missing-packet-id"))
        missing_packet_id = 1;
      else if (unformat (input, "inject-missing-generation"))
        missing_generation = 1;
      else if (unformat (input, "inject-uid-unknown"))
        uid_unknown = 1;
      else if (unformat (input, "owner-local"))
        owner_mode = NFQUEUE_LIVE_OWNER_MODE_LOCAL;
      else if (unformat (input, "owner-remote"))
        owner_mode = NFQUEUE_LIVE_OWNER_MODE_REMOTE;
      else if (unformat (input, "owner-mixed"))
        owner_mode = NFQUEUE_LIVE_OWNER_MODE_MIXED;
      else if (unformat (input, "inject-owner-queue-full"))
        owner_queue_full = 1;
      else if (unformat (input, "inject-completion-credit-exhaustion"))
        credit_exhaustion = 1;
      else if (unformat (input, "inject-verdict-failed-definite"))
        verdict_failed_definite = 1;
      else if (unformat (input, "inject-verdict-outcome-unknown"))
        verdict_outcome_unknown = 1;
      else if (unformat (input, "inject-receive-fault"))
        inject_receive_fault = 1;
      else if (unformat (input, "hold-obligation"))
        hold_obligation = 1;
      else if (unformat (input, "two-workers"))
        require_two_workers = 1;
      else if (unformat (input, "normal-capacity %u", &normal_capacity))
        ;
      else if (unformat (input, "reserve-capacity %u", &reserve_capacity))
        ;
      else if (unformat (input, "inject-normal-capacity-exhaustion"))
        inject_normal_capacity_exhaustion = 1;
      else if (unformat (input,
                         "arm-normal-capacity-exhaustion-after-fill"))
        arm_normal_capacity_exhaustion = 1;
      else
        return clib_error_return (0, "unknown nfqueue-live-poc dual option");
    }
  error = nfqueue_live_enable_dual (vm, (u16) queue_base, stale, duplicate,
                                    completion_overflow, uid_unknown,
                                    require_two_workers, normal_capacity,
                                    reserve_capacity,
                                    inject_normal_capacity_exhaustion,
                                    arm_normal_capacity_exhaustion);
  if (!error)
    {
      nfqueue_live_main.inject_missing_packet_id = missing_packet_id;
      nfqueue_live_main.inject_missing_generation = missing_generation;
      nfqueue_live_main.inject_uid_unknown = uid_unknown;
      __atomic_store_n (&nfqueue_live_main.owner_mode, owner_mode,
                        __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_owner_queue_full,
                        owner_queue_full, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_completion_credit_exhaustion,
                        credit_exhaustion, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_verdict_failed_definite,
                        verdict_failed_definite, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_verdict_outcome_unknown,
                        verdict_outcome_unknown, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.inject_receive_fault,
                        inject_receive_fault, __ATOMIC_RELEASE);
      __atomic_store_n (&nfqueue_live_main.hold_obligation, hold_obligation,
                        __ATOMIC_RELEASE);
    }
  return error;
}

VLIB_CLI_COMMAND (nfqueue_live_enable_dual_command, static) = {
  .path = "nfqueue-live-poc enable-dual",
  .short_help = "nfqueue-live-poc enable-dual queue-base <n> "
                "[inject-stale] [inject-duplicate] "
                "[inject-completion-overflow] [inject-missing-packet-id] "
                "[inject-missing-generation] [inject-uid-unknown] "
                "[owner-local|owner-remote|owner-mixed] "
                "[inject-owner-queue-full] [inject-completion-credit-exhaustion] "
                "[inject-verdict-failed-definite|inject-verdict-outcome-unknown] "
                "[inject-receive-fault] [hold-obligation] "
                "[two-workers] [normal-capacity <n>] [reserve-capacity <n>] "
                "[inject-normal-capacity-exhaustion] "
                "[arm-normal-capacity-exhaustion-after-fill]",
  .function = nfqueue_live_enable_dual_command_fn,
};

static clib_error_t *
nfqueue_live_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  u8 force_deadline = 0;
  (void) vm;
  (void) cmd;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "deadline"))
        force_deadline = 1;
      else
        return clib_error_return (0, "nfqueue-live disable: unknown option");
    }
  nfqueue_live_main.teardown_deadline_forced = force_deadline;
  return nfqueue_live_disable ();
}

VLIB_CLI_COMMAND (nfqueue_live_disable_command, static) = {
  .path = "nfqueue-live-poc disable",
  .short_help = "nfqueue-live-poc disable [deadline]",
  .function = nfqueue_live_disable_command_fn,
};

static clib_error_t *
nfqueue_live_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  u8 owner_mode_value = __atomic_load_n (&nm->owner_mode, __ATOMIC_ACQUIRE);
  const char *owner_mode = owner_mode_value == NFQUEUE_LIVE_OWNER_MODE_LOCAL ?
                             "local" :
                               owner_mode_value == NFQUEUE_LIVE_OWNER_MODE_REMOTE ?
                                 "remote" : "mixed";
  const char *last_direction =
    nm->last_device_direction == NFQUEUE_LIVE_DIRECTION_OUTPUT ? "OUTPUT" :
      "INPUT";
  u32 enabled_lanes = 0;
  u32 open_queues = 0;
  u32 open_handles = 0;
  int resource_netlink_fd = nm->netlink_fd;
  u64 completion_credit_acquired =
    nfqueue_live_counter_load (&nm->completion_credit_acquired);
  u64 completion_credit_released =
    nfqueue_live_counter_load (&nm->completion_credit_released);
  u64 completion_credit_residue =
    completion_credit_acquired >= completion_credit_released ?
      completion_credit_acquired - completion_credit_released : 0;
  u64 completion_outcome_succeeded =
    nfqueue_live_counter_load (&nm->completion_outcome_succeeded);
  u64 completion_outcome_failed_definite =
    nfqueue_live_counter_load (&nm->completion_outcome_failed_definite);
  u64 completion_outcome_unknown =
    nfqueue_live_counter_load (&nm->completion_outcome_unknown);
  u64 completion_duplicate_attempts =
    nfqueue_live_counter_load (&nm->completion_duplicate_attempts);
  u64 completion_stale_generation =
    nfqueue_live_counter_load (&nm->completion_stale_generation);
  u64 completion_debt_raised =
    nfqueue_live_counter_load (&nm->completion_debt_raised);
  u64 completion_debt_settled =
    nfqueue_live_counter_load (&nm->completion_debt_settled);
  for (u32 i = 0; i < nm->lane_count; i++)
    {
      enabled_lanes += nm->lanes[i].enabled != 0;
      open_queues += nm->lanes[i].queue != 0;
      open_handles += nm->lanes[i].handle != 0;
      if (resource_netlink_fd < 0 && nm->lanes[i].netlink_fd >= 0)
        resource_netlink_fd = nm->lanes[i].netlink_fd;
    }
  if (open_queues == 0 && nm->queue != 0)
    open_queues = 1;
  if (open_handles == 0 && nm->handle != 0)
    open_handles = 1;
  (void) input;
  (void) cmd;
  vlib_cli_output (vm, "enabled %u family ip%u queue %u generation %llu",
                   nm->enabled, nm->family, nm->queue_num,
                   (unsigned long long) nm->generation);
  vlib_cli_output (
    vm,
    "teardown-state %s teardown-event-count %u teardown-drain-attempts %u teardown-drain-limit %u teardown-deadline-forced %u teardown-deadline-reached %u",
    nfqueue_live_teardown_state_name (nfqueue_live_teardown_state_load (nm)),
    nm->teardown_event_count, nm->teardown_drain_attempts,
    nm->teardown_drain_limit, nm->teardown_deadline_forced,
    nm->teardown_deadline_reached);
  vlib_cli_output (
    vm,
    "teardown-transition-rejections %llu teardown-drain-accepts %llu teardown-deadline-accepts %llu teardown-deadline-failed-definite %llu teardown-deadline-unknown %llu teardown-identity-unrecoverable %llu teardown-obligation-residue %llu teardown-late-completion %llu teardown-late-settlements %llu",
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_transition_rejections),
    (unsigned long long) nfqueue_live_counter_load (&nm->teardown_drain_accepts),
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_deadline_accepts),
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_deadline_failed_definite),
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_deadline_outcome_unknown),
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_identity_unrecoverable),
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_obligation_residue),
    (unsigned long long) nfqueue_live_counter_load (&nm->teardown_late_completion),
    (unsigned long long) nfqueue_live_counter_load (&nm->teardown_late_settlements));
  vlib_cli_output (
    vm,
    "teardown-rings ingress-depth %u completion-depth %u origin-return-depth %u late-return-depth %u completion-channel-open %u completion-frames-at-close %llu",
    (nm->ingress.tail + NFQUEUE_LIVE_RING_CAPACITY - nm->ingress.head) %
      NFQUEUE_LIVE_RING_CAPACITY,
    (nm->completion.tail + NFQUEUE_LIVE_RING_CAPACITY - nm->completion.head) %
      NFQUEUE_LIVE_RING_CAPACITY,
    (nm->origin_return.tail + NFQUEUE_LIVE_RING_CAPACITY -
     nm->origin_return.head) % NFQUEUE_LIVE_RING_CAPACITY,
    (nm->late_return.tail + NFQUEUE_LIVE_RING_CAPACITY -
     nm->late_return.head) % NFQUEUE_LIVE_RING_CAPACITY,
    nfqueue_live_teardown_completion_open (nm),
    (unsigned long long) nfqueue_live_counter_load (
      &nm->teardown_completion_frames_at_close));
  vlib_cli_output (
    vm,
    "teardown-resources netlink-fd %d completion-fd %d queue-open %u handle-open %u enabled-lanes %u",
    resource_netlink_fd, nm->completion_fd, open_queues, open_handles,
    enabled_lanes);
  vlib_cli_output (vm, "held-obligation %u held-buffer-index %u",
                   __atomic_load_n (&nm->held_obligation, __ATOMIC_ACQUIRE),
                   __atomic_load_n (&nm->held_buffer_index, __ATOMIC_ACQUIRE));
  for (u32 i = 0; i < nm->teardown_event_count; i++)
    vlib_cli_output (vm, "teardown-transition %u %s", i,
                     nfqueue_live_teardown_event_name (
                       nm->teardown_events[i]));
  vlib_cli_output (vm, "buffer-data-size %u worker-thread %u origin-lane %u workers %u worker-ids %u,%u owner-mode %s",
                   data_size, nfqueue_live_counter32_load (&nm->last_worker_thread),
                   nm->origin_lane,
                   nm->worker_count, nm->first_worker_thread,
                   nm->second_worker_thread, owner_mode);
  vlib_cli_output (vm, "datagrams %llu callbacks %llu multiple-message-datagrams %llu rejects %llu",
                   (unsigned long long) nm->datagrams,
                   (unsigned long long) nm->callbacks,
                   (unsigned long long) nm->multiple_message_datagrams,
                   (unsigned long long) nm->multiple_message_rejects);
  vlib_cli_output (vm, "envelope-messages %llu valid-messages %llu recoverable-messages %llu rejected-messages %llu",
                   (unsigned long long) nm->envelope_message_count,
                   (unsigned long long) nm->envelope_valid_message_count,
                   (unsigned long long) nm->envelope_recoverable_message_count,
                   (unsigned long long) nm->envelope_rejected_messages);
  vlib_cli_output (vm, "envelope-recovery-attempts %llu recoveries %llu",
                   (unsigned long long) nm->envelope_recovery_attempts,
                   (unsigned long long) nm->envelope_recoveries);
  vlib_cli_output (vm, "envelope-netlink-header-bytes %llu attribute-bytes %llu attribute-aligned-bytes %llu",
                   (unsigned long long) nm->envelope_netlink_header_bytes,
                   (unsigned long long) nm->envelope_attribute_bytes,
                   (unsigned long long) nm->envelope_attribute_aligned_bytes);
  vlib_cli_output (vm, "envelope-payload-offset %llu usable-l3-envelope %llu parsed-bytes %llu",
                   (unsigned long long) nm->envelope_payload_offset,
                   (unsigned long long) nm->envelope_usable_l3_bytes,
                   (unsigned long long) nm->envelope_parsed_bytes);
  vlib_cli_output (vm, "envelope-boundary-passes %llu exact-boundary-passes %llu oversize-rejects %llu malformed-rejects %llu",
                   (unsigned long long) nm->envelope_boundary_passes,
                   (unsigned long long) nm->envelope_exact_boundary_passes,
                   (unsigned long long) nm->envelope_oversize_rejects,
                   (unsigned long long) nm->envelope_malformed_rejects);
  vlib_cli_output (vm, "live-buffer-receives %llu inline-metadata-writes %llu payload-pointer-projections %llu",
                   (unsigned long long) nm->live_buffer_receives,
                   (unsigned long long) nm->inline_metadata_writes,
                   (unsigned long long) nm->payload_pointer_projections);
  vlib_cli_output (vm, "normal-capacity %u normal-outstanding %u normal-peak-occupancy %u normal-capacity-exhaustions %llu",
                   nm->normal_capacity, nm->normal_outstanding,
                   nm->normal_peak_occupancy,
                   (unsigned long long) nm->normal_capacity_exhaustions);
  vlib_cli_output (vm, "normal-capacity-arm-after-fill %u",
                   nm->arm_normal_capacity_exhaustion);
  vlib_cli_output (vm, "reserve-enabled %u reserve-capacity %u reserve-envelope-bytes %u reserve-startup-reservations %llu reserve-startup-failures %llu reserve-outstanding %u reserve-peak-occupancy %u reserve-inflight-peak %u",
                   nm->reserve_enabled, nm->reserve_capacity,
                   nm->reserve_buffer_data_size,
                   (unsigned long long) nm->reserve_startup_reservations,
                   (unsigned long long) nm->reserve_startup_failures,
                   nm->reserve_outstanding, nm->reserve_peak_occupancy,
                   nm->reserve_peak_inflight);
  vlib_cli_output (vm, "reserve-direct-obligations %llu reserve-direct-completions %llu reserve-direct-native-returns %llu reserve-native-returns %llu reserve-exhaustions %llu reserve-losses %llu reserve-degraded-health %llu",
                   (unsigned long long) nm->reserve_direct_obligations,
                   (unsigned long long) nm->reserve_direct_completions,
                   (unsigned long long) nm->reserve_direct_native_returns,
                   (unsigned long long) nm->reserve_native_returns,
                   (unsigned long long) nm->reserve_exhaustions,
                   (unsigned long long) nm->reserve_losses,
                   (unsigned long long) nm->reserve_degraded_health);
  vlib_cli_output (vm, "reserve-loss-materializations %llu reserve-loss-unmaterialized %llu reserve-loss-native-drops %llu reserve-loss-failed-definite %llu reserve-loss-unknown %llu reserve-loss-identity-misses %llu reserve-receive-faults %llu dynamic-reserve-growth %llu cross-lane-reserve-borrows %llu reserve-blocking-waits %llu",
                   (unsigned long long) nm->reserve_loss_materializations,
                   (unsigned long long) nm->reserve_loss_unmaterialized,
                   (unsigned long long) nm->reserve_loss_native_drops,
                   (unsigned long long) nm->reserve_loss_outcome_failed_definite,
                   (unsigned long long) nm->reserve_loss_outcome_unknown,
                   (unsigned long long) nm->reserve_loss_identity_misses,
                   (unsigned long long) nm->reserve_receive_faults,
                   (unsigned long long) nm->reserve_dynamic_growth_attempts,
                   (unsigned long long) nm->reserve_cross_lane_borrows,
                   (unsigned long long) nm->reserve_blocking_waits);
  vlib_cli_output (vm, "reserve-receive-fault-inject %u",
                   __atomic_load_n (&nm->inject_receive_fault,
                                    __ATOMIC_ACQUIRE));
  vlib_cli_output (vm, "reserve-parser-attempts 0 reserve-flow-enters 0 reserve-policy-verdicts 0 reserve-delivery-success-claims 0 reserve-copy-count %u",
                   (unsigned int) NFQUEUE_LIVE_PACKET_COPY_PATHS);
  vlib_cli_output (vm, "last-buffer-index %u last-buffer-base 0x%llx datagram-length %u",
                   nm->last_buffer_index, (unsigned long long) nm->last_buffer_base,
                   nm->last_datagram_length);
  vlib_cli_output (vm, "nfqa-payload-offset %u nfqa-payload-length %u original-length %u captured-length %u",
                   nm->last_payload_offset, nm->last_payload_length,
                   nm->last_original_length, nm->last_captured_length);
  vlib_cli_output (vm, "packet-id %u queue-generation %llu origin-lane %u hook %u device-packet-direction %s",
                   nm->last_packet_id,
                   (unsigned long long) nm->last_queue_generation,
                   nm->last_origin_lane, nm->last_hook, last_direction);
  vlib_cli_output (vm, "hook %u ip-version %u uid-known %u uid %u",
                   nm->last_hook, nm->last_ip_version,
                   nm->last_uid_known, nm->last_uid);
  vlib_cli_output (vm, "uid-known-packets %llu uid-unknown-fast-path %llu uid-waits %llu uid-cache-reads %llu uid-replays %llu",
                   (unsigned long long) nm->uid_known_packets,
                   (unsigned long long) nm->uid_unknown_fast_path,
                   (unsigned long long) nm->uid_waits,
                   (unsigned long long) nm->uid_cache_reads,
                   (unsigned long long) nm->uid_replays);
  vlib_cli_output (vm, "ingress-identity-missing %llu missing-packet-id %llu missing-queue-generation %llu",
                   (unsigned long long) nm->missing_ingress_identity,
                   (unsigned long long) nm->missing_packet_id,
                   (unsigned long long) nm->missing_queue_generation);
  vlib_cli_output (vm, "payload-span-checks %llu payload-span-failures %llu packet-copies %llu",
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->payload_span_checks),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->payload_span_failures),
                   (unsigned long long) NFQUEUE_LIVE_PACKET_COPY_PATHS);
  vlib_cli_output (vm, "scratch-rx-buffers %llu full-packet-memcpy %llu per-packet-heap-objects %llu",
                   (unsigned long long) NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS,
                   (unsigned long long) NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS,
                   (unsigned long long) NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS);
  vlib_cli_output (vm, "handoffs %llu owner-mismatches %llu owner-invalid-state %llu",
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->handoff_count),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_mismatch_count),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_invalid_state));
  vlib_cli_output (vm, "owner-local-obligations %llu owner-remote-obligations %llu owner-remote-handoffs %llu owner-queue-full %llu owner-terminal-intents %llu ingress-queue-full %llu",
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_local_obligations),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_remote_obligations),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_remote_handoffs),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_queue_full),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->owner_terminal_intents),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->ingress_queue_full));
  vlib_cli_output (vm, "completion-credit-capacity %u completion-credit-acquired %llu completion-credit-released %llu completion-credit-exhausted %llu completion-credits-held %u residue-completion-credits %llu",
                   nm->completion_credit_capacity,
                   (unsigned long long) completion_credit_acquired,
                   (unsigned long long) completion_credit_released,
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->completion_credit_exhausted),
                   __atomic_load_n (&nm->completion_credits_held, __ATOMIC_ACQUIRE),
                   (unsigned long long) completion_credit_residue);
  vlib_cli_output (vm, "identity-proof-checks %llu identity-proof-matches %llu identity-proof-failures %llu",
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->identity_proof_checks),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->identity_proof_matches),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->identity_proof_failures));
  for (u32 i = 0; i < NFQUEUE_LIVE_MAX_HANDOFF_SAMPLES; i++)
    {
      nfqueue_live_handoff_sample_t sample;
      nfqueue_live_handoff_sample_snapshot (nm, i, &sample);
      if (!sample.before_valid && !sample.after_valid)
        continue;
      vlib_cli_output (vm, "handoff-before slot %u valid %u owner-worker %u buffer-index %u buffer-base 0x%llx packet-id %u generation %llu origin-lane %u payload-offset %u payload-length %u obligation-nonce %u stage %u",
                       i, sample.before_valid, sample.before_worker,
                       sample.before_buffer_index,
                       (unsigned long long) sample.before_buffer_base,
                       sample.before_packet_id,
                       (unsigned long long) sample.before_generation,
                       sample.before_origin_lane,
                       sample.before_payload_offset,
                       sample.before_payload_length,
                       sample.before_obligation_nonce, sample.before_stage);
      vlib_cli_output (vm, "handoff-after slot %u valid %u owner-worker %u buffer-index %u buffer-base 0x%llx packet-id %u generation %llu origin-lane %u payload-offset %u payload-length %u obligation-nonce %u stage %u",
                       i, sample.after_valid, sample.after_worker,
                       sample.after_buffer_index,
                       (unsigned long long) sample.after_buffer_base,
                       sample.after_packet_id,
                       (unsigned long long) sample.after_generation,
                       sample.after_origin_lane,
                       sample.after_payload_offset,
                       sample.after_payload_length,
                       sample.after_obligation_nonce, sample.after_stage);
    }
  vlib_cli_output (vm, "completion-frames %llu stale %llu duplicate %llu ring-overflow %llu origin-return-overflow %llu",
                   (unsigned long long) nm->completion_frames,
                   (unsigned long long) nm->completion_stale,
                   (unsigned long long) nm->completion_duplicate,
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->completion_ring_overflow),
                   (unsigned long long) nfqueue_live_counter_load (
                     &nm->origin_return_overflow));
  vlib_cli_output (vm, "cap-len-missing %llu truncated-datagrams %llu fail-open-settlements %llu identity-unrecoverable %llu",
                   (unsigned long long) nm->cap_len_missing,
                   (unsigned long long) nm->truncated_datagrams,
                   (unsigned long long) nm->fail_open_settlements,
                   (unsigned long long) nm->identity_unrecoverable);
  vlib_cli_output (vm, "verdict-attempts %llu send-success %llu send-failures %llu outcome-unknown %llu",
                   (unsigned long long) nm->verdict_attempts,
                   (unsigned long long) nm->verdict_send_success,
                   (unsigned long long) nm->verdict_send_failures,
                   (unsigned long long) completion_outcome_unknown);
  vlib_cli_output (vm, "physical-verdict-attempts %llu completion-outcome-succeeded %llu completion-outcome-failed-definite %llu completion-outcome-unknown %llu",
                   (unsigned long long) nm->verdict_attempts,
                   (unsigned long long) completion_outcome_succeeded,
                   (unsigned long long) completion_outcome_failed_definite,
                   (unsigned long long) completion_outcome_unknown);
  vlib_cli_output (vm, "native-verdict-calls %llu verdict-definite-rejections %llu verdict-ambiguous-results %llu",
                   (unsigned long long) nm->native_verdict_calls,
                   (unsigned long long) nm->verdict_definite_rejections,
                   (unsigned long long) nm->verdict_ambiguous_results);
  vlib_cli_output (vm, "last-verdict-generation %llu last-verdict-packet-id %u last-verdict-origin-lane %u last-verdict-outcome %s verdict-identity-mismatches %llu verdict-fault-injections %llu",
                   (unsigned long long) nm->last_verdict_generation,
                   nm->last_verdict_packet_id, nm->last_verdict_origin_lane,
                   nfqueue_live_outcome_name ((nfqueue_live_completion_outcome_t) nm->last_verdict_outcome),
                   (unsigned long long) nm->verdict_identity_mismatches,
                   (unsigned long long) nm->verdict_fault_injections);
  vlib_cli_output (vm, "last-verdict-errno %u", nm->last_verdict_errno);
  vlib_cli_output (vm, "completion-debt %u completion-debt-raised %llu completion-debt-settled %llu duplicate-attempts %llu stale-generation-completions %llu",
                   __atomic_load_n (&nm->completion_debt, __ATOMIC_ACQUIRE),
                   (unsigned long long) completion_debt_raised,
                   (unsigned long long) completion_debt_settled,
                   (unsigned long long) completion_duplicate_attempts,
                   (unsigned long long) completion_stale_generation);
  vlib_cli_output (vm, "retry-attempts %llu worker-reentries %llu policy-re-evaluations %llu replacement-payloads %llu terminal-intent-rewrites %llu policy-verdict-rewrites %llu",
                   (unsigned long long) nm->retry_attempts,
                   (unsigned long long) nm->worker_reentries,
                   (unsigned long long) nm->policy_re_evaluations,
                   (unsigned long long) nm->replacement_payloads,
                   (unsigned long long) nm->terminal_intent_rewrites,
                   (unsigned long long) nm->policy_verdict_rewrites);
  vlib_cli_output (vm, "native-buffer-returns %llu outstanding-obligations %u ingress-alloc-failures %llu",
                   (unsigned long long) nm->native_buffer_returns,
                   nfqueue_live_outstanding_load (nm),
                   (unsigned long long) nm->ingress_alloc_failures);
  vlib_cli_output (vm, "message-obligations %llu ledger-message-obligations %llu message-rejections %llu copy-count %u residue-obligations %u",
                   (unsigned long long) nm->message_obligations,
                   (unsigned long long) nm->message_obligations,
                   (unsigned long long) nm->message_rejections,
                   NFQUEUE_LIVE_PACKET_COPY_PATHS,
                   nfqueue_live_outstanding_load (nm));
  vlib_cli_output (vm, "packet-leases %llu policy-verdicts %u adapter-policy-parser-attempts %u",
                   (unsigned long long) nm->message_obligations, 0u, 0u);
  for (u32 i = 0; i < nm->lane_count; i++)
    {
      nfqueue_live_lane_t *lane = &nm->lanes[i];
      const char *lane_direction =
        nfqueue_live_device_direction (lane->hook) ==
            NFQUEUE_LIVE_DIRECTION_OUTPUT ? "OUTPUT" : "INPUT";
      vlib_cli_output (vm, "lane %u family ip%u hook %s queue %u generation %llu enabled %u datagrams %llu callbacks %llu obligations %llu verdict-attempts %llu native-returns %llu reserve-capacity %u reserve-available %u reserve-peak-occupancy %u reserve-direct-obligations %llu reserve-direct-completions %llu reserve-direct-native-returns %llu reserve-native-returns %llu reserve-exhaustions %llu reserve-losses %llu reserve-loss-materializations %llu reserve-loss-unmaterialized %llu reserve-loss-drops %llu reserve-loss-failed-definite %llu reserve-loss-unknown %llu reserve-loss-identity-misses %llu reserve-receive-faults %llu",
                       i, lane->family, lane_direction, lane->queue_num,
                       (unsigned long long) lane->generation, lane->enabled,
                       (unsigned long long) lane->datagrams,
                       (unsigned long long) lane->callbacks,
                       (unsigned long long) lane->message_obligations,
                       (unsigned long long) lane->verdict_attempts,
                       (unsigned long long) lane->native_buffer_returns,
                       lane->reserve_capacity, lane->reserve_available,
                       lane->reserve_peak_occupancy,
                       (unsigned long long) lane->reserve_direct_obligations,
                       (unsigned long long) lane->reserve_direct_completions,
                       (unsigned long long) lane->reserve_direct_native_returns,
                       (unsigned long long) lane->reserve_native_returns,
                       (unsigned long long) lane->reserve_exhaustions,
                       (unsigned long long) lane->reserve_losses,
                       (unsigned long long) lane->reserve_loss_materializations,
                       (unsigned long long) lane->reserve_loss_unmaterialized,
                       (unsigned long long) lane->reserve_loss_native_drops,
                       (unsigned long long) lane->reserve_loss_outcome_failed_definite,
                       (unsigned long long) lane->reserve_loss_outcome_unknown,
                       (unsigned long long) lane->reserve_loss_identity_misses,
                       (unsigned long long) lane->reserve_receive_faults);
    }
  return 0;
}

VLIB_CLI_COMMAND (nfqueue_live_show_command, static) = {
  .path = "show nfqueue-live-poc",
  .short_help = "show nfqueue-live-poc",
  .function = nfqueue_live_show_command_fn,
};

static clib_error_t *
nfqueue_live_init (vlib_main_t *vm)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  nm->vm = vm;
  /* Worker VLIB mains may not be fully populated when plugin init runs (this
   * is observable on Android).  Keep the queue uninitialized until enable,
   * when the runtime has verified its worker requirement. */
  nm->frame_queue_index = ~0u;
  nfqueue_live_reset_runtime (nm);
  return 0;
}

VLIB_INIT_FUNCTION (nfqueue_live_init);
