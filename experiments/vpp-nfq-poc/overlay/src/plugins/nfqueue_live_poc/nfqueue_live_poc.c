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
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <nfqueue_live_poc/nfqueue_live_envelope.h>

#define NFQUEUE_LIVE_RING_CAPACITY 128u
#define NFQUEUE_LIVE_MAX_OUTSTANDING (NFQUEUE_LIVE_RING_CAPACITY - 1u)
#define NFQUEUE_LIVE_ACCEPT NF_ACCEPT
#define NFQUEUE_LIVE_FLAG_UID_KNOWN (1u << 0)
#define NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN (1u << 1)
#define NFQUEUE_LIVE_FLAG_STATE_SHIFT 2
#define NFQUEUE_LIVE_FLAG_STATE_MASK (7u << NFQUEUE_LIVE_FLAG_STATE_SHIFT)
#define NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED (1u << 5)
#define NFQUEUE_LIVE_FLAG_OUTCOME_UNKNOWN (1u << 6)
#define NFQUEUE_LIVE_FLAG_OUTCOME_FAILED (1u << 7)
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
#define NFQUEUE_LIVE_HANDOFF_TAG_MASK 0x7fu
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

nfqueue_live_main_t nfqueue_live_main = {
  .netlink_fd = -1,
  .completion_fd = -1,
  .netlink_file_index = ~0,
  .completion_file_index = ~0,
  .worker_thread = 1,
};

extern vlib_node_registration_t nfqueue_live_ingress_process_node;
extern vlib_node_registration_t nfqueue_live_owner_node;

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
nfqueue_live_outstanding_inc (nfqueue_live_main_t *nm)
{
  (void) __atomic_fetch_add (&nm->outstanding, 1, __ATOMIC_RELEASE);
}

static_always_inline void
nfqueue_live_outstanding_dec (nfqueue_live_main_t *nm)
{
  u32 previous = __atomic_fetch_sub (&nm->outstanding, 1, __ATOMIC_ACQ_REL);
  ASSERT (previous != 0);
}

static_always_inline u8
nfqueue_live_completion_credit_acquire (nfqueue_live_main_t *nm)
{
  u32 held = __atomic_load_n (&nm->completion_credits_held,
                              __ATOMIC_RELAXED);
  if (nm->inject_completion_credit_exhaustion)
    {
      nm->inject_completion_credit_exhaustion = 0;
      nm->completion_credit_exhausted++;
      return 0;
    }
  while (held < nm->completion_credit_capacity)
    if (__atomic_compare_exchange_n (&nm->completion_credits_held, &held,
                                     held + 1, 0, __ATOMIC_ACQ_REL,
                                     __ATOMIC_RELAXED))
      {
        nm->completion_credit_acquired++;
        return 1;
      }
  nm->completion_credit_exhausted++;
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
  nm->completion_credit_released++;
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
  if (nm->owner_mode == NFQUEUE_LIVE_OWNER_MODE_LOCAL)
    return meta->initial_worker;
  if (nm->owner_mode == NFQUEUE_LIVE_OWNER_MODE_REMOTE)
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

/* A compact inline handoff tag makes the source snapshot part of the buffer
 * itself.  The complete fields are still recorded and checked at the
 * destination; this tag prevents concurrent source-worker vectors from
 * confusing one global evidence snapshot with another packet. */
static_always_inline u8
nfqueue_live_handoff_identity_tag (u32 buffer_index, uword buffer_base,
                                   const nfqueue_live_meta_t *meta)
{
  u64 mix = (u64) buffer_index * 0x9e3779b1u;
  mix ^= (u64) buffer_base;
  mix ^= (u64) meta->packet_id << 17;
  mix ^= (u64) meta->payload_offset << 29;
  mix ^= (u64) meta->payload_length << 41;
  mix ^= nfqueue_live_meta_generation (meta);
  mix ^= (u64) nfqueue_live_meta_origin_lane (meta) << 53;
  mix ^= mix >> 33;
  mix *= 0xff51afd7ed558ccdu;
  mix ^= mix >> 29;
  u8 tag = (u8) (mix & NFQUEUE_LIVE_HANDOFF_TAG_MASK);
  return tag == 0 ? 1 : tag;
}

static void
nfqueue_live_record_handoff_before (nfqueue_live_main_t *nm, u32 buffer_index,
                                    vlib_buffer_t *buffer,
                                    const nfqueue_live_meta_t *meta)
{
  nm->handoff_before_buffer_index = buffer_index;
  nm->handoff_before_buffer_base = (uword) vlib_buffer_get_current (buffer);
  nm->handoff_before_packet_id = meta->packet_id;
  nm->handoff_before_payload_offset = meta->payload_offset;
  nm->handoff_before_payload_length = meta->payload_length;
  nm->handoff_before_generation = nfqueue_live_meta_generation (meta);
  nm->handoff_before_origin_lane = nfqueue_live_meta_origin_lane (meta);
}

static u8
nfqueue_live_record_handoff_after (nfqueue_live_main_t *nm, u32 buffer_index,
                                   vlib_buffer_t *buffer,
                                   const nfqueue_live_meta_t *meta)
{
  nm->handoff_after_buffer_index = buffer_index;
  nm->handoff_after_buffer_base = (uword) vlib_buffer_get_current (buffer);
  nm->handoff_after_packet_id = meta->packet_id;
  nm->handoff_after_payload_offset = meta->payload_offset;
  nm->handoff_after_payload_length = meta->payload_length;
  nm->handoff_after_generation = nfqueue_live_meta_generation (meta);
  nm->handoff_after_origin_lane = nfqueue_live_meta_origin_lane (meta);
  nm->identity_proof_checks++;
  /* Several source-worker vectors may be in flight at once.  The destination
   * proves the complete inline identity against the live buffer it received
   * (index/base plus every identity field) and checks the source tag retained
   * in handoff_stage; no side lease table can race or be consulted here. */
  u8 expected_tag = nfqueue_live_handoff_identity_tag (
    buffer_index, nm->handoff_after_buffer_base, meta);
  if (nm->handoff_after_buffer_index == buffer_index &&
      nm->handoff_after_buffer_base ==
        (uword) vlib_buffer_get_current (buffer) &&
      nm->handoff_after_packet_id == meta->packet_id &&
      nm->handoff_after_payload_offset == meta->payload_offset &&
      nm->handoff_after_payload_length == meta->payload_length &&
      nm->handoff_after_generation == nfqueue_live_meta_generation (meta) &&
      nm->handoff_after_origin_lane == nfqueue_live_meta_origin_lane (meta) &&
      (meta->handoff_stage & NFQUEUE_LIVE_HANDOFF_CANONICAL) != 0 &&
      (meta->handoff_stage & NFQUEUE_LIVE_HANDOFF_TAG_MASK) == expected_tag)
    {
      nm->identity_proof_matches++;
      return 1;
    }
  else
    {
      nm->identity_proof_failures++;
      return 0;
    }
}

static void
nfqueue_live_wake_completion (nfqueue_live_main_t *nm)
{
  u64 one = 1;
  if (write (nm->completion_fd, &one, sizeof (one)) == (ssize_t) sizeof (one))
    nm->completion_wake_writes++;
  else if (errno != EAGAIN && errno != EWOULDBLOCK)
    nm->completion_wake_errors++;
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

static void
nfqueue_live_send_verdict (nfqueue_live_main_t *nm,
                           struct nfq_q_handle *queue, u32 packet_id,
                           u32 verdict)
{
  for (u32 i = 0; i < nm->lane_count; i++)
    if (nm->lanes[i].queue == queue)
      {
        nm->lanes[i].verdict_attempts++;
        break;
      }
  if (nfq_set_verdict (queue, packet_id, verdict, 0, 0) < 0)
    {
      nm->verdict_send_failures++;
      nm->last_verdict_errno = errno;
    }
  else
    {
      /* A successful send proves only that the local netlink socket accepted
       * the datagram. Kernel verdict acceptance remains OUTCOME_UNKNOWN. */
      nm->verdict_send_success++;
      nm->completion_outcome_unknown++;
    }
  nm->verdict_attempts++;
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
  if (meta->completion_refs != 0 ||
      nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_RETURNED);
  nfqueue_live_outstanding_dec (nm);
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
nfqueue_live_publish_terminal (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  if (meta->completion_refs == 0)
    return;
  /* A terminal token is the only worker-side intent counted here.  Normal
   * completion frames do not imply a terminal/fail-open path. */
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
  nm->owner_terminal_intents++;
  nfqueue_live_completion_t terminal = {
    .buffer_index = buffer_index,
    .generation_lo = meta->generation_lo,
    .generation_hi = meta->generation_hi,
    .packet_id = meta->packet_id,
    .obligation_nonce = meta->obligation_nonce,
    .origin_lane = nfqueue_live_meta_origin_lane (meta),
    .verdict = NFQUEUE_LIVE_ACCEPT,
    .terminal = 1,
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
      nm->origin_return_overflow++;
      return;
    }
  nfqueue_live_wake_completion (nm);
}

static void
nfqueue_live_settle_on_origin (nfqueue_live_main_t *nm, u32 buffer_index,
                               nfqueue_live_meta_t *meta)
{
  nfqueue_live_lane_t *lane = nfqueue_live_lane_for_meta (nm, meta);
  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED)
    return;
  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) == 0)
    {
      meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
      nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
      if (lane && lane->queue)
        nfqueue_live_send_verdict (nm, lane->queue, meta->packet_id,
                                   NFQUEUE_LIVE_ACCEPT);
      nm->fail_open_settlements++;
    }
  meta->completion_refs = 0;
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
nfqueue_live_drop_completion_ref (nfqueue_live_main_t *nm, u32 buffer_index,
                                  nfqueue_live_meta_t *meta,
                                  const nfqueue_live_completion_t *entry)
{
  if (!entry->reference_held || meta->completion_refs == 0)
    return;
  meta->completion_refs--;
  if (meta->completion_refs == 0)
    nfqueue_live_return_buffer (nm, buffer_index, meta);
}

static void
nfqueue_live_complete_one (nfqueue_live_main_t *nm,
                           const nfqueue_live_completion_t *entry)
{
  vlib_buffer_t *buffer;
  nfqueue_live_meta_t *meta;

  buffer = vlib_get_buffer (nm->vm, entry->buffer_index);
  meta = nfqueue_live_meta (buffer);

  /* Check the full completion identity before touching verdict or reference
   * state. Generation alone is insufficient when a packet id is reused. */
  if (!nfqueue_live_completion_identity_matches (meta, entry) ||
      nfqueue_live_state (meta) < NFQUEUE_LIVE_STATE_COMPLETION)
    {
      nm->completion_stale++;
      return;
    }

  if ((meta->flags & NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED) != 0)
    {
      nm->completion_duplicate++;
      nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
      return;
    }

  meta->flags |= NFQUEUE_LIVE_FLAG_VERDICT_ATTEMPTED;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_ATTEMPTED);
  if (entry->terminal)
    nm->fail_open_settlements++;
  nfqueue_live_lane_t *lane = nfqueue_live_lane_for_meta (nm, meta);
  if (!lane || !lane->queue)
    {
      nm->missing_ingress_identity++;
      nm->missing_queue_generation++;
      nfqueue_live_drop_completion_ref (nm, entry->buffer_index, meta, entry);
      return;
    }
  nfqueue_live_send_verdict (nm, lane->queue, meta->packet_id, entry->verdict);

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
  nfqueue_live_drain_completion_queue (nm);
  return 0;
}

static void
nfqueue_live_direct_accept (nfqueue_live_main_t *nm,
                            struct nfq_q_handle *queue, u32 packet_id)
{
  nm->message_rejections++;
  nfqueue_live_send_verdict (nm, queue, packet_id, NFQUEUE_LIVE_ACCEPT);
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
  meta->completion_refs = 1;
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
  nm->payload_span_checks++;
  if (meta->payload_offset > meta->datagram_length ||
      meta->payload_length > meta->datagram_length - meta->payload_offset)
    {
      nm->payload_span_failures++;
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

  if (nm->quiescing)
    return 0;

  while (1)
    {
      if (vlib_buffer_alloc (nm->vm, &buffer_index, 1) != 1)
        {
          nm->ingress_alloc_failures++;
          return 0;
        }
      buffer = vlib_get_buffer (nm->vm, buffer_index);
      base = vlib_buffer_get_current (buffer);
      capacity = vlib_buffer_get_default_data_size (nm->vm);
      received = recv (lane->netlink_fd, base, capacity,
                       MSG_DONTWAIT | MSG_TRUNC);
      if (received < 0)
        {
          vlib_buffer_free_one (nm->vm, buffer_index);
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            return 0;
          return clib_error_return_unix (0, "nfqueue-live recv");
        }
      if (received == 0)
        {
          vlib_buffer_free_one (nm->vm, buffer_index);
          continue;
        }
      nm->live_buffer_receives++;
      lane->datagrams++;
      nm->datagrams++;
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
                  nm->ingress_queue_full++;
                  nfqueue_live_completion_credit_release (nm, meta);
                  nfqueue_live_direct_accept (nm, lane->queue,
                                              meta->packet_id);
                  datagram.callback_verdicts++;
                  nfqueue_live_release_unqueued (nm, buffer_index, meta);
                }
              else
                {
                  nfqueue_live_outstanding_inc (nm);
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
  nfqueue_live_completion_t completion = {
    .buffer_index = buffer_index,
    .generation_lo = meta->generation_lo,
    .generation_hi = meta->generation_hi,
    .packet_id = meta->packet_id,
    .obligation_nonce = meta->obligation_nonce,
    .origin_lane = nfqueue_live_meta_origin_lane (meta),
    .verdict = NFQUEUE_LIVE_ACCEPT,
    .reference_held = 1,
  };
  u8 stale_requested = nm->inject_stale != 0;
  u8 duplicate_requested = nm->inject_duplicate != 0;
  u32 required_slots = 1 + stale_requested + duplicate_requested;
  u8 primary_pushed;
  u8 stale_pushed = 1;
  u8 duplicate_pushed = 1;

  if (nfqueue_live_state (meta) == NFQUEUE_LIVE_STATE_RETURNED ||
      meta->completion_refs == 0)
    return 0;
  nfqueue_live_set_state (meta, NFQUEUE_LIVE_STATE_COMPLETION);
  if (nm->inject_completion_overflow)
    {
      /* Reserve every free normal-ring slot with an exact duplicate. The
       * original reference stays reserved for the emergency origin token. */
      nfqueue_live_completion_lock (nm);
      while (nfqueue_live_completion_free_slots (&nm->completion) != 0)
        {
          nfqueue_live_completion_t filler = completion;
          if (!nfqueue_live_completion_push (&nm->completion, &filler))
            break;
          meta->completion_refs++;
        }
      nfqueue_live_completion_unlock (nm);
      nm->inject_completion_overflow = 0;
    }
  /* A stale token carries no reference; only an exact duplicate owns an
   * additional inline reference. */
  nfqueue_live_completion_lock (nm);
  if (nfqueue_live_completion_free_slots (&nm->completion) < required_slots)
    {
      nfqueue_live_completion_unlock (nm);
      nm->completion_ring_overflow++;
      nm->inject_stale = 0;
      nm->inject_duplicate = 0;
      nfqueue_live_publish_terminal (nm, buffer_index, meta);
      return 0;
    }
  if (duplicate_requested)
    meta->completion_refs++;
  primary_pushed = nfqueue_live_completion_push (&nm->completion, &completion);
  if (!primary_pushed)
    {
      if (duplicate_requested)
        meta->completion_refs--;
      nfqueue_live_completion_unlock (nm);
      nm->completion_ring_overflow++;
      nfqueue_live_publish_terminal (nm, buffer_index, meta);
      return 0;
    }
  if (stale_requested)
    {
      nfqueue_live_completion_t stale = completion;
      stale.reference_held = 0;
      stale.obligation_nonce++;
      if (stale.obligation_nonce == 0)
        stale.packet_id++;
      stale_pushed = nfqueue_live_completion_push (&nm->completion, &stale);
      nm->inject_stale = 0;
    }
  if (duplicate_requested)
    {
      nfqueue_live_completion_t duplicate = completion;
      duplicate_pushed =
        nfqueue_live_completion_push (&nm->completion, &duplicate);
      if (!duplicate_pushed)
        meta->completion_refs--;
      nm->inject_duplicate = 0;
    }
  nfqueue_live_completion_unlock (nm);
  if (!stale_pushed)
    nm->completion_ring_overflow++;
  if (!duplicate_pushed)
    nm->completion_ring_overflow++;
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

      nm->handoff_count++;
      nm->last_worker_thread = worker_thread;
      if (nfqueue_live_state (meta) != NFQUEUE_LIVE_STATE_LIVE)
        nm->owner_invalid_state++;
      nm->payload_span_checks++;
      if ((meta->flags & NFQUEUE_LIVE_FLAG_PAYLOAD_IN_SPAN) == 0 ||
          meta->payload_offset > meta->datagram_length ||
          meta->payload_length > meta->datagram_length - meta->payload_offset)
        {
          nm->payload_span_failures++;
          nfqueue_live_publish_terminal (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }

      if (meta->handoff_stage == NFQUEUE_LIVE_HANDOFF_INITIAL)
        {
          if (worker_thread != meta->initial_worker)
            {
              nm->owner_invalid_state++;
              nfqueue_live_publish_terminal (nm, buffer_index, meta);
              from++;
              n_left--;
              continue;
            }
          if (meta->canonical_worker != meta->initial_worker)
            {
              nm->owner_mismatch_count++;
              nm->owner_remote_obligations++;
              nfqueue_live_record_handoff_before (nm, buffer_index, buffer,
                                                  meta);
              target_thread = (u16) meta->canonical_worker;
              /* Publish the destination-stage marker before enqueue so the
               * receiving worker cannot observe a stale initial-stage value. */
              meta->handoff_stage =
                NFQUEUE_LIVE_HANDOFF_CANONICAL |
                nfqueue_live_handoff_identity_tag (
                  buffer_index, (uword) vlib_buffer_get_current (buffer), meta);
              if (nm->inject_owner_queue_full)
                {
                  nm->inject_owner_queue_full = 0;
                  enqueued = 0;
                }
              else
                enqueued = vlib_buffer_enqueue_to_thread (
                  vm, node, nm->frame_queue_index, &buffer_index,
                  &target_thread, 1, 1);
              if (enqueued != 1)
                {
                  nm->owner_queue_full++;
                  nfqueue_live_publish_terminal (nm, buffer_index, meta);
                }
              else
                {
                  nm->owner_remote_handoffs++;
                }
              from++;
              n_left--;
              continue;
            }
          nm->owner_local_obligations++;
          meta->handoff_stage =
            NFQUEUE_LIVE_HANDOFF_CANONICAL |
            nfqueue_live_handoff_identity_tag (
              buffer_index, (uword) vlib_buffer_get_current (buffer), meta);
          (void) nfqueue_live_publish_completion (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }

      if (worker_thread != meta->canonical_worker)
        {
          nm->owner_invalid_state++;
          nfqueue_live_publish_terminal (nm, buffer_index, meta);
          from++;
          n_left--;
          continue;
        }
      if (!nfqueue_live_record_handoff_after (nm, buffer_index, buffer, meta))
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
          nm->ingress_queue_full++;
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
nfqueue_live_reset_runtime (nfqueue_live_main_t *nm)
{
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
      nm->readers[i].nm = nm;
      nm->readers[i].lane_index = (u8) i;
    }
  nm->ingress.head = 0;
  nm->ingress.tail = 0;
  nm->completion.head = 0;
  nm->completion.tail = 0;
  nm->origin_return.head = 0;
  nm->origin_return.tail = 0;
  nm->completion_push_lock = 0;
  nm->origin_return_push_lock = 0;
  __atomic_store_n (&nm->outstanding, 0, __ATOMIC_RELEASE);
  __atomic_store_n (&nm->completion_credits_held, 0, __ATOMIC_RELEASE);
  nm->completion_credit_capacity = NFQUEUE_LIVE_MAX_OUTSTANDING;
  nm->next_obligation_nonce = 0;
  nm->last_buffer_index = ~0;
  nm->last_buffer_base = 0;
  nm->last_worker_thread = ~0;
  nm->handoff_before_buffer_index = ~0;
  nm->handoff_after_buffer_index = ~0;
  nm->handoff_before_buffer_base = 0;
  nm->handoff_after_buffer_base = 0;
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

static clib_error_t *
nfqueue_live_drain_bounded (nfqueue_live_main_t *nm)
{
  u32 attempt;
  for (attempt = 0; attempt < 200; attempt++)
    {
      nfqueue_live_drain_ingress_queue (nm);
      nfqueue_live_drain_completion_queue (nm);
      if (nfqueue_live_outstanding_load (nm) == 0)
        return 0;
      /* Workers continue to run while the origin lane polls the completion
       * transport. The bound makes teardown failure explicit. */
      usleep (1000);
    }
  nfqueue_live_drain_ingress_queue (nm);
  nfqueue_live_drain_completion_queue (nm);
  if (nfqueue_live_outstanding_load (nm) != 0)
    return clib_error_return (0,
                              "nfqueue-live bounded drain left %u obligations",
                              nfqueue_live_outstanding_load (nm));
  return 0;
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
                    u8 inject_completion_overflow)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_error_t *error;

  if (nm->enabled)
    return clib_error_return (0, "nfqueue-live-poc already enabled");
  if (vlib_get_n_threads () < 2)
    return clib_error_return (0, "start VPP with at least one worker");
  nfqueue_live_reset_runtime (nm);
  nm->vm = vm;
  nm->queue_num = queue_num;
  nm->family = family;
  nm->origin_lane = 0;
  nm->worker_thread = 1;
  nm->worker_count = clib_min (vlib_num_workers (), 2u);
  nm->first_worker_thread = 1;
  nm->second_worker_thread = 2;
  nm->owner_mode = NFQUEUE_LIVE_OWNER_MODE_MIXED;
  nm->inject_stale = inject_stale;
  nm->inject_duplicate = inject_duplicate;
  nm->inject_completion_overflow = inject_completion_overflow;
  nm->lane_count = 1;
  nm->dual_mode = 0;
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
  error = nfqueue_live_open_completion (nm);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  nm->enabled = 1;
  return 0;
}

static clib_error_t *
nfqueue_live_enable_dual (vlib_main_t *vm, u16 queue_base,
                          u8 inject_stale, u8 inject_duplicate,
                          u8 inject_completion_overflow,
                          u8 inject_uid_unknown, u8 require_two_workers)
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
  nm->queue_num = queue_base;
  nm->family = 0;
  nm->origin_lane = 0;
  nm->worker_thread = 1;
  nm->worker_count = clib_min (vlib_num_workers (), 2u);
  nm->first_worker_thread = 1;
  nm->second_worker_thread = 2;
  nm->owner_mode = NFQUEUE_LIVE_OWNER_MODE_MIXED;
  nm->inject_stale = inject_stale;
  nm->inject_duplicate = inject_duplicate;
  nm->inject_completion_overflow = inject_completion_overflow;
  nm->inject_uid_unknown = inject_uid_unknown;
  nm->lane_count = NFQUEUE_LIVE_MAX_LANES;
  nm->dual_mode = 1;
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
  error = nfqueue_live_open_completion (nm);
  if (error)
    {
      nfqueue_live_close (nm);
      return error;
    }
  nm->enabled = 1;
  return 0;
}

static clib_error_t *
nfqueue_live_disable (void)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  clib_error_t *error;
  if (!nm->enabled)
    return 0;
  nm->quiescing = 1;
  for (u32 i = 0; i < nm->lane_count; i++)
    if (nm->lanes[i].netlink_file_index != ~0)
      {
        clib_file_del_by_index (&file_main, nm->lanes[i].netlink_file_index);
        nm->lanes[i].netlink_file_index = ~0;
      }
  nm->netlink_file_index = ~0;
  error = nfqueue_live_drain_bounded (nm);
  if (error)
    return error;
  nfqueue_live_close (nm);
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
      else
        return clib_error_return (0, "unknown nfqueue-live-poc option");
    }
  error = nfqueue_live_enable (vm, (u16) queue_num, family, stale, duplicate,
                               completion_overflow);
  if (!error)
    {
      nfqueue_live_main.inject_missing_packet_id = missing_packet_id;
      nfqueue_live_main.inject_missing_generation = missing_generation;
      nfqueue_live_main.inject_uid_unknown = uid_unknown;
      nfqueue_live_main.owner_mode = owner_mode;
      nfqueue_live_main.inject_owner_queue_full = owner_queue_full;
      nfqueue_live_main.inject_completion_credit_exhaustion = credit_exhaustion;
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
                "[inject-owner-queue-full] [inject-completion-credit-exhaustion]",
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
  u8 require_two_workers = 0;
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
      else if (unformat (input, "two-workers"))
        require_two_workers = 1;
      else
        return clib_error_return (0, "unknown nfqueue-live-poc dual option");
    }
  error = nfqueue_live_enable_dual (vm, (u16) queue_base, stale, duplicate,
                                    completion_overflow, uid_unknown,
                                    require_two_workers);
  if (!error)
    {
      nfqueue_live_main.inject_missing_packet_id = missing_packet_id;
      nfqueue_live_main.inject_missing_generation = missing_generation;
      nfqueue_live_main.inject_uid_unknown = uid_unknown;
      nfqueue_live_main.owner_mode = owner_mode;
      nfqueue_live_main.inject_owner_queue_full = owner_queue_full;
      nfqueue_live_main.inject_completion_credit_exhaustion = credit_exhaustion;
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
                "[two-workers]",
  .function = nfqueue_live_enable_dual_command_fn,
};

static clib_error_t *
nfqueue_live_disable_command_fn (vlib_main_t *vm, unformat_input_t *input,
                                 vlib_cli_command_t *cmd)
{
  (void) vm;
  (void) input;
  (void) cmd;
  return nfqueue_live_disable ();
}

VLIB_CLI_COMMAND (nfqueue_live_disable_command, static) = {
  .path = "nfqueue-live-poc disable",
  .short_help = "nfqueue-live-poc disable",
  .function = nfqueue_live_disable_command_fn,
};

static clib_error_t *
nfqueue_live_show_command_fn (vlib_main_t *vm, unformat_input_t *input,
                              vlib_cli_command_t *cmd)
{
  nfqueue_live_main_t *nm = &nfqueue_live_main;
  u32 data_size = vlib_buffer_get_default_data_size (vm);
  const char *owner_mode = nm->owner_mode == NFQUEUE_LIVE_OWNER_MODE_LOCAL ?
                             "local" :
                               nm->owner_mode == NFQUEUE_LIVE_OWNER_MODE_REMOTE ?
                                 "remote" : "mixed";
  const char *last_direction =
    nm->last_device_direction == NFQUEUE_LIVE_DIRECTION_OUTPUT ? "OUTPUT" :
      "INPUT";
  (void) input;
  (void) cmd;
  vlib_cli_output (vm, "enabled %u family ip%u queue %u generation %llu",
                   nm->enabled, nm->family, nm->queue_num,
                   (unsigned long long) nm->generation);
  vlib_cli_output (vm, "buffer-data-size %u worker-thread %u origin-lane %u workers %u worker-ids %u,%u owner-mode %s",
                   data_size, nm->last_worker_thread, nm->origin_lane,
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
                   (unsigned long long) nm->payload_span_checks,
                   (unsigned long long) nm->payload_span_failures,
                   (unsigned long long) NFQUEUE_LIVE_PACKET_COPY_PATHS);
  vlib_cli_output (vm, "scratch-rx-buffers %llu full-packet-memcpy %llu per-packet-heap-objects %llu",
                   (unsigned long long) NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS,
                   (unsigned long long) NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS,
                   (unsigned long long) NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS);
  vlib_cli_output (vm, "handoffs %llu owner-mismatches %llu owner-invalid-state %llu",
                   (unsigned long long) nm->handoff_count,
                   (unsigned long long) nm->owner_mismatch_count,
                   (unsigned long long) nm->owner_invalid_state);
  vlib_cli_output (vm, "owner-local-obligations %llu owner-remote-obligations %llu owner-remote-handoffs %llu owner-queue-full %llu owner-terminal-intents %llu ingress-queue-full %llu",
                   (unsigned long long) nm->owner_local_obligations,
                   (unsigned long long) nm->owner_remote_obligations,
                   (unsigned long long) nm->owner_remote_handoffs,
                   (unsigned long long) nm->owner_queue_full,
                   (unsigned long long) nm->owner_terminal_intents,
                   (unsigned long long) nm->ingress_queue_full);
  vlib_cli_output (vm, "completion-credit-capacity %u completion-credit-acquired %llu completion-credit-released %llu completion-credit-exhausted %llu completion-credits-held %u residue-completion-credits %u",
                   nm->completion_credit_capacity,
                   (unsigned long long) nm->completion_credit_acquired,
                   (unsigned long long) nm->completion_credit_released,
                   (unsigned long long) nm->completion_credit_exhausted,
                   __atomic_load_n (&nm->completion_credits_held, __ATOMIC_ACQUIRE),
                   __atomic_load_n (&nm->completion_credits_held, __ATOMIC_ACQUIRE));
  vlib_cli_output (vm, "identity-proof-checks %llu identity-proof-matches %llu identity-proof-failures %llu",
                   (unsigned long long) nm->identity_proof_checks,
                   (unsigned long long) nm->identity_proof_matches,
                   (unsigned long long) nm->identity_proof_failures);
  vlib_cli_output (vm, "handoff-before buffer-index %u buffer-base 0x%llx packet-id %u generation %llu origin-lane %u payload-offset %u payload-length %u",
                   nm->handoff_before_buffer_index,
                   (unsigned long long) nm->handoff_before_buffer_base,
                   nm->handoff_before_packet_id,
                   (unsigned long long) nm->handoff_before_generation,
                   nm->handoff_before_origin_lane,
                   nm->handoff_before_payload_offset,
                   nm->handoff_before_payload_length);
  vlib_cli_output (vm, "handoff-after buffer-index %u buffer-base 0x%llx packet-id %u generation %llu origin-lane %u payload-offset %u payload-length %u",
                   nm->handoff_after_buffer_index,
                   (unsigned long long) nm->handoff_after_buffer_base,
                   nm->handoff_after_packet_id,
                   (unsigned long long) nm->handoff_after_generation,
                   nm->handoff_after_origin_lane,
                   nm->handoff_after_payload_offset,
                   nm->handoff_after_payload_length);
  vlib_cli_output (vm, "completion-frames %llu stale %llu duplicate %llu ring-overflow %llu origin-return-overflow %llu",
                   (unsigned long long) nm->completion_frames,
                   (unsigned long long) nm->completion_stale,
                   (unsigned long long) nm->completion_duplicate,
                   (unsigned long long) nm->completion_ring_overflow,
                   (unsigned long long) nm->origin_return_overflow);
  vlib_cli_output (vm, "cap-len-missing %llu truncated-datagrams %llu fail-open-settlements %llu identity-unrecoverable %llu",
                   (unsigned long long) nm->cap_len_missing,
                   (unsigned long long) nm->truncated_datagrams,
                   (unsigned long long) nm->fail_open_settlements,
                   (unsigned long long) nm->identity_unrecoverable);
  vlib_cli_output (vm, "verdict-attempts %llu send-success %llu send-failures %llu outcome-unknown %llu",
                   (unsigned long long) nm->verdict_attempts,
                   (unsigned long long) nm->verdict_send_success,
                   (unsigned long long) nm->verdict_send_failures,
                   (unsigned long long) nm->completion_outcome_unknown);
  vlib_cli_output (vm, "native-buffer-returns %llu outstanding-obligations %u ingress-alloc-failures %llu",
                   (unsigned long long) nm->native_buffer_returns,
                   nfqueue_live_outstanding_load (nm),
                   (unsigned long long) nm->ingress_alloc_failures);
  vlib_cli_output (vm, "ledger-message-obligations %llu message-rejections %llu copy-count %u residue-obligations %u",
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
      vlib_cli_output (vm, "lane %u family ip%u hook %s queue %u generation %llu enabled %u datagrams %llu callbacks %llu obligations %llu verdict-attempts %llu native-returns %llu",
                       i, lane->family, lane_direction, lane->queue_num,
                       (unsigned long long) lane->generation, lane->enabled,
                       (unsigned long long) lane->datagrams,
                       (unsigned long long) lane->callbacks,
                       (unsigned long long) lane->message_obligations,
                       (unsigned long long) lane->verdict_attempts,
                       (unsigned long long) lane->native_buffer_returns);
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
  nm->frame_queue_index = vlib_frame_queue_main_init (
    nfqueue_live_owner_node.index, 0);
  nfqueue_live_reset_runtime (nm);
  return 0;
}

VLIB_INIT_FUNCTION (nfqueue_live_init);
