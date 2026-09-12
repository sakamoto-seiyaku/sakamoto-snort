/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_FLOW_ENTRY_H
#define SAKAMOTO_PRODUCT_FLOW_ENTRY_H

/*
 * Worker-local FlowRuntime owns one preallocated pool and hash index for all
 * tracked protocols. It is independent of VPP, Android, Rust and the policy
 * ABI. Early DROP only records rejection; PASS_NEXT performs lookup/create.
 * Creation/destruction/flush require stopped or drained owner execution;
 * observe/decision never allocate heap or access a peer. Normal close/reuse
 * delivers an END via the composition callback, which allocates a VPP buffer.
 */

#include <stddef.h>
#include <stdint.h>
#include "product_packet.h"
#include "product_flow_tracker.h"

#define PRODUCT_FLOW_ENTRY_ADDRESS_BYTES UINT32_C (16)
#define PRODUCT_FLOW_ENTRY_UID_UNKNOWN UINT32_MAX
#define PRODUCT_FLOW_ENTRY_NETWORK_CONTEXT_UNKNOWN UINT32_MAX

#define PRODUCT_FLOW_ENTRY_FAMILY_IPV4 UINT8_C (4)
#define PRODUCT_FLOW_ENTRY_FAMILY_IPV6 UINT8_C (6)
#define PRODUCT_FLOW_ENTRY_PROTOCOL_TCP UINT8_C (6)
#define PRODUCT_FLOW_ENTRY_PROTOCOL_UDP UINT8_C (17)

#define PRODUCT_FLOW_ENTRY_DIRECTION_INPUT UINT8_C (1)
#define PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT UINT8_C (3)

/* Stage result: an early DROP must never allocate state. */
#define PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT UINT8_C (0)
#define PRODUCT_FLOW_ENTRY_VERDICT_DROP UINT8_C (1)

/* The optional cached decision of a later policy stage. */
#define PRODUCT_FLOW_ENTRY_DECISION_NONE UINT8_C (0)
#define PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT UINT8_C (1)
#define PRODUCT_FLOW_ENTRY_DECISION_DROP UINT8_C (2)

#define PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG PRODUCT_FLOW_DIRECTION_ORIG
#define PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY PRODUCT_FLOW_DIRECTION_REPLY

typedef enum
{
  PRODUCT_FLOW_ENTRY_STATUS_OK = 0,
  PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT,
  PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET,
  PRODUCT_FLOW_ENTRY_STATUS_INVALID_REVISION,
  PRODUCT_FLOW_ENTRY_STATUS_REVISION_NOT_ADVANCING,
  PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER,
  PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED,
  PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP,
  PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND,
  PRODUCT_FLOW_ENTRY_STATUS_STALE_REVISION,
  PRODUCT_FLOW_ENTRY_STATUS_INVALID_DECISION,
  PRODUCT_FLOW_ENTRY_STATUS_ALLOCATION_FAILED,
  PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION,
  PRODUCT_FLOW_ENTRY_STATUS_WRONG_STATE,
} product_flow_entry_status_t;

typedef enum
{
  PRODUCT_FLOW_END_NONE = 0,
  PRODUCT_FLOW_END_CLOSED,
  PRODUCT_FLOW_END_EXPIRED,
  PRODUCT_FLOW_END_REPLACED,
} product_flow_end_reason_t;

/* Identity of the immutable snapshot acquired by this packet. Revision/hash
 * zero is the bootstrap view; generation is always the running generation. */
typedef struct
{
  uint64_t generation;
  uint64_t revision;
  uint64_t snapshot_hash;
} product_flow_policy_identity_t;

/* Attribution and counters accompany the already assigned typed identity. */
typedef struct
{
  const product_packet_facts_t *facts; /* synchronous borrow; never stored */
  product_flow_policy_identity_t policy;
  uint32_t uid;
  uint32_t network_context;
  uint32_t packet_bytes;
  uint8_t device_direction;
  uint8_t reserved[3];
  uint64_t timestamp;
} product_flow_entry_packet_t;

/* Only the current worker may mutate this state during packet processing. */
typedef struct
{
  product_canonical_owner_key_t key;
  uint64_t canonical_hash;
  uint8_t in_use;
  uint8_t origin_is_endpoint_a;
  uint8_t flow_origin_device_direction;
  uint8_t last_device_direction;
  uint8_t last_flow_direction;
  uint8_t decision;
  uint8_t linked;
  uint8_t end_reason;
  uint32_t uid;
  uint32_t network_context;
  uint64_t first_seen;
  uint64_t last_seen;
  uint64_t packets;
  uint64_t bytes;
  uint64_t policy_generation;
  uint64_t policy_revision;
  uint64_t policy_snapshot_hash;
  uint64_t winner_rule_id;
  uint32_t reason_id;
  uint64_t incarnation;
  uint64_t side_packets[2]; /* ORIG, REPLY */
  uint64_t side_bytes[2];
  /* One indexed timer per linked entry, never a list of stale refreshes.
   * Deadline survives unlink for the END consumer; heap_position does not. */
  uint64_t deadline_us;
  uint32_t heap_position;
  uint8_t timeout_class;
  /* The typed key is the protocol tag; every tracker shares this one pool. */
  union {
    product_tcp_state_t tcp;
    product_udp_state_t udp;
    product_icmp_state_t icmp;
  } protocol_state;
} product_flow_entry_t;

typedef struct
{
  const product_flow_entry_t *entry; /* borrowed until owner mutation/flush */
  uint32_t slot;
  uint16_t owner_worker;
  uint8_t flow_direction;
  uint8_t created;
  uint8_t reused;
  uint8_t revision_invalidated;
  uint8_t expired_before_observe;
  uint32_t previous_slot;
  uint64_t previous_deadline_us;
  uint64_t previous_incarnation; /* old instance retained by its FlowEnd */
  product_tracker_result_t tracker; /* NONE/UNKNOWN when no observation occurs */
} product_flow_entry_observation_t;

typedef struct
{
  uint16_t worker_index;
  uint16_t worker_count;
  uint64_t generation;
  uint64_t allocated_bytes;
  uint32_t capacity;
  uint32_t high_watermark;
  uint32_t active_entries;
  uint32_t linked_entries;
  uint32_t ending_entries; /* allocated but no longer searchable */
  uint32_t timer_entries;
  uint64_t release_count;
  uint64_t administrative_release_count;
  uint64_t allocation_count;
  uint64_t reuse_count;
  uint64_t early_drop_count;
  uint64_t wrong_owner_count;
  uint64_t capacity_rejection_count;
  uint64_t revision_invalidation_count;
  uint64_t revision_mismatch_count;
  uint64_t flush_count;
  struct {
    uint32_t active;
    uint64_t creates;
    uint64_t hits;
    uint64_t capacity_misses;
    uint64_t invalid_packets;
    uint64_t closed;
  } protocol[3]; /* TCP, UDP, ICMP_QUERY, sharing one total capacity */
} product_flow_runtime_snapshot_t;

typedef struct product_flow_runtime product_flow_runtime_t;

/* One composition callback, not a subscriber list. Called synchronously on
 * the owner after unlink; it must deliver one FlowEnd and leave entry alive.
 * In the product it allocates/enqueues a native empty buffer or exits fatally.
 * It must not release/reenter the runtime before returning. */
typedef void (*product_flow_end_callback_t) (
  void *context, const product_flow_entry_t *entry, uint32_t slot,
  product_flow_end_reason_t reason);

/* Allocate once before admission. *runtime must be NULL; failure leaves it NULL.
 * Capacity is explicit, immutable until destruction, and has no protocol quota.
 * generation is immutable; no entry or borrowed pointer survives recreation. */
product_flow_entry_status_t
product_flow_runtime_create (product_flow_runtime_t **runtime,
                             uint16_t worker_index, uint16_t worker_count,
                             uint64_t generation, uint32_t capacity);

/* Set once on an empty runtime before admission. There is no synchronous
 * cleanup fallback when the product FlowEnd composition is absent. */
product_flow_entry_status_t product_flow_runtime_set_end_callback (
  product_flow_runtime_t *runtime, product_flow_end_callback_t callback,
  void *context);

/* Owner-local close hides the entry before delivering its end signal. The
 * slot remains allocated and immutable until release_end from native free.
 * Generation/incarnation reject stale commands and already-recycled slots. */
product_flow_entry_status_t product_flow_runtime_close (
  product_flow_runtime_t *runtime, uint32_t slot, uint64_t generation,
  uint64_t incarnation, product_flow_end_reason_t reason);
product_flow_entry_status_t product_flow_runtime_release_end (
  product_flow_runtime_t *runtime, uint32_t slot, uint64_t generation,
  uint64_t incarnation, product_flow_end_reason_t reason);

/* Owner-local timer primitives shared by the controlled S226 arms. Nothing
 * schedules automatically: the caller must supply an explicit monotonic
 * deadline. Production protocol refresh/wake composition belongs to S227.
 * A single preallocated index bounds memory to entry capacity. */
product_flow_entry_status_t product_flow_runtime_set_deadline (
  product_flow_runtime_t *runtime, uint32_t slot, uint64_t generation,
  uint64_t incarnation, uint64_t deadline_us, product_ct_timeout_t timeout_class);
uint64_t product_flow_runtime_next_deadline (const product_flow_runtime_t *runtime);
product_flow_entry_status_t product_flow_runtime_run_due (
  product_flow_runtime_t *runtime, uint64_t now_us, uint32_t budget,
  uint32_t *closed);

/*
 * DROP precedes lookup/allocation. PASS_NEXT consumes the validated assignment
 * on the caller's current-worker pool; there is no owner selector or remote
 * pool accessor here. TCP/UDP L4_PORTS and ICMP_QUERY share this runtime.
 * OK with entry == NULL and INVALID CtFacts is a rejected new TCP candidate,
 * not allocation failure or an implicit packet verdict. TCP tuple replacement
 * closes the old instance through FlowEnd before looking for another free slot;
 * the still-allocated old slot cannot satisfy the new allocation.
 */
product_flow_entry_status_t
product_flow_entry_observe (product_flow_runtime_t *pool,
                            const product_owner_assignment_t *assignment,
                            const product_flow_entry_packet_t *packet,
                            uint8_t stage_verdict,
                            product_flow_entry_observation_t *observation);

/* Cache only the decision from this packet's acquired snapshot. */
product_flow_entry_status_t
product_flow_entry_set_decision (product_flow_runtime_t *pool,
                                 const product_flow_entry_t *entry,
                                 const product_flow_policy_identity_t *policy,
                                 uint8_t decision, uint64_t winner_rule_id,
                                 uint32_t reason_id);

/* Stop/profile boundary after graph drain. Refuse to invalidate a live END. */
product_flow_entry_status_t product_flow_runtime_flush (product_flow_runtime_t *pool);
void product_flow_runtime_destroy (product_flow_runtime_t *pool);
/* Diagnostics require the current owner or a drained/control worker barrier. */
product_flow_runtime_snapshot_t product_flow_runtime_snapshot (
  const product_flow_runtime_t *pool);
const product_flow_entry_t *product_flow_runtime_entry (
  const product_flow_runtime_t *pool, uint32_t slot);

uint32_t product_flow_entry_pool_active_count (
  const product_flow_runtime_t *pool);

#endif
