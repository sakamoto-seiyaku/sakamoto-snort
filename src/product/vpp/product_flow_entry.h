/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_FLOW_ENTRY_H
#define SAKAMOTO_PRODUCT_FLOW_ENTRY_H

/*
 * Worker-local FlowRuntime owns one preallocated pool and hash index for all
 * tracked protocols. It is independent of VPP, Android, Rust and the policy
 * ABI. Early DROP only records rejection; PASS_NEXT performs lookup/create.
 * Creation/destruction/flush require stopped or drained owner execution;
 * ordinary observe/decision calls allocate nothing and never access a peer.
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
} product_flow_entry_status_t;

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
  uint16_t reserved;
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
  /* The key protocol is the tag; TCP/ICMP remain unimplemented placeholders. */
  union {
    struct { uint8_t initialized; } tcp;
    product_udp_state_t udp;
    struct { uint8_t initialized; } icmp;
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
  product_tracker_result_t tracker; /* NONE/UNKNOWN for unimplemented protocols */
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
  } protocol[3]; /* TCP, UDP, ICMP_QUERY, sharing one total capacity */
} product_flow_runtime_snapshot_t;

typedef struct product_flow_runtime product_flow_runtime_t;

/* Allocate once before admission. *runtime must be NULL; failure leaves it NULL.
 * Capacity is explicit, immutable until destruction, and has no protocol quota.
 * generation is immutable; no entry or borrowed pointer survives recreation. */
product_flow_entry_status_t
product_flow_runtime_create (product_flow_runtime_t **runtime,
                             uint16_t worker_index, uint16_t worker_count,
                             uint64_t generation, uint32_t capacity);

/*
 * DROP precedes lookup/allocation. PASS_NEXT consumes the validated assignment
 * on the caller's current-worker pool; there is no owner selector or remote
 * pool accessor here. TCP/UDP L4_PORTS and ICMP_QUERY share this runtime.
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

/* Stop/profile boundary: clear every slot without changing pool capacity. */
void product_flow_runtime_flush (product_flow_runtime_t *pool);
void product_flow_runtime_destroy (product_flow_runtime_t *pool);
/* Diagnostics require the current owner or a drained/control worker barrier. */
product_flow_runtime_snapshot_t product_flow_runtime_snapshot (
  const product_flow_runtime_t *pool);
const product_flow_entry_t *product_flow_runtime_entry (
  const product_flow_runtime_t *pool, uint32_t slot);

uint32_t product_flow_entry_pool_active_count (
  const product_flow_runtime_t *pool);

#endif
