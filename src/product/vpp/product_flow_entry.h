/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_FLOW_ENTRY_H
#define SAKAMOTO_PRODUCT_FLOW_ENTRY_H

/*
 * This is the small stateful seam for the first Product flow release.  It is
 * deliberately independent of VPP, Android, Rust, and the policy ABI.  A
 * caller owns one pool per worker. Early DROP only records rejection;
 * PASS_NEXT performs the bounded owner-local lookup/create.
 */

#include <stddef.h>
#include <stdint.h>
#include "product_packet.h"

#define PRODUCT_FLOW_ENTRY_MAX_ENTRIES UINT32_C (64)
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

#define PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG UINT8_C (1)
#define PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY UINT8_C (2)

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
} product_flow_entry_status_t;

/* Attribution and counters accompany the already assigned typed identity. */
typedef struct
{
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
  uint64_t policy_revision;
  uint64_t policy_snapshot_hash;
  uint64_t winner_rule_id;
  uint32_t reason_id;
} product_flow_entry_t;

typedef struct
{
  product_flow_entry_t *entry;
  uint16_t owner_worker;
  uint8_t flow_direction;
  uint8_t created;
  uint8_t reused;
  uint8_t revision_invalidated;
} product_flow_entry_observation_t;

typedef struct
{
  uint16_t worker_index;
  uint16_t worker_count;
  uint32_t active_entries;
  uint64_t active_snapshot_hash;
  uint64_t active_policy_revision;
  uint64_t allocation_count;
  uint64_t reuse_count;
  uint64_t early_drop_count;
  uint64_t wrong_owner_count;
  uint64_t capacity_rejection_count;
  uint64_t revision_invalidation_count;
  uint64_t flush_count;
  product_flow_entry_t entries[PRODUCT_FLOW_ENTRY_MAX_ENTRIES];
} product_flow_entry_pool_t;

/* Initialize one fixed-capacity pool for one canonical flow owner. */
product_flow_entry_status_t
product_flow_entry_pool_init (product_flow_entry_pool_t *pool,
                              uint16_t worker_index, uint16_t worker_count);

/* Publish a revision/hash epoch without scanning or mutating existing entries. */
product_flow_entry_status_t
product_flow_entry_publish_revision (product_flow_entry_pool_t *pool,
                                     uint64_t policy_revision,
                                     uint64_t snapshot_hash);

/*
 * DROP precedes lookup/allocation. PASS_NEXT consumes the validated assignment
 * on the caller's current-worker pool; there is no owner selector or remote
 * pool accessor here. L4_PORTS is the bounded S208 eligibility scope.
 */
product_flow_entry_status_t
product_flow_entry_observe (product_flow_entry_pool_t *pool,
                            const product_owner_assignment_t *assignment,
                            const product_flow_entry_packet_t *packet,
                            uint8_t stage_verdict,
                            product_flow_entry_observation_t *observation);

/* Cache the result of a later stage for the current active revision. */
product_flow_entry_status_t
product_flow_entry_set_decision (product_flow_entry_pool_t *pool,
                                 product_flow_entry_t *entry,
                                 uint8_t decision, uint64_t winner_rule_id,
                                 uint32_t reason_id);

/* Stop/profile boundary: clear every slot without changing pool capacity. */
void product_flow_entry_pool_flush (product_flow_entry_pool_t *pool);

uint32_t product_flow_entry_pool_active_count (
  const product_flow_entry_pool_t *pool);

#endif
