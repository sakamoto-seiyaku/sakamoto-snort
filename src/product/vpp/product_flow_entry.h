/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_FLOW_ENTRY_H
#define SAKAMOTO_PRODUCT_FLOW_ENTRY_H

/*
 * This is the small stateful seam for the first Product flow release.  It is
 * deliberately independent of VPP, Android, Rust, and the policy ABI.  A
 * caller owns one pool per worker and invokes it only after the early policy
 * stages have returned PASS_NEXT.
 */

#include <stddef.h>
#include <stdint.h>

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

/* Packet facts retained by the worker-owned flow table. */
typedef struct
{
  uint32_t uid;
  uint32_t network_context;
  uint32_t packet_bytes;
  uint8_t family;
  uint8_t protocol;
  uint8_t device_direction;
  uint8_t reserved;
  uint16_t source_port;
  uint16_t destination_port;
  uint64_t timestamp;
  uint8_t source_address[PRODUCT_FLOW_ENTRY_ADDRESS_BYTES];
  uint8_t destination_address[PRODUCT_FLOW_ENTRY_ADDRESS_BYTES];
} product_flow_entry_packet_t;

/*
 * Mutable state is owned by exactly one worker.  UID/context are attribution
 * facts and are intentionally not part of the canonical identity below.
 */
typedef struct
{
  uint8_t in_use;
  uint8_t family;
  uint8_t protocol;
  uint8_t origin_is_endpoint_a;
  uint8_t flow_origin_device_direction;
  uint8_t last_device_direction;
  uint8_t last_flow_direction;
  uint8_t decision;
  uint32_t uid;
  uint32_t network_context;
  uint16_t endpoint_a_port;
  uint16_t endpoint_b_port;
  uint8_t endpoint_a_address[PRODUCT_FLOW_ENTRY_ADDRESS_BYTES];
  uint8_t endpoint_b_address[PRODUCT_FLOW_ENTRY_ADDRESS_BYTES];
  uint64_t first_seen;
  uint64_t last_seen;
  uint64_t packets;
  uint64_t bytes;
  uint64_t policy_revision;
  uint64_t winner_rule_id;
  uint32_t reason_id;
  uint32_t reserved;
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
  uint64_t hash_seed;
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
                              uint16_t worker_index, uint16_t worker_count,
                              uint64_t hash_seed);

/* Publish a successor revision without scanning or mutating existing entries. */
product_flow_entry_status_t
product_flow_entry_publish_revision (product_flow_entry_pool_t *pool,
                                     uint64_t policy_revision);

/* Select the canonical owner from the direction-independent five-tuple. */
product_flow_entry_status_t
product_flow_entry_owner_for_packet (uint16_t worker_count, uint64_t hash_seed,
                                     const product_flow_entry_packet_t *packet,
                                     uint16_t *owner_worker);

/*
 * Observe one packet after early policy.  DROP returns EARLY_DROP before any
 * lookup/allocation.  PASS_NEXT performs bounded lookup/create on this pool.
 */
product_flow_entry_status_t
product_flow_entry_observe (product_flow_entry_pool_t *pool,
                            const product_flow_entry_packet_t *packet,
                            uint8_t stage_verdict,
                            product_flow_entry_observation_t *observation);

/*
 * Observe after a caller has already run the product Owner Selector and Owner
 * Guard.  The supplied owner is checked against this pool, but is not
 * recomputed: the graph's Canonical Flow Key includes its flow-domain input,
 * while this standalone module intentionally has no graph-domain dependency.
 */
product_flow_entry_status_t
product_flow_entry_observe_on_owner (
  product_flow_entry_pool_t *pool, const product_flow_entry_packet_t *packet,
  uint8_t stage_verdict, uint16_t owner_worker,
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
