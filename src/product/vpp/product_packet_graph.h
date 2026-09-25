/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_PACKET_GRAPH_H
#define SAKAMOTO_PRODUCT_PACKET_GRAPH_H

#include "product_packet.h"
#include "product_packet_completion.h"
#include "product_l4_policy.h"

#include <stdint.h>

#include <vlib/vlib.h>

#define PRODUCT_PACKET_GRAPH_L4_DIRECTION_INPUT UINT8_C (1)
#define PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT UINT8_C (3)
#define PRODUCT_PACKET_GRAPH_L4_ACTION_ALLOW UINT8_C (1)
#define PRODUCT_PACKET_GRAPH_L4_ACTION_DROP UINT8_C (2)
#define PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP UINT8_C (6)
#define PRODUCT_PACKET_GRAPH_L4_FAMILY_IPV4 UINT32_C (4)
#define PRODUCT_PACKET_GRAPH_L4_WINNER_NONE UINT32_C (0)
#define PRODUCT_PACKET_GRAPH_L4_WINNER_RULE UINT32_C (2)
#define PRODUCT_PACKET_GRAPH_L4_EVALUATION_NONE UINT32_C (0)
#define PRODUCT_PACKET_GRAPH_L4_EVALUATION_MATCH UINT32_C (1)
#define PRODUCT_PACKET_GRAPH_L4_EVALUATION_NO_MATCH UINT32_C (2)
#define PRODUCT_PACKET_GRAPH_GATE_TABLE_MAX_ENTRIES UINT32_C (64)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NONE UINT32_C (0)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_NO_RULE UINT32_C (1)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_UID UINT32_C (2)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_CONTEXT UINT32_C (3)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_IFINDEX UINT32_C (4)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_UNKNOWN_DIRECTION UINT32_C (5)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_FAMILY UINT32_C (6)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PROTOCOL UINT32_C (7)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_ADDRESS UINT32_C (8)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PORTS_UNAVAILABLE UINT32_C (9)
#define PRODUCT_PACKET_GRAPH_GATE_NO_MATCH_PORT UINT32_C (10)

/* Diagnostic replay allocates only a descriptor carrier, never an NFQ packet
 * obligation. Its rejection must not return or settle the original buffer. */
int product_packet_graph_replay_completion (
  vlib_main_t *vm, const product_packet_completion_frame_t *completion);
uint64_t product_packet_graph_completion_frame_debt (void);
/* Control-only under worker barrier: stop new lifecycle work and settle
 * fragments while origin lanes stay open; already-enqueued FlowEnds drain. */
void product_packet_graph_quiesce (vlib_main_t *vm);

typedef struct
{
  uint64_t revision;
  uint64_t snapshot_hash;
  uint64_t rule_id;
  uint32_t subject_uid;
  uint32_t network_context_id;
  uint32_t blocked;
  uint32_t reason_id;
} product_packet_graph_gate_policy_t;

/* S191 compatibility input.  Typed S192 bundles use the GateTable below. */
typedef struct
{
  uint64_t revision;
  uint64_t snapshot_hash;
  uint64_t rule_id;
  uint32_t subject_uid;
  uint32_t network_context_id;
  uint32_t reason_id;
  uint32_t priority;
  uint32_t order;
  uint32_t source_address;
  uint32_t destination_address;
  uint16_t source_port_first;
  uint16_t source_port_last;
  uint16_t destination_port_first;
  uint16_t destination_port_last;
  uint8_t source_prefix_length;
  uint8_t destination_prefix_length;
  uint8_t direction;
  uint8_t protocol;
  uint8_t action;
} product_packet_graph_l4_policy_t;

/*
 * Gate entries use the same normalized predicate shape as the L4 matcher, but
 * allow family/protocol/direction wildcards.  The graph owns a fixed table of
 * these entries; disabled bundle entries are removed before publication.
 */
typedef product_l4_policy_rule_t product_packet_graph_gate_entry_t;

typedef struct
{
  uint32_t entry_count;
  uint32_t max_probes;
  product_packet_graph_gate_entry_t
    entries[PRODUCT_PACKET_GRAPH_GATE_TABLE_MAX_ENTRIES];
} product_packet_graph_gate_table_t;

typedef struct
{
  uint64_t active_generation;
  uint64_t active_revision;
  uint64_t snapshot_hash;
  uint32_t active_entry_count;
  uint32_t max_probes;
  uint64_t rule_id;
  uint64_t last_match_revision;
  uint64_t last_match_rule_id;
  uint32_t last_match_winner_rank;
  uint32_t last_match_probes;
  uint32_t last_match_candidate_count;
  uint32_t last_no_match_reason;
  uint32_t last_match_action;
  uint32_t last_match_reason_id;
  uint64_t drop_records;
  uint64_t last_drop_revision;
  uint64_t last_drop_rule_id;
  uint64_t last_drop_completion_attempts;
  uint32_t subject_uid;
  uint32_t network_context_id;
  uint32_t blocked;
  uint32_t reason_id;
  uint32_t last_drop_uid;
  uint32_t last_drop_network_context;
  uint32_t last_drop_reason_id;
  uint32_t last_drop_verdict;
  uint32_t last_drop_winner;
  uint32_t last_drop_uid_known;
  uint32_t last_drop_device_direction;
} product_packet_graph_gate_status_t;

typedef struct
{
  uint64_t active_revision;
  uint64_t snapshot_hash;
  uint64_t active_generation;
  uint64_t rule_id;
  uint64_t match_records;
  uint64_t no_match_records;
  uint64_t last_match_revision;
  uint64_t last_match_rule_id;
  uint64_t last_evaluation_revision;
  uint32_t subject_uid;
  uint32_t network_context_id;
  uint32_t reason_id;
  uint32_t priority;
  uint32_t order;
  uint32_t direction;
  uint32_t protocol;
  uint32_t action;
  uint32_t last_match_uid;
  uint32_t last_match_network_context;
  uint32_t last_match_reason_id;
  uint32_t last_match_verdict;
  uint32_t last_match_winner;
  uint32_t last_match_uid_known;
  uint32_t last_match_device_direction;
  uint32_t last_match_action;
  uint32_t last_evaluation_result;
  uint32_t last_evaluation_verdict;
  uint32_t last_evaluation_device_direction;
  uint32_t view_active;
  uint32_t view_rule_count;
  uint32_t view_max_probes;
  uint32_t index_subtables;
  uint32_t index_entries;
  uint32_t index_storage_bytes;
  uint32_t index_max_query_work;
  uint32_t last_match_winner_rank;
  uint32_t last_match_probes;
  uint32_t last_match_candidate_count;
  uint32_t last_no_match_reason;
  /* S192 evidence identity.  Keys are zero when no typed evaluation has
   * committed for the current graph generation. */
  uint64_t typed_match_policy_key;
  uint64_t typed_match_probe_key;
  uint64_t last_evaluation_probe_key;
} product_packet_graph_l4_status_t;

typedef enum
{
  PRODUCT_PACKET_GRAPH_POLICY_STAGE_NONE = 0,
  PRODUCT_PACKET_GRAPH_POLICY_STAGE_GATE = 1,
  PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4 = 2,
} product_packet_graph_policy_stage_t;

typedef enum
{
  PRODUCT_PACKET_GRAPH_POLICY_VERDICT_NONE = 0,
  PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT = 1,
  PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP = 2,
} product_packet_graph_policy_verdict_t;

/*
 * The stage result is graph-local evidence.  S192 bundle publications use the
 * immutable product_l4_policy_view matcher; the legacy scalar lookup remains
 * behind this interface only for S191 compatibility.
 */
typedef struct
{
  uint8_t stage;
  uint8_t verdict;
  uint8_t matched;
  uint8_t terminal_preserved;
  uint32_t winner;
  uint64_t generation;
  uint64_t revision;
  uint64_t snapshot_hash;
  uint64_t rule_id;
  uint32_t reason_id;
} product_packet_graph_policy_evaluation_t;

/* Bounded worker-local FlowEntry evidence; this is deliberately not ABI data. */
typedef struct
{
  uint32_t worker_count;
  uint32_t max_entries_per_worker;
  uint32_t active_entries;
  uint64_t active_generation;
  uint64_t active_revision;
  uint64_t active_snapshot_hash;
  uint64_t allocation_count;
  uint64_t reuse_count;
  uint64_t early_drop_count;
  uint64_t wrong_owner_count;
  uint64_t capacity_rejection_count;
  uint64_t revision_invalidation_count;
  uint64_t revision_mismatch_count;
  uint64_t unavailable_count;
  uint64_t pass_next_count;
  uint64_t drop_count;
  uint64_t flush_count;
} product_packet_graph_flow_status_t;

/*
 * One complete graph policy publication.  The caller owns both rule arrays for
 * the duration of the call; the graph copies the GateTable and compiles the L4
 * view into its inactive immutable bank before publishing it.  Rules must
 * already be projected to product_l4_policy_rule_t (IPv4 bytes [0..3], tail
 * zero) and must exclude disabled bundle entries.
 */
typedef struct
{
  uint64_t generation;
  uint64_t revision;
  uint64_t snapshot_hash;
  const product_packet_graph_gate_entry_t *gate_entries;
  uint32_t gate_entry_count;
  const product_l4_policy_rule_t *l4_rules;
  uint32_t l4_rule_count;
} product_packet_graph_policy_bundle_t;

int product_packet_graph_start_external (vlib_main_t *vm, u64 generation);
void product_packet_graph_stop_external (vlib_main_t *vm);

uint32_t product_packet_graph_trace_limit (void);
uint32_t product_packet_graph_worker_count (void);
uint64_t product_packet_graph_hash_seed (void);
uint32_t product_packet_graph_handoff_credits (void);
uint32_t product_packet_graph_enabled (void);
uint32_t product_packet_graph_accepting (void);
uint64_t product_packet_graph_obligation_debt (void);
uint64_t product_packet_graph_buffer_debt (void);
uint64_t product_packet_graph_handoff_debt (void);

void product_packet_graph_publish_gate_policy (
  const product_packet_graph_gate_policy_t *policy);
void product_packet_graph_clear_gate_policy (uint64_t revision,
                                             uint64_t snapshot_hash);
void product_packet_graph_gate_status (
  product_packet_graph_gate_status_t *status);

void product_packet_graph_publish_l4_policy (
  const product_packet_graph_l4_policy_t *policy);
void product_packet_graph_clear_l4_policy (uint64_t revision,
                                            uint64_t snapshot_hash);
void product_packet_graph_l4_status (product_packet_graph_l4_status_t *status);
void product_packet_graph_flow_status (
  product_packet_graph_flow_status_t *status);

/* Typed S192 bundle seam.  Invalid input is rejected before publication. */
product_packet_result_t product_packet_graph_publish_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle);

/* Descriptive alias for control-plane callers that use apply terminology. */
product_packet_result_t product_packet_graph_apply_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle);

product_packet_result_t product_packet_graph_policy_stage (
  product_packet_lease_t *lease,
  product_packet_graph_policy_evaluation_t *evaluation);

/* Platform availability is independent of numeric values. These accessors
 * own the audited ordinary product subgraph only. Generation mismatch returns
 * false and clears availability; no value is used as an unknown sentinel. */
void product_packet_graph_set_platform_facts (vlib_buffer_t *buffer,
                                            const product_platform_packet_facts_t *platform,
                                            uint64_t generation);
int product_packet_graph_get_platform_facts (const vlib_buffer_t *buffer,
                                           uint64_t generation,
                                           product_platform_packet_facts_t *platform);

/*
 * Returns 1 when native frame scheduling accepts buffer ownership. A zero
 * return leaves ownership with the Adapter caller. Completion runs later on
 * the origin worker; acceptance does not mean verdict or buffer return.
 */
int product_packet_graph_submit_external (vlib_main_t *vm, u32 buffer_index,
                                          const product_platform_packet_facts_t *platform,
                                          const product_adapter_obligation_t *obligation);

#endif
