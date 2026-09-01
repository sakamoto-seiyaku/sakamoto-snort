/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_PACKET_GRAPH_H
#define SAKAMOTO_PRODUCT_PACKET_GRAPH_H

#include "product_packet.h"
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

/*
 * Policy-hint direction is the normalized Device Packet Direction: INPUT is
 * 1 and OUTPUT is 3.  interface_id remains adapter interface/provenance
 * metadata and is never a direction source.  In particular, VPN TUN-origin
 * packets retain their TUN provenance in interface_id while callers provide
 * OUTPUT in profile_id; flow-stack return packets leave profile_id unknown.
 */

typedef void (*product_packet_graph_completion_fn_t) (
  vlib_main_t *vm, u32 buffer_index, const product_packet_lease_t *lease,
  u64 origin_obligation_id,
  product_packet_terminal_intent_t terminal_intent,
  product_packet_runtime_drop_reason_t runtime_drop_reason, void *opaque);

typedef struct
{
  u16 arrival_worker;
  u16 owner_worker;
  u8 primary_remote;
} product_packet_graph_external_result_t;

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

/*
 * S191 deliberately carries one stateless IPv4/TCP classifier.  Its scalar
 * addresses are network-order u32 values; they are not the byte-array
 * address projection used by the future multi-rule matcher.
 */
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

typedef struct
{
  uint64_t active_revision;
  uint64_t snapshot_hash;
  uint64_t rule_id;
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
  uint32_t last_match_winner_rank;
  uint32_t last_match_probes;
  uint32_t last_match_candidate_count;
  uint32_t last_no_match_reason;
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
  uint64_t revision;
  uint64_t rule_id;
  uint32_t reason_id;
} product_packet_graph_policy_evaluation_t;

/*
 * One complete graph policy publication.  The caller owns l4_rules for the
 * duration of the call; the graph compiles a private copy into its inactive
 * immutable bank before publishing it.  Rules must already be projected to
 * product_l4_policy_rule_t (IPv4 bytes [0..3], tail zero) and must exclude
 * disabled bundle entries.  A bundle currently carries at most one blocked
 * Gate claim because the existing Gate stage is scalar; L4 supports the full
 * bounded matcher view.
 */
typedef struct
{
  uint64_t generation;
  uint64_t revision;
  uint64_t snapshot_hash;
  const product_l4_policy_rule_t *l4_rules;
  uint32_t l4_rule_count;
  uint8_t gate_present;
  uint8_t reserved[3];
  product_packet_graph_gate_policy_t gate;
} product_packet_graph_policy_bundle_t;

int product_packet_graph_start_external (vlib_main_t *vm, u64 generation);
void product_packet_graph_stop_external (vlib_main_t *vm);

uint32_t product_packet_graph_worker_count (void);
uint32_t product_packet_graph_flow_domain (void);
uint64_t product_packet_graph_hash_seed (void);
uint32_t product_packet_graph_handoff_credits (void);
uint32_t product_packet_graph_enabled (void);
uint32_t product_packet_graph_accepting (void);
uint64_t product_packet_graph_obligation_debt (void);
uint64_t product_packet_graph_buffer_debt (void);
uint64_t product_packet_graph_handoff_debt (void);

void product_packet_graph_register_external_completion (
  product_packet_graph_completion_fn_t completion, void *opaque);

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

/* Typed S192 bundle seam.  Invalid input is rejected before publication. */
product_packet_result_t product_packet_graph_publish_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle);

/* Descriptive alias for control-plane callers that use apply terminology. */
product_packet_result_t product_packet_graph_apply_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle);

product_packet_result_t product_packet_graph_policy_stage (
  product_packet_lease_t *lease,
  product_packet_graph_policy_evaluation_t *evaluation);

/*
 * Adapters may attach only compact policy hints to the VPP buffer.  The
 * packet graph validates the generation before consuming them, so stale
 * buffers cannot reuse a previous packet's subject or network context.
 * `profile_id` is the normalized Device Packet Direction; `interface_id`
 * carries adapter interface/provenance and must not be reinterpreted as
 * direction by the graph.
 */
void product_packet_graph_set_policy_hints (vlib_buffer_t *buffer,
                                            const product_packet_hints_t *hints,
                                            uint16_t generation);
int product_packet_graph_get_policy_hints (const vlib_buffer_t *buffer,
                                           uint16_t generation,
                                           product_packet_hints_t *hints);

int product_packet_graph_submit_external (vlib_main_t *vm, u32 buffer_index,
                                          const product_packet_hints_t *hints,
                                          u64 origin_obligation_id,
                                          product_packet_graph_external_result_t
                                            *external_result);

#endif
