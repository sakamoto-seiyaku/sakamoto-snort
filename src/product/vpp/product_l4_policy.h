/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_L4_POLICY_H
#define SAKAMOTO_PRODUCT_L4_POLICY_H

/*
 * This header is deliberately independent of VPP, Android, Rust, and the
 * public Product ABI.  The VPP graph/adapters project their normalized packet
 * facts into these types at their integration seam.
 */

#include <stddef.h>
#include <stdint.h>

#define PRODUCT_STATIC_EXPRESSION_BYTES 64
#define PRODUCT_STATIC_EXPRESSION_DEPTH 8

/* Fixed source-bytecode contract; see docs/interfaces/T06_STATIC_EXPRESSIONS.md. */
typedef enum {
  PRODUCT_STATIC_AND = 1, PRODUCT_STATIC_OR = 2, PRODUCT_STATIC_NOT = 3,
  PRODUCT_STATIC_FAMILY = 4, PRODUCT_STATIC_PROTOCOL = 5,
  PRODUCT_STATIC_DIRECTION = 6, PRODUCT_STATIC_NETWORK = 7,
  PRODUCT_STATIC_INTERFACE = 8, PRODUCT_STATIC_SOURCE_CIDR = 9,
  PRODUCT_STATIC_DESTINATION_CIDR = 10, PRODUCT_STATIC_SOURCE_PORT = 11,
  PRODUCT_STATIC_DESTINATION_PORT = 12,
  PRODUCT_EXPRESSION_CT_STATE = 13, PRODUCT_EXPRESSION_FLOW_DIRECTION = 14,
  PRODUCT_EXPRESSION_APPLICATION_PROTOCOL = 15
} product_static_opcode_t;

#define PRODUCT_L4_POLICY_MAX_RULES UINT32_C (128)
#define PRODUCT_L4_POLICY_MAX_UID_BUCKETS PRODUCT_L4_POLICY_MAX_RULES
#define PRODUCT_L4_POLICY_MAX_PROBES PRODUCT_L4_POLICY_MAX_RULES
#define PRODUCT_L4_POLICY_MAX_SUBJECT_PROBES UINT32_C (16)
#define PRODUCT_L4_POLICY_ADDRESS_BYTES UINT32_C (16)

#define PRODUCT_L4_POLICY_FAMILY_IPV4 UINT8_C (4)
#define PRODUCT_L4_POLICY_FAMILY_IPV6 UINT8_C (6)

#define PRODUCT_L4_POLICY_PROTOCOL_TCP UINT8_C (6)
#define PRODUCT_L4_POLICY_PROTOCOL_UDP UINT8_C (17)

/* Device direction intentionally follows the existing packet-graph domain. */
#define PRODUCT_L4_POLICY_DIRECTION_ANY UINT8_C (0)
#define PRODUCT_L4_POLICY_DIRECTION_INPUT UINT8_C (1)
#define PRODUCT_L4_POLICY_DIRECTION_OUTPUT UINT8_C (3)

#define PRODUCT_L4_POLICY_ACTION_NONE UINT8_C (0)
#define PRODUCT_L4_POLICY_ACTION_ALLOW UINT8_C (1)
#define PRODUCT_L4_POLICY_ACTION_DROP UINT8_C (2)

/* ALLOW continues packet/Flow processing with the complete winner retained. */
#define PRODUCT_L4_POLICY_VERDICT_PASS_NEXT UINT8_C (0)
#define PRODUCT_L4_POLICY_VERDICT_DROP UINT8_C (1)

#define PRODUCT_L4_POLICY_EVALUATION_NO_MATCH UINT8_C (0)
#define PRODUCT_L4_POLICY_EVALUATION_MATCH UINT8_C (1)

/* UINT32_MAX is a wildcard for dimensions that have an any value. */
#define PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY UINT32_MAX
#define PRODUCT_L4_POLICY_IFINDEX_ANY UINT32_MAX
#define PRODUCT_L4_POLICY_PORT_FIRST_ANY UINT16_C (0)
#define PRODUCT_L4_POLICY_PORT_LAST_ANY UINT16_MAX

typedef enum
{
  PRODUCT_L4_POLICY_STATUS_OK = 0,
  PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT,
  PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED,
  PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
  PRODUCT_L4_POLICY_STATUS_DUPLICATE_RULE_ID,
  PRODUCT_L4_POLICY_STATUS_NOT_FOUND,
} product_l4_policy_status_t;

typedef enum
{
  PRODUCT_L4_POLICY_NO_MATCH_NONE = 0,
  PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID,
  PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_FAMILY,
  PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_PROTOCOL,
  PRODUCT_L4_POLICY_NO_MATCH_L4_UNAVAILABLE,
  PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_DIRECTION,
  PRODUCT_L4_POLICY_NO_MATCH_NO_SUBJECT,
  PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
} product_l4_policy_no_match_reason_t;

/*
 * A source rule.  rule_id and reason_id are nonzero stable identities; uid
 * must be a complete UID rather than UINT32_MAX.  IPv4 addresses use the
 * first four bytes in network order and require bytes 4..15 to be zero; IPv6
 * uses all sixteen bytes. Family zero is a wildcard and requires zero address
 * bytes and prefixes. Protocol zero is a wildcard; port predicates still need
 * available TCP/UDP ports. A zero prefix means any address in that family.
 */
typedef struct
{
  uint32_t expression_length;
  uint8_t expression[PRODUCT_STATIC_EXPRESSION_BYTES];
  uint64_t rule_id;
  uint32_t uid;
  uint32_t network_context_id;
  uint32_t ifindex;
  uint32_t priority;
  uint32_t order;
  uint32_t reason_id;
  uint16_t source_port_first;
  uint16_t source_port_last;
  uint16_t destination_port_first;
  uint16_t destination_port_last;
  uint8_t family;
  uint8_t protocol;
  uint8_t direction;
  uint8_t source_prefix_length;
  uint8_t destination_prefix_length;
  uint8_t action;
  uint8_t mode; /* 0 enforce, 1 observe; zero preserves direct-rule callers. */
  uint8_t source_address[PRODUCT_L4_POLICY_ADDRESS_BYTES];
  uint8_t destination_address[PRODUCT_L4_POLICY_ADDRESS_BYTES];
} product_l4_policy_rule_t;

/* Normalized packet-local input projected from the shared VPP PacketFacts. */
typedef struct
{
  uint32_t uid;
  uint32_t network_context_id;
  uint32_t ifindex;
  uint16_t source_port;
  uint16_t destination_port;
  uint8_t family;
  uint8_t protocol;
  uint8_t direction;
  uint8_t uid_known;
  uint8_t direction_known;
  uint8_t network_context_known;
  uint8_t ifindex_known;
  /* False makes only port-dependent rules no-match; other predicates remain
   * evaluable. */
  uint8_t ports_available;
  uint8_t source_address[PRODUCT_L4_POLICY_ADDRESS_BYTES];
  uint8_t destination_address[PRODUCT_L4_POLICY_ADDRESS_BYTES];
  uint8_t ct_state; /* NEW=1, ESTABLISHED=2, INVALID=3; not transport state. */
  uint8_t flow_direction; /* ORIG=1, REPLY=2, independent of device direction. */
  uint8_t ct_state_known;
  uint8_t flow_direction_known;
  uint64_t protocol_set; /* Stable catalog bit projection, all published facts. */
  uint8_t protocol_set_known;
} product_l4_policy_packet_t;

typedef struct
{
  product_l4_policy_rule_t source;
  uint32_t winner_rank;
  uint8_t position;
  uint8_t plan;
  uint16_t factor_first[2], factor_last[2];
} product_l4_policy_compiled_rule_t;

typedef struct
{
  uint32_t uid;
  uint32_t first_rule;
  uint32_t rule_count;
  uint8_t requires_flow; /* At least one whole rule is post-flow. */
  uint8_t dependencies; /* Conservative union for the entire application. */
} product_l4_policy_uid_bucket_t;

/* Private fixed candidate index; entries always refer to whole rules. */
#define PRODUCT_L4_DIRECT_ENTRIES 32
#define PRODUCT_L4_INDEX_ENTRIES 256
#define PRODUCT_L4_PLAN_DIRECT 1
#define PRODUCT_L4_PLAN_FACTORIZED 2
#define PRODUCT_L4_PLAN_RESIDUAL 3
#define PRODUCT_L4_CONDITION_ITEMS (PRODUCT_L4_POLICY_MAX_RULES * (PRODUCT_STATIC_EXPRESSION_BYTES + 9))
#define PRODUCT_L4_COMPILE_PEAK_LIMIT (384U * 1024U)
#define PRODUCT_L4_INDEX_KEY_BYTES 42
#define PRODUCT_L4_INDEX_SLOTS 16
#define PRODUCT_L4_INDEX_NONE UINT16_MAX

typedef struct {
  uint8_t mask[PRODUCT_L4_INDEX_KEY_BYTES];
  uint16_t heads[PRODUCT_L4_INDEX_SLOTS];
  uint16_t first_rank;
  uint16_t subject;
} product_l4_policy_subtable_t;

typedef struct {
  uint8_t key[PRODUCT_L4_INDEX_KEY_BYTES];
  uint16_t next, rule;
} product_l4_policy_index_entry_t;

typedef struct {
  uint32_t subtables, entries, storage_bytes, max_query_work;
} product_l4_policy_index_resources_t;

/* Native compiler seam, not a source-format setting or cross-language ABI.
 * Budgets may reduce optimization, but never permit incomplete evaluation.
 * Fixed storage bounds are counted even when only part of an array is used. */
typedef struct {
  uint32_t direct_entries, index_entries, factor_rules, condition_items, peak_bytes;
} product_l4_policy_compile_budget_t;

typedef struct {
  uint32_t direct_rules, factorized_rules, residual_rules, condition_items;
  uint32_t query_state_bytes, compile_scratch_bytes, publication_peak_bytes;
} product_l4_policy_plan_resources_t;

/*
 * Fixed storage makes the compiled view usable from a VPP worker without a
 * hot-path allocation.  The arrays are an implementation detail for callers;
 * evaluation and rank lookup are the stable module interface.
 */
typedef struct
{
  uint32_t rule_count;
  uint32_t uid_bucket_count;
  uint32_t max_probes;
  uint32_t subtable_count;
  uint32_t entry_count;
  product_l4_policy_subtable_t subtables[PRODUCT_L4_INDEX_ENTRIES];
  product_l4_policy_index_entry_t entries[PRODUCT_L4_INDEX_ENTRIES];
  product_l4_policy_compiled_rule_t rules[PRODUCT_L4_POLICY_MAX_RULES];
  product_l4_policy_uid_bucket_t
    uid_buckets[PRODUCT_L4_POLICY_MAX_UID_BUCKETS];
} product_l4_policy_view_t;

typedef struct
{
  uint8_t evaluation;
  uint8_t stage_verdict;
  uint8_t action;
  uint8_t no_match_reason;
  uint8_t mode;
  uint8_t actual_action;
  uint64_t rule_id;
  uint32_t reason_id;
  uint32_t priority;
  uint32_t order;
  uint32_t winner_rank;
  uint32_t probes;
  uint32_t probe_limit;
  uint32_t subject_probes;
  uint32_t candidate_count;
  uint32_t subtable_probes;
  uint32_t key_probes;
} product_l4_policy_match_result_t;

product_l4_policy_status_t product_static_expression_validate (const uint8_t *, uint32_t);

/* Position is snapshot-owned; a rule is evaluated wholly at exactly one side.
 * ALL remains the complete ordered semantic seam. PRE NoMatch is not final;
 * PRE Match preserves the entire result across flow observation. */
typedef enum {
  PRODUCT_L4_POLICY_POSITION_ALL = 0,
  PRODUCT_L4_POLICY_POSITION_PRE = 1,
  PRODUCT_L4_POLICY_POSITION_POST = 2
} product_l4_policy_position_t;
product_l4_policy_status_t product_l4_policy_match_position (
  const product_l4_policy_view_t *, const product_l4_policy_packet_t *,
  product_l4_policy_position_t, product_l4_policy_match_result_t *);

/* Only placement is queried; no partial matching or candidate filtering. */
int product_l4_policy_requires_flow (const product_l4_policy_view_t *, uint32_t uid);

void product_l4_policy_index_resources (const product_l4_policy_view_t *,
                                        product_l4_policy_index_resources_t *);

product_l4_policy_compile_budget_t product_l4_policy_default_budget (void);
void product_l4_policy_plan_resources (const product_l4_policy_view_t *,
                                       product_l4_policy_plan_resources_t *);
product_l4_policy_status_t product_l4_policy_compile_with_budget (
  product_l4_policy_view_t *, const product_l4_policy_rule_t *, size_t,
  const product_l4_policy_compile_budget_t *);

void product_l4_policy_init (product_l4_policy_view_t *view);

product_l4_policy_status_t
product_l4_policy_compile (product_l4_policy_view_t *view,
                           const product_l4_policy_rule_t *rules,
                           size_t rule_count);

product_l4_policy_status_t
product_l4_policy_match (const product_l4_policy_view_t *view,
                         const product_l4_policy_packet_t *packet,
                         product_l4_policy_match_result_t *result);

/* Descriptive alias for callers that prefer the stage-evaluation name. */
product_l4_policy_status_t
product_l4_policy_evaluate (const product_l4_policy_view_t *view,
                            const product_l4_policy_packet_t *packet,
                            product_l4_policy_match_result_t *result);

product_l4_policy_status_t
product_l4_policy_rule_rank (const product_l4_policy_view_t *view,
                             uint64_t rule_id, uint32_t *winner_rank);

/* Dependency contract: all static values/availability are conservatively
 * guarded. Dynamic producers must add their dependency and canonical projection
 * here before their predicates can be cached. Never summarize only the winner. */
#define PRODUCT_POLICY_DEP_STATIC 1U
#define PRODUCT_POLICY_DEP_CT 2U
#define PRODUCT_POLICY_DEP_LPI 4U
#define PRODUCT_POLICY_CACHE_CAPACITY 128U
#define PRODUCT_POLICY_CACHE_MAX_CAPACITY 128U

typedef struct {
  uint64_t generation, revision, snapshot_hash, flow_incarnation;
} product_policy_cache_identity_t;

typedef struct {
  product_policy_cache_identity_t identity;
  product_l4_policy_packet_t packet;
  uint32_t position;
  uint32_t dependencies;
} product_policy_cache_guard_t;

typedef struct {
  product_policy_cache_guard_t guard;
  product_l4_policy_match_result_t result;
  uint8_t valid;
} product_policy_cache_entry_t;

typedef struct {
  /* Zero chooses the measured default. Set once before owner admission;
   * storage is fixed even for a smaller active capacity. */
  uint32_t capacity, occupied;
  uint64_t hits, misses, replacements;
  product_policy_cache_entry_t entries[PRODUCT_POLICY_CACHE_MAX_CAPACITY];
} product_policy_cache_t;

/* Owner-only synchronous operation; NULL cache means ordinary matching.
 * No borrowed view/Flow pointer survives. Identity is from the protected packet
 * snapshot and the current observation, never a slot index or a fact version.
 * Full semantic results are retained; leaf/index work is zero on hits.
 * subject_probes includes the guard dependency lookup on both paths.
 * Errors are never cached. Caller owns the common attribution/accounting path. */
product_l4_policy_status_t product_l4_policy_match_cached (
  product_policy_cache_t *, const product_l4_policy_view_t *,
  const product_l4_policy_packet_t *, const product_policy_cache_identity_t *,
  product_l4_policy_position_t, product_l4_policy_match_result_t *);

#endif
