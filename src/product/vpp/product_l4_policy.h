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

/* An early-stage allow continues to the next stage. */
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
 * uses all sixteen bytes.  A prefix length of zero means any address within
 * the explicitly selected family.
 */
typedef struct
{
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
} product_l4_policy_packet_t;

typedef struct
{
  product_l4_policy_rule_t source;
  uint32_t winner_rank;
} product_l4_policy_compiled_rule_t;

typedef struct
{
  uint32_t uid;
  uint32_t first_rule;
  uint32_t rule_count;
} product_l4_policy_uid_bucket_t;

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
  uint64_t rule_id;
  uint32_t reason_id;
  uint32_t priority;
  uint32_t order;
  uint32_t winner_rank;
  uint32_t probes;
  uint32_t probe_limit;
  uint32_t subject_probes;
  uint32_t candidate_count;
} product_l4_policy_match_result_t;

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

#endif
