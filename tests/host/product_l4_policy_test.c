/* SPDX-License-Identifier: Apache-2.0 */

#include "product_l4_policy.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(condition, message)                                             \
  do                                                                          \
    {                                                                         \
      if (!(condition))                                                       \
        {                                                                     \
          fprintf (stderr, "FAIL: %s\n", (message));                         \
          failures++;                                                         \
        }                                                                     \
    }                                                                         \
  while (0)

#define CHECK_STATUS(actual, expected, message)                                \
  CHECK ((actual) == (expected), (message))

static product_l4_policy_rule_t
rule_template (uint64_t rule_id, uint32_t uid, uint8_t family,
               uint8_t protocol, uint32_t priority, uint32_t order,
               uint8_t action)
{
  product_l4_policy_rule_t rule;
  memset (&rule, 0, sizeof (rule));
  rule.rule_id = rule_id;
  rule.uid = uid;
  rule.network_context_id = PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY;
  rule.ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
  rule.priority = priority;
  rule.order = order;
  rule.reason_id = (uint32_t) rule_id + 1000U;
  rule.source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  rule.source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  rule.destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
  rule.destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
  rule.family = family;
  rule.protocol = protocol;
  rule.direction = PRODUCT_L4_POLICY_DIRECTION_ANY;
  rule.action = action;
  rule.source_prefix_length = 0;
  rule.destination_prefix_length = 0;
  return rule;
}

static product_l4_policy_packet_t
packet_template (uint32_t uid, uint8_t family, uint8_t protocol,
                 uint16_t source_port, uint16_t destination_port)
{
  product_l4_policy_packet_t packet;
  memset (&packet, 0, sizeof (packet));
  packet.uid = uid;
  packet.uid_known = 1;
  packet.family = family;
  packet.protocol = protocol;
  packet.direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
  packet.direction_known = 1;
  packet.network_context_id = 9;
  packet.network_context_known = 1;
  packet.ifindex = 42;
  packet.ifindex_known = 1;
  packet.source_port = source_port;
  packet.destination_port = destination_port;
  packet.ports_available = 1;
  return packet;
}

static void
set_ipv4 (uint8_t address[PRODUCT_L4_POLICY_ADDRESS_BYTES], uint32_t value)
{
  memset (address, 0, PRODUCT_L4_POLICY_ADDRESS_BYTES);
  address[0] = (uint8_t) (value >> 24);
  address[1] = (uint8_t) (value >> 16);
  address[2] = (uint8_t) (value >> 8);
  address[3] = (uint8_t) value;
}

static void
set_ipv6 (uint8_t address[PRODUCT_L4_POLICY_ADDRESS_BYTES], uint8_t seed)
{
  size_t index;
  for (index = 0; index < PRODUCT_L4_POLICY_ADDRESS_BYTES; index++)
    address[index] = (uint8_t) (seed + index);
}

static product_l4_policy_match_result_t
match (const product_l4_policy_view_t *view,
       const product_l4_policy_packet_t *packet)
{
  product_l4_policy_match_result_t result;
  CHECK_STATUS (product_l4_policy_match (view, packet, &result),
                PRODUCT_L4_POLICY_STATUS_OK,
                "matcher call must return status OK for packet outcomes");
  return result;
}

static void
check_result_match (const product_l4_policy_match_result_t *result,
                    uint64_t rule_id, uint32_t rank, uint8_t action,
                    uint8_t verdict, const char *message)
{
  CHECK (result->evaluation == PRODUCT_L4_POLICY_EVALUATION_MATCH, message);
  CHECK (result->rule_id == rule_id, "winner rule id must be stable");
  CHECK (result->winner_rank == rank, "winner rank must be exposed");
  CHECK (result->action == action, "winner action must be exposed");
  CHECK (result->stage_verdict == verdict,
         "stage verdict must follow allow/drop semantics");
  CHECK (result->reason_id == (uint32_t) rule_id + 1000U,
         "winner reason id must be exposed");
  CHECK (result->no_match_reason == PRODUCT_L4_POLICY_NO_MATCH_NONE,
         "a match must not carry a no-match reason");
}

static void
check_no_match (const product_l4_policy_match_result_t *result,
                uint8_t reason, const char *message)
{
  CHECK (result->evaluation == PRODUCT_L4_POLICY_EVALUATION_NO_MATCH, message);
  CHECK (result->stage_verdict == PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
         "no-match must pass to the next stage");
  CHECK (result->action == PRODUCT_L4_POLICY_ACTION_NONE,
         "no-match must not expose an action");
  CHECK (result->winner_rank == 0 && result->rule_id == 0,
         "no-match must not expose a winner");
  CHECK (result->no_match_reason == reason,
         "no-match reason must identify the bounded fallback");
}

static void
test_four_family_protocols (void)
{
  product_l4_policy_rule_t rules[4];
  product_l4_policy_view_t view;
  product_l4_policy_packet_t packet;
  product_l4_policy_match_result_t result;
  size_t index;

  rules[0] = rule_template (401, 401, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  rules[1] = rule_template (402, 402, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_UDP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  rules[2] = rule_template (403, 403, PRODUCT_L4_POLICY_FAMILY_IPV6,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  rules[3] = rule_template (404, 404, PRODUCT_L4_POLICY_FAMILY_IPV6,
                            PRODUCT_L4_POLICY_PROTOCOL_UDP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  product_l4_policy_init (&view);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 4),
                PRODUCT_L4_POLICY_STATUS_OK,
                "all four family/protocol combinations must compile");
  for (index = 0; index < 4; index++)
    {
      packet = packet_template (rules[index].uid, rules[index].family,
                                rules[index].protocol, 1234, 443);
      if (packet.family == PRODUCT_L4_POLICY_FAMILY_IPV4)
        {
          set_ipv4 (packet.source_address, UINT32_C (0xc0000201));
          set_ipv4 (packet.destination_address, UINT32_C (0xc6336402));
        }
      else
        {
          set_ipv6 (packet.source_address, 1);
          set_ipv6 (packet.destination_address, 33);
        }
      result = match (&view, &packet);
      check_result_match (&result, rules[index].rule_id, 1,
                          rules[index].action,
                          rules[index].action == PRODUCT_L4_POLICY_ACTION_DROP
                            ? PRODUCT_L4_POLICY_VERDICT_DROP
                            : PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
                          "each family/protocol pair must match its subject");
      CHECK (result.probes <= 1 && result.probe_limit == 1,
             "one-rule subject must expose one bounded candidate probe");
    }
}

static void
test_precedence_and_ranks (void)
{
  product_l4_policy_rule_t rules[4];
  product_l4_policy_view_t view;
  product_l4_policy_packet_t packet;
  product_l4_policy_match_result_t result;
  uint32_t rank;

  rules[0] = rule_template (100, 7, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 20, 0,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  rules[1] = rule_template (20, 7, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 10, 9,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  rules[2] = rule_template (10, 7, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 10, 9,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  rules[3] = rule_template (5, 7, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 10, 9,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  product_l4_policy_init (&view);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 4),
                PRODUCT_L4_POLICY_STATUS_OK,
                "overlapping rules with all tie keys must compile");
  packet = packet_template (7, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 2);
  result = match (&view, &packet);
  check_result_match (&result, 5, 1, PRODUCT_L4_POLICY_ACTION_ALLOW,
                      PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
                      "priority then order then rule id must select one winner");
  CHECK (result.priority == 10 && result.order == 9,
         "winner must expose its source precedence fields");
  CHECK_STATUS (product_l4_policy_rule_rank (&view, 5, &rank),
                PRODUCT_L4_POLICY_STATUS_OK,
                "rank lookup must find a compiled rule");
  CHECK (rank == 1, "best precedence rule must have rank one");
  CHECK_STATUS (product_l4_policy_rule_rank (&view, 10, &rank),
                PRODUCT_L4_POLICY_STATUS_OK,
                "rank lookup must expose all rule ranks");
  CHECK (rank == 2, "same-level lower rule id must have the next rank");
  CHECK_STATUS (product_l4_policy_rule_rank (&view, 20, &rank),
                PRODUCT_L4_POLICY_STATUS_OK,
                "rank lookup must expose the third rule");
  CHECK (rank == 3, "same-level order tie must remain consecutive");
  CHECK_STATUS (product_l4_policy_rule_rank (&view, 100, &rank),
                PRODUCT_L4_POLICY_STATUS_OK,
                "rank lookup must expose the lower-priority rule");
  CHECK (rank == 4, "all ranks must be consecutive within a UID subject");
  CHECK_STATUS (product_l4_policy_rule_rank (&view, 999, &rank),
                PRODUCT_L4_POLICY_STATUS_NOT_FOUND,
                "unknown rule rank must be explicit");
  CHECK (rank == 0, "unknown rule rank must not fabricate a rank");
}

static void
test_cidr_and_ports (void)
{
  product_l4_policy_rule_t rules[3];
  product_l4_policy_view_t view;
  product_l4_policy_packet_t packet;
  product_l4_policy_match_result_t result;

  rules[0] = rule_template (501, 8, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  set_ipv4 (rules[0].source_address, UINT32_C (0xc0000200));
  set_ipv4 (rules[0].destination_address, UINT32_C (0xc6336402));
  rules[0].source_prefix_length = 24;
  rules[0].destination_prefix_length = 32;
  rules[0].source_port_first = 1000;
  rules[0].source_port_last = 2000;
  rules[0].destination_port_first = 443;
  rules[0].destination_port_last = 443;

  rules[1] = rule_template (502, 8, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 2, 1,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  set_ipv4 (rules[1].destination_address, UINT32_C (0xc6336402));
  rules[1].destination_prefix_length = 32;
  rules[1].destination_port_first = 8443;
  rules[1].destination_port_last = 8443;

  rules[2] = rule_template (503, 8, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 3, 1,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  rules[2].source_port_first = 3000;
  rules[2].source_port_last = 3010;
  rules[2].destination_port_first = 9000;
  rules[2].destination_port_last = 9010;

  product_l4_policy_init (&view);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 3),
                PRODUCT_L4_POLICY_STATUS_OK,
                "CIDR and port range rules must compile");
  packet = packet_template (8, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1500, 443);
  set_ipv4 (packet.source_address, UINT32_C (0xc0000217));
  set_ipv4 (packet.destination_address, UINT32_C (0xc6336402));
  result = match (&view, &packet);
  check_result_match (&result, 501, 1, PRODUCT_L4_POLICY_ACTION_DROP,
                      PRODUCT_L4_POLICY_VERDICT_DROP,
                      "IPv4 CIDR and inclusive source/destination ports must match");

  packet.source_port = 2500;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
                  "outside source port range must no-match");

  packet.source_port = 1500;
  packet.destination_port = 8443;
  result = match (&view, &packet);
  check_result_match (&result, 502, 2, PRODUCT_L4_POLICY_ACTION_ALLOW,
                      PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
                      "exact destination port must select the matching rule");

  packet.source_port = 3005;
  packet.destination_port = 9005;
  result = match (&view, &packet);
  check_result_match (&result, 503, 3, PRODUCT_L4_POLICY_ACTION_ALLOW,
                      PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
                      "inclusive source and destination ranges must match");

  rules[0] = rule_template (504, 8, PRODUCT_L4_POLICY_FAMILY_IPV6,
                            PRODUCT_L4_POLICY_PROTOCOL_UDP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  set_ipv6 (rules[0].source_address, 0x20);
  set_ipv6 (rules[0].destination_address, 0x40);
  rules[0].source_prefix_length = 64;
  rules[0].destination_prefix_length = 96;
  rules[0].source_port_first = 6000;
  rules[0].source_port_last = 6010;
  rules[0].destination_port_first = 53;
  rules[0].destination_port_last = 53;
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 1),
                PRODUCT_L4_POLICY_STATUS_OK,
                "IPv6 CIDR and UDP rule must compile");
  packet = packet_template (8, PRODUCT_L4_POLICY_FAMILY_IPV6,
                            PRODUCT_L4_POLICY_PROTOCOL_UDP, 6005, 53);
  set_ipv6 (packet.source_address, 0x20);
  set_ipv6 (packet.destination_address, 0x40);
  result = match (&view, &packet);
  check_result_match (&result, 504, 1, PRODUCT_L4_POLICY_ACTION_DROP,
                      PRODUCT_L4_POLICY_VERDICT_DROP,
                      "IPv6 CIDR and UDP port predicates must match equally");
}

static void
test_context_direction_and_uid (void)
{
  product_l4_policy_rule_t rules[3];
  product_l4_policy_view_t view;
  product_l4_policy_packet_t packet;
  product_l4_policy_match_result_t result;

  rules[0] = rule_template (601, 11, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  rules[0].network_context_id = 7;
  rules[0].ifindex = 42;
  rules[0].direction = PRODUCT_L4_POLICY_DIRECTION_INPUT;
  rules[1] = rule_template (602, 11, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 2, 1,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  rules[1].network_context_id = 7;
  rules[1].ifindex = 42;
  rules[1].direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
  rules[2] = rule_template (603, 12, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  rules[2].network_context_id = 7;
  rules[2].ifindex = 42;
  rules[2].direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT;

  product_l4_policy_init (&view);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 3),
                PRODUCT_L4_POLICY_STATUS_OK,
                "context, ifindex, direction, and UID rules must compile");
  packet = packet_template (11, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 2);
  packet.network_context_id = 7;
  packet.ifindex = 42;
  packet.direction = PRODUCT_L4_POLICY_DIRECTION_INPUT;
  result = match (&view, &packet);
  check_result_match (&result, 601, 1, PRODUCT_L4_POLICY_ACTION_DROP,
                      PRODUCT_L4_POLICY_VERDICT_DROP,
                      "input direction and matching context must select rule");

  packet.direction = PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
  result = match (&view, &packet);
  check_result_match (&result, 602, 2, PRODUCT_L4_POLICY_ACTION_ALLOW,
                      PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
                      "output direction must select the output rule");

  packet.network_context_id = 8;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
                  "wrong network context must no-match");

  packet.network_context_id = 7;
  packet.ifindex = 43;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
                  "wrong ifindex must no-match");

  packet.ifindex = 42;
  packet.network_context_known = 0;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
                  "unknown concrete network context must no-match");

  rules[0] = rule_template (604, 13, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 1),
                PRODUCT_L4_POLICY_STATUS_OK,
                "wildcard context rule must compile");
  packet.uid = 13;
  packet.network_context_known = 0;
  result = match (&view, &packet);
  check_result_match (&result, 604, 1, PRODUCT_L4_POLICY_ACTION_DROP,
                      PRODUCT_L4_POLICY_VERDICT_DROP,
                      "wildcard context may match without context evidence");

  packet.uid_known = 0;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID,
                  "unknown complete UID must never produce a policy winner");
  packet.uid_known = 1;
  packet.uid = UINT32_MAX;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID,
                  "unknown UID sentinel must never produce a policy winner");
  packet.uid = 999;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_NO_SUBJECT,
                  "known UID without a subject view must no-match");
}

static void
test_unsupported_and_unavailable (void)
{
  product_l4_policy_rule_t rules[2];
  product_l4_policy_rule_t port_only;
  product_l4_policy_view_t view;
  product_l4_policy_packet_t packet =
    packet_template (17, PRODUCT_L4_POLICY_FAMILY_IPV4,
                     PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 2);
  product_l4_policy_match_result_t result;

  rules[0] = rule_template (701, 17, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  rules[0].destination_port_first = 443;
  rules[0].destination_port_last = 443;
  rules[1] = rule_template (702, 17, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 2, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  product_l4_policy_init (&view);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 2),
                PRODUCT_L4_POLICY_STATUS_OK,
                "unsupported-input test rule must compile");
  packet.ports_available = 0;
  result = match (&view, &packet);
  check_result_match (&result, 702, 2, PRODUCT_L4_POLICY_ACTION_DROP,
                      PRODUCT_L4_POLICY_VERDICT_DROP,
                      "unavailable ports must skip only port-dependent rules");
  CHECK (result.probes <= 2 && result.probe_limit == 2,
         "unavailable ports must retain a bounded candidate scan");

  port_only = rules[0];
  CHECK_STATUS (product_l4_policy_compile (&view, &port_only, 1),
                PRODUCT_L4_POLICY_STATUS_OK,
                "port-only rule must compile for unavailable-L4 fallback");
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_L4_UNAVAILABLE,
                  "port-only rule must no-match when ports are unavailable");
  CHECK (result.probes <= 1 && result.probe_limit == 1,
         "port-only unavailable lookup must remain bounded and observable");

  rules[1] = rule_template (703, 17, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 2, 1,
                            PRODUCT_L4_POLICY_ACTION_ALLOW);
  CHECK_STATUS (product_l4_policy_compile (&view, rules, 2),
                PRODUCT_L4_POLICY_STATUS_OK,
                "allow fallback rule must compile");
  result = match (&view, &packet);
  check_result_match (&result, 703, 2, PRODUCT_L4_POLICY_ACTION_ALLOW,
                      PRODUCT_L4_POLICY_VERDICT_PASS_NEXT,
                      "unavailable ports must preserve allow semantics for"
                      " non-port rules");

  packet.ports_available = 1;
  packet.family = 5;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_FAMILY,
                  "unsupported family must be PASS_NEXT with no winner");
  packet.family = PRODUCT_L4_POLICY_FAMILY_IPV4;
  packet.protocol = 1;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_NO_RULE,
                  "unsupported protocol must be PASS_NEXT with no winner");
  packet.protocol = PRODUCT_L4_POLICY_PROTOCOL_TCP;
  packet.direction_known = 1;
  packet.direction = 2;
  result = match (&view, &packet);
  check_no_match (&result, PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_DIRECTION,
                  "unsupported direction must be PASS_NEXT with no winner");
  CHECK (result.stage_verdict != PRODUCT_L4_POLICY_VERDICT_DROP,
         "unsupported facts must never become a policy drop");
}

static void
test_permutation_invariance (void)
{
  product_l4_policy_rule_t original[6];
  product_l4_policy_rule_t permuted[6];
  product_l4_policy_view_t first;
  product_l4_policy_view_t second;
  product_l4_policy_packet_t packet;
  product_l4_policy_match_result_t left;
  product_l4_policy_match_result_t right;
  size_t index;

  original[0] = rule_template (801, 18, PRODUCT_L4_POLICY_FAMILY_IPV4,
                               PRODUCT_L4_POLICY_PROTOCOL_TCP, 20, 1,
                               PRODUCT_L4_POLICY_ACTION_ALLOW);
  original[1] = rule_template (802, 18, PRODUCT_L4_POLICY_FAMILY_IPV4,
                               PRODUCT_L4_POLICY_PROTOCOL_TCP, 5, 7,
                               PRODUCT_L4_POLICY_ACTION_DROP);
  original[2] = rule_template (803, 18, PRODUCT_L4_POLICY_FAMILY_IPV4,
                               PRODUCT_L4_POLICY_PROTOCOL_TCP, 5, 2,
                               PRODUCT_L4_POLICY_ACTION_ALLOW);
  original[3] = rule_template (804, 18, PRODUCT_L4_POLICY_FAMILY_IPV4,
                               PRODUCT_L4_POLICY_PROTOCOL_TCP, 5, 2,
                               PRODUCT_L4_POLICY_ACTION_DROP);
  original[4] = rule_template (805, 18, PRODUCT_L4_POLICY_FAMILY_IPV4,
                               PRODUCT_L4_POLICY_PROTOCOL_TCP, 30, 1,
                               PRODUCT_L4_POLICY_ACTION_DROP);
  original[5] = rule_template (806, 19, PRODUCT_L4_POLICY_FAMILY_IPV6,
                               PRODUCT_L4_POLICY_PROTOCOL_UDP, 1, 1,
                               PRODUCT_L4_POLICY_ACTION_DROP);
  original[0].source_port_first = 1000;
  original[0].source_port_last = 2000;
  original[1].destination_port_first = 443;
  original[1].destination_port_last = 443;
  original[2].source_prefix_length = 24;
  set_ipv4 (original[2].source_address, UINT32_C (0xc0000200));
  original[3].destination_prefix_length = 32;
  set_ipv4 (original[3].destination_address, UINT32_C (0xc6336402));
  original[4].source_port_first = 3000;
  original[4].source_port_last = 4000;
  original[4].destination_port_first = 8000;
  original[4].destination_port_last = 9000;

  permuted[0] = original[4];
  permuted[1] = original[2];
  permuted[2] = original[5];
  permuted[3] = original[0];
  permuted[4] = original[3];
  permuted[5] = original[1];
  product_l4_policy_init (&first);
  product_l4_policy_init (&second);
  CHECK_STATUS (product_l4_policy_compile (&first, original, 6),
                PRODUCT_L4_POLICY_STATUS_OK,
                "original physical arrangement must compile");
  CHECK_STATUS (product_l4_policy_compile (&second, permuted, 6),
                PRODUCT_L4_POLICY_STATUS_OK,
                "permuted physical arrangement must compile");

  packet = packet_template (18, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1500, 443);
  set_ipv4 (packet.source_address, UINT32_C (0xc0000217));
  set_ipv4 (packet.destination_address, UINT32_C (0xc6336402));
  left = match (&first, &packet);
  right = match (&second, &packet);
  CHECK (memcmp (&left, &right, sizeof (left)) == 0,
         "exact/wildcard/range candidate arrangement must not alter winner");
  CHECK (left.rule_id == 803 && left.winner_rank == 1,
         "permutation vector must exercise same-priority rule-id tie");

  packet.source_port = 3500;
  packet.destination_port = 8500;
  left = match (&first, &packet);
  right = match (&second, &packet);
  CHECK (memcmp (&left, &right, sizeof (left)) == 0,
         "range candidate placement must remain permutation invariant");

  for (index = 0; index < 5; index++)
    {
      uint32_t left_rank;
      uint32_t right_rank;
      CHECK_STATUS (product_l4_policy_rule_rank (&first,
                                                 original[index].rule_id,
                                                 &left_rank),
                    PRODUCT_L4_POLICY_STATUS_OK,
                    "original rank must be available");
      CHECK_STATUS (product_l4_policy_rule_rank (&second,
                                                 original[index].rule_id,
                                                 &right_rank),
                    PRODUCT_L4_POLICY_STATUS_OK,
                    "permuted rank must be available");
      CHECK (left_rank == right_rank,
             "physical input permutation must preserve every WinnerRank");
    }
}

static void
test_bounded_probes_and_capacity (void)
{
  product_l4_policy_rule_t rules[PRODUCT_L4_POLICY_MAX_RULES];
  product_l4_policy_rule_t overflow;
  product_l4_policy_view_t view;
  product_l4_policy_packet_t packet;
  product_l4_policy_match_result_t result;
  uint32_t index;

  for (index = 0; index < PRODUCT_L4_POLICY_MAX_RULES; index++)
    rules[index] = rule_template (900U + index, 21,
                                  PRODUCT_L4_POLICY_FAMILY_IPV4,
                                  PRODUCT_L4_POLICY_PROTOCOL_UDP,
                                  index + 1U, 0,
                                  PRODUCT_L4_POLICY_ACTION_ALLOW);
  product_l4_policy_init (&view);
  CHECK_STATUS (product_l4_policy_compile (&view, rules,
                                           PRODUCT_L4_POLICY_MAX_RULES),
                PRODUCT_L4_POLICY_STATUS_OK,
                "maximum bounded rule capacity must compile");
  CHECK (view.max_probes == PRODUCT_L4_POLICY_MAX_PROBES,
         "compiled view must expose its maximum candidate probe budget");
  packet = packet_template (21, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_UDP, 10, 20);
  packet.protocol = PRODUCT_L4_POLICY_PROTOCOL_TCP;
  result = match (&view, &packet);
  CHECK (result.probes == 0,
         "same-mask miss rejects the subtable without residual candidate checks");
  CHECK (result.probe_limit == PRODUCT_L4_POLICY_MAX_PROBES,
         "winner lookup must expose the applicable probe limit");

  packet.protocol = PRODUCT_L4_POLICY_PROTOCOL_UDP;
  packet.source_port = 0;
  packet.destination_port = 0;
  result = match (&view, &packet);
  CHECK (result.probes <= result.probe_limit
           && result.probe_limit <= PRODUCT_L4_POLICY_MAX_PROBES,
         "no-match lookup must remain within its bounded probe budget");

  overflow = rule_template (9999, 22, PRODUCT_L4_POLICY_FAMILY_IPV4,
                            PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                            PRODUCT_L4_POLICY_ACTION_DROP);
  CHECK_STATUS (product_l4_policy_compile (&view, &overflow, 1),
                PRODUCT_L4_POLICY_STATUS_OK,
                "recompilation must replace the previous bounded view");
  CHECK (view.rule_count == 1,
         "successful compile must publish one complete successor view");
  CHECK_STATUS (product_l4_policy_compile (
                  &view, rules, PRODUCT_L4_POLICY_MAX_RULES + 1U),
                PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED,
                "rule capacity must be rejected before view replacement");
  CHECK (view.rule_count == 1 && view.rules[0].source.rule_id == 9999,
         "failed capacity compile must preserve the prior complete view");
}

static void
test_compile_validation (void)
{
  product_l4_policy_rule_t rule =
    rule_template (10001, 1, PRODUCT_L4_POLICY_FAMILY_IPV4,
                   PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                   PRODUCT_L4_POLICY_ACTION_DROP);
  product_l4_policy_rule_t duplicate[2] = { rule, rule };
  product_l4_policy_view_t view;

  product_l4_policy_init (&view);
  rule.source_port_first = 9;
  rule.source_port_last = 8;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1),
                PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "reversed port range must be rejected");
  rule = rule_template (10001, 1, PRODUCT_L4_POLICY_FAMILY_IPV4,
                        PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                        PRODUCT_L4_POLICY_ACTION_DROP);
  rule.source_prefix_length = 33;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1),
                PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "IPv4 prefix above 32 must be rejected");
  rule = rule_template (10001, 1, PRODUCT_L4_POLICY_FAMILY_IPV4,
                        PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                        PRODUCT_L4_POLICY_ACTION_DROP);
  rule.source_address[15] = 1;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1),
                PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "noncanonical IPv4 address padding must be rejected");
  rule = rule_template (0, 1, PRODUCT_L4_POLICY_FAMILY_IPV4,
                        PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                        PRODUCT_L4_POLICY_ACTION_DROP);
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1),
                PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "zero stable rule id must be rejected");
  rule = rule_template (10002, UINT32_MAX, PRODUCT_L4_POLICY_FAMILY_IPV4,
                        PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                        PRODUCT_L4_POLICY_ACTION_DROP);
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1),
                PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "unknown UID sentinel must be rejected for a rule");
  rule = rule_template (10003, 1, PRODUCT_L4_POLICY_FAMILY_IPV4,
                        PRODUCT_L4_POLICY_PROTOCOL_TCP, 1, 1,
                        PRODUCT_L4_POLICY_ACTION_DROP);
  rule.reason_id = 0;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1),
                PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "zero reason id must be rejected");
  CHECK_STATUS (product_l4_policy_compile (&view, duplicate, 2),
                PRODUCT_L4_POLICY_STATUS_DUPLICATE_RULE_ID,
                "duplicate stable rule ids must be rejected");
}

/* A missing network fact remains unavailable through NOT; an available port
 * can independently prove OR. Literal vectors calibrate the Boolean contract. */
static void
test_static_expression_availability (void)
{
  product_l4_policy_rule_t rule = rule_template (70001, 9, 0, 0, 1, 0, 2);
  product_l4_policy_packet_t packet = packet_template (9, 4, 17, 0, 65535);
  product_l4_policy_view_t view;
  const uint8_t expression[] = {7, 1, 0, 0, 0, 3, 12, 255, 255, 255, 255, 2};
  memcpy (rule.expression, expression, sizeof expression);
  rule.expression_length = sizeof expression;
  packet.network_context_known = 0;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1), 0, "compile OR/NOT");
  CHECK (match (&view, &packet).rule_id == 70001, "known true OR unavailable wins");
  packet.destination_port = 65534;
  CHECK (match (&view, &packet).rule_id == 0, "NOT unavailable never wins");
  packet.network_context_known = 1;
  packet.network_context_id = 2;
  CHECK (match (&view, &packet).rule_id == 70001, "NOT known false wins");
  /* Exact byte and depth limits; failed compilation preserves the old view. */
  memset (rule.expression, 0, sizeof rule.expression);
  unsigned at = 0;
  for (unsigned i = 0; i < 3; ++i) {
    rule.expression[at++] = 9; rule.expression[at++] = 4;
    at += 17;
    if (i) rule.expression[at++] = 1;
  }
  rule.expression[at++] = 4; rule.expression[at++] = 4;
  rule.expression[at++] = 1; rule.expression[at++] = 3; rule.expression[at++] = 3;
  CHECK (at == 64, "literal maximum-length expression");
  rule.expression_length = at;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1), 0, "exact 64-byte expression accepted");
  CHECK (match (&view, &packet).rule_id == 70001, "maximum expression fully evaluated");
  rule.expression_length = 65;
  CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1), PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                "overlong expression rejected before read");
  CHECK (match (&view, &packet).rule_id == 70001, "failed compile leaves prior full plan intact");
  const uint8_t invalid[][6] = {{1}, {3}, {0}, {13}, {4, 9}, {6, 2}, {11, 2, 0, 1, 0}, {9, 4}};
  const unsigned lengths[] = {1,1,1,1,2,2,5,2};
  for (unsigned i = 0; i < sizeof lengths / sizeof lengths[0]; ++i) {
    rule.expression_length = lengths[i];
    memset (rule.expression, 0, 64); memcpy (rule.expression, invalid[i], lengths[i]);
    CHECK_STATUS (product_l4_policy_compile (&view, &rule, 1), PRODUCT_L4_POLICY_STATUS_INVALID_RULE,
                  "malformed operator/operand rejected");
  }
}

static void
test_factor_budget (void)
{
  product_l4_policy_view_t view, old;
  product_l4_policy_rule_t rule = rule_template (1201, 21, 4, 6, 1, 0, 2);
  rule.source_port_first = rule.destination_port_first = 1;
  rule.source_port_last = rule.destination_port_last = 65534;
  CHECK (product_l4_policy_compile (&view, &rule, 1) == 0, "large range product compiles");
  product_l4_policy_plan_resources_t plan;
  product_l4_policy_plan_resources (&view, &plan);
  CHECK (plan.factorized_rules == 1 && plan.direct_rules == 0 && plan.residual_rules == 0,
         "900 complete range combinations retain two interval factors");
  product_l4_policy_compile_budget_t budget = product_l4_policy_default_budget ();
  budget.factor_rules = 0;
  CHECK (product_l4_policy_compile_with_budget (&view, &rule, 1, &budget) == 0,
         "factor budget exhaustion uses a complete residual plan");
  product_l4_policy_plan_resources (&view, &plan);
  CHECK (plan.residual_rules == 1, "residual alternative is observable");
  old = view;
  budget.index_entries = 0;
  CHECK (product_l4_policy_compile_with_budget (&view, &rule, 1, &budget)
         == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED, "all legal plans exceeding total entries reject");
  CHECK (!memcmp (&view, &old, sizeof view), "failed compiler preserves caller view");
  budget = product_l4_policy_default_budget ();
  budget.condition_items = 8;
  CHECK (product_l4_policy_compile_with_budget (&view, &rule, 1, &budget)
         == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED, "condition budget rejects complete view");
  CHECK (!memcmp (&view, &old, sizeof view), "condition failure preserves old view");
  budget = product_l4_policy_default_budget ();
  budget.peak_bytes = plan.publication_peak_bytes - 1;
  CHECK (product_l4_policy_compile_with_budget (&view, &rule, 1, &budget)
         == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED, "publication overlap participates in budget");
  CHECK (!memcmp (&view, &old, sizeof view), "peak failure preserves old view");
  budget.peak_bytes++;
  CHECK (product_l4_policy_compile_with_budget (&view, &rule, 1, &budget) == 0,
         "exact complete storage budget is admitted");
  /* Complementary halves, direction changes and PRE/POST never accumulate. */
  const uint16_t ports[][2] = {{1,0},{0,1},{1,1},{65535,1},{1,65535},{65534,65534}};
  for (unsigned i = 0; i < sizeof ports / sizeof ports[0]; ++i)
    {
      product_l4_policy_packet_t packet = packet_template (21, 4, 6, ports[i][0], ports[i][1]);
      packet.direction = i % 2 ? PRODUCT_L4_POLICY_DIRECTION_INPUT : PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
      product_l4_policy_match_result_t match;
      CHECK (product_l4_policy_match (&view, &packet, &match) == 0, "factor query completes");
      CHECK (match.rule_id == ((i == 2 || i == 5) ? 1201U : 0U), "factors only complete within current query");
      CHECK (product_l4_policy_match_position (&view, &packet, PRODUCT_L4_POLICY_POSITION_POST, &match) == 0
             && !match.rule_id, "PRE factors cannot complete at POST");
    }
  product_l4_policy_rule_t many[PRODUCT_L4_POLICY_MAX_RULES];
  for (unsigned i = 0; i < PRODUCT_L4_POLICY_MAX_RULES; ++i)
    {
      many[i] = rule; many[i].rule_id += i;
      many[i].source_port_first = many[i].destination_port_first = 1;
      many[i].source_port_last = many[i].destination_port_last = 6;
    }
  CHECK (product_l4_policy_compile (&view, many, PRODUCT_L4_POLICY_MAX_RULES) == 0,
         "whole-view expansion pressure cannot reject a legal smaller plan");
  product_l4_policy_plan_resources (&view, &plan);
  CHECK (plan.direct_rules > 0 && plan.factorized_rules > 0
         && plan.direct_rules + plan.factorized_rules == PRODUCT_L4_POLICY_MAX_RULES,
         "shared view mixes expansion and complete factor plans within capacity");
  product_l4_policy_packet_t packet = packet_template (21, 4, 6, 3, 3);
  product_l4_policy_match_result_t match;
  CHECK (product_l4_policy_match (&view, &packet, &match) == 0 && match.rule_id == 1201,
         "budget pressure preserves full Rank winner");

}

static void
test_exact_range_plan (void)
{
  product_l4_policy_view_t view;
  product_l4_policy_rule_t rule = rule_template (1200, 21, 4, 6, 1, 0, 2);
  rule.source_port_first = 1; rule.source_port_last = 6;
  rule.destination_port_first = 1; rule.destination_port_last = 6;
  CHECK (product_l4_policy_compile (&view, &rule, 1) == 0, "small range plan compiles");
  product_l4_policy_index_resources_t resources;
  product_l4_policy_index_resources (&view, &resources);
  CHECK (resources.entries == 16, "two four-mask ranges expand to sixteen complete entries");
  for (unsigned source = 0; source <= 7; ++source)
    for (unsigned destination = 0; destination <= 7; ++destination)
      {
        product_l4_policy_packet_t packet = packet_template (21, 4, 6, source, destination);
        product_l4_policy_match_result_t result;
        CHECK (product_l4_policy_match (&view, &packet, &result) == 0, "range query completes");
        CHECK (result.rule_id == ((source >= 1 && source <= 6 && destination >= 1 && destination <= 6) ? 1200U : 0U), "exact range winner");
        CHECK (result.probes <= 1, "fragments never repeat a whole-rule check");
      }
}

int
main (void)
{
  test_exact_range_plan ();
  test_factor_budget ();
  CHECK (PRODUCT_L4_POLICY_DIRECTION_INPUT == 1
           && PRODUCT_L4_POLICY_DIRECTION_OUTPUT == 3,
         "device direction domain must remain INPUT=1 and OUTPUT=3");
  test_static_expression_availability ();
  test_four_family_protocols ();
  test_precedence_and_ranks ();
  test_cidr_and_ports ();
  test_context_direction_and_uid ();
  test_unsupported_and_unavailable ();
  test_permutation_invariance ();
  test_bounded_probes_and_capacity ();
  test_compile_validation ();
  if (failures != 0)
    return 1;
  puts ("sakamoto Product stateless L4 policy semantic vectors: PASS");
  return 0;
}
