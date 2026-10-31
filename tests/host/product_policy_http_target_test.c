/* SPDX-License-Identifier: Apache-2.0 */
#include "product_l4_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_l4_policy_rule_t rule (uint64_t id, unsigned action, const uint8_t *expression, unsigned length)
{
  product_l4_policy_rule_t r = {.rule_id = id, .reason_id = 9, .uid = 17, .action = (uint8_t) action,
    .network_context_id = UINT32_MAX, .ifindex = UINT32_MAX,
    .source_port_last = 65535, .destination_port_last = 65535, .expression_length = (uint16_t) length};
  memcpy (r.expression, expression, length);
  return r;
}

static product_l4_policy_packet_t packet (unsigned source, unsigned available, uint64_t lists)
{
  /* Plain HTTP: no TLS/QUIC protocol bit, SNI unavailable. */
  return (product_l4_policy_packet_t){.uid = 17, .uid_known = 1, .family = 4, .protocol = 6,
    .protocol_set = 0, .protocol_set_known = 1, .sni_result = PRODUCT_SNI_UNAVAILABLE,
    .domain_source = (uint8_t) source, .domain_available = (uint8_t) available, .domain_lists = lists};
}

static uint64_t winner (const product_l4_policy_view_t *view, const product_l4_policy_packet_t *p)
{
  product_l4_policy_match_result_t result;
  assert (!product_l4_policy_match (view, p, &result));
  return result.evaluation == PRODUCT_L4_POLICY_EVALUATION_MATCH ? result.rule_id : 0;
}

int main (void)
{
  const uint8_t list0[] = {PRODUCT_EXPRESSION_DOMAIN_LIST, 0};
  const uint8_t sni_absent[] = {PRODUCT_EXPRESSION_SNI_ABSENT, 1};
  product_l4_policy_view_t view;
  product_l4_policy_rule_t rules[2] = {rule (7, 2, list0, sizeof (list0)), rule (8, 2, sni_absent, sizeof (sni_absent))};
  assert (!product_l4_policy_compile (&view, rules, 1));
  /* The target is a member of list 0: the domain rule wins for a direct HTTP source. */
  assert (winner (&view, &(product_l4_policy_packet_t){0}) == 0);
  product_l4_policy_packet_t p = packet (PRODUCT_POLICY_DOMAIN_HTTP_TARGET, 1, 1);
  assert (winner (&view, &p) == 7);
  p = packet (PRODUCT_POLICY_DOMAIN_HTTP_TARGET, 1, 0);          /* known target, not in the list */
  assert (winner (&view, &p) == 0);
  p = packet (PRODUCT_POLICY_DOMAIN_HTTP_TARGET, 0, 1);          /* target unavailable: no domain decision */
  assert (winner (&view, &p) == 0);
  p = packet (PRODUCT_POLICY_DOMAIN_SOCKS_TARGET, 1, 1);         /* a SOCKS target is a direct source too */
  assert (winner (&view, &p) == 7);
  p = packet (PRODUCT_POLICY_DOMAIN_SOCKS_TARGET, 0, 1);
  assert (winner (&view, &p) == 0);
  p = packet (PRODUCT_POLICY_DOMAIN_SNI, 1, 1);                  /* the same plain flow with an SNI source stays inapplicable */
  assert (winner (&view, &p) == 0);
  /* An explicit SNI condition is never satisfied by an HTTP target. */
  assert (!product_l4_policy_compile (&view, rules + 1, 1));
  p = packet (PRODUCT_POLICY_DOMAIN_HTTP_TARGET, 1, 1);
  assert (winner (&view, &p) == 0);
  puts ("HTTP and SOCKS target domain sources PASS");
  return 0;
}
