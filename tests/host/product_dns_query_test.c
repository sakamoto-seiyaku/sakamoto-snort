/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t query_wire[] = {
  0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1
};
static product_l4_policy_view_t fixture_view;
static product_domains_t *fixture_domains;
static product_dns_context_t fixture_context;

static product_l4_policy_rule_t rule (unsigned id, unsigned priority, unsigned action)
{
  return (product_l4_policy_rule_t) {
    .uid = 10123, .rule_id = id, .reason_id = id, .priority = priority,
    .action = action, .network_context_id = UINT32_MAX, .ifindex = UINT32_MAX,
    .source_port_last = UINT16_MAX, .destination_port_last = UINT16_MAX,
    .expression_length = 2, .expression = { PRODUCT_EXPRESSION_DOMAIN_LIST, 0 }
  };
}

static void fixture (void)
{
  sakamoto_product_domains_t source = { .list_count = 2, .entry_count = 2,
    .entries = {{ .length = 11, .name = "example.com", .mode = 1 },
                { .length = 12, .name = "else.example", .list = 1 }} };
  assert (!product_domains_build (&source, &fixture_domains));
  fixture_context = (product_dns_context_t) {
    .domains = fixture_domains, .caller = PRODUCT_DNS_CALLER_KERNEL_APP,
    .packet = { .uid = 10123, .uid_known = 1, .family = 4, .protocol = 17,
      .direction = 3, .direction_known = 1, .ports_available = 1,
      .source_port = 40000, .destination_port = 53,
      .destination_address = { 192, 168, 1, 53 } }
  };
}

static product_l4_policy_match_result_t evaluate (const uint8_t *wire, size_t length,
                                                const product_l4_policy_rule_t *rules,
                                                unsigned count,
                                                product_dns_query_t *query)
{
  assert (!product_l4_policy_compile (&fixture_view, rules, count));
  product_dns_inspect_query (wire, length, &fixture_context, query);
  assert (query->codec_peak_bytes <= PRODUCT_DNS_CODEC_BYTES);
  product_dns_resources_t resources = product_dns_resources ();
  assert (!resources.codec_live_bytes && !resources.active_operations);
  product_l4_policy_match_result_t result;
  assert (!product_l4_policy_match (&fixture_view, &query->packet, &result));
  return result;
}

static void reliable_query_is_denied_before_original_forwarding (void)
{
  static const uint8_t wire[] = {
    0x12,0x34,1,0,0,1,0,0,0,0,0,0,
    7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1
  };
  sakamoto_product_domains_t source = { .list_count = 1, .entry_count = 1,
    .entries = {{ .length = 11, .name = "example.com" }} };
  product_domains_t *domains = NULL;
  assert (!product_domains_build (&source, &domains));
  product_dns_context_t context = {
    .domains = domains, .caller = PRODUCT_DNS_CALLER_KERNEL_APP,
    .packet = { .uid = 10123, .uid_known = 1, .family = 4, .protocol = 17,
      .direction = 3, .direction_known = 1, .ports_available = 1,
      .source_port = 40000, .destination_port = 53 }
  };
  product_l4_policy_rule_t rule = {
    .rule_id = 310, .reason_id = 310, .uid = 10123, .action = 2,
    .network_context_id = UINT32_MAX, .ifindex = UINT32_MAX,
    .source_port_last = UINT16_MAX, .destination_port_last = UINT16_MAX,
    .expression_length = 2, .expression = { PRODUCT_EXPRESSION_DOMAIN_LIST, 0 }
  };
  static product_l4_policy_view_t view;
  assert (!product_l4_policy_compile (&view, &rule, 1));
  product_dns_query_t query;
  product_dns_inspect_query (wire, sizeof (wire), &context, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE);
  assert (query.id == 0x1234 && query.qtype == 1 && query.qclass == 1);
  assert (!strcmp (query.name, "example.com"));
  assert (query.packet.sni_result == 0);
  product_l4_policy_match_result_t result;
  assert (!product_l4_policy_match (&view, &query.packet, &result));
  assert (result.rule_id == 310 && result.actual_action == 2);
  product_domains_destroy (domains);
}

static void caller_availability_boolean_and_real_transport (void)
{
  fixture ();
  product_dns_query_t query;
  product_l4_policy_rule_t r = rule (310, 1, 2);
  fixture_context.caller = PRODUCT_DNS_CALLER_UNKNOWN;
  product_l4_policy_match_result_t result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && !query.packet.domain_available);
  assert (!result.evaluation); /* Known system socket UID is insufficient. */
  r.expression[2] = PRODUCT_STATIC_NOT; r.expression_length = 3;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (!result.evaluation); /* NOT unavailable never manufactures a hit. */
  memcpy (r.expression, (uint8_t[]) { PRODUCT_EXPRESSION_DOMAIN_LIST, 0,
    PRODUCT_STATIC_PROTOCOL, 17, PRODUCT_STATIC_OR }, 5);
  r.expression_length = 5;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (result.rule_id == 310); /* Independent available generic branch. */
  r.expression[4] = PRODUCT_STATIC_AND;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (!result.evaluation);
  fixture_context.caller = PRODUCT_DNS_CALLER_KERNEL_APP;
  memcpy (r.expression, (uint8_t[]) { PRODUCT_EXPRESSION_DOMAIN_LIST, 0,
    PRODUCT_STATIC_DESTINATION_PORT, 0xbb, 1, 0xbb, 1, PRODUCT_STATIC_AND }, 8);
  r.expression_length = 8;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (!result.evaluation); /* Business443 must not replace actual DNS53. */
  assert (!memcmp (query.packet.destination_address, (uint8_t[]) {192,168,1,53}, 4));
  r = rule (311, 1, 2);
  memcpy (r.expression, (uint8_t[]) { PRODUCT_EXPRESSION_DOMAIN_LIST, 1,
    PRODUCT_EXPRESSION_DOMAIN_LIST, 0, PRODUCT_STATIC_OR }, 5);
  r.expression_length = 5;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (result.rule_id == 311); /* Selected-list any-match. */
  r.expression[4] = PRODUCT_STATIC_AND;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (!result.evaluation); /* An explicit AND remains AND. */
  r = rule (312, 1, 2);
  memcpy (r.expression, (uint8_t[]) { PRODUCT_EXPRESSION_SNI_ABSENT, 1,
    PRODUCT_EXPRESSION_DOMAIN_LIST, 0, PRODUCT_STATIC_OR }, 5);
  r.expression_length = 5;
  result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (!result.evaluation && !query.packet.sni_result);
  product_domains_destroy (fixture_domains);
}

static void rank_observe_rr_types_and_cache (void)
{
  fixture ();
  product_dns_query_t query;
  product_l4_policy_rule_t rules[2] = { rule (310, 2, 2), rule (311, 1, 1) };
  rules[1].expression_length = 0;
  product_l4_policy_match_result_t result = evaluate (query_wire, sizeof (query_wire), rules, 2, &query);
  assert (result.rule_id == 311 && result.actual_action == 1);
  rules[0].priority = 0;
  result = evaluate (query_wire, sizeof (query_wire), rules, 2, &query);
  assert (result.rule_id == 310 && result.actual_action == 2);
  rules[0].mode = 1;
  result = evaluate (query_wire, sizeof (query_wire), rules, 2, &query);
  assert (result.rule_id == 310 && result.action == 2 && result.actual_action == 1);
  uint8_t wire[sizeof (query_wire)];
  const uint16_t types[] = { 1, 28, 16, 15, 33, 65, 65000 };
  for (unsigned family = 4; family <= 6; family += 2)
    for (unsigned i = 0; i < sizeof (types) / sizeof (*types); ++i)
      {
        memcpy (wire, query_wire, sizeof (wire));
        wire[sizeof (wire) - 4] = types[i] >> 8;
        wire[sizeof (wire) - 3] = types[i];
        fixture_context.packet.family = family;
        result = evaluate (wire, sizeof (wire), rules, 2, &query);
        assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && query.qtype == types[i]);
        assert (result.rule_id == 310 && query.packet.domain_available);
        assert (!memcmp (wire, query_wire, sizeof (wire) - 4));
      }
  product_policy_cache_t cache = { .capacity = 2 };
  product_policy_cache_identity_t identity = { 1, 2, 3, 4 };
  assert (!product_l4_policy_match_cached (&cache, &fixture_view, &query.packet,
    &identity, PRODUCT_L4_POLICY_POSITION_ALL, &result));
  assert (result.rule_id == 310);
  assert (!product_l4_policy_match_cached (&cache, &fixture_view, &query.packet,
    &identity, PRODUCT_L4_POLICY_POSITION_ALL, &result));
  assert (cache.hits == 1);
  fixture_context.caller = PRODUCT_DNS_CALLER_UNKNOWN;
  product_dns_inspect_query (query_wire, sizeof (query_wire), &fixture_context, &query);
  assert (!product_l4_policy_match_cached (&cache, &fixture_view, &query.packet,
    &identity, PRODUCT_L4_POLICY_POSITION_ALL, &result));
  assert (result.rule_id == 311 && cache.misses == 2);
  product_domains_destroy (fixture_domains);
}

static void malformed_messages_are_not_successful_no_match (void)
{
  fixture ();
  product_l4_policy_rule_t r = rule (310, 1, 2);
  product_dns_query_t query;
  uint8_t wire[sizeof (query_wire)];
  for (size_t length = 0; length < sizeof (query_wire); ++length)
    {
      product_l4_policy_match_result_t result = evaluate (query_wire, length, &r, 1, &query);
      assert (query.coverage == PRODUCT_DNS_MALFORMED && !query.packet.domain_available);
      assert (!result.evaluation);
    }
  memcpy (wire, query_wire, sizeof (wire));
  wire[12] = 0xc0; wire[13] = 12; /* cyclic compression */
  (void) evaluate (wire, sizeof (wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_MALFORMED && !query.packet.domain_available);
  memcpy (wire, query_wire, sizeof (wire)); wire[5] = 2;
  (void) evaluate (wire, sizeof (wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_UNSUPPORTED);
  memcpy (wire, query_wire, sizeof (wire)); wire[2] |= 0x08;
  (void) evaluate (wire, sizeof (wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_UNSUPPORTED);
  memcpy (wire, query_wire, sizeof (wire)); wire[2] |= 0x80;
  (void) evaluate (wire, sizeof (wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_NOT_QUERY);
  /* A valid maximum-sized record set exceeds the finite codec budget. */
  static uint8_t large[65000];
  memcpy (large, query_wire, sizeof (query_wire));
  const unsigned count = 5000;
  large[10] = count >> 8; large[11] = count & 255;
  for (unsigned i = 0; i < count; ++i)
    memcpy (large + sizeof (query_wire) + i * 12,
      (uint8_t[]) {0xc0,12,0xfd,0xe8,0,1,0,0,0,0,0,0}, 12);
  (void) evaluate (large, sizeof (query_wire) + count * 12, &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_CAPACITY && !query.packet.domain_available);
  assert (query.codec_peak_bytes && query.codec_peak_bytes <= PRODUCT_DNS_CODEC_BYTES);
  product_l4_policy_match_result_t result = evaluate (query_wire, sizeof (query_wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && result.rule_id == 310);
  product_domains_destroy (fixture_domains);
}

static void canonical_and_unrepresentable_names (void)
{
  fixture ();
  product_l4_policy_rule_t r = rule (310, 1, 2);
  product_dns_query_t query;
  uint8_t wire[sizeof (query_wire) + 64];
  memcpy (wire, query_wire, sizeof (query_wire));
  wire[13] = 'E'; wire[21] = 'C';
  product_l4_policy_match_result_t result = evaluate (wire, sizeof (query_wire), &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && result.rule_id == 310);
  /* The root terminator yields the same absolute name; no dot is invented. */
  assert (!strcmp (query.name, "Example.Com"));
  /* Valid compressed additional owner and opaque unknown RDATA are retained. */
  memcpy (wire, query_wire, sizeof (query_wire)); wire[11] = 1;
  memcpy (wire + sizeof (query_wire),
    (uint8_t[]) {0xc0,12,0xfd,0xe8,0,1,0,0,0,0,0,3,0,0xff,0x5a}, 15);
  result = evaluate (wire, sizeof (query_wire) + 15, &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && result.rule_id == 310);
  /* A service-label QName can still match its configured descendant suffix. */
  memcpy (wire, query_wire, 12);
  memcpy (wire + 12, (uint8_t[]) {4,'_','s','v','c',7,'e','x','a','m','p','l','e',
    3,'c','o','m',0,0,33,0,1}, 22);
  result = evaluate (wire, 34, &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && result.rule_id == 310);
  /* A dot inside a wire label is escaped by the codec. It must never become
   * the syntactically different domain "example.com" or a confident NOT hit. */
  memcpy (wire, query_wire, 12);
  memcpy (wire + 12, (uint8_t[]) {11,'e','x','a','m','p','l','e','.','c','o','m',0,0,1,0,1}, 17);
  r.expression[2] = PRODUCT_STATIC_NOT; r.expression_length = 3;
  result = evaluate (wire, 29, &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && !query.packet.domain_available);
  assert (!result.evaluation);
  memcpy (wire, query_wire, sizeof (query_wire)); wire[sizeof (query_wire)] = 0xff;
  (void) evaluate (wire, sizeof (query_wire) + 1, &r, 1, &query);
  assert (query.coverage == PRODUCT_DNS_MALFORMED && !query.packet.domain_available);
  product_domains_destroy (fixture_domains);
}

static void bounded_wire_mutations_release_every_operation (void)
{
  fixture ();
  static uint8_t wire[PRODUCT_DNS_MESSAGE_MAX];
  uint32_t random = 310;
  product_dns_query_t query;
  for (unsigned attempt = 0; attempt < 12000; ++attempt)
    {
      random = random * UINT32_C (1664525) + UINT32_C (1013904223);
      size_t length = attempt % 3 ? sizeof (query_wire) : random & UINT16_MAX;
      memset (wire, 0, length);
      memcpy (wire, query_wire, length < sizeof (query_wire) ? length : sizeof (query_wire));
      for (unsigned mutation = 0; mutation < 8 && length; ++mutation)
        {
          random = random * UINT32_C (1664525) + UINT32_C (1013904223);
          wire[random % length] ^= (uint8_t) (random >> 24);
        }
      product_dns_inspect_query (wire, length, &fixture_context, &query);
      assert (query.codec_peak_bytes <= PRODUCT_DNS_CODEC_BYTES);
      product_dns_resources_t resources = product_dns_resources ();
      assert (!resources.codec_live_bytes && !resources.active_operations);
    }
  product_dns_inspect_query (query_wire, sizeof (query_wire), &fixture_context, &query);
  assert (query.coverage == PRODUCT_DNS_QUERY_COMPLETE && query.packet.domain_available);
  product_domains_destroy (fixture_domains);
}

int main (void)
{
  reliable_query_is_denied_before_original_forwarding ();
  caller_availability_boolean_and_real_transport ();
  rank_observe_rr_types_and_cache ();
  malformed_messages_are_not_successful_no_match ();
  canonical_and_unrepresentable_names ();
  bounded_wire_mutations_release_every_operation ();
  puts ("Root DNS query semantic seam: PASS");
  return 0;
}
