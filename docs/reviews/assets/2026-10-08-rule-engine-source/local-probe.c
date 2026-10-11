#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "product_l4_policy.h"

static product_l4_policy_rule_t rule(unsigned id) {
  product_l4_policy_rule_t r = {0};
  r.rule_id = id; r.reason_id = 1; r.uid = 1000;
  r.network_context_id = UINT32_MAX; r.ifindex = UINT32_MAX;
  r.priority = id; r.family = 4; r.protocol = 17; r.direction = 3;
  r.source_port_last = r.destination_port_last = UINT16_MAX;
  r.action = 2;
  return r;
}

static void inspect(const char *name, product_l4_policy_rule_t *rules,
                    unsigned count, product_l4_policy_packet_t *packet) {
  product_l4_policy_view_t *view = calloc(1, sizeof(*view));
  if (!view) exit(2);
  int status = product_l4_policy_compile(view, rules, count);
  if (status) { fprintf(stderr, "compile=%d\n", status); exit(3); }
  product_l4_policy_match_result_t result;
  status = product_l4_policy_match(view, packet, &result);
  if (status) exit(4);
  product_l4_policy_index_resources_t index;
  product_l4_policy_index_resources(view, &index);
  printf("%s rules=%u masks=%u entries=%u winner=%llu rank=%u subject_probes=%u subtable_probes=%u key_probes=%u residual_probes=%u bound=%u\n",
         name, count, index.subtables, index.entries,
         (unsigned long long) result.rule_id, result.winner_rank,
         result.subject_probes, result.subtable_probes, result.key_probes,
         result.probes, index.max_query_work);
  free(view);
}

int main(void) {
  printf("layout view=%zu source_rule=%zu compiled_rule=%zu subtable=%zu entry=%zu packet=%zu result=%zu cache_guard=%zu cache_entry=%zu owner_cache=%zu\n",
         sizeof(product_l4_policy_view_t), sizeof(product_l4_policy_rule_t),
         sizeof(product_l4_policy_compiled_rule_t), sizeof(product_l4_policy_subtable_t),
         sizeof(product_l4_policy_index_entry_t), sizeof(product_l4_policy_packet_t),
         sizeof(product_l4_policy_match_result_t), sizeof(product_policy_cache_guard_t),
         sizeof(product_policy_cache_entry_t), sizeof(product_policy_cache_t));
  product_l4_policy_plan_resources_t plan;
  product_l4_policy_plan_resources(NULL, &plan);
  product_l4_policy_compile_budget_t budget = product_l4_policy_default_budget();
  printf("representation query_state=%u compile_scratch=%u publication_peak=%u publication_limit=%u publication_margin=%u\n",
         plan.query_state_bytes, plan.compile_scratch_bytes, plan.publication_peak_bytes,
         budget.peak_bytes, budget.peak_bytes - plan.publication_peak_bytes);
  product_l4_policy_rule_t rules[128];
  product_l4_policy_packet_t p = {0};
  p.uid = 1000; p.uid_known = 1; p.family = 4; p.protocol = 17;
  p.direction = 3; p.direction_known = 1; p.ports_available = 1;
  p.source_port = 12345; p.destination_port = 443;
  for (unsigned i = 0; i < 128; ++i) {
    rules[i] = rule(i + 1);
    rules[i].destination_prefix_length = 32;
    rules[i].destination_address[0] = 10;
    rules[i].destination_address[3] = (unsigned char) i;
  }
  p.destination_address[0] = 10; p.destination_address[3] = 255;
  inspect("same-mask-exact-miss", rules, 128, &p);
  p.destination_address[3] = 63;
  inspect("same-mask-exact-hit", rules, 128, &p);
  for (unsigned i = 0; i < 128; ++i) {
    rules[i] = rule(i + 1);
    rules[i].source_prefix_length = (unsigned char) (i % 32 + 1);
    rules[i].destination_prefix_length = (unsigned char) (i / 32 + 1);
    rules[i].source_address[0] = 10;
    rules[i].destination_address[0] = 10;
  }
  p.source_address[0] = p.destination_address[0] = 255;
  inspect("128-mask-miss", rules, 128, &p);
  rules[0] = rule(1);
  inspect("128-mask-first-winner", rules, 128, &p);
  return 0;
}
