/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only timing of the current Product C saved-source activation path. */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct {
  product_l4_policy_view_t *view;
  product_domains_t *domains;
  uint64_t publish_compile_ns;
  uint64_t old_destroy_ns;
  unsigned publications;
} runtime_t;

static uint64_t now_ns (void)
{
  struct timespec clock;
  assert (clock_gettime (CLOCK_MONOTONIC, &clock) == 0);
  return (uint64_t) clock.tv_sec * UINT64_C (1000000000) + clock.tv_nsec;
}

static uint32_t publish (void *opaque, uint64_t revision, uint64_t hash,
                         const product_l4_policy_rule_t *rules, uint32_t count,
                         product_domains_t *domains)
{
  runtime_t *runtime = opaque;
  assert (revision && hash && count);
  uint64_t begin = now_ns ();
  uint32_t result = product_l4_policy_compile (runtime->view, rules, count);
  runtime->publish_compile_ns = now_ns () - begin;
  if (result) return result;
  begin = now_ns ();
  product_domains_destroy (runtime->domains);
  runtime->old_destroy_ns = now_ns () - begin;
  runtime->domains = domains;
  ++runtime->publications;
  return 0;
}

int main (int argc, char **argv)
{
  if (argc != 3) return 2;
  unsigned repetitions = (unsigned) strtoul (argv[2], NULL, 10);
  if (!repetitions || repetitions > 1000) return 2;
  product_rule_config_t *config = product_rule_config_open (argv[1]);
  if (!config) return 3;
  sakamoto_product_rule_config_status_t status;
  product_rule_config_query (config, &status);
  if (!status.count || !status.domains.entry_count) return 4;
  runtime_t runtime = {.view = calloc (1, sizeof (product_l4_policy_view_t))};
  if (!runtime.view) return 5;
  printf ("source_rules=%u domain_entries=%u compile_peak_bytes=%u\n",
          status.count, status.domains.entry_count,
          product_rule_config_compile_peak_bytes ());
  puts ("repetition,activate_ns,publish_compile_ns,old_destroy_ns,publications");
  for (unsigned i = 0; i < repetitions + 5; ++i)
    {
      uint64_t begin = now_ns ();
      uint32_t result = product_rule_config_activate (config, publish, &runtime);
      uint64_t elapsed = now_ns () - begin;
      if (result) {
        fprintf (stderr, "activate failed: %u at %u\n", result, i);
        return 6;
      }
      if (i >= 5)
        printf ("%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u\n",
                i - 5, elapsed, runtime.publish_compile_ns,
                runtime.old_destroy_ns, runtime.publications);
    }
  const char *name = "example.test";
  const unsigned queries = 100000;
  volatile uint64_t signature = 0;
  uint64_t begin = now_ns ();
  for (unsigned i = 0; i < queries; ++i)
    signature += product_domains_match (runtime.domains,
      (const uint8_t *) name, strlen (name));
  uint64_t domain_ns = now_ns () - begin;
  product_l4_policy_packet_t packet = {
    .uid = 12001, .uid_known = 1, .family = 4, .protocol = 17,
    .source_port = 45302, .destination_port = 5004,
    .ports_available = 1, .direction = 3, .direction_known = 1,
    .network_context_id = 0, .network_context_known = 1,
    .flow_direction = 1, .flow_direction_known = 1,
    .ct_state = 1, .ct_state_known = 1,
    /* Stable catalog RTP 1017 is bit 16; this matches the live R4 Flow. */
    .protocol_set_known = 1, .protocol_set = UINT64_C (1) << 16,
    .sni_result = 0, .domain_lists = 0
  };
  begin = now_ns ();
  for (unsigned i = 0; i < queries; ++i)
    {
      product_l4_policy_match_result_t result;
      assert (product_l4_policy_match (runtime.view, &packet, &result) == 0);
      assert (result.rule_id && result.actual_action == 1);
      signature += result.rule_id + result.actual_action + result.probes;
    }
  uint64_t match_ns = now_ns () - begin;
  printf ("query,%" PRIu64 ",%" PRIu64 ",%u,%" PRIu64 "\n",
          domain_ns, match_ns, queries, signature);
  product_domains_destroy (runtime.domains);
  free (runtime.view);
  product_rule_config_close (config);
  return 0;
}
