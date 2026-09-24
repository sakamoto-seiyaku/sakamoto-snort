/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>

typedef struct {
  product_l4_policy_view_t view;
  uint64_t revision;
  unsigned publications;
  int reject;
} runtime_t;

static uint32_t
publish (void *opaque, uint64_t revision, uint64_t hash,
         const product_l4_policy_rule_t *rule, uint32_t count)
{
  runtime_t *runtime = opaque;
  assert (hash != 0);
  if (runtime->reject) return 1;
  assert (product_l4_policy_compile (&runtime->view, rule, count)
          == PRODUCT_L4_POLICY_STATUS_OK);
  runtime->revision = revision;
  runtime->publications++;
  return 0;
}

int main (void)
{
  char directory[] = "/tmp/sakamoto-rule-config-XXXXXX";
  assert (mkdtemp (directory));
  char path[256];
  snprintf (path, sizeof (path), "%s/rules", directory);
  product_rule_config_t *config = product_rule_config_open (path);
  assert (config);
  runtime_t runtime = {0};
  assert (product_rule_config_activate (config, publish, &runtime) == 0);
  sakamoto_product_rule_config_status_t status;
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 1 && status.active_revision == 1);
  assert (status.saved_rule_version == 0 && !status.rule.present);
  assert (status.save_error == 0 && status.compile_error == 0);
  assert (runtime.publications == 1 && runtime.view.rule_count == 0);
  sakamoto_product_rule_config_request_t request = {
    .schema = 1, .operation = SAKAMOTO_RULE_CONFIG_REPLACE,
    .expected_saved_revision = 1,
    .rule = { .present = 1, .uid = 12345, .protocol = 17,
      .direction = 3, .action = 2, .source_port = 32000,
      .destination_port = 40608, .source_address = {127,0,0,1},
      .destination_address = {127,0,0,2} }
  };
  assert (product_rule_config_replace (config, &request, publish, &runtime) == 0);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 2 && status.active_revision == 2);
  assert ((status.saved_rule_version >> 16) != 0);
  assert ((status.saved_rule_version & 65535) == 1);
  assert (status.active_rule_version == status.saved_rule_version);
  assert (runtime.view.rule_count == 1);
  product_l4_policy_packet_t packet = {
    .uid = 12345, .uid_known = 1, .family = 4, .protocol = 17,
    .direction = 3, .direction_known = 1, .ports_available = 1,
    .source_port = 32000, .destination_port = 40608,
    .source_address = {127,0,0,1}, .destination_address = {127,0,0,2}
  };
  product_l4_policy_match_result_t match;
  assert (product_l4_policy_match (&runtime.view, &packet, &match) == 0);
  assert (match.rule_id == status.saved_rule_version && match.action == 2);
  assert (match.stage_verdict == PRODUCT_L4_POLICY_VERDICT_DROP);
  product_rule_config_close (config);
  config = product_rule_config_open (path);
  assert (config);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 2 && status.active_revision == 0);
  assert (product_rule_config_activate (config, publish, &runtime) == 0);
  assert (product_l4_policy_match (&runtime.view, &packet, &match) == 0);
  assert (match.rule_id == status.saved_rule_version && match.action == 2);
  uint64_t first_version = status.saved_rule_version;
  request.expected_saved_revision = 2;
  request.rule.protocol = 6;
  assert (product_rule_config_replace (config, &request, publish, &runtime)
          == SAKAMOTO_RULE_CONFIG_UNSUPPORTED);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 3 && status.active_revision == 2);
  assert (status.saved_rule_version == first_version + 1);
  assert (status.active_rule_version == first_version);
  assert (status.rule.protocol == 6 && status.save_error == 0);
  assert (product_l4_policy_match (&runtime.view, &packet, &match) == 0);
  assert (match.rule_id == first_version && match.action == 2);
  request.rule.protocol = 17;
  assert (product_rule_config_replace (config, &request, publish, &runtime)
          == SAKAMOTO_RULE_CONFIG_CONFLICT);
  request.expected_saved_revision = 3;
  request.rule.action = 1;
  struct rlimit previous, limited;
  assert (getrlimit (RLIMIT_FSIZE, &previous) == 0);
  limited = previous; limited.rlim_cur = 16;
  void (*old_signal) (int) = signal (SIGXFSZ, SIG_IGN);
  assert (setrlimit (RLIMIT_FSIZE, &limited) == 0);
  assert (product_rule_config_replace (config, &request, publish, &runtime)
          == SAKAMOTO_RULE_CONFIG_IO);
  assert (setrlimit (RLIMIT_FSIZE, &previous) == 0);
  signal (SIGXFSZ, old_signal);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 3 && status.active_revision == 2);
  assert (status.rule.protocol == 6 && status.save_error != 0);
  product_rule_config_t *readback = product_rule_config_open (path);
  sakamoto_product_rule_config_status_t saved;
  product_rule_config_query (readback, &saved);
  assert (saved.saved_revision == 3 && saved.rule.protocol == 6 && saved.save_error == 0);
  product_rule_config_close (readback);
  assert (product_rule_config_replace (config, &request, publish, &runtime) == 0);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 4 && status.active_revision == 4);
  assert (status.saved_rule_version == first_version + 2);
  assert (!status.save_error && !status.compile_error);
  assert (product_l4_policy_match (&runtime.view, &packet, &match) == 0);
  assert (match.action == 1 && match.rule_id == first_version + 2);
  packet.destination_port++;
  assert (product_l4_policy_match (&runtime.view, &packet, &match) == 0);
  assert (match.evaluation == PRODUCT_L4_POLICY_EVALUATION_NO_MATCH);
  runtime.reject = 1;
  request.expected_saved_revision = 4;
  memset (&request.rule, 0, sizeof (request.rule));
  assert (product_rule_config_replace (config, &request, publish, &runtime)
          == SAKAMOTO_RULE_CONFIG_PUBLISH);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 5 && status.active_revision == 4);
  assert (!status.rule.present && status.active_rule_version == first_version + 2);
  runtime.reject = 0;
  assert (product_rule_config_activate (config, publish, &runtime) == 0);
  product_rule_config_query (config, &status);
  assert (status.active_revision == 5 && !status.active_rule_version);
  product_rule_config_close (config);
  FILE *broken = fopen (path, "w");
  assert (broken && fputs ("broken source\n", broken) >= 0 && fclose (broken) == 0);
  config = product_rule_config_open (path);
  product_rule_config_query (config, &status);
  assert (status.saved_revision == 0 && status.active_revision == 0 && status.save_error);
  unsigned publications = runtime.publications;
  assert (product_rule_config_activate (config, publish, &runtime) != 0);
  assert (runtime.publications == publications);
  product_rule_config_close (config);
  unlink (path);
  rmdir (directory);
  puts ("rule configuration: empty, exact UDP, reload, separate saved/active failures, recovery");
  return 0;
}
