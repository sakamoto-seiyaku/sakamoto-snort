/* SPDX-License-Identifier: Apache-2.0 */
/* Coarse policy/controlled snapshot client. Never a packet/classifier injector. */
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static sakamoto_product_bytes_t bytes (const char *s) {
  return (sakamoto_product_bytes_t) {(const uint8_t *) s, (uint32_t) strlen (s)};
}
int main (int argc, char **argv) {
  /* socket generation files revision mode uid context ifindex
   * mode: 0 empty, 1 Gate, 2 L4 OUT, 3 L4 IN, 4 external snapshot */
  if (argc != 9) return 2;
  uint64_t generation = strtoull (argv[2], NULL, 10);
  uint64_t revision = strtoull (argv[4], NULL, 10);
  unsigned mode = strtoul (argv[5], NULL, 10);
  uint32_t uid = strtoul (argv[6], NULL, 10);
  uint32_t context = strtoul (argv[7], NULL, 10);
  uint32_t ifindex = strtoul (argv[8], NULL, 10);
  if (mode > 4) return 2;
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  uint32_t rc = sakamoto_product_core_connect (bytes (argv[1]), generation, &handle, &status);
  if (rc) return (int) rc;
  if (mode == 4) {
    sakamoto_product_network_snapshot_t snapshot = {.revision = revision};
    if (context) {
      snapshot.count = 1;
      snapshot.entries[0] = (sakamoto_product_network_entry_t) {ifindex, context};
    }
    rc = sakamoto_product_core_publish_network (handle, generation, &snapshot);
  } else {
    sakamoto_product_policy_bundle_t bundle = {0};
    bundle.abi_version = SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION;
    bundle.struct_size = sizeof (bundle);
    bundle.requested_revision = revision;
    bundle.snapshot_hash = revision;
    bundle.default_pass = 1;
    snprintf (bundle.snapshot_identity, sizeof (bundle.snapshot_identity), "s235/%llu",
              (unsigned long long) revision);
    if (mode) {
      unsigned count = mode == 1 ? 1 : 2;
      if (mode == 1) bundle.gate_entry_count = count;
      else bundle.l4_rule_count = count;
      for (unsigned i = 0; i < count; ++i) {
        sakamoto_product_policy_rule_entry_t *rule = mode == 1 ?
          &bundle.gate_entries[i] : &bundle.l4_entries[i];
        rule->subject_uid = uid;
        rule->network_context = context;
        rule->ifindex = ifindex;
        rule->rule_kind = mode == 1 ? SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE :
                                     SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4;
        rule->action = SAKAMOTO_PRODUCT_POLICY_ACTION_DROP;
        rule->enabled = 1; rule->rule_id = 23500 + mode * 10 + i; rule->reason_id = 235;
        if (mode != 1) {
          rule->ip_family = i ? 6 : 4; rule->ip_protocol = 17;
          rule->direction = mode == 3 ? SAKAMOTO_PRODUCT_POLICY_DIRECTION_INPUT :
                                       SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT;
          rule->source_port_last = rule->destination_port_last = 65535;
        }
      }
    }
    rc = sakamoto_product_core_apply_policy_bundle (handle, generation, bytes (argv[3]), &bundle, &status);
  }
  printf ("control rc=%u generation=%llu revision=%llu mode=%u uid=%u context=%u ifindex=%u\n",
          rc, (unsigned long long) generation, (unsigned long long) revision, mode, uid, context, ifindex);
  printf ("detail=%s\n", status.error_detail);
  sakamoto_product_core_disconnect (handle);
  sakamoto_product_core_destroy (handle);
  return rc ? 1 : 0;
}
