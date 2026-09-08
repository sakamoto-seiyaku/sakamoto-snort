/* S219 first-fragment policy control client: Rust Product Core -> generated VAPI. */
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sakamoto_product_bytes_t bytes(const char *s) {
  return (sakamoto_product_bytes_t){(const uint8_t *)s, (uint32_t)strlen(s)};
}

int main(int argc, char **argv) {
  if (argc != 8) return 2; /* socket generation files-dir revision mode uid ifindex */
  uint64_t generation = strtoull(argv[2], NULL, 10);
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  uint32_t rc = sakamoto_product_core_connect(bytes(argv[1]), generation,
                                             &handle, &status);
  if (rc) return (int)rc;
  sakamoto_product_policy_bundle_t bundle = {0};
  bundle.abi_version = SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION;
  bundle.struct_size = sizeof(bundle);
  bundle.requested_revision = strtoull(argv[4], NULL, 10);
  bundle.snapshot_hash = bundle.requested_revision;
  bundle.default_pass = 1;
  snprintf(bundle.snapshot_identity, sizeof(bundle.snapshot_identity),
           "s219/revision/%s", argv[4]);
  int mode = atoi(argv[5]);
  if (mode) {
    bundle.gate_entry_count = 1;
    sakamoto_product_policy_rule_entry_t *r = &bundle.gate_entries[0];
    r->subject_uid = (uint32_t) strtoul(argv[6], NULL, 10);
    r->network_context = 1;
    r->ifindex = 31;
    r->rule_kind = SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE;
    r->action = SAKAMOTO_PRODUCT_POLICY_ACTION_DROP;
    r->enabled = 1;
    r->rule_id = 21900 + mode;
    r->reason_id = 219;
    if (mode == 2) {
      bundle.gate_entry_count = 0;
      bundle.l4_rule_count = 2;
      for (unsigned i = 0; i < 2; i++) {
        bundle.l4_entries[i] = *r;
        sakamoto_product_policy_rule_entry_t *l4 = &bundle.l4_entries[i];
        l4->rule_kind = SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4;
        l4->ip_family = i ? 6 : 4;
        l4->ip_protocol = 17;
        l4->direction = SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT;
        l4->source_port_last = l4->destination_port_last = 65535;
        l4->rule_id += i;
      }
      memset(r, 0, sizeof(*r));
    }
  }
  rc = sakamoto_product_core_apply_policy_bundle(handle, generation,
                          bytes(argv[3]), &bundle, &status);
  printf("policy rc=%u generation=%llu revision=%llu mode=%s\n", rc,
         (unsigned long long)generation,
         (unsigned long long)bundle.requested_revision, argv[5]);
  printf("detail=%s\n", status.error_detail);
  sakamoto_product_core_disconnect(handle);
  sakamoto_product_core_destroy(handle);
  return (int)rc;
}
