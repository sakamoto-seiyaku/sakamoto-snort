/* Real Linux acceptance control client: Rust Product Core -> generated VAPI. */
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sakamoto_product_bytes_t bytes(const char *s) {
  return (sakamoto_product_bytes_t){(const uint8_t *)s, (uint32_t)strlen(s)};
}

int main(int argc, char **argv) {
  if (argc != 6) return 2; /* socket generation files-dir revision blocked */
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
           "s230/revision/%s", argv[4]);
  if (atoi(argv[5])) {
    bundle.gate_entry_count = 1;
    sakamoto_product_policy_rule_entry_t *r = &bundle.gate_entries[0];
    r->subject_uid = 0;
    r->network_context = UINT32_MAX;
    r->ifindex = SAKAMOTO_PRODUCT_POLICY_IFINDEX_ANY;
    r->rule_kind = SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE;
    r->action = SAKAMOTO_PRODUCT_POLICY_ACTION_DROP;
    r->enabled = 1;
    r->rule_id = 230;
    r->reason_id = 230;
  }
  rc = sakamoto_product_core_apply_policy_bundle(handle, generation,
                          bytes(argv[3]), &bundle, &status);
  printf("policy rc=%u generation=%llu revision=%llu blocked=%s\n", rc,
         (unsigned long long)generation,
         (unsigned long long)bundle.requested_revision, argv[5]);
  printf("detail=%s\n", status.error_detail);
  sakamoto_product_core_disconnect(handle);
  sakamoto_product_core_destroy(handle);
  return (int)rc;
}
