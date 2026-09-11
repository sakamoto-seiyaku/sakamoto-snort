/* S229 NFQUEUE fragment policy helper: Rust Product Core -> generated VAPI. */
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
           "s229-nfq/revision/%s", argv[4]);
  if (atoi(argv[5])) {
    const uint32_t uids[] = {0, 1000};
    unsigned index = 0;
    for (unsigned u = 0; u < 2; ++u) {
      for (unsigned f = 0; f < 2; ++f) {
        for (unsigned d = 0; d < 2; ++d) {
        sakamoto_product_policy_rule_entry_t *r = &bundle.l4_entries[index];
        r->subject_uid = uids[u];
        r->network_context = UINT32_MAX;
        r->ifindex = SAKAMOTO_PRODUCT_POLICY_IFINDEX_ANY;
        r->rule_kind = SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4;
        r->action = SAKAMOTO_PRODUCT_POLICY_ACTION_DROP;
        r->enabled = 1;
        r->ip_family = f ? 6 : 4;
        r->ip_protocol = 17;
        r->direction = d ? SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT
                         : SAKAMOTO_PRODUCT_POLICY_DIRECTION_INPUT;
        r->source_port_last = 65535;
        r->destination_port_last = 65535;
        r->rule_id = 22910 + index;
        r->reason_id = 229;
        ++index;
        }
      }
    }
    bundle.l4_rule_count = index;
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
