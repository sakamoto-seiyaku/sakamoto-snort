/* S241: narrow OUTPUT source-port DROP through real Product Core/VAPI. */
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sakamoto_product_bytes_t bytes(const char *value)
{ return (sakamoto_product_bytes_t){(const uint8_t *)value, (uint32_t)strlen(value)}; }

int main(int argc, char **argv)
{
  if (argc != 8 && argc != 9) return 2; /* api generation files-dir revision protocol uid source-port [last-port] */
  unsigned protocol = (unsigned)strtoul(argv[5], NULL, 10);
  unsigned port = (unsigned)strtoul(argv[7], NULL, 10);
  unsigned last_port = argc == 9 ? (unsigned)strtoul(argv[8], NULL, 10) : port;
  if ((protocol && protocol != 6 && protocol != 17) || port > 65535 || (protocol && !port)) return 2;
  if (last_port < port || last_port > 65535) return 2;
  uint64_t generation = strtoull(argv[2], NULL, 10);
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  uint32_t result = sakamoto_product_core_connect(bytes(argv[1]), generation, &handle, &status);
  if (result) return (int)result;
  sakamoto_product_policy_bundle_t bundle = {0};
  bundle.abi_version = SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION;
  bundle.struct_size = sizeof(bundle);
  bundle.requested_revision = strtoull(argv[4], NULL, 10);
  bundle.snapshot_hash = bundle.requested_revision;
  bundle.default_pass = 1;
  snprintf(bundle.snapshot_identity, sizeof(bundle.snapshot_identity), "s241/%s", argv[4]);
  if (protocol) {
    bundle.l4_rule_count = 2;
    for (unsigned i = 0; i < 2; ++i) {
      sakamoto_product_policy_rule_entry_t *rule = &bundle.l4_entries[i];
      rule->subject_uid = (uint32_t)strtoul(argv[6], NULL, 10);
      rule->network_context = UINT32_MAX;
      rule->ifindex = SAKAMOTO_PRODUCT_POLICY_IFINDEX_ANY;
      rule->rule_kind = SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4;
      rule->action = SAKAMOTO_PRODUCT_POLICY_ACTION_DROP;
      rule->enabled = 1;
      rule->rule_id = 24100 + i;
      rule->reason_id = 241;
      rule->ip_family = i ? 6 : 4;
      rule->ip_protocol = protocol;
      rule->direction = SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT;
      rule->source_port_first = port;
      rule->source_port_last = last_port;
      rule->destination_port_last = 65535;
    }
  }
  result = sakamoto_product_core_apply_policy_bundle(handle, generation, bytes(argv[3]), &bundle, &status);
  printf("policy rc=%u generation=%llu revision=%llu protocol=%u source_port=%u last_port=%u detail=%s\n",
    result, (unsigned long long)generation, (unsigned long long)bundle.requested_revision,
    protocol, port, last_port, status.error_detail);
  sakamoto_product_core_disconnect(handle);
  sakamoto_product_core_destroy(handle);
  return (int)result;
}
