/* SPDX-License-Identifier: Apache-2.0 */
/* Product rule-source control for the dedicated VPN TUN I/O packet test. */
#include "sakamoto_product_core_ffi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sakamoto_product_bytes_t bytes(const char *value)
{
  return (sakamoto_product_bytes_t) { (const uint8_t *) value,
                                      (uint32_t) strlen(value) };
}

int main(int argc, char **argv)
{
  if (argc != 6) return 2; /* socket generation mode uid source-port */
  uint64_t generation = strtoull(argv[2], NULL, 10);
  uint32_t mode = (uint32_t) strtoul(argv[3], NULL, 10);
  uint32_t uid = (uint32_t) strtoul(argv[4], NULL, 10);
  uint32_t port = (uint32_t) strtoul(argv[5], NULL, 10);
  if ((mode != 0 && mode != 1 && mode != 4) || !generation || !uid || port > 65535)
    return 2;
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  uint32_t rc = sakamoto_product_core_connect(bytes(argv[1]), generation,
                                              &handle, &status);
  if (rc) return (int) rc;
  sakamoto_product_rule_config_request_t request = {.schema = SAKAMOTO_RULE_CONFIG_SCHEMA};
  sakamoto_product_rule_config_status_t source = {0};
  rc = sakamoto_product_core_rule_config(handle, generation, &request, &source);
  if (rc || source.result) goto done;
  request.operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL;
  request.expected_saved_revision = source.saved_revision;
  if (mode) {
    request.count = 1;
    request.rules[0] = (sakamoto_product_direct_rule_t) {
      .uid = uid, .network_context = UINT32_MAX, .ifindex = UINT32_MAX,
      .direction = SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT, .action = 2,
      .protocol = mode == 4 ? 17 : 0,
      .source_port_first = mode == 4 ? port : 0,
      .source_port_last = mode == 4 ? port : 65535,
      .destination_port_last = 65535,
    };
  }
  rc = sakamoto_product_core_rule_config(handle, generation, &request, &source);
done:
  printf("policy rc=%u result=%u generation=%llu revision=%llu mode=%u active_revision=%llu detail=%s\n",
         rc, source.result, (unsigned long long) generation,
         (unsigned long long) source.saved_revision, mode,
         (unsigned long long) source.active_revision, status.error_detail);
  sakamoto_product_core_disconnect(handle);
  sakamoto_product_core_destroy(handle);
  return rc || source.result ? 1 : 0;
}
