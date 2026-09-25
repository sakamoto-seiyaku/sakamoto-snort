/* SPDX-License-Identifier: Apache-2.0 */
/* Persistent real Product API session: avoids VAPI client registration while
 * a packet reader is deliberately held. Never writes the source file itself. */
#include "sakamoto_product_core_ffi.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
  if (argc != 3) return 2;
  uint64_t generation = strtoull(argv[2], NULL, 10);
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  sakamoto_product_bytes_t path = {(const uint8_t *)argv[1], (uint32_t)strlen(argv[1])};
  uint32_t rc = sakamoto_product_core_connect(path, generation, &handle, &status);
  if (rc) return (int)rc;
  puts("ready"); fflush(stdout);
  uint64_t revision;
  unsigned mode;
  while (scanf("%" SCNu64 " %u", &revision, &mode) == 2) {
    sakamoto_product_rule_config_request_t request = {.schema=1};
    sakamoto_product_rule_config_status_t source = {0};
    rc = sakamoto_product_core_rule_config(handle, generation, &request, &source);
    if (rc || source.result || source.count != 2 || source.graph.binding_count != 2
        || source.saved_revision != revision || mode > 1) return 3;
    request.operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL;
    request.expected_saved_revision = revision;
    request.count = source.count;
    memcpy(request.rules, source.rules, sizeof request.rules);
    request.graph = source.graph;
    request.graph.bindings[0].mode = mode;
    rc = sakamoto_product_core_rule_config(handle, generation, &request, &source);
    printf("{\"rc\":%u,\"result\":%u,\"saved_revision\":%" PRIu64
           ",\"active_revision\":%" PRIu64 "}\n",
           rc, source.result, source.saved_revision, source.active_revision);
    fflush(stdout);
    if (rc || source.result) return 4;
  }
  sakamoto_product_core_disconnect(handle);
  sakamoto_product_core_destroy(handle);
  return 0;
}
