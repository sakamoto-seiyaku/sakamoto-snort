/* Controlled VAPI publication; never a platform event or packet injector. */
#include "sakamoto_product_core_ffi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 4) return 2;
  sakamoto_product_bytes_t socket = {
    (const uint8_t *)argv[1], (uint32_t)strlen(argv[1])};
  uint64_t generation = strtoull(argv[2], NULL, 10);
  sakamoto_product_network_snapshot_t snapshot = {0};
  snapshot.revision = strtoull(argv[3], NULL, 10);
  sakamoto_product_core_handle_t *handle = NULL;
  sakamoto_product_status_t status = {0};
  uint32_t code = sakamoto_product_core_connect(socket, generation, &handle, &status);
  if (!code) code = sakamoto_product_core_publish_network(handle, generation, &snapshot);
  printf("controlled_snapshot generation=%llu revision=%llu code=%u\n",
         (unsigned long long)generation, (unsigned long long)snapshot.revision, code);
  if (handle) {
    sakamoto_product_core_disconnect(handle);
    sakamoto_product_core_destroy(handle);
  }
  return code ? 1 : 0;
}
