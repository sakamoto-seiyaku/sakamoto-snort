/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_NETWORK_H
#define SAKAMOTO_PRODUCT_NETWORK_H

#include <stdint.h>

/* Control-plane values only. Unknown is absence from this bounded map. */
#define SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES 32U
#define SAKAMOTO_PRODUCT_NETWORK_WIFI 1U
#define SAKAMOTO_PRODUCT_NETWORK_MOBILE 2U
#define SAKAMOTO_PRODUCT_NETWORK_VPN 4U
#define SAKAMOTO_PRODUCT_NETWORK_WIRED 8U

typedef struct {
  uint32_t linux_ifindex;
  uint32_t context;
} sakamoto_product_network_entry_t;

typedef struct {
  uint64_t revision;
  uint64_t event_elapsed_ns;
  uint32_t count;
  uint32_t reserved;
  sakamoto_product_network_entry_t entries[SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES];
} sakamoto_product_network_snapshot_t;

#ifdef __cplusplus
static_assert(sizeof(sakamoto_product_network_snapshot_t) == 280,
              "network snapshot ABI size");
#else
_Static_assert(sizeof(sakamoto_product_network_snapshot_t) == 280,
               "network snapshot ABI size");
#endif

#endif
