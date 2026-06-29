/* SPDX-License-Identifier: Apache-2.0 */

#ifndef TUN_POC_CONTROL_SHIM_H
#define TUN_POC_CONTROL_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TUN_POC_CONTROL_SHIM_ABI_VERSION 1u

typedef struct
{
  int32_t retval;
  uint8_t enabled;
  uint8_t owner_cache_enabled;
  uint8_t block_owner_uid_set;
  uint8_t reserved0;
  uint32_t mode;
  uint64_t rx_packets;
  uint64_t tx_packets;
  uint64_t shim_tx_packets;
  uint64_t blocked_packets;
  uint64_t resolver_queries;
  uint64_t resolver_hits;
  uint64_t owner_cache_hits;
  uint64_t uid_blocked_packets;
  int32_t block_owner_uid;
  int32_t last_owner_uid;
} tun_poc_status_out_t;

uint32_t tun_poc_control_shim_abi_version (void);
int tun_poc_status_get (const char *api_sock, tun_poc_status_out_t *out);

#ifdef __cplusplus
}
#endif

#endif
