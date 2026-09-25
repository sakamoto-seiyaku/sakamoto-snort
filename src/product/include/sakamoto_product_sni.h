/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_SNI_QUERY_H
#define SAKAMOTO_PRODUCT_SNI_QUERY_H
#include <stdint.h>
/* Borrow-free single Flow query; generation/owner/slot/incarnation are required.
 * A stale/ended identity returns an error and a zero result, never another Flow. */
typedef struct {
  uint64_t generation, incarnation, protocols;
  uint32_t worker, slot, result, stop, attempts, bytes, work, cache_bytes;
  uint32_t name_length, protocols_available;
  char name[254];
} sakamoto_product_sni_status_t;
#endif
