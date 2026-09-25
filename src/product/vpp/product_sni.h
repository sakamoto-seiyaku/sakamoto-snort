/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_SNI_H
#define SAKAMOTO_PRODUCT_SNI_H
#include <stdint.h>
#define PRODUCT_SNI_NAME_BYTES 254U
#define PRODUCT_TCP_CACHE_SIDE_BYTES 4096U
#define PRODUCT_TCP_CACHE_RANGES 16U
#define PRODUCT_SNI_MAX_PACKETS 20U
#define PRODUCT_SNI_TIMEOUT_US UINT64_C(5000000)
typedef enum { PRODUCT_SNI_UNAVAILABLE, PRODUCT_SNI_NAME, PRODUCT_SNI_ABSENT } product_sni_result_t;
typedef enum { PRODUCT_SNI_RUNNING, PRODUCT_SNI_COMPLETE, PRODUCT_SNI_MALFORMED,
  PRODUCT_SNI_UNSUPPORTED, PRODUCT_SNI_SEQUENCE, PRODUCT_SNI_BYTE_BUDGET,
  PRODUCT_SNI_PACKET_BUDGET, PRODUCT_SNI_TIMEOUT, PRODUCT_SNI_FLOW_END } product_sni_stop_t;
/* One TCP-owned cache, independent directional sequence spaces. TLS borrows
 * these bytes synchronously and retains only small result/attempt metadata. */
typedef struct {
  uint8_t bytes[2][PRODUCT_TCP_CACHE_SIDE_BYTES];
  uint32_t base_sequence[2];
  struct { uint16_t first, last; } ranges[2][PRODUCT_TCP_CACHE_RANGES];
  uint16_t length[2];
  uint16_t contiguous[2];
  uint8_t started[2], range_count[2];
} product_tcp_byte_cache_t;
typedef struct {
  uint64_t started_us, deadline_us;
  uint32_t bytes, work;
  uint16_t name_length;
  uint8_t result, stop, attempts;
  char name[PRODUCT_SNI_NAME_BYTES];
} product_sni_state_t;
#endif
