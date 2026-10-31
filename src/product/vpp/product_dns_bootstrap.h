/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DNS_BOOTSTRAP_H
#define PRODUCT_DNS_BOOTSTRAP_H
#include <stddef.h>
#include <stdint.h>
#define PRODUCT_DNS_BOOTSTRAP_ADDRESSES 4U
#define PRODUCT_DNS_BOOTSTRAP_QUERY_BYTES 512U
typedef struct { uint32_t family; uint8_t address[16]; } product_dns_bootstrap_address_t;
/* Private, synchronous bounded codec. Its only caller is the selected
 * upstream transport; application queries cannot acquire bootstrap authority. */
int product_dns_bootstrap_query(const char *,uint16_t id,unsigned type,
  uint8_t [PRODUCT_DNS_BOOTSTRAP_QUERY_BYTES],size_t *);
/* 1 address data, 0 valid NODATA, 2 correlated TC, -1 invalid/failure. */
int product_dns_bootstrap_answer(const uint8_t *,size_t,const uint8_t *,size_t,
  product_dns_bootstrap_address_t [PRODUCT_DNS_BOOTSTRAP_ADDRESSES],unsigned *);
#endif
