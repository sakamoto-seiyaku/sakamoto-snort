/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_CONFIG_COPY_H
#define SAKAMOTO_PRODUCT_DNS_CONFIG_COPY_H
#include "sakamoto_product_rule_config.h"
#include <string.h>

/* The generated VAPI and VPP structs have distinct C types. Keep their one
 * bounded field mapping here; the caller supplies the numeric byte order. */
#define SAKAMOTO_DNS_HOST_VALUE(value) (value)
#define SAKAMOTO_DNS_CONFIG_COPY(dst, src, number) do { \
  (dst).enabled=number((src).enabled); (dst).family=number((src).family); \
  (dst).port=number((src).port); (dst).reserved=number((src).reserved); \
  memcpy((dst).address,(src).address,16); \
  (dst).endpoint_count=number((src).endpoint_count); (dst).route_count=number((src).route_count); \
  (dst).exception_count=number((src).exception_count); (dst).reserved2=number((src).reserved2); \
  for (unsigned dns_i=0;dns_i<SAKAMOTO_DNS_MAX_ENDPOINTS;++dns_i) { \
    (dst).endpoints[dns_i].transport=number((src).endpoints[dns_i].transport); \
    (dst).endpoints[dns_i].family=number((src).endpoints[dns_i].family); \
    (dst).endpoints[dns_i].port=number((src).endpoints[dns_i].port); \
    (dst).endpoints[dns_i].reserved=number((src).endpoints[dns_i].reserved); \
    memcpy((dst).endpoints[dns_i].address,(src).endpoints[dns_i].address,16); \
    memcpy((dst).endpoints[dns_i].identity,(src).endpoints[dns_i].identity,256); \
  } \
  for (unsigned dns_i=0;dns_i<SAKAMOTO_DNS_MAX_ROUTES;++dns_i) { \
    (dst).routes[dns_i].count=number((src).routes[dns_i].count); \
    (dst).routes[dns_i].reserved=number((src).routes[dns_i].reserved); \
    for (unsigned dns_j=0;dns_j<SAKAMOTO_DNS_MAX_ENDPOINTS;++dns_j) \
      (dst).routes[dns_i].candidates[dns_j]=number((src).routes[dns_i].candidates[dns_j]); \
  } \
  for (unsigned dns_i=0;dns_i<SAKAMOTO_DNS_MAX_EXCEPTIONS;++dns_i) { \
    (dst).exceptions[dns_i].match=number((src).exceptions[dns_i].match); \
    (dst).exceptions[dns_i].target=number((src).exceptions[dns_i].target); \
    (dst).exceptions[dns_i].route=number((src).exceptions[dns_i].route); \
    (dst).exceptions[dns_i].length=number((src).exceptions[dns_i].length); \
    memcpy((dst).exceptions[dns_i].name,(src).exceptions[dns_i].name,256); \
  } \
} while (0)
#endif
