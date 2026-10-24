/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_ROUTE_H
#define SAKAMOTO_PRODUCT_DNS_ROUTE_H
#include "sakamoto_product_rule_config.h"
#include <string.h>

/* A narrow numeric ordinary endpoint. Scoped link-local IPv6 requires an
 * interface contract absent from this configuration, so it cannot publish. */
static inline int product_dns_route_valid (const sakamoto_product_dns_config_t *route)
{
  if (!route || route->enabled > 1 || route->reserved) return 0;
  if (!route->enabled && !route->family && !route->port &&
      !memcmp (route->address, (uint8_t[16]) {0}, 16)) return 1;
  if (!route->port || route->port > UINT16_MAX) return 0;
  if (route->family == 4)
    return route->address[0] && route->address[0] < 224 &&
      !memcmp (route->address + 4, (uint8_t[12]) {0}, 12);
  if (route->family == 6)
    return memcmp (route->address, (uint8_t[16]) {0}, 16) && route->address[0] != 0xff &&
      !(route->address[0] == 0xfe && (route->address[1] & 0xc0) == 0x80);
  return 0;
}
#endif
