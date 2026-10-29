/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_ROUTE_H
#define SAKAMOTO_PRODUCT_DNS_ROUTE_H
#include "sakamoto_product_rule_config.h"
#include <arpa/inet.h>
#include <string.h>

/* Scoped link-local IPv6 needs an interface contract, absent from this profile. */
static inline int product_dns_address_valid (unsigned family, unsigned port, const uint8_t address[16])
{
  if (!port || port > UINT16_MAX) return 0;
  if (family == 4)
    return address[0] && address[0] < 224 && !memcmp (address + 4, (uint8_t[12]) {0}, 12);
  if (family == 6)
    return memcmp (address, (uint8_t[16]) {0}, 16) && address[0] != 0xff &&
      !(address[0] == 0xfe && (address[1] & 0xc0) == 0x80);
  return 0;
}

static inline int product_dns_name_valid (const uint8_t name[256], unsigned length)
{
  if (!length || length > 253 || name[length]) return 0;
  unsigned label = 0;
  for (unsigned i = 0; i < length; ++i)
    if (name[i] == '.') { if (!label || label > 63) return 0; label = 0; }
    else {
      if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9') ||
            name[i] == '-' || name[i] == '_')) return 0;
      ++label;
    }
  return label && label <= 63 && !memcmp (name + length, (uint8_t[256]) {0}, 256 - length);
}

static inline int product_dns_route_valid (const sakamoto_product_dns_config_t *config)
{
  if (!config || config->enabled > 1 || config->reserved || config->reserved2 ||
      config->endpoint_count > SAKAMOTO_DNS_MAX_ENDPOINTS || config->route_count > SAKAMOTO_DNS_MAX_ROUTES ||
      config->exception_count > SAKAMOTO_DNS_MAX_EXCEPTIONS) return 0;
  for (unsigned i = 0; i < SAKAMOTO_DNS_MAX_ENDPOINTS; ++i) {
    const sakamoto_product_dns_endpoint_t *e = &config->endpoints[i];
    if (i >= config->endpoint_count) {
      if (memcmp (e, &(sakamoto_product_dns_endpoint_t) {0}, sizeof (*e))) return 0;
      continue;
    }
    size_t n = strnlen ((const char *) e->identity, sizeof (e->identity));
    uint8_t numeric[16];
    if ((e->transport != 1 && e->transport != 2) || e->reserved ||
        !product_dns_address_valid (e->family, e->port, e->address) || n >= 256 || !n ||
        (!product_dns_name_valid (e->identity, n) &&
         inet_pton (AF_INET, (const char *) e->identity, numeric) != 1 &&
         inet_pton (AF_INET6, (const char *) e->identity, numeric) != 1) ||
        memcmp (e->identity + n, (uint8_t[256]) {0}, 256 - n)) return 0;
  }
  for (unsigned i = 0; i < SAKAMOTO_DNS_MAX_ROUTES; ++i) {
    const sakamoto_product_dns_route_t *r = &config->routes[i];
    if (i >= config->route_count) {
      if (memcmp (r, &(sakamoto_product_dns_route_t) {0}, sizeof (*r))) return 0;
      continue;
    }
    if (!r->count || r->count > SAKAMOTO_DNS_MAX_ENDPOINTS || r->reserved) return 0;
    unsigned seen = 0;
    for (unsigned j = 0; j < SAKAMOTO_DNS_MAX_ENDPOINTS; ++j) {
      if (j >= r->count) { if (r->candidates[j]) return 0; continue; }
      if (r->candidates[j] >= config->endpoint_count || (seen & (1U << r->candidates[j]))) return 0;
      seen |= 1U << r->candidates[j];
    }
  }
  for (unsigned i = 0; i < SAKAMOTO_DNS_MAX_EXCEPTIONS; ++i) {
    const sakamoto_product_dns_exception_t *e = &config->exceptions[i];
    if (i >= config->exception_count) {
      if (memcmp (e, &(sakamoto_product_dns_exception_t) {0}, sizeof (*e))) return 0;
      continue;
    }
    if (e->match > 1 || e->target > 1 || (e->target ? e->route >= config->route_count : e->route != 0) ||
        !product_dns_name_valid (e->name, e->length)) return 0;
    for (unsigned j = 0; j < i; ++j)
      if (e->match == config->exceptions[j].match && !strcmp ((const char *) e->name,
            (const char *) config->exceptions[j].name)) return 0;
  }
  if (!config->endpoint_count)
    return !config->route_count && !config->exception_count &&
      ((!config->enabled && !config->family && !config->port &&
        !memcmp (config->address, (uint8_t[16]) {0}, 16)) ||
       product_dns_address_valid (config->family, config->port, config->address));
  if (!config->route_count) return 0;
  const sakamoto_product_dns_endpoint_t *first = &config->endpoints[config->routes[0].candidates[0]];
  return config->family == first->family && config->port == first->port &&
    !memcmp (config->address, first->address, 16);
}
#endif
