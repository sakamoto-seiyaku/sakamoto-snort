/* Generated from resources/application-protocol-catalog/catalog.tsv. */
#ifndef PRODUCT_PROTOCOL_CATALOG_H
#define PRODUCT_PROTOCOL_CATALOG_H
#include <stdint.h>
#include <string.h>
#define PRODUCT_PROTOCOL_CATALOG_COUNT 5U
static inline uint64_t product_protocol_bit (uint32_t id)
{
  switch (id) {
    case 1001: return UINT64_C (1) << 0;
    case 1002: return UINT64_C (1) << 1;
    case 1003: return UINT64_C (1) << 2;
    case 1004: return UINT64_C (1) << 3;
    case 1005: return UINT64_C (1) << 4;
    default: return 0;
  }
}
static inline const char *product_protocol_key (uint32_t id)
{
  switch (id) {
    case 1001: return "dns";
    case 1002: return "http";
    case 1003: return "tls";
    case 1004: return "quic";
    case 1005: return "ssh";
    default: return "";
  }
}
static inline uint32_t product_protocol_id_at (unsigned bit)
{
  static const uint32_t ids[] = { 1001, 1002, 1003, 1004, 1005 };
  return bit < PRODUCT_PROTOCOL_CATALOG_COUNT ? ids[bit] : 0;
}
static inline uint32_t product_protocol_provider_id (const char *alias)
{
  if (!alias) return 0;
  if (!strcmp (alias, "lpi:dns")) return 1001;
  if (!strcmp (alias, "lpi:http")) return 1002;
  if (!strcmp (alias, "lpi:ssl")) return 1003;
  if (!strcmp (alias, "lpi:tls")) return 1003;
  if (!strcmp (alias, "lpi:quic")) return 1004;
  if (!strcmp (alias, "lpi:ssh")) return 1005;
  return 0;
}
#endif
