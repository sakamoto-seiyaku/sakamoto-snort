/* Generated from resources/application-protocol-catalog/catalog.tsv. */
#ifndef PRODUCT_PROTOCOL_CATALOG_H
#define PRODUCT_PROTOCOL_CATALOG_H
#include <stdint.h>
#include <string.h>
#define PRODUCT_PROTOCOL_CATALOG_COUNT 10U
static inline uint64_t product_protocol_bit (uint32_t id)
{
  switch (id) {
    case 1001: return UINT64_C (1) << 0;
    case 1002: return UINT64_C (1) << 1;
    case 1003: return UINT64_C (1) << 2;
    case 1004: return UINT64_C (1) << 3;
    case 1005: return UINT64_C (1) << 4;
    case 1006: return UINT64_C (1) << 5;
    case 1007: return UINT64_C (1) << 6;
    case 1008: return UINT64_C (1) << 7;
    case 1009: return UINT64_C (1) << 8;
    case 1010: return UINT64_C (1) << 9;
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
    case 1006: return "mdns";
    case 1007: return "smtp";
    case 1008: return "ftp-control";
    case 1009: return "ftp-data";
    case 1010: return "ftps";
    default: return "";
  }
}
static inline uint32_t product_protocol_id_at (unsigned bit)
{
  static const uint32_t ids[] = { 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010 };
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
  if (!strcmp (alias, "sakamoto:mdns")) return 1006;
  if (!strcmp (alias, "sakamoto:smtp")) return 1007;
  if (!strcmp (alias, "sakamoto:ftp-control")) return 1008;
  if (!strcmp (alias, "sakamoto:ftp-data")) return 1009;
  if (!strcmp (alias, "sakamoto:ftps")) return 1010;
  return 0;
}
#endif
