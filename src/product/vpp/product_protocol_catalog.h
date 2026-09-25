/* Generated from resources/application-protocol-catalog/catalog.tsv. */
#ifndef PRODUCT_PROTOCOL_CATALOG_H
#define PRODUCT_PROTOCOL_CATALOG_H
#include <stdint.h>
#include <string.h>
#define PRODUCT_PROTOCOL_CATALOG_COUNT 20U
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
    case 1011: return UINT64_C (1) << 10;
    case 1012: return UINT64_C (1) << 11;
    case 1013: return UINT64_C (1) << 12;
    case 1014: return UINT64_C (1) << 13;
    case 1015: return UINT64_C (1) << 14;
    case 1016: return UINT64_C (1) << 15;
    case 1017: return UINT64_C (1) << 16;
    case 1018: return UINT64_C (1) << 17;
    case 1019: return UINT64_C (1) << 18;
    case 1020: return UINT64_C (1) << 19;
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
    case 1011: return "openvpn";
    case 1012: return "wireguard";
    case 1013: return "socks4";
    case 1014: return "socks5";
    case 1015: return "rdp";
    case 1016: return "stun";
    case 1017: return "rtp";
    case 1018: return "rtcp";
    case 1019: return "sip";
    case 1020: return "dtls";
    default: return "";
  }
}
static inline uint32_t product_protocol_id_at (unsigned bit)
{
  static const uint32_t ids[] = { 1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008, 1009, 1010, 1011, 1012, 1013, 1014, 1015, 1016, 1017, 1018, 1019, 1020 };
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
  if (!strcmp (alias, "sakamoto:openvpn")) return 1011;
  if (!strcmp (alias, "sakamoto:wireguard")) return 1012;
  if (!strcmp (alias, "sakamoto:socks4")) return 1013;
  if (!strcmp (alias, "sakamoto:socks5")) return 1014;
  if (!strcmp (alias, "sakamoto:rdp")) return 1015;
  if (!strcmp (alias, "sakamoto:stun")) return 1016;
  if (!strcmp (alias, "sakamoto:rtp")) return 1017;
  if (!strcmp (alias, "sakamoto:rtcp")) return 1018;
  if (!strcmp (alias, "sakamoto:sip")) return 1019;
  if (!strcmp (alias, "sakamoto:dtls")) return 1020;
  return 0;
}
#endif
