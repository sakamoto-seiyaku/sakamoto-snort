/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_DNS_ADMISSION_H
#define SAKAMOTO_PRODUCT_ROOT_DNS_ADMISSION_H

#include <stdint.h>
#include <string.h>

typedef struct
{
  uint8_t family, dns_header_present;
  uint8_t source_address[16], resolver_address[16];
  uint16_t source_port, resolver_port, id, query_flags;
  uint32_t packet_length;
} product_root_dns_admission_facts_t;

typedef enum
{
  PRODUCT_ROOT_DNS_ADMISSION_NON_DNS = 0,
  PRODUCT_ROOT_DNS_ADMISSION_QUERY = 1,
  PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE = 2,
} product_root_dns_admission_classification_t;

static inline uint16_t
product_root_dns_admission_be16 (const uint8_t *data)
{
  return (uint16_t) (((uint16_t) data[0] << 8) | data[1]);
}

/* This is admission classification, not DNS validation or policy. It walks a
 * physically visible IPv6 extension prefix without the shared semantic
 * parser's 256-byte work budget so an otherwise unsupported query cannot use
 * a resource fallback to escape enabled replacement. Every step consumes at
 * least eight visible bytes, keeping the walk bounded by the captured prefix. */
static inline product_root_dns_admission_classification_t
product_root_dns_admission_classify (const uint8_t *data, uint32_t length,
                                     product_root_dns_admission_facts_t *out)
{
  product_root_dns_admission_facts_t facts = {0};
  if (!data || !length)
    return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
  uint32_t at;
  uint8_t protocol;
  if ((data[0] >> 4) == 4)
    {
      if (length < 20)
        return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
      at = (uint32_t) (data[0] & 15) * 4;
      if (at < 20 || (product_root_dns_admission_be16 (data + 6) & 0x1fff))
        return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
      protocol = data[9];
      facts.family = 4;
      facts.packet_length = product_root_dns_admission_be16 (data + 2);
      memcpy (facts.source_address, data + 12, 4);
      memcpy (facts.resolver_address, data + 16, 4);
      if (at > length)
        {
          if (out) *out = facts;
          return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
        }
    }
  else if ((data[0] >> 4) == 6)
    {
      if (length < 40)
        return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
      at = 40;
      protocol = data[6];
      facts.family = 6;
      facts.packet_length = 40 + product_root_dns_admission_be16 (data + 4);
      memcpy (facts.source_address, data + 8, 16);
      memcpy (facts.resolver_address, data + 24, 16);
      while (protocol == 0 || protocol == 43 || protocol == 60
             || protocol == 51 || protocol == 44)
        {
          if (protocol == 44)
            {
              if (length - at < 8)
                {
                  if (out) *out = facts;
                  return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
                }
              if (product_root_dns_admission_be16 (data + at + 2) & 0xfff8)
                return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
              protocol = data[at];
              at += 8;
            }
          else
            {
              if (length - at < 2)
                {
                  if (out) *out = facts;
                  return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
                }
              uint32_t bytes = protocol == 51
                ? ((uint32_t) data[at + 1] + 2) * 4
                : ((uint32_t) data[at + 1] + 1) * 8;
              if (!bytes)
                return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
              if (bytes > length - at)
                {
                  if (out) *out = facts;
                  return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
                }
              protocol = data[at];
              at += bytes;
            }
        }
    }
  else
    return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
  if (protocol != 17)
    return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
  if (length - at < 4)
    {
      if (out) *out = facts;
      return PRODUCT_ROOT_DNS_ADMISSION_INCOMPLETE;
    }
  if (product_root_dns_admission_be16 (data + at + 2) != 53)
    return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
  facts.source_port = product_root_dns_admission_be16 (data + at);
  facts.resolver_port = 53;
  if (length - at >= 12)
    {
      facts.dns_header_present = 1;
      facts.id = product_root_dns_admission_be16 (data + at + 8);
      facts.query_flags = product_root_dns_admission_be16 (data + at + 10);
      if (facts.query_flags & 0x8000)
        return PRODUCT_ROOT_DNS_ADMISSION_NON_DNS;
    }
  if (out)
    *out = facts;
  return PRODUCT_ROOT_DNS_ADMISSION_QUERY;
}

static inline int
product_root_dns_admission_query (const uint8_t *data, uint32_t length,
                                  product_root_dns_admission_facts_t *out)
{
  return product_root_dns_admission_classify (data, length, out)
    == PRODUCT_ROOT_DNS_ADMISSION_QUERY;
}

#endif
