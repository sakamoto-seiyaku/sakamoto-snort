/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns.h"
#include "product_cares.h"
#include <string.h>

static uint16_t read_u16 (const uint8_t *wire)
{
  return (uint16_t) (((uint16_t) wire[0] << 8) | wire[1]);
}

product_dns_resources_t product_dns_resources (void)
{
  size_t bytes, operations;
  product_cares_memory_status (&bytes, &operations);
  return (product_dns_resources_t) { bytes, operations };
}

void product_dns_inspect_query (const uint8_t *wire, size_t length,
                                const product_dns_context_t *context,
                                product_dns_query_t *out)
{
  if (!out) return;
  memset (out, 0, sizeof (*out));
  if (!context) return;
  out->packet = context->packet;
  out->caller = context->caller == PRODUCT_DNS_CALLER_KERNEL_APP &&
    context->packet.uid_known && context->packet.uid != UINT32_MAX
      ? PRODUCT_DNS_CALLER_KERNEL_APP : PRODUCT_DNS_CALLER_UNKNOWN;
  out->packet.domain_source = PRODUCT_POLICY_DOMAIN_DNS_QNAME;
  out->packet.domain_available = 0;
  out->packet.domain_lists = 0;
  if (!wire || length < 4)
    { out->coverage = PRODUCT_DNS_MALFORMED; return; }
  out->id = read_u16 (wire);
  out->flags = read_u16 (wire + 2);
  if (out->flags & 0x8000) return;
  if (length < 12 || length > PRODUCT_DNS_MESSAGE_MAX)
    { out->coverage = PRODUCT_DNS_MALFORMED; return; }
  if ((out->flags & 0x7800) || read_u16 (wire + 4) != 1)
    { out->coverage = PRODUCT_DNS_UNSUPPORTED; return; }
  if (product_cares_memory_begin (PRODUCT_DNS_CODEC_BYTES))
    { out->coverage = PRODUCT_DNS_CAPACITY; return; }
  ares_dns_record_t *record = NULL;
  ares_status_t status = product_cares_parse (wire, length, &record);
  out->coverage = status == ARES_ENOMEM ? PRODUCT_DNS_CAPACITY : PRODUCT_DNS_MALFORMED;
  if (status == ARES_SUCCESS && ares_dns_record_query_cnt (record) == 1)
    {
      const char *name = NULL;
      ares_dns_rec_type_t type;
      ares_dns_class_t dnsclass;
      status = ares_dns_record_query_get (record, 0, &name, &type, &dnsclass);
      if (status == ARES_SUCCESS && name && strlen (name) < sizeof (out->name))
        {
          out->qtype = type;
          out->qclass = dnsclass;
          out->name_length = strlen (name);
          memcpy (out->name, name, out->name_length + 1);
          /* c-ares represents the valid DNS root as an empty string. Keep an
           * explicit root QName distinct from missing/unrepresentable facts. */
          if (!out->name_length)
            { out->name[0] = '.'; out->name[1] = 0; out->name_length = 1; }
          out->coverage = PRODUCT_DNS_QUERY_COMPLETE;
          if (out->caller == PRODUCT_DNS_CALLER_KERNEL_APP && context->domains_available)
            {
              out->packet.domain_available = !product_domains_lookup_dns (
                context->domains, (const uint8_t *) out->name, out->name_length,
                &out->packet.domain_lists);
            }
        }
      else if (status == ARES_SUCCESS) out->coverage = PRODUCT_DNS_UNSUPPORTED;
    }
  ares_dns_record_destroy (record);
  size_t unreleased = 0;
  out->codec_peak_bytes = product_cares_memory_end (&unreleased);
  if (unreleased)
    {
      out->coverage = PRODUCT_DNS_MALFORMED;
      out->packet.domain_available = 0;
      out->packet.domain_lists = 0;
    }
}
