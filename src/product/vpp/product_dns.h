/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DNS_H
#define SAKAMOTO_PRODUCT_DNS_H

#include "product_l4_policy.h"
#include "product_domains.h"

#define PRODUCT_DNS_MESSAGE_MAX 65535U
#define PRODUCT_DNS_CODEC_BYTES (512U * 1024U)

typedef enum {
  PRODUCT_DNS_NOT_QUERY = 0,
  PRODUCT_DNS_QUERY_COMPLETE,
  PRODUCT_DNS_MALFORMED,
  PRODUCT_DNS_UNSUPPORTED,
  PRODUCT_DNS_CAPACITY,
  PRODUCT_DNS_COPY_GAP,
} product_dns_coverage_t;

/* A known socket UID alone does not establish the original DNS caller. */
typedef enum {
  PRODUCT_DNS_CALLER_UNKNOWN = 0,
  PRODUCT_DNS_CALLER_KERNEL_APP = 1,
} product_dns_caller_t;

typedef struct {
  product_l4_policy_packet_t packet;
  const product_domains_t *domains; /* synchronous protected-snapshot borrow */
  product_dns_caller_t caller;
} product_dns_context_t;

typedef struct {
  product_l4_policy_packet_t packet;
  uint32_t codec_peak_bytes;
  uint16_t id, flags, qtype, qclass, name_length;
  uint8_t coverage, caller;
  char name[256];
} product_dns_query_t;

/* Complete message observation only. No wire rewrite, retained borrow, socket,
 * permission cache, or asynchronous work. Generic packet facts stay intact. */
void product_dns_inspect_query (const uint8_t *, size_t,
                                const product_dns_context_t *,
                                product_dns_query_t *);
typedef struct { uint64_t codec_live_bytes, active_operations; } product_dns_resources_t;
product_dns_resources_t product_dns_resources (void);
#endif
