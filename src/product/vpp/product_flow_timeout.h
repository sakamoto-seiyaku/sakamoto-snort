/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FLOW_TIMEOUT_H
#define SAKAMOTO_PRODUCT_FLOW_TIMEOUT_H

#include "product_flow_tracker.h"

/* OVS 3c2bea086ef8912d57331173af266f21d36740a0 default policy, in us.
 * S227 enables UDP only; the same map will acquire TCP/ICMP in S236.
 * No tracker or caller gets an independently configurable timeout policy. */
static inline uint64_t
product_flow_timeout_us (product_ct_timeout_t timeout)
{
  switch (timeout)
    {
    case PRODUCT_CT_TIMEOUT_OTHER_FIRST:
    case PRODUCT_CT_TIMEOUT_OTHER_MULTIPLE: return UINT64_C (60000000);
    case PRODUCT_CT_TIMEOUT_OTHER_BIDIR: return UINT64_C (30000000);
    default: return 0;
    }
}

static inline int
product_flow_deadline (product_ct_timeout_t timeout, uint64_t now_us,
                       uint64_t *deadline_us)
{
  uint64_t duration = product_flow_timeout_us (timeout);
  if (!duration || !deadline_us) return 0;
  *deadline_us = now_us > UINT64_MAX - duration ? UINT64_MAX : now_us + duration;
  return 1;
}

#endif
