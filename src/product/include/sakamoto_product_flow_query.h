/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FLOW_QUERY_H
#define SAKAMOTO_PRODUCT_FLOW_QUERY_H

#include <stdint.h>
#include <stddef.h>
#include "sakamoto_product_observation.h"

/* One VPP main-thread query scans at most 256 slots under the worker barrier.
 * Pages are live samples: a cursor does not freeze or change Flow ownership. */
#define SAKAMOTO_FLOW_QUERY_PAGE 16U
#define SAKAMOTO_FLOW_QUERY_SCAN 256U
typedef struct {
  uint64_t incarnation, first_seen, last_seen;
  uint64_t packets[2], bytes[2];
  uint64_t policy_generation, policy_revision, policy_hash, winner, protocols;
  uint32_t worker, slot, uid, network, query_class;
  uint32_t sni_result, sni_stop, lpi_stop;
  uint16_t ports[2];
  uint8_t family, protocol, kind, origin_is_a;
  uint8_t flow_origin_direction, last_device_direction, last_flow_direction;
  uint8_t protocols_available;
  uint8_t addresses[32];
  product_observation_attribution_t attribution[2];
} sakamoto_product_flow_entry_t;

typedef struct {
  uint64_t generation;
  uint64_t allocated_bytes[2], capacity_misses[2];
  uint32_t capacity[2], active[2], high_watermark[2];
  uint32_t cursor, next_cursor, scanned, count, done;
  sakamoto_product_flow_entry_t entries[SAKAMOTO_FLOW_QUERY_PAGE];
} sakamoto_product_flow_page_t;

#ifdef __cplusplus
#define SAKAMOTO_FLOW_ASSERT static_assert
#else
#define SAKAMOTO_FLOW_ASSERT _Static_assert
#endif
SAKAMOTO_FLOW_ASSERT (sizeof (sakamoto_product_flow_entry_t) == 496,
                      "flow query entry ABI");
SAKAMOTO_FLOW_ASSERT (offsetof (sakamoto_product_flow_page_t, entries) == 88,
                      "flow query page ABI");
SAKAMOTO_FLOW_ASSERT (sizeof (sakamoto_product_flow_page_t) == 8024,
                      "flow query page size");
#undef SAKAMOTO_FLOW_ASSERT

#endif
