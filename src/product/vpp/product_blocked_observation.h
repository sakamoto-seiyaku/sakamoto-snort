/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_BLOCKED_OBSERVATION_H
#define SAKAMOTO_PRODUCT_BLOCKED_OBSERVATION_H

#include "product_packet.h"
#include "sakamoto_product_observation.h"

/* This owner-local state only sees an already decided PRE policy DROP. It
 * never looks up a FlowEntry or interprets CT, LPI or payload bytes. */
typedef struct product_blocked_observation product_blocked_observation_t;
typedef void (*product_blocked_emit_t) (void *, const product_observation_record_t *);

product_blocked_observation_t *product_blocked_observation_create (
  uint32_t capacity, uint64_t generation, uint16_t owner,
  product_blocked_emit_t emit, void *context);
void product_blocked_observation_destroy (product_blocked_observation_t *);
void product_blocked_observation_observe (
  product_blocked_observation_t *, const product_owner_assignment_t *,
  uint32_t uid, uint32_t network, uint8_t device_direction, uint32_t bytes,
  uint64_t mono_us, uint64_t utc_us,
  const product_observation_attribution_t *attribution);
uint64_t product_blocked_observation_deadline (const product_blocked_observation_t *);
void product_blocked_observation_flush_due (product_blocked_observation_t *,
                                             uint64_t now_us, uint32_t budget);
uint32_t product_blocked_observation_active (const product_blocked_observation_t *);
uint64_t product_blocked_observation_misses (const product_blocked_observation_t *);
uint64_t product_blocked_observation_retired (const product_blocked_observation_t *);
#endif
