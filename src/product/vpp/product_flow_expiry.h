/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FLOW_EXPIRY_H
#define SAKAMOTO_PRODUCT_FLOW_EXPIRY_H
#include <vlib/vlib.h>
#include "product_flow_entry.h"

/* Bind fresh, empty owner runtimes before admission. S226 selected the
 * owner-local one-shot deadline driver; startup failure leaves no live FD.
 * The old comparison is available only with an explicit experiment startup. */
int product_flow_expiry_bind (uint64_t generation, product_flow_runtime_t **runtimes);
void product_flow_expiry_quiesce (void); /* lifecycle worker barrier held */
void product_flow_expiry_changed (vlib_main_t *vm); /* owner END cleanup */
void product_flow_expiry_observed (vlib_main_t *vm,
  const product_flow_entry_observation_t *observation, uint64_t now_us);
void product_flow_expiry_released (vlib_main_t *vm,
  const product_flow_entry_t *entry, uint32_t slot);
#endif
