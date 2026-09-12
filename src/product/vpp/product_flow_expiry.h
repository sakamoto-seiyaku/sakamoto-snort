/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_FLOW_EXPIRY_H
#define SAKAMOTO_PRODUCT_FLOW_EXPIRY_H
#include <vlib/vlib.h>
#include "product_flow_entry.h"

/* S226's default-off comparison driver. Binding does not allocate a timerfd,
 * enable a node, attach a timer, or choose a production wake strategy. */
void product_flow_expiry_bind (uint64_t generation, product_flow_runtime_t **runtimes);
void product_flow_expiry_quiesce (void); /* lifecycle worker barrier held */
void product_flow_expiry_observed (vlib_main_t *vm,
  const product_flow_entry_observation_t *observation, uint64_t now_us);
void product_flow_expiry_released (vlib_main_t *vm,
  const product_flow_entry_t *entry, uint32_t slot);
#endif
