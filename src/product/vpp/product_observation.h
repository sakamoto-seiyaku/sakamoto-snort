/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_OBSERVATION_VPP_H
#define SAKAMOTO_PRODUCT_OBSERVATION_VPP_H
#include "product_flow_entry.h"
#include "sakamoto_product_observation.h"
#include <vlib/vlib.h>
int product_observation_bind (uint64_t, product_flow_runtime_t **);
void product_observation_unbind (void);
void product_observation_quiesce (void);
void product_observation_observed (vlib_main_t *, const product_flow_entry_t *, uint32_t);
void product_observation_end (vlib_main_t *, const product_flow_entry_t *, uint32_t);
uint64_t product_observation_deadline (unsigned owner);
void product_observation_flush_due (vlib_main_t *, uint64_t);
void product_observation_basic (vlib_main_t *, unsigned outcome, uint32_t bytes);
void product_observation_status (product_observation_status_t *);
#endif
