/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_FLOW_STACK_DRIVER_H
#define SAKAMOTO_PRODUCT_VPN_FLOW_STACK_DRIVER_H
#include "product_vpn_flow_stack.h"
#include <vlib/vlib.h>

/* Native lifecycle wiring. Start/attach/stop request are control operations
 * under the VPP worker barrier. Mutable stack operations execute only on the
 * selected worker, including close. Every frozen graph owner has an independent
 * shard and socket-authorization channel. */
int product_vpn_flow_stack_driver_start(vlib_main_t *vm, uint64_t generation);
int product_vpn_flow_stack_driver_attach(int fd, uint32_t owner); /* consumes fd */
void product_vpn_flow_stack_driver_quiesce(void);
int product_vpn_flow_stack_driver_stopped(void);
int product_vpn_flow_stack_driver_enabled(void);
int product_vpn_flow_stack_driver_ready(void);
/* Validation-only one-shot capacity rejection, configured under CLI barrier. */
int product_vpn_flow_stack_driver_reject_after(uint32_t owner, uint32_t packets);
product_vpn_flow_stack_input_result_t product_vpn_flow_stack_driver_input(
  vlib_main_t *vm, vlib_node_runtime_t *node, const uint8_t *l3, size_t length,
  const product_platform_packet_facts_t *platform, uint64_t generation,
  uint64_t flow_incarnation);

#endif
