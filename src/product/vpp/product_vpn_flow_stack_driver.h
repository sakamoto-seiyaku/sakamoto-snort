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
  uint64_t flow_incarnation, uint64_t request_token);

/* Complete-message local UDP path, selected before HEV Direct creation. */
product_vpn_flow_stack_input_result_t product_vpn_flow_stack_driver_local_udp(
  vlib_main_t *, const uint8_t *, size_t, const product_platform_packet_facts_t *,
  uint64_t generation, uint64_t incarnation, uint64_t *session,
  uint8_t *message, size_t capacity, size_t *length);
int product_vpn_flow_stack_driver_local_reply_context(vlib_main_t *, uint64_t generation,
  uint64_t session, const uint8_t *, size_t, const product_vpn_flow_stack_transport_t *);
product_vpn_flow_stack_input_result_t product_vpn_flow_stack_driver_local_tcp(vlib_main_t *,
  const uint8_t *, size_t, const product_platform_packet_facts_t *, uint64_t generation,
  uint64_t incarnation, uint64_t *session);
void product_vpn_flow_stack_driver_tcp_drain(vlib_main_t *);
/* Last owner-published bounded snapshot, read under the control-plane barrier. */
product_vpn_flow_stack_snapshot_t product_vpn_flow_stack_driver_tcp_status(unsigned owner);
int product_vpn_flow_stack_driver_tcp_reply(vlib_main_t *, uint64_t generation, uint64_t session,
  uint64_t token, const uint8_t *, size_t, const product_vpn_flow_stack_transport_t *);
int product_vpn_flow_stack_driver_tcp_abandon(vlib_main_t *, uint64_t generation,
  uint64_t session, uint64_t token);
uint64_t product_vpn_flow_stack_driver_dns_reservation(unsigned owner);
int product_vpn_flow_stack_driver_dns_authorize(vlib_main_t *, uint64_t generation,
  uint64_t cookie, int fd);
#endif
