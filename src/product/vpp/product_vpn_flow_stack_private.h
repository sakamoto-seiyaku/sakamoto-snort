/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_FLOW_STACK_PRIVATE_H
#define SAKAMOTO_PRODUCT_VPN_FLOW_STACK_PRIVATE_H

#include "product_vpn_flow_stack.h"

/* Lifecycle/socket broker wiring only; ordinary packet callers do not see
 * socket descriptors. Submission borrows the original fd; SCM_RIGHTS creates
 * a broker-owned duplicate. Completion arrives later on this same owner. */
typedef int (*product_vpn_flow_stack_broker_fn)(void *opaque,
  uint64_t generation, uint64_t session, int original_fd);
typedef void (*product_vpn_flow_stack_trace_fn)(void *opaque, const char *event,
  uint64_t serial, uint64_t session, uintptr_t object, size_t bytes,
  int result, unsigned kind);

typedef struct {
  uint64_t generation;
  uint32_t owner_index, max_sessions, max_pcbs, max_sockets, max_input_packets, max_pbufs;
  uint32_t max_packet_bytes, task_stack_bytes, broker_timeout_ms, idle_timeout_ms;
  product_vpn_flow_stack_output_fn output;
  product_vpn_flow_stack_broker_fn broker;
  product_vpn_flow_stack_trace_fn trace;
  void *opaque;
} product_vpn_flow_stack_config_t;

product_vpn_flow_stack_t *product_vpn_flow_stack_create(
  const product_vpn_flow_stack_config_t *config);
int product_vpn_flow_stack_broker_complete(product_vpn_flow_stack_t *stack,
  uint64_t generation, uint64_t session, unsigned error, uint64_t underlay_epoch,
  uint32_t network_context, int context_known);
int product_vpn_flow_stack_invalidate_underlay(product_vpn_flow_stack_t *stack,
  uint64_t generation, uint64_t epoch);

#endif
