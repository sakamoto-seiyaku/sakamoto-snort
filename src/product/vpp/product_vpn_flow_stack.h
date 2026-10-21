/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_FLOW_STACK_H
#define SAKAMOTO_PRODUCT_VPN_FLOW_STACK_H

#include "product_packet.h"
#include <stddef.h>
#include <stdint.h>

/* Independent packet storage. No VPP buffer index, FlowEntry, PCB or pbuf
 * crosses this interface. All operations after creation run on one owner. */
typedef struct product_vpn_flow_stack product_vpn_flow_stack_t;

typedef enum {
  PRODUCT_VPN_FLOW_STACK_ACCEPTED,
  PRODUCT_VPN_FLOW_STACK_NO_CAPACITY,
  PRODUCT_VPN_FLOW_STACK_UNSUPPORTED,
  PRODUCT_VPN_FLOW_STACK_NOT_RUNNING,
  PRODUCT_VPN_FLOW_STACK_INVALID_GENERATION,
  PRODUCT_VPN_FLOW_STACK_FAILED,
} product_vpn_flow_stack_input_result_t;

typedef struct {
  const uint8_t *data;
  size_t length;
} product_vpn_flow_stack_span_t;

typedef enum {
  PRODUCT_VPN_FLOW_STACK_OUTPUT_ACCEPTED,
  PRODUCT_VPN_FLOW_STACK_OUTPUT_NO_MEMORY,
  PRODUCT_VPN_FLOW_STACK_OUTPUT_REJECTED,
} product_vpn_flow_stack_output_result_t;

/* Spans and facts are borrowed only until callback return. ACCEPTED means
 * an independent copy was submitted, not that policy or TUN delivery passed.
 * The callback must schedule, not recursively execute, the shared graph. */
typedef product_vpn_flow_stack_output_result_t (*product_vpn_flow_stack_output_fn)(
  void *opaque, const product_vpn_flow_stack_span_t *spans, unsigned count,
  size_t total, const product_platform_packet_facts_t *platform,
  uint64_t generation, uint64_t serial, uint64_t underlay_epoch,
  uint64_t flow_incarnation);

typedef struct {
  uint32_t quanta, runnable;
  int timeout_ms;
  uint8_t stopped;
} product_vpn_flow_stack_step_result_t;

typedef enum {
  PRODUCT_VPN_FLOW_STACK_FAULT_NONE,
  PRODUCT_VPN_FLOW_STACK_FAULT_SESSION_CAPACITY,
  PRODUCT_VPN_FLOW_STACK_FAULT_PCB_CAPACITY,
  PRODUCT_VPN_FLOW_STACK_FAULT_SOCKET_CAPACITY,
  PRODUCT_VPN_FLOW_STACK_FAULT_PACKET_CREDIT,
  PRODUCT_VPN_FLOW_STACK_FAULT_PBUF_CAPACITY,
  PRODUCT_VPN_FLOW_STACK_FAULT_ALLOCATION,
  PRODUCT_VPN_FLOW_STACK_FAULT_SOCKET_CREATE,
  PRODUCT_VPN_FLOW_STACK_FAULT_BROKER_SUBMIT,
  PRODUCT_VPN_FLOW_STACK_FAULT_BROKER_TIMEOUT,
  PRODUCT_VPN_FLOW_STACK_FAULT_PROTECT,
  PRODUCT_VPN_FLOW_STACK_FAULT_BIND,
  PRODUCT_VPN_FLOW_STACK_FAULT_AUTHORIZATION,
  PRODUCT_VPN_FLOW_STACK_FAULT_CONNECT_REFUSED,
  PRODUCT_VPN_FLOW_STACK_FAULT_NETWORK_UNREACHABLE,
  PRODUCT_VPN_FLOW_STACK_FAULT_CONNECT,
  PRODUCT_VPN_FLOW_STACK_FAULT_SOCKET_IO,
  PRODUCT_VPN_FLOW_STACK_FAULT_OUTPUT_CAPACITY,
  PRODUCT_VPN_FLOW_STACK_FAULT_OUTPUT_REJECTED,
  PRODUCT_VPN_FLOW_STACK_FAULT_COUNT,
} product_vpn_flow_stack_fault_t;

typedef struct {
  uint64_t input_accepted, input_rejected, input_copy_calls, input_copy_bytes;
  uint64_t output_accepted, output_rejected;
  uint64_t sessions_created, sessions_closed, sockets_created, sockets_closed;
  uint64_t direct_sent, direct_received, broker_requested, broker_completed;
  uint64_t udp_send_calls, udp_send_requested, udp_send_datagrams;
  uint64_t udp_send_partial, udp_send_blocked, udp_send_max;
  uint64_t tcp_rx_rounds, tcp_read_calls, tcp_read_blocked;
  uint64_t tcp_commits, tcp_commit_bytes, tcp_write_blocked, tcp_output_calls;
  uint64_t tcp_commit_max;
  uint32_t sessions, input_packets, pbufs, pbuf_peak;
  uint32_t pcbs, pcb_peak, sockets, socket_peak, input_pbufs;
  uint64_t pcb_allocations, pcb_frees;
  uint64_t faults[PRODUCT_VPN_FLOW_STACK_FAULT_COUNT];
  uint64_t fault_count, first_fault_ms, last_fault_ms, last_fault_session;
  product_vpn_flow_stack_fault_t last_fault;
  int last_fault_error;
  uint8_t running, stopped;
} product_vpn_flow_stack_snapshot_t;

const char *product_vpn_flow_stack_fault_name(product_vpn_flow_stack_fault_t fault);

/* Copies the complete L3 input before returning. It does not wait for socket
 * authorization or run a transport task. Only reliable original-app identity
 * is retained; return network facts come from the actual socket binding. */
product_vpn_flow_stack_input_result_t product_vpn_flow_stack_input_copy(
  product_vpn_flow_stack_t *stack, const uint8_t *l3, size_t length,
  const product_platform_packet_facts_t *platform, uint64_t generation,
  uint64_t flow_incarnation);

/* Each turn consumes bounded real transport work, including while draining.
 * timeout_ms is a transport timer, not the FlowRuntime Conntrack deadline. */
product_vpn_flow_stack_step_result_t product_vpn_flow_stack_step(
  product_vpn_flow_stack_t *stack, uint32_t quanta, uint32_t max_us);
void product_vpn_flow_stack_quiesce(product_vpn_flow_stack_t *stack);
/* Caller first drains accepted graph output and obtains stopped from step. */
int product_vpn_flow_stack_close(product_vpn_flow_stack_t *stack);
int product_vpn_flow_stack_poll_fd(const product_vpn_flow_stack_t *stack);
product_vpn_flow_stack_snapshot_t product_vpn_flow_stack_snapshot(
  const product_vpn_flow_stack_t *stack);

#endif
