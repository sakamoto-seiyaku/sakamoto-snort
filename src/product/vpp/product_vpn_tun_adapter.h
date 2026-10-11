/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_TUN_ADAPTER_H
#define SAKAMOTO_PRODUCT_VPN_TUN_ADAPTER_H
#include <vlib/vlib.h>
#include "product_packet_completion.h"
#include "product_vpn_flow_stack.h"

enum {
  PRODUCT_VPN_TUN_CAPTURE_CAPACITY = 128,
  PRODUCT_VPN_RETURN_WORKERS = 2,
  PRODUCT_VPN_RETURN_CAPACITY = 128,
};

/* The native packet graph runs for either product VPN or controlled validation. */
int product_vpn_tun_enabled (void);
int product_vpn_tun_product_mode (void);
void product_vpn_tun_mode_init (void);
/* Product readiness requires the TUN, graph and both egress shards. */
int product_vpn_tun_product_ready (void);
int product_vpn_tun_start (vlib_main_t *vm, u64 generation);
u64 product_vpn_tun_attached (void);
u64 product_vpn_tun_captured (void);
/* Validation-only bounded delay; ownership stays in native completion storage. */
int product_vpn_tun_return_held(vlib_main_t *vm,
  const product_packet_completion_frame_t *completion);
product_vpn_flow_stack_output_result_t product_vpn_tun_submit_return(
  vlib_main_t *vm, const product_vpn_flow_stack_span_t *spans, unsigned count,
  size_t total, const product_platform_packet_facts_t *platform,
  uint64_t generation, uint64_t serial, uint64_t underlay_epoch,
  uint64_t flow_incarnation);
/* Exact full-width lineage lookup for an admitted Product VPN return. */
int product_vpn_tun_return_incarnation (u64 generation, u64 token,
  u64 *incarnation);

/* Invoked by the shared completion node on this obligation's origin worker. */
int product_vpn_tun_complete_from_graph (vlib_main_t *vm, u32 buffer_index,
  const product_packet_completion_frame_t *completion);
/* Only after a valid completion and native free; never for replay probes. */
void product_vpn_tun_return_freed(vlib_main_t *vm, u32 buffer_index,
  const product_packet_completion_frame_t *completion);

#endif
