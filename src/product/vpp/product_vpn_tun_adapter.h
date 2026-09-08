/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_TUN_ADAPTER_H
#define SAKAMOTO_PRODUCT_VPN_TUN_ADAPTER_H
#include <vlib/vlib.h>
#include "product_packet_completion.h"

/* Controlled graph validation only; no VPN egress readiness is implied. */
int product_vpn_tun_validation_enabled (void);
int product_vpn_tun_start (vlib_main_t *vm, u64 generation);
u64 product_vpn_tun_attached (void);
u64 product_vpn_tun_captured (void);

/* Invoked by the shared completion node on this obligation's origin worker. */
void product_vpn_tun_complete_from_graph (vlib_main_t *vm, u32 buffer_index,
  const product_packet_completion_frame_t *completion);

#endif
