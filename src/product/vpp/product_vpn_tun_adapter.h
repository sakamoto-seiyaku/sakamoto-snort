/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_VPN_TUN_ADAPTER_H
#define SAKAMOTO_PRODUCT_VPN_TUN_ADAPTER_H
#include <vlib/vlib.h>

/* Controlled graph validation only; no VPN egress readiness is implied. */
int product_vpn_tun_validation_enabled (void);
int product_vpn_tun_start (vlib_main_t *vm, u64 generation);
u64 product_vpn_tun_attached (void);
u64 product_vpn_tun_captured (void);

#endif
