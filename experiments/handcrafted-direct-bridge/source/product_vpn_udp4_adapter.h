/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_VPN_UDP4_ADAPTER_H
#define SAKAMOTO_PRODUCT_VPN_UDP4_ADAPTER_H

#include <stdint.h>

#include <vlib/vlib.h>

int product_vpn_udp4_adapter_start (vlib_main_t *vm, uint64_t generation);
void product_vpn_udp4_adapter_stop (vlib_main_t *vm);

int product_vpn_udp4_adapter_available (void);
int product_vpn_udp4_adapter_protection_running (void);

uint64_t product_vpn_udp4_adapter_tun_fd_attached (void);
uint64_t product_vpn_udp4_adapter_direct_socket_attached (void);
uint64_t product_vpn_udp4_adapter_direct_protect_succeeded (void);
uint64_t product_vpn_udp4_adapter_direct_bind_succeeded (void);
uint64_t product_vpn_udp4_adapter_tun_ingress_packets (void);
uint64_t product_vpn_udp4_adapter_udp4_tun_origin_packets (void);
uint64_t product_vpn_udp4_adapter_flow_stack_admissions (void);
uint64_t product_vpn_udp4_adapter_direct_send_succeeded (void);
uint64_t product_vpn_udp4_adapter_direct_transport_failed (void);
uint64_t product_vpn_udp4_adapter_flow_stack_return_packets (void);
uint64_t product_vpn_udp4_adapter_flow_stack_return_provenance_packets (void);
uint64_t product_vpn_udp4_adapter_tun_write_completions (void);
uint64_t product_vpn_udp4_adapter_infrastructure_faults (void);
uint64_t product_vpn_udp4_adapter_duplicate_or_stale_drops (void);

#endif
