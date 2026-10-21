/* SPDX-License-Identifier: MIT */
#ifndef SAKAMOTO_LWIPOPTS_H
#define SAKAMOTO_LWIPOPTS_H

/* Dual-stack transport profile. VPP owns shared validation/reassembly/policy;
 * lwIP owns TCP/UDP transport and its own protocol-required buffering. */
#include <stddef.h>
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TIMERS 0
#define LWIP_TCP 1
#define LWIP_TCP_PCB_NUM_EXT_ARGS 1
#ifdef SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT
#define TCP_MSS (SAKAMOTO_PRODUCT_VPN_TUN_MTU - 60)
#else
#define TCP_MSS 1360
#endif
#define TCP_WND 32768
#ifdef SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT
#define TCP_SND_BUF 65528
#else
#define TCP_SND_BUF 32768
#endif
#define TCP_OVERSIZE 0
/* Exhaustion rejects the current allocation, not another flow's queued data. */
#define PBUF_POOL_FREE_OOSEQ 0
#define LWIP_HOOK_FILENAME "hev-lwip-hooks.h"
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_IPV6_AUTOCONFIG 0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0
#define LWIP_IPV6_MLD 0
#define LWIP_IPV6_REASS 0
#define LWIP_IPV6_FRAG 0
#define LWIP_ICMP6 1
#define LWIP_IPV6_DUP_DETECT_ATTEMPTS 0
#define LWIP_IPV6_ADDRESS_LIFETIMES 0
#define LWIP_UDP 1
#define LWIP_UDPLITE 0
#define LWIP_RAW 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_ICMP 0
#define LWIP_IGMP 0
#define LWIP_DNS 0
#define LWIP_DHCP 0
#define LWIP_AUTOIP 0
#define IP_FORWARD 0
#define IP_REASSEMBLY 0
#define IP_FRAG 0
#define LWIP_HAVE_LOOPIF 0
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_STATS 0
#define SO_REUSE 0
#define MEM_ALIGNMENT 8U
#define MEM_CUSTOM_ALLOCATOR 1
#define MEMP_MEM_MALLOC 1
#define MEM_CUSTOM_MALLOC hev_lwip_malloc
#define MEM_CUSTOM_CALLOC hev_lwip_calloc
#define MEM_CUSTOM_FREE hev_lwip_free
void *hev_lwip_malloc(size_t size);
void *hev_lwip_calloc(size_t count, size_t size);
void hev_lwip_free(void *memory);
#define PBUF_POOL_BUFSIZE 2048
#define LWIP_SUPPORT_CUSTOM_PBUF 0
#define PBUF_LINK_HLEN 0
#define CHECKSUM_CHECK_IP 1
#define CHECKSUM_CHECK_UDP 1
#define LWIP_CHECKSUM_ON_COPY 1
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

#endif
