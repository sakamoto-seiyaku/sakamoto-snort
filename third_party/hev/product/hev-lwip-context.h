/* SPDX-License-Identifier: MIT */
#ifndef SAKAMOTO_HEV_LWIP_CONTEXT_H
#define SAKAMOTO_HEV_LWIP_CONTEXT_H

#include "lwip/ip.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "lwip/priv/nd6_priv.h"
#include "lwip/prot/nd6.h"
#include "lwip/priv/tcp_priv.h"
#include <stdint.h>

enum { HEV_LWIP_PBUF_POOL, HEV_LWIP_PBUF_RAM, HEV_LWIP_PBUF_REF,
       HEV_LWIP_PBUF_KINDS };
enum { HEV_LWIP_RESOURCE_PCB, HEV_LWIP_RESOURCE_PBUF,
       HEV_LWIP_RESOURCE_ALLOCATION, HEV_LWIP_RESOURCE_PCB_ALLOCATION };

/* Storage belongs to the explicit HEV owner, never to a process singleton.
 * TLS contains only the current pointer while that owner is executing. */
typedef struct {
  struct ip_globals ip;
  struct netif *interfaces;
  struct netif *default_interface;
  struct udp_pcb *udp;
  u16_t next_udp_port;
  u16_t next_ip_id;
  u8_t next_interface;
  char address_text[40];
#if LWIP_TCP
  struct tcp_pcb *tcp_bound, *tcp_active, *tcp_timewait, *tcp_in_pcb;
  union tcp_listen_pcbs_t tcp_listeners;
  struct tcp_pcb **tcp_lists[NUM_TCP_PCB_LISTS];
  u32_t tcp_clock, tcp_iss;
  u16_t tcp_next_port;
  u8_t tcp_changed, tcp_timer_phase, tcp_timer_count, tcp_ext_id;
  struct tcp_seg tcp_in_segment;
  struct tcp_hdr *tcp_in_header;
  u16_t tcp_in_option_length, tcp_in_option_first, tcp_in_option_index;
  u8_t *tcp_in_option_second;
  u32_t tcp_in_sequence, tcp_in_acknowledgment;
  tcpwnd_size_t tcp_in_acked;
  u16_t tcp_in_length;
  u8_t tcp_in_flags, tcp_in_received_flags;
  struct pbuf *tcp_in_data;
  /* Borrowed PCB only while its synchronous IP output callback executes.
   * This identifies the transport, including timer-generated output; it is
   * neither a packet map nor a retained VPP/FlowEntry pointer. */
  const struct tcp_pcb *tcp_output_pcb;
  err_t (*tcp_input_guard)(void *opaque, struct tcp_pcb *pcb);
  void *tcp_opaque;
#endif
#if LWIP_IPV6
  struct nd6_neighbor_cache_entry neighbors[LWIP_ND6_NUM_NEIGHBORS];
  struct nd6_destination_cache_entry destinations[LWIP_ND6_NUM_DESTINATIONS];
  struct nd6_prefix_list_entry prefixes[LWIP_ND6_NUM_PREFIXES];
  struct nd6_router_list_entry routers[LWIP_ND6_NUM_ROUTERS];
  u32_t nd6_reachable, nd6_retransmit;
  u8_t nd6_queued, nd6_rs_reduction;
  netif_addr_idx_t nd6_cached_destination;
  s8_t nd6_last_router;
  ip6_addr_t nd6_multicast;
  union {
    struct lladdr_option lladdr;
    struct mtu_option mtu;
    struct prefix_option prefix;
#if LWIP_ND6_RDNSS_MAX_DNS_SERVERS
    struct rdnss_option rdnss;
#endif
  } nd6_ra;
#endif
  uint32_t max_pbufs, pbufs, pbuf_peak;
  uint32_t max_pcbs, pcbs, pcb_peak;
  uint64_t pcb_allocations, pcb_frees;
  void (*resource_failure)(void *opaque, unsigned resource);
  void *resource_opaque;
  uint32_t pbuf_live[HEV_LWIP_PBUF_KINDS];
  uint64_t pbuf_allocations[HEV_LWIP_PBUF_KINDS];
  uint64_t pbuf_frees[HEV_LWIP_PBUF_KINDS];
  void (*pbuf_event)(void *opaque, void *object, unsigned kind, int allocated);
  void *pbuf_opaque;
  size_t heap_live, heap_bytes, heap_peak_bytes;
  uint64_t heap_allocations, heap_frees;
} hev_lwip_context_t;

void hev_lwip_context_init(hev_lwip_context_t *context);
hev_lwip_context_t *hev_lwip_context_bind(hev_lwip_context_t *context);
hev_lwip_context_t *hev_lwip_context_current(void);
u16_t *hev_lwip_udp_port(void);
u16_t *hev_lwip_ip_id(void);
u8_t *hev_lwip_netif_num(void);
char *hev_lwip_address_text(void);
void *hev_lwip_pbuf_allocate(unsigned kind, size_t size);
void hev_lwip_pbuf_deallocate(void *object, unsigned kind);
/* Called only by the pinned memp allocator for TCP/UDP/listener PCBs. No
 * independent allocation map, shared quota or allocation-driven eviction. */
int hev_lwip_pcb_admit(unsigned type);
void hev_lwip_pcb_allocated(unsigned type, void *object);
void hev_lwip_pcb_freed(unsigned type, void *object);
#if LWIP_TCP
err_t hev_lwip_tcp_input_guard(struct tcp_pcb *pcb);
#endif

#endif
