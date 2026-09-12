/* SPDX-License-Identifier: MIT */
#include "hev-lwip-context.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

static _Thread_local hev_lwip_context_t *current;

hev_lwip_context_t *hev_lwip_context_current(void)
{ return current; }

void
hev_lwip_context_init(hev_lwip_context_t *context)
{
  memset(context, 0, sizeof(*context));
  context->next_udp_port = 0xc000;
  context->max_pbufs = UINT32_MAX;
  context->max_pcbs = UINT32_MAX;
#if LWIP_TCP
  context->tcp_next_port = 0xc000;
  context->tcp_iss = 6510;
  context->tcp_lists[0] = &context->tcp_listeners.pcbs;
  context->tcp_lists[1] = &context->tcp_bound;
  context->tcp_lists[2] = &context->tcp_active;
  context->tcp_lists[3] = &context->tcp_timewait;
#endif
#if LWIP_IPV6
  context->nd6_reachable = LWIP_ND6_REACHABLE_TIME;
  context->nd6_retransmit = LWIP_ND6_RETRANS_TIMER;
#endif
}

hev_lwip_context_t *
hev_lwip_context_bind(hev_lwip_context_t *context)
{
  hev_lwip_context_t *previous = current;
  current = context;
  return previous;
}

struct ip_globals *hev_lwip_ip_data(void)
{ assert(current); return &current->ip; }
struct netif **hev_lwip_netif_list(void)
{ assert(current); return &current->interfaces; }
struct netif **hev_lwip_netif_default(void)
{ assert(current); return &current->default_interface; }
struct udp_pcb **hev_lwip_udp_pcbs(void)
{ assert(current); return &current->udp; }
u16_t *hev_lwip_udp_port(void)
{ assert(current); return &current->next_udp_port; }
u16_t *hev_lwip_ip_id(void)
{ assert(current); return &current->next_ip_id; }
u8_t *hev_lwip_netif_num(void)
{ assert(current); return &current->next_interface; }
char *hev_lwip_address_text(void)
{ assert(current); return current->address_text; }

#if LWIP_TCP
struct tcp_pcb **hev_lwip_tcp_input_pcb(void)
{ assert(current); return &current->tcp_in_pcb; }
u32_t *hev_lwip_tcp_ticks(void)
{ assert(current); return &current->tcp_clock; }
u8_t *hev_lwip_tcp_changed(void)
{ assert(current); return &current->tcp_changed; }
struct tcp_pcb **hev_lwip_tcp_bound(void)
{ assert(current); return &current->tcp_bound; }
union tcp_listen_pcbs_t *hev_lwip_tcp_listen(void)
{ assert(current); return &current->tcp_listeners; }
struct tcp_pcb **hev_lwip_tcp_active(void)
{ assert(current); return &current->tcp_active; }
struct tcp_pcb **hev_lwip_tcp_timewait(void)
{ assert(current); return &current->tcp_timewait; }
struct tcp_pcb **const *hev_lwip_tcp_lists(void)
{ assert(current); return current->tcp_lists; }
void tcp_timer_needed(void)
{
  /* NO_SYS external-driver profile: the owner derives its next bounded
   * tcp_tmr turn from its active/TIME_WAIT lists, without sys_timeout state. */
  assert(current);
}
err_t hev_lwip_tcp_input_guard(struct tcp_pcb *pcb)
{
  assert(current);
  return current->tcp_input_guard ?
    current->tcp_input_guard(current->tcp_opaque, pcb) : ERR_OK;
}
#endif

void *hev_lwip_pbuf_allocate(unsigned kind, size_t size)
{
  void *object;
  assert(current && kind < HEV_LWIP_PBUF_KINDS);
  if (current->pbufs >= current->max_pbufs) {
    if (current->resource_failure)
      current->resource_failure(current->resource_opaque, HEV_LWIP_RESOURCE_PBUF);
    return NULL;
  }
  if (kind == HEV_LWIP_PBUF_RAM)
    object = mem_malloc(size);
  else
    object = memp_malloc(kind == HEV_LWIP_PBUF_POOL ? MEMP_PBUF_POOL : MEMP_PBUF);
  if (!object) {
    if (current->resource_failure)
      current->resource_failure(current->resource_opaque, HEV_LWIP_RESOURCE_ALLOCATION);
    return NULL;
  }
  ++current->pbuf_allocations[kind];
  ++current->pbuf_live[kind];
  if (++current->pbufs > current->pbuf_peak)
    current->pbuf_peak = current->pbufs;
  if (current->pbuf_event)
    current->pbuf_event(current->pbuf_opaque, object, kind, 1);
  return object;
}

void hev_lwip_pbuf_deallocate(void *object, unsigned kind)
{
  assert(current && object && kind < HEV_LWIP_PBUF_KINDS);
  assert(current->pbufs && current->pbuf_live[kind]);
  ++current->pbuf_frees[kind];
  --current->pbuf_live[kind];
  --current->pbufs;
  if (current->pbuf_event)
    current->pbuf_event(current->pbuf_opaque, object, kind, 0);
  if (kind == HEV_LWIP_PBUF_RAM)
    mem_free(object);
  else
    memp_free(kind == HEV_LWIP_PBUF_POOL ? MEMP_PBUF_POOL : MEMP_PBUF, object);
}

static int is_pcb(unsigned type)
{
  return type == MEMP_UDP_PCB || type == MEMP_TCP_PCB || type == MEMP_TCP_PCB_LISTEN;
}

int hev_lwip_pcb_admit(unsigned type)
{
  if (!is_pcb(type)) return 1;
  if (!current) abort();
  if (current->pcbs < current->max_pcbs) return 1;
  if (current->resource_failure)
    current->resource_failure(current->resource_opaque, HEV_LWIP_RESOURCE_PCB);
  return 0;
}

void hev_lwip_pcb_allocated(unsigned type, void *object)
{
  if (!is_pcb(type)) return;
  if (!current) abort();
  if (!object) {
    if (current->resource_failure)
      current->resource_failure(current->resource_opaque, HEV_LWIP_RESOURCE_PCB_ALLOCATION);
    return;
  }
  if (current->pcbs >= current->max_pcbs) abort();
  ++current->pcb_allocations;
  if (++current->pcbs > current->pcb_peak) current->pcb_peak = current->pcbs;
}

void hev_lwip_pcb_freed(unsigned type, void *object)
{
  if (!is_pcb(type) || !object) return;
  if (!current || !current->pcbs) abort();
  --current->pcbs;
  ++current->pcb_frees;
}
