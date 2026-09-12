/* SPDX-License-Identifier: MIT */
#include "hev-lwip-context.h"
#include "lwip/init.h"
#include "lwip/inet_chksum.h"
#include "lwip/nd6.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Host-only allocator and creation callback; this proves the real lwIP seam,
 * not Android protection, HEV transport or product readiness. */
static unsigned allocations;
void *hev_lwip_malloc(size_t size)
{ void *p = malloc(size); if (p) ++allocations; return p; }
void *hev_lwip_calloc(size_t count, size_t size)
{ void *p = calloc(count, size); if (p) ++allocations; return p; }
void hev_lwip_free(void *p)
{ if (p) { assert(allocations); --allocations; free(p); } }
unsigned int lwip_port_rand(void) { return 1234; }

struct fixture {
  hev_lwip_context_t context;
  struct netif interface;
  struct udp_pcb *sessions[4];
  unsigned created, received, rejected;
  int reject;
};

static void receive_packet(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                           const ip_addr_t *address, u16_t port)
{
  struct fixture *f = arg;
  (void)address;
  assert(port == 12345 && pcb->remote_port == port);
  assert(p->tot_len == 1 && *(unsigned char *)p->payload == 42);
  ++f->received;
  pbuf_free(p);
}

static void create_session(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                           const ip_addr_t *address, u16_t port)
{
  struct fixture *f = arg;
  (void)p; /* creation borrows; udp_input delivers or frees the packet */
  assert(ip_addr_cmp(&pcb->local_ip, address) && pcb->local_port == port);
  if (f->reject) { ++f->rejected; udp_remove(pcb); return; }
  assert(f->created < 4);
  f->sessions[f->created++] = pcb;
  udp_recv(pcb, receive_packet, f);
}

static err_t interface_init(struct netif *interface)
{
  interface->name[0] = 'h'; interface->name[1] = 'v';
  interface->mtu = 1500;
  interface->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP | NETIF_FLAG_PRETEND;
  return ERR_OK;
}

static void setup(struct fixture *f)
{
  ip4_addr_t address, mask, gateway;
  struct udp_pcb *listener;
  memset(f, 0, sizeof(*f));
  hev_lwip_context_init(&f->context);
  hev_lwip_context_bind(&f->context);
  lwip_init();
  IP4_ADDR(&address, 10, 0, 0, 1);
  IP4_ADDR(&mask, 255, 255, 255, 0);
  IP4_ADDR(&gateway, 0, 0, 0, 0);
  assert(netif_add(&f->interface, &address, &mask, &gateway, f,
                   interface_init, ip4_input));
  netif_set_default(&f->interface);
  listener = udp_new(); assert(listener);
  listener->pretend_netif_idx = netif_get_index(&f->interface);
  assert(udp_bind(listener, IP_ANY_TYPE, 0) == ERR_OK);
  udp_recv(listener, create_session, f);
}

static void inject(unsigned destination, unsigned port)
{
  unsigned char packet[29] = {
    0x45, 0, 0, 29, 0, 1, 0, 0, 64, 17, 0, 0,
    10, 0, 0, 2, 192, 0, 2, 1,
    0x30, 0x39, 0, 0, 0, 9, 0, 0, 42
  };
  u16_t checksum;
  struct pbuf *p;
  packet[19] = (unsigned char)destination;
  packet[22] = (unsigned char)(port >> 8);
  packet[23] = (unsigned char)port;
  checksum = inet_chksum(packet, 20);
  memcpy(packet + 10, &checksum, 2);
  p = pbuf_alloc(PBUF_RAW, sizeof(packet), PBUF_POOL); assert(p);
  assert(pbuf_take(p, packet, sizeof(packet)) == ERR_OK);
  assert(ip4_input(p, netif_default) == ERR_OK);
}

static void cleanup(struct fixture *f)
{
  hev_lwip_context_bind(&f->context);
  while (udp_pcbs) udp_remove(udp_pcbs);
  netif_remove(&f->interface);
  assert(!udp_pcbs && !netif_list && !netif_default);
  assert(!f->context.pbufs);
  for (unsigned i = 0; i < HEV_LWIP_PBUF_KINDS; ++i) {
    assert(!f->context.pbuf_live[i]);
    assert(f->context.pbuf_allocations[i] == f->context.pbuf_frees[i]);
  }
}

static void check_pbuf_budget(struct fixture *f)
{
  unsigned baseline = allocations;
  f->context.max_pbufs = 2;
  /* Natural pool chain exceeds the owner cap; its partial chain unwinds. */
  assert(!pbuf_alloc(PBUF_RAW, 5000, PBUF_POOL));
  assert(!f->context.pbufs && allocations == baseline);
  assert(f->context.pbuf_peak == 2);
  struct pbuf *pool = pbuf_alloc(PBUF_RAW, 1, PBUF_POOL);
  struct pbuf *ram = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM);
  assert(pool && ram && f->context.pbufs == 2);
  assert(f->context.pbuf_live[HEV_LWIP_PBUF_POOL] == 1);
  assert(f->context.pbuf_live[HEV_LWIP_PBUF_RAM] == 1);
  assert(!pbuf_alloc_reference(NULL, 0, PBUF_REF));
  pbuf_ref(pool);
  assert(pbuf_free(pool) == 0 && f->context.pbufs == 2);
  assert(pbuf_free(pool) == 1 && f->context.pbufs == 1);
  struct pbuf *ref = pbuf_alloc_reference(NULL, 0, PBUF_REF);
  assert(ref && f->context.pbuf_live[HEV_LWIP_PBUF_REF] == 1);
  pbuf_free(ref); pbuf_free(ram);
  assert(!f->context.pbufs && allocations == baseline);
  f->context.max_pbufs = UINT32_MAX;
}

int main(void)
{
  struct fixture a, b;
  unsigned before;
  const char *a_text;
  setup(&a);
  check_pbuf_budget(&a);
  a_text = ip4addr_ntoa(netif_ip4_addr(&a.interface));
  assert(!strcmp(a_text, "10.0.0.1"));
  inject(1, 9000); inject(1, 9001); inject(2, 9000); inject(1, 9000);
  assert(a.created == 3 && a.received == 4);
  assert(a.sessions[0] != a.sessions[1] && a.sessions[0] != a.sessions[2]);
  setup(&b);
  assert(ip4addr_ntoa(netif_ip4_addr(&b.interface)) != a_text);
  assert(!strcmp(a_text, "10.0.0.1"));
  assert(b.interface.num == 0 && a.interface.num == 0);
  inject(1, 9000);
  assert(b.created == 1 && b.received == 1);
  assert(b.sessions[0] != a.sessions[0]);
  before = allocations;
  b.reject = 1;
  inject(3, 9000);
  assert(b.rejected == 1 && allocations == before);
  b.reject = 0;
  inject(3, 9000);
  assert(b.created == 2 && b.received == 2);
  hev_lwip_context_bind(&a.context);
  assert(netif_default == &a.interface);
  inject(1, 9000);
  assert(a.created == 3 && a.received == 5);
  ip6_addr_t address6;
  assert(ip6addr_aton("fd00::1", &address6));
  a.context.destinations[0].destination_addr = address6;
  b.context.destinations[0].destination_addr = address6;
  hev_lwip_context_bind(&a.context);
  const char *a6_text = ip6addr_ntoa(&address6);
  char a6_saved[40];
  strcpy(a6_saved, a6_text);
  nd6_clear_destination_cache();
  assert(ip6_addr_isany(&a.context.destinations[0].destination_addr));
  assert(!ip6_addr_isany(&b.context.destinations[0].destination_addr));
  hev_lwip_context_bind(&b.context);
  assert(ip6addr_aton("fd00::2", &address6));
  assert(ip6addr_ntoa(&address6) != a6_text);
  assert(!strcmp(a6_text, a6_saved));
  cleanup(&a);
  assert(!ip6_addr_isany(&b.context.destinations[0].destination_addr));
  cleanup(&b);
  hev_lwip_context_bind(NULL);
  assert(allocations == 0);
  return 0;
}
