/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "hev-lwip-context.h"
#include "hev-socks5-session-udp.h"
#include <hev-task-mutex.h>
#include <hev-task-system.h>
#include <lwip/init.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Real Direct session/fd/recvmsg/lwIP. Distinct loopback addresses model the
 * selected underlay and virtual TUN destinations without creating interfaces.
 * Owner/broker/packet-policy integration is covered by the owner and Device
 * cases; this is the exact receive boundary that must reject its own return. */
static unsigned allocations, outputs;
void *hev_lwip_malloc(size_t bytes){void *p=malloc(bytes);if(p)++allocations;return p;}
void *hev_lwip_calloc(size_t count,size_t bytes){void *p=calloc(count,bytes);if(p)++allocations;return p;}
void hev_lwip_free(void *p){if(p){assert(allocations);--allocations;free(p);}}
unsigned int lwip_port_rand(void){return 1234;}
static err_t output(struct netif *netif,struct pbuf *p,const ip4_addr_t *destination)
{
  (void)netif;assert(ip4_addr4(destination)==2&&p->tot_len==29);uint8_t wire[29];
  assert(pbuf_copy_partial(p,wire,sizeof(wire),0)==sizeof(wire));
  assert(wire[28]==43&&wire[9]==17&&wire[12]==127&&wire[15]==3);
  assert(wire[20]==(5353>>8)&&wire[21]==(5353&255)&&wire[22]==(5353>>8)&&wire[23]==(5353&255));
  ++outputs;return ERR_OK;
}
static err_t initialize(struct netif *netif)
{netif->name[0]='h';netif->name[1]='v';netif->mtu=1500;netif->flags=NETIF_FLAG_UP|NETIF_FLAG_LINK_UP|NETIF_FLAG_PRETEND;netif->output=output;return ERR_OK;}
static void run(void *unused)
{
  (void)unused;hev_lwip_context_t context;hev_lwip_context_init(&context);hev_lwip_context_bind(&context);lwip_init();
  struct netif netif={0};ip4_addr_t ip,mask,gateway;
  IP4_ADDR(&ip,10,0,0,1);IP4_ADDR(&mask,255,255,255,0);IP4_ADDR(&gateway,0,0,0,0);
  assert(netif_add(&netif,&ip,&mask,&gateway,NULL,initialize,ip4_input));netif_set_default(&netif);
  struct udp_pcb *pcb=udp_new();assert(pcb);IP_ADDR4(&pcb->local_ip,224,0,0,251);IP_ADDR4(&pcb->remote_ip,10,0,0,2);
  pcb->local_port=pcb->remote_port=5353;pcb->netif_idx=netif_get_index(&netif);
  HevTaskMutex mutex;assert(!hev_task_mutex_init(&mutex));
  HevSocks5SessionUDP *session=hev_socks5_session_udp_direct_new(pcb,&mutex,1);assert(session);
  hev_socks5_session_set_task(HEV_SOCKS5_SESSION(session),hev_task_self());
  session->base.fd=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(session->base.fd>=0);
  struct in_addr selected={.s_addr=htonl(INADDR_LOOPBACK)};
  assert(!setsockopt(session->base.fd,IPPROTO_IP,IP_MULTICAST_IF,&selected,sizeof(selected)));
  struct sockaddr_in group={.sin_family=AF_INET,.sin_port=htons(5353),.sin_addr.s_addr=htonl(0xe00000fb)};
  assert(!hev_socks5_session_udp_direct_mdns(session,(void *)&group,sizeof(group)));
  int peer=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(peer>=0);int reuse=1;
  assert(!setsockopt(peer,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)));
  struct sockaddr_in from={.sin_family=AF_INET,.sin_port=htons(5353),.sin_addr.s_addr=htonl(0x7f000003)};
  assert(!bind(peer,(void *)&from,sizeof(from)));uint8_t value=43,scratch[16];int result;
  struct sockaddr_in destination={.sin_family=AF_INET,.sin_port=htons(5353),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
  assert(sendto(peer,&value,1,0,(void *)&destination,sizeof(destination))==1);
  struct pollfd ready={.fd=session->base.fd,.events=POLLIN};assert(poll(&ready,1,1000)==1);
  assert(hev_socks5_session_udp_direct_receive(session,scratch,sizeof(scratch),&result)==1&&result==ERR_OK&&outputs==1);
  unsigned baseline=allocations;
  /* This is the same valid responder's exact payload, now arriving at the
   * virtual destination used by this session's own materialized return. */
  destination.sin_addr.s_addr=htonl(0x7f000002);
  assert(sendto(peer,&value,1,0,(void *)&destination,sizeof(destination))==1);
  assert(poll(&ready,1,1000)==1);
  assert(hev_socks5_session_udp_direct_receive(session,scratch,sizeof(scratch),&result)==1);
  assert(outputs==1&&allocations==baseline); /* Never feed the return back. */
  int original=session->base.fd;hev_object_unref(HEV_OBJECT(session));
  assert(fcntl(original,F_GETFD)<0&&errno==EBADF&&!udp_pcbs);assert(!close(peer));
  netif_remove(&netif);hev_lwip_context_bind(NULL);assert(!allocations);
}
int main(void)
{
  alarm(5);assert(!hev_task_system_init());HevTask *task=hev_task_new(32768);assert(task);
  hev_task_run(task,run,NULL);hev_task_system_run();hev_task_system_fini();
  puts("real mDNS socket accepts underlay datagram, rejects its own virtual-network return and frees resources PASS");
}
