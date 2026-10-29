/* SPDX-License-Identifier: MIT */
#define _GNU_SOURCE
#include "hev-owner.h"
#include "lwip/inet_chksum.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Actual HEV owner, queue, scheduler, socket and lwIP return. The controlled
 * broker selects loopback as this Host fixture's multicast network. */
static uint64_t session;
static int upstream;
static unsigned outputs;
static unsigned expected_source = 1;
static int broker(void *unused,uint64_t generation,uint64_t id,int fd)
{
  assert(!unused&&generation==321);session=id;upstream=fd;
  struct in_addr loop={.s_addr=htonl(INADDR_LOOPBACK)};
  assert(!setsockopt(fd,IPPROTO_IP,IP_MULTICAST_IF,&loop,sizeof(loop)));return 0;
}
static hev_owner_output_result_t output(void *unused,const hev_owner_span_t *spans,unsigned count,
  size_t total,const hev_owner_facts_t *facts,uint64_t generation,uint64_t serial)
{
  assert(!unused&&count&&total==29&&generation==321&&serial);
  uint8_t packet[29];size_t at=0;
  for(unsigned i=0;i<count;++i){assert(spans[i].length<=total-at);memcpy(packet+at,spans[i].data,spans[i].length);at+=spans[i].length;}
  assert(at==total&&packet[28]==43&&packet[9]==17);
  assert(!memcmp(packet+12,(uint8_t[]){127,0,0,expected_source},4));
  assert(!memcmp(packet+16,(uint8_t[]){10,0,0,2},4));
  assert(packet[20]==(5353>>8)&&packet[21]==(5353&255)&&packet[22]==0x30&&packet[23]==0x39);
  assert(facts->uid==10123&&facts->flow_incarnation==13&&facts->underlay_epoch==8);
  ++outputs;return HEV_OWNER_OUTPUT_ACCEPTED;
}
static void step(hev_owner_t *owner)
{assert(hev_owner_step(owner,4,10000).quanta<=4);}
int main(void)
{
  alarm(5);int peer=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(peer>=0);
  int reuse=1;assert(!setsockopt(peer,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)));
  struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(5353)};
  assert(!bind(peer,(void *)&address,sizeof(address)));
  struct ip_mreq membership={.imr_multiaddr.s_addr=inet_addr("224.0.0.251"),.imr_interface.s_addr=htonl(INADDR_LOOPBACK)};
  assert(!setsockopt(peer,IPPROTO_IP,IP_ADD_MEMBERSHIP,&membership,sizeof(membership)));
  hev_owner_config_t config={.generation=321,.max_sessions=1,.max_input_packets=2,.max_pbufs=16,
    .max_packet_bytes=1500,.task_stack_bytes=32768,.broker_timeout_ms=1000,.udp_idle_timeout_ms=1000,
    .output=output,.broker=broker};
  hev_owner_t *owner=hev_owner_create(&config);assert(owner);
  uint8_t packet[29]={0x45,0,0,29,0,1,0,0,255,17,0,0,10,0,0,2,224,0,0,251,
    0x30,0x39,5353>>8,5353&255,0,9,0,0,42};
  uint16_t checksum=inet_chksum(packet,20);memcpy(packet+10,&checksum,2);
  hev_owner_facts_t facts={.uid=10123,.availability=HEV_OWNER_UID_KNOWN,.flow_incarnation=13};
  assert(hev_owner_input_copy(owner,packet,sizeof(packet),&facts,321)==HEV_OWNER_INPUT_ACCEPTED);
  step(owner);assert(session&&!hev_owner_snapshot(owner).direct_sent);
  struct pollfd ready={.fd=peer,.events=POLLIN};assert(!poll(&ready,1,20));
  hev_owner_binding_t binding={.underlay_epoch=8,.network_context=9,.context_known=1};
  assert(!hev_owner_broker_complete(owner,321,session,1,&binding));step(owner);
  assert(poll(&ready,1,1000)==1);
  struct sockaddr_in source;socklen_t size=sizeof(source);uint8_t value;
  assert(recvfrom(peer,&value,1,0,(void *)&source,&size)==1&&value==42);
  int unrelated=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(unrelated>=0);
  value=43;assert(sendto(unrelated,&value,1,0,(void *)&source,size)==1);
  ready.fd=upstream;assert(poll(&ready,1,1000)==1);step(owner);assert(!outputs);
  assert(!close(unrelated)); /* A non-mDNS source port cannot inject a return. */
  assert(sendto(peer,&value,1,0,(void *)&source,size)==1);
  ready.fd=upstream;
  assert(poll(&ready,1,1000)==1); /* A multicast peer's unicast response must be received. */
  step(owner);assert(outputs==1);
  int second=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(second>=0);
  assert(!setsockopt(second,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)));
  address.sin_addr.s_addr=htonl(0x7f000002);
  assert(!bind(second,(void *)&address,sizeof(address)));
  assert(sendto(second,&value,1,0,(void *)&source,size)==1);
  assert(poll(&ready,1,1000)==1);expected_source=2;step(owner);assert(outputs==2);assert(!close(second));
  hev_owner_quiesce(owner);step(owner);
  hev_owner_snapshot_t state=hev_owner_snapshot(owner);
  assert(state.stopped&&!state.sessions&&!state.pbufs&&!state.input_packets);
  assert(state.sockets_created==state.sockets_closed&&state.direct_sent==1&&state.direct_received==3);
  assert(!hev_owner_destroy(owner));
  owner=hev_owner_create(&config);assert(owner);
  assert(hev_owner_input_copy(owner,packet,sizeof(packet),&facts,321)==HEV_OWNER_INPUT_ACCEPTED);
  step(owner);hev_owner_quiesce(owner);step(owner);
  assert(hev_owner_broker_complete(owner,321,session,1,&binding)<0);
  state=hev_owner_snapshot(owner);assert(state.stopped&&!state.sessions&&!state.pbufs&&!state.input_packets&&!state.direct_sent);
  assert(state.sockets_created==state.sockets_closed);assert(!hev_owner_destroy(owner));assert(!close(peer));
  puts("real HEV multicast DNS preserves actual peer reply, broker gate and exact Stop resources PASS");
}
