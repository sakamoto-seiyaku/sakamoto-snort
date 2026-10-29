/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_root_dns_io.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const uint8_t question[] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
typedef struct {int fd; unsigned events; uint64_t cookie;} watch_t;
static watch_t watches[8], authorization[8];
static unsigned authorization_count, answers, failures;
static product_dns_proxy_key_t answered;
static int watch(void *context,int fd,unsigned events,uint64_t cookie)
{
  assert(!context);watch_t *slot=NULL;
  for(unsigned i=0;i<8;++i)if(watches[i].events&&watches[i].fd==fd)slot=&watches[i];
  if(!events){if(slot)memset(slot,0,sizeof(*slot));return 1;}
  if(!slot)for(unsigned i=0;i<8;++i)if(!watches[i].events){slot=&watches[i];break;}
  assert(slot);*slot=(watch_t){fd,events,cookie};return 1;
}
static int authorize(void *context,int fd,uint64_t cookie)
{
  assert(!context&&authorization_count<8);
  authorization[authorization_count++]=(watch_t){fd,0,cookie};return 0;
}
static void answer(void *context,const product_dns_proxy_key_t *key,unsigned transport,
  const uint8_t *wire,size_t length,uint64_t now)
{
  assert(!context&&transport==1&&length==sizeof(question)&&now);
  assert(wire[2]==0x81&&wire[3]==0x80);++answers;answered=*key;
}
static void failed(void *context,const product_dns_proxy_key_t *key,uint64_t now)
{assert(!context&&key&&now);++failures;}
static unsigned watched(void)
{unsigned count=0;for(unsigned i=0;i<8;++i)count+=!!watches[i].events;return count;}
static void drive(product_root_dns_io_t *io,uint64_t now)
{
  watch_t saved[8];struct pollfd ready[8];unsigned count=0;
  for(unsigned i=0;i<8;++i)if(watches[i].events){saved[count]=watches[i];
    ready[count++]=(struct pollfd){.fd=watches[i].fd,.events=POLLIN};}
  assert(poll(ready,count,20)>=0);
  for(unsigned i=0;i<count;++i)if(ready[i].revents)
    product_root_dns_io_ready(io,321,saved[i].cookie,saved[i].fd,PRODUCT_ROOT_DNS_READ,now);
}
static int peer(unsigned family,uint16_t *port)
{
  int fd=socket(family==4?AF_INET:AF_INET6,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(fd>=0);
  struct sockaddr_in v4={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
  struct sockaddr_in6 v6={.sin6_family=AF_INET6,.sin6_addr=IN6ADDR_LOOPBACK_INIT};
  if(family==6){int one=1;assert(!setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&one,sizeof(one)));}
  void *address=family==4?(void *)&v4:(void *)&v6;socklen_t length=family==4?sizeof(v4):sizeof(v6);
  assert(!bind(fd,address,length)&&!getsockname(fd,address,&length));
  *port=ntohs(family==4?v4.sin_port:v6.sin6_port);return fd;
}
static product_dns_proxy_key_t key(unsigned family,uint16_t port,unsigned attempt)
{
  product_dns_proxy_key_t result={.generation=321,.token=1,.incarnation=8,.attempt=attempt,
    .network_revision=5,.route_revision=7,.resolver_id=attempt,.resolver_family=family,.resolver_port=port};
  if(family==4)memcpy(result.resolver_address,(uint8_t[]){127,0,0,1},4);
  else result.resolver_address[15]=1;
  return result;
}
static void no_packet(int fd)
{struct pollfd p={.fd=fd,.events=POLLIN};assert(!poll(&p,1,20));}
static struct sockaddr_storage receive(int fd,const uint8_t *query)
{
  struct sockaddr_storage client;socklen_t size=sizeof(client);uint8_t wire[512];
  struct pollfd p={.fd=fd,.events=POLLIN};assert(poll(&p,1,1000)==1);
  assert(recvfrom(fd,wire,sizeof(wire),0,(struct sockaddr *)&client,&size)==sizeof(question));
  assert(!memcmp(wire,query,sizeof(question)));return client;
}
static void respond(int fd,unsigned family,struct sockaddr_storage client,const uint8_t *query)
{
  uint8_t wire[sizeof(question)];memcpy(wire,query,sizeof(wire));wire[2]=0x81;wire[3]=0x80;
  assert(sendto(fd,wire,sizeof(wire),0,(struct sockaddr *)&client,
    family==4?sizeof(struct sockaddr_in):sizeof(struct sockaddr_in6))==sizeof(wire));
}
static void ordered_endpoints_and_bounded_pool(unsigned family)
{
  int peers[7];uint16_t ports[7];product_dns_proxy_key_t keys[7];
  for(unsigned i=0;i<7;++i){peers[i]=peer(family,&ports[i]);keys[i]=key(family,ports[i],i+1);}
  product_dns_proxy_route_t route={.enabled=1,.family=family,.port=ports[0],.endpoint_count=7,
    .route_count=1,.routes={{.count=7,.candidates={0,1,2,3,4,5,6}}}};
  memcpy(route.address,keys[0].resolver_address,16);
  for(unsigned i=0;i<7;++i){route.endpoints[i]=(sakamoto_product_dns_endpoint_t){.transport=1,.family=family,.port=ports[i]};
    memcpy(route.endpoints[i].address,keys[i].resolver_address,16);
    snprintf((char *)route.endpoints[i].identity,256,"resolver-%u.test",i);}
  uint64_t sequence=0;product_root_dns_io_callbacks_t callbacks={.watch=watch,.answer=answer,.failed=failed};
  product_root_dns_io_t *io=product_root_dns_io_open(321,&route,0,&sequence,&callbacks,NULL,100);assert(io);
  unsigned initial_answers=answers;
  assert(product_root_dns_io_send(io,&keys[0],1,question,sizeof(question),100000000,101)==1);
  struct sockaddr_storage primary=receive(peers[0],question);no_packet(peers[1]);
  product_root_dns_io_cancel(io,&keys[0]);
  uint8_t backup[sizeof(question)];memcpy(backup,question,sizeof(backup));++backup[0];
  assert(product_root_dns_io_send(io,&keys[1],1,backup,sizeof(backup),100000000,102)==1);
  struct sockaddr_storage selected=receive(peers[1],backup);no_packet(peers[0]);
  respond(peers[0],family,primary,question);drive(io,103);
  assert(answers==initial_answers); /* Retired primary cannot answer the backup. */
  respond(peers[1],family,selected,backup);drive(io,104);
  assert(answers==initial_answers+1&&!memcmp(&answered,&keys[1],sizeof(answered)));
  product_root_dns_io_cancel(io,&keys[1]);
  for(unsigned i=0;i<6;++i){
    assert(product_root_dns_io_send(io,&keys[i],1,question,sizeof(question),100000000,200+i)==1);
    (void)receive(peers[i],question);
  }
  assert(product_root_dns_io_send(io,&keys[6],1,question,sizeof(question),100000000,210)==0);
  no_packet(peers[6]);product_root_dns_io_status_t state=product_root_dns_io_status(io);
  assert(state.sockets==6&&state.requests==6&&state.high_water_sockets==6&&state.capacity==1&&watched()==6);
  assert(state.allocated_bytes<=product_root_dns_io_reservation());
  for(unsigned i=0;i<6;++i)product_root_dns_io_cancel(io,&keys[i]);
  assert(!product_root_dns_io_status(io).requests);
  product_root_dns_io_expire(io,210+PRODUCT_ROOT_DNS_IDLE_US);
  assert(!product_root_dns_io_status(io).sockets&&!watched());
  product_root_dns_io_close(io);assert(!watched());
  for(unsigned i=0;i<7;++i)assert(!close(peers[i]));
}
static void independent_async_authorization(unsigned family)
{
  uint16_t ports[2];int peers[]={peer(family,&ports[0]),peer(family,&ports[1])};
  product_dns_proxy_key_t keys[]={key(family,ports[0],1),key(family,ports[1],2)};
  product_dns_proxy_route_t route={.enabled=1,.family=family,.port=ports[0],.endpoint_count=2,
    .route_count=1,.routes={{.count=2,.candidates={0,1}}}};
  for(unsigned i=0;i<2;++i){route.endpoints[i]=(sakamoto_product_dns_endpoint_t){.transport=1,.family=family,.port=ports[i]};
    memcpy(route.endpoints[i].address,keys[i].resolver_address,16);
    snprintf((char *)route.endpoints[i].identity,256,"resolver-%u.test",i);}
  memcpy(route.address,keys[0].resolver_address,16);authorization_count=0;
  uint64_t sequence=0;product_root_dns_io_callbacks_t callbacks={.authorize=authorize,.watch=watch,.answer=answer,.failed=failed};
  product_root_dns_io_t *io=product_root_dns_io_open(321,&route,0,&sequence,&callbacks,NULL,100);assert(io);
  assert(product_root_dns_io_send(io,&keys[0],1,question,sizeof(question),100000000,101)==1);
  assert(product_root_dns_io_send(io,&keys[1],1,question,sizeof(question),100000000,102)==1);
  assert(authorization_count==2&&!watched());no_packet(peers[0]);no_packet(peers[1]);
  assert(!product_root_dns_io_authorized(io,321,authorization[1].cookie,1,103));
  (void)receive(peers[1],question);no_packet(peers[0]);
  assert(!product_root_dns_io_authorized(io,321,authorization[0].cookie,1,104));
  (void)receive(peers[0],question);
  for(unsigned i=0;i<2;++i)product_root_dns_io_cancel(io,&keys[i]);
  product_root_dns_io_expire(io,104+PRODUCT_ROOT_DNS_IDLE_US);assert(!watched());
  keys[1].attempt=3;
  assert(product_root_dns_io_send(io,&keys[1],1,question,sizeof(question),100000000,104+PRODUCT_ROOT_DNS_IDLE_US+1)==1);
  assert(authorization_count==3&&authorization[2].cookie!=authorization[1].cookie);
  assert(product_root_dns_io_authorized(io,321,authorization[1].cookie,1,104+PRODUCT_ROOT_DNS_IDLE_US+2)<0);
  no_packet(peers[1]);product_root_dns_io_cancel(io,&keys[1]);
  (void)product_root_dns_io_authorized(io,321,authorization[2].cookie,1,104+PRODUCT_ROOT_DNS_IDLE_US+3);
  assert(!product_root_dns_io_status(io).requests);no_packet(peers[1]);
  product_root_dns_io_close(io);assert(!watched());
  for(unsigned i=0;i<2;++i)assert(!close(peers[i]));
}
int main(void)
{
  for(unsigned family=4;family<=6;family+=2){ordered_endpoints_and_bounded_pool(family);independent_async_authorization(family);}
  assert(!failures);puts("actual dual-stack selected resolver sockets, six-channel bound, retired answer and async cookie fencing PASS");
}
