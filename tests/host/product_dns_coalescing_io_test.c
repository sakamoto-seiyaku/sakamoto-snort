/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_dns_proxy.h"
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

typedef struct {int fd;unsigned events;uint64_t cookie;} watch_t;
typedef struct {
 product_dns_proxy_t *proxy;product_root_dns_io_t *io;product_dns_proxy_snapshot_t snapshot;
 watch_t watches[8];uint64_t now,sequence,deadline;unsigned replies,ids[2],uids[2],codes[2],sent,cancelled;
} fixture_t;
static product_l4_policy_view_t view;
static const uint8_t question[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
 7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
static int watch(void *opaque,int fd,unsigned events,uint64_t cookie)
{
 fixture_t *f=opaque;watch_t *slot=NULL;
 for(unsigned i=0;i<8;++i)if(f->watches[i].events&&f->watches[i].fd==fd){slot=&f->watches[i];break;}
 if(!events){if(slot)memset(slot,0,sizeof(*slot));return 1;}
 if(!slot)for(unsigned i=0;i<8;++i)if(!f->watches[i].events){slot=&f->watches[i];break;}
 assert(slot);*slot=(watch_t){fd,events,cookie};return 1;
}
static int send_query(void *opaque,const product_dns_proxy_key_t *key,unsigned transport,
 const uint8_t *wire,size_t length,uint64_t deadline)
{
 fixture_t *f=opaque;++f->sent;if(f->deadline)assert(f->deadline==deadline);else f->deadline=deadline;
 return product_root_dns_io_send(f->io,key,transport,wire,length,deadline,f->now);
}
static void cancel(void *opaque,const product_dns_proxy_key_t *key)
{fixture_t *f=opaque;++f->cancelled;product_root_dns_io_cancel(f->io,key);}
static int reply(void *opaque,const product_dns_proxy_event_t *event,const uint8_t *wire,size_t length)
{
 fixture_t *f=opaque;assert(f->replies<2&&length>=12);
 unsigned i=f->replies++;f->ids[i]=(unsigned)wire[0]*256+wire[1];f->uids[i]=event->input.context.packet.uid;f->codes[i]=wire[3]&15;
 assert(event->key.token==i+1&&event->input.identity.transport_session==21+i);return 1;
}
static int acquire(void *opaque,const product_dns_proxy_input_t *input,product_dns_proxy_snapshot_t *snapshot)
{fixture_t *f=opaque;*snapshot=f->snapshot;snapshot->context.packet=input->context.packet;snapshot->context.caller=input->context.caller;return 1;}
static void answer(void *opaque,const product_dns_proxy_key_t *key,unsigned transport,const uint8_t *wire,size_t length,uint64_t now)
{fixture_t *f=opaque;product_dns_proxy_answer(f->proxy,key,transport,wire,length,now);}
static void failure(void *opaque,const product_dns_proxy_key_t *key,uint64_t now)
{fixture_t *f=opaque;product_dns_proxy_fail(f->proxy,key,now);}
static void drive(fixture_t *f)
{
 struct pollfd ready[8];watch_t saved[8];unsigned count=0;
 for(unsigned i=0;i<8;++i)if(f->watches[i].events){saved[count]=f->watches[i];
  ready[count]=(struct pollfd){.fd=saved[count].fd,.events=((f->watches[i].events&1)?POLLIN:0)|((f->watches[i].events&2)?POLLOUT:0)};++count;}
 assert(poll(ready,count,20)>=0);
 for(unsigned i=0;i<count;++i)if(ready[i].revents)product_root_dns_io_ready(f->io,77,saved[i].cookie,saved[i].fd,
  ((ready[i].revents&(POLLIN|POLLHUP))?PRODUCT_ROOT_DNS_READ:0)|((ready[i].revents&POLLOUT)?PRODUCT_ROOT_DNS_WRITE:0)
  |((ready[i].revents&(POLLERR|POLLNVAL))?PRODUCT_ROOT_DNS_ERROR:0),f->now);
}
static void receive_stream(fixture_t *f,int fd,uint8_t *wire,size_t length)
{
 size_t at=0;for(unsigned attempt=0;attempt<50&&at<length;++attempt){drive(f);
  ssize_t n=recv(fd,wire+at,length-at,MSG_DONTWAIT);if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK))continue;assert(n>0);at+=(size_t)n;}
 assert(at==length);
}
static void run(unsigned profile,unsigned family,unsigned protocol,unsigned continuation,unsigned deny_first)
{
 fixture_t f={.now=1000000};assert(!product_l4_policy_compile(&view,NULL,0));
 int af=family==4?AF_INET:AF_INET6;
 int udp=socket(af,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0),tcp=socket(af,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);assert(udp>=0&&tcp>=0);
 struct sockaddr_storage resolver={0};socklen_t bytes;
 if(family==4){struct sockaddr_in *a=(struct sockaddr_in*)&resolver;a->sin_family=AF_INET;a->sin_addr.s_addr=htonl(INADDR_LOOPBACK);bytes=sizeof(*a);}
 else{struct sockaddr_in6 *a=(struct sockaddr_in6*)&resolver;a->sin6_family=AF_INET6;a->sin6_addr=in6addr_loopback;bytes=sizeof(*a);}
 assert(!bind(tcp,(struct sockaddr*)&resolver,bytes));assert(!getsockname(tcp,(struct sockaddr*)&resolver,&bytes));
 assert(!listen(tcp,8)&&!bind(udp,(struct sockaddr*)&resolver,bytes));
 product_dns_proxy_route_t route={.enabled=1,.family=family,.port=family==4?ntohs(((struct sockaddr_in*)&resolver)->sin_port):ntohs(((struct sockaddr_in6*)&resolver)->sin6_port)};
 if(family==4)memcpy(route.address,(uint8_t[]){127,0,0,1},4);else route.address[15]=1;
 product_root_dns_io_callbacks_t io_callbacks={.watch=watch,.answer=answer,.failed=failure};
 f.io=product_root_dns_io_open(77,&route,0,&f.sequence,&io_callbacks,&f,f.now);assert(f.io);
 product_dns_proxy_input_t input={.identity={.generation=77,.incarnation=11,.network_revision=5,.now_us=f.now,.profile=profile,.transport_session=21},
  .token=1,.route_revision=3,.slot=UINT32_MAX,.context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP,
  .packet={.uid=10123,.uid_known=1,.family=family,.protocol=protocol,.direction=3,.direction_known=1,.ports_available=1,.source_port=40000,.destination_port=53}}};
 f.snapshot=(product_dns_proxy_snapshot_t){.context=input.context,.view=&view,.identity={77,3,123,0},.network_revision=5,.route_revision=3};
 product_dns_proxy_callbacks_t callbacks={.send=send_query,.cancel=cancel,.reply=reply,.acquire=acquire};
 f.proxy=product_dns_proxy_open(77,&route,&callbacks,&f);assert(f.proxy);
 assert(product_dns_proxy_submit(f.proxy,&input,question,sizeof(question),&f.snapshot));
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;input.context.packet.uid=10124;input.context.packet.source_port=40001;
 input.identity.now_us=f.now=2000000;uint8_t follow[sizeof(question)];memcpy(follow,question,sizeof(follow));follow[0]=0xab;follow[1]=0xcd;
 product_dns_proxy_snapshot_t current=f.snapshot;current.context.packet=input.context.packet;
 assert(product_dns_proxy_submit(f.proxy,&input,follow,sizeof(follow),&current));
 product_dns_proxy_resources_t resource=product_dns_proxy_resources(f.proxy);
 assert(resource.active==2&&resource.exchanges==1&&resource.cache_entries==0&&f.replies==0&&f.sent==1);
 assert(product_root_dns_io_status(f.io).udp_sent==1&&product_root_dns_io_status(f.io).requests==1);
 struct pollfd peer={.fd=udp,.events=POLLIN};assert(poll(&peer,1,1000)==1);
 uint8_t wire[sizeof(question)+16];struct sockaddr_storage client;socklen_t client_bytes=sizeof(client);
 assert(recvfrom(udp,wire,sizeof(wire),0,(struct sockaddr*)&client,&client_bytes)==sizeof(question));
 assert(!memcmp(wire+2,question+2,sizeof(question)-2));assert(!poll(&peer,1,20));
 int stream=-1;
 if(continuation){uint8_t tc[sizeof(question)];memcpy(tc,wire,sizeof(tc));tc[2]=0x83;tc[3]=0x80;
  assert(sendto(udp,tc,sizeof(tc),0,(struct sockaddr*)&client,client_bytes)==sizeof(tc));
  for(unsigned i=0;i<50&&f.sent<2;++i){drive(&f);}
  assert(f.sent==2&&f.deadline==4000000);
  struct pollfd listener={.fd=tcp,.events=POLLIN};assert(poll(&listener,1,1000)==1);
  stream=accept4(tcp,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);assert(stream>=0);
  uint8_t framed[sizeof(question)+2];receive_stream(&f,stream,framed,sizeof(framed));
  assert(framed[0]==0&&framed[1]==sizeof(question)&&!memcmp(framed+4,question+2,sizeof(question)-2));
  memcpy(wire,framed+2,sizeof(question));assert(product_dns_proxy_deadline(f.proxy)==4000000);
 }
 if(deny_first){product_l4_policy_rule_t rule={.uid=10123,.rule_id=320,.reason_id=320,.action=2,
  .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX};
  assert(!product_l4_policy_compile(&view,&rule,1));++f.snapshot.identity.revision;}
 wire[2]=0x81;wire[3]=0x80;wire[7]=1;
 memcpy(wire+sizeof(question),(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
 f.now=3500000;
 if(continuation){uint8_t framed[sizeof(wire)+2];framed[0]=sizeof(wire)>>8;framed[1]=sizeof(wire);memcpy(framed+2,wire,sizeof(wire));
  assert(send(stream,framed,sizeof(framed),MSG_NOSIGNAL)==sizeof(framed));}
 else assert(sendto(udp,wire,sizeof(wire),0,(struct sockaddr*)&client,client_bytes)==sizeof(wire));
 for(unsigned i=0;i<50&&f.replies<2;++i)drive(&f);
 assert(f.replies==2&&f.ids[0]==0x1234&&f.ids[1]==0xabcd&&f.uids[0]==10123&&f.uids[1]==10124);
 assert(f.codes[0]==(deny_first?5U:0U)&&f.codes[1]==0&&f.cancelled==1);
 assert(product_dns_proxy_resources(f.proxy).active==0&&product_dns_proxy_resources(f.proxy).cache_entries==1);
 assert(product_root_dns_io_status(f.io).requests==0&&!poll(&peer,1,20));
 int owned_fd=-1;for(unsigned i=0;i<8;++i)if(f.watches[i].events)owned_fd=f.watches[i].fd;assert(owned_fd>=0);
 product_dns_proxy_close(f.proxy);product_root_dns_io_close(f.io);
 for(unsigned i=0;i<8;++i)assert(!f.watches[i].events);
 assert(fcntl(owned_fd,F_GETFD)==-1&&errno==EBADF);if(stream>=0)close(stream);close(udp);close(tcp);
}
int main(void)
{
 for(unsigned profile=1;profile<=2;++profile)for(unsigned family=4;family<=6;family+=2)
  for(unsigned protocol=6;protocol<=17;protocol+=11)for(unsigned continuation=0;continuation<2;++continuation)
   run(profile,family,protocol,continuation,continuation);
 puts("PASS16 Host POSIX Root/VPN-context dual-stack UDP/TCP clients: realoneexchange, independentApp policy/replies, TCfixeddeadline and closedfds");return 0;
}
