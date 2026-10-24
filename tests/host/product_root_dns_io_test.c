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

static const uint8_t question[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
typedef struct {int fd;unsigned events;uint64_t cookie;} watch_t;
static watch_t watches[PRODUCT_DNS_PROXY_SOCKETS];
static product_root_dns_io_t *active_io;
static unsigned answers, failures;
static uint8_t answer_wire[65535];
static size_t answer_length;
static product_dns_proxy_key_t answered_key;
static unsigned answered_transport;

static int watch (void *context,int fd,unsigned events,uint64_t cookie)
{
  assert (!context);
  watch_t *slot=NULL;
  for(unsigned i=0;i<PRODUCT_DNS_PROXY_SOCKETS;++i)
    if(watches[i].events && watches[i].fd==fd) {slot=&watches[i];break;}
  if(!events) {if(slot) memset(slot,0,sizeof(*slot));return 1;}
  if(!slot) for(unsigned i=0;i<PRODUCT_DNS_PROXY_SOCKETS;++i)
    if(!watches[i].events) {slot=&watches[i];break;}
  assert(slot);*slot=(watch_t){fd,events,cookie};return 1;
}
static void answer (void *context,const product_dns_proxy_key_t *key,unsigned transport,
  const uint8_t *wire,size_t length,uint64_t now)
{
  assert(!context && now && length<=sizeof(answer_wire));
  ++answers;answered_key=*key;answered_transport=transport;
  memcpy(answer_wire,wire,length);answer_length=length;
  if(transport==PRODUCT_DNS_PROXY_TCP) product_root_dns_io_cancel(active_io,key);
}
static void failed (void *context,const product_dns_proxy_key_t *key,uint64_t now)
{
  assert(!context && now);++failures;product_root_dns_io_cancel(active_io,key);
}
static void drive (uint64_t generation,uint64_t now)
{
  struct pollfd ready[PRODUCT_DNS_PROXY_SOCKETS];
  watch_t saved[PRODUCT_DNS_PROXY_SOCKETS];unsigned count=0;
  for(unsigned i=0;i<PRODUCT_DNS_PROXY_SOCKETS;++i) if(watches[i].events)
    {
      saved[count]=watches[i];
      ready[count++]=(struct pollfd){.fd=watches[i].fd,
        .events=((watches[i].events&PRODUCT_ROOT_DNS_READ)?POLLIN:0)
          |((watches[i].events&PRODUCT_ROOT_DNS_WRITE)?POLLOUT:0)};
    }
  assert(poll(ready,count,20)>=0);
  for(unsigned i=0;i<count;++i) if(ready[i].revents)
    product_root_dns_io_ready(active_io,generation,saved[i].cookie,saved[i].fd,
      ((ready[i].revents&(POLLIN|POLLHUP))?PRODUCT_ROOT_DNS_READ:0)
      |((ready[i].revents&POLLOUT)?PRODUCT_ROOT_DNS_WRITE:0)
      |((ready[i].revents&(POLLERR|POLLNVAL))?PRODUCT_ROOT_DNS_ERROR:0),now);
}
static int watched_count (void)
{int result=0;for(unsigned i=0;i<PRODUCT_DNS_PROXY_SOCKETS;++i) result+=!!watches[i].events;return result;}

static void peer_read (int fd,uint8_t *wire,size_t length,uint64_t now)
{
  size_t at=0;
  for(unsigned attempt=0;attempt<50 && at<length;++attempt)
    {
      drive(90,now);
      ssize_t received=recv(fd,wire+at,length-at,MSG_DONTWAIT);
      if(received<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) continue;
      assert(received>0);at+=received;
    }
  assert(at==length);
}

static void read_progress (uint64_t bytes,uint64_t now)
{
  for(unsigned attempt=0;attempt<50 && product_root_dns_io_status(active_io).tcp_read_bytes<bytes;++attempt)
    drive(90,now);
  assert(product_root_dns_io_status(active_io).tcp_read_bytes==bytes);
}

int main (void)
{
  int udp=socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
  int tcp=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
  assert(udp>=0 && tcp>=0);
  struct sockaddr_in resolver={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)}};
  assert(!bind(udp,(struct sockaddr*)&resolver,sizeof(resolver)));
  socklen_t resolver_length=sizeof(resolver);
  assert(!getsockname(udp,(struct sockaddr*)&resolver,&resolver_length));
  assert(!bind(tcp,(struct sockaddr*)&resolver,sizeof(resolver)) && !listen(tcp,16));
  product_dns_proxy_route_t route={.enabled=1,.family=4,.port=ntohs(resolver.sin_port),.address={127,0,0,1}};
  product_root_dns_io_callbacks_t callbacks={.watch=watch,.answer=answer,.failed=failed};
  uint64_t sequence=0;
  active_io=product_root_dns_io_open(90,&route,0,&sequence,&callbacks,NULL,1000);
  assert(active_io && watched_count()==1);
  watch_t original=watches[0];
  product_dns_proxy_key_t key={.generation=90,.token=5,.incarnation=8,.attempt=1,.network_revision=3,.route_revision=4};
  assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),100000,1010)==1);
  uint8_t received[2048];struct sockaddr_in client;socklen_t client_length=sizeof(client);
  struct pollfd peer_ready={.fd=udp,.events=POLLIN};
  assert(poll(&peer_ready,1,1000)==1 && (peer_ready.revents&POLLIN));
  assert(recvfrom(udp,received,sizeof(received),0,(struct sockaddr*)&client,&client_length)==sizeof(question));
  assert(!memcmp(received,question,sizeof(question)));
  received[2]=0x83;received[3]=0x80;
  assert(sendto(udp,received,sizeof(question),0,(struct sockaddr*)&client,client_length)==sizeof(question));
  product_root_dns_io_ready(active_io,89,original.cookie,original.fd,PRODUCT_ROOT_DNS_READ,1020);
  assert(!answers && product_root_dns_io_status(active_io).stale==1);
  drive(90,1030);
  assert(answers==1 && answered_transport==PRODUCT_DNS_PROXY_UDP && !memcmp(&answered_key,&key,sizeof(key)));
  assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),100000,1040)==1);
  peer_ready=(struct pollfd){.fd=tcp,.events=POLLIN};
  assert(poll(&peer_ready,1,1000)==1 && (peer_ready.revents&POLLIN));
  int peer=accept4(tcp,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);assert(peer>=0);
  peer_read(peer,received,sizeof(question)+2,1050);
  assert(received[0]==0 && received[1]==sizeof(question));
  assert(!memcmp(received+2,question,sizeof(question)));
  uint8_t framed[sizeof(question)+2];framed[0]=0;framed[1]=sizeof(question);
  memcpy(framed+2,question,sizeof(question));framed[4]=0x81;framed[5]=0x80;
  assert(send(peer,framed,1,MSG_NOSIGNAL)==1);read_progress(1,1060);assert(answers==1);
  assert(send(peer,framed+1,11,MSG_NOSIGNAL)==11);read_progress(12,1070);assert(answers==1);
  assert(send(peer,framed+12,sizeof(framed)-12,MSG_NOSIGNAL)==sizeof(framed)-12);
  read_progress(sizeof(framed),1080);
  assert(answers==2 && answered_transport==PRODUCT_DNS_PROXY_TCP && answer_length==sizeof(question));
  assert(!memcmp(answer_wire,framed+2,sizeof(question)) && !memcmp(&answered_key,&key,sizeof(key)));
  close(peer);
  product_root_dns_io_status_t status=product_root_dns_io_status(active_io);
  uint64_t baseline=status.allocated_bytes;
  assert(status.sockets==1 && status.requests==0 && status.tcp_sent==1 && status.tcp_received==1);
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i)
    {key.attempt=10+i;assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),100000,1090)==1);}
  key.attempt=100;
  assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),100000,1090)==0);
  status=product_root_dns_io_status(active_io);
  assert(status.sockets==6 && status.high_water_sockets==6 && status.capacity==1 && watched_count()==6);
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i)
    {key.attempt=10+i;product_root_dns_io_cancel(active_io,&key);}
  assert(product_root_dns_io_status(active_io).allocated_bytes==baseline && watched_count()==1);
  uint64_t idle=product_root_dns_io_deadline(active_io);
  assert(idle==1030+PRODUCT_ROOT_DNS_IDLE_US);
  product_root_dns_io_expire(active_io,idle);
  assert(!product_root_dns_io_status(active_io).sockets && !watched_count());
  key.attempt=101;
  assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),idle+100000,idle+1)==1);
  assert(watched_count()==1 && watches[0].cookie!=original.cookie);
  product_root_dns_io_ready(active_io,90,original.cookie,watches[0].fd,PRODUCT_ROOT_DNS_READ,idle+2);
  assert(product_root_dns_io_status(active_io).stale==2 && answers==2 && !failures);
  int final_fd=watches[0].fd;
  product_root_dns_io_close(active_io);active_io=NULL;
  assert(!watched_count() && fcntl(final_fd,F_GETFD)==-1 && errno==EBADF);
  close(udp);close(tcp);
  puts("actual Root DNS UDP/TCP sockets: wire, partial framing, capacity, cancel, idle and stale events PASS");
}
