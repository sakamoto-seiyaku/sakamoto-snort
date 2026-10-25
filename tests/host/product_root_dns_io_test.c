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
static uint64_t authorization_cookie;
static int authorize(void *context,int fd,uint64_t cookie)
{ assert(!context&&fd>=0&&cookie);authorization_cookie=cookie;return 0; }
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

int main (int argc,char **argv)
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
  if(argc==2 && !strcmp(argv[1],"idle-authorization")) {
    callbacks.authorize=authorize;
    active_io=product_root_dns_io_open(90,&route,0,&sequence,&callbacks,NULL,100);
    assert(active_io&&product_root_dns_io_status(active_io).udp_state==PRODUCT_ROOT_DNS_UDP_AUTHORIZING);
    product_dns_proxy_key_t key={.generation=90,.token=9,.attempt=1};
    assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),1000,101)==1);
    uint64_t first_cookie=authorization_cookie;
    struct pollfd peer={.fd=udp,.events=POLLIN};assert(!poll(&peer,1,20));
    assert(!product_root_dns_io_authorized(active_io,90,first_cookie,1,110));
    assert(product_root_dns_io_status(active_io).udp_state==PRODUCT_ROOT_DNS_UDP_AUTHORIZED);
    assert(poll(&peer,1,1000)==1);
    uint8_t wire[sizeof(question)];assert(recv(udp,wire,sizeof(wire),0)==sizeof(wire));
    assert(!memcmp(wire,question,sizeof(wire)));product_root_dns_io_cancel(active_io,&key);
    uint64_t idle=product_root_dns_io_deadline(active_io);
    product_root_dns_io_expire(active_io,idle);
    product_root_dns_io_status_t state=product_root_dns_io_status(active_io);
    assert(state.udp_state==PRODUCT_ROOT_DNS_UDP_IDLE&&!state.udp_ready&&!state.sockets&&!watched_count());
    ++key.attempt;
    assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),idle+1000,idle+1)==1);
    uint64_t denied_cookie=authorization_cookie;assert(denied_cookie!=first_cookie);
    assert(product_root_dns_io_status(active_io).udp_state==PRODUCT_ROOT_DNS_UDP_AUTHORIZING);
    assert(!product_root_dns_io_status(active_io).udp_ready&&!poll(&peer,1,20));
    assert(product_root_dns_io_authorized(active_io,90,first_cookie,1,idle+2)<0&&!poll(&peer,1,20));
    assert(!product_root_dns_io_authorized(active_io,90,denied_cookie,0,idle+10));
    state=product_root_dns_io_status(active_io);
    assert(state.udp_state==PRODUCT_ROOT_DNS_UDP_FAILED&&!state.sockets&&!state.requests&&failures==1);
    assert(product_root_dns_io_authorized(active_io,90,denied_cookie,1,idle+11)<0&&!poll(&peer,1,20));
    ++key.attempt;
    assert(product_root_dns_io_send(active_io,&key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),idle+2000,idle+20)==1);
    assert(authorization_cookie!=denied_cookie&&!poll(&peer,1,20));
    assert(!product_root_dns_io_authorized(active_io,90,authorization_cookie,1,idle+30));
    state=product_root_dns_io_status(active_io);
    assert(state.udp_state==PRODUCT_ROOT_DNS_UDP_AUTHORIZED&&state.udp_ready&&state.errors==1);
    assert(poll(&peer,1,1000)==1&&recv(udp,wire,sizeof(wire),0)==sizeof(wire));
    assert(!memcmp(wire,question,sizeof(wire))&&failures==1);
    product_root_dns_io_cancel(active_io,&key);
    int owned_fd=watches[0].fd;
    product_root_dns_io_close(active_io);active_io=NULL;
    assert(!watched_count()&&fcntl(owned_fd,F_GETFD)==-1&&errno==EBADF);
    assert(product_root_dns_io_status(NULL).udp_state==PRODUCT_ROOT_DNS_UDP_NONE);
    assert(product_root_dns_io_authorized(NULL,90,authorization_cookie,1,idle+40)<0&&!poll(&peer,1,20));
    /* Reaping an initial authorization that never completed is not proof of a
     * clean, previously authorized idle route. Late success cannot revive it. */
    active_io=product_root_dns_io_open(90,&route,0,&sequence,&callbacks,NULL,idle+100);
    uint64_t unconfirmed=authorization_cookie;
    product_root_dns_io_expire(active_io,idle+100+PRODUCT_ROOT_DNS_IDLE_US);
    assert(product_root_dns_io_status(active_io).udp_state==PRODUCT_ROOT_DNS_UDP_FAILED);
    assert(!product_root_dns_io_status(active_io).udp_ready&&!product_root_dns_io_status(active_io).sockets);
    assert(product_root_dns_io_authorized(active_io,90,unconfirmed,1,idle+101+PRODUCT_ROOT_DNS_IDLE_US)<0);
    assert(!poll(&peer,1,20));product_root_dns_io_close(active_io);active_io=NULL;
    close(udp);close(tcp);
    puts("actual idle reopen reauthorizes FIRST UDP input; denied/stale/stop never send; current state recovers despite historical error PASS");return 0;
  }
  if(argc==2 && !strcmp(argv[1],"authorization")) {
    callbacks.authorize=authorize;
    active_io=product_root_dns_io_open(90,&route,0,&sequence,&callbacks,NULL,100);
    assert(active_io&&!watched_count());
    assert(product_root_dns_io_status(active_io).authorizing==1&&!product_root_dns_io_status(active_io).udp_ready);
    product_dns_proxy_key_t auth_key={.generation=90,.token=6,.attempt=1};
    assert(product_root_dns_io_send(active_io,&auth_key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),1000,101)==1);
    struct pollfd no_udp={.fd=udp,.events=POLLIN};assert(!poll(&no_udp,1,20));
    uint64_t denied_cookie=authorization_cookie;
    assert(!product_root_dns_io_authorized(active_io,90,denied_cookie,0,110));
    assert(failures==1&&!product_root_dns_io_status(active_io).udp_ready&&!product_root_dns_io_status(active_io).requests);
    assert(!product_root_dns_io_status(active_io).sockets&&!product_root_dns_io_status(active_io).authorizing);
    assert(product_root_dns_io_authorized(active_io,90,denied_cookie,1,111)<0&&!poll(&no_udp,1,20));
    product_root_dns_io_close(active_io);
    active_io=product_root_dns_io_open(90,&route,0,&sequence,&callbacks,NULL,120);
    assert(active_io&&authorization_cookie!=denied_cookie);
    ++auth_key.attempt;
    assert(product_root_dns_io_send(active_io,&auth_key,PRODUCT_DNS_PROXY_UDP,question,sizeof(question),1000,121)==1);
    assert(!poll(&no_udp,1,20));
    assert(!product_root_dns_io_authorized(active_io,90,authorization_cookie,1,130));
    assert(watched_count()==1&&product_root_dns_io_status(active_io).udp_ready&&!product_root_dns_io_status(active_io).authorizing);
    assert(poll(&no_udp,1,1000)==1);
    uint8_t datagram[sizeof(question)];assert(recv(udp,datagram,sizeof(datagram),0)==sizeof(question));
    assert(!memcmp(datagram,question,sizeof(question)));product_root_dns_io_cancel(active_io,&auth_key);
    ++auth_key.attempt;
    assert(product_root_dns_io_send(active_io,&auth_key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),1000,200)==1);
    uint64_t late=authorization_cookie;
    struct pollfd no_connect={.fd=tcp,.events=POLLIN};assert(poll(&no_connect,1,20)==0);
    assert(!product_root_dns_io_authorized(active_io,90,late,1,1001));
    assert(poll(&no_connect,1,20)==0 && failures==2); /* First late event cannot start a connection. */
    assert(product_root_dns_io_authorized(active_io,90,late,1,1002)<0 && failures==2);
    ++auth_key.attempt;
    assert(product_root_dns_io_send(active_io,&auth_key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),2000,1100)==1);
    assert(!product_root_dns_io_authorized(active_io,90,authorization_cookie,1,1110));
    assert(poll(&no_connect,1,1000)==1);
    int authorized_peer=accept4(tcp,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);assert(authorized_peer>=0);
    uint8_t authorized_wire[sizeof(question)+2];peer_read(authorized_peer,authorized_wire,sizeof(authorized_wire),1111);
    assert(!memcmp(authorized_wire+2,question,sizeof(question)));
    product_root_dns_io_cancel(active_io,&auth_key);close(authorized_peer);
    ++auth_key.attempt;
    assert(product_root_dns_io_send(active_io,&auth_key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),3000,2100)==1);
    assert(!product_root_dns_io_authorized(active_io,90,authorization_cookie,1,2110));
    assert(poll(&no_connect,1,1000)==1);
    int expired_peer=accept4(tcp,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);assert(expired_peer>=0);
    drive(90,3001);
    struct pollfd ended={.fd=expired_peer,.events=POLLIN};assert(poll(&ended,1,1000)==1);
    assert(recv(expired_peer,datagram,sizeof(datagram),0)==0&&failures==3);close(expired_peer);
    ++auth_key.attempt;
    assert(product_root_dns_io_send(active_io,&auth_key,PRODUCT_DNS_PROXY_TCP,question,sizeof(question),4000,3100)==1);
    uint64_t cancelled_cookie=authorization_cookie;
    product_root_dns_io_cancel(active_io,&auth_key);
    assert(product_root_dns_io_authorized(active_io,90,cancelled_cookie,1,3110)<0);
    assert(poll(&no_connect,1,20)==0);
    product_root_dns_io_close(active_io);active_io=NULL;
    assert(product_root_dns_io_authorized(NULL,90,cancelled_cookie,1,3111)<0&&!watched_count());
    close(udp);close(tcp);
    puts("actual authorization pending/success/deadline/cancel/late: no expired connect or application bytes PASS");return 0;
  }
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
