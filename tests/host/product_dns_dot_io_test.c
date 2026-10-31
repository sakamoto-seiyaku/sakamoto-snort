/* SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "product_root_dns_io.h"
#include <arpa/inet.h>
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/random.h>

static const uint8_t question[] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
typedef struct { int fd; unsigned events; uint64_t cookie; } watch_t;
static watch_t watches[8], pending;
static unsigned answers, failures;
static unsigned bootstrap_port;
static unsigned rng_failure;
ssize_t __real_getrandom(void *,size_t,unsigned);
ssize_t __wrap_getrandom(void *buffer,size_t length,unsigned flags)
{if(rng_failure){errno=EAGAIN;return -1;}return __real_getrandom(buffer,length,flags);}
static int bootstrap_mode(unsigned mode) {return (mode>=4&&mode<=7)||mode==9||mode==10||(mode>=13&&mode<=16);}

static int original_network(void *context,product_root_dns_network_t *network)
{
  assert(!context&&bootstrap_port);
  *network=(product_root_dns_network_t){.family=4,.port=bootstrap_port,.ifindex=1,.address={127,0,0,1}};
  return 1;
}
static uint64_t monotonic_us(void)
{
  struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));
  return (uint64_t)t.tv_sec*1000000+t.tv_nsec/1000;
}
static int watch(void *context,int fd,unsigned events,uint64_t cookie)
{
  assert(!context);watch_t *slot=NULL;
  for(unsigned i=0;i<8;++i)if(watches[i].events&&watches[i].fd==fd)slot=&watches[i];
  if(!events){if(slot)memset(slot,0,sizeof(*slot));return 1;}
  if(!slot)for(unsigned i=0;i<8;++i)if(!watches[i].events){slot=&watches[i];break;}
  assert(slot);*slot=(watch_t){fd,events,cookie};return 1;
}
static int authorize(void *context,int fd,uint64_t cookie)
{assert(!context&&!pending.cookie);pending=(watch_t){fd,0,cookie};return 0;}
static void answer(void *context,const product_dns_proxy_key_t *key,unsigned transport,
  const uint8_t *wire,size_t length,uint64_t now)
{
  assert(!context&&key->generation==322&&transport==3&&now);
  assert(length==sizeof(question)&&wire[2]==0x81&&wire[3]==0x80);
  assert(!memcmp(wire+12,question+12,length-12));++answers;
}
static void failed(void *context,const product_dns_proxy_key_t *key,uint64_t now)
{assert(!context&&key->generation==322&&now);++failures;}
int main(int argc,char **argv)
{
  assert(argc==6||argc==7);
  unsigned family=atoi(argv[1]),mode=atoi(argv[5]);
  if(bootstrap_mode(mode)){assert(argc==7);bootstrap_port=atoi(argv[6]);}
  product_dns_proxy_route_t route={.enabled=1,.family=bootstrap_mode(mode)?0:family,.port=atoi(argv[2]),
    .endpoint_count=1,.route_count=1,.routes={{.count=1}},
    .endpoints={{.transport=3}}};
  if(!bootstrap_mode(mode))assert(inet_pton(family==4?AF_INET:AF_INET6,family==4?"127.0.0.1":"::1",route.address)==1);
  route.endpoints[0].family=route.family;route.endpoints[0].port=route.port;
  memcpy(route.endpoints[0].address,route.address,16);
  snprintf((char *)route.endpoints[0].identity,256,"%s",argv[3]);
  product_root_dns_io_callbacks_t callbacks={.watch=watch,.answer=answer,.failed=failed,
    .authorize=(mode==2||mode==9||mode==17)?authorize:NULL,.trust_directory=argv[4],
    .bootstrap_network=bootstrap_mode(mode)?original_network:NULL};
  uint64_t sequence=0,now=monotonic_us(),end=now+3000000;
  product_root_dns_io_t *io=product_root_dns_io_open(322,&route,0,&sequence,&callbacks,NULL,now);
  assert(io);
  uint64_t baseline_bytes=product_root_dns_io_status(io).allocated_bytes;
  product_dns_proxy_key_t key={.generation=322,.token=1,.incarnation=1,.attempt=1,
    .network_revision=1,.route_revision=1,.resolver_family=route.family,.resolver_port=route.port,.resolver_id=1};
  memcpy(key.resolver_address,route.address,16);
  int sent=product_root_dns_io_send(io,&key,3,question,sizeof(question),end,now);
  if(mode==3){assert(sent==-1&&!product_root_dns_io_status(io).tls_connections);product_root_dns_io_close(io);return 0;}
  assert(sent==1);
  if(mode==11){
    product_dns_proxy_key_t keys[PRODUCT_ROOT_DNS_TCP_SOCKETS];keys[0]=key;
    for(unsigned i=1;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i){keys[i]=key;keys[i].token=i+1;
      assert(product_root_dns_io_send(io,&keys[i],3,question,sizeof(question),end,now)==1);}
    product_dns_proxy_key_t excess=key;excess.token=99;
    assert(product_root_dns_io_send(io,&excess,3,question,sizeof(question),end,now)==0);
    product_root_dns_io_status_t status=product_root_dns_io_status(io);
    assert(status.capacity==1&&status.sockets==PRODUCT_ROOT_DNS_TCP_SOCKETS&&status.tls_connections==PRODUCT_ROOT_DNS_TCP_SOCKETS);
    assert(status.allocated_bytes<=product_root_dns_io_reservation());
    for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_SOCKETS;++i)product_root_dns_io_cancel(io,&keys[i]);
    assert(!product_root_dns_io_status(io).sockets&&product_root_dns_io_status(io).allocated_bytes==baseline_bytes);product_root_dns_io_close(io);return 0;
  }
  rng_failure=mode==12;
  if(mode==17){
    uint64_t cookie=pending.cookie;assert(cookie);
    product_root_dns_io_expire(io,end);
    assert(failures==1&&!answers&&!product_root_dns_io_status(io).sockets);
    assert(product_root_dns_io_authorized(io,322,cookie,1,end+1)==-1);
    assert(product_root_dns_io_status(io).allocated_bytes==baseline_bytes);
    product_root_dns_io_close(io);return 0;
  }

  if(mode==2){
    assert(pending.cookie&&!product_root_dns_io_status(io).tcp_sent);
    struct timespec delay={.tv_nsec=100000000};nanosleep(&delay,NULL);
    printf("authorization_grant_us=%llu\n",(unsigned long long)monotonic_us());fflush(stdout);
    assert(!product_root_dns_io_authorized(io,322,pending.cookie,1,monotonic_us()));
    pending=(watch_t){0};
  }
  while(!answers&&!failures&&(now=monotonic_us())<end){
    if(mode==9&&pending.cookie){
      struct timespec delay={.tv_nsec=100000000};nanosleep(&delay,NULL);
      uint64_t cookie=pending.cookie;pending=(watch_t){0};
      printf("authorization_grant_us=%llu\n",(unsigned long long)monotonic_us());fflush(stdout);
      assert(!product_root_dns_io_authorized(io,322,cookie,1,monotonic_us()));
    }
    struct pollfd fds[8];watch_t saved[8];unsigned count=0;
    for(unsigned i=0;i<8;++i)if(watches[i].events){
      saved[count]=watches[i];fds[count++]=(struct pollfd){.fd=watches[i].fd,
        .events=((watches[i].events&1)?POLLIN:0)|((watches[i].events&2)?POLLOUT:0)};
    }
    assert(poll(fds,count,10)>=0);
    for(unsigned i=0;i<count;++i)if(fds[i].revents){
      unsigned events=((fds[i].revents&POLLIN)?1:0)|((fds[i].revents&POLLOUT)?2:0)|
        ((fds[i].revents&(POLLERR|POLLNVAL))?4:0);
      product_root_dns_io_ready(io,322,saved[i].cookie,saved[i].fd,events,monotonic_us());
    }
    product_root_dns_io_expire(io,monotonic_us());
    if(mode==8&&product_root_dns_io_status(io).tls_started){
      assert(!product_root_dns_io_status(io).tls_verified&&!product_root_dns_io_status(io).tcp_sent);
      product_root_dns_io_cancel(io,&key);
      for(unsigned i=0;i<count;++i)product_root_dns_io_ready(io,321,saved[i].cookie,saved[i].fd,3,monotonic_us());
      assert(!product_root_dns_io_status(io).sockets&&!answers&&!failures);break;
    }
  }
  if(mode==1||mode==12||(mode>=14&&mode<=16))assert(failures==1&&!answers);
  else if(mode!=8)assert(answers==1&&!failures);
  product_root_dns_io_cancel(io,&key);
  assert(product_root_dns_io_status(io).allocated_bytes<=product_root_dns_io_reservation());
  product_root_dns_io_close(io);
  for(unsigned i=0;i<8;++i)assert(!watches[i].events);
  puts("actual DoT authentication, original identity, reply and clean socket closure PASS");
}
