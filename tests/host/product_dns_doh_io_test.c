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

/* Real nonblocking TLS + HTTP/1.1 DoH exchange against an independent OpenSSL peer.
 * The Python driver chooses the peer behavior and the exact expected outcome. */
static const uint8_t question[] = {0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
typedef struct { int fd; unsigned events; uint64_t cookie; } watch_t;
static watch_t watches[8];
static unsigned answers, failures, progress_calls, bootstrap_port;
static product_dns_proxy_io_event_t last;
/* Socket, buffer and parser accounting must return exactly. TLS memory is reported
 * live; after a completed handshake it may retain the CA key's lazily built Montgomery
 * cache (charged to the connection slot until the owner closes), a few hundred bytes. */
static uint64_t non_tls(const product_root_dns_io_status_t *status){return status->allocated_bytes-status->tls_bytes;}
static void assert_released(product_root_dns_io_t *io,uint64_t baseline)
{
  product_root_dns_io_status_t status=product_root_dns_io_status(io);
  if(status.sockets||non_tls(&status)!=baseline||status.tls_connections){
    fprintf(stderr,"sockets=%u non_tls=%llu baseline=%llu tls_connections=%u\n",status.sockets,
      (unsigned long long)non_tls(&status),(unsigned long long)baseline,status.tls_connections);
    abort();
  }
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
static int original_network(void *context,product_root_dns_network_t *network)
{
  assert(!context&&bootstrap_port);
  *network=(product_root_dns_network_t){.family=4,.port=bootstrap_port,.ifindex=1,.address={127,0,0,1}};
  return 1;
}
static void progress(void *context,const product_dns_proxy_key_t *key,const product_dns_proxy_io_event_t *event)
{assert(!context&&key->generation==323);last=*event;++progress_calls;}
static void answer(void *context,const product_dns_proxy_key_t *key,unsigned transport,
  const uint8_t *wire,size_t length,uint64_t now)
{
  assert(!context&&key->generation==323&&transport==PRODUCT_DNS_PROXY_DOH&&now);
  assert(length==sizeof(question)&&wire[2]==0x81&&wire[3]==0x80);
  assert(!memcmp(wire+12,question+12,length-12));++answers;
}
static void failed(void *context,const product_dns_proxy_key_t *key,uint64_t now)
{assert(!context&&key->generation==323&&now);++failures;}

/* argv: family port host trust expect http_error http_status alpn age [cancel | bootstrap PORT] */
int main(int argc,char **argv)
{
  assert(argc==10||argc==11||argc==12);
  unsigned family=atoi(argv[1]),port=atoi(argv[2]);
  const char *host=argv[3],*expect=argv[5];
  unsigned want_error=atoi(argv[6]),want_status=atoi(argv[7]),want_alpn=atoi(argv[8]);
  uint32_t want_age=(uint32_t)strtoul(argv[9],NULL,10);
  int cancel=argc==11&&!strcmp(argv[10],"cancel");
  int bootstrap=argc==12&&!strcmp(argv[10],"bootstrap");
  if(bootstrap)bootstrap_port=atoi(argv[11]);
  product_dns_proxy_route_t route={.enabled=1,.family=bootstrap?0:family,.port=port,
    .endpoint_count=1,.route_count=1,.routes={{.count=1}},.endpoints={{.transport=PRODUCT_DNS_PROXY_DOH}}};
  if(!bootstrap)assert(inet_pton(family==4?AF_INET:AF_INET6,family==4?"127.0.0.1":"::1",route.address)==1);
  route.endpoints[0].family=route.family;route.endpoints[0].port=port;
  memcpy(route.endpoints[0].address,route.address,16);
  /* "host NUL path": only the host is the TLS service identity. */
  size_t host_length=strlen(host);
  memcpy(route.endpoints[0].identity,host,host_length);
  memcpy(route.endpoints[0].identity+host_length+1,"/dns-query",10);
  product_root_dns_io_callbacks_t callbacks={.watch=watch,.answer=answer,.failed=failed,
    .progress=progress,.trust_directory=argv[4],.bootstrap_network=bootstrap?original_network:NULL};
  uint64_t sequence=0,now=monotonic_us(),end=now+3000000;
  assert(product_root_dns_io_config_reservation(&route)<=product_root_dns_io_reservation());
  product_root_dns_io_t *io=product_root_dns_io_open(323,&route,0,&sequence,&callbacks,NULL,now);
  assert(io);
  product_root_dns_io_status_t opened=product_root_dns_io_status(io);
  uint64_t baseline=non_tls(&opened);
  product_dns_proxy_key_t key={.generation=323,.token=1,.incarnation=1,.attempt=1,
    .network_revision=1,.route_revision=1,.resolver_family=route.family,.resolver_port=port,.resolver_id=1};
  memcpy(key.resolver_address,route.address,16);
  assert(product_root_dns_io_send(io,&key,PRODUCT_DNS_PROXY_DOH,question,sizeof(question),end,now)==1);
  while(!answers&&!failures&&(now=monotonic_us())<end){
    struct pollfd fds[8];watch_t saved[8];unsigned count=0;
    for(unsigned i=0;i<8;++i)if(watches[i].events){
      saved[count]=watches[i];fds[count++]=(struct pollfd){.fd=watches[i].fd,
        .events=((watches[i].events&1)?POLLIN:0)|((watches[i].events&2)?POLLOUT:0)};
    }
    assert(poll(fds,count,10)>=0);
    for(unsigned i=0;i<count;++i)if(fds[i].revents){
      unsigned events=((fds[i].revents&POLLIN)?1:0)|((fds[i].revents&POLLOUT)?2:0)|
        ((fds[i].revents&(POLLERR|POLLNVAL))?4:0);
      product_root_dns_io_ready(io,323,saved[i].cookie,saved[i].fd,events,monotonic_us());
    }
    product_root_dns_io_expire(io,monotonic_us());
    if(cancel&&product_root_dns_io_status(io).tcp_sent){
      /* The request is on the wire and the response is pending: cancel, then old
       * generation and stale cookie events must neither answer nor fail. */
      assert(product_root_dns_io_status(io).tls_verified);
      product_root_dns_io_cancel(io,&key);
      for(unsigned i=0;i<count;++i){
        product_root_dns_io_ready(io,322,saved[i].cookie,saved[i].fd,3,monotonic_us());
        product_root_dns_io_ready(io,323,saved[i].cookie,saved[i].fd,3,monotonic_us());
      }
      assert(!answers&&!failures);
      assert_released(io,baseline);
      product_root_dns_io_close(io);
      puts("cancelled");return 0;
    }
  }
  assert(!cancel);
  if(!strcmp(expect,"answer")){
    assert(answers==1&&!failures);
    assert(last.tls==PRODUCT_DNS_TLS_AUTHENTICATED&&!last.http_error);
    if(bootstrap)assert(last.bootstrap==PRODUCT_DNS_BOOTSTRAP_RESOLVED&&last.bootstrap_family==4&&last.connection_family==4);
    else assert(last.bootstrap==PRODUCT_DNS_BOOTSTRAP_NONE);
  }else{
    assert(failures==1&&!answers&&progress_calls);
    assert(last.tls==PRODUCT_DNS_TLS_FAILED||last.tls==PRODUCT_DNS_TLS_AUTHENTICATED||last.tls==PRODUCT_DNS_TLS_HANDSHAKING);
  }
  if(last.http_error!=want_error||last.http_status!=want_status||last.alpn!=want_alpn||last.http_age!=want_age){
    fprintf(stderr,"http_error=%u/%u status=%u/%u alpn=%u/%u age=%u/%u tls=%u\n",last.http_error,want_error,
      last.http_status,want_status,last.alpn,want_alpn,last.http_age,want_age,last.tls);
    abort();
  }
  assert(product_root_dns_io_status(io).allocated_bytes<=product_root_dns_io_reservation());
  product_root_dns_io_cancel(io,&key);
  assert_released(io,baseline);
  assert(product_root_dns_io_status(io).tls_bytes-opened.tls_bytes<=4096);
  product_root_dns_io_close(io);
  printf("%s http_error=%u http_status=%u alpn=%u age=%u\n",expect,last.http_error,last.http_status,last.alpn,last.http_age);
  return 0;
}
