/* SPDX-License-Identifier: Apache-2.0 */
#include "product_root_dns_tcp_io.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef TCP_SAVE_SYN
#define TCP_SAVE_SYN 27
#define TCP_SAVED_SYN 28
#endif

typedef struct {
  int fd;
  uint64_t cookie, partial_deadline, idle_deadline, read_resume, write_resume;
  size_t used;
  uint8_t eof;
  uint8_t input[PRODUCT_DNS_MESSAGE_MAX + 2U];
} tcp_client_t;
typedef struct {
  uint64_t token, session, deadline;
  uint8_t *wire;
  size_t length, sent;
  uint64_t order;
  uint8_t active;
} tcp_output_t;
struct product_root_dns_tcp_io {
  uint64_t generation;
  uint8_t product_listener;
  uint64_t *sequence;
  uint64_t order;
  int listener[2];
  uint64_t listener_cookie[2];
  product_root_dns_tcp_callbacks_t callbacks;
  void *context;
  tcp_client_t clients[PRODUCT_ROOT_DNS_TCP_CLIENTS];
  tcp_output_t outputs[PRODUCT_ROOT_DNS_TCP_OUTPUTS];
  product_root_dns_tcp_status_t status;
};
static uint16_t be16(const uint8_t *p) { return (uint16_t)p[0] << 8 | p[1]; }
static uint32_t be32(const uint8_t *p)
{ return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static uint64_t cookie(product_root_dns_tcp_io_t *io)
{ return *io->sequence < (UINT64_C(1) << 42) - 1 ? ++*io->sequence : 0; }
static int watch_client(product_root_dns_tcp_io_t *io, tcp_client_t *client)
{
  /* Keep the ET subscription after FIN while upstream work remains: a later
   * terminal RST must cancel promptly. Repeated EOF is not a new edge. */
  unsigned events = PRODUCT_ROOT_DNS_READ;
  for (unsigned i=0; i<PRODUCT_ROOT_DNS_TCP_OUTPUTS; ++i)
    if (io->outputs[i].active && io->outputs[i].session==client->cookie && io->outputs[i].wire)
      { events |= PRODUCT_ROOT_DNS_WRITE; break; }
  return io->callbacks.watch(io->context, client->fd, events ? events | PRODUCT_ROOT_DNS_TCP_EDGE : 0, client->cookie);
}
static void release_output(product_root_dns_tcp_io_t *io, tcp_output_t *output, int success)
{
  uint64_t token=output->token;
  int queued=output->wire!=NULL;
  io->status.allocated_bytes-=output->length;
  free(output->wire); memset(output,0,sizeof(*output));
  if (queued) {
    --io->status.outputs;
    if (success) ++io->status.delivered; else ++io->status.write_failed;
    io->callbacks.delivered(io->context,token,success);
  } else --io->status.pending;
}
static void close_client(product_root_dns_tcp_io_t *io, tcp_client_t *client, uint64_t now)
{
  uint64_t session=client->cookie;
  if (client->fd<0) return;
  io->callbacks.watch(io->context,client->fd,0,session);
  close(client->fd);
  memset(client,0,sizeof(*client)); client->fd=-1;
  --io->status.clients; --io->status.sockets; ++io->status.closed;
  /* Retire the socket before cancellation can synchronously call reply. */
  io->callbacks.ended(io->context,session,now);
  for (unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++i)
    if (io->outputs[i].active && io->outputs[i].session==session)
      release_output(io,&io->outputs[i],0);
}
static int arm_client(product_root_dns_tcp_io_t *io,tcp_client_t *client,uint64_t now)
{
  if(watch_client(io,client))return 1;
  io->status.last_error=errno?errno:ENOMEM; ++io->status.capacity;
  close_client(io,client,now);return 0;
}
static int session_pending(const product_root_dns_tcp_io_t *io, uint64_t session)
{
  for (unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++i)
    if (io->outputs[i].active && io->outputs[i].session==session) return 1;
  return 0;
}
static int endpoint(int fd, unsigned family, product_root_dns_tcp_endpoint_t *endpoint)
{
  struct sockaddr_storage peer={0}, original={0};
  socklen_t size=sizeof(peer);
  if (getpeername(fd,(struct sockaddr *)&peer,&size)) return 0;
  size=sizeof(original);
  if (family==4) {
    if (getsockopt(fd,SOL_IP,80,&original,&size)) return 0;
  } else if (getsockname(fd,(struct sockaddr *)&original,&size)) return 0;
  endpoint->family=family;
  if (family==4) {
    const struct sockaddr_in *p=(const void *)&peer,*o=(const void *)&original;
    if (p->sin_family!=AF_INET || o->sin_family!=AF_INET) return 0;
    memcpy(endpoint->source_address,&p->sin_addr,4);
    memcpy(endpoint->resolver_address,&o->sin_addr,4);
    endpoint->source_port=ntohs(p->sin_port); endpoint->resolver_port=ntohs(o->sin_port);
  } else {
    const struct sockaddr_in6 *p=(const void *)&peer,*o=(const void *)&original;
    if (p->sin6_family!=AF_INET6 || o->sin6_family!=AF_INET6) return 0;
    memcpy(endpoint->source_address,&p->sin6_addr,16);
    memcpy(endpoint->resolver_address,&o->sin6_addr,16);
    endpoint->source_port=ntohs(p->sin6_port); endpoint->resolver_port=ntohs(o->sin6_port);
  }
  /* Saved SYN from this kernel socket disambiguates same-tuple reconnects.
   * It is not a UID lookup or a guessed application identity. */
  uint8_t syn[512]; size=sizeof(syn);
  if (getsockopt(fd,IPPROTO_TCP,TCP_SAVED_SYN,syn,&size)) return 0;
  size_t at=0;
  if (size>=20 && (syn[0]>>4)==4) {
    at=(syn[0]&15)*4U;
    if (family!=4 || at<20 || syn[9]!=6 || (be16(syn+6)&0x3fff) ||
        memcmp(syn+12,endpoint->source_address,4)) return 0;
  } else if (size>=40 && (syn[0]>>4)==6) {
    if (family!=6 || memcmp(syn+8,endpoint->source_address,16)) return 0;
    at=40; uint8_t protocol=syn[6];
    while(protocol==0 || protocol==43 || protocol==60 || protocol==51) {
      if(at+2>size)return 0;
      size_t bytes=protocol==51?((size_t)syn[at+1]+2)*4:((size_t)syn[at+1]+1)*8;
      if(bytes>size-at)return 0;
      protocol=syn[at];at+=bytes;
    }
    if(protocol!=6)return 0;
  } else return 0;
  if (at+20>size || be16(syn+at)!=endpoint->source_port || !(syn[at+13]&2)) return 0;
  endpoint->syn_sequence=be32(syn+at+4); endpoint->saved_syn=1;
  return 1;
}
static void accept_clients(product_root_dns_tcp_io_t *io, unsigned listener, uint64_t now)
{
  for (unsigned budget=0;budget<16;++budget) {
    int fd=accept4(io->listener[listener],NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
    if (fd<0) { if(errno==EINTR) continue; break; }
    product_root_dns_tcp_endpoint_t peer={0};
    tcp_client_t *client=NULL;
    for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i)
      if(io->clients[i].fd<0){client=&io->clients[i];break;}
    uint64_t id=cookie(io);
    if (!client || !id || !endpoint(fd,listener?6:4,&peer) ||
        !io->callbacks.accepted(io->context,id,&peer)) {
      io->status.last_error=errno; close(fd); ++io->status.rejected; continue;
    }
    memset(client,0,sizeof(*client));client->fd=fd;client->cookie=id;
    client->idle_deadline=now+PRODUCT_ROOT_DNS_IDLE_US;
    ++io->status.accepted; ++io->status.clients; ++io->status.sockets;
    if(io->status.clients>io->status.high_water_clients)io->status.high_water_clients=io->status.clients;
    arm_client(io,client,now);
  }
}
static void write_client(product_root_dns_tcp_io_t *io,tcp_client_t *client,uint64_t now)
{
  size_t written=0;
  for(unsigned budget=0;budget<16 && written<65536;++budget) {
    tcp_output_t *next=NULL;
    for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++i) {
      tcp_output_t *item=&io->outputs[i];
      if(item->active && item->wire && item->session==client->cookie &&
          (!next || item->order<next->order))next=item;
    }
    if(!next)break;
    size_t count=next->length-next->sent;
    if(count>65536-written)count=65536-written;
    ssize_t n=send(client->fd,next->wire+next->sent,count,MSG_DONTWAIT|MSG_NOSIGNAL);
    if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) { client->write_resume=0;break; }
    if(n<0 && errno==EINTR)continue;
    if(n<=0){close_client(io,client,now);return;}
    written+=(size_t)n;next->sent+=(size_t)n;
    client->idle_deadline=now+PRODUCT_ROOT_DNS_IDLE_US;
    if(next->sent==next->length)release_output(io,next,1);
    client->write_resume=now+1;
  }
  if(client->eof && !session_pending(io,client->cookie)) {close_client(io,client,now);return;}
  arm_client(io,client,now);
}
static void read_client(product_root_dns_tcp_io_t *io,tcp_client_t *client,uint64_t now)
{
  unsigned frames=0,reads=0;
  while(frames<16 && reads<4) {
    if(client->used>=2) {
      size_t length=be16(client->input);
      if(client->used>=length+2) {
        tcp_output_t *request=NULL;
        for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++i)
          if(!io->outputs[i].active){request=&io->outputs[i];break;}
        uint64_t serial=cookie(io);
        if(!request || !serial) {
          ++io->status.capacity;close_client(io,client,now);return;
        }
        uint64_t token=UINT64_C(0x8000000000000000)|serial;
        *request=(tcp_output_t){.active=1,.session=client->cookie,.token=token,
          .deadline=now+PRODUCT_DNS_REQUEST_US};
        ++io->status.pending;++io->status.frames;++frames;
        client->partial_deadline=0;client->idle_deadline=now+PRODUCT_ROOT_DNS_IDLE_US;
        io->callbacks.query(io->context,client->cookie,token,client->input+2,length,now);
        if(client->fd<0)return;
        if(length<2 && request->active && !request->wire)release_output(io,request,0);
        client->used-=length+2;
        memmove(client->input,client->input+length+2,client->used);
        if(client->used)client->partial_deadline=now+PRODUCT_DNS_REQUEST_US;
        continue;
      }
    }
    if(client->eof)break;
    ssize_t n=recv(client->fd,client->input+client->used,sizeof(client->input)-client->used,MSG_DONTWAIT);
    ++reads;
    if(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK))break;
    if(n<0 && errno==EINTR)continue;
    if(n<0){close_client(io,client,now);return;}
    if(!n){client->eof=1;break;}
    if(!client->used)client->partial_deadline=now+PRODUCT_DNS_REQUEST_US;
    client->used+=(size_t)n;
  }
  if(client->eof && client->used) {
    /* A trailing incomplete frame cannot cancel already accepted requests. */
    ++io->status.partial_expired;client->used=0;client->partial_deadline=0;
  }
  client->read_resume=(frames==16 || reads==4)?now+1:0;
  if(client->eof && !session_pending(io,client->cookie)){close_client(io,client,now);return;}
  arm_client(io,client,now);
}
static int open_listeners(product_root_dns_tcp_io_t *io,uint16_t port)
{
  for(unsigned i=0;i<2;++i) {
    int family=i?AF_INET6:AF_INET;
    int fd=socket(family,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(fd<0)goto failed;
    io->listener[i]=fd;++io->status.sockets;
    int enabled=1;
    uint32_t mark=PRODUCT_ROOT_DNS_SOCKET_MARK;
    if(io->product_listener && setsockopt(fd,SOL_SOCKET,SO_MARK,&mark,sizeof(mark)))goto failed;
    if(io->product_listener && i && setsockopt(fd,IPPROTO_IPV6,75,&enabled,sizeof(enabled)))goto failed;
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&enabled,sizeof(enabled)) ||
        setsockopt(fd,IPPROTO_TCP,TCP_SAVE_SYN,&enabled,sizeof(enabled)))goto failed;
    if(i && setsockopt(fd,IPPROTO_IPV6,IPV6_V6ONLY,&enabled,sizeof(enabled)))goto failed;
    if(i) {
      struct sockaddr_in6 address={.sin6_family=AF_INET6,.sin6_port=htons(port)};
      if(bind(fd,(struct sockaddr*)&address,sizeof(address)))goto failed;
    } else {
      struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
      if(bind(fd,(struct sockaddr*)&address,sizeof(address)))goto failed;
      socklen_t length=sizeof(address);
      if(getsockname(fd,(struct sockaddr*)&address,&length))goto failed;
      port=ntohs(address.sin_port);io->status.port=port;
    }
    io->listener_cookie[i]=cookie(io);
    if(!io->listener_cookie[i] || listen(fd,PRODUCT_ROOT_DNS_TCP_CLIENTS) ||
        !io->callbacks.watch(io->context,fd,PRODUCT_ROOT_DNS_READ,io->listener_cookie[i]))goto failed;
  }
  io->status.accepting=1;return 1;
failed:
  io->status.last_error=errno?errno:EIO;
  for(unsigned i=0;i<2;++i)if(io->listener[i]>=0) {
    io->callbacks.watch(io->context,io->listener[i],0,io->listener_cookie[i]);
    close(io->listener[i]);io->listener[i]=-1;--io->status.sockets;
  }
  errno=io->status.last_error;return 0;
}
product_root_dns_tcp_io_t *product_root_dns_tcp_io_open(uint64_t generation,
  uint16_t port,uint64_t *sequence,const product_root_dns_tcp_callbacks_t *callbacks,void *context,uint64_t now)
{
  if(!generation || !sequence || !callbacks || !callbacks->watch || !callbacks->accepted ||
      !callbacks->query || !callbacks->delivered || !callbacks->ended)return NULL;
  product_root_dns_tcp_io_t *io=calloc(1,sizeof(*io));if(!io)return NULL;
  io->generation=generation;io->sequence=sequence;io->callbacks=*callbacks;io->context=context;
  io->product_listener=port!=0;
  for(unsigned i=0;i<2;++i)io->listener[i]=-1;
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i)io->clients[i].fd=-1;
  io->status.allocated_bytes=io->status.high_water_bytes=sizeof(*io);
  if(open_listeners(io,port))return io;
  int error=errno;product_root_dns_tcp_io_close(io,now);errno=error;return NULL;
}
int product_root_dns_tcp_io_resume(product_root_dns_tcp_io_t *io,uint64_t now)
{
  (void)now;
  return io && (io->status.accepting || open_listeners(io,io->status.port));
}
void product_root_dns_tcp_io_close(product_root_dns_tcp_io_t *io,uint64_t now)
{
  if(!io)return;
  for(unsigned i=0;i<2;++i)if(io->listener[i]>=0) {
    io->callbacks.watch(io->context,io->listener[i],0,io->listener_cookie[i]);close(io->listener[i]);
  }
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i)close_client(io,&io->clients[i],now);
  free(io);
}
void product_root_dns_tcp_io_quiesce(product_root_dns_tcp_io_t *io,uint64_t now)
{
  if(!io || !io->status.accepting)return;
  io->status.accepting=0;
  for(unsigned i=0;i<2;++i)if(io->listener[i]>=0) {
    io->callbacks.watch(io->context,io->listener[i],0,io->listener_cookie[i]);
    close(io->listener[i]);io->listener[i]=-1;--io->status.sockets;
  }
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i) {
    tcp_client_t *client=&io->clients[i];if(client->fd<0)continue;
    client->eof=1;client->used=0;client->partial_deadline=0;client->read_resume=0;
    client->write_resume=now;arm_client(io,client,now);
  }
}
int product_root_dns_tcp_io_ready(product_root_dns_tcp_io_t *io,uint64_t generation,
  uint64_t identity,int fd,unsigned events,uint64_t now)
{
  if(!io)return 0;
  if(generation!=io->generation){++io->status.stale;return 0;}
  for(unsigned i=0;i<2;++i)if(io->listener[i]==fd && io->listener_cookie[i]==identity) {
    if(events&PRODUCT_ROOT_DNS_READ)accept_clients(io,i,now);
    return 1;
  }
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i) {
    tcp_client_t *client=&io->clients[i];
    if(client->fd!=fd || client->cookie!=identity)continue;
    if(events&PRODUCT_ROOT_DNS_ERROR){close_client(io,client,now);return 1;}
    if(events&PRODUCT_ROOT_DNS_READ)read_client(io,client,now);
    if(client->fd>=0 && (events&PRODUCT_ROOT_DNS_WRITE))write_client(io,client,now);
    return 1;
  }
  return 0;
}
int product_root_dns_tcp_io_reply(product_root_dns_tcp_io_t *io,uint64_t session,
  uint64_t token,const uint8_t *wire,size_t length,uint64_t now)
{
  if(!io || !wire || length>PRODUCT_DNS_MESSAGE_MAX)return 0;
  tcp_client_t *client=NULL;tcp_output_t *request=NULL;
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i)
    if(io->clients[i].fd>=0 && io->clients[i].cookie==session){client=&io->clients[i];break;}
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++i)
    if(io->outputs[i].active && io->outputs[i].session==session && io->outputs[i].token==token)
      {request=&io->outputs[i];break;}
  if(!client || !request || request->wire){++io->status.stale;return 0;}
  if(length+2>PRODUCT_ROOT_DNS_TCP_WORK_BYTES-io->status.allocated_bytes || io->order==UINT64_MAX) {
    ++io->status.capacity;close_client(io,client,now);return 0;
  }
  uint8_t *copy=malloc(length+2);
  if(!copy){++io->status.capacity;close_client(io,client,now);return 0;}
  copy[0]=length>>8;copy[1]=length;memcpy(copy+2,wire,length);
  request->wire=copy;request->length=length+2;request->order=++io->order;
  --io->status.pending;++io->status.outputs;
  if(io->status.outputs>io->status.high_water_outputs)io->status.high_water_outputs=io->status.outputs;
  io->status.allocated_bytes+=length+2;
  if(io->status.allocated_bytes>io->status.high_water_bytes)io->status.high_water_bytes=io->status.allocated_bytes;
  client->write_resume=now+1;return arm_client(io,client,now);
}
void product_root_dns_tcp_io_expire(product_root_dns_tcp_io_t *io,uint64_t now)
{
  if(!io)return;
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i) {
    tcp_client_t *client=&io->clients[i];if(client->fd<0)continue;
    if((client->partial_deadline && client->partial_deadline<=now) ||
        (!session_pending(io,client->cookie) && client->idle_deadline<=now)) {
      io->status.partial_expired+=client->partial_deadline && client->partial_deadline<=now;
      close_client(io,client,now);continue;
    }
    int expired=0;
    for(unsigned j=0;j<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++j)
      if(io->outputs[j].active && io->outputs[j].session==client->cookie &&
          io->outputs[j].deadline<=now){expired=1;break;}
    if(expired){close_client(io,client,now);continue;}
    if(client->read_resume && client->read_resume<=now) {
      client->read_resume=0;read_client(io,client,now);
    }
    if(client->fd>=0 && client->write_resume && client->write_resume<=now) {
      client->write_resume=0;write_client(io,client,now);
    }
  }
}
uint64_t product_root_dns_tcp_io_deadline(const product_root_dns_tcp_io_t *io)
{
  uint64_t next=UINT64_MAX;if(!io)return next;
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_CLIENTS;++i) {
    const tcp_client_t *client=&io->clients[i];if(client->fd<0)continue;
    if(client->partial_deadline && client->partial_deadline<next)next=client->partial_deadline;
    if(client->read_resume && client->read_resume<next)next=client->read_resume;
    if(client->write_resume && client->write_resume<next)next=client->write_resume;
    if(!session_pending(io,client->cookie) && client->idle_deadline<next)next=client->idle_deadline;
  }
  for(unsigned i=0;i<PRODUCT_ROOT_DNS_TCP_OUTPUTS;++i)
    if(io->outputs[i].active && io->outputs[i].deadline<next)next=io->outputs[i].deadline;
  return next;
}
product_root_dns_tcp_status_t product_root_dns_tcp_io_status(const product_root_dns_tcp_io_t *io)
{return io?io->status:(product_root_dns_tcp_status_t){0};}
