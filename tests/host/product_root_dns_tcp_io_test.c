/* SPDX-License-Identifier: Apache-2.0 */
#include "product_root_dns_tcp_io.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct { int fd; unsigned events; uint64_t cookie; } watch_t;
static watch_t watches[16];
static product_root_dns_tcp_io_t *io;
static uint64_t session, sessions[8], tokens[129], query_sessions[129], sequence;
static unsigned accepted_count;
static unsigned queries, deliveries, failures, ends;
static unsigned mode;
static unsigned fail_output_malloc;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t bytes) {
  if(fail_output_malloc && bytes==65537) { --fail_output_malloc;errno=ENOMEM;return NULL; }
  return __real_malloc(bytes);
}
static int watch(void *ctx,int fd,unsigned events,uint64_t cookie) {
  (void)ctx; unsigned slot=16;
  for(unsigned i=0;i<16;++i)if(watches[i].events&&watches[i].fd==fd){slot=i;break;}
  if(slot==16)for(unsigned i=0;i<16;++i)if(!watches[i].events){slot=i;break;}
  assert(slot<16);
  if(events && cookie==session) {
    int bytes=4096;assert(!setsockopt(fd,SOL_SOCKET,SO_SNDBUF,&bytes,sizeof(bytes)));
    if(mode==3)return 0;
  }
  watches[slot]=(watch_t){fd,events,cookie};return 1;
}
static int accepted(void *ctx,uint64_t id,const product_root_dns_tcp_endpoint_t *ep) {
  (void)ctx;assert(ep->family==4&&ep->source_port&&ep->saved_syn);
  assert(ep->resolver_address[0]==127&&ep->resolver_port);
  assert(accepted_count<8);sessions[accepted_count++]=id;session=id;return 1;
}
static void query(void *ctx,uint64_t id,uint64_t token,const uint8_t *data,size_t len,uint64_t now) {
  (void)ctx;(void)now;unsigned found=0;
  for(unsigned i=0;i<accepted_count;++i)found|=id==sessions[i];
  assert(found&&queries<129&&len==3&&data[0]==0x12&&data[1]==0x34);
  tokens[queries]=token;query_sessions[queries++]=id;
  if(mode==2 || mode==6) {
    uint8_t answer[8000];memset(answer,0x63,sizeof(answer));
    answer[0]=0x12;answer[1]=0x34;answer[2]=data[2];
    assert(product_root_dns_tcp_io_reply(io,id,token,answer,sizeof(answer),now));
  }
}
static void delivered(void *ctx,uint64_t token,int success) {
  (void)ctx;assert(token);if(success)++deliveries;else {assert(mode==7);++failures;}
}
static void ended(void *ctx,uint64_t id,uint64_t now) {
  (void)ctx;(void)now;unsigned found=0;
  for(unsigned i=0;i<accepted_count;++i)found|=id==sessions[i];
  assert(found);++ends;
}
static void pump(uint64_t now) {
  for(unsigned pass=0;pass<8;++pass) {
    watch_t saved[16];memcpy(saved,watches,sizeof(saved));
    for(unsigned i=0;i<16;++i)if(saved[i].events) {
      struct pollfd p={saved[i].fd,POLLIN|((saved[i].events&2)?POLLOUT:0),0};
      assert(poll(&p,1,pass==0?10:0)>=0);
      if(p.revents)product_root_dns_tcp_io_ready(io,317,saved[i].cookie,p.fd,
        ((p.revents&(POLLIN|POLLHUP))?1:0)|((p.revents&POLLOUT)?2:0)|((p.revents&(POLLERR|POLLNVAL))?4:0),now);
    }
    product_root_dns_tcp_io_expire(io,now);
  }
}
int main(int argc,char **argv) {
  mode=argc>1?(unsigned)atoi(argv[1]):0;
  product_root_dns_tcp_callbacks_t cb={watch,accepted,query,delivered,ended};
  io=product_root_dns_tcp_io_open(317,0,&sequence,&cb,NULL,100);
  if(!io)perror("Root TCP listener");
  assert(io);uint16_t port=product_root_dns_tcp_io_status(io).port;assert(port);
  int client=socket(AF_INET,SOCK_STREAM,0);assert(client>=0);
  struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(port)};
  address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  assert(!connect(client,(struct sockaddr*)&address,sizeof(address)));pump(101);if(!session)fprintf(stderr,"accept rejected=%llu error=%d\n",(unsigned long long)product_root_dns_tcp_io_status(io).rejected,product_root_dns_tcp_io_status(io).last_error);assert(session);
  if(mode==7) {
    int clients[9]={client};
    for(unsigned i=1;i<9;++i) {
      clients[i]=socket(AF_INET,SOCK_STREAM,0);assert(clients[i]>=0);
      assert(!connect(clients[i],(struct sockaddr*)&address,sizeof(address)));pump(101);
    }
    product_root_dns_tcp_status_t s=product_root_dns_tcp_io_status(io);
    assert(accepted_count==8 && s.clients==8 && s.high_water_clients==8 && s.rejected==1);
    uint8_t frames[200];for(unsigned i=0;i<40;++i)
      memcpy(frames+5*i,(uint8_t[]){0,3,0x12,0x34,(uint8_t)i},5);
    assert(write(clients[7],frames,sizeof(frames))==sizeof(frames));
    for(unsigned tick=102;tick<106 && queries<40;++tick)pump(tick);
    assert(queries==40 && product_root_dns_tcp_io_status(io).pending==40);
    uint8_t answer[65535];memset(answer,0x63,sizeof(answer));unsigned queued=0;int result=1;
    while(queued<40 && (result=product_root_dns_tcp_io_reply(io,session,tokens[queued],answer,sizeof(answer),106))==1)++queued;
    s=product_root_dns_tcp_io_status(io);
    assert(queued>0 && queued<40 && result==-1 && !failures && !deliveries && !ends);
    assert(s.clients==8 && s.pending==40-queued && s.outputs==queued && s.capacity==1);
    assert(s.high_water_bytes<=PRODUCT_ROOT_DNS_TCP_WORK_BYTES &&
      s.high_water_bytes>PRODUCT_ROOT_DNS_TCP_WORK_BYTES-sizeof(answer)-2);
    for(unsigned i=queued;i<40;++i) {
      uint8_t fallback[]={0x12,0x34,(uint8_t)i};
      assert(product_root_dns_tcp_io_reply(io,session,tokens[i],fallback,sizeof(fallback),107)==1);
    }
    size_t total=(size_t)queued*(sizeof(answer)+2)+(40-queued)*5U,got=0;
    uint8_t *received=malloc(total);assert(received);
    for(unsigned tick=108;tick<20108 && got<total;++tick) {
      pump(tick);ssize_t n=recv(clients[7],received+got,total-got,MSG_DONTWAIT);
      if(n>0)got+=(size_t)n;else {
        assert(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
        struct pollfd ready={clients[7],POLLIN,0};assert(poll(&ready,1,100)>=0);
      }
    }
    assert(got==total && deliveries==40 && !failures && !ends);
    size_t at=0;for(unsigned i=0;i<queued;++i) {
      assert(received[at]==0xff && received[at+1]==0xff);
      assert(!memcmp(received+at+2,answer,sizeof(answer)));at+=sizeof(answer)+2;
    }
    for(unsigned i=queued;i<40;++i) {
      uint8_t expected[]={0,3,0x12,0x34,(uint8_t)i};
      assert(!memcmp(received+at,expected,sizeof(expected)));at+=sizeof(expected);
    }
    assert(at==total);free(received);
    product_root_dns_tcp_io_quiesce(io,20108);pump(20109);
    s=product_root_dns_tcp_io_status(io);assert(!s.clients&&!s.sockets&&!s.pending&&!s.outputs&&ends==8);
    for(unsigned i=0;i<9;++i)close(clients[i]);
    product_root_dns_tcp_io_close(io,20110);for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP 2MiB ceiling preserves independent queued and fallback replies: PASS");return 0;
  }
  if(mode==12) {
    assert(write(client,(uint8_t[]){0,3,0x12,0x34,1,0,3,0x12,0x34,2},10)==10);
    pump(102);assert(queries==2 && !ends);
    uint8_t large[65535];memset(large,0x63,sizeof(large));fail_output_malloc=1;
    assert(product_root_dns_tcp_io_reply(io,session,tokens[0],large,sizeof(large),103)==-1);
    product_root_dns_tcp_status_t s=product_root_dns_tcp_io_status(io);
    assert(!fail_output_malloc && s.clients==1 && s.pending==2 && !ends && !deliveries);
    assert(product_root_dns_tcp_io_reply(io,session,tokens[0],(uint8_t[]){0x12,0x34,0x81},3,104)==1);
    assert(product_root_dns_tcp_io_reply(io,session,tokens[1],(uint8_t[]){0x12,0x34,0x82},3,104)==1);
    pump(105);uint8_t reply[10];size_t got=0;
    while(got<sizeof(reply)) {
      ssize_t n=recv(client,reply+got,sizeof(reply)-got,0);assert(n>0);got+=(size_t)n;
    }
    assert(!memcmp(reply,(uint8_t[]){0,3,0x12,0x34,0x81,0,3,0x12,0x34,0x82},10));
    assert(deliveries==2 && !failures && !ends);
    close(client);pump(106);assert(ends==1);
    product_root_dns_tcp_io_close(io,107);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP one real output malloc failure preserves both independent replies: PASS");return 0;
  }
  if(mode==13) {
    assert(write(client,(uint8_t[]){0,3,0x12,0x34,1,0,3,0x12,0x34,2},10)==10);
    pump(102);assert(queries==2 && !ends);
    assert(!product_root_dns_tcp_io_abandon(io,session+1,tokens[0],103));
    assert(product_root_dns_tcp_io_abandon(io,session,tokens[0],103)==1);
    assert(!product_root_dns_tcp_io_abandon(io,session,tokens[0],103));
    assert(product_root_dns_tcp_io_status(io).pending==1 && !ends);
    assert(product_root_dns_tcp_io_reply(io,session,tokens[1],(uint8_t[]){0x12,0x34,0x82},3,104)==1);
    pump(105);uint8_t reply[5];assert(read(client,reply,sizeof(reply))==5);
    assert(!memcmp(reply,(uint8_t[]){0,3,0x12,0x34,0x82},5));
    assert(deliveries==1 && !failures && !ends && !product_root_dns_tcp_io_status(io).pending);
    close(client);pump(106);assert(ends==1);
    product_root_dns_tcp_io_close(io,107);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP undeliverable token retires once without affecting another request: PASS");return 0;
  }
  if(mode==8) {
    uint8_t frames[129*5];for(unsigned i=0;i<129;++i)
      memcpy(frames+5*i,(uint8_t[]){0,3,0x12,0x34,(uint8_t)i},5);
    assert(write(client,frames,sizeof(frames))==sizeof(frames));
    assert(!shutdown(client,SHUT_WR));
    product_root_dns_tcp_status_t s=product_root_dns_tcp_io_status(io);
    for(unsigned tick=102;tick<120 && !s.capacity && !ends;++tick) {
      pump(tick);s=product_root_dns_tcp_io_status(io);
    }
    /* The complete 129th frame waits within the existing bounded input buffer;
     * it must not close the stream or cancel the 128 accepted obligations. */
    assert(queries==128 && s.frames==128 && !ends && s.clients==1 && s.pending==128);
    assert(!s.outputs&&!deliveries&&!failures && s.capacity==1);
    for(unsigned i=0;i<128;++i) {
      uint8_t answer[]={0x12,0x34,(uint8_t)i};
      assert(product_root_dns_tcp_io_reply(io,session,tokens[i],answer,sizeof(answer),120));
    }
    for(unsigned tick=121;tick<150 && queries<129;++tick)pump(tick);
    assert(queries==129 && !ends && deliveries==128);
    assert(product_root_dns_tcp_io_reply(io,session,tokens[128],(uint8_t[]){0x12,0x34,128},3,150));
    uint8_t replies[129*5];size_t got=0;
    for(unsigned tick=151;tick<250 && got<sizeof(replies);++tick) {
      pump(tick);ssize_t n=recv(client,replies+got,sizeof(replies)-got,MSG_DONTWAIT);
      if(n>0)got+=(size_t)n;else {
        assert(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
        struct pollfd ready={client,POLLIN,0};assert(poll(&ready,1,100)>=0);
      }
    }
    assert(got==sizeof(replies) && deliveries==129 && ends==1 && !failures);
    assert(!memcmp(replies,frames,sizeof(frames)));
    close(client);pump(250);assert(ends==1);
    product_root_dns_tcp_io_close(io,251);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP 128 pending obligations survive a bounded 129th frame and all 129 replies drain: PASS");return 0;
  }
  if(mode==9 || mode==11) {
    uint8_t frames[129*5];for(unsigned i=0;i<129;++i)
      memcpy(frames+5*i,(uint8_t[]){0,3,0x12,0x34,(uint8_t)i},5);
    assert(write(client,frames,sizeof(frames))==sizeof(frames));
    product_root_dns_tcp_status_t s=product_root_dns_tcp_io_status(io);
    for(unsigned tick=102;tick<120 && !s.capacity && !ends;++tick) {
      pump(tick);s=product_root_dns_tcp_io_status(io);
    }
    assert(queries==128 && s.pending==128 && s.clients==1 && s.capacity==1 && !ends);
    assert(product_root_dns_tcp_io_deadline(io)>1000); /* No busy retry or false partial-frame expiry. */
    pump(1000);s=product_root_dns_tcp_io_status(io);
    assert(s.pending==128 && s.clients==1 && !ends);
    if(mode==9) {
      struct linger reset={1,0};assert(!setsockopt(client,SOL_SOCKET,SO_LINGER,&reset,sizeof(reset)));
      close(client);pump(1001);s=product_root_dns_tcp_io_status(io);
      assert(ends==1 && !s.clients && !s.pending && queries==128 && !deliveries);
      product_root_dns_tcp_io_close(io,1002);
      for(unsigned i=0;i<16;++i)assert(!watches[i].events);
      puts("Root TCP blocked full frame retains RST watch and retires accepted work once: PASS");return 0;
    }
    product_root_dns_tcp_io_quiesce(io,1001);
    for(unsigned i=0;i<128;++i) {
      uint8_t answer[]={0x12,0x34,(uint8_t)i};
      assert(product_root_dns_tcp_io_reply(io,session,tokens[i],answer,sizeof(answer),1002));
    }
    uint8_t replies[128*5];size_t got=0;
    for(unsigned tick=1003;tick<1100 && got<sizeof(replies);++tick) {
      pump(tick);ssize_t n=recv(client,replies+got,sizeof(replies)-got,MSG_DONTWAIT);
      if(n>0)got+=(size_t)n;else {
        assert(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
        struct pollfd ready={client,POLLIN,0};assert(poll(&ready,1,100)>=0);
      }
    }
    s=product_root_dns_tcp_io_status(io);
    assert(got==sizeof(replies) && !memcmp(replies,frames,sizeof(replies)));
    assert(queries==128 && deliveries==128 && ends==1 && !s.clients && !s.pending && !s.outputs && !s.sockets);
    close(client);product_root_dns_tcp_io_close(io,1101);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP Stop discards only unadmitted full frame and drains all accepted replies: PASS");return 0;
  }
  if(mode==10) {
    uint8_t frames[128*5];for(unsigned i=0;i<128;++i)
      memcpy(frames+5*i,(uint8_t[]){0,3,0x12,0x34,(uint8_t)i},5);
    assert(write(client,frames,sizeof(frames))==sizeof(frames));
    for(unsigned tick=102;tick<120 && queries<128;++tick)pump(tick);
    assert(queries==128 && product_root_dns_tcp_io_status(io).pending==128);
    int other=socket(AF_INET,SOCK_STREAM,0);assert(other>=0);
    assert(!connect(other,(struct sockaddr*)&address,sizeof(address)));pump(120);
    assert(accepted_count==2 && sessions[0]!=sessions[1]);
    assert(write(other,(uint8_t[]){0,3,0x12,0x34,0x80},5)==5);
    product_root_dns_tcp_status_t s=product_root_dns_tcp_io_status(io);
    for(unsigned tick=121;tick<140 && !s.capacity;++tick) {
      pump(tick);s=product_root_dns_tcp_io_status(io);
    }
    assert(s.capacity==1 && s.clients==2 && s.pending==128 && queries==128 && !ends);
    assert(product_root_dns_tcp_io_reply(io,sessions[0],tokens[0],(uint8_t[]){0x12,0x34,0},3,140));
    for(unsigned tick=141;tick<160 && queries<129;++tick)pump(tick);
    assert(queries==129 && query_sessions[128]==sessions[1] && deliveries==1 && !ends);
    assert(product_root_dns_tcp_io_reply(io,sessions[1],tokens[128],(uint8_t[]){0x12,0x34,0x80},3,160));
    pump(161);uint8_t reply[5];assert(read(other,reply,sizeof(reply))==5);
    assert(!memcmp(reply,(uint8_t[]){0,3,0x12,0x34,0x80},5));
    close(other);close(client);pump(162);
    s=product_root_dns_tcp_io_status(io);assert(ends==2 && !s.clients && !s.pending && !s.outputs);
    product_root_dns_tcp_io_close(io,163);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP output slot freed by one client resumes a blocked different client: PASS");return 0;
  }
  if(mode==5) {
    assert(write(client,(uint8_t[]){0,3,0x12,0x34,1},5)==5);
    assert(!shutdown(client,SHUT_WR));pump(102);assert(queries==1 && !ends);
    assert(product_root_dns_tcp_io_status(io).pending==1);
    struct linger reset={1,0};assert(!setsockopt(client,SOL_SOCKET,SO_LINGER,&reset,sizeof(reset)));
    close(client);pump(103);
    assert(ends==1 && !product_root_dns_tcp_io_status(io).clients && !product_root_dns_tcp_io_status(io).pending);
    product_root_dns_tcp_io_close(io,104);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP FIN then real RST cancels once before query deadline: PASS");return 0;
  }
  if(mode==3) {
    assert(ends==1 && !queries && !product_root_dns_tcp_io_status(io).clients);
    assert(product_root_dns_tcp_io_status(io).capacity==1);
    close(client);product_root_dns_tcp_io_close(io,110);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts("Root TCP failed client watch retires exact session and all resources: PASS");return 0;
  }
  if(mode==2 || mode==6) {
    uint8_t frames[200];
    for(unsigned i=0;i<40;++i)memcpy(frames+5*i,(uint8_t[]){0,3,0x12,0x34,(uint8_t)i},5);
    assert(write(client,frames,sizeof(frames))==sizeof(frames));
    for(unsigned tick=102;tick<112;++tick)pump(tick);
    assert(queries==40 && product_root_dns_tcp_io_status(io).outputs>0);
    for(unsigned i=1;i<40;++i)assert(tokens[i]!=tokens[i-1]);
    if(mode==6) {
      product_root_dns_tcp_status_t before=product_root_dns_tcp_io_status(io);
      product_root_dns_tcp_io_quiesce(io,112);
      assert(!product_root_dns_tcp_io_status(io).accepting);
      assert(product_root_dns_tcp_io_status(io).outputs==before.outputs);
      assert(product_root_dns_tcp_io_resume(io,113));
      assert(product_root_dns_tcp_io_status(io).accepting);
      int fresh=socket(AF_INET,SOCK_STREAM,0);assert(fresh>=0);
      assert(!connect(fresh,(struct sockaddr*)&address,sizeof(address)));pump(114);
      assert(accepted_count==2 && sessions[0]!=sessions[1]);
      assert(write(fresh,(uint8_t[]){0,3,0x12,0x34,0x7f},5)==5);
      pump(115);assert(queries==41);
      uint8_t reply[8002];size_t received=0;
      while(received<sizeof(reply)) {
        ssize_t n=recv(fresh,reply+received,sizeof(reply)-received,MSG_DONTWAIT);
        if(n>0)received+=(size_t)n;
        else {assert(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK));pump(116);}
      }
      assert(!memcmp(reply,(uint8_t[]){0x1f,0x40,0x12,0x34,0x7f},5));
      assert(product_root_dns_tcp_io_status(io).outputs>0);
      close(fresh);pump(117);
    }
    size_t total=40U*8002U,got=0;uint8_t *answer=malloc(total);assert(answer);
    assert(!shutdown(client,SHUT_WR));
    for(unsigned tick=112;tick<10112 && got<total;++tick) {
      pump(tick);ssize_t n=recv(client,answer+got,total-got,MSG_DONTWAIT);
      if(n>0)got+=(size_t)n;
      else assert(n<0 && (errno==EAGAIN || errno==EWOULDBLOCK));
    }
    assert(got==total);pump(10113);assert(deliveries==(mode==6?41U:40U) && ends==(mode==6?2U:1U));
    for(unsigned i=0;i<40;++i) {
      assert(!memcmp(answer+8002*i,(uint8_t[]){0x1f,0x40,0x12,0x34,(uint8_t)i},5));
      for(unsigned j=5;j<8002;++j)assert(answer[8002*i+j]==0x63);
    }
    free(answer);close(client);product_root_dns_tcp_io_close(io,10114);
    for(unsigned i=0;i<16;++i)assert(!watches[i].events);
    puts(mode==6?"Root TCP off/on resumes fresh listeners while old blocked output drains byte-exactly: PASS":"Root TCP >16 coalesced frames progress while writes block, then byte-exact drain: PASS");return 0;
  }
  /* Split length header, then two coalesced requests reusing the same DNS ID. */
  assert(write(client,(uint8_t[]){0},1)==1);pump(102);assert(!queries);
  assert(write(client,(uint8_t[]){3,0x12,0x34,1,0,3,0x12,0x34,2},9)==9);
  if(mode==1)assert(write(client,(uint8_t[]){0},1)==1);
  assert(!shutdown(client,SHUT_WR));pump(103);assert(queries==2&&!ends&&tokens[0]!=tokens[1]);
  if(mode==1)assert(product_root_dns_tcp_io_status(io).partial_expired==1);
  assert(product_root_dns_tcp_io_reply(io,session,tokens[1],(uint8_t[]){0x12,0x34,0x82},3,104));
  assert(product_root_dns_tcp_io_reply(io,session,tokens[0],(uint8_t[]){0x12,0x34,0x81},3,104));
  pump(105);uint8_t result[10];size_t got=0;
  while(got<sizeof(result)){ssize_t n=read(client,result+got,sizeof(result)-got);assert(n>0);got+=n;}
  assert(!memcmp(result,(uint8_t[]){0,3,0x12,0x34,0x82,0,3,0x12,0x34,0x81},10));
  assert(deliveries==2&&ends==1&&!product_root_dns_tcp_io_status(io).clients);
  assert(!product_root_dns_tcp_io_reply(io,session,tokens[0],result,10,106));
  close(client);product_root_dns_tcp_io_close(io,107);
  for(unsigned i=0;i<16;++i)assert(!watches[i].events);
  puts("Root local TCP split/coalesced frames, same-ID out-of-order replies and half-close: PASS");
}
