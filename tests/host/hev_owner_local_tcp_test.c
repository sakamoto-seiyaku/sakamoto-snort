/* SPDX-License-Identifier: MIT */
#include "hev-owner.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  hev_owner_t *owner;
  uint64_t generation, session;
  uint32_t seq, ack;
  unsigned family, broker_calls, outputs, source, done, failed;
  uint64_t completed[128];
  uint8_t received[131074];size_t received_length;
  uint8_t packet[10000]; size_t length;
} fixture_t;
static uint16_t get16(const uint8_t *p) { return (uint16_t)p[0]<<8|p[1]; }
static uint32_t get32(const uint8_t *p) { return (uint32_t)get16(p)<<16|get16(p+2); }
static void put16(uint8_t *p,unsigned x) { p[0]=x>>8;p[1]=x; }
static void put32(uint8_t *p,uint32_t x) { put16(p,x>>16);put16(p+2,x); }
static uint32_t sum(const uint8_t *p,size_t n)
{ uint32_t s=0;while(n>1){s+=get16(p);p+=2;n-=2;}if(n)s+=(uint32_t)*p<<8;return s; }
static uint16_t checksum(uint32_t s) { while(s>>16)s=(s&65535)+(s>>16);return ~s; }
static void done(void *opaque,uint64_t generation,uint64_t session,uint64_t token,int success)
{
 fixture_t *f=opaque;assert(generation==f->generation && session && token);
 if(success){assert(f->done<128);f->completed[f->done++]=token;}else ++f->failed;
}
static int broker(void *opaque,uint64_t gen,uint64_t session,int fd)
{ fixture_t *f=opaque;(void)gen;(void)session;(void)fd;++f->broker_calls;return 0; }
static hev_owner_output_result_t output(void *opaque,const hev_owner_span_t *spans,
 unsigned count,size_t total,const hev_owner_facts_t *facts,uint64_t gen,uint64_t serial)
{
 fixture_t *f=opaque;assert(gen==f->generation && serial && total<=sizeof(f->packet));
 f->length=0;for(unsigned i=0;i<count;++i){memcpy(f->packet+f->length,spans[i].data,spans[i].length);f->length+=spans[i].length;}
 assert(f->length==total);assert(facts->uid==10001 && facts->flow_incarnation==71);
 f->session=facts->transport_session;++f->outputs;
 unsigned ip=f->family==6?40:20;unsigned h=(f->packet[ip+12]>>4)*4;
 if(total>ip+h) {
  assert(facts->local_reply_token && facts->underlay_epoch==99 && facts->network_context==7);
  assert(facts->availability&HEV_OWNER_CONTEXT_KNOWN);
  uint32_t seq=get32(f->packet+ip+4);size_t bytes=total-ip-h;
  assert(seq==f->ack && bytes<=sizeof(f->received)-f->received_length);
  memcpy(f->received+f->received_length,f->packet+ip+h,bytes);f->received_length+=bytes;f->ack+=bytes;
 }
 return HEV_OWNER_OUTPUT_ACCEPTED;
}
static hev_owner_input_result_t inject(fixture_t *f,unsigned flags,const uint8_t *data,size_t length)
{
 uint8_t p[10000]={0};unsigned ip=f->family==6?40:20;unsigned h=(flags&2)?24:20;size_t n=ip+h+length;
 uint32_t pseudo;
 if(f->family==6){p[0]=0x60;put16(p+4,h+length);p[6]=6;p[7]=64;assert(inet_pton(AF_INET6,"fd00::2",p+8)==1);assert(inet_pton(AF_INET6,"2001:db8::53",p+24)==1);pseudo=sum(p+8,32)+h+length+6;}
 else{p[0]=0x45;put16(p+2,n);p[8]=64;p[9]=6;assert(inet_pton(AF_INET,"10.0.0.2",p+12)==1);assert(inet_pton(AF_INET,"192.0.2.53",p+16)==1);put16(p+10,checksum(sum(p,20)));pseudo=sum(p+12,8)+h+length+6;}
 uint8_t *t=p+ip;put16(t,f->source);put16(t+2,53);put32(t+4,f->seq);put32(t+8,f->ack);t[12]=(h/4)<<4;t[13]=flags;put16(t+14,32768);
 if(flags&2){t[20]=2;t[21]=4;put16(t+22,1360);}if(length)memcpy(t+h,data,length);put16(t+16,checksum(pseudo+sum(t,h+length)));
 /* Independent raw-packet client; local selection precedes any Direct work. */
 hev_owner_facts_t facts={.uid=10001,.flow_incarnation=71,.availability=HEV_OWNER_UID_KNOWN|HEV_OWNER_LOCAL_TCP};
 hev_owner_input_context_t context={0};
 return hev_owner_input_copy_context(f->owner,p,n,&facts,f->generation,&context);
}
static void send_bytes(fixture_t *f,const uint8_t *data,size_t length)
{
 while(length) {
  size_t n=length>9000?9000:length;
  assert(inject(f,24,data,n)==HEV_OWNER_INPUT_ACCEPTED);
  f->seq+=n;data+=n;length-=n;
 }
}
static void flush(fixture_t *f,unsigned count)
{
 for(unsigned i=0;i<64 && f->done<count;++i) {
  hev_owner_step(f->owner,16,10000);
  assert(inject(f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 }
 assert(f->done==count);
}
int main(int argc,char **argv)
{
 fixture_t f={.generation=318,.seq=100000,.source=12345,.family=argc>1&&!strcmp(argv[1],"ipv6")?6:4};
 const char *mode=argc>2?argv[2]:"basic";
 hev_owner_config_t c={.generation=f.generation,.max_sessions=16,.max_input_packets=64,.max_pbufs=256,
  .max_packet_bytes=10000,.task_stack_bytes=65536,.broker_timeout_ms=1000,.udp_idle_timeout_ms=1000,
  .output=output,.broker=broker,.local_tcp_done=done,.opaque=&f};
 f.owner=hev_owner_create(&c);assert(f.owner);
 assert(inject(&f,2,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);assert(f.outputs && f.session);
 unsigned ip=f.family==6?40:20;assert(f.packet[ip+13]==0x12);f.ack=get32(f.packet+ip+4)+1;++f.seq;
 assert(inject(&f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 for(unsigned i=0;i<16;++i) { hev_owner_step(f.owner,16,10000); }
 hev_owner_snapshot_t s=hev_owner_snapshot(f.owner);
 assert(s.sessions==1 && !s.faults[HEV_OWNER_FAULT_SOCKET_CREATE]);
 assert(s.sockets_created==0 && f.broker_calls==0); /* Same original RED assertion. */
 static const uint8_t q[]={0x51,0x51,1,0,0,1,0,0,0,0,0,0,1,'a',4,'t','e','s','t',0,0,1,0,1};
 uint8_t frame[sizeof(q)+2];put16(frame,sizeof(q));memcpy(frame+2,q,sizeof(q));
 uint8_t readback[65535];size_t length=0;uint64_t session=0,first=0,second=0;
 hev_owner_binding_t binding={.underlay_epoch=99,.network_context=7,.context_known=1};
 if(!strcmp(mode,"pending") || !strcmp(mode,"bytes")) {
  unsigned wanted=!strcmp(mode,"pending")?129:40;
  uint8_t requests[129*sizeof(frame)];
  for(unsigned i=0;i<wanted;++i)memcpy(requests+i*sizeof(frame),frame,sizeof(frame));
  send_bytes(&f,requests,wanted*sizeof(frame));
  uint8_t answer[65535];memset(answer,0xa5,sizeof(answer));memcpy(answer,q,sizeof(q));answer[2]=0x81;answer[3]=0x80;
  unsigned admitted=0;
  for(unsigned i=0;i<wanted;++i) {
   uint64_t token;
   int got=hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,readback,sizeof(readback),&length);
   if(i==128) {assert(got==-1);break;}
   assert(got==1 && length==sizeof(q) && !memcmp(readback,q,length));
   if(!strcmp(mode,"bytes")) {
    int result=hev_owner_local_tcp_reply(f.owner,f.generation,session,token,answer,sizeof(answer),&binding);
    if(!result)++admitted;
   }
  }
  s=hev_owner_snapshot(f.owner);
  assert(s.local_tcp_bytes<=HEV_OWNER_LOCAL_TCP_BYTES);
  if(!strcmp(mode,"pending"))assert(s.local_tcp_pending==128 && s.local_tcp_pending_peak==128);
  else assert(admitted>1 && admitted<40 && s.local_tcp_outputs==admitted && s.local_tcp_pending==40-admitted);
 } else {
  send_bytes(&f,frame,1);assert(!hev_owner_local_tcp_next(f.owner,f.generation,&session,&first,readback,sizeof(readback),&length));
  uint8_t tail[2*sizeof(frame)-1];memcpy(tail,frame+1,sizeof(frame)-1);memcpy(tail+sizeof(frame)-1,frame,sizeof(frame));tail[sizeof(frame)-1+15]='b';
  send_bytes(&f,tail,sizeof(tail));
  assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&first,readback,sizeof(readback),&length)==1);
  assert(length==sizeof(q)&&!memcmp(readback,q,length));
  assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&second,readback,sizeof(readback),&length)==1);
  assert(first!=second && readback[13]=='b' && get16(readback)==0x5151);
  if(!strcmp(mode,"partial-fin")) {
   uint8_t partial=0;send_bytes(&f,&partial,1);
   assert(inject(&f,17,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);++f.seq;
   hev_owner_step(f.owner,16,10000);s=hev_owner_snapshot(f.owner);
   assert(s.sessions==1 && s.local_tcp_pending==2); /* complete requests survive a trailing partial FIN */
  }
  uint8_t reply[sizeof(q)];memcpy(reply,q,sizeof(q));reply[2]=0x81;reply[3]=0x80;reply[13]='b';
  assert(hev_owner_local_tcp_reply(f.owner,f.generation+1,session,second,reply,sizeof(reply),&binding)==-1);
  assert(hev_owner_local_tcp_reply(f.owner,f.generation,session+1,second,reply,sizeof(reply),&binding)==-1);
  assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,second,reply,sizeof(reply),&binding));
  reply[13]='a';assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,first,reply,sizeof(reply),&binding));
  flush(&f,2);assert(f.completed[0]==second && f.completed[1]==first && f.received_length==2*sizeof(frame));
  assert(get16(f.received)==sizeof(q) && f.received[15]=='b' && f.received[sizeof(frame)+15]=='a');
  if(!strcmp(mode,"partial-fin"))goto finished;
  /* Actual 65535-byte complete framed message, including unknown EDNS padding.
   * The final segment contains both the preceding tail and further TCP bytes. */
  uint8_t *large=calloc(1,65537);assert(large);put16(large,65535);memcpy(large+2,q,sizeof(q));large[2+11]=1;
  size_t at=2+sizeof(q);large[at]=0;put16(large+at+1,41);put16(large+at+3,4096);put16(large+at+9,65535-sizeof(q)-11);
  put16(large+at+11,12);put16(large+at+13,65535-sizeof(q)-15);
  send_bytes(&f,large,65537);
  assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&first,readback,sizeof(readback),&length)==1 && length==65535);
  assert(!memcmp(readback,large+2,length));
  large[4]=0x81;large[5]=0x80;
  assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,first,large+2,65535,&binding));
  flush(&f,3);assert(f.received_length==2*sizeof(frame)+65537 && !memcmp(f.received+2*sizeof(frame),large,65537));free(large);
  /* Eight admitted local sessions remain when the ninth SYN is rejected. */
  for(unsigned i=1;i<8;++i){f.source=12345+i;f.seq=100000;f.ack=0;assert(inject(&f,2,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);}
  f.source=12353;f.seq=100000;f.ack=0;assert(inject(&f,2,NULL,0)==HEV_OWNER_INPUT_NO_CAPACITY);
  s=hev_owner_snapshot(f.owner);assert(s.local_tcp_sessions==8 && s.local_tcp_peak==8 && !s.sockets_created);
 }
finished:
 hev_owner_quiesce(f.owner);hev_owner_step(f.owner,64,10000);s=hev_owner_snapshot(f.owner);
 assert(s.stopped && !s.sessions && !s.sockets && !s.pbufs && !s.local_tcp_bytes && !s.local_tcp_pending && !s.local_tcp_outputs);
 assert(!hev_owner_destroy(f.owner));
 printf("IPv%u local TCP %s bounds/identities/clean Stop PASS\n",f.family,mode);return 0;
}
