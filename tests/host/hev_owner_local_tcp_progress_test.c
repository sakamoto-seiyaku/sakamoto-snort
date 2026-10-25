/* SPDX-License-Identifier: MIT */
/* Public owner-step progress contract, reusing only the independent raw client. */
#define main existing_local_tcp_cases
#include "hev_owner_local_tcp_test.c"
#undef main
#include <time.h>
static uint64_t monotonic_ms(void)
{ struct timespec now;assert(!clock_gettime(CLOCK_MONOTONIC,&now));return (uint64_t)now.tv_sec*1000+now.tv_nsec/1000000; }
static void memory_wait(unsigned family)
{
 fixture_t f={.generation=319,.seq=100000,.source=12346,.family=family};
 hev_owner_config_t c={.generation=f.generation,.max_sessions=16,.max_input_packets=64,.max_pbufs=4,
  .max_packet_bytes=10000,.task_stack_bytes=65536,.broker_timeout_ms=1000,.udp_idle_timeout_ms=1000,
  .output=output,.broker=broker,.local_tcp_done=done,.opaque=&f};
 f.owner=hev_owner_create(&c);assert(f.owner);assert(inject(&f,2,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 unsigned ip=family==6?40:20;f.ack=get32(f.packet+ip+4)+1;++f.seq;assert(inject(&f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 const uint8_t frame[]={0,2,0x51,0x51};send_bytes(&f,frame,sizeof(frame));
 uint8_t request[2];size_t length=0;uint64_t session=0,token=0;
 assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,request,sizeof(request),&length)==1);
 uint8_t *answer=calloc(1,65535);assert(answer);
 hev_owner_binding_t binding={.underlay_epoch=99,.network_context=7,.context_known=1};
 assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,token,answer,65535,&binding));free(answer);
 uint64_t began=monotonic_ms();hev_owner_step_result_t step=hev_owner_step(f.owner,16,10000);
 hev_owner_snapshot_t snapshot=hev_owner_snapshot(f.owner);
 /* Public pbuf budget really rejects the bounded tcp_write before sndbuf is
  * full. The failed write must wait for an event or a true deadline. */
 assert(snapshot.faults[HEV_OWNER_FAULT_PBUF_CAPACITY]>0 && snapshot.local_tcp_outputs==1);
 assert(!f.received_length && !f.done && !f.failed && !step.runnable && step.timeout_ms>10);
 unsigned turns=0;
 while(!f.failed && monotonic_ms()-began<12000) {
  assert(step.timeout_ms>=0 && step.timeout_ms<=250 && !step.runnable);
  struct timespec wait={.tv_sec=step.timeout_ms/1000,.tv_nsec=(step.timeout_ms%1000)*1000000L};
  assert(!nanosleep(&wait,NULL));step=hev_owner_step(f.owner,16,10000);++turns;
 }
 assert(f.failed==1 && !f.done && !f.received_length && monotonic_ms()-began>=9500 && turns<80);
 hev_owner_quiesce(f.owner);step=hev_owner_step(f.owner,64,10000);snapshot=hev_owner_snapshot(f.owner);
 assert(step.stopped && !snapshot.sessions && !snapshot.pbufs && !snapshot.local_tcp_outputs && !snapshot.local_tcp_bytes);
 assert(!hev_owner_destroy(f.owner));
}
int main(int argc,char **argv)
{
 fixture_t f={.generation=318,.seq=100000,.source=12345,.family=argc>1&&!strcmp(argv[1],"ipv6")?6:4};
 hev_owner_config_t c={.generation=f.generation,.max_sessions=16,.max_input_packets=64,.max_pbufs=256,
  .max_packet_bytes=10000,.task_stack_bytes=65536,.broker_timeout_ms=1000,.udp_idle_timeout_ms=1000,
  .output=output,.broker=broker,.local_tcp_done=done,.opaque=&f};
 f.owner=hev_owner_create(&c);assert(f.owner);
 assert(inject(&f,2,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 unsigned ip=f.family==6?40:20;f.ack=get32(f.packet+ip+4)+1;++f.seq;
 assert(inject(&f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 const uint8_t query[]={0x51,0x51,1,0,0,1,0,0,0,0,0,0,1,'a',4,'t','e','s','t',0,0,1,0,1};
 uint8_t frame[sizeof(query)+2];put16(frame,sizeof(query));memcpy(frame+2,query,sizeof(query));send_bytes(&f,frame,sizeof(frame));
 uint8_t readback[65535];size_t length=0;uint64_t session=0,token=0;
 assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,readback,sizeof(readback),&length)==1);
 hev_owner_step_result_t step=hev_owner_step(f.owner,16,10000);
 assert(!step.runnable && step.timeout_ms>10); /* pending upstream is blocked */
 hev_owner_binding_t binding={.underlay_epoch=99,.network_context=7,.context_known=1};
 assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,token,query,sizeof(query),&binding));
 step=hev_owner_step(f.owner,16,10000);
 assert(f.received_length==sizeof(frame) && !f.done);
 assert(!step.runnable && step.timeout_ms>10); /* written output waits for ACK */
 assert(inject(&f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED && f.done==1);
 send_bytes(&f,frame,sizeof(frame));
 assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,readback,sizeof(readback),&length)==1);
 uint8_t *large=calloc(1,65535);assert(large);memcpy(large,query,sizeof(query));large[2]=0x81;large[3]=0x80;
 assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,token,large,65535,&binding));free(large);
 step=hev_owner_step(f.owner,16,10000);
 assert(f.received_length>sizeof(frame) && f.received_length<sizeof(frame)+65537);
 assert(step.runnable); /* another bounded write can run now, without a packet */
 unsigned turns=0;
 while(step.runnable && turns++<8)step=hev_owner_step(f.owner,16,10000);
 assert(turns<8 && !step.runnable && step.timeout_ms>10); /* full sndbuf waits */
 for(unsigned i=0;i<64 && f.done<2;++i) {
  assert(inject(&f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);step=hev_owner_step(f.owner,16,10000);
  unsigned bound=0;while(step.runnable && bound++<8)step=hev_owner_step(f.owner,16,10000);
  assert(bound<8);
 }
 assert(f.done==2 && f.received_length==sizeof(frame)+65537);
 hev_owner_quiesce(f.owner);hev_owner_step(f.owner,64,10000);hev_owner_snapshot_t end=hev_owner_snapshot(f.owner);
 assert(end.stopped && !end.sessions && !end.sockets && !end.pbufs && !end.local_tcp_pending && !end.local_tcp_outputs && !end.local_tcp_bytes);
 assert(!hev_owner_destroy(f.owner));
 memory_wait(f.family);
 printf("IPv%u event-driven local pending/ACK/writable/deadline/Stop PASS\n",f.family);return 0;
}
