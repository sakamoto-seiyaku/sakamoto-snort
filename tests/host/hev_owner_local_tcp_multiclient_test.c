/* SPDX-License-Identifier: MIT */
/* Actual lwIP local TCP clients compete for one owner-local pending slot. */
#define main local_tcp_base_main
#include "hev_owner_local_tcp_test.c"
#undef main

typedef struct { unsigned source; uint32_t seq,ack; uint64_t session; } client_state_t;

static client_state_t connect_client(fixture_t *f,unsigned source)
{
 f->source=source;f->seq=100000;f->ack=0;
 assert(inject(f,2,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 unsigned ip=f->family==6?40:20;assert(f->packet[ip+13]==0x12);
 f->ack=get32(f->packet+ip+4)+1;++f->seq;
 assert(inject(f,16,NULL,0)==HEV_OWNER_INPUT_ACCEPTED);
 for(unsigned i=0;i<16;++i)hev_owner_step(f->owner,16,10000);
 return (client_state_t){source,f->seq,f->ack,f->session};
}

static void select_client(fixture_t *f,const client_state_t *c)
{ f->source=c->source;f->seq=c->seq;f->ack=c->ack; }

int main(int argc,char **argv)
{
 fixture_t f={.generation=318,.family=argc>1&&!strcmp(argv[1],"ipv6")?6:4};
 hev_owner_config_t config={.generation=f.generation,.max_sessions=16,.max_input_packets=64,.max_pbufs=256,
  .max_packet_bytes=10000,.task_stack_bytes=65536,.broker_timeout_ms=1000,.udp_idle_timeout_ms=1000,
  .output=output,.broker=broker,.local_tcp_done=done,.opaque=&f};
 f.owner=hev_owner_create(&config);assert(f.owner);
 client_state_t older=connect_client(&f,12345);
 client_state_t newer=connect_client(&f,12346);
 assert(older.session!=newer.session);
 static const uint8_t q[]={0x51,0x51,1,0,0,1,0,0,0,0,0,0,1,'a',4,'t','e','s','t',0,0,1,0,1};
 uint8_t frame[sizeof(q)+2];put16(frame,sizeof(q));memcpy(frame+2,q,sizeof(q));
 uint8_t requests[129*sizeof(frame)];for(unsigned i=0;i<129;++i)memcpy(requests+i*sizeof(frame),frame,sizeof(frame));
 select_client(&f,&newer);send_bytes(&f,requests,sizeof(requests));newer.seq=f.seq;
 uint8_t message[65535];size_t length;uint64_t session,token,tokens[128];
 for(unsigned i=0;i<128;++i) {
  assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,message,sizeof(message),&length)==1);
  assert(session==newer.session && length==sizeof(q));tokens[i]=token;
 }
 assert(!hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,message,sizeof(message),&length));
 select_client(&f,&older);send_bytes(&f,frame,sizeof(frame));older.seq=f.seq;
 assert(!hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,message,sizeof(message),&length));
 hev_owner_snapshot_t s=hev_owner_snapshot(f.owner);
 assert(s.sessions==2 && s.local_tcp_pending==128 && !f.failed);
 hev_owner_binding_t binding={.underlay_epoch=99,.network_context=7,.context_known=1};
 uint8_t reply[sizeof(q)];memcpy(reply,q,sizeof(q));reply[2]=0x81;reply[3]=0x80;
 assert(!hev_owner_local_tcp_reply(f.owner,f.generation,newer.session,tokens[0],reply,sizeof(reply),&binding));
 select_client(&f,&newer);flush(&f,1);newer.ack=f.ack;
 /* The older blocked client gets the newly free slot, even though the newer
  * client is first in the session list and also has a complete frame. */
 assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,message,sizeof(message),&length)==1);
 assert(session==older.session && length==sizeof(q));
 assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,token,reply,sizeof(reply),&binding));
 select_client(&f,&older);flush(&f,2);older.ack=f.ack;
 assert(hev_owner_local_tcp_next(f.owner,f.generation,&session,&token,message,sizeof(message),&length)==1);
 assert(session==newer.session && length==sizeof(q));
 assert(!hev_owner_local_tcp_reply(f.owner,f.generation,session,token,reply,sizeof(reply),&binding));
 select_client(&f,&newer);flush(&f,3);
 hev_owner_quiesce(f.owner);hev_owner_step(f.owner,64,10000);s=hev_owner_snapshot(f.owner);
 assert(s.stopped && !s.sessions && !s.sockets && !s.pbufs && !s.local_tcp_bytes && !s.local_tcp_pending);
 assert(f.done==3 && f.failed==127);
 for(unsigned i=1;i<128;++i) {
  unsigned matches=0;for(unsigned j=0;j<127;++j)matches+=tokens[i]==f.failed_tokens[j];
  assert(matches==1);
 }
 assert(!hev_owner_destroy(f.owner));
 printf("IPv%u local TCP cross-session bounded pending fairness and Stop PASS\n",f.family);return 0;
}
