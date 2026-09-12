#!/usr/bin/env python3
"""Differential core test against the exact pinned OVS source, not a model.

OVS packet/storage/clock dependencies are test stubs. The three protocol
functions are extracted unchanged. Product INVALID rollback is intentional.
"""
import argparse
import hashlib
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--ovs', type=Path, required=True)
parser.add_argument('--library-output', type=Path)
args = parser.parse_args()
source = (args.ovs / 'lib/conntrack-tcp.c').read_text()
assert hashlib.sha256(source.encode()).hexdigest() == '94f0b7379399334824ebfd9fa3ae7ec14545eb252cfea789efbc6ec0ec23fdb1'
prefix = r'''
#include "product_flow_tracker.h"
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TCP_SYN 2
#define TCP_FIN 1
#define TCP_RST 4
#define TCP_ACK 16
#define TCP_PSH 8
#define TCP_URG 32
#define TCP_FLAGS(x) ((x)&255)
#define TCP_OFFSET(x) ((x)>>12)
#define INT_MOD_LT(a,b) ((int32_t)((uint32_t)(a)-(uint32_t)(b))<0)
#define INT_MOD_LEQ(a,b) ((int32_t)((uint32_t)(a)-(uint32_t)(b))<=0)
#define INT_MOD_GT(a,b) ((int32_t)((uint32_t)(a)-(uint32_t)(b))>0)
#define INT_MOD_GEQ(a,b) ((int32_t)((uint32_t)(a)-(uint32_t)(b))>=0)
#define MAX(a,b) ((a)>(b)?(a):(b))
#define MIN(a,b) ((a)<(b)?(a):(b))
#define DIV_ROUND_UP(a,b) (((a)+(b)-1)/(b))
#define COVERAGE_INC(x) ((void)0)
#define CONTAINER_OF(p,t,m) ((t*)((char*)(p)-offsetof(t,m)))
enum ct_dpif_tcp_state {CT_DPIF_TCPS_CLOSED, CT_DPIF_TCPS_LISTEN,
 CT_DPIF_TCPS_SYN_SENT, CT_DPIF_TCPS_SYN_RECV, CT_DPIF_TCPS_ESTABLISHED,
 CT_DPIF_TCPS_CLOSE_WAIT, CT_DPIF_TCPS_FIN_WAIT_1, CT_DPIF_TCPS_CLOSING,
 CT_DPIF_TCPS_LAST_ACK, CT_DPIF_TCPS_FIN_WAIT_2, CT_DPIF_TCPS_TIME_WAIT};
enum ct_update_res {CT_UPDATE_VALID=11, CT_UPDATE_INVALID, CT_UPDATE_NEW, CT_UPDATE_VALID_NEW};
enum {CT_TM_TCP_FIRST_PACKET=41, CT_TM_TCP_OPENING, CT_TM_TCP_ESTABLISHED,
 CT_TM_TCP_CLOSING, CT_TM_TCP_FIN_WAIT, CT_TM_TCP_CLOSED};
struct conn {unsigned tp_id, timeout;};
struct conntrack {unsigned unused;};
struct tcp_header {uint16_t a,b; uint32_t tcp_seq,tcp_ack;
 uint16_t tcp_ctl,tcp_winsz,csum,urg;};
struct dp_packet {struct tcp_header tcp; uint8_t options[40]; uint32_t payload;};
static unsigned refreshed;
static uint32_t get_16aligned_be32(const uint32_t *p) {uint32_t v;memcpy(&v,p,4);return v;}
static void *dp_packet_l4(struct dp_packet *p) {return &p->tcp;}
static uint32_t dp_packet_get_tcp_payload_length(struct dp_packet *p) {return p->payload;}
static int conntrack_get_tcp_seq_chk(struct conntrack *ct) {(void)ct;return 1;}
static void *xzalloc(size_t size) {void *p=calloc(1,size);assert(p);return p;}
static void conn_update_expiration(struct conntrack *ct,struct conn *c,unsigned timeout,long long now) {
 (void)ct;(void)now;c->timeout=timeout;++refreshed;
}
#define conn_init_expiration conn_update_expiration
'''
core = source[source.index('struct tcp_peer {'):source.index('static uint8_t\ntcp_peer_to_protoinfo_flags')]
suffix = r'''
static uint32_t random_state=0x222239;
static uint32_t random32(void) {uint32_t x=random_state;x^=x<<13;x^=x>>17;x^=x<<5;return random_state=x;}
static void compare_peer(const product_tcp_peer_t *a,const struct tcp_peer *b) {
 assert(a->seqlo==b->seqlo && a->seqhi==b->seqhi && a->max_window==b->max_win);
 assert(a->window_scale==b->wscale && a->phase==(unsigned)b->state);
}
int main(void) {
 assert(sizeof(struct tcp_header)==20);
 unsigned valid=0,invalid=0,replaced=0,loose=0;
 for(unsigned flow=0;flow<128;++flow) {
  struct conntrack ct={0};struct conn_tcp *reference=NULL;
  product_tcp_state_t state={0};
  for(unsigned step=0;step<1024;++step) {
   unsigned side=reference?(random32()&1):0;
   const uint8_t flags[]={2,18,16,17,4,20,24,48,0,3,6,8,32,16,16,16};
   unsigned flag=flags[random32()%16],length=(random32()%4)?random32()%128:0;
   uint32_t seq=reference?reference->peer[side].seqlo:random32();
   uint32_t ack=reference?reference->peer[!side].seqlo:random32();
   if(random32()%8==0) seq=random32(); else seq+=random32()%9-4;
   if(random32()%8==0) ack=random32(); else ack+=random32()%9-4;
   unsigned scale=random32()%20,known=random32()&1,window=random32()&65535;
   product_packet_facts_t p={.l3_status=PRODUCT_PACKET_L3_COMPLETE,
    .l4_status=PRODUCT_PACKET_L4_COMPLETE,.ip_family=flow&1?6:4,.protocol=6,
    .l4_header_length=known?24:20,.transport_length=(known?24:20)+length,
    .tcp_flags=flag,.tcp_sequence=seq,.tcp_acknowledgment=ack,.tcp_window=window,
    .tcp_window_scale_known=known,.tcp_window_scale=scale};
   struct dp_packet wire={.tcp={.tcp_seq=htonl(seq),.tcp_ack=htonl(ack),
    .tcp_ctl=((known?6:5)<<12)|flag,.tcp_winsz=htons(window)},.payload=length};
   if(known) {wire.options[0]=3;wire.options[1]=3;wire.options[2]=scale;}
   product_tcp_state_t before=state;
   product_tracker_result_t actual=product_tcp_update(&state,&p,side?2:1);
   refreshed=0;
   enum ct_update_res expected;
   struct conn_tcp snapshot;
   if(!reference) {
    if(tcp_valid_new(&wire)) {reference=conn_tcp_cast(tcp_new_conn(&ct,&wire,0,0));expected=CT_UPDATE_VALID_NEW;}
    else expected=CT_UPDATE_INVALID;
   } else {
    snapshot=*reference;
    expected=tcp_conn_update(&ct,&reference->up,&wire,side,0);
    if(expected==CT_UPDATE_INVALID || expected==CT_UPDATE_NEW) *reference=snapshot;
   }
   if(expected==CT_UPDATE_INVALID) {
    ++invalid;assert(actual.update==PRODUCT_CT_UPDATE_INVALID);
    assert(!actual.refresh_deadline && actual.timeout==PRODUCT_CT_TIMEOUT_NONE);
    assert(!memcmp(&state,&before,sizeof state));
   } else if(expected==CT_UPDATE_NEW) {
    ++replaced;assert(actual.update==PRODUCT_CT_UPDATE_NEW);
    assert(actual.close_old_instance && actual.create_replacement && !actual.refresh_deadline);
    assert(!memcmp(&state,&before,sizeof state));
    free(reference);reference=NULL;state=(product_tcp_state_t){0};
   } else {
    ++valid;loose+=!refreshed;
    assert(actual.update==(expected==CT_UPDATE_VALID?PRODUCT_CT_UPDATE_VALID:PRODUCT_CT_UPDATE_VALID_NEW));
    assert(actual.facts.state==(expected==CT_UPDATE_VALID?PRODUCT_CT_ESTABLISHED:PRODUCT_CT_NEW));
    assert(actual.refresh_deadline==!!refreshed && state.initialized);
    assert(actual.timeout==reference->up.timeout-CT_TM_TCP_FIRST_PACKET+PRODUCT_CT_TIMEOUT_TCP_FIRST_PACKET);
    for(unsigned i=0;i<2;++i) compare_peer(&state.peer[i],&reference->peer[i]);
   }
  }
  free(reference);
 }
 assert(valid && invalid && replaced && loose);
 printf("PASS pinned OVS differential: valid=%u invalid=%u replacement=%u permissive_no_refresh=%u\n",valid,invalid,replaced,loose);
}
'''
oracle = r'''
struct oracle {struct conntrack ct; struct conn_tcp *connection;};
void *oracle_create(void) {return calloc(1,sizeof(struct oracle));}
void oracle_destroy(void *opaque) {struct oracle *o=opaque;free(o->connection);free(o);}
void oracle_step(void *opaque,const uint32_t *input,uint32_t *output) {
 struct oracle *o=opaque;unsigned known=input[5],scale=input[6];
 struct dp_packet packet={.tcp={.tcp_ctl=((known?6:5)<<12)|input[0],
  .tcp_seq=htonl(input[1]),.tcp_ack=htonl(input[2]),.tcp_winsz=htons(input[3])},.payload=input[4]};
 if(known) {packet.options[0]=3;packet.options[1]=3;packet.options[2]=scale;}
 unsigned replaced=0;enum ct_update_res res;refreshed=0;
 if(!o->connection) {
  if(tcp_valid_new(&packet)) {o->connection=conn_tcp_cast(tcp_new_conn(&o->ct,&packet,0,0));res=CT_UPDATE_VALID_NEW;}
  else res=CT_UPDATE_INVALID;
 } else {
  struct conn_tcp before=*o->connection;
  res=tcp_conn_update(&o->ct,&o->connection->up,&packet,input[7],0);
  if(res==CT_UPDATE_INVALID) *o->connection=before;
  if(res==CT_UPDATE_NEW) {
   free(o->connection);o->connection=conn_tcp_cast(tcp_new_conn(&o->ct,&packet,0,0));
   res=CT_UPDATE_VALID_NEW;replaced=1;
  }
 }
 memset(output,0,15*sizeof(uint32_t));output[0]=res;output[1]=!!refreshed;
 output[2]=res==CT_UPDATE_INVALID?0:o->connection->up.timeout;
 output[3]=o->connection!=NULL;output[4]=replaced;
 if(o->connection) for(unsigned i=0;i<2;++i) {
  struct tcp_peer *p=&o->connection->peer[i];unsigned n=5+i*5;
  output[n]=p->seqlo;output[n+1]=p->seqhi;output[n+2]=p->max_win;
  output[n+3]=p->wscale;output[n+4]=p->state;
 }
}
'''
with tempfile.TemporaryDirectory(prefix='s222-ovs-') as temporary:
    source = Path(temporary) / 'test.c'
    binary = Path(temporary) / 'test'
    if args.library_output:
        # The replay oracle has no Product include or linked implementation.
        source.write_text(prefix.replace('#include "product_flow_tracker.h"', '') + core + oracle)
        args.library_output.parent.mkdir(parents=True,exist_ok=True)
        subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-O2','-shared','-fPIC',
                        str(source),'-o',str(args.library_output)],check=True)
        raise SystemExit(0)
    source.write_text(prefix + core + suffix)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
                    '-I' + str(ROOT / 'src/product/vpp'), str(source),
                    str(ROOT / 'src/product/vpp/product_flow_tcp.c'), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15)
