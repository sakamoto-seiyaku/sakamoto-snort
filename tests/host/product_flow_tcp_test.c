/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_tracker.h"
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { FIN=1, SYN=2, RST=4, ACK=16 };
static product_packet_facts_t packet(unsigned flags, uint32_t seq, uint32_t ack, unsigned length)
{
  return (product_packet_facts_t) {.l3_status=PRODUCT_PACKET_L3_COMPLETE,
    .l4_status=PRODUCT_PACKET_L4_COMPLETE, .ip_family=4, .protocol=6,
    .tcp_flags=flags, .tcp_sequence=seq, .tcp_acknowledgment=ack,
    .tcp_window=8192, .l4_header_length=20, .transport_length=20+length};
}
static product_tracker_result_t update(product_tcp_state_t *state, unsigned side,
                                      unsigned flags, uint32_t seq, uint32_t ack, unsigned length)
{
  product_packet_facts_t p=packet(flags,seq,ack,length);
  return product_tcp_update(state,&p,side?PRODUCT_FLOW_DIRECTION_REPLY:PRODUCT_FLOW_DIRECTION_ORIG);
}
static void handshake(product_tcp_state_t *s, uint32_t a, uint32_t b)
{
  assert(update(s,0,SYN,a,0,0).update==PRODUCT_CT_UPDATE_VALID_NEW);
  assert(update(s,0,SYN,a,0,0).update==PRODUCT_CT_UPDATE_VALID_NEW);
  product_tracker_result_t r=update(s,1,SYN|ACK,b,a+1,0);
  assert(r.update==PRODUCT_CT_UPDATE_VALID && r.facts.state==PRODUCT_CT_ESTABLISHED);
  assert(r.timeout==PRODUCT_CT_TIMEOUT_TCP_OPENING && r.refresh_deadline);
  r=update(s,0,ACK,a+1,b+1,0);
  assert(r.update==PRODUCT_CT_UPDATE_VALID && r.timeout==PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED);
  assert(s->peer[0].phase==PRODUCT_TCP_ESTABLISHED && s->peer[1].phase==PRODUCT_TCP_ESTABLISHED);
}
static void lifecycle(void)
{
  product_tcp_state_t s={0}; handshake(&s,100,500);
  assert(update(&s,0,ACK,101,501,100).update==PRODUCT_CT_UPDATE_VALID);
  assert(update(&s,0,ACK,101,501,100).update==PRODUCT_CT_UPDATE_VALID); /* retransmit */
  assert(update(&s,1,ACK,501,201,80).update==PRODUCT_CT_UPDATE_VALID);
  assert(update(&s,1,ACK,501,201,80).update==PRODUCT_CT_UPDATE_VALID);
  product_tcp_state_t before=s;
  assert(update(&s,0,ACK,1000000,581,100).update==PRODUCT_CT_UPDATE_INVALID);
  assert(!memcmp(&s,&before,sizeof s));
  assert(update(&s,0,FIN|ACK,201,581,0).timeout==PRODUCT_CT_TIMEOUT_TCP_CLOSING);
  assert(update(&s,1,ACK,581,202,0).timeout==PRODUCT_CT_TIMEOUT_TCP_CLOSING);
  assert(update(&s,1,FIN|ACK,581,202,0).timeout==PRODUCT_CT_TIMEOUT_TCP_FIN_WAIT);
  assert(update(&s,0,ACK,202,582,0).timeout==PRODUCT_CT_TIMEOUT_TCP_CLOSED);
  before=s;
  product_tracker_result_t r=update(&s,1,SYN,999,0,0);
  assert(r.update==PRODUCT_CT_UPDATE_NEW && r.close_old_instance && r.create_replacement);
  assert(!memcmp(&s,&before,sizeof s));
  assert(s.peer[0].flags_history==(SYN|ACK|FIN));
}
static void resets_and_wrap(void)
{
  for(unsigned delta=0;delta<3;++delta) {
    product_tcp_state_t s={0}; handshake(&s,UINT32_MAX-5,1234);
    assert(update(&s,0,ACK,UINT32_MAX-4,1235,10).update==PRODUCT_CT_UPDATE_VALID);
    assert(s.peer[0].seqlo==5);
    product_tracker_result_t r=update(&s,0,RST|ACK,4+delta,1235,0);
    assert(r.update==PRODUCT_CT_UPDATE_VALID && r.timeout==PRODUCT_CT_TIMEOUT_TCP_CLOSED);
    assert(s.peer[0].phase==PRODUCT_TCP_TIME_WAIT && s.peer[1].phase==PRODUCT_TCP_TIME_WAIT);
  }
  product_tcp_state_t s={0}; handshake(&s,100,500);
  product_tcp_state_t before=s;
  assert(update(&s,0,RST|ACK,333,501,0).update==PRODUCT_CT_UPDATE_INVALID);
  assert(!memcmp(&s,&before,sizeof s));
  assert(update(&s,0,RST|ACK,100,0,0).update==PRODUCT_CT_UPDATE_VALID); /* broken zero ACK */
}
static void scales(void)
{
  for(unsigned shift=0;shift<=15;++shift) for(unsigned present=0;present<2;++present) {
    product_tcp_state_t s={0}; product_packet_facts_t p=packet(SYN,100,0,0);
    p.ip_family=6; p.tcp_window_scale_known=1; p.tcp_window_scale=shift;
    assert(product_tcp_update(&s,&p,1).update==PRODUCT_CT_UPDATE_VALID_NEW);
    assert((s.peer[0].window_scale&15)==(shift>14?14:shift));
    p=packet(SYN|ACK,500,101,0); p.ip_family=6;
    p.tcp_window_scale_known=present; p.tcp_window_scale=3;
    assert(product_tcp_update(&s,&p,2).update==PRODUCT_CT_UPDATE_VALID);
    assert(present || s.peer[0].window_scale==0);
    assert(update(&s,0,ACK,101,501,0).timeout==PRODUCT_CT_TIMEOUT_TCP_ESTABLISHED);
  }
}
static void permissive_and_invalid(void)
{
  product_tcp_state_t s={0};
  assert(update(&s,0,ACK,4000,6000,10).update==PRODUCT_CT_UPDATE_VALID_NEW);
  assert(s.peer[0].window_scale==0x40 && s.peer[1].window_scale==0x40);
  assert(update(&s,1,ACK,6000,4010,10).update==PRODUCT_CT_UPDATE_VALID);
  s=(product_tcp_state_t){0}; update(&s,0,SYN,100,0,0);
  product_tracker_result_t r=update(&s,0,ACK,1000,0,1);
  assert(r.update==PRODUCT_CT_UPDATE_VALID && !r.refresh_deadline);
  assert(r.timeout==PRODUCT_CT_TIMEOUT_TCP_FIRST_PACKET);
  s=(product_tcp_state_t){.initialized=1,.timeout=PRODUCT_CT_TIMEOUT_TCP_OPENING,
    .peer={{.phase=PRODUCT_TCP_ESTABLISHED,.seqlo=100,.seqhi=200,.max_window=1000},
           {.phase=PRODUCT_TCP_CLOSED,.seqhi=500000,.max_window=1}}};
  product_tcp_state_t before=s;
  assert(update(&s,1,ACK,300,1000000,30).update==PRODUCT_CT_UPDATE_INVALID);
  assert(!memcmp(&s,&before,sizeof s)); /* reject after provisional peer initialization */
  const unsigned flags[]={0,FIN,SYN|RST,SYN|FIN,8,32,SYN|ACK};
  for(unsigned i=0;i<sizeof flags/sizeof flags[0];++i) {
    s=(product_tcp_state_t){0}; before=s;
    assert(update(&s,0,flags[i],10,20,0).update==PRODUCT_CT_UPDATE_INVALID);
    assert(!memcmp(&s,&before,sizeof s));
  }
}
static void runtime(void)
{
  product_packet_facts_t p=packet(SYN|ACK,100,200,0);
  p.source_address[15]=1; p.destination_address[15]=2;
  p.source_port=50000; p.destination_port=443;
  product_worker_layout_t layout={2,123}; product_owner_assignment_t key;
  assert(product_owner_assign(&layout,&p,&key)==PRODUCT_PACKET_OK);
  product_flow_runtime_t *pool=NULL;
  assert(product_flow_runtime_create(&pool,key.execution_owner,2,1,1)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_entry_packet_t observed={.facts=&p,.policy={1,1,100},
    .uid=10001,.packet_bytes=40,.device_direction=3};
  product_flow_entry_observation_t o;
  assert(product_flow_entry_observe(pool,&key,&observed,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(!o.entry && !o.created && o.tracker.facts.state==PRODUCT_CT_INVALID);
  assert(o.tracker.facts.direction==PRODUCT_FLOW_DIRECTION_UNKNOWN);
  assert(product_flow_runtime_snapshot(pool).active_entries==0);
  p.tcp_flags=SYN;
  assert(product_flow_entry_observe(pool,&key,&observed,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.created && o.tracker.update==PRODUCT_CT_UPDATE_VALID_NEW);
  uint64_t incarnation=o.entry->incarnation;
  p.tcp_flags=ACK; p.tcp_sequence=1000000; p.tcp_acknowledgment=1000000; p.transport_length=60;
  product_tcp_state_t before=o.entry->protocol_state.tcp;
  assert(product_flow_entry_observe(pool,&key,&observed,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.reused && o.tracker.facts.state==PRODUCT_CT_INVALID);
  assert(!memcmp(&before,&o.entry->protocol_state.tcp,sizeof before));
  observed.policy=(product_flow_policy_identity_t){1,2,200};
  p.tcp_flags=RST; p.tcp_sequence=100; p.transport_length=20;
  assert(product_flow_entry_observe(pool,&key,&observed,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.revision_invalidated && o.tracker.timeout==PRODUCT_CT_TIMEOUT_TCP_CLOSED);
  key.source_is_a^=1; /* A new SYN in the opposite direction defines new ORIG. */
  p.tcp_flags=SYN; p.tcp_sequence=500;
  assert(product_flow_entry_observe(pool,&key,&observed,1,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
  assert(product_flow_runtime_snapshot(pool).protocol[0].closed==0);
  assert(product_flow_entry_observe(pool,&key,&observed,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.created && !o.reused && o.previous_incarnation==incarnation);
  assert(o.entry->incarnation>incarnation && o.entry->packets==1);
  assert(o.entry->origin_is_endpoint_a==key.source_is_a && o.flow_direction==PRODUCT_FLOW_DIRECTION_ORIG);
  assert(o.tracker.close_old_instance && o.tracker.create_replacement);
  product_flow_runtime_snapshot_t stats=product_flow_runtime_snapshot(pool);
  assert(stats.capacity==1 && stats.active_entries==1 && stats.allocation_count==2);
  assert(stats.protocol[0].closed==1 && stats.protocol[0].invalid_packets==2);
  observed.facts=NULL;
  assert(product_flow_entry_observe(pool,&key,&observed,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  assert(product_flow_runtime_snapshot(pool).protocol[0].closed==1);
  product_flow_runtime_flush(pool);
  assert(!product_flow_runtime_snapshot(pool).active_entries);
  product_flow_runtime_destroy(pool);
}
int main(void)
{
  lifecycle(); resets_and_wrap(); scales(); permissive_and_invalid(); runtime();
  puts("TCP tracker: handshake, retransmit, window/scale, wrap, midstream, FIN/RST, reuse and rollback PASS");
}
