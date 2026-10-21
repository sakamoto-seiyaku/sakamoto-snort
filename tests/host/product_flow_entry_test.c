/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const product_worker_layout_t layout={2,UINT64_C(0x6f776e65722d3137)};
static product_packet_facts_t facts(unsigned family,unsigned protocol,unsigned port) {
  product_packet_facts_t f={0};
  f.l3_status=PRODUCT_PACKET_L3_COMPLETE;f.l4_status=PRODUCT_PACKET_L4_COMPLETE;
  f.ip_family=family;f.protocol=protocol;f.source_port=port;f.destination_port=443;
  if(protocol==6) { f.tcp_flags=16;f.l4_header_length=f.transport_length=20;f.tcp_window=8192; }
  f.source_address[15]=1;f.destination_address[15]=2;
  if(family==6)f.source_address[0]=f.destination_address[0]=0x20;
  return f;
}
static product_owner_assignment_t assign(product_packet_facts_t f) {
  product_owner_assignment_t a;
  assert(product_owner_assign(&layout,&f,&a)==PRODUCT_PACKET_OK);return a;
}
static product_owner_assignment_t reverse(product_packet_facts_t f) {
  unsigned char tmp[16];memcpy(tmp,f.source_address,16);
  memcpy(f.source_address,f.destination_address,16);memcpy(f.destination_address,tmp,16);
  unsigned port=f.source_port;f.source_port=f.destination_port;f.destination_port=port;
  return assign(f);
}
static product_flow_entry_packet_t packet(unsigned direction,unsigned bytes,unsigned time) {
  return (product_flow_entry_packet_t){.policy={1,0,0},.uid=10001,.network_context=7,.packet_bytes=bytes,.device_direction=direction,.timestamp=time};
}
static void observe(product_flow_runtime_t *pool,const product_owner_assignment_t *a,
                    product_flow_entry_packet_t p,product_flow_entry_observation_t *o) {
  /* These storage vectors deliberately inject assigned identities, including
   * full-hash collisions. Supply corresponding decoded-facts fixtures too. */
  product_packet_facts_t f=facts(a->key.ip_family,a->key.protocol,0);
  if(a->key.kind==PRODUCT_OWNER_KEY_ICMP_QUERY) {
    f.l4_status=PRODUCT_PACKET_L4_OTHER_TERMINAL;
    f.icmp_identity_known=1;f.icmp_identifier=a->key.transport.query.identifier;
    f.icmp_type=a->key.ip_family==4?8:128;
  }
  p.facts=&f;
  assert(product_flow_entry_observe(pool,a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
}

static void prefetch(product_flow_runtime_t *runtime,
                     const product_owner_assignment_t *assignment) {
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  product_flow_runtime_prefetch(runtime,assignment,PRODUCT_FLOW_PREFETCH_BUCKET);
  product_flow_runtime_prefetch(runtime,assignment,PRODUCT_FLOW_PREFETCH_INDEX);
  product_flow_runtime_prefetch(runtime,assignment,PRODUCT_FLOW_PREFETCH_STATE);
#else
  (void)runtime;(void)assignment;
#endif
}

static void prepared_window_order(void) {
  /* Every future tuple is a miss during preparation. Adjacent and separated
   * packets must still see earlier creates and ordered direction/accounting.
   * Full-hash collisions force the compact index to compare complete keys. */
  product_flow_runtime_t *prepared=NULL,*reference=NULL;
  assert(!product_flow_runtime_create(&prepared,0,2,1,4));
  assert(!product_flow_runtime_create(&reference,0,2,1,4));
  product_owner_assignment_t keys[6];
  const unsigned sequence[]={0,1,0,0,1,0};
  for(unsigned i=0;i<6;i++) {
    keys[i]=assign(facts(sequence[i]?6:4,17,23000+sequence[i]));
    keys[i].execution_owner=0;
    keys[i].canonical_hash=UINT64_C(0x123400001234);
    if(i==2 || i==4)keys[i].source_is_a^=1;
  }
  product_flow_runtime_snapshot_t before=product_flow_runtime_snapshot(prepared);
#ifdef SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT
  for(unsigned stage=PRODUCT_FLOW_PREFETCH_BUCKET;stage<=PRODUCT_FLOW_PREFETCH_STATE;stage++)
    for(unsigned i=0;i<6;i++)
      product_flow_runtime_prefetch(prepared,&keys[i],(product_flow_prefetch_stage_t)stage);
  product_flow_runtime_prefetch(NULL,&keys[0],PRODUCT_FLOW_PREFETCH_STATE);
  product_flow_runtime_prefetch(prepared,NULL,PRODUCT_FLOW_PREFETCH_STATE);
  product_owner_assignment_t invalid=keys[0];invalid.valid=0;
  prefetch(prepared,&invalid);
  invalid=keys[0];invalid.execution_owner=1;prefetch(prepared,&invalid);
  product_flow_runtime_prefetch(prepared,&keys[0],(product_flow_prefetch_stage_t)99);
#endif
  product_flow_runtime_snapshot_t after=product_flow_runtime_snapshot(prepared);
  assert(!memcmp(&before,&after,sizeof before));
  assert(!product_flow_entry_current_incarnation(prepared,&keys[0],1,1));
  for(unsigned i=0;i<6;i++) {
    product_flow_entry_observation_t a,b;
    product_flow_entry_packet_t p=packet(i&1?1:3,40+i,i+1);
    p.policy=(product_flow_policy_identity_t){1,1,101};
    observe(prepared,&keys[i],p,&a);
    observe(reference,&keys[i],p,&b);
    prefetch(prepared,&keys[(i+1)%6]);
    prefetch(prepared,&keys[i]);
    assert(a.slot==b.slot && a.created==b.created && a.reused==b.reused);
    assert(a.flow_direction==b.flow_direction && !memcmp(a.entry,b.entry,sizeof *a.entry));
    assert(!product_flow_entry_set_decision(prepared,a.entry,&p.policy,1,91,7));
    assert(!product_flow_entry_set_decision(reference,b.entry,&p.policy,1,91,7));
    const product_flow_entry_t *interior=(const product_flow_entry_t *)((const char *)a.entry+1);
    assert(product_flow_entry_set_decision(prepared,interior,&p.policy,1,91,7)
           ==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT);
  }
  const product_flow_entry_t *a=product_flow_runtime_entry(prepared,0);
  const product_flow_entry_t *b=product_flow_runtime_entry(prepared,1);
  assert(a->packets==4 && a->bytes==170 && a->side_packets[0]==3 && a->side_packets[1]==1);
  assert(b->packets==2 && b->bytes==85 && b->side_packets[0]==1 && b->side_packets[1]==1);
  before=product_flow_runtime_snapshot(prepared);after=product_flow_runtime_snapshot(reference);
  assert(!memcmp(&before,&after,sizeof before));
  prefetch(prepared,&keys[0]);
  assert(!product_flow_runtime_flush(prepared));
  prefetch(prepared,&keys[0]);
  assert(!product_flow_entry_current_incarnation(prepared,&keys[0],1,7));
  product_flow_entry_observation_t fresh;
  observe(prepared,&keys[0],packet(3,64,7),&fresh);
  assert(fresh.created && fresh.slot==0 && fresh.entry->incarnation>2);
  assert(product_flow_runtime_snapshot(prepared).allocated_bytes==before.allocated_bytes);
  product_flow_runtime_destroy(prepared);product_flow_runtime_destroy(reference);
}

static void mixed_capacity(void) {
  product_flow_runtime_t *runtime=NULL;
  assert(product_flow_runtime_create(&runtime,0,2,1,3)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_owner_assignment_t keys[3];
  product_flow_entry_observation_t o;
  for(unsigned protocol=0;protocol<3;protocol++) {
    product_packet_facts_t f=facts(6,protocol==0?6:protocol==1?17:58,12345);
    f.icmp_identity_known=1;f.icmp_type=128;f.icmp_identifier=17;
    keys[protocol]=assign(f);
    /* Deliberate full-hash collisions on one owner exercise complete keys. */
    keys[protocol].execution_owner=0;keys[protocol].canonical_hash=UINT64_C(0x123400001234);
    observe(runtime,&keys[protocol],packet(3,64,1),&o);
    assert(o.created && o.slot==protocol);
  }
  product_flow_runtime_snapshot_t s=product_flow_runtime_snapshot(runtime);
  assert(s.capacity==3 && s.active_entries==3 && s.high_watermark==3);
  assert(s.allocated_bytes>=3*sizeof(product_flow_entry_t));
  for(unsigned protocol=0;protocol<3;protocol++) {
    assert(s.protocol[protocol].active==1 && s.protocol[protocol].creates==1);
    product_owner_assignment_t hit=keys[protocol];
    /* Reserved/irrelevant bytes cannot split a typed identity. */
    if(protocol==2)hit.key.transport.query.reserved=65535;
    else hit.key.query_class=255;
    hit.source_is_a^=1;
    observe(runtime,&hit,packet(1,80,2),&o);
    assert(o.reused && o.slot==protocol && o.flow_direction==2);
    assert(o.entry->side_packets[0]==1 && o.entry->side_packets[1]==1);
    assert(o.entry->side_bytes[0]==64 && o.entry->side_bytes[1]==80);
    product_owner_assignment_t miss=keys[protocol];
    if(protocol==2)miss.key.transport.query.identifier++;
    else miss.key.transport.ports.a++;
    product_flow_entry_packet_t p=packet(3,64,3);
    product_packet_facts_t f=facts(miss.key.ip_family,miss.key.protocol,0);
    if(protocol==2) {
      f.l4_status=PRODUCT_PACKET_L4_OTHER_TERMINAL;
      f.icmp_identity_known=1;f.icmp_identifier=miss.key.transport.query.identifier;
      f.icmp_type=128;
    }
    p.facts=&f;
    assert(product_flow_entry_observe(runtime,&miss,&p,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED);
    assert(!o.entry && !o.created);
    assert(product_flow_entry_observe(runtime,&miss,&p,1,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
  }
  s=product_flow_runtime_snapshot(runtime);
  assert(s.allocation_count==3 && s.reuse_count==3 && s.capacity_rejection_count==3 && s.early_drop_count==3);
  for(unsigned protocol=0;protocol<3;protocol++)
    assert(s.protocol[protocol].hits==1 && s.protocol[protocol].capacity_misses==1);
  uint64_t old=product_flow_runtime_entry(runtime,0)->incarnation;
  product_flow_runtime_flush(runtime);
  assert(!product_flow_runtime_entry(runtime,0));
  observe(runtime,&keys[0],packet(3,64,4),&o);
  assert(o.created && o.slot==0 && o.entry->incarnation>old);
  assert(product_flow_runtime_snapshot(runtime).capacity==3);
  product_flow_runtime_destroy(runtime);
  runtime=NULL;
  assert(product_flow_runtime_create(&runtime,0,2,2,3)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_entry_packet_t stale=packet(3,64,5);
  assert(product_flow_entry_observe(runtime,&keys[0],&stale,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
  assert(!product_flow_entry_pool_active_count(runtime));
  assert(product_flow_runtime_snapshot(runtime).revision_mismatch_count==1);
  product_flow_runtime_destroy(runtime);
}

static uint32_t ended_slot;
static uint64_t ended_incarnation;
static void record_uid_replacement(void *context,const product_flow_entry_t *entry,
                                   uint32_t slot,product_flow_end_reason_t reason) {
  (void)context;assert(reason==PRODUCT_FLOW_END_REPLACED);
  ended_slot=slot;ended_incarnation=entry->incarnation;
}

static void unknown_uid_enrichment(void) {
  product_packet_facts_t f=facts(4,17,32111);
  product_owner_assignment_t a=assign(f);
  product_flow_runtime_t *pool=NULL;
  product_flow_entry_observation_t o;
  assert(product_flow_runtime_create(&pool,a.execution_owner,2,1,16)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(product_flow_runtime_set_end_callback(pool,record_uid_replacement,NULL)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_entry_packet_t p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,72,10);
  p.uid=PRODUCT_FLOW_ENTRY_UID_UNKNOWN;p.facts=&f;
  assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_DROP,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
  assert(!product_flow_entry_enrich_uid(pool,&a,1,1,12345,11));
  assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.created && o.entry->uid==PRODUCT_FLOW_ENTRY_UID_UNKNOWN);
  const product_flow_entry_t *entry=o.entry;
  uint64_t incarnation=entry->incarnation;
  product_packet_facts_t reply=f;
  unsigned char address[16];memcpy(address,reply.source_address,16);
  memcpy(reply.source_address,reply.destination_address,16);
  memcpy(reply.destination_address,address,16);
  unsigned port=reply.source_port;reply.source_port=reply.destination_port;
  reply.destination_port=port;
  product_owner_assignment_t reverse=assign(reply);
  product_flow_entry_packet_t returned=packet(PRODUCT_FLOW_ENTRY_DIRECTION_INPUT,72,10);
  returned.uid=PRODUCT_FLOW_ENTRY_UID_UNKNOWN;returned.facts=&reply;
  assert(product_flow_entry_observe_existing(pool,&reverse,&returned,
      PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,incarnation,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.reused && o.entry->incarnation==incarnation && entry->side_packets[1]==1);
  assert(product_flow_entry_current_incarnation(pool,&a,1,11)==incarnation);
  assert(!product_flow_entry_enrich_uid(pool,&a,2,incarnation,12345,11));
  assert(!product_flow_entry_enrich_uid(pool,&a,1,incarnation+1,12345,11));
  assert(product_flow_entry_enrich_uid(pool,&a,1,incarnation,12345,11)==1);
  assert(entry->uid==12345 && entry->packets==2 && entry->bytes==144);
  prefetch(pool,&a);
  assert(product_flow_entry_enrich_uid(pool,&a,1,incarnation,23456,12)==2);
  assert(entry->uid==12345);
  assert(!product_flow_entry_current_incarnation(pool,&a,1,12));
  assert(ended_incarnation==incarnation);
  prefetch(pool,&a);
  assert(product_flow_runtime_release_end(pool,ended_slot,1,incarnation,
      PRODUCT_FLOW_END_REPLACED)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_runtime_flush(pool);
  product_flow_runtime_destroy(pool);
}

static void stale_return_after_uid_replacement(void) {
  product_packet_facts_t outbound=facts(4,17,45774);
  product_packet_facts_t reply=outbound;
  unsigned char address[16];memcpy(address,reply.source_address,16);
  memcpy(reply.source_address,reply.destination_address,16);
  memcpy(reply.destination_address,address,16);
  unsigned port=reply.source_port;reply.source_port=reply.destination_port;
  reply.destination_port=port;
  product_owner_assignment_t a=assign(outbound),r=assign(reply);
  product_flow_runtime_t *pool=NULL;
  product_flow_entry_observation_t o;
  assert(product_flow_runtime_create(&pool,a.execution_owner,2,1,16)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(product_flow_runtime_set_end_callback(pool,record_uid_replacement,NULL)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_entry_packet_t p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,72,10);
  p.uid=PRODUCT_FLOW_ENTRY_UID_UNKNOWN;p.facts=&outbound;
  assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.created);
  uint64_t old=o.entry->incarnation;
  assert(product_flow_entry_enrich_uid(pool,&a,1,old,12630,10)==1);
  assert(product_flow_entry_enrich_uid(pool,&a,1,old,12631,11)==2);
  assert(!product_flow_entry_current_incarnation(pool,&a,1,11));
  product_flow_entry_packet_t returned=packet(PRODUCT_FLOW_ENTRY_DIRECTION_INPUT,72,11);
  returned.uid=12630;returned.facts=&reply;
  assert(product_flow_entry_observe_existing(pool,&r,&returned,
      PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,old,&o)==PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
  assert(!product_flow_entry_current_incarnation(pool,&a,1,11));
  assert(product_flow_runtime_release_end(pool,ended_slot,1,old,
      PRODUCT_FLOW_END_REPLACED)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  p.timestamp=12;
  assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.created && o.entry->uid==PRODUCT_FLOW_ENTRY_UID_UNKNOWN && o.entry->incarnation!=old);
  uint64_t current=o.entry->incarnation;
  returned.timestamp=13;
  assert(product_flow_entry_observe_existing(pool,&r,&returned,
      PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,old,&o)==PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
  assert(product_flow_entry_current_incarnation(pool,&a,1,13)==current);
  assert(product_flow_entry_enrich_uid(pool,&a,1,current,12631,12)==1);
  assert(product_flow_entry_observe_existing(pool,&r,&returned,
      PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,old,&o)==PRODUCT_FLOW_ENTRY_STATUS_NOT_FOUND);
  returned.uid=12631;
  assert(product_flow_entry_observe_existing(pool,&r,&returned,
      PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,current,&o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(o.reused && o.entry->incarnation==current && o.entry->uid==12631);
  assert(product_flow_runtime_close(pool,o.slot,1,current,
      PRODUCT_FLOW_END_REPLACED)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(product_flow_runtime_release_end(pool,ended_slot,1,current,
      PRODUCT_FLOW_END_REPLACED)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  assert(product_flow_runtime_flush(pool)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  product_flow_runtime_destroy(pool);
}

int main(void) {
  prepared_window_order();
  unknown_uid_enrichment();
  stale_return_after_uid_replacement();
  product_flow_runtime_t *invalid=NULL;
  assert(product_flow_runtime_create(&invalid,0,2,1,0)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT && !invalid);
  assert(product_flow_runtime_create(&invalid,0,2,1,UINT32_MAX)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT && !invalid);
  assert(product_flow_runtime_create(&invalid,2,2,1,3)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT && !invalid);
  assert(product_flow_runtime_create(&invalid,0,2,0,3)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT && !invalid);
  mixed_capacity();
  /* S221: Echo queries share FlowEntry storage with TCP and UDP. */
  for (unsigned family=4;family<=6;family+=2) {
    product_packet_facts_t echo=facts(family,family==4?1:58,0);
    echo.icmp_identity_known=1;echo.icmp_type=family==4?8:128;
    echo.icmp_identifier=321;
    product_owner_assignment_t query=assign(echo);
    assert(query.key.kind==PRODUCT_OWNER_KEY_ICMP_QUERY);
    product_flow_runtime_t *echo_pool=NULL;
    product_flow_entry_observation_t echo_observation;
    assert(product_flow_runtime_create(&echo_pool,query.execution_owner,2,1,128)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    observe(echo_pool,&query,packet(3,64,1),&echo_observation);
    assert(echo_observation.created);
    product_flow_runtime_destroy(echo_pool);
  }
  for(unsigned family=4;family<=6;family+=2)for(unsigned protocol=6;protocol<=17;protocol+=11) {
    product_packet_facts_t f=facts(family,protocol,40000);
    product_owner_assignment_t a=assign(f),reply=reverse(f);
    product_flow_runtime_t *pool=NULL;
    product_flow_entry_observation_t o;
    assert(product_flow_runtime_create(&pool,a.execution_owner,2,1,128)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    product_flow_entry_packet_t p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,120,10);
    assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_DROP,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
    assert(!o.entry && !product_flow_runtime_snapshot(pool).active_entries && !product_flow_runtime_snapshot(pool).allocation_count);
    /* A reverse/midstream packet, not the earlier dropped packet, defines ORIG. */
    p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_INPUT,80,11);observe(pool,&reply,p,&o);
    const product_flow_entry_t *entry=o.entry;
    assert(o.created && o.flow_direction==PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG);
    assert(entry->origin_is_endpoint_a==reply.source_is_a && entry->flow_origin_device_direction==1);
    assert(entry->policy_revision==0 && entry->decision==PRODUCT_FLOW_ENTRY_DECISION_NONE);
    p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,120,12);p.uid=20002;p.network_context=99;p.policy=(product_flow_policy_identity_t){1,1,101};
    observe(pool,&a,p,&o);
    assert(o.reused && o.entry==entry && o.flow_direction==PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY && o.revision_invalidated);
    assert(entry->uid==10001 && entry->network_context==7 && entry->packets==2 && entry->bytes==200);
    assert(product_flow_entry_set_decision(pool,entry,&p.policy,PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT,9001,77)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    product_flow_entry_t before=*entry;
    product_flow_policy_identity_t old=p.policy;
    p=packet(3,100,13);p.policy=(product_flow_policy_identity_t){1,2,202};
    /* Publishing elsewhere has no pool API and cannot mutate this entry. */
    assert(memcmp(&before,entry,sizeof(before))==0);
    assert(product_flow_entry_set_decision(pool,entry,&p.policy,1,1,1)==PRODUCT_FLOW_ENTRY_STATUS_STALE_REVISION);
    observe(pool,&reply,p,&o);
    assert(o.revision_invalidated && o.entry==entry && entry->decision==PRODUCT_FLOW_ENTRY_DECISION_NONE);
    assert(entry->packets==3 && entry->bytes==300 && entry->first_seen==11 && entry->flow_origin_device_direction==1);
    assert(entry->origin_is_endpoint_a==reply.source_is_a && o.flow_direction==1);
    before=*entry;
    p=packet(0,90,14);p.policy=(product_flow_policy_identity_t){1,2,303};
    assert(memcmp(&before,entry,sizeof(before))==0);
    observe(pool,&a,p,&o);
    assert(o.revision_invalidated && entry->policy_snapshot_hash==303 && entry->packets==4 && entry->bytes==390);
    p.timestamp=15;observe(pool,&a,p,&o);assert(!o.revision_invalidated && entry->packets==5);
    /* A previously acquired old snapshot may finish; the next new packet
     * must invalidate its decision again, never reuse a stale identity. */
    product_flow_policy_identity_t current=p.policy;
    p.policy=old;p.timestamp=16;observe(pool,&a,p,&o);
    assert(o.revision_invalidated && entry->policy_revision==1);
    assert(product_flow_entry_set_decision(pool,entry,&old,1,11,7)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    assert(product_flow_entry_set_decision(pool,entry,&current,1,22,8)==PRODUCT_FLOW_ENTRY_STATUS_STALE_REVISION);
    p.policy=current;p.timestamp=17;observe(pool,&a,p,&o);
    assert(o.revision_invalidated && entry->decision==0 && entry->winner_rule_id==0 && entry->reason_id==0);
    p.policy.generation=2;p.timestamp=18;
    assert(product_flow_entry_observe(pool,&a,&p,0,&o)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_GENERATION);
    assert(entry->policy_generation==1 && entry->policy_revision==2 && entry->policy_snapshot_hash==303);
    assert(entry->packets==7 && entry->bytes==660 && entry->first_seen==11 && entry->uid==10001);
    p.policy.generation=1;
    before=*entry;
    assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_DROP,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
    assert(memcmp(&before,entry,sizeof(before))==0);
    product_flow_runtime_t *wrong=NULL;
    assert(product_flow_runtime_create(&wrong,a.execution_owner^1,2,1,128)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    assert(product_flow_entry_observe(wrong,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER);
    assert(!product_flow_runtime_snapshot(wrong).active_entries && product_flow_runtime_snapshot(wrong).wrong_owner_count==1);
    assert(product_flow_entry_set_decision(wrong,entry,&p.policy,PRODUCT_FLOW_ENTRY_DECISION_DROP,1,1)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT);
    assert(memcmp(&before,entry,sizeof(before))==0);
    product_flow_runtime_flush(pool);assert(!product_flow_runtime_snapshot(pool).active_entries && !entry->in_use);
    product_flow_runtime_destroy(wrong);
    product_flow_runtime_destroy(pool);
  }
  /* Fully equal endpoints stay ORIG even when device direction changes. */
  product_packet_facts_t f=facts(4,17,443);memcpy(f.destination_address,f.source_address,16);
  product_owner_assignment_t a=assign(f),r=reverse(f);
  assert(a.source_is_a==r.source_is_a);
  product_flow_runtime_t *pool=NULL;product_flow_entry_observation_t o;
  assert(product_flow_runtime_create(&pool,a.execution_owner,2,1,128)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  observe(pool,&a,packet(1,28,1),&o);const product_flow_entry_t *same=o.entry;
  observe(pool,&r,packet(3,28,2),&o);assert(o.entry==same && o.flow_direction==1 && same->flow_origin_device_direction==1);
  /* A hash collision still compares the complete typed key. */
  product_packet_facts_t other=facts(6,17,40001);product_owner_assignment_t collision=assign(other);
  while(collision.execution_owner!=a.execution_owner){other.source_port++;collision=assign(other);}
  collision.canonical_hash=a.canonical_hash;
  observe(pool,&collision,packet(3,48,3),&o);
  assert(o.created && o.entry!=same && product_flow_runtime_snapshot(pool).active_entries==2);
  observe(pool,&a,packet(3,28,4),&o);assert(o.entry==same && same->packets==3);
  product_flow_runtime_flush(pool);
  /* Fixed capacity rejects the new identity without replacing existing state. */
  unsigned port=10000;
  for(unsigned i=0;i<128;i++) {
    do {f=facts(4,6,port++);a=assign(f);}while(a.execution_owner!=product_flow_runtime_snapshot(pool).worker_index);
    observe(pool,&a,packet(3,40,i),&o);assert(o.created);
  }
  product_flow_entry_t first=*product_flow_runtime_entry(pool,0);
  do {f=facts(4,6,port++);a=assign(f);}while(a.execution_owner!=product_flow_runtime_snapshot(pool).worker_index);
  product_flow_entry_packet_t p=packet(3,40,100);
  p.facts=&f;
  assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED);
  assert(product_flow_runtime_snapshot(pool).active_entries==128 && memcmp(&first,product_flow_runtime_entry(pool,0),sizeof(first))==0);
  a.valid=0;assert(product_flow_entry_observe(pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  product_flow_runtime_flush(pool);assert(product_flow_entry_pool_active_count(pool)==0);
  product_flow_runtime_destroy(pool);
  puts("S208/S209/S221 owner-local FlowRuntime, typed pool and snapshot properties: PASS");
  return 0;
}
