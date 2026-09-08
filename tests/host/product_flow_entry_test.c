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
  return (product_flow_entry_packet_t){.uid=10001,.network_context=7,.packet_bytes=bytes,.device_direction=direction,.timestamp=time};
}
static void observe(product_flow_entry_pool_t *pool,const product_owner_assignment_t *a,
                    product_flow_entry_packet_t p,product_flow_entry_observation_t *o) {
  assert(product_flow_entry_observe(pool,a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,o)==PRODUCT_FLOW_ENTRY_STATUS_OK);
}
int main(void) {
  for(unsigned family=4;family<=6;family+=2)for(unsigned protocol=6;protocol<=17;protocol+=11) {
    product_packet_facts_t f=facts(family,protocol,40000);
    product_owner_assignment_t a=assign(f),reply=reverse(f);
    product_flow_entry_pool_t pool;
    product_flow_entry_observation_t o;
    assert(product_flow_entry_pool_init(&pool,a.execution_owner,2)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    product_flow_entry_packet_t p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,120,10);
    assert(product_flow_entry_observe(&pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_DROP,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
    assert(!o.entry && !pool.active_entries && !pool.allocation_count);
    /* A reverse/midstream packet, not the earlier dropped packet, defines ORIG. */
    p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_INPUT,80,11);observe(&pool,&reply,p,&o);
    product_flow_entry_t *entry=o.entry;
    assert(o.created && o.flow_direction==PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_ORIG);
    assert(entry->origin_is_endpoint_a==reply.source_is_a && entry->flow_origin_device_direction==1);
    assert(entry->policy_revision==0 && entry->decision==PRODUCT_FLOW_ENTRY_DECISION_NONE);
    assert(product_flow_entry_publish_revision(&pool,1,101)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    p=packet(PRODUCT_FLOW_ENTRY_DIRECTION_OUTPUT,120,12);p.uid=20002;p.network_context=99;
    observe(&pool,&a,p,&o);
    assert(o.reused && o.entry==entry && o.flow_direction==PRODUCT_FLOW_ENTRY_FLOW_DIRECTION_REPLY && o.revision_invalidated);
    assert(entry->uid==10001 && entry->network_context==7 && entry->packets==2 && entry->bytes==200);
    assert(product_flow_entry_set_decision(&pool,entry,PRODUCT_FLOW_ENTRY_DECISION_PASS_NEXT,9001,77)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    product_flow_entry_t before=*entry;
    assert(product_flow_entry_publish_revision(&pool,2,202)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    assert(memcmp(&before,entry,sizeof(before))==0);
    observe(&pool,&reply,packet(3,100,13),&o);
    assert(o.revision_invalidated && o.entry==entry && entry->decision==PRODUCT_FLOW_ENTRY_DECISION_NONE);
    assert(entry->packets==3 && entry->bytes==300 && entry->first_seen==11 && entry->flow_origin_device_direction==1);
    assert(entry->origin_is_endpoint_a==reply.source_is_a && o.flow_direction==1);
    before=*entry;
    assert(product_flow_entry_publish_revision(&pool,2,303)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    assert(memcmp(&before,entry,sizeof(before))==0);
    observe(&pool,&a,packet(0,90,14),&o);
    assert(o.revision_invalidated && entry->policy_snapshot_hash==303 && entry->packets==4 && entry->bytes==390);
    assert(product_flow_entry_publish_revision(&pool,2,303)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    observe(&pool,&a,packet(1,90,15),&o);assert(!o.revision_invalidated && entry->packets==5);
    assert(product_flow_entry_publish_revision(&pool,1,101)==PRODUCT_FLOW_ENTRY_STATUS_REVISION_NOT_ADVANCING);
    before=*entry;
    assert(product_flow_entry_observe(&pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_DROP,&o)==PRODUCT_FLOW_ENTRY_STATUS_EARLY_DROP);
    assert(memcmp(&before,entry,sizeof(before))==0);
    product_flow_entry_pool_t wrong;
    assert(product_flow_entry_pool_init(&wrong,a.execution_owner^1,2)==PRODUCT_FLOW_ENTRY_STATUS_OK);
    assert(product_flow_entry_observe(&wrong,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_WRONG_OWNER);
    assert(!wrong.active_entries && wrong.wrong_owner_count==1);
    assert(product_flow_entry_set_decision(&wrong,entry,PRODUCT_FLOW_ENTRY_DECISION_DROP,1,1)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_ARGUMENT);
    assert(memcmp(&before,entry,sizeof(before))==0);
    product_flow_entry_pool_flush(&pool);assert(!pool.active_entries && !entry->in_use);
  }
  /* Fully equal endpoints stay ORIG even when device direction changes. */
  product_packet_facts_t f=facts(4,17,443);memcpy(f.destination_address,f.source_address,16);
  product_owner_assignment_t a=assign(f),r=reverse(f);
  assert(a.source_is_a==r.source_is_a);
  product_flow_entry_pool_t pool;product_flow_entry_observation_t o;
  assert(product_flow_entry_pool_init(&pool,a.execution_owner,2)==PRODUCT_FLOW_ENTRY_STATUS_OK);
  observe(&pool,&a,packet(1,28,1),&o);product_flow_entry_t *same=o.entry;
  observe(&pool,&r,packet(3,28,2),&o);assert(o.entry==same && o.flow_direction==1 && same->flow_origin_device_direction==1);
  /* A hash collision still compares the complete typed key. */
  product_packet_facts_t other=facts(6,17,40001);product_owner_assignment_t collision=assign(other);
  while(collision.execution_owner!=a.execution_owner){other.source_port++;collision=assign(other);}
  collision.canonical_hash=a.canonical_hash;
  observe(&pool,&collision,packet(3,48,3),&o);
  assert(o.created && o.entry!=same && pool.active_entries==2);
  observe(&pool,&a,packet(3,28,4),&o);assert(o.entry==same && same->packets==3);
  product_flow_entry_pool_flush(&pool);
  /* Fixed capacity rejects the new identity without replacing existing state. */
  unsigned port=10000;
  for(unsigned i=0;i<PRODUCT_FLOW_ENTRY_MAX_ENTRIES;i++) {
    do {f=facts(4,6,port++);a=assign(f);}while(a.execution_owner!=pool.worker_index);
    observe(&pool,&a,packet(3,40,i),&o);assert(o.created);
  }
  product_flow_entry_t first=pool.entries[0];
  do {f=facts(4,6,port++);a=assign(f);}while(a.execution_owner!=pool.worker_index);
  product_flow_entry_packet_t p=packet(3,40,100);
  assert(product_flow_entry_observe(&pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_CAPACITY_EXCEEDED);
  assert(pool.active_entries==64 && memcmp(&first,&pool.entries[0],sizeof(first))==0);
  a.valid=0;assert(product_flow_entry_observe(&pool,&a,&p,PRODUCT_FLOW_ENTRY_VERDICT_PASS_NEXT,&o)==PRODUCT_FLOW_ENTRY_STATUS_INVALID_PACKET);
  product_flow_entry_pool_flush(&pool);assert(product_flow_entry_pool_active_count(&pool)==0);
  puts("S208 owner-local typed FlowEntry mutation properties: PASS");
  return 0;
}
