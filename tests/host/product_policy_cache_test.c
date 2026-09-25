/* SPDX-License-Identifier: Apache-2.0 */
#include "product_l4_policy.h"
#include "product_flow_entry.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_l4_policy_rule_t rule(unsigned id, unsigned priority, unsigned action)
{
  return (product_l4_policy_rule_t){.uid=17,.rule_id=id,.reason_id=id,
    .priority=priority,.action=action,.network_context_id=UINT32_MAX,
    .ifindex=UINT32_MAX,.source_port_last=65535,.destination_port_last=65535};
}
static void winner_dependency(void)
{
  product_l4_policy_view_t view;
  product_l4_policy_rule_t rules[2]={rule(1,1,2),rule(2,2,1)};
  rules[0].expression_length=2;
  memcpy(rules[0].expression,(uint8_t[]){PRODUCT_EXPRESSION_CT_STATE,2},2);
  assert(product_l4_policy_compile(&view,rules,2)==0);
  product_policy_cache_t cache={0};
  product_policy_cache_identity_t id={.generation=1,.revision=1,.snapshot_hash=123,.flow_incarnation=1};
  product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=17,
    .direction=3,.direction_known=1,.ct_state=1,.ct_state_known=1};
  product_l4_policy_match_result_t result;
  for(unsigned i=0;i<2;++i) {
    assert(product_l4_policy_match_cached(&cache,&view,&packet,&id,0,&result)==0);
    assert(result.rule_id==2 && result.actual_action==1 && result.winner_rank==2);
  }
  assert(cache.hits==1 && cache.misses==1);
  packet.ct_state=2;
  assert(product_l4_policy_match_cached(&cache,&view,&packet,&id,0,&result)==0);
  assert(result.rule_id==1 && result.actual_action==2 && cache.misses==2);

}

static void equivalent(const product_l4_policy_match_result_t *a,
                       const product_l4_policy_match_result_t *b)
{
  assert(a->evaluation==b->evaluation && a->stage_verdict==b->stage_verdict);
  assert(a->rule_id==b->rule_id && a->winner_rank==b->winner_rank);
  assert(a->action==b->action && a->actual_action==b->actual_action && a->mode==b->mode);
  assert(a->priority==b->priority && a->order==b->order && a->reason_id==b->reason_id);
  assert(a->no_match_reason==b->no_match_reason);
}

static void warm(product_policy_cache_t *cache, const product_l4_policy_view_t *view,
                 product_l4_policy_packet_t *packet, product_policy_cache_identity_t *identity,
                 product_l4_policy_position_t position)
{
  product_l4_policy_match_result_t direct, cached;
  assert(product_l4_policy_match_position(view,packet,position,&direct)==0);
  assert(product_l4_policy_match_cached(cache,view,packet,identity,position,&cached)==0);
  equivalent(&direct,&cached);
  uint64_t hits=cache->hits;
  assert(product_l4_policy_match_cached(cache,view,packet,identity,position,&cached)==0);
  equivalent(&direct,&cached);
  assert(cache->hits==hits+1 && !cached.probes && !cached.key_probes && !cached.subtable_probes);
}

static void identities_and_pressure(void)
{
  product_l4_policy_view_t old, changed;
  product_l4_policy_rule_t r=rule(91,2,2);
  r.mode=1; r.expression_length=2;
  memcpy(r.expression,(uint8_t[]){PRODUCT_EXPRESSION_FLOW_DIRECTION,2},2);
  assert(product_l4_policy_compile(&old,&r,1)==0);
  r.mode=0;
  assert(product_l4_policy_compile(&changed,&r,1)==0);
  product_policy_cache_t cache={.capacity=1}, peer={0};
  product_policy_cache_identity_t identity={1,2,3,4};
  product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=17,
    .direction=3,.direction_known=1,.flow_direction=2,.flow_direction_known=1};
  warm(&cache,&old,&packet,&identity,0);
  assert(peer.hits==0 && peer.misses==0);
  /* Same revision, different hash must not retain observe ALLOW. */
  identity.snapshot_hash++;
  warm(&cache,&changed,&packet,&identity,0);
  assert(cache.misses==2);
  /* Protected old reader may finish after a newer snapshot was queried. */
  identity.snapshot_hash--;
  warm(&cache,&old,&packet,&identity,0);
  assert(cache.misses==3);
  identity.generation++;
  warm(&cache,&old,&packet,&identity,0); assert(cache.misses==4);
  identity.revision++;
  warm(&cache,&old,&packet,&identity,0); assert(cache.misses==5);
  identity.flow_incarnation++;
  warm(&cache,&old,&packet,&identity,0); assert(cache.misses==6);
  /* NoMatch, direction and subject changes must each be complete queries. */
  packet.flow_direction_known=0;
  warm(&cache,&old,&packet,&identity,0); assert(cache.misses==7);
  packet.flow_direction_known=1; packet.flow_direction=1;
  warm(&cache,&old,&packet,&identity,0); assert(cache.misses==8);
  packet.uid=18;
  warm(&cache,&old,&packet,&identity,0); assert(cache.misses==9);
  packet.uid=17;
  warm(&cache,&old,&packet,&identity,1); assert(cache.misses==10);
  warm(&cache,&old,&packet,&identity,2); assert(cache.misses==11);
  assert(cache.occupied==1 && cache.replacements==10);
  product_l4_policy_match_result_t result;
  uint64_t misses=cache.misses;
  assert(product_l4_policy_match_cached(&cache,NULL,&packet,&identity,0,&result)==PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT);
  assert(cache.misses==misses);
}

static void end_callback(void *context, const product_flow_entry_t *entry,
                         uint32_t slot, product_flow_end_reason_t reason)
{
  (void)entry; (void)slot; (void)reason;
  ++*(unsigned *)context;
}

static void lifecycle(void)
{
  product_flow_runtime_t *runtime=NULL;
  unsigned ends=0;
  assert(product_flow_runtime_create(&runtime,0,1,1,1)==0);
  assert(product_flow_runtime_set_end_callback(runtime,end_callback,&ends)==0);
  product_l4_policy_view_t view;
  product_l4_policy_rule_t rules[2]={rule(1,1,2),rule(2,2,1)};
  rules[0].expression_length=2;
  memcpy(rules[0].expression,(uint8_t[]){PRODUCT_EXPRESSION_CT_STATE,2},2);
  assert(product_l4_policy_compile(&view,rules,2)==0);
  product_policy_cache_t cache={.capacity=1};
  product_packet_facts_t facts={.l3_status=PRODUCT_PACKET_L3_COMPLETE,
    .l4_status=PRODUCT_PACKET_L4_COMPLETE,.ip_family=4,.protocol=17,
    .source_port=40000,.destination_port=443,.packet_length=48,.transport_length=28,
    .l4_header_length=8};
  facts.source_address[0]=10;facts.source_address[3]=1;
  facts.destination_address[0]=10;facts.destination_address[3]=2;
  product_owner_assignment_t assignment;
  product_worker_layout_t layout={1,123};
  assert(product_owner_assign(&layout,&facts,&assignment)==PRODUCT_PACKET_OK);
  product_flow_entry_packet_t input={.facts=&facts,.policy={1,1,123},.uid=17,
    .device_direction=3,.packet_bytes=48,.timestamp=1};
  product_flow_entry_observation_t observation;
  assert(product_flow_entry_observe(runtime,&assignment,&input,0,&observation)==0);
  assert(observation.created);
  product_policy_cache_identity_t identity={1,1,123,observation.entry->incarnation};
  product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=17,
    .direction=3,.direction_known=1,.ct_state=observation.tracker.facts.state,
    .ct_state_known=1,.flow_direction=observation.tracker.facts.direction,.flow_direction_known=1};
  warm(&cache,&view,&packet,&identity,2);
  uint32_t slot=observation.slot;
  uint64_t incarnation=observation.entry->incarnation;
  assert(product_flow_runtime_close(runtime,slot,1,incarnation,PRODUCT_FLOW_END_CLOSED)==0);
  assert(ends==1);
  assert(product_flow_runtime_release_end(runtime,slot,1,incarnation,PRODUCT_FLOW_END_CLOSED)==0);
  input.timestamp=2;
  assert(product_flow_entry_observe(runtime,&assignment,&input,0,&observation)==0);
  assert(observation.created && observation.slot==slot && observation.entry->incarnation!=incarnation);
  assert(observation.entry->packets==1);
  identity.flow_incarnation=observation.entry->incarnation;
  warm(&cache,&view,&packet,&identity,2);
  assert(cache.misses==2);
  /* Publication retains cumulative packets and the same live Flow instance. */
  input.policy.revision=2;input.policy.snapshot_hash=456;input.timestamp=3;
  assert(product_flow_entry_observe(runtime,&assignment,&input,0,&observation)==0);
  assert(observation.reused && observation.entry->incarnation==identity.flow_incarnation);
  assert(observation.entry->packets==2 && observation.entry->bytes==96);
  identity.revision=2;identity.snapshot_hash=456;
  warm(&cache,&view,&packet,&identity,2);
  assert(cache.misses==3);
  product_flow_runtime_destroy(runtime);
}

int main(void)
{
  winner_dependency(); identities_and_pressure(); lifecycle();
  puts("complete result cache, identities, collisions and Flow reuse: PASS");
}
