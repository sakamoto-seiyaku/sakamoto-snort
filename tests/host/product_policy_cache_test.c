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
  uint64_t initial_hits=cache->hits, initial_misses=cache->misses;
  assert(product_l4_policy_match_cached(cache,view,packet,identity,position,&cached)==0);
  equivalent(&direct,&cached);
  if(cache->misses==initial_misses+1 && direct.subject_probes) {
#if defined(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
    assert(cached.subject_probes==direct.subject_probes);
#else
    assert(cached.subject_probes==2*direct.subject_probes);
#endif
  }
  uint64_t hits=cache->hits;
  assert(product_l4_policy_match_cached(cache,view,packet,identity,position,&cached)==0);
  equivalent(&direct,&cached);
  assert(!cached.probes && !cached.key_probes && !cached.subtable_probes);
#if defined(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
  if (direct.no_match_reason==PRODUCT_L4_POLICY_NO_MATCH_NO_SUBJECT
      || direct.no_match_reason==PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID
      || direct.no_match_reason==PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_FAMILY
      || direct.no_match_reason==PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_DIRECTION) {
    assert(cache->hits==initial_hits && cache->misses==initial_misses);
    return;
  }
#else
  (void)initial_hits; (void)initial_misses;
#endif
  assert(cache->hits==hits+1);
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
  warm(&cache,&old,&packet,&identity,0);
#if defined(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
  assert(cache.misses==8);
#else
  assert(cache.misses==9);
#endif
  uint64_t subject_misses=cache.misses;
  packet.uid=17;
  warm(&cache,&old,&packet,&identity,1); assert(cache.misses==subject_misses+1);
  warm(&cache,&old,&packet,&identity,2); assert(cache.misses==subject_misses+2);
  assert(cache.occupied==1 && cache.replacements==cache.misses-1);
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

#if defined(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
static void shared_prepared_facts(void)
{
  product_l4_policy_view_t old, changed;
  product_l4_policy_rule_t rules[4]={rule(101,1,2),rule(102,2,2),
                                    rule(103,3,2),rule(104,4,1)};
  rules[0].mode=1; rules[0].order=9; rules[0].reason_id=501;
  rules[0].expression_length=2;
  memcpy(rules[0].expression,(uint8_t[]){PRODUCT_EXPRESSION_CT_STATE,2},2);
  rules[1].expression_length=5;
  memcpy(rules[1].expression,(uint8_t[]){PRODUCT_EXPRESSION_APPLICATION_PROTOCOL,234,3,0,0},5); /* 1002 */
  rules[2].expression_length=2;
  memcpy(rules[2].expression,(uint8_t[]){PRODUCT_EXPRESSION_DOMAIN_LIST,0},2);
  assert(product_l4_policy_compile(&old,rules,4)==0);
  product_policy_cache_t cache={.capacity=1};
  product_policy_cache_identity_t identity={1,1,123,0};
  product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=17,
    .direction=3,.direction_known=1,.ports_available=1,.source_port=1234,.destination_port=443};
  product_l4_policy_prepared_query_t query={0};
  product_l4_policy_match_result_t direct, result;
  assert(product_l4_policy_match_prepared(&query,&packet,1,&result)
         ==PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT);
  assert(product_l4_policy_prepare(&old,&packet,&query)==0 && query.prepared);
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,1,&result)==0);
  assert(!result.evaluation && result.subject_probes==1 && cache.misses==1);
  packet.ct_state=1; packet.ct_state_known=1;
  packet.flow_direction=1; packet.flow_direction_known=1;
  packet.protocol_set_known=1; identity.flow_incarnation=1;
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,2,&result)==0);
  assert(result.rule_id==104 && result.subject_probes==0 && cache.misses==2);
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,2,&result)==0);
  assert(result.rule_id==104 && !result.probes && cache.hits==1);

  const product_l4_policy_packet_t transitions[]={
    {.ct_state=2,.ct_state_known=1},
    {.ct_state=2,.ct_state_known=0},
    {.ct_state=1,.ct_state_known=1,.protocol_set=UINT64_C(2),.protocol_set_known=0},
    {.ct_state=1,.ct_state_known=1,.protocol_set=UINT64_C(2),.protocol_set_known=1},
    {.ct_state=1,.ct_state_known=1,.protocol_set=UINT64_C(4),.protocol_set_known=1,.sni_result=PRODUCT_SNI_NAME,.domain_lists=1},
    {.ct_state=1,.ct_state_known=1,.protocol_set=UINT64_C(4),.protocol_set_known=1,.sni_result=PRODUCT_SNI_NAME},
    {.ct_state=1,.ct_state_known=1,.protocol_set=UINT64_C(4),.protocol_set_known=1,.sni_result=PRODUCT_SNI_ABSENT,.domain_lists=1},
    {.ct_state=1,.ct_state_known=1,.protocol_set=UINT64_C(4),.protocol_set_known=1,.domain_lists=1},
  };
  const uint64_t winners[]={101,104,104,102,103,104,104,104};
  for(unsigned n=0;n<sizeof transitions/sizeof transitions[0];++n) {
    packet.ct_state=transitions[n].ct_state; packet.ct_state_known=transitions[n].ct_state_known;
    packet.protocol_set=transitions[n].protocol_set; packet.protocol_set_known=transitions[n].protocol_set_known;
    packet.sni_result=transitions[n].sni_result; packet.domain_lists=transitions[n].domain_lists;
    uint64_t misses=cache.misses;
    assert(product_l4_policy_match_position(&old,&packet,2,&direct)==0);
    assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,2,&result)==0);
    equivalent(&direct,&result);
    assert(result.rule_id==winners[n] && result.subject_probes==0 && cache.misses==misses+1);
    if(n==0) assert(result.mode==1 && result.actual_action==1 && result.action==2
                   && result.order==9 && result.priority==1 && result.reason_id==501);
  }
  uint64_t misses=cache.misses;
  identity.flow_incarnation++;
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,2,&result)==0);
  assert(cache.misses==misses+1 && result.rule_id==104);
  packet.flow_direction_known=0;
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,2,&result)==0);
  assert(cache.misses==misses+2 && result.rule_id==104);
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,1,&result)==0);
  assert(cache.misses==misses+3 && !result.evaluation);

  rules[0].mode=0; packet.ct_state=2; packet.ct_state_known=1;
  assert(product_l4_policy_compile(&changed,rules,4)==0);
  identity.revision++; identity.snapshot_hash++;
  product_l4_policy_prepared_query_t newer={0};
  assert(product_l4_policy_prepare(&changed,&packet,&newer)==0);
  assert(product_l4_policy_match_prepared_cached(&cache,&newer,&packet,&identity,2,&result)==0);
  assert(result.rule_id==101 && result.actual_action==2 && result.subject_probes==1);
  identity.revision--; identity.snapshot_hash--;
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,2,&result)==0);
  assert(result.rule_id==101 && result.mode==1 && result.actual_action==1 && result.subject_probes==0);
}

static void prepared_no_match_and_errors(void)
{
  product_l4_policy_view_t empty, populated;
  product_l4_policy_rule_t r=rule(1,1,2);
  assert(product_l4_policy_compile(&empty,NULL,0)==0);
  assert(product_l4_policy_compile(&populated,&r,1)==0);
  product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.protocol=17,.ports_available=0};
  product_policy_cache_t cache={0};
  product_policy_cache_identity_t identity={1,2,3,4};
  product_l4_policy_prepared_query_t query={0};
  product_l4_policy_match_result_t result, direct;
  const unsigned reasons[]={PRODUCT_L4_POLICY_NO_MATCH_NO_SUBJECT,
    PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID,PRODUCT_L4_POLICY_NO_MATCH_UNKNOWN_UID,
    PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_FAMILY,PRODUCT_L4_POLICY_NO_MATCH_UNSUPPORTED_DIRECTION,
    PRODUCT_L4_POLICY_NO_MATCH_NO_SUBJECT};
  for(unsigned n=0;n<sizeof reasons/sizeof reasons[0];++n) {
    const product_l4_policy_view_t *view=n?&populated:&empty;
    packet.uid=17; packet.uid_known=1; packet.family=4; packet.direction=3; packet.direction_known=1;
    if(n==1) {packet.uid_known=0;packet.family=9;}
    if(n==2) packet.uid=UINT32_MAX;
    if(n==3) {packet.family=9;packet.direction=2;}
    if(n==4) packet.direction=2;
    if(n==5) packet.uid=18;
    assert(product_l4_policy_prepare(view,&packet,&query)==0);
    assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,0,&result)==0);
    assert(product_l4_policy_match_position(view,&packet,0,&direct)==0);
    equivalent(&direct,&result);
    assert(result.no_match_reason==reasons[n] && result.probe_limit==view->max_probes);
    assert(!result.probes && !result.subtable_probes && !result.key_probes);
    assert(cache.hits==0 && cache.misses==0 && cache.occupied==0);
  }
  assert(product_l4_policy_prepare(NULL,&packet,&query)==PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT);
  assert(!query.prepared);
  assert(product_l4_policy_match_prepared(&query,&packet,0,&result)==PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT);
  assert(product_l4_policy_prepare(&populated,&packet,&query)==0);
  uint32_t probes=query.subject_probes;
  assert(product_l4_policy_match_prepared_cached(&cache,&query,&packet,&identity,3,&result)==PRODUCT_L4_POLICY_STATUS_INVALID_ARGUMENT);
  assert(query.subject_probes==probes && !cache.misses);
}
#endif

int main(void)
{
#if defined(SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT)
  shared_prepared_facts(); prepared_no_match_and_errors();
#endif
  winner_dependency(); identities_and_pressure(); lifecycle();
  puts("complete result cache, identities, collisions and Flow reuse: PASS");
}
