/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_l4_policy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static product_l4_policy_rule_t rule(uint64_t id, uint32_t priority, uint8_t action)
{
  return (product_l4_policy_rule_t) {
    .rule_id=id, .uid=17, .priority=priority, .reason_id=(uint32_t)id,
    .network_context_id=UINT32_MAX, .ifindex=UINT32_MAX, .action=action,
    .source_port_last=65535, .destination_port_last=65535,
  };
}

static void placement_and_rejection(void)
{
  product_l4_policy_view_t view;
  product_l4_policy_rule_t rules[3]={rule(1,1,2),rule(2,2,1),rule(3,1,1)};
  rules[0].expression_length=5;
  memcpy(rules[0].expression,(uint8_t[]){13,2,14,2,1},5);
  /* An operand equal to a CT opcode is not a dynamic leaf. */
  rules[2].uid=18; rules[2].expression_length=5;
  memcpy(rules[2].expression,(uint8_t[]){7,13,0,0,0},5);
  assert(product_l4_policy_compile(&view,rules,3)==0);
  assert(product_l4_policy_requires_flow(&view,17));
  assert(!product_l4_policy_requires_flow(&view,18));
  assert(!product_l4_policy_requires_flow(&view,19));
  product_l4_policy_view_t old=view;
  const uint8_t invalid[][2]={{13,0},{13,4},{14,0},{14,3}};
  for(unsigned i=0;i<sizeof invalid/sizeof invalid[0];++i) {
    rules[0].expression_length=2;
    memcpy(rules[0].expression,invalid[i],2);
    assert(product_l4_policy_compile(&view,rules,3)==PRODUCT_L4_POLICY_STATUS_INVALID_RULE);
    assert(!memcmp(&view,&old,sizeof view));
  }
  rules[0].expression_length=1;rules[0].expression[0]=13;
  assert(product_l4_policy_compile(&view,rules,3)==PRODUCT_L4_POLICY_STATUS_INVALID_RULE);
  assert(!memcmp(&view,&old,sizeof view));
}

static product_packet_facts_t facts(unsigned family,unsigned protocol)
{
  product_packet_facts_t f={
    .l3_status=PRODUCT_PACKET_L3_COMPLETE,.l4_status=PRODUCT_PACKET_L4_COMPLETE,
    .ip_family=family,.protocol=protocol,.source_port=41000,.destination_port=443,
    .packet_length=40,.l4_header_length=20,.transport_length=20,.tcp_window=8192,
    .tcp_flags=2,.tcp_sequence=100,
  };
  f.source_address[15]=1;f.destination_address[15]=2;
  if(family==6) f.source_address[0]=f.destination_address[0]=0x20;
  return f;
}

static void reverse(product_packet_facts_t *f)
{
  uint8_t address[16];memcpy(address,f->source_address,16);
  memcpy(f->source_address,f->destination_address,16);
  memcpy(f->destination_address,address,16);
  uint16_t port=f->source_port;f->source_port=f->destination_port;f->destination_port=port;
}

static product_flow_entry_observation_t observe(product_flow_runtime_t *runtime,
  product_packet_facts_t *f, product_flow_policy_identity_t identity, unsigned device_direction)
{
  const product_worker_layout_t layout={1,123};
  product_owner_assignment_t assignment;
  assert(product_owner_assign(&layout,f,&assignment)==PRODUCT_PACKET_OK);
  product_flow_entry_packet_t packet={.facts=f,.policy=identity,.uid=17,
    .packet_bytes=f->packet_length,.device_direction=device_direction,.timestamp=1};
  product_flow_entry_observation_t observation;
  assert(product_flow_entry_observe(runtime,&assignment,&packet,0,&observation)==0);
  return observation;
}

static product_l4_policy_match_result_t match(const product_l4_policy_view_t *view,
  const product_packet_facts_t *f,const product_flow_entry_observation_t *o,unsigned direction)
{
  product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=f->ip_family,
    .protocol=f->protocol,.direction=direction,.direction_known=1,.ports_available=1,
    .source_port=f->source_port,.destination_port=f->destination_port,
    .ct_state=o->tracker.facts.state,.ct_state_known=o->tracker.facts.state!=0,
    .flow_direction=o->tracker.facts.direction,.flow_direction_known=o->tracker.facts.direction!=0};
  product_l4_policy_match_result_t result;
  assert(product_l4_policy_match(view,&packet,&result)==0);
  return result;
}

static void flow_changes(unsigned family,unsigned protocol,unsigned first_device_direction)
{
  product_flow_runtime_t *runtime=NULL;
  assert(product_flow_runtime_create(&runtime,0,1,1,8)==0);
  product_l4_policy_rule_t rules[2]={rule(11,1,2),rule(12,2,1)};
  rules[0].expression_length=5;
  memcpy(rules[0].expression,(uint8_t[]){13,2,14,2,1},5); /* ESTABLISHED AND REPLY */
  product_l4_policy_view_t view;
  assert(product_l4_policy_compile(&view,rules,2)==0);
  product_flow_policy_identity_t identity={1,1,100};
  product_packet_facts_t f=facts(family,protocol);
  product_flow_entry_observation_t o=observe(runtime,&f,identity,first_device_direction);
  assert(o.created && o.tracker.facts.state==PRODUCT_CT_NEW);
  assert(o.tracker.facts.direction==PRODUCT_FLOW_DIRECTION_ORIG);
  uint64_t incarnation=o.entry->incarnation;
  assert(match(&view,&f,&o,first_device_direction).rule_id==12);
  assert(product_flow_entry_set_decision(runtime,o.entry,&identity,1,12,12)==0);

  reverse(&f);f.tcp_flags=18;f.tcp_sequence=500;f.tcp_acknowledgment=101;
  unsigned second_direction=first_device_direction==1?3:1;
  o=observe(runtime,&f,identity,second_direction);
  assert(o.reused && o.entry->incarnation==incarnation);
  assert(o.tracker.facts.state==PRODUCT_CT_ESTABLISHED && o.tracker.facts.direction==2);
  product_l4_policy_match_result_t result=match(&view,&f,&o,second_direction);
  assert(result.rule_id==11 && result.winner_rank==1 && result.actual_action==2);
  assert(product_flow_entry_set_decision(runtime,o.entry,&identity,2,11,11)==0);
  assert(o.entry->packets==2 && o.entry->side_packets[1]==1);

  /* A dropped reply is still observed: the following ORIG is established.
   * A policy replacement cannot clear the incarnation or the tracker state. */
  identity=(product_flow_policy_identity_t){1,2,200};
  rules[0].expression[3]=1;rules[0].mode=1; /* ESTABLISHED AND ORIG, observe DROP */
  assert(product_l4_policy_compile(&view,rules,2)==0);
  assert(o.entry->incarnation==incarnation && o.entry->packets==2);
  reverse(&f);f.tcp_flags=16;f.tcp_sequence=101;f.tcp_acknowledgment=501;
  o=observe(runtime,&f,identity,first_device_direction);
  assert(o.revision_invalidated && o.entry->incarnation==incarnation && o.entry->packets==3);
  assert(o.tracker.facts.state==2 && o.tracker.facts.direction==1);
  result=match(&view,&f,&o,first_device_direction);
  assert(result.rule_id==11 && result.mode==1 && result.action==2 && result.actual_action==1);
  assert(product_flow_entry_set_decision(runtime,o.entry,&identity,1,11,11)==0);

  /* Higher-ranked static ALLOW wins in the same deferred view. */
  rules[1].priority=0;rules[0].mode=0;
  assert(product_l4_policy_compile(&view,rules,2)==0);
  result=match(&view,&f,&o,first_device_direction);
  assert(result.rule_id==12 && result.winner_rank==1 && result.actual_action==1);
  assert(product_l4_policy_requires_flow(&view,17));
  assert(o.entry->incarnation==incarnation && o.entry->side_packets[0]==2);
  product_flow_runtime_destroy(runtime);
}

static void invalid_without_entry(void)
{
  product_flow_runtime_t *runtime=NULL;
  assert(product_flow_runtime_create(&runtime,0,1,1,1)==0);
  product_packet_facts_t f=facts(4,6);f.tcp_flags=18; /* Unsolicited SYN+ACK. */
  product_flow_entry_observation_t o=observe(runtime,&f,(product_flow_policy_identity_t){1,1,100},1);
  assert(!o.entry && o.tracker.facts.state==3 && o.tracker.facts.direction==0);
  product_l4_policy_rule_t r=rule(21,1,2);r.expression_length=2;
  memcpy(r.expression,(uint8_t[]){13,3},2);
  product_l4_policy_view_t view;assert(product_l4_policy_compile(&view,&r,1)==0);
  assert(match(&view,&f,&o,1).rule_id==21);
  r.expression_length=3;memcpy(r.expression,(uint8_t[]){14,1,3},3);
  assert(product_l4_policy_compile(&view,&r,1)==0);
  assert(match(&view,&f,&o,1).rule_id==0); /* NOT missing ORIG is unavailable. */
  assert(product_flow_runtime_snapshot(runtime).active_entries==0);
  product_flow_runtime_destroy(runtime);
}

int main(void)
{
  placement_and_rejection();invalid_without_entry();
  for(unsigned family=4;family<=6;family+=2)
    for(unsigned protocol=6;protocol<=17;protocol+=11)
      for(unsigned direction=1;direction<=3;direction+=2)
        flow_changes(family,protocol,direction);
  puts("T07 CT policy: scoped placement, both protocols/families/directions, Rank, observe, lifecycle PASS");
}
