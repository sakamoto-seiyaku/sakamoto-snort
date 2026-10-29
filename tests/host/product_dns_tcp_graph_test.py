#!/usr/bin/env python3
"""Actual Root/VPN TCP graph glue + shared DNS core with controlled Flow/VPP dependencies.

This is a Host semantic/integration seam, not NFQUEUE, Android caller or wire proof.
The Product functions and record producer are extracted unchanged at test time.
"""
from pathlib import Path
from product_root_dns_mark_fixture import tcp_selected_fixture
import argparse
import os
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'src/product/vpp/product_packet_graph.c').read_text()

def function(name, result):
    match = re.search(r'\n(?:void )?' + name + r'\s*\([^;]*?\n\{', SOURCE, re.S)
    assert match, name
    tokens = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|[{}]', re.S)
    depth = 0
    for token in tokens.finditer(SOURCE, match.end() - 1):
        if token.group() == '{': depth += 1
        elif token.group() == '}':
            depth -= 1
            if not depth: return result + '\n' + re.sub(r'^void ', '', SOURCE[match.start() + 1:token.end()]) + '\n'
    raise AssertionError(name)

def typedef(name):
    end = re.search(r'\}\s*' + name + r'\s*;', SOURCE)
    assert end, name
    start = list(re.finditer(r'\btypedef\s+struct\b', SOURCE[:end.start()]))[-1].start()
    return SOURCE[start:end.end()] + '\n'

prefix = r"""
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "product_dns_tcp.h"
#include "product_dns_proxy.h"
#include "product_flow_entry.h"
#include "sakamoto_product_observation.h"
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;
typedef struct {unsigned thread_index;} vlib_main_t;
typedef struct {u32 current_length;u8 bytes[4096];} vlib_buffer_t;
static vlib_buffer_t buffer;
static u64 clock_us=100;
static unsigned flow_present, flow_observations, retire_during_flow;
static u64 fresh_protocols;
static u64 return_incarnation, return_session, return_epoch;
static product_flow_entry_t entry;
static char pool_marker;
static vlib_main_t vm={1};
typedef struct {
 u64 observed,complete,unknown_caller,allowed,dropped,unchecked;
 u64 malformed,unsupported,capacity,copy_gap;
 u32 codec_peak_bytes;
} product_dns_owner_status_t;
typedef struct {
 u64 generation;
 product_dns_owner_status_t dns[2];
 product_dns_owner_t dns_requests[2];
 product_dns_tcp_owner_t dns_tcp[2];
 product_flow_runtime_t *flow_pools[2];
} product_packet_graph_main_t;
static product_packet_graph_main_t product_packet_graph_main;
typedef struct {
 u64 generation;product_domains_t *domains;product_l4_policy_view_t view;product_dns_proxy_route_t dns;
} bank_t;
static bank_t bank;
typedef struct {
 bank_t *bank;
 struct {u64 generation,revision,snapshot_hash;} identity;
 unsigned trace;
} product_policy_snapshot_t;
typedef struct {
 u64 generation,revision,snapshot_hash,rule_id;
 u32 rule_index,reason_id;
 u8 stage,verdict,matched,declared_action,actual_action,mode,terminal_preserved;
} product_packet_graph_policy_evaluation_t;
#define PRODUCT_PACKET_GRAPH_POLICY_STAGE_L4 1
#define PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT 1
#define PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP 2
#define clib_memset memset
#define clib_memcpy_fast memcpy
static unsigned vlib_get_worker_index(unsigned thread) {assert(thread==1);return 0;}
static double vlib_time_now(vlib_main_t *v) {assert(v==&vm);return (double)clock_us/1000000.0;}
static vlib_buffer_t *vlib_get_buffer(vlib_main_t *v,u32 index) {assert(v==&vm && index==3);return &buffer;}
static void *vlib_buffer_get_current(vlib_buffer_t *b) {return b->bytes;}
static struct {u64 revision;} network={5};
static __typeof__(network) *product_network_snapshot_current(void) {return &network;}
/* Original TCP fixture has no proxy owner; full Root work accounting is
 * exercised by product_root_dns_adapter_test.c. */
static u64 root_dns_tcp_other_bytes(unsigned owner) {assert(owner<2);return 0;}
uint64_t product_flow_entry_current_incarnation(product_flow_runtime_t *pool,
 const product_owner_assignment_t *assignment,uint64_t generation,uint64_t now)
{(void)assignment;(void)now;assert(pool==(void*)&pool_marker && generation==77);return flow_present?entry.incarnation:0;}
const product_flow_entry_t *product_flow_entry_current(product_flow_runtime_t *pool,
 const product_owner_assignment_t *assignment,uint64_t generation,uint64_t now,uint32_t *slot)
{(void)assignment;(void)now;assert(pool==(void*)&pool_marker && generation==77);*slot=flow_present?3:UINT32_MAX;return flow_present?&entry:NULL;}
static int product_vpn_tun_return_context(u64 generation,u64 token,u64 *inc,u64 *session,u64 *epoch)
{assert(generation==77 && token);*inc=return_incarnation;*session=return_session;*epoch=return_epoch;return !!return_session;}
static unsigned product_packet_graph_worker_count(void) {return 2;}
static void product_packet_graph_flow_observe(vlib_main_t *v,u32 index,product_packet_lease_t *lease,
 const product_packet_graph_policy_evaluation_t *evaluation,int trace,product_flow_entry_observation_t *out)
{
 assert(v==&vm && index==3 && evaluation->generation==77 && !trace);
 ++flow_observations;memset(out,0,sizeof(*out));
 if(retire_during_flow) {
   product_dns_tcp_end(&product_packet_graph_main.dns_tcp[0],77,entry.incarnation);
   ++entry.incarnation;retire_during_flow=0;
 }
 entry.lpi.protocols=fresh_protocols;entry.lpi.available=!!fresh_protocols;
 out->entry=&entry;out->slot=3;
 out->tracker.facts.state=PRODUCT_CT_ESTABLISHED;
 out->tracker.facts.direction=lease->platform.direction==3?PRODUCT_FLOW_DIRECTION_ORIG:PRODUCT_FLOW_DIRECTION_REPLY;
}
static product_dns_observation_record_t records[256];
static unsigned record_count;
static void product_observation_dns(vlib_main_t *v,const product_dns_observation_record_t *record)
{
 assert(v==&vm && record_count<256);records[record_count]=*record;
 records[record_count].length=product_dns_observation_wire_bytes(record);records[record_count].version=product_dns_observation_wire_version(record);
 records[record_count].flags=PRODUCT_OBSERVATION_DNS;++record_count;
}
"""

suffix = r"""
static product_packet_lease_t lease;
static product_policy_snapshot_t snapshot;
static const uint8_t frame[]={0,29,0x12,0x34,1,0,0,1,0,0,0,0,0,0,
 7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
static product_l4_policy_rule_t rule(unsigned id,unsigned action,unsigned list)
{
 return (product_l4_policy_rule_t){.uid=10123,.rule_id=id,.reason_id=id,
 .action=action,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
 .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
 .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,list}};
}
static void reset(unsigned family)
{
 for(unsigned n=0;n<2;++n) {
  product_dns_tcp_stop(&product_packet_graph_main.dns_tcp[n]);
  product_dns_owner_stop(&product_packet_graph_main.dns_requests[n]);
  product_dns_tcp_start(&product_packet_graph_main.dns_tcp[n],77);
  product_dns_owner_start(&product_packet_graph_main.dns_requests[n],77);
 }
 product_packet_graph_main.generation=77;
 product_packet_graph_main.flow_pools[0]=(void*)&pool_marker;
 product_domains_destroy(bank.domains);memset(&bank,0,sizeof(bank));bank.generation=77;
 sakamoto_product_domains_t source={.list_count=2,.entry_count=2,
  .entries={{.length=11,.name="example.com"},{.list=1,.length=10,.name="alias.test"}}};
 assert(!product_domains_build(&source,&bank.domains));
 snapshot=(product_policy_snapshot_t){.bank=&bank,.identity={77,3,123}};
 lease=(product_packet_lease_t){.policy_owner_ready=1,.origin_obligation_id=10};
 lease.platform=(product_platform_packet_facts_t){.uid=10123,.availability=9,
  .direction=PRODUCT_PACKET_DIRECTION_OUTPUT,.provenance=PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE};
 lease.facts=(product_packet_facts_t){.protocol=6,.ip_family=family,
  .l3_status=PRODUCT_PACKET_L3_COMPLETE,.l4_status=PRODUCT_PACKET_L4_COMPLETE,
  .source_port=40000,.destination_port=53,.transport_offset=40,.l4_header_length=20,
  .source_address={192,0,2,2},.destination_address={192,0,2,53}};
 if(family==4) {
  memset(lease.facts.source_address,0,16);memset(lease.facts.destination_address,0,16);
  memcpy(lease.facts.source_address+12,(uint8_t[]){192,0,2,2},4);
  memcpy(lease.facts.destination_address+12,(uint8_t[]){192,0,2,53},4);
 }
 if(family==6) {
  memset(lease.facts.source_address,0,16);memset(lease.facts.destination_address,0,16);
  lease.facts.source_address[0]=lease.facts.destination_address[0]=0x20;
  lease.facts.source_address[1]=lease.facts.destination_address[1]=1;
  lease.facts.source_address[15]=2;lease.facts.destination_address[15]=53;
 }
 lease.assignment.source_is_a=1;lease.assignment.valid=1;
 memset(&entry,0,sizeof(entry));entry.incarnation=8;entry.origin_is_endpoint_a=1;
 flow_present=flow_observations=retire_during_flow=record_count=0;fresh_protocols=0;
 return_incarnation=return_session=return_epoch=0;
}
static product_dns_tcp_graph_t packet_copied(uint32_t sequence,const uint8_t *bytes,size_t length,uint8_t flags,size_t copied)
{
 product_dns_tcp_graph_t context;
 lease.facts.tcp_sequence=sequence;lease.facts.tcp_flags=flags;
 lease.facts.transport_length=20+length;lease.facts.packet_length=60+length;
 assert(copied<=length);
 buffer.current_length=60+copied;if(length) memcpy(buffer.bytes+60,bytes,length);
 uint8_t untouched[4096];memcpy(untouched,buffer.bytes,buffer.current_length);
 ++lease.origin_obligation_id;++clock_us;
 product_packet_graph_dns_tcp_prepare(&vm,3,&lease,&snapshot,&context);
 assert(!memcmp(untouched,buffer.bytes,buffer.current_length));
 assert(lease.terminal_intent==PRODUCT_PACKET_INTENT_NONE); // Normal owner stage settles the one packet verdict.
 return context;
}
static product_dns_tcp_graph_t packet(uint32_t sequence,const uint8_t *bytes,size_t length,uint8_t flags)
{return packet_copied(sequence,bytes,length,flags,length);}
static void anchor(void)
{
 packet(100,NULL,0,2);
 assert(!product_packet_graph_main.dns_tcp[0].active); // Unadmitted SYN reserves nothing.
 flow_present=1;packet(100,NULL,0,2);
 assert(product_packet_graph_main.dns_tcp[0].active==1 && !flow_observations);
}
static void fresh_post_facts_and_rank_advance_flow_once_for_coalesced_frames(void)
{
 for(unsigned family=4;family<=6;family+=2) {
  reset(family);anchor();
  product_l4_policy_rule_t rules[]={rule(313,2,0),rule(314,1,0)};
  const uint8_t expression[]={17,0,15,0xed,3,0,0,1}; // Domain0 AND new SSH fact.
  memcpy(rules[0].expression,expression,sizeof(expression));rules[0].expression_length=sizeof(expression);
  rules[1].priority=1;assert(!product_l4_policy_compile(&bank.view,rules,2));
  fresh_protocols=UINT64_C(1)<<4;
  product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
  assert(context.complete && context.flow_observed && context.match.rule_id==313);
  assert(context.match.actual_action==2 && flow_observations==1 && record_count==1);
  assert(records[0].protocol==6 && records[0].winner==313 && records[0].message_sequence==1);
  assert(records[0].tcp_sequence==101 && records[0].packet_direction==3);
  assert(records[0].family==family && records[0].caller==1 && records[0].domain_available);
  assert(records[0].length==704 && records[0].version==8);
 }
 reset(4);anchor();product_l4_policy_rule_t allow=rule(314,1,0);
 assert(!product_l4_policy_compile(&bank.view,&allow,1));
 uint8_t combined[sizeof(frame)*3];for(unsigned n=0;n<3;++n) memcpy(combined+n*sizeof(frame),frame,sizeof(frame));
 product_dns_tcp_graph_t context=packet(101,combined,sizeof(combined),0x18);
 assert(context.complete && context.match.rule_id==314 && flow_observations==1 && record_count==3);
 for(unsigned n=0;n<3;++n) {
  assert(records[n].token==records[0].token && records[n].message_sequence==n+1);
  assert(records[n].coverage==1 && records[n].actual_action==1);
 }
}
static void pre_drop_skips_flow_and_incomplete_bytes_keep_the_normal_final_decision(void)
{
 reset(4);anchor();product_l4_policy_rule_t deny=rule(315,2,0);deny.expression_length=0;
 assert(!product_l4_policy_compile(&bank.view,&deny,1));
 product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
 assert(context.complete && context.match.rule_id==315 && !context.flow_observed && !flow_observations);
 reset(4);anchor();context=packet(101,frame,1,0x18);
 assert(!context.complete && context.pending_valid && !context.flow_observed && !record_count);
 product_packet_graph_policy_evaluation_t final={.generation=77,.revision=3,.snapshot_hash=123,
  .matched=1,.rule_id=315,.declared_action=2,.actual_action=2,.verdict=PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP};
 product_flow_entry_observation_t flow={.entry=&entry,.slot=3};
 product_packet_graph_dns_record(&vm,&lease,&snapshot,&context.pending.facts.question,NULL,0,&final,&flow);
 assert(record_count==1 && records[0].coverage==PRODUCT_DNS_TCP_PENDING);
 assert(records[0].winner==315 && records[0].actual_action==2 && !records[0].domain_available && !records[0].name_length);
}
static void current_flow_retirement_cannot_reuse_or_free_an_active_byte_borrow(void)
{
 reset(4);anchor();product_l4_policy_rule_t deny=rule(316,2,0);
 assert(!product_l4_policy_compile(&bank.view,&deny,1));retire_during_flow=1;
 product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
 assert(context.flow_observed && !context.complete && context.pending_valid && flow_observations==1);
 assert(context.pending.facts.question.coverage==PRODUCT_DNS_TCP_MIDSTREAM);
 assert(!context.pending.facts.question.name_length && !context.pending.facts.question.packet.domain_available);
 assert(!product_packet_graph_main.dns_tcp[0].active && !product_packet_graph_main.dns_tcp[0].allocated_bytes);
}
static void insufficient_coverage_keeps_actual_root_records_and_generic_verdict(void)
{
 for(unsigned family=4;family<=6;family+=2)
  for(unsigned scenario=0;scenario<7;++scenario) {
   reset(family);product_dns_tcp_graph_t context;unsigned expected;
   if(scenario==0) {
    flow_present=1;context=packet(101,frame,sizeof(frame),0x18);expected=PRODUCT_DNS_TCP_MIDSTREAM;
   } else {
    anchor();
    if(scenario==1) {context=packet(132,frame,sizeof(frame),0x18);expected=PRODUCT_DNS_TCP_GAP;}
    else if(scenario==2) {
     packet(101,frame,10,0x18);uint8_t changed[10];memcpy(changed,frame,10);changed[4]^=1;
     context=packet(101,changed,sizeof(changed),0x18);expected=PRODUCT_DNS_TCP_CONFLICT;
    } else if(scenario==3) {
     context=packet_copied(101,frame,sizeof(frame),0x18,10);expected=PRODUCT_DNS_COPY_GAP;
    } else if(scenario==4) {
     context=packet(101+65537,frame,1,0x18);expected=PRODUCT_DNS_CAPACITY;
    } else if(scenario==5) {
     packet(101,frame,1,0x18);clock_us+=PRODUCT_DNS_REQUEST_US;
     product_dns_tcp_expire(&product_packet_graph_main.dns_tcp[0],clock_us);
     context=packet(102,frame+1,sizeof(frame)-1,0x18);expected=PRODUCT_DNS_TCP_EXPIRED;
    } else {
     product_l4_policy_rule_t generic=rule(999,2,0);generic.expression_length=0;
     assert(!product_l4_policy_compile(&bank.view,&generic,1));
     uint8_t malformed[13]={0,11};context=packet(101,malformed,sizeof(malformed),0x18);
     expected=PRODUCT_DNS_MALFORMED;
    }
   }
   if(scenario==6) {
    assert(!context.complete && !context.pending_valid && record_count==1);
    assert(records[0].coverage==expected && records[0].family==family && records[0].message_sequence==1);
    assert(records[0].actual_action==2 && records[0].winner==999 && !records[0].domain_available);
    continue;
   }
   assert(!context.complete && context.pending_valid && context.pending.facts.question.coverage==expected);
   product_packet_graph_policy_evaluation_t final={.generation=77,.revision=3,.snapshot_hash=123,
    .matched=1,.rule_id=999,.declared_action=2,.actual_action=2,.verdict=PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP};
   product_flow_entry_observation_t flow={.entry=&entry,.slot=3};
   product_packet_graph_dns_record(&vm,&lease,&snapshot,&context.pending.facts.question,NULL,0,&final,&flow);
   assert(record_count==1 && records[0].coverage==expected && records[0].family==family);
   assert(records[0].actual_action==2 && records[0].winner==999 && !records[0].domain_available);
   assert(!records[0].name_length && records[0].message_sequence==(scenario==6?1:0));
  }
 reset(4);flow_present=1;lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
 lease.facts.source_port=53;lease.facts.destination_port=40000;
 product_dns_tcp_graph_t context=packet(501,frame,sizeof(frame),0x18);
 assert(context.pending_valid && context.pending.stage==2 && context.pending.facts.correlation==PRODUCT_DNS_UNMATCHED);
 assert(context.pending.facts.question.coverage==PRODUCT_DNS_TCP_MIDSTREAM);
}
static void injected_packets_do_not_acquire_original_path_framing(void)
{
 reset(4);
 lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED;
 product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
 assert(!context.complete && !context.pending_valid && !product_packet_graph_main.dns_tcp[0].active);
}
static void vpn_direct_queries_share_framing_and_per_message_policy(void)
{
 for(unsigned family=4;family<=6;family+=2) {
  reset(family);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  anchor();
  product_l4_policy_rule_t deny=rule(314,2,0);
  assert(!product_l4_policy_compile(&bank.view,&deny,1));
  product_dns_tcp_graph_t context=packet(101,frame,1,0x18);
  assert(!context.complete && context.pending_valid);
  context=packet(102,frame+1,sizeof(frame)-1,0x18);
  assert(context.complete && context.match.rule_id==314 && context.match.actual_action==2);
  assert(record_count==1 && records[0].adapter_profile==2 && records[0].protocol==6);
  assert(records[0].caller==PRODUCT_DNS_CALLER_PLATFORM_APP && records[0].message_sequence==1);
 }
}
static void vpn_split_unknown_caller_keeps_current_packet_uid_for_generic_policy(void)
{
 unsigned failures=0;
 for(unsigned family=4;family<=6;family+=2)
  for(unsigned current_known=0;current_known<2;++current_known)
   for(unsigned post=0;post<2;++post) {
  reset(family);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  lease.platform.uid=current_known?UINT32_MAX:2000;
  lease.platform.availability=current_known?0:PRODUCT_PLATFORM_UID_KNOWN;
  anchor();
  product_l4_policy_rule_t rules[]={rule(314,2,0),rule(315,2,0)};
  rules[0].uid=rules[1].uid=2000;rules[1].priority=1;rules[1].expression_length=0;
  if(post) {
   const uint8_t expression[]={PRODUCT_EXPRESSION_APPLICATION_PROTOCOL,0xed,3,0,0};
   memcpy(rules[1].expression,expression,sizeof(expression));rules[1].expression_length=sizeof(expression);
   fresh_protocols=UINT64_C(1)<<4;
  }
  assert(!product_l4_policy_compile(&bank.view,rules,2));
  product_dns_tcp_graph_t context=packet(101,frame,1,0x18);
  assert(!context.complete && context.pending_valid);
  lease.platform.uid=current_known?2000:UINT32_MAX;
  lease.platform.availability=current_known?PRODUCT_PLATFORM_UID_KNOWN:0;
  context=packet(102,frame+1,sizeof(frame)-1,0x18);
  assert(context.complete && record_count==1);
  if(context.match.actual_action!=(current_known?2:0) || context.match.rule_id!=(current_known?315:0)) {
   fprintf(stderr,"split UID family=%u current_known=%u post=%u actual_action=%u winner=%llu expected_action=%u\n",
    family,current_known,post,context.match.actual_action,(unsigned long long)context.match.rule_id,current_known?2:0);
   ++failures;
  }
  assert(records[0].caller==PRODUCT_DNS_CALLER_UNKNOWN && !records[0].domain_available);
  assert(records[0].uid==(current_known?UINT32_MAX:2000)); // first-byte identity is immutable
  assert(records[0].packet_uid==(current_known?2000:UINT32_MAX));
 }
 assert(!failures);
}
static void retained_unknown_question_rechecks_current_uid_without_rewriting_admission(void)
{
 reset(4);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
 lease.platform.uid=UINT32_MAX;lease.platform.availability=0;anchor();
 product_l4_policy_rule_t generic=rule(315,2,0);generic.uid=2000;generic.expression_length=0;
 assert(!product_l4_policy_compile(&bank.view,&generic,1));
 product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
 assert(context.complete && record_count==1 && records[0].actual_action==1);
 lease.platform.uid=2000;lease.platform.availability=PRODUCT_PLATFORM_UID_KNOWN;
 ++snapshot.identity.revision;
 context=packet(132,frame,1,0x18);
 assert(!context.complete && context.pending_valid && record_count==1);
 product_l4_policy_packet_t current;product_packet_graph_l4_packet_projection(&lease,&current);
 product_l4_policy_match_result_t actual;
 assert(!product_l4_policy_match_position(&bank.view,&current,PRODUCT_L4_POLICY_POSITION_ALL,&actual));
 assert(actual.rule_id==315 && actual.actual_action==2);
 lease.platform.uid=UINT32_MAX;lease.platform.availability=0;++snapshot.identity.revision;
 context=packet(132,frame,1,0x18);
 assert(!context.complete && record_count==2 && records[1].actual_action==1);
 assert(records[1].tcp_continuation && records[1].packet_uid==UINT32_MAX && !records[1].winner);
 assert(records[0].actual_action==1 && !records[0].winner && records[0].policy_revision==3);
}
static void retained_query_generic_output_rule_cannot_drop_a_current_input_packet(void)
{
 reset(4);anchor();
 product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
 assert(context.complete && record_count==1 && records[0].actual_action==1);
 product_l4_policy_rule_t generic=rule(315,2,0);
 generic.expression_length=0;generic.direction=PRODUCT_L4_POLICY_DIRECTION_OUTPUT;
 assert(!product_l4_policy_compile(&bank.view,&generic,1));++snapshot.identity.revision;
 lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
 lease.facts.source_port=53;lease.facts.destination_port=40000;
 uint8_t address[16];memcpy(address,lease.facts.source_address,16);
 memcpy(lease.facts.source_address,lease.facts.destination_address,16);
 memcpy(lease.facts.destination_address,address,16);
 packet(500,NULL,0,0x12);
 context=packet(501,frame,1,0x18);
 product_l4_policy_packet_t current;product_packet_graph_l4_packet_projection(&lease,&current);
 product_l4_policy_match_result_t actual;
 assert(!product_l4_policy_match_position(&bank.view,&current,PRODUCT_L4_POLICY_POSITION_ALL,&actual));
 assert(!actual.evaluation && !context.complete && context.pending_valid);
 if(record_count!=1 || records[0].actual_action!=1 || records[0].policy_revision!=3) for(unsigned n=0;n<record_count;++n)
  fprintf(stderr,"retained generic normal n=%u action=%u winner=%llu continuation=%u revision=%llu\n",
   n,records[n].actual_action,(unsigned long long)records[n].winner,records[n].tcp_continuation,(unsigned long long)records[n].policy_revision);
 assert(record_count==1 && records[0].actual_action==1 && records[0].policy_revision==3);
}
static void retained_mixed_dns_or_packet_rule_keeps_its_whole_rule_restriction(void)
{
 reset(4);lease.platform.uid=2000;lease.platform.availability=PRODUCT_PLATFORM_UID_KNOWN;anchor();
 product_l4_policy_rule_t mixed=rule(316,2,0);mixed.uid=2000;
 const uint8_t expression[]={PRODUCT_EXPRESSION_DOMAIN_LIST,0,PRODUCT_STATIC_DIRECTION,3,PRODUCT_STATIC_OR};
 memcpy(mixed.expression,expression,sizeof(expression));mixed.expression_length=sizeof(expression);
 assert(!product_l4_policy_compile(&bank.view,&mixed,1));
 product_dns_tcp_graph_t context=packet(101,frame,sizeof(frame),0x18);
 assert(context.complete && context.match.rule_id==316 && context.match.actual_action==2);
 assert(records[0].caller==PRODUCT_DNS_CALLER_UNKNOWN && !records[0].domain_available);
 lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
 lease.facts.source_port=53;lease.facts.destination_port=40000;
 uint8_t address[16];memcpy(address,lease.facts.source_address,16);
 memcpy(lease.facts.source_address,lease.facts.destination_address,16);
 memcpy(lease.facts.destination_address,address,16);
 packet(500,NULL,0,0x12);context=packet(501,frame,1,0x18);
 assert(context.complete && context.match.rule_id==316 && context.match.actual_action==2);
 assert(record_count==2 && records[1].tcp_continuation && records[1].winner==316);
}
static void vpn_direct_binding_preserves_original_query_and_actual_return_context(void)
{
 for(unsigned family=4;family<=6;family+=2) {
  reset(family);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;
  lease.platform.availability|=PRODUCT_PLATFORM_CONTEXT_KNOWN;lease.platform.network_context_id=3;
  anchor();
  /* The Direct input accepts SYN before the asynchronous protect/bind reply. */
  product_packet_graph_dns_request_transport(&vm,77,lease.origin_obligation_id,8,71,0,0,0);
  product_packet_graph_dns_transport_bound(&vm,77,71,9,7,1);
  packet(101,frame,sizeof(frame),0x18);
  const uint64_t query_token=lease.origin_obligation_id;
  product_packet_graph_dns_request_transport(&vm,77,query_token,8,71,9,7,1);
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
  lease.platform.availability=PRODUCT_PLATFORM_CONTEXT_KNOWN;lease.platform.network_context_id=7;
  lease.facts.source_port=53;lease.facts.destination_port=40000;
  uint8_t address[16];memcpy(address,lease.facts.source_address,16);
  memcpy(lease.facts.source_address,lease.facts.destination_address,16);
  memcpy(lease.facts.destination_address,address,16);
  return_incarnation=8;return_session=71;return_epoch=9;
  packet(500,NULL,0,0x12);
  uint8_t response[sizeof(frame)];memcpy(response,frame,sizeof(frame));response[4]=0x81;response[5]=0x80;
  product_dns_tcp_graph_t context=packet(501,response,sizeof(response),0x18);
  assert(context.complete && record_count==2);
  assert(records[1].correlation==PRODUCT_DNS_CORRELATED && records[1].query_token==query_token);
  assert(records[1].query_incarnation==8 && records[1].transport_session==71 && records[1].underlay_epoch==9);
  assert(records[1].caller==PRODUCT_DNS_CALLER_PLATFORM_APP && records[1].packet_uid==UINT32_MAX);
  assert(records[1].network==7 && records[1].adapter_profile==2 && records[1].packet_direction==1);
  assert(product_packet_graph_main.dns_tcp[0].active==1);
 }
}
static void prebroker_synack_anchors_only_the_exact_selected_tcp_session(void)
{
 for(unsigned family=4;family<=6;family+=2)
  for(unsigned bound_before=0;bound_before<2;++bound_before) {
  reset(family);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;anchor();
  product_packet_graph_dns_request_transport(&vm,77,lease.origin_obligation_id,8,71,0,0,0);
  if(bound_before) product_packet_graph_dns_transport_bound(&vm,77,71,9,7,1);
  packet(101,frame,sizeof(frame),0x18);
  product_packet_graph_dns_request_transport(&vm,77,lease.origin_obligation_id,8,71,bound_before?9:0,7,bound_before);
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;lease.platform.availability=0;
  lease.facts.source_port=53;lease.facts.destination_port=40000;
  uint8_t address[16];memcpy(address,lease.facts.source_address,16);
  memcpy(lease.facts.source_address,lease.facts.destination_address,16);
  memcpy(lease.facts.destination_address,address,16);
  return_incarnation=8;return_session=71;return_epoch=0;
  /* The local handshake was stamped before the broker completed, even when
   * its queued graph execution happens after the real binding publication. */
  packet(500,NULL,0,0x12);
  if(!bound_before) product_packet_graph_dns_transport_bound(&vm,77,71,9,7,1);
  /* Zero-epoch DNS data remains ineligible and cannot consume the frame. */
  uint8_t response[sizeof(frame)];memcpy(response,frame,sizeof(frame));response[4]=0x81;response[5]=0x80;
  product_dns_tcp_graph_t context=packet(501,response,sizeof(response),0x18);
  assert(!context.complete && context.pending_valid && record_count==1);
  return_epoch=9;lease.platform.availability=PRODUCT_PLATFORM_CONTEXT_KNOWN;
  lease.platform.network_context_id=7;
  context=packet(501,response,sizeof(response),0x18);
  assert(context.complete && record_count==2 && records[1].coverage==PRODUCT_DNS_QUERY_COMPLETE);
  assert(records[1].transport_session==71 && records[1].underlay_epoch==9);
 }
}
static void invalid_prebroker_handshakes_cannot_anchor_current_reverse_bytes(void)
{
 for(unsigned scenario=0;scenario<7;++scenario) {
  reset(scenario%2?6:4);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;anchor();
  product_packet_graph_dns_request_transport(&vm,77,lease.origin_obligation_id,8,71,0,0,0);
  packet(101,frame,sizeof(frame),0x18);
  product_packet_graph_dns_request_transport(&vm,77,lease.origin_obligation_id,8,71,0,0,0);
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;lease.platform.availability=0;
  lease.facts.source_port=53;lease.facts.destination_port=40000;
  uint8_t address[16];memcpy(address,lease.facts.source_address,16);
  memcpy(lease.facts.source_address,lease.facts.destination_address,16);
  memcpy(lease.facts.destination_address,address,16);
  return_incarnation=8;return_session=71;return_epoch=0;
  if(scenario==0) return_incarnation=7;
  if(scenario==1) return_session=70;
  if(scenario==2) return_incarnation=return_session=0;
  if(scenario==3) ++network.revision;
  if(scenario==4) {lease.platform.availability=PRODUCT_PLATFORM_CONTEXT_KNOWN;lease.platform.network_context_id=7;}
  uint8_t one=0;
  packet(999,scenario==5?&one:NULL,scenario==5?1:0,scenario==6?2:0x12);
  return_incarnation=8;return_session=71;return_epoch=0;network.revision=5;
  lease.platform.availability=0;
  packet(500,NULL,0,0x12);
  product_packet_graph_dns_transport_bound(&vm,77,71,9,7,1);
  return_epoch=9;lease.platform.availability=PRODUCT_PLATFORM_CONTEXT_KNOWN;lease.platform.network_context_id=7;
  uint8_t response[sizeof(frame)];memcpy(response,frame,sizeof(frame));response[4]=0x81;response[5]=0x80;
  product_dns_tcp_graph_t context=packet(501,response,sizeof(response),0x18);
  assert(context.complete && record_count==2 && records[1].coverage==PRODUCT_DNS_QUERY_COMPLETE);
  assert(records[1].correlation==PRODUCT_DNS_CORRELATED && records[1].underlay_epoch==9);
 }
}
static void return_stamp_survives_an_unavailable_current_flow(void)
{
 reset(4);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
 product_dns_tcp_graph_t context={.lease=&lease,.flow_observed=1};
 product_l4_policy_packet_t packet={0};
 product_dns_identity_t identity={.generation=77,.incarnation=8,.transport_session=71,.underlay_epoch=9};
 assert(!product_packet_graph_dns_tcp_flow_facts(&context,&packet,&identity));
 assert(identity.incarnation==8 && identity.transport_session==71 && identity.underlay_epoch==9);
 assert(!packet.ct_state_known && !packet.flow_direction_known);
}
static void stale_direct_returns_cannot_change_current_framing_or_reopen_a_closed_flow(void)
{
 for(unsigned scenario=0;scenario<7;++scenario) {
  reset(scenario%2?6:4);lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_VPN_TUN;anchor();
  product_packet_graph_dns_request_transport(&vm,77,lease.origin_obligation_id,8,71,9,0,0);
  packet(101,frame,sizeof(frame),0x18);uint64_t query_token=lease.origin_obligation_id;
  product_packet_graph_dns_request_transport(&vm,77,query_token,8,71,9,0,0);
  lease.platform.provenance=PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN;
  lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
  lease.facts.source_port=53;lease.facts.destination_port=40000;
  uint8_t address[16];memcpy(address,lease.facts.source_address,16);
  memcpy(lease.facts.source_address,lease.facts.destination_address,16);
  memcpy(lease.facts.destination_address,address,16);
  return_incarnation=8;return_session=71;return_epoch=9;
  packet(500,NULL,0,0x12);
  if(scenario==0) return_incarnation=7;
  if(scenario==1) return_session=70;
  if(scenario==2) return_epoch=8;
  if(scenario==3) return_session=return_epoch=return_incarnation=0;
  if(scenario==4) ++network.revision;
  if(scenario==5) {lease.platform.availability|=PRODUCT_PLATFORM_CONTEXT_KNOWN;lease.platform.network_context_id=3;}
  if(scenario==6) {
   /* Old-generation/incarnation events have no effect on the current flow. */
   product_dns_tcp_end(&product_packet_graph_main.dns_tcp[0],76,8);
   product_dns_tcp_end(&product_packet_graph_main.dns_tcp[0],77,7);
   product_packet_graph_dns_request_transport(&vm,76,query_token,8,99,99,0,0);
   product_packet_graph_dns_transport_bound(&vm,76,71,99,0,0);
   product_packet_graph_dns_request_transport(&vm,77,query_token,7,99,99,0,0);
   return_session=99;
  }
  uint8_t response[sizeof(frame)];memcpy(response,frame,sizeof(frame));response[4]=0x81;response[5]=0x80;
  product_dns_tcp_graph_t context=packet(501,response,7,0x18);
  assert(!context.complete && context.pending_valid && context.pending.facts.question.coverage==PRODUCT_DNS_TCP_MIDSTREAM);
  assert(product_packet_graph_main.dns_tcp[0].active==1 && record_count==1);
  return_incarnation=8;return_session=71;return_epoch=9;network.revision=5;lease.platform.availability=0;
  context=packet(501,response,sizeof(response),0x18);
  assert(context.complete && record_count==2 && records[1].correlation==PRODUCT_DNS_CORRELATED);
  assert(records[1].query_token==query_token && records[1].message_sequence==1);
  product_dns_tcp_end(&product_packet_graph_main.dns_tcp[0],77,8);
  assert(!product_packet_graph_main.dns_tcp[0].active && !product_packet_graph_main.dns_tcp[0].allocated_bytes);
  context=packet(501,response,sizeof(response),0x18);
  assert(!context.complete && context.pending_valid && !product_packet_graph_main.dns_tcp[0].active);
  product_dns_tcp_stop(&product_packet_graph_main.dns_tcp[0]);
  product_dns_owner_stop(&product_packet_graph_main.dns_requests[0]);
  product_packet_graph_dns_request_transport(&vm,77,query_token,8,71,9,0,0);
  product_packet_graph_dns_transport_bound(&vm,77,71,9,0,0);
  context=packet(501,response,sizeof(response),0x18);
  assert(!context.complete && !context.pending_valid && !product_packet_graph_main.dns_tcp[0].active);
 }
}
static void every_coalesced_malformed_frame_keeps_its_own_normal_identity(void)
{
 for(unsigned family=4;family<=6;family+=2)
  for(unsigned response=0;response<2;++response)
   for(unsigned deny=0;deny<2;++deny)
    for(unsigned mixed=0;mixed<2;++mixed) {
    reset(family);anchor();
    if(response) {
     lease.platform.direction=PRODUCT_PACKET_DIRECTION_INPUT;
     lease.facts.source_port=53;lease.facts.destination_port=40000;
     uint8_t address[16];memcpy(address,lease.facts.source_address,16);
     memcpy(lease.facts.source_address,lease.facts.destination_address,16);
     memcpy(lease.facts.destination_address,address,16);
     packet(500,NULL,0,0x12);
    }
    if(deny) {
     product_l4_policy_rule_t generic=rule(999,2,0);generic.expression_length=0;
     assert(!product_l4_policy_compile(&bank.view,&generic,1));
    }
    const uint8_t malformed[]={0,3,0x12,0x34,0x81,0,3,0x56,0x78,0x81};
    uint8_t wire[sizeof(malformed)+sizeof(frame)];size_t size=sizeof(malformed);
    if(mixed) {
     memcpy(wire,malformed,5);memcpy(wire+5,frame,sizeof(frame));
     if(response) {wire[9]=0x81;wire[10]=0x80;}
     memcpy(wire+5+sizeof(frame),malformed+5,5);size+=sizeof(frame);
    } else memcpy(wire,malformed,size);
    product_dns_tcp_graph_t context=packet(response?501:101,wire,size,0x18);
    if(context.pending_valid) {
     product_packet_graph_policy_evaluation_t final={.generation=77,.revision=3,.snapshot_hash=123,
      .matched=deny,.rule_id=deny?999:0,.declared_action=deny?2:0,.actual_action=deny?2:0,
      .verdict=deny?PRODUCT_PACKET_GRAPH_POLICY_VERDICT_DROP:PRODUCT_PACKET_GRAPH_POLICY_VERDICT_PASS_NEXT};
     product_packet_graph_dns_record(&vm,&lease,&snapshot,&context.pending.facts.question,
      response?&context.pending.facts:NULL,context.pending.facts.correlation,&final,&context.flow);
    }
    assert(record_count==2+mixed && "every framed malformed message must reach normal history");
    for(unsigned n=0;n<2+mixed;++n) {
     unsigned valid=mixed && n==1;
     assert(records[n].coverage==(valid?PRODUCT_DNS_QUERY_COMPLETE:PRODUCT_DNS_MALFORMED));
     assert(records[n].message_sequence==n+1);
     assert(records[n].token==records[0].token && records[n].stage==(response?2:1));
     assert(records[n].actual_action==(deny?2:1) && records[n].winner==(deny?999:0));
     assert(records[n].family==family);
     if(!valid) assert(!records[n].domain_available && !records[n].name_length);
    }
    assert(context.complete==(int)mixed && flow_observations==(deny?0:1));
   }
}
int main(void)
{
 const char *selected=getenv("SAKAMOTO_TCP_GRAPH_CASE");
 if(selected && !strcmp(selected,"uid")) {
  vpn_split_unknown_caller_keeps_current_packet_uid_for_generic_policy();goto cleanup;
 }
 if(selected && !strcmp(selected,"retained-generic")) {
  retained_query_generic_output_rule_cannot_drop_a_current_input_packet();goto cleanup;
 }
 stale_direct_returns_cannot_change_current_framing_or_reopen_a_closed_flow();
 prebroker_synack_anchors_only_the_exact_selected_tcp_session();
 invalid_prebroker_handshakes_cannot_anchor_current_reverse_bytes();
 return_stamp_survives_an_unavailable_current_flow();
 vpn_direct_binding_preserves_original_query_and_actual_return_context();
 vpn_direct_queries_share_framing_and_per_message_policy();
 vpn_split_unknown_caller_keeps_current_packet_uid_for_generic_policy();
 retained_unknown_question_rechecks_current_uid_without_rewriting_admission();
 retained_query_generic_output_rule_cannot_drop_a_current_input_packet();
 retained_mixed_dns_or_packet_rule_keeps_its_whole_rule_restriction();
 every_coalesced_malformed_frame_keeps_its_own_normal_identity();
 fresh_post_facts_and_rank_advance_flow_once_for_coalesced_frames();
 pre_drop_skips_flow_and_incomplete_bytes_keep_the_normal_final_decision();
 current_flow_retirement_cannot_reuse_or_free_an_active_byte_borrow();
 insufficient_coverage_keeps_actual_root_records_and_generic_verdict();
 injected_packets_do_not_acquire_original_path_framing();
cleanup:
 for(unsigned n=0;n<2;++n) {product_dns_tcp_stop(&product_packet_graph_main.dns_tcp[n]);product_dns_owner_stop(&product_packet_graph_main.dns_requests[n]);}
 product_domains_destroy(bank.domains);
 puts("Root/VPN TCP graph PRE/Flow/POST, Direct lineage, coalesced identity, coverage and retirement: PASS");
}
"""

parser = argparse.ArgumentParser()
parser.add_argument('libraries', nargs='+')
parser.add_argument('--case', choices=('all','uid','retained-generic'), default='all')
args = parser.parse_args()
policy_cache=Path(args.libraries[1]).resolve().parent/'CMakeCache.txt'
batch=re.search(r'^SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT:BOOL=(ON|OFF)$',policy_cache.read_text(),re.M)
assert batch, 'The linked policy library must have its actual CMake configuration'
defines=['-DSAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=1']if batch[1]=='ON'else[]
print('TCP graph policy ABI: ROOT_BATCH_EXPERIMENT='+batch[1]+' case='+args.case,flush=True)
with tempfile.TemporaryDirectory(prefix='sakamoto-dns-tcp-graph-') as tmp:
    source, binary = Path(tmp) / 'test.c', Path(tmp) / 'test'
    source.write_text(prefix + tcp_selected_fixture()
        + function('product_packet_graph_l4_direction_from_platform', 'static void')
        + function('product_packet_graph_l4_packet_projection', 'static void')
        + function('product_packet_graph_dns_identity', 'static product_dns_identity_t')
        + function('product_packet_graph_dns_request_transport', 'void')
        + function('product_packet_graph_dns_transport_bound', 'void')
        + function('product_packet_graph_dns_record', 'static void')
        + typedef('product_dns_tcp_graph_t')
        + function('product_packet_graph_dns_tcp_flow_facts', 'static int')
        + function('product_packet_graph_dns_tcp_record', 'static void')
        + function('product_packet_graph_dns_tcp_prepare', 'static void') + suffix)
    subprocess.run(['cc', '-std=gnu11', '-Wall', '-Wextra', '-Werror', *defines,
        '-I'+str(ROOT / 'src/product/vpp'), '-I'+str(ROOT / 'src/product/include'),
        str(source), str(ROOT / 'src/product/vpp/product_flow_tcp.c'),
        *args.libraries, '-lm', '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, timeout=15,
        env=dict(os.environ,SAKAMOTO_TCP_GRAPH_CASE=args.case))
