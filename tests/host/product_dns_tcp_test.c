/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_tcp.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static product_dns_owner_t requests;
static product_dns_tcp_owner_t owner;
static product_l4_policy_view_t view;
static const uint8_t frame[]={0,29,0x12,0x34,1,0,0,1,0,0,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
static product_dns_tcp_input_t input;
static unsigned complete, rejected;
static uint64_t last_sequence[2];
static unsigned coverage_count[12];
static product_dns_tcp_event_t last_event, last_complete_event;
static void observed(void *context,const product_dns_tcp_event_t *event)
{
  assert(context==&complete);
  last_event=*event;
  assert(event->facts.question.coverage<12);
  ++coverage_count[event->facts.question.coverage];
  if(event->facts.question.coverage!=PRODUCT_DNS_QUERY_COMPLETE) return;
  last_complete_event=*event;
  ++complete;
  assert(!strcmp(event->facts.question.name,"example.com"));
  assert(event->facts.question.packet.protocol==6);
  assert(event->continuation || event->message_sequence>last_sequence[event->stage==2]);
  last_sequence[event->stage==2]=event->message_sequence;
  rejected+=event->match.actual_action==PRODUCT_L4_POLICY_ACTION_DROP;
}
static void send(uint32_t sequence,const uint8_t *bytes,size_t size,uint8_t flags)
{
  input.sequence=sequence;input.bytes=bytes;input.copied=input.length=size;input.flags=flags;
  ++input.token;++input.identity.now_us;
  product_dns_tcp_process(&owner,&requests,&input,observed,&complete);
}
static void reset(void)
{
  product_dns_tcp_stop(&owner);product_dns_owner_stop(&requests);
  product_dns_tcp_start(&owner,77);product_dns_owner_start(&requests,77);
  product_l4_policy_init(&view);
  input=(product_dns_tcp_input_t){.context={.domains_available=1,
    .caller=PRODUCT_DNS_CALLER_PLATFORM_APP,
    .packet={.uid=10123,.uid_known=1,.family=4,.protocol=6,.direction=3,
      .direction_known=1,.ports_available=1,.source_port=40000,.destination_port=53,
      .source_address={192,0,2,2},.destination_address={192,0,2,53}}},
    .identity={.generation=77,.incarnation=8,.network_revision=5,.profile=1,.now_us=100},
    .policy={77,3,123,0},.view=&view,.token=10};
  complete=rejected=0;memset(last_sequence,0,sizeof(last_sequence));memset(coverage_count,0,sizeof(coverage_count));
}
static void split_coalesced_and_continuous_frames_move_the_window(void)
{
  reset();send(100,NULL,0,2);
  send(101,frame,1,0x18);assert(!complete);
  send(102,frame+1,13,0x18);assert(!complete);
  send(115,frame+14,sizeof(frame)-14,0x18);assert(complete==1);
  uint8_t combined[sizeof(frame)*2];memcpy(combined,frame,sizeof(frame));
  memcpy(combined+sizeof(frame),frame,sizeof(frame));
  send(132,combined,sizeof(combined),0x18);assert(complete==3);
  for(unsigned i=0;i<5000;++i) send(194+i*sizeof(frame),frame,sizeof(frame),0x18);
  assert(complete==5003); // 155KiB in one direction exceeds any fixed prefix.
  assert(owner.active==1 && owner.allocated_bytes<=PRODUCT_DNS_TCP_FLOW_BYTES);
  product_dns_tcp_stop(&owner);assert(!owner.active && !owner.allocated_bytes);
}
static void out_of_order_pipeline_completes_every_ready_frame_once(void)
{
  reset();send(100,NULL,0,2);
  uint8_t combined[sizeof(frame)*3];
  for(unsigned n=0;n<3;++n) memcpy(combined+n*sizeof(frame),frame,sizeof(frame));
  send(132,combined+sizeof(frame),sizeof(frame)*2,0x18);
  assert(!complete && coverage_count[PRODUCT_DNS_TCP_GAP]==1);
  send(101,combined,sizeof(frame),0x18);
  assert(complete==3);
  send(101,combined,sizeof(combined),0x18);
  assert(complete==3 && owner.duplicates>=sizeof(combined));
  assert(coverage_count[PRODUCT_DNS_TCP_OLD_BYTES]==1);
  send(194,frame,sizeof(frame),0x18);assert(complete==4);
}
static void rejection_covers_later_data_and_rechecks_current_policy(void)
{
  reset();
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,
    .entries={{.length=11,.name="example.com"}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
  input.context.domains=domains;
  product_l4_policy_rule_t rule={.uid=10123,.rule_id=313,.reason_id=313,
    .action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&view,&rule,1));
  send(100,NULL,0,2);
  send(101,frame,17,0x18);assert(!rejected);
  send(118,frame+17,sizeof(frame)-17,0x18);assert(rejected==1);
  assert(last_event.match.rule_id==313 && !last_event.continuation);
  send(132,frame,1,0x18);
  assert(rejected==2 && last_event.continuation && last_event.message_sequence==1);
  send(999,frame,1,2); // Conflicting observation must not bypass a known rejection.
  assert(rejected==3 && last_event.continuation && last_event.match.actual_action==2);
  rule.action=1;rule.rule_id=314;input.policy.revision=4;input.policy.hash=456;
  assert(!product_l4_policy_compile(&view,&rule,1));
  send(132,frame,sizeof(frame),0x18);
  assert(last_event.match.rule_id==314 && last_event.match.actual_action==1);
  assert(!last_event.continuation && last_event.message_sequence==2);
  // A newly rejecting policy uses the latest real name before a new frame completes.
  rule.action=2;rule.rule_id=315;input.policy.revision=5;input.policy.hash=789;
  assert(!product_l4_policy_compile(&view,&rule,1));
  send(163,frame,1,0x18);
  assert(last_event.continuation && last_event.match.rule_id==315 && rejected==4);
  product_domains_destroy(domains);
}
static void reverse_direction(void)
{
  product_l4_policy_packet_t *packet=&input.context.packet;
  uint8_t address[16];memcpy(address,packet->source_address,16);
  memcpy(packet->source_address,packet->destination_address,16);
  memcpy(packet->destination_address,address,16);
  uint16_t port=packet->source_port;packet->source_port=packet->destination_port;packet->destination_port=port;
  packet->direction=packet->direction==3?1:3;
}
static size_t reply_wire(uint8_t *wire)
{
  const uint8_t answer[]={
    0x12,0x34,0x81,0x80,0,1,0,2,0,0,0,0,
    7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1,
    0xc0,12,0,5,0,1,0,0,0,60,0,12,
    5,'a','l','i','a','s',4,'t','e','s','t',0,
    0xc0,41,0,1,0,1,0,0,0,60,0,4,192,0,2,1};
  wire[0]=sizeof(answer)>>8;wire[1]=sizeof(answer);memcpy(wire+2,answer,sizeof(answer));
  return sizeof(answer)+2;
}
static void answers_use_original_caller_and_current_connected_alias_rules(void)
{
  for(unsigned known=0;known<2;++known)
    {
      reset();input.context.caller=known?PRODUCT_DNS_CALLER_PLATFORM_APP:PRODUCT_DNS_CALLER_UNKNOWN;
      sakamoto_product_domains_t source={.list_count=2,.entry_count=2,
        .entries={{.length=11,.name="example.com"},{.list=1,.length=10,.name="alias.test"}}};
      product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
      input.context.domains=domains;
      send(100,NULL,0,2);send(101,frame,sizeof(frame),0x18);
      assert(complete==1 && last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
      product_l4_policy_rule_t rule={.uid=10123,.rule_id=313,.reason_id=313,
        .action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
        .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
        .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,1}};
      assert(!product_l4_policy_compile(&view,&rule,1));
      ++input.policy.revision;input.policy.hash=456;
      reverse_direction();input.context.packet.uid=999;input.context.caller=PRODUCT_DNS_CALLER_UNKNOWN;
      send(500,NULL,0,0x12);
      uint8_t wire[128];size_t length=reply_wire(wire);
      send(501,wire,9,0x18);assert(!rejected);
      send(510,wire+9,length-9,0x18);
      assert(last_event.stage==2 && last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
      assert(last_event.facts.query_uid==10123 && last_event.facts.query_token==12);
      assert(last_event.facts.name_count==2 && !strcmp(last_event.facts.names[1].name,"alias.test"));
      assert(last_event.facts.question.caller==known);
      assert(rejected==known);
      assert(last_event.match.actual_action==(known?2:0));
      if(known)
        {
          // Query-direction data is affected by the rejected response on this connection.
          reverse_direction();send(132,frame,1,0x18);
          assert(last_event.continuation && last_event.stage==2 && rejected==2);
        }
      product_domains_destroy(domains);
    }
}
static void tcp_id_reuse_after_an_answer_is_a_new_request(void)
{
  reset();send(100,NULL,0,2);send(101,frame,sizeof(frame),0x18);
  reverse_direction();send(500,NULL,0,0x12);
  uint8_t wire[128];size_t length=reply_wire(wire);
  send(501,wire,length,0x18);
  assert(last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
  reverse_direction();send(132,frame,sizeof(frame),0x18);
  assert(last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
  uint64_t token=input.token;
  reverse_direction();send(501+length,wire,length,0x18);
  assert(last_event.facts.correlation==PRODUCT_DNS_CORRELATED && last_event.facts.query_token==token);
}
static void gaps_conflicts_midstream_limits_expiry_and_late_events_are_truthful(void)
{
  reset();send(101,frame,sizeof(frame),0x18);
  assert(!complete && coverage_count[PRODUCT_DNS_TCP_MIDSTREAM]==1);
  reset();send(100,NULL,0,2);send(101,frame,10,0x18);
  uint8_t changed[10];memcpy(changed,frame,sizeof(changed));changed[4]^=1;
  send(101,changed,sizeof(changed),0x18);
  assert(coverage_count[PRODUCT_DNS_TCP_CONFLICT]==1 && !complete);
  send(111,frame+10,sizeof(frame)-10,0x18);assert(!complete);
  reset();send(100,NULL,0,2);
  input.sequence=101;input.bytes=frame;input.length=sizeof(frame);input.copied=10;input.flags=0x18;
  product_dns_tcp_process(&owner,&requests,&input,observed,&complete);
  assert(coverage_count[PRODUCT_DNS_COPY_GAP]==1 && !complete);
  reset();send(100,NULL,0,2);send(101+65537,frame,1,0x18);
  assert(coverage_count[PRODUCT_DNS_CAPACITY]==1 && !complete);
  reset();send(100,NULL,0,2);send(101,frame,1,0x18);
  input.identity.now_us+=PRODUCT_DNS_REQUEST_US;
  product_dns_tcp_expire(&owner,input.identity.now_us);
  send(102,frame+1,sizeof(frame)-1,0x18);
  assert(owner.expired==1 && coverage_count[PRODUCT_DNS_TCP_EXPIRED]==1 && !complete);
  reset();send(UINT32_MAX-5,NULL,0,2);
  send(UINT32_MAX-4,frame,sizeof(frame),0x18);assert(complete==1);
  product_dns_tcp_end(&owner,76,8);assert(owner.active==1);
  product_dns_tcp_end(&owner,77,9);assert(owner.active==1);
  product_dns_tcp_end(&owner,77,8);assert(!owner.active && !owner.allocated_bytes);
  input.identity.generation=76;send(100,NULL,0,2);assert(!owner.active);
  input.identity.generation=77;
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {input.context.packet.source_port=40000+n;input.identity.incarnation=8+n;send(100,NULL,0,2);}
  assert(owner.active==PRODUCT_DNS_TCP_FLOWS && owner.allocated_bytes<=
    PRODUCT_DNS_TCP_FLOWS*PRODUCT_DNS_TCP_FLOW_BYTES);
  input.context.packet.source_port=50000;input.identity.incarnation=1000;
  send(101,frame,sizeof(frame),0x18);
  assert(coverage_count[PRODUCT_DNS_CAPACITY]==1 && owner.active==PRODUCT_DNS_TCP_FLOWS);
  product_dns_tcp_stop(&owner);assert(!owner.active && !owner.allocated_bytes);
  send(101,frame,sizeof(frame),0x18);assert(!owner.active);
}
static unsigned flow_advances;
static int fresh_flow_facts(void *context,product_l4_policy_packet_t *packet,product_dns_identity_t *identity)
{
  assert(context==&flow_advances);++flow_advances;
  packet->protocol_set_known=1;packet->protocol_set=UINT64_C(1)<<4; // newly obtained SSH catalog fact
  packet->ct_state_known=1;packet->ct_state=2;
  packet->flow_direction_known=1;packet->flow_direction=1;
  identity->incarnation=8;
  return 0;
}
static void complete_frames_use_this_packets_post_facts_and_whole_rule_rank(void)
{
  reset();
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,
    .entries={{.length=11,.name="example.com"}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
  input.context.domains=domains;
  product_l4_policy_rule_t rules[2];
  rules[0]=(product_l4_policy_rule_t){.uid=10123,.rule_id=313,.reason_id=313,
    .action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=8,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0,
      PRODUCT_EXPRESSION_APPLICATION_PROTOCOL,0xed,3,0,0,PRODUCT_STATIC_AND}};
  rules[1]=rules[0];rules[1].rule_id=314;rules[1].priority=1;rules[1].action=1;rules[1].expression_length=2;
  assert(!product_l4_policy_compile(&view,rules,2));
  input.flow_facts=fresh_flow_facts;input.flow_context=&flow_advances;flow_advances=0;
  send(100,NULL,0,2);send(101,frame,sizeof(frame),0x18);
  assert(flow_advances==1 && last_event.match.rule_id==313 && rejected==1);
  assert(last_event.facts.question.packet.ct_state==2);
  product_domains_destroy(domains);
}
static void unknown_caller_split_queries_and_answers_use_current_generic_uid(void)
{
  for(unsigned response=0;response<2;++response)
    for(unsigned current_known=0;current_known<2;++current_known)
      {
        reset();input.context.caller=PRODUCT_DNS_CALLER_UNKNOWN;
        input.context.packet.uid=UINT32_MAX;input.context.packet.uid_known=0;
        product_l4_policy_rule_t rules[2]={
          {.uid=2000,.rule_id=313,.reason_id=313,.action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
           .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
           .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}},
          {.uid=2000,.rule_id=314,.reason_id=314,.priority=1,.action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
           .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX}};
        assert(!product_l4_policy_compile(&view,rules,2));
        send(100,NULL,0,2);
        uint8_t wire[128];const uint8_t *bytes=frame;size_t size=sizeof(frame);unsigned sequence=101;
        if(response)
          {
            send(101,frame,sizeof(frame),0x18);assert(complete==1 && !rejected);
            reverse_direction();send(500,NULL,0,0x12);
            size=reply_wire(wire);bytes=wire;sequence=501;
          }
        input.context.packet.uid=current_known?UINT32_MAX:2000;
        input.context.packet.uid_known=!current_known;
        send(sequence,bytes,8,0x18);
        input.context.packet.uid=current_known?2000:UINT32_MAX;
        input.context.packet.uid_known=current_known;
        send(sequence+8,bytes+8,size-8,0x18);
        assert(last_event.stage==(response?2:1));
        assert(last_event.facts.question.caller==PRODUCT_DNS_CALLER_UNKNOWN);
        assert(!last_event.facts.question.packet.domain_available);
        assert(last_event.facts.question.packet.uid==(current_known?UINT32_MAX:2000));
        assert(last_event.match.actual_action==(current_known?2:0));
        assert(last_event.match.rule_id==(current_known?314:0));
        if(response)
          {
            assert(last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
            assert(last_event.facts.query_uid==UINT32_MAX && !last_event.facts.query_uid_known);
          }
      }
}
static void a_released_rejected_query_correlates_its_later_alias_answer(void)
{
  reset();
  sakamoto_product_domains_t source={.list_count=2,.entry_count=2,
    .entries={{.length=11,.name="example.com"},{.list=1,.length=10,.name="alias.test"}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
  input.context.domains=domains;
  product_l4_policy_rule_t rules[2];
  rules[0]=(product_l4_policy_rule_t){.uid=10123,.rule_id=313,.reason_id=313,
    .action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&view,rules,1));
  send(100,NULL,0,2);send(101,frame,sizeof(frame),0x18);assert(rejected==1);
  rules[1]=rules[0];rules[1].action=1;rules[1].priority=1;rules[1].rule_id=314;
  rules[0].expression[1]=1;rules[0].rule_id=315;
  ++input.policy.revision;input.policy.hash=456;
  assert(!product_l4_policy_compile(&view,rules,2));
  send(101,frame,sizeof(frame),0x18);
  assert(last_complete_event.continuation && last_complete_event.match.actual_action==1);
  uint64_t allowed_token=input.token;
  reverse_direction();send(500,NULL,0,0x12);
  uint8_t wire[128];size_t length=reply_wire(wire);send(501,wire,length,0x18);
  assert(last_event.facts.correlation==PRODUCT_DNS_CORRELATED && last_event.facts.query_token==allowed_token);
  assert(last_event.facts.query_policy.revision==4 && last_event.match.rule_id==315 && rejected==2);
  product_domains_destroy(domains);
}
static void every_split_boundary_preserves_bidirectional_framing(void)
{
  uint8_t reply[128];size_t reply_length=reply_wire(reply);
  for(unsigned family=4;family<=6;family+=2)
    for(unsigned cut=1;cut<sizeof(frame);++cut)
      {
        reset();input.context.packet.family=family;send(100,NULL,0,2);
        send(101,frame,cut,0x18);assert(!complete);
        send(101+cut,frame+cut,sizeof(frame)-cut,0x18);assert(complete==1);
        reverse_direction();send(500,NULL,0,0x12);
        unsigned split=1+(cut%(reply_length-1));
        send(501,reply,split,0x18);assert(complete==1);
        send(501+split,reply+split,reply_length-split,0x18);
        assert(complete==2 && last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
        assert(last_event.facts.question.packet.family==family && last_event.facts.name_count==2);
      }
}
static void repeated_inflight_id_is_ambiguous_without_becoming_original_app(void)
{
  reset();send(100,NULL,0,2);
  uint8_t pipeline[sizeof(frame)*2];
  memcpy(pipeline,frame,sizeof(frame));memcpy(pipeline+sizeof(frame),frame,sizeof(frame));
  send(101,pipeline,sizeof(pipeline),0x18);
  assert(complete==2 && last_event.facts.correlation==PRODUCT_DNS_AMBIGUOUS);
  send(101,pipeline,sizeof(pipeline),0x18);assert(complete==2);
  reverse_direction();send(500,NULL,0,0x12);
  uint8_t reply[128];size_t size=reply_wire(reply);send(501,reply,size,0x18);
  assert(last_event.facts.correlation==PRODUCT_DNS_AMBIGUOUS);
  assert(!last_event.facts.query_token && !last_event.facts.question.caller);
  assert(!last_event.facts.names[0].available && !last_event.facts.names[1].available);
}
static void maximum_message_and_unknown_edns_fit_the_moving_window(void)
{
  static uint8_t framed[PRODUCT_DNS_MESSAGE_MAX+2U];
  reset();memset(framed,0,sizeof(framed));memcpy(framed,frame,sizeof(frame));
  framed[0]=framed[1]=255;framed[13]=1; // Additional OPT, preserving the actual Question.
  const unsigned option_bytes=PRODUCT_DNS_MESSAGE_MAX-(sizeof(frame)-2U)-11U;
  const unsigned data_bytes=option_bytes-4U;
  const uint8_t opt[]={0,0,41,4,208,0,0,0,0,option_bytes>>8,option_bytes&255,
    0xfd,0xe9,data_bytes>>8,data_bytes&255};
  memcpy(framed+sizeof(frame),opt,sizeof(opt));
  send(100,NULL,0,2);
  send(101,framed,32769,0x18);assert(!complete);
  send(32870,framed+32769,sizeof(framed)-32769,0x18);
  assert(complete==1 && last_event.facts.question.codec_peak_bytes<=PRODUCT_DNS_CODEC_BYTES);
  reverse_direction();send(500,NULL,0,0x12);framed[4]=0x81;framed[5]=0x80;
  send(501,framed,32768,0x18);assert(complete==1);
  send(33269,framed+32768,sizeof(framed)-32768,0x18);
  assert(complete==2 && last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
  assert(last_event.facts.name_count==1 && owner.allocated_bytes<=PRODUCT_DNS_TCP_FLOW_BYTES);
  reverse_direction();send(101+sizeof(framed),frame,sizeof(frame),0x18);
  assert(complete==3 && last_event.message_sequence==2 && last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
}
static void a_short_dns_message_does_not_hide_the_next_known_frame(void)
{
  uint8_t reply[128];size_t reply_length=reply_wire(reply);
  for(unsigned family=4;family<=6;family+=2)
    for(unsigned size=0;size<12;++size)
      for(unsigned variant=0;variant<5;++variant)
        {
          reset();input.context.packet.family=family;send(100,NULL,0,2);
          uint8_t stream[sizeof(frame)+13]={0};stream[1]=size;
          memcpy(stream+size+2,frame,sizeof(frame));
          const unsigned cuts[]={1,2,size+1,size+2,size+1+sizeof(frame)};
          unsigned cut=cuts[variant];
          send(101,stream,cut,0x18);
          send(101+cut,stream+cut,size+2+sizeof(frame)-cut,0x18);
          assert(coverage_count[PRODUCT_DNS_MALFORMED]==1 && complete==1);
          assert(last_event.facts.question.coverage==PRODUCT_DNS_QUERY_COMPLETE);
          assert(last_event.message_sequence==2 && owner.messages==2);
          assert(owner.active==1 && owner.allocated_bytes<=PRODUCT_DNS_TCP_FLOW_BYTES);

          reset();input.context.packet.family=family;send(100,NULL,0,2);
          send(101,frame,sizeof(frame),0x18);reverse_direction();send(500,NULL,0,0x12);
          uint8_t responses[141]={0};responses[1]=size;
          if(size>=3) responses[4]=0x81;
          memcpy(responses+size+2,reply,reply_length);
          const unsigned response_cuts[]={1,2,size+1,size+2,size+1+reply_length};
          cut=response_cuts[variant];
          send(501,responses,cut,0x18);
          send(501+cut,responses+cut,size+2+reply_length-cut,0x18);
          assert(complete==2 && coverage_count[PRODUCT_DNS_MALFORMED]==1);
          assert(last_event.stage==2 && last_event.message_sequence==2);
          assert(last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
          assert(!product_dns_resources().codec_live_bytes && !product_dns_resources().active_operations);
        }
  reset();send(100,NULL,0,2);
  uint8_t malformed[sizeof(frame)*2];memcpy(malformed,frame,sizeof(frame));
  malformed[14]=0xc0;malformed[15]=12; // Circular Question pointer, known frame length.
  memcpy(malformed+sizeof(frame),frame,sizeof(frame));
  send(101,malformed,sizeof(malformed),0x18);
  assert(coverage_count[PRODUCT_DNS_MALFORMED]==1 && complete==1);
  assert(last_event.message_sequence==2 && last_event.facts.correlation==PRODUCT_DNS_CORRELATED);
}
static void malformed_frames_preserve_rejection_current_policy_and_deadlines(void)
{
  reset();
  sakamoto_product_domains_t source={.list_count=1,.entry_count=1,
    .entries={{.length=11,.name="example.com"}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
  input.context.domains=domains;
  product_l4_policy_rule_t rule={.uid=10123,.rule_id=313,.reason_id=313,
    .action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&view,&rule,1));
  send(100,NULL,0,2);send(101,frame,sizeof(frame),0x18);assert(rejected==1);
  uint8_t stream[5+sizeof(frame)]={0,3,0x12,0x34,0};memcpy(stream+5,frame,sizeof(frame));
  send(132,stream,sizeof(stream),0x18);
  assert(rejected==2 && last_event.continuation && owner.messages==1);
  rule.action=1;rule.rule_id=314;input.policy.revision=4;input.policy.hash=456;
  assert(!product_l4_policy_compile(&view,&rule,1));send(132,stream,sizeof(stream),0x18);
  assert(last_event.match.actual_action==1 && last_event.match.rule_id==314);
  assert(last_event.message_sequence==3 && coverage_count[PRODUCT_DNS_MALFORMED]==1);
  assert(owner.messages==3 && rejected==2);
  // Releasing an earlier denied request does not merge a later same-ID frame.
  assert(last_event.facts.correlation==PRODUCT_DNS_AMBIGUOUS);
  product_domains_destroy(domains);

  reset();send(100,NULL,0,2);const uint8_t short_frame[13]={0,11};
  send(101,short_frame,sizeof(short_frame),0x18);
  assert(coverage_count[PRODUCT_DNS_MALFORMED]==1 && product_dns_tcp_deadline(&owner)==UINT64_MAX);
  assert(!product_dns_owner_active(&requests,input.identity.now_us));
  product_dns_tcp_end(&owner,77,8);assert(!owner.active && !owner.allocated_bytes);
  reset();send(100,NULL,0,2);send(101,short_frame,5,0x18);
  input.identity.now_us+=PRODUCT_DNS_REQUEST_US;product_dns_tcp_expire(&owner,input.identity.now_us);
  send(106,short_frame+5,sizeof(short_frame)-5,0x18);
  send(114,frame,sizeof(frame),0x18);
  assert(!complete && coverage_count[PRODUCT_DNS_TCP_EXPIRED]>=1);
  assert(owner.active==1 && owner.allocated_bytes<=PRODUCT_DNS_TCP_FLOW_BYTES);
  product_dns_tcp_stop(&owner);assert(!owner.active && !owner.allocated_bytes);
}

static void pipelined_request_capacity_and_owner_isolation_remain_bounded(void)
{
  reset();send(100,NULL,0,2);
  uint8_t request[sizeof(frame)];memcpy(request,frame,sizeof(request));
  for(unsigned n=0;n<PRODUCT_DNS_REQUESTS+1;++n)
    {
      request[2]=(0x3000+n)>>8;request[3]=(0x3000+n)&255;
      send(101+n*sizeof(frame),request,sizeof(request),0x18);
      assert(last_event.facts.correlation==(n<PRODUCT_DNS_REQUESTS
        ? PRODUCT_DNS_CORRELATED : PRODUCT_DNS_REQUEST_CAPACITY));
    }
  assert(product_dns_owner_active(&requests,input.identity.now_us)==PRODUCT_DNS_REQUESTS);
  assert(requests.capacity==1 && !rejected);
  product_dns_tcp_stop(&owner);product_dns_owner_stop(&requests);
  assert(!product_dns_owner_active(&requests,input.identity.now_us) && !owner.allocated_bytes);

  reset();
  for(unsigned n=0;n<PRODUCT_DNS_TCP_FLOWS;++n)
    {
      input.context.packet.source_port=40000+n;input.identity.incarnation=8+n;
      send(100,NULL,0,2);
    }
  assert(owner.active==PRODUCT_DNS_TCP_FLOWS);
  product_dns_tcp_owner_t *other=calloc(1,sizeof(*other));
  product_dns_owner_t *other_requests=calloc(1,sizeof(*other_requests));
  assert(other && other_requests);
  product_dns_tcp_start(other,77);product_dns_owner_start(other_requests,77);
  input.context.packet.source_port=50000;input.identity.incarnation=1000;
  input.sequence=100;input.flags=2;input.length=input.copied=0;input.bytes=NULL;
  product_dns_tcp_process(other,other_requests,&input,observed,&complete);
  input.sequence=101;input.flags=0x18;input.length=input.copied=sizeof(frame);input.bytes=frame;
  product_dns_tcp_process(other,other_requests,&input,observed,&complete);
  assert(complete==1 && other->active==1 && owner.active==PRODUCT_DNS_TCP_FLOWS);
  product_dns_tcp_stop(other);product_dns_owner_stop(other_requests);
  assert(!other->active && !other->allocated_bytes);
  free(other);free(other_requests);product_dns_tcp_stop(&owner);
}

static unsigned fuzz_events;
static void fuzz_observed(void *context,const product_dns_tcp_event_t *event)
{
  assert(context==&fuzz_events);++fuzz_events;
  const product_dns_query_t *question=&event->facts.question;
  assert(question->coverage>=1 && question->coverage<=PRODUCT_DNS_TCP_OLD_BYTES);
  assert(question->codec_peak_bytes<=PRODUCT_DNS_CODEC_BYTES);
  assert(question->packet.protocol==6 && event->match.actual_action!=PRODUCT_L4_POLICY_ACTION_DROP);
  if(question->coverage!=PRODUCT_DNS_QUERY_COMPLETE) assert(!question->packet.domain_available);
}
static void malformed_lengths_truncation_and_seeded_mutations_release_owned_work(void)
{
  for(unsigned size=0;size<12;++size)
    {
      reset();send(100,NULL,0,2);uint8_t length[13]={0};length[1]=size;
      send(101,length,size+2,0x18);
      assert(coverage_count[PRODUCT_DNS_MALFORMED]==1 && !complete);
    }
  uint32_t random=313;
  for(unsigned attempt=0;attempt<512;++attempt)
    {
      reset();send(100,NULL,0,2);
      uint8_t wire[2050];size_t payload=sizeof(frame)-2;
      memcpy(wire,frame,sizeof(frame));
      if(attempt%4==0)
        {
          payload=12+(random%2035);
          for(size_t n=2;n<payload+2;++n)
            {random=random*UINT32_C(1664525)+UINT32_C(1013904223);wire[n]=random>>24;}
        }
      else if(attempt%4!=1)
        for(unsigned n=0;n<1+attempt%8;++n)
          {
            random=random*UINT32_C(1664525)+UINT32_C(1013904223);
            wire[2+random%payload]^=random>>24;
          }
      wire[0]=payload>>8;wire[1]=payload;
      uint8_t original[2050];memcpy(original,wire,payload+2);
      input.bytes=wire;input.copied=input.length=payload+2;input.sequence=101;input.flags=0x18;
      unsigned before=fuzz_events;
      product_dns_tcp_process(&owner,&requests,&input,fuzz_observed,&fuzz_events);
      assert(!memcmp(original,wire,payload+2));
      if(attempt%4==1) assert(fuzz_events==before+1 && owner.messages==1);
      assert(!product_dns_resources().codec_live_bytes && !product_dns_resources().active_operations);
      product_dns_tcp_stop(&owner);product_dns_owner_stop(&requests);
      assert(!owner.active && !owner.allocated_bytes);
    }
}

int main(void)
{
  split_coalesced_and_continuous_frames_move_the_window();
  out_of_order_pipeline_completes_every_ready_frame_once();
  rejection_covers_later_data_and_rechecks_current_policy();
  answers_use_original_caller_and_current_connected_alias_rules();
  tcp_id_reuse_after_an_answer_is_a_new_request();
  gaps_conflicts_midstream_limits_expiry_and_late_events_are_truthful();
  complete_frames_use_this_packets_post_facts_and_whole_rule_rank();
  unknown_caller_split_queries_and_answers_use_current_generic_uid();
  a_released_rejected_query_correlates_its_later_alias_answer();
  every_split_boundary_preserves_bidirectional_framing();
  repeated_inflight_id_is_ambiguous_without_becoming_original_app();
  maximum_message_and_unknown_edns_fit_the_moving_window();
  a_short_dns_message_does_not_hide_the_next_known_frame();
  malformed_frames_preserve_rejection_current_policy_and_deadlines();
  pipelined_request_capacity_and_owner_isolation_remain_bounded();
  malformed_lengths_truncation_and_seeded_mutations_release_owned_work();
  product_dns_owner_stop(&requests);
  puts("continuous original-path TCP DNS: PASS");
}
