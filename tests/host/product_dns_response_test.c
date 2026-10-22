/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Independent wire example: example.com -> alias.test, followed by an A.
 * The compressed owner points to the Question; no wire is reconstructed. */
static const uint8_t answer[] = {
  0x12,0x34,0x81,0x80,0,1,0,2,0,0,0,0,
  7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1,
  0xc0,12,0,5,0,1,0,0,0,60,0,12,
  5,'a','l','i','a','s',4,'t','e','s','t',0,
  0xc0,41,0,1,0,1,0,0,0,60,0,4,192,0,2,1
};
static product_dns_owner_t owner;

static product_dns_context_t conversation (int reply)
{
  product_dns_context_t context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP,
    .packet={.uid=10123,.uid_known=1,.family=4,.protocol=17,
      .direction=reply ? 1 : 3,.direction_known=1,.ports_available=1,
      .source_port=reply ? 53 : 40000,.destination_port=reply ? 40000 : 53,
      .source_address={192,0,2,2},.destination_address={192,0,2,53}}};
  if (reply)
    {
      memcpy(context.packet.source_address,(uint8_t[]){192,0,2,53},4);
      memcpy(context.packet.destination_address,(uint8_t[]){192,0,2,2},4);
      context.caller=PRODUCT_DNS_CALLER_UNKNOWN;
    }
  return context;
}

static product_dns_query_t original_query (product_dns_context_t *context)
{
  uint8_t wire[29];memcpy(wire,answer,sizeof(wire));
  wire[2]=1;wire[3]=0;wire[7]=0;
  product_dns_query_t query;
  product_dns_inspect_query(wire,sizeof(wire),context,&query);
  assert(query.coverage==PRODUCT_DNS_QUERY_COMPLETE);
  return query;
}

static product_dns_identity_t identity (unsigned profile)
{
  return (product_dns_identity_t){.generation=77,.incarnation=8,
    .network_revision=5,.now_us=100,.profile=profile};
}

static void remember (product_dns_context_t *context, product_dns_identity_t *id)
{
  product_dns_query_t query=original_query(context);
  product_dns_policy_identity_t policy={77,3,123,310};
  assert(product_dns_remember(&owner,&query,id,17,&policy)==PRODUCT_DNS_CORRELATED);
}

static void vpn_binding_never_enriches_a_completed_cold_caller(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  context.caller=PRODUCT_DNS_CALLER_UNKNOWN;
  product_dns_identity_t id=identity(2);
  remember(&context,&id);
  /* This is the actual transport-admission event for the original token.
   * Broker binding arrives later and supplies no caller evidence. */
  product_dns_request_transport(&owner,77,17,8,55,0,0,0);
  product_dns_transport_bound(&owner,76,55,7,1,1); // Late generation rejected.
  context=conversation(1);context.packet.network_context_known=1;
  context.packet.network_context_id=1;
  id.transport_session=55;id.underlay_epoch=7;
  product_dns_response_t response;
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_BINDING_UNAVAILABLE);
  product_dns_transport_bound(&owner,77,55,7,1,1);
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED && response.query_token==17);
  assert(response.transport_session==55 && response.underlay_epoch==7);
  assert(response.question.caller==PRODUCT_DNS_CALLER_UNKNOWN && !response.names[1].available);
  ++id.underlay_epoch;
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_BINDING_UNAVAILABLE && !response.query_token);
  --id.underlay_epoch;++id.transport_session;
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_BINDING_UNAVAILABLE);
  product_dns_owner_stop(&owner);
}

static void transport_and_question_context_are_required(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  product_dns_identity_t original=identity(1);
  remember(&context,&original);
  context=conversation(1);
  for(unsigned change=0;change<10;++change)
    {
      product_dns_context_t wrong=context;
      product_dns_identity_t id=original;
      uint8_t wire[sizeof(answer)];memcpy(wire,answer,sizeof(wire));
      if(change==0) ++id.generation;
      if(change==1) ++id.incarnation;
      if(change==2) ++id.network_revision;
      if(change==3) id.profile=2;
      if(change==4) ++wrong.packet.source_address[3];
      if(change==5) ++wrong.packet.destination_port;
      if(change==6) wrong.packet.direction=3;
      if(change==7) wire[1]++;
      if(change==8) wire[28]=3; // Different QCLASS.
      if(change==9) wire[13]='a'; // Different Question, same ID.
      product_dns_response_t response;
      product_dns_inspect_response(wire,sizeof(wire),&wrong,&id,&owner,&response);
      assert(response.correlation!=PRODUCT_DNS_CORRELATED && !response.query_token);
      assert(response.question.caller==PRODUCT_DNS_CALLER_UNKNOWN);
    }
  product_dns_response_t response;
  uint8_t mixed[sizeof(answer)];memcpy(mixed,answer,sizeof(mixed));mixed[13]='E';
  product_dns_inspect_response(mixed,sizeof(mixed),&context,&original,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED);
  /* A subsequent identical ID/Question cannot distinguish a new logical
   * query from a late duplicate answer to the completed one. */
  context=conversation(0);
  product_dns_query_t query=original_query(&context);
  product_dns_policy_identity_t policy={77,3,123,310};
  assert(product_dns_remember(&owner,&query,&original,18,&policy)==PRODUCT_DNS_AMBIGUOUS);
  context=conversation(1);
  product_dns_inspect_response(answer,sizeof(answer),&context,&original,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_AMBIGUOUS && response.matched_requests==2);
  product_dns_owner_stop(&owner);
}

static product_l4_policy_rule_t domain_rule(unsigned id,unsigned priority,unsigned list,unsigned action)
{
  return (product_l4_policy_rule_t){.uid=10123,.rule_id=id,.reason_id=id,
    .priority=priority,.action=action,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,list}};
}

static void whole_rules_keep_each_name_and_one_rank(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  product_dns_identity_t id=identity(1);remember(&context,&id);
  sakamoto_product_domains_t source={.list_count=2,.entry_count=2,
    .entries={{.length=11,.name="example.com"},{.length=10,.name="alias.test",.list=1}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
  context=conversation(1);context.domains=domains;context.domains_available=1;
  product_dns_response_t response;
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  assert(response.names[0].available && response.names[1].available);
  static product_l4_policy_view_t view;
  product_l4_policy_rule_t rules[]={domain_rule(1,2,0,2),domain_rule(2,1,1,1)};
  product_l4_policy_match_result_t result;
  assert(!product_l4_policy_compile(&view,rules,2));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==2 && result.actual_action==1); // Alias ALLOW has ordinary Rank.
  rules[0].priority=0;
  assert(!product_l4_policy_compile(&view,rules,2));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==1 && result.actual_action==2);
  rules[0]=domain_rule(3,0,0,2);
  memcpy(rules[0].expression,(uint8_t[]){17,0,17,1,PRODUCT_STATIC_AND},5);
  rules[0].expression_length=5;
  assert(!product_l4_policy_compile(&view,rules,1));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(!result.evaluation); // QName in A and CNAME in B never form A AND B.
  rules[0].expression[4]=PRODUCT_STATIC_OR;
  assert(!product_l4_policy_compile(&view,rules,1));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==3);
  rules[0]=domain_rule(4,0,1,2);rules[0].mode=1;
  assert(!product_l4_policy_compile(&view,rules,1));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.action==2 && result.actual_action==1); // Observe retains declared DROP.
  rules[0]=domain_rule(5,0,1,2);
  memcpy(rules[0].expression,(uint8_t[]){PRODUCT_EXPRESSION_SNI_ABSENT,1,17,1,PRODUCT_STATIC_OR},5);
  rules[0].expression_length=5;
  assert(!product_l4_policy_compile(&view,rules,1));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(!result.evaluation && !context.packet.sni_result);
  /* The response's actual destination is the client's ephemeral port. */
  rules[0]=domain_rule(6,0,1,2);
  memcpy(rules[0].expression,(uint8_t[]){17,1,PRODUCT_STATIC_DESTINATION_PORT,0xbb,1,0xbb,1,PRODUCT_STATIC_AND},8);
  rules[0].expression_length=8;
  assert(!product_l4_policy_compile(&view,rules,1));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(!result.evaluation && context.packet.destination_address[3]==2);
  product_dns_owner_stop(&owner);product_domains_destroy(domains);
}

static void request_capacity_expiry_stop_and_generation_are_bounded(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  product_dns_query_t query=original_query(&context);
  product_dns_policy_identity_t policy={77,3,123,310};
  product_dns_identity_t id=identity(1);
  for(unsigned i=0;i<PRODUCT_DNS_REQUESTS;++i)
    {
      query.id=i;
      assert(product_dns_remember(&owner,&query,&id,i+1,&policy)==PRODUCT_DNS_CORRELATED);
    }
  assert(product_dns_owner_active(&owner,id.now_us)==PRODUCT_DNS_REQUESTS);
  query.id=UINT16_MAX;
  assert(product_dns_remember(&owner,&query,&id,9999,&policy)==PRODUCT_DNS_REQUEST_CAPACITY);
  context=conversation(1);
  uint8_t wire[sizeof(answer)];memcpy(wire,answer,sizeof(wire));wire[0]=wire[1]=0;
  product_dns_response_t response;
  product_dns_inspect_response(wire,sizeof(wire),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_REQUEST_CAPACITY && !response.query_token);
  id.now_us+=PRODUCT_DNS_REQUEST_US;
  assert(!product_dns_owner_active(&owner,id.now_us));
  product_dns_inspect_response(wire,sizeof(wire),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_UNMATCHED);
  product_dns_owner_stop(&owner);
  context=conversation(0);query=original_query(&context);
  assert(product_dns_remember(&owner,&query,&id,17,&policy)==PRODUCT_DNS_UNMATCHED);
  product_dns_owner_start(&owner,78);
  product_dns_transport_bound(&owner,77,55,7,1,1);
  assert(product_dns_remember(&owner,&query,&id,17,&policy)==PRODUCT_DNS_UNMATCHED);
  assert(!product_dns_owner_active(&owner,id.now_us));
  product_dns_owner_stop(&owner);
}

static void class_any_question_keeps_its_actual_connected_cname(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  uint8_t wire[sizeof(answer)];memcpy(wire,answer,sizeof(wire));wire[28]=255;
  uint8_t query_wire[29];memcpy(query_wire,wire,sizeof(query_wire));
  query_wire[2]=1;query_wire[3]=query_wire[7]=0;
  product_dns_query_t query;
  product_dns_inspect_query(query_wire,sizeof(query_wire),&context,&query);
  assert(query.coverage==PRODUCT_DNS_QUERY_COMPLETE && query.qclass==255);
  product_dns_identity_t id=identity(1);
  product_dns_policy_identity_t policy={77,3,123,310};
  assert(product_dns_remember(&owner,&query,&id,17,&policy)==PRODUCT_DNS_CORRELATED);
  context=conversation(1);
  product_dns_response_t response;
  product_dns_inspect_response(wire,sizeof(wire),&context,&id,&owner,&response);
  assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==2);
  assert(!strcmp(response.names[1].name,"alias.test"));
  /* ANY does not connect an IN alias to an unrelated CHAOS-class RR. */
  uint8_t cross_class[256];memcpy(cross_class,wire,sizeof(wire));
  const uint8_t unrelated[]={5,'a','l','i','a','s',4,'t','e','s','t',0,
    0,5,0,3,0,0,0,60,0,10,3,'b','a','d',4,'t','e','s','t',0};
  memcpy(cross_class+sizeof(wire),unrelated,sizeof(unrelated));cross_class[7]=3;
  product_dns_inspect_response(cross_class,sizeof(wire)+sizeof(unrelated),&context,&id,&owner,&response);
  assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==2);
  product_dns_owner_stop(&owner);
}

static void put16(uint8_t *p,unsigned number) { p[0]=number>>8;p[1]=number; }
static size_t wire_name(uint8_t *wire,const char *name)
{
  size_t used=0;
  while(*name)
    {
      const char *dot=strchr(name,'.');size_t length=dot ? (size_t)(dot-name) : strlen(name);
      wire[used++]=length;memcpy(wire+used,name,length);used+=length;
      if(!dot) break;
      name=dot+1;
    }
  wire[used++]=0;return used;
}
static size_t cname(uint8_t *wire,const char *owner_name,const char *target)
{
  size_t used=wire_name(wire,owner_name);
  memcpy(wire+used,(uint8_t[]){0,5,0,1,0,0,0,60,0,0},10);
  size_t length=wire_name(wire+used+10,target);put16(wire+used+8,length);
  return used+10+length;
}
static void inspect_fixture(const uint8_t *wire,size_t length,product_dns_response_t *response)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  product_dns_identity_t id=identity(1);remember(&context,&id);
  context=conversation(1);context.domains_available=1; // Valid, empty list snapshot.
  product_dns_inspect_response(wire,length,&context,&id,&owner,response);
  product_dns_resources_t resources=product_dns_resources();
  assert(!resources.codec_live_bytes && !resources.active_operations);
  assert(response->question.codec_peak_bytes<=PRODUCT_DNS_CODEC_BYTES);
}

static void connected_chain_limits_cycles_duplicates_and_unrelated_data(void)
{
  uint8_t wire[8192];
  product_dns_response_t response;
  for(unsigned count=0;count<=33;++count)
    {
      memcpy(wire,answer,29);put16(wire+6,count);
      size_t length=29;
      for(unsigned i=0;i<count;++i)
        {
          char from[64],to[64];
          if(!i) strcpy(from,"example.com");else snprintf(from,sizeof(from),"n%u.test",i);
          snprintf(to,sizeof(to),"n%u.test",i+1);
          length+=cname(wire+length,from,to);
        }
      uint8_t untouched[8192];memcpy(untouched,wire,length);
      inspect_fixture(wire,length,&response);
      assert(!memcmp(wire,untouched,length));
      if(count<=32)
        assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==count+1);
      else
        {
          assert(response.question.coverage==PRODUCT_DNS_CAPACITY && response.chain_status==3);
          for(unsigned i=0;i<response.name_count;++i) assert(!response.names[i].available);
        }
    }
  memcpy(wire,answer,29);put16(wire+6,2);
  size_t length=29+cname(wire+29,"example.com","alias.test");
  length+=cname(wire+length,"alias.test","example.com");
  inspect_fixture(wire,length,&response);
  assert(response.question.coverage==PRODUCT_DNS_MALFORMED && response.chain_status==1);
  memcpy(wire,answer,29);put16(wire+6,2);
  length=29+cname(wire+29,"example.com","alias.test");
  length+=cname(wire+length,"example.com","different.test");
  inspect_fixture(wire,length,&response);
  assert(response.question.coverage==PRODUCT_DNS_MALFORMED && response.chain_status==2);
  memcpy(wire,answer,29);put16(wire+6,3);
  length=29+cname(wire+29,"alias.test","last.test"); // Out-of-order Answer chain.
  length+=cname(wire+length,"example.com","alias.test");
  length+=cname(wire+length,"example.com","alias.test"); // Harmless duplicate.
  inspect_fixture(wire,length,&response);
  assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==3);
  assert(!strcmp(response.names[2].name,"last.test"));
  put16(wire+6,0);put16(wire+10,1);
  length=29+cname(wire+29,"example.com","alias.test"); // Additional is not an Answer chain.
  inspect_fixture(wire,length,&response);
  assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==1);
  memcpy(wire,answer,29);put16(wire+6,1);
  length=29+cname(wire+29,"unrelated.test","alias.test");
  inspect_fixture(wire,length,&response);
  assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==1);
  /* An MX target and HTTPS target/hint remain their own RDATA, never aliases. */
  const unsigned types[]={15,33,65,65000};
  for(unsigned i=0;i<4;++i)
    {
      memcpy(wire,answer,29);put16(wire+6,1);length=29;
      wire[length++]=0xc0;wire[length++]=12;
      put16(wire+length,types[i]);length+=2;
      memcpy(wire+length,(uint8_t[]){0,1,0,0,0,60},6);length+=6;
      size_t size_at=length;length+=2;size_t start=length;
      if(types[i]==33) { memset(wire+length,0,6);length+=6; }
      else if(types[i]!=65000) { wire[length++]=0;wire[length++]=0; }
      length+=wire_name(wire+length,"alias.test");put16(wire+size_at,length-start);
      inspect_fixture(wire,length,&response);
      assert(response.question.coverage==PRODUCT_DNS_QUERY_COMPLETE && response.name_count==1);
    }
  product_dns_owner_stop(&owner);
}

static void malformed_truncated_and_mutated_answers_release_the_codec(void)
{
  product_dns_response_t response;
  for(size_t size=0;size<sizeof(answer);++size)
    {
      inspect_fixture(answer,size,&response);
      assert(response.question.coverage!=PRODUCT_DNS_QUERY_COMPLETE);
      assert(!response.names[0].available);
    }
  uint8_t wire[sizeof(answer)+1];memcpy(wire,answer,sizeof(answer));
  wire[sizeof(answer)]=0xff;
  inspect_fixture(wire,sizeof(wire),&response);
  assert(response.question.coverage==PRODUCT_DNS_MALFORMED);
  memcpy(wire,answer,sizeof(answer));wire[2]|=2; // A complete TC message is partial coverage.
  inspect_fixture(wire,sizeof(answer),&response);
  assert(response.question.coverage==PRODUCT_DNS_COPY_GAP && !response.names[1].available);
  memcpy(wire,answer,sizeof(answer));wire[12]=0xc0;wire[13]=12;
  inspect_fixture(wire,sizeof(answer),&response);
  assert(response.question.coverage==PRODUCT_DNS_MALFORMED);
  uint32_t random=312;
  for(unsigned attempt=0;attempt<3000;++attempt)
    {
      memcpy(wire,answer,sizeof(answer));
      for(unsigned i=0;i<4;++i)
        {
          random=random*UINT32_C(1664525)+UINT32_C(1013904223);
          wire[random%sizeof(answer)]^=random>>24;
        }
      inspect_fixture(wire,sizeof(answer),&response);
    }
  product_dns_owner_stop(&owner);
}

static void response_not_requires_one_available_candidate(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  product_dns_identity_t id=identity(1);remember(&context,&id);
  sakamoto_product_domains_t source={.list_count=2,.entry_count=2,
    .entries={{.length=11,.name="example.com"},{.length=10,.name="alias.test",.list=1}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&source,&domains));
  context=conversation(1);context.domains=domains;context.domains_available=1;
  product_dns_response_t response;
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  product_l4_policy_rule_t rules[]={domain_rule(7,0,1,2),domain_rule(8,1,1,1),domain_rule(9,10,0,1)};
  rules[0].expression[2]=PRODUCT_STATIC_NOT;rules[0].expression_length=3;
  rules[2].expression_length=0; // Independent generic fallback.
  static product_l4_policy_view_t view;
  product_l4_policy_match_result_t result;
  assert(!product_l4_policy_compile(&view,rules,3));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==7 && result.actual_action==2); // Only QName satisfies NOT alias-list.
  rules[0].priority=2;
  assert(!product_l4_policy_compile(&view,rules,3));
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==8 && result.actual_action==1); // Alias ALLOW still uses Rank.
  rules[0].priority=0;assert(!product_l4_policy_compile(&view,rules,3));
  product_dns_inspect_response(answer,sizeof(answer)-1,&context,&id,&owner,&response);
  assert(response.question.coverage==PRODUCT_DNS_MALFORMED);
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==9 && result.actual_action==1);
  uint8_t wire[8192];memcpy(wire,answer,29);put16(wire+6,33);
  size_t length=29;
  for(unsigned i=0;i<33;++i)
    {
      char from[64],to[64];
      if(!i) strcpy(from,"example.com");else snprintf(from,sizeof(from),"n%u.test",i);
      snprintf(to,sizeof(to),"n%u.test",i+1);
      length+=cname(wire+length,from,to);
    }
  product_dns_inspect_response(wire,length,&context,&id,&owner,&response);
  assert(response.question.coverage==PRODUCT_DNS_CAPACITY && response.name_count==33);
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==9 && result.actual_action==1); // No NOT hit from an incomplete chain.
  product_dns_owner_start(&owner,77);
  product_dns_context_t cold=conversation(0);cold.caller=PRODUCT_DNS_CALLER_UNKNOWN;
  remember(&cold,&id);
  product_dns_inspect_response(answer,sizeof(answer),&context,&id,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED && !response.question.caller);
  assert(!product_dns_response_match(&view,&context.packet,&response,0,&result));
  assert(result.rule_id==9 && result.actual_action==1); // Known current socket does not upgrade original caller.
  product_dns_owner_stop(&owner);product_domains_destroy(domains);
}

static void a_different_interface_does_not_borrow_the_original_caller(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  context.packet.ifindex_known=1;context.packet.ifindex=7;
  product_dns_query_t query=original_query(&context);
  product_dns_identity_t identity={.generation=77,.incarnation=8,
    .network_revision=5,.now_us=100,.profile=1};
  product_dns_policy_identity_t policy={77,3,123,310};
  assert(product_dns_remember(&owner,&query,&identity,17,&policy)==PRODUCT_DNS_CORRELATED);
  context=conversation(1);context.packet.ifindex_known=1;context.packet.ifindex=8;
  product_dns_response_t response;
  product_dns_inspect_response(answer,sizeof(answer),&context,&identity,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_UNMATCHED);
  assert(response.question.caller==PRODUCT_DNS_CALLER_UNKNOWN && !response.query_token);
  context.packet.ifindex=7;
  product_dns_inspect_response(answer,sizeof(answer),&context,&identity,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED && response.query_token==17);
  product_dns_owner_stop(&owner);
}

static void retransmits_with_different_decisions_do_not_choose_one_history(void)
{
  product_dns_owner_start(&owner,77);
  product_dns_context_t context=conversation(0);
  product_dns_query_t query=original_query(&context);
  product_dns_identity_t identity={.generation=77,.incarnation=8,
    .network_revision=5,.now_us=100,.profile=1};
  product_dns_policy_identity_t policy={77,3,123,310};
  assert(product_dns_remember(&owner,&query,&identity,17,&policy)==PRODUCT_DNS_CORRELATED);
  assert(product_dns_remember(&owner,&query,&identity,18,&policy)==PRODUCT_DNS_CORRELATED);
  policy.revision=4;policy.hash=456;
  assert(product_dns_remember(&owner,&query,&identity,19,&policy)==PRODUCT_DNS_AMBIGUOUS);
  context=conversation(1);
  product_dns_response_t response;
  product_dns_inspect_response(answer,sizeof(answer),&context,&identity,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_AMBIGUOUS && !response.query_token);
  assert(!response.query_policy.revision && response.question.caller==PRODUCT_DNS_CALLER_UNKNOWN);
  product_dns_owner_stop(&owner);
}

static void connected_alias_uses_original_caller_and_current_policy(void)
{
  sakamoto_product_domains_t source = {.list_count=2,.entry_count=2,
    .entries={{.length=11,.name="example.com"},
              {.length=10,.name="alias.test",.list=1}}};
  product_domains_t *domains=NULL;
  assert(!product_domains_build(&source,&domains));
  product_dns_context_t context={.domains=domains,.domains_available=1,
    .caller=PRODUCT_DNS_CALLER_PLATFORM_APP,
    .packet={.uid=10123,.uid_known=1,.family=4,.protocol=17,
      .direction=3,.direction_known=1,.ports_available=1,
      .source_port=40000,.destination_port=53,
      .source_address={192,0,2,2},.destination_address={192,0,2,53}}};
  product_dns_identity_t identity={.generation=77,.incarnation=8,
    .network_revision=5,.now_us=100,.profile=1};
  product_dns_owner_start(&owner,77);
  uint8_t query_wire[29]; memcpy(query_wire,answer,sizeof(query_wire));
  query_wire[2]=1;query_wire[3]=0;query_wire[7]=0;
  product_dns_query_t query;
  product_dns_inspect_query(query_wire,sizeof(query_wire),&context,&query);
  assert(query.coverage==PRODUCT_DNS_QUERY_COMPLETE);
  product_dns_policy_identity_t original={77,3,123,310};
  assert(product_dns_remember(&owner,&query,&identity,17,&original)==PRODUCT_DNS_CORRELATED);
  context.packet.direction=1;
  context.packet.source_port=53;context.packet.destination_port=40000;
  memcpy(context.packet.source_address,(uint8_t[]){192,0,2,53},4);
  memcpy(context.packet.destination_address,(uint8_t[]){192,0,2,2},4);
  context.caller=PRODUCT_DNS_CALLER_UNKNOWN;context.packet.uid_known=0;
  identity.now_us=101;
  product_dns_response_t response;
  product_dns_inspect_response(answer,sizeof(answer),&context,&identity,&owner,&response);
  assert(response.correlation==PRODUCT_DNS_CORRELATED);
  assert(response.query_token==17 && response.query_policy.revision==3);
  assert(response.question.caller==PRODUCT_DNS_CALLER_PLATFORM_APP);
  assert(response.name_count==2 && !strcmp(response.names[1].name,"alias.test"));
  assert(response.names[0].lists==1 && response.names[1].lists==2);
  static product_l4_policy_view_t view;
  product_l4_policy_rule_t rule={.uid=10123,.rule_id=312,.reason_id=312,
    .action=2,.network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,
    .source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
    .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,1}};
  assert(!product_l4_policy_compile(&view,&rule,1));
  product_l4_policy_match_result_t result;
  assert(!product_dns_response_match(&view,&context.packet,&response,
    PRODUCT_L4_POLICY_POSITION_ALL,&result));
  assert(result.rule_id==312 && result.actual_action==2);
  /* Replacing the current snapshot changes the response's own winner. */
  rule.action=1;rule.rule_id=313;
  assert(!product_l4_policy_compile(&view,&rule,1));
  assert(!product_dns_response_match(&view,&context.packet,&response,
    PRODUCT_L4_POLICY_POSITION_ALL,&result));
  assert(result.rule_id==313 && result.actual_action==1);
  assert(response.query_policy.revision==3); /* Historical decision survives. */
  product_dns_owner_stop(&owner);
  assert(!product_dns_owner_active(&owner,102));
  product_domains_destroy(domains);
}

int main(void)
{
  connected_alias_uses_original_caller_and_current_policy();
  a_different_interface_does_not_borrow_the_original_caller();
  retransmits_with_different_decisions_do_not_choose_one_history();
  vpn_binding_never_enriches_a_completed_cold_caller();
  transport_and_question_context_are_required();
  whole_rules_keep_each_name_and_one_rank();
  response_not_requires_one_available_candidate();
  request_capacity_expiry_stop_and_generation_are_bounded();
  class_any_question_keeps_its_actual_connected_cname();
  connected_chain_limits_cycles_duplicates_and_unrelated_data();
  malformed_truncated_and_mutated_answers_release_the_codec();
  puts("UDP reply correlation and connected CNAME policy: PASS");
}
