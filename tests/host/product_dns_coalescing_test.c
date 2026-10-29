/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_proxy.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static product_l4_policy_view_t view;
static product_dns_proxy_snapshot_t snapshot;
static product_dns_proxy_key_t upstream;
static unsigned sends, replies, cancellations;
static uint8_t sent[512];
static size_t sent_length;
static uint64_t sent_deadline;
static unsigned sent_transport;
static int send_result=1;
static unsigned received_ids[128], received_uids[128], received_codes[128];
static product_dns_proxy_key_t waiter_keys[256];
static unsigned queries, terminals;
static product_dns_proxy_event_t reply_events[128];
static product_dns_proxy_event_t terminal_events[256];
static unsigned resource_uid,resource_attempts,fallback_rejected,stale_uid,abandoned;
static uint64_t abandoned_token;
static unsigned fail_encoding, failed_allocations;
void *__real_malloc(size_t);
void *__wrap_malloc(size_t bytes)
{
 if(fail_encoding==2){fail_encoding=0;++failed_allocations;return NULL;}
 return __real_malloc(bytes);
}
static product_dns_proxy_t *reentrant_proxy;
static unsigned reentrant_action;
static void reenter_with_uncached_question(void);
static int send_query(void *ctx,const product_dns_proxy_key_t *key,unsigned transport,
 const uint8_t *wire,size_t length,uint64_t deadline)
{ (void)ctx;assert((transport==1||transport==2)&&deadline);sent_transport=transport;sent_deadline=deadline;upstream=*key;memcpy(sent,wire,length);sent_length=length;++sends;return send_result; }
static int reply(void *ctx,const product_dns_proxy_event_t *event,const uint8_t *wire,size_t length)
{ (void)ctx;assert(length>=12&&replies<128);
 if(resource_uid && event->stage==2 && event->input.context.packet.uid==resource_uid) {
  if(fail_encoding==1)fail_encoding=2;
  ++resource_attempts;return -1;
 }
 if(stale_uid && event->stage==2 && event->input.context.packet.uid==stale_uid)return 0;
 if(fallback_rejected && event->stage==3 && event->result==PRODUCT_DNS_PROXY_CAPACITY)return 0;
 received_ids[replies]=wire[0]*256U+wire[1];
 reply_events[replies]=*event;received_codes[replies]=wire[3]&15;received_uids[replies++]=event->input.context.packet.uid;
 if(reentrant_action){unsigned action=reentrant_action;reentrant_action=0;
  if(action==1)product_dns_proxy_cancel(reentrant_proxy,&waiter_keys[1],event->input.identity.now_us);
  else if(action==2)product_dns_proxy_stop(reentrant_proxy,event->input.identity.now_us);
  else if(action==3)product_dns_proxy_answer(reentrant_proxy,&upstream,sent_transport,wire,length,event->input.identity.now_us);
  else reenter_with_uncached_question();
 }return 1; }
static void cancel(void *ctx,const product_dns_proxy_key_t *key)
{ (void)ctx;unsigned found=0;for(unsigned i=0;i<queries;++i)found|=!memcmp(key,&waiter_keys[i],sizeof(*key));
 assert(found);++cancellations; }
static int acquire(void *ctx,const product_dns_proxy_input_t *in,product_dns_proxy_snapshot_t *out)
{ (void)ctx;*out=snapshot;out->context.packet=in->context.packet;out->context.caller=in->context.caller;return 1; }
static void observe(void *ctx,const product_dns_proxy_event_t *event)
{ (void)ctx;if(event->stage==1&&event->result==PRODUCT_DNS_PROXY_QUERY){assert(queries<256);waiter_keys[queries++]=event->key;}
 else if(event->stage!=1){assert(terminals<256);terminal_events[terminals++]=*event;} }
static void abandon(void *ctx,const product_dns_proxy_event_t *event)
{ (void)ctx;++abandoned;abandoned_token=event->input.token; }
static const uint8_t question[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
 7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
static product_dns_proxy_input_t input;
static void reenter_with_uncached_question(void)
{
 uint8_t other[sizeof(question)];memcpy(other,question,sizeof(other));other[13]='z';
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;
 ++input.identity.now_us;
 assert(product_dns_proxy_submit(reentrant_proxy,&input,other,sizeof(other),&snapshot));
}
static product_dns_proxy_t *open_proxy(void)
{
 sends=replies=cancellations=queries=terminals=reentrant_action=resource_uid=resource_attempts=0;
 fallback_rejected=stale_uid=abandoned=0;abandoned_token=0;send_result=1;
 fail_encoding=failed_allocations=0;
 assert(!product_l4_policy_compile(&view,NULL,0));
 input=(product_dns_proxy_input_t){.identity={.generation=77,.network_revision=5,.now_us=1000000,.profile=1,
 .incarnation=11,.transport_session=21},.token=1,.route_revision=3,.slot=UINT32_MAX,
 .context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP,.packet={.uid=10123,.uid_known=1,.family=4,
 .protocol=17,.direction=3,.direction_known=1,.ports_available=1,.source_port=40000,.destination_port=53}}};
 snapshot=(product_dns_proxy_snapshot_t){.context=input.context,.view=&view,.identity={77,3,123,0},
 .network_revision=5,.route_revision=3};
 product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={192,0,2,53}};
 product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.cancel=cancel,.acquire=acquire,.observe=observe,.abandon=abandon};
 product_dns_proxy_t *proxy=product_dns_proxy_open(77,&route,&callbacks,NULL);assert(proxy);return proxy;
}
static void independent_simultaneous_waiters(void)
{
 product_dns_proxy_t *proxy=open_proxy();
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 uint8_t next[sizeof(question)];memcpy(next,question,sizeof(next));next[0]=0xab;next[1]=0xcd;
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;input.context.packet.uid=10124;input.context.packet.source_port=40001;
 assert(product_dns_proxy_submit(proxy,&input,next,sizeof(next),&snapshot));
 assert(product_dns_proxy_resources(proxy).cache_entries==0&&replies==0);
 assert(sends==1); /* two simultaneously outstanding requests, no cached answer */
 uint8_t answer[sizeof(question)+16];memcpy(answer,sent,sent_length);answer[2]=0x81;answer[3]=0x80;answer[7]=1;
 memcpy(answer+sent_length,(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
 product_dns_proxy_answer(proxy,&upstream,1,answer,sizeof(answer),1000001);
 assert(replies==2&&received_ids[0]==0x1234&&received_ids[1]==0xabcd);
 assert(received_uids[0]==10123&&received_uids[1]==10124);
 assert(cancellations==1&&product_dns_proxy_resources(proxy).active==0);
 product_dns_proxy_close(proxy);
}
static void submit_pair(product_dns_proxy_t *proxy,uint64_t delay)
{
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;
 input.context.packet.uid=10124;input.context.packet.source_port=40001;input.identity.now_us+=delay;
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 assert(sends==1&&queries==2&&replies==0&&product_dns_proxy_resources(proxy).active==2);
}
static void answer_pair(product_dns_proxy_t *proxy,uint64_t now)
{
 uint8_t wire[sizeof(question)+16];memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x80;wire[7]=1;
 memcpy(wire+sent_length,(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
 product_dns_proxy_answer(proxy,&upstream,sent_transport,wire,sizeof(wire),now);
}
static void joining_waiter_keeps_the_original_candidate_deadline(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1000000);
 const uint64_t original=4000000;assert(sent_deadline==original);
 product_dns_proxy_advance(proxy,2500000,5,3);
 assert(sends==2&&sent_deadline==original); /* retry never extends candidate */
 product_dns_proxy_advance(proxy,original,5,3);
 assert(replies==2&&received_codes[0]==2&&received_codes[1]==2);
 assert(product_dns_proxy_resources(proxy).active==0&&cancellations==1);
 answer_pair(proxy,original+1);assert(replies==2&&!product_dns_proxy_resources(proxy).cache_entries);
 product_dns_proxy_close(proxy);
}
static void cancelling_one_waiter_keeps_the_other_before_candidate_deadline(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1000000);
 product_dns_proxy_cancel(proxy,&waiter_keys[0],2100000);
 assert(!replies&&!cancellations&&product_dns_proxy_resources(proxy).active==1);
 answer_pair(proxy,3500000);
 assert(replies==1&&received_uids[0]==10124&&received_codes[0]==0&&cancellations==1);
 assert(product_dns_proxy_resources(proxy).cancelled==1);
 product_dns_proxy_close(proxy);
}
static void late_answer_cannot_extend_candidate_after_first_waiter_cancels(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1000000);
 product_dns_proxy_cancel(proxy,&waiter_keys[0],2100000);
 answer_pair(proxy,4000001); /* before any timeout advance callback */
 assert(replies==1&&received_uids[0]==10124&&received_codes[0]==2&&cancellations==1);
 assert(!product_dns_proxy_resources(proxy).active&&!product_dns_proxy_resources(proxy).cache_entries);
 product_dns_proxy_close(proxy);
}
static void truncated_udp_continuation_keeps_the_original_candidate_deadline(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1000000);
 uint8_t tc[sizeof(question)];memcpy(tc,sent,sizeof(tc));tc[2]=0x83;tc[3]=0x80;
 product_dns_proxy_answer(proxy,&upstream,1,tc,sizeof(tc),2100000);
 assert(sends==2&&sent_transport==2&&sent_deadline==4000000);
 answer_pair(proxy,3500000);assert(replies==2&&received_codes[0]==0&&received_codes[1]==0);
 product_dns_proxy_close(proxy);
}
static void cancellation_end_stop_and_late_events_settle_each_waiter_once(void)
{
 for(unsigned action=0;action<5;++action){
  product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1);product_dns_proxy_key_t old=upstream;
  if(action==0){product_dns_proxy_cancel(proxy,&waiter_keys[0],2000000);product_dns_proxy_cancel(proxy,&waiter_keys[1],2000000);}
  else if(action==1){product_dns_proxy_end(proxy,77,11,2000000);assert(product_dns_proxy_resources(proxy).active==1);
   product_dns_proxy_end(proxy,77,12,2000000);}
  else if(action==2){product_dns_proxy_session_end(proxy,77,21,2000000);assert(product_dns_proxy_resources(proxy).active==1);
   product_dns_proxy_session_end(proxy,77,22,2000000);}
  else if(action==3)product_dns_proxy_stop(proxy,2000000);
  else{snapshot.network_revision=6;product_dns_proxy_advance(proxy,2000000,6,3);}
  assert(product_dns_proxy_resources(proxy).active==0&&product_dns_proxy_resources(proxy).exchanges==0);
  assert(cancellations==1&&terminals==2&&replies==(action==4?2U:0U));
  unsigned before_replies=replies,before_terminals=terminals;
  answer_pair(proxy,2000001);product_dns_proxy_fail(proxy,&old,2000002);
  product_dns_proxy_cancel(proxy,&waiter_keys[0],2000003);product_dns_proxy_advance(proxy,6000000,6,3);
  assert(replies==before_replies&&terminals==before_terminals&&!product_dns_proxy_resources(proxy).cache_entries);
  product_dns_proxy_close(proxy);assert(cancellations==1);
 }
}
static void a_retired_group_key_cannot_complete_its_replacement(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1);product_dns_proxy_key_t old=upstream;
 uint8_t old_wire[sizeof(question)+16];memcpy(old_wire,sent,sent_length);old_wire[2]=0x81;old_wire[3]=0x80;old_wire[7]=1;
 memcpy(old_wire+sent_length,(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
 product_dns_proxy_cancel(proxy,&waiter_keys[0],1500000);product_dns_proxy_cancel(proxy,&waiter_keys[1],1500000);
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;input.identity.now_us=2000000;
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 assert(sends==2&&product_dns_proxy_resources(proxy).active==1);
 product_dns_proxy_answer(proxy,&old,1,old_wire,sizeof(old_wire),2000001);
 assert(!replies&&product_dns_proxy_resources(proxy).active==1&&!product_dns_proxy_resources(proxy).cache_entries);
 answer_pair(proxy,2000002);assert(replies==1&&received_codes[0]==0&&cancellations==2);
 product_dns_proxy_close(proxy);
}
static void current_policy_is_independent_before_join_and_before_delivery(void)
{
 for(unsigned when=0;when<2;++when){
  product_dns_proxy_t *proxy=open_proxy();
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
  product_l4_policy_rule_t deny={.uid=when?10123:10124,.rule_id=320,.reason_id=320,.action=2,
   .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX};
  if(!when){assert(!product_l4_policy_compile(&view,&deny,1));++snapshot.identity.revision;}
  ++input.token;++input.identity.incarnation;++input.identity.transport_session;input.context.packet.uid=10124;input.context.packet.source_port=40001;
  product_dns_proxy_snapshot_t latest=snapshot;latest.context.packet=input.context.packet;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&latest));
  if(!when){assert(replies==1&&received_uids[0]==10124&&received_codes[0]==5);
   assert(product_dns_proxy_resources(proxy).active==1&&product_dns_proxy_resources(proxy).coalesced==0);}
  else{assert(!product_l4_policy_compile(&view,&deny,1));++snapshot.identity.revision;
   assert(!replies&&product_dns_proxy_resources(proxy).active==2);}
  answer_pair(proxy,2000000);
  assert(sends==1&&replies==2&&product_dns_proxy_resources(proxy).cache_entries==1);
  if(when){assert(received_uids[0]==10123&&received_codes[0]==5&&received_uids[1]==10124&&received_codes[1]==0);
   assert(reply_events[0].policy.revision>reply_events[0].query_policy.revision);
   assert(reply_events[1].policy.revision>reply_events[1].query_policy.revision);}
  else assert(received_uids[1]==10123&&received_codes[1]==0);
  product_dns_proxy_close(proxy);
 }
}
static void opaque_options_and_full_question_or_view_differences_do_not_join(void)
{
 for(unsigned variant=0;variant<12;++variant){
  product_dns_proxy_t *proxy=open_proxy();uint8_t q[sizeof(question)+15];memcpy(q,question,sizeof(question));size_t length=sizeof(question);
  if(variant==4||variant==5){q[11]=1;memcpy(q+length,(uint8_t[]){0,0,41,4,208,0,0,0,0,0,4,0xfd,0xe8,0,0},15);length+=15;}
  assert(product_dns_proxy_submit(proxy,&input,q,length,&snapshot));
  ++input.token;
  if(variant==0)q[13]='E';
  else if(variant==1)q[3]=0x10;
  else if(variant==2)q[sizeof(question)-3]=28;
  else if(variant==3)q[sizeof(question)-1]=3;
  else if(variant==5)q[length-3]=0xe9;
  else if(variant==6)++input.identity.network_revision;
  else if(variant==7)++input.route_revision;
  else if(variant==8)++input.identity.underlay_epoch;
  else if(variant==9)++input.identity.profile;
  else if(variant==10){input.context.packet.network_context_known=1;input.context.packet.network_context_id=9;}
  else if(variant==11)input.context.packet.destination_address[0]=1;
  snapshot.context.packet=input.context.packet;snapshot.network_revision=input.identity.network_revision;snapshot.route_revision=input.route_revision;
  assert(product_dns_proxy_submit(proxy,&input,q,length,&snapshot));
  assert(sends==2&&!replies&&product_dns_proxy_resources(proxy).active==2&&product_dns_proxy_resources(proxy).exchanges==2);
  if(variant==4||variant==5)assert(!memcmp(sent+2,q+2,length-2));
  product_dns_proxy_close(proxy);assert(cancellations==2);
 }
 /* Safe empty EDNS0+DO joins only when all bytes, including UDP capacity, agree. */
 product_dns_proxy_t *proxy=open_proxy();uint8_t q[sizeof(question)+11];memcpy(q,question,sizeof(question));q[11]=1;
 memcpy(q+sizeof(question),(uint8_t[]){0,0,41,4,208,0,0,0x80,0,0,0},11);
 assert(product_dns_proxy_submit(proxy,&input,q,sizeof(q),&snapshot));++input.token;
 assert(product_dns_proxy_submit(proxy,&input,q,sizeof(q),&snapshot));assert(sends==1&&product_dns_proxy_resources(proxy).active==2);
 q[sizeof(question)+4]=0xd1;++input.token;
 assert(product_dns_proxy_submit(proxy,&input,q,sizeof(q),&snapshot));assert(sends==2&&product_dns_proxy_resources(proxy).active==3);
 product_dns_proxy_close(proxy);
}
static void waiter_capacity_is_independent_of_exchange_capacity(void)
{
 product_dns_proxy_t *proxy=open_proxy();uint64_t baseline=product_dns_proxy_resources(proxy).owned_bytes;
 for(unsigned i=0;i<128;++i){input.token=i+1;assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));}
 product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
 assert(sends==1&&!replies&&resources.active==128&&resources.exchanges==1&&resources.coalesced==127);
 assert(resources.owned_bytes==baseline+sizeof(question));++input.token;
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 assert(sends==1&&replies==1&&received_codes[0]==2&&reply_events[0].result==PRODUCT_DNS_PROXY_CAPACITY);
 assert(!reply_events[0].match.rule_id&&product_dns_proxy_resources(proxy).active==128);
 product_dns_proxy_cancel(proxy,&waiter_keys[0],1500000);++input.token;
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));assert(sends==1&&product_dns_proxy_resources(proxy).active==128);
 product_dns_proxy_stop(proxy,2000000);
 assert(cancellations==1&&product_dns_proxy_resources(proxy).owned_bytes==baseline&&product_dns_proxy_resources(proxy).active==0);
 product_dns_proxy_close(proxy);
}
static void same_round_response_cancel_stop_and_failure_are_exactly_once(void)
{
 for(unsigned action=1;action<=3;++action){
  product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1);reentrant_proxy=proxy;reentrant_action=action;
  answer_pair(proxy,2000000);
  assert(replies==(action==3?2U:1U)&&terminals==2&&cancellations==1&&product_dns_proxy_resources(proxy).active==0);
  unsigned before=replies;answer_pair(proxy,2000001);assert(replies==before);
  product_dns_proxy_close(proxy);
 }
 product_dns_proxy_t *proxy=open_proxy();submit_pair(proxy,1);send_result=-1;
 uint8_t tc[sizeof(question)];memcpy(tc,sent,sizeof(tc));tc[2]=0x83;tc[3]=0x80;
 product_dns_proxy_answer(proxy,&upstream,1,tc,sizeof(tc),2000000);
 assert(sends==2&&replies==2&&received_codes[0]==2&&received_codes[1]==2&&cancellations==1&&terminals==2);
 product_dns_proxy_close(proxy);
}
static void connected_alias_policy_is_per_app_and_unknown_never_inherits_a_caller(void)
{
 for(unsigned unknown=0;unknown<2;++unknown){
  product_dns_proxy_t *proxy=open_proxy();
  sakamoto_product_domains_t lists={.list_count=1,.entry_count=1,
   .entries={{.list=0,.length=10,.name="alias.test"}}};
  product_domains_t *domains=NULL;assert(!product_domains_build(&lists,&domains));
  snapshot.context.domains=domains;snapshot.context.domains_available=1;input.context.domains_available=1;
  if(unknown)input.context.caller=PRODUCT_DNS_CALLER_UNKNOWN;
  product_dns_proxy_snapshot_t initial=snapshot;initial.context.caller=input.context.caller;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&initial));
  ++input.token;++input.identity.incarnation;++input.identity.transport_session;
  input.context.caller=PRODUCT_DNS_CALLER_PLATFORM_APP;input.context.packet.uid=10124;input.context.packet.source_port=40001;
  product_dns_proxy_snapshot_t second=snapshot;second.context.packet=input.context.packet;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&second));assert(sends==1&&!replies);
  product_l4_policy_rule_t deny={.uid=10123,.rule_id=320,.reason_id=320,.action=2,
   .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
   .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
  assert(!product_l4_policy_compile(&view,&deny,1));++snapshot.identity.revision;
  uint8_t wire[256];memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x80;wire[7]=2;
  size_t at=sent_length;
  memcpy(wire+at,(uint8_t[]){0xc0,12,0,5,0,1,0,0,0,30,0,12,5,'a','l','i','a','s',4,'t','e','s','t',0},24);at+=24;
  memcpy(wire+at,(uint8_t[]){0xc0,0,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
  wire[at+1]=(uint8_t)(sent_length+12);at+=16;
  product_dns_proxy_answer(proxy,&upstream,1,wire,at,2000000);
  assert(replies==2&&received_codes[0]==(unknown?0U:5U)&&received_codes[1]==0);
  assert(reply_events[0].query.caller==(unknown?PRODUCT_DNS_CALLER_UNKNOWN:PRODUCT_DNS_CALLER_PLATFORM_APP));
  assert(reply_events[0].match.rule_id==(unknown?0U:320U)&&reply_events[1].match.rule_id==0);
  assert(product_dns_proxy_resources(proxy).cache_entries==1&&cancellations==1);
  product_dns_proxy_close(proxy);product_domains_destroy(domains);
 }
}
static void one_tcp_output_capacity_failure_gets_own_servfail(void)
{
 product_dns_proxy_t *proxy=open_proxy();
 input.context.packet.protocol=6;snapshot.context.packet.protocol=6;resource_uid=10123;
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 uint8_t second[sizeof(question)];memcpy(second,question,sizeof(second));second[0]=0xab;second[1]=0xcd;
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;
 input.context.packet.uid=10124;input.context.packet.source_port=40001;
 assert(product_dns_proxy_submit(proxy,&input,second,sizeof(second),&snapshot));
 assert(sends==1 && !replies && product_dns_proxy_resources(proxy).active==2);
 answer_pair(proxy,2000000);
 assert(resource_attempts==1 && replies==2 && terminals==2 && cancellations==1);
 assert(received_ids[0]==0x1234 && received_codes[0]==2 && received_uids[0]==10123);
 assert(received_ids[1]==0xabcd && received_codes[1]==0 && received_uids[1]==10124);
 assert(terminal_events[0].stage==3 && terminal_events[0].result==PRODUCT_DNS_PROXY_CAPACITY);
 assert(terminal_events[0].response && !terminal_events[0].cached);
 assert(terminal_events[0].policy.revision==snapshot.identity.revision);
 assert(terminal_events[0].output_bytes==sizeof(question) && terminal_events[0].delivery==1);
 assert(terminal_events[1].stage==2 && terminal_events[1].result==PRODUCT_DNS_PROXY_UPSTREAM);
 assert(!product_dns_proxy_resources(proxy).active && !product_dns_proxy_resources(proxy).exchanges);
 product_dns_proxy_close(proxy);
}
static void failed_servfail_encoding_keeps_source_policy_and_zero_output(void)
{
 for(unsigned cached=0;cached<2;++cached) {
  product_dns_proxy_t *proxy=open_proxy();
  input.context.packet.protocol=6;snapshot.context.packet.protocol=6;
  if(cached) {
   assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
   answer_pair(proxy,1000001);
   ++input.token;++input.identity.incarnation;++input.identity.transport_session;
   input.identity.now_us=1000002;
  }
  unsigned before=terminals,accepted=replies;
  resource_uid=10123;fail_encoding=1;
  /* Admission uses the previous query policy; delivery acquires this newer
   * current response policy even when the final local encoding fails. */
  product_dns_proxy_snapshot_t admitted=snapshot;
  ++snapshot.identity.revision;++snapshot.identity.hash;
  assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&admitted));
  if(!cached)answer_pair(proxy,1000001);
  assert(failed_allocations==1 && !fail_encoding && resource_attempts==1);
  assert(terminals==before+1 && replies==accepted && abandoned==1);
  const product_dns_proxy_event_t *event=&terminal_events[before];
  assert(event->stage==3 && event->result==PRODUCT_DNS_PROXY_CAPACITY);
  assert(event->response && event->cached==cached && event->rcode==2);
  assert(event->policy.revision==snapshot.identity.revision &&
    event->query_policy.revision==admitted.identity.revision);
  assert(event->output_bytes==0 && event->delivery==2 && abandoned_token==input.token);
  assert(!product_dns_proxy_resources(proxy).active);
  product_dns_proxy_close(proxy);
 }
}
static void cached_reply_can_reenter_with_a_new_pending_question(void)
{
 product_dns_proxy_t *proxy=open_proxy();
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 answer_pair(proxy,1000001);
 assert(replies==1 && sends==1 && product_dns_proxy_resources(proxy).cache_entries==1);
 ++input.token;++input.identity.incarnation;++input.identity.transport_session;
 input.identity.now_us=1000002;
 reentrant_proxy=proxy;reentrant_action=4;
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));
 product_dns_proxy_resources_t resources=product_dns_proxy_resources(proxy);
 assert(replies==2 && sends==2 && resources.active==1 && resources.exchanges==1);
 assert(resources.cache_entries==1 && resources.cache_hits==1 && resources.cache_misses==2);
 answer_pair(proxy,1000004);
 assert(replies==3 && terminals==3 && received_codes[2]==0);
 assert(!product_dns_proxy_resources(proxy).active && cancellations==3);
 product_dns_proxy_close(proxy);
}
static void undeliverable_and_stale_tcp_outputs_retire_only_own_token(void)
{
 for(unsigned stale=0;stale<2;++stale) {
  product_dns_proxy_t *proxy=open_proxy();
  input.context.packet.protocol=6;snapshot.context.packet.protocol=6;
  if(stale)stale_uid=10123;else {resource_uid=10123;fallback_rejected=1;}
  submit_pair(proxy,1);answer_pair(proxy,2000000);
  assert(replies==1 && received_uids[0]==10124 && received_codes[0]==0);
  assert(abandoned==1 && abandoned_token==1 && terminals==2 && cancellations==1);
  assert(terminal_events[0].stage==(stale?2:3));
  assert(terminal_events[0].result==(stale?PRODUCT_DNS_PROXY_UPSTREAM:PRODUCT_DNS_PROXY_CAPACITY));
  assert(terminal_events[0].delivery==2 && terminal_events[1].delivery==1);
  assert(terminal_events[0].response && !terminal_events[0].cached);
  assert(terminal_events[0].policy.revision==snapshot.identity.revision);
  assert(terminal_events[0].output_bytes==(stale?sizeof(question)+16:sizeof(question)));
  assert(!product_dns_proxy_resources(proxy).active && !product_dns_proxy_resources(proxy).exchanges);
  product_dns_proxy_close(proxy);
 }
}
int main(void)
{
 independent_simultaneous_waiters();
 joining_waiter_keeps_the_original_candidate_deadline();
 cancelling_one_waiter_keeps_the_other_before_candidate_deadline();
 late_answer_cannot_extend_candidate_after_first_waiter_cancels();
 truncated_udp_continuation_keeps_the_original_candidate_deadline();
 cancellation_end_stop_and_late_events_settle_each_waiter_once();
 a_retired_group_key_cannot_complete_its_replacement();
 current_policy_is_independent_before_join_and_before_delivery();
 opaque_options_and_full_question_or_view_differences_do_not_join();
 waiter_capacity_is_independent_of_exchange_capacity();
 same_round_response_cancel_stop_and_failure_are_exactly_once();
 connected_alias_policy_is_per_app_and_unknown_never_inherits_a_caller();
 one_tcp_output_capacity_failure_gets_own_servfail();
 failed_servfail_encoding_keeps_source_policy_and_zero_output();
 undeliverable_and_stale_tcp_outputs_retire_only_own_token();
 cached_reply_can_reenter_with_a_new_pending_question();
 puts("PASS public DNS coalescing identity, current policy, strict3s candidate, equivalence, capacity and exactly-once lifecycle");return 0;
}
