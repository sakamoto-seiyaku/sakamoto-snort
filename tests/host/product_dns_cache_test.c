/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_proxy.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static product_l4_policy_view_t view;
static product_dns_proxy_snapshot_t snapshot;
static product_dns_proxy_input_t input;
static product_dns_proxy_key_t key;
static unsigned sends, replies;
static uint8_t sent[65535], received[65535];
static size_t sent_length, received_length;
static product_dns_proxy_event_t completed;
static int send_query(void *ctx,const product_dns_proxy_key_t *k,unsigned transport,
 const uint8_t *wire,size_t length,uint64_t deadline)
{ (void)ctx;(void)transport;assert(deadline);key=*k;memcpy(sent,wire,length);sent_length=length;++sends;return 1; }
static int reply(void *ctx,const product_dns_proxy_event_t *event,const uint8_t *wire,size_t length)
{ (void)ctx;completed=*event;memcpy(received,wire,length);received_length=length;++replies;return 1; }
static int acquire(void *ctx,const product_dns_proxy_input_t *in,product_dns_proxy_snapshot_t *out)
{
 (void)ctx;*out=snapshot;out->context.packet=in->context.packet;out->context.caller=in->context.caller;
 out->context.packet.direction=1;
 out->context.packet.source_port=in->context.packet.destination_port;
 out->context.packet.destination_port=in->context.packet.source_port;
 memcpy(out->context.packet.source_address,in->context.packet.destination_address,16);
 memcpy(out->context.packet.destination_address,in->context.packet.source_address,16);
 assert(out->context.domains==snapshot.context.domains);return 1;
}
static const uint8_t question[]={0x12,0x34,1,0,0,1,0,0,0,0,0,0,
 7,'e','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
static product_dns_proxy_t *open_proxy(void)
{
 assert(!product_l4_policy_compile(&view,NULL,0));sends=replies=0;
 input=(product_dns_proxy_input_t){.identity={.generation=77,.network_revision=5,.now_us=1000000,.profile=1},
  .token=1,.route_revision=3,.slot=UINT32_MAX,.context={.caller=PRODUCT_DNS_CALLER_PLATFORM_APP,
  .packet={.uid=10123,.uid_known=1,.family=4,.protocol=17,.direction=3,.direction_known=1,
   .ports_available=1,.source_port=40000,.destination_port=53}}};
 snapshot=(product_dns_proxy_snapshot_t){.context=input.context,.view=&view,
  .identity={77,3,123,0},.network_revision=5,.route_revision=3};
 product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={192,0,2,53}};
 product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire};
 product_dns_proxy_t *proxy=product_dns_proxy_open(77,&route,&callbacks,NULL);assert(proxy);return proxy;
}
static void answer(product_dns_proxy_t *proxy,unsigned ttl)
{
 uint8_t wire[sizeof(question)+16];assert(sent_length==sizeof(question));
 memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x80;wire[7]=1;
 memcpy(wire+sizeof(question),(uint8_t[]){0xc0,12,0,1,0,1,0,0,0,0,0,4,192,0,2,9},16);
 wire[sizeof(question)+9]=(uint8_t)ttl;
 product_dns_proxy_answer(proxy,&key,PRODUCT_DNS_PROXY_UDP,wire,sizeof(wire),input.identity.now_us);
}
static void current_request_reuses_data_and_restores_id(void)
{
 product_dns_proxy_t *proxy=open_proxy();
 assert(product_dns_proxy_submit(proxy,&input,question,sizeof(question),&snapshot));answer(proxy,30);
 assert(sends==1&&replies==1);
 uint8_t next[sizeof(question)];memcpy(next,question,sizeof(next));next[0]=0xab;next[1]=0xcd;
 ++input.token;input.identity.now_us+=2000000;
 assert(product_dns_proxy_submit(proxy,&input,next,sizeof(next),&snapshot));
 assert(sends==1&&replies==2); /* same valid data; no second upstream */
 assert(received[0]==0xab&&received[1]==0xcd&&received_length==sizeof(question)+16);
 assert(!memcmp(received+12,question+12,sizeof(question)-12));
 assert(received[sizeof(question)+9]==28); /* original TTL30 minus two seconds */
 product_dns_proxy_close(proxy);
}

static void submit(product_dns_proxy_t *proxy,const uint8_t *wire,size_t length)
{
 ++input.token;snapshot.context.packet=input.context.packet;snapshot.context.caller=input.context.caller;
 assert(product_dns_proxy_submit(proxy,&input,wire,length,&snapshot));
}
static size_t make_answer(uint8_t *wire,unsigned ttl,unsigned type,size_t data_length)
{
 size_t end=12;while(end<sent_length&&sent[end])end+=sent[end]+1;end+=5;
 assert(end<=sent_length&&end+12+data_length+sent_length-end<=65535);
 memcpy(wire,sent,end);wire[2]=0x81;wire[3]=0x80;wire[7]=1;
 uint8_t *rr=wire+end;memcpy(rr,(uint8_t[]){0xc0,12,0,0,0,1,0,0,0,0,0,0},12);
 rr[2]=type>>8;rr[3]=type;rr[6]=ttl>>24;rr[7]=ttl>>16;rr[8]=ttl>>8;rr[9]=ttl;
 rr[10]=data_length>>8;rr[11]=data_length;memset(rr+12,0xa5,data_length);
 if(type==1&&data_length==4)memcpy(rr+12,(uint8_t[]){192,0,2,9},4);
 memcpy(rr+12+data_length,sent+end,sent_length-end);
 return sent_length+12+data_length;
}
static void feed(product_dns_proxy_t *proxy,uint8_t *wire,size_t length)
{ product_dns_proxy_answer(proxy,&key,PRODUCT_DNS_PROXY_UDP,wire,length,input.identity.now_us); }
static void zero_expiry_errors_and_fractional_ttl(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit(proxy,question,sizeof(question));answer(proxy,0);
 submit(proxy,question,sizeof(question));assert(sends==2);answer(proxy,1);
 input.identity.now_us+=1;submit(proxy,question,sizeof(question));
 assert(sends==2&&completed.result==PRODUCT_DNS_PROXY_CACHE&&received[sizeof(question)+9]==0);
 input.identity.now_us+=999999;submit(proxy,question,sizeof(question));assert(sends==3);
 product_dns_proxy_fail(proxy,&key,input.identity.now_us);assert((received[3]&15)==2);
 submit(proxy,question,sizeof(question));assert(sends==4); /* no stale rescue or cached local SERVFAIL */
 uint8_t error[sizeof(question)];memcpy(error,sent,sizeof(error));error[2]=0x81;error[3]=0x85;
 feed(proxy,error,sizeof(error));assert((received[3]&15)==5);
 submit(proxy,question,sizeof(question));assert(sends==5); /* upstream REFUSED is not cacheable */
 product_dns_proxy_close(proxy);
}
static void full_question_flags_and_edns_partition_data(void)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t q[sizeof(question)+32],wire[256];
 memcpy(q,question,sizeof(question));submit(proxy,q,sizeof(question));answer(proxy,30);
 q[13]='E';submit(proxy,q,sizeof(question));assert(sends==2);answer(proxy,30);
 submit(proxy,q,sizeof(question));assert(sends==2);assert(received[13]=='E');
 q[3]=0x10;submit(proxy,q,sizeof(question));assert(sends==3);answer(proxy,30);
 q[sizeof(question)-1]=3;submit(proxy,q,sizeof(question));assert(sends==4);product_dns_proxy_fail(proxy,&key,input.identity.now_us);
 q[sizeof(question)-1]=1;q[sizeof(question)-3]=28;
 submit(proxy,q,sizeof(question));assert(sends==5);product_dns_proxy_fail(proxy,&key,input.identity.now_us);
 memcpy(q,question,sizeof(question));q[11]=1;
 memcpy(q+sizeof(question),(uint8_t[]){0,0,41,4,208,0,0,0x80,0,0,0},11);
 size_t n=sizeof(question)+11;submit(proxy,q,n);assert(sends==6);
 size_t a=make_answer(wire,30,1,4);feed(proxy,wire,a);submit(proxy,q,n);
 assert(sends==6&&completed.result==PRODUCT_DNS_PROXY_CACHE);
 q[sizeof(question)+7]=0;submit(proxy,q,n);assert(sends==7);a=make_answer(wire,30,1,4);feed(proxy,wire,a);
 submit(proxy,q,n);assert(sends==7);
 /* An opaque option is forwarded exactly, but never ignored for reuse. */
 q[sizeof(question)+10]=4;memcpy(q+n,(uint8_t[]){0xfd,0xe8,0,0},4);n+=4;
 submit(proxy,q,n);assert(sends==8);a=make_answer(wire,30,1,4);feed(proxy,wire,a);
 submit(proxy,q,n);assert(sends==9);
 product_dns_proxy_close(proxy);
}
static size_t negative_answer(uint8_t *wire,unsigned rcode,unsigned soa_ttl,unsigned minimum,int soa)
{
 memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x80|rcode;wire[9]=soa;
 if(!soa)return sent_length;
 uint8_t *rr=wire+sent_length;
 memcpy(rr,(uint8_t[]){0xc0,12,0,6,0,1,0,0,0,0,0,22,0,0},14);
 rr[9]=soa_ttl;memset(rr+14,0,20);rr[33]=minimum;
 return sent_length+34;
}
static void soa_negative_ttl_is_the_shorter_verified_lifetime(void)
{
 for(unsigned rcode=0;rcode<=3;rcode+=3)for(unsigned order=0;order<2;++order){
  product_dns_proxy_t *proxy=open_proxy();uint8_t wire[256];
  unsigned ttl=order?7:30,minimum=order?30:7;
  submit(proxy,question,sizeof(question));size_t length=negative_answer(wire,rcode,ttl,minimum,1);feed(proxy,wire,length);
  assert(replies==1);input.identity.now_us+=1000000;submit(proxy,question,sizeof(question));
  assert(sends==1&&completed.result==PRODUCT_DNS_PROXY_CACHE&&(received[3]&15)==rcode);
  assert(received[sizeof(question)+9]==6); /* min(7,30) minus one */
  input.identity.now_us+=6000000;submit(proxy,question,sizeof(question));assert(sends==2);
  product_dns_proxy_close(proxy);
 }
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[256];
 submit(proxy,question,sizeof(question));feed(proxy,wire,negative_answer(wire,3,30,7,0));
 submit(proxy,question,sizeof(question));assert(sends==2);product_dns_proxy_close(proxy);
}
static void network_route_stop_and_late_results_are_fenced(void)
{
 product_dns_proxy_t *proxy=open_proxy();submit(proxy,question,sizeof(question));answer(proxy,30);
 ++snapshot.network_revision;input.identity.network_revision=snapshot.network_revision;
 product_dns_proxy_advance(proxy,input.identity.now_us,snapshot.network_revision,snapshot.route_revision);
 submit(proxy,question,sizeof(question));assert(sends==2);
 product_dns_proxy_key_t old=key;uint8_t late[65535];size_t n=make_answer(late,30,1,4);
 ++snapshot.route_revision;input.route_revision=snapshot.route_revision;
 product_dns_proxy_advance(proxy,input.identity.now_us,snapshot.network_revision,snapshot.route_revision);
 assert((received[3]&15)==2&&product_dns_proxy_resources(proxy).active==0);
 product_dns_proxy_answer(proxy,&old,PRODUCT_DNS_PROXY_UDP,late,n,input.identity.now_us);
 submit(proxy,question,sizeof(question));assert(sends==3);answer(proxy,30);
 product_dns_proxy_resources_t before=product_dns_proxy_resources(proxy);assert(before.cache_entries==1);
 product_dns_proxy_stop(proxy,input.identity.now_us);
 assert(product_dns_proxy_resources(proxy).cache_entries==0&&product_dns_proxy_resources(proxy).active==0);
 product_dns_proxy_answer(proxy,&key,PRODUCT_DNS_PROXY_UDP,late,n,input.identity.now_us);
 assert(product_dns_proxy_resources(proxy).cache_entries==0);
 product_dns_proxy_close(proxy);
}
static void unique_question(uint8_t *q,unsigned index,unsigned type)
{
 memcpy(q,question,sizeof(question));char name[8];assert(snprintf(name,sizeof(name),"c%06u",index)==7);
 memcpy(q+13,name,7);q[sizeof(question)-4]=type>>8;q[sizeof(question)-3]=type;
}
static void entry_byte_limits_lru_and_owner_isolation(void)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t q[sizeof(question)],wire[65535];
 for(unsigned i=0;i<512;++i){unique_question(q,i,1);submit(proxy,q,sizeof(q));answer(proxy,30);}
 assert(product_dns_proxy_resources(proxy).cache_entries==512);
 unique_question(q,0,1);submit(proxy,q,sizeof(q));assert(sends==512);
 unique_question(q,512,1);submit(proxy,q,sizeof(q));answer(proxy,30);assert(sends==513);
 unique_question(q,0,1);submit(proxy,q,sizeof(q));assert(sends==513); /* touched entry survives */
 unique_question(q,1,1);submit(proxy,q,sizeof(q));assert(sends==514); /* least recent data evicted */
 product_dns_proxy_close(proxy);proxy=open_proxy();
 for(unsigned i=0;i<40;++i){unique_question(q,i,65000);submit(proxy,q,sizeof(q));size_t n=make_answer(wire,30,65000,60000);feed(proxy,wire,n);}
 product_dns_proxy_resources_t r=product_dns_proxy_resources(proxy);
 assert(r.cache_entries>0&&r.cache_entries<40&&r.cache_evictions>0&&r.cache_bytes<=2097152&&r.cache_high_water_bytes<=2097152);
 unique_question(q,0,65000);submit(proxy,q,sizeof(q));assert(sends==41);
 product_dns_proxy_t *other=open_proxy();submit(other,question,sizeof(question));assert(sends==1);
 product_dns_proxy_close(other);product_dns_proxy_close(proxy);
}

static void cached_alias_uses_current_app_policy_and_keeps_data(void)
{
 product_dns_proxy_t *proxy=open_proxy();
 sakamoto_product_domains_t lists={.list_count=2,.entry_count=2,
  .entries={{.list=0,.length=10,.name="alias.test"},{.list=1,.length=11,.name="example.com"}}};
 product_domains_t *domains=NULL;assert(!product_domains_build(&lists,&domains));
 snapshot.context.domains=domains;snapshot.context.domains_available=1;
 input.context.domains_available=1;
 submit(proxy,question,sizeof(question));
 uint8_t wire[256];memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x80;wire[7]=2;
 size_t at=sent_length;
 memcpy(wire+at,(uint8_t[]){0xc0,12,0,5,0,1,0,0,0,30,0,12,
  5,'a','l','i','a','s',4,'t','e','s','t',0},24);at+=24;
 memcpy(wire+at,(uint8_t[]){0xc0,0,0,1,0,1,0,0,0,30,0,4,192,0,2,9},16);
 wire[at+1]=(uint8_t)(sent_length+12);at+=16;feed(proxy,wire,at);
 assert(replies==1&&product_dns_proxy_resources(proxy).cache_entries==1);
 product_l4_policy_rule_t rule={.uid=10123,.rule_id=319,.reason_id=319,.action=2,
  .network_context_id=UINT32_MAX,.ifindex=UINT32_MAX,.source_port_last=UINT16_MAX,.destination_port_last=UINT16_MAX,
  .expression_length=2,.expression={PRODUCT_EXPRESSION_DOMAIN_LIST,0}};
 assert(!product_l4_policy_compile(&view,&rule,1));++snapshot.identity.revision;
 submit(proxy,question,sizeof(question));
 assert(sends==1&&replies==2&&completed.result==PRODUCT_DNS_PROXY_REFUSED&&completed.cached);
 assert((received[3]&15)==5&&completed.match.rule_id==319);
 assert(product_dns_proxy_resources(proxy).cache_entries==1); /* refused delivery does not poison data */
 input.context.packet.uid=10124;submit(proxy,question,sizeof(question));
 assert(sends==1&&replies==3&&completed.result==PRODUCT_DNS_PROXY_CACHE&&(received[3]&15)==0);
 rule.expression[1]=1;assert(!product_l4_policy_compile(&view,&rule,1));++snapshot.identity.revision;
 input.context.packet.uid=10123;uint64_t hits=product_dns_proxy_resources(proxy).cache_hits;
 submit(proxy,question,sizeof(question));assert(sends==1&&replies==4&&(received[3]&15)==5&&!completed.cached);
 assert(product_dns_proxy_resources(proxy).cache_hits==hits); /* QName denial precedes lookup */
 assert(!product_l4_policy_compile(&view,NULL,0));++snapshot.identity.revision;
 submit(proxy,question,sizeof(question));assert(sends==1&&completed.result==PRODUCT_DNS_PROXY_CACHE);
 product_dns_proxy_close(proxy);product_domains_destroy(domains);
}
static void all_record_ttls_age_and_opaque_bytes_survive(void)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t q[sizeof(question)],wire[256];
 unique_question(q,0,65000);submit(proxy,q,sizeof(q));size_t length=make_answer(wire,30,65000,4);
 wire[7]=2;memcpy(wire+length,(uint8_t[]){0xc0,12,0,16,0,1,0,0,0,1,0,2,1,'x'},14);length+=14;
 feed(proxy,wire,length);assert(replies==1);
 input.identity.now_us+=500000;submit(proxy,q,sizeof(q));assert(sends==1&&completed.cached);
 assert(received[sizeof(question)+9]==29&&received[sizeof(question)+16+9]==0);
 assert(!memcmp(received+sizeof(question)+12,(uint8_t[]){0xa5,0xa5,0xa5,0xa5},4));
 input.identity.now_us+=500000;submit(proxy,q,sizeof(q));assert(sends==2);
 product_dns_proxy_close(proxy);
}
static void ttl_with_reserved_high_bit_has_no_positive_lifetime(void)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[256];
 submit(proxy,question,sizeof(question));size_t n=make_answer(wire,UINT32_C(0x80000001),1,4);feed(proxy,wire,n);
 assert(replies==1);
 submit(proxy,question,sizeof(question));assert(sends==2); /* RFC2181: high-bit TTL is zero, not 68 years */
 product_dns_proxy_close(proxy);
}
int main(void)
{
 current_request_reuses_data_and_restores_id();zero_expiry_errors_and_fractional_ttl();
 full_question_flags_and_edns_partition_data();soa_negative_ttl_is_the_shorter_verified_lifetime();
 network_route_stop_and_late_results_are_fenced();entry_byte_limits_lru_and_owner_isolation();
 cached_alias_uses_current_app_policy_and_keeps_data();all_record_ttls_age_and_opaque_bytes_survive();
 ttl_with_reserved_high_bit_has_no_positive_lifetime();
 puts("DNS cache public-message behavior passed");return 0;
}
