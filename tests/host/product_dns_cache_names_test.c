/* SPDX-License-Identifier: Apache-2.0 */
/* Public complete-message qualification vectors. No private cache interface. */
#define main dns_cache_behavior_suite
#include "product_dns_cache_test.c"
#undef main
static const uint8_t owner_question[]={0xc0,12};
static const uint8_t owner_root[]={0};
static const uint8_t owner_com[]={3,'c','o','m',0};
static const uint8_t owner_dot_label[]={11,'e','x','a','m','p','l','e','.','c','o','m',0};
static const uint8_t owner_nul_label[]={8,'c','o','m',0,'e','v','i','l',0};
static const uint8_t owner_backslash[]={4,'c','\\','o','m',0};
static size_t soa(uint8_t *wire,size_t at,const uint8_t *owner,size_t owner_length,
 uint32_t ttl,uint32_t minimum,unsigned klass)
{
 memcpy(wire+at,owner,owner_length);at+=owner_length;
 memcpy(wire+at,(uint8_t[]){0,6,0,1,0,0,0,0,0,22,0,0},12);
 wire[at+3]=klass;wire[at+4]=ttl>>24;wire[at+5]=ttl>>16;wire[at+6]=ttl>>8;wire[at+7]=ttl;
 memset(wire+at+12,0,20);wire[at+28]=minimum>>24;wire[at+29]=minimum>>16;wire[at+30]=minimum>>8;wire[at+31]=minimum;
 return at+32;
}
static unsigned failures;
static void vector(const char *label,const uint8_t *owner,size_t owner_length,
 unsigned rcode,uint32_t ttl,uint32_t minimum,unsigned copies,unsigned klass,int expected_cache)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[1024];submit(proxy,question,sizeof(question));
 memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x80|rcode;wire[9]=copies;
 size_t length=sent_length;
 for(unsigned i=0;i<copies;++i)length=soa(wire,length,owner,owner_length,ttl,minimum,klass);
 feed(proxy,wire,length);
 unsigned first_replies=replies;
 int transparent=first_replies==1&&received_length==length&&!memcmp(received+2,wire+2,length-2);
 input.identity.now_us+=1;submit(proxy,question,sizeof(question));
 int actual_cache=sends==1&&replies==2&&completed.cached;
 int pass=transparent&&actual_cache==expected_cache;
 printf("%s expected_cache=%d actual_cache=%d first_transparent=%d sends=%u status=%s\n",
  label,expected_cache,actual_cache,transparent,sends,pass?"PASS":"FAIL");
 failures+=!pass;product_dns_proxy_close(proxy);
}
static void cname_vector(const char *label,int binary_target,int expected_cache)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[1024];submit(proxy,question,sizeof(question));
 memcpy(wire,sent,sent_length);wire[2]=0x81;wire[3]=0x83;wire[7]=1;wire[9]=1;size_t at=sent_length;
 const uint8_t standard_target[]={5,'a','l','i','a','s',4,'t','e','s','t',0};
 const uint8_t literal_dot_target[]={10,'a','l','i','a','s','.','t','e','s','t',0};
 const uint8_t false_owner[]={6,'a','l','i','a','s','\\',4,'t','e','s','t',0};
 const uint8_t zone_test[]={4,'t','e','s','t',0};
 const uint8_t *target=binary_target?literal_dot_target:standard_target;
 size_t target_length=binary_target?sizeof(literal_dot_target):sizeof(standard_target);
 memcpy(wire+at,(uint8_t[]){0xc0,12,0,5,0,1,0,0,0,30,0,0},12);wire[at+11]=target_length;at+=12;
 memcpy(wire+at,target,target_length);at+=target_length;
 at=soa(wire,at,binary_target==1?false_owner:zone_test,binary_target==1?sizeof(false_owner):sizeof(zone_test),30,7,1);
 feed(proxy,wire,at);int transparent=replies==1&&received_length==at&&!memcmp(received+2,wire+2,at-2);
 input.identity.now_us+=1;submit(proxy,question,sizeof(question));int actual=sends==1&&replies==2&&completed.cached;
 int pass=transparent&&actual==expected_cache;
 printf("%s expected_cache=%d actual_cache=%d first_transparent=%d sends=%u status=%s\n",label,expected_cache,actual,transparent,sends,pass?"PASS":"FAIL");
 failures+=!pass;product_dns_proxy_close(proxy);
}
int main(void)
{
 vector("genuine-full-ancestor",owner_question,sizeof(owner_question),3,30,7,1,1,1);
 vector("genuine-label-ancestor",owner_com,sizeof(owner_com),3,7,30,1,1,1);
 vector("genuine-root-ancestor",owner_root,sizeof(owner_root),3,30,7,1,1,1);
 vector("literal-dot-is-not-label-separator",owner_dot_label,sizeof(owner_dot_label),3,30,7,1,1,0);
 vector("embedded-nul-does-not-shorten-zone",owner_nul_label,sizeof(owner_nul_label),3,30,7,1,1,0);
 vector("literal-backslash-not-an-escape",owner_backslash,sizeof(owner_backslash),3,30,7,1,1,0);
 vector("nodata-valid-soa",owner_question,sizeof(owner_question),0,30,7,1,1,1);
 vector("soa-ttl-zero",owner_question,sizeof(owner_question),3,0,7,1,1,0);
 vector("soa-minimum-zero",owner_question,sizeof(owner_question),3,30,0,1,1,0);
 vector("no-soa",owner_question,sizeof(owner_question),3,30,7,0,1,0);
 vector("ambiguous-duplicate-soa",owner_question,sizeof(owner_question),3,30,7,2,1,0);
 vector("wrong-soa-class",owner_question,sizeof(owner_question),3,30,7,1,3,0);
 vector("soa-high-bit-zero",owner_question,sizeof(owner_question),3,UINT32_C(0x80000001),7,1,1,0);
 cname_vector("cname-terminal-genuine-ancestor",0,1);
 cname_vector("cname-terminal-escaped-label-false-ancestor",1,0);
 cname_vector("cname-terminal-dot-does-not-create-a-parent-label",2,0);
 fflush(stdout);assert(!failures);return 0;
}
