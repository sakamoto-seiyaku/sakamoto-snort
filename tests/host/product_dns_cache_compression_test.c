/* SPDX-License-Identifier: Apache-2.0 */
/* Full messages enter the public proxy; unsafe wire is delivered exactly and
 * must take the real upstream path again. Legal nested compression still hits. */
#define main dns_cache_behavior_suite
#include "product_dns_cache_test.c"
#undef main
static size_t rr(uint8_t *wire,size_t at,unsigned owner,unsigned type,const uint8_t *data,size_t bytes)
{
 memcpy(wire+at,(uint8_t[]){0xc0,0,0,0,0,1,0,0,0,30,0,0},12);
 wire[at]|=owner>>8;wire[at+1]=owner;wire[at+2]=type>>8;wire[at+3]=type;
 wire[at+10]=bytes>>8;wire[at+11]=bytes;memcpy(wire+at+12,data,bytes);return at+12+bytes;
}
static void check(product_dns_proxy_t *proxy,uint8_t *wire,size_t length,const char *label,int reusable)
{
 uint8_t original[2048],q[sizeof(question)];assert(length<=sizeof(original));memcpy(original,wire,length);
 feed(proxy,wire,length);assert(replies==1&&received_length==length&&!memcmp(received+2,original+2,length-2));
 assert(product_dns_proxy_resources(proxy).cache_entries==(unsigned)reusable);
 memcpy(q,question,sizeof(q));q[0]=0xab;q[1]=0xcd;input.identity.now_us+=1;submit(proxy,q,sizeof(q));
 assert(replies==2||sends==2); /* Original stranding regression remains required. */
 if(reusable){assert(sends==1&&replies==2&&completed.cached);}
 else {
  assert(sends==2&&replies==1&&!completed.cached&&product_dns_proxy_resources(proxy).active==1);
  wire[0]=sent[0];wire[1]=sent[1];feed(proxy,wire,length);
  assert(replies==2&&!completed.cached&&received_length==length&&!memcmp(received+2,original+2,length-2));
 }
 assert(received[0]==q[0]&&received[1]==q[1]&&!memcmp(received+12,q+12,sizeof(q)-12));
 assert(product_dns_proxy_resources(proxy).active==0);
 printf("%s reusable=%d complete_wire=1 active=0 PASS\n",label,reusable);product_dns_proxy_close(proxy);
}
static void owner_reference(const char *label,unsigned target_kind,int reusable)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[2048];submit(proxy,question,sizeof(question));
 size_t n=make_answer(wire,UINT32_C(0x01610000),1,4);wire[7]=2;
 /* TTL encodes the valid name 'a'; A bytes encode the same name. Neither is
  * a name boundary even though the mature codec can decode a pointer there. */
 memcpy(wire+sizeof(question)+12,(uint8_t[]){1,'a',0,9},4);
 unsigned target=target_kind==0?sizeof(question)+6:target_kind==1?sizeof(question)+12:
  target_kind==2?sizeof(question)+2:target_kind==3?sizeof(question):12;
 uint8_t txt[]={1,'x'};n=rr(wire,n,target,16,txt,sizeof(txt));
 check(proxy,wire,n,label,reusable);
}
static size_t name_data(uint8_t *data,unsigned type,int compressed,unsigned target,size_t *name)
{
 size_t at=type==15||type==64||type==65?2:type==24?18:type==33?6:type==35?7:0;
 memset(data,0,64);*name=at;
 if(compressed){data[at++]=0xc0|(target>>8);data[at++]=target;}
 else {memcpy(data+at,(uint8_t[]){1,'a',0},3);at+=3;}
 if(type==6){data[at++]=0;memset(data+at,0,20);at+=20;data[at-1]=7;}
 if(type==24)data[at++]=0x55;
 return at;
}
static void rdata_reference(unsigned type,int unsafe)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[2048],data[64];submit(proxy,question,sizeof(question));
 size_t n=make_answer(wire,UINT32_C(0x01610000),1,4);wire[7]=1;wire[11]=2;
 size_t field,bytes=name_data(data,type,unsafe,sizeof(question)+6,&field),start=n;
 n=rr(wire,n,12,type,data,bytes);
 uint8_t txt[]={1,'x'};n=rr(wire,n,start+12+field,16,txt,sizeof(txt));
 char label[64];snprintf(label,sizeof(label),"rdata-%u-%s",type,unsafe?"ttl-pointer":"valid-anchor");
 check(proxy,wire,n,label,!unsafe);
}
static void opaque(int pointer)
{
 product_dns_proxy_t *proxy=open_proxy();uint8_t wire[2048];submit(proxy,question,sizeof(question));
 size_t n=make_answer(wire,30,1,4);wire[7]=2;
 uint8_t data[]={pointer?0xc0:0xa5,12};n=rr(wire,n,12,65000,data,sizeof(data));
 check(proxy,wire,n,pointer?"opaque-possible-pointer":"opaque-no-pointer",!pointer);
}
int main(void)
{
 owner_reference("owner-references-ttl",0,0);owner_reference("owner-references-address",1,0);
 owner_reference("owner-references-type",2,0);owner_reference("owner-pointer-to-pointer",3,1);
 owner_reference("owner-references-question",4,1);
 const unsigned types[]={2,5,6,12,15,24,33,35,64,65};
 for(unsigned i=0;i<sizeof(types)/sizeof(types[0]);++i)rdata_reference(types[i],0);
 const unsigned compressed[]={2,5,6,12,15};
 for(unsigned i=0;i<sizeof(compressed)/sizeof(compressed[0]);++i)rdata_reference(compressed[i],1);
 opaque(0);opaque(1);return 0;
}
