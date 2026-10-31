/* SPDX-License-Identifier: Apache-2.0 */
#include "product_dns_bootstrap.h"
#include "product_dns.h"
#include "product_dns_route.h"
#include "product_cares.h"
#include <strings.h>

int product_dns_bootstrap_query(const char *name,uint16_t id,unsigned type,
  uint8_t wire[PRODUCT_DNS_BOOTSTRAP_QUERY_BYTES],size_t *length)
{
  if(!name||!length||(type!=ARES_REC_TYPE_A&&type!=ARES_REC_TYPE_AAAA)||
      product_cares_memory_begin(PRODUCT_DNS_CODEC_BYTES))return 0;
  ares_dns_record_t *record=NULL;unsigned char *encoded=NULL;size_t bytes=0;
  int status=ares_dns_record_create(&record,id,ARES_FLAG_RD,ARES_OPCODE_QUERY,ARES_RCODE_NOERROR);
  if(status==ARES_SUCCESS)status=ares_dns_record_query_add(record,name,type,ARES_CLASS_IN);
  if(status==ARES_SUCCESS)status=ares_dns_write(record,&encoded,&bytes);
  int valid=status==ARES_SUCCESS&&bytes>=12&&bytes<=PRODUCT_DNS_BOOTSTRAP_QUERY_BYTES;
  if(valid){memcpy(wire,encoded,bytes);*length=bytes;}
  ares_free_string(encoded);ares_dns_record_destroy(record);
  size_t unreleased=0;(void)product_cares_memory_end(&unreleased);
  return valid&&!unreleased;
}

static int same_name(const char *a,const char *b)
{
  size_t x=strlen(a),y=strlen(b);
  if(x&&a[x-1]=='.')--x;
  if(y&&b[y-1]=='.')--y;
  return x==y&&!strncasecmp(a,b,x);
}
int product_dns_bootstrap_answer(const uint8_t *query,size_t query_length,
  const uint8_t *wire,size_t length,
  product_dns_bootstrap_address_t addresses[PRODUCT_DNS_BOOTSTRAP_ADDRESSES],unsigned *count)
{
  if(!count)return -1;
  *count=0;
  product_dns_context_t context={0};product_dns_query_t expected;
  product_dns_inspect_query(query,query_length,&context,&expected);
  if(expected.coverage!=PRODUCT_DNS_QUERY_COMPLETE)return -1;
  product_dns_response_t response;
  product_dns_inspect_answer(wire,length,&context,&expected,&response);
  if(response.correlation!=PRODUCT_DNS_CORRELATED)return -1;
  if(response.question.flags&0x0200)return 2;
  if(response.question.coverage!=PRODUCT_DNS_QUERY_COMPLETE||response.rcode||
     response.chain_status||!response.name_count)return -1;
  if(product_cares_memory_begin(PRODUCT_DNS_CODEC_BYTES))return -1;
  ares_dns_record_t *record=NULL;
  int valid=product_cares_parse(wire,length,&record)==ARES_SUCCESS;
  if(valid)for(size_t i=0;i<ares_dns_record_rr_cnt(record,ARES_SECTION_ANSWER);++i){
    const ares_dns_rr_t *rr=ares_dns_record_rr_get_const(record,ARES_SECTION_ANSWER,i);
    if(ares_dns_rr_get_class(rr)!=ARES_CLASS_IN||ares_dns_rr_get_type(rr)!=expected.qtype||
       !same_name(ares_dns_rr_get_name(rr),response.names[response.name_count-1].name))continue;
    product_dns_bootstrap_address_t address={.family=expected.qtype==ARES_REC_TYPE_A?4:6};
    const void *data=address.family==4?(const void *)ares_dns_rr_get_addr(rr,ARES_RR_A_ADDR):
      (const void *)ares_dns_rr_get_addr6(rr,ARES_RR_AAAA_ADDR);
    if(!data)continue;
    memcpy(address.address,data,address.family==4?4:16);
    if(!product_dns_address_valid(address.family,853,address.address))continue;
    unsigned duplicate=0;
    for(unsigned j=0;j<*count;++j)duplicate|=!memcmp(&address,&addresses[j],sizeof(address));
    if(!duplicate&&*count<PRODUCT_DNS_BOOTSTRAP_ADDRESSES)addresses[(*count)++]=address;
  }
  ares_dns_record_destroy(record);size_t unreleased=0;(void)product_cares_memory_end(&unreleased);
  if(!valid||unreleased)return -1;
  return *count?1:0;
}
