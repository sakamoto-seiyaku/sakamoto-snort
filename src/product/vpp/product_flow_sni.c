/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include <string.h>

/* RFC5246 6.2/7.4.1.2 and RFC8446 4.1.2/5.1. Record spans refer into the
 * sole TCP cache. Neither a second Hello nor packet storage is created. */
#define TLS_RECORDS 32U
#define TLS_EXTENSIONS 128U
#define TLS_WORK_LIMIT 131072U
typedef struct {
  const uint8_t *bytes;
  struct { unsigned at, size; } spans[TLS_RECORDS];
  unsigned count, span, offset, position, size;
} hello_reader_t;
static unsigned u16(const uint8_t *p) { return (unsigned)p[0]*256+p[1]; }
static unsigned take(hello_reader_t *r, unsigned n)
{
  unsigned value=0;
  while(n--) {
    while(r->span<r->count && r->offset==r->spans[r->span].size) {
      ++r->span;r->offset=0;
    }
    value=(value<<8)|r->bytes[r->spans[r->span].at+r->offset++];
    ++r->position;
  }
  return value;
}
static void skip(hello_reader_t *r,unsigned n)
{ while(n--) (void)take(r,1); }
static int vector(hello_reader_t *r,unsigned prefix,unsigned *size)
{
  if(prefix>r->size-r->position) return 0;
  *size=take(r,prefix);
  return *size<=r->size-r->position;
}
static int host_name(hello_reader_t *r,unsigned n,char name[PRODUCT_SNI_NAME_BYTES])
{
  if(!n || n>=PRODUCT_SNI_NAME_BYTES) return 0;
  unsigned label=0, numeric=1, previous=0, dots=0, octet=0, ip_valid=1;
  for(unsigned i=0;i<n;++i) {
    unsigned c=take(r,1);
    if(c>='A' && c<='Z') c+='a'-'A';
    if(c=='.') {
      if(!label || previous=='-') return 0;
      if(octet>255) ip_valid=0;
      ++dots;octet=0;label=0;
    } else {
      if(!((c>='a' && c<='z') || (c>='0' && c<='9') || c=='-')
         || (!label && c=='-') || ++label>63) return 0;
      if(c<'0' || c>'9') numeric=0;
      else if(octet<=255) octet=octet*10+c-'0';
    }
    name[i]=(char)c;previous=c;
  }
  name[n]=0;
  /* RFC6066 host_name excludes literal IPs, terminal dots and empty labels. */
  return label && previous!='-' && !(numeric && dots==3 && ip_valid && octet<=255);
}

/* 0 incomplete, otherwise terminal stop reason. Only COMPLETE publishes. */
static unsigned client_hello(const uint8_t *p,unsigned n,product_sni_state_t *s)
{
  hello_reader_t r={.bytes=p};
  unsigned at=0, wanted=0;
  while(at<n) {
    if(n-at<5) return PRODUCT_SNI_RUNNING;
    if(p[at]!=22 || p[at+1]!=3 || p[at+2]<1 || p[at+2]>3) return PRODUCT_SNI_UNSUPPORTED;
    unsigned size=u16(p+at+3);
    if(!size || size>16384) return PRODUCT_SNI_MALFORMED;
    if(size>PRODUCT_TCP_CACHE_SIDE_BYTES-5) return PRODUCT_SNI_BYTE_BUDGET;
    if(size>n-at-5) return PRODUCT_SNI_RUNNING;
    if(r.count==TLS_RECORDS) return PRODUCT_SNI_BYTE_BUDGET;
    r.spans[r.count].at=at+5;r.spans[r.count++].size=size;
    r.size+=size;at+=5+size;
    if(!wanted && r.size>=4) {
      unsigned type=take(&r,1);wanted=take(&r,3)+4;
      r.span=r.offset=r.position=0;
      if(type!=1) return PRODUCT_SNI_UNSUPPORTED;
      if(wanted<45) return PRODUCT_SNI_MALFORMED;
      if(wanted>PRODUCT_TCP_CACHE_SIDE_BYTES-5) return PRODUCT_SNI_BYTE_BUDGET;
    }
    if(wanted && r.size>=wanted) break;
  }
  if(!wanted || r.size<wanted) return PRODUCT_SNI_RUNNING;
  if(wanted>TLS_WORK_LIMIT-s->work) return PRODUCT_SNI_BYTE_BUDGET;
  s->work+=wanted;r.size=wanted;
  skip(&r,4);
  unsigned version=take(&r,2);
  if(version<0x0301 || version>0x0303) return PRODUCT_SNI_UNSUPPORTED;
  skip(&r,32);
  unsigned size;
  if(!vector(&r,1,&size) || size>32) return PRODUCT_SNI_MALFORMED;
  skip(&r,size);
  if(!vector(&r,2,&size) || !size || (size&1)) return PRODUCT_SNI_MALFORMED;
  skip(&r,size);
  if(!vector(&r,1,&size) || !size) return PRODUCT_SNI_MALFORMED;
  unsigned null_compression=0;
  for(unsigned i=0;i<size;++i) if(!take(&r,1)) null_compression=1;
  if(!null_compression) return PRODUCT_SNI_MALFORMED;
  char name[PRODUCT_SNI_NAME_BYTES]={0};
  unsigned name_length=0;
  if(r.position!=r.size) {
    if(!vector(&r,2,&size) || size!=r.size-r.position) return PRODUCT_SNI_MALFORMED;
    uint16_t extensions[TLS_EXTENSIONS];unsigned count=0;
    while(r.position<r.size) {
      if(r.size-r.position<4) return PRODUCT_SNI_MALFORMED;
      unsigned type=take(&r,2);
      if(count==TLS_EXTENSIONS) return PRODUCT_SNI_BYTE_BUDGET;
      for(unsigned i=0;i<count;++i) if(extensions[i]==type) return PRODUCT_SNI_MALFORMED;
      extensions[count++]=(uint16_t)type;
      if(!vector(&r,2,&size)) return PRODUCT_SNI_MALFORMED;
      if(type) {skip(&r,size);continue;}
      unsigned end=r.position+size, names;
      if(size<5 || !vector(&r,2,&names) || names!=size-2) return PRODUCT_SNI_MALFORMED;
      /* RFC6066 currently defines only host_name. Unknown NameType has no
       * defined framing to skip: keep the whole result unavailable. */
      if(take(&r,1)) return PRODUCT_SNI_UNSUPPORTED;
      if(!vector(&r,2,&name_length) || name_length!=end-r.position
         || !host_name(&r,name_length,name)) return PRODUCT_SNI_MALFORMED;
    }
  }
  s->result=name_length?PRODUCT_SNI_NAME:PRODUCT_SNI_ABSENT;
  s->name_length=(uint16_t)name_length;
  memcpy(s->name,name,sizeof name);
  return PRODUCT_SNI_COMPLETE;
}
void product_flow_sni_stop(product_flow_entry_t *entry,unsigned reason)
{
  if(!entry->sni.stop) entry->sni.stop=(uint8_t)reason;
  entry->sni.deadline_us=0;
  /* Return all logical cache ranges immediately; reserved capacity belongs
   * to the preallocated Flow pool and can never become a parser-slot quota. */
  memset(&entry->tcp_bytes,0,sizeof entry->tcp_bytes);
}
void product_flow_sni_observe(product_flow_entry_t *entry,
  const product_packet_facts_t *facts,const uint8_t *payload,uint32_t length)
{
  product_sni_state_t *s=&entry->sni;
  if(s->stop) return;
  if(facts->protocol!=6) {product_flow_sni_stop(entry,PRODUCT_SNI_UNSUPPORTED);return;}
  if(s->attempts && entry->last_seen-s->started_us>=PRODUCT_SNI_TIMEOUT_US) {
    product_flow_sni_stop(entry,PRODUCT_SNI_TIMEOUT);return;
  }
  unsigned side=entry->last_flow_direction==PRODUCT_FLOW_DIRECTION_REPLY;
  product_tcp_byte_cache_t *cache=&entry->tcp_bytes;
  uint32_t sequence=facts->tcp_sequence+!!(facts->tcp_flags&2);
  if(!length) {
    if((facts->tcp_flags&2) && !cache->started[side]) {
      cache->started[side]=1;cache->next_sequence[side]=sequence;
    }
    return;
  }
  if(!s->attempts) {
    s->started_us=entry->last_seen;
    s->deadline_us=entry->last_seen>UINT64_MAX-PRODUCT_SNI_TIMEOUT_US
      ? UINT64_MAX : entry->last_seen+PRODUCT_SNI_TIMEOUT_US;
  }
  ++s->attempts;
  if(cache->started[side] && sequence!=cache->next_sequence[side]) {
    product_flow_sni_stop(entry,PRODUCT_SNI_SEQUENCE);return;
  }
  if(length>PRODUCT_TCP_CACHE_SIDE_BYTES-cache->length[side]) {
    product_flow_sni_stop(entry,PRODUCT_SNI_BYTE_BUDGET);return;
  }
  cache->started[side]=1;cache->next_sequence[side]=sequence+length;
  memcpy(cache->bytes[side]+cache->length[side],payload,length);
  cache->length[side]+=(uint16_t)length;s->bytes+=length;
  unsigned stop=client_hello(cache->bytes[side],cache->length[side],s);
  if(stop) product_flow_sni_stop(entry,stop);
  else if(s->attempts==PRODUCT_SNI_MAX_PACKETS) product_flow_sni_stop(entry,PRODUCT_SNI_PACKET_BUDGET);
}
