/* SPDX-License-Identifier: Apache-2.0 */
#include "product_flow_entry.h"
#include "product_hello.h"
#include <string.h>

/* DTLS 1.0/1.2 ClientHello SNI (RFC 6347 4.1, 4.2.2; RFC 9147 keeps the same
 * plaintext ClientHello framing). Handshake fragments of the first ClientHello
 * the origin sends are reassembled by fragment offset into the Flow's UDP
 * reserved storage; retransmitted identical fragments are absorbed, conflicting
 * ones are malformed. The complete body is rewritten into TLS ClientHello form
 * (DTLS version mapped, cookie removed) and handed to the shared TLS parser, so
 * extension and host_name rules are identical to TLS. Nothing is held or
 * delayed: every datagram is forwarded under the current verdict. */
#define DTLS_RECORD_HEADER 13U
#define DTLS_HANDSHAKE_HEADER 12U
#define DTLS_RECORDS 8U
#define DTLS_FRAGMENTS 16U
#define DTLS_WORK_LIMIT 131072U

static unsigned u16(const uint8_t *p) { return (unsigned)p[0]<<8|p[1]; }
static unsigned u24(const uint8_t *p) { return (unsigned)p[0]<<16|(unsigned)p[1]<<8|p[2]; }
static int dtls_version(const uint8_t *p) { return p[0]==0xfe && (p[1]==0xff || p[1]==0xfd); }

int product_flow_dtls_candidate(const uint8_t *payload,uint32_t length)
{ return length>=DTLS_RECORD_HEADER && payload[0]==22 && dtls_version(payload+1); }

static unsigned insert(product_quic_crypto_t *q,product_sni_state_t *s,
  unsigned first,const uint8_t *data,unsigned size)
{
  if(size>DTLS_WORK_LIMIT-s->work) return PRODUCT_SNI_BYTE_BUDGET;
  s->work+=size;
  unsigned last=first+size,begin=0,end,lo=first,hi=last,unique=size;
  while(begin<q->range_count && q->ranges[begin].last<first) ++begin;
  end=begin;
  while(end<q->range_count && q->ranges[end].first<=last) {
    unsigned left=q->ranges[end].first,right=q->ranges[end].last;
    unsigned overlap_first=left>first?left:first,overlap_last=right<last?right:last;
    if(overlap_first<overlap_last) {
      unsigned overlap=overlap_last-overlap_first;
      if(memcmp(q->bytes+overlap_first,data+overlap_first-first,overlap)) return PRODUCT_SNI_MALFORMED;
      unique-=overlap;
    }
    if(left<lo) lo=left;
    if(right>hi) hi=right;
    ++end;
  }
  if(!unique) return PRODUCT_SNI_RUNNING;
  if(q->range_count-(end-begin)==PRODUCT_QUIC_CRYPTO_RANGES) return PRODUCT_SNI_BYTE_BUDGET;
  memcpy(q->bytes+first,data,size);
  memmove(q->ranges+begin+1,q->ranges+end,(q->range_count-end)*sizeof q->ranges[0]);
  q->ranges[begin].first=(uint16_t)lo;q->ranges[begin].last=(uint16_t)hi;
  q->range_count=(uint8_t)(q->range_count-(end-begin)+1);
  q->length+=(uint16_t)unique;s->bytes+=unique;
  return PRODUCT_SNI_RUNNING;
}

/* Complete DTLS ClientHello body -> TLS handshake message for the shared parser. */
static unsigned parse(const product_quic_crypto_t *q,product_sni_state_t *s)
{
  const uint8_t *b=q->bytes;
  unsigned n=q->dtls_message_length;
  if(n<2+32+1+1) return PRODUCT_SNI_MALFORMED;
  if(!dtls_version(b)) return PRODUCT_SNI_UNSUPPORTED;
  unsigned at=2+32, session=b[at];
  if(session>32 || at+1+session+1>n) return PRODUCT_SNI_MALFORMED;
  at+=1+session;
  unsigned cookie_at=at, cookie=b[at];
  if(at+1+cookie>n) return PRODUCT_SNI_MALFORMED;
  unsigned body=n-1-cookie;                       /* TLS body: no cookie field */
  if(body+4>PRODUCT_QUIC_CRYPTO_BYTES) return PRODUCT_SNI_BYTE_BUDGET;
  uint8_t tls[PRODUCT_QUIC_CRYPTO_BYTES];
  tls[0]=1;tls[1]=(uint8_t)(body>>16);tls[2]=(uint8_t)(body>>8);tls[3]=(uint8_t)body;
  tls[4]=3;tls[5]=b[1]==0xfd?3:2;                 /* DTLS 1.2 ~ TLS 1.2, DTLS 1.0 ~ TLS 1.1 */
  memcpy(tls+6,b+2,cookie_at-2);
  memcpy(tls+4+cookie_at,b+cookie_at+1+cookie,n-cookie_at-1-cookie);
  product_hello_span_t span={0,body+4};
  return product_sni_parse_hello(tls,&span,1,body+4,s);
}

static unsigned fragments(product_flow_entry_t *entry,const uint8_t *p,unsigned n)
{
  product_quic_crypto_t *q=&entry->quic_crypto;
  product_sni_state_t *s=&entry->sni;
  unsigned count=0;
  while(n) {
    if(n<DTLS_HANDSHAKE_HEADER) return PRODUCT_SNI_MALFORMED;
    if(++count>DTLS_FRAGMENTS) return PRODUCT_SNI_BYTE_BUDGET;
    unsigned type=p[0],length=u24(p+1),seq=u16(p+4),offset=u24(p+6),size=u24(p+9);
    if(size>n-DTLS_HANDSHAKE_HEADER || offset>length || size>length-offset) return PRODUCT_SNI_MALFORMED;
    if(type!=1) return PRODUCT_SNI_UNSUPPORTED;     /* the origin's first flight starts with ClientHello */
    if(!length) return PRODUCT_SNI_MALFORMED;
    if(length>PRODUCT_QUIC_CRYPTO_BYTES-4) return PRODUCT_SNI_BYTE_BUDGET;
    if(!q->dtls_message_length) {q->dtls_message_length=length;q->dtls_message_seq=(uint16_t)seq;}
    /* Only the first ClientHello is assembled; a cookie retry carries the same SNI. */
    if(seq==q->dtls_message_seq) {
      if(length!=q->dtls_message_length) return PRODUCT_SNI_MALFORMED;
      unsigned stop=insert(q,s,offset,p+DTLS_HANDSHAKE_HEADER,size);
      if(stop) return stop;
    }
    p+=DTLS_HANDSHAKE_HEADER+size;n-=DTLS_HANDSHAKE_HEADER+size;
  }
  unsigned contiguous=q->range_count && !q->ranges[0].first?q->ranges[0].last:0;
  if(contiguous<=q->contiguous) return PRODUCT_SNI_RUNNING;
  q->contiguous=(uint16_t)contiguous;
  if(contiguous<q->dtls_message_length) return PRODUCT_SNI_RUNNING;
  if(q->dtls_message_length>DTLS_WORK_LIMIT-s->work) return PRODUCT_SNI_BYTE_BUDGET;
  s->work+=q->dtls_message_length;
  return parse(q,s);
}

void product_flow_dtls_observe(product_flow_entry_t *entry,const uint8_t *payload,uint32_t length)
{
  product_sni_state_t *s=&entry->sni;
  product_quic_crypto_t *q=&entry->quic_crypto;
  if(s->attempts && entry->last_seen-s->started_us>=PRODUCT_SNI_TIMEOUT_US) {
    product_flow_sni_stop(entry,PRODUCT_SNI_TIMEOUT);return;
  }
  if(!length) return;
  /* Server flights (HelloVerifyRequest, ServerHello) carry no client SNI. */
  if(q->direction && q->direction!=entry->last_flow_direction) return;
  if(!s->attempts) {
    s->started_us=entry->last_seen;
    s->deadline_us=entry->last_seen>UINT64_MAX-PRODUCT_SNI_TIMEOUT_US
      ? UINT64_MAX : entry->last_seen+PRODUCT_SNI_TIMEOUT_US;
    q->direction=entry->last_flow_direction;
  }
  ++s->attempts;
  if(length>DTLS_WORK_LIMIT-s->work) {product_flow_sni_stop(entry,PRODUCT_SNI_BYTE_BUDGET);return;}
  s->work+=length;
  unsigned stop=PRODUCT_SNI_RUNNING,records=0;
  for(uint32_t at=0;at<length && !stop;) {
    const uint8_t *r=payload+at;
    uint32_t left=length-at;
    if(left<DTLS_RECORD_HEADER || !dtls_version(r+1)) {stop=PRODUCT_SNI_MALFORMED;break;}
    if(++records>DTLS_RECORDS) {stop=PRODUCT_SNI_BYTE_BUDGET;break;}
    unsigned size=u16(r+11);
    if(!size || size>left-DTLS_RECORD_HEADER) {stop=PRODUCT_SNI_MALFORMED;break;}
    /* Anything but a plaintext (epoch 0) handshake record means the ClientHello is over. */
    if(r[0]!=22 || u16(r+3)) stop=PRODUCT_SNI_UNSUPPORTED;
    else stop=fragments(entry,r+DTLS_RECORD_HEADER,size);
    at+=DTLS_RECORD_HEADER+size;
  }
  if(stop) product_flow_sni_stop(entry,stop);
  else if(s->attempts==PRODUCT_SNI_MAX_PACKETS) product_flow_sni_stop(entry,PRODUCT_SNI_PACKET_BUDGET);
}
