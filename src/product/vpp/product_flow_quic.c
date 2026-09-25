/* SPDX-License-Identifier: Apache-2.0 */
#include "product_hello.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include <string.h>

#define QUIC_PACKET_BYTES 4096U
#define QUIC_SPANS 32U
#define QUIC_FRAMES 64U
#define QUIC_PACKETS 8U
#define QUIC_WORK_LIMIT 131072U

int product_quic_init(void)
{
  /* Upstream hardware-capability probes cache their result on first use.
   * Prime both AES and GCM on the existing serialized graph startup path,
   * before owner workers can race their first Initial. All packet contexts
   * and key schedules remain stack-local after this one-time preparation. */
  const uint8_t key[16]={0};
  mbedtls_aes_context aes;mbedtls_aes_init(&aes);
  int rc=mbedtls_aes_setkey_enc(&aes,key,128);
  mbedtls_aes_free(&aes);
  mbedtls_gcm_context gcm;mbedtls_gcm_init(&gcm);
  if(!rc) rc=mbedtls_gcm_setkey(&gcm,MBEDTLS_CIPHER_ID_AES,key,128);
  mbedtls_gcm_free(&gcm);
  return rc;
}

/* RFC2104 with fixed small public Initial keys, over the upstream SHA-256
 * primitive. Stack contexts avoid the generic MD/HKDF API's heap allocation. */
static int initial_hmac(const uint8_t *key,unsigned key_size,
  const uint8_t *input,unsigned size,uint8_t output[32])
{
  uint8_t pad[64],inner[32];
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  memset(pad,0x36,sizeof pad);
  for(unsigned i=0;i<key_size;++i) pad[i]^=key[i];
  int rc=mbedtls_sha256_starts(&ctx,0);
  if(!rc) rc=mbedtls_sha256_update(&ctx,pad,sizeof pad);
  if(!rc) rc=mbedtls_sha256_update(&ctx,input,size);
  if(!rc) rc=mbedtls_sha256_finish(&ctx,inner);
  for(unsigned i=0;i<sizeof pad;++i) pad[i]^=0x36^0x5c;
  if(!rc) rc=mbedtls_sha256_starts(&ctx,0);
  if(!rc) rc=mbedtls_sha256_update(&ctx,pad,sizeof pad);
  if(!rc) rc=mbedtls_sha256_update(&ctx,inner,sizeof inner);
  if(!rc) rc=mbedtls_sha256_finish(&ctx,output);
  mbedtls_sha256_free(&ctx);
  return rc;
}
/* RFC8446 HKDF-Expand-Label, empty context and <=32 output bytes: exactly
 * one RFC5869 expansion block. Labels below are fixed, never packet input. */
static int initial_label(const uint8_t secret[32],const char *label,
                          unsigned size,uint8_t *output)
{
  uint8_t info[32]={0},block[32];
  unsigned n=(unsigned)strlen(label);
  info[1]=(uint8_t)size;info[2]=(uint8_t)(6+n);
  memcpy(info+3,"tls13 ",6);memcpy(info+9,label,n);
  info[10+n]=1;
  int rc=initial_hmac(secret,32,info,11+n,block);
  if(!rc) memcpy(output,block,size);
  return rc;
}
static int varint(const uint8_t *p,unsigned n,unsigned *at,uint64_t *value)
{
  if(*at>=n) return 0;
  unsigned size=1U<<(p[*at]>>6);
  if(size>n-*at) return 0;
  uint64_t v=p[(*at)++]&63;
  for(unsigned i=1;i<size;++i) v=(v<<8)|p[(*at)++];
  *value=v;return 1;
}
/* Sorted, disjoint half-open ranges cover only copied CRYPTO bytes. Identical
 * overlaps are valid retransmissions; conflicting content cannot be assembled. */
static unsigned insert_crypto(product_quic_crypto_t *q,product_sni_state_t *s,
  unsigned first,const uint8_t *data,unsigned size)
{
  if(size>QUIC_WORK_LIMIT-s->work) return PRODUCT_SNI_BYTE_BUDGET;
  s->work+=size;
  unsigned last=first+size,begin=0,end,lo=first,hi=last,unique=size;
  while(begin<q->range_count && q->ranges[begin].last<first) ++begin;
  end=begin;
  while(end<q->range_count && q->ranges[end].first<=last) {
    unsigned left=q->ranges[end].first,right=q->ranges[end].last;
    unsigned overlap_first=left>first?left:first,overlap_last=right<last?right:last;
    if(overlap_first<overlap_last) {
      unsigned overlap=overlap_last-overlap_first;
      if(memcmp(q->bytes+overlap_first,data+overlap_first-first,overlap))
        return PRODUCT_SNI_MALFORMED;
      unique-=overlap;
    }
    if(left<lo) lo=left;
    if(right>hi) hi=right;
    ++end;
  }
  if(!unique) return PRODUCT_SNI_RUNNING;
  if(q->range_count-(end-begin)==PRODUCT_QUIC_CRYPTO_RANGES)
    return PRODUCT_SNI_BYTE_BUDGET;
  memcpy(q->bytes+first,data,size);
  memmove(q->ranges+begin+1,q->ranges+end,
          (q->range_count-end)*sizeof q->ranges[0]);
  q->ranges[begin].first=(uint16_t)lo;q->ranges[begin].last=(uint16_t)hi;
  q->range_count=(uint8_t)(q->range_count-(end-begin)+1);
  q->length+=(uint16_t)unique;s->bytes+=unique;
  return PRODUCT_SNI_RUNNING;
}
static unsigned frames(const uint8_t *p,unsigned n,product_flow_entry_t *entry)
{
  product_quic_crypto_t *q=&entry->quic_crypto;
  product_sni_state_t *state=&entry->sni;
  unsigned at=0,count=0,frame_count=0;
  while(at<n) {
    if(!p[at]) {++at;continue;}
    if(++frame_count>QUIC_FRAMES) return PRODUCT_SNI_BYTE_BUDGET;
    uint64_t type;
    if(!varint(p,n,&at,&type)) return PRODUCT_SNI_MALFORMED;
    if(type==1) continue; /* PING */
    if(type==2 || type==3) {
      uint64_t largest,delay,ranges,first;
      if(!varint(p,n,&at,&largest) || !varint(p,n,&at,&delay)
         || !varint(p,n,&at,&ranges) || !varint(p,n,&at,&first)
         || first>largest) return PRODUCT_SNI_MALFORMED;
      if(ranges>32) return PRODUCT_SNI_BYTE_BUDGET;
      largest-=first;
      for(unsigned i=0;i<ranges;++i) {
        uint64_t gap,range;
        if(!varint(p,n,&at,&gap) || !varint(p,n,&at,&range)
           || gap+2>largest || range>largest-gap-2) return PRODUCT_SNI_MALFORMED;
        largest-=gap+2+range;
      }
      if(type==3) for(unsigned i=0;i<3;++i)
        if(!varint(p,n,&at,&delay)) return PRODUCT_SNI_MALFORMED;
      continue;
    }
    if(type!=6) return PRODUCT_SNI_UNSUPPORTED;
    uint64_t offset,size;
    if(!varint(p,n,&at,&offset) || !varint(p,n,&at,&size) || size>n-at)
      return PRODUCT_SNI_MALFORMED;
    if(!size) continue;
    if(offset>PRODUCT_QUIC_CRYPTO_BYTES || size>PRODUCT_QUIC_CRYPTO_BYTES-offset
       || count==QUIC_SPANS) return PRODUCT_SNI_BYTE_BUDGET;
    ++count;
    unsigned stop=insert_crypto(q,state,(unsigned)offset,p+at,(unsigned)size);
    if(stop) return stop;
    at+=(unsigned)size;
  }
  unsigned contiguous=q->range_count && !q->ranges[0].first?q->ranges[0].last:0;
  if(contiguous<=q->contiguous) return PRODUCT_SNI_RUNNING;
  q->contiguous=(uint16_t)contiguous;
  product_hello_span_t span={0,contiguous};
  return product_sni_parse_hello(q->bytes,&span,1,contiguous,state);
}
static unsigned initial(const uint8_t *p,unsigned n,product_flow_entry_t *entry,
                        unsigned *consumed)
{
  product_quic_crypto_t *q=&entry->quic_crypto;
  if(n<5) return PRODUCT_SNI_MALFORMED;
  uint32_t version=(uint32_t)p[1]<<24|(uint32_t)p[2]<<16|(uint32_t)p[3]<<8|p[4];
  if(version!=1) return PRODUCT_SNI_QUIC_VERSION;
  if((p[0]&0x30)!=0) return PRODUCT_SNI_UNSUPPORTED;
  if(n<6) return PRODUCT_SNI_MALFORMED;
  unsigned at=5;
  unsigned dcid_size=p[at++];
  if(dcid_size>20 || dcid_size>n-at) return PRODUCT_SNI_MALFORMED;
  const uint8_t *dcid=p+at;at+=dcid_size;
  if(q->anchored && (q->dcid_size!=dcid_size || memcmp(q->dcid,dcid,dcid_size)))
    return PRODUCT_SNI_UNSUPPORTED;
  if(at==n) return PRODUCT_SNI_MALFORMED;
  unsigned scid_size=p[at++];
  if(scid_size>20 || scid_size>n-at) return PRODUCT_SNI_MALFORMED;
  at+=scid_size;
  uint64_t token,length;
  if(!varint(p,n,&at,&token) || token>n-at) return PRODUCT_SNI_MALFORMED;
  at+=(unsigned)token;
  if(!varint(p,n,&at,&length) || length<20 || length>n-at) return PRODUCT_SNI_MALFORMED;
  unsigned end=at+(unsigned)length;
  *consumed=end;
  /* A bounded copy restores the protected header in-place and supplies
   * authenticated plaintext for borrowed spans. No Flow retains this buffer. */
  uint8_t packet[QUIC_PACKET_BYTES];
  memcpy(packet,p,end);
  static const uint8_t salt[20]={0x38,0x76,0x2c,0xf7,0xf5,0x59,0x34,0xb3,
    0x4d,0x17,0x9a,0xe6,0xa4,0xc8,0x0c,0xad,0xcc,0xbb,0x7f,0x0a};
  uint8_t secret[32],client[32],key[16],iv[12],hp[16],mask[16];
  if(initial_hmac(salt,sizeof salt,dcid,dcid_size,secret)
     || initial_label(secret,"client in",32,client)
     || initial_label(client,"quic key",16,key)
     || initial_label(client,"quic iv",12,iv)
     || initial_label(client,"quic hp",16,hp)) return PRODUCT_SNI_CRYPTO_ERROR;
  mbedtls_aes_context aes;mbedtls_aes_init(&aes);
  int rc=mbedtls_aes_setkey_enc(&aes,hp,128);
  if(!rc) rc=mbedtls_aes_crypt_ecb(&aes,MBEDTLS_AES_ENCRYPT,p+at+4,mask);
  mbedtls_aes_free(&aes);
  if(rc) return PRODUCT_SNI_CRYPTO_ERROR;
  packet[0]^=mask[0]&15;
  unsigned pn_size=(packet[0]&3)+1;
  uint64_t pn=0;
  for(unsigned i=0;i<pn_size;++i) {
    packet[at+i]^=mask[i+1];pn=(pn<<8)|packet[at+i];
  }
  /* RFC9000 Appendix A.3 after the first observed PN window. A missing
   * earlier flight cannot be guessed; only authenticated packets advance it. */
  if(q->anchored) {
    uint64_t expected=q->largest_pn+1,window=UINT64_C(1)<<(8*pn_size);
    pn=(expected&~(window-1))|pn;
    if(pn+window/2<=expected && pn<(UINT64_C(1)<<62)-window) pn+=window;
    else if(pn>expected+window/2 && pn>=window) pn-=window;
  }
  for(unsigned i=0;i<8;++i) iv[11-i]^=(uint8_t)(pn>>(8*i));
  unsigned header=at+pn_size,body=end-header-16;
  mbedtls_gcm_context gcm;mbedtls_gcm_init(&gcm);
  rc=mbedtls_gcm_setkey(&gcm,MBEDTLS_CIPHER_ID_AES,key,128);
  if(!rc) rc=mbedtls_gcm_auth_decrypt(&gcm,body,iv,sizeof iv,packet,header,
    p+end-16,16,p+header,packet+header);
  mbedtls_gcm_free(&gcm);
  if(rc==MBEDTLS_ERR_GCM_AUTH_FAILED) return PRODUCT_SNI_QUIC_AUTH;
  if(rc) return PRODUCT_SNI_CRYPTO_ERROR;
  if(packet[0]&12) return PRODUCT_SNI_MALFORMED;
  if(!q->anchored) {
    memcpy(q->dcid,dcid,dcid_size);q->dcid_size=(uint8_t)dcid_size;
    q->direction=entry->last_flow_direction;q->anchored=1;q->largest_pn=pn;
  } else if(pn>q->largest_pn) q->largest_pn=pn;
  return frames(packet+header,body,entry);
}
void product_flow_quic_observe(product_flow_entry_t *entry,
  const uint8_t *payload,uint32_t length)
{
  product_sni_state_t *s=&entry->sni;
  if(s->attempts && entry->last_seen-s->started_us>=PRODUCT_SNI_TIMEOUT_US) {
    product_flow_sni_stop(entry,PRODUCT_SNI_TIMEOUT);return;
  }
  if(!length) return;
  if(!s->attempts) {
    s->started_us=entry->last_seen;
    s->deadline_us=entry->last_seen>UINT64_MAX-PRODUCT_SNI_TIMEOUT_US
      ? UINT64_MAX : entry->last_seen+PRODUCT_SNI_TIMEOUT_US;
  }
  ++s->attempts;
  if(length>QUIC_PACKET_BYTES || length>QUIC_WORK_LIMIT-s->work) {
    product_flow_sni_stop(entry,PRODUCT_SNI_BYTE_BUDGET);return;
  }
  s->work+=length;
  unsigned stop=PRODUCT_SNI_RUNNING;
  if((payload[0]&0xc0)==0xc0 && (!entry->quic_crypto.anchored
      || entry->quic_crypto.direction==entry->last_flow_direction)) {
    /* Minimum Initial size applies to the UDP datagram, not each coalesced
     * QUIC packet. Bound crypto invocations independently of tiny framing. */
    if(length<1200) stop=PRODUCT_SNI_MALFORMED;
    else for(unsigned at=0,packets=0;at<length;) {
      if((payload[at]&0xc0)!=0xc0) break;
      if(++packets>QUIC_PACKETS) {stop=PRODUCT_SNI_BYTE_BUDGET;break;}
      unsigned consumed=0;
      stop=initial(payload+at,length-at,entry,&consumed);
      if(stop) break;
      at+=consumed;
    }
  }
  if(stop) product_flow_sni_stop(entry,stop);
  else if(s->attempts==PRODUCT_SNI_MAX_PACKETS)
    product_flow_sni_stop(entry,PRODUCT_SNI_PACKET_BUDGET);
}
