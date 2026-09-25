/* SPDX-License-Identifier: Apache-2.0 */
#include "product_hello.h"
#include "mbedtls/aes.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include <string.h>

#define QUIC_PACKET_BYTES 4096U
#define QUIC_SPANS 32U
#define QUIC_FRAMES 64U
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
static unsigned frames(const uint8_t *p,unsigned n,product_sni_state_t *state)
{
  product_hello_span_t spans[QUIC_SPANS];
  uint64_t offsets[QUIC_SPANS];
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
    if(offset>QUIC_PACKET_BYTES || size>QUIC_PACKET_BYTES-offset
       || count==QUIC_SPANS) return PRODUCT_SNI_BYTE_BUDGET;
    unsigned i=count;
    while(i && offsets[i-1]>offset) {
      offsets[i]=offsets[i-1];spans[i]=spans[i-1];--i;
    }
    offsets[i]=offset;spans[i]=(product_hello_span_t){at,(unsigned)size};
    ++count;at+=(unsigned)size;
  }
  unsigned total=0;
  for(unsigned i=0;i<count;++i) {
    if(offsets[i]!=total) return PRODUCT_SNI_QUIC_INCOMPLETE;
    total+=spans[i].size;
  }
  unsigned stop=product_sni_parse_hello(p,spans,count,total,state);
  return stop ? stop : PRODUCT_SNI_QUIC_INCOMPLETE;
}
static unsigned initial(const uint8_t *p,unsigned n,product_sni_state_t *state)
{
  if(n<5) return PRODUCT_SNI_MALFORMED;
  uint32_t version=(uint32_t)p[1]<<24|(uint32_t)p[2]<<16|(uint32_t)p[3]<<8|p[4];
  if(version!=1) return PRODUCT_SNI_QUIC_VERSION;
  if((p[0]&0x30)!=0) return PRODUCT_SNI_UNSUPPORTED;
  if(n<1200) return PRODUCT_SNI_MALFORMED;
  unsigned at=5;
  unsigned dcid_size=p[at++];
  if(dcid_size>20 || dcid_size>n-at) return PRODUCT_SNI_MALFORMED;
  const uint8_t *dcid=p+at;at+=dcid_size;
  if(at==n) return PRODUCT_SNI_MALFORMED;
  unsigned scid_size=p[at++];
  if(scid_size>20 || scid_size>n-at) return PRODUCT_SNI_MALFORMED;
  at+=scid_size;
  uint64_t token,length;
  if(!varint(p,n,&at,&token) || token>n-at) return PRODUCT_SNI_MALFORMED;
  at+=(unsigned)token;
  if(!varint(p,n,&at,&length) || length<20 || length>n-at) return PRODUCT_SNI_MALFORMED;
  unsigned end=at+(unsigned)length;
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
  uint32_t pn=0;
  for(unsigned i=0;i<pn_size;++i) {
    packet[at+i]^=mask[i+1];pn=(pn<<8)|packet[at+i];
  }
  for(unsigned i=0;i<4;++i) iv[11-i]^=(uint8_t)(pn>>(8*i));
  unsigned header=at+pn_size,body=end-header-16;
  mbedtls_gcm_context gcm;mbedtls_gcm_init(&gcm);
  rc=mbedtls_gcm_setkey(&gcm,MBEDTLS_CIPHER_ID_AES,key,128);
  if(!rc) rc=mbedtls_gcm_auth_decrypt(&gcm,body,iv,sizeof iv,packet,header,
    p+end-16,16,p+header,packet+header);
  mbedtls_gcm_free(&gcm);
  if(rc==MBEDTLS_ERR_GCM_AUTH_FAILED) return PRODUCT_SNI_QUIC_AUTH;
  if(rc) return PRODUCT_SNI_CRYPTO_ERROR;
  if(packet[0]&12) return PRODUCT_SNI_MALFORMED;
  return frames(packet+header,body,state);
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
  s->bytes+=length;s->work+=length;
  unsigned stop=PRODUCT_SNI_RUNNING;
  if((payload[0]&0xc0)==0xc0) stop=initial(payload,length,s);
  if(stop) product_flow_sni_stop(entry,stop);
  else if(s->attempts==PRODUCT_SNI_MAX_PACKETS)
    product_flow_sni_stop(entry,PRODUCT_SNI_PACKET_BUDGET);
}
