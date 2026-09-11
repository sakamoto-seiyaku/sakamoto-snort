/* SPDX-License-Identifier: Apache-2.0 */
/* Local-endpoint reassembly with a temporary per-worker table,
 * first-fragment identity and detached completion stages.
 * This implementation stores only bounded native-buffer descriptors. */
#include "product_fragment.h"
#include <string.h>
#include <stdlib.h>

static uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static uint32_t be32(const uint8_t *p) { return ((uint32_t)be16(p) << 16) | be16(p+2); }
static uint64_t mix(uint64_t h, uint8_t b) { return (h ^ b) * UINT64_C(1099511628211); }
static int extension(uint8_t protocol) {
  return protocol==0 || protocol==43 || protocol==60 || protocol==51;
}
static int extension_end(const uint8_t *data, unsigned length,
                         unsigned at, uint8_t protocol, unsigned *end) {
  if (at>length || length-at<2) return 0;
  unsigned bytes=protocol==51 ? ((unsigned)data[at+1]+2)*4
                             : ((unsigned)data[at+1]+1)*8;
  if (bytes>length-at) return 0;
  *end=at+bytes;
  return 1;
}
static uint64_t key_hash(const product_fragment_key_t *key) {
  uint64_t h=UINT64_C(14695981039346656037);
  h=mix(mix(h,key->family),key->protocol);
  for (unsigned i=0;i<16;i++) h=mix(mix(h,key->source[i]),key->destination[i]);
  for (unsigned i=0;i<4;i++) h=mix(h,(uint8_t)(key->identification >> (24-i*8)));
  return h;
}
static int key_equal(const product_fragment_key_t *a,const product_fragment_key_t *b) {
  return a->family==b->family && a->protocol==b->protocol && a->identification==b->identification
    && !memcmp(a->source,b->source,16) && !memcmp(a->destination,b->destination,16);
}

uint16_t product_fragment_worker(const product_worker_layout_t *layout,
                                const product_fragment_key_t *key) {
  /* Symmetric L3 placement is independent of ID, ports and arrival lane.
   * This temporary placement hash does not create an OwnerAssignment. */
  if (!layout || !layout->worker_count || !key) return PRODUCT_EXECUTION_OWNER_UNKNOWN;
  uint64_t hash=mix(UINT64_C(14695981039346656037),key->family);
  const uint8_t *a=key->source, *b=key->destination;
  if (memcmp(a,b,16)>0) { a=key->destination; b=key->source; }
  for (unsigned i=0;i<16;i++) hash=mix(mix(hash,a[i]),b[i]);
  return (uint16_t)(hash % layout->worker_count);
}

int product_fragment_parse(const uint8_t *data,size_t size,
                           product_fragment_piece_t *p,product_packet_facts_t *f) {
  memset(p,0,sizeof(*p)); memset(f,0,sizeof(*f));
  if (!size) return 0;
  unsigned family=data[0]>>4, length, header;
  if (family==4) {
    if (size<8 || !(be16(data+6)&0x3fff)) return 0;
    if (size<20) return -1;
    header=(data[0]&15)*4; length=be16(data+2);
    if (header<20 || header>length || length>size) return -1;
    p->offset=(be16(data+6)&0x1fff)*8; p->more=!!(data[6]&0x20);
    p->key.protocol=data[9]; p->key.identification=be16(data+4);
    memcpy(p->key.source+12,data+12,4); memcpy(p->key.destination+12,data+16,4);
  } else if (family==6) {
    if (size<40) return -1;
    length=40+be16(data+4);
    if (length>size) return -1;
    unsigned at=40, previous=6;
    uint8_t protocol=data[6];
    while (extension(protocol)) {
      unsigned end;
      if (!extension_end(data,length,at,protocol,&end)) return -1;
      previous=at; protocol=data[at]; at=end;
    }
    if (protocol!=44) return 0;
    if (length-at<8 || (be16(data+at+2)&6)) return -1;
    header=at+8;
    p->previous_next_header=previous;
    p->offset=be16(data+at+2)&0xfff8; p->more=data[at+3]&1;
    p->key.protocol=data[at]; p->key.identification=be32(data+at+4);
    memcpy(p->key.source,data+8,16); memcpy(p->key.destination,data+24,16);
  } else return 0;
  unsigned payload=length-header;
  if (!payload || (p->more && payload%8) || (uint32_t)p->offset+payload>65535) return -1;
  p->key.family=family; p->header_length=header; p->length=payload;
  if (!p->offset) {
    f->l3_status=PRODUCT_PACKET_L3_COMPLETE; f->ip_family=family; f->protocol=p->key.protocol;
    unsigned identity_header=header;
    while (family==6 && extension(f->protocol)) {
      unsigned end;
      if (!extension_end(data,length,identity_header,f->protocol,&end)) return -1;
      f->protocol=data[identity_header]; identity_header=end;
    }
    if (family==6 && f->protocol==44) return -1;
    unsigned identity_length=length-identity_header;
    memcpy(f->source_address,p->key.source,16); memcpy(f->destination_address,p->key.destination,16);
    f->l4_status=PRODUCT_PACKET_L4_OTHER_TERMINAL;
    if (f->protocol==6 || f->protocol==17) {
      /* First-fragment identity only: full L4 validation stays after assembly. */
      if (identity_length<4) return -1;
      f->source_port=be16(data+identity_header); f->destination_port=be16(data+identity_header+2);
      f->l4_status=PRODUCT_PACKET_L4_COMPLETE;
    } else if ((family==4 && f->protocol==1) || (family==6 && f->protocol==58)) {
      if (identity_length<8) return -1;
      f->icmp_type=data[identity_header]; f->icmp_code=data[identity_header+1];
      f->icmp_identifier=be16(data+identity_header+4);
      f->icmp_identity_known=f->icmp_code==0 &&
        ((family==4 && (f->icmp_type==0 || f->icmp_type==8)) ||
         (family==6 && (f->icmp_type==128 || f->icmp_type==129)));
    }
  }
  return 1;
}

int product_fragment_table_init(product_fragment_table_t *t,uint32_t capacity,
                                uint32_t limit,uint64_t timeout_us) {
  if (!t || !capacity || capacity==UINT32_MAX || !limit ||
      limit==UINT32_MAX || !timeout_us) return 0;
  memset(t,0,sizeof(*t)); t->capacity=capacity; t->original_limit=limit; t->timeout_us=timeout_us;
  size_t rows=(size_t)capacity+1, columns=(size_t)limit+1;
  if (rows>SIZE_MAX/columns || rows*columns>SIZE_MAX/sizeof(*t->storage)) return 0;
  t->bucket_count=capacity;
  t->contexts=calloc(capacity,sizeof(*t->contexts));
  t->buckets=calloc(t->bucket_count,sizeof(*t->buckets));
  t->storage=calloc(rows*columns,sizeof(*t->storage));
  if (!t->contexts || !t->buckets || !t->storage) {
    product_fragment_table_destroy(t); return 0;
  }
  t->detached=t->storage+(size_t)capacity*columns;
  for (unsigned i=0;i<t->bucket_count;i++) t->buckets[i]=PRODUCT_FRAGMENT_INDEX_NONE;
  for (unsigned i=0;i<capacity;i++) {
    t->contexts[i].free_next=i+1<capacity?i+1:PRODUCT_FRAGMENT_INDEX_NONE;
    t->contexts[i].bundle.pieces=t->storage+(size_t)i*columns;
  }
  return 1;
}
void product_fragment_table_destroy(product_fragment_table_t *t) {
  if (!t) return;
  free(t->storage); free(t->buckets); free(t->contexts);
  memset(t,0,sizeof(*t));
}
static void detach(product_fragment_table_t *t,uint32_t index,product_fragment_bundle_t *out) {
  product_fragment_context_t *c=&t->contexts[index];
  unsigned bucket=key_hash(&c->key)%t->bucket_count;
  uint32_t *link=&t->buckets[bucket];
  while (*link!=index) link=&t->contexts[*link].next;
  *link=c->next; *out=c->bundle; c->active=0; t->active--;
  c->bundle.pieces=t->detached; t->detached=out->pieces;
  c->free_next=t->free_head; t->free_head=index;
}
product_fragment_result_t product_fragment_push(product_fragment_table_t *t,
    const product_fragment_piece_t *p,const product_owner_assignment_t *assignment,
    uint64_t now,product_fragment_bundle_t *out) {
  memset(out,0,sizeof(*out));
  out->pieces=t->detached;
  unsigned bucket=key_hash(&p->key)%t->bucket_count;
  uint32_t index=t->buckets[bucket];
  while (index!=PRODUCT_FRAGMENT_INDEX_NONE && !key_equal(&t->contexts[index].key,&p->key))
    index=t->contexts[index].next;
  if (index==PRODUCT_FRAGMENT_INDEX_NONE) {
    if (t->free_head==PRODUCT_FRAGMENT_INDEX_NONE) {
      out->pieces[0]=*p; out->count=1; return PRODUCT_FRAGMENT_CONTEXT_FULL;
    }
    index=t->free_head; product_fragment_context_t *c=&t->contexts[index];
    product_fragment_piece_t *pieces=c->bundle.pieces;
    t->free_head=c->free_next; memset(c,0,sizeof(*c));
    c->bundle.pieces=pieces;
    c->key=p->key; c->active=1; c->started_us=now; c->bundle.first=PRODUCT_FRAGMENT_INDEX_NONE;
    c->next=t->buckets[bucket]; t->buckets[bucket]=index; t->active++;
  }
  product_fragment_context_t *c=&t->contexts[index];
  uint32_t end=(uint32_t)p->offset+p->length;
  product_fragment_result_t error=PRODUCT_FRAGMENT_WAIT;
  if (c->bundle.count==t->original_limit) error=PRODUCT_FRAGMENT_BUNDLE_FULL;
  else if ((!p->offset && c->bundle.first!=PRODUCT_FRAGMENT_INDEX_NONE) ||
           (!p->more && c->have_last)) error=PRODUCT_FRAGMENT_CONFLICT;
  if (error!=PRODUCT_FRAGMENT_WAIT) {
    detach(t,index,out); out->pieces[out->count++]=*p; return error;
  }
  if (!p->offset) { c->bundle.first=c->bundle.count; c->bundle.assignment=*assignment; }
  if (!p->more) { c->have_last=1; c->bundle.total_length=end; }
  c->bundle.pieces[c->bundle.count++]=*p;
  uint64_t received=0;
  for (unsigned i=0;i<c->bundle.count;i++) received+=c->bundle.pieces[i].length;
  if (c->have_last && c->bundle.first!=PRODUCT_FRAGMENT_INDEX_NONE && received>=c->bundle.total_length) {
    /* Select the newest contiguous middle ranges backwards from the last.
     * Unselected duplicate originals still receive exactly one completion. */
    uint32_t cursor=c->bundle.total_length;
    product_fragment_piece_t *first=&c->bundle.pieces[c->bundle.first];
    for (unsigned i=0;i<c->bundle.count;i++) {
      product_fragment_piece_t *q=&c->bundle.pieces[i];
      q->selected=0;
      if (!q->more) { q->selected=1; cursor=q->offset; }
    }
    if (!first->more) cursor=first->length;
    while (cursor>first->length) {
      uint32_t previous=cursor;
      for (uint32_t i=c->bundle.count;i>0;i--) {
        product_fragment_piece_t *q=&c->bundle.pieces[i-1];
        if (q->offset && q->more && q->length &&
            (uint32_t)q->offset+q->length==cursor) {
          q->selected=1; cursor=q->offset; break;
        }
      }
      if (cursor==previous) break;
    }
    if (cursor!=first->length) {
      detach(t,index,out); return PRODUCT_FRAGMENT_CONFLICT;
    }
    first->selected=1;
    detach(t,index,out); return PRODUCT_FRAGMENT_COMPLETE;
  }
  return PRODUCT_FRAGMENT_WAIT;
}
int product_fragment_take_expired(product_fragment_table_t *t,uint64_t now,int flush,
                                  product_fragment_bundle_t *out) {
  for (unsigned i=0;i<t->capacity;i++) {
    product_fragment_context_t *c=&t->contexts[i];
    if (c->active && (flush || (now>=c->started_us && now-c->started_us>=t->timeout_us))) {
      detach(t,i,out); return 1;
    }
  }
  return 0;
}
