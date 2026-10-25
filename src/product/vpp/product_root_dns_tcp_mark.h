/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ROOT_DNS_TCP_MARK_H
#define SAKAMOTO_PRODUCT_ROOT_DNS_TCP_MARK_H
#include "product_root_dns_tcp_io.h"
#include <vlib/vlib.h>

/* Pinned VPP gives this Product-only path a generic u32 flow_id. Root writes
 * it for every ingress, including an absent/zero NFQA_MARK. It is read only
 * for an original unfragmented TCP53 packet with the capture qualification bit, after
 * native origin identity validation and before buffer return. Reassembly and
 * other graph lifetimes must never consume it as an original skb mark. */
_Static_assert(offsetof(vlib_buffer_t,flow_id)==8, "pinned VPP generic flow identifier offset");
_Static_assert(sizeof(((vlib_buffer_t *)0)->flow_id)==sizeof(uint32_t),
  "Root original mark uses pinned VPP's existing generic flow identifier");
static inline void product_root_dns_capture_mark(vlib_buffer_t *buffer,uint32_t mark)
{ buffer->flow_id=mark; }
static inline uint32_t product_root_dns_original_mark(const vlib_buffer_t *buffer)
{ return buffer->flow_id; }

static inline size_t product_root_dns_tcp_offset(const uint8_t *data,size_t length)
{
  if(!data || length<20)return 0;
  size_t at;uint8_t protocol;
  if((data[0]>>4)==4) {
    at=(data[0]&15)*4U;
    if(at<20 || (data[6]&0x3f) || data[7])return 0;
    protocol=data[9];
  } else if((data[0]>>4)==6 && length>=40) {
    at=40;protocol=data[6];
    while(protocol==0 || protocol==43 || protocol==60 || protocol==51) {
      if(at+2>length)return 0;
      size_t bytes=protocol==51?((size_t)data[at+1]+2)*4:((size_t)data[at+1]+1)*8;
      if(bytes>length-at)return 0;
      protocol=data[at];at+=bytes;
    }
  } else return 0;
  return protocol==6 && at+20<=length && data[at+2]==0 && data[at+3]==53 ? at : 0;
}
static inline int product_root_dns_tcp_packet_bytes(const uint8_t *data,size_t length)
{ return product_root_dns_tcp_offset(data,length)!=0; }
static inline int product_root_dns_tcp_syn_bytes(const uint8_t *data,size_t length)
{
  size_t at=product_root_dns_tcp_offset(data,length);
  return at && (data[at+13]&0x17)==2;
}
#endif
