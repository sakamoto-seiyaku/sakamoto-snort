/* SPDX-License-Identifier: Apache-2.0 */
/* Fault retained bytes after a valid public insertion. No production mutation
 * API is added. Both eligibility and mature-codec failures must use upstream. */
#include "../../src/product/vpp/product_dns_proxy.c"
#define main dns_cache_behavior_suite
#include "product_dns_cache_test.c"
#undef main
int main(void)
{
 for(unsigned fault=0;fault<2;++fault){
  product_dns_proxy_t *proxy=open_proxy();submit(proxy,question,sizeof(question));answer(proxy,30);
  assert(replies==1&&proxy->cache.count==1);dns_cache_entry_t *entry=NULL;
  for(unsigned i=0;i<DNS_CACHE_ENTRIES;++i)if(proxy->cache.entries[i].data)entry=&proxy->cache.entries[i];
  assert(entry);uint8_t *wire=entry->data+entry->query_length;
  if(fault)wire[2]&=0x7f; /* eligibility passes; mature correlation rejects QR=0 */
  else wire[sizeof(question)+11]=255; /* eligibility walker rejects RDLENGTH */
  ++input.identity.now_us;submit(proxy,question,sizeof(question));
  assert(sends==2&&replies==1&&product_dns_proxy_resources(proxy).active==1&&proxy->cache.count==0);
  answer(proxy,30);assert(replies==2&&!completed.cached&&product_dns_proxy_resources(proxy).active==0);
  assert(received_length==sizeof(question)+16&&!memcmp(received,question,2)&&!memcmp(received+12,question+12,sizeof(question)-12));
  product_dns_proxy_close(proxy);printf("cache_read_fault=%u upstream_recovery=1 active=0 PASS\n",fault);
 }
 return 0;
}
