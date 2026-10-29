/* SPDX-License-Identifier: Apache-2.0 */
/* Fault retained bytes after a valid public insertion. No production mutation
 * API is added. Both eligibility and mature-codec failures must use upstream. */
#include "../../src/product/vpp/product_dns_proxy.c"
#define main dns_cache_behavior_suite
#include "product_dns_cache_test.c"
#undef main
int main(void)
{
 for(unsigned ordered=0;ordered<2;++ordered)for(unsigned fault=0;fault<2;++fault){
  product_dns_proxy_t *proxy=open_proxy();
  if(ordered){
   product_dns_proxy_close(proxy);
   product_dns_proxy_route_t route={.enabled=1,.family=4,.port=53,.address={192,0,2,53},
    .endpoint_count=2,.route_count=1,.routes={{.count=2,.candidates={0,1}}},
    .endpoints={{.transport=1,.family=4,.port=53,.address={192,0,2,53},.identity="primary.test"},
     {.transport=1,.family=4,.port=54,.address={192,0,2,54},.identity="backup.test"}}};
   product_dns_proxy_callbacks_t callbacks={.send=send_query,.reply=reply,.acquire=acquire};
   proxy=product_dns_proxy_open(77,&route,&callbacks,NULL);assert(proxy);
  }
  submit(proxy,question,sizeof(question));answer(proxy,30);
  assert(replies==1&&proxy->cache.count==1);dns_cache_entry_t *entry=NULL;
  for(unsigned i=0;i<DNS_CACHE_ENTRIES;++i)if(proxy->cache.entries[i].data)entry=&proxy->cache.entries[i];
  assert(entry);uint8_t *wire=entry->data+entry->query_length;
  if(fault)wire[2]&=0x7f; /* eligibility passes; mature correlation rejects QR=0 */
  else wire[sizeof(question)+11]=255; /* eligibility walker rejects RDLENGTH */
  ++input.identity.now_us;submit(proxy,question,sizeof(question));
  assert(sends==2&&replies==1&&product_dns_proxy_resources(proxy).active==1&&proxy->cache.count==0);
  assert(key.resolver_id==ordered&&!proxy->resources.failed_attempts&&!proxy->resources.failovers);
  assert(!proxy->resources.health[0].failures&&!proxy->resources.health[1].failures);
  answer(proxy,30);assert(replies==2&&!completed.cached&&product_dns_proxy_resources(proxy).active==0);
  assert(received_length==sizeof(question)+16&&!memcmp(received,question,2)&&!memcmp(received+12,question+12,sizeof(question)-12));
  product_dns_proxy_close(proxy);printf("ordered=%u cache_read_fault=%u same_candidate_upstream_recovery=1 active=0 PASS\n",ordered,fault);
 }
 return 0;
}
