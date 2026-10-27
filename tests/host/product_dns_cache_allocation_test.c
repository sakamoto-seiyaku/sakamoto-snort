/* SPDX-License-Identifier: Apache-2.0 */
/* Real allocator observation around the existing public message seam. The
 * candidate size comes from the supplied complete query + answer wire, never
 * an internal cache type, field or container layout. Codec/output scratch has
 * distinct sizes. All actual allocations remain real; nothing is mocked. */
#define main dns_cache_behavior_suite
#include "product_dns_cache_test.c"
#undef main
#include <stdint.h>
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__real_realloc(void *,size_t);
void __real_free(void *);
static struct { void *pointer; size_t bytes; } allocations[8192];
static uint64_t live_bytes, actual_cache_peak;
static size_t candidate_bytes;
static unsigned candidate_allocations;
static product_dns_proxy_t *observed_proxy;
static size_t forget(void *pointer)
{
 if(!pointer)return 0;
 for(unsigned i=0;i<8192;++i)if(allocations[i].pointer==pointer){
  size_t bytes=allocations[i].bytes;allocations[i].pointer=NULL;live_bytes-=bytes;return bytes;
 }
 return 0;
}
static void remember(void *pointer,size_t bytes)
{
 if(!pointer)return;
 for(unsigned i=0;i<8192;++i)if(!allocations[i].pointer){
  allocations[i].pointer=pointer;allocations[i].bytes=bytes;live_bytes+=bytes;
  if(observed_proxy&&bytes==candidate_bytes){
   product_dns_proxy_resources_t r=product_dns_proxy_resources(observed_proxy);
   assert(live_bytes>=r.owned_bytes);uint64_t actual=live_bytes-r.owned_bytes;
   if(actual>actual_cache_peak)actual_cache_peak=actual;
   ++candidate_allocations;
  }
  return;
 }
 assert(!"allocator witness capacity");
}
void *__wrap_malloc(size_t bytes)
{ void *p=__real_malloc(bytes);remember(p,bytes);return p; }
void *__wrap_calloc(size_t count,size_t bytes)
{ assert(!bytes||count<=SIZE_MAX/bytes);void *p=__real_calloc(count,bytes);remember(p,count*bytes);return p; }
void *__wrap_realloc(void *pointer,size_t bytes)
{
 size_t old=forget(pointer);void *p=__real_realloc(pointer,bytes);
 if(p)remember(p,bytes);else if(bytes)remember(pointer,old);return p;
}
void __wrap_free(void *pointer)
{ (void)forget(pointer);__real_free(pointer); }
int main(void)
{
 product_dns_proxy_t *proxy=open_proxy();observed_proxy=proxy;
 uint8_t q[sizeof(question)],wire[65535];
 for(unsigned i=0;i<40;++i){
  unique_question(q,i,65000);submit(proxy,q,sizeof(q));size_t n=make_answer(wire,30,65000,60000);
  candidate_bytes=sizeof(q)+n;feed(proxy,wire,n);
 }
 product_dns_proxy_resources_t r=product_dns_proxy_resources(proxy);
 assert(r.cache_evictions>0&&candidate_allocations==40);
 printf("actual_cache_candidate_peak=%llu public_cache_high_water=%llu byte_limit=2097152 candidates=%u\n",
  (unsigned long long)actual_cache_peak,(unsigned long long)r.cache_high_water_bytes,candidate_allocations);fflush(stdout);
 assert(actual_cache_peak<=2097152); /* includes newly allocated data plus all old live data and fixed cache storage */
 observed_proxy=NULL;product_dns_proxy_close(proxy);assert(!live_bytes);
 return 0;
}
