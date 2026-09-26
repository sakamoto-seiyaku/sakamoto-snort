/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_domains.h"
#include "product_domains_memory.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#ifdef PRODUCT_DOMAINS_VPP_HEAP
#include <vppinfra/mem.h>
#endif

static size_t live_blocks, live_bytes, peak_bytes;
static unsigned allocation_calls, fail_at;
void *__real_product_domains_memory_alloc(void *, size_t);
void __real_product_domains_memory_free(void *, void *);
void *__wrap_product_domains_memory_alloc(void *heap, size_t bytes) {
    ++allocation_calls;
    if (fail_at && allocation_calls == fail_at) return NULL;
    void *p = __real_product_domains_memory_alloc(heap, bytes);
    if (p) {
        ++live_blocks; live_bytes += product_domains_memory_size(p);
        if (live_bytes > peak_bytes) peak_bytes=live_bytes;
    }
    return p;
}
void __wrap_product_domains_memory_free(void *heap, void *p) {
    if (p) { assert(live_blocks); --live_blocks; live_bytes -= product_domains_memory_size(p); }
    __real_product_domains_memory_free(heap,p);
}

static uint64_t flat_memberships(const sakamoto_product_domains_t *source, const char *name) {
    uint64_t found=0;
    size_t length=strlen(name);
    for (unsigned i=0;i<source->entry_count;++i) {
        const sakamoto_product_domain_entry_t *entry=&source->entries[i];
        if (length < entry->length) continue;
        size_t offset=length-entry->length;
        if (offset && (!entry->mode || name[offset-1]!='.')) continue;
        if (!memcmp(name+offset,entry->name,entry->length)) found |= UINT64_C(1)<<entry->list;
    }
    return found;
}

static void fault_cleanup_and_all_memberships(void) {
    sakamoto_product_domains_t source={.list_count=64,.entry_count=256};
    for (unsigned i=0;i<source.entry_count;++i) {
        sakamoto_product_domain_entry_t *e=&source.entries[i];
        e->list=i%64; e->mode=(i/64)&1;
        /* Repeated keys, compressed paths and branch splits all participate. */
        snprintf((char *)e->name,sizeof e->name,"%c%u.branch%u.example.com",'a'+i%26,i%91,i%5);
        e->length=strlen((char *)e->name);
    }
    assert(!product_domains_normalize(&source));
    product_domains_t *old=NULL;
    assert(!product_domains_build(&source,&old));
    size_t old_bytes=live_bytes, old_blocks=live_blocks;
    for (unsigned i=0;i<source.entry_count;++i) {
        char name[258];
        snprintf(name,sizeof name,"x.%s",source.entries[i].name);
        assert(product_domains_match(old,(uint8_t *)name,strlen(name))==flat_memberships(&source,name));
    }
    allocation_calls=0;
    product_domains_t *next=NULL;
    assert(!product_domains_build(&source,&next));
    unsigned calls=allocation_calls;
    product_domains_destroy(next);
    assert(live_bytes==old_bytes && live_blocks==old_blocks);
    unsigned rejected=0, recovered=0;
    for (unsigned fault=1;fault<=calls;++fault) {
        fail_at=fault; allocation_calls=0; next=NULL;
        int result=product_domains_build(&source,&next);
        fail_at=0;
        if (result) { assert(result==PRODUCT_DOMAINS_MEMORY && !next); ++rejected; }
        else {
            ++recovered;
            for (unsigned i=0;i<source.entry_count;++i) {
                const char *name=(char *)source.entries[i].name;
                assert(product_domains_match(next,(const uint8_t *)name,strlen(name))==flat_memberships(&source,name));
            }
            product_domains_destroy(next);
        }
        assert(live_bytes==old_bytes && live_blocks==old_blocks);
        const char *name=(char *)source.entries[fault%256].name;
        assert(product_domains_match(old,(const uint8_t *)name,strlen(name))==flat_memberships(&source,name));
    }
    product_domains_destroy(old);
    assert(!live_bytes && !live_blocks);
    printf("T18 full domain build: %u allocations, %u rejected, %u recovered, peak %zu bytes\n",
           calls,rejected,recovered,peak_bytes);
}

static void invalid_and_boundary_names(void) {
    for (unsigned i=0;i<12;++i) {
        const char *bad[]={"", ".", "a..b", "a.example..", "-a.example", "a-.example", "a_b.example",
                          "https://example.com", "*.example.com", "example.com:443", "a/b", "\xc3\xa9.example"};
        sakamoto_product_domains_t source={.list_count=1,.entry_count=1};
        source.entries[0].length=strlen(bad[i]);
        memcpy(source.entries[0].name,bad[i],source.entries[0].length);
        assert(product_domains_normalize(&source)==PRODUCT_DOMAINS_INVALID);
    }
    sakamoto_product_domains_t source={.list_count=64,.entry_count=2};
    source.entries[0].list=63; source.entries[0].mode=1; source.entries[0].length=253;
    memset(source.entries[0].name,'a',253);
    source.entries[0].name[63]=source.entries[0].name[127]=source.entries[0].name[191]='.';
    source.entries[1]=(sakamoto_product_domain_entry_t){.list=1,.length=21,.name="xn--bcher-kva.example"};
    source.entries[1].length=strlen((char *)source.entries[1].name);
    assert(!product_domains_normalize(&source));
    product_domains_t *domains=NULL;
    assert(!product_domains_build(&source,&domains));
    assert(product_domains_match(domains,source.entries[0].name,253)==UINT64_C(1)<<63);
    assert(product_domains_match(domains,source.entries[1].name,source.entries[1].length)==2);
    product_domains_destroy(domains);
    source.entries[0].name[63]='a';
    assert(product_domains_normalize(&source)==PRODUCT_DOMAINS_INVALID);
    source.entry_count=257; domains=(product_domains_t *)1;
    assert(product_domains_build(&source,&domains)==PRODUCT_DOMAINS_INVALID && !domains);
}

static void overlapping_lists(void) {
    sakamoto_product_domains_t source = {.list_count = 4, .entry_count = 4,
        .entries = {{.list=0,.mode=0,.length=11,.name="Example.COM"},
                    {.list=1,.mode=1,.length=12,.name="example.com."},
                    {.list=2,.mode=1,.length=7,.name="sub.com"},
                    {.list=3,.mode=1,.length=3,.name="com"}}};
    assert(product_domains_normalize(&source) == 0);
    product_domains_t *domains = NULL;
    assert(product_domains_build(&source, &domains) == 0);
    assert(product_domains_match(domains, (const uint8_t *)"EXAMPLE.COM", 11) == 11);
    assert(product_domains_match(domains, (const uint8_t *)"x.example.com", 13) == 10);
    assert(product_domains_match(domains, (const uint8_t *)"badexample.com", 14) == 8);
    assert(product_domains_match(domains, (const uint8_t *)"x.sub.com", 9) == 12);
    assert(product_domains_match(domains, (const uint8_t *)"example.com.evil", 16) == 0);
    assert(product_domains_bytes(domains) > 0);
    product_domains_destroy(domains);
}

static unsigned long long clock_ns(void) {
    struct timespec value; assert(!clock_gettime(CLOCK_MONOTONIC,&value));
    return (unsigned long long)value.tv_sec*1000000000ULL+(unsigned long long)value.tv_nsec;
}
static void bounded_cost(void) {
    sakamoto_product_domains_t source={.list_count=64,.entry_count=256};
    for(unsigned i=0;i<256;++i) {
        source.entries[i].list=i%64;source.entries[i].mode=1;
        source.entries[i].length=snprintf((char *)source.entries[i].name,256,"d%u.example.com",i);
    }
    product_domains_t *domains=NULL;
    unsigned long long start=clock_ns();
    for(unsigned i=0;i<100;++i) {
        assert(!product_domains_build(&source,&domains));
        product_domains_destroy(domains);
    }
    unsigned long long build_ns=clock_ns()-start;
    assert(!product_domains_build(&source,&domains));
    char names[256][32];
    for(unsigned i=0;i<256;++i) snprintf(names[i],32,"x.d%u.example.com",i);
    start=clock_ns();
    for(unsigned i=0;i<200000;++i)
        assert(product_domains_match(domains,(const uint8_t *)names[i%256],strlen(names[i%256]))==
               (UINT64_C(1)<<(i%64)));
    unsigned long long query_ns=clock_ns()-start;
    printf("{\"kind\":\"domain_cost\",\"entries\":256,\"builds\":100,\"build_destroy_ns\":%llu,"
           "\"queries\":200000,\"query_ns\":%llu,\"snapshot_bytes\":%zu,\"allocation_peak_bytes\":%zu}\n",
           build_ns,query_ns,product_domains_bytes(domains),peak_bytes);
    product_domains_destroy(domains);
    assert(!live_bytes && !live_blocks);
}

#ifdef PRODUCT_DOMAINS_VPP_HEAP
static void actual_heap_exhaustion(void) {
    clib_mem_heap_t *original=clib_mem_get_heap();
    clib_mem_heap_t *heap=clib_mem_create_heap(NULL,512*1024,1,"T18 domain failure test");
    assert(heap);
    clib_mem_set_heap(heap);
    sakamoto_product_domains_t source={.list_count=1,.entry_count=1,
        .entries={{.length=11,.name="example.com"}}};
    product_domains_t *old=NULL, *next=NULL;
    assert(!product_domains_build(&source,&old));
    size_t old_bytes=live_bytes, old_blocks=live_blocks;
    void *pressure[1024]; unsigned used=0;
    while (used<1024 && (pressure[used]=clib_mem_heap_alloc_aligned_or_null(heap,1024,16))) ++used;
    assert(used && used<1024);
    assert(product_domains_build(&source,&next)==PRODUCT_DOMAINS_MEMORY && !next);
    assert(live_bytes==old_bytes && live_blocks==old_blocks);
    assert(product_domains_match(old,(const uint8_t *)"example.com",11)==1);
    while (used) clib_mem_heap_free(heap,pressure[--used]);
    assert(!product_domains_build(&source,&next));
    assert(product_domains_match(next,(const uint8_t *)"example.com",11)==1);
    /* Destruction deliberately runs with another active heap. */
    clib_mem_set_heap(original);
    product_domains_destroy(next);product_domains_destroy(old);
    assert(!live_bytes && !live_blocks);
    clib_mem_destroy_heap(heap);
    puts("T18 VPP real heap exhaustion, old result, retry and cross-heap free: PASS");
}
#endif
int main(void) {
#ifdef PRODUCT_DOMAINS_VPP_HEAP
    assert(clib_mem_init(NULL,8*1024*1024));
#endif
    overlapping_lists();
    invalid_and_boundary_names();
    fault_cleanup_and_all_memberships();
    bounded_cost();
#ifdef PRODUCT_DOMAINS_VPP_HEAP
    actual_heap_exhaustion();
#endif
    puts("Product domain memberships: PASS");
    return 0;
}
