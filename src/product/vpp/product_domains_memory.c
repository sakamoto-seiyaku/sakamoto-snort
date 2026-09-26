/* SPDX-License-Identifier: Apache-2.0 */
#include "product_domains_memory.h"
#include <stdint.h>
#ifdef PRODUCT_DOMAINS_VPP_HEAP
#include <vppinfra/mem.h>
void *product_domains_memory_heap(void) { return clib_mem_get_heap(); }
void *product_domains_memory_alloc(void *heap, size_t bytes) {
    return clib_mem_heap_alloc_aligned_or_null(heap, bytes, _Alignof(max_align_t));
}
void product_domains_memory_free(void *heap, void *pointer) {
    if (pointer) clib_mem_heap_free(heap, pointer);
}
size_t product_domains_memory_size(void *pointer) { return clib_mem_size(pointer); }
#else
/* Standalone semantic-test binding. Production always selects VPP above. */
#include <stdlib.h>
typedef union { size_t bytes; max_align_t alignment; } allocation_header_t;
void *product_domains_memory_heap(void) { return NULL; }
void *product_domains_memory_alloc(void *heap, size_t bytes) {
    (void)heap;
    if (bytes > SIZE_MAX - sizeof(allocation_header_t)) return NULL;
    allocation_header_t *p = malloc(sizeof(*p) + bytes);
    if (!p) return NULL;
    p->bytes = bytes;
    return p + 1;
}
void product_domains_memory_free(void *heap, void *pointer) {
    (void)heap;
    if (pointer) free((allocation_header_t *)pointer - 1);
}
size_t product_domains_memory_size(void *pointer) {
    return ((allocation_header_t *)pointer - 1)->bytes;
}
#endif
