/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DOMAINS_MEMORY_H
#define PRODUCT_DOMAINS_MEMORY_H
#include <stddef.h>
/* One compile-time platform binding, not a runtime backend selector. */
void *product_domains_memory_heap(void);
void *product_domains_memory_alloc(void *heap, size_t bytes);
void product_domains_memory_free(void *heap, void *pointer);
size_t product_domains_memory_size(void *pointer);
#endif
