/* SPDX-License-Identifier: Apache-2.0 */
#ifndef PRODUCT_DOMAINS_RAX_H
#define PRODUCT_DOMAINS_RAX_H
#include <stddef.h>
void *product_domains_rax_alloc(size_t);
void *product_domains_rax_realloc(void *, size_t);
void product_domains_rax_free(void *);
size_t product_domains_rax_size(void *);
#define rax_malloc product_domains_rax_alloc
#define rax_realloc product_domains_rax_realloc
#define rax_free product_domains_rax_free
#define rax_ptr_alloc_size product_domains_rax_size
#endif
