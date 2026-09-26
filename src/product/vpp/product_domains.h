/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DOMAINS_NATIVE_H
#define SAKAMOTO_PRODUCT_DOMAINS_NATIVE_H
#include "sakamoto_product_domains.h"
#include <stddef.h>

/* Immutable after build. Destruction requires that all borrowing readers have
 * left. The captured allocation heap must outlive the object. */
typedef struct product_domains product_domains_t;
#define PRODUCT_DOMAINS_MAX_BYTES (128U * 1024U)
enum { PRODUCT_DOMAINS_OK, PRODUCT_DOMAINS_INVALID, PRODUCT_DOMAINS_MEMORY };

/* In-place source canonicalization; called only on a private candidate. */
int product_domains_normalize(sakamoto_product_domains_t *);
int product_domains_build(const sakamoto_product_domains_t *, product_domains_t **);
void product_domains_destroy(product_domains_t *);
/* No allocation or mutation. Input is a validated network name, not a URL. */
uint64_t product_domains_match(const product_domains_t *, const uint8_t *, size_t);
size_t product_domains_bytes(const product_domains_t *);
#endif
