/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_CARES_H
#define SAKAMOTO_PRODUCT_CARES_H
#include "namespace.h"
#include <ares.h>
#include <ares_dns_record.h>
#include <stddef.h>
#include <stdint.h>

/* Owner-thread synchronous allocation scope. The codec has no mutable global
 * allocator hooks. No codec-owned object may leave this scope. */
int product_cares_memory_begin (size_t limit);
size_t product_cares_memory_end (size_t *unreleased);
void product_cares_memory_status (size_t *, size_t *);
/* Public parse() does not report unconsumed trailing bytes. Use the pinned
 * buffer seam to require exactly one whole wire message. */
ares_status_t product_cares_parse (const uint8_t *, size_t, ares_dns_record_t **);
#endif
