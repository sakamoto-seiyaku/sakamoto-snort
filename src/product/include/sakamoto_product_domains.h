/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_DOMAINS_H
#define SAKAMOTO_PRODUCT_DOMAINS_H
#include <stdint.h>

#define SAKAMOTO_DOMAIN_MAX_LISTS 64U
#define SAKAMOTO_DOMAIN_MAX_ENTRIES 256U
#define SAKAMOTO_DOMAIN_NAME_BYTES 256U
#define SAKAMOTO_DOMAIN_EXACT 0U
#define SAKAMOTO_DOMAIN_DESCENDANTS 1U

typedef struct {
    uint32_t list, mode, length;
    uint8_t name[SAKAMOTO_DOMAIN_NAME_BYTES];
} sakamoto_product_domain_entry_t;

typedef struct {
    uint32_t list_count, entry_count;
    sakamoto_product_domain_entry_t entries[SAKAMOTO_DOMAIN_MAX_ENTRIES];
} sakamoto_product_domains_t;
#endif
