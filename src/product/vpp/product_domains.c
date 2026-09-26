/* SPDX-License-Identifier: Apache-2.0 */
#include "product_domains.h"
#include "product_domains_memory.h"
#include "product_domains_rax.h"
#include "../../../third_party/rax/rax.h"
#include <assert.h>
#include <errno.h>
#include <string.h>

struct product_domains {
    rax *tree;
    void *heap;
    size_t bytes;
    uint32_t values_used;
    uint64_t values[SAKAMOTO_DOMAIN_MAX_ENTRIES];
};

/* rax's allocator ABI has no context argument. Build/free are synchronous and
 * scoped; read-only raxFind never uses this context or allocates. */
static _Thread_local product_domains_t *building;

void *product_domains_rax_alloc(size_t bytes) {
    assert(building);
    if (!bytes || bytes > PRODUCT_DOMAINS_MAX_BYTES - building->bytes) {
        errno = ENOMEM;
        return NULL;
    }
    void *p = product_domains_memory_alloc(building->heap, bytes);
    if (!p) { errno = ENOMEM; return NULL; }
    size_t actual = product_domains_memory_size(p);
    if (actual > PRODUCT_DOMAINS_MAX_BYTES - building->bytes) {
        product_domains_memory_free(building->heap, p);
        errno = ENOMEM;
        return NULL;
    }
    building->bytes += actual;
    return p;
}
void product_domains_rax_free(void *p) {
    if (!p) return;
    assert(building);
    size_t bytes = product_domains_memory_size(p);
    assert(bytes <= building->bytes);
    building->bytes -= bytes;
    product_domains_memory_free(building->heap, p);
}
size_t product_domains_rax_size(void *p) { return p ? product_domains_memory_size(p) : 0; }
void *product_domains_rax_realloc(void *p, size_t bytes) {
    if (!bytes) { product_domains_rax_free(p); return NULL; }
    void *next = product_domains_rax_alloc(bytes);
    if (!next) return NULL;
    if (p) {
        size_t old = product_domains_memory_size(p);
        memcpy(next, p, old < bytes ? old : bytes);
        product_domains_rax_free(p);
    }
    return next;
}

static int name_valid(const uint8_t *name, size_t length) {
    if (!length || length > 253) return 0;
    size_t label = 0;
    for (size_t i = 0; i < length; ++i) {
        unsigned c = name[i];
        if (c == '.') {
            if (!label || name[i - 1] == '-') return 0;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-') ||
                (!label && c == '-') || ++label > 63) return 0;
        }
    }
    return label && name[length - 1] != '-';
}

int product_domains_normalize(sakamoto_product_domains_t *source) {
    if (!source || source->list_count > SAKAMOTO_DOMAIN_MAX_LISTS ||
        source->entry_count > SAKAMOTO_DOMAIN_MAX_ENTRIES) return PRODUCT_DOMAINS_INVALID;
    for (uint32_t i = 0; i < source->entry_count; ++i) {
        sakamoto_product_domain_entry_t *entry = &source->entries[i];
        if (entry->list >= source->list_count || entry->mode > 1 ||
            !entry->length || entry->length > 254) return PRODUCT_DOMAINS_INVALID;
        for (size_t j = entry->length; j < sizeof entry->name; ++j)
            if (entry->name[j]) return PRODUCT_DOMAINS_INVALID;
        if (entry->name[entry->length - 1] == '.') entry->name[--entry->length] = 0;
        if (!name_valid(entry->name, entry->length)) return PRODUCT_DOMAINS_INVALID;
        for (size_t j = 0; j < entry->length; ++j)
            if (entry->name[j] >= 'A' && entry->name[j] <= 'Z') entry->name[j] += 'a' - 'A';
    }
    memset(source->entries + source->entry_count, 0,
           (SAKAMOTO_DOMAIN_MAX_ENTRIES - source->entry_count) * sizeof source->entries[0]);
    return PRODUCT_DOMAINS_OK;
}

static void reverse_key(uint8_t *key, const uint8_t *name, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = name[length - i - 1];
        key[i + 1] = c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
    }
}

int product_domains_build(const sakamoto_product_domains_t *source, product_domains_t **out) {
    if (!out) return PRODUCT_DOMAINS_INVALID;
    *out = NULL;
    if (!source || source->list_count > SAKAMOTO_DOMAIN_MAX_LISTS ||
        source->entry_count > SAKAMOTO_DOMAIN_MAX_ENTRIES) return PRODUCT_DOMAINS_INVALID;
    for (uint32_t i = 0; i < source->entry_count; ++i)
        if (source->entries[i].list >= source->list_count || source->entries[i].mode > 1 ||
            !name_valid(source->entries[i].name, source->entries[i].length))
            return PRODUCT_DOMAINS_INVALID;
    if (!source->entry_count) return PRODUCT_DOMAINS_OK;
    void *heap = product_domains_memory_heap();
    product_domains_t *domains = product_domains_memory_alloc(heap, sizeof *domains);
    if (!domains) return PRODUCT_DOMAINS_MEMORY;
    memset(domains, 0, sizeof *domains);
    domains->heap = heap;
    domains->bytes = product_domains_memory_size(domains);
    product_domains_t *previous = building;
    building = domains;
    domains->tree = raxNew();
    int result = PRODUCT_DOMAINS_MEMORY;
    if (!domains->tree) goto done;
    for (uint32_t i = 0; i < source->entry_count; ++i) {
        const sakamoto_product_domain_entry_t *entry = &source->entries[i];
        uint8_t key[SAKAMOTO_DOMAIN_NAME_BYTES];
        key[0] = entry->mode;
        reverse_key(key, entry->name, entry->length);
        void *found = NULL;
        int exists = raxFind(domains->tree, key, entry->length + 1, &found);
        uint64_t membership = UINT64_C(1) << entry->list;
        if (exists) { *(uint64_t *)found |= membership; continue; }
        uint64_t *value = &domains->values[domains->values_used];
        *value = membership;
        if (!raxInsert(domains->tree, key, entry->length + 1, value, NULL)) goto done;
        ++domains->values_used;
    }
    result = PRODUCT_DOMAINS_OK;
done:
    building = previous;
    if (result) product_domains_destroy(domains);
    else *out = domains;
    return result;
}

void product_domains_destroy(product_domains_t *domains) {
    if (!domains) return;
    product_domains_t *previous = building;
    building = domains;
    if (domains->tree) raxFree(domains->tree);
    assert(domains->bytes == product_domains_memory_size(domains));
    building = previous;
    product_domains_memory_free(domains->heap, domains);
}

uint64_t product_domains_match(const product_domains_t *domains, const uint8_t *name, size_t length) {
    if (!domains || !name || !name_valid(name, length)) return 0;
    uint8_t key[SAKAMOTO_DOMAIN_NAME_BYTES];
    reverse_key(key, name, length);
    key[0] = SAKAMOTO_DOMAIN_EXACT;
    void *value = NULL;
    int exists = raxFind(domains->tree, key, length + 1, &value);
    uint64_t memberships = exists ? *(const uint64_t *)value : 0;
    key[0] = SAKAMOTO_DOMAIN_DESCENDANTS;
    for (size_t end = 1; end <= length; ++end) {
        if (end != length && key[end + 1] != '.') continue;
        exists = raxFind(domains->tree, key, end + 1, &value);
        if (exists) memberships |= *(const uint64_t *)value;
    }
    return memberships;
}
size_t product_domains_bytes(const product_domains_t *domains) { return domains ? domains->bytes : 0; }
