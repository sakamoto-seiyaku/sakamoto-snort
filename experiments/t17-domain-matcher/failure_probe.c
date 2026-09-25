/* Isolated builder-failure experiment, never loaded into Product. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
#if defined(DATRIE)
#include <datrie/trie.h>
#elif defined(RAX)
#include "rax.h"
#else
#include <vppinfra/hash.h>
#include <vppinfra/mem.h>
#endif
static unsigned long fail_at, allocations;
static int injected;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
static int reject(void) {
    if (fail_at && ++allocations == fail_at) {
        injected = 1; errno = ENOMEM;
        (void)write(2, "allocation_injected\n", 20);
        return 1;
    }
    return 0;
}
void *__wrap_malloc(size_t n) { return reject() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { return reject() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t n) { return reject() ? NULL : __real_realloc(p, n); }
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    struct rlimit no_core = {0, 0}; setrlimit(RLIMIT_CORE, &no_core);
    unsigned long requested = strtoul(argv[1], NULL, 10);
    int failed = 0, preserved = 0;
#if defined(DATRIE)
    AlphaMap *a = alpha_map_new(); if (!a || alpha_map_add_range(a, '-', 'z')) return 2;
    Trie *tree = trie_new(a); alpha_map_free(a); if (!tree) return 2;
    AlphaChar original[] = {'s','e','e','d',0};
    if (!trie_store(tree, original, 42)) return 2;
#elif defined(RAX)
    rax *tree = raxNew(); if (!tree || !raxInsert(tree, (unsigned char *)"seed", 4, (void *)42, NULL)) return 2;
#else
    (void)requested;
    if (!clib_mem_init(NULL, 64 << 10)) return 2;
    uword *tree = hash_create_string(0, sizeof(uword));
    hash_set_mem(tree, "seed", 42);
#endif
    (void)write(2, "builder_ready\n", 14);
    fail_at = requested;
    char (*keys)[64] = __real_calloc(10000, 64);
    if (!keys) return 2;
    for (unsigned i = 0; i < 10000; i++) {
        snprintf(keys[i], 64, "unique%08u.example.test", i);
#if defined(DATRIE)
        AlphaChar key[64]; size_t n = strlen(keys[i]);
        for (size_t j = 0; j <= n; j++) key[j] = (unsigned char)keys[i][j];
        if (!trie_store(tree, key, (TrieData)i)) { failed = 1; break; }
#elif defined(RAX)
        if (!raxInsert(tree, (unsigned char *)keys[i], strlen(keys[i]), (void *)(uintptr_t)(i + 1), NULL)) { failed = 1; break; }
#else
        hash_set_mem(tree, keys[i], i);
#endif
    }
    fail_at = 0;
#if defined(DATRIE)
    TrieData value; preserved = trie_retrieve(tree, original, &value) && value == 42;
    trie_free(tree);
#elif defined(RAX)
    void *value; preserved = raxFind(tree, (unsigned char *)"seed", 4, &value) && value == (void *)42;
    raxFree(tree);
#else
    uword *value = hash_get_mem(tree, "seed"); preserved = value && *value == 42;
    hash_free(tree);
#endif
    free(keys);
    printf("{\"injected\":%d,\"allocation\":%lu,\"failure_returned\":%d,\"seed_preserved\":%d}\n",
           injected, requested, failed, preserved);
    return preserved ? 0 : 3;
}
