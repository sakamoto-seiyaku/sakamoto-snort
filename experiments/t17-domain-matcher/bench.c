/* Experiment only. Public-library adapters; never import into Product. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#if defined(DATRIE)
#include <datrie/trie.h>
#elif defined(RAX)
#include "rax.h"
#else
#include <vppinfra/hash.h>
#include <vppinfra/mem.h>
#endif

typedef struct { char name[254]; uint64_t exact, descendants; } Entry;
typedef struct { unsigned char name[1024]; size_t len; int status; uint64_t mask; } Query;
static Entry *entries;
static size_t entry_count;
static uint64_t allocation_calls;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n) { allocation_calls++; return __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { allocation_calls++; return __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t n) { allocation_calls++; return __real_realloc(p, n); }
static void fail(const char *s) { fprintf(stderr, "%s\n", s); exit(2); }
static uint64_t now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
static long rss(void) {
    FILE *f = fopen("/proc/self/status", "r");
    char line[256]; long n = -1;
    if (!f) return n;
    while (fgets(line, sizeof line, f)) if (sscanf(line, "VmRSS: %ld kB", &n) == 1) break;
    fclose(f); return n;
}
static int normalize(const unsigned char *in, size_t n, char out[254]) {
    if (!n || n > 253) return -1;
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = in[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c == '.') {
            if (!label || out[i - 1] == '-') return -1;
            label = 0;
        } else {
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') ||
                (!label && c == '-') || ++label > 63) return -1;
        }
        out[i] = (char)c;
    }
    if (!label || out[n - 1] == '-') return -1;
    out[n] = 0;
    return 0;
}

typedef struct {
#if defined(DATRIE)
    Trie *tree; TrieState *root, *cursor;
#elif defined(RAX)
    rax *tree;
#else
    uword *tree;
#endif
} Dictionary;
static Dictionary build(void) {
    Dictionary d = {0};
#if defined(DATRIE)
    AlphaMap *alpha = alpha_map_new();
    if (!alpha || alpha_map_add_range(alpha, '-', 'z')) fail("alphabet allocation failed");
    d.tree = trie_new(alpha); alpha_map_free(alpha);
    if (!d.tree) fail("trie allocation failed");
#elif defined(RAX)
    d.tree = raxNew(); if (!d.tree) fail("rax allocation failed");
#else
    d.tree = hash_create_string(0, sizeof(uword));
#endif
    for (size_t i = 0; i < entry_count; i++) {
        size_t n = strlen(entries[i].name);
#if defined(DATRIE)
        AlphaChar key[254];
        for (size_t j = 0; j < n; j++) key[j] = (unsigned char)entries[i].name[n - j - 1];
        key[n] = 0;
        if (!trie_store(d.tree, key, (TrieData)i)) fail("trie store failed");
#elif defined(RAX)
        unsigned char key[254];
        for (size_t j = 0; j < n; j++) key[j] = (unsigned char)entries[i].name[n - j - 1];
        if (!raxInsert(d.tree, key, n, (void *)(uintptr_t)(i + 1), NULL)) fail("rax insert failed");
#else
        (void)n;
        hash_set_mem(d.tree, entries[i].name, i);
#endif
    }
#if defined(DATRIE)
    d.root = trie_root(d.tree); d.cursor = trie_root(d.tree);
    if (!d.root || !d.cursor) fail("cursor allocation failed");
#endif
    return d;
}
static void destroy(Dictionary *d) {
#if defined(DATRIE)
    trie_state_free(d->root); trie_state_free(d->cursor); trie_free(d->tree);
#elif defined(RAX)
    raxFree(d->tree);
#else
    hash_free(d->tree);
#endif
}
static int lookup(Dictionary *d, const Query *q, uint64_t *result) {
    char name[254]; *result = 0;
    if (normalize(q->name, q->len, name)) return -1;
    size_t n = q->len;
#if defined(DATRIE)
    trie_state_copy(d->cursor, d->root);
    for (size_t j = 0; j < n; j++) {
        if (!trie_state_walk(d->cursor, (unsigned char)name[n - j - 1])) break;
        if ((j + 1 == n || name[n - j - 2] == '.') && trie_state_is_terminal(d->cursor)) {
            TrieData idx = trie_state_get_data(d->cursor);
            if (idx < 0 || (size_t)idx >= entry_count) fail("invalid trie payload");
            *result |= entries[idx].descendants;
            if (j + 1 == n) *result |= entries[idx].exact;
        }
    }
#elif defined(RAX)
    unsigned char reversed[254];
    for (size_t j = 0; j < n; j++) reversed[j] = (unsigned char)name[n - j - 1];
    for (size_t j = 1; j <= n; j++) if (j == n || reversed[j] == '.') {
        void *value;
        if (raxFind(d->tree, reversed, j, &value)) {
            size_t idx = (uintptr_t)value - 1;
            *result |= entries[idx].descendants;
            if (j == n) *result |= entries[idx].exact;
        }
    }
#else
    for (size_t j = 0; j < n; j++) if (!j || name[j - 1] == '.') {
        uword *value = hash_get_mem(d->tree, name + j);
        if (value) {
            *result |= entries[*value].descendants;
            if (!j) *result |= entries[*value].exact;
        }
    }
#endif
    return 0;
}
static int compare_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
int main(int argc, char **argv) {
    if (argc != 4) fail("usage: bench entries.tsv queries.tsv run-id");
    long baseline = rss();
#if !defined(DATRIE) && !defined(RAX)
    if (!clib_mem_init(NULL, 256 << 20)) fail("VPP heap initialization failed");
#endif
    entries = calloc(100010, sizeof(*entries));
    Query *queries = calloc(30000, sizeof(*queries));
    uint64_t *samples = calloc(30000, sizeof(*samples));
    if (!entries || !queries || !samples) fail("input allocation failed");
    FILE *f = fopen(argv[1], "r"); if (!f) fail("open entries failed");
    while (entry_count < 100010 && fscanf(f, "%253s\t%" SCNx64 "\t%" SCNx64,
           entries[entry_count].name, &entries[entry_count].exact,
           &entries[entry_count].descendants) == 3) entry_count++;
    if (!feof(f)) fail("invalid or excessive entries");
    fclose(f);
    f = fopen(argv[2], "r"); if (!f) fail("open queries failed");
    size_t count = 0; char line[4096];
    while (fgets(line, sizeof line, f)) {
        if (count >= 30000) fail("excessive queries");
        char *tab = strchr(line, '\t'); if (!tab) fail("invalid query input");
        size_t hexlen = (size_t)(tab - line);
        Query *q = &queries[count++]; q->len = hexlen / 2;
        if (hexlen % 2 || q->len > sizeof(q->name)) fail("invalid query length");
        for (size_t j = 0; j < q->len; j++) {
            unsigned byte; if (sscanf(line + j * 2, "%2x", &byte) != 1) fail("invalid hex");
            q->name[j] = (unsigned char)byte;
        }
        if (sscanf(tab + 1, "%d\t%" SCNx64, &q->status, &q->mask) != 2) fail("invalid oracle");
    }
    fclose(f); if (!count || !entry_count) fail("empty workload");
    long input_rss = rss();
    uint64_t start = now(); Dictionary old = build(); uint64_t build_ns = now() - start;
    long built_rss = rss();
    start = now(); Dictionary current = build(); uint64_t replacement_ns = now() - start;
    long replacement_rss = rss(); destroy(&old); long resident_rss = rss();
    uint64_t before = allocation_calls, checksum = 0;
    for (size_t i = 0; i < count; i++) {
        uint64_t value; start = now(); int status = lookup(&current, &queries[i], &value);
        samples[i] = now() - start;
        if (status != queries[i].status || value != queries[i].mask) {
            fprintf(stderr, "oracle mismatch query=%zu status=%d/%d mask=%" PRIx64 "/%" PRIx64 "\n",
                    i, status, queries[i].status, value, queries[i].mask); return 3;
        }
        checksum ^= value;
    }
    uint64_t query_allocations = allocation_calls - before;
    start = now();
    for (unsigned repeat = 0; repeat < 20; repeat++) for (size_t i = 0; i < count; i++) {
        uint64_t value; lookup(&current, &queries[i], &value); checksum += value;
    }
    uint64_t batch_ns = now() - start;
    query_allocations += allocation_calls - before - query_allocations;
    qsort(samples, count, sizeof(*samples), compare_u64);
    struct rusage usage; getrusage(RUSAGE_SELF, &usage);
    size_t structure_bytes = 0;
#if defined(RAX)
    structure_bytes = raxAllocSize(current.tree);
#elif !defined(DATRIE)
    structure_bytes = hash_bytes(current.tree);
#endif
    printf("{\"run_id\":\"%s\",\"entries\":%zu,\"queries\":%zu,\"build_ns\":%" PRIu64
           ",\"replacement_build_ns\":%" PRIu64 ",\"baseline_rss_kib\":%ld,\"input_rss_kib\":%ld"
           ",\"built_rss_kib\":%ld,\"replacement_rss_kib\":%ld,\"resident_rss_kib\":%ld"
           ",\"peak_rss_kib\":%ld,\"p50_ns\":%" PRIu64 ",\"p95_ns\":%" PRIu64
           ",\"p99_ns\":%" PRIu64 ",\"batch_ns\":%" PRIu64 ",\"batch_queries\":%zu"
           ",\"query_allocations_wrapped\":%" PRIu64 ",\"structure_bytes\":%zu,\"checksum\":%" PRIu64 "}\n",
           argv[3], entry_count, count, build_ns, replacement_ns, baseline, input_rss,
           built_rss, replacement_rss, resident_rss, usage.ru_maxrss, samples[count / 2],
           samples[count * 95 / 100], samples[count * 99 / 100], batch_ns, count * 20,
           query_allocations, structure_bytes, checksum);
    destroy(&current); free(samples); free(queries); free(entries);
    return query_allocations ? 4 : 0;
}
