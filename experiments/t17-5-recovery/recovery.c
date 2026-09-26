/* T17.5 component experiment, not Product source. */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <vppinfra/mem.h>
#include "rax.h"
#include "allocator.h"

typedef struct { char name[254]; uint64_t exact, descendants; } Entry;
typedef struct { unsigned char name[1024]; size_t len; int status; uint64_t mask; } Query;
typedef struct { rax *tree; Entry *entries; size_t count; unsigned version; } Snapshot;
static Entry input[100010];
static Query queries[30000];
static uint64_t samples[30000];
static size_t input_count, query_count;
static size_t calls, live_count, live_bytes, peak_bytes, fail_at, injected;
static int fail_continuously;
static uint64_t cleanup_ns;
static const char *build_stage;
static size_t inserted;

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(3); }
}
static uint64_t now(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}
size_t recovery_size(void *p) { return p ? clib_mem_size(p) : 0; }
void *recovery_alloc(size_t n) {
    calls++;
    if (fail_at && (calls == fail_at || (fail_continuously && calls >= fail_at))) {
        injected++; errno = ENOMEM; return NULL;
    }
    void *p = clib_mem_alloc_or_null(n);
    if (!p) { errno = ENOMEM; return NULL; }
    live_count++; live_bytes += recovery_size(p);
    if (live_bytes > peak_bytes) peak_bytes = live_bytes;
    return p;
}
void recovery_free(void *p) {
    if (!p) return;
    require(live_count > 0 && live_bytes >= recovery_size(p), "allocation ledger underflow");
    live_count--; live_bytes -= recovery_size(p); clib_mem_free(p);
}
void *recovery_realloc(void *p, size_t n) {
    if (!n) { recovery_free(p); return NULL; }
    void *q = recovery_alloc(n);
    if (!q) return NULL;
    if (p) memcpy(q, p, recovery_size(p) < n ? recovery_size(p) : n);
    recovery_free(p); return q;
}
static uint64_t rotate(uint64_t value) { return (value << 1) | (value >> 63); }
static void destroy(Snapshot *s) {
    if (!s) return;
    if (s->tree) raxFree(s->tree);
    recovery_free(s->entries); recovery_free(s);
}
static Snapshot *build(unsigned version, size_t count, int reject_publication) {
    build_stage = "snapshot"; inserted = 0;
    Snapshot *s = recovery_alloc(sizeof(*s));
    if (!s) return NULL;
    *s = (Snapshot){.count = count, .version = version};
    build_stage = "payload";
    s->entries = recovery_alloc(count * sizeof(*s->entries));
    if (!s->entries) goto failed;
    memcpy(s->entries, input, count * sizeof(*s->entries));
    if (version != 1) for (size_t i = 0; i < count; i++) {
        s->entries[i].exact = rotate(s->entries[i].exact);
        s->entries[i].descendants = rotate(s->entries[i].descendants);
    }
    build_stage = "tree"; s->tree = raxNew();
    if (!s->tree) goto failed;
    for (size_t i = 0; i < count; i++) {
        build_stage = "insert";
        unsigned char reversed[254]; size_t n = strlen(s->entries[i].name);
        for (size_t j = 0; j < n; j++) reversed[j] = s->entries[i].name[n-j-1];
        errno = 0;
        if (!raxInsert(s->tree, reversed, n, (void *)(uintptr_t)(i+1), NULL)) {
            require(errno == ENOMEM, "unexpected duplicate or logical insertion failure");
            goto failed;
        }
        inserted++;
    }
    build_stage = "prepublish";
    if (!reject_publication) return s;
failed:;
    uint64_t start = now(); destroy(s); cleanup_ns += now() - start;
    return NULL;
}
static int normalize(const Query *q, char out[254]) {
    if (!q->len || q->len > 253) return -1;
    size_t label = 0;
    for (size_t i = 0; i < q->len; i++) {
        unsigned char c = q->name[i];
        if (c >= 'A' && c <= 'Z') c += 'a'-'A';
        if (c == '.') {
            if (!label || out[i-1] == '-') return -1;
            label = 0;
        } else if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') ||
                   (!label && c == '-') || ++label > 63) return -1;
        out[i] = c;
    }
    if (!label || out[q->len-1] == '-') return -1;
    out[q->len] = 0; return 0;
}
static int lookup(const Snapshot *s, const Query *q, uint64_t *mask) {
    char name[254]; unsigned char reversed[254]; *mask = 0;
    if (normalize(q, name)) return -1;
    for (size_t j = 0; j < q->len; j++) reversed[j] = name[q->len-j-1];
    for (size_t j = 1; j <= q->len; j++) if (j == q->len || reversed[j] == '.') {
        void *value;
        if (raxFind(s->tree, reversed, j, &value)) {
            size_t idx = (uintptr_t)value - 1;
            require(idx < s->count, "invalid payload");
            *mask |= s->entries[idx].descendants;
            if (j == q->len) *mask |= s->entries[idx].exact;
        }
    }
    return 0;
}
static void check(const Snapshot *s) {
    size_t before = calls;
    for (size_t i = 0; i < query_count; i++) {
        uint64_t mask;
        int status = lookup(s, &queries[i], &mask);
        uint64_t expected = s->version == 1 ? queries[i].mask : rotate(queries[i].mask);
        require(status == queries[i].status && mask == expected, "independent oracle mismatch");
    }
    require(calls == before, "query allocated");
}
static long rss(void) {
    FILE *f = fopen("/proc/self/status", "r"); char line[256]; long value = -1;
    if (!f) return value;
    while (fgets(line, sizeof(line), f)) if (sscanf(line, "VmRSS: %ld kB", &value) == 1) break;
    fclose(f); return value;
}
static void load(const char *entries_path, const char *queries_path) {
    FILE *f = fopen(entries_path, "r"); require(f != NULL, "open entries");
    while (input_count < 100010 && fscanf(f, "%253s\t%" SCNx64 "\t%" SCNx64,
           input[input_count].name, &input[input_count].exact, &input[input_count].descendants) == 3) input_count++;
    require(feof(f) && input_count, "bad entries"); fclose(f);
    f = fopen(queries_path, "r"); require(f != NULL, "open queries");
    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        require(query_count < 30000, "too many queries");
        Query *q = &queries[query_count++]; char *tab = strchr(line, '\t');
        require(tab != NULL, "bad query"); size_t n = tab - line;
        require(n % 2 == 0 && n/2 <= sizeof(q->name), "bad query length"); q->len = n/2;
        for (size_t j = 0; j < q->len; j++) {
            unsigned byte; require(sscanf(line+j*2, "%2x", &byte) == 1, "bad hex"); q->name[j] = byte;
        }
        require(sscanf(tab+1, "%d\t%" SCNx64, &q->status, &q->mask) == 2, "bad oracle");
    }
    fclose(f); require(query_count > 0, "no queries");
}
static int compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b; return (x > y) - (x < y);
}
static void cost(const char *run_id) {
    long input_rss = rss(); uint64_t start = now();
    Snapshot *old = build(1, input_count, 0); require(old != NULL, "old build failed");
    uint64_t old_ns = now()-start; check(old); size_t old_bytes = live_bytes;
    long old_rss = rss(); start = now();
    unsigned saved = 2;
    Snapshot *candidate = build(saved, input_count, 0); require(candidate != NULL, "new build failed");
    uint64_t new_ns = now()-start; check(candidate); check(old);
    size_t coexist_bytes = live_bytes; long coexist_rss = rss();
    Snapshot *active = candidate; start = now(); destroy(old);
    uint64_t retired_ns = now()-start; long active_rss = rss();
    size_t before = calls; uint64_t checksum = 0;
    for (size_t i = 0; i < query_count; i++) {
        uint64_t mask; start = now(); lookup(active, &queries[i], &mask);
        samples[i] = now()-start; checksum ^= mask;
    }
    start = now();
    for (unsigned r = 0; r < 20; r++) for (size_t i = 0; i < query_count; i++) {
        uint64_t mask; lookup(active, &queries[i], &mask); checksum += mask;
    }
    uint64_t batch_ns = now()-start; require(calls == before, "timed query allocated");
    qsort(samples, query_count, sizeof(*samples), compare);
    struct rusage usage; getrusage(RUSAGE_SELF, &usage);
    size_t active_bytes = live_bytes; destroy(active); require(!live_bytes && !live_count, "final leak");
    printf("{\"run_id\":\"%s\",\"mode\":\"cost\",\"entries\":%zu,\"queries\":%zu,"
           "\"old_build_ns\":%"PRIu64",\"new_build_ns\":%"PRIu64",\"retire_ns\":%"PRIu64","
           "\"input_rss_kib\":%ld,\"old_rss_kib\":%ld,\"coexist_rss_kib\":%ld,\"active_rss_kib\":%ld,"
           "\"peak_rss_kib\":%ld,\"old_bytes\":%zu,\"coexist_bytes\":%zu,\"active_bytes\":%zu,\"peak_bytes\":%zu,"
           "\"p50_ns\":%"PRIu64",\"p95_ns\":%"PRIu64",\"p99_ns\":%"PRIu64",\"batch_ns\":%"PRIu64","
           "\"batch_queries\":%zu,\"checksum\":%"PRIu64",\"query_allocations\":0,\"final_live\":0}\n",
           run_id,input_count,query_count,old_ns,new_ns,retired_ns,input_rss,old_rss,coexist_rss,active_rss,
           usage.ru_maxrss,old_bytes,coexist_bytes,active_bytes,peak_bytes,samples[query_count/2],
           samples[query_count*95/100],samples[query_count*99/100],batch_ns,query_count*20,checksum);
}
static void faults(const char *run_id, int exhaustive) {
    Snapshot *active = build(1,input_count,0); require(active != NULL,"old build"); check(active);
    Snapshot *identity = active; size_t baseline_bytes=live_bytes, baseline_count=live_count;
    calls=0; Snapshot *probe=build(2,input_count,0); require(probe != NULL,"count build");
    size_t total=calls; destroy(probe); unsigned saved=1; size_t rejected=0, tolerated=0;
    uint64_t start=now(), max_cleanup=0, max_attempt=0;
    size_t targeted[]={1,2,3,4,5,50,500,total/2,total,total+1,total+2};
    size_t attempts=exhaustive ? total+2 : sizeof(targeted)/sizeof(targeted[0]);
    for (size_t attempt=0; attempt<attempts; attempt++) {
        size_t point=exhaustive ? attempt+1 : targeted[attempt];
        saved++; calls=0; injected=0; fail_at=point<=total ? point : (point==total+1 ? 5 : 0);
        fail_continuously=point==total+1;
        uint64_t before_cleanup=cleanup_ns, before_attempt=now();
        Snapshot *candidate=build(saved,input_count,point==total+2);
        uint64_t attempt_ns=now()-before_attempt, reclaimed_ns=cleanup_ns-before_cleanup;
        if(attempt_ns>max_attempt) max_attempt=attempt_ns;
        if(reclaimed_ns>max_cleanup) max_cleanup=reclaimed_ns;
        /* A failed optional shrink may still yield a complete valid candidate. */
        if (candidate) { check(candidate); destroy(candidate); tolerated++; }
        else rejected++;
        require(point==total+2 || injected>0,"fault not reached");
        require(active==identity && active->version==1 && saved>active->version,"half publication");
        require(live_bytes==baseline_bytes && live_count==baseline_count,"failed build leaked");
        check(active);
    }
    fail_at=0; fail_continuously=0; calls=0; saved++;
    Snapshot *next=build(saved,input_count,0); require(next != NULL,"retry failed"); check(next);
    active=next; require(active!=identity && active->version==saved,"retry identity");
    check(identity); destroy(identity); check(active); destroy(active);
    require(!live_bytes && !live_count,"final leak");
    printf("{\"run_id\":\"%s\",\"mode\":\"%s\",\"entries\":%zu,\"queries\":%zu,"
           "\"allocation_points\":%zu,\"attempts\":%zu,\"rejected_builds\":%zu,\"tolerated_failures\":%zu,"
           "\"max_cleanup_ns\":%"PRIu64",\"max_attempt_ns\":%"PRIu64","
           "\"cleanup_ns\":%"PRIu64",\"elapsed_ns\":%"PRIu64",\"saved_version\":%u,"
           "\"active_version\":%u,\"old_preserved\":true,\"retry_published\":true,\"final_live\":0}\n",
           run_id,exhaustive ? "faults" : "targeted",input_count,query_count,total,attempts,rejected,tolerated,
           max_cleanup,max_attempt,cleanup_ns,now()-start,saved,saved);
}
static void exhaustion(const char *run_id) {
    strcpy(input[0].name,"seed.example.test"); input[0].exact=1;
    memcpy(queries[0].name,input[0].name,strlen(input[0].name)); queries[0].len=strlen(input[0].name);
    queries[0].mask=1; query_count=1;
    Snapshot *active=build(1,1,0); require(active!=NULL,"seed build"); check(active);
    Snapshot *identity=active; size_t baseline_bytes=live_bytes,baseline_count=live_count;
    for(size_t i=1;i<200;i++) { snprintf(input[i].name,sizeof(input[i].name),"x%zu.example.test",i); input[i].exact=4; }
    unsigned saved=2; uint64_t start=now(); Snapshot *candidate=build(saved,200,0);
    require(candidate==NULL && errno==ENOMEM,"actual exhaustion did not return ENOMEM");
    require(!strcmp(build_stage,"insert") && inserted>0,"exhaustion missed node growth");
    size_t failed_after=inserted;
    require(live_bytes==baseline_bytes && live_count==baseline_count,"exhaustion leak");
    require(active==identity && active->version==1,"exhaustion half publication"); check(active);
    uint64_t failure_ns=now()-start; saved=3; candidate=build(saved,1,0);
    require(candidate!=NULL,"exhaustion retry"); active=candidate; check(active); check(identity);
    destroy(identity); destroy(active); require(!live_bytes&&!live_count,"exhaustion final leak");
    printf("{\"run_id\":\"%s\",\"mode\":\"exhaustion\",\"failure_ns\":%"PRIu64","
           "\"cleanup_ns\":%"PRIu64",\"old_preserved\":true,\"saved_version\":3,\"active_version\":3,"
           "\"retry_published\":true,\"injected\":0,\"failed_after_inserts\":%zu,\"final_live\":0}\n",run_id,failure_ns,cleanup_ns,failed_after);
}
int main(int argc,char **argv) {
    require(argc==5,"usage: recovery cost|faults|exhaustion entries queries run-id");
    struct rlimit no_core={0,0}; setrlimit(RLIMIT_CORE,&no_core);
    int exhaust=!strcmp(argv[1],"exhaustion");
    require(clib_mem_init(NULL,exhaust ? 64<<10 : 256<<20)!=NULL,"heap initialization");
    if(exhaust) exhaustion(argv[4]);
    else { load(argv[2],argv[3]); if(!strcmp(argv[1],"cost")) cost(argv[4]);
           else { require(!strcmp(argv[1],"faults") || !strcmp(argv[1],"targeted"),"unknown mode");
                  faults(argv[4],!strcmp(argv[1],"faults")); } }
    return 0;
}
