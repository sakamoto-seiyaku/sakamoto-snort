/* E01 auxiliary API-cost sensitivity, not a packet-pipeline benchmark. */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

static volatile uint64_t sink;
static uint64_t cpu_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t)) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int main(void)
{
    const unsigned count = 1000000;
    puts("{\"kind\":\"auxiliary_clock_api_only\",\"iterations\":1000000,\"rounds\":[");
    for (unsigned round = 0; round < 7; ++round) {
        uint64_t start = cpu_ns();
        for (unsigned i = 0; i < count; ++i) sink += i;
        uint64_t empty = cpu_ns() - start;
        start = cpu_ns();
        for (unsigned i = 0; i < count; ++i) {
            struct timespec t;
            if (clock_gettime(CLOCK_REALTIME, &t)) return 1;
            sink += (uint64_t)t.tv_nsec;
        }
        uint64_t sampled = cpu_ns() - start;
        printf("%s{\"empty_cpu_ns\":%" PRIu64 ",\"sampled_cpu_ns\":%" PRIu64 "}",
               round ? ",\n" : "", empty, sampled);
    }
    puts("\n]}");
    return 0;
}
