/* E01 auxiliary API-cost sensitivity, not a packet-pipeline benchmark. */
#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile uint64_t sink;
static uint64_t cpu_ns(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t)) return 0;
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "now")) {
        struct timespec mono, wall;
        if (clock_gettime(CLOCK_MONOTONIC, &mono) || clock_gettime(CLOCK_REALTIME, &wall)) return 1;
        printf("{\"monotonic_ns\":%" PRIu64 ",\"realtime_ns\":%" PRIu64 "}\n",
            (uint64_t)mono.tv_sec * UINT64_C(1000000000) + (uint64_t)mono.tv_nsec,
            (uint64_t)wall.tv_sec * UINT64_C(1000000000) + (uint64_t)wall.tv_nsec);
        return 0;
    }
    if (argc != 1) return 2;
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
