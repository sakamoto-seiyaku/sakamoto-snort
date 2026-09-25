/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>

static uint64_t clock_ns(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}

static uint64_t signature(uint64_t value, const product_l4_policy_match_result_t *r) {
    const uint64_t fields[] = {r->evaluation, r->stage_verdict, r->action,
        r->no_match_reason, r->mode, r->actual_action, r->rule_id, r->reason_id,
        r->priority, r->order, r->winner_rank};
    for (unsigned i = 0; i < sizeof fields / sizeof fields[0]; ++i)
        value = (value ^ fields[i]) * UINT64_C(1099511628211);
    return value;
}

static product_l4_policy_packet_t packet(unsigned n) {
    static const uint16_t ports[] = {0, 1, 3, 6, 7, 15, 30, 31, 63, 65, 67,
                                    127, 1025, 2049, 4095, 8193, 32768, 65534, 65535};
    return (product_l4_policy_packet_t) {.uid = 17, .uid_known = 1, .family = 4,
        .protocol = 6, .direction = n % 2 ? 1 : 3, .direction_known = 1,
        .ports_available = n % 11 != 0, .source_port = ports[n % 19],
        .destination_port = ports[(n / 19) % 19], .ct_state = n % 3 + 1,
        .ct_state_known = n % 7 != 0};
}

int main(int argc, char **argv) {
    assert(argc == 6);
    unsigned shape = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned count = (unsigned)strtoul(argv[2], NULL, 10);
    unsigned path = (unsigned)strtoul(argv[3], NULL, 10);
    unsigned direct = (unsigned)strtoul(argv[4], NULL, 10);
    unsigned entries = (unsigned)strtoul(argv[5], NULL, 10);
    assert(shape < 5 && count && count <= 128 && path < 3);
    product_l4_policy_rule_t *rules = calloc(256, sizeof(*rules));
    product_l4_policy_rule_t *effective = calloc(256, sizeof(*effective));
    product_l4_policy_view_t *views = malloc(4 * sizeof(*views));
    assert(rules && effective && views);
    /* Materialize all four views and both arrays: old reader, inactive bank,
     * preflight and publication coexist while compiling the replacement. */
    memset(views, 0xa5, 4 * sizeof(*views));
    for (unsigned i = 0; i < count; ++i) {
        unsigned offset = shape < 3 ? 64 * i : 0;
        rules[i] = (product_l4_policy_rule_t) {.rule_id = 1000 + i, .uid = 17,
            .network_context_id = UINT32_MAX, .ifindex = UINT32_MAX, .family = 4,
            .protocol = 6, .priority = i % 3, .order = count - i, .reason_id = 100 + i,
            .source_port_first = offset + 1, .source_port_last = offset + (shape == 0 ? 1 : 6),
            .destination_port_first = 1, .destination_port_last = shape == 2 ? 30 : 6,
            .action = i % 2 ? 1 : 2, .mode = i % 3 == 0};
        if (shape >= 3) {
            rules[i].source_port_last = rules[i].destination_port_last = 65534;
            const uint8_t expression[] = {PRODUCT_EXPRESSION_CT_STATE, 2};
            memcpy(rules[i].expression, expression, sizeof expression);
            rules[i].expression_length = sizeof expression;
        }
        if (shape == 4) {
            rules[i].expression[rules[i].expression_length++] = PRODUCT_STATIC_NOT;
        }
    }
    memcpy(effective, rules, 256 * sizeof(*rules));
    product_l4_policy_compile_budget_t budget = product_l4_policy_default_budget();
    budget.direct_entries = path ? 0 : direct;
    budget.index_entries = entries;
    budget.factor_rules = path == 2 ? 0 : 128;
    for (unsigned i = 0; i < 4; ++i)
        assert(product_l4_policy_compile_with_budget(&views[i], effective, count, &budget) == 0);
    product_l4_policy_index_resources_t index;
    product_l4_policy_plan_resources_t plan;
    product_l4_policy_index_resources(&views[2], &index);
    product_l4_policy_plan_resources(&views[2], &plan);
    product_l4_policy_compile_budget_t exhausted = budget;
    exhausted.index_entries = count - 1;
    assert(product_l4_policy_compile_with_budget(&views[2], effective, count, &exhausted)
           == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    assert(!memcmp(&views[2], &views[0], sizeof(*views)));
    exhausted = budget; exhausted.condition_items = plan.condition_items - 1;
    assert(product_l4_policy_compile_with_budget(&views[2], effective, count, &exhausted)
           == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    assert(!memcmp(&views[2], &views[0], sizeof(*views)));
    exhausted = budget; exhausted.peak_bytes = plan.publication_peak_bytes - 1;
    assert(product_l4_policy_compile_with_budget(&views[2], effective, count, &exhausted)
           == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    assert(!memcmp(&views[2], &views[0], sizeof(*views)));

    uint64_t began = clock_ns();
    const unsigned compiles = 40, queries = 20000;
    for (unsigned n = 0; n < compiles; ++n)
        assert(product_l4_policy_compile_with_budget(&views[2], effective, count, &budget) == 0);
    uint64_t compile_ns = clock_ns() - began;
    uint64_t hash = UINT64_C(14695981039346656037), work = 0;
    began = clock_ns();
    for (unsigned n = 0; n < queries; ++n) {
        product_l4_policy_packet_t p = packet(n);
        product_l4_policy_match_result_t result;
        assert(product_l4_policy_match(&views[2], &p, &result) == 0);
        hash = signature(hash, &result);
        unsigned actual = result.probes + result.key_probes + result.subtable_probes + result.subject_probes;
        assert(actual <= index.max_query_work);
        work += actual;
    }
    uint64_t query_ns = clock_ns() - began;
    /* The untouched old reader gives the same complete results after all
     * successor compilation and failure cases, with no reused query state. */
    uint64_t old_hash = UINT64_C(14695981039346656037);
    for (unsigned n = 0; n < queries; ++n) {
        product_l4_policy_packet_t p = packet(n);
        product_l4_policy_match_result_t result;
        assert(product_l4_policy_match(&views[0], &p, &result) == 0);
        old_hash = signature(old_hash, &result);
    }
    assert(old_hash == hash);
    struct rusage usage;
    assert(getrusage(RUSAGE_SELF, &usage) == 0);
    /* Linux rusage high-water can retain the fork/exec launcher's high-water.
     * /proc reports this executable's current address-space high-water. */
    unsigned long vm_hwm = 0, vm_rss = 0;
    FILE *memory = fopen("/proc/self/status", "r");
    assert(memory);
    char line[256];
    while (fgets(line, sizeof line, memory)) {
        unsigned long value;
        if (sscanf(line, "VmHWM: %lu kB", &value) == 1) vm_hwm = value;
        if (sscanf(line, "VmRSS: %lu kB", &value) == 1) vm_rss = value;
    }
    assert(fclose(memory) == 0 && vm_hwm >= vm_rss && vm_rss);

    printf("{\"shape\":%u,\"rules\":%u,\"path\":%u,\"direct_limit\":%u,\"entry_budget\":%u,"
        "\"signature\":\"%016" PRIx64 "\",\"compile_ns\":%" PRIu64 ",\"compiles\":%u,"
        "\"query_ns\":%" PRIu64 ",\"queries\":%u,\"work\":%" PRIu64 ","
        "\"direct\":%u,\"factorized\":%u,\"residual\":%u,\"conditions\":%u,"
        "\"entries\":%u,\"masks\":%u,\"view_bytes\":%zu,\"materialized_view_bytes\":%zu,"
        "\"query_state_bytes\":%u,\"compile_scratch_bytes\":%u,\"publication_peak_bytes\":%u,"
        "\"management_peak_bytes\":%u,\"process_maxrss_kib\":%lu,\"process_rss_kib\":%lu,\"rusage_maxrss_kib\":%ld}\n",
        shape, count, path, direct, entries, hash, compile_ns, compiles, query_ns, queries, work,
        plan.direct_rules, plan.factorized_rules, plan.residual_rules, plan.condition_items,
        index.entries, index.subtables, sizeof(*views), 4 * sizeof(*views),
        plan.query_state_bytes, plan.compile_scratch_bytes, plan.publication_peak_bytes,
        product_rule_config_compile_peak_bytes(), vm_hwm, vm_rss, usage.ru_maxrss);
    free(views); free(effective); free(rules);
    return 0;
}
