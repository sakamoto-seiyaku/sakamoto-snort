/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <errno.h>

/* Link-time random provider replacement is test-only. It exercises the public
 * creation operation under zero and retained-identity collisions. */
static const uint64_t random_values[] = {
    0, UINT64_C(0x123456789abc0000), UINT64_C(0x123456789abc0000), UINT64_C(0x23456789abcd0000)};
static unsigned random_at;
ssize_t __real_getrandom(void *, size_t, unsigned);
ssize_t __wrap_getrandom(void *buffer, size_t length, unsigned flags) {
    if (random_at < sizeof(random_values) / sizeof(random_values[0])) {
        assert(length == sizeof(uint64_t));
        memcpy(buffer, &random_values[random_at++], length);
        return (ssize_t)length;
    }
    return __real_getrandom(buffer, length, flags);
}

static int fail_directory_sync;
int __real_fsync(int);
int __wrap_fsync(int fd) {
    struct stat st;
    if (fail_directory_sync && fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

typedef struct {
    product_l4_policy_view_t view;
    uint64_t revision;
    unsigned publications;
    int reject;
} runtime_t;

static uint32_t publish(void *opaque, uint64_t revision, uint64_t hash,
                        const product_l4_policy_rule_t *rule, uint32_t count) {
    runtime_t *runtime = opaque;
    assert(hash != 0);
    if (runtime->reject)
        return 1;
    assert(product_l4_policy_compile(&runtime->view, rule, count) == PRODUCT_L4_POLICY_STATUS_OK);
    runtime->revision = revision;
    runtime->publications++;
    return 0;
}

static void ordinary_network_disable(void) {
    random_at = 0; /* deterministic creation identities for hand-decided Rank ties */
    char directory[] = "/tmp/sakamoto-network-disable-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema = 1, .operation = 3, .expected_saved_revision = 1, .count = 1,
        .rules = {{.uid = 12345, .network_context = 1, .ifindex = UINT32_MAX,
                   .direction = 3, .action = 2,
                   .source_port_last = 65535, .destination_port_last = 65535}}};
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.count == 1 && status.rules[0].priority == 0);
    product_l4_policy_packet_t packet = {.uid = 12345, .uid_known = 1,
        .network_context_id = 1, .network_context_known = 1,
        .direction = 3, .direction_known = 1, .family = 6, .protocol = 58};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[0].version && match.actual_action == 2);
    packet.network_context_id = 2;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(!match.rule_id);
    /* An ordinary allow exception wins the priority/order tie by logical ID.
     * Moving only its order behind the disable reverses the actual winner. */
    sakamoto_product_rule_config_request_t exception = {
        .schema = 1, .operation = 2, .expected_saved_revision = status.saved_revision,
        .count = 2};
    exception.rules[0] = status.rules[0];
    exception.rules[1] = status.rules[0];
    exception.rules[1].version = UINT64_C(65537);
    exception.rules[1].action = 1;
    assert(product_rule_config_replace(config, &exception, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    packet.network_context_id = 1;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == UINT64_C(65537) && match.action == 1 && match.actual_action == 1);
    exception.expected_saved_revision = status.saved_revision;
    exception.rules[1].version = 0;
    exception.rules[1].base_version = UINT64_C(65537);
    exception.rules[1].order = 1;
    assert(product_rule_config_replace(config, &exception, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[0].version && match.actual_action == 2);
    exception.expected_saved_revision = status.saved_revision;
    exception.count = 1;
    assert(product_rule_config_replace(config, &exception, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    /* Shared group observes DROP; the direct switch wins while present. */
    sakamoto_product_rule_config_request_t grouped = {
        .schema = 1, .operation = 2, .expected_saved_revision = status.saved_revision,
        .count = 2, .graph = {.group_count = 1, .edge_count = 1, .binding_count = 2,
            .groups = {10}, .edges = {{10, 1, 1}},
            .bindings = {{1, 12345, 2, 10, 1}, {2, 23456, 2, 10, 0}}}};
    grouped.rules[0] = status.rules[0];
    grouped.rules[1] = status.rules[0];
    grouped.rules[1].version = 0; grouped.rules[1].uid = UINT32_MAX;
    grouped.rules[1].priority = UINT32_MAX;
    assert(product_rule_config_replace(config, &grouped, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    packet.network_context_id = 1;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[0].version && match.actual_action == 2);
    packet.uid = 23456;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[1].version && match.actual_action == 2);
    uint64_t shared_version = status.rules[1].version;
    packet.uid = 12345;
    request.expected_saved_revision = status.saved_revision;
    request.rules[0].action = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.count == 1 && status.active_count == 2);
    assert(status.graph.edges[0].target == 0 && status.rules[0].version == shared_version);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == shared_version && match.action == 2 && match.actual_action == 1);
    /* Ordinary complete editing can promote an allow exception ahead of fallback. */
    grouped.expected_saved_revision = status.saved_revision;
    grouped.graph = status.graph;
    grouped.rules[0] = status.rules[0];
    grouped.rules[1] = request.rules[0];
    grouped.rules[1].priority = 10; grouped.rules[1].action = 1;
    assert(product_rule_config_replace(config, &grouped, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[1].version && match.actual_action == 1);
    product_rule_config_close(config);
    unlink(path); rmdir(directory);
}

static void network_disable_scope_and_failures(void) {
    char directory[] = "/tmp/sakamoto-network-scope-XXXXXX";
    assert(mkdtemp(directory));
    char path[256]; snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema = 1, .operation = 3, .expected_saved_revision = 1, .count = 1,
        .rules = {{.uid = 12345, .network_context = 1, .ifindex = 7,
            .family = 4, .protocol = 0, .direction = 3, .action = 2,
            .source_prefix = 24, .destination_prefix = 24,
            .source_address = {192,0,2}, .destination_address = {198,51,100},
            .source_port_first = 0, .source_port_last = 0,
            .destination_port_first = 0, .destination_port_last = 65535}}};
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    uint64_t version = status.rules[0].version, revision = status.saved_revision;
    request.expected_saved_revision = revision;
    unsigned publications = runtime.publications;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == revision && status.rules[0].version == version &&
           runtime.publications == publications);
    product_l4_policy_packet_t packet = {.uid = 12345, .uid_known = 1,
        .network_context_id = 1, .network_context_known = 1, .ifindex = 7, .ifindex_known = 1,
        .family = 4, .protocol = 17, .direction = 3, .direction_known = 1,
        .ports_available = 1, .source_port = 0, .destination_port = 443,
        .source_address = {192,0,2,1}, .destination_address = {198,51,100,2}};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == version && match.actual_action == 2);
    for (unsigned outside = 0; outside < 13; ++outside) {
        product_l4_policy_packet_t other = packet;
        switch (outside) {
        case 0: other.uid++; break;
        case 1: other.uid_known = 0; break;
        case 2: other.network_context_id = 2; break;
        case 3: other.network_context_known = 0; break;
        case 4: other.ifindex = 8; break;
        case 5: other.ifindex_known = 0; break;
        case 6: other.direction = 1; break;
        case 7: other.direction_known = 0; break;
        case 8: other.source_address[2] = 3; break;
        case 9: other.destination_address[2] = 101; break;
        case 10: other.source_port = 1; break;
        case 11: other.ports_available = 0; break;
        case 12: other.protocol = 1; break; /* ICMP has no port zero predicate. */
        }
        assert(product_l4_policy_match(&runtime.view, &other, &match) == 0);
        assert(!match.rule_id && match.stage_verdict == PRODUCT_L4_POLICY_VERDICT_PASS_NEXT);
    }
    request.expected_saved_revision--;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_CONFLICT);
    request.expected_saved_revision++;
    /* An ordinary source is editable and referencable, never a protected kind. */
    sakamoto_product_rule_config_request_t full = {.schema = 1, .operation = 2,
        .expected_saved_revision = revision, .count = 1,
        .graph = {.group_count = 1, .edge_count = 1, .groups = {10}, .edges = {{10,1,0}}}};
    full.rules[0] = status.rules[0];
    assert(product_rule_config_replace(config, &full, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    request.expected_saved_revision = status.saved_revision;
    request.rules[0].action = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_REFERENCE);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == request.expected_saved_revision && status.rules[0].version == version);
    full.expected_saved_revision = status.saved_revision;
    full.graph = (sakamoto_product_rule_graph_t){0};
    full.count = 2; full.rules[1] = full.rules[0]; full.rules[1].version = 0;
    assert(product_rule_config_replace(config, &full, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    request.expected_saved_revision = status.saved_revision;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_CONFLICT);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.count == 2 && status.rules[0].protocol == 0);
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    product_rule_config_close(config); unlink(path); rmdir(directory);
}

static void reusable_groups(void) {
    char directory[] = "/tmp/sakamoto-rule-groups-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema = 1,
        .operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL,
        .expected_saved_revision = 1,
        .count = 1,
        .rules = {{.uid = UINT32_MAX,
                   .family = 4,
                   .protocol = 17,
                   .action = 2,
                   .network_context = UINT32_MAX,
                   .ifindex = UINT32_MAX,
                   .source_port_last = 65535,
                   .destination_port_last = 65535}},
        .graph = {.group_count = 2,
                  .edge_count = 3,
                  .binding_count = 3,
                  .groups = {10, 20},
                  .edges = {{10, 1, 0}, {20, 2, 10}, {20, 1, 0}},
                  .bindings = {{1, 12345, 2, 20, 0}, {2, 23456, 2, 20, 1}, {3, 12345, 1, 0, 0}}}};
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.count == 1 && status.active_count == 2);
    assert(status.graph.group_count == 2 && status.graph.binding_count == 3);
    for (unsigned i = 0; i < 2; ++i) {
        product_l4_policy_packet_t packet = {
            .uid = i ? 23456 : 12345, .uid_known = 1, .family = 4, .protocol = 17};
        product_l4_policy_match_result_t match;
        assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
        assert(match.rule_id == status.rules[0].version && match.candidate_count == 1);
        assert(match.action == 2 && match.mode == i && match.actual_action == (i ? 1 : 2));
        assert(match.stage_verdict == (i ? 0 : 1));
    }
    request.expected_saved_revision = status.saved_revision;
    request.rules[0] = status.rules[0];
    unsigned publications = runtime.publications;
    request.graph.bindings[2].mode = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_MODE_CONFLICT);
    product_rule_config_query(config, &status);
    assert(status.error_index == UINT32_MAX && runtime.publications == publications);
    request.graph.bindings[2].mode = 0;
    request.graph.edges[0].target = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_REFERENCE);
    request.graph.edges[0].target = 0;
    request.graph.edges[0].kind = 2;
    request.graph.edges[0].target = 20;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_CYCLE);
    request.graph.edges[0] = (sakamoto_product_group_edge_t){10, 1, 0};
    request.graph.group_count = 9;
    request.graph.edge_count = 8;
    for (unsigned i = 0; i < 9; ++i)
        request.graph.groups[i] = (i + 1) * 10;
    for (unsigned i = 0; i < 8; ++i)
        request.graph.edges[i] = (sakamoto_product_group_edge_t){(i + 1) * 10, 2, (i + 2) * 10};
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_LIMIT);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == request.expected_saved_revision &&
           runtime.publications == publications);
    request.graph = status.graph;
    /* Same contents, different identity: both remain candidates; no group winner. */
    request.count = 2;
    request.rules[1] = request.rules[0];
    request.rules[1].version = 0;
    request.graph.edges[3] = (sakamoto_product_group_edge_t){20, 1, 1};
    request.graph.edge_count = 4;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.active_count == 4 && status.count == 2);
    product_l4_policy_packet_t packet = {.uid = 12345, .uid_known = 1, .family = 4, .protocol = 17};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    uint64_t winner = status.rules[0].version < status.rules[1].version ? status.rules[0].version
                                                                        : status.rules[1].version;
    assert(match.rule_id == winner && match.candidate_count == 2 && match.action == 2);
    /* A binding-only update preserves rule identity and changes actual action. */
    request.expected_saved_revision = status.saved_revision;
    memcpy(request.rules, status.rules, sizeof(request.rules));
    request.graph.bindings[0].mode = request.graph.bindings[2].mode = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == winner && match.action == 2 && match.actual_action == 1);
    product_rule_config_query(config, &status);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.graph.edge_count == 4 && status.graph.bindings[1].mode == 1);
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void graph_resource_boundaries(void) {
    char directory[] = "/tmp/sakamoto-group-limits-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {.schema = 1,
                                                      .operation = 2,
                                                      .expected_saved_revision = 1,
                                                      .count = 1,
                                                      .rules = {{.uid = UINT32_MAX,
                                                                 .family = 4,
                                                                 .protocol = 17,
                                                                 .action = 2,
                                                                 .network_context = UINT32_MAX,
                                                                 .ifindex = UINT32_MAX,
                                                                 .source_port_last = 65535,
                                                                 .destination_port_last = 65535}},
                                                      .graph = {.group_count = 8,
                                                                .edge_count = 8,
                                                                .binding_count = 1,
                                                                .bindings = {{1, 12345, 2, 1, 0}}}};
    for (unsigned i = 0; i < 8; ++i) {
        request.graph.groups[i] = i + 1;
        request.graph.edges[i] =
            (sakamoto_product_group_edge_t){i + 1, i == 7 ? 1 : 2, i == 7 ? 0 : i + 2};
    }
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.active_count == 1 && status.graph.group_count == 8);
    request.rules[0] = status.rules[0];
    request.expected_saved_revision = status.saved_revision;
    memset(&request.graph, 0, sizeof(request.graph));
    request.graph.group_count = 2;
    request.graph.groups[0] = 1;
    request.graph.groups[1] = 2;
    request.graph.binding_count = 1;
    request.graph.bindings[0] = (sakamoto_product_rule_binding_t){1, 12345, 2, 1, 0};
    /* Exactly 4096 traversed references: root + 63*(child+63 leaves) + 63 leaves.
     * The 4032 repeated leaf paths still compile to one candidate. */
    for (unsigned i = 0; i < 63; ++i) {
        request.graph.edges[request.graph.edge_count++] = (sakamoto_product_group_edge_t){1, 2, 2};
        request.graph.edges[request.graph.edge_count++] = (sakamoto_product_group_edge_t){2, 1, 0};
        request.graph.edges[request.graph.edge_count++] = (sakamoto_product_group_edge_t){1, 1, 0};
    }
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.active_count == 1);
    request.expected_saved_revision = status.saved_revision;
    request.graph.edges[request.graph.edge_count++] = (sakamoto_product_group_edge_t){1, 1, 0};
    unsigned publications = runtime.publications;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_LIMIT);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == request.expected_saved_revision &&
           status.active_revision == status.saved_revision);
    assert(status.graph.edge_count == 189 && runtime.publications == publications);
    product_l4_policy_packet_t packet = {.uid = 12345, .uid_known = 1, .family = 4, .protocol = 17};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[0].version && match.candidate_count == 1 &&
           match.actual_action == 2);
    /* Effective-view capacity is a save-success/compile-failure, not truncation. */
    memset(&request.graph, 0, sizeof(request.graph));
    request.graph.group_count = 1;
    request.graph.groups[0] = 1;
    request.graph.edge_count = 2;
    request.graph.edges[0] = (sakamoto_product_group_edge_t){1, 1, 0};
    request.graph.edges[1] = (sakamoto_product_group_edge_t){1, 1, 1};
    request.count = 2;
    request.rules[1] = request.rules[0];
    request.rules[1].version = 0;
    request.graph.binding_count = 65;
    for (unsigned i = 0; i < 65; ++i)
        request.graph.bindings[i] = (sakamoto_product_rule_binding_t){i + 1, 12345 + i, 2, 1, 0};
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == request.expected_saved_revision + 1 &&
           status.active_revision == request.expected_saved_revision);
    assert(status.graph.binding_count == 65 && status.active_count == 1 &&
           runtime.publications == publications);
    assert(status.compiler_status == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.graph.binding_count == 65 && status.count == 2 && !status.active_revision);
    assert(product_rule_config_activate(config, publish, &runtime) == SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void ordinary_group_fallback(void) {
    char directory[] = "/tmp/sakamoto-group-fallback-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t legacy = {
        .schema = 1,
        .operation = 1,
        .expected_saved_revision = 1,
        .rule = {.present = 1, .uid = UINT32_MAX, .protocol = 17, .action = 2}};
    assert(product_rule_config_replace(config, &legacy, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_INVALID);

    sakamoto_product_rule_config_request_t request = {.schema = 1,
                                                      .operation = 2,
                                                      .expected_saved_revision = 1,
                                                      .count = 2,
                                                      .graph = {.group_count = 1,
                                                                .groups = {1},
                                                                .edge_count = 2,
                                                                .edges = {{1, 1, 1}, {1, 1, 0}},
                                                                .binding_count = 1,
                                                                .bindings = {{1, 12345, 2, 1, 0}}}};
    request.rules[0] = (sakamoto_product_direct_rule_t){.uid = UINT32_MAX,
                                                        .family = 4,
                                                        .protocol = 17,
                                                        .action = 1,
                                                        .network_context = UINT32_MAX,
                                                        .ifindex = UINT32_MAX,
                                                        .source_port_last = 65535,
                                                        .destination_port_first = 443,
                                                        .destination_port_last = 443};
    request.rules[1] = request.rules[0];
    request.rules[1].action = 2;
    request.rules[1].priority = UINT32_MAX;
    request.rules[1].destination_port_first = 0;
    request.rules[1].destination_port_last = 65535;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    product_l4_policy_packet_t packet = {.uid = 12345,
                                         .uid_known = 1,
                                         .family = 4,
                                         .protocol = 17,
                                         .ports_available = 1,
                                         .destination_port = 443};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0 &&
           match.rule_id == status.rules[0].version && match.actual_action == 1);
    packet.destination_port = 444;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0 &&
           match.rule_id == status.rules[1].version && match.actual_action == 2);
    packet.uid = 23456;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0 && !match.rule_id &&
           match.stage_verdict == PRODUCT_L4_POLICY_VERDICT_PASS_NEXT);
    request.expected_saved_revision = status.saved_revision;
    memcpy(request.rules, status.rules, sizeof(request.rules));
    /* Invalid unbound groups cannot hide behind application applicability. */
    request.graph.group_count = 3;
    request.graph.groups[1] = 2;
    request.graph.groups[2] = 3;
    request.graph.edge_count = 4;
    request.graph.edges[2] = (sakamoto_product_group_edge_t){2, 2, 3};
    request.graph.edges[3] = (sakamoto_product_group_edge_t){3, 2, 2};
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_CYCLE);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void legacy_source_rejects_reusable_uid(void) {
    char directory[] = "/tmp/sakamoto-legacy-uid-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    FILE *f = fopen(path, "w");
    assert(
        f &&
        fputs(
            "sakamoto-rule-config/1\n1 65537\n1 4294967295 17 3 2 32000 40608\n7f000001 7f000002\n",
            f) >= 0);
    assert(fclose(f) == 0);
    product_rule_config_t *config = product_rule_config_open(path);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.save_error == SAKAMOTO_RULE_CONFIG_INVALID && !status.saved_revision);
    product_rule_config_close(config);
    /* V2 direct sources also cannot reinterpret an invalid UID as reusable. */
    unsigned char raw[144] = {0};
    memcpy(raw, "SKRULE02", 8);
    raw[8] = 1;
    raw[16] = 1;
    raw[20] = 1;
    raw[24] = raw[26] = raw[32] = raw[34] = 1;
    memset(raw + 48, 255, 12);
    raw[68] = 4;
    raw[72] = 17;
    raw[76] = 3;
    raw[80] = 2;
    f = fopen(path, "wb");
    assert(f && fwrite(raw, 1, sizeof(raw), f) == sizeof(raw) && fclose(f) == 0);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.save_error == SAKAMOTO_RULE_CONFIG_INVALID && !status.saved_revision);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void complete_configuration(void) {
    char directory[] = "/tmp/sakamoto-rule-full-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {.schema = 1,
                                                      .operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL,
                                                      .expected_saved_revision = 1,
                                                      .count = 2};
    for (unsigned i = 0; i < 2; ++i) {
        request.rules[i].uid = 12345;
        request.rules[i].family = i ? 6 : 4;
        request.rules[i].protocol = i ? 6 : 17;
        request.rules[i].direction = 3;
        request.rules[i].action = 2;
        request.rules[i].network_context = request.rules[i].ifindex = UINT32_MAX;
        request.rules[i].source_port_last = 65535;
        request.rules[i].destination_port_first = 40000;
        request.rules[i].destination_port_last = 41000;
    }
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.count == 2 && status.active_count == 2);
    assert(status.rules[0].version == UINT64_C(0x123456789abc0001));
    assert(status.rules[1].version == UINT64_C(0x23456789abcd0001));
    assert(random_at == 4);
    assert(status.saved_revision == status.active_revision);
    for (unsigned i = 0; i < 2; ++i) {
        product_l4_policy_packet_t packet = {.uid = 12345,
                                             .uid_known = 1,
                                             .family = i ? 6 : 4,
                                             .protocol = i ? 6 : 17,
                                             .direction = 3,
                                             .direction_known = 1,
                                             .ports_available = 1,
                                             .source_port = 32000,
                                             .destination_port = 40608};
        product_l4_policy_match_result_t match;
        assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
        assert(match.rule_id == status.rules[i].version && match.action == 2);
    }
    uint64_t revision = status.saved_revision, version = status.rules[0].version;
    request.expected_saved_revision = revision;
    request.rules[1].source_prefix = 129;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_INVALID);
    product_rule_config_query(config, &status);
    assert(status.error_index == 1 && status.saved_revision == revision);
    memcpy(request.rules, status.rules, sizeof(request.rules));
    unsigned publications = runtime.publications;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == revision && runtime.publications == publications);
    request.rules[0].action = 1; /* Explicit import cannot rebind the full ID. */
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_CONFLICT);
    request.rules[0].base_version = version;
    request.rules[0].version = 0;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.rules[0].version == version + 1 &&
           status.rules[1].version == request.rules[1].version);
    request.expected_saved_revision = status.saved_revision;
    memcpy(request.rules, status.rules, sizeof(request.rules));
    request.rules[0].version = (version & ~UINT64_C(65535)) | 65535;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    request.expected_saved_revision = status.saved_revision;
    request.rules[0].base_version = request.rules[0].version;
    request.rules[0].version = 0;
    request.rules[0].action = 2;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_EXHAUSTED);
    memcpy(request.rules, status.rules, sizeof(request.rules));
    request.rules[1] = request.rules[0];
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_CONFLICT);
    /* Complete source exceeds the compiler's existing 128-rule capacity. */
    request.count = 129;
    for (unsigned i = 0; i < request.count; ++i) {
        request.rules[i] = status.rules[1];
        request.rules[i].version = 0;
        request.rules[i].uid = 10000 + i;
    }
    uint64_t active = status.active_revision;
    publications = runtime.publications;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(status.count == 129 && status.active_revision == active &&
           status.saved_revision == active + 1);
    assert(status.compiler_status == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    assert(runtime.publications == publications && runtime.view.rule_count == 2);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.count == 129 && status.active_revision == 0 && status.save_error == 0);
    /* A new process has no old in-memory snapshot to rescue readiness. */
    memset(&runtime, 0, sizeof(runtime));
    uint64_t saved_revision = status.saved_revision;
    uint64_t saved_version = status.rules[0].version;
    assert(product_rule_config_activate(config, publish, &runtime) == SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(status.compile_error == SAKAMOTO_RULE_CONFIG_COMPILE);
    assert(status.saved_revision == saved_revision && status.active_revision == 0);
    assert(status.count == 129 && status.rules[0].version == saved_version);
    assert(runtime.publications == 0 && runtime.revision == 0);
    request.expected_saved_revision = saved_revision;
    memcpy(request.rules, status.rules, sizeof(request.rules));
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == saved_revision && status.count == 129);
    assert(status.active_revision == 0 && runtime.publications == 0);
    request.expected_saved_revision = status.saved_revision;
    request.count = 2;
    memcpy(request.rules, status.rules, sizeof(request.rules));
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.active_count == 2 && status.active_revision == status.saved_revision);
    assert(status.saved_revision == saved_revision + 1 && status.rules[0].version == saved_version);
    assert(runtime.publications == 1 && !status.compile_error);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void platform_conditions(void) {
    char directory[] = "/tmp/sakamoto-rule-platform-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema = 1,
        .operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL,
        .expected_saved_revision = 1,
        .count = 1,
        .rules = {{.uid = 12345,
                   .family = 6,
                   .protocol = 6,
                   .direction = 1,
                   .action = 2,
                   .network_context = 2,
                   .ifindex = 7,
                   .priority = 9,
                   .order = 4,
                   .source_prefix = 64,
                   .destination_prefix = 64,
                   .source_address = {0x20, 1, 0xd, 0xb8},
                   .destination_address = {0x20, 1, 0xd, 0xb8, 0, 1},
                   .source_port_first = 100,
                   .source_port_last = 200,
                   .destination_port_first = 443,
                   .destination_port_last = 443}}};
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    product_l4_policy_packet_t packet = {
        .uid = 12345,
        .uid_known = 1,
        .family = 6,
        .protocol = 6,
        .direction = 1,
        .direction_known = 1,
        .network_context_id = 2,
        .network_context_known = 1,
        .ifindex = 7,
        .ifindex_known = 1,
        .source_address = {0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
        .destination_address = {0x20, 1, 0xd, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2},
        .ports_available = 1,
        .source_port = 150,
        .destination_port = 443};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.rules[0].version && match.priority == 9 && match.order == 4 &&
           match.action == 2);
    product_l4_policy_packet_t missing = packet;
    missing.network_context_known = 0;
    assert(product_l4_policy_match(&runtime.view, &missing, &match) == 0 && !match.rule_id);
    missing = packet;
    missing.ifindex_known = 0;
    assert(product_l4_policy_match(&runtime.view, &missing, &match) == 0 && !match.rule_id);
    missing = packet;
    missing.direction = 3;
    assert(product_l4_policy_match(&runtime.view, &missing, &match) == 0 && !match.rule_id);
    missing = packet;
    missing.ports_available = 0;
    assert(product_l4_policy_match(&runtime.view, &missing, &match) == 0 && !match.rule_id);
    missing = packet;
    missing.source_port = 201;
    assert(product_l4_policy_match(&runtime.view, &missing, &match) == 0 && !match.rule_id);
    missing = packet;
    missing.source_address[4] = 1;
    assert(product_l4_policy_match(&runtime.view, &missing, &match) == 0 && !match.rule_id);
    uint64_t deleted_version = status.rules[0].version;
    /* Deletion cannot make a retained complete ID acquire new content. */
    request.expected_saved_revision = status.saved_revision;
    request.count = 0;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    request.expected_saved_revision = status.saved_revision;
    request.count = 1;
    request.rules[0].version = deleted_version;
    request.rules[0].action = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_CONFLICT);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void uncertain_durability(void) {
    char directory[] = "/tmp/sakamoto-rule-durability-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    fail_directory_sync = 1;
    product_rule_config_t *config = product_rule_config_open(path);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 1 && status.active_revision == 0 &&
           status.save_error == SAKAMOTO_RULE_CONFIG_DURABILITY_UNCERTAIN);
    runtime_t runtime = {0};
    assert(product_rule_config_activate(config, publish, &runtime) != 0 &&
           runtime.publications == 0);
    fail_directory_sync = 0;
    product_rule_config_t *reopened = product_rule_config_open(path);
    sakamoto_product_rule_config_status_t disk;
    product_rule_config_query(reopened, &disk);
    assert(disk.saved_revision == status.saved_revision && disk.save_error == 0);
    product_rule_config_close(config);
    config = reopened;
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    sakamoto_product_rule_config_request_t request = {.schema = 1,
                                                      .operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL,
                                                      .expected_saved_revision = 1,
                                                      .count = 1,
                                                      .rules = {{.uid = 12345,
                                                                 .family = 4,
                                                                 .protocol = 17,
                                                                 .action = 2,
                                                                 .source_port_last = 65535,
                                                                 .destination_port_last = 65535,
                                                                 .network_context = UINT32_MAX,
                                                                 .ifindex = UINT32_MAX}}};
    fail_directory_sync = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) != 0);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 2 && status.active_revision == 1 && status.count == 1 &&
           status.save_error == SAKAMOTO_RULE_CONFIG_DURABILITY_UNCERTAIN);
    assert(runtime.publications == 1 && runtime.view.rule_count == 0);
    fail_directory_sync = 0;
    reopened = product_rule_config_open(path);
    product_rule_config_query(reopened, &disk);
    assert(disk.saved_revision == status.saved_revision &&
           disk.rules[0].version == status.rules[0].version && !disk.save_error);
    request.expected_saved_revision = status.saved_revision;
    request.rules[0] = status.rules[0];
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 2 && status.active_revision == 2 && status.save_error == 0);
    product_rule_config_close(reopened);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void legacy_source_migration(void) {
    char directory[] = "/tmp/sakamoto-rule-migrate-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    FILE *file = fopen(path, "w");
    assert(file);
    assert(fputs("sakamoto-rule-config/1\n12 18364758544493051906\n1 12345 17 3 2 32000 "
                 "40608\n7f000001 7f000002\n",
                 file) >= 0);
    assert(fclose(file) == 0);
    product_rule_config_t *config = product_rule_config_open(path);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 12 && status.count == 1 && status.save_error == 0);
    assert(status.rules[0].version == UINT64_C(0xfedcba9876540002));
    runtime_t runtime = {0};
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    sakamoto_product_rule_config_request_t request = {.schema = 1,
                                                      .operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL,
                                                      .expected_saved_revision = 12,
                                                      .count = 1};
    request.rules[0] = status.rules[0];
    request.rules[0].base_version = request.rules[0].version;
    request.rules[0].version = 0;
    request.rules[0].action = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 13 && status.count == 1 && status.save_error == 0);
    assert(status.rules[0].version == UINT64_C(0xfedcba9876540003) && status.rules[0].action == 1);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
}

static void static_expression_save_and_publish(int dynamic) {
    char directory[] = "/tmp/sakamoto-expression-XXXXXX";
    assert(mkdtemp(directory));
    char path[256]; snprintf(path, sizeof path, "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema = 1, .operation = 2, .expected_saved_revision = 1, .count = 1,
        .rules = {{.version = 0x12340001, .uid = 7, .network_context = UINT32_MAX,
            .ifindex = UINT32_MAX, .action = 2, .source_port_last = 65535,
            .destination_port_last = 65535, .expression_length = 5,
            .expression = {12, 255, 255, 255, 255}}}};
    if (dynamic) memcpy(request.rules[0].expression, (uint8_t[]){13,2,14,2,1},5);
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_l4_policy_packet_t packet = {.uid=7, .uid_known=1, .family=4, .protocol=17,
        .ports_available=1, .destination_port=65535, .ct_state=2, .ct_state_known=1,
        .flow_direction=2, .flow_direction_known=1};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == 0x12340001 && match.actual_action == 2);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 2 && status.active_revision == 2);
    assert(product_l4_policy_requires_flow(&runtime.view,7)==dynamic);
    assert(!product_l4_policy_requires_flow(&runtime.view,8));
    product_rule_config_close(config); config=product_rule_config_open(path);
    assert(product_rule_config_activate(config,publish,&runtime)==0);
    product_rule_config_query(config,&status);
    assert(status.rules[0].expression_length==5);
    assert(!memcmp(status.rules[0].expression,request.rules[0].expression,5));
    assert(product_l4_policy_requires_flow(&runtime.view,7)==dynamic);
    request.expected_saved_revision = 2;
    request.rules[0].expression[1] = dynamic ? 1 : 254;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_CONFLICT);
    request.rules[0].version = 0;
    request.rules[0].base_version = status.rules[0].version;
    /* Malformed NOT, oversized bytes and dirty unused bytes never save. */
    request.rules[0].expression_length = 1;
    memset(request.rules[0].expression, 0, 64); request.rules[0].expression[0] = 3;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_INVALID);
    request.rules[0].expression_length = 65;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_INVALID);
    request.rules[0].expression_length = 2;
    request.rules[0].expression[0] = 4; request.rules[0].expression[1] = 4;
    request.rules[0].expression[63] = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_INVALID);
    request.rules[0].expression[63] = 0;
    /* A valid depth-nine source is saved, compilation refuses it, and the
     * previously published complete rule keeps winning. */
    request.rules[0].expression_length = 10;
    memset(request.rules[0].expression + 2, 3, 8);
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 3 && status.active_revision == 2);
    assert(status.rules[0].version == 0x12340002 && status.error_index == 0);
    assert(status.compiler_status == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    assert(runtime.publications == 2);
    assert(product_l4_policy_requires_flow(&runtime.view,7)==dynamic);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0 && match.rule_id == 0x12340001);
    product_rule_config_close(config); config = product_rule_config_open(path);
    assert(product_rule_config_activate(config, publish, &runtime) == SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 3 && status.active_revision == 0);
    request.expected_saved_revision = 3; request.rules[0].base_version = 0x12340002;
    request.rules[0].expression_length = 9; request.rules[0].expression[9] = 0;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.active_revision == 4 && status.rules[0].version == 0x12340003);
    product_rule_config_close(config); config = product_rule_config_open(path);
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.rules[0].expression_length == 9 && status.active_revision == 4);
    assert(memcmp(status.rules[0].expression, request.rules[0].expression, 64) == 0);
    product_rule_config_close(config); unlink(path); rmdir(directory);
}

static void ct_publication_failure(void) {
    char directory[] = "/tmp/sakamoto-ct-publish-XXXXXX";
    assert(mkdtemp(directory));
    char path[256]; snprintf(path, sizeof path, "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema=1, .operation=2, .expected_saved_revision=1, .count=1,
        .rules={{.version=0x56780001, .uid=17, .network_context=UINT32_MAX,
            .ifindex=UINT32_MAX, .action=2, .source_port_last=65535,
            .destination_port_last=65535, .expression_length=2, .expression={13,2}}}};
    assert(product_rule_config_replace(config,&request,publish,&runtime)==0);
    product_l4_policy_view_t old=runtime.view;
    request.expected_saved_revision=2;request.rules[0].base_version=0x56780001;
    request.rules[0].version=0;request.rules[0].action=1;
    request.rules[0].expression_length=0;memset(request.rules[0].expression,0,64);
    runtime.reject=1;
    assert(product_rule_config_replace(config,&request,publish,&runtime)==SAKAMOTO_RULE_CONFIG_PUBLISH);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config,&status);
    assert(status.saved_revision==3 && status.active_revision==2 && !status.rules[0].expression_length);
    assert(!memcmp(&old,&runtime.view,sizeof old) && product_l4_policy_requires_flow(&runtime.view,17));
    product_l4_policy_packet_t packet={.uid=17,.uid_known=1,.family=4,.ct_state=2,.ct_state_known=1};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view,&packet,&match)==0 && match.rule_id==0x56780001 && match.actual_action==2);
    runtime.reject=0;
    assert(product_rule_config_activate(config,publish,&runtime)==0);
    assert(!product_l4_policy_requires_flow(&runtime.view,17));
    assert(product_l4_policy_match(&runtime.view,&packet,&match)==0 && match.actual_action==1);
    product_rule_config_close(config);unlink(path);rmdir(directory);
}

static void large_plan_save_failure(void) {
    char directory[] = "/tmp/sakamoto-factor-config-XXXXXX";
    assert(mkdtemp(directory));
    char path[256]; snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    runtime_t runtime = {0};
    sakamoto_product_rule_config_request_t request = {
        .schema = 1, .operation = 2, .expected_saved_revision = 1, .count = 128};
    for (unsigned i = 0; i < 129; ++i)
        request.rules[i] = (sakamoto_product_direct_rule_t) {
            .version = ((uint64_t)(1000 + i) << 16) | 1, .uid = 17,
            .network_context = UINT32_MAX, .ifindex = UINT32_MAX,
            .family = 4, .protocol = 6, .priority = i + 1, .action = 2,
            .source_port_first = 1, .source_port_last = 65534,
            .destination_port_first = 1, .destination_port_last = 65534};
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_l4_policy_plan_resources_t plan;
    product_l4_policy_plan_resources(&runtime.view, &plan);
    assert(plan.factorized_rules == 128 && !plan.direct_rules && !plan.residual_rules);
    assert(product_rule_config_compile_peak_bytes() >= plan.publication_peak_bytes);
    assert(product_rule_config_compile_peak_bytes() <= PRODUCT_RULE_CONFIG_COMPILE_MEMORY_LIMIT);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    uint64_t old_version = status.rules[0].version, old_revision = status.active_revision;
    product_l4_policy_packet_t packet = {.uid = 17, .uid_known = 1, .family = 4,
        .protocol = 6, .ports_available = 1, .source_port = 32768, .destination_port = 32768};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == old_version && match.winner_rank == 1 && match.actual_action == 2);
    request.expected_saved_revision = status.saved_revision;
    request.count = 129;
    request.rules[0].base_version = old_version; request.rules[0].version = 0;
    request.rules[0].action = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) == SAKAMOTO_RULE_CONFIG_COMPILE);
    product_rule_config_query(config, &status);
    assert(!status.save_error && status.compiler_status == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED);
    assert(status.count == 129 && status.saved_revision == old_revision + 1);
    assert(status.active_revision == old_revision && status.active_count == 128);
    assert(status.rules[0].version == old_version + 1 && status.rules[0].action == 1);
    assert(runtime.publications == 1 && runtime.revision == old_revision);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == old_version && match.winner_rank == 1 && match.actual_action == 2);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.count == 129 && status.rules[0].version == old_version + 1 && status.rules[0].action == 1);
    assert(status.saved_revision == old_revision + 1);
    request.expected_saved_revision = status.saved_revision; request.count = 128;
    memcpy(request.rules, status.rules, sizeof(request.rules));
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == old_version + 1 && match.winner_rank == 1 && match.actual_action == 1);
    product_rule_config_close(config); unlink(path); rmdir(directory);
}

int main(void) {
    large_plan_save_failure();
    ct_publication_failure();
    static_expression_save_and_publish(0);
    static_expression_save_and_publish(1);
    complete_configuration();
    network_disable_scope_and_failures();
    ordinary_network_disable();
    reusable_groups();
    graph_resource_boundaries();
    ordinary_group_fallback();
    legacy_source_rejects_reusable_uid();
    platform_conditions();
    uncertain_durability();
    legacy_source_migration();
    char directory[] = "/tmp/sakamoto-rule-config-XXXXXX";
    assert(mkdtemp(directory));
    char path[256];
    snprintf(path, sizeof(path), "%s/rules", directory);
    product_rule_config_t *config = product_rule_config_open(path);
    assert(config);
    runtime_t runtime = {0};
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 1 && status.active_revision == 1);
    assert(status.saved_rule_version == 0 && !status.rule.present);
    assert(status.save_error == 0 && status.compile_error == 0);
    assert(runtime.publications == 1 && runtime.view.rule_count == 0);
    sakamoto_product_rule_config_request_t request = {
        .schema = 1,
        .operation = SAKAMOTO_RULE_CONFIG_REPLACE,
        .expected_saved_revision = 1,
        .rule = {.present = 1,
                 .uid = 12345,
                 .protocol = 17,
                 .direction = 3,
                 .action = 2,
                 .source_port = 32000,
                 .destination_port = 40608,
                 .source_address = {127, 0, 0, 1},
                 .destination_address = {127, 0, 0, 2}}};
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 2 && status.active_revision == 2);
    assert((status.saved_rule_version >> 16) != 0);
    assert((status.saved_rule_version & 65535) == 1);
    assert(status.active_rule_version == status.saved_rule_version);
    assert(runtime.view.rule_count == 1);
    product_l4_policy_packet_t packet = {.uid = 12345,
                                         .uid_known = 1,
                                         .family = 4,
                                         .protocol = 17,
                                         .direction = 3,
                                         .direction_known = 1,
                                         .ports_available = 1,
                                         .source_port = 32000,
                                         .destination_port = 40608,
                                         .source_address = {127, 0, 0, 1},
                                         .destination_address = {127, 0, 0, 2}};
    product_l4_policy_match_result_t match;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.saved_rule_version && match.action == 2);
    assert(match.stage_verdict == PRODUCT_L4_POLICY_VERDICT_DROP);
    product_rule_config_close(config);
    config = product_rule_config_open(path);
    assert(config);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 2 && status.active_revision == 0);
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == status.saved_rule_version && match.action == 2);
    uint64_t first_version = status.saved_rule_version;
    request.expected_saved_revision = 2;
    request.rule.protocol = 1;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_UNSUPPORTED);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 3 && status.active_revision == 2);
    assert(status.saved_rule_version == first_version + 1);
    assert(status.active_rule_version == first_version);
    assert(status.rule.protocol == 1 && status.save_error == 0);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.rule_id == first_version && match.action == 2);
    request.rule.protocol = 17;
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_CONFLICT);
    request.expected_saved_revision = 3;
    request.rule.action = 1;
    struct rlimit previous, limited;
    assert(getrlimit(RLIMIT_FSIZE, &previous) == 0);
    limited = previous;
    limited.rlim_cur = 16;
    void (*old_signal)(int) = signal(SIGXFSZ, SIG_IGN);
    assert(setrlimit(RLIMIT_FSIZE, &limited) == 0);
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_IO);
    assert(setrlimit(RLIMIT_FSIZE, &previous) == 0);
    signal(SIGXFSZ, old_signal);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 3 && status.active_revision == 2);
    assert(status.rule.protocol == 1 && status.save_error != 0);
    product_rule_config_t *readback = product_rule_config_open(path);
    sakamoto_product_rule_config_status_t saved;
    product_rule_config_query(readback, &saved);
    assert(saved.saved_revision == 3 && saved.rule.protocol == 1 && saved.save_error == 0);
    product_rule_config_close(readback);
    assert(product_rule_config_replace(config, &request, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 4 && status.active_revision == 4);
    assert(status.saved_rule_version == first_version + 2);
    assert(!status.save_error && !status.compile_error);
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.action == 1 && match.rule_id == first_version + 2);
    packet.destination_port++;
    assert(product_l4_policy_match(&runtime.view, &packet, &match) == 0);
    assert(match.evaluation == PRODUCT_L4_POLICY_EVALUATION_NO_MATCH);
    runtime.reject = 1;
    request.expected_saved_revision = 4;
    memset(&request.rule, 0, sizeof(request.rule));
    assert(product_rule_config_replace(config, &request, publish, &runtime) ==
           SAKAMOTO_RULE_CONFIG_PUBLISH);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 5 && status.active_revision == 4);
    assert(!status.rule.present && status.active_rule_version == first_version + 2);
    runtime.reject = 0;
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    product_rule_config_query(config, &status);
    assert(status.active_revision == 5 && !status.active_rule_version);
    product_rule_config_close(config);
    FILE *broken = fopen(path, "w");
    assert(broken && fputs("broken source\n", broken) >= 0 && fclose(broken) == 0);
    config = product_rule_config_open(path);
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 0 && status.active_revision == 0 && status.save_error);
    unsigned publications = runtime.publications;
    assert(product_rule_config_activate(config, publish, &runtime) != 0);
    assert(runtime.publications == publications);
    product_rule_config_close(config);
    unlink(path);
    rmdir(directory);
    puts("rule configuration: empty, exact UDP, reload, separate saved/active failures, recovery");
    return 0;
}
