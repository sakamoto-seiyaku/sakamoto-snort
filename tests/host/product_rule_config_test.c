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
    assert(fputs("sakamoto-rule-config/1\n12 18364758544493051906\n1 12345 17 3 2 32000 40608\n7f000001 7f000002\n", file) >= 0);
    assert(fclose(file) == 0);
    product_rule_config_t *config = product_rule_config_open(path);
    sakamoto_product_rule_config_status_t status;
    product_rule_config_query(config, &status);
    assert(status.saved_revision == 12 && status.count == 1 && status.save_error == 0);
    assert(status.rules[0].version == UINT64_C(0xfedcba9876540002));
    runtime_t runtime = {0};
    assert(product_rule_config_activate(config, publish, &runtime) == 0);
    sakamoto_product_rule_config_request_t request = {
        .schema = 1, .operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL,
        .expected_saved_revision = 12, .count = 1
    };
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
    unlink(path); rmdir(directory);
}

int main(void) {
    complete_configuration();
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
