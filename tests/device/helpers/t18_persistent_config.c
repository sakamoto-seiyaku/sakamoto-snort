/* SPDX-License-Identifier: Apache-2.0 */
/* Test-only persistent Product VAPI client. The first connect happens before
 * the reader hold; subsequent complete list replacements use that session. */
#include "sakamoto_product_abi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *step, uint32_t code, const sakamoto_product_rule_config_status_t *status) {
    fprintf(stderr, "%s code=%u result=%u saved=%llu active=%llu\n", step, code,
            status ? status->result : 0,
            (unsigned long long)(status ? status->saved_revision : 0),
            (unsigned long long)(status ? status->active_revision : 0));
    exit(1);
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    uint64_t generation = strtoull(argv[2], NULL, 10);
    sakamoto_product_bytes_t socket = {(const uint8_t *)argv[1], (uint32_t)strlen(argv[1])};
    sakamoto_product_session_t *session = NULL;
    sakamoto_product_status_t connection = {0};
    uint32_t code = sakamoto_product_session_connect(socket, generation, &session, &connection);
    if (code || !session) fail("connect", code, NULL);
    sakamoto_product_rule_config_request_t *request = calloc(1, sizeof *request);
    sakamoto_product_rule_config_status_t *status = calloc(1, sizeof *status);
    sakamoto_product_domains_t *original = calloc(1, sizeof *original);
    if (!request || !status || !original) fail("allocation", 2, NULL);
    request->schema = SAKAMOTO_RULE_CONFIG_SCHEMA;
    request->operation = SAKAMOTO_RULE_CONFIG_QUERY;
    code = sakamoto_product_session_rule_config(session, generation, request, status);
    if (code || status->result || !status->active_revision ||
        status->domains.list_count != 3 || status->domains.entry_count != 6)
        fail("query", code, status);
    *original = status->domains;
    printf("ready revision=%llu entries=%u\n", (unsigned long long)status->active_revision,
           status->domains.entry_count);
    fflush(stdout);
    char line[32];
    while (fgets(line, sizeof line, stdin)) {
        int without = !strcmp(line, "without-exact\n");
        if (!without && strcmp(line, "full\n")) fail("command", 1, status);
        memset(request, 0, sizeof *request);
        request->schema = SAKAMOTO_RULE_CONFIG_SCHEMA;
        request->operation = SAKAMOTO_RULE_CONFIG_REPLACE_ALL;
        request->expected_saved_revision = status->saved_revision;
        request->count = status->count;
        memcpy(request->rules, status->rules, status->count * sizeof status->rules[0]);
        request->graph = status->graph;
        request->domains = *original;
        if (without) {
            request->domains.entry_count = 0;
            for (unsigned i = 0; i < original->entry_count; ++i)
                if (original->entries[i].list != 0)
                    request->domains.entries[request->domains.entry_count++] = original->entries[i];
            memset(request->domains.entries + request->domains.entry_count, 0,
                   (SAKAMOTO_DOMAIN_MAX_ENTRIES - request->domains.entry_count) * sizeof request->domains.entries[0]);
        }
        code = sakamoto_product_session_rule_config(session, generation, request, status);
        if (code || status->result || status->saved_revision != status->active_revision)
            fail("replace", code, status);
        printf("applied revision=%llu saved=%llu result=%u entries=%u\n",
               (unsigned long long)status->active_revision,
               (unsigned long long)status->saved_revision, status->result,
               status->domains.entry_count);
        fflush(stdout);
    }
    free(original); free(status); free(request);
    code = sakamoto_product_session_disconnect(session);
    if (code) return (int)code;
    return (int)sakamoto_product_session_destroy(session);
}
