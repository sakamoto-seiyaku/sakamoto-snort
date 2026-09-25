/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "product_rule_config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <unistd.h>

#define SOURCE_BYTES                                                                               \
    (36 + 8 * SAKAMOTO_RULE_CONFIG_MAX_IDENTITIES + 180 * SAKAMOTO_RULE_CONFIG_MAX_RULES +         \
     4 * SAKAMOTO_RULE_CONFIG_MAX_GROUPS + 12 * SAKAMOTO_RULE_CONFIG_MAX_EDGES +                   \
     20 * SAKAMOTO_RULE_CONFIG_MAX_BINDINGS)
struct product_rule_config {
    char *path;
    sakamoto_product_rule_config_status_t state;
    uint32_t retained_count;
    uint64_t retained[SAKAMOTO_RULE_CONFIG_MAX_IDENTITIES];
};

/* The encoding has explicit widths and byte order, no native structure padding.
 * Retained values are identity high-water marks, never old rule conditions. */
static void put(uint8_t **at, uint64_t value, unsigned width) {
    for (unsigned i = 0; i < width; ++i) {
        *(*at)++ = value & 255;
        value >>= 8;
    }
}
static uint64_t get(const uint8_t **at, unsigned width) {
    uint64_t value = 0;
    for (unsigned i = 0; i < width; ++i)
        value |= (uint64_t) * (*at)++ << (8 * i);
    return value;
}
#define RULE_FIELDS(F)                                                                             \
    F(uid)                                                                                         \
    F(network_context)                                                                             \
    F(ifindex)                                                                                     \
    F(priority) F(order) F(family) F(protocol) F(direction) F(action) F(source_prefix)             \
        F(destination_prefix) F(source_port_first) F(source_port_last) F(destination_port_first)   \
            F(destination_port_last) F(reserved)
static size_t encode(const product_rule_config_t *config, uint8_t *bytes) {
    uint8_t *at = bytes;
    memcpy(at, "SKRULE04", 8);
    at += 8;
    put(&at, config->state.saved_revision, 8);
    put(&at, config->state.count, 4);
    put(&at, config->retained_count, 4);
    for (unsigned i = 0; i < config->retained_count; ++i)
        put(&at, config->retained[i], 8);
    for (unsigned i = 0; i < config->state.count; ++i) {
        const sakamoto_product_direct_rule_t *r = &config->state.rules[i];
        put(&at, r->version, 8);
        put(&at, 0, 8);
#define WRITE(field) put(&at, r->field, 4);
        RULE_FIELDS(WRITE)
#undef WRITE
        memcpy(at, r->source_address, 16);
        at += 16;
        memcpy(at, r->destination_address, 16);
        at += 16;
        put(&at, r->expression_length, 4);
        memcpy(at, r->expression, 64);
        at += 64;
    }
    const sakamoto_product_rule_graph_t *g = &config->state.graph;
    put(&at, g->group_count, 4);
    put(&at, g->edge_count, 4);
    put(&at, g->binding_count, 4);
    for (unsigned i = 0; i < g->group_count; ++i)
        put(&at, g->groups[i], 4);
    for (unsigned i = 0; i < g->edge_count; ++i) {
        put(&at, g->edges[i].group, 4);
        put(&at, g->edges[i].kind, 4);
        put(&at, g->edges[i].target, 4);
    }
    for (unsigned i = 0; i < g->binding_count; ++i) {
        const sakamoto_product_rule_binding_t *b = &g->bindings[i];
        put(&at, b->id, 4);
        put(&at, b->uid, 4);
        put(&at, b->kind, 4);
        put(&at, b->target, 4);
        put(&at, b->mode, 4);
    }
    return (size_t)(at - bytes);
}
static void project(sakamoto_product_rule_config_status_t *s) {
    memset(&s->rule, 0, sizeof(s->rule));
    s->saved_rule_version = s->count ? s->rules[0].version : 0;
    s->active_rule_version = s->active_count ? s->active_versions[0] : 0;
    if (s->count == 1) {
        const sakamoto_product_direct_rule_t *r = &s->rules[0];
        s->rule.present = 1;
        s->rule.uid = r->uid;
        s->rule.protocol = r->protocol;
        s->rule.direction = r->direction;
        s->rule.action = r->action;
        s->rule.source_port = r->source_port_first;
        s->rule.destination_port = r->destination_port_first;
        memcpy(s->rule.source_address, r->source_address, 4);
        memcpy(s->rule.destination_address, r->destination_address, 4);
    }
}
static int valid_version(uint64_t version) {
    return (version >> 16) != 0 && (version & UINT16_MAX) != 0;
}
static int valid_rule(const sakamoto_product_direct_rule_t *r) {
    if (r->reserved || (r->family != 0 && r->family != 4 && r->family != 6) ||
        r->protocol > 255 || (r->direction != 0 && r->direction != 1 && r->direction != 3) ||
        (r->action != 1 && r->action != 2) || r->source_prefix > (r->family == 4 ? 32U : 128U) ||
        r->destination_prefix > (r->family == 4 ? 32U : 128U) ||
        r->source_port_first > r->source_port_last || r->source_port_last > 65535 ||
        r->destination_port_first > r->destination_port_last || r->destination_port_last > 65535)
        return 0;
    if ((!r->family && (r->source_prefix || r->destination_prefix ||
                        memcmp(r->source_address, (uint8_t[16]){0}, 16) ||
                        memcmp(r->destination_address, (uint8_t[16]){0}, 16))))
        return 0;
    if (r->family == 4)
        for (unsigned i = 4; i < 16; ++i)
            if (r->source_address[i] || r->destination_address[i])
                return 0;
    if (product_static_expression_validate(r->expression, r->expression_length) ==
        PRODUCT_L4_POLICY_STATUS_INVALID_RULE) return 0;
    for (unsigned i = r->expression_length; i < 64; ++i)
        if (r->expression[i]) return 0;
    return 1;
}
static int same_content(const sakamoto_product_direct_rule_t *a,
                        const sakamoto_product_direct_rule_t *b) {
#define SAME(field)                                                                                \
    if (a->field != b->field)                                                                      \
        return 0;
    RULE_FIELDS(SAME)
#undef SAME
    if (a->expression_length != b->expression_length ||
        memcmp(a->expression, b->expression, 64)) return 0;
    return memcmp(a->source_address, b->source_address, 16) == 0 &&
           memcmp(a->destination_address, b->destination_address, 16) == 0;
}
static int retained_index(const product_rule_config_t *c, uint64_t version) {
    for (unsigned i = 0; i < c->retained_count; ++i)
        if ((c->retained[i] >> 16) == (version >> 16))
            return (int)i;
    return -1;
}
static const sakamoto_product_direct_rule_t *current_rule(const product_rule_config_t *c,
                                                          uint64_t version) {
    for (unsigned i = 0; i < c->state.count; ++i)
        if ((c->state.rules[i].version >> 16) == (version >> 16))
            return &c->state.rules[i];
    return NULL;
}
static void legacy_rule(sakamoto_product_direct_rule_t *out,
                        const sakamoto_product_config_rule_t *in) {
    memset(out, 0, sizeof(*out));
    out->uid = in->uid;
    out->family = 4;
    out->protocol = in->protocol;
    out->direction = in->direction;
    out->action = in->action;
    out->network_context = PRODUCT_L4_POLICY_NETWORK_CONTEXT_ANY;
    out->ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
    out->source_prefix = out->destination_prefix = 32;
    out->source_port_first = out->source_port_last = in->source_port;
    out->destination_port_first = out->destination_port_last = in->destination_port;
    memcpy(out->source_address, in->source_address, 4);
    memcpy(out->destination_address, in->destination_address, 4);
}
static uint32_t load_v1(product_rule_config_t *c, const uint8_t *bytes, size_t length) {
    if (length >= 512)
        return SAKAMOTO_RULE_CONFIG_INVALID;
    char text[512], canonical[512];
    memcpy(text, bytes, length);
    text[length] = 0;
    unsigned long long revision, version;
    unsigned a[8];
    int end = 0;
    sakamoto_product_config_rule_t r = {0};
    int fields = sscanf(
        text,
        "sakamoto-rule-config/1\n%llu %llu\n%u %u %u %u %u %u %u\n%2x%2x%2x%2x %2x%2x%2x%2x\n%n",
        &revision, &version, &r.present, &r.uid, &r.protocol, &r.direction, &r.action,
        &r.source_port, &r.destination_port, &a[0], &a[1], &a[2], &a[3], &a[4], &a[5], &a[6], &a[7],
        &end);
    if (fields != 17 || end != (int)length || !revision || r.present > 1 ||
        (version && !valid_version(version)) || (r.present && !version))
        return SAKAMOTO_RULE_CONFIG_INVALID;
    for (unsigned i = 0; i < 4; ++i) {
        r.source_address[i] = a[i];
        r.destination_address[i] = a[i + 4];
    }
    int n =
        snprintf(canonical, sizeof(canonical),
                 "sakamoto-rule-config/1\n%llu %llu\n%u %u %u %u %u %u %u\n%02x%02x%02x%02x "
                 "%02x%02x%02x%02x\n",
                 revision, version, r.present, r.uid, r.protocol, r.direction, r.action,
                 r.source_port, r.destination_port, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    if (n != (int)length || memcmp(canonical, bytes, length))
        return SAKAMOTO_RULE_CONFIG_INVALID;
    if (r.present) {
        legacy_rule(&c->state.rules[0], &r);
        c->state.rules[0].version = version;
        if (r.uid == UINT32_MAX || !valid_rule(&c->state.rules[0]))
            return SAKAMOTO_RULE_CONFIG_INVALID;
    } else {
        sakamoto_product_config_rule_t empty = {0};
        if (memcmp(&r, &empty, sizeof(r)))
            return SAKAMOTO_RULE_CONFIG_INVALID;
    }
    c->state.saved_revision = revision;
    c->state.count = r.present;
    if (version) {
        c->retained_count = 1;
        c->retained[0] = version;
    }
    project(&c->state);
    return 0;
}
static int group_index(const sakamoto_product_rule_graph_t *g, uint32_t id) {
    for (unsigned i = 0; i < g->group_count; ++i)
        if (g->groups[i] == id)
            return (int)i;
    return -1;
}
/* Bounded DFS retains all source paths in the saved graph, while membership
 * deduplicates only the emitted rule/application view. */
static uint32_t members(const sakamoto_product_rule_config_status_t *s, uint32_t kind,
                        uint32_t target, uint32_t *stack, unsigned depth, unsigned *steps,
                        uint8_t *selected) {
    if (++*steps > SAKAMOTO_RULE_CONFIG_MAX_EXPANSION)
        return SAKAMOTO_RULE_CONFIG_LIMIT;
    if (kind == SAKAMOTO_RULE_CONFIG_RULE) {
        if (target >= s->count)
            return SAKAMOTO_RULE_CONFIG_REFERENCE;
        selected[target] = 1;
        return 0;
    }
    if (kind != SAKAMOTO_RULE_CONFIG_GROUP || group_index(&s->graph, target) < 0)
        return SAKAMOTO_RULE_CONFIG_REFERENCE;
    for (unsigned i = 0; i < depth; ++i)
        if (stack[i] == target)
            return SAKAMOTO_RULE_CONFIG_CYCLE;
    if (depth == SAKAMOTO_RULE_CONFIG_MAX_DEPTH)
        return SAKAMOTO_RULE_CONFIG_LIMIT;
    stack[depth] = target;
    for (unsigned i = 0; i < s->graph.edge_count; ++i) {
        const sakamoto_product_group_edge_t *e = &s->graph.edges[i];
        if (e->group == target) {
            uint32_t error = members(s, e->kind, e->target, stack, depth + 1, steps, selected);
            if (error)
                return error;
        }
    }
    return 0;
}
static uint32_t select_members(const sakamoto_product_rule_config_status_t *s, uint32_t kind,
                               uint32_t target, uint8_t *selected) {
    uint32_t stack[SAKAMOTO_RULE_CONFIG_MAX_DEPTH];
    unsigned steps = 0;
    memset(selected, 0, SAKAMOTO_RULE_CONFIG_MAX_RULES);
    return members(s, kind, target, stack, 0, &steps, selected);
}
static uint32_t validate_graph(const sakamoto_product_rule_config_status_t *s) {
    const sakamoto_product_rule_graph_t *g = &s->graph;
    if (g->group_count > SAKAMOTO_RULE_CONFIG_MAX_GROUPS ||
        g->edge_count > SAKAMOTO_RULE_CONFIG_MAX_EDGES ||
        g->binding_count > SAKAMOTO_RULE_CONFIG_MAX_BINDINGS)
        return SAKAMOTO_RULE_CONFIG_LIMIT;
    uint8_t selected[SAKAMOTO_RULE_CONFIG_MAX_RULES];
    for (unsigned i = 0; i < g->group_count; ++i) {
        if (!g->groups[i])
            return SAKAMOTO_RULE_CONFIG_INVALID;
        for (unsigned j = 0; j < i; ++j)
            if (g->groups[j] == g->groups[i])
                return SAKAMOTO_RULE_CONFIG_CONFLICT;
        uint32_t error = select_members(s, 2, g->groups[i], selected);
        if (error)
            return error;
    }
    for (unsigned i = 0; i < g->edge_count; ++i)
        if (group_index(g, g->edges[i].group) < 0)
            return SAKAMOTO_RULE_CONFIG_REFERENCE;
    uint8_t selections[SAKAMOTO_RULE_CONFIG_MAX_BINDINGS][SAKAMOTO_RULE_CONFIG_MAX_RULES];
    for (unsigned i = 0; i < g->binding_count; ++i) {
        const sakamoto_product_rule_binding_t *b = &g->bindings[i];
        if (!b->id || b->uid == UINT32_MAX || b->mode > 1)
            return SAKAMOTO_RULE_CONFIG_INVALID;
        uint8_t *bound = selections[i];
        uint32_t error = select_members(s, b->kind, b->target, bound);
        if (error)
            return error;
        for (unsigned r = 0; r < s->count; ++r)
            if (bound[r] && b->mode && s->rules[r].uid == b->uid)
                return SAKAMOTO_RULE_CONFIG_MODE_CONFLICT;
        for (unsigned j = 0; j < i; ++j) {
            const sakamoto_product_rule_binding_t *prior = &g->bindings[j];
            if (prior->id == b->id)
                return SAKAMOTO_RULE_CONFIG_CONFLICT;
            if (prior->uid != b->uid || prior->mode == b->mode)
                continue;
            for (unsigned r = 0; r < s->count; ++r)
                if (bound[r] && selections[j][r])
                    return SAKAMOTO_RULE_CONFIG_MODE_CONFLICT;
        }
    }
    return 0;
}
static uint32_t decode(product_rule_config_t *c, const uint8_t *bytes, size_t length) {
    int v4 = length >= 8 && !memcmp(bytes, "SKRULE04", 8);
    int v3 = v4 || (length >= 8 && !memcmp(bytes, "SKRULE03", 8));
    if (length < 8 || (!v3 && memcmp(bytes, "SKRULE02", 8)))
        return load_v1(c, bytes, length);
    if (length < 24)
        return SAKAMOTO_RULE_CONFIG_INVALID;
    const uint8_t *at = bytes + 8;
    uint64_t revision = get(&at, 8);
    uint32_t count = get(&at, 4), retained = get(&at, 4);
    if (!revision || count > SAKAMOTO_RULE_CONFIG_MAX_RULES ||
        retained > SAKAMOTO_RULE_CONFIG_MAX_IDENTITIES ||
        length < 24 + 8 * (size_t)retained + (v4 ? 180 : 112) * (size_t)count)
        return SAKAMOTO_RULE_CONFIG_INVALID;
    for (unsigned i = 0; i < retained; ++i) {
        uint64_t version = get(&at, 8);
        if (!valid_version(version) || retained_index(c, version) >= 0)
            return SAKAMOTO_RULE_CONFIG_INVALID;
        c->retained[c->retained_count++] = version;
    }
    for (unsigned i = 0; i < count; ++i) {
        sakamoto_product_direct_rule_t *r = &c->state.rules[i];
        r->version = get(&at, 8);
        r->base_version = get(&at, 8);
#define READ(field) r->field = get(&at, 4);
        RULE_FIELDS(READ)
#undef READ
        memcpy(r->source_address, at, 16);
        at += 16;
        memcpy(r->destination_address, at, 16);
        at += 16;
        if (v4) {
            r->expression_length = get(&at, 4);
            memcpy(r->expression, at, 64); at += 64;
        }
        int index = retained_index(c, r->version);
        if ((!v3 && r->uid == UINT32_MAX) || !valid_rule(r) || r->base_version ||
            !valid_version(r->version) || index < 0 || c->retained[index] != r->version)
            return SAKAMOTO_RULE_CONFIG_INVALID;
        for (unsigned j = 0; j < i; ++j)
            if ((c->state.rules[j].version >> 16) == (r->version >> 16))
                return SAKAMOTO_RULE_CONFIG_INVALID;
    }
    c->state.count = count;
    if (v3) {
        if ((size_t)(bytes + length - at) < 12)
            return SAKAMOTO_RULE_CONFIG_INVALID;
        sakamoto_product_rule_graph_t *g = &c->state.graph;
        g->group_count = get(&at, 4);
        g->edge_count = get(&at, 4);
        g->binding_count = get(&at, 4);
        if (g->group_count > SAKAMOTO_RULE_CONFIG_MAX_GROUPS ||
            g->edge_count > SAKAMOTO_RULE_CONFIG_MAX_EDGES ||
            g->binding_count > SAKAMOTO_RULE_CONFIG_MAX_BINDINGS ||
            (size_t)(bytes + length - at) !=
                4U * g->group_count + 12U * g->edge_count + 20U * g->binding_count)
            return SAKAMOTO_RULE_CONFIG_INVALID;
        for (unsigned i = 0; i < g->group_count; ++i)
            g->groups[i] = get(&at, 4);
        for (unsigned i = 0; i < g->edge_count; ++i) {
            g->edges[i].group = get(&at, 4);
            g->edges[i].kind = get(&at, 4);
            g->edges[i].target = get(&at, 4);
        }
        for (unsigned i = 0; i < g->binding_count; ++i) {
            sakamoto_product_rule_binding_t *b = &g->bindings[i];
            b->id = get(&at, 4);
            b->uid = get(&at, 4);
            b->kind = get(&at, 4);
            b->target = get(&at, 4);
            b->mode = get(&at, 4);
        }
        uint32_t error = validate_graph(&c->state);
        if (error)
            return error;
    }
    if (at != bytes + length)
        return SAKAMOTO_RULE_CONFIG_INVALID;
    c->state.saved_revision = revision;
    project(&c->state);
    return 0;
}
static uint32_t load_source(product_rule_config_t *c) {
    int fd = open(c->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return SAKAMOTO_RULE_CONFIG_IO;
    struct stat st;
    uint8_t *bytes = malloc(SOURCE_BYTES);
    size_t length = 0;
    int valid = bytes && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
                st.st_size <= SOURCE_BYTES;
    while (valid && length < (size_t)st.st_size) {
        ssize_t n = read(fd, bytes + length, (size_t)st.st_size - length);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            valid = 0;
            break;
        }
        length += (size_t)n;
    }
    close(fd);
    uint32_t result = valid ? decode(c, bytes, length) : SAKAMOTO_RULE_CONFIG_IO;
    free(bytes);
    if (result) {
        memset(&c->state, 0, sizeof(c->state));
        c->retained_count = 0;
    }
    return result;
}
static uint32_t save_source(product_rule_config_t *config, const product_rule_config_t *candidate) {
    uint8_t *bytes = malloc(SOURCE_BYTES);
    size_t path_size = strlen(config->path) + 16;
    char *temporary = malloc(path_size), *parent = strdup(config->path);
    if (!bytes || !temporary || !parent) {
        free(bytes);
        free(temporary);
        free(parent);
        return SAKAMOTO_RULE_CONFIG_IO;
    }
    size_t length = encode(candidate, bytes);
    snprintf(temporary, path_size, "%s.tmp.XXXXXX", config->path);
    char *slash = strrchr(parent, '/');
    if (slash == parent)
        slash[1] = 0;
    else
        *slash = 0;
    int directory = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    free(parent);
    int fd = -1;
    uint32_t result = SAKAMOTO_RULE_CONFIG_IO;
    struct stat owner;
    if (directory < 0 || fstat(directory, &owner))
        goto done;
    fd = mkstemp(temporary);
    if (fd < 0)
        goto done;
    if (geteuid() == 0 && fchown(fd, owner.st_uid, owner.st_gid))
        goto done;
    if (fchmod(fd, 0600))
        goto done;
    for (size_t written = 0; written < length;) {
        ssize_t n = write(fd, bytes + written, length - written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto done;
        written += (size_t)n;
    }
    if (fsync(fd))
        goto done;
    if (close(fd)) {
        fd = -1;
        goto done;
    }
    fd = -1;
    if (rename(temporary, config->path))
        goto done;
    /* The rename has saved complete bytes even if directory durability fails. */
    config->state = candidate->state;
    config->retained_count = candidate->retained_count;
    memcpy(config->retained, candidate->retained, sizeof(config->retained));
    if (fsync(directory)) {
        result = SAKAMOTO_RULE_CONFIG_DURABILITY_UNCERTAIN;
        goto done;
    }
    result = 0;
done:
    if (fd >= 0)
        close(fd);
    if (directory >= 0)
        close(directory);
    unlink(temporary);
    free(temporary);
    free(bytes);
    return result;
}
product_rule_config_t *product_rule_config_open(const char *path) {
    if (!path || path[0] != '/' || !path[1])
        return NULL;
    product_rule_config_t *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->path = strdup(path);
    if (!c->path) {
        free(c);
        return NULL;
    }
    struct stat st;
    if (lstat(path, &st) && errno == ENOENT) {
        product_rule_config_t *empty = calloc(1, sizeof(*empty));
        if (!empty)
            c->state.save_error = SAKAMOTO_RULE_CONFIG_IO;
        else {
            empty->state.saved_revision = 1;
            c->state.save_error = save_source(c, empty);
            free(empty);
        }
    } else
        c->state.save_error = load_source(c);
    c->state.error_index = UINT32_MAX;
    return c;
}
void product_rule_config_close(product_rule_config_t *c) {
    if (c) {
        free(c->path);
        free(c);
    }
}
void product_rule_config_query(const product_rule_config_t *c,
                               sakamoto_product_rule_config_status_t *out) {
    if (c && out)
        *out = c->state;
}
uint32_t product_rule_config_activate(product_rule_config_t *c,
                                      product_rule_config_publish_t publish, void *opaque) {
    if (!c || !publish)
        return SAKAMOTO_RULE_CONFIG_INVALID;
    if (c->state.save_error)
        return c->state.save_error;
    c->state.error_index = UINT32_MAX;
    c->state.compiler_status = 0;
    product_l4_policy_rule_t *rules = calloc(SAKAMOTO_RULE_CONFIG_MAX_RULES, sizeof(*rules));
    product_l4_policy_rule_t *effective =
        calloc(SAKAMOTO_RULE_CONFIG_MAX_RULES, sizeof(*effective));
    product_l4_policy_view_t *view = malloc(sizeof(*view));
    uint8_t *bytes = malloc(SOURCE_BYTES);
    uint32_t result = SAKAMOTO_RULE_CONFIG_COMPILE;
    if (!rules || !effective || !view || !bytes)
        goto done;
    for (unsigned i = 0; i < c->state.count; ++i) {
        const sakamoto_product_direct_rule_t *s = &c->state.rules[i];
        product_l4_policy_rule_t *r = &rules[i];
        if (s->protocol != 0 && s->protocol != 6 && s->protocol != 17) {
            c->state.error_index = i;
            result = SAKAMOTO_RULE_CONFIG_UNSUPPORTED;
            goto done;
        }
        r->expression_length = s->expression_length;
        memcpy(r->expression, s->expression, 64);
        uint32_t expression_status = product_static_expression_validate(r->expression, r->expression_length);
        if (expression_status) {
            c->state.error_index = i;
            c->state.compiler_status = expression_status;
            result = SAKAMOTO_RULE_CONFIG_COMPILE;
            goto done;
        }
        r->rule_id = s->version;
        r->uid = s->uid;
        r->network_context_id = s->network_context;
        r->ifindex = s->ifindex;
        r->priority = s->priority;
        r->order = s->order;
        r->reason_id = 1;
        r->family = s->family;
        r->protocol = s->protocol;
        r->direction = s->direction;
        r->action = s->action;
        r->source_prefix_length = s->source_prefix;
        r->destination_prefix_length = s->destination_prefix;
        r->source_port_first = s->source_port_first;
        r->source_port_last = s->source_port_last;
        r->destination_port_first = s->destination_port_first;
        r->destination_port_last = s->destination_port_last;
        memcpy(r->source_address, s->source_address, 16);
        memcpy(r->destination_address, s->destination_address, 16);
    }
    uint32_t effective_count = 0;
    /* Each implicit direct binding and each explicit binding expands into the
     * same view. Duplicate paths never reach the worker matcher. */
    for (unsigned b = 0; b <= c->state.graph.binding_count; ++b) {
        uint8_t selected[SAKAMOTO_RULE_CONFIG_MAX_RULES];
        const sakamoto_product_rule_binding_t *binding = b ? &c->state.graph.bindings[b - 1] : NULL;
        if (binding) {
            result = select_members(&c->state, binding->kind, binding->target, selected);
            if (result)
                goto done;
        }
        for (unsigned i = 0; i < c->state.count; ++i) {
            if (binding ? !selected[i] : rules[i].uid == UINT32_MAX)
                continue;
            uint32_t uid = binding ? binding->uid : rules[i].uid;
            unsigned prior;
            for (prior = 0; prior < effective_count; ++prior)
                if (effective[prior].uid == uid && effective[prior].rule_id == rules[i].rule_id)
                    break;
            if (prior != effective_count)
                continue;
            if (effective_count == SAKAMOTO_RULE_CONFIG_MAX_RULES) {
                c->state.compiler_status = PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED;
                result = SAKAMOTO_RULE_CONFIG_COMPILE;
                goto done;
            }
            effective[effective_count] = rules[i];
            effective[effective_count].uid = uid;
            effective[effective_count++].mode = binding ? binding->mode : 0;
        }
    }
    result = SAKAMOTO_RULE_CONFIG_COMPILE;
    c->state.compiler_status = product_l4_policy_compile(view, effective, effective_count);
    if (c->state.compiler_status)
        goto done;
    size_t length = encode(c, bytes);
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < length; ++i) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    if (!hash)
        hash = 1;
    result = publish(opaque, c->state.saved_revision, hash, effective, effective_count)
                 ? SAKAMOTO_RULE_CONFIG_PUBLISH
                 : 0;
    if (!result) {
        c->state.active_revision = c->state.saved_revision;
        c->state.active_count = effective_count;
        memset(c->state.active_versions, 0, sizeof(c->state.active_versions));
        for (unsigned i = 0; i < effective_count; ++i)
            c->state.active_versions[i] = effective[i].rule_id;
        project(&c->state);
    }
done:
    c->state.compile_error = result;
    free(effective);
    free(rules);
    free(view);
    free(bytes);
    return result;
}
static uint32_t assign_version(const product_rule_config_t *old, product_rule_config_t *next,
                               sakamoto_product_direct_rule_t *r) {
    if (r->base_version) {
        const sakamoto_product_direct_rule_t *prior = current_rule(old, r->base_version);
        if (r->version || !prior || prior->version != r->base_version)
            return SAKAMOTO_RULE_CONFIG_CONFLICT;
        r->version = prior->version;
        if (!same_content(r, prior)) {
            if ((r->version & 65535) == 65535)
                return SAKAMOTO_RULE_CONFIG_EXHAUSTED;
            ++r->version;
        }
        r->base_version = 0;
    } else if (r->version) {
        if (!valid_version(r->version))
            return SAKAMOTO_RULE_CONFIG_INVALID;
        int index = retained_index(old, r->version);
        const sakamoto_product_direct_rule_t *prior = current_rule(old, r->version);
        if (index >= 0 &&
            (r->version < old->retained[index] ||
             (r->version == old->retained[index] && (!prior || !same_content(r, prior)))))
            return SAKAMOTO_RULE_CONFIG_CONFLICT;
    } else {
        for (unsigned attempt = 0; attempt < 32; ++attempt) {
            uint64_t value;
            ssize_t count;
            do {
                count = getrandom(&value, sizeof(value), 0);
            } while (count < 0 && errno == EINTR);
            if (count != sizeof(value))
                return SAKAMOTO_RULE_CONFIG_IO;
            value = (value & UINT64_C(0xffffffffffff0000)) | 1;
            if ((value >> 16) && retained_index(next, value) < 0) {
                r->version = value;
                break;
            }
        }
        if (!r->version)
            return SAKAMOTO_RULE_CONFIG_CONFLICT;
    }
    int index = retained_index(next, r->version);
    if (index < 0) {
        if (next->retained_count == SAKAMOTO_RULE_CONFIG_MAX_IDENTITIES)
            return SAKAMOTO_RULE_CONFIG_EXHAUSTED;
        index = next->retained_count++;
    }
    next->retained[index] = r->version;
    return 0;
}
uint32_t product_rule_config_replace(product_rule_config_t *c,
                                     const sakamoto_product_rule_config_request_t *request,
                                     product_rule_config_publish_t publish, void *opaque) {
    if (!c || !request || !publish || request->schema != SAKAMOTO_RULE_CONFIG_SCHEMA ||
        request->reserved || request->count > SAKAMOTO_RULE_CONFIG_MAX_RULES ||
        (request->operation != SAKAMOTO_RULE_CONFIG_REPLACE &&
         request->operation != SAKAMOTO_RULE_CONFIG_REPLACE_ALL &&
         request->operation != SAKAMOTO_RULE_CONFIG_NETWORK_DISABLE))
        return SAKAMOTO_RULE_CONFIG_INVALID;
    c->state.error_index = UINT32_MAX;
    if (request->expected_saved_revision != c->state.saved_revision)
        return SAKAMOTO_RULE_CONFIG_CONFLICT;
    product_rule_config_t *next = malloc(sizeof(*next));
    if (!next)
        return SAKAMOTO_RULE_CONFIG_IO;
    *next = *c;
    memset(next->state.rules, 0, sizeof(next->state.rules));
    memset(&next->state.graph, 0, sizeof(next->state.graph));
    uint32_t result = SAKAMOTO_RULE_CONFIG_INVALID;
    if (request->operation == SAKAMOTO_RULE_CONFIG_REPLACE) {
        const sakamoto_product_config_rule_t *r = &request->rule;
        if (request->count || r->reserved || r->present > 1 ||
            (r->present && r->uid == UINT32_MAX) || c->state.count > 1 ||
            c->state.graph.group_count || c->state.graph.binding_count ||
            request->graph.group_count || request->graph.edge_count || request->graph.binding_count)
            goto done;
        next->state.count = r->present;
        if (r->present) {
            legacy_rule(&next->state.rules[0], r);
            if (c->state.count)
                next->state.rules[0].base_version = c->state.rules[0].version;
        } else {
            sakamoto_product_config_rule_t empty = {0};
            if (memcmp(r, &empty, sizeof(*r)))
                goto done;
        }
    } else if (request->operation == SAKAMOTO_RULE_CONFIG_NETWORK_DISABLE) {
        if (request->count != 1 || request->graph.group_count || request->graph.edge_count ||
            request->graph.binding_count || request->rules[0].uid == UINT32_MAX ||
            request->rules[0].version || request->rules[0].base_version ||
            !valid_rule(&request->rules[0]))
            goto done;
        *next = *c;
        sakamoto_product_direct_rule_t target = request->rules[0];
        target.action = 2;
        target.priority = target.order = 0;
        unsigned found = next->state.count;
        for (unsigned i = 0; i < next->state.count; ++i)
            if (same_content(&target, &next->state.rules[i])) {
                if (found != next->state.count) { result = SAKAMOTO_RULE_CONFIG_CONFLICT; goto done; }
                found = i;
            }
        if (request->rules[0].action == 2 && found == next->state.count) {
            if (next->state.count == SAKAMOTO_RULE_CONFIG_MAX_RULES) {
                result = SAKAMOTO_RULE_CONFIG_LIMIT; goto done;
            }
            next->state.rules[next->state.count++] = target;
        } else if (request->rules[0].action == 1 && found < next->state.count) {
            for (unsigned i = 0; i < next->state.graph.edge_count; ++i) {
                sakamoto_product_group_edge_t *e = &next->state.graph.edges[i];
                if (e->kind != 1) continue;
                if (e->target == found) { result = SAKAMOTO_RULE_CONFIG_REFERENCE; goto done; }
                if (e->target > found) --e->target;
            }
            for (unsigned i = 0; i < next->state.graph.binding_count; ++i) {
                sakamoto_product_rule_binding_t *b = &next->state.graph.bindings[i];
                if (b->kind != 1) continue;
                if (b->target == found) { result = SAKAMOTO_RULE_CONFIG_REFERENCE; goto done; }
                if (b->target > found) --b->target;
            }
            memmove(&next->state.rules[found], &next->state.rules[found+1],
                    (--next->state.count - found) * sizeof(target));
        }
    } else {
        next->state.graph = request->graph;
        next->state.count = request->count;
        memcpy(next->state.rules, request->rules, request->count * sizeof(request->rules[0]));
    }
    for (unsigned i = 0; i < next->state.count; ++i) {
        sakamoto_product_direct_rule_t *r = &next->state.rules[i];
        c->state.error_index = i;
        if (!valid_rule(r)) {
            result = SAKAMOTO_RULE_CONFIG_INVALID;
            goto done;
        }
        result = assign_version(c, next, r);
        if (result)
            goto done;
        for (unsigned j = 0; j < i; ++j)
            if ((next->state.rules[j].version >> 16) == (r->version >> 16)) {
                result = SAKAMOTO_RULE_CONFIG_CONFLICT;
                goto done;
            }
    }
    c->state.error_index = UINT32_MAX;
    result = validate_graph(&next->state);
    if (result)
        goto done;
    c->state.error_index = UINT32_MAX;
    next->state.error_index = UINT32_MAX;
    int unchanged =
        next->state.count == c->state.count &&
        next->state.graph.group_count == c->state.graph.group_count &&
        next->state.graph.edge_count == c->state.graph.edge_count &&
        next->state.graph.binding_count == c->state.graph.binding_count &&
        !memcmp(next->state.graph.groups, c->state.graph.groups,
                4U * next->state.graph.group_count) &&
        !memcmp(next->state.graph.edges, c->state.graph.edges,
                sizeof(next->state.graph.edges[0]) * next->state.graph.edge_count) &&
        !memcmp(next->state.graph.bindings, c->state.graph.bindings,
                sizeof(next->state.graph.bindings[0]) * next->state.graph.binding_count);
    for (unsigned i = 0; unchanged && i < next->state.count; ++i)
        unchanged = next->state.rules[i].version == c->state.rules[i].version &&
                    same_content(&next->state.rules[i], &c->state.rules[i]);
    if (unchanged && c->state.saved_revision != 0) {
        if (c->state.save_error) {
            c->state.save_error = save_source(c, next);
            if (c->state.save_error) {
                result = c->state.save_error;
                goto done;
            }
        }
        result = c->state.active_revision == c->state.saved_revision && !c->state.compile_error
                     ? 0
                     : product_rule_config_activate(c, publish, opaque);
        goto done;
    }
    if (c->state.saved_revision == UINT64_MAX) {
        result = SAKAMOTO_RULE_CONFIG_EXHAUSTED;
        goto done;
    }
    next->state.saved_revision++;
    project(&next->state);
    c->state.save_error = save_source(c, next);
    result = c->state.save_error;
    if (!result)
        result = product_rule_config_activate(c, publish, opaque);
done:
    free(next);
    return result;
}
