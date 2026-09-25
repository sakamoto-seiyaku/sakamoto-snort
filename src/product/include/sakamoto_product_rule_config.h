/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_RULE_CONFIG_ABI_H
#define SAKAMOTO_PRODUCT_RULE_CONFIG_ABI_H

#include <stdint.h>

#define SAKAMOTO_RULE_CONFIG_SCHEMA UINT32_C(1)
#define SAKAMOTO_RULE_CONFIG_QUERY UINT32_C(0)
#define SAKAMOTO_RULE_CONFIG_REPLACE UINT32_C(1)
#define SAKAMOTO_RULE_CONFIG_REPLACE_ALL UINT32_C(2)
#define SAKAMOTO_RULE_CONFIG_MAX_RULES 256
#define SAKAMOTO_RULE_CONFIG_MAX_IDENTITIES 4096

#define SAKAMOTO_RULE_CONFIG_OK UINT32_C(0)
#define SAKAMOTO_RULE_CONFIG_INVALID UINT32_C(1)
#define SAKAMOTO_RULE_CONFIG_CONFLICT UINT32_C(2)
#define SAKAMOTO_RULE_CONFIG_IO UINT32_C(3)
#define SAKAMOTO_RULE_CONFIG_UNSUPPORTED UINT32_C(4)
#define SAKAMOTO_RULE_CONFIG_COMPILE UINT32_C(5)
#define SAKAMOTO_RULE_CONFIG_PUBLISH UINT32_C(6)
#define SAKAMOTO_RULE_CONFIG_EXHAUSTED UINT32_C(7)
#define SAKAMOTO_RULE_CONFIG_NOT_READY UINT32_C(8)
/* Rename completed, but directory durability could not be confirmed. The
 * saved identity describes actual complete bytes; compilation is forbidden. */
#define SAKAMOTO_RULE_CONFIG_DURABILITY_UNCERTAIN UINT32_C(9)

/* Addresses are four network-order bytes. Numeric fields are host order at
 * the C ABI; generated VAPI owns wire conversion. No pointer crosses it. */
typedef struct {
    uint32_t present;
    uint32_t uid;
    uint32_t protocol;
    uint32_t direction;
    uint32_t action;
    uint32_t source_port;
    uint32_t destination_port;
    uint32_t reserved;
    uint8_t source_address[4];
    uint8_t destination_address[4];
} sakamoto_product_config_rule_t;

/* Complete direct source entry. base_version is an edit precondition, never
 * persisted; version is an assigned or explicitly imported complete identity. */
typedef struct {
    uint64_t version;
    uint64_t base_version;
    uint32_t uid, network_context, ifindex, priority, order;
    uint32_t family, protocol, direction, action;
    uint32_t source_prefix, destination_prefix;
    uint32_t source_port_first, source_port_last;
    uint32_t destination_port_first, destination_port_last;
    uint32_t reserved;
    uint8_t source_address[16], destination_address[16];
} sakamoto_product_direct_rule_t;

#define SAKAMOTO_RULE_CONFIG_MAX_GROUPS 64
#define SAKAMOTO_RULE_CONFIG_MAX_EDGES 512
#define SAKAMOTO_RULE_CONFIG_MAX_BINDINGS 128
#define SAKAMOTO_RULE_CONFIG_MAX_DEPTH 8
#define SAKAMOTO_RULE_CONFIG_MAX_EXPANSION 4096
#define SAKAMOTO_RULE_CONFIG_REFERENCE UINT32_C(10)
#define SAKAMOTO_RULE_CONFIG_CYCLE UINT32_C(11)
#define SAKAMOTO_RULE_CONFIG_LIMIT UINT32_C(12)
#define SAKAMOTO_RULE_CONFIG_MODE_CONFLICT UINT32_C(13)
#define SAKAMOTO_RULE_CONFIG_RULE UINT32_C(1)
#define SAKAMOTO_RULE_CONFIG_GROUP UINT32_C(2)
#define SAKAMOTO_RULE_CONFIG_ENFORCE UINT32_C(0)
#define SAKAMOTO_RULE_CONFIG_OBSERVE UINT32_C(1)

typedef struct {
    uint32_t group, kind, target;
} sakamoto_product_group_edge_t;
typedef struct {
    uint32_t id, uid, kind, target, mode;
} sakamoto_product_rule_binding_t;
typedef struct {
    uint32_t group_count, edge_count, binding_count;
    uint32_t groups[SAKAMOTO_RULE_CONFIG_MAX_GROUPS];
    sakamoto_product_group_edge_t edges[SAKAMOTO_RULE_CONFIG_MAX_EDGES];
    sakamoto_product_rule_binding_t bindings[SAKAMOTO_RULE_CONFIG_MAX_BINDINGS];
} sakamoto_product_rule_graph_t;

typedef struct {
    uint32_t schema;
    uint32_t operation;
    uint64_t expected_saved_revision;
    sakamoto_product_config_rule_t rule;
    uint32_t count, reserved;
    sakamoto_product_direct_rule_t rules[SAKAMOTO_RULE_CONFIG_MAX_RULES];
    sakamoto_product_rule_graph_t graph;
} sakamoto_product_rule_config_request_t;

typedef struct {
    uint64_t generation;
    uint64_t saved_revision;
    uint64_t active_revision;
    uint64_t saved_rule_version;
    uint64_t active_rule_version;
    uint32_t result;
    uint32_t save_error;
    uint32_t compile_error;
    uint32_t reserved;
    sakamoto_product_config_rule_t rule;
    uint32_t count, active_count, error_index, compiler_status;
    sakamoto_product_direct_rule_t rules[SAKAMOTO_RULE_CONFIG_MAX_RULES];
    uint64_t active_versions[SAKAMOTO_RULE_CONFIG_MAX_RULES];
    sakamoto_product_rule_graph_t graph;
} sakamoto_product_rule_config_status_t;

#endif
