/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_OI2_BROKER_CONTRACT_H
#define SAKAMOTO_OI2_BROKER_CONTRACT_H

#include <stdint.h>

#define OI2_BROKER_ABI_VERSION 1u
#define OI2_BROKER_QUEUE_CAPACITY 4u

enum oi2_socket_family {
    OI2_FAMILY_IPV4 = 4,
    OI2_FAMILY_IPV6 = 6,
};

enum oi2_socket_kind {
    OI2_KIND_TCP = 1,
    OI2_KIND_UDP = 2,
};

enum oi2_completion_result {
    OI2_RESULT_SUCCESS = 1,
    OI2_RESULT_BIND_FAILURE = 2,
    OI2_RESULT_PROTECT_FAILURE = 3,
    OI2_RESULT_BROKER_UNAVAILABLE = 4,
};

/* Request flags are test controls carried across the same production-shaped
 * ABI.  They never change ownership: the broker still owns only the received
 * SCM_RIGHTS duplicate and always closes it exactly once. */
enum oi2_request_flags {
    OI2_FLAG_NONE = 0,
    OI2_FLAG_BIND_FAILURE = 1u << 0,
    OI2_FLAG_PROTECT_FAILURE = 1u << 1,
    OI2_FLAG_BROKER_UNAVAILABLE = 1u << 2,
};

/* This is the opaque payload carried beside exactly one SCM_RIGHTS fd. */
typedef struct oi2_broker_request {
    uint32_t abi_version;
    uint32_t family;
    uint32_t kind;
    uint32_t owner;
    uint32_t shard;
    uint32_t reserved;
    uint64_t token;
    uint64_t generation;
    uint64_t underlay_epoch;
    uint32_t target_port;
    uint32_t flags;
} oi2_broker_request_t;

typedef struct oi2_broker_completion {
    uint32_t abi_version;
    uint32_t result;
    uint32_t fault_reason;
    uint32_t owner;
    uint32_t shard;
    uint32_t reserved;
    uint64_t token;
    uint64_t generation;
    uint64_t underlay_epoch;
} oi2_broker_completion_t;

#endif
