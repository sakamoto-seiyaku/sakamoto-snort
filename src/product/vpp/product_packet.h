/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_PACKET_H
#define SAKAMOTO_PRODUCT_PACKET_H

#include <stddef.h>
#include <stdint.h>

typedef enum
{
  PRODUCT_PACKET_OK = 0,
  PRODUCT_PACKET_INVALID_ARGUMENT,
  PRODUCT_PACKET_INVALID_L3,
  PRODUCT_PACKET_TRUNCATED_ENVELOPE,
  PRODUCT_PACKET_UNSUPPORTED_ENVELOPE,
  PRODUCT_PACKET_CORRECTIVE_HANDOFF,
  PRODUCT_PACKET_REPEATED_OWNER_MISMATCH,
  PRODUCT_PACKET_ORDER_VIOLATION,
  PRODUCT_PACKET_ALREADY_SETTLED,
} product_packet_result_t;

typedef enum
{
  PRODUCT_PACKET_L3_UNAVAILABLE = 0,
  PRODUCT_PACKET_L3_COMPLETE,
} product_packet_l3_status_t;

typedef enum
{
  PRODUCT_PACKET_L4_UNAVAILABLE = 0,
  PRODUCT_PACKET_L4_INVALID_OR_UNAVAILABLE = PRODUCT_PACKET_L4_UNAVAILABLE,
  PRODUCT_PACKET_L4_COMPLETE,
  PRODUCT_PACKET_L4_OTHER_TERMINAL,
  PRODUCT_PACKET_L4_FRAGMENT,
} product_packet_l4_status_t;

typedef enum
{
  PRODUCT_PACKET_DISTRIBUTION_LOCAL = 0,
  PRODUCT_PACKET_DISTRIBUTION_PRIMARY_REMOTE,
} product_packet_distribution_t;

typedef enum
{
  PRODUCT_PACKET_INTENT_NONE = 0,
  PRODUCT_PACKET_INTENT_PASS_ADAPTER,
  PRODUCT_PACKET_INTENT_DROP_RUNTIME,
} product_packet_terminal_intent_t;

typedef enum
{
  PRODUCT_PACKET_DROP_NONE = 0,
  PRODUCT_PACKET_DROP_INVALID_ENVELOPE,
  PRODUCT_PACKET_DROP_TRUNCATED_ENVELOPE,
  PRODUCT_PACKET_DROP_UNSUPPORTED_ENVELOPE,
  PRODUCT_PACKET_DROP_REPEATED_OWNER_MISMATCH,
  PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION,
  PRODUCT_PACKET_DROP_CORRECTIVE_HANDOFF_CONGESTION,
  PRODUCT_PACKET_DROP_POLICY_GATE,
  PRODUCT_PACKET_DROP_POLICY_L4,
} product_packet_runtime_drop_reason_t;

typedef struct
{
  uint32_t uid;
  uint32_t queue_id;
  uint32_t interface_id;
  uint64_t network_context_id;
  uint32_t profile_id;
} product_packet_hints_t;

typedef struct
{
  uint16_t worker_count;
  uint64_t hash_seed;
} product_worker_layout_t;

typedef struct
{
  const uint8_t *data;
  size_t length;
  uint16_t current_worker;
  uint32_t flow_domain;
  uint64_t origin_obligation_id;
  product_packet_hints_t hints;
} product_packet_ingress_t;

typedef struct
{
  uint8_t l3_status;
  uint8_t l4_status;
  uint8_t ip_family;
  uint8_t protocol;
  uint8_t source_address[16];
  uint8_t destination_address[16];
  uint16_t source_port;
  uint16_t destination_port;
  uint16_t l3_header_length;
  uint16_t l4_header_length;
  uint32_t packet_length;
} product_packet_facts_t;

typedef struct
{
  uint8_t address[16];
  uint16_t port;
} product_packet_endpoint_t;

typedef struct
{
  uint8_t ip_family;
  uint8_t protocol;
  uint16_t reserved;
  product_packet_endpoint_t endpoint_a;
  product_packet_endpoint_t endpoint_b;
} product_canonical_flow_key_t;

typedef struct
{
  product_packet_facts_t facts;
  product_canonical_flow_key_t canonical_key;
  product_packet_hints_t hints;
  uint64_t origin_obligation_id;
  uint16_t expected_owner;
  uint8_t distribution;
  uint8_t primary_handoff_count;
  uint8_t corrective_handoff_count;
  uint8_t owner_guarded;
  uint8_t terminal_intent;
  uint8_t terminal_count;
  uint8_t runtime_drop_reason;
  uint8_t settled;
} product_packet_lease_t;

product_packet_result_t
product_packet_admit (const product_worker_layout_t *layout,
                      const product_packet_ingress_t *ingress,
                      product_packet_lease_t *lease);

product_packet_result_t
product_packet_owner_guard (product_packet_lease_t *lease,
                            uint16_t current_worker);

product_packet_result_t
product_packet_owner_from_facts (const product_worker_layout_t *layout,
                                 uint32_t flow_domain,
                                 const product_packet_facts_t *facts,
                                 product_canonical_flow_key_t *key,
                                 uint16_t *owner);

product_packet_result_t
product_packet_set_terminal (product_packet_lease_t *lease,
                             product_packet_terminal_intent_t intent);

product_packet_result_t product_packet_settle (product_packet_lease_t *lease);

#endif
