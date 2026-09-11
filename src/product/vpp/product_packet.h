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
  /* Root pre-policy capacity disposition; never a Policy Verdict. */
  PRODUCT_PACKET_INTENT_PROCESSING_CAPACITY_BYPASS,
} product_packet_terminal_intent_t;

typedef enum
{
  PRODUCT_PACKET_BYPASS_NONE = 0,
  PRODUCT_PACKET_BYPASS_PRIMARY_CREDIT_EXHAUSTED,
  PRODUCT_PACKET_BYPASS_PRIMARY_ENQUEUE_REJECTED,
  PRODUCT_PACKET_BYPASS_REASSEMBLY_RESOURCE,
} product_packet_processing_bypass_reason_t;

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
  PRODUCT_PACKET_DROP_OWNER_DELIVERY_MISMATCH,
  PRODUCT_PACKET_DROP_FLOW_CAPACITY,
  PRODUCT_PACKET_DROP_FLOW_MUTATION,
  PRODUCT_PACKET_DROP_REASSEMBLY_MALFORMED,
  PRODUCT_PACKET_DROP_REASSEMBLY_TIMEOUT,
  PRODUCT_PACKET_DROP_REASSEMBLY_STOP,
  PRODUCT_PACKET_DROP_REASSEMBLY_INTERNAL,
  PRODUCT_PACKET_DROP_REASSEMBLY_NO_RETURN,
} product_packet_runtime_drop_reason_t;

typedef enum
{
  PRODUCT_PACKET_DIRECTION_UNKNOWN = 0,
  PRODUCT_PACKET_DIRECTION_INPUT = 1,
  PRODUCT_PACKET_DIRECTION_OUTPUT = 3,
} product_packet_direction_t;

typedef enum
{
  PRODUCT_PACKET_PROVENANCE_UNKNOWN = 0,
  PRODUCT_PACKET_PROVENANCE_ROOT_NFQUEUE,
  PRODUCT_PACKET_PROVENANCE_VPN_TUN,
  PRODUCT_PACKET_PROVENANCE_FLOW_STACK_RETURN,
  PRODUCT_PACKET_PROVENANCE_GRAPH_INJECTED,
} product_packet_provenance_t;

enum
{
  PRODUCT_PLATFORM_UID_KNOWN = 1 << 0,
  PRODUCT_PLATFORM_IFINDEX_KNOWN = 1 << 1,
  PRODUCT_PLATFORM_CONTEXT_KNOWN = 1 << 2,
};

typedef struct
{
  uint32_t uid;
  uint32_t linux_ifindex;
  uint32_t network_context_id;
  uint8_t availability;
  uint8_t direction; /* product_packet_direction_t */
  uint8_t provenance; /* product_packet_provenance_t */
  uint8_t reserved;
} product_platform_packet_facts_t;

typedef enum
{
  PRODUCT_ADAPTER_OBLIGATION_NONE = 0,
  PRODUCT_ADAPTER_OBLIGATION_ROOT_NFQUEUE,
  PRODUCT_ADAPTER_OBLIGATION_GRAPH_INJECTED,
  PRODUCT_ADAPTER_OBLIGATION_VPN_TUN,
} product_adapter_obligation_kind_t;

/* Graph nodes carry this value opaquely. Only the adapter decodes it. */
typedef struct
{
  uint64_t token;
  uint64_t queue_generation;
  uint32_t packet_id;
  uint16_t origin_lane;
  uint8_t kind;
  uint8_t origin_worker; /* frozen Adapter placement; never an owner key */
} product_adapter_obligation_t;

_Static_assert (sizeof (product_platform_packet_facts_t) == 16,
                "platform facts inline contract");
_Static_assert (sizeof (product_adapter_obligation_t) == 24,
                "adapter obligation inline contract");

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
  uint64_t origin_obligation_id;
  product_platform_packet_facts_t platform;
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
  /* Parsed once; future TCP tracker consumes these values without decoding. */
  uint32_t tcp_sequence;
  uint32_t tcp_acknowledgment;
  uint16_t tcp_window;
  uint16_t transport_length;
  uint16_t transport_offset;
  uint16_t icmp_identifier;
  uint16_t icmp_sequence;
  uint8_t tcp_flags;
  uint8_t tcp_window_scale;
  uint8_t tcp_window_scale_known;
  uint8_t icmp_type;
  uint8_t icmp_code;
  uint8_t icmp_identity_known;
} product_packet_facts_t;

typedef struct
{
  uint8_t address[16];
  uint16_t port;
} product_packet_endpoint_t;

typedef enum
{
  PRODUCT_OWNER_KEY_NONE = 0,
  PRODUCT_OWNER_KEY_L3,
  PRODUCT_OWNER_KEY_L4_PORTS,
  PRODUCT_OWNER_KEY_ICMP_QUERY,
} product_owner_key_kind_t;

enum { PRODUCT_ICMP_QUERY_ECHO = 1, PRODUCT_EXECUTION_OWNER_UNKNOWN = UINT16_MAX };

typedef struct
{
  uint8_t kind; /* product_owner_key_kind_t */
  uint8_t ip_family;
  uint8_t protocol;
  uint8_t query_class; /* only ICMP_QUERY; request/reply share one class */
  uint8_t address_a[16];
  uint8_t address_b[16];
  union
  {
    struct { uint16_t a, b; } ports;
    struct { uint16_t identifier, reserved; } query;
  } transport;
} product_canonical_owner_key_t;

typedef struct
{
  product_canonical_owner_key_t key;
  uint64_t canonical_hash;
  uint16_t execution_owner;
  uint8_t source_is_a; /* projection only; not semantic packet/flow direction */
  uint8_t valid;
} product_owner_assignment_t;

_Static_assert (sizeof (product_canonical_owner_key_t) == 40, "typed owner key");

/* The sole assignment interface consumes already parsed facts, never bytes or
 * platform/completion identity. A successful result is immutable downstream. */
product_packet_result_t
product_owner_assign (const product_worker_layout_t *layout,
                      const product_packet_facts_t *facts,
                      product_owner_assignment_t *assignment);

typedef struct
{
  product_packet_facts_t facts;
  product_owner_assignment_t assignment;
  product_platform_packet_facts_t platform;
  uint64_t origin_obligation_id;
  uint8_t distribution;
  uint8_t primary_handoff_count;
  uint8_t corrective_handoff_count;
  uint8_t policy_owner_ready;
  uint8_t terminal_intent;
  uint8_t terminal_count;
  uint8_t runtime_drop_reason;
  uint8_t processing_bypass_reason;
  uint8_t settled;
} product_packet_lease_t;

product_packet_result_t
product_packet_bypass_primary_capacity (
  product_packet_lease_t *lease,
  product_packet_processing_bypass_reason_t reason);

product_packet_result_t
product_packet_admit (const product_worker_layout_t *layout,
                      const product_packet_ingress_t *ingress,
                      product_packet_lease_t *lease);

/* Reassembly supplies the first-fragment assignment. Validate the complete
 * packet and its identity, but do not hash or select an owner a second time. */
product_packet_result_t
product_packet_admit_selected (const product_worker_layout_t *layout,
                               const product_packet_ingress_t *ingress,
                               const product_owner_assignment_t *assignment,
                               product_packet_lease_t *lease);

#ifdef SAKAMOTO_PRODUCT_HOST_EVIDENCE
product_packet_result_t
product_packet_owner_guard (product_packet_lease_t *lease,
                            uint16_t current_worker);
#endif

product_packet_result_t
product_packet_set_terminal (product_packet_lease_t *lease,
                             product_packet_terminal_intent_t intent);

product_packet_result_t product_packet_settle (product_packet_lease_t *lease);

#endif
