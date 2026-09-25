/* SPDX-License-Identifier: Apache-2.0 */
#ifndef SAKAMOTO_PRODUCT_ABI_H
#define SAKAMOTO_PRODUCT_ABI_H

#include <stddef.h>
#include <stdint.h>
#include "sakamoto_product_network.h"
#include "sakamoto_product_sni.h"
#include "sakamoto_product_rule_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This is a deliberately small, fixed-width, non-unwinding seam. */
#define SAKAMOTO_PRODUCT_ABI_VERSION UINT32_C(1)
#define SAKAMOTO_PRODUCT_API_VERSION UINT32_C(1)
#define SAKAMOTO_PRODUCT_ARTIFACT_ID_MAX UINT32_C(96)
#define SAKAMOTO_PRODUCT_API_IDENTITY_MAX UINT32_C(96)
#define SAKAMOTO_PRODUCT_VPP_REVISION_MAX UINT32_C(48)
#define SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX UINT32_C(128)
#define SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX UINT32_C(96)

/*
 * SAKAMOTO-192 policy-bundle ABI.  The legacy ProductPolicySnapshot below is
 * intentionally unchanged for S188-S191 callers.  New callers use one
 * versioned, fixed-capacity successor snapshot instead of applying rules one
 * at a time.
 */
#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION UINT32_C(1)
#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES UINT32_C(64)
#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES UINT32_C(64)
#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_RULES \
  SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES
#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES UINT32_C(128)
#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_FORMAT "sakamoto-policy-bundle/v1"

#define SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE UINT32_C(1)
#define SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4 UINT32_C(2)
#define SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4 UINT32_C(4)
#define SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV6 UINT32_C(6)
#define SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_TCP UINT32_C(6)
#define SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_UDP UINT32_C(17)
#define SAKAMOTO_PRODUCT_POLICY_DIRECTION_INPUT UINT32_C(1)
#define SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT UINT32_C(3)
#define SAKAMOTO_PRODUCT_POLICY_ACTION_PASS_NEXT UINT32_C(1)
#define SAKAMOTO_PRODUCT_POLICY_ACTION_DROP UINT32_C(2)
#define SAKAMOTO_PRODUCT_POLICY_IFINDEX_ANY UINT32_MAX

typedef struct {
  const uint8_t *data;
  uint32_t length;
} sakamoto_product_bytes_t;

/* Keep values as integer tags.  Do not model these as a fieldless Rust enum. */
#define SAKAMOTO_PRODUCT_OK UINT32_C(0)
#define SAKAMOTO_PRODUCT_INVALID_ARGUMENT UINT32_C(1)
#define SAKAMOTO_PRODUCT_ALLOCATION_FAILED UINT32_C(2)
#define SAKAMOTO_PRODUCT_CONNECT_FAILED UINT32_C(3)
#define SAKAMOTO_PRODUCT_DISCONNECTED UINT32_C(4)
#define SAKAMOTO_PRODUCT_STALE_HANDLE UINT32_C(5)
#define SAKAMOTO_PRODUCT_API_UNAVAILABLE UINT32_C(6)
#define SAKAMOTO_PRODUCT_QUERY_FAILED UINT32_C(7)
#define SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH UINT32_C(8)
#define SAKAMOTO_PRODUCT_INTERNAL_ERROR UINT32_C(9)
#define SAKAMOTO_PRODUCT_UNKNOWN_TAG UINT32_C(10)
/* Appended after the original tag set to preserve existing numeric values. */
#define SAKAMOTO_PRODUCT_DISCONNECT_FAILED UINT32_C(11)
#define SAKAMOTO_PRODUCT_POLICY_STORE_FAILED UINT32_C(12)
#define SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED UINT32_C(13)
/* A policy request crossed the VAPI submission boundary without a
 * trustworthy terminal reply.  Reconcile this through the durable mutation
 * fence before issuing another policy mutation. */
#define SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN UINT32_C(14)
/* A durable unknown mutation fence blocks dependent mutations on this
 * generation until a fresh-generation status readback reconciles it. */
#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FENCED UINT32_C(15)

/* Debug-only, one-shot typed mutation fault controls.  These values are
 * control-plane test inputs, not policy outcome tags. */
#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE UINT32_C(0)
#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK UINT32_C(1)
#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT UINT32_C(2)

typedef struct {
  uint32_t schema_version;
  uint32_t reserved;
  uint64_t requested_revision;
  uint64_t snapshot_hash;
  uint32_t snapshot_empty;
  uint32_t default_pass;
  uint32_t gate_claim_count;
  uint32_t l4_rule_count;
  uint32_t gate_subject_uid;
  uint32_t gate_network_context;
  uint32_t gate_blocked;
  uint32_t gate_reason_id;
  uint64_t gate_rule_id;
  uint32_t l4_subject_uid;
  uint32_t l4_network_context;
  uint32_t l4_ip_family;
  uint32_t l4_ip_protocol;
  uint32_t l4_direction;
  uint32_t l4_action;
  uint32_t l4_source_prefix_len;
  uint32_t l4_destination_prefix_len;
  uint32_t l4_source_port_first;
  uint32_t l4_source_port_last;
  uint32_t l4_destination_port_first;
  uint32_t l4_destination_port_last;
  uint32_t l4_priority;
  uint32_t l4_order;
  uint32_t l4_reason_id;
  uint32_t l4_reserved;
  uint64_t l4_rule_id;
  uint8_t l4_source_address[16];
  uint8_t l4_destination_address[16];
  char snapshot_identity[SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX];
} sakamoto_product_policy_snapshot_t;

/* One typed rule entry in a complete policy successor.  Gate entries use
 * rule_kind=GATE and leave L4-only fields at zero; L4 entries use
 * rule_kind=L4 and populate the full match tuple.  L4 IPv4 addresses follow
 * the PacketFacts canonical shape (network-order bytes 0..3, bytes 4..15
 * zero); the legacy scalar snapshot above retains its S191 tail placement.
 * ifindex=SAKAMOTO_PRODUCT_POLICY_IFINDEX_ANY is the interface wildcard.
 * The fixed arrays in the bundle make the upper bound part of the ABI rather
 * than an allocation convention. */
typedef struct {
  uint32_t subject_uid;
  uint32_t network_context;
  uint32_t ifindex;
  uint32_t rule_kind;
  uint32_t ip_family;
  uint32_t ip_protocol;
  uint32_t direction;
  uint32_t action;
  uint32_t enabled;
  uint32_t source_prefix_len;
  uint32_t destination_prefix_len;
  uint32_t source_port_first;
  uint32_t source_port_last;
  uint32_t destination_port_first;
  uint32_t destination_port_last;
  uint32_t priority;
  uint32_t order;
  uint32_t reason_id;
  uint32_t reserved;
  uint64_t rule_id;
  uint8_t source_address[16];
  uint8_t destination_address[16];
} sakamoto_product_policy_rule_entry_t;

/* Complete immutable Gate + L4 runtime snapshot.  struct_size is checked at
 * the typed boundary so an append-only future ABI cannot be misread as v1. */
typedef struct {
  uint32_t abi_version;
  uint32_t struct_size;
  uint64_t requested_revision;
  uint64_t snapshot_hash;
  uint32_t gate_entry_count;
  uint32_t l4_rule_count;
  uint32_t default_pass;
  uint32_t reserved;
  char snapshot_identity[SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX];
  sakamoto_product_policy_rule_entry_t gate_entries[
    SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES];
  sakamoto_product_policy_rule_entry_t l4_entries[
    SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES];
} sakamoto_product_policy_bundle_t;

typedef struct {
  uint32_t abi_version;
  uint32_t api_version;
  uint32_t status_code;
  uint32_t reserved;
  uint64_t generation;
  uint32_t core_ready;
  uint32_t adapter_available;
  uint32_t protection_running;
  uint32_t plugin_loaded;
  uint32_t vapi_handle_live;
  uint32_t generation_live;
  uint32_t reserved_flags;
  char artifact_id[SAKAMOTO_PRODUCT_ARTIFACT_ID_MAX];
  char api_identity[SAKAMOTO_PRODUCT_API_IDENTITY_MAX];
  char vpp_revision[SAKAMOTO_PRODUCT_VPP_REVISION_MAX];
  char error_detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
  uint32_t root_nfqueue_queue_id;
  uint32_t root_nfqueue_queue_last;
  uint32_t root_nfqueue_lane_count;
  uint32_t root_nfqueue_ready_lane_mask;
  uint64_t root_nfqueue_generation;
  uint64_t root_nfqueue_verdict_attempts;
  uint64_t root_nfqueue_internal_settlements;
  uint64_t root_nfqueue_buffer_returns;
  uint64_t root_nfqueue_origin_local_completions;
  uint64_t root_nfqueue_origin_remote_completions;
  uint64_t root_nfqueue_lane0_verdict_attempts;
  uint64_t root_nfqueue_lane1_verdict_attempts;
  uint64_t root_nfqueue_input_packets;
  uint64_t root_nfqueue_output_packets;
  uint64_t root_nfqueue_ipv4_packets;
  uint64_t root_nfqueue_ipv6_packets;
  uint64_t root_nfqueue_tcp_packets;
  uint64_t root_nfqueue_udp_packets;
  uint64_t root_nfqueue_uid_known_packets;
  uint64_t root_nfqueue_uid_unknown_packets;
  uint32_t root_nfqueue_last_ip_family;
  uint32_t root_nfqueue_last_protocol;
  uint32_t root_nfqueue_last_hook;
  uint32_t root_nfqueue_last_uid_known;
  uint32_t root_nfqueue_last_uid;
  uint32_t root_nfqueue_last_queue_id;
  uint32_t root_nfqueue_last_packet_id;
  uint64_t root_nfqueue_verdict_succeeded;
  uint64_t root_nfqueue_verdict_failed_definite;
  uint64_t root_nfqueue_verdict_outcome_unknown;
  uint64_t root_nfqueue_ingress_identity_missing;
  uint64_t root_nfqueue_graph_submit_fail_opens;
  uint64_t root_nfqueue_non_owner_bypasses;
  uint64_t root_nfqueue_duplicate_completion_drops;
  uint64_t root_nfqueue_stale_completion_drops;
  uint64_t vpn_tun_fd_attached;
  uint64_t vpn_direct_udp4_socket_attached;
  uint64_t vpn_direct_udp4_protect_succeeded;
  uint64_t vpn_direct_udp4_bind_succeeded;
  uint64_t vpn_tun_ingress_packets;
  uint64_t vpn_tun_udp4_tun_origin_packets;
  uint64_t vpn_flow_stack_admissions;
  uint64_t vpn_direct_udp4_send_succeeded;
  uint64_t vpn_direct_udp4_transport_failed;
  uint64_t vpn_flow_stack_return_packets;
  uint64_t vpn_flow_stack_return_provenance_packets;
  uint64_t vpn_tun_write_completions;
  uint64_t vpn_infrastructure_faults;
  uint64_t vpn_duplicate_or_stale_drops;
  uint32_t product_graph_worker_count;
  uint64_t product_graph_hash_seed;
  uint32_t product_graph_handoff_credits;
  uint32_t product_graph_vpp_worker_count;
  uint32_t product_graph_vpp_main_core;
  uint32_t product_graph_vpp_worker0_thread_index;
  uint32_t product_graph_vpp_worker0_core;
  uint32_t product_graph_vpp_worker1_thread_index;
  uint32_t product_graph_vpp_worker1_core;
  uint32_t product_graph_enabled;
  uint32_t product_graph_accepting;
  uint32_t product_graph_worker_layout_ready;
  uint64_t product_graph_obligation_debt;
  uint64_t product_graph_buffer_debt;
  uint64_t product_graph_handoff_debt;
  uint64_t policy_requested_revision;
  uint64_t policy_active_revision;
  uint64_t policy_generation;
  uint64_t policy_snapshot_hash;
  uint64_t policy_worker0_revision;
  uint64_t policy_worker1_revision;
  uint32_t policy_snapshot_empty;
  uint32_t policy_default_pass;
  uint32_t policy_gate_claim_count;
  uint32_t policy_l4_rule_count;
  uint32_t policy_last_apply_status_code;
  uint32_t policy_mixed_revision;
  uint32_t policy_artifact_match;
  uint32_t policy_generation_match;
  char policy_snapshot_identity[SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX];
  uint32_t policy_gate_subject_uid;
  uint32_t policy_gate_network_context;
  uint32_t policy_gate_blocked;
  uint32_t policy_gate_reason_id;
  uint64_t policy_gate_rule_id;
  uint64_t policy_drop_records;
  uint64_t policy_last_drop_revision;
  uint64_t policy_last_drop_rule_id;
  uint64_t policy_last_drop_completion_attempts;
  uint32_t policy_last_drop_uid;
  uint32_t policy_last_drop_network_context;
  uint32_t policy_last_drop_reason_id;
  uint32_t policy_last_drop_verdict;
  uint32_t policy_last_drop_winner;
  uint32_t policy_last_drop_uid_known;
  uint32_t policy_last_drop_device_direction;
  /* S191 L4 evidence extension.  These fields are distinct from Gate/drop
   * attribution so an allow or no-match cannot be mistaken for a default
   * adapter pass. */
  uint64_t policy_l4_active_revision;
  uint64_t policy_l4_rule_id;
  uint64_t policy_l4_match_records;
  uint64_t policy_l4_no_match_records;
  uint64_t policy_l4_last_match_revision;
  uint64_t policy_l4_last_match_rule_id;
  uint32_t policy_l4_subject_uid;
  uint32_t policy_l4_network_context;
  uint32_t policy_l4_ip_family;
  uint32_t policy_l4_ip_protocol;
  uint32_t policy_l4_direction;
  uint32_t policy_l4_action;
  uint32_t policy_l4_priority;
  uint32_t policy_l4_order;
  uint32_t policy_l4_reason_id;
  uint32_t policy_l4_last_match_uid;
  uint32_t policy_l4_last_match_network_context;
  uint32_t policy_l4_last_match_reason_id;
  uint32_t policy_l4_last_match_verdict;
  uint32_t policy_l4_last_match_winner;
  uint32_t policy_l4_last_match_uid_known;
  uint32_t policy_l4_last_match_device_direction;
  uint32_t policy_l4_last_match_action;
  uint32_t policy_l4_last_evaluation_result;
  uint32_t policy_l4_last_evaluation_verdict;
  uint32_t policy_l4_last_evaluation_device_direction;
  /* S192 bounded matcher-view evidence extension.  These fields are appended
   * so S191 consumers retain their existing prefix layout. */
  uint32_t policy_l4_view_active;
  uint32_t policy_l4_view_rule_count;
  uint32_t policy_l4_view_max_probes;
  uint32_t policy_l4_view_last_match_winner_rank;
  uint32_t policy_l4_view_last_match_probes;
  uint32_t policy_l4_view_last_match_candidate_count;
  uint32_t policy_l4_view_last_no_match_reason;
  /* S192 typed-match/evaluation correlation keys. */
  uint64_t policy_l4_typed_match_policy_key;
  uint64_t policy_l4_typed_match_probe_key;
  uint64_t policy_l4_last_evaluation_probe_key;
} sakamoto_product_status_t;

/* Compile every consumer against the same layout, not just the bridge. */
#if defined(__cplusplus)
static_assert(sizeof(sakamoto_product_bytes_t) == 16U,
              "product bytes ABI changed");
static_assert(sizeof(sakamoto_product_policy_snapshot_t) == 264U,
              "product policy snapshot ABI changed");
static_assert(sizeof(sakamoto_product_policy_rule_entry_t) == 120U,
              "product policy rule entry ABI changed");
static_assert(offsetof(sakamoto_product_policy_rule_entry_t, rule_id) == 80U,
              "product policy rule entry identity offset changed");
static_assert(offsetof(sakamoto_product_policy_rule_entry_t, source_address) == 88U,
              "product policy source address offset changed");
static_assert(offsetof(sakamoto_product_policy_rule_entry_t, destination_address) == 104U,
              "product policy destination address offset changed");
static_assert(sizeof(sakamoto_product_policy_bundle_t) == 15496U,
              "product policy bundle ABI changed");
static_assert(offsetof(sakamoto_product_policy_bundle_t, snapshot_identity) == 40U,
              "product policy bundle identity offset changed");
static_assert(offsetof(sakamoto_product_policy_bundle_t, gate_entries) == 136U,
              "product policy bundle Gate offset changed");
static_assert(offsetof(sakamoto_product_policy_bundle_t, l4_entries) == 7816U,
              "product policy bundle L4 offset changed");
static_assert(offsetof(sakamoto_product_status_t, generation) == 16U,
              "product status generation ABI changed");
static_assert(offsetof(sakamoto_product_status_t, artifact_id) == 52U,
              "product status identity ABI changed");
static_assert(sizeof(sakamoto_product_status_t) == 1304U,
              "product status ABI changed");
#else
_Static_assert(sizeof(sakamoto_product_bytes_t) == 16U,
               "product bytes ABI changed");
_Static_assert(sizeof(sakamoto_product_policy_snapshot_t) == 264U,
               "product policy snapshot ABI changed");
_Static_assert(sizeof(sakamoto_product_policy_rule_entry_t) == 120U,
               "product policy rule entry ABI changed");
_Static_assert(offsetof(sakamoto_product_policy_rule_entry_t, rule_id) == 80U,
               "product policy rule entry identity offset changed");
_Static_assert(offsetof(sakamoto_product_policy_rule_entry_t, source_address) == 88U,
               "product policy source address offset changed");
_Static_assert(offsetof(sakamoto_product_policy_rule_entry_t, destination_address) == 104U,
               "product policy destination address offset changed");
_Static_assert(sizeof(sakamoto_product_policy_bundle_t) == 15496U,
               "product policy bundle ABI changed");
_Static_assert(offsetof(sakamoto_product_policy_bundle_t, snapshot_identity) == 40U,
               "product policy bundle identity offset changed");
_Static_assert(offsetof(sakamoto_product_policy_bundle_t, gate_entries) == 136U,
               "product policy bundle Gate offset changed");
_Static_assert(offsetof(sakamoto_product_policy_bundle_t, l4_entries) == 7816U,
               "product policy bundle L4 offset changed");
_Static_assert(offsetof(sakamoto_product_status_t, generation) == 16U,
               "product status generation ABI changed");
_Static_assert(offsetof(sakamoto_product_status_t, artifact_id) == 52U,
               "product status identity ABI changed");
_Static_assert(sizeof(sakamoto_product_status_t) == 1304U,
               "product status ABI changed");
#endif

/* Opaque to Rust and to all callers except the bridge implementation. */
typedef struct sakamoto_product_session sakamoto_product_session_t;

uint32_t sakamoto_product_session_sni_query (
  sakamoto_product_session_t *, uint64_t generation, uint32_t worker,
  uint32_t slot, uint64_t incarnation, sakamoto_product_sni_status_t *);

uint32_t sakamoto_product_session_rule_config(
  sakamoto_product_session_t *, uint64_t generation,
  const sakamoto_product_rule_config_request_t *,
  sakamoto_product_rule_config_status_t *);

uint32_t sakamoto_product_abi_version(void);
uint32_t sakamoto_product_api_version(void);

uint32_t sakamoto_product_session_connect(
    sakamoto_product_bytes_t api_socket, uint64_t expected_generation,
    sakamoto_product_session_t **out_session,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_session_query(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    sakamoto_product_status_t *out_status);

uint32_t sakamoto_product_session_apply_policy(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    const sakamoto_product_policy_snapshot_t *snapshot,
    sakamoto_product_status_t *out_status);

/* One transaction for a complete successor Gate + L4 snapshot. */
uint32_t sakamoto_product_session_publish_network(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    const sakamoto_product_network_snapshot_t *snapshot);

/* Explicit supervisor stop; ordinary session disconnect MUST NOT stop VPP.
 * On OK, out_stopped is 0 (draining) or 1 (native debt zero and lanes closed).
 * Callers bound the interval between the first step and process cleanup. */
uint32_t sakamoto_product_session_stop_root(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    uint32_t *out_stopped);

uint32_t sakamoto_product_session_apply_policy_bundle(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    const sakamoto_product_policy_bundle_t *bundle,
    sakamoto_product_status_t *out_status);

/* Arm one debug-only, one-shot typed mutation fault on this generation. */
uint32_t sakamoto_product_session_set_policy_mutation_fault(
    sakamoto_product_session_t *session, uint64_t expected_generation,
    uint32_t fault_mode);

/* Retires transport state but keeps a tombstone so stale use is explicit. */
uint32_t sakamoto_product_session_disconnect(
    sakamoto_product_session_t *session);

/* Frees the tombstone; callers must not use the pointer afterward. */
uint32_t sakamoto_product_session_destroy(
    sakamoto_product_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
