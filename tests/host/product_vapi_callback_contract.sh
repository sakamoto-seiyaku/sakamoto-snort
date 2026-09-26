#!/usr/bin/env bash
set -euo pipefail

# Real generated VAPI headers/runtime are unavailable in this Host checkout.
# Compile the production bridge against a tiny API-shaped stub and exercise
# callback omission/error, pre-submit definite failure, null replies, and
# retval failures for both the scalar and typed policy apply paths. The bridge
# must preserve ambiguity as OUTCOME_UNKNOWN and issue only one native typed
# apply per call.

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
stub_dir="$(mktemp -d /tmp/sakamoto-vapi-callback-contract.XXXXXX)"
cleanup() {
  if [[ "${SAKAMOTO_VAPI_TEST_KEEP:-0}" == 1 ]]; then
    echo "VAPI test artifacts: $stub_dir"
    return
  fi
  rm -rf -- "$stub_dir"
}
trap cleanup EXIT
mkdir -p "$stub_dir/vapi"

cat > "$stub_dir/vapi/vapi_stub.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VAPI_STUB_H
#define SAKAMOTO_TEST_VAPI_STUB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void *vapi_ctx_t;
typedef unsigned int vapi_msg_id_t;
typedef int vapi_error_e;
typedef struct {
  uint32_t retval;
  uint32_t abi_version;
  uint32_t api_version;
  uint64_t generation;
  uint8_t core_ready;
  uint8_t adapter_available;
  uint8_t protection_running;
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
  uint32_t policy_gate_subject_uid;
  uint32_t policy_gate_network_context;
  uint8_t policy_gate_blocked;
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
  uint8_t policy_last_drop_uid_known;
  uint32_t policy_last_drop_device_direction;
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
  uint32_t policy_l4_view_active;
  uint32_t policy_l4_view_rule_count;
  uint32_t policy_l4_view_max_probes;
  uint32_t policy_l4_view_last_match_winner_rank;
  uint32_t policy_l4_view_last_match_probes;
  uint32_t policy_l4_view_last_match_candidate_count;
  uint32_t policy_l4_view_last_no_match_reason;
  uint64_t policy_l4_typed_match_policy_key;
  uint64_t policy_l4_typed_match_probe_key;
  uint64_t policy_l4_last_evaluation_probe_key;
  uint8_t artifact_id[96];
  uint8_t api_identity[96];
  uint8_t vpp_revision[48];
  uint8_t policy_snapshot_identity[96];
} vapi_payload_product_core_status_reply;
typedef struct {
  struct {
    uint32_t client_index;
    uint32_t context;
    uint16_t _vl_msg_id;
  } header;
} vapi_msg_product_core_status;
typedef struct {
  uint64_t generation;
  uint64_t requested_revision;
  uint64_t snapshot_hash;
  uint8_t snapshot_empty;
  uint8_t default_pass;
  uint32_t gate_claim_count;
  uint32_t l4_rule_count;
  uint32_t gate_subject_uid;
  uint32_t gate_network_context;
  uint8_t gate_blocked;
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
  uint8_t snapshot_identity[96];
} vapi_payload_product_core_policy_apply;
typedef struct {
  struct {
    uint32_t client_index;
    uint32_t context;
    uint16_t _vl_msg_id;
  } header;
  vapi_payload_product_core_policy_apply payload;
} vapi_msg_product_core_policy_apply;
typedef struct {
  int32_t retval;
} vapi_payload_product_core_policy_apply_reply;
typedef struct __attribute__((__packed__)) {
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
} vapi_type_product_policy_rule_entry;
typedef struct __attribute__((__packed__)) {
  int32_t retval;
} vapi_payload_product_core_policy_bundle_apply_reply;
typedef struct __attribute__((__packed__)) {
  uint64_t generation;
  uint32_t abi_version;
  uint32_t struct_size;
  uint64_t requested_revision;
  uint64_t snapshot_hash;
  uint32_t gate_entry_count;
  uint32_t l4_rule_count;
  uint32_t default_pass;
  uint32_t reserved;
  uint8_t snapshot_identity[96];
  vapi_type_product_policy_rule_entry gate_entries[64];
  vapi_type_product_policy_rule_entry l4_entries[64];
} vapi_payload_product_core_policy_bundle_apply;
typedef struct __attribute__((__packed__)) {
  uint16_t _vl_msg_id;
  uint32_t client_index;
  uint32_t context;
} vapi_msg_product_core_policy_bundle_apply_header;
typedef struct __attribute__((__packed__)) {
  vapi_msg_product_core_policy_bundle_apply_header header;
  vapi_payload_product_core_policy_bundle_apply payload;
} vapi_msg_product_core_policy_bundle_apply;
typedef vapi_error_e (*vapi_product_core_status_callback_t)(
  vapi_ctx_t, void *, vapi_error_e, bool,
  vapi_payload_product_core_status_reply *);
typedef vapi_error_e (*vapi_product_core_policy_apply_callback_t)(
  vapi_ctx_t, void *, vapi_error_e, bool,
  vapi_payload_product_core_policy_apply_reply *);
typedef vapi_error_e (*vapi_product_core_policy_bundle_apply_callback_t)(
  vapi_ctx_t, void *, vapi_error_e, bool,
  vapi_payload_product_core_policy_bundle_apply_reply *);
typedef struct { int32_t retval; } vapi_payload_product_core_network_publish_reply;
typedef struct {
  struct {
    uint64_t generation, revision, event_elapsed_ns;
    uint32_t count, reserved;
    struct { uint32_t linux_ifindex, network_context; } entries[32];
  } payload;
} vapi_msg_product_core_network_publish;
typedef vapi_error_e (*vapi_product_core_network_publish_callback_t)(
  vapi_ctx_t, void *, vapi_error_e, bool,
  vapi_payload_product_core_network_publish_reply *);

typedef struct { int32_t retval; uint64_t generation; uint32_t stopped; }
  vapi_payload_product_core_root_stop_reply;
typedef struct { struct { uint64_t generation; } payload; } vapi_msg_product_core_root_stop;
typedef vapi_error_e (*vapi_product_core_root_stop_callback_t)(
  vapi_ctx_t, void *, vapi_error_e, bool, vapi_payload_product_core_root_stop_reply *);

typedef struct { struct { uint64_t generation, incarnation; uint32_t worker, slot; } payload; } vapi_msg_product_core_sni_query;
typedef struct { int32_t retval; uint64_t generation, incarnation, protocols; uint32_t worker, slot, result, stop, attempts, bytes, work, cache_bytes, name_length, protocols_available; char name[254]; } vapi_payload_product_core_sni_query_reply;
typedef vapi_error_e (*vapi_product_core_sni_query_callback_t)(vapi_ctx_t,void *,vapi_error_e,bool,vapi_payload_product_core_sni_query_reply *);
extern vapi_msg_id_t vapi_msg_id_product_core_sni_query, vapi_msg_id_product_core_sni_query_reply;
vapi_msg_product_core_sni_query *vapi_alloc_product_core_sni_query(vapi_ctx_t);
vapi_error_e vapi_product_core_sni_query(vapi_ctx_t,vapi_msg_product_core_sni_query *,vapi_product_core_sni_query_callback_t,void *);
#include "sakamoto_product_rule_config.h"
typedef struct {
  struct { uint64_t generation; uint32_t schema, operation; uint64_t expected_saved_revision;
    sakamoto_product_config_rule_t rule; uint32_t count, reserved; sakamoto_product_direct_rule_t rules[256]; sakamoto_product_rule_graph_t graph; sakamoto_product_domains_t domains; sakamoto_product_config_metadata_t metadata; } payload;
} vapi_msg_product_core_rule_config;
typedef struct { int32_t retval; uint64_t generation, saved_revision, active_revision,
  saved_rule_version, active_rule_version; uint32_t result, save_error, compile_error;
  sakamoto_product_config_rule_t rule; uint32_t count, active_count, error_index, compiler_status; sakamoto_product_direct_rule_t rules[256]; uint64_t active_versions[256]; sakamoto_product_rule_graph_t graph; sakamoto_product_domains_t domains; sakamoto_product_config_metadata_t metadata; } vapi_payload_product_core_rule_config_reply;
typedef vapi_error_e (*vapi_product_core_rule_config_callback_t)(vapi_ctx_t, void *,
  vapi_error_e, bool, vapi_payload_product_core_rule_config_reply *);
extern vapi_msg_id_t vapi_msg_id_product_core_rule_config;
extern vapi_msg_id_t vapi_msg_id_product_core_rule_config_reply;
vapi_msg_product_core_rule_config *vapi_alloc_product_core_rule_config(vapi_ctx_t);
vapi_error_e vapi_product_core_rule_config(vapi_ctx_t, vapi_msg_product_core_rule_config *,
  vapi_product_core_rule_config_callback_t, void *);

#define VAPI_OK 0
#define VAPI_EINVAL 22
#define VAPI_MODE_BLOCKING 1
#define DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON \
  vapi_msg_id_t vapi_msg_id_memclnt;
#define DEFINE_VAPI_MSG_IDS_VLIB_API_JSON \
  vapi_msg_id_t vapi_msg_id_vlib;
#define DEFINE_VAPI_MSG_IDS_PRODUCT_CORE_API_JSON \
  vapi_msg_id_t vapi_msg_id_product_core_sni_query; \
  vapi_msg_id_t vapi_msg_id_product_core_sni_query_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_rule_config; \
  vapi_msg_id_t vapi_msg_id_product_core_rule_config_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_status; \
  vapi_msg_id_t vapi_msg_id_product_core_status_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_apply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_apply_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_network_publish; \
  vapi_msg_id_t vapi_msg_id_product_core_network_publish_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_root_stop; \
  vapi_msg_id_t vapi_msg_id_product_core_root_stop_reply;

extern vapi_msg_id_t vapi_msg_id_product_core_status;
extern vapi_msg_id_t vapi_msg_id_product_core_status_reply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_apply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_apply_reply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply_reply;
extern vapi_msg_id_t vapi_msg_id_product_core_network_publish;
extern vapi_msg_id_t vapi_msg_id_product_core_network_publish_reply;
extern vapi_msg_id_t vapi_msg_id_product_core_root_stop;
extern vapi_msg_id_t vapi_msg_id_product_core_root_stop_reply;
vapi_msg_product_core_root_stop *vapi_alloc_product_core_root_stop(vapi_ctx_t);
vapi_error_e vapi_product_core_root_stop(vapi_ctx_t, vapi_msg_product_core_root_stop *,
  vapi_product_core_root_stop_callback_t, void *);

vapi_error_e vapi_ctx_alloc(vapi_ctx_t *);
void vapi_ctx_free(vapi_ctx_t);
void vapi_msg_free(vapi_ctx_t, void *);
size_t vapi_get_request_count(vapi_ctx_t);
bool vapi_is_msg_available(vapi_ctx_t, vapi_msg_id_t);
vapi_error_e vapi_connect_ex(vapi_ctx_t, const char *, const char *, int, int,
                             int, bool, bool);
vapi_error_e vapi_disconnect(vapi_ctx_t);
vapi_msg_product_core_status *vapi_alloc_product_core_status(vapi_ctx_t);
vapi_error_e vapi_product_core_status(
  vapi_ctx_t, vapi_msg_product_core_status *,
  vapi_product_core_status_callback_t, void *);
vapi_msg_product_core_policy_apply *vapi_alloc_product_core_policy_apply(vapi_ctx_t);
vapi_error_e vapi_product_core_policy_apply(
  vapi_ctx_t, vapi_msg_product_core_policy_apply *,
  vapi_product_core_policy_apply_callback_t, void *);
vapi_msg_product_core_policy_bundle_apply *
vapi_alloc_product_core_policy_bundle_apply(vapi_ctx_t);
vapi_error_e vapi_product_core_policy_bundle_apply(
  vapi_ctx_t, vapi_msg_product_core_policy_bundle_apply *,
  vapi_product_core_policy_bundle_apply_callback_t, void *);
vapi_msg_product_core_network_publish *vapi_alloc_product_core_network_publish(vapi_ctx_t);
vapi_error_e vapi_product_core_network_publish(vapi_ctx_t,
  vapi_msg_product_core_network_publish *, vapi_product_core_network_publish_callback_t, void *);

extern int sakamoto_test_request_available;
extern int sakamoto_test_reply_available;
extern int sakamoto_test_policy_apply_available;
extern int sakamoto_test_policy_apply_reply_available;
extern int sakamoto_test_send_calls;
extern int sakamoto_test_policy_send_calls;
extern int sakamoto_test_policy_bundle_send_calls;
extern int sakamoto_test_send_invalid_id_calls;
extern int sakamoto_test_omit_callback;
extern int sakamoto_test_policy_omit_callback;
extern int sakamoto_test_policy_bundle_omit_callback;
extern int sakamoto_test_ctx_alloc_error;
extern int sakamoto_test_connect_error;
extern int sakamoto_test_alloc_message;
extern int sakamoto_test_policy_alloc_message;
extern int sakamoto_test_send_error;
extern int sakamoto_test_policy_send_error;
extern int sakamoto_test_policy_bundle_send_error;
extern int sakamoto_test_callback_error;
extern int sakamoto_test_policy_callback_error;
extern int sakamoto_test_policy_bundle_callback_error;
extern int sakamoto_test_null_reply;
extern int sakamoto_test_policy_null_reply;
extern int sakamoto_test_policy_bundle_null_reply;
extern int sakamoto_test_reply_retval;
extern int sakamoto_test_policy_reply_retval;
extern int sakamoto_test_policy_bundle_reply_retval;
extern int sakamoto_test_disconnect_error;

#endif
EOF
for header in memclnt.api.vapi.h vapi.h vlib.api.vapi.h product_core.api.vapi.h; do
  printf '%s\n' '#include "vapi_stub.h"' > "$stub_dir/vapi/$header"
done

cat > "$stub_dir/vapi_stub.c" <<'EOF'
#include "vapi/vapi_stub.h"
#include <stdlib.h>
#include <string.h>

int sakamoto_test_request_available = 1;
int sakamoto_test_reply_available = 1;
int sakamoto_test_policy_apply_available = 1;
int sakamoto_test_policy_apply_reply_available = 1;
int sakamoto_test_send_calls = 0;
int sakamoto_test_policy_send_calls = 0;
int sakamoto_test_policy_bundle_send_calls = 0;
int sakamoto_test_send_invalid_id_calls = 0;
int sakamoto_test_omit_callback = 0;
int sakamoto_test_policy_omit_callback = 0;
int sakamoto_test_policy_bundle_omit_callback = 0;
int sakamoto_test_ctx_alloc_error = 0;
int sakamoto_test_connect_error = 0;
int sakamoto_test_alloc_message = 0;
int sakamoto_test_policy_alloc_message = 0;
int sakamoto_test_send_error = 0;
int sakamoto_test_policy_send_error = 0;
int sakamoto_test_policy_bundle_send_error = 0;
int sakamoto_test_callback_error = 0;
int sakamoto_test_policy_callback_error = 0;
int sakamoto_test_policy_bundle_callback_error = 0;
int sakamoto_test_null_reply = 0;
int sakamoto_test_policy_null_reply = 0;
int sakamoto_test_policy_bundle_null_reply = 0;
int sakamoto_test_reply_retval = 0;
int sakamoto_test_policy_reply_retval = 0;
int sakamoto_test_policy_bundle_reply_retval = 0;
int sakamoto_test_disconnect_error = 0;
int sakamoto_test_network_send_calls = 0;
int sakamoto_test_network_omit_callback = 0;
int sakamoto_test_network_send_error = 0;
int sakamoto_test_context_count = 0;
int sakamoto_test_live_messages = 0;
static size_t pending_requests;
int sakamoto_test_rule_config_mode;
int sakamoto_test_rule_config_calls;
int sakamoto_test_root_stop_mode;
int sakamoto_test_root_stop_calls;

static void *test_message_alloc(size_t size)
{
  void *message = calloc(1, size);
  if (message) ++sakamoto_test_live_messages;
  return message;
}

void vapi_msg_free(vapi_ctx_t context, void *message)
{
  (void)context;
  if (--sakamoto_test_live_messages < 0) abort();
  free(message);
}

size_t vapi_get_request_count(vapi_ctx_t context)
{
  (void)context;
  return pending_requests;
}

vapi_error_e
vapi_ctx_alloc (vapi_ctx_t *context)
{
  if (sakamoto_test_ctx_alloc_error != 0)
    return sakamoto_test_ctx_alloc_error;
  *context = (vapi_ctx_t) (uintptr_t) 1U;
  ++sakamoto_test_context_count;
  pending_requests = 0;
  vapi_msg_id_product_core_status = 100U;
  vapi_msg_id_product_core_status_reply = 101U;
  vapi_msg_id_product_core_policy_apply = 102U;
  vapi_msg_id_product_core_policy_apply_reply = 103U;
  vapi_msg_id_product_core_policy_bundle_apply = 104U;
  vapi_msg_id_product_core_policy_bundle_apply_reply = 105U;
  vapi_msg_id_product_core_network_publish = 106U;
  vapi_msg_id_product_core_network_publish_reply = 107U;
  vapi_msg_id_product_core_root_stop = 108U;
  vapi_msg_id_product_core_root_stop_reply = 109U;
  vapi_msg_id_product_core_sni_query = 112U;
  vapi_msg_id_product_core_sni_query_reply = 113U;
  vapi_msg_id_product_core_rule_config = 110U;
  vapi_msg_id_product_core_rule_config_reply = 111U;
  return VAPI_OK;
}

void
vapi_ctx_free (vapi_ctx_t context)
{
  (void) context;
  if (--sakamoto_test_context_count < 0) abort();
}

bool
vapi_is_msg_available (vapi_ctx_t context, vapi_msg_id_t type)
{
  (void) context;
  if (type == vapi_msg_id_product_core_sni_query || type == vapi_msg_id_product_core_sni_query_reply) return true;
  if (type == vapi_msg_id_product_core_rule_config || type == vapi_msg_id_product_core_rule_config_reply) return true;
  if (type == vapi_msg_id_product_core_root_stop
      || type == vapi_msg_id_product_core_root_stop_reply)
    return sakamoto_test_root_stop_mode != 8;
  if (type == vapi_msg_id_product_core_status)
    return sakamoto_test_request_available != 0;
  if (type == vapi_msg_id_product_core_status_reply)
    return sakamoto_test_reply_available != 0;
  if (type == vapi_msg_id_product_core_policy_apply)
    return sakamoto_test_policy_apply_available != 0;
  if (type == vapi_msg_id_product_core_policy_apply_reply)
    return sakamoto_test_policy_apply_reply_available != 0;
  if (type == vapi_msg_id_product_core_policy_bundle_apply
      || type == vapi_msg_id_product_core_policy_bundle_apply_reply
      || type == vapi_msg_id_product_core_network_publish
      || type == vapi_msg_id_product_core_network_publish_reply)
    return true;
  return false;
}

vapi_error_e
vapi_connect_ex (vapi_ctx_t context, const char *name, const char *socket,
                 int retries, int timeout, int mode, bool do_pthread,
                 bool do_auto_handle)
{
  (void) context;
  (void) name;
  (void) socket;
  (void) retries;
  (void) timeout;
  (void) mode;
  (void) do_pthread;
  (void) do_auto_handle;
  if (sakamoto_test_connect_error != 0)
    return sakamoto_test_connect_error;
  return VAPI_OK;
}

vapi_error_e
vapi_disconnect (vapi_ctx_t context)
{
  (void) context;
  pending_requests = 0;
  return sakamoto_test_disconnect_error;
}

vapi_msg_product_core_rule_config *vapi_alloc_product_core_rule_config(vapi_ctx_t context)
{
  (void) context;
  return sakamoto_test_rule_config_mode == 7 ? NULL : test_message_alloc(sizeof(vapi_msg_product_core_rule_config));
}
vapi_error_e vapi_product_core_rule_config(vapi_ctx_t context, vapi_msg_product_core_rule_config *message,
  vapi_product_core_rule_config_callback_t callback, void *opaque)
{
  ++sakamoto_test_rule_config_calls;
  int mode = sakamoto_test_rule_config_mode;
  if (mode == 6) return VAPI_EINVAL;
  if (message->payload.schema != 1 || (message->payload.operation != 1 && message->payload.operation != 2)
      || message->payload.expected_saved_revision != 8 || message->payload.rule.uid != 12345
      || message->payload.rule.source_address[0] != 127) abort();
  if (message->payload.operation == 2 && (message->payload.count != 2
      || message->payload.rules[1].version != UINT64_C(0xfedcba9876540002)
      || message->payload.rules[1].network_context != 3 || message->payload.rules[1].ifindex != 7
      || message->payload.rules[1].source_port_last != 65000
      || message->payload.rules[1].source_address[15] != 1
      || message->payload.domains.list_count != 64 || message->payload.domains.entry_count != 1
      || message->payload.domains.entries[0].list != 63 || message->payload.domains.entries[0].mode != 1
      || message->payload.domains.entries[0].length != 11
      || memcmp(message->payload.domains.entries[0].name,"example.com",12)
      || strcmp((char *)message->payload.metadata.rules[1].name,"Imported rule")
      || strcmp((char *)message->payload.metadata.rules[1].source,"policy.json")
      || strcmp((char *)message->payload.metadata.lists[63].name,"Imported list")
      || strcmp((char *)message->payload.metadata.lists[63].source,"domains.txt"))) abort();
  vapi_payload_product_core_rule_config_reply reply = {
    .generation = message->payload.generation + (mode == 5),
    .saved_revision = 9, .active_revision = mode == 4 ? 8 : 9,
    .saved_rule_version = UINT64_C(0xfedcba9876540002),
    .active_rule_version = mode == 4 ? UINT64_C(0xfedcba9876540001) : UINT64_C(0xfedcba9876540002),
    .result = mode == 4 ? 4 : 0, .compile_error = mode == 4 ? 4 : 0,
    .rule = message->payload.rule,
  };
  reply.graph = message->payload.graph;
  reply.domains = message->payload.domains;
  reply.metadata = message->payload.metadata;
  reply.count = message->payload.count;
  reply.active_count = message->payload.count;
  memcpy (reply.rules, message->payload.rules, sizeof (reply.rules));
  reply.active_versions[1] = UINT64_C(0xfedcba9876540001);
  if (mode == 8) reply.count = 257;
  if (mode == 9) reply.domains.list_count = 65;
  if (mode == 10) reply.domains.entry_count = 257;
  if (mode == 11) { reply.domains.entry_count = 1; reply.domains.entries[0].length = 254; }
  vapi_msg_free(context, message);
  pending_requests = mode == 1;
  if (mode == 1) return VAPI_OK;
  return callback(context, opaque, mode == 2 ? VAPI_EINVAL : VAPI_OK, true, mode == 3 ? NULL : &reply);
}

vapi_msg_product_core_root_stop *
vapi_alloc_product_core_root_stop(vapi_ctx_t context)
{
  (void) context;
  return sakamoto_test_root_stop_mode == 9 ? NULL
    : test_message_alloc(sizeof(vapi_msg_product_core_root_stop));
}
vapi_error_e
vapi_product_core_root_stop(vapi_ctx_t context, vapi_msg_product_core_root_stop *message,
  vapi_product_core_root_stop_callback_t callback, void *opaque)
{
  ++sakamoto_test_root_stop_calls;
  int mode = sakamoto_test_root_stop_mode;
  if (mode == 6) return VAPI_EINVAL;
  vapi_payload_product_core_root_stop_reply reply = {
    .generation = message->payload.generation + (mode == 3),
    .stopped = mode == 1 ? 0 : (mode == 4 ? 2 : 1),
    .retval = mode == 5 ? -1 : 0,
  };
  vapi_msg_free(context, message);
  pending_requests = mode == 7;
  if (mode == 7) return VAPI_OK;
  return callback(context, opaque, mode == 10 ? VAPI_EINVAL : VAPI_OK,
                  true, mode == 2 ? NULL : &reply);
}

vapi_msg_product_core_network_publish *
vapi_alloc_product_core_network_publish(vapi_ctx_t context)
{
  (void) context;
  return test_message_alloc(sizeof(vapi_msg_product_core_network_publish));
}
vapi_error_e
vapi_product_core_network_publish(vapi_ctx_t context,
  vapi_msg_product_core_network_publish *message,
  vapi_product_core_network_publish_callback_t callback, void *opaque)
{
  ++sakamoto_test_network_send_calls;
  if (sakamoto_test_network_send_error) return sakamoto_test_network_send_error;
  vapi_msg_free(context, message);
  pending_requests = !!sakamoto_test_network_omit_callback;
  if (sakamoto_test_network_omit_callback) return VAPI_OK;
  vapi_payload_product_core_network_publish_reply reply = {0};
  return callback(context, opaque, VAPI_OK, true, &reply);
}

vapi_msg_product_core_status *
vapi_alloc_product_core_status (vapi_ctx_t context)
{
  (void) context;
  if (sakamoto_test_alloc_message != 0)
    return NULL;
  vapi_msg_product_core_status *message =
    test_message_alloc (sizeof (vapi_msg_product_core_status));
  if (message != NULL)
    message->header._vl_msg_id =
      sakamoto_test_request_available ? 7U : UINT16_MAX;
  return message;
}

vapi_error_e
vapi_product_core_status (vapi_ctx_t context,
                          vapi_msg_product_core_status *message,
                          vapi_product_core_status_callback_t callback,
                          void *callback_context)
{
  (void) context;
  ++sakamoto_test_send_calls;
  if (message->header._vl_msg_id == UINT16_MAX)
    ++sakamoto_test_send_invalid_id_calls;
  if (sakamoto_test_send_error != 0)
    return sakamoto_test_send_error;
  vapi_msg_free(context, message);
  pending_requests = !!sakamoto_test_omit_callback;
  if (sakamoto_test_omit_callback)
    return VAPI_OK;
  if (sakamoto_test_null_reply)
    {
      callback (context, callback_context, VAPI_OK, true, NULL);
      return VAPI_OK;
    }
  vapi_payload_product_core_status_reply reply = {0};
  reply.generation = 77U;
  reply.core_ready = 1U;
  reply.artifact_id[0] = 'a';
  reply.api_identity[0] = 'b';
  reply.vpp_revision[0] = 'c';
  reply.retval = (uint32_t) sakamoto_test_reply_retval;
  callback (context, callback_context,
            sakamoto_test_callback_error == 0 ? VAPI_OK
                                                : sakamoto_test_callback_error,
            true, &reply);
  return VAPI_OK;
}

vapi_msg_product_core_policy_apply *
vapi_alloc_product_core_policy_apply (vapi_ctx_t context)
{
  (void) context;
  if (sakamoto_test_policy_alloc_message != 0)
    return NULL;
  vapi_msg_product_core_policy_apply *message =
    test_message_alloc (sizeof (vapi_msg_product_core_policy_apply));
  if (message != NULL)
    message->header._vl_msg_id =
      sakamoto_test_policy_apply_available ? 9U : UINT16_MAX;
  return message;
}

vapi_error_e
vapi_product_core_policy_apply (
  vapi_ctx_t context, vapi_msg_product_core_policy_apply *message,
  vapi_product_core_policy_apply_callback_t callback, void *callback_context)
{
  (void) context;
  ++sakamoto_test_policy_send_calls;
  if (message->header._vl_msg_id == UINT16_MAX)
    ++sakamoto_test_send_invalid_id_calls;
  if (sakamoto_test_policy_send_error != 0)
    return sakamoto_test_policy_send_error;
  vapi_msg_free(context, message);
  pending_requests = !!sakamoto_test_policy_omit_callback;
  if (sakamoto_test_policy_omit_callback)
    return VAPI_OK;
  if (sakamoto_test_policy_null_reply)
    {
      callback (context, callback_context, VAPI_OK, true, NULL);
      return VAPI_OK;
    }
  vapi_payload_product_core_policy_apply_reply reply = {0};
  reply.retval = sakamoto_test_policy_reply_retval;
  callback (context, callback_context,
            sakamoto_test_policy_callback_error == 0
              ? VAPI_OK
              : sakamoto_test_policy_callback_error,
            true, &reply);
  return VAPI_OK;
}

vapi_msg_product_core_policy_bundle_apply *
vapi_alloc_product_core_policy_bundle_apply (vapi_ctx_t context)
{
  (void) context;
  vapi_msg_product_core_policy_bundle_apply *message =
    test_message_alloc (sizeof (vapi_msg_product_core_policy_bundle_apply));
  if (message != NULL)
    message->header._vl_msg_id = 11U;
  return message;
}

vapi_error_e
vapi_product_core_policy_bundle_apply (
  vapi_ctx_t context, vapi_msg_product_core_policy_bundle_apply *message,
  vapi_product_core_policy_bundle_apply_callback_t callback,
  void *callback_context)
{
  if (callback == NULL)
    return VAPI_EINVAL;
  ++sakamoto_test_policy_bundle_send_calls;
  if (sakamoto_test_policy_bundle_send_error != 0)
    return sakamoto_test_policy_bundle_send_error;
  vapi_msg_free(context, message);
  pending_requests = !!sakamoto_test_policy_bundle_omit_callback;
  if (sakamoto_test_policy_bundle_omit_callback)
    return VAPI_OK;
  if (sakamoto_test_policy_bundle_null_reply)
    {
      callback (context, callback_context, VAPI_OK, true, NULL);
      return VAPI_OK;
    }
  vapi_payload_product_core_policy_bundle_apply_reply reply = {0};
  reply.retval = sakamoto_test_policy_bundle_reply_retval;
  callback (context, callback_context,
            sakamoto_test_policy_bundle_callback_error == 0
              ? VAPI_OK
              : sakamoto_test_policy_bundle_callback_error,
            true, &reply);
  return VAPI_OK;
}
int sakamoto_test_sni_mode;
vapi_msg_product_core_sni_query *vapi_alloc_product_core_sni_query(vapi_ctx_t context)
{ (void)context;return test_message_alloc(sizeof(vapi_msg_product_core_sni_query)); }
vapi_error_e vapi_product_core_sni_query(vapi_ctx_t context,vapi_msg_product_core_sni_query *message,
  vapi_product_core_sni_query_callback_t callback,void *opaque)
{
  vapi_payload_product_core_sni_query_reply reply={.generation=message->payload.generation,
    .incarnation=message->payload.incarnation,.worker=message->payload.worker,.slot=message->payload.slot,
    .result=2,.stop=1};
  if(sakamoto_test_sni_mode==6) return VAPI_EINVAL;
  vapi_msg_free(context,message);
  if(sakamoto_test_sni_mode==1) ++reply.generation;
  if(sakamoto_test_sni_mode==2) ++reply.incarnation;
  if(sakamoto_test_sni_mode==3) return callback(context,opaque,VAPI_OK,true,NULL);
  if(sakamoto_test_sni_mode==4) {pending_requests=1;return VAPI_OK;}
  if(sakamoto_test_sni_mode==5) reply.name_length=254;
  if(sakamoto_test_sni_mode==7) reply.retval=-5;
  if(sakamoto_test_sni_mode>=8) {reply.result=0;reply.stop=(uint32_t)sakamoto_test_sni_mode+1;}
  return callback(context,opaque,VAPI_OK,true,&reply);
}

EOF

cat > "$stub_dir/harness.c" <<'EOF'
#include "sakamoto_product_abi.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int sakamoto_test_request_available;
extern int sakamoto_test_reply_available;
extern int sakamoto_test_policy_apply_available;
extern int sakamoto_test_policy_apply_reply_available;
extern int sakamoto_test_send_calls;
extern int sakamoto_test_policy_send_calls;
extern int sakamoto_test_policy_bundle_send_calls;
extern int sakamoto_test_send_invalid_id_calls;
extern int sakamoto_test_omit_callback;
extern int sakamoto_test_policy_omit_callback;
extern int sakamoto_test_policy_bundle_omit_callback;
extern int sakamoto_test_ctx_alloc_error;
extern int sakamoto_test_connect_error;
extern int sakamoto_test_alloc_message;
extern int sakamoto_test_policy_alloc_message;
extern int sakamoto_test_send_error;
extern int sakamoto_test_policy_send_error;
extern int sakamoto_test_policy_bundle_send_error;
extern int sakamoto_test_callback_error;
extern int sakamoto_test_policy_callback_error;
extern int sakamoto_test_policy_bundle_callback_error;
extern int sakamoto_test_null_reply;
extern int sakamoto_test_policy_null_reply;
extern int sakamoto_test_policy_bundle_null_reply;
extern int sakamoto_test_reply_retval;
extern int sakamoto_test_policy_reply_retval;
extern int sakamoto_test_policy_bundle_reply_retval;
extern int sakamoto_test_disconnect_error;
extern int sakamoto_test_network_send_calls;
extern int sakamoto_test_network_omit_callback;
extern int sakamoto_test_network_send_error;
extern int sakamoto_test_context_count;
extern int sakamoto_test_live_messages;
extern int sakamoto_test_rule_config_mode;
extern int sakamoto_test_rule_config_calls;
extern int sakamoto_test_root_stop_mode;
extern int sakamoto_test_root_stop_calls;
static sakamoto_product_session_t **current_session;
static int expect_retired(sakamoto_product_session_t *session);

static void
reset_faults (void)
{
  sakamoto_test_ctx_alloc_error = 0;
  sakamoto_test_connect_error = 0;
  sakamoto_test_alloc_message = 0;
  sakamoto_test_send_error = 0;
  sakamoto_test_policy_send_error = 0;
  sakamoto_test_policy_bundle_send_error = 0;
  sakamoto_test_callback_error = 0;
  sakamoto_test_policy_callback_error = 0;
  sakamoto_test_policy_bundle_callback_error = 0;
  sakamoto_test_null_reply = 0;
  sakamoto_test_policy_null_reply = 0;
  sakamoto_test_policy_bundle_null_reply = 0;
  sakamoto_test_reply_retval = 0;
  sakamoto_test_policy_reply_retval = 0;
  sakamoto_test_policy_bundle_reply_retval = 0;
  sakamoto_test_disconnect_error = 0;
  sakamoto_test_omit_callback = 0;
  sakamoto_test_policy_omit_callback = 0;
  sakamoto_test_policy_bundle_omit_callback = 0;
  sakamoto_test_policy_alloc_message = 0;
  sakamoto_test_network_omit_callback = 0;
  sakamoto_test_network_send_error = 0;
  sakamoto_test_root_stop_mode = 0;
  sakamoto_test_rule_config_mode = 0;
  // Transport dispatch failures now retire the session. Each independent
  // fault case starts with a new handle instead of reusing retired callbacks.
  if (current_session && *current_session) {
    int stops_before_close = sakamoto_test_root_stop_calls;
    if (sakamoto_product_session_destroy(*current_session)) abort();
    if (stops_before_close != sakamoto_test_root_stop_calls) {
      fprintf(stderr, "ordinary session close stopped the runtime\n");
      abort();
    }
    const char socket_path[] = "/tmp/unused-vapi-callback-contract.sock";
    sakamoto_product_bytes_t path = {(const uint8_t *)socket_path, sizeof(socket_path) - 1};
    sakamoto_product_status_t status;
    if (sakamoto_product_session_connect(path, 77, current_session, &status)) abort();
  }
}

static int
expect_connect_code (sakamoto_product_bytes_t path, uint32_t expected,
                     const char *case_name)
{
  sakamoto_product_session_t *session = NULL;
  sakamoto_product_status_t status;
  uint32_t code = sakamoto_product_session_connect (path, 77U, &session,
                                                     &status);
  if (code != expected || status.status_code != expected || session != NULL)
    {
      fprintf (stderr, "%s: got code=%u status=%u session=%p expected=%u\n",
               case_name, code, status.status_code, (void *) session, expected);
      if (session != NULL)
        sakamoto_product_session_destroy (session);
      return 1;
    }
  return 0;
}

static int
expect_connect_code_detail (sakamoto_product_bytes_t path, uint32_t expected,
                            const char *detail, const char *case_name)
{
  sakamoto_product_session_t *session = NULL;
  sakamoto_product_status_t status;
  uint32_t code = sakamoto_product_session_connect (path, 77U, &session,
                                                     &status);
  if (code != expected || status.status_code != expected || session != NULL
      || strstr (status.error_detail, detail) == NULL)
    {
      fprintf (stderr, "%s: got code=%u status=%u detail=%s expected=%u/%s\n",
               case_name, code, status.status_code, status.error_detail,
               expected, detail);
      if (session != NULL)
        sakamoto_product_session_destroy (session);
      return 1;
    }
  return 0;
}

static int
expect_query_code_detail (sakamoto_product_session_t *session,
                          uint32_t expected, const char *detail,
                          const char *case_name)
{
  sakamoto_product_status_t status;
  uint32_t code = sakamoto_product_session_query (session, 77U, &status);
  if (code != expected || status.status_code != expected
      || strstr (status.error_detail, detail) == NULL)
    {
      fprintf (stderr, "%s: got code=%u status=%u detail=%s expected=%u/%s\n",
               case_name, code, status.status_code, status.error_detail,
               expected, detail);
      return 1;
    }
  return (sakamoto_test_send_error || sakamoto_test_omit_callback)
    ? expect_retired(session) : 0;
}

static sakamoto_product_policy_snapshot_t
valid_empty_policy (void)
{
  sakamoto_product_policy_snapshot_t snapshot;
  memset (&snapshot, 0, sizeof (snapshot));
  snapshot.schema_version = 1;
  snapshot.requested_revision = 1;
  snapshot.snapshot_hash = 12345;
  snapshot.snapshot_empty = 1;
  snapshot.default_pass = 1;
  memcpy (snapshot.snapshot_identity, "empty-policy/v1/revision-1",
          sizeof ("empty-policy/v1/revision-1"));
  return snapshot;
}

static sakamoto_product_policy_bundle_t
valid_empty_policy_bundle (void)
{
  sakamoto_product_policy_bundle_t bundle;
  memset (&bundle, 0, sizeof (bundle));
  bundle.abi_version = SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION;
  bundle.struct_size = (uint32_t) sizeof (bundle);
  bundle.requested_revision = 1U;
  bundle.snapshot_hash = 12345U;
  bundle.default_pass = 1U;
  memcpy (bundle.snapshot_identity, "bundle/v1",
          sizeof ("bundle/v1"));
  return bundle;
}

static int expect_retired(sakamoto_product_session_t *session)
{
  uint32_t stopped = 99;
  sakamoto_product_network_snapshot_t network = {.revision = 2};
  sakamoto_product_status_t status;
  sakamoto_product_policy_snapshot_t scalar = valid_empty_policy();
  sakamoto_product_policy_bundle_t bundle = valid_empty_policy_bundle();
  int sends = sakamoto_test_network_send_calls + sakamoto_test_send_calls
    + sakamoto_test_policy_send_calls + sakamoto_test_policy_bundle_send_calls
    + sakamoto_test_root_stop_calls;
  if (sakamoto_product_session_publish_network(session, 77, &network) != SAKAMOTO_PRODUCT_STALE_HANDLE
      || sakamoto_product_session_query(session, 77, &status) != SAKAMOTO_PRODUCT_STALE_HANDLE
      || sakamoto_product_session_apply_policy(session, 77, &scalar, &status) != SAKAMOTO_PRODUCT_STALE_HANDLE
      || sakamoto_product_session_apply_policy_bundle(session, 77, &bundle, &status) != SAKAMOTO_PRODUCT_STALE_HANDLE
      || sakamoto_product_session_stop_root(session, 77, &stopped) != SAKAMOTO_PRODUCT_STALE_HANDLE
      || stopped != 0
      || sends != sakamoto_test_network_send_calls + sakamoto_test_send_calls
        + sakamoto_test_policy_send_calls + sakamoto_test_policy_bundle_send_calls
        + sakamoto_test_root_stop_calls) {
    fprintf(stderr, "retired VAPI context admitted a subsequent generated request\n");
    return 1;
  }
  return 0;
}

static int
expect_policy_code_detail (sakamoto_product_session_t *session,
                           uint32_t expected, const char *detail,
                           const char *case_name)
{
  sakamoto_product_status_t status;
  sakamoto_product_policy_snapshot_t snapshot = valid_empty_policy ();
  uint32_t code = sakamoto_product_session_apply_policy (session, 77U,
                                                         &snapshot, &status);
  if (code != expected || status.status_code != expected
      || strstr (status.error_detail, detail) == NULL)
    {
      fprintf (stderr, "%s: got code=%u status=%u detail=%s expected=%u/%s\n",
               case_name, code, status.status_code, status.error_detail,
               expected, detail);
      return 1;
    }
  return (sakamoto_test_policy_send_error || sakamoto_test_policy_omit_callback)
    ? expect_retired(session) : 0;
}

static int
expect_policy_bundle_code_detail (sakamoto_product_session_t *session,
                                  uint32_t expected, const char *detail,
                                  const char *case_name)
{
  sakamoto_product_status_t status;
  sakamoto_product_policy_bundle_t bundle = valid_empty_policy_bundle ();
  int status_send_calls = sakamoto_test_send_calls;
  sakamoto_test_policy_bundle_send_calls = 0;
  uint32_t code = sakamoto_product_session_apply_policy_bundle (
    session, 77U, &bundle, &status);
  if (code != expected || status.status_code != expected
      || strstr (status.error_detail, detail) == NULL
      || sakamoto_test_policy_bundle_send_calls != 1
      || sakamoto_test_send_calls != status_send_calls)
    {
      fprintf (stderr,
               "%s: got code=%u status=%u detail=%s bundle_sends=%d "
               "status_sends=%d expected=%u/%s/1/%d\n",
               case_name, code, status.status_code, status.error_detail,
               sakamoto_test_policy_bundle_send_calls,
               sakamoto_test_send_calls, expected, detail, status_send_calls);
      return 1;
    }
  return (sakamoto_test_policy_bundle_send_error || sakamoto_test_policy_bundle_omit_callback)
    ? expect_retired(session) : 0;
}

int
main (void)
{
  const char socket_path[] = "/tmp/unused-vapi-callback-contract.sock";
  sakamoto_product_bytes_t path = {
    .data = (const uint8_t *) socket_path,
    .length = (uint32_t) (sizeof (socket_path) - 1U),
  };
  sakamoto_product_session_t *session = NULL;
  sakamoto_product_status_t status;

  sakamoto_test_ctx_alloc_error = 99;
  if (expect_connect_code (path, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                           "VAPI context allocation") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_connect_error = 99;
  if (expect_connect_code (path, SAKAMOTO_PRODUCT_CONNECT_FAILED,
                           "VAPI connect") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_alloc_message = 1;
  if (expect_connect_code (path, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                           "VAPI request allocation") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_send_error = 99;
  if (expect_connect_code_detail (path, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                  "VAPI status request send failed",
                                  "VAPI request send") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_callback_error = 99;
  if (expect_connect_code_detail (path, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                  "VAPI status callback failed",
                                  "VAPI callback error") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_null_reply = 1;
  if (expect_connect_code_detail (path, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                  "VAPI status callback returned a null reply",
                                  "VAPI null reply") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_reply_retval = 17;
  if (expect_connect_code_detail (path, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                  "VPP status request returned retval=17",
                                  "VPP retval") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_send_calls = 0;
  sakamoto_test_send_invalid_id_calls = 0;

  sakamoto_test_request_available = 0;
  sakamoto_test_reply_available = 1;
  uint32_t code = sakamoto_product_session_connect (path, 77U, &session,
                                                    &status);
  if (code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || status.status_code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || session != NULL || sakamoto_test_send_calls != 0
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "missing VAPI request must not allocate/send\n");
      return 1;
    }

  sakamoto_test_request_available = 1;
  sakamoto_test_reply_available = 0;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || status.status_code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || session != NULL || sakamoto_test_send_calls != 0
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "missing VAPI reply must not allocate/send\n");
      return 1;
    }

  sakamoto_test_request_available = 1;
  sakamoto_test_reply_available = 1;
  sakamoto_test_policy_apply_available = 0;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || status.status_code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || session != NULL || sakamoto_test_send_calls != 0
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "missing VAPI policy apply must not allocate/send\n");
      return 1;
    }

  sakamoto_test_policy_apply_available = 1;
  sakamoto_test_policy_apply_reply_available = 0;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || status.status_code != SAKAMOTO_PRODUCT_API_UNAVAILABLE
      || session != NULL || sakamoto_test_send_calls != 0
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "missing VAPI policy apply reply must not allocate/send\n");
      return 1;
    }

  sakamoto_test_policy_apply_reply_available = 1;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_OK || session == NULL
      || sakamoto_test_send_calls != 1
      || sakamoto_test_send_invalid_id_calls != 0)
    {
      fprintf (stderr, "available VAPI messages did not use the normal path\n");
      return 1;
    }

  sakamoto_product_policy_bundle_t bundle = valid_empty_policy_bundle ();
  current_session = &session;
  const uint32_t config_codes[] = {0, 14, 14, 14, 0, 5, 14, 2, 14, 14, 14, 14};
  for (unsigned operation = 1; operation <= 2; ++operation)
  for (unsigned mode = 0; mode < sizeof(config_codes)/sizeof(config_codes[0]); ++mode) {
    reset_faults();
    sakamoto_test_rule_config_mode = mode;
    sakamoto_product_rule_config_request_t request = {
      .schema = 1, .operation = operation, .expected_saved_revision = 8,
      .rule = {.present = 1, .uid = 12345, .protocol = 17, .direction = 3, .action = 2,
        .source_port = 32000, .destination_port = 40608, .source_address = {127,0,0,1},
        .destination_address = {127,0,0,2}}
    };
    if (operation == 2) {
      request.graph = (sakamoto_product_rule_graph_t){.group_count=1,.groups={10},.edge_count=1,.edges={{10,1,1}},.binding_count=1,.bindings={{7,12345,2,10,1}}};
      request.domains = (sakamoto_product_domains_t){.list_count=64,.entry_count=1,
        .entries={{.list=63,.mode=1,.length=11,.name="example.com"}}};
      strcpy((char *)request.metadata.rules[1].name,"Imported rule");
      strcpy((char *)request.metadata.rules[1].source,"policy.json");
      strcpy((char *)request.metadata.lists[63].name,"Imported list");
      strcpy((char *)request.metadata.lists[63].source,"domains.txt");
      request.count = 2;
      request.rules[1] = (sakamoto_product_direct_rule_t) {
        .version = UINT64_C(0xfedcba9876540002), .uid = 12345, .network_context = 3, .ifindex = 7,
        .family = 6, .protocol = 6, .direction = 1, .action = 2,
        .source_port_first = 100, .source_port_last = 65000,
        .source_address = {0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1}
      };
    }
    sakamoto_product_rule_config_status_t config;
    int before = sakamoto_test_rule_config_calls;
    code = sakamoto_product_session_rule_config(session, 77, &request, &config);
    if (code != config_codes[mode] || sakamoto_test_rule_config_calls-before != (mode != 7)) {
      fprintf(stderr, "rule config mode=%u code=%u calls=%d\n", mode, code, sakamoto_test_rule_config_calls-before); return 1;
    }
    if (!code && (config.saved_revision != 9 || config.active_revision != (mode == 4 ? 8U : 9U)
        || config.saved_rule_version != UINT64_C(0xfedcba9876540002)
        || config.result != (mode == 4 ? 4U : 0U) || config.rule.uid != 12345)) return 1;
    if (!code && operation == 2 && (config.count != 2 || config.active_count != 2
        || config.rules[1].version != UINT64_C(0xfedcba9876540002)
        || config.rules[1].network_context != 3 || config.rules[1].ifindex != 7
        || config.rules[1].source_port_last != 65000 || config.rules[1].source_address[15] != 1
        || config.active_versions[1] != UINT64_C(0xfedcba9876540001)
        || config.graph.group_count != 1 || config.graph.groups[0] != 10
        || config.graph.edge_count != 1 || config.graph.edges[0].target != 1
        || config.graph.binding_count != 1 || config.graph.bindings[0].uid != 12345 || config.graph.bindings[0].mode != 1
        || memcmp(&config.domains,&request.domains,sizeof config.domains)
        || memcmp(&config.metadata,&request.metadata,sizeof config.metadata))) return 1;
    if ((mode == 1 || mode == 2 || mode == 3 || mode == 5 || mode == 6 || mode >= 8)
        && expect_retired(session)) return 1;
  }
  reset_faults();
  const uint32_t stop_codes[] = {
    SAKAMOTO_PRODUCT_OK, SAKAMOTO_PRODUCT_OK, SAKAMOTO_PRODUCT_INTERNAL_ERROR,
    SAKAMOTO_PRODUCT_STALE_HANDLE, SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH,
    SAKAMOTO_PRODUCT_PROTOCOL_MISMATCH, SAKAMOTO_PRODUCT_INTERNAL_ERROR,
    SAKAMOTO_PRODUCT_INTERNAL_ERROR, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
    SAKAMOTO_PRODUCT_ALLOCATION_FAILED, SAKAMOTO_PRODUCT_INTERNAL_ERROR,
  };
  uint32_t stopped = 99;
  if (sakamoto_product_session_stop_root(NULL, 77, &stopped)
        != SAKAMOTO_PRODUCT_INVALID_ARGUMENT || stopped != 0
      || sakamoto_product_session_stop_root(session, 0, &stopped)
        != SAKAMOTO_PRODUCT_INVALID_ARGUMENT
      || sakamoto_product_session_stop_root(session, 77, NULL)
        != SAKAMOTO_PRODUCT_INVALID_ARGUMENT
      || sakamoto_product_session_stop_root(session, 76, &stopped)
        != SAKAMOTO_PRODUCT_STALE_HANDLE || sakamoto_test_root_stop_calls != 0)
    return 1;
  for (unsigned mode = 0; mode < sizeof(stop_codes)/sizeof(stop_codes[0]); ++mode) {
    reset_faults();
    sakamoto_test_root_stop_mode = (int)mode;
    int before = sakamoto_test_root_stop_calls;
    stopped = 99;
    code = sakamoto_product_session_stop_root(session, 77, &stopped);
    if (code != stop_codes[mode] || stopped != (mode == 0)
        || sakamoto_test_root_stop_calls - before != (mode != 8 && mode != 9)) {
      fprintf(stderr, "root stop mode=%u code=%u stopped=%u calls=%d\n",
        mode, code, stopped, sakamoto_test_root_stop_calls - before);
      return 1;
    }
    if ((mode == 6 || mode == 7) && expect_retired(session)) return 1;
  }
  reset_faults();
  /* A real blocking VAPI failure may retain a stack callback. No subsequent
   * network publication, query or policy request may reach that context. */
  sakamoto_product_network_snapshot_t network = {.revision = 1};
  sakamoto_test_network_omit_callback = 1;
  if (sakamoto_product_session_publish_network(session, 77, &network)
      != SAKAMOTO_PRODUCT_INTERNAL_ERROR) return 1;
  int network_sends = sakamoto_test_network_send_calls;
  int old_status_sends = sakamoto_test_send_calls;
  int old_policy_sends = sakamoto_test_policy_bundle_send_calls;
  if (sakamoto_product_session_publish_network(session, 77, &network)
        != SAKAMOTO_PRODUCT_STALE_HANDLE
      || sakamoto_product_session_query(session, 77, &status)
        != SAKAMOTO_PRODUCT_STALE_HANDLE
      || sakamoto_product_session_apply_policy_bundle(session, 77, &bundle, &status)
        != SAKAMOTO_PRODUCT_STALE_HANDLE
      || network_sends != sakamoto_test_network_send_calls
      || old_status_sends != sakamoto_test_send_calls
      || old_policy_sends != sakamoto_test_policy_bundle_send_calls) {
    fprintf(stderr, "failed dispatch allowed another request on a retired callback context\n");
    return 1;
  }
  reset_faults();
  sakamoto_test_network_send_error = 99;
  if (sakamoto_product_session_publish_network(session, 77, &network)
      != SAKAMOTO_PRODUCT_INTERNAL_ERROR || expect_retired(session)) return 1;
  reset_faults();
  sakamoto_test_policy_bundle_send_calls = 0;
  code = sakamoto_product_session_apply_policy_bundle (session, 77U, &bundle,
                                                       &status);
  if (code != SAKAMOTO_PRODUCT_OK || status.status_code != SAKAMOTO_PRODUCT_OK
      || sakamoto_test_policy_bundle_send_calls != 1
      || status.generation != 77U)
    {
      fprintf (stderr, "typed policy bundle did not use one native apply\n");
      return 1;
    }

  /* The debug pre-submit seam is one-shot and must not call generated VAPI.
   * It is a definite failure because this harness knows the request was never
   * submitted; Product Core may discard the staged successor and retry. */
  reset_faults ();
  if (sakamoto_product_session_set_policy_mutation_fault (
        session, 77U,
        SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT)
      != SAKAMOTO_PRODUCT_OK)
    {
      fprintf (stderr, "could not arm pre-submit policy fault\n");
      return 1;
    }
  int status_send_calls = sakamoto_test_send_calls;
  sakamoto_test_policy_bundle_send_calls = 0;
  code = sakamoto_product_session_apply_policy_bundle (session, 77U, &bundle,
                                                       &status);
  if (code != SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED
      || status.status_code != SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED
      || strstr (status.error_detail, "was not submitted") == NULL
      || sakamoto_test_policy_bundle_send_calls != 0
      || sakamoto_test_send_calls != status_send_calls)
    {
      fprintf (stderr,
               "pre-submit policy fault crossed VAPI boundary: code=%u "
               "status=%u detail=%s bundle_sends=%d status_sends=%d\n",
               code, status.status_code, status.error_detail,
               sakamoto_test_policy_bundle_send_calls,
               sakamoto_test_send_calls);
      return 1;
    }

  /* A consumed arm cannot affect the following successor. */
  reset_faults ();
  sakamoto_test_policy_bundle_send_calls = 0;
  code = sakamoto_product_session_apply_policy_bundle (session, 77U, &bundle,
                                                       &status);
  if (code != SAKAMOTO_PRODUCT_OK || status.status_code != SAKAMOTO_PRODUCT_OK
      || sakamoto_test_policy_bundle_send_calls != 1)
    {
      fprintf (stderr, "pre-submit policy fault was not one-shot\n");
      return 1;
    }

  /* Exercise the same callback-omission mode used by the installed seam,
   * rather than only the lower-level test callback toggle. */
  reset_faults ();
  if (sakamoto_product_session_set_policy_mutation_fault (
        session, 77U,
        SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK)
      != SAKAMOTO_PRODUCT_OK)
    {
      fprintf (stderr, "could not arm callback-omission policy fault\n");
      return 1;
    }
  if (expect_policy_bundle_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy bundle apply callback was not invoked",
        "debug armed typed policy callback omission") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_policy_bundle_send_error = 99;
  if (expect_policy_bundle_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy bundle apply request send failed",
        "VAPI typed policy bundle send") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_bundle_callback_error = 99;
  if (expect_policy_bundle_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy bundle apply callback failed",
        "VAPI typed policy bundle callback") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_bundle_null_reply = 1;
  if (expect_policy_bundle_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy bundle apply callback returned a null reply",
        "VAPI typed policy bundle null reply") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_bundle_reply_retval = 17;
  if (expect_policy_bundle_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED,
        "VPP policy bundle apply returned retval=17",
        "VAPI typed policy bundle retval") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_bundle_omit_callback = 1;
  if (expect_policy_bundle_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy bundle apply callback was not invoked",
        "VAPI typed policy bundle callback omission") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_policy_send_error = 99;
  if (expect_policy_code_detail (session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                                 "VAPI policy apply request send failed",
                                 "VAPI policy send") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_callback_error = 99;
  if (expect_policy_code_detail (session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                                 "VAPI policy apply callback failed",
                                 "VAPI policy callback") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_null_reply = 1;
  if (expect_policy_code_detail (
        session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy apply callback returned a null reply",
        "VAPI policy null reply") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_reply_retval = 17;
  if (expect_policy_code_detail (session, SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED,
                                 "VPP policy apply returned retval=17",
                                 "VAPI policy retval") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_policy_omit_callback = 1;
  if (expect_policy_code_detail (session, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                                 "VAPI policy apply callback was not invoked",
                                 "VAPI policy callback omission") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_send_error = 99;
  if (expect_query_code_detail (session, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                "VAPI status request send failed",
                                "VAPI query send") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_callback_error = 99;
  if (expect_query_code_detail (session, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                "VAPI status callback failed",
                                "VAPI query callback") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_null_reply = 1;
  if (expect_query_code_detail (session, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                "VAPI status callback returned a null reply",
                                "VAPI query null reply") != 0)
    return 1;
  reset_faults ();
  sakamoto_test_reply_retval = 17;
  if (expect_query_code_detail (session, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                "VPP status request returned retval=17",
                                "VAPI query VPP retval") != 0)
    return 1;
  reset_faults ();

  sakamoto_test_disconnect_error = 99;
  code = sakamoto_product_session_disconnect (session);
  if (code != SAKAMOTO_PRODUCT_DISCONNECT_FAILED)
    {
      fprintf (stderr, "VAPI disconnect failure was not preserved: got %u\n",
               code);
      sakamoto_product_session_destroy (session);
      return 1;
    }
  sakamoto_test_disconnect_error = 0;
  sakamoto_product_session_destroy (session);
  session = NULL;

  sakamoto_test_omit_callback = 1;
  code = sakamoto_product_session_connect (path, 77U, &session, &status);
  if (code != SAKAMOTO_PRODUCT_QUERY_FAILED
      || status.status_code != SAKAMOTO_PRODUCT_QUERY_FAILED
      || strstr (status.error_detail, "callback was not invoked") == NULL
      || session != NULL)
    {
      fprintf (stderr, "callback omission was not reported as QUERY_FAILED\n");
      return 1;
    }
  reset_faults();
  extern int sakamoto_test_sni_mode;
  for(int mode=0;mode<13;++mode) {
    sakamoto_test_sni_mode=mode;
    sakamoto_product_sni_status_t facts={0};
    if(sakamoto_product_session_connect(path,77U,&session,&status)) return 1;
    uint32_t expected=(mode==0 || (mode>=8 && mode<=11))?SAKAMOTO_PRODUCT_OK:mode==7?SAKAMOTO_PRODUCT_STALE_HANDLE:SAKAMOTO_PRODUCT_QUERY_FAILED;
    code=sakamoto_product_session_sni_query(session,77U,1,2,3,&facts);
    if(code!=expected || (mode==0 && (facts.result!=2 || facts.incarnation!=3))
       || (mode!=0 && facts.result)
       || (mode>=8 && mode<=11 && facts.stop!=(uint32_t)mode+1)) return 1;
    if(mode>0 && mode<7 && sakamoto_product_session_sni_query(session,77U,1,2,3,&facts)!=SAKAMOTO_PRODUCT_STALE_HANDLE) return 1;
    sakamoto_product_session_destroy(session);session=NULL;
  }
  if (sakamoto_test_context_count != 0) {
    fprintf(stderr, "retired VAPI context was not reclaimed\n");
    return 1;
  }
  if (sakamoto_test_live_messages != 0) {
    fprintf(stderr, "unsent VAPI messages were not reclaimed: %d\n", sakamoto_test_live_messages);
    return 1;
  }
  return 0;
}
EOF

test_flags=()
if [[ "${SAKAMOTO_VAPI_TEST_SANITIZE:-0}" == 1 ]]; then
  # This host's Clang 14 PIE sanitizer can crash in AsanInitInternal/mmap
  # before main. Fix only this throwaway checker address layout; never the
  # Product binaries or system-wide ASLR policy.
  test_flags=(-g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie -no-pie)
fi
"${SAKAMOTO_VAPI_TEST_CC:-cc}" -std=c11 -Wall -Wextra -Werror -pthread "${test_flags[@]}" \
  -I"$repo_root/src/product/include" -I"$repo_root/src/product/native" -I"$stub_dir" \
  "${SAKAMOTO_VAPI_BRIDGE_TEST_SOURCE:-$repo_root/src/product/native/sakamoto_product_vapi.c}" \
  "$stub_dir/vapi_stub.c" "$stub_dir/harness.c" \
  -o "$stub_dir/callback-contract"
"$stub_dir/callback-contract"
echo "sakamoto production VAPI callback contract: PASS"
