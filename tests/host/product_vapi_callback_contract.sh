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
  uint32_t product_graph_flow_domain;
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

#define VAPI_OK 0
#define VAPI_EINVAL 22
#define VAPI_MODE_BLOCKING 1
#define DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON \
  vapi_msg_id_t vapi_msg_id_memclnt;
#define DEFINE_VAPI_MSG_IDS_VLIB_API_JSON \
  vapi_msg_id_t vapi_msg_id_vlib;
#define DEFINE_VAPI_MSG_IDS_PRODUCT_CORE_API_JSON \
  vapi_msg_id_t vapi_msg_id_product_core_status; \
  vapi_msg_id_t vapi_msg_id_product_core_status_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_apply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_apply_reply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply; \
  vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply_reply;

extern vapi_msg_id_t vapi_msg_id_product_core_status;
extern vapi_msg_id_t vapi_msg_id_product_core_status_reply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_apply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_apply_reply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply;
extern vapi_msg_id_t vapi_msg_id_product_core_policy_bundle_apply_reply;

vapi_error_e vapi_ctx_alloc(vapi_ctx_t *);
void vapi_ctx_free(vapi_ctx_t);
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

vapi_error_e
vapi_ctx_alloc (vapi_ctx_t *context)
{
  if (sakamoto_test_ctx_alloc_error != 0)
    return sakamoto_test_ctx_alloc_error;
  *context = (vapi_ctx_t) (uintptr_t) 1U;
  vapi_msg_id_product_core_status = 100U;
  vapi_msg_id_product_core_status_reply = 101U;
  vapi_msg_id_product_core_policy_apply = 102U;
  vapi_msg_id_product_core_policy_apply_reply = 103U;
  vapi_msg_id_product_core_policy_bundle_apply = 104U;
  vapi_msg_id_product_core_policy_bundle_apply_reply = 105U;
  return VAPI_OK;
}

void
vapi_ctx_free (vapi_ctx_t context)
{
  (void) context;
}

bool
vapi_is_msg_available (vapi_ctx_t context, vapi_msg_id_t type)
{
  (void) context;
  if (type == vapi_msg_id_product_core_status)
    return sakamoto_test_request_available != 0;
  if (type == vapi_msg_id_product_core_status_reply)
    return sakamoto_test_reply_available != 0;
  if (type == vapi_msg_id_product_core_policy_apply)
    return sakamoto_test_policy_apply_available != 0;
  if (type == vapi_msg_id_product_core_policy_apply_reply)
    return sakamoto_test_policy_apply_reply_available != 0;
  if (type == vapi_msg_id_product_core_policy_bundle_apply
      || type == vapi_msg_id_product_core_policy_bundle_apply_reply)
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
  return sakamoto_test_disconnect_error;
}

vapi_msg_product_core_status *
vapi_alloc_product_core_status (vapi_ctx_t context)
{
  (void) context;
  if (sakamoto_test_alloc_message != 0)
    return NULL;
  vapi_msg_product_core_status *message =
    calloc (1U, sizeof (vapi_msg_product_core_status));
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
    calloc (1U, sizeof (vapi_msg_product_core_policy_apply));
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
    calloc (1U, sizeof (vapi_msg_product_core_policy_bundle_apply));
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
  (void) message;
  if (callback == NULL)
    return VAPI_EINVAL;
  ++sakamoto_test_policy_bundle_send_calls;
  if (sakamoto_test_policy_bundle_send_error != 0)
    return sakamoto_test_policy_bundle_send_error;
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
EOF

cat > "$stub_dir/harness.c" <<'EOF'
#include "sakamoto_product_abi.h"
#include <stdint.h>
#include <stdio.h>
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
  return 0;
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
  return 0;
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
  return 0;
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
  return 0;
}
EOF

cc -std=c11 -Wall -Wextra -Werror -pthread \
  -I"$repo_root/src/product/include" -I"$stub_dir" \
  "$repo_root/src/product/native/sakamoto_product_vapi.c" \
  "$stub_dir/vapi_stub.c" "$stub_dir/harness.c" \
  -o "$stub_dir/callback-contract"
"$stub_dir/callback-contract"
echo "sakamoto production VAPI callback contract: PASS"
