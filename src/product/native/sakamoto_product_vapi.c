/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Production transport for the Host Product Core.  This translation unit is
 * selected only by the pinned-VPP build; ordinary semantic tests use the
 * explicitly named fixture transport in sakamoto_product_host_fixture_abi.c.
 * The two implementations share the public ABI but never share a packet or
 * VPP buffer.  VAPI is blocking and the session lock is the one serialized
 * owner.
 */

#include "sakamoto_product_abi.h"
#include "sakamoto_product_status.h"

#include <stdbool.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wsign-compare"
#endif
#include <vapi/memclnt.api.vapi.h>
#include <vapi/vapi.h>
#include <vapi/vlib.api.vapi.h>
#include <vapi/product_core.api.vapi.h>
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON;
DEFINE_VAPI_MSG_IDS_VLIB_API_JSON;
DEFINE_VAPI_MSG_IDS_PRODUCT_CORE_API_JSON;

struct sakamoto_product_session {
  vapi_ctx_t context;
  uint64_t generation;
  int connected;
  uint32_t policy_mutation_fault_mode;
  pthread_mutex_t mutex;
};

typedef struct {
  uint32_t transport_code;
  bool callback_called;
  sakamoto_product_status_t *status;
} status_call_t;

typedef struct {
  uint32_t transport_code;
  bool callback_called;
  sakamoto_product_status_t *status;
} apply_call_t;

static bool
product_core_api_available (vapi_ctx_t context)
{
  return vapi_is_msg_available (context, vapi_msg_id_product_core_status)
         && vapi_is_msg_available (context,
                                   vapi_msg_id_product_core_status_reply)
         && vapi_is_msg_available (context,
                                   vapi_msg_id_product_core_policy_apply)
         && vapi_is_msg_available (
           context, vapi_msg_id_product_core_policy_apply_reply);
}

static bool
product_core_policy_bundle_api_available (vapi_ctx_t context)
{
  return product_core_api_available (context)
         && vapi_is_msg_available (
           context, vapi_msg_id_product_core_policy_bundle_apply)
         && vapi_is_msg_available (
           context, vapi_msg_id_product_core_policy_bundle_apply_reply);
}

static bool
policy_bundle_identity_valid (const sakamoto_product_policy_bundle_t *bundle)
{
  size_t length = 0U;
  while (length < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX
         && bundle->snapshot_identity[length] != '\0')
    ++length;
  if (length == 0U || length == SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX)
    return false;
  for (size_t index = length + 1U;
       index < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX; ++index)
    if (bundle->snapshot_identity[index] != '\0')
      return false;
  for (size_t index = 0U; index < length; ++index)
    if (bundle->snapshot_identity[index] == '\n'
        || bundle->snapshot_identity[index] == '\r'
        || bundle->snapshot_identity[index] == '=')
      return false;
  return true;
}

static bool
policy_bundle_rule_valid (const sakamoto_product_policy_rule_entry_t *entry,
                          uint32_t kind)
{
  if (entry->subject_uid == UINT32_MAX || entry->network_context == 0U
      || entry->rule_kind != kind
      || (entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_PASS_NEXT
          && entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_DROP)
      || entry->enabled > 1U || entry->rule_id == 0U
      || entry->reason_id == 0U || entry->reserved != 0U)
    return false;
  if (kind == SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE)
    {
      sakamoto_product_policy_rule_entry_t zero = {0};
      return entry->ip_family == 0U && entry->ip_protocol == 0U
        && entry->direction == 0U && entry->source_prefix_len == 0U
        && entry->destination_prefix_len == 0U
        && entry->source_port_first == 0U && entry->source_port_last == 0U
        && entry->destination_port_first == 0U
        && entry->destination_port_last == 0U && entry->priority == 0U
        && entry->order == 0U
        && memcmp (entry->source_address, zero.source_address,
                   sizeof entry->source_address) == 0
        && memcmp (entry->destination_address, zero.destination_address,
                   sizeof entry->destination_address) == 0;
    }
  uint32_t max_prefix = entry->ip_family
    == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4 ? 32U : 128U;
  if (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4)
    for (size_t index = 4U; index < 16U; ++index)
      if (entry->source_address[index] != 0U
          || entry->destination_address[index] != 0U)
        return false;
  return (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4
          || entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV6)
    && (entry->ip_protocol == SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_TCP
        || entry->ip_protocol == SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_UDP)
    && (entry->direction == SAKAMOTO_PRODUCT_POLICY_DIRECTION_INPUT
        || entry->direction == SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT)
    && entry->source_prefix_len <= max_prefix
    && entry->destination_prefix_len <= max_prefix
    && entry->source_port_first <= entry->source_port_last
    && entry->destination_port_first <= entry->destination_port_last
    && entry->source_port_last <= UINT16_MAX
    && entry->destination_port_last <= UINT16_MAX;
}

static bool
policy_bundle_valid (const sakamoto_product_policy_bundle_t *bundle)
{
  if (bundle->abi_version != SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION
      || bundle->struct_size != sizeof (*bundle)
      || bundle->requested_revision == 0U || bundle->snapshot_hash == 0U
      || bundle->gate_entry_count
           > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES
      || bundle->l4_rule_count
           > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES
      || bundle->gate_entry_count + bundle->l4_rule_count
           > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES
      || bundle->default_pass > 1U || bundle->reserved != 0U
      || !policy_bundle_identity_valid (bundle))
    return false;
  sakamoto_product_policy_rule_entry_t zero = {0};
  uint64_t rule_ids[SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES];
  uint32_t rule_id_count = 0U;
  for (uint32_t index = 0U;
       index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES; ++index)
    {
      const sakamoto_product_policy_rule_entry_t *entry =
        &bundle->gate_entries[index];
      if (index < bundle->gate_entry_count)
        {
          if (!policy_bundle_rule_valid (entry,
                                         SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE))
            return false;
          for (uint32_t prior = 0U; prior < rule_id_count; ++prior)
            if (rule_ids[prior] == entry->rule_id)
              return false;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof zero) != 0)
        return false;
    }
  for (uint32_t index = 0U;
       index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES; ++index)
    {
      const sakamoto_product_policy_rule_entry_t *entry =
        &bundle->l4_entries[index];
      if (index < bundle->l4_rule_count)
        {
          if (!policy_bundle_rule_valid (entry,
                                         SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4))
            return false;
          for (uint32_t prior = 0U; prior < rule_id_count; ++prior)
            if (rule_ids[prior] == entry->rule_id)
              return false;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof zero) != 0)
        return false;
    }
  return true;
}

static vapi_error_e
status_reply (vapi_ctx_t context, void *callback_context, vapi_error_e rv,
              bool is_last, vapi_payload_product_core_status_reply *reply)
{
  (void) context;
  (void) is_last;
  status_call_t *call = callback_context;
  if (call == NULL)
    return VAPI_EINVAL;
  call->callback_called = true;
  if (rv != VAPI_OK || reply == NULL)
    {
      const char *detail = rv != VAPI_OK
        ? "VAPI status callback failed"
        : "VAPI status callback returned a null reply";
      call->transport_code = SAKAMOTO_PRODUCT_QUERY_FAILED;
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
      return VAPI_OK;
    }
  call->status->status_code = SAKAMOTO_PRODUCT_OK;
  call->status->abi_version = reply->abi_version;
  call->status->api_version = reply->api_version;
  call->status->generation = reply->generation;
  call->status->core_ready = reply->core_ready != 0;
  call->status->adapter_available = reply->adapter_available != 0;
  call->status->protection_running = reply->protection_running != 0;
  call->status->root_nfqueue_queue_id = reply->root_nfqueue_queue_id;
  call->status->root_nfqueue_queue_last = reply->root_nfqueue_queue_last;
  call->status->root_nfqueue_lane_count = reply->root_nfqueue_lane_count;
  call->status->root_nfqueue_ready_lane_mask =
    reply->root_nfqueue_ready_lane_mask;
  call->status->root_nfqueue_generation = reply->root_nfqueue_generation;
  call->status->root_nfqueue_verdict_attempts =
    reply->root_nfqueue_verdict_attempts;
  call->status->root_nfqueue_internal_settlements =
    reply->root_nfqueue_internal_settlements;
  call->status->root_nfqueue_buffer_returns =
    reply->root_nfqueue_buffer_returns;
  call->status->root_nfqueue_origin_local_completions =
    reply->root_nfqueue_origin_local_completions;
  call->status->root_nfqueue_origin_remote_completions =
    reply->root_nfqueue_origin_remote_completions;
  call->status->root_nfqueue_lane0_verdict_attempts =
    reply->root_nfqueue_lane0_verdict_attempts;
  call->status->root_nfqueue_lane1_verdict_attempts =
    reply->root_nfqueue_lane1_verdict_attempts;
  call->status->root_nfqueue_input_packets =
    reply->root_nfqueue_input_packets;
  call->status->root_nfqueue_output_packets =
    reply->root_nfqueue_output_packets;
  call->status->root_nfqueue_ipv4_packets =
    reply->root_nfqueue_ipv4_packets;
  call->status->root_nfqueue_ipv6_packets =
    reply->root_nfqueue_ipv6_packets;
  call->status->root_nfqueue_tcp_packets = reply->root_nfqueue_tcp_packets;
  call->status->root_nfqueue_udp_packets = reply->root_nfqueue_udp_packets;
  call->status->root_nfqueue_uid_known_packets =
    reply->root_nfqueue_uid_known_packets;
  call->status->root_nfqueue_uid_unknown_packets =
    reply->root_nfqueue_uid_unknown_packets;
  call->status->root_nfqueue_last_ip_family =
    reply->root_nfqueue_last_ip_family;
  call->status->root_nfqueue_last_protocol =
    reply->root_nfqueue_last_protocol;
  call->status->root_nfqueue_last_hook = reply->root_nfqueue_last_hook;
  call->status->root_nfqueue_last_uid_known =
    reply->root_nfqueue_last_uid_known;
  call->status->root_nfqueue_last_uid = reply->root_nfqueue_last_uid;
  call->status->root_nfqueue_last_queue_id =
    reply->root_nfqueue_last_queue_id;
  call->status->root_nfqueue_last_packet_id =
    reply->root_nfqueue_last_packet_id;
  call->status->root_nfqueue_verdict_succeeded =
    reply->root_nfqueue_verdict_succeeded;
  call->status->root_nfqueue_verdict_failed_definite =
    reply->root_nfqueue_verdict_failed_definite;
  call->status->root_nfqueue_verdict_outcome_unknown =
    reply->root_nfqueue_verdict_outcome_unknown;
  call->status->root_nfqueue_ingress_identity_missing =
    reply->root_nfqueue_ingress_identity_missing;
  call->status->root_nfqueue_graph_submit_fail_opens =
    reply->root_nfqueue_graph_submit_fail_opens;
  call->status->root_nfqueue_non_owner_bypasses =
    reply->root_nfqueue_non_owner_bypasses;
  call->status->root_nfqueue_duplicate_completion_drops =
    reply->root_nfqueue_duplicate_completion_drops;
  call->status->root_nfqueue_stale_completion_drops =
    reply->root_nfqueue_stale_completion_drops;
  call->status->vpn_tun_fd_attached = reply->vpn_tun_fd_attached;
  call->status->vpn_direct_udp4_socket_attached =
    reply->vpn_direct_udp4_socket_attached;
  call->status->vpn_direct_udp4_protect_succeeded =
    reply->vpn_direct_udp4_protect_succeeded;
  call->status->vpn_direct_udp4_bind_succeeded =
    reply->vpn_direct_udp4_bind_succeeded;
  call->status->vpn_tun_ingress_packets =
    reply->vpn_tun_ingress_packets;
  call->status->vpn_tun_udp4_tun_origin_packets =
    reply->vpn_tun_udp4_tun_origin_packets;
  call->status->vpn_flow_stack_admissions =
    reply->vpn_flow_stack_admissions;
  call->status->vpn_direct_udp4_send_succeeded =
    reply->vpn_direct_udp4_send_succeeded;
  call->status->vpn_direct_udp4_transport_failed =
    reply->vpn_direct_udp4_transport_failed;
  call->status->vpn_flow_stack_return_packets =
    reply->vpn_flow_stack_return_packets;
  call->status->vpn_flow_stack_return_provenance_packets =
    reply->vpn_flow_stack_return_provenance_packets;
  call->status->vpn_tun_write_completions =
    reply->vpn_tun_write_completions;
  call->status->vpn_infrastructure_faults =
    reply->vpn_infrastructure_faults;
  call->status->vpn_duplicate_or_stale_drops =
    reply->vpn_duplicate_or_stale_drops;
  call->status->product_graph_worker_count =
    reply->product_graph_worker_count;
  call->status->product_graph_hash_seed =
    reply->product_graph_hash_seed;
  call->status->product_graph_handoff_credits =
    reply->product_graph_handoff_credits;
  call->status->product_graph_vpp_worker_count =
    reply->product_graph_vpp_worker_count;
  call->status->product_graph_vpp_main_core =
    reply->product_graph_vpp_main_core;
  call->status->product_graph_vpp_worker0_thread_index =
    reply->product_graph_vpp_worker0_thread_index;
  call->status->product_graph_vpp_worker0_core =
    reply->product_graph_vpp_worker0_core;
  call->status->product_graph_vpp_worker1_thread_index =
    reply->product_graph_vpp_worker1_thread_index;
  call->status->product_graph_vpp_worker1_core =
    reply->product_graph_vpp_worker1_core;
  call->status->product_graph_enabled = reply->product_graph_enabled;
  call->status->product_graph_accepting = reply->product_graph_accepting;
  call->status->product_graph_worker_layout_ready =
    reply->product_graph_worker_layout_ready;
  call->status->product_graph_obligation_debt =
    reply->product_graph_obligation_debt;
  call->status->product_graph_buffer_debt =
    reply->product_graph_buffer_debt;
  call->status->product_graph_handoff_debt =
    reply->product_graph_handoff_debt;
  call->status->policy_requested_revision =
    reply->policy_requested_revision;
  call->status->policy_active_revision = reply->policy_active_revision;
  call->status->policy_generation = reply->policy_generation;
  call->status->policy_snapshot_hash = reply->policy_snapshot_hash;
  call->status->policy_worker0_revision = reply->policy_worker0_revision;
  call->status->policy_worker1_revision = reply->policy_worker1_revision;
  call->status->policy_snapshot_empty = reply->policy_snapshot_empty;
  call->status->policy_default_pass = reply->policy_default_pass;
  call->status->policy_gate_claim_count = reply->policy_gate_claim_count;
  call->status->policy_l4_rule_count = reply->policy_l4_rule_count;
  call->status->policy_last_apply_status_code =
    reply->policy_last_apply_status_code;
  call->status->policy_mixed_revision = reply->policy_mixed_revision;
  call->status->policy_artifact_match = reply->policy_artifact_match;
  call->status->policy_generation_match = reply->policy_generation_match;
  call->status->policy_gate_subject_uid = reply->policy_gate_subject_uid;
  call->status->policy_gate_network_context =
    reply->policy_gate_network_context;
  call->status->policy_gate_blocked = reply->policy_gate_blocked;
  call->status->policy_gate_reason_id = reply->policy_gate_reason_id;
  call->status->policy_gate_rule_id = reply->policy_gate_rule_id;
  call->status->policy_drop_records = reply->policy_drop_records;
  call->status->policy_last_drop_revision = reply->policy_last_drop_revision;
  call->status->policy_last_drop_rule_id = reply->policy_last_drop_rule_id;
  call->status->policy_last_drop_completion_attempts =
    reply->policy_last_drop_completion_attempts;
  call->status->policy_last_drop_uid = reply->policy_last_drop_uid;
  call->status->policy_last_drop_network_context =
    reply->policy_last_drop_network_context;
  call->status->policy_last_drop_reason_id = reply->policy_last_drop_reason_id;
  call->status->policy_last_drop_verdict = reply->policy_last_drop_verdict;
  call->status->policy_last_drop_winner = reply->policy_last_drop_winner;
  call->status->policy_last_drop_uid_known =
    reply->policy_last_drop_uid_known;
  call->status->policy_last_drop_device_direction =
    reply->policy_last_drop_device_direction;
  call->status->policy_l4_active_revision = reply->policy_l4_active_revision;
  call->status->policy_l4_rule_id = reply->policy_l4_rule_id;
  call->status->policy_l4_match_records = reply->policy_l4_match_records;
  call->status->policy_l4_no_match_records = reply->policy_l4_no_match_records;
  call->status->policy_l4_last_match_revision =
    reply->policy_l4_last_match_revision;
  call->status->policy_l4_last_match_rule_id =
    reply->policy_l4_last_match_rule_id;
  call->status->policy_l4_subject_uid = reply->policy_l4_subject_uid;
  call->status->policy_l4_network_context = reply->policy_l4_network_context;
  call->status->policy_l4_ip_family = reply->policy_l4_ip_family;
  call->status->policy_l4_ip_protocol = reply->policy_l4_ip_protocol;
  call->status->policy_l4_direction = reply->policy_l4_direction;
  call->status->policy_l4_action = reply->policy_l4_action;
  call->status->policy_l4_priority = reply->policy_l4_priority;
  call->status->policy_l4_order = reply->policy_l4_order;
  call->status->policy_l4_reason_id = reply->policy_l4_reason_id;
  call->status->policy_l4_last_match_uid = reply->policy_l4_last_match_uid;
  call->status->policy_l4_last_match_network_context =
    reply->policy_l4_last_match_network_context;
  call->status->policy_l4_last_match_reason_id =
    reply->policy_l4_last_match_reason_id;
  call->status->policy_l4_last_match_verdict =
    reply->policy_l4_last_match_verdict;
  call->status->policy_l4_last_match_winner = reply->policy_l4_last_match_winner;
  call->status->policy_l4_last_match_uid_known =
    reply->policy_l4_last_match_uid_known;
  call->status->policy_l4_last_match_device_direction =
    reply->policy_l4_last_match_device_direction;
  call->status->policy_l4_last_match_action = reply->policy_l4_last_match_action;
  call->status->policy_l4_last_evaluation_result =
    reply->policy_l4_last_evaluation_result;
  call->status->policy_l4_last_evaluation_verdict =
    reply->policy_l4_last_evaluation_verdict;
  call->status->policy_l4_last_evaluation_device_direction =
    reply->policy_l4_last_evaluation_device_direction;
  call->status->policy_l4_view_active = reply->policy_l4_view_active;
  call->status->policy_l4_view_rule_count = reply->policy_l4_view_rule_count;
  call->status->policy_l4_view_max_probes = reply->policy_l4_view_max_probes;
  call->status->policy_l4_view_last_match_winner_rank =
    reply->policy_l4_view_last_match_winner_rank;
  call->status->policy_l4_view_last_match_probes =
    reply->policy_l4_view_last_match_probes;
  call->status->policy_l4_view_last_match_candidate_count =
    reply->policy_l4_view_last_match_candidate_count;
  call->status->policy_l4_view_last_no_match_reason =
    reply->policy_l4_view_last_no_match_reason;
  call->status->policy_l4_typed_match_policy_key =
    reply->policy_l4_typed_match_policy_key;
  call->status->policy_l4_typed_match_probe_key =
    reply->policy_l4_typed_match_probe_key;
  call->status->policy_l4_last_evaluation_probe_key =
    reply->policy_l4_last_evaluation_probe_key;
  call->status->plugin_loaded = 1U;
  call->status->vapi_handle_live = 1U;
  call->status->generation_live = 1U;
  sakamoto_product_status_copy_text (
    call->status->artifact_id, sizeof (call->status->artifact_id),
    reply->artifact_id, sizeof (reply->artifact_id));
  sakamoto_product_status_copy_text (
    call->status->api_identity, sizeof (call->status->api_identity),
    reply->api_identity, sizeof (reply->api_identity));
  sakamoto_product_status_copy_text (
    call->status->vpp_revision, sizeof (call->status->vpp_revision),
    reply->vpp_revision, sizeof (reply->vpp_revision));
  sakamoto_product_status_copy_text (
    call->status->policy_snapshot_identity,
    sizeof (call->status->policy_snapshot_identity),
    reply->policy_snapshot_identity, sizeof (reply->policy_snapshot_identity));
  if (reply->retval != 0)
    {
      char detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
      call->transport_code = SAKAMOTO_PRODUCT_QUERY_FAILED;
      (void) snprintf (detail, sizeof (detail),
                       "VPP status request returned retval=%d",
                       (int) reply->retval);
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
    }
  return VAPI_OK;
}

static vapi_error_e
policy_apply_reply (vapi_ctx_t context, void *callback_context,
                    vapi_error_e rv, bool is_last,
                    vapi_payload_product_core_policy_apply_reply *reply)
{
  (void) context;
  (void) is_last;
  apply_call_t *call = callback_context;
  if (call == NULL)
    return VAPI_EINVAL;
  call->callback_called = true;
  if (rv != VAPI_OK || reply == NULL)
    {
      const char *detail = rv != VAPI_OK
        ? "VAPI policy apply callback failed"
        : "VAPI policy apply callback returned a null reply";
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
      return VAPI_OK;
    }
  if (reply->retval != 0)
    {
      char detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
      (void) snprintf (detail, sizeof (detail),
                       "VPP policy apply returned retval=%d",
                       (int) reply->retval);
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
    }
  return VAPI_OK;
}

static vapi_error_e
policy_bundle_apply_reply (
  vapi_ctx_t context, void *callback_context, vapi_error_e rv, bool is_last,
  vapi_payload_product_core_policy_bundle_apply_reply *reply)
{
  (void) context;
  (void) is_last;
  apply_call_t *call = callback_context;
  if (call == NULL)
    return VAPI_EINVAL;
  call->callback_called = true;
  if (rv != VAPI_OK || reply == NULL)
    {
      const char *detail = rv != VAPI_OK
        ? "VAPI policy bundle apply callback failed"
        : "VAPI policy bundle apply callback returned a null reply";
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
      return VAPI_OK;
    }
  if (reply->retval != 0)
    {
      char detail[SAKAMOTO_PRODUCT_ERROR_DETAIL_MAX];
      call->transport_code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
      (void) snprintf (detail, sizeof (detail),
                       "VPP policy bundle apply returned retval=%d",
                       (int) reply->retval);
      sakamoto_product_status_error (call->status, call->transport_code,
                                     detail);
    }
  return VAPI_OK;
}

/* The public ABI is naturally aligned while generated VAPI types are packed. */
static void
policy_bundle_rule_to_vapi (
  const sakamoto_product_policy_rule_entry_t *source,
  vapi_type_product_policy_rule_entry *destination)
{
  destination->subject_uid = source->subject_uid;
  destination->network_context = source->network_context;
  destination->ifindex = source->ifindex;
  destination->rule_kind = source->rule_kind;
  destination->ip_family = source->ip_family;
  destination->ip_protocol = source->ip_protocol;
  destination->direction = source->direction;
  destination->action = source->action;
  destination->enabled = source->enabled;
  destination->source_prefix_len = source->source_prefix_len;
  destination->destination_prefix_len = source->destination_prefix_len;
  destination->source_port_first = source->source_port_first;
  destination->source_port_last = source->source_port_last;
  destination->destination_port_first = source->destination_port_first;
  destination->destination_port_last = source->destination_port_last;
  destination->priority = source->priority;
  destination->order = source->order;
  destination->reason_id = source->reason_id;
  destination->reserved = source->reserved;
  destination->rule_id = source->rule_id;
  memcpy (destination->source_address, source->source_address,
          sizeof (destination->source_address));
  memcpy (destination->destination_address, source->destination_address,
          sizeof (destination->destination_address));
}

static uint32_t
query_status (sakamoto_product_session_t *session,
              sakamoto_product_status_t *status)
{
  if (!product_core_api_available (session->context))
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "required Product Core VAPI messages are unavailable");
      return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  vapi_msg_product_core_status *message =
    vapi_alloc_product_core_status (session->context);
  if (message == NULL)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                                     "cannot allocate VAPI status request");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  status_call_t call = {.transport_code = SAKAMOTO_PRODUCT_OK,
                        .callback_called = false,
                        .status = status};
  vapi_error_e rv = vapi_product_core_status (
    session->context, message, status_reply, &call);
  if (rv == VAPI_OK && !call.callback_called)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                     "VAPI status callback was not invoked");
      return SAKAMOTO_PRODUCT_QUERY_FAILED;
    }
  if (rv != VAPI_OK && call.transport_code == SAKAMOTO_PRODUCT_OK)
    {
      sakamoto_product_status_error (status, SAKAMOTO_PRODUCT_QUERY_FAILED,
                                     "VAPI status request send failed");
      return SAKAMOTO_PRODUCT_QUERY_FAILED;
    }
  return call.transport_code != SAKAMOTO_PRODUCT_OK ? call.transport_code
                                                    : status->status_code;
}

static uint32_t
apply_policy_snapshot (sakamoto_product_session_t *session,
                       const sakamoto_product_policy_snapshot_t *snapshot,
                       sakamoto_product_status_t *status)
{
  if (!product_core_api_available (session->context))
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "required Product Core VAPI messages are unavailable");
      return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  vapi_msg_product_core_policy_apply *message =
    vapi_alloc_product_core_policy_apply (session->context);
  if (message == NULL)
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot allocate VAPI policy apply request");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  message->payload.generation = session->generation;
  message->payload.requested_revision = snapshot->requested_revision;
  message->payload.snapshot_hash = snapshot->snapshot_hash;
  message->payload.snapshot_empty = snapshot->snapshot_empty != 0U;
  message->payload.default_pass = snapshot->default_pass != 0U;
  message->payload.gate_claim_count = snapshot->gate_claim_count;
  message->payload.l4_rule_count = snapshot->l4_rule_count;
  message->payload.gate_subject_uid = snapshot->gate_subject_uid;
  message->payload.gate_network_context = snapshot->gate_network_context;
  message->payload.gate_blocked = snapshot->gate_blocked != 0U;
  message->payload.gate_reason_id = snapshot->gate_reason_id;
  message->payload.gate_rule_id = snapshot->gate_rule_id;
  message->payload.l4_subject_uid = snapshot->l4_subject_uid;
  message->payload.l4_network_context = snapshot->l4_network_context;
  message->payload.l4_ip_family = snapshot->l4_ip_family;
  message->payload.l4_ip_protocol = snapshot->l4_ip_protocol;
  message->payload.l4_direction = snapshot->l4_direction;
  message->payload.l4_action = snapshot->l4_action;
  message->payload.l4_source_prefix_len = snapshot->l4_source_prefix_len;
  message->payload.l4_destination_prefix_len =
    snapshot->l4_destination_prefix_len;
  message->payload.l4_source_port_first = snapshot->l4_source_port_first;
  message->payload.l4_source_port_last = snapshot->l4_source_port_last;
  message->payload.l4_destination_port_first =
    snapshot->l4_destination_port_first;
  message->payload.l4_destination_port_last =
    snapshot->l4_destination_port_last;
  message->payload.l4_priority = snapshot->l4_priority;
  message->payload.l4_order = snapshot->l4_order;
  message->payload.l4_reason_id = snapshot->l4_reason_id;
  message->payload.l4_reserved = snapshot->l4_reserved;
  message->payload.l4_rule_id = snapshot->l4_rule_id;
  memcpy (message->payload.l4_source_address, snapshot->l4_source_address,
          sizeof (snapshot->l4_source_address));
  memcpy (message->payload.l4_destination_address,
          snapshot->l4_destination_address,
          sizeof (snapshot->l4_destination_address));
  memset (message->payload.snapshot_identity, 0,
          sizeof (message->payload.snapshot_identity));
  memcpy (message->payload.snapshot_identity, snapshot->snapshot_identity,
          sizeof (snapshot->snapshot_identity));

  apply_call_t call = {.transport_code = SAKAMOTO_PRODUCT_OK,
                       .callback_called = false,
                       .status = status};
  vapi_error_e rv = vapi_product_core_policy_apply (
    session->context, message, policy_apply_reply, &call);
  if (rv == VAPI_OK && !call.callback_called)
    {
      sakamoto_product_status_error (
        status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
        "VAPI policy apply callback was not invoked");
      return SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
    }
  if (rv != VAPI_OK && call.transport_code == SAKAMOTO_PRODUCT_OK)
    {
      sakamoto_product_status_error (status,
                                     SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                                     "VAPI policy apply request send failed");
      return SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
    }
  if (call.transport_code != SAKAMOTO_PRODUCT_OK)
    return call.transport_code;
  return query_status (session, status);
}

uint32_t
sakamoto_product_abi_version (void)
{
  return SAKAMOTO_PRODUCT_ABI_VERSION;
}

uint32_t
sakamoto_product_api_version (void)
{
  return SAKAMOTO_PRODUCT_API_VERSION;
}

uint32_t
sakamoto_product_session_connect (sakamoto_product_bytes_t api_socket,
                                   uint64_t expected_generation,
                                   sakamoto_product_session_t **out_session,
                                   sakamoto_product_status_t *out_status)
{
  if (out_session != NULL)
    *out_session = NULL;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (out_session == NULL || out_status == NULL || api_socket.data == NULL
      || api_socket.length == 0U || api_socket.length >= sizeof (((struct sockaddr_un *) 0)->sun_path)
      || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "socket path and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  for (uint32_t index = 0U; index < api_socket.length; ++index)
    if (api_socket.data[index] == 0U)
      {
        sakamoto_product_status_error (
          out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
          "socket path contains an embedded NUL");
        return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
      }
  char *socket_path = calloc ((size_t) api_socket.length + 1U, sizeof (*socket_path));
  if (socket_path == NULL)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot allocate VAPI socket path");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  memcpy (socket_path, api_socket.data, api_socket.length);
  vapi_ctx_t context = NULL;
  vapi_error_e rv = vapi_ctx_alloc (&context);
  if (rv != VAPI_OK)
    {
      free (socket_path);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                                     "cannot allocate VAPI context");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  rv = vapi_connect_ex (context, "sakamoto-product-core", socket_path, 1, 1,
                        VAPI_MODE_BLOCKING, true, true);
  free (socket_path);
  if (rv != VAPI_OK)
    {
      vapi_ctx_free (context);
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_CONNECT_FAILED,
                                     "cannot connect to VPP VAPI");
      return SAKAMOTO_PRODUCT_CONNECT_FAILED;
    }
  if (!product_core_api_available (context))
    {
      vapi_disconnect (context);
      vapi_ctx_free (context);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
        "required Product Core VAPI messages are unavailable");
      return SAKAMOTO_PRODUCT_API_UNAVAILABLE;
    }
  sakamoto_product_session_t *session = calloc (1U, sizeof (*session));
  if (session == NULL || pthread_mutex_init (&session->mutex, NULL) != 0)
    {
      if (session != NULL)
        free (session);
      vapi_disconnect (context);
      vapi_ctx_free (context);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
        "cannot initialize VAPI session");
      return SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
    }
  session->context = context;
  session->generation = expected_generation;
  session->connected = 1;
  uint32_t code = query_status (session, out_status);
  if (code != SAKAMOTO_PRODUCT_OK
      || out_status->generation != expected_generation)
    {
      if (code == SAKAMOTO_PRODUCT_OK)
        sakamoto_product_status_error (
          out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
          "VPP generation does not match the active generation");
      vapi_disconnect (context);
      vapi_ctx_free (context);
      pthread_mutex_destroy (&session->mutex);
      free (session);
      return out_status->status_code;
    }
  *out_session = session;
  return SAKAMOTO_PRODUCT_OK;
}

uint32_t
sakamoto_product_session_query (sakamoto_product_session_t *session,
                                 uint64_t expected_generation,
                                 sakamoto_product_status_t *out_status)
{
  if (out_status == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      code = query_status (session, out_status);
      if (code == SAKAMOTO_PRODUCT_OK
          && out_status->generation != expected_generation)
        {
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
            "VPP generation does not match the active generation");
          code = SAKAMOTO_PRODUCT_STALE_HANDLE;
        }
    }
  pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_apply_policy (
  sakamoto_product_session_t *session, uint64_t expected_generation,
  const sakamoto_product_policy_snapshot_t *snapshot,
  sakamoto_product_status_t *out_status)
{
  if (out_status == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || snapshot == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session, snapshot and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      code = apply_policy_snapshot (session, snapshot, out_status);
      if (code == SAKAMOTO_PRODUCT_OK
          && out_status->generation != expected_generation)
        {
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
            "VPP generation does not match the active generation");
          code = SAKAMOTO_PRODUCT_STALE_HANDLE;
        }
    }
  pthread_mutex_unlock (&session->mutex);
  return code;
}

/* One complete successor is sent through the generated typed VAPI message. */
uint32_t
sakamoto_product_session_apply_policy_bundle (
  sakamoto_product_session_t *session, uint64_t expected_generation,
  const sakamoto_product_policy_bundle_t *bundle,
  sakamoto_product_status_t *out_status)
{
  if (out_status == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_status_reset (out_status, expected_generation);
  if (session == NULL || bundle == NULL || expected_generation == 0U)
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "session, bundle and non-zero generation are required");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (!policy_bundle_valid (bundle))
    {
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_INVALID_ARGUMENT,
        "policy bundle ABI, identity, or bounded counts are invalid");
      return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    }
  if (pthread_mutex_lock (&session->mutex) != 0)
    {
      sakamoto_product_status_error (out_status,
                                     SAKAMOTO_PRODUCT_INTERNAL_ERROR,
                                     "cannot lock VAPI session");
      return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
    }
  uint32_t code = SAKAMOTO_PRODUCT_OK;
  if (!session->connected || expected_generation != session->generation)
    {
      sakamoto_product_status_reset (out_status, session->generation);
      sakamoto_product_status_error (
        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
        "session is retired or belongs to another generation");
      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
    }
  else
    {
      if (!product_core_policy_bundle_api_available (session->context))
        {
          sakamoto_product_status_error (
            out_status, SAKAMOTO_PRODUCT_API_UNAVAILABLE,
            "Product Core typed policy bundle VAPI messages are unavailable");
          code = SAKAMOTO_PRODUCT_API_UNAVAILABLE;
        }
      else
        {
          /* Consume a pre-submit fault before allocating or handing a
           * message to generated VAPI.  This is a definite failure: the
           * request is known not to have been submitted, so Product Core may
           * discard the temp file and let an explicit retry proceed. */
          uint32_t fault_mode = session->policy_mutation_fault_mode;
          if (fault_mode
              == SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT)
            {
              session->policy_mutation_fault_mode =
                SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE;
              sakamoto_product_status_error (
                out_status, SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED,
                "debug policy bundle apply was not submitted");
              code = SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED;
            }
          else
            {
              vapi_msg_product_core_policy_bundle_apply *message =
                vapi_alloc_product_core_policy_bundle_apply (session->context);
              if (message == NULL)
                {
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_ALLOCATION_FAILED,
                    "cannot allocate VAPI policy bundle apply request");
                  code = SAKAMOTO_PRODUCT_ALLOCATION_FAILED;
                  goto policy_bundle_apply_done;
                }
              message->payload.generation = session->generation;
              message->payload.abi_version = bundle->abi_version;
              message->payload.struct_size = bundle->struct_size;
              message->payload.requested_revision = bundle->requested_revision;
              message->payload.snapshot_hash = bundle->snapshot_hash;
              message->payload.gate_entry_count = bundle->gate_entry_count;
              message->payload.l4_rule_count = bundle->l4_rule_count;
              message->payload.default_pass = bundle->default_pass;
              message->payload.reserved = bundle->reserved;
              memcpy (message->payload.snapshot_identity,
                      bundle->snapshot_identity,
                      sizeof (message->payload.snapshot_identity));
              for (uint32_t index = 0U;
                   index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES;
                   ++index)
                policy_bundle_rule_to_vapi (
                  &bundle->gate_entries[index],
                  &message->payload.gate_entries[index]);
              for (uint32_t index = 0U;
                   index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES;
                   ++index)
                policy_bundle_rule_to_vapi (
                  &bundle->l4_entries[index],
                  &message->payload.l4_entries[index]);

              apply_call_t call = {.transport_code = SAKAMOTO_PRODUCT_OK,
                                   .callback_called = false,
                                   .status = out_status};
              /* The debug fault is consumed at the generated typed-call
               * boundary.  The request is still sent once; only its reply is
               * made untrusted so Product Core must fence and reconcile. */
              session->policy_mutation_fault_mode =
                SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE;
              vapi_error_e rv = vapi_product_core_policy_bundle_apply (
                session->context, message, policy_bundle_apply_reply, &call);
              if (fault_mode
                  == SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK)
                {
                  call.callback_called = false;
                  call.transport_code = SAKAMOTO_PRODUCT_OK;
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                    "VAPI policy bundle apply callback was not invoked");
                  code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
                }
              else if (rv == VAPI_OK && !call.callback_called)
                {
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                    "VAPI policy bundle apply callback was not invoked");
                  code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
                }
              else if (rv != VAPI_OK
                       && call.transport_code == SAKAMOTO_PRODUCT_OK)
                {
                  sakamoto_product_status_error (
                    out_status, SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN,
                    "VAPI policy bundle apply request send failed");
                  code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;
                }
              else if (call.transport_code != SAKAMOTO_PRODUCT_OK)
                code = call.transport_code;
              else
                {
                  code = query_status (session, out_status);
                  if (code == SAKAMOTO_PRODUCT_OK
                      && out_status->generation != expected_generation)
                    {
                      sakamoto_product_status_error (
                        out_status, SAKAMOTO_PRODUCT_STALE_HANDLE,
                        "VPP generation does not match the active generation");
                      code = SAKAMOTO_PRODUCT_STALE_HANDLE;
                    }
                  }
            }
        }
    }
policy_bundle_apply_done:
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_set_policy_mutation_fault (
  sakamoto_product_session_t *session, uint64_t expected_generation,
  uint32_t fault_mode)
{
  if (session == NULL || expected_generation == 0U
      || (fault_mode != SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_NONE
          && fault_mode != SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_OMIT_CALLBACK
          && fault_mode
               != SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT))
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  uint32_t code = SAKAMOTO_PRODUCT_OK;
  if (!session->connected || expected_generation != session->generation)
    code = SAKAMOTO_PRODUCT_STALE_HANDLE;
  else
    session->policy_mutation_fault_mode = fault_mode;
  (void) pthread_mutex_unlock (&session->mutex);
  return code;
}

uint32_t
sakamoto_product_session_disconnect (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (pthread_mutex_lock (&session->mutex) != 0)
    return SAKAMOTO_PRODUCT_INTERNAL_ERROR;
  vapi_error_e rv = VAPI_OK;
  if (session->connected)
    {
      session->connected = 0;
      rv = vapi_disconnect (session->context);
      vapi_ctx_free (session->context);
      session->context = NULL;
    }
  pthread_mutex_unlock (&session->mutex);
  return rv == VAPI_OK ? SAKAMOTO_PRODUCT_OK
                       : SAKAMOTO_PRODUCT_DISCONNECT_FAILED;
}

uint32_t
sakamoto_product_session_destroy (sakamoto_product_session_t *session)
{
  if (session == NULL)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  uint32_t code = sakamoto_product_session_disconnect (session);
  if (code != SAKAMOTO_PRODUCT_OK)
    return code;
  pthread_mutex_destroy (&session->mutex);
  free (session);
  return SAKAMOTO_PRODUCT_OK;
}
