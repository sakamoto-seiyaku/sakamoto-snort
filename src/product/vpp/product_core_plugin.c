/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Product identity and coarse readiness share this plugin with the VPP-native
 * packet kernel graph. Root NFQUEUE exposes the dual-stack INPUT/OUTPUT
 * platform adapter. The VPN Flow Stack remains separate.
 */

#include <errno.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/plugin/plugin.h>
#include <vnet/vnet.h>
#include <vpp/app/version.h>

#include "product_core.api_enum.h"
#include "product_core.api_types.h"
#include "sakamoto_product_abi.h"
#include "product_core_identity.h"
#include "product_l4_policy.h"
#include "product_packet_graph.h"
#include "product_root_nfqueue_adapter.h"

#ifndef SAKAMOTO_PRODUCT_VPP_REVISION
#error "the product plugin must be compiled with the pinned VPP revision"
#endif

typedef struct
{
  vlib_main_t *vlib_main;
  u16 msg_id_base;
  u64 generation;
  u8 core_ready;
  u64 policy_requested_revision;
  u64 policy_active_revision;
  u64 policy_generation;
  u64 policy_snapshot_hash;
  u64 policy_worker0_revision;
  u64 policy_worker1_revision;
  u32 policy_snapshot_empty;
  u32 policy_default_pass;
  u32 policy_gate_claim_count;
  u32 policy_l4_rule_count;
  u32 policy_last_apply_status_code;
  u32 policy_mixed_revision;
  u32 policy_artifact_match;
  u32 policy_generation_match;
  u8 policy_snapshot_identity[96];
  u32 policy_gate_subject_uid;
  u32 policy_gate_network_context;
  u32 policy_gate_blocked;
  u32 policy_gate_reason_id;
  u64 policy_gate_rule_id;
  u64 policy_drop_records;
  u64 policy_last_drop_revision;
  u64 policy_last_drop_rule_id;
  u64 policy_last_drop_completion_attempts;
  u32 policy_last_drop_uid;
  u32 policy_last_drop_network_context;
  u32 policy_last_drop_reason_id;
  u32 policy_last_drop_verdict;
  u32 policy_last_drop_winner;
  u32 policy_last_drop_uid_known;
  u32 policy_last_drop_device_direction;
} product_core_main_t;

product_core_main_t product_core_main;

#define REPLY_MSG_ID_BASE product_core_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

static u64
product_core_generation (void)
{
  const char *value = getenv ("SAKAMOTO_PRODUCT_GENERATION");
  if (value == NULL || *value == '\0')
    return 1;
  errno = 0;
  char *end = 0;
  unsigned long long generation = strtoull (value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || generation == 0)
    return 1;
  return (u64) generation;
}

static int
product_core_profile_is_root (void)
{
  const char *profile = getenv ("SAKAMOTO_RUNTIME_PROFILE");
  return profile != 0 && strcmp (profile, "root") == 0;
}

static int
product_core_adapter_available (void)
{
  if (product_core_profile_is_root ())
    return product_root_nfqueue_adapter_available ();
  return 0;
}

static int
product_core_protection_running (void)
{
  if (product_core_profile_is_root ())
    return product_root_nfqueue_adapter_available ();
  return 0;
}

static u32
product_core_vpp_main_core (void)
{
  if (vec_len (vlib_worker_threads) > 0 && vlib_worker_threads[0].cpu_id >= 0)
    return (u32) vlib_worker_threads[0].cpu_id;
  if (vlib_thread_main.main_lcore != UINT32_MAX)
    return vlib_thread_main.main_lcore;
  return UINT32_MAX;
}

static u32
product_core_vpp_worker_thread_index (u32 worker)
{
  if (worker >= vlib_num_workers ())
    return UINT32_MAX;
  return vlib_get_worker_thread_index (worker);
}

static u32
product_core_vpp_worker_core (u32 worker)
{
  u32 thread_index = product_core_vpp_worker_thread_index (worker);
  if (thread_index == UINT32_MAX || thread_index >= vec_len (vlib_worker_threads)
      || vlib_worker_threads[thread_index].cpu_id < 0)
    return UINT32_MAX;
  return (u32) vlib_worker_threads[thread_index].cpu_id;
}

static u32
product_core_graph_worker_layout_ready (void)
{
  return vlib_num_workers () == product_packet_graph_worker_count () ? 1 : 0;
}

static void
product_core_copy_policy_identity (u8 destination[96], const u8 source[96])
{
  clib_memset (destination, 0, 96);
  for (u32 index = 0; index < 95 && source[index] != 0; ++index)
      destination[index] = source[index];
}

static u32
product_core_ipv4_from_snapshot_address (const u8 address[16])
{
  return ((u32) address[12] << 24) | ((u32) address[13] << 16)
         | ((u32) address[14] << 8) | address[15];
}

static void
product_core_set_policy_status_fields (vl_api_product_core_status_reply_t *rmp)
{
  product_core_main_t *pcm = &product_core_main;
  product_packet_graph_gate_status_t gate_status;
  product_packet_graph_l4_status_t l4_status;
  product_packet_graph_gate_status (&gate_status);
  product_packet_graph_l4_status (&l4_status);

  rmp->policy_requested_revision =
    clib_host_to_net_u64 (pcm->policy_requested_revision);
  rmp->policy_active_revision =
    clib_host_to_net_u64 (pcm->policy_active_revision);
  rmp->policy_generation = clib_host_to_net_u64 (pcm->policy_generation);
  rmp->policy_snapshot_hash =
    clib_host_to_net_u64 (pcm->policy_snapshot_hash);
  rmp->policy_worker0_revision =
    clib_host_to_net_u64 (pcm->policy_worker0_revision);
  rmp->policy_worker1_revision =
    clib_host_to_net_u64 (pcm->policy_worker1_revision);
  rmp->policy_snapshot_empty = htonl (pcm->policy_snapshot_empty);
  rmp->policy_default_pass = htonl (pcm->policy_default_pass);
  rmp->policy_gate_claim_count = htonl (pcm->policy_gate_claim_count);
  rmp->policy_l4_rule_count = htonl (pcm->policy_l4_rule_count);
  rmp->policy_last_apply_status_code =
    htonl (pcm->policy_last_apply_status_code);
  rmp->policy_mixed_revision = htonl (pcm->policy_mixed_revision);
  rmp->policy_artifact_match = htonl (pcm->policy_artifact_match);
  rmp->policy_generation_match = htonl (pcm->policy_generation_match);
  clib_memset (rmp->policy_snapshot_identity, 0,
               sizeof (rmp->policy_snapshot_identity));
  clib_memcpy (rmp->policy_snapshot_identity, pcm->policy_snapshot_identity,
               sizeof (pcm->policy_snapshot_identity));
  rmp->policy_gate_subject_uid = htonl (pcm->policy_gate_subject_uid);
  rmp->policy_gate_network_context = htonl (pcm->policy_gate_network_context);
  rmp->policy_gate_blocked = pcm->policy_gate_blocked != 0;
  rmp->policy_gate_reason_id = htonl (pcm->policy_gate_reason_id);
  rmp->policy_gate_rule_id = clib_host_to_net_u64 (pcm->policy_gate_rule_id);
  rmp->policy_drop_records = clib_host_to_net_u64 (gate_status.drop_records);
  rmp->policy_last_drop_revision =
    clib_host_to_net_u64 (gate_status.last_drop_revision);
  rmp->policy_last_drop_rule_id =
    clib_host_to_net_u64 (gate_status.last_drop_rule_id);
  rmp->policy_last_drop_completion_attempts =
    clib_host_to_net_u64 (gate_status.last_drop_completion_attempts);
  rmp->policy_last_drop_uid = htonl (gate_status.last_drop_uid);
  rmp->policy_last_drop_network_context =
    htonl (gate_status.last_drop_network_context);
  rmp->policy_last_drop_reason_id =
    htonl (gate_status.last_drop_reason_id);
  rmp->policy_last_drop_verdict = htonl (gate_status.last_drop_verdict);
  rmp->policy_last_drop_winner = htonl (gate_status.last_drop_winner);
  rmp->policy_last_drop_uid_known = gate_status.last_drop_uid_known != 0;
  rmp->policy_last_drop_device_direction =
    htonl (gate_status.last_drop_device_direction);
  rmp->policy_l4_active_revision =
    clib_host_to_net_u64 (l4_status.active_revision);
  rmp->policy_l4_rule_id = clib_host_to_net_u64 (l4_status.rule_id);
  rmp->policy_l4_match_records =
    clib_host_to_net_u64 (l4_status.match_records);
  rmp->policy_l4_no_match_records =
    clib_host_to_net_u64 (l4_status.no_match_records);
  rmp->policy_l4_last_match_revision =
    clib_host_to_net_u64 (l4_status.last_match_revision);
  rmp->policy_l4_last_match_rule_id =
    clib_host_to_net_u64 (l4_status.last_match_rule_id);
  rmp->policy_l4_subject_uid = htonl (l4_status.subject_uid);
  rmp->policy_l4_network_context = htonl (l4_status.network_context_id);
  rmp->policy_l4_ip_family = htonl (l4_status.rule_id == 0
                                      ? 0 : 4);
  rmp->policy_l4_ip_protocol = htonl (l4_status.protocol);
  rmp->policy_l4_direction = htonl (l4_status.direction);
  rmp->policy_l4_action = htonl (l4_status.action);
  rmp->policy_l4_priority = htonl (l4_status.priority);
  rmp->policy_l4_order = htonl (l4_status.order);
  rmp->policy_l4_reason_id = htonl (l4_status.reason_id);
  rmp->policy_l4_last_match_uid = htonl (l4_status.last_match_uid);
  rmp->policy_l4_last_match_network_context =
    htonl (l4_status.last_match_network_context);
  rmp->policy_l4_last_match_reason_id =
    htonl (l4_status.last_match_reason_id);
  rmp->policy_l4_last_match_verdict = htonl (l4_status.last_match_verdict);
  rmp->policy_l4_last_match_winner = htonl (l4_status.last_match_winner);
  rmp->policy_l4_last_match_uid_known =
    htonl (l4_status.last_match_uid_known);
  rmp->policy_l4_last_match_device_direction =
    htonl (l4_status.last_match_device_direction);
  rmp->policy_l4_last_match_action = htonl (l4_status.last_match_action);
  rmp->policy_l4_last_evaluation_result =
    htonl (l4_status.last_evaluation_result);
  rmp->policy_l4_last_evaluation_verdict =
    htonl (l4_status.last_evaluation_verdict);
  rmp->policy_l4_last_evaluation_device_direction =
    htonl (l4_status.last_evaluation_device_direction);
  rmp->policy_l4_view_active = htonl (l4_status.view_active);
  rmp->policy_l4_view_rule_count = htonl (l4_status.view_rule_count);
  rmp->policy_l4_view_max_probes = htonl (l4_status.view_max_probes);
  rmp->policy_l4_view_last_match_winner_rank =
    htonl (l4_status.last_match_winner_rank);
  rmp->policy_l4_view_last_match_probes =
    htonl (l4_status.last_match_probes);
  rmp->policy_l4_view_last_match_candidate_count =
    htonl (l4_status.last_match_candidate_count);
  rmp->policy_l4_view_last_no_match_reason =
    htonl (l4_status.last_no_match_reason);
  rmp->policy_l4_typed_match_policy_key =
    clib_host_to_net_u64 (l4_status.typed_match_policy_key);
  rmp->policy_l4_typed_match_probe_key =
    clib_host_to_net_u64 (l4_status.typed_match_probe_key);
  rmp->policy_l4_last_evaluation_probe_key =
    clib_host_to_net_u64 (l4_status.last_evaluation_probe_key);
}

static void
vl_api_product_core_status_t_handler (vl_api_product_core_status_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_status_reply_t *rmp;
  int rv = 0;
  (void) mp;

  REPLY_MACRO2 (VL_API_PRODUCT_CORE_STATUS_REPLY,
                ({
                  rmp->retval = htonl (rv);
                  rmp->abi_version = htonl (SAKAMOTO_PRODUCT_ABI_VERSION);
                  rmp->api_version = htonl (SAKAMOTO_PRODUCT_API_VERSION);
                  rmp->generation = clib_host_to_net_u64 (pcm->generation);
                  rmp->core_ready = pcm->core_ready;
                  rmp->adapter_available =
                    product_core_adapter_available () ? 1 : 0;
                  rmp->protection_running =
                    product_core_protection_running () ? 1 : 0;
                  rmp->root_nfqueue_queue_id =
                    htonl (product_root_nfqueue_adapter_queue_id ());
                  rmp->root_nfqueue_queue_last =
                    htonl (product_root_nfqueue_adapter_queue_last ());
                  rmp->root_nfqueue_lane_count =
                    htonl (product_root_nfqueue_adapter_lane_count ());
                  rmp->root_nfqueue_ready_lane_mask =
                    htonl (product_root_nfqueue_adapter_ready_lane_mask ());
                  rmp->root_nfqueue_generation =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_generation ());
                  rmp->root_nfqueue_verdict_attempts =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_verdict_attempts ());
                  rmp->root_nfqueue_internal_settlements =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_internal_settlements ());
                  rmp->root_nfqueue_buffer_returns =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_buffer_returns ());
                  rmp->root_nfqueue_origin_local_completions =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_origin_local_completions ());
                  rmp->root_nfqueue_origin_remote_completions =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_origin_remote_completions ());
                  rmp->root_nfqueue_lane0_verdict_attempts =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_lane_verdict_attempts (0));
                  rmp->root_nfqueue_lane1_verdict_attempts =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_lane_verdict_attempts (1));
                  rmp->root_nfqueue_input_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_input_packets ());
                  rmp->root_nfqueue_output_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_output_packets ());
                  rmp->root_nfqueue_ipv4_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_ipv4_packets ());
                  rmp->root_nfqueue_ipv6_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_ipv6_packets ());
                  rmp->root_nfqueue_tcp_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_tcp_packets ());
                  rmp->root_nfqueue_udp_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_udp_packets ());
                  rmp->root_nfqueue_uid_known_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_uid_known_packets ());
                  rmp->root_nfqueue_uid_unknown_packets =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_uid_unknown_packets ());
                  rmp->root_nfqueue_last_ip_family =
                    htonl (product_root_nfqueue_adapter_last_ip_family ());
                  rmp->root_nfqueue_last_protocol =
                    htonl (product_root_nfqueue_adapter_last_protocol ());
                  rmp->root_nfqueue_last_hook =
                    htonl (product_root_nfqueue_adapter_last_hook ());
                  rmp->root_nfqueue_last_uid_known =
                    htonl (product_root_nfqueue_adapter_last_uid_known ());
                  rmp->root_nfqueue_last_uid =
                    htonl (product_root_nfqueue_adapter_last_uid ());
                  rmp->root_nfqueue_last_queue_id =
                    htonl (product_root_nfqueue_adapter_last_queue_id ());
                  rmp->root_nfqueue_last_packet_id =
                    htonl (product_root_nfqueue_adapter_last_packet_id ());
                  rmp->root_nfqueue_verdict_succeeded =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_verdict_succeeded ());
                  rmp->root_nfqueue_verdict_failed_definite =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_verdict_failed_definite ());
                  rmp->root_nfqueue_verdict_outcome_unknown =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_verdict_outcome_unknown ());
                  rmp->root_nfqueue_ingress_identity_missing =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_ingress_identity_missing ());
                  rmp->root_nfqueue_graph_submit_fail_opens =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_graph_submit_fail_opens ());
                  rmp->root_nfqueue_non_owner_bypasses =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_non_owner_bypasses ());
                  rmp->root_nfqueue_duplicate_completion_drops =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_duplicate_completion_drops ());
                  rmp->root_nfqueue_stale_completion_drops =
                    clib_host_to_net_u64 (
                      product_root_nfqueue_adapter_stale_completion_drops ());
                  rmp->vpn_tun_fd_attached =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_direct_udp4_socket_attached =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_direct_udp4_protect_succeeded =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_direct_udp4_bind_succeeded =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_tun_ingress_packets =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_tun_udp4_tun_origin_packets =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_flow_stack_admissions =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_direct_udp4_send_succeeded =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_direct_udp4_transport_failed =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_flow_stack_return_packets =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_flow_stack_return_provenance_packets =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_tun_write_completions =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_infrastructure_faults =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->vpn_duplicate_or_stale_drops =
                    clib_host_to_net_u64 (
                      0 /* VPN Flow Stack not implemented; reserved ABI counter. */);
                  rmp->product_graph_worker_count =
                    htonl (product_packet_graph_worker_count ());
                  rmp->product_graph_flow_domain =
                    htonl (product_packet_graph_flow_domain ());
                  rmp->product_graph_hash_seed =
                    clib_host_to_net_u64 (product_packet_graph_hash_seed ());
                  rmp->product_graph_handoff_credits =
                    htonl (product_packet_graph_handoff_credits ());
                  rmp->product_graph_vpp_worker_count =
                    htonl (vlib_num_workers ());
                  rmp->product_graph_vpp_main_core =
                    htonl (product_core_vpp_main_core ());
                  rmp->product_graph_vpp_worker0_thread_index =
                    htonl (product_core_vpp_worker_thread_index (0));
                  rmp->product_graph_vpp_worker0_core =
                    htonl (product_core_vpp_worker_core (0));
                  rmp->product_graph_vpp_worker1_thread_index =
                    htonl (product_core_vpp_worker_thread_index (1));
                  rmp->product_graph_vpp_worker1_core =
                    htonl (product_core_vpp_worker_core (1));
                  rmp->product_graph_enabled =
                    htonl (product_packet_graph_enabled ());
                  rmp->product_graph_accepting =
                    htonl (product_packet_graph_accepting ());
                  rmp->product_graph_worker_layout_ready =
                    htonl (product_core_graph_worker_layout_ready ());
                  rmp->product_graph_obligation_debt =
                    clib_host_to_net_u64 (
                      product_packet_graph_obligation_debt ());
                  rmp->product_graph_buffer_debt =
                    clib_host_to_net_u64 (product_packet_graph_buffer_debt ());
                  rmp->product_graph_handoff_debt =
                    clib_host_to_net_u64 (product_packet_graph_handoff_debt ());
                  product_core_set_policy_status_fields (rmp);
                  clib_memset (rmp->artifact_id, 0, sizeof (rmp->artifact_id));
                  clib_memset (rmp->api_identity, 0, sizeof (rmp->api_identity));
                  clib_memset (rmp->vpp_revision, 0, sizeof (rmp->vpp_revision));
                  clib_memcpy (rmp->artifact_id,
                               SAKAMOTO_PRODUCT_ARTIFACT_ID,
                               sizeof (SAKAMOTO_PRODUCT_ARTIFACT_ID));
                  clib_memcpy (rmp->api_identity,
                               SAKAMOTO_PRODUCT_API_IDENTITY,
                               sizeof (SAKAMOTO_PRODUCT_API_IDENTITY));
                  clib_memcpy (rmp->vpp_revision,
                               SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION,
                               sizeof (SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION));
                }));
}

static int
product_core_policy_identity_valid (const uint8_t identity[96])
{
  size_t length = 0;

  while (length < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX
         && identity[length] != '\0')
    length++;
  if (length == 0 || length == SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX)
    return 0;
  for (size_t index = length + 1;
       index < SAKAMOTO_PRODUCT_POLICY_IDENTITY_MAX; index++)
    if (identity[index] != '\0')
      return 0;
  for (size_t index = 0; index < length; index++)
    if (identity[index] == '\n' || identity[index] == '\r'
        || identity[index] == '=')
      return 0;
  return 1;
}

static int
product_core_policy_rule_valid (
  const sakamoto_product_policy_rule_entry_t *entry, uint32_t kind)
{
  if (entry->subject_uid == UINT32_MAX || entry->network_context == 0
      || entry->rule_kind != kind
      || (entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_PASS_NEXT
          && entry->action != SAKAMOTO_PRODUCT_POLICY_ACTION_DROP)
      || entry->enabled > 1 || entry->rule_id == 0 || entry->reason_id == 0
      || entry->reserved != 0)
    return 0;

  if (kind == SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE)
    {
      static const uint8_t zero_address[16] = {0};
      uint32_t max_prefix;

      /* GateMatrix is a bounded predicate table.  Zero is the wildcard for
       * family/protocol/direction and the authoring ABI leaves L4-only port
       * fields at zero; the graph normalizes those fields to any-port. */
      if ((entry->ip_family != 0
              && entry->ip_family != SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4
              && entry->ip_family != SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV6)
          || (entry->ip_protocol != 0
              && entry->ip_protocol != SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_TCP
              && entry->ip_protocol != SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_UDP)
          || (entry->direction != 0
              && entry->direction != SAKAMOTO_PRODUCT_POLICY_DIRECTION_INPUT
              && entry->direction != SAKAMOTO_PRODUCT_POLICY_DIRECTION_OUTPUT)
          || entry->source_port_first > UINT16_MAX
          || entry->source_port_last > UINT16_MAX
          || entry->destination_port_first > UINT16_MAX
          || entry->destination_port_last > UINT16_MAX
          || (entry->source_port_first != 0
              && entry->source_port_first > entry->source_port_last)
          || (entry->destination_port_first != 0
              && entry->destination_port_first > entry->destination_port_last))
        return 0;
      if (entry->ip_family == 0)
        return entry->source_prefix_len == 0
               && entry->destination_prefix_len == 0
               && memcmp (entry->source_address, zero_address, 16) == 0
               && memcmp (entry->destination_address, zero_address, 16) == 0;

      max_prefix = entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4
                     ? 32
                     : 128;
      if (entry->source_prefix_len > max_prefix
          || entry->destination_prefix_len > max_prefix)
        return 0;
      if (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4)
        for (size_t index = 4; index < 16; index++)
          if (entry->source_address[index] != 0
              || entry->destination_address[index] != 0)
            return 0;
      return 1;
    }

  uint32_t max_prefix;
  if (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV4)
    {
      max_prefix = 32;
      for (size_t index = 4; index < 16; index++)
        if (entry->source_address[index] != 0
            || entry->destination_address[index] != 0)
          return 0;
    }
  else if (entry->ip_family == SAKAMOTO_PRODUCT_POLICY_IP_FAMILY_IPV6)
    max_prefix = 128;
  else
    return 0;

  return (entry->ip_protocol == SAKAMOTO_PRODUCT_POLICY_IP_PROTOCOL_TCP
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

static int
product_core_policy_bundle_entries_valid (
  const sakamoto_product_policy_rule_entry_t *gate_entries,
  uint32_t gate_entry_count,
  const sakamoto_product_policy_rule_entry_t *l4_entries,
  uint32_t l4_rule_count)
{
  const sakamoto_product_policy_rule_entry_t zero = {0};
  uint64_t rule_ids[SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES];
  uint32_t rule_id_count = 0;

  for (uint32_t index = 0;
       index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES; index++)
    {
      const sakamoto_product_policy_rule_entry_t *entry = &gate_entries[index];
      if (index < gate_entry_count)
        {
          if (!product_core_policy_rule_valid (
                entry, SAKAMOTO_PRODUCT_POLICY_RULE_KIND_GATE))
            return 0;
          for (uint32_t prior = 0; prior < rule_id_count; prior++)
            if (rule_ids[prior] == entry->rule_id)
              return 0;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof (*entry)) != 0)
        return 0;
    }
  for (uint32_t index = 0;
       index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES; index++)
    {
      const sakamoto_product_policy_rule_entry_t *entry = &l4_entries[index];
      if (index < l4_rule_count)
        {
          if (!product_core_policy_rule_valid (
                entry, SAKAMOTO_PRODUCT_POLICY_RULE_KIND_L4))
            return 0;
          for (uint32_t prior = 0; prior < rule_id_count; prior++)
            if (rule_ids[prior] == entry->rule_id)
              return 0;
          rule_ids[rule_id_count++] = entry->rule_id;
        }
      else if (memcmp (entry, &zero, sizeof (*entry)) != 0)
        return 0;
    }
  return 1;
}

static void
product_core_policy_rule_from_vapi (
  const vl_api_product_policy_rule_entry_t *source,
  sakamoto_product_policy_rule_entry_t *destination)
{
  memset (destination, 0, sizeof (*destination));
  destination->subject_uid = ntohl (source->subject_uid);
  destination->network_context = ntohl (source->network_context);
  destination->ifindex = ntohl (source->ifindex);
  destination->rule_kind = ntohl (source->rule_kind);
  destination->ip_family = ntohl (source->ip_family);
  destination->ip_protocol = ntohl (source->ip_protocol);
  destination->direction = ntohl (source->direction);
  destination->action = ntohl (source->action);
  destination->enabled = ntohl (source->enabled);
  destination->source_prefix_len = ntohl (source->source_prefix_len);
  destination->destination_prefix_len = ntohl (source->destination_prefix_len);
  destination->source_port_first = ntohl (source->source_port_first);
  destination->source_port_last = ntohl (source->source_port_last);
  destination->destination_port_first = ntohl (source->destination_port_first);
  destination->destination_port_last = ntohl (source->destination_port_last);
  destination->priority = ntohl (source->priority);
  destination->order = ntohl (source->order);
  destination->reason_id = ntohl (source->reason_id);
  destination->reserved = ntohl (source->reserved);
  destination->rule_id = clib_net_to_host_u64 (source->rule_id);
  memcpy (destination->source_address, source->source_address,
          sizeof (destination->source_address));
  memcpy (destination->destination_address, source->destination_address,
          sizeof (destination->destination_address));
}

static void
product_core_l4_rule_from_bundle (
  const sakamoto_product_policy_rule_entry_t *source,
  product_l4_policy_rule_t *destination)
{
  memset (destination, 0, sizeof (*destination));
  destination->rule_id = source->rule_id;
  destination->uid = source->subject_uid;
  destination->network_context_id = source->network_context;
  destination->ifindex = source->ifindex;
  destination->priority = source->priority;
  destination->order = source->order;
  destination->reason_id = source->reason_id;
  destination->source_port_first = (uint16_t) source->source_port_first;
  destination->source_port_last = (uint16_t) source->source_port_last;
  destination->destination_port_first =
    (uint16_t) source->destination_port_first;
  destination->destination_port_last =
    (uint16_t) source->destination_port_last;
  destination->family = (uint8_t) source->ip_family;
  destination->protocol = (uint8_t) source->ip_protocol;
  destination->direction = (uint8_t) source->direction;
  destination->source_prefix_length = (uint8_t) source->source_prefix_len;
  destination->destination_prefix_length =
    (uint8_t) source->destination_prefix_len;
  destination->action = source->action == SAKAMOTO_PRODUCT_POLICY_ACTION_DROP
                          ? PRODUCT_L4_POLICY_ACTION_DROP
                          : PRODUCT_L4_POLICY_ACTION_ALLOW;
  memcpy (destination->source_address, source->source_address,
          sizeof (destination->source_address));
  memcpy (destination->destination_address, source->destination_address,
          sizeof (destination->destination_address));
}

static void
product_core_gate_rule_from_bundle (
  const sakamoto_product_policy_rule_entry_t *source,
  product_packet_graph_gate_entry_t *destination)
{
  product_core_l4_rule_from_bundle (source, destination);
  /* Gate authoring uses zero as the omitted interface predicate. */
  if (source->ifindex == 0)
    destination->ifindex = PRODUCT_L4_POLICY_IFINDEX_ANY;
  /* Gate-only ABI entries encode an omitted port predicate as all zeros. */
  if (source->source_port_first == 0 && source->source_port_last == 0)
    {
      destination->source_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
      destination->source_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
    }
  if (source->destination_port_first == 0 && source->destination_port_last == 0)
    {
      destination->destination_port_first = PRODUCT_L4_POLICY_PORT_FIRST_ANY;
      destination->destination_port_last = PRODUCT_L4_POLICY_PORT_LAST_ANY;
    }
}

static void
vl_api_product_core_policy_bundle_apply_t_handler (
  vl_api_product_core_policy_bundle_apply_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_policy_bundle_apply_reply_t *rmp;
  sakamoto_product_policy_rule_entry_t gate_entries[
    SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES];
  sakamoto_product_policy_rule_entry_t l4_entries[
    SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES];
  product_packet_graph_gate_entry_t gate_rules[
    SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES];
  product_l4_policy_rule_t l4_rules[
    SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES];
  product_l4_policy_view_t next_l4_view;
  u64 request_generation = clib_net_to_host_u64 (mp->generation);
  u64 requested_revision = clib_net_to_host_u64 (mp->requested_revision);
  u64 snapshot_hash = clib_net_to_host_u64 (mp->snapshot_hash);
  u32 abi_version = ntohl (mp->abi_version);
  u32 struct_size = ntohl (mp->struct_size);
  u32 gate_entry_count = ntohl (mp->gate_entry_count);
  u32 l4_rule_count = ntohl (mp->l4_rule_count);
  u32 default_pass = ntohl (mp->default_pass);
  u32 reserved = ntohl (mp->reserved);
  u32 active_gate_count = 0;
  u32 gate_claim_count = 0;
  u32 active_l4_count = 0;
  int32_t rv = 0;

  for (u32 index = 0; index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES;
       index++)
    product_core_policy_rule_from_vapi (&mp->gate_entries[index],
                                        &gate_entries[index]);
  for (u32 index = 0; index < SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES;
       index++)
    product_core_policy_rule_from_vapi (&mp->l4_entries[index],
                                        &l4_entries[index]);

  if (request_generation != pcm->generation)
    {
      rv = -5;
      pcm->policy_requested_revision = requested_revision;
      pcm->policy_last_apply_status_code = 5;
      pcm->policy_generation_match = 0;
    }
  else if (abi_version != SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION
           || struct_size != sizeof (sakamoto_product_policy_bundle_t)
           || requested_revision == 0 || snapshot_hash == 0
           || gate_entry_count > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES
           || l4_rule_count > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES
           || gate_entry_count + l4_rule_count
                > SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES
           || default_pass > 1 || reserved != 0
           || !product_core_policy_identity_valid (mp->snapshot_identity)
           || !product_core_policy_bundle_entries_valid (
                gate_entries, gate_entry_count, l4_entries, l4_rule_count))
    {
      rv = -22;
      pcm->policy_requested_revision = requested_revision;
      pcm->policy_last_apply_status_code = 22;
      pcm->policy_generation = pcm->generation;
      pcm->policy_generation_match = 1;
    }
  else
    {
      for (u32 index = 0; index < gate_entry_count; index++)
        if (gate_entries[index].enabled != 0)
          {
            product_core_gate_rule_from_bundle (
              &gate_entries[index], &gate_rules[active_gate_count]);
            active_gate_count++;
            if (gate_entries[index].action
                == SAKAMOTO_PRODUCT_POLICY_ACTION_DROP)
              {
                gate_claim_count++;
              }
          }
      for (u32 index = 0; index < l4_rule_count; index++)
        if (l4_entries[index].enabled != 0)
          product_core_l4_rule_from_bundle (&l4_entries[index],
                                            &l4_rules[active_l4_count++]);

      product_l4_policy_init (&next_l4_view);
      product_l4_policy_status_t compile_status = product_l4_policy_compile (
        &next_l4_view, l4_rules, active_l4_count);
      if (compile_status != PRODUCT_L4_POLICY_STATUS_OK)
        rv = compile_status == PRODUCT_L4_POLICY_STATUS_CAPACITY_EXCEEDED
               ? -7
               : -22;
      else
        {
          product_packet_graph_policy_bundle_t graph_bundle = {
            .generation = pcm->generation,
            .revision = requested_revision,
            .snapshot_hash = snapshot_hash,
            .gate_entries = gate_rules,
            .gate_entry_count = active_gate_count,
            .l4_rules = l4_rules,
            .l4_rule_count = active_l4_count,
          };
          rv = product_packet_graph_apply_policy_bundle (&graph_bundle);
        }

      if (rv == 0)
        {
          pcm->policy_requested_revision = requested_revision;
          pcm->policy_active_revision = requested_revision;
          pcm->policy_generation = pcm->generation;
          pcm->policy_snapshot_hash = snapshot_hash;
          pcm->policy_worker0_revision = requested_revision;
          pcm->policy_worker1_revision = requested_revision;
          pcm->policy_snapshot_empty = gate_entry_count == 0
                                       && l4_rule_count == 0;
          pcm->policy_default_pass = default_pass;
          pcm->policy_gate_claim_count = gate_claim_count;
          pcm->policy_l4_rule_count = l4_rule_count;
          pcm->policy_last_apply_status_code = 0;
          pcm->policy_mixed_revision = 0;
          pcm->policy_artifact_match = 1;
          pcm->policy_generation_match = 1;
          pcm->policy_gate_subject_uid = 0;
          pcm->policy_gate_network_context = 0;
          pcm->policy_gate_blocked = 0;
          pcm->policy_gate_reason_id = 0;
          pcm->policy_gate_rule_id = 0;
          /* A scalar status identity is valid only for a one-entry table. */
          if (active_gate_count == 1)
            {
              const product_packet_graph_gate_entry_t *entry = &gate_rules[0];
              pcm->policy_gate_subject_uid = entry->uid;
              pcm->policy_gate_network_context = entry->network_context_id;
              pcm->policy_gate_blocked =
                entry->action == PRODUCT_L4_POLICY_ACTION_DROP;
              pcm->policy_gate_reason_id = entry->reason_id;
              pcm->policy_gate_rule_id = entry->rule_id;
            }
          product_core_copy_policy_identity (pcm->policy_snapshot_identity,
                                             mp->snapshot_identity);
        }
      else
        {
          /* A failed compile/publication never replaces the prior view. */
          pcm->policy_requested_revision = requested_revision;
          pcm->policy_last_apply_status_code =
            rv < 0 ? (u32) -rv : (u32) rv;
          pcm->policy_generation = pcm->generation;
          pcm->policy_generation_match = 1;
        }
    }

  REPLY_MACRO2 (VL_API_PRODUCT_CORE_POLICY_BUNDLE_APPLY_REPLY,
                ({
                  rmp->retval = htonl (rv);
                }));
}

static void
vl_api_product_core_policy_apply_t_handler (
  vl_api_product_core_policy_apply_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_policy_apply_reply_t *rmp;
  i32 rv = 0;
  u64 request_generation = clib_net_to_host_u64 (mp->generation);
  u64 requested_revision = clib_net_to_host_u64 (mp->requested_revision);
  u64 snapshot_hash = clib_net_to_host_u64 (mp->snapshot_hash);
  u32 snapshot_empty = mp->snapshot_empty ? 1U : 0U;
  u32 default_pass = mp->default_pass ? 1U : 0U;
  u32 gate_claim_count = ntohl (mp->gate_claim_count);
  u32 l4_rule_count = ntohl (mp->l4_rule_count);
  u32 gate_subject_uid = ntohl (mp->gate_subject_uid);
  u32 gate_network_context = ntohl (mp->gate_network_context);
  u32 gate_blocked = mp->gate_blocked ? 1U : 0U;
  u32 gate_reason_id = ntohl (mp->gate_reason_id);
  u64 gate_rule_id = clib_net_to_host_u64 (mp->gate_rule_id);
  u32 l4_subject_uid = ntohl (mp->l4_subject_uid);
  u32 l4_network_context = ntohl (mp->l4_network_context);
  u32 l4_ip_family = ntohl (mp->l4_ip_family);
  u32 l4_ip_protocol = ntohl (mp->l4_ip_protocol);
  u32 l4_direction = ntohl (mp->l4_direction);
  u32 l4_action = ntohl (mp->l4_action);
  u32 l4_source_prefix_len = ntohl (mp->l4_source_prefix_len);
  u32 l4_destination_prefix_len = ntohl (mp->l4_destination_prefix_len);
  u32 l4_source_port_first = ntohl (mp->l4_source_port_first);
  u32 l4_source_port_last = ntohl (mp->l4_source_port_last);
  u32 l4_destination_port_first = ntohl (mp->l4_destination_port_first);
  u32 l4_destination_port_last = ntohl (mp->l4_destination_port_last);
  u32 l4_priority = ntohl (mp->l4_priority);
  u32 l4_order = ntohl (mp->l4_order);
  u32 l4_reason_id = ntohl (mp->l4_reason_id);
  u64 l4_rule_id = clib_net_to_host_u64 (mp->l4_rule_id);
  product_packet_graph_l4_policy_t parsed_l4 = { 0 };
  int valid_l4 = l4_rule_count == 1
                 && gate_claim_count == 0
                 && !snapshot_empty && default_pass
                 && gate_subject_uid == 0 && gate_network_context == 0
                 && gate_blocked == 0 && gate_reason_id == 0
                 && gate_rule_id == 0
                 && l4_subject_uid != UINT32_MAX
                 && l4_network_context != 0 && l4_reason_id != 0
                 && l4_rule_id != 0
                 && l4_ip_family == PRODUCT_PACKET_GRAPH_L4_FAMILY_IPV4
                 && l4_ip_protocol == PRODUCT_PACKET_GRAPH_L4_PROTOCOL_TCP
                 && (l4_direction == PRODUCT_PACKET_GRAPH_L4_DIRECTION_INPUT
                     || l4_direction == PRODUCT_PACKET_GRAPH_L4_DIRECTION_OUTPUT)
                 && (l4_action == PRODUCT_PACKET_GRAPH_L4_ACTION_ALLOW
                     || l4_action == PRODUCT_PACKET_GRAPH_L4_ACTION_DROP)
                 && l4_source_prefix_len <= 32
                 && l4_destination_prefix_len <= 32
                 && l4_source_port_first <= UINT16_MAX
                 && l4_source_port_last <= UINT16_MAX
                 && l4_destination_port_first <= UINT16_MAX
                 && l4_destination_port_last <= UINT16_MAX
                 && l4_source_port_first <= l4_source_port_last
                 && l4_destination_port_first <= l4_destination_port_last;
  int valid_empty = snapshot_empty && default_pass && gate_claim_count == 0
                    && l4_rule_count == 0;
  int valid_gate_block =
    !snapshot_empty && default_pass && gate_claim_count == 1
    && l4_rule_count == 0 && gate_subject_uid != UINT32_MAX
    && gate_network_context != 0 && gate_blocked
    && gate_reason_id != 0 && gate_rule_id != 0;
  int valid_gate_open =
    !snapshot_empty && default_pass && gate_claim_count == 0
    && l4_rule_count == 0 && gate_subject_uid != UINT32_MAX
    && gate_network_context != 0 && !gate_blocked
    && gate_reason_id != 0 && gate_rule_id != 0;

  if (request_generation != pcm->generation)
    {
      rv = -5;
      pcm->policy_requested_revision = requested_revision;
      pcm->policy_last_apply_status_code = 5;
      pcm->policy_generation_match = 0;
    }
  else if (requested_revision == 0 || snapshot_hash == 0
           || (!valid_empty && !valid_gate_block && !valid_gate_open
               && !valid_l4))
    {
      rv = -22;
      pcm->policy_requested_revision = requested_revision;
      pcm->policy_last_apply_status_code = 22;
      pcm->policy_generation = pcm->generation;
      pcm->policy_generation_match = 1;
    }
  else
    {
      pcm->policy_requested_revision = requested_revision;
      pcm->policy_active_revision = requested_revision;
      pcm->policy_generation = pcm->generation;
      pcm->policy_snapshot_hash = snapshot_hash;
      pcm->policy_worker0_revision = requested_revision;
      pcm->policy_worker1_revision = requested_revision;
      pcm->policy_snapshot_empty = snapshot_empty;
      pcm->policy_default_pass = default_pass;
      pcm->policy_gate_claim_count = gate_claim_count;
      pcm->policy_l4_rule_count = l4_rule_count;
      pcm->policy_last_apply_status_code = 0;
      pcm->policy_mixed_revision = 0;
      pcm->policy_artifact_match = 1;
      pcm->policy_generation_match = 1;
      pcm->policy_gate_subject_uid =
        valid_gate_block || valid_gate_open ? gate_subject_uid : 0;
      pcm->policy_gate_network_context =
        valid_gate_block || valid_gate_open ? gate_network_context : 0;
      pcm->policy_gate_blocked = valid_gate_block ? 1U : 0U;
      pcm->policy_gate_reason_id =
        valid_gate_block || valid_gate_open ? gate_reason_id : 0;
      pcm->policy_gate_rule_id =
        valid_gate_block || valid_gate_open ? gate_rule_id : 0;
      product_core_copy_policy_identity (pcm->policy_snapshot_identity,
                                         mp->snapshot_identity);
      if (valid_l4)
        {
          parsed_l4.revision = requested_revision;
          parsed_l4.snapshot_hash = snapshot_hash;
          parsed_l4.rule_id = l4_rule_id;
          parsed_l4.subject_uid = l4_subject_uid;
          parsed_l4.network_context_id = l4_network_context;
          parsed_l4.reason_id = l4_reason_id;
          parsed_l4.priority = l4_priority;
          parsed_l4.order = l4_order;
          parsed_l4.source_address =
            product_core_ipv4_from_snapshot_address (mp->l4_source_address);
          parsed_l4.destination_address =
            product_core_ipv4_from_snapshot_address (
              mp->l4_destination_address);
          parsed_l4.source_port_first = (u16) l4_source_port_first;
          parsed_l4.source_port_last = (u16) l4_source_port_last;
          parsed_l4.destination_port_first =
            (u16) l4_destination_port_first;
          parsed_l4.destination_port_last = (u16) l4_destination_port_last;
          parsed_l4.source_prefix_length = (u8) l4_source_prefix_len;
          parsed_l4.destination_prefix_length =
            (u8) l4_destination_prefix_len;
          parsed_l4.direction = (u8) l4_direction;
          parsed_l4.protocol = (u8) l4_ip_protocol;
          parsed_l4.action = (u8) l4_action;
          product_packet_graph_publish_l4_policy (&parsed_l4);
        }
      else if (valid_gate_block)
        {
          product_packet_graph_gate_policy_t policy = {
            .revision = requested_revision,
            .snapshot_hash = snapshot_hash,
            .rule_id = gate_rule_id,
            .subject_uid = gate_subject_uid,
            .network_context_id = gate_network_context,
            .blocked = 1U,
            .reason_id = gate_reason_id,
          };
          product_packet_graph_publish_gate_policy (&policy);
        }
      else
        {
          product_packet_graph_clear_gate_policy (requested_revision,
                                                  snapshot_hash);
        }
    }

  REPLY_MACRO2 (VL_API_PRODUCT_CORE_POLICY_APPLY_REPLY,
                ({
                  rmp->retval = htonl (rv);
                }));
}

#include "product_core.api.c"

static clib_error_t *
product_core_init (vlib_main_t *vm)
{
  product_core_main_t *pcm = &product_core_main;
  pcm->vlib_main = vm;
  pcm->generation = product_core_generation ();
  pcm->msg_id_base = setup_message_id_table ();
  if (pcm->msg_id_base == UINT16_MAX)
    {
      pcm->core_ready = 0;
      return clib_error_return (0,
                                "product core API message ID table unavailable");
    }
  pcm->core_ready = 1;
  if (product_core_profile_is_root ()
      && !product_root_nfqueue_adapter_start (vm, pcm->generation))
    pcm->core_ready = 0;
  return 0;
}

VLIB_INIT_FUNCTION (product_core_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Sakamoto Product VPP packet kernel and control identity",
};
