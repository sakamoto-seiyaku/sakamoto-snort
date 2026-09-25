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
#include "product_network_snapshot.h"
#include "product_vpn_tun_adapter.h"
#include "product_rule_config.h"
#include "product_core_policy.h"

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
static product_rule_config_t *product_source_config;
static int product_core_waiting_for_policy;
extern vlib_node_registration_t product_core_start_adapters_node;

static uint32_t
product_core_publish_source (void *opaque, uint64_t revision, uint64_t hash,
                             const product_l4_policy_rule_t *rule, uint32_t count)
{
  product_core_main_t *pcm = opaque;
  product_packet_graph_policy_bundle_t bundle = {
    .generation = pcm->generation, .revision = revision, .snapshot_hash = hash,
    .l4_rules = rule, .l4_rule_count = count
  };
  if (product_packet_graph_apply_policy_bundle (&bundle) != PRODUCT_PACKET_OK)
    return SAKAMOTO_RULE_CONFIG_PUBLISH;
  pcm->policy_requested_revision = pcm->policy_active_revision = revision;
  pcm->policy_generation = pcm->generation;
  pcm->policy_snapshot_hash = hash;
  pcm->policy_worker0_revision = pcm->policy_worker1_revision = revision;
  pcm->policy_snapshot_empty = count == 0;
  pcm->policy_default_pass = 1;
  pcm->policy_gate_claim_count = 0;
  pcm->policy_l4_rule_count = count;
  pcm->policy_last_apply_status_code = 0;
  pcm->policy_artifact_match = pcm->policy_generation_match = 1;
  snprintf ((char *) pcm->policy_snapshot_identity,
            sizeof (pcm->policy_snapshot_identity), "rule-config/1/%llu/%llu",
            (unsigned long long) revision, (unsigned long long) hash);
  return 0;
}

int
product_core_policy_start (uint64_t generation)
{
  if (!product_source_config || generation != product_core_main.generation)
    return 0;
  return product_rule_config_activate (product_source_config,
                                       product_core_publish_source,
                                       &product_core_main) == 0;
}

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
                      product_vpn_tun_attached ());
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
                      product_vpn_tun_captured ());
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

/* Superseded snapshot writers cannot bypass the VPP-owned source. */
static void
vl_api_product_core_policy_apply_t_handler (vl_api_product_core_policy_apply_t *mp)
{
  (void) mp;
  vl_api_product_core_policy_apply_reply_t *rmp;
  int rv = -95;
  REPLY_MACRO2 (VL_API_PRODUCT_CORE_POLICY_APPLY_REPLY,
                ({ rmp->retval = htonl (rv); }));
}

static void
vl_api_product_core_policy_bundle_apply_t_handler (vl_api_product_core_policy_bundle_apply_t *mp)
{
  (void) mp;
  vl_api_product_core_policy_bundle_apply_reply_t *rmp;
  int rv = -95;
  REPLY_MACRO2 (VL_API_PRODUCT_CORE_POLICY_BUNDLE_APPLY_REPLY,
                ({ rmp->retval = htonl (rv); }));
}

static void
vl_api_product_core_rule_config_t_handler (vl_api_product_core_rule_config_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_rule_config_reply_t *rmp;
  sakamoto_product_rule_config_request_t request = {
    .schema = ntohl (mp->schema), .operation = ntohl (mp->operation),
    .expected_saved_revision = clib_net_to_host_u64 (mp->expected_saved_revision)
  };
#define FROM_RULE(field) request.rule.field = ntohl (mp->rule.field)
  FROM_RULE (present); FROM_RULE (uid); FROM_RULE (protocol);
  FROM_RULE (direction); FROM_RULE (action); FROM_RULE (source_port);
  FROM_RULE (destination_port); FROM_RULE (reserved);
#undef FROM_RULE
  memcpy (request.rule.source_address, mp->rule.source_address, 4);
  memcpy (request.rule.destination_address, mp->rule.destination_address, 4);
  request.count = ntohl (mp->count); request.reserved = ntohl (mp->reserved);
  for (unsigned i = 0; i < request.count && i < SAKAMOTO_RULE_CONFIG_MAX_RULES; ++i)
    {
      request.rules[i].version = clib_net_to_host_u64 (mp->rules[i].version);
      request.rules[i].base_version = clib_net_to_host_u64 (mp->rules[i].base_version);
      request.rules[i].uid = ntohl (mp->rules[i].uid);
      request.rules[i].network_context = ntohl (mp->rules[i].network_context);
      request.rules[i].ifindex = ntohl (mp->rules[i].ifindex);
      request.rules[i].priority = ntohl (mp->rules[i].priority);
      request.rules[i].order = ntohl (mp->rules[i].order);
      request.rules[i].family = ntohl (mp->rules[i].family);
      request.rules[i].protocol = ntohl (mp->rules[i].protocol);
      request.rules[i].direction = ntohl (mp->rules[i].direction);
      request.rules[i].action = ntohl (mp->rules[i].action);
      request.rules[i].source_prefix = ntohl (mp->rules[i].source_prefix);
      request.rules[i].destination_prefix = ntohl (mp->rules[i].destination_prefix);
      request.rules[i].source_port_first = ntohl (mp->rules[i].source_port_first);
      request.rules[i].source_port_last = ntohl (mp->rules[i].source_port_last);
      request.rules[i].destination_port_first = ntohl (mp->rules[i].destination_port_first);
      request.rules[i].destination_port_last = ntohl (mp->rules[i].destination_port_last);
      request.rules[i].reserved = ntohl (mp->rules[i].reserved);
      request.rules[i].expression_length = ntohl(mp->rules[i].expression_length);
      memcpy(request.rules[i].expression, mp->rules[i].expression, 64);
      memcpy (request.rules[i].source_address, mp->rules[i].source_address, 16);
      memcpy (request.rules[i].destination_address, mp->rules[i].destination_address, 16);
    }
  request.graph.group_count = ntohl (mp->graph.group_count);
  request.graph.edge_count = ntohl (mp->graph.edge_count);
  request.graph.binding_count = ntohl (mp->graph.binding_count);
  for (unsigned i = 0; i < request.graph.group_count && i < SAKAMOTO_RULE_CONFIG_MAX_GROUPS; ++i) {
    request.graph.groups[i] = ntohl (mp->graph.groups[i]);
  }
  for (unsigned i = 0; i < request.graph.edge_count && i < SAKAMOTO_RULE_CONFIG_MAX_EDGES; ++i) {
    request.graph.edges[i].group = ntohl (mp->graph.edges[i].group);
    request.graph.edges[i].kind = ntohl (mp->graph.edges[i].kind);
    request.graph.edges[i].target = ntohl (mp->graph.edges[i].target);
  }
  for (unsigned i = 0; i < request.graph.binding_count && i < SAKAMOTO_RULE_CONFIG_MAX_BINDINGS; ++i) {
    request.graph.bindings[i].id = ntohl (mp->graph.bindings[i].id);
    request.graph.bindings[i].uid = ntohl (mp->graph.bindings[i].uid);
    request.graph.bindings[i].kind = ntohl (mp->graph.bindings[i].kind);
    request.graph.bindings[i].target = ntohl (mp->graph.bindings[i].target);
    request.graph.bindings[i].mode = ntohl (mp->graph.bindings[i].mode);
  }
  sakamoto_product_rule_config_status_t status = {0};
  uint32_t result = SAKAMOTO_RULE_CONFIG_NOT_READY;
  int rv = 0;
  if (clib_net_to_host_u64 (mp->generation) != pcm->generation) rv = -5;
  else if (request.schema != SAKAMOTO_RULE_CONFIG_SCHEMA) result = SAKAMOTO_RULE_CONFIG_INVALID;
  else if (product_source_config)
    {
      if (request.operation == SAKAMOTO_RULE_CONFIG_QUERY) result = 0;
      else if (request.operation == SAKAMOTO_RULE_CONFIG_REPLACE || request.operation == SAKAMOTO_RULE_CONFIG_REPLACE_ALL || request.operation == SAKAMOTO_RULE_CONFIG_NETWORK_DISABLE)
        result = product_rule_config_replace (product_source_config, &request,
                                              product_core_publish_source, pcm);
      else result = SAKAMOTO_RULE_CONFIG_INVALID;
    }
  if (product_source_config) product_rule_config_query (product_source_config, &status);
  if (!rv && !result && request.operation != SAKAMOTO_RULE_CONFIG_QUERY
      && status.active_revision && product_core_waiting_for_policy)
    vlib_process_signal_event (pcm->vlib_main,
                               product_core_start_adapters_node.index, 1, 0);
  REPLY_MACRO2 (VL_API_PRODUCT_CORE_RULE_CONFIG_REPLY, ({
    rmp->retval = htonl (rv);
    rmp->generation = clib_host_to_net_u64 (pcm->generation);
    rmp->saved_revision = clib_host_to_net_u64 (status.saved_revision);
    rmp->active_revision = clib_host_to_net_u64 (status.active_revision);
    rmp->saved_rule_version = clib_host_to_net_u64 (status.saved_rule_version);
    rmp->active_rule_version = clib_host_to_net_u64 (status.active_rule_version);
    rmp->result = htonl (result);
    rmp->save_error = htonl (status.save_error);
    rmp->compile_error = htonl (status.compile_error);
    rmp->rule.present = htonl (status.rule.present);
    rmp->rule.uid = htonl (status.rule.uid);
    rmp->rule.protocol = htonl (status.rule.protocol);
    rmp->rule.direction = htonl (status.rule.direction);
    rmp->rule.action = htonl (status.rule.action);
    rmp->rule.source_port = htonl (status.rule.source_port);
    rmp->rule.destination_port = htonl (status.rule.destination_port);
    rmp->rule.reserved = htonl (status.rule.reserved);

    memcpy (rmp->rule.source_address, status.rule.source_address, 4);
    memcpy (rmp->rule.destination_address, status.rule.destination_address, 4);
    rmp->count = htonl (status.count);
    rmp->active_count = htonl (status.active_count);
    rmp->error_index = htonl (status.error_index);
    rmp->compiler_status = htonl (status.compiler_status);
    for (unsigned i = 0; i < status.count; ++i)
      {
        rmp->rules[i].version = clib_host_to_net_u64 (status.rules[i].version);
        rmp->rules[i].base_version = clib_host_to_net_u64 (status.rules[i].base_version);
        rmp->rules[i].uid = htonl (status.rules[i].uid);
        rmp->rules[i].network_context = htonl (status.rules[i].network_context);
        rmp->rules[i].ifindex = htonl (status.rules[i].ifindex);
        rmp->rules[i].priority = htonl (status.rules[i].priority);
        rmp->rules[i].order = htonl (status.rules[i].order);
        rmp->rules[i].family = htonl (status.rules[i].family);
        rmp->rules[i].protocol = htonl (status.rules[i].protocol);
        rmp->rules[i].direction = htonl (status.rules[i].direction);
        rmp->rules[i].action = htonl (status.rules[i].action);
        rmp->rules[i].source_prefix = htonl (status.rules[i].source_prefix);
        rmp->rules[i].destination_prefix = htonl (status.rules[i].destination_prefix);
        rmp->rules[i].source_port_first = htonl (status.rules[i].source_port_first);
        rmp->rules[i].source_port_last = htonl (status.rules[i].source_port_last);
        rmp->rules[i].destination_port_first = htonl (status.rules[i].destination_port_first);
        rmp->rules[i].destination_port_last = htonl (status.rules[i].destination_port_last);
        rmp->rules[i].reserved = htonl (status.rules[i].reserved);
        rmp->rules[i].expression_length = htonl(status.rules[i].expression_length);
        memcpy(rmp->rules[i].expression, status.rules[i].expression, 64);
        memcpy (rmp->rules[i].source_address, status.rules[i].source_address, 16);
        memcpy (rmp->rules[i].destination_address, status.rules[i].destination_address, 16);
      }
    rmp->graph.group_count = htonl (status.graph.group_count);
    rmp->graph.edge_count = htonl (status.graph.edge_count);
    rmp->graph.binding_count = htonl (status.graph.binding_count);
    for (unsigned i = 0; i < status.graph.group_count && i < SAKAMOTO_RULE_CONFIG_MAX_GROUPS; ++i) {
      rmp->graph.groups[i] = htonl (status.graph.groups[i]);
    }
    for (unsigned i = 0; i < status.graph.edge_count && i < SAKAMOTO_RULE_CONFIG_MAX_EDGES; ++i) {
      rmp->graph.edges[i].group = htonl (status.graph.edges[i].group);
      rmp->graph.edges[i].kind = htonl (status.graph.edges[i].kind);
      rmp->graph.edges[i].target = htonl (status.graph.edges[i].target);
    }
    for (unsigned i = 0; i < status.graph.binding_count && i < SAKAMOTO_RULE_CONFIG_MAX_BINDINGS; ++i) {
      rmp->graph.bindings[i].id = htonl (status.graph.bindings[i].id);
      rmp->graph.bindings[i].uid = htonl (status.graph.bindings[i].uid);
      rmp->graph.bindings[i].kind = htonl (status.graph.bindings[i].kind);
      rmp->graph.bindings[i].target = htonl (status.graph.bindings[i].target);
      rmp->graph.bindings[i].mode = htonl (status.graph.bindings[i].mode);
    }
    for (unsigned i = 0; i < status.active_count; ++i)
      rmp->active_versions[i] = clib_host_to_net_u64 (status.active_versions[i]);

  }));
}

static void
vl_api_product_core_network_publish_t_handler (
  vl_api_product_core_network_publish_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_network_publish_reply_t *rmp;
  sakamoto_product_network_snapshot_t snapshot = {0};
  u64 generation = clib_net_to_host_u64 (mp->generation);
  snapshot.revision = clib_net_to_host_u64 (mp->revision);
  snapshot.event_elapsed_ns = clib_net_to_host_u64 (mp->event_elapsed_ns);
  snapshot.count = ntohl (mp->count);
  snapshot.reserved = ntohl (mp->reserved);
  for (u32 i = 0; i < SAKAMOTO_PRODUCT_NETWORK_MAX_INTERFACES; ++i)
    {
      snapshot.entries[i].linux_ifindex = ntohl (mp->entries[i].linux_ifindex);
      snapshot.entries[i].context = ntohl (mp->entries[i].network_context);
    }
  int rv = generation == pcm->generation && pcm->core_ready
    && product_network_snapshot_publish (pcm->vlib_main, generation, &snapshot)
    ? 0 : -1;
  REPLY_MACRO2 (VL_API_PRODUCT_CORE_NETWORK_PUBLISH_REPLY,
               ({ rmp->retval = htonl (rv); }));
}

static void
vl_api_product_core_root_stop_t_handler (vl_api_product_core_root_stop_t *mp)
{
  product_core_main_t *pcm = &product_core_main;
  vl_api_product_core_root_stop_reply_t *rmp;
  u64 generation = clib_net_to_host_u64 (mp->generation);
  /* Default VPP API dispatch holds the worker barrier. No blocking wait
   * here: the supervisor retries only after this reply releases workers. */
  int stopped = product_core_profile_is_root () && generation == pcm->generation
    ? product_root_nfqueue_adapter_stop_step (pcm->vlib_main, generation) : -1;
  int rv = stopped < 0 ? -1 : 0;
  REPLY_MACRO2 (VL_API_PRODUCT_CORE_ROOT_STOP_REPLY,
    ({ rmp->retval = htonl (rv);
       rmp->generation = clib_host_to_net_u64 (pcm->generation);
       rmp->stopped = htonl (stopped == 1); }));
}

#include "product_core.api.c"

static clib_error_t *
product_core_init (vlib_main_t *vm)
{
  product_core_main_t *pcm = &product_core_main;
  pcm->vlib_main = vm;
  pcm->generation = product_core_generation ();
  product_source_config = product_rule_config_open (getenv ("SAKAMOTO_RULE_CONFIG_PATH"));
  pcm->msg_id_base = setup_message_id_table ();
  if (pcm->msg_id_base == UINT16_MAX)
    {
      pcm->core_ready = 0;
      return clib_error_return (0,
                                "product core API message ID table unavailable");
    }
  /* These main-thread handlers publish immutable banks and never access a
   * worker's FlowEntry pool. Queries and lifecycle retain their barriers. */
  vl_api_set_msg_thread_safe (vlibapi_get_main (),
    pcm->msg_id_base + VL_API_PRODUCT_CORE_POLICY_BUNDLE_APPLY, 1);
  vl_api_set_msg_thread_safe (vlibapi_get_main (),
    pcm->msg_id_base + VL_API_PRODUCT_CORE_POLICY_APPLY, 1);
  vl_api_set_msg_thread_safe (vlibapi_get_main (),
    pcm->msg_id_base + VL_API_PRODUCT_CORE_RULE_CONFIG, 1);
  pcm->core_ready = 1;
  return 0;
}

VLIB_INIT_FUNCTION (product_core_init);

/* Worker clones initially contain the main epoll fd. Wait until worker init
 * has created each worker's own file-poll state before assigning an fd. */
static u32 product_core_worker_ready_mask;

static clib_error_t *
product_core_worker_ready (vlib_main_t *vm)
{
  if (vm->thread_index == 1 || vm->thread_index == 2)
    clib_atomic_fetch_or (&product_core_worker_ready_mask,
                          1U << (vm->thread_index - 1));
  return 0;
}

VLIB_WORKER_INIT_FUNCTION (product_core_worker_ready);

static uword
product_core_start_adapters (vlib_main_t *vm, vlib_node_runtime_t *node,
                             vlib_frame_t *frame)
{
  product_core_main_t *pcm = &product_core_main;
  f64 deadline = vlib_time_now (vm) + 1.0;
  (void)node; (void)frame;
  if (!product_core_profile_is_root () && !product_vpn_tun_validation_enabled ())
    return 0;
  while (clib_atomic_load_acq_n (&product_core_worker_ready_mask) != 3)
    {
      if (vlib_time_now (vm) >= deadline)
        return 0;
      vlib_process_wait_for_event_or_clock (vm, 0.001);
    }
  for (;;)
    {
      vlib_worker_thread_barrier_sync (vm);
      int started = product_core_profile_is_root ()
        ? product_root_nfqueue_adapter_start (vm, pcm->generation)
        : product_vpn_tun_start (vm, pcm->generation);
      vlib_worker_thread_barrier_release (vm);
      sakamoto_product_rule_config_status_t config = {0};
      if (product_source_config)
        product_rule_config_query (product_source_config, &config);
      /* Only a source failure is an online repair wait. Adapter/control
       * failures keep their existing bounded supervisor recovery. */
      if (started || config.active_revision
          || (!config.compile_error && !config.save_error))
        break;
      product_core_waiting_for_policy = 1;
      vlib_process_wait_for_event (vm);
      (void) vlib_process_get_events (vm, 0);
      product_core_waiting_for_policy = 0;
    }
  return 0;
}

VLIB_REGISTER_NODE (product_core_start_adapters_node) = {
  .function = product_core_start_adapters,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "product-adapter-start",
  /* Match VPP's CLI control-process stack. Root startup now partitions real
   * VPP buffers before opening listeners; forced-inline allocator/free code
   * exceeds the default 32 KiB process stack in an unoptimized host build.
   * This is one bounded control-plane stack, not packet receive storage. */
  .process_log2_n_stack_bytes = 18,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Sakamoto Product VPP packet kernel and control identity",
};
