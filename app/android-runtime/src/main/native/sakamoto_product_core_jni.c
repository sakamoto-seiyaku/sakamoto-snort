/* SPDX-License-Identifier: Apache-2.0 */

#include <jni.h>

#include "sakamoto_product_abi.h"
#include "sakamoto_product_core_ffi.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

JNIEXPORT jlongArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeRuleConfig (
  JNIEnv *env, jclass type, jlong handle, jlong generation, jint operation,
  jlong expected_saved, jintArray fields)
{
  (void) type;
  sakamoto_product_rule_config_request_t request = {
    .schema = 1, .operation = (uint32_t) operation,
    .expected_saved_revision = (uint64_t) expected_saved
  };
  sakamoto_product_rule_config_status_t status = {0};
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (handle && generation > 0 && fields && (*env)->GetArrayLength (env, fields) == 9)
    {
      jint values[9];
      (*env)->GetIntArrayRegion (env, fields, 0, 9, values);
      if ((*env)->ExceptionCheck (env)) return NULL;
      request.rule.present = (uint32_t) values[0];
      request.rule.uid = (uint32_t) values[1];
      request.rule.protocol = (uint32_t) values[2];
      request.rule.direction = (uint32_t) values[3];
      request.rule.action = (uint32_t) values[4];
      request.rule.source_port = (uint32_t) values[5];
      request.rule.destination_port = (uint32_t) values[6];
      for (unsigned i = 0; i < 4; ++i)
        {
          request.rule.source_address[i] = (uint32_t) values[7] >> (24 - 8*i);
          request.rule.destination_address[i] = (uint32_t) values[8] >> (24 - 8*i);
        }
      code = sakamoto_product_core_rule_config (
        (sakamoto_product_core_handle_t *) (uintptr_t) handle,
        (uint64_t) generation, &request, &status);
    }
  uint32_t source = 0, destination = 0;
  for (unsigned i = 0; i < 4; ++i)
    { source = (source << 8) | status.rule.source_address[i];
      destination = (destination << 8) | status.rule.destination_address[i]; }
  jlong values[] = { code, (jlong) status.generation,
    (jlong) status.saved_revision, (jlong) status.active_revision,
    (jlong) status.saved_rule_version, (jlong) status.active_rule_version,
    status.result, status.save_error, status.compile_error, status.rule.present,
    status.rule.uid, status.rule.protocol, status.rule.direction, status.rule.action,
    status.rule.source_port, status.rule.destination_port, source, destination };
  jlongArray result = (*env)->NewLongArray (env, 18);
  if (result) (*env)->SetLongArrayRegion (env, result, 0, 18, values);
  return result;
}

/* Shared positional layout is documented in T02_RULE_CONFIGURATION.md and
 * checked by the Java and production VAPI boundary tests. */
enum {
    COMPLETE_RULE_WORDS = 43,
    COMPLETE_REPLY_HEADER_WORDS = 13,
    COMPLETE_SOURCE_WORD = 18,
    COMPLETE_DESTINATION_WORD = 22,
};

JNIEXPORT jlongArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeCompleteRuleConfig(
    JNIEnv *env, jclass type, jlong handle, jlong generation, jint operation, jlong expected_saved,
    jlongArray fields) {
    (void)type;
    sakamoto_product_rule_config_request_t request = {.schema = SAKAMOTO_RULE_CONFIG_SCHEMA,
                                                      .operation = (uint32_t)operation,
                                                      .expected_saved_revision =
                                                          (uint64_t)expected_saved};
    sakamoto_product_rule_config_status_t status = {0};
    uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
    jsize length = fields ? (*env)->GetArrayLength(env, fields) : -1;
    jsize rule_offset = 0;
    uint32_t rule_count = length >= 0 ? (uint32_t)length / COMPLETE_RULE_WORDS : UINT32_MAX;
    int valid = length >= 0 && length % COMPLETE_RULE_WORDS == 0;
    if (length > 0) {
        jlong marker;
        (*env)->GetLongArrayRegion(env, fields, 0, 1, &marker);
        if ((*env)->ExceptionCheck(env)) return NULL;
        if (marker == -1) {
            jlong header[5];
            if (length < 5) return NULL;
            (*env)->GetLongArrayRegion(env, fields, 0, 5, header);
            if ((*env)->ExceptionCheck(env)) return NULL;
            if (header[1] < 0 || header[1] > SAKAMOTO_RULE_CONFIG_MAX_RULES || header[2] < 0 || header[2] > SAKAMOTO_RULE_CONFIG_MAX_GROUPS ||
                header[3] < 0 || header[3] > SAKAMOTO_RULE_CONFIG_MAX_EDGES || header[4] < 0 || header[4] > SAKAMOTO_RULE_CONFIG_MAX_BINDINGS)
                return NULL;
            rule_offset = 5; rule_count = header[1];
            request.graph.group_count = header[2]; request.graph.edge_count = header[3];
            request.graph.binding_count = header[4];
            valid = length == 5 + rule_count * COMPLETE_RULE_WORDS + header[2] + 3*header[3] + 5*header[4];
            if (!valid) return NULL;
            jsize at = 5 + rule_count * COMPLETE_RULE_WORDS;
            for (unsigned i = 0; i < request.graph.group_count; ++i) {
                jlong value;
                (*env)->GetLongArrayRegion(env, fields, at++, 1, &value);
                if ((*env)->ExceptionCheck(env) || value < 0 || (uint64_t)value > UINT32_MAX) return NULL;
                request.graph.groups[i] = value;
            }
            for (unsigned i = 0; i < request.graph.edge_count; ++i) {
                jlong values[3];
                (*env)->GetLongArrayRegion(env, fields, at, 3, values); at += 3;
                if ((*env)->ExceptionCheck(env)) return NULL;
                for (unsigned j = 0; j < 3; ++j) if (values[j] < 0 || (uint64_t)values[j] > UINT32_MAX) return NULL;
                request.graph.edges[i] = (sakamoto_product_group_edge_t){values[0], values[1], values[2]};
            }
            for (unsigned i = 0; i < request.graph.binding_count; ++i) {
                jlong values[5];
                (*env)->GetLongArrayRegion(env, fields, at, 5, values); at += 5;
                if ((*env)->ExceptionCheck(env)) return NULL;
                for (unsigned j = 0; j < 5; ++j) if (values[j] < 0 || (uint64_t)values[j] > UINT32_MAX) return NULL;
                request.graph.bindings[i] = (sakamoto_product_rule_binding_t){values[0], values[1], values[2], values[3], values[4]};
            }
        }
    }
    if (handle && generation > 0 && valid && rule_count <= SAKAMOTO_RULE_CONFIG_MAX_RULES &&
        (operation == 0 || operation == 2 || operation == 3)) {
        request.count = rule_count;
        for (unsigned i = 0; i < request.count; ++i) {
            jlong values[COMPLETE_RULE_WORDS];
            (*env)->GetLongArrayRegion(env, fields, rule_offset + i * COMPLETE_RULE_WORDS, COMPLETE_RULE_WORDS,
                                       values);
            if ((*env)->ExceptionCheck(env))
                return NULL;
            for (unsigned j = 2; j < COMPLETE_RULE_WORDS; ++j)
                if (values[j] < 0 || (uint64_t)values[j] > UINT32_MAX)
                    return NULL;
            request.rules[i].version = (uint64_t)values[0];
            request.rules[i].base_version = (uint64_t)values[1];
            request.rules[i].uid = (uint32_t)values[2];
            request.rules[i].network_context = (uint32_t)values[3];
            request.rules[i].ifindex = (uint32_t)values[4];
            request.rules[i].priority = (uint32_t)values[5];
            request.rules[i].order = (uint32_t)values[6];
            request.rules[i].family = (uint32_t)values[7];
            request.rules[i].protocol = (uint32_t)values[8];
            request.rules[i].direction = (uint32_t)values[9];
            request.rules[i].action = (uint32_t)values[10];
            request.rules[i].source_prefix = (uint32_t)values[11];
            request.rules[i].destination_prefix = (uint32_t)values[12];
            request.rules[i].source_port_first = (uint32_t)values[13];
            request.rules[i].source_port_last = (uint32_t)values[14];
            request.rules[i].destination_port_first = (uint32_t)values[15];
            request.rules[i].destination_port_last = (uint32_t)values[16];
            request.rules[i].reserved = (uint32_t)values[17];
            request.rules[i].expression_length = (uint32_t)values[26];
            for (unsigned j = 0; j < 64; ++j)
                request.rules[i].expression[j] = (uint64_t)values[27+j/4] >> (24-(j%4)*8);
            for (unsigned j = 0; j < 16; ++j) {
                request.rules[i].source_address[j] =
                    (uint64_t)values[COMPLETE_SOURCE_WORD + j / 4] >> (24 - (j % 4) * 8);
                request.rules[i].destination_address[j] =
                    (uint64_t)values[COMPLETE_DESTINATION_WORD + j / 4] >> (24 - (j % 4) * 8);
            }
        }
        code =
            sakamoto_product_core_rule_config((sakamoto_product_core_handle_t *)(uintptr_t)handle,
                                              (uint64_t)generation, &request, &status);
    }
    if (status.count > SAKAMOTO_RULE_CONFIG_MAX_RULES ||
        status.active_count > SAKAMOTO_RULE_CONFIG_MAX_RULES ||
        status.graph.group_count > SAKAMOTO_RULE_CONFIG_MAX_GROUPS || status.graph.edge_count > SAKAMOTO_RULE_CONFIG_MAX_EDGES || status.graph.binding_count > SAKAMOTO_RULE_CONFIG_MAX_BINDINGS)
        return NULL;
    jlong header[] = {code,
                      (jlong)status.generation,
                      (jlong)status.saved_revision,
                      (jlong)status.active_revision,
                      (jlong)status.saved_rule_version,
                      (jlong)status.active_rule_version,
                      status.result,
                      status.save_error,
                      status.compile_error,
                      status.count,
                      status.active_count,
                      status.error_index,
                      status.compiler_status};
    jlongArray result =
        (*env)->NewLongArray(env, COMPLETE_REPLY_HEADER_WORDS + COMPLETE_RULE_WORDS * status.count +
                                      status.active_count + 3 + status.graph.group_count +
                                      3*status.graph.edge_count + 5*status.graph.binding_count);
    if (!result)
        return NULL;
    (*env)->SetLongArrayRegion(env, result, 0, COMPLETE_REPLY_HEADER_WORDS, header);
    for (unsigned i = 0; i < status.count; ++i) {
        jlong values[COMPLETE_RULE_WORDS] = {(jlong)status.rules[i].version, 0};
        values[2] = status.rules[i].uid;
        values[3] = status.rules[i].network_context;
        values[4] = status.rules[i].ifindex;
        values[5] = status.rules[i].priority;
        values[6] = status.rules[i].order;
        values[7] = status.rules[i].family;
        values[8] = status.rules[i].protocol;
        values[9] = status.rules[i].direction;
        values[10] = status.rules[i].action;
        values[11] = status.rules[i].source_prefix;
        values[12] = status.rules[i].destination_prefix;
        values[13] = status.rules[i].source_port_first;
        values[14] = status.rules[i].source_port_last;
        values[15] = status.rules[i].destination_port_first;
        values[16] = status.rules[i].destination_port_last;
        values[17] = status.rules[i].reserved;
        values[26] = status.rules[i].expression_length;
        for (unsigned j = 0; j < 64; ++j)
            values[27+j/4] |= (jlong)status.rules[i].expression[j] << (24-(j%4)*8);
        for (unsigned j = 0; j < 16; ++j) {
            values[COMPLETE_SOURCE_WORD + j / 4] |= (jlong)status.rules[i].source_address[j]
                                                    << (24 - (j % 4) * 8);
            values[COMPLETE_DESTINATION_WORD + j / 4] |=
                (jlong)status.rules[i].destination_address[j] << (24 - (j % 4) * 8);
        }
        (*env)->SetLongArrayRegion(env, result,
                                   COMPLETE_REPLY_HEADER_WORDS + i * COMPLETE_RULE_WORDS,
                                   COMPLETE_RULE_WORDS, values);
    }
    for (unsigned i = 0; i < status.active_count; ++i) {
        jlong version = (jlong)status.active_versions[i];
        (*env)->SetLongArrayRegion(
            env, result, COMPLETE_REPLY_HEADER_WORDS + status.count * COMPLETE_RULE_WORDS + i, 1,
            &version);
    }
    jsize at = COMPLETE_REPLY_HEADER_WORDS + COMPLETE_RULE_WORDS * status.count + status.active_count;
    jlong graph_header[] = {status.graph.group_count, status.graph.edge_count, status.graph.binding_count};
    (*env)->SetLongArrayRegion(env, result, at, 3, graph_header); at += 3;
    for (unsigned i = 0; i < status.graph.group_count; ++i) {
        jlong value = status.graph.groups[i];
        (*env)->SetLongArrayRegion(env, result, at++, 1, &value);
    }
    for (unsigned i = 0; i < status.graph.edge_count; ++i) {
        const sakamoto_product_group_edge_t *e = &status.graph.edges[i];
        jlong values[] = {e->group, e->kind, e->target};
        (*env)->SetLongArrayRegion(env, result, at, 3, values); at += 3;
    }
    for (unsigned i = 0; i < status.graph.binding_count; ++i) {
        const sakamoto_product_rule_binding_t *b = &status.graph.bindings[i];
        jlong values[] = {b->id, b->uid, b->kind, b->target, b->mode};
        (*env)->SetLongArrayRegion(env, result, at, 5, values); at += 5;
    }
    return result;
}

enum
{
  /* Keep the S191 prefix count named for source-compatible contracts; the
   * appended S192 view values are part of the wire count below. */
  STATUS_VALUE_COUNT = 135,
  STATUS_VIEW_VALUE_COUNT = 7,
  STATUS_ASSOCIATION_VALUE_COUNT = 3,
  STATUS_WIRE_VALUE_COUNT = STATUS_VALUE_COUNT + STATUS_VIEW_VALUE_COUNT
                             + STATUS_ASSOCIATION_VALUE_COUNT,
  CONNECT_VALUE_COUNT = STATUS_WIRE_VALUE_COUNT + 1,
};

static void
status_reset (sakamoto_product_status_t *status, uint64_t generation)
{
  memset (status, 0, sizeof (*status));
  status->abi_version = SAKAMOTO_PRODUCT_ABI_VERSION;
  status->api_version = SAKAMOTO_PRODUCT_API_VERSION;
  status->generation = generation;
  status->status_code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  strncpy (status->error_detail, "invalid Product Core JNI arguments",
           sizeof (status->error_detail) - 1U);
}

static jobjectArray
status_values (JNIEnv *env, const sakamoto_product_status_t *status,
               jlong handle, int include_handle)
{
  jclass string_class = (*env)->FindClass (env, "java/lang/String");
  if (string_class == NULL)
    return NULL;
  const jsize length = include_handle ? CONNECT_VALUE_COUNT : STATUS_WIRE_VALUE_COUNT;
  jobjectArray values = (*env)->NewObjectArray (env, length, string_class, NULL);
  (*env)->DeleteLocalRef (env, string_class);
  if (values == NULL)
    return NULL;

  char numeric[32];
  const char *fields[CONNECT_VALUE_COUNT];
  int index = 0;
  if (include_handle)
    {
      snprintf (numeric, sizeof (numeric), "%" PRId64, (int64_t) handle);
      fields[index++] = numeric;
    }

  char code[32];
  char generation[32];
  char core_ready[2];
  char adapter_available[2];
  char protection_running[2];
  char plugin_loaded[2];
  char vapi_handle_live[2];
  char generation_live[2];
  char abi_version[32];
  char api_version[32];
  char root_nfqueue_queue_id[32];
  char root_nfqueue_queue_last[32];
  char root_nfqueue_lane_count[32];
  char root_nfqueue_ready_lane_mask[32];
  char root_nfqueue_generation[32];
  char root_nfqueue_verdict_attempts[32];
  char root_nfqueue_internal_settlements[32];
  char root_nfqueue_buffer_returns[32];
  char root_nfqueue_origin_local_completions[32];
  char root_nfqueue_origin_remote_completions[32];
  char root_nfqueue_lane0_verdict_attempts[32];
  char root_nfqueue_lane1_verdict_attempts[32];
  char root_nfqueue_input_packets[32];
  char root_nfqueue_output_packets[32];
  char root_nfqueue_ipv4_packets[32];
  char root_nfqueue_ipv6_packets[32];
  char root_nfqueue_tcp_packets[32];
  char root_nfqueue_udp_packets[32];
  char root_nfqueue_uid_known_packets[32];
  char root_nfqueue_uid_unknown_packets[32];
  char root_nfqueue_last_ip_family[32];
  char root_nfqueue_last_protocol[32];
  char root_nfqueue_last_hook[32];
  char root_nfqueue_last_uid_known[32];
  char root_nfqueue_last_uid[32];
  char root_nfqueue_last_queue_id[32];
  char root_nfqueue_last_packet_id[32];
  char root_nfqueue_verdict_succeeded[32];
  char root_nfqueue_verdict_failed_definite[32];
  char root_nfqueue_verdict_outcome_unknown[32];
  char root_nfqueue_ingress_identity_missing[32];
  char root_nfqueue_graph_submit_fail_opens[32];
  char root_nfqueue_non_owner_bypasses[32];
  char root_nfqueue_duplicate_completion_drops[32];
  char root_nfqueue_stale_completion_drops[32];
  char vpn_tun_fd_attached[32];
  char vpn_direct_udp4_socket_attached[32];
  char vpn_direct_udp4_protect_succeeded[32];
  char vpn_direct_udp4_bind_succeeded[32];
  char vpn_tun_ingress_packets[32];
  char vpn_tun_udp4_tun_origin_packets[32];
  char vpn_flow_stack_admissions[32];
  char vpn_direct_udp4_send_succeeded[32];
  char vpn_direct_udp4_transport_failed[32];
  char vpn_flow_stack_return_packets[32];
  char vpn_flow_stack_return_provenance_packets[32];
  char vpn_tun_write_completions[32];
  char vpn_infrastructure_faults[32];
  char vpn_duplicate_or_stale_drops[32];
  char product_graph_worker_count[32];
  char product_graph_hash_seed[32];
  char product_graph_handoff_credits[32];
  char product_graph_vpp_worker_count[32];
  char product_graph_vpp_main_core[32];
  char product_graph_vpp_worker0_thread_index[32];
  char product_graph_vpp_worker0_core[32];
  char product_graph_vpp_worker1_thread_index[32];
  char product_graph_vpp_worker1_core[32];
  char product_graph_enabled[32];
  char product_graph_accepting[32];
  char product_graph_worker_layout_ready[32];
  char product_graph_obligation_debt[32];
  char product_graph_buffer_debt[32];
  char product_graph_handoff_debt[32];
  char policy_requested_revision[32];
  char policy_active_revision[32];
  char policy_generation[32];
  char policy_snapshot_hash[32];
  char policy_worker0_revision[32];
  char policy_worker1_revision[32];
  char policy_snapshot_empty[32];
  char policy_default_pass[32];
  char policy_gate_claim_count[32];
  char policy_l4_rule_count[32];
  char policy_last_apply_status_code[32];
  char policy_mixed_revision[32];
  char policy_artifact_match[32];
  char policy_generation_match[32];
  char policy_gate_subject_uid[32];
  char policy_gate_network_context[32];
  char policy_gate_blocked[32];
  char policy_gate_reason_id[32];
  char policy_gate_rule_id[32];
  char policy_drop_records[32];
  char policy_last_drop_revision[32];
  char policy_last_drop_rule_id[32];
  char policy_last_drop_completion_attempts[32];
  char policy_last_drop_uid[32];
  char policy_last_drop_network_context[32];
  char policy_last_drop_reason_id[32];
  char policy_last_drop_verdict[32];
  char policy_last_drop_winner[32];
  char policy_last_drop_uid_known[32];
  char policy_last_drop_device_direction[32];
  char policy_l4_active_revision[32];
  char policy_l4_rule_id[32];
  char policy_l4_match_records[32];
  char policy_l4_no_match_records[32];
  char policy_l4_last_match_revision[32];
  char policy_l4_last_match_rule_id[32];
  char policy_l4_subject_uid[32];
  char policy_l4_network_context[32];
  char policy_l4_ip_family[32];
  char policy_l4_ip_protocol[32];
  char policy_l4_direction[32];
  char policy_l4_action[32];
  char policy_l4_priority[32];
  char policy_l4_order[32];
  char policy_l4_reason_id[32];
  char policy_l4_last_match_uid[32];
  char policy_l4_last_match_network_context[32];
  char policy_l4_last_match_reason_id[32];
  char policy_l4_last_match_verdict[32];
  char policy_l4_last_match_winner[32];
  char policy_l4_last_match_uid_known[32];
  char policy_l4_last_match_device_direction[32];
  char policy_l4_last_match_action[32];
  char policy_l4_last_evaluation_result[32];
  char policy_l4_last_evaluation_verdict[32];
  char policy_l4_last_evaluation_device_direction[32];
  char policy_l4_view_active[32];
  char policy_l4_view_rule_count[32];
  char policy_l4_view_max_probes[32];
  char policy_l4_view_last_match_winner_rank[32];
  char policy_l4_view_last_match_probes[32];
  char policy_l4_view_last_match_candidate_count[32];
  char policy_l4_view_last_no_match_reason[32];
  char policy_l4_typed_match_policy_key[32];
  char policy_l4_typed_match_probe_key[32];
  char policy_l4_last_evaluation_probe_key[32];
  snprintf (code, sizeof (code), "%" PRIu32, status->status_code);
  snprintf (generation, sizeof (generation), "%" PRIu64, status->generation);
  snprintf (abi_version, sizeof (abi_version), "%" PRIu32, status->abi_version);
  snprintf (api_version, sizeof (api_version), "%" PRIu32, status->api_version);
  snprintf (root_nfqueue_queue_id, sizeof (root_nfqueue_queue_id), "%" PRIu32,
            status->root_nfqueue_queue_id);
  snprintf (root_nfqueue_queue_last, sizeof (root_nfqueue_queue_last),
            "%" PRIu32, status->root_nfqueue_queue_last);
  snprintf (root_nfqueue_lane_count, sizeof (root_nfqueue_lane_count),
            "%" PRIu32, status->root_nfqueue_lane_count);
  snprintf (root_nfqueue_ready_lane_mask,
            sizeof (root_nfqueue_ready_lane_mask), "%" PRIu32,
            status->root_nfqueue_ready_lane_mask);
  snprintf (root_nfqueue_generation, sizeof (root_nfqueue_generation),
            "%" PRIu64, status->root_nfqueue_generation);
  snprintf (root_nfqueue_verdict_attempts,
            sizeof (root_nfqueue_verdict_attempts), "%" PRIu64,
            status->root_nfqueue_verdict_attempts);
  snprintf (root_nfqueue_internal_settlements,
            sizeof (root_nfqueue_internal_settlements), "%" PRIu64,
            status->root_nfqueue_internal_settlements);
  snprintf (root_nfqueue_buffer_returns,
            sizeof (root_nfqueue_buffer_returns), "%" PRIu64,
            status->root_nfqueue_buffer_returns);
  snprintf (root_nfqueue_origin_local_completions,
            sizeof (root_nfqueue_origin_local_completions), "%" PRIu64,
            status->root_nfqueue_origin_local_completions);
  snprintf (root_nfqueue_origin_remote_completions,
            sizeof (root_nfqueue_origin_remote_completions), "%" PRIu64,
            status->root_nfqueue_origin_remote_completions);
  snprintf (root_nfqueue_lane0_verdict_attempts,
            sizeof (root_nfqueue_lane0_verdict_attempts), "%" PRIu64,
            status->root_nfqueue_lane0_verdict_attempts);
  snprintf (root_nfqueue_lane1_verdict_attempts,
            sizeof (root_nfqueue_lane1_verdict_attempts), "%" PRIu64,
            status->root_nfqueue_lane1_verdict_attempts);
  snprintf (root_nfqueue_input_packets, sizeof (root_nfqueue_input_packets),
            "%" PRIu64, status->root_nfqueue_input_packets);
  snprintf (root_nfqueue_output_packets, sizeof (root_nfqueue_output_packets),
            "%" PRIu64, status->root_nfqueue_output_packets);
  snprintf (root_nfqueue_ipv4_packets, sizeof (root_nfqueue_ipv4_packets),
            "%" PRIu64, status->root_nfqueue_ipv4_packets);
  snprintf (root_nfqueue_ipv6_packets, sizeof (root_nfqueue_ipv6_packets),
            "%" PRIu64, status->root_nfqueue_ipv6_packets);
  snprintf (root_nfqueue_tcp_packets, sizeof (root_nfqueue_tcp_packets),
            "%" PRIu64, status->root_nfqueue_tcp_packets);
  snprintf (root_nfqueue_udp_packets, sizeof (root_nfqueue_udp_packets),
            "%" PRIu64, status->root_nfqueue_udp_packets);
  snprintf (root_nfqueue_uid_known_packets,
            sizeof (root_nfqueue_uid_known_packets), "%" PRIu64,
            status->root_nfqueue_uid_known_packets);
  snprintf (root_nfqueue_uid_unknown_packets,
            sizeof (root_nfqueue_uid_unknown_packets), "%" PRIu64,
            status->root_nfqueue_uid_unknown_packets);
  snprintf (root_nfqueue_last_ip_family,
            sizeof (root_nfqueue_last_ip_family), "%" PRIu32,
            status->root_nfqueue_last_ip_family);
  snprintf (root_nfqueue_last_protocol, sizeof (root_nfqueue_last_protocol),
            "%" PRIu32, status->root_nfqueue_last_protocol);
  snprintf (root_nfqueue_last_hook, sizeof (root_nfqueue_last_hook),
            "%" PRIu32, status->root_nfqueue_last_hook);
  snprintf (root_nfqueue_last_uid_known,
            sizeof (root_nfqueue_last_uid_known), "%" PRIu32,
            status->root_nfqueue_last_uid_known);
  snprintf (root_nfqueue_last_uid, sizeof (root_nfqueue_last_uid),
            "%" PRIu32, status->root_nfqueue_last_uid);
  snprintf (root_nfqueue_last_queue_id, sizeof (root_nfqueue_last_queue_id),
            "%" PRIu32, status->root_nfqueue_last_queue_id);
  snprintf (root_nfqueue_last_packet_id,
            sizeof (root_nfqueue_last_packet_id), "%" PRIu32,
            status->root_nfqueue_last_packet_id);
  snprintf (root_nfqueue_verdict_succeeded,
            sizeof (root_nfqueue_verdict_succeeded), "%" PRIu64,
            status->root_nfqueue_verdict_succeeded);
  snprintf (root_nfqueue_verdict_failed_definite,
            sizeof (root_nfqueue_verdict_failed_definite), "%" PRIu64,
            status->root_nfqueue_verdict_failed_definite);
  snprintf (root_nfqueue_verdict_outcome_unknown,
            sizeof (root_nfqueue_verdict_outcome_unknown), "%" PRIu64,
            status->root_nfqueue_verdict_outcome_unknown);
  snprintf (root_nfqueue_ingress_identity_missing,
            sizeof (root_nfqueue_ingress_identity_missing), "%" PRIu64,
            status->root_nfqueue_ingress_identity_missing);
  snprintf (root_nfqueue_graph_submit_fail_opens,
            sizeof (root_nfqueue_graph_submit_fail_opens), "%" PRIu64,
            status->root_nfqueue_graph_submit_fail_opens);
  snprintf (root_nfqueue_non_owner_bypasses,
            sizeof (root_nfqueue_non_owner_bypasses), "%" PRIu64,
            status->root_nfqueue_non_owner_bypasses);
  snprintf (root_nfqueue_duplicate_completion_drops,
            sizeof (root_nfqueue_duplicate_completion_drops), "%" PRIu64,
            status->root_nfqueue_duplicate_completion_drops);
  snprintf (root_nfqueue_stale_completion_drops,
            sizeof (root_nfqueue_stale_completion_drops), "%" PRIu64,
            status->root_nfqueue_stale_completion_drops);
  snprintf (vpn_tun_fd_attached, sizeof (vpn_tun_fd_attached), "%" PRIu64,
            status->vpn_tun_fd_attached);
  snprintf (vpn_direct_udp4_socket_attached,
            sizeof (vpn_direct_udp4_socket_attached), "%" PRIu64,
            status->vpn_direct_udp4_socket_attached);
  snprintf (vpn_direct_udp4_protect_succeeded,
            sizeof (vpn_direct_udp4_protect_succeeded), "%" PRIu64,
            status->vpn_direct_udp4_protect_succeeded);
  snprintf (vpn_direct_udp4_bind_succeeded,
            sizeof (vpn_direct_udp4_bind_succeeded), "%" PRIu64,
            status->vpn_direct_udp4_bind_succeeded);
  snprintf (vpn_tun_ingress_packets, sizeof (vpn_tun_ingress_packets),
            "%" PRIu64, status->vpn_tun_ingress_packets);
  snprintf (vpn_tun_udp4_tun_origin_packets,
            sizeof (vpn_tun_udp4_tun_origin_packets), "%" PRIu64,
            status->vpn_tun_udp4_tun_origin_packets);
  snprintf (vpn_flow_stack_admissions, sizeof (vpn_flow_stack_admissions),
            "%" PRIu64, status->vpn_flow_stack_admissions);
  snprintf (vpn_direct_udp4_send_succeeded,
            sizeof (vpn_direct_udp4_send_succeeded), "%" PRIu64,
            status->vpn_direct_udp4_send_succeeded);
  snprintf (vpn_direct_udp4_transport_failed,
            sizeof (vpn_direct_udp4_transport_failed), "%" PRIu64,
            status->vpn_direct_udp4_transport_failed);
  snprintf (vpn_flow_stack_return_packets,
            sizeof (vpn_flow_stack_return_packets), "%" PRIu64,
            status->vpn_flow_stack_return_packets);
  snprintf (vpn_flow_stack_return_provenance_packets,
            sizeof (vpn_flow_stack_return_provenance_packets), "%" PRIu64,
            status->vpn_flow_stack_return_provenance_packets);
  snprintf (vpn_tun_write_completions, sizeof (vpn_tun_write_completions),
            "%" PRIu64, status->vpn_tun_write_completions);
  snprintf (vpn_infrastructure_faults, sizeof (vpn_infrastructure_faults),
            "%" PRIu64, status->vpn_infrastructure_faults);
  snprintf (vpn_duplicate_or_stale_drops,
            sizeof (vpn_duplicate_or_stale_drops), "%" PRIu64,
            status->vpn_duplicate_or_stale_drops);
  snprintf (product_graph_worker_count, sizeof (product_graph_worker_count),
            "%" PRIu32, status->product_graph_worker_count);
  snprintf (product_graph_hash_seed, sizeof (product_graph_hash_seed),
            "%" PRIu64, status->product_graph_hash_seed);
  snprintf (product_graph_handoff_credits,
            sizeof (product_graph_handoff_credits), "%" PRIu32,
            status->product_graph_handoff_credits);
  snprintf (product_graph_vpp_worker_count,
            sizeof (product_graph_vpp_worker_count), "%" PRIu32,
            status->product_graph_vpp_worker_count);
  snprintf (product_graph_vpp_main_core,
            sizeof (product_graph_vpp_main_core), "%" PRIu32,
            status->product_graph_vpp_main_core);
  snprintf (product_graph_vpp_worker0_thread_index,
            sizeof (product_graph_vpp_worker0_thread_index), "%" PRIu32,
            status->product_graph_vpp_worker0_thread_index);
  snprintf (product_graph_vpp_worker0_core,
            sizeof (product_graph_vpp_worker0_core), "%" PRIu32,
            status->product_graph_vpp_worker0_core);
  snprintf (product_graph_vpp_worker1_thread_index,
            sizeof (product_graph_vpp_worker1_thread_index), "%" PRIu32,
            status->product_graph_vpp_worker1_thread_index);
  snprintf (product_graph_vpp_worker1_core,
            sizeof (product_graph_vpp_worker1_core), "%" PRIu32,
            status->product_graph_vpp_worker1_core);
  snprintf (product_graph_enabled, sizeof (product_graph_enabled), "%" PRIu32,
            status->product_graph_enabled);
  snprintf (product_graph_accepting, sizeof (product_graph_accepting),
            "%" PRIu32, status->product_graph_accepting);
  snprintf (product_graph_worker_layout_ready,
            sizeof (product_graph_worker_layout_ready), "%" PRIu32,
            status->product_graph_worker_layout_ready);
  snprintf (product_graph_obligation_debt,
            sizeof (product_graph_obligation_debt), "%" PRIu64,
            status->product_graph_obligation_debt);
  snprintf (product_graph_buffer_debt, sizeof (product_graph_buffer_debt),
            "%" PRIu64, status->product_graph_buffer_debt);
  snprintf (product_graph_handoff_debt, sizeof (product_graph_handoff_debt),
            "%" PRIu64, status->product_graph_handoff_debt);
  snprintf (policy_requested_revision, sizeof (policy_requested_revision),
            "%" PRIu64, status->policy_requested_revision);
  snprintf (policy_active_revision, sizeof (policy_active_revision),
            "%" PRIu64, status->policy_active_revision);
  snprintf (policy_generation, sizeof (policy_generation),
            "%" PRIu64, status->policy_generation);
  snprintf (policy_snapshot_hash, sizeof (policy_snapshot_hash),
            "%" PRIu64, status->policy_snapshot_hash);
  snprintf (policy_worker0_revision, sizeof (policy_worker0_revision),
            "%" PRIu64, status->policy_worker0_revision);
  snprintf (policy_worker1_revision, sizeof (policy_worker1_revision),
            "%" PRIu64, status->policy_worker1_revision);
  snprintf (policy_snapshot_empty, sizeof (policy_snapshot_empty),
            "%" PRIu32, status->policy_snapshot_empty);
  snprintf (policy_default_pass, sizeof (policy_default_pass),
            "%" PRIu32, status->policy_default_pass);
  snprintf (policy_gate_claim_count, sizeof (policy_gate_claim_count),
            "%" PRIu32, status->policy_gate_claim_count);
  snprintf (policy_l4_rule_count, sizeof (policy_l4_rule_count),
            "%" PRIu32, status->policy_l4_rule_count);
  snprintf (policy_last_apply_status_code,
            sizeof (policy_last_apply_status_code), "%" PRIu32,
            status->policy_last_apply_status_code);
  snprintf (policy_mixed_revision, sizeof (policy_mixed_revision),
            "%" PRIu32, status->policy_mixed_revision);
  snprintf (policy_artifact_match, sizeof (policy_artifact_match),
            "%" PRIu32, status->policy_artifact_match);
  snprintf (policy_generation_match, sizeof (policy_generation_match),
            "%" PRIu32, status->policy_generation_match);
  snprintf (policy_gate_subject_uid, sizeof (policy_gate_subject_uid),
            "%" PRIu32, status->policy_gate_subject_uid);
  snprintf (policy_gate_network_context,
            sizeof (policy_gate_network_context), "%" PRIu32,
            status->policy_gate_network_context);
  snprintf (policy_gate_blocked, sizeof (policy_gate_blocked), "%" PRIu32,
            status->policy_gate_blocked);
  snprintf (policy_gate_reason_id, sizeof (policy_gate_reason_id),
            "%" PRIu32, status->policy_gate_reason_id);
  snprintf (policy_gate_rule_id, sizeof (policy_gate_rule_id), "%" PRIu64,
            status->policy_gate_rule_id);
  snprintf (policy_drop_records, sizeof (policy_drop_records), "%" PRIu64,
            status->policy_drop_records);
  snprintf (policy_last_drop_revision, sizeof (policy_last_drop_revision),
            "%" PRIu64, status->policy_last_drop_revision);
  snprintf (policy_last_drop_rule_id, sizeof (policy_last_drop_rule_id),
            "%" PRIu64, status->policy_last_drop_rule_id);
  snprintf (policy_last_drop_completion_attempts,
            sizeof (policy_last_drop_completion_attempts), "%" PRIu64,
            status->policy_last_drop_completion_attempts);
  snprintf (policy_last_drop_uid, sizeof (policy_last_drop_uid), "%" PRIu32,
            status->policy_last_drop_uid);
  snprintf (policy_last_drop_network_context,
            sizeof (policy_last_drop_network_context), "%" PRIu32,
            status->policy_last_drop_network_context);
  snprintf (policy_last_drop_reason_id, sizeof (policy_last_drop_reason_id),
            "%" PRIu32, status->policy_last_drop_reason_id);
  snprintf (policy_last_drop_verdict, sizeof (policy_last_drop_verdict),
            "%" PRIu32, status->policy_last_drop_verdict);
  snprintf (policy_last_drop_winner, sizeof (policy_last_drop_winner),
            "%" PRIu32, status->policy_last_drop_winner);
  snprintf (policy_last_drop_uid_known,
            sizeof (policy_last_drop_uid_known), "%" PRIu32,
            status->policy_last_drop_uid_known);
  snprintf (policy_last_drop_device_direction,
            sizeof (policy_last_drop_device_direction), "%" PRIu32,
            status->policy_last_drop_device_direction);
  snprintf (policy_l4_active_revision, sizeof (policy_l4_active_revision),
            "%" PRIu64, status->policy_l4_active_revision);
  snprintf (policy_l4_rule_id, sizeof (policy_l4_rule_id), "%" PRIu64,
            status->policy_l4_rule_id);
  snprintf (policy_l4_match_records, sizeof (policy_l4_match_records),
            "%" PRIu64, status->policy_l4_match_records);
  snprintf (policy_l4_no_match_records, sizeof (policy_l4_no_match_records),
            "%" PRIu64, status->policy_l4_no_match_records);
  snprintf (policy_l4_last_match_revision,
            sizeof (policy_l4_last_match_revision), "%" PRIu64,
            status->policy_l4_last_match_revision);
  snprintf (policy_l4_last_match_rule_id,
            sizeof (policy_l4_last_match_rule_id), "%" PRIu64,
            status->policy_l4_last_match_rule_id);
  snprintf (policy_l4_subject_uid, sizeof (policy_l4_subject_uid), "%" PRIu32,
            status->policy_l4_subject_uid);
  snprintf (policy_l4_network_context, sizeof (policy_l4_network_context),
            "%" PRIu32, status->policy_l4_network_context);
  snprintf (policy_l4_ip_family, sizeof (policy_l4_ip_family), "%" PRIu32,
            status->policy_l4_ip_family);
  snprintf (policy_l4_ip_protocol, sizeof (policy_l4_ip_protocol), "%" PRIu32,
            status->policy_l4_ip_protocol);
  snprintf (policy_l4_direction, sizeof (policy_l4_direction), "%" PRIu32,
            status->policy_l4_direction);
  snprintf (policy_l4_action, sizeof (policy_l4_action), "%" PRIu32,
            status->policy_l4_action);
  snprintf (policy_l4_priority, sizeof (policy_l4_priority), "%" PRIu32,
            status->policy_l4_priority);
  snprintf (policy_l4_order, sizeof (policy_l4_order), "%" PRIu32,
            status->policy_l4_order);
  snprintf (policy_l4_reason_id, sizeof (policy_l4_reason_id), "%" PRIu32,
            status->policy_l4_reason_id);
  snprintf (policy_l4_last_match_uid, sizeof (policy_l4_last_match_uid),
            "%" PRIu32, status->policy_l4_last_match_uid);
  snprintf (policy_l4_last_match_network_context,
            sizeof (policy_l4_last_match_network_context), "%" PRIu32,
            status->policy_l4_last_match_network_context);
  snprintf (policy_l4_last_match_reason_id,
            sizeof (policy_l4_last_match_reason_id), "%" PRIu32,
            status->policy_l4_last_match_reason_id);
  snprintf (policy_l4_last_match_verdict,
            sizeof (policy_l4_last_match_verdict), "%" PRIu32,
            status->policy_l4_last_match_verdict);
  snprintf (policy_l4_last_match_winner,
            sizeof (policy_l4_last_match_winner), "%" PRIu32,
            status->policy_l4_last_match_winner);
  snprintf (policy_l4_last_match_uid_known,
            sizeof (policy_l4_last_match_uid_known), "%" PRIu32,
            status->policy_l4_last_match_uid_known);
  snprintf (policy_l4_last_match_device_direction,
            sizeof (policy_l4_last_match_device_direction), "%" PRIu32,
            status->policy_l4_last_match_device_direction);
  snprintf (policy_l4_last_match_action, sizeof (policy_l4_last_match_action),
            "%" PRIu32, status->policy_l4_last_match_action);
  snprintf (policy_l4_last_evaluation_result,
            sizeof (policy_l4_last_evaluation_result), "%" PRIu32,
            status->policy_l4_last_evaluation_result);
  snprintf (policy_l4_last_evaluation_verdict,
            sizeof (policy_l4_last_evaluation_verdict), "%" PRIu32,
            status->policy_l4_last_evaluation_verdict);
  snprintf (policy_l4_last_evaluation_device_direction,
            sizeof (policy_l4_last_evaluation_device_direction), "%" PRIu32,
            status->policy_l4_last_evaluation_device_direction);
  snprintf (policy_l4_view_active, sizeof (policy_l4_view_active), "%" PRIu32,
            status->policy_l4_view_active);
  snprintf (policy_l4_view_rule_count, sizeof (policy_l4_view_rule_count),
            "%" PRIu32, status->policy_l4_view_rule_count);
  snprintf (policy_l4_view_max_probes, sizeof (policy_l4_view_max_probes),
            "%" PRIu32, status->policy_l4_view_max_probes);
  snprintf (policy_l4_view_last_match_winner_rank,
            sizeof (policy_l4_view_last_match_winner_rank), "%" PRIu32,
            status->policy_l4_view_last_match_winner_rank);
  snprintf (policy_l4_view_last_match_probes,
            sizeof (policy_l4_view_last_match_probes), "%" PRIu32,
            status->policy_l4_view_last_match_probes);
  snprintf (policy_l4_view_last_match_candidate_count,
            sizeof (policy_l4_view_last_match_candidate_count), "%" PRIu32,
            status->policy_l4_view_last_match_candidate_count);
  snprintf (policy_l4_view_last_no_match_reason,
            sizeof (policy_l4_view_last_no_match_reason), "%" PRIu32,
            status->policy_l4_view_last_no_match_reason);
  snprintf (policy_l4_typed_match_policy_key,
            sizeof (policy_l4_typed_match_policy_key), "%" PRIu64,
            status->policy_l4_typed_match_policy_key);
  snprintf (policy_l4_typed_match_probe_key,
            sizeof (policy_l4_typed_match_probe_key), "%" PRIu64,
            status->policy_l4_typed_match_probe_key);
  snprintf (policy_l4_last_evaluation_probe_key,
            sizeof (policy_l4_last_evaluation_probe_key), "%" PRIu64,
            status->policy_l4_last_evaluation_probe_key);
  core_ready[0] = status->core_ready ? '1' : '0';
  core_ready[1] = '\0';
  adapter_available[0] = status->adapter_available ? '1' : '0';
  adapter_available[1] = '\0';
  protection_running[0] = status->protection_running ? '1' : '0';
  protection_running[1] = '\0';
  plugin_loaded[0] = status->plugin_loaded ? '1' : '0';
  plugin_loaded[1] = '\0';
  vapi_handle_live[0] = status->vapi_handle_live ? '1' : '0';
  vapi_handle_live[1] = '\0';
  generation_live[0] = status->generation_live ? '1' : '0';
  generation_live[1] = '\0';

  fields[index++] = code;
  fields[index++] = generation;
  fields[index++] = core_ready;
  fields[index++] = adapter_available;
  fields[index++] = protection_running;
  fields[index++] = plugin_loaded;
  fields[index++] = vapi_handle_live;
  fields[index++] = generation_live;
  fields[index++] = status->artifact_id;
  fields[index++] = status->api_identity;
  fields[index++] = status->vpp_revision;
  fields[index++] = status->error_detail;
  fields[index++] = abi_version;
  fields[index++] = api_version;
  fields[index++] = root_nfqueue_queue_id;
  fields[index++] = root_nfqueue_queue_last;
  fields[index++] = root_nfqueue_lane_count;
  fields[index++] = root_nfqueue_ready_lane_mask;
  fields[index++] = root_nfqueue_generation;
  fields[index++] = root_nfqueue_verdict_attempts;
  fields[index++] = root_nfqueue_internal_settlements;
  fields[index++] = root_nfqueue_buffer_returns;
  fields[index++] = root_nfqueue_origin_local_completions;
  fields[index++] = root_nfqueue_origin_remote_completions;
  fields[index++] = root_nfqueue_lane0_verdict_attempts;
  fields[index++] = root_nfqueue_lane1_verdict_attempts;
  fields[index++] = root_nfqueue_input_packets;
  fields[index++] = root_nfqueue_output_packets;
  fields[index++] = root_nfqueue_ipv4_packets;
  fields[index++] = root_nfqueue_ipv6_packets;
  fields[index++] = root_nfqueue_tcp_packets;
  fields[index++] = root_nfqueue_udp_packets;
  fields[index++] = root_nfqueue_uid_known_packets;
  fields[index++] = root_nfqueue_uid_unknown_packets;
  fields[index++] = root_nfqueue_last_ip_family;
  fields[index++] = root_nfqueue_last_protocol;
  fields[index++] = root_nfqueue_last_hook;
  fields[index++] = root_nfqueue_last_uid_known;
  fields[index++] = root_nfqueue_last_uid;
  fields[index++] = root_nfqueue_last_queue_id;
  fields[index++] = root_nfqueue_last_packet_id;
  fields[index++] = root_nfqueue_verdict_succeeded;
  fields[index++] = root_nfqueue_verdict_failed_definite;
  fields[index++] = root_nfqueue_verdict_outcome_unknown;
  fields[index++] = root_nfqueue_ingress_identity_missing;
  fields[index++] = root_nfqueue_graph_submit_fail_opens;
  fields[index++] = root_nfqueue_non_owner_bypasses;
  fields[index++] = root_nfqueue_duplicate_completion_drops;
  fields[index++] = root_nfqueue_stale_completion_drops;
  fields[index++] = vpn_tun_fd_attached;
  fields[index++] = vpn_direct_udp4_socket_attached;
  fields[index++] = vpn_direct_udp4_protect_succeeded;
  fields[index++] = vpn_direct_udp4_bind_succeeded;
  fields[index++] = vpn_tun_ingress_packets;
  fields[index++] = vpn_tun_udp4_tun_origin_packets;
  fields[index++] = vpn_flow_stack_admissions;
  fields[index++] = vpn_direct_udp4_send_succeeded;
  fields[index++] = vpn_direct_udp4_transport_failed;
  fields[index++] = vpn_flow_stack_return_packets;
  fields[index++] = vpn_flow_stack_return_provenance_packets;
  fields[index++] = vpn_tun_write_completions;
  fields[index++] = vpn_infrastructure_faults;
  fields[index++] = vpn_duplicate_or_stale_drops;
  fields[index++] = product_graph_worker_count;
  fields[index++] = product_graph_hash_seed;
  fields[index++] = product_graph_handoff_credits;
  fields[index++] = product_graph_vpp_worker_count;
  fields[index++] = product_graph_vpp_main_core;
  fields[index++] = product_graph_vpp_worker0_thread_index;
  fields[index++] = product_graph_vpp_worker0_core;
  fields[index++] = product_graph_vpp_worker1_thread_index;
  fields[index++] = product_graph_vpp_worker1_core;
  fields[index++] = product_graph_enabled;
  fields[index++] = product_graph_accepting;
  fields[index++] = product_graph_worker_layout_ready;
  fields[index++] = product_graph_obligation_debt;
  fields[index++] = product_graph_buffer_debt;
  fields[index++] = product_graph_handoff_debt;
  fields[index++] = policy_requested_revision;
  fields[index++] = policy_active_revision;
  fields[index++] = policy_generation;
  fields[index++] = policy_snapshot_hash;
  fields[index++] = policy_worker0_revision;
  fields[index++] = policy_worker1_revision;
  fields[index++] = policy_snapshot_empty;
  fields[index++] = policy_default_pass;
  fields[index++] = policy_gate_claim_count;
  fields[index++] = policy_l4_rule_count;
  fields[index++] = policy_last_apply_status_code;
  fields[index++] = policy_mixed_revision;
  fields[index++] = policy_artifact_match;
  fields[index++] = policy_generation_match;
  fields[index++] = status->policy_snapshot_identity;
  fields[index++] = policy_gate_subject_uid;
  fields[index++] = policy_gate_network_context;
  fields[index++] = policy_gate_blocked;
  fields[index++] = policy_gate_reason_id;
  fields[index++] = policy_gate_rule_id;
  fields[index++] = policy_drop_records;
  fields[index++] = policy_last_drop_revision;
  fields[index++] = policy_last_drop_rule_id;
  fields[index++] = policy_last_drop_completion_attempts;
  fields[index++] = policy_last_drop_uid;
  fields[index++] = policy_last_drop_network_context;
  fields[index++] = policy_last_drop_reason_id;
  fields[index++] = policy_last_drop_verdict;
  fields[index++] = policy_last_drop_winner;
  fields[index++] = policy_last_drop_uid_known;
  fields[index++] = policy_last_drop_device_direction;
  fields[index++] = policy_l4_active_revision;
  fields[index++] = policy_l4_rule_id;
  fields[index++] = policy_l4_match_records;
  fields[index++] = policy_l4_no_match_records;
  fields[index++] = policy_l4_last_match_revision;
  fields[index++] = policy_l4_last_match_rule_id;
  fields[index++] = policy_l4_subject_uid;
  fields[index++] = policy_l4_network_context;
  fields[index++] = policy_l4_ip_family;
  fields[index++] = policy_l4_ip_protocol;
  fields[index++] = policy_l4_direction;
  fields[index++] = policy_l4_action;
  fields[index++] = policy_l4_priority;
  fields[index++] = policy_l4_order;
  fields[index++] = policy_l4_reason_id;
  fields[index++] = policy_l4_last_match_uid;
  fields[index++] = policy_l4_last_match_network_context;
  fields[index++] = policy_l4_last_match_reason_id;
  fields[index++] = policy_l4_last_match_verdict;
  fields[index++] = policy_l4_last_match_winner;
  fields[index++] = policy_l4_last_match_uid_known;
  fields[index++] = policy_l4_last_match_device_direction;
  fields[index++] = policy_l4_last_match_action;
  fields[index++] = policy_l4_last_evaluation_result;
  fields[index++] = policy_l4_last_evaluation_verdict;
  fields[index++] = policy_l4_last_evaluation_device_direction;
  fields[index++] = policy_l4_view_active;
  fields[index++] = policy_l4_view_rule_count;
  fields[index++] = policy_l4_view_max_probes;
  fields[index++] = policy_l4_view_last_match_winner_rank;
  fields[index++] = policy_l4_view_last_match_probes;
  fields[index++] = policy_l4_view_last_match_candidate_count;
  fields[index++] = policy_l4_view_last_no_match_reason;
  fields[index++] = policy_l4_typed_match_policy_key;
  fields[index++] = policy_l4_typed_match_probe_key;
  fields[index++] = policy_l4_last_evaluation_probe_key;

  for (int value_index = 0; value_index < index; ++value_index)
    {
      jstring value = (*env)->NewStringUTF (env, fields[value_index]);
      if (value == NULL)
        return NULL;
      (*env)->SetObjectArrayElement (env, values, value_index, value);
      (*env)->DeleteLocalRef (env, value);
    }
  return values;
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeConnect (
    JNIEnv *env, jclass clazz, jstring api_socket, jlong generation)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *handle = NULL;
  const char *socket = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (api_socket != NULL && generation > 0)
    {
      socket = (*env)->GetStringUTFChars (env, api_socket, NULL);
      if (socket == NULL)
        return NULL;
      jsize socket_length = (*env)->GetStringUTFLength (env, api_socket);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) socket,
        .length = (uint32_t) socket_length,
      };
      code = sakamoto_product_core_connect (bytes, (uint64_t) generation,
                                            &handle, &status);
      (*env)->ReleaseStringUTFChars (env, api_socket, socket);
    }
  /* Keep the function return and status tag consistent at the JNI seam. */
  if (status.status_code != code)
    status.status_code = code;
  jobjectArray values = status_values (
      env, &status, (jlong) (intptr_t) handle, 1);
  if (values == NULL && handle != NULL)
    (void) sakamoto_product_core_destroy (handle);
  return values;
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeQuery (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  uint32_t code = sakamoto_product_core_query (
      native_handle, generation > 0 ? (uint64_t) generation : 0U, &status);
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyEmptyPolicy (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && generation > 0 && native_handle != NULL)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      jsize path_length = (*env)->GetStringUTFLength (env, files_dir);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) path_length,
      };
      code = sakamoto_product_core_apply_empty_policy (
          native_handle, (uint64_t) generation, bytes, &status);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyEmptyPolicyRevision (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir,
    jlong revision)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && generation > 0 && native_handle != NULL
      && revision > 0)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      jsize path_length = (*env)->GetStringUTFLength (env, files_dir);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) path_length,
      };
      code = sakamoto_product_core_apply_empty_policy_revision (
          native_handle, (uint64_t) generation, bytes, (uint64_t) revision,
          &status);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyNetworkGatePolicy (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir,
    jint subject_uid, jint network_context, jboolean blocked, jlong rule_id,
    jint reason_id)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && generation > 0 && native_handle != NULL
      && subject_uid >= 0 && network_context > 0 && rule_id > 0
      && reason_id > 0)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      jsize path_length = (*env)->GetStringUTFLength (env, files_dir);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) path_length,
      };
      code = sakamoto_product_core_apply_network_gate_policy (
          native_handle, (uint64_t) generation, bytes, (uint32_t) subject_uid,
          (uint32_t) network_context, blocked ? 1U : 0U,
          (uint64_t) rule_id, (uint32_t) reason_id, &status);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyNetworkGatePolicyRevision (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir,
    jlong revision, jint subject_uid, jint network_context, jboolean blocked,
    jlong rule_id, jint reason_id)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && generation > 0 && native_handle != NULL
      && revision > 0 && subject_uid >= 0 && network_context > 0
      && rule_id > 0 && reason_id > 0)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      jsize path_length = (*env)->GetStringUTFLength (env, files_dir);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) path_length,
      };
      code = sakamoto_product_core_apply_network_gate_policy_revision (
          native_handle, (uint64_t) generation, bytes, (uint64_t) revision,
          (uint32_t) subject_uid, (uint32_t) network_context,
          blocked ? 1U : 0U, (uint64_t) rule_id, (uint32_t) reason_id,
          &status);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyL4Policy (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir,
    jint subject_uid, jint network_context, jint ip_family, jint ip_protocol,
    jint direction, jint action, jstring source_cidr, jstring destination_cidr,
    jint source_port_first, jint source_port_last,
    jint destination_port_first, jint destination_port_last, jint priority,
    jint order, jlong rule_id, jint reason_id)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  const char *source = NULL;
  const char *destination = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && source_cidr != NULL && destination_cidr != NULL
      && generation > 0 && native_handle != NULL && subject_uid >= 0
      && network_context > 0 && ip_family == 4 && ip_protocol == 6
      && (direction == 1 || direction == 3) && (action == 1 || action == 2)
      && source_port_first >= 0 && source_port_last >= source_port_first
      && source_port_last <= UINT16_MAX && destination_port_first >= 0
      && destination_port_last >= destination_port_first
      && destination_port_last <= UINT16_MAX && priority >= 0 && order >= 0
      && rule_id > 0
      && reason_id > 0)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      source = (*env)->GetStringUTFChars (env, source_cidr, NULL);
      if (source == NULL)
        {
          (*env)->ReleaseStringUTFChars (env, files_dir, path);
          return NULL;
        }
      destination = (*env)->GetStringUTFChars (env, destination_cidr, NULL);
      if (destination == NULL)
        {
          (*env)->ReleaseStringUTFChars (env, source_cidr, source);
          (*env)->ReleaseStringUTFChars (env, files_dir, path);
          return NULL;
        }
      sakamoto_product_bytes_t files_dir_bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) (*env)->GetStringUTFLength (env, files_dir),
      };
      sakamoto_product_bytes_t source_bytes = {
        .data = (const uint8_t *) source,
        .length = (uint32_t) (*env)->GetStringUTFLength (env, source_cidr),
      };
      sakamoto_product_bytes_t destination_bytes = {
        .data = (const uint8_t *) destination,
        .length =
          (uint32_t) (*env)->GetStringUTFLength (env, destination_cidr),
      };
      code = sakamoto_product_core_apply_l4_policy (
        native_handle, (uint64_t) generation, files_dir_bytes,
        (uint32_t) subject_uid, (uint32_t) network_context,
        (uint32_t) ip_family, (uint32_t) ip_protocol, (uint32_t) direction,
        (uint32_t) action, source_bytes, destination_bytes,
        (uint32_t) source_port_first, (uint32_t) source_port_last,
        (uint32_t) destination_port_first, (uint32_t) destination_port_last,
        (uint32_t) priority, (uint32_t) order, (uint64_t) rule_id,
        (uint32_t) reason_id, &status);
      (*env)->ReleaseStringUTFChars (env, destination_cidr, destination);
      (*env)->ReleaseStringUTFChars (env, source_cidr, source);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyL4PolicyRevision (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir,
    jlong revision, jint subject_uid, jint network_context, jint ip_family,
    jint ip_protocol, jint direction, jint action, jstring source_cidr,
    jstring destination_cidr, jint source_port_first, jint source_port_last,
    jint destination_port_first, jint destination_port_last, jint priority,
    jint order, jlong rule_id, jint reason_id)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  const char *source = NULL;
  const char *destination = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && source_cidr != NULL && destination_cidr != NULL
      && generation > 0 && native_handle != NULL && revision > 0
      && subject_uid >= 0 && network_context > 0 && ip_family == 4
      && ip_protocol == 6 && (direction == 1 || direction == 3)
      && (action == 1 || action == 2) && source_port_first >= 0
      && source_port_last >= source_port_first
      && source_port_last <= UINT16_MAX && destination_port_first >= 0
      && destination_port_last >= destination_port_first
      && destination_port_last <= UINT16_MAX && priority >= 0 && order >= 0
      && rule_id > 0
      && reason_id > 0)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      source = (*env)->GetStringUTFChars (env, source_cidr, NULL);
      if (source == NULL)
        {
          (*env)->ReleaseStringUTFChars (env, files_dir, path);
          return NULL;
        }
      destination = (*env)->GetStringUTFChars (env, destination_cidr, NULL);
      if (destination == NULL)
        {
          (*env)->ReleaseStringUTFChars (env, source_cidr, source);
          (*env)->ReleaseStringUTFChars (env, files_dir, path);
          return NULL;
        }
      sakamoto_product_bytes_t files_dir_bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) (*env)->GetStringUTFLength (env, files_dir),
      };
      sakamoto_product_bytes_t source_bytes = {
        .data = (const uint8_t *) source,
        .length = (uint32_t) (*env)->GetStringUTFLength (env, source_cidr),
      };
      sakamoto_product_bytes_t destination_bytes = {
        .data = (const uint8_t *) destination,
        .length =
          (uint32_t) (*env)->GetStringUTFLength (env, destination_cidr),
      };
      code = sakamoto_product_core_apply_l4_policy_revision (
        native_handle, (uint64_t) generation, files_dir_bytes,
        (uint64_t) revision, (uint32_t) subject_uid,
        (uint32_t) network_context, (uint32_t) ip_family,
        (uint32_t) ip_protocol, (uint32_t) direction, (uint32_t) action,
        source_bytes, destination_bytes, (uint32_t) source_port_first,
        (uint32_t) source_port_last, (uint32_t) destination_port_first,
        (uint32_t) destination_port_last, (uint32_t) priority,
        (uint32_t) order, (uint64_t) rule_id, (uint32_t) reason_id,
        &status);
      (*env)->ReleaseStringUTFChars (env, destination_cidr, destination);
      (*env)->ReleaseStringUTFChars (env, source_cidr, source);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeStopRoot (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation)
{
  (void) env;
  (void) clazz;
  if (!handle || generation <= 0) return -(jint) SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  uint32_t stopped = 0;
  uint32_t code = sakamoto_product_core_stop_root (
    (sakamoto_product_core_handle_t *) (intptr_t) handle,
    (uint64_t) generation, &stopped);
  return code == SAKAMOTO_PRODUCT_OK ? (jint) stopped : -(jint) code;
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativePublishNetwork (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation,
    jlong revision, jlong event_elapsed_ns, jintArray pairs)
{
  (void) clazz;
  if (!handle || generation <= 0 || revision <= 0 || event_elapsed_ns < 0 || !pairs)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  jsize size = (*env)->GetArrayLength (env, pairs);
  if (size < 0 || size > 64 || size % 2)
    return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  jint values[64] = {0};
  (*env)->GetIntArrayRegion (env, pairs, 0, size, values);
  if ((*env)->ExceptionCheck (env)) return SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  sakamoto_product_network_snapshot_t snapshot = {0};
  snapshot.revision = (uint64_t) revision;
  snapshot.event_elapsed_ns = (uint64_t) event_elapsed_ns;
  snapshot.count = (uint32_t) size / 2;
  for (uint32_t i = 0; i < snapshot.count; ++i)
    {
      snapshot.entries[i].linux_ifindex = (uint32_t) values[i * 2];
      snapshot.entries[i].context = (uint32_t) values[i * 2 + 1];
    }
  return (jint) sakamoto_product_core_publish_network (
    (sakamoto_product_core_handle_t *) (intptr_t) handle,
    (uint64_t) generation, &snapshot);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyPolicyBundle (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir,
    jbyteArray bundle_payload)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && bundle_payload != NULL && generation > 0
      && native_handle != NULL)
    {
      jsize payload_length = (*env)->GetArrayLength (env, bundle_payload);
      if (payload_length == (jsize) sizeof (sakamoto_product_policy_bundle_t))
        {
          path = (*env)->GetStringUTFChars (env, files_dir, NULL);
          if (path == NULL)
            return NULL;
          sakamoto_product_policy_bundle_t bundle;
          memset (&bundle, 0, sizeof (bundle));
          (*env)->GetByteArrayRegion (env, bundle_payload, 0, payload_length,
                                      (jbyte *) &bundle);
          if ((*env)->ExceptionCheck (env))
            {
              (*env)->ReleaseStringUTFChars (env, files_dir, path);
              return NULL;
            }
          sakamoto_product_bytes_t files_dir_bytes = {
            .data = (const uint8_t *) path,
            .length = (uint32_t) (*env)->GetStringUTFLength (env, files_dir),
          };
          code = sakamoto_product_core_apply_policy_bundle (
              native_handle, (uint64_t) generation, files_dir_bytes, &bundle,
              &status);
          (*env)->ReleaseStringUTFChars (env, files_dir, path);
        }
      else
        {
          strncpy (status.error_detail,
                   "Product policy bundle payload has an invalid fixed size",
                   sizeof (status.error_detail) - 1U);
        }
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeSetPolicyMutationFault (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jint fault_mode)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (generation > 0 && native_handle != NULL)
    code = sakamoto_product_core_set_policy_mutation_fault (
        native_handle, (uint64_t) generation, (uint32_t) fault_mode, &status);
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeReconcilePolicy (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && generation > 0 && native_handle != NULL)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      jsize path_length = (*env)->GetStringUTFLength (env, files_dir);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) path_length,
      };
      code = sakamoto_product_core_reconcile_policy (
          native_handle, (uint64_t) generation, bytes, &status);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jobjectArray JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeReconcileEmptyPolicy (
    JNIEnv *env, jclass clazz, jlong handle, jlong generation, jstring files_dir)
{
  (void) clazz;
  sakamoto_product_status_t status;
  status_reset (&status, generation > 0 ? (uint64_t) generation : 0U);
  sakamoto_product_core_handle_t *native_handle =
      (sakamoto_product_core_handle_t *) (intptr_t) handle;
  const char *path = NULL;
  uint32_t code = SAKAMOTO_PRODUCT_INVALID_ARGUMENT;
  if (files_dir != NULL && generation > 0 && native_handle != NULL)
    {
      path = (*env)->GetStringUTFChars (env, files_dir, NULL);
      if (path == NULL)
        return NULL;
      jsize path_length = (*env)->GetStringUTFLength (env, files_dir);
      sakamoto_product_bytes_t bytes = {
        .data = (const uint8_t *) path,
        .length = (uint32_t) path_length,
      };
      code = sakamoto_product_core_reconcile_empty_policy (
          native_handle, (uint64_t) generation, bytes, &status);
      (*env)->ReleaseStringUTFChars (env, files_dir, path);
    }
  if (status.status_code != code)
    status.status_code = code;
  return status_values (env, &status, 0, 0);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeDisconnect (
    JNIEnv *env, jclass clazz, jlong handle)
{
  (void) env;
  (void) clazz;
  return (jint) sakamoto_product_core_disconnect (
      (sakamoto_product_core_handle_t *) (intptr_t) handle);
}

JNIEXPORT jint JNICALL
Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeDestroy (
    JNIEnv *env, jclass clazz, jlong handle)
{
  (void) env;
  (void) clazz;
  return (jint) sakamoto_product_core_destroy (
      (sakamoto_product_core_handle_t *) (intptr_t) handle);
}
