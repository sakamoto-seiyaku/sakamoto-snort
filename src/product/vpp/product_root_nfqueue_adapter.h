/* SPDX-License-Identifier: Apache-2.0 */

#ifndef SAKAMOTO_PRODUCT_ROOT_NFQUEUE_ADAPTER_H
#define SAKAMOTO_PRODUCT_ROOT_NFQUEUE_ADAPTER_H

#include <stdint.h>

#include <vlib/vlib.h>

int product_root_nfqueue_adapter_start (vlib_main_t *vm, u64 generation);
void product_root_nfqueue_adapter_stop (vlib_main_t *vm);
int product_root_nfqueue_adapter_available (void);
uint32_t product_root_nfqueue_adapter_queue_id (void);
uint32_t product_root_nfqueue_adapter_queue_last (void);
uint32_t product_root_nfqueue_adapter_lane_count (void);
uint32_t product_root_nfqueue_adapter_ready_lane_mask (void);
uint64_t product_root_nfqueue_adapter_generation (void);
uint64_t product_root_nfqueue_adapter_verdict_attempts (void);
uint64_t product_root_nfqueue_adapter_verdict_succeeded (void);
uint64_t product_root_nfqueue_adapter_verdict_failed_definite (void);
uint64_t product_root_nfqueue_adapter_verdict_outcome_unknown (void);
uint64_t product_root_nfqueue_adapter_ingress_identity_missing (void);
uint64_t product_root_nfqueue_adapter_graph_submit_fail_opens (void);
uint64_t product_root_nfqueue_adapter_non_owner_bypasses (void);
uint64_t product_root_nfqueue_adapter_duplicate_completion_drops (void);
uint64_t product_root_nfqueue_adapter_stale_completion_drops (void);
uint64_t product_root_nfqueue_adapter_internal_settlements (void);
uint64_t product_root_nfqueue_adapter_buffer_returns (void);
uint64_t product_root_nfqueue_adapter_origin_local_completions (void);
uint64_t product_root_nfqueue_adapter_origin_remote_completions (void);
uint64_t product_root_nfqueue_adapter_lane_verdict_attempts (
  uint32_t lane_index);
uint64_t product_root_nfqueue_adapter_input_packets (void);
uint64_t product_root_nfqueue_adapter_output_packets (void);
uint64_t product_root_nfqueue_adapter_ipv4_packets (void);
uint64_t product_root_nfqueue_adapter_ipv6_packets (void);
uint64_t product_root_nfqueue_adapter_tcp_packets (void);
uint64_t product_root_nfqueue_adapter_udp_packets (void);
uint64_t product_root_nfqueue_adapter_uid_known_packets (void);
uint64_t product_root_nfqueue_adapter_uid_unknown_packets (void);
uint32_t product_root_nfqueue_adapter_last_ip_family (void);
uint32_t product_root_nfqueue_adapter_last_protocol (void);
uint32_t product_root_nfqueue_adapter_last_hook (void);
uint32_t product_root_nfqueue_adapter_last_uid_known (void);
uint32_t product_root_nfqueue_adapter_last_uid (void);
uint32_t product_root_nfqueue_adapter_last_queue_id (void);
uint32_t product_root_nfqueue_adapter_last_packet_id (void);

#endif
