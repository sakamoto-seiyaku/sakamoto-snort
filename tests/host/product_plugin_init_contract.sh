#!/usr/bin/env bash
set -euo pipefail

# Compile the production plugin translation unit against a deliberately tiny
# VPP-shaped seam. The fake generated API controls setup_message_id_table(),
# while the test calls the real VLIB init function registered by the plugin.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
plugin_source="$repo_root/src/product/vpp/product_core_plugin.c"
work_dir="$(mktemp -d /tmp/sakamoto-product-plugin-init.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT
mkdir -p "$work_dir/vlib" "$work_dir/vlibapi" "$work_dir/vlibmemory" \
  "$work_dir/vnet/plugin" "$work_dir/vnet" "$work_dir/vpp/app"

cat >"$work_dir/vlib/vlib.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIB_H
#define SAKAMOTO_TEST_VLIB_H
#include <stdint.h>
#include <stdarg.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int32_t i32;
typedef struct { u32 thread_index; } vlib_main_t;
typedef double f64;
typedef unsigned long uword;
typedef struct { int unused; } vlib_node_runtime_t;
typedef struct { int unused; } vlib_frame_t;
typedef struct { uword (*function)(vlib_main_t *, vlib_node_runtime_t *, vlib_frame_t *); int type; const char *name; unsigned process_log2_n_stack_bytes; u32 index; } vlib_node_registration_t;
#define VLIB_NODE_TYPE_PROCESS 1
#define VLIB_REGISTER_NODE(name) vlib_node_registration_t name
#define VLIB_WORKER_INIT_FUNCTION(fn) clib_error_t *(*test_worker_init)(vlib_main_t *) = fn
#define clib_atomic_fetch_or(p, v) __atomic_fetch_or(p, v, __ATOMIC_RELAXED)
#define clib_atomic_load_acq_n(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
static inline f64 vlib_time_now(vlib_main_t *vm) { (void)vm; return 0; }
static inline void vlib_process_wait_for_event_or_clock(vlib_main_t *vm, f64 t) { (void)vm; (void)t; }
static inline void vlib_process_signal_event(vlib_main_t *vm, uword node, uword type, uword data) { (void)vm; (void)node; (void)type; (void)data; }
static inline void vlib_process_wait_for_event(vlib_main_t *vm) { (void)vm; }
static inline uword vlib_process_get_events(vlib_main_t *vm, uword **data) { (void)vm; (void)data; return 1; }
static inline void vlib_worker_thread_barrier_sync(vlib_main_t *vm) { (void)vm; }
static inline void vlib_worker_thread_barrier_release(vlib_main_t *vm) { (void)vm; }
typedef struct { int unused; } vlib_buffer_t;
typedef struct { const char *message; } clib_error_t;
typedef struct { int unused; } unformat_input_t;
typedef struct vlib_cli_command vlib_cli_command_t;
struct vlib_cli_command {
  const char *path;
  clib_error_t *(*function)(vlib_main_t *, unformat_input_t *, vlib_cli_command_t *);
};
#define VLIB_CLI_COMMAND(name, storage) storage vlib_cli_command_t name __attribute__((used))
static inline void vlib_cli_output(vlib_main_t *vm, const char *format, ...) {
  (void) vm; (void) format;
}
extern clib_error_t sakamoto_test_error;
static inline clib_error_t *
sakamoto_test_error_return (int ignored, const char *format, ...)
{
  (void) ignored;
  (void) format;
  sakamoto_test_error.message = "message-id-table unavailable";
  return &sakamoto_test_error;
}
#define clib_error_return(...) sakamoto_test_error_return (__VA_ARGS__)
#define clib_memset memset
#define clib_memcpy memcpy
#define clib_host_to_net_u32(value) (value)
#define clib_net_to_host_u32(value) (value)
#define clib_host_to_net_u64 value_identity_u64
#define clib_net_to_host_u64 value_identity_u64
static inline u64 value_identity_u64 (u64 value) { return value; }
#define VLIB_INIT_FUNCTION(fn) \
  clib_error_t *(*sakamoto_test_init)(vlib_main_t *) = fn
#endif
EOF
cat >"$work_dir/vlib/threads.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIB_THREADS_H
#define SAKAMOTO_TEST_VLIB_THREADS_H
#include "vlib.h"

typedef struct {
  int cpu_id;
} vlib_worker_thread_t;

typedef struct {
  u32 n_vlib_mains;
  u32 main_lcore;
} vlib_thread_main_t;

extern vlib_worker_thread_t *vlib_worker_threads;
extern vlib_thread_main_t vlib_thread_main;
extern unsigned long sakamoto_test_worker_thread_count;

#define vec_len(v) ((v) == 0 ? 0 : sakamoto_test_worker_thread_count)

static inline u32
vlib_num_workers (void)
{
  return vlib_thread_main.n_vlib_mains == 0 ? 0 : vlib_thread_main.n_vlib_mains - 1U;
}

static inline u32
vlib_get_worker_thread_index (u32 worker_index)
{
  return worker_index + 1U;
}

#endif
EOF

cat >"$work_dir/vlibapi/api.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIBAPI_H
#define SAKAMOTO_TEST_VLIBAPI_H
static unsigned char sakamoto_test_thread_safe[256];
static inline void *vlibapi_get_main(void) { return 0; }
static inline void vl_api_set_msg_thread_safe(void *main, unsigned id, int safe) {
  (void) main;
  if (id < 256) sakamoto_test_thread_safe[id] = (unsigned char)safe;
}
#endif
EOF
cat >"$work_dir/vlibmemory/api.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VLIBMEMORY_H
#define SAKAMOTO_TEST_VLIBMEMORY_H
#endif
EOF
cat >"$work_dir/vnet/vnet.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VNET_H
#define SAKAMOTO_TEST_VNET_H
#endif
EOF
cat >"$work_dir/vpp/app/version.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VPP_VERSION_H
#define SAKAMOTO_TEST_VPP_VERSION_H
#define VPP_BUILD_VER "test-vpp"
#endif
EOF
cat >"$work_dir/vnet/plugin/plugin.h" <<'EOF'
#ifndef SAKAMOTO_TEST_VNET_PLUGIN_H
#define SAKAMOTO_TEST_VNET_PLUGIN_H
typedef struct {
  const char *version;
  const char *description;
} vlib_plugin_registration_t;
#define VLIB_PLUGIN_REGISTER() vlib_plugin_registration_t vlib_plugin_registration
#endif
EOF
cat >"$work_dir/vlibapi/api_helper_macros.h" <<'EOF'
#ifndef SAKAMOTO_TEST_API_HELPERS_H
#define SAKAMOTO_TEST_API_HELPERS_H
#define REPLY_MACRO2(message_id, body) \
  do { \
    (void) (message_id); \
    rmp = (void *) (uintptr_t) 1U; \
    body; \
  } while (0)
#define REPLY_MACRO2_ZERO(message_id, body) REPLY_MACRO2(message_id, body)
static inline void *vl_api_client_index_to_registration (uint32_t index) {
  (void) index;
  return (void *) (uintptr_t) 1U;
}
#endif
EOF

cat >"$work_dir/product_core.api_enum.h" <<'EOF'
#ifndef SAKAMOTO_TEST_PRODUCT_CORE_ENUM_H
#define SAKAMOTO_TEST_PRODUCT_CORE_ENUM_H
#define VL_API_PRODUCT_CORE_SNI_QUERY_REPLY 22
#define VL_API_PRODUCT_CORE_OBSERVATION_QUERY_REPLY 24
#define VL_API_PRODUCT_CORE_RULE_CONFIG 20
#define VL_API_PRODUCT_CORE_RULE_CONFIG_REPLY 21
#define VL_API_PRODUCT_CORE_STATUS_REPLY 1
#define VL_API_PRODUCT_CORE_POLICY_APPLY_REPLY 2
#define VL_API_PRODUCT_CORE_POLICY_BUNDLE_APPLY_REPLY 3
#define VL_API_PRODUCT_CORE_POLICY_APPLY 4
#define VL_API_PRODUCT_CORE_POLICY_BUNDLE_APPLY 5
#define VL_API_PRODUCT_CORE_NETWORK_PUBLISH_REPLY 6
#define VL_API_PRODUCT_CORE_ROOT_STOP_REPLY 7
#define VL_API_PRODUCT_CORE_ROOT_STOP 8
#endif
EOF
cat >"$work_dir/product_core.api_types.h" <<'EOF'
#ifndef SAKAMOTO_TEST_PRODUCT_CORE_TYPES_H
#define SAKAMOTO_TEST_PRODUCT_CORE_TYPES_H
#include "sakamoto_product_rule_config.h"
#include "sakamoto_product_observation.h"
typedef struct { uint64_t generation; } vl_api_product_core_observation_query_t;
typedef struct { int32_t retval; uint64_t generation, mapping_bytes; uint32_t version, owners, flow_capacity, connected, blocked_capacity, blocked_active[2]; uint64_t blocked_capacity_misses[2], blocked_retired[2]; product_observation_channel_status_t channels[4]; } vl_api_product_core_observation_query_reply_t;
typedef struct { uint64_t generation, incarnation; uint32_t worker, slot; } vl_api_product_core_sni_query_t;
typedef struct { int32_t retval; uint64_t generation, incarnation, protocols; uint32_t worker, slot, result, stop, attempts, bytes, work, cache_bytes, name_length, protocols_available; char name[254]; } vl_api_product_core_sni_query_reply_t;
typedef sakamoto_product_config_rule_t vl_api_product_config_rule_t;
typedef struct { uint32_t client_index; uint64_t generation; uint32_t schema, operation; uint64_t expected_saved_revision; vl_api_product_config_rule_t rule; uint32_t count, reserved; sakamoto_product_direct_rule_t rules[256]; sakamoto_product_rule_graph_t graph; sakamoto_product_domains_t domains; sakamoto_product_config_metadata_t metadata; } vl_api_product_core_rule_config_t;
typedef struct { int32_t retval; uint64_t generation, saved_revision, active_revision, saved_rule_version, active_rule_version; uint32_t result, save_error, compile_error; vl_api_product_config_rule_t rule; uint32_t count, active_count, error_index, compiler_status; sakamoto_product_direct_rule_t rules[256]; uint64_t active_versions[256]; sakamoto_product_rule_graph_t graph; sakamoto_product_domains_t domains; sakamoto_product_config_metadata_t metadata; } vl_api_product_core_rule_config_reply_t;
typedef struct {
  int32_t retval;
  uint32_t abi_version;
  uint32_t api_version;
  uint64_t generation;
  u8 core_ready;
  u8 adapter_available;
  u8 protection_running;
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
  u8 policy_gate_blocked;
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
  u8 policy_last_drop_uid_known;
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
  u64 policy_l4_typed_match_policy_key;
  u64 policy_l4_typed_match_probe_key;
  u64 policy_l4_last_evaluation_probe_key;
  u8 artifact_id[96];
  u8 api_identity[96];
  u8 vpp_revision[48];
  u8 policy_snapshot_identity[96];
} vl_api_product_core_status_reply_t;
typedef struct { int unused; } vl_api_product_core_status_t;
typedef struct {
  uint64_t generation;
  uint64_t requested_revision;
  uint64_t snapshot_hash;
  u8 snapshot_empty;
  u8 default_pass;
  uint32_t gate_claim_count;
  uint32_t l4_rule_count;
  uint32_t gate_subject_uid;
  uint32_t gate_network_context;
  u8 gate_blocked;
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
  u8 l4_source_address[16];
  u8 l4_destination_address[16];
  u8 snapshot_identity[96];
} vl_api_product_core_policy_apply_t;
typedef struct {
  int32_t retval;
} vl_api_product_core_policy_apply_reply_t;
typedef struct __attribute__ ((packed)) {
  u32 subject_uid;
  u32 network_context;
  u32 ifindex;
  u32 rule_kind;
  u32 ip_family;
  u32 ip_protocol;
  u32 direction;
  u32 action;
  u32 enabled;
  u32 source_prefix_len;
  u32 destination_prefix_len;
  u32 source_port_first;
  u32 source_port_last;
  u32 destination_port_first;
  u32 destination_port_last;
  u32 priority;
  u32 order;
  u32 reason_id;
  u32 reserved;
  u64 rule_id;
  u8 source_address[16];
  u8 destination_address[16];
} vl_api_product_policy_rule_entry_t;
typedef struct {
  u64 generation;
  u32 abi_version;
  u32 struct_size;
  u64 requested_revision;
  u64 snapshot_hash;
  u32 gate_entry_count;
  u32 l4_rule_count;
  u32 default_pass;
  u32 reserved;
  u8 snapshot_identity[96];
  vl_api_product_policy_rule_entry_t gate_entries[64];
  vl_api_product_policy_rule_entry_t l4_entries[64];
} vl_api_product_core_policy_bundle_apply_t;
typedef struct {
  int32_t retval;
} vl_api_product_core_policy_bundle_apply_reply_t;
typedef struct {
  u64 generation, revision, event_elapsed_ns;
  u32 count, reserved;
  struct { u32 linux_ifindex, network_context; } entries[32];
} vl_api_product_core_network_publish_t;
typedef struct { int32_t retval; } vl_api_product_core_network_publish_reply_t;
typedef struct { u64 generation; } vl_api_product_core_root_stop_t;
typedef struct { int32_t retval; u64 generation; u32 stopped; } vl_api_product_core_root_stop_reply_t;
#endif
EOF
cat >"$work_dir/product_core_identity.h" <<'EOF'
#ifndef SAKAMOTO_TEST_PRODUCT_CORE_IDENTITY_H
#define SAKAMOTO_TEST_PRODUCT_CORE_IDENTITY_H
#ifndef SAKAMOTO_PRODUCT_ABI_VERSION
#define SAKAMOTO_PRODUCT_ABI_VERSION 1
#endif
#ifndef SAKAMOTO_PRODUCT_API_VERSION
#define SAKAMOTO_PRODUCT_API_VERSION 1
#endif
#define SAKAMOTO_PRODUCT_ARTIFACT_ID "test-artifact"
#define SAKAMOTO_PRODUCT_API_IDENTITY "test-api"
#define SAKAMOTO_PRODUCT_MANIFEST_VPP_REVISION "test-revision"
#endif
EOF
cat >"$work_dir/product_core.api.c" <<'EOF'
extern u16 sakamoto_test_message_id_base;
static u16
setup_message_id_table (void)
{
  (void) vl_api_product_core_sni_query_t_handler;
  (void) vl_api_product_core_observation_query_t_handler;
  (void) vl_api_product_core_status_t_handler;
  (void) vl_api_product_core_policy_apply_t_handler;
  (void) vl_api_product_core_rule_config_t_handler;
  (void) vl_api_product_core_policy_bundle_apply_t_handler;
  (void) vl_api_product_core_network_publish_t_handler;
  (void) vl_api_product_core_root_stop_t_handler;
  return sakamoto_test_message_id_base;
}
EOF

cat >"$work_dir/harness.c" <<EOF
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "vlib/vlib.h"
#include "vlib/threads.h"
#include "$repo_root/src/product/vpp/product_packet_graph.h"
#include "$repo_root/src/product/vpp/product_network_snapshot.h"

clib_error_t sakamoto_test_error;
u16 sakamoto_test_message_id_base;
vlib_worker_thread_t sakamoto_test_workers[3] = {{0}, {1}, {2}};
vlib_worker_thread_t *vlib_worker_threads = sakamoto_test_workers;
vlib_thread_main_t vlib_thread_main = {
  .n_vlib_mains = 3U,
  .main_lcore = 0U,
};
unsigned long sakamoto_test_worker_thread_count = 3U;

#define SAKAMOTO_PRODUCT_VPP_REVISION "test-revision"
int
product_root_nfqueue_adapter_available (void)
{
  return 0;
}

uint32_t
product_root_nfqueue_adapter_queue_id (void)
{
  return 176U;
}

uint32_t
product_root_nfqueue_adapter_queue_last (void)
{
  return 177U;
}

uint32_t
product_root_nfqueue_adapter_lane_count (void)
{
  return 2U;
}

uint32_t
product_root_nfqueue_adapter_ready_lane_mask (void)
{
  return 3U;
}

uint64_t
product_root_nfqueue_adapter_generation (void)
{
  return 0U;
}

uint64_t
product_root_nfqueue_adapter_verdict_attempts (void)
{
  return 0U;
}

uint64_t product_root_nfqueue_adapter_verdict_succeeded (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_verdict_failed_definite (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_verdict_outcome_unknown (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_ingress_identity_missing (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_graph_submit_fail_opens (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_non_owner_bypasses (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_duplicate_completion_drops (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_stale_completion_drops (void) { return 0U; }

uint64_t
product_root_nfqueue_adapter_internal_settlements (void)
{
  return 0U;
}

uint64_t
product_root_nfqueue_adapter_buffer_returns (void)
{
  return 0U;
}

uint64_t
product_root_nfqueue_adapter_origin_local_completions (void)
{
  return 0U;
}

uint64_t
product_root_nfqueue_adapter_origin_remote_completions (void)
{
  return 0U;
}

uint64_t
product_root_nfqueue_adapter_lane_verdict_attempts (uint32_t lane_index)
{
  (void) lane_index;
  return 0U;
}

uint64_t product_root_nfqueue_adapter_input_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_output_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_ipv4_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_ipv6_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_tcp_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_udp_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_uid_known_packets (void) { return 0U; }
uint64_t product_root_nfqueue_adapter_uid_unknown_packets (void) { return 0U; }
uint32_t product_root_nfqueue_adapter_last_ip_family (void) { return 0U; }
uint32_t product_root_nfqueue_adapter_last_protocol (void) { return 0U; }
uint32_t product_root_nfqueue_adapter_last_hook (void) { return 0U; }
uint32_t product_root_nfqueue_adapter_last_uid_known (void) { return 0U; }
uint32_t product_root_nfqueue_adapter_last_uid (void) { return UINT32_MAX; }
uint32_t product_root_nfqueue_adapter_last_queue_id (void) { return 0U; }
uint32_t product_root_nfqueue_adapter_last_packet_id (void) { return 0U; }

int
product_root_nfqueue_adapter_start (vlib_main_t *vm, u64 generation)
{
  (void) vm;
  (void) generation;
  return 0;
}

int product_vpn_udp4_adapter_available (void) { return 0; }
int product_vpn_tun_validation_enabled (void) { return 0; }
int product_vpn_tun_start (vlib_main_t *vm, u64 generation) {
  (void) vm; (void) generation; return 0;
}
u64 product_vpn_tun_attached (void) { return 0; }
u64 product_vpn_tun_captured (void) { return 0; }
int product_root_nfqueue_adapter_stop_step (vlib_main_t *vm, u64 generation) {
  (void) vm; (void) generation; return 0;
}
int product_network_snapshot_publish (vlib_main_t *vm, u64 generation,
  const sakamoto_product_network_snapshot_t *snapshot) {
  (void) vm; (void) generation; (void) snapshot; return 0;
}
int product_vpn_udp4_adapter_protection_running (void) { return 0; }
uint64_t product_vpn_udp4_adapter_tun_fd_attached (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_direct_socket_attached (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_direct_protect_succeeded (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_direct_bind_succeeded (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_tun_ingress_packets (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_udp4_tun_origin_packets (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_flow_stack_admissions (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_direct_send_succeeded (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_direct_transport_failed (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_flow_stack_return_packets (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_flow_stack_return_provenance_packets (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_tun_write_completions (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_infrastructure_faults (void) { return 0U; }
uint64_t product_vpn_udp4_adapter_duplicate_or_stale_drops (void) { return 0U; }
int product_vpn_udp4_adapter_start (vlib_main_t *vm, uint64_t generation)
{
  (void) vm;
  (void) generation;
  return 0;
}
int product_packet_graph_sni_query(uint64_t generation,uint32_t worker,uint32_t slot,
  uint64_t incarnation,sakamoto_product_sni_status_t *out)
{(void)generation;(void)worker;(void)slot;(void)incarnation;memset(out,0,sizeof *out);return -5;}
#include "sakamoto_product_observation.h"
void product_observation_status (product_observation_status_t *out) { memset(out,0,sizeof *out); }
uint32_t product_packet_graph_worker_count (void) { return 2U; }
uint64_t product_packet_graph_hash_seed (void) { return 0x6f776e65722d3137ULL; }
uint32_t product_packet_graph_handoff_credits (void) { return 32U; }
uint32_t product_packet_graph_enabled (void) { return 1U; }
uint32_t product_packet_graph_accepting (void) { return 1U; }
uint64_t product_packet_graph_obligation_debt (void) { return 0U; }
uint64_t product_packet_graph_buffer_debt (void) { return 0U; }
uint64_t product_packet_graph_handoff_debt (void) { return 0U; }
void product_packet_graph_publish_gate_policy (
  const product_packet_graph_gate_policy_t *policy)
{
  (void) policy;
}
void product_packet_graph_clear_gate_policy (uint64_t revision,
                                             uint64_t snapshot_hash)
{
  (void) revision;
  (void) snapshot_hash;
}
void product_packet_graph_gate_status (product_packet_graph_gate_status_t *status)
{
  if (status != NULL)
    memset (status, 0, sizeof (*status));
}
void product_packet_graph_publish_l4_policy (
  const product_packet_graph_l4_policy_t *policy)
{
  (void) policy;
}
void product_packet_graph_clear_l4_policy (uint64_t revision,
                                           uint64_t snapshot_hash)
{
  (void) revision;
  (void) snapshot_hash;
}
void product_packet_graph_l4_status (product_packet_graph_l4_status_t *status)
{
  if (status != NULL)
    memset (status, 0, sizeof (*status));
}
product_packet_result_t product_packet_graph_apply_policy_bundle (
  const product_packet_graph_policy_bundle_t *bundle)
{
  (void) bundle;
  return PRODUCT_PACKET_OK;
}

#include "$repo_root/src/product/vpp/product_core_plugin.c"

int
main (void)
{
  vlib_main_t vm = {0};
  sakamoto_test_message_id_base = UINT16_MAX;
  sakamoto_test_error.message = NULL;
  clib_error_t *error = sakamoto_test_init (&vm);
  if (error == NULL || product_core_main.core_ready != 0U
      || product_core_main.msg_id_base != UINT16_MAX
      || strstr (error->message, "unavailable") == NULL)
    {
      fprintf (stderr, "message-id setup failure was not fail-closed\\n");
      return 1;
    }

  sakamoto_test_message_id_base = 42U;
  sakamoto_test_error.message = NULL;
  error = sakamoto_test_init (&vm);
  if (error != NULL || product_core_main.core_ready == 0U
      || product_core_main.msg_id_base != 42U
      || sakamoto_test_thread_safe[42U + VL_API_PRODUCT_CORE_ROOT_STOP] != 0
      || product_core_start_adapters_node.process_log2_n_stack_bytes < 18)
    {
      fprintf (stderr, "available message-id setup did not reach ready\\n");
      return 1;
    }
  return 0;
}
EOF

cc -std=c11 -Wall -Wextra -Werror \
  -I"$work_dir" -I"$repo_root/src/product/include" -I"$repo_root/src/product/vpp" \
  "$repo_root/src/product/vpp/product_rule_config.c" \
  "$repo_root/src/product/vpp/product_l4_policy.c" \
  "$repo_root/src/product/vpp/product_domains.c" \
  "$repo_root/src/product/vpp/product_domains_memory.c" \
  "$repo_root/src/product/vpp/product_domains_rax.c" \
  "$work_dir/harness.c" -lm -o "$work_dir/plugin-init-contract"
"$work_dir/plugin-init-contract"
echo "sakamoto production VPP plugin init contract: PASS"
