#![deny(unsafe_op_in_unsafe_fn)]

// Keep the established crate-root interface; implementation modules are private.
mod ffi;
mod rule_config;
pub use rule_config::{ConfigRule, RuleConfigRequest, RuleConfigStatus};
mod session;

pub use ffi::{
    abi_version, api_version, sakamoto_product_core_apply_empty_policy,
    sakamoto_product_core_apply_empty_policy_revision, sakamoto_product_core_apply_l4_policy,
    sakamoto_product_core_apply_l4_policy_revision,
    sakamoto_product_core_apply_network_gate_policy,
    sakamoto_product_core_apply_network_gate_policy_revision,
    sakamoto_product_core_apply_policy_bundle, sakamoto_product_core_connect,
    sakamoto_product_core_destroy, sakamoto_product_core_disconnect,
    sakamoto_product_core_publish_network, sakamoto_product_core_query,
    sakamoto_product_core_reconcile_empty_policy, sakamoto_product_core_reconcile_policy,
    sakamoto_product_core_set_policy_mutation_fault, sakamoto_product_core_stop_root,
    ProductCoreHandle,
};
pub use session::ProductCore;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductBytes {
    pub data: *const u8,
    pub length: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductPolicySnapshot {
    pub schema_version: u32,
    pub reserved: u32,
    pub requested_revision: u64,
    pub snapshot_hash: u64,
    pub snapshot_empty: u32,
    pub default_pass: u32,
    pub gate_claim_count: u32,
    pub l4_rule_count: u32,
    pub gate_subject_uid: u32,
    pub gate_network_context: u32,
    pub gate_blocked: u32,
    pub gate_reason_id: u32,
    pub gate_rule_id: u64,
    pub l4_subject_uid: u32,
    pub l4_network_context: u32,
    pub l4_ip_family: u32,
    pub l4_ip_protocol: u32,
    pub l4_direction: u32,
    pub l4_action: u32,
    pub l4_source_prefix_len: u32,
    pub l4_destination_prefix_len: u32,
    pub l4_source_port_first: u32,
    pub l4_source_port_last: u32,
    pub l4_destination_port_first: u32,
    pub l4_destination_port_last: u32,
    pub l4_priority: u32,
    pub l4_order: u32,
    pub l4_reason_id: u32,
    pub l4_reserved: u32,
    pub l4_rule_id: u64,
    pub l4_source_address: [u8; 16],
    pub l4_destination_address: [u8; 16],
    pub snapshot_identity: [u8; 96],
}

/* SAKAMOTO-192 keeps the S188-S191 single-slot ABI above intact and adds a
 * fixed-capacity successor snapshot.  These Rust layouts intentionally mirror
 * sakamoto_product_abi.h field-for-field. */
pub const POLICY_BUNDLE_ABI_VERSION: u32 = 1;
pub const POLICY_BUNDLE_MAX_GATE_ENTRIES: usize = 64;
pub const POLICY_BUNDLE_MAX_L4_ENTRIES: usize = 64;
pub const POLICY_BUNDLE_MAX_L4_RULES: usize = POLICY_BUNDLE_MAX_L4_ENTRIES;
pub const POLICY_BUNDLE_MAX_RULE_ENTRIES: usize =
    POLICY_BUNDLE_MAX_GATE_ENTRIES + POLICY_BUNDLE_MAX_L4_ENTRIES;
pub const PRODUCT_POLICY_IFINDEX_ANY: u32 = u32::MAX;
pub const POLICY_MUTATION_FAULT_NONE: u32 = 0;
pub const POLICY_MUTATION_FAULT_OMIT_CALLBACK: u32 = 1;
pub const POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductPolicyRuleEntry {
    pub subject_uid: u32,
    pub network_context: u32,
    pub ifindex: u32,
    pub rule_kind: u32,
    pub ip_family: u32,
    pub ip_protocol: u32,
    pub direction: u32,
    pub action: u32,
    pub enabled: u32,
    pub source_prefix_len: u32,
    pub destination_prefix_len: u32,
    pub source_port_first: u32,
    pub source_port_last: u32,
    pub destination_port_first: u32,
    pub destination_port_last: u32,
    pub priority: u32,
    pub order: u32,
    pub reason_id: u32,
    pub reserved: u32,
    pub rule_id: u64,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductPolicyBundle {
    pub abi_version: u32,
    pub struct_size: u32,
    pub requested_revision: u64,
    pub snapshot_hash: u64,
    pub gate_entry_count: u32,
    pub l4_rule_count: u32,
    pub default_pass: u32,
    pub reserved: u32,
    pub snapshot_identity: [u8; 96],
    pub gate_entries: [ProductPolicyRuleEntry; POLICY_BUNDLE_MAX_GATE_ENTRIES],
    pub l4_entries: [ProductPolicyRuleEntry; POLICY_BUNDLE_MAX_L4_ENTRIES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductStatus {
    pub abi_version: u32,
    pub api_version: u32,
    pub status_code: u32,
    pub reserved: u32,
    pub generation: u64,
    pub core_ready: u32,
    pub adapter_available: u32,
    pub protection_running: u32,
    pub plugin_loaded: u32,
    pub vapi_handle_live: u32,
    pub generation_live: u32,
    pub reserved_flags: u32,
    pub artifact_id: [u8; 96],
    pub api_identity: [u8; 96],
    pub vpp_revision: [u8; 48],
    pub error_detail: [u8; 128],
    pub root_nfqueue_queue_id: u32,
    pub root_nfqueue_queue_last: u32,
    pub root_nfqueue_lane_count: u32,
    pub root_nfqueue_ready_lane_mask: u32,
    pub root_nfqueue_generation: u64,
    pub root_nfqueue_verdict_attempts: u64,
    pub root_nfqueue_internal_settlements: u64,
    pub root_nfqueue_buffer_returns: u64,
    pub root_nfqueue_origin_local_completions: u64,
    pub root_nfqueue_origin_remote_completions: u64,
    pub root_nfqueue_lane0_verdict_attempts: u64,
    pub root_nfqueue_lane1_verdict_attempts: u64,
    pub root_nfqueue_input_packets: u64,
    pub root_nfqueue_output_packets: u64,
    pub root_nfqueue_ipv4_packets: u64,
    pub root_nfqueue_ipv6_packets: u64,
    pub root_nfqueue_tcp_packets: u64,
    pub root_nfqueue_udp_packets: u64,
    pub root_nfqueue_uid_known_packets: u64,
    pub root_nfqueue_uid_unknown_packets: u64,
    pub root_nfqueue_last_ip_family: u32,
    pub root_nfqueue_last_protocol: u32,
    pub root_nfqueue_last_hook: u32,
    pub root_nfqueue_last_uid_known: u32,
    pub root_nfqueue_last_uid: u32,
    pub root_nfqueue_last_queue_id: u32,
    pub root_nfqueue_last_packet_id: u32,
    pub root_nfqueue_verdict_succeeded: u64,
    pub root_nfqueue_verdict_failed_definite: u64,
    pub root_nfqueue_verdict_outcome_unknown: u64,
    pub root_nfqueue_ingress_identity_missing: u64,
    pub root_nfqueue_graph_submit_fail_opens: u64,
    pub root_nfqueue_non_owner_bypasses: u64,
    pub root_nfqueue_duplicate_completion_drops: u64,
    pub root_nfqueue_stale_completion_drops: u64,
    pub vpn_tun_fd_attached: u64,
    pub vpn_direct_udp4_socket_attached: u64,
    pub vpn_direct_udp4_protect_succeeded: u64,
    pub vpn_direct_udp4_bind_succeeded: u64,
    pub vpn_tun_ingress_packets: u64,
    pub vpn_tun_udp4_tun_origin_packets: u64,
    pub vpn_flow_stack_admissions: u64,
    pub vpn_direct_udp4_send_succeeded: u64,
    pub vpn_direct_udp4_transport_failed: u64,
    pub vpn_flow_stack_return_packets: u64,
    pub vpn_flow_stack_return_provenance_packets: u64,
    pub vpn_tun_write_completions: u64,
    pub vpn_infrastructure_faults: u64,
    pub vpn_duplicate_or_stale_drops: u64,
    pub product_graph_worker_count: u32,
    pub product_graph_hash_seed: u64,
    pub product_graph_handoff_credits: u32,
    pub product_graph_vpp_worker_count: u32,
    pub product_graph_vpp_main_core: u32,
    pub product_graph_vpp_worker0_thread_index: u32,
    pub product_graph_vpp_worker0_core: u32,
    pub product_graph_vpp_worker1_thread_index: u32,
    pub product_graph_vpp_worker1_core: u32,
    pub product_graph_enabled: u32,
    pub product_graph_accepting: u32,
    pub product_graph_worker_layout_ready: u32,
    pub product_graph_obligation_debt: u64,
    pub product_graph_buffer_debt: u64,
    pub product_graph_handoff_debt: u64,
    pub policy_requested_revision: u64,
    pub policy_active_revision: u64,
    pub policy_generation: u64,
    pub policy_snapshot_hash: u64,
    pub policy_worker0_revision: u64,
    pub policy_worker1_revision: u64,
    pub policy_snapshot_empty: u32,
    pub policy_default_pass: u32,
    pub policy_gate_claim_count: u32,
    pub policy_l4_rule_count: u32,
    pub policy_last_apply_status_code: u32,
    pub policy_mixed_revision: u32,
    pub policy_artifact_match: u32,
    pub policy_generation_match: u32,
    pub policy_snapshot_identity: [u8; 96],
    pub policy_gate_subject_uid: u32,
    pub policy_gate_network_context: u32,
    pub policy_gate_blocked: u32,
    pub policy_gate_reason_id: u32,
    pub policy_gate_rule_id: u64,
    pub policy_drop_records: u64,
    pub policy_last_drop_revision: u64,
    pub policy_last_drop_rule_id: u64,
    pub policy_last_drop_completion_attempts: u64,
    pub policy_last_drop_uid: u32,
    pub policy_last_drop_network_context: u32,
    pub policy_last_drop_reason_id: u32,
    pub policy_last_drop_verdict: u32,
    pub policy_last_drop_winner: u32,
    pub policy_last_drop_uid_known: u32,
    pub policy_last_drop_device_direction: u32,
    pub policy_l4_active_revision: u64,
    pub policy_l4_rule_id: u64,
    pub policy_l4_match_records: u64,
    pub policy_l4_no_match_records: u64,
    pub policy_l4_last_match_revision: u64,
    pub policy_l4_last_match_rule_id: u64,
    pub policy_l4_subject_uid: u32,
    pub policy_l4_network_context: u32,
    pub policy_l4_ip_family: u32,
    pub policy_l4_ip_protocol: u32,
    pub policy_l4_direction: u32,
    pub policy_l4_action: u32,
    pub policy_l4_priority: u32,
    pub policy_l4_order: u32,
    pub policy_l4_reason_id: u32,
    pub policy_l4_last_match_uid: u32,
    pub policy_l4_last_match_network_context: u32,
    pub policy_l4_last_match_reason_id: u32,
    pub policy_l4_last_match_verdict: u32,
    pub policy_l4_last_match_winner: u32,
    pub policy_l4_last_match_uid_known: u32,
    pub policy_l4_last_match_device_direction: u32,
    pub policy_l4_last_match_action: u32,
    pub policy_l4_last_evaluation_result: u32,
    pub policy_l4_last_evaluation_verdict: u32,
    pub policy_l4_last_evaluation_device_direction: u32,
    pub policy_l4_view_active: u32,
    pub policy_l4_view_rule_count: u32,
    pub policy_l4_view_max_probes: u32,
    pub policy_l4_view_last_match_winner_rank: u32,
    pub policy_l4_view_last_match_probes: u32,
    pub policy_l4_view_last_match_candidate_count: u32,
    pub policy_l4_view_last_no_match_reason: u32,
    pub policy_l4_typed_match_policy_key: u64,
    pub policy_l4_typed_match_probe_key: u64,
    pub policy_l4_last_evaluation_probe_key: u64,
}

pub const ABI_VERSION: u32 = 1;

#[repr(C)]
pub struct ProductNetworkSnapshot {
    pub revision: u64,
    pub event_elapsed_ns: u64,
    pub count: u32,
    pub reserved: u32,
    pub entries: [[u32; 2]; 32],
}
const _: () = assert!(std::mem::size_of::<ProductNetworkSnapshot>() == 280);

pub const API_VERSION: u32 = 1;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Ok,
    InvalidArgument,
    AllocationFailed,
    ConnectFailed,
    Disconnected,
    StaleHandle,
    ApiUnavailable,
    QueryFailed,
    ProtocolMismatch,
    InternalError,
    UnknownTag,
    DisconnectFailed,
    PolicyStoreFailed,
    PolicyApplyFailed,
    PolicyOutcomeUnknown,
    PolicyMutationFenced,
    Unknown(u32),
}

impl ErrorCode {
    fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Ok,
            1 => Self::InvalidArgument,
            2 => Self::AllocationFailed,
            3 => Self::ConnectFailed,
            4 => Self::Disconnected,
            5 => Self::StaleHandle,
            6 => Self::ApiUnavailable,
            7 => Self::QueryFailed,
            8 => Self::ProtocolMismatch,
            9 => Self::InternalError,
            10 => Self::UnknownTag,
            11 => Self::DisconnectFailed,
            12 => Self::PolicyStoreFailed,
            13 => Self::PolicyApplyFailed,
            14 => Self::PolicyOutcomeUnknown,
            15 => Self::PolicyMutationFenced,
            value => Self::Unknown(value),
        }
    }

    pub fn raw(self) -> u32 {
        match self {
            Self::Ok => 0,
            Self::InvalidArgument => 1,
            Self::AllocationFailed => 2,
            Self::ConnectFailed => 3,
            Self::Disconnected => 4,
            Self::StaleHandle => 5,
            Self::ApiUnavailable => 6,
            Self::QueryFailed => 7,
            Self::ProtocolMismatch => 8,
            Self::InternalError => 9,
            Self::UnknownTag => 10,
            Self::DisconnectFailed => 11,
            Self::PolicyStoreFailed => 12,
            Self::PolicyApplyFailed => 13,
            Self::PolicyOutcomeUnknown => 14,
            Self::PolicyMutationFenced => 15,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Status {
    pub abi_version: u32,
    pub api_version: u32,
    pub code: ErrorCode,
    pub generation: u64,
    pub core_ready: bool,
    pub adapter_available: bool,
    pub protection_running: bool,
    pub plugin_loaded: bool,
    pub vapi_handle_live: bool,
    pub generation_live: bool,
    pub artifact_id: String,
    pub api_identity: String,
    pub vpp_revision: String,
    pub error_detail: String,
    pub root_nfqueue_queue_id: u32,
    pub root_nfqueue_queue_last: u32,
    pub root_nfqueue_lane_count: u32,
    pub root_nfqueue_ready_lane_mask: u32,
    pub root_nfqueue_generation: u64,
    pub root_nfqueue_verdict_attempts: u64,
    pub root_nfqueue_internal_settlements: u64,
    pub root_nfqueue_buffer_returns: u64,
    pub root_nfqueue_origin_local_completions: u64,
    pub root_nfqueue_origin_remote_completions: u64,
    pub root_nfqueue_lane0_verdict_attempts: u64,
    pub root_nfqueue_lane1_verdict_attempts: u64,
    pub root_nfqueue_input_packets: u64,
    pub root_nfqueue_output_packets: u64,
    pub root_nfqueue_ipv4_packets: u64,
    pub root_nfqueue_ipv6_packets: u64,
    pub root_nfqueue_tcp_packets: u64,
    pub root_nfqueue_udp_packets: u64,
    pub root_nfqueue_uid_known_packets: u64,
    pub root_nfqueue_uid_unknown_packets: u64,
    pub root_nfqueue_last_ip_family: u32,
    pub root_nfqueue_last_protocol: u32,
    pub root_nfqueue_last_hook: u32,
    pub root_nfqueue_last_uid_known: u32,
    pub root_nfqueue_last_uid: u32,
    pub root_nfqueue_last_queue_id: u32,
    pub root_nfqueue_last_packet_id: u32,
    pub root_nfqueue_verdict_succeeded: u64,
    pub root_nfqueue_verdict_failed_definite: u64,
    pub root_nfqueue_verdict_outcome_unknown: u64,
    pub root_nfqueue_ingress_identity_missing: u64,
    pub root_nfqueue_graph_submit_fail_opens: u64,
    pub root_nfqueue_non_owner_bypasses: u64,
    pub root_nfqueue_duplicate_completion_drops: u64,
    pub root_nfqueue_stale_completion_drops: u64,
    pub vpn_tun_fd_attached: u64,
    pub vpn_direct_udp4_socket_attached: u64,
    pub vpn_direct_udp4_protect_succeeded: u64,
    pub vpn_direct_udp4_bind_succeeded: u64,
    pub vpn_tun_ingress_packets: u64,
    pub vpn_tun_udp4_tun_origin_packets: u64,
    pub vpn_flow_stack_admissions: u64,
    pub vpn_direct_udp4_send_succeeded: u64,
    pub vpn_direct_udp4_transport_failed: u64,
    pub vpn_flow_stack_return_packets: u64,
    pub vpn_flow_stack_return_provenance_packets: u64,
    pub vpn_tun_write_completions: u64,
    pub vpn_infrastructure_faults: u64,
    pub vpn_duplicate_or_stale_drops: u64,
    pub product_graph_worker_count: u32,
    pub product_graph_hash_seed: u64,
    pub product_graph_handoff_credits: u32,
    pub product_graph_vpp_worker_count: u32,
    pub product_graph_vpp_main_core: u32,
    pub product_graph_vpp_worker0_thread_index: u32,
    pub product_graph_vpp_worker0_core: u32,
    pub product_graph_vpp_worker1_thread_index: u32,
    pub product_graph_vpp_worker1_core: u32,
    pub product_graph_enabled: u32,
    pub product_graph_accepting: u32,
    pub product_graph_worker_layout_ready: u32,
    pub product_graph_obligation_debt: u64,
    pub product_graph_buffer_debt: u64,
    pub product_graph_handoff_debt: u64,
    pub policy_requested_revision: u64,
    pub policy_active_revision: u64,
    pub policy_generation: u64,
    pub policy_snapshot_hash: u64,
    pub policy_worker0_revision: u64,
    pub policy_worker1_revision: u64,
    pub policy_snapshot_empty: bool,
    pub policy_default_pass: bool,
    pub policy_gate_claim_count: u32,
    pub policy_l4_rule_count: u32,
    pub policy_last_apply_status_code: u32,
    pub policy_mixed_revision: bool,
    pub policy_artifact_match: bool,
    pub policy_generation_match: bool,
    pub policy_snapshot_identity: String,
    pub policy_gate_subject_uid: u32,
    pub policy_gate_network_context: u32,
    pub policy_gate_blocked: bool,
    pub policy_gate_reason_id: u32,
    pub policy_gate_rule_id: u64,
    pub policy_drop_records: u64,
    pub policy_last_drop_revision: u64,
    pub policy_last_drop_rule_id: u64,
    pub policy_last_drop_completion_attempts: u64,
    pub policy_last_drop_uid: u32,
    pub policy_last_drop_network_context: u32,
    pub policy_last_drop_reason_id: u32,
    pub policy_last_drop_verdict: u32,
    pub policy_last_drop_winner: u32,
    pub policy_last_drop_uid_known: bool,
    pub policy_last_drop_device_direction: u32,
    pub policy_l4_active_revision: u64,
    pub policy_l4_rule_id: u64,
    pub policy_l4_match_records: u64,
    pub policy_l4_no_match_records: u64,
    pub policy_l4_last_match_revision: u64,
    pub policy_l4_last_match_rule_id: u64,
    pub policy_l4_subject_uid: u32,
    pub policy_l4_network_context: u32,
    pub policy_l4_ip_family: u32,
    pub policy_l4_ip_protocol: u32,
    pub policy_l4_direction: u32,
    pub policy_l4_action: u32,
    pub policy_l4_priority: u32,
    pub policy_l4_order: u32,
    pub policy_l4_reason_id: u32,
    pub policy_l4_last_match_uid: u32,
    pub policy_l4_last_match_network_context: u32,
    pub policy_l4_last_match_reason_id: u32,
    pub policy_l4_last_match_verdict: u32,
    pub policy_l4_last_match_winner: u32,
    pub policy_l4_last_match_uid_known: u32,
    pub policy_l4_last_match_device_direction: u32,
    pub policy_l4_last_match_action: u32,
    pub policy_l4_last_evaluation_result: u32,
    pub policy_l4_last_evaluation_verdict: u32,
    pub policy_l4_last_evaluation_device_direction: u32,
    pub policy_l4_view_active: u32,
    pub policy_l4_view_rule_count: u32,
    pub policy_l4_view_max_probes: u32,
    pub policy_l4_view_last_match_winner_rank: u32,
    pub policy_l4_view_last_match_probes: u32,
    pub policy_l4_view_last_match_candidate_count: u32,
    pub policy_l4_view_last_no_match_reason: u32,
    pub policy_l4_typed_match_policy_key: u64,
    pub policy_l4_typed_match_probe_key: u64,
    pub policy_l4_last_evaluation_probe_key: u64,
}

impl Status {
    fn from_ffi(value: ProductStatus) -> Self {
        Self {
            abi_version: value.abi_version,
            api_version: value.api_version,
            code: ErrorCode::from_raw(value.status_code),
            generation: value.generation,
            core_ready: value.core_ready != 0,
            adapter_available: value.adapter_available != 0,
            protection_running: value.protection_running != 0,
            plugin_loaded: value.plugin_loaded != 0,
            vapi_handle_live: value.vapi_handle_live != 0,
            generation_live: value.generation_live != 0,
            artifact_id: bounded_string(&value.artifact_id),
            api_identity: bounded_string(&value.api_identity),
            vpp_revision: bounded_string(&value.vpp_revision),
            error_detail: bounded_string(&value.error_detail),
            root_nfqueue_queue_id: value.root_nfqueue_queue_id,
            root_nfqueue_queue_last: value.root_nfqueue_queue_last,
            root_nfqueue_lane_count: value.root_nfqueue_lane_count,
            root_nfqueue_ready_lane_mask: value.root_nfqueue_ready_lane_mask,
            root_nfqueue_generation: value.root_nfqueue_generation,
            root_nfqueue_verdict_attempts: value.root_nfqueue_verdict_attempts,
            root_nfqueue_internal_settlements: value.root_nfqueue_internal_settlements,
            root_nfqueue_buffer_returns: value.root_nfqueue_buffer_returns,
            root_nfqueue_origin_local_completions: value.root_nfqueue_origin_local_completions,
            root_nfqueue_origin_remote_completions: value.root_nfqueue_origin_remote_completions,
            root_nfqueue_lane0_verdict_attempts: value.root_nfqueue_lane0_verdict_attempts,
            root_nfqueue_lane1_verdict_attempts: value.root_nfqueue_lane1_verdict_attempts,
            root_nfqueue_input_packets: value.root_nfqueue_input_packets,
            root_nfqueue_output_packets: value.root_nfqueue_output_packets,
            root_nfqueue_ipv4_packets: value.root_nfqueue_ipv4_packets,
            root_nfqueue_ipv6_packets: value.root_nfqueue_ipv6_packets,
            root_nfqueue_tcp_packets: value.root_nfqueue_tcp_packets,
            root_nfqueue_udp_packets: value.root_nfqueue_udp_packets,
            root_nfqueue_uid_known_packets: value.root_nfqueue_uid_known_packets,
            root_nfqueue_uid_unknown_packets: value.root_nfqueue_uid_unknown_packets,
            root_nfqueue_last_ip_family: value.root_nfqueue_last_ip_family,
            root_nfqueue_last_protocol: value.root_nfqueue_last_protocol,
            root_nfqueue_last_hook: value.root_nfqueue_last_hook,
            root_nfqueue_last_uid_known: value.root_nfqueue_last_uid_known,
            root_nfqueue_last_uid: value.root_nfqueue_last_uid,
            root_nfqueue_last_queue_id: value.root_nfqueue_last_queue_id,
            root_nfqueue_last_packet_id: value.root_nfqueue_last_packet_id,
            root_nfqueue_verdict_succeeded: value.root_nfqueue_verdict_succeeded,
            root_nfqueue_verdict_failed_definite: value.root_nfqueue_verdict_failed_definite,
            root_nfqueue_verdict_outcome_unknown: value.root_nfqueue_verdict_outcome_unknown,
            root_nfqueue_ingress_identity_missing: value.root_nfqueue_ingress_identity_missing,
            root_nfqueue_graph_submit_fail_opens: value.root_nfqueue_graph_submit_fail_opens,
            root_nfqueue_non_owner_bypasses: value.root_nfqueue_non_owner_bypasses,
            root_nfqueue_duplicate_completion_drops: value.root_nfqueue_duplicate_completion_drops,
            root_nfqueue_stale_completion_drops: value.root_nfqueue_stale_completion_drops,
            vpn_tun_fd_attached: value.vpn_tun_fd_attached,
            vpn_direct_udp4_socket_attached: value.vpn_direct_udp4_socket_attached,
            vpn_direct_udp4_protect_succeeded: value.vpn_direct_udp4_protect_succeeded,
            vpn_direct_udp4_bind_succeeded: value.vpn_direct_udp4_bind_succeeded,
            vpn_tun_ingress_packets: value.vpn_tun_ingress_packets,
            vpn_tun_udp4_tun_origin_packets: value.vpn_tun_udp4_tun_origin_packets,
            vpn_flow_stack_admissions: value.vpn_flow_stack_admissions,
            vpn_direct_udp4_send_succeeded: value.vpn_direct_udp4_send_succeeded,
            vpn_direct_udp4_transport_failed: value.vpn_direct_udp4_transport_failed,
            vpn_flow_stack_return_packets: value.vpn_flow_stack_return_packets,
            vpn_flow_stack_return_provenance_packets: value
                .vpn_flow_stack_return_provenance_packets,
            vpn_tun_write_completions: value.vpn_tun_write_completions,
            vpn_infrastructure_faults: value.vpn_infrastructure_faults,
            vpn_duplicate_or_stale_drops: value.vpn_duplicate_or_stale_drops,
            product_graph_worker_count: value.product_graph_worker_count,
            product_graph_hash_seed: value.product_graph_hash_seed,
            product_graph_handoff_credits: value.product_graph_handoff_credits,
            product_graph_vpp_worker_count: value.product_graph_vpp_worker_count,
            product_graph_vpp_main_core: value.product_graph_vpp_main_core,
            product_graph_vpp_worker0_thread_index: value.product_graph_vpp_worker0_thread_index,
            product_graph_vpp_worker0_core: value.product_graph_vpp_worker0_core,
            product_graph_vpp_worker1_thread_index: value.product_graph_vpp_worker1_thread_index,
            product_graph_vpp_worker1_core: value.product_graph_vpp_worker1_core,
            product_graph_enabled: value.product_graph_enabled,
            product_graph_accepting: value.product_graph_accepting,
            product_graph_worker_layout_ready: value.product_graph_worker_layout_ready,
            product_graph_obligation_debt: value.product_graph_obligation_debt,
            product_graph_buffer_debt: value.product_graph_buffer_debt,
            product_graph_handoff_debt: value.product_graph_handoff_debt,
            policy_requested_revision: value.policy_requested_revision,
            policy_active_revision: value.policy_active_revision,
            policy_generation: value.policy_generation,
            policy_snapshot_hash: value.policy_snapshot_hash,
            policy_worker0_revision: value.policy_worker0_revision,
            policy_worker1_revision: value.policy_worker1_revision,
            policy_snapshot_empty: value.policy_snapshot_empty != 0,
            policy_default_pass: value.policy_default_pass != 0,
            policy_gate_claim_count: value.policy_gate_claim_count,
            policy_l4_rule_count: value.policy_l4_rule_count,
            policy_last_apply_status_code: value.policy_last_apply_status_code,
            policy_mixed_revision: value.policy_mixed_revision != 0,
            policy_artifact_match: value.policy_artifact_match != 0,
            policy_generation_match: value.policy_generation_match != 0,
            policy_snapshot_identity: bounded_string(&value.policy_snapshot_identity),
            policy_gate_subject_uid: value.policy_gate_subject_uid,
            policy_gate_network_context: value.policy_gate_network_context,
            policy_gate_blocked: value.policy_gate_blocked != 0,
            policy_gate_reason_id: value.policy_gate_reason_id,
            policy_gate_rule_id: value.policy_gate_rule_id,
            policy_drop_records: value.policy_drop_records,
            policy_last_drop_revision: value.policy_last_drop_revision,
            policy_last_drop_rule_id: value.policy_last_drop_rule_id,
            policy_last_drop_completion_attempts: value.policy_last_drop_completion_attempts,
            policy_last_drop_uid: value.policy_last_drop_uid,
            policy_last_drop_network_context: value.policy_last_drop_network_context,
            policy_last_drop_reason_id: value.policy_last_drop_reason_id,
            policy_last_drop_verdict: value.policy_last_drop_verdict,
            policy_last_drop_winner: value.policy_last_drop_winner,
            policy_last_drop_uid_known: value.policy_last_drop_uid_known != 0,
            policy_last_drop_device_direction: value.policy_last_drop_device_direction,
            policy_l4_active_revision: value.policy_l4_active_revision,
            policy_l4_rule_id: value.policy_l4_rule_id,
            policy_l4_match_records: value.policy_l4_match_records,
            policy_l4_no_match_records: value.policy_l4_no_match_records,
            policy_l4_last_match_revision: value.policy_l4_last_match_revision,
            policy_l4_last_match_rule_id: value.policy_l4_last_match_rule_id,
            policy_l4_subject_uid: value.policy_l4_subject_uid,
            policy_l4_network_context: value.policy_l4_network_context,
            policy_l4_ip_family: value.policy_l4_ip_family,
            policy_l4_ip_protocol: value.policy_l4_ip_protocol,
            policy_l4_direction: value.policy_l4_direction,
            policy_l4_action: value.policy_l4_action,
            policy_l4_priority: value.policy_l4_priority,
            policy_l4_order: value.policy_l4_order,
            policy_l4_reason_id: value.policy_l4_reason_id,
            policy_l4_last_match_uid: value.policy_l4_last_match_uid,
            policy_l4_last_match_network_context: value.policy_l4_last_match_network_context,
            policy_l4_last_match_reason_id: value.policy_l4_last_match_reason_id,
            policy_l4_last_match_verdict: value.policy_l4_last_match_verdict,
            policy_l4_last_match_winner: value.policy_l4_last_match_winner,
            policy_l4_last_match_uid_known: value.policy_l4_last_match_uid_known,
            policy_l4_last_match_device_direction: value.policy_l4_last_match_device_direction,
            policy_l4_last_match_action: value.policy_l4_last_match_action,
            policy_l4_last_evaluation_result: value.policy_l4_last_evaluation_result,
            policy_l4_last_evaluation_verdict: value.policy_l4_last_evaluation_verdict,
            policy_l4_last_evaluation_device_direction: value
                .policy_l4_last_evaluation_device_direction,
            policy_l4_view_active: value.policy_l4_view_active,
            policy_l4_view_rule_count: value.policy_l4_view_rule_count,
            policy_l4_view_max_probes: value.policy_l4_view_max_probes,
            policy_l4_view_last_match_winner_rank: value.policy_l4_view_last_match_winner_rank,
            policy_l4_view_last_match_probes: value.policy_l4_view_last_match_probes,
            policy_l4_view_last_match_candidate_count: value
                .policy_l4_view_last_match_candidate_count,
            policy_l4_view_last_no_match_reason: value.policy_l4_view_last_no_match_reason,
            policy_l4_typed_match_policy_key: value.policy_l4_typed_match_policy_key,
            policy_l4_typed_match_probe_key: value.policy_l4_typed_match_probe_key,
            policy_l4_last_evaluation_probe_key: value.policy_l4_last_evaluation_probe_key,
        }
    }
}

fn validate_status_identity(status: &Status) -> Result<(), ProductError> {
    if status.abi_version != ABI_VERSION {
        return Err(ProductError::AbiVersion {
            expected: ABI_VERSION,
            actual: status.abi_version,
        });
    }
    if status.api_version != API_VERSION {
        return Err(ProductError::ApiVersion {
            expected: API_VERSION,
            actual: status.api_version,
        });
    }
    Ok(())
}

fn bounded_string(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProductError {
    AbiVersion {
        expected: u32,
        actual: u32,
    },
    ApiVersion {
        expected: u32,
        actual: u32,
    },
    Native {
        code: ErrorCode,
        status: Status,
    },
    PathContainsNul,
    PolicyStore {
        detail: String,
    },
    /// A prior mutation has no trustworthy terminal reply.  Only a fresh
    /// Product Core generation may clear this durable fence by readback.
    MutationFenceActive {
        generation: u64,
        requested_revision: u64,
    },
    GenerationActive {
        generation: u64,
    },
    GenerationRetired {
        generation: u64,
    },
}

impl ProductError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::AbiVersion { .. } | Self::ApiVersion { .. } => ErrorCode::ProtocolMismatch,
            Self::Native { code, .. } => *code,
            Self::PathContainsNul => ErrorCode::InvalidArgument,
            Self::PolicyStore { .. } => ErrorCode::PolicyStoreFailed,
            Self::MutationFenceActive { .. } => ErrorCode::PolicyMutationFenced,
            Self::GenerationActive { .. } | Self::GenerationRetired { .. } => {
                ErrorCode::StaleHandle
            }
        }
    }
}

impl ProductStatus {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl Status {
    fn empty(generation: u64) -> Self {
        Self {
            abi_version: ABI_VERSION,
            api_version: API_VERSION,
            code: ErrorCode::Disconnected,
            generation,
            core_ready: false,
            adapter_available: false,
            protection_running: false,
            plugin_loaded: false,
            vapi_handle_live: false,
            generation_live: false,
            artifact_id: String::new(),
            api_identity: String::new(),
            vpp_revision: String::new(),
            error_detail: String::new(),
            root_nfqueue_queue_id: 0,
            root_nfqueue_queue_last: 0,
            root_nfqueue_lane_count: 0,
            root_nfqueue_ready_lane_mask: 0,
            root_nfqueue_generation: 0,
            root_nfqueue_verdict_attempts: 0,
            root_nfqueue_internal_settlements: 0,
            root_nfqueue_buffer_returns: 0,
            root_nfqueue_origin_local_completions: 0,
            root_nfqueue_origin_remote_completions: 0,
            root_nfqueue_lane0_verdict_attempts: 0,
            root_nfqueue_lane1_verdict_attempts: 0,
            root_nfqueue_input_packets: 0,
            root_nfqueue_output_packets: 0,
            root_nfqueue_ipv4_packets: 0,
            root_nfqueue_ipv6_packets: 0,
            root_nfqueue_tcp_packets: 0,
            root_nfqueue_udp_packets: 0,
            root_nfqueue_uid_known_packets: 0,
            root_nfqueue_uid_unknown_packets: 0,
            root_nfqueue_last_ip_family: 0,
            root_nfqueue_last_protocol: 0,
            root_nfqueue_last_hook: 0,
            root_nfqueue_last_uid_known: 0,
            root_nfqueue_last_uid: 0,
            root_nfqueue_last_queue_id: 0,
            root_nfqueue_last_packet_id: 0,
            root_nfqueue_verdict_succeeded: 0,
            root_nfqueue_verdict_failed_definite: 0,
            root_nfqueue_verdict_outcome_unknown: 0,
            root_nfqueue_ingress_identity_missing: 0,
            root_nfqueue_graph_submit_fail_opens: 0,
            root_nfqueue_non_owner_bypasses: 0,
            root_nfqueue_duplicate_completion_drops: 0,
            root_nfqueue_stale_completion_drops: 0,
            vpn_tun_fd_attached: 0,
            vpn_direct_udp4_socket_attached: 0,
            vpn_direct_udp4_protect_succeeded: 0,
            vpn_direct_udp4_bind_succeeded: 0,
            vpn_tun_ingress_packets: 0,
            vpn_tun_udp4_tun_origin_packets: 0,
            vpn_flow_stack_admissions: 0,
            vpn_direct_udp4_send_succeeded: 0,
            vpn_direct_udp4_transport_failed: 0,
            vpn_flow_stack_return_packets: 0,
            vpn_flow_stack_return_provenance_packets: 0,
            vpn_tun_write_completions: 0,
            vpn_infrastructure_faults: 0,
            vpn_duplicate_or_stale_drops: 0,
            product_graph_worker_count: 0,
            product_graph_hash_seed: 0,
            product_graph_handoff_credits: 0,
            product_graph_vpp_worker_count: 0,
            product_graph_vpp_main_core: 0,
            product_graph_vpp_worker0_thread_index: 0,
            product_graph_vpp_worker0_core: 0,
            product_graph_vpp_worker1_thread_index: 0,
            product_graph_vpp_worker1_core: 0,
            product_graph_enabled: 0,
            product_graph_accepting: 0,
            product_graph_worker_layout_ready: 0,
            product_graph_obligation_debt: 0,
            product_graph_buffer_debt: 0,
            product_graph_handoff_debt: 0,
            policy_requested_revision: 0,
            policy_active_revision: 0,
            policy_generation: 0,
            policy_snapshot_hash: 0,
            policy_worker0_revision: 0,
            policy_worker1_revision: 0,
            policy_snapshot_empty: false,
            policy_default_pass: false,
            policy_gate_claim_count: 0,
            policy_l4_rule_count: 0,
            policy_last_apply_status_code: 0,
            policy_mixed_revision: false,
            policy_artifact_match: false,
            policy_generation_match: false,
            policy_snapshot_identity: String::new(),
            policy_gate_subject_uid: 0,
            policy_gate_network_context: 0,
            policy_gate_blocked: false,
            policy_gate_reason_id: 0,
            policy_gate_rule_id: 0,
            policy_drop_records: 0,
            policy_last_drop_revision: 0,
            policy_last_drop_rule_id: 0,
            policy_last_drop_completion_attempts: 0,
            policy_last_drop_uid: 0,
            policy_last_drop_network_context: 0,
            policy_last_drop_reason_id: 0,
            policy_last_drop_verdict: 0,
            policy_last_drop_winner: 0,
            policy_last_drop_uid_known: false,
            policy_last_drop_device_direction: 0,
            policy_l4_active_revision: 0,
            policy_l4_rule_id: 0,
            policy_l4_match_records: 0,
            policy_l4_no_match_records: 0,
            policy_l4_last_match_revision: 0,
            policy_l4_last_match_rule_id: 0,
            policy_l4_subject_uid: 0,
            policy_l4_network_context: 0,
            policy_l4_ip_family: 0,
            policy_l4_ip_protocol: 0,
            policy_l4_direction: 0,
            policy_l4_action: 0,
            policy_l4_priority: 0,
            policy_l4_order: 0,
            policy_l4_reason_id: 0,
            policy_l4_last_match_uid: 0,
            policy_l4_last_match_network_context: 0,
            policy_l4_last_match_reason_id: 0,
            policy_l4_last_match_verdict: 0,
            policy_l4_last_match_winner: 0,
            policy_l4_last_match_uid_known: 0,
            policy_l4_last_match_device_direction: 0,
            policy_l4_last_match_action: 0,
            policy_l4_last_evaluation_result: 0,
            policy_l4_last_evaluation_verdict: 0,
            policy_l4_last_evaluation_device_direction: 0,
            policy_l4_view_active: 0,
            policy_l4_view_rule_count: 0,
            policy_l4_view_max_probes: 0,
            policy_l4_view_last_match_winner_rank: 0,
            policy_l4_view_last_match_probes: 0,
            policy_l4_view_last_match_candidate_count: 0,
            policy_l4_view_last_no_match_reason: 0,
            policy_l4_typed_match_policy_key: 0,
            policy_l4_typed_match_probe_key: 0,
            policy_l4_last_evaluation_probe_key: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{align_of, size_of};

    #[test]
    fn abi_layout_is_explicit_and_stable() {
        assert_eq!(size_of::<ProductBytes>(), 16);
        assert_eq!(align_of::<ProductBytes>(), 8);
        assert_eq!(size_of::<ProductPolicySnapshot>(), 264);
        assert_eq!(align_of::<ProductPolicySnapshot>(), 8);
        assert_eq!(size_of::<ProductPolicyRuleEntry>(), 120);
        assert_eq!(align_of::<ProductPolicyRuleEntry>(), 8);
        assert_eq!(size_of::<ProductPolicyBundle>(), 15_496);
        assert_eq!(align_of::<ProductPolicyBundle>(), 8);
        assert_eq!(size_of::<ProductStatus>(), 1304);
        assert_eq!(align_of::<ProductStatus>(), 8);
    }

    #[test]
    fn unknown_integer_tags_are_not_accepted_as_known_errors() {
        assert_eq!(
            ErrorCode::from_raw(0xfeed_beef),
            ErrorCode::Unknown(0xfeed_beef)
        );
        assert_eq!(ErrorCode::Unknown(0xfeed_beef).raw(), 0xfeed_beef);
        assert_eq!(ErrorCode::PolicyStoreFailed.raw(), 12);
        assert_eq!(ErrorCode::PolicyApplyFailed.raw(), 13);
        assert_eq!(ErrorCode::PolicyOutcomeUnknown.raw(), 14);
        assert_eq!(ErrorCode::PolicyMutationFenced.raw(), 15);
        assert_eq!(ErrorCode::from_raw(14), ErrorCode::PolicyOutcomeUnknown);
        assert_eq!(ErrorCode::from_raw(15), ErrorCode::PolicyMutationFenced);
    }

    #[test]
    fn status_identity_versions_are_checked_at_the_typed_boundary() {
        let mut status = Status::empty(9);
        status.abi_version = ABI_VERSION + 1;
        assert!(matches!(
            validate_status_identity(&status),
            Err(ProductError::AbiVersion {
                expected: ABI_VERSION,
                actual: 2
            })
        ));
        status.abi_version = ABI_VERSION;
        status.api_version = API_VERSION + 1;
        assert!(matches!(
            validate_status_identity(&status),
            Err(ProductError::ApiVersion {
                expected: API_VERSION,
                actual: 2
            })
        ));
    }
}
