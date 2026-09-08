#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::{BTreeSet, HashSet};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::Ipv4Addr;
use std::os::raw::c_uint;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::{Mutex, OnceLock};

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

impl ProductPolicyRuleEntry {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl ProductPolicyBundle {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
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

#[repr(C)]
struct ProductSession {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn sakamoto_product_abi_version() -> c_uint;
    fn sakamoto_product_api_version() -> c_uint;
    fn sakamoto_product_session_connect(
        api_socket: ProductBytes,
        expected_generation: u64,
        out_session: *mut *mut ProductSession,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    fn sakamoto_product_session_query(
        session: *mut ProductSession,
        expected_generation: u64,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    fn sakamoto_product_session_apply_policy(
        session: *mut ProductSession,
        expected_generation: u64,
        snapshot: *const ProductPolicySnapshot,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    fn sakamoto_product_session_apply_policy_bundle(
        session: *mut ProductSession,
        expected_generation: u64,
        bundle: *const ProductPolicyBundle,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    fn sakamoto_product_session_set_policy_mutation_fault(
        session: *mut ProductSession,
        expected_generation: u64,
        fault_mode: u32,
    ) -> c_uint;
    fn sakamoto_product_session_disconnect(session: *mut ProductSession) -> c_uint;
    fn sakamoto_product_session_destroy(session: *mut ProductSession) -> c_uint;
}

pub const ABI_VERSION: u32 = 1;
pub const API_VERSION: u32 = 1;

pub fn abi_version() -> u32 {
    unsafe { sakamoto_product_abi_version() }
}

pub fn api_version() -> u32 {
    unsafe { sakamoto_product_api_version() }
}

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
            policy_l4_last_evaluation_device_direction:
                value.policy_l4_last_evaluation_device_direction,
            policy_l4_view_active: value.policy_l4_view_active,
            policy_l4_view_rule_count: value.policy_l4_view_rule_count,
            policy_l4_view_max_probes: value.policy_l4_view_max_probes,
            policy_l4_view_last_match_winner_rank:
                value.policy_l4_view_last_match_winner_rank,
            policy_l4_view_last_match_probes: value.policy_l4_view_last_match_probes,
            policy_l4_view_last_match_candidate_count:
                value.policy_l4_view_last_match_candidate_count,
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

fn validate_policy_identity(bytes: &[u8]) -> Result<String, ProductError> {
    let end = bytes
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| ProductError::PolicyStore {
            detail: "policy bundle snapshot identity is not NUL terminated".to_owned(),
        })?;
    if bytes[end + 1..].iter().any(|value| *value != 0) {
        return Err(ProductError::PolicyStore {
            detail: "policy bundle snapshot identity has non-zero padding".to_owned(),
        });
    }
    let value = std::str::from_utf8(&bytes[..end]).map_err(|_| ProductError::PolicyStore {
        detail: "policy bundle snapshot identity is not UTF-8".to_owned(),
    })?;
    if value.is_empty() || value.contains(['\n', '\r', '=']) {
        return Err(ProductError::PolicyStore {
            detail: "policy bundle snapshot identity is empty or not a property value".to_owned(),
        });
    }
    Ok(value.to_owned())
}

fn validate_policy_rule_entry(
    entry: &ProductPolicyRuleEntry,
    expected_kind: u32,
    label: &str,
) -> Result<(), ProductError> {
    let invalid = || ProductError::PolicyStore {
        detail: format!("{label} contains invalid typed rule fields"),
    };
    if entry.subject_uid == u32::MAX
        || entry.network_context == 0
        || entry.rule_kind != expected_kind
        || entry.action != PRODUCT_POLICY_ACTION_PASS_NEXT
            && entry.action != PRODUCT_POLICY_ACTION_DROP
        || entry.enabled > 1
        || entry.rule_id == 0
        || entry.reason_id == 0
        || entry.reserved != 0
    {
        return Err(invalid());
    }
    if expected_kind == PRODUCT_POLICY_RULE_KIND_GATE {
        if entry.ip_family != 0
            || entry.ip_protocol != 0
            || entry.direction != 0
            || entry.source_prefix_len != 0
            || entry.destination_prefix_len != 0
            || entry.source_port_first != 0
            || entry.source_port_last != 0
            || entry.destination_port_first != 0
            || entry.destination_port_last != 0
            || entry.priority != 0
            || entry.order != 0
            || entry.source_address.iter().any(|value| *value != 0)
            || entry.destination_address.iter().any(|value| *value != 0)
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if entry.ip_family != PRODUCT_POLICY_IP_FAMILY_IPV4
        && entry.ip_family != PRODUCT_POLICY_IP_FAMILY_IPV6
    {
        return Err(invalid());
    }
    if entry.ip_family == PRODUCT_POLICY_IP_FAMILY_IPV4
        && (entry.source_address[4..].iter().any(|value| *value != 0)
            || entry.destination_address[4..].iter().any(|value| *value != 0))
    {
        return Err(invalid());
    }
    if entry.ip_protocol != PRODUCT_POLICY_IP_PROTOCOL_TCP
        && entry.ip_protocol != PRODUCT_POLICY_IP_PROTOCOL_UDP
    {
        return Err(invalid());
    }
    if entry.direction != PRODUCT_POLICY_DIRECTION_INPUT
        && entry.direction != PRODUCT_POLICY_DIRECTION_OUTPUT
    {
        return Err(invalid());
    }
    let max_prefix = if entry.ip_family == PRODUCT_POLICY_IP_FAMILY_IPV4 {
        32
    } else {
        128
    };
    if entry.source_prefix_len > max_prefix
        || entry.destination_prefix_len > max_prefix
        || entry.source_port_first > entry.source_port_last
        || entry.destination_port_first > entry.destination_port_last
        || entry.source_port_last > u16::MAX as u32
        || entry.destination_port_last > u16::MAX as u32
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_policy_bundle(bundle: &ProductPolicyBundle) -> Result<String, ProductError> {
    if bundle.abi_version != POLICY_BUNDLE_ABI_VERSION
        || bundle.struct_size as usize != std::mem::size_of::<ProductPolicyBundle>()
        || bundle.requested_revision == 0
        || bundle.snapshot_hash == 0
        || bundle.gate_entry_count as usize > POLICY_BUNDLE_MAX_GATE_ENTRIES
        || bundle.l4_rule_count as usize > POLICY_BUNDLE_MAX_L4_ENTRIES
        || (bundle.gate_entry_count as usize)
            .checked_add(bundle.l4_rule_count as usize)
            .is_none_or(|count| count > POLICY_BUNDLE_MAX_RULE_ENTRIES)
        || bundle.default_pass > 1
        || bundle.reserved != 0
    {
        return Err(ProductError::PolicyStore {
            detail: "policy bundle header or bounded counts are invalid".to_owned(),
        });
    }
    let identity = validate_policy_identity(&bundle.snapshot_identity)?;
    let mut rule_ids = HashSet::new();
    for (index, entry) in bundle.gate_entries.iter().enumerate() {
        if index < bundle.gate_entry_count as usize {
            validate_policy_rule_entry(
                entry,
                PRODUCT_POLICY_RULE_KIND_GATE,
                &format!("policy bundle Gate entry {index}"),
            )?;
            if !rule_ids.insert(entry.rule_id) {
                return Err(ProductError::PolicyStore {
                    detail: format!("policy bundle duplicate stable rule ID at Gate entry {index}"),
                });
            }
        } else if *entry != ProductPolicyRuleEntry::zeroed() {
            return Err(ProductError::PolicyStore {
                detail: format!("policy bundle unused Gate entry {index} is non-zero"),
            });
        }
    }
    for (index, entry) in bundle.l4_entries.iter().enumerate() {
        if index < bundle.l4_rule_count as usize {
            validate_policy_rule_entry(
                entry,
                PRODUCT_POLICY_RULE_KIND_L4,
                &format!("policy bundle L4 entry {index}"),
            )?;
            if !rule_ids.insert(entry.rule_id) {
                return Err(ProductError::PolicyStore {
                    detail: format!("policy bundle duplicate stable rule ID at L4 entry {index}"),
                });
            }
        } else if *entry != ProductPolicyRuleEntry::zeroed() {
            return Err(ProductError::PolicyStore {
                detail: format!("policy bundle unused L4 entry {index} is non-zero"),
            });
        }
    }
    Ok(identity)
}

#[derive(Debug, Eq, PartialEq)]
pub enum ProductError {
    AbiVersion { expected: u32, actual: u32 },
    ApiVersion { expected: u32, actual: u32 },
    Native { code: ErrorCode, status: Status },
    PathContainsNul,
    PolicyStore { detail: String },
    /// A prior mutation has no trustworthy terminal reply.  Only a fresh
    /// Product Core generation may clear this durable fence by readback.
    MutationFenceActive {
        generation: u64,
        requested_revision: u64,
    },
    GenerationActive { generation: u64 },
    GenerationRetired { generation: u64 },
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

#[derive(Default)]
struct GenerationLedger {
    active: Option<u64>,
    pending: Option<u64>,
    retired: BTreeSet<u64>,
}

impl GenerationLedger {
    fn ensure_available(&self, generation: u64) -> Result<(), ProductError> {
        if let Some(active) = self.active {
            return Err(ProductError::GenerationActive { generation: active });
        }
        if let Some(pending) = self.pending {
            return Err(ProductError::GenerationActive {
                generation: pending,
            });
        }
        if self.retired.contains(&generation) {
            return Err(ProductError::GenerationRetired { generation });
        }
        Ok(())
    }

    fn reserve(&mut self, generation: u64) -> Result<(), ProductError> {
        self.ensure_available(generation)?;
        self.pending = Some(generation);
        Ok(())
    }

    fn commit(&mut self, generation: u64) {
        debug_assert_eq!(self.pending, Some(generation));
        self.pending = None;
        self.active = Some(generation);
    }

    fn release(&mut self, generation: u64) {
        if self.pending == Some(generation) {
            self.pending = None;
        }
    }

    fn retire(&mut self, generation: u64) {
        if self.active == Some(generation) {
            self.active = None;
        }
        self.retired.insert(generation);
    }
}

static GENERATION_LEDGER: OnceLock<Mutex<GenerationLedger>> = OnceLock::new();

fn generation_ledger() -> &'static Mutex<GenerationLedger> {
    GENERATION_LEDGER.get_or_init(|| Mutex::new(GenerationLedger::default()))
}

fn lock_generation_ledger() -> std::sync::MutexGuard<'static, GenerationLedger> {
    generation_ledger()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

const EMPTY_POLICY_STORE_DIR: &str = "product-policy";
const POLICY_BUNDLE_STORE_FILE: &str = "policy-bundle.properties";
const POLICY_BUNDLE_STORE_TEMP_FILE: &str = "policy-bundle.properties.tmp";
const POLICY_BUNDLE_STORE_SCHEMA: &str = "sakamoto-policy-bundle/v1";
const EMPTY_POLICY_STORE_FILE: &str = "empty-intent.properties";
const EMPTY_POLICY_STORE_TEMP_FILE: &str = "empty-intent.properties.tmp";
const EMPTY_POLICY_STORE_SCHEMA: &str = "sakamoto-empty-policy-intent/v1";
const NETWORK_GATE_POLICY_STORE_FILE: &str = "network-gate-intent.properties";
const NETWORK_GATE_POLICY_STORE_TEMP_FILE: &str = "network-gate-intent.properties.tmp";
const NETWORK_GATE_POLICY_STORE_SCHEMA: &str = "sakamoto-network-gate-policy-intent/v1";
const L4_POLICY_STORE_FILE: &str = "l4-intent.properties";
const L4_POLICY_STORE_TEMP_FILE: &str = "l4-intent.properties.tmp";
const L4_POLICY_STORE_SCHEMA: &str = "sakamoto-l4-policy-intent/v1";
const POLICY_MUTATION_FENCE_FILE: &str = "policy-mutation-fence.properties";
const POLICY_MUTATION_FENCE_TEMP_FILE: &str = "policy-mutation-fence.properties.tmp";
const POLICY_MUTATION_CANDIDATE_FILE: &str = "policy-mutation-candidate.properties";
const POLICY_MUTATION_FENCE_SCHEMA: &str = "sakamoto-policy-mutation-fence/v2";
const POLICY_MUTATION_FENCE_STATE_UNKNOWN: &str = "unknown";
const EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const PRODUCT_L4_IP_FAMILY_IPV4: u32 = 4;
const PRODUCT_L4_IP_PROTOCOL_TCP: u32 = 6;
const PRODUCT_L4_DIRECTION_INPUT: u32 = 1;
const PRODUCT_L4_DIRECTION_OUTPUT: u32 = 3;
const PRODUCT_L4_ACTION_PASS_NEXT: u32 = 1;
const PRODUCT_L4_ACTION_DROP: u32 = 2;
const PRODUCT_POLICY_RULE_KIND_GATE: u32 = 1;
const PRODUCT_POLICY_RULE_KIND_L4: u32 = 2;
const PRODUCT_POLICY_IP_FAMILY_IPV4: u32 = 4;
const PRODUCT_POLICY_IP_FAMILY_IPV6: u32 = 6;
const PRODUCT_POLICY_IP_PROTOCOL_TCP: u32 = 6;
const PRODUCT_POLICY_IP_PROTOCOL_UDP: u32 = 17;
const PRODUCT_POLICY_DIRECTION_INPUT: u32 = 1;
const PRODUCT_POLICY_DIRECTION_OUTPUT: u32 = 3;
const PRODUCT_POLICY_ACTION_PASS_NEXT: u32 = 1;
const PRODUCT_POLICY_ACTION_DROP: u32 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
struct EmptyPolicySnapshot {
    revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
}

impl EmptyPolicySnapshot {
    fn new(revision: u64) -> Result<Self, ProductError> {
        if revision == 0 {
            return Err(ProductError::PolicyStore {
                detail: "empty policy revision must be positive".to_owned(),
            });
        }
        let snapshot_identity = format!("empty-policy/v1/revision-{revision}");
        let material = format!(
            "schema=empty-policy/v1\nrevision={revision}\ndefault_pass=true\ngate_claim_count=0\nl4_rule_count=0\n"
        );
        let snapshot_hash = fnv1a64(material.as_bytes());
        Ok(Self {
            revision,
            snapshot_hash,
            snapshot_identity,
        })
    }

    fn to_ffi(&self) -> ProductPolicySnapshot {
        let mut snapshot = ProductPolicySnapshot::zeroed();
        snapshot.schema_version = EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION;
        snapshot.requested_revision = self.revision;
        snapshot.snapshot_hash = self.snapshot_hash;
        snapshot.snapshot_empty = 1;
        snapshot.default_pass = 1;
        snapshot.gate_claim_count = 0;
        snapshot.l4_rule_count = 0;
        snapshot.gate_subject_uid = 0;
        snapshot.gate_network_context = 0;
        snapshot.gate_blocked = 0;
        snapshot.gate_reason_id = 0;
        snapshot.gate_rule_id = 0;
        copy_status_text(&mut snapshot.snapshot_identity, &self.snapshot_identity);
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NetworkGatePolicySnapshot {
    revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
    subject_uid: u32,
    network_context: u32,
    blocked: bool,
    rule_id: u64,
    reason_id: u32,
}

impl NetworkGatePolicySnapshot {
    fn new(
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Self, ProductError> {
        if revision == 0
            || subject_uid == u32::MAX
            || network_context == 0
            || rule_id == 0
            || reason_id == 0
        {
            return Err(ProductError::PolicyStore {
                detail: "network gate policy snapshot fields are invalid".to_owned(),
            });
        }
        let state = if blocked { "blocked" } else { "open" };
        let snapshot_identity = format!(
            "network-gate/v1/revision-{revision}/uid-{subject_uid}/context-{network_context}/{state}"
        );
        let material = format!(
            "schema=network-gate/v1\nrevision={revision}\ndefault_pass=true\ngate_claim_count={}\nl4_rule_count=0\nsubject_uid={subject_uid}\nnetwork_context={network_context}\nblocked={blocked}\nrule_id={rule_id}\nreason_id={reason_id}\n",
            if blocked { 1 } else { 0 }
        );
        let snapshot_hash = fnv1a64(material.as_bytes());
        Ok(Self {
            revision,
            snapshot_hash,
            snapshot_identity,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        })
    }

    fn to_ffi(&self) -> ProductPolicySnapshot {
        let mut snapshot = ProductPolicySnapshot::zeroed();
        snapshot.schema_version = EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION;
        snapshot.requested_revision = self.revision;
        snapshot.snapshot_hash = self.snapshot_hash;
        snapshot.snapshot_empty = 0;
        snapshot.default_pass = 1;
        snapshot.gate_claim_count = if self.blocked { 1 } else { 0 };
        snapshot.l4_rule_count = 0;
        snapshot.gate_subject_uid = self.subject_uid;
        snapshot.gate_network_context = self.network_context;
        snapshot.gate_blocked = u32::from(self.blocked);
        snapshot.gate_reason_id = self.reason_id;
        snapshot.gate_rule_id = self.rule_id;
        copy_status_text(&mut snapshot.snapshot_identity, &self.snapshot_identity);
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Ipv4Cidr {
    text: String,
    address: [u8; 16],
    prefix_len: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StatelessL4PolicySnapshot {
    revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
    subject_uid: u32,
    network_context: u32,
    ip_family: u32,
    ip_protocol: u32,
    direction: u32,
    action: u32,
    source: Ipv4Cidr,
    destination: Ipv4Cidr,
    source_port_first: u32,
    source_port_last: u32,
    destination_port_first: u32,
    destination_port_last: u32,
    priority: u32,
    order: u32,
    rule_id: u64,
    reason_id: u32,
}

impl StatelessL4PolicySnapshot {
    #[allow(clippy::too_many_arguments)]
    fn new(
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Self, ProductError> {
        if revision == 0
            || subject_uid == u32::MAX
            || network_context == 0
            || ip_family != PRODUCT_L4_IP_FAMILY_IPV4
            || ip_protocol != PRODUCT_L4_IP_PROTOCOL_TCP
            || !matches!(
                direction,
                PRODUCT_L4_DIRECTION_INPUT | PRODUCT_L4_DIRECTION_OUTPUT
            )
            || !matches!(action, PRODUCT_L4_ACTION_PASS_NEXT | PRODUCT_L4_ACTION_DROP)
            || source_port_first > source_port_last
            || destination_port_first > destination_port_last
            || source_port_last > u16::MAX as u32
            || destination_port_last > u16::MAX as u32
            || rule_id == 0
            || reason_id == 0
        {
            return Err(ProductError::PolicyStore {
                detail: "stateless L4 policy snapshot fields are invalid".to_owned(),
            });
        }
        let source = parse_ipv4_cidr(source_cidr, "stateless L4 source CIDR")?;
        let destination = parse_ipv4_cidr(destination_cidr, "stateless L4 destination CIDR")?;
        let action_name = match action {
            PRODUCT_L4_ACTION_DROP => "drop",
            _ => "allow",
        };
        let snapshot_identity = format!(
            "l4tcp4/1/revision-{revision}/uid-{subject_uid}/context-{network_context}/rule-{rule_id}/{action_name}"
        );
        let material = format!(
            "schema=l4tcp4/1\nrevision={revision}\ndefault_pass=true\ngate_claim_count=0\nl4_rule_count=1\nsubject_uid={subject_uid}\nnetwork_context={network_context}\nip_family={ip_family}\nip_protocol={ip_protocol}\ndirection={direction}\naction={action}\nsource_cidr={}\ndestination_cidr={}\nsource_port_first={source_port_first}\nsource_port_last={source_port_last}\ndestination_port_first={destination_port_first}\ndestination_port_last={destination_port_last}\npriority={priority}\norder={order}\nrule_id={rule_id}\nreason_id={reason_id}\n",
            source.text, destination.text
        );
        let snapshot_hash = fnv1a64(material.as_bytes());
        Ok(Self {
            revision,
            snapshot_hash,
            snapshot_identity,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source,
            destination,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        })
    }

    fn to_ffi(&self) -> ProductPolicySnapshot {
        let mut snapshot = ProductPolicySnapshot::zeroed();
        snapshot.schema_version = EMPTY_POLICY_SNAPSHOT_SCHEMA_VERSION;
        snapshot.requested_revision = self.revision;
        snapshot.snapshot_hash = self.snapshot_hash;
        snapshot.snapshot_empty = 0;
        snapshot.default_pass = 1;
        snapshot.gate_claim_count = 0;
        snapshot.l4_rule_count = 1;
        snapshot.gate_subject_uid = 0;
        snapshot.gate_network_context = 0;
        snapshot.gate_blocked = 0;
        snapshot.gate_reason_id = 0;
        snapshot.gate_rule_id = 0;
        snapshot.l4_subject_uid = self.subject_uid;
        snapshot.l4_network_context = self.network_context;
        snapshot.l4_ip_family = self.ip_family;
        snapshot.l4_ip_protocol = self.ip_protocol;
        snapshot.l4_direction = self.direction;
        snapshot.l4_action = self.action;
        snapshot.l4_source_prefix_len = self.source.prefix_len;
        snapshot.l4_destination_prefix_len = self.destination.prefix_len;
        snapshot.l4_source_port_first = self.source_port_first;
        snapshot.l4_source_port_last = self.source_port_last;
        snapshot.l4_destination_port_first = self.destination_port_first;
        snapshot.l4_destination_port_last = self.destination_port_last;
        snapshot.l4_priority = self.priority;
        snapshot.l4_order = self.order;
        snapshot.l4_reason_id = self.reason_id;
        snapshot.l4_rule_id = self.rule_id;
        snapshot.l4_source_address = self.source.address;
        snapshot.l4_destination_address = self.destination.address;
        copy_status_text(&mut snapshot.snapshot_identity, &self.snapshot_identity);
        snapshot
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RuntimePolicySnapshot {
    Empty(EmptyPolicySnapshot),
    NetworkGate(NetworkGatePolicySnapshot),
    StatelessL4(StatelessL4PolicySnapshot),
    Bundle(ProductPolicyBundle),
}

impl RuntimePolicySnapshot {
    fn revision(&self) -> u64 {
        match self {
            Self::Empty(snapshot) => snapshot.revision,
            Self::NetworkGate(snapshot) => snapshot.revision,
            Self::StatelessL4(snapshot) => snapshot.revision,
            Self::Bundle(snapshot) => snapshot.requested_revision,
        }
    }

    fn to_ffi(&self) -> ProductPolicySnapshot {
        match self {
            Self::Empty(snapshot) => snapshot.to_ffi(),
            Self::NetworkGate(snapshot) => snapshot.to_ffi(),
            Self::StatelessL4(snapshot) => snapshot.to_ffi(),
            Self::Bundle(_) => {
                panic!("complete policy bundle must use the bundle native apply path")
            }
        }
    }

    fn bundle(&self) -> Option<&ProductPolicyBundle> {
        match self {
            Self::Bundle(bundle) => Some(bundle),
            _ => None,
        }
    }

    fn target_file(&self) -> &'static str {
        match self {
            Self::Empty(_) => EMPTY_POLICY_STORE_FILE,
            Self::NetworkGate(_) => NETWORK_GATE_POLICY_STORE_FILE,
            Self::StatelessL4(_) => L4_POLICY_STORE_FILE,
            Self::Bundle(_) => POLICY_BUNDLE_STORE_FILE,
        }
    }
}

/*
 * A mutation fence is the durable hand-off between a VAPI request that may
 * have reached VPP and the next Product Core generation.  It is deliberately
 * a small properties record rather than an ABI extension: ProductStatus keeps
 * its fixed layout, while the revision/hash/identity tuple remains available
 * across a process death.  The fence is written only for an ambiguous,
 * post-submit policy outcome and is cleared only after fresh-generation
 * readback (never by a delayed reply on the fenced generation).
 */
#[derive(Clone, Debug, Eq, PartialEq)]
struct PolicyMutationFence {
    generation: u64,
    predecessor_generation: u64,
    predecessor_revision: u64,
    predecessor_hash: u64,
    requested_revision: u64,
    snapshot_hash: u64,
    snapshot_identity: String,
    artifact_id: String,
    api_identity: String,
    operation_id: String,
    target_file: String,
}

fn valid_mutation_fence_identity(value: &str) -> bool {
    !value.is_empty() && value.len() < 96 && !value.contains(['\n', '\r', '='])
}

impl PolicyMutationFence {
    fn for_snapshot(
        generation: u64,
        predecessor: &Status,
        snapshot: &ProductPolicySnapshot,
        target_file: &str,
    ) -> Result<Self, ProductError> {
        let snapshot_identity = bounded_string(&snapshot.snapshot_identity);
        let artifact_id = predecessor.artifact_id.clone();
        let api_identity = predecessor.api_identity.clone();
        if generation == 0
            || snapshot.requested_revision == 0
            || snapshot.snapshot_hash == 0
            || !valid_mutation_fence_identity(&snapshot_identity)
            || !valid_mutation_fence_identity(&artifact_id)
            || !valid_mutation_fence_identity(&api_identity)
            || !matches!(
                target_file,
                POLICY_BUNDLE_STORE_FILE
                    | EMPTY_POLICY_STORE_FILE
                    | NETWORK_GATE_POLICY_STORE_FILE
                    | L4_POLICY_STORE_FILE
            )
        {
            return Err(ProductError::PolicyStore {
                detail: "unknown policy outcome has no complete mutation identity".to_owned(),
            });
        }
        let operation_id = format!(
            "policy-snapshot/v1/revision-{}/hash-{}",
            snapshot.requested_revision, snapshot.snapshot_hash
        );
        Ok(Self {
            generation,
            predecessor_generation: predecessor.generation,
            predecessor_revision: predecessor.policy_active_revision,
            predecessor_hash: predecessor.policy_snapshot_hash,
            requested_revision: snapshot.requested_revision,
            snapshot_hash: snapshot.snapshot_hash,
            snapshot_identity,
            artifact_id,
            api_identity,
            operation_id,
            target_file: target_file.to_owned(),
        })
    }

    fn for_bundle(
        generation: u64,
        predecessor: &Status,
        bundle: &ProductPolicyBundle,
    ) -> Result<Self, ProductError> {
        let snapshot_identity = bounded_string(&bundle.snapshot_identity);
        let artifact_id = predecessor.artifact_id.clone();
        let api_identity = predecessor.api_identity.clone();
        if generation == 0
            || bundle.requested_revision == 0
            || bundle.snapshot_hash == 0
            || !valid_mutation_fence_identity(&snapshot_identity)
            || !valid_mutation_fence_identity(&artifact_id)
            || !valid_mutation_fence_identity(&api_identity)
        {
            return Err(ProductError::PolicyStore {
                detail: "unknown policy outcome has no complete mutation identity".to_owned(),
            });
        }
        let operation_id = format!(
            "policy-bundle/v1/revision-{}/hash-{}",
            bundle.requested_revision, bundle.snapshot_hash
        );
        Ok(Self {
            generation,
            predecessor_generation: predecessor.generation,
            predecessor_revision: predecessor.policy_active_revision,
            predecessor_hash: predecessor.policy_snapshot_hash,
            requested_revision: bundle.requested_revision,
            snapshot_hash: bundle.snapshot_hash,
            snapshot_identity,
            artifact_id,
            api_identity,
            operation_id,
            target_file: POLICY_BUNDLE_STORE_FILE.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProductPolicyStore {
    files_dir: PathBuf,
}

impl ProductPolicyStore {
    fn new(files_dir: &Path) -> Self {
        Self {
            files_dir: files_dir.to_path_buf(),
        }
    }

    fn current_mutation_fence(&self) -> Result<Option<PolicyMutationFence>, ProductError> {
        let path = self.mutation_fence_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let metadata = fs::metadata(&path).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation fence metadata could not be read: {error}"),
        })?;
        if metadata.len() > 4096 {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence exceeds its bounded record size".to_owned(),
            });
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("policy mutation fence could not be read: {error}"),
            })?;
        if property_value(&text, "schema").unwrap_or_default() != POLICY_MUTATION_FENCE_SCHEMA
            || property_value(&text, "state").unwrap_or_default()
                != POLICY_MUTATION_FENCE_STATE_UNKNOWN
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence schema or state is unsupported".to_owned(),
            });
        }
        let target_file = required_string_property(&text, "targetFile", "policy mutation fence")?;
        if target_file != POLICY_BUNDLE_STORE_FILE
            && target_file != EMPTY_POLICY_STORE_FILE
            && target_file != NETWORK_GATE_POLICY_STORE_FILE
            && target_file != L4_POLICY_STORE_FILE
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence target is unsupported".to_owned(),
            });
        }
        let candidate_file = required_string_property(
            &text,
            "candidateFile",
            "policy mutation fence",
        )?;
        if candidate_file != POLICY_MUTATION_CANDIDATE_FILE {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence candidate is unsupported".to_owned(),
            });
        }
        let snapshot_identity = required_string_property(
            &text,
            "snapshotIdentity",
            "policy mutation fence",
        )?;
        if snapshot_identity.len() >= 96
            || snapshot_identity.contains(['\n', '\r', '='])
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence identity is invalid".to_owned(),
            });
        }
        let artifact_id = required_string_property(&text, "artifactId", "policy mutation fence")?;
        let api_identity = required_string_property(&text, "apiIdentity", "policy mutation fence")?;
        if !valid_mutation_fence_identity(&artifact_id)
            || !valid_mutation_fence_identity(&api_identity)
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence artifact/API identity is invalid".to_owned(),
            });
        }
        let operation_id = required_string_property(&text, "operationId", "policy mutation fence")?;
        if operation_id.len() > 255 || operation_id.contains(['\n', '\r', '=']) {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence operation identity is invalid".to_owned(),
            });
        }
        Ok(Some(PolicyMutationFence {
            generation: required_u64_property(&text, "generation", "policy mutation fence")?,
            predecessor_generation: optional_u64_property(
                &text,
                "predecessorGeneration",
                "policy mutation fence",
            )?,
            predecessor_revision: optional_u64_property(
                &text,
                "predecessorRevision",
                "policy mutation fence",
            )?,
            predecessor_hash: optional_u64_property(
                &text,
                "predecessorHash",
                "policy mutation fence",
            )?,
            requested_revision: required_u64_property(
                &text,
                "requestedRevision",
                "policy mutation fence",
            )?,
            snapshot_hash: required_u64_property(
                &text,
                "snapshotHash",
                "policy mutation fence",
            )?,
            snapshot_identity,
            artifact_id,
            api_identity,
            operation_id,
            target_file,
        }))
    }

    fn has_unresolved_mutation_artifact(&self) -> bool {
        [
            self.mutation_candidate_state_file(),
            self.mutation_fence_temp_state_file(),
            self.state_dir().join(POLICY_BUNDLE_STORE_TEMP_FILE),
            self.state_dir().join(EMPTY_POLICY_STORE_TEMP_FILE),
            self.state_dir().join(NETWORK_GATE_POLICY_STORE_TEMP_FILE),
            self.state_dir().join(L4_POLICY_STORE_TEMP_FILE),
        ]
        .iter()
        .any(|path| path.is_file())
    }

    fn write_mutation_fence(&self, fence: &PolicyMutationFence) -> Result<(), ProductError> {
        if fence.generation == 0
            || fence.requested_revision == 0
            || fence.snapshot_hash == 0
            || !valid_mutation_fence_identity(&fence.snapshot_identity)
            || !valid_mutation_fence_identity(&fence.artifact_id)
            || !valid_mutation_fence_identity(&fence.api_identity)
            || fence.operation_id.is_empty()
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence identity is incomplete".to_owned(),
            });
        }
        if fence.operation_id.len() > 255
            || fence.operation_id.contains(['\n', '\r', '='])
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence identity is not bounded".to_owned(),
            });
        }
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation fence directory could not be created: {error}"),
        })?;
        let temporary = directory.join(POLICY_MUTATION_FENCE_TEMP_FILE);
        let target = self.mutation_fence_state_file();
        let text = format!(
            "schema={POLICY_MUTATION_FENCE_SCHEMA}\nstate={POLICY_MUTATION_FENCE_STATE_UNKNOWN}\ngeneration={}\npredecessorGeneration={}\npredecessorRevision={}\npredecessorHash={}\nrequestedRevision={}\nsnapshotHash={}\nsnapshotIdentity={}\nartifactId={}\napiIdentity={}\noperationId={}\ntargetFile={}\ncandidateFile={}\n",
            fence.generation,
            fence.predecessor_generation,
            fence.predecessor_revision,
            fence.predecessor_hash,
            fence.requested_revision,
            fence.snapshot_hash,
            fence.snapshot_identity,
            fence.artifact_id,
            fence.api_identity,
            fence.operation_id,
            fence.target_file,
            POLICY_MUTATION_CANDIDATE_FILE,
        );
        if text.len() > 4096 {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation fence record is too large".to_owned(),
            });
        }
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("policy mutation fence temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("policy mutation fence could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation fence could not be published: {error}"),
        })
    }

    fn clear_mutation_fence(&self) -> Result<(), ProductError> {
        match fs::remove_file(self.mutation_fence_state_file()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("policy mutation fence could not be cleared: {error}"),
            }),
        }
    }

    fn quarantine_policy_bundle(
        &self,
        temporary: &Path,
    ) -> Result<(), ProductError> {
        fs::rename(temporary, self.mutation_candidate_state_file()).map_err(|error| {
            ProductError::PolicyStore {
                detail: format!("unknown policy bundle could not be retained: {error}"),
            }
        })
    }

    fn quarantine_persisted_intent(&self, target_file: &str) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        if !target.is_file() {
            return Err(ProductError::PolicyStore {
                detail: "persisted policy intent disappeared before reconcile".to_owned(),
            });
        }
        let candidate = self.mutation_candidate_state_file();
        if candidate.exists() {
            return Err(ProductError::PolicyStore {
                detail: "orphaned policy mutation candidate blocks reconcile".to_owned(),
            });
        }
        fs::rename(&target, &candidate).map_err(|error| ProductError::PolicyStore {
            detail: format!("persisted policy intent could not be retained: {error}"),
        })
    }

    fn restore_mutation_candidate(&self, target_file: &str) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        if !self.mutation_candidate_state_file().is_file() {
            return Ok(());
        }
        fs::rename(self.mutation_candidate_state_file(), &target).map_err(|error| {
            ProductError::PolicyStore {
                detail: format!("persisted policy intent could not be restored: {error}"),
            }
        })
    }

    fn validate_mutation_candidate(
        &self,
        fence: &PolicyMutationFence,
    ) -> Result<(), ProductError> {
        let path = self.mutation_candidate_state_file();
        if !path.is_file() {
            return Err(ProductError::PolicyStore {
                detail: "unknown policy candidate is missing during readback".to_owned(),
            });
        }
        let metadata = fs::metadata(&path).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy mutation candidate metadata could not be read: {error}"),
        })?;
        if metadata.len() > 64 * 1024 {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation candidate exceeds its bounded size".to_owned(),
            });
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("policy mutation candidate could not be read: {error}"),
            })?;
        let revision =
            required_u64_property(&text, "revision", "policy mutation candidate")?;
        let snapshot_hash =
            required_u64_property(&text, "snapshotHash", "policy mutation candidate")?;
        let snapshot_identity = required_string_property(
            &text,
            "snapshotIdentity",
            "policy mutation candidate",
        )?;
        if revision != fence.requested_revision
            || snapshot_hash != fence.snapshot_hash
            || snapshot_identity != fence.snapshot_identity
        {
            return Err(ProductError::PolicyStore {
                detail: "policy mutation candidate identity does not match its fence".to_owned(),
            });
        }
        Ok(())
    }

    fn promote_mutation_candidate(&self, target_file: &str) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        fs::rename(self.mutation_candidate_state_file(), &target).map_err(|error| {
            ProductError::PolicyStore {
                detail: format!("reconciled policy candidate could not be published: {error}"),
            }
        })?;
        self.remove_other_policy_intents(target_file)
    }

    fn discard_mutation_candidate(&self) {
        let _ = fs::remove_file(self.mutation_candidate_state_file());
    }

    fn current_snapshot(&self) -> Result<Option<RuntimePolicySnapshot>, ProductError> {
        /* A bundle is the only authoritative v1 successor.  Compatibility
         * intents are consulted only when no bundle exists, never merged with
         * a bundle or with one another. */
        if let Some(bundle) = self.current_policy_bundle()? {
            return Ok(Some(RuntimePolicySnapshot::Bundle(bundle)));
        }
        let mut selected = None;
        if let Some(snapshot) = self.current_empty_snapshot()? {
            selected = Some(RuntimePolicySnapshot::Empty(snapshot));
        }
        if let Some(snapshot) = self.current_network_gate_snapshot()? {
            let candidate = RuntimePolicySnapshot::NetworkGate(snapshot);
            if selected
                .as_ref()
                .map(|current| candidate.revision() >= current.revision())
                .unwrap_or(true)
            {
                selected = Some(candidate);
            }
        }
        if let Some(snapshot) = self.current_l4_snapshot()? {
            let candidate = RuntimePolicySnapshot::StatelessL4(snapshot);
            if selected
                .as_ref()
                .map(|current| candidate.revision() >= current.revision())
                .unwrap_or(true)
            {
                selected = Some(candidate);
            }
        }
        Ok(selected)
    }

    fn current_policy_bundle(&self) -> Result<Option<ProductPolicyBundle>, ProductError> {
        let path = self.policy_bundle_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("policy bundle could not be read: {error}"),
            })?;
        if property_value(&text, "schema").unwrap_or_default() != POLICY_BUNDLE_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "policy bundle schema is unsupported".to_owned(),
            });
        }
        let mut bundle = ProductPolicyBundle::zeroed();
        bundle.abi_version = required_u32_property(&text, "abiVersion", "policy bundle")?;
        bundle.struct_size = required_u32_property(&text, "structSize", "policy bundle")?;
        bundle.requested_revision =
            required_u64_property(&text, "revision", "policy bundle")?;
        bundle.snapshot_hash =
            required_u64_property(&text, "snapshotHash", "policy bundle")?;
        bundle.gate_entry_count =
            required_u32_property(&text, "gateEntryCount", "policy bundle")?;
        bundle.l4_rule_count = required_u32_property(&text, "l4RuleCount", "policy bundle")?;
        bundle.default_pass = required_u32_property(&text, "defaultPass", "policy bundle")?;
        bundle.snapshot_identity = fixed_text_property(&text, "snapshotIdentity", "policy bundle")?;
        for index in 0..(bundle.gate_entry_count as usize).min(POLICY_BUNDLE_MAX_GATE_ENTRIES) {
            bundle.gate_entries[index] = parse_policy_rule_entry(
                &text,
                "gate",
                index,
                PRODUCT_POLICY_RULE_KIND_GATE,
            )?;
        }
        for index in 0..(bundle.l4_rule_count as usize).min(POLICY_BUNDLE_MAX_L4_ENTRIES) {
            bundle.l4_entries[index] = parse_policy_rule_entry(
                &text,
                "l4",
                index,
                PRODUCT_POLICY_RULE_KIND_L4,
            )?;
        }
        validate_policy_bundle(&bundle)?;
        Ok(Some(bundle))
    }

    fn current_empty_snapshot(&self) -> Result<Option<EmptyPolicySnapshot>, ProductError> {
        let path = self.state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("empty policy intent could not be read: {error}"),
            })?;
        let schema = property_value(&text, "schema").unwrap_or_default();
        if schema != EMPTY_POLICY_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "empty policy intent schema is unsupported".to_owned(),
            });
        }
        let revision = property_value(&text, "revision")
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|revision| *revision != 0)
            .ok_or_else(|| ProductError::PolicyStore {
                detail: "empty policy intent revision is invalid".to_owned(),
            })?;
        Ok(Some(EmptyPolicySnapshot::new(revision)?))
    }

    fn current_network_gate_snapshot(
        &self,
    ) -> Result<Option<NetworkGatePolicySnapshot>, ProductError> {
        let path = self.network_gate_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("network gate policy intent could not be read: {error}"),
            })?;
        let schema = property_value(&text, "schema").unwrap_or_default();
        if schema != NETWORK_GATE_POLICY_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "network gate policy intent schema is unsupported".to_owned(),
            });
        }
        let revision = required_u64_property(&text, "revision", "network gate policy")?;
        let subject_uid = required_u32_property(&text, "subjectUid", "network gate policy")?;
        let network_context =
            required_u32_property(&text, "networkContext", "network gate policy")?;
        let blocked = required_bool_property(&text, "blocked", "network gate policy")?;
        let rule_id = required_u64_property(&text, "ruleId", "network gate policy")?;
        let reason_id = required_u32_property(&text, "reasonId", "network gate policy")?;
        Ok(Some(NetworkGatePolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?))
    }

    fn current_l4_snapshot(&self) -> Result<Option<StatelessL4PolicySnapshot>, ProductError> {
        let path = self.l4_state_file();
        if !path.is_file() {
            return Ok(None);
        }
        let mut text = String::new();
        File::open(&path)
            .and_then(|mut file| file.read_to_string(&mut text))
            .map_err(|error| ProductError::PolicyStore {
                detail: format!("stateless L4 policy intent could not be read: {error}"),
            })?;
        let schema = property_value(&text, "schema").unwrap_or_default();
        if schema != L4_POLICY_STORE_SCHEMA {
            return Err(ProductError::PolicyStore {
                detail: "stateless L4 policy intent schema is unsupported".to_owned(),
            });
        }
        let revision = required_u64_property(&text, "revision", "stateless L4 policy")?;
        let subject_uid = required_u32_property(&text, "subjectUid", "stateless L4 policy")?;
        let network_context =
            required_u32_property(&text, "networkContext", "stateless L4 policy")?;
        let ip_family = required_u32_property(&text, "ipFamily", "stateless L4 policy")?;
        let ip_protocol = required_u32_property(&text, "ipProtocol", "stateless L4 policy")?;
        let direction = required_u32_property(&text, "direction", "stateless L4 policy")?;
        let action = required_u32_property(&text, "action", "stateless L4 policy")?;
        let source_cidr = property_value(&text, "sourceCidr").unwrap_or_else(|| "0.0.0.0/0".into());
        let destination_cidr =
            property_value(&text, "destinationCidr").unwrap_or_else(|| "0.0.0.0/0".into());
        let source_port_first =
            required_u32_property(&text, "sourcePortFirst", "stateless L4 policy")?;
        let source_port_last =
            required_u32_property(&text, "sourcePortLast", "stateless L4 policy")?;
        let destination_port_first =
            required_u32_property(&text, "destinationPortFirst", "stateless L4 policy")?;
        let destination_port_last =
            required_u32_property(&text, "destinationPortLast", "stateless L4 policy")?;
        let priority = required_u32_property(&text, "priority", "stateless L4 policy")?;
        let order = required_u32_property(&text, "order", "stateless L4 policy")?;
        let rule_id = required_u64_property(&text, "ruleId", "stateless L4 policy")?;
        let reason_id = required_u32_property(&text, "reasonId", "stateless L4 policy")?;
        Ok(Some(StatelessL4PolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            &source_cidr,
            &destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )?))
    }

    fn stage_empty_snapshot(
        &self,
        snapshot: &EmptyPolicySnapshot,
    ) -> Result<PathBuf, ProductError> {
        let temporary = self.state_dir().join(EMPTY_POLICY_STORE_TEMP_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=true\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=0\n",
            EMPTY_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash
        );
        self.stage_intent_text(temporary, text, "empty policy intent")
    }

    fn stage_network_gate_snapshot(
        &self,
        snapshot: &NetworkGatePolicySnapshot,
    ) -> Result<PathBuf, ProductError> {
        let temporary = self
            .state_dir()
            .join(NETWORK_GATE_POLICY_STORE_TEMP_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount={}\nl4RuleCount=0\nsubjectUid={}\nnetworkContext={}\nblocked={}\nruleId={}\nreasonId={}\n",
            NETWORK_GATE_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            if snapshot.blocked { 1 } else { 0 },
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.blocked,
            snapshot.rule_id,
            snapshot.reason_id
        );
        self.stage_intent_text(temporary, text, "network gate policy intent")
    }

    fn stage_l4_snapshot(
        &self,
        snapshot: &StatelessL4PolicySnapshot,
    ) -> Result<PathBuf, ProductError> {
        let temporary = self.state_dir().join(L4_POLICY_STORE_TEMP_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=1\nsubjectUid={}\nnetworkContext={}\nipFamily={}\nipProtocol={}\ndirection={}\naction={}\nsourceCidr={}\ndestinationCidr={}\nsourcePrefixLen={}\ndestinationPrefixLen={}\nsourcePortFirst={}\nsourcePortLast={}\ndestinationPortFirst={}\ndestinationPortLast={}\npriority={}\norder={}\nruleId={}\nreasonId={}\n",
            L4_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.ip_family,
            snapshot.ip_protocol,
            snapshot.direction,
            snapshot.action,
            snapshot.source.text,
            snapshot.destination.text,
            snapshot.source.prefix_len,
            snapshot.destination.prefix_len,
            snapshot.source_port_first,
            snapshot.source_port_last,
            snapshot.destination_port_first,
            snapshot.destination_port_last,
            snapshot.priority,
            snapshot.order,
            snapshot.rule_id,
            snapshot.reason_id
        );
        self.stage_intent_text(temporary, text, "stateless L4 policy intent")
    }

    fn stage_intent_text(
        &self,
        temporary: PathBuf,
        text: String,
        label: &str,
    ) -> Result<PathBuf, ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("{label} directory could not be created: {error}"),
        })?;
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("{label} temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("{label} could not be staged: {error}"),
                })?;
        }
        Ok(temporary)
    }

    fn commit_staged_intent(
        &self,
        temporary: &Path,
        target_file: &str,
    ) -> Result<(), ProductError> {
        let target = self.state_dir().join(target_file);
        fs::rename(temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy intent could not be published: {error}"),
        })?;
        self.remove_other_policy_intents(target_file)
    }

    fn remove_other_policy_intents(&self, target_file: &str) -> Result<(), ProductError> {
        if target_file != EMPTY_POLICY_STORE_FILE {
            self.remove_empty_intent()?;
        }
        if target_file != NETWORK_GATE_POLICY_STORE_FILE {
            self.remove_network_gate_intent()?;
        }
        if target_file != L4_POLICY_STORE_FILE {
            self.remove_l4_intent()?;
        }
        if target_file != POLICY_BUNDLE_STORE_FILE {
            self.remove_policy_bundle_intent()?;
        }
        Ok(())
    }

    fn stage_policy_bundle(&self, bundle: &ProductPolicyBundle) -> Result<PathBuf, ProductError> {
        validate_policy_bundle(bundle)?;
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy bundle directory could not be created: {error}"),
        })?;
        let temporary = directory.join(POLICY_BUNDLE_STORE_TEMP_FILE);
        let text = serialize_policy_bundle(bundle);
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("policy bundle temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("policy bundle could not be staged: {error}"),
                })?;
        }
        Ok(temporary)
    }

    fn commit_policy_bundle(&self, temporary: &Path) -> Result<(), ProductError> {
        let target = self.policy_bundle_state_file();
        fs::rename(temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("policy bundle could not be published: {error}"),
        })?;
        Ok(())
    }

    fn discard_staged_policy_bundle(&self, temporary: &Path) {
        let _ = fs::remove_file(temporary);
    }

    #[allow(dead_code)]
    fn publish_policy_bundle(&self, bundle: &ProductPolicyBundle) -> Result<(), ProductError> {
        let temporary = self.stage_policy_bundle(bundle)?;
        if let Err(error) = self.commit_policy_bundle(&temporary) {
            self.discard_staged_policy_bundle(&temporary);
            return Err(error);
        }
        Ok(())
    }

    fn publish_next_empty_snapshot(&self) -> Result<EmptyPolicySnapshot, ProductError> {
        self.publish_empty_snapshot_revision(self.next_revision()?)
    }

    fn publish_empty_snapshot_revision(
        &self,
        revision: u64,
    ) -> Result<EmptyPolicySnapshot, ProductError> {
        let snapshot = EmptyPolicySnapshot::new(revision)?;
        self.write_intent(&snapshot)?;
        self.remove_network_gate_intent()?;
        self.remove_l4_intent()?;
        self.remove_policy_bundle_intent()?;
        Ok(snapshot)
    }

    fn publish_next_network_gate_snapshot(
        &self,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<NetworkGatePolicySnapshot, ProductError> {
        self.publish_network_gate_snapshot_revision(
            self.next_revision()?,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )
    }

    fn publish_network_gate_snapshot_revision(
        &self,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<NetworkGatePolicySnapshot, ProductError> {
        let snapshot = NetworkGatePolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?;
        self.write_network_gate_intent(&snapshot)?;
        self.remove_empty_intent()?;
        self.remove_l4_intent()?;
        self.remove_policy_bundle_intent()?;
        Ok(snapshot)
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_next_l4_snapshot(
        &self,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<StatelessL4PolicySnapshot, ProductError> {
        self.publish_l4_snapshot_revision(
            self.next_revision()?,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source_cidr,
            destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_l4_snapshot_revision(
        &self,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<StatelessL4PolicySnapshot, ProductError> {
        let snapshot = StatelessL4PolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source_cidr,
            destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )?;
        self.write_l4_intent(&snapshot)?;
        self.remove_empty_intent()?;
        self.remove_network_gate_intent()?;
        self.remove_policy_bundle_intent()?;
        Ok(snapshot)
    }

    fn next_revision(&self) -> Result<u64, ProductError> {
        let mut revision = 0_u64;
        if let Some(snapshot) = self.current_empty_snapshot()? {
            revision = revision.max(snapshot.revision);
        }
        if let Some(snapshot) = self.current_network_gate_snapshot()? {
            revision = revision.max(snapshot.revision);
        }
        if let Some(snapshot) = self.current_l4_snapshot()? {
            revision = revision.max(snapshot.revision);
        }
        if let Some(bundle) = self.current_policy_bundle()? {
            revision = revision.max(bundle.requested_revision);
        }
        revision
            .checked_add(1)
            .ok_or_else(|| ProductError::PolicyStore {
                detail: "policy revision overflow".to_owned(),
            })
    }

    fn write_intent(&self, snapshot: &EmptyPolicySnapshot) -> Result<(), ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("empty policy intent directory could not be created: {error}"),
        })?;
        let temporary = directory.join(EMPTY_POLICY_STORE_TEMP_FILE);
        let target = directory.join(EMPTY_POLICY_STORE_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=true\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=0\n",
            EMPTY_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash
        );
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!("empty policy intent temp file could not be opened: {error}"),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("empty policy intent could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("empty policy intent could not be published: {error}"),
        })
    }

    fn write_network_gate_intent(
        &self,
        snapshot: &NetworkGatePolicySnapshot,
    ) -> Result<(), ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("network gate policy intent directory could not be created: {error}"),
        })?;
        let temporary = directory.join(NETWORK_GATE_POLICY_STORE_TEMP_FILE);
        let target = directory.join(NETWORK_GATE_POLICY_STORE_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount={}\nl4RuleCount=0\nsubjectUid={}\nnetworkContext={}\nblocked={}\nruleId={}\nreasonId={}\n",
            NETWORK_GATE_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            if snapshot.blocked { 1 } else { 0 },
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.blocked,
            snapshot.rule_id,
            snapshot.reason_id
        );
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!(
                    "network gate policy intent temp file could not be opened: {error}"
                ),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("network gate policy intent could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("network gate policy intent could not be published: {error}"),
        })
    }

    fn write_l4_intent(&self, snapshot: &StatelessL4PolicySnapshot) -> Result<(), ProductError> {
        let directory = self.state_dir();
        fs::create_dir_all(&directory).map_err(|error| ProductError::PolicyStore {
            detail: format!("stateless L4 policy intent directory could not be created: {error}"),
        })?;
        let temporary = directory.join(L4_POLICY_STORE_TEMP_FILE);
        let target = directory.join(L4_POLICY_STORE_FILE);
        let text = format!(
            "schema={}\nrevision={}\nsnapshotIdentity={}\nsnapshotHash={}\nempty=false\ndefaultPass=true\ngateClaimCount=0\nl4RuleCount=1\nsubjectUid={}\nnetworkContext={}\nipFamily={}\nipProtocol={}\ndirection={}\naction={}\nsourceCidr={}\ndestinationCidr={}\nsourcePrefixLen={}\ndestinationPrefixLen={}\nsourcePortFirst={}\nsourcePortLast={}\ndestinationPortFirst={}\ndestinationPortLast={}\npriority={}\norder={}\nruleId={}\nreasonId={}\n",
            L4_POLICY_STORE_SCHEMA,
            snapshot.revision,
            snapshot.snapshot_identity,
            snapshot.snapshot_hash,
            snapshot.subject_uid,
            snapshot.network_context,
            snapshot.ip_family,
            snapshot.ip_protocol,
            snapshot.direction,
            snapshot.action,
            snapshot.source.text,
            snapshot.destination.text,
            snapshot.source.prefix_len,
            snapshot.destination.prefix_len,
            snapshot.source_port_first,
            snapshot.source_port_last,
            snapshot.destination_port_first,
            snapshot.destination_port_last,
            snapshot.priority,
            snapshot.order,
            snapshot.rule_id,
            snapshot.reason_id
        );
        {
            let mut file = File::create(&temporary).map_err(|error| ProductError::PolicyStore {
                detail: format!(
                    "stateless L4 policy intent temp file could not be opened: {error}"
                ),
            })?;
            file.write_all(text.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|error| ProductError::PolicyStore {
                    detail: format!("stateless L4 policy intent could not be written: {error}"),
                })?;
        }
        fs::rename(&temporary, &target).map_err(|error| ProductError::PolicyStore {
            detail: format!("stateless L4 policy intent could not be published: {error}"),
        })
    }

    fn remove_network_gate_intent(&self) -> Result<(), ProductError> {
        let path = self.network_gate_state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale network gate policy intent could not be removed: {error}"),
            }),
        }
    }

    fn remove_empty_intent(&self) -> Result<(), ProductError> {
        let path = self.state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale empty policy intent could not be removed: {error}"),
            }),
        }
    }

    fn remove_l4_intent(&self) -> Result<(), ProductError> {
        let path = self.l4_state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale stateless L4 policy intent could not be removed: {error}"),
            }),
        }
    }

    fn remove_policy_bundle_intent(&self) -> Result<(), ProductError> {
        let path = self.policy_bundle_state_file();
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(ProductError::PolicyStore {
                detail: format!("stale policy bundle could not be removed: {error}"),
            }),
        }
    }

    fn state_dir(&self) -> PathBuf {
        self.files_dir.join(EMPTY_POLICY_STORE_DIR)
    }

    fn state_file(&self) -> PathBuf {
        self.state_dir().join(EMPTY_POLICY_STORE_FILE)
    }

    fn network_gate_state_file(&self) -> PathBuf {
        self.state_dir().join(NETWORK_GATE_POLICY_STORE_FILE)
    }

    fn l4_state_file(&self) -> PathBuf {
        self.state_dir().join(L4_POLICY_STORE_FILE)
    }

    fn policy_bundle_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_BUNDLE_STORE_FILE)
    }

    fn mutation_fence_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_MUTATION_FENCE_FILE)
    }

    fn mutation_fence_temp_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_MUTATION_FENCE_TEMP_FILE)
    }

    fn mutation_candidate_state_file(&self) -> PathBuf {
        self.state_dir().join(POLICY_MUTATION_CANDIDATE_FILE)
    }
}

fn parse_ipv4_cidr(value: &str, label: &str) -> Result<Ipv4Cidr, ProductError> {
    let trimmed = value.trim();
    let normalized = if trimmed.is_empty() {
        "0.0.0.0/0"
    } else {
        trimmed
    };
    let (address_text, prefix_text) =
        normalized
            .split_once('/')
            .ok_or_else(|| ProductError::PolicyStore {
                detail: format!("{label} must use IPv4 CIDR notation"),
            })?;
    let address = address_text
        .parse::<Ipv4Addr>()
        .map_err(|_| ProductError::PolicyStore {
            detail: format!("{label} address is invalid"),
        })?;
    let prefix_len = prefix_text
        .parse::<u32>()
        .ok()
        .filter(|value| *value <= 32)
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} prefix length is invalid"),
        })?;
    let mut bytes = [0_u8; 16];
    bytes[12..16].copy_from_slice(&address.octets());
    Ok(Ipv4Cidr {
        text: format!("{address}/{prefix_len}"),
        address: bytes,
        prefix_len,
    })
}

fn property_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name == key {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn required_string_property(text: &str, key: &str, label: &str) -> Result<String, ProductError> {
    property_value(text, key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn fixed_text_property(text: &str, key: &str, label: &str) -> Result<[u8; 96], ProductError> {
    let value = required_string_property(text, key, label)?;
    if value.contains(['\n', '\r', '=']) || value.len() >= 96 {
        return Err(ProductError::PolicyStore {
            detail: format!("{label} {key} exceeds its fixed text field"),
        });
    }
    let mut output = [0_u8; 96];
    copy_status_text(&mut output, &value);
    Ok(output)
}

fn parse_hex_address(value: &str, label: &str) -> Result<[u8; 16], ProductError> {
    if value.len() != 32 {
        return Err(ProductError::PolicyStore {
            detail: format!("{label} must contain exactly 16 encoded bytes"),
        });
    }
    let bytes = value.as_bytes();
    let mut output = [0_u8; 16];
    for index in 0..16 {
        let text = std::str::from_utf8(&bytes[index * 2..index * 2 + 2]).map_err(|_| {
            ProductError::PolicyStore {
                detail: format!("{label} is not hexadecimal"),
            }
        })?;
        output[index] = u8::from_str_radix(text, 16).map_err(|_| ProductError::PolicyStore {
            detail: format!("{label} is not hexadecimal"),
        })?;
    }
    Ok(output)
}

fn hex_address(value: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
    for byte in value {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn parse_policy_rule_entry(
    text: &str,
    family: &str,
    index: usize,
    expected_kind: u32,
) -> Result<ProductPolicyRuleEntry, ProductError> {
    let prefix = format!("{family}.{index}");
    let label = format!("policy bundle {family} entry {index}");
    let mut entry = ProductPolicyRuleEntry::zeroed();
    entry.subject_uid = required_u32_property(
        text,
        &format!("{prefix}.subjectUid"),
        &label,
    )?;
    entry.network_context = required_u32_property(
        text,
        &format!("{prefix}.networkContext"),
        &label,
    )?;
    entry.ifindex = required_u32_property(text, &format!("{prefix}.ifindex"), &label)?;
    entry.rule_kind = required_u32_property(text, &format!("{prefix}.ruleKind"), &label)?;
    entry.ip_family = required_u32_property(text, &format!("{prefix}.ipFamily"), &label)?;
    entry.ip_protocol = required_u32_property(text, &format!("{prefix}.ipProtocol"), &label)?;
    entry.direction = required_u32_property(text, &format!("{prefix}.direction"), &label)?;
    entry.action = required_u32_property(text, &format!("{prefix}.action"), &label)?;
    entry.enabled = required_u32_property(text, &format!("{prefix}.enabled"), &label)?;
    entry.source_prefix_len =
        required_u32_property(text, &format!("{prefix}.sourcePrefixLen"), &label)?;
    entry.destination_prefix_len =
        required_u32_property(text, &format!("{prefix}.destinationPrefixLen"), &label)?;
    entry.source_port_first =
        required_u32_property(text, &format!("{prefix}.sourcePortFirst"), &label)?;
    entry.source_port_last =
        required_u32_property(text, &format!("{prefix}.sourcePortLast"), &label)?;
    entry.destination_port_first =
        required_u32_property(text, &format!("{prefix}.destinationPortFirst"), &label)?;
    entry.destination_port_last =
        required_u32_property(text, &format!("{prefix}.destinationPortLast"), &label)?;
    entry.priority = required_u32_property(text, &format!("{prefix}.priority"), &label)?;
    entry.order = required_u32_property(text, &format!("{prefix}.order"), &label)?;
    entry.reason_id = required_u32_property(text, &format!("{prefix}.reasonId"), &label)?;
    entry.reserved = required_u32_property(text, &format!("{prefix}.reserved"), &label)?;
    entry.rule_id = required_u64_property(text, &format!("{prefix}.ruleId"), &label)?;
    entry.source_address = parse_hex_address(
        &required_string_property(text, &format!("{prefix}.sourceAddress"), &label)?,
        &format!("{label} sourceAddress"),
    )?;
    entry.destination_address = parse_hex_address(
        &required_string_property(text, &format!("{prefix}.destinationAddress"), &label)?,
        &format!("{label} destinationAddress"),
    )?;
    validate_policy_rule_entry(&entry, expected_kind, &label)?;
    Ok(entry)
}

fn serialize_policy_rule_entry(
    text: &mut String,
    family: &str,
    index: usize,
    entry: &ProductPolicyRuleEntry,
) {
    let prefix = format!("{family}.{index}");
    text.push_str(&format!(
        "{prefix}.subjectUid={}\n{prefix}.networkContext={}\n{prefix}.ifindex={}\n{prefix}.ruleKind={}\n{prefix}.ipFamily={}\n{prefix}.ipProtocol={}\n{prefix}.direction={}\n{prefix}.action={}\n{prefix}.enabled={}\n{prefix}.sourcePrefixLen={}\n{prefix}.destinationPrefixLen={}\n{prefix}.sourcePortFirst={}\n{prefix}.sourcePortLast={}\n{prefix}.destinationPortFirst={}\n{prefix}.destinationPortLast={}\n{prefix}.priority={}\n{prefix}.order={}\n{prefix}.reasonId={}\n{prefix}.reserved={}\n{prefix}.ruleId={}\n{prefix}.sourceAddress={}\n{prefix}.destinationAddress={}\n",
        entry.subject_uid,
        entry.network_context,
        entry.ifindex,
        entry.rule_kind,
        entry.ip_family,
        entry.ip_protocol,
        entry.direction,
        entry.action,
        entry.enabled,
        entry.source_prefix_len,
        entry.destination_prefix_len,
        entry.source_port_first,
        entry.source_port_last,
        entry.destination_port_first,
        entry.destination_port_last,
        entry.priority,
        entry.order,
        entry.reason_id,
        entry.reserved,
        entry.rule_id,
        hex_address(&entry.source_address),
        hex_address(&entry.destination_address),
    ));
}

fn serialize_policy_bundle(bundle: &ProductPolicyBundle) -> String {
    let mut text = String::with_capacity(18_000);
    text.push_str(&format!(
        "schema={POLICY_BUNDLE_STORE_SCHEMA}\nabiVersion={}\nstructSize={}\nrevision={}\nsnapshotHash={}\ngateEntryCount={}\nl4RuleCount={}\ndefaultPass={}\nsnapshotIdentity={}\n",
        bundle.abi_version,
        bundle.struct_size,
        bundle.requested_revision,
        bundle.snapshot_hash,
        bundle.gate_entry_count,
        bundle.l4_rule_count,
        bundle.default_pass,
        bounded_string(&bundle.snapshot_identity),
    ));
    for index in 0..bundle.gate_entry_count as usize {
        serialize_policy_rule_entry(&mut text, "gate", index, &bundle.gate_entries[index]);
    }
    for index in 0..bundle.l4_rule_count as usize {
        serialize_policy_rule_entry(&mut text, "l4", index, &bundle.l4_entries[index]);
    }
    text
}

fn required_u64_property(text: &str, key: &str, label: &str) -> Result<u64, ProductError> {
    property_value(text, key)
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value != 0)
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn optional_u64_property(text: &str, key: &str, label: &str) -> Result<u64, ProductError> {
    property_value(text, key)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn required_u32_property(text: &str, key: &str, label: &str) -> Result<u32, ProductError> {
    property_value(text, key)
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        })
}

fn required_bool_property(text: &str, key: &str, label: &str) -> Result<bool, ProductError> {
    match property_value(text, key).as_deref() {
        Some("true") | Some("1") => Ok(true),
        Some("false") | Some("0") => Ok(false),
        _ => Err(ProductError::PolicyStore {
            detail: format!("{label} {key} is invalid"),
        }),
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

fn active_policy_matches_fence(
    status: &Status,
    fence: &PolicyMutationFence,
    expected_generation: u64,
) -> bool {
    expected_generation != 0
        && status.code == ErrorCode::Ok
        && status.generation == expected_generation
        && status.policy_requested_revision == fence.requested_revision
        && status.policy_active_revision == fence.requested_revision
        && status.policy_generation == expected_generation
        && status.policy_generation_match
        && status.policy_last_apply_status_code == 0
        && !status.policy_mixed_revision
        && status.policy_artifact_match
        && status.policy_snapshot_hash == fence.snapshot_hash
        && status.policy_snapshot_identity == fence.snapshot_identity
        && status.artifact_id == fence.artifact_id
        && status.api_identity == fence.api_identity
}

fn is_policy_outcome_unknown(error: &ProductError) -> bool {
    matches!(
        error,
        ProductError::Native {
            code: ErrorCode::PolicyOutcomeUnknown,
            ..
        }
    )
}

#[derive(Debug)]
pub struct ProductCore {
    session: Option<NonNull<ProductSession>>,
    generation: u64,
    _not_send_or_sync: PhantomData<*mut ()>,
}

/// Opaque owner exposed by the small C facade below.
///
/// The pointer is deliberately the only thing crossing the native boundary;
/// ProductCore and its generated-VAPI session remain Rust-owned.
#[repr(C)]
pub struct ProductCoreHandle {
    core: ProductCore,
}

impl ProductCore {
    fn ensure_mutation_unfenced(&self, store: &ProductPolicyStore) -> Result<(), ProductError> {
        if let Some(fence) = store.current_mutation_fence()? {
            return Err(ProductError::MutationFenceActive {
                generation: fence.generation,
                requested_revision: fence.requested_revision,
            });
        }
        if store.has_unresolved_mutation_artifact() {
            return Err(ProductError::PolicyStore {
                detail: "orphaned policy mutation artifact requires reconciliation".to_owned(),
            });
        }
        Ok(())
    }

    fn reconcile_unknown_mutation(
        &mut self,
        store: &ProductPolicyStore,
        fence: &PolicyMutationFence,
    ) -> Result<Status, ProductError> {
        /* A reply from the fenced generation cannot clear this record.  A
         * fresh handle first reads active state, then adopts or discards the
         * retained candidate without issuing another VAPI mutation. */
        if fence.generation == self.generation {
            return Err(ProductError::MutationFenceActive {
                generation: fence.generation,
                requested_revision: fence.requested_revision,
            });
        }
        let mut status = self.query()?;
        let active_matches = active_policy_matches_fence(&status, fence, self.generation);
        if active_matches {
            store.validate_mutation_candidate(fence)?;
            store.promote_mutation_candidate(&fence.target_file)?;
        } else {
            /* Do not replay a target that the fresh generation did not report
             * as active.  The previous durable intent remains untouched. */
            store.discard_mutation_candidate();
        }
        store.clear_mutation_fence()?;
        status.error_detail = if active_matches {
            format!(
                "unknown policy mutation reconciled by active revision readback ({})",
                fence.operation_id
            )
        } else {
            format!(
                "unknown policy mutation discarded after active revision readback ({})",
                fence.operation_id
            )
        };
        Ok(status)
    }

    pub fn connect(path: &Path, generation: u64) -> Result<(Self, Status), ProductError> {
        let actual_abi = abi_version();
        if actual_abi != ABI_VERSION {
            return Err(ProductError::AbiVersion {
                expected: ABI_VERSION,
                actual: actual_abi,
            });
        }
        let actual_api = api_version();
        if actual_api != API_VERSION {
            return Err(ProductError::ApiVersion {
                expected: API_VERSION,
                actual: actual_api,
            });
        }
        {
            let mut ledger = lock_generation_ledger();
            ledger.reserve(generation)?;
        }
        let path = match path.to_str() {
            Some(path) => path,
            None => {
                lock_generation_ledger().release(generation);
                return Err(ProductError::PathContainsNul);
            }
        };
        let path = match CString::new(path) {
            Ok(path) => path,
            Err(_) => {
                lock_generation_ledger().release(generation);
                return Err(ProductError::PathContainsNul);
            }
        };
        let bytes = ProductBytes {
            data: path.as_ptr().cast(),
            length: path.as_bytes().len().try_into().unwrap_or(u32::MAX),
        };
        let mut session = std::ptr::null_mut();
        let mut status = ProductStatus::zeroed();
        let code = unsafe {
            sakamoto_product_session_connect(bytes, generation, &mut session, &mut status)
        };
        let status = Status::from_ffi(status);
        if code != 0 {
            lock_generation_ledger().release(generation);
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        let session = match NonNull::new(session) {
            Some(session) => session,
            None => {
                lock_generation_ledger().release(generation);
                return Err(ProductError::Native {
                    code: ErrorCode::AllocationFailed,
                    status: status.clone(),
                });
            }
        };
        if let Err(error) = validate_status_identity(&status) {
            unsafe {
                let _ = sakamoto_product_session_disconnect(session.as_ptr());
                let _ = sakamoto_product_session_destroy(session.as_ptr());
            }
            lock_generation_ledger().release(generation);
            return Err(error);
        }
        let mut ledger = lock_generation_ledger();
        if ledger.pending != Some(generation) {
            unsafe {
                let _ = sakamoto_product_session_disconnect(session.as_ptr());
                let _ = sakamoto_product_session_destroy(session.as_ptr());
            }
            return Err(ProductError::GenerationActive { generation });
        }
        ledger.commit(generation);
        drop(ledger);
        Ok((
            Self {
                session: Some(session),
                generation,
                _not_send_or_sync: PhantomData,
            },
            status,
        ))
    }

    pub fn query(&mut self) -> Result<Status, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut raw = ProductStatus::zeroed();
        let code =
            unsafe { sakamoto_product_session_query(session.as_ptr(), self.generation, &mut raw) };
        let status = Status::from_ffi(raw);
        if code != 0 {
            if matches!(ErrorCode::from_raw(code), ErrorCode::StaleHandle) {
                self.retire_generation();
            }
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        validate_status_identity(&status)?;
        Ok(status)
    }

    /// Arm one debug-only, one-shot fault at the generated typed bundle
    /// boundary.  The VAPI session owns the arm so the same mutex serializes
    /// arming and consuming it with the actual bundle request.
    pub fn set_policy_mutation_fault(&mut self, fault_mode: u32) -> Result<(), ProductError> {
        if fault_mode != POLICY_MUTATION_FAULT_NONE
            && fault_mode != POLICY_MUTATION_FAULT_OMIT_CALLBACK
            && fault_mode != POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT
        {
            return Err(ProductError::Native {
                code: ErrorCode::InvalidArgument,
                status: Status {
                    code: ErrorCode::InvalidArgument,
                    error_detail: "unsupported debug policy mutation fault mode".to_owned(),
                    ..Status::empty(self.generation)
                },
            });
        }
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let code = unsafe {
            sakamoto_product_session_set_policy_mutation_fault(
                session.as_ptr(),
                self.generation,
                fault_mode,
            )
        };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status {
                    code: ErrorCode::from_raw(code),
                    error_detail: "debug policy mutation fault could not be armed".to_owned(),
                    ..Status::empty(self.generation)
                },
            });
        }
        Ok(())
    }

    pub fn apply_empty_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = EmptyPolicySnapshot::new(store.next_revision()?)?;
        let temporary = store.stage_empty_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            EMPTY_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    pub fn apply_empty_policy_revision(
        &mut self,
        files_dir: &Path,
        revision: u64,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = EmptyPolicySnapshot::new(revision)?;
        let temporary = store.stage_empty_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            EMPTY_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    pub fn apply_network_gate_policy(
        &mut self,
        files_dir: &Path,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = NetworkGatePolicySnapshot::new(
            store.next_revision()?,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?;
        let temporary = store.stage_network_gate_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            NETWORK_GATE_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    pub fn apply_network_gate_policy_revision(
        &mut self,
        files_dir: &Path,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        blocked: bool,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = NetworkGatePolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            blocked,
            rule_id,
            reason_id,
        )?;
        let temporary = store.stage_network_gate_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            NETWORK_GATE_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_l4_policy(
        &mut self,
        files_dir: &Path,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = StatelessL4PolicySnapshot::new(
            store.next_revision()?,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source_cidr,
            destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )?;
        let temporary = store.stage_l4_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            L4_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_l4_policy_revision(
        &mut self,
        files_dir: &Path,
        revision: u64,
        subject_uid: u32,
        network_context: u32,
        ip_family: u32,
        ip_protocol: u32,
        direction: u32,
        action: u32,
        source_cidr: &str,
        destination_cidr: &str,
        source_port_first: u32,
        source_port_last: u32,
        destination_port_first: u32,
        destination_port_last: u32,
        priority: u32,
        order: u32,
        rule_id: u64,
        reason_id: u32,
    ) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let snapshot = StatelessL4PolicySnapshot::new(
            revision,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            source_cidr,
            destination_cidr,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        )?;
        let temporary = store.stage_l4_snapshot(&snapshot)?;
        self.apply_staged_policy_snapshot(
            &store,
            &temporary,
            L4_POLICY_STORE_FILE,
            snapshot.to_ffi(),
            &predecessor,
        )
    }

    fn apply_staged_policy_snapshot(
        &mut self,
        store: &ProductPolicyStore,
        temporary: &Path,
        target_file: &str,
        snapshot: ProductPolicySnapshot,
        predecessor: &Status,
    ) -> Result<Status, ProductError> {
        match self.apply_policy_snapshot(snapshot) {
            Ok(status) => {
                if let Err(error) = store.commit_staged_intent(temporary, target_file) {
                    store.discard_staged_policy_bundle(temporary);
                    return Err(error);
                }
                Ok(status)
            }
            Err(error) if is_policy_outcome_unknown(&error) => {
                let fence =
                    PolicyMutationFence::for_snapshot(self.generation, predecessor, &snapshot, target_file)?;
                if let Err(store_error) = store.quarantine_policy_bundle(temporary) {
                    /* Keep the staged file when quarantine fails.  The
                     * unresolved-artifact gate prevents a later replay. */
                    return Err(store_error);
                }
                if let Err(store_error) = store.write_mutation_fence(&fence) {
                    /* Keep the candidate as an orphaned safety marker.  A
                     * failed fence write must not make a later caller replay
                     * an operation whose VPP outcome is still unknown. */
                    return Err(store_error);
                }
                Err(error)
            }
            Err(error) => {
                store.discard_staged_policy_bundle(temporary);
                Err(error)
            }
        }
    }

    /// Validate and publish one complete Gate + L4 successor.  The bundle is
    /// staged as one file, sent through one native apply call, and committed
    /// only after native success; a rejected native apply removes only the
    /// temporary file and leaves the previous bundle untouched.
    pub fn apply_policy_bundle(
        &mut self,
        files_dir: &Path,
        bundle: &ProductPolicyBundle,
    ) -> Result<Status, ProductError> {
        validate_policy_bundle(bundle)?;
        let store = ProductPolicyStore::new(files_dir);
        self.ensure_mutation_unfenced(&store)?;
        let predecessor = self.query()?;
        let temporary = store.stage_policy_bundle(bundle)?;
        match self.apply_policy_bundle_native(bundle) {
            Ok(status) => {
                if let Err(error) = store.commit_policy_bundle(&temporary) {
                    store.discard_staged_policy_bundle(&temporary);
                    return Err(error);
                }
                Ok(status)
            }
            Err(error) if is_policy_outcome_unknown(&error) =>
            {
                let fence = match PolicyMutationFence::for_bundle(
                    self.generation,
                    &predecessor,
                    bundle,
                ) {
                    Ok(fence) => fence,
                    Err(fence_error) => {
                        store.discard_staged_policy_bundle(&temporary);
                        return Err(fence_error);
                    }
                };
                if let Err(store_error) = store.quarantine_policy_bundle(&temporary) {
                    /* Keep the staged file when quarantine fails.  The
                     * unresolved-artifact gate prevents a later replay. */
                    return Err(store_error);
                }
                if let Err(store_error) = store.write_mutation_fence(&fence) {
                    /* Keep the candidate as an orphaned safety marker.  A
                     * failed fence write must not make a later caller replay
                     * an operation whose VPP outcome is still unknown. */
                    return Err(store_error);
                }
                Err(error)
            }
            Err(error) => {
                store.discard_staged_policy_bundle(&temporary);
                Err(error)
            }
        }
    }

    pub fn reconcile_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        let store = ProductPolicyStore::new(files_dir);
        if let Some(fence) = store.current_mutation_fence()? {
            return self.reconcile_unknown_mutation(&store, &fence);
        }
        if store.has_unresolved_mutation_artifact() {
            return Err(ProductError::PolicyStore {
                detail: "orphaned policy mutation artifact requires a durable fence".to_owned(),
            });
        }
        match store.current_snapshot()? {
            Some(snapshot) => self.reconcile_persisted_snapshot(&store, &snapshot),
            None => self.query(),
        }
    }

    pub fn reconcile_empty_policy(&mut self, files_dir: &Path) -> Result<Status, ProductError> {
        self.reconcile_policy(files_dir)
    }

    fn reconcile_persisted_snapshot(
        &mut self,
        store: &ProductPolicyStore,
        snapshot: &RuntimePolicySnapshot,
    ) -> Result<Status, ProductError> {
        let predecessor = self.query()?;
        let target_file = snapshot.target_file();
        store.quarantine_persisted_intent(target_file)?;
        let result = match snapshot.bundle() {
            Some(bundle) => self.apply_policy_bundle_native(bundle),
            None => self.apply_policy_snapshot(snapshot.to_ffi()),
        };
        match result {
            Ok(status) => {
                if let Err(error) = store.promote_mutation_candidate(target_file) {
                    let _ = store.restore_mutation_candidate(target_file);
                    return Err(error);
                }
                Ok(status)
            }
            Err(error) if is_policy_outcome_unknown(&error) => {
                let fence = match snapshot.bundle() {
                    Some(bundle) => {
                        PolicyMutationFence::for_bundle(self.generation, &predecessor, bundle)
                    }
                    None => PolicyMutationFence::for_snapshot(
                        self.generation,
                        &predecessor,
                        &snapshot.to_ffi(),
                        target_file,
                    ),
                };
                let fence = match fence {
                    Ok(fence) => fence,
                    Err(fence_error) => {
                        /* The native outcome is already unknown.  Keep the
                         * candidate as a safety marker if identity
                         * construction fails, so a later reconcile cannot
                         * replay it without an explicit repair. */
                        return Err(fence_error);
                    }
                };
                if let Err(store_error) = store.write_mutation_fence(&fence) {
                    /* Keep the candidate when the durable fence cannot be
                     * written; orphan detection blocks automatic replay. */
                    return Err(store_error);
                }
                Err(error)
            }
            Err(error) => {
                if let Err(store_error) = store.restore_mutation_candidate(target_file) {
                    return Err(store_error);
                }
                Err(error)
            }
        }
    }

    fn apply_policy_snapshot(
        &mut self,
        snapshot: ProductPolicySnapshot,
    ) -> Result<Status, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut raw = ProductStatus::zeroed();
        let code = unsafe {
            sakamoto_product_session_apply_policy(
                session.as_ptr(),
                self.generation,
                &snapshot,
                &mut raw,
            )
        };
        let status = Status::from_ffi(raw);
        if code != 0 {
            if matches!(ErrorCode::from_raw(code), ErrorCode::StaleHandle) {
                self.retire_generation();
            }
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        validate_status_identity(&status)?;
        Ok(status)
    }

    fn apply_policy_bundle_native(
        &mut self,
        bundle: &ProductPolicyBundle,
    ) -> Result<Status, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut raw = ProductStatus::zeroed();
        let code = unsafe {
            sakamoto_product_session_apply_policy_bundle(
                session.as_ptr(),
                self.generation,
                bundle,
                &mut raw,
            )
        };
        let status = Status::from_ffi(raw);
        if code != 0 {
            if matches!(ErrorCode::from_raw(code), ErrorCode::StaleHandle) {
                self.retire_generation();
            }
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status,
            });
        }
        validate_status_identity(&status)?;
        Ok(status)
    }

    pub fn disconnect(&mut self) -> Result<(), ProductError> {
        let Some(session) = self.session else {
            return Ok(());
        };
        let code = unsafe { sakamoto_product_session_disconnect(session.as_ptr()) };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status::empty(self.generation),
            });
        }
        self.retire_generation();
        Ok(())
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn retire_generation(&self) {
        let mut ledger = lock_generation_ledger();
        ledger.retire(self.generation);
    }
}

impl Drop for ProductCore {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            let _ = unsafe { sakamoto_product_session_disconnect(session.as_ptr()) };
            let _ = unsafe { sakamoto_product_session_destroy(session.as_ptr()) };
            self.retire_generation();
        }
    }
}

fn copy_status_text(destination: &mut [u8], value: &str) {
    let bytes = value.as_bytes();
    let count = bytes.len().min(destination.len().saturating_sub(1));
    if count != 0 {
        destination[..count].copy_from_slice(&bytes[..count]);
    }
    if !destination.is_empty() {
        destination[count] = 0;
    }
}

fn status_to_ffi(status: &Status) -> ProductStatus {
    let mut value = ProductStatus::zeroed();
    value.abi_version = status.abi_version;
    value.api_version = status.api_version;
    value.status_code = status.code.raw();
    value.generation = status.generation;
    value.core_ready = u32::from(status.core_ready);
    value.adapter_available = u32::from(status.adapter_available);
    value.protection_running = u32::from(status.protection_running);
    value.plugin_loaded = u32::from(status.plugin_loaded);
    value.vapi_handle_live = u32::from(status.vapi_handle_live);
    value.generation_live = u32::from(status.generation_live);
    copy_status_text(&mut value.artifact_id, &status.artifact_id);
    copy_status_text(&mut value.api_identity, &status.api_identity);
    copy_status_text(&mut value.vpp_revision, &status.vpp_revision);
    copy_status_text(&mut value.error_detail, &status.error_detail);
    value.root_nfqueue_queue_id = status.root_nfqueue_queue_id;
    value.root_nfqueue_queue_last = status.root_nfqueue_queue_last;
    value.root_nfqueue_lane_count = status.root_nfqueue_lane_count;
    value.root_nfqueue_ready_lane_mask = status.root_nfqueue_ready_lane_mask;
    value.root_nfqueue_generation = status.root_nfqueue_generation;
    value.root_nfqueue_verdict_attempts = status.root_nfqueue_verdict_attempts;
    value.root_nfqueue_internal_settlements = status.root_nfqueue_internal_settlements;
    value.root_nfqueue_buffer_returns = status.root_nfqueue_buffer_returns;
    value.root_nfqueue_origin_local_completions = status.root_nfqueue_origin_local_completions;
    value.root_nfqueue_origin_remote_completions = status.root_nfqueue_origin_remote_completions;
    value.root_nfqueue_lane0_verdict_attempts = status.root_nfqueue_lane0_verdict_attempts;
    value.root_nfqueue_lane1_verdict_attempts = status.root_nfqueue_lane1_verdict_attempts;
    value.root_nfqueue_input_packets = status.root_nfqueue_input_packets;
    value.root_nfqueue_output_packets = status.root_nfqueue_output_packets;
    value.root_nfqueue_ipv4_packets = status.root_nfqueue_ipv4_packets;
    value.root_nfqueue_ipv6_packets = status.root_nfqueue_ipv6_packets;
    value.root_nfqueue_tcp_packets = status.root_nfqueue_tcp_packets;
    value.root_nfqueue_udp_packets = status.root_nfqueue_udp_packets;
    value.root_nfqueue_uid_known_packets = status.root_nfqueue_uid_known_packets;
    value.root_nfqueue_uid_unknown_packets = status.root_nfqueue_uid_unknown_packets;
    value.root_nfqueue_last_ip_family = status.root_nfqueue_last_ip_family;
    value.root_nfqueue_last_protocol = status.root_nfqueue_last_protocol;
    value.root_nfqueue_last_hook = status.root_nfqueue_last_hook;
    value.root_nfqueue_last_uid_known = status.root_nfqueue_last_uid_known;
    value.root_nfqueue_last_uid = status.root_nfqueue_last_uid;
    value.root_nfqueue_last_queue_id = status.root_nfqueue_last_queue_id;
    value.root_nfqueue_last_packet_id = status.root_nfqueue_last_packet_id;
    value.root_nfqueue_verdict_succeeded = status.root_nfqueue_verdict_succeeded;
    value.root_nfqueue_verdict_failed_definite = status.root_nfqueue_verdict_failed_definite;
    value.root_nfqueue_verdict_outcome_unknown = status.root_nfqueue_verdict_outcome_unknown;
    value.root_nfqueue_ingress_identity_missing = status.root_nfqueue_ingress_identity_missing;
    value.root_nfqueue_graph_submit_fail_opens = status.root_nfqueue_graph_submit_fail_opens;
    value.root_nfqueue_non_owner_bypasses = status.root_nfqueue_non_owner_bypasses;
    value.root_nfqueue_duplicate_completion_drops = status.root_nfqueue_duplicate_completion_drops;
    value.root_nfqueue_stale_completion_drops = status.root_nfqueue_stale_completion_drops;
    value.vpn_tun_fd_attached = status.vpn_tun_fd_attached;
    value.vpn_direct_udp4_socket_attached = status.vpn_direct_udp4_socket_attached;
    value.vpn_direct_udp4_protect_succeeded = status.vpn_direct_udp4_protect_succeeded;
    value.vpn_direct_udp4_bind_succeeded = status.vpn_direct_udp4_bind_succeeded;
    value.vpn_tun_ingress_packets = status.vpn_tun_ingress_packets;
    value.vpn_tun_udp4_tun_origin_packets = status.vpn_tun_udp4_tun_origin_packets;
    value.vpn_flow_stack_admissions = status.vpn_flow_stack_admissions;
    value.vpn_direct_udp4_send_succeeded = status.vpn_direct_udp4_send_succeeded;
    value.vpn_direct_udp4_transport_failed = status.vpn_direct_udp4_transport_failed;
    value.vpn_flow_stack_return_packets = status.vpn_flow_stack_return_packets;
    value.vpn_flow_stack_return_provenance_packets =
        status.vpn_flow_stack_return_provenance_packets;
    value.vpn_tun_write_completions = status.vpn_tun_write_completions;
    value.vpn_infrastructure_faults = status.vpn_infrastructure_faults;
    value.vpn_duplicate_or_stale_drops = status.vpn_duplicate_or_stale_drops;
    value.product_graph_worker_count = status.product_graph_worker_count;
    value.product_graph_hash_seed = status.product_graph_hash_seed;
    value.product_graph_handoff_credits = status.product_graph_handoff_credits;
    value.product_graph_vpp_worker_count = status.product_graph_vpp_worker_count;
    value.product_graph_vpp_main_core = status.product_graph_vpp_main_core;
    value.product_graph_vpp_worker0_thread_index = status.product_graph_vpp_worker0_thread_index;
    value.product_graph_vpp_worker0_core = status.product_graph_vpp_worker0_core;
    value.product_graph_vpp_worker1_thread_index = status.product_graph_vpp_worker1_thread_index;
    value.product_graph_vpp_worker1_core = status.product_graph_vpp_worker1_core;
    value.product_graph_enabled = status.product_graph_enabled;
    value.product_graph_accepting = status.product_graph_accepting;
    value.product_graph_worker_layout_ready = status.product_graph_worker_layout_ready;
    value.product_graph_obligation_debt = status.product_graph_obligation_debt;
    value.product_graph_buffer_debt = status.product_graph_buffer_debt;
    value.product_graph_handoff_debt = status.product_graph_handoff_debt;
    value.policy_requested_revision = status.policy_requested_revision;
    value.policy_active_revision = status.policy_active_revision;
    value.policy_generation = status.policy_generation;
    value.policy_snapshot_hash = status.policy_snapshot_hash;
    value.policy_worker0_revision = status.policy_worker0_revision;
    value.policy_worker1_revision = status.policy_worker1_revision;
    value.policy_snapshot_empty = u32::from(status.policy_snapshot_empty);
    value.policy_default_pass = u32::from(status.policy_default_pass);
    value.policy_gate_claim_count = status.policy_gate_claim_count;
    value.policy_l4_rule_count = status.policy_l4_rule_count;
    value.policy_last_apply_status_code = status.policy_last_apply_status_code;
    value.policy_mixed_revision = u32::from(status.policy_mixed_revision);
    value.policy_artifact_match = u32::from(status.policy_artifact_match);
    value.policy_generation_match = u32::from(status.policy_generation_match);
    copy_status_text(
        &mut value.policy_snapshot_identity,
        &status.policy_snapshot_identity,
    );
    value.policy_gate_subject_uid = status.policy_gate_subject_uid;
    value.policy_gate_network_context = status.policy_gate_network_context;
    value.policy_gate_blocked = u32::from(status.policy_gate_blocked);
    value.policy_gate_reason_id = status.policy_gate_reason_id;
    value.policy_gate_rule_id = status.policy_gate_rule_id;
    value.policy_drop_records = status.policy_drop_records;
    value.policy_last_drop_revision = status.policy_last_drop_revision;
    value.policy_last_drop_rule_id = status.policy_last_drop_rule_id;
    value.policy_last_drop_completion_attempts = status.policy_last_drop_completion_attempts;
    value.policy_last_drop_uid = status.policy_last_drop_uid;
    value.policy_last_drop_network_context = status.policy_last_drop_network_context;
    value.policy_last_drop_reason_id = status.policy_last_drop_reason_id;
    value.policy_last_drop_verdict = status.policy_last_drop_verdict;
    value.policy_last_drop_winner = status.policy_last_drop_winner;
    value.policy_last_drop_uid_known = u32::from(status.policy_last_drop_uid_known);
    value.policy_last_drop_device_direction = status.policy_last_drop_device_direction;
    value.policy_l4_active_revision = status.policy_l4_active_revision;
    value.policy_l4_rule_id = status.policy_l4_rule_id;
    value.policy_l4_match_records = status.policy_l4_match_records;
    value.policy_l4_no_match_records = status.policy_l4_no_match_records;
    value.policy_l4_last_match_revision = status.policy_l4_last_match_revision;
    value.policy_l4_last_match_rule_id = status.policy_l4_last_match_rule_id;
    value.policy_l4_subject_uid = status.policy_l4_subject_uid;
    value.policy_l4_network_context = status.policy_l4_network_context;
    value.policy_l4_ip_family = status.policy_l4_ip_family;
    value.policy_l4_ip_protocol = status.policy_l4_ip_protocol;
    value.policy_l4_direction = status.policy_l4_direction;
    value.policy_l4_action = status.policy_l4_action;
    value.policy_l4_priority = status.policy_l4_priority;
    value.policy_l4_order = status.policy_l4_order;
    value.policy_l4_reason_id = status.policy_l4_reason_id;
    value.policy_l4_last_match_uid = status.policy_l4_last_match_uid;
    value.policy_l4_last_match_network_context = status.policy_l4_last_match_network_context;
    value.policy_l4_last_match_reason_id = status.policy_l4_last_match_reason_id;
    value.policy_l4_last_match_verdict = status.policy_l4_last_match_verdict;
    value.policy_l4_last_match_winner = status.policy_l4_last_match_winner;
    value.policy_l4_last_match_uid_known = status.policy_l4_last_match_uid_known;
    value.policy_l4_last_match_device_direction = status.policy_l4_last_match_device_direction;
    value.policy_l4_last_match_action = status.policy_l4_last_match_action;
    value.policy_l4_last_evaluation_result = status.policy_l4_last_evaluation_result;
    value.policy_l4_last_evaluation_verdict = status.policy_l4_last_evaluation_verdict;
    value.policy_l4_last_evaluation_device_direction =
        status.policy_l4_last_evaluation_device_direction;
    value.policy_l4_view_active = status.policy_l4_view_active;
    value.policy_l4_view_rule_count = status.policy_l4_view_rule_count;
    value.policy_l4_view_max_probes = status.policy_l4_view_max_probes;
    value.policy_l4_view_last_match_winner_rank =
        status.policy_l4_view_last_match_winner_rank;
    value.policy_l4_view_last_match_probes = status.policy_l4_view_last_match_probes;
    value.policy_l4_view_last_match_candidate_count =
        status.policy_l4_view_last_match_candidate_count;
    value.policy_l4_view_last_no_match_reason = status.policy_l4_view_last_no_match_reason;
    value.policy_l4_typed_match_policy_key = status.policy_l4_typed_match_policy_key;
    value.policy_l4_typed_match_probe_key = status.policy_l4_typed_match_probe_key;
    value.policy_l4_last_evaluation_probe_key = status.policy_l4_last_evaluation_probe_key;
    value
}

fn error_status(error: &ProductError, generation: u64) -> ProductStatus {
    match error {
        ProductError::Native { status, .. } => status_to_ffi(status),
        ProductError::AbiVersion { actual, .. } => {
            let mut status = Status::empty(generation);
            status.abi_version = *actual;
            status.code = ErrorCode::ProtocolMismatch;
            status.error_detail = "Product Core ABI version mismatch".to_owned();
            status_to_ffi(&status)
        }
        ProductError::ApiVersion { actual, .. } => {
            let mut status = Status::empty(generation);
            status.api_version = *actual;
            status.code = ErrorCode::ProtocolMismatch;
            status.error_detail = "Product Core API version mismatch".to_owned();
            status_to_ffi(&status)
        }
        ProductError::PathContainsNul => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::InvalidArgument;
            status.error_detail = "API socket path is invalid".to_owned();
            status_to_ffi(&status)
        }
        ProductError::PolicyStore { detail } => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::PolicyStoreFailed;
            status.error_detail = detail.clone();
            status_to_ffi(&status)
        }
        ProductError::MutationFenceActive {
            generation: fenced_generation,
            requested_revision,
        } => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::PolicyMutationFenced;
            status.generation = *fenced_generation;
            status.policy_requested_revision = *requested_revision;
            status.error_detail =
                "policy mutation is fenced until fresh-generation readback".to_owned();
            status_to_ffi(&status)
        }
        ProductError::GenerationActive { generation: active } => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.generation = *active;
            status.error_detail = "another Product Core generation is active".to_owned();
            status_to_ffi(&status)
        }
        ProductError::GenerationRetired {
            generation: retired,
        } => {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.generation = *retired;
            status.error_detail = "Product Core generation has been retired".to_owned();
            status_to_ffi(&status)
        }
    }
}

fn invalid_status(generation: u64, detail: &str) -> ProductStatus {
    let mut status = Status::empty(generation);
    status.code = ErrorCode::InvalidArgument;
    status.error_detail = detail.to_owned();
    status_to_ffi(&status)
}

fn panic_status(generation: u64) -> ProductStatus {
    let mut status = Status::empty(generation);
    status.code = ErrorCode::InternalError;
    status.error_detail = "Product Core facade panicked".to_owned();
    status_to_ffi(&status)
}

fn socket_path(bytes: ProductBytes) -> Result<String, ProductError> {
    if bytes.data.is_null() || bytes.length == 0 {
        return Err(ProductError::PathContainsNul);
    }
    let bytes = unsafe { std::slice::from_raw_parts(bytes.data, bytes.length as usize) };
    if bytes.contains(&0) {
        return Err(ProductError::PathContainsNul);
    }
    let value = std::str::from_utf8(bytes).map_err(|_| ProductError::PathContainsNul)?;
    Ok(value.to_owned())
}

/// Connect a Rust-owned ProductCore and return its first status.
///
/// The function catches Rust panics so no unwinding crosses JNI/C. The caller
/// must pass valid writable output pointers and must later destroy a returned
/// handle exactly once.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_connect(
    api_socket: ProductBytes,
    generation: u64,
    out_handle: *mut *mut ProductCoreHandle,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_handle.is_null() || out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        *out_handle = std::ptr::null_mut();
        *out_status = invalid_status(generation, "invalid Product Core connect arguments");
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let path = match socket_path(api_socket) {
            Ok(path) => path,
            Err(error) => {
                let status = error_status(&error, generation);
                unsafe { *out_status = status };
                return Err(error);
            }
        };
        match ProductCore::connect(Path::new(&path), generation) {
            Ok((core, status)) => {
                unsafe {
                    *out_status = status_to_ffi(&status);
                    *out_handle = Box::into_raw(Box::new(ProductCoreHandle { core }));
                }
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error)
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(error)) => error_status(&error, generation).status_code,
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Query the same Rust-owned ProductCore session for a generation.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_query(
    handle: *mut ProductCoreHandle,
    generation: u64,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core query arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.query() {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Persist and publish a fresh empty default-pass policy snapshot.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_empty_policy(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.apply_empty_policy(Path::new(&dir)) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Persist and publish an empty default-pass snapshot at the supplied
/// Authoring Policy Bundle revision.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_empty_policy_revision(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    revision: u64,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() || revision == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle
            .core
            .apply_empty_policy_revision(Path::new(&dir), revision)
        {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Persist and publish one Root Network Gate policy snapshot.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_network_gate_policy(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    subject_uid: u32,
    network_context: u32,
    blocked: u32,
    rule_id: u64,
    reason_id: u32,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.apply_network_gate_policy(
            Path::new(&dir),
            subject_uid,
            network_context,
            blocked != 0,
            rule_id,
            reason_id,
        ) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Persist and publish one Root Network Gate policy snapshot at the supplied
/// Authoring Policy Bundle revision.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_network_gate_policy_revision(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    revision: u64,
    subject_uid: u32,
    network_context: u32,
    blocked: u32,
    rule_id: u64,
    reason_id: u32,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() || revision == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.apply_network_gate_policy_revision(
            Path::new(&dir),
            revision,
            subject_uid,
            network_context,
            blocked != 0,
            rule_id,
            reason_id,
        ) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Persist and publish one stateless L4 policy snapshot.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_l4_policy(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    subject_uid: u32,
    network_context: u32,
    ip_family: u32,
    ip_protocol: u32,
    direction: u32,
    action: u32,
    source_cidr: ProductBytes,
    destination_cidr: ProductBytes,
    source_port_first: u32,
    source_port_last: u32,
    destination_port_first: u32,
    destination_port_last: u32,
    priority: u32,
    order: u32,
    rule_id: u64,
    reason_id: u32,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let source = match socket_path(source_cidr) {
            Ok(value) => value,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let destination = match socket_path(destination_cidr) {
            Ok(value) => value,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.apply_l4_policy(
            Path::new(&dir),
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            &source,
            &destination,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        ) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Persist and publish one stateless L4 policy snapshot at the supplied
/// Authoring Policy Bundle revision.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_l4_policy_revision(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    revision: u64,
    subject_uid: u32,
    network_context: u32,
    ip_family: u32,
    ip_protocol: u32,
    direction: u32,
    action: u32,
    source_cidr: ProductBytes,
    destination_cidr: ProductBytes,
    source_port_first: u32,
    source_port_last: u32,
    destination_port_first: u32,
    destination_port_last: u32,
    priority: u32,
    order: u32,
    rule_id: u64,
    reason_id: u32,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() || revision == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let source = match socket_path(source_cidr) {
            Ok(value) => value,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let destination = match socket_path(destination_cidr) {
            Ok(value) => value,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.apply_l4_policy_revision(
            Path::new(&dir),
            revision,
            subject_uid,
            network_context,
            ip_family,
            ip_protocol,
            direction,
            action,
            &source,
            &destination,
            source_port_first,
            source_port_last,
            destination_port_first,
            destination_port_last,
            priority,
            order,
            rule_id,
            reason_id,
        ) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Arm one debug-only, one-shot typed policy mutation fault for this handle.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_set_policy_mutation_fault(
    handle: *mut ProductCoreHandle,
    generation: u64,
    fault_mode: u32,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        *out_status = invalid_status(generation, "invalid Product Core fault arguments");
    }
    if handle.is_null() || generation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.set_policy_mutation_fault(fault_mode) {
            Ok(()) => {
                let mut status = Status::empty(generation);
                status.code = ErrorCode::Ok;
                status.error_detail = "debug policy mutation fault armed".to_owned();
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Validate, stage, and apply one complete successor policy bundle.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_apply_policy_bundle(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    bundle: *const ProductPolicyBundle,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() || bundle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        let bundle = unsafe { &*bundle };
        match handle.core.apply_policy_bundle(Path::new(&dir), bundle) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Reconcile the latest persisted policy intent, or return current status if
/// no intent exists yet.  A durable unknown-mutation fence takes the
/// readback-only path and never submits the retained candidate again.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_reconcile_policy(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.reconcile_policy(Path::new(&dir)) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Reconcile the persisted empty policy intent, or return current status if no
/// intent exists yet.  Unknown mutations are resolved by fresh-generation
/// readback rather than automatic replay.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_reconcile_empty_policy(
    handle: *mut ProductCoreHandle,
    generation: u64,
    files_dir: ProductBytes,
    out_status: *mut ProductStatus,
) -> c_uint {
    if out_status.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe { *out_status = invalid_status(generation, "invalid Product Core policy arguments") };
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let dir = match socket_path(files_dir) {
            Ok(path) => path,
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                return Err(error.code());
            }
        };
        let handle = unsafe { &mut *handle };
        if handle.core.generation() != generation {
            let mut status = Status::empty(generation);
            status.code = ErrorCode::StaleHandle;
            status.error_detail = "Product Core generation does not match the handle".to_owned();
            unsafe { *out_status = status_to_ffi(&status) };
            return Err(ErrorCode::StaleHandle);
        }
        match handle.core.reconcile_policy(Path::new(&dir)) {
            Ok(status) => {
                unsafe { *out_status = status_to_ffi(&status) };
                Ok(())
            }
            Err(error) => {
                unsafe { *out_status = error_status(&error, generation) };
                Err(error.code())
            }
        }
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => {
            unsafe { *out_status = panic_status(generation) };
            ErrorCode::InternalError.raw()
        }
    }
}

/// Disconnect a ProductCore session while retaining its tombstone handle.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_disconnect(
    handle: *mut ProductCoreHandle,
) -> c_uint {
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let handle = unsafe { &mut *handle };
        handle.core.disconnect().map_err(|error| error.code())
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

/// Destroy a handle after disconnecting it. Drop remains the final safety net.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_destroy(handle: *mut ProductCoreHandle) -> c_uint {
    if handle.is_null() {
        return ErrorCode::InvalidArgument.raw();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut handle = unsafe { Box::from_raw(handle) };
        let code = handle.core.disconnect().map_err(|error| error.code());
        drop(handle);
        code
    }));
    match result {
        Ok(Ok(())) => ErrorCode::Ok.raw(),
        Ok(Err(code)) => code.raw(),
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

impl ProductStatus {
    fn zeroed() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl ProductPolicySnapshot {
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

    fn complete_fence_readback(fence: &PolicyMutationFence, generation: u64) -> Status {
        let mut status = Status::empty(generation);
        status.code = ErrorCode::Ok;
        status.policy_requested_revision = fence.requested_revision;
        status.policy_active_revision = fence.requested_revision;
        status.policy_generation = generation;
        status.policy_snapshot_hash = fence.snapshot_hash;
        status.policy_last_apply_status_code = 0;
        status.policy_artifact_match = true;
        status.policy_generation_match = true;
        status.policy_snapshot_identity = fence.snapshot_identity.clone();
        status.artifact_id = fence.artifact_id.clone();
        status.api_identity = fence.api_identity.clone();
        status
    }

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
    fn policy_bundle_validation_accepts_bounded_dual_stack_tcp_udp_entries() {
        let mut bundle = valid_policy_bundle();
        bundle.gate_entry_count = POLICY_BUNDLE_MAX_GATE_ENTRIES as u32;
        bundle.l4_rule_count = POLICY_BUNDLE_MAX_L4_ENTRIES as u32;
        for index in 0..POLICY_BUNDLE_MAX_GATE_ENTRIES {
            bundle.gate_entries[index] = valid_gate_entry(index as u64 + 1);
        }
        for index in 0..POLICY_BUNDLE_MAX_L4_ENTRIES {
            let mut entry = valid_l4_entry(index as u64 + 1000);
            if index % 2 == 1 {
                entry.ip_family = PRODUCT_POLICY_IP_FAMILY_IPV6;
                entry.ip_protocol = PRODUCT_POLICY_IP_PROTOCOL_UDP;
                entry.source_prefix_len = 128;
                entry.destination_prefix_len = 128;
            }
            bundle.l4_entries[index] = entry;
        }
        assert_eq!(validate_policy_bundle(&bundle).unwrap(), "bundle/v1");
    }

    #[test]
    fn policy_bundle_validation_rejects_capacity_and_typed_field_overflow() {
        let mut bundle = valid_policy_bundle();
        bundle.gate_entry_count = (POLICY_BUNDLE_MAX_GATE_ENTRIES as u32) + 1;
        assert!(validate_policy_bundle(&bundle).is_err());

        let mut invalid_family = valid_policy_bundle();
        invalid_family.l4_entries[0].ip_family = 5;
        assert!(validate_policy_bundle(&invalid_family).is_err());

        let mut invalid_protocol = valid_policy_bundle();
        invalid_protocol.l4_entries[0].ip_protocol = 1;
        assert!(validate_policy_bundle(&invalid_protocol).is_err());

        let mut invalid_ipv4_address = valid_policy_bundle();
        invalid_ipv4_address.l4_entries[0].source_address[15] = 1;
        assert!(validate_policy_bundle(&invalid_ipv4_address).is_err());

        let mut invalid_id = valid_policy_bundle();
        invalid_id.l4_entries[0].rule_id = 0;
        assert!(validate_policy_bundle(&invalid_id).is_err());

        let mut duplicate_id = valid_policy_bundle();
        duplicate_id.l4_entries[0].rule_id = duplicate_id.gate_entries[0].rule_id;
        assert!(validate_policy_bundle(&duplicate_id).is_err());

        let mut invalid_unused = valid_policy_bundle();
        invalid_unused.l4_entries[1].reason_id = 99;
        assert!(validate_policy_bundle(&invalid_unused).is_err());
    }

    #[test]
    fn policy_bundle_store_round_trips_one_authoritative_snapshot() {
        let root = unique_policy_dir("policy-bundle-store");
        let store = ProductPolicyStore::new(&root);
        let bundle = valid_policy_bundle();
        store.publish_policy_bundle(&bundle).unwrap();
        assert!(store.policy_bundle_state_file().is_file());
        assert!(!store.state_file().exists());
        assert_eq!(store.current_policy_bundle().unwrap(), Some(bundle));
        assert_eq!(
            store.current_snapshot().unwrap(),
            Some(RuntimePolicySnapshot::Bundle(bundle))
        );

        let mut invalid = bundle;
        invalid.l4_rule_count = (POLICY_BUNDLE_MAX_L4_ENTRIES as u32) + 1;
        assert!(store.publish_policy_bundle(&invalid).is_err());
        assert_eq!(store.current_policy_bundle().unwrap(), Some(bundle));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_policy_mutation_persists_bounded_fence_and_candidate() {
        let root = unique_policy_dir("policy-mutation-fence");
        let store = ProductPolicyStore::new(&root);
        let bundle = valid_policy_bundle();
        let mut predecessor = Status::empty(7);
        predecessor.policy_active_revision = 41;
        predecessor.policy_snapshot_hash = 0x1111;
        predecessor.policy_snapshot_identity = "bundle/v1/revision-41".to_owned();
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();

        let fence = PolicyMutationFence::for_bundle(7, &predecessor, &bundle).unwrap();
        let temporary = store.stage_policy_bundle(&bundle).unwrap();
        store.quarantine_policy_bundle(&temporary).unwrap();
        store.write_mutation_fence(&fence).unwrap();

        assert_eq!(store.current_mutation_fence().unwrap(), Some(fence.clone()));
        assert!(store.mutation_candidate_state_file().is_file());
        assert!(store.mutation_fence_state_file().is_file());

        let mut old_generation = ProductCore {
            session: None,
            generation: 7,
            _not_send_or_sync: PhantomData,
        };
        assert!(matches!(
            old_generation.reconcile_unknown_mutation(&store, &fence),
            Err(ProductError::MutationFenceActive {
                generation: 7,
                requested_revision: 42
            })
        ));
        assert!(store.mutation_fence_state_file().is_file());

        let readback = complete_fence_readback(&fence, 8);
        assert!(active_policy_matches_fence(&readback, &fence, 8));
        assert!(!active_policy_matches_fence(&predecessor, &fence, 8));

        store.promote_mutation_candidate(&fence.target_file).unwrap();
        store.clear_mutation_fence().unwrap();
        assert_eq!(store.current_policy_bundle().unwrap(), Some(bundle));
        assert!(!store.mutation_fence_state_file().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_policy_mutation_mismatch_discards_candidate_without_replay() {
        let root = unique_policy_dir("policy-mutation-mismatch");
        let store = ProductPolicyStore::new(&root);
        let bundle = valid_policy_bundle();
        let mut predecessor = Status::empty(9);
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();
        let fence = PolicyMutationFence::for_bundle(9, &predecessor, &bundle).unwrap();
        let temporary = store.stage_policy_bundle(&bundle).unwrap();
        store.quarantine_policy_bundle(&temporary).unwrap();
        store.write_mutation_fence(&fence).unwrap();

        let mut readback = complete_fence_readback(&fence, 10);
        readback.policy_requested_revision = predecessor.policy_active_revision;
        readback.policy_active_revision = predecessor.policy_active_revision;
        readback.policy_snapshot_hash = predecessor.policy_snapshot_hash;
        readback.policy_snapshot_identity = predecessor.policy_snapshot_identity.clone();
        assert!(!active_policy_matches_fence(&readback, &fence, 10));
        store.discard_mutation_candidate();
        store.clear_mutation_fence().unwrap();

        assert!(!store.mutation_candidate_state_file().exists());
        assert!(!store.mutation_fence_state_file().exists());
        assert!(!store.policy_bundle_state_file().exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_policy_mutation_requires_complete_fresh_status() {
        let mut predecessor = Status::empty(15);
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();
        let fence = PolicyMutationFence::for_bundle(15, &predecessor, &valid_policy_bundle())
            .unwrap();
        let complete = complete_fence_readback(&fence, 16);
        assert!(active_policy_matches_fence(&complete, &fence, 16));

        let mut wrong_generation = complete.clone();
        wrong_generation.generation = 15;
        assert!(!active_policy_matches_fence(&wrong_generation, &fence, 16));

        let mut wrong_policy_generation = complete.clone();
        wrong_policy_generation.policy_generation = 15;
        assert!(!active_policy_matches_fence(&wrong_policy_generation, &fence, 16));

        let mut generation_unfenced = complete.clone();
        generation_unfenced.policy_generation_match = false;
        assert!(!active_policy_matches_fence(&generation_unfenced, &fence, 16));

        let mut apply_failed = complete.clone();
        apply_failed.policy_last_apply_status_code = 22;
        assert!(!active_policy_matches_fence(&apply_failed, &fence, 16));

        let mut artifact_unmatched = complete.clone();
        artifact_unmatched.policy_artifact_match = false;
        assert!(!active_policy_matches_fence(&artifact_unmatched, &fence, 16));

        let mut wrong_artifact = complete.clone();
        wrong_artifact.artifact_id = "different-artifact".to_owned();
        assert!(!active_policy_matches_fence(&wrong_artifact, &fence, 16));

        let mut wrong_api = complete.clone();
        wrong_api.api_identity = "different-api".to_owned();
        assert!(!active_policy_matches_fence(&wrong_api, &fence, 16));

        let mut failed_status = complete;
        failed_status.code = ErrorCode::PolicyApplyFailed;
        assert!(!active_policy_matches_fence(&failed_status, &fence, 16));
    }

    #[test]
    fn scalar_policy_stage_preserves_previous_intent_while_fenced() {
        let root = unique_policy_dir("policy-scalar-fence");
        let store = ProductPolicyStore::new(&root);
        let previous = store.publish_next_empty_snapshot().unwrap();
        let successor = EmptyPolicySnapshot::new(2).unwrap();
        let temporary = store.stage_empty_snapshot(&successor).unwrap();
        assert_eq!(
            store.current_empty_snapshot().unwrap().unwrap(),
            previous
        );

        let mut predecessor = Status::empty(11);
        predecessor.artifact_id = "sakamoto-product-vpp-host-v1".to_owned();
        predecessor.api_identity = "product_core.api/v1".to_owned();
        let fence = PolicyMutationFence::for_snapshot(
            11,
            &predecessor,
            &successor.to_ffi(),
            EMPTY_POLICY_STORE_FILE,
        )
        .unwrap();
        store.quarantine_policy_bundle(&temporary).unwrap();
        store.write_mutation_fence(&fence).unwrap();
        assert_eq!(
            store.current_empty_snapshot().unwrap().unwrap(),
            previous
        );

        store.discard_mutation_candidate();
        store.clear_mutation_fence().unwrap();
        assert_eq!(
            store.current_empty_snapshot().unwrap().unwrap(),
            previous
        );
        fs::remove_dir_all(root).unwrap();
    }

    fn valid_policy_bundle() -> ProductPolicyBundle {
        let mut bundle = ProductPolicyBundle::zeroed();
        bundle.abi_version = POLICY_BUNDLE_ABI_VERSION;
        bundle.struct_size = size_of::<ProductPolicyBundle>() as u32;
        bundle.requested_revision = 42;
        bundle.snapshot_hash = 0x0123_4567_89ab_cdef;
        bundle.gate_entry_count = 1;
        bundle.l4_rule_count = 1;
        bundle.default_pass = 1;
        copy_status_text(&mut bundle.snapshot_identity, "bundle/v1");
        bundle.gate_entries[0] = valid_gate_entry(1);
        bundle.l4_entries[0] = valid_l4_entry(2);
        bundle
    }

    fn valid_gate_entry(rule_id: u64) -> ProductPolicyRuleEntry {
        let mut entry = ProductPolicyRuleEntry::zeroed();
        entry.subject_uid = 1010001;
        entry.network_context = 1;
        entry.rule_kind = PRODUCT_POLICY_RULE_KIND_GATE;
        entry.action = PRODUCT_POLICY_ACTION_DROP;
        entry.enabled = 1;
        entry.reason_id = 136000017;
        entry.rule_id = rule_id;
        entry
    }

    fn valid_l4_entry(rule_id: u64) -> ProductPolicyRuleEntry {
        let mut entry = ProductPolicyRuleEntry::zeroed();
        entry.subject_uid = 1010001;
        entry.network_context = 1;
        entry.rule_kind = PRODUCT_POLICY_RULE_KIND_L4;
        entry.ip_family = PRODUCT_POLICY_IP_FAMILY_IPV4;
        entry.ip_protocol = PRODUCT_POLICY_IP_PROTOCOL_TCP;
        entry.direction = PRODUCT_POLICY_DIRECTION_OUTPUT;
        entry.action = PRODUCT_POLICY_ACTION_DROP;
        entry.enabled = 1;
        entry.source_prefix_len = 0;
        entry.destination_prefix_len = 32;
        entry.source_port_first = 0;
        entry.source_port_last = u16::MAX as u32;
        entry.destination_port_first = 443;
        entry.destination_port_last = 443;
        entry.priority = 10;
        entry.order = 0;
        entry.reason_id = 136000191;
        entry.rule_id = rule_id;
        entry.destination_address[0..4].copy_from_slice(&[192, 0, 2, 1]);
        entry
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
        assert_eq!(
            ErrorCode::from_raw(14),
            ErrorCode::PolicyOutcomeUnknown
        );
        assert_eq!(
            ErrorCode::from_raw(15),
            ErrorCode::PolicyMutationFenced
        );
    }

    #[test]
    fn product_core_requires_a_generation() {
        let error = ProductCore::connect(Path::new("/does/not/exist"), 0).unwrap_err();
        assert!(matches!(
            error,
            ProductError::Native {
                code: ErrorCode::InvalidArgument,
                ..
            }
        ));
    }

    #[test]
    fn generation_ledger_allows_only_one_active_generation() {
        let mut ledger = GenerationLedger::default();
        assert!(ledger.reserve(7).is_ok());
        ledger.commit(7);
        assert!(matches!(
            ledger.reserve(8),
            Err(ProductError::GenerationActive { generation: 7 })
        ));
        ledger.retire(7);
        assert!(matches!(
            ledger.reserve(7),
            Err(ProductError::GenerationRetired { generation: 7 })
        ));
        assert!(ledger.reserve(8).is_ok());
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

    #[test]
    fn empty_policy_store_publishes_immutable_snapshots_with_fresh_revisions() {
        let root = unique_policy_dir("empty-policy-store");
        let store = ProductPolicyStore::new(&root);
        let first = store.publish_next_empty_snapshot().unwrap();
        let second = store.publish_next_empty_snapshot().unwrap();

        assert_eq!(first.revision, 1);
        assert_eq!(second.revision, 2);
        assert_ne!(first.snapshot_hash, second.snapshot_hash);
        assert_eq!(second.snapshot_identity, "empty-policy/v1/revision-2");
        let restored = store.current_empty_snapshot().unwrap().unwrap();
        assert_eq!(restored, second);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn empty_policy_snapshot_ffi_has_no_gate_or_l4_claims() {
        let snapshot = EmptyPolicySnapshot::new(7).unwrap().to_ffi();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.requested_revision, 7);
        assert!(snapshot.snapshot_hash != 0);
        assert_eq!(snapshot.snapshot_empty, 1);
        assert_eq!(snapshot.default_pass, 1);
        assert_eq!(snapshot.gate_claim_count, 0);
        assert_eq!(snapshot.l4_rule_count, 0);
        assert_eq!(
            bounded_string(&snapshot.snapshot_identity),
            "empty-policy/v1/revision-7"
        );
    }

    #[test]
    fn network_gate_policy_snapshot_ffi_carries_one_gate_claim_when_blocked() {
        let snapshot =
            NetworkGatePolicySnapshot::new(8, 1010001, 1, true, 0x5100_0000_0f68_3111, 136000017)
                .unwrap()
                .to_ffi();
        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.requested_revision, 8);
        assert!(snapshot.snapshot_hash != 0);
        assert_eq!(snapshot.snapshot_empty, 0);
        assert_eq!(snapshot.default_pass, 1);
        assert_eq!(snapshot.gate_claim_count, 1);
        assert_eq!(snapshot.l4_rule_count, 0);
        assert_eq!(snapshot.gate_subject_uid, 1010001);
        assert_eq!(snapshot.gate_network_context, 1);
        assert_eq!(snapshot.gate_blocked, 1);
        assert_eq!(snapshot.gate_reason_id, 136000017);
        assert_eq!(snapshot.gate_rule_id, 0x5100_0000_0f68_3111);
        assert_eq!(
            bounded_string(&snapshot.snapshot_identity),
            "network-gate/v1/revision-8/uid-1010001/context-1/blocked"
        );
    }

    #[test]
    fn stateless_l4_policy_snapshot_ffi_carries_one_root_tcp_rule() {
        let snapshot = StatelessL4PolicySnapshot::new(
            9,
            1010001,
            1,
            PRODUCT_L4_IP_FAMILY_IPV4,
            PRODUCT_L4_IP_PROTOCOL_TCP,
            PRODUCT_L4_DIRECTION_OUTPUT,
            PRODUCT_L4_ACTION_DROP,
            "0.0.0.0/0",
            "192.168.4.5/32",
            0,
            65_535,
            19_191,
            19_191,
            10,
            0,
            0x5100_0000_0f68_3191,
            136000191,
        )
        .unwrap()
        .to_ffi();

        assert_eq!(snapshot.schema_version, 1);
        assert_eq!(snapshot.requested_revision, 9);
        assert!(snapshot.snapshot_hash != 0);
        assert_eq!(snapshot.snapshot_empty, 0);
        assert_eq!(snapshot.default_pass, 1);
        assert_eq!(snapshot.gate_claim_count, 0);
        assert_eq!(snapshot.l4_rule_count, 1);
        assert_eq!(snapshot.l4_subject_uid, 1010001);
        assert_eq!(snapshot.l4_network_context, 1);
        assert_eq!(snapshot.l4_ip_family, PRODUCT_L4_IP_FAMILY_IPV4);
        assert_eq!(snapshot.l4_ip_protocol, PRODUCT_L4_IP_PROTOCOL_TCP);
        assert_eq!(snapshot.l4_direction, PRODUCT_L4_DIRECTION_OUTPUT);
        assert_eq!(snapshot.l4_action, PRODUCT_L4_ACTION_DROP);
        assert_eq!(snapshot.l4_source_prefix_len, 0);
        assert_eq!(snapshot.l4_destination_prefix_len, 32);
        assert_eq!(snapshot.l4_source_port_first, 0);
        assert_eq!(snapshot.l4_source_port_last, 65_535);
        assert_eq!(snapshot.l4_destination_port_first, 19_191);
        assert_eq!(snapshot.l4_destination_port_last, 19_191);
        assert_eq!(snapshot.l4_priority, 10);
        assert_eq!(snapshot.l4_order, 0);
        assert_eq!(snapshot.l4_reason_id, 136000191);
        assert_eq!(snapshot.l4_rule_id, 0x5100_0000_0f68_3191);
        assert_eq!(&snapshot.l4_source_address[12..16], &[0, 0, 0, 0]);
        assert_eq!(&snapshot.l4_destination_address[12..16], &[192, 168, 4, 5]);
        assert_eq!(
            bounded_string(&snapshot.snapshot_identity),
            "l4tcp4/1/revision-9/uid-1010001/context-1/rule-5836665117330649489/drop"
        );
    }

    #[test]
    fn policy_store_reconciles_l4_intent_and_clears_other_policy_intents() {
        let root = unique_policy_dir("policy-store-l4");
        let store = ProductPolicyStore::new(&root);
        let empty = store.publish_next_empty_snapshot().unwrap();
        let l4 = store
            .publish_next_l4_snapshot(
                1010001,
                1,
                PRODUCT_L4_IP_FAMILY_IPV4,
                PRODUCT_L4_IP_PROTOCOL_TCP,
                PRODUCT_L4_DIRECTION_OUTPUT,
                PRODUCT_L4_ACTION_DROP,
                "0.0.0.0/0",
                "192.168.4.5/32",
                0,
                65_535,
                19_191,
                19_191,
                10,
                0,
                0x5100_0000_0f68_3191,
                136000191,
            )
            .unwrap();
        assert_eq!(empty.revision, 1);
        assert_eq!(l4.revision, 2);
        assert!(!store.state_file().exists());
        assert!(!store.network_gate_state_file().exists());
        assert!(store.l4_state_file().exists());

        let restored_l4 = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_l4.requested_revision, 2);
        assert_eq!(restored_l4.snapshot_empty, 0);
        assert_eq!(restored_l4.gate_claim_count, 0);
        assert_eq!(restored_l4.l4_rule_count, 1);
        assert_eq!(restored_l4.l4_destination_port_first, 19_191);
        assert_eq!(restored_l4.l4_destination_port_last, 19_191);

        let cleared = store.publish_next_empty_snapshot().unwrap();
        assert_eq!(cleared.revision, 3);
        assert!(!store.l4_state_file().exists());
        let restored_empty = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_empty.requested_revision, 3);
        assert_eq!(restored_empty.snapshot_empty, 1);
        assert_eq!(restored_empty.l4_rule_count, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_store_reconciles_the_latest_empty_or_network_gate_intent() {
        let root = unique_policy_dir("policy-store-latest");
        let store = ProductPolicyStore::new(&root);
        let empty = store.publish_next_empty_snapshot().unwrap();
        let gate = store
            .publish_next_network_gate_snapshot(1010001, 1, true, 0x5100_0000_0f68_3111, 136000017)
            .unwrap();
        assert_eq!(empty.revision, 1);
        assert_eq!(gate.revision, 2);
        let restored = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored.requested_revision, 2);
        assert_eq!(restored.gate_claim_count, 1);
        let open = store
            .publish_next_network_gate_snapshot(1010001, 1, false, 0x5100_0000_0f68_3111, 136000017)
            .unwrap();
        assert_eq!(open.revision, 3);
        let restored_open = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_open.requested_revision, 3);
        assert_eq!(restored_open.snapshot_empty, 0);
        assert_eq!(restored_open.gate_claim_count, 0);
        assert_eq!(restored_open.gate_blocked, 0);
        let cleared = store.publish_next_empty_snapshot().unwrap();
        assert_eq!(cleared.revision, 4);
        assert!(!store.network_gate_state_file().exists());
        let restored_empty = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_empty.requested_revision, 4);
        assert_eq!(restored_empty.snapshot_empty, 1);
        let authored_gate = store
            .publish_network_gate_snapshot_revision(
                99,
                1010001,
                1,
                true,
                0x5100_0000_0f68_3111,
                136000017,
            )
            .unwrap();
        assert_eq!(authored_gate.revision, 99);
        let restored_gate = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_gate.requested_revision, 99);
        assert_eq!(restored_gate.gate_claim_count, 1);
        let authored_open = store.publish_empty_snapshot_revision(100).unwrap();
        assert_eq!(authored_open.revision, 100);
        assert!(!store.network_gate_state_file().exists());
        let restored_open_empty = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_open_empty.requested_revision, 100);
        assert_eq!(restored_open_empty.snapshot_empty, 1);
        assert_eq!(restored_open_empty.gate_claim_count, 0);
        let stale_empty = store.publish_empty_snapshot_revision(200).unwrap();
        assert_eq!(stale_empty.revision, 200);
        let lower_authored_gate = store
            .publish_network_gate_snapshot_revision(
                101,
                1010001,
                1,
                true,
                0x5100_0000_0f68_3111,
                136000017,
            )
            .unwrap();
        assert_eq!(lower_authored_gate.revision, 101);
        assert!(!store.state_file().exists());
        let restored_lower_gate = store.current_snapshot().unwrap().unwrap().to_ffi();
        assert_eq!(restored_lower_gate.requested_revision, 101);
        assert_eq!(restored_lower_gate.snapshot_empty, 0);
        assert_eq!(restored_lower_gate.gate_claim_count, 1);
        fs::remove_dir_all(root).unwrap();
    }

    fn unique_policy_dir(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "sakamoto-product-core-{name}-{}-{nanos}",
            std::process::id()
        ))
    }
}
