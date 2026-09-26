//! Non-unwinding C facade and native session bindings.

use crate::{
    ErrorCode, ProductBytes, ProductCore, ProductError, ProductNetworkSnapshot,
    ProductPolicyBundle, ProductStatus, Status,
};
use std::os::raw::c_uint;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

#[repr(C)]
pub(super) struct ProductSession {
    _private: [u8; 0],
}

unsafe extern "C" {
    pub(super) fn sakamoto_product_session_observation_query(
        session: *mut ProductSession,
        generation: u64,
        out: *mut crate::observation::ObservationHealth,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_sni_query(
        session: *mut ProductSession,
        generation: u64,
        worker: u32,
        slot: u32,
        incarnation: u64,
        out: *mut crate::SniStatus,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_rule_config(
        session: *mut ProductSession,
        expected_generation: u64,
        request: *const crate::RuleConfigRequest,
        out_status: *mut crate::RuleConfigStatus,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_stop_root(
        session: *mut ProductSession,
        expected_generation: u64,
        out_stopped: *mut u32,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_publish_network(
        session: *mut ProductSession,
        expected_generation: u64,
        snapshot: *const ProductNetworkSnapshot,
    ) -> c_uint;
    pub(super) fn sakamoto_product_abi_version() -> c_uint;
    pub(super) fn sakamoto_product_api_version() -> c_uint;
    pub(super) fn sakamoto_product_session_connect(
        api_socket: ProductBytes,
        expected_generation: u64,
        out_session: *mut *mut ProductSession,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_query(
        session: *mut ProductSession,
        expected_generation: u64,
        out_status: *mut ProductStatus,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_set_policy_mutation_fault(
        session: *mut ProductSession,
        expected_generation: u64,
        fault_mode: u32,
    ) -> c_uint;
    pub(super) fn sakamoto_product_session_disconnect(session: *mut ProductSession) -> c_uint;
    pub(super) fn sakamoto_product_session_destroy(session: *mut ProductSession) -> c_uint;
}

#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_observation_start(
    handle: *mut ProductCoreHandle,
    generation: u64,
) -> c_uint {
    if handle.is_null() || generation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        match core.start_observation() {
            Ok(()) => 0,
            Err(_) => ErrorCode::ApiUnavailable.raw(),
        }
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_observation_start_at(
    handle: *mut ProductCoreHandle,
    generation: u64,
    store_path: ProductBytes,
) -> c_uint {
    if handle.is_null() || generation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        let path = match socket_path(store_path) {
            Ok(path) => path,
            Err(_) => return ErrorCode::InvalidArgument.raw(),
        };
        match core.start_observation_at(std::path::Path::new(&path)) {
            Ok(()) => 0,
            Err(_) => ErrorCode::ApiUnavailable.raw(),
        }
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_observation_query(
    handle: *mut ProductCoreHandle,
    generation: u64,
    operation: u32,
    reply: *mut u8,
    reply_capacity: u32,
    out_length: *mut u32,
) -> c_uint {
    if handle.is_null()
        || generation == 0
        || operation > 2
        || reply.is_null()
        || out_length.is_null()
        || reply_capacity == 0
    {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        *out_length = 0;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        if operation != 0 && core.pause_observation(operation == 1).is_err() {
            return ErrorCode::ApiUnavailable.raw();
        }
        let response = core.observation_json();
        if response.len() > reply_capacity as usize {
            return ErrorCode::AllocationFailed.raw();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(response.as_ptr(), reply, response.len());
            *out_length = response.len() as u32;
        }
        0
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_rule_import(
    handle: *mut ProductCoreHandle,
    generation: u64,
    operation: u32,
    expected_revision: u64,
    input: ProductBytes,
    reply: *mut u8,
    reply_capacity: u32,
    out_length: *mut u32,
) -> c_uint {
    if handle.is_null()
        || generation == 0
        || operation > 1
        || reply.is_null()
        || out_length.is_null()
        || reply_capacity < crate::rule_import::MAX_IMPORT_REPLY_BYTES as u32
        || (input.length != 0 && input.data.is_null())
        || (operation == 0 && input.length != 0)
    {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        *out_length = 0;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        let bytes = if input.length == 0 {
            &[][..]
        } else if input.length as usize > crate::rule_import::MAX_IMPORT_BYTES {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(input.data, input.length as usize) }
        };
        let response = if input.length as usize > crate::rule_import::MAX_IMPORT_BYTES {
            serde_json::json!({"stage":"prepare","error":"input exceeds 1 MiB"}).to_string()
        } else {
            match std::str::from_utf8(bytes) {
                Ok(text) => core.rule_import_json(
                    if operation == 1 { Some(text) } else { None },
                    expected_revision,
                ),
                Err(_) => {
                    serde_json::json!({"stage":"prepare","error":"input is not UTF-8"}).to_string()
                }
            }
        };
        if response.len() > reply_capacity as usize {
            return ErrorCode::InternalError.raw();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(response.as_ptr(), reply, response.len());
            *out_length = response.len() as u32;
        }
        0
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_rule_config(
    handle: *mut ProductCoreHandle,
    generation: u64,
    request: *const crate::RuleConfigRequest,
    out_status: *mut crate::RuleConfigStatus,
) -> c_uint {
    if handle.is_null() || request.is_null() || out_status.is_null() || generation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        out_status.write_bytes(0, 1);
        (*out_status).error_index = u32::MAX;
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        match core.rule_config_boxed(unsafe { &*request }) {
            Ok(status) => {
                unsafe { out_status.copy_from_nonoverlapping(&*status, 1) };
                0
            }
            Err(ProductError::Native { code, .. }) => code.raw(),
            Err(_) => ErrorCode::InternalError.raw(),
        }
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

/// Publish control-plane platform facts on the existing serialized session.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_publish_network(
    handle: *mut ProductCoreHandle,
    generation: u64,
    snapshot: *const ProductNetworkSnapshot,
) -> c_uint {
    if handle.is_null() || snapshot.is_null() || generation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        match core.session {
            Some(session) => unsafe {
                sakamoto_product_session_publish_network(session.as_ptr(), generation, snapshot)
            },
            None => ErrorCode::StaleHandle.raw(),
        }
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}
/// One supervisor-owned Root stop step; no packet or buffer crosses this FFI.
#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_stop_root(
    handle: *mut ProductCoreHandle,
    generation: u64,
    out_stopped: *mut u32,
) -> c_uint {
    if !out_stopped.is_null() {
        unsafe { *out_stopped = 0 };
    }
    if handle.is_null() || out_stopped.is_null() || generation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        match core.session {
            Some(session) => unsafe {
                sakamoto_product_session_stop_root(session.as_ptr(), generation, out_stopped)
            },
            None => ErrorCode::StaleHandle.raw(),
        }
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}

pub fn abi_version() -> u32 {
    unsafe { sakamoto_product_abi_version() }
}

pub fn api_version() -> u32 {
    unsafe { sakamoto_product_api_version() }
}

/// Opaque owner exposed by the small C facade below.
///
/// The pointer is deliberately the only thing crossing the native boundary;
/// ProductCore and its generated-VAPI session remain Rust-owned.
#[repr(C)]
pub struct ProductCoreHandle {
    core: ProductCore,
}

pub(super) fn copy_status_text(destination: &mut [u8], value: &str) {
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
    value.policy_l4_view_last_match_winner_rank = status.policy_l4_view_last_match_winner_rank;
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

#[no_mangle]
pub unsafe extern "C" fn sakamoto_product_core_sni_query(
    handle: *mut ProductCoreHandle,
    generation: u64,
    worker: u32,
    slot: u32,
    incarnation: u64,
    out: *mut crate::SniStatus,
) -> c_uint {
    if handle.is_null() || out.is_null() || generation == 0 || incarnation == 0 {
        return ErrorCode::InvalidArgument.raw();
    }
    unsafe {
        *out = crate::SniStatus::default();
    }
    match catch_unwind(AssertUnwindSafe(|| {
        let core = unsafe { &mut (*handle).core };
        if core.generation != generation {
            return ErrorCode::StaleHandle.raw();
        }
        match core.query_sni(worker, slot, incarnation) {
            Ok(status) => {
                unsafe { *out = status };
                0
            }
            Err(ProductError::Native { code, .. }) => code.raw(),
            Err(_) => ErrorCode::InternalError.raw(),
        }
    })) {
        Ok(code) => code,
        Err(_) => ErrorCode::InternalError.raw(),
    }
}
