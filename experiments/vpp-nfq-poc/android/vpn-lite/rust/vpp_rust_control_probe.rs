/* SPDX-License-Identifier: Apache-2.0 */

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::raw::{c_char, c_int};
use std::ptr;

#[repr(C)]
struct TunPocClient {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Default)]
struct TunPocStatusOut {
    retval: i32,
    enabled: u8,
    owner_cache_enabled: u8,
    block_owner_uid_set: u8,
    reserved0: u8,
    mode: u32,
    rx_packets: u64,
    tx_packets: u64,
    shim_tx_packets: u64,
    blocked_packets: u64,
    resolver_queries: u64,
    resolver_hits: u64,
    owner_cache_hits: u64,
    uid_blocked_packets: u64,
    block_owner_uid: i32,
    last_owner_uid: i32,
}

#[repr(C)]
struct TunPocOwnerPolicy {
    owner_cache_enabled: u8,
    block_owner_uid_set: u8,
    reserved0: u16,
    block_owner_uid: i32,
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn tun_poc_control_shim_abi_version() -> u32;
    fn tun_poc_client_open(api_sock: *const c_char, client_out: *mut *mut TunPocClient) -> c_int;
    fn tun_poc_client_close(client: *mut TunPocClient) -> c_int;
    fn tun_poc_client_status_get(client: *mut TunPocClient, out: *mut TunPocStatusOut) -> c_int;
    fn tun_poc_client_owner_policy_set(
        client: *mut TunPocClient,
        policy: *const TunPocOwnerPolicy,
        vpp_retval: *mut i32,
    ) -> c_int;
}

fn write_status(log: &mut impl Write, label: &str, status: &TunPocStatusOut) -> io::Result<()> {
    writeln!(
        log,
        "{label} retval={} enabled={} mode={} owner_cache={} block_uid_set={} block_uid={} last_uid={} rx={} tx={} shim_tx={} blocked={} resolver_queries={} resolver_hits={} owner_cache_hits={} uid_blocked={}",
        status.retval,
        status.enabled,
        status.mode,
        status.owner_cache_enabled,
        status.block_owner_uid_set,
        status.block_owner_uid,
        status.last_owner_uid,
        status.rx_packets,
        status.tx_packets,
        status.shim_tx_packets,
        status.blocked_packets,
        status.resolver_queries,
        status.resolver_hits,
        status.owner_cache_hits,
        status.uid_blocked_packets
    )
}

unsafe fn run_round(
    log: &mut impl Write,
    api_sock: *const c_char,
    block_owner_uid: i32,
    round: i32,
) -> i32 {
    let mut client = ptr::null_mut();
    let mut result = 0;
    let mut status = TunPocStatusOut::default();

    let _ = writeln!(log, "round={round} begin");
    let rc = tun_poc_client_open(api_sock, &mut client);
    let _ = writeln!(log, "round={round} open_rc={rc}");
    if rc != 0 {
        return rc;
    }

    let rc = tun_poc_client_status_get(client, &mut status);
    let _ = writeln!(log, "round={round} status_before_rc={rc}");
    if rc != 0 {
        result = rc;
    } else {
        let _ = write_status(log, "status_before", &status);
        if status.retval != 0 {
            result = -30;
        }
    }

    if result == 0 {
        let policy = TunPocOwnerPolicy {
            owner_cache_enabled: 1,
            block_owner_uid_set: 1,
            reserved0: 0,
            block_owner_uid: block_owner_uid,
        };
        let mut vpp_retval = -1;
        let rc = tun_poc_client_owner_policy_set(client, &policy, &mut vpp_retval);
        let _ = writeln!(
            log,
            "round={round} policy_set_rc={rc} policy_set_vpp_retval={vpp_retval}"
        );
        if rc != 0 || vpp_retval != 0 {
            result = if rc != 0 { rc } else { vpp_retval };
        }
    }

    if result == 0 {
        let rc = tun_poc_client_status_get(client, &mut status);
        let _ = writeln!(log, "round={round} status_set_rc={rc}");
        if rc != 0 {
            result = rc;
        } else {
            let _ = write_status(log, "status_set", &status);
            if status.retval != 0
                || status.owner_cache_enabled == 0
                || status.block_owner_uid_set == 0
                || status.block_owner_uid != block_owner_uid
            {
                result = -31;
            }
        }
    }

    if result == 0 {
        let policy = TunPocOwnerPolicy {
            owner_cache_enabled: 0,
            block_owner_uid_set: 0,
            reserved0: 0,
            block_owner_uid: 0,
        };
        let mut vpp_retval = -1;
        let rc = tun_poc_client_owner_policy_set(client, &policy, &mut vpp_retval);
        let _ = writeln!(
            log,
            "round={round} policy_clear_rc={rc} policy_clear_vpp_retval={vpp_retval}"
        );
        if rc != 0 || vpp_retval != 0 {
            result = if rc != 0 { rc } else { vpp_retval };
        }
    }

    if result == 0 {
        let rc = tun_poc_client_status_get(client, &mut status);
        let _ = writeln!(log, "round={round} status_after_rc={rc}");
        if rc != 0 {
            result = rc;
        } else {
            let _ = write_status(log, "status_after", &status);
            if status.retval != 0
                || status.owner_cache_enabled != 0
                || status.block_owner_uid_set != 0
            {
                result = -32;
            }
        }
    }

    let close_rc = tun_poc_client_close(client);
    let _ = writeln!(
        log,
        "round={round} close_rc={close_rc} result={}",
        if result == 0 { "pass" } else { "fail" }
    );
    if result == 0 && close_rc != 0 {
        result = close_rc;
    }
    result
}

#[no_mangle]
pub unsafe extern "C" fn sakamoto_rust_vpp_control_probe(
    api_sock: *const c_char,
    log_path: *const c_char,
    block_owner_uid: c_int,
    rounds: c_int,
) -> c_int {
    if api_sock.is_null() || log_path.is_null() {
        return -1;
    }

    let log_path = match CStr::from_ptr(log_path).to_str() {
        Ok(path) => path,
        Err(_) => return -2,
    };
    let mut log = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(log_path)
    {
        Ok(log) => log,
        Err(_) => return -3,
    };

    let rounds = rounds.clamp(1, 20);
    let uid = getuid();
    let _ = writeln!(
        log,
        "abi_version={} uid={} api_sock={} rounds={rounds}",
        tun_poc_control_shim_abi_version(),
        uid,
        CStr::from_ptr(api_sock).to_string_lossy()
    );

    let mut result = 0;
    for round in 1..=rounds {
        let rc = run_round(&mut log, api_sock, block_owner_uid, round);
        if rc != 0 && result == 0 {
            result = rc;
        }
        let _ = log.flush();
    }
    let _ = writeln!(
        log,
        "result={} rc={result}",
        if result == 0 { "pass" } else { "fail" }
    );
    let _ = log.flush();
    result
}
