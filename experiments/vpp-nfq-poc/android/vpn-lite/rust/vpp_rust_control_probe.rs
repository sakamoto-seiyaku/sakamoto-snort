/* SPDX-License-Identifier: Apache-2.0 */

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;

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

fn status_rc(client: *mut TunPocClient) -> c_int {
    let mut status = MaybeUninit::<TunPocStatusOut>::zeroed();
    unsafe { tun_poc_client_status_get(client, status.as_mut_ptr()) }
}

fn wait_for_marker(log: &mut impl Write, label: &str, path: &Path, timeout_seconds: c_int) -> bool {
    let deadline = timeout_seconds.clamp(5, 120) as u64 * 10;
    for _ in 0..deadline {
        if path.exists() {
            let _ = writeln!(log, "{label}_marker_seen=1 path={}", path.display());
            let _ = log.flush();
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let _ = writeln!(log, "{label}_marker_seen=0 path={}", path.display());
    let _ = log.flush();
    false
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

#[no_mangle]
pub unsafe extern "C" fn sakamoto_rust_vpp_reconnect_probe(
    api_sock: *const c_char,
    log_path: *const c_char,
    stale_marker: *const c_char,
    reopen_marker: *const c_char,
    timeout_seconds: c_int,
) -> c_int {
    if api_sock.is_null() || log_path.is_null() || stale_marker.is_null() || reopen_marker.is_null()
    {
        return -1;
    }

    let log_path = match CStr::from_ptr(log_path).to_str() {
        Ok(path) => path,
        Err(_) => return -2,
    };
    let stale_marker = CStr::from_ptr(stale_marker).to_string_lossy().into_owned();
    let reopen_marker = CStr::from_ptr(reopen_marker).to_string_lossy().into_owned();
    let mut log = match OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(log_path)
    {
        Ok(log) => log,
        Err(_) => return -3,
    };

    let uid = getuid();
    let _ = writeln!(
        log,
        "abi_version={} uid={} api_sock={} timeout_seconds={}",
        tun_poc_control_shim_abi_version(),
        uid,
        CStr::from_ptr(api_sock).to_string_lossy(),
        timeout_seconds
    );

    let mut old_client = ptr::null_mut();
    let initial_open_rc = tun_poc_client_open(api_sock, &mut old_client);
    let _ = writeln!(log, "initial_open_rc={initial_open_rc}");
    if initial_open_rc != 0 || old_client.is_null() {
        let _ = writeln!(log, "result=fail rc={initial_open_rc}");
        return if initial_open_rc != 0 {
            initial_open_rc
        } else {
            -4
        };
    }

    let initial_status_rc = status_rc(old_client);
    let _ = writeln!(log, "initial_status_rc={initial_status_rc}");
    if initial_status_rc != 0 {
        let close_rc = tun_poc_client_close(old_client);
        let _ = writeln!(log, "initial_close_rc={close_rc} result=fail");
        return initial_status_rc;
    }
    let _ = writeln!(log, "ready=1");
    let _ = log.flush();

    if !wait_for_marker(&mut log, "stale", Path::new(&stale_marker), timeout_seconds) {
        let close_rc = tun_poc_client_close(old_client);
        let _ = writeln!(log, "stale_close_rc={close_rc} result=fail rc=-5");
        return -5;
    }

    let stale_status_rc = status_rc(old_client);
    let _ = writeln!(log, "stale_status_rc={stale_status_rc}");
    if stale_status_rc == 0 {
        let close_rc = tun_poc_client_close(old_client);
        let _ = writeln!(log, "stale_close_rc={close_rc} result=fail rc=-6");
        return -6;
    }
    let stale_close_rc = tun_poc_client_close(old_client);
    let _ = writeln!(log, "stale_close_rc={stale_close_rc}");
    if stale_close_rc != 0 {
        let _ = writeln!(log, "stale_close_error=expected_disconnect");
    }

    if !wait_for_marker(
        &mut log,
        "reopen",
        Path::new(&reopen_marker),
        timeout_seconds,
    ) {
        let _ = writeln!(log, "result=fail rc=-7");
        return -7;
    }

    let mut new_client = ptr::null_mut();
    let fresh_open_rc = tun_poc_client_open(api_sock, &mut new_client);
    let _ = writeln!(log, "fresh_open_rc={fresh_open_rc}");
    if fresh_open_rc != 0 || new_client.is_null() {
        let _ = writeln!(log, "result=fail rc={fresh_open_rc}");
        return if fresh_open_rc != 0 {
            fresh_open_rc
        } else {
            -8
        };
    }
    let fresh_status_rc = status_rc(new_client);
    let _ = writeln!(log, "fresh_status_rc={fresh_status_rc}");
    let fresh_close_rc = tun_poc_client_close(new_client);
    let _ = writeln!(log, "fresh_close_rc={fresh_close_rc}");
    if fresh_status_rc != 0 {
        let _ = writeln!(log, "result=fail rc={fresh_status_rc}");
        return fresh_status_rc;
    }
    if fresh_close_rc != 0 {
        let _ = writeln!(log, "result=fail rc={fresh_close_rc}");
        return fresh_close_rc;
    }

    let _ = writeln!(log, "result=pass rc=0");
    let _ = log.flush();
    0
}
