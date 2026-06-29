// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};

const TUN_POC_CONTROL_SHIM_ABI_VERSION: u32 = 1;

#[repr(C)]
#[derive(Debug)]
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

unsafe extern "C" {
    fn tun_poc_control_shim_abi_version() -> u32;
    fn tun_poc_status_get(api_sock: *const c_char, out: *mut TunPocStatusOut) -> c_int;
}

fn main() {
    let api_sock = env::args()
        .nth(1)
        .unwrap_or_else(|| "/run/vpp/api.sock".to_owned());
    let api_sock = CString::new(api_sock).expect("api socket path contains interior NUL");

    let abi_version = unsafe { tun_poc_control_shim_abi_version() };
    if abi_version != TUN_POC_CONTROL_SHIM_ABI_VERSION {
        eprintln!(
            "unexpected shim ABI version: got {}, expected {}",
            abi_version, TUN_POC_CONTROL_SHIM_ABI_VERSION
        );
        std::process::exit(1);
    }

    let mut status = MaybeUninit::<TunPocStatusOut>::zeroed();
    let rc = unsafe { tun_poc_status_get(api_sock.as_ptr(), status.as_mut_ptr()) };
    if rc != 0 {
        eprintln!("tun_poc_status_get failed: rc={}", rc);
        std::process::exit(1);
    }

    let status = unsafe { status.assume_init() };
    if status.retval != 0 {
        eprintln!("tun_poc_status retval={}", status.retval);
        std::process::exit(1);
    }
    if status.enabled != 0 || status.rx_packets != 0 || status.blocked_packets != 0 {
        eprintln!("unexpected fresh tun_poc status: {:?}", status);
        std::process::exit(1);
    }

    println!("tun_poc_status via Rust FFI shim:");
    println!(
        "  enabled={} mode={} retval={}",
        status.enabled, status.mode, status.retval
    );
    println!(
        "  counters rx={} tx={} shim_tx={} blocked={}",
        status.rx_packets, status.tx_packets, status.shim_tx_packets, status.blocked_packets
    );
    println!(
        "  owner cache_enabled={} block_uid_set={} block_uid={} last_uid={}",
        status.owner_cache_enabled,
        status.block_owner_uid_set,
        status.block_owner_uid,
        status.last_owner_uid
    );
}
