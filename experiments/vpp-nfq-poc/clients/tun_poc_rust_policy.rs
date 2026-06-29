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

#[repr(C)]
struct TunPocOwnerPolicy {
    owner_cache_enabled: u8,
    block_owner_uid_set: u8,
    reserved0: u16,
    block_owner_uid: i32,
}

unsafe extern "C" {
    fn tun_poc_control_shim_abi_version() -> u32;
    fn tun_poc_status_get(api_sock: *const c_char, out: *mut TunPocStatusOut) -> c_int;
    fn tun_poc_owner_policy_set(
        api_sock: *const c_char,
        policy: *const TunPocOwnerPolicy,
        vpp_retval: *mut i32,
    ) -> c_int;
}

fn read_status(api_sock: *const c_char) -> TunPocStatusOut {
    let mut status = MaybeUninit::<TunPocStatusOut>::zeroed();
    let rc = unsafe { tun_poc_status_get(api_sock, status.as_mut_ptr()) };
    if rc != 0 {
        eprintln!("tun_poc_status_get failed: rc={}", rc);
        std::process::exit(1);
    }

    let status = unsafe { status.assume_init() };
    if status.retval != 0 {
        eprintln!("tun_poc_status retval={}", status.retval);
        std::process::exit(1);
    }
    status
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

    let before = read_status(api_sock.as_ptr());
    if before.owner_cache_enabled != 0 || before.block_owner_uid_set != 0 {
        eprintln!("expected fresh owner policy before set, got {:?}", before);
        std::process::exit(1);
    }

    let policy = TunPocOwnerPolicy {
        owner_cache_enabled: 1,
        block_owner_uid_set: 1,
        reserved0: 0,
        block_owner_uid: 4242,
    };
    let mut vpp_retval = 0;
    let rc = unsafe { tun_poc_owner_policy_set(api_sock.as_ptr(), &policy, &mut vpp_retval) };
    if rc != 0 || vpp_retval != 0 {
        eprintln!(
            "tun_poc_owner_policy_set failed: rc={} retval={}",
            rc, vpp_retval
        );
        std::process::exit(1);
    }

    let after = read_status(api_sock.as_ptr());
    if after.owner_cache_enabled != 1
        || after.block_owner_uid_set != 1
        || after.block_owner_uid != 4242
    {
        eprintln!("owner policy did not apply: {:?}", after);
        std::process::exit(1);
    }

    println!("tun_poc_owner_policy_set via Rust FFI shim:");
    println!("  retval={}", vpp_retval);
    println!("tun_poc_status after Rust FFI mutation:");
    println!(
        "  owner_cache_enabled={} block_owner_uid_set={} block_owner_uid={}",
        after.owner_cache_enabled, after.block_owner_uid_set, after.block_owner_uid
    );
}
