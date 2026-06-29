// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::ptr;

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

#[repr(C)]
struct TunPocClient {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn tun_poc_control_shim_abi_version() -> u32;
    fn tun_poc_client_open(
        api_sock: *const c_char,
        client_out: *mut *mut TunPocClient,
    ) -> c_int;
    fn tun_poc_client_close(client: *mut TunPocClient) -> c_int;
    fn tun_poc_client_status_get(
        client: *mut TunPocClient,
        out: *mut TunPocStatusOut,
    ) -> c_int;
    fn tun_poc_client_owner_policy_set(
        client: *mut TunPocClient,
        policy: *const TunPocOwnerPolicy,
        vpp_retval: *mut i32,
    ) -> c_int;
}

fn read_status(client: *mut TunPocClient) -> TunPocStatusOut {
    let mut status = MaybeUninit::<TunPocStatusOut>::zeroed();
    let rc = unsafe { tun_poc_client_status_get(client, status.as_mut_ptr()) };
    if rc != 0 {
        eprintln!("tun_poc_client_status_get failed: rc={}", rc);
        std::process::exit(1);
    }

    let status = unsafe { status.assume_init() };
    if status.retval != 0 {
        eprintln!("tun_poc_status retval={}", status.retval);
        std::process::exit(1);
    }
    status
}

fn set_policy(client: *mut TunPocClient, policy: TunPocOwnerPolicy) {
    let mut vpp_retval = 0;
    let rc = unsafe { tun_poc_client_owner_policy_set(client, &policy, &mut vpp_retval) };
    if rc != 0 || vpp_retval != 0 {
        eprintln!(
            "tun_poc_client_owner_policy_set failed: rc={} retval={}",
            rc, vpp_retval
        );
        std::process::exit(1);
    }
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

    let mut client: *mut TunPocClient = ptr::null_mut();
    let rc = unsafe { tun_poc_client_open(api_sock.as_ptr(), &mut client) };
    if rc != 0 || client.is_null() {
        eprintln!("tun_poc_client_open failed: rc={}", rc);
        std::process::exit(1);
    }

    let before = read_status(client);
    if before.owner_cache_enabled != 0 || before.block_owner_uid_set != 0 {
        eprintln!("expected fresh owner policy before set, got {:?}", before);
        std::process::exit(1);
    }

    set_policy(
        client,
        TunPocOwnerPolicy {
            owner_cache_enabled: 1,
            block_owner_uid_set: 1,
            reserved0: 0,
            block_owner_uid: 4242,
        },
    );
    let after_set = read_status(client);
    if after_set.owner_cache_enabled != 1
        || after_set.block_owner_uid_set != 1
        || after_set.block_owner_uid != 4242
    {
        eprintln!("owner policy did not apply: {:?}", after_set);
        std::process::exit(1);
    }

    set_policy(
        client,
        TunPocOwnerPolicy {
            owner_cache_enabled: 0,
            block_owner_uid_set: 0,
            reserved0: 0,
            block_owner_uid: -1,
        },
    );
    let after_clear = read_status(client);
    if after_clear.owner_cache_enabled != 0
        || after_clear.block_owner_uid_set != 0
        || after_clear.block_owner_uid != -1
    {
        eprintln!("owner policy did not clear: {:?}", after_clear);
        std::process::exit(1);
    }

    let close_rc = unsafe { tun_poc_client_close(client) };
    if close_rc != 0 {
        eprintln!("tun_poc_client_close failed: rc={}", close_rc);
        std::process::exit(1);
    }

    println!("tun_poc persistent Rust FFI shim:");
    println!(
        "  before owner_cache_enabled={} block_owner_uid_set={} block_owner_uid={}",
        before.owner_cache_enabled, before.block_owner_uid_set, before.block_owner_uid
    );
    println!(
        "  after_set owner_cache_enabled={} block_owner_uid_set={} block_owner_uid={}",
        after_set.owner_cache_enabled, after_set.block_owner_uid_set, after_set.block_owner_uid
    );
    println!(
        "  after_clear owner_cache_enabled={} block_owner_uid_set={} block_owner_uid={}",
        after_clear.owner_cache_enabled,
        after_clear.block_owner_uid_set,
        after_clear.block_owner_uid
    );
}
