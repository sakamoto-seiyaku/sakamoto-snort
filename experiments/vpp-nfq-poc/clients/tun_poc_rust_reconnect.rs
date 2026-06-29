// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::CString;
use std::io::{self, Write};
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::ptr;
use std::thread;
use std::time::Duration;

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
}

fn print_flush(line: &str) {
    println!("{}", line);
    io::stdout().flush().expect("stdout flush failed");
}

fn wait_for_marker(path: &Path) {
    while !path.exists() {
        thread::sleep(Duration::from_millis(50));
    }
}

fn open_client(api_sock: *const c_char) -> *mut TunPocClient {
    let mut client: *mut TunPocClient = ptr::null_mut();
    let rc = unsafe { tun_poc_client_open(api_sock, &mut client) };
    if rc != 0 || client.is_null() {
        eprintln!("tun_poc_client_open failed: rc={}", rc);
        std::process::exit(1);
    }
    client
}

fn status_rc(client: *mut TunPocClient) -> c_int {
    let mut status = MaybeUninit::<TunPocStatusOut>::zeroed();
    unsafe { tun_poc_client_status_get(client, status.as_mut_ptr()) }
}

fn expect_status_ok(client: *mut TunPocClient) {
    let rc = status_rc(client);
    if rc != 0 {
        eprintln!("tun_poc_client_status_get failed: rc={}", rc);
        std::process::exit(1);
    }
}

fn main() {
    let mut args = env::args();
    let _program = args.next();
    let api_sock = args.next().expect("missing api socket path");
    let stale_marker = args.next().expect("missing stale marker path");
    let reopen_marker = args.next().expect("missing reopen marker path");
    let api_sock = CString::new(api_sock).expect("api socket path contains interior NUL");
    let stale_marker = Path::new(&stale_marker);
    let reopen_marker = Path::new(&reopen_marker);

    let abi_version = unsafe { tun_poc_control_shim_abi_version() };
    if abi_version != TUN_POC_CONTROL_SHIM_ABI_VERSION {
        eprintln!(
            "unexpected shim ABI version: got {}, expected {}",
            abi_version, TUN_POC_CONTROL_SHIM_ABI_VERSION
        );
        std::process::exit(1);
    }

    let old_client = open_client(api_sock.as_ptr());
    expect_status_ok(old_client);
    print_flush("initial_status_ok");

    wait_for_marker(stale_marker);
    let stale_rc = status_rc(old_client);
    if stale_rc == 0 {
        eprintln!("stale status unexpectedly succeeded");
        std::process::exit(1);
    }
    print_flush(&format!("stale_status_failed rc={}", stale_rc));

    let close_rc = unsafe { tun_poc_client_close(old_client) };
    print_flush(&format!("stale_client_close rc={}", close_rc));

    wait_for_marker(reopen_marker);
    let new_client = open_client(api_sock.as_ptr());
    expect_status_ok(new_client);
    let close_rc = unsafe { tun_poc_client_close(new_client) };
    if close_rc != 0 {
        eprintln!("new client close failed: rc={}", close_rc);
        std::process::exit(1);
    }
    print_flush("reopen_status_ok");
}
