// SPDX-License-Identifier: Apache-2.0

use std::env;
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::os::raw::{c_char, c_int};
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;

const TUN_POC_CONTROL_SHIM_ABI_VERSION: u32 = 1;
const THREADS: usize = 4;
const CALLS_PER_THREAD: usize = 5;

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

struct SharedClient(*mut TunPocClient);

unsafe impl Send for SharedClient {}

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

fn status_once(client: *mut TunPocClient) {
    let mut status = MaybeUninit::<TunPocStatusOut>::zeroed();
    let rc = unsafe { tun_poc_client_status_get(client, status.as_mut_ptr()) };
    if rc != 0 {
        panic!("tun_poc_client_status_get failed: rc={}", rc);
    }

    let status = unsafe { status.assume_init() };
    if status.retval != 0 {
        panic!("tun_poc_status retval={}", status.retval);
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

    let shared = Arc::new(Mutex::new(SharedClient(client)));
    let mut handles = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        let shared = Arc::clone(&shared);
        handles.push(thread::spawn(move || {
            for _ in 0..CALLS_PER_THREAD {
                let guard = shared.lock().expect("shared client mutex poisoned");
                status_once(guard.0);
            }
        }));
    }

    for handle in handles {
        handle.join().expect("status worker thread panicked");
    }

    let client = match Arc::try_unwrap(shared) {
        Ok(mutex) => mutex.into_inner().expect("shared client mutex poisoned").0,
        Err(_) => {
            eprintln!("shared client still has references");
            std::process::exit(1);
        }
    };
    let close_rc = unsafe { tun_poc_client_close(client) };
    if close_rc != 0 {
        eprintln!("tun_poc_client_close failed: rc={}", close_rc);
        std::process::exit(1);
    }

    println!("tun_poc serialized Rust FFI shim threads:");
    println!(
        "  threads={} calls_per_thread={} total_calls={}",
        THREADS,
        CALLS_PER_THREAD,
        THREADS * CALLS_PER_THREAD
    );
}
