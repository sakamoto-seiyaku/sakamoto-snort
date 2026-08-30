use sakamoto_product_core::{ErrorCode, ProductCore};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAGIC: u32 = 0x534b_5043;
const VERSION: u16 = 1;
const OP_CONNECT: u16 = 1;
const OP_QUERY: u16 = 2;
const CORE_READY: u32 = 1 << 0;
const PLUGIN_LOADED: u32 = 1 << 3;
const VAPI_LIVE: u32 = 1 << 4;
const GENERATION_LIVE: u32 = 1 << 5;

fn unique_socket(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "sakamoto-product-{name}-{}-{nanos}.sock",
        std::process::id()
    ))
}

fn lifecycle_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn response(generation: u64, status: u32, detail: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 392];
    bytes[0..4].copy_from_slice(&MAGIC.to_le_bytes());
    bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
    bytes[8..12].copy_from_slice(&status.to_le_bytes());
    bytes[12..20].copy_from_slice(&generation.to_le_bytes());
    let flags = CORE_READY | PLUGIN_LOADED | VAPI_LIVE | GENERATION_LIVE;
    bytes[20..24].copy_from_slice(&flags.to_le_bytes());
    bytes[24..24 + 15].copy_from_slice(b"host-fixture-v1");
    bytes[120..120 + 31].copy_from_slice(b"product_core.api/1.0.0@1b103f1d");
    bytes[216..216 + 8].copy_from_slice(b"fixture1");
    let detail_len = detail.len().min(127);
    bytes[264..264 + detail_len].copy_from_slice(&detail[..detail_len]);
    bytes
}

fn request(stream: &mut std::os::unix::net::UnixStream) -> (u16, u64) {
    let mut bytes = [0u8; 16];
    stream.read_exact(&mut bytes).unwrap();
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), MAGIC);
    assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), VERSION);
    (
        u16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
    )
}

#[test]
fn one_connection_is_reused_for_two_serialized_queries_and_retired_on_stop() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("persistent");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind lifecycle test socket: {error}"),
    };
    let (done_tx, done_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(request(&mut stream), (OP_CONNECT, 41));
        stream.write_all(&response(41, 0, b"")).unwrap();
        assert_eq!(request(&mut stream), (OP_QUERY, 41));
        stream.write_all(&response(41, 0, b"")).unwrap();
        assert_eq!(request(&mut stream), (OP_QUERY, 41));
        stream.write_all(&response(41, 0, b"")).unwrap();
        done_tx.send(()).unwrap();
    });

    let (mut core, connected) = ProductCore::connect(&path, 41).unwrap();
    assert_eq!(connected.code, ErrorCode::Ok);
    assert!(connected.core_ready);
    assert!(!connected.adapter_available);
    assert!(!connected.protection_running);
    assert!(connected.plugin_loaded);
    assert!(connected.vapi_handle_live);
    assert!(connected.generation_live);
    assert_eq!(core.query().unwrap().generation, 41);
    assert_eq!(core.query().unwrap().generation, 41);
    core.disconnect().unwrap();
    let stale = core.query().unwrap_err();
    assert!(matches!(
        stale,
        sakamoto_product_core::ProductError::Native {
            code: ErrorCode::StaleHandle,
            ..
        }
    ));
    done_rx.recv().unwrap();
    server.join().unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn a_reply_for_another_generation_is_rejected_at_connect() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("stale");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind lifecycle test socket: {error}"),
    };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(request(&mut stream), (OP_CONNECT, 8));
        stream
            .write_all(&response(9, 0, b"wrong generation"))
            .unwrap();
    });
    let result = ProductCore::connect(&path, 8);
    assert!(matches!(
        result,
        Err(sakamoto_product_core::ProductError::Native {
            code: ErrorCode::StaleHandle,
            ..
        })
    ));
    server.join().unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn native_query_failure_tag_and_detail_reach_the_rust_boundary() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("typed-query-failure");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind typed failure test socket: {error}"),
    };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(request(&mut stream), (OP_CONNECT, 17));
        stream
            .write_all(&response(
                17,
                ErrorCode::QueryFailed.raw(),
                b"VAPI status request send failed",
            ))
            .unwrap();
    });

    let result = ProductCore::connect(&path, 17);
    match result {
        Err(sakamoto_product_core::ProductError::Native { code, status }) => {
            assert_eq!(code, ErrorCode::QueryFailed);
            assert_eq!(status.code, ErrorCode::QueryFailed);
            assert_eq!(status.error_detail, "VAPI status request send failed");
        }
        other => panic!("typed query failure was lost at Rust boundary: {other:?}"),
    }
    server.join().unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn stopping_a_generation_retires_it_but_next_generation_can_connect() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("retire");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind lifecycle test socket: {error}"),
    };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(request(&mut stream), (OP_CONNECT, 101));
        stream.write_all(&response(101, 0, b"")).unwrap();
    });
    let (mut core, _) = ProductCore::connect(&path, 101).unwrap();
    core.disconnect().unwrap();
    assert!(matches!(
        ProductCore::connect(&path, 101),
        Err(sakamoto_product_core::ProductError::GenerationRetired { generation: 101 })
    ));
    server.join().unwrap();
    fs::remove_file(&path).unwrap();

    let next_path = unique_socket("next");
    let next_listener = UnixListener::bind(&next_path).unwrap();
    let next_server = thread::spawn(move || {
        let (mut stream, _) = next_listener.accept().unwrap();
        assert_eq!(request(&mut stream), (OP_CONNECT, 102));
        stream.write_all(&response(102, 0, b"")).unwrap();
    });
    let (_, status) = ProductCore::connect(&next_path, 102).unwrap();
    assert_eq!(status.generation, 102);
    next_server.join().unwrap();
    fs::remove_file(next_path).unwrap();
}

#[test]
fn a_second_active_generation_is_rejected_before_a_second_transport() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("single-active");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind lifecycle test socket: {error}"),
    };
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        assert_eq!(request(&mut stream), (OP_CONNECT, 201));
        stream.write_all(&response(201, 0, b"")).unwrap();
        // Keep the first generation alive long enough to prove that the
        // second connect is rejected by the Rust ledger, not the transport.
        thread::sleep(std::time::Duration::from_millis(100));
    });

    let (core, _) = ProductCore::connect(&path, 201).unwrap();
    let second = ProductCore::connect(&path, 202);
    assert!(matches!(
        second,
        Err(sakamoto_product_core::ProductError::GenerationActive { generation: 201 })
    ));
    drop(core);
    server.join().unwrap();
    fs::remove_file(path).unwrap();
}

#[test]
fn concurrent_connect_reserves_before_a_second_transport() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("concurrent-reservation");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind lifecycle test socket: {error}"),
    };
    let (first_seen_tx, first_seen_rx) = mpsc::channel();
    let (transport_count_tx, transport_count_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        assert_eq!(request(&mut first), (OP_CONNECT, 301));
        first_seen_tx.send(()).unwrap();

        thread::sleep(Duration::from_millis(100));
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut second = None;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    second = Some(stream);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(error) => panic!("unexpected second accept error: {error}"),
            }
        }

        first.write_all(&response(301, 0, b"")).unwrap();
        if let Some(mut second) = second {
            assert_eq!(request(&mut second), (OP_CONNECT, 302));
            second.write_all(&response(302, 0, b"")).unwrap();
            transport_count_tx.send(2usize).unwrap();
        } else {
            transport_count_tx.send(1usize).unwrap();
        }
    });

    let first_path = path.clone();
    let first = thread::spawn(move || match ProductCore::connect(&first_path, 301) {
        Ok((mut core, status)) => {
            let code = status.code;
            core.disconnect().unwrap();
            Ok(code)
        }
        Err(error) => Err(error),
    });
    first_seen_rx.recv().unwrap();
    let second_path = path.clone();
    let second = thread::spawn(move || match ProductCore::connect(&second_path, 302) {
        Ok((mut core, status)) => {
            let code = status.code;
            core.disconnect().unwrap();
            Ok(code)
        }
        Err(error) => Err(error),
    });

    let first_result = first.join().unwrap();
    let second_result = second.join().unwrap();
    let transport_count = transport_count_rx.recv().unwrap();
    server.join().unwrap();
    fs::remove_file(path).unwrap();

    assert_eq!(transport_count, 1, "second connect reached the transport");
    assert!(first_result.is_ok() ^ second_result.is_ok());
    assert!(matches!(
        first_result.as_ref().err().or(second_result.as_ref().err()),
        Some(sakamoto_product_core::ProductError::GenerationActive { generation: 301 })
    ));
}

#[test]
fn failed_connect_releases_reservation_for_a_fresh_connect() {
    let _test_lock = lifecycle_test_lock();
    let path = unique_socket("failed-reservation");
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("socket seam unavailable in this sandbox; rerun outside it");
            return;
        }
        Err(error) => panic!("cannot bind lifecycle test socket: {error}"),
    };
    let (first_seen_tx, first_seen_rx) = mpsc::channel();
    let (transport_count_tx, transport_count_rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut first, _) = listener.accept().unwrap();
        assert_eq!(request(&mut first), (OP_CONNECT, 401));
        first_seen_tx.send(()).unwrap();

        thread::sleep(Duration::from_millis(100));
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut second = None;
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((stream, _)) => {
                    second = Some(stream);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(error) => panic!("unexpected second accept error: {error}"),
            }
        }

        let second_seen = second.is_some();
        first
            .write_all(&response(401, ErrorCode::ConnectFailed.raw(), b"failed"))
            .unwrap();
        if let Some(mut second) = second {
            assert_eq!(request(&mut second), (OP_CONNECT, 401));
            second
                .write_all(&response(401, ErrorCode::ConnectFailed.raw(), b"failed"))
                .unwrap();
        }

        listener.set_nonblocking(false).unwrap();
        let (mut fresh, _) = listener.accept().unwrap();
        assert_eq!(request(&mut fresh), (OP_CONNECT, 401));
        fresh.write_all(&response(401, 0, b"")).unwrap();
        transport_count_tx
            .send(if second_seen { 3usize } else { 2usize })
            .unwrap();
    });

    let first_path = path.clone();
    let first = thread::spawn(move || match ProductCore::connect(&first_path, 401) {
        Ok((mut core, status)) => {
            let code = status.code;
            core.disconnect().unwrap();
            Ok(code)
        }
        Err(error) => Err(error),
    });
    first_seen_rx.recv().unwrap();
    let competing_path = path.clone();
    let competing = thread::spawn(move || match ProductCore::connect(&competing_path, 401) {
        Ok((mut core, status)) => {
            let code = status.code;
            core.disconnect().unwrap();
            Ok(code)
        }
        Err(error) => Err(error),
    });

    let first = first.join().unwrap();
    assert!(matches!(
        first,
        Err(sakamoto_product_core::ProductError::Native {
            code: ErrorCode::ConnectFailed,
            ..
        })
    ));
    let competing = competing.join().unwrap();
    assert!(matches!(
        competing,
        Err(sakamoto_product_core::ProductError::GenerationActive { generation: 401 })
    ));
    let (_, status) = ProductCore::connect(&path, 401).unwrap();
    assert_eq!(status.code, ErrorCode::Ok);

    assert_eq!(transport_count_rx.recv().unwrap(), 2);
    server.join().unwrap();
    fs::remove_file(path).unwrap();
}
