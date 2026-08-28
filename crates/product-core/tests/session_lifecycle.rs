use sakamoto_product_core::{ErrorCode, ProductCore};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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
fn stopping_a_generation_retires_it_but_next_generation_can_connect() {
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
