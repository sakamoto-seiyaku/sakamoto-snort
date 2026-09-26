use sakamoto_product_core::observation::FlowRecord;
use sakamoto_product_core::observation_store::ObservationStore;

#[test]
fn live_pending_is_visible_but_only_committed_tail_survives_restart() {
    let root = std::env::temp_dir().join(format!("e02-live-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let mut r = FlowRecord {
        generation: 9,
        incarnation: 1,
        sequence: 1,
        activity_utc_us: 61_000_000,
        packets: [2, 1],
        bytes: [120, 60],
        ..Default::default()
    };
    store.consume(&[r.clone()], 62_000_000).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([2, 1]));
    assert_eq!(
        store.query()["persistence"]["packets"],
        serde_json::json!([0, 0])
    );
    store.flush().unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([2, 1]));
    assert_eq!(
        store.query()["persistence"]["packets"],
        serde_json::json!([2, 1])
    );
    r.sequence = 2;
    r.packets = [3, 2];
    r.bytes = [180, 120];
    store.consume(&[r.clone()], 63_000_000).unwrap();
    drop(store);
    let mut store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([2, 1]));
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    store.consume(&[r.clone(), r], 64_000_000).unwrap();
    store.flush().unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([3, 2]));
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn end_tail_uses_activity_minute_and_survives_reopen_without_recount() {
    let root = std::env::temp_dir().join(format!("t22-tail-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let mut r = FlowRecord {
        generation: 7,
        owner: 0,
        slot: 3,
        incarnation: 2,
        sequence: 1,
        first_seen: 10,
        last_seen: 20,
        activity_utc_us: 119_000_000,
        packets: [2, 1],
        bytes: [120, 60],
        ..Default::default()
    };
    store.consume(&[r.clone()], 200_000_000).unwrap();
    r.sequence = 2;
    r.last_seen = 30;
    r.ended = true;
    r.packets = [3, 2];
    r.bytes = [180, 120];
    store.consume(&[r.clone()], 250_000_000).unwrap();
    let q = store.query();
    assert_eq!(q["minutes"]["60"]["packets"], serde_json::json!([3, 2]));
    assert!(q["minutes"].get("240").is_none());
    assert_eq!(q["ended"], 1);
    store.flush().unwrap();
    drop(store);
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[r], 999_000_000).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([3, 2]));
    assert_eq!(store.query()["ended"], 1);
    assert_eq!(
        store.query()["recent"]["00000000000250000000:7:0:3:2"]["first_end_us"],
        250_000_000u64
    );
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn locked_database_keeps_live_updates_bounded_and_retries_atomic_commit() {
    let root = std::env::temp_dir().join(format!("e02-lock-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    assert!(ObservationStore::open(&path).is_err());
    let mut r = FlowRecord {
        generation: 4,
        incarnation: 1,
        sequence: 1,
        activity_utc_us: 61_000_000,
        packets: [1, 0],
        bytes: [80, 0],
        ..Default::default()
    };
    store.consume(&[r.clone()], 61_000_000).unwrap();
    store.flush().unwrap();
    let blocker = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    r.sequence = 2;
    r.packets = [3, 0];
    r.bytes = [220, 0];
    store.consume(&[r.clone()], 62_000_000).unwrap();
    let started = std::time::Instant::now();
    assert!(store.flush().is_err());
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
    assert_eq!(store.query()["packets"], serde_json::json!([3, 0]));
    assert_eq!(
        store.query()["persistence"]["packets"],
        serde_json::json!([1, 0])
    );
    assert!(store.query()["save_error"].is_string());
    blocker.execute_batch("ROLLBACK").unwrap();
    store.flush().unwrap();
    store.close().unwrap();
    drop(store);
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[r.clone(), r], 63_000_000).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([3, 0]));
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    drop(store);
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn instance_reuse_sequence_gaps_and_backwards_wall_clock_do_not_mix_cumulative_values() {
    let root = std::env::temp_dir().join(format!("t22-clock-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let mut store = ObservationStore::open(&root.join("overall.json")).unwrap();
    let mut r = FlowRecord {
        generation: 5,
        incarnation: 1,
        sequence: 1,
        first_seen: 10,
        last_seen: 20,
        activity_utc_us: 121_000_000,
        packets: [2, 1],
        bytes: [120, 60],
        ..Default::default()
    };
    store.consume(&[r.clone()], 130_000_000).unwrap();
    r.sequence = 3;
    r.last_seen = 30;
    r.activity_utc_us = 59_000_000;
    r.clock_changed = true;
    r.packets = [4, 3];
    r.bytes = [240, 180];
    store.consume(&[r.clone()], 140_000_000).unwrap();
    assert_eq!(
        store.query()["minutes"]["0"]["packets"],
        serde_json::json!([2, 2])
    );
    assert_eq!(
        store.query()["minutes"]["120"]["packets"],
        serde_json::json!([2, 1])
    );
    let stale = r.clone();
    r.incarnation = 2;
    r.sequence = 1;
    r.packets = [1, 0];
    r.bytes = [80, 0];
    store.consume(&[r.clone(), stale], 150_000_000).unwrap();
    r.generation = 6;
    store.consume(&[r], 160_000_000).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([6, 3]));
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    store.close().unwrap();
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn corrupt_store_is_not_replaced_and_counter_overflow_cannot_partially_commit() {
    let root = std::env::temp_dir().join(format!("t22-invalid-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    std::fs::write(&path, b"interrupted external corruption").unwrap();
    assert!(ObservationStore::open(&path).is_err());
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"interrupted external corruption"
    );
    std::fs::remove_file(&path).unwrap();
    let mut store = ObservationStore::open(&path).unwrap();
    let r = FlowRecord {
        generation: 1,
        incarnation: 1,
        sequence: 1,
        activity_utc_us: 1,
        packets: [u64::MAX, 0],
        bytes: [u64::MAX, 0],
        ..Default::default()
    };
    store.consume(&[r], 1).unwrap();
    let another = FlowRecord {
        generation: 2,
        incarnation: 1,
        sequence: 1,
        activity_utc_us: 2,
        packets: [1, 1],
        bytes: [1, 1],
        ..Default::default()
    };
    assert!(store.consume(&[another], 2).is_err());
    assert_eq!(store.query()["packets"], serde_json::json!([u64::MAX, 0]));
    assert_eq!(store.query()["baselines"], 1);
    assert_eq!(store.query()["save_error"], "packet_overflow");
    store.flush().unwrap();
    drop(store);
    let restored = ObservationStore::open(&path).unwrap();
    assert_eq!(
        restored.query()["packets"],
        serde_json::json!([u64::MAX, 0])
    );
    assert_eq!(restored.query()["baselines"], 1);
    drop(restored);
    std::fs::remove_dir_all(root).unwrap();
}

fn legacy_fixture(record: &FlowRecord) -> serde_json::Value {
    serde_json::json!({"schema":1,
        "baselines": {"8:0:0":{"record":record,"first_end_us":170_000_000}},
        "recent":{"00000000000170000000:8:0:0:1":{"record":record,"first_end_us":170_000_000}},
        "minutes":{"60":{"packets":[4,2],"bytes":[240,120]}},
        "totals":{"packets":[4,2],"bytes":[240,120]},"ended":1,"accepted":2,"rejected":1,
        "gaps":3,"clock_changes":1,"open_session":false,"recoveries":2,
        "first_activity_us":61_000_000,"last_activity_us":119_000_000})
}

#[test]
fn legacy_migration_is_once_preserves_history_and_rejects_inconsistent_input() {
    let root = std::env::temp_dir().join(format!("e02-migration-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let r = FlowRecord {
        generation: 8,
        incarnation: 1,
        sequence: 2,
        ended: true,
        activity_utc_us: 119_000_000,
        packets: [4, 2],
        bytes: [240, 120],
        ..Default::default()
    };
    let mut fixture = legacy_fixture(&r);
    fixture["totals"]["packets"] = serde_json::json!([3, 2]);
    let invalid = serde_json::to_vec(&fixture).unwrap();
    std::fs::write(&path, &invalid).unwrap();
    assert!(ObservationStore::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), invalid);
    let bytes = serde_json::to_vec(&legacy_fixture(&r)).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let mut store = ObservationStore::open(&path).unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([4, 2]));
    assert_eq!(q["bytes"], serde_json::json!([240, 120]));
    assert_eq!(q["minutes"]["60"]["packets"], serde_json::json!([4, 2]));
    assert_eq!(q["coverage"]["gaps"], 3);
    assert_eq!(q["coverage"]["clock_changes"], 1);
    assert_eq!(q["coverage"]["recoveries"], 2);
    assert_eq!(q["recent_count"], 1);
    assert_eq!(q["ended"], 1);
    store.consume(&[r], 180_000_000).unwrap();
    store.close().unwrap();
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    // A successful migration marker owns future history even if an obsolete
    // predecessor is later damaged: no second import or empty reset.
    std::fs::write(&path, b"obsolete legacy").unwrap();
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([4, 2]));
    assert_eq!(store.query()["rejected"], 2);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn transaction_failure_after_baseline_write_leaves_no_partial_committed_lifecycle() {
    let root = std::env::temp_dir().join(format!("e02-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let injector = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    injector.execute_batch("CREATE TRIGGER fail_minute BEFORE INSERT ON observation WHEN NEW.kind=3 BEGIN SELECT RAISE(ABORT,'test minute failure'); END").unwrap();
    let r = FlowRecord {
        generation: 1,
        incarnation: 1,
        sequence: 1,
        ended: true,
        activity_utc_us: 61_000_000,
        packets: [3, 2],
        bytes: [180, 120],
        ..Default::default()
    };
    store.consume(&[r.clone()], 62_000_000).unwrap();
    assert!(store.flush().is_err());
    assert_eq!(store.query()["packets"], serde_json::json!([3, 2]));
    assert_eq!(
        store.query()["persistence"]["packets"],
        serde_json::json!([0, 0])
    );
    drop(store);
    injector.execute_batch("DROP TRIGGER fail_minute").unwrap();
    let mut store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([0, 0]));
    assert_eq!(store.query()["baselines"], 0);
    assert_eq!(store.query()["ended"], 0);
    assert_eq!(store.query()["stored_minute_count"], 0);
    store.consume(&[r], 62_000_000).unwrap();
    store.close().unwrap();
    drop(store);
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([3, 2]));
    assert_eq!(store.query()["ended"], 1);
    drop(store);
    drop(injector);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_migration_retries_original_without_partial_history() {
    let root = std::env::temp_dir().join(format!("e02-import-failure-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let r = FlowRecord {
        generation: 8,
        incarnation: 1,
        sequence: 2,
        ended: true,
        activity_utc_us: 119_000_000,
        packets: [4, 2],
        bytes: [240, 120],
        ..Default::default()
    };
    let bytes = serde_json::to_vec(&legacy_fixture(&r)).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let injector = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    injector.execute_batch("CREATE TABLE observation(kind INTEGER NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(kind,key)) WITHOUT ROWID;
        CREATE TRIGGER fail_import BEFORE INSERT ON observation WHEN NEW.kind=3 BEGIN SELECT RAISE(ABORT,'test import failure'); END").unwrap();
    assert!(ObservationStore::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    injector.execute_batch("DROP TRIGGER fail_import").unwrap();
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([4, 2]));
    assert_eq!(store.query()["baselines"], 1);
    assert_eq!(store.query()["ended"], 1);
    drop(store);
    drop(injector);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dirty_capacity_during_lock_failure_is_bounded_and_loss_is_explicit() {
    let root = std::env::temp_dir().join(format!("e02-bounded-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let blocker = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut failures = 0;
    for slot in 0..5000 {
        let r = FlowRecord {
            generation: 1,
            slot,
            incarnation: 1,
            sequence: 1,
            activity_utc_us: 61_000_000,
            packets: [1, 0],
            bytes: [60, 0],
            ..Default::default()
        };
        failures += store.consume(&[r], 62_000_000).is_err() as usize;
    }
    let q = store.query();
    assert!(failures > 0);
    assert!(
        q["persistence"]["pending_rows"].as_u64().unwrap()
            <= q["limits"]["dirty_rows"].as_u64().unwrap()
    );
    assert!(q["packets"][0].as_u64().unwrap() < 5000);
    assert_eq!(q["persistence"]["packets"], serde_json::json!([0, 0]));
    assert_eq!(q["coverage"]["incomplete"], true);
    blocker.execute_batch("ROLLBACK").unwrap();
    store.close().unwrap();
    drop(store);
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], q["packets"]);
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    drop(store);
    drop(blocker);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_exit_discards_only_uncommitted_tail() {
    if let Ok(path) = std::env::var("E02_CRASH_STORE") {
        let mut store = ObservationStore::open(std::path::Path::new(&path)).unwrap();
        let mut r = FlowRecord {
            generation: 2,
            incarnation: 1,
            sequence: 1,
            activity_utc_us: 61_000_000,
            packets: [4, 2],
            bytes: [240, 120],
            ..Default::default()
        };
        store.consume(&[r.clone()], 62_000_000).unwrap();
        store.flush().unwrap();
        r.sequence = 2;
        r.packets = [8, 5];
        r.bytes = [480, 300];
        store.consume(&[r], 63_000_000).unwrap();
        std::process::exit(0); // Deliberately skips Rust and SQLite destructors.
    }
    let root = std::env::temp_dir().join(format!("e02-crash-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    assert!(std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "process_exit_discards_only_uncommitted_tail",
            "--nocapture"
        ])
        .env("E02_CRASH_STORE", &path)
        .status()
        .unwrap()
        .success());
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([4, 2]));
    assert_eq!(store.query()["bytes"], serde_json::json!([240, 120]));
    assert_eq!(
        store.query()["minutes"]["60"]["packets"],
        serde_json::json!([4, 2])
    );
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn checkpoint_failure_distinguishes_durable_commit_from_maintenance_and_retries() {
    let root = std::env::temp_dir().join(format!("e02-checkpoint-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let reader = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM observation")
        .unwrap();
    let r = FlowRecord {
        generation: 3,
        incarnation: 1,
        sequence: 1,
        activity_utc_us: 61_000_000,
        packets: [5, 3],
        bytes: [300, 180],
        ..Default::default()
    };
    store.consume(&[r], 62_000_000).unwrap();
    assert!(store.flush().is_err());
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([5, 3]));
    assert_eq!(q["persistence"]["packets"], serde_json::json!([5, 3]));
    assert_eq!(q["save_error"], "observation_checkpoint_busy");
    assert!(store.flush().is_err());
    assert!(
        store.has_pending(),
        "repeated checkpoint failure still needs idle work"
    );
    reader.execute_batch("ROLLBACK").unwrap();
    assert!(store.wait_timeout_ms() > 0);
    std::thread::sleep(std::time::Duration::from_millis(
        store.wait_timeout_ms() as u64 + 10,
    ));
    store.consume(&[], 63_000_000).unwrap();
    assert!(!store.has_pending());
    assert_eq!(store.query()["persistence"]["maintenance_pending"], false);
    assert!(store.query()["save_error"].is_null());
    assert!(store.query()["persistence"]["error"].is_null());
    assert_eq!(store.query()["packets"], serde_json::json!([5, 3]));
    assert!(
        store.query()["persistence"]["checkpoints"]
            .as_u64()
            .unwrap()
            > 0
    );
    drop(store);
    drop(reader);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn interrupted_migration_reopens_original_after_transaction_recovery() {
    if let Ok(path) = std::env::var("E02_MIGRATION_CRASH_STORE") {
        let _store = ObservationStore::open(std::path::Path::new(&path)).unwrap();
        panic!("migration should be interrupted inside its transaction");
    }
    let root = std::env::temp_dir().join(format!("e02-migration-crash-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let r = FlowRecord {
        generation: 8,
        incarnation: 1,
        sequence: 2,
        ended: true,
        activity_utc_us: 119_000_000,
        packets: [4, 2],
        bytes: [240, 120],
        ..Default::default()
    };
    let bytes = serde_json::to_vec(&legacy_fixture(&r)).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let database = path.with_extension("sqlite3");
    let injector = rusqlite::Connection::open(&database).unwrap();
    // A finite, deliberately slow SQLite trigger gives the parent a witness
    // that Product is inside the import transaction before sending SIGKILL.
    injector.execute_batch("CREATE TABLE observation(kind INTEGER NOT NULL,key TEXT NOT NULL,value BLOB NOT NULL,PRIMARY KEY(kind,key)) WITHOUT ROWID;
        CREATE TRIGGER slow_import BEFORE INSERT ON observation WHEN NEW.kind=3 BEGIN
        SELECT sum(n) FROM (WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM numbers WHERE n<100000000) SELECT n FROM numbers); END").unwrap();
    drop(injector);
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "interrupted_migration_reopens_original_after_transaction_recovery",
            "--nocapture",
        ])
        .env("E02_MIGRATION_CRASH_STORE", &path)
        .spawn()
        .unwrap();
    let journal = std::path::PathBuf::from(format!("{}-journal", database.display()));
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::fs::metadata(&journal).map_or(0, |m| m.len()) == 0
        && std::time::Instant::now() < deadline
    {
        assert!(
            child.try_wait().unwrap().is_none(),
            "child completed before interruption"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let transaction_started = std::fs::metadata(&journal).map_or(0, |m| m.len()) > 0;
    child.kill().unwrap();
    assert!(!child.wait().unwrap().success());
    assert!(transaction_started, "durable rollback journal witness");
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let injector = rusqlite::Connection::open(&database).unwrap();
    injector.execute_batch("DROP TRIGGER slow_import").unwrap();
    drop(injector);
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([4, 2]));
    assert_eq!(store.query()["bytes"], serde_json::json!([240, 120]));
    assert_eq!(store.query()["ended"], 1);
    assert_eq!(store.query()["baselines"], 1);
    assert_eq!(store.query()["coverage"]["gaps"], 3);
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}
