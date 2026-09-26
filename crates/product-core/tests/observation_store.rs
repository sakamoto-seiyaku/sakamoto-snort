use sakamoto_product_core::observation::FlowRecord;
use sakamoto_product_core::observation_store::ObservationStore;

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
fn failed_write_and_interrupted_pending_file_preserve_the_committed_baseline() {
    let root = std::env::temp_dir().join(format!("t22-failure-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
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
    std::fs::create_dir(path.with_extension("pending")).unwrap();
    r.sequence = 2;
    r.packets = [3, 0];
    r.bytes = [220, 0];
    assert!(store.consume(&[r.clone()], 62_000_000).is_err());
    assert_eq!(store.query()["packets"], serde_json::json!([1, 0]));
    assert!(store.query()["save_error"].is_string());
    std::fs::remove_dir(path.with_extension("pending")).unwrap();
    std::fs::write(path.with_extension("pending"), b"partial interrupted write").unwrap();
    drop(store);
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[r.clone(), r], 63_000_000).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([3, 0]));
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    drop(store);
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
