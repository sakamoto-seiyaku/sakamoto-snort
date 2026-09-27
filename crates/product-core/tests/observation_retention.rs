use sakamoto_product_core::observation::{Attribution, FlowRecord};
use sakamoto_product_core::observation_store::ObservationStore;

const MINUTE: u64 = 60_000_000;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

fn test_path(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("t27-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    root.join("overall.json")
}

fn record(utc: u64, slot: u32, incarnation: u64, packets: u64, ended: bool) -> FlowRecord {
    let a = Attribution {
        valid: true, segment: 1, activity_utc_us: utc,
        policy_generation: 5, policy_revision: 7, policy_hash: 9,
        uid: 42, winner: 65537, name: "recorded".into(),
        declared_action: 1, actual_action: 1,
        protocol_set: (1 << 0) | (1 << 5), protocols_available: true,
        ..Default::default()
    };
    FlowRecord {
        generation: 5, owner: 0, slot, incarnation, sequence: 1,
        first_seen: 1, last_seen: 1, activity_utc_us: utc,
        protocol: 17, packets: [packets, 0], bytes: [packets * 64, 0],
        attribution: [a, Attribution::default()], ended,
        ..Default::default()
    }
}

#[test]
fn all_views_roll_up_once_and_keep_active_delta_after_restart() {
    let path = test_path("tiers");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    let mut flow = record(at, 1, 1, 2, false);
    store.consume(&[flow.clone()], at).unwrap();
    store.flush().unwrap();
    store.consume(&[], at + 48 * HOUR + 49_000_000).unwrap();
    assert_eq!(store.query()["stored_minute_count"], 1);
    store.consume(&[], at + 48 * HOUR + MINUTE).unwrap();
    let q = store.query();
    assert!(q["minutes"].as_object().unwrap().is_empty());
    assert_eq!(q["hour_windows"]["counts"]["overall"], 1);
    assert_eq!(q["hour_windows"]["counts"]["applications"], 1);
    assert_eq!(q["hour_windows"]["counts"]["rules"], 1);
    assert_eq!(q["hour_windows"]["counts"]["protocols"], 3);
    assert_eq!(q["hour_windows"]["protocol_windows"].as_object().unwrap().values()
        .find(|v| v["layer"] == "l7" && v["protocol_id"] == 1001).unwrap()["share"]["packets"][0], 1.0);
    store.flush().unwrap();
    drop(store);

    let mut store = ObservationStore::open(&path).unwrap();
    flow.sequence = 2;
    flow.last_seen = 2;
    flow.packets[0] = 5;
    flow.bytes[0] = 320;
    store.consume(&[flow.clone(), flow.clone()], at + 48 * HOUR + 2 * MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([5, 0]));
    assert_eq!(store.query()["hour_windows"]["overall"].as_object().unwrap().values()
        .next().unwrap()["packets"], serde_json::json!([5, 0]));
    store.consume(&[], at + 30 * DAY + 3_000_000_000).unwrap();
    assert_eq!(store.query()["hour_windows"]["counts"]["overall"], 1);
    store.consume(&[], at + 30 * DAY + HOUR).unwrap();
    assert_eq!(store.query()["day_windows"]["counts"]["overall"], 1);
    assert_eq!(store.query()["hour_windows"]["counts"]["overall"], 0);
    store.flush().unwrap();
    drop(store);

    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[], at + 180 * DAY + DAY - 2 * MINUTE).unwrap();
    assert_eq!(store.query()["day_windows"]["counts"]["overall"], 1);
    store.consume(&[], at + 180 * DAY + DAY).unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([5, 0]));
    assert_eq!(q["coverage"]["evicted"]["packets"], serde_json::json!([5, 0]));
    assert_eq!(q["coverage"]["incomplete"], true);
    assert_eq!(q["baselines"], 1);
    store.consume(&[], at + 2 * DAY).unwrap(); // backward clock does not restore history
    assert_eq!(store.query()["coverage"]["evicted"]["packets"], serde_json::json!([5, 0]));
    flow.sequence = 3;
    flow.last_seen = 3;
    flow.packets[0] = 7;
    flow.bytes[0] = 448;
    flow.activity_utc_us = at + 180 * DAY + DAY + MINUTE;
    flow.attribution[0].activity_utc_us = flow.activity_utc_us;
    store.consume(&[flow.clone(), flow], at + 180 * DAY + DAY + MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([7, 0]));
    assert_eq!(store.query()["coverage"]["evicted"]["packets"], serde_json::json!([5, 0]));
    assert_eq!(store.query()["stored_minute_count"], 1);
    store.flush().unwrap();
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["coverage"]["evicted"]["packets"], serde_json::json!([5, 0]));
    assert_eq!(reopened.query()["packets"], serde_json::json!([7, 0]));
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn first_end_expiry_compacts_baseline_without_recounting_late_duplicate() {
    let path = test_path("ends");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    let ended = record(at, 1, 1, 4, true);
    store.consume(&[ended.clone()], at).unwrap();
    store.flush().unwrap();
    store.consume(&[ended.clone()], at + HOUR).unwrap();
    assert_eq!(store.query()["recent_count"], 1);
    store.consume(&[], at + DAY + MINUTE).unwrap();
    let q = store.query();
    assert_eq!(q["recent_count"], 0);
    assert_eq!(q["baselines"], 0);
    assert_eq!(q["end_marker_count"], 1);
    store.flush().unwrap();
    drop(store);

    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[ended.clone()], at + DAY + 2 * MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([4, 0]));
    let next = record(at + DAY + 3 * MINUTE, 1, 2, 2, false);
    store.consume(&[next], at + DAY + 3 * MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([6, 0]));
    assert_eq!(store.query()["baselines"], 1);
    assert_eq!(store.query()["end_marker_count"], 0);
    store.flush().unwrap();
    drop(store);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn scaled_disk_pressure_reclaims_ended_detail_and_preserves_exact_totals() {
    let path = test_path("pressure");
    let config = serde_json::json!({
        "minute_age_us": 48 * HOUR, "hour_age_us": 30 * DAY,
        "day_age_us": 180 * DAY, "end_age_us": DAY,
        "budget_bytes": 1024 * 1024, "working_reserve_bytes": 64 * 1024,
        "clock_offset_us": 0,
    });
    std::fs::write(path.with_extension("retention-test.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    for slot in 0..500 {
        store.consume(&[record(at, slot, 1, 1, true)], at + slot as u64 * 1000).unwrap();
    }
    store.flush().unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([500, 0]));
    assert!(q["storage_space"]["within_budget"].as_bool().unwrap());
    assert!(q["end_marker_count"].as_u64().unwrap() > 0,
        "pressure must compact ended baselines: {q}");
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([500, 0]));
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn quota_rechecks_freed_pages_before_promoting_or_evicting_history() {
    let path = test_path("minimal-pressure");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[record(at, 1, 1, 2, true)], at).unwrap();
    store.close().unwrap(); drop(store);
    let size = std::fs::metadata(path.with_extension("sqlite3")).unwrap().len();
    let config = serde_json::json!({"minute_age_us":48 * HOUR,
        "hour_age_us":30 * DAY,"day_age_us":180 * DAY,"end_age_us":DAY,
        "budget_bytes":(size * 3).max(64 * 1024),
        "working_reserve_bytes":0,"clock_offset_us":0});
    std::fs::write(path.with_extension("retention-test.json"),
        serde_json::to_vec(&config).unwrap()).unwrap();
    let mut store = ObservationStore::open(&path).unwrap();
    for _ in 0..10 {
        if !store.query()["persistence"]["maintenance_pending"].as_bool().unwrap() { break; }
        store.flush().unwrap();
    }
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([2, 0]));
    assert_eq!(q["recent_count"], 0);
    assert_eq!(q["stored_minute_count"], 1);
    assert_eq!(q["hour_windows"]["counts"]["overall"], 0);
    assert_eq!(q["coverage"]["evicted"]["packets"], serde_json::json!([0, 0]));
    drop(store);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn scaled_quota_promotes_old_minutes_before_shortening_aggregate_coverage() {
    let path = test_path("promote");
    let config = serde_json::json!({
        "minute_age_us": 48 * HOUR, "hour_age_us": 30 * DAY,
        "day_age_us": 180 * DAY, "end_age_us": DAY,
        "budget_bytes": 1024 * 1024, "working_reserve_bytes": 64 * 1024,
        "clock_offset_us": 0,
    });
    std::fs::write(path.with_extension("retention-test.json"), serde_json::to_vec(&config).unwrap()).unwrap();
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    let mut flow = record(at, 1, 1, 1, false);
    for i in 0..1000u64 {
        flow.sequence = i + 1;
        flow.last_seen = i + 1;
        flow.packets[0] = i + 1;
        flow.bytes[0] = (i + 1) * 64;
        flow.activity_utc_us = at + i * MINUTE;
        flow.attribution[0].activity_utc_us = flow.activity_utc_us;
        store.consume(&[flow.clone()], flow.activity_utc_us).unwrap_or_else(|error|
            panic!("record {i}: {error}; state={}", serde_json::json!({
                "space":store.query()["storage_space"],
                "dirty":store.query()["persistence"]["pending_rows"],
                "minutes":store.query()["stored_minute_count"],
                "hours":store.query()["hour_windows"]["counts"]["overall"],
                "days":store.query()["day_windows"]["counts"]["overall"]})));
    }
    store.flush().unwrap_or_else(|error|
        panic!("final flush: {error}; state={}", serde_json::json!({
            "space":store.query()["storage_space"],
            "dirty":store.query()["persistence"]["pending_rows"],
            "minutes":store.query()["stored_minute_count"],
            "hours":store.query()["hour_windows"]["counts"]["overall"],
            "days":store.query()["day_windows"]["counts"]["overall"],
            "transition":store.query()["retention_transition"],
            "evicted":store.query()["coverage"]["evicted"]})));
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([1000, 0]));
    assert_eq!(q["baselines"], 1);
    assert!(q["hour_windows"]["counts"]["overall"].as_u64().unwrap() > 0,
        "quota must promote oldest minute rows: {q}");
    assert_eq!(q["coverage"]["evicted"]["packets"], serde_json::json!([0, 0]));
    assert!(q["storage_space"]["within_budget"].as_bool().unwrap());
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([1000, 0]));
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn interrupted_rollup_restarts_from_one_committed_layer() {
    let path = test_path("interrupted");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[record(at, 1, 1, 3, false)], at).unwrap();
    store.flush().unwrap();
    store.consume(&[], at + 48 * HOUR + MINUTE).unwrap();
    assert_eq!(store.query()["hour_windows"]["counts"]["overall"], 1);
    drop(store); // The prepared rollup and its deletions were never committed.

    let mut reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["minutes"].as_object().unwrap().len(), 1);
    assert_eq!(reopened.query()["hour_windows"]["counts"]["overall"], 0);
    assert_eq!(reopened.query()["packets"], serde_json::json!([3, 0]));
    reopened.consume(&[], at + 48 * HOUR + MINUTE).unwrap();
    reopened.flush().unwrap();
    drop(reopened);
    let final_store = ObservationStore::open(&path).unwrap();
    assert!(final_store.query()["minutes"].as_object().unwrap().is_empty());
    assert_eq!(final_store.query()["hour_windows"]["counts"]["overall"], 1);
    assert_eq!(final_store.query()["packets"], serde_json::json!([3, 0]));
    drop(final_store);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn blocked_and_unknown_contributions_follow_the_same_tiers() {
    let path = test_path("kinds");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut blocked = record(at, 2, 1, 1, true);
    blocked.blocked = true;
    blocked.end_reason = 2;
    blocked.attribution[0].winner = 131073;
    blocked.attribution[0].declared_action = 2;
    blocked.attribution[0].actual_action = 2;
    blocked.attribution[0].protocols_available = false;
    blocked.attribution[0].protocol_set = 0;
    let unknown = FlowRecord {
        generation: 5, owner: 0, slot: 3, incarnation: 1, sequence: 1,
        first_seen: 1, last_seen: 1, activity_utc_us: at,
        protocol: 17, packets: [3, 0], bytes: [192, 0],
        ..Default::default()
    };
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[record(at, 1, 1, 2, false), blocked, unknown], at).unwrap();
    store.consume(&[], at + 48 * HOUR + MINUTE).unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([6, 0]));
    assert_eq!(q["blocked"]["packets"], serde_json::json!([1, 0]));
    assert_eq!(q["hour_windows"]["counts"]["overall"], 1);
    assert_eq!(q["hour_windows"]["counts"]["attribution_unknown"], 1);
    assert_eq!(q["hour_windows"]["counts"]["applications"], 2);
    assert_eq!(q["hour_windows"]["counts"]["rules"], 2);
    assert_eq!(q["hour_windows"]["counts"]["protocols"], 5);
    assert_eq!(q["end_marker_count"], 1);
    assert_eq!(q["recent_count"], 0);
    store.flush().unwrap();
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([6, 0]));
    assert_eq!(reopened.query()["hour_windows"], q["hour_windows"]);
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn real_clock_forward_jump_cannot_age_history_by_180_days() {
    let path = test_path("clock-jump");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume_real(&[record(now, 1, 1, 2, false)], now).unwrap();
    store.flush().unwrap();
    store.tick_real(now + 181 * DAY).unwrap();
    assert_eq!(store.query()["stored_minute_count"], 1);
    assert_eq!(store.query()["coverage"]["retention_clock_held"], true);
    assert_eq!(store.query()["coverage"]["evicted"]["packets"], serde_json::json!([0, 0]));
    store.tick_real(now - DAY).unwrap();
    store.close().unwrap();
    drop(store);
    let mut reopened = ObservationStore::open(&path).unwrap();
    reopened.tick_real(now + 181 * DAY).unwrap();
    assert_eq!(reopened.query()["stored_minute_count"], 1);
    assert_eq!(reopened.query()["packets"], serde_json::json!([2, 0]));
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn retired_generation_markers_are_reclaimed_without_admitting_old_records() {
    let path = test_path("generation");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(5).unwrap();
    let ended = record(at, 1, 1, 3, true);
    store.consume(&[ended.clone()], at).unwrap();
    store.consume(&[], at + DAY + MINUTE).unwrap();
    assert_eq!(store.query()["end_marker_count"], 1);
    store.begin_generation(6).unwrap();
    assert_eq!(store.query()["end_marker_count"], 0);
    store.consume(&[ended], at + DAY + 2 * MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([3, 0]));
    let mut next = record(at + DAY + 3 * MINUTE, 1, 1, 2, false);
    next.generation = 6;
    store.consume(&[next], at + DAY + 3 * MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([5, 0]));
    store.flush().unwrap();
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([5, 0]));
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn generation_retirement_commits_in_bounded_pages() {
    let path = test_path("generation-pages");
    let at = 200 * DAY + MINUTE + 10_000_000;
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(5).unwrap();
    for slot in 0..600 {
        store.consume(&[record(at, slot, 1, 1, false)], at).unwrap();
    }
    store.flush().unwrap();
    store.begin_generation(6).unwrap();
    assert!(store.query()["baselines"].as_u64().unwrap() < 600);
    assert_eq!(store.query()["packets"], serde_json::json!([600, 0]));
    for _ in 0..10 {
        if store.query()["baselines"] == 0 { break; }
        store.flush().unwrap();
    }
    assert_eq!(store.query()["baselines"], 0);
    assert_eq!(store.query()["packets"], serde_json::json!([600, 0]));
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["baselines"], 0);
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
#[ignore = "run explicitly against an isolated copy of real Linux Product observations"]
fn real_linux_records_controlled_time_and_capacity() {
    let input = std::path::PathBuf::from(std::env::var("T27_LIVE_STORE_PATH").expect("real store"));
    let output = std::path::PathBuf::from(std::env::var("T27_LIVE_REPORT_DIR").expect("report dir"));
    std::fs::create_dir_all(&output).unwrap();
    let copy = |label: &str| {
        let dir = output.join(label);
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("overall.json");
        std::fs::copy(input.with_extension("sqlite3"), path.with_extension("sqlite3")).unwrap();
        if input.is_file() { std::fs::copy(&input, &path).unwrap(); }
        path
    };
    let age_path = copy("age");
    let mut store = ObservationStore::open(&age_path).unwrap();
    let before = store.query();
    assert!(before["packets"][0].as_u64().unwrap() > 0);
    assert!(before["rule_window_count"].as_u64().unwrap() > 0);
    let last = before["coverage"]["last_activity_us"].as_u64().unwrap();
    store.tick(last + 48 * HOUR + 2 * MINUTE).unwrap();
    store.flush().unwrap();
    let hourly = store.query();
    assert_eq!(hourly["packets"], before["packets"]);
    assert_eq!(hourly["stored_minute_count"], 0);
    assert!(hourly["hour_windows"]["counts"]["overall"].as_u64().unwrap() > 0);
    assert!(hourly["hour_windows"]["counts"]["rules"].as_u64().unwrap() > 0);
    store.close().unwrap(); drop(store);
    let mut store = ObservationStore::open(&age_path).unwrap();
    assert_eq!(store.query()["packets"], before["packets"]);
    store.tick(last + 30 * DAY + 2 * HOUR).unwrap();
    store.flush().unwrap();
    let daily = store.query();
    assert_eq!(daily["packets"], before["packets"]);
    assert!(daily["day_windows"]["counts"]["overall"].as_u64().unwrap() > 0);
    store.close().unwrap(); drop(store);
    let mut store = ObservationStore::open(&age_path).unwrap();
    store.tick(last + 180 * DAY + 2 * DAY).unwrap();
    store.flush().unwrap();
    let expired = store.query();
    assert_eq!(expired["packets"], before["packets"]);
    assert!(expired["day_windows"]["overall"].as_object().unwrap().is_empty());
    assert_eq!(expired["coverage"]["evicted"]["packets"], before["packets"]);
    store.close().unwrap(); drop(store);

    let pressure_path = copy("pressure");
    let db_size = std::fs::metadata(pressure_path.with_extension("sqlite3")).unwrap().len();
    let budget = (db_size + 4096) * 3 + 8192;
    let config = serde_json::json!({"minute_age_us": 48 * HOUR,
        "hour_age_us": 30 * DAY, "day_age_us": 180 * DAY,
        "end_age_us": DAY, "budget_bytes": budget,
        "working_reserve_bytes": 0, "clock_offset_us": 0});
    std::fs::write(pressure_path.with_extension("retention-test.json"),
        serde_json::to_vec(&config).unwrap()).unwrap();
    let mut store = ObservationStore::open(&pressure_path).unwrap();
    for _ in 0..40 {
        if !store.query()["persistence"]["maintenance_pending"].as_bool().unwrap() { break; }
        store.flush().unwrap();
    }
    let pressured = store.query();
    assert_eq!(pressured["packets"], before["packets"]);
    assert!(pressured["storage_space"]["within_budget"].as_bool().unwrap());
    assert!(pressured["recent_count"].as_u64().unwrap() < before["recent_count"].as_u64().unwrap()
        || pressured["hour_windows"]["counts"]["overall"].as_u64().unwrap() > 0
        || pressured["coverage"]["evicted"]["packets"][0].as_u64().unwrap() > 0);
    store.close().unwrap(); drop(store);
    let db = rusqlite::Connection::open(pressure_path.with_extension("sqlite3")).unwrap();
    let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(integrity, "ok");
    let pages: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    let page_size: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
    drop(db);
    let report = serde_json::json!({"source_store":input,"age":{
        "before":before,"hourly":hourly,"daily":daily,"expired":expired},
        "pressure":{"configuration":config,"result":pressured,
            "integrity":integrity,"page_count":pages,"page_size":page_size,
            "database_and_primary_index_bytes":pages * page_size}});
    std::fs::write(output.join("result.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
}

#[test]
#[ignore = "explicit SQLite batch and compaction cost comparison"]
fn compare_bounded_sqlite_batches_and_compaction_cost() {
    let output = std::path::PathBuf::from(std::env::var("T27_BATCH_REPORT_DIR")
        .expect("batch report directory"));
    std::fs::create_dir_all(&output).unwrap();
    let at = 200 * DAY + MINUTE + 10_000_000;
    let records: Vec<_> = (0..1000u32).map(|slot| {
        let mut row = record(at, slot, 1, 1, false);
        row.attribution[0].uid = slot + 100;
        row
    }).collect();
    let mut arms = Vec::new();
    for batch in [64usize, 256, 1000] {
        let path = output.join(format!("batch-{batch}/overall.json"));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut store = ObservationStore::open(&path).unwrap();
        let started = std::time::Instant::now();
        for chunk in records.chunks(batch) {
            store.consume(chunk, at).unwrap();
            store.flush().unwrap();
        }
        let ingestion_ms = started.elapsed().as_millis();
        let pre = store.query();
        let rollup_started = std::time::Instant::now();
        store.tick(at + 48 * HOUR + 2 * MINUTE).unwrap();
        for _ in 0..200 {
            if !store.query()["persistence"]["maintenance_pending"].as_bool().unwrap() { break; }
            store.flush().unwrap();
        }
        store.flush().unwrap();
        let rollup_ms = rollup_started.elapsed().as_millis();
        let mut query_us = Vec::new();
        for _ in 0..10 {
            let began = std::time::Instant::now();
            let response = store.query();
            assert_eq!(response["packets"], serde_json::json!([1000, 0]));
            query_us.push(began.elapsed().as_micros());
        }
        query_us.sort();
        let final_query = store.query();
        assert_eq!(final_query["hour_windows"]["counts"]["overall"], 1);
        assert_eq!(final_query["hour_windows"]["counts"]["applications"], 1000);
        store.close().unwrap(); drop(store);
        let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
        let pages: i64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
        let page_size: i64 = db.query_row("PRAGMA page_size", [], |r| r.get(0)).unwrap();
        let integrity: String = db.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
        assert_eq!(integrity, "ok");
        arms.push(serde_json::json!({"batch_records":batch,"ingestion_ms":ingestion_ms,
            "rollup_ms":rollup_ms,"query_us_median":query_us[5],"query_us_p90":query_us[9],
            "commits":final_query["persistence"]["commits"],
            "checkpoints":final_query["persistence"]["checkpoints"],
            "wal_peak_bytes":final_query["persistence"]["wal_peak_bytes"],
            "actual_bytes":final_query["storage_space"]["actual_bytes"],
            "database_and_index_bytes":pages * page_size,
            "pre_traffic":pre["packets"],"post_traffic":final_query["packets"],
            "integrity":integrity}));
    }
    std::fs::write(output.join("result.json"), serde_json::to_vec_pretty(&arms).unwrap()).unwrap();
    println!("t27_sqlite_batch_comparison {}", serde_json::json!(arms));
}
