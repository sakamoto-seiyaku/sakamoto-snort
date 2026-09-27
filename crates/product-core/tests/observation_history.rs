use sakamoto_product_core::observation::{Attribution, FlowRecord};
use sakamoto_product_core::observation_store::ObservationStore;

fn ended(slot: u32, version: u64, name: &str, action: u8, minute: u64) -> FlowRecord {
    FlowRecord {
        generation: 26, owner: 0, slot, incarnation: 1, sequence: 1,
        first_seen: slot as u64 + 1, last_seen: slot as u64 + 1,
        activity_utc_us: minute * 1_000_000, ended: true,
        protocol: 17, packets: [1, 0], bytes: [72, 0],
        attribution: [Attribution {
            segment: 1, activity_utc_us: minute * 1_000_000,
            policy_generation: 26, policy_revision: minute, policy_hash: minute + 200,
            winner: version, uid: 100, declared_action: action, actual_action: action,
            valid: true, name: name.into(), ..Default::default()
        }, Attribution::default()], ..Default::default()
    }
}

#[test]
fn full_versions_names_actions_and_missing_metadata_survive_end_and_reopen() {
    let root = std::env::temp_dir().join(format!("t26-history-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let old = 0xfedc_ba98_7654_0001;
    let renamed = 0xfedc_ba98_7654_0002;
    let unknown = 0xabcd_ef01_2345_0001;
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[
        ended(1, old, "before rename", 2, 61),
        ended(2, old, "", 2, 61),
        ended(3, renamed, "after rename", 1, 62),
        ended(4, unknown, "", 1, 63),
    ], 63_000_000).unwrap();
    let check = |q: serde_json::Value| {
        assert_eq!(q["packets"], serde_json::json!([4, 0]));
        assert_eq!(q["ended"], 4);
        assert_eq!(q["rule_metadata_count"], 2);
        assert_eq!(q["rule_metadata_conflicts"], 0);
        let rows = q["rule_windows"].as_object().unwrap();
        let old_row = rows.values().find(|v| v["interpretation"]["version"] == old.to_string()).unwrap();
        assert_eq!(old_row["counts"]["packets"], serde_json::json!([2, 0]));
        assert_eq!(old_row["attribution"]["name"], "before rename");
        assert_eq!(old_row["interpretation"]["actual_action"], 2);
        assert_eq!(old_row["interpretation"]["logical_identity"], "fedcba987654");
        assert_eq!(old_row["interpretation"]["revision"], 1);
        assert_eq!(old_row["interpretation"]["conditions"]["status"], "unavailable");
        assert!(rows.values().any(|v| v["interpretation"]["version"] == renamed.to_string()
            && v["interpretation"]["name"] == "after rename"
            && v["interpretation"]["actual_action"] == 1));
        let recent = q["recent"].as_object().unwrap();
        assert!(recent.values().any(|v| v["record"]["attribution"][0]["interpretation"]["name_status"] == "linked"
            && v["record"]["attribution"][0]["interpretation"]["name"] == "before rename"));
        assert!(recent.values().any(|v| v["record"]["attribution"][0]["interpretation"]["version"] == unknown.to_string()
            && v["record"]["attribution"][0]["interpretation"]["name_status"] == "unavailable"
            && v["record"]["attribution"][0]["interpretation"]["name"].is_null()));
        assert!(recent.values().all(|v| v["record"]["attribution"][0]["interpretation"]["scope"] == "last_directional_segment"));
    };
    check(store.query());
    store.close().unwrap();
    drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    check(reopened.query());
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn conflicting_name_does_not_fill_missing_history_with_latest_name() {
    let root = std::env::temp_dir().join(format!("t26-conflict-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let version = 0xabcd_ef01_2345_0001;
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[ended(1, version, "first", 2, 61)], 61_000_000).unwrap();
    store.consume(&[ended(2, version, "second", 2, 62)], 62_000_000).unwrap();
    store.consume(&[ended(3, version, "", 2, 63)], 63_000_000).unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([3, 0]));
    assert_eq!(q["rule_metadata_conflicts"], 1);
    assert!(q["rule_windows"].as_object().unwrap().values().any(|row|
        row["attribution"]["name"] == "first"));
    assert!(q["rule_windows"].as_object().unwrap().values().any(|row|
        row["attribution"]["name"] == "second"));
    assert!(q["recent"].as_object().unwrap().values().any(|v|
        v["record"]["attribution"][0]["interpretation"]["name_status"] == "conflict"
        && v["record"]["attribution"][0]["interpretation"]["name"].is_null()));
    store.close().unwrap(); drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["rule_metadata_conflicts"], 1);
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn same_window_name_conflict_keeps_existing_history_unchanged() {
    let root = std::env::temp_dir().join(format!("t26-window-conflict-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[ended(1, 65537, "first", 1, 61)], 61_000_000).unwrap();
    let before = store.query()["rule_windows"].clone();
    assert_eq!(store.consume(&[ended(2, 65537, "second", 1, 61)], 61_000_001)
        .unwrap_err(), "observation_rule_reference_conflict");
    let q = store.query();
    assert_eq!(q["rule_windows"], before);
    assert_eq!(q["packets"], serde_json::json!([1, 0]));
    assert_eq!(q["coverage"]["incomplete"], true);
    store.close().unwrap(); drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn full_name_table_reports_missing_links_without_losing_packet_counts() {
    let root = std::env::temp_dir().join(format!("t26-name-cap-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut seed = ObservationStore::open(&path).unwrap();
    seed.close().unwrap(); drop(seed);
    let mut db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    {
        let mut insert = tx.prepare("INSERT INTO observation(kind,key,value) VALUES(8,?1,?2)").unwrap();
        for i in 1..=65536u64 {
            let version = (i << 16) | 1;
            insert.execute(rusqlite::params![version.to_string(), b"\"known\""]).unwrap();
        }
    }
    tx.commit().unwrap(); drop(db);
    let mut store = ObservationStore::open(&path).unwrap();
    let new_version = (65537u64 << 16) | 1;
    store.consume(&[ended(1, new_version, "overflow", 1, 61)], 61_000_000).unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([1, 0]));
    assert_eq!(q["rule_metadata_count"], 65536);
    assert_eq!(q["rule_metadata_association_misses"], 1);
    assert_eq!(q["coverage"]["rule_metadata_incomplete"], true);
    assert!(q["rule_windows"].as_object().unwrap().values().any(|row|
        row["interpretation"]["name"] == "overflow"));
    store.close().unwrap(); drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([1, 0]));
    assert_eq!(reopened.query()["rule_metadata_association_misses"], 1);
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn invalid_recent_attribution_never_displays_stale_name_or_action() {
    let root = std::env::temp_dir().join(format!("t26-invalid-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut record = ended(1, 65537, "stale", 2, 61);
    record.attribution[0].valid = false;
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[record], 61_000_000).unwrap();
    let q = store.query();
    assert_eq!(q["packets"], serde_json::json!([1, 0]));
    assert_eq!(q["attribution_unknown"]["packets"], serde_json::json!([1, 0]));
    assert_eq!(q["rule_window_count"], 0);
    assert_eq!(q["rule_metadata_count"], 0);
    let recent = q["recent"].as_object().unwrap().values().next().unwrap();
    let interpreted = &recent["record"]["attribution"][0]["interpretation"];
    assert!(interpreted["version"].is_null());
    assert!(interpreted["name"].is_null());
    assert!(interpreted["actual_action"].is_null());
    assert_eq!(interpreted["conditions"]["reason"], "attribution_unavailable");
    store.close().unwrap(); drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    let persisted = reopened.query();
    assert!(persisted["recent"].as_object().unwrap().values().next().unwrap()
        ["record"]["attribution"][0]["interpretation"]["name"].is_null());
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn failed_rule_metadata_write_cannot_commit_counts_or_lifecycle_alone() {
    let root = std::env::temp_dir().join(format!("t26-atomic-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let injector = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    injector.execute_batch("CREATE TRIGGER fail_rule_name BEFORE INSERT ON observation
        WHEN NEW.kind=8 BEGIN SELECT RAISE(ABORT,'test rule metadata failure'); END").unwrap();
    let record = ended(1, 65537, "saved name", 2, 61);
    store.consume(&[record.clone()], 61_000_000).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([1, 0]));
    assert_eq!(store.query()["rule_metadata_count"], 1);
    assert!(store.flush().is_err());
    assert_eq!(store.query()["persistence"]["pending"], true);
    drop(store); // Abnormal consumer death loses only the pending batch.
    injector.execute_batch("DROP TRIGGER fail_rule_name").unwrap();
    drop(injector);
    let mut reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([0, 0]));
    assert_eq!(reopened.query()["rule_window_count"], 0);
    assert_eq!(reopened.query()["recent_count"], 0);
    assert_eq!(reopened.query()["rule_metadata_count"], 0);
    assert_eq!(reopened.query()["coverage"]["incomplete"], true);
    reopened.consume(&[record], 61_000_001).unwrap();
    reopened.flush().unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([1, 0]));
    assert_eq!(reopened.query()["rule_metadata_count"], 1);
    assert_eq!(reopened.query()["rule_window_count"], 1);
    assert_eq!(reopened.query()["recent_count"], 1);
    reopened.close().unwrap(); drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn duplicate_end_does_not_extend_recent_lifetime_or_remove_active_baseline() {
    let root = std::env::temp_dir().join(format!("t26-retain-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    let first_us = 61_000_000;
    let first = ended(1, 65537, "first", 1, 61);
    store.consume(&[first.clone()], first_us).unwrap();
    store.consume(&[first], first_us + 1).unwrap(); // Duplicate END is rejected.
    assert_eq!(store.query()["recent_count"], 1);
    let later_us = first_us + 24 * 60 * 60 * 1_000_000;
    let later = ended(2, 131073, "later", 1, later_us / 1_000_000);
    store.consume(&[later], later_us).unwrap();
    let q = store.query();
    assert_eq!(q["recent_count"], 1);
    assert_eq!(q["baselines"], 2); // Old cumulative state is still needed for dedup.
    assert_eq!(q["rule_window_count"], 2); // The coarse effects outlive END detail.
    assert_eq!(q["rule_metadata_count"], 2);
    assert_eq!(q["packets"], serde_json::json!([2, 0]));
    assert!(q["recent"].as_object().unwrap().values().all(|recent|
        recent["record"]["attribution"][0]["interpretation"]["name"] == "later"));
    store.close().unwrap(); drop(store);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["recent_count"], 1);
    assert_eq!(reopened.query()["baselines"], 2);
    drop(reopened);
    std::fs::remove_dir_all(root).unwrap();
}
