//! External public-store boundary: real SQLite statement failure and process loss.
use sakamoto_product_core::observation::{Attribution, FlowRecord};
use sakamoto_product_core::observation_store::ObservationStore;
use std::path::Path;

fn record(sequence: u64, ended: bool) -> FlowRecord {
    let context = Attribution {
        segment: 1,
        activity_utc_us: 61_000_000,
        policy_generation: 77,
        policy_revision: 9,
        policy_hash: u64::MAX - 1,
        winner: u64::MAX - 65534,
        uid: 42,
        declared_action: 2,
        actual_action: 1,
        mode: 1,
        valid: true,
        name: "original observe rule".into(),
        ..Default::default()
    };
    FlowRecord {
        generation: 77,
        incarnation: 1,
        sequence,
        packets: [sequence, sequence],
        bytes: [sequence * 60, sequence * 80],
        ended,
        activity_utc_us: 61_000_000,
        attribution: [context.clone(), context],
        ..Default::default()
    }
}
fn same_views(left: &serde_json::Value, right: &serde_json::Value) {
    for field in [
        "packets",
        "bytes",
        "minutes",
        "application_windows",
        "rule_windows",
        "attribution_unknown",
        "baselines",
        "ended",
        "accepted",
    ] {
        assert_eq!(left[field], right[field], "atomic recovery field {field}");
    }
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "crash" {
        let mut store = ObservationStore::open(Path::new(&args[2])).unwrap();
        store.consume(&[record(2, true)], 62_000_000).unwrap();
        assert_eq!(store.query()["packets"], serde_json::json!([2, 2]));
        assert_eq!(
            store.query()["persistence"]["packets"],
            serde_json::json!([1, 1])
        );
        std::process::exit(86);
    }
    let root = Path::new(&args[1]);
    for kind in [4, 5] {
        let path = root.join(format!("kind-{kind}/overall.json"));
        let mut store = ObservationStore::open(&path).unwrap();
        store.consume(&[record(1, false)], 61_000_000).unwrap();
        store.flush().unwrap();
        let committed = store.query();
        let injector = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
        injector.execute_batch(&format!("CREATE TRIGGER fail_effect BEFORE UPDATE ON observation WHEN NEW.kind={kind} BEGIN SELECT RAISE(ABORT,'injected effect failure'); END")).unwrap();
        store.consume(&[record(2, true)], 62_000_000).unwrap();
        let live = store.query();
        assert!(store
            .flush()
            .unwrap_err()
            .contains("injected effect failure"));
        assert_eq!(
            store.query()["persistence"]["packets"],
            serde_json::json!([1, 1])
        );
        drop(store);
        injector.execute_batch("DROP TRIGGER fail_effect").unwrap();
        let mut store = ObservationStore::open(&path).unwrap();
        same_views(&store.query(), &committed);
        store
            .consume(&[record(2, true), record(2, true)], 62_000_000)
            .unwrap();
        store.flush().unwrap();
        same_views(&store.query(), &live);
        assert_eq!(store.query()["rejected"], 1);
        drop(store);
        drop(injector);
        println!("sqlite_effect_failure_kind_{kind}=PASS");
    }
    let path = root.join("crash/overall.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.consume(&[record(1, false)], 61_000_000).unwrap();
    store.flush().unwrap();
    let committed = store.query();
    drop(store);
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("crash")
        .arg(&path)
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(86));
    let store = ObservationStore::open(&path).unwrap();
    same_views(&store.query(), &committed);
    assert_eq!(store.query()["coverage"]["incomplete"], true);
    println!("process_loss_preserves_all_committed_views=PASS");
}
