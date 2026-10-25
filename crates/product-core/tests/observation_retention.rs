use sakamoto_product_core::observation::{Attribution, FlowRecord};
use sakamoto_product_core::dns_observation::DnsRecord;
use sakamoto_product_core::observation_store::ObservationStore;

const MINUTE: u64 = 60_000_000;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

#[test]
fn real_clock_reconciliation_preserves_fresh_details_across_close_and_generations() {
    let seed_path = std::env::var_os("SAKAMOTO_RECEIPT_SEED_PATH");
    let path = seed_path.clone().map(std::path::PathBuf::from)
        .unwrap_or_else(|| test_path("clock-reconcile-detail"));
    let wall = || std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_micros() as u64;
    let dns = |generation, token| dns_record(generation, token, wall());
    let ended = |generation, slot, blocked| ended_record(generation, slot, blocked, wall());
    if seed_path.is_some() {
        let old = wall() - 3 * DAY;
        let mut store = ObservationStore::open(&path).unwrap();
        store.begin_generation(5).unwrap();
        store.consume_dns(&[dns(5, 1)], old).unwrap();
        store.consume(&[ended(5, 1, false), ended(5, 2, true)], old).unwrap();
        store.close().unwrap();
        drop(store);

        // The complete earlier generation is closed in a separate process.
        let previous_dns = dns(6, 2);
        let previous_ends = [ended(6, 1, false), ended(6, 2, true)];
        let mut store = ObservationStore::open(&path).unwrap();
        store.begin_generation(6).unwrap();
        store.consume_dns_real(&[previous_dns.clone()], wall()).unwrap();
        store.consume_real(&previous_ends, wall()).unwrap();
        assert_eq!(store.query()["coverage"]["retention_clock_held"], true);
        store.close().unwrap();
        assert_eq!(store.query()["persistence"]["pending"], false);
        drop(store);
        std::fs::write(path.with_extension("expected-dns.json"),
            serde_json::to_vec(&previous_dns).unwrap()).unwrap();
        eprintln!("clock-reconcile-seed-process {}", std::process::id());
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "real_clock_reconciliation_preserves_fresh_details_across_close_and_generations",
            "--nocapture"])
        .env("SAKAMOTO_RECEIPT_SEED_PATH", &path).output().unwrap();
    eprintln!("clock-reconcile-reader-process {}\n{}", std::process::id(),
        String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stdout));
    let previous_dns: DnsRecord = serde_json::from_slice(
        &std::fs::read(path.with_extension("expected-dns.json")).unwrap()).unwrap();

    let current_dns = dns(7, 3);
    let current_ends = [ended(7, 1, false), ended(7, 2, true)];
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(7).unwrap();
    // Backward wall input places fresh rows ahead of genuinely old legacy keys.
    // The following stable forward correction must still expire the old rows.
    store.consume_dns_real(&[current_dns.clone()], wall() - 4 * DAY).unwrap();
    store.consume_real(&current_ends, wall() - 4 * DAY).unwrap();
    store.tick_real(wall()).unwrap();
    let before = store.query();
    assert_eq!(before["dns"]["retained_count"], 3);
    assert_eq!(before["dns"]["rejected"], 0);
    assert_eq!(before["recent_count"], 6);
    assert_eq!(before["packets"], serde_json::json!([9, 0]));
    assert_eq!(before["blocked"]["packets"], serde_json::json!([3, 0]));
    assert_eq!(before["rejected"], 0);
    let started = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(60_100));
    store.tick_real(wall()).unwrap();
    assert!(started.elapsed() >= std::time::Duration::from_secs(60));
    assert_eq!(store.query()["coverage"]["retention_clock_held"], false);
    store.close().unwrap();
    drop(store);

    let mut reopened = ObservationStore::open(&path).unwrap();
    let reply = reopened.query();
    eprintln!("clock-reconcile-core {}", serde_json::json!({
        "dns_retained": reply["dns"]["retained_count"],
        "dns_evicted": reply["dns"]["evicted"],
        "recent_count": reply["recent_count"], "packets": reply["packets"],
        "blocked_packets": reply["blocked"]["packets"],
        "rejected": reply["rejected"], "detail_age_clock": reply["coverage"]["detail_age_clock"],
    }));
    assert_eq!(reply["dns"]["retained_count"], 2,
        "clock reconciliation must expire genuinely old detail, not fresh closed/current generations");
    assert_eq!(reply["dns"]["evicted"], 1);
    let rows = reply["dns"]["recent"].as_object().unwrap();
    for expected in [&previous_dns, &current_dns] {
        assert!(rows.values().any(|row| row["record"] == serde_json::to_value(expected).unwrap()));
    }
    assert_eq!(reply["recent_count"], 4, "fresh Flow and Blocked END share the receive-age contract");
    assert_eq!(reply["packets"], serde_json::json!([9, 0]));
    assert_eq!(reply["blocked"]["packets"], serde_json::json!([3, 0]));
    // A duplicate END cannot restart the original receive-age timer.
    reopened.consume_real(&current_ends, wall()).unwrap();
    reopened.consume(&[], wall() + DAY + MINUTE).unwrap();
    reopened.close().unwrap();
    assert_eq!(reopened.query()["dns"]["retained_count"], 0);
    assert_eq!(reopened.query()["recent_count"], 0);
    assert_eq!(reopened.query()["packets"], serde_json::json!([9, 0]));
    drop(reopened);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

fn dns_record(generation: u64, token: u64, utc: u64) -> DnsRecord {
    DnsRecord {
        generation, owner: 0, token, mono_us: token, activity_utc_us: utc,
        policy_generation: generation, policy_revision: 9, policy_hash: 123,
        uid: 42, network: u32::MAX, slot: u32::MAX,
        id: token as u16, query_flags: 0x0100, qtype: 1, qclass: 1,
        source_port: 40000, resolver_port: 53, family: 4, protocol: 17,
        direction: 3, availability: 9, caller: 1, coverage: 1,
        declared_action: 1, actual_action: 1, domain_available: true, stage: 1,
        source_address: [192,168,1,2,0,0,0,0,0,0,0,0,0,0,0,0],
        resolver_address: [192,168,1,53,0,0,0,0,0,0,0,0,0,0,0,0],
        name: "fresh.example".into(), ..Default::default()
    }
}

fn ended_record(generation: u64, slot: u32, blocked: bool, utc: u64) -> FlowRecord {
    let mut row = record(utc, slot, 1, if blocked { 1 } else { 2 }, true);
    row.generation = generation;
    row.attribution[0].policy_generation = generation;
    row.blocked = blocked;
    if blocked {
        row.end_reason = 2;
        row.attribution[0].actual_action = 2;
        row.attribution[0].declared_action = 2;
        for attribution in &mut row.attribution {
            attribution.protocols_available = false;
            attribution.protocol_set = 0;
        }
    }
    row
}

#[test]
fn real_receipts_survive_aborted_forward_and_backward_candidates_with_visible_boot_fallback() {
    let path = test_path("clock-aborted-detail");
    let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_micros() as u64;
    let mut store = ObservationStore::open_with_boot_count(&path, Some(0)).unwrap();
    store.begin_generation(5).unwrap();
    for (token, received) in [(1, wall), (2, wall + 181 * DAY), (3, wall - DAY)] {
        store.consume_dns_real(&[dns_record(5, token, wall)], received).unwrap();
        store.consume_real(&[ended_record(5, token as u32 * 2, false, wall),
            ended_record(5, token as u32 * 2 + 1, true, wall)], received).unwrap();
    }
    store.tick_real(wall).unwrap(); // abort the forward candidate
    let reply = store.query();
    assert_eq!(reply["dns"]["retained_count"], 3);
    assert_eq!(reply["recent_count"], 6);
    assert_eq!(reply["packets"], serde_json::json!([9, 0]));
    assert_eq!(reply["blocked"]["packets"], serde_json::json!([3, 0]));
    assert_eq!(reply["rejected"], 0);
    assert!(reply["dns"]["recent"].as_object().unwrap().values().all(|row|
        row["received_us"].as_u64().unwrap() <= wall + 1_000_000));
    store.close().unwrap();
    drop(store);

    let mut same_boot = ObservationStore::open_with_boot_count(&path, Some(0)).unwrap();
    same_boot.tick_real(wall - 181 * DAY).unwrap();
    let same = same_boot.query();
    assert_eq!(same["dns"]["retained_count"], 3);
    assert_eq!(same["coverage"]["detail_age_clock"]["dns_fallback_rows"], 0);
    assert_eq!(same["coverage"]["detail_age_clock"]["ended_fallback_rows"], 0);
    same_boot.close().unwrap();
    drop(same_boot);

    let mut other_boot = ObservationStore::open_with_boot_count(&path, Some(1)).unwrap();
    let different = other_boot.query();
    // A different boot cannot compare those monotonic anchors. The explicitly
    // weaker historical mapping expires the backward-wall row at its safe age.
    assert_eq!(different["dns"]["retained_count"], 2);
    assert_eq!(different["dns"]["evicted"], 1);
    assert_eq!(different["recent_count"], 4);
    assert_eq!(different["packets"], serde_json::json!([9, 0]));
    assert_eq!(different["coverage"]["detail_age_clock"]["dns_fallback_rows"], 2);
    assert_eq!(different["coverage"]["detail_age_clock"]["ended_fallback_rows"], 4);
    other_boot.close().unwrap();
    drop(other_boot);
    // The ordinary Host boot-id namespace cannot impersonate Android count0.
    let mut host = ObservationStore::open(&path).unwrap();
    assert_eq!(host.query()["coverage"]["detail_age_clock"]["dns_fallback_rows"], 2);
    host.consume(&[], wall + DAY + MINUTE).unwrap();
    host.close().unwrap();
    assert_eq!(host.query()["dns"]["retained_count"], 0);
    assert_eq!(host.query()["recent_count"], 0);
    drop(host);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn all_supported_flow_owners_share_dns_flow_and_blocked_retention() {
    let path = test_path("all-owner-receipts");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_micros() as u64;
    let mut store = ObservationStore::open_with_boot_count(&path, Some(7)).unwrap();
    store.begin_generation(5).unwrap();
    let mut expected_dns = Vec::new();
    let mut expected_ends = Vec::new();
    for (token, owner) in [(1, 2), (2, 61), (3, 62), (4, u16::MAX)] {
        let mut dns = dns_record(5, token, now);
        dns.owner = owner;
        if owner == 2 || owner == 61 { expected_dns.push(dns.clone()); }
        store.consume_dns_real(&[dns], now).unwrap();
        let mut flow = ended_record(5, 1, false, now);
        let mut blocked = ended_record(5, 2, true, now);
        flow.owner = owner;
        blocked.owner = owner;
        if owner == 2 || owner == 61 {
            expected_ends.push(serde_json::to_value(&flow).unwrap());
            expected_ends.push(serde_json::to_value(&blocked).unwrap());
        }
        store.consume_real(&[flow, blocked], now).unwrap();
    }
    let reply = store.query();
    eprintln!("all-owner-receipt-core {}", serde_json::json!({
        "packets": reply["packets"], "blocked": reply["blocked"]["packets"],
        "accepted": reply["accepted"], "rejected": reply["rejected"],
        "dns": reply["dns"]["accepted"], "dns_rejected": reply["dns"]["rejected"],
        "recent_count": reply["recent_count"],
    }));
    assert_eq!(reply["packets"], serde_json::json!([6, 0]));
    assert_eq!(reply["blocked"]["packets"], serde_json::json!([2, 0]));
    assert_eq!(reply["accepted"], 4);
    assert_eq!(reply["rejected"], 4);
    assert_eq!(reply["dns"]["accepted"], 2);
    assert_eq!(reply["dns"]["rejected"], 2);
    assert_eq!(reply["recent_count"], 4);
    store.close().unwrap();
    drop(store);
    let mut reopened = ObservationStore::open_with_boot_count(&path, Some(7)).unwrap();
    assert_eq!(reopened.query()["packets"], serde_json::json!([6, 0]));
    assert_eq!(reopened.query()["recent_count"], 4);
    assert_eq!(reopened.query()["coverage"]["detail_age_clock"]["ended_fallback_rows"], 0);
    reopened.close().unwrap();
    drop(reopened);
    let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    assert_eq!(db.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0)).unwrap(), "ok");
    let mut select = db.prepare("SELECT kind,value FROM observation WHERE kind IN (2,20)").unwrap();
    let rows: Vec<(i64, serde_json::Value)> = select.query_map([], |row|
        Ok((row.get(0)?, row.get::<_, Vec<u8>>(1)?))).unwrap()
        .map(|row| { let (kind, value) = row.unwrap(); (kind, serde_json::from_slice(&value).unwrap()) })
        .collect();
    assert_eq!(rows.iter().filter(|(kind, _)| *kind == 2).count(), 4);
    assert_eq!(rows.iter().filter(|(kind, _)| *kind == 20).count(), 2);
    for expected in &expected_ends {
        assert!(rows.iter().any(|(kind, row)| *kind == 2 && row["record"] == *expected));
    }
    for expected in &expected_dns {
        assert!(rows.iter().any(|(kind, row)| *kind == 20
            && row["record"] == serde_json::to_value(expected).unwrap()));
    }
    drop(select);
    drop(db);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

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
fn duplicate_end_at_recent_capacity_preserves_counts_and_existing_detail() {
    let path = test_path("duplicate-end-capacity");
    let at = 200 * DAY + MINUTE;
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(5).unwrap();
    let records: Vec<_> = (0..32768).map(|slot| FlowRecord {
        generation: 5, slot, incarnation: 1, sequence: 1,
        activity_utc_us: at, first_seen: 1, last_seen: 1,
        packets: [1, 0], bytes: [64, 0], ended: true,
        ..Default::default()
    }).collect();
    // Seed a valid legacy representation. Its absent attribution field is a
    // supported serde default; canonical modern rows hit SQLite byte pressure
    // before this independent 32768-row count limit can be reached.
    let mut total = records[0].clone();
    total.packets = [32768, 0];
    total.bytes = [2097152, 0];
    store.consume(&[total], at).unwrap();
    store.close().unwrap();
    drop(store);
    let mut db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    let tx = db.transaction().unwrap();
    tx.execute("DELETE FROM observation WHERE kind IN (1,2)", []).unwrap();
    let mut metadata: serde_json::Value = serde_json::from_slice(&tx.query_row(
        "SELECT value FROM observation WHERE kind=0", [], |row| row.get::<_, Vec<u8>>(0)
    ).unwrap()).unwrap();
    metadata["accepted"] = 32768.into();
    metadata["ended"] = 32768.into();
    tx.execute("UPDATE observation SET value=?1 WHERE kind=0",
        [serde_json::to_vec(&metadata).unwrap()]).unwrap();
    {
        let mut insert = tx.prepare("INSERT INTO observation(kind,key,value) VALUES(?1,?2,?3)").unwrap();
        for record in &records {
            let mut encoded = serde_json::to_value(record).unwrap();
            encoded.as_object_mut().unwrap().remove("attribution");
            let value = serde_json::to_vec(&serde_json::json!({
                "record": encoded, "first_end_us": at
            })).unwrap();
            let identity = format!("5:0:{}", record.slot);
            insert.execute(rusqlite::params![1, identity, value]).unwrap();
            insert.execute(rusqlite::params![2, format!("{at:020}:{identity}:1"), value]).unwrap();
        }
    }
    tx.commit().unwrap();
    assert_eq!(db.query_row("SELECT count(*) FROM observation WHERE kind=2", [],
        |row| row.get::<_, u32>(0)).unwrap(), 32768);
    drop(db);
    let mut store = ObservationStore::open(&path).unwrap();
    let before = store.query();
    eprintln!("duplicate-capacity-precondition {}", serde_json::json!({
        "recent_count": before["recent_count"], "packets": before["packets"],
        "storage_space": before["storage_space"], "persistence": before["persistence"],
    }));
    assert_eq!(before["recent_count"], 32768, "real full-capacity prerequisite");
    store.consume(&[records[0].clone()], at + MINUTE).unwrap();
    let after = store.query();
    assert_eq!(after["packets"], serde_json::json!([32768, 0]));
    assert_eq!(after["recent_count"], 32768);
    assert_eq!(after["accepted"], 32768);
    assert_eq!(after["recent"], before["recent"]);
    assert_eq!(after["rejected"], 1);
    store.consume(&[records[32767].clone()], at + MINUTE + 1).unwrap();
    assert_eq!(store.query()["recent"], before["recent"]);
    assert_eq!(store.query()["packets"], serde_json::json!([32768, 0]));
    let mut next = records[0].clone();
    next.incarnation = 2;
    next.packets = [2, 0];
    next.bytes = [128, 0];
    store.consume(&[next], at + 2 * MINUTE).unwrap();
    assert_eq!(store.query()["packets"], serde_json::json!([32770, 0]));
    assert_eq!(store.query()["recent_count"], 32768);
    store.close().unwrap();
    drop(store);
    let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    let newest_first: serde_json::Value = serde_json::from_slice(&db.query_row(
        "SELECT value FROM observation WHERE kind=2 AND key=?1",
        [format!("{at:020}:5:0:32767:1")], |row| row.get::<_, Vec<u8>>(0)).unwrap()).unwrap();
    assert_eq!(newest_first["first_end_us"], at);
    let keys: std::collections::BTreeSet<String> = db.prepare(
        "SELECT key FROM observation WHERE kind=2").unwrap().query_map([], |row| row.get(0))
        .unwrap().map(Result::unwrap).collect();
    let mut expected: std::collections::BTreeSet<_> = (0..32768)
        .map(|slot| format!("{at:020}:5:0:{slot}:1")).collect();
    expected.remove(&format!("{at:020}:5:0:0:1"));
    expected.insert(format!("{:020}:5:0:0:2", at + 2 * MINUTE));
    assert_eq!(keys, expected);
    drop(db);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
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
        let sqlite = path.with_extension("sqlite3");
        std::fs::copy(input.with_extension("sqlite3"), &sqlite).unwrap();
        // A sealed real-observation input can be intentionally read-only.
        // The test never opens it in place: its isolated copy must be writable
        // because opening the store can checkpoint/recover persisted state.
        let mut permissions = std::fs::metadata(&sqlite).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(&sqlite, permissions).unwrap();
        if input.is_file() { std::fs::copy(&input, &path).unwrap(); }
        path
    };
    let drain_retention = |store: &mut ObservationStore| {
        // A real retained store can have several bounded transition steps.
        // One flush proves neither completion nor persistence; drain the
        // existing maintenance state without changing the test clock again.
        for _ in 0..256 {
            if !store.query()["persistence"]["maintenance_pending"].as_bool().unwrap() {
                return;
            }
            store.flush().unwrap();
        }
        assert!(!store.query()["persistence"]["maintenance_pending"].as_bool().unwrap(),
            "retention did not settle within its bounded test budget");
    };
    let age_path = copy("age");
    let mut store = ObservationStore::open(&age_path).unwrap();
    let before = store.query();
    assert!(before["packets"][0].as_u64().unwrap() > 0);
    assert!(before["rule_window_count"].as_u64().unwrap() > 0);
    let last = before["coverage"]["last_activity_us"].as_u64().unwrap();
    store.tick(last + 48 * HOUR + 2 * MINUTE).unwrap();
    drain_retention(&mut store);
    let hourly = store.query();
    assert_eq!(hourly["packets"], before["packets"]);
    assert_eq!(hourly["stored_minute_count"], 0);
    assert!(hourly["hour_windows"]["counts"]["overall"].as_u64().unwrap() > 0);
    assert!(hourly["hour_windows"]["counts"]["rules"].as_u64().unwrap() > 0);
    store.close().unwrap(); drop(store);
    let mut store = ObservationStore::open(&age_path).unwrap();
    assert_eq!(store.query()["packets"], before["packets"]);
    store.tick(last + 30 * DAY + 2 * HOUR).unwrap();
    drain_retention(&mut store);
    let daily = store.query();
    assert_eq!(daily["packets"], before["packets"]);
    assert!(daily["day_windows"]["counts"]["overall"].as_u64().unwrap() > 0);
    store.close().unwrap(); drop(store);
    let mut store = ObservationStore::open(&age_path).unwrap();
    store.tick(last + 180 * DAY + 2 * DAY).unwrap();
    drain_retention(&mut store);
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
