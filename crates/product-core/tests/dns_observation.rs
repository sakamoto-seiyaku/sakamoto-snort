use sakamoto_product_core::dns_observation::DnsRecord;
use sakamoto_product_core::observation_store::ObservationStore;

fn test_root(label: &str) -> std::path::PathBuf {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_nanos();
    std::env::temp_dir().join(format!("s310-dns-{label}-{}-{nonce}", std::process::id()))
}

fn query(token: u64, caller: u8, action: u8) -> DnsRecord {
    DnsRecord {
        generation: 77, owner: 0, token, mono_us: token,
        activity_utc_us: 60_000_000 + token,
        policy_generation: 77, policy_revision: 9, policy_hash: 123,
        winner: if action == 2 { 310 } else { 0 },
        uid: 10123, network: u32::MAX, slot: u32::MAX,
        id: token as u16, query_flags: 0x0100, qtype: 1, qclass: 1,
        source_port: 40000, resolver_port: 53, family: 4, protocol: 17,
        direction: 3, availability: if caller == 1 { 9 } else { 1 }, caller,
        coverage: 1, declared_action: action, actual_action: action,
        domain_available: caller == 1, stage: 1,
        source_address: [192,168,1,2,0,0,0,0,0,0,0,0,0,0,0,0],
        resolver_address: [192,168,1,53,0,0,0,0,0,0,0,0,0,0,0,0],
        rule_name: if action == 2 { "block name".into() } else { String::new() },
        name: "example.com".into(), ..Default::default()
    }
}

fn admission_resource(token: u64, delivery: u8) -> DnsRecord {
    DnsRecord {
        generation: 77, owner: 0, token, mono_us: token,
        activity_utc_us: 60_000_000 + token, uid: u32::MAX,
        network: u32::MAX, slot: u32::MAX, id: 0x1234,
        query_flags: 0x0100, source_port: 40000, resolver_port: 53,
        family: 4, protocol: 17, direction: 3, coverage: 5,
        stage: 3, delivery, source_address: [192,0,2,2,0,0,0,0,0,0,0,0,0,0,0,0],
        resolver_address: [192,0,2,53,0,0,0,0,0,0,0,0,0,0,0,0],
        query_token: token, route_revision: 3, proxy_result: 6,
        adapter_profile: 1, packet_uid: u32::MAX, proxy_flags: 9,
        ..Default::default()
    }
}

#[test]
fn dns_decisions_share_sqlite_and_survive_reopen() {
    let root = test_root("store");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    store.consume_dns(&[query(1, 1, 2), query(2, 0, 1)], 61_000_000).unwrap();
    let check = |reply: serde_json::Value| {
        assert_eq!(reply["storage"], "sqlite");
        assert_eq!(reply["dns"]["accepted"], 2);
        let rows = reply["dns"]["recent"].as_object().unwrap();
        assert_eq!(rows.len(), 2);
        let denied = rows.values().find(|row| row["record"]["token"] == 1).unwrap();
        assert_eq!(denied["record"]["winner"], 310);
        assert_eq!(denied["record"]["rule_name"], "block name");
        assert_eq!(denied["record"]["name"], "example.com");
        assert_eq!(denied["record"]["delivery"], 0);
        let unknown = rows.values().find(|row| row["record"]["token"] == 2).unwrap();
        assert_eq!(unknown["record"]["uid"], 10123);
        assert_eq!(unknown["record"]["caller"], 0);
        assert_eq!(unknown["record"]["domain_available"], false);
    };
    check(store.query());
    store.close().unwrap();
    drop(store);
    let store = ObservationStore::open(&path).unwrap();
    check(store.query());
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn admission_resource_failure_is_durable_and_not_a_policy_refusal() {
    let root = test_root("admission-resource");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    store.consume_dns(&[admission_resource(31, 6), admission_resource(32, 7)],
        61_000_000).unwrap();
    store.close().unwrap();
    drop(store);
    let store = ObservationStore::open(&path).unwrap();
    let reply = store.query();
    assert_eq!(reply["dns"]["accepted"], 2);
    let rows = reply["dns"]["recent"].as_object().unwrap();
    for row in rows.values() {
        let record = &row["record"];
        assert_eq!(record["proxy_result"], 6);
        assert_eq!(record["proxy_flags"], 9);
        assert_eq!(record["request_attempt"], 0);
        assert_eq!(record["winner"], 0);
        assert_eq!(record["reply_rcode"], 0);
        assert!(matches!(record["delivery"].as_u64(), Some(6 | 7)));
    }
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dns_details_are_bounded_and_old_generations_cannot_rewrite_them() {
    let root = test_root("bound");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    let records: Vec<_> = (1..=4097).map(|token| query(token, 1, 2)).collect();
    store.consume_dns(&records, 61_000_000).unwrap();
    let reply = store.query();
    assert_eq!(reply["dns"]["accepted"], 4097);
    assert_eq!(reply["dns"]["retained_count"], 4096);
    assert_eq!(reply["dns"]["evicted"], 1);
    assert_eq!(reply["dns"]["recent"].as_object().unwrap().len(), 128);
    assert_eq!(reply["dns"]["query_truncated"], true);
    assert!(reply["persistence"]["pending_rows"].as_u64().unwrap() <= 4096);
    // An identical repeated event is idempotent. A conflicting token keeps the
    // first decision and reports a gap, rather than rewriting history.
    store.consume_dns(&[query(4097, 1, 2)], 61_000_001).unwrap();
    let mut conflict = query(4097, 1, 2);
    conflict.name = "changed.example".into();
    store.consume_dns(&[conflict], 61_000_002).unwrap();
    store.begin_generation(78).unwrap();
    store.consume_dns(&[query(5000, 1, 2)], 61_000_003).unwrap();
    let reply = store.query();
    assert_eq!(reply["dns"]["accepted"], 4097);
    assert_eq!(reply["dns"]["rejected"], 2);
    assert_eq!(reply["coverage"]["incomplete"], true);
    assert!(reply["dns"]["recent"].as_object().unwrap().values()
        .all(|row| row["record"]["name"] == "example.com"));
    // Recent detail has its own finite age. Historical counters remain true.
    for _ in 0..40 {
        store.tick(61_000_003 + 24 * 60 * 60 * 1_000_000).unwrap();
        store.flush().unwrap(); // Retention intentionally yields at the shared dirty budget.
    }
    store.close().unwrap();
    assert_eq!(store.query()["dns"]["retained_count"], 0);
    drop(store);
    let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    assert_eq!(db.query_row("SELECT count(*) FROM observation WHERE kind=20", [],
        |row| row.get::<_, u32>(0)).unwrap(), 0);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dns_rows_obey_existing_database_byte_pressure() {
    let root = test_root("pressure");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    std::fs::write(path.with_extension("retention-test.json"), serde_json::to_vec(&serde_json::json!({
        "minute_age_us": 60_000_000u64, "hour_age_us": 3_600_000_000u64,
        "day_age_us": 86_400_000_000u64, "end_age_us": 86_400_000_000u64,
        "budget_bytes": 262144, "working_reserve_bytes": 32768
    })).unwrap()).unwrap();
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    for token in 1..=256 {
        store.consume_dns(&[query(token, 1, 2)], 61_000_000).unwrap();
    }
    store.close().unwrap();
    let reply = store.query();
    assert_eq!(reply["dns"]["accepted"], 256);
    assert!(reply["dns"]["evicted"].as_u64().unwrap() > 0);
    assert!(reply["dns"]["retained_count"].as_u64().unwrap() < 256);
    assert!(reply["persistence"]["error"].is_null());
    drop(store);
    assert!(std::fs::metadata(path.with_extension("sqlite3")).unwrap().len() <= 76 * 1024);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn recent_dns_uses_receive_time_across_independent_lane_tokens() {
    let root = test_root("lane-order");
    std::fs::create_dir_all(&root).unwrap();
    let mut store = ObservationStore::open(&root.join("observation.json")).unwrap();
    store.begin_generation(77).unwrap();
    let busy_lane: Vec<_> = (1000..1128).map(|token| query(token, 1, 2)).collect();
    store.consume_dns(&busy_lane, 61_000_000).unwrap();
    let mut newest = query(1, 1, 1);
    newest.owner = 1;
    store.consume_dns(&[newest], 61_000_001).unwrap();
    let reply = store.query();
    let recent = reply["dns"]["recent"].as_object().unwrap();
    assert_eq!(recent.len(), 128);
    assert!(recent.values().any(|row| row["record"]["token"] == 1
        && row["record"]["owner"] == 1));
    drop(store);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn vpn_proxy_stages_preserve_normal_sqlite_history_and_return_provenance() {
    let root = test_root("vpn-proxy");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    let mut records = Vec::new();
    for (token, profile, provenance) in [(101, 1, 5), (102, 2, 3)] {
        for stage in 1..=4 {
            let mut record = query(token, 1, 1);
            record.adapter_profile = profile;
            record.packet_uid = record.uid;
            record.packet_availability = 1;
            record.route_revision = 3;
            record.request_attempt = 1;
            record.proxy_flags = 1;
            record.upstream_family = 4;
            record.upstream_address = [192,0,2,53,0,0,0,0,0,0,0,0,0,0,0,0];
            record.upstream_port = 53053;
            record.upstream_transport = 1;
            record.client_udp_capacity = 512;
            record.reply_capacity = 512;
            record.stage = stage;
            if stage != 1 { record.query_token = token; }
            if stage == 2 || stage == 4 {
                record.direction = 1;
                record.query_flags = 0x8180;
            }
            if stage == 4 {
                record.return_provenance = provenance;
                record.return_packet_uid = record.uid;
                record.return_token = (1u64 << 63) | token;
                record.delivery = 2;
            }
            assert!(record.valid(), "profile {profile} stage {stage}");
            records.push(record);
        }
    }
    store.consume_dns(&records, 61_000_000).unwrap();
    let mut invalid = records[7].clone();
    invalid.return_provenance = 5; // Root raw lineage cannot masquerade as VPN.
    assert!(!invalid.valid());
    invalid = records[3].clone();
    invalid.return_provenance = 3;
    assert!(!invalid.valid());
    store.close().unwrap(); drop(store);
    let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    let mut select = db.prepare("SELECT value FROM observation WHERE kind=20").unwrap();
    let persisted: Vec<DnsRecord> = select.query_map([], |row| row.get::<_, Vec<u8>>(0)).unwrap()
        .map(|value| serde_json::from_value(serde_json::from_slice::<serde_json::Value>(&value.unwrap()).unwrap()["record"].clone()).unwrap()).collect();
    assert_eq!(persisted.len(), records.len());
    for expected in &records { assert!(persisted.contains(expected)); }
    drop(select); drop(db);
    let reopened = ObservationStore::open(&path).unwrap();
    assert_eq!(reopened.query()["dns"]["accepted"], 8);
    drop(reopened); std::fs::remove_dir_all(root).unwrap();
}
