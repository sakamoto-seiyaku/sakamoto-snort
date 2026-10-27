use sakamoto_product_core::dns_observation::DnsRecord;
use sakamoto_product_core::observation_store::ObservationStore;

#[test]
#[ignore = "requires source-linked Root/VPN real malloc-failure Adapter records"]
fn source_linked_cache_resource_failures_survive_decode_and_sqlite_reopen() {
    let wire = std::fs::read(std::env::var("SAKAMOTO_DNS_CACHE_RESOURCE_RECORDS").unwrap()).unwrap();
    assert_eq!(wire.len(), 120 * 704);
    let decoded: Vec<_> = wire.chunks_exact(704).map(DnsRecord::decode).collect();
    let records: Vec<_> = decoded.iter().filter_map(Clone::clone).collect();
    let root = std::env::var_os("SAKAMOTO_DNS_CODEC_EVIDENCE_DIR")
        .map(std::path::PathBuf::from).unwrap_or_else(|| test_root("cache-resource"));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_micros() as u64;
    store.consume_dns(&records, now).unwrap();
    store.close().unwrap();drop(store);
    let mut restored = ObservationStore::open(&path).unwrap();
    let snapshot = restored.query();
    std::fs::write(root.join("reopened.json"), serde_json::to_vec_pretty(&serde_json::json!({
        "wire_records": 120, "decode_rejected_indices": decoded.iter().enumerate()
            .filter_map(|(index, record)| record.is_none().then_some(index)).collect::<Vec<_>>(),
        "after": snapshot,
    })).unwrap()).unwrap();
    assert_eq!(records.len(), 120, "every actual Adapter record must decode, including cached-output CAPACITY");
    assert_eq!(snapshot["dns"]["accepted"], 120);
    assert_eq!(snapshot["dns"]["rejected"], 0);
    let rows = snapshot["dns"]["recent"].as_object().unwrap();
    assert_eq!(rows.len(), 120);
    for record in &records {
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(rows.values().filter(|row| row["record"] == value).count(), 1);
    }
    for profile in [1, 2] { for family in [4, 6] { for protocol in [6, 17] {
        let scoped: Vec<_> = records.iter().filter(|record| record.adapter_profile == profile
            && record.family == family && record.protocol == protocol).collect();
        assert_eq!(scoped.len(), 15);
        assert_eq!(scoped.iter().filter(|record| record.proxy_flags == 17
            && record.proxy_result == 6 && matches!(record.stage, 3 | 4)
            && record.reply_rcode == 2 && record.upstream_session == 0).count(), 2);
    } } }
    // Cache provenance only permits the precise local output failure. Other
    // error results, source mixing and absent response facts remain invalid.
    let cached_error = records.iter().find(|record| record.proxy_flags == 17
        && record.stage == 3 && record.proxy_result == 6).unwrap();
    for change in 0..10 {
        let mut invalid = cached_error.clone();
        match change {
            0 => invalid.stage = 1,
            1 => invalid.proxy_flags |= 4,
            2 => invalid.proxy_flags |= 8,
            3 => invalid.upstream_session = 1,
            4 => invalid.proxy_result = 7,
            5 => invalid.reply_rcode = 0,
            6 => invalid.correlation = 0,
            7 => invalid.matched_requests = 0,
            8 => invalid.query_flags &= !0x8000,
            _ => invalid.candidate_count = 0,
        }
        assert!(!invalid.valid(), "invalid cached-resource scope {change} must be rejected");
    }
    // A conflicting replay cannot replace the persisted resource failure.
    let mut conflict = cached_error.clone();conflict.name = "changed.example".into();
    assert!(conflict.valid());restored.consume_dns(&[conflict], now + 1).unwrap();
    assert_eq!(restored.query()["dns"]["recent"], snapshot["dns"]["recent"]);
    assert_eq!(restored.query()["dns"]["rejected"], 1);
    restored.close().unwrap();
}

#[test]
#[ignore = "requires source-linked VPN TCP Adapter OFF records"]
fn selected_local_tcp_without_upstream_survives_decode_and_sqlite_reopen() {
    let wire = std::fs::read(std::env::var("SAKAMOTO_DNS_VPN_TCP_OFF_RECORDS").unwrap()).unwrap();
    // Each address family produces success3, cancelled-view3, no-route3,
    // policy refusal2, FORMERR2, NOTIMP2 and no-reply-identity1.
    assert_eq!(wire.len(), 32 * 704);
    let records: Vec<_> = wire.chunks_exact(704).filter_map(DnsRecord::decode).collect();
    let root = std::env::var_os("SAKAMOTO_DNS_CODEC_EVIDENCE_DIR")
        .map(std::path::PathBuf::from).unwrap_or_else(|| test_root("local-tcp-no-upstream"));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
        .unwrap().as_micros() as u64;
    store.consume_dns(&records, now).unwrap();
    store.close().unwrap();
    drop(store);
    let mut restored = ObservationStore::open(&path).unwrap();
    let snapshot = restored.query();
    assert_eq!(snapshot["dns"]["accepted"], 32,
        "all real Adapter observations, including absent-upstream local errors, must persist");
    assert_eq!(snapshot["dns"]["rejected"], 0);
    let rows = snapshot["dns"]["recent"].as_object().unwrap();
    assert_eq!(rows.len(), 32);
    for record in &records {
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(rows.values().filter(|row| row["record"] == value).count(), 1);
    }
    let absent = records.iter().find(|record|
        record.upstream_family == 0 && record.stage == 3 && record.proxy_result == 9).unwrap();
    for change in 0..9 {
        let mut invalid = absent.clone();
        match change {
            0 => { invalid.protocol = 17; invalid.message_sequence = 0; invalid.reply_capacity = 512; }
            1 => invalid.adapter_profile = 1,
            2 => invalid.upstream_address[0] = 1,
            3 => invalid.upstream_port = 53,
            4 => invalid.upstream_family = 4,
            5 => invalid.upstream_session = 1,
            6 => invalid.proxy_flags |= 4,
            7 => invalid.transport_session = 0,
            _ => { invalid.stage = 2; invalid.direction = 1; invalid.query_flags |= 0x8000; invalid.proxy_result = 1; }
        }
        assert!(!invalid.valid(), "invalid absent-upstream scope {change} must still be rejected");
    }
    let mut conflict = absent.clone();
    conflict.name = "changed.example.com".into();
    assert!(conflict.valid());
    restored.consume_dns(&[conflict], now + 1).unwrap();
    let after = restored.query();
    assert_eq!(after["dns"]["accepted"], 32);
    assert_eq!(after["dns"]["rejected"], 1);
    assert_eq!(after["dns"]["recent"], snapshot["dns"]["recent"]);
    restored.close().unwrap();
}

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

fn proxy_query(token: u64, protocol: u8, profile: u8) -> DnsRecord {
    let mut record = query(token, 1, 1);
    record.id = 0x1234;
    record.incarnation = 8;
    record.slot = 3;
    record.protocol = protocol;
    record.message_sequence = if protocol == 6 { token } else { 0 };
    record.adapter_profile = profile;
    record.packet_uid = record.uid;
    record.packet_availability = 9;
    record.network_revision = 5;
    record.route_revision = 1140;
    record.transport_session = 4;
    record.request_attempt = token - 12;
    record.proxy_flags = 1;
    record.upstream_family = 4;
    record.upstream_address = [192,0,2,53,0,0,0,0,0,0,0,0,0,0,0,0];
    record.upstream_port = 53053;
    record.upstream_transport = 1;
    record.client_udp_capacity = 512;
    record.reply_capacity = if protocol == 6 { 65535 } else { 512 };
    assert!(record.valid());
    record
}

#[test]
fn proxy_requests_with_reused_numbers_keep_their_scoped_sqlite_identity() {
    let root = test_root("proxy-scope");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    let udp = [proxy_query(13, 17, 2), proxy_query(14, 17, 2)];
    store.consume_dns(&udp, 61_000_000).unwrap();
    let first_receipts = store.query()["dns"]["recent"].clone();
    let tcp: Vec<_> = udp.iter().map(|record| {
        let mut record = record.clone();
        record.protocol = 6;
        record.message_sequence = record.token;
        record.reply_capacity = 65535;
        record.route_revision = 1150;
        record.transport_session = 27;
        record.incarnation = 30;
        assert!(record.valid());
        record
    }).collect();
    store.consume_dns(&tcp, 62_000_000).unwrap();
    let reply = store.query();
    assert_eq!(reply["dns"]["accepted"], 4);
    assert_eq!(reply["dns"]["rejected"], 0);
    for (key, receipt) in first_receipts.as_object().unwrap() {
        assert_eq!(&reply["dns"]["recent"][key], receipt);
    }
    let mut expected = udp.to_vec();
    expected.extend(tcp.iter().cloned());
    // Each of these is another real request identity, even when its opaque
    // token and attempt number have the same numeric value.
    for change in 0..5 {
        for original in &tcp {
            let mut record = original.clone();
            match change {
                0 => record.route_revision += 1,
                1 => record.transport_session += 1,
                2 => record.incarnation += 1,
                3 => record.network_revision += 1,
                _ => record.adapter_profile = 1,
            }
            assert!(record.valid());
            store.consume_dns(&[record.clone()], 63_000_000).unwrap();
            expected.push(record);
        }
    }
    for original in &udp {
        let mut root_udp = original.clone();
        root_udp.adapter_profile = 1;
        store.consume_dns(&[root_udp.clone()], 63_000_000).unwrap();
        expected.push(root_udp);
    }
    for original in udp.iter().chain(&tcp) {
        let mut ipv6 = original.clone();
        ipv6.family = 6;
        ipv6.source_address = "fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets();
        ipv6.resolver_address = "2001:db8::53".parse::<std::net::Ipv6Addr>().unwrap().octets();
        assert!(ipv6.valid());
        store.consume_dns(&[ipv6.clone()], 63_000_000).unwrap();
        expected.push(ipv6);
    }
    let before_replay = store.query()["dns"]["recent"].clone();
    store.consume_dns(&expected, 64_000_000).unwrap();
    assert_eq!(store.query()["dns"]["recent"], before_replay);
    assert_eq!(store.query()["dns"]["accepted"], expected.len());
    assert_eq!(store.query()["dns"]["rejected"], 0);
    let mut conflict = tcp[0].clone();
    conflict.name = "different.example".into();
    assert!(conflict.valid());
    store.consume_dns(&[conflict], 65_000_000).unwrap();
    assert_eq!(store.query()["dns"]["rejected"], 1);
    assert_eq!(store.query()["dns"]["recent"], before_replay);
    store.close().unwrap();
    drop(store);
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["dns"]["recent"], before_replay);
    drop(store);
    let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    let length: i64 = db.query_row("SELECT max(length(key)) FROM observation WHERE kind=20",
        [], |row| row.get(0)).unwrap();
    assert!(length <= 192);
    let mut select = db.prepare("SELECT value FROM observation WHERE kind=20").unwrap();
    let persisted: Vec<serde_json::Value> = select.query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap().map(|row| serde_json::from_slice(&row.unwrap()).unwrap()).collect();
    assert_eq!(persisted.len(), expected.len());
    for record in expected {
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(persisted.iter().filter(|row| row["record"] == value).count(), 1);
    }
    drop(select);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_proxy_rows_keep_exact_keys_payloads_and_receipts_across_scoped_replay() {
    for profile in [1, 2] {
        for family in [4, 6] {
            let root = test_root(&format!("legacy-proxy-{profile}-{family}"));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("observation.json");
            let mut original = proxy_query(13, 17, profile);
            if family == 6 {
                original.family = 6;
                original.source_address = "fd00::2".parse::<std::net::Ipv6Addr>().unwrap().octets();
                original.resolver_address = "2001:db8::53".parse::<std::net::Ipv6Addr>().unwrap().octets();
            }
            assert!(original.valid());
            let mut store = ObservationStore::open(&path).unwrap();
            store.begin_generation(77).unwrap();
            store.consume_dns(&[original.clone()], 61_000_000).unwrap();
            store.close().unwrap();
            drop(store);
            let database = path.with_extension("sqlite3");
            let db = rusqlite::Connection::open(&database).unwrap();
            let (current_key, original_payload): (String, Vec<u8>) = db.query_row(
                "SELECT key,value FROM observation WHERE kind=20", [],
                |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
            // Prior shipped format, deliberately independent of the new key
            // implementation. Only this test fixture's storage key changes.
            let legacy_key = "00000000000000000077:00000000000000000013:0000:proxy:00000000000000000001:1:00:00000000000000000000";
            assert_ne!(current_key, legacy_key);
            db.execute("UPDATE observation SET key=?2 WHERE kind=20 AND key=?1",
                rusqlite::params![current_key, legacy_key]).unwrap();
            drop(db);

            let mut store = ObservationStore::open(&path).unwrap();
            let original_receipt = store.query()["dns"]["recent"][legacy_key].clone();
            assert_eq!(original_receipt["received_us"], 61_000_000);
            store.consume_dns(&[original.clone()], 62_000_000).unwrap();
            assert_eq!(store.query()["dns"]["accepted"], 1);
            assert_eq!(store.query()["dns"]["rejected"], 0);
            assert_eq!(store.query()["dns"]["recent"][legacy_key], original_receipt);
            let mut conflict = original.clone();
            conflict.name = "different.example".into();
            assert!(conflict.valid());
            store.consume_dns(&[conflict], 63_000_000).unwrap();
            assert_eq!(store.query()["dns"]["rejected"], 1);
            let mut tcp = original.clone();
            tcp.protocol = 6;
            tcp.message_sequence = tcp.token;
            tcp.reply_capacity = 65535;
            tcp.transport_session = 27;
            tcp.incarnation = 30;
            tcp.route_revision = 1150;
            assert!(tcp.valid());
            store.consume_dns(&[tcp.clone()], 64_000_000).unwrap();
            store.consume_dns(&[tcp.clone()], 65_000_000).unwrap();
            assert_eq!(store.query()["dns"]["accepted"], 2);
            assert_eq!(store.query()["dns"]["rejected"], 1);
            assert_eq!(store.query()["dns"]["recent"][legacy_key], original_receipt);
            store.close().unwrap();
            drop(store);
            let store = ObservationStore::open(&path).unwrap();
            assert_eq!(store.query()["dns"]["accepted"], 2);
            assert_eq!(store.query()["dns"]["rejected"], 1);
            assert_eq!(store.query()["dns"]["recent"][legacy_key], original_receipt);
            drop(store);
            let db = rusqlite::Connection::open(database).unwrap();
            let persisted: Vec<u8> = db.query_row(
                "SELECT value FROM observation WHERE kind=20 AND key=?1", [legacy_key],
                |row| row.get(0)).unwrap();
            assert_eq!(persisted, original_payload);
            let count: i64 = db.query_row("SELECT count(*) FROM observation WHERE kind=20", [],
                |row| row.get(0)).unwrap();
            assert_eq!(count, 2);
            drop(db);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
}

#[test]
fn maximum_proxy_scope_stays_within_the_existing_sqlite_key_bound() {
    let root = test_root("proxy-key-bound");
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("observation.json");
    let mut record = proxy_query(13, 6, 2);
    record.generation = u64::MAX;
    record.policy_generation = u64::MAX;
    record.owner = 61;
    record.token = u64::MAX;
    record.message_sequence = u64::MAX;
    record.incarnation = u64::MAX;
    record.transport_session = u64::MAX;
    record.network_revision = u64::MAX;
    record.route_revision = u64::MAX;
    record.request_attempt = u64::MAX;
    record.stage = 4;
    record.direction = 1;
    record.query_flags = 0x8180;
    record.query_token = u64::MAX;
    record.return_token = u64::MAX;
    record.return_provenance = 3;
    record.return_packet_uid = record.uid;
    record.delivery = 2;
    assert!(record.valid());
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(u64::MAX).unwrap();
    store.consume_dns(&[record], 61_000_000).unwrap();
    assert_eq!(store.query()["dns"]["accepted"], 1);
    store.close().unwrap();
    drop(store);
    let store = ObservationStore::open(&path).unwrap();
    assert_eq!(store.query()["dns"]["retained_count"], 1);
    drop(store);
    let db = rusqlite::Connection::open(path.with_extension("sqlite3")).unwrap();
    let length: i64 = db.query_row("SELECT length(key) FROM observation WHERE kind=20", [],
        |row| row.get(0)).unwrap();
    assert!(length <= 192);
    drop(db);
    std::fs::remove_dir_all(root).unwrap();
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

#[test]
fn cached_answers_preserve_source_current_policy_and_normal_sqlite_reopen() {
    let root = test_root("cache-source");
    std::fs::create_dir(&root).unwrap();
    let path = root.join("observation.json");
    let mut records = Vec::new();
    for profile in 1..=2 {
        for protocol in [17, 6] {
            let mut record = proxy_query(20 + records.len() as u64, protocol, profile);
            record.stage = 2;
            record.direction = 1;
            record.query_flags = 0x8180;
            record.query_token = record.token;
            record.proxy_flags = 17;
            record.proxy_result = 11;
            record.upstream_session = 0; // The cached request did not create a new resolver socket.
            record.query_policy_generation = 77;
            record.query_policy_revision = 8;
            record.query_policy_hash = 100;
            record.policy_revision = 10;
            record.output_bytes = 45;
            record.delivery = if protocol == 6 { 8 } else { 1 };
            assert!(record.valid());
            let mut invalid = record.clone();
            invalid.upstream_session = 99;
            assert!(!invalid.valid());
            invalid = record.clone(); invalid.proxy_flags |= 4;
            assert!(!invalid.valid());
            invalid = record.clone(); invalid.proxy_flags = 1;
            assert!(!invalid.valid());
            records.push(record);
        }
    }
    let mut denied = records[0].clone();
    denied.token = 30; denied.query_token = 30; denied.request_attempt = 18;
    denied.proxy_result = 2; denied.reply_rcode = 5;
    denied.policy_revision = 11; denied.winner = 319;
    denied.actual_action = 2; denied.declared_action = 2;
    assert!(denied.valid());
    records.push(denied);
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap();
    store.consume_dns(&records, 61_000_000).unwrap();
    store.close().unwrap(); drop(store);
    let mut reopened = ObservationStore::open(&path).unwrap();
    let result = reopened.query();
    assert_eq!(result["dns"]["accepted"], 5);
    assert_eq!(result["dns"]["rejected"], 0);
    let rows = result["dns"]["recent"].as_object().unwrap();
    assert_eq!(rows.len(), records.len());
    for record in records {
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(rows.values().filter(|row| row["record"] == value).count(), 1);
    }
    reopened.close().unwrap();
}
