use sakamoto_product_core::dns_observation::DnsRecord;
use sakamoto_product_core::observation_store::ObservationStore;

#[test]
#[ignore = "requires source-linked Root/VPN ordered-routing Adapter records"]
fn actual_ordered_attempts_survive_normal_decode_store_and_reopen() {
    let wire = std::fs::read(std::env::var_os("SAKAMOTO_DNS_ROUTING_RECORDS").unwrap()).unwrap();
    assert_eq!(wire.len(), 48 * 720);
    let records: Vec<_> = wire.chunks_exact(720)
        .map(|bytes| DnsRecord::decode(bytes).expect("every actual Adapter record must decode"))
        .collect();
    let root = std::path::PathBuf::from(std::env::var_os("SAKAMOTO_DNS_ROUTING_STORE").unwrap());
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("decoded-input-records.json"),
        serde_json::to_vec_pretty(&records).unwrap()).unwrap();
    for profile in [1, 2] { for family in [4, 6] { for protocol in [6, 17] {
        let scoped: Vec<_> = records.iter().filter(|r| r.adapter_profile == profile
            && r.family == family && r.protocol == protocol).collect();
        assert_eq!(scoped.len(), 6);
        assert_eq!(scoped.iter().map(|r| r.stage).collect::<Vec<_>>(), [1, 5, 5, 5, 2, 4]);
        assert!(scoped.iter().all(|r| r.uid == 10123 && r.caller == 1
            && r.token == scoped[0].token && r.request_attempt == scoped[0].request_attempt
            && r.resolution_route == 0 && r.network_revision == scoped[0].network_revision
            && r.route_revision == scoped[0].route_revision));
        assert_eq!(scoped.iter().map(|r| r.resolver_id).collect::<Vec<_>>(), [1, 1, 1, 2, 2, 2]);
        let primary = scoped[1].upstream_attempt;
        let backup = scoped[3].upstream_attempt;
        assert_ne!(primary, backup); assert_ne!(primary, 0); assert_ne!(backup, 0);
        assert_eq!(scoped.iter().map(|r| r.upstream_attempt).collect::<Vec<_>>(),
            [0, primary, primary, backup, backup, backup]);
        for (record, result) in scoped[1..4].iter().zip([12, 14, 12]) {
            assert_eq!(record.proxy_result, result);
            assert_eq!(record.actual_action, 0); assert_eq!(record.declared_action, 0);
            assert_eq!(record.delivery, 0); assert_eq!(record.policy_generation, 0);
            assert_eq!(record.upstream_session, 0);
        }
        assert_eq!(scoped[4].upstream_port, 15354);
        assert_eq!(scoped[5].upstream_port, 15354);
        assert_eq!(scoped[5].proxy_result, 1);
    } } }
    let path = root.join("observation.json");
    let mut store = ObservationStore::open(&path).unwrap();
    store.begin_generation(77).unwrap(); store.consume_dns(&records, 61_000_000).unwrap();
    assert_eq!(store.query()["dns"]["accepted"], 48);
    assert_eq!(store.query()["dns"]["rejected"], 0);
    store.close().unwrap(); drop(store);
    let mut reopened = ObservationStore::open(&path).unwrap();
    let snapshot = reopened.query();
    assert_eq!(snapshot["dns"]["retained_count"], 48);
    let recent = snapshot["dns"]["recent"].as_object().unwrap();
    for record in &records {
        let value = serde_json::to_value(record).unwrap();
        assert_eq!(recent.values().filter(|row| row["record"] == value).count(), 1);
    }
    // Replaying the same attempt is idempotent. A changed failure cannot
    // overwrite the original timeout under its existing identity.
    reopened.consume_dns(&records, 61_000_001).unwrap();
    assert_eq!(reopened.query()["dns"]["accepted"], 48);
    let mut conflict = records.iter().find(|r| r.stage == 5 && r.proxy_result == 14).unwrap().clone();
    conflict.name = "changed.example".into();
    reopened.consume_dns(&[conflict], 61_000_002).unwrap();
    assert_eq!(reopened.query()["dns"]["rejected"], 1);
    assert_eq!(reopened.query()["dns"]["recent"], snapshot["dns"]["recent"]);
    std::fs::write(root.join("reopened.json"), serde_json::to_vec_pretty(&snapshot).unwrap()).unwrap();
    reopened.close().unwrap();
}
