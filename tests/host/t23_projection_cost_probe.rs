//! Descriptive cost decomposition at the real public store call pattern.
use sakamoto_product_core::observation::{Attribution, FlowRecord};
use sakamoto_product_core::observation_store::ObservationStore;
use std::time::Instant;
fn main() {
    let path = std::env::args().nth(1).unwrap();
    let mut store = ObservationStore::open(std::path::Path::new(&path)).unwrap();
    let a = Attribution { segment: 1, activity_utc_us: 61_000_000,
        policy_generation: 999999, policy_revision: 1, policy_hash: 123,
        winner: 65537, uid: 60001, declared_action: 2, actual_action: 1, mode: 1,
        valid: true, name: "projection decomposition".into(), ..Default::default() };
    let mut r = FlowRecord { generation: 999999, incarnation: 1, activity_utc_us: 61_000_000,
        attribution: [a.clone(), a], ..Default::default() };
    let mut consume_ns = 0; let mut query_ns = 0;
    let start = Instant::now();
    for sequence in 1..=1000 {
        r.sequence = sequence; r.packets = [sequence, sequence]; r.bytes = [sequence*60, sequence*80];
        let before = Instant::now(); store.consume(std::slice::from_ref(&r), 62_000_000).unwrap();
        consume_ns += before.elapsed().as_nanos();
        let before = Instant::now(); std::hint::black_box(store.query());
        query_ns += before.elapsed().as_nanos();
    }
    let elapsed_ns = start.elapsed().as_nanos();
    store.close().unwrap();
    println!("{{\"iterations\":1000,\"consume_ns\":{consume_ns},\"query_ns\":{query_ns},\"elapsed_ns\":{elapsed_ns}}}");
}
