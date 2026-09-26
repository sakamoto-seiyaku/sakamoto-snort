//! Exercise the public Product store against an injected filesystem failure.
use sakamoto_product_core::observation_store::ObservationStore;
use std::path::Path;

fn main() {
    let path = std::env::args().nth(1).expect("store path");
    assert!(ObservationStore::open(Path::new(&path)).is_err(), "first parent fsync must fail");
    let mut store = ObservationStore::open(Path::new(&path)).expect("retry store open");
    assert_eq!(store.query()["packets"].to_string(), "[0,0]");
    store.close().unwrap();
    println!("parent-fsync-error-surfaced-and-retry-opened");
}
