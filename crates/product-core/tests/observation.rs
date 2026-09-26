use sakamoto_product_core::observation::{FlowRecord, Overview};

#[test]
fn end_applies_tail_without_reviving_on_old_update() {
    let mut view = Overview::new(7, 2, 1024);
    let mut record = FlowRecord {
        generation: 7,
        owner: 0,
        slot: 3,
        incarnation: 11,
        ..Default::default()
    };
    record.sequence = 1;
    record.packets = [1, 0];
    record.bytes = [60, 0];
    assert!(view.consume(record.clone()));
    let old = record.clone();
    record.sequence = 2;
    record.packets = [3, 1];
    record.bytes = [180, 80];
    record.ended = true;
    assert!(view.consume(record.clone()));
    assert!(!view.consume(old));
    assert!(!view.consume(record));
    assert_eq!(view.packets, [3, 1]);
    assert_eq!(view.bytes, [180, 80]);
    assert_eq!(view.active, 0);
    assert_eq!(view.ended, 1);
}

#[test]
fn rollback_and_retired_incarnation_cannot_change_overview() {
    let mut view = Overview::new(9, 2, 4);
    let first = FlowRecord {
        generation: 9,
        owner: 1,
        slot: 2,
        incarnation: 40,
        sequence: 1,
        packets: [2, 1],
        bytes: [120, 70],
        ..Default::default()
    };
    assert!(view.consume(first.clone()));
    let mut rollback = first.clone();
    rollback.sequence = 2;
    rollback.bytes[0] = 119;
    assert!(!view.consume(rollback));
    let replacement = FlowRecord {
        incarnation: 41,
        packets: [1, 0],
        bytes: [40, 0],
        ..first.clone()
    };
    assert!(view.consume(replacement));
    assert!(!view.consume(FlowRecord {
        sequence: 99,
        ended: true,
        ..first.clone()
    }));
    assert!(!view.consume(FlowRecord {
        generation: 10,
        incarnation: 42,
        ..first
    }));
    assert_eq!(view.packets, [3, 1]);
    assert_eq!(view.bytes, [160, 70]);
    assert_eq!(view.active, 1);
    assert!(view.incomplete);
    assert_eq!(view.rejected, 3);
}

#[test]
fn wire_record_is_length_and_version_checked() {
    let mut bytes = [0u8; 152];
    bytes[0..4].copy_from_slice(&[128, 0, 1, 2]);
    bytes[16] = 7; // generation
    bytes[24] = 11; // incarnation
    bytes[32] = 1; // update
    bytes[56] = 3; // ORIG packets
    bytes[80] = 80; // REPLY bytes
    bytes[112] = 4;
    bytes[113] = 17;
    bytes[120..128].copy_from_slice(&[10, 1, 2, 3, 10, 4, 5, 6]);
    let r = FlowRecord::decode(&bytes).unwrap();
    assert_eq!(r.generation, 7);
    assert_eq!(r.incarnation, 11);
    assert_eq!(r.packets, [3, 0]);
    assert_eq!(r.bytes, [0, 80]);
    assert_eq!(r.addresses, [10, 1, 2, 3, 10, 4, 5, 6]);
    bytes[0] = 127;
    assert!(FlowRecord::decode(&bytes).is_none());
    bytes[0] = 128;
    bytes[2] = 2;
    assert!(FlowRecord::decode(&bytes).is_none());
}
