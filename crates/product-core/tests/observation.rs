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
fn blocked_and_flow_with_same_slot_remain_independent() {
    let mut view = Overview::new(77, 2, 4);
    let flow = FlowRecord {
        generation: 77, owner: 0, slot: 1, incarnation: 1, sequence: 1,
        packets: [1, 0], bytes: [60, 0], ..Default::default()
    };
    let blocked = FlowRecord {
        blocked: true, packets: [2, 0], bytes: [120, 0], ..flow.clone()
    };
    assert!(view.consume(blocked.clone()));
    assert!(view.consume(flow));
    assert_eq!(view.packets, [3, 0]);
    assert_eq!(view.blocked_packets, [2, 0]);
    assert_eq!(view.active, 2);
    assert_eq!(view.blocked_active, 1);
    assert!(!view.consume(blocked.clone()));
    assert!(view.consume(FlowRecord { sequence: 2, ended: true, end_reason: 2, ..blocked }));
    assert_eq!(view.active, 1);
    assert_eq!(view.blocked_active, 0);
    assert_eq!(view.blocked_ended, 1);
}

#[test]
fn blocked_shape_uses_its_own_capacity_and_drop_provenance() {
    let mut view = Overview::new(77, 2, 2048);
    assert_eq!(view.records.len(), 4096);
    assert_eq!(view.blocked_records.len(), 2048);
    let mut record = FlowRecord {
        blocked: true, generation: 77, owner: 0, slot: 1024,
        incarnation: 1, sequence: 1, ..Default::default()
    };
    assert!(!view.consume(record.clone()));
    record.slot = 1;
    record.attribution[0].valid = true;
    record.attribution[0].winner = 65537;
    record.attribution[0].actual_action = 1;
    assert!(!view.consume(record.clone()));
    record.attribution[0].actual_action = 2;
    assert!(view.consume(record));
    assert_eq!(view.blocked_active, 1);
}

#[test]
fn wire_record_is_length_and_version_checked() {
    let mut bytes = [0u8; 448];
    bytes[0..4].copy_from_slice(&[168, 1, 4, 2]);
    bytes[16] = 7; // generation
    bytes[24] = 11; // incarnation
    bytes[32] = 1; // update
    bytes[56] = 3; // ORIG packets
    bytes[80] = 80; // REPLY bytes
    bytes[112] = 4;
    bytes[113] = 17;
    bytes[416..424].copy_from_slice(&[10, 1, 2, 3, 10, 4, 5, 6]);
    bytes[128] = 1; // ORIG segment
    bytes[128 + 24] = 61; // activity UTC
    bytes[128 + 32] = 7; // policy generation
    bytes[128 + 40] = 3; // revision
    bytes[128 + 48] = 9; // hash
    bytes[128 + 56..128 + 64].copy_from_slice(&65537u64.to_le_bytes());
    bytes[128 + 64] = 42; // UID
    bytes[128 + 72..128 + 76].copy_from_slice(&[2, 1, 1, 1]);
    bytes[128 + 76..128 + 79].copy_from_slice(b"old");
    let r = FlowRecord::decode(&bytes).unwrap();
    assert_eq!(r.attribution[0].name, "old");
    assert_eq!(r.attribution[0].winner, 65537);
    assert_eq!(r.attribution[0].declared_action, 2);
    assert_eq!(r.attribution[0].actual_action, 1);
    assert!(!r.attribution[1].valid);
    assert_eq!(r.generation, 7);
    assert_eq!(r.incarnation, 11);
    assert_eq!(r.packets, [3, 0]);
    assert_eq!(r.bytes, [0, 80]);
    assert_eq!(r.addresses, [10, 1, 2, 3, 10, 4, 5, 6]);
    bytes[3] |= 8; // same record is invalid as blocked/actual ALLOW
    assert!(FlowRecord::decode(&bytes).is_none());
    bytes[128 + 73] = 2; // valid blocked/actual DROP
    assert!(FlowRecord::decode(&bytes).unwrap().blocked);
    bytes[117] = 2; // live blocked record cannot claim idle END reason
    assert!(FlowRecord::decode(&bytes).is_none());
    bytes[3] |= 1; // idle END requires reason 2
    assert!(FlowRecord::decode(&bytes).unwrap().ended);
    bytes[117] = 0;
    assert!(FlowRecord::decode(&bytes).is_none());
    bytes[3] &= !8;
    bytes[0] = 127;
    assert!(FlowRecord::decode(&bytes).is_none());
    bytes[0] = 168;
    bytes[2] = 1;
    assert!(FlowRecord::decode(&bytes).is_none());
}
