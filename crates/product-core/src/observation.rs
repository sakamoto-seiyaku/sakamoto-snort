//! Bounded current overview. This is not a persistent history store.
use crate::{ffi, ErrorCode, ProductCore, ProductError, Status};
use serde::{Deserialize, Serialize};

#[path = "../../../generated/rust/application_protocol_catalog.rs"]
#[allow(dead_code)] // This module shares the generated catalog with other languages.
mod protocol_catalog;

pub fn protocol_label(bit: u32) -> Option<(u32, &'static str)> {
    protocol_catalog::APPLICATION_PROTOCOL_CATALOG
        .iter()
        .filter(|entry| entry.status == "active")
        .nth(bit as usize)
        .map(|entry| (entry.id, entry.key))
}

/// Stored windows retain released identities even after a later catalog
/// marks an ID reserved. Live bit positions still use active entries only.
pub fn historical_protocol_label(id: u32) -> Option<&'static str> {
    protocol_catalog::APPLICATION_PROTOCOL_CATALOG
        .iter()
        .find(|entry| entry.id == id)
        .map(|entry| entry.key)
}

pub fn protocol_mask() -> u64 {
    let count = protocol_catalog::APPLICATION_PROTOCOL_CATALOG
        .iter()
        .filter(|entry| entry.status == "active")
        .count();
    if count == 64 { u64::MAX } else { (1u64 << count) - 1 }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ChannelHealth {
    pub attempted: u64,
    pub published: u64,
    pub full: u64,
    pub oversize: u64,
    pub consumed: u64,
    pub notify_errors: u64,
    pub allocation_lost: u64,
    pub pending: u64,
    pub notifications: u64,
    pub basic_packets: [u64; 3],
    pub basic_bytes: [u64; 3],
    pub occupancy: u32,
    pub capacity: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ObservationHealth {
    pub generation: u64,
    pub mapping_bytes: u64,
    pub version: u32,
    pub owners: u32,
    pub flow_capacity: u32,
    pub connected: u32,
    pub blocked_capacity: u32,
    pub blocked_active: [u32; 2],
    pub blocked_capacity_misses: [u64; 2],
    pub blocked_retired: [u64; 2],
    pub channels: [ChannelHealth; 4],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LiveFlowEntry {
    pub incarnation: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub policy_generation: u64,
    pub policy_revision: u64,
    pub policy_hash: u64,
    pub winner: u64,
    pub protocols: u64,
    pub worker: u32,
    pub slot: u32,
    pub uid: u32,
    pub network: u32,
    pub query_class: u32,
    pub sni_result: u32,
    pub sni_stop: u32,
    pub lpi_stop: u32,
    pub ports: [u16; 2],
    pub family: u8,
    pub protocol: u8,
    pub kind: u8,
    pub origin_is_a: u8,
    pub flow_origin_direction: u8,
    pub last_device_direction: u8,
    pub last_flow_direction: u8,
    pub protocols_available: u8,
    pub addresses: [u8; 32],
    pub attribution: [LiveFlowAttribution; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LiveFlowAttribution {
    pub segment: u64,
    pub start_packets: u64,
    pub start_bytes: u64,
    pub activity_utc_us: u64,
    pub policy_generation: u64,
    pub policy_revision: u64,
    pub policy_hash: u64,
    pub winner: u64,
    pub uid: u32,
    pub network: u32,
    pub declared_action: u8,
    pub actual_action: u8,
    pub mode: u8,
    pub valid: u8,
    pub name: [u8; 64],
    pub padding: [u8; 4],
    pub protocol_set: u64,
    pub protocols_available: u8,
    pub protocol_padding: [u8; 7],
}

impl Default for LiveFlowAttribution {
    fn default() -> Self { Self {
        segment:0,start_packets:0,start_bytes:0,activity_utc_us:0,
        policy_generation:0,policy_revision:0,policy_hash:0,winner:0,
        uid:0,network:0,declared_action:0,actual_action:0,mode:0,valid:0,
        name:[0;64],padding:[0;4],protocol_set:0,protocols_available:0,
        protocol_padding:[0;7],
    }}
}

fn published_labels(mask: u64) -> Vec<serde_json::Value> {
    (0..64)
        .filter(|bit| mask & (1u64 << bit) != 0)
        .filter_map(|bit| protocol_label(bit).map(|(id, key)| serde_json::json!({"id":id,"key":key})))
        .collect()
}

impl LiveFlowAttribution {
    fn json(&self) -> serde_json::Value {
        if self.valid == 0 { return serde_json::json!({"available":false}); }
        let end = self.name.iter().position(|byte| *byte == 0).unwrap_or(self.name.len());
        let name = std::str::from_utf8(&self.name[..end]).ok();
        serde_json::json!({
            "available":true,"segment":self.segment.to_string(),
            "start_packets":self.start_packets,"start_bytes":self.start_bytes,
            "activity_utc_us":self.activity_utc_us,
            "policy_generation":self.policy_generation.to_string(),
            "policy_revision":self.policy_revision.to_string(),"policy_hash":self.policy_hash.to_string(),
            "winner":self.winner.to_string(),"uid":self.uid,"network":self.network,
            "declared_action":self.declared_action,"actual_action":self.actual_action,
            "mode":self.mode,"name":name,
            "protocols_available":self.protocols_available != 0,
            "protocol_set":self.protocol_set.to_string(),
            "protocol_labels":published_labels(self.protocol_set),
        })
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LiveFlowPage {
    pub generation: u64,
    pub allocated_bytes: [u64; 2],
    pub capacity_misses: [u64; 2],
    pub capacity: [u32; 2],
    pub active: [u32; 2],
    pub high_watermark: [u32; 2],
    pub cursor: u32,
    pub next_cursor: u32,
    pub scanned: u32,
    pub count: u32,
    pub done: u32,
    pub entries: [LiveFlowEntry; 16],
}

impl LiveFlowEntry {
    fn endpoint(&self, side: usize) -> String {
        let bytes = &self.addresses[side * 16..side * 16 + 16];
        match self.family {
            4 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).unwrap()).to_string(),
            6 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string(),
            _ => "unknown".into(),
        }
    }

    fn json(&self) -> serde_json::Value {
        let labels = published_labels(self.protocols);
        serde_json::json!({
            "worker":self.worker,"slot":self.slot,"incarnation":self.incarnation.to_string(),
            "canonical_a":self.endpoint(0),"canonical_b":self.endpoint(1),
            "port_a":self.ports[0],"port_b":self.ports[1],
            "origin_is_a":self.origin_is_a != 0,"family":self.family,
            "protocol":self.protocol,"kind":self.kind,"query_class":self.query_class,
            "uid":self.uid,"network":self.network,
            "first_seen_monotonic_us":self.first_seen,
            "last_seen_monotonic_us":self.last_seen,
            "packets":self.packets,"bytes":self.bytes,
            "flow_origin_device_direction":self.flow_origin_direction,
            "last_device_direction":self.last_device_direction,
            "last_flow_direction":self.last_flow_direction,
            "protocols_available":self.protocols_available != 0,
            "protocol_set":self.protocols.to_string(),"protocol_labels":labels,
            "lpi_stop":self.lpi_stop,"sni_result":self.sni_result,"sni_stop":self.sni_stop,
            "policy_generation":self.policy_generation.to_string(),"policy_revision":self.policy_revision.to_string(),
            "policy_hash":self.policy_hash.to_string(),"winner":self.winner.to_string(),
            "attribution":[self.attribution[0].json(),self.attribution[1].json()]
        })
    }
}

impl LiveFlowPage {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "source":"vpp","generation":self.generation,
            "cursor":self.cursor,"next_cursor":self.next_cursor,
            "scanned":self.scanned,"count":self.count,"done":self.done != 0,
            "page_limit":16,"scan_limit":256,
            "snapshot_consistent_across_pages":false,
            "capacity":self.capacity,"active":self.active,
            "high_watermark":self.high_watermark,
            "allocated_bytes":self.allocated_bytes,
            "capacity_misses":self.capacity_misses,
            "entries":self.entries[..self.count as usize].iter().map(LiveFlowEntry::json).collect::<Vec<_>>()
        })
    }
}

/// Direction-local segment provenance. Start counters delimit only this segment;
/// a lost predecessor is never inferred from the latest context.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Attribution {
    pub segment: u64,
    pub start_packets: u64,
    pub start_bytes: u64,
    pub activity_utc_us: u64,
    pub policy_generation: u64,
    pub policy_revision: u64,
    pub policy_hash: u64,
    pub winner: u64,
    pub uid: u32,
    pub network: u32,
    pub declared_action: u8,
    pub actual_action: u8,
    pub mode: u8,
    pub valid: bool,
    pub name: String,
    #[serde(default)]
    pub protocol_set: u64,
    #[serde(default)]
    pub protocols_available: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FlowRecord {
    #[serde(default)]
    pub blocked: bool,
    pub generation: u64,
    pub owner: u16,
    pub slot: u32,
    pub incarnation: u64,
    pub sequence: u64,
    pub first_seen: u64,
    pub last_seen: u64,
    pub activity_utc_us: u64,
    pub clock_changed: bool,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub ended: bool,
    pub uid: u32,
    pub network: u32,
    pub family: u8,
    pub protocol: u8,
    pub origin_device_direction: u8,
    pub last_device_direction: u8,
    pub last_flow_direction: u8,
    pub end_reason: u8,
    pub ports: [u16; 2],
    pub addresses: Vec<u8>,
    pub policy_revision: u64,
    pub winner: u64,
    #[serde(default)]
    pub attribution: [Attribution; 2],
}

impl FlowRecord {
    pub fn kind_attribution_valid(&self) -> bool {
        !self.blocked
            || ((if self.ended { self.end_reason == 2 } else { self.end_reason == 0 })
                && self
                    .attribution
                    .iter()
                    .all(|a| !a.valid || (a.actual_action == 2 && a.winner != 0)))
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 456 {
            return None;
        }
        let u16_at = |n| u16::from_le_bytes([data[n], data[n + 1]]);
        let u32_at = |n| u32::from_le_bytes(data[n..n + 4].try_into().unwrap());
        let u64_at = |n| u64::from_le_bytes(data[n..n + 8].try_into().unwrap());
        let length = u16_at(0) as usize;
        let address_bytes = match data[112] {
            4 => 8,
            6 => 32,
            _ => return None,
        };
        if length != 448 + address_bytes
            || data.len() < length
            || data[2] != 5
            || data[3] & !15 != 0
            || data[6..8] != [0, 0]
            || data[118..120] != [0, 0]
        {
            return None;
        }
        let decode_attribution = |offset: usize| -> Option<Attribution> {
            let name = &data[offset + 76..offset + 140];
            let end = name.iter().position(|b| *b == 0)?;
            if name[end..].iter().any(|b| *b != 0)
                || data[offset + 140..offset + 144] != [0; 4]
                || data[offset + 152] > 1
                || data[offset + 153..offset + 160] != [0; 7]
                || data[offset + 75] > 1
            {
                return None;
            }
            Some(Attribution {
                segment: u64_at(offset),
                start_packets: u64_at(offset + 8),
                start_bytes: u64_at(offset + 16),
                activity_utc_us: u64_at(offset + 24),
                policy_generation: u64_at(offset + 32),
                policy_revision: u64_at(offset + 40),
                policy_hash: u64_at(offset + 48),
                winner: u64_at(offset + 56),
                uid: u32_at(offset + 64),
                network: u32_at(offset + 68),
                declared_action: data[offset + 72],
                actual_action: data[offset + 73],
                mode: data[offset + 74],
                valid: data[offset + 75] != 0,
                name: std::str::from_utf8(&name[..end]).ok()?.into(),
                protocol_set: u64_at(offset + 144),
                protocols_available: data[offset + 152] != 0,
            })
        };
        let record = Self {
            blocked: data[3] & 8 != 0,
            generation: u64_at(16),
            owner: u16_at(4),
            slot: u32_at(8),
            incarnation: u64_at(24),
            sequence: u64_at(32),
            first_seen: u64_at(40),
            last_seen: u64_at(48),
            activity_utc_us: u64_at(120),
            clock_changed: data[3] & 4 != 0,
            packets: [u64_at(56), u64_at(64)],
            bytes: [u64_at(72), u64_at(80)],
            ended: data[3] & 1 != 0,
            uid: u32_at(12),
            network: u32_at(104),
            family: data[112],
            protocol: data[113],
            origin_device_direction: data[114],
            last_device_direction: data[115],
            last_flow_direction: data[116],
            end_reason: data[117],
            ports: [u16_at(108), u16_at(110)],
            addresses: data[448..length].to_vec(),
            policy_revision: u64_at(88),
            winner: u64_at(96),
            attribution: [decode_attribution(128)?, decode_attribution(288)?],
        };
        (record.kind_attribution_valid()
            && record.attribution.iter().all(|a| {
                a.protocol_set & !protocol_mask() == 0
                    && (a.protocols_available || a.protocol_set == 0)
                    && (!record.blocked || (!a.protocols_available && a.protocol_set == 0))
            }))
        .then_some(record)
    }
}

#[derive(Debug, Serialize)]
pub struct Overview {
    pub generation: u64,
    pub packets: [u64; 2],
    pub bytes: [u64; 2],
    pub active: u64,
    pub ended: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub incomplete: bool,
    pub records: Vec<Option<FlowRecord>>,
    pub blocked_records: Vec<Option<FlowRecord>>,
    pub blocked_packets: [u64; 2],
    pub blocked_bytes: [u64; 2],
    pub blocked_active: u64,
    pub blocked_ended: u64,
    capacity: usize,
    blocked_capacity: usize,
}

impl Overview {
    pub fn new(generation: u64, owners: usize, capacity: usize) -> Self {
        Self {
            generation,
            packets: [0; 2],
            bytes: [0; 2],
            active: 0,
            ended: 0,
            accepted: 0,
            rejected: 0,
            incomplete: false,
            records: vec![None; owners * capacity],
            blocked_records: vec![None; owners * capacity.min(1024)],
            blocked_packets: [0; 2],
            blocked_bytes: [0; 2],
            blocked_active: 0,
            blocked_ended: 0,
            capacity,
            blocked_capacity: capacity.min(1024),
        }
    }

    /// Each slot retains its greatest incarnation, including its END tombstone.
    /// Replacing a still-active instance denotes a missing END, not a new delta
    /// from the old instance. Cumulative rollback rejects the entire update.
    pub fn consume(&mut self, record: FlowRecord) -> bool {
        let capacity = if record.blocked { self.blocked_capacity } else { self.capacity };
        let index = record.owner as usize * capacity + record.slot as usize;
        let records = if record.blocked {
            &mut self.blocked_records
        } else {
            &mut self.records
        };
        if record.generation != self.generation
            || record.incarnation == 0
            || record.sequence == 0
            || record.slot as usize >= capacity
            || index >= records.len()
            || record.last_seen < record.first_seen
            || !record.kind_attribution_valid()
        {
            self.rejected += 1;
            return false;
        }
        let mut packets = record.packets;
        let mut bytes = record.bytes;
        if let Some(old) = &records[index] {
            if record.incarnation < old.incarnation
                || (record.incarnation == old.incarnation
                    && (old.ended
                        || record.sequence <= old.sequence
                        || record.last_seen < old.last_seen
                        || (0..2).any(|i| {
                            record.packets[i] < old.packets[i] || record.bytes[i] < old.bytes[i]
                        })))
            {
                self.rejected += 1;
                return false;
            }
            if record.incarnation == old.incarnation {
                if record.sequence != old.sequence + 1 {
                    self.incomplete = true;
                }
                for i in 0..2 {
                    packets[i] -= old.packets[i];
                    bytes[i] -= old.bytes[i];
                }
            } else {
                if !old.ended {
                    self.active -= 1;
                    if record.blocked { self.blocked_active -= 1; }
                    self.incomplete = true;
                }
                self.active += 1;
                if record.blocked { self.blocked_active += 1; }
            }
        } else {
            self.active += 1;
            if record.blocked { self.blocked_active += 1; }
            if record.sequence != 1 {
                self.incomplete = true;
            }
        }
        for i in 0..2 {
            self.packets[i] = self.packets[i].saturating_add(packets[i]);
            self.bytes[i] = self.bytes[i].saturating_add(bytes[i]);
            if record.blocked {
                self.blocked_packets[i] = self.blocked_packets[i].saturating_add(packets[i]);
                self.blocked_bytes[i] = self.blocked_bytes[i].saturating_add(bytes[i]);
            }
        }
        if record.ended {
            self.active -= 1;
            self.ended += 1;
            if record.blocked {
                self.blocked_active -= 1;
                self.blocked_ended += 1;
            }
        }
        records[index] = Some(record);
        self.accepted += 1;
        true
    }
}

impl ProductCore {
    pub fn query_live_flows(&mut self, cursor: u32) -> Result<LiveFlowPage, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut page = LiveFlowPage::default();
        let code = unsafe { ffi::sakamoto_product_session_flow_query(
            session.as_ptr(), self.generation, cursor, &mut page) };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status::empty(self.generation),
            });
        }
        Ok(page)
    }

    pub fn observation_page_json(&mut self, cursor: u32) -> String {
        let mut reply: serde_json::Value = serde_json::from_str(&self.observation_json())
            .expect("observation JSON");
        reply["current_flows"] = match self.query_live_flows(cursor) {
            Ok(page) => page.json(),
            Err(error) => serde_json::json!({"source":"vpp","error":format!("{error:?}")}),
        };
        reply["vpp"] = match self.query() {
            Ok(status) => serde_json::json!({
                "source":"vpp","generation":status.generation,
                "core_ready":status.core_ready,
                "adapter_available":status.adapter_available,
                "protection_running":status.protection_running,
                "graph_enabled":status.product_graph_enabled,
                "graph_accepting":status.product_graph_accepting,
                "policy_requested_revision":status.policy_requested_revision.to_string(),
                "policy_active_revision":status.policy_active_revision.to_string(),
                "policy_generation":status.policy_generation.to_string(),
                "policy_snapshot_hash":status.policy_snapshot_hash.to_string(),
                "policy_last_apply_status_code":status.policy_last_apply_status_code,
                "policy_rule_count":status.policy_l4_rule_count,
                "logical_hits":status.policy_l4_match_records,
                "policy_drops":status.policy_drop_records,
                "root_input_packets":status.root_nfqueue_input_packets,
                "root_output_packets":status.root_nfqueue_output_packets,
                "root_verdict_attempts":status.root_nfqueue_verdict_attempts,
                "root_verdict_failed_definite":status.root_nfqueue_verdict_failed_definite,
                "root_verdict_outcome_unknown":status.root_nfqueue_verdict_outcome_unknown,
                "root_graph_submit_fail_opens":status.root_nfqueue_graph_submit_fail_opens,
                "vpn_tun_ingress_packets":status.vpn_tun_ingress_packets,
                "vpn_tun_write_completions":status.vpn_tun_write_completions,
                "vpn_infrastructure_faults":status.vpn_infrastructure_faults,
                "error_detail":status.error_detail,
            }),
            Err(error) => serde_json::json!({"source":"vpp","error":format!("{error:?}")}),
        };
        let source = crate::RuleConfigRequest { schema: 1, ..Default::default() };
        reply["policy_source"] = match self.rule_config_boxed(&source) {
            Ok(status) => serde_json::json!({
                "source":"vpp","generation":status.generation,
                "saved_revision":status.saved_revision.to_string(),"active_revision":status.active_revision.to_string(),
                "saved_rule_version":status.saved_rule_version.to_string(),
                "active_rule_version":status.active_rule_version.to_string(),
                "result":status.result,"save_error":status.save_error,
                "compile_error":status.compile_error,"compiler_status":status.compiler_status,
                "error_index":status.error_index,"saved_rule_count":status.count,
                "active_rule_count":status.active_count,
            }),
            Err(error) => serde_json::json!({"source":"vpp","error":format!("{error:?}")}),
        };
        reply.to_string()
    }

    pub fn query_observation_health(&mut self) -> Result<ObservationHealth, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut health = ObservationHealth::default();
        let code = unsafe {
            ffi::sakamoto_product_session_observation_query(
                session.as_ptr(),
                self.generation,
                &mut health,
            )
        };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status::empty(self.generation),
            });
        }
        Ok(health)
    }

    pub fn start_observation(&mut self) -> Result<(), String> {
        let path = self.api_path.with_file_name("observation.json");
        self.start_observation_at(&path)
    }

    pub fn start_observation_at(&mut self, path: &std::path::Path) -> Result<(), String> {
        if self.observation.is_none() {
            self.observation = Some(crate::observation_service::ObservationService::start(
                &self.api_path,
                self.generation,
                path,
            )?);
        }
        Ok(())
    }

    pub fn observation_json(&mut self) -> String {
        let health = self.query_observation_health();
        let mut overview = self.observation.as_ref().map(|s| s.snapshot());
        if let Some(ref mut snapshot) = overview {
            let source = if crate::history::needs_source(snapshot) {
                crate::history::live_source(self)
            } else {
                Err("no_historical_rule_reference")
            };
            crate::history::annotate(snapshot, source);
        }
        match health {
            Ok(health) => serde_json::json!({ "schema": 1, "health": health,
                "consumer": overview, "persistent_history": true })
            .to_string(),
            Err(error) => serde_json::json!({ "schema": 1, "error": format!("{error:?}"),
                "consumer": overview, "persistent_history": true })
            .to_string(),
        }
    }

    /// Controlled ingestion pause for bounded-loss validation. The packet
    /// producer and normal health query remain live; this creates no replay.
    pub fn pause_observation(&mut self, pause: bool) -> Result<(), String> {
        self.observation
            .as_ref()
            .ok_or("consumer_not_started")?
            .pause(pause);
        Ok(())
    }
}

#[cfg(test)]
mod live_flow_query_tests {
    use super::*;

    #[test]
    fn native_page_layout_and_published_facts_keep_their_identity() {
        assert_eq!(std::mem::size_of::<LiveFlowAttribution>(), 160);
        assert_eq!(std::mem::size_of::<LiveFlowEntry>(), 496);
        assert_eq!(std::mem::size_of::<LiveFlowPage>(), 8024);
        let mut page = LiveFlowPage { generation: 19, count: 1, scanned: 2,
            next_cursor: 2, capacity: [1024, 1024], active: [1, 0],
            ..LiveFlowPage::default() };
        page.entries[0] = LiveFlowEntry {
            incarnation: 7, worker: 0, slot: 1, family: 4, protocol: 17,
            ports: [44000, 53], protocols: 1, protocols_available: 1,
            packets: [2, 1], bytes: [200, 100], ..LiveFlowEntry::default()
        };
        page.entries[0].addresses[12..16].copy_from_slice(&[10, 1, 2, 3]);
        page.entries[0].addresses[28..32].copy_from_slice(&[10, 4, 5, 6]);
        page.entries[0].winner = u64::MAX;
        page.entries[0].attribution[0].valid = 1;
        page.entries[0].attribution[0].winner = u64::MAX;
        let view = page.json();
        assert_eq!(view["generation"], 19);
        assert_eq!(view["next_cursor"], 2);
        assert_eq!(view["entries"][0]["canonical_a"], "10.1.2.3");
        assert_eq!(view["entries"][0]["canonical_b"], "10.4.5.6");
        assert_eq!(view["entries"][0]["packets"], serde_json::json!([2, 1]));
        assert_eq!(view["entries"][0]["winner"], u64::MAX.to_string());
        assert_eq!(view["entries"][0]["attribution"][0]["winner"], u64::MAX.to_string());
        let (id, key) = protocol_label(0).unwrap();
        assert_eq!(view["entries"][0]["protocol_labels"][0]["id"], id);
        assert_eq!(view["entries"][0]["protocol_labels"][0]["key"], key);
        page.entries[0].protocols = 0;
        page.entries[0].protocols_available = 0;
        let unknown = page.json();
        assert_eq!(unknown["entries"][0]["protocols_available"], false);
        assert!(unknown["entries"][0]["protocol_labels"].as_array().unwrap().is_empty());
    }
}
