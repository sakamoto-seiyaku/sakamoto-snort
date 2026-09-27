//! Bounded current overview. This is not a persistent history store.
use crate::{ffi, ErrorCode, ProductCore, ProductError, Status};
use serde::{Deserialize, Serialize};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct ChannelHealth {
    pub attempted: u64,
    pub published: u64,
    pub full: u64,
    pub oversize: u64,
    pub consumed: u64,
    pub notify_errors: u64,
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
    pub channels: [ChannelHealth; 4],
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
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FlowRecord {
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
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 424 {
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
        if length != 416 + address_bytes
            || data.len() < length
            || data[2] != 3
            || data[3] & !7 != 0
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
            })
        };
        Some(Self {
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
            addresses: data[416..length].to_vec(),
            policy_revision: u64_at(88),
            winner: u64_at(96),
            attribution: [decode_attribution(128)?, decode_attribution(272)?],
        })
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
    capacity: usize,
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
            capacity,
        }
    }

    /// Each slot retains its greatest incarnation, including its END tombstone.
    /// Replacing a still-active instance denotes a missing END, not a new delta
    /// from the old instance. Cumulative rollback rejects the entire update.
    pub fn consume(&mut self, record: FlowRecord) -> bool {
        let index = record.owner as usize * self.capacity + record.slot as usize;
        if record.generation != self.generation
            || record.incarnation == 0
            || record.sequence == 0
            || record.slot as usize >= self.capacity
            || index >= self.records.len()
            || record.last_seen < record.first_seen
        {
            self.rejected += 1;
            return false;
        }
        let mut packets = record.packets;
        let mut bytes = record.bytes;
        if let Some(old) = &self.records[index] {
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
                    self.incomplete = true;
                }
                self.active += 1;
            }
        } else {
            self.active += 1;
            if record.sequence != 1 {
                self.incomplete = true;
            }
        }
        for i in 0..2 {
            self.packets[i] = self.packets[i].saturating_add(packets[i]);
            self.bytes[i] = self.bytes[i].saturating_add(bytes[i]);
        }
        if record.ended {
            self.active -= 1;
            self.ended += 1;
        }
        self.records[index] = Some(record);
        self.accepted += 1;
        true
    }
}

impl ProductCore {
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
        let overview = self.observation.as_ref().map(|s| s.snapshot());
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
