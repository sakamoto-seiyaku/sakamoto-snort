//! Bounded DNS query-decision records on the existing observation transport.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub generation: u64,
    pub owner: u16,
    pub token: u64,
    pub incarnation: u64,
    pub mono_us: u64,
    pub activity_utc_us: u64,
    pub policy_generation: u64,
    pub policy_revision: u64,
    pub policy_hash: u64,
    pub winner: u64,
    pub uid: u32,
    pub network: u32,
    pub ifindex: u32,
    pub codec_peak_bytes: u32,
    pub slot: u32,
    pub id: u16,
    pub query_flags: u16,
    pub qtype: u16,
    pub qclass: u16,
    pub source_port: u16,
    pub resolver_port: u16,
    pub family: u8,
    pub protocol: u8,
    pub direction: u8,
    pub availability: u8,
    pub caller: u8,
    pub coverage: u8,
    pub declared_action: u8,
    pub actual_action: u8,
    pub mode: u8,
    pub domain_available: bool,
    pub stage: u8,
    pub delivery: u8,
    pub source_address: [u8; 16],
    pub resolver_address: [u8; 16],
    pub rule_name: String,
    pub name: String,
}

impl DnsRecord {
    pub fn valid(&self) -> bool {
        self.generation != 0 && self.token != 0 && self.owner < 62
            && matches!(self.family, 4 | 6) && self.protocol == 17
            && self.direction == 3 && self.resolver_port == 53
            && self.stage == 1 && self.delivery == 0
            && self.coverage >= 1 && self.coverage <= 5
            && self.caller <= 1 && self.availability & !15 == 0
            && self.query_flags & 0x8000 == 0
            && self.codec_peak_bytes <= 512 * 1024
            && self.name.len() <= 255 && self.name.is_ascii()
            && !self.name.as_bytes().contains(&0)
            && self.rule_name.len() <= 63 && !self.rule_name.as_bytes().contains(&0)
            && (self.family != 4 || (self.source_address[4..] == [0; 12]
                && self.resolver_address[4..] == [0; 12]))
            && (self.caller == 1) == (self.availability & 9 == 9 && self.uid != u32::MAX)
            && (self.slot == u32::MAX) == (self.incarnation == 0)
            && (!self.domain_available || (self.caller == 1 && self.coverage == 1
                && !self.name.is_empty()))
            && self.declared_action <= 2 && self.actual_action <= 2 && self.mode <= 1
            && (if self.winner == 0 {
                self.mode == 0 && self.actual_action == self.declared_action
            } else {
                self.policy_generation == self.generation && self.policy_revision != 0
                    && self.declared_action != 0
                    && self.actual_action == if self.mode == 1 { 1 } else { self.declared_action }
            })
    }

    pub(crate) fn key(&self) -> String {
        format!("{:020}:{:020}:{:04}", self.generation, self.token, self.owner)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 480 || data[2..4] != [5, 16]
            || data[6..8] != [0, 0] || data[126..128] != [0, 0] {
            return None;
        }
        let u16_at = |n| u16::from_le_bytes(data[n..n + 2].try_into().unwrap());
        let u32_at = |n| u32::from_le_bytes(data[n..n + 4].try_into().unwrap());
        let u64_at = |n| u64::from_le_bytes(data[n..n + 8].try_into().unwrap());
        if u16_at(0) != 480 || u16_at(112) > 255 || data[123] > 1 { return None; }
        let name_length = u16_at(112) as usize;
        if data[224 + name_length..480].iter().any(|byte| *byte != 0) { return None; }
        let rule_name = &data[160..224];
        let rule_length = rule_name.iter().position(|byte| *byte == 0)?;
        if rule_name[rule_length..].iter().any(|byte| *byte != 0) { return None; }
        let record = Self {
            generation: u64_at(8), owner: u16_at(4), token: u64_at(16),
            incarnation: u64_at(24), mono_us: u64_at(32), activity_utc_us: u64_at(40),
            policy_generation: u64_at(48), policy_revision: u64_at(56),
            policy_hash: u64_at(64), winner: u64_at(72), uid: u32_at(80),
            network: u32_at(84), ifindex: u32_at(88), codec_peak_bytes: u32_at(92),
            slot: u32_at(96), id: u16_at(100), query_flags: u16_at(102),
            qtype: u16_at(104), qclass: u16_at(106), source_port: u16_at(108),
            resolver_port: u16_at(110), family: data[114], protocol: data[115],
            direction: data[116], availability: data[117], caller: data[118],
            coverage: data[119], declared_action: data[120], actual_action: data[121],
            mode: data[122], domain_available: data[123] != 0,
            stage: data[124], delivery: data[125],
            source_address: data[128..144].try_into().ok()?,
            resolver_address: data[144..160].try_into().ok()?,
            rule_name: std::str::from_utf8(&rule_name[..rule_length]).ok()?.into(),
            name: std::str::from_utf8(&data[224..224 + name_length]).ok()?.into(),
        };
        record.valid().then_some(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn wire_record() -> [u8; 480] {
        let mut data = [0; 480];
        data[..2].copy_from_slice(&480u16.to_le_bytes());
        data[2] = 5;
        data[3] = 16;
        data[8..16].copy_from_slice(&77u64.to_le_bytes());
        data[16..24].copy_from_slice(&310u64.to_le_bytes());
        data[32..40].copy_from_slice(&1u64.to_le_bytes());
        data[40..48].copy_from_slice(&123456u64.to_le_bytes());
        data[48..56].copy_from_slice(&77u64.to_le_bytes());
        data[56..64].copy_from_slice(&9u64.to_le_bytes());
        data[64..72].copy_from_slice(&123u64.to_le_bytes());
        data[72..80].copy_from_slice(&310u64.to_le_bytes());
        data[80..84].copy_from_slice(&10123u32.to_le_bytes());
        data[84..88].copy_from_slice(&u32::MAX.to_le_bytes());
        data[96..100].copy_from_slice(&u32::MAX.to_le_bytes());
        data[100..102].copy_from_slice(&0x1234u16.to_le_bytes());
        data[102..104].copy_from_slice(&0x0100u16.to_le_bytes());
        data[104..106].copy_from_slice(&1u16.to_le_bytes());
        data[106..108].copy_from_slice(&1u16.to_le_bytes());
        data[108..110].copy_from_slice(&40000u16.to_le_bytes());
        data[110..112].copy_from_slice(&53u16.to_le_bytes());
        data[112..114].copy_from_slice(&11u16.to_le_bytes());
        data[114..126].copy_from_slice(&[4,17,3,9,1,1,2,2,0,1,1,0]);
        data[128..132].copy_from_slice(&[192,168,1,2]);
        data[144..148].copy_from_slice(&[192,168,1,53]);
        data[160..170].copy_from_slice(b"block name");
        data[224..235].copy_from_slice(b"example.com");
        data
    }

    #[test]
    fn decodes_query_identity_without_claiming_delivery() {
        let record = DnsRecord::decode(&wire_record()).expect("DNS record on normal owner channel");
        assert_eq!(record.name, "example.com");
        assert_eq!(record.caller, 1);
        assert_eq!(record.uid, 10123);
        assert_eq!(record.winner, 310);
        assert_eq!(record.actual_action, 2);
        assert_eq!(record.resolver_address[..4], [192,168,1,53]);
        assert_eq!(record.resolver_port, 53);
        assert_eq!(record.delivery, 0);
    }

    #[test]
    fn rejects_inconsistent_reliability_and_availability() {
        for (offset, value) in [(117, 1), (118, 0), (119, 2), (122, 1), (123, 2), (125, 1)] {
            let mut data = wire_record();
            data[offset] = value;
            assert!(DnsRecord::decode(&data).is_none(), "offset {offset}");
        }
        let mut data = wire_record();
        data[117] = 1; data[118] = 0; data[123] = 0;
        let unknown = DnsRecord::decode(&data).unwrap();
        assert_eq!(unknown.uid, 10123); // Socket identity is still retained.
        assert!(!unknown.domain_available);
        data[235] = b'x';
        assert!(DnsRecord::decode(&data).is_none());
    }
}
