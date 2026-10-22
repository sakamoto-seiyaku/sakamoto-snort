//! Bounded original DNS query/response records on the existing observation transport.
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
    #[serde(default)] pub query_token: u64,
    #[serde(default)] pub query_policy_generation: u64,
    #[serde(default)] pub query_policy_revision: u64,
    #[serde(default)] pub query_policy_hash: u64,
    #[serde(default)] pub query_winner: u64,
    #[serde(default)] pub network_revision: u64,
    #[serde(default)] pub transport_session: u64,
    #[serde(default)] pub underlay_epoch: u64,
    #[serde(default)] pub query_incarnation: u64,
    #[serde(default)] pub matched_requests: u16,
    #[serde(default)] pub retransmits: u16,
    #[serde(default)] pub candidate_count: u8,
    #[serde(default)] pub name_index: u8,
    #[serde(default)] pub name_source: u8,
    #[serde(default)] pub chain_status: u8,
    #[serde(default)] pub correlation: u8,
    #[serde(default)] pub domain_lists: u64,
    #[serde(default)] pub rcode: u16,
    #[serde(default)] pub adapter_profile: u8,
    #[serde(default)] pub packet_uid: u32,
    #[serde(default)] pub packet_availability: u8,
}

impl DnsRecord {
    pub fn valid(&self) -> bool {
        // The INPUT/UDP53 control point is known even when the DNS header
        // could not be read. Preserve that bounded error without inventing QR
        // or accepting complete/correlated answers without response flags.
        let header_unavailable = self.query_flags == 0 && self.id == 0
            && self.qtype == 0 && self.qclass == 0 && self.name.is_empty()
            && self.candidate_count == 0 && self.name_index == 0 && self.name_source == 0
            && self.chain_status == 0 && self.matched_requests == 0
            && self.correlation == 2 && matches!(self.coverage, 2 | 5);
        self.generation != 0 && self.token != 0 && self.owner < 62
            && matches!(self.family, 4 | 6) && self.protocol == 17
            && self.resolver_port == 53 && self.delivery == 0
            && ((self.stage == 1 && self.direction == 3 && self.query_flags & 0x8000 == 0)
                || (self.stage == 2 && self.direction == 1
                    && (self.query_flags & 0x8000 != 0 || header_unavailable)))
            && self.coverage >= 1 && self.coverage <= 5
            && self.caller <= 1 && self.availability & !15 == 0
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
            && self.correlation <= 5 && self.chain_status <= 3 && self.adapter_profile <= 2
            && self.candidate_count <= 33 && self.name_source <= 1 && self.rcode <= 4095
            && self.packet_availability & !15 == 0
            && (self.adapter_profile == 0 || ((self.packet_availability & 1 != 0)
                == (self.packet_uid != u32::MAX)))
            && (self.candidate_count == 0 || self.name_index < self.candidate_count)
            && (self.stage != 1 || (self.name_index == 0 && self.name_source == 0
                && self.chain_status == 0 && self.query_token == 0))
            && (self.stage != 2 || ((self.name_source == 1) == (self.name_index != 0)
                && (self.correlation == 1 || (self.caller == 0 && !self.domain_available))
                && (if self.correlation == 1 {
                    self.query_token != 0 && self.query_policy_generation == self.generation
                        && self.query_incarnation != 0 && self.matched_requests == 1
                        && (self.adapter_profile != 2 || (self.transport_session != 0 && self.underlay_epoch != 0))
                } else {
                    self.query_token == 0 && self.query_policy_generation == 0
                        && self.query_policy_revision == 0 && self.query_policy_hash == 0
                        && self.query_winner == 0 && self.query_incarnation == 0
                })))
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
        let base = format!("{:020}:{:020}:{:04}", self.generation, self.token, self.owner);
        if self.stage == 1 { base } else { format!("{base}:{}:{:02}", self.stage, self.name_index) }
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 480 || data[3] != 16 || !matches!(data[2], 5 | 6)
            || data[6..8] != [0, 0] {
            return None;
        }
        let u16_at = |n| u16::from_le_bytes(data[n..n + 2].try_into().unwrap());
        let u32_at = |n| u32::from_le_bytes(data[n..n + 4].try_into().unwrap());
        let u64_at = |n| u64::from_le_bytes(data[n..n + 8].try_into().unwrap());
        let extended = data[2] == 6;
        if u16_at(0) != if extended { 576 } else { 480 }
            || (extended && (data.len() < 576 || data[571] != 0))
            || (!extended && data[126..128] != [0, 0])
            || u16_at(112) > 255 || data[123] > 1 { return None; }
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
            query_token: if extended { u64_at(480) } else { 0 },
            query_policy_generation: if extended { u64_at(488) } else { 0 },
            query_policy_revision: if extended { u64_at(496) } else { 0 },
            query_policy_hash: if extended { u64_at(504) } else { 0 },
            query_winner: if extended { u64_at(512) } else { 0 },
            network_revision: if extended { u64_at(520) } else { 0 },
            transport_session: if extended { u64_at(528) } else { 0 },
            underlay_epoch: if extended { u64_at(536) } else { 0 },
            query_incarnation: if extended { u64_at(544) } else { 0 },
            matched_requests: if extended { u16_at(552) } else { 0 },
            retransmits: if extended { u16_at(554) } else { 0 },
            candidate_count: if extended { data[556] } else { 0 },
            name_index: if extended { data[126] } else { 0 },
            name_source: if extended { data[557] } else { 0 },
            chain_status: if extended { data[127] } else { 0 },
            correlation: if extended { data[558] } else { 0 },
            domain_lists: if extended { u64_at(560) } else { 0 },
            rcode: if extended { u16_at(568) } else { 0 },
            adapter_profile: if extended { data[570] } else { 0 },
            packet_uid: if extended { u32_at(572) } else { u32_at(80) },
            packet_availability: if extended { data[559] } else { data[117] },
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

    #[test]
    fn decodes_reply_names_with_separate_query_and_response_identities() {
        let mut data = [0; 576];
        data[..480].copy_from_slice(&wire_record());
        data[..2].copy_from_slice(&576u16.to_le_bytes());
        data[2] = 6;
        data[102..104].copy_from_slice(&0x8180u16.to_le_bytes());
        data[116] = 1;
        data[124] = 2;
        data[126] = 1; // Actual connected alias, second name of this answer.
        data[480..488].copy_from_slice(&17u64.to_le_bytes());
        data[488..496].copy_from_slice(&77u64.to_le_bytes());
        data[496..504].copy_from_slice(&3u64.to_le_bytes());
        data[504..512].copy_from_slice(&456u64.to_le_bytes());
        data[520..528].copy_from_slice(&5u64.to_le_bytes());
        data[544..552].copy_from_slice(&8u64.to_le_bytes());
        data[552..554].copy_from_slice(&1u16.to_le_bytes());
        data[556] = 2; data[557] = 1; data[558] = 1;
        let record = DnsRecord::decode(&data).expect("reply on normal owner channel");
        assert_eq!(record.stage, 2);
        assert_eq!(record.query_token, 17);
        assert_eq!(record.query_policy_revision, 3);
        assert_eq!(record.policy_revision, 9);
        assert_eq!(record.name_index, 1);
        assert_eq!(record.name_source, 1);
        assert_eq!(record.correlation, 1);
        assert_eq!(record.delivery, 0);
        let mut query = DnsRecord::decode(&wire_record()).unwrap();
        query.token = record.token;
        assert_ne!(query.key(), record.key());
        let mut first = record.clone(); first.name_index = 0; first.name_source = 0;
        assert_ne!(first.key(), record.key());
    }

    #[test]
    fn missing_response_header_is_only_a_qualified_coverage_gap() {
        let mut data = [0; 576];
        data[..480].copy_from_slice(&wire_record());
        data[..2].copy_from_slice(&576u16.to_le_bytes());
        data[2] = 6;
        data[100..108].fill(0);
        data[112..114].fill(0);
        data[116] = 1;
        data[117] = 1; data[118] = 0; data[119] = 2; data[123] = 0; data[124] = 2;
        data[224..480].fill(0);
        data[558] = 2;
        assert!(DnsRecord::decode(&data).is_some());
        data[119] = 5;
        assert!(DnsRecord::decode(&data).is_some());
        // A missing header cannot claim a complete answer, Question or match.
        for (offset, value) in [(119, 1), (104, 1), (556, 1), (558, 1)] {
            let mut invalid = data;
            invalid[offset] = value;
            assert!(DnsRecord::decode(&invalid).is_none(), "offset {offset}");
        }
    }
}
