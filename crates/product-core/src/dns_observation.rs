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
    #[serde(default)] pub message_sequence: u64,
    #[serde(default)] pub tcp_sequence: u32,
    #[serde(default)] pub tcp_continuation: u8,
    #[serde(default)] pub packet_direction: u8,
    #[serde(default)] pub route_revision: u64,
    #[serde(default)] pub request_attempt: u64,
    #[serde(default)] pub upstream_session: u64,
    #[serde(default, skip_serializing_if = "zero_u64")] pub upstream_attempt: u64,
    #[serde(default, skip_serializing_if = "zero_u32")] pub resolution_route: u32,
    #[serde(default, skip_serializing_if = "zero_u32")] pub resolver_id: u32,
    #[serde(default)] pub upstream_address: [u8; 16],
    #[serde(default)] pub upstream_port: u16,
    #[serde(default)] pub upstream_family: u8,
    #[serde(default)] pub upstream_transport: u8,
    #[serde(default)] pub proxy_result: u8,
    #[serde(default)] pub reply_rcode: u16,
    #[serde(default)] pub client_udp_capacity: u16,
    #[serde(default)] pub reply_capacity: u16,
    #[serde(default)] pub output_bytes: u32,
    #[serde(default)] pub proxy_flags: u32,
    #[serde(default)] pub return_token: u64,
    #[serde(default)] pub return_policy_generation: u64,
    #[serde(default)] pub return_policy_revision: u64,
    #[serde(default)] pub return_policy_hash: u64,
    #[serde(default)] pub return_winner: u64,
    #[serde(default)] pub return_declared_action: u8,
    #[serde(default)] pub return_actual_action: u8,
    #[serde(default)] pub return_mode: u8,
    #[serde(default)] pub return_provenance: u8,
    #[serde(default)] pub return_packet_uid: u32,
    #[serde(default, skip_serializing_if = "zero_u8")] pub transport_metadata: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")] pub service_identity: String,
    #[serde(default, skip_serializing_if = "zero_address")] pub connection_address: [u8;16],
    #[serde(default, skip_serializing_if = "zero_address")] pub bootstrap_address: [u8;16],
    #[serde(default, skip_serializing_if = "zero_u16")] pub connection_port: u16,
    #[serde(default, skip_serializing_if = "zero_u16")] pub bootstrap_port: u16,
    #[serde(default, skip_serializing_if = "zero_u32")] pub bootstrap_ifindex: u32,
    #[serde(default, skip_serializing_if = "zero_i32")] pub tls_error: i32,
    #[serde(default, skip_serializing_if = "zero_u8")] pub connection_family: u8,
    #[serde(default, skip_serializing_if = "zero_u8")] pub bootstrap_family: u8,
    #[serde(default, skip_serializing_if = "zero_u8")] pub tls_state: u8,
    #[serde(default, skip_serializing_if = "zero_u8")] pub bootstrap_state: u8,
    #[serde(default, skip_serializing_if = "zero_u8")] pub authorization_state: u8,
    #[serde(default, skip_serializing_if = "zero_u8")] pub trust_source: u8,
    /// DoH only (observation version 11): ALPN outcome, HTTP failure class, status and Age.
    #[serde(default, skip_serializing_if = "zero_u8")] pub alpn_state: u8,
    #[serde(default, skip_serializing_if = "zero_u8")] pub http_error: u8,
    #[serde(default, skip_serializing_if = "zero_u16")] pub http_status: u16,
    #[serde(default, skip_serializing_if = "zero_u32")] pub http_age: u32,
}

fn zero_u8(value: &u8) -> bool { *value == 0 }
fn zero_u16(value: &u16) -> bool { *value == 0 }
fn zero_i32(value: &i32) -> bool { *value == 0 }
fn zero_address(value: &[u8;16]) -> bool { *value == [0;16] }
fn zero_u64(value: &u64) -> bool { *value == 0 }
fn zero_u32(value: &u32) -> bool { *value == 0 }

impl DnsRecord {
    pub fn valid(&self) -> bool {
        if !self.valid_transport_metadata() { return false; }
        if self.proxy_flags & 1 != 0 { return self.valid_proxy(); }
        if self.route_revision != 0 || self.request_attempt != 0 || self.upstream_session != 0
            || self.upstream_attempt != 0 || self.resolution_route != 0 || self.resolver_id != 0
            || self.upstream_address != [0;16] || self.upstream_port != 0 || self.upstream_family != 0
            || self.upstream_transport != 0 || self.proxy_result != 0 || self.reply_rcode != 0
            || self.client_udp_capacity != 0 || self.reply_capacity != 0 || self.output_bytes != 0
            || self.proxy_flags != 0 || self.return_token != 0 || self.return_policy_generation != 0
            || self.return_policy_revision != 0 || self.return_policy_hash != 0 || self.return_winner != 0
            || self.return_declared_action != 0 || self.return_actual_action != 0 || self.return_mode != 0
            || self.return_provenance != 0 || self.return_packet_uid != 0 { return false; }
        // The INPUT port53 control point is known even when the DNS header
        // could not be read. Preserve that bounded error without inventing QR
        // or accepting complete/correlated answers without response flags.
        let header_unavailable = self.query_flags == 0 && self.id == 0
            && self.qtype == 0 && self.qclass == 0 && self.name.is_empty()
            && self.candidate_count == 0 && self.name_index == 0 && self.name_source == 0
            && self.chain_status == 0 && self.matched_requests == 0
            && self.correlation == 2 && (matches!(self.coverage, 2 | 5)
                || (self.protocol == 6 && matches!(self.coverage, 4 | 6..=11)));
        self.generation != 0 && self.token != 0 && self.owner < 62
            && matches!(self.family, 4 | 6) && matches!(self.protocol, 6 | 17)
            && self.resolver_port == 53 && self.delivery == 0
            && ((self.stage == 1 && self.direction == 3 && self.query_flags & 0x8000 == 0)
                || (self.stage == 2 && self.direction == 1
                    && (self.query_flags & 0x8000 != 0 || header_unavailable)))
            && self.coverage >= 1 && self.coverage <= if self.protocol == 6 { 11 } else { 5 }
            && (if self.protocol == 6 {
                matches!(self.adapter_profile, 1 | 2) && matches!(self.packet_direction, 1 | 3)
                    && self.tcp_continuation <= 1
                    && (self.tcp_continuation == 1 || self.packet_direction == self.direction)
                    && (self.coverage != 1 || self.message_sequence != 0)
                    && (self.tcp_continuation == 0 || self.coverage == 1)
                    && (self.coverage < 6 || (self.name.is_empty() && self.qtype == 0
                        && self.qclass == 0 && self.query_flags == 0 && self.id == 0
                        && self.candidate_count == 0 && !self.domain_available))
            } else {
                self.message_sequence == 0 && self.tcp_sequence == 0
                    && self.tcp_continuation == 0 && self.packet_direction == 0
            })
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

    fn valid_transport_metadata(&self) -> bool {
        let no_connection = self.connection_family == 0 && self.connection_port == 0
            && self.connection_address == [0;16];
        let no_bootstrap = self.bootstrap_family == 0 && self.bootstrap_port == 0
            && self.bootstrap_address == [0;16] && self.bootstrap_ifindex == 0;
        if self.transport_metadata == 0 {
            return self.service_identity.is_empty() && no_connection && no_bootstrap
                && self.tls_state == 0 && self.bootstrap_state == 0
                && self.authorization_state == 0 && self.trust_source == 0 && self.tls_error == 0
                && self.doh_fields_zero();
        }
        let address = |family, port, value: &[u8;16]| matches!(family,4|6) && port != 0
            && *value != [0;16] && value[0] != 255
            && (family != 4 || (value[0] != 0 && value[0] < 224 && value[4..] == [0;12]))
            && (family != 6 || value[0] != 0xff);
        if self.transport_metadata != 1 || self.proxy_flags & 1 == 0 || !matches!(self.upstream_transport,3|4)
            || self.service_identity.is_empty() || self.service_identity.len() > 255
            || !self.service_identity.is_ascii() || self.service_identity.as_bytes().contains(&0)
            || self.service_identity.bytes().any(|c| !(c.is_ascii_alphanumeric() || matches!(c,b'.'|b'-'|b'_'|b':')))
            || self.tls_state > 4 || self.bootstrap_state > 3 || self.authorization_state > 3 || self.trust_source > 2
            || (!no_connection && (!address(self.connection_family,self.connection_port,&self.connection_address)
                || self.connection_port != self.upstream_port))
            || (!no_bootstrap && (!address(self.bootstrap_family,self.bootstrap_port,&self.bootstrap_address)
                || self.bootstrap_port != 53 || self.bootstrap_ifindex == 0))
            || (self.bootstrap_state == 0 && !no_bootstrap)
            || (matches!(self.bootstrap_state,1|2) && no_bootstrap)
            || (self.tls_state == 2 && (no_connection || self.authorization_state != 2 || self.trust_source == 0 || self.tls_error != 0)) {
            return false;
        }
        let doh = self.upstream_transport == 4;
        if !doh && !self.doh_fields_zero() { return false; }
        if doh && (self.alpn_state > 3 || self.http_error > 12 || self.http_status > 599) { return false; }
        if self.tls_state == 4 {
            // Retained data creates no connection, authentication or HTTP claim.
            return self.proxy_flags & 16 != 0 && no_connection && no_bootstrap
                && self.bootstrap_state == 0 && self.authorization_state == 0 && self.trust_source == 0 && self.tls_error == 0
                && self.doh_fields_zero();
        }
        if self.proxy_flags & 20 != 0 && matches!(self.stage,2|4) {
            // A delivered DoH answer needs a complete 200 response on http/1.1 (or no ALPN).
            return self.tls_state == 2
                && (!doh || (self.http_status == 200 && self.http_error == 0 && matches!(self.alpn_state,1|2)));
        }
        true
    }

    fn doh_fields_zero(&self) -> bool {
        self.alpn_state == 0 && self.http_error == 0 && self.http_status == 0 && self.http_age == 0
    }

    fn valid_proxy(&self) -> bool {
        let admission_resource = self.proxy_flags & 8 != 0;
        // A cache answer can pass complete correlation and then fail its
        // output allocation. Its local SERVFAIL still retains the actual
        // cached response provenance through error and delivery records.
        let cached_output_resource = matches!(self.stage, 3 | 4)
            && self.proxy_result == 6 && self.reply_rcode == 2
            && self.coverage == 1 && self.correlation == 1
            && self.matched_requests == 1 && self.candidate_count != 0
            && self.chain_status == 0 && self.query_flags & 0x8000 != 0;
        // A selected HEV TCP session remains local after replacement is OFF.
        // Its later messages can have no selected upstream and still produce
        // real query/error/delivery observations. Keep that absence explicit.
        let local_without_upstream = self.adapter_profile == 2 && self.protocol == 6
            && self.proxy_flags == 1 && self.upstream_transport == 1
            && self.upstream_family == 0 && self.upstream_port == 0
            && self.upstream_address == [0; 16] && self.upstream_session == 0
            && self.candidate_count == 0 && self.matched_requests == 0
            && self.name_index == 0 && self.name_source == 0
            && self.chain_status == 0 && self.correlation == 0 && self.rcode == 0
            && (self.stage != 4 || self.return_provenance == 3)
            && matches!((self.stage, self.proxy_result, self.reply_rcode),
                (1, 0 | 10, 0) | (1 | 4, 2, 5) | (1 | 4, 4, 1)
                | (1 | 4, 5, 4) | (3 | 4, 6 | 9, 2));
        let common = self.generation != 0 && self.token != 0 && self.owner < 62 && matches!(self.adapter_profile, 1 | 2)
            && matches!(self.family,4|6) && matches!(self.protocol,6|17) && self.resolver_port == 53
            && self.route_revision != 0
            && self.proxy_result <= 15 && (self.proxy_result < 12 || self.stage == 5)
            && self.resolver_id <= 8 && (self.resolution_route < 8 || self.resolution_route == u32::MAX)
            && (self.resolution_route != u32::MAX || self.resolver_id == 0)
            && self.proxy_flags & !31 == 0 && self.delivery <= 8 && self.reply_rcode <= 4095 && self.rcode <= 4095
            && self.coverage >= 1 && self.coverage <= 5 && self.codec_peak_bytes <= 512*1024
            && self.caller <= 1 && self.availability & !15 == 0 && self.packet_availability & !15 == 0
            && (self.caller == 1) == (self.availability & 9 == 9 && self.uid != u32::MAX)
            && (self.packet_availability & 1 != 0) == (self.packet_uid != u32::MAX)
            && (self.slot == u32::MAX) == (self.incarnation == 0)
            && self.name.len() <= 255 && self.name.is_ascii() && !self.name.as_bytes().contains(&0)
            && self.rule_name.len() <= 63 && !self.rule_name.as_bytes().contains(&0)
            && (self.family != 4 || (self.source_address[4..] == [0;12] && self.resolver_address[4..] == [0;12]))
            && (!self.domain_available || (self.caller == 1 && self.coverage == 1 && !self.name.is_empty()))
            && self.correlation <= 5 && self.candidate_count <= 33 && self.chain_status <= 3
            && self.name_source <= 1 && (self.candidate_count == 0 || self.name_index < self.candidate_count)
            && (if self.protocol == 6 { self.message_sequence == self.token && self.transport_session != 0 || admission_resource }
                else { self.message_sequence == 0 })
            && self.tcp_sequence == 0 && self.tcp_continuation == 0
            && (self.delivery != 8 || (self.protocol == 6 && self.stage != 4))
            && matches!(self.stage,1..=5)
            && (if self.stage == 1 { self.direction == 3 && self.query_flags & 0x8000 == 0 && self.query_token == 0 }
                else if self.stage == 2 { self.direction == 1 && self.query_flags & 0x8000 != 0 && self.query_token == self.token }
                else if self.stage == 3 { self.direction == 3 && self.query_token == self.token }
                else if self.stage == 4 { self.direction == 1 && self.query_flags & 0x8000 != 0 && self.query_token == self.token && self.return_token != 0 }
                else { self.direction == 3 && self.query_flags & 0x8000 == 0 && self.query_token == self.token
                    && (12..=15).contains(&self.proxy_result) && self.upstream_attempt != 0
                    && self.coverage == 1 && self.delivery == 0 && self.reply_rcode == 0 && self.rcode == 0
                    && self.proxy_flags == 1 && self.upstream_session == 0 && self.output_bytes == 0
                    && self.candidate_count == 0 && self.matched_requests == 0 && self.correlation == 0
                    && self.return_token == 0 && self.policy_generation == 0 && self.policy_revision == 0
                    && self.policy_hash == 0 && self.winner == 0 && self.actual_action == 0 && self.declared_action == 0
                    && self.mode == 0 && self.return_policy_generation == 0 && self.return_policy_revision == 0
                    && self.return_policy_hash == 0 && self.return_winner == 0 && self.return_declared_action == 0
                    && self.return_actual_action == 0 && self.return_mode == 0 && self.return_provenance == 0
                    && self.return_packet_uid == 0 })
            && self.declared_action <= 2 && self.actual_action <= 2 && self.mode <= 1
            && (self.winner == 0 || (self.policy_generation == self.generation && self.policy_revision != 0
                && self.actual_action == if self.mode == 1 {1} else {self.declared_action}))
            && (self.proxy_flags & 16 == 0 || (self.proxy_flags & 12 == 0 && self.upstream_session == 0 && self.upstream_attempt == 0
                && ((matches!(self.stage, 2 | 4) && matches!(self.proxy_result, 2 | 11))
                    || cached_output_resource)))
            && (self.proxy_result != 11 || self.proxy_flags & 16 != 0)
            && self.return_declared_action <= 2 && self.return_actual_action <= 2 && self.return_mode <= 1
            && (self.return_winner == 0 || (self.return_policy_generation == self.generation && self.return_policy_revision != 0))
            && (self.return_provenance == 0 || self.return_provenance == if self.adapter_profile == 1 {5} else {3});
        common && if admission_resource {
            self.proxy_flags == 9 && self.stage == 3 && self.proxy_result == 6
                && self.request_attempt == 0 && self.upstream_session == 0
                && self.upstream_address == [0;16] && self.upstream_port == 0
                && self.upstream_family == 0 && self.upstream_transport == 0
                && matches!(self.delivery,4|6|7)
                && matches!(self.coverage,4|5) && self.reply_rcode == 0 && self.rcode == 0
                && self.client_udp_capacity == 0 && self.reply_capacity == 0 && self.output_bytes == 0
                && self.winner == 0 && self.policy_generation == 0 && self.policy_revision == 0
                && self.policy_hash == 0 && self.return_token == 0 && self.return_winner == 0
        } else {
            self.request_attempt != 0 && matches!(self.upstream_transport,1|2|3|4)
                && ((matches!(self.upstream_family,4|6) && self.upstream_port != 0
                    && (self.upstream_family != 4 || self.upstream_address[4..] == [0;12]))
                    || (self.transport_metadata == 1 && matches!(self.upstream_transport,3|4)
                        && self.upstream_family == 0 && self.upstream_address == [0;16] && self.upstream_port != 0)
                    || local_without_upstream)
                && (self.delivery <= 5 || self.delivery == 8) && (self.client_udp_capacity == 0 || self.client_udp_capacity >= 512)
                && (if self.protocol == 6 { self.reply_capacity == 65535 }
                    else { (512..=1232).contains(&self.reply_capacity) })
                && self.output_bytes <= u32::from(self.reply_capacity)
        }
    }

    pub(crate) fn key(&self) -> String {
        let base = format!("{:020}:{:020}:{:04}", self.generation, self.token, self.owner);
        if self.proxy_flags & 1 != 0 {
            // Tokens and attempt numbers belong to their actual Adapter,
            // transport session and resolution view. In particular HEV TCP
            // tokens need not be globally disjoint from TUN/NFQUEUE tokens.
            // Hex scope components keep the complete key below the existing
            // 192-byte store limit, including every u64 at its maximum value.
            let key = format!("{base}:proxy2:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{}:{:x}:{:x}",
                self.adapter_profile, self.protocol, self.family, self.incarnation,
                self.transport_session, self.network_revision, self.route_revision,
                self.request_attempt, self.stage, self.name_index, self.return_token);
            if self.stage == 5 { format!("{key}:a:{:x}:{:x}",self.upstream_attempt,self.proxy_result) } else { key }
        } else if self.protocol == 6 {
            format!("{base}:tcp:{:020}:{}:{:02}:{}", self.message_sequence,
                self.stage, self.name_index, self.tcp_continuation)
        } else if self.stage == 1 { base }
        else { format!("{base}:{}:{:02}", self.stage, self.name_index) }
    }

    pub(crate) fn legacy_proxy_key(&self) -> Option<String> {
        (self.proxy_flags & 1 != 0 && self.stage != 5).then(|| format!(
            "{:020}:{:020}:{:04}:proxy:{:020}:{}:{:02}:{:020}",
            self.generation, self.token, self.owner, self.request_attempt,
            self.stage, self.name_index, self.return_token))
    }

    pub(crate) fn storage_key_matches(&self, key: &str) -> bool {
        self.key() == key || self.legacy_proxy_key().is_some_and(|legacy| legacy == key)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 480 || data[3] != 16 || !matches!(data[2], 5 | 6 | 7 | 8 | 9 | 10 | 11)
            || data[6..8] != [0, 0] {
            return None;
        }
        let u16_at = |n| u16::from_le_bytes(data[n..n + 2].try_into().unwrap());
        let u32_at = |n| u32::from_le_bytes(data[n..n + 4].try_into().unwrap());
        let u64_at = |n| u64::from_le_bytes(data[n..n + 8].try_into().unwrap());
        let extended = data[2] >= 6;
        let tcp_extended = data[2] >= 7;
        let proxy_extended = data[2] >= 8;
        let routing_extended = data[2] >= 9;
        let tls_extended = data[2] >= 10;
        let doh_extended = data[2] >= 11;
        let expected = if tls_extended {1032} else if routing_extended {720} else if proxy_extended {704} else if tcp_extended { 592 } else if extended { 576 } else { 480 };
        if u16_at(0) != expected || data.len() < expected as usize
            || (tcp_extended && data[590..592] != [0, 0])
            || (extended && data[571] != 0 && !doh_extended)
            || (proxy_extended && ((data[637] != 0 && !doh_extended) || data[652..656] != [0;4]))
            || (!extended && data[126..128] != [0, 0])
            || u16_at(112) > 255 || data[123] > 1 { return None; }
        let name_length = u16_at(112) as usize;
        if data[224 + name_length..480].iter().any(|byte| *byte != 0) { return None; }
        let rule_name = &data[160..224];
        let rule_length = rule_name.iter().position(|byte| *byte == 0)?;
        if rule_name[rule_length..].iter().any(|byte| *byte != 0) { return None; }
        let service_identity = if tls_extended {
            let text = &data[720..976];
            let length = text.iter().position(|byte| *byte == 0)?;
            if text[length..].iter().any(|byte| *byte != 0) || (!doh_extended && data[1026..1032] != [0;6]) { return None; }
            std::str::from_utf8(&text[..length]).ok()?.to_owned()
        } else { String::new() };
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
            message_sequence: if tcp_extended { u64_at(576) } else { 0 },
            tcp_sequence: if tcp_extended { u32_at(584) } else { 0 },
            tcp_continuation: if tcp_extended { data[588] } else { 0 },
            packet_direction: if tcp_extended { data[589] } else { 0 },
            route_revision: if proxy_extended {u64_at(592)} else {0},
            request_attempt: if proxy_extended {u64_at(600)} else {0},
            upstream_session: if proxy_extended {u64_at(608)} else {0},
            upstream_attempt: if routing_extended {u64_at(704)} else {0},
            resolution_route: if routing_extended {u32_at(712)} else {0},
            resolver_id: if routing_extended {u32_at(716)} else {0},
            upstream_address: if proxy_extended {data[616..632].try_into().ok()?} else {[0;16]},
            upstream_port: if proxy_extended {u16_at(632)} else {0},
            upstream_family: if proxy_extended {data[634]} else {0},
            upstream_transport: if proxy_extended {data[635]} else {0},
            proxy_result: if proxy_extended {data[636]} else {0},
            reply_rcode: if proxy_extended {u16_at(638)} else {0},
            client_udp_capacity: if proxy_extended {u16_at(640)} else {0},
            reply_capacity: if proxy_extended {u16_at(642)} else {0},
            output_bytes: if proxy_extended {u32_at(644)} else {0},
            proxy_flags: if proxy_extended {u32_at(648)} else {0},
            return_token: if proxy_extended {u64_at(656)} else {0},
            return_policy_generation: if proxy_extended {u64_at(664)} else {0},
            return_policy_revision: if proxy_extended {u64_at(672)} else {0},
            return_policy_hash: if proxy_extended {u64_at(680)} else {0},
            return_winner: if proxy_extended {u64_at(688)} else {0},
            return_declared_action: if proxy_extended {data[696]} else {0},
            return_actual_action: if proxy_extended {data[697]} else {0},
            return_mode: if proxy_extended {data[698]} else {0},
            return_provenance: if proxy_extended {data[699]} else {0},
            return_packet_uid: if proxy_extended {u32_at(700)} else {0},
            transport_metadata: u8::from(tls_extended), service_identity,
            connection_address: if tls_extended {data[976..992].try_into().ok()?} else {[0;16]},
            bootstrap_address: if tls_extended {data[992..1008].try_into().ok()?} else {[0;16]},
            connection_port: if tls_extended {u16_at(1008)} else {0},
            bootstrap_port: if tls_extended {u16_at(1010)} else {0},
            bootstrap_ifindex: if tls_extended {u32_at(1012)} else {0},
            tls_error: if tls_extended {i32::from_le_bytes(data[1016..1020].try_into().ok()?)} else {0},
            connection_family: if tls_extended {data[1020]} else {0},
            bootstrap_family: if tls_extended {data[1021]} else {0},
            tls_state: if tls_extended {data[1022]} else {0},
            bootstrap_state: if tls_extended {data[1023]} else {0},
            authorization_state: if tls_extended {data[1024]} else {0},
            trust_source: if tls_extended {data[1025]} else {0},
            alpn_state: if doh_extended {data[571]} else {0},
            http_error: if doh_extended {data[637]} else {0},
            http_status: if doh_extended {u16_at(1026)} else {0},
            http_age: if doh_extended {u32_at(1028)} else {0},
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
    #[test]
    fn vpn_tcp_uses_the_normal_frame_contract_without_weakening_return_binding() {
        let mut data = [0; 592];
        data[..480].copy_from_slice(&wire_record());
        data[..2].copy_from_slice(&592u16.to_le_bytes());
        data[2] = 7; data[115] = 6; data[570] = 2;
        data[559] = 9; data[572..576].copy_from_slice(&10123u32.to_le_bytes());
        data[576..584].copy_from_slice(&1u64.to_le_bytes()); data[589] = 3;
        let query = DnsRecord::decode(&data).expect("VPN TCP query belongs to normal history");
        assert_eq!(query.adapter_profile, 2);
        data[24..32].copy_from_slice(&8u64.to_le_bytes());
        data[96..100].copy_from_slice(&3u32.to_le_bytes());
        data[102..104].copy_from_slice(&0x8180u16.to_le_bytes());
        data[116] = 1; data[124] = 2; data[589] = 1;
        data[480..488].copy_from_slice(&310u64.to_le_bytes());
        data[488..496].copy_from_slice(&77u64.to_le_bytes());
        data[544..552].copy_from_slice(&8u64.to_le_bytes());
        data[552..554].copy_from_slice(&1u16.to_le_bytes());
        data[558] = 1;
        assert!(DnsRecord::decode(&data).is_none(), "correlated VPN returns require actual binding");
        data[528..536].copy_from_slice(&71u64.to_le_bytes());
        data[536..544].copy_from_slice(&9u64.to_le_bytes());
        let reply = DnsRecord::decode(&data).expect("stamped VPN TCP response");
        assert_eq!((reply.transport_session, reply.underlay_epoch, reply.query_incarnation), (71, 9, 8));
        for (offset, value) in [(570, 0), (570, 3), (589, 0), (558, 6)] {
            let mut invalid = data; invalid[offset] = value;
            assert!(DnsRecord::decode(&invalid).is_none(), "guard offset {offset}");
        }
    }
    #[test]
    fn tcp_frames_keep_distinct_normal_history_identities() {
        let mut data = [0; 592];
        data[..480].copy_from_slice(&wire_record());
        data[..2].copy_from_slice(&592u16.to_le_bytes());
        data[2] = 7;
        data[115] = 6;
        data[576..584].copy_from_slice(&1u64.to_le_bytes());
        data[584..588].copy_from_slice(&101u32.to_le_bytes());
        data[589] = 3;
        data[570] = 1; data[559] = 9;
        data[572..576].copy_from_slice(&10123u32.to_le_bytes());
        let first = DnsRecord::decode(&data).expect("Root TCP query through normal ABI");
        data[576..584].copy_from_slice(&2u64.to_le_bytes());
        data[584..588].copy_from_slice(&132u32.to_le_bytes());
        let second = DnsRecord::decode(&data).expect("second query coalesced in the same packet");
        assert_ne!(first.key(), second.key());
        assert_eq!(first.protocol, 6);
        // Existing UDP query keys remain unchanged for stored history.
        let legacy = DnsRecord::decode(&wire_record()).unwrap();
        assert_eq!(legacy.key(), "00000000000000000077:00000000000000000310:0000");
    }

    #[test]
    fn admission_resource_is_not_a_proxy_attempt_or_policy_result() {
        let mut record = DnsRecord {
            generation: 77, token: 9, owner: 0, uid: u32::MAX,
            network: u32::MAX, slot: u32::MAX, family: 4, protocol: 17,
            direction: 3, coverage: 5, stage: 3, delivery: 6,
            source_port: 40000, resolver_port: 53, query_token: 9,
            route_revision: 5, proxy_result: 6, adapter_profile: 1,
            packet_uid: u32::MAX, proxy_flags: 9,
            ..DnsRecord::default()
        };
        assert!(record.valid());
        record.delivery = 7;
        assert!(record.valid());
        record.delivery = 4;
        assert!(record.valid());
        record.delivery = 5;
        assert!(!record.valid());
        record.delivery = 6;
        record.request_attempt = 1;
        assert!(!record.valid());
        record.request_attempt = 0;
        record.reply_capacity = 1232;
        assert!(!record.valid());
    }

}
