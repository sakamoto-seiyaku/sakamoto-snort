//! Online source configuration is owned by VPP. These are packet-free adapters.
use crate::{ffi, ErrorCode, ProductCore, ProductError, Status};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConfigRule {
    pub present: u32,
    pub uid: u32,
    pub protocol: u32,
    pub direction: u32,
    pub action: u32,
    pub source_port: u32,
    pub destination_port: u32,
    pub reserved: u32,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
}

pub const MAX_CONFIG_RULES: usize = 256;
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectRule {
    pub version: u64,
    pub base_version: u64,
    pub uid: u32,
    pub network_context: u32,
    pub ifindex: u32,
    pub priority: u32,
    pub order: u32,
    pub family: u32,
    pub protocol: u32,
    pub direction: u32,
    pub action: u32,
    pub source_prefix: u32,
    pub destination_prefix: u32,
    pub source_port_first: u32,
    pub source_port_last: u32,
    pub destination_port_first: u32,
    pub destination_port_last: u32,
    pub reserved: u32,
    pub source_address: [u8; 16],
    pub destination_address: [u8; 16],
    pub expression_length: u32,
    pub expression: [u8; 64],
}
impl Default for DirectRule {
    fn default() -> Self {
        // All fields are integer scalars/arrays; zero is a valid empty request.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupEdge {
    pub group: u32,
    pub kind: u32,
    pub target: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleBinding {
    pub id: u32,
    pub uid: u32,
    pub kind: u32,
    pub target: u32,
    pub mode: u32,
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleGraph {
    pub group_count: u32,
    pub edge_count: u32,
    pub binding_count: u32,
    pub groups: [u32; 64],
    pub edges: [GroupEdge; 512],
    pub bindings: [RuleBinding; 128],
}
impl Default for RuleGraph {
    fn default() -> Self {
        Self {
            group_count: 0,
            edge_count: 0,
            binding_count: 0,
            groups: [0; 64],
            edges: [GroupEdge::default(); 512],
            bindings: [RuleBinding::default(); 128],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DomainEntry {
    pub list: u32,
    pub mode: u32,
    pub length: u32,
    pub name: [u8; 256],
}
impl Default for DomainEntry {
    fn default() -> Self {
        Self {
            list: 0,
            mode: 0,
            length: 0,
            name: [0; 256],
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Domains {
    pub list_count: u32,
    pub entry_count: u32,
    pub entries: [DomainEntry; 256],
}
impl Default for Domains {
    fn default() -> Self {
        Self {
            list_count: 0,
            entry_count: 0,
            entries: [DomainEntry::default(); 256],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleConfigRequest {
    pub schema: u32,
    pub operation: u32,
    pub expected_saved_revision: u64,
    pub rule: ConfigRule,
    pub count: u32,
    pub reserved_full: u32,
    pub rules: [DirectRule; MAX_CONFIG_RULES],
    pub graph: RuleGraph,
    pub domains: Domains,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct RuleConfigStatus {
    pub generation: u64,
    pub saved_revision: u64,
    pub active_revision: u64,
    pub saved_rule_version: u64,
    pub active_rule_version: u64,
    pub result: u32,
    pub save_error: u32,
    pub compile_error: u32,
    pub reserved: u32,
    pub rule: ConfigRule,
    pub count: u32,
    pub active_count: u32,
    pub error_index: u32,
    pub compiler_status: u32,
    pub rules: [DirectRule; MAX_CONFIG_RULES],
    pub active_versions: [u64; MAX_CONFIG_RULES],
    pub graph: RuleGraph,
    pub domains: Domains,
}

impl DirectRule {
    /// A transient request text, not a Rust-owned saved configuration.
    pub fn parse(line: &str) -> Result<Self, &'static str> {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 16 && fields.len() != 17 {
            return Err("expected 16 fields and optional expression hex");
        }
        let n = |i: usize| {
            fields[i]
                .parse::<u32>()
                .map_err(|_| "invalid unsigned field")
        };
        let cidr = |text: &str| -> Result<(u32, u32, [u8; 16]), &'static str> {
            if text == "*" {
                return Ok((0, 0, [0; 16]));
            }
            let (ip, prefix) = text.split_once('/').ok_or("CIDR required")?;
            let ip = ip
                .parse::<std::net::IpAddr>()
                .map_err(|_| "invalid numeric address")?;
            let prefix = prefix.parse::<u32>().map_err(|_| "invalid prefix")?;
            let mut bytes = [0; 16];
            let family = match ip {
                std::net::IpAddr::V4(a) => {
                    bytes[..4].copy_from_slice(&a.octets());
                    4
                }
                std::net::IpAddr::V6(a) => {
                    bytes = a.octets();
                    6
                }
            };
            Ok((family, prefix, bytes))
        };
        let (family, source_prefix, source_address) = cidr(fields[10])?;
        let (destination_family, destination_prefix, destination_address) = cidr(fields[11])?;
        if family != destination_family {
            return Err("CIDR families differ");
        }
        let mut expression = [0; 64];
        let mut expression_length = 0;
        if fields.len() == 17 {
            let hex = fields[16];
            if hex.is_empty() || hex.len() > 128 || hex.len() % 2 != 0 || !hex.is_ascii() {
                return Err("expression must be 1..64 hex bytes");
            }
            for (i, byte) in expression.iter_mut().take(hex.len() / 2).enumerate() {
                *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                    .map_err(|_| "invalid expression hex")?;
            }
            expression_length = (hex.len() / 2) as u32;
        }
        Ok(Self {
            expression,
            expression_length,
            version: fields[0].parse().map_err(|_| "invalid version")?,
            base_version: fields[1].parse().map_err(|_| "invalid base version")?,
            uid: n(2)?,
            network_context: n(3)?,
            ifindex: n(4)?,
            priority: n(5)?,
            order: n(6)?,
            protocol: n(7)?,
            direction: n(8)?,
            action: n(9)?,
            family,
            source_prefix,
            destination_prefix,
            source_address,
            destination_address,
            source_port_first: n(12)?,
            source_port_last: n(13)?,
            destination_port_first: n(14)?,
            destination_port_last: n(15)?,
            reserved: 0,
        })
    }
}

impl RuleConfigRequest {
    /// Append one transient diagnostic input line; VPP validates graph semantics.
    pub fn push_line(&mut self, line: &str) -> Result<(), &'static str> {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.is_empty() {
            return Ok(());
        }
        let n = |i: usize| {
            f[i].parse::<u32>()
                .map_err(|_| "invalid unsigned graph field")
        };
        match f[0] {
            "lists" => {
                if f.len() != 2 || self.domains.list_count != 0 {
                    return Err("invalid list declaration");
                }
                let count = n(1)?;
                if count > 64 {
                    return Err("too many domain lists");
                }
                self.domains.list_count = count;
            }
            "domain" => {
                if f.len() != 4 || self.domains.entry_count >= 256 {
                    return Err("invalid domain fields/count");
                }
                let list = n(1)?;
                let mode = match f[2] {
                    "exact" => 0,
                    "descendants" => 1,
                    _ => return Err("invalid domain mode"),
                };
                let name = f[3].as_bytes();
                if list >= self.domains.list_count
                    || name.is_empty()
                    || name.len() > 254
                    || !name.is_ascii()
                {
                    return Err("invalid domain list/name; use ASCII A-labels");
                }
                let mut entry = DomainEntry {
                    list,
                    mode,
                    length: name.len() as u32,
                    ..Default::default()
                };
                entry.name[..name.len()].copy_from_slice(name);
                self.domains.entries[self.domains.entry_count as usize] = entry;
                self.domains.entry_count += 1;
            }
            "group" => {
                if f.len() != 2 || self.graph.group_count == 64 {
                    return Err("invalid group count/fields");
                }
                self.graph.groups[self.graph.group_count as usize] = n(1)?;
                self.graph.group_count += 1;
            }
            "edge" => {
                if f.len() != 4 || self.graph.edge_count == 512 {
                    return Err("invalid edge count/fields");
                }
                self.graph.edges[self.graph.edge_count as usize] = GroupEdge {
                    group: n(1)?,
                    kind: n(2)?,
                    target: n(3)?,
                };
                self.graph.edge_count += 1;
            }
            "bind" => {
                if f.len() != 6 || self.graph.binding_count == 128 {
                    return Err("invalid binding count/fields");
                }
                self.graph.bindings[self.graph.binding_count as usize] = RuleBinding {
                    id: n(1)?,
                    uid: n(2)?,
                    kind: n(3)?,
                    target: n(4)?,
                    mode: n(5)?,
                };
                self.graph.binding_count += 1;
            }
            _ => {
                if self.count as usize == MAX_CONFIG_RULES {
                    return Err("too many source rules");
                }
                self.rules[self.count as usize] = DirectRule::parse(line)?;
                self.count += 1;
            }
        }
        Ok(())
    }
}

impl Default for RuleConfigRequest {
    fn default() -> Self {
        Self {
            schema: 1,
            operation: 0,
            expected_saved_revision: 0,
            rule: ConfigRule::default(),
            count: 0,
            reserved_full: 0,
            rules: [DirectRule::default(); MAX_CONFIG_RULES],
            graph: RuleGraph::default(),
            domains: Domains::default(),
        }
    }
}
impl Default for RuleConfigStatus {
    fn default() -> Self {
        Self {
            generation: 0,
            saved_revision: 0,
            active_revision: 0,
            saved_rule_version: 0,
            active_rule_version: 0,
            result: 0,
            save_error: 0,
            compile_error: 0,
            reserved: 0,
            rule: ConfigRule::default(),
            count: 0,
            active_count: 0,
            error_index: u32::MAX,
            compiler_status: 0,
            rules: [DirectRule::default(); MAX_CONFIG_RULES],
            graph: RuleGraph::default(),
            domains: Domains::default(),
            active_versions: [0; MAX_CONFIG_RULES],
        }
    }
}

impl ProductCore {
    pub fn rule_config(
        &mut self,
        request: &RuleConfigRequest,
    ) -> Result<RuleConfigStatus, ProductError> {
        let session = self.session.ok_or(ProductError::Native {
            code: ErrorCode::Disconnected,
            status: Status::empty(self.generation),
        })?;
        let mut status = RuleConfigStatus::default();
        let code = unsafe {
            ffi::sakamoto_product_session_rule_config(
                session.as_ptr(),
                self.generation,
                request,
                &mut status,
            )
        };
        if code != 0 {
            return Err(ProductError::Native {
                code: ErrorCode::from_raw(code),
                status: Status {
                    code: ErrorCode::from_raw(code),
                    error_detail:
                        "online VPP rule configuration request failed; query before retrying".into(),
                    ..Status::empty(self.generation)
                },
            });
        }
        Ok(status)
    }

    pub fn query_rule_config(&mut self) -> Result<RuleConfigStatus, ProductError> {
        self.rule_config(&RuleConfigRequest {
            schema: 1,
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_domain_source_survives_the_request_adapter() {
        let mut request = RuleConfigRequest::default();
        request.push_line("lists 64").unwrap();
        request
            .push_line("domain 63 descendants Example.COM.")
            .unwrap();
        assert_eq!(request.domains.list_count, 64);
        assert_eq!(request.domains.entry_count, 1);
        let entry = request.domains.entries[0];
        assert_eq!((entry.list, entry.mode, entry.length), (63, 1, 12));
        assert_eq!(&entry.name[..12], b"Example.COM.");
        assert!(entry.name[12..].iter().all(|b| *b == 0));
        assert_eq!(std::mem::size_of::<DomainEntry>(), 268);
        assert_eq!(std::mem::size_of::<Domains>(), 68616);
        for bad in [
            "domain 64 exact a.example",
            "domain 0 glob a.example",
            "domain 0 exact é.example",
        ] {
            assert!(request.push_line(bad).is_err());
        }
    }
    #[test]
    fn expression_bytes_survive_the_request_adapter() {
        let line = "0 0 17 4294967295 4294967295 1 0 0 0 2 * * 0 65535 0 65535";
        let r = DirectRule::parse(&format!("{line} 0701000000030cffffffff02")).unwrap();
        assert_eq!(r.expression_length, 12);
        assert_eq!(
            &r.expression[..12],
            &[7, 1, 0, 0, 0, 3, 12, 255, 255, 255, 255, 2]
        );
        assert!(r.expression[12..].iter().all(|b| *b == 0));
        for hex in ["0".into(), "gg".into(), "aa".repeat(65), "éé".into()] {
            assert!(DirectRule::parse(&format!("{line} {hex}")).is_err());
        }
    }
    #[test]
    fn fixed_width_online_contract_retains_full_unsigned_rule_version() {
        assert_eq!(std::mem::size_of::<ConfigRule>(), 40);
        assert_eq!(
            std::mem::size_of::<RuleConfigRequest>(),
            64 + 184 * MAX_CONFIG_RULES + 8976 + 68616
        );
        assert_eq!(
            std::mem::size_of::<RuleConfigStatus>(),
            112 + 192 * MAX_CONFIG_RULES + 8976 + 68616
        );
        let status = RuleConfigStatus {
            saved_rule_version: 0xfedc_ba98_7654_0001,
            ..Default::default()
        };
        assert_eq!(status.saved_rule_version >> 16, 0xfedc_ba98_7654);
        assert_eq!(status.saved_rule_version & 65535, 1);
    }
}
