//! Call-owned import preparation. VPP owns the saved source and compilation.
use crate::rule_config::{GroupEdge, RuleBinding, SourceMetadata};
use crate::{DirectRule, DomainEntry, ProductCore, RuleConfigRequest, RuleConfigStatus};
use serde::{Deserialize, Serialize};

pub const MAX_IMPORT_BYTES: usize = 1024 * 1024;
pub const MAX_IMPORT_REPLY_BYTES: usize = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    rules: Vec<Rule>,
    groups: Vec<u32>,
    edges: Vec<[u32; 3]>,
    bindings: Vec<[u32; 5]>,
    lists: Vec<List>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Rule {
    name: String,
    source: String,
    definition: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct List {
    name: String,
    source: String,
    syntax: String,
    entries: Vec<String>,
}

fn metadata(name: &str, source: &str) -> Result<SourceMetadata, String> {
    if name.len() >= 64
        || source.len() >= 128
        || name.chars().chain(source.chars()).any(char::is_control)
    {
        return Err(
            "metadata must be UTF-8 without controls, name <=63 bytes and source <=127 bytes"
                .into(),
        );
    }
    let mut out = SourceMetadata::default();
    out.name[..name.len()].copy_from_slice(name.as_bytes());
    out.source[..source.len()].copy_from_slice(source.as_bytes());
    Ok(out)
}

fn normalize_name(input: &str) -> Result<String, String> {
    let name = input.strip_suffix('.').unwrap_or(input);
    if name.is_empty() || name.ends_with('.') || name.chars().any(char::is_whitespace) {
        return Err("invalid domain name".into());
    }
    let ascii = idna::domain_to_ascii_strict(name).map_err(|_| "invalid IDNA domain name")?;
    if ascii.is_empty() || ascii.len() > 253 || ascii.ends_with('.') {
        return Err("invalid domain name length/tail".into());
    }
    Ok(ascii)
}

fn parse_entry<'a>(syntax: &str, entry: &'a str) -> Result<(u32, &'a str), &'static str> {
    match syntax {
        "native-v1" => match entry.split_once(' ') {
            Some(("exact", name)) => Ok((0, name)),
            Some(("descendants", name)) => Ok((1, name)),
            _ => Err("expected exact or descendants followed by one name"),
        },
        "plain-exact-v1" => Ok((0, entry)),
        "adblock-domain-v1" => entry
            .strip_prefix("||")
            .and_then(|s| s.strip_suffix('^'))
            .map(|name| (1, name))
            .ok_or("only a domain-anchored ||name^ entry is supported"),
        "clash-domain-v1" => match entry.split_once(',') {
            Some(("DOMAIN", name)) => Ok((0, name)),
            Some(("DOMAIN-SUFFIX", name)) => Ok((1, name)),
            _ => Err("only DOMAIN,name or DOMAIN-SUFFIX,name is supported"),
        },
        _ => Err("unsupported list syntax"),
    }
}

/// Prepare one complete, bounded replacement. This function never saves or
/// compiles; the returned request is submitted to the existing VPP API.
pub fn prepare_rule_import(
    text: &str,
    expected_revision: u64,
) -> Result<Box<RuleConfigRequest>, String> {
    if text.len() > MAX_IMPORT_BYTES {
        return Err("input exceeds 1 MiB".into());
    }
    let document: Document = serde_json::from_str(text).map_err(|e| format!("format: {e}"))?;
    if document.format != "sakamoto-config-v1" {
        return Err("unsupported import format".into());
    }
    if document.rules.len() > 256
        || document.groups.len() > 64
        || document.edges.len() > 512
        || document.bindings.len() > 128
        || document.lists.len() > 64
    {
        return Err("configuration exceeds source capacity".into());
    }
    let mut request = RuleConfigRequest::boxed();
    request.operation = 2;
    request.expected_saved_revision = expected_revision;
    request.count = document.rules.len() as u32;
    for (i, rule) in document.rules.iter().enumerate() {
        request.rules[i] =
            DirectRule::parse(&rule.definition).map_err(|e| format!("rule[{i}]: {e}"))?;
        request.metadata.rules[i] =
            metadata(&rule.name, &rule.source).map_err(|e| format!("rule[{i}]: {e}"))?;
    }
    request.graph.group_count = document.groups.len() as u32;
    request.graph.edge_count = document.edges.len() as u32;
    request.graph.binding_count = document.bindings.len() as u32;
    request.graph.groups[..document.groups.len()].copy_from_slice(&document.groups);
    for (out, &[group, kind, target]) in request.graph.edges.iter_mut().zip(&document.edges) {
        *out = GroupEdge {
            group,
            kind,
            target,
        };
    }
    for (out, &[id, uid, kind, target, mode]) in
        request.graph.bindings.iter_mut().zip(&document.bindings)
    {
        *out = RuleBinding {
            id,
            uid,
            kind,
            target,
            mode,
        };
    }
    request.domains.list_count = document.lists.len() as u32;
    for (list_index, list) in document.lists.iter().enumerate() {
        request.metadata.lists[list_index] =
            metadata(&list.name, &list.source).map_err(|e| format!("list[{list_index}]: {e}"))?;
        if !matches!(
            list.syntax.as_str(),
            "native-v1" | "plain-exact-v1" | "adblock-domain-v1" | "clash-domain-v1"
        ) {
            return Err(format!("list[{list_index}]: unsupported syntax"));
        }
        for (entry_index, entry) in list.entries.iter().enumerate() {
            let (mode, name) = parse_entry(&list.syntax, entry)
                .map_err(|e| format!("list[{list_index}].entry[{entry_index}]: {e}"))?;
            let name = normalize_name(name)
                .map_err(|e| format!("list[{list_index}].entry[{entry_index}]: {e}"))?;
            if request.domains.entries[..request.domains.entry_count as usize]
                .iter()
                .any(|e| {
                    e.list == list_index as u32
                        && e.mode == mode
                        && e.length as usize == name.len()
                        && &e.name[..name.len()] == name.as_bytes()
                })
            {
                continue;
            }
            if request.domains.entry_count == 256 {
                return Err("domain entries exceed 256".into());
            }
            let mut out = DomainEntry {
                list: list_index as u32,
                mode,
                length: name.len() as u32,
                ..Default::default()
            };
            out.name[..name.len()].copy_from_slice(name.as_bytes());
            request.domains.entries[request.domains.entry_count as usize] = out;
            request.domains.entry_count += 1;
        }
    }
    Ok(request)
}

fn text_field(bytes: &[u8]) -> Result<&str, String> {
    let end = bytes
        .iter()
        .position(|b| *b == 0)
        .ok_or("unterminated source metadata")?;
    if bytes[end..].iter().any(|b| *b != 0) {
        return Err("noncanonical source metadata tail".into());
    }
    let text = std::str::from_utf8(&bytes[..end]).map_err(|_| "invalid UTF-8 source metadata")?;
    if text.chars().any(char::is_control) {
        return Err("invalid source metadata control".into());
    }
    Ok(text)
}

fn rule_definition(rule: &DirectRule) -> Result<String, String> {
    if rule.reserved != 0 || rule.base_version != 0 || rule.expression_length > 64 {
        return Err("invalid saved rule fields".into());
    }
    let address = |bytes: [u8; 16], prefix: u32| -> Result<String, String> {
        match rule.family {
            0 if prefix == 0 && bytes == [0; 16] => Ok("*".into()),
            4 if prefix <= 32 && bytes[4..] == [0; 12] => Ok(format!(
                "{}/{}",
                std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
                prefix
            )),
            6 if prefix <= 128 => Ok(format!("{}/{}", std::net::Ipv6Addr::from(bytes), prefix)),
            _ => Err("invalid saved address family/prefix".into()),
        }
    };
    let mut text = format!(
        "{} 0 {} {} {} {} {} {} {} {} {} {} {} {} {} {}",
        rule.version,
        rule.uid,
        rule.network_context,
        rule.ifindex,
        rule.priority,
        rule.order,
        rule.protocol,
        rule.direction,
        rule.action,
        address(rule.source_address, rule.source_prefix)?,
        address(rule.destination_address, rule.destination_prefix)?,
        rule.source_port_first,
        rule.source_port_last,
        rule.destination_port_first,
        rule.destination_port_last
    );
    if rule.expression_length != 0 {
        use std::fmt::Write;
        text.push(' ');
        for byte in &rule.expression[..rule.expression_length as usize] {
            write!(&mut text, "{byte:02x}").expect("String formatting cannot fail");
        }
    }
    Ok(text)
}

/// Export only VPP's queried saved source. This creates a caller-owned document,
/// not another authoritative or editable configuration store.
pub fn export_rule_config(status: &RuleConfigStatus) -> Result<String, String> {
    if status.saved_revision == 0 {
        return Err("no valid saved source is available to export".into());
    }
    if status.count > 256
        || status.active_count > 256
        || status.graph.group_count > 64
        || status.graph.edge_count > 512
        || status.graph.binding_count > 128
        || status.domains.list_count > 64
        || status.domains.entry_count > 256
    {
        return Err("invalid source counts in reply".into());
    }
    let mut document = Document {
        format: "sakamoto-config-v1".into(),
        rules: Vec::new(),
        groups: status.graph.groups[..status.graph.group_count as usize].to_vec(),
        edges: status.graph.edges[..status.graph.edge_count as usize]
            .iter()
            .map(|e| [e.group, e.kind, e.target])
            .collect(),
        bindings: status.graph.bindings[..status.graph.binding_count as usize]
            .iter()
            .map(|b| [b.id, b.uid, b.kind, b.target, b.mode])
            .collect(),
        lists: Vec::new(),
    };
    for (i, rule) in status.rules[..status.count as usize].iter().enumerate() {
        document.rules.push(Rule {
            name: text_field(&status.metadata.rules[i].name)?.into(),
            source: text_field(&status.metadata.rules[i].source)?.into(),
            definition: rule_definition(rule)?,
        });
    }
    for i in 0..status.domains.list_count as usize {
        document.lists.push(List {
            name: text_field(&status.metadata.lists[i].name)?.into(),
            source: text_field(&status.metadata.lists[i].source)?.into(),
            syntax: "native-v1".into(),
            entries: Vec::new(),
        });
    }
    for entry in &status.domains.entries[..status.domains.entry_count as usize] {
        if entry.list >= status.domains.list_count || entry.length > 253 {
            return Err("invalid domain reply".into());
        }
        let mode = match entry.mode {
            0 => "exact",
            1 => "descendants",
            _ => return Err("invalid domain mode in reply".into()),
        };
        let name = std::str::from_utf8(&entry.name[..entry.length as usize])
            .map_err(|_| "invalid domain reply")?;
        document.lists[entry.list as usize]
            .entries
            .push(format!("{mode} {name}"));
    }
    serde_json::to_string_pretty(&document).map_err(|e| format!("export: {e}"))
}

impl ProductCore {
    /// The same online import/export operation is used by Host and Android.
    /// `None` queries/exports; `Some` submits one complete prepared replacement.
    pub fn rule_import_json(&mut self, text: Option<&str>, expected_revision: u64) -> String {
        let request = match text {
            Some(text) => match prepare_rule_import(text, expected_revision) {
                Ok(request) => request,
                Err(error) => {
                    return serde_json::json!({"stage":"prepare", "error":error}).to_string()
                }
            },
            None => RuleConfigRequest::boxed(),
        };
        let status = match self.rule_config_boxed(&request) {
            Ok(status) => status,
            Err(error) => {
                return serde_json::json!({"stage":"transport", "code":error.code().raw(),
                "error":"online configuration unavailable; query saved state before retrying"})
                .to_string()
            }
        };
        let configuration = match export_rule_config(&status).and_then(|text| {
            serde_json::from_str::<serde_json::Value>(&text).map_err(|e| e.to_string())
        }) {
            Ok(configuration) => configuration,
            Err(error) => {
                return serde_json::json!({"stage":"reply", "error":error,
                "saved_revision":status.saved_revision,"active_revision":status.active_revision})
                .to_string()
            }
        };
        serde_json::json!({"stage":"vpp", "generation":status.generation,
            "saved_revision":status.saved_revision,"active_revision":status.active_revision,
            "result":status.result,"save_error":status.save_error,"compile_error":status.compile_error,
            "error_index":status.error_index,"compiler_status":status.compiler_status,
            "active_versions":status.active_versions[..status.active_count as usize].iter().map(u64::to_string).collect::<Vec<_>>(),
            "configuration":configuration}).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list_input(syntax: &str, entries: &[&str]) -> String {
        serde_json::json!({"format":"sakamoto-config-v1", "rules":[], "groups":[],
            "edges":[], "bindings":[], "lists":[{"name":"sample", "source":"fixture",
                "syntax":syntax, "entries":entries}]})
        .to_string()
    }

    #[test]
    fn declared_source_syntax_and_duplicates_never_broaden_a_filter() {
        let request = prepare_rule_import(
            &list_input("adblock-domain-v1", &["||Example.COM^", "||example.com.^"]),
            0,
        )
        .unwrap();
        assert_eq!(request.domains.entry_count, 1);
        assert_eq!(request.domains.entries[0].mode, 1);
        let request = prepare_rule_import(
            &list_input(
                "clash-domain-v1",
                &["DOMAIN,example.com", "DOMAIN-SUFFIX,sub.example.com"],
            ),
            0,
        )
        .unwrap();
        assert_eq!(request.domains.entry_count, 2);
        assert_eq!(request.domains.entries[0].mode, 0);
        assert_eq!(request.domains.entries[1].mode, 1);
        for (syntax, entry) in [
            ("native-v1", "exact *.example.com"),
            ("native-v1", "descendants https://example.com/path"),
            ("adblock-domain-v1", "||example.com^$third-party"),
            ("adblock-domain-v1", "||*.example.com^"),
            ("adblock-domain-v1", "@@||example.com^"),
            ("adblock-domain-v1", "||example.com/path^"),
            ("clash-domain-v1", "DOMAIN,example.com,Proxy"),
            ("clash-domain-v1", "DOMAIN-KEYWORD,example"),
            ("clash-domain-v1", "DOMAIN-WILDCARD,*.example.com"),
            ("plain-exact-v1", "||example.com^"),
        ] {
            assert!(
                prepare_rule_import(&list_input(syntax, &[entry]), 0).is_err(),
                "{syntax}: {entry}"
            );
        }
    }

    #[test]
    fn export_reimport_preserves_full_rules_graph_lists_and_provenance() {
        let input = r#"{"format":"sakamoto-config-v1",
          "rules":[{"name":"IPv6 条件","source":"local \"sample\"",
            "definition":"18364758544493051905 0 4294967295 3 9 4 5 6 1 2 2001:db8::/32 2001:db8:1::/48 10 20 443 444 11000f0200000002"}],
          "groups":[7],"edges":[[7,1,0]],"bindings":[[11,17,2,7,1]],
          "lists":[{"name":"包含子域","source":"source.txt","syntax":"clash-domain-v1",
            "entries":["DOMAIN-SUFFIX,BÜCHER.Example."]}] }"#;
        let request = prepare_rule_import(input, 6).unwrap();
        let mut saved = RuleConfigStatus::boxed();
        saved.count = request.count;
        saved.rules = request.rules;
        saved.graph = request.graph;
        saved.domains = request.domains;
        saved.metadata = request.metadata;
        saved.saved_revision = 7;
        saved.active_revision = 7;
        let exported = export_rule_config(&saved).unwrap();
        let roundtrip = prepare_rule_import(&exported, saved.saved_revision).unwrap();
        assert_eq!(roundtrip.rules[0], request.rules[0]);
        assert_eq!(roundtrip.metadata, request.metadata);
        assert_eq!(roundtrip.graph.groups[0], 7);
        assert_eq!(
            roundtrip.graph.edges[0],
            GroupEdge {
                group: 7,
                kind: 1,
                target: 0
            }
        );
        assert_eq!(
            roundtrip.graph.bindings[0],
            RuleBinding {
                id: 11,
                uid: 17,
                kind: 2,
                target: 7,
                mode: 1
            }
        );
        assert_eq!(roundtrip.domains.entry_count, 1);
        assert_eq!(roundtrip.domains.entries[0].mode, 1);
        assert_eq!(
            &roundtrip.domains.entries[0].name[..21],
            b"xn--bcher-kva.example"
        );
        assert_eq!(export_rule_config(&saved).unwrap(), exported);
    }

    #[test]
    fn complete_unicode_import_preserves_conditions_and_normalizes_only_names() {
        let input = r#"{
          "format":"sakamoto-config-v1",
          "rules":[{"name":"TLS example","source":"local sample",
            "definition":"18364758544493051905 0 17 4294967295 4294967295 4 3 6 3 2 * * 1000 2000 443 443 1100"}],
          "groups":[],"edges":[],"bindings":[],
          "lists":[{"name":"Unicode list","source":"sample.txt","syntax":"native-v1",
            "entries":["exact BÜCHER.Example.","descendants Example.COM."]}]
        }"#;
        let request = prepare_rule_import(input, 9).unwrap();
        assert_eq!(request.expected_saved_revision, 9);
        assert_eq!(request.operation, 2);
        assert_eq!(request.count, 1);
        let r = request.rules[0];
        assert_eq!(r.version, 0xfedc_ba98_7654_0001);
        assert_eq!((r.protocol, r.direction, r.action), (6, 3, 2));
        assert_eq!(
            (
                r.source_port_first,
                r.source_port_last,
                r.destination_port_first,
                r.destination_port_last
            ),
            (1000, 2000, 443, 443)
        );
        assert_eq!(&r.expression[..r.expression_length as usize], &[17, 0]);
        assert_eq!(request.domains.entry_count, 2);
        let first = request.domains.entries[0];
        assert_eq!(
            &first.name[..first.length as usize],
            b"xn--bcher-kva.example"
        );
        let second = request.domains.entries[1];
        assert_eq!((second.list, second.mode), (0, 1));
        assert_eq!(&second.name[..second.length as usize], b"example.com");
        assert_eq!(&request.metadata.rules[0].name[..11], b"TLS example");
        assert_eq!(&request.metadata.rules[0].source[..12], b"local sample");
        assert_eq!(&request.metadata.lists[0].name[..12], b"Unicode list");
        assert_eq!(&request.metadata.lists[0].source[..10], b"sample.txt");
    }
}
