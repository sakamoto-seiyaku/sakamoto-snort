//! Query-time interpretation of persisted rule facts against one VPP source.
//! The source is never copied into the observation database.
use crate::{rule_import::export_rule_config, ProductCore, RuleConfigRequest};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) struct RuleSource {
    revision: u64,
    hash: u64,
    configuration: Value,
    indexes: BTreeMap<u64, usize>,
}

fn identity(text: &str) -> Option<(u64, u64)> {
    let (revision, hash) = text.strip_prefix("rule-config/1/")?.split_once('/')?;
    let revision = revision.parse::<u64>().ok()?;
    let hash = hash.parse::<u64>().ok()?;
    (revision != 0 && hash != 0).then_some((revision, hash))
}

pub(crate) fn needs_source(snapshot: &Value) -> bool {
    let persistent = &snapshot["persistent"];
    persistent["rule_windows"]
        .as_object()
        .is_some_and(|windows| !windows.is_empty())
        || persistent["recent"].as_object().is_some_and(|recent| {
            recent.values().any(|item| {
                item["record"]["attribution"]
                    .as_array()
                    .is_some_and(|sides| {
                        sides
                            .iter()
                            .any(|side| side["winner"].as_u64().unwrap_or(0) != 0)
                    })
            })
        })
}

/// A successful association requires two equal active-snapshot reads around
/// the VPP-owned saved-source query. A changed or failed read proves nothing.
pub(crate) fn live_source(core: &mut ProductCore) -> Result<RuleSource, &'static str> {
    let before = core.query().map_err(|_| "source_query_failed")?;
    let request = RuleConfigRequest::boxed();
    let saved = core
        .rule_config_boxed(&request)
        .map_err(|_| "source_query_failed")?;
    let after = core.query().map_err(|_| "source_query_failed")?;
    if before.policy_snapshot_identity != after.policy_snapshot_identity
        || before.policy_active_revision != after.policy_active_revision
        || before.policy_generation != after.policy_generation
    {
        return Err("source_changed_during_query");
    }
    let (revision, hash) =
        identity(&before.policy_snapshot_identity).ok_or("snapshot_identity_unavailable")?;
    if before.policy_generation != core.generation()
        || saved.generation != core.generation()
        || before.policy_active_revision != revision
        || saved.active_revision != revision
        || saved.saved_revision != revision
        || saved.compile_error != 0
    {
        return Err("matching_saved_source_unavailable");
    }
    let text = export_rule_config(&saved).map_err(|_| "saved_source_invalid")?;
    let configuration: Value = serde_json::from_str(&text).map_err(|_| "saved_source_invalid")?;
    let rules = configuration["rules"]
        .as_array()
        .ok_or("saved_source_invalid")?;
    if rules.len() != saved.count as usize {
        return Err("saved_source_invalid");
    }
    let active: std::collections::BTreeSet<u64> = saved
        .active_versions
        .iter()
        .take(saved.active_count as usize)
        .copied()
        .collect();
    let mut indexes = BTreeMap::new();
    for index in 0..rules.len() {
        // export_rule_config emits these typed saved rules in the same order.
        let version = saved.rules[index].version;
        if version >> 16 == 0 || version & 65535 == 0 {
            return Err("saved_source_invalid");
        }
        if active.contains(&version) && indexes.insert(version, index).is_some() {
            return Err("saved_source_invalid");
        }
    }
    Ok(RuleSource {
        revision,
        hash,
        configuration,
        indexes,
    })
}

fn interpret_reference(
    attribution: &Value,
    interpretation: &mut Value,
    source: &Result<RuleSource, &'static str>,
) -> bool {
    let Some(version) = interpretation["version"]
        .as_str()
        .and_then(|v| v.parse::<u64>().ok())
    else {
        return false;
    };
    fn unavailable(interpretation: &mut Value, reason: &str) {
        interpretation["conditions"] = json!({"status":"unavailable","reason":reason});
    }
    if attribution["valid"] == false {
        unavailable(interpretation, "attribution_unavailable");
        return false;
    }
    let source = match source {
        Ok(source) => source,
        Err(reason) => {
            unavailable(interpretation, reason);
            return false;
        }
    };
    if attribution["policy_revision"].as_u64() != Some(source.revision)
        || attribution["policy_hash"].as_u64() != Some(source.hash)
    {
        unavailable(interpretation, "matching_source_unavailable");
        return false;
    }
    let Some(&index) = source.indexes.get(&version) else {
        unavailable(interpretation, "rule_version_absent");
        return false;
    };
    let saved_name = source.configuration["rules"][index]["name"].as_str();
    if interpretation["name_status"] == "conflict"
        || saved_name.is_none()
        || interpretation["name"]
            .as_str()
            .is_some_and(|name| Some(name) != saved_name)
    {
        unavailable(interpretation, "metadata_conflict");
        return false;
    }
    interpretation["conditions"] = json!({"status":"available","source_rule_index":index});
    true
}

/// Only the visible bounded history is interpreted. All other saved rows and
/// the packet producer remain untouched; unresolved sources stay explicit.
pub(crate) fn annotate(snapshot: &mut Value, source: Result<RuleSource, &'static str>) {
    let persistent = &mut snapshot["persistent"];
    if !persistent.is_object() {
        return;
    }
    let mut any_available = false;
    if let Some(windows) = persistent["rule_windows"].as_object_mut() {
        for window in windows.values_mut() {
            let attribution = window["attribution"].clone();
            any_available |=
                interpret_reference(&attribution, &mut window["interpretation"], &source);
        }
    }
    if let Some(recent) = persistent["recent"].as_object_mut() {
        for item in recent.values_mut() {
            for side in 0..2 {
                let attribution = item["record"]["attribution"][side].clone();
                any_available |= interpret_reference(
                    &attribution,
                    &mut item["record"]["attribution"][side]["interpretation"],
                    &source,
                );
            }
        }
    }
    persistent["history_source"] = if any_available {
        let source = source.expect("available reference has a source");
        json!({"status":"available", "revision":source.revision.to_string(),
            "hash":source.hash.to_string(), "configuration":source.configuration})
    } else {
        json!({"status":"unavailable", "reason":source.err().unwrap_or("no_matching_source_for_visible_history")})
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_lookup_is_unneeded_without_visible_rule_history() {
        assert!(!needs_source(
            &json!({"persistent":{"rule_windows":{},"recent":{}}})
        ));
        assert!(needs_source(
            &json!({"persistent":{"rule_windows":{"one":{}},"recent":{}}})
        ));
        assert!(needs_source(
            &json!({"persistent":{"rule_windows":{},"recent":{
                "ended":{"record":{"attribution":[{"winner":65537},{"winner":0}]}}
            }}})
        ));
    }

    #[test]
    fn matching_snapshot_and_version_are_required_for_complete_conditions() {
        let config = json!({"rules":[{"name":"old","definition":"65537 0 ..."}],
            "groups":[],"edges":[],"bindings":[],"lists":[{"name":"reference","entries":["exact example.org"]}]});
        let source = RuleSource {
            revision: 5,
            hash: 99,
            configuration: config,
            indexes: BTreeMap::from([(65537, 0)]),
        };
        let mut snapshot = json!({"persistent":{"rule_windows":{
            "old":{"attribution":{"valid":true,"winner":65537,"policy_revision":5,"policy_hash":98},
                   "interpretation":{"version":"65537","name":"old","name_status":"recorded"}},
            "current":{"attribution":{"valid":true,"winner":65537,"policy_revision":5,"policy_hash":99},
                   "interpretation":{"version":"65537","name":"old","name_status":"recorded"}}
        },"recent":{}}});
        annotate(&mut snapshot, Ok(source));
        let windows = &snapshot["persistent"]["rule_windows"];
        assert_eq!(
            windows["old"]["interpretation"]["conditions"]["status"],
            "unavailable"
        );
        assert_eq!(
            windows["current"]["interpretation"]["conditions"]["status"],
            "available"
        );
        assert_eq!(
            snapshot["persistent"]["history_source"]["configuration"]["lists"][0]["entries"][0],
            "exact example.org"
        );
    }

    #[test]
    fn missing_source_or_conflicted_metadata_never_substitutes_conditions() {
        let history = || {
            json!({"persistent":{"rule_windows":{
            "r":{"attribution":{"valid":true,"winner":65537,"policy_revision":5,"policy_hash":99},
                 "interpretation":{"version":"65537","name":null,"name_status":"conflict"}}
        },"recent":{}}})
        };
        let mut absent = history();
        annotate(&mut absent, Err("source_query_failed"));
        assert_eq!(
            absent["persistent"]["rule_windows"]["r"]["interpretation"]["conditions"]["reason"],
            "source_query_failed"
        );
        assert!(absent["persistent"]["history_source"]["configuration"].is_null());
        let mut conflict = history();
        annotate(
            &mut conflict,
            Ok(RuleSource {
                revision: 5,
                hash: 99,
                configuration: json!({"rules":[{"name":"new","definition":"65537 0 ..."}]}),
                indexes: BTreeMap::from([(65537, 0)]),
            }),
        );
        assert_eq!(
            conflict["persistent"]["rule_windows"]["r"]["interpretation"]["conditions"]["reason"],
            "metadata_conflict"
        );
        assert!(conflict["persistent"]["history_source"]["configuration"].is_null());
    }
}
