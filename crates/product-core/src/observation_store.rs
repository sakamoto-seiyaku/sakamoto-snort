//! Minimal transactional overall-window store. No raw event log or repository framework.
use crate::observation::{historical_protocol_label, protocol_label, protocol_mask, Attribution, FlowRecord};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_SNAPSHOT: u64 = 64 * 1024 * 1024;
const MAX_BASELINES: usize = 131072;
const MAX_END_MARKERS: usize = 262144;
const MAX_RECENT: usize = 32768;
const MAX_MINUTES: usize = 262144;
const MAX_DIRTY: usize = 4096;
const MAX_EFFECT_WINDOWS: usize = 65536;
const MAX_PROTOCOL_WINDOWS: usize = 65536;
const MAX_RULE_NAMES: usize = 65536;
const FLUSH_ROWS: usize = 2048;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
// The 256 MiB owner budget includes the retained <=64 MiB predecessor,
// <=64 MiB database (indexes included), <=81 MiB WAL and bookkeeping. With
// cache spilling disabled, one bounded transaction writes each database page
// at most once at commit. Checkpoint before another transaction at 16 MiB.
const DATABASE_LIMIT: u64 = 64 * 1024 * 1024;
const WAL_LIMIT: u64 = 16 * 1024 * 1024;
const MAX_QUERY_MINUTES: usize = 2880;
const MAX_QUERY_HOURS: usize = 720;
const MAX_QUERY_DAYS: usize = 180;
const RECENT_US: u64 = 24 * 60 * 60 * 1_000_000;
const MINUTE_US: u64 = 60 * 1_000_000;
const HOUR_US: u64 = 60 * MINUTE_US;
const DAY_US: u64 = 24 * HOUR_US;
const MINUTE_AGE_US: u64 = 48 * HOUR_US;
const HOUR_AGE_US: u64 = 30 * DAY_US;
const DAY_AGE_US: u64 = 180 * DAY_US;
const RETENTION_ROWS_PER_BATCH: usize = 256;
const FULL_RECLAIM_ATTEMPTS: usize = 32;
const MAX_PROTOCOLS_PER_APP_BUCKET: usize = 128;
const STORAGE_BUDGET: u64 = 256 * 1024 * 1024;
const WORKING_RESERVE: u64 = 48 * 1024 * 1024;
const CLOCK_RECONCILE: Duration = Duration::from_secs(60);
#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetentionLimits {
    minute_age_us: u64,
    hour_age_us: u64,
    day_age_us: u64,
    end_age_us: u64,
    budget_bytes: u64,
    working_reserve_bytes: u64,
    #[serde(default)]
    clock_offset_us: u64,
}
impl Default for RetentionLimits {
    fn default() -> Self {
        Self { minute_age_us: MINUTE_AGE_US, hour_age_us: HOUR_AGE_US,
            day_age_us: DAY_AGE_US, end_age_us: RECENT_US,
            budget_bytes: STORAGE_BUDGET, working_reserve_bytes: WORKING_RESERVE,
            clock_offset_us: 0 }
    }
}
impl RetentionLimits {
    fn database_limit(self) -> u64 {
        DATABASE_LIMIT.min((self.budget_bytes - self.working_reserve_bytes) / 3)
            / 4096 * 4096
    }
    fn load(path: &Path) -> Result<(Self, bool), String> {
        let config_path = path.with_extension("retention-test.json");
        let bytes = match std::fs::read(config_path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Self::default(), false)),
            Err(e) => return Err(e.to_string()),
        };
        if bytes.len() > 4096 { return Err("observation_retention_config_size".into()); }
        let limits: Self = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        if limits.minute_age_us < MINUTE_US || limits.hour_age_us < limits.minute_age_us
            || limits.day_age_us < limits.hour_age_us || limits.end_age_us == 0
            || limits.budget_bytes < 64 * 1024 || limits.budget_bytes > STORAGE_BUDGET
            || limits.working_reserve_bytes > limits.budget_bytes / 2
            || limits.clock_offset_us > 365 * DAY_US {
            return Err("observation_retention_config_bounds".into());
        }
        Ok((limits, true))
    }
}
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[derive(Clone, Copy, Default, Serialize, Deserialize)]
struct Counts {
    packets: [u64; 2],
    bytes: [u64; 2],
}
impl Counts {
    fn add(&mut self, delta: &Self) -> Result<(), String> {
        for i in 0..2 {
            self.packets[i] = self.packets[i]
                .checked_add(delta.packets[i])
                .ok_or("packet_overflow")?;
            self.bytes[i] = self.bytes[i]
                .checked_add(delta.bytes[i])
                .ok_or("byte_overflow")?;
        }
        Ok(())
    }
    fn difference(&self, smaller: &Self) -> Result<Self, String> {
        let mut result = Self::default();
        for side in 0..2 {
            result.packets[side] = self.packets[side]
                .checked_sub(smaller.packets[side]).ok_or("observation_count_underflow")?;
            result.bytes[side] = self.bytes[side]
                .checked_sub(smaller.bytes[side]).ok_or("observation_count_underflow")?;
        }
        Ok(result)
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct ApplicationWindow {
    minute: u64,
    uid: u32,
    actual_action: u8,
    counts: Counts,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RuleReference {
    policy_generation: u64,
    policy_revision: u64,
    policy_hash: u64,
    winner: u64,
    uid: u32,
    network: u32,
    declared_action: u8,
    actual_action: u8,
    mode: u8,
    name: String,
}
impl From<&Attribution> for RuleReference {
    fn from(a: &Attribution) -> Self {
        Self {
            policy_generation: a.policy_generation,
            policy_revision: a.policy_revision,
            policy_hash: a.policy_hash,
            winner: a.winner,
            uid: a.uid,
            network: a.network,
            declared_action: a.declared_action,
            actual_action: a.actual_action,
            mode: a.mode,
            name: a.name.clone(),
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct RuleWindow {
    minute: u64,
    attribution: RuleReference,
    counts: Counts,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ProtocolLayer {
    #[serde(rename = "l4")]
    L4,
    #[serde(rename = "l7")]
    L7,
    #[serde(rename = "l7_none")]
    L7None,
    #[serde(rename = "l7_unavailable")]
    L7Unavailable,
}
impl ProtocolLayer {
    fn key(self) -> &'static str {
        match self {
            Self::L4 => "l4",
            Self::L7 => "l7",
            Self::L7None => "l7_none",
            Self::L7Unavailable => "l7_unavailable",
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct ProtocolWindow {
    minute: u64,
    uid: u32,
    actual_action: u8,
    layer: ProtocolLayer,
    protocol_id: u32,
    key: String,
    counts: Counts,
}

#[derive(Clone, Serialize, Deserialize)]
struct Baseline {
    record: FlowRecord,
    first_end_us: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct EndMarker {
    incarnation: u64,
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct WindowSet {
    totals: BTreeMap<u64, Counts>,
    unknown: BTreeMap<u64, Counts>,
    applications: BTreeMap<String, ApplicationWindow>,
    rules: BTreeMap<String, RuleWindow>,
    protocols: BTreeMap<String, ProtocolWindow>,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum RetentionTransition {
    Rollup { from: i32, to: i32, start: u64 },
    EvictDay { start: u64 },
}
fn first_at<T: Clone>(rows: &BTreeMap<String, T>, start: u64) -> Option<(String, T)> {
    let prefix = format!("{start:020}:");
    rows.range(prefix.clone()..).next()
        .filter(|(key, _)| key.starts_with(&prefix))
        .map(|(key, row)| (key.clone(), row.clone()))
}

fn latest_rows_at<T: Clone>(rows: &BTreeMap<String, T>, start: u64,
    limit: usize) -> BTreeMap<String, T> {
    let lower = format!("{start:020}:");
    let upper = format!("{start:020};");
    rows.range(lower..upper).rev().take(limit)
        .map(|(key, row)| (key.clone(), row.clone())).collect()
}

fn count_rows_at<T>(rows: &BTreeMap<String, T>, start: u64) -> usize {
    let lower = format!("{start:020}:");
    let upper = format!("{start:020};");
    rows.range(lower..upper).count()
}

fn overlapping_rows<T, U>(source: &BTreeMap<String, T>, target: &BTreeMap<String, U>,
    start: u64, target_start: u64) -> usize {
    let lower = format!("{start:020}:");
    let upper = format!("{start:020};");
    source.range(lower..upper)
        .filter(|(key, _)| target.contains_key(&rekey(target_start, key)))
        .count()
}

fn rekey(start: u64, key: &str) -> String {
    format!("{start:020}{}", &key[20..])
}

fn merged_application(old: Option<&ApplicationWindow>, source: &ApplicationWindow,
    start: u64) -> Result<ApplicationWindow, String> {
    let mut row = old.cloned().unwrap_or_else(|| {
        let mut row = source.clone(); row.minute = start; row.counts = Counts::default(); row
    });
    if row.minute != start || row.uid != source.uid || row.actual_action != source.actual_action {
        return Err("observation_rollup_application_conflict".into());
    }
    row.counts.add(&source.counts)?;
    Ok(row)
}

fn merged_rule(old: Option<&RuleWindow>, source: &RuleWindow,
    start: u64) -> Result<RuleWindow, String> {
    let mut row = old.cloned().unwrap_or_else(|| {
        let mut row = source.clone(); row.minute = start; row.counts = Counts::default(); row
    });
    let mut existing = row.attribution.clone(); existing.name.clear();
    let mut incoming = source.attribution.clone(); incoming.name.clear();
    if row.minute != start || existing != incoming {
        return Err("observation_rollup_rule_conflict".into());
    }
    if !row.attribution.name.is_empty() && !source.attribution.name.is_empty()
        && row.attribution.name != source.attribution.name {
        row.attribution.name.clear();
    }
    if row.attribution.name.is_empty() && !source.attribution.name.is_empty()
        && row.counts.packets == [0; 2] && row.counts.bytes == [0; 2] {
        row.attribution.name = source.attribution.name.clone();
    }
    row.counts.add(&source.counts)?;
    Ok(row)
}

fn merged_protocol(old: Option<&ProtocolWindow>, source: &ProtocolWindow,
    start: u64) -> Result<ProtocolWindow, String> {
    let mut row = old.cloned().unwrap_or_else(|| {
        let mut row = source.clone(); row.minute = start; row.counts = Counts::default(); row
    });
    if row.minute != start || row.layer != source.layer || row.protocol_id != source.protocol_id
        || row.key != source.key || row.uid != source.uid
        || row.actual_action != source.actual_action {
        return Err("observation_rollup_protocol_conflict".into());
    }
    row.counts.add(&source.counts)?;
    Ok(row)
}

fn bucket_expired(now_us: u64, start_sec: u64, width_sec: u64, age_us: u64) -> bool {
    now_us.saturating_sub(start_sec.saturating_add(width_sec).saturating_mul(1_000_000))
        >= age_us
}

impl WindowSet {
    fn merge(&mut self, incoming: &Self, start: u64) -> Result<(), String> {
        for counts in incoming.totals.values() {
            self.totals.entry(start).or_default().add(counts)?;
        }
        for counts in incoming.unknown.values() {
            self.unknown.entry(start).or_default().add(counts)?;
        }
        for (key, row) in &incoming.applications {
            let mut next = row.clone(); next.minute = start;
            let target = self.applications.entry(rekey(start, key)).or_insert_with(|| {
                next.counts = Counts::default(); next.clone()
            });
            target.counts.add(&row.counts)?;
        }
        for (key, row) in &incoming.rules {
            let mut next = row.clone(); next.minute = start;
            let target = self.rules.entry(rekey(start, key)).or_insert_with(|| {
                next.counts = Counts::default(); next.clone()
            });
            let mut left = target.attribution.clone(); left.name.clear();
            let mut right = row.attribution.clone(); right.name.clear();
            if left != right { return Err("observation_rollup_rule_conflict".into()); }
            if !target.attribution.name.is_empty() && !row.attribution.name.is_empty()
                && target.attribution.name != row.attribution.name {
                target.attribution.name.clear();
            }
            if target.attribution.name.is_empty() && !row.attribution.name.is_empty()
                && target.counts.packets == [0; 2] && target.counts.bytes == [0; 2] {
                target.attribution.name = row.attribution.name.clone();
            }
            target.counts.add(&row.counts)?;
        }
        for (key, row) in &incoming.protocols {
            let mut next = row.clone(); next.minute = start;
            let target = self.protocols.entry(rekey(start, key)).or_insert_with(|| {
                next.counts = Counts::default(); next.clone()
            });
            if target.layer != row.layer || target.protocol_id != row.protocol_id
                || target.key != row.key || target.uid != row.uid
                || target.actual_action != row.actual_action {
                return Err("observation_rollup_protocol_conflict".into());
            }
            target.counts.add(&row.counts)?;
        }
        Ok(())
    }

    fn query(&self, names: &BTreeMap<u64, Option<String>>, width_sec: u64,
        hidden: Option<u64>) -> serde_json::Value {
        let limit = if width_sec == 3600 { MAX_QUERY_HOURS } else { MAX_QUERY_DAYS };
        let hidden_prefix = hidden.map(|start| format!("{start:020}:"));
        let visible = |key: &str| hidden_prefix.as_ref().is_none_or(|prefix| !key.starts_with(prefix));
        let rules: BTreeMap<_, _> = self.rules.iter().rev()
            .filter(|(key, _)| visible(key)).take(limit).map(|(key, window)| {
            let mut row = serde_json::to_value(window).expect("stored rule window");
            row["interpretation"] = rule_interpretation(window.attribution.winner,
                &window.attribution.name, names, window.attribution.actual_action, true);
            (key, row)
        }).collect();
        let protocols: BTreeMap<_, _> = self.protocols.iter().rev()
            .filter(|(key, _)| visible(key)).take(limit).map(|(key, window)| {
            let app_key = format!("{:020}:{}:{}", window.minute, window.uid, window.actual_action);
            let denominator = &self.applications[&app_key].counts;
            (key, serde_json::json!({
                "minute": window.minute, "uid": window.uid,
                "actual_action": window.actual_action, "layer": window.layer,
                "protocol_id": window.protocol_id, "key": window.key,
                "counts": window.counts, "denominator": denominator,
                "share": protocol_share(&window.counts, denominator),
            }))
        }).collect();
        let totals_count = self.totals.len() - usize::from(hidden.is_some_and(|start| self.totals.contains_key(&start)));
        let unknown_count = self.unknown.len() - usize::from(hidden.is_some_and(|start| self.unknown.contains_key(&start)));
        let apps_count = self.applications.len() - hidden.map_or(0, |start| count_rows_at(&self.applications, start));
        let rules_count = self.rules.len() - hidden.map_or(0, |start| count_rows_at(&self.rules, start));
        let protocols_count = self.protocols.len() - hidden.map_or(0, |start| count_rows_at(&self.protocols, start));
        serde_json::json!({
            "bucket_width_sec": width_sec,
            "overall": self.totals.iter().rev().filter(|(key, _)| Some(**key) != hidden)
                .take(limit).collect::<BTreeMap<_,_>>(),
            "attribution_unknown": self.unknown.iter().rev().filter(|(key, _)| Some(**key) != hidden)
                .take(limit).collect::<BTreeMap<_,_>>(),
            "application_windows": self.applications.iter().rev().filter(|(key, _)| visible(key))
                .take(limit).collect::<BTreeMap<_,_>>(),
            "rule_windows": rules, "protocol_windows": protocols,
            "counts": {"overall": totals_count, "attribution_unknown": unknown_count,
                "applications": apps_count, "rules": rules_count,
                "protocols": protocols_count},
            "query_limit": limit,
            "truncated": totals_count > limit || unknown_count > limit
                || apps_count > limit || rules_count > limit || protocols_count > limit,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct State {
    baselines: BTreeMap<String, Baseline>,
    recent: BTreeMap<String, Baseline>,
    minutes: BTreeMap<u64, Counts>,
    #[serde(default)]
    unknown_minutes: BTreeMap<u64, Counts>,
    #[serde(default)]
    applications: BTreeMap<String, ApplicationWindow>,
    #[serde(default)]
    rules: BTreeMap<String, RuleWindow>,
    #[serde(default)]
    protocols: BTreeMap<String, ProtocolWindow>,
    #[serde(default)]
    rule_names: BTreeMap<u64, Option<String>>,
    #[serde(default)]
    hours: WindowSet,
    #[serde(default)]
    days: WindowSet,
    #[serde(default)]
    end_markers: BTreeMap<String, EndMarker>,
    #[serde(flatten)]
    meta: Metadata,
}
#[derive(Clone, Serialize, Deserialize)]
struct Metadata {
    schema: u32,
    #[serde(default)]
    attribution_schema: u32,
    #[serde(default)]
    attribution_unknown: Counts,
    #[serde(default)]
    legacy_unattributed: Counts,
    #[serde(default)]
    protocol_schema: u32,
    #[serde(default)]
    legacy_protocol_unavailable: Counts,
    #[serde(default)]
    l4_unknown: Counts,
    #[serde(default)]
    l7_unknown: Counts,
    #[serde(default)]
    rule_metadata_association_misses: u64,
    totals: Counts,
    #[serde(default)]
    blocked_totals: Counts,
    #[serde(default)]
    blocked_ended: u64,
    ended: u64,
    accepted: u64,
    rejected: u64,
    gaps: u64,
    clock_changes: u64,
    open_session: bool,
    recoveries: u64,
    first_activity_us: Option<u64>,
    last_activity_us: Option<u64>,
    #[serde(default)]
    retention_watermark_us: u64,
    #[serde(default)]
    evicted: Counts,
    #[serde(default)]
    evicted_unknown: Counts,
    #[serde(default)]
    evicted_l4: Counts,
    #[serde(default)]
    evicted_attributed: Counts,
    #[serde(default)]
    retention_boot_id: String,
    #[serde(default)]
    retention_uptime_us: u64,
    #[serde(default)]
    current_generation: u64,
    #[serde(default)]
    transition: Option<RetentionTransition>,
}
impl Default for Metadata {
    fn default() -> Self {
        Self {
            schema: 1,
            attribution_schema: 1,
            attribution_unknown: Counts::default(),
            legacy_unattributed: Counts::default(),
            protocol_schema: 1,
            legacy_protocol_unavailable: Counts::default(),
            l4_unknown: Counts::default(),
            l7_unknown: Counts::default(),
            rule_metadata_association_misses: 0,
            totals: Counts::default(),
            blocked_totals: Counts::default(),
            blocked_ended: 0,
            ended: 0,
            accepted: 0,
            rejected: 0,
            gaps: 0,
            clock_changes: 0,
            open_session: false,
            recoveries: 0,
            first_activity_us: None,
            last_activity_us: None,
            retention_watermark_us: 0,
            evicted: Counts::default(),
            evicted_unknown: Counts::default(),
            evicted_l4: Counts::default(),
            evicted_attributed: Counts::default(),
            retention_boot_id: String::new(),
            retention_uptime_us: 0,
            current_generation: 0,
            transition: None,
        }
    }
}
impl Default for State {
    fn default() -> Self {
        Self {
            baselines: BTreeMap::new(),
            recent: BTreeMap::new(),
            minutes: BTreeMap::new(),
            unknown_minutes: BTreeMap::new(),
            applications: BTreeMap::new(),
            rules: BTreeMap::new(),
            protocols: BTreeMap::new(),
            rule_names: BTreeMap::new(),
            hours: WindowSet::default(),
            days: WindowSet::default(),
            end_markers: BTreeMap::new(),
            meta: Metadata::default(),
        }
    }
}
impl State {
    fn views(&self, base: i32) -> (&BTreeMap<u64, Counts>, &BTreeMap<u64, Counts>,
        &BTreeMap<String, ApplicationWindow>, &BTreeMap<String, RuleWindow>,
        &BTreeMap<String, ProtocolWindow>) {
        if base == 3 {
            (&self.minutes, &self.unknown_minutes, &self.applications, &self.rules, &self.protocols)
        } else {
            let set = if base == 9 { &self.hours } else { &self.days };
            (&set.totals, &set.unknown, &set.applications, &set.rules, &set.protocols)
        }
    }

    fn views_mut(&mut self, base: i32) -> (&mut BTreeMap<u64, Counts>, &mut BTreeMap<u64, Counts>,
        &mut BTreeMap<String, ApplicationWindow>, &mut BTreeMap<String, RuleWindow>,
        &mut BTreeMap<String, ProtocolWindow>) {
        if base == 3 {
            (&mut self.minutes, &mut self.unknown_minutes, &mut self.applications,
                &mut self.rules, &mut self.protocols)
        } else {
            let set = if base == 9 { &mut self.hours } else { &mut self.days };
            (&mut set.totals, &mut set.unknown, &mut set.applications,
                &mut set.rules, &mut set.protocols)
        }
    }
}
#[derive(Default)]
struct Dirty {
    baselines: BTreeSet<String>,
    recent: BTreeSet<String>,
    minutes: BTreeSet<u64>,
    unknown_minutes: BTreeSet<u64>,
    applications: BTreeSet<String>,
    rules: BTreeSet<String>,
    protocols: BTreeSet<String>,
    rule_names: BTreeSet<u64>,
    meta: bool,
    retained: BTreeSet<(i32, String)>,
    end_markers: BTreeSet<String>,
}
impl Dirty {
    fn mark(&mut self, kind: i32, key: &str) {
        match kind {
            3 => { self.minutes.insert(key.parse().expect("minute key")); }
            4 => { self.applications.insert(key.to_owned()); }
            5 => { self.rules.insert(key.to_owned()); }
            6 => { self.unknown_minutes.insert(key.parse().expect("unknown minute key")); }
            7 => { self.protocols.insert(key.to_owned()); }
            9..=18 => { self.retained.insert((kind, key.to_owned())); }
            _ => unreachable!("observation tier kind"),
        }
        self.meta = true;
    }
    fn len(&self) -> usize {
        self.baselines.len()
            + self.recent.len()
            + self.minutes.len()
            + self.applications.len()
            + self.rules.len()
            + self.protocols.len()
            + self.rule_names.len()
            + self.unknown_minutes.len()
            + self.retained.len()
            + self.end_markers.len()
    }
}

const UPSERT_ROW: &str = "INSERT INTO observation(kind,key,value) VALUES(?1,?2,?3)
    ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value";

fn identity_key(record: &FlowRecord) -> String {
    // Existing Flow keys remain byte-for-byte stable across the upgrade.
    if record.blocked {
        format!("B:{}:{}:{}", record.generation, record.owner, record.slot)
    } else {
        format!("{}:{}:{}", record.generation, record.owner, record.slot)
    }
}

fn key_generation(key: &str) -> Option<u64> {
    let mut parts = key.split(':');
    let first = parts.next()?;
    (if first == "B" { parts.next()? } else { first }).parse().ok()
}

fn l4_key(id: u32) -> Option<&'static str> {
    match id {
        1 => Some("icmp"),
        6 => Some("tcp"),
        17 => Some("udp"),
        58 => Some("icmpv6"),
        _ => None,
    }
}

fn stage_protocol_window(
    existing: &BTreeMap<String, ProtocolWindow>,
    staged: &mut BTreeMap<String, ProtocolWindow>,
    minute: u64,
    attribution: &Attribution,
    layer: ProtocolLayer,
    protocol_id: u32,
    key: &str,
    contribution: &Counts,
) -> Result<(), String> {
    let window_key = format!("{minute:020}:{}:{}:{}:{protocol_id}",
        attribution.uid, attribution.actual_action, layer.key());
    let window = staged.entry(window_key.clone()).or_insert_with(|| {
        existing.get(&window_key).cloned().unwrap_or(ProtocolWindow {
            minute, uid: attribution.uid, actual_action: attribution.actual_action,
            layer, protocol_id, key: key.into(), counts: Counts::default(),
        })
    });
    if window.layer != layer || window.protocol_id != protocol_id || window.key != key
        || window.minute != minute || window.uid != attribution.uid
        || window.actual_action != attribution.actual_action {
        return Err("observation_protocol_reference_conflict".into());
    }
    window.counts.add(contribution)
}

fn protocol_share(counts: &Counts, denominator: &Counts) -> serde_json::Value {
    let ratio = |numerator: u64, total: u64| (total != 0).then(|| numerator as f64 / total as f64);
    serde_json::json!({
        "packets": [ratio(counts.packets[0], denominator.packets[0]),
                    ratio(counts.packets[1], denominator.packets[1])],
        "bytes": [ratio(counts.bytes[0], denominator.bytes[0]),
                  ratio(counts.bytes[1], denominator.bytes[1])],
    })
}

fn rule_interpretation(
    winner: u64,
    recorded_name: &str,
    names: &BTreeMap<u64, Option<String>>,
    actual_action: u8,
    proven: bool,
) -> serde_json::Value {
    if !proven {
        return serde_json::json!({"version": null, "name": null,
            "name_status": "unavailable", "actual_action": null,
            "conditions": {"status": "unavailable", "reason": "attribution_unavailable"}});
    }
    if winner == 0 {
        return serde_json::json!({"version": null, "name": null,
            "name_status": "not_applicable", "actual_action": actual_action,
            "conditions": {"status": "not_applicable"}});
    }
    let linked = names.get(&winner);
    let (name, status) = if !recorded_name.is_empty() {
        (Some(recorded_name), "recorded")
    } else if let Some(Some(name)) = linked {
        (Some(name.as_str()), "linked")
    } else if linked.is_some() {
        (None, "conflict")
    } else {
        (None, "unavailable")
    };
    serde_json::json!({"version": winner.to_string(),
        "logical_identity": format!("{:012x}", winner >> 16),
        "revision": winner & 65535, "name": name, "name_status": status,
        "actual_action": actual_action,
        "conditions": {"status": "unavailable", "reason": "matching_source_unavailable"}})
}

fn put_row(
    statement: &mut rusqlite::Statement<'_>,
    kind: i32,
    key: &str,
    value: &impl Serialize,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if key.len() > 192 || bytes.len() > 4096 {
        return Err("observation_row_capacity".into());
    }
    statement
        .execute(params![kind, key, bytes])
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn put_or_delete<T: Serialize>(
    tx: &rusqlite::Transaction<'_>,
    statement: &mut rusqlite::Statement<'_>,
    kind: i32,
    key: &str,
    value: Option<&T>,
) -> Result<(), String> {
    if let Some(value) = value {
        put_row(statement, kind, key, value)
    } else {
        tx.execute("DELETE FROM observation WHERE kind=?1 AND key=?2", params![kind, key])
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

pub struct ObservationStore {
    path: PathBuf,
    _lock: File,
    db: Connection,
    state: State,
    committed: Metadata,
    dirty: Dirty,
    last_flush: Instant,
    save_error: Option<String>,
    uncertain: bool,
    commits: u64,
    checkpoints: u64,
    wal_peak_bytes: u64,
    maintenance_pending: bool,
    retention_work_pending: bool,
    limits: RetentionLimits,
    scaled_test: bool,
    boot_id: String,
    uptime_at_open_us: u64,
    clock_origin_us: u64,
    clock_started: Instant,
    clock_held: bool,
    clock_candidate: Option<(u64, Instant)>,
    stale_generations_pending: bool,
}
impl ObservationStore {
    fn has_row(&self, kind: i32, key: &str) -> bool {
        match kind {
            1 => self.state.baselines.contains_key(key),
            2 => self.state.recent.contains_key(key),
            3 => key.parse::<u64>().ok().is_some_and(|key| self.state.minutes.contains_key(&key)),
            4 => self.state.applications.contains_key(key),
            5 => self.state.rules.contains_key(key),
            6 => key.parse::<u64>().ok().is_some_and(|key| self.state.unknown_minutes.contains_key(&key)),
            7 => self.state.protocols.contains_key(key),
            8 => key.parse::<u64>().ok().is_some_and(|key| self.state.rule_names.contains_key(&key)),
            19 => self.state.end_markers.contains_key(key),
            9..=18 => {
                let (set, base) = if kind < 14 { (&self.state.hours, 9) }
                    else { (&self.state.days, 14) };
                match kind - base {
                    0 => key.parse::<u64>().ok().is_some_and(|key| set.totals.contains_key(&key)),
                    1 => set.applications.contains_key(key),
                    2 => set.rules.contains_key(key),
                    3 => key.parse::<u64>().ok().is_some_and(|key| set.unknown.contains_key(&key)),
                    4 => set.protocols.contains_key(key),
                    _ => false,
                }
            }
            _ => false,
        }
    }

    fn deletion_rows(&self) -> Vec<(i32, String)> {
        let mut candidates = Vec::with_capacity(self.dirty.len());
        for key in &self.dirty.baselines { candidates.push((1, key.clone())); }
        for key in &self.dirty.recent { candidates.push((2, key.clone())); }
        for key in &self.dirty.minutes { candidates.push((3, key.to_string())); }
        for key in &self.dirty.applications { candidates.push((4, key.clone())); }
        for key in &self.dirty.rules { candidates.push((5, key.clone())); }
        for key in &self.dirty.unknown_minutes { candidates.push((6, key.to_string())); }
        for key in &self.dirty.protocols { candidates.push((7, key.clone())); }
        for key in &self.dirty.rule_names { candidates.push((8, key.to_string())); }
        candidates.extend(self.dirty.retained.iter().cloned());
        for key in &self.dirty.end_markers { candidates.push((19, key.clone())); }
        candidates.retain(|(kind, key)| !self.has_row(*kind, key));
        candidates
    }
    fn flush_rows(&self) -> usize {
        FLUSH_ROWS.min((self.limits.database_limit() / 4096) as usize).max(64)
    }
    fn next_tier_step_dirty_bound(&self, base: i32, start: u64, eviction: bool) -> usize {
        let (_, _, apps, _, protocols) = self.state.views(base);
        if let Some((_, app)) = first_at(apps, start) {
            let prefix = format!("{start:020}:{}:{}:", app.uid, app.actual_action);
            let protocols = protocols.range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
                .take(MAX_PROTOCOLS_PER_APP_BUCKET + 1).count();
            (1 + protocols) * if eviction { 1 } else { 2 }
        } else if eviction { 1 } else { 2 }
    }

    fn dirty_room_for(&self, additional: usize) -> bool {
        self.dirty.len().saturating_add(additional) <= MAX_DIRTY
    }
    fn discard_day_step(&mut self, start: u64) -> Result<bool, String> {
        let transition = RetentionTransition::EvictDay { start };
        if self.state.meta.transition.is_some_and(|current| current != transition) {
            return Err("observation_retention_transition_busy".into());
        }
        if self.state.meta.transition.is_none() {
            let total = *self.state.days.totals.get(&start)
                .ok_or("observation_eviction_missing_total")?;
            let unknown = self.state.days.unknown.get(&start).copied().unwrap_or_default();
            let attributed = total.difference(&unknown)?;
            self.state.meta.evicted.add(&total)?;
            self.state.meta.evicted_unknown.add(&unknown)?;
            self.state.meta.evicted_attributed.add(&attributed)?;
            self.state.meta.transition = Some(transition);
            self.dirty.meta = true;
        }
        let (_, _, apps, rules, protocols) = self.state.views(14);
        if let Some((key, app)) = first_at(apps, start) {
            let prefix = format!("{start:020}:{}:{}:", app.uid, app.actual_action);
            let protocol_rows: Vec<_> = protocols.range(prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&prefix))
                .take(MAX_PROTOCOLS_PER_APP_BUCKET + 1)
                .map(|(key, row)| (key.clone(), row.clone())).collect();
            if protocol_rows.len() > MAX_PROTOCOLS_PER_APP_BUCKET {
                return Err("observation_rollup_protocol_group_capacity".into());
            }
            let mut l4 = self.state.meta.evicted_l4;
            for (_, row) in &protocol_rows {
                if row.layer == ProtocolLayer::L4 { l4.add(&row.counts)?; }
            }
            {
                let (_, _, apps, _, protocols) = self.state.views_mut(14);
                apps.remove(&key);
                for (key, _) in &protocol_rows { protocols.remove(key); }
            }
            self.state.meta.evicted_l4 = l4;
            self.dirty.mark(15, &key);
            for (key, _) in protocol_rows { self.dirty.mark(18, &key); }
            return Ok(true);
        }
        if first_at(protocols, start).is_some() {
            return Err("observation_rollup_orphan_protocol".into());
        }
        if let Some((key, _)) = first_at(rules, start) {
            self.state.views_mut(14).3.remove(&key);
            self.dirty.mark(16, &key);
            return Ok(true);
        }
        let (totals, unknown, _, _, _) = self.state.views(14);
        if unknown.contains_key(&start) {
            self.state.views_mut(14).1.remove(&start);
            self.dirty.mark(17, &start.to_string());
            return Ok(true);
        }
        if totals.contains_key(&start) {
            self.state.views_mut(14).0.remove(&start);
            self.dirty.mark(14, &start.to_string());
            self.state.meta.transition = None;
            return Ok(true);
        }
        Ok(false)
    }
    fn rollup_step(&mut self, from: i32, to: i32, start: u64,
        divisor: u64) -> Result<bool, String> {
        let transition = RetentionTransition::Rollup { from, to, start };
        if self.state.meta.transition.is_some_and(|current| current != transition) {
            return Err("observation_retention_transition_busy".into());
        }
        if self.state.meta.transition.is_none() {
            self.state.meta.transition = Some(transition);
            self.dirty.meta = true;
        }
        let target_start = start / divisor * divisor;
        let (_, _, source_apps, source_rules, source_protocols) = self.state.views(from);
        if let Some((key, app)) = first_at(source_apps, start) {
            let source_prefix = format!("{start:020}:{}:{}:", app.uid, app.actual_action);
            let protocol_rows: Vec<_> = source_protocols.range(source_prefix.clone()..)
                .take_while(|(key, _)| key.starts_with(&source_prefix))
                .take(MAX_PROTOCOLS_PER_APP_BUCKET + 1)
                .map(|(key, row)| (key.clone(), row.clone())).collect();
            if protocol_rows.len() > MAX_PROTOCOLS_PER_APP_BUCKET {
                return Err("observation_rollup_protocol_group_capacity".into());
            }
            let target_key = rekey(target_start, &key);
            let (_, _, target_apps, _, target_protocols) = self.state.views(to);
            if target_apps.len() >= MAX_EFFECT_WINDOWS && !target_apps.contains_key(&target_key) {
                return Err("observation_rollup_target_capacity".into());
            }
            let target_app = merged_application(target_apps.get(&target_key), &app, target_start)?;
            let mut target_protocol_rows = Vec::with_capacity(protocol_rows.len());
            let mut added = 0;
            for (source_key, row) in &protocol_rows {
                let target_key = rekey(target_start, source_key);
                if !target_protocols.contains_key(&target_key) { added += 1; }
                let target_row = merged_protocol(target_protocols.get(&target_key), row, target_start)?;
                target_protocol_rows.push((source_key.clone(), target_key, target_row));
            }
            if target_protocols.len() + added > MAX_PROTOCOL_WINDOWS {
                return Err("observation_rollup_target_capacity".into());
            }
            {
                let (_, _, apps, _, protocols) = self.state.views_mut(to);
                apps.insert(target_key.clone(), target_app);
                for (_, key, row) in &target_protocol_rows { protocols.insert(key.clone(), row.clone()); }
            }
            self.dirty.mark(to + 1, &target_key);
            for (_, key, _) in &target_protocol_rows { self.dirty.mark(to + 4, key); }
            {
                let (_, _, apps, _, protocols) = self.state.views_mut(from);
                apps.remove(&key);
                for (key, _, _) in &target_protocol_rows { protocols.remove(key); }
            }
            self.dirty.mark(from + 1, &key);
            for (key, _, _) in target_protocol_rows { self.dirty.mark(from + 4, &key); }
            return Ok(true);
        }
        if first_at(source_protocols, start).is_some() {
            return Err("observation_rollup_orphan_protocol".into());
        }
        if let Some((key, rule)) = first_at(source_rules, start) {
            let target_key = rekey(target_start, &key);
            let (_, _, _, target_rules, _) = self.state.views(to);
            if target_rules.len() >= MAX_EFFECT_WINDOWS && !target_rules.contains_key(&target_key) {
                return Err("observation_rollup_target_capacity".into());
            }
            let target_row = merged_rule(target_rules.get(&target_key), &rule, target_start)?;
            self.state.views_mut(to).3.insert(target_key.clone(), target_row);
            self.state.views_mut(from).3.remove(&key);
            self.dirty.mark(to + 2, &target_key);
            self.dirty.mark(from + 2, &key);
            return Ok(true);
        }
        let (source_totals, source_unknown, _, _, _) = self.state.views(from);
        if let Some(&counts) = source_unknown.get(&start) {
            let (target_totals, target_unknown, _, _, _) = self.state.views(to);
            let _ = target_totals;
            if target_unknown.len() >= MAX_MINUTES && !target_unknown.contains_key(&target_start) {
                return Err("observation_rollup_target_capacity".into());
            }
            let mut target = target_unknown.get(&target_start).copied().unwrap_or_default();
            target.add(&counts)?;
            self.state.views_mut(to).1.insert(target_start, target);
            self.state.views_mut(from).1.remove(&start);
            self.dirty.mark(to + 3, &target_start.to_string());
            self.dirty.mark(from + 3, &start.to_string());
            return Ok(true);
        }
        if let Some(&counts) = source_totals.get(&start) {
            let (target_totals, _, _, _, _) = self.state.views(to);
            if target_totals.len() >= MAX_MINUTES && !target_totals.contains_key(&target_start) {
                return Err("observation_rollup_target_capacity".into());
            }
            let mut target = target_totals.get(&target_start).copied().unwrap_or_default();
            target.add(&counts)?;
            self.state.views_mut(to).0.insert(target_start, target);
            self.state.views_mut(from).0.remove(&start);
            self.dirty.mark(to, &target_start.to_string());
            self.dirty.mark(from, &start.to_string());
            self.state.meta.transition = None;
            return Ok(true);
        }
        Ok(false)
    }
    fn retire_old_generation_rows(&mut self, limit: usize) -> usize {
        let generation = self.state.meta.current_generation;
        if generation == 0 { self.stale_generations_pending = false; return 0; }
        let old_baselines: Vec<_> = self.state.baselines.iter()
            .filter(|(_, row)| row.record.generation != generation)
            .take(limit).map(|(key, _)| key.clone()).collect();
        let remaining = limit.saturating_sub(old_baselines.len());
        let old_markers: Vec<_> = self.state.end_markers.keys()
            .filter(|key| key_generation(key) != Some(generation))
            .take(remaining).cloned().collect();
        let count = old_baselines.len() + old_markers.len();
        for key in old_baselines {
            self.state.baselines.remove(&key);
            self.dirty.baselines.insert(key);
        }
        for key in old_markers {
            self.state.end_markers.remove(&key);
            self.dirty.end_markers.insert(key);
        }
        self.stale_generations_pending = self.state.baselines.values()
            .any(|row| row.record.generation != generation)
            || self.state.end_markers.keys().any(|key| key_generation(key) != Some(generation));
        if count != 0 { self.dirty.meta = true; }
        count
    }

    pub fn begin_generation(&mut self, generation: u64) -> Result<(), String> {
        if generation == 0 || generation < self.state.meta.current_generation {
            return Err("observation_generation_regression".into());
        }
        if generation == self.state.meta.current_generation { return Ok(()); }
        self.state.meta.current_generation = generation;
        self.dirty.meta = true;
        self.retire_old_generation_rows(RETENTION_ROWS_PER_BATCH);
        self.flush()
    }
    fn boot_clock() -> Option<(String, u64)> {
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
        let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
        let seconds = uptime.split_whitespace().next()?.parse::<f64>().ok()?;
        Some((boot_id.trim().to_owned(), (seconds * 1_000_000.0) as u64))
    }

    fn wall_now_us() -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_micros() as u64).unwrap_or(0)
    }

    fn safe_real_time(&mut self, wall_now_us: u64) -> u64 {
        if self.scaled_test { return wall_now_us; }
        let elapsed = self.clock_started.elapsed().as_micros() as u64;
        let authorized = self.clock_origin_us.saturating_add(elapsed);
        if wall_now_us > authorized.saturating_add(1_000_000) {
            self.clock_held = true;
            let stable = self.clock_candidate.as_ref().is_some_and(|(first_wall, first_at)| {
                first_at.elapsed() >= CLOCK_RECONCILE
                    && wall_now_us.abs_diff(first_wall.saturating_add(first_at.elapsed().as_micros() as u64))
                        <= 1_000_000
            });
            if stable {
                self.clock_origin_us = wall_now_us.saturating_sub(elapsed);
                self.clock_candidate = None;
                self.clock_held = false;
                return wall_now_us;
            }
            let reset = self.clock_candidate.as_ref().is_none_or(|(first_wall, first_at)|
                wall_now_us.abs_diff(first_wall.saturating_add(first_at.elapsed().as_micros() as u64))
                    > 1_000_000);
            if reset { self.clock_candidate = Some((wall_now_us, Instant::now())); }
            return authorized;
        }
        self.clock_candidate = None;
        self.clock_held = authorized > wall_now_us.saturating_add(1_000_000);
        wall_now_us
    }

    fn record_clock_anchor(&mut self) {
        if self.scaled_test { return; }
        self.state.meta.retention_boot_id = self.boot_id.clone();
        self.state.meta.retention_uptime_us = self.uptime_at_open_us
            .saturating_add(self.clock_started.elapsed().as_micros() as u64);
        self.dirty.meta = true;
    }

    pub fn consume_real(&mut self, records: &[FlowRecord], wall_now_us: u64) -> Result<(), String> {
        let safe_now = self.safe_real_time(wall_now_us);
        self.record_clock_anchor();
        self.consume(records, safe_now)
    }

    pub fn tick_real(&mut self, wall_now_us: u64) -> Result<(), String> {
        let safe_now = self.safe_real_time(wall_now_us);
        if safe_now >= self.state.meta.retention_watermark_us.saturating_add(MINUTE_US)
            || self.maintenance_pending {
            self.record_clock_anchor();
        }
        self.tick(safe_now)
    }
    fn record_save_error(&mut self, error: &str) {
        self.save_error = Some(error.to_owned());
        if !self.uncertain { self.mark_gap(); }
        self.uncertain = true;
    }
    fn space_pressure(&self) -> Result<bool, String> {
        let (_, actual) = self.owned_files()?;
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let free: i64 = self.db.query_row("PRAGMA freelist_count", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let max_pages = (self.limits.database_limit() / 4096) as i64;
        let warning_pages = max_pages - (max_pages / 10).max(1);
        let headroom = (64 * 1024).min(self.limits.budget_bytes / 16);
        Ok(actual.saturating_add(self.limits.working_reserve_bytes)
            > self.limits.budget_bytes.saturating_sub(headroom)
            || (pages >= warning_pages && free < 8))
    }

    fn retire_unused_names(&mut self) -> bool {
        let available = MAX_DIRTY.saturating_sub(self.dirty.len()).min(64);
        if available == 0 { return false; }
        let mut referenced = BTreeSet::new();
        for row in self.state.rules.values().chain(self.state.hours.rules.values())
            .chain(self.state.days.rules.values()) {
            referenced.insert(row.attribution.winner);
        }
        for row in self.state.baselines.values().filter(|row| !row.record.ended)
            .chain(self.state.recent.values()) {
            for a in &row.record.attribution {
                if a.valid && a.winner != 0 { referenced.insert(a.winner); }
            }
        }
        let candidates: Vec<_> = self.state.rule_names.keys()
            .filter(|version| !referenced.contains(version)).take(available).copied().collect();
        for version in &candidates {
            self.state.rule_names.remove(version);
            self.dirty.rule_names.insert(*version);
        }
        !candidates.is_empty()
    }

    fn reclaim_pressure(&mut self) -> Result<bool, String> {
        // Callers advance ordinary expiry first. Each pressure call then
        // changes only one bounded unit before the next write attempt.
        if self.stale_generations_pending && self.dirty.len() < MAX_DIRTY / 2 {
            self.retire_old_generation_rows(RETENTION_ROWS_PER_BATCH);
            return Ok(true);
        }
        // END detail can be reclaimed while a large tier transition is
        // partially staged. This gives a FULL retry space to commit the
        // transition without starting another tier transition.
        if let Some((key, _)) = self.state.recent.first_key_value() {
            if !self.dirty_room_for(3) { return Ok(false); }
            self.expire_recent(key.clone());
            return Ok(true);
        }
        if self.retire_unused_names() { return Ok(true); }
        if let Some(transition) = self.state.meta.transition {
            let bound = match transition {
                RetentionTransition::Rollup { from, start, .. } =>
                    self.next_tier_step_dirty_bound(from, start, false),
                RetentionTransition::EvictDay { start } =>
                    self.next_tier_step_dirty_bound(14, start, true),
            };
            if !self.dirty_room_for(bound) { return Ok(false); }
            return match transition {
                RetentionTransition::Rollup { from, to, start } =>
                    self.rollup_step(from, to, start, if to == 9 { 3600 } else { 86400 }),
                RetentionTransition::EvictDay { start } => self.discard_day_step(start),
            };
        }
        if let Some((&start, _)) = self.state.minutes.first_key_value() {
            if !self.dirty_room_for(self.next_tier_step_dirty_bound(3, start, false)) {
                return Ok(false);
            }
            return self.rollup_step(3, 9, start, 3600);
        }
        if let Some((&start, _)) = self.state.hours.totals.first_key_value() {
            if !self.dirty_room_for(self.next_tier_step_dirty_bound(9, start, false)) {
                return Ok(false);
            }
            return self.rollup_step(9, 14, start, 86400);
        }
        if let Some((&start, _)) = self.state.days.totals.first_key_value() {
            if !self.dirty_room_for(self.next_tier_step_dirty_bound(14, start, true)) {
                return Ok(false);
            }
            return self.discard_day_step(start);
        }
        Ok(false)
    }
    fn owned_files(&self) -> Result<(BTreeMap<String, u64>, u64), String> {
        let parent = self.path.parent().ok_or("observation_store_parent")?;
        let stem = self.path.file_name().unwrap().to_string_lossy().into_owned();
        let predecessor = self.path.with_extension("json").file_name().unwrap()
            .to_string_lossy().into_owned();
        let lock = self.path.with_extension("lock").file_name().unwrap()
            .to_string_lossy().into_owned();
        let test_config = self.path.with_extension("retention-test.json").file_name().unwrap()
            .to_string_lossy().into_owned();
        let mut files = BTreeMap::<String, u64>::new();
        let mut total = 0u64;
        let entries = std::fs::read_dir(parent).map_err(|e| e.to_string())?;
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name != predecessor && name != lock && name != test_config
                && !name.starts_with(&stem) { continue; }
            let metadata = entry.metadata().map_err(|e| e.to_string())?;
            if metadata.is_file() {
                total = total.saturating_add(metadata.len());
                files.insert(name, metadata.len());
            }
        }
        Ok((files, total))
    }

    fn storage_space(&self) -> serde_json::Value {
        let Ok((files, total)) = self.owned_files() else {
            return serde_json::json!({"error": "directory_unreadable"});
        };
        serde_json::json!({"files": files, "actual_bytes": total,
            "working_reserve_bytes": self.limits.working_reserve_bytes,
            "budget_bytes": self.limits.budget_bytes,
            "within_budget": total.saturating_add(self.limits.working_reserve_bytes)
                <= self.limits.budget_bytes})
    }

    fn projected_tier_query(&self, from: i32, to: i32, start: u64,
        target_start: u64) -> serde_json::Value {
        let target = if to == 9 { &self.state.hours } else { &self.state.days };
        let width = if to == 9 { 3600 } else { 86400 };
        let (source_totals, source_unknown, source_apps, source_rules, source_protocols) =
            self.state.views(from);
        let limit = if width == 3600 { MAX_QUERY_HOURS } else { MAX_QUERY_DAYS };
        let mut projected = WindowSet {
            totals: target.totals.iter().rev().take(limit).map(|(key, row)| (*key, *row)).collect(),
            unknown: target.unknown.iter().rev().take(limit).map(|(key, row)| (*key, *row)).collect(),
            applications: target.applications.iter().rev().take(limit)
                .map(|(key, row)| (key.clone(), row.clone())).collect(),
            rules: target.rules.iter().rev().take(limit)
                .map(|(key, row)| (key.clone(), row.clone())).collect(),
            protocols: target.protocols.iter().rev().take(limit)
                .map(|(key, row)| (key.clone(), row.clone())).collect(),
        };
        let source = WindowSet {
            totals: source_totals.get(&start).map(|counts|
                [(start, *counts)].into()).unwrap_or_default(),
            unknown: source_unknown.get(&start).map(|counts|
                [(start, *counts)].into()).unwrap_or_default(),
            applications: latest_rows_at(source_apps, start, limit),
            rules: latest_rows_at(source_rules, start, limit),
            protocols: latest_rows_at(source_protocols, start, limit),
        };
        projected.merge(&source, target_start).expect("validated rollup projection");
        // A visible protocol can have a less recent application key. Build
        // that one denominator from both physical tiers, without copying
        // either application's full map.
        let denominator_keys: BTreeSet<_> = projected.protocols.values().map(|row|
            (row.uid, row.actual_action)).collect();
        for (uid, action) in denominator_keys {
            let target_key = format!("{target_start:020}:{uid}:{action}");
            let source_key = format!("{start:020}:{uid}:{action}");
            let complete = if let Some(source_app) = source_apps.get(&source_key) {
                merged_application(target.applications.get(&target_key), source_app, target_start)
                    .expect("validated protocol denominator")
            } else {
                target.applications.get(&target_key).cloned()
                    .expect("validated protocol denominator")
            };
            projected.applications.insert(target_key, complete);
        }
        let overall_count = target.totals.len() + usize::from(source_totals.contains_key(&start))
            - usize::from(source_totals.contains_key(&start) && target.totals.contains_key(&target_start));
        let unknown_count = target.unknown.len() + usize::from(source_unknown.contains_key(&start))
            - usize::from(source_unknown.contains_key(&start) && target.unknown.contains_key(&target_start));
        let application_count = target.applications.len() + count_rows_at(source_apps, start)
            - overlapping_rows(source_apps, &target.applications, start, target_start);
        let rule_count = target.rules.len() + count_rows_at(source_rules, start)
            - overlapping_rows(source_rules, &target.rules, start, target_start);
        let protocol_count = target.protocols.len() + count_rows_at(source_protocols, start)
            - overlapping_rows(source_protocols, &target.protocols, start, target_start);
        let mut response = projected.query(&self.state.rule_names, width, None);
        response["counts"] = serde_json::json!({"overall":overall_count,
            "attribution_unknown":unknown_count,"applications":application_count,
            "rules":rule_count,"protocols":protocol_count});
        response["truncated"] = (overall_count > limit || unknown_count > limit
            || application_count > limit || rule_count > limit || protocol_count > limit).into();
        response
    }
    fn expire_recent(&mut self, key: String) {
        if let Some(ended) = self.state.recent.remove(&key) {
            self.dirty.recent.insert(key);
            let id = identity_key(&ended.record);
            if self.state.baselines.get(&id).is_some_and(|baseline|
                baseline.record.ended && baseline.record.incarnation == ended.record.incarnation) {
                self.state.baselines.remove(&id);
                self.dirty.baselines.insert(id.clone());
                self.state.end_markers.insert(id.clone(), EndMarker {
                    incarnation: ended.record.incarnation,
                });
                self.dirty.end_markers.insert(id);
            }
            self.dirty.meta = true;
        }
    }

    fn retention_due(&self) -> bool {
        let now = self.state.meta.retention_watermark_us;
        self.stale_generations_pending || self.state.meta.transition.is_some()
            || self.state.recent.first_key_value().is_some_and(|(_, row)|
            row.first_end_us.is_some_and(|at| now.saturating_sub(at) >= self.limits.end_age_us))
            || self.state.minutes.first_key_value().is_some_and(|(&at, _)|
                bucket_expired(now, at, 60, self.limits.minute_age_us))
            || self.state.hours.totals.first_key_value().is_some_and(|(&at, _)|
                bucket_expired(now, at, 3600, self.limits.hour_age_us))
            || self.state.days.totals.first_key_value().is_some_and(|(&at, _)|
                bucket_expired(now, at, 86400, self.limits.day_age_us))
    }

    fn advance_retention(&mut self, received_us: u64) -> Result<(), String> {
        let now = self.state.meta.retention_watermark_us.max(received_us);
        if now != self.state.meta.retention_watermark_us {
            self.state.meta.retention_watermark_us = now;
            self.dirty.meta = true;
        }
        if self.stale_generations_pending && self.dirty.len() < MAX_DIRTY / 2 {
            self.retire_old_generation_rows(RETENTION_ROWS_PER_BATCH);
        }
        let mut work = 0;
        let mut dropped_day = false;
        while work < RETENTION_ROWS_PER_BATCH && self.dirty.len() < MAX_DIRTY / 2 {
            if let Some(transition) = self.state.meta.transition {
                match transition {
                    RetentionTransition::Rollup { from, to, start } => {
                        self.rollup_step(from, to, start, if to == 9 { 3600 } else { 86400 })?;
                    }
                    RetentionTransition::EvictDay { start } => {
                        self.discard_day_step(start)?;
                        dropped_day = true;
                    }
                }
            } else if let Some((key, _)) = self.state.recent.first_key_value().filter(|(_, row)|
                row.first_end_us.is_some_and(|at| now.saturating_sub(at) >= self.limits.end_age_us)) {
                self.expire_recent(key.clone());
            } else if let Some((&start, _)) = self.state.minutes.first_key_value().filter(|(&at, _)|
                bucket_expired(now, at, 60, self.limits.minute_age_us)) {
                self.rollup_step(3, 9, start, 3600)?;
            } else if let Some((&start, _)) = self.state.hours.totals.first_key_value().filter(|(&at, _)|
                bucket_expired(now, at, 3600, self.limits.hour_age_us)) {
                self.rollup_step(9, 14, start, 86400)?;
            } else if let Some((&start, _)) = self.state.days.totals.first_key_value().filter(|(&at, _)|
                bucket_expired(now, at, 86400, self.limits.day_age_us)) {
                self.discard_day_step(start)?;
                dropped_day = true;
            } else {
                break;
            }
            work += 1;
        }
        if dropped_day { self.retire_unused_names(); }
        if work != 0 { self.retention_work_pending = true; }
        self.maintenance_pending = self.retention_due();
        Ok(())
    }

    pub fn open(path: &Path) -> Result<Self, String> {
        let (limits, scaled_test) = RetentionLimits::load(path)?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        match std::fs::create_dir(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && parent.is_dir() => {}
            Err(e) => return Err(e.to_string()),
        }
        let containing = parent
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(containing)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path.with_extension("lock"))
            .map_err(|e| e.to_string())?;
        if unsafe { flock(lock.as_raw_fd(), 2 | 4) } != 0 {
            return Err("observation_store_busy".into());
        }
        // Keep the legacy input path stable at the ABI boundary. SQLite is a
        // sibling file; a committed metadata row is the migration marker.
        let database = path.with_extension("sqlite3");
        OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o600)
            .open(&database)
            .map_err(|e| e.to_string())?;
        if std::fs::metadata(&database)
            .map_err(|e| e.to_string())?
            .len()
            > limits.database_limit()
        {
            return Err("observation_database_capacity".into());
        }
        let db = Connection::open(&database).map_err(|e| e.to_string())?;
        db.busy_timeout(Duration::ZERO).map_err(|e| e.to_string())?;
        db.execute_batch(
            "PRAGMA page_size=4096; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;
            PRAGMA synchronous=FULL; PRAGMA auto_vacuum=FULL; PRAGMA cache_spill=OFF;
            CREATE TABLE IF NOT EXISTS observation (kind INTEGER NOT NULL, key TEXT NOT NULL,
              value BLOB NOT NULL, PRIMARY KEY(kind,key)) WITHOUT ROWID;",
        )
        .map_err(|e| e.to_string())?;
        let max_pages = (limits.database_limit() / 4096) as i64;
        db.pragma_update(None, "max_page_count", max_pages).map_err(|e| e.to_string())?;
        let page_size: i64 = db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let oversized: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM observation WHERE length(key)>192 OR length(value)>4096)", [], |r| r.get(0)).map_err(|e| e.to_string())?;
        if page_size != 4096 || oversized {
            return Err("observation_store_bounds".into());
        }
        let meta: Option<Vec<u8>> = db
            .query_row(
                "SELECT value FROM observation WHERE kind=0 AND key=''",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let mut state = if let Some(ref meta) = meta {
            let mut state = State {
                meta: serde_json::from_slice(&meta).map_err(|e| e.to_string())?,
                ..State::default()
            };
            let mut statement = db
                .prepare("SELECT kind,key,value FROM observation WHERE kind<>0")
                .map_err(|e| e.to_string())?;
            let mut rows = statement.query([]).map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let kind: i32 = row.get(0).map_err(|e| e.to_string())?;
                let key: String = row.get(1).map_err(|e| e.to_string())?;
                let bytes: Vec<u8> = row.get(2).map_err(|e| e.to_string())?;
                match kind {
                    1 => {
                        state.baselines.insert(
                            key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    2 => {
                        state.recent.insert(
                            key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    3 => {
                        state.minutes.insert(
                            key.parse::<u64>().map_err(|e| e.to_string())?,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    4 => {
                        state.applications.insert(
                            key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    5 => {
                        state.rules.insert(
                            key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    6 => {
                        state.unknown_minutes.insert(
                            key.parse::<u64>().map_err(|e| e.to_string())?,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    7 => {
                        state.protocols.insert(
                            key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    8 => {
                        state.rule_names.insert(
                            key.parse::<u64>().map_err(|e| e.to_string())?,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?,
                        );
                    }
                    9 | 14 => {
                        let target = if kind == 9 { &mut state.hours } else { &mut state.days };
                        target.totals.insert(key.parse::<u64>().map_err(|e| e.to_string())?,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
                    }
                    10 | 15 => {
                        let target = if kind == 10 { &mut state.hours } else { &mut state.days };
                        target.applications.insert(key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
                    }
                    11 | 16 => {
                        let target = if kind == 11 { &mut state.hours } else { &mut state.days };
                        target.rules.insert(key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
                    }
                    12 | 17 => {
                        let target = if kind == 12 { &mut state.hours } else { &mut state.days };
                        target.unknown.insert(key.parse::<u64>().map_err(|e| e.to_string())?,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
                    }
                    13 | 18 => {
                        let target = if kind == 13 { &mut state.hours } else { &mut state.days };
                        target.protocols.insert(key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
                    }
                    19 => {
                        state.end_markers.insert(key,
                            serde_json::from_slice(&bytes).map_err(|e| e.to_string())?);
                    }
                    _ => return Err("observation_store_schema".into()),
                }
                Self::validate_bounds(&state)?;
            }
            state
        } else {
            let existing: i64 = db
                .query_row("SELECT count(*) FROM observation", [], |r| r.get(0))
                .map_err(|e| e.to_string())?;
            if existing != 0 {
                return Err("observation_missing_metadata".into());
            }
            match File::open(path) {
                Ok(file) => {
                    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_SNAPSHOT {
                        return Err("observation_snapshot_too_large".into());
                    }
                    let mut bytes = Vec::new();
                    file.take(MAX_SNAPSHOT + 1)
                        .read_to_end(&mut bytes)
                        .map_err(|e| e.to_string())?;
                    if bytes.len() as u64 > MAX_SNAPSHOT {
                        return Err("observation_snapshot_too_large".into());
                    }
                    serde_json::from_slice(&bytes)
                        .map_err(|e| format!("observation_store_corrupt:{e}"))?
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
                Err(e) => return Err(e.to_string()),
            }
        };
        if state.meta.evicted_attributed.packets == [0; 2]
            && state.meta.evicted_attributed.bytes == [0; 2]
            && (state.meta.evicted.packets != [0; 2] || state.meta.evicted.bytes != [0; 2]) {
            state.meta.evicted_attributed = state.meta.evicted.difference(&state.meta.evicted_unknown)?;
        }
        Self::validate_state(&state)?;
        if state.meta.attribution_schema == 0 {
            // Earlier committed history has no directional provenance. Preserve
            // every total without guessing from its latest winner or config.
            state.meta.attribution_unknown = state.meta.totals;
            state.meta.legacy_unattributed = state.meta.totals;
            state.meta.attribution_schema = 1;
        }
        if state.meta.protocol_schema == 0 {
            // V4 and earlier records cannot prove which labels covered their
            // historical increments. Preserve totals and mark that boundary.
            state.meta.legacy_protocol_unavailable = state.meta.totals;
            state.meta.l4_unknown = state.meta.totals;
            state.meta.l7_unknown = state.meta.totals;
            state.meta.protocol_schema = 1;
        }
        let (boot_id, uptime_at_open_us) = Self::boot_clock().unwrap_or_default();
        let clock_origin_us = if state.meta.retention_watermark_us != 0 {
            let downtime = if !boot_id.is_empty()
                && state.meta.retention_boot_id == boot_id
                && uptime_at_open_us >= state.meta.retention_uptime_us {
                uptime_at_open_us - state.meta.retention_uptime_us
            } else { 0 };
            state.meta.retention_watermark_us.saturating_add(downtime)
        } else {
            state.meta.last_activity_us.unwrap_or_else(Self::wall_now_us)
        };
        let stale_generations_pending = state.meta.current_generation != 0
            && (state.baselines.values().any(|row|
                row.record.generation != state.meta.current_generation)
                || state.end_markers.keys().any(|key|
                    key_generation(key) != Some(state.meta.current_generation)));
        let mut store = Self {
            path: database,
            _lock: lock,
            db,
            committed: state.meta.clone(),
            state,
            dirty: Dirty::default(),
            last_flush: Instant::now(),
            save_error: None,
            uncertain: false,
            commits: 0,
            checkpoints: 0,
            wal_peak_bytes: 0,
            maintenance_pending: false,
            retention_work_pending: false,
            limits,
            scaled_test,
            boot_id,
            uptime_at_open_us,
            clock_origin_us,
            clock_started: Instant::now(),
            clock_held: false,
            clock_candidate: None,
            stale_generations_pending,
        };
        if meta.is_none() {
            store.migrate()?;
        }
        let vacuum_mode: i64 = store.db.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if vacuum_mode != 1 {
            store.db.execute_batch("PRAGMA auto_vacuum=FULL; VACUUM;")
                .map_err(|e| e.to_string())?;
        }
        store.db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; PRAGMA journal_size_limit=0;")
            .map_err(|e| e.to_string())?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
        if store.state.meta.open_session {
            store.state.meta.recoveries = store.state.meta.recoveries.saturating_add(1);
            store.state.meta.gaps = store.state.meta.gaps.saturating_add(1);
        }
        store.state.meta.open_session = true;
        store.dirty.meta = true;
        store.flush()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<(), String> {
        // The import transaction walks the bounded live state directly. It
        // does not expand the normal 4096-key dirty set to all historical rows.
        let tx = self.db.transaction().map_err(|e| e.to_string())?;
        {
            let mut put = tx.prepare_cached(UPSERT_ROW).map_err(|e| e.to_string())?;
            for (key, value) in &self.state.baselines {
                put_row(&mut put, 1, key, value)?;
            }
            for (key, value) in &self.state.recent {
                put_row(&mut put, 2, key, value)?;
            }
            for (key, value) in &self.state.minutes {
                put_row(&mut put, 3, &key.to_string(), value)?;
            }
            for (key, value) in &self.state.applications {
                put_row(&mut put, 4, key, value)?;
            }
            for (key, value) in &self.state.rules {
                put_row(&mut put, 5, key, value)?;
            }
            for (key, value) in &self.state.unknown_minutes {
                put_row(&mut put, 6, &key.to_string(), value)?;
            }
            for (key, value) in &self.state.protocols {
                put_row(&mut put, 7, key, value)?;
            }
            for (key, value) in &self.state.rule_names {
                put_row(&mut put, 8, &key.to_string(), value)?;
            }
            for (base, set) in [(9, &self.state.hours), (14, &self.state.days)] {
                for (key, value) in &set.totals { put_row(&mut put, base, &key.to_string(), value)?; }
                for (key, value) in &set.applications { put_row(&mut put, base + 1, key, value)?; }
                for (key, value) in &set.rules { put_row(&mut put, base + 2, key, value)?; }
                for (key, value) in &set.unknown { put_row(&mut put, base + 3, &key.to_string(), value)?; }
                for (key, value) in &set.protocols { put_row(&mut put, base + 4, key, value)?; }
            }
            for (key, value) in &self.state.end_markers {
                put_row(&mut put, 19, key, value)?;
            }
            put_row(&mut put, 0, "", &self.state.meta)?;
        }
        let count: i64 = tx
            .query_row("SELECT count(*) FROM observation", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let meta: Vec<u8> = tx
            .query_row(
                "SELECT value FROM observation WHERE kind=0 AND key=''",
                [],
                |r| r.get(0),
            )
            .map_err(|e| e.to_string())?;
        let integrity: String = tx
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if count as usize
            != 1 + self.state.baselines.len()
                + self.state.recent.len()
                + self.state.minutes.len()
                + self.state.applications.len()
                + self.state.rules.len()
                + self.state.unknown_minutes.len()
                + self.state.protocols.len()
                + self.state.rule_names.len()
                + [&self.state.hours, &self.state.days].iter().map(|set|
                    set.totals.len() + set.applications.len() + set.rules.len()
                        + set.unknown.len() + set.protocols.len()).sum::<usize>()
                + self.state.end_markers.len()
            || meta != serde_json::to_vec(&self.state.meta).map_err(|e| e.to_string())?
            || integrity != "ok"
        {
            return Err("observation_migration_verification".into());
        }
        tx.commit().map_err(|e| e.to_string())?;
        self.committed = self.state.meta.clone();
        self.commits += 1;
        Ok(())
    }

    fn validate_bounds(state: &State) -> Result<(), String> {
        if state.meta.schema != 1 {
            return Err("observation_store_schema".into());
        }
        if state.baselines.len() > MAX_BASELINES
            || state.recent.len() > MAX_RECENT
            || state.minutes.len() > MAX_MINUTES
            || state.unknown_minutes.len() > MAX_MINUTES
            || state.applications.len() > MAX_EFFECT_WINDOWS
            || state.rules.len() > MAX_EFFECT_WINDOWS
            || state.protocols.len() > MAX_PROTOCOL_WINDOWS
            || state.rule_names.len() > MAX_RULE_NAMES
            || state.end_markers.len() > MAX_END_MARKERS
            || [&state.hours, &state.days].iter().any(|set|
                set.totals.len() > MAX_MINUTES || set.unknown.len() > MAX_MINUTES
                    || set.applications.len() > MAX_EFFECT_WINDOWS
                    || set.rules.len() > MAX_EFFECT_WINDOWS
                    || set.protocols.len() > MAX_PROTOCOL_WINDOWS)
        {
            return Err("observation_state_capacity".into());
        }
        Ok(())
    }

    fn validate_state(state: &State) -> Result<(), String> {
        Self::validate_bounds(state)?;
        let hidden_day = match state.meta.transition {
            Some(RetentionTransition::EvictDay { start }) => Some(start),
            _ => None,
        };
        let mut totals = Counts::default();
        for (minute, counts) in &state.minutes {
            if minute % 60 != 0 {
                return Err("observation_invalid_minute".into());
            }
            totals.add(counts)?;
        }
        for (set, width) in [(&state.hours, 3600), (&state.days, 86400)] {
            for (start, counts) in &set.totals {
                if start % width != 0 { return Err("observation_invalid_rollup_time".into()); }
                if width == 86400 && hidden_day == Some(*start) { continue; }
                totals.add(counts)?;
            }
        }
        totals.add(&state.meta.evicted)?;
        if totals.packets != state.meta.totals.packets || totals.bytes != state.meta.totals.bytes {
            return Err("observation_inconsistent_totals".into());
        }
        if state.meta.blocked_ended > state.meta.ended
            || (0..2).any(|side| {
                state.meta.blocked_totals.packets[side] > totals.packets[side]
                    || state.meta.blocked_totals.bytes[side] > totals.bytes[side]
            })
        {
            return Err("observation_inconsistent_blocked_totals".into());
        }
        if state.meta.attribution_schema > 1 {
            return Err("observation_attribution_schema".into());
        }
        for (&version, name) in &state.rule_names {
            if version >> 16 == 0 || version & 65535 == 0
                || name.as_ref().is_some_and(|n| n.is_empty() || n.len() > 63 || n.as_bytes().contains(&0))
            {
                return Err("observation_invalid_rule_metadata".into());
            }
        }
        if state.meta.attribution_schema == 1 {
            let mut attributed = state.meta.attribution_unknown;
            for window in state.applications.values() {
                if window.minute % 60 != 0 || !(1..=3).contains(&window.actual_action) {
                    return Err("observation_invalid_application_window".into());
                }
                attributed.add(&window.counts)?;
            }
            for (set, width) in [(&state.hours, 3600), (&state.days, 86400)] {
                for window in set.applications.values() {
                    if window.minute % width != 0 || !(1..=3).contains(&window.actual_action) {
                        return Err("observation_invalid_application_window".into());
                    }
                    if width != 86400 || hidden_day != Some(window.minute) {
                        attributed.add(&window.counts)?;
                    }
                }
            }
            attributed.add(&state.meta.evicted_attributed)?;
            if attributed.packets != totals.packets || attributed.bytes != totals.bytes {
                return Err("observation_inconsistent_attribution".into());
            }
            let mut unknown = state.meta.legacy_unattributed;
            for (minute, counts) in &state.unknown_minutes {
                if minute % 60 != 0 {
                    return Err("observation_invalid_minute".into());
                }
                unknown.add(counts)?;
            }
            for (set, width) in [(&state.hours, 3600), (&state.days, 86400)] {
                for (start, counts) in &set.unknown {
                    if width != 86400 || hidden_day != Some(*start) { unknown.add(counts)?; }
                }
            }
            unknown.add(&state.meta.evicted_unknown)?;
            if unknown.packets != state.meta.attribution_unknown.packets
                || unknown.bytes != state.meta.attribution_unknown.bytes
            {
                return Err("observation_inconsistent_unknown".into());
            }
            for window in state.rules.values() {
                if window.minute % 60 != 0
                    || window.attribution.winner == 0
                    || window.attribution.name.len() > 63
                {
                    return Err("observation_invalid_rule_window".into());
                }
            }
            for (set, width) in [(&state.hours, 3600), (&state.days, 86400)] {
                for window in set.rules.values() {
                    if window.minute % width != 0 || window.attribution.winner == 0
                        || window.attribution.name.len() > 63 {
                        return Err("observation_invalid_rule_window".into());
                    }
                }
            }
        } else if !state.applications.is_empty()
            || !state.rules.is_empty()
            || !state.unknown_minutes.is_empty()
        {
            return Err("observation_attribution_schema".into());
        }
        if state.meta.protocol_schema > 1 {
            return Err("observation_protocol_schema".into());
        }
        if state.meta.protocol_schema == 0 {
            if !state.protocols.is_empty() {
                return Err("observation_protocol_schema".into());
            }
        } else {
            let mut l4 = state.meta.l4_unknown;
            for (row_key, window) in &state.protocols {
                if window.minute % 60 != 0 || !(1..=3).contains(&window.actual_action) {
                    return Err("observation_invalid_protocol_window".into());
                }
                if row_key != &format!("{:020}:{}:{}:{}:{}", window.minute, window.uid,
                    window.actual_action, window.layer.key(), window.protocol_id) {
                    return Err("observation_invalid_protocol_window".into());
                }
                let app_key = format!("{:020}:{}:{}", window.minute, window.uid, window.actual_action);
                let Some(app) = state.applications.get(&app_key) else {
                    return Err("observation_protocol_without_application".into());
                };
                if (0..2).any(|side| window.counts.packets[side] > app.counts.packets[side]
                    || window.counts.bytes[side] > app.counts.bytes[side]) {
                    return Err("observation_protocol_exceeds_application".into());
                }
                match window.layer {
                    ProtocolLayer::L4 if l4_key(window.protocol_id) == Some(window.key.as_str()) => {
                        l4.add(&window.counts)?;
                    }
                    ProtocolLayer::L7 if historical_protocol_label(window.protocol_id)
                        == Some(window.key.as_str()) => {}
                    ProtocolLayer::L7None | ProtocolLayer::L7Unavailable
                        if window.protocol_id == 0 && window.key.is_empty() => {}
                    _ => return Err("observation_invalid_protocol_window".into()),
                }
            }
            for (set, width) in [(&state.hours, 3600), (&state.days, 86400)] {
                for (row_key, window) in &set.protocols {
                    if window.minute % width != 0 || !(1..=3).contains(&window.actual_action)
                        || row_key != &format!("{:020}:{}:{}:{}:{}", window.minute,
                            window.uid, window.actual_action, window.layer.key(), window.protocol_id) {
                        return Err("observation_invalid_protocol_window".into());
                    }
                    let app_key = format!("{:020}:{}:{}", window.minute, window.uid, window.actual_action);
                    let Some(app) = set.applications.get(&app_key) else {
                        return Err("observation_protocol_without_application".into());
                    };
                    if (0..2).any(|side| window.counts.packets[side] > app.counts.packets[side]
                        || window.counts.bytes[side] > app.counts.bytes[side]) {
                        return Err("observation_protocol_exceeds_application".into());
                    }
                    if width == 86400 && hidden_day == Some(window.minute) { continue; }
                    match window.layer {
                        ProtocolLayer::L4 if l4_key(window.protocol_id) == Some(window.key.as_str()) => l4.add(&window.counts)?,
                        ProtocolLayer::L7 if historical_protocol_label(window.protocol_id) == Some(window.key.as_str()) => {},
                        ProtocolLayer::L7None | ProtocolLayer::L7Unavailable
                            if window.protocol_id == 0 && window.key.is_empty() => {},
                        _ => return Err("observation_invalid_protocol_window".into()),
                    }
                }
            }
            l4.add(&state.meta.evicted_l4)?;
            if (hidden_day.is_none() && (l4.packets != totals.packets || l4.bytes != totals.bytes))
                || (0..2).any(|side| state.meta.l7_unknown.packets[side] > totals.packets[side]
                    || state.meta.l7_unknown.bytes[side] > totals.bytes[side]) {
                return Err("observation_inconsistent_protocol".into());
            }
        }
        for (key, baseline) in &state.baselines {
            let r = &baseline.record;
            if key != &identity_key(r)
                || !Self::valid_record(r)
                || Self::validate_segments(r, None).is_err()
                || baseline.first_end_us.is_some() != r.ended
            {
                return Err("observation_invalid_baseline".into());
            }
        }
        for (key, baseline) in &state.recent {
            let r = &baseline.record;
            let Some(first) = baseline.first_end_us else {
                return Err("observation_invalid_lifecycle".into());
            };
            if !r.ended
                || !Self::valid_record(r)
                || key != &format!("{first:020}:{}:{}", identity_key(r), r.incarnation)
            {
                return Err("observation_invalid_lifecycle".into());
            }
        }
        for (key, marker) in &state.end_markers {
            if marker.incarnation == 0 || state.baselines.contains_key(key) {
                return Err("observation_invalid_end_marker".into());
            }
        }
        Ok(())
    }

    fn valid_attribution(a: &Attribution, packets: u64, bytes: u64) -> bool {
        !a.valid
            || (a.segment != 0
                && a.activity_utc_us != 0
                && a.policy_generation != 0
                && a.policy_revision != 0
                && a.policy_hash != 0
                && a.start_packets <= packets
                && a.start_bytes <= bytes
                && a.name.len() <= 63
                && !a.name.as_bytes().contains(&0)
                && (1..=2).contains(&a.declared_action)
                && (1..=3).contains(&a.actual_action)
                && a.mode <= 1
                && (a.actual_action == 3
                    || a.actual_action == if a.mode == 1 { 1 } else { a.declared_action })
                && (a.winner != 0 || (a.name.is_empty() && a.mode == 0 && a.declared_action == 1)))
    }

    fn validate_segments(record: &FlowRecord, previous: Option<&FlowRecord>) -> Result<(), String> {
        for side in 0..2 {
            let a = &record.attribution[side];
            if !Self::valid_attribution(a, record.packets[side], record.bytes[side]) {
                return Err("observation_invalid_segment".into());
            }
            if let Some(old) = previous.filter(|p| p.incarnation == record.incarnation) {
                let b = &old.attribution[side];
                if a.valid
                    && b.valid
                    && (a.segment < b.segment
                        || (a.segment == b.segment
                            && (a.start_packets != b.start_packets
                                || a.start_bytes != b.start_bytes
                                || RuleReference::from(a) != RuleReference::from(b)
                                || a.protocol_set != b.protocol_set
                                || a.protocols_available != b.protocols_available))
                        || (a.segment > b.segment
                            && (a.start_packets < old.packets[side]
                                || a.start_bytes < old.bytes[side])))
                {
                    return Err("observation_inconsistent_segment".into());
                }
            }
        }
        Ok(())
    }

    fn valid_record(record: &FlowRecord) -> bool {
        record.generation != 0
            && record.incarnation != 0
            && record.sequence != 0
            && record.owner < 2
            && record.slot < 65536
            && record.kind_attribution_valid()
            && record.attribution.iter().all(|a| (a.protocols_available || a.protocol_set == 0)
                && (!record.blocked || (!a.protocols_available && a.protocol_set == 0)))
            && record.last_seen >= record.first_seen
            && record.activity_utc_us != 0
            && record.addresses.len() <= 32
            && record
                .attribution
                .iter()
                .all(|a| a.name.len() <= 63 && !a.name.as_bytes().contains(&0))
    }

    fn valid_current_record(record: &FlowRecord) -> bool {
        Self::valid_record(record)
            && record.attribution.iter().all(|a| a.protocol_set & !protocol_mask() == 0)
    }

    pub fn has_pending(&self) -> bool {
        self.dirty.meta || self.dirty.len() != 0 || self.maintenance_pending
    }

    pub fn wait_timeout_ms(&self) -> i32 {
        if !self.has_pending() {
            return (MINUTE_US / 1000) as i32;
        }
        FLUSH_INTERVAL
            .saturating_sub(self.last_flush.elapsed())
            .as_millis()
            .max(1) as i32
    }

    pub fn tick(&mut self, now_us: u64) -> Result<(), String> {
        let now = now_us.saturating_add(self.limits.clock_offset_us);
        if now >= self.state.meta.retention_watermark_us.saturating_add(MINUTE_US)
            || self.maintenance_pending {
            if let Err(error) = self.advance_retention(now) {
                self.record_save_error(&error);
                return Err(error);
            }
        }
        if self.has_pending() && self.last_flush.elapsed() >= FLUSH_INTERVAL {
            self.flush()?;
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), String> {
        self.last_flush = Instant::now();
        let result = self.flush_inner();
        match &result {
            Ok(()) => {
                self.save_error = None;
                self.uncertain = false;
            }
            Err(error) => self.record_save_error(error),
        }
        result
    }

    fn flush_inner(&mut self) -> Result<(), String> {
        self.advance_retention(self.state.meta.retention_watermark_us)?;
        let pressured = self.space_pressure()?;
        if pressured && !self.retention_work_pending {
            let reclaimed = self.reclaim_pressure()?;
            // Finish the one bucket already selected for promotion. A fresh
            // pressure decision follows this commit and checkpoint, when
            // auto-vacuum has made the actual freed pages measurable.
            for _ in 0..RETENTION_ROWS_PER_BATCH {
                let Some(transition) = self.state.meta.transition else { break; };
                let bound = match transition {
                    RetentionTransition::Rollup { from, start, .. } =>
                        self.next_tier_step_dirty_bound(from, start, false),
                    RetentionTransition::EvictDay { start } =>
                        self.next_tier_step_dirty_bound(14, start, true),
                };
                if !self.dirty_room_for(bound) { break; }
                match transition {
                    RetentionTransition::Rollup { from, to, start } => {
                        self.rollup_step(from, to, start, if to == 9 { 3600 } else { 86400 })?;
                    }
                    RetentionTransition::EvictDay { start } => {
                        self.discard_day_step(start)?;
                    }
                }
            }
            if !reclaimed && self.dirty.len() == 0 {
                return Err("observation_storage_budget_exhausted".into());
            }
        }
        if !self.has_pending() {
            return Ok(());
        }
        let result = if !self.dirty.meta && self.dirty.len() == 0 {
            self.checkpoint()
        } else {
            let mut write = self.write_dirty();
            for _ in 0..FULL_RECLAIM_ATTEMPTS {
                if !matches!(&write, Err(error) if error.contains("full")) { break; }
                // A failed expiry write cannot be measured after commit yet.
                // Make bounded space in this same transaction, with the
                // already staged age work still preceding pressure work.
                let mut reclaimed = false;
                for _ in 0..8 {
                    if !self.reclaim_pressure()? { break; }
                    reclaimed = true;
                }
                if !reclaimed { break; }
                write = self.write_dirty();
            }
            write.and_then(|()| {
                // FULL synchronous COMMIT already succeeded. A later checkpoint
                // failure must not report these contributions as uncommitted.
                self.record_wal_size();
                self.committed = self.state.meta.clone();
                self.dirty = Dirty::default();
                self.retention_work_pending = false;
                self.commits += 1;
                self.checkpoint()
            })
        };
        result
    }

    fn write_dirty(&mut self) -> Result<(), String> {
        if std::fs::metadata(format!("{}-wal", self.path.display())).map_or(0, |m| m.len())
            >= WAL_LIMIT
        {
            self.checkpoint()?;
        }
        let deletes = self.deletion_rows();
        let tx = self.db.transaction().map_err(|e| e.to_string())?;
        for (kind, key) in deletes {
            tx.execute("DELETE FROM observation WHERE kind=?1 AND key=?2", params![kind, key])
                .map_err(|e| e.to_string())?;
        }
        {
            let mut put = tx.prepare_cached(UPSERT_ROW).map_err(|e| e.to_string())?;
            for key in &self.dirty.baselines {
                put_or_delete(&tx, &mut put, 1, key, self.state.baselines.get(key))?;
            }
            for key in &self.dirty.recent {
                if let Some(value) = self.state.recent.get(key) {
                    put_row(&mut put, 2, key, value)?;
                } else {
                    tx.execute("DELETE FROM observation WHERE kind=2 AND key=?1", [key])
                        .map_err(|e| e.to_string())?;
                }
            }
            for key in &self.dirty.minutes {
                put_or_delete(&tx, &mut put, 3, &key.to_string(), self.state.minutes.get(key))?;
            }
            for key in &self.dirty.applications {
                put_or_delete(&tx, &mut put, 4, key, self.state.applications.get(key))?;
            }
            for key in &self.dirty.rules {
                put_or_delete(&tx, &mut put, 5, key, self.state.rules.get(key))?;
            }
            for key in &self.dirty.unknown_minutes {
                put_or_delete(&tx, &mut put, 6, &key.to_string(), self.state.unknown_minutes.get(key))?;
            }
            for key in &self.dirty.protocols {
                put_or_delete(&tx, &mut put, 7, key, self.state.protocols.get(key))?;
            }
            for key in &self.dirty.rule_names {
                put_or_delete(&tx, &mut put, 8, &key.to_string(), self.state.rule_names.get(key))?;
            }
            for (kind, key) in &self.dirty.retained {
                let (set, base) = if *kind < 14 { (&self.state.hours, 9) }
                    else { (&self.state.days, 14) };
                match *kind - base {
                    0 => put_or_delete(&tx, &mut put, *kind, key,
                        set.totals.get(&key.parse::<u64>().map_err(|e| e.to_string())?))?,
                    1 => put_or_delete(&tx, &mut put, *kind, key, set.applications.get(key))?,
                    2 => put_or_delete(&tx, &mut put, *kind, key, set.rules.get(key))?,
                    3 => put_or_delete(&tx, &mut put, *kind, key,
                        set.unknown.get(&key.parse::<u64>().map_err(|e| e.to_string())?))?,
                    4 => put_or_delete(&tx, &mut put, *kind, key, set.protocols.get(key))?,
                    _ => return Err("observation_store_schema".into()),
                }
            }
            for key in &self.dirty.end_markers {
                put_or_delete(&tx, &mut put, 19, key, self.state.end_markers.get(key))?;
            }
            put_row(&mut put, 0, "", &self.state.meta)?;
        }
        tx.commit().map_err(|e| e.to_string())
    }

    fn record_wal_size(&mut self) {
        let bytes = std::fs::metadata(format!("{}-wal", self.path.display()))
            .map_or(0, |metadata| metadata.len());
        self.wal_peak_bytes = self.wal_peak_bytes.max(bytes);
    }

    fn checkpoint(&mut self) -> Result<(), String> {
        self.maintenance_pending = true;
        let busy: i32 = self
            .db
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        if busy != 0 {
            return Err("observation_checkpoint_busy".into());
        }
        self.checkpoints += 1;
        self.maintenance_pending = self.retention_due() || self.space_pressure()?;
        Ok(())
    }

    pub fn consume(&mut self, records: &[FlowRecord], received_us: u64) -> Result<(), String> {
        let received_us = received_us.saturating_add(self.limits.clock_offset_us);
        if let Err(error) = self.advance_retention(received_us) {
            self.record_save_error(&error);
            return Err(error);
        }
        if self.state.rule_names.len() == MAX_RULE_NAMES {
            self.retire_unused_names();
        }
        // A failed flush does not stop the live merge while dirty capacity is
        // still available. Retry at most once per interval, never per packet.
        let mut flush_error = if self.last_flush.elapsed() >= FLUSH_INTERVAL {
            self.flush().err()
        } else {
            None
        };
        for record in records {
            if self.state.applications.len() >= MAX_EFFECT_WINDOWS
                || self.state.rules.len() >= MAX_EFFECT_WINDOWS
                || self.state.protocols.len() >= MAX_PROTOCOL_WINDOWS
                || self.state.minutes.len() >= MAX_MINUTES {
                for _ in 0..64 {
                    let reclaimed = match self.reclaim_pressure() {
                        Ok(reclaimed) => reclaimed,
                        Err(error) => {
                            self.record_save_error(&error);
                            return Err(error);
                        }
                    };
                    if !reclaimed { break; }
                    if self.state.applications.len() < MAX_EFFECT_WINDOWS
                        && self.state.rules.len() < MAX_EFFECT_WINDOWS
                        && self.state.protocols.len() < MAX_PROTOCOL_WINDOWS
                        && self.state.minutes.len() < MAX_MINUTES { break; }
                }
            }
            // Multi-view records can dirty more rows than overall-only ones.
            // Commit between records before the next bounded drain can exceed
            // capacity. A failed attempt still leaves room for live merging.
            if self.dirty.len() >= self.flush_rows() && self.save_error.is_none() {
                if let Err(error) = self.flush() {
                    flush_error = Some(error);
                }
            }
            // One record may touch every stable L7 label in both directions,
            // plus its L4, application, rule and baseline rows.
            if self.dirty.len() + 64 > MAX_DIRTY {
                self.mark_gap();
                self.save_error = Some("observation_dirty_capacity".into());
                return Err("observation_dirty_capacity".into());
            }
            if let Err(error) = self.consume_one(record, received_us) {
                self.save_error = Some(error.clone());
                self.mark_gap();
                return Err(error);
            }
        }
        if let Err(error) = self.advance_retention(received_us) {
            self.record_save_error(&error);
            return Err(error);
        }
        if self.dirty.len() >= self.flush_rows() && self.save_error.is_none() {
            self.flush()?;
        }
        if let Some(error) = flush_error {
            return Err(error);
        }
        Ok(())
    }

    fn consume_one(&mut self, record: &FlowRecord, received_us: u64) -> Result<(), String> {
        self.dirty.meta = true;
        if !Self::valid_current_record(record) {
            self.state.meta.rejected = self.state.meta.rejected.saturating_add(1);
            self.state.meta.gaps = self.state.meta.gaps.saturating_add(1);
            return Ok(());
        }
        // The Blocked namespace cannot collide with a simultaneous Flow slot.
        let key = identity_key(record);
        if self.stale_generations_pending && self.state.baselines.len() >= MAX_BASELINES {
            self.retire_old_generation_rows(RETENTION_ROWS_PER_BATCH);
        }
        if self.state.meta.current_generation != 0
            && record.generation != self.state.meta.current_generation {
            self.state.meta.rejected = self.state.meta.rejected.saturating_add(1);
            return Ok(());
        }
        if !self.state.baselines.contains_key(&key)
            && self.state.end_markers.get(&key).is_some_and(|marker|
                record.incarnation <= marker.incarnation) {
            self.state.meta.rejected = self.state.meta.rejected.saturating_add(1);
            return Ok(());
        }
        let mut delta = Counts {
            packets: record.packets,
            bytes: record.bytes,
        };
        while (!self.state.baselines.contains_key(&key) && self.state.baselines.len() >= MAX_BASELINES)
            || (record.ended && self.state.recent.len() >= MAX_RECENT) {
            let Some((oldest, _)) = self.state.recent.first_key_value() else { break; };
            self.expire_recent(oldest.clone());
        }
        if !self.state.baselines.contains_key(&key) && self.state.baselines.len() >= MAX_BASELINES {
            return Err("observation_baseline_capacity".into());
        }
        if record.ended && self.state.recent.len() >= MAX_RECENT {
            return Err("observation_recent_capacity".into());
        }
        let old = self.state.baselines.get(&key);
        if let Some(old) = old {
            let previous = &old.record;
            if record.incarnation < previous.incarnation
                || (record.incarnation == previous.incarnation
                    && (previous.ended
                        || record.sequence <= previous.sequence
                        || record.last_seen < previous.last_seen
                        || (0..2).any(|i| {
                            record.packets[i] < previous.packets[i]
                                || record.bytes[i] < previous.bytes[i]
                        })))
            {
                self.state.meta.rejected = self.state.meta.rejected.saturating_add(1);
                return Ok(());
            }
            if record.incarnation == previous.incarnation {
                if record.sequence - previous.sequence != 1 {
                    self.state.meta.gaps = self.state.meta.gaps.saturating_add(1);
                }
                for i in 0..2 {
                    delta.packets[i] -= previous.packets[i];
                    delta.bytes[i] -= previous.bytes[i];
                }
            } else if !previous.ended {
                self.state.meta.gaps = self.state.meta.gaps.saturating_add(1);
            }
        }
        if old.map_or(true, |b| b.record.incarnation != record.incarnation) && record.sequence != 1
        {
            self.state.meta.gaps = self.state.meta.gaps.saturating_add(1);
        }
        if record.clock_changed
            && old.map_or(true, |b| {
                b.record.incarnation != record.incarnation || !b.record.clock_changed
            })
        {
            self.state.meta.clock_changes = self.state.meta.clock_changes.saturating_add(1);
        }
        Self::validate_segments(record, old.map(|b| &b.record))?;
        // Stage all affected rows before mutating the live aggregate. One
        // record can touch two application and two rule rows, never history.
        let mut applications = BTreeMap::<String, ApplicationWindow>::new();
        let mut rules = BTreeMap::<String, RuleWindow>::new();
        let mut protocols = BTreeMap::<String, ProtocolWindow>::new();
        let mut rule_names = BTreeMap::<u64, Option<String>>::new();
        let mut unknown = self.state.meta.attribution_unknown;
        let mut l4_unknown = self.state.meta.l4_unknown;
        let mut l7_unknown = self.state.meta.l7_unknown;
        let mut unattributed = Counts::default();
        let mut minutes = BTreeMap::<u64, Counts>::new();
        let mut activity_times = [0; 3];
        for side in 0..2 {
            let a = &record.attribution[side];
            if a.valid && a.winner >> 16 != 0 && a.winner & 65535 != 0 && !a.name.is_empty() {
                let prior = rule_names.get(&a.winner)
                    .or_else(|| self.state.rule_names.get(&a.winner));
                let next = match prior {
                    None => Some(a.name.clone()),
                    Some(Some(name)) if name == &a.name => Some(name.clone()),
                    Some(_) => None, // Reused/conflicting version cannot name missing records.
                };
                rule_names.insert(a.winner, next);
            }
            let mut contribution = Counts::default();
            if a.valid && a.segment != 0 && a.activity_utc_us != 0 {
                let start_packets = record.packets[side]
                    .checked_sub(a.start_packets)
                    .ok_or("observation_invalid_segment")?;
                let start_bytes = record.bytes[side]
                    .checked_sub(a.start_bytes)
                    .ok_or("observation_invalid_segment")?;
                contribution.packets[side] = delta.packets[side].min(start_packets);
                contribution.bytes[side] = delta.bytes[side].min(start_bytes);
            }
            unattributed.packets[side] = delta.packets[side] - contribution.packets[side];
            unattributed.bytes[side] = delta.bytes[side] - contribution.bytes[side];
            let mut unclassified = Counts::default();
            unclassified.packets[side] = unattributed.packets[side];
            unclassified.bytes[side] = unattributed.bytes[side];
            l4_unknown.add(&unclassified)?;
            l7_unknown.add(&unclassified)?;
            if contribution.packets[side] == 0 && contribution.bytes[side] == 0 {
                continue;
            }
            activity_times[side] = a.activity_utc_us;
            let minute = a.activity_utc_us / 60_000_000 * 60;
            minutes
                .entry(minute)
                .or_insert_with(|| self.state.minutes.get(&minute).copied().unwrap_or_default())
                .add(&contribution)?;
            let app_key = format!("{minute:020}:{}:{}", a.uid, a.actual_action);
            let window = applications.entry(app_key.clone()).or_insert_with(|| {
                self.state
                    .applications
                    .get(&app_key)
                    .cloned()
                    .unwrap_or(ApplicationWindow {
                        minute,
                        uid: a.uid,
                        actual_action: a.actual_action,
                        counts: Counts::default(),
                    })
            });
            window.counts.add(&contribution)?;
            if let Some(key) = l4_key(record.protocol as u32) {
                stage_protocol_window(&self.state.protocols, &mut protocols, minute, a,
                    ProtocolLayer::L4, record.protocol as u32, key, &contribution)?;
            } else {
                l4_unknown.add(&contribution)?;
            }
            if a.protocols_available {
                if a.protocol_set == 0 {
                    stage_protocol_window(&self.state.protocols, &mut protocols, minute, a,
                        ProtocolLayer::L7None, 0, "", &contribution)?;
                } else {
                    let mut remaining = a.protocol_set;
                    while remaining != 0 {
                        let bit = remaining.trailing_zeros();
                        let (id, key) = protocol_label(bit).ok_or("observation_invalid_protocol")?;
                        stage_protocol_window(&self.state.protocols, &mut protocols, minute, a,
                            ProtocolLayer::L7, id, key, &contribution)?;
                        remaining &= remaining - 1;
                    }
                }
            } else {
                l7_unknown.add(&contribution)?;
                stage_protocol_window(&self.state.protocols, &mut protocols, minute, a,
                    ProtocolLayer::L7Unavailable, 0, "", &contribution)?;
            }
            if a.winner != 0 {
                let rule_key = format!(
                    "{minute:020}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                    a.uid,
                    a.network,
                    a.policy_generation,
                    a.policy_revision,
                    a.policy_hash,
                    a.winner,
                    a.mode,
                    a.declared_action,
                    a.actual_action
                );
                let window = rules.entry(rule_key.clone()).or_insert_with(|| {
                    self.state
                        .rules
                        .get(&rule_key)
                        .cloned()
                        .unwrap_or(RuleWindow {
                            minute,
                            attribution: a.into(),
                            counts: Counts::default(),
                        })
                });
                let mut incoming = RuleReference::from(a);
                let mut existing = window.attribution.clone();
                existing.name.clear();
                incoming.name.clear();
                if existing != incoming {
                    return Err("observation_rule_reference_conflict".into());
                }
                if !window.attribution.name.is_empty() && !a.name.is_empty()
                    && window.attribution.name != a.name {
                    return Err("observation_rule_reference_conflict".into());
                }
                if window.attribution.name.is_empty() {
                    if !a.name.is_empty() {
                        window.attribution.name = a.name.clone();
                    } else if let Some(Some(name)) = rule_names.get(&a.winner)
                        .or_else(|| self.state.rule_names.get(&a.winner)) {
                        window.attribution.name = name.clone();
                    }
                }
                window.counts.add(&contribution)?;
            }
        }
        if self.state.applications.len()
            + applications
                .keys()
                .filter(|k| !self.state.applications.contains_key(*k))
                .count()
            > MAX_EFFECT_WINDOWS
            || self.state.rules.len()
                + rules
                    .keys()
                    .filter(|k| !self.state.rules.contains_key(*k))
                .count()
                > MAX_EFFECT_WINDOWS
            || self.state.protocols.len()
                + protocols.keys().filter(|k| !self.state.protocols.contains_key(*k)).count()
                > MAX_PROTOCOL_WINDOWS
        {
            return Err("observation_effect_window_capacity".into());
        }
        // A full association table must not discard packet counts. The actual
        // record/window still retains its supplied name; only future blank-name
        // records may lose this optional cross-record link.
        let mut spare = MAX_RULE_NAMES.saturating_sub(self.state.rule_names.len());
        let staged_names = rule_names.len();
        rule_names.retain(|version, _| {
            if self.state.rule_names.contains_key(version) { true }
            else if spare != 0 { spare -= 1; true }
            else { false }
        });
        let association_misses = (staged_names - rule_names.len()) as u64;
        unknown.add(&unattributed)?;
        let unknown_minute = record.activity_utc_us / 60_000_000 * 60;
        let has_unknown = unattributed.packets != [0; 2] || unattributed.bytes != [0; 2];
        let mut unknown_count = self
            .state
            .unknown_minutes
            .get(&unknown_minute)
            .copied()
            .unwrap_or_default();
        if has_unknown {
            activity_times[2] = record.activity_utc_us;
            unknown_count.add(&unattributed)?;
            minutes
                .entry(unknown_minute)
                .or_insert_with(|| {
                    self.state
                        .minutes
                        .get(&unknown_minute)
                        .copied()
                        .unwrap_or_default()
                })
                .add(&unattributed)?;
        }
        if self.state.minutes.len()
            + minutes
                .keys()
                .filter(|k| !self.state.minutes.contains_key(*k))
                .count()
            > MAX_MINUTES
            || (has_unknown
                && !self.state.unknown_minutes.contains_key(&unknown_minute)
                && self.state.unknown_minutes.len() >= MAX_MINUTES)
        {
            return Err("observation_minute_capacity".into());
        }
        let mut totals = self.state.meta.totals;
        totals.add(&delta)?;
        let mut blocked_totals = self.state.meta.blocked_totals;
        if record.blocked { blocked_totals.add(&delta)?; }
        // All checked arithmetic and capacity admission has completed. Apply
        // baseline, lifecycle and every view together to the one live state.
        for (minute, count) in minutes {
            self.state.minutes.insert(minute, count);
            self.dirty.minutes.insert(minute);
        }
        if has_unknown {
            self.state
                .unknown_minutes
                .insert(unknown_minute, unknown_count);
            self.dirty.unknown_minutes.insert(unknown_minute);
        }
        self.state.meta.totals = totals;
        self.state.meta.blocked_totals = blocked_totals;
        // Coverage describes the timestamps actually used by retained
        // contributions, including independent directions and unknown growth.
        // A zero-delta direction or state-only update cannot widen it.
        if let Some(first) = activity_times.iter().copied().filter(|t| *t != 0).min() {
            let last = activity_times.iter().copied().max().unwrap();
            self.state.meta.first_activity_us = Some(
                self.state
                    .meta
                    .first_activity_us
                    .map_or(first, |v| v.min(first)),
            );
            self.state.meta.last_activity_us = Some(
                self.state
                    .meta
                    .last_activity_us
                    .map_or(last, |v| v.max(last)),
            );
        }
        self.state.meta.attribution_unknown = unknown;
        self.state.meta.l4_unknown = l4_unknown;
        self.state.meta.l7_unknown = l7_unknown;
        self.state.meta.rule_metadata_association_misses = self.state.meta
            .rule_metadata_association_misses.saturating_add(association_misses);
        for (key, window) in applications {
            self.dirty.applications.insert(key.clone());
            self.state.applications.insert(key, window);
        }
        for (key, window) in rules {
            self.dirty.rules.insert(key.clone());
            self.state.rules.insert(key, window);
        }
        for (key, window) in protocols {
            self.dirty.protocols.insert(key.clone());
            self.state.protocols.insert(key, window);
        }
        for (version, name) in rule_names {
            if self.state.rule_names.get(&version) != Some(&name) {
                self.dirty.rule_names.insert(version);
                self.state.rule_names.insert(version, name);
            }
        }
        let baseline = Baseline {
            record: record.clone(),
            first_end_us: record.ended.then_some(received_us),
        };
        if record.ended {
            self.state.meta.ended = self.state.meta.ended.saturating_add(1);
            if record.blocked {
                self.state.meta.blocked_ended = self.state.meta.blocked_ended.saturating_add(1);
            }
            let recent_key = format!("{received_us:020}:{key}:{}", record.incarnation);
            self.dirty.recent.insert(recent_key.clone());
            self.state.recent.insert(recent_key, baseline.clone());
        }
        self.dirty.baselines.insert(key.clone());
        if self.state.end_markers.remove(&key).is_some() {
            self.dirty.end_markers.insert(key.clone());
        }
        self.state.baselines.insert(key, baseline);
        self.state.meta.accepted = self.state.meta.accepted.saturating_add(1);
        Ok(())
    }

    pub fn mark_gap(&mut self) {
        self.state.meta.gaps = self.state.meta.gaps.saturating_add(1);
        self.dirty.meta = true;
    }

    pub fn close(&mut self) -> Result<(), String> {
        self.state.meta.open_session = false;
        self.dirty.meta = true;
        self.flush()
    }

    pub fn query(&self) -> serde_json::Value {
        // Fixed bounded response from maintained counters, never a raw-record
        // rescan. A sparse query can span more than 48 hours; report its bounds.
        let hidden_start = match self.state.meta.transition {
            Some(RetentionTransition::Rollup { from: 3, to: 9, start }) => Some(start),
            _ => None,
        };
        let hidden_hour = match self.state.meta.transition {
            Some(RetentionTransition::Rollup { from: 9, to: 14, start }) => Some(start),
            _ => None,
        };
        let hidden_day = match self.state.meta.transition {
            Some(RetentionTransition::EvictDay { start }) => Some(start),
            _ => None,
        };
        let hidden_prefix = hidden_start.map(|start| format!("{start:020}:"));
        let minutes: BTreeMap<_, _> = self
            .state
            .minutes
            .iter()
            .rev()
            .filter(|(key, _)| Some(**key) != hidden_start)
            .take(MAX_QUERY_MINUTES)
            .collect();
        let unknown_minutes: BTreeMap<_, _> = self
            .state
            .unknown_minutes
            .iter()
            .rev()
            .filter(|(key, _)| Some(**key) != hidden_start)
            .take(MAX_QUERY_MINUTES)
            .collect();
        let applications: BTreeMap<_, _> = self
            .state
            .applications
            .iter()
            .rev()
            .filter(|(key, _)| hidden_prefix.as_ref().is_none_or(|prefix| !key.starts_with(prefix)))
            .take(MAX_QUERY_MINUTES)
            .collect();
        let rules: BTreeMap<_, _> = self.state.rules.iter().rev()
            .filter(|(key, _)| hidden_prefix.as_ref().is_none_or(|prefix| !key.starts_with(prefix)))
            .take(MAX_QUERY_MINUTES)
            .map(|(key, window)| {
                let mut row = serde_json::to_value(window).expect("stored rule window");
                row["interpretation"] = rule_interpretation(
                    window.attribution.winner, &window.attribution.name,
                    &self.state.rule_names, window.attribution.actual_action, true);
                (key, row)
            }).collect();
        let protocols: BTreeMap<_, _> = self.state.protocols.iter().rev()
            .filter(|(key, _)| hidden_prefix.as_ref().is_none_or(|prefix| !key.starts_with(prefix)))
            .take(MAX_QUERY_MINUTES)
            .map(|(key, window)| {
                let app_key = format!("{:020}:{}:{}", window.minute, window.uid, window.actual_action);
                let denominator = &self.state.applications[&app_key].counts;
                (key, serde_json::json!({
                    "minute": window.minute, "uid": window.uid,
                    "actual_action": window.actual_action, "layer": window.layer,
                    "protocol_id": window.protocol_id, "key": window.key,
                    "counts": window.counts, "denominator": denominator,
                    "share": protocol_share(&window.counts, denominator),
                }))
            }).collect();
        let recent: BTreeMap<_, _> = self.state.recent.iter().rev().take(128)
            .map(|(key, baseline)| {
                let mut row = serde_json::to_value(baseline).expect("stored recent observation");
                for side in 0..2 {
                    let a = &baseline.record.attribution[side];
                    let mut interpretation = rule_interpretation(
                        a.winner, &a.name, &self.state.rule_names, a.actual_action, a.valid);
                    interpretation["scope"] = "last_directional_segment".into();
                    interpretation["segment_counts"] = if a.valid {
                        serde_json::json!({
                            "packets": baseline.record.packets[side].saturating_sub(a.start_packets),
                            "bytes": baseline.record.bytes[side].saturating_sub(a.start_bytes),
                        })
                    } else {
                        serde_json::Value::Null
                    };
                    row["record"]["attribution"][side]["interpretation"] = interpretation;
                }
                (key, row)
            }).collect();
        let mut response = serde_json::json!({ "schema": 1, "storage": "sqlite", "visibility": "live_including_pending",
            "persistence": { "packets": self.committed.totals.packets, "bytes": self.committed.totals.bytes,
                "accepted": self.committed.accepted, "pending_rows": self.dirty.len(), "pending": self.dirty.meta || self.dirty.len() != 0,
                "maintenance_pending": self.maintenance_pending,
                "commits": self.commits, "checkpoints": self.checkpoints, "error": self.save_error,
                "wal_peak_bytes": self.wal_peak_bytes },
            "limits": { "dirty_rows": MAX_DIRTY, "baselines": MAX_BASELINES, "recent": MAX_RECENT,
                "minutes": MAX_MINUTES, "database_bytes": DATABASE_LIMIT, "budget_bytes": STORAGE_BUDGET },
            "packets": self.state.meta.totals.packets, "bytes": self.state.meta.totals.bytes,
            "application_windows": applications, "rule_windows": rules,
            "attribution_unknown": self.state.meta.attribution_unknown,
            "attribution_unknown_minutes": unknown_minutes,
            "legacy_unattributed": self.state.meta.legacy_unattributed,
            "unknown_minute_count": self.state.unknown_minutes.len(),
            "unknown_query_truncated": self.state.unknown_minutes.len() > MAX_QUERY_MINUTES,
            "application_window_count": self.state.applications.len(), "rule_window_count": self.state.rules.len(),
            "effect_query_limit": MAX_QUERY_MINUTES, "effect_window_limit": MAX_EFFECT_WINDOWS,
            "application_query_truncated": self.state.applications.len() > MAX_QUERY_MINUTES,
            "rule_query_truncated": self.state.rules.len() > MAX_QUERY_MINUTES,
            "minutes": minutes, "ended": self.state.meta.ended, "recent": recent,
            "recent_count": self.state.recent.len(), "recent_query_limit": 128,
            "minute_query_limit": MAX_QUERY_MINUTES,
            "minute_query_truncated": self.state.minutes.len() > MAX_QUERY_MINUTES,
            "stored_minute_count": self.state.minutes.len(),
            "baselines": self.state.baselines.len(), "accepted": self.state.meta.accepted,
            "rejected": self.state.meta.rejected, "save_error": self.save_error,
            "coverage": { "scope": "observed_flows", "incomplete": self.state.meta.gaps != 0 || self.uncertain,
                "attribution_incomplete": self.state.meta.attribution_unknown.packets != [0; 2] || self.state.meta.attribution_unknown.bytes != [0; 2],
                "gaps": self.state.meta.gaps, "recoveries": self.state.meta.recoveries,
                "clock_changes": self.state.meta.clock_changes,
                "first_activity_us": self.state.meta.first_activity_us,
                "last_activity_us": self.state.meta.last_activity_us },
            "open_session": self.state.meta.open_session, "legacy_input_limit_bytes": MAX_SNAPSHOT });
        response["protocol_windows"] = serde_json::json!(protocols);
        response["limits"]["minute_age_us"] = self.limits.minute_age_us.into();
        response["limits"]["hour_age_us"] = self.limits.hour_age_us.into();
        response["limits"]["day_age_us"] = self.limits.day_age_us.into();
        response["limits"]["end_age_us"] = self.limits.end_age_us.into();
        response["limits"]["scaled_test"] = self.scaled_test.into();
        response["limits"]["clock_offset_us"] = self.limits.clock_offset_us.into();
        response["limits"]["budget_bytes"] = self.limits.budget_bytes.into();
        response["limits"]["flush_rows"] = self.flush_rows().into();
        response["coverage"]["evicted"] = serde_json::json!(self.state.meta.evicted);
        response["coverage"]["retention_watermark_us"] = self.state.meta.retention_watermark_us.into();
        response["coverage"]["retention_clock_held"] = self.clock_held.into();
        response["coverage"]["incomplete"] = (self.state.meta.gaps != 0 || self.uncertain
            || self.state.meta.evicted.packets != [0; 2] || self.state.meta.evicted.bytes != [0; 2]).into();
        response["hour_windows"] = match self.state.meta.transition {
            Some(RetentionTransition::Rollup { from: 3, to: 9, start }) =>
                self.projected_tier_query(3, 9, start, start / 3600 * 3600),
            _ => self.state.hours.query(&self.state.rule_names, 3600, hidden_hour),
        };
        response["day_windows"] = match self.state.meta.transition {
            Some(RetentionTransition::Rollup { from: 9, to: 14, start }) =>
                self.projected_tier_query(9, 14, start, start / 86400 * 86400),
            _ => self.state.days.query(&self.state.rule_names, 86400, hidden_day),
        };
        response["retention_transition"] = serde_json::json!(self.state.meta.transition);
        response["protocol_window_count"] = self.state.protocols.len().into();
        response["protocol_query_truncated"] =
            (self.state.protocols.len() > MAX_QUERY_MINUTES).into();
        if let Some(hidden) = hidden_start {
            let visible = self.state.minutes.len() - usize::from(self.state.minutes.contains_key(&hidden));
            let unknown = self.state.unknown_minutes.len()
                - usize::from(self.state.unknown_minutes.contains_key(&hidden));
            let applications = self.state.applications.len() - count_rows_at(&self.state.applications, hidden);
            let rules = self.state.rules.len() - count_rows_at(&self.state.rules, hidden);
            let protocols = self.state.protocols.len() - count_rows_at(&self.state.protocols, hidden);
            response["stored_minute_count"] = visible.into();
            response["minute_query_truncated"] = (visible > MAX_QUERY_MINUTES).into();
            response["unknown_minute_count"] = unknown.into();
            response["unknown_query_truncated"] = (unknown > MAX_QUERY_MINUTES).into();
            response["application_window_count"] = applications.into();
            response["application_query_truncated"] = (applications > MAX_QUERY_MINUTES).into();
            response["rule_window_count"] = rules.into();
            response["rule_query_truncated"] = (rules > MAX_QUERY_MINUTES).into();
            response["protocol_window_count"] = protocols.into();
            response["protocol_query_truncated"] = (protocols > MAX_QUERY_MINUTES).into();
        }
        response["storage_space"] = self.storage_space();
        let mut retained_first = [self.state.minutes.keys().find(|key| Some(**key) != hidden_start).copied(),
            self.state.hours.totals.keys().find(|key| Some(**key) != hidden_hour).copied(),
            self.state.days.totals.keys().find(|key| Some(**key) != hidden_day).copied()];
        let mut retained_last = [self.state.minutes.keys().rev().find(|key| Some(**key) != hidden_start).copied(),
            self.state.hours.totals.keys().rev().find(|key| Some(**key) != hidden_hour).copied(),
            self.state.days.totals.keys().rev().find(|key| Some(**key) != hidden_day).copied()];
        if let Some(RetentionTransition::Rollup { from: 3, start, .. }) = self.state.meta.transition {
            retained_first[1] = Some(retained_first[1].map_or(start / 3600 * 3600,
                |old| old.min(start / 3600 * 3600)));
            retained_last[1] = Some(retained_last[1].map_or(start / 3600 * 3600,
                |old| old.max(start / 3600 * 3600)));
        }
        if let Some(RetentionTransition::Rollup { from: 9, start, .. }) = self.state.meta.transition {
            retained_first[2] = Some(retained_first[2].map_or(start / 86400 * 86400,
                |old| old.min(start / 86400 * 86400)));
            retained_last[2] = Some(retained_last[2].map_or(start / 86400 * 86400,
                |old| old.max(start / 86400 * 86400)));
        }
        let first = retained_first
            .into_iter().flatten().min();
        let last = retained_last
            .into_iter().flatten().max();
        response["coverage"]["retained_first_bucket_utc_sec"] = serde_json::json!(first);
        response["coverage"]["retained_last_bucket_utc_sec"] = serde_json::json!(last);
        response["end_marker_count"] = serde_json::json!(self.state.end_markers.len());
        response["rule_metadata_count"] = serde_json::json!(self.state.rule_names.len());
        response["rule_metadata_conflicts"] = serde_json::json!(
            self.state.rule_names.values().filter(|name| name.is_none()).count());
        response["rule_metadata_association_misses"] =
            serde_json::json!(self.state.meta.rule_metadata_association_misses);
        response["coverage"]["rule_metadata_incomplete"] = serde_json::json!(
            self.state.meta.rule_metadata_association_misses != 0
                || self.state.rule_names.values().any(|name| name.is_none()));
        response["l4_unknown"] = serde_json::json!(self.state.meta.l4_unknown);
        response["l7_unknown"] = serde_json::json!(self.state.meta.l7_unknown);
        response["legacy_protocol_unavailable"] =
            serde_json::json!(self.state.meta.legacy_protocol_unavailable);
        response["coverage"]["protocol_incomplete"] = serde_json::json!(
            self.state.meta.l4_unknown.packets != [0; 2]
                || self.state.meta.l4_unknown.bytes != [0; 2]
                || self.state.meta.l7_unknown.packets != [0; 2]
                || self.state.meta.l7_unknown.bytes != [0; 2]
        );
        response["blocked"] = serde_json::json!({
            "packets": self.state.meta.blocked_totals.packets,
            "bytes": self.state.meta.blocked_totals.bytes,
            "ended": self.state.meta.blocked_ended,
        });
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_reclaim_can_free_ended_detail_during_partial_rollup() {
        let root = std::env::temp_dir().join(format!("t27-partial-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("overall.json");
        let at = 200 * DAY_US + MINUTE_US + 1_000_000;
        let mut store = ObservationStore::open(&path).unwrap();
        let record = FlowRecord {
            generation: 5, slot: 1, incarnation: 1, sequence: 1,
            activity_utc_us: at, first_seen: 1, last_seen: 1,
            packets: [2, 0], bytes: [128, 0], ended: true,
            attribution: [Attribution {
                valid: true, segment: 1, activity_utc_us: at,
                policy_generation: 5, policy_revision: 1, policy_hash: 9,
                uid: 42, winner: 65537, name: "old".into(),
                declared_action: 1, actual_action: 1,
                protocols_available: true, protocol_set: 1,
                ..Default::default()
            }, Attribution::default()],
            ..Default::default()
        };
        store.consume(&[record.clone()], at).unwrap();
        store.flush().unwrap();
        let minute = at / MINUTE_US * 60;
        assert!(store.rollup_step(3, 9, minute, 3600).unwrap());
        assert!(store.state.meta.transition.is_some());
        assert!(store.reclaim_pressure().unwrap());
        assert!(store.state.meta.transition.is_some());
        assert_eq!(store.state.recent.len(), 0);
        assert_eq!(store.state.end_markers.len(), 1);
        store.flush().unwrap();
        assert_eq!(store.query()["packets"], serde_json::json!([2, 0]));
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[ignore = "explicit high-cardinality partial-transition cost probe"]
    fn partial_transition_query_is_bounded_at_high_cardinality() {
        let root = std::env::temp_dir().join(format!("t27-query-cost-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("overall.json");
        let at = 200 * DAY_US + 61_000_000;
        let mut store = ObservationStore::open(&path).unwrap();
        for slot in 0..5000u32 {
            let a = Attribution {
                valid: true, segment: 1, activity_utc_us: at,
                policy_generation: 5, policy_revision: 1, policy_hash: 9,
                uid: slot + 100, winner: 65537, name: "many".into(),
                declared_action: 1, actual_action: 1,
                protocols_available: true, protocol_set: 1,
                ..Default::default()
            };
            let record = FlowRecord {
                generation: 5, slot, incarnation: 1, sequence: 1,
                activity_utc_us: at, first_seen: 1, last_seen: 1,
                protocol: 17, packets: [1, 0], bytes: [64, 0],
                attribution: [a, Attribution::default()],
                ..Default::default()
            };
            store.consume(&[record], at).unwrap();
        }
        store.flush().unwrap();
        let minute = at / MINUTE_US * 60;
        store.rollup_step(3, 9, minute, 3600).unwrap();
        let before = Instant::now();
        let query = store.query();
        let elapsed_ms = before.elapsed().as_millis();
        let reply_bytes = serde_json::to_vec(&query).unwrap().len();
        println!("t27_partial_query rows=5000 elapsed_ms={elapsed_ms} reply_bytes={reply_bytes}");
        assert_eq!(query["stored_minute_count"], 0);
        assert_eq!(query["hour_windows"]["counts"]["applications"], 5000);
        assert_eq!(query["hour_windows"]["counts"]["rules"], 5000);
        assert_eq!(query["hour_windows"]["overall"].as_object().unwrap().values()
            .next().unwrap()["packets"], serde_json::json!([5000, 0]));
        assert!(elapsed_ms < 2000);
        assert!(reply_bytes < 4 * 1024 * 1024);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_partial_rollup_and_day_eviction_query_as_one_logical_tier() {
        let root = std::env::temp_dir().join(format!("t27-partial-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("overall.json");
        let at = 200 * DAY_US + 61_000_000;
        let attribution = Attribution {
            valid: true, segment: 1, activity_utc_us: at,
            policy_generation: 5, policy_revision: 1, policy_hash: 9,
            uid: 42, winner: 65537, name: "old".into(),
            declared_action: 1, actual_action: 1,
            protocols_available: true, protocol_set: 1,
            ..Default::default()
        };
        let record = FlowRecord {
            generation: 5, slot: 1, incarnation: 1, sequence: 1,
            activity_utc_us: at, first_seen: 1, last_seen: 1,
            protocol: 17, packets: [2, 0], bytes: [128, 0],
            attribution: [attribution, Attribution::default()],
            ..Default::default()
        };
        let mut store = ObservationStore::open(&path).unwrap();
        store.consume(&[record], at).unwrap();
        store.flush().unwrap();
        let minute = at / MINUTE_US * 60;
        assert!(store.rollup_step(3, 9, minute, 3600).unwrap());
        let query = store.query();
        assert_eq!(query["stored_minute_count"], 0);
        assert_eq!(query["hour_windows"]["overall"].as_object().unwrap().values()
            .next().unwrap()["packets"], serde_json::json!([2, 0]));
        assert_eq!(query["hour_windows"]["counts"]["applications"], 1);
        assert_eq!(query["hour_windows"]["counts"]["rules"], 1);
        assert_eq!(query["hour_windows"]["counts"]["protocols"], 2);
        store.write_dirty().unwrap();
        store.checkpoint().unwrap();
        drop(store);
        let mut store = ObservationStore::open(&path).unwrap();
        assert_eq!(store.query()["hour_windows"]["counts"]["rules"], 1);
        store.consume(&[], at + 48 * HOUR_US + MINUTE_US).unwrap();
        store.flush().unwrap();
        store.consume(&[], at + 30 * DAY_US + HOUR_US).unwrap();
        store.flush().unwrap();
        assert_eq!(store.query()["day_windows"]["counts"]["overall"], 1);
        let day = minute / 86400 * 86400;
        assert!(store.discard_day_step(day).unwrap());
        let query = store.query();
        assert_eq!(query["packets"], serde_json::json!([2, 0]));
        assert_eq!(query["day_windows"]["counts"]["overall"], 0);
        assert_eq!(query["coverage"]["evicted"]["packets"], serde_json::json!([2, 0]));
        store.write_dirty().unwrap();
        store.checkpoint().unwrap();
        drop(store);
        let mut store = ObservationStore::open(&path).unwrap();
        assert_eq!(store.query()["coverage"]["evicted"]["packets"], serde_json::json!([2, 0]));
        store.consume(&[], at + 180 * DAY_US + 2 * DAY_US).unwrap();
        store.flush().unwrap();
        drop(store);
        let reopened = ObservationStore::open(&path).unwrap();
        assert_eq!(reopened.query()["packets"], serde_json::json!([2, 0]));
        assert_eq!(reopened.query()["coverage"]["evicted"]["packets"], serde_json::json!([2, 0]));
        drop(reopened);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sqlite_full_preserves_committed_counts_and_bounded_live_tail() {
        let root = std::env::temp_dir().join(format!("e02-full-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("overall.json");
        let mut store = ObservationStore::open(&path).unwrap();
        // Inject the real SQLite capacity failure at the database boundary;
        // assertions use only the public store/query/reopen behavior.
        let pages: i64 = store
            .db
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .unwrap();
        store
            .db
            .pragma_update(None, "max_page_count", pages)
            .unwrap();
        let records: Vec<_> = (0..64)
            .map(|slot| FlowRecord {
                generation: 1,
                slot,
                incarnation: 1,
                sequence: 1,
                activity_utc_us: 61_000_000,
                packets: [1, 1],
                bytes: [60, 60],
                ..Default::default()
            })
            .collect();
        store.consume(&records, 62_000_000).unwrap();
        assert!(store.flush().unwrap_err().contains("full"));
        assert!(store.query()["coverage"]["incomplete"].as_bool().unwrap());
        assert!(store.query()["coverage"]["gaps"].as_u64().unwrap() > 0);
        assert!(store.query()["persistence"]["error"].as_str().unwrap().contains("full"));
        assert_eq!(store.query()["packets"], serde_json::json!([64, 64]));
        assert_eq!(
            store.query()["persistence"]["packets"],
            serde_json::json!([0, 0])
        );
        store
            .db
            .pragma_update(None, "max_page_count", 16384)
            .unwrap();
        store.flush().unwrap();
        store.close().unwrap();
        drop(store);
        let mut store = ObservationStore::open(&path).unwrap();
        store.consume(&records, 63_000_000).unwrap();
        assert_eq!(store.query()["packets"], serde_json::json!([64, 64]));
        assert_eq!(store.query()["coverage"]["incomplete"], true);
        drop(store);
        std::fs::remove_dir_all(root).unwrap();
    }
}
