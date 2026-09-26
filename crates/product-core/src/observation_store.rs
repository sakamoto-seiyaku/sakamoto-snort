//! Minimal transactional overall-window store. No raw event log or repository framework.
use crate::observation::FlowRecord;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const MAX_SNAPSHOT: u64 = 32 * 1024 * 1024;
const MAX_QUERY_MINUTES: usize = 2880;
const RECENT_US: u64 = 24 * 60 * 60 * 1_000_000;
unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
}

#[derive(Clone, Default, Serialize, Deserialize)]
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
}
#[derive(Clone, Serialize, Deserialize)]
struct Baseline {
    record: FlowRecord,
    first_end_us: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct State {
    schema: u32,
    baselines: BTreeMap<String, Baseline>,
    recent: BTreeMap<String, Baseline>,
    minutes: BTreeMap<u64, Counts>,
    totals: Counts,
    ended: u64,
    accepted: u64,
    rejected: u64,
    gaps: u64,
    clock_changes: u64,
    open_session: bool,
    recoveries: u64,
    first_activity_us: Option<u64>,
    last_activity_us: Option<u64>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            schema: 1,
            baselines: BTreeMap::new(),
            recent: BTreeMap::new(),
            minutes: BTreeMap::new(),
            totals: Counts::default(),
            ended: 0,
            accepted: 0,
            rejected: 0,
            gaps: 0,
            clock_changes: 0,
            open_session: false,
            recoveries: 0,
            first_activity_us: None,
            last_activity_us: None,
        }
    }
}

pub struct ObservationStore {
    path: PathBuf,
    _lock: File,
    state: State,
    save_error: Option<String>,
    uncertain: bool,
}
impl ObservationStore {
    pub fn open(path: &Path) -> Result<Self, String> {
        let parent = path.parent().ok_or("store_parent_missing")?;
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        // The caller supplies an established storage root. Create only its
        // immediate observation directory, never an implicit directory tree.
        match std::fs::create_dir(parent) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && parent.is_dir() => {}
            Err(error) => return Err(error.to_string()),
        }
        // A file+leaf-directory fsync does not durably publish a newly created
        // observation directory in its parent. Sync on EVERY open: a preceding
        // failed/interrupted open may have left a visible but unsynced entry.
        let containing = match parent.parent() {
            Some(p) if p.as_os_str().is_empty() => Path::new("."),
            Some(p) => p,
            None => parent,
        };
        File::open(containing)
            .and_then(|file| file.sync_all())
            .map_err(|e| e.to_string())?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path.with_extension("lock"))
            .map_err(|e| e.to_string())?;
        // LOCK_EX | LOCK_NB: another backend owns this store, never wait for it.
        if unsafe { flock(lock.as_raw_fd(), 2 | 4) } != 0 {
            return Err("observation_store_busy".into());
        }
        let mut state = match File::open(path) {
            Ok(file) => {
                if file.metadata().map_err(|e| e.to_string())?.len() > MAX_SNAPSHOT {
                    return Err("observation_snapshot_too_large".into());
                }
                let mut bytes = Vec::new();
                file.take(MAX_SNAPSHOT + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|e| e.to_string())?;
                let decoded: State = serde_json::from_slice(&bytes)
                    .map_err(|e| format!("observation_store_corrupt:{e}"))?;
                if decoded.schema != 1 {
                    return Err("observation_store_schema".into());
                }
                decoded
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.to_string()),
        };
        if state.open_session {
            state.recoveries += 1;
            state.gaps += 1;
        }
        state.open_session = true;
        let mut store = Self {
            path: path.to_owned(),
            _lock: lock,
            state: State::default(),
            save_error: None,
            uncertain: false,
        };
        store.commit(state)?;
        Ok(store)
    }

    fn commit(&mut self, next: State) -> Result<(), String> {
        let result: Result<(), String> = (|| {
            let bytes = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_SNAPSHOT {
                return Err("observation_snapshot_too_large".into());
            }
            let temporary = self.path.with_extension("pending");
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| e.to_string())?;
            std::fs::rename(&temporary, &self.path).map_err(|e| e.to_string())?;
            // After rename, use the new baseline even if directory durability is
            // uncertain: subsequent writes must never recount the visible file.
            self.state = next;
            let parent = self.path.parent().unwrap();
            File::open(if parent.as_os_str().is_empty() {
                Path::new(".")
            } else {
                parent
            })
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
            Ok(())
        })();
        if let Err(error) = &result {
            self.save_error = Some(error.clone());
            self.uncertain = true;
        } else {
            self.save_error = None;
        }
        result
    }

    pub fn consume(&mut self, records: &[FlowRecord], received_us: u64) -> Result<(), String> {
        let next = match self.next_state(records, received_us) {
            Ok(next) => next,
            Err(error) => {
                self.save_error = Some(error.clone());
                self.uncertain = true;
                return Err(error);
            }
        };
        self.commit(next)?;
        self.uncertain = false;
        Ok(())
    }

    fn next_state(&self, records: &[FlowRecord], received_us: u64) -> Result<State, String> {
        let mut next = self.state.clone();
        if self.uncertain {
            next.gaps += 1;
        }
        next.recent.retain(|_, value| {
            value
                .first_end_us
                .map_or(true, |first| received_us.saturating_sub(first) < RECENT_US)
        });
        for record in records {
            if record.generation == 0
                || record.incarnation == 0
                || record.sequence == 0
                || record.owner >= 2
                || record.slot >= 65536
                || record.last_seen < record.first_seen
                || record.activity_utc_us == 0
            {
                next.rejected += 1;
                next.gaps += 1;
                continue;
            }
            let key = format!("{}:{}:{}", record.generation, record.owner, record.slot);
            let mut delta = Counts {
                packets: record.packets,
                bytes: record.bytes,
            };
            let old = next.baselines.get(&key);
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
                    next.rejected += 1;
                    continue;
                }
                if record.incarnation == previous.incarnation {
                    if record.sequence - previous.sequence != 1 {
                        next.gaps += 1;
                    }
                    for i in 0..2 {
                        delta.packets[i] -= previous.packets[i];
                        delta.bytes[i] -= previous.bytes[i];
                    }
                } else if !previous.ended {
                    next.gaps += 1;
                }
            }
            if old.map_or(true, |b| b.record.incarnation != record.incarnation)
                && record.sequence != 1
            {
                next.gaps += 1;
            }
            if record.clock_changed
                && old.map_or(true, |b| {
                    b.record.incarnation != record.incarnation || !b.record.clock_changed
                })
            {
                next.clock_changes += 1;
            }
            if delta.packets != [0; 2] || delta.bytes != [0; 2] {
                let minute = record.activity_utc_us / 60_000_000 * 60;
                next.minutes.entry(minute).or_default().add(&delta)?;
                next.totals.add(&delta)?;
                next.first_activity_us = Some(
                    next.first_activity_us
                        .map_or(record.activity_utc_us, |v| v.min(record.activity_utc_us)),
                );
                next.last_activity_us = Some(
                    next.last_activity_us
                        .map_or(record.activity_utc_us, |v| v.max(record.activity_utc_us)),
                );
            }
            let baseline = Baseline {
                record: record.clone(),
                first_end_us: record.ended.then_some(received_us),
            };
            if record.ended {
                next.ended += 1;
                next.recent.insert(
                    format!("{received_us:020}:{key}:{}", record.incarnation),
                    baseline.clone(),
                );
            }
            next.baselines.insert(key, baseline);
            next.accepted += 1;
        }
        Ok(next)
    }

    pub fn mark_gap(&mut self) {
        self.uncertain = true;
    }

    pub fn close(&mut self) -> Result<(), String> {
        let mut next = self.state.clone();
        next.open_session = false;
        if self.uncertain {
            next.gaps += 1;
        }
        self.commit(next)
    }

    pub fn query(&self) -> serde_json::Value {
        // Fixed bounded response from maintained counters, never a raw-record
        // rescan. A sparse query can span more than 48 hours; report its bounds.
        let minutes: BTreeMap<_, _> = self
            .state
            .minutes
            .iter()
            .rev()
            .take(MAX_QUERY_MINUTES)
            .collect();
        let recent: BTreeMap<_, _> = self.state.recent.iter().rev().take(128).collect();
        serde_json::json!({ "schema": 1, "storage": "atomic_json_snapshot",
            "packets": self.state.totals.packets, "bytes": self.state.totals.bytes,
            "minutes": minutes, "ended": self.state.ended, "recent": recent,
            "recent_count": self.state.recent.len(), "recent_query_limit": 128,
            "minute_query_limit": MAX_QUERY_MINUTES,
            "minute_query_truncated": self.state.minutes.len() > MAX_QUERY_MINUTES,
            "stored_minute_count": self.state.minutes.len(),
            "baselines": self.state.baselines.len(), "accepted": self.state.accepted,
            "rejected": self.state.rejected, "save_error": self.save_error,
            "coverage": { "scope": "observed_flows", "incomplete": self.state.gaps != 0 || self.uncertain,
                "gaps": self.state.gaps, "recoveries": self.state.recoveries,
                "clock_changes": self.state.clock_changes,
                "first_activity_us": self.state.first_activity_us,
                "last_activity_us": self.state.last_activity_us },
            "open_session": self.state.open_session, "snapshot_limit_bytes": MAX_SNAPSHOT })
    }
}
