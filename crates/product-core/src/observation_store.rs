//! Minimal transactional overall-window store. No raw event log or repository framework.
use crate::observation::FlowRecord;
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
const MAX_RECENT: usize = 32768;
const MAX_MINUTES: usize = 262144;
const MAX_DIRTY: usize = 4096;
const FLUSH_ROWS: usize = 2048;
const FLUSH_INTERVAL: Duration = Duration::from_secs(1);
// The 256 MiB owner budget includes the retained <=64 MiB predecessor,
// <=64 MiB database (indexes included), <=81 MiB WAL and bookkeeping. With
// cache spilling disabled, one bounded transaction writes each database page
// at most once at commit. Checkpoint before another transaction at 16 MiB.
const DATABASE_LIMIT: u64 = 64 * 1024 * 1024;
const WAL_LIMIT: u64 = 16 * 1024 * 1024;
const MAX_QUERY_MINUTES: usize = 2880;
const RECENT_US: u64 = 24 * 60 * 60 * 1_000_000;
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
}
#[derive(Clone, Serialize, Deserialize)]
struct Baseline {
    record: FlowRecord,
    first_end_us: Option<u64>,
}
#[derive(Clone, Serialize, Deserialize)]
struct State {
    baselines: BTreeMap<String, Baseline>,
    recent: BTreeMap<String, Baseline>,
    minutes: BTreeMap<u64, Counts>,
    #[serde(flatten)]
    meta: Metadata,
}
#[derive(Clone, Serialize, Deserialize)]
struct Metadata {
    schema: u32,
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
impl Default for Metadata {
    fn default() -> Self {
        Self {
            schema: 1,
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
impl Default for State {
    fn default() -> Self {
        Self {
            baselines: BTreeMap::new(),
            recent: BTreeMap::new(),
            minutes: BTreeMap::new(),
            meta: Metadata::default(),
        }
    }
}
#[derive(Default)]
struct Dirty {
    baselines: BTreeSet<String>,
    recent: BTreeSet<String>,
    minutes: BTreeSet<u64>,
    meta: bool,
}
impl Dirty {
    fn len(&self) -> usize {
        self.baselines.len() + self.recent.len() + self.minutes.len()
    }
}

const UPSERT_ROW: &str = "INSERT INTO observation(kind,key,value) VALUES(?1,?2,?3)
    ON CONFLICT(kind,key) DO UPDATE SET value=excluded.value";

fn put_row(
    statement: &mut rusqlite::Statement<'_>,
    kind: i32,
    key: &str,
    value: &impl Serialize,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if key.len() > 80 || bytes.len() > 4096 {
        return Err("observation_row_capacity".into());
    }
    statement
        .execute(params![kind, key, bytes])
        .map_err(|e| e.to_string())?;
    Ok(())
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
    maintenance_pending: bool,
}
impl ObservationStore {
    pub fn open(path: &Path) -> Result<Self, String> {
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
            > DATABASE_LIMIT
        {
            return Err("observation_database_capacity".into());
        }
        let db = Connection::open(&database).map_err(|e| e.to_string())?;
        db.busy_timeout(Duration::ZERO).map_err(|e| e.to_string())?;
        db.execute_batch(
            "PRAGMA page_size=4096; PRAGMA cache_size=-2048; PRAGMA mmap_size=0;
            PRAGMA synchronous=FULL; PRAGMA max_page_count=16384; PRAGMA cache_spill=OFF;
            CREATE TABLE IF NOT EXISTS observation (kind INTEGER NOT NULL, key TEXT NOT NULL,
              value BLOB NOT NULL, PRIMARY KEY(kind,key)) WITHOUT ROWID;",
        )
        .map_err(|e| e.to_string())?;
        let page_size: i64 = db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(|e| e.to_string())?;
        let oversized: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM observation WHERE length(key)>80 OR length(value)>4096)", [], |r| r.get(0)).map_err(|e| e.to_string())?;
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
        let state = if let Some(ref meta) = meta {
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
        Self::validate_state(&state)?;
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
            maintenance_pending: false,
        };
        if meta.is_none() {
            store.migrate()?;
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
            != 1 + self.state.baselines.len() + self.state.recent.len() + self.state.minutes.len()
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
        {
            return Err("observation_state_capacity".into());
        }
        Ok(())
    }

    fn validate_state(state: &State) -> Result<(), String> {
        Self::validate_bounds(state)?;
        let mut totals = Counts::default();
        for (minute, counts) in &state.minutes {
            if minute % 60 != 0 {
                return Err("observation_invalid_minute".into());
            }
            totals.add(counts)?;
        }
        if totals.packets != state.meta.totals.packets || totals.bytes != state.meta.totals.bytes {
            return Err("observation_inconsistent_totals".into());
        }
        for (key, baseline) in &state.baselines {
            let r = &baseline.record;
            if key != &format!("{}:{}:{}", r.generation, r.owner, r.slot)
                || !Self::valid_record(r)
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
                || key
                    != &format!(
                        "{first:020}:{}:{}:{}:{}",
                        r.generation, r.owner, r.slot, r.incarnation
                    )
            {
                return Err("observation_invalid_lifecycle".into());
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
            && record.last_seen >= record.first_seen
            && record.activity_utc_us != 0
            && record.addresses.len() <= 32
    }

    pub fn has_pending(&self) -> bool {
        self.dirty.meta || self.dirty.len() != 0 || self.maintenance_pending
    }

    pub fn wait_timeout_ms(&self) -> i32 {
        if !self.has_pending() {
            return -1;
        }
        FLUSH_INTERVAL
            .saturating_sub(self.last_flush.elapsed())
            .as_millis()
            .max(1) as i32
    }

    pub fn flush(&mut self) -> Result<(), String> {
        self.last_flush = Instant::now();
        if !self.has_pending() {
            return Ok(());
        }
        let result = if !self.dirty.meta && self.dirty.len() == 0 {
            self.checkpoint()
        } else {
            self.write_dirty().and_then(|()| {
                // FULL synchronous COMMIT already succeeded. A later checkpoint
                // failure must not report these contributions as uncommitted.
                self.committed = self.state.meta.clone();
                self.dirty = Dirty::default();
                self.commits += 1;
                self.checkpoint()
            })
        };
        match &result {
            Ok(()) => {
                self.save_error = None;
                self.uncertain = false;
            }
            Err(e) => {
                self.save_error = Some(e.clone());
                if !self.uncertain {
                    self.mark_gap();
                }
                self.uncertain = true;
            }
        }
        result
    }

    fn write_dirty(&mut self) -> Result<(), String> {
        if std::fs::metadata(format!("{}-wal", self.path.display())).map_or(0, |m| m.len())
            >= WAL_LIMIT
        {
            self.checkpoint()?;
        }
        let tx = self.db.transaction().map_err(|e| e.to_string())?;
        {
            let mut put = tx.prepare_cached(UPSERT_ROW).map_err(|e| e.to_string())?;
            for key in &self.dirty.baselines {
                put_row(&mut put, 1, key, &self.state.baselines[key])?;
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
                put_row(&mut put, 3, &key.to_string(), &self.state.minutes[key])?;
            }
            put_row(&mut put, 0, "", &self.state.meta)?;
        }
        tx.commit().map_err(|e| e.to_string())
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
        self.maintenance_pending = false;
        Ok(())
    }

    pub fn consume(&mut self, records: &[FlowRecord], received_us: u64) -> Result<(), String> {
        // A failed flush does not stop the live merge while dirty capacity is
        // still available. Retry at most once per interval, never per packet.
        let flush_error = if self.last_flush.elapsed() >= FLUSH_INTERVAL {
            self.flush().err()
        } else {
            None
        };
        // Expire oldest ended details with bounded deletion work. The full
        // minute/hour/day retention chain remains the later retention slice.
        while self.dirty.len() < MAX_DIRTY {
            let expired = self
                .state
                .recent
                .first_key_value()
                .and_then(|(key, value)| {
                    value
                        .first_end_us
                        .filter(|first| received_us.saturating_sub(*first) >= RECENT_US)
                        .map(|_| key.clone())
                });
            let Some(key) = expired else {
                break;
            };
            self.dirty.meta = true;
            self.state.recent.remove(&key);
            self.dirty.recent.insert(key);
        }
        for record in records {
            if self.dirty.len() + 3 > MAX_DIRTY {
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
        if self.dirty.len() >= FLUSH_ROWS && self.save_error.is_none() {
            self.flush()?;
        }
        if let Some(error) = flush_error {
            return Err(error);
        }
        Ok(())
    }

    fn consume_one(&mut self, record: &FlowRecord, received_us: u64) -> Result<(), String> {
        self.dirty.meta = true;
        if !Self::valid_record(record) {
            self.state.meta.rejected = self.state.meta.rejected.saturating_add(1);
            self.state.meta.gaps = self.state.meta.gaps.saturating_add(1);
            return Ok(());
        }
        let key = format!("{}:{}:{}", record.generation, record.owner, record.slot);
        let mut delta = Counts {
            packets: record.packets,
            bytes: record.bytes,
        };
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
        if delta.packets != [0; 2] || delta.bytes != [0; 2] {
            let minute = record.activity_utc_us / 60_000_000 * 60;
            if !self.state.minutes.contains_key(&minute) && self.state.minutes.len() >= MAX_MINUTES
            {
                return Err("observation_minute_capacity".into());
            }
            let mut count = self.state.minutes.get(&minute).copied().unwrap_or_default();
            let mut totals = self.state.meta.totals;
            count.add(&delta)?;
            totals.add(&delta)?;
            self.state.minutes.insert(minute, count);
            self.state.meta.totals = totals;
            self.dirty.minutes.insert(minute);
            self.state.meta.first_activity_us = Some(
                self.state
                    .meta
                    .first_activity_us
                    .map_or(record.activity_utc_us, |v| v.min(record.activity_utc_us)),
            );
            self.state.meta.last_activity_us = Some(
                self.state
                    .meta
                    .last_activity_us
                    .map_or(record.activity_utc_us, |v| v.max(record.activity_utc_us)),
            );
        }
        let baseline = Baseline {
            record: record.clone(),
            first_end_us: record.ended.then_some(received_us),
        };
        if record.ended {
            self.state.meta.ended = self.state.meta.ended.saturating_add(1);
            let recent_key = format!("{received_us:020}:{key}:{}", record.incarnation);
            self.dirty.recent.insert(recent_key.clone());
            self.state.recent.insert(recent_key, baseline.clone());
        }
        self.dirty.baselines.insert(key.clone());
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
        let minutes: BTreeMap<_, _> = self
            .state
            .minutes
            .iter()
            .rev()
            .take(MAX_QUERY_MINUTES)
            .collect();
        let recent: BTreeMap<_, _> = self.state.recent.iter().rev().take(128).collect();
        serde_json::json!({ "schema": 1, "storage": "sqlite", "visibility": "live_including_pending",
            "persistence": { "packets": self.committed.totals.packets, "bytes": self.committed.totals.bytes,
                "accepted": self.committed.accepted, "pending_rows": self.dirty.len(), "pending": self.dirty.meta || self.dirty.len() != 0,
                "maintenance_pending": self.maintenance_pending,
                "commits": self.commits, "checkpoints": self.checkpoints, "error": self.save_error },
            "limits": { "dirty_rows": MAX_DIRTY, "baselines": MAX_BASELINES, "recent": MAX_RECENT,
                "minutes": MAX_MINUTES, "database_bytes": DATABASE_LIMIT, "budget_bytes": 256*1024*1024 },
            "packets": self.state.meta.totals.packets, "bytes": self.state.meta.totals.bytes,
            "minutes": minutes, "ended": self.state.meta.ended, "recent": recent,
            "recent_count": self.state.recent.len(), "recent_query_limit": 128,
            "minute_query_limit": MAX_QUERY_MINUTES,
            "minute_query_truncated": self.state.minutes.len() > MAX_QUERY_MINUTES,
            "stored_minute_count": self.state.minutes.len(),
            "baselines": self.state.baselines.len(), "accepted": self.state.meta.accepted,
            "rejected": self.state.meta.rejected, "save_error": self.save_error,
            "coverage": { "scope": "observed_flows", "incomplete": self.state.meta.gaps != 0 || self.uncertain,
                "gaps": self.state.meta.gaps, "recoveries": self.state.meta.recoveries,
                "clock_changes": self.state.meta.clock_changes,
                "first_activity_us": self.state.meta.first_activity_us,
                "last_activity_us": self.state.meta.last_activity_us },
            "open_session": self.state.meta.open_session, "legacy_input_limit_bytes": MAX_SNAPSHOT })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
