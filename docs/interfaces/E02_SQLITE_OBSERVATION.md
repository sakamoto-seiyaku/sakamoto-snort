# E02 SQLite observation boundary

SAKAMOTO-288 implements the storage direction in ADR-0010. The public test seams
remain T22's Rust store ingestion/query, actual C transport → Rust consumer/API,
and filesystem/database interruption. No packet wire or configuration ownership
changes. The caller still supplies the legacy `overall.json` location; Rust owns
the sibling `overall.sqlite3`, SQLite journal files and existing advisory lock.

The ordinary `consumer.persistent` response is the maintained **live** view,
including accepted uncommitted increments. `visibility=live_including_pending`
makes that boundary explicit. `persistence` separately reports committed totals,
accepted count, pending state/row count, separate maintenance-pending state,
commit/checkpoint counts and latest error. The storage identity is `sqlite` with
schema 1; wire V2 and the C start ABI are unchanged.
Existing minute, lifecycle and coverage fields retain their meanings. Committing
clears dirty keys and updates the small persistence-status snapshot; it does not
add counts to live state again. `consumer.store_error` remains the last error in
that consumer lifetime, while the store's error describes the latest attempt.

One Rust-owned connection uses bundled SQLite, WAL, `synchronous=FULL`, zero busy
timeout and no SQLite automatic checkpoint. Rust checkpoints immediately after
each successful batch, keeping its maintenance cost inside that batch; a failed
checkpoint is reported separately from the already successful commit boundary. One transaction upserts affected baseline,
recent END and minute rows together with overall metadata. Payloads are bounded
typed JSON values within SQLite rows, preserving full unsigned counters without
SQL signed-integer coercion. They are not a whole-history snapshot or raw log.
The single live aggregate is updated in place; no second aggregation pipeline,
backend selector or background work queue is introduced.

The consumer submits at a one-second monotonic deadline or 2,048 dirty rows,
with a maximum of 4,096 dirty keys. Its queue wait uses the next deadline, so idle
traffic tails commit without another packet. Failed writes retain dirty state
and retry no more often than the deadline; live merging continues while bounded
capacity remains. At capacity, further store input is rejected with explicit
incomplete coverage. VPP does not wait: existing bounded, lossy IPC remains its
only interaction. An abnormal exit may discard the pending batch; the committed
open-session marker exposes incomplete recovery. No replay is promised.

An existing valid JSON file imports once in one transaction. Input totals must
match maintained minutes, and baseline/lifecycle identities must be valid. The
metadata row is the committed import marker. Failure exposes an error and leaves
the original available for retry; successful migration retains the original as
a predecessor, never imports it again and never silently substitutes empty state.

The implementation bounds live baseline, recent END and minute row counts and
reserves database/journal/migration working space under the 256 MiB total envelope.
The database page limit includes indexes. Cache spilling is disabled to bound
per-transaction WAL work; checkpointing runs on the Rust consumer and never on a
VPP owner. These are conservative admission/workspace guards for this storage
slice, not the completed product retention policy. Full 48-hour minutes,
30-day hours, 180-day days and ordered quota reclamation belong to the existing
SAKAMOTO-279 / T27 ticket. E02 retains T22's 24-hour first-END expiry and does not
delete active baselines to make space or reset accounting.
