# SQLite observation storage discussion — 2026-09-26

User invoked `grill-with-docs` and selected: “就使用 sqlite吧 跨平台也1可用”.
This is a design discussion, not implementation or benchmark completion.
Ask one substantive decision at a time and record the answer. Do not reopen
already accepted rules merely because the storage engine changes.

## Accepted direction and existing constraints

- Embedded SQLite in the Rust observation backend; recorded in
  [ADR-0010](../adr/0010-sqlite-observation-storage.md).
- VPP configuration ownership and the selected `svm_msg_q` transport stay as
  established by ADR-0009 and the user's T20 selection.
- Incremental maintained views, cumulative deduplication, END tail handling,
  atomic baseline/lifecycle/window advancement and explicit missing coverage
  remain the existing behavior requirements, not new choices.
- The formal normal-observation budget is 256 MiB including indexes and
  maintenance logs with working space reserved; T22's 32 MiB JSON guard is
  only an experimental implementation limit.
- E01 publication approval was received and its report comment was fully read
  back (`5a252001-9541-4899-8283-780ecec565f5`). At that publication boundary E01 remained In Progress;
  no new storage implementation or T23 dispatch has occurred.

## Question 1 — existing development JSON history (accepted)

Current Android history survives runtime/profile cleanup in
`files/observation/overall.json`. E01 restored the accepted history byte-for-byte;
the latest accepted test totals are 318/318 directional packets. See
[T22's contract](../interfaces/T22_MINUTE_WINDOWS.md) and
[E01's report](../testing/2026-09-26_E01_PIPELINE_RESULTS.md).

Recommendation for discussion: migrate an existing valid JSON store once into
SQLite without recounting cumulative traffic. Keep the original file until the
transaction and verification succeed; on failure expose an error rather than
silently initialize empty history. Whether this development-only predecessor
needs a migration path is a user decision, not an assumed requirement.

Alternative: the first SQLite version starts fresh, with explicit history-reset
semantics and deliberate handling of the existing development file. No deletion
or reset is authorized by this pending question.

User accepted: “一次性迁移可以”. Implement one-time migration of valid existing
JSON history with preserved cumulative results, retaining the original until
success and reporting migration failure without silently resetting history.
No file migration or deletion has been performed in this discussion.

WAL mode, durability settings, schema and benchmark implementation choices have
not been approved by implication.

## Alternative storage shapes — discussion

The user asks whether a better approach exists beyond a database. Relevant
alternatives are an append-only change log with periodic checkpoints, partitioned
time-bucket files with a separate consumption baseline, or another embedded
key/value engine. These can reduce whole-file rewriting, but they must still
provide atomic baseline/window advancement, interrupted-write recovery, bounded
retention and query support. No alternative has been selected or measured here.
SQLite remains the selected direction; an alternatives question does not revoke
that choice.

## Initial version — accepted shape

User: “还是那样不能阻塞vpp sqlire 加上内存合并批处理 应该作为初版足够了。”

- SQLite plus Rust-side in-memory merging and batch persistence is accepted for
  the initial version.
- VPP never waits for the database, checkpointing, Rust progress or recovery.
  Existing bounded export and explicit gap semantics continue to apply.
- Batching must remain bounded. A full or failed downstream cannot justify an
  unbounded pending-record queue or a packet-domain wait.
- One transaction advances the affected committed baselines, lifecycle and
  minute contributions consistently. Exact batching parameters remain engineering
  defaults to be measured, not user-approved performance claims.

## Question 2 — uncommitted batch failure boundary (accepted)

Recommendation: an unexpected process exit may lose the current uncommitted
in-memory batch. Already committed totals must remain consistent and must not be
counted twice after recovery. Restart exposes incomplete coverage; it does not
promise recovery of records no longer available from the lossy export channel.
Visible in-memory freshness must not be described as durable commitment.

User accepted: “接受 这一点观测丢失完全没啥关系”. Uncommitted observations may
be lost on abnormal exit; committed consistency, deduplication and explicit
incomplete coverage remain required. This does not authorize packet loss or
loss of already acknowledged durable statistics.

No interval, row-count threshold, WAL/synchronous setting or Product
implementation has been selected by implication.

## Question 3 — query visibility during batching (accepted)

Recommendation: normal queries include the latest accepted in-memory aggregate,
combining committed history with pending deltas exactly once. Report persistence
progress/errors separately; do not call these fresh totals fully durable.
After a crash the uncommitted tail may disappear, within the accepted loss
boundary. Alternative: queries show committed-only history and therefore lag
until the next batch is committed. This is an API data contract, not a UI design.

User accepted: “最好包含 但是这里设计不要太复杂”. Normal queries include pending
in-memory increments. Keep the existing backend-maintained aggregate as the live
query view and a bounded dirty set for SQLite updates; committing clears dirty
state only after success and does not add those increments to live totals again.
Do not introduce a second independent aggregation engine, generic cache framework
or per-record durability tracking. Preserve simple persistence status/error
reporting separately from the live totals.

## Proposed design closure

Resolved product choices: SQLite; one-time existing-history migration; bounded
Rust in-memory merging and batch transactions; no VPP wait; accepted loss of
uncommitted observations on abnormal exit; live queries include pending totals.
Existing accounting, retained-history policy and explicit incomplete-coverage
semantics remain binding. Exact schema, batching thresholds, SQLite settings and
checkpoint scheduling are implementation choices constrained by those semantics
and measured against E01; they do not warrant a new generalized storage framework.
User confirmed closure: “可以 需要更新任务吗？”. The resolved direction is
authorized for implementation and comparative remeasurement. Update Plane to
record E01's user decision and track the new implementation/remeasurement as a
separate prerequisite before T23. Product work has not started at this point.


## Task update after accepted closure

[SAKAMOTO-288 / E02](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/9f590981-cdd8-4e9e-9e47-b6c3ba660a61) is the separate ready-for-agent implementation and remeasurement prerequisite under SAKAMOTO-251. It depends on E01 and blocks T23 while all original edges are preserved. The user's selected direction satisfies E01's required decision gate; the experimental findings stay unchanged.

E02 preserves the accepted semantics and compares matched Host 0/1k/10k/60k and Android 0/10k history cases, including deferred writes/checkpoint costs and failure/restart invariants. Schema, batch defaults and SQLite settings remain implementer choices under these constraints. Successful ordinary implementation and representative verification can unblock T23; there is no additional mandatory selection gate. Actual major findings or changes to accepted behavior return to discussion. This task update does not implement E02.
