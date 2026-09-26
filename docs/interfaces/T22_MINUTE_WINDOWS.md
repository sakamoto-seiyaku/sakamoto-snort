# T22 persistent overall minutes

Storage implementation update: [E02 SQLite observation](E02_SQLITE_OBSERVATION.md)
supersedes the JSON persistence and committed-only query behavior described
below. This document retains T22's original delivery contract and wire/time
semantics; use E02 for the current live/pending and persistence boundary.

The agreed test seams are the existing Product observation ingestion/query API,
the real C transport → Rust consumer boundary, and filesystem interruption.
These implement SAKAMOTO-273's Host, Linux and Android verification requirements.

Rust owns one observation consumer and a separate observation store. VPP remains
the configuration writer. No queue ACK, resend, UI ingestion or new view is added.
The first storage implementation is an atomically replaced JSON snapshot: minimum
slot baselines, lifecycle, overall ORIG/REPLY minute counters and coverage metadata
advance together. A separate advisory lock prevents concurrent writers. Each
bounded drained batch is committed by file fsync, rename and directory fsync.
The supplied path has an existing, durably established storage root (Android's
application files directory). Rust may create its immediate observation directory;
it syncs that directory's containing directory on every open, including retries
after failed or interrupted creation. It does not implicitly create a directory tree.
The snapshot is deliberately replaceable; write amplification, startup cost and
space are inputs to E01, not an approved release storage engine or quota policy.

Observation wire V2 adds `activity_utc_us` before addresses (offset 120), retaining
owner monotonic first/last activity for ordering and expiry. IPv4/IPv6 lengths are
136/160 bytes; queue classes become 144/160 bytes. VPP samples wall time on real
activity and retains that value for pending flush and END. A backwards wall clock
does not reject monotonic growth: it can update an earlier UTC minute. No old bucket
is moved. A clock-discontinuity flag exposes detected changes rather than pretending
that a delayed END occurred at receive time. UTC placement remains approximate;
coalesced growth goes to its last activity minute without interpolation.

Identity is generation/owner/slot/incarnation with monotonic sequence and cumulative
directional counters. Duplicate/stale updates and duplicate END cannot count again
or move first-END time. END growth is committed before its lifecycle changes.
An interrupted consumer leaves a durable open-session marker. Restart preserves
committed totals and baselines and exposes incomplete coverage; it does not invent
an END or recover records the bounded queue has already lost. A new runtime
generation is required after a transport consumer disconnect, as in T21.
Every consumer termination records an incomplete coverage boundary, including an
empty overview, because producer quiescence and complete draining are not proven.

The normal observation query reports maintained minutes, committed totals, errors,
coverage and baseline/lifecycle counts. It does not rescan raw events. This ticket
does not implement compression, multi-view attribution, full retention or the
256 MiB release budget. A bounded snapshot size failure preserves the previous
baseline and reports a save error, never deleting active state to recount from zero.

The snapshot guard is 32 MiB, excluding the temporary replacement and in-memory
copies; it is not a complete storage quota. A commit contains at most 256 normal
records drained from the two owners. The query returns at most 2,880 newest
nonempty minute entries and 128 recent ended entries, with truncation/count fields.
Sparse minutes may span more than 48 hours; total counters cover all retained
minutes. Recent details are pruned opportunistically on writes from first-END
consumption time. This is not the later complete retention/rollup policy.

`consumer.store_error` retains the last save/open error in that consumer lifetime;
`consumer.persistent.save_error` describes its latest save attempt. Coverage
bounds describe activity timestamps used by retained contributions, not an
uninterrupted protection interval. `gaps` counts observed gap indications, not
missing packets. `clock_changes` counts instances with a detected wall/monotonic
offset discontinuity greater than one second, not all operating-system clock
events. Basic VPP counters remain separately queryable and are never adjusted
to force agreement with incomplete history.

Android RuntimeService passes the application-owned
`files/observation/overall.json` to the additive C entrypoint
`sakamoto_product_core_observation_start_at`; this path survives profile/runtime
cleanup. The original C start entrypoint remains ABI-compatible. Host acceptance
uses `observation-serve <api-socket> <generation> <persistent-file>`; callers
requiring cross-generation history must supply a path outside the runtime folder.
The ordinary observation query reads the backend-maintained in-memory summary.
An open/save failure is reported there and does not become a packet-path wait.
