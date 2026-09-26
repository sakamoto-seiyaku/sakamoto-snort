---
status: accepted
date: 2026-09-26
---

# SQLite for Rust-owned observation storage

The user selected SQLite after reviewing E01's whole-snapshot write amplification.
Rust will use embedded SQLite for observation storage, replacing T22's provisional
whole-file JSON snapshot. Cross-platform availability and maintaining a familiar
transactional engine are preferred to building a custom incremental file store.
The [E01 report](../testing/2026-09-26_E01_PIPELINE_RESULTS.md) is the comparison
baseline; no SQLite performance or implementation acceptance is claimed yet.

This refines the storage implementation under [ADR-0009](0009-unified-rules-and-vpp-owned-configuration.md).
VPP remains the configuration-file writer and packet-domain owner. Rust retains
observation consumption, maintained views and separate storage. Existing counting,
atomic baseline/lifecycle/window advancement, incomplete-coverage and retention
requirements remain authoritative; selecting SQLite does not relax them.

The user additionally selected bounded in-memory merging and batch persistence
in Rust for the initial version. SQLite work, checkpointing and storage failures
must never make VPP wait. Export remains bounded and loss-tolerant with explicit
coverage gaps; batching is not permission for unbounded buffering or silent
relaxation of committed-data guarantees.

The user accepts loss of the current uncommitted observation batch on abnormal
exit. Committed data must remain transactionally consistent and deduplicated;
recovery continues to expose incomplete coverage rather than invent missing data.

Normal queries include the latest in-memory increments. Keep a single maintained
live aggregate and bounded dirty state for persistence; successful commits must
not add pending contributions to the live totals a second time. Persistence
status and errors remain separate from query freshness.

The user also accepted one-time migration of valid development JSON history,
retaining the original until migration succeeds and reporting failure without
silently resetting history. The [SQLite discussion](../reviews/2026-09-26_SQLITE_OBSERVATION_DISCUSSION.md)
records design closure and authorization to implement and remeasure. Concrete
schema, bounded batch thresholds and checkpoint scheduling remain engineering
choices under the accepted semantics. No Product completion is claimed by this ADR.
