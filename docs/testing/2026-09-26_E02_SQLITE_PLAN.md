# E02 implementation and matched remeasurement

SAKAMOTO-288 implements ADR-0010 and the [storage boundary](../interfaces/E02_SQLITE_OBSERVATION.md).
The approved comparison is E01's retained whole-JSON results versus this SQLite
implementation. There is no new engine-selection gate or invented numerical
performance threshold.

First verify public-store behavior: live pending visibility, no commit recount,
committed recovery, accepted uncommitted loss, END/stale/generation/clock cases,
valid and invalid legacy migration, interrupted/failed migration retry, atomic
transaction failure, busy/full storage, bounded pending state and checkpointing.
Use actual SQLite failures and process replacement where relevant. Existing C
transport/producer and Rust suites cover unchanged packet/IPC invariants.

Build Linux and Android from one recorded source closure. Reuse E01's experimental
startup controls and workload generator, without importing POC source. Product
overlays must restore exact bytes and preserve the 34 pre-existing dirty files.
Host matches 0/1k/10k/60k historical zero-contribution seeds and the low/burst/
sustained pressure workload; an empty-history full workload retains idle,
multiple active flows, turnover and parked-consumer coverage. Android matches
0/10k seeds with the full controlled-VPN workload, using the established bounded
192-flow parked phase. The real accepted Android history is separately preserved
and migrated; synthetic seeds use isolated stores.

Collect actual packet identities and endpoint results, VPP basic/Flow counts,
normal live API queries, committed status and database contents. Include both
directions and bytes, source/artifact/config/profile/generation identity and
rehashed negative mutations. Measure consumer/process CPU, process write bytes,
startup, RSS/HWM, live and durable freshness, database/WAL/maintenance footprint.
Close every cost window after delayed flush and required checkpoint, retaining
the work and elapsed settlement rather than reporting traffic-only costs.

The comparison identifies the old and new source closures and controls explicitly.
It cannot claim electrical energy, Doze, long-term thermal behavior, strict Root
A/B/C isolation, full attribution, full retention or release qualification. Root
ambient mixed-UID traffic remains a known scope limit. Retain failed probes and
perform only finite distinguishing follow-up tests. Complete independent Standards
and Spec reviews, fixes/rechecks, scoped commits, Plane read-back and an owner
handoff before treating E02 as complete.
