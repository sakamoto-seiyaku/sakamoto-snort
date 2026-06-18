## Context

Flow Telemetry records are produced from NFQUEUE packet hot paths. The current packet topology splits INPUT and OUTPUT into separate queue ranges, so two worker threads can concurrently update and export the same conntrack telemetry entry for opposite directions of one flow.

The entry counters are relaxed atomics and only increase, but the current producer forms local counter snapshots before acquiring `exportInProgress`. A later packet can export a newer snapshot first; the earlier packet can then acquire the guard and export stale counters with a newer `recordSeq`. This produces consumer-visible counter rollbacks even though the in-memory counters did not roll back.

## Goals / Non-Goals

**Goals:**

- Guarantee same-flow `FLOW` records are monotonic by `recordSeq` for cumulative counters and `lastSeenNs`.
- Preserve the hot-path model: lock-free counter increments, no per-packet mutex, no global lock, no I/O, no dynamic allocation, no string formatting.
- Keep the existing best-effort ring write and `recordSeq`-after-success semantics.
- Make each exported record internally consistent: totals equal the per-direction sums in that payload.

**Non-Goals:**

- No NFQUEUE topology rewrite, shared queue pool, or per-flow steering in this change.
- No Flow Telemetry ABI or native consumer decoder change.
- No attempt to provide a perfectly atomic snapshot of all metadata fields outside the export serialization point.

## Decisions

1. **Two-stage export decision**

- Choice: keep the current guard-free due check as a cheap prefilter, then acquire `exportInProgress` only if the flow might need an export. After acquiring the guard, re-read counters, `lastExport*`, decision/rule state, and timestamps, then recompute `BEGIN`/`UPDATE` and due conditions.
- Rationale: this fixes stale export snapshots without turning every telemetry-active packet into a locked update.
- Alternative rejected: guard or mutex around every telemetry counter update. That would serialize high-throughput bidirectional flows and increase NFQUEUE tail latency.

2. **Export payloads use fresh guard-protected snapshots**

- Choice: payload fields that drive rollback reports are read after `exportInProgress` is acquired. `recordSeq` is assigned from the current stored sequence in the same guarded window and is stored only after a successful ring write.
- Rationale: successful same-flow exports are already serialized by `exportInProgress`; moving snapshot formation into that window creates a clear linearization point.

3. **Monotonic `lastSeenNs`**

- Choice: update `lastSeenNs` with an atomic max helper rather than a plain store.
- Rationale: split INPUT/OUTPUT workers can process packets with different timestamps out of order. An older worker must not overwrite a newer observed packet time.
- Trade-off: this adds a small CAS loop per telemetry-active packet. It is bounded, uses relaxed memory order, and only runs when Flow Telemetry has an active consumer.

4. **Known direction requirement and derived exported totals**

- Choice: require packet telemetry producers to pass `packetDir=in|out`; observations with `packetDir=unknown` are ignored before conntrack entry lookup/allocation. Continue maintaining total counter atomics for cheap threshold prechecks, but encode `totalPackets` and `totalBytes` from the fresh per-direction snapshot for accepted observations.
- Rationale: exported records should satisfy `total == in + out`. Ignoring unknown-direction observations keeps the hot path branch cheap and prevents mixed known/unknown observations from making derived totals exclude previously counted packets.

## Risks / Trade-offs

- [Risk] Extra atomic loads in export path increase overhead -> Mitigation: the additional reads happen only after the cheap precheck says export might be due.
- [Risk] Monotonic timestamp CAS adds per-packet cost while telemetry is active -> Mitigation: relaxed CAS on one field is cheaper than per-entry locking and is limited to Flow Telemetry consumer sessions.
- [Risk] Guard-inner recomputation suppresses records that the guard-free precheck thought were due -> Mitigation: this is intended; another thread may have already exported the progress.
- [Risk] Metadata fields other than counters/time can still reflect latest packet context rather than a fully transactional packet snapshot -> Mitigation: this change targets rollback correctness without adding a seqlock or per-packet lock to the hot path.
