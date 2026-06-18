## Why

Flow Telemetry consumers can observe `counter rollbacks`: for the same `flowInstanceId`, `recordSeq` increases while cumulative packet/byte counters or `lastSeenNs` decrease. This is a producer-side correctness issue exposed by the current split INPUT/OUTPUT NFQUEUE worker topology, where both directions of one conntrack flow may update and export the same telemetry entry concurrently.

## What Changes

- Make `Conntrack` FLOW export linearize payload snapshots at the per-entry export guard, not before it.
- Preserve lock-free per-packet counter updates and keep the existing guard-free due precheck as a cheap "maybe export" filter.
- Re-read counters, `lastExport*`, decision key/rule state, and time state after acquiring `exportInProgress`; recompute `BEGIN`/`UPDATE` and due conditions inside the guard before encoding.
- Ensure exported cumulative totals are internally consistent with per-direction counters.
- Make telemetry `lastSeenNs` monotonic so older packet contexts cannot overwrite a newer packet timestamp.
- Keep the Flow Telemetry ABI and transport unchanged: no payload layout change, no new record type, no consumer decoder migration.
- Defer `shared queue pool / per-flow steering` to a later topology/performance change; this fix must not depend on queue affinity for correctness.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `flow-telemetry-records`: require same-flow FLOW records observed by increasing `recordSeq` to expose nondecreasing cumulative counters and nondecreasing `lastSeenNs`.

## Impact

- Affected code: `src/Conntrack.cpp`, host conntrack telemetry tests, and the Flow Telemetry records spec.
- Affected behavior: same-flow FLOW records become monotonic under concurrent INPUT/OUTPUT processing.
- Affected APIs: no public binary layout or control command changes.
- Dependencies: no new dependencies; implementation must preserve NFQUEUE hot-path constraints and avoid per-packet locks.
