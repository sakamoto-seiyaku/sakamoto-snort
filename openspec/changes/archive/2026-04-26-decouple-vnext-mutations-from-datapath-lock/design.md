## Context

`mutexListeners` is currently used both as the packet / DNS datapath quiesce lock and as the outer lock for several vNext mutation commands. That means a large control-plane operation can hold the same lock that packet verdict and DNS decision windows need in shared mode.

The main offenders are not the vNext wire protocol or individual command schemas. The issue is the dispatch-level lock model: `DOMAINLISTS.IMPORT`, `DOMAINLISTS.APPLY`, `DOMAINRULES.APPLY`, `DOMAINPOLICY.APPLY`, `IPRULES.APPLY`, `CONFIG.SET`, and `METRICS.RESET` are treated as globally exclusive datapath operations even when most of their work is protected by manager-local locks or lock-free snapshot publish.

## Goals / Non-Goals

**Goals:**

- Keep packet / DNS verdict paths independent from long vNext mutation CPU, allocation, parse, compile, JSON, or filesystem I/O.
- Preserve control-plane mutation ordering by serializing vNext mutation commands with a control-plane mutex that is not used by packet / DNS hot paths.
- Preserve `RESETALL` semantics by making reset mutually exclusive with in-flight vNext mutations before it takes the datapath quiesce lock.
- Keep current vNext protocol, response shapes, and APPLY/IMPORT atomicity semantics.

**Non-Goals:**

- No vNext schema, command name, or JSON response change.
- No global transaction framework or universal prepared-artifact abstraction.
- No rewrite of manager-local locking unless implementation finds a concrete intermediate-state exposure.
- No attempt to solve detached session lifecycle, raw stream fd ownership, or signal shutdown latency in this change.

## Decisions

1. **Split lock responsibilities instead of building a transaction framework.**
   - `mutexListeners` remains the datapath quiesce lock for startup, `RESETALL`, and short packet / DNS shared windows.
   - A new process-level control mutation mutex serializes vNext mutation commands with each other.
   - Rationale: existing managers already provide local locks and snapshot publish; the fastest safe fix is to remove the wrong outer lock from the hot-path dependency chain.
   - Alternative rejected: prepared artifacts for every mutation command. It would be more invasive and duplicates manager-local transaction logic before proving a need.

2. **Make `RESETALL` wait for control mutations before quiescing datapath.**
   - `snortResetAll()` should acquire the save/reset coordinator, then the control mutation mutex, then `mutexListeners` exclusively.
   - vNext mutation dispatch should acquire only the control mutation mutex, then execute the handler without `mutexListeners`.
   - Rationale: reset must not interleave with apply/import state changes, but packet/DNS traffic should not wait behind ordinary mutations.

3. **Keep read paths conservative for this change.**
   - Read-only vNext commands may keep the existing shared `mutexListeners` behavior unless a specific test or profile shows it is a problem.
   - Rationale: this change targets high-risk long mutation commands and avoids broad lock churn.

4. **Use manager-local atomicity as the first implementation boundary.**
   - `IpRulesEngine` already publishes hot snapshots atomically; packet evaluation uses `hotSnapshot()`.
   - `DomainList` import already builds and persists outside its local publish lock, then swaps/rebuilds snapshots under its own mutex.
   - `RulesManager`, `BlockingListManager`, and domain policy/app managers should continue to own their internal consistency.
   - If a handler exposes intermediate state after the outer lock is removed, fix that manager with a narrow batch API rather than reintroducing `mutexListeners`.

## Risks / Trade-offs

- **Risk: reset and mutation deadlock** → Mitigate with a single documented lock order: save/reset coordinator → control mutation mutex → `mutexListeners`.
- **Risk: a manager exposes intermediate state that the old outer lock masked** → Mitigate by auditing each mutation handler after removing the outer lock and adding local batch APIs only where needed.
- **Risk: control mutations now block each other for longer** → Acceptable; this serialization is off the datapath hot path and preserves simple vNext mutation ordering.
- **Risk: legacy control still uses old locking** → Acceptable for this change; the finding targets vNext large mutation dispatch and legacy stream/control migration is separate.

## Migration Plan

- Implement as an internal runtime locking change with no protocol migration.
- Update concurrency docs to define the new lock responsibilities.
- Rollback is straightforward: restore the previous vNext dispatch lock classification if regression appears, though that reintroduces datapath stall risk.

## Open Questions

None.
