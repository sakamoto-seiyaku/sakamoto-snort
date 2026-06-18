## 1. Spec / control surface
- [x] 1.1 Extend `app-ip-l3l4-rules` spec: define minimal `ct` match dimensions + atomic validation rules.
- [x] 1.2 Add new `l4-conntrack-core` spec (minimal correctness + concurrency contract).

## 2. Conntrack core (C++ port)
- [x] 2.0 Define conntrack packet input model (TCP fields/ICMP fields) + fragment handling policy.
- [x] 2.1 Implement conntrack core module (IPv4 only): keying, table, timeouts, capacity/eviction policy.
  - Import OVS default timeout policy table (loose) for TCP/UDP/ICMP/other.
  - Define max-entries cap and overflow behavior (`invalid` + counter; no crash).
- [x] 2.2 Implement protocol trackers: TCP / ICMP / other(UDP+other).
- [x] 2.3 Implement sweep/expiration + deferred reclamation (epoch/QSBR baseline).
  - Lazy-expire on hit: expired entry is treated as miss.
  - Budgeted per-shard sweep with cursor; create-path triggers sweepBudget before insert.
  - Optional hot-path best-effort sweep: interval + try_lock; never blocks verdict.
  - QSBR read-side boundary at `conntrack.update(...)`; unlink → retireList → grace-period free.
- [x] 2.4 Add metrics hooks (optional): track ct table size/creates/evictions (non-hot-path).

## 3. Integration into IPRULES
- [x] 3.1 Add `ct` fields into rule definition + parsing + validation.
- [x] 3.2 Add `ct` fields into compiled matcher / PacketKeyV4 evaluation input.
  - Extend `PacketKeyV4` to include `ct.state/ct.direction` (and ensure decision cache keys on them).
  - Enforce evaluation order: `conntrack.update → build key(ct.*) → decision cache → classifier`.
- [x] 3.3 Plumb required TCP metadata from `PacketListener` to conntrack update call site (no extra copies).
- [x] 3.4 Add per-UID gating (default: `App` + `rulesEpoch` cached caps) to skip conntrack when uid has no `ct` consumers.
- [x] 3.5 Extend PREFLIGHT to account for `ct` usage (ensure bounded cost).
  - Define and implement per-UID `usesCt` detection (`ct.state != any || ct.direction != any`)

## 4. Tests
- [x] 4.1 Host unit tests: ct semantics for TCP/UDP/ICMP/other.
- [x] 4.2 Host concurrency tests: split in/out updates on same flow.
- [x] 4.3 Integration tests: control-plane parse/atomicity for `ct` keys.
- [x] 4.4 Unit test: gating cache refresh on rulesEpoch change (no stale caps).

## 5. Real-device verification
- [x] 5.1 Tier-1: functional matrix on device for `ct=new/established` rules.
- [x] 5.2 Tier-1: perf compare `ct off` vs `ct on` using existing perf baseline.
- [x] 5.3 Record results in `docs/testing/ip/` (baseline table + notes).

## 6. Docs sync (after implementation is verified)
- [x] 6.1 Update `docs/INTERFACE_SPECIFICATION.md` for the new `IPRULES.*` `ct` syntax and examples.
