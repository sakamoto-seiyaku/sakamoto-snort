## 1. ABI / Ring POC Tests First

- [x] 1.1 Add host tests for telemetry ring layout constants (`slotBytes`, `ringDataBytes`, `slotCount`, `maxPayloadBytes`) and explicit little-endian serialization helpers
- [x] 1.2 Add host tests for fixed-slot producer semantics: commit success, overwrite old committed slot, reject WRITING slot without wait/spin, record-too-large drop
- [x] 1.3 Add host tests for consumer ticket gap detection and per-flow `recordSeq` behavior after failed writes
- [x] 1.4 Add a device/integration test plan for a simulated frontend mmap reader that opens telemetry, receives fd, polls slots, and validates at least one synthetic test record path

## 2. Telemetry Ring / Session Core

- [x] 2.1 Implement RAII fd/shared-memory/session ownership classes for telemetry sessions (non-copyable, movable, no raw owning `new/delete`)
- [x] 2.2 Implement fixed-slot shared-memory ring allocation, session/ring header initialization, slot states, ticket reservation, payload copy, and commit
- [x] 2.3 Implement producer drop accounting for `consumerAbsent`, `slotBusy`, `recordTooLarge`, `disabled`, and `resourcePressure`
- [x] 2.4 Implement consumer ownership model: single active consumer, later OPEN preempts old session, CLOSE idempotent, old ring logically invalid after close/preempt/reset
- [x] 2.5 Implement synthetic/test-only record writer hook for ABI POC tests without connecting real packet/DNS hot paths

## 3. vNext Control Surface / State

- [x] 3.1 Add vNext `TELEMETRY.OPEN` / `TELEMETRY.CLOSE` handler with strict args validation and `level=off|flow`
- [x] 3.2 Implement Unix-domain-only fd passing for `TELEMETRY.OPEN(level=flow)` and reject TCP/non-fd-capable sessions with `INVALID_ARGUMENT` + hint
- [x] 3.3 Return OPEN metadata: `actualLevel`, `sessionId`, `abiVersion`, `slotBytes`, `slotCount`, `ringDataBytes`, `maxPayloadBytes`, `writeTicketSnapshot`
- [x] 3.4 Extend `METRICS.GET(name=telemetry)` with minimal channel health state and reject `args.app`
- [x] 3.5 Integrate RESETALL with telemetry session rebuild: invalidate old ring/session, clear telemetry state baseline, do not emit per-flow RESETALL END records

## 4. FLOW Record Producer

- [x] 4.1 Add binary `FLOW` payload encoder with `payloadVersion`, `flowRecordKind=BEGIN|UPDATE|END`, `flowInstanceId`, `recordSeq`, tuple/family/uid/interface/proto metadata, decision fields, and cumulative counters
- [x] 4.2 Extend conntrack/flow entry state with allocated `flowInstanceId`, last exported totals, last decision key, last export time, short TTL markers, and per-flow `recordSeq`
- [x] 4.3 Treat Flow Telemetry `level=flow` as a conntrack/flow observation consumer while preserving existing no-consumer conntrack gating when telemetry is off/absent
- [x] 4.4 Emit `BEGIN`, `UPDATE`, and `END` on packet-driven triggers: create, CT/decision change, packets/bytes threshold, max export interval, idle/TCP end/resource/telemetry-disabled retire
- [x] 4.5 Represent `IFACE_BLOCK` / IP `BLOCK` attempts in the unified flow table with `blockTtlMs`; never use a separate deny-flow table
- [x] 4.6 Ensure FlowRecord excludes Debug Stream fields (`wouldRuleId`, candidates, shadow/why-not, domain hints, domainRuleId, DNS↔IP mapping)

## 5. DNS_DECISION Record Producer

- [x] 5.1 Add binary `DNS_DECISION` payload encoder with blocked DNS decision fields, bounded inline `queryName` (255 bytes), policy source, optional domain rule attribution, timestamp, uid/userId/app metadata
- [x] 5.2 Hook DNS decision path to emit `DNS_DECISION` records only for blocked decisions and only through the telemetry exporter
- [x] 5.3 Ensure allowed DNS decisions do not emit `DNS_DECISION` and DNS records do not carry response IP details or IP count

## 6. Hot Path / Resource Safety

- [x] 6.1 Keep packet hot path to at most one exporter/config pointer read and pass the pointer/context downward; avoid repeated deep-path global checks
- [x] 6.2 Verify telemetry writes perform no socket I/O, JSON formatting, DNS/domain lookup, dynamic allocation, blocking locks, or unbounded scans on verdict paths
- [x] 6.3 Implement bounded sweep / expired-entry recovery before refusing new telemetry flow entries under flow table pressure
- [x] 6.4 Ensure telemetry failures never change packet or DNS verdict and only affect telemetry drop/state counters

## 7. Tests / Verification

- [x] 7.1 Run new host telemetry ring/session/record encoder tests
- [x] 7.2 Extend vNext host/integration tests for `TELEMETRY.OPEN/CLOSE`, strict reject, single-consumer preemption, TCP OPEN rejection, RESETALL rebuild, and `METRICS.GET(name=telemetry)`
- [x] 7.3 Extend device IP tests to cover `FLOW` records for IPv4/IPv6, TCP/UDP/ICMP/other, allow/default allow/block/iface block, and per-flow `recordSeq` gap visibility
  - Done: `tests/device/ip/cases/18_flow_telemetry_smoke.sh` validates the FLOW matrix on device, includes cross-family `flowInstanceId` uniqueness, and observes tiny-ring per-flow `recordSeq` gaps.
- [x] 7.4 Extend DNS device/integration tests to cover blocked-only `DNS_DECISION` records
  - Done: `18_flow_telemetry_smoke.sh` injects blocked and allowed DNS decisions and asserts only the blocked domain emits `DNS_DECISION`.
- [x] 7.5 Run host ASAN/UBSAN preset for changed tests and fix all memory/UB issues before review
  - Done: `snort-host-tests-asan` passed 214/214; `snort-host-tests-ubsan` passed 214/214. UBSAN keeps `undefined` enabled and disables only RapidJSON-triggered `pointer-overflow` instrumentation.
- [x] 7.6 Run a Flow Off vs Flow On performance comparison; target throughput drop <= 5%-10%, otherwise report p50/p95/p99 verdict path latency and bottleneck notes
  - Done: final device run completed 20,000,000 bytes both Flow Off and Flow On, `drop_pct=0.00` against target 10.00; off p50/p95/p99 = 79/479/1151 us, on p50/p95/p99 = 87/479/959 us.

## 8. Docs / Build / Validation

- [x] 8.1 Update `docs/INTERFACE_SPECIFICATION.md` with `TELEMETRY.OPEN/CLOSE`, fd passing limits, ring ABI defaults, record type summary, and `METRICS.GET(name=telemetry)`
- [x] 8.2 Update `docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md` only if implementation reveals a necessary decision correction
  - Reviewed: no decision correction needed; the discovered cross-family `flowInstanceId` collision was fixed in implementation and covered by host/device tests.
- [x] 8.3 Update CMake build wiring for new telemetry sources/tests
- [x] 8.4 Update `Android.bp` only when new production sources require it; do not run `snort-build-regen-graph` unless `Android.bp` has changed
- [x] 8.5 Run `openspec validate add-flow-telemetry-plane --strict`
