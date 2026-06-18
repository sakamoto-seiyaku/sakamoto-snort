## 1. Interface Contract and Tests First

- [x] 1.1 Update `docs/INTERFACE_SPECIFICATION.md` with the `dns.explain` and `pkt.explain` v1 schemas, stable stage names, self-contained rule/list/mask snapshots, candidate cap, and non-overlap with Flow Telemetry/Metrics/history
- [x] 1.2 Add host tests for stream JSON builders proving tracked `dns` events serialize `explain.version=1`, `kind="dns-policy"`, `inputs`, `final`, and ordered `stages`
- [x] 1.3 Add host tests for stream JSON builders proving tracked `pkt` events serialize `explain.version=1`, `kind="packet-verdict"`, `inputs`, `final`, and ordered `stages`
- [x] 1.4 Add host tests proving `activity` events and stream notices do not gain `explain`
- [x] 1.5 Add host tests proving candidate snapshot arrays are stable, capped at `maxExplainCandidatesPerStage=64`, retain the winning snapshot, and set `truncated=true` when over cap
- [x] 1.6 Add host tests proving stream replay is only a bounded debug prebuffer and is not exposed/documented as a history/timeline API

## 2. Shared Debug Explain Data Model

- [x] 2.1 Add compact C++ debug explain snapshot types for DNS and packet stream events; avoid JSON formatting in verdict paths
- [x] 2.2 Define stable stage-name constants and skip-reason constants for DNS and packet explanations
- [x] 2.3 Extend `ControlVNextStreamManager::DnsEvent` and `PktEvent` to carry optional explain snapshots without changing subscription, replay, pending queue, or notice mechanics
- [x] 2.4 Extend `ControlVNextStreamJson` to serialize the explain snapshots and keep existing event envelope invariants
- [x] 2.5 Add shared bounded candidate snapshot helpers that preserve stable ordering, retain the winning snapshot, and emit explicit truncation metadata
- [x] 2.6 Mark top-level `dns`/`pkt` stream fields as compatibility summaries in docs/tests; do not add new normal telemetry fields to the stream event envelope

## 3. DNS Explainability

- [x] 3.1 Extend `CustomRules` with tracked-only helpers that collect matching rule/list-entry snapshots in ascending ruleId order with the 64-item cap and truncation marker
- [x] 3.2 Extend `DomainManager` with device-wide explain helpers for allow/block custom list and rule stages, preserving existing `authorized/blocked` verdict semantics and exposing self-contained list/rule snapshots
- [x] 3.3 Extend `App` with a DomainPolicy explain helper that emits ordered stages: app allow list, app block list, app allow rules, app block rules, device-wide allow, device-wide block, mask fallback
- [x] 3.4 Update `DnsListener` so tracked DNS verdicts use the explain helper and attach the snapshot to `DnsEvent`
- [x] 3.5 Ensure untracked DNS verdicts still skip per-event construction and only update suppressed notice counters
- [x] 3.6 Ensure `maskFallback` carries enough mask evidence to explain the final verdict without reading current app/domain masks separately

## 4. Packet Explainability

- [x] 4.1 Add an IPRULES debug explain API on the hot snapshot that reports enforce and would candidates in effective evaluation order while keeping normal `evaluate()` unchanged
- [x] 4.2 Add host tests comparing IPRULES normal verdict results against debug explain winners for IPv4 and IPv6 allow/block/would-match cases
- [x] 4.3 Extend `PacketManager::make` to build a tracked-only packet explain snapshot with stages: `ifaceBlock`, `iprules.enforce`, `domainIpLeak`, `iprules.would`
- [x] 4.4 Include packet inputs in the snapshot: `blockEnabled`, `iprulesEnabled`, direction, family, proto, `l4Status`, interface fields, and conntrack state/direction when evaluated
- [x] 4.5 Include self-contained IPRULES rule definition snapshots for enforce and would candidates: `ruleId`, `clientRuleId`, `matchKey`, `action`, `enforce`, `log`, `family`, `dir`, `iface`, `ifindex`, `proto`, `ct`, `src`, `dst`, `sport`, `dport`, and `priority`
- [x] 4.6 Include `ifaceBlock` evidence: app interface mask, packet interface bit/kind, evaluated intersection, outcome, and short-circuit reason
- [x] 4.7 Preserve existing verdict, metrics, per-rule stats, and Flow Telemetry behavior while treating top-level stream fields as compatibility summaries only
- [x] 4.8 Ensure untracked packet verdicts still skip per-event construction and only update suppressed notice counters

## 5. Build and Documentation Wiring

- [x] 5.1 Update CMake wiring for any new host tests or source files
- [x] 5.2 Update `Android.bp` only if new production source files require it; do not run `snort-build-regen-graph`
- [x] 5.3 Keep all new implementation RAII/const-correct and avoid raw owning `new/delete`, C-style casts, or `using namespace std` in headers
- [x] 5.4 Keep DNS/packet verdict paths free of socket I/O, disk I/O, DNS lookup, unbounded scans, and JSON formatting
- [x] 5.5 Ensure `notice="suppressed"` and `notice="dropped"` remain debug delivery diagnostics, not Metrics replacements or normal telemetry records

## 6. Device Coverage

- [x] 6.1 Extend domain device smoke to assert tracked `dns` explain output for app-scope rule, device-wide rule, and mask fallback winners
- [x] 6.2 Extend domain device smoke to assert `tracked=0` suppresses per-event DNS explain output and preserves suppressed notices
- [x] 6.3 Extend IP device smoke to assert tracked `pkt` explain output for IPRULES allow, IPRULES block, would-block overlay, and `IFACE_BLOCK` short-circuit
- [x] 6.4 Extend IP device smoke to assert `tracked=0` suppresses per-event packet explain output and preserves suppressed notices

## 7. Verification

- [x] 7.1 Run `openspec validate add-debug-stream-explainability --strict`
- [x] 7.2 Run `cmake --preset dev-debug`
- [x] 7.3 Run the host test gate for changed stream/domain/iprules tests
- [x] 7.4 Run ASAN and UBSAN host variants and fix all memory/UB issues before review
- [x] 7.5 Run TSAN for changed conntrack/iprules/stream concurrency-sensitive tests if packet explain helpers touch shared state
- [x] 7.6 Run device domain smoke coverage for Debug Stream DNS explainability
- [x] 7.7 Run device IP smoke coverage for Debug Stream packet explainability
- [x] 7.8 Run `git diff --check` and verify no generated/tracked build artifacts are accidentally staged
