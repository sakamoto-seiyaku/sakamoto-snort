## 1. ABI / Encoder Tests First

- [x] 1.1 Add host tests that assert the replacement `FLOW` payload v1 constants, fixed offsets, payload size, little-endian writes, and `kFlowV1Bytes <= kMaxPayloadBytes`
- [x] 1.2 Add host encoder tests for IPv4 and IPv6 TCP/UDP records with explicit verdict/action, `packetDir`, `flowOriginDir`, `firstSeenNs`, `lastSeenNs`, known flags, and per-direction counters
- [x] 1.3 Add host encoder tests for ICMP and ICMPv6 records carrying `icmpType`, `icmpCode`, and `icmpId` while keeping TCP/UDP ports unavailable
- [x] 1.4 Add host encoder tests for END records with `IDLE_TIMEOUT`, `TCP_END_DETECTED`, `RESOURCE_EVICTED`, and `TELEMETRY_DISABLED`
- [x] 1.5 Add host encoder tests for `L3_OBSERVATION` records with `l4Status=fragment` and `l4Status=invalid-or-unavailable-l4`

## 2. FLOW Payload ABI Implementation

- [x] 2.1 Replace `FlowTelemetryRecords` `FLOW` payload v1 offset constants, flags, enums, and `encodeFlowV1` signature to cover all raw facts in the spec
- [x] 2.2 Keep serialization explicit and padding-free: write each field by constexpr offset and little-endian helper, with no public ABI dependency on C++ struct layout
- [x] 2.3 Update in-repo test helpers that read `FLOW` payloads to use the replacement offsets and field meanings
- [x] 2.4 Update `tests/device/telemetry/native/telemetry_consumer.cpp` to decode and print the replacement `FLOW` layout, including L3 observation and END reason

## 3. Packet Facts Handoff

- [x] 3.1 Introduce a stack-only telemetry packet facts object that carries packet direction, tuple bytes, L4 status, ports availability, ICMP metadata, known flags, verdict/action, reason/rule attribution, and packet length
- [x] 3.2 Populate `uidKnown` and `ifindexKnown` in `PacketListener` from netfilter attributes before defaulting numeric values to 0
- [x] 3.3 Pass `packetDir=input?in:out` and observed `ifindex/ifaceKindBit` through `PacketManager` without adding strings, heap allocation, blocking I/O, or extra global lookups
- [x] 3.4 Preserve Debug Stream fields and behavior without moving would-match, candidate rules, domain hints, or DNS/IP join data into `FLOW`

## 4. Normal Flow Producer

- [x] 4.1 Extend conntrack telemetry state with `firstSeenNs`, `lastSeenNs`, `flowOriginDir`, per-direction cumulative counters, usable `pickedUpMidStream`, and last exported raw decision fields
- [x] 4.2 Emit BEGIN/UPDATE/END using the replacement payload while preserving per-flow `recordSeq` advancement only after successful ring writes
- [x] 4.3 Include explicit verdict/action in the decision key with `ctState`, `ctDir`, `reasonId`, and optional `ruleId`
- [x] 4.4 Maintain block/iface-block short TTL behavior and normal ALLOW/default-allow timeout behavior with no separate deny-flow table
- [x] 4.5 Keep telemetry failures, record-too-large drops, and resource pressure from changing packet verdicts

## 5. L3 Observation Producer

- [x] 5.1 Add telemetry-only L3 observation handling for IPv4 fragments, IPv6 fragments, and invalid/unavailable L4 parse results
- [x] 5.2 Ensure L3 observation records carry `portsAvailable=0`, zero ports, packet direction, addresses, proto, verdict/action, reasonId, known flags, and cumulative counters
- [x] 5.3 Ensure L3 observation records are not treated as normal L4 lifecycle records and do not fabricate CT state, ports, ICMP lifecycle, or TCP/UDP semantics
- [x] 5.4 Bound L3 observation state with `invalidTtlMs` or equivalent existing telemetry limits and preserve resource-pressure accounting

## 6. Docs / Interface / OpenSpec Sync

- [x] 6.1 Update `docs/INTERFACE_SPECIFICATION.md` with the replacement `FLOW` binary layout, enum values, flags, field offsets, and compatibility warning
- [x] 6.2 Confirm `docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md` and `docs/IMPLEMENTATION_ROADMAP.md` remain consistent with the implemented layout; adjust only if implementation reveals a decision correction
- [x] 6.3 Do not create, modify, move, or archive anything under `openspec/changes/archive/` as part of this change

## 7. Verification

- [x] 7.1 Run the new host `FlowTelemetryRecords` encoder tests
- [x] 7.2 Run host conntrack/producer tests covering recordSeq gaps, direction counters, first/last seen, end reasons, ICMP details, and L3 observation
- [x] 7.3 Run host ASAN and UBSAN presets for changed tests and fix all memory/UB findings
- [x] 7.4 Run device telemetry smoke with the updated native consumer for IPv4/IPv6 TCP, UDP, ICMP, fragment, invalid L4, allow, block, iface block, and DNS blocked-only regression
- [x] 7.5 Run Flow Off vs Flow On performance comparison and report throughput drop or p50/p95/p99 verdict-path latency against the existing 5%-10% target
- [x] 7.6 Run `openspec validate add-flow-telemetry-raw-facts-completeness --strict`
