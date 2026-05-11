## 1. Producer Correctness

- [x] 1.1 Add a small relaxed atomic max helper for telemetry `lastSeenNs`
- [x] 1.2 Rework IPv4 packet-driven FLOW export so guard-free due checks only prefilter and final snapshot/due/kind decisions happen inside `exportInProgress`
- [x] 1.3 Apply the same guarded final snapshot/due/kind logic to IPv6 FLOW export
- [x] 1.4 Derive exported totals from fresh per-direction counters when packet direction is known
- [x] 1.5 Preserve existing END export/session cleanup behavior and `recordSeq` advancement only after successful ring writes

## 2. Regression Coverage

- [x] 2.1 Add host helpers to decode FLOW cumulative counters and `lastSeenNs`
- [x] 2.2 Add a deterministic concurrent same-flow telemetry regression that stresses split INPUT/OUTPUT style interleaving
- [x] 2.3 Extend existing direction-counter assertions to require `totalPackets == inPackets + outPackets` and `totalBytes == inBytes + outBytes`

## 3. Verification

- [x] 3.1 Run `openspec validate fix-flow-telemetry-counter-rollbacks --strict`
- [x] 3.2 Build and run focused `conntrack_tests`
- [x] 3.3 Run the Conntrack TSAN lane or document if unavailable
- [x] 3.4 Run broader host sanitizer checks if changed code is not fully covered by the focused lane

## 4. Review Follow-up

- [x] 4.1 Ignore `packetDir=Unknown` conntrack telemetry observations and cover the no-op behavior
