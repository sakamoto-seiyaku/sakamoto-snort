## Why

Flow Telemetry MVP has a working bounded export channel, but the current `FLOW` payload does not carry enough raw facts for frontend Activity timelines and flow inspection. The daemon already observes many of these facts on the packet/debug path; this change makes the normal telemetry record complete enough that consumers do not have to guess ICMP details, packet direction, L4 parse availability, END cause, known/unknown attribution, or fragment/invalid L4 semantics.

## What Changes

- **BREAKING** Replace the existing fixed 102-byte `FLOW` payload v1 layout in place; do not add `FLOW v2`, do not dual-write old/new records, and do not preserve a compatibility window for old consumers.
- Expand `FLOW` records with raw facts required by frontend Activity:
  - ICMP/ICMPv6 `icmpType`, `icmpCode`, and `icmpId`.
  - `l4Status` and `portsAvailable`.
  - packet direction and flow origin direction.
  - `firstSeenNs`, `lastSeenNs`, and stable `endReason`.
  - explicit `verdict` / action, while `reasonId` remains cause attribution.
  - `uidKnown`, `ifindexKnown`, and usable `pickedUpMidStream` lifecycle semantics.
  - per-direction cumulative packet/byte counters.
- Represent fragment / invalid / unavailable L4 packets as `FLOW` L3 observation facts instead of fabricating normal L4 flows or fake ports.
- Keep `DNS_DECISION` blocked-only and separate from `FLOW`; do not add DNS/IP join records.
- Preserve Flow Telemetry transport semantics: fixed-slot shared-memory ring, best-effort writes, ticket gaps, per-flow `recordSeq`, single consumer, and RESETALL/session-boundary behavior.
- Synchronize daemon encoder/producer code, native telemetry consumer decoding, frontend consumer contract, OpenSpec specs, and `docs/INTERFACE_SPECIFICATION.md`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `flow-telemetry-records`: expands and replaces the `FLOW` payload v1 schema and semantics for raw fact completeness, L3 observation, direction counters, explicit verdict/action, END reason, time semantics, ICMP details, known flags, and `pickedUpMidStream`.

## Impact

- Affected APIs: `FLOW` binary payload layout under `recordType=1`; existing old-layout consumers are incompatible and must be updated with the daemon.
- Affected code: `FlowTelemetryRecords` encoder/constants, `Conntrack` telemetry state and producer paths, `PacketManager` / `PacketListener` telemetry facts handoff, native device telemetry consumer decode, tests, and interface docs.
- Affected tests: host ABI/encoder tests, flow producer tests, L3 observation tests, native consumer smoke, device telemetry smoke, host ASAN/UBSAN, and Flow Off vs Flow On performance comparison.
- Dependencies: no new external dependencies; implementation must preserve hot-path constraints and use explicit serialization rather than C++ struct layout.
