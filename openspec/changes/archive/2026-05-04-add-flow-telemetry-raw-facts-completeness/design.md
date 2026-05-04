## Context

Flow Telemetry MVP already provides `TELEMETRY.OPEN/CLOSE`, a fixed-slot shared-memory ring, `FLOW` records, blocked-only `DNS_DECISION` records, and minimal telemetry health state. The current `FLOW` payload is a compact 102-byte CT-first record that exports tuple, CT state/direction, final `reasonId/ruleId`, and total counters.

Frontend Activity now needs a more complete raw fact layer. Some facts already exist before `PacketManager::make` or inside conntrack, such as packet input direction, L4 parse status, `portsAvailable`, ICMP type/code/id, UID/ifindex attr presence, and packet length. They are lost when the current long `observeFlowTelemetry(...)` argument list narrows the packet into the old flow encoder.

This change must keep the daemon firewall path bounded: no hot-path disk or socket I/O, no JSON formatting, no DNS/domain lookup, no unbounded scans, no blocking waits, and no dependency on C++ struct padding for the public ABI.

## Goals / Non-Goals

**Goals:**

- Replace the existing `FLOW` payload v1 layout in place and update all in-repo producers/consumers/docs/specs together.
- Export raw facts needed by Activity: ICMP details, L4 status, port availability, packet and origin direction, first/last seen timestamps, END reason, explicit verdict/action, known flags, usable `pickedUpMidStream`, and per-direction cumulative counters.
- Represent fragment / invalid / unavailable L4 packets as L3 observation facts without pretending they have normal L4 lifecycle or available ports.
- Preserve Flow Telemetry's transport contract: bounded shared-memory records, best-effort writes, session boundaries, record drops visible through telemetry health, and no verdict impact.

**Non-Goals:**

- No `FLOW v2`, dual-write mode, compatibility window, or legacy 102-byte decoder support.
- No changes to `DNS_DECISION`, no DNS/IP join records, no domain hints in `FLOW`, and no rule candidate/debug evidence fields.
- No VPN logical / underlay interface attribution and no `rulesEpoch`; keep observed interface and current `ruleId` non-reuse assumption.
- No full active-flow END flood during RESETALL, `TELEMETRY.CLOSE`, or session rebuild.

## Decisions

1. **Replace `FLOW` v1 layout in place**

- Choice: keep `recordType=FLOW` and `payloadVersion=1`, but replace the old fixed 102-byte payload.
- Rationale: the project has no released stable frontend ABI yet, and the working decision explicitly allows breaking the current layout for raw facts completeness.
- Alternative rejected: `FLOW v2` or dual-writing old/new records. It would increase producer and consumer complexity and ring pressure without providing a needed compatibility guarantee.

2. **Introduce a packet facts handoff object**

- Choice: replace the expanding `Conntrack::observeFlowTelemetry(...)` parameter list with a small stack-only facts object carrying packet direction, L4 status, port availability, ICMP meta, verdict reason/action, known flags, tuple bytes, and packet length.
- Rationale: `PacketListener` already observes these facts; a single object prevents repeated signature churn and keeps telemetry facts explicit.
- C++ constraint: no owning raw pointers, no heap allocation, and no string fields in the hot-path facts object.

3. **Keep normal flow and L3 observation semantics distinct**

- Choice: normal TCP/UDP/ICMP/other-terminal traffic remains CT-backed where possible; fragment / invalid / unavailable L4 traffic is exported as `L3_OBSERVATION`.
- Rationale: frontend needs traffic and anomaly visibility, but fabricating ports or a normal L4 lifecycle would make Activity misleading.
- L3 observation records carry tuple/family/proto/addresses/direction/counters/verdict fields where known, with `portsAvailable=0`, ports set to 0, and CT state/direction marked invalid/any as appropriate.

4. **Store cumulative counters only, including direction splits**

- Choice: keep `totalPackets/totalBytes` and add cumulative `inPackets/inBytes/outPackets/outBytes`.
- Rationale: consumers can derive windows from cumulative snapshots and detect gaps through `recordSeq`; direction splits cannot be reconstructed reliably from old aggregate-only records.
- Direction mapping: existing packet `input=true` maps to `packetDir=in` and increments `in*`; `input=false` maps to `out` and increments `out*`.

5. **Separate record time from flow time**

- Choice: retain `timestampNs` as the record event/export timestamp and add `firstSeenNs/lastSeenNs`.
- Rationale: END records may be emitted by sweep/retire paths; consumers must not treat END `timestampNs` as the last packet time.

6. **Keep control/ring/session behavior unchanged**

- Choice: `TELEMETRY.OPEN/CLOSE`, fd passing, ring slot header, ticket gap behavior, RESETALL session rebuild, and minimal telemetry health remain as they are.
- Rationale: the missing capability is `FLOW` payload content, not the transport.

## Risks / Trade-offs

- [Risk] New payload grows enough to increase ring pressure -> Mitigation: keep fields fixed-width, avoid strings, verify `kFlowV1Bytes <= kMaxPayloadBytes`, and run Flow On/Off perf comparison.
- [Risk] Producer paths diverge between IPv4, IPv6, normal flow, and L3 observation -> Mitigation: centralize explicit encoding in `FlowTelemetryRecords` and keep a common facts object.
- [Risk] END reason becomes misleading for session shutdown -> Mitigation: RESETALL/CLOSE/session rebuild remain session boundaries and do not require full `TELEMETRY_DISABLED` END flood.
- [Risk] Old consumers misdecode the new layout -> Mitigation: document the breaking change and update native/frontend consumers in the same implementation change.
- [Risk] Hot-path overhead regresses -> Mitigation: use stack-only facts, relaxed atomics for counters, bounded sweep only, no blocking locks or dynamic allocation in verdict paths, and sanitizer/perf validation before review.

## Migration Plan

- Update OpenSpec and `docs/INTERFACE_SPECIFICATION.md` before or with implementation so the new offset table is authoritative.
- Update daemon encoders/producers and the native telemetry consumer in the same change.
- Treat old `FLOW` payload consumers as incompatible; frontend must update its decoder alongside the daemon.
- No persistent daemon state migration is required because Flow Telemetry records are session/export data, not daemon policy state.

## Open Questions

- None for proposal scope. Numeric enum values and exact offsets are implementation details to define in `docs/INTERFACE_SPECIFICATION.md`, `FlowTelemetryRecords.hpp`, and tests, while preserving the semantics in this change.
