# Android VPN Implementation Feasibility POC Campaign

Status: research contract, 2026-08-23  
Tracker: SAKAMOTO-131  
Scope: non-root Android VPN/TUN Runtime Profile

This document defines the bounded research campaign that precedes formal Android
VPN implementation. It records what remains stable while preserving room for
the evidence-guided roadmap to change. It is not a production specification,
release gate, capacity sizing decision, or POC implementation source.

## 1. Objective and completion level

The campaign asks:

> Can the accepted Android VPN architecture be implemented correctly on the
> target arm64 Android environment with bounded resources, explicit failure and
> overload behavior, and convergent network/runtime lifecycle semantics?

The completion level is **Android VPN Engineering Feasibility**. Reaching it
requires more than a one-shot connection: the campaign must show a working
minimum complete VPN dataplane, real network and lifecycle behavior, application
UID attribution sufficient for per-app policy foundations, bounded ownership and
teardown, and no architecture-level resource or performance failure.

The final feasibility audit is claim-family based. The following required
families must each have valid Pixel evidence for the Android-specific portion,
with Host/model evidence allowed to complete deterministic subcoverage:

- minimum full-device VPN dataplane: real IPv4/IPv6 TCP and UDP, including DNS
  as ordinary TCP/UDP traffic, policy allow/drop separation, and TUN return;
- application identity: distinct real App UIDs, cache hit/miss and refresh,
  non-blocking lookup, and no FlowOwner-key contamination;
- network and lifecycle: real underlay creation, bind/protect, network/epoch
  change, stop, fault, restart, stale-event rejection, and teardown settlement;
- ownership and failure: owner-local execution, representative multi-owner
  isolation, bounded overload behavior, and no cross-owner state or callback
  pollution;
- engineering envelope: bounded flow/socket/buffer/timer resources, no
  increasing FD/thread/RSS trend in the tested envelope, and no
  architecture-level performance cliff.

An `INCONCLUSIVE`, `INVALID`, or `INSUFFICIENT_EVIDENCE` result in any required
family blocks campaign completion; an `INVALID` family is treated as
insufficient evidence rather than as a passing omission. A `FAIL` either drives an `ADJUSTMENT_REQUIRED`
continuation or, when it contradicts a baseline invariant, `REOPENS_ARCHITECTURE`.
Claims explicitly outside this contract remain non-claims rather than hidden
completion failures, but must be listed in the final audit.

This level does not require final production constants, release-budget proof,
OEM compatibility, product UI, persistent storage, or a release artifact.

## 2. Product and architecture boundary

The campaign covers the non-root VPN/TUN Runtime Profile:

- Android `VpnService` TUN ingress and return.
- The shared VPP graph, canonical FlowOwner selection, and VPN provenance.
- Owner-inline HEV/lwIP Flow Stack execution and owner-local Direct Egress.
- Android bind/protect broker behavior before socket connect or first send.
- Original-destination IPv4/IPv6 TCP and UDP, including DNS as ordinary TCP or
  UDP traffic.
- Minimum policy allow/drop behavior sufficient to prove that policy drop does
  not enter transport.
- Application UID attribution needed by the per-app policy foundation:
  distinct real App UIDs, cache hit/miss, non-blocking lookup, and lifecycle
  refresh. Full Application Catalog and UI identity presentation are outside
  this campaign.
- Underlay/network epoch changes, stop, injected fault, bounded restart,
  stale-event rejection, resource settlement, and representative engineering
  envelope evidence.

Root/NFQUEUE is a parallel Runtime Profile with an already evidenced basic
route. Its evidence may be reused for shared VPP, ownership, and completion
principles, but Root hooks, queue placement, and verdict behavior are not
reopened or re-run by this campaign.

## 3. Evidence-backed Architecture Baseline

The current baseline is the owner-inline external-driver topology selected by
the bounded OI1–OI5 evidence and recorded in
`docs/adr/0007-owner-local-lwip-direct-egress.md` and
`experiments/vpp-nfq-poc/OI_REQUIREMENT_AUDIT.md`.

The baseline means:

- The canonical FlowOwner is the only executor of its HEV/lwIP mutable
  callbacks.
- A FlowOwner-local Flow Stack shard is fixed for the lifetime of a live flow;
  live migration, alternate-owner spill, and a second egress hash are not the
  default design.
- A wait-only helper may observe fd/timer readiness and publish an opaque,
  generation-tagged wake. It cannot execute Flow Stack callbacks or own
  transport state.
- The Android broker performs platform-only underlay bind and
  `VpnService.protect()`. The owner consumes the directional completion and
  alone continues, fails, or tears down transport state.
- Protected sockets have an underlay epoch fixed at creation. There is no
  unprotected retry or implicit Direct/SOCKS fallback.
- TUN-origin and Flow-Stack-origin packets use one shared graph and immutable
  provenance; provenance is not inserted into the canonical flow key.
- Generation/epoch gates cover packet, wake, timer, broker, socket, output,
  ownership token, and teardown events.
- VPP workers do not wait for socket I/O, Android APIs, timers, name
  resolution, or capacity. Overload is explicit runtime/transport evidence,
  not a policy verdict or a bypass.

This is a revisable baseline, not an immutable freeze. Ordinary harness or
implementation-seam corrections do not reopen it. Contradictory higher-
fidelity evidence, a material platform constraint, a safety failure, or a
clearly superior route may reopen the affected decision explicitly.

## 4. Evidence roles and target environment

### Pixel 6a

The dedicated Pixel 6a arm64 Android device is the highest-fidelity and final
device-level feasibility environment for this campaign. It is the required
decision environment for Android-specific behavior: TUN, `VpnService`, Android
socket protection, Network/underlay behavior, UID attribution, bionic/NDK
integration, scheduler interaction, lifecycle, real network, and target-device
resource measurements.

The device is dedicated to this project. Real whole-device IPv4/IPv6 VPN
routing is allowed for network POCs, including traffic from the terminal and
other controlled applications. Narrow routes or per-App isolation may be used
for a diagnostic cell, but cannot replace final full-device network evidence.

Pixel evidence proves this target environment, not all third-party OEM systems.
OEM-specific compatibility is outside the current campaign and is a later
post-release concern.

### Host and deterministic model

Host x86 and deterministic models remain valid evidence where they answer a
platform-neutral question more completely or reproducibly:

- state transitions and scheduler order;
- stale/duplicate event matrices;
- exact resource ledgers and fault injection;
- ownership tripwires and cross-owner isolation;
- bounded model coverage that is impractical to enumerate on-device.

Host evidence does not substitute for Pixel on Android-specific behavior,
real arm64 integration, underlay/network transitions, UID APIs, or target
capacity. If Host and Pixel appear to conflict, first verify that the same
question, artifact, scope, and evidence semantics were used; the Pixel result
decides Android-specific behavior.

## 5. Stable rules and revisable roadmap

Stable for the campaign:

- the engineering-feasibility objective;
- VPN-only scope and Root/NFQUEUE non-reopening boundary;
- evidence roles and Pixel final-device rule;
- the Evidence-backed Architecture Baseline and its reopen rule;
- the distinction between POC Correction and formal implementation;
- the Finding Ledger and Evidence Gap Map as separate inputs;
- lightweight evidence discipline and two-level conclusion vocabulary;
- continuous execution unless an interruption condition is met.

Revisable from evidence:

- the number, order, and grouping of POCs;
- Evidence Batch membership and blocking edges;
- exact traffic cells, endpoint fixtures, network conditions, and durations;
- worker/shard counts, queue/credit/buffer sizes, timer budgets, and load
  levels;
- the concrete Android harness, monitoring, and artifact layout;
- which gaps can be closed by Host/model and which must be repeated on Pixel.

The roadmap is therefore an **Evidence-Guided POC Roadmap**, not a fixed
checklist. A change to it must state which finding or gap caused the change.

## 6. Continuous execution rule

POCs are organized into Evidence Batches by their shared upper-level
engineering question, not by a fixed count. A planned chain runs continuously:

1. Finish the registered cells and exploratory follow-ups for the current POC.
2. Record ordinary findings, apply the smallest POC Correction needed to make
   the question observable, and rerun affected cells.
3. Continue to the next POC or batch when the current question is settled; do
   not hold a decision meeting after each cell or partial result.
4. After the planned campaign chain, combine all evidence and perform the
   feasibility audit.

Execution stops early only when one of these conditions holds:

- a core invariant of the Evidence-backed Architecture Baseline is contradicted;
- correctness requires paired-thread transport execution, global mutable
  authority, live migration/spill, an unprotected fallback, or a second packet
  path;
- the remaining POC premise is invalid, so continuing cannot produce an
  interpretable result;
- the device safety boundary or controlled-network scope is violated;
- new authority, external infrastructure, or an irreversible operation is
  required;
- a materially superior architecture makes the remaining old-route work
  unreasonable.

Build, deploy, harness, timing, logging, FD lifetime, cleanup, and similar
ordinary defects are findings. They receive a POC Correction and continue the
chain unless they expose one of the interruption conditions above.

## 7. Lightweight POC Protocol

Before a POC, register only:

- its main question and current working assumption;
- the decisive counter-evidence;
- the safety boundary;
- the minimum facts required for a supported conclusion;
- Host/model/Pixel responsibilities and known non-claims.

During execution, exploratory cells, random schedules, fault injection,
additional observations, and harness corrections are allowed. Additions must
remain visible and must not silently weaken a gate. At completion, seal the
artifact identity, raw evidence, environment, findings, supported conclusion,
and non-claims.

## 8. Conclusion vocabulary

Cell-level result:

- `PASS`: the registered cell produced the expected evidence.
- `FAIL`: the registered cell contradicted its expected behavior.
- `INCONCLUSIVE`: the cell ran but evidence cannot decide the question.
- `INVALID`: the cell did not exercise the registered question.

Roadmap meaning:

- `SUPPORTS_BASELINE`: bounded evidence supports continuing the current route.
- `ADJUSTMENT_REQUIRED`: a real issue requires local correction or redesign,
  but does not reopen the architecture.
- `REOPENS_ARCHITECTURE`: a core assumption is contradicted and the campaign
  must pause for a route decision.
- `INSUFFICIENT_EVIDENCE`: the experiment was valid but does not cover enough
  of the claim.

Every conclusion must say in plain language what the evidence supports and what
it does not support. A cell `PASS` is never by itself a campaign `SUPPORTS_BASELINE`.

## 9. Campaign outputs and next planning step

The campaign uses two linked but semantically separate records:

- `POC Finding Ledger`: observed problems, including already repaired problems,
  their evidence, POC Corrections, formal invariants, and status.
- `Evidence Gap Map`: important claims and the Host/model/Pixel evidence and
  non-claims for each, including unproven gaps that are not observed defects.

The concrete POC design is produced only after these records are complete. The
design must group related gaps into Evidence Batches, define each POC and its
true blockers, and specify Pixel evidence, exploratory latitude, conclusion
rules, and interruption conditions. It is then converted into execution tickets
for the continuous POC chain.

## 10. Non-goals and explicit non-claims

This contract does not claim:

- production readiness, release approval, or final capacity constants;
- throughput, latency, power, thermal, or soak budgets already passing;
- third-party OEM compatibility;
- complete Android Product UI, policy authoring, catalog, or persistence;
- Root/NFQUEUE revalidation;
- arbitrary external/default-route behavior before the future real-network POCs
  produce it;
- four-worker Android evidence merely because Host or a two-owner Host runner
  passed;
- that a POC correction is a production implementation.

## References

- [Project glossary](../../CONTEXT.md)
- [ADR-0007: Owner-local lwIP direct egress](../../docs/adr/0007-owner-local-lwip-direct-egress.md)
- [OI requirement audit](./OI_REQUIREMENT_AUDIT.md)
- [S126 OI1 journal](./S126_OI1_EXECUTION_JOURNAL.md)
- [S127 OI2 journal](./S127_OI2_EXECUTION_JOURNAL.md)
- [S128 OI3 journal](./S128_OI3_EXECUTION_JOURNAL.md)
- [S129 OI4 journal](./S129_OI4_EXECUTION_JOURNAL.md)
- [S130 OI5 journal](./S130_OI5_EXECUTION_JOURNAL.md)
- [POC Finding Ledger](./POC_FINDING_LEDGER.md)
- [Android VPN Evidence Gap Map](./ANDROID_VPN_EVIDENCE_GAP_MAP.md)
- [Evidence-Guided Android VPN POC Campaign Specification](./ANDROID_VPN_POC_CAMPAIGN_SPEC.md)
