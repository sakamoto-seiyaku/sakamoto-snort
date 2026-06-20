# SNORT-10 Mainline Reconstruction Baseline

Status: implementation baseline for the `snort10-mainline-reconstruction`
branch, 2026-06-20.

This document records the code-shape decision for rebuilding the daemon
mainline after the SNORT-10 architecture discussion. It does not replace the
module contracts in `NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md`,
`L4_CONNTRACK_WORKING_DECISIONS.md`, or the interface specification.

## Decision

The active source tree is rebuilt as a clean mainline layout instead of
incrementally editing the old flat `src/` directory in place.

- Previous current-head source is preserved under `archive/current-head/src/`.
- The branch point is tagged as `pre-snort10-current-head-2026-06-20`.
- Archived code is reference material only; it is not an active build target.
- The old legacy control plane is not carried forward.
- Old pre-SNORT-10 direct mutation surfaces are not carried forward.
- This execution stops before SNORT-12. It does not implement SNORT-12,
  SNORT-13, or any later module.

The new active `src/` layout starts as a minimal root daemon base:

- `src/main`: daemon entry point and shutdown runtime.
- `src/control/vnext`: control-vNext framing/codec plus minimal base server.
- `src/config`: fixed runtime constants for the base.
- `src/core/packet`: reusable packet parsing/topology headers that are still
  valid as isolated foundations.
- `src/core/metrics`: low-level reason/metrics helpers that remain isolated.
- `src/app`: isolated package-state helper.

## Active Base Scope

The active daemon in this baseline now provides the pass-through predecessor
needed before SNORT-12 packet parsing work starts:

- listens on abstract unix socket `@sucre-snort-control-vnext`;
- accepts an inherited Android init socket named `sucre-snort-control-vnext`
  when launched by init/service plumbing;
- accepts control-vNext netstring JSON frames;
- supports `HELLO`, `RESETALL`, and `QUIT`;
- starts the dual-stack NFQUEUE pass-through hook/listener/verdict runtime;
- exposes `HELLO.capabilities=["snort10-base","nfqueue-pass-through"]` once
  pass-through runtime readiness is true;
- runs host unit tests for isolated helpers, the control-vNext codec, the
  pass-through runtime contract, and control socket launch paths;
- provides one device smoke entry, `snort-dx-snort10-base`, for
  `HELLO` / `RESETALL` / `QUIT` plus pass-through hook readiness.

`RESETALL` in this base only reinstalls or quiesces base-owned NFQUEUE
hook/listener/runtime state. It must not restore old policy/config mutation,
stream state, CT tables, telemetry producers, domain state, checkpoints, or an
authoring store.

## Explicit Exclusions

These are not part of this baseline and must not be pulled in implicitly:

- Bounded packet copy or `PacketFacts`.
- Hot-path capability table, policy cache, or advanced prefilter.
- CT runtime, CT hash table, `CtFacts`, or CT consumers.
- Traffic Windows basic/detail tiers.
- Packet Diagnostics / Diagnostic Focus.
- IPRULES Authoring Layer, direct `IPRULES.APPLY`, or checkpoint mutation.
- PerfMetrics producer beyond isolated helper code.
- Flow Telemetry producers, shared-memory rings, and stream managers.
- DNS/domain stream, Domain-IP Association, Resolved-IP Policy, RDNS.
- Old legacy control and old generic stream control.

## Module Order

The planned implementation order remains:

1. SNORT-12 Packet Datapath Foundation.
2. SNORT-13 Hot-Path Capability and Policy Cache.
3. SNORT-14 Conntrack A++ Runtime.
4. SNORT-15 Traffic Windows v1.
5. SNORT-16 Packet Diagnostics / Diagnostic Focus.
6. SNORT-17 IPRULES Authoring Layer v1.
7. SNORT-18 PerfMetrics / Datapath Performance Indicators.
8. SNORT-19 First-round Integration / Device Acceptance.

SNORT-12 is the first module allowed to reintroduce bounded packet copy,
PacketFacts construction, parser status semantics, or non-pass-through packet
processing.
SNORT-14 is the first module allowed to reintroduce CT. SNORT-17 is the first
module allowed to reintroduce policy mutation APIs.

## Build And Test Gates

The base-compatible gates are intentionally narrow:

- `snort-host-tests`
- `snort-host-tests-asan`
- `snort-host-tests-ubsan`
- `snort-host-tests-gate`
- `snort-dx-snort10-base` when a rooted Android device is available
- `snort-build-ndk` / NDK target build

CT-specific TSAN gates and old dx-smoke targets are inactive until their
owning modules reintroduce matching runtime code.

## Reintroduction Rule

Later slices may copy code out of `archive/current-head/src/`, but each copy
must satisfy the current SNORT-10 contract for that module. The default action
is not "restore old code"; it is "adapt the minimum proven pieces into the new
module boundary."
