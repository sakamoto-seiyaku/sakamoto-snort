---
status: accepted
date: 2026-08-02
---

# VPP-native packet I/O adapters

For the pinned target VPP revision, Root/NFQUEUE and VPN/TUN packet I/O execute inside VPP-native C Adapter
plugins rather than crossing a Rust–VPP–Rust bridge for every packet. Its plugin build enables C but not C++,
so C++ is not a target plugin or packet-domain implementation language. A future pinned VPP revision may
reopen that language boundary only if its native plugin build supports C++ and a concrete need justifies it.
Rust remains the product control, lifecycle, configuration, policy
snapshot, status, and compatibility layer behind a coarse-grained non-unwinding C ABI; it does not receive,
complete, return, or own individual live VPP packet buffers. This supersedes ADR-0005 while preserving its
underlying exactly-once Adapter Completion, generation, bounded-resource, and teardown obligations inside
the native Adapter.

Root uses multiple independently owned NFQUEUE lanes with connection-stable kernel `queue-balance` as
Initial Execution Placement, not as packet or flow ownership. Each native lane exclusively operates its
queue/socket for receive and verdict. The shared Canonical Owner Key and fixed Worker Layout select one
ExecutionOwner for every valid IPv4/IPv6 packet: complete TCP/UDP uses `L4_PORTS`, and supported ICMP Echo
request/reply uses `ICMP_QUERY` with a normalized query class and identifier, excluding sequence. Both supply
a FlowOwner/session identity for later tracking; other legal protocols or unavailable transport identity use
`L3` without creating a synthetic flow. This typed-key clarification follows S207 and does not add an ICMP tracker. Owner-local packets continue without enqueue, while mismatches use bounded canonical-owner processing
and return their terminal intent to the origin lane, which performs the packet's single verdict operation
with the original queue generation and packet ID. VPN begins with one native TUN Platform I/O Lane and uses
the same ExecutionOwner and completion-routing model; ADR-0007 defines the separate post-policy TCP/UDP VPN
Flow Stack Packet Boundary. Normal worker transfer moves VPP buffer indexes and metadata, never copies
complete packet bytes.

This shape is chosen from the Pixel 6a W2/Q2 POC: address-diverse Q2/Q4 kernel placement mismatched the
project's canonical owner for about half of packets, so queue identity cannot replace software distribution;
bounded origin return closed the normal, overload, stale/duplicate, and lifecycle ledgers; shared
NFQUEUE-TX/trylock reached only about 52.6% mixed and 60.9% all-remote direct hits and produced more aggregate
CPU/context activity, so it is rejected. Descriptor/credit depth remains a measured runtime capacity rather
than a fixed architectural constant.

P3 proved route, ownership, and ledger correctness with throwaway copied-prefix descriptors; it did not prove
the production no-copy/live-buffer integration. Its prefix length, pool depth, queue count, and worker count
are scoped experimental parameters, not normative implementation constants. SAKAMOTO-72..81 later added
throwaway live-buffer ownership evidence: single-message direct materialization, worker handoff, origin
completion, and native return passed on host and Android, while multi-message datagrams were safely rejected
before admission rather than materialized as independent no-copy obligations.

The historical P5/P6 conditional-worker-wake implementation was not accepted. An early P5 diagnostic observed about 44%
sleeping-worker publish-to-terminal p99 improvement, but that result was not a product acceptance result.
The final P6d campaign-21 completed all 32 formal arms validly and still failed the pre-registered gates:
idle C-A one-sided 95% upper `+0.091950 pp` exceeded `+0.05 pp`, while sleep-confirmed p99 improvement
had a one-sided 95% lower bound of `-3.110%` versus the `20%` target. The p50 regression gate passed at
about `+0.054%`; external power remained inconclusive. The wake mechanism therefore remains research-only,
and persistent/per-packet wake remains diagnostic-only. A future adoption discussion requires a new mechanism
hypothesis, independently hashed artifact, and a fresh pre-registered campaign that passes both idle and
sleep-confirmed latency gates.

## 2026-09-12 Event-driven worker notification decision

The S239 Product artifact exposed seconds-long cross-worker dispatch delays
under the Android idle profile. The user accepts a complete coalesced
notification and sleep protocol for the existing VPP 26.02 baseline, informed
by the [Linux notification investigation](../reviews/LINUX_EVENTFD_EPOLL_COALESCING_CONTRACT.md)
and [implementation/race analysis](../reviews/LINUX_WAKE_COALESCING_IMPLEMENTATION_RESEARCH.md).
This authorizes implementation and fresh Pixel qualification; it does not
restore the rejected historical patch or claim the new artifact has passed.

- Keep VPP 26.02 pinned. Do not adopt the newer development-line handoff queue
  merely for version freshness. Reconsider an upgrade only for demonstrated
  benefit and acceptable migration/verification cost.
- Reuse native frame batches and the per-worker nonblocking, non-semaphore
  eventfd with level-triggered EPOLLIN. Combine kernel notification retention
  and event aggregation with a single ordered user-space pending latch that
  suppresses redundant writes. ET/ONESHOT is not required for coalescing.
- Publish native work before notification. Every publication participates in
  the ordered latch operation, including coalesced publications. The consumer
  acknowledges before rechecking authoritative remote and local runnable work;
  it cannot block with already-dequeued graph frames or other immediately
  executable work remaining. Concrete atomics and queue predicates must have
  a complete ordering argument, not a two-location acquire/release sketch.
- Integrate all existing users of the worker wake fd, including node interrupts
  and lifecycle barriers. Do not stack independent flags or drain callbacks
  whose interactions can consume another wake cause without checking its work.
  Preserve bounded dispatch, partial-publication progress, notification errors,
  delayed publishers, shutdown and descriptor-generation lifetime.
- Future timer deadlines and dependency-blocked work are not reasons for
  permanent polling; they require appropriate bounded wait/progress sources.
  Correct notification never depends on a later packet, unrelated CLI barrier,
  or a long periodic timeout rescuing missed work.
- Do not require optional kernel membarrier capabilities, custom kernels or
  device-specific power instructions. Use supported baseline system interfaces
  and correctly ordered C/ARM64 atomics; NDK build success is not device proof.
- Retain the existing packet ownership, per-owner capacity and two-copy
  contracts. Notification is neither packet ownership transfer nor delivery
  acknowledgement. No additional packet queue, payload copy or transport-state
  sharing is introduced for waking workers.

The first implementation must be complete for these correctness and lifecycle
requirements, not a temporary "works in a smoke test" version. Established
notification coalescing belongs in this baseline. More aggressive suppression,
spin tails or upstream queue upgrades wait for an observed Product bottleneck;
copy or policy-engine costs are possible hotspots, not measured conclusions.

Fresh Pixel tests must cover isolated sleeping-worker packets, publish/ack/wait
races, local pending frames, both owners and IP families, load-to-idle recovery,
timer/completion progress and stop/restart. Measure idle CPU and latency as well
as resource conservation; pre-register gates and retain the prior P6 results
as historical counter-evidence, never silently relabel them PASS. Any changed
performance gate needs an explicit decision before measurements. Acceptance
of this design does not waive product or release performance qualification.

## Consequences

### 2026-09-12 Qualification task boundary

The user explicitly separates formal CPU/p99 comparison into SAKAMOTO-248.
SAKAMOTO-239 closes W2 ownership, reliable notification, fault settlement and
lifecycle correctness using its current Product/Pixel evidence. This task
split does not approve a new performance comparator or waive the existing
pre-registration, historical P6 non-GO, idle/tail-latency or release gates.
SAKAMOTO-248 retains the formal comparison and qualification requirements;
it does not block subsequent functional implementation merely because those
performance measurements are pending.

- ADR-0008 removes the former Snort C++ daemon, host model, test suite, NDK artifact, and archive. None may be restored, translated, or used as a compatibility fallback for this Adapter. The active product implementation target remains VPP-native C only.
- Packet bytes and live VPP buffer ownership do not cross the Rust compatibility boundary.
- NFQUEUE queue balance supplies receive parallelism and flow stickiness only; it never establishes
  canonical ExecutionOwner or FlowOwner correctness.
- NFQUEUE handles and verdict operations are origin-lane confined; Flow workers never use shared-TX locking
  to bypass completion return.
- Root and VPN remain interchangeable Packet capture Adapters over one VPP graph and policy runtime rather
  than separate dataplanes.
- Production capacity sizing, broader Android payload envelope, product supervisor/restart policy, soak,
  release integration, and any optimized conditional-wake artifact remain release gates rather than accepted
  POC claims. SAKAMOTO-77/S80 provide POC evidence for exactly-once outcome partitioning and IPv4/IPv6
  live-buffer parity, but do not freeze production buffer size, queue/worker counts, credit depth, reserve
  depth, or downstream delivery guarantees.
