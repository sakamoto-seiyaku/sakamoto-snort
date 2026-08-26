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
Initial Execution Placement, not as flow ownership. Each native lane exclusively operates its queue/socket
for receive and verdict. The shared Canonical Flow Key and fixed Worker Layout select the final FlowOwner:
owner-local packets continue without enqueue, while mismatches use bounded canonical-owner processing and
return their terminal intent to the origin lane, which performs the packet's single verdict operation with
the original queue generation and packet ID. VPN begins with one native TUN Platform I/O Lane and uses the
same FlowOwner and completion-routing model; ADR-0007 defines the separate post-policy VPN Flow Stack Packet
Boundary. Normal worker transfer moves VPP buffer indexes and metadata, never copies complete packet bytes.

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

Conditional worker wake is not accepted as part of this ADR. An early P5 diagnostic observed about 44%
sleeping-worker publish-to-terminal p99 improvement, but that result was not a product acceptance result.
The final P6d campaign-21 completed all 32 formal arms validly and still failed the pre-registered gates:
idle C-A one-sided 95% upper `+0.091950 pp` exceeded `+0.05 pp`, while sleep-confirmed p99 improvement
had a one-sided 95% lower bound of `-3.110%` versus the `20%` target. The p50 regression gate passed at
about `+0.054%`; external power remained inconclusive. The wake mechanism therefore remains research-only,
and persistent/per-packet wake remains diagnostic-only. A future adoption discussion requires a new mechanism
hypothesis, independently hashed artifact, and a fresh pre-registered campaign that passes both idle and
sleep-confirmed latency gates.

## Consequences

- ADR-0008 removes the former Snort C++ daemon, host model, test suite, NDK artifact, and archive. None may be restored, translated, or used as a compatibility fallback for this Adapter. The active product implementation target remains VPP-native C only.
- Packet bytes and live VPP buffer ownership do not cross the Rust compatibility boundary.
- NFQUEUE queue balance supplies receive parallelism and flow stickiness only; it never establishes
  canonical FlowOwner correctness.
- NFQUEUE handles and verdict operations are origin-lane confined; Flow workers never use shared-TX locking
  to bypass completion return.
- Root and VPN remain interchangeable Packet capture Adapters over one VPP graph and policy runtime rather
  than separate dataplanes.
- Production capacity sizing, broader Android payload envelope, product supervisor/restart policy, soak,
  release integration, and any optimized conditional-wake artifact remain release gates rather than accepted
  POC claims. SAKAMOTO-77/S80 provide POC evidence for exactly-once outcome partitioning and IPv4/IPv6
  live-buffer parity, but do not freeze production buffer size, queue/worker counts, credit depth, reserve
  depth, or downstream delivery guarantees.
