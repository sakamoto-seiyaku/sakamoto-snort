---
status: accepted
date: 2026-08-02
---

# VPP-native packet I/O adapters

Root/NFQUEUE and VPN/TUN packet I/O execute inside VPP-native C/C++ Adapter plugins rather than crossing a
Rust–VPP–Rust bridge for every packet. Rust remains the product control, lifecycle, configuration, policy
snapshot, status, and compatibility layer behind a coarse-grained non-unwinding C ABI; it does not receive,
complete, return, or own individual live VPP packet buffers. This supersedes ADR-0005 while preserving its
underlying exactly-once Adapter Completion, generation, bounded-resource, and teardown obligations inside
the native Adapter.

Root uses multiple independently owned NFQUEUE lanes with connection-stable kernel `queue-balance` as
Initial Execution Placement, not as flow ownership. Each native lane exclusively operates its queue/socket
for receive and verdict. The shared Canonical Flow Key and fixed Worker Layout select the final FlowOwner:
owner-local packets continue without enqueue, while mismatches use bounded canonical-owner processing and
return their terminal intent to the origin lane, which performs the packet's single verdict operation with
the original queue generation and packet ID. VPN begins with one native TUN/HEV I/O owner and uses the same
FlowOwner and completion-routing model. Normal worker transfer moves VPP buffer indexes and metadata, never
copies complete packet bytes.

This shape is chosen from the Pixel 6a W2/Q2 POC: address-diverse Q2/Q4 kernel placement mismatched the
project's canonical owner for about half of packets, so queue identity cannot replace software distribution;
bounded origin return closed the normal, overload, stale/duplicate, and lifecycle ledgers; shared
NFQUEUE-TX/trylock reached only about 52.6% mixed and 60.9% all-remote direct hits and produced more aggregate
CPU/context activity, so it is rejected. Descriptor/credit depth remains a measured runtime capacity rather
than a fixed architectural constant.

P3 proved route, ownership, and ledger correctness with throwaway copied-prefix descriptors; it did not prove
the production no-copy/live-buffer integration. Its prefix length, pool depth, queue count, and worker count
are scoped experimental parameters, not normative implementation constants.

Conditional worker wake is not accepted as part of this ADR. The POC proved that sleeping-worker
publish-to-terminal p99 improved by about 44%, but the tested diagnostics-disabled handshake failed the
pre-registered idle CPU gate relative to exact-unpatched VPP. The wake mechanism therefore remains a
separate prototype and release gate: an optimized new artifact must pass both idle non-regression and
sleep-confirmed latency regression before adoption. Persistent/per-packet wake remains diagnostic-only.

## Consequences

- Packet bytes and live VPP buffer ownership do not cross the Rust compatibility boundary.
- NFQUEUE queue balance supplies receive parallelism and flow stickiness only; it never establishes
  canonical FlowOwner correctness.
- NFQUEUE handles and verdict operations are origin-lane confined; Flow workers never use shared-TX locking
  to bypass completion return.
- Root and VPN remain interchangeable Packet capture Adapters over one VPP graph and policy runtime rather
  than separate dataplanes.
- Real verdict-send failure settlement, production credit sizing, IPv4/IPv6 live-buffer integration, soak,
  and an optimized conditional-wake artifact remain release gates rather than accepted POC claims.
