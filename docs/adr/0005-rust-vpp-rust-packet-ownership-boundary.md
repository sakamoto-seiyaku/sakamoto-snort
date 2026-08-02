---
status: superseded by ADR-0006
date: 2026-08-01
---

# Rust–VPP–Rust packet ownership boundary

> Superseded on 2026-08-02. The Android W2/Q2 multi-queue POC showed that a VPP-native Adapter can own
> NFQUEUE ingress, canonical-owner return, and origin-lane verdict completion without a per-packet
> Rust–VPP–Rust bridge. The retained ownership and completion obligations move into the VPP-native Adapter;
> Rust remains the coarse-grained control and compatibility boundary described by ADR-0006. This file is
> retained to record the rejected alternative and is no longer normative.

Rust replaces the surrounding C++ packet-I/O program, not the C VPP plugins or graph. Rust exclusively
owns platform receive and Adapter Completion; a successful ingress call moves one packet into C/VPP, which
exclusively owns its buffer, graph processing, worker handoff, parsing, session work, policy evaluation, and
Runtime Disposition until a terminal Completion Frame moves decided live buffers back to their originating
Rust Platform I/O Lane. Rust then performs each packet's single platform send/allow/drop attempt and returns
the backing buffers to the VPP pool through a narrow batched C buffer-return interface. That final call
performs memory return only: it does not re-enter the graph, revise the decision, perform platform I/O, or
retry completion.

There is exactly one backing buffer pool: the existing modified-VPP pool. The Sakamoto C return wrapper is
not another pool, lease table, or packet store. It accepts only buffer-index ownership and routes it to the
native free path, which performs chain/refcount handling, metadata and exdata cleanup, registered free
callbacks, cache handling, and eventual shared-pool return. The wrapper's registered Rust-lane contract must
be safe for batched calls from those lanes. Rust must not bypass that lifecycle by writing the shared pool
under its lock.

Ingress/result transfer and final return form one bidirectional Rust–VPP bridge. The VPP-to-Rust direction
carries Completion Frames of decided live buffer indexes and Runtime Dispositions; the Rust-to-VPP direction
carries those same indexes back after Adapter Completion. Rust and C may call across this narrow ABI
normally, but neither direction materializes another packet or allocator. Any directional lanes are bridge
transport internals, not additional memory pools or independent PacketLease authorities.

Platform I/O never executes on a VPP Flow worker. Each Rust Platform I/O Lane owns its assigned NFQUEUE or
VPN fd set for both receive and completion, waits for readiness when idle, and drains bounded bursts when
awake. A VPP terminal worker only publishes a Completion Frame. When the lane is armed for sleep, the first
publication that changes its completion state from empty to nonempty may perform one coalesced nonblocking
`eventfd` notification; further publications do not wake per packet, and sustained traffic drains without
repeated notification syscalls. This single wake edge is accepted because prompt completion, a sleeping Rust
owner, and zero producer notification cannot all be provided simultaneously.

Platform batching remains Adapter-specific. A Root lane constructs independent `NFQNL_MSG_VERDICT` messages
and may place several in one Netlink datagram; it does not use `nfq_set_verdict_batch()` unless it has proven a
contiguous same-verdict packet-ID prefix. The VPN lane may use `sendmmsg()` for multiple HEV
`SOCK_SEQPACKET` records. Android TUN remains one packet per `write`/`writev`; its bounded loop still runs only
on Rust, never on a VPP worker. The first release introduces no deliberate batching delay and performs no
automatic completion retry.

The final hot-path return is a bounded, nonblocking, batched call. A checked-out buffer implicitly carries its
right to return, so a valid return in an active Adapter generation cannot encounter `FULL`, rejection, retry,
or fallback. Pool exhaustion can occur only when acquiring an ingress buffer. A valid batch consumes the Rust
leases unconditionally and invokes the native return lifecycle; normal return requires no per-packet
acknowledgement. Teardown keeps the Adapter generation and return interface alive until all outstanding
leases and queued Completion Frames are zero. Stale-generation, duplicate, or invalid-buffer return is an
ownership invariant violation, not an ordinary fallible return result. Detection fail-stops the affected
dataplane runtime: it stops new admission, emits bounded fatal evidence, and relies on the supervisor to
recreate the VPP runtime and its fixed pool. It must not retry, discard the index and continue, or attempt a
speculative free after ownership proof has been lost.

The two Rust/C ownership transfers use a narrow, non-unwinding C ABI with explicit success/failure ownership
semantics. The final buffer-return call instead has a non-failing consume contract for a valid live lease.
Rust must make duplicate use or duplicate return of a returned packet unrepresentable in safe code, but no
Rust owner type exists inside the VPP graph or across VPP worker
handoff. This preserves the zero-copy goal without allowing Rust to manipulate VPP freelists directly or
requiring a full-packet copy out of VPP storage. The first-release ownership protocol ends through an explicit
Rust-to-C buffer-return call; Rust `Drop` behavior is not part of the architecture or PacketLease state model.
