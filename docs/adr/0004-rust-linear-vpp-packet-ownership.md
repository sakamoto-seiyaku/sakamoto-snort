---
status: superseded by ADR-0005
date: 2026-08-01
---

# Rust linear ownership for VPP packet buffers

> Superseded on 2026-08-01. This ADR assumed that Rust packet code would execute inside the VPP graph and
> own live VPP buffers across worker processing. That premise was incorrect: Rust replaces the surrounding
> C++ program, while VPP plugins, graph nodes, buffer processing, and worker handoff remain C/VPP. The
> accepted boundary is Rust platform I/O -> C/VPP decision processing -> Rust Adapter Completion. This file
> is retained only to record the rejected premise; none of the `LocalPacket`, Rust worker-handoff, or Rust
> VPP-entrypoint requirements below are normative.

The production VPP/Rust packet path represents an admitted platform packet with the still-live VPP buffer
itself. It does not translate the current C++ descriptor pool, generation handle, or independent
`PacketLease` object into Rust. Adapter completion identity and obligation facts remain inline VPP buffer
metadata, while Rust provides a linear safe owner for the interval in which one worker is processing that
buffer.

On a worker, one live VPP buffer has exactly one safe `LocalPacket`. This type is non-`Copy`, non-`Clone`,
`!Send`, and `!Sync`. Safe graph code may inspect packet bytes and metadata only through lifetime-bounded
borrows. Any terminal disposition or ownership transfer consumes `LocalPacket`; safe code cannot construct
a second owner or independently retain its raw buffer index.

Cross-worker movement does not send the Rust owner. A private unsafe VPP queue boundary consumes the local
owner, extracts the sole raw `u32` index token, and enqueues it. The destination dequeue boundary constructs
exactly one new worker-local owner. The numeric index is copyable inside VPP, but the queue contract treats it
as one linear ownership token. Raw-index construction and extraction remain private unsafe operations with
documented liveness, uniqueness, pool, generation, and queue-state preconditions.

Queue results preserve ownership explicitly: successful enqueue transfers the token to the queue;
non-enqueue returns the still-armed owner to the caller. An Adapter-obligated packet must never use a VPP
handoff mode that frees non-enqueued buffers on congestion. Root platform completion additionally requires a
thread-affine origin-lane permit, and VPN completion requires its I/O-owner permit. Packet ownership alone
does not authorize operation of an NFQUEUE socket, TUN fd, or HEV fd.

The owner uses a private armed/disarmed representation such as `Option<BufferIndex>` and consumes the index
with `take()` at a proven transfer boundary. `Pin` is unnecessary because the wrapper is not address
sensitive. `ManuallyDrop`, `mem::forget`, `Arc`, reference counting, and an independent lease table are not
part of the normal ownership surface.

Rust does not guarantee that destructors run: safe code may forget a value, and process termination or an
aborting panic may skip destruction. Consequently `Drop` cannot prove Adapter exactly-once completion and
must not be the normal error, completion, or fail-open path. Every expected parser, policy, capacity, and
handoff result explicitly consumes the owner into a disposition. In the first release, `Drop` observing an
armed owner records minimal allocation-free invariant evidence and terminates the entire process hosting the
VPP dataplane. It does not invent `ALLOW`, call a thread-affine platform API, directly free an obligated VPP
buffer, attempt worker/Adapter-local in-process recovery, or continue using VPP state after the unique-
ownership proof has broken. A supervisor may start a new dataplane process; Control Plane co-location remains
a separate topology decision. A future emergency-return mechanism requires separate evidence
that it is nonblocking, non-failing, generation-safe, teardown-safe, and unable to duplicate an existing
queue token; even then it is containment rather than the correctness proof.

Rust packet entrypoints called by VPP use the ordinary non-unwinding `extern "C"` ABI. Expected errors return
explicit status or disposition values; Rust panic never crosses into VPP, and a foreign C++ exception never
enters Rust. This FFI soundness rule does not require a repository-wide Cargo `panic = "abort"` profile.
The production panic strategy remains deferred until the Rust crate and process topology is fixed. The
armed-owner fatal invariant is independent of that compilation choice.

## Considered Options

- Make `LocalPacket` `Send` and move it through arbitrary Rust queues. Rejected because `Send` authorizes
  movement to any thread and cannot express transfer only through a specific VPP frame queue or preserve
  thread-affine completion authority.
- Rebuild the C++ descriptor/lease table in Rust. Rejected because VPP already owns the live buffer and
  carries the required metadata; the second lifetime system adds stale-handle and capacity states without
  improving the packet path.
- Use `Drop` to choose fail-open and route completion. Rejected because destructor execution is not
  guaranteed, implicit policy hides missing explicit graph exits, and a destructor may run on a worker that
  has no platform-completion authority.
- Use a worker-local linear owner with private raw-index queue transitions and separate completion permits.
  Accepted because it matches VPP's buffer-index handoff while making duplicate safe owners and arbitrary
  cross-thread use unrepresentable.

## Consequences

- Unsafe code is concentrated in frame ingress/dequeue, packet-view construction, queue transfer, and final
  VPP/platform completion boundaries. Each boundary must document and test its ownership preconditions.
- Packet views cannot outlive the local owner or worker context and cannot coexist with a consuming handoff.
- Root and VPN share the linear ownership contract but keep Adapter-private completion fields and permits.
- Adapter generation remains a runtime metadata check across FFI/queue transitions; Rust lifetimes do not
  replace teardown and generation validation.
- Compile-fail tests must prove the owner and completion permits are neither `Send` nor `Sync` and cannot be
  cloned or converted from raw indices by safe callers.
- Queue fault-injection must prove that every result retains exactly one owner/token and that obligated
  buffers never enter generic congestion-free behavior.
- The unexpected armed-`Drop` path is a product-visible Runtime defect, not a policy verdict or ordinary
  packet-capacity fault.
- Non-unwinding FFI is fixed now; artifact-wide abort versus unwind compilation remains a later packaging
  decision rather than part of this ownership ADR.
