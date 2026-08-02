# Rust/VPP packet ownership research

> Scope correction (2026-08-01): the `LocalPacket` model below assumed Rust would own VPP buffers while
> executing packet work inside the VPP graph. That premise was rejected. Rust owns platform I/O before VPP
> ingress and after VPP returns its result; C/VPP exclusively owns graph processing and worker handoff. The
> detailed Rust/VPP-buffer owner model below is therefore non-normative and must not guide implementation.

Date: 2026-08-01

Status: focused implementation research. This note does not change an accepted architecture decision.

Discussion refinement: the research recommendation to use `panic = "abort"` for the release packet crate was
not accepted as a current architecture requirement. The accepted boundary is ordinary non-unwinding
`extern "C"`, explicit expected-error returns, and no panic or foreign exception crossing the VPP/Rust FFI.
The artifact-wide panic strategy is deferred until crate/process topology is known. The armed-owner fatal
invariant remains accepted and does not depend on the selected Cargo panic profile.

## Question

How should a Rust replacement represent one still-live VPP buffer, lend packet views to graph code,
transfer ownership across VPP workers, and preserve thread-affine Root/VPN completion without copying
packet bytes or creating a second lease object?

## Executive conclusion

Use a small **worker-local linear owner**, not a globally `Send` RAII handle:

```rust
#[must_use = "a live VPP packet must be explicitly completed or transferred"]
pub(crate) struct LocalPacket {
    index: Option<BufferIndex>,
    _thread_local: PhantomData<*mut ()>, // !Send + !Sync
}
```

- `LocalPacket` is non-`Copy`, non-`Clone`, `!Send`, and `!Sync`.
- Its constructor from a raw `u32` is private and `unsafe`; only frame ingress/dequeue code may call it.
- Inspection returns lifetime-bounded views borrowed from `LocalPacket`; ordinary code never obtains a
  raw index or an unbounded packet pointer.
- A cross-worker handoff consumes the local owner, extracts the index, and calls one private queue
  abstraction. The queue physically copies a `u32`, but semantically moves the sole ownership token.
  Its dequeue boundary constructs the next worker's `LocalPacket` exactly once.
- Root NFQUEUE completion additionally requires an origin-lane permit; VPN completion requires its I/O
  owner permit. Those permits are also `!Send + !Sync`. Merely holding a packet cannot authorize an FD or
  NFQUEUE operation.
- Use an `Option<BufferIndex>` as the armed/disarmed field. This avoids placing `ManuallyDrop` in the
  public owner and makes a successful explicit transfer disarm the destructor with safe code.
- `Drop` is an invariant tripwire, not the normal fail-open/completion path and not the proof of
  exactly-once. A destructor must not invent policy, call a thread-affine platform API, free an obligated
  VPP buffer, or silently continue after losing its only handle. The first implementation should record a
  minimal fatal diagnostic and terminate the runtime on an armed unexpected drop. If later evidence proves
  a nonblocking, non-failing, generation-safe emergency return primitive, `Drop` may use it as a best-effort
  containment mechanism, but correctness must remain independent of it.
- `Pin` is irrelevant: the Rust owner is an index value, has no self-reference, and does not depend on its
  own address.

This is stricter and simpler than making `OwnedPacket: Send`. If an owning wrapper implements `Send`, any
safe Rust caller can move it to an arbitrary thread; `Send` cannot express “only transferable through this
specific VPP frame queue.” Keeping the local owner `!Send` and putting the raw-index transition inside a
private handoff abstraction expresses the real boundary.

## Evidence and reasoning

### 1. Move-only owner and borrowed packet views

Rust references borrow rather than own, and their lifetime bounds how long the referent may be used. A
consuming method taking `self` moves the owner, making the old binding unusable. These language properties
fit a live VPP buffer directly: parsing accepts `&LocalPacket` (or a view tied to that borrow), while
handoff and completion consume `LocalPacket`. See the official Rust Book on
[ownership](https://doc.rust-lang.org/stable/book/ch04-01-what-is-ownership.html) and
[references and borrowing](https://doc.rust-lang.org/stable/book/ch04-02-references-and-borrowing.html).

Recommended surface:

```rust
impl LocalPacket {
    pub(crate) fn view<'a>(&'a self, worker: &'a WorkerContext) -> PacketView<'a>;

    pub(crate) fn handoff(
        self,
        queue: &WorkerHandoffQueue,
        target: WorkerId,
    ) -> Result<(), HandoffError<Self>>;

    pub(crate) fn complete_root(
        self,
        permit: &mut RootLanePermit<'_>,
        intent: TerminalIntent,
    ) -> CompletionOutcome;
}
```

`PacketView<'a>` may contain references/slices created by a narrow unsafe VPP accessor, but `'a` must be
tied to both the owner borrow and the worker context that makes the VPP buffer address valid. No view may be
stored in a queue, returned as `'static`, or coexist with a consuming transfer. Mutation should require a
separate capability rather than exposing `&mut [u8]` from the ordinary owner.

The existing C++ baseline already deletes copy construction/assignment and permits only move construction/
assignment (`src/core/flow/FlowSteering.hpp`, `PacketLease`, lines 126-137). Rust should preserve that intent,
not its separate descriptor table.

### 2. Raw-index construction is necessarily unsafe

A `u32` cannot prove that the VPP buffer is live, uniquely owned, from the expected pool/runtime, or not
already queued. Therefore this must not exist as a public safe conversion:

```rust
impl LocalPacket {
    /// # Safety
    /// `index` names one live VPP buffer owned exclusively by the caller. No other
    /// LocalPacket or queued ownership token may exist for it.
    unsafe fn from_frame_index(index: u32) -> Self;
}
```

The Rust Reference defines an unsafe function as one whose caller must uphold extra conditions the compiler
cannot check, and requires those conditions to be documented. It also distinguishes the unsafe function's
proof obligation from the unsafe block that discharges one
([Rust Reference: `unsafe`](https://doc.rust-lang.org/stable/reference/unsafe-keyword.html)). Enable
`#![deny(unsafe_op_in_unsafe_fn)]` even if the first crate is not yet Edition 2024.

Keep all constructors in the VPP boundary module. Safe packet code should not be able to obtain
`BufferIndex`, call `from_frame_index`, or manufacture an owner from Adapter metadata.

### 3. Cross-worker handoff: numeric copy, semantic move

The modified VPP handoff implementation compresses `u32` buffer indices into the destination frame queue,
publishes the element, and returns the number enqueued
(`/home/js/backup/backup/Git/vpp/src/vlib/buffer_funcs.c`, lines 290-346). Copying those four bytes is not a
second packet owner if the Rust handoff abstraction consumes the source owner and only the dequeue boundary
can reconstruct the destination owner.

The abstraction must specify ownership for every result:

```text
enqueue success       source disarmed; queue owns index
enqueue not performed source owner returned in HandoffError<LocalPacket>
dequeue success       queue token consumed; destination LocalPacket created once
congestion drop       forbidden for an obligated platform packet
```

This last rule matters because VPP's generic `vlib_buffer_enqueue_to_thread(..., drop_on_congestion=1)`
frees indices that could not be queued (same file, lines 343-346). An obligated PacketLease cannot use that
behavior. The selected completion/return queue must either be capacity-proven not to fail or return ownership
to the caller without freeing it.

Rust's standard channel error types follow the useful ownership pattern: `SendError<T>` contains the value
that could not be sent, allowing the caller to recover it
([`std::sync::mpsc::SendError`](https://doc.rust-lang.org/std/sync/mpsc/struct.SendError.html)). The VPP queue
wrapper should provide the same semantic contract even though it does not use `std::sync::mpsc`.

### 4. `Send`/`Sync` and thread-affine completion

`Send` means ownership may be transferred between threads; `Sync` means shared references may be shared
between threads. They are auto traits, so a wrapper containing only `u32` fields becomes both automatically
([Rust Book: `Send` and `Sync`](https://doc.rust-lang.org/stable/book/ch16-04-extensible-concurrency-sync-and-send.html),
[`std::marker::Sync`](https://doc.rust-lang.org/std/marker/trait.Sync.html)). That default is too broad for a
worker-local VPP context.

Use `PhantomData<*mut ()>` to suppress both auto traits on stable Rust. The official Nomicon lists
`PhantomData<*mut T>` as `!Send + !Sync`; `PhantomData<Cell<&'a ()>>` would instead be `Send + !Sync`
([Nomicon: `PhantomData`](https://doc.rust-lang.org/nomicon/phantom-data.html)). The latter is not recommended
for `LocalPacket`, because it still permits arbitrary thread transfer.

Thread-affine authority should be a separate, unforgeable borrow:

```rust
pub(crate) struct RootLanePermit<'lane> {
    lane: LaneId,
    generation: AdapterGeneration,
    _lane: PhantomData<&'lane mut RootLaneContext>,
    _thread_local: PhantomData<*mut ()>,
}
```

`complete_root` validates the buffer metadata's origin lane/generation against the permit before clearing
the obligation and invoking the platform completion boundary. The analogous VPN permit belongs to the
single I/O owner. This separates **packet ownership** (which moves between workers) from **completion
authority** (which does not).

Alternative rejected: `OwnedPacket: Send + !Sync`. It prevents concurrent shared access but allows safe
code to move the destructor and packet to any thread. The Nomicon uses a thread-affine guard as the canonical
reason a destructor-bearing type may need to be `!Send`
([Nomicon: `Send` and `Sync`](https://doc.rust-lang.org/nomicon/send-and-sync.html)).

### 5. `Drop` cannot prove external completion

Normal scope exit and Rust unwinding run destructors
([Rust Reference: destructors](https://doc.rust-lang.org/stable/reference/destructors.html),
[Rust Reference: panic unwinding](https://doc.rust-lang.org/stable/reference/panic.html)). That makes `Drop`
useful for detecting an accidental `?`, early return, or forgotten branch.

It is not a correctness guarantee:

- `mem::forget` is safe and deliberately suppresses the destructor; its documentation explicitly says
  Rust safety does not guarantee destructors always run
  ([`core::mem::forget`](https://doc.rust-lang.org/core/mem/fn.forget.html)).
- `std::process::exit` does not run stack destructors on any thread
  ([`std::process::exit`](https://doc.rust-lang.org/std/process/fn.exit.html)).
- `panic=abort` aborts immediately, irrespective of FFI ABI, so it does not unwind packet owners
  ([Nomicon: FFI and unwinding](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding)).

Therefore “exactly one Adapter completion while the runtime remains healthy” must be proved by explicit
graph exits, consuming methods, queue ownership, and the teardown barrier. It must not be stated as “the
destructor guarantees completion.”

Recommended destructor policy:

1. A normal handoff/completion takes the index out of `Option`, performs the ownership transition, and leaves
   `None`; `Drop` then does nothing.
2. `Drop` observing `Some(index)` records one allocation-free fatal invariant diagnostic.
3. First implementation terminates the runtime rather than freeing an obligated buffer, calling a foreign
   socket from the wrong worker, inventing `ALLOW`, or continuing after losing the unique handle.
4. A later emergency-return enqueue is permissible only if independently proven nonblocking, non-failing,
   valid throughout teardown, generation checked, and unable to duplicate an already queued owner. Even then
   it is best-effort containment, not the ownership proof.

Why not immediately put fail-open recovery in `Drop`? It mixes policy and thread routing into an implicit
language hook, may execute during panic/unwind, and has no general way to report queue failure. It would also
hide missing explicit graph exits. All expected parser/capacity/control errors should explicitly consume the
packet into the already accepted runtime disposition path.

### 6. Prefer `Option::take` over a public `ManuallyDrop` design

`ManuallyDrop<T>` inhibits automatic destruction but shifts the “moved exactly once” proof into unsafe code.
Its official documentation warns that manually dropped values must not be exposed back to safe code and that
`take` leaves the container apparently unchanged, requiring the caller to prevent reuse
([`std::mem::ManuallyDrop`](https://doc.rust-lang.org/std/mem/struct.ManuallyDrop.html)).

An internal `Option<BufferIndex>` provides the required armed/disarmed representation with safe operations:

```rust
fn take_index(&mut self) -> BufferIndex {
    self.index.take().expect("LocalPacket already consumed")
}
```

Do not expose this method outside the ownership module. If a very narrow FFI adapter later needs
`ManuallyDrop` to eliminate a panic window while converting ownership, confine it to that adapter and keep it
out of the public struct. Never use `mem::forget` as the normal ownership-transfer primitive.

### 7. Panic and FFI rules

Rust panics must not cross the VPP C ABI. Use non-unwinding `extern "C"` entrypoints. If a Rust panic reaches
a non-unwind ABI boundary it safely aborts; `extern "C-unwind"` is only for an intentional cross-language
unwind contract and is inappropriate here
([Nomicon: FFI and unwinding](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding),
[Rust Reference: external ABIs](https://doc.rust-lang.org/reference/items/external-blocks.html#abi)).

Recommended first-release posture:

- release packet crate: `panic = "abort"`;
- no panicking operations in normal packet/Drop paths (no indexing without checks, allocation, formatting,
  mutex poisoning assumptions, or `unwrap` on runtime data);
- `Drop` uses a no-panic fatal hook, not `panic!`;
- convert every expected error to an explicit consuming disposition before returning to C;
- do not claim `catch_unwind` restores a packet after arbitrary panic; with `panic=abort` it cannot run, and
  with unwinding it only catches Rust panics under its documented limits.

An abort does not run destructors, so crash recovery remains an Adapter/supervisor/kernel responsibility,
not a Rust ownership property.

### 8. `Pin` is not needed

Pinning is for values whose validity depends on remaining at one memory address, such as self-referential
types and intrusive structures
([`std::pin`](https://doc.rust-lang.org/std/pin/)). Moving a Rust `LocalPacket` changes only the location of a
small index/guard value; the VPP buffer remains in VPP storage and is found again through the index. The
wrapper is not address-sensitive, so adding `Pin` or `PhantomPinned` would add ceremony without protecting a
real invariant.

### 9. Generation and ABA protection

Adapter generation is still required in buffer metadata and completion permits. It prevents an old Root
queue identity or VPN completion target from being used after teardown/profile replacement.

Do not add a second Rust generation table merely because VPP indices are reusable. Under the linear model,
an index can be reused only after its old owner was explicitly completed/freed, at which point no old safe
owner or queue token remains. If future code stores raw indices in detached tasks, timers, or externally
addressable handles, that breaks the premise and requires a new generation/lifetime design rather than a
small exception.

### 10. FFI representation

Do not pass `LocalPacket`, Rust references, `Option`, or Rust enums across C ABI. Pass raw scalar indices and
explicit `#[repr(C)]` data-transfer structs only at the boundary. A private
`#[repr(transparent)] struct BufferIndex(u32)` has the same layout and ABI as `u32`, according to the Rust
Reference
([type layout: transparent representation](https://doc.rust-lang.org/stable/reference/type-layout.html#the-transparent-representation)),
but representation does not establish liveness or uniqueness; construction remains unsafe.

For VPP opaque metadata mirrored in Rust:

- use `#[repr(C)]` and fixed-width integer fields;
- represent C bitfields/foreign enums as integers plus validation rather than accepting arbitrary bytes as a
  Rust enum discriminant;
- add C and Rust compile-time size/alignment/offset checks;
- keep Adapter-private union interpretation behind the Adapter module.

The modified fork similarly keeps small ownership facts in VPP buffer metadata and passes buffer indices.
For example, `vnet_buffer_opaque3_t` contains `session_owner_thread` and packet flags
(`/home/js/backup/backup/Git/vpp/src/vnet/buffer.h`, lines 543-571), while session cleanup frees retained
first-packet indices only if ownership was not transferred
(`/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager.c`, lines 324-340).
This supports the buffer-resident model but does not itself supply Rust's proof boundary.

## Minimal type/operation model

```text
unsafe frame ingress/dequeue
        |
        v
LocalPacket (!Send, !Sync, armed)
  | borrow                  | consume                 | consume
  v                         v                         v
PacketView<'_>       private VPP handoff       completion + lane permit
                           |                         |
                           v                         v
                    queued raw u32             obligation cleared,
                    (sole queue token)          one platform operation,
                           |                    buffer freed
                           v
                 unsafe destination dequeue
                           |
                           v
                 LocalPacket (!Send, !Sync)
```

There is no separate lease allocation, descriptor table, `Arc`, reference count, `Pin`, or packet copy.

## Required proof/tests before implementation acceptance

1. Compile-fail tests (for example `trybuild`) proving `LocalPacket` and completion permits are neither `Send`
   nor `Sync`, cannot be cloned, and cannot expose a raw index through safe APIs.
2. Property/model tests for enqueue success/failure/dequeue showing exactly one armed owner or queue token at
   every step.
3. Tests that every expected parser/policy/capacity error explicitly consumes the packet; no normal test may
   trigger the unexpected-`Drop` hook.
4. Fault injection at handoff/return queue saturation and teardown, proving an obligated buffer is never
   passed to VPP's congestion-free path.
5. Origin lane/generation mismatch tests proving completion performs no platform call and enters the explicit
   invariant-fault path.
6. FFI layout assertions for all shared structs and sanitizer/Miri coverage for the pure-Rust ownership
   wrapper where possible. Miri cannot validate VPP itself, so FFI preconditions still require native tests.
7. A release-profile test confirming the selected panic strategy and that no Rust panic unwinds across a C
   entrypoint.

## Decision recommendation for the ongoing discussion

Accept the non-`Copy`/non-`Clone` principle, but refine it as follows:

> Each worker holds a `!Send + !Sync` `LocalPacket`. Cross-worker movement consumes it through a private VPP
> queue boundary that transfers one raw buffer index and reconstructs one new local owner. Platform
> completion additionally requires a thread-affine origin permit. `Drop` is a fatal invariant tripwire, not
> fail-open policy and not the exactly-once proof.

This is the smallest model that uses Rust ownership where it is strong, while acknowledging what Rust does
not guarantee: destructor execution, external I/O completion, VPP index uniqueness, and queue behavior.
