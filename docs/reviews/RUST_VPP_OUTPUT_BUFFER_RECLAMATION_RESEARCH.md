# Rust/VPP output buffer reclamation research

Date: 2026-08-01

Status: superseded implementation research. Source-level facts about native VPP free remain useful, but the
foreign-context return-route recommendation below is not the accepted Sakamoto architecture. ADR-0006 keeps
packet I/O, completion, and native buffer return inside the VPP Adapter; Rust has no live-buffer return path.
Do not use this note to reintroduce a second return route, return capacity, or per-packet Rust bridge.

> Historical ADR-0005 correction (2026-08-02), itself superseded by ADR-0006: a valid checked-out buffer was
> modeled as implicitly carrying its right to return, with Rust performing platform completion through a C
> batch-return interface. That Rust return path is no longer the current design. The historical alternatives
> below remain useful only for explaining why arbitrary raw `vlib_buffer_free` calls are not an interface.

## Question

After Rust has transferred a packet into C/VPP, how should it later regain a decided VPP-backed packet,
perform Root/VPN platform I/O, and return the backing buffer without confusing Adapter Completion with VPP
allocator reclamation?

## Executive conclusion

There are two separate operations with different failure models:

1. **Adapter Completion / platform I/O** may succeed, fail definitely, or have unknown outcome. NFQUEUE
   verdict submission, TUN write and HEV-facing socket send have real return values and errors.
2. **Reclamation of one valid owned VPP buffer reference** is not an I/O operation. VPP's native
   `vlib_buffer_free`, `vlib_buffer_free_no_next` and `vlib_buffer_free_one` return `void`; they decrement
   reference counts and return buffers whose count reaches zero to a pool. Invalid/double release is a
   violated precondition detected by assertions/debug validation, not a recoverable allocator error.

Therefore:

- the production interface is the registered Sakamoto Rust→C batch-return wrapper, not raw
  `vlib_buffer_free` and not a separate return route;
- a Rust Platform I/O Lane passes only valid owned buffer indexes; the wrapper consumes them without an
  ordinary failure result and preserves the native VPP cleanup/pool lifecycle internally;
- logical Adapter Completion is recorded before/independently of reclamation. A reclamation invariant fault
  must never rewrite an `ALLOW`/`DROP` Policy Verdict or a platform completion outcome;
- first release uses synchronous nonblocking platform calls on the designated Platform I/O Lane, then explicitly
  consume/reclaim the lease. True kernel-async I/O over VPP memory is a later lifetime design: the lease must
  remain live until kernel completion.

The accepted first-release architecture specifies only explicit consume/release through the C return wrapper.
It does not assign protocol semantics to Rust `Drop`; an internal RAII guard remains an optional implementation
technique rather than part of PacketLease or Adapter Completion.

The registered C return wrapper is not a second memory pool or queue. It returns owned indexes to the one
existing modified-VPP buffer lifecycle while preserving native cleanup and callbacks.

## 1. What VPP native free actually does

### API and return value

In the modified fork:

```c
always_inline void vlib_buffer_free(vlib_main_t *vm, u32 *buffers, u32 n);
always_inline void vlib_buffer_free_no_next(vlib_main_t *vm, u32 *buffers, u32 n);
always_inline void vlib_buffer_free_one(vlib_main_t *vm, u32 buffer_index);
```

All call `vlib_buffer_free_inline`; none reports failure
(`/home/js/backup/backup/Git/vpp/src/vlib/buffer_funcs.h`, lines 795-1071).

For each buffer, the implementation validates the buffer in assertion-enabled builds, atomically decrements
`ref_count`, and queues it for pool return only when the count becomes zero. `vlib_buffer_free` follows and
releases `VLIB_BUFFER_NEXT_PRESENT` chains; `vlib_buffer_free_no_next` releases only the supplied references.
Consequently, a successful logical release does not necessarily make a buffer immediately available: another
valid reference can keep `ref_count > 0`. That is normal reference accounting, not failure.

### Preconditions and invariant failures

`vlib_buffer_validate` asserts `ref_count > 0`, a valid pool index, and that the buffer address lies in that
pool (`buffer_funcs.h`, lines 96-109). With `CLIB_DEBUG > 0`, `vlib_buffer_pool_put` calls
`vlib_buffer_validate_alloc_free(..., VLIB_BUFFER_KNOWN_ALLOCATED)`; the validator calls `clib_panic` for an
unknown/already-free index (`src/vlib/buffer.c`, lines 309-340). Release builds do not turn those bugs into a
recoverable status.

The free path also calls registered free callbacks before pool insertion, but ignores their `u32` return
values (`buffer_funcs.h`, lines 739-754). A callback is therefore not a veto/failure channel for reclamation.

**Finding:** a wrapper that returns “VPP allocator free failed” would invent a state the native API does not
have. The valid call consumes the reference; an invalid call is a correctness bug and may assert, panic, corrupt
state or double-return in a non-debug build.

### Thread/context affinity

`vlib_buffer_pool_put` selects `bp->threads[vm->thread_index]`, fills that VPP context's per-thread cache, and
only takes the pool spinlock when overflowing to the shared pool (`buffer_funcs.h`, lines 734-783). This is
strong local-source evidence that a random Rust adapter thread should not manufacture/use a worker's `vm` and
call `vlib_buffer_free_one` directly.

Historical upstream VPP frame queues had an explicit `VLIB_FRAME_QUEUE_ELT_FREE_BUFFERS` message whose target
VPP thread handled the message by calling `vlib_buffer_free(vm, ...)`
([FD.io VPP 20.05 `threads.c`](https://s3-docs.fd.io/vpp/20.05.1/d3/d18/threads_8c_source.html#l00450)). The
current modified fork no longer exposes that exact mechanism in the inspected source, so it should not be
copied as an API. It is primary-source precedent for the ownership pattern: foreign/producer context returns
indices; the destination VPP context performs native reclamation.

## 2. Narrow C API: distinguish direct free from cross-thread return

### Same-context primitive

If C invokes Rust synchronously from the VPP context and still owns the lease, the internal C helper can be:

```c
void sakamoto_vpp_release_local_v1(
    struct sakamoto_vpp_context *context,
    uint32_t buffer_index);
```

Its contract, not its return value, must state:

- caller owns exactly one live reference to the head buffer;
- `context` is the current VPP execution context for the call;
- no borrowed packet pointer survives the call;
- the PacketLease completion obligation has already been cleared by its proper completion owner;
- the call consumes the caller's reference, including the chain if the wrapper uses `free_one`.

This function should be private/unsafe to Rust. Assertions, generation checks and counters are valuable, but
they do not convert native free into `Result`.

### Cross-thread return primitive

When a Rust I/O owner is not executing as the target VPP context, its API is not direct “free”; it routes this
owned token to the VPP context that performs native free:

```c
void sakamoto_vpp_return_buffer_v1(
    struct sakamoto_return_port *port,
    uint32_t adapter_generation,
    uint32_t buffer_index);
```

Required semantics:

- a valid call consumes the sole Rust token; Rust must never use or return the index again;
- target VPP context drains tokens, validates the still-live Buffer-Resident PacketLease metadata, clears
  reclamation-only state, and calls native `vlib_buffer_free_one`.
- queue closure happens only after ingress is quiesced and outstanding output leases/return tokens are zero.

The one preallocated VPP buffer population is the capacity ledger. Every checked-out buffer implicitly carries
its place on the way back; the route must be sized from the complete eligible population and kept alive until
its outstanding count reaches zero. Consequently the API must not expose `FULL`, closed, retry, or fallback as
ordinary outcomes. Stale-generation, duplicate, invalid-index, or premature-close observations are ownership
invariant failures; assertions and fatal diagnostics should expose them rather than inventing a recoverable
owner state after the consume boundary.

## 3. Rust ownership model for a returned packet

Recommended safe wrapper:

```rust
#[must_use = "a returned VPP packet must be explicitly reclaimed"]
pub(crate) struct OutputLease {
    token: Option<ReturnToken>,
    view: PacketViewDescriptor,
    completion: Option<AdapterCompletion>,
    _not_send_sync: PhantomData<*mut ()>,
}
```

- non-`Copy`, non-`Clone`;
- constructed only by a private unsafe dequeue boundary after consuming one VPP return-queue token;
- `bytes(&self)` creates a borrow whose lifetime cannot exceed the lease;
- platform I/O borrows bytes; it does not consume/release the buffer;
- recording Adapter Completion stores logical evidence but does not reclaim memory;
- `return_to_vpp(self)` consumes the valid lease unconditionally.

Illustrative API:

```rust
impl OutputLease {
    fn bytes(&self) -> &[u8];

    fn record_completion(
        &mut self,
        outcome: AdapterCompletion,
    ) -> Result<(), DuplicateCompletion>;

    fn return_to_vpp(mut self, port: &ReturnPort) {
        let token = self.token.take().expect("already consumed");
        unsafe { port.return_buffer(token) }
    }
}
```

The real implementation must not panic on runtime data; the example only shows linear ownership. Contract
validation belongs at the unsafe boundary and in invariant checks, not in an ordinary return-failure enum.

Adapter-private completion APIs should normally combine “perform exactly one platform operation” and “record
its outcome,” then call `return_to_vpp` as a separate final step. This keeps Adapter Completion evidence
separate from the buffer lifecycle.

## 4. Platform I/O and buffer lifetime

### Synchronous Root/NFQUEUE completion

`nfq_set_verdict` returns the result of the netlink send path; official source returns `nfnl_sendiov(...)`
([libnetfilter_queue source](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/libnetfilter__queue_8c_source.html#l00855)).
The origin lane performs the one call, classifies its return as the already defined Adapter Completion
outcome, then returns the VPP backing token to its VPP reclamation context. Reclamation neither proves nor
retries the verdict.

Root normally does not need packet bytes for an unchanged ACCEPT/DROP verdict, but it must keep the lease live
until the verdict operation returns because the completion identity and obligation metadata remain attached
to it.

### Synchronous TUN/HEV output

Linux `write`/`writev` and `sendmsg` return bytes transferred or `-1`; ordinary write APIs may report partial
success, and a nonblocking socket may return `EAGAIN`/`EWOULDBLOCK
([write(2)](https://man7.org/linux/man-pages/man2/write.2.html),
[writev(2)](https://man7.org/linux/man-pages/man2/writev.2.html),
[sendmsg(2)](https://man7.org/linux/man-pages/man2/sendmsg.2.html)). Linux TUN accepts IP packets written by
userspace ([kernel TUN/TAP documentation](https://docs.kernel.org/networking/tuntap.html)).

For the first release:

1. the designated I/O owner waits for/observes readiness without lending out the packet;
2. it borrows the VPP bytes and performs the one configured nonblocking syscall;
3. it classifies the exact return (including unexpected short write) into Adapter Completion;
4. after the syscall returns, the borrow ends;
5. it explicitly returns/reclaims the `OutputLease`.

Readiness waiting before the one physical submission is not a second submission. If the chosen first-release
contract treats `EAGAIN` as a failed/unknown one-shot completion, it must not loop inside `reclaim` or retain the
lease in an unbounded retry queue.

### True asynchronous kernel I/O

If packet data is submitted to POSIX AIO, io_uring, zero-copy send, or another operation that may still read
the userspace memory later, immediate VPP release is invalid. Linux's io_uring documentation states that data
buffers for inflight read/write operations must remain valid until completion
([io_uring(7)](https://man7.org/linux/man-pages/man7/io_uring.7.html)); POSIX AIO has the same lifetime rule
([aio(7)](https://man7.org/linux/man-pages/man7/aio.7.html)).

That design requires a new explicit owner:

```text
OutputLease --submit accepted--> InflightOutputLease --CQE--> OutputLease/CompletedLease --return_to_vpp--> VPP
```

The request table owns the noncopy lease token until the exact completion event; teardown must cancel/drain
inflight operations before closing the return port. A raw buffer index in `user_data`, a detached future, or
release immediately after SQE submission is insufficient. This is the future detached-async lifetime design
already excluded from the first release.

## 5. Alternatives

### Callback-scoped borrow

C retains ownership, calls Rust with a borrowed packet view, Rust performs synchronous I/O and returns an
outcome, and C releases locally after the callback.

**Good:** smallest Rust lifetime surface; no cross-thread reclamation queue; Rust cannot retain the view in
safe code.

**Limit:** callback must run on the correct VPP/I/O context and finish synchronously. It cannot wait for
readiness or kernel-async completion, and doing blocking I/O on a packet worker is unacceptable. The accepted
architecture assigns Root/VPN platform I/O to Rust rather than a VPP execution context, so this is not the
first-release path.

### Explicit consume/release

Rust owns `OutputLease`, performs synchronous I/O, and calls `return_to_vpp(self)`.

**Good:** directly expresses the actual ownership transfer; works with a separate I/O owner; the valid consume
boundary is linear and easy to test.

**Recommendation:** default.

### Optional implementation-local RAII guard

`Drop` can catch accidental early returns, but Rust explicitly permits `mem::forget`, process exit skips stack
destructors, and `panic=abort` does not unwind
([`mem::forget`](https://doc.rust-lang.org/core/mem/fn.forget.html),
[`process::exit`](https://doc.rust-lang.org/std/process/fn.exit.html),
[Rust panic/FFI rules](https://doc.rust-lang.org/nomicon/ffi.html#ffi-and-unwinding)). It therefore cannot prove
the architecture's exactly-once ownership protocol and must not perform or invent Adapter Completion.

**Conclusion:** do not prescribe `Drop` in the architecture. The normal path explicitly calls the C return
wrapper. A future implementation may use a module-private RAII guard solely to prevent an early-return leak,
but correctness, Adapter Completion, and shutdown accounting must not depend on its destructor running.

### Deferred release queue

Rust enqueues a token; a target VPP context frees it.

**Good:** respects VPP per-thread context/cache; batches frees; supports a separate Rust I/O owner.

**Cost:** one bounded queue and drain node when the existing result transport cannot be reused;
teardown/generation and the capacity proof become explicit. This is warranted boundary complexity, not a
second packet/lease table or capacity resource: the queue contains only the live buffer index plus the minimum
generation/routing token, and its usable capacity covers the complete eligible buffer population.

**Recommendation:** use for cross-thread output; direct local free only for callback-scoped same-context output.

## 6. Recommended state/ordering

```text
decided VPP packet
  -> ownership returned to designated Root lane / VPN I/O owner
  -> OutputLease owns live VPP backing
  -> platform syscall borrows bytes/identity
  -> Adapter Completion outcome recorded
  -> borrow ends
  -> return port consumes buffer token (Rust owner disarmed; no ordinary failure result)
  -> target VPP context drains token
  -> clears reclamation metadata
  -> vlib_buffer_free_one(void)
```

For policy `DROP` with no platform byte submission, the designated Rust completion owner records the relevant
completion/disposition and enters the same return tail. The accepted first-release boundary sends every
decided buffer to Rust Adapter Completion; the VPP Flow owner does not locally free policy drops.

## 7. POC and acceptance gates

1. **Native behavior:** debug build proves a valid release, chain release and `ref_count > 1` release; fault
   tests in a subprocess demonstrate double/invalid free is an assertion/panic, not a returned error.
2. **Threading:** compare direct free on the owning VPP context with Rust-thread return + VPP-context drain;
   prohibit arbitrary-thread native free in the safe API.
3. **Route ownership:** model/property tests prove every valid return consumes the Rust owner and every
   dequeued token is freed once.
4. **Capacity:** prove the route's usable capacity covers the complete eligible-live-buffer population,
   including any reserved slot; maximum legal occupancy cannot produce `FULL`. Inject undersizing, premature
   close, stale generation, duplicate, and invalid tokens only to verify fatal invariant detection.
5. **Platform results:** NFQUEUE error, TUN/HEV success, short write, `EINTR`, `EAGAIN`, peer close and teardown
   each record completion first and reclaim exactly once afterward.
6. **Borrow lifetime:** compile-fail tests prove packet views cannot outlive/move independently of
   `OutputLease`; `OutputLease` is noncopy/nonclone and thread-affinity matches the I/O owner.
7. **Async gate:** if any io_uring/AIO/zero-copy path is proposed, demonstrate that reclamation occurs only
   after CQE/notification/cancellation drain, including shutdown. Otherwise it remains out of scope.
8. **Performance:** batch return tokens and VPP frees; measure cycles/packet, return-ring occupancy, drain
   latency, cache misses and pool availability against same-context C free.

## Final recommendation

Model a decided returned packet as an explicit Rust `OutputLease`. Platform I/O borrows it and produces an
Adapter Completion outcome. Then `return_to_vpp(self)` transfers the buffer token through a capacity-derived
VPP-context return port. A valid return consumes ownership and has no ordinary result; the target VPP context
later calls native `vlib_buffer_free_one`, whose truthful return type is also `void`. Pool exhaustion exists
only at ingress checkout, never when returning a buffer that is already one member of that fixed pool.

Use callback-scoped local release only where Rust runs synchronously on the correct VPP/I/O context. Do not
make RAII Drop part of the ownership protocol, do not call VPP free from an arbitrary Rust thread, and do not
submit VPP memory to true asynchronous I/O without an explicit inflight lease that survives until completion.
