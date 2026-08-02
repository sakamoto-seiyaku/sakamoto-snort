# Returning VPP-Owned Packet Buffers from Foreign Rust Threads

Status: superseded research note; not an accepted design basis
Date: 2026-08-01

> Superseded on 2026-08-02. ADR-0006 keeps packet I/O, Adapter Completion, and buffer return inside the
> VPP-native Adapter, so production has no foreign Rust-thread packet return boundary. The VPP/DPDK/AF_XDP
> facts below remain evidence that callers must use an allocator-specific interface rather than inventing
> raw foreign-thread frees. The option-B recommendation and sizing discussion are historical and non-normative.

> Design correction (2026-08-01): an earlier revision modeled the internal return route as an independently
> fallible queue with `Accepted`/`Rejected` results. That contradicts the fixed-pool conservation invariant.
> A valid checked-out buffer already accounts for one member of the sole preallocated pool, so its return
> cannot fail for capacity. The route must be sized from every buffer eligible to use it and remain open until
> all such buffers return. `FULL`, closed-port, stale-generation, duplicate, and invalid-buffer conditions are
> design/lifecycle invariant violations, not ordinary ownership results.

## Historical question and rejected conclusion

When a separate Rust I/O thread finishes with a packet whose storage is still owned by VPP, which context should perform the final `vlib_buffer_free`?

There is no current, upstream VPP API or cross-framework industry rule that makes arbitrary foreign-thread calls to `vlib_buffer_free` a recognized best practice. This research originally recommended:

> Historical/rejected: route the live buffer index through bounded storage and let a designated VPP context
> drain it.

ADR-0005 rejected that additional return route in favor of a Sakamoto-owned, registered Rust→C batch-return
interface to the sole pool. The evidence below still explains why the wrapper must own allocator-specific
details; it does not select an internal return-ring topology. The original option-B reasoning was cumulative:

- the fork's buffer free path selects worker-local cache state through `vm->thread_index`;
- VPP's established cross-worker mechanism transfers buffer indices through frame queues;
- older VPP code included a queue element whose target worker explicitly freed transferred buffers;
- DPDK documents separate rules for non-EAL-thread mempool access rather than assuming any thread may use the fast path;
- AF_XDP and io_uring use explicit ownership rings, bounded capacity, batching, and conditional wakeups.

Those analogues support the ownership-ring shape. They do not themselves guarantee VPP thread safety.

## Facts from the modified VPP fork

The target source is `/home/js/backup/backup/Git/vpp`, branch `dev-26.03`.

In `src/vlib/buffer_funcs.h`, `vlib_buffer_free`, `vlib_buffer_free_no_next`, and `vlib_buffer_free_one` return `void`. The inline free path decrements `ref_count`; buffers reaching zero are passed to `vlib_buffer_pool_put`. That function chooses `bp->threads[vm->thread_index]`, fills that thread's local cache, and uses the shared-pool spinlock only when the local cache overflows. Debug builds validate that the buffer is known allocated. Free callbacks run before insertion into the pool, but their return values are not a recoverable free result.

This means a Rust caller cannot treat VPP free as a fallible operation and recover a lease afterward. More importantly, passing a borrowed `vlib_main_t` from the wrong OS thread is not justified merely because the pool ultimately has a lock: the complete operation includes worker-local cache selection, refcount handling, callbacks, template/reset behavior, and debug allocation state.

The current fork's `vlib_buffer_enqueue_to_thread` can free unqueued buffers when `drop_on_congestion` is enabled. It is therefore unsuitable as-is for an obligated `PacketLease` return path: congestion must not silently destroy or lose the caller's only ownership token.

Historical VPP provides useful precedent, not a current API contract. VPP 20.05 handled `VLIB_FRAME_QUEUE_ELT_FREE_BUFFERS` by having the dequeuing VPP thread call `vlib_buffer_free(vm, ...)`. The present fork no longer contains that queue-element type. Recreating the ownership principle is reasonable; depending on the removed symbol is not.

## Options compared

| Option | Ownership correctness | Hot-path behavior | Recommendation |
|---|---|---|---|
| A. Rust thread directly frees into VPP | No explicit VPP contract for an arbitrary foreign thread; wrong `vm` can address the wrong worker-local cache | Lowest apparent handoff cost, but hides affinity and teardown hazards | Reject as default |
| B. Capacity-derived return route, drained by VPP context | Explicit transfer; final free occurs in the intended runtime context | Adds a second scheduling/return route that the accepted design does not need | Historical; rejected |
| C. Synchronous RPC/callback onto VPP context | Strong affinity if RPC completion means free finished | Cross-core round trip, blocking/deadlock and priority-inversion risk | Low-rate/admin path only |
| D. DPDK mempool put/external buffer | Direct mempool put bypasses VPP lifetime semantics; external buffers model different ownership | DPDK has efficient bulk/user-cache APIs, but only under its explicit allocator contract | Do not use to return VPP buffers |
| E. Reference-counted foreign buffer | Can model genuine shared lifetime, but risks two lifetime authorities | Atomic cost and substantially more state/failure cases | Reserve for real fan-out or external DMA |

### A. Direct return from the Rust I/O thread

Direct return would be defensible only if the Rust execution context were registered and operated as the relevant VPP context under an explicit fork-level contract. At that point it would no longer be an arbitrary foreign I/O thread. No such general contract was found in the current VPP documentation or target fork.

The shared backing pool's lock does not prove that the whole `vlib_buffer_free` path is foreign-thread safe. A direct call also makes teardown difficult: the pool and callbacks could disappear while an I/O thread still holds a buffer index.

Therefore the production wrapper should make direct foreign-thread free unrepresentable. A diagnostic counter for any attempted direct free should remain zero.

### B. Capacity-derived ownership-return route

The ring transports ownership, not packet contents. An entry should normally contain the live VPP buffer index and the minimum route/generation token required to identify its reclamation owner. It must not allocate a second packet buffer or copy packet bytes.

Prefer one single-producer/single-consumer ring per Rust producer and VPP reclamation owner when the topology permits it. AF_XDP explicitly documents its rings as SPSC and requires applications to synchronize multiple users themselves. If several producers must target one VPP context, use separate SPSC rings or a verified MPSC implementation; do not concurrently drive an SPSC ring.

The producer interface should have a consume-only semantic for a valid live lease:

```text
return_buffer(lease) -> ()
```

The call consumes the `PacketLease`; it has no `FULL`, rejection, retry, or fallback branch. This does not
claim that arbitrary invalid inputs are recoverable: a closed generation, duplicate index, invalid index, or
misrouted lease violates the ownership contract and must be detected by assertions/fatal invariant evidence.
The route remains usable until its outstanding count is zero, so a valid caller cannot encounter closure.

The VPP-side consumer drains entries in bounded batches and invokes the native VPP free operation. A drain budget prevents reclamation from starving ordinary graph work. Batch size and budget are tuning variables to measure, not constants to infer from analogy.

#### Publication and wakeup

If Rust implements the ring, publication/consumption ordering must be proved using the official Rust atomic model—typically Release publication paired with Acquire observation—rather than relying on x86 behavior. The exact ring algorithm needs its own tests and, ideally, a well-audited implementation.

Start with bounded polling from an appropriate VPP node or by piggybacking the normal graph loop. If measurements show unacceptable idle CPU or reclamation latency, add an empty-to-nonempty edge notification such as `eventfd`. AF_XDP's `needs_wakeup` demonstrates the value of avoiding a syscall for every buffer; it does not prescribe VPP's mechanism. The notification design must prevent lost wakeups. Avoid per-buffer syscalls.

#### Capacity and backpressure

Capacity must be derived from the maximum number of live leases eligible to return to that VPP context,
including platform I/O in flight and any intermediate output queue. Account for whether a power-of-two ring
sacrifices one slot. If several routes partition the population, the partition and each bound must be proved.

Admission must stop before the system can create more outstanding leases than it can eventually return. A return ring that is smaller than the post-policy live-buffer bound creates a new failure point after the policy decision has already completed.

The resulting design has no legal ring-full state: the one fixed buffer population bounds both checked-out
leases and their return storage. A full observation is evidence that sizing, accounting, routing, or
publication is wrong; it is not a runtime branch whose fallback must preserve a rejected lease. The producer
remains nonblocking and consumes every valid return.

### C. Synchronous RPC or callback

An RPC that executes the final free on the target VPP context gives clear affinity and a simple completion boundary. It is nevertheless a poor per-packet output path: the foreign I/O thread waits for graph scheduling, a cross-core round trip is introduced, and teardown or lock ordering can deadlock. Batching reduces but does not remove these concerns.

This option is appropriate for rare administrative reclamation or a low-rate batch fallback. A synchronous Rust callback invoked by VPP on the same thread can also be correct, but it cannot represent a separate thread that waits for platform I/O without extending the lifetime beyond the callback.

### D. DPDK mempool and external-buffer patterns

DPDK explicitly distinguishes normal per-lcore cached mempool calls from access by unregistered non-EAL threads. Its documentation directs non-EAL users toward generic get/put operations with a user-owned cache, which can be flushed, and provides bulk put APIs. This is strong evidence that foreign-thread allocator access requires an allocator-specific contract.

It is not permission to call `rte_mempool_put` on VPP packet storage. The modified VPP DPDK plugin builds DPDK mempools using VPP custom ops and maps objects into VPP buffer-pool structures. A direct DPDK put would bypass VPP `ref_count`, callbacks, debug known-state validation, and other VPP buffer semantics. It could make storage appear free to DPDK while VPP still considers its buffer live.

DPDK external buffers solve a different problem: a user-managed backing allocation is attached to an mbuf together with shared metadata, a reference count, and a final free callback. This is appropriate only if a future allocator or DMA device genuinely owns the backing memory. It should not be introduced merely to return a VPP-owned packet.

### E. Reference-counted foreign buffers

VPP buffers already carry a reference count. Wrapping the buffer index in Rust `Arc` adds another lifetime authority; the last `Arc` drop still cannot safely perform the final VPP free from an arbitrary thread. Rust's `Arc` also uses atomic operations and should be selected for shared ownership, not as a substitute for an ownership route.

A reference-counted scheme is correct only when every foreign reference has a matching, explicitly integrated VPP reference and the final transition is routed to a valid VPP reclamation context. That is worthwhile for genuine packet fan-out, shared external buffers, or asynchronous DMA with multiple consumers. For one platform write in flight, an explicit `InflightOutputLease` state is simpler and preserves a single lifetime authority.

## Proposed first-release contract

1. A successful output handoff moves the `PacketLease` into the Rust I/O subsystem.
2. Platform submission moves it into an explicit in-flight owner; submission failure leaves or returns the lease to its current owner.
3. Exactly one terminal platform result produces a return token for the designated VPP reclamation context.
4. Publishing a valid return consumes the Rust lease unconditionally; return-route capacity and lifecycle make ordinary publication failure impossible.
5. Only the VPP consumer calls `vlib_buffer_free`; native free remains `void` and has no Rust-side rollback.
6. The consumer validates generation/route before freeing and drains in bounded batches.
7. No adapter outcome causes the packet to re-enter policy processing, and no payload copy is introduced for reclamation.

If an existing output-completion route already terminates on the correct VPP context and can preserve these ownership phases unambiguously, it may serve as the physical return transport. The requirement is a bounded, explicit ownership transfer—not an unnecessary extra ring.

## Shutdown and reconfiguration barrier

Reconfiguration must not allow an old-generation token to reach a replaced pool or callback table. The safe order is:

1. stop admission of new ingress and newly decided output for the affected generation;
2. keep platform I/O owners and return ports alive;
3. complete or explicitly cancel every platform operation;
4. return every remaining lease and continue draining return routes;
5. verify both the outstanding-lease count and every affected ring are zero/empty;
6. only then close the generation, unregister callbacks, and release pool/runtime state.

A deadline expiry should report exact outstanding counts, oldest age, ring occupancy, and reclamation target. It must not close the VPP pool underneath live tokens. Tokens from a closed or mismatched generation are ownership faults, not packets to reinterpret.

## Required observability

Expose bounded, low-cardinality metrics per return route:

- return entries published and drained;
- drain batches and batch-size histogram;
- current occupancy and high-water mark;
- capacity-bound assertions and closed/stale/duplicate/invalid invariant violations (all expected to remain zero);
- return latency and oldest outstanding age;
- Rust-owned leases and platform operations in flight;
- wakeups, empty polls, and drain-budget exhaustion;
- teardown remainder by generation and target;
- attempted direct foreign frees, expected to remain zero;
- a sticky fatal ownership-invariant signal.

Avoid per-packet error logs. They can amplify the same congestion or consumer-stall fault that caused the condition.

## POC and validation plan

The POC should compare designs, not merely demonstrate that one run survives:

- per-producer SPSC rings versus a verified MPSC ring;
- polling versus empty-to-nonempty notification;
- several drain batch sizes and budgets;
- a low-rate batched synchronous RPC as a latency baseline;
- registered VPP-context direct free, if the fork can establish that contract, only as a controlled benchmark—not arbitrary foreign-thread free.

Measure cycles per returned token, cache misses, throughput, p99 return age, VPP pool availability, VPP and
Rust CPU use, wakeup rate, and shutdown drain time. Prove that the maximum eligible live-buffer population
cannot produce route `FULL`; separately inject sizing/accounting bugs, premature closure, generation mismatch,
consumer stall, producer exit, lost-wakeup races, duplicate/invalid returns, chained buffers, nonzero VPP
refcounts, and callbacks that must execute exactly once. These injections validate invariant detection, not a
normal retry/fallback path.

DPDK direct put should remain a source-level negative finding unless a separately owned DPDK-buffer profile is intentionally designed. Corrupting VPP ownership to benchmark it is not useful validation.

## Primary sources

- FD.io VPP, [VLIB architecture: handing off buffers between threads](https://docs.fd.io/vpp/23.02/developer/corearchitecture/vlib.html). Describes per-worker frame queues, suggested queue sizing, and producer/consumer congestion.
- FD.io VPP, [VLIB architecture (22.02)](https://docs.fd.io/vpp/22.02/developer/corearchitecture/vlib.html). Documents enqueue/drop-on-congestion ownership behavior.
- FD.io VPP 20.05.1 source, [`threads.c`](https://s3-docs.fd.io/vpp/20.05.1/d3/d18/threads_8c_source.html). Historical target-context handling of `VLIB_FRAME_QUEUE_ELT_FREE_BUFFERS`.
- DPDK, [`rte_mempool.h` API](https://doc.dpdk.org/api/rte__mempool_8h.html) and [source](https://doc.dpdk.org/api/rte__mempool_8h_source.html). Documents EAL-thread caches, generic operations for non-EAL users, and bulk put.
- DPDK, [Mempool Library](https://doc.dpdk.org/guides-18.11/prog_guide/mempool_lib.html). Describes per-core and user-owned caches.
- DPDK, [Thread Safety](https://doc.dpdk.org/guides-25.11/prog_guide/thread_safety.html). Describes the one-thread-per-logical-core model and fast-path caveats.
- DPDK, [`rte_mbuf.h` external-buffer API](https://doc.dpdk.org/api/rte__mbuf_8h.html) and [mbuf library](https://doc.dpdk.org/guides-19.05/prog_guide/mbuf_lib.html). Documents external-buffer free callbacks and direct/indirect-buffer reference counts.
- Linux kernel, [AF_XDP](https://docs.kernel.org/networking/af_xdp.html). Documents explicit ownership transfer through fill/completion rings, SPSC rules, capacity behavior, and `needs_wakeup`.
- Linux man-pages, [io_uring provided buffers](https://man7.org/linux/man-pages/man7/io_uring_provided_buffers.7.html) and [io_uring overview](https://man7.org/linux/man-pages/man7/io_uring.7.html). Documents buffer-ring ownership, batching, exhaustion, and shared submission/completion rings.
- Rust standard library, [`Send`](https://doc.rust-lang.org/stable/core/marker/trait.Send.html), [`Sync`](https://doc.rust-lang.org/std/marker/trait.Sync.html), and atomic [`Ordering`](https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html). Defines cross-thread ownership/shareability and publication ordering.
