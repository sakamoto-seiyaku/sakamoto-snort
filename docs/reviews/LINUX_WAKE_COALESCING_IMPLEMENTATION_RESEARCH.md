# Linux worker wake coalescing: implementation research

Investigated 2026-09-12. Design input only; no product/device changes or acceptance
claim. Scope: mature libuv/QEMU notifier implementations, race handling, and a
defensible candidate for the existing VPP 26.02 integration. No VPP upgrade,
foreign framework import, or optional `membarrier` prerequisite is proposed.
The existing packet-wake HOLD still requires an explicit reviewed decision.
See the companion [Linux eventfd/epoll contract](LINUX_EVENTFD_EPOLL_COALESCING_CONTRACT.md)
for kernel implementation and Android platform evidence.

## Source pins and what they actually establish

QEMU `v10.1.0` resolves to `f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3`;
libuv `v1.52.1` resolves to `1cfa32ff59c076ffb6ed735bbc8c18361558661f`.
These are inspected implementation versions, not claims about the latest release.

### libuv: application-level latch plus Linux readiness

`uv_async_send()` uses a userspace pending flag: an early relaxed load can skip
the call; otherwise an atomic exchange chooses whether to write. It is that
flag—not epoll—that suppresses producer syscalls. The consumer reads the fd,
then atomically clears pending before invoking the callback. Linux uses a normal
nonblocking, close-on-exec eventfd. Writes retry `EINTR`, accept `EAGAIN`, and
abort on other failure. The read loop retries interruption and stops after one
successful eventfd read because its buffer is larger than eight bytes. Close
and loop-stop coordinate with in-flight send activity before closing the fd.
This is an implementation example, not permission to race arbitrary calls
against an already destroyed handle.
[Pinned libuv async.c](https://github.com/libuv/libuv/blob/1cfa32ff59c076ffb6ed735bbc8c18361558661f/src/unix/async.c).

The Linux backend transfers the watcher's requested mask to epoll unchanged;
the async watcher requests `POLLIN`, with no `EPOLLET` or `EPOLLONESHOT`.
Thus the inspected async notifier is level-triggered. The loop also invalidates
stopped watchers and filters events whose interests have changed.
[Pinned libuv linux.c](https://github.com/libuv/libuv/blob/1cfa32ff59c076ffb6ed735bbc8c18361558661f/src/unix/linux.c#L1320-L1445).

Version caution: live libuv docs identify stronger send/callback ordering as
changed in 1.53.0 and warn about earlier coalescing paths. Do not copy the pinned
relaxed early-return optimization and assume the newer guarantee. A proposed
C protocol below deliberately requires an ordered RMW on every publication.
[Mutable libuv API documentation](https://docs.libuv.org/en/v1.x/async.html).

### QEMU: raw notifier is not the syscall suppression mechanism

`event_notifier_set()` writes for every call on an initialized notifier. It
retries `EINTR`, treats `EAGAIN` as already-pending readiness, and returns other
errors. Its non-semaphore eventfd is nonblocking and close-on-exec. The read
helper handles interrupted reads and returns after one successful eventfd
read; pipe draining is different. Cleanup closes descriptors and resets fields,
but this helper alone contains no concurrent-writer lifetime protocol. An
`initialized` field check is not a reference count or fd-reuse defense.
[Pinned QEMU EventNotifier](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/event_notifier-posix.c).

Higher up, `aio_notify()` orders prior work before `notified`, executes a full
barrier, then conditionally calls the notifier after reading `notify_me`.
Acknowledgement clears `notified` and barriers before work inspection. Detached
bottom-half slices are included when calculating whether blocking is allowed.
[Pinned QEMU async.c](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/async.c).

The consumer publishes sleep interest, executes the paired full barrier, and
rechecks notification before waiting. It stops advertising sleep interest after
the wait. This is a complete paired protocol; it cannot be reduced to two
unrelated release stores and acquire loads.
[Pinned QEMU aio-posix.c](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/aio-posix.c#L636-L690).

QEMU's epoll mask conversion uses IN/OUT/HUP/ERR without ET or ONESHOT. These
mature implementations therefore provide direct precedent for LT notification;
ET is not a prerequisite for batching or userspace syscall suppression.
[Pinned QEMU epoll backend](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/fdmon-epoll.c#L23-L45).

## Separate three different kinds of coalescing

The following distinction is essential to the design; kernel details and Android
support are investigated separately by the main worker-idle investigation.

| Layer | What is combined | What is not eliminated |
| --- | --- | --- |
| Native publication | Many packet indices in a published frame/batch | Need to publish and notify each destination receiving work |
| Userspace notifier latch | Many publications within one acknowledgement epoch | At least one atomic operation per publication in this candidate |
| eventfd/epoll readiness | Accumulated counter and ready-fd reporting | Producer writes that userspace actually invokes |

Do not equate notification counts with packet counts. Do not describe ET as a
guaranteed single callback per counter zero-to-positive transition, or as a way
to remove write syscalls. LT plus a normal eventfd leaves a readable condition
available until acknowledged, without ONESHOT rearm operations.

## Candidate: one ordered pending latch, LT eventfd, acknowledgement before recheck

This is a proposed adaptation of the demonstrated mechanisms, not an upstream
implementation copied verbatim or a completed VPP proof. Prefer one notifier
per destination worker, one fd reader, and the existing native packet queues.
`pending` is a notification latch, not a packet counter or a sleeping flag.
Use one C11 atomic object, initially zero; all transitions below are sequentially
consistent RMW operations. No speculative relaxed-load skip is allowed.

Producer, while holding a valid notifier-generation lifetime reference:

```text
publish the native frame/batch using the queue's required release protocol
old = atomic_exchange_seq_cst(pending, 1)
if old == 0:
    write eight-byte value 1 to the destination's nonblocking eventfd
    retry EINTR; accept EAGAIN as existing readiness
    on other failure enter an explicit infrastructure-failure path
release lifetime reference
```

Consumer, as one indivisible logical sleep-preparation sequence (not a lock):

```text
read the normal eventfd once, retrying EINTR
accept either an eight-byte read or EAGAIN; other results are infrastructure errors
atomic_exchange_seq_cst(pending, 0)     // acknowledge and enable the next writer
recheck authoritative remote queues AND all immediately runnable local work
if work is runnable:
    execute a bounded scheduling pass; do not block
else:
    epoll_wait with the next actual deadline
```

While continuing known work, the worker need not clear the latch every packet
or every graph node. Clear/recheck at the controlled scheduling boundary before
blocking. Poll other fd sources nonblocking as needed for fairness. Never let a
separate callback drain the notifier between the final recheck and blocking.
If existing callbacks acknowledge it earlier, the sequence must still perform
the ordered reset and complete recheck before any later blocking call.

This replaces a sleep-state handshake with an acknowledgement epoch. It can
write once while the destination is already busy, then suppress subsequent
writes until acknowledgement. It does not promise zero busy-worker writes or
zero cross-core cache traffic. Measure that tradeoff against a fully proved
sleep-interest protocol; the latch is a complete candidate, not a temporary
correctness hack or an assertion of optimality.

### Why the important races have a path forward

- Producer RMW before consumer reset: ordered RMWs on the same object carry
  preceding publication into the consumer's post-reset recheck, including
  multiple coalesced producers. The queues must still use their own correct
  synchronization and must not give false-empty answers for published work.
- Producer RMW after reset: the first sees zero and owns a write; later ones
  coalesce. The consumer either sees work and stays runnable or obtains fd
  readiness, including a write made before it enters `epoll_wait`.
- Write between fd read and latch reset: the reset/recheck observes the
  publication. A remaining counter can cause an extra wake, not missing work.
- Winner paused between RMW and syscall: a concurrently running consumer may
  process its published work before the delayed write. That write is then
  harmless extra readiness. A sleeping consumer depends on the writer being
  scheduled to finish notification; this is not a hard real-time guarantee.
- Clearing after inspecting work is forbidden: a producer can coalesce into
  the old latch after the consumer's empty check, and a later clear can erase
  the only reason to stay awake.

The first case requires every producer to execute the RMW even when pending
is already one. The proof does not rely on two-location acquire/release
Store→Load ordering or on an eventfd syscall magically synchronizing arbitrary
C queue memory. Confirm exact C/VPP atomic semantics before implementation.

### Read/write error and lifetime contract

One successful normal eventfd read acknowledges the accumulated value at that
point; racing later writes are allowed to remain readable. LT permits returning
to useful work without a potentially unbounded drain-until-EAGAIN loop under
continuous producers. Do not use `EFD_SEMAPHORE` or permanently subscribe to
`EPOLLOUT`. `EAGAIN` on a read is not a packet loss; it can represent stale
readiness. A failed write other than `EINTR`/`EAGAIN` cannot be quietly ignored
after taking ownership of the wake. Define a fail-stop/reporting path that
cannot strand a worker indefinitely behind the now-set latch.

For teardown, an integer generation check alone is insufficient: a writer can
pass it, be descheduled, and later write to a reused fd. Use existing worker
quiescence/join if it excludes all publishers; otherwise acquire a lifecycle
reference atomically against closing before publication. Stop new admission,
quiesce all publishers including elected-but-delayed writers, resolve owned
work, remove the fd watch, and only then close/free notifier state. Do not
hold a lifecycle mutex over ordinary packet execution. Specify whether stop
must permit drain-related publications before closing admission; otherwise
the teardown sequence itself can deadlock.

## VPP 26.02 integration and acceptance obligations

No new packet queue, payload copy or alternate packet-domain implementation is
needed. Hook notification to actual completed native publication, once per
destination batch; failed enqueue is not work. The sleep gate must include
already-dequeued `pending_frames`, actionable completions, runnable HEV work,
and due timers. Merely having an outstanding packet obligation or a future
timer is not a reason to spin; those require a registered future wake source.

Audit a multi-producer reserved-but-unpublished queue head explicitly. A later
ready slot may be inaccessible until the head producer finishes. Do not infer
"nothing can become runnable without a wake" from a failed dequeue alone.
Every publication that can unblock head progress must participate in notification;
a generic nonempty hint is insufficient proof, and spinning on reserved work
would convert producer preemption into idle CPU consumption.

The existing VPP eventfd is also used by Android patch 0018 barrier wakes and
the node-interrupt `vlib_thread_wakeup` path, with existing `wakeup_pending`
handling. The single-latch algorithm above is a candidate protocol, not
authorization to stack another independent latch onto that shared fd. Inventory
every writer, drain callback and flag reset first. Either integrate the shared
wake causes under one proved acknowledgement/recheck contract, or explicitly
prove mixed direct writers cannot have their required wake drained without
their underlying barrier/interrupt condition being checked. Preserve barrier
and shutdown progress and notifier ownership. Sharing the fd does not mean
the different wake reasons share identical scheduling or lifetime rules.

Before adoption, run deterministic interleavings covering every bullet above,
multiple producers, late writer teardown, fd reuse, and native queue partial
publication. On the actual Pixel build test both owner directions, isolated
packets after idle, bidirectional bursts, sustained-load fairness, idle return,
stop/restart, and exact buffer/credit accounting. Compare syscall counts,
acknowledgement epochs, worker CPU and latency tails. Host tests cannot certify
Android scheduling, power, or VPP integration. Existing S239 evidence remains
a failing control until fresh device results establish otherwise.
