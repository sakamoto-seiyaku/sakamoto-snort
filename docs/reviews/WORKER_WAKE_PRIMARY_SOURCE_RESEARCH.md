# Worker wake/idle protocols: QEMU, Seastar and libuv

Status: primary-source research input, not an implementation decision or device
acceptance. Investigated 2026-09-11. No product code was imported or changed.

Scope: reliable cross-thread work notification while retaining blocking idle.
The companion [Android VPP investigation](ANDROID_VPP_WORKER_IDLE_RESEARCH.md)
covers upstream VPP, Linux/DPDK and the device experiment plan.

## Current question and evidence boundary

S239 reproduced owner 1 cross-worker delays around 1–2 seconds while same-APK
owner 0 succeeded. Its inspected native enqueue publishes a frame and sets
`check_frame_queues`, without waking the destination; the Android sleep path
does not check that flag. These are findings for the recorded artifact, not an
assertion about every VPP version. See [S239 device evidence](../testing/2026-09-11_S239_W2_DISPATCH_EVIDENCE.md).

The subsequent local audit also identifies already-dequeued `pending_frames`
before a potentially blocking file poll. That state must be audited separately
from the source handoff queue: removing work from a queue does not execute it.
The companion investigation records the corresponding local/upstream details.

The prior conditional packet-wake proposal remains on HOLD under
[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md) and
[per-worker ownership](../decisions/PER_WORKER_FLOW_OWNERSHIP.md).
Research does not restore that patch or reopen the accepted ownership/copy
boundaries. Foreign frameworks below provide protocols to examine, not source
to transplant into the VPP-native C product.

## Pinned source selection

Release tags were resolved using their projects' Git remotes. Pinned links
below identify the inspected releases, not a claim that they are latest.

| Project | Inspected release | Resolved commit |
| --- | --- | --- |
| QEMU | `v10.1.0` | `f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3` |
| Seastar | `seastar-25.05.0` | `8df8212e53577e1d8477a5c901457cd61d88afc7` |
| libuv | `v1.52.1` | `1cfa32ff59c076ffb6ed735bbc8c18361558661f` |

The ScyllaDB explanatory article is dated 2018-02-15. QEMU `master` atomic docs
and libuv `v1.x` API docs are mutable pages retrieved on the investigation date;
their claims must not be silently applied to older releases.

## QEMU: readiness, sleep interest and the kernel notifier are distinct

QEMU's producer enqueues the bottom half before `aio_notify()`. Notification
orders prior work before setting `notified`, then executes a full barrier
before reading `notify_me`; only an interested consumer needs an event-notifier
write. Acceptance clears `notified`, then uses a full barrier before examining
work. The actual fd callback separately clears the kernel notifier. Crucially,
timeout calculation examines both the shared bottom-half list and detached
local slices; non-idle work in either makes the timeout zero.
[QEMU async.c](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/async.c).

In blocking `aio_poll()`, the consumer publishes `notify_me`, executes the
paired full barrier, and rechecks `notified`; a pending notification changes
the timeout to zero. It clears sleep interest only after the wait and then
accepts notification before dispatching bottom halves and ready handlers.
QEMU also performs a final poll when leaving poll mode to catch a concurrent
event. The optimization explicitly relies on reevaluating all relevant work
before the next blocking call. The context has one event-loop owner; this is
not permission for arbitrary concurrent consumers.
[QEMU aio-posix.c](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/aio-posix.c#L611-L698).

Its POSIX notifier initializes nonblocking, close-on-exec eventfd where
available. Writes retry `EINTR`; `EAGAIN` is accepted because a notification is
already pending. Other errors are returned. Its read helper retries interruption
and handles eventfd differently from a full pipe buffer. This helper is not the
work queue and does not establish the higher-level sleep protocol by itself.
[QEMU event_notifier-posix.c](https://github.com/qemu/qemu/blob/f8b2f64e2336a28bf0d50b6ef8a7d8c013e9bcf3/util/event_notifier-posix.c#L99-L136).

Relevance: this separates three questions we must answer locally—was work
published, may the worker block, and is a durable wake pending? Checking only
the original queue cannot answer whether its detached frames still need to run.
This is an inference for our integration, not a QEMU guarantee about VPP.

## Seastar: arm/recheck and subsystem vetoes, with an ARM caveat

The SMP poller first marks `_sleeping`, obtains a systemwide memory barrier,
then polls queues again. Barrier contention or newly observed work cancels
sleep. Queue producers call `maybe_wakeup()` after push; its compiler fence
relies on that systemwide barrier, not relaxed atomics alone. `wakeup()` clears
the sleeping flag before writing eventfd, reducing subsequent writes without
promising exactly one syscall across racing producers. The main loop includes
locally runnable tasks in its work check. Each poller must permit interrupt
mode; a veto unwinds previously armed pollers. Due I/O submissions or timers
can veto sleep; future deadlines can be armed to wake it.
[Seastar reactor.cc](https://github.com/scylladb/seastar/blob/8df8212e53577e1d8477a5c901457cd61d88afc7/src/core/reactor.cc).

The barrier helper queries/registers Linux private-expedited membarrier
support. It serializes attempts using a nonblocking try-lock because concurrent
kernel membarrier calls can serialize while reactors cannot respond to wakes.
Failure to obtain the try-lock sends execution back to polling. On AArch64,
missing native membarrier makes the try helper refuse sleep instead of using
its TLB-invalidation fallback. Consequently, copying this optimization without
its complete platform contract could produce permanent polling on mobile.
[Seastar systemwide_memory_barrier.cc](https://github.com/scylladb/seastar/blob/8df8212e53577e1d8477a5c901457cd61d88afc7/src/core/systemwide_memory_barrier.cc).

ScyllaDB's first-party explanation distinguishes safe queue publication from
safe conditional wake: both participants need Store→Load ordering in the
straightforward protocol. Its historical optimization moves producer barriers
to the consumer through systemwide barriers. It documents contention trouble
at intermediate load and why a TLB-based trick is not portable to ARM.
[ScyllaDB explanation, 2018](https://www.scylladb.com/2018/02/15/memory-barriers-seastar-linux/).

Recommendation: borrow the obligation to let every immediately runnable
subsystem veto blocking; do not adopt global membarrier or a spin fallback as
our default repair. Their cost, availability and kernel policy would require
separate Android evidence. Idle CPU behavior is itself an acceptance criterion.

## libuv: coalesced signals are not counted work

The live API docs explicitly allow multiple sends to produce one callback.
They currently describe sequentially consistent send/callback ordering and
mark that guarantee as changed in 1.53.0, warning about earlier coalesced paths.
This is a documentation-version caveat, not verification that 1.53.0 is the
installed or latest release.
[libuv mutable async API docs](https://docs.libuv.org/en/v1.x/async.html).

In the inspected 1.52.1 source, the producer has an early relaxed read of
`pending`; otherwise it uses an atomic exchange and writes only on transition
to pending. The consumer drains the fd and atomically clears pending before
invoking the callback. Close/stop coordinate with in-flight send operations
before fd teardown. These are useful ordering and lifetime review sites, but
the early coalescing return must not be treated as the newer API's full-fence
guarantee.
[libuv async.c](https://github.com/libuv/libuv/blob/1cfa32ff59c076ffb6ed735bbc8c18361558661f/src/unix/async.c).

Inference: our consumer must inspect authoritative work after a notification,
not process exactly one packet per wake. Any notification-pending suppression
bit needs a defined clear/recheck order and fd-generation lifetime; clearing
it after deciding the queue is empty can erase a producer's only notification.

## Memory-ordering proof obligation

Acquire/release synchronizes across a matching observation, not merely because
both sides use those words. A release store followed by an acquire load of a
different location is not automatically a full Store→Load barrier. Compiler
barriers do not constrain CPU reordering. QEMU documents these distinctions
and recommends hiding low-level atomics behind documented abstractions.
[QEMU atomic documentation](https://www.qemu.org/docs/master/devel/atomics.html).

For a candidate VPP protocol, explicitly rule out the outcome where the
producer sees "not sleeping" while the consumer sees "no work", and both
then stop making progress. A two-location acquire/release sketch alone does
not rule this out. The actual queue publication, notification state and
consumer recheck need a complete C/architecture argument—e.g. an appropriate
fully ordered handshake—not a selection of individual atomics copied from
different frameworks. Validate on ARM64; passing x86 stress does not prove it.

## Recommended experiment obligations, not passed results

1. Preserve the failing S239 artifact as control. Compare candidate and control
   with identical traffic, ownership, artifact identity and timeout policy.
2. Exercise isolated input and return packets after verified idle, without a
   subsequent packet or periodic application poke to rescue progress.
3. Inject controlled pauses around sleep publication, final queue check, fd
   wait entry, notifier drain/clear and local-frame dispatch. Cover multiple
   producers and bidirectional handoff. Check exact packet identity and debt.
4. Assert that locally pending frames, runnable HEV tasks and immediately
   actionable completions prevent blocking. Future timers and blocked I/O
   must instead register a wake source; existence of an outstanding obligation
   alone must not force endless spinning.
5. Run bursts and sustained traffic with bounded processing/fairness, then
   verify return to idle. Count notification attempts, writes, coalescing,
   spurious wakes, blocked time and per-worker CPU alongside latency tails.
6. Race shutdown/restart with notifications. Prove no writes to recycled fds,
   use-after-free worker state, stranded buffers, or stale-generation work.

These are proposed tests, not measurements. Pixel testing must include the
actual installed native artifact and both owner directions; record scheduling,
thermal and power context when interpreting latency or idle cost. No cited
framework establishes an Android energy target, a latency bound, or product
acceptance. All changes still require the reviewed HOLD-boundary decision and
fresh real-device evidence.
