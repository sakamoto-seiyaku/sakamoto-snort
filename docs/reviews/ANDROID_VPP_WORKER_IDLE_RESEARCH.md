# Android VPP worker idle and notification research

Date: 2026-09-11. Scope: S239 design evidence, not an accepted implementation,
VPP revision upgrade, or new device PASS. The user requested primary-source
research and requires all selected behavior to be tested on the real device.
This research used the research skill, with parallel primary-source reading;
the companion [reactor study](WORKER_WAKE_PRIMARY_SOURCE_RESEARCH.md) covers
QEMU, Seastar and libuv.

## Conclusion

We should not treat event-driven VPP execution as an entirely novel problem.
Upstream VPP itself now provides relevant handshake machinery. Borrow the
invariants and examine exact revision behavior, not a whole implementation or
its tuning constants. Our proposed direction remains bounded owner-local
execution with reliable notification and idle sleep. No product source or
dependency pin was changed by this research.

The current product pins VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`.
The inspected Android stage adds its own idle behavior: 1000 ms maximum epoll
sleep, ignoring worker polling-node counts, and no handoff-pending or local
pending-frame check before blocking. The existing
[Pixel evidence](../testing/2026-09-11_S239_W2_DISPATCH_EVIDENCE.md) shows
reproducible seconds-long cross-worker delays; it does not identify copy cost
or justify a third copy.

## 1. The closest reference is newer upstream VPP

VPP's April 2025 file-handling change moved epoll into graph scheduling and
provided an eventfd per thread. Thus saying that upstream has no sleep/wake
requirements is too broad. The relevant question is how our pinned graph,
queues and Android idle overrides fit together.
[Original upstream change](https://github.com/FDio/vpp/commit/5c72a3780f765ba165c240c11921e0f2d229c702).

The June 2026 handoff rework replaces the old frame-queue implementation with
fixed-slot MPSC handoff rings and a per-thread pending bitmap. It is a broad
queue change, not a standalone wake patch. Wholesale cherry-picking or
upgrading the pin would also affect queue interfaces and our retained-buffer
completion semantics; that is not authorized by this research.
[Pinned handoff rework](https://github.com/FDio/vpp/commit/a788d6c589f115227003ebc4e6b8116c75d7f435).

In that revision, the sleeper publishes `thread_sleeps` with sequential
consistency, then checks the handoff-pending bitmap with the same ordering.
A pending handoff cancels blocking. The file loop also honors a temporary
no-sleep counter. These are source facts, not a claim that all Android work
sources are covered by this upstream revision.
[Pinned file.c](https://github.com/FDio/vpp/blob/a788d6c589f115227003ebc4e6b8116c75d7f435/src/vlib/file.c).

The producer publishes slot contents, marks a pending bitmap with seq_cst,
and requests wake on a detected empty-to-nonempty transition. The consumer
atomically collects the pending bitmap, reasserts pending work when its
dequeue budget is reached, and sets `file_poll_no_sleep_epolls = 512` after
dequeueing. This separates payload visibility, work indication, notification,
and post-dequeue execution. The exact empty-transition test depends on that
ring's reservation/publication protocol; it must not be copied into our older
queue without proof. The 512-count active tail is not a mobile default or a
time-duration promise.
[Pinned handoff.c](https://github.com/FDio/vpp/blob/a788d6c589f115227003ebc4e6b8116c75d7f435/src/vlib/handoff.c).

The corresponding wake function checks sleeping with seq_cst and coalesces
eventfd writes through an atomic `wakeup_pending` exchange. Merely lifting the
exchange into an unrelated drain/clear sequence would not preserve a proof.
[Pinned threads.h](https://github.com/FDio/vpp/blob/a788d6c589f115227003ebc4e6b8116c75d7f435/src/vlib/threads.h).

Upstream also added distinct counts for main loops, epoll calls, sleep-path
entries, fd-ready returns, wake requests, and actual eventfd writes. These
distinctions are useful measurement categories. A sleep-path entry is not
proof of actual kernel sleep residency, and fd-ready returns include causes
other than handoff notification.
[Counter change](https://github.com/FDio/vpp/commit/cffa3a61fdfa3849867671ff6579a14574a6914b).

## 2. Linux notification semantics do not replace a queue protocol

An ordinary non-semaphore eventfd accumulates a kernel counter; a read returns
the value and resets it. A positive counter is readable through epoll. A
notification written before the waiter blocks can therefore remain observable.
Nonblocking writes can return EAGAIN at saturation; error paths need explicit
handling rather than silently assuming every notification succeeded. These
properties do not establish C shared-memory queue ordering and do not make
notification counts equal packet counts.
[Linux eventfd manual](https://man7.org/linux/man-pages/man2/eventfd.2.html).

Linux's lockless wait-queue documentation explicitly pairs waiter preparation
and condition publication with memory barriers. It warns that testing for
waiters without the required ordering can miss work. This is kernel code, not
a userspace implementation recipe: it corroborates the race, while a C/ARM64
implementation needs its own justified atomic protocol. Two independent
release stores followed by acquire loads are not, by themselves, a proof that
both participants cannot observe the old values.
[Linux waitqueue_active contract](https://docs.kernel.org/driver-api/basics.html#wait-queues-and-wake-events).

Epoll edge triggering requires special care when only part of the available
I/O is consumed; blocking again while data remains can stall the loop.
Level triggering is the default. This motivates retaining explicit runnable
state after a processing budget ends, rather than waiting for another edge.
It is not evidence that our present eventfd registration is edge-triggered.
[Linux epoll manual](https://man7.org/linux/man-pages/man7/epoll.7.html).

## 3. DPDK is useful for workload transitions, not mobile constants

DPDK's power-management documentation distinguishes monitor, pause and
frequency-scaling approaches. Descriptor monitoring has platform and driver
requirements; the documented x86 WAITPKG/RTM mechanisms are not an assumed
capability of Android ARM64 TUN/HEV. A frequency governor or a NIC RX interrupt
scheme is not a substitute for waking a worker on a userspace software queue.
[DPDK 25.03 power management](https://doc.dpdk.org/guides-25.03/prog_guide/power_man.html).

DPDK's vhost/virtio interrupt test plans exercise a useful observable cycle:
traffic wakes the worker, stopped traffic permits sleep, and restarted traffic
wakes it again, including multiple queues. We adopt that test shape, not its
NIC setup or an assertion that those tests qualify our APK.
[DPDK interrupt test plan](https://doc.dpdk.org/dts/test_plans/vhost_virtio_user_interrupt_test_plan.html).

## 4. Design recommendations — inference for this product

Treat these as candidate implementation requirements, not adopted code:

1. Keep one native scheduler-owned notification/idle contract. Packet callers
   publish their existing bounded native frames; they should not each invent
   a sleep check or write the destination TUN fd.
2. Distinguish queued remote work from already-dequeued local work. Inspect
   `pending_frames`, runnable node interrupts and budget-limited completion
   work before permitting a blocking wait. A notification cannot fix a loop
   that goes back to sleep before executing its local work.
3. Review payload publication, notification coalescing, sleep arming, recheck,
   eventfd drain and rearming as one protocol. Include multiple producers,
   interrupted syscalls, and shutdown; do not review only the enqueue function.
4. Preserve independent admission/credit and buffer ownership. Notification
   conveys an execution opportunity, not packet ownership, completion or
   delivery acknowledgement.
5. Separate runnable-now work from future deadlines. A future timer should
   limit the next wait, not force continuous polling. A currently runnable
   retry should not be hidden by ignoring all worker polling nodes. Actual
   dependency-blocked retries also need a bounded progress/wake strategy,
   not an unlimited hot spin while the destination is unavailable.
6. Start with an understandable handshake and measurable counters. Add active
   spinning, hysteresis or more aggressive notification suppression only when
   the correct baseline has a demonstrated cost worth reducing.

Three useful experimental arms are: unchanged failing baseline; a simple
diagnostic notification reference plus correct local-work checks; and an
armed/coalesced candidate with the same checks. The diagnostic reference is
not permission to release unconditional per-packet wake. The former P6 HOLD
and its measurement history remain relevant; a new correctness justification
does not erase idle, tail-latency or release gates.

## 5. Pixel acceptance design

Every selected candidate must run as a freshly built native VPP + Product
plugin + installed APK closure on Pixel `28201JEGR0XPAJ`, using `./dev/adb`.
Host tests can expose controlled races and model memory ordering, but do not
replace any of the device rows below. Every row is **proposed, not executed**
by this research turn.

| Device scenario | Evidence required |
| --- | --- |
| Isolated packet to sleeping owner, both directions | Real sleep/wakeup trace plus publish-to-dispatch and exact echo; no later packet, CLI barrier or periodic test tick supplying the wake |
| Queue drained into local pending frames | Execution proceeds before blocking; queue-empty must not be mistaken for no runnable work |
| Publish before arm / between arm and recheck / after recheck | Controlled interleavings in the same compiled notification path; no stranded published carrier |
| Notify during eventfd drain and coalescing reset | All work executes across repeated sleep cycles; deliberately delayed notifier and multiple producers included |
| Burst → sustained flow → quiet → isolated packet | Bounded work, no wake-per-packet assumption, no idle spin tail that never ends, successful first packet after quiet |
| W2 IPv4 and IPv6 together, owner exhaustion swapped | Owner-local callbacks and quotas; other owner continues while TUN can serve it; credits remain charged until actual free |
| Timers and completion backlog without new ingress | HEV/expiry work respects its deadline model; retained completion progresses without a new application packet |
| Broker reply, stop and restart during idle | Existing lifecycle wake still works, no generation-crossing event or leaked buffer/fd, both workers drain |
| Screen off / actual Doze / resume | Record actual power and policy state; distinguish application/network restrictions from a worker wake failure |
| Idle and sparse-load A/B; sustained-load A/B | Per-thread and whole-process CPU, wake requests/writes, actual scheduling, latency distribution, throughput and thermal state |

Pre-register sample sizes, deadlines, tolerances, counter definitions, workload
seeds and comparison order before running. Keep the existing 1500 ms echo
failure oracle; merely beating it is not sufficient latency acceptance.
Report each transfer leg and end-to-end latency separately. Use enough
observations for the advertised percentiles; do not infer a p99 result from
three packets. Any altered former P6 acceptance threshold requires an explicit
decision before measurements, not a post-hoc adjustment to obtain a pass.

Use short, bounded tracing to diagnose races and separate low-instrumentation
performance runs. Avoid repeated CLI queries during sparse-latency windows:
their worker barriers can accidentally wake the target and mask the problem.
An expired safety timeout fails the isolated-wake test even if it eventually
rescues the packet. Do not count `/proc` CPU as direct battery-power evidence;
actual energy claims need appropriate device measurement and controlled
conditions. Report thermal throttling, charging, affinity and background load.

Android Doze can defer CPU/network activity and needs explicit testing and
state recording. Waking a process thread through eventfd is not equivalent to
waking a suspended phone or bypassing Android power policy. No blanket wake
lock or optimization exemption is proposed here.
[Android Doze documentation](https://developer.android.com/training/monitoring-device-state/doze-standby).

## Scope boundary

Research supports a candidate direction; it does not establish a race-free
implementation or mobile energy benefit. No new candidate device result is
claimed. S239's authoritative requirements remain in Plane and its accepted
ADRs; this note is an evidence and experiment-design artifact, not a replacement
tracker. Source from deleted C++ mainline or C/VPP POCs was not used as an
implementation reference.
