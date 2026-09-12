# Linux eventfd/epoll coalescing: usable guarantees and design obligations

Date: 2026-09-12. Follow-up to the user's request for a complete, established
notification design rather than a merely usable first patch. Research input
only: VPP stays pinned to 26.02; no product code, kernel policy, or device state
was changed. This uses the research skill and independent primary-source
inspection. Companion: [QEMU/libuv implementation study](LINUX_WAKE_COALESCING_IMPLEMENTATION_RESEARCH.md).

## What Linux already provides

An ordinary eventfd (without EFD_SEMAPHORE) accumulates writes in a counter.
A successful eight-byte read obtains the accumulated count and resets it;
a positive count is readable by epoll. A notification need not coincide with
the waiter entering epoll. Use nonblocking mode for the worker path and keep
the descriptor lifetime stable. This is a notification counter, not packet
storage or a packet-delivery acknowledgement.
[eventfd ABI](https://man7.org/linux/man-pages/man2/eventfd.2.html).

Epoll combines events occurring between waits. LT is the default; ET removes
automatic repeated reporting merely because readiness remains. ET callers
must retain knowledge that a source is ready until nonblocking I/O establishes
otherwise. EPOLLONESHOT requires explicit rearming. These modes govern fd
readiness, not shared-memory queue publication or the lifetime of an unrelated
VPP buffer.
[epoll ABI](https://man7.org/linux/man-pages/man7/epoll.7.html).

Linux v6.6's eventfd write path locks the counter, increments it, and calls the
poll wake path when waiters exist on each successful write. It does not restrict
that path to counter zero-to-positive transitions. Thus kernel accumulation
does not erase the syscall, counter-lock or notification-path work already
performed by each sender. This version is explanatory source, not a required
Android kernel version or an internal-layout compatibility promise.
[Pinned eventfd implementation](https://github.com/torvalds/linux/blob/v6.6/fs/eventfd.c#L242-L273).

The corresponding epoll callback avoids repeatedly inserting an already-linked
item into its ready list. Delivery requeues LT items for readiness checking,
but not ET items. A later write can invoke the callback again after an ET item
was delivered, even if the eventfd counter never reached zero. Therefore
"EPOLLET guarantees one report until the counter returns to zero" is not a
valid optimization premise. Applications must follow the documented readiness
contract, not exact callback counts.
[Pinned eventpoll implementation](https://github.com/torvalds/linux/blob/v6.6/fs/eventpoll.c).

## Four different kinds of batching

| Layer | What is combined | What is not guaranteed |
| --- | --- | --- |
| Native VPP frame | Several buffer indices per publication | No automatic notification unless wired |
| User-space pending latch | Repeated work publications can share a notification write | Requires publish/acknowledge/recheck ordering |
| eventfd counter | Several successful writes can be consumed by one read | Does not eliminate those write syscalls |
| epoll ready list | Multiple readiness notifications can share a returned event | Does not count or execute packets |

These are complementary, not substitutes. Kernel support should be reused,
while user-space coalescing must not be justified by kernel behavior it does
not actually provide.

## Proposed direction, not accepted implementation

Prefer the existing per-worker nonblocking eventfd and **LT EPOLLIN** as the
initial candidate for this control notification. This is not rejection of
optimization: normal eventfd counter accumulation and epoll event combination
already apply in LT. One consumer draining a counter has no demonstrated need
for ONESHOT rearm calls or ET's extra ready-source bookkeeping. The exact
throughput/CPU comparison remains measurable, not assumed.

Pair it with a mature user-space coalescing protocol, rather than mandatory
per-packet writes or a second queue. The companion study examines an atomic
pending latch with acknowledgement **before** scanning work. Every publication
participates in the ordered operation, including the coalesced path; a relaxed
early return cannot silently substitute for required payload visibility.

A pending latch and an armed-sleeper handshake are different protocols.
Do not stack both optimizations by default. First compare whether a single
ordered latch provides sufficient write suppression and a simpler complete
proof. An armed-only optimization may reduce busy-time writes further, but
introduces another state relationship. Neither candidate depends on optional
systemwide membarrier support.

The complete contract must address:

- native queue publication and acquisition, including multiple producers and
  a reserved but not yet published head slot;
- consumption of eventfd readiness and reset of the user-space latch;
- bounded dispatch with a persistent runnable indication when budget remains;
- already-dequeued local graph frames, runnable HEV tasks and due timers;
- delayed writers, stop, descriptor reuse and generation lifetime;
- EINTR, EAGAIN, allocation failure and unexpected notification errors;
- fairness between fd callbacks and graph execution, without indefinite drain
  loops under continuous arrivals.

Existence of an outstanding obligation does not itself forbid sleeping.
Immediately runnable work forbids blocking; blocked work needs a reliable
future progress source. This distinction matters for completion backpressure
and future timer deadlines.

## Android and device qualification

The installed NDK r29 sysroot declares eventfd, eventfd_read and eventfd_write
in `sys/eventfd.h`; the current Product artifact already uses eventfd/epoll.
That local build evidence does not certify all vendor kernels. The candidate
must rely on public baseline semantics, not Linux v6.6 internal locking or an
optional kernel optimization. ARM64 atomics require a full memory-ordering
argument; passing an x86 stress test is insufficient.

The follow-up Pixel experiment must distinguish counters for published
frames, latch transitions, successful eventfd writes, eventfd reads, epoll
events, actual thread wakeups and packets executed. They are not interchangeable.
Run both a kernel-batched reference and the coalesced candidate with identical
native frame batching and work checks; do not compare different packet batch
sizes and attribute the result solely to the latch.

Required scenarios include pre-wait notifications; accumulated writes;
write/read races; publish immediately before and after latch reset; delayed
first notifier with later coalesced publishers; budget-exhausted local work;
isolated packets after verified sleep in both directions; traffic-to-idle
transitions; shutdown with a delayed writer; and actual W2 IPv4/IPv6 Product
traffic. Test API semantics directly and then the integrated native path.
Negative-control variants must expose the missed-wake/local-pending bugs so
the harness cannot pass by periodically waking workers itself.

LT/ET comparison is a diagnostic question, not a requirement to ship two modes.
No new candidate or Linux API probe was executed on Pixel in this research
turn. All behavioral acceptance remains pending actual device evidence; the
broader [Pixel matrix](ANDROID_VPP_WORKER_IDLE_RESEARCH.md#5-pixel-acceptance-design)
still applies. Prior wake-patch HOLD is not silently lifted by this note.
