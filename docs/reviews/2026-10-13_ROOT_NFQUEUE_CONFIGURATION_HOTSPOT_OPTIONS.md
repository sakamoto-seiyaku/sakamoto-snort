# Root NFQUEUE configuration and remaining CPU hotspots

Date: 2026-10-13. Portable NFQUEUE/common Linux and Product VPP mechanisms only.
The user explicitly excludes device-specific driver tuning. This research changes
no Product source, device setting, hook, flag, benchmark, tracker or commit.

## Finding and evidence boundary

Common configuration can reduce prequeue segmentation/copy, syscall and wakeup
counts, and improve execution placement. Ordinary NFQUEUE settings do not delete
the transmission that an accepted packet still requires. Consequently, target
portable improvements in the large scheduling/reinjection paths, while retaining
stable smaller Product functions as independent work. Increasing queue depth
alone is not a demonstrated fix for the dominant TX dispatch samples.

Fixed packed source closure is
`c9d4552d9f50a5ae6fed21afb0cb1b7c130ff7fefc3abc78178cf2d3d83cb5ae`.
Its retained profiles show:

| Visible work in fixed packed | CPU share | Interpretation |
| --- | ---: | --- |
| Reinjection and descendants | 45.75% | Remaining hooks, delivery and outgoing transmission |
| `queue_work_on` self | 14.74%, 281 samples | All under DHD TX dispatch and `nf_reinject`; identifies a large measured path, not a portable driver-control proposal |
| `finish_task_switch` self | 11.54%, 220 samples | 147 epoll-return, 53 reinjection-preemption, 9 observation-write-preemption, 11 other |
| `ipt_do_table` self | 4.67%, 89 samples | 87 under verdict reinjection |
| `product_packet_graph_l4_match_evidence_key` self | 2.10%, 40 samples | Stable separate Product optimization target |
| NFQ callback excluding visible reinjection | 1.42% | Its own visible work is much smaller than its descendants |

Inclusive parent shares overlap descendants. These are sampled VPP CPU, not wall
latency, invocation counts, lock waits or attainable savings. The B and scalar S
`queue_work_on` leaves have equal 281 samples and equal absolute sampled period;
the larger B percentage does not establish increased driver work. One B collector
boundary remains incomplete, so this is diagnostic evidence, not a new qualified
performance comparison.
[Profile drilldown](../../build-output/root-packed-flame-followup-20261013/drilldown.json),
[campaign limits](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#64-slot-completion-碰撞修复与延迟分段--2026-10-13).

All nine fixed-address UDP windows captured and settled verdicts on lane 0,
although canonical policy owners split across two workers. Current configuration
is four lanes, two per family; COPY_PACKET, requested range 65535 and kernel
maximum 65531; flags UID_GID | FAIL_OPEN = 9; maxlen 1024. Hooks use queue balance
176:177 / 178:179 plus bypass, without CPU fanout.
[Adapter configuration](../../src/product/vpp/product_root_nfqueue_adapter.c:677),
[hooks](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java:5921),
[lane/hash audit](2026-10-12_ROOT_NFQUEUE_PARALLELISM_SOURCE_AUDIT.md).

Primary common-kernel source is pinned to Android Common
`66e758f7d0c01a696c3a9db8929417e7403a1571`; eleven decoded official files and hashes
are retained in [the manifest](../../build-output/root-packed-flame-followup-20261013/primary-source/android-common-manifest.json).
Common APIs are portable candidates, but their availability and effective values
still need capability checks on each supported device.

## Ranked portable options

1. **Own ingress/completion budgets, wakeup coalescing and worker placement.**
   This directly addresses the large scheduling path without changing vendor
   controls. The adapter already drains up to 64 receive datagrams per readiness
   callback, submits bounded ingress batches and sends bounded verdict windows.
   The current worker notification latch already coalesces eventfd writes until
   acknowledgement and pending-work recheck. Inspect actual packets per callback,
   publication/wakeup counts, epoll ready FDs, pending-frame drainage and origin
   return batches before introducing another batching layer. Product-owned
   budget/flush changes can reduce repeated wakeups and submissions; there is
   no source-backed guarantee of reducing all 11.54% switching CPU.

   Existing verdict-send off-CPU intervals show the generator immediately
   succeeds VPP in 93.28% of cases, establishing test scheduling competition.
   First compare capability-based producer/worker placement while preserving
   traffic, VPP behavior and CPU policy. Select from the permitted CPU/cpuset
   topology; do not hardcode this Pixel's core numbers or assume every device
   has the same clusters. Measure aggregate/system CPU as well as per-worker
   CPU, since kernel work can move between tasks or CPUs.

   **Benefit:** fewer unnecessary syscalls, wakeups and runnable preemptions;
   better locality. **Risk/prerequisite:** preserve bounded capacity, origin
   ownership, exact completion and notification/recheck correctness; record
   actual scheduler/epoll behavior. Longer batching may add delay; continuous
   busy polling can increase power. Compare dense, light and idle behavior.
   **Priority: first common experiment.**
   [Receive budget](../../src/product/vpp/product_root_nfqueue_adapter.c:1482),
   [ingress flush](../../src/product/vpp/product_root_nfqueue_adapter.c:1392),
   [worker notification latch](../../src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch),
   [scheduler witnesses](../../build-output/root-verdict-slot-fix-20261012/diagnostic-groups.json).

2. **Exercise both existing NFQ queues with connection-stable placement.**
   IPv4 queue balance hashes sorted addresses and protocol, omitting ports.
   Increasing the range still leaves one fixed address/protocol hash on one
   lane. Existing queues can distribute receive, verdict and synchronous
   reinjection work if traffic actually selects both. This spreads work;
   lower total CPU must be measured. Smaller per-lane verdict batches and shared
   downstream resources can offset the gain.

   First use reachable address diversity or deterministic bidirectional
   port-rule classification for known test tuples, selecting ordinary NFQUEUE
   queue numbers while preserving the current capture scope and Android marks.
   The small controlled classification is an experiment, not a scalable general
   per-flow rule architecture. A general port-aware classifier is separate
   capability-dependent work; no stock queue-balance switch in this source adds
   ports. HMARK can hash ports/conntrack, but writes `skb->mark`, so direct adoption
   would conflict with Android mark preservation and is not proposed here.
   Keep canonical policy ownership and immutable origin FD completion regardless
   of the receive lane.

   CPU fanout uses the CPU executing the kernel hook modulo queue count, not
   canonical owner; it helps only when hook CPUs vary and can move one flow
   between lanes. A pinned producer or single RX CPU can still select one lane.
   **Benefit:** use the already-existing second origin worker for the large
   synchronous kernel continuation. **Risk/prerequisite:** demonstrate both
   lane deltas, preserve bidirectional connection placement and validate order,
   NAT/fragment behavior, mixed verdicts and coverage. **Priority: second common
   experiment, after removing producer competition; fanout stays diagnostic.**
   [Queue hash](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/net/netfilter/nf_queue.h#49),
   [CPU fanout](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/xt_NFQUEUE.c#85),
   [HMARK mark assignment](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/xt_HMARK.c#208).

3. **Retain stable Product functions and owned hook work as bounded targets.**
   The 2.10% evidence-key function qualifies as its own optimization target.
   Exact APK-matching disassembly confirms three actual calls in match recording,
   with flags 1, 1 and 0; redundant probe construction survived compiler
   optimization. Avoiding repeated construction can remove real work while
   preserving policy/evidence identity. Also identify the actual table/chain
   behind the 4.67% `ipt_do_table` leaf, then simplify only owned redundant
   matches if present. NF_ACCEPT continues remaining hooks; NF_STOP would change
   firewall semantics by skipping them.
   **Benefit:** work removal in code/rules we own. **Risk/prerequisite:** retain
   exact evidence identity and Android firewall semantics; a sampled function's
   entire share is not an achievable-gain estimate. **Priority: pursue alongside
   the larger common-path experiments.**
   [Matching disassembly](../../build-output/root-packed-flame-followup-20261013/record-match-disassembly.txt),
   [match construction](../../src/product/vpp/product_packet_graph.c),
   [accept traversal](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nf_queue.c#325).

4. **Standard NFQA_CFG_F_GSO can remove early segmentation, but requires a
   complete adapter contract.** With the flag absent, GSO skbs are segmented
   before NFQ and each segment is enqueued. The flag preserves the skb and also
   avoids NFQ's CHECKSUM_PARTIAL helper. The current ordinary 1200 B UDP helper
   does not request UDP_SEGMENT, so this campaign shows no prequeue-segmentation
   gain; checksum deferral remains a separate unmeasured mechanism.

   Root currently receives into one existing default-data VPP buffer with
   MSG_TRUNC. Oversized datagrams go through accept-unadmitted handling; the
   shared IP parser requires the complete IP length. Merely adding the flag
   could turn large TCP packets into policy bypass. SKB_INFO/CAP_LEN diagnostic
   parsing is not a complete GSO packet contract.
   **Benefit:** fewer NFQ messages/verdicts and less early segmentation for
   suitable TCP; possible deferred checksum work. **Risk/prerequisite:** bounded
   full-packet storage, GSO/checksum facts, tracker/reassembly accounting and exact
   completion; later TX may still segment according to device capabilities.
   Compare bytes and delivered wire packets as well as CPU per NFQ skb.
   **Priority: portable realistic-TCP prototype, after current UDP targets.**
   [Prequeue segmentation](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#844),
   [checksum helper](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#432),
   [receive/truncation](../../src/product/vpp/product_root_nfqueue_adapter.c:1568),
   [full IP parser](../../src/product/vpp/product_packet.c:254),
   [later TX segmentation](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/core/dev.c#3740).

5. **Maxlen and SO_RCVBUF are portable pressure controls, not driver-work
   elimination.** Maxlen bounds kernel obligations; RCVBUF bounds Netlink socket
   memory. The adapter uses maxlen 1024 and does not set SO_RCVBUF; 64 pending
   identities and 72 receive buffers per lane are separate bounds. Observe queue
   occupancy, queue-full/unicast loss and effective socket memory before tuning.
   SO_RCVBUF is capped by rmem_max and internally doubled. Deeper backlog can
   increase residence time and packet-ID search work while Product credits stay
   fixed. **Benefit:** absorb demonstrated bursts without bypass/loss.
   **Risk/prerequisite:** verify effective values and fail-open coverage; do not
   count reduced policy work as a CPU saving. **Priority: tune when pressure
   evidence exists, not as the first response to TX dispatch/switching samples.**
   [Queue pressure](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#690),
   [Netlink memory pressure](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1212),
   [RCVBUF cap](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/core/sock.c#1177),
   [RCVBUF accounting](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/core/sock.c#954).

6. **Copy range, flags and epoll timeout have narrow semantics.** Copy size is
   min(range, skb length): lowering 65531 to a value still above the UDP packet
   does not save copied bytes; truncating below complete IP length violates the
   current parser contract. COPY_META or removing UID_GID removes needed evidence.
   FAIL_OPEN/queue-bypass affects failure coverage, not legitimate CPU per fully
   qualified packet. Ordinary accepted verdicts continue the saved network path.

   VPP pin `9258530f3804a152578ce11cc7c8a1e9eab88ed0` applies poll-sleep-usec to
   main only. The Android idle patch allows a 1000 ms idle epoll timeout, but
   readable NFQ/eventfd FDs wake it early: timeout is not a deliberate packet
   delay. Increasing timeout does not remove traffic-triggered wakeups. A bounded
   active-poll window is an own-code power/latency tradeoff, requiring actual
   readiness evidence and light/idle measurements.
   **Benefit:** copy savings under a future different packet contract or fewer
   unnecessary wakeups. **Risk/prerequisite:** full policy evidence and correct
   notification/recheck; no unconditional busy polling. **Priority: mechanism-
   specific follow-up rather than a blanket configuration change.**
   [Copy sizing](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#438),
   [accepted continuation](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nf_queue.c#297),
   [pinned file poll](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/file.c#L106),
   [Android idle patch](../../src/product/vpp/android/patches/0017-vpp-android-idle-profile.patch).

## Concrete common next experiment

1. Keep fixed packed, capture rules, policy, permitted VPP worker placement,
   packet bytes/count/rate and burst shape unchanged. Select an allowed producer
   CPU distinct from the workers using discovered topology, compare with the
   existing placement, and record runnable preemption, epoll wakeups, packets
   per callback, aggregate/system CPU, per-thread CPU and delivery.
2. With producer competition controlled, exercise both existing queues using
   verified connection-stable test classification or reachable address diversity.
   Confirm both lane capture/verdict deltas before interpreting CPU; retain
   verdict batch sizes, owner handoff/return, ordering and policy qualification.
3. Use the measured readiness/publication counts to choose one bounded own
   ingress/origin flush or wakeup improvement. Optimize repeated evidence-key
   construction separately; identify owned redundant hook work separately.
4. Study GSO with realistic TCP only after the full-packet adapter contract is
   concrete. Change maxlen/RCVBUF only when their pressure boundaries are observed.

For every comparison report RTT p50/p95/p99 and absolute increments with CPU,
power, throughput and coverage. The user's distinction is that roughly 10–20 ms
has a different personal impact from 100–200 ms; it neither ignores p99 nor
creates a 200 ms SLA. The frozen 1.25 campaign guard remains historical data.

## Historical device inventory, excluded from optimization scope

Read-only post-campaign inventory found `bcmdhd4389`, driver .21, exposed TX LB
and doorbell aggregation controls, one netdev TX/RX queue, `pfifo_fast`, RPS 00
and an unsuccessful XPS read. Product remained stopped at generation 1969; no
setting changed. These readings do not establish campaign settings or explain
historical cumulative qdisc drops. Public BCM4389 source was retained at
`de86f6ec77fd3ea86aba02b8c045a4f9fac69732`, whose .16 banner differs from this
module's .21; it was mechanism research, not exact binary proof. Following the
user's explicit direction, no driver tuning comparison is proposed.
[Inventory](../../build-output/root-packed-flame-followup-20261013/device-config/result.json),
[parameter values](../../build-output/root-packed-flame-followup-20261013/device-config/parameter-values.json),
[LB readings](../../build-output/root-packed-flame-followup-20261013/device-config/wifi-lb-readings.json),
[vendor-source manifest](../../build-output/root-packed-flame-followup-20261013/primary-source/bcm4389/source-manifest.json).
