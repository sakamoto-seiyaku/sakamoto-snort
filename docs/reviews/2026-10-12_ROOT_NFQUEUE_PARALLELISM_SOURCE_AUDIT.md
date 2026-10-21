# Root NFQUEUE parallelism after sendmmsg: source audit

Date: 2026-10-12. Evidence and experiment candidates only; this report does not
change the accepted placement model, runtime defaults, or sendmmsg qualification.
The product inspection used the current dirty C mainline above repository HEAD
`54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6`; HEAD alone does not identify the tested
artifact. The dated [batch experiment](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md)
and its retained APK/source identities identify the measured artifacts.

## Finding

The fixed-address IPv4 UDP load exposes one receive/verdict lane even though
policy processing reaches both canonical workers. Linux NFQUEUE queue balance
does not hash UDP ports. Therefore, 64 distinct port tuples between the same
addresses do not exercise two kernel queues. This explains the observed lane
concentration without requiring a global verdict mutex hypothesis. The matched
Android source registers ordinary verdict callbacks as RCU callbacks; its
NFNETLINK subsystem mutex applies to configuration, not ordinary verdicts.
[Android hash_v4/nfqueue_hash, lines 49–58 and 105–125](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/net/netfilter/nf_queue.h#49),
[Android nfqnl_cb, lines 1434–1458](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1434),
[Android nfnetlink_rcv_msg, lines 288–304](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#288).

This is a demonstrated imbalance in execution placement and a candidate scaling
limit. It is not proof of an already saturated CPU or measured lock contention.

## Source identity and limits

The retained dense B profile identifies kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` in
[its metadata](../../build-output/root-sendmmsg-20261012/runs/dense0-B/graphs/root-udp-fixed-hotspots.json).
The official Android Common commit corresponding to that suffix is
`66e758f7d0c01a696c3a9db8929417e7403a1571`, tree
`3af870e65f83f28194791550ffe26f13f58eb1c7`; its Makefile specifies 6.1.134.
[Commit metadata](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571?format=JSON),
[Makefile](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/Makefile#2).

The upstream comparison is Linux v6.1 commit
`830b3c68c1fb1e9176028d02ef86f3cf76aa2476`.
[Upstream release commit](https://github.com/torvalds/linux/commit/830b3c68c1fb1e9176028d02ef86f3cf76aa2476).
Citation correction, 2026-10-12: upstream ranges and anchors below now use actual
raw-source lines, correcting browser-rendered offsets; findings are unchanged.
The relevant hash, RCU dispatch, queue-lock scope, direct Netlink callback and
sendmmsg loop mechanisms agree in these two revisions. The Android line numbers
below refer to real source lines, not rendered page offsets. Official Gitiles
`?format=TEXT` sources were retrieved and decoded when browser page fetching
failed. Matching the advertised commit does not establish byte-for-byte identity
of the device's vendor modules, KernelSU additions or kernel build configuration.

## What the measured workers actually do

The three dense B windows have all admission/preparation and origin completion
on VPP thread 1, worker 0, CPU 1. Thread 2, worker 1, CPU 2 performs its selected
policy work and publishes completion back to the origin. All four lanes are
configured and ready; only IPv4 lane 0 has captured packets in these windows.
The before/after deltas are preserved in
[thread-and-callchain.json](../../build-output/root-sendmmsg-20261012/parallelism-analysis/thread-and-callchain.json),
with original [dense0-B CLI](../../build-output/root-sendmmsg-20261012/runs/dense0-B/after-cli.txt),
[dense1-B CLI](../../build-output/root-sendmmsg-20261012/runs/dense1-B/after-cli.txt) and
[dense2-B CLI](../../build-output/root-sendmmsg-20261012/runs/dense2-B/after-cli.txt).

| Lane | Family | Kernel queue | VPP worker/thread | Measured capture/verdict placement |
| --- | --- | --- | --- | --- |
| 0 | IPv4 | 176 | worker 0 / thread 1 | All measured IPv4 load |
| 1 | IPv4 | 177 | worker 1 / thread 2 | Zero captured packets |
| 2 | IPv6 | 178 | worker 0 / thread 1 | Zero captured packets |
| 3 | IPv6 | 179 | worker 1 / thread 2 | Zero captured packets |

Measured policy packet deltas total 48,447 on thread 1 and 30,414 on thread 2,
approximately 61.4% / 38.6%. This is actual canonical-owner work distribution,
which differs from kernel receive placement. CPU monitoring over approximately
17.4765 seconds of sampled coverage totals 7.49 CPU seconds on worker 0 and 1.47
on worker 1, with 0.01 on main. Worker 0 accounts for about 83.5% of monitored
process CPU time, but uses about 42.9% of one CPU over that coverage; worker 1
uses about 8.4%. The separate period-weighted cpu-clock profile gives worker 0
about 88.1% of sampled process CPU. These are different estimators/windows and
must not be combined or described as a CPU operating at 83.5% or 88.1% capacity.
The derivation and window coverage are in the same
[analysis artifact](../../build-output/root-sendmmsg-20261012/parallelism-analysis/thread-and-callchain.json).

## Kernel queue balance and CPU fanout

For ordinary IPv4 queue balance, `hash_v4` sorts the two IPv4 addresses, hashes
those two words plus `iph->protocol`, and `nfqueue_hash` maps that hash into the
configured queue range using `reciprocal_scale`. Neither source nor destination
port is read. IPv6 also does not read ports: this revision's `hash_v6` uses
selected words from the two IPv6 addresses and does not add an IP protocol word.
Thus the often-used description “address plus protocol hash” is accurate for
IPv4, but not a precise description of this IPv6 implementation.
[Android nf_queue.h, hash_v4/hash_v6/nfqueue_hash, lines 49–125](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/include/net/netfilter/nf_queue.h#49),
[Linux v6.1 equivalents, lines 49–125](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/include/net/netfilter/nf_queue.h#L49).

`--queue-cpu-fanout` selects `first_queue + smp_processor_id() % queues_total`
at the NFQUEUE target. It refers to the CPU executing that kernel hook, not the
VPP canonical worker or the CPU chosen for the later verdict callback. With two
queues, CPU parity selects the lane. Pinning two VPP workers does not cause a
single pinned OUTPUT producer or single-CPU INPUT path to fan out.
[Android nfqueue_tg_v3, lines 85–108](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/xt_NFQUEUE.c#85),
[Linux v6.1 nfqueue_tg_v3, lines 85–108](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netfilter/xt_NFQUEUE.c#L85).

CPU fanout removes address-based queue stickiness. If a flow's hook executes on
different CPUs over time, its packets can enter different queues. It may expose
receive/verdict parallelism when hook CPUs vary; it also creates a potential
cross-lane arrival/completion reorder. Those are source-derived consequences,
not device observations from this campaign.

## What is serialized by which lock

| Operation | Confirmed synchronization in matched Android source | Consequence |
| --- | --- | --- |
| NFQ ordinary `NFQNL_MSG_VERDICT` | `NFNL_CB_RCU` dispatch | No NFNETLINK subsystem mutex around this callback |
| NFQ range `NFQNL_MSG_VERDICT_BATCH` | `NFNL_CB_RCU` dispatch | Also no subsystem mutex; different verdict semantics |
| NFQ `NFQNL_MSG_CONFIG` | `NFNL_CB_MUTEX` dispatch | Queue configuration uses the subsystem mutex |
| Queue lookup | RCU instance lookup; verdict validates peer port ID | Different user sockets cannot freely issue verdicts for another queue's peer |
| Normal verdict dequeue | This queue instance's `queue->lock`, with BH disabled | Linear packet-ID search and list removal occur while locked |
| Normal verdict reinjection | After `find_dequeue_entry` releases `queue->lock` | Normal reinjection is not covered by that queue lock |
| Packet enqueue | This queue instance's `queue->lock` | Includes count/ID changes, Netlink unicast to its user peer, and append to queue list |
| Destroy/flush | Instance-table lock for topology changes; flush takes queue lock | Flush performs DROP reinjection under queue lock; this is not normal verdict processing |

The first three rows follow
[nfqnl_cb, lines 1434–1458](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1434)
and [nfnetlink_rcv_msg, lines 288–304](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#288).
The instance, lookup, dequeue, enqueue and flush rows follow
[nfqnl_instance/instance_lookup, lines 57–114](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#57),
[verdict_instance_lookup, lines 1077–1090](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1077),
[find_dequeue_entry and nfqnl_flush, lines 206–262](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#206),
[__nfqnl_enqueue_packet, lines 690–746](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#690),
and [nfqnl_recv_verdict, lines 1225–1288](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#1225).
Upstream corroborates the normal queue-lock boundaries in
[find_dequeue_entry, lines 205–224](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netfilter/nfnetlink_queue.c#L205)
and [__nfqnl_enqueue_packet, lines 657–714](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netfilter/nfnetlink_queue.c#L657).

The normal verdict callback calls `nfqnl_reinject` after removing the packet.
`nf_reinject` continues the applicable hooks and invokes the saved `okfn` for an
accepted packet. Routing, local UDP delivery and transmission can therefore be
charged to the origin worker's verdict syscall stack. Their individual locks
are not the NFQ queue-instance lock.
[Android nfqnl_reinject, lines 228–246](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink_queue.c#228),
[Android nf_reinject, lines 297–355](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nf_queue.c#297),
[Linux v6.1 nf_reinject, lines 299–357](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netfilter/nf_queue.c#L299).

Even with one userspace verdict writer, kernel enqueue can race its dequeue on
the same queue instance. Conversely, packets in different NFQ instances do not
share that instance lock. The linear dequeue search can become more expensive
with deep queues or out-of-order completions. These are possible contention or
CPU-cost mechanisms; current CPU samples do not measure their waiting time.

## sendmmsg does not make one kernel callback parallel

`__sys_sendmmsg` looks up one socket and processes its messages in a `while`
loop through `___sys_sendmsg`. Each Netlink message reaches the kernel receiver
via `netlink_unicast_kernel`, which directly invokes the receive callback in
the sending context. One sendmmsg call therefore still processes its independent
verdicts serially. Two owning worker threads using their respective bound FDs
can enter ordinary verdict callbacks concurrently; the inspected path does not
wrap them in a global NFNETLINK verdict mutex. Shared allocator, socket accounting,
conntrack, local delivery, device queues and driver costs can still limit scaling.
[Android __sys_sendmmsg, lines 2608–2673](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/socket.c#2608),
[Android netlink_sendmsg, lines 1778–1865](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1778),
[Android netlink_unicast_kernel, lines 1300–1319](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netlink/af_netlink.c#1300),
[Linux v6.1 sendmmsg loop, lines 2581–2646](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/socket.c#L2581),
[Linux v6.1 direct kernel receiver, lines 1307–1326](https://github.com/torvalds/linux/blob/830b3c68c1fb1e9176028d02ef86f3cf76aa2476/net/netlink/af_netlink.c#L1307).

The product candidate sends separate `NFQNL_MSG_VERDICT` messages. A syscall
named sendmmsg does not emit an `NFNL_MSG_BATCH_BEGIN` transaction, and it does
not become the same-verdict range operation `NFQNL_MSG_VERDICT_BATCH`. The
NFNETLINK transaction-batch mutex path cannot be inferred from the syscall's
batching name.
[Product verdict construction](../../src/product/vpp/product_root_nfqueue_adapter.c:645),
[Product sendmmsg window](../../src/product/vpp/product_root_nfqueue_adapter.c:1120),
[Android nfnetlink_rcv, lines 642–660](https://android.googlesource.com/kernel/common/+/66e758f7d0c01a696c3a9db8929417e7403a1571/net/netfilter/nfnetlink.c#642).

## Product hook and ownership inspection

The C adapter does not construct iptables hooks. It opens and binds one Netlink
FD per lane, configures that queue, and assigns its file listener to that lane's
worker. Lane mapping is `family_lane = lane_index % 2`, with worker equal to
family_lane. Completion validates immutable origin lane, worker, generation and
packet identity, and sends through that original lane FD.
[Lane reset/open](../../src/product/vpp/product_root_nfqueue_adapter.c:1643),
[Completion validation](../../src/product/vpp/product_root_nfqueue_adapter.c:943),
[Supervisor ownership comment](../../src/product/vpp/product_root_nfqueue_adapter.c:1908).

RuntimeService constructs INPUT/OUTPUT TCP/UDP/Echo hooks with
`--queue-balance 176:177` for IPv4 and `178:179` for IPv6, plus `--queue-bypass`.
OUTPUT additionally selects the application UID. It does not add
`--queue-cpu-fanout`. Native `NFQA_CFG_F_FAIL_OPEN` configuration is separate
from the no-listener bypass rule flag.
[Hook ranges](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java:5900),
[productRootFamilyHooks](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java:5921),
[Native queue flags](../../src/product/vpp/product_root_nfqueue_adapter.c:45).

CPU fanout does not itself violate per-packet origin-exclusive FD ownership:
each packet can retain whichever origin lane actually received it. It does
change connection-stable initial placement and can alter cross-lane arrival
ordering before canonical-owner processing. Correct canonical owner selection
alone does not prove unchanged tracker/reassembly ordering or tail latency.
The accepted baseline explicitly uses connection-stable queue balance, so fanout
remains a separate diagnostic/adoption question, not an automatic change allowed
by this audit.
[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md),
[Per-worker ownership and origin completion contract](../decisions/PER_WORKER_FLOW_OWNERSHIP.md).

## Smallest discriminating experiment

1. Keep the same APK, sendmmsg setting, hook rules, CPU placement, packet count,
   bytes, rate, burst interval and policy. Compare the existing fixed-address
   load with a controlled address-diverse load using an echo target that already
   supports multiple reachable addresses. Verify actual queue 176/177 and lane
   0/1 deltas before interpreting CPU or p99. Different addresses can still hash
   to the same queue; a nominal multi-address input does not prove Q2 exercised.
2. Measure per-lane capture, settled verdicts, syscall batch sizes, per-thread
   CPU, owner handoffs/returns, qualified-policy success, fail-open, delivery and
   latency together. Splitting current batches between lanes can reduce messages
   per sendmmsg call, so balanced placement need not reduce aggregate CPU.
3. If queues become balanced but total CPU or tails fail to improve, use the
   complete kernel callchains to separate NFQ dequeue work from reinjection,
   socket wakeups and driver work. A `_raw_spin_*` frame, especially an unlock
   frame, is CPU execution evidence and cannot identify lock waiting. A contention
   conclusion requires a supported lock-wait/slowpath measurement and lock identity.
4. Only if fixed-address behavior needs direct investigation, run CPU fanout as
   an isolated diagnostic with recorded/restored hook rules and known hook-CPU
   distribution. Exercise one bidirectional flow entering both lanes, validate
   canonical state ownership, protocol/reassembly behavior, ordering, mixed
   verdicts, generation/stop and completion conservation before considering
   adoption. Changing only VPP CPU placement is insufficient to ensure fanout.

No product edits, device/network trials, tracker writes or commits were made
for this source audit. The three dense B windows are reused evidence. Further
performance and driver conclusions belong to the accompanying measured-path
analysis, not to the presence of a spinlock in this source.
