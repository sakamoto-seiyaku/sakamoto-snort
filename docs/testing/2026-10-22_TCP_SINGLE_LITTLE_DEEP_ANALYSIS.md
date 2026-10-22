# Single TCP on little cores: deeper offline analysis

2026-10-22; follows [the frozen measurement](2026-10-22_TCP_SINGLE_LITTLE_CORES.md)
at commit `048f7e12`. No new device run, native build or Product change.
The device remains in its audited original/stopped state. S293 stays open;
S308 stays Done. User subsequently authorized Plane publication and more analysis.

## What the existing evidence now explains

- Actual capture/primary batches average1.28–1.30 packets, return graph frames
  1.68–1.72 and completion publications1.96–1.99. A64-packet limit is not an
  achieved64-packet batch. No capture read-budget exhaustion was recorded.
- The owner's previously unclassified54.32% contains concrete socket receive/
  usercopy, Product policy/observation and HEV/lwIP work. Its symbols were resolved;
  the original conservative *phase* classifier did not assign that mixed work.
- Most I/O completion samples include Linux processing induced by TUN write:
  TCP/IP, netfilter, checksum, copies and wakeups. The46.41% kernel-TUN group is
  contained in the52.57% completion group; adding them would double count.
- A32KiB ring/send-buffer turnover constraint is visible, but historical direct
  interventions already show that enlarging it can worsen throughput and that
  32KiB can reach approximately500Mbps. Investigate ACK/scheduling turnover and
  actual batching/notification density before proposing another buffer variant.
- Shared-policy frequency and substantial system work outside the four bound
  little cores remain visible. Neither owner52% CPU nor I/O44% proves a saturated
  core, a radio cap, or the cause of the remaining off-CPU interval.

## 1. CPU hotspots: self locations versus inclusive contexts

Only the separate345.63Mbps profile is used here: owner 2,093 samples, I/O 1,754,
main 1, total 3,848 at 199 Hz. All periods happen to be 5,025,125 ns, so sample fractions
and period fractions coincide in this record. Total sampled CPU: 19.336681 s sums
threads; it is not wall time or energy. The six userspace ELF identities match
frozen symbols; kernel/module/vDSO symbols are recorded device identities only.
No reported loss/truncation and zero unresolved observed frames do not establish
complete unwinding, especially across coroutine/context-switch boundaries.

### Where the old unknown phase spent self CPU

Each row below partitions a subset of the original `other_unknown` selection.
Percentages use **all samples in that thread**, not just the unknown subset.
Categories are explicit offline interpretations of the observed leaf DSO/name;
ambiguous static helper names and TLS/PLT targets remain separate.

| Exclusive leaf category within old unknown | Owner samples / owner% | I/O samples / I/O% |
| --- | --- | --- |
| Product graph/policy/flow/observation | 252 /12.04% | 3 /0.17% |
| Linux usercopy/datagram iterator | 185 /8.84% | 9 /0.51% |
| Linux locks/scheduler/workqueue | 157 /7.50% | 89 /5.07% |
| Linux syscall/VFS/security | 136 /6.50% | 145 /8.27% |
| HEV/lwIP transport | 50 /2.39% | 0 |
| lwIP checksum | 45 /2.15% | 0 |
| Linux epoll leaf | 20 /0.96% | 33 /1.88% |
| All other exclusive leaves | 292 /13.95% | 83 /4.73% |
| Original unknown total | 1137 /54.32% | 362 /20.64% |

The last remainder includes52 ambiguous plugin-helper samples and28 TLS/PLT
samples on the owner. It is not an asserted single stage. Full assignments,
DSOs and raw chains are retained in `profile-decomposition.json`.

Concrete largest self leaves across **all** thread samples:

| Thread | DSO | Leaf | Samples | Thread self% |
| --- | --- | --- | --- | --- |
| Owner | kernel record | `_raw_spin_unlock_irq` | 235 | 11.23% |
| Owner | kernel record | `__arch_copy_to_user` | 148 | 7.07% |
| Owner | libc | `__memmove_aarch64_simd` | 69 | 3.30% |
| Owner | libvlib | `vlib_frame_queue_dequeue_fn` | 66 | 3.15% |
| Owner | Product plugin/lwIP | `inet_chksum` | 44 | 2.10% |
| Owner | Product plugin | `product_packet_policy_node_fn` | 42 | 2.01% |
| I/O | kernel record | `_raw_spin_unlock_irqrestore` | 126 | 7.18% |
| I/O | kernel record | `ipt_do_table` | 125 | 7.13% |
| I/O | libvlib | `vlib_frame_queue_dequeue_fn` | 81 | 4.62% |
| I/O | kernel record | `_raw_spin_unlock_irq` | 68 | 3.88% |
| I/O | kernel record | `do_csum` | 49 | 2.79% |
| I/O | kernel record | `__arch_copy_from_user` | 32 | 1.82% |

These are CPU sample locations. An unlock symbol is not evidence of spin
waiting; `finish_task_switch` or epoll self CPU is not blocked duration.
HEV/lwIP is statically linked into the Product plugin, so that DSO does not mean
all its CPU belongs to Product policy code.

Inclusive observed anchors overlap and **cannot be summed into a CPU budget**:
owner HEV/lwIP transport: 841 samples (40.18%); protected socket
`tcp_recvmsg`: 302 samples (14.43%); policy: 390 samples (18.63%);
frame-queue: 265 samples (12.66%); eventfd-write: 190 samples (9.08%);
observation-publish: 95 samples (4.54%). The 302 socket receive samples all occur in the old
unknown phase; a largest concrete chain has 105 samples:
`__arch_copy_to_user → ... → tcp_recvmsg_locked → ... → readv →
hev_socks5_session_tcp_direct_receive → tcp_session_task → hev_task_executer →
hev_task_execute`. This proves that observed receive/usercopy context, not its
missing ancestry back to VPP. The old unknown owner selection contains 501 samples whose observed chains
end at coroutine/context boundaries. It also contains 30 samples with only
1–3 observed frames; these selections are not asserted disjoint.
Those callers are not reconstructed.

The owner's 235 `_raw_spin_unlock_irq` self samples split exclusively into
186 under eventfd-write, 37 under timerfd-settime and 12 under eventfd-read.
Within 186, 137 follow completion publish/retained enqueue/native wakeup and 49
follow observation export/publish. These are sample memberships, **not numbers
of notifications or syscalls**. Both notification paths already coalesce:
[actual patched native wakeup](../../src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch)
uses a sequentially consistent `wakeup_pending` exchange on every publication;
a nonzero pending value coalesces the syscall. The owner acknowledges before
its complete work recheck. The measured out-of-line implementation does **not**
use the clean upstream header's `thread_sleeps` precondition;
[observation transport](../../src/product/native/product_observation_transport.c)
uses its own atomic pending latch. Observation exports on create/change or32
packets/64KiB plus its existing deferred-flush path. Adding another pending latch
or describing this as unconditional per-packet notification would misread source.
The measurement did not collect observation `notifications`/consumption counters
or an exact native successful-eventfd-write count.

### Exact I/O overlap and kernel work

| Observed set | Samples | I/O sample% | All VPP sample% |
| --- | --- | --- | --- |
| Completion phase AND kernel TUN-write | 814 | 46.41% | 21.15% |
| Completion phase WITHOUT kernel TUN-write | 108 | 6.16% | 2.81% |
| Kernel TUN-write WITHOUT completion | 0 | 0% | 0% |
| Neither | 832 | 47.43% | 21.62% |

Thus 922 = 814 + 108. Of the 108 difference, 46 still include
`product_vpn_tun_write_once` under libc/syscall/VFS/security or freeing paths;
only 62 lack that wrapper. The 108 cannot be labeled pure bookkeeping/free.
The observed write-wrapper set is 860, containing 814 kernel-TUN samples.

All 125 I/O `ipt_do_table` self samples have observed `tun_get_user` ancestry,
through Linux IP delivery/netfilter under the TUN write. They are not Product
rule-policy self CPU. Within the 814 TUN-kernel samples, TCP/IP anchors cover 585,
netfilter 324, checksum 56 and from-user copy 35; these contexts overlap. They
include Linux work delivering the virtual return packet and waking the socket
receiver. They do not quantify network transmission, syscall latency, pure copy
cost, or the whole phone's CPU budget. Generic read/epoll/syscall/scheduler paths
instead account for much of the I/O old-unknown20.64%.

## 2. Actual batches, packet direction and cost denominators

Pre/post CLI deltas are different brackets from the timed client bytes and CPU
monitor. These are observed graph ratios, not Wi-Fi wire packet rates:

| Window | Capture/primary packets per publication | Return admit vectors/frame | Completion vectors/publication | Origin vectors/frame |
| --- | --- | --- | --- | --- |
| Little repeat1 | 1.305 | 1.716 | 1.987 | 2.142 |
| Little repeat2 | 1.284 | 1.678 | 1.973 | 2.120 |
| Little repeat3 | 1.280 | 1.693 | 1.957 | 2.112 |
| Separate profile | 1.432 | 2.016 | 2.282 | 2.438 |
| Historical N2 A1, scalar | 1.000 | 1.000 | 2.150 | 2.287 |
| Historical N2 B2, adopted | 1.487 | 2.132 | 2.105 | 2.278 |
| Historical N2 B3, adopted | 1.482 | 2.116 | 2.118 | 2.290 |
| Historical N2 A4, scalar | 1.000 | 1.000 | 2.103 | 2.264 |

For example repeat1 has88927 primary vectors/68149 calls;96244 return admit
vectors/56085 frames;185171 completion vectors/93182 publications and185171
origin vectors/86430 frames. Capture lifetime maxima are5/5/6 packets and
budget-exit deltas0 in the three little repeats. Native frame256 and bounded
windows64 permit larger ready batches; they do not wait to assemble them.
Historical N2 rows retain the same single-flow tuple but differ in topology,
client CPU, throughput and artifact package; they show mechanisms, not a new
controlled gain comparison. Historical four-flow costs remain background in
[the previous report](2026-10-22_S308_TCP_DOWNLOAD_CPU.md).

Actual owner driver deltas are108247/112713/106774 schedule requests,
18357/18161/18067 readiness callbacks and71155/73692/70778 node invocations.
They count different seams; none equals native eventfd writes, actual task
wakeups or packets. Existing pending gates may collapse requests.

Matching UID2000/source31000/peer41723 FlowEntries show original-direction mean
IP-buffer lengths40.0005B and reply lengths8250.94/8259.96/8245.97B
(approximately8.25kB decimal,8.06KiB). Original traffic is ACK/control dominated,
with request/SYN and other control packets included; CLI has no per-packet TCP
flag/option trace to count pure ACKs exactly. Reply/original packet ratios are
1.082/1.062/1.075. These are virtual-IP buffers, not protected Linux socket/Wi-Fi
wire segments. Both directions traverse graph policy and completion, so useful
payload bytes alone conceal considerable ACK-side packet work.

Return `tun.write_size` bracket bytes are794103720/821576724/778534640, including
IP/TCP headers and tiny other-flow differences. `tcp_receive` committed payload
is790253956/817598012/774758076B; each is exactly32768B above the client's
790221188/817565244/774725308 received bytes. These are different milestones and
brackets, not proof that32KiB was lost or retransmitted. Their relationship is
consistent with bounded pipeline data at the window boundary; no packet/ACK
trace here identifies its exact location.

The original stationary-extrapolation CPU/GiB estimates remain26.13/25.34/25.60.
Dividing raw monitor CPU by CLI-bracket total graph vectors gives only a
**mixed-bracket proxy**102.1/98.2/99.7µs per IP buffer. It is not an exact timed
per-packet CPU measurement or a comparison threshold. No exact per-packet CPU,
TCP retransmission rate, TCP_INFO/RTT or syscall count was collected.

## 3. Frequency, system CPU and scheduler observations

Shared policy0 residency-weighted frequencies over the system brackets were
1.341/1.353/1.358GHz; maximum1803MHz residency shares18.13/15.94/16.99%.
These weights include idle and all work sharing the cluster; they are not each
Product thread's executed-cycle frequency. The outer system snapshots span
21.46/21.49/21.57s, while individual stat/residency reads happen serially inside
those brackets. Do not substitute these for the20s byte interval.

Five wholly traffic-contained condition passes per repeat show this sparse
trend (pass-start offsets, actual readings occur inside each1.5–3.3s pass):

| Repeat | Offsets seconds | Policy0 sampled MHz | LITTLE sampled °C |
| --- | --- | --- | --- |
| 1 | 0.11,3.64,7.77,11.73,15.50 | 1803,1598,1803,1197,1803 | 45,42,42,44,43 |
| 2 | 1.26,5.07,9.24,13.07,16.98 | 1704,1803,1197,1197,1803 | 46,44,45,46,47 |
| 3 | 0.51,4.25,8.33,12.39,16.43 | 1598,1803,1197,1803,1328 | 48,48,45,45,45 |

Temperature ranges rise across some lifecycle brackets, but this sparse series
and residency do not prove thermal throttling caused the throughput variation.
The separate profile has1.372GHz residency-weighted policy0 frequency; it cannot
serve as a profiler-overhead control. Read-only collection wall duration is not
its CPU cost; no independent sampler-overhead subtraction is available.

Per-core `/proc/stat` busy excludes idle+iowait; IRQ and softirq are **subsets**
of busy, not extra CPU to add to it:

| CPU | Repeat1 busy% | Repeat2 busy% | Repeat3 busy% | Softirq range% |
| --- | --- | --- | --- | --- |
| 0 | 45.92 | 44.79 | 48.00 | 0.29–0.34 |
| 1 | 57.00 | 59.74 | 54.37 | 0.34–0.44 |
| 2 | 50.51 | 52.01 | 48.37 | 0.85–0.96 |
| 3 | 36.81 | 34.51 | 34.75 | 0.40 |
| 4 | 43.85 | 42.37 | 41.21 | 23.77–23.91 |
| 5 | 26.41 | 26.79 | 25.00 | 10.19–10.61 |
| 6 | 14.44 | 15.71 | 13.96 | 6.20–6.87 |
| 7 | 14.58 | 15.07 | 14.34 | 3.21–3.62 |

Full IRQ components are in JSON (CPU4 about3.0–3.2%, CPU5 about1.1%). This
proves work outside the bound little-core threads; per-CPU softirq classes and
IRQ-device mapping were not captured, so CPU4/5 work cannot be assigned directly
to Wi-Fi NET_RX. CPU0 busy far exceeds VPP main0.05–0.10%; background/system/
collection work is substantial but not independently attributed. Its CPU and
the separate receiver21–23% are not subtracted from Product CPU using mismatched
brackets.

Existing per-TID schedstat deltas add a narrower scheduler observation:
owner runnable runqueue wait0.485/0.470/0.394s; I/O0.557/0.534/0.478s. These are
outer-bracket accumulated runnable waits, not epoll/socket blocked time. They
must not fill the remaining approximately48% owner wall-time budget. On-CPU
samples explain where owner runs; without current off-CPU/ACK timing they do
not explain why it is not continuously running or establish the bottleneck.

## 4. Which source limits are really enabled

`source-config-proof.json` hashes the actual patched staged HEV source, Product
entry points, actual patched VPP source/stage header, CMakeCache and compile
definitions. The clean pinned inline wakeup header is not the measured path. The current
cache unstripped plugin exactly matches frozen SHA256
`cb946bfb1085a08d498e164101ef14dc310eefa8cb7298d5d8c73b444bf35e46`;
the retained strip proof matches the measured APK plugin. Native `libvlib`
Build ID `4acf27fe74dfd190a38aeea3c9821f0b73678161` matches the profile. Its
unstripped actual-cache ELF matches the retained symbols, and the existing strip
proof plus direct stage/APK SHA comparison matches `73068ccc…d2fa6`. The actual
stage header equals that patched cache header; disassembly is retained beside
the proof. No rebuild was needed.

- LARGE_SEGMENT isON: MSS9940. TCP_BATCH, TCP_BUFFER and TCP_PROGRESS areOFF.
- The HEV ring is constructed with `TCP_SND_BUF`,32768B; lwIP sender byte credit
  is also32768B. This is not Linux protected-socket `SO_RCVBUF`. `TCP_WND=32768`
  is lwIP's receive-side advertised-window setting, a different direction/role.
- The normal direct receive round does one nonblocking `readv` if ring space
  exists, then up to two ring spans with each commit capped at negotiated MSS
  and available lwIP sndbuf. Observed max commits2 matches this enabled branch;
  the experimental eight-commit branch isOFF. Ring data is released by the
  actual `tcp_sent` ACK callback, preserving lwIP's no-copy lifetime.
- Product invokes `step(8,200µs)`. The cooperative scheduler checks task count,
  quantum budget and monotonic deadline between task turns;200µs is not a hard
  preemption limit or an intentional200µs sleep. A runnable result reschedules
  the existing VPP node. No per-cause budget-hit counter was collected.
- TCP_PROGRESS OFF leaves the printed wait/wake diagnostic rows zero. Those
  zeros mean the instrumentation is inactive, not no waits. Enabling that flag
  also changes readiness-interest behavior, so it is not a neutral probe switch.

Timed-bracket loop-entry observations:

| Repeat | Receive rounds | Ring full observations | sndbuf full observations | Ring/round% | sndbuf/round% | readv EAGAIN/calls% |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | 163079 | 93980 | 60211 | 57.63 | 36.92 | 19.20 |
| 2 | 168683 | 96867 | 63194 | 57.43 | 37.46 | 17.68 |
| 3 | 160997 | 90642 | 58792 | 56.30 | 36.52 | 20.90 |

All lifetimes reach ring_peak/flight_peak32768B. Full checks are separate `if`
statements before send/receive, not a sndbuf branch skipping window/cwnd checks.
Their window/cwnd-full observations are0, but this does not prove those limits
never matter between observations. Repeated rounds may observe the same full
state many times: these are not independent full events or wall-time fractions.
At the measured rates,32768B divided by delivered byte rate is0.829/0.802/0.846ms,
a dimensionally consistent turnover hypothesis, **not measured RTT or ACK time**.

### Historical counterevidence constrains that hypothesis

The [October21 investigation](2026-10-21_VPN_LONG_TCP_SEGMENTS_AND_PROGRESS.md)
already performed a same-source32/65528/65528/32 buffer intervention:20s rates
159.22/134.73/136.01/149.91Mbps. Separate trace return-to-ACK means were1414µs
for the first32KiB control and2986/2728µs after enlargement. More flight and queue
occupancy did not improve that slow scenario. Do not repeat blind enlargement
because the present ring often appears full.

That historical32KiB diagnostic artifact reached503.10/504.62Mbps when only the
receiver was fixed to CPU3, with ACK cycles375/344µs. Later ordinary uninstrumented
APK `b92e5120…` (batch/buffer/progressOFF) repeated free/CPU3/CPU3/free at
251.93/496.62/535.54/265.39Mbps; adjacent direct control507.15Mbps. Historical
scheduler records identify41538/41706 TUN-path switches immediately to the actual
free receiver TID, versus0/107 when receiver was on CPU3. This was direct causal
placement evidence for that old topology, not a name-based guess.

Those artifacts/topology/owner placement differ from current N1 dedicated I/O;
they cannot prove a current regression or transfer that cause unchanged.
They do refute a universal32KiB/approximately300Mbps ceiling. The current receiver
already has CPU3 singleton affinity, so the exact old same-core preemption
pattern must not simply be assumed to recur. Historical JSON identities and
selected raw numbers are in `historical-counterevidence.json`.

## 5. Evidence ranking and the next bounded discriminator

**Established:** actual tiny ready batches; ACK/control-heavy original side;
per-packet Linux work inside TUN return; meaningful notification-path self CPU;
32KiB ring/sndbuf entry pressure; shared variable frequency; CPU4/5 system work.

**Supported hypotheses, not established causes:** ACK/service-turnover and
placement can govern how quickly the32KiB lifetime is released and how many
ready packets meet one graph turn; short batches amplify fixed scheduling,
frame-queue and notification work. Historical interventions support testing
this family, not selecting a buffer size or removing required observation.

The next bounded experiment should be the placement discriminator below. A
second mechanism window is conditional, **not executed here**:

1. **Placement discriminator:** same current APK, N1, source tuple, defaults and
   receiverCPU3; compare ownerCPU1/I/OCPU2 with ownerCPU2/I/OCPU1 in a small
   counterbalanced set of20s windows. Keep main0 and record actual TIDs, policy0
   residency, system CPU and stops. A repeatable change would support role/core
   placement sensitivity; no change would weaken this narrow hypothesis. Shared
   frequency and background work still need recording. No new owner/hash policy,
   buffer variant, or broad matrix is required.
2. **Conditional ACK/notification mechanism discriminator:** if the placement
   result warrants further mechanism work, one separate bounded diagnostic
   window on the unchanged current layout, adding current off-CPU scheduler/TID
   evidence and existing observation publication/notification/consumption
   counters. A narrowly bounded ACK-release/return trace would distinguish
   slow32KiB release from upstream empty reads and graph service gaps. Require
   exact probe identities and CPU versus wall separation. Do not use the
   behavior-changing TCP_PROGRESS flag as neutral instrumentation, infer eventfd
   counts from samples, or add a latch already present. A new diagnostic build
   is unnecessary for the existing counters/off-CPU portion; packet timing would
   need an explicitly scoped probe and its perturbation accounted for.

## Reproduction, review and publication

From the repository root:

```sh
rtk proxy python3 tests/benchmark/tcp_single_little_analysis.py \
  --campaign build-output/tcp-single-little-20261022 \
  --historical-campaign build-output/s308-tcp-download-attempt3-20261022 \
  --output build-output/tcp-single-little-deep-analysis-20261022
rtk proxy python3 tests/benchmark/tcp_single_little_profile.py
```

New outputs live in `build-output/tcp-single-little-deep-analysis-20261022/`:
`graph-system.json`, `frequency-thermal-timeline.csv`,
`profile-decomposition.json`, `findings.md`, source/config proof and historical
counterevidence. The original profile, protocol, raw windows and original
measurement values are unchanged. Four focused accounting regressions check
IRQ subset arithmetic, missing-core data and CPU/frequency counter reset;
independent explicit GPT-6.1 Spec/Standards review covers the new tools/report.
No69-test Product suite or device campaign was repeated for offline analysis.
Final identities/review/publication proof are retained in `closeout.json` there.
Raw evidence/APKs/symbols remain local gitignored artifacts, without a portable
archive. The original results were published once after explicit authorization
as S293 comment `63f13439-4da2-429c-9811-ddc656f81145`; this report's new analysis
can be published separately under that subsequent authorization, keeping S293 open.
