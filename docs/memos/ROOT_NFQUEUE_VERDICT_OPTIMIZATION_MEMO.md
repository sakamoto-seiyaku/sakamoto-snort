# Root NFQUEUE verdict optimization memo

Updated: 2026-10-13. Current VPP-native C Product work, distinct from the historical
[Android/VPP POC memo](ANDROID_VPP_POC_DECISION_MEMO.md). Source findings, measured
results and candidate choices retain their separate scope.

The match-evidence reuse is now installed and tested onPixel. Both APKs pass
256 ALLOW/256 DROP semantics; all60000 payload packets across six fixed AB/BA/AB
windows arrive. Recording-scope CPU samples shrink2.15%→1.22%, but whole-path
CPU/Q improvement is **not established**: all-window descriptive observation is
+4.82% (interval crosses1), with one final kernel snapshot unassessed. No retry
or performance-adoption claim. Original APK/config/Stopped are restored.
[Real-device results and limits](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#匹配证据真机前后对照--2026-10-13).

The portable I/O attempt ended after seven traffic windows and an owner-live
start failure. Every measured window failed delivery qualification; two-lane
placement was real, but this campaign provides no adoption result. Remaining
traffic/idle/pressure cells were not executed or retried. Original APK, full
configuration and Stopped state are restored. Previous measurements below
remain unchanged.
[Current experiment](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#通用-io-配置与预算对照--2026-10-13).

## Current product judgment — continue whole-path batch plus packed

After seeing the absolute figures, the user clarified on2026-10-13 that the
final25.2 ms probe p99 versus scalar15.7 ms should not block batching progress.
The increment is9.5 ms, weighed against8.69% lower CPU/Q and85.91% fewer verdict
calls/datagrams. The earlier emphasis on a60.5% relative increase overstated
the product significance of the experiment's preset≤1.25 ratio threshold.
Whole-path batch plus packed remains the main candidate for continued work.

Report absolute latency and its increment first; retain relative ratios as
diagnostic data. The frozen campaign, failed original guard and racing snapshot
remain unchanged. This later product judgment does not relabel the experiment
as passing its original protocol or establish a new numerical latency budget.
The user's further clarification is to keep p99 in the overall CPU/user-experience
tradeoff:10–20 ms and100–200 ms have different practical weight in the personal
scenario. Those examples are not a newly specified SLA or permission to ignore tails.
[Recorded user clarification](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#用户确认后的延迟判断--2026-10-13).

## Flamegraph follow-up — large costs first, then stable single functions

The existing nine CPU-only records were drilled into caller stacks and normalized
by Q, without new device collection. Fixed packed's remaining reinjection/network
stack share is45.75%; Netlink excluding NFQ is3.46%, syscall excluding Netlink0.73%.
The281 queue_work_on leaf samples all follow the dhd TX chain in worker0; scalar
also has281 samples. Its14.74% vs13.31% share does not show increased absolute
driver work. Finish_task_switch has220 packed leaf samples:147 under epoll return,
53 under verdict/reinject preemption,9 under observation-write preemption.

The2.10% evidence-key leaf is a separate product candidate: all40 samples are
under match recording, whose then-current source recomputed the same probe key
and packet projection. The later reuse within one recording call retains identical
hashes, association semantics and publication order. Another40 samples belong
to the actual cached matcher, also2.10%; do not merge them into one function.
Shared atomic record contention remains an unmeasured source hypothesis.

The user explicitly restricts subsequent work to portable NFQUEUE/common Linux
configuration and our own VPP mechanisms, excluding vendor-driver or individual
device tuning. Driver caller stacks explain costs; the read-only BCM inventory
is not a proposed optimization. Continue investigating configurations that change
accepted-packet work count or placement, and our wakeup behavior. Rank
those against the large hotspots; the narrow evidence-key reuse is now implemented
with the bounded validation linked above. The recorded p99 remains part of that judgment: B24.5/18.9/25.2 ms,
S19.6/16.6/15.7 ms; mean RTT differs by about0.17–0.23 ms. The successful recorded
probe maxima are B88.172 ms and S27.442 ms, with no≥100 ms sample in either arm.
[Drilldown and raw caller stacks](../../build-output/root-packed-flame-followup-20261013/index.html),
[full follow-up record](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#packed-火焰图继续分析与-nfqueue-配置方向--2026-10-13).
[Portable configuration options and limits](../reviews/2026-10-13_ROOT_NFQUEUE_CONFIGURATION_HOTSPOT_OPTIONS.md).

## Latest result — slot fix and nine-window diagnosis complete

The user authorized continuing whole-path VPP batch plus packed. The actual
allocator regression now admits a displaced ID into a free record while preserving
the older loan, exact completion identity, duplicate/stale exclusion and the
64-record capacity. Two lane-private bitmaps add16 B/lane; seven diagnostic
counters add56 B/lane,288 B total across four lanes. Fresh classic/fixed packed
artifacts differ only in the allocation branch, and a fixed-source scalar control
separately compared the final sender choices. The recorded build switches are
currently OFF and the allocator fix remains in source; the9.5 ms RTT increment
is not a product-level reason to block the next packed step.

A separate timing helper and off-CPU capability check passed on the Pixel in
the ordinary running Root context. Local timing gaps and the remaining RTT stay
distinct; no cross-host clock subtraction or claim of pure Wi-Fi time is made.
The stopped-context app-UID failure and local profiler pull preparation failure
remain archived; the existing successful record was recovered, not resampled.
All three fresh artifacts passed the same exact512×64 B mixed wire gate and
real negative-send check. Fixed packed also passed the refused middle-ID check;
the representative VPN smoke started and stopped cleanly.
[Implementation, method and complete evidence](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#64-slot-completion-碰撞修复与延迟分段--2026-10-13).

The controlled50 ms owner hold reproduced68 completion rejections in the classic
allocator despite pending-full=0. Fixed packed encountered113 home collisions
with0 completion rejections;1 genuine normal-buffer bypass stayed explicit.
This confirms the controlled cause and fix, not the history of every event in
the older campaign. During the nine performance windows, the classic first
window had8 completion rejections/full0; the six fixed packed/scalar windows had
49 home collisions and0 ingress rejections. Capacities and credits were unchanged.

The protocol ran all nine windows in balanced ABS/BSA/SAB order. A is classic
packed, B is fixed packed, S is fixed scalar with the same fixed source. Each
window used6 s,1 s warmup,4kpps and32-packet bursts with the separate timing helper
and trace-offcpu collection. The preparation attempt before this campaign failed
the helper-source identity check before runtimeStart, traffic or profiling;
its protocol and empty measurement record remain archived. After correcting that
wrapper source selection, the new protocol was frozen before any sampled window.
No sampled window was retried or replaced.

| Dense CPU/Q contrast, all three rounds retained | Geometric mean change | t(2)95% interval | Original protocol guards |
| --- | ---: | --- | --- |
| fixed packed / classic packed | +2.59% | [+0.90%, +4.32%] | Fail |
| fixed packed / fixed scalar | −8.69% | [−9.22%, −8.17%] | Fail |
| fixed scalar / classic packed | +12.36% | [+10.19%, +14.58%] | Fail |

Fixed packed averaged7.097 independent messages per syscall/datagram, reducing
normalized calls/datagrams85.91% vs fixed scalar. Its p99/scalar ratios were
1.250 /1.139 /1.605; the final round failed the≤1.25 guard. That same final B
window had a racing initial kernel/native snapshot (4376 vs4377) and remains
unqualified; its final30687/30687 boundary was clean. This does not prove a lost
packet. All windows delivered24000/24000 payloads, retained their timing rows and
stopped cleanly. The CPU signal supports retaining packed as a candidate, while
the measured+2.59% vs classic packed records a correctness-fix tradeoff.
[All nine checks and paired ratios](../../build-output/root-verdict-slot-fix-20261012/summary.json),
[CPU-only flamegraph browser](../../build-output/root-verdict-slot-fix-20261012/comparison.html).

Explicit on-cpu profiles show kernel shares74.31% /74.13% /78.68% for A/B/S.
Visible Netlink work excluding NFQ is3.54% /3.46% /8.05%, and verdict syscall
work excluding Netlink is0.98% /0.73% /3.46%. Reinjection remains43.66% /45.75%
/43.87%. These mutually exclusive visible stack shares describe VPP CPU and
retain sampling limits; they are not intrinsic costs or attainable gains.

For fixed packed, each window's slowest1% probes have92.13%–95.90% of RTT in
the residual duration; across those same probes it is94.89%, phone RX-to-read
4.96%, peer RX-to-send-call0.16%. Residual includes the outgoing product/kernel
path and network, so it is not a pure Wi-Fi measurement. Component marginal
p99s are not added; the recorded same-probe duration sums are conserved.
[Per-probe timing and clipped off-CPU evidence](../../build-output/root-verdict-slot-fix-20261012/diagnostic-summary.json).

Fixed packed has3688 verdict-send-visible off-CPU intervals, maximum5.545 ms;
3687 have raw sched-switch state256 (preempted runnable),1 has state0. The exact
device-kernel source defines that interpretation. The immediate successor is
socket-load in93.28% of those intervals, establishing generator/VPP scheduling
competition in this test. The successor is only the first task after switch-out;
its count or interval duration is not generator CPU time. This evidence does
not support describing the observed send waits as sleeping in an NFQ lock,
and does not prove the cause of a particular probe's tens-of-ms RTT. Packet-ID
ownership correlation and application/network/driver scheduling remain outside
this capture. [Raw scheduler witnesses and exact-source hashes](../../build-output/root-verdict-slot-fix-20261012/diagnostic-groups.json).

Original empty configuration semantics were restored through the ordinary API
at saved=active950, and the original baseline-v4 OFF APK, UID12632 and Root grant
were retained. Generation1969 stopped with native debt, hooks, queues and VPP
process absent. The owned peer PID2523238 was identity-checked, stopped and
verified absent. [Restoration](../../build-output/root-verdict-slot-fix-20261012/final-restoration/result.json),
[final evidence closure](../../build-output/root-verdict-slot-fix-20261012/final-proof.json).

The next discriminator would be bounded packet-ID timing through the outgoing
path and independent client scheduling, if that diagnosis becomes useful.
It is not a prerequisite for continuing packed given the user's judgment of
the observed absolute latency. The sampled campaign remains unchanged.

## Earlier result — same-window scalar / sendmmsg / packed, 2026-10-12

All twelve fixed windows ran on Product source
`7464d472bc44905e8e2a5a93ecf059d57d359916a9bb5ff87ee3f852053dc135`.
The three senders share the same 16-item origin prepare/flush/finish window,
graph batch mode, resources, rules, workload and profiler. Fresh APKs have the
same DEX and eleven other native payloads, with exact matching plugin symbols.
Host actual-function, protected-page origin and build checks passed. All three
final Android wire gates proved 512 independent attempts, 256 ALLOW / 256 DROP,
peer 256 and clean stop; packed additionally proved a rejected middle ID whose
later messages still ran. Native submission success remains distinct from
callback success. [Complete implementation, diagnosis and comparison](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#三种同窗口-verdict-发送器的对照--2026-10-12).

| Dense CPU/Q contrast, all three rounds retained | Geometric mean change | t(2) 95% interval | All guards |
| --- | ---: | --- | --- |
| sendmmsg / scalar | −2.07% | [−7.74%, +3.95%] | Fail |
| packed / scalar | −10.91% | [−15.62%, −5.94%] | Fail |
| packed / sendmmsg | −9.03% | [−9.52%, −8.54%] | Fail |

Packed averaged 7.182 messages/datagram and reduced normalized datagram count
86.08% against either single-message datagram sender. Sendmmsg averaged 7.357
messages/call but still used one datagram per verdict. The packed CPU signal
is promising within this short campaign, but packed/scalar p99 ratios were
1.285 / 1.324 / 1.474, all above the frozen 1.25 guard. Some dense windows also
had direct ingress bypass. No contrast passed all three rounds. The single
light sendmmsg window lacked a stable initial kernel/native snapshot and stays
unqualified; it was not replaced. Both experimental switches remain default OFF.
[All window checks, ratios and raw evidence](../../build-output/root-verdict-datagram-20261012/summary.json).

All twelve exact-APK flamegraphs are retained. Dense period-weighted kernel
shares were 76.41% / 75.48% / 73.52% for scalar/sendmmsg/packed. Visible Netlink
work excluding NFQ callback was 9.77% / 8.36% / 4.59%, and verdict syscall work
excluding visible Netlink was 3.80% / 2.82% / 0.78%. Reinjection and subsequent
network-stack work remained 46.15% / 45.67% / 44.96%. These stack partitions
are not intrinsic cost measurements or achievable speedup estimates; CPU-clock
does not explain p99 or off-CPU waits. [Comparison and flamegraph browser](../../build-output/root-verdict-datagram-20261012/comparison.html),
[reproducible visible-stack attribution](../../build-output/root-verdict-datagram-20261012/stack-attribution.json).

Preflight failures, invalid trace setup, delayed peer reception and a split-owner
wire fixture remain archived. The final diagnostic CLI permits zero under the
existing barrier at any time, preserving ordinals and in-flight trace flags;
the independent exact-count wire probe uses two destination ports separated
by two, while the performance helper and load stay unchanged. Healthy boundary
checks catch hidden unicast FAIL_OPEN gaps when native counters are stable;
they do not cover queue-full FAIL_OPEN before packet-ID assignment.

The device was restored to the previous baseline-v4 OFF APK, UID 12632 and
retained Root grant. Original empty configuration semantics were restored through
the normal API at saved=active=940, and generation 1949 stopped with no native
debt, hooks, queues or VPP process. The owned benchmark peer was stopped and
verified absent. [Restoration](../../build-output/root-verdict-datagram-20261012/final-restoration/result.json),
[final evidence proof](../../build-output/root-verdict-datagram-20261012/final-proof.json).

The next useful investigation is direct ingress bypass and p99/off-CPU timing;
default adoption still requires a fresh frozen comparison passing the complete
guards. This campaign adds no retries, larger resources or relaxed thresholds.

A follow-up read of the retained records found bypass in all three senders, with
parsed capture minus graph submission exactly matching direct ingress accepts;
normal-buffer reserve accepts and identity loss were zero. The remaining cause
range is completion-slot reservation or graph submission, rather than a packed-only
finding. Reservation indexes by `packet_id % 64` and refuses an active slot, so
old/new ID collisions are a concrete diagnostic candidate, not a proven per-packet
cause. The measured p99 is UDP probe round-trip latency through Wi-Fi and the peer;
the current CPU-only records cannot locate its waits. [Cause scope and measurement definition](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#p99-和入口旁路的已知原因范围).

An isolated probe of the actual reserve function reproduced rejection of ID 65
with only ID 1 still active and 63 slots free, while ID 66 could reserve normally.
This proves the ID-modulo collision mechanism for a valid out-of-order completion
pattern, but not the cause of all seventeen Pixel events. The actual probe-wait
helper woke promptly for a readable descriptor, ruling out an unconditional
pacing-deadline wait in that helper. [Retained host probe and limits](../../build-output/root-verdict-followup-20261012/result.json).

The candidate combination is whole-path VPP batch plus the packed sender.
Sendmmsg and packed are alternative senders at the same boundary. One already
packed same-lane/flags window needs one syscall; wrapping its one datagram in
sendmmsg adds no further syscall reduction. Keep the sendmmsg arm for comparison;
investigate latency and the reservation mechanism without discarding the measured
CPU and datagram reductions. Defaults and device installation remain unchanged.

## Earlier eight-window sendmmsg result

The whole-path graph batch and independent-message `sendmmsg` candidates remain
default OFF. The fixed eight-window sendmmsg comparison used Product source
`cff2dc6a2615add43f68a57791bc6324fa88b6d3d774aa4a4933eebcbeae4a71`, with graph
batch ON in both arms. Dense windows averaged 7.114 verdicts/syscall, reducing
normalized verdict syscalls 85.94%. CPU/Q was descriptively 3.29% lower, but its
interval crossed 1 and the strict zero-bypass and first-pair p99 guards failed.
No stable whole-path benefit or default adoption was established. The device
was restored to the prior baseline APK, original empty rule semantics and a
stopped runtime. [Full experiment and cleanup](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#root-独立-verdict-的-sendmmsg-尝试--2026-10-12).

## CPU attribution correction

The width of a verdict callback includes the kernel work performed after the
packet is accepted. It cannot be called intrinsic NFQUEUE overhead. Retained
dense B samples place 42.31% of sampled VPP process CPU in the `nf_reinject`
subchain, including IP output and Wi-Fi transmission. The Wi-Fi driver chain
is 18.60%; `queue_work_on` self time is 13.66%. These overlap and must not be
summed. A visible NFQ callback without visible reinjection accounts for 1.39%,
while Netlink without the visible NFQ callback accounts for 10.72%.
[Reproducible six-window attribution](../../build-output/root-verdict-datagram-research-20261012/stack-attribution.json).

The records sample only VPP process CPU. They exclude application-side enqueue
and later driver workers, do not measure off-CPU waits, and do not establish
lock contention or the cause of p99 variation. Stack partitions are evidence
for where to investigate, not exact intrinsic costs or predicted savings.

## Datagram mechanism and retained research

Submit the current bounded window's independent `NFQNL_MSG_VERDICT` messages in
one Netlink datagram. Keep each packet ID, ALLOW/DROP, immutable queue generation,
origin lane and one physical attempt. Group only already-ready work with the
same lane and syscall flags; retain the 16-item origin window and existing
prepare/finish/pool-return lifecycle. No new credits, packet queue, payload copy,
future-packet wait, retries or ACK-wait ledger are part of this candidate.
[Primary-source research](../reviews/2026-10-12_ROOT_NETLINK_VERDICT_DATAGRAM_RESEARCH.md).

The current request array already contains contiguous 32-byte records. A direct
`sendto` of at most 512 bytes is the smallest candidate: each child `nlmsg_len`
remains 32, while the syscall length is their aligned aggregate. Check actual
record stride and `NLMSG_ALIGN(nlmsg_len)` rather than relying on today's layout.
Do not pass the first child to the existing one-message send helper, which uses
only its individual length. A 16-iovec `sendmsg` is unnecessary here and can
add kernel iovec-import allocation above the eight-entry inline threshold. The
[extracted Product-layout compile probe](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-verdict-layout.c)
confirmed 32-byte stride and 512-byte aggregate on the host; this is not Android
artifact identity or NFQUEUE wire evidence.

This candidate can amortize datagram allocation/copy-call, Netlink lookup and
accounting, and receiver capability checks. NFNL attribute parsing, NFQ lookup,
queue dequeue and reinjection remain per message. The matched Android SELinux
Netlink hook also scans the child messages individually. There is no evidence
that the full verdict or Wi-Fi cost can be removed by packing.

## Result and failure boundary

The current accepted contract derives Adapter Completion `SUCCEEDED` from the
successful native terminal-operation return. It does not establish every kernel
verdict callback or network delivery. Netlink permits requested success ACKs
and sends per-message errors; the Product's normal path does not request or wait
for success ACKs. A full datagram byte return can coexist with callback errors
or a malformed child stopping later parsing. This is a shared limitation of
the scalar/sendmmsg native-return baseline and the candidate, not evidence for
downgrading every ordinary no-ACK completion to `OUTCOME_UNKNOWN`.
[Accepted ownership contract and scope clarification](../decisions/PER_WORKER_FLOW_OWNERSHIP.md).

At research time, the receive path did not classify `NLMSG_ERROR` as a verdict-control
reply. The implementation above now recognizes pure control envelopes and keeps bounded
lane-local error counts and first/last diagnostics rather than misclassifying
them as packets with missing identity. This neither waits for ACK nor retroactively
changes an already-returned native submission outcome. No-error-reply observation
alone cannot prove callback success because reply allocation or delivery can fail.

For the inspected kernel-directed contiguous `sendto` path, known pre-dispatch
rejection applies to the entire submitted group. An unexpected short nonnegative
return has no reliable per-ID prefix and is unknown for the group; never resend
the datagram or any possibly submitted ID. The `sendmmsg` positive-count prefix
and untouched-tail loop must not be reused for a single datagram. Pool returns
and debts remain per original obligation regardless of submission outcome.

## Qualification boundary

Two isolated host-kernel probes passed without configuring queues or hooks:
[NETLINK_ROUTE](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-netlink-probe.json)
returned independent success/error/success results for three requests in one
96-byte datagram; [NETLINK_NETFILTER with no CAP_NET_ADMIN](../../build-output/root-verdict-datagram-research-20261012/probes/sakamoto-packed-nfnetlink-denial-probe.json)
returned all 96 bytes while emitting one first-message `EPERM` reply and executing
no verdict callback. The latter demonstrates the submission/processing distinction,
not normal authorized Product verdict behavior. Probe sources and primary-source
snapshots are [retained with SHA-256](../../build-output/root-verdict-datagram-research-20261012/retained-inputs.json).

The research-phase source inspection and unprivileged Netlink probes established
interface feasibility. The later Product wire gates and twelve-window campaign
above provide separate correctness and performance evidence, with failed guards retained.
Before interpreting a new comparison, actual Product code must prove complete
framing, mixed decisions, singleton/full/partial windows, lane/flag separation,
stale/duplicate/replay exclusion, pre-dispatch failure, unknown-return handling,
per-ID pool conservation and normal/draining stop. Wire checks must separately
exercise ALLOW/DROP and a rejected middle ID whose later messages still run.

A measured candidate must use fresh same-source artifacts and exact symbols,
keep graph mode, capacities, policy, workload and profiling equal, and freeze
the comparison before sampling. Include sendmmsg as the direct comparator to
isolate datagram packing; do not compare a new candidate to old saved windows.
Both senders must share the same origin-window prepare/flush/finish wrapper.
At research time, the verdict-batch OFF scalar path sent before origin reclaim
flush. The completed three-sender experiment places scalar in the same wrapper
to keep completion timing equal while changing datagram shape. This does not
retroactively change the historical scalar/sendmmsg campaign or its claims.
Report datagrams per syscall and messages per datagram as separate mechanisms,
with CPU/Q, zero bypass, delivery and p99 guards together. Existing failures
remain recorded and default OFF remains the current result.

The research phase changed no Product backend, hook mode or device installation;
the subsequent authorized attempt is recorded above. Queue-placement balance and shortened queue residence are separate
candidates, not additional changes to fold into the datagram comparison.


## Portable placement, budget and socket-capacity attempt

One APK enabled fixed whole-path+packed for A/P/M/R/K. Producer placement moved
from allowed0..7 to0/3 on this device; M/R/K used two genuinely active symmetric
IPv4 lanes. Read budgets were64 or32, and K requested ordinary SO_RCVBUF327680,
reading back655360 versus the default327680. Maxlen1024, credits and packet pools
were unchanged. New generation-local tuning and counters add88 B/lane,352 B total.
Host actual-callback and real-device mixed ALLOW/DROP/fault prerequisites passed.

Seven fixed dense windows delivered only42.9–81.1% of24000 payload each. Their
successful-probe p99 was713.5–1000.3 ms, with17–60 probes. No measured arm showed
lower CPU/Q than A in the complete first round; those unqualified sequential
figures are not a causal configuration comparison. Three final snapshots raced
and stayed unassessed. The second-round M start then hit product_core_owner_live;
the fixed schedule stopped, without resampling. No three-round interval, idle
comparison or intentional socket-pressure result can be claimed.

Mechanism remains useful: two lanes each captured50%, but A/P/M messages per
callback fell18.00/10.57/7.24 and per packed call10.53/8.11/7.09. Budget32 bound
only one callback; receive ENOBUFS was0. No observed socket pressure establishes
a larger-buffer benefit. Kernel CPU remained67.9–73.6% in the seven exact-APK
on-cpu profiles. Placement greatly reduced generator immediate successors in
verdict-visible preemption, while long RTT tails remained. Neither those stacks
nor residual RTT isolate network/driver cause or justify vendor tuning.

Current defaults remain budget64/socket default and experiment flagsOFF. Keep
whole-path+packed's earlier candidate judgment, and explain this run's delivery/
latency environment and startup ownership evidence before a new frozen comparison.
[All fixed positions, raw failures, profiles and restoration](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#通用-io-配置与预算对照--2026-10-13).


## Match-evidence reuse implementation

The record call now shares one packet projection, policy key and common hash
prefix, computes probe/subject suffixes once each, and reuses the probe key for
last-evaluation and typed association. Work goes3→1 projections,4→1 policy-key
hashes and277→102 hash bytes per Match record. All scalar atomic publications
retain their order; policy key remains the final commit marker. NoMatch hash
bytes, associations, diagnostic fields and zero-marker semantics remain intact.

An independent serialized oracle validates4864 edge/random inputs against the
actual C functions, including record/no-match and publication behavior. ASan/
UBSan and the current policy/settlement regressions pass. Fresh API31 arm64
Release builds with experimentsOFF and batch+packedON show one policy-key call with projection/prefix/suffix inlined, replacing three
single-key calls. The other
2.10% cached-matcher hotspot is unchanged. Only product_packet_graph.c differs
in the1338-file Product closure; no ABI or persistent-memory field is added.

Three pre-registered Host pairs reduce isolated record CPU from216–220 ns to
79–82 ns (geometric ratio0.37010). The final empty-view NoMatch records differ by about0.06–1.77 ns (+1.24%;
descriptive t(2) interval crosses1), after removing an initial9.37% auxiliary-call
regression. All intermediate timing data remain retained. This excludes packet
I/O, lookup, shared-write contention, Android scheduling and network; no new total-device CPU or latency
claim and no device deployment. [Code, raw timings and ARM64 proof](../testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#匹配证据计算复用--2026-10-13).
