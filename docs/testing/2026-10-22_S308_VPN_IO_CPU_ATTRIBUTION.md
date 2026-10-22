# S308 dedicated VPN I/O CPU attribution

This records attribution checkpoint `c3e22eae`. The user subsequently selected
packet-path topology lookup removal,48 default VPN primary packet credits and
ready-capture submission batches64 (callback budget64, independent of the TCP
experiment), plus native return graph/completion frame batching with individual
nonblocking writes and settlement. The user then unified primary publication,
normal completion, existing retry and origin/I/O consumption/reclamation at64,
retaining per-owner primary credits48 and native return frames256.
That later [implementation/qualification](2026-10-22_S308_ADOPTED_UNIFIED_WINDOWS.md) is separate from the unchanged
measurements below. The selection does not turn these results into a CPU win.
The subsequent [single/four-flow download study](2026-10-22_S308_TCP_DOWNLOAD_CPU.md) has its own frozen protocol, measurements and CPU/flame coverage.

2026-10-22, Pixel 6a `28201JEGR0XPAJ`, Plane SAKAMOTO-308 under S293.
**Removing measured packet-path environment parsing did not establish a
whole-path CPU improvement. The candidate was frozen and Product source restored.**
This commit adds profiling/verification tools and evidence; it adopts no Product
optimization, capacity setting or ADR-0012 performance decision. S293 remains open.

## Scope and experiment

The [S306 diagnosis](2026-10-22_S306_VPN_HANDOFF_DIAGNOSIS.md),
[S307 tuning](2026-10-22_S307_VPN_HANDOFF_TUNING.md) and S307 final handoff were
read before this investigation. Its original tuple remains primary: 4×16 UDP
sockets, source25000+i/destination41723+i, 1200-byte payloads, burst1, five-second
windows, canonical59/5 owner skew. N2 uses main CPU0, owners1/2, dedicated TUN
I/O3 and client4. Scalar capture1 and32 primary credits are explicit in every
new window. MTU10000/MSS9940, ordinary-page2048×10240 pool,32KiB TCP buffers and
all other experiment settings remain fixed. TCP windows last20 seconds.
S307's48-credit headroom alternative remains separate evidence; it was not
rescanned or declared a CPU improvement here.

The ranked falsifiable hypotheses were: read/readiness dominates I/O CPU;
buffer/parse/selector/admission dominates; completion/write/free dominates;
or fixed dispatch accounts for much of the low-rate cost. Exact CPU-clock
stacks, rather than publication counts, discriminate them. No idle baseline
was subtracted. No cross-callback holding, timer, persistent queue, polling,
extra packet copy, owner rerouting or lifecycle change was introduced.

The first attempt, `build-output/s308-profile-20261022/`, stopped at preflight
with `ConnectionRefusedError` from the prepared Host endpoint. It ran no load
and changed no APK. The retry used campaign-owned Host peer PID4165074; its
command and final SIGTERM/gone proof are retained. The Pixel was selected onto
saved `Openwrt_5G` through fresh Wi-Fi UI bounds without retrieving credentials.

## Exact artifacts and symbols

| Artifact | APK SHA-256 | Plugin SHA-256 |
| --- | --- | --- |
| Frozen S307 scalar control | `0c5764c9204b830c3b32c0a3a059ab2cf408105910124fc72f590e2b90110c35` | `99858b739d84aab6e462ccb328babf98032b95d669cf9e262bfe16992dca877d` |
| Rejected topology-snapshot candidate | `ec5f81c76c8a0d1758291f294b70470cbfc3d314c406535ea798aa45efd0fd71` | `c2917054585b0582a1b9b75e3606b3f0a4f79c8fb2592727f0249cbb8b6cfe8c` |

The candidate is frozen in `build-output/s308-topology-snapshot-20261022/`,
including `candidate-and-test.patch`, actual seam tests, source snapshot,
APKs, native stages and matching unstripped plugin. Its production graph SHA-256
is `d8269ff56b4ddaf3eb457511fcaaf7187eef16f6f26fd70c1911cb71cbf32977`;
the patch SHA-256 is `f8dc3e083d7bc8543d46450f3beab24c192d4318265bf3f23aee7a3dfdcc8ede`.
The candidate was not retained in Product or its Host tests.

`build-output/s308-symbols-20261022/identity.json` verifies stripping the supplied
unstripped plugin/VPP libraries reproduces the frozen APK payload bytes. Pinned
VPP symbols come from the existing Android VPP cache `08ffa19d…a9aaedc`.
Exact device libc, linker and netd ELF files are retained. The
`record-build-id-verification.json` audit checks72 recorded DSO identities
across six profiles: every supplied userspace ELF matches the recorded build ID,
with only simpleperf's documented fixed-width zero padding accommodated.
Kernel/module/vDSO identities and symbols come from the device record; these
were not independently rebuilt or source-line verified.

Control plugin build ID is `fad3f883599b592801bc352d64da3f4a759d2c1f`,
VPP `libvlib` is `4acf27fe74dfd190a38aeea3c9821f0b73678161`, and libc is
`8dc8afb9a8c98d2a9ecf47561e4816e1`. Installed APK/native hashes, affinity,
generation, exact policy hash and raw stop ledgers are independently recomputed
by [s308_summary.py](../../tests/benchmark/s308_summary.py).

## CPU attribution, coverage and probe limits

[s308_profile.py](../../tests/benchmark/s308_profile.py) filters each record to
the exact client monotonic interval and VPP PID. It uses `cpu-clock` at199Hz;
recorded periods approximate sampled CPU nanoseconds. Exclusive phases use the
nearest exact symbol anchor, keep mixed callbacks unknown and retain every
observed chain. Inclusive rows overlap and cannot be summed. Kernel leaf groups
use exact syscall ancestry and keep unmatched kernel work separate. A symbol
resolving successfully does not prove a complete call chain or full phase coverage.

All six records report zero lost samples/records and zero reported truncated
stacks. All observed leaf symbols resolve. FP still has unresolved caller frames
in331/763 heavy-owner and17/115 light-owner samples; its I/O chains have none.
DWARF has no unresolved frames in these windows. Observed depths and leaf-only
counts are retained; absence of an unresolved symbol is not an unwind proof.

| UDP I/O profile | Samples; period sum CPU s | `getenv` CPU s; share | Kernel leaf share | Assigned phase share |
| --- | --- | --- | --- | --- |
| Control FP |362;1.819|0.266;14.6%|50.3%|52.8%|
| Control DWARF |360;1.809|0.332;18.3%|41.7%|69.2%|
| Candidate DWARF |342;1.719|0;0%|55.8%|71.3%|

FP's I/O first/last samples occur at0.014/4.720s within a5.003s workload;
control DWARF at0.017/4.622s within5.001s. These are observed spans, not a proof
of continuous temporal coverage. The corresponding `/proc` monitor covers
4.411/4.414s and reports1.95/1.97 I/O CPU seconds. Whole-process sampled CPU
is6.07/6.11s; the full-window extrapolations are retained separately. Period sums
and scheduler accounting have different boundaries and must not be equated.
TCP's owner0/owner1/I/O period sums are11.653/11.784/11.171s, versus `/proc`
11.24/11.36/10.47s over19.361s; last worker samples occur near19.775s of20s.

The control FP profile was bracketed by unprofiled controls at150.91/150.72
CPU s/GiB; FP measured154.30, about2.2–2.4% higher. Subsequent DWARF/off-CPU
arms measured155.23/154.42. This is descriptive probe perturbation with time
drift, not a correction factor to subtract. Candidate DWARF UDP measured150.44
versus its unprofiled143.64/145.19 arms; those were separate windows and do not
isolate probe overhead. TCP DWARF measured32.65/32.64 for control/candidate.
Every profiled row is excluded from optimization cost comparisons.

The separate scheduler trace contains63252 records with no reported loss.
Observed I/O off-CPU intervals total2.985s:2.967s in file-poll/epoll stacks,
0.006s preempted work and0.012s other. Owner0 has0.981s off-CPU, including
0.854s file poll and0.097s preemption. These are clipped retained intervals;
terminal intervals may be missing. They are not CPU costs or complete wait
accounting. See `s308-analysis-20261022/udp-waits.json`.

## Attributed candidate and negative result

Both FP and DWARF expose `getenv` beneath external submission; DWARF additionally
names `product_runtime_topology_current`. The production origin helper reparses
startup owner/I/O settings for each submitted packet. TCP also exposes this path
on the owners: control `getenv` leaf periods are0.598/0.698/0.302s for
owner0/owner1/I/O, or5.1/5.9/2.7% of their sampled CPU.

The candidate uses the already validated graph-generation `owner_count` and
`adapter_kind` for origin/return checks. Startup still validates the environment
and actual topology. Actual production startup, stop and submission functions
were tested in scalar and batch compile modes: invalid topology, live debt,
N1 Root→N3 VPN restart, stale generation/kind, owner returns, I/O rejection,
original buffer metadata and exactly-once conservation. The new test failed
before the fix on packet-path environment lookup; successful tests and the
discarded patch are retained with the candidate.

Candidate profiles have no `getenv` in any retained worker chain. UDP admission/
publication sampled CPU decreases0.608→0.281s, but read/readiness increases
0.201→0.452s and dispatch0.231→0.271s; unknown phases remain0.558/0.492s.
These short independent profiles do not establish that removed lookup periods
become whole-path savings. TCP owner0/owner1/I/O sums remain
11.754/11.779/11.191s. Its attributed completion/write/free phase is8.171/8.513s
for control/candidate. The mechanism was removed without a measured cost win.

Unprofiled control/candidate/candidate/control,32 credits and scalar1:

| Workload | Control CPU s/GiB | Candidate CPU s/GiB | Control Mbps; loss | Candidate Mbps; loss |
| --- | --- | --- | --- | --- |
| Original8kpps |144.35/144.65|143.64/145.19|76.34/76.11;201/237|76.11/76.53;223/14|
|16kpps |88.17/90.70|89.58/89.29|147.81/151.82;2314/579|151.86/151.61;619/705|
| TCP |33.31/32.40|32.96/33.18|448.92/463.11;not UDP loss|444.33/445.62;not UDP loss|

Original8kpps CPU µs per delivered payload packet is161.33/161.66 for controls
and160.53/162.27 for candidates. All three comparisons overlap. The16kpps first
control also misses638 offered pacing slots and sends79362 packets; its2314
endpoint losses exceed1437 primary rejections. Other16kpps arms miss239/283/269
slots and send79761/79717/79731 packets. Counters include probes/background
traffic; endpoint loss is not assigned wholly to credit rejection.

TCP successful probes/timeouts are1071/0,1056/0,943/1,236/4 in execution order;
p99 upper bounds are299.1/290.1/309.2/345.7ms on successes only. UDP probe
attempts, successes, timeouts, deadline cancellations and errors are checked
against raw denominators. Full per-window metrics, per-thread CPU, CPU sampling
coverage, p99, counters, throughput and RSS remain in
`build-output/s308-analysis-20261022/summary.json`:20 verified windows,
six profiled and14 unprofiled, including the two probe controls.
All native stops settle with zero debt. Enqueue, allocation, write and return
credit/stamp/buffer failures are zero. Capture pauses/resumes total105/105;
they are bounded backpressure observations, not missing events. Observed RSS
ranges124805120–127258624 bytes. Sampled RSS is not an allocation budget or a
proof of unobserved peaks. Temperature/background traffic were not controlled.

## Remaining named mechanisms and design boundary

The following exclusive kernel-leaf ancestry groups are subsets of I/O
CPU-clock periods, not syscall counts or off-CPU intervals:

| I/O sampled CPU s | UDP control/candidate | TCP control/candidate |
| --- | --- | --- |
| Kernel `eventfd_write` publication |0.116/0.116|0.101/0.101|
| Kernel epoll syscall work |0.246/0.221|0.261/0.156|
| Kernel TUN read |0.111/0.126|0.251/0.327|
| Kernel TUN write/return |0.010/0.035|7.377/7.608|
| Other kernel ancestry |0.241/0.427|1.226/1.236|

TCP TUN-write kernel work is66.0/68.0% of I/O sampled periods. Observed leaves
include `_raw_spin_unlock_irqrestore`1.261/1.256s, `ipt_do_table`1.211/1.146s,
`do_csum`0.342/0.327s and `__arch_copy_from_user`0.261/0.307s; full exact
callers are retained. These are Android kernel packet-injection costs observed
under TUN write, not proof that each cost is inherent to every implementation.

UDP DWARF control/candidate CLI deltas show40820/40871 scalar captures and admit
frames,40735/40739 primary publication calls,35591/33838 owner completion
publications for41552/41614 completion vectors, and34709/32846 origin frames
for41637/41746 vectors. TCP has178914/184317 scalar capture calls,
178842/184221 primary publications,99492/100432 completion publications for
385905/397892 vectors and44083/42006 origin frames for385977/397988 vectors.
CLI brackets include work around the client interval and are not exact CPU
profile denominators. Capture callback counts are37884/36877 UDP and32212/31916
TCP. Allocation attempts include the final nonblocking empty read. Publication
counts do not establish eventfd write counts; the existing latch coalesces wakes.
Accumulated callback nanoseconds are wall time and are not used as CPU attribution.

The next concrete design question is which cost should be targeted: UDP's
readiness/publication/dispatch cycle, or TCP's return TUN-write kernel path.
An eventfd-only change cannot be assumed to reclaim the large TCP write subset.
Holding captures across callbacks to combine UDP work would require an explicit
bounded residence/latency, capacity, wake/timer and stop-settlement design.
That decision is not made here. No result establishes that all remaining cost
is unavoidable or that a timed accumulation design will improve CPU.

## Verification, restoration and retention

The candidate's full Host suite passed68/68 with exact
`PRODUCT_ARTIFACT_DIR=build-output/s308-host-cache-20261022/product-vpp-host-first`
under local-socket access. Both Android runtime contract suites passed. The
initial sandbox run was65/68: two socket-denial setup failures and a leaked
`VPP_HOST_STAGE_DIR` affecting a negative contract. Its log is retained alongside
the corrected68/68 run. This is candidate Host evidence, not Android functional
qualification. Because the candidate was rejected and Product source restored,
no new N1/N3 Root/VPN fault qualification is claimed or inferred from it.

Persistent Android/Host compilation caches were reused. Candidate first builds
had0 Rust/2 Ninja actions; unchanged repeats had0/0, identical compiled hashes/
timestamps and native payload. After source restoration the normal Android
builder reproduced control plugin`99858b…a877d`; its unchanged second build again
had zero Rust/Ninja actions. See `s308-restored-cache-20261022/result.json`.
The explicitly named negative-candidate distribution remains frozen separately.

The [device restoration audit](../../build-output/s308-device-restoration-20261022/result.json)
verifies original APK`cc329acc…9a1110`, exact rules`2b24ea…a450f`, saved Wi-Fi
`CU_7WFb_5G`, stopped runtime, no VPP/NFQUEUE hooks/queues, and no simpleperf or
load helper. Campaign-owned Host peer4165074 is gone after verified SIGTERM.
The first cleanup audit found it still active because a sandbox process view
had hidden its `/proc` entry; the final audit and stop use the same escalated
process namespace. That failed check is retained.

Analyzer boundary/exclusivity tests and campaign profile/default/recovery tests
pass. Every implementation and independent Spec/Standards agent used explicit
`gpt-6.1-sol` with `fork_turns=none`; final review proof is retained in
`build-output/s308-analysis-20261022/reviews.json`.

All raw attempts, profiles, matching ELF symbols, source/tool snapshots, APKs,
cache proofs and failed setup logs remain in the named `build-output/s308-*`
directories. The evidence index is
`build-output/s308-analysis-20261022/evidence-index.json`. These gitignored local
inputs are **not a portable archive supplied by this commit**. Retain or package
their exact identities before transferring this investigation.
