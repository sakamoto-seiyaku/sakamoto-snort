# S307 bounded VPN handoff tuning

2026-10-22, Pixel 6a `28201JEGR0XPAJ`, Plane SAKAMOTO-307 under S293.
The dedicated TUN I/O worker and original-buffer handoff remain mandatory.
**48 credits provide measured loss headroom; no tested setting establishes a
whole-path CPU improvement.** Defaults remain 32 primary credits and scalar
capture submission. The optional bounded capture-submission diagnostic is kept
separate from the TCP/return-output experiments. No adoption threshold is set.

## Scope and identities

All implementation and review agents used GPT-6.1. The original S304 workload
is retained: N=2, main CPU0, owner CPUs1/2, TUN I/O CPU3, client CPU4,
4×16 UDP sockets, source base25000, 1200-byte payload, burst1, five-second
windows. Its canonical hash distributes the 64 payload flows 59/5; it is not
replaced with a balanced tuple. The load ladder offers 4/8/12/16 kpps.
TCP uses 20-second windows and 4×16 sockets, with explicit nonoverlapping
source ranges recorded in each manifest. MTU10000/MSS9940, ordinary-page
2048×10240 buffer pool, 32KiB TCP buffers, Root batch+packed verdicts and all
VPN TCP/UDP/progress/buffer experiments remain fixed.

| Artifact | APK SHA-256 | Native plugin SHA-256 |
| --- | --- | --- |
| Original dedicated-I/O control | `6a424ab27181b40772a4298e46d6bf5bf4c19329618e78a3ea35d2139bf32ce1` | `a6634cd5c18a6278026604aa40cf81fecfb409cb4f19c49f56435ba47d6b7635` |
| Capture callback budget32 only | `40b8b2399b7731033d7e59ca3991651bb32c2a58c3f51dfb5a8cec34c11c8722` | `5580f0a3c69b81bb52018cf5d3d3344c300e2bb366c17428afd8502d5f33984c` |
| Completion normal publication32 only | `dd532244a85d7940ae52f10b62da3aea80b0a5568443cb1957f9988fd4eb19f2` | `1eaccb727325a701621fde617294eec48745982c0aed7d5d13778b135721eb99` |
| Primary publication32 only | `8b58966927cf539d7489470747e93d6f0ee7090ab89d7ac279145d4f06e7dc01` | `cf8c78991e8b878d6684e749ee2cf7ef4d66eef8a0fd026daee5761d17447ce2` |
| Runtime capture-submission diagnostic | `0c5764c9204b830c3b32c0a3a059ab2cf408105910124fc72f590e2b90110c35` | `99858b739d84aab6e462ccb328babf98032b95d669cf9e262bfe16992dca877d` |

Candidate patches, complete Product source hashes, stages, cache proofs and
matching unstripped symbols are retained in
`build-output/s307-{capture32,completion32,primary32,capture-batch-runtime}-20261022/`.
The baseline restored-cache proof is `build-output/s307-restored-cache-20261022/`.
Every unchanged second native build had zero Rust compilations, zero Ninja
actions, identical compiled timestamps and identical native payloads. Builders
reused persistent cache key
`728fd88e885f4558b7e3d6eff6bd1a43a032c1c08d6ebe8b0a72b22701cb53b6`.
Native and APK output directories isolate publication, not dependency builds.
The fixed VPP stage properties bind revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0`,
runtime closure `27a6f7e011faaa9f25df6f5d92f4d2e6bb1646734b694d33728eeec3602463fe`
and core patch closure `ebeb71ace719113198d100ae262ac87a8c8380b2d22a043e2a00bc1cb49c4415`.

## Measurement rules

The [raw verifier](../../tests/benchmark/s307_summary.py) recomputes delivery,
loss, per-thread CPU, RSS, counter deltas, installed APK/native identities,
affinity, generation, stop debt and UDP probe denominators. Its machine output
is [summary.json](../../build-output/s307-summary-20261022/summary.json).
The [campaign runner](../../tests/benchmark/s307_vpn_tuning.py) explicitly sets
each credit/capture arm, retains failed attempts, stops the runtime before
restoring the original APK and records each manifest/tool identity.

CPU samples are restricted to the client traffic interval. Coverage is shorter
than the interval because samples occur approximately every200ms; sampled CPU
seconds and coverage are retained, and CPU/GiB uses the explicitly extrapolated
full-window estimate. RSS is the observed process peak during those samples,
not allocated-capacity accounting, whole-phone memory, energy or a proof of
unobserved transient peaks. Host-peer CPU is not Pixel CPU.

UDP `probe_requests = samples + timeouts + cancelled + probe-send errors` is
checked against raw helper output. P99 uses successful samples only; timeouts
and deadline cancellations are separate. TCP successful latency samples and
aggregate client timeouts are reported separately; the TCP helper does not
expose a separate attempted-probe denominator. Sparse successful samples do not
qualify latency. Primary rejection includes probes/background packets, so it
need not equal payload loss. All windows retain zero-debt native stop audits.

All rows are descriptive device observations. Background traffic and temperature
were not controlled; ABBA reduces time drift without eliminating it. The first
32-credit window lost379 packets versus44 in the final control. Outer-bracket
CPU1 weighted frequency was1710/1705/1719/1719MHz across that sequence; owner0
runqueue wait was173/119/132/119ms. These broader brackets include CLI time and
do not establish the outlier's cause. No row is discarded.

## Original-load credit discriminator

Uninstrumented, same original control APK, order32/48/48/32:

| Credits | Payload loss | CPU s/GiB | Probe p99 upper ms | Successful samples; timeouts |
| --- | ---: | ---: | ---: | --- |
|32 first|379|139.71|149.4|600;0|
|48 first|22|147.39|69.2|878;0|
|48 second|6|146.13|65.4|829;1|
|32 last|44|147.88|68.0|899;0|

Raw: [first credit ABBA](../../build-output/s307-credit-abba-20261022/campaign.json).
The variation within32 is material. These rows suggest headroom and do not
establish a stable CPU/latency improvement.

A separate [timing ABBA](../../build-output/s307-timing-abba-20261022/campaign.json)
reused the exact frozen S306 probe-v2 artifact and source patch. Instrumented
CPU is excluded from cost comparisons. Payload loss was113/0/0/136;
all publication/dequeue stamps matched. Heavy-owner lifetime peak credits
were32/45/46/32. In the48 arms, before-window peaks were13/34, so the measured
windows did raise those maxima. Hold-count/sum/histogram results are
before/after deltas; maxima and occupancy peaks include warmup and are labeled
as lifetime values. This measures publication-to-policy credit hold, not every
pre-publication or owner-service phase. The raw verifier retains all bins and
sample counts; maxima must not be subtracted.

| Heavy owner / credit arm | Window hold samples | Mean hold µs | Window holds≥5ms | Lifetime peak credits |
| --- | ---: | ---: | ---: | ---: |
|32 first|37142|120.01|36|32|
|48 first|37355|90.15|14|45|
|48 second|37365|91.30|0|46|
|32 last|37134|119.70|60|32|

The means and threshold counts use measured-window deltas; the final column
includes warmup. Histogram bins do not establish an exact percentile.

## One-variable batching scans

Each scan used32 credits and the original8kpps fixture, with control/candidate/
candidate/control order. Ring, capture obligations, return capacity and pool
were fixed.

| Isolated setting | Control payload loss | Candidate payload loss | Control CPU s/GiB | Candidate CPU s/GiB |
| --- | --- | --- | --- | --- |
| Capture callback64→32 |51/54|81/69|150.86/150.38|149.99/150.95|
| Normal completion publication16→32 |155/308|254/128|144.42/139.27|138.40/146.65|
| Primary publication16→32 |121/66|61/114|149.13/150.11|149.91/151.11|

Raw campaigns: [capture32](../../build-output/s307-capture32-abba-20261022/campaign.json),
[completion32](../../build-output/s307-completion32-abba-20261022/campaign.json),
[primary32](../../build-output/s307-primary32-abba-20261022/campaign.json).
Primary32 enlarged both metadata and failure arrays to32 while preserving the
64-index/target bounds; policy16, preparation4, completion16 and origin16 were
unchanged. Its actual helper seam passed retained rejection/credit/settlement
checks with ASan/UBSan; LeakSanitizer was disabled because the execution sandbox
uses ptrace. None of these scans demonstrates a cost improvement.

The mechanism discriminator found default scalar TUN submission generates
one-vector admit frames and one primary publication per packet. Raising a
publication cap cannot combine separate one-vector frames. The former
`show product batch` omitted the dedicated I/O thread; it now reports actual
VPP workers, including I/O. Earlier omitted counters are unknown, not zero.

The optional `product tun capture-batch <1..64>` instead batches already-ready
captures within one callback. It carries only original indexes and metadata,
flushes at the selected limit and at every callback exit, and adds no timer,
polling, extra packet copy, owner reroute or persistent packet queue. Configuration
requires an attached, active, empty VPN graph under the CLI worker barrier,
with no origin/buffer/handoff/completion debt. Full-width parsing rejects invalid
values before narrowing. The limit resets each generation; default1 preserves
scalar submission when the existing TCP experiment isOFF. TCP experimentON
retains its prior64 default. No TCP or return-output experiment was enabled here.

| Same artifact capture1/64/64/1 | Scalar controls | Capture64 |
| --- | --- | --- |
|8kpps payload loss|46/91|53/35|
|8kpps CPU s/GiB|149.38/151.83|150.36/150.80|
|TCP delivered Mbps|462.29/448.93|408.35/434.90|
|TCP CPU s/GiB|32.73/33.41|34.68/33.93|
|TCP successful probes; timeouts|907;0 /1031;0|1032;0 /856;2|

Raw [capture UDP](../../build-output/s307-capture-batch-abba-20261022/campaign.json)
and [capture TCP](../../build-output/s307-capture-batch-tcp-abba-20261022/campaign.json).
At8kpps, mean ready batch was only about1.08: I/O publications fell roughly7%
without a CPU/GiB improvement. TCP mean ready batch was about5, cutting I/O
admit frames from182–184k to33–35k. I/O sampled CPU fell from10.95/10.67s to
9.89/10.39s, alongside reduced delivered throughput; owner CPU fell similarly.
Fewer publication calls alone did not improve whole-path CPU per delivered byte.

## Credit load ladder and topology regressions

The same runtime-diagnostic artifact used capture1 throughout. Within each
offered rate, credits were32/48/48/32. The original skewed tuple and all other
capacities stayed fixed.

| Offered kpps |32-credit payload loss|48-credit payload loss|32-credit CPU s/GiB|48-credit CPU s/GiB|
| --- | --- | --- | --- | --- |
|4|42/0|0/0|245.33/241.69|248.19/235.48|
|8|154/63|34/13|145.63/150.39|151.34/149.74|
|12|456/150|130/62|113.36/113.98|113.57/113.42|
|16|611/1109|616/444|91.10/89.14|90.14/88.96|

[Raw ladder](../../build-output/s307-credit-ladder-20261022/campaign.json)
contains offered/sent/received, pacing misses, throughput, probe counts/timeouts,
per-thread CPU and RSS for all16 windows. Enqueue failures remained zero. Credits48
mitigated loss in these8/12kpps pairs and did not remove loss at16kpps. CPU/GiB
ranges overlap; this is headroom evidence, not CPU-cost closure.

Final [TCP and N1/N3 regressions](../../build-output/s307-credit-qualification-20261022/campaign.json)
retain N2 TCP32/48/48/32 plus N1/N3 UDP/TCP at48 credits, capture1. N1 uses
owner CPU1; N3 uses1/2/1; both keep I/O CPU3 and client CPU4.

| Configuration | Throughput Mbps | Payload loss | CPU s/GiB | Successful probes; timeouts |
| --- | ---: | --- | ---: | --- |
|N1 UDP48|76.60|64|142.48|838;3|
|N1 TCP48|460.60|not a UDP measure|22.37|467;5|
|N3 UDP48|76.72|13|178.58|878;0|
|N3 TCP48|395.59|not a UDP measure|32.80|563;2|

N2 TCP throughput was384.32/432.99/444.59/459.32Mbps; CPU/GiB35.92/34.64/33.31/32.48.
The first32 control had only7 successful latency samples and4 aggregate client
timeouts; its p99 is not latency evidence. All rows remain in the raw report.
These topology regressions demonstrate scoped delivery and settled stops, not
loss-free or latency-qualified operation for every topology.

The [counterbalanced TCP48/32/32/48](../../build-output/s307-tcp-counterbalance-restored-rules-20261022/campaign.json)
delivered449.43/448.97/432.20/446.82Mbps, with CPU/GiB33.09/32.62/34.22/33.66.
Successful latency samples were293/289/1011/1024 with aggregate client
timeouts3/4/0/0. Credit rejects were4/168/102/0 and enqueue failures zero.
Its overlapping cost ranges do not establish a CPU win. Together with the
earlier ABBA, this retains both orders and their conditional latency limits.

The [first counterbalance attempt](../../build-output/s307-tcp-counterbalance-20261022/campaign.json)
was rejected before load: Root functional UI operations had changed the saved
rule source to`7523de7fabf9cc9e4a824e886d7283af173434b5184e05ac555a549d8fd57914`.
No measurement row is accepted from it. The recorded pre-Root revision1132 and
rule version allowed exact reconstruction of the prior source, removing the two
new test identity entries; its full SHA-256 matched original
`2b24ea2630d231e9f52f014aa8a64ae1ba593d1f1371389f05c92b97517a450f`.
The [retained before/after bytes and reconstruction](../../build-output/s307-summary-20261022/rule-restoration/reconstruction.json)
bind this restoration. The successful retry therefore uses the exact original
policy source, not a newly declared equivalent policy.

## Capacity and memory audit

The constraints below explain what was held fixed. This is not an exhaustive
parameter search or a proof that handoff CPU cost is unavoidable.

| Knob | Audited bound and decision |
| --- | --- |
| Primary packet credits | Current diagnostic CLI0..48, default32. Zero is a fault setting.48 is the current exposed limit, not a claimed physical maximum. Primary rejection dominated; native enqueue failure was zero. |
| Native primary/completion rings |64/128 elements per target, each element holds vectors, not one packet credit. Increasing rings is not a discriminator for observed credit rejection with enqueue0. Runtime logical2 slots are fault settings retaining full allocations, not memory-saving native allocations. |
| Native allocation constraints | Positive power-of-two element count; pinned source asserts `nelts >=8+(1+tm->n_threads)`. Measured N≤3 satisfies it. `ASSERT` is debug-dependent (`CLIB_ASSERT_ENABLE`, normally `CLIB_DEBUG>0`); source assertions alone do not establish Release high-N rejection or safety. Higher-N capacity is unverified here; no topology limit is changed. |
| Capture obligations |128, fixed. Raising alone cannot raise owner credits. A64-obligation artifact was built but never installed/measured, and makes no performance claim. |
| Capture callback |64 default;32 measured. Runtime submission1..64 uses a64-element callback-local index/metadata array and always flushes before return. It changes publication grouping, not packet capacity. |
| Primary/policy/preparation windows |16/16/4 defaults. Primary32 was isolated with coupled arrays expanded. Uninstrumented primary8 was built but never installed; S306's separately instrumented8 result remains historical, not this scan's cost evidence. |
| Completion | Normal append/flush16; arrays and retry scan64. Completion32 changed only normal publication, not retry64 or origin16. |
| Returns |128 per owner with128 power-of-two stamp slots. Their equality is asserted; no increase was attempted because no return credit/stamp/buffer failure appeared. |
| Retained completion backlog |8192 indexes/thread. Static inequalities separately cover Root carriers and VPN capture + all owner return allowances +3×injection capacity. With61 potential VPN owners:128+61×128+3×64=8128<8192. |
| Native pool |2048 buffers,10240 data bytes, unchanged. No buffer allocation failure in performance windows; increasing it would not directly resolve primary credit rejection. |

Android type sizes were read from matching unstripped candidate symbols;
[type-sizes.json](../../build-output/s307-summary-20261022/type-sizes.json)
binds the input. Queue elements are2176 bytes, queue headers384, VPP buffer
headers256, capture obligations16 and external submission items48. For N2:

- Pool data:20,971,520 bytes; buffer stride allocation:2048×10496=21,495,808 bytes.
  `show physmem` reports5318 ordinary4KiB pages=21,782,528 bytes for its arena.
- Primary+completion element/header storage:4×[(64+128)×2176+2×384]=1,674,240 bytes.
  All four native FQMs, including injection/probe64/64, total2,791,424 bytes before
  allocator/vector overhead. These are capacity calculations, not total process RSS.
- Credits32→48 allocate no new pool/ring bytes. N2 permits at most32 additional
  held native buffers,335,872 stride bytes, within the existing capture/pool bounds.
- Capture submission's64×48=3072-byte callback-local metadata/index array is
  bounded stack storage; the batch helper additionally has a64-byte acceptance mask.
  These are not64 copied packet payloads or an extra persistent packet queue.
- The retained completion queue type is32896 bytes per allocated VPP-thread slot;
  the current static63-slot allocation is2,072,448 bytes. Return stamp storage is
 2056 bytes per provisioned owner slot. Existing per-owner Flow Stack/flow state,
  VPP heaps and library mappings contribute to RSS separately.

Observed RSS remains a sampled footprint; raw JSON exposes each window's value.
Memory limits are reported separately from credit-held allowance and delivery.

## Functional faults, verification and retained limits

The [first functional campaign](../../build-output/s307-functional-20261022/campaign.json)
passed independent N1/N3 real UDP return/stress checks with capture64, including
short-write/EAGAIN result injection, FlowEnd close/expiry, original buffer/index,
one completion/write/free and clean stop. Its following N1 physical completion
pressure attempt did **not** trigger deferral after six64-packet bursts and isHOLD.
The [48-credit discriminator](../../build-output/s307-functional-credit48-20261022/campaign.json)
likewise did not trigger deferral. In the first failure, all392 captures completed
with zero debt; native completion slots2 were active and primary rejects were101.
These are retained unexercised fault attempts, not Product settlement failures
or passing physical congestion tests.

Capture batching combines vectors into fewer completion frames. The subsequent
fixture therefore distinguishes scalar physical ring pressure from an existing,
explicit bounded original-completion hold/release for capture64. The latter
exercises actual retained retry/debt/index settlement and does not claim that
the native ring physically filled. The Host actual production completion seam
independently forces native enqueue failure masks, retry wrap and exactly-once
release. No physical pressure gate was weakened into a pass.

The [split qualification](../../build-output/s307-functional-split-20261022/campaign.json)
passed all seven rows: trace-enabled N1/N3 capture64 held-completion faults,
ordinary Product N1/N3 scalar capture1 physical ring pressure, capture64 stop
with retained originals and pre-staged draining, and Root N1/N3 real NFQUEUE
ALLOW/DROP/recovery/topology/owner-lifecycle checks. Independent verifiers checked
the trace/ordinary/Root rows; both stop rows additionally passed the native
zero-debt owner/graph stop verifier. The two earlier real-return stress rows
and these seven rows together provide the scoped functional evidence. Ordinary
mode and trace-enabled validation are distinct and are not silently combined.
The fixture's `--completion-phase-primary-credits 48` means primary packet
credits used during completion pressure; it is not a separate completion credit
budget. Historical failed-arm JSON used the shorter key `completion_credits`
for the same primary budget.

The actual TUN callback/CLI seam executes all1..64 limits, scalar and full64
batches, partial EAGAIN/allocation exits, mixed rejection settlement, capture128
backpressure and draining. Existing actual external/primary/completion/origin
seams cover metadata publication, unordered native failure results and retry
settlement. The campaign recovery check verifies inherited32/48 overrides, TCP
field isolation and stop-before-original-reinstall after a collector exception.

Full Host CTest passed67/68; the sole failure was setup: the unified-rule
runtime test lacked `PRODUCT_ARTIFACT_DIR`. Its original failure log remains
`build-output/s307-verification-20261022/ctest.log`. Both Android runtime contract
suites passed, as did the VPN collector baseline and campaign recovery checks.
Host artifact and targeted-gate results are recorded separately from that full
suite count.

The current Host artifact warm proof is
[s307-host-cache-fixed](../../build-output/s307-host-cache-fixed-20261022/result.json):
first0 Rust/6 Ninja actions, unchanged repeat0/0 with identical payloads and
compiled timestamps. The targeted unified-rule runtime test then passed1/1 with
that exact artifact and local socket access; its transcript is
`build-output/s307-verification-20261022/targeted-rule-runtime.log`. This does not
rewrite the original full-suite count. An earlier Host artifact publication
failed the builder's required output-name preflight before compilation; its
`build-output/s307-host-cache-20261022/first.log` is retained.

Standards review found two campaign-tool issues: input plan reserialization
could disagree with its recorded byte hash, and an omitted capture setting
could inherit a prepared64 arm. Both were corrected and independently rechecked
with compact-plan identity and inherited-setting regression tests. Omission
explicitly means the artifact's native default, allowing old experimental APKs
that predate the capture CLI. Spec review independently recomputed all52 initial
measurement rows from raw inputs and found no remaining finding at that stage.
The same explicit GPT-6.1 Spec reviewer subsequently independently checked the
four counterbalanced rows, hold table, Host gate, matching symbols and final
restoration, with no findings. The final summary contains56 verified windows.

The final [Pixel restoration audit](../../build-output/s307-device-restoration-20261022/result.json)
verifies original APK`cc329acc…9a1110`, exact original rule source`2b24ea…a450f`,
saved Wi-Fi`CU_7WFb_5G` at192.168.1.104, stopped runtime and no VPP PID,
NFQUEUE queue or hook. Each campaign restored the original APK; the final Wi-Fi
selection used saved-network UI without retrieving credentials. The preexisting
Host peer PID4065319 was left running; newly created functional endpoints were
stopped by their owning collectors.

## Evidence retention and follow-on boundary

The raw campaigns, APKs, matching symbols, patches, helper/tool snapshots and
failed attempts remain in the named local `build-output/` directories. They are
gitignored and are **not** made portable by committing this report and scripts.
Use this workspace or package those exact named inputs before transferring the
investigation. S304's earlier portable archive remains separate evidence.

Current evidence supports retaining32 and48 as scoped credit alternatives, with
48 offering more measured headroom and neither establishing a CPU win. Capture
batching is an optional diagnostic with measured UDP/TCP tradeoffs, not a chosen
new default. The scans do not cover every bounded queue/coalescing design.
Holding packets across callbacks to accumulate a timed batch would require a
separate latency/lifecycle design decision; no such timer or polling was added.
S293's broader acceptance remains open; these measurements do not choose new
Product defaults.
