# S306 VPN primary handoff diagnosis

Measured 2026-10-22 on Pixel 6a `28201JEGR0XPAJ`. Plane SAKAMOTO-306,
parent SAKAMOTO-293. This record audits the interrupted investigation and adds
two bounded GPT-6.1 measurements. **No Product fix is established.** Product
sources and default capacities are unchanged. ADR-0012 adoption remains the
user’s decision. S292 describes an older local-owner scheduling mechanism and
is not proof for this dedicated-I/O failure.

## Reproduction and identity

The exact [S304 artifacts and workload](2026-10-22_S304_VPN_IO_PERFORMANCE.md)
were rerun: N=2 owners on CPUs1/2, dedicated I/O on CPU3, client on CPU4,
4×16 fixed UDP sockets, 1200-byte payloads, 8000 offered packets/s, burst1,
5-second windows, inner MTU10000 and 2048×10240 native buffers.
The original base25000 tuple workload is retained unchanged.

| Artifact/window | Sent | Peer payload receipts | Credit rejects | Enqueue rejects |
| --- | ---: | ---: | ---: | ---: |
| old A1 | 40000 | 40000 | 0 | 0 |
| new B1 | 39941 | 39637 | 310 | 0 |
| new B2 | 39954 | 39763 | 192 | 0 |
| old A2 | 40000 | 40000 | 0 | 0 |

[Raw reproduction](../../build-output/s306-repro-paced-20261022/campaign.json)
retains manifests, installed/native hashes, actual affinity, before/after CLI,
client and peer results, CPU samples and native stop logs. Old/new APKs are
`b92e51202821d64e2a5571dea02998fcee19eaceaa1370e9348e407964a94a78` and
`6a424ab27181b40772a4298e46d6bf5bf4c19329618e78a3ea35d2139bf32ce1`.
The S306 collector hash is
`c5851e87fd7d4ed22d35ece77c9614e4b8bccdb6700a73dbb93b4bc59341b7f2`;
its layout validation differs from frozen S304. The helper bytes are unchanged.
Reject counters include ordinary background/probe packets; payload loss need
not equal the aggregate reject counter.

An [independent raw-counter audit](../../build-output/s306-model61-evidence-audit-20261022.json)
recomputed the reported rows. Reapplying probe-v2’s retained `source.patch`
reconstructed all three recorded Product source hashes exactly. The restored
plugin hash is `a6634cd5c18a6278026604aa40cf81fecfb409cb4f19c49f56435ba47d6b7635`,
matching S304’s new installed payload. [Initial restored cache proof](../../build-output/s306-model61-restored-cache-20261022/result.json)
and [final restored cache proof](../../build-output/s306-model61-final-restored-cache-20261022/result.json)
show unchanged repeat builds with zero Rust compilations, zero Ninja actions,
unchanged compiled timestamps and identical native payloads. Persistent Product
cache `728fd88e…cb53b6` was reused throughout.

## Hypotheses and measurements

Predictions distinguished four mechanisms before the additional experiments:
(1) unpublished primary batches retain credits, so earlier publication should
reduce rejection; (2) owner work delays service, so publication size alone will
not remove gaps; (3) wake latency, so rejection should concentrate while the
owner sleeps; (4) producer bursts, so rejection can occur shortly after a release.

The original uninstrumented [32/48/48/32 credit perturbation](../../build-output/s306-credit-probe-20261022/campaign.json)
had payload losses159/52/31/233 and credit rejects160/52/31/236; enqueue rejects
were zero. More credit mitigated loss without establishing a fix.

Probe-v1 incorrectly stamped the scalar path while the workload used primary
batch admission. Its hold timing is invalid and retained as a failed instrument
attempt in `s306-probe-20261022` / `s306-timing-20261022`.
The [corrected v2 source](../../build-output/s306-probe-v2-20261022/source.patch)
stamps immediately before publication and at owner policy receipt, using bounded
arrays and zero per-packet log output. [All four v2 windows](../../build-output/s306-timing-v2-20261022/campaign.json)
had zero stamp misses and enqueue rejects. The 32-credit losses were86/250;
48-credit losses0/35. Owner0 publication-to-receipt mean was108–127µs, maximum
4.68–15.13ms. This includes queue/wake/service delay, not just policy execution.
Credit pools reached their configured limit. Most sampled rejects followed a
callback with at least8 captures within1ms. Some clusters followed6–14ms without
release; another 48-credit cluster rejected within0.19ms of a release. Bursts and
active owner service can therefore coexist with capacity exhaustion.

The separate [off-CPU overlap](../../build-output/s306-offcpu-20261022/reject-overlap.json)
contains59218 records with no reported kernel/userspace loss. Of73 owner0 rejects
inside the exact load interval,13 overlap epoll sleep,3 preempted work,57 are
on-CPU or unrecorded. Owner0 slept in epoll for~0.862s and had~0.090s preempted
work. This weakens a pure missed-wakeup explanation; it does not prove every
on-CPU interval was useful service. The instrumented on-CPU profile has1265
samples and cannot identify the clean old/new CPU delta by itself.

A TUN callback budget64→16 candidate failed: losses70/319, rejects75/319,
enqueue0; owner0 hold mean147–152µs, max20.1ms. It removed callbacks of32+
captures but not the failure. The source was restored.

The additional [primary publication threshold8 experiment](../../build-output/s306-publish8-paced-model61-20261022/campaign.json)
changes only the batch flush threshold from `min(16, credits)` to `min(8, credits)`
on the exact v2 probe, retaining32 credits and TUN budget64. Losses191/132,
credit rejects191/143, enqueue0, stamp misses0; owner0 hold means134/122µs,
maxima6.61/11.19ms. This negative candidate does not establish a useful
publication-only fix. Its [patch, source hashes and APK](../../build-output/s306-publish8-model61-20261022/)
remain frozen; [warm cache proof](../../build-output/s306-publish8-model61-20261022/cache-proof/result.json)
passed. No probe or candidate remains in Product source.

## Canonical owner pressure discriminator

The original64 payload tuples do not evenly use the two owners: **59/5 flows**.
The actual Product `product_owner_assign` was compiled directly with a small
retained [C harness](../../build-output/s306-owner-reconstruction-model61-20261022/owner_assignment.c),
using the graph seed `0x6f776e65722d3137`, packet endpoints10.111.0.2 and
192.168.4.5, source25000+i and destination41723+i. Its [source-bound result](../../build-output/s306-owner-reconstruction-model61-20261022/result.json)
checks all64 complete canonical hashes and owners against raw `flow.entry`
rows in both windows of each cohort. Every hash and owner matched.

FNV’s odd multiplier preserves low-bit parity. Incrementing both ports together
cancels their low-bit alternation until the high-byte crossings differ. Direct
`hash % 2` therefore places59 flows on owner0. This explains the observed owner
pressure; it does not authorize changing canonical hashing or changing S304’s
reference workload.

A new workload changes **only source-port base25000→25056**, on the exact
unmodified v2 probe APK and32 credits. This changes the expected split to27/37.
[Raw alternate campaign](../../build-output/s306-port25056-paced-model61-20261022/campaign.json):

| Cohort/window | Flow split owner0/1 | Actual original payload packets owner0/1 | Payload loss | Credit rejects |
| --- | --- | --- | ---: | ---: |
| original v2 B32-1 | 59/5 | 36730/3145 | 86 | 89 |
| original v2 B32-2 | 59/5 | 36504/3176 | 250 | 251 |
| base25056 B32-1 | 27/37 | 16862/23083 | 31 | 28 |
| base25056 B32-2 | 27/37 | 16872/23102 | 15 | 23 |

Alternate windows still exhaust credit and lose packets. Two sequential windows
per cohort do not establish a general improvement or performance threshold.
Original payload packets above are owner FlowEntry `orig_packets` for the exact64
payload tuples, excluding the four probes and background traffic. Their sum
matches peer payload receipts. This is evidence that uneven owner service load
is material, while input/service variability remains.

## CPU limits and next discriminating experiment

Unprofiled original artifact windows over~5.62s of thread CPU accounting showed
old owner0~3.84–3.90s and owner1~0.51–0.53s; new owner0~3.38–3.41s,
owner1~0.47–0.50s and I/O~1.67s. The new thread accounts for most additional
aggregate CPU, while owner0 is somewhat cheaper. The two APKs have other code
differences: these measurements do not assign every extra CPU cycle to handoff.

The user clarified that the separate TUN and owner threads make handoff mandatory.
The next investigation is bounded buffer/configuration tuning, keeping the
handoff, topology and canonical owner fixed. Preserve the original skewed
base25000 workload as the required baseline; base25056 is sensitivity only.
No arbitrary adoption threshold has been selected.

Current knobs and constraints for the next matrix:

| Setting | Actual current value / mechanism | Bounds and coupling |
| --- | --- | --- |
| Primary credits | VPN32 per owner; manifest `primary_handoff_credits` accepts32/48 | Runtime `product capacity credits N primary-slots N completion-slots N` permits credits0..48, primary slots2/64, completion slots2/128; only active graph with all debts and rings empty, protected by CLI barrier. Zero is a fault test, not a tuning default. |
| Primary native ring |64 frame elements per target | Elements contain vectors, not individual packet credits. Diagnostic resizing retains the original full native allocation; smaller logical slots do not prove memory savings. Enlarging needs reviewed native allocation and credit bounds. |
| Completion ring |128 frame elements per target | Existing diagnostic2-slot arm tests congestion; native retained retry stays bounded. |
| TUN outstanding capture |128 obligations | Original buffer index/token stays live until settlement. Raising this alone cannot increase owner primary credits. |
| TUN read callback budget |64; source `TUN_CAPTURE_BUDGET` |16 already failed to remove loss; budget must allow completion writes and stop progress. |
| Primary execution/publication batch |`PRODUCT_PACKET_BATCH_SIZE=16`, flush at `min(16, credits)` |8 candidate failed; metadata/failed arrays use this constant although index arrays are64. It is an execution window, not extra capacity. |
| Policy/prepare batch |16/4 |Changing shared batch constants can affect Root; isolate the parameter and test actual call seam. |
| Completion execution batch |append/flush16; retry budget64 |`PRODUCT_COMPLETION_BATCH_SIZE=64` allocates arrays and limits retry; append currently compares `PRODUCT_PACKET_BATCH_SIZE=16`. Do not mistake array size for normal publication size. |
| Return capacity and stamp ledger |128 per return worker,128 stamp slots |Static equality in TUN adapter; stamp size must be power of two. Preserve per-owner allowances and complete startup allocation. |
| Completion retained backlog |8192 indexes per VPP thread |Static coverage must exceed capture + all owner return allowances +3×injection capacity, and separately Root lane carriers. Preserve both inequalities and exactly-once settlement. |
| Native pool |2048 buffers ×10240 data bytes, ordinary pages |Fixed workload pool; increasing queue capacity increases potential live buffers/RSS and may merely move rejection downstream. |
| Capture submission batching |`SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT=OFF` |ON changes TUN submission and TCP-related paths together; it is not an isolated primary-publication knob. |

Start with an uninstrumented same-source32/48/48/32 credit arm on the original
fixture, collecting CPU per delivered packet, actual per-thread CPU, endpoint
loss, probe sample count/timeouts/histogram, queue peak/hold time, read pauses,
return faults, RSS/native buffers and stop debt. Existing32/48 data shows the
tradeoff but lacks a complete memory/latency decision surface. Extend supported
bounded configuration only where the next matrix requires it, validating all
coupled capacities before admission. Then vary one capture/publication/completion
budget at a time around the selected credit arm with fixed ring/pool sizes.
Use separate profiled windows for mechanism attribution and unprofiled A/B/B/A
for cost. Retain failures and repeat original functional Root/VPN gates before
claiming a supported Product tuning change. If counters remain ambiguous, bounded
publication/dequeue/policy timestamps can distinguish queue delay from owner
service without removing handoff or changing ownership.

Native ring allocation additionally requires a power-of-two element count and
`frame_queue_nelts >= 8 + (1 + tm->n_threads)` in pinned VPP `threads.c`.
The2-slot diagnostic is applied to a previously allocated empty ring and is
not a legal2-slot native allocation. Do not infer that `FRAME_QUEUE_MAX_NELTS=64`
is a proved arbitrary tuning upper bound; audit allocation arithmetic and the
actual worker count before extending supported configuration.

## Cleanup and verification

Final Product source equals HEAD `e83b56b4b34c8d6af3f1a5ec69839f3fd4cc0bec`.
The [restoration evidence](../../build-output/s306-device-restoration-model61-20261022/)
verifies original APK `cc329acc…9a1110`, original saved Wi-Fi `CU_7WFb_5G`
(address192.168.1.104), stopped runtime and no VPP PID. Earlier campaigns restored
S300-A (`4db6…bc72`); the final restore explicitly corrected this to the original
S300-G from the initial prepared manifest. All failed candidates, raw results,
source patches, symbols and APKs remain in their named evidence directories.
Functional Root/VPN regression is required for an actual Product fix; this
investigation leaves Product unchanged and makes no new functional claim.

Independent GPT-6.1 Standards/Spec review corrected the old measured APK identity,
made every runner credit arm explicit despite inherited prepared settings, and
added stopped-state recovery before restoration after collector failure. Historical
runner bytes are retained in [source snapshots](../../build-output/s306-source-snapshots/);
measurement manifests retain their original hashes.

Publication8 matching unstripped symbols were reconstructed from its frozen
patch and verified against byte-identical staged plugin payload; see
[symbol reconstruction](../../build-output/s306-publish8-model61-20261022/symbol-reconstruction.json).
The [last restored cache proof](../../build-output/s306-model61-symbols-final-restored-cache-20261022/result.json)
again verifies the baseline plugin and zero-build unchanged repeat. Python
compilation, staged whitespace checks, and mocked full-runner tests for inherited
credits and failed-collector restoration passed. Both review axes confirmed
their corrections with no remaining findings.
