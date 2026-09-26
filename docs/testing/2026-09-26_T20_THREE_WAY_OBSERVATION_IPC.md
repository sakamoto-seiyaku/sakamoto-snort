# T20 three-way observation IPC comparison

The user explicitly extended [SAKAMOTO-271](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/7d77e5d6-cf66-49f2-ae7b-bec9a12b85ff)
with “20这里要求继续实行 3种 比较补充上”. This report adds an independently
written minimal C SPSC ring plus eventfd and reruns **all three candidates**.
The extension was registered after the [two-way result](2026-09-26_T20_OBSERVATION_IPC.md),
not retrospectively described as part of its original preregistration.

**Recommendation for user review remains Aeron C SPSC.** The minimal ring works
within this tested envelope, but has no clear overall cost/latency advantage
that establishes a reason to own another queue implementation. It saves only
1280 bytes across two shared queues versus Aeron. All three pass the final
corrected-witness matrix. An earlier VPP widened-length miss and an Aeron burst
tail outlier remain important counter-evidence; neither is relabelled as fixed.
T20 remains In Progress; **no direction is selected and T21 remains blocked**.

## Contract and source identities

The [plan extension](../../experiments/t20-observation-ipc/PLAN.md) fixes the new
algorithm, common comparison and additional checks before implementation/run.
The [README](../../experiments/t20-observation-ipc/README.md) gives reproduction.
No old Product C++ or packet POC source was imported, and no Product/APK changed.

| Candidate | Queue / notification |
| --- | --- |
| Aeron | 1.53.2, `664f58e705f850dfb926f6293707b204ba804726`; variable-byte C SPSC subset; notification once per batch containing an admitted record |
| VPP | `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, existing Android profile; three slot classes and native eventfd transitions |
| Minimal | New `minimal_ring.c/.h`; variable-byte SPSC with an 8-byte header and padding at wrap; same successful-batch eventfd path as Aeron |

One independent C producer and one Rust consumer, one thread each, two independent
normal/debug capacities, 262144 data bytes per channel. The primary distribution
remains 128/512/2048 bytes at 70/20/10. Cumulative/attribution/combined-END fields
and deterministic sentinel payload are unchanged. VPP's classes remain
512 × 128, 128 × 512 and 64 × 2048 bytes; it does not borrow another class when
the smallest fitting class is full. Both byte rings use actual aligned lengths.

The common harness includes a pre-poll publication witness, boundary lengths
and EINTR handling in its eventfd helpers. Therefore **none of the old measurements
is used as a current comparator**. Three repetitions rotate order A/V/M, V/M/A,
M/A/V. The original 13 workloads plus boundary and notification-window cases give
135 runs per platform. Complete original evidence has an immutable copy under
`build-output/t20-three-way-20260926/prior-two-way-snapshot/`.

Evidence root: `build-output/t20-three-way-20260926/`.

- Same native source closure on Host and ARM64:
  `11f82153497bc90af1bc2d21bb1b6dbea9ce62225787ac11cb8a6b69c11075cb`.
  This hashes sorted compact JSON of the eight native source/header/test file
  hashes: `ipc.c/.h`, `producer.c`, `consumer.rs`, `query.c`,
  `minimal_ring.c/.h`, `minimal_ring_test.c`.
- Host `host-c/build.json` SHA-256:
  `3b4eff768a4d6175abd21085166512acacb89858ba5c7814c9cae1fc272b0eaa`.
- ARM64 `android-c/build.json` SHA-256:
  `43439ec23c6fdcecfbf422ce49212e6071519b59d0ac5b794a2d896a338e9db1`.
- Builds compile from retained source snapshots, retain compiler/target commands,
  exact dependency hashes and stage/profile metadata, and refuse to overwrite a
  completed build. Final runs: `host-matrix-c/`, `pixel-matrix-c/`.
- Pixel reads back all 12 deployed executable/library/test SHA-256 values before
  execution. The runner records environment and confirms removal of its fresh
  directory and owned processes. Only `dev/adb` is used, serially.

## Minimal queue ordering and correctness

The two shared positions are independent, aligned, lock-free 64-bit C atomics.
No process pointer is stored in the mapping. Capacity is a power of two; unsigned
position differences cover 64-bit wrap while occupancy remains at most capacity.

1. Producer acquire-loads released head space, checks the full record plus any
   padding fits, writes header/payload, then release-stores tail once. A rejected
   write changes no ring byte. There is no allocation, mutex, retry or consumer
   wait in admission.
2. Consumer acquire-loads tail before reading bytes. It validates record bounds,
   invokes callbacks on borrowed bytes and release-stores head only after those
   callbacks finish. Producer cannot reclaim those bytes during a callback.
3. Padding and the following record are published together. Reader work is
   bounded by the requested record limit plus at most one wrap marker. Malformed
   bounds/reserved fields or inconsistent positions fail rather than read outside
   the ring. A dead reader's generation is discarded; no abandoned-borrow repair
   or replay is promised.

This is the ordering argument for the implementation, supported by target tests;
it is not a formal proof for every compiler/platform. The consumer still calls
the C implementation, rather than reproducing its atomics as Rust structs.

Primitive tests pass on Host and actual ARM64. Nine groups cover lengths and
invalid lengths, insufficient space for another 128-byte record with 100 repeated
non-mutating rejections, exact byte-capacity occupancy after wrapped reclamation,
borrowed-record protection, physical wrap, near-UINT64_MAX counter wrap,
malformed published headers, the wait-epoch regression, and 200000 operations
checked against an independent FIFO model over more than 100 physical wraps.
Host ASan/UBSan with leak detection
also passes. The first model schedule accidentally drained only one item whenever
its low-bit predicate matched and did not reach the registered wrap coverage;
that failure is retained. The test was corrected to select drain size from
different PRNG bits; the queue implementation was not changed to erase the failure.

All three candidates are exercised in real separate C/Rust processes, with
different mapping addresses. The original full, paused, absent, exited and
borrowed-callback-death cases remain. Each offered record is attempted once;
independent queries read failure counters without consuming records. Debug
pressure leaves all 320 normal records delivered in every isolation run.
Fresh generations follow process-death cases; stale attachment/query rejects.

The boundary case cycles eleven lengths between 128 and 2048 bytes, including
unaligned lengths, for 20000 records. The notification-window case inserts a
test-only 200 µs delay after the reader's empty check, with 10000 single-record
offers paced at a requested 100 µs. A producer never waits for the reader's phase.
Each corrected ARM64 run records 9156–9583 admissions bracketed by the same odd
wait epoch. An odd epoch begins after the empty check and advances to an even
value immediately before poll. Producer samples it before and after the queue
call; a later wait cannot count an earlier publication. All records are consumed
without a timeout. This instruments the wait race; it is not a Product delay or ACK.

Independent review found that the first three-way witness sampled a phase only
after publication and could count an earlier publication in a later wait. That
P2 coverage defect is corrected by the monotonic epoch bracket, with regression
cases for entry, exit and later-window/ABA transitions. The common header is v2.
All three candidates were rebuilt and remeasured; old `*-matrix-b` results are
not evidence for the corrected witness. No queue-algorithm defect was demonstrated.

## Results and the retained unmet condition

| Platform / candidate | Integrity and lifecycle checks | Registered zero-loss paced checks |
| --- | --- | --- |
| Host, all three | All 135 run ledgers verified | All pass |
| ARM64 Aeron | All 45 run ledgers verified | All pass |
| ARM64 Minimal | All 45 run ledgers verified | All pass |
| ARM64 VPP | All 45 final run ledgers verified | All final runs pass; earlier B miss retained below |

Earlier `pixel-matrix-b/2-boundary-vpp.json` offers 20000 valid records, admits/consumes 19979 and counts
21 admission failures. Byte/sequence/count/sum/xor ledgers agree for every admitted
record. Other VPP boundary repetitions admit all 20000. There is no observed
corruption or unexplained accepted-record loss. All three final C repetitions
admit 20000, but the queue/classes were not changed to fix this miss. **The prior
observation still prevents an unconditional zero-loss claim for that mixture.**

The strict verifier's failure is retained in `pixel-strict-verifier-failure.log`.
Its new reporting mode continues checking all integrity/artifact/coverage rules
and emits `VERIFIED_WITH_UNMET_GATES`, explicitly retaining this failed condition;
it does not emit PASS or change the condition. This reporting change happened
after the observation and is disclosed here. The later C rerun was required by
the witness correction, not used to replace the B failure; C passes strict checks.
The precise saturated class/scheduling trigger was not instrumented, so a causal
attribution beyond counted admission loss is not claimed. A VPP choice must carry
this capacity limitation into actual-record sizing or further qualification.

Eleven altered witnesses are rejected per platform: the original eight plus
missing pre-poll coverage, counter-wrap evidence and wait-epoch regression.
Device artifact membership,
hashes, complete matrix, exact workload, distinct generations and cleanup are
also mandatory. Expected corrupt-payload exit 6 and borrowed-callback death exit
42 are successful negative tests, not unexplained process failures.

## ARM64 cost comparison

Medians of three repetitions; the JSON summaries retain all values and ranges.
CPU is the median of **per-run producer plus consumer CPU**, including the common
generator/validator and timing storage. Export includes notification, excludes
pacing sleep/record construction. Delivery ends after Rust content validation.
These are instrumented transport costs, not pure queue instruction costs or the
future storage pipeline. Candidate order rotates, but phone scheduling/frequency
are not locked; these are exploratory comparisons without confidence intervals.

| Workload | Candidate | Combined CPU ms | Export p99 µs | Delivery p99 µs | Wait calls |
| --- | --- | ---: | ---: | ---: | ---: |
| 32000, batch32 | Aeron | 538.7 | 62.9 | 995.5 | 1000 |
| same | VPP | 575.9 | 58.9 | 610.3 | 1104 |
| same | Minimal | 508.5 | 57.8 | 844.2 | 1000 |
| 128000, batch128 | Aeron | 1307.6 | 19.7 | 1624.0 | 998 |
| same | VPP | 993.5 | 44.1 | 937.4 | 2807 |
| same | Minimal | 1444.5 | 14.4 | 1572.2 | 998 |
| 200000 unpaced offers | Aeron | 269.5 | 1.180 | 1781.4 | 163 |
| same | VPP | 242.2 | 0.977 | 2765.5 | 499 |
| same | Minimal | 244.9 | 0.773 | 1386.8 | 3 |
| 20000 boundary records | Aeron | 326.3 | 60.2 | 1187.3 | 626 |
| same | VPP | 545.9 | 60.8 | 645.5 | 702 |
| same | Minimal | 369.0 | 58.8 | 1072.5 | 625 |

The table contains only the corrected C matrix; it does not erase VPP's earlier
B boundary failure. Burst CPU totals do not process equal admitted work: Aeron
admits median 159910 (52895–182659), Minimal 144879 (103966–160288), VPP 113385
(104778–131889). The rest are counted admission drops.
Do not infer a per-record CPU winner from those unequal totals.

Minimal's batch32 combined CPU is slightly lower than Aeron's median, but Aeron's
range is 504–545 ms and Minimal's 488–531 ms. At batch128 Aeron is lower by median,
with broad overlapping ranges. At sparse single records export p99 is 335.6 µs
Aeron, 287.3 VPP and 342.6 Minimal. There is no consistent minimal-ring win.
One final Aeron burst repetition admits only 52895 records and has delivery p99
70.243 ms; its other repetitions have p99 1.344 and 1.781 ms. This outlier has no
corruption or wait timeout, but its cause was not isolated and it is not dismissed
as merely scheduling. It prevents a claim of consistently superior Aeron burst
latency or admission. The recommendation is a reuse/maintenance preference, not
a declaration that Aeron won every measured dimension. VPP can notify earlier inside a batch,
while both byte rings notify at the batch boundary; policy differences remain
part of the measured tradeoff. Old two-way numbers are not pooled with this run.

| Resource / idle measure | Aeron | VPP | Minimal |
| --- | ---: | ---: | ---: |
| Requested shared bytes, two channels plus common header | 529920 | 540032 | 528640 |
| Absent consumer: admitted records out of 100000 | 656 | 704 | 656 |
| Absent consumer: admitted payload bytes | 256768 | 262144 | 256768 |
| Batch32 consumer current RSS, KiB | 4328 | 4924 | 4280 |
| Producer CPU during 3-second idle, ms | 0.501 | 0.049 | 0.040 |
| Consumer CPU over idle plus one delivery, ms | 0.531 | 0.716 | 0.721 |
| Consumer blocking waits in that idle case | 1 | 1 | 1 |

All idle waits complete without timeout; all observed producer idle CPU values
are below 1 ms. This small sample is not an energy ranking. No permanent polling or wakelock is
introduced. Absent consumers do not stop producer progress, and the minimal ring
does not overwrite unread slots. The fixed-class saturated record mixture differs
from a byte ring's final mixture, so VPP's larger count is not a universal capacity
advantage. RSS includes runtime/validation allocations; shared pages must not be
summed twice. VPP libraries already ship in the Product/VAPI closure, so standalone
RSS/ELF differences do not measure incremental APK or Product cost.

This is the same available Pixel, Android shell identity, USB powered, 4 KiB pages,
API31/ARM64 native executables. It is not Doze, energy, app-identity/SELinux,
multi-owner, 16 KiB-page or release qualification. Full environment, virtual
address size, context switches and all latency quantiles remain in raw evidence.

## Selection and maintenance tradeoff

| Candidate | What is reused / owned | Decision implication |
| --- | --- | --- |
| Aeron | Pinned Apache-2.0 queue algorithm, small subset packaging/error seam; project owns mapping, notification, generation and record contract | Recommended for reuse and variable capacity, not as a universal performance winner; burst outlier remains explicit |
| VPP | Already-shipped Apache-2.0 dependency and native notifier; project owns matching ABI/profile, classes and facade | Final checks pass, but the earlier widened-length admission loss remains a capacity qualification limit |
| Minimal | No new queue dependency; project owns all queue layout, ordering, wrap/corruption behavior, regressions and future changes | Technically viable in this envelope; 1.25 KiB shared saving and mixed timing results do not establish a compelling advantage over reuse |

Choosing Minimal would not mean restarting all supporting work from nothing:
the C/Rust test infrastructure, notification experience and contract evidence now
exist. It would mean accepting ownership of the queue itself. Its short source
does not remove that maintenance responsibility, and this campaign is not the
same history of independent use and fixes as an upstream library.

The user must review these three outcomes and explicitly choose. No third backend
is integrated into Product. T21 must independently implement the chosen Product
seam without importing POC source, then compare actual record sizes/rhythm and
owner topology against this envelope. FD negotiation/memfd, APK identity, lifecycle
quiescence, partial-batch scheduling and actual storage remain Product work.
E01/274 retains the separate mandatory user review of the **complete** observation
pipeline and its costs/gaps. Nothing here satisfies that pipeline gate.

## Validation, preservation and review

Host and ARM64 primitive tests pass; Host ASan/UBSan/leak detection passes after
rerunning outside the traced sandbox which LeakSanitizer rejects. That original
sandbox failure, the first model coverage failure, and the VPP strict-verifier
failure remain retained. C and Rust extension builds use warnings as errors.
The experiment catalog passes and the unchanged full Product Host suite passes
50/50 with local-socket permission. No Product source was changed.

The 34 entering dirty paths are checked byte-for-byte against the extension's
baseline. No catalog edit is needed because the existing T20 group covers the
new files. Prior two-way files and hashes remain available from their snapshot;
the old dated result is historical rather than silently rewritten.
Independent review is recorded in
[the three-way review](../reviews/2026-09-26_T20_THREE_WAY_CODE_REVIEW.md).
Final index and pending-decision handoff retain the unmet condition and no selected
direction. Task state and the decision remain in Plane.
