# T30 combined cost and default calibration

[SAKAMOTO-282 / T30](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/0787fc9d-808b-48f5-bb2c-b7cacab78a5c)
remeasures representative combined Product work after the
[T29 integration](2026-09-27_T29_COMBINED_RESULTS.md). The packet target is
VPP-native C. T30 changes test collectors and evidence checks only; it makes no
Product implementation or default change. The current values remain
engineering initial values within the accepted rule/observation semantics.

## Workload, identity and verification

The paired workload compares the same functional four-rule configuration with
64 effective rules and 65 domain entries. The additional 60 rules are bound to
the tested UID, have distinct UDP destination ports 60000–60059 and never win;
the additional 64 exact names are in the live domain list. This increases
compiler/index and query work while leaving the independently checked RTP/STUN
and QUIC/SNI/domain outcome unchanged. Each Product generation keeps both Flows
active through three complete publications, observe → enforce → recover for RTP,
and then clears the test configuration. Root and controlled VPN run serially.
The fixture source, exact requests, current configuration bytes, source and
installed artifact hashes, captures, generations, full explanations, dashboard
queries and cleanup are retained under `build-output/t30-20260927/`.

The final comparison is `linux-baseline-c` ↔ `linux-scaled-c` and
`pixel-baseline-b` ↔ `pixel-scaled-d`. Independent packet oracles report `VALID`
for all four runs. Linux selected 219 traced RTP/QUIC packet paths per run,
29 RTP endpoint exchanges, 75 QUIC echoes, one actual DROP and six full
explanations. Each Pixel Root and controlled-VPN run selected 119 traced paths,
29 RTP exchanges, 25 QUIC echoes, one actual DROP and five full explanations.
The Pixel profile generations are 1758/1759 for baseline and 1762/1763 for the
final scaled run. Per-profile Flow identity survives updates; expected winner,
declared/actual action, mode, revision and historical source availability agree
with packet and Rust windows. The final-source Pixel APK SHA-256 is
`a004f6b2f722a3853c1b5fb43ecdbf52b5ce2708778d64126992281667619568`,
Product source closure `416331755499a6c16a75231c9089f6413ebe46155f438b4d65c79dde8be08a2e`.
Linux uses T29's source-b Product artifact closure
`0efda6e4538b0322393b898be8dcd3c7188d582a3770a56ae55fdf40d2aebd8b`;
T29's build witness proves the final Pixel source changed only Java diagnostic/UI
code and that native libraries are byte-identical. Pairwise cost comparisons
stay within one source/artifact and the same platform.

A separate current-Product Linux run, `linux-supplement-f`, keeps four Flows
live together in one 64-rule/65-domain generation: R2 SMTP, R3 OpenVPN, R4
RTP/STUN and QUIC/SNI/domain. Two of its 60 additional rules are whole LPI
predicates for SMTP and OpenVPN. They win in observe mode with declared DROP,
actual ALLOW and correct historical explanation through revisions 2→4; the
remaining 58 are nonmatching port rules. Its independent
[supplemental oracle](../../build-output/t30-20260927/linux-supplement-f-verification.json)
joins socket peer commands/replies to native packet admissions, all four stable
Flow identities, protocol facts, five maintained L7 labels, resource counters,
rule windows and clean stop. The original T29 Linux packet oracle also passes
for its concurrent RTP/QUIC portion. The first supplemental attempt `e` retained
an OpenVPN rule that lost to a higher-ranked negated RTP rule; the test workload
priority was corrected for `f` without changing Product rule semantics.

The [cost oracle](../../build-output/t30-20260927/cost-verification-final-c.json)
checks the actual configuration counts, source and sampler hashes, artifact-bound
packet verdicts, policy/Flow resources, parser and cache state, process samples,
and settled stores. The [packet timing oracle](../../build-output/t30-20260927/packet-timing-final-b.json)
pairs each selected native `s216` admit/terminal token and classifies its POST
cache result: 219 paired RTP/QUIC packets in each matched Linux run, 119 in
each Pixel profile and 245 across the four protocols in the supplemental run.
Neither uses Product detection to generate the expected winner.
The [evidence index](../../build-output/t30-20260927/evidence-index.json)
contains the raw campaigns, first attempts, logs and final stopped-device proof:
2,010 files / 100,739,639 bytes, index SHA-256
`c4db46054e0418fd6256f45c8ea0f0b70dbea8fd56929245583741d12be6224c`.
All indexed file hashes were independently recomputed with zero mismatch.

## Memory and work envelope

Live `show product rule-budget`, `show product policy-index` and `show product
flows` from the scaled generations give the following. Bounds are fixed
admission/reservation accounting, not a measured process RSS delta.

| Component | Current observation or bound | Interpretation |
| --- | ---: | --- |
| Complete rule compile envelope | 2,045,364 / 2,097,152 B | Includes source and metadata, old/new rule views, three domain structures for old/new/building, query scratch and two worker caches; 51,788 B below the 2 MiB guard. |
| Policy publication envelope | 386,932 / 393,216 B | Four-view compile/publication overlap; already inside the complete compile envelope, with 6,284 B margin. |
| Actual indexed view / work | 63,512 B in both shapes; masks 1→2; entries 4→64; maximum query work 25→146 | Fixed view storage is charged even when few rules are active. The 5.84× work-bound increase is a genuine scale cost, not a packet latency ratio. |
| Two Flow owners | 9,261,384 B each, 18,522,768 B total | Each has 1,024 slots of 9,024-B FlowEntry; parser/TCP/QUIC/SNI/LPI state is inside the entry, so it is not added again. The four-flow Linux run peaks at three slots on owner 0 and one on owner 1, with no capacity miss. |
| Worker policy caches | 25,632 B each, 128 slots | Included in the complete compile envelope above. Final Linux scaled counters: 312 hits / 26 misses; baseline: 311 / 27. Pixel Root/VPN final scaled counters: 212 / 26 and 215 / 39. |
| Four normal/debug record channels | 987,904-B generation mapping | Separate from rule/Flow allocation. The final Pixel Root/VPN dashboards show 50/30 normal-channel publications, 38/20 notifications and 56/31 Rust waits, with zero full/oversize/notify errors and zero pending at the settled query. The Rust store's accepted count is cumulative 50→80 across those two profile generations. |

The nonoverlapping accounted native subtotal is 21,556,036 B (20.56 MiB): two
Flow pools + the full rule compile envelope + one channel mapping. It excludes
VPP infrastructure, allocator retention, stacks, Java/Rust heap, socket/kernel
buffers and SQLite. It is neither an RSS estimate nor a release memory cap.
The same Flows run across bank 0→1→0 publications. The compile envelope reserves
old/new coexistence even where the sampled CLI sees zero old readers; T11's
separate held-reader packet regression established functional reader safety.

## Observed CPU, packet path, storage and temperature

At 250 ms Linux and 1 s Pixel sampling cadence, short allocation peaks may be
missed. `/proc` CPU ticks are 10 ms units. Linux runs were 18.474 s baseline and
21.107 s scaled; Pixel full two-profile runs were 128.073 s and 128.659 s.
These durations include diagnostic queries, screenshot/UI work and cleanup.

| Whole-run process sample | Four-rule baseline | 64-rule scaled |
| --- | ---: | ---: |
| Linux VPP peak sampled RSS / CPU ticks | 234,104 KiB / 2,795 | 234,300 KiB / 3,330 |
| Linux separate Rust consumer RSS / CPU ticks | 11,700 KiB / 16 | 11,708 KiB / 18 |
| Pixel Root VPP peak sampled RSS / CPU ticks | 124,472 KiB / 57 | 124,408 KiB / 72 |
| Pixel VPN VPP peak sampled RSS / CPU ticks | 124,780 KiB / 73 | 124,856 KiB / 70 |
| Pixel Java/Rust RuntimeService peak sampled RSS / CPU ticks | 190,556 KiB / 2,497 | 193,392 KiB / 2,548 |

The separate 21.890 s four-flow Linux run sampled VPP/Rust RSS peaks of
234,288/11,880 KiB and 3,535/18 CPU ticks. Its normal queues published 64
records with 40 notifications and 123 Rust waits, zero full events or pending
work at query. The sampled owned SQLite files peaked at 77,824 B, while Rust
reported a 41,232-B WAL peak and 19 commits. These whole-run numbers include
the same VPP scheduling and diagnostic/control work as the paired Linux runs;
the fixed Flow reservation already accounts for additional active entries.

The final scaled Pixel process write-byte deltas were 2,420,736 Root VPP,
1,581,056 VPN VPP and 647,168 RuntimeService. The baseline phone write-byte
counter is unavailable: its compound Android shell read omitted `/proc/io`.
The later standalone read was verified before the final scaled run. Process
write bytes include configuration, logging and database work, and are not
physical NAND writes. Linux VPP writes were 2,043,904→2,166,784 B and the
separate consumer 737,280→786,432 B in the matched runs. Pixel's Java/Rust
process stayed alive between profiles and earlier runs, so its VmHWM of
204,140 KiB is inherited; sampled current RSS is reported above instead.

Native selected-packet admit→terminal medians, in microseconds, are below.
Each Linux run has 149 QUIC / 51 RTP hot-POST packets; each Pixel profile has
51 of each. Cold samples are only 8–11 per protocol and remain in the raw
oracle. The trace includes packet graph, parser, cache, accounting and diagnostic
logging; it excludes endpoint and underlay delivery. These short runs do not
support a throughput or latency SLO.

| Product path | QUIC hot baseline→scaled | RTP hot baseline→scaled |
| --- | ---: | ---: |
| Linux Root/NFQUEUE | 102.8→102.5 µs | 179.5→194.6 µs |
| Pixel Root | 596.8→770.0 µs | 830.2→595.0 µs |
| Pixel controlled VPN | 390.3→455.4 µs | 1,055.6→725.3 µs |

The opposing directions and Linux RTP hot tails (p90 13.4/16.5 ms) caution
against claiming a speedup or a stable per-packet bound from this traced,
foreground workload. Three Linux host rule-replace calls had median full
CLI/process/IPC times 32.898→34.804 ms. Six phone replaces had median
tap/Activity/poll times 2.944→2.904 s. Nine Linux rule-query calls per arm had
median full process/IPC times 29.776→29.695 ms; the four-flow run was
28.494 ms. Those wall times include process startup and do not isolate matching.
In the four-flow Linux run, SMTP (9 cold / 11 hot POST packets) had
155.3/134.0 µs cold/hot admit→terminal medians, and OpenVPN's six cold POST
packets had 143.6 µs median. The [supplemental oracle](../../build-output/t30-20260927/linux-supplement-f-verification.json)
records SMTP LPI seven calls / 253 admitted bytes and SNI 76 work units,
OpenVPN LPI six calls / 120 bytes and SNI 40 work units; both coexist with
QUIC's 5,909 SNI work units, RTP's 1,336, two owner caches and the same
published snapshots. These are current Product counters, while R2/R3/R4's
separate ARM64 call-time samples remain their local detector-cost baselines.

The [source-bound C cost helper](../../build-output/t30-20260927/compile-arm-run-d/result.json)
uses the current `product_rule_config_activate` implementation on the exact
saved 4/1, 64/65 port-scale and 64/65 four-protocol rule sources. It times
native validation, effective expansion, policy compile, domain build, hash and
a test publish callback that compiles the published view and retires the old
domain tree. It excludes disk save, VAPI/IPC, worker synchronization and VPP
process scheduling. Each target ran three alternated rounds of 100 timed
activations after five warmups, plus 100,000 exact-domain and un-cached RTP
whole-rule match calls per round. Both Host and physical ARM64 binaries use `-O2`, retained
source snapshots/commands and executed binary hashes. Median observations:

| Native source shape | Host activation / match | Pixel ARM64 activation / match |
| --- | ---: | ---: |
| 4 rules, 1 domain | 8.58 µs / 148 ns | 46.02 µs / 239 ns |
| 64 rules, 65 domains, port scale | 116.76 µs / 218 ns | 383.26 µs / 265 ns |
| 64 rules, 65 domains, SMTP+OpenVPN rules | 120.17 µs / 240 ns | 382.77 µs / 287 ns |

ARM64 exact-domain lookup medians were 149.8/101.6/89.0 ns in the same order;
Host was 35.1/37.4/40.5 ns. These nonmonotonic short-run results reflect
clock/cache/order noise and query shape. The helper is compiler-core and
matcher evidence on the actual phone CPU, not a VPP packet-path or end-to-end
application latency claim. The per-query figures include assertions and
signature accumulation inside the same loop. Its [Host companion](../../build-output/t30-20260927/compile-host-run-d/result.json)
preserves the same source/case hashes; T10's wider plan-shape regressions remain
the relevant independent counterexamples.

The isolated Pixel observation store's maximum sampled actual DB+WAL+SHM+lock
files were 90,112 B, matching the Root live storage-space query; VPN settled at
65,536 B. Rust reported Root/VPN WAL peaks of 37,112/28,872 B, 23/16 commits,
22/16 checkpoints and no pending rows or save error at query. The 256 MiB
owned-file budget, 64 MiB DB cap, 16 MiB WAL guard, 48 MiB working reserve,
4,096 dirty-key cap and 2,048-row flush trigger were unchanged. A short
65–90 KiB history is evidence of this workload, not a 180-day or full-budget
retention test; T27 supplies the separate quota/age pressure evidence.

Pixel battery temperature was 37.3→37.7°C in the earlier baseline and
38.4→38.9°C in the later scaled run. USB power, warm order, active screen,
diagnostic traffic and ambient/device activity were not controlled for energy.
The temperatures are environmental snapshots; no battery-life or thermal
steady-state comparison follows. Process context-switch deltas in the raw cost
oracle and Rust wait/notification counters are wakeup proxies, not hardware
wakeups or Doze measurements.

## Default decision and remaining limits

Retain the current initial limits: 128-entry owner policy cache, 256 source
rules/128 effective rules, 256 domain entries, 2 MiB compile and 384 KiB
publication guards, 1,024 Flow slots per owner, current bounded parser/work
windows, four-channel 987,904-B mapping, one-second/2,048-row SQLite flush,
and T27's 48-hour minute / 30-day hour / 180-day day / 24-hour END retention
under 256 MiB. The 64/65 live combination stayed within the guards and retained
complete semantics and normal stop. The small compile/publication margins and
5.84× larger index query-work bound are explicit costs, not evidence that a
larger default improves this phone. T09's many-mask slowdown, T10 direct-plan
regression, T11 cheap-rule cache regression, T17 rax query/RSS tradeoff, E01's
whole-file writes, E02's SQLite improvement, T23's write amplification and
T27's 64-versus-256 flush tradeoff remain counter-evidence to blanket speed or
memory claims. No candidate or numerical SLO is selected by this run.

The current scaled run did not fill a record channel. T29's separate 10,006-send
Root/VPN run on native-identical source b reported 113 channel-full events per
profile while Product packets completed, tails were accounted by actual device
ingress and no buffer debt remained. It is the retained overload/no-consumer-wait
evidence; this T30 test-only change did not alter that Product path. T14/T16
parser byte/work exhaustion, T10 compilation limits, T27 SQLite FULL/rollup
pressure and T23 stale-query/failure behavior remain separately verified at
their own boundaries. No lossless history or underlay delivery promise is
inferred from queue-full counts.

The combined phone workload has two active protocol Flows and the Linux
supplemental generation has four simultaneous protocol Flows. Prior T23
exercised 128 active sockets and T14 exercised 48 simultaneous parser attempts
in separate generations. It does not claim every R2/R3/R4 detector pair in one
Flow, a 128-rule/256-domain maximum live phone qualification, 180-day physical
soak, background/Doze energy, an electrical power measure or a universal
throughput advantage. R2–R4 ARM64 owner-call/state measurements stay attached
to their original tickets; T29 adds multi-label RTP/QUIC and separate TLS/import
interaction evidence. Ordinary VPN Start remains
`vpn_flow_stack_not_ready`; controlled HEV/TUN traffic has
`protectionRunning=false`, so neither phone result is ordinary VPN release
protection. The parent SAKAMOTO-251 retains any future release/device-fleet
qualification; this cost ticket does not create an implied release gate.

The first Linux scale attempt omitted the dashboard environment required by the
existing independent oracle; its raw packet run and failed verifier remain
indexed, followed by the corrected passing run. The first phone storage sampler
did not parse Android's `ls` output, and its compound `/proc/io` command omitted
write bytes; both observations are retained alongside the corrected final run.
An old `tests/android/runtime-contract-test.sh` invocation reaches a removed
Rust policy file; the current `android-runtime-contract-test.sh` passes. The
first final stopped-device readback found a cached `:runtime` process after the
service had stopped; `dumpsys activity services` showed no active service.
After package force-stop, the strict readback
[`PASS`](../../build-output/t30-20260927/device-readback-after-force-stop/summary.json)
at generation 1763 found no VPP/service/hooks/selector, exact installed
APK/native, intact KernelSU grant, SQLite integrity `ok`, and all 1,575
pre-existing nonmetadata rows plus ordinary DB/JSON hashes unchanged. The
[last readback](../../build-output/t30-20260927/device-readback-after-cost/summary.json)
reconfirmed that state after the temporary ARM64 compiler helper was removed.

Full current gates: CTest 51/51, Rust 73 passed / three ignored, and Android
runtime contract PASS. Python syntax and `git diff --check` pass. The independent
Standards and Spec review is in [the review record](2026-09-27_T30_COMBINED_COST_REVIEW.md).
