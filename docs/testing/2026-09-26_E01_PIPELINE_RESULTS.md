# E01 actual observation pipeline results — 2026-09-26

SAKAMOTO-274 remains **In Progress / USER_REVIEW_REQUIRED**. These are evidence-validity results and recommendations, not a performance PASS or approval to start T23. The selected VPP transport remains the T20 decision. No Product source or storage implementation is changed by this experiment.

## Decision supported by the evidence

The existing producer → VPP svm_msg_q → Rust cumulative overview → transactional minute snapshot → normal API chain accounts for the measured traffic without observation loss under normal Linux and controlled Android VPN loads. Whole-file JSON persistence has substantial cost as retained history grows: on the Pixel, a 4.69 MB synthetic starting snapshot led to **771.78 MB of RuntimeService process write accounting** during 162 normal-phase store batches, versus 52.46–60.06 MB with an empty starting store. This supports adjusting persistence before treating the current storage implementation as a scalable foundation. It does not select a replacement storage engine.

| Classification | Evidence and allowed interpretation |
| --- | --- |
| Usable for the measured next step | Fixed queue/wire, cumulative accounting, minute conservation and ordinary low-rate freshness work in the measured scope. A bounded small-history continuation is an option only if the user explicitly accepts its constraints. |
| Adjust then remeasure | Whole JSON rewrite grows from 0.34 MB to 903 MB of process writes in matched Linux pressure cases. Prefer a separately approved bounded persistence design/remeasurement before expanding retained history. Correctness and atomic baseline/window advancement must remain unchanged. |
| Insufficient evidence | Strict Root A/B/C, sustained background/Doze, electrical energy, thermal steady state, full retention/attribution/multilabel/Blocked Observation, and a release resource budget. No release or whole-product claim follows. |

The user must choose whether to adjust storage now, continue a bounded small-history slice with an explicit limit, or require one distinguishing experiment. Keep E01 and downstream blocking until that choice is recorded. A storage follow-up should compare the current snapshot with a proposed bounded transactional implementation at identical 0/1k/10k/60k synthetic baselines on Host and 0/10k on Android, preserving failed-write and restart invariants. This is a proposed finite test, not an automatically authorized implementation.

## Reproduction and evidence identity

The preregistration and prospective adjustments are in [the experiment plan](2026-09-26_E01_PIPELINE_PLAN.md). Raw evidence is under `build-output/e01-20260926/`; `evidence-index.json` seals the final evidence inventory. Build manifests retain source closure, source files/diff, artifacts, native hashes and timestamps. Each run retains applied parameters, generations, workload payload identities, endpoint logs, actual packet captures, process samples, API snapshots, final store and cleanup. Verifier results identify their own exact source hash.

| Campaign | Source closure | Result |
| --- | --- | --- |
| `linux-c` | `b17f4dda32a176f7feab96a24973b930fbfe3d57ac02861780aeb7e7ee877f01` | Nine arms, real isolated VPP/Linux packet path; original workload with 1024 pause flows |
| `pixel-vpn-c`, freshness, Android pressure/guard; Linux pressure/fault | `9e2dc538b4b9ae3e57bd04b51508930553d40783cb1161d888696906c4e5a42b` | Startup-controlled native configuration; same native closure across these Host/ARM builds; controlled VPN 192 pause flows |

Each main comparison is A, B, C, C, B, A, G, F, D in fresh generations/stores. A disables record/export and associated activity clock bookkeeping, B enables ordinary export and Rust overview without persistence, C adds the current store. G changes growth 32→128 packets; F changes refresh 1 s→250 ms; D changes drain 128→16 per channel. Byte threshold 65536, due-flush budget 64, fixed queue layout and per-batch durability remain unchanged. A/B is combined producer-bookkeeping cost, not isolated clock cost.

Reproduction entry points are `tests/evidence/build_e01.py`, `tests/evidence/run_e01_linux.py`, `tests/device/e01-pixel-pipeline.py`, `tests/evidence/verify_e01.py`, and `tests/evidence/e01_metrics.py`. Build tooling temporarily applies a test-only overlay and restores exact Product bytes, including rollback if application fails. Linux launcher uses a distinct network namespace; Android uses only `./dev/adb`. Recorded `host-pressure-runner.json` contains exact pressure commands. Main collectors preserve runner source and operations; use the same manifest/workload revision when repeating a campaign.

## Cost comparisons

Values below cover idle, low, burst, sustained, active and short phases, **before** deliberate consumer pause/recovery. Each has 1916 sent echo requests. They include deferred refresh/write completion and fixed diagnostic/query control. Linux `linux-c` closes its windows using the next pre-send sample; Android uses direct post-settlement samples. Earlier traffic-only metrics are retained and must not be paired with settled store totals. Process CPU has 10 ms tick resolution. Rust on Android means the whole RuntimeService process; its dedicated consumer CPU is separately shown. MB means decimal bytes/1,000,000.

### Linux full matrix

| Arm | VPP CPU ms | Consumer CPU ms | Rust process CPU ms | Process write MB | Batches | Store elapsed ms | Peak Rust HWM KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 11580.0 | 0.0 | 0.0 | 0.00 | 0 | 0.00 | 5556 |
| B | 11670.0 | 10.0 | 20.0 | 0.00 | 0 | 0.00 | 11720 |
| C | 11700.0 | 180.0 | 200.0 | 28.94 | 363 | 1040.20 | 13580 |
| C | 11670.0 | 170.0 | 210.0 | 28.68 | 359 | 1020.95 | 13672 |
| B | 11660.0 | 0.0 | 30.0 | 0.00 | 0 | 0.00 | 11976 |
| A | 11590.0 | 0.0 | 10.0 | 0.00 | 0 | 0.00 | 5464 |
| G | 11680.0 | 160.0 | 180.0 | 28.64 | 302 | 872.09 | 13540 |
| F | 11680.0 | 170.0 | 190.0 | 27.55 | 367 | 1019.03 | 13512 |
| D | 11680.0 | 170.0 | 200.0 | 28.96 | 363 | 1035.90 | 13596 |

### Pixel 6a / bluejay controlled VPN

| Arm | VPP CPU ms | Consumer CPU ms | Rust process CPU ms | Process write MB | Batches | Store elapsed ms | Peak Rust HWM KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A | 5850.0 | 0.0 | 720.0 | 0.61 | 0 | 0.00 | 165704 |
| B | 5730.0 | 130.0 | 780.0 | 0.93 | 0 | 0.00 | 166240 |
| C | 5710.0 | 2080.0 | 2810.0 | 60.06 | 746 | 5971.18 | 165604 |
| C | 5490.0 | 1730.0 | 2420.0 | 52.46 | 655 | 5784.68 | 165628 |
| B | 5900.0 | 120.0 | 760.0 | 0.92 | 0 | 0.00 | 165852 |
| A | 6090.0 | 0.0 | 700.0 | 0.70 | 0 | 0.00 | 165452 |
| G | 5430.0 | 1540.0 | 2240.0 | 51.43 | 592 | 4949.05 | 165456 |
| F | 5690.0 | 1830.0 | 2640.0 | 51.56 | 712 | 6121.81 | 165776 |
| D | 5930.0 | 1920.0 | 2600.0 | 58.57 | 729 | 6414.32 | 165728 |

VPP process CPU includes its packet/input scheduling baseline; the small Host A/B difference and variable phone A/B difference do not identify a precise per-packet export cost. Phone B consumer cost is 120–130 ms; C is 1730–2080 ms. Store elapsed time includes synchronous copy/serialize/filesystem save work and waiting, not just CPU. This instrumentation does not isolate copy, encoding and fsync into separate timers. Per-phase samples and query timing remain in the metrics JSON.

G reduced phone batches to 592 and consumer CPU to 1540 ms in one run, but the spread between the two default C runs cautions against choosing it as an optimum. F bounded the measured low-tail freshness more tightly; D did not demonstrate a cost advantage. No significance test, maximum-throughput estimate or invented acceptance threshold is claimed.

### Matched Linux synthetic-history pressure

All cases use the startup-controlled build, C, and the same low/burst/sustained workload (1276 request/reply pairs plus a final one-pair freshness probe). Only pre-existing valid zero-contribution baseline count changes. Thus they test retained-state sensitivity, not implemented attribution or a real history upper bound. No synthetic packet contribution is added.

| Seed baselines | Final snapshot MB | Consumer CPU ms | Rust write MB | Store batches | Store elapsed ms | Consumer ready ms | Peak HWM KiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 0.001 | 10 | 0.34 | 82 | 210.51 | 31.80 | 5732 |
| 1000 | 0.470 | 120 | 37.68 | 80 | 336.73 | 32.22 | 7060 |
| 10000 | 4.689 | 790 | 332.98 | 71 | 1113.39 | 76.02 | 22104 |
| 60000 | 28.214 | 2800 | 902.96 | 32 | 3084.18 | 288.14 | 79996 |
| guard-72000 | 33.863 | 0 | 0.00 | 0 | 0.00 | 29.52 | 5620 |
| fault-1000 | 0.470 | 110 | 31.09 | 82 | 284.41 | 35.00 | 7384 |

Ready timing is a polling-observed Host consumer connection/startup interval under warm-cache conditions, not cold filesystem startup latency. The rejected oversized case connects quickly because its store fails to open; it is not a fast usable store.

The Pixel 10k-baseline full workload began with 4,688,476 bytes of synthetic historical state. Normal phases recorded 162 batches, 7.89 s consumer CPU, 8.56 s RuntimeService CPU, 11.79 s store elapsed time and **771,784,704 process write bytes**. Final file size after all phases was 4,910,397 bytes; peak process HWM was 181,436 KiB. Baseline C was about 165,600 KiB. Exact old synthetic baselines remained unchanged; all 4216 actual Flow packets were accounted for without queue loss. This pressure run uses the same phone/native configuration and full workload as empty-history C, but it is one sensitivity observation, not a repeated confidence interval.

The approximately 772 MB is repeated whole-file snapshot write accounting. It is neither network traffic nor the final store size nor measured physical NAND writes. Slower persistence also changes queue batching: 162 batches instead of 655–746, so batch count itself is not an independent control.

At 72k seeds the file is 33,863,120 bytes, above the existing 32 MiB input guard. Both Host and phone expose `observation_snapshot_too_large`, keep the old file unchanged and keep packet/overview processing alive. Phone guard ran 20 successful echo pairs: 40 Flow packets plus 2 captured platform IP packets. No usable persistent history is fabricated. This guard is a refusal bound, not a complete retention/space policy.

The Linux fault case places an actual directory at the pending-snapshot path during burst. The API exposes the write error and incomplete coverage; committed totals remain unchanged at the failed boundary. After removal, later cumulative records safely reach 2554 packet contributions, matching overview/capture, while incomplete coverage remains visible. This is an actual filesystem failure/recovery observation, separate from deterministic T22 tests; an equivalent phone write-fault run was not performed.

## Accounting, pause loss and time placement

Every retained packet is independently checked at the actual VPP capture boundary, using payload identity, address/port direction and 92-byte IPv4 UDP packets. Consumer/generation, queue conservation, cumulative byte totals, committed minute conservation and final on-disk/API identity are verified. Platform IPv6 ICMP packets contribute to basic IP totals but are not misrepresented as UDP Flow records.

Linux normal C phases yield basic = overview = durable = 3832 packets with no full queues. During the deliberate 1024-new-flow parked-consumer phase, packets continue through VPP and the consumer accepts no records. Final basic count is 6138; each C run persists 5174 contributions, with 1435/1437 failed record publications and explicit durable incomplete coverage. Record publication loss is not a count of lost network packets, and the 964 missing contributions are not fabricated. All 3069 Linux echoes returned. No replay or second accounting path was introduced.

Phone full matrices send 2108 requests each and retain 2106–2108 actual replies. Captured Flow totals match valid cumulative contributions in every export arm, with zero queue-full events; absent network replies remain network evidence. The phone 192-flow pause is constrained by existing per-owner VPN session capacity and does not claim queue saturation. Root mixed-UID INPUT traffic prevents a pure Root ABC oracle; those attempts stay HOLD. The existing Root hook semantics were not narrowed for the experiment.

UTC minute buckets use coalesced last-activity placement, not exact per-packet historical timestamps. Independent capture-versus-store bucket comparisons give L1 packet-count differences of 0 for both default C runs on each platform; sensitivity G/F/D have phone differences 230/24/10 and Host 0/8/0. L1 is twice the number moved between buckets when total counts agree. These are descriptive boundary effects; zero in a particular run does not prove exact placement generally. Byte/count conservation still holds.

## Freshness, scheduler proxies and platform context

An additional controlled VPN low-rate C/F experiment sends 20 echo pairs, then brackets normal API polls with the device monotonic clock. Default C becomes fully visible within **592.33–1057.73 ms** of the last send; F within **0–490.62 ms** (already visible at the first poll). RPC and polling overhead are included. These are one-tail visibility bounds, not packet latency percentiles or a guarantee. Host single-pair polling upper bounds were C 1037.66/1044.92 ms and F 327.37 ms. Flow-record activity-age samples include state-only END and must not be called delivery latency.

Phone normal-phase notifications/waits were B 822–843/821–841, C 426–518/378–455, and 10k pressure 87/84. Fewer notifications under slower persistence reflect batching, not proven lower power. C RuntimeService common-thread voluntary/involuntary context-switch deltas were 2565–2854/2235–2284. Threads absent at either endpoint are excluded and turnover is retained. These counters are scheduler proxies, not exact hardware wakeups.

During the 10-second idle phase, C consumer CPU rounded to 0 ms; VPP and RuntimeService each consumed 10–20 ms including control work. Battery/charging/temperature snapshots are retained before/after the USB-connected campaign. The tests do not isolate electrical energy, deep idle, Doze or thermal equilibrium. Idle/low/burst explicitly returned HOME; sustained/active/short/pause kept the diagnostic sender foreground because earlier background sender scheduling produced a 150.59-second application receive duration despite only 3.80 ms between its captured request/reply. This is retained as a generator confound, not labelled IPC delay.

The separately compiled auxiliary CLOCK_REALTIME loop measured about 20.88–21.04 ns/call above empty-loop CPU on Host and 37.17–54.26 ns/call on ARM64 (seven 1M-call rounds). It proves only API-loop cost sensitivity under those runs. It does not estimate real pipeline CPU or battery use. Source/binary hashes and raw rounds are retained in `aux-clock/`.

## Proposed starting points; no automatic selection

Keep the chosen VPP transport and present fixed queues (four 512-descriptor channels, total mapping 332,544 bytes) for a bounded next experiment: normal traffic and 10k Android history produced no publication loss. Increasing queues would not remove whole-snapshot rewrite cost; forced long consumer stalls demonstrably remain lossy and visible.

Keep 32-packet/65536-byte growth, 1-second refresh, 128-record drain and existing atomic per-batch persistence as the comparison baseline. Treat 128-packet growth as a candidate to reduce record/save frequency, with latency/placement tradeoffs; treat 250 ms refresh as a candidate only if roughly subsecond low-tail visibility matters enough to remeasure its work and energy. The 16-record drain has no demonstrated benefit here. Do not combine sensitivity changes into an unmeasured winner.

For storage, recommend user approval to adjust then remeasure before expanding retained history. A fallback choice is explicitly bounded small-history development, with a measured storage budget and later mandatory remeasurement. Neither option authorizes dropping live baselines, delaying acknowledged durability silently, changing counting semantics or implementing replay. The current 32 MiB rejection is not an acceptable substitute for a selected retention policy.

## Verification, review and restoration

Final verification files are `linux-c-verification-final.json`, `pixel-vpn-c-verification-final.json`, `pixel-vpn-freshness-c-verification-final.json`, each pressure `*-verification.json`, and `regression-final.json`. Rehashed semantic mutations reject hidden basic packets/overflow, bad generations, store/API mismatch, wrong measured process, missing minute totals, wrong Flow addresses, fabricated bytes and direction swaps. Freshness adds target/clock checks. Linux main rejects 10 mutations, Android main 9, Android freshness 12. Oversized/fault cases are independently checked but are not claimed to pass all ordinary-store mutations.

Three experiment-overlay regressions cover failure during the second replacement, idempotent mixed-state restoration, and protection of a concurrent edit. Final deterministic Host (50/50 CTest) and Rust (28 tests) suites pass on the restored Product; initial sandbox socket denials are retained separately and rerun with permitted local socket access. Native Linux and real ARM64 pipeline builds/runs are the experimental acceptance; T22 native/sanitizer calibration remains the referenced invariant baseline, not a newly claimed E01 sanitizer run.

The original accepted T22 APK `4b635774337dac2b8b921f3fcf36a4bb1e211de55422d3b3cc41ac27c63a10e4` was reinstalled. Installed APK/native hashes match its build manifest, KernelSU grant remains valid, accepted history is byte-identical at packets [318,318] and bytes [19152,19152], runtime is stopped, and no VPP/tcpdump process, owned NFQUEUE rule, active TUN or E01 device scratch remains. Android netd may retain its own inactive tun0 accounting chains; they are not a Product-owned active TUN. See `device-restoration/`.

Initial review found CPU settlement-window omissions, weak byte/direction/freshness oracles, cleanup error short-circuiting and missing Linux isolation checks. These are fixed with closed resource windows, independent negative mutations, guarded cleanup and network-namespace witnesses. Follow-up findings on retained peak-memory samples, freshness poll validity and partial overlay rollback are fixed. Final Standards and Spec review outcomes are recorded in the separate review report. All 34 pre-existing dirty files are preserved exactly.

No user result decision has yet been recorded. E01 remains In Progress and T23 remains blocked.
