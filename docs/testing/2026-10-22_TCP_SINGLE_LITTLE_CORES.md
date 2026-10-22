# Single TCP download on separate little cores

2026-10-22, Pixel6a `28201JEGR0XPAJ`, open parent SAKAMOTO-293.
User requested the current CPU placement and a single TCP download with the
roles on separate little cores. Three unprofiled20s repeats and one independent
199Hz DWARF window passed. No Product source, native build, APK or traffic helper
was changed. S308 remains Done; this measurement does not close S293.

## CPU placement and frozen workload

The device reports online CPUs0–7. CPUs0–3 have capacity160 and maximum
1803000kHz under shared cpufreq policy0; CPUs4–5 capacity498/max2253000kHz,
and6–7 capacity1024/max2802000kHz. Separate little CPUs share a frequency policy.

| Role | This run | Prior S308 download placement |
| --- | --- | --- |
| VPP main | CPU0, little | CPU0, little |
| Flow owner | N1 owner0 on CPU1, little | N2 owners on CPUs1/2, little |
| Dedicated TUN I/O | CPU2, little | CPU3, little |
| Download helper main and receiver | CPU3, little; mask `8` | CPU4, medium; mask `10` |

All three VPP TIDs had exactly the corresponding single CPU in
`Cpus_allowed_list`; every recorded monitor `last_cpu` matched. Independent
lifecycle snapshots also checked each VPP TID7–9 times (main9 times in repeat3)
and both helper TIDs5 times per window: allowed CPU3 and observed CPU3.
`/proc` processor values are sampled last CPUs, not a scheduler trace. Singleton
affinity constrains migration; it does not prove continuous execution.
The helper's independent CPU accounting includes its main and receiver threads.
Wi-Fi IRQs, kernel/system threads, monitor/CLI helpers and background work were
not moved. **This does not put all phone work on little cores.**

Frozen protocol:
`build-output/tcp-single-little-20261022-plan/protocol.json`, SHA256
`526e8b20945884eacbdee82a31611f67941913db799eece3c82c93663828cfe5`.
Raw topology is adjacent as `device-cpu-topology.txt`.

Only the adopted B artifact was used, based on commit `09e9e734`:

| Artifact | SHA256 |
| --- | --- |
| APK | `fbb5cd3bf98ad2df0304572bbdcf564b485336f3f4e8cfb6b8f76a348169c1a2` |
| Product plugin | `798c1f42a5768a1c21db4e7c02bad466bb1b272aced4b71d042bfc75ea8e075d` |
| Frozen collector `tests/benchmark/pixel_quick.py` | `63881bc630f594da0d4c2252d1b7fcff4f9ae0d725f9569b4d24327402f1c531` |
| Frozen Android socket-load helper | `075e780dd4c5aa1de34d654ef8ec7cd698399c2112638662e5f4913b2ba53015` |
| Adapted campaign driver, retained in raw evidence | `89c4c2782f19d2a3fe25927b010dd27b7a6573af6f15e46f1423972f264f08f9` |

The driver adapts the prior schedule/manifest to N1 and adds read-only per-TID
snapshots to its condition sampler. The collector/native/helper bytes remain
frozen. Installation verifies APK and every native ZIP member. No native build
or new dependency cache was needed.

One receiver thread, one persistent TCP `D` download from Host
`192.168.4.5:41723` to Pixel, source31000, no `E`/echo/probe connections.
Source31000 was absent from TCP/TCP6 including TIME_WAIT before each window;
all bounded120s checks returned within0.14s, without substituting ports.
A separate live2s warmup proved the UID2000/peer FlowEntry while active and
joined before timed collection. It uses separate ephemeral ports.
MTU10000/MSS9940,2048 buffers of10240 data bytes, unchanged rules, native48
credits and capture64 defaults; no diagnostic credit/capture overrides.
Test Wi-Fi was saved Openwrt_5G,192.168.4.151,5GHz/11ax; initial RSSI−52dBm,
reported link2041Mbps. Link rate is not delivered TCP capacity.

## Three unprofiled observations

100% CPU is one occupied core. VPP total sums main, owner and I/O on their
separate cores; about95% total does not mean an individual core is full.
Generator CPU is a separate process and is excluded from VPP total.

| Repeat | Delivered bytes | Download Mbps | VPP total% | Main0% | Owner1% | I/O2% | Generator3% | CPU coverage% | Estimated CPU s/GiB* |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 790221188 | 316.07 | 96.14 | 0.10 | 52.34 | 43.70 | 22.49 | 98.29 | 26.13 |
| 2 | 817565244 | 327.01 | 96.47 | 0.05 | 52.58 | 43.84 | 22.65 | 98.31 | 25.34 |
| 3 | 774725308 | 309.87 | 92.36 | 0.05 | 50.35 | 41.96 | 21.33 | 98.31 | 25.60 |

Actual client durations were20.00118/20.00101/20.00118s. Raw VPP CPU was
18.90/18.97/18.16s over monitor intervals19.65857/19.66369/19.66252s.
Generator getrusage deltas were4.497924/4.530438/4.265625 CPU s over their
client intervals. These are CPU occupancy, not energy or off-CPU wait.

*VPP CPU/GiB extrapolates the observed tick rate over the complete client
interval, assuming stationarity. The monitor covers98.29–98.31%, not the exact
full byte interval; these estimates are not exact whole-window CPU measurements.
Full raw monitor and client intervals are retained. No equal-throughput or
pure-affinity saving is established: there is no concurrent A arm, owner count
changed from the historical N2, and historical rates/environment varied.
The approximately500Mbps wireless reference is not a hard cap or pass target;
these observations do not establish a compute or radio bottleneck.

Each repeat had five frequency/thermal snapshots whose entire outer uptime
bracket lay within the client interval. Shared policy0 sampled ranges were
1197–1803/1197–1803/1197–1803MHz; LITTLE thermal-zone11 sampled ranges
42–45/44–47/45–48°C. These are sparse points, not per-core independent frequency
controls or complete thermal trajectories. Per-core raw time-in-state and
system CPU observations are retained before/after collection.
The lifecycle condition command took approximately1.5–3.3s wall time per pass,
plus a1s wait; wall duration is not its CPU overhead. No independent sampler
CPU-overhead control was measured. Read-only sampling and background work may
perturb results.

## Graph counters, memory and stop

Counter deltas below use the retained pre/post CLI brackets; they include their
bracket gap and are not exact packet counts for the client's byte interval.

| Window | Captured/submitted | Completed | Return/write attempts/success | Credit/enqueue rejects | Deferred/retries | Policy/runtime drops; errors; rejects; write failures |
| --- | --- | --- | --- | --- | --- | --- |
| Repeat1 | 88927 | 185171 | 96244 | 0/0 | 0/0 | all0 |
| Repeat2 | 93645 | 193112 | 99467 | 0/0 | 0/0 | all0 |
| Repeat3 | 87809 | 182223 | 94414 | 0/0 | 0/0 | all0 |
| Separate profile | 96725 | 201928 | 105203 | 0/0 | 0/0 | all0 |

All windows had one download stream with data, zero client errors/timeouts,
zero server send errors and zero output rejections. Helper instrumentation does
not report TCP retransmissions: zero Product drops does not prove zero network
loss or TCP retransmission. No probe/latency samples were requested.

Unprofiled VPP RSS peaks106233856/106156032/106041344 bytes; generator maxRSS
4784/4992/4956KiB. RSS is observed resident memory, not total reserved native
capacity. Each generation2555/2556/2557/2558 recorded owner stopped, graph/read
quiescence, TUN stop with pending/buffers/frames/obligations0 and fd−1. This is
scoped ordinary-load stop evidence, not a repeat of all prior fault campaigns.

## Independent profile and flamegraphs

The separate window delivered345.63Mbps with VPP97.26% (main0.05%, owner52.61%,
I/O44.60%) and generator21.98%. It is excluded from the three cost observations;
its throughput cannot demonstrate profiler overhead or a performance gain.

199Hz `cpu-clock`, DWARF:3848 records (main1, owner2093, I/O1754), no reported
lost or truncated samples. All six recorded userspace ELF IDs match supplied
symbols: Product plugin, libc, linker64, libsvm, libvlib and libvppinfra. Native
symbol ELFs strip to the exact frozen APK bytes. Four kernel/module/vDSO IDs
are device records only, not independently rebuilt or source-verified.

All observed leaf and observed-chain frames resolved in this profile; that does
not establish complete unwinding. The existing classifier leaves54.32% of
owner and20.64% of I/O sampled periods outside its named phases. I/O's
completion/write/free family is52.57% of its sampled periods; its narrower
kernel-leaf TUN-write-return group is46.41%. These groups are different views,
not additive or whole-path fractions. Owner transport is22.60%; the remaining
owner work is only partially classified. All are on-CPU samples, not syscall
wall duration or scheduler waiting.

- Flame index: `build-output/tcp-single-little-profile-20261022/index.html`.
- Owner and I/O SVG/folded stacks, CPU chart, attribution and DSO audit:
  `build-output/tcp-single-little-profile-20261022/profile-single-little/`.
- Raw campaign/conditions/manifest/client/monitor/CLI/stop data and numeric/TID
  audit: `build-output/tcp-single-little-20261022/`.

## Restoration, review and publication

Final restoration audit PASS:
`build-output/tcp-single-little-20261022/restoration/result.json`.
Original APK `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`,
original rules `2b24ea2630d231e9f52f014aa8a64ae1ba593d1f1371389f05c92b97517a450f`,
saved CU_7WFb_5G, stopped/no VPP/runtime-service/NFQUEUE/hooks/test helper or
profiler. Owned Host endpoint exited and is absent.

Only this dated report is a repository change. No Product/collector/tool source
was changed, so the prior69-test functional suite was not repeated. The four
new windows, exact affinity/CPU arithmetic, graph deltas, raw profile replay,
identities and restoration receive independent explicit GPT-6.1 Spec/Standards
review before commit. Final proof is retained in
`build-output/tcp-single-little-20261022/closeout.json`.
All raw evidence, APKs, matching symbols and flames are local gitignored
artifacts; no portable archive was created.

The attempted Plane scope comment was rejected by automatic approval review:
it did not accept measurement permission as authorization to disclose the
specific internal scope, artifact hashes and operational details. No retry or
bypass occurred. A local scope/results draft is retained for user review; S293
stays open and S308 stays Done. Tracker publication remains pending permission.

### Later publication authorization

After the measurement was committed, the user explicitly authorized Plane
publication and further analysis. The exact completed-results draft was
published once to S293 as comment
`63f13439-4da2-429c-9811-ddc656f81145`; normalized content read-back PASS and
parent remains open. Receipt:
`build-output/tcp-single-little-20261022/plane-publication-approved-receipt.json`.
This resolves the earlier publication block without changing the historical
rejection or measurement evidence.
