# Historical 500 Mbps configuration at fixed little-cluster frequency

Date: 2026-10-22. Base checkout: `d43dd3e0b531dae5e40a10a56d1bb63b323e3b75`.

The exact retained October 21 ordinary VPN APK/configuration delivered **313.86 and 303.05 Mbps** in two 20-second downloads with policy0 fixed at 1.803 GHz. The historical 496.62/535.54 Mbps pair was not reproduced. Both original collector windows completed with no client errors/timeouts and passed UID, flow ownership, native capacity, stop and rules-identity gates. This observation cannot identify a Wi-Fi, phone, frequency or Product bottleneck: the historical pair ran at another time with dynamic frequency, and this experiment has no simultaneous direct-path control.

## Results

| Window | Delivered bytes | Actual seconds | Mbps | Historical Mbps | Probe p99 upper | VPP CPU seconds / sampled seconds | Helper CPU seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| old500-maxfreq-B1 | 784747748 | 20.002354136 | 313.862155 | 496.62 | 51.1 ms | 14.12 / 19.856995 | 3.259988 |
| old500-maxfreq-B2 | 757648624 | 20.000364186 | 303.053931 | 535.54 | 54.3 ms | 13.74 / 19.659931 | 3.173898 |

Mbps is `bytes × 8 / ((end_monotonic_ns-start_monotonic_ns)/1e9) / 1e6`, using D download bytes only; the original helper excludes E probe bytes. There is one bulk download and one light probe per window, one helper thread, source-port pairs31156/31157 and31160/31161. The helper's probe interval remains its original20ms default;606/603 latency samples are retained. No500Mbps acceptance threshold was introduced. Native CPU samples cover19.857/19.660s within the actual20.002354/20.000364s client windows; estimated full-window VPP CPU/GiB is19.4613/19.8096. Generator CPU is measured separately and is16.30%/15.87% of one core. Neither CPU ticks nor frequency residency is an energy or hardware-cycle measurement.

## Frozen historical conditions

The user requested replaying yesterday's version/configuration with frequency still fixed. Design was frozen before execution in [protocol.json](../../build-output/old500-maxfreq-repro-20261022-plan/protocol.json), SHA256 `3bdc26e6962e284191541ce1af5b326348fa9b0b21928a7ee52bb5d7e794af6b`.

| Input | SHA256 |
| --- | --- |
| APK | `b92e51202821d64e2a5571dea02998fcee19eaceaa1370e9348e407964a94a78` |
| Product source closure, recorded by original build | `8318c4c9eb778517157eff41d52f0743cc1dec97e631eb720d9fa9387986e50c` |
| Native Product plugin | `65f33fae5451f6218f2c8cd974f2f1d13a088352e0f3316cfae1e2fae2df2f0f` |
| Old rules binary | `5bd3d78401ddfa51e162a0167c0413eae6de826b4ecf7ca2d11dfa19c98a7b35` |
| Unchanged collector | `4483d42241a53adf6ad65d8a2aae2c984f30a02ea74994db9d9cb640608a6519` |
| Android helper | `5321c45d3cc3d5898efa461be6dba24304e344739b6ce8f52309da4962e27361` |
| Host helper | `ebac6c3fc9a8659d5ca5ba1523403fc93b1d0c1981a8e116736f6bce9946ed85` |
| Retained Android helper C source | `99bd217bef6171bc03bd2d0d88497e49fe767a598c120095c46244f7f330a690` |

All12installed native hashes matched the original build manifest before both cells. No Product/helper/collector build or Product-source modification occurred. The wrapper points the collector's source-identity check at its retained old helper C source; it does not import implementation into Product. [Frozen tool hashes](../../build-output/old500-maxfreq-repro-20261022/frozen-tools.json) cover the driver, preparation, guard and wrapper before first timing. The collector file itself is unchanged. The wrapper adds assertions over existing CLI replies and no extra device export action.

Topology is the historical N2 owner layout: mainCPU0, owner0 plus TUN onCPU1, bulk download owner1 onCPU2, timed helper main and receiver onCPU3. There is no dedicated I/O worker. Actual TID singleton allowed masks and sampled processors match all roles; target UID2000 bulk/probe FlowEntries show worker1/worker0, revision976, rule0, ALLOW. The exact old rules binary stayed unchanged before/after each collector, and its retained offline export has no rules/groups/bindings/edges/lists. Current installed starting rules were replaced reversibly only while stopped, without manufacturing a revision or modifying the rule API.

Old defaults are32768-byte TCP send/ring and receive window, MTU10000/MSS9940,2048×10240-byte native buffer pool, primary credits32, primary/completion slots64/128, ordinary publication/reclaim16, completion retry64, return credits128, scalar capture submission1 and read budget64. Batch/progress/buffer experiments are off. Original unbound250ms warmup uses2threads×8bulk plus1probe each, joins before original CLI/UID gates and timed connections. Both intended ports were absent from TCP/TCP6 including TIME_WAIT immediately before each run. One newly owned host server on192.168.4.5:41722 served both cells, with PID/starttime/exe/argv/hash retained and identity-owned cleanup. No profiling or path probe was used.

## Frequency and environment

Before each cell, an independent device FIFO watchdog was ready before policy0 minimum changed from300000 to its existing maximum1803000kHz. Maximum, governors, other policies, cpusets, IRQ placement and thermal controls were not changed. Guard end follows collector final snapshots/native stop and precedes original APK restoration. Both guards returned normally with no120s expiration. Fresh original policy0/4/6 settings were restored after each window and at final audit.

All9retained current/minimum/maximum samples per cell report1803000kHz. Bracketing policy0 time_in_state deltas are3395/3404ticks at1803000, zero at every other state. These brackets include setup/stop, so their totals are not the20s client duration. Passive samples record all policy frequencies, thermal values, VPP/helper task status/stat/schedstat and device uptime; each sample is a sequential shell observation, not an atomic snapshot. The nominal1s sampler waits after its command, yielding roughly4s spacing during task collection. Exact monitor records and task evidence are retained in the raw files and audit.

The pre-campaign test network wasOpenwrt_5G,192.168.4.151,5GHz5180MHz,802.11ax,RSSI−52dBm, negotiated Tx1921/Rx2401Mbps. These are one pre-campaign association/PHY observation, not measured payload capacity or per-window radio telemetry. LITTLE thermal readings span43–45°C inB1 and45–58°C inB2; battery26.9–27.0/27.1°C. The whole-system CPU snapshots record activity beyond the bound Product/helper tasks, including IRQ/softIRQ and other clusters. Small-role bindings do not make the entire phone little-only. These data establish neither an isolated frequency gain nor an energy saving.

## Restoration and retained failure

Both timed cells completed on their first attempt. The original driver's final restoration assertion failed because Android root `cp -a` through `/data/local/tmp` lost app-data SELinux category labels. The failure remains in [campaign.json](../../build-output/old500-maxfreq-repro-20261022/campaign.json), initial/final metadata and the first restoration output. This was a restoration issue after both measurements; there were no additional timed retries.

[Recovery evidence](../../build-output/old500-maxfreq-repro-20261022/restoration-recovery.json) records applying the exact initial SELinux label `u:object_r:app_data_file:s0:c72,c266,c512,c768` to the copied configuration/preferences trees while stopped. Original bytes, modes, owners, tree mtimes and SELinux labels then matched; parent`..`directory mtimes are outside the copied-tree comparison and changed through normal runtime file operations. The entire original configuration and preferences remain preserved in a local tar and device backup.

Final identity is original APK`cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`, all original12native hashes, original rules`2b24ea2630d231e9f52f014aa8a64ae1ba593d1f1371389f05c92b97517a450f`, exact original preferences, and original policy0/4/6 minimum/maximum/governors. KernelSU root grant remained intact. Runtime is stopped, mayBeActive=false; VPP, helper, profiler, app and runtime-service PIDs are absent, NFQUEUE is empty, and the owned host peer is gone. [Final network readiness](../../build-output/old500-maxfreq-repro-20261022/final-network-ready.json) confirms originalCU_7WFb_5G and DHCP192.168.1.104. Backups and raw evidence are retained; no caches were altered.

## Recompute and evidence

Run `rtk proxy python3 build-output/old500-maxfreq-repro-20261022-plan/audit.py`. The [audit.json](../../build-output/old500-maxfreq-repro-20261022/audit.json) independently recomputes throughput, old target ownership/policy, native CPU summary, frequency residency, sampled task placement, system CPU deltas and native stop debt. Per-cell result/client/peer/cpu/system snapshots, before/after CLI, retained native stop logs, operation logs and conditions JSONL live under [raw evidence](../../build-output/old500-maxfreq-repro-20261022/). Original campaign status remainsINCOMPLETE to retain its caught restoration failure; audit status isCOMPLETE_WITH_RESTORATION_RECOVERY. The raw evidence and recomputable audit support direct review.
