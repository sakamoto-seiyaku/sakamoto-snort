# Post-reconnect old single flow and conditional current APK

Date: 2026-10-22. Base checkout`d43dd3e0b531dae5e40a10a56d1bb63b323e3b75`.

The exact old single-flow configuration delivered **306.74 and333.05Mbps**, both collectorCOMPLETE with errors0/timeouts0 and all strict gates passing. Their arithmetic mean is**319.89Mbps**. The user requested testing the current APK only if the old single-flow result returned to approximately500Mbps. The pre-frozen operational condition was both old windows qualified and mean≥480Mbps; it was not met. **Current APK stage:SKIPPED; zero current windows executed.**480Mbps is only the frozen branching rule, not a hardware limit or Product acceptance target.

## Old single-flow results

| Window | D bytes | Actual seconds | D Mbps | Pre Tx/Rx Mbps | After Tx/Rx Mbps | Probe samples / p99 upper |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| postwifi-old-single-1 | 766857904 | 20.000491017 | 306.735631 | 1814/2161 | 2041/2161 | 615 / 58.8ms |
| postwifi-old-single-2 | 832657320 | 20.000885549 | 333.048181 | 1814/2401 | 2041/2161 | 546 / 47.0ms |

The unchanged TCP-fixed helper counts D download bytes only, excluding E probe reply bytes. Mbps is`bytes×8/((end_monotonic_ns-start_monotonic_ns)/1e9)/1e6`. Both20sD1E1windows ran exactly once, with no retry or additional Wi-Fi toggle. Before each collector, after frequency readiness, savedOpenwrt_5G had192.168.4.151,802.11ax,5180MHz,RSSI−52dBm and host192.168.4.5 ping success. Raw status/IP/ping and post-window status are retained; no PHY-rate threshold or opportunistic reassociation was used.

The recorded negotiated PHY rates remained high while single-flow payload throughput stayed near300Mbps. The earlier pre-toggle low-throughput cohort also recordedTx1921/Rx2401Mbps, matching the first preflight in the separately requested post-toggle4Dcohort. Thus the observations do not establish that negotiated Wi-Fi rate aged down to300Mbps, or isolate a reconnect effect. The preceding [4/64-flow and separate post-reconnect4Dmeasurements](2026-10-22_OLD_500_MULTIFLOW_MAXFREQ.md) have different concurrency/tuples/timing and their failed gates remain explicit. PHY rate is not application payload capacity; no direct-path control or bottleneck diagnosis was added here.

## Frozen configuration and evidence

[Protocol](../../build-output/postwifi-single-old-conditional-current-20261022-plan/protocol.json) SHA256`73f78c782102930054bbcfd01bde22964d4129a881a66796a8f860be377dc2c2` was frozen before the stage. Exact oldAPKb92e5120…, original12native hashes, Product source closure8318c4c9…, rules5bd3d784…, unchanged old collector4483d422…, Android helper5321c45d…/hostebac6c3f… and retained helper C source99bd217b… match the [historical replay identities](2026-10-22_OLD_500_MAXFREQ_REPRODUCTION.md). [Frozen tool hashes](../../build-output/postwifi-single-old-conditional-current-20261022/frozen-tools.json) cover the driver, wrapper, preparation and guard. No Product/helper/collector source modification, build or cache mutation occurred. The output-only wrapper retains exact raw CLI responses before unchanged strict validations.

Historical N2 topology is mainCPU0, owner0+TUNCPU1, bulk owner1CPU2, timed helper main/receiverCPU3. Source pairs31156/31157and31160/31161 were absent fromTCP/TCP6includingTIME_WAIT before their windows. Both target bulk/probe FlowEntries had UID2000, owner1/owner0, ALLOW/rule0/revision976 and canonical hash consistency. Old32768-byte send/ring/window, MTU10000/MSS9940,2048×10240pool,32primary credits,64/128primary/completion slots, scalar capture1/read budget64 remain unchanged, with batch/progress/buffer experiments off. The old250ms unbound2threads×8D+1Ewarmup joins before the original warm UID/peer gate and timed connections. Exact old rules remained unchanged; existing offline export is empty at revision976. One new identity-owned host peer served192.168.4.5:41722 and was cleaned up afterward.

Only policy0 minimum changed300000→its already permitted maximum1803000kHz, after an independent120sFIFO watchdog was ready. All positive bracketing policy0residency was1803000 (3356/3378ticks), all retained current/minimum/maximum samples were1803000, and both watchdogs ended normally with no expiry. Other policies, maximums, governors, thermal controls, IRQs and cpusets were not changed. Brackets include setup/stop and exceed20s; passive task/thermal snapshots are sequential rather than atomic. Bound roles do not make the entire phone little-only, and these counters are not energy or hardware-cycle measurements.

| Window | Main / owner0 / owner1 CPU seconds | Native sample coverage | Helper CPU seconds |
| --- | ---: | ---: | ---: |
| postwifi-old-single-1 | 0.02 / 6.31 / 7.53 | 19.661024s | 3.211754 |
| postwifi-old-single-2 | 0.00 / 6.77 / 8.07 | 19.667179s | 3.506389 |

All actual TID allowed masks and sampled processors match the declared placement. Whole-system CPU/IRQ/softIRQ, per-owner native counters, CPU sample intervals and helper CPU are retained separately. Both generation-specific native stop logs settle sessions, sockets, buffers, pending work, frames and obligations to zero. Endpoint delivery remains distinct from a lossless or policy-throughput release qualification.

## Conditional decision and restoration

[conditional-decision.json](../../build-output/postwifi-single-old-conditional-current-20261022/conditional-decision.json) records both raw client hashes, old audit hash, both qualified flags, arithmetic mean319.891906Mbps and false480Mbps trigger. The current7105cbd8…APK/N1/65528-byte/D1E0recipe was declared in the protocol, but was neither installed nor measured for this stage. No current-stage tool build, fallback, alternate placement or extra arm ran.

[Restoration](../../build-output/postwifi-single-old-conditional-current-20261022/restoration.json) isCOMPLETE: originalAPKcc329acc…, all12original native hashes, originalrules2b24ea26…, exact preferences and complete configuration/preferences bytes/modes/owners/tree mtimes/SELinux categories match the fresh initial backup. Parent`..`directory mtimes are outside the copied-tree comparison. Original policy0/4/6minimum/maximum/governors are restored. Runtime is stopped/mayBeActive=false, no VPP/helper/profiler/app/runtime-service PID or NFQUEUE entry remains, KernelSU root grant is intact, and the owned peer is gone. Latest user network preference is preserved: Openwrt_5G remains connected.

Recompute with`rtk proxy python3 build-output/postwifi-single-old-conditional-current-20261022-plan/audit-old.py`. [audit-old.json](../../build-output/postwifi-single-old-conditional-current-20261022/audit-old.json), both result/client/CPU/system/native/CLI files, frequency guards, link records and exact evidence inventory support direct review. The ten windows across this conversation are not pooled as one controlled experiment: the preceding eight windows and this separately authorized two-window stage retain separate protocols and statuses.
