# Historical VPN configuration: 4 and 64 downloads at fixed little frequency

Date: 2026-10-22. Base checkout`d43dd3e0b531dae5e40a10a56d1bb63b323e3b75`.

Observed delivery was313.86/303.05Mbps for the preceding1-flow pair, **348.63Mbps at4flows**, and **453.57Mbps at64flows** in the collector-complete windows from these sequential cohorts. Each second repeat failed a strict flow/UID gate and remains an endpoint-only diagnostic. No failure was retried. These measurements cannot establish a Wi-Fi or whole-phone ceiling: they include the VPN, fixed CPU placement, old transport profile, helper and changing device/network conditions, without a simultaneous direct-path control.

The user's subsequent request to switch Wi-Fi off/on and reconnect savedOpenwrt_5G was completed **after all four timed windows**. FinalOpenwrt_5G has DHCP192.168.4.151 and host192.168.4.5 is reachable. No window from the initial four-window campaign ran after that toggle. A subsequent separately authorized two-window4D cohort is reported below; these sequential observations do not isolate a reconnect effect.

## All declared windows

| Window | D bytes | Actual seconds | D Mbps | Status | Client errors / timeouts | Probe samples / p99 upper |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| old500-maxfreq-4D-1 | 871934724 | 20.008080007 | 348.633042 | Collector COMPLETE | 0 / 0 | 484 / 113.0ms |
| old500-maxfreq-4D-2 | 885203664 | 20.000888071 | 354.065744 | UNQUALIFIED diagnostic | 0 / 1 | 13 / 47.0ms |
| old500-maxfreq-64D-1 | 1134112380 | 20.003490245 | 453.565799 | Collector COMPLETE | 0 / 0 | 1060 / 299.0ms |
| old500-maxfreq-64D-2 | 1130217984 | 20.004019663 | 451.996350 | UNQUALIFIED diagnostic | 0 / 1 | 1039 / 324.4ms |

D Mbps is `client.bytes ×8 / actual monotonic seconds /1e6`. The unchanged old helper counts only D download bytes in TCP-fixed mode; E probe reply bytes contribute latency samples, not `client.bytes`.4D uses1receiver thread and1Eprobe;64D uses4receiver threads×16D each and4Eprobes. All timed helper main/receiver TIDs are bound toCPU3. The helper's original20ms probe interval is unchanged. The reported p99 values are histogram upper bounds;4D-2 has only13samples and a timeout, so its47ms bound is not evidence of improved latency.

4D-2 failed after the completed client/system snapshots when the post-window CLI showed probe31220 as a40-byte SYN entry with UID4294967295 instead of2000. It also had one client timeout. The original wrapper raised before the collector saved the complete afterCLI/peer/CPU summary; the offending entry remains in the exact error, and the original200ms native CPU monitor was recovered after normal stop. Full post-window target distribution is unavailable for this cell.

The frozen [continuation amendment](../../build-output/old500-multiflow-maxfreq-20261022/continuation-amendment.json) allowed only the two still-unrun64Dwindows, keeping original protocol/driver/wrapper hashes immutable. A new output-only wrapper saves unchanged CLI replies before the identical validations; it adds no device action or packet change. A new owned peer was started after the original peer had been cleaned up.64D-2 then failed the same strict validation because source31415 had no final FlowEntry; its rawCLI is retained. It also had one timeout. The other63Dentries and all4Eentries were observed with UID2000/canonical owner/ALLOW/rule0/revision976. These failures were not waived or silently substituted.

## Placement and CPU

| Window | Main CPU-s | Owner0 CPU-s | Owner1 CPU-s | Native sample coverage | Helper CPU-s (% one core) | Observed D split owner0/1; E split |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| old500-maxfreq-4D-1 | 0.01 | 8.89 | 5.07 | 19.677811s | 3.197167 (15.98%) | 2/2; 0/1 |
| old500-maxfreq-4D-2 | 0.02 | 8.47 | 5.30 | 19.692735s | 3.258973 (16.29%) | Unavailable after gate failure |
| old500-maxfreq-64D-1 | 0.01 | 13.82 | 10.48 | 19.688312s | 6.178150 (30.89%) | 32/32; 2/2 |
| old500-maxfreq-64D-2 | 0.01 | 13.93 | 10.41 | 19.725398s | 6.151017 (30.75%) | 32/31; 2/2; one D entry missing |

Native CPU uses only monitor samples inside each actual client window; the failed-cell monitors were recovered without rerunning traffic. The helper's process CPU is separate. Sparse passive task samples verify singleton allowed masks and sampled processors for mainCPU0, owner0+TUNCPU1, owner1CPU2 and every helper TIDCPU3. Canonical hash modulo2 determines each observed owner; no ports were selected for balancing or remapped. TUN work and both owners consume CPU; these averages do not by themselves locate a bottleneck. Whole-system `/proc/stat`, per-CPU IRQ/softIRQ, task tick/schedstat and owner counters remain in the raw snapshots/audit. IRQs/cpusets were not moved, and other clusters remained active.

The4D-1 primary-credit rejection/runtime-drop counts were28both before and after the window (zero bracketing delta).64D-1 counts rose9→26 (delta17), and64D-2 rose0→16 (delta16); these are native diagnostic brackets, including nearby setup/CLI time, not a precisely synchronized packet-loss rate.4D-2 had7before; its full afterCLI is unavailable. All four retained native stop logs settle sessions, sockets, pending work, buffers, frames and obligations to zero. Collector-complete delivery is not a lossless or policy-throughput release qualification.

## Frozen inputs and frequency

[Protocol](../../build-output/old500-multiflow-maxfreq-20261022-plan/protocol.json) SHA256`711cf53590dd0f251777080f5c03c7930e8740a71e77e378236635930b90e736` was frozen before timing. APK`b92e51202821d64e2a5571dea02998fcee19eaceaa1370e9348e407964a94a78`, recorded Product source closure`8318c4c9eb778517157eff41d52f0743cc1dec97e631eb720d9fa9387986e50c`, all12native hashes, old rules`5bd3d78401ddfa51e162a0167c0413eae6de826b4ecf7ca2d11dfa19c98a7b35`, unchanged collector`4483d42241a53adf6ad65d8a2aae2c984f30a02ea74994db9d9cb640608a6519` and helpers are identical to the [two-window historical replay](2026-10-22_OLD_500_MAXFREQ_REPRODUCTION.md). Frozen complete tool hashes and continuation hashes are retained. No Product/source/helper/collector build or cache change occurred. The wrapper's source-identity check points at the retained old helper C snapshotSHA99bd217b…, not today's changed helper source.

Historical N2 topology and32768-byte send/ring/window, MTU10000/MSS9940,2048×10240pool,32primary credits,64/128primary/completion slots, scalar capture1/read budget64 remain unchanged, with batch/progress/buffer experiments off. The exact oldrules snapshot and existing offline export have empty effective rule/group/binding/list collections at revision976. Rules were copied only while stopped; collector identity checks confirm they remained unchanged. The old unbound250ms warmup (2threads×8D+1Eeach) joins before the unchanged warm UID/peer gate and timed connections. Every declared source port was absent fromTCP/TCP6includingTIME_WAIT before its window. All four planned20s client windows ran exactly once.

Only policy0 minimum was raised300000→its existing maximum1803000kHz after the independent120s FIFO watchdog was ready. All positive bracketing residency occurred at1803000 (3414/3408/3465/3465ticks); every retained policy0 current/minimum/maximum sample is1803000. All four watchdogs ended normally without expiry and restored original policy0/4/6minimum/maximum/governors. Residency brackets include setup/stop and are not20s timing measurements. Passive thermal/task reads are sequential, roughly4s apart during task collection, not atomic snapshots. LITTLE thermal spans42–47,45–54,42–52and47–55°C respectively; battery27.2–27.8°C overall. Per-cell before/afterWi-Fi status records association, RSSI and negotiated PHY rates; PHY rate is not measured application capacity. No energy/hardware-cycle or isolated frequency benefit is claimed.

## Wi-Fi operation and final state

The latest user [Wi-Fi amendment](../../build-output/old500-multiflow-maxfreq-20261022-plan/wifi-reconnect-user-amendment.json), SHA256`474f95c97608a94e27bd7d08aa08a6d635bac44dcafce604f3e4832d30a4df5f`, overrides the earlier finalCU_7WFb_5G target.64D-2 timing had already started when the request reached the sole operator, so it completed before the radio changed. After native stop, frequency restoration, original APK/configuration/preferences restoration and owned-peer cleanup, Wi-Fi was disabled (disabled status retained), enabled, then savedOpenwrt_5G selected through fresh UI bounds. [Reconnect evidence](../../build-output/old500-multiflow-maxfreq-20261022/wifi-reconnect/result.json) includes before/off/on/after status/IP/link, XML, screenshot, DHCP192.168.4.151 and successful two-packet host ping. No remaining windows from the initial four-window protocol existed, and no extra timed run was added to that campaign. The later explicit request for two post-reconnect4Dwindows has its own frozen protocol/dataset below.

[Final nonnetwork restoration](../../build-output/old500-multiflow-maxfreq-20261022/continuation-restoration.json) verifies originalAPKcc329acc…, all12original native hashes, originalrules2b24ea26…, exact original preferences, complete configuration/preferences bytes/modes/owners/tree mtimes/SELinux categories, and original CPU policies. Parent`..`directory mtimes are outside the copied-tree comparison. Root grant is intact; runtime is stopped/mayBeActive=false, with no VPP/helper/profiler/app/runtime-service PID or NFQUEUE entries. Both identity-owned peers are gone. Complete initial and continuation backups and all failure evidence remain retained.

## Recompute

Run `rtk proxy python3 build-output/old500-multiflow-maxfreq-20261022-plan/audit.py`. [audit.json](../../build-output/old500-multiflow-maxfreq-20261022/audit.json) recomputes all four endpoint rates and flags two qualified/two failed windows, verifies frequency residency/guards, actual task placement, available per-flow ownership, native CPU, systemCPU and stop debt. Raw campaign/continuation statuses remainINCOMPLETE because each retains its failed window; restoration and user-requested reconnect areCOMPLETE. The raw evidence and recomputable audit support direct review.

## Separately authorized post-reconnect4D repetitions

After the reconnect was complete, the user explicitly requested four-flow testing again and inspection of negotiated Wi-Fi rates before testing. This is a separate two-window cohort, not a retry of the failed cells above. [New protocol](../../build-output/old500-postwifi-4flow-maxfreq-20261022-plan/protocol.json) SHA256`3beab7140fa48e7c6b0ca78d364610c90d3ad2030048539b02e1b199b54623b8` was frozen before execution; [new raw dataset](../../build-output/old500-postwifi-4flow-maxfreq-20261022/) and all tool hashes are separate. Only ports31500–31504and31516–31520were used. Both20s4D1Ewindows ran once, with the identical old APK/helper/collector/warmup/topology/defaults and independent fixed1.803GHz guards. No64D/direct/profile/layout test or additional radio toggle was added.

Immediately before each collector, after frequency readiness, rawWi-Fi status, IP and one-packet host reachability were retained. Both associated with savedOpenwrt_5G,192.168.4.151,802.11ax,5180MHz,RSSI−52dBm; no negotiated-rate threshold was imposed. The initial fresh preflight wasTx1921/Rx2401Mbps. These PHY values are association observations, not application payload capacity.

| Post-reconnect window | Pre Tx/Rx Mbps | After Tx/Rx Mbps | D bytes / actual seconds | D Mbps | Status | Probe samples / p99 upper |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| old500-postwifi-4D-1 | 1921/2401 | 1814/2161 | 1353976532 / 20.002225718s | 541.530348 | UNQUALIFIED diagnostic | 308 / 103.6ms |
| old500-postwifi-4D-2 | 2161/2161 | 1921/2161 | 1236609164 / 20.001067514s | 494.617265 | Collector COMPLETE | 365 / 96.5ms |

Both clients reported errors0/timeouts0. Postwifi4D-1 nevertheless remains unqualified: the final probe31504entry had UID4294967295 as a40-byte SYN, failing the unchanged UID2000gate. The rawCLI was saved before validation, and its original native CPU monitor recovered after stop. All4Dentries had the expected UID/canonical ownership/policy; the probe's final UID did not pass. Postwifi4D-2 passed all5target tuple gates and the original collector. Both observed bulk splits were2/2owners, with the probe onowner1; this distribution was observed, not selected.

Native main/owner0/owner1CPU seconds were0.00/12.34/5.81 over19.887990s sampled coverage in postwifi4D-1, and0.01/10.48/8.06 over19.686369s in postwifi4D-2. Helper CPU was4.809265/4.691985s (24.04/23.46% of one core). Actual allowed masks and sampled processors again matched main0/owner0+TUN1/owner1CPU2/helperCPU3. Primary rejection and runtime-drop counts were0before and after both brackets. Native stop debt, buffers, sessions and sockets settled normally in both generations. LITTLE thermal readings span43–51°C and45–52°C respectively; battery27.4–27.5°C. Only positive policy0residency was at1803000 (3469/3453ticks), all sampled cur/min/max were1803000, and both guards restored normally without expiry.

Observed4Ddelivery was348.63Mbps with one initial collector-complete window before reconnect and494.62Mbps with one collector-complete window afterward. The companion rates354.07and541.53Mbps remain unqualified diagnostics with their failures retained. This sequence is compatible with changing conditions; it does not isolate a reconnect benefit or prove a Wi-Fi/phone ceiling. Source ports, canonical flow identities, timing and thermal/network conditions differ across these independently requested cohorts.

[Post-reconnect restoration](../../build-output/old500-postwifi-4flow-maxfreq-20261022/restoration.json) isCOMPLETE: originalcc329APK/all12native, original2b24rules, complete original configuration/preferences bytes/modes/owners/tree mtimes/SELinux categories and original policy0/4/6frequencies/governors are restored. Runtime is stopped/mayBeActive=false, no VPP/helper/profiler/app/runtime-service PID or NFQUEUE remains, root grant is intact and the identity-owned host peer is gone. Latest user preference is honored: Openwrt_5G remains connected. The campaign remainsINCOMPLETE because postwifi4D-1failed its UIDgate; restoration success does not erase that failure.

Recompute this separate cohort with `rtk proxy python3 build-output/old500-postwifi-4flow-maxfreq-20261022-plan/audit.py`; [post-reconnect audit](../../build-output/old500-postwifi-4flow-maxfreq-20261022/audit.json) flags one complete/one failed window, verifies rates, CPU, task placement, frequency and native stop debt, and retains immediate precollector link evidence. The earlier protocols/data/statuses remain unchanged.
