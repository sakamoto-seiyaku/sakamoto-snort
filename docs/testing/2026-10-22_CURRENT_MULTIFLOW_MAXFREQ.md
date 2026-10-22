# Current APK multiflow at fixed little-cluster frequency

Date:2026-10-22. Frozen base checkout`8c4234c6e0f782c21e33b0706bd6335ceb5fc921`.

The current APK delivered **479.31/461.85Mbps with4downloads**, both collectorCOMPLETE. The64-download windows recorded **440.52/469.51Mbps endpoint delivery**, but both failed the strict final UID gate and remain unqualified diagnostics. Every client reported zero errors/timeouts. This sequential sample does not establish a Wi-Fi or phone ceiling; increasing concurrency beyond4did not produce a qualified higher-throughput result here.

The user requested continuing under the conditions of the immediately preceding [current single-flow tests](2026-10-22_POSTWIFI_CURRENT_SINGLE.md). Those post-retoggle single-flow windows were257.50/300.00Mbps. The same current configuration, fixed frequency and savedOpenwrt association were retained; no additional Wi-Fi toggle or reassociation occurred in this multiflow stage.

## All declared windows

| Window | D bytes | Actual seconds | D Mbps | Status | Pre Tx/Rx Mbps | After Tx/Rx Mbps |
| --- | ---: | ---: | ---: | --- | ---: | ---: |
| current-maxfreq-4D-1 | 1198585272 | 20.005181040 | 479.309943 | Collector COMPLETE | 1633/2401 | 2041/2401 |
| current-maxfreq-4D-2 | 1154713236 | 20.001412120 | 461.852685 | Collector COMPLETE | 1814/2401 | 1729/2161 |
| current-maxfreq-64D-1 | 1101886008 | 20.010492686 | 440.523290 | UNQUALIFIED diagnostic | 1814/2161 | 1921/2161 |
| current-maxfreq-64D-2 | 1174156288 | 20.006487559 | 469.510216 | UNQUALIFIED diagnostic | 1814/2161 | 2041/2161 |

Rates are`D bytes×8/actual monotonic seconds/1e6`.4Duses1receiver thread×4downloads;64Duses4receiver threads×16downloads. The unchanged helper confirms4/64connections and4/64streams with data, with0Eprobes and0latency samples. Every immediate precollector snapshot, taken after frequency readiness, showsOpenwrt_5G,192.168.4.151,802.11ax,5180MHz,RSSI−52dBm (−51in the final window) and host ping success. Negotiated PHY rates are not measured payload capacity.

Both4Dwindows passed all intended tuple UID2000/owner0/ALLOW/rule0/revision1132checks. Each64Dwindow had all64target entries in the final rawCLI, but source31848/31925 respectively had UID4294967295 as a40-byte SYN; the other63entries met the UID/policy/owner checks. The wrapper saved exact CLI before raising. These final snapshot failures do not erase the helper's endpoint delivery, and zero helper timeouts do not waive the strict gate. Both failures remain in result/campaign JSON. No retries or extra windows ran.

## CPU, counters and fixed conditions

| Window | Main / owner / I/O CPU seconds | Native sample coverage | Helper CPU seconds (% one core) |
| --- | ---: | ---: | ---: |
| current-maxfreq-4D-1 | 0.01 / 8.52 / 6.30 | 19.886553029s | 3.786150 (18.93%) |
| current-maxfreq-4D-2 | 0.01 / 8.33 / 6.19 | 19.682676279s | 3.705308 (18.53%) |
| current-maxfreq-64D-1 | 0.01 / 13.82 / 8.96 | 19.685877329s | 6.110693 (30.54%) |
| current-maxfreq-64D-2 | 0.01 / 14.34 / 9.37 | 19.682431325s | 6.338197 (31.68%) |

CPU comes from monitor samples strictly inside actual client intervals, with exact begin/end and coverage retained. Failed-cell monitors were recovered read-only after normal stop; traffic was not rerun. Actual task allowed masks/sampled processors match mainCPU0, owner0CPU1, dedicated TUN I/OCPU2 and helper main/all receiversCPU3. System CPU/IRQ/softIRQ, task ticks/schedstat and helper process CPU are separate raw evidence; bound tasks do not make the whole phone little-only.

Primary credit-rejection and TUN runtime-drop counters stayed0in both4Dbrackets.64D-1went0→369 and64D-2went74→375 (deltas369/301). These brackets include nearby setup/CLI time; they are not synchronized packet-loss rates. TUN write-failure counters remained0. Generation-specific native stop logs settle sessions/sockets/pending work/buffers/frames/obligations to zero in all four windows. Endpoint delivery is not a lossless or Product release qualification.

[Protocol](../../build-output/current-multiflow-maxfreq-20261022-plan/protocol.json) SHA256`332072b6b09dd8ea6c16b07d065c5bae6449ffb9118a5872e311a21dfc3a8b03` was frozen before timing. The exact current7105APK, Product closure98b2c06c…, all12native hashes, Android helper075e780d…, host1debf988…, collector63881bc6… and source45d3b6fd… match the full [current single-flow identities](2026-10-22_POSTWIFI_CURRENT_SINGLE.md). Frozen new driver/wrapper/guard/audit identities are retained. No Product/helper/collector build/source change, cache mutation, default override, profiler, direct arm or alternate placement occurred.

N1native defaults remain65528send/ring,32768receive,48primary credits, capture64/shared64/native return frame256, MTU10000/MSS9940 and2048×10240pool, with TCP experiments off. Every cell starts a fresh ordinary VPN lifetime. The existing current2s live UID/peer warmup uses the declared thread/flow count with0Eprobes and joins before timing. All declared ports31700–31703,31716–31719,31800–31863and31900–31963were absent fromTCP/TCP6includingTIME_WAIT before their windows, bounded120swithout substitution. Endpoint remains192.168.4.5:41723; N1canonical ownership is owner0, without remapping.

Only policy0minimum was raised300000→its existing maximum1803000kHz after each independent120sFIFO watchdog was ready. All positive bracketing residency was1803000 (3466/3464/3491/3524ticks), every retained current/minimum/maximum sample was1803000, and all guards restored normally without expiry. Other policies/governors/maximums, thermal controls, IRQs and cpusets were unchanged. Brackets include setup/stop and exceed20s. LITTLE thermal ranges were42–46,45–52,46–52and48–56°C. Sequential thermal/radio/system drift is recorded; no isolated Wi-Fi/concurrency mechanism, energy or hardware-cycle claim follows.

## Restoration and recomputation

[Restoration](../../build-output/current-multiflow-maxfreq-20261022/restoration.json) isCOMPLETE: originalcc329APK/all12native, original2b24rules, complete original configuration/preferences bytes/modes/owners/tree mtimes/SELinux categories and original policy0/4/6limits/governors match fresh backups. Parent`..`directory mtimes are outside the copied-tree comparison. KernelSU root grant is intact; runtime is stopped/mayBeActive=false, no VPP/helper/profiler/app/runtime-service PID or NFQUEUE remains, and the identity-owned host peer is gone. Latest user preference is honored: Openwrt_5G remains connected.

Recompute with`rtk proxy python3 build-output/current-multiflow-maxfreq-20261022-plan/audit.py`. [audit.json](../../build-output/current-multiflow-maxfreq-20261022/audit.json) records two complete/two failed windows and recomputes D rates, CPU intervals, per-flow checks, actual task placement, frequency residency and native stop debt. Raw CLI/client/CPU/system/conditions/PHY/guard/stop files and complete frozen tool/evidence inventories remain retained. The earlier current single-flow and old-APK datasets/statuses are unchanged.
