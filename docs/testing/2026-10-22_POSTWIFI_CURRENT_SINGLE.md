# Current APK single flow before and after requested Wi-Fi toggle

Date:2026-10-22. Frozen base checkout`8c4234c6e0f782c21e33b0706bd6335ceb5fc921`.

The current7105APK delivered **303.62/335.54Mbps before** the requested Wi-Fi OFF/ON and **257.50/300.00Mbps after**, with all four20s windows collectorCOMPLETE and client errors0/timeouts0. Arithmetic means are **319.581204Mbps before** and **278.753989Mbps after**. This small sequential sample did not show a return toward500Mbps after reconnecting; it does not identify a Wi-Fi aging mechanism or a phone/network ceiling.

The user explicitly requested this current cohort unconditionally after an earlier conditional comparison was skipped. That [earlier conditional decision](2026-10-22_POSTWIFI_SINGLE_OLD_AND_CURRENT.md) remains historicallySKIPPED; these are separate new datasets. The user then requested finishing the first pair, switching Wi-Fi OFF/ON, and repeating the same two current windows.

## Delivered data and PHY observations

| Window | D bytes | Actual seconds | D Mbps | Pre Tx/Rx Mbps | After Tx/Rx Mbps |
| --- | ---: | ---: | ---: | ---: | ---: |
| postwifi-current-single-1 | 759072180 | 20.000549692 | 303.620527 | 1814/2161 | 2041/2161 |
| postwifi-current-single-2 | 839138972 | 20.006777598 | 335.541880 | 1814/2161 | 1921/2161 |
| current-single-retoggle-1 | 643996552 | 20.007309987 | 257.504503 | 1814/2401 | 1921/2161 |
| current-single-retoggle-2 | 750066700 | 20.001547047 | 300.003474 | 1814/2161 | 1814/2161 |

D Mbps is`bytes×8/((end_monotonic_ns-start_monotonic_ns)/1e9)/1e6`. Each helper result confirms one D download connection, one stream with data and zero E probes; no latency percentile is available in this D1E0recipe. Source31000→192.168.4.5:41723 is identical in all four windows. Each fresh VPN lifetime waited for source31000 to be absent fromTCP/TCP6includingTIME_WAIT, bounded120s, without replacing the port.

All immediate precollector snapshots, captured after frequency readiness, showed savedOpenwrt_5G,192.168.4.151,802.11ax,5180MHz,RSSI−52dBm and host ping success. PHY is a negotiated radio rate, not measured application capacity. The earlier old single-flow approximately300Mbps cohort also recorded high PHY rates, so these observations do not establish a negotiated-rate decline to300Mbps.

## Exact current configuration and CPU

The retained APK is`7105cbd896052e7d3ea1c8edfe5e00ad1d75a208425e9e7d5fed7aed5f3eff57`; recorded Product source closure`98b2c06c0666044d151d61a3954b0eeab93fb27b8bddbec4954e417b377bb0a4`; plugin`c3b3406d637af2cb7dddf7fa8bdebce84605688826316967fd3cfd9a792406b7`. All12installed native hashes matched APK ZIP members before each cell. Current Android helper`075e780dd4c5aa1de34d654ef8ec7cd698399c2112638662e5f4913b2ba53015`, host helper`1debf988c55135151e2e0f4dc6783ee43149e54bc435ae7aa964c639ea32ce95`, unchanged collector`63881bc630f594da0d4c2252d1b7fcff4f9ae0d725f9569b4d24327402f1c531` and helper source`45d3b6fdadd72701f98e2392009af1e6940b919c1f4efbaf36c9fe38b7d3e0ed` were verified. No Product/helper/collector build, source change, cache mutation or diagnostic default override occurred.

N1placement is mainCPU0, owner0CPU1, dedicated TUN I/OCPU2, helper main/receiverCPU3. Actual singleton allowed masks and sampled processors match every role. Defaults remain65528-byte send/ring,32768receive window,48primary credits, capture64, shared publication/completion/reclaim64, native return frame256, MTU10000/MSS9940 and2048×10240native pool; TCP batch/progress/buffer experiments are off. The existing current2s live UID/peer warmup with one D/zero E joins before timing. Raw CLI is saved before strict default/target checks. Every measured target has UID2000, owner0, ALLOW/rule0/revision1132, with original2b24rules unchanged.

| Window | Main / owner / I/O CPU seconds | Native CPU sample coverage | Helper CPU seconds (% one core) |
| --- | ---: | ---: | ---: |
| postwifi-current-single-1 | 0.00 / 6.09 / 4.60 | 19.868784799s | 2.441471 (12.21%) |
| postwifi-current-single-2 | 0.01 / 6.49 / 4.96 | 19.864644419s | 2.671773 (13.35%) |
| current-single-retoggle-1 | 0.00 / 5.40 / 4.13 | 19.667245656s | 2.158368 (10.79%) |
| current-single-retoggle-2 | 0.01 / 5.95 / 4.54 | 19.668857350s | 2.460442 (12.30%) |

CPU summaries use raw monitor samples strictly inside each actual client interval; exact first/last sample times, task ticks/schedstat, helper CPU and whole-system CPU/IRQ/softIRQ are retained. CPU cost differences versus the earlier old N2/D1E1recipe do not isolate an APK-version benefit. Primary rejection, runtime-drop and TUN write-failure counters stayed0across all four brackets. Each generation's native stop settles sessions, sockets, pending work, buffers, frames and obligations to zero. Collector-complete endpoint delivery remains separate from a lossless or Product release qualification.

Only policy0minimum changed300000→its existing maximum1803000kHz, after a fresh independent120sFIFO watchdog was ready. Every current/minimum/maximum sample was1803000, all positive bracketing residency was1803000, and all four guards restored normally without expiration. Other cluster limits/governors, thermal controls, IRQs and cpusets were unchanged. Brackets include setup/stop and exceed20s; passive thermal/task reads are sequential, not atomic. Small-role placement does not make the whole phone little-only, and these counters are not energy/hardware cycles.

## Requested toggle, protocols and restoration

The [before protocol](../../build-output/postwifi-current-single-maxfreq-20261022-plan/protocol.json), SHAd06080beb57c58f44ec0f39c862ce67e0e4e7b4ebba5aa24f93890ed7d1e3f9d, and [after protocol](../../build-output/postwifi-current-single-retoggle-maxfreq-20261022-plan/protocol.json), SHA68193ded31f57eca2339283b63e79f7e79797c86857fd94421debdbc5b1ca84c, were frozen before their timings. Only the new outer drivers/wrappers/guards were adapted; frozen hashes are retained per dataset. All four declared windows ran exactly once, without retry, profiling, alternative layout or extra arm.

After the first two windows had finished and native/helper/frequency/original-state cleanup passed, exactly one newly requested Wi-Fi OFF/ON was performed. [Toggle evidence](../../build-output/postwifi-current-single-retoggle-maxfreq-20261022/wifi-reconnect/result.json) retains before/off/on/after status/IP, actual disabled state, fresh UI XML/bounds, screenshot, association wait and two-packet host ping. Before the toggle PHY wasTx1921/Rx2161Mbps; after savedOpenwrt reconnection it wasTx1814/Rx2401Mbps at192.168.4.151. No PHY threshold, repeated reassociation or toggle inside timing was used. The subsequent two windows kept the identical APK/configuration/helper/collector/ports/warmup/bindings/frequency. Sequential drift and thermal/radio variation remain recorded, so no isolated causal aging/reconnect claim follows.

[Final restoration](../../build-output/postwifi-current-single-retoggle-maxfreq-20261022/restoration.json) isCOMPLETE: originalcc329APK/all12native, original2b24rules, full configuration/preferences bytes/modes/owners/tree mtimes/SELinux categories and original policy0/4/6limits/governors match fresh backups. Parent`..`directory mtimes are outside the copied-tree comparison. Root grant is intact, runtime is stopped/mayBeActive=false, no VPP/helper/profiler/app/runtime-service PID or NFQUEUE remains, and both identity-owned host peers are gone. Latest user network preference is honored: Openwrt_5G remains connected.

Recompute each dataset with its`*-plan/audit.py`: [before audit](../../build-output/postwifi-current-single-maxfreq-20261022/audit.json) and [after audit](../../build-output/postwifi-current-single-retoggle-maxfreq-20261022/audit.json). Raw client/peer/CPU/system/native/CLI/conditions/PHY/guard/restoration files and exact tool/evidence inventories remain in their separate output roots. The user's subsequent current multiflow continuation has a separate protocol and report.
