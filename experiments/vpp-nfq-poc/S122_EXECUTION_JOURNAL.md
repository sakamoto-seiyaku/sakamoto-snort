# SAKAMOTO-122 Execution Journal

> Chronological raw record. Conclusions and decisions are in
> `S122_PACKET_PATH_PERF_MEMO.md`; the result files below are the source of
> truth for individual samples.

## Scope

- Plane item: `SAKAMOTO-122` (`POC-4: Android 真机 VPP↔HEV/lwIP Packet-Path Performance`).
- Device gate: Pixel 6a, Android arm64. Host builds were used only to build or
  debug the test artifacts; they do not count as POC completion.
- Path under test: VPP buffer → lwIP `pbuf` (copy A) → UDP/TCP echo → netif
  output → VPP buffer (copy B).
- Protocols: UDP and TCP. Payloads: 33, 64, 512, 1400 bytes. Loads: low
  (1,000 packets), high (100,000, burst 1), burst 8, burst 32 (100,000
  packets). The long profile uses 1,000,000 packets, payload 1400, burst 32.

## Chronological ledger

| Time/order | Action or observation | Raw evidence |
| --- | --- | --- |
| 1 | Created and started `SAKAMOTO-122` in Plane; kept state `In Progress`. | Plane work item and comments |
| 2 | Built/staged the arm64 HEV library and VPP plugin; started VPP with main on core 0 and worker 1 on the Pixel 6a. | `results/s122/20260821-pixel6a-{udp,tcp}-matrix/device-metadata.raw` |
| 3 | First device UDP attempt exposed a packet-port byte-order error; corrected the test packet builder and rebuilt the plugin. | `overlay/src/plugins/hev_external_driver_poc/s122_packet_path_perf.c` |
| 4 | Device runs then stopped in HEV netif output. Instrumentation showed the last operation was `hev_task_self()` on the foreign VPP worker. Removed that per-packet HEV task lookup from the test boundary, rebuilt HEV, and reran. | `patches/hev-flow-stack-owner-foreign-thread.patch`; final matrix files |
| 5 | UDP matrix: 16/16 cases returned `PASS`; submitted, received, echoed, and output packet counters matched the requested count; `queue-error=0`. | `results/s122/20260821-pixel6a-udp-matrix/udp-*.raw` |
| 6 | Initial long TCP check exposed a receive-window/sequence-number issue in the fixture. The test was changed to advance both sides' sequence numbers after each synchronous echo. | `overlay/src/plugins/hev_external_driver_poc/s122_packet_path_perf.c` |
| 7 | TCP payload 1400 initially exercised segmentation and did not prove the requested packet count. Added an MSS 1460 SYN option and made count mismatch a failure; reran the affected matrix cases. | `overlay/src/plugins/hev_external_driver_poc/s122_packet_path_perf.c`; final TCP raws |
| 8 | TCP matrix: 16/16 final cases returned `PASS`; data submit/receive/echo/output counters matched; handshake counters were `submit=2`, `output=1`; `queue-error=0`. | `results/s122/20260821-pixel6a-tcp-matrix/tcp-*.raw` |
| 9 | Recorded UDP 30 s simpleperf profile: 54,485 samples, 0 lost. | `results/s122/20260821-pixel6a-flamegraph/{perf.data,report.txt,report-self.txt,flamegraph.html}` |
| 10 | Recorded TCP 30 s simpleperf profile: 60,027 samples, 0 lost. | `results/s122/20260821-pixel6a-tcp-flamegraph/{perf.data,report.txt,report-self.txt,flamegraph.html}` |
| 11 | Recorded resource/thermal samples while running 300,000 TCP packets (payload 1400, burst 32). | `results/s122/20260821-pixel6a-tcp-resource-v2/resource.raw` |
| 12 | This execution did not run three statistical repeats, a separate 10 s warm-up per matrix case, multi-connection TCP, or a real VPN/TUN endpoint; those remain follow-up coverage. | Plane scope vs. result directories |

## Device/build facts

- Device serial: `28201JEGR0XPAJ`
- Model/product: `Pixel 6a` / `bluejay`
- Build: `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`
- Final matrix VPP instance: PID `13693`; `vpp_main` LWP `13693`, core 0;
  `vpp_wk_0` LWP `13695`, core 1; two process threads.
- Local staged artifact SHA-256: HEV
  `d7db41d7dce69e69f08b194fa1d411a59da9362b7626687bb5c6b1060e94bf60`;
  VPP plugin
  `d73c1d16ab861e2af368ad2f157d239e52c2be0baaa62b1af00d3e3bffb2218c`.
- The callback thread identity reported by every final run is the same for
  setup/worker/receive/output within that run.

## Representative raw results

These are copied from the final raw files; they are not replacements for the
full files.

| Run | Result | Counters | Boundary copies A/B | Elapsed |
| --- | --- | --- | --- | --- |
| UDP, p1400, 100k, burst 1 | `PASS` | submit/recv/echo/output = 100000; queue error 0 | 142,800,000 / 142,800,000 bytes | 2,977,986,858 ns |
| UDP, p1400, 100k, burst 32 | `PASS` | submit/recv/echo/output = 100000; queue error 0 | 142,800,000 / 142,800,000 bytes | 1,703,284,343 ns |
| TCP, p1400, 100k, burst 1 | `PASS` | data submit/recv/echo/output = 100000; total submit 100002; output 100001; queue error 0 | 144,000,084 / 144,000,044 bytes | 4,134,775,271 ns |
| TCP, p1400, 100k, burst 32 | `PASS` | data submit/recv/echo/output = 100000; total submit 100002; output 100001; queue error 0 | 144,000,084 / 144,000,044 bytes | 1,732,036,703 ns |

## Resource observations

- Corrected TCP resource run: payload 1400, count 300000, burst 32; final
  counters were data submit/recv/echo/output `300000`, total submit `300002`,
  output `300001`, queue error `0`.
- `VmRSS=157896 kB`, `VmHWM=159620 kB`, and `Threads=2` remained unchanged in
  the recorded samples.
- `thermalservice` reported `Thermal Status: 0`; observed VIRTUAL-SKIN was
  about 31.85 °C and TPU 35 °C in the corrected run. These are observations of
  this run, not device-wide thermal guarantees.
- The recorded `dumpsys cpuinfo` window showed `13% 13693/vpp` (11% user,
  1.4% kernel); this is a historical window supplied by Android, not an
  instantaneous sample.

## Evidence layout

- UDP matrix: `results/s122/20260821-pixel6a-udp-matrix/`
- TCP matrix: `results/s122/20260821-pixel6a-tcp-matrix/`
- UDP profile: `results/s122/20260821-pixel6a-flamegraph/`
- TCP profile: `results/s122/20260821-pixel6a-tcp-flamegraph/`
- UDP resource run: `results/s122/20260821-pixel6a-resource/`
- TCP resource run (authoritative corrected script):
  `results/s122/20260821-pixel6a-tcp-resource-v2/`

The current result set is therefore a deterministic single-run packet-path
baseline, not a statistically complete workload characterization.
