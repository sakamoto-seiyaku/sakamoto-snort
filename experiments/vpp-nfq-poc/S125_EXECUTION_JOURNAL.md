# S125 / POC-7 execution journal

状态：**已执行 Pixel 短 pilot；尚未执行 Tier 0/Tier 1 正式矩阵**。本文件记录
命令、原始计数、hash 和失败事实；解释性结论放在 `S125_COPY_INVESTMENT_MEMO.md`。

## 2026-08-22 — design/instrumentation gate

- `S125_POC7_DESIGN.md` 将实验臂固定为 `full`、`udp-reflect`、`ingress-only`、
  `memcpy-cal`；默认执行入口为 Tier 0，未启动真机。
- S124 plugin source overlay applied successfully with
  `SKIP_CORE_PATCHES=1`; host compile of `s124_vpn_tun_owner.c` completed with
  `/usr/bin/clang`, `-Werror`.
- Android JNI native source compiled with
  `aarch64-linux-android31-clang -std=c11 -Wall -Wextra`.
- Java sources compiled with `javac -source 8 -target 8`; only the existing
  deprecated-API note was emitted.
- `bash -n scripts/android-run-s125-poc7.sh` passed.
- `python3 -m unittest tests/test_s125_parse_results.py` passed.
- `git diff --check` passed.
- Added monotonic timestamps to each native VPP CLI snapshot and kept the monitor
  sampling `show s124-vpn-tun` for the lifetime of the VPP child.
- Added `patches/hev-poc7-tcp-copy-timing.patch`: pinned lwIP `tcp_out.c` now
  attributes the three real `TCP_WRITE_FLAG_COPY` sites to owner-local
  `tcp_copy_ns/tcp_copy_bytes`; VPP enables the timer only for observed TCP
  packets and reads the snapshot on the owning worker.
- Rebuilt the pinned HEV fixture on host and Android arm64; both exports
  `flow_stack_owner_tcp_copy_metrics` and
  `flow_stack_owner_tcp_copy_timing_enable`.
- Applied the HEV patch in a clean temporary source fixture with `patch --dry-run`
  and a forward apply/diff check; no source drift was observed.
- Runner now records device/artifact identity, thermal guards, both UDP/TCP
  representative simpleperf reports, per-cell summaries, and a run summary;
  Tier 0 defaults to full UDP plus all three controls with `off/sample64/full`.
- The worker envelope now records `submit-total-ns` for full and all three
  control arms, so full-vs-control path differences are measurable rather than
  inferred from missing fields. Only `observe=full` enters nested copy
  attribution because HEV perf counters are cumulative while VPP stage timers
  are sampled.
- Control-arm instrumentation overhead uses offered send PPS (their receive
  goodput is intentionally zero), while echo arms use receive goodput.
- Stress probe stop now cancels active flow sockets/executor so a timed-out cell
  cannot bleed packets or log lines into the next cell.
- Run aggregation now requires matched Tier-0 control keys and reports p05/p95
  copy-share/simpleperf evidence; a lone valid arm or a max-of-mixed-config cell
  cannot silently produce a final decision.
- Host golden fixture parsed to `observedPathNs=370`, `observedCopyNsUdp=130`,
  `copyShareUdp=0.351351...`; this is parser test data, not a device result.
- No APK was installed, no `VpnService` permission was requested, and no Pixel
  packet cell or performance number was produced in this stage.

## 2026-08-22 — evidence-chain hardening (no device run)

- Plugin compile command completed for
  `s124_vpn_tun_owner.c`; the stage output now emits parse success/error and the
  output line emits successful/partial `write-bytes` plus `output-copy-bytes=0`.
- Parser tests completed: `python3 -m unittest discover -s experiments/vpp-nfq-poc/tests
  -p 'test_*.py'` — 3 tests passed; `py_compile` passed.
- Java compile completed with `javac -source 8 -target 8`; only the existing
  deprecated-API note was emitted. The stress payload now reserves 8-byte run id
  and 8-byte sequence fields (minimum payload 21 B); flow/done/fail records carry
  the run id.
- Runner shell syntax check completed with `bash -n`; probe completion now waits
  for the run-id-matched `done`/`fail` record.
- Pinned HEV host shared library rebuilt at `/tmp/hev-3911f79/bin/`; `nm -D`
  reported `flow_stack_owner_tcp_copy_metrics` and
  `flow_stack_owner_tcp_copy_timing_enable`.
- Pinned HEV Android arm64 library rebuilt at
  `experiments/vpp-nfq-poc/work/android-hev-poc7-stage/lib/arm64-v8a/`; both
  symbols were present in the staged library.
- A clean temporary HEV source fixture made from the saved originals accepted
  `hev-poc7-tcp-copy-timing.patch` with `patch --dry-run --forward`.
- No APK was installed, no `VpnService` permission was requested, and no Pixel
  cell or device performance number was produced in this stage.

## 2026-08-22 — artifact gate

- The pre-existing Android configure directory attempted to regenerate with
  stale `VPP_PLUGINS=nfqueue_live_poc` and failed because that plugin was absent;
  a fresh `/tmp/s125-vpp-android` configure was then used.
- Android VPP configure completed in `/tmp/s125-vpp-android` from the patched
  `work/vpp/src` with `VPP_PLUGINS=hev_external_driver_poc`.
- Android arm64 target `hev_external_driver_poc_plugin` built successfully with
  `CCACHE_DIR=/tmp/s125-ccache`; the linked object was copied into the temporary
  `/tmp/s125-vpp-stage` runtime stage.
- Debug APK build completed with the temporary VPP stage and the rebuilt HEV
  arm64 stage. APK entries verified:
  `lib/arm64-v8a/hev_external_driver_poc_plugin.so` and
  `lib/arm64-v8a/libhev-socks5-tunnel.so`.
- APK `libhev-socks5-tunnel.so` strings contained both POC-7 TCP symbols; the
  plugin strings contained `parse-packets` and `output-copy-bytes 0`.
- APK SHA-256:
  `2da3d8c6516715ff9a5994db46d5f258b106d2611c297f71f9c13e1ca5521f9e`.
- No APK was installed, no `VpnService` permission was requested, and no Pixel
  cell or device performance number was produced in this stage.

## Execution gate still open

- Pixel Tier 0 `observe=off` vs `sample64` overhead must be ≤3%.
- TCP calibration additionally compares `full` vs `sample64` (≤3%), bounding the
  cost of enabling the pure-copy timer on every packet used for attribution.
- All control arms must produce valid raw files and steady monotonic snapshots.
- The APK must contain the POC-7 HEV metric symbol and the external-driver plugin;
  Tier 2 representative cells require `SIMPLEPERF=1`.
- TCP pure-copy attribution is now instrumented but has no device result yet;
  no copy-investment conclusion is claimed before Pixel Tier 0/Tier 1.

## 2026-08-22 — Pixel short pilot / parse diagnostic

- Run directory: `/tmp/s125-pilot-diagnostic-20260822-023716`.
- Unified baseline VPP core/plugin and APK were installed on Pixel 6a
  (`28201JEGR0XPA`); registration evidence was present.
- UDP worker=1 and worker=2 cells each produced one steady parse error:
  `parse-errors=1`, `parse-error-bytes=48`, `parse-error-last-len=48`,
  `parse-error-last-version=6`; the run was invalid under the then-current
  parser. No final metric was taken from this run.

## 2026-08-22 — Pixel short pilot / foreign-input classification

- Run directory: `/tmp/s125-pilot-foreign-20260822-024000`.
- UDP worker=1: `parse-errors=0`, `foreignPackets=1`, `foreignBytes=48`,
  `copyShareUdp=0.0009475860118804987`; app flow correctness passed.
- UDP worker=2: `parse-errors=0`, `foreignPackets=1`, `foreignBytes=48`,
  `copyShareUdp=0.0010480186384555464`; app flow correctness passed.
- The foreign packet was IPv6, 48 bytes, Next Header 58 (ICMPv6). The full-stage
  setup snapshot recorded 7 foreign packets / 448 bytes; the steady delta above
  is the cell value.
- TCP calibration cells in this run included `NoRouteToHost` startup failures;
  no TCP copy metric was accepted.

## 2026-08-22 — Pixel short pilot / TCP handshake diagnostics

- Run directories: `/tmp/s125-pilot-tcp-settled-20260822-024538`,
  `/tmp/s125-pilot-tcp-settled10-20260822-024727`,
  `/tmp/s125-pilot-tcp-header-20260822-025941`,
  `/tmp/s125-pilot-tcp-header2-20260822-030151`.
- Runner restart/ready settle fields were recorded; TCP cells still timed out
  after the source port was changed to kernel allocation and fixed TCP socket
  options were removed.
- Latest header run app result: TCP connect timeout (5000 ms) for both workers.
- Latest worker=1 stage snapshot included target input `3 packets/180 bytes` and
  output `1 packet/44 bytes`; `parse-errors=0`; foreign `7 packets/448 bytes`.
- Latest worker=1 TCP input header: `len=60`, `src-port=44124`,
  `dst-port=49155`, `flags=2`, `seq=2973606673`, `ack=0`,
  `src-ip=33582858`, `dst-ip=16777226`.
- Latest worker=1 TCP output header: `len=44`, `src-port=49155`,
  `dst-port=44124`, `flags=18`, `seq=6510`, `ack=2973606674`,
  `src-ip=16777226`, `dst-ip=33582858`.
- The corresponding worker=2 cell also timed out. No `tcp_copy_ns` or
  `tcp_copy_bytes` value was used for a performance conclusion.
- Device route snapshot during a fresh VPN session: `10.0.0.1 dev tun0
  src 10.111.0.2` for the VPN UID. `tcpdump` on tun0 produced no packet record
  because VPP consumed the packet immediately.

## 2026-08-22 — post-pilot checks

- After the parser/runner/plugin/Java changes:
  `python3 -m unittest discover -s experiments/vpp-nfq-poc/tests -p 'test_*.py'`
  — 4 parser tests passed.
- `py_compile`, `bash -n`, and `git diff --check` passed.
- Current artifact was rebuilt from the pinned baseline VPP core plus the updated
  plugin and HEV arm64 library; the formal Tier 0/Tier 1 matrix remains unstarted.

## 2026-08-22 — Pixel short regression / UDP timeout-drain change

- Command used repo-local `./dev/adb`; result directory:
  `/tmp/s125-gate-check3-20260822-033847`.
- Device: Pixel 6a, serial `28201JEGR0XPA`, Android 16.
- Run manifest: `tcpHandshakeGate=passed`, `udpClosedTimeoutMs=1000`,
  `udpSaturatingTimeoutMs=200`, `cellCount=3`.
- APK SHA-256:
  `d6e6e43181ebc9ba024e382280e9ef383a395b613c24d0d43b49b0a02f701b36`.
- VPP plugin SHA-256:
  `a996276102cdcfb38dc4cf51e3f37bd9e59d1f1f3590ea41db312705e73a705f`.
- HEV library SHA-256:
  `fe476e75c9ddc619c07df030f935dad36962cc40a4bc578866eb89d5c3ecedf9`.
- TCP gate cell `full-w1-tcp-f1-p33-b1-closed-ofull-r0`: valid; app
  `sent=6963 received=6963 errors=0 unexpected=0 late=0`; `tcpHandshakeReady=true`,
  input SYN `1`, output SYN-ACK `1`, input ACK `9534`, input data `9531`, output
  data `9528`, checksum error counters `0`.
- UDP worker=1 cell `full-w1-udp-f1-p33-b1-closed-ofull-r1`: valid; app
  `sent=5464 received=5464 errors=0 unexpected=0 late=0`; parse errors `0`,
  foreign `1 packet/48 B`, checksum errors `0`, `copyShareUdp=0.0014230694069745033`.
- UDP worker=2 cell `full-w2-udp-f1-p33-b1-closed-ofull-r1`: valid; app
  `sent=5681 received=5681 errors=0 unexpected=0 late=0`; parse errors `0`,
  foreign `1 packet/48 B`, checksum errors `0`, `copyShareUdp=0.0014916834945962092`;
  owner packet deltas `{"0":5670,"1":0}`.
- No Tier 0 control matrix, 3-repeat calibration, Tier 1, or Tier 2 simpleperf
  collection was run in this short regression.

## 2026-08-22 — Pixel short regression / two-worker counter race fix

- First 8-flow check `/tmp/s125-workercheck-20220822-034226` had app
  `sent=19759 received=19759 errors=0`, both owners active, but parser reported
  `output-write-byte-shortfall` (`pbuf-bytes=1372561`, `write-bytes=1372439`)
  while output errno/partial counters were zero.
- The plugin was rebuilt with atomic cross-worker accumulation/snapshot for
  output, checksum, TCP-event, control-arm, and submit counters.
- Rebuilt APK SHA-256:
  `127848bd3d822352d73b1640682f2dc685a615a0e8fdf54f5280fb2bea32a929`.
- Re-run directory: `/tmp/s125-workercheck2-20260822-034812`.
- TCP gate cell: valid; app `sent=7250 received=7250 errors=0`; output
  `pbuf-bytes=516986 write-bytes=516986 partial=0 eagain=0 other-errors=0`.
- UDP worker=1, flows=8: valid; app `sent=14823 received=14823 errors=0`;
  owner deltas `{"0":15463}`; output `pbuf-bytes=943243 write-bytes=943243`.
- UDP worker=2, flows=8: valid; app `sent=19086 received=19086 errors=0`;
  owner deltas `{"0":12952,"1":7426}`; output
  `pbuf-bytes=1243058 write-bytes=1243058 partial=0 eagain=0 other-errors=0`;
  `copyShareUdp=0.0004946946473284346`.
- This was a short owner-distribution check only; no formal matrix or decision.

## 2026-08-22 — Pixel short regression / TCP owner-hash mix

- Before hash mixing, `/tmp/s125-tcpworkercheck-20220822-035034` TCP
  `workers=2,flows=8` had app `7202/7202`, checksum errors `0`, but all owner
  packets were on owner 1; parser marked `worker-distribution-incomplete`.
- The test-only canonical tuple hash now applies a final avalanche before the
  owner modulo, avoiding the Android even-ephemeral-port low-bit collapse.
- Rebuilt APK SHA-256:
  `cb83777586f71c405fdc3bdcef43dcb075f3c1fc0a3e870d04208a18071f81a3`.
- Re-run directory: `/tmp/s125-tcpworkercheck2-20220822-035348`.
- TCP gate cell: valid; app `6959/6959`, checksum errors `0`, output
  `pbuf-bytes=527498 write-bytes=527498`.
- TCP worker=1, flows=8: one short cell had `insufficient-steady-samples` due
  the 2-second monitor window; raw app remained `7745/7745`, checksum errors `0`.
- TCP worker=2, flows=8: valid; app `19348/19348 errors=0`, all 8 flows connected
  and first-echo ready, owner deltas `{"0":7885,"1":11741}`, output
  `pbuf-bytes=1431530 write-bytes=1431530`, `tcpCopyBytes=647130`,
  `tcpWriteCopyBytes=647130`, `copyShareTcp=0.0005842073227843427`.
- This was a short multi-worker correctness/instrumentation check only; no formal
  matrix or decision.

## 2026-08-22 — Pixel control-smoke / parser and fire-and-count failure discovery

- Run directory: `/tmp/s125-control-smoke2-20220822-041240`.
- The first post-pacing control smoke retained raw app/VPP logs but was not a valid
  measurement. The runner invocation accidentally left `steadySeconds=30`; the
  fire-and-count sender used the then-current `100000 ns` pacing.
- Ingress-only and memcpy-cal cells eventually reported `fatalFlows=1` with app
  `IOException:sendto_failed:ENETUNREACH`; VPP raw log recorded child `status=6`.
- Before the VPP exit, representative enqueue drops were non-zero (for example,
  ingress-only worker=1 observe=full `enqueue-drops=8237`, memcpy-cal worker=2
  observe=off `enqueue-drops=13787`). The parser also hit a `ZeroDivisionError`
  when a failed fire-and-count flow had `done sent=0`.
- Source inspection of the pinned VPP helper showed that
  `vlib_buffer_enqueue_to_thread(..., drop_on_congestion=1)` already frees dropped
  buffers. The plugin then freed the same `bi` a second time in its congestion path.

## 2026-08-22 — Pixel control-smoke / double-free fix and pacing calibration

- Plugin was rebuilt after removing the second free on the congestion-drop path;
  the code comment records VPP helper ownership. APK rebuilt with Java failure
  logging and bounded fire-and-count pacing.
- `/tmp/s125-control-smoke3-20220822-042009` used `100000 ns` pacing and corrected
  `WARMUP_SECONDS=1 STEADY_SECONDS=3 DRAIN_SECONDS=2`. No VPP crash/fatal flow was
  observed, but all four ingress-only cells still had enqueue drops:
  worker=1 `2599/3656` (full/off), worker=2 `2430/3528` (full/off).
- `/tmp/s125-control-smoke4-20220822-042333` used `1000000 ns` pacing. No crash;
  all eight ingress-only/memcpy-cal cells had `fatalFlows=0`, but enqueue drops
  remained (`42..890` per cell), so the cells were invalid and not used as metrics.
- `/tmp/s125-control-smoke5-20220822-042949` used `5000000 ns` pacing. All cells
  remained crash-free, but enqueue drops remained (`42..89` per cell); no metric
  was accepted.

## 2026-08-22 — Pixel control-smoke / zero-drop calibration point

- `/tmp/s125-control-smoke6-20220822-043423` used the registered
  `fireAndCountPacingNsPerPacket=10000000` (10 ms) and the short durations
  `warmup=1 steady=3 drain=2`.
- TCP packet gate: valid, app `6492/6492`, `errors=0`, `enqueue-drops=0`.
- Ingress-only, UDP payload 33, burst 1, saturating, both observe modes and both
  worker settings: all four cells `valid=true`, `fatalFlows=0`, app errors `0`,
  `enqueue-drops=0`; app steady offered rates were `91.7, 92.0, 92.3, 92.0 pps`.
- `/tmp/s125-control-smoke7-20220822-043638` used the same registered pacing for
  memcpy-cal. Both observe modes and both worker settings: all four cells
  `valid=true`, `fatalFlows=0`, app errors `0`, `enqueue-drops=0`; app steady
  offered rates were `92.0..92.7 pps`.
- Current artifact for the zero-drop runs: runner `s125-poc7/v5`, APK SHA-256
  `5fa4d1dd41777a96683a37a3fba6ed1e2a6928932a26421c72a7fe2b0554d380`, plugin
  SHA-256 `ffa8a7cf9eedcf7c28bbb3719961d3aad151d1bfb9620f3830b32fab8734c1dc`,
  HEV SHA-256 `fe476e75c9ddc619c07df030f935dad36962cc40a4bc578866eb89d5c3ecedf9`.
- No formal Tier-0/Tier-1/Tier-2 result was taken from these short controls; they
  only establish the precondition that the control source is bounded and lossless
  at the registered calibration pace.

## 2026-08-22 — Tier-0 attempt / runner thermal-guard abort

- Initial formal result directory: `/tmp/s125-tier0-20220822-044043`.
- TCP gate and the first three formal full-UDP cells completed with valid summaries;
  examples: gate app `8188/8188`, full UDP w1/p33/b1 observe=full
  `sent=57672 received=57613 errors=0`, and observe=off
  `sent=60024 received=59965 errors=0`.
- The runner stopped before completing the fourth cell with
  `line 150: guard_id: unbound variable` while entering `thermal_guard` under
  `set -u`. The defect was the same-command expansion of
  `raw=...${guard_id}` before the preceding `local guard_id="$1"` assignment.
- The first formal directory remains raw evidence only; no run summary or decision
  from this aborted attempt is accepted. Runner was patched to split the two local
  declarations before restarting Tier-0.

## 2026-08-22 — Tier-0 formal rerun / raw audit

- Formal result directory: \`/tmp/s125-tier0-rerun-20260822-044826\`.
- Runner: \`s125-poc7/v5\`; formal run completed with exit code \`0\`; run summary
  contains \`298\` cells, of which \`220\` are valid and \`78\` are invalid.
- TCP handshake gate: passed (\`repeat=0\` gate cell valid; app sent/received
  counters matched; SYN/SYN-ACK/ACK/data/output-data counters present).
- Invalid-cell reasons were \`72\` \`enqueue-drops\` cells in the ingress-only and
  memcpy-cal fire-and-count \`burst=32\` controls, plus \`6\` \`thermal-limit-exceeded\`
  cells in high-load udp-reflect \`burst=32\` cells. No invalid cell in this set
  reported a VPP fatal flow.
- Fire-and-count invalid cells recorded \`enqueue-drops\` in the \`13..19\` range
  (the app steady sent count was approximately \`2912..2976\` for the 30-second
  window). The raw cells remain under the result directory and were not used as
  control evidence.
- The run summary decision was \`INCONCLUSIVE\`; \`matchedControlCount=4\`,
  \`controlsPass=false\`, \`controlDeltasPass=false\`, and \`payloadSlopePass=false\`.
  The Tier-0 run did not contain the registered TCP 33-byte/1400-byte payload
  pair, so no TCP payload-slope conclusion was taken.

## 2026-08-22 — Fire-and-count pacing repair / real-device smoke

- Source defect found after the formal run: \`runUdpBatch\` and \`runTcpBatch\`
  slept only after sending the whole \`burst\` batch. For \`burst=32\`, this created
  a queue-overrunning microburst despite the registered 10 ms/packet average.
- Java was changed to park 10 ms between packets for \`expectEcho=false\`; the
  final packet is not followed by an extra sleep. APK rebuilt with the matching
  VPP runtime/plugin pair: APK SHA-256
  \`d9cc6295029c4f89dad7bc72b7fe0369592e1697fa1fc9ddd8918f1b7d02dfb3\`,
  plugin SHA-256 \`ffa8a7cf9eedcf7c28bbb3719961d3aad151d1bfb9620f3830b32fab8734c1dc\`.
- An intermediate smoke using a plugin built against a different VPP binary was
  rejected before measurement (\`/tmp/s125-control-repair-20260822-104314\`);
  device log showed missing symbol \`vlib_frame_queue_wakeup_mode\`. It is retained
  as startup-diagnostic raw only.
- Matching-plugin repair smoke: \`/tmp/s125-control-repair2-20260822-104623\`.
  It covered ingress-only and memcpy-cal, workers 1/2, UDP payload 33/1400,
  \`burst=32\`, observe off/full, one repeat, short \`warmup=2/steady=10/drain=3\`.
  All \`16/16\` cells were valid, \`enqueue-drops=0\`, \`fatalFlows=0\`, app errors
  \`0\`, and app offered \`960\` packets at \`96000\` milli-pps in each cell. This is
  a repair smoke, not a formal three-repeat Tier-0 result.

## 2026-08-22 — Formal fire-and-count control repair

- Formal control result directory: \`/tmp/s125-control-formal-repair-20260822-105832\`.
- Matrix: ingress-only and memcpy-cal; workers 1/2; UDP payload 33/1400; burst 32;
  saturating; observe off/sample64/full; three repeats; warmup/steady/drain
  \`10/30/10\` seconds.
- All \`72/72\` cells were valid. Every cell had \`enqueue-drops=0\`,
  \`fatalFlows=0\`, and no parser reason. These cells replace the old formal
  burst=32 control cells for reconciliation; the old raw remains unchanged.

## 2026-08-22 — Thermal recovery

- Recovery result directory: \`/tmp/s125-thermal-recovery-20260822-122545\`.
- Matrix: udp-reflect; workers 1/2; UDP payload 33/1400; burst 32; saturating;
  observe off/sample64/full; one repeat; warmup/steady/drain \`10/30/10\` seconds.
- All \`12/12\` recovery cells were valid under the registered 65000 millicelsius
  limit. Thermal maxima were \`47000..63000\` millicelsius; queue drops were retained
  as saturating capacity loss and no correctness parser reason was emitted.

## 2026-08-22 — Reconciled Tier-0 parse

- Reconciled parser input: original formal cells plus the \`72\` formal repaired
  control cells and \`12\` thermal recovery cells. Output:
  \`/tmp/s125-tier0-reconciled-20260822-122545/run-summary.json\`.
- Aggregate: \`382\` cells, \`304\` valid, \`128\` timing-ready, all \`8\` matched UDP
  control keys present, TCP handshake gate passed. Decision remains
  \`INCONCLUSIVE\`.
- Remaining gate failures are measurement evidence, not app/VPP crashes: several
  full-vs-sample64 overhead comparisons exceed the registered 3% bound, two matched
  full-observation memcpy-minus-ingress path deltas are negative, and the Tier-0
  TCP payload-slope pair/simpleperf evidence is not present.

## 2026-08-22 — Calibrated CPU-counter timer / long UDP observation run

- Replaced the per-packet wall-clock timer in the canonical plugin overlay with a
  one-time-calibrated `clib_cpu_time_now()` counter; the wall-clock path remains a
  fallback if calibration fails. Android arm64 build succeeded. Plugin SHA-256:
  `4bf18afa21d2f87502cef04984f8f54b3b60a652a9f1a989783fa0bbd0b56899`; APK SHA-256:
  `276d5ac10d17d71fbb0d21fb891c966b83bef56f333d5ccbb4cb8a8744248e22`; HEV library
  SHA-256: `3cf7d6707c0e1163b8f3f08a8d812aeb102fc8c7cf8ae0daf885ea819ab9e55e`.
- Supplemental real-device result: `/tmp/s125-timer-cal-20260822-141947`.
  Device was Pixel 6a / Android 16 (`28201JEGR0XPAJ`). Matrix was `full` and
  `udp-reflect`, worker=1, UDP, one flow, payload=33 B, burst=1, saturating,
  observe `off/sample64/full`, three repeats; warmup/steady/drain was 20/60/20 s.
  TCP gate and TCP calibration were intentionally disabled because this run was a
  timer/UDP supplement, not a replacement for the registered Tier-0 matrix.
- All `18/18` cells were `valid=true`; every cell had `enqueue-drops=0`, no fatal
  flow, no mismatch/reorder/unexpected output, and checksum errors remained zero.
  Saturating drain recorded `errors=118` and `late=119..120` in each long cell;
  these were timeout/late capacity records and did not invalidate the saturating
  cells. Thermal maxima were `45000..49000` millicelsius and all guards passed.
- Parser output: full UDP goodput median `61928 B/s`, sent-rate median
  `1878600 milli-pps`; udp-reflect goodput median `61715 B/s`, sent-rate median
  `1872133 milli-pps`. Full-observation UDP copy-share was
  `0.00058055..0.00068330` (P05/P95); per full cell `udpCopyNs` was
  `9449054..10805117 ns` for `3412629..4032138` copied bytes. Output
  `pbuf-bytes == write-bytes` in every full cell and `output-copy-bytes=0`.
- Full-vs-reflect full-observation path median difference was
  `+318956947 ns` over the 60 s steady aggregate. The sample64 path delta was
  `-490555740 ns`, so it is retained as instrumentation/noise evidence and not
  treated as a copy delta.
- Observation gate: full-arm off vs sample64 goodput differed by `3.7339%`
  (`pass=false`), while full vs sample64 differed by `0.0016%` (`pass=true`).
  Reflect-arm off vs sample64 differed by `1.9200%` and full vs sample64 by
  `0.4263%` (both pass). The run therefore improved the timer path but did not
  satisfy the complete instrumentation gate.
- This run has only UDP/33 B/one-flow data, no p1400 pair, no TCP gate or
  simpleperf, and no ingress-only/memcpy-cal control arm. It is not eligible for
  `DEFER`, `TARGETED`, or `MUST_INVEST`; the parser decision remains
  `INCONCLUSIVE`. Raw evidence and the machine summary are preserved under the
  result directory above.

## 2026-08-22 — UDP 1400B plus TCP calibration on calibrated timer

- Result directory: `/tmp/s125-p1400-tcp-cal-20260822-145832`. Same Pixel 6a,
  APK, HEV library, and CPU-counter plugin as the preceding long run. Artifact
  hashes were APK `276d5ac10d17d71fbb0d21fb891c966b83bef56f333d5ccbb4cb8a8744248e22`,
  plugin `4bf18afa21d2f87502cef04984f8f54b3b60a652a9f1a989783fa0bbd0b56899`,
  HEV `3cf7d6707c0e1163b8f3f08a8d812aeb102fc8c7cf8ae0daf885ea819ab9e55e`.
- The real TCP packet-path gate passed before the matrix: gate cell app
  `sent=5706 received=5706 errors=0`, `tcpConnectedFlows=1`,
  `tcpFirstEchoFlows=1`; raw VPP counters contained SYN, SYN-ACK, ACK, TCP data
  and output data, with all TCP/UDP checksum errors zero.
- UDP supplement: `full` and `udp-reflect`, worker=1, one flow, UDP payload
  1400 B, burst=1, saturating, observe off/sample64/full, three repeats,
  warmup/steady/drain `10/30/10` s. All `18/18` cells were valid, with no
  enqueue drop, fatal flow, mismatch, reorder, unexpected packet, or checksum
  error. Thermal maxima were `46000..49000` millicelsius; saturating cells had
  only the expected drain late records.
- TCP calibration supplement: full worker=1, one flow, payload=33 B, burst=1,
  saturating, observe off/sample64/full, three repeats. All `9/9` cells were
  valid with `sent=received`, errors/mismatch/reorder/unexpected all zero.
  Combined with the gate, the result directory contains `28` valid summaries.
- UDP 1400 B full-observation copy seam: `udpCopyNs=17113032..18944495 ns`,
  `udpCopyBytes=64990800..74029200`, `copyShareUdp=0.00178828..0.00199855`.
  `pbuf-bytes == write-bytes` and `output-copy-bytes=0` held for all full cells.
- TCP 33 B full-observation copy seam: `tcpCopyNs=16418652..17363523 ns`,
  `tcpCopyBytes=2560635..2721543`, `copyShareTcp=0.00136665..0.00143427`.
  TCP successful-write copy bytes matched the lwIP test seam bytes; TCP gate
  counters and checksum checks remained clean.
- The p1400 parser result is `/tmp/s125-p1400-tcp-cal-20260822-145832/run-summary.json`.
  Its formal decision is `INCONCLUSIVE`: TCP gate passed, but the p33/p1400
  payload pair and registered control arms were not in the same run, and the
  instrumentation gate failed. In this run alone, off→sample64 goodput deltas
  were `5.871%` (TCP), `6.188%` (full UDP), and `5.802%` (udp-reflect UDP);
  full→sample64 was `2.466%`, `1.677%`, and `9.097%` respectively.
- Combining the same-plugin p33 long run with this p1400/TCP run produced
  `/tmp/s125-p33-p1400-tcp-combined-20260822-153247/run-summary.json` with
  `46/46` valid cells and a passing UDP payload slope: `1400/33=42.4242`
  copy-bytes-per-packet ratio. TCP payload slope is still missing its p1400
  pair. The combined decision remains `INCONCLUSIVE` because instrumentation
  and control evidence are incomplete; no investment label is taken.

## 2026-08-22 — simpleperf tool-gate repair and valid 32-flow sample

- First diagnostic attempt `/tmp/s125-simpleperf-udp32-w1-20260822-153510`
  pushed the runner's old Linux x86_64 binary to the ARM64 phone. Device log
  recorded `not executable: 64-bit ELF file`; the result was discarded as a
  tool failure, not a packet-path result.
- The next arm64 attempt `/tmp/s125-simpleperf-udp32-w1-arm64-20260822-153918`
  successfully recorded a 9.6 MB `simpleperf.data`, but Android simpleperf
  rejected the runner's Linux-only `--stdio` report option. The cell also had
  `enqueue-drops=113118`, so it was not a valid performance sample. The raw
  data is retained only as a diagnostic artifact.
- Runner was repaired to default to the NDK Android arm64 binary, use Android
  `report -o`, and allow an explicit `SIMPLEPERF_FORCE=1` for a stable
  representative cell. `bash -n` and `git diff --check` passed after the patch.
- Valid representative result: `/tmp/s125-simpleperf-udp32-w2-b1-arm64-20260822-154315`.
  Matrix was full UDP, worker=2, 32 flows, payload=1400 B, burst=1,
  saturating, observe=full, steady=30 s, arm64 simpleperf duration=20 s.
  Cell was `valid=true`, `enqueue-drops=0`, `mismatches=0`,
  `reordered=0`, `unexpected=0`; owner packet deltas were `117988/114603`.
  Saturating drain recorded `errors=377` and `late=377`, with no correctness
  parser reason. The measured UDP copy-share was `0.00035962`,
  `udpCopyNs=99553853`, `udpCopyBytes=325627400` and observed path
  `1043930857301 ns`.
- The Android arm64 report is present and parses. Top CPU samples were
  `s124_checksum_sum=20.07%`, kernel `_raw_spin_unlock_irqrestore=11.25%`,
  `ipt_do_table=5.48%`, `s124_vpn_tun_worker_node_fn=2.41%`, and
  `__memmove_aarch64_simd=2.01%` (copy symbols total `2.11%`, including
  kernel `__memmove` and `__memcpy_chk`). `s124_now_ns` was `0.54%`.
  This is a valid representative flamegraph evidence cell, but it does not
  satisfy the complete Tier-2 matrix or repair the Tier-0 instrumentation gate.

## 2026-08-22 — Paired-observe artifact gate and lightweight snapshot

- The first paired-observe APK was rejected before measurement because the
  temporary plugin had been built against the mutable work tree. Its undefined
  `vlib_frame_queue_wakeup_mode` was not exported by the staged Android runtime;
  `/tmp/s125-paired-observe-p1400-pluginfix-20260822-160722` is retained as
  startup-diagnostic raw only. The build path was corrected to inject the
  canonical plugin name and compile from the exact clean runtime source snapshot.
- The matched pair is VPP
  `3235eb48ec4240cba9fd3100ec7d86c90481511518438c77c16723529b9907f5`, staged
  `libvlib.so` `57c2ec8892d68ae2e5995965a9d449709a5904e96e7b4998aa000854e2c321c4`,
  plugin `57e7842312746b3d4d383ed13915f1627f495ddefd970813225b7e5d28050bd3`,
  and APK `74c2eb88adef14dc69ca2ee4a941626b1ddc8225f599f9499bc59c7726dd60dd`.
  The APK member hash equals the plugin hash and contains
  `show s124-vpn-tun-lite`.
- The existing `show s124-vpn-tun` performs HEV/lwIP pool/credit diagnostics and
  occasionally delayed a paired interval by 20–30 seconds under load. A
  test-only `show s124-vpn-tun-lite` was added; it reads VPP-owned counters only,
  so paired snapshots no longer call the HEV identity callbacks. The full show
  command used by cell parsing and registration monitoring is unchanged.
- `/tmp/s125-paired-lite-p1400-off-sample-full-20260822-1642`: real Pixel 6a,
  full UDP, worker=1, payload=1400 B, burst=1, saturating, valid cell, no queue
  drops/owner mismatch, thermal max 47000 millicelsius. Intervals were
  `5.849/5.729/5.688 s` for off/sample64/full; enqueue deltas were
  `10486/14770/15690` and observed-packet deltas `0/231/15690`. It proves the
  command and mode transitions, but the saturating offered rate was ramping, so
  it is not a formal overhead gate.
- `/tmp/s125-paired-lite-p1400-closed-20260822-1650`: closed UDP,
  warmup/steady/drain `10/40/5 s`, valid with `sent=received=94393`, no
  errors/late/mismatch, no queue drops, thermal max 47000. Forward order
  off/sample64/full had `10.705/10.779/10.827 s` intervals and enqueue deltas
  `23461/18183/17815` (about `2191.5/1686.8/1645.5 packets/s`). Full timing
  deltas were `101962634 ns` TUN-read, `5353413 ns` ingress-copy and
  `3037313 ns` parse for `17816` observed packets.
- `/tmp/s125-paired-lite-p1400-closed-full-sample-off-20260822-1700` was the
  reverse-order repeat and remained valid (`sent=received=92894`, no queue
  drops, thermal max 47000). Its first full interval was `10.759 s` and
  `17734` packets (`1648.3 packets/s`), consistent with the forward full
  interval. The sample interval was delayed to `33.929 s` by device-side CLI
  scheduling after the probe had started draining; it is retained as timing
  diagnostic and excluded from rate comparison.
- These paired cells are supplemental evidence, not a replacement for the
  registered three-repeat instrumentation gate. They show that full/sample64
  can be close on a stable closed interval, but the off baseline remains
  order/state-sensitive and a CLI command can still be delayed. The parser and
  investment decision therefore remain `INCONCLUSIVE`; no zero-copy, lwIP, or
  multi-worker production change is authorized by this data.

## 2026-08-22 — Same-artifact TCP payload-slope calibration

- Result directory: `/tmp/s125-tcp-slope-20260822-1720`. This was a real
  Pixel 6a / Android 16 run using one matched APK/runtime/plugin/HEV artifact:
  APK `0d939512de3fecb2d266636ec336de77382213135a3fe8e09257b5e13d5a7522`,
  VPP plugin `57e7842312746b3d4d383ed13915f1627f495ddefd970813225b7e5d28050bd3`,
  and HEV `3cf7d6707c0e1163b8f3f08a8d812aeb102fc8c7cf8ae0daf885ea819ab9e55e`.
  APK members were byte-for-byte equal to the staged plugin and HEV libraries.
- Matrix was `full`, worker=1, one TCP flow, payload `33/1400 B`, burst=1,
  `closed`, observe `off/sample64/full`, three repeats, `10/30/10 s`
  warmup/steady/drain; one additional p33 TCP handshake gate preceded the
  repeated cells. All `19/19` summaries were valid. Every repeated cell had
  `sent=received`, errors/late/mismatch/reorder/unexpected `0`,
  `enqueue-drops=0`, and checksum-error counters `0`; thermal maxima were
  `44000..48000` millicelsius.
- TCP gate passed: app handshake/first echo succeeded and raw VPP counters
  contained SYN, SYN-ACK, ACK, input/output data. The gate itself is a
  correctness precondition, not part of the copy-share estimate.
- Full-observation TCP copy seam, excluding the gate repeat: 33 B had
  `tcpWriteCopyBytesPerPacket` median `32.9931` (range `32.9857..32.9941`),
  `tcpCopyNs` median `40.365 ms`, observed-path median `31.101 s`, and
  `copyShareTcp` median `0.1297%` (range `0.1269..0.1422%`). 1400 B had
  `1399.6501` bytes/packet (range `1398.7740..1400.3510`), `tcpCopyNs`
  median `117.041 ms`, observed-path median `30.888 s`, and
  `copyShareTcp` median `0.3812%` (range `0.3518..0.3835%`).
- The within-run TCP copy-bytes slope was `1399.6501 / 32.9931 = 42.4272x`;
  the large-payload copy accounted for `99.975%` of the configured 1400 B.
  Thus the measured seam follows payload size and is not merely a fixed timer
  artifact. This is a TCP-only slope; the parser correctly leaves the overall
  payload-slope gate false because a registered formal run must contain both
  UDP and TCP pairs.
- The closed-load instrumentation checks were mixed: p33 off→full relative
  delta `2.98%` passed, but full→sample64 was `3.23%` and failed the `3%`
  bound; p1400 full→sample64 `2.59%` passed, but off→full was `4.43%` and
  failed. Therefore this run is supplemental calibration, not the registered
  formal timing gate. `run-summary.json` decision remains
  `INCONCLUSIVE` (`missing-valid-timing-control-or-instrumentation-evidence`).
- Next registered work is unchanged: execute saturating TCP p33/p1400 with the
  same artifact, then the repaired Tier-0 UDP control arms and their thermal
  recovery/repeats. No production lwIP, zero-copy, or multi-worker change is
  justified by this calibration alone.

## 2026-08-22 — Saturating TCP calibration / registered TCP gate

- Result directory: `/tmp/s125-tcp-slope-sat-20260822-1705`. The run used the
  same matched APK/plugin/HEV artifact recorded above. It contained one TCP
  handshake gate (`repeat=0`, closed p33) plus the registered full-path
  saturating p33/p1400 pair, worker=1, one flow, burst=1,
  `observe=off/sample64/full`, three repeats, `10/30/10 s` phases. All
  `19/19` summaries were valid; thermal maxima were `43000..47000` millicelsius,
  with no app errors, late/mismatch/reorder/unexpected packets, enqueue drops,
  or checksum errors.
- The TCP handshake gate passed again, and the formal TCP instrumentation
  calibration for p33 passed: off median goodput `86755 B/s`, sample64
  `88859 B/s`, full `88653 B/s`; off→full relative delta `2.43%` and
  full→sample64 `0.23%`, both within the `3%` bound.
- Saturating full TCP copy seam: p33 `tcpWriteCopyBytesPerPacket` median
  `32.9822` (range `32.9712..32.9973`), copy time median `37.187 ms`,
  observed-path median `30.153 s`, `copyShareTcp` median `0.1233%`
  (range `0.1221..0.1280%`); p1400 median `1399.4516` bytes/packet
  (range `1398.7922..1399.6259`), copy time median `106.306 ms`,
  observed-path median `30.796 s`, `copyShareTcp` median `0.3508%`
  (range `0.3452..0.3933%`).
- Saturating TCP payload slope is `1399.4516 / 32.9822 = 42.4305x`, with
  `99.961%` of the configured 1400 B represented by the measured copy. The
  TCP-only slope row passes. The parser was corrected to exclude the intentional
  `repeat=0` handshake gate from slope grouping; a gate correctness cell must
  not create a synthetic missing-payload row.
- The formal run is still not a final investment decision: p1400 off→full
  instrumentation delta was `5.95%` (fail), although p1400 full→sample64 was
  `1.00%` (pass), and this run has no UDP slope/control arms. Reparsed summary
  remains `INCONCLUSIVE` for the expected missing control/instrumentation
  evidence. The TCP-specific gate and slope are now complete; next work is the
  same-artifact repaired Tier-0 UDP control matrix and its thermal recovery.

## 2026-08-22 — Tier-0 continuation paused by decision

- The same-artifact Tier-0 UDP control matrix was started at
  `/tmp/s125-tier0-current-20260822-1735` and intentionally paused before the
  next control arm. The partial set contains `7/7` completed valid summaries:
  the TCP gate plus full/w1/UDP/33 B/burst=1 p33 cells through part of repeat 2.
  The partial parser output is `run-summary-partial.json`; it is diagnostic only
  and must not be merged into a formal Tier-0 decision.
- The runner was interrupted at the user's request after the current cell
  boundary. Its cleanup trap stopped VPN/VPP; device check showed no residual
  `vpp` process and no CLI socket. All completed raw files remain available for
  later continuation or audit; the incomplete directory is not treated as a
  failed performance sample.
- Decision for this phase: existing true-device evidence is sufficient to make
  a bounded engineering direction—visible VPP/HEV/lwIP copy is currently a
  low-priority optimization target, while checksum, queue/lock scheduling and
  kernel/netfilter work are more promising—but not sufficient to claim a
  formal `DEFER`/investment threshold. Tier-0 controls, complete off/sample64
  gate closure, and broader multi-worker/Tier-1 coverage are deferred, not
  blockers for starting the non-zero-copy optimization pass.
