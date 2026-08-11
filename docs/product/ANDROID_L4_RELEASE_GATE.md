# Android L4 Product Release Gate

Status: draft release-gate dossier for SAKAMOTO-59. This document is not a
release approval. It records the shared Root/VPN release contract, evidence
already gathered, and the remaining gaps that must be closed before the Android
L4 Product Release can be declared complete.

中文状态：这是 SAKAMOTO-59 的发布门禁档案草案，不是发布批准。它把 Root/VPN 共同发布合同、
已有证据和剩余缺口固定到仓库中，避免后续只凭记忆关单。

## 1. Release scope

In scope:

- Android only.
- One installable APK containing the same Android L4 product for Root and VPN Runtime Profiles.
- App-first Network Gate, L4 rule, Activity, health, recovery, import/export, and diagnostics flows.
- Root/NFQUEUE and VPN/TUN/HEV as mutually exclusive Runtime Profiles under the same policy authority.

Out of scope for this release gate:

- Linux, Windows, and macOS product releases.
- Protocol Identification / libprotoident enforcement.
- Stateful conntrack, TCP stream reassembly, HTTP/TLS/QUIC metadata, IDS/IPS, gateway/NAT.
- A zero-leak / recognition-hold product promise.

中文范围：

- 只发布 Android。
- Root 与 VPN 是同一个产品里的两个互斥运行 Profile，不拆成两个产品。
- 发布前必须证明两者消费同一套 Authoring Policy、Runtime Profile、Activity 与恢复合同。
- Linux、Windows、macOS 不进入本 release gate。

## 2. Supported matrix policy

The release cannot be called complete until a release APK completes the first
end-to-end user scenario on every device class listed as supported.

Current validation device class:

- Android physical device with repo-local `./dev/adb` access.
- Root-capable profile for Root/NFQUEUE validation.
- VPN-capable profile for VpnService + TUN + HEV validation.

Supported matrix entries must record:

- device model / Android version / ABI;
- Root support and authorization state;
- VPN authorization state;
- IPv4/IPv6 availability;
- APK build id and native daemon build id;
- matrix result directory.

Current gap: functional evidence exists in debug-APK device matrix result
directories, and S59 now has non-debug release-candidate budget and closure
gate reruns. The final signed release APK still needs to rerun the table below
before S59 can close.

### Current supported-device compatibility rollup

This table records current debug-APK functional evidence plus the latest
non-debug release-candidate budget and closure reruns. It is useful for
compatibility tracking, but it is not final release evidence.

| Device | Android | ABI | Root | VPN | IPv4/IPv6 | Evidence | Release status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Google Pixel 6a (`28201JEGR0XPAJ`) | Android 16 / SDK 36 | arm64-v8a | Authorized in Root/NFQUEUE matrices | VpnService authorized in VPN/TUN/HEV matrices | IPv4 and IPv6 covered across S52/S55/S58/S71 | S52 `build-output/s58-root-l4-workflow-evidence/s52-root-l4-product-matrix-20260811-160107.log`; S55 `build-output/s55-product-vpn-transport-matrix/20260811-160345`; S58 `build-output/s58-vpn-l4-product-workflow-matrix/20260811-162540/matrix.log`; S59 release-candidate budget `build-output/s59-release-budget-probe/20260811-183645`; S70 `build-output/s70-profile-lifecycle-matrix/20260811-150941/matrix.log`; S71 debug `build-output/s71-dual-profile-closure-gate/20260811-164754`; S71 release-candidate `build-output/s71-dual-profile-closure-gate/20260811-182004` | Debug functional matrices plus release-candidate budget and closure reruns; final signed release APK rerun required |

## 3. Functional release evidence ledger

| Requirement | Evidence | Status |
| --- | --- | --- |
| Installable APK starts both profiles | `tests/device/s70-profile-lifecycle-matrix.sh`, `tests/device/s71-dual-profile-closure-gate.sh` | Present |
| Root first L4 user workflow | `tests/device/s52-root-l4-product-matrix.sh` | Present |
| VPN first L4 user workflow | `tests/device/s58-vpn-l4-product-workflow-matrix.sh` | Present |
| Shared Adapter conformance | `cmake --build --preset dev-debug --target snort-host-tests` | Present |
| Dual-stack verdict coverage | S52/S55/S71 device matrices and host packet-policy tests | Present |
| Lifecycle, fault, recovery, profile switch | S54/S57/S70/S71 contracts and device evidence | Present |
| Policy persistence / old snapshot on failure | `tests/android/AndroidRuntimeContractTest.java` product transaction and apply-failure cases | Present |
| VPN IPv4/IPv6 TCP and UDP production proof | `tests/device/s55-product-vpn-transport-matrix.sh` | Present |
| Root fail-open fault envelope | S51/S52/S68/S71 evidence lineage and host adapter tests | Current S71 release-candidate rollup present; final signed release APK rerun required |
| Root no-residue release proof | S70/S71 evidence lineage | Current S71 release-candidate rollup present; final signed release APK rerun required |

Current debug-evidence rollup:

- Root L4 workflow: `build-output/s58-root-l4-workflow-evidence/s52-root-l4-product-matrix-20260811-160107.log`
  records `matrix.result=PASS`, real IPv4 TCP drop/restore, IPv6 TCP policy vector,
  source CIDR, UDP, ICMP, other-protocol vector, L4 prefill, and allowed FlowEntry.
- VPN L4 workflow: `build-output/s58-vpn-l4-product-workflow-matrix/20260811-162540/matrix.log`
  records `matrix.result=PASS`, debug APK SHA-256
  `d95146cd3ddbfad9d111b89c1c110b8889002fa711480d5ccf210db5d069635c`,
  no-recognition-hold first packet, late attribution L4 drop, Activity L4 prefill,
  and restore allowed FlowEntry.
- VPN transport: `build-output/s55-product-vpn-transport-matrix/20260811-160345`
  records `packet-adapter-vpn-tun-hev`, `vpn-tun-fd-handoff`,
  `vpn-tun-transport-fd-handoff`, TCP IPv4/IPv6 probes, UDP DNS bytes, no policy
  drops, and stopped projection after cleanup. This directory lacks a
  `matrix.log`, so it remains an evidence directory rather than a complete
  release rollup.
- Profile lifecycle: `build-output/s70-profile-lifecycle-matrix/20260811-150941/matrix.log`
  records `matrix.result=PASS`, Root start, Root→VPN, VPN→Root, Activity
  recreation, app process death, Protection Pause, binding/policy preservation,
  cleanup fault visibility, runtime crash recovery, Doze baseline, and final
  cleanup.
- Dual-profile closure: `build-output/s71-dual-profile-closure-gate/20260811-164754`
  records `matrix.result=PASS`, host runtime contract, host/VPP graph
  conformance, NDK daemon build, Root NFQUEUE matrix, product VPN matrix, and
  profile lifecycle matrix. Root evidence includes `root.gate=PASS`,
  `root.inputUidSeam=UID_UNAVAILABLE_WITH_UNKNOWN_APPLICATION_PASS`,
  `restart.finalCleanup.result=PASS`, `sigkill_fault.recovery.result=PASS`,
  `sigkill_fault.finalCleanup.result=PASS`, and `final.noResidue.result=PASS`
  through the nested Root matrix log.

Latest release-candidate closure rollup:

- Result directory: `build-output/s71-dual-profile-closure-gate/20260811-182004`.
- APK variant: `release-candidate`.
- Result: `matrix.result=PASS`.
- Host runtime contract, host/VPP graph conformance, NDK daemon build, Root
  NFQUEUE matrix, product VPN matrix, and profile lifecycle matrix all recorded
  `PASS`.
- Root evidence records `root.gate=PASS`,
  `root.inputUidSeam=UID_UNAVAILABLE_WITH_UNKNOWN_APPLICATION_PASS`,
  `restart.finalCleanup.result=PASS`, `sigkill_fault.recovery.result=PASS`,
  `sigkill_fault.finalCleanup.result=PASS`, and `final.noResidue.result=PASS`.
- Lifecycle evidence records `lifecycle.gate=PASS`; debug-only cleanup fault
  injection is explicitly skipped under release-candidate while
  `cleanupFault.releaseCandidateNormalStop=PASS` proves the release-candidate
  normal stop/no-residue path.

S58 latest evidence:

- Commit: `466ad5c s58 prove vpn l4 product workflow`.
- Result directory: `build-output/s58-vpn-l4-product-workflow-matrix/20260811-162540`.
- Product L4 drop: `DROP/L4`, rule `5970116917207709392`, revision `32`.
- VPN no-recognition-hold: first unknown packet forwarded, no policy drop.
- Late attribution: `policyDropActivity.uid=12546`, `stage=L4`, revision `32`.
- Activity prefill: available for `android.uid:12546`, `198.51.100.58/32:443`.
- Restore: product allow returns `PASS_NEXT`; traffic recovers; allowed FlowEntry records uid, remote endpoint, packets, bytes, and revision.

## 4. Release budget ledger

The following budget table is required before release approval. The initial gate
records evidence even when a final threshold is still pending; release approval
must not treat `TBD` as pass.

| Budget | Required record | Current status |
| --- | --- | --- |
| Latency | p50/p95/p99 verdict or workflow latency per profile | Current S59 release-candidate workflow probe present; final signed release APK rerun required |
| Throughput | Root and VPN nominal throughput / transaction rate | Current S59 release-candidate app download / transaction-rate probe present; final signed release APK rerun required |
| Drop | policy drop counters and unintended drop counters | S52/S55/S58 plus S59 release-candidate probe counters present |
| Capacity high-watermark | queue/flow/activity high-watermark and overflow behavior | Current S59 release-candidate Root queue, FlowEntry table, and Activity capacity/eviction probe present; VPN queue N/A because VPN/TUN has no NFQUEUE lease queue |
| Corrective handoff | owner mismatch / corrective handoff counters | S59 release-candidate owner-fault / owner-guard counters present and thresholded at `0`; final signed release APK rerun required |
| CPU/RSS | idle and active CPU/RSS per profile | S59 release-candidate idle and active CPU/RSS present; final signed release APK rerun required |
| Screen-off power | screen-off idle power or proxy budget | Current S59 release-candidate 10-second screen-off power-supply proxy present; release-duration rerun required |
| Thermal | thermal status before/after release workload | S59 release-candidate thermal before/after status present; release workload rerun required |
| Shutdown drain release | bounded drain and resource release timing | S59 release-candidate stop-to-stopped timing present and thresholded at `<=10000 ms`; final signed release APK rerun required |

Current measurement entry:

- `tests/device/s59-release-budget-probe.sh` records debug or
  release-candidate Root/VPN measurements for workflow latency p50/p95/p99,
  nominal download throughput, adapter drop/capacity/corrective-handoff
  counters, CPU/RSS, screen-off power-supply proxy, thermal status, and
  shutdown drain timing. The script also emits `budget_thresholds` and
  `budget_result` sections and fails the matrix when an enforced budget row
  fails. It remains a release-budget evidence collector; it does not turn
  release-candidate measurements into final release approval.

Current S59 budget threshold defaults:

| Threshold | Default | Override |
| --- | --- | --- |
| Workflow latency p99 | `1500 ms` | `S59_BUDGET_MAX_WORKFLOW_P99_MS` |
| Download throughput | `>= 1.00 Mbps` | `S59_BUDGET_MIN_DOWNLOAD_MBPS` |
| TCP-connect transaction rate fallback | `>= 1.00 tps`, `<= 1` failure per 10 attempts | `S59_BUDGET_MIN_TXN_TPS`, `S59_BUDGET_MAX_TXN_FAILURES` |
| Idle CPU | `<= 10.00%` | `S59_BUDGET_MAX_IDLE_CPU_PCT` |
| Active CPU | `<= 25.00%` | `S59_BUDGET_MAX_ACTIVE_CPU_PCT` |
| RSS | `<= 65536 KiB` | `S59_BUDGET_MAX_RSS_KB` |
| Shutdown drain | `<= 10000 ms` | `S59_BUDGET_MAX_SHUTDOWN_DRAIN_MS` |
| Flow capacity misses | `0` | `S59_BUDGET_MAX_FLOW_CAPACITY_MISSES` |
| Corrective handoff / owner faults | `0` | `S59_BUDGET_MAX_OWNER_FAULTS` |
| Thermal status | `<= 2` | `S59_BUDGET_MAX_THERMAL_STATUS` |
| Screen-off proxy duration | `>= 10 s` | `S59_BUDGET_MIN_SCREEN_OFF_SEC` |

Latest debug budget probe:

- Result directory: `build-output/s59-release-budget-probe/20260811-172742`.
- Device: Google Pixel 6a (`28201JEGR0XPAJ`), Android 16 / SDK 36,
  arm64-v8a.
- APK: `app/android-runtime/build/outputs/sakamoto-runtime-debug.apk`,
  SHA-256 `c810bf7cf778b49f886c647d9210d2cccb9c129dc87e2d84067a4c6329f14cae`.
- Root workflow latency: samples `3`, p50 `602 ms`, p95 `626 ms`,
  p99 `626 ms`.
- VPN workflow latency: samples `3`, p50 `608 ms`, p95 `614 ms`,
  p99 `614 ms`.
- Throughput / transaction rate: Root `RECORDED_APP_DOWNLOAD`,
  `500000` bytes in `1125 ms`, `3.56 Mbps`; VPN
  `RECORDED_APP_TCP_CONNECT_TXN_RATE`, `10/10` successful TCP-connect
  transactions over `7181 ms`, `1.39 tps`, with app download fallback
  reason `Connection reset`.
- CPU/RSS idle sample: Root `0.50% / 37516 KiB`, VPN `4.50% / 37388 KiB`.
- CPU/RSS active sample: Root `5.97% / 37520 KiB`, VPN `1.64% / 37392 KiB`.
- Adapter counters: Root `droppedPackets=0`, `ownerFaultPassThroughPackets=0`;
  VPN `droppedPackets=0`, `ownerGuardMismatches=0`,
  `transportFailedPackets=0`.
- Flow table high-watermark: Root `6/64` with `0` capacity misses; VPN `17/64`
  with `0` capacity misses.
- Activity capacity: Root allowed activity `8/8` with `760` evictions; VPN
  allowed activity `8/8` with `94` evictions; drop activity `0/8` for both.
- Screen-off power proxy: both profiles recorded `RECORDED_PROXY` over `10 s`.
  Root wakefulness `Awake -> Dozing -> Awake`, current_now before/start/end/after
  `-6562/-15312/-625/-6562 uA`; VPN wakefulness `Awake -> Dozing -> Awake`,
  current_now before/start/end/after `312/-12500/-3437/-2500 uA`.
- Thermal status: Root `0 -> 0`; VPN `0 -> 0`.
- Shutdown drain: Root `4813 ms`; VPN `4853 ms`.
- Throughput note: VPN app download still returned `Connection reset`, so this
  run records transaction-rate fallback rather than nominal download Mbps for
  VPN. Final release approval still needs a release-APK rerun and explicit
  pass/fail thresholds.

Latest release-candidate budget probe:

- Result directory: `build-output/s59-release-budget-probe/20260811-183645`.
- Device: Google Pixel 6a (`28201JEGR0XPAJ`), Android 16 / SDK 36,
  arm64-v8a.
- APK: `app/android-runtime/build/outputs/sakamoto-runtime-release-candidate.apk`,
  SHA-256 `b2f4f4dc65de65cb79780f6697c1ea71455908910602aeda4885436ddb0ae634`.
- Build status: `release_candidate_non_debug_not_final_signing`; APK manifest
  records `android:debuggable=false`, and the artifact contract verifies it.
- Budget thresholds: p99 workflow `<=1500 ms`, Root app download
  `>=1.00 Mbps`, VPN fallback `>=1.00 tps` with `<=1` failed TCP-connect
  transaction, idle CPU `<=10%`, active CPU `<=25%`, RSS `<=65536 KiB`,
  shutdown drain `<=10000 ms`, flow capacity misses `0`, owner faults `0`,
  thermal status `<=2`, and screen-off proxy duration `>=10 s`.
- Budget result: `budget.result=PASS`, `budget.failures=none`.
- Root workflow latency: samples `3`, p50 `420 ms`, p95 `431 ms`,
  p99 `431 ms`.
- VPN workflow latency: samples `3`, p50 `437 ms`, p95 `454 ms`,
  p99 `454 ms`.
- Throughput / transaction rate: Root `RECORDED_APP_DOWNLOAD`,
  `500000` bytes in `767 ms`, `4.00 Mbps`; VPN
  `RECORDED_APP_TCP_CONNECT_TXN_RATE`, `10/10` successful TCP-connect
  transactions over `6804 ms`, `1.47 tps`, with app download fallback
  reason `Connection reset`.
- CPU/RSS idle sample: Root `0.50% / 37492 KiB`, VPN `4.00% / 36984 KiB`.
- CPU/RSS active sample: Root `4.34% / 37496 KiB`, VPN `1.47% / 36996 KiB`.
- Adapter counters: Root `droppedPackets=0`, `ownerFaultPassThroughPackets=0`;
  VPN `droppedPackets=0`, `ownerGuardMismatches=0`,
  `transportFailedPackets=0`.
- Queue high-watermark: Root NFQUEUE pending lease queue `1/64`; Root
  terminal completion history `64/64`. VPN queue is N/A because VPN/TUN does
  not use the NFQUEUE lease queue.
- Flow table high-watermark: Root `6/64` with `0` capacity misses; VPN `17/64`
  with `0` capacity misses.
- Activity capacity: Root allowed activity `8/8` with `597` evictions; VPN
  allowed activity `8/8` with `88` evictions; drop activity `0/8` for both.
- Screen-off power proxy: both profiles recorded `RECORDED_PROXY` over `10 s`.
  Root wakefulness `Awake -> Dozing -> Awake`, current_now before/start/end/after
  `312/-10312/-2500/-41250 uA`; VPN wakefulness `Awake -> Dozing -> Awake`,
  current_now before/start/end/after `-1562/-7500/-625/-5625 uA`.
- Thermal status: Root `0 -> 0`; VPN `0 -> 0`.
- Shutdown drain: Root `5470 ms`; VPN `4283 ms`.
- Throughput note: VPN app download still returned `Connection reset`, so this
  run records transaction-rate fallback rather than nominal download Mbps for
  VPN. Final release approval still needs final signed release APK evidence and
  release-duration power evidence.

Minimum release rule: every budget row must have a measurement source, result
directory, date, device, and pass/fail decision before S59 can close.

## 5. User install and quick start

### English quick start

1. Install the Android APK built for this release.
2. Open Sakamoto.
3. Choose a Runtime Profile:
   - Root: recommended when Root is available and authorized.
   - VPN: recommended when Root is unavailable or the user prefers Android VpnService.
4. Start protection and wait for health to show running.
5. Open the app list and select an application.
6. Use Network Gate for broad app connectivity control.
7. Use L4 rules for IP/protocol/port-specific control.
8. Verify Activity after traffic:
   - drops show verdict, winner, rule, reason, and policy revision;
   - allowed flows show remote endpoint, protocol/port, direction, packets, bytes, and revision.
9. Use recovery actions when the health state reports permission, transport, runtime, pause, or recovery issues.
10. Export a desensitized diagnostic bundle before reporting bugs.

### 中文快速开始

1. 安装本 release 的 Android APK。
2. 打开 Sakamoto。
3. 选择运行 Profile：
   - Root：设备支持并已授权 Root 时推荐。
   - VPN：Root 不可用，或用户希望使用 Android VpnService 时使用。
4. 启动保护，等待健康状态进入 running。
5. 进入应用列表并选择目标应用。
6. 使用 Network Gate 做应用级联网开关。
7. 使用 L4 rule 做 IP / protocol / port 级控制。
8. 产生流量后查看 Activity：
   - drop 显示 verdict、winner、rule、reason 和 policy revision；
   - allow 显示远端、protocol/port、方向、packet/byte 和 revision。
9. 如果出现权限、transport、runtime、pause 或 recovery 状态，按界面恢复动作处理。
10. 反馈问题前导出脱敏诊断包。

## 6. Root and VPN user explanation

Root Profile:

- Uses privileged Root/NFQUEUE packet capture.
- Can observe Root-specific kernel/NFQUEUE behavior.
- Must remove NFQUEUE hooks and owned runtime residue on stop.
- Fails closed to user-visible permission/recovery state if Root authorization is missing.

VPN Profile:

- Uses Android VpnService, TUN fd handoff, and HEV transport.
- Does not require Root authorization.
- Android VPN UID attribution is non-blocking: unknown first packets are not held or replayed.
- Late attribution affects later packets and Activity evidence; completed verdicts are not retroactively changed.

中文说明：

- Root 模式依赖 Root/NFQUEUE，能力更接近内核路径，但必须严格清理 hook、进程、socket 和 profile residue。
- VPN 模式依赖 Android VpnService/TUN/HEV，不需要 Root；首包 UID 未识别时不会等待，后续归因成功后才按应用重新匹配。

## 7. Rules, Activity, and recovery guide

Rules:

- Network Gate is the broad app/network-context control.
- L4 Rule is the advanced IPv4/IPv6, CIDR, protocol, port/range, direction, and action control.
- Gate drop wins before L4.
- L4 allow cannot reopen a Gate drop.
- Apply failure must keep the old runtime snapshot active.

Activity:

- Drop activity comes from bounded ActivityAccumulator detail.
- Allowed flow activity comes from FlowEntry evidence.
- Bounded detail eviction must not change verdicts or exact counters.
- Activity rows must show app, time, remote IP, protocol/port, device packet direction, flow direction, packets, bytes, verdict, winner, and policy revision.

Recovery:

- Permission failures are user-actionable, not silent runtime restarts.
- VPN transport failure is separate from policy drop.
- Protection Pause is a product state, not an ordinary crash.
- Recovery state must show whether automatic recovery is pending or user intervention is required.

## 8. Privacy and diagnostic policy

Privacy principles:

- Product state stores app/control/activity facts needed for the user workflow.
- Diagnostics must be bounded and desensitized by default.
- Do not include API keys, signing keys, private user content, or raw long-lived packet payloads in release diagnostics.
- Remote IP, protocol/port, UID, rule id, reason id, revision, counters, health code, and build id are allowed diagnostic facts when needed for troubleshooting.
- Diagnostic export must make profile, device, APK/native build id, and result timestamp explicit.

中文隐私口径：

- 默认诊断应脱敏、有界，不导出密钥、签名材料、用户私密内容或长期原始 payload。
- 为排查网络控制问题，可包含远端 IP、端口、UID、rule/reason/revision、counter、health code 和 build id。

## 9. Known limitations

- Android only; Linux/Windows/macOS are explicitly out of this release gate.
- VPN first packet may be Unknown Application; no recognition hold and no retroactive verdict rewrite.
- ICMP Echo over VPN is not a release capability unless a pinned HEV build and device matrix prove it.
- Protocol Identification / application protocol rules are not part of Android L4 Product Release.
- No stateful conntrack or TCP stream reassembly.
- No zero-leak promise for short flows before attribution or later protocol recognition.
- Final signed release APK evidence and release-duration power evidence block
  final S59 closure.

## 10. Feedback entry points

The product must expose or document four user-findable feedback routes before release:

1. Bug report: include APK version, profile, health state, expected behavior, observed behavior, and desensitized diagnostics.
2. Compatibility report: include device model, Android version, ABI, Root availability, VPN authorization state, IPv4/IPv6 availability, and failing matrix step.
3. Feature request: describe the user task, profile, app, rule type, and why existing Gate/L4 controls are insufficient.
4. Help request: include the current onboarding/recovery step and any visible health issue action.

Current implementation slice: the Android debug/product control surface exposes
`Export diagnostics / feedback`, which writes
`debug/release-diagnostics.properties` using schema
`sakamoto.android_l4.release_diagnostics.v1` and shows Bug report,
Compatibility report, Feature request, and Help request guidance. Final release
notes still need to publish the same routes for non-debug distribution.

## 11. Release-notes template

Release notes for Android L4 Product Release must include:

- APK version and native daemon build id.
- Supported device matrix.
- Root/VPN profile summary.
- New controls: Network Gate, L4 Rule, Activity, recovery.
- Verification evidence: Root workflow, VPN workflow, VPN transport matrix, lifecycle/profile-switch matrix, host conformance.
- Performance and power budget summary.
- Privacy and diagnostics summary.
- Known limitations.
- Feedback routes.

## 12. S59 closure checklist

S59 can move to Done only when all rows are true:

- [ ] Release APK evidence uses the final release artifact, not only debug APK.
- [ ] Root and VPN complete the same first end-to-end user scenario on supported matrix devices.
- [ ] Shared Adapter conformance and profile lifecycle/fault/recovery/persistence gates are green.
- [ ] VPN IPv4/IPv6 TCP/UDP evidence is green.
- [ ] Root fail-open fault envelope and no-residue evidence are green.
- [ ] Release budget ledger is fully populated, with no `TBD` rows treated as pass.
- [ ] English and Chinese install/quick-start/help/privacy/limitations/release-notes content is published.
- [x] Desensitized diagnostic export and user feedback entry points are visible to users.
