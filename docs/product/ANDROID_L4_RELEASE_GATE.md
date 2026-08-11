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

Current gap: the evidence exists in device matrix result directories, but the
supported-device compatibility table still needs to be promoted into a stable
release artifact.

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
| Root fail-open fault envelope | S51/S52/S68/S71 evidence lineage and host adapter tests | Needs release-level rollup |
| Root no-residue release proof | S70/S71 evidence lineage | Needs release-level rollup |

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
| Latency | p50/p95/p99 verdict or workflow latency per profile | TBD |
| Throughput | Root and VPN nominal throughput / transaction rate | TBD |
| Drop | policy drop counters and unintended drop counters | Partially present in S52/S55/S58 |
| Capacity high-watermark | queue/flow/activity high-watermark and overflow behavior | TBD |
| Corrective handoff | owner mismatch / corrective handoff counters | Host conformance present; release rollup TBD |
| CPU/RSS | idle and active CPU/RSS per profile | Historical trim evidence exists; release measurement TBD |
| Screen-off power | screen-off idle power or proxy budget | TBD |
| Thermal | thermal status before/after release workload | TBD |
| Shutdown drain release | bounded drain and resource release timing | Lifecycle evidence present; timing budget TBD |

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
- Release budget rows marked `TBD` block final S59 closure.

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
