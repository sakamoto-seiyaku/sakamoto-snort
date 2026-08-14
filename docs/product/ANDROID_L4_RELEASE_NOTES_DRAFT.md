# Android L4 Product Release Notes Draft

Status: repository-staged draft for SAKAMOTO-59. This is not a public release
announcement and not a release approval. The final signed release APK and its
Root/VPN matrix, budget, and power reruns still block final closure.

中文状态：这是 SAKAMOTO-59 的仓库内发布说明草案，不是公开发布公告，也不是发布批准。
最终签名 release APK 及其 Root/VPN matrix、budget、power 复跑仍然阻塞最终关单。

2026-08-14 correction: existing VPN/TUN/HEV results predate the selected Direct Egress direction and do not
prove the release VPN transport. This draft must not be published until SAKAMOTO-102 and the final signed
release gates close.

## Release Summary

Android L4 Product Release delivers one Android product with two mutually
exclusive Runtime Profiles:

- Root Profile uses Root/NFQUEUE packet capture.
- VPN Profile uses Android VpnService, TUN fd handoff, and the evidence-selected VPN Userspace Flow Stack.

Both profiles consume the same App-first policy authority, Activity model,
diagnostics export, and recovery contract. The release scope is Android only.
Linux, Windows, and macOS are not part of this gate.

Protocol Identification and application-protocol rules are not included in this
Android L4 Product Release. They belong to the later Protocol Identification
Release.

## User-Facing Changes

- Choose Root or VPN Runtime Profile from the same Android product surface.
- Start protection and verify profile health before applying rules.
- Select an Android application and control its connectivity with Network Gate.
- Add Basic L4 rules for IPv4/IPv6, CIDR, protocol, port or port range, and
  direction.
- Inspect Activity for drops, allowed flows, policy revision, rule winner, and
  recovery context.
- Export desensitized diagnostics and use one of the documented feedback routes:
  Bug report, Compatibility report, Feature request, or Help request.

## Supported Device Evidence

Current validation evidence is for Google Pixel 6a (`28201JEGR0XPAJ`), Android
16 / SDK 36, `arm64-v8a`.

Repository evidence already records:

- Root first L4 workflow PASS.
- VPN first L4 workflow PASS.
- VPN IPv4/IPv6 TCP and UDP transport evidence PASS.
- Profile lifecycle, profile switch, fault recovery, Protection Pause, and
  cleanup evidence PASS.
- Dual-profile closure gate PASS for debug and non-debug release-candidate
  artifacts.
- Release-candidate budget probe PASS.

The current release-candidate APK is
`app/android-runtime/build/outputs/sakamoto-runtime-release-candidate.apk` with
SHA-256 `3ad1ff0c9769b8ca3a1cd10b047452739aa8f44cb304fb47b6888fc0bdf35623`.
It is non-debuggable, but it is not the final signed release APK.

## Budget Summary

The latest release-candidate budget probe records:

- Root workflow p99: `462 ms`.
- VPN workflow p99: `427 ms`.
- Root app download: `4.00 Mbps`.
- VPN TCP-connect fallback: `10/10` successes, `1.46 tps`.
- Idle CPU/RSS: Root `0.50% / 37576 KiB`; VPN `4.50% / 37600 KiB`.
- Active CPU/RSS: Root `4.90% / 37580 KiB`; VPN `1.73% / 37540 KiB`.
- Root owner-fault pass-through packets: `0`.
- VPN owner guard mismatches: `0`.
- Flow capacity misses: `0` for both profiles.
- Screen-off power proxy: `60 s` recorded for both profiles.
- Thermal status: `0 -> 0` for both profiles.
- Shutdown drain: Root `5482 ms`; VPN `2949 ms`.

Budget result: `PASS` for the non-debug release-candidate run. Final release
approval still requires the same evidence from the final signed release APK.

## Installation And Quick Start

1. Install the Android APK built for this release.
2. Open Sakamoto.
3. Choose Root when root authorization is available, or VPN when root is not
   available or the user prefers Android VpnService.
4. Start protection and wait for health to show running.
5. Select an application.
6. Use Network Gate for broad app connectivity control.
7. Use L4 rules for IP, protocol, port, and direction-specific control.
8. Check Activity after traffic to confirm drops, allows, rule attribution,
   counters, and policy revision.
9. Use recovery actions when permission, transport, runtime, pause, or recovery
   health states appear.
10. Export a desensitized diagnostic bundle before reporting bugs.

## 中文安装与快速开始

1. 安装本 release 的 Android APK。
2. 打开 Sakamoto。
3. 设备支持并已授权 Root 时选择 Root；没有 Root 或希望使用 Android VpnService 时选择 VPN。
4. 启动保护，等待健康状态进入 running。
5. 选择目标应用。
6. 使用 Network Gate 做应用级联网开关。
7. 使用 L4 rule 做 IP、协议、端口和方向控制。
8. 产生流量后查看 Activity，确认 drop、allow、rule 归因、计数和 policy revision。
9. 出现权限、transport、runtime、pause 或 recovery 状态时，按界面恢复动作处理。
10. 反馈问题前导出脱敏诊断包。

## Privacy And Diagnostics

Diagnostics are bounded and desensitized by default. They must not export API
keys, signing keys, private user content, or raw long-lived packet payloads.

Diagnostic facts may include profile, device, APK/native build id, timestamp,
remote IP, protocol/port, UID, rule id, reason id, revision, counters, and
health code when needed for troubleshooting.

## Known Limitations

- Android only.
- Final signed release APK evidence is still missing.
- VPN first packets may be Unknown Application. The product does not wait,
  cache, replay, or retroactively rewrite completed verdicts.
- VPN app download budget currently uses a TCP-connect transaction-rate fallback
  when the app download probe returns `Connection reset`.
- Direct Egress is not release-proven until SAKAMOTO-102 closes.
- ICMP Echo over VPN is not a release capability unless the Sakamoto HEV Fork and
  device matrix prove it.
- Protocol Identification, application-protocol rules, libprotoident
  enforcement, stateful conntrack, TCP stream reassembly, and HTTP/TLS/QUIC
  metadata are out of scope for this release.
- There is no zero-leak or recognition-hold product promise.

## Feedback Routes

- Bug report: include APK version, profile, health state, expected behavior,
  observed behavior, and desensitized diagnostics.
- Compatibility report: include device model, Android version, ABI, Root
  availability, VPN authorization state, IPv4/IPv6 availability, and failing
  matrix step.
- Feature request: describe the user task, profile, app, rule type, and why
  existing Gate/L4 controls are insufficient.
- Help request: include the current onboarding or recovery step and any visible
  health issue action.
