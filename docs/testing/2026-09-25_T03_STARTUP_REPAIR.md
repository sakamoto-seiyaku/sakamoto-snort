# T03: startup policy failure remains repairable online

Date: 2026-09-25. Scope: [SAKAMOTO-254](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/d7c2eaa5-324a-4c45-8e8b-2315c1eae77c).
Result: **PASS for T03 representative acceptance**. This implements the startup
repair slice of [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md)
and the [unified rule specification](../product/UNIFIED_RULE_ENGINE_SPEC.md).
The [interface contract](../interfaces/T03_STARTUP_REPAIR.md) records ownership,
readiness, continuation, failure and stop semantics. It does not lift the
ordinary-user VPN launch gate.

## Source and evidence

The final Host and Android builds share Product source closure
`a04e29b72d9fb00eeae8f0f659da56c7b3a2edb0d60e87d057ad10630977703d`.
Their frozen manifests record base commit
`49a97cfffa1d7282ec9a6bf5042db3a10d72ec2d`, the exact source bytes and dirty diff.
The implementation commit does not change these bytes. API identity remains
`product_core.api/1.0.0@eb8f9cae`.

Evidence root: `build-output/t03-20260925/`; start at `acceptance-index.json`.
Raw local evidence remains necessary for the independent verification.

| Evidence | Result and scope |
| --- | --- |
| `linux-build-c/build.json`, sibling `product-vpp-host-t03-c/` | Official VPP/plugin/Rust build, frozen source and artifact hashes |
| `pixel-build-c/build.json` | Matching ARM64/APK build; APK SHA-256 `7245570bce4b1aeb401f189255f251dc9b90fd7b7ebbbcf4ab902c98c1124ffc` |
| `host-tests-final.xml` | Complete applicable root CTest suite, 41/41 PASS; includes C semantics, Java lifecycle/health, Rust session and native VAPI/plugin tests |
| `linux-e/`, `linux-e-verified.json` | Independent PASS: two real VPP lifetimes, eight captured dual-stack UDP packets and four uncaptured ordinary echoes during management-only repair |
| `pixel-c/`, `pixel-c-verified.json` | Independent PASS: six runtime lifetimes, eight Root dual-stack UDP packets, four controlled VPN IPv4 UDP packets and four ordinary echoes without product capture |
| `linux-e-negative-witnesses.json`, `pixel-c-negative-witnesses.json` | Seven falsified process, winner, protection, active-snapshot, source, endpoint and cleanup witnesses rejected per platform |
| `review-results.md` | Separate Standards/Spec review and focused final review closure |

## Original acceptance mapping

| Original requirement | Implementation and evidence |
| --- | --- |
| 构造已保存但编译失败的新版本，停止并重新启动；没有旧内存快照时明确报告策略未就绪。 | The API saves all 129 direct rules, exceeding the existing 128-rule compiler capacity. After restart, saved revision and all rule IDs survive while active revision is zero, compile error is 5 and compiler status is 2. Android reports `rule_configuration_not_active`, healthy management and protection false. `restart-source.conf` / `not-ready-query.txt` on Linux and each Pixel `*-unrepaired` / `*-repair` phase bind these facts to the new process and generation. |
| 在 VPP/control 基础健康的前提下，规则查询、错误查询、修改/替换、保存和重试应用入口保持可用。 | Existing complete-rule queries and replacement use the same VAPI/Rust/Java session. Both collectors query the invalid source, retry the exact saved IDs without changing revision, observe the same compilation error, then repair through that API. Pixel Query/Replace controls remain operable; request text, clicks, XML and screenshots are retained. |
| 编译并发布有效快照前不启用产品流量接管，不将管理进程存活报告为 protection running；Root/VPN 生命周期据此衔接。 | RuntimeService establishes healthy management first and validates the active snapshot before installing Root hooks or creating Android TUN. Failed startup has no native Root lanes/queues or attached TUN, and ordinary traffic echoes without product capture. VPP's main-thread process resumes its configuration-blocked Adapter initialization after successful publication. Java still requires explicit Start and platform prerequisites. |
| 通过同一 API 修复后能够进入正常生命周期，不清空规则、不静默跳过失败规则、不自动回退已保存的修改来伪造成功。 | Retry preserves all 129 saved rules and fails. Explicit correction removes surplus entries while preserving the first two already-saved ALLOW rules and their full IDs; the saved revision advances once. There is no hidden fallback file or empty-policy replacement. Pixel repair and UI Start preserve the same generation and process; packet delivery then follows the corrected source. |
| 运行中更新失败仍保留已有有效快照；配置失败与进程崩溃、权限不足、Adapter 故障使用各自正确处理。 | Before restart, both Root/VPN and Linux continue the preceding DROP snapshot after the newer ALLOW source fails compilation. Current Host tests distinguish policy/pending-capture status from typed control failure, permission failure, transport failure and bounded crash recovery. New health-summary regression first reproduced the incorrect runtime-fault cleanup guidance, then verifies saved-rule correction or explicit Start. Exit monitoring covers management-only generations; policy failures do not trigger crash restart. See the fault-scope paragraph below for the device limit. |
| 验证失败时平台资源不会形成残留或死 TUN，正常停止仍可执行；不改变 OS lockdown 的权威行为。 | Pixel explicitly stops an unrepaired generation in each profile before another repair attempt. All six processes are absent after stopping, with no Product hooks/queues; failed VPN startup has no TUN fd or native listener to drain. After publication, native drain remains mandatory even before platform capture. Active VPN owner teardown retains zero sessions, inputs, pbufs and packet debt with sockets closed and timer/broker fds retired. Ordinary-network observations do not bypass OS lockdown. |
| 把 policy readiness、Adapter readiness 和产品 protection running 分开验证；沿现有受控 VPN 验收限制解释结果，不能为通过本票而强置保护状态或把包测试成功称作普通用户发布验收。 | `startup-readiness.properties` separately records healthy management, nonzero active policy revision, native Adapter readiness, platform capture started and product protection. After repair but before Start, policy is ready while capture/protection remain false. Root becomes protection true only after hooks; controlled VPN remains protection false before and after real packet tests. No protection flag is forced. |
| 完成本票代表性验证并保留证据；未执行项明确说明与最近承接位置，不把 host PASS 当作设备 PASS。 | Source-bound Host, Linux and actual Android evidence are recorded separately. Independent verification joins config bytes/API versions, process/generation, request UI and actual packets/endpoint outcomes. All prescribed representative T03 platform flows ran. Broader fault, device and combined-product qualification remain explicitly scoped below. |

## Observed lifecycle and resource behavior

Linux uses an isolated user/network namespace with real VPP, native NFQUEUE and
kernel UDP echo peers. The first lifetime proves DROP and retained DROP after
saved compilation failure. The restarted lifetime has no active snapshot or
NFQUEUE capture; four dual-stack ordinary echoes bypass Product while the
management API remains available. Repair reuses that generation, after which
actual ALLOW then DROP packets match the corrected source. Both native stops
finish with zero packet debt and absent processes.

Pixel runs three lifetimes per profile: seed an active DROP and save an invalid
ALLOW update; restart without an active snapshot and stop unrepaired; restart
again, query/retry/correct through visible diagnostic controls and explicitly
Start the same generation. Root probes cover IPv4 and IPv6; the controlled VPN
probe covers the existing IPv4 TUN → owner-local HEV → protected Direct socket
path. Each phase joins packet bytes/nonces, UID, active source revision, rule
version and actual verdict/completion to an independent endpoint observation.
Screenshots/XML prove operations and displayed state, not packet processing.

Final Pixel generations are 1497–1502: Root seed/unrepaired/repair, then VPN
seed/unrepaired/repair. Generation 1502 is stopped in VPN profile with
`mayBeActive=false`, `protectionRunning=false` and no error. The one app-owned
mode-0600 source remains saved revision 51 with two explicit VPN-targeted ALLOW
rules. Endpoints were cleaned and the previous stay-awake setting restored.
The final always-on VPN app and lockdown settings are unset (`null`); this is
not a lockdown-enabled acceptance run and no OS policy setting was changed.

## Error handling, review and retained attempts

The two-axis review found no documented-standard violation or confirmed spec
implementation defect. Its evidence-scope feedback prompted targeted Host tests
for competing failures. The resulting red health-summary test found startup
configuration errors classified as runtime faults; the correction and Start
categories now give the appropriate action. Both reviewers confirmed the final
addition. Host TDD also covers healthy management without Adapter readiness,
generation fencing, conservative VPN drain after publication, unavailable
control queries and preserving no old in-memory snapshot across restart.

Retained attempts are not final acceptance:

- `linux-a/`: sandbox denied netlink before launching VPP; no packet acceptance.
- `linux-b/`: namespace proc permissions prevented reading the NFQUEUE table.
  The collector now records native lane descriptors/readiness plus netlink and
  hook evidence; `linux-c/` completed the earlier implementation.
- `pixel-a/`: Android shell could not enumerate interfaces; this diagnostic now
  uses the already authorized Root read. The collector stopped cleanly, and
  `pixel-a-fixture-recovery/` repaired its intentionally invalid source through
  the same visible API before the next run.
- `linux-d/` and `pixel-b/` completed the prior build's behavior, but the later
  health-category fix changed source identity. Final acceptance uses only
  `linux-e/` and `pixel-c/` with build c.
- `host-tests-a.xml`: old source-order assertions still expected hooks before
  process startup, and the sandbox denied local UDS. The assertions now enforce
  the required policy-before-hook/TUN order; the full suite ran with its local
  socket permissions. `host-tests-final.xml` includes the later health fix.

Failure classification and recovery-policy branches have current Host coverage.
This campaign does not newly exercise a device crash, revoked KernelSU grant or
Adapter fault during repair/resumption. The actual earlier sidecar-kill and
broker-failure evidence is dated in [S243 lifecycle](2026-09-12_S243_LIFECYCLE_CHECKPOINT.md),
with its own source identity and limits; it is not relabelled T03 device PASS.
Broader combined Root/VPN qualification is [SAKAMOTO-281](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64).
No public VPN launch, performance/power budget, physical cellular coverage,
all transport/condition combinations or 24-hour TCP expiry result is implied.

## Rechecking

```sh
rtk proxy python3 tests/evidence/verify_t03_repair.py build-output/t03-20260925/linux-e
rtk proxy python3 tests/evidence/verify_t03_repair.py build-output/t03-20260925/pixel-c
```

Fresh collection uses `tests/device/t03-linux-repair.py` in an isolated netns and
`tests/device/t03-pixel-repair.py` with a matching installed APK. Android operations
are serialized through `dev/adb`; a replacement install requires checking
KernelSU authorization before diagnosing a Root startup failure.
