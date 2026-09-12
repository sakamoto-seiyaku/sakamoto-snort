# 当前实现 Roadmap（Tooling + 功能主线）

更新时间：2026-09-02
状态：当前共识（以仓库内 code + tests + docs/decisions + `docs/INTERFACE_SPECIFICATION.md` 为准；开放工作以 Plane `Sakamoto` / `SAKAMOTO` 为准；OpenSpec 仅作历史归档）

> **2026-08-26 reset:** ADR-0008 removed every Snort C++ implementation,
> host test, NDK/APK daemon artifact, and archive. Any `[DONE]` item below
> whose executable evidence depends on `libsucre_snortd.so`, `snort-host-tests`,
> or the former C++ daemon is historical evidence, not a current-head gate.
> Do not revive it as a C++ compatibility path. The VPP-native C Module,
> Rust control plane, and Java RuntimeService baseline is now represented by
> S170 and S171-S196. S197 completed the active legacy-reference cleanup on
> 2026-09-02; later work must not treat it as an open runtime path.

## 0. 阅读指南

本文结构：
- 1) 当前结论：一屏摘要（回答“现在做到哪了”）
- 2) 已完成：事实清单（按模块；带日期）
- 3) 下一步候选：待讨论后排序
- 4) 后置：不挡主线的 backlog / 边界说明
- Appendix：战略备注 / 架构边界判断（NOTE；非任务）

运行环境术语（工程化讨论统一用这套）：
- `Host`：本机 `gtest/CTest`
- `Host + ASAN`：同一套 Host case 的 AddressSanitizer 变体
- `Host + UBSan`：同一套 Host case 的 UndefinedBehaviorSanitizer 变体；日常 host gate 顺序为 normal → ASAN → UBSan
- `Device / DX`：ADB + root 真机集成（smoke/diagnostics/IP 模组/perf/longrun）
- `Native Debug`：真机原生调试（LLDB / VS Code + CodeLLDB），见 `docs/tooling/VSCODE_CMAKE_WORKFLOW.md`

历史用语：
- 仓库里现存 `p0/p1/p2` 只保留为历史 CTest label / 存量文档用语，不再当作当前路线图阶段名。

Status 口径（全篇统一）：
- `[DONE YYYY-MM-DD]`：已落地并归档/收敛
- `[NOW]`：当前正在做（本周/本迭代）
- `[NEXT]`：下一步紧接着做（已明确但未开始）
- `[HOLD YYYY-MM-DD]`：证据已记录，但继续执行受设计、环境或准入条件阻塞
- `[CANDIDATE]`：候选方向；不代表已有开放任务，进入实现前必须先有 Plane work item
- `[NOTE]`：战略/架构判断（非任务，不与 TODO 混用）

单一真相 / 索引：
- 产品、UI、内容与发布基线：`docs/product/ANDROID_L4_PRODUCT_PLAN.md`
- Host 现状盘点：`docs/testing/HOST_TEST_SURVEY.md`
- Device/DX 重组纲领：`docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`
- Device/DX 冒烟 casebook：`docs/testing/DEVICE_SMOKE_CASEBOOK.md`
- Device/DX 覆盖矩阵：`docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`
- 历史 vNext 设计材料（已归档；非权威）：`docs/archived/DOMAIN_IP_FUSION/`
- 对外接口规范（vNext-only）：`docs/INTERFACE_SPECIFICATION.md`
- 可观测性口径：`docs/INTERFACE_SPECIFICATION.md`、`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`、`docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md`
- RESETALL runtime 并发边界：`docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md`
- NFQUEUE / packet datapath 重构边界：`docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md`
- per-worker flow ownership：`docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md`
- Android Functional Closure contract 与 evidence matrix：`docs/decisions/ANDROID_FUNCTIONAL_CLOSURE_CONTRACT.md`
- VPP-native packet I/O Adapter boundary：`docs/adr/0006-vpp-native-packet-io-adapters.md`
- one policy bundle 与 stage-owned rule families：`docs/adr/0001-policy-bundle-staged-enforcement.md`
- L4 Conntrack stateful 语义参考：`docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`
- SNORT-10 mainline 重组基线：`docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md`
- Android/VPP 当前交接：`docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md`
- Plane 工作入口：`docs/agents/issue-tracker.md`。`SNORT-10` 与 `SNORT-12..19` 是 workspace reset 前的历史规划标识，不是当前 Plane 项目标识；新的开放工作使用 `SAKAMOTO-*`。
- OpenSpec 历史归档：`archive/openspec/changes/archive/` 与 `archive/openspec/specs/`（仅作历史参考；不再作为当前流程约束）

长期约束（对后续所有 Plane work item / implementation slice 生效）：
- 工程化任务只做 test/debug/tooling；不得顺势夹带产品功能实现。
- 如确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 1. 当前结论（1 屏可读）

### 1.1 工程化（测试/工作流）

- 当前默认开发 preset 已把 `SNORT_ENABLE_DEVICE_TESTS=OFF`，因此 `dev-debug`、`host-asan-clang` 与 `host-ubsan-clang` 会先收敛到纯 Host 回归。
- Device/DX active/optional 入口（vNext-only；smoke fail-fast）：
  - smoke：`dx-smoke`（platform → control → datapath）
  - diagnostics：`dx-diagnostics` / `dx-diagnostics-perf-network-load`
  - optional casebook：`dx-casebook-other`（`## 其他` Case 1–2；不进默认 `dx-smoke` 主链）
  - IP 模组：`tests/device/ip/run.sh --profile smoke|matrix|stress|perf|longrun`
- Device/DX 冒烟 casebook 已补齐；后续以 casebook 为验收口径维护（见 2.2）。
- 真机冒烟过程中发现的 **snort 本体问题**仍可在 docs 中保留复现证据；在当前架构重置阶段，不再拆成分散 backlog，先纳入 `SNORT-10` 讨论或等架构结论后再单独建项。
- 根目录 OpenSpec 工作区已迁出到 `archive/openspec/`；后续新工作默认走 Plane + docs/decisions/CONTEXT.md 工作流，不再为默认流程创建 OpenSpec change。
- 2026-04-30 已收口的后端支撑闭环：
  - Flow Telemetry：常态观测原始事实层 MVP；前端 Activity 新需求已暴露 raw facts completeness 缺口。
  - Packet diagnostics / legacy Debug Stream：旧 tracked 调试取证链条是 pre-SNORT-10 历史能力；SNORT-10 packet 侧目标为 session-owned Packet Diagnostics / Diagnostic Focus，DNS stream 暂时冻结。
  - Policy Bundle Checkpoints：固定槽位 policy-only snapshot / atomic restore 是 pre-SNORT-10 历史原语；SNORT-10 Authoring Layer 使用 Draft / Commit / Apply / latest-five Checkpoint / Runtime Snapshot 模型。
  - NDK r29 VPP stage workflow：当前 VPP-native stage build/deploy/debug 基线。

### 1.2 功能（Domain + IP + Flow Telemetry）

- 当前 active executable 是 VPP-native Product Core / RuntimeService baseline；以下 Domain+IP、CT、Telemetry 完成项是 `archive/current-head/` 保留的 pre-SNORT-10 历史实现证据，不是当前 active runtime capability。
- pre-SNORT-10 current-head 的 Domain+IP“后端融合”（vNext control 平面 + observability 口径 + datapath 接线）曾完成稳定回归；IPv4/IPv6 双栈、L4 conntrack core、DomainPolicy device-wide 命名收敛、DomainRules per-rule observability 均保留为迁移证据。
- 目标 VPP runtime 已收敛为 per-worker、per-flow single-owner；Root/NFQUEUE 与 VPN/TUN
  Packet Capture Adapter 必须进入统一 flow steering。旧 SNORT-10 的全局共享 CT A++
  baseline 已被取代，但 PacketFacts、consumer-driven facts、bounded observability 和
  policy stage 等边界继续保留。
- A/B/C/D 口径已经全部落地：
  - A：packet verdict 可观测（`reasonId/ruleId` + rule execution mode；旧 `wouldRuleId/wouldDrop` 已被 SNORT-10 归入 legacy stream 口径）
  - B：DomainPolicy counters（`policySource` / `domainSources`）
  - C：IP per-rule stats（随 IPRULES v1 一起落地）
  - D：PerfMetrics（SNORT-10 新口径为 `packetVerdictLatencyUs` / `nfqueueHealth`，旧 `nfq_total_us` 只可作为迁移 alias）
- IPRULES dual-stack（IPv4/IPv6）+ L4 conntrack core 已落地；真机 Tier-1 模组（netns+veth）已成为 datapath 的主要可重复验收环境。
- [DONE 2026-04-30] Flow Telemetry MVP 已完成：bounded shared-memory records、vNext `TELEMETRY.OPEN/CLOSE`、minimal telemetry metrics、`FLOW` / blocked-only `DNS_DECISION` producers、真机 mmap consumer 通路与 Flow On/Off perf 对照均已落地。
- Flow Telemetry 的分层边界已收口：常态 records 只包含业务事实（`FLOW` / `DNS_DECISION`），Packet Diagnostics 承担 packet-side 深度取证，Metrics 保留为后端低基数健康状态。
- 前端支撑所需的历史后端原语已基本闭环：legacy Debug Stream explainability、checkpoint / rollback、Flow Telemetry export channel 均已落地；SNORT-10 后 packet-side explain 目标改为 Packet Diagnostics，不再扩展旧 tracked packet stream。
- [NOTE] NFQUEUE topology / power / performance 不再作为文档内隐式 TODO 追踪；新的开放工作统一进入 Plane `Sakamoto`。历史 `SNORT-10` 只保留为架构讨论背景。

## 2. 已完成（事实清单）

### 2.1 工程化（DX workflow / 真机测试组织）

- [DONE 2026-04-23] `rework-dx-smoke`：收敛 active smoke 入口到 `dx-smoke{,-platform,-control,-datapath}`（spec：`archive/openspec/specs/dx-smoke-workflow/spec.md`）
- [DONE 2026-04-24] `rework-dx-diagnostics`：收敛 active diagnostics 入口到 `dx-diagnostics{,-perf-network-load}`（spec：`archive/openspec/specs/dx-diagnostics-workflow/spec.md`）
- [DONE 2026-03-24] `add-ip-test-component`：IP 真机测试模组（Tier‑1 netns+veth + profiles；spec：`archive/openspec/specs/ip-test-component/spec.md`）
- [DONE 2026-03-24] `add-iprules-cacheoff-build-variant`：cache-off 变体 + perf 对照记录（记录：`docs/testing/PERFORMANCE_TEST_RECORD.md`）
- [DONE 2026-04-22] `update-post-domain-ip-fusion-rollup`：后置 rollup（验证/文档/longrun 归位；仅保留为 archive 记录）
- [DONE 2026-04-30] `migrate-root-daemon-to-ndk-r29`：root daemon build/deploy/debug 主路径迁移到 NDK r29，归档 Soong/Android source active 入口，产出 `build-output/sucre-snort-ndk` 与 APK-native `.so` handoff artifact（spec：`archive/openspec/specs/root-daemon-ndk-release/spec.md`、`archive/openspec/specs/vscode-cmake-development/spec.md`）

### 2.2 工程化（Device smoke casebook 补齐）

- [DONE 2026-04-24] `complete-device-smoke-casebook-platform`：补齐 platform gate 可解释性（host 工具链 + vNext HELLO sanity + `--skip-deploy` 语义；spec：`archive/openspec/specs/dx-smoke-platform-gate/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-domain`：补齐 pre-SNORT-10 `DEVICE_SMOKE_CASEBOOK.md` `## 域名` Case 1–9（dns stream e2e、traffic/domainSources bucket、suppressed notice、真实 resolver hook BLOCKED 语义、DOMAINRULES(ruleIds)；spec：`archive/openspec/specs/dx-smoke-domain-casebook/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-ip`：补齐 IP 模块 smoke 口径（allow/block/would-match、`block.enabled=0`、`iprules.enabled=0`、payload bytes、维度级 traffic/reasons/stats、pkt stream 字段；spec：`archive/openspec/specs/dx-smoke-ip-casebook/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-conntrack`：补齐历史 Conntrack 模块 smoke 口径（`ct.state/direction` 最小闭环、create-on-accept、block 不 create entry；spec：`archive/openspec/specs/dx-smoke-conntrack-casebook/spec.md`）。SNORT-10 后的新 CT runtime 语义以 `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md` 为准，不再把 create-on-accept / block 不 create entry 作为新架构原则。
- [DONE 2026-04-25] `complete-device-smoke-casebook-other`：补齐 pre-SNORT-10 `DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2（`perfmetrics.enabled` 可用性验证、极端规模 limits sanity；spec：`archive/openspec/specs/dx-smoke-other-casebook/spec.md`）

### 2.3 功能（Domain+IP；后端已收敛）

- [DONE 2026-04-21] vNext codec + ctl：`add-control-vnext-codec-ctl`（spec：`archive/openspec/specs/control-vnext-codec/spec.md`、`archive/openspec/specs/sucre-snort-ctl/spec.md`）
- [DONE 2026-04-21] vNext daemon base（meta/inventory/config）：`add-control-vnext-daemon-base`（spec：`archive/openspec/specs/control-vnext-daemon-base/spec.md`）
- [DONE 2026-04-21] vNext domain surface：`add-control-vnext-domain-surface`（spec：`archive/openspec/specs/control-vnext-domain-surface/spec.md`）
- [DONE 2026-04-22] vNext iprules surface：`add-control-vnext-iprules-surface`（spec：`archive/openspec/specs/control-vnext-iprules-surface/spec.md`）
- [DONE 2026-04-22] vNext metrics surface（traffic/conntrack/perf/reasons/domainSources）：`add-control-vnext-metrics`（spec：`archive/openspec/specs/control-vnext-metrics-surface/spec.md`、`archive/openspec/specs/traffic-observability/spec.md`、`archive/openspec/specs/conntrack-observability/spec.md`）
- [DONE 2026-04-22] vNext stream surface（pkt/dns/activity + notice/barrier）：`add-control-vnext-stream`（spec：`archive/openspec/specs/control-vnext-stream-surface/spec.md`）
- [DONE 2026-04-22] legacy 冻结收口 + lane 分轨：`stabilize-control-transition-surface`（spec：`archive/openspec/specs/control-transition-surface/spec.md`）
- [DONE 2026-03-24] pktstream 可观测性：`add-pktstream-observability`（spec：`archive/openspec/specs/pktstream-observability/spec.md`）
- [DONE 2026-03-24] IPRULES v1（IPv4 L3/L4 + per-rule stats）：`add-app-ip-l3l4-rules-engine`（spec：`archive/openspec/specs/app-ip-l3l4-rules/spec.md`）
- [DONE 2026-03-27] DomainPolicy observability（policySource counters）：`add-domain-policy-observability`（spec：`archive/openspec/specs/domain-policy-observability/spec.md`）
- [DONE 2026-03-30] L4 conntrack core：`add-iprules-conntrack-core`（spec：`archive/openspec/specs/l4-conntrack-core/spec.md`）
- [DONE 2026-04-27] IPRULES IPv4/IPv6 双栈：`add-iprules-dual-stack-ipv6`（required `family`/mk2、IPv6 header walker + `l4Status`、conntrack byFamily metrics、host + device Tier‑1 回归；决策入口：`docs/decisions/IPRULES_DUAL_STACK_WORKING_DECISIONS.md`）
- [DONE 2026-04-27] DomainPolicy device-wide 命名收敛：`rename-domain-policy-global-to-domain-device-wide`（`GLOBAL_*` 对外收敛为 `DOMAIN_DEVICE_WIDE_*`；spec：`archive/openspec/specs/domain-policy-observability/spec.md`）
- [DONE 2026-04-28] DomainRules per-rule observability：`add-domainrules-per-rule-observability`（域名规则命中/状态观测补齐；spec：`archive/openspec/specs/domainrules-per-rule-observability/spec.md`）
- [DONE 2026-03-15] perfmetrics：`add-perfmetrics-observability`（spec：`archive/openspec/specs/perfmetrics-observability/spec.md`）
- [DONE 2026-04-30] Flow Telemetry Plane：`add-flow-telemetry-plane`（shared-memory ring export channel、`TELEMETRY.OPEN/CLOSE`、`METRICS.GET(name=telemetry)`、`FLOW` / `DNS_DECISION` records、host + 真机 + perf + longrun 回归；spec：`archive/openspec/specs/control-vnext-telemetry-surface/spec.md`、`archive/openspec/specs/flow-telemetry-export-channel/spec.md`、`archive/openspec/specs/flow-telemetry-records/spec.md`）
- [DONE 2026-04-30] Debug Stream explainability：`add-debug-stream-explainability`（tracked DNS / packet stream 自包含 `explain` 取证链条、规则/名单/mask/iface/IPRULES candidate snapshots、host + device domain/IP smoke 回归；spec：`archive/openspec/specs/debug-stream-explainability/spec.md`、`archive/openspec/specs/control-vnext-stream-surface/spec.md`）
- [DONE 2026-04-30] Policy Bundle Checkpoints：`add-policy-bundle-checkpoints`（固定 `0..2` checkpoint slots、64 MiB policy-only bundle、DomainLists 私有 staging + atomic restore、runtime epoch cleanup、host sanitizer + device smoke 回归；spec：`archive/openspec/specs/policy-bundle-checkpoints/spec.md`、`archive/openspec/specs/control-vnext-checkpoint-surface/spec.md`、`archive/openspec/specs/dx-smoke-checkpoint-casebook/spec.md`）

### 2.4 稳定性（运行期并发边界）

- [DONE 2026-04-26] RESETALL runtime 并发边界：修复 `RESETALL` 与周期性 `snortSave()` 竞态，以及 packet / DNS 热路径锁外准备对象跨 reset 发布问题；设计口径见 `docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md`，审查状态见 `docs/reviews/CURRENT_HEAD_CPP_CONCURRENCY_REVIEW.md`。
- [DONE 2026-04-26] legacy stream 冻结：`DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 不再作为实时事件通道；当时支持入口统一到 vNext `STREAM.START(type=dns|pkt|activity)`，但 SNORT-10 packet 侧新目标为 `DIAGNOSTICS.START(channel=packet)`，DNS stream 暂时冻结。
- [DONE 2026-04-26] vNext mutation / datapath 锁拆分：新增 control mutation mutex，普通 vNext apply/import/config/metrics reset 不再持有 `mutexListeners` 覆盖大 CPU / I/O 工作；`RESETALL` 仍按 save/reset → control mutation → datapath quiesce 顺序完整串行化。
- [DONE 2026-04-26] daemon lifecycle ownership：`stabilize-daemon-lifecycle-ownership`（main-owned shutdown、session-owned fd、active session budget、send deadline；并更新 concurrency review lifecycle findings）

### 2.5 文档（对外契约 / 权威口径）

- [DONE 2026-04-26] `sync-iprules-dual-stack-authority-docs`：同步 dual-stack IPRULES 的权威设计/契约文档，避免跨文档漂移与误读。
- [DONE 2026-04-27] 接口规范收敛：重写 `docs/INTERFACE_SPECIFICATION.md` 为 vNext-only，并归档 legacy 版到 `docs/archived/INTERFACE_SPECIFICATION_v3.7_2026-04-26_legacy.md`。
- [DONE 2026-04-29] Flow Telemetry 工作纲领收口：`docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md` 明确常态 records、Debug Stream、Metrics 与旧 `tracked` 的历史边界；SNORT-10 后 packet-side 诊断以 Packet Diagnostics / Diagnostic Focus 为目标。

## 3. 当前产品主线与后续候选

2026-07-19 顺序覆盖：当前唯一 `[NOW]` 路径是定义 Android L4 Product Release 与共同的
UI/content/release 基线。先收口用户场景、UI 信息架构、product-facing view model 和完成标准，
再将第一条端到端场景拆成 Plane vertical slices。历史 `[NEXT]` 不得越过该产品基线直接恢复
archived runtime 或创建孤立的数据面实现任务。

### 3.1 当前后端闭环状态

- [DONE 2026-04-30] Flow Telemetry MVP 已覆盖常态 records 初始原始事实层；前端 Activity 新需求暴露的 ICMP、方向、L4 状态、END/time/verdict/known flags、L3 observation 等 raw facts completeness 缺口进入 3.4 下一轮。
- [DONE 2026-04-30] Debug Stream explainability 已覆盖 tracked DNS / packet verdict 的历史自包含取证链条；SNORT-10 packet 侧由 Packet Diagnostics / Diagnostic Focus 取代，DNS stream 暂时冻结。
- [DONE 2026-04-30] Policy Bundle Checkpoints 已覆盖 pre-SNORT-10 后端固定槽位 checkpoint / rollback 原语；SNORT-10 Authoring Layer 以 latest-five Checkpoint / Runtime Snapshot 模型为新目标。
- [DONE 2026-04-30] NDK r29 VPP stage workflow 已成为当前 VPP-native stage build/deploy/debug 基线；后续 APK/RuntimeService 集成不再依赖 Android source / Soong daemon 路径。
- [NOTE] OpenSpec 工作流已归档；新的产品/工程工作在产品计划稳定后进入 Plane。
- [NOTE] SNORT-10 mainline reconstruction 是历史迁移基线：旧 `src/` 与 daemon/control/NFQUEUE pass-through base 仅用于解释 ADR-0008 前的证据；当前 active build 由 `src/product` VPP-native C、`crates/product-core` Rust 与 Android Java supervisor 组成。边界见 `docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md`。

### 3.2 当前主线：Android L4 Product Release

> 本节中的 S12-S31 条目是 ADR-0008 前的历史证据，保留用于追溯，不是 current-head
> implementation 或 release gate。当前 S170/S171-S196 状态以 Plane 和 recovery dossier 为准。

- [DONE 2026-07-19] SAKAMOTO-12 APK-native daemon packaging handoff：debug APK 已纳入 `build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so`，并完成真机安装、artifact hash 与进程快照验收；release signing/upgrade/rollback 仍未覆盖。
- [DONE 2026-07-19] SAKAMOTO-12 RuntimeService root launch：由 `${applicationInfo.nativeLibraryDir}/libsucre_snortd.so` 启动 daemon，校验 `HELLO.daemonBuildId/artifactAbi/capabilities`，并以本地 runtime log、PID 文件和 root TERM/KILL 完成停止清理；KernelSU 授权、foreground service、crash/restart policy 仍待独立 POC。
- [DONE 2026-07-19] SAKAMOTO-13 RuntimeService process-death observation：确认 `am force-stop` 后 root daemon 会孤儿化为 PID 1 子进程；该历史失败边界由 SAKAMOTO-14 继续处理。
- [HOLD 2026-07-19] SAKAMOTO-14 RuntimeService process-death containment：daemon `getppid()` monitor 能在 APK 被 force-stop 后自动退出，控制 socket 消失，fresh RuntimeService 可恢复；但 NFQUEUE/iptables 链仍残留，网络 hook cleanup 尚未成立，Android release handoff 继续 HOLD。
- [DONE 2026-07-19] SAKAMOTO-15 NFQUEUE hook cleanup：正常停止与 APK force-stop 均能清理 IPv4/IPv6 hook、链和控制 socket，fresh RuntimeService 恢复通过；foreground service、release signing、升级/回滚与 tombstone 仍待验证。
- [DONE 2026-07-19] SAKAMOTO-16 RuntimeService repeated lifecycle residue：5 次短周期 normal start/stop、预置双栈链/jump 幂等归一化、APK force-stop 与 fresh recovery 均通过；长稳、foreground service、Doze、升级/回滚与 SIGKILL 仍待验证。
- [HOLD 2026-07-19] SAKAMOTO-17 daemon SIGTERM/SIGKILL cleanup boundary：SIGTERM 可通过 daemon destructor 清理双栈 NFQUEUE hook；SIGKILL 后 daemon/socket 虽退出但 hook 残留，必须由 supervisor 或显式 root cleanup 兜底，自动恢复边界仍未满足。
- [HOLD 2026-07-19] SAKAMOTO-18 RuntimeService foreground/background lifecycle smoke：后台切换与 5 秒锁屏期间 daemon、socket、双栈 hook 和本地 adb-reverse HTTP 探针均通过，受控停止清理通过；但 service dump 为 `startForegroundCount:0` 且无本包通知，foreground service 仍未实现。
- [DONE 2026-07-19] SAKAMOTO-19 RuntimeService short Doze differential：模拟 USB 断电、锁屏并强制进入 10 秒 deep Doze；daemon、socket、双栈 hook 保持，Doze 前后本地 HTTP 探针通过，受控停止清理通过；长稳/电量认证与 foreground service 仍不在结论内。
- [DONE 2026-07-19] SAKAMOTO-20 APK upgrade/rollback hook residue：同一 debug 签名下 versionCode 1→2 升级与 2→1 回滚均在 RuntimeService 活跃时完成；旧 daemon、socket、双栈 hook 自动清理，新旧版本重新启动均归一为 4 个顶层 jump，停止清理通过；release signing/key rotation、数据迁移和中断安装仍未覆盖。
- [DONE 2026-07-19] SAKAMOTO-21 RuntimeService foreground service implementation：增加 `startForeground`、`snort-runtime` notification channel、`specialUse` manifest 类型和 debug 通知权限；后台/5 秒锁屏期间 foreground state、notification、daemon/socket/hook 与本地探针均通过，受控停止清理通过；用户运行时通知授权、release UX、重启/OEM 长稳仍待验证。
- [DONE 2026-07-19] SAKAMOTO-22 RuntimeService supervisor cleanup：观察 root daemon 非预期退出后自动清理双栈 NFQUEUE jump/chain 与 PID 文件；SIGKILL 后 daemon、control socket、hook 均消失，fresh start/stop recovery 通过；crash backoff、并发 stop/kill、service process death 与 release 行为仍待验证。
- [DONE 2026-07-19] SAKAMOTO-23 daemon crash/restart boundary：`SIGABRT` 后 RuntimeService 能观察非预期退出并清理 daemon/socket/NFQUEUE hook；5 秒 bounded window 内未发生自动重启，fresh manual recovery 通过；自动重启、backoff、重复 crash policy 与 release 行为仍为 HOLD。
- [DONE 2026-07-19] SAKAMOTO-24 RuntimeService root permission denial：KernelSU deny 时 app UID 的 `/system/bin/su` 不可执行，RuntimeService 明确记录 `runtime_start_result=fail`，无 daemon/socket/NFQUEUE 残留；恢复 allowlist 并重启后 fresh start/stop 通过；用户授权 UX、live revocation 与 release 策略仍待验证。
- [HOLD 2026-07-19] SAKAMOTO-25 RuntimeService artifact mismatch boundary：错误 ELF 与 HELLO protocol mismatch 均在成功前 fail closed 且无残留，正常构件恢复通过；同 ABI 但篡改非空 build ID 仍被当前 gate 接受，预期 build ID/hash 绑定、签名构件校验与 release 策略待补。
- [DONE 2026-07-19] SAKAMOTO-26 RuntimeService APK daemon hash gate：build script 将发布期 expected SHA-256 写入 APK asset，RuntimeService 在 root launch 前校验 extracted daemon；正常/恢复通过，同 ABI 篡改构件在 `root_launch=started` 前失败且无残留。APK signing/key trust、release key rotation 与 asset/daemon 同时被替换的攻击模型仍未覆盖。
- [HOLD 2026-07-19] SAKAMOTO-27 live KernelSU permission revocation：不重启修改 app allow byte 后，后续 `su` 请求仍可成功，说明授权状态由 KernelSU 缓存/启动态加载；app force-stop cleanup 与 allowlist restore/reboot recovery 通过。运行中撤权与无需 reboot 的策略仍待定义。
- [DONE 2026-07-19] SAKAMOTO-28 RuntimeService app process death cleanup：直接 kill Android app PID，不调用 runtimeStop，root daemon 通过 parent-death guard 退出，control socket 与双栈 NFQUEUE hook 自动消失，fresh recovery 通过；更广泛 OEM kill reason/tombstone 采集仍待验证。
- [DONE 2026-07-19] SAKAMOTO-29 RuntimeService reboot recovery：RuntimeService 活跃时 reboot，启动后无 root daemon、app process、control socket、双栈 hook 且无自动拉起，fresh start/stop recovery 通过；OEM boot policy 与 reboot 中断安装未覆盖。
- [DONE 2026-07-19] SAKAMOTO-30 APK signature/key rotation boundary：不同签名 key 的同 package APK 被 `INSTALL_FAILED_UPDATE_INCOMPATIBLE` 拒绝，原 package 保持存在，原签名 APK RuntimeService recovery 通过；正式 release key rotation、签名 lineage 与 staged migration 未覆盖。
- [DONE 2026-07-19] SAKAMOTO-31 RuntimeService notification permission denial：撤销 `POST_NOTIFICATIONS` 后 `startForeground`、root daemon 与 RuntimeService 启动仍通过，受控停止无 daemon/socket/NFQUEUE 残留；恢复授权后 fresh recovery 通过。该结论仅覆盖 Android 16 Pixel 6a debug APK，不等同于 release notification UX 验收。
- [DONE 2026-08-04] SAKAMOTO-32 VPP experimental NFQUEUE plugin audit and hardening（Android-only）：
  Pixel 6a P0-P5 已收口 multi-queue Initial Placement、约 50% scoped canonical mismatch、bounded
  canonical-return/origin verdict correctness、shared-TX rejection、credit-depth sensitivity 与
  conditional-wake latency/idle split decision。架构采用 ADR-0006 的 VPP-native Adapter hot path。
  S32 是历史 audit closure，不再独立阻塞当前工作；后续 SAKAMOTO-72..81 live-buffer POC 已
  继续补齐 ownership seam 证据，但正式产品准入仍由 S68/S69/S71 和 release/capacity gates 负责。
  P6d final campaign-21 已完成 32/32
  有效 arms，但 idle C-A 单侧 95% 上界 `+0.091950 pp` 超过 `+0.05 pp`，sleep-confirmed p99 下界
  `-3.110%` 低于 `20%` 目标；p50 回归上界 `+0.054%` 通过。当前 wake patch 因有效正式实验
  non-GO 不得进入 release；功耗无外部功率仪，仍为 INCONCLUSIVE。
- [DONE 2026-08-10] SAKAMOTO-72..81 VPP-native NFQUEUE live-buffer ownership closure POC：
  `experiments/vpp-nfq-poc/SAKAMOTO-81_HANDOFF.md` 返回主设计流。single-message NFQUEUE
  obligation 的 direct materialization、worker handoff、origin completion 与 native return 均
  PASS；one-buffer-per-obligation 为 PARTIAL，因为 multi-message datagram 采用 admission 前安全
  拒绝，不证明一个 buffer 内多 obligation 的 no-copy materialization。Android S80 证明 Pixel 6a
  上真实 IPv4/IPv6 ICMP NFQUEUE obligation、remote mismatch、duplicate/stale、clean drain、
  process-death/fresh restart 与 clean/fresh zero residue；但 Android final evidence 使用
  `buffer-data-size 2048`，不证明 Android 9000-byte capacity。该 POC 不完成 S68 Gate/L4 产品
  切片、VPN parity、Debug Activity、release packaging、production capacity 常量或 supervisor
  restart/backoff policy。
- [NOW 2026-07-19] Android L4 Product Release definition：按 `docs/product/ANDROID_L4_PRODUCT_PLAN.md`
  收口 Android-only、Root/VPN Runtime Profile、Basic L4、Product UI、content、help、release 和
  community feedback；当前先稳定核心产品接口并推进 Root/NFQUEUE 数据面 vertical slice，详细
  UI 设计后移集中处理，但仍保留为该 Release 的完成条件。
- [NOTE] VPP flow runtime 使用 per-worker single-owner；旧 shared CT A++ baseline
  已被 `docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md` 取代。
- [NEXT] FlowSteering vertical slice：工程顺序先完成 Root/NFQUEUE，再将 VPN/TUN 接入同一个
  deep Module Interface；这不拆分产品阶段，Android L4 Product Release 必须同时完成两种互斥
  Runtime Profile。两种 Packet capture Adapter 都使用 VPP-native plugin hot path；Rust 只通过
  粗粒度 compatibility ABI 管理 lifecycle、configuration、policy snapshot、status 与 diagnostics，
  不接收逐包 callback 或 live VPP buffer。普通
  报文由 Primary Software Distribution 以包含 IP protocol 的 direction-independent canonical
  五元组选择最终 owner，按目标 worker 组 batch/frame 并第一次直接投递，UID 不参与分流；
  Worker Layout 与 per-worker pool/cache capacity 启动时固定。Owner Guard 必须在任何私有 state
  更新前执行；只允许一次 Corrective Handoff，第二次 mismatch 丢弃。IP 分片参考 fork 的两阶段
  handoff，在 bounded reassembly worker co-locate/reassemble，再把 policy-ready packet 交给首片
  五元组选择的最终 owner；验证双向首次同 owner、corrective-handoff fault path、fragment
  disorder/duplicate/overlap/timeout、queue congestion 和 worker skew。该切片消费 S72-S81 handoff
  作为 ownership seam 证据，不重新把 throwaway live-buffer POC 当成产品代码。
- [NOTE] Conditional wake 当前只保留为研究方向：P5 早期诊断的约 44% sleep-confirmed p99 改善未被最终
  正式协议复现；P6d campaign-21 的 32 个 arms 全部有效，但 idle CPU 与 p99 gates 均 non-GO，p50
  gate 通过，功耗 inconclusive。当前 patch 和 mode3 persistent wake 不产品化；若未来重新开启，必须
  先提出新的机制假设，生成新的 hashed artifact，并用独立预注册协议验收 idle、latency、恢复和
  transition-race 条件，不能给旧 artifact 追加样本。
- [NEXT] 第一条 vertical slice：安装/授权 → 启动保护 → 选择应用 → 创建 IP/端口规则 →
  在 Activity 看到实际阻止与原因 → 删除规则并验证恢复。切片必须同时覆盖 UI、Rust control
  plane、VPP dataplane、测试、帮助和 release evidence。
- [NOTE] Android L4 Product Release 的完整范围同时包含 app Wi-Fi/Mobile/VPN Network Gate
  和 advanced Basic IPRULES（双栈 CIDR、五元组、端口范围、方向与接口）；这些表达能力不再
  拆成后续 CIDR/Ports 产品版本。vertical slice 仍按最小端到端场景逐步交付。
- [NOTE] L4PolicyMatcher 当前保留 UID 分组内按优先级有界扫描，保证静态匹配正确；结构重构
  延后独立设计，不是 S229/FlowRuntime 前置条件。以下是此前讨论的布局方向，不是当前实现
  或冻结的后续选择：只实现一个 priority-tiered stateless classifier，
  只按 complete Linux UID 建外层 SubjectView，内含 network Gate bit mask 与独立 IPv4/IPv6
  classifier；direction/network/interface/protocol/CIDR/port 保留为桶内 matcher 维度。在 priority
  level 内使用 mask shape、masked hash 和 bounded port-range residual check；按 `priority asc,
  explicit order asc, ruleId asc` 编译连续 WinnerRank，并以 subtable bestPossibleRank 安全早停；
  以 Android correctness、packet cost、memory、apply cost 和 worst-case probes 验收，不引入 ACL
  session/cache。
- [NEXT] Early-drop Activity boundary：Gate/L4 `DROP` 不创建 FlowEntry；热路径更新精确 app/rule
  counters，并写入 fixed-capacity worker ActivityAccumulator。只有 `PASS_NEXT` lookup/create
  FlowEntry；Accumulator eviction 只影响 UI detail，必须有明确 lost/evicted observability metrics。
- [NEXT] Protocol Identification Release：Android L4 Product Release 稳定后，在同一个
  worker-private FlowEntry 上增加 libprotoident，使用 Recognize-then-enforce；不引入 early hold、
  full CT、stream reassembly 或复杂 QUIC 适配。SAKAMOTO-61 记录了 current-packet cutoff
  metadata：Adapter completion 前产生的同步识别事实只进入当前 FlowEntry recognition state、
  Activity projection 和 provider-neutral 状态证据；ProtocolRule、real provider、以及由 current
  graph facts 影响当前 packet verdict 的消费路径尚未实现。异步结果仍只能影响后续 packet。
  SAKAMOTO-61 已完成 provider-neutral pre-decision work：ApplicationProtocolCatalog、disabled
  provider seam、FlowEntry recognition state、Activity projection、VPP reference inventory、
  libprotoident/stellar_lpi probes、selected PCAP smoke 和 provider-source decision inputs。仍未
  开始/未能声明完成的是 provider source/license/corpus/runtime enablement、real Android provider
  evidence、ProtocolRule enforcement 与 product verdict consumption。
- [NEXT] VPN Direct Egress evidence frontier：按 SAKAMOTO-114 → 115 → 116 → 117 依次证明真实
  pinned HEV/lwIP instance isolation、真实 VPP↔Flow Stack C Packet Boundary、真实 buffer/copy /
  overload/generation envelope，以及 Android owner-inline vs paired-native-thread topology；随后才恢复
  SAKAMOTO-98 → 99 → 100 → 101 → 102 的 target TCP、UDP、recovery、performance 与 closure。
  旧 external HEV child、SOCK_SEQPACKET、SOCKS fixture 和 Host model 只保留为 scoped evidence，
  不能替代这一 frontier。SAKAMOTO-59 Product Release gate 必须等待 SAKAMOTO-102 的 Direct
  Egress closure；ICMP Echo 只有通过 capability/device tests 后才发布，其它 protocol 不属于 VPN
  第一版 forwarding promise。Transport Outcome 必须与 Policy Verdict 和 Adapter Completion 分开归因。
- [NOTE] SNORT-10 Authoring / Restore UX 和 Flow Telemetry consumer 的历史目标只保留为
  可复用设计输入；其最终产品形态必须由 Android L4 UI 场景驱动。

### 3.3 候选 B：vNext 迁移与 legacy 下线（偏接口收敛）

- [NEXT] `migrate-to-control-vnext`：前端与对外工具默认切到 vNext，覆盖 Packet Diagnostics / Diagnostic Focus UX、Authoring Layer / Checkpoint Restore UX、telemetry consumer、迁移期开关、回滚口径与 legacy 并存窗口。
- [NEXT] legacy control 下线判据：明确 `60606` / legacy command 的保留期限、兼容窗口、诊断入口替代方案和最终删除条件。
- [NOTE] 这条线依赖真实版本/发布策略配合，适合在前端 RuntimeService handoff 基本可跑后推进。

### 3.4 候选 C：后端能力扩展（偏新能力）

- [DONE 2026-05-04] Flow Telemetry raw facts completeness：直接替换现有 `FLOW` payload v1 layout（不做 v2/兼容窗口/双写），补齐 ICMP type/code/id、`packetDir/flowOriginDir`、per-direction cumulative counters、`l4Status/portsAvailable`、L3 observation、`endReason`、`firstSeenNs/lastSeenNs`、显式 `verdict/action`、`uidKnown/ifindexKnown` 与可用的 `pickedUpMidStream` 语义；runtime producer 已补齐 `IPRULES=0` 时的 telemetry CT observation、`RESOURCE_EVICTED` END、按 scan budget 限制的 bounded `TELEMETRY_DISABLED` END cleanup，以及 `ruleId=0` 的 known/unknown 区分；已同步 daemon、native consumer、历史 OpenSpec 主规格与 `docs/INTERFACE_SPECIFICATION.md`。
- [NEXT] Android/VPP implementation planning：产品流程稳定后，把 handoff 中 D0-D4 的 process、
  Packet Capture Adapter、VPP graph、control/health 和 lifecycle 约束映射到第一条 vertical slice。
  PacketFacts、parser status、bounded queues、exactly-one verdict 和 immutable Runtime Snapshot
  继续作为底层准入要求；不恢复旧 direct `IPRULES.APPLY`。
- [NOTE] flow steering / owner handoff 是 per-worker correctness 基础，不再是 CT A++ 之后的
  可选 perf mode。具体 hash、queue 和 backpressure Interface 随第一条 vertical slice 收口。
- [CANDIDATE] `ip-leak` 重新纳入设计：在统一 DomainPolicy + IPRULES 口径下决定启用条件、优先级、可观测性与控制面形态。
- [CANDIDATE] “真实系统 resolver hook” 的平台闭环：仅当仍要把它作为真机 DNS 验收链路时推进。
- [CANDIDATE] 更强的 L4 stateful semantics：在 Protocol Identification Release 之后重新排序；
  不进入前两个产品版本。
- [NEXT] libprotoident application protocol identification：第二阶段已承诺；SAKAMOTO-61 已完成
  reference/probe/pre-decision seam，下一步取决于 provider source、license/provenance、corpus
  privacy/import 和 runtime enablement 决策。产品形态仍只实现 Recognize-then-enforce；L7
  HTTP/TLS/QUIC metadata 仍不属于近期承诺。

### 3.5 文档收尾（降低误读）

- [DONE 2026-04-29] Flow Telemetry 纲领文件已从讨论草案收口为工作决策文档。
- [DONE 2026-04-30] Flow Telemetry 接口已随 `add-flow-telemetry-plane` 同步到 `docs/INTERFACE_SPECIFICATION.md`。
- [DONE 2026-05-04] Flow Telemetry raw facts completeness 已同步历史 OpenSpec 主规格与 `docs/INTERFACE_SPECIFICATION.md`，新的 `FLOW` v1 binary layout 以接口文档 offset 表为准。
- [NOTE] Traffic Explorer 的 Direction split 需求不再驱动 snort producer 变更；当前 native `FLOW` 已稳定导出 `inPackets/inBytes/outPackets/outBytes`，后续工作只在 app 侧 retained summary 传播与 UI 聚合。
- [DONE 2026-04-30] Debug Stream explainability 与 Policy Bundle Checkpoints 已同步到历史 OpenSpec 主规格；`docs/INTERFACE_SPECIFICATION.md` 后续只在接口新增/变更时刷新。
- [NOTE] 当前 `docs/INTERFACE_SPECIFICATION.md` 已收敛为 vNext-only 契约（legacy 版已归档）；若下一轮先做 Flow Telemetry raw facts completeness，应先更新 telemetry ABI 契约；若先做前端 handoff，则优先补 RuntimeService / APK packaging 契约文档。

## 4. 后置候选（不挡主线）

- [CANDIDATE] 后端新能力候选集中在 3.4；讨论前不主动开实现任务，避免把产品集成期切回底层扩张期。
- [CANDIDATE] 前端/consumer 侧的 Top-K、timeline、history、Geo/ASN、注释、查询索引与 checkpoint 命名/历史不进入 daemon backlog，除非实现时暴露出明确的后端契约缺口。
- [CANDIDATE] 若下一轮优先做 RuntimeService / APK handoff，应同步补充发布、升级、回滚、日志采集与 crash/tombstone 诊断口径。

---

## Appendix A. 战略备注（NOTE；非任务）

以下几点用于承接“domain-only 旧骨架 + 新增 IP 一条腿”后的中长期整理方向；当前仅记录问题意识与推荐顺序，不视为已定方案：

- **DomainPolicy 命名边界已收口，后续以接口同步为主**：`GLOBAL_*` 已对外收敛为 `DOMAIN_DEVICE_WIDE_*`；后续不再把它列为主线 backlog，只在接口文档/测试发现漂移时修正。
- **可观测性分层已进入产品集成阶段**：旧的 A/B/C/D counters/stream/perfmetrics 已落地；Flow Telemetry MVP 已补齐前端常态 Top-K/timeline/history 所需的原始 records 层。SNORT-10 packet-side 深度取证目标是 Packet Diagnostics / Diagnostic Focus，旧 Debug Stream 只保留为历史能力与 DNS-line 冻结背景。后续重点不再是继续给 daemon 增加聚合口径，而是把 `Flow Telemetry records`（业务事实）、`Packet Diagnostics`（深度取证）、`Metrics`（后端低基数健康状态）接到 consumer / 前端工作流。
- **checkpoint / rollback 历史后端原语已落地**：pre-SNORT-10 daemon 已提供固定槽位 policy bundle snapshot 与 atomic restore，避免前端用多条 apply 命令模拟回滚时出现半恢复。SNORT-10 Authoring Layer 不继续以固定槽位作为目标，而是使用 Draft / Commit / Apply / latest-five Checkpoint / Runtime Snapshot 模型。
- **`ip-leak` 继续后置，但必须重新定义定位**：它横跨 domain 与 IP，两边都相关；当前不宜提前混入已收敛主线。需要在统一口径下重新回答它到底是“补位能力 / 默认关闭能力 / 某类场景下的重要能力”中的哪一种。
- **Flow runtime 转向 per-worker single-owner**：历史 userspace conntrack 与 OVS-derived semantics
  保留为未来 stateful 参考，但 shared CT A++ 不再是 runtime 重构目标。第一版只建立产品 Activity
  和后续 libprotoident 所需的 bounded PASS_NEXT FlowEntry；early drop 使用独立 bounded
  ActivityAccumulator，不承诺完整 CT。
- **libprotoident 是第二阶段，metadata 不是**：application protocol identification 已成为明确的
  阶段性发版目标；HTTP/TLS/QUIC metadata、stream reassembly 和复杂 QUIC 适配继续后置。

## Appendix B. 架构边界上的当前判断（NOTE；非任务）

基于当前实现形态（Android + root + NFQUEUE + userspace quick verdict），先记录一个高层判断，供后续讨论时反复对照：

- **DomainPolicy 与 IPRULES 不是二选一**：前者更偏语义友好、面向域名/名单/规则与用户理解；后者更偏底层强约束、面向 L3/L4 包判决与最终兜底。后续的目标应是“边界清晰 + 仲裁明确”，而不是把两者揉成一个失去层次的总开关。
- **强项**：device-level 的 DNS / domain-policy、IPv4/IPv6 L3/L4 规则、per-app 判决、可解释性、真机回归与性能基线。
- **可扩展但需谨慎**：L4 flow state、连接级语义、更加稳定的 cross-packet observability。
- **不应先验承诺**：被动式 full HTTP/HTTPS 语义识别；尤其在加密协议持续增强的前提下，不应把未来产品路线押注在“靠被动包检查看清上层明文语义”上。

## Appendix C. 说明：A/B/C/D 与 IPRULES 的顺序心智（NOTE；非任务）

- **A 先落地**：`reasonId/ruleId/would-match + src/dst IP` 属于后续所有规则系统的 shared 契约；先把 vNext packet stream / metrics 基座收敛，避免 IP 规则与域名侧各自“先实现再对齐”导致返工。
- **C 不拆独立里程碑**：per-rule stats 是 IP 规则引擎的 v1 必需能力（“从一开始就可解释 + 可量化”）；更合理的拆法是：在 IPRULES v1 change 内按任务拆出 “核心判决链路先跑通 → stats/输出口径补齐 → 验收/回归”。
- **B 已补齐**：它与 IPRULES 基本解耦，当前已落地；剩余工作主要是把过期设计文档状态修正，避免被误读成“未开始”。
- **D 独立**：perfmetrics 只承载性能健康指标；它在语义上独立于 A/B/C，可在任意时点推进，不改变当前主线优先级。
- **A/B/C/D 之后的历史 daemon 主线曾收敛到 Flow Telemetry**：前端常态观测不继续扩充 daemon 聚合 counters，而是由 daemon 导出 bounded records，consumer 负责持久化、查询与派生统计。该段只保留迁移背景；当前后续重点以 VPP Product Core/Rust status 与 Plane 为准。
