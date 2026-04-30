# 当前实现 Roadmap（Tooling + 功能主线）

更新时间：2026-04-30
状态：当前共识（以仓库内 code + tests + OpenSpec 主规格为准）

## 0. 阅读指南

本文结构：
- 1) 当前结论：一屏摘要（回答“现在做到哪了”）
- 2) 已完成：事实清单（按模块；带日期）
- 3) 待办：下一步工作（按优先级）
- 4) 后置：不挡主线的 backlog
- Appendix：战略备注 / 架构边界判断（NOTE；非任务）

运行环境术语（工程化讨论统一用这套）：
- `Host`：本机 `gtest/CTest`
- `Host + ASAN`：同一套 Host case 的 AddressSanitizer 变体
- `Device / DX`：ADB + root 真机集成（smoke/diagnostics/IP 模组/perf/longrun）
- `Native Debug`：真机原生调试（LLDB / VS Code + CodeLLDB），见 `docs/tooling/VSCODE_CMAKE_WORKFLOW.md`

历史用语：
- 仓库里现存 `p0/p1/p2` 只保留为历史 CTest label / 存量文档用语，不再当作当前路线图阶段名。

Status 口径（全篇统一）：
- `[DONE YYYY-MM-DD]`：已落地并归档/收敛
- `[NOW]`：当前正在做（本周/本迭代）
- `[NEXT]`：下一步紧接着做（已明确但未开始）
- `[BACKLOG]`：明确后置（不挡当前主线）
- `[NOTE]`：战略/架构判断（非任务，不与 TODO 混用）

单一真相 / 索引：
- Host 现状盘点：`docs/testing/HOST_TEST_SURVEY.md`
- Device/DX 重组纲领：`docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`
- Device/DX 冒烟 casebook：`docs/testing/DEVICE_SMOKE_CASEBOOK.md`
- Device/DX 覆盖矩阵：`docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`
- 历史 vNext 设计材料（已归档；非权威）：`docs/archived/DOMAIN_IP_FUSION/`
- 对外接口规范（vNext-only）：`docs/INTERFACE_SPECIFICATION.md`
- 可观测性口径：`docs/INTERFACE_SPECIFICATION.md`、`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`、`docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md`
- RESETALL runtime 并发边界：`docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md`
- OpenSpec 主规格：`openspec/specs/`

长期约束（对后续所有 change 生效）：
- 工程化任务只做 test/debug/tooling；不得顺势夹带产品功能实现。
- 如确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 1. 当前结论（1 屏可读）

### 1.1 工程化（测试/工作流）

- 当前默认开发 preset 已把 `SNORT_ENABLE_DEVICE_TESTS=OFF`，因此 `dev-debug` 与 `host-asan-clang` 会先收敛到纯 Host 回归。
- Device/DX active/optional 入口（vNext-only；smoke fail-fast）：
  - smoke：`dx-smoke`（platform → control → datapath）
  - diagnostics：`dx-diagnostics` / `dx-diagnostics-perf-network-load`
  - optional casebook：`dx-casebook-other`（`## 其他` Case 1–2；不进默认 `dx-smoke` 主链）
  - IP 模组：`tests/device/ip/run.sh --profile smoke|matrix|stress|perf|longrun`
- Device/DX 冒烟补齐以 casebook 为验收口径推进（见 2.2）。
- 真机冒烟过程中发现的 **snort 本体问题**统一记录在 `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`（避免混进 casebook/脚本变更里）。
- OpenSpec 当前 active changes：
  - `add-debug-stream-explainability`：Debug Stream 自包含取证链条（已创建，待实现）。
  - `add-policy-bundle-checkpoints`：前端 checkpoint / rollback 所需的后端固定槽位 policy bundle 原语（已创建，待实现）。

### 1.2 功能（Domain + IP + Flow Telemetry）

- Domain+IP 的“后端融合”（vNext control 平面 + observability 口径 + datapath 接线）已完成并稳定回归；IPv4/IPv6 双栈、L4 conntrack core、DomainPolicy device-wide 命名收敛、DomainRules per-rule observability 均已完成。
- A/B/C/D 口径已经全部落地：
  - A：pkt verdict 可观测（`reasonId/ruleId/wouldRuleId`）
  - B：DomainPolicy counters（`policySource` / `domainSources`）
  - C：IP per-rule stats（随 IPRULES v1 一起落地）
  - D：perfmetrics（`nfq_total_us` / `dns_decision_us` 等）
- IPRULES dual-stack（IPv4/IPv6）+ L4 conntrack core 已落地；真机 Tier-1 模组（netns+veth）已成为 datapath 的主要可重复验收环境。
- [DONE 2026-04-30] Flow Telemetry MVP 已完成：bounded shared-memory records、vNext `TELEMETRY.OPEN/CLOSE`、minimal telemetry metrics、`FLOW` / blocked-only `DNS_DECISION` producers、真机 mmap consumer 通路与 Flow On/Off perf 对照均已落地。
- Flow Telemetry 的分层边界已收口：常态 records 只包含业务事实（`FLOW` / `DNS_DECISION`），Debug Stream 保留为深度取证能力，Metrics 保留为后端低基数健康状态。
- 前端支撑缺口已收敛：Flow Telemetry 已完成；Debug Stream explainability 已独立建 change；checkpoint / rollback 升级为后端需要提供的最小强保证能力，形式为固定槽位 Policy Bundle Checkpoint。

## 2. 已完成（事实清单）

### 2.1 工程化（DX workflow / 真机测试组织）

- [DONE 2026-04-23] `rework-dx-smoke`：收敛 active smoke 入口到 `dx-smoke{,-platform,-control,-datapath}`（spec：`openspec/specs/dx-smoke-workflow/spec.md`）
- [DONE 2026-04-24] `rework-dx-diagnostics`：收敛 active diagnostics 入口到 `dx-diagnostics{,-perf-network-load}`（spec：`openspec/specs/dx-diagnostics-workflow/spec.md`）
- [DONE 2026-03-24] `add-ip-test-component`：IP 真机测试模组（Tier‑1 netns+veth + profiles；spec：`openspec/specs/ip-test-component/spec.md`）
- [DONE 2026-03-24] `add-iprules-cacheoff-build-variant`：cache-off 变体 + perf 对照记录（记录：`docs/testing/PERFORMANCE_TEST_RECORD.md`）
- [DONE 2026-04-22] `update-post-domain-ip-fusion-rollup`：后置 rollup（验证/文档/longrun 归位；仅保留为 archive 记录）

### 2.2 工程化（Device smoke casebook 补齐）

- [DONE 2026-04-24] `complete-device-smoke-casebook-platform`：补齐 platform gate 可解释性（host 工具链 + vNext HELLO sanity + `--skip-deploy` 语义；spec：`openspec/specs/dx-smoke-platform-gate/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-domain`：补齐 `DEVICE_SMOKE_CASEBOOK.md` `## 域名` Case 1–9（dns stream e2e、traffic/domainSources bucket、suppressed notice、真实 resolver hook BLOCKED 语义、DOMAINRULES(ruleIds)；spec：`openspec/specs/dx-smoke-domain-casebook/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-ip`：补齐 IP 模块 smoke 口径（allow/block/would-match、`block.enabled=0`、`iprules.enabled=0`、payload bytes、维度级 traffic/reasons/stats、pkt stream 字段；spec：`openspec/specs/dx-smoke-ip-casebook/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-conntrack`：补齐 Conntrack 模块 smoke 口径（`ct.state/direction` 最小闭环、create-on-accept、block 不 create entry；spec：`openspec/specs/dx-smoke-conntrack-casebook/spec.md`）
- [DONE 2026-04-25] `complete-device-smoke-casebook-other`：补齐 `DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2（perfmetrics.enabled 可用性验证、极端规模 limits sanity；spec：`openspec/specs/dx-smoke-other-casebook/spec.md`）

### 2.3 功能（Domain+IP；后端已收敛）

- [DONE 2026-04-21] vNext codec + ctl：`add-control-vnext-codec-ctl`（spec：`openspec/specs/control-vnext-codec/spec.md`、`openspec/specs/sucre-snort-ctl/spec.md`）
- [DONE 2026-04-21] vNext daemon base（meta/inventory/config）：`add-control-vnext-daemon-base`（spec：`openspec/specs/control-vnext-daemon-base/spec.md`）
- [DONE 2026-04-21] vNext domain surface：`add-control-vnext-domain-surface`（spec：`openspec/specs/control-vnext-domain-surface/spec.md`）
- [DONE 2026-04-22] vNext iprules surface：`add-control-vnext-iprules-surface`（spec：`openspec/specs/control-vnext-iprules-surface/spec.md`）
- [DONE 2026-04-22] vNext metrics surface（traffic/conntrack/perf/reasons/domainSources）：`add-control-vnext-metrics`（spec：`openspec/specs/control-vnext-metrics-surface/spec.md`、`openspec/specs/traffic-observability/spec.md`、`openspec/specs/conntrack-observability/spec.md`）
- [DONE 2026-04-22] vNext stream surface（pkt/dns/activity + notice/barrier）：`add-control-vnext-stream`（spec：`openspec/specs/control-vnext-stream-surface/spec.md`）
- [DONE 2026-04-22] legacy 冻结收口 + lane 分轨：`stabilize-control-transition-surface`（spec：`openspec/specs/control-transition-surface/spec.md`）
- [DONE 2026-03-24] pktstream 可观测性：`add-pktstream-observability`（spec：`openspec/specs/pktstream-observability/spec.md`）
- [DONE 2026-03-24] IPRULES v1（IPv4 L3/L4 + per-rule stats）：`add-app-ip-l3l4-rules-engine`（spec：`openspec/specs/app-ip-l3l4-rules/spec.md`）
- [DONE 2026-03-27] DomainPolicy observability（policySource counters）：`add-domain-policy-observability`（spec：`openspec/specs/domain-policy-observability/spec.md`）
- [DONE 2026-03-30] L4 conntrack core：`add-iprules-conntrack-core`（spec：`openspec/specs/l4-conntrack-core/spec.md`）
- [DONE 2026-04-27] IPRULES IPv4/IPv6 双栈：`add-iprules-dual-stack-ipv6`（required `family`/mk2、IPv6 header walker + `l4Status`、conntrack byFamily metrics、host + device Tier‑1 回归；决策入口：`docs/decisions/IPRULES_DUAL_STACK_WORKING_DECISIONS.md`）
- [DONE 2026-04-27] DomainPolicy device-wide 命名收敛：`rename-domain-policy-global-to-domain-device-wide`（`GLOBAL_*` 对外收敛为 `DOMAIN_DEVICE_WIDE_*`；spec：`openspec/specs/domain-policy-observability/spec.md`）
- [DONE 2026-04-28] DomainRules per-rule observability：`add-domainrules-per-rule-observability`（域名规则命中/状态观测补齐；spec：`openspec/specs/domainrules-per-rule-observability/spec.md`）
- [DONE 2026-03-15] perfmetrics：`add-perfmetrics-observability`（spec：`openspec/specs/perfmetrics-observability/spec.md`）
- [DONE 2026-04-30] Flow Telemetry Plane：`add-flow-telemetry-plane`（shared-memory ring export channel、`TELEMETRY.OPEN/CLOSE`、`METRICS.GET(name=telemetry)`、`FLOW` / `DNS_DECISION` records、host + 真机 + perf + longrun 回归；spec：`openspec/specs/control-vnext-telemetry-surface/spec.md`、`openspec/specs/flow-telemetry-export-channel/spec.md`、`openspec/specs/flow-telemetry-records/spec.md`）

### 2.4 稳定性（运行期并发边界）

- [DONE 2026-04-26] RESETALL runtime 并发边界：修复 `RESETALL` 与周期性 `snortSave()` 竞态，以及 packet / DNS 热路径锁外准备对象跨 reset 发布问题；设计口径见 `docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md`，审查状态见 `docs/reviews/CURRENT_HEAD_CPP_CONCURRENCY_REVIEW.md`。
- [DONE 2026-04-26] legacy stream 冻结：`DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 不再作为实时事件通道；支持入口统一到 vNext `STREAM.START(type=dns|pkt|activity)`，消除 legacy 同步 socket write 对热路径与 `RESETALL` 的反压风险。
- [DONE 2026-04-26] vNext mutation / datapath 锁拆分：新增 control mutation mutex，普通 vNext apply/import/config/metrics reset 不再持有 `mutexListeners` 覆盖大 CPU / I/O 工作；`RESETALL` 仍按 save/reset → control mutation → datapath quiesce 顺序完整串行化。
- [DONE 2026-04-26] daemon lifecycle ownership：`stabilize-daemon-lifecycle-ownership`（main-owned shutdown、session-owned fd、active session budget、send deadline；并更新 concurrency review lifecycle findings）

### 2.5 文档（对外契约 / 权威口径）

- [DONE 2026-04-26] `sync-iprules-dual-stack-authority-docs`：同步 dual-stack IPRULES 的权威设计/契约文档，避免跨文档漂移与误读。
- [DONE 2026-04-27] 接口规范收敛：重写 `docs/INTERFACE_SPECIFICATION.md` 为 vNext-only，并归档 legacy 版到 `docs/archived/INTERFACE_SPECIFICATION_v3.7_2026-04-26_legacy.md`。
- [DONE 2026-04-29] Flow Telemetry 工作纲领收口：`docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md` 明确常态 records、Debug Stream、Metrics 与 `tracked` 的边界。

## 3. 待办（按优先级）

### 3.1 Flow Telemetry 主线（常态观测原始事实层）

- [DONE 2026-04-30] `add-flow-telemetry-plane` 已覆盖 Flow Telemetry MVP：Ring/session ABI POC、FlowRecord producer、DnsDecisionRecord producer、Control/state/metrics integration、接口文档同步、host/device/perf/longrun 验证。
- [NOTE] 后续不再把 daemon 侧 Flow Telemetry MVP 切分为多个 active change；剩余工作进入 3.2 的独立 backlog。

### 3.2 后续独立能力（不混入 Flow Telemetry MVP）

- [NOW] `add-debug-stream-explainability`：补齐策略链条证据，使 Debug 场景只靠 tracked Debug Stream 还原 DNS 请求与 packet verdict 的取证链条；不新增 Flow Telemetry records、Metrics、Top-K、timeline/history。
- [NOW] `add-policy-bundle-checkpoints`：新增 3 个固定 `CHECKPOINT.*` slot，保存 policy-only bundle，并提供 atomic-or-no-op restore；用于前端 undo / rollback / 自救工作流的后端最小强保证原语。
- [BACKLOG] Flow Telemetry consumer / 前端持久化查询库：records 的落盘、索引、Top-K、timeline、Geo/ASN/注释等由前端/consumer 层实现，不放进 daemon。

### 3.3 迁移与下线（前端/对外工具；不是后端能力缺口）

- [BACKLOG] `migrate-to-control-vnext`：前端与对外工具默认切到 vNext、tracked UX、迁移期开关/回滚口径、legacy 并存窗口与 `60606` 下线判据（需要真实版本/发布策略配合，独立于后端）

### 3.4 文档收尾（降低误读）

- [DONE 2026-04-29] Flow Telemetry 纲领文件已从讨论草案收口为工作决策文档。
- [DONE 2026-04-30] Flow Telemetry 接口已随 `add-flow-telemetry-plane` 同步到 `docs/INTERFACE_SPECIFICATION.md`。
- [NOTE] 仅在接口新增/变更后刷新 `docs/INTERFACE_SPECIFICATION.md`；当前已于 2026-04-30 收敛为 vNext-only + Flow Telemetry 契约（legacy 版已归档）。

## 4. 后置 / Backlog（不挡主线）

- [BACKLOG] `ip-leak` 重新纳入设计：在统一口径下决定启用条件、优先级、可观测性与控制面形态（当前保持独立 backlog，不反向污染已收敛主线）
- [BACKLOG] “真实系统 resolver hook” 的平台闭环（如未来仍坚持把它作为真机 DNS 验收链路）
- [BACKLOG] 更强的 L4 stateful semantics（超出当前 `ct.state/ct.direction` 最小闭环的扩展能力）
- [BACKLOG] L7 / HTTP / HTTPS 被动识别（暂不作为已承诺主线）

---

## Appendix A. 战略备注（NOTE；非任务）

以下几点用于承接“domain-only 旧骨架 + 新增 IP 一条腿”后的中长期整理方向；当前仅记录问题意识与推荐顺序，不视为已定方案：

- **DomainPolicy 命名边界已收口，后续以接口同步为主**：`GLOBAL_*` 已对外收敛为 `DOMAIN_DEVICE_WIDE_*`；后续不再把它列为主线 backlog，只在接口文档/测试发现漂移时修正。
- **可观测性分层进入 Flow Telemetry 阶段**：旧的 A/B/C/D counters/stream/perfmetrics 已落地；Flow Telemetry MVP 已补齐前端常态 Top-K/timeline/history 所需的原始 records 层。后续继续按 `Flow Telemetry records`（业务事实）、`Debug Stream`（深度取证）、`Metrics`（后端低基数健康状态）三层推进。
- **checkpoint / rollback 升级为后端最小强保证能力**：前端仍负责命名、历史、备注、工作流与导入导出包；daemon 只提供固定槽位 policy bundle snapshot 与 atomic restore，避免前端用多条 apply 命令模拟回滚时出现半恢复。
- **`ip-leak` 继续后置，但必须重新定义定位**：它横跨 domain 与 IP，两边都相关；当前不宜提前混入已收敛主线。需要在统一口径下重新回答它到底是“补位能力 / 默认关闭能力 / 某类场景下的重要能力”中的哪一种。
- **L4 conntrack core 已落地，但更强的 flow-state 仍应谨慎后置**：当前仓库已经具备最小闭环的 userspace conntrack（`ct.state/ct.direction` + hot-path gating + host/真机验证）；后续若继续扩展更强的 L4 状态语义，仍应作为独立能力评估其热路径成本、内存模型与 Android 设备约束。当前纲领入口见 `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`；实现原则仍是“以 OVS conntrack 语义为母本做 C++ 重实现”，不是重新设计另一套状态系统。
- **L7 / HTTP / HTTPS 识别暂不作为已承诺主线**：现阶段更稳的产品定位仍是 DNS/domain-policy + IPv4 L3/L4 判决与观测。更高层协议识别是否值得做、能做到什么程度，应在后续单独评估，而不是默认沿着“继续往上解包”自然推进。

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
- **A/B/C/D 之后的主线是 Flow Telemetry**：前端常态观测不继续扩充 daemon 聚合 counters，而是由 daemon 导出 bounded records，consumer 负责持久化、查询与派生统计。
