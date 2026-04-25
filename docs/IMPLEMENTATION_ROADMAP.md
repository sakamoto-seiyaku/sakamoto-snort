# 当前实现 Roadmap（Tooling + 功能主线）

更新时间：2026-04-25
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
- vNext 协议/命令：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`、`docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- 可观测性口径：`docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`
- OpenSpec 主规格：`openspec/specs/`

长期约束（对后续所有 change 生效）：
- 工程化任务只做 test/debug/tooling；不得顺势夹带产品功能实现。
- 如确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 1. 当前结论（1 屏可读）

### 1.1 工程化（测试/工作流）

- 当前默认开发 preset 已把 `SNORT_ENABLE_DEVICE_TESTS=OFF`，因此 `dev-debug` 与 `host-asan-clang` 会先收敛到纯 Host 回归。
- Device/DX active 入口（vNext-only；fail-fast）：
  - smoke：`dx-smoke`（platform → control → datapath）
  - diagnostics：`dx-diagnostics` / `dx-diagnostics-perf-network-load`
  - IP 模组：`tests/device/ip/run.sh --profile smoke|matrix|stress|perf|longrun`
- Device/DX 冒烟补齐以 casebook 为验收口径推进（见 3.1）。
- 真机冒烟过程中发现的 **snort 本体问题**统一记录在 `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`（避免混进 casebook/脚本变更里）。
- [NOW] OpenSpec 当前 active changes：无（下一步见 3.1）。

### 1.2 功能（Domain + IP）

- Domain+IP 的“后端融合”（vNext control 平面 + observability 口径 + datapath 接线）已完成并稳定回归；后续主风险点是**迁移与命名梳理**（前端/对外工具默认切 vNext、legacy 并存窗口与下线判据），而不是后端能力缺失。
- A/B/C/D 口径已经全部落地：
  - A：pkt verdict 可观测（`reasonId/ruleId/wouldRuleId`）
  - B：DomainPolicy counters（`policySource` / `domainSources`）
  - C：IP per-rule stats（随 IPRULES v1 一起落地）
  - D：perfmetrics（`nfq_total_us` / `dns_decision_us` 等）
- IPRULES v1 + L4 conntrack core 已落地；真机 Tier‑1 模组（netns+veth）已成为 datapath 的主要可重复验收环境。

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
- [DONE 2026-03-15] perfmetrics：`add-perfmetrics-observability`（spec：`openspec/specs/perfmetrics-observability/spec.md`）

## 3. 待办（按优先级）

### 3.1 工程化：Device / DX 冒烟 Casebook 补齐（以 casebook 为验收口径）

- [NEXT] `complete-device-smoke-casebook-other`：把 `perfmetrics.enabled` 的“可用性验证”提炼进 smoke 口径，并补上极端规模（海量 domain/import、海量 iprules）“失败必须可解释 + daemon 仍可 HELLO”的场景（默认不进 `dx-smoke` 主链，可选运行）

### 3.2 迁移与下线（前端/对外工具；不是后端能力缺口）

- [BACKLOG] `migrate-to-control-vnext`：前端与对外工具默认切到 vNext、tracked UX、迁移期开关/回滚口径、legacy 并存窗口与 `60606` 下线判据（需要真实版本/发布策略配合，独立于后端）

### 3.3 文档收尾（降低误读）

- [NEXT] 巡检并收敛仍保留历史语境的设计文档，避免被误读成“待实现提案”（例如已落地回执类文档）。
- [NEXT] 仅在接口新增/变更后刷新 `docs/INTERFACE_SPECIFICATION.md`，避免“接口文档先行”导致漂移。

## 4. 后置 / Backlog（不挡主线）

- [BACKLOG] 命名与语义边界梳理：尤其是 domain-only 历史命名（例如 `GLOBAL_*`）与 domain+IP 语义边界的统一（目标是收敛心智，不做接口大重构）
- [BACKLOG] `ip-leak` 重新纳入设计：在统一口径下决定启用条件、优先级、可观测性与控制面形态（当前保持独立 backlog，不反向污染已收敛主线）
- [BACKLOG] IPv6 新规则语义
- [BACKLOG] 域名规则 per-rule observability / stats
- [BACKLOG] “真实系统 resolver hook” 的平台闭环（如未来仍坚持把它作为真机 DNS 验收链路）
- [BACKLOG] 更强的 L4 stateful semantics（超出当前 `ct.state/ct.direction` 最小闭环的扩展能力）
- [BACKLOG] L7 / HTTP / HTTPS 被动识别（暂不作为已承诺主线）

---

## Appendix A. 战略备注（NOTE；非任务）

以下几点用于承接“domain-only 旧骨架 + 新增 IP 一条腿”后的中长期整理方向；当前仅记录问题意识与推荐顺序，不视为已定方案：

- **接口 / 模块命名梳理是必做项**：原始系统大量命名天然偏向 domain-only；在引入 IPRULES 后，需要系统性梳理哪些对外命令、对内模块名、文档术语的语义已经扩大、缩窄或变得含混。目标是**收敛命名与边界**，不是做一次接口大重构。
- **可观测性命名与分层也要跟着梳理**：A/B/C/D 已分别落地，但后续仍需统一“events / metrics / reasons / sources / per-rule stats”的命名规则与展示口径，避免 domain/IP 两套术语长期并存。
- **`ip-leak` 继续后置，但必须重新定义定位**：它横跨 domain 与 IP，两边都相关；当前不宜提前混入已收敛主线。需要在统一口径下重新回答它到底是“补位能力 / 默认关闭能力 / 某类场景下的重要能力”中的哪一种。
- **L4 conntrack core 已落地，但更强的 flow-state 仍应谨慎后置**：当前仓库已经具备最小闭环的 userspace conntrack（`ct.state/ct.direction` + hot-path gating + host/真机验证）；后续若继续扩展更强的 L4 状态语义，仍应作为独立能力评估其热路径成本、内存模型与 Android 设备约束。当前纲领入口见 `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`；实现原则仍是“以 OVS conntrack 语义为母本做 C++ 重实现”，不是重新设计另一套状态系统。
- **L7 / HTTP / HTTPS 识别暂不作为已承诺主线**：现阶段更稳的产品定位仍是 DNS/domain-policy + IPv4 L3/L4 判决与观测。更高层协议识别是否值得做、能做到什么程度，应在后续单独评估，而不是默认沿着“继续往上解包”自然推进。

## Appendix B. 架构边界上的当前判断（NOTE；非任务）

基于当前实现形态（Android + root + NFQUEUE + userspace quick verdict），先记录一个高层判断，供后续讨论时反复对照：

- **DomainPolicy 与 IPRULES 不是二选一**：前者更偏语义友好、面向域名/名单/规则与用户理解；后者更偏底层强约束、面向 L3/L4 包判决与最终兜底。后续的目标应是“边界清晰 + 仲裁明确”，而不是把两者揉成一个失去层次的总开关。
- **强项**：device-level 的 DNS / domain-policy、IPv4 L3/L4 规则、per-app 判决、可解释性、真机回归与性能基线。
- **可扩展但需谨慎**：L4 flow state、连接级语义、更加稳定的 cross-packet observability。
- **不应先验承诺**：被动式 full HTTP/HTTPS 语义识别；尤其在加密协议持续增强的前提下，不应把未来产品路线押注在“靠被动包检查看清上层明文语义”上。

## Appendix C. 说明：A/B/C/D 与 IPRULES 的顺序心智（NOTE；非任务）

- **A 先落地**：`reasonId/ruleId/would-match + src/dst IP` 属于后续所有规则系统的 shared 契约；先把 PKTSTREAM/metrics 基座收敛，避免 IP 规则与域名侧各自“先实现再对齐”导致返工。
- **C 不拆独立里程碑**：per-rule stats 是 IP 规则引擎的 v1 必需能力（“从一开始就可解释 + 可量化”）；更合理的拆法是：在 IPRULES v1 change 内按任务拆出 “核心判决链路先跑通 → stats/输出口径补齐 → 验收/回归”。
- **B 已补齐**：它与 IPRULES 基本解耦，当前已落地；剩余工作主要是把过期设计文档状态修正，避免被误读成“未开始”。
- **D 独立**：perfmetrics 只承载性能健康指标；它在语义上独立于 A/B/C，可在任意时点推进，不改变当前主线优先级。
