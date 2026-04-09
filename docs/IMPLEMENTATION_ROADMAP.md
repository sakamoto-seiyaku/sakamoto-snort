# 当前实现 Roadmap（Tooling + 功能主线）

更新时间：2026-04-09  
状态：当前共识；本文包含两条主线（互不混用代号）：
- **工程化**：测试/回归/真机调试工作流（单元测试、集成测试、真机原生调试）
- **功能**：可观测性分层 `A/B/C/D`（见 `docs/decisions/OBSERVABILITY_WORKING_DECISIONS.md`），以及其上层的 IPRULES / DomainPolicy 相关实现

## 1. 工程化基线（已收敛）

工程化（test/debug/tooling）阶段号使用 `P0/P1/P2/P3`，与功能线（A/B/C/D、IPRULES）互不混用：

- **P0 Host-side 单元测试（gtest）**：见 `tests/host/`
- **P1 Host-driven 集成测试（host/WSL 驱动真机）**：见 `tests/integration/run.sh` 与 `tests/integration/lib.sh`
- **P2 真机集成 / smoke / 兼容性验证 / perf**：见 `tests/integration/device-smoke.sh`、`tests/integration/perf-network-load.sh`、`tests/integration/iprules-device-matrix.sh`（runbook：`docs/testing/IPRULES_DEVICE_VERIFICATION.md`）、`tests/integration/full-smoke.sh`，以及项目级 IP 真机模组 `tests/device-modules/ip/run.sh`
- **P3 真机原生调试（LLDB / VS Code + CodeLLDB）**：见 `docs/tooling/VSCODE_CMAKE_WORKFLOW.md`

长期约束（对后续所有 change 生效）：
- 工程化任务只做 test/debug/tooling；不得顺势夹带产品功能实现。
- 如确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 2. 功能主线收敛状态（A/B/C + IPRULES + conntrack；D 独立）

基于 `docs/decisions/OBSERVABILITY_WORKING_DECISIONS.md` 与 `docs/decisions/IP_RULE_POLICY_WORKING_DECISIONS.md` 的当前共识，A/B/C 主线推荐顺序如下：

`A（Packet 判决层可观测性：add-pktstream-observability） → IPRULES v1（add-app-ip-l3l4-rules-engine，包含 C：per-rule stats） → B（DomainPolicy 层 counters：policySource） → ip-leak 融合 / IPv6 / 域名 per-rule（TBD）`

> 术语提醒：DomainPolicy 文档/代码中的 `GLOBAL_*` 是“域名侧 device-wide 层”，并非 domain+IP 的真正全局；统一命名会在后续 domain+IP 融合阶段一并处理。

当前落地状态（以仓库内 code + tests 为准）：
- ✅ A：`add-pktstream-observability`（PKTSTREAM vNext schema + `reasonId/ruleId/wouldRuleId`）
- ✅ D：`perfmetrics-observability`（`PERFMETRICS` / `METRICS.PERF` + `tests/integration/perf-network-load.sh`）
- ✅ IPRULES v1：`add-app-ip-l3l4-rules-engine`（IPv4 L3/L4 per-UID rules + per-rule stats + `tests/integration/iprules.sh`）
- ✅ IPRULES v1 真机矩阵补偿项：`docs/testing/IPRULES_DEVICE_VERIFICATION.md` + `tests/integration/iprules-device-matrix.sh`（已记录多次目标真机运行结果）
- ✅ IPRULES cache-off 诊断变体：`add-iprules-cacheoff-build-variant`（`sucre-snort-iprules-nocache` + host nocache 单测 + 真机 perf 诊断入口）
- ✅ IP 真机测试模组（Tier-1）：`tests/device-modules/ip/run.sh`（OpenSpec change `add-ip-test-component` 已归档）
  - 已完成：runner/目录结构、Tier-1 `netns+veth`、`smoke`/`matrix`/`stress`/`perf` 入口、核心 functional matrix（`IPRULES/IFACE_BLOCK/BLOCKIPLEAKS`）、neper baseline、cache-off 基线记录、ruleset sweep（`perf_ruleset_sweep.sh`）
  - Deferred（post domain+IP fusion）：`longrun` case + 对应文档补齐、（可选）轻量 `ip-smoke` 接入 CTest/CI（见 `update-post-domain-ip-fusion-rollup`）
- ✅ B：DomainPolicy counters（`policySource`；OpenSpec：`add-domain-policy-observability`）
  - 控制面：`METRICS.DOMAIN.SOURCES*` + RESET 严格边界
  - tests：host 单测 + host-driven integration（见 `tests/integration/run.sh` 的 IT-12）
  - 真机闭环：已可通过 `DEV.DNSQUERY` 在真机上稳定闭环 B 层计数；“真实系统 resolver → netd socket → DnsListener”链路仍属平台/环境排障项，不阻塞 B 层本身验收
- ✅ L4 conntrack core：`add-iprules-conntrack-core`（OpenSpec 已归档）
  - 能力：userspace conntrack core 已接入 `IPRULES`，支持 `ct.state={new|established|invalid}`、`ct.direction={orig|reply}`，并保留“无 ct consumer 时跳过热路径更新”的 gating 语义
  - 文档：主规格已提升到 `openspec/specs/l4-conntrack-core/spec.md`；接口已同步到 `docs/INTERFACE_SPECIFICATION.md`
  - tests：host 单测 + Tier-1 真机 case `22_conntrack_ct.sh` + `perf_ct_compare` 已落地，并有独立记录 `docs/testing/ip/CONNTRACK_CT_TIER1_VERIFICATION.md`
- ⏳ 多用户 / blockmask chains /（post domain+IP fusion）收尾：`update-post-domain-ip-fusion-rollup`（延后执行 backlog；当前不阻塞 IP/observability 主线）
  - 当前 active backlog scope 仅包含：blockmask chains 剩余验证、multi-user 剩余验证/文档、IP test module 的 `longrun`/文档/可选 CI hook

## 3. 之后的工作（按优先级）

现在主线已经从“把 A/B/C/D 和 IPRULES 做出来”切换到“收尾 + 融合 + 下一阶段规划”。后续工作建议分三层看：

### 3.1 立刻可做（低风险收尾）

- 已完成：`add-domain-policy-observability` 已归档；当前 OpenSpec active changes 已收敛到真正未完成项
- 已完成：`add-iprules-conntrack-core` 已归档；roadmap 先前把它写成“待研究方向”，现已改为已落地能力
- 当前唯一 active change：`update-post-domain-ip-fusion-rollup`；它不是新功能 change，而是 backlog rollup，范围只包括剩余验证、文档补齐与 Tier-1 longrun/可选 CI hook
- 继续巡检并收敛仍保留历史语境的设计文档；例如 `docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md` 现已转为已落地回执，应继续避免被误读成“待实现提案”
- 保持 `docs/INTERFACE_SPECIFICATION.md` 与当前控制面一致；目前 `METRICS.DOMAIN.SOURCES*` 与 `IPRULES ct.*` 已同步，后续只在接口新增时再刷新

### 3.2 下一条真正的功能主线

- **domain+IP fusion**：统一“域名侧 GLOBAL_* 并不是真全局”的命名与语义边界，梳理 DomainPolicy / IPRULES / legacy 路径之间的融合口径（入口：`docs/decisions/DOMAIN_IP_FUSION_CHECKLIST.md`）
- **ip-leak 重新纳入设计**：在 fusion 阶段统一决定其启用条件、优先级、可观测性与控制面形态；当前仍保持独立 backlog，不反向污染已收敛的 IPRULES v1/B 层语义

### 3.3 明确后置（不要提前打散主线）

- `update-post-domain-ip-fusion-rollup` 中的 blockmask chains 剩余验证（bit/listId 组合、兼容性、BLOCKMASK 归一化）
- `update-post-domain-ip-fusion-rollup` 中的 multi-user 剩余验证与文档补齐（单用户回归、多用户场景、`SNORT_MULTI_USER_REFACTOR` 更新、`full-smoke` 用例沉淀）
- IP 真机测试模组的 `longrun` case、对应文档补齐，以及可选 `ip-smoke` CTest/CI hook
- IPv6 新规则语义
- 域名规则 per-rule 级 observability / stats
- “真实系统 resolver hook” 的平台闭环（如果未来仍坚持把它作为真机 DNS 验收链路）
- 更强的 L4 stateful semantics（超出当前 `ct.state/ct.direction` 最小闭环的扩展能力）

说明（对应你提议的 “IP rule → C → B”）：
- **A 必须先落地**：`reasonId/ruleId/would-match + src/dst IP` 属于后续所有规则系统的 shared 契约；先把 PKTSTREAM/metrics 基座收敛，避免 IP 规则与域名侧各自“先实现再对齐”导致返工。
- **C 不建议拆成独立里程碑**：per-rule stats 是 IP 规则引擎的 v1 必需能力（“从一开始就可解释 + 可量化”）；更合理的拆法是：在 `add-app-ip-l3l4-rules-engine` change 内部按任务拆出 “核心判决链路先跑通 → stats/输出口径补齐 → 验收/回归”。
- **B 已补齐**：它与 IPRULES 基本解耦，当前已落地；剩余工作主要是归档与把过期设计文档状态修正，避免 roadmap/设计文档继续把它当作“未开始”。
- **D 不参与上述排序**：D 只承载 `nfq_total_us` / `dns_decision_us` 这类性能健康指标；它在语义上独立于 A/B/C，可作为单独 change 在任意时点推进，不改变当前主线优先级。当前已落地：见 `openspec/specs/perfmetrics-observability/spec.md` 与 `tests/integration/perf-network-load.sh`。
- **IP test module 与 integration lane 当前并存**：`tests/device-modules/ip/run.sh --profile matrix|stress` 已覆盖核心语义；`tests/integration/iprules-device-matrix.sh` 暂保留为 legacy 对照/额外用例入口（直到确认完全收敛并可替代为止）。
- **OpenSpec 主规格已同步到位**：A / IPRULES v1 / cache-off / ip-test-component / DomainPolicy observability / L4 conntrack core 相关 change 已归档；当前 capability 已体现在 `openspec/specs/pktstream-observability/spec.md`、`openspec/specs/app-ip-l3l4-rules/spec.md`、`openspec/specs/domain-policy-observability/spec.md` 与 `openspec/specs/l4-conntrack-core/spec.md`。当前 OpenSpec in-flight/backlog 以 `update-post-domain-ip-fusion-rollup` 为主。

## 4. 战略备注（记录方向，不提前锁死实现）

以下几点用于承接“domain-only 旧骨架 + 新增 IP 一条腿”后的中长期整理方向；当前仅记录问题意识与推荐顺序，不视为已定方案：

- **接口 / 模块命名梳理是必做项**：原始系统大量命名天然偏向 domain-only；在引入 IPRULES 后，需要系统性梳理哪些对外命令、对内模块名、文档术语的语义已经扩大、缩窄或变得含混。目标是**收敛命名与边界**，不是做一次接口大重构。
- **可观测性命名与分层也要跟着梳理**：A/B/C/D 已分别落地，但后续仍需在 domain+IP fusion 阶段统一“events / metrics / reasons / sources / per-rule stats”的命名规则与展示口径，避免 domain/IP 两套术语长期并存。
- **`ip-leak` 继续后置，但必须重新定义定位**：它横跨 domain 与 IP，两边都相关；当前不宜提前混入已收敛主线。等 domain+IP fusion 时，需要重新回答它到底是“补位能力 / 默认关闭能力 / 某类场景下的重要能力”中的哪一种。
- **L4 conntrack core 已落地，但更强的 flow-state 仍应谨慎后置**：当前仓库已经具备最小闭环的 userspace conntrack（`ct.state/ct.direction` + hot-path gating + host/真机验证）；后续若继续扩展更强的 L4 状态语义，仍应作为独立能力评估其热路径成本、内存模型与 Android 设备约束。当前纲领入口见 `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`；实现原则仍是“以 OVS conntrack 语义为母本做 C++ 重实现”，不是重新设计另一套状态系统。
- **L7 / HTTP / HTTPS 识别暂不作为已承诺主线**：现阶段更稳的产品定位仍是 DNS/domain-policy + IPv4 L3/L4 判决与观测。更高层协议识别是否值得做、能做到什么程度，应在后续单独评估，而不是默认沿着“继续往上解包”自然推进。

## 5. 架构边界上的当前判断

基于当前实现形态（Android + root + NFQUEUE + userspace quick verdict），先记录一个高层判断，供后续讨论时反复对照：

- **DomainPolicy 与 IPRULES 不是二选一**：前者更偏语义友好、面向域名/名单/规则与用户理解；后者更偏底层强约束、面向 L3/L4 包判决与最终兜底。后续融合的目标应是“边界清晰 + 仲裁明确”，而不是把两者揉成一个失去层次的总开关。
- **强项**：device-level 的 DNS / domain-policy、IPv4 L3/L4 规则、per-app 判决、可解释性、真机回归与性能基线。
- **可扩展但需谨慎**：L4 flow state、连接级语义、更加稳定的 cross-packet observability。
- **不应先验承诺**：被动式 full HTTP/HTTPS 语义识别；尤其在加密协议持续增强的前提下，不应把未来产品路线押注在“靠被动包检查看清上层明文语义”上。

> 注：`docs/INTERFACE_SPECIFICATION.md` 作为对外接口汇总，应在相关 change 合并并稳定后统一刷新，避免“接口文档先行”导致漂移。当前已同步：`METRICS.DOMAIN.SOURCES*` 与 `IPRULES ct.*`。
