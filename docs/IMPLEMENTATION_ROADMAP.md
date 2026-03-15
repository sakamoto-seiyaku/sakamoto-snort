# 当前实现 Roadmap（Tooling + 功能主线）

更新时间：2026-03-15  
状态：当前共识；本文包含两条主线（互不混用代号）：
- **工程化**：测试/回归/真机调试工作流（单元测试、集成测试、真机原生调试）
- **功能**：可观测性分层 `A/B/C/D`（见 `docs/OBSERVABILITY_WORKING_DECISIONS.md`），以及其上层的 IPRULES / DomainPolicy 相关实现

## 1. 工程化基线（已收敛）

当前仓库已经把“可测试 + 可真机调试”的闭环固化为可重复执行的入口（不再使用 `P0/P1/P2/P3` 作为阶段号）：

- 单元测试（host-side / gtest）：见 `tests/host/`
- 集成测试 / 真机回归：见 `tests/integration/`
  - baseline：`tests/integration/run.sh`
  - 平台专项 smoke / compatibility：`tests/integration/device-smoke.sh`
  - perf baseline：`tests/integration/perf-network-load.sh`
  - 协议全量回归：`tests/integration/full-smoke.sh`（更广，但不替代 smoke）
- 真机原生调试（LLDB / VS Code + CodeLLDB）：见 `docs/VSCODE_CMAKE_WORKFLOW.md`

长期约束（对后续所有 change 生效）：
- 工程化任务只做 test/debug/tooling；不得顺势夹带产品功能实现。
- 如确需极小的 test seam / debug seam，必须先说明必要性，并把范围压到最小。

## 2. 功能主线顺序（A/B/C + IPRULES；D 独立）

基于 `docs/OBSERVABILITY_WORKING_DECISIONS.md` 与 `docs/IP_RULE_POLICY_WORKING_DECISIONS.md` 的当前共识，A/B/C 主线推荐顺序如下：

`A（Packet 判决层可观测性：add-pktstream-observability） → IPRULES v1（add-app-ip-l3l4-rules-engine，包含 C：per-rule stats） → B（DomainPolicy 层 counters：policySource） → ip-leak 融合 / IPv6 / 域名 per-rule（TBD）`

说明（对应你提议的 “IP rule → C → B”）：
- **A 必须先落地**：`reasonId/ruleId/would-match + src/dst IP` 属于后续所有规则系统的 shared 契约；先把 PKTSTREAM/metrics 基座收敛，避免 IP 规则与域名侧各自“先实现再对齐”导致返工。
- **C 不建议拆成独立里程碑**：per-rule stats 是 IP 规则引擎的 v1 必需能力（“从一开始就可解释 + 可量化”）；更合理的拆法是：在 `add-app-ip-l3l4-rules-engine` change 内部按任务拆出 “核心判决链路先跑通 → stats/输出口径补齐 → 验收/回归”。
- **B 可后置但不应长期拖欠**：它与 IPRULES 基本解耦，因此放在 IP 主线之后没问题；但建议在 IPRULES 主线落地后立刻补齐，避免域名侧长期缺乏默认可查的归因与 counters。
- **D 不参与上述排序**：D 只承载 `nfq_total_us` / `dns_decision_us` 这类性能健康指标；它在语义上独立于 A/B/C，可作为单独 change 在任意时点推进，不改变当前主线优先级。

> 注：`docs/INTERFACE_SPECIFICATION.md` 作为对外接口汇总，应在相关 change 合并并稳定后统一刷新，避免“接口文档先行”导致漂移。
