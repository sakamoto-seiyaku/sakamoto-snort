## ADDED Requirements

### Requirement: IP test component exists and is runnable on real devices
系统（仓库）MUST 提供一个可重复执行的 IP 真机测试模组，用于在真机上回归验证 IP/L3-L4 firewall 相关逻辑的端到端行为（控制面下发 → NFQUEUE 真实流量 → 判决/归因/统计）。

#### Scenario: Run the IP smoke profile
- **WHEN** 开发者运行 IP 组件的 smoke 入口
- **THEN** 组件 SHALL 优先在不依赖额外外部基础设施的情况下触发最小真实网络流量（ICMP/TCP/UDP 至少其一）
- **AND** 组件 SHALL 对 `IPRULES` 的 enforce 命中与 bypass 行为给出明确断言（PASS/FAIL/SKIP）
- **AND** IF 真机缺少必要前置（如无法获取 root、缺 `ip netns`/`veth` 支持且未配置可用的 Tier-2/Tier-3 流量源）
  **THEN** 组件 SHALL 以 `SKIP` 结束，并输出明确原因（而不是误报 FAIL）

### Requirement: The IP component supports running subsets and produces a stable summary
IP 测试模组 MUST 支持按 profile/group/case 运行子集，并输出稳定的汇总（PASSED/FAILED/SKIPPED 计数）以用于回归比较。

#### Scenario: Run a single case
- **WHEN** 开发者通过参数选择运行一个单独用例
- **THEN** 组件 SHALL 仅运行该用例，并输出汇总

### Requirement: IP assertions use consistent observability sources
IP 测试模组对判决归因的断言 MUST 优先使用 `PKTSTREAM`（`reasonId/ruleId/wouldRuleId/wouldDrop`）与 `METRICS.REASONS`；per-rule stats 与其它信息仅作为补强与排障信息。

#### Scenario: Enforce ALLOW asserts ruleId
- **GIVEN** 已下发一条可命中的 `ALLOW,enforce=1` 规则
- **WHEN** 组件触发真实流量
- **THEN** 组件 SHALL 验证 `PKTSTREAM` 中出现 `reasonId=IP_RULE_ALLOW` 且携带该规则 `ruleId`
