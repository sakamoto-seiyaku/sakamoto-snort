## ADDED Requirements

### Requirement: Domain Case 9 覆盖 dns ruleId 归因与 METRICS.domainRuleStats
`dx-smoke-control` MUST 在既有 Domain Case 9（`DOMAINRULES` + `DOMAINPOLICY(ruleIds)`）基础上，额外覆盖：

1. dns stream `type=dns` 事件在 `policySource=CUSTOM_RULE_*` 时输出 `ruleId`；
2. `METRICS.GET(name=domainRuleStats)` 的 per-rule counters 随 **tracked DNS verdict** 增长；
3. `METRICS.RESET(name=domainRuleStats)` 的清零语义与后续再增长。

#### Scenario: CUSTOM_RULE buckets 的 dns event 输出 ruleId 且 domainRuleStats 计数增长
- **GIVEN** 测试创建一条 allow rule（`ruleId=a`）与一条 block rule（`ruleId=b`），并通过 app scope policy 引用两条 ruleIds
- **AND** 测试为目标 uid 设置 `tracked=1` 并启动 `STREAM.START(type=dns)`
- **WHEN** 测试通过 `dx-netd-inject` 注入分别命中 allow 与 block 的两个唯一域名
- **THEN** allow DNS event MUST 为 `policySource=CUSTOM_RULE_WHITE` 且包含 `ruleId=a`
- **AND** block DNS event MUST 为 `policySource=CUSTOM_RULE_BLACK` 且包含 `ruleId=b`
- **AND** `METRICS.GET(name=domainRuleStats)` 中 `ruleId=a` 的 `allowHits` MUST 增长
- **AND** `METRICS.GET(name=domainRuleStats)` 中 `ruleId=b` 的 `blockHits` MUST 增长

#### Scenario: domainRuleStats reset 后归零并可再次增长
- **GIVEN** `METRICS.GET(name=domainRuleStats)` 中至少一个 counter 大于 0
- **WHEN** 测试执行 `METRICS.RESET(name=domainRuleStats)`
- **THEN** 后续 `METRICS.GET(name=domainRuleStats)` 中所有 counters MUST 为 0
- **WHEN** 之后再次注入一次可命中某 ruleId 的 DNS 判决
- **THEN** 对应 counter MUST 再次增长
