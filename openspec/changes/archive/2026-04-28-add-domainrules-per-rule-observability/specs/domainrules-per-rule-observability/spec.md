## ADDED Requirements

### Requirement: DomainPolicy 对外暴露 ruleId 归因（dns stream + DEV.DOMAIN.QUERY）
系统 MUST 在以下对外可观测面补齐 DomainRule 级别归因字段：

1. tracked dns stream 事件（`STREAM.START(type=dns)` 输出的 `type="dns"` event）
2. `DEV.DOMAIN.QUERY` 返回结果

字段约束（两处一致）：

- `ruleId`（u32，可选）：当本次 DNS verdict 的 `policySource` 来自规则分支时，系统 MUST 填充一个确定性的 `ruleId`。

规则分支定义：
- `CUSTOM_RULE_WHITE` / `CUSTOM_RULE_BLACK`
- `DOMAIN_DEVICE_WIDE_AUTHORIZED` / `DOMAIN_DEVICE_WIDE_BLOCKED`（仅当该 decision 实际来自 *rule*，而非 device-wide 名单时才填充 `ruleId`）

#### Scenario: CUSTOM_RULE_* dns event 输出 ruleId
- **GIVEN** 某 app `tracked=1` 且 `domain.custom.enabled=1`
- **AND** baseline `DOMAINRULES` 中存在一条 allow rule（`ruleId=a`）与一条 block rule（`ruleId=b`）
- **AND** app scope `DOMAINPOLICY` 分别引用 allow 与 block 两条 `ruleIds`
- **WHEN** 触发该 app 对两个唯一域名的 DNS 判决并输出 `type="dns"` 事件
- **THEN** allow DNS event MUST 为 `policySource="CUSTOM_RULE_WHITE"` 且包含 `ruleId=a`
- **AND** block DNS event MUST 为 `policySource="CUSTOM_RULE_BLACK"` 且包含 `ruleId=b`

#### Scenario: DEV.DOMAIN.QUERY 返回 ruleId
- **GIVEN** 某 app 的 policy 规则分支会命中某域名
- **WHEN** 客户端调用 `DEV.DOMAIN.QUERY(app,domain)`
- **THEN** 返回 MUST 包含 `policySource` 与 `ruleId`

### Requirement: ruleId 归因必须 deterministic（选择最小 ruleId）
当同一规则集合内存在多条规则同时匹配时，系统 MUST 以确定性的方式选择 `ruleId`：

- `ruleId` MUST 为该集合内“所有匹配规则”的 **最小 `ruleId`**（升序最小）。

#### Scenario: 多条规则同时命中时选择最小 ruleId
- **GIVEN** app scope allow ruleset 中存在两条都会命中目标域名的规则 `ruleId=10` 与 `ruleId=2`
- **WHEN** 系统为该 app 对该域名做 DNS 判决并输出归因字段
- **THEN** 输出的 `ruleId` MUST 为 `2`（而非 `10`）

### Requirement: METRICS.GET(name=domainRuleStats) 暴露拉取式 per-rule counters
系统 MUST 在 vNext `METRICS.GET` 中支持 `name="domainRuleStats"`，并返回固定 wrapper：

```json
{"domainRuleStats":{"rules":[ ... ]}}
```

其中：

- `domainRuleStats.rules[]` MUST 为 array，按 `ruleId` 升序。
- 每个 item MUST 至少包含：
  - `ruleId`（u32）
  - `allowHits`（u64）：该 ruleId 作为 allow 归因规则被选中（`ruleId`）的次数
  - `blockHits`（u64）：该 ruleId 作为 block 归因规则被选中（`ruleId`）的次数
- 返回集合 MUST 以 `DOMAINRULES` baseline 为准：
  - 当前 baseline 中存在的每个 ruleId MUST 都出现在 `rules[]` 中（即使 counters 为 0）。
  - baseline 为空时，`rules[]` MUST 为空数组。

#### Scenario: domainRuleStats 返回按 ruleId 排序且覆盖 baseline 全量
- **GIVEN** baseline `DOMAINRULES` 中存在 `ruleId=0` 与 `ruleId=3`
- **WHEN** 客户端调用 `METRICS.GET` 且 `args.name="domainRuleStats"`
- **THEN** 响应 MUST 为 `ok=true`
- **AND** `result.domainRuleStats.rules` MUST 为 array
- **AND** `rules[0].ruleId` MUST 为 `0`
- **AND** `rules[1].ruleId` MUST 为 `3`
- **AND** `rules[0]` 与 `rules[1]` MUST 都包含 `allowHits` 与 `blockHits`

### Requirement: per-rule counters 的更新口径与 gating
per-rule counters 的统计单位 MUST 为 **真实 DNS verdict**（`DnsListener` 路径的一次判决）：

- 当本次 verdict 产生 `ruleId` 且 verdict 为 allow 时，对应 `allowHits += 1`。
- 当本次 verdict 产生 `ruleId` 且 verdict 为 block 时，对应 `blockHits += 1`。

gating：

- 当 `block.enabled=1` 且 `app.tracked=1` 时系统 MUST 更新 per-rule counters。
- 当 `app.tracked=0` 时系统 MUST NOT 更新 per-rule counters。
- 当 `block.enabled=0` 时系统 MUST NOT 更新 per-rule counters。
- `DEV.DOMAIN.QUERY` MUST NOT 更新 per-rule counters（仅用于观测与调试）。

#### Scenario: tracked-only + block.enabled gating 生效
- **GIVEN** baseline 中存在至少一条可命中的 ruleId
- **WHEN** `block.enabled=1` 且 `app.tracked=0` 时触发一次 DNS 判决
- **THEN** `METRICS.GET(name=domainRuleStats)` 的任意 `allowHits/blockHits` MUST NOT 因本次判决而增长
- **WHEN** `block.enabled=1` 且 `app.tracked=1` 时再次触发一次可命中该 ruleId 的 DNS 判决
- **THEN** 对应 `allowHits` 或 `blockHits` MUST 至少增长 1

### Requirement: METRICS.RESET(name=domainRuleStats) 清零 counters（since-boot）
系统 MUST 支持 `METRICS.RESET(name=domainRuleStats)`，其语义为 since-boot counters 清零：

- reset 后 `METRICS.GET(name=domainRuleStats)` 返回的所有 `allowHits/blockHits` MUST 为 0。
- `RESETALL` MUST 同样清零 domainRuleStats counters。

#### Scenario: domainRuleStats reset 后归零并可再次增长
- **GIVEN** `METRICS.GET(name=domainRuleStats)` 中至少一个 counter 大于 0
- **WHEN** 客户端调用 `METRICS.RESET` 且 `args.name="domainRuleStats"`
- **THEN** 后续调用 `METRICS.GET(name=domainRuleStats)` 时所有 counters MUST 为 0
- **WHEN** 之后再次触发一次可命中某 ruleId 的 DNS 判决
- **THEN** 对应 counter MUST 再次增长
