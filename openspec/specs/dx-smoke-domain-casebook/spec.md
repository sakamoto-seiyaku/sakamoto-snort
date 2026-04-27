# dx-smoke-domain-casebook Specification

## Purpose
TBD - created by archiving change complete-device-smoke-casebook-domain. Update Purpose after archive.
## Requirements
### Requirement: dx-smoke-control 承接 Domain casebook 全部域名 Case
`dx-smoke-control` MUST 将 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## 域名` 下 Case 1–9 作为 active vNext smoke 的测试责任，并 MUST 为每个 case 提供可回查 check id。

#### Scenario: Domain casebook 覆盖完整
- **WHEN** 开发者运行 `dx-smoke-control`
- **THEN** 测试 SHALL 执行 Domain Case 1、2、3、4、5、6、7、8、9 的自动化检查
- **AND** 每条检查 SHALL 使用 vNext 控制面或 vNext DEV-only trigger
- **AND** active 执行路径 SHALL NOT 调用 legacy 文本协议命令

### Requirement: Domain surface 补齐负向契约
`dx-smoke-control` MUST 在现有 `DOMAINRULES`、`DOMAINPOLICY`、`DOMAINLISTS`、`DOMAINLISTS.IMPORT` 基线之外，验证 casebook Domain Case 1 的负向契约，防止状态损坏被误报为通过。

#### Scenario: DOMAINLISTS.IMPORT unknown listId 被拒绝
- **WHEN** 测试对不存在的 `listId` 执行 `DOMAINLISTS.IMPORT`
- **THEN** 响应 SHALL 为失败
- **AND** 错误 SHALL 表达 `INVALID_ARGUMENT` 或等价参数错误语义
- **AND** 输出 SHALL 包含可排查 hint

#### Scenario: 删除仍被 policy 引用的 ruleId 被拒绝
- **WHEN** 测试尝试删除仍被 `DOMAINPOLICY` 引用的 `ruleId`
- **THEN** 响应 SHALL 为失败
- **AND** 错误 SHALL 表达冲突或参数错误语义
- **AND** 输出 SHALL 包含冲突 rule/policy 的可解释信息

### Requirement: DomainSources 使用 bucket 级断言
`dx-smoke-control` MUST 补齐 casebook Domain Case 2 的 bucket 级 `domainSources` 覆盖，而不只断言 total 增长。

#### Scenario: domainSources reset gating growth 仍成立
- **WHEN** 测试 reset `domainSources` 并分别在 `block.enabled=0` 与 `block.enabled=1` 下触发 Domain 判决
- **THEN** reset 后 total SHALL 为 0
- **AND** `block.enabled=0` 时 counters SHALL 不增长
- **AND** `block.enabled=1` 时 counters SHALL 增长

#### Scenario: domainSources 覆盖 APP DEVICE_WIDE FALLBACK buckets
- **WHEN** 测试执行 Domain Case 3、6、7
- **THEN** `domainSources(app)` SHALL 覆盖 `CUSTOM_*`、`DOMAIN_DEVICE_WIDE_*`、`MASK_FALLBACK` 的 allow/block bucket
- **AND** 每个 bucket 的增长 SHALL 与对应 DNS verdict 一致

### Requirement: DNS netd inject e2e 覆盖 stream traffic domainSources
`dx-smoke-control` MUST 通过 `dx-netd-inject` 稳定触发 casebook Domain Case 3，并验证 dns stream、`traffic.dns` 与 `domainSources` 的端到端一致性。

#### Scenario: app custom allow block DNS 注入可观测
- **WHEN** 测试为目标 uid 设置 `tracked=1`、`domain.custom.enabled=1`，并下发 app scope allow/block domains
- **AND** 测试启动 `STREAM.START(type=dns)` 后注入 allow 与 block 两个唯一域名
- **THEN** stream SHALL 包含对应 uid/domain 的两条 `type=dns` 事件
- **AND** allow 事件 SHALL 为 `blocked=false`、`getips=true`、`policySource=CUSTOM_WHITELIST`、`scope=APP`、`useCustomList=true`
- **AND** block 事件 SHALL 为 `blocked=true`、`getips=false`、`policySource=CUSTOM_BLACKLIST`、`scope=APP`、`useCustomList=true`
- **AND** per-app `traffic.dns.allow` 与 `traffic.dns.block` SHALL 增长
- **AND** per-app `domainSources` 的 `CUSTOM_WHITELIST.allow` 与 `CUSTOM_BLACKLIST.block` SHALL 增长

### Requirement: DNS tracked disabled 输出 suppressed notice
`dx-smoke-control` MUST 覆盖 casebook Domain Case 4：`tracked=0` 时不输出本次 DNS event，但仍输出 suppressed notice 并增长 metrics。

#### Scenario: tracked disabled suppresses dns events but keeps metrics
- **WHEN** 测试将目标 uid 设置为 `tracked=0` 并启动 `STREAM.START(type=dns)`
- **AND** 测试通过 `dx-netd-inject` 注入唯一域名
- **THEN** stream SHALL NOT 输出本次注入对应的 `type=dns` 事件
- **AND** stream SHALL 输出 `type=notice`、`notice=suppressed`、`stream=dns`
- **AND** suppressed notice SHALL 包含 DNS traffic snapshot 与 tracked 开启提示
- **AND** per-app `traffic.dns.*` 与 `domainSources` SHALL 增长

### Requirement: domain.custom.enabled 改变 Domain 判决路径
`dx-smoke-control` MUST 覆盖 casebook Domain Case 5，验证 `domain.custom.enabled` 的 0/1 状态会改变 DomainPolicy 判决路径。

#### Scenario: custom enabled uses app policy and custom disabled falls back
- **WHEN** 测试对唯一域名下发 app scope block domain
- **AND** 测试在 `domain.custom.enabled=1` 下执行 Domain 判决
- **THEN** verdict SHALL 为 `blocked=true` 且 `policySource=CUSTOM_BLACKLIST`
- **WHEN** 测试在同一域名上切换 `domain.custom.enabled=0` 后再次执行 Domain 判决
- **THEN** verdict SHALL 回落到 `policySource=MASK_FALLBACK`、`scope=FALLBACK`
- **AND** `domainSources(app)` SHALL 记录 `CUSTOM_BLACKLIST.block` 与 `MASK_FALLBACK.allow` 或 `MASK_FALLBACK.block` 的增长

### Requirement: APP policy 优先级高于 DEVICE_WIDE policy
`dx-smoke-control` MUST 覆盖 casebook Domain Case 6，验证 APP 策略覆盖 DEVICE_WIDE 策略，且 stream 与 metrics 的 source/scope 可解释。

#### Scenario: app allow overrides device block
- **WHEN** device policy block 唯一域名且 app policy allow 同一域名
- **AND** 测试通过 `dx-netd-inject` 注入该域名
- **THEN** DNS event SHALL 为 `blocked=false`
- **AND** `policySource` SHALL 为 `CUSTOM_WHITELIST`
- **AND** `scope` SHALL 为 `APP`

#### Scenario: app block overrides device allow
- **WHEN** device policy allow 唯一域名且 app policy block 同一域名
- **AND** 测试通过 `dx-netd-inject` 注入该域名
- **THEN** DNS event SHALL 为 `blocked=true`
- **AND** `policySource` SHALL 为 `CUSTOM_BLACKLIST`
- **AND** `scope` SHALL 为 `APP`

#### Scenario: device policy applies when app policy is absent
- **WHEN** device policy block 唯一域名且 app policy 不包含该域名
- **AND** 测试通过 `dx-netd-inject` 注入该域名
- **THEN** DNS event SHALL 为 `blocked=true`
- **AND** `policySource` SHALL 为 `DOMAIN_DEVICE_WIDE_BLOCKED`
- **AND** `scope` SHALL 为 `DEVICE_WIDE`

### Requirement: DomainLists enable disable 与 allow 覆盖 block 影响判决
`dx-smoke-control` MUST 覆盖 casebook Domain Case 7，验证 DomainLists 不只是能 apply/import，还会实际影响 DNS verdict。

#### Scenario: enabled block list blocks matching domain
- **WHEN** 测试创建 enabled block list 并导入唯一域名
- **AND** 目标 uid 使用 `domain.custom.enabled=0` 与覆盖该 list bit 的 `block.mask`
- **AND** 测试通过 `dx-netd-inject` 注入该域名
- **THEN** DNS event SHALL 为 `policySource=MASK_FALLBACK`、`scope=FALLBACK`、`blocked=true`、`useCustomList=false`
- **AND** `domMask` 与 `appMask` SHALL 包含对应 list bit

#### Scenario: disabled block list no longer blocks matching domain
- **WHEN** 测试将同一 block list 设置为 `enabled=0` 后再次注入同一域名
- **THEN** DNS event SHALL 为 `blocked=false`
- **AND** `domMask` SHALL 不再包含 disabled list bit

#### Scenario: allow list overrides enabled block list
- **WHEN** 同一唯一域名同时存在于 enabled block list 与 enabled allow list
- **AND** 测试通过 `dx-netd-inject` 注入该域名
- **THEN** DNS event SHALL 为 `blocked=false`
- **AND** `useCustomList` SHALL 为 false
- **AND** per-app `traffic.dns` 与 `domainSources` SHALL 记录 `MASK_FALLBACK` allow/block 路径增长

### Requirement: 真机真实 resolver DNS e2e 有明确 BLOCKED 语义
`dx-smoke-control` MUST 覆盖 casebook Domain Case 8：在 netd resolv hook 就绪时执行真实 resolver DNS e2e；hook 未就绪时报告 `BLOCKED`，不得静默通过。

#### Scenario: resolver hook inactive reports BLOCKED
- **WHEN** 测试无法确认 netd resolv hook 已激活
- **THEN** Domain Case 8 SHALL 报告 `BLOCKED`
- **AND** 输出 SHALL 包含 `dev/dev-netd-resolv.sh status|prepare` 或等价修复提示

#### Scenario: resolver hook active produces DNS stream metrics
- **WHEN** netd resolv hook 已激活
- **AND** 测试为目标 uid 下发会 block 唯一域名的策略并触发真实 DNS 解析
- **THEN** dns stream SHALL 包含匹配 uid/domain 的 `type=dns` 事件
- **AND** 事件 SHALL 为 `blocked=true`、`getips=false`
- **AND** per-app `traffic.dns.block` 与对应 `domainSources` bucket SHALL 增长

### Requirement: DOMAINRULES ruleIds 端到端覆盖 CUSTOM_RULE buckets
`dx-smoke-control` MUST 覆盖 casebook Domain Case 9，通过 `DOMAINRULES` + `DOMAINPOLICY(ruleIds)` 验证 `CUSTOM_RULE_WHITE` 与 `CUSTOM_RULE_BLACK`。

#### Scenario: DOMAINRULES allow and block ruleIds are observable
- **WHEN** 测试创建一条 exact-domain allow rule 与一条 regex block rule
- **AND** app scope policy 引用两条 ruleIds
- **AND** 测试通过 `dx-netd-inject` 分别注入 allow 与 block 唯一域名
- **THEN** allow DNS event SHALL 为 `blocked=false`、`getips=true`、`policySource=CUSTOM_RULE_WHITE`、`scope=APP`
- **AND** block DNS event SHALL 为 `blocked=true`、`getips=false`、`policySource=CUSTOM_RULE_BLACK`、`scope=APP`
- **AND** per-app `traffic.dns.allow` 与 `traffic.dns.block` SHALL 增长
- **AND** per-app `domainSources` 的 `CUSTOM_RULE_WHITE.allow` 与 `CUSTOM_RULE_BLACK.block` SHALL 增长

### Requirement: Domain casebook tests restore mutated state
Every Domain casebook test in `dx-smoke-control` MUST restore mutable device/app state that it changes, including config keys, app/domain policy, domain rules, and domain lists.

#### Scenario: Domain case cleanup preserves later tests
- **WHEN** a Domain case changes config, policy, rules, or lists
- **THEN** the test SHALL restore the previous state before the next case starts
- **AND** cleanup failures SHALL fail the test unless the run is already reporting `BLOCKED`
