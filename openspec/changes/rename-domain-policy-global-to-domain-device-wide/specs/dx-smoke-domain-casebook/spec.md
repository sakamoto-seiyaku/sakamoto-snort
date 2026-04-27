## MODIFIED Requirements

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

