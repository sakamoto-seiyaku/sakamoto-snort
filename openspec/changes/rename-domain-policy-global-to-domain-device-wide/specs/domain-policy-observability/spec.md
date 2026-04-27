## MODIFIED Requirements

### Requirement: policySource is deterministic and matches App::blocked branch order
系统 MUST 定义一个固定、可枚举的 `policySource`（字符串枚举），其取值集合 MUST 为：
- `CUSTOM_WHITELIST`
- `CUSTOM_BLACKLIST`
- `CUSTOM_RULE_WHITE`
- `CUSTOM_RULE_BLACK`
- `DOMAIN_DEVICE_WIDE_AUTHORIZED`（domain-only device-wide）
- `DOMAIN_DEVICE_WIDE_BLOCKED`（domain-only device-wide）
- `MASK_FALLBACK`

在给定 `domain != nullptr` 且 `BLOCK=1` 的前提下，`policySource` MUST 按与现有 `App::blocked()` 一致的优先级决策且命中唯一：
`CUSTOM_WHITELIST` > `CUSTOM_BLACKLIST` > `CUSTOM_RULE_WHITE` > `CUSTOM_RULE_BLACK`
> `DOMAIN_DEVICE_WIDE_AUTHORIZED` > `DOMAIN_DEVICE_WIDE_BLOCKED` > `MASK_FALLBACK`。

当 `_useCustomList==false` 时，系统 MUST 不访问 custom/device-wide 分支，且 `policySource` MUST 始终为 `MASK_FALLBACK`。

#### Scenario: _useCustomList=0 collapses to MASK_FALLBACK
- **GIVEN** `_useCustomList=0`
- **WHEN** 系统对任意 DNS 请求做 DomainPolicy 判决
- **THEN** 对应的 `policySource` SHALL 为 `MASK_FALLBACK`

### Requirement: METRICS.DOMAIN.SOURCES returns fixed wrapper JSON with stable keys
`METRICS.DOMAIN.SOURCES` MUST 返回有效 JSON，且 MUST 返回固定 wrapper：

```json
{"sources":{ ... }}
```

`sources` 对象 MUST 固定包含上述 7 个 `policySource` key；每个 key 的 value MUST 固定包含：
- `allow`（uint64）
- `block`（uint64）

即使 counters 全为 0，系统仍 MUST 返回所有 key 且值为 0。

#### Scenario: METRICS.DOMAIN.SOURCES returns stable keys
- **WHEN** 客户端调用 `METRICS.DOMAIN.SOURCES`
- **THEN** 返回值 SHALL 为有效 JSON
- **AND** 顶层对象 SHALL 包含 key `sources`
- **AND** `sources` SHALL 包含 key `CUSTOM_WHITELIST`
- **AND** `sources` SHALL 包含 key `DOMAIN_DEVICE_WIDE_BLOCKED`
- **AND** `sources` SHALL 包含 key `MASK_FALLBACK`

