# domain-policy-observability Specification

## Purpose
TBD - created by archiving change add-domain-policy-observability. Update Purpose after archive.
## Requirements
### Requirement: DomainPolicy source counters are exposed via METRICS.DOMAIN.SOURCES*
系统 MUST 通过控制面暴露以下命令（拉取式 counters）：
- `METRICS.DOMAIN.SOURCES`
- `METRICS.DOMAIN.SOURCES.APP <uid|str> [USER <userId>]`
- `METRICS.DOMAIN.SOURCES.RESET`
- `METRICS.DOMAIN.SOURCES.RESET.APP <uid|str> [USER <userId>]`

所有 counters 生命周期为 since boot（不持久化），reset 仅清零。

参数非法或 app 不存在时，系统 MUST 返回 `NOK`（不得返回 0 bytes）。

#### Scenario: Commands reject invalid parameters
- **WHEN** 客户端调用 `METRICS.DOMAIN.SOURCES foo`
- **THEN** 返回值 SHALL 为 `NOK`

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

### Requirement: Counters update per DNS verdict, gated by BLOCK, not by tracked
统计单位 MUST 为 **DNS 请求**：每次 DNS 判决（一次 DomainPolicy verdict）更新 counters 一次：
- `blocked=false` → 对应 source 的 `allow += 1`
- `blocked=true` → 对应 source 的 `block += 1`

gating：
- 当 `BLOCK=1` 时，系统 MUST 更新 counters。
- 当 `BLOCK=0` 时，系统 MUST NOT 更新 counters。

系统 MUST NOT 以 `tracked` 作为 counters 的 gating 条件（即 `tracked=0` 仍会更新 counters）。

热路径约束：
- counters MUST 使用固定维度结构存储，并在热路径仅执行 `atomic++(relaxed)`；
- 系统 SHALL NOT 在更新 counters 时做 map 插入、动态分配或阻塞 I/O。

#### Scenario: tracked=0 still increments counters
- **GIVEN** `BLOCK=1`
- **AND** 某 app 的 `tracked=0`
- **WHEN** 该 app 触发至少 1 次 DNS 判决
- **THEN** 后续调用 `METRICS.DOMAIN.SOURCES` 时 `sources` 中至少一个计数 SHALL 大于等于 1

### Requirement: Reset semantics are strict
`METRICS.DOMAIN.SOURCES.RESET` MUST 清空 device-wide 与 per-app counters。

`METRICS.DOMAIN.SOURCES.RESET.APP ...` MUST 仅清空目标 app 的 per-app counters，且 MUST NOT 影响其他 app 的 per-app counters。

严格 reset 边界：
- 当 `...RESET*` 返回 `OK` 后，后续新发生的 DNS 判决 MUST 只能记入 reset 之后的 counters；
- 系统 SHALL NOT 产生“部分清零、部分保留”的不确定边界语义。

`RESETALL` MUST 同时清空 domain sources counters。

#### Scenario: RESET clears counters
- **GIVEN** `METRICS.DOMAIN.SOURCES` 中至少一个计数大于 0
- **WHEN** 客户端调用 `METRICS.DOMAIN.SOURCES.RESET`
- **THEN** 后续调用 `METRICS.DOMAIN.SOURCES` 时所有计数 SHALL 为 0
