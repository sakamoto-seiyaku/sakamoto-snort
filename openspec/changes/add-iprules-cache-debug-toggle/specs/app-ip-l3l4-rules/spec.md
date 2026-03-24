## ADDED Requirements

### Requirement: DEV.IPRULES.CACHE toggles the IPRULES decision cache (IP only)
系统 SHALL 提供一个 DEV-only 的调试开关，用于在运行时启用/禁用 IPRULES 的 hot-path 决策缓存（当前阶段仅 IP；不覆盖域名/DNS）。

#### Scenario: Query current cache state
- **WHEN** 调用 `DEV.IPRULES.CACHE`（无参数）
- **THEN** 系统 SHALL 返回当前值 `0|1`

#### Scenario: Enable cache
- **WHEN** 调用 `DEV.IPRULES.CACHE 1`
- **THEN** 系统 SHALL 返回 `OK`
- **AND** 后续包的 `IpRulesEngine::evaluate()` SHALL 使用决策缓存

#### Scenario: Disable cache
- **WHEN** 调用 `DEV.IPRULES.CACHE 0`
- **THEN** 系统 SHALL 返回 `OK`
- **AND** 后续包的 `IpRulesEngine::evaluate()` SHALL bypass 决策缓存（每次都走规则评估）

#### Scenario: Idempotent set
- **GIVEN** 当前值为 `0`（或 `1`）
- **WHEN** 再次调用 `DEV.IPRULES.CACHE 0`（或 `DEV.IPRULES.CACHE 1`）
- **THEN** 系统 SHALL 返回 `OK`
- **AND** 系统 SHALL 保持当前值不变

#### Scenario: Invalid argument
- **WHEN** 调用 `DEV.IPRULES.CACHE <x>` 且 `<x>` 不为 `0|1`
- **THEN** 系统 SHALL 返回 `NOK`
- **AND** 系统 SHALL 不改变当前值

#### Scenario: Permission gating
- **WHEN** 非 `root(0)` 且非 `shell(2000)` 的调用者发起 `DEV.IPRULES.CACHE ...`
- **THEN** 系统 SHALL 返回 `NOK`

#### Scenario: No semantic change
- **GIVEN** 同一组启用规则与同一个 `PacketKeyV4`
- **WHEN** 在 cache=1 与 cache=0 两种模式下分别调用 `evaluate()`
- **THEN** 两次判决的 `Decision.kind` 与 `Decision.ruleId` SHALL 一致（缓存仅影响性能，不影响语义）

