## ADDED Requirements

### Requirement: A cache-off build variant exists for IPRULES decision cache (IP only)
系统（仓库）SHALL 提供一个 DEV-only 的 `sucre-snort` 二进制变体，用于在真机 perf 诊断时禁用 IPRULES 的 hot-path 决策缓存（当前阶段仅 IP；不覆盖域名/DNS）。

说明：该能力以“二进制变体”实现，而不是运行时开关，以避免在默认产物的每个包热路径上引入额外判断成本。

#### Scenario: Build produces two binaries
- **WHEN** 开发者执行项目的标准 dev 构建流程
- **THEN** 系统 SHALL 产出两份可执行二进制：
  - `sucre-snort`：默认产物；决策缓存启用（行为与当前一致）
  - `sucre-snort-iprules-nocache`：DEV-only 变体；决策缓存禁用（用于 perf 诊断）

#### Scenario: Cache-off bypasses decision cache
- **GIVEN** 正在运行 cache-off 变体
- **WHEN** 触发 IPRULES 的包判决
- **THEN** `IpRulesEngine::evaluate()` SHALL bypass per-thread 决策缓存（每次都执行规则评估）

#### Scenario: No semantic change between variants
- **GIVEN** 同一组启用规则与同一个 `PacketKeyV4`
- **WHEN** 在默认产物与 cache-off 变体下分别调用 `evaluate()`
- **THEN** 两次判决的 `Decision.kind` 与 `Decision.ruleId` SHALL 一致（变体仅用于性能诊断，不改变语义）
