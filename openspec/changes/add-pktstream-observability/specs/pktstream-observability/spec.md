## ADDED Requirements

### Requirement: PKTSTREAM Packet events include reasonId and src/dst IP
系统 MUST 将 PKTSTREAM 的 Packet 事件升级为同时输出：
- `ipVersion: 4|6`
- `srcIp: string`
- `dstIp: string`
- `reasonId: string`（必填）

系统 MUST 移除旧的动态字段 `ipv4|ipv6`。

#### Scenario: Packet event contains required fields
- **WHEN** 客户端调用 `PKTSTREAM.START`
- **THEN** 每条 Packet 事件 SHALL 包含 `ipVersion/srcIp/dstIp/reasonId`

#### Scenario: Legacy ipv4/ipv6 key is not present
- **WHEN** 客户端调用 `PKTSTREAM.START`
- **THEN** Packet 事件 SHALL 不包含 key `ipv4`
- **AND** Packet 事件 SHALL 不包含 key `ipv6`

### Requirement: reasonId is deterministic and minimally explains the verdict
系统 MUST 为每个 Packet 事件输出且仅输出一个 `reasonId`。至少在当前 baseline 判决下，reasonId MUST 按固定优先级选择唯一值：
`IFACE_BLOCK` > `ALLOW_DEFAULT`。

若实际 `reasonId=IFACE_BLOCK`，事件 SHALL NOT 包含来自更低优先级规则层的 `ruleId` 或 `wouldRuleId`。

当前最小 reasonId 集与场景验收明确以 legacy `ip-leak` 分支未参与 Packet 最终判决为前提（可理解为当前验收场景下 `BLOCKIPLEAKS=0`）。若后续恢复该附属功能，其新增 reasonId 与场景由对应 change 增量补充，不属于本 change 当前实现/验收前提。

#### Scenario: IFACE_BLOCK uses IFACE_BLOCK reasonId
- **GIVEN** 某包满足接口拦截条件
- **WHEN** 系统对该包产生 PKTSTREAM 事件
- **THEN** `accepted` SHALL 为 0
- **AND** `reasonId` SHALL 为 `IFACE_BLOCK`
- **AND** 事件 SHALL NOT 包含来自更低优先级规则层的 `ruleId` 或 `wouldRuleId`

#### Scenario: Default accept uses ALLOW_DEFAULT
- **GIVEN** 某包不满足任何当前已启用的 drop 条件且无规则引擎 override
- **AND** 当前验收场景下未启用 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=0`）
- **WHEN** 系统对该包产生 PKTSTREAM 事件
- **THEN** `accepted` SHALL 为 1
- **AND** `reasonId` SHALL 为 `ALLOW_DEFAULT`

### Requirement: Would-match is represented by wouldRuleId/wouldDrop without changing verdict
系统 MUST 支持以 `wouldRuleId` 与 `wouldDrop` 表达 would-drop（`action=BLOCK, enforce=0, log=1`）命中：
- `wouldRuleId` 出现时，系统 MUST 保持本包实际 verdict 为 ACCEPT（`accepted=1`）
- `wouldRuleId` 出现时，事件 MUST 包含 `wouldDrop=1`
- `wouldRuleId` 出现时，事件 MUST 仍包含 `reasonId`，且 `reasonId` MUST 解释实际 verdict（即 `accepted` 的原因）
- 系统 MUST 保证每包最多输出 1 个 `wouldRuleId`

#### Scenario: wouldRuleId does not change accepted
- **GIVEN** 某包不满足接口拦截条件
- **AND** 当前验收场景下未启用 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=0`）
- **AND** 该包未命中任何 `enforce=1` 的规则（无论 action=ALLOW|BLOCK）
- **AND** 某包命中一个 would-drop 规则（`action=BLOCK, enforce=0, log=1`）
- **WHEN** 系统输出 PKTSTREAM 事件
- **THEN** `accepted` SHALL 为 1
- **AND** 事件 SHALL 包含 `wouldRuleId`
- **AND** 事件 SHALL 包含 `wouldDrop`
- **AND** `wouldDrop` SHALL 为 1
- **AND** `reasonId` SHALL 为 `ALLOW_DEFAULT`

### Requirement: Device-wide reason counters are exposed via METRICS.REASONS
系统 MUST 在控制面提供 device-wide 的 per-reason counters（拉取式，不依赖 PKTSTREAM）：
- 命令 `METRICS.REASONS` MUST 返回顶层对象 `{"reasons": {...}}`
- `reasons` 对象中每个 reasonId 的 value MUST 固定包含 `packets/bytes`（uint64）
- `bytes` MUST 按 NFQUEUE `NFQA_PAYLOAD` 长度口径累计（即当前 Packet 路径传递的全包长度 `len`）
- 命令 `METRICS.REASONS.RESET` MUST 清空上述 counters
- counters MUST 在热路径以非阻塞方式更新（仅允许 `atomic++`，不得新增锁/IO/分配）
- counters MUST 不依赖 `app->tracked()`
- counters 的生命周期为 since boot（重启后归零），不要求持久化

#### Scenario: METRICS.REASONS reflects observed decisions
- **GIVEN** `BLOCK=1`
- **AND** 当前验收场景下未启用 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=0`）
- **AND** 某包在 baseline 判决下被 ACCEPT（其 PKTSTREAM 事件 `reasonId=ALLOW_DEFAULT`）
- **WHEN** 客户端调用 `METRICS.REASONS`
- **THEN** 返回值中的 `ALLOW_DEFAULT.packets` SHALL 大于等于 1

#### Scenario: METRICS.REASONS.RESET clears counters
- **GIVEN** `METRICS.REASONS` 中至少一个 reason 的 `packets` 大于 0
- **WHEN** 客户端调用 `METRICS.REASONS.RESET`
- **THEN** 后续调用 `METRICS.REASONS` 时，所有 reason 的 `packets/bytes` SHALL 为 0

#### Scenario: RESETALL also clears reason counters
- **GIVEN** `METRICS.REASONS` 中至少一个 reason 的 `packets` 大于 0
- **WHEN** 客户端调用 `RESETALL`
- **THEN** 后续调用 `METRICS.REASONS` 时，所有 reason 的 `packets/bytes` SHALL 为 0

#### Scenario: METRICS.REASONS does not depend on tracked
- **GIVEN** `BLOCK=1`
- **AND** 当前验收场景下未启用 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=0`）
- **AND** 某个 app 的 `tracked=0`
- **AND** 该 app 产生一个 baseline 判决为 ACCEPT 的 Packet 事件（其 `reasonId=ALLOW_DEFAULT`）
- **WHEN** 客户端调用 `METRICS.REASONS`
- **THEN** 返回值中的 `ALLOW_DEFAULT.packets` SHALL 大于等于 1
