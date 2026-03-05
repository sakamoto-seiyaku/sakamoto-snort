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
系统 MUST 为每个 Packet 事件输出且仅输出一个 `reasonId`。至少在 baseline 判决下，reasonId MUST 按固定优先级选择唯一值：
`IFACE_BLOCK` > `IP_LEAK_BLOCK` > `ALLOW_DEFAULT`。

#### Scenario: IFACE_BLOCK outranks IP_LEAK_BLOCK
- **GIVEN** 某包同时满足接口拦截与 ip-leak 拦截条件
- **WHEN** 系统对该包产生 PKTSTREAM 事件
- **THEN** `accepted` SHALL 为 0
- **AND** `reasonId` SHALL 为 `IFACE_BLOCK`

#### Scenario: Default accept uses ALLOW_DEFAULT
- **GIVEN** 某包不满足任何 drop 条件且无规则引擎 override
- **WHEN** 系统对该包产生 PKTSTREAM 事件
- **THEN** `accepted` SHALL 为 1
- **AND** `reasonId` SHALL 为 `ALLOW_DEFAULT`

### Requirement: Would-match is represented by wouldRuleId/wouldDrop without changing verdict
系统 MUST 支持以 `wouldRuleId` 与 `wouldDrop` 表达 would-drop（`enforce=0, log=1`）命中：
- `wouldRuleId` 出现时，系统 MUST 保持本包实际 verdict 为 ACCEPT（`accepted=1`）
- `wouldRuleId` 出现时，事件 MUST 包含 `wouldDrop=1`
- `wouldRuleId` 出现时，事件 MUST 仍包含 `reasonId`，且 `reasonId` MUST 解释实际 verdict（即 `accepted` 的原因）
- 系统 MUST 保证每包最多输出 1 个 `wouldRuleId`

#### Scenario: wouldRuleId does not change accepted
- **GIVEN** 某包不满足接口拦截与 ip-leak 拦截条件
- **AND** 该包未命中任何 `enforce=1` 的规则（无论 action=ALLOW|BLOCK）
- **AND** 某包命中一个 would-drop 规则（`enforce=0, log=1`）
- **WHEN** 系统输出 PKTSTREAM 事件
- **THEN** `accepted` SHALL 为 1
- **AND** 事件 SHALL 包含 `wouldRuleId`
- **AND** 事件 SHALL 包含 `wouldDrop`
- **AND** `wouldDrop` SHALL 为 1
- **AND** `reasonId` SHALL 为 `ALLOW_DEFAULT`

### Requirement: Device-wide reason counters are exposed via METRICS.REASONS
系统 MUST 在控制面提供 device-wide 的 per-reason counters（拉取式，不依赖 PKTSTREAM）：
- 命令 `METRICS.REASONS` MUST 返回每个 reasonId 的 `packets/bytes`（uint64）
- 命令 `METRICS.REASONS.RESET` MUST 清空上述 counters
- counters MUST 在热路径以非阻塞方式更新（仅允许 `atomic++`，不得新增锁/IO/分配）
- counters 的生命周期为 since boot（重启后归零），不要求持久化

#### Scenario: METRICS.REASONS reflects observed decisions
- **GIVEN** `BLOCK=1`
- **AND** 某包在 baseline 判决下被 ACCEPT（其 PKTSTREAM 事件 `reasonId=ALLOW_DEFAULT`）
- **WHEN** 客户端调用 `METRICS.REASONS`
- **THEN** 返回值中的 `ALLOW_DEFAULT.packets` SHALL 大于等于 1

#### Scenario: METRICS.REASONS.RESET clears counters
- **GIVEN** `METRICS.REASONS` 中至少一个 reason 的 `packets` 大于 0
- **WHEN** 客户端调用 `METRICS.REASONS.RESET`
- **THEN** 后续调用 `METRICS.REASONS` 时，所有 reason 的 `packets/bytes` SHALL 为 0
