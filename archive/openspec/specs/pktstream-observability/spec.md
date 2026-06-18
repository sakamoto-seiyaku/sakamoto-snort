# pktstream-observability Specification

## Purpose
TBD - created by archiving change add-pktstream-observability. Update Purpose after archive.
## Requirements
### Requirement: vNext packet stream events include reasonId and src/dst IP
系统 MUST 将 vNext packet stream 的 Packet 事件升级为同时输出：
- `ipVersion: 4|6`
- `srcIp: string`
- `dstIp: string`
- `reasonId: string`（必填）

系统 MUST 移除旧的动态字段 `ipv4|ipv6`。

#### Scenario: Packet event contains required fields
- **WHEN** 客户端调用 vNext `STREAM.START(type=pkt)`
- **THEN** 每条 Packet 事件 SHALL 包含 `ipVersion/srcIp/dstIp/reasonId`

#### Scenario: Legacy ipv4/ipv6 key is not present
- **WHEN** 客户端调用 vNext `STREAM.START(type=pkt)`
- **THEN** Packet 事件 SHALL 不包含 key `ipv4`
- **AND** Packet 事件 SHALL 不包含 key `ipv6`

### Requirement: reasonId is deterministic and minimally explains the verdict
系统 MUST 为每个 Packet 事件输出且仅输出一个 `reasonId`。至少在当前 baseline 判决下，reasonId MUST 按固定优先级选择唯一值：
`IFACE_BLOCK` > `ALLOW_DEFAULT`。

若实际 `reasonId=IFACE_BLOCK`，事件 SHALL NOT 包含来自更低优先级规则层的 `ruleId` 或 `wouldRuleId`。

当前阶段验收以 `BLOCKIPLEAKS=0` 为前提（该附属功能默认关闭，不作为阻塞项）。

为避免开发态开启 `BLOCKIPLEAKS=1` 时出现“drop 但 reasonId 无法解释”的缺口：当 legacy IP leak 拦截导致本包被 DROP（`accepted=0`）时，系统 SHALL 使用临时 reasonId `IP_LEAK_BLOCK` 表达该原因；若同时命中接口拦截，`IFACE_BLOCK` 优先级更高。

#### Scenario: IFACE_BLOCK uses IFACE_BLOCK reasonId
- **GIVEN** 某包满足接口拦截条件
- **WHEN** 系统对该包产生 vNext packet stream 事件
- **THEN** `accepted` SHALL 为 0
- **AND** `reasonId` SHALL 为 `IFACE_BLOCK`
- **AND** 事件 SHALL NOT 包含来自更低优先级规则层的 `ruleId` 或 `wouldRuleId`

#### Scenario: Default accept uses ALLOW_DEFAULT
- **GIVEN** 某包不满足任何当前已启用的 drop 条件且无规则引擎 override
- **AND** 当前验收场景下未启用 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=0`）
- **WHEN** 系统对该包产生 vNext packet stream 事件
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
- **WHEN** 系统输出 vNext packet stream 事件
- **THEN** `accepted` SHALL 为 1
- **AND** 事件 SHALL 包含 `wouldRuleId`
- **AND** 事件 SHALL 包含 `wouldDrop`
- **AND** `wouldDrop` SHALL 为 1
- **AND** `reasonId` SHALL 为 `ALLOW_DEFAULT`

### Requirement: Device-wide reason counters are exposed via METRICS.REASONS
系统 MUST 在控制面提供 device-wide 的 per-reason counters（拉取式，不依赖 vNext packet stream 是否开启）：
- 命令 `METRICS.REASONS` MUST 返回顶层对象 `{"reasons": {...}}`
- `reasons` 对象中每个 reasonId 的 value MUST 固定包含 `packets/bytes`（uint64）
- `reasons` 对象 MUST 至少包含以下 key（即使其 counters 为 0）：
  - `IFACE_BLOCK`
  - `ALLOW_DEFAULT`
  - `IP_RULE_ALLOW`
  - `IP_RULE_BLOCK`
- `bytes` MUST 按 NFQUEUE `NFQA_PAYLOAD` 长度口径累计（即当前 Packet 路径传递的全包长度 `len`）
- 命令 `METRICS.REASONS.RESET` MUST 清空上述 counters
- counters MUST 在热路径以非阻塞方式更新（仅允许 `atomic++`，不得新增锁/IO/分配）
- counters MUST 不依赖 `app->tracked()`
- counters 的生命周期为 since boot（重启后归零），不要求持久化

#### Scenario: METRICS.REASONS reflects observed decisions
- **GIVEN** `BLOCK=1`
- **AND** 当前验收场景下未启用 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=0`）
- **AND** 某包在 baseline 判决下被 ACCEPT（其 vNext packet stream 事件 `reasonId=ALLOW_DEFAULT`）
- **WHEN** 客户端调用 `METRICS.REASONS`
- **THEN** 返回值中的 `ALLOW_DEFAULT.packets` SHALL 大于等于 1

#### Scenario: METRICS.REASONS returns stable keys
- **WHEN** 客户端调用 `METRICS.REASONS`
- **THEN** 返回值中的 `reasons` 对象 SHALL 包含 key `IFACE_BLOCK`
- **AND** 返回值中的 `reasons` 对象 SHALL 包含 key `ALLOW_DEFAULT`
- **AND** 返回值中的 `reasons` 对象 SHALL 包含 key `IP_RULE_ALLOW`
- **AND** 返回值中的 `reasons` 对象 SHALL 包含 key `IP_RULE_BLOCK`

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

### Requirement: vNext packet events include stable `l4Status`
For each vNext packet stream event with `type="pkt"`, the system MUST include `l4Status` (string) and it MUST be always-present.

`l4Status` MUST be one of:
- `known-l4`
- `other-terminal`
- `fragment`
- `invalid-or-unavailable-l4`

Port output requirements:
- `srcPort` and `dstPort` MUST be always-present numbers.
- If `l4Status` is not `known-l4`, `srcPort` and `dstPort` MUST be `0` (port is unavailable).

Protocol interpretation note:
- `protocol="other"` alone MUST NOT be used to infer a legal terminal other-protocol; clients MUST treat it as legal terminal only when `l4Status="other-terminal"`.

#### Scenario: Packet event contains required `l4Status`
- **WHEN** 客户端调用 vNext `STREAM.START(type=pkt)`
- **THEN** 每条 `type="pkt"` 事件 MUST 包含 `l4Status`

#### Scenario: Non-known-l4 events use port 0
- **GIVEN** 系统为某包输出 `type="pkt"` 事件且 `l4Status!="known-l4"`
- **WHEN** 事件被序列化输出
- **THEN** `srcPort` MUST 为 `0`
- **AND** `dstPort` MUST 为 `0`

