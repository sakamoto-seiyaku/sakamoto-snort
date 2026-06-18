## ADDED Requirements

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

