# Change: PKTSTREAM 可观测性基座（reasonId + would-match + src/dst IP）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


## Why
P0/P1 设计初衷需要对用户提供“友好可观测性”与“策略调试（当前主要指 BLOCK 规则的 would-block / would-match）”：
- 现状 PKTSTREAM 只有 `accepted`，缺少“为什么”；
- 现状 Packet 事件只输出单个对端 IP（`ipv4|ipv6` 动态字段），不足以支撑后续 L3/L4 规则与诊断；
- 我们不新增新的观测通路，复用 PKTSTREAM（前端负责采集/汇总/丢弃）。

因此需要先把 PKTSTREAM 的可观测性契约独立成 change，作为后续 IP 规则引擎与域名系统可解释性的基础。

## What Changes
- 升级 PKTSTREAM Packet 事件 schema：
  - 新增：`reasonId`（必填）、`ruleId`（可选）、`wouldRuleId`（可选，每包最多 1 个）、`wouldDrop`（可选，0|1）
  - 新增：`ipVersion(4|6)`、`srcIp`、`dstIp`
  - 移除：旧动态字段 `ipv4|ipv6`
  - 说明：除上述新增/移除字段外，其它既有字段保持不变（例如 `app/uid/userId/direction/interface/protocol/host/srcPort/dstPort/accepted`）；其中既有 `host` 字段继续表示 **remote endpoint** 的名称（入站对应 `srcIp`，出站对应 `dstIp`）
- 定义 P0 最小 reasonId 集合与确定性选择规则（避免“同包多原因”含混）。
- 新增常态拉取式指标（不依赖 PKTSTREAM）：
  - `METRICS.REASONS`：device-wide 的 per-reason counters（`packets/bytes`，since boot）
  - `METRICS.REASONS.RESET`：清空上述 counters（用于调试/验收）
- 明确已知风险：PKTSTREAM 同步写 socket，慢消费者可能反压热路径；作为产品/文档约束处理，不在本 change 立刻重构 stream 通路。

## Relationship to existing changes
- 本 change 提供 PKTSTREAM/`reasonId` 的契约，后续规则系统（例如 `add-app-ip-l3l4-rules-engine`）只需按契约填充 `ruleId/wouldRuleId/wouldDrop` 与相应 `reasonId`。

## Non-Goals
- 不改变现状 gating：`BLOCK=0` 时仍不进入 `PacketManager::make`，因此不会产出 PKTSTREAM（保持事实语义）。
- 不做全局 safety-mode；would-match 仅作为“规则级/批次规则”的语义约定。
- 不要求在 engine_off（例如 `BLOCK=0`）时逐包输出 `reasonId`；engine_off 属于状态解释（例如通过 `BLOCK`/`ACTIVITYSTREAM`）。
- 当前不要求为 legacy `ip-leak` 分支（可理解为 `BLOCKIPLEAKS=1` 时的旧路径）补齐最终 `reasonId` 命名、优先级与验收场景；该部分统一记为 TBD，不作为本 change 当前落地阻塞项。
- 不覆盖 DNSSTREAM/ACTIVITYSTREAM（仅 PKTSTREAM）。

## TBD (Next)
- 其它常态 counters/metrics（例如域名 `policySource` 计数、IP 规则 per-rule stats 的统一输出口径与复用）：TBD。域名侧的归因与 counters 口径已在 `docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md` 固化（暂不新建域名相关 change）。

## Impact
- Affected docs（实现时）：`docs/INTERFACE_SPECIFICATION.md`
- Affected code（实现时）：`src/PacketListener.cpp`, `src/PacketManager.hpp`, `src/PacketManager.cpp`, `src/Packet.hpp`, `src/Packet.cpp`, `src/Control.hpp`, `src/Control.cpp`
- Affected verification tooling（实现/验收时）：`tests/integration/full-smoke.sh`, `tests/integration/lib.sh`
