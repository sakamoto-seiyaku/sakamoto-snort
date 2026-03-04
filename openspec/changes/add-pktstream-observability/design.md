# Design: PKTSTREAM 可观测性基座（reasonId + would-match + src/dst IP）

## 0. Scope
本 change 只定义 PKTSTREAM 的 Packet 事件 schema 与 `reasonId/ruleId/wouldRuleId/wouldDrop` 语义；不新增通路、不做全局 safety-mode、不改动现有 gating。

## 1. Constraints (non-negotiable)
- NFQUEUE 热路径不引入新锁/重 IO；可观测性只允许“增加字段输出 + 轻量统计”，不得新增阻塞点。
- 已知风险：`Streamable::stream()` 对订阅 socket 同步写入，慢消费者可能反压；本 change 仅要求文档明确该风险。

## 2. PKTSTREAM Packet schema (vNext)
### 2.1 IP 字段（统一 IPv4/IPv6）
- `ipVersion: 4|6`
- `srcIp: string`：IP 头部的源地址（即 `saddr`）
- `dstIp: string`：IP 头部的目的地址（即 `daddr`）

移除旧 schema 中的动态字段 `ipv4|ipv6`（该字段只表达“对端 IP”，且不利于后续扩展）。

### 2.2 可解释字段
- `reasonId: string`（必填）：解释本包的**实际 verdict**（P0 最小集合见下）
- `ruleId?: string|int`：当“实际执行的规则”命中并决定 verdict 时填充
- `wouldRuleId?: string|int`：当命中 `enforce=0, log=1` 的 would-drop 规则时填充（每包最多 1 个）
- `wouldDrop?: 0|1`：当命中 would-drop 时为 1（用于前端直接渲染“命中但未执行拦截”）

约束：
- `reasonId` MUST 始终解释实际 verdict（即 `accepted` 的原因）。
- `wouldRuleId` 出现时，本包 MUST 仍为 `accepted=1`（would-match 不改变实际 verdict）。
- `wouldRuleId` 出现时，事件 MUST 包含 `wouldDrop=1`。

## 3. reasonId (P0 minimum)
Packet 侧 P0 最小 reasonId 集合（字符串）：
- `IFACE_BLOCK`：接口拦截（hard-drop）
- `IP_LEAK_BLOCK`：ip-leak 拦截（域名系统输出的一部分）
- `ALLOW_DEFAULT`：默认放行
- `IP_RULE_ALLOW`：IP 规则 allow（后续规则引擎填充）
- `IP_RULE_BLOCK`：IP 规则 block（后续规则引擎填充）

注：log-only/would-match 不使用独立 reasonId；通过 `wouldRuleId/wouldDrop` 表达。

reasonId 选择必须确定且唯一；至少在 baseline（无规则引擎 override）下遵循优先级：
`IFACE_BLOCK` > `IP_LEAK_BLOCK` > `ALLOW_DEFAULT`

## 4. Notes for future rule engines
- `ruleId` 与 `wouldRuleId` 的稳定性、tie-break 与“每包最多 1 条 would-match”由各规则引擎在其 change 中定义/实现，但必须遵循本 change 的字段契约（含 `wouldDrop` 语义）。

## 5. TBD (Next)
- 常态 counters/metrics（域名系统与 IP 规则等）如何统一对外暴露与复用：TBD（下一轮专题）。
