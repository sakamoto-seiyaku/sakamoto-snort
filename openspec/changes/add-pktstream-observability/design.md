# Design: PKTSTREAM 可观测性基座（reasonId + would-match + src/dst IP）

## 0. Scope
本 change 定义：
- PKTSTREAM 的 Packet 事件 schema 与 `reasonId/ruleId/wouldRuleId/wouldDrop` 语义；
- A 层常态 counters：device-wide 的 per-reason packets/bytes（`METRICS.REASONS`）。

本 change 不新增通路、不做全局 safety-mode、不改动现有 gating。

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

## 5. Reason metrics (A): `METRICS.REASONS`
为支持“常态默认可查”的可观测性（不依赖 PKTSTREAM），系统提供 device-wide 的 per-reason 计数器：

- 命令：
  - `METRICS.REASONS`：返回 per-reason counters
  - `METRICS.REASONS.RESET`：清空 counters
- 维度与字段：
  - reasonId：沿用本 change 定义的最小集合（至少包含 `IFACE_BLOCK/IP_LEAK_BLOCK/ALLOW_DEFAULT`，以及为后续规则引擎预留的 `IP_RULE_ALLOW/IP_RULE_BLOCK`）
  - `packets:uint64`：命中该 reasonId 的包数
  - `bytes:uint64`：命中该 reasonId 的 payload bytes（使用 Packet 路径现有 `len` 口径）
- 生命周期：
  - since boot（进程内计数），不要求持久化；重启后归零
  - reset 命令用于调试/验收
- 更新点与约束（热路径）：
  - 计数器更新必须发生在“同一条判决链路”得出最终 reasonId 之后
  - 热路径只允许 `atomic++ (memory_order_relaxed)`；不得引入新锁、不得做 IO、不得做动态分配
  - counters 不得依赖 PKTSTREAM 订阅者是否存在（拉取式接口）
- gating（保持事实语义）：
  - 仅对进入 `PacketManager::make()` 的包计数（当前事实：`BLOCK=0` 时不进入判决链路）

## 6. TBD (Next)
- 域名侧 `policySource` 归因与 counters 口径：已固化在 `docs/DOMAIN_POLICY_OBSERVABILITY.md`，实现与对外接口 TBD。
- 常态 counters/metrics（域名系统与 IP 规则等）如何统一对外暴露与复用：TBD（下一轮专题）。
