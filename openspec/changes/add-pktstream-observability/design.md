# Design: PKTSTREAM 可观测性基座（reasonId + would-match + src/dst IP）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


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

既有 `host` 字段保持不变，但其语义需要显式澄清：它继续表示 **remote endpoint** 的名称，而不是新增 `srcIp/dstIp` 中的任意一端。具体地：
- 入站包（`direction=in`）时，`host` 对应 `srcIp`
- 出站包（`direction=out`）时，`host` 对应 `dstIp`

IPv6 说明：本 change 要求 IPv4/IPv6 的 Packet 事件都输出 `reasonId`。在当前阶段（IPv6 不受新 IPv4 规则影响），IPv6 的 `reasonId` 仍按同一套优先级链选择（例如 `IFACE_BLOCK` 或 `ALLOW_DEFAULT`）。

### 2.2 可解释字段
- `reasonId: string`（必填）：解释本包的**实际 verdict**（P0 最小集合见下）
- `ruleId?: string|int`：当“实际执行的规则”命中并决定 verdict 时填充
- `wouldRuleId?: string|int`：当命中 `action=BLOCK, enforce=0, log=1` 的 would-drop 规则时填充（每包最多 1 个）
- `wouldDrop?: 0|1`：当命中 would-drop 时为 1（用于前端直接渲染“命中但未执行拦截”）

约束：
- `reasonId` MUST 始终解释实际 verdict（即 `accepted` 的原因）。
- `wouldRuleId` 出现时，本包 MUST 仍为 `accepted=1`（would-match 不改变实际 verdict）。
- `wouldRuleId` 出现时，事件 MUST 包含 `wouldDrop=1`。
- 若实际 `reasonId=IFACE_BLOCK`，事件 MUST NOT 包含来自更低优先级规则层的 `ruleId` 或 `wouldRuleId`。

## 3. reasonId (P0 minimum)
Packet 侧当前阶段的最小 reasonId 集合（字符串）：
- `IFACE_BLOCK`：接口拦截（hard-drop）
- `ALLOW_DEFAULT`：默认放行
- `IP_RULE_ALLOW`：IP 规则 allow（后续规则引擎填充）
- `IP_RULE_BLOCK`：IP 规则 block（后续规则引擎填充）

注：
- 当前的 log-only/would-match 仅指 BLOCK 规则的 would-block；不使用独立 reasonId，而通过 `wouldRuleId/wouldDrop` 表达。
- 当前 P0 基线/验收明确以 legacy `ip-leak` 路径未参与 Packet 最终判决为前提（可理解为当前验收场景下 `BLOCKIPLEAKS=0`）；`BLOCKIPLEAKS=1` 时是否恢复独立 reasonId、其命名与优先级，统一留到后续融合阶段单独收敛。

reasonId 选择必须确定且唯一；至少在当前 baseline（无规则引擎 override，且不纳入 legacy `ip-leak` 分支）下遵循优先级：
`IFACE_BLOCK` > `ALLOW_DEFAULT`

### 3.1 Reason priority across layers (current known set)
为避免后续规则系统落地时出现“同包多原因”或“先 allow 再被 legacy drop”的歧义，本项目当前约束的判决边界为：

1) **先执行硬原因**：`IFACE_BLOCK`（命中即终止；不得携带更低层 `ruleId/wouldRuleId`）。  
2) **再执行 IP 规则引擎（若启用）**：若其给出 `Allow`/`Block`，则该结果为 **最终 verdict**，不再回落到 legacy/domain 路径：  
   - `Allow` → `reasonId=IP_RULE_ALLOW`  
   - `Block` → `reasonId=IP_RULE_BLOCK`  
3) **仅当 IP 规则层 `NoMatch`** 时，才允许回落到 legacy/domain 路径：在当前 A 层验收基线（可理解为 `BLOCKIPLEAKS=0`）下，该路径仅产生 `ALLOW_DEFAULT`。  

> 注：`ip-leak` 与其它 legacy drop 原因的 reasonId 命名与优先级不属于本 change；若未来恢复其参与 Packet 最终判决，必须以独立 change 增量定义其 reasonId 与优先级链。

## 4. Notes for future rule engines
- `ruleId` 与 `wouldRuleId` 的稳定性、tie-break 与“每包最多 1 条 would-match”由各规则引擎在其 change 中定义/实现，但必须遵循本 change 的字段契约（含 `wouldDrop` 语义）。

## 5. Reason metrics (A): `METRICS.REASONS`
为支持“常态默认可查”的可观测性（不依赖 PKTSTREAM），系统提供 device-wide 的 per-reason 计数器：

- 命令：
  - `METRICS.REASONS`：返回 per-reason counters
  - `METRICS.REASONS.RESET`：清空 counters
- JSON shape：
  - 顶层固定返回 `{"reasons": {...}}`
  - `reasons` 对象的 key 为 reasonId；每个 value 固定包含 `packets:uint64` 与 `bytes:uint64`
- 维度与字段：
  - reasonId：沿用本 change 定义的最小集合（至少包含 `IFACE_BLOCK/ALLOW_DEFAULT`，以及为后续规则引擎预留的 `IP_RULE_ALLOW/IP_RULE_BLOCK`）
  - `packets:uint64`：命中该 reasonId 的包数
  - `bytes:uint64`：命中该 reasonId 的字节数（沿用当前 Packet 路径的 `len` 口径，即 NFQUEUE `NFQA_PAYLOAD` 的全包长度；不是去头后的纯 payload）
- 生命周期：
  - since boot（进程内计数），不要求持久化；重启后归零
  - `METRICS.REASONS.RESET` 用于调试/验收
  - `RESETALL` 作为全局数据清理路径时，也必须通过 `pktManager.reset()` 一并清空 reason counters
- 更新点与约束（热路径）：
  - 计数器更新必须发生在“同一条判决链路”得出最终 reasonId 之后
  - 热路径只允许 `atomic++ (memory_order_relaxed)`；不得引入新锁、不得做 IO、不得做动态分配
  - counters 不得依赖 PKTSTREAM 订阅者是否存在（拉取式接口）
  - counters 不得依赖 `app->tracked()`；即使现有流量 stats 仍受 `tracked` gating，A 层 reason counters 也必须默认可查
- gating（保持事实语义）：
  - 仅对进入 `PacketManager::make()` 的包计数（当前事实：`BLOCK=0` 时不进入判决链路）

## 6. TBD (Next)
- 域名侧 `policySource` 归因与 counters 口径：已固化在 `docs/DOMAIN_POLICY_OBSERVABILITY.md`，实现与对外接口 TBD。
- 常态 counters/metrics（域名系统与 IP 规则等）如何统一对外暴露与复用：TBD（下一轮专题）。
