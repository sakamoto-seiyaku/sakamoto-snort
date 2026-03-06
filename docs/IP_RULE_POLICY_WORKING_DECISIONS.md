# IP 规则引擎与 Policy 合流：工作决策与原则（P0/P1）

更新时间：2026-03-05  
状态：纲领性工作结论（可迭代修订；实现与验收以 OpenSpec change 为准）

---

## 0. 目标与范围

本文件的目标：把 IP 相关功能的**上位原则**与**已决定的关键语义**固化成“纲领”，用于后续实现/细化时反复对照，避免细节讨论把系统带偏。

范围包含：
- per‑App(UID) 的 IPv4 L3/L4 规则引擎（语义 + 性能/并发约束 + 控制面协议）。
- 与域名系统产物 `IP_LEAK_BLOCK` 的 Packet 侧合流语义（不重构域名系统内部）。
- 可解释性与观测契约（reasonId/ruleId/would‑match + per‑rule stats）的**边界与口径**。

范围不包含（明确后置）：
- 域名系统的独立开关语义（DOMAINPOLICY/DOMAINMAP/DNS `getips` 等）与“最终融合”形态。
- IPv6 新规则语义（本期 IPv6 默认放行且不提示）。

---

## 1. 单一真相（权威入口）

为避免“讨论摘录/二手结论”互相打架，权威以以下文档为准：

1) IP 规则引擎与合流策略（语义/算法/控制面）：  
`openspec/changes/add-app-ip-l3l4-rules-engine/`

2) PKTSTREAM schema + reasonId/would‑match 契约（字段与口径）：  
`openspec/changes/add-pktstream-observability/`

3) 原始讨论摘录（只用于追溯决策背景，不作最终规范）：  
`docs/IP_RULE_POLICY_DISCUSSION_RAW_EXCERPTS_019cad3d-d9ba-7b21-9dc8-ae0f84c12ba1.md`

辅助材料（调研/事实语义）：
- `docs/P0P1_BACKEND_WORKING_DECISIONS.md`
- `docs/IP_RULE_ENGINE_RESEARCH.md`

---

## 2. 决策原则（做取舍时的上位约束）

1) **NFQUEUE 热路径不引入新锁/重 IO/动态分配**  
热路径只允许纯计算、只读快照查询与固定维度的 `atomic++(relaxed)`。

2) **更新必须原子：snapshot + atomic publish（RCU 风格）**  
热路径只能看到“旧或新”完整版本，不存在中间态；控制面在新快照上编译并一次性发布。

3) **可解释必须确定且唯一**  
同一时刻同一包命中多条规则时，必须按固定规则选出唯一“最终命中”，稳定输出 `reasonId + ruleId`，并让 per‑rule stats 归因不漂移。

4) **表达力受控 + 预检（preflight）硬保护**  
不追求“任意组合的防火墙”；允许的语义必须能被编译为受控的最坏复杂度，并用硬上限拒绝超限配置。

5) **不新增观测通路**  
事件复用 PKTSTREAM；常态统计通过控制面拉取（per‑rule stats），不引入新的存储/查询系统。

6) **分层推进：后端骨架可扩展，前端按 P0/P1 逐步开放**  
后端先把“字段全集 + 分类器骨架 + 合流/可解释/预检”钉死；前端按阶段只开放子集，避免后续因接口形态返工。

---

## 3. 已决定：两系统 + 合流器（Policy Combiner）

### 3.1 系统边界
- **域名系统**：保持现状内部规则逻辑；Packet 侧本期只消费其 `IP_LEAK_BLOCK` 结果（受 `BLOCKIPLEAKS` 驱动，依赖 Domain↔IP 映射）。
- **IP 规则系统**：新增 per‑UID IPv4 L3/L4 规则引擎，支持 `ALLOW/BLOCK` + 显式 `priority` + `enforce/log`。
- **合流器（Combiner）**：只在 Packet 判决点合并两边候选，不要求重构域名系统内部。

### 3.2 不可覆盖的硬原因
- `IFACE_BLOCK` 保持 hard‑drop：命中必 DROP，IP 规则不得覆盖（无论 allow/priority）。

### 3.3 可配置的合流顺序：`POLICY.ORDER`
合流由控制面枚举 `POLICY.ORDER` 决定（均在 `IFACE_BLOCK` 之后执行）：
- `DOMAIN_FIRST`：先应用 `IP_LEAK_BLOCK`，若需 DROP 则直接 DROP；否则再看 IP 规则。
- `IP_FIRST`：先看 IP 规则（命中则用其 verdict）；否则再看 `IP_LEAK_BLOCK`。
- `PRIORITY`：两边都计算候选，按统一 tie‑break 选胜者；其中 `IP_LEAK_BLOCK` 作为域名系统的一部分参与比较，但其 `priority` 为内部常量（不对外暴露数值）。

> 结论：`IP_LEAK_BLOCK` 继续视为域名系统匹配结果；它是否能被 IP 的 `ALLOW` 覆盖取决于 `POLICY.ORDER`。

---

## 4. 已决定：IP 规则引擎语义（对外可见的关键点）

### 4.1 规则模型（v1）
每条规则至少包含：
- 归属：`uid`
- 动作：`ALLOW|BLOCK`
- 开关：`enabled`、`enforce`、`log`
- 优先级：显式 `priority`
- 匹配维度（IPv4）：
  - `direction`（in/out/any）
  - `ifaceKind`（wifi/data/vpn/unmanaged/any）+ 可选 `ifindex` 精确匹配
  - `proto`（tcp/udp/icmp/any）
  - `src/dst IPv4 CIDR`（`/0..32`）
  - `src/dst port`（any / 精确 / range）
- 预留：`ct`（本期可解析但不强制参与匹配）

### 4.2 命中唯一性（稳定归因）
同一包命中多条规则时，必须按固定 tie‑break 选出唯一胜者：
1) `priority`（高者胜）
2) `specificityScore`（编译期计算，仅在 priority 相等时用）
3) `ruleId`（小者胜，保证稳定）

### 4.3 safety‑mode（逐条/批次规则；每包最多 1 条 would‑match）
- `enforce=1`：命中时实际执行 `ALLOW/BLOCK` 改变 verdict，并输出 `ruleId`。
- `enforce=0, log=1`：命中时不得改变实际 verdict，只输出 would‑match（`wouldRuleId + wouldDrop=1`），且每包最多 1 条。

### 4.4 per‑rule stats（常态可查，不依赖 PKTSTREAM）
- 每条规则维护 `hit*` 与 `wouldHit*`（since boot，不持久化；重启归零）。
- 若需要跨重启保留/做长期分析，由前端周期性读取并自行持久化；后端不承担存储职责。
- 统计只归因到“最终胜出规则”和“最终 would‑match 规则（若有）”，避免一包多记。

### 4.5 IPv4/IPv6 边界
- 本期新规则语义仅作用于 IPv4。
- IPv6 流量不受新规则影响（默认放行且不提示“被规则检查过”）。

---

## 5. 已决定：实现基线（所有细节必须与此一致）

1) **Snapshot 模型**：immutable snapshot + atomic publish  
`atomic<shared_ptr<const EngineSnapshot>>`；控制面编译新快照并一次性发布；热路径只读查询。

2) **分类器路线**：OVS 风格 mask‑subtable classifier  
按 `MaskSig`（字段 mask 形状）分子表；`UidView` 内 subtables 按 `subtable.maxPriority` 降序；lookup 顺序扫描并用 `maxPriority` 早停。

3) **端口 range**：bucket 内 predicate 扫描（不做展开）  
range 规则进入 bucket 的 `rangeCandidates`（按 priority 降序）；lookup 线性扫描直到首个命中；必须有硬上限保护最坏耗时。

4) **Preflight（复杂度预检）**：推荐告警 + 硬上限拒绝  
至少输出并校验：`rulesTotal/rangeRulesTotal/subtablesTotal/maxSubtablesPerUid/maxRangeRulesPerBucket`（可选内存估算）。  
超推荐阈值：允许 apply 但给 warning；超硬上限：拒绝 apply（`NOK` + report）。

5) **zero‑cost disable**：`IPRULES=0` 时热路径不得做任何 snapshot load/lookup。

---

## 6. 明确延后/非目标（避免误当结论）

- 域名系统独立开关（DOMAINPOLICY/DOMAINMAP）与 DNS `getips` 行为：推迟到最终融合阶段再决定。
- IPv6 的新规则语义：后置。
- 不实现全局 checkpoint/rollback；safety‑mode 仅限规则引擎内 `enforce/log`。
- 不在 P0/P1 强行重构域名系统内部（DomainList/自定义名单与规则链保持原样）。

---

## 7. 与原始讨论摘录的差异/澄清（以权威入口为准）

1) **would‑match 不使用独立 reasonId**  
早期讨论中出现过 `IPRULE_WOULD_BLOCK` 一类表述；当前契约为 `wouldRuleId + wouldDrop=1`，`reasonId` 始终解释实际 verdict（见 `openspec/changes/add-pktstream-observability/`）。

2) **reasonId 命名以 PKTSTREAM change 为准**  
统一使用 `IP_RULE_ALLOW/IP_RULE_BLOCK`（而非 `IPRULE_*` 等变体）。

3) **端口 range 走 predicate 扫描 + 硬上限**  
讨论中曾出现“编译期展开”的备选；当前确定不展开，避免 expanded‑entries 爆炸（见 `openspec/changes/add-app-ip-l3l4-rules-engine/design.md`）。
