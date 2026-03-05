# 可观测性：工作决策与原则（P0/P1）

更新时间：2026-03-05  
状态：工作结论（可迭代修订；实现与验收以 OpenSpec change 为准）

---

## 0. 定义（我们说的“可观测性”是什么）

本项目的可观测性 = **事件（Events）** + **指标/计数（Metrics/Counters）** 两条腿：

- **Events（调试型）**：`PKTSTREAM/DNSSTREAM/ACTIVITYSTREAM` 等 push 流；用于“看最近发生了什么、为什么”。
- **Metrics（常态型）**：拉取式 counters；用于“默认可查、不会因为前端慢而拖热路径”的命中统计与健康信息。

后端只负责输出结构化事件/指标；前端负责采集、过滤、聚合、落库、过期丢弃（不在后端新增存储/查询系统）。

---

## 1. 决策原则（下结论时遵循的逻辑）

1) **NFQUEUE 热路径不引入新锁/重 IO/动态分配**  
热路径仅允许纯计算、只读快照查询与固定维度的 `atomic++(relaxed)`。

2) **不新增观测通路**  
事件复用现有 stream；常态统计通过控制面拉取（Prometheus 风格），不引入新 daemon/存储。

3) **不做全局 safety-mode（现在不做、以后也不做）**  
safety-mode 仅针对“规则引擎内的逐条/批次规则”（`enforce/log`），不要求全系统 dry-run。

4) **事实优先于规划**  
以源码事实语义（gating、判决链路、stream 风险）约束设计；规划随实现调整。

5) **域名系统不在 P0/P1 大重构**  
先把可解释骨架与最关键的 IP 规则落地；域名细粒度定位（per-rule）后置。

---

## 2. 决策拆分（A/B/C 三层）

为避免“域名 vs IP”割裂，可观测性拆成三层（每层有独立的口径与边界）：

- **A：Packet 判决层（device-wide）**  
面向“最终 verdict 的原因”与常态 reason counters。
- **B：DomainPolicy 层（DNS 口径）**  
面向“域名策略命中来源（policySource）”与常态 counters。
- **C：IP 规则层（per-rule）**  
面向“新 IP 规则引擎每条规则的运行时命中统计”。

---

## 3. Events（调试型）核心结论

### 3.1 PKTSTREAM 的定位
`PKTSTREAM` 是 packet decision event pipe：事件从“活动包”升级为“判决摘要事件”，前端订阅/采集/聚合即可。

### 3.2 reasonId / would-match 语义
- `reasonId` **只解释实际 verdict**（即 `accepted` 的原因），每包仅 1 个且确定性选择。
- log-only 不使用独立 `reasonId`：使用 `wouldRuleId + wouldDrop=1` 表达 would-match；并且 `accepted` 仍为 1。

### 3.3 stream 风险（必须认知）
`Streamable::stream()` 在调用线程同步写 socket；慢消费者可能反压并拖慢热路径。产品与文档需要把 PKTSTREAM 定位为“调试期开、短期开、持续读”。

---

## 4. Metrics（常态型）核心结论

### 4.1 A：reasonId counters（Packet，device-wide）
目标：默认可查、与 PKTSTREAM 订阅无关、热路径只做 `atomic++`。

- 对外：`METRICS.REASONS` / `METRICS.REASONS.RESET`
- 字段：每个 `reasonId` 的 `packets/bytes`
- 生命周期：since boot（进程内，不落盘；重启归零）
- gating：保持事实语义，仅对进入 Packet 判决链路的包统计（当前 `BLOCK=0` 不进入判决链路）

对应 OpenSpec：`add-pktstream-observability`。

### 4.2 B：DomainPolicy `policySource` counters（DNS 口径）
目标：域名功能已完整，必须补上“默认可查”的归因与 counters，避免后置导致设计困难。

- `policySource` 枚举与优先级：与现有 `App::blocked()` 分支顺序一一对应（不细到 ruleId/listId）。
- 统计口径：**按 DNS 请求计数**（每次 DNS 判决更新一次）。
- 明确：**先不考虑 ip-leak**（附加功能，不因小事大）。
- 生命周期：since boot（进程内，不落盘）
- 对外接口（拟定）：`METRICS.DOMAIN.SOURCES*`（device-wide + per-app）

权威文档：`docs/DOMAIN_POLICY_OBSERVABILITY.md`（域名侧不新建 OpenSpec change）。

### 4.3 C：IP per-rule runtime stats（IP 规则引擎）
目标：新 IP 规则从一开始就必须支持可解释 + per-rule stats（常态可查，不依赖 PKTSTREAM）。

- 每条规则 stats：`hitPackets/hitBytes/lastHitTsNs` + `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`
- 输出：`IPRULES.PRINT` 在 rule 对象中包含 `stats`
- 生命周期：since boot（不持久化）；规则 UPDATE 建议清零 stats
- 热路径：只对“最终命中规则”和“最终 would-match 规则（若有）”做无锁原子更新

对应 OpenSpec：`add-app-ip-l3l4-rules-engine`。

---

## 5. 明确延后/非目标（避免误解）

- 不做全局 safety-mode（dry-run 全系统）。
- 不要求 `BLOCK=0` 时逐包输出 reasonId（engine_off 属于状态解释：`BLOCK/ACTIVITYSTREAM`）。
- 不做域名规则 per-rule counters（regex/wildcard/listId）：现状聚合 regex 无法归因，需更大重构，后置。
- 不把 ip-leak 混进域名 policySource counters：如需统计，后续以独立维度/命令追加。
- 不在后端引入 Prometheus/集中存储角色：前端自行采样与落库。

---

## 6. 归属与“单一真相”（避免文件互相打架）

1) PKTSTREAM schema + reasonId/would-match 契约 + A 层 `METRICS.REASONS`：  
`openspec/changes/add-pktstream-observability/`

2) IP 规则语义 + C 层 per-rule stats（含 `IPRULES.PRINT` 的 `stats`）：  
`openspec/changes/add-app-ip-l3l4-rules-engine/`

3) 域名侧 `policySource` 与 B 层 counters 口径：  
`docs/DOMAIN_POLICY_OBSERVABILITY.md`

