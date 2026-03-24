# 可观测性：工作决策与原则（P0/P1）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


更新时间：2026-03-15  
状态：工作结论（可迭代修订；实现与验收以 OpenSpec change 为准）

---

## 0. 定义（我们说的“可观测性”是什么）

本项目的可观测性 = **事件（Events）** + **指标/计数（Metrics/Counters）** 两条腿：

- **Events（调试型）**：`PKTSTREAM/DNSSTREAM/ACTIVITYSTREAM` 等 push 流；用于“看最近发生了什么、为什么”。
- **Metrics（常态型）**：拉取式 counters；用于“默认可查、不会因为前端慢而拖热路径”的命中统计与健康信息。

后端只负责输出结构化事件/指标；前端负责采集、过滤、聚合、落库、过期丢弃（不在后端新增存储/查询系统）。

---

## 1. 决策原则（下结论时遵循的逻辑）

1) **在现状基础上，NFQUEUE 热路径不引入新的锁/重 IO/动态分配**  
热路径仅允许纯计算、只读快照查询与固定维度的 `atomic++(relaxed)`；不得新增阻塞点。

2) **不新增观测通路**  
事件复用现有 stream；常态统计通过控制面拉取（Prometheus 风格），不引入新 daemon/存储。

3) **不做全局 safety-mode（现在不做、以后也不做）**  
safety-mode 仅针对“规则引擎内的逐条/批次规则”（`enforce/log`），不要求全系统 dry-run。

4) **事实优先于规划**  
以源码事实语义（gating、判决链路、stream 风险）约束设计；规划随实现调整。

5) **域名系统不在 P0/P1 大重构**  
先把可解释骨架与最关键的 IP 规则落地；域名细粒度定位（per-rule）后置。

6) **当前未发正式版：不预设历史迁移包袱，但观测接口仍须稳定收敛**  
当前不需要为了已发布旧版本预留额外兼容/迁移逻辑；但 stream 字段、metrics 口径与 reasonId 语义依然不能随意变。只有当存在明确重大理由（例如修复错误语义、消除跨文档冲突、满足已确认需求）时，才允许调整，并且必须同步更新权威文档与相关 change。

---

## 2. 决策拆分（A/B/C/D 四层）

为避免“域名 vs IP”割裂，可观测性拆成四层（每层有独立的口径与边界）：

- **A：Packet 判决层（device-wide）**  
面向“最终 verdict 的原因”与常态 reason counters。
- **B：DomainPolicy 层（DNS 口径）**  
面向“域名策略命中来源（policySource）”与常态 counters。
- **C：IP 规则层（per-rule）**  
面向“新 IP 规则引擎每条规则的运行时命中统计”。
- **D：性能健康指标层（latency / health metrics）**  
面向“这次处理花了多久”，而不是“为什么命中”。

对 D 层的当前结论如下：

- 当前只关心两个核心指标：`nfq_total_us` 与 `dns_decision_us`。
- D 属于常态 metrics，可在正常运行中按需开启/关闭；不要求前端持续订阅 stream。
- D 的控制面、口径与 JSON shape 必须稳定；是否采集仅由运行时开关控制，**不以 debug/release 区分接口与语义**。
- D 与 A/B/C 的语义独立，也不参与 `A → IPRULES v1（含 C） → B` 这条功能主线排序；其对应 change 可按需要独立推进。

---

## 3. Events（调试型）核心结论

### 3.1 PKTSTREAM 的定位
`PKTSTREAM` 是 packet decision event pipe：事件从“活动包”升级为“判决摘要事件”，前端订阅/采集/聚合即可。

### 3.2 reasonId / would-match 语义
- `reasonId` **只解释实际 verdict**（即 `accepted` 的原因），每包仅 1 个且确定性选择。
- 当前 would-match 仅指 `action=BLOCK, enforce=0, log=1` 的 would-block dry-run；不为 `ALLOW` 定义对称的 would-allow 语义。
- log-only/would-block 不使用独立 `reasonId`：使用 `wouldRuleId + wouldDrop=1` 表达 would-match；并且仅在该包无 `enforce=1` 最终命中时出现，此时 `accepted` 仍为 1。
- 若包的实际 `reasonId=IFACE_BLOCK`，则不得再附带来自更低优先级规则层的 `ruleId`/`wouldRuleId`。

### 3.3 stream 风险（必须认知）
`Streamable::stream()` 在调用线程同步写 socket；慢消费者可能反压并拖慢热路径。产品与文档需要把 PKTSTREAM 定位为“调试期开、短期开、持续读”。

---

## 4. Metrics（常态型）核心结论

### 4.1 A：reasonId counters（Packet，device-wide）
目标：默认可查、与 PKTSTREAM 订阅无关、热路径只做 `atomic++`。

- 对外：`METRICS.REASONS` / `METRICS.REASONS.RESET`
- 字段：每个 `reasonId` 的 `packets/bytes`
- JSON shape：固定为顶层对象 `{"reasons": {...}}`
- 生命周期：since boot（进程内，不落盘；重启归零）
- counters 不依赖 `tracked`（默认可查），也不依赖 PKTSTREAM 是否开启
- gating：保持事实语义，仅对进入 Packet 判决链路的包统计（当前 `BLOCK=0` 不进入判决链路）
- 当前 P0 基线/验收明确以 legacy `ip-leak` 路径**未参与 Packet 最终判决**为前提（可理解为当前 A 层验收场景下 `BLOCKIPLEAKS=0`）；`BLOCKIPLEAKS=1` 时是否恢复独立 `reasonId`、其命名与优先级，统一留到后续融合阶段单独收敛

对应 OpenSpec：`add-pktstream-observability`。

### 4.2 B：DomainPolicy `policySource` counters（DNS 口径）
目标：域名功能已完整，必须补上“默认可查”的归因与 counters，避免后置导致设计困难。

- `policySource` 枚举与优先级：与现有 `App::blocked()` 分支顺序一一对应（不细到 ruleId/listId）。
- 统计口径：**按 DNS 请求计数**（每次 DNS 判决更新一次）。
- 明确：**先不考虑 ip-leak**（附加功能，不因小事大）。
- 生命周期：since boot（进程内，不落盘）
- 对外接口（拟定）：`METRICS.DOMAIN.SOURCES*`（device-wide + per-app）

权威文档：`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`（域名侧不新建 OpenSpec change）。

### 4.3 C：IP per-rule runtime stats（IP 规则引擎）
目标：新 IP 规则从一开始就必须支持可解释 + per-rule stats（常态可查，不依赖 PKTSTREAM）。

- 每条规则 stats：`hitPackets/hitBytes/lastHitTsNs` + `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`
- 输出：`IPRULES.PRINT` 在 rule 对象中包含 `stats`
- 生命周期：since boot（不持久化）；规则 `UPDATE` 后 MUST 清零 stats，规则从 `enabled=0` 重新 `ENABLE` 后也 MUST 清零 stats，避免旧命中混入新语义
- `enabled=0` 的规则不得更新任何 hit/wouldHit 计数，也不得进入 active complexity 口径
- 热路径：只对“最终命中规则”和“最终 would-match 规则（若有）”做无锁原子更新

对应 OpenSpec：`add-app-ip-l3l4-rules-engine`。

### 4.4 D：性能健康指标（NFQ / DNS latency）
目标：以**尽可能小的热路径代价**，在正常运行情况下提供默认可拉取的 latency 指标，用于性能基线、回归对比与线上健康观察。

- 当前只定义两个核心指标：
  - `nfq_total_us`：单个 NFQ 包在 userspace 中的总处理时间。
  - `dns_decision_us`：单次 DNS 判决请求的处理时间。
- 这组指标即 D 层；它与 A/B/C 并列，属于 observability 的 health/perf 维度；不复用 `reasonId` / `policySource` / per-rule stats 语义。
- D 的实现与落地节奏独立于 A/B/C；只要控制面与口径稳定，其 change 可单独推进，不作为主线依赖。
- 对外接口拟定为：`PERFMETRICS [<0|1>]`、`METRICS.PERF`、`METRICS.PERF.RESET`。
- `PERFMETRICS=0` 时热路径只允许一个极轻量 gating branch；`PERFMETRICS=1` 时才做计时与聚合。
- 接口、字段与语义**不区分 debug/release**；是否采集仅由运行时开关决定。

#### 4.4.1 指标边界（固定口径）

- `nfq_total_us`
  - 开始：`PacketListener::callback()` 入口。
  - 结束：`sendVerdict()` 返回之后。
  - 语义：覆盖 packet parse、`App/Host` 构造、锁等待、`pktManager.make()`、以及 verdict 回写。
- `dns_decision_us`
  - 开始：DNS 请求体（`len/domain/uid`）已读完，且 `App/Domain` 已构造完成之后。
  - 结束：`verdict/getips` 两个返回值写回完成之后。
  - 语义：只覆盖“判决本身”；**不**把后续 IP 上传阶段纳入 latency，以免混入对端上传节奏。

#### 4.4.2 聚合口径

- 单位统一为 `us`。
- 生命周期统一为 `since_reset_or_enable`：
  - `PERFMETRICS 0→1` 时自动清零；
  - `METRICS.PERF.RESET` 时显式清零；
  - 重启后归零，不持久化。
- 当前最小输出集合固定为：`samples/min/avg/p50/p95/p99/max`。
- 统计方式优先采用 histogram/分桶聚合，不保存逐样本历史，也不做每包日志输出。

#### 4.4.3 热路径约束

- 不得为这组指标新增 stream、磁盘 I/O、每包 JSON、每包日志或长时间持锁。
- NFQ 路径应优先使用 per-thread / per-queue 分片聚合，snapshot 时再 merge，避免全局争用。
- DNS 路径允许采用更简单的轻量聚合实现，但仍不得在热路径引入阻塞点。
- 这组指标属于“正常运行时可开启”的常态 metrics，而不是 debug-only instrumentation。

---

## 5. 明确延后/非目标（避免误解）

- 不做全局 safety-mode（dry-run 全系统）。
- 不要求 `BLOCK=0` 时逐包输出 reasonId（engine_off 属于状态解释：`BLOCK/ACTIVITYSTREAM`）。
- 不要求本轮为 legacy `BLOCKIPLEAKS=1` 分支补齐最终 `reasonId` 命名与验收场景；该路径当前明确视为 TBD，不作为 A 层落地阻塞项。
- 不做域名规则 per-rule counters（regex/wildcard/listId）：现状聚合 regex 无法归因，需更大重构，后置。
- 不把 ip-leak 混进域名 policySource counters：如需统计，后续以独立维度/命令追加。
- 不把 `ping RTT`、control socket 往返或前端消费延迟当作 `nfq_total_us` / `dns_decision_us` 的替代口径。
- 不在后端引入 Prometheus/集中存储角色：前端自行采样与落库。

---

## 6. 归属与“单一真相”（避免文件互相打架）

1) PKTSTREAM schema + reasonId/would-match 契约 + A 层 `METRICS.REASONS`：  
`openspec/changes/add-pktstream-observability/`

2) IP 规则语义 + C 层 per-rule stats（含 `IPRULES.PRINT` 的 `stats`）：  
`openspec/changes/add-app-ip-l3l4-rules-engine/`

3) 域名侧 `policySource` 与 B 层 counters 口径：  
`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`

4) D 层性能健康指标（`PERFMETRICS` / `METRICS.PERF*`）的边界与口径：  
`openspec/specs/perfmetrics-observability/`（历史 change 归档：`openspec/changes/archive/2026-03-15-add-perfmetrics-observability/`）
