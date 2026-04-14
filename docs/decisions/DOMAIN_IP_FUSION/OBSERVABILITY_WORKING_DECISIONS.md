# 可观测性：工作决策与原则（P0/P1）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


更新时间：2026-04-14  
状态：工作结论 + vNext 设计收敛（新增 `tracked` 统一语义、`METRICS.TRAFFIC*`、`METRICS.CONNTRACK`、stream `type`/suppressed 事件；待实现）

落地任务清单：`docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_IMPLEMENTATION_TASKS.md`

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
现状：`Streamable::stream()` 在调用线程同步写 socket；慢消费者可能反压并拖慢 NFQUEUE 热路径，甚至阻塞 `RESETALL` 等需要独占 `mutexListeners` 的操作。

本轮融合红线（与 `DOMAIN_IP_FUSION_CHECKLIST.md:2.8` 一致）：

- hot path / `mutexListeners` 锁内不得写 socket，也不得做大 JSON 构造/pretty-format。
- 逐条事件必须先进入**有界队列/ring**，由独立 writer 线程（或等价机制）异步 flush。
- 反压时允许 drop，且必须通过 `type="notice"` 显式提示（不新增独立 metrics；最小字段：`notice="dropped"` + `droppedEvents`）。

产品口径：即便实现异步化，`PKTSTREAM` 仍是“调试期开、短期开、持续读”的通道，不提供“完整不丢”保证。

### 3.4 stream vNext：事件 envelope（`type`）与 suppressed 汇总（NOTICE）

目标：在“调试正确性优先”的前提下，让前端能**可靠解析**、用户能**明确知道自己为什么看不到事件**。

#### 3.4.1 `type` 字段（可靠解析）

- vNext 决策：`DNSSTREAM/PKTSTREAM` 事件都增加顶层字段 `type`，用于显式区分事件类别。
- 候选值（最小集合）：
  - `type="dns"`：DNS 判决事件（DNSSTREAM）
  - `type="pkt"`：packet 判决事件（PKTSTREAM）
  - `type="notice"`：系统提示事件（例如 suppressed）
- 线协议（vNext；为可靠解析与避免输出交织）：
  - 输出采用 NDJSON：**一行一个 JSON 对象**，以 LF（`\n`）分隔；事件 JSON 不得包含换行；不再发送 NUL terminator。
  - `pretty` 禁止：stream 不支持多行/缩进输出；若客户端请求 pretty（命令 `!` 后缀）必须报错并拒绝开启 stream。
  - `*.STOP` 的 `OK` 以 JSON ack 返回：`{"ok": true}`；任何失败以 `{"error": {...}}` 返回（与错误模型一致），确保前端可统一按 NDJSON 解析。
  - 进入 stream 模式后，禁止在同一连接上执行非 stream 控制命令（避免输出交织破坏解析）；如需查询/配置请另开控制连接。

> 说明：stream 开启时优先正确性与可回溯性；字段增加不作为性能优化目标。

#### 3.4.2 suppressed NOTICE（按秒聚合，避免“开了 stream 但什么都没有”）

问题：当 stream 开着但某些 app 未 `tracked` 时，我们会过滤这些 app 的逐条事件输出；如果不提示，用户会误以为 stream 坏了。

决策：stream 内新增 `type="notice"` 的 **suppressed 汇总事件**：

- 触发条件：stream 已开启，且在该输出窗口内存在“被 tracked 过滤”的事件。
- 频率：**最多 1 条/秒/streamType（dns/pkt）**（严格限频）。
  - 注：当前控制面默认是 **单控制端（Android App 1:1）**，因此 suppressed 不引入 per-subscriber 语义；按 streamType 限频即可。
- 内容：输出窗口内的被过滤增量计数，字段尽量复用 `METRICS.TRAFFIC` 的结构（见 4.5），并提供最小操作提示。
- 不要求列出 uid 列表（防止爆炸）；定位“是谁”交给 `METRICS.TRAFFIC*`。
- NOTICE 不持久化、也不参与 horizon 回放：仅对**当前已开启的 stream 连接**实时输出，且只对 stream 开启后的流量生效。若前端需要持久化，应保持 stream 常开并自行落库/聚合。

建议 JSON shape（示例）：

```json
{
  "type": "notice",
  "notice": "suppressed",
  "stream": "dns|pkt",
  "windowMs": 1000,
  "traffic": {
    "dns": {"allow": 0, "block": 0},
    "rxp": {"allow": 0, "block": 0},
    "rxb": {"allow": 0, "block": 0},
    "txp": {"allow": 0, "block": 0},
    "txb": {"allow": 0, "block": 0}
  },
  "hint": "untracked apps have traffic; use TRACK <uid> or METRICS.TRAFFIC*"
}
```

补充决策：反压/队列满导致丢事件时，也必须输出 `type="notice"` 的汇总提示（**不新增独立 metrics**）：

- `notice="dropped"`：表示在该窗口内有逐条事件因反压被丢弃。
- 频率：最多 1 条/秒/streamType（dns/pkt）。
- 字段最小集合：`type/notice/stream/windowMs/droppedEvents`（其余可选）。
- NOTICE 只实时；不进入 ring buffer，不参与 horizon 回放，不落盘。

#### 3.4.3 stream vNext：最小事件字段集合（DNS/packet 同构心智模型）

目标：在 stream 开启时，“单条事件可自解释”，同时字段集合固定、可控。

- `type="dns"`（DNS 判决事件）最小字段：
  - 识别：`type`
  - 时间：`timestamp`
  - 归属：`app/uid/userId`
  - 输入：`domain/domMask/appMask`（判决时快照）
  - 输出：`blocked`
  - 回溯：`policySource/useCustomList/scope/getips`
  - 备注：不输出 legacy `color`（该字段来自开源版本用于区分链条，当前系统语义已扩展且不再对应；若未来定义新语义再讨论新增字段）

- `type="pkt"`（packet 判决事件）最小字段：
  - 识别：`type`
  - 时间：`timestamp`
  - 归属：`app/uid/userId`
  - 输入（五元组与上下文）：`scope?/direction/ipVersion/protocol/srcIp/dstIp/srcPort/dstPort/length/ifindex/ifaceKindBit/interface?`
    - `scope`（可选）：统一心智模型的 scope 宽度（`APP|DEVICE_WIDE|FALLBACK`）；仅当 verdict 能明确归因到对应 scope 时输出
      - 例如：`IFACE_BLOCK` → `APP`；`IP_RULE_*` → `APP|DEVICE_WIDE`（取决于命中规则来源，未来支持 `IPRULES.GLOBAL.*` 时区分）
      - `ALLOW_DEFAULT` 等“无明确规则命中”的路径可以不输出 `scope`
    - `ifaceKindBit`：接口类型 bit（与 `blockIface` 同口径：WiFi=1/Data=2/VPN=4/Unmanaged=128）
    - `interface`（name）仅用于可读性；**不得**作为唯一标识或规则匹配依据（以 `ifindex` 为准）
    - `host`（可选）：若存在可解释的 host name（例如 reverse-dns 或其它映射结果）则一并输出；仅用于可读性/排障，**不得**作为唯一标识或仲裁依据
  - 输出：`accepted/reasonId`
  - 回溯：`ruleId?`、`wouldRuleId?`、`wouldDrop?`
  - Conntrack（可选、避免误导）：仅当该包实际参与 `ct.*` 维度匹配时输出 `ct{state,direction}`

- `type="notice"`（系统提示事件）最小字段：
  - `notice="suppressed"` + `stream="dns|pkt"` + `windowMs`
  - `traffic{dns/rxp/rxb/txp/txb -> {allow,block}}`
  - `hint`
  - `notice="dropped"` + `stream="dns|pkt"` + `windowMs` + `droppedEvents`

#### 3.4.4 stream vNext：回放（horizon）与持久化（save/restore）策略

前提：当前未发正式版，**不承担向后兼容包袱**；stream 的第一目标是调试可回溯，而不是长期历史存储。

决策（vNext）：

- `type="notice"`（suppressed 等系统提示）：
  - **只实时输出**；不进入 ring buffer，不参与 horizon 回放，不落盘。
- `type="dns"` / `type="pkt"`（逐条事件）：
  - **只保留进程内 ring buffer**（用于可选 horizon 回放）。
  - **不做落盘 save/restore**：重启后自然清空；若前端需要持久化，应保持 stream 常开并自行落库。
- stream 关闭时：
  - 不记录/不构造任何逐条事件与 ring buffer（避免热路径分配与锁开销）；仅保留常态 metrics。
- `DNSSTREAM.STOP` / `PKTSTREAM.STOP`：
  - 清空 ring buffer + pending queue（若有）；下次 `START` 视为全新 session（horizon 只回放本次开启期间的 ring）。
- `DNSSTREAM.START` / `PKTSTREAM.START`（回放参数；不影响已有流）：
  - 语法：`*.START [<horizonSec> [<minSize>]]`（单位：秒/条数）
  - 参数仅影响“本次连接启动时的回放（replay）”，不得改变 ring 的保留策略，也不得影响已存在的其它连接/流。
  - 默认：`horizonSec=0`、`minSize=0`（不回放历史，只看实时）。
  - 同一连接重复 `*.START`：报 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - `*.START` 成功：不返回 `OK`（直接开始输出事件）。
  - `*.STOP`：返回 `OK`，并且 **幂等**（未 started 时也返回 `OK`）。
  - 回放选择规则（已确认；v1）：
    - 回放集合 = “时间窗内事件” ∪ “最近 `minSize` 条事件”（两者取并集）。
    - `horizonSec=0` 时仅按 `minSize` 回放；`0/0` 表示不回放。
    - 若请求超出 ring 现存范围：尽力回放（最多回放 ring 中现存事件），不报错。
- 性能红线（实现要求）：逐条事件输出必须异步化（hot path 只做有界 enqueue）；反压允许 drop，并通过 `type="notice"`（`notice="dropped"`）可定位。
- horizon 默认值：建议默认 `0`（只看开启后的实时）；需要回放时由控制面显式传入 horizon。
- `RESETALL` 必须强制 stop 并断开 stream 连接，清空 ring buffer/queue（见 4.7.2）。

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
- 当前 P0 基线/验收明确以 legacy `ip-leak` overlay **关闭**为前提（可理解为验收场景下 `BLOCKIPLEAKS=0`）。
  - `BLOCKIPLEAKS=1` 时，若 overlay 产生最终 DROP，则它自然计入 A 层与 traffic 口径（例如 `reasonId=IP_LEAK_BLOCK`）。
  - 该路径是否长期保留、以及其优先级/解释口径（相对 DomainPolicy 与 IPRULES），仍视为 TBD，留到后续融合阶段单独收敛。

对应主规格：`openspec/specs/pktstream-observability/spec.md`。

### 4.2 B：DomainPolicy `policySource` counters（DNS 口径）
目标：域名功能已完整，必须补上“默认可查”的归因与 counters，避免后置导致设计困难。

- `policySource` 枚举与优先级：与现有 `App::blocked()` 分支顺序一一对应（不细到 ruleId/listId）。
- `policySource` 对外命名（fusion 收敛口径；不做 alias/双写）：`CUSTOM_LIST_AUTHORIZED/BLOCKED`、`CUSTOM_RULE_AUTHORIZED/BLOCKED`、`DOMAIN_DEVICE_WIDE_AUTHORIZED/BLOCKED`、`MASK_FALLBACK`（历史 `CUSTOM_*WHITE/BLACK`、`GLOBAL_*` 仅视为内部实现名）。
- 统计口径：**按 DNS 请求计数**（每次 DNS 判决更新一次）。
- 明确：**先不考虑 ip-leak**（附加功能，不因小事大）。
- 生命周期：since boot（进程内，不落盘）
- 对外接口：`METRICS.DOMAIN.SOURCES*`（device-wide + per-app（per-UID））

权威文档：`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`（主规格：`openspec/specs/domain-policy-observability/spec.md`；历史 change：`openspec/changes/archive/2026-03-27-add-domain-policy-observability/`）。

### 4.3 C：IP per-rule runtime stats（IP 规则引擎）
目标：新 IP 规则从一开始就必须支持可解释 + per-rule stats（常态可查，不依赖 PKTSTREAM）。

- 每条规则 stats：`hitPackets/hitBytes/lastHitTsNs` + `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`
- 输出：`IPRULES.PRINT` 在 rule 对象中包含 `stats`
- 生命周期：since boot（不持久化）；规则 `UPDATE` 后 MUST 清零 stats，规则从 `enabled=0` 重新 `ENABLE` 后也 MUST 清零 stats，避免旧命中混入新语义
- `enabled=0` 的规则不得更新任何 hit/wouldHit 计数，也不得进入 active complexity 口径
- 热路径：只对“最终命中规则”和“最终 would-match 规则（若有）”做无锁原子更新

对应主规格：`openspec/specs/app-ip-l3l4-rules/spec.md`。

### 4.4 D：性能健康指标（NFQ / DNS latency）
目标：以**尽可能小的热路径代价**，在正常运行情况下提供默认可拉取的 latency 指标，用于性能基线、回归对比与线上健康观察。

- 当前只定义两个核心指标：
  - `nfq_total_us`：单个 NFQ 包在 userspace 中的总处理时间。
  - `dns_decision_us`：单次 DNS 判决请求的处理时间。
- 这组指标即 D 层；它与 A/B/C 并列，属于 observability 的 health/perf 维度；不复用 `reasonId` / `policySource` / per-rule stats 语义。
- D 的实现与落地节奏独立于 A/B/C；当前已独立落地，不改变主线排序。
- 对外接口为：`PERFMETRICS [<0|1>]`、`METRICS.PERF`、`METRICS.PERF.RESET`。
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

### 4.5 Traffic（DNS + packet）轻量 counters：`METRICS.TRAFFIC*`

目标：提供一套 **always-on（轻量）** 的 per-app（per-UID）与 device-wide 流量 counters，覆盖 DNS + packet 两条腿，用于：

- “默认可查”的基础吞吐/命中统计（不会依赖 stream 或重型 stats）
- stream 开启但某些 app 未 tracked 时的 suppressed 定位（3.4.2）
- 后续性能基线/回归的最小观测底座

#### 4.5.1 口径（必须锁死）

- 维度固定为：`dns/rxp/rxb/txp/txb`
- 每个维度都输出 `{allow, block}`
- 维度语义（v1）：
  - `dns`：按 DNS 请求计数（每次 DNS 判决更新一次；无 bytes 维度）。
  - `rxp/rxb`：NFQUEUE **INPUT（LOCAL_IN / iptables INPUT）** 路径上的 packet 数/bytes（外部→本机方向）。
  - `txp/txb`：NFQUEUE **OUTPUT（LOCAL_OUT / iptables OUTPUT）** 路径上的 packet 数/bytes（本机→外部方向）。
  - bytes 口径为 NFQUEUE payload 长度（与 PKTSTREAM 的 `length` 一致）。
- 方向定义必须与 **NFQUEUE 的队列分裂/合并模式无关**：即使未来 INPUT/OUTPUT 共用 queue range，也必须按 packet 的 hook/链路方向归类。
  - `rx/tx（INPUT/OUTPUT）` 与 conntrack 的 `ct.direction（orig/reply）` **不是**同一个概念：前者解释“本机收/发”，后者解释“首包方向”。
- `allow/block` 口径（v1）：只看最终 verdict
  - DNS：`blocked=false → allow`，`blocked=true → block`
  - packet：`NF_ACCEPT → allow`，`NF_DROP → block`
  - would-match（log-only/would-block）不改变最终 verdict，因此计入 `allow`（其统计由 per-rule `wouldHit*` 承担）
- `block` 只看最终 verdict：所有导致最终 DROP 的路径都计入（例如 `IFACE_BLOCK`、`IP_RULE_*`、以及当前仍存在的 `IP_LEAK_BLOCK`）
  - 注：`IP_LEAK_BLOCK` 本身是否保留属于后续决策；只要路径仍存在，其 verdict 就自然计入 `block`。
- gating：**仅在 `settings.blockEnabled()==true` 时累计**（与现有 metrics 一致；`BLOCK=0` 时 dataplane bypass，不统计）
- `METRICS.TRAFFIC` 的 device-wide 汇总必须是**全量**（包含 tracked/untracked 的所有 app），否则会导致 suppressed 定位与“默认可查”口径失真

#### 4.5.2 控制面命令与 JSON shape（v1）

- `METRICS.TRAFFIC`：

```json
{
  "traffic": {
    "dns": {"allow": 0, "block": 0},
    "rxp": {"allow": 0, "block": 0},
    "rxb": {"allow": 0, "block": 0},
    "txp": {"allow": 0, "block": 0},
    "txb": {"allow": 0, "block": 0}
  }
}
```

- `METRICS.TRAFFIC.APP <uid|pkg> [USER <userId>]`：

```json
{
  "uid": 123456,
  "userId": 0,
  "app": "com.example",
  "traffic": {
    "dns": {"allow": 0, "block": 0},
    "rxp": {"allow": 0, "block": 0},
    "rxb": {"allow": 0, "block": 0},
    "txp": {"allow": 0, "block": 0},
    "txb": {"allow": 0, "block": 0}
  }
}
```

- app selector（多用户语义）：
  - 统一语法：`<uid>` 或 `<pkg> [USER <userId>]`（禁止 `<pkg> <userId>` 这种位置参数，避免 silent 选错与未来扩展冲突）。
  - INT（`<uid>`）：uid 本身已包含 userId（`uid/100000`），无需额外 `USER` 子句。
  - STR（`<pkg>`）：允许可选 `USER <userId>` 用于消歧。
    - `<pkg>` 允许匹配 canonical `name` 或 `allNames`（别名）；若匹配到多个 app → 必须拒绝并要求 `<uid>` 或更明确输入。
    - 若未指定 `USER` 且存在多个 userId 下同名 package → 必须拒绝并要求指定 `USER`（避免 silent 选错；正确性优先）。

- `METRICS.TRAFFIC.RESET` / `METRICS.TRAFFIC.RESET.APP ...`
- 生命周期：since boot（进程内）；`RESET` 清零；`RESETALL` 必须清零（见 4.7）。

#### 4.5.3 实现约束（热路径）

- traffic counters 必须是固定维度的 `atomic++(relaxed)`，不得复用现有 `StatsTPL/AppStats/DomainStats`（其包含 `shift()/localtime_r/mktime` + map 更新，非轻量）。
- v1 建议实现为 **per-app（per-UID）轻量 counters always-on**；device-wide `METRICS.TRAFFIC` 查询时汇总所有 app 的快照（避免热路径额外全局原子争用）。
  - 若未来需要进一步降低 `METRICS.TRAFFIC` 查询成本，可再引入可选的 device-wide sharded counters；但这会让热路径每次更新多一次（或多次）`atomic++`，属于 tradeoff。

### 4.6 Conntrack（L4）轻量 counters：`METRICS.CONNTRACK`

目标：暴露 conntrack core 的最小健康计数，用于容量/扫表/溢出等诊断；不做 per-flow/per-entry dump。

- v1 字段固定为：
  - `totalEntries`
  - `creates`
  - `expiredRetires`
  - `overflowDrops`
- gating：仅在 `settings.blockEnabled()==true` 时有意义/更新
- 生命周期：since boot（进程内）；`RESETALL` 必须清零（见 4.7）
- v1 暂不提供独立 `METRICS.CONNTRACK.RESET`：先锁死 `RESETALL` 行为即可

建议 JSON shape：

```json
{
  "conntrack": {
    "totalEntries": 0,
    "creates": 0,
    "expiredRetires": 0,
    "overflowDrops": 0
  }
}
```

### 4.7 `tracked` 统一语义（两条腿一致）与重型 stats 边界

目标：让 `tracked` 成为跨 DNS/packet 的统一概念：控制“重型统计/逐条事件”的噪音与热路径成本，而不影响判决本身。

#### 4.7.1 `tracked` 的语义（vNext）

- `tracked` **不影响** allow/drop 判决，只影响 observability：
  - stream 逐条事件输出（DNSSTREAM/PKTSTREAM）
  - 重型历史 stats（现有 `ALL.* / APP.* / DOMAINS.*` 体系）
- `tracked` **不 gating** 轻量 always-on counters（A/B/C/4.5/4.6）：
  - `METRICS.REASONS`、`METRICS.DOMAIN.SOURCES*`、`IPRULES.PRINT stats`、`METRICS.TRAFFIC*`、`METRICS.CONNTRACK` 等应默认可查
- 默认值：`tracked=false`（便于极限压测与降低默认噪音；需要观测某个 app 时显式 `TRACK`）
- `tracked` 不持久化：daemon 重启后全部恢复为 `false`；如前端希望“重启后继续追踪”，由前端在连接建立后重新下发相关命令。

#### 4.7.2 `RESETALL` 与 counters 边界（补充）

`RESETALL` 必须清零：

- `METRICS.TRAFFIC*`
- `METRICS.CONNTRACK`
- 以及既有：`METRICS.REASONS*`、`METRICS.DOMAIN.SOURCES*`、`IPRULES` runtime stats、`METRICS.PERF*`
- 并且必须清理所有“观测状态”：
  - `tracked`：全部重置为 `false`
  - stream：强制 stop 并断开连接；清空 `DNSSTREAM/PKTSTREAM` 的 ring buffer/queue
  - 若实现中仍存在历史遗留的 stream 落盘文件（例如旧版 `dnsstream` save）：应同步删除，避免回放混入旧 schema 数据

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
`openspec/specs/pktstream-observability/spec.md`

2) IP 规则语义 + C 层 per-rule stats（含 `IPRULES.PRINT` 的 `stats`）：  
`openspec/specs/app-ip-l3l4-rules/spec.md`

3) 域名侧 `policySource` 与 B 层 counters 口径：  
`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`

4) D 层性能健康指标（`PERFMETRICS` / `METRICS.PERF*`）的边界与口径：  
`openspec/specs/perfmetrics-observability/spec.md`（历史 change 归档：`openspec/changes/archive/2026-03-15-add-perfmetrics-observability/`）
