# 可观测性：工作决策与原则（P0/P1）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


更新时间：2026-04-20  
状态：工作结论 + vNext 设计收敛（新增 `tracked` 统一语义、`METRICS.GET(name=traffic|conntrack)`、统一 `STREAM.START/STOP(type=...)`、stream `type`/suppressed 事件；待实现）

落地任务清单：`docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_IMPLEMENTATION_TASKS.md`

---

## 0. 定义（我们说的“可观测性”是什么）

本项目的可观测性 = **事件（Events）** + **指标/计数（Metrics/Counters）** 两条腿：

- **Events（调试型）**：统一 `STREAM.START(type=pkt|dns|activity)` 的 push 流；用于“看最近发生了什么、为什么”。
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

- vNext 决策：所有 stream（`type=dns|pkt|activity|notice`）事件都增加顶层字段 `type`，用于显式区分事件类别。
- 候选值（最小集合）：
  - `type="dns"`：DNS 判决事件
  - `type="pkt"`：packet 判决事件
  - `type="activity"`：activity 事件
  - `type="notice"`：系统提示事件（例如 suppressed）
- 线协议（vNext；为可靠解析与避免输出交织）：
  - framing 采用 netstring（见 `CONTROL_PROTOCOL_VNEXT.md`）：每条 response/event 都是一个 netstring frame，payload 为 UTF‑8 JSON object；不发送 NUL terminator。
    - 严格 JSON（2.10）：所有字符串字段必须正确 escape（至少处理 `\" \\ \n \r \t`）。
  - stream events 与 control response 共享同一 framing，但 event 不得包含 `id/ok`（避免与 response 混淆）。
  - `STREAM.STOP` 的 ack 是该 STOP 的 response frame（`{"id":...,"ok":true}`）；失败为 `{"id":...,"ok":false,"error":{...}}`（与错误模型一致）。
  - 进入 stream 模式后，禁止在同一连接上执行非 stream 控制命令（避免输出交织与心智分裂）；如需查询/配置请另开控制连接。

> 说明：stream 开启时优先正确性与可回溯性；字段增加不作为性能优化目标。

#### 3.4.2 suppressed NOTICE（按秒聚合，避免“开了 stream 但什么都没有”）

问题：当 stream 开着但某些 app 未 `tracked` 时，我们会过滤这些 app 的逐条事件输出；如果不提示，用户会误以为 stream 坏了。

决策：stream 内新增 `type="notice"` 的 **suppressed 汇总事件**：

- 触发条件：stream 已开启，且在该输出窗口内存在“被 tracked 过滤”的事件。
- 频率：**最多 1 条/秒/streamType（dns/pkt）**（严格限频）。
  - 注：按 2.8-A 单连接约束，同一时间每种 stream 只允许 1 条连接订阅，因此 suppressed 不引入 per-subscriber 语义；按 streamType 限频即可。
- 内容：输出窗口内的被过滤增量计数，字段尽量复用 `METRICS.GET(name=traffic)` 的结构（见 4.5），并提供最小操作提示。
- 不要求列出 uid 列表（防止爆炸）；定位“是谁”交给 `METRICS.GET(name=traffic, app=...)`。
- NOTICE 不持久化、也不参与 horizon 回放：仅对**当前已开启的 stream 连接**实时输出，且只对 stream 开启后的流量生效。若前端需要持久化，应保持 stream 常开并自行落库/聚合。

`notice="dropped"`（反压丢事件提示）补充锁死（已确认；2.12-A）：
- drop policy：pending queue 满时 drop-oldest（保留最新事件）。
- `droppedEvents`：按“被丢弃的逐条事件条数”计数（不按 bytes）；不包含 NOTICE 自身。
- NOTICE 频率：最多 1 条/秒/streamType；`windowMs` 输出实际聚合窗口。

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
  "hint": "untracked apps have traffic; enable tracked via CONFIG.SET (scope=app,set={tracked:1}) or query METRICS.GET(name=traffic)"
}
```

补充决策：反压/队列满导致丢事件时，也必须输出 `type="notice"` 的汇总提示（**不新增独立 metrics**）：

- `notice="dropped"`：表示在该窗口内有逐条事件因反压被丢弃。
- 频率：最多 1 条/秒/streamType（dns/pkt）。
- 字段最小集合：`type/notice/stream/windowMs/droppedEvents`（其余可选）。
- NOTICE 只实时；不进入 ring buffer，不参与 horizon 回放，不落盘。

#### 3.4.3 stream vNext：最小事件字段集合（DNS/packet 同构心智模型）

目标：在 stream 开启时，“单条事件可自解释”，同时字段集合固定、可控。

**字段类型与缺失表示（已确认；2.24‑A）**
- optional 字段缺失时：**省略该 key**（不输出 `"n/a"`/空字符串；不依赖客户端猜测）。
- 布尔语义字段：统一使用 JSON boolean（`true|false`），例如：`blocked/accepted/wouldDrop/blockEnabled`。
- `timestamp` 格式锁死为字符串：`"<sec>.<nsec>"`（nsec 固定 9 位，不足补 0）；DNS/pkt 同口径。
  - 注：这条约束只适用于 stream 事件 schema；控制面里“开关类命令”的返回值仍可维持 legacy `0|1`（numbers），两者不强行统一。
- `protocol` 字段类型锁死为 string（对用户/前端更友好）：`"tcp"|"udp"|"icmp"|"other"`（ICMPv6 同样使用 `"icmp"`；未知/不支持用 `"other"`，不使用 `"n/a"`）。

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
    - `domain`（可选）：来自 DNS‑learned Domain↔IP bridge 的 best‑effort 域名；仅用于可读性/排障，**不得**作为唯一标识或仲裁依据
      - 仅当 bridge 命中且 `domain.validIP()==true` 时输出（避免陈旧映射误导）。
    - `host`（可选）：来自 reverse‑dns 的 best‑effort host name；仅用于可读性/排障，**不得**作为唯一标识或仲裁依据
    - 补充：
      - `domain/host` 若输出，应来自 bridge / reverse‑dns 缓存；不得为了补这两个字段在 packet 热路径额外引入 DomainPolicy 判决（仅在已进入 `tracked` 的观测路径时按需计算）。
      - `domain.validIP()` 内部需要 `time()`；为满足 2.8 的 ACA 红线，建议在 **writer/序列化线程**做 `validIP` 判定与字段输出，避免 hot path 每包调用 `time()`。
      - `domain/host` 属于 best‑effort 可读性字段；不承诺“判决时快照”，允许轻微漂移（例如 reverse‑dns 结果延迟出现）。
      - 对外解释口径（已确认；2.33-A）：
        - `domain/host` 缺失表示“未知/不可得”，不是错误；前端可省略展示或显示 `-`。
        - `domain` 即使存在，也只是“该 IP 当前关联到的一个 domain 标签”，不保证与该包真实业务域名一致（例如 CDN/多域名共享 IP）；不得用于归因或仲裁解释。
        - 若需要更强排障，应查看 `STREAM.START(type=dns)`（含 `getips/domMask/appMask/policySource`）或常态 metrics（`METRICS.GET(name=domainSources)`/`METRICS.GET(name=traffic)`）。
  - 输出：`accepted/reasonId`
  - 回溯：`ruleId?`、`wouldRuleId?`、`wouldDrop?`
    - `wouldDrop`：仅当 `wouldRuleId` 存在时输出；类型为 boolean（与 `accepted` 同类语义）。
  - Conntrack（可选、避免误导）：仅当该包实际参与 `ct.*` 维度匹配时输出 `ct{state,direction}`

- `type="activity"`（activity 事件）最小字段：
  - 识别：`type`
  - 输出：`blockEnabled`（boolean）
  - 可选（解释辅助）：`uid/userId/app`（例如 top app；回显风格与其它事件一致）

- `type="notice"`（系统提示事件）最小字段：
  - `notice="suppressed"` + `stream="dns|pkt"` + `windowMs`
  - `traffic{dns/rxp/rxb/txp/txb -> {allow,block}}`
  - `hint`
  - `notice="dropped"` + `stream="dns|pkt"` + `windowMs` + `droppedEvents`
  - `notice="started"` + `stream="dns|pkt|activity"`（可选 echo：`horizonSec/minSize`）

#### 3.4.4 stream vNext：回放（horizon）与持久化（save/restore）策略

前提：当前未发正式版，**不承担向后兼容包袱**；stream 的第一目标是调试可回溯，而不是长期历史存储。

决策（vNext）：

- `type="notice"`（suppressed 等系统提示）：
  - **只实时输出**；不进入 ring buffer，不参与 horizon 回放，不落盘。
- `type="dns"` / `type="pkt"`（逐条事件）：
  - **只保留进程内 ring buffer**（用于可选 horizon 回放）。
  - **不做落盘 save/restore**：重启后自然清空；若前端需要持久化，应保持 stream 常开并自行落库。
- `type="activity"`：
  - **只实时输出**；不进入 ring buffer，不参与 horizon 回放，不落盘。
- 无订阅者（stream 关闭时）：
  - 未 `tracked` 的 app：不构造逐条事件/不入 ring（避免把可选成本变成每包必经成本）。
  - 已 `tracked` 的 app：仍构造逐条事件并进入进程内 ring（用于 `STREAM.START(type=dns|pkt, horizonSec/minSize)` 回放）；不做 socket I/O；不落盘。
  - 如需完全关闭逐条事件的观测成本，应通过 `CONFIG.SET`（`scope=app`，`set.tracked=0`）关闭 `tracked`（D8：tracked 持久化，且前端开启时必须提示性能影响）。
- `STREAM.STOP`：
  - 返回 response frame（`{"id":...,"ok":true}`；幂等）；并清理 pending queue（若有）。
  - **ack barrier（已确认；2.9-B）**：
    - STOP 必须先禁用该连接订阅并清空该连接 pending queue（允许丢弃尾部未发送事件/notice），再输出 `{"id":...,"ok":true}`。
    - `{"id":...,"ok":true}` 必须是该 STOP 的最后一个输出 frame；ack 后不得再输出任何事件/notice，直到下一次 `STREAM.START`。
  - 对 dns/pkt：清空 ring buffer；下次 `START` 视为全新 session（horizon 只回放自上次 `STOP/RESETALL` 之后积累的 ring）。
- `STREAM.START`（入口统一；通过 `args.type` 区分；不影响其它连接）：
  - request `args`：
    - `type="dns"|"pkt"`：支持 `horizonSec/minSize`（单位：秒/条数；默认 `0/0`）
    - `type="activity"`：不支持回放参数（应省略；或要求为 `0/0`）
  - 参数仅影响“本次连接启动时的回放（replay）”，不得改变 ring 的保留策略，也不得影响其它 stream 类型（dns/pkt/activity 之间互不影响）。
  - **单连接约束（已确认；2.8-A）**：同一时间每种 stream 只允许 1 条连接订阅；已有连接存在时，新的 `STREAM.START` 返回 `STATE_CONFLICT`（避免“STOP 清空 ring”影响其它订阅者的语义矛盾）。
  - **连接拓扑（已确认；2.27-A）**：同一条 stream 连接同一时间只允许订阅一种 streamType；连接一旦 `STREAM.START(type=dns)`，则在 `STREAM.STOP` 之前，任何试图在同一连接上启动其它 type 或执行非 stream 控制命令，一律 `STATE_CONFLICT`。需要同时看 dns+pkt+activity 时，前端应使用多条连接（每种 streamType 一条）。
  - 同一连接重复 `STREAM.START`：报 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - `STREAM.START` 成功：先返回 response frame（`{"id":...,"ok":true}`），并且必须先输出一次 `type="notice", notice="started"`（至少一条；不进入 ring、不参与 horizon、不落盘），然后才开始回放（若有）与实时事件输出。
  - `STREAM.STOP`：返回 response frame（`{"id":...,"ok":true}`），并且 **幂等**（未 started 时也返回 `{"id":...,"ok":true}`）。
  - 回放选择规则（已确认；v1）：
    - 回放集合 = “时间窗内事件” ∪ “最近 `minSize` 条事件”（两者取并集）。
    - `horizonSec=0` 时仅按 `minSize` 回放；`0/0` 表示不回放。
    - 若请求超出 ring 现存范围：尽力回放（最多回放 ring 中现存事件），不报错。
  - **有界 cap（已确认；2.31-A）**：
    - ring 与 pending queue 都必须有明确的“按事件条数”的上限（不在本阶段锁具体数值，但必须存在且可配置/可验证）。
      - `maxRingEvents`：ring 最多保留 N 条事件（超出时 drop-oldest；影响 replay 但不影响实时）。
      - `maxPendingEvents`：pending queue 最多 N 条待发送事件（超出时 drop-oldest，并计入 `droppedEvents`，触发 `notice="dropped"`）。
    - `STREAM.START`（`type=dns|pkt`）的 `horizonSec/minSize` 必须 clamp 到能力上限（例如 `minSize<=maxRingEvents`；`horizonSec<=maxHorizonSec`），并把**实际生效值**通过 `notice="started"` echo 回去（避免前端误解）。
- `STREAM.START(type=activity)`：
  - request：`{"id":...,"cmd":"STREAM.START","args":{"type":"activity"}}`（无回放参数）
  - 同一连接重复 `STREAM.START`：报 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - 成功：先返回 response frame（`{"id":...,"ok":true}`），并且必须先输出一次 `type="notice", notice="started"`，并且至少应输出一次当前状态快照。
- 性能红线（实现要求）：逐条事件输出必须异步化（hot path 只做有界 enqueue）；反压允许 drop，并通过 `type="notice"`（`notice="dropped"`）可定位。
- horizon 默认值：建议默认 `0`（只看开启后的实时）；需要回放时由控制面显式传入 horizon。
- `RESETALL` 必须强制 stop 并断开 stream 连接，清空 ring buffer/queue（见 4.7.2）。

---

## 4. Metrics（常态型）核心结论

### 4.1 A：reasonId counters（Packet，device-wide）
目标：默认可查、与 `STREAM.START(type=pkt)` 订阅无关、热路径只做 `atomic++`。

- 对外：`METRICS.GET(name=reasons)` / `METRICS.RESET(name=reasons)`
- 字段：每个 `reasonId` 的 `packets/bytes`
- JSON shape：固定为顶层对象 `{"reasons": {...}}`
- 生命周期：since boot（进程内，不落盘；重启归零）
- counters 不依赖 `tracked`（默认可查），也不依赖 stream 是否开启
- gating：保持事实语义，仅对进入 Packet 判决链路的包统计（当前 `BLOCK=0` 不进入判决链路）
- legacy `BLOCKIPLEAKS/ip-leak` overlay：本轮 fusion 已裁决为**冻结并强制关闭（无作用）**（见本目录 2.21 / D31）。因此 A 层 reasons metrics（`METRICS.GET(name=reasons)`）与 traffic 口径**不讨论也不暴露**任何 `IP_LEAK_*` 类 `reasonId`。

对应主规格：`openspec/specs/pktstream-observability/spec.md`。

### 4.2 B：DomainPolicy `policySource` counters（DNS 口径）
目标：域名功能已完整，必须补上“默认可查”的归因与 counters，避免后置导致设计困难。

- `policySource` 枚举与优先级：与现有 `App::blocked()` 分支顺序一一对应（不细到 ruleId/listId）。
- `policySource` 对外命名（fusion 收敛口径；不做 alias/双写）：`CUSTOM_LIST_ALLOWED/BLOCKED`、`CUSTOM_RULE_ALLOWED/BLOCKED`、`DOMAIN_DEVICE_WIDE_ALLOWED/BLOCKED`、`MASK_FALLBACK`（历史 `CUSTOM_*WHITE/BLACK`、`GLOBAL_*` 仅视为内部实现名）。
- 统计口径：**按 DNS 请求计数**（每次 DNS 判决更新一次）。
- gating：保持事实语义，仅在 `BLOCK=1` 时随 DNS 判决递增（`BLOCK=0` 不计数；不做全局 dry-run）。
- 明确：本轮 **不考虑** `ip-leak/BLOCKIPLEAKS`（已冻结并强制关闭，无作用）。
- 生命周期：since boot（进程内，不落盘）
- 对外：`METRICS.GET(name=domainSources)` / `METRICS.RESET(name=domainSources)`（device-wide + per-app（per-UID））

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
- 对外：
  - 开关：`CONFIG.SET(scope=device,set={perfmetrics.enabled:0|1})`
  - 查询：`METRICS.GET(name=perf)`
  - reset：`METRICS.RESET(name=perf)`
- `perfmetrics.enabled=0` 时热路径只允许一个极轻量 gating branch；`perfmetrics.enabled=1` 时才做计时与聚合。
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
  - `perfmetrics.enabled 0→1` 时自动清零；
  - `METRICS.RESET(name=perf)` 时显式清零；
  - 重启后归零，不持久化。
- 当前最小输出集合固定为：`samples/min/avg/p50/p95/p99/max`。
- 统计方式优先采用 histogram/分桶聚合，不保存逐样本历史，也不做每包日志输出。

#### 4.4.3 热路径约束

- 不得为这组指标新增 stream、磁盘 I/O、每包 JSON、每包日志或长时间持锁。
- NFQ 路径应优先使用 per-thread / per-queue 分片聚合，snapshot 时再 merge，避免全局争用。
- DNS 路径允许采用更简单的轻量聚合实现，但仍不得在热路径引入阻塞点。
- 这组指标属于“正常运行时可开启”的常态 metrics，而不是 debug-only instrumentation。

### 4.5 Traffic（DNS + packet）轻量 counters：metrics name=`traffic`（`METRICS.GET`）

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
- `block` 只看最终 verdict：所有导致最终 DROP 的路径都计入（例如 `IFACE_BLOCK`、`IP_RULE_*` 等）。
- gating：**仅在 `settings.blockEnabled()==true` 时累计**（与现有 metrics 一致；`BLOCK=0` 时 dataplane bypass，不统计）
- `METRICS.GET(name=traffic)` 的 device-wide 汇总必须是**全量**（包含 tracked/untracked 的所有 app），否则会导致 suppressed 定位与“默认可查”口径失真

#### 4.5.2 控制面命令与 JSON shape（v1）

- device-wide query：

```json
{"id":1,"cmd":"METRICS.GET","args":{"name":"traffic"}}
```

```json
{"id":1,"ok":true,"result":{"traffic":{
  "dns":{"allow":0,"block":0},
  "rxp":{"allow":0,"block":0},
  "rxb":{"allow":0,"block":0},
  "txp":{"allow":0,"block":0},
  "txb":{"allow":0,"block":0}
}}}
```

- per-app query：

```json
{"id":2,"cmd":"METRICS.GET","args":{"name":"traffic","app":{"uid":10123}}}
```

或：

```json
{"id":2,"cmd":"METRICS.GET","args":{"name":"traffic","app":{"pkg":"com.example","userId":0}}}
```

```json
{"id":2,"ok":true,"result":{
  "uid":123456,"userId":0,"app":"com.example",
  "traffic":{
    "dns":{"allow":0,"block":0},
    "rxp":{"allow":0,"block":0},
    "rxb":{"allow":0,"block":0},
    "txp":{"allow":0,"block":0},
    "txb":{"allow":0,"block":0}
  }
}}
```

- reset（device-wide / per-app）：

```json
{"id":3,"cmd":"METRICS.RESET","args":{"name":"traffic"}}
{"id":4,"cmd":"METRICS.RESET","args":{"name":"traffic","app":{"uid":10123}}}
```

- 生命周期：since boot（进程内）；`RESET` 清零；`RESETALL` 必须清零（见 4.7）。

#### 4.5.3 实现约束（热路径）

- traffic counters 必须是固定维度的 `atomic++(relaxed)`，不得复用现有 `StatsTPL/AppStats/DomainStats`（其包含 `shift()/localtime_r/mktime` + map 更新，非轻量）。
- v1 建议实现为 **per-app（per-UID）轻量 counters always-on**；device-wide traffic 查询时汇总所有 app 的快照（避免热路径额外全局原子争用）。
  - 若未来需要进一步降低 device-wide traffic 查询成本，可再引入可选的 device-wide sharded counters；但这会让热路径每次更新多一次（或多次）`atomic++`，属于 tradeoff。

### 4.6 Conntrack（L4）轻量 counters：metrics name=`conntrack`（`METRICS.GET`）

目标：暴露 conntrack core 的最小健康计数，用于容量/扫表/溢出等诊断；不做 per-flow/per-entry dump。

- v1 字段固定为：
  - `totalEntries`
  - `creates`
  - `expiredRetires`
  - `overflowDrops`
- gating：仅在 `settings.blockEnabled()==true` 时有意义/更新
- 生命周期：since boot（进程内）；`RESETALL` 必须清零（见 4.7）
- v1 暂不提供独立 reset：`conntrack` 仅 `RESETALL` 清零（`METRICS.RESET(name=conntrack)` 应返回 `INVALID_ARGUMENT`）

建议 JSON shape：

```json
{"id":1,"ok":true,"result":{"conntrack":{
  "totalEntries":0,
  "creates":0,
  "expiredRetires":0,
  "overflowDrops":0
}}}
```

### 4.7 `tracked` 统一语义（两条腿一致）与重型 stats 边界

目标：让 `tracked` 成为跨 DNS/packet 的统一概念：控制“重型统计/逐条事件”的噪音与热路径成本，而不影响判决本身。

#### 4.7.1 `tracked` 的语义（vNext）

- `tracked` **不影响** allow/drop 判决，只影响 observability：
  - stream 逐条事件输出（`type=dns|pkt`）
  - 重型历史 stats（现有 `ALL.* / APP.* / DOMAINS.*` 体系）
- `tracked` **不 gating** 轻量 always-on counters（A/B/C/4.5/4.6）：
  - `METRICS.GET(name=reasons)`、`METRICS.GET(name=domainSources)`、`IPRULES.PRINT stats`、`METRICS.GET(name=traffic)`、`METRICS.GET(name=conntrack)` 等应默认可查
- 默认值：`tracked=false`（便于极限压测与降低默认噪音；需要观测某个 app 时通过 `CONFIG.SET(scope=app,set={tracked:1})` 显式开启）
- `tracked` 持久化（D8）：daemon 重启后保持原值；前端在显式开启 tracked 时必须提示用户“可能带来性能影响”。
- 升级/UX 注意：由于 `tracked` 语义在融合后可能变“更重”，前端必须在 UI 中显式展示当前 tracked 状态（尤其是升级后已存在 `tracked=true` 的 app），避免用户在未确认的情况下长期处于 tracked 状态。

#### 4.7.2 `RESETALL` 与 counters 边界（补充）

`RESETALL` 必须清零：

- `METRICS.GET(name=traffic)`
- `METRICS.GET(name=conntrack)`
- 以及既有：`METRICS.GET(name=reasons)`、`METRICS.GET(name=domainSources)`、`IPRULES` runtime stats、`METRICS.GET(name=perf)`
- 并且必须清理所有“观测状态”：
  - `tracked`：全部重置为 `false`
  - stream：强制 stop 并断开连接；清空 dns/pkt ring buffer/queue，并清理 activity 会话态
  - 若实现中仍存在历史遗留的 stream 落盘文件（例如旧版 `dnsstream` save）：应同步删除，避免回放混入旧 schema 数据

---

## 5. 明确延后/非目标（避免误解）

- 不做全局 safety-mode（dry-run 全系统）。
- 不要求 `block.enabled=0` 时逐包输出 reasonId（engine_off 属于状态解释：`CONFIG.GET(block.enabled)` / `STREAM.START(type=activity)`）。
- legacy `BLOCKIPLEAKS/ip-leak`：本轮已裁决为**冻结并强制关闭（无作用）**；vNext 不提供接口；不做 reasonId/metrics/stream 叙事。
- 不做域名规则 per-rule counters（regex/wildcard/listId）：现状聚合 regex 无法归因，需更大重构，后置。
- 不把 ip-leak 混进域名 policySource counters：若未来另开 change 重新引入/替代 ip-leak，可再以独立维度/命令追加。
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
