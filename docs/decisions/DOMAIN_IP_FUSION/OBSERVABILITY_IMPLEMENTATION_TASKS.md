# 可观测性 vNext：落地任务清单（Domain + IP Fusion）

更新时间：2026-04-17  
状态：任务分解（仅列“要做什么”；不在此处实现代码）

> 本文是把 `OBSERVABILITY_WORKING_DECISIONS.md` 的工作结论提炼为可执行 task list。
> 本文只维护本目录（`docs/decisions/DOMAIN_IP_FUSION/`）内的任务分解；切片与 gate 以 `docs/IMPLEMENTATION_ROADMAP.md` 为准；不在此处推动代码与其它权威规格更新。

## 0. 参考

- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`（总纲；2.8 ACA 性能红线）
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`（可观测性工作结论）

## 0.1 与 Roadmap 的关系（避免分科漂移）

- `docs/IMPLEMENTATION_ROADMAP.md` 负责定义“切片（change）与 P0/P1/P2 gate”；本文件只负责把 **可观测性切片**展开为可执行 task list。
- 本文件覆盖的范围：roadmap `3.2.1` 的 `add-control-vnext-metrics` + `add-control-vnext-stream`（统称 “observability vNext”）。
- 本文件中提到的 **通用 vNext 基础设施**（netstring framing、严格 JSON parse/encode、selector/错误模型/strict reject）应在 `add-control-vnext-codec-ctl` + `add-control-vnext-daemon-base` 完成；本文件只复述其对 stream/metrics 的使用要求，避免重复设计。

## 1. 范围与边界（先锁死）

- **目标**：在不改变 allow/drop 语义的前提下，补齐“默认可查”的轻量 counters + 可调试的 stream vNext（可靠解析 + 可回溯 + 可定位缺失原因）。
- **红线（ACA）**：hot path / `mutexListeners` 锁内只做纯判决 + 固定维度 atomic + 有界 enqueue；stream I/O 必须异步；gate 必须是真 gate。
- **明确非目标**：
  - legacy `BLOCKIPLEAKS/ip-leak`：本轮**冻结并强制关闭（无作用）**；vNext 不提供接口；不做 reasonId/metrics/stream 叙事。
  - 不做域名规则 per-rule counters（regex/wildcard/listId 归因）。
  - 不在后端引入 Prometheus/集中存储；前端自行采样与落库。

## 2. 需要落地的对外产物（接口/shape）

1) **stream vNext（DNSSTREAM/PKTSTREAM）**
   - 事件 envelope：`type="dns"|"pkt"|"notice"`。
   - `type="notice"`：
     - `notice="suppressed"`：tracked 过滤提示（按秒聚合，最多 1 条/秒/streamType）。
     - `notice="dropped"`：反压/队列满导致的丢事件提示（按秒聚合，最多 1 条/秒/streamType；仅实时，不进 ring，不回放，不落盘）。
   - `type="dns"` / `type="pkt"`：字段集合按 working decisions 固定；字段必须是“判决时快照”。

2) **常态 metrics**
   - `METRICS.GET(name=traffic)` / `METRICS.GET(name=traffic, app=...)`（DNS + packet 的轻量 counters；always-on；tracked 不 gating）。
   - `METRICS.GET(name=conntrack)`（conntrack 健康计数；v1 不提供独立 reset 命令，仅 `RESETALL` 清零）。

## 3. 实现任务分解（按依赖顺序）

### 3.1 Traffic：metrics name=`traffic`（always-on，固定维度）

- 对外入口（命令面已统一；见 `CONTROL_COMMANDS_VNEXT.md`）：
  - `METRICS.GET(name=traffic)`
  - `METRICS.GET(name=traffic, app=...)`（`args.app` 为结构化 selector）
  - `METRICS.RESET(name=traffic)`
  - `METRICS.RESET(name=traffic, app=...)`（`args.app` 为结构化 selector）
- 指标口径锁死（v1）：
  - 维度：`dns/rxp/rxb/txp/txb`；每维 `{allow, block}`。
  - `allow/block` 仅看最终 verdict；would-match 不改变 verdict。
  - gating：仅在 `settings.blockEnabled()==true` 时累计（与既有 counters 一致）。
  - device-wide 汇总必须全量（包含 tracked/untracked）。
- 实现约束：
  - 必须是固定维度 `atomic++(relaxed)`；不得复用重型 `StatsTPL/*Stats`（避免时间分桶与 map 更新成本）。
  - 建议：per-app（per-UID） always-on 轻量 counters；device-wide 查询时汇总快照（避免热路径全局争用）。
- 测试/验收（最小集合）：
  - `BLOCK=0` 时不累计；`BLOCK=1` 时累计。
  - per-app（per-UID）与 device-wide 口径一致；reset 清零；RESETALL 清零。
  - selector 语义与歧义拒绝：使用 `CONTROL_PROTOCOL_VNEXT.md` 的结构化 selector（`args.app={"uid":...}` 或 `{"pkg":"...","userId":...}`）；`<pkg>` 仅匹配 canonical；歧义/不存在必须返回结构化错误（`SELECTOR_AMBIGUOUS/SELECTOR_NOT_FOUND + candidates[]`）。

### 3.2 Conntrack：metrics name=`conntrack`（always-on，健康计数）

- 对外入口：`METRICS.GET(name=conntrack)`
- 输出字段固定（v1）：`totalEntries/creates/expiredRetires/overflowDrops`
- gating：仅在 `settings.blockEnabled()==true` 时更新/有意义（与既有 dataplane counters 一致）
- reset 语义：
  - v1 不提供独立 reset：`METRICS.RESET(name=conntrack)` 应返回 `INVALID_ARGUMENT`；`RESETALL` 必须清零。
- 测试/验收：
  - 输出 shape 稳定；RESETALL 后归零。

### 3.3 stream pipeline：异步化 + 真 gate（满足 2.8）

> 这是 stream vNext 的“基础设施任务”，优先级高于 schema 增量。

- 引入异步 writer（或等价机制）：
  - hot path 仅做**有界 enqueue**（不得同步写 socket）。
  - writer 线程负责：序列化（严格 JSON、compact）+ netstring framing/写 socket；处理断连清理。
- 反压策略（必须明确并实现）：
  - 允许 drop（队列满/慢消费者）。
  - **必须可定位**：通过 `type="notice"` 显式提示（不新增独立 metrics）。
    - 最小要求：`type="notice" + notice="dropped" + stream + windowMs + droppedEvents`（其余字段可选）。
  - 口径锁死（2.12-A）：pending queue/ring 满时 drop-oldest；`droppedEvents` 按“被丢弃的逐条事件条数”（不按 bytes）；最多 1 条/秒/streamType，并输出实际 `windowMs`。
  - **有界 cap（2.31-A）**：
    - 必须实现按事件条数的 `maxRingEvents` 与 `maxPendingEvents` 上限（不在本阶段锁具体数值，但必须存在且可验证）。
    - `STREAM.START(type=dns|pkt,horizonSec/minSize)` 必须 clamp 到能力上限，并在 `notice="started"` 中 echo 实际生效值（避免前端误解）。
- 真 gate：
  - `tracked` 是逐条事件 gate：未 tracked 不构造逐条事件对象/不入 ring（无论是否订阅）。
  - 无订阅者时：对 tracked app 仍可维护进程内 ring（用于 `STREAM.START(type=dns|pkt,horizonSec/minSize)` 回放），但不得做 socket I/O。
  - app 未 tracked：不输出逐条事件；若存在订阅则转为 suppressed NOTICE（见 3.4）。
- STOP 语义：
  - `STREAM.STOP`（当前 type 为 `dns|pkt`）必须清空 ring buffer + pending queue（若有）；下次 `STREAM.START` 视为全新 session。
  - `STREAM.STOP`（当前 type 为 `activity`）仅停止输出并清理会话态（不涉及 ring/horizon）。
  - **ack barrier（2.9-B）**：STOP 必须先禁用该连接订阅并清空该连接 pending queue（允许丢弃尾部未发送事件/notice），再输出该 STOP 的 response frame（`{"id":...,"ok":true}`）；该 response 必须是该 STOP 的最后一个输出 frame，ack 后不得再输出任何事件/notice，直到下一次 `STREAM.START`。
- START/STOP（回放参数与状态机；不影响已有流）：
  - request `args`：
    - `type="dns"|"pkt"`：`horizonSec/minSize`（int，默认 `0/0` 不回放历史）
    - `type="activity"`：不支持回放参数（应省略；或要求为 `0/0`）
  - 同一连接重复 `STREAM.START`：返回 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - **连接拓扑（2.27-A）**：同一条 stream 连接同一时间只允许订阅一种 streamType；若该连接已 `STREAM.START(type=dns)`，则在 `STREAM.STOP` 之前该连接上的其它 type 或非 stream 控制命令一律 `STATE_CONFLICT`。需要同时看 dns+pkt+activity 时，前端使用多条连接（每种 streamType 一条）。
  - `STREAM.START` 成功：先返回 response frame（`{"id":...,"ok":true}`），随后必须先输出一次 `type="notice", notice="started"`（至少一条，避免“无流量=无反馈”；不入 ring/不回放/不落盘），再进入回放（若有）与实时事件输出。
  - `STREAM.STOP` 返回 response frame（`{"id":...,"ok":true}`）且幂等（未 started 也返回 `{"id":...,"ok":true}`）。
  - 回放选择规则（v1）：回放集合 = “时间窗内事件” ∪ “最近 `minSize` 条事件”；`horizonSec=0` 时仅按 `minSize` 回放；请求超出 ring 则尽力回放（不报错）。
- 线协议（vNext；可靠解析）：
  - framing 采用 netstring（见 `CONTROL_PROTOCOL_VNEXT.md`）：每条 response/event 都是一个 netstring frame，payload 为 UTF‑8 JSON object；不发送 NUL terminator。
    - 严格 JSON（2.10）：所有字符串字段必须正确 escape（至少处理 `\" \\ \n \r \t`；vNext 必须引入统一 JSON string encoder）。
  - `STREAM.STOP` 的 response frame 作为 ack barrier（见上）；任何失败返回 `{"id":...,"ok":false,"error":{...}}`。
  - 进入 stream 模式后禁止复用连接执行非 stream 控制命令；如需查询/配置另开控制连接。
  - 注：netstring framing + 严格 JSON encoder/decoder 属于 vNext core 共享能力；实现上应在 `add-control-vnext-codec-ctl` + `add-control-vnext-daemon-base` 落地并复用，避免 observability 切片自建一套 writer/encoder 口径。
- 并发/锁：
  - `mutexListeners` 锁内不得做 I/O；不得做大 JSON 构造；不得做无界分配。
  - `RESETALL`（独占锁）不得被 writer/队列阻塞。
- 验收：
  - 开 stream 与不开 stream 的 NFQUEUE 延迟差异在可控范围（以 perfmetrics 基线对比）。
  - 慢消费者不会拖死 hot path；断连可回收；RESETALL 不被饿死。

### 3.4 stream vNext schema：`type` + suppressed NOTICE + 快照字段

- `DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM` 事件增加顶层 `type` 字段。
- `type="notice"`：实现 `notice="suppressed"`（按秒聚合，最多 1 条/秒/streamType）。
  - NOTICE 只实时；不进 ring；不参与 horizon；不落盘。
  - NOTICE 内容尽量复用 `METRICS.GET(name=traffic)` 的结构；不输出 uid 列表；提示用 `CONFIG.SET(scope=app,set={tracked:1})` 或 `METRICS.GET(name=traffic, app=...)` 定位。
- `type="notice"`：实现 `notice="dropped"`（反压丢事件提示；按秒聚合，最多 1 条/秒/streamType）。
  - 最小字段集合：`type/notice/stream/windowMs/droppedEvents`（其余可选）。
  - NOTICE 只实时；不进 ring；不参与 horizon；不落盘。
- `type="dns"`：补齐并固定最小字段集合：
  - `policySource/useCustomList/scope/getips/domMask/appMask`（判决时快照）
- `type="pkt"`：补齐并固定最小字段集合：
  - `accepted/reasonId/ruleId?/wouldRuleId?/wouldDrop?` + 五元组基础字段
    - 布尔语义字段（已确认；2.24‑A）：`accepted/wouldDrop` 使用 JSON boolean；optional 字段缺失时省略该 key（不输出 `"n/a"`）。
  - 可选可读性字段：`domain?`（bridge）与 `host?`（reverse‑dns）；不得作为唯一标识/仲裁依据；不得为了填充该字段把 DomainPolicy 判决拉回 packet 热路径
    - `domain` 仅当 `domain.validIP()==true` 时输出；`validIP` 判定建议在 writer/序列化线程执行，避免 hot path 每包 `time()`。
  - `ct{state,direction}` 仅在实际参与 `ct.*` 匹配时输出（避免误导）
- `type="activity"`：补齐并固定最小字段集合：
  - `blockEnabled`（boolean）
  - 可选：`uid/userId/app`（例如 top app；回显风格与其它事件一致）
- horizon/ring 策略：
  - 逐条事件：仅进程内 ring（仅对 tracked app 维护；与订阅无关，用于 `STREAM.START(type=dns|pkt,horizonSec/minSize)` 回放）；默认 horizon=0。
  - 不做 save/restore；升级允许丢弃历史缓存文件。
- reset：
  - `RESETALL` 强制 stop 并断开 stream 连接（按 2.8-A：stream 订阅单连接约束；control 连接可并发），清空 dns/pkt ring/queue，并清理 activity 会话态；并删除历史遗留落盘 stream 文件（若仍存在）。
- 验收：
  - 前端可稳定按 `type` 解析；字段齐全且自解释；suppressed 可定位。

### 3.5 `tracked` 统一语义（两条腿一致）

- 锁死语义：
  - `tracked` 不影响判决；只影响逐条事件（含 ring capture）+ heavy stats。
  - `tracked` 不 gating 轻量 counters（`METRICS.GET(name=reasons|domainSources|traffic|conntrack)` 等）。
  - 默认 `tracked=false`；**持久化**（D8）；前端显式开启 tracked 时必须提示“可能带来性能影响”。
- 验收：
  - 开 stream 时：tracked=false 的 app 不出逐条事件，但会触发 suppressed NOTICE；同时 `METRICS.GET(name=traffic)` 仍增长。

## 4. 文档与规格更新（实现阶段执行；此处只列任务）

- 更新权威接口/spec（按“单一真相”原则）：
  - `openspec/specs/pktstream-observability/spec.md`：stream vNext schema（`type`/notice）+ 解释口径。
  - 为 metrics name=`traffic` / `conntrack` 新增独立 spec（入口统一为 `METRICS.GET`/`METRICS.RESET`；避免把 stream 与 counters 绑死在同一 spec）。
  - `docs/INTERFACE_SPECIFICATION.md`：补齐命令名与 JSON shape（包含 selector 多用户语义）。
- 更新实现路线图与 change 切片描述：`docs/IMPLEMENTATION_ROADMAP.md`（仅在进入实现阶段时同步）。

## 5. 推荐实现顺序（observability vNext：`add-control-vnext-metrics` → `add-control-vnext-stream`）

1) Traffic metrics（metrics name=`traffic`；`METRICS.GET`/`METRICS.RESET`）
2) Conntrack metrics（metrics name=`conntrack`；`METRICS.GET`；仅 `RESETALL` 清零）
3) stream pipeline 异步化 + 真 gate + drop 定位（先基础设施）
4) stream vNext schema（`type` + suppressed NOTICE + 快照字段 + horizon/ring/reset）
5) 文档/spec 同步（openspec + interface spec + roadmap）
