# 可观测性 vNext：落地任务清单（Domain + IP Fusion）

更新时间：2026-04-14  
状态：任务分解（仅列“要做什么”；不在此处实现代码）

> 本文是把 `OBSERVABILITY_WORKING_DECISIONS.md` 的工作结论提炼为可执行 task list。
> 讨论阶段只维护本目录（`docs/decisions/DOMAIN_IP_FUSION/`）内文档，不外溢到代码与其他权威文档。

## 0. 参考

- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`（总纲；2.8 ACA 性能红线）
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`（可观测性工作结论）

## 1. 范围与边界（先锁死）

- **目标**：在不改变 allow/drop 语义的前提下，补齐“默认可查”的轻量 counters + 可调试的 stream vNext（可靠解析 + 可回溯 + 可定位缺失原因）。
- **红线（ACA）**：hot path / `mutexListeners` 锁内只做纯判决 + 固定维度 atomic + 有界 enqueue；stream I/O 必须异步；gate 必须是真 gate。
- **明确非目标**：
  - 不在本轮收敛 legacy `BLOCKIPLEAKS/ip-leak`（冻结、默认关闭）。
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
   - `METRICS.TRAFFIC` / `METRICS.TRAFFIC.APP ...`（DNS + packet 的轻量 counters；always-on；tracked 不 gating）。
   - `METRICS.CONNTRACK`（conntrack 健康计数；v1 不提供独立 reset 命令，仅 `RESETALL` 清零）。

## 3. 实现任务分解（按依赖顺序）

### 3.1 `METRICS.TRAFFIC*`（always-on，固定维度）

- 新增控制面命令：
  - `METRICS.TRAFFIC`
  - `METRICS.TRAFFIC.APP <uid|pkg> [USER <userId>]`
  - `METRICS.TRAFFIC.RESET`
  - `METRICS.TRAFFIC.RESET.APP <uid|pkg> [USER <userId>]`
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
  - selector 语法与歧义拒绝（见 checklist 2.5）：禁止 `<pkg> <userId>`；未指定 USER 且跨 userId 同名包 → 拒绝；`<pkg>` 可匹配 `allNames` 且歧义 → 拒绝并提示 `<uid>`。

### 3.2 `METRICS.CONNTRACK`（always-on，健康计数）

- 新增控制面命令：`METRICS.CONNTRACK`
- 输出字段固定（v1）：`totalEntries/creates/expiredRetires/overflowDrops`
- gating：仅在 `settings.blockEnabled()==true` 时更新/有意义（与既有 dataplane counters 一致）
- reset 语义：
  - v1 不提供 `METRICS.CONNTRACK.RESET`；`RESETALL` 必须清零。
- 测试/验收：
  - 输出 shape 稳定；RESETALL 后归零。

### 3.3 stream pipeline：异步化 + 真 gate（满足 2.8）

> 这是 stream vNext 的“基础设施任务”，优先级高于 schema 增量。

- 引入异步 writer（或等价机制）：
  - hot path 仅做**有界 enqueue**（不得同步写 socket）。
  - writer 线程负责：序列化/pretty-format/写 socket；处理断连清理。
- 反压策略（必须明确并实现）：
  - 允许 drop（队列满/慢消费者）。
  - **必须可定位**：通过 `type="notice"` 显式提示（不新增独立 metrics）。
    - 最小要求：`type="notice" + notice="dropped" + stream + windowMs + droppedEvents`（其余字段可选）。
- 真 gate：
  - stream 未开启时：不构造逐条事件对象、不维护 ring buffer。
  - app 未 tracked：不输出逐条事件；转为 suppressed NOTICE（见 3.4）。
- STOP 语义：
  - `DNSSTREAM.STOP` / `PKTSTREAM.STOP` 必须清空 ring buffer + pending queue（若有）；下次 `START` 视为全新 session。
- START/STOP（回放参数与状态机；不影响已有流）：
  - 语法：`*.START [<horizonSec> [<minSize>]]`；默认 `0/0`（不回放历史）。
  - 同一连接重复 `*.START`：返回 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - `*.START` 成功不返回 `OK`；`*.STOP` 返回 `OK` 且幂等（未 started 也返回 `OK`）。
  - 回放选择规则（v1）：回放集合 = “时间窗内事件” ∪ “最近 `minSize` 条事件”；`horizonSec=0` 时仅按 `minSize` 回放；请求超出 ring 则尽力回放（不报错）。
- 线协议（NDJSON；可靠解析）：
  - 输出采用 NDJSON：一行一个 JSON 对象，以 LF（`\n`）分隔；事件 JSON 不得包含换行；不再发送 NUL terminator。
  - `pretty` 禁止；若客户端请求 pretty（命令 `!` 后缀）必须报错并拒绝开启 stream。
  - `*.STOP` 返回 JSON ack：`{"ok": true}`；任何失败以 `{"error": {...}}` 返回（与错误模型一致）。
  - 进入 stream 模式后禁止复用连接执行非 stream 控制命令；如需查询/配置另开控制连接。
- 并发/锁：
  - `mutexListeners` 锁内不得做 I/O；不得做大 JSON 构造；不得做无界分配。
  - `RESETALL`（独占锁）不得被 writer/队列阻塞。
- 验收：
  - 开 stream 与不开 stream 的 NFQUEUE 延迟差异在可控范围（以 perfmetrics 基线对比）。
  - 慢消费者不会拖死 hot path；断连可回收；RESETALL 不被饿死。

### 3.4 stream vNext schema：`type` + suppressed NOTICE + 快照字段

- `DNSSTREAM/PKTSTREAM` 事件增加顶层 `type` 字段。
- `type="notice"`：实现 `notice="suppressed"`（按秒聚合，最多 1 条/秒/streamType）。
  - NOTICE 只实时；不进 ring；不参与 horizon；不落盘。
  - NOTICE 内容尽量复用 `METRICS.TRAFFIC` 的结构；不输出 uid 列表；提示用 `TRACK`/`METRICS.TRAFFIC*` 定位。
- `type="notice"`：实现 `notice="dropped"`（反压丢事件提示；按秒聚合，最多 1 条/秒/streamType）。
  - 最小字段集合：`type/notice/stream/windowMs/droppedEvents`（其余可选）。
  - NOTICE 只实时；不进 ring；不参与 horizon；不落盘。
- `type="dns"`：补齐并固定最小字段集合：
  - `policySource/useCustomList/scope/getips/domMask/appMask`（判决时快照）
- `type="pkt"`：补齐并固定最小字段集合：
  - `accepted/reasonId/ruleId?/wouldRuleId?/wouldDrop?` + 五元组基础字段
  - `ct{state,direction}` 仅在实际参与 `ct.*` 匹配时输出（避免误导）
- horizon/ring 策略：
  - 逐条事件：仅进程内 ring（仅在 stream 开启期间维护）；默认 horizon=0。
  - 不做 save/restore；升级允许丢弃历史缓存文件。
- reset：
  - `RESETALL` 强制 stop 并断开 stream 连接（控制端 1:1），清空 dns/pkt ring/queue；并删除历史遗留落盘 stream 文件（若仍存在）。
- 验收：
  - 前端可稳定按 `type` 解析；字段齐全且自解释；suppressed 可定位。

### 3.5 `tracked` 统一语义（两条腿一致）

- 锁死语义：
  - `tracked` 不影响判决；只影响逐条事件 + heavy stats。
  - `tracked` 不 gating 轻量 counters（`METRICS.REASONS/DOMAIN.SOURCES*/TRAFFIC*/CONNTRACK` 等）。
  - 默认 `tracked=false`；不持久化；daemon 重启后全部回到 false。
- 验收：
  - 开 stream 时：tracked=false 的 app 不出逐条事件，但会触发 suppressed NOTICE；同时 `METRICS.TRAFFIC` 仍增长。

## 4. 文档与规格更新（实现阶段执行；此处只列任务）

- 更新权威接口/spec（按“单一真相”原则）：
  - `openspec/specs/pktstream-observability/spec.md`：stream vNext schema（`type`/notice）+ 解释口径。
  - 为 `METRICS.TRAFFIC*` / `METRICS.CONNTRACK` 新增独立 spec（避免把 stream 与 counters 绑死在同一 spec；建议新 spec 覆盖 traffic + conntrack counters）。
  - `docs/INTERFACE_SPECIFICATION.md`：补齐命令名与 JSON shape（包含 selector 多用户语义）。
- 更新实现路线图与 change 切片描述：`docs/IMPLEMENTATION_ROADMAP.md`（仅在进入实现阶段时同步）。

## 5. 推荐 change 切片顺序（实现阶段参考）

1) `METRICS.TRAFFIC*`（always-on counters + reset 语义）
2) `METRICS.CONNTRACK`
3) stream pipeline 异步化 + 真 gate + drop 定位（先基础设施）
4) stream vNext schema（`type` + suppressed NOTICE + 快照字段 + horizon/ring/reset）
5) 文档/spec 同步（openspec + interface spec + roadmap）
