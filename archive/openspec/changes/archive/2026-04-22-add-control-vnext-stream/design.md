## Context

当前 daemon 已具备 vNext 控制面基础设施（netstring framing + strict JSON + envelope invariants）以及 domain/iprules/metrics surfaces，但缺少 vNext-compatible 的 streaming surface。现有 legacy streams（DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM）基于 `Streamable<T>` 同步写 socket，存在慢消费者反压导致 hot path 阻塞的风险，也难以满足 vNext 的可靠解析要求（strict JSON、事件与 response 的 envelope 区分、STOP ack barrier、notice 语义、以及 replay/horizon 规则）。

本变更实现 `STREAM.START/STOP` 以及 vNext stream pipeline（bounded ring + bounded pending queue + async flush + drop/suppress notice），并与 `tracked` 统一语义/RESETALL 生命周期对齐。

约束与单一真相：
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`：状态机与 `STATE_CONFLICT`、STOP ack barrier
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`：`STREAM.*` 命令入口
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`：schema、notice、ring/horizon、cap、tracked 语义
- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`：RESETALL/默认 tracked 等生命周期边界

## Goals / Non-Goals

**Goals:**
- 在 vNext 控制连接上实现 `STREAM.START/STOP`，并输出 netstring-framed 的 strict JSON events（event 不含 `id/ok`，顶层 `type` 区分）。
- 实现满足 ACA 红线的 stream pipeline：hot path 仅做有界 enqueue/atomic；socket I/O 与 JSON 序列化在异步 writer（或等价机制）中完成；慢消费者允许 drop-oldest，并通过 `type="notice"` 可定位。
- 支持 v1 replay 规则（`horizonSec/minSize` 取并集、尽力回放）、以及 `notice="started"`/`suppressed`/`dropped` 语义（限频 ≤1/秒/streamType）。
- 与 `tracked` 统一语义对齐：默认 `tracked=false`；tracked 仅 gate 逐条事件与重型 stats；轻量 counters 不依赖 tracked。
- RESETALL 语义锁死：强制断开所有 stream 连接、清空 ring/pending、并回到干净基线（tracked=false）。

**Non-Goals:**
- 不做 stream 事件落盘 save/restore（进程内 ring-only；重启自然清空）。
- 不保证 “完整不丢” 的事件交付；慢消费者允许丢弃并通过 notice 提示。
- 不实现多订阅者（v1 锁死：每 streamType 同一时间只允许 1 条连接订阅）。
- 不新增权限模型/鉴权（沿用 vNext v1 现状）。

## Decisions

1) **全局 Stream Manager（每 streamType 单订阅者）**
   - 引入全局 `ControlVNextStreamManager`，按 `stream="dns"|"pkt"|"activity"` 维护：
     - subscription（当前订阅连接/会话态）
     - pending queue（待发送事件，cap=`maxPendingEvents`，drop-oldest）
     - ring buffer（仅 dns/pkt；cap=`maxRingEvents`；仅 tracked app 维护，用于 replay）
     - 聚合计数（suppressed/dropped，用于 notice，限频 ≤1/秒/streamType）
   - 保证：同一时间每种 stream 只允许 1 条连接订阅；冲突返回 `STATE_CONFLICT`。

2) **事件构造与 `tracked` 真 gate**
   - dns/pkt 逐条事件只对 `tracked==true` 的 app 构造并进入 ring（与是否订阅无关）；未 tracked 时不构造逐条事件、不入 ring。
   - 当 stream 已订阅且遇到未 tracked 的流量时，仅更新 suppressed 聚合计数（固定维度 atomic），由 writer 输出 `notice="suppressed"`（不输出 uid 列表）。

3) **Writer：严格 JSON + netstring framing + bounded flush**
   - 事件与 notice 使用 RapidJSON 构造，复用 `ControlVNext::encodeJson`（compact）与 `encodeNetstring`。
   - writer 只在控制线程/专用 writer 中写 socket；dataplane/hot path 不做 socket I/O。
   - 发送顺序：
     - `STREAM.START`：先 response，再第一条 event 必为 `type="notice", notice="started"`（echo clamp 后的实际 `horizonSec/minSize`），然后 replay→realtime。
     - `STREAM.STOP`：先禁用订阅并清空 pending（允许丢弃尾部），再输出 STOP response frame；该 response 为 ack barrier（ack 后不得再输出任何 event/notice，直到下一次 START）。

4) **会话状态机：stream mode 禁止非 stream 命令**
   - `ControlVNextSession` 进入 stream mode 后，除 `STREAM.START/STOP` 外的任何控制命令统一返回 `STATE_CONFLICT`，避免 event/response 交织导致解析不可靠。

5) **RESETALL 集成**
   - `RESETALL` 调用 stream manager 的 `resetAll()`：
     - 强制 stop 并断开所有 stream 连接（best-effort）
     - 清空 dns/pkt ring 与所有 pending/notice 窗口状态
     - 删除历史遗留的落盘 stream 文件（若存在）
   - 同时将 `tracked` 默认改为 false（全新启动/RESETALL 后）。

## Risks / Trade-offs

- [慢消费者导致 writer 堵塞] → 采用 bounded pending queue + drop-oldest；必要时断开连接；并通过 `notice="dropped"` 可定位。
- [实现复杂度上升（会话进入 stream mode）] → 明确 `STATE_CONFLICT` 规则；要求前端用多连接分别订阅 dns/pkt/activity。
- [tracked 默认变更可能影响既有调试习惯] → 通过 `notice="suppressed"` + `hint` 指引用户开启 tracked，且 tracked 仍可持久化（显式开启后保持）。
