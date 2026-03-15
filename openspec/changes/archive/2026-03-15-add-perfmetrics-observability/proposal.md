# Change: D 层性能健康指标（NFQ / DNS service time）

## Why
我们需要一组**常态型**、可在真机上长期运行的性能健康指标，用来：
- 在不依赖前端持续订阅 stream 的情况下，给出“热路径处理速度”的 baseline；
- 支撑后续 IP rules / DNS policy 的性能回归对比；
- 避免用 `ping RTT` 这类端到端指标替代 userspace service time（RTT 会混入网络与对端因素，无法定位 NFQ/DNS 判决自身的成本）。

当前最关键、且对用户体验最直接的两条路径是：
- NFQUEUE 单包从进入 userspace 到 verdict 回写的处理时长；
- 单次 DNS 判决请求从“请求解析完成”到“verdict/getips 写回”的处理时长。

## What Changes
- 新增 D 层 performance health metrics（常态 metrics，可运行时开关）：
  - `nfq_total_us`：单个 NFQ 包的 userspace 总处理时间（`PacketListener::callback()` entry → `sendVerdict()` return）。
  - `dns_decision_us`：单次 DNS 判决处理时间（`len/domain/uid` 已读完且 `App/Domain` 已构造完成 → `verdict/getips` 写回完成）。
- 新增控制面命令（不区分 debug/release 语义）：
  - `PERFMETRICS [<0|1>]`：查询/设置是否采集 D 层指标（`0→1` 自动清零；仅接受 `0|1`，非法参数返回 `NOK`）。
  - `METRICS.PERF`：拉取 `{"perf":{...}}` 的聚合结果（固定 JSON shape；与现有 `METRICS.*` 风格一致）。
  - `METRICS.PERF.RESET`：清零上述聚合结果（不改变 enable 状态）。
- 聚合方式：固定维度的直方图/分桶 + 原子计数，不保留逐样本历史、不开 per-packet 日志/JSON。

## Relationship to existing changes
- D 层与 A/B/C 语义独立：不复用 `reasonId` / `policySource` / per-rule stats。
- D 层不参与 `A → IPRULES v1（含 C） → B` 的功能主线排序；可作为独立 change 随时推进。

## Non-Goals
- 不提供 `ping RTT` 作为 `nfq_total_us` 的替代口径。
- 不新增新的 stream、存储系统或每包日志输出。
- 不把 DNS 后续 IP 上传阶段纳入 `dns_decision_us`（避免混入对端上传节奏）。

## Impact
- Affected code（实现阶段）：`src/PacketListener.cpp`, `src/DnsListener.cpp`, `src/Control.cpp`, `src/Control.hpp`
- Affected docs（实现阶段）：`docs/INTERFACE_SPECIFICATION.md`
- Affected perf tooling（实现阶段）：`tests/integration/perf-network-load.sh`
