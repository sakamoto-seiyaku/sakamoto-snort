# Design: D layer perf health metrics

## Goals
- 常态运行可用：不依赖 debug-only instrumentation。
- 可控：运行时开关，默认关闭；开关对热路径影响最小。
- 口径固定：`nfq_total_us` / `dns_decision_us` 的开始/结束点明确且稳定。
- 输出稳定：固定 JSON shape 与字段集合；支持回归对比。

## Control surface
- `PERFMETRICS [<0|1>]`
  - 无参数：返回 `0|1`
  - `0→1`：自动清零（`since_reset_or_enable`）
- `METRICS.PERF`
  - 返回两个指标的聚合对象（单位 `us`）：`nfq_total_us` 与 `dns_decision_us`
- `METRICS.PERF.RESET`
  - 清零聚合数据，不改变 enable 状态

## Metric boundaries
- `nfq_total_us`
  - start：`PacketListener::callback()` 入口
  - end：`sendVerdict()` 返回之后
- `dns_decision_us`
  - start：DNS 请求体（`len/domain/uid`）已读完，且 `App/Domain` 已构造完成之后
  - end：`verdict/getips` 写回完成之后
  - **不**包含后续 IP 上传阶段

## Aggregation
- 不保存逐样本历史，不做 per-packet 日志/JSON。
- 采用固定分桶直方图 + 原子计数：
  - 热路径：`PERFMETRICS=0` 时仅一次极轻量 gating branch；`PERFMETRICS=1` 时做 `now()` + 单次分桶计数。
  - 读取侧（`METRICS.PERF`）：合并快照并计算 `avg/p50/p95/p99`。
- `avg` 采用 `sum / samples`（整数微秒）。
- `pXX` 使用 nearest-rank 定义，从直方图近似得到（bucket upper bound）。

## Reset semantics
- `PERFMETRICS 0→1`：自动清零。
- `METRICS.PERF.RESET`：显式清零。
- `RESETALL`：清零并恢复默认关闭状态。

## Output shape (fixed)
`METRICS.PERF` 返回：
```json
{
  "nfq_total_us": {"samples":0,"min":0,"avg":0,"p50":0,"p95":0,"p99":0,"max":0},
  "dns_decision_us": {"samples":0,"min":0,"avg":0,"p50":0,"p95":0,"p99":0,"max":0}
}
```

当 `samples=0` 时，其他字段均为 `0`。
