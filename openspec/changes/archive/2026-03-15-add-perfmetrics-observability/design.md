# Design: D layer perf health metrics

## Goals
- 常态运行可用：不依赖 debug-only instrumentation。
- 可控：运行时开关，默认关闭；开关对热路径影响最小。
- 口径固定：`nfq_total_us` / `dns_decision_us` 的开始/结束点明确且稳定。
- 输出稳定：固定 JSON shape 与字段集合；支持回归对比。

## Hot-path constraints
- `PERFMETRICS=0`：热路径 MUST 只做一次极轻量 gating branch；MUST 不做 `now()`、不更新任何聚合状态。
- `PERFMETRICS=1`：热路径只允许 `now()` + O(1) 更新（分片 `samples/sum/min/max` + 单次分桶计数），不得新增锁/IO/动态分配/日志。
- 时钟：耗时测量使用单调递增时钟（不受系统时间调整影响），并以整数微秒（向下取整）输出。

### Cost expectations (what overhead we are introducing)
启用后（`PERFMETRICS=1`）这套指标必然会在每包引入额外成本，主要来源是：
- **2 次单调时钟读取**（entry/exit 各一次，用于计算 delta）。
- **O(1) 聚合更新**（`samples/sum/min/max` + 1 次 bucket `count++`）。

这类成本在“高 pps”场景会线性放大：即使单包只多几十到几百 ns，百万 pps 也可能吃掉明显 CPU。设计目标不是“零成本”，而是：
- `PERFMETRICS=0` 时几乎不变（只有一次分支）。
- `PERFMETRICS=1` 时把开销压到 **无锁、无 IO、无分配、无日志** 的 O(1) 常数级更新，且用分片减少争用。

## Control surface
- `PERFMETRICS [<0|1>]`
  - 无参数：返回 `0|1`
  - `0→1`：自动清零（`since_reset_or_enable`）
  - 仅接受 `0|1`；其他参数返回 `NOK`
  - `1→1` / `0→0` 为幂等设置：不触发清零
- `METRICS.PERF`
  - 返回顶层对象 `{"perf": {...}}`（单位 `us`），其中 `perf` 固定包含两个指标：`nfq_total_us` 与 `dns_decision_us`
  - 当 `PERFMETRICS=0` 时，返回值为全 `0`（`samples=0`，其余字段均为 `0`）
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
  - 热路径：`PERFMETRICS=0` 时仅一次极轻量 gating branch；`PERFMETRICS=1` 时做 `now()` + 更新分片聚合（`samples/sum/min/max` + 单次分桶计数）。
  - 读取侧（`METRICS.PERF`）：合并快照并计算 `avg/p50/p95/p99`。
- 分片建议：
  - NFQ 路径优先使用 per-thread / per-queue 分片聚合，snapshot 时再 merge，避免全局争用。
  - DNS 路径可采用更简单的聚合实现，但仍不得在热路径引入阻塞点。
- `avg` 采用 `sum / samples`（整数微秒）。
- `pXX` 使用 nearest-rank 定义，从直方图近似得到（bucket upper bound）。

## Buckets (why + what to fix before implementation)
我们需要 `p50/p95/p99`，但不能保存逐样本历史（热路径与内存都不允许），因此必须用 histogram/分桶近似：
- 每个样本会被映射到某个 bucket（一个 `us` 区间），并对该 bucket 做 `count++`。
- `METRICS.PERF` 读取时按 bucket 计数累加到目标 rank（nearest-rank），返回“首次达到该 rank 的 bucket upper bound”作为 `pXX`。

**Bucket 边界一旦改变，`pXX` 的近似值就会改变**（即使真实样本分布相同），因此 bucket 的边界/生成规则必须在实现前固定下来，才能保证跨版本可比。

### Bucket v1 (conservative): log2 buckets with fixed sub-buckets
目标：热路径 O(1) 映射、无循环/无二分查找；读侧 scan bucket 的成本可接受。

为尽量避免实现后再调参导致 `pXX` 漂移，我们先把 v1 bucket 规则**固定**为：
- 子桶数：`S = 8`
- 覆盖范围（上界）：`MAX_US = 2^24 - 1`（≈ 16.7s）
- 溢出策略：`us >= 2^24` 的样本全部 **clamp 到最后一个 bucket**（其 upper bound 仍为 `MAX_US`）

说明：
- 上述 clamp **只影响** `p50/p95/p99`（它们返回 bucket upper bound，因此自然不会超过 `MAX_US`）。
- `min/avg/max` 仍应基于**真实样本值**维护与计算；即使某个样本 `us >= 2^24`，也应更新真实的 `max` 与 `sum`（不要把样本值截断到 `MAX_US`）。

映射规则（输入 `us` 为非负整数微秒）：
- `us <= 7`：bucket upper bound `ub = us`（0..7 精确）
- `us >= 8`：
  - `k = min(floor(log2(us)), 23)`（因此 `base = 2^k` 最大为 `2^23`）
  - `base = 2^k`
  - `width = base / S = 2^(k-3)`（`k>=3`，因此 `width` 为整数且是 2 的幂）
  - `sub = min(S-1, floor((us - base) / width))`
  - bucket upper bound（**整数、包含该桶内最大可能样本**）：
    `ub = base + (sub + 1) * width - 1`

位运算形式（便于实现 O(1) 且避免除法）：
- `shift = k - 3`
- `sub = min(7, (us - (1<<k)) >> shift)`
- `ub = (1<<k) + ((sub + 1) << shift) - 1`

这样 `pXX` 的分辨率大约是“每个 2 倍区间内的 1/S”（例如 `S=8` ≈ 12.5%）；并且由于我们返回的是 bucket upper bound，`pXX` 会是一个**保守上界**，误差上限约为 `width - 1`（单位 `us`）。

一个直观例子（`S=8`）：
- `us=8..15` 会落到 upper bound `8..15`（此时 `width=1`，几乎无量化误差）
- `us=16..31` 的 upper bound 依次为：`17,19,21,23,25,27,29,31`（`width=2`）
- `us=32..63` 的 upper bound 依次为：`35,39,43,47,51,55,59,63`（`width=4`）

v1 的 bucket 规则在本 change 中固定为上述参数；若未来需要调整 bucket（影响 `pXX` 近似），必须通过新的 change 显式变更（或引入版本字段），避免 silent drift。

## Reset semantics
- `PERFMETRICS 0→1`：自动清零。
- `METRICS.PERF.RESET`：显式清零。
- `RESETALL`：清零并恢复默认关闭状态。

## Output shape (fixed)
`METRICS.PERF` 返回：
```json
{
  "perf": {
    "nfq_total_us": {"samples":0,"min":0,"avg":0,"p50":0,"p95":0,"p99":0,"max":0},
    "dns_decision_us": {"samples":0,"min":0,"avg":0,"p50":0,"p95":0,"p99":0,"max":0}
  }
}
```

当 `samples=0` 时，其他字段均为 `0`。
