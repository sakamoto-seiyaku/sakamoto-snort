## ADDED Requirements

### Requirement: D layer perf metrics are runtime-toggleable
系统 MUST 通过控制面暴露以下命令：
- `PERFMETRICS [<0|1>]`
- `METRICS.PERF`
- `METRICS.PERF.RESET`

`PERFMETRICS` MUST 在无参数时返回 `0|1`。

`PERFMETRICS <0|1>` MUST 在成功设置时返回 `OK`，且 MUST 仅接受 `0` 或 `1`：
- `PERFMETRICS 0` / `PERFMETRICS 1` → `OK`
- 其他参数（含整数 `2`、字符串 `foo` 等） → `NOK`

`PERFMETRICS` 的设置语义 MUST 为幂等：
- `PERFMETRICS 0→1` MUST 自动清零聚合数据
- `PERFMETRICS 1→1` / `PERFMETRICS 0→0` MUST NOT 触发清零

`PERFMETRICS` 的默认值 MUST 为 `0`（进程启动后默认关闭；不要求持久化）。

#### Scenario: PERFMETRICS can be toggled
- **WHEN** 客户端调用 `PERFMETRICS`
- **THEN** 返回值 SHALL 为 `0` 或 `1`
- **WHEN** 客户端调用 `PERFMETRICS 1`
- **THEN** 返回值 SHALL 为 `OK`

#### Scenario: PERFMETRICS rejects invalid values
- **WHEN** 客户端调用 `PERFMETRICS 2`
- **THEN** 返回值 SHALL 为 `NOK`

### Requirement: METRICS.PERF returns fixed JSON shape in microseconds
系统 MUST 在 `METRICS.PERF` 返回一个顶层对象，固定包含 key `perf`。

`perf` 的 value MUST 为对象，且 MUST 固定包含两个 key：
- `nfq_total_us`
- `dns_decision_us`

每个 key 的 value MUST 为对象，且 MUST 固定包含字段（单位 `us`）：
`samples/min/avg/p50/p95/p99/max`（全部为非负整数；`samples` 为 uint64）。

当 `samples=0` 时，其他字段 MUST 为 `0`。

当 `PERFMETRICS=0` 时，`METRICS.PERF` MUST 对两个指标均返回全 `0`（即 `samples=0`，其余字段也为 `0`）。

时钟与取整：
- `nfq_total_us` / `dns_decision_us` 的耗时 MUST 使用单调递增时钟测量（不受系统时间调整影响）。
- `us` 值 MUST 以整数微秒返回（向下取整）。

字段定义（对 `samples>0` 的情况）：
- `min/max`：最小/最大样本值（单位 `us`）。
- `avg`：算术平均值，定义为 `floor(sum(values) / samples)`（单位 `us`，整数微秒；其中 `values` 为所有样本值）。
- `p50/p95/p99`：按 nearest-rank 百分位数定义（常规定义）：
  - 令 `N = samples`，把所有样本值按非降序排序为 `x[1..N]`
  - `pXX = x[ ceil(XX/100 * N) ]`

当实现采用 histogram/分桶近似时，系统 MUST 以 nearest-rank 的 rank 为目标，返回“使累计计数首次达到该 rank 的最小 bucket upper bound”作为 `pXX`。

当实现采用固定范围的 buckets 并对 bucket 映射做 clamp 时：
- `p50/p95/p99` 的返回值 MAY 因为 buckets 的范围上界而被 clamp（因为它本质上返回 bucket upper bound）。
- `min/avg/max` MUST 始终基于**真实样本值**计算；MUST NOT 用 bucket upper bound 代替真实样本值，也 MUST NOT 因为 percentile 的 clamp 而截断真实样本值。

#### Scenario: METRICS.PERF returns required keys
- **WHEN** 客户端调用 `METRICS.PERF`
- **THEN** 返回值 SHALL 为有效 JSON
- **AND** 返回值 SHALL 包含 key `perf`
- **AND** `perf` 对象 SHALL 包含 key `nfq_total_us`
- **AND** `perf` 对象 SHALL 包含 key `dns_decision_us`

#### Scenario: METRICS.PERF returns all zeros when PERFMETRICS=0
- **GIVEN** `PERFMETRICS=0`
- **WHEN** 客户端调用 `METRICS.PERF`
- **THEN** `perf.nfq_total_us.samples` SHALL 为 `0`
- **AND** `perf.dns_decision_us.samples` SHALL 为 `0`

#### Scenario: PERFMETRICS=0 does not collect samples under traffic
- **GIVEN** `PERFMETRICS=0`
- **WHEN** 设备产生可进入 NFQUEUE 的网络包流量
- **THEN** 后续调用 `METRICS.PERF` 时 `perf.nfq_total_us.samples` SHALL 为 `0`

### Requirement: nfq_total_us measures PacketListener callback service time
系统 MUST 按固定边界采集 `nfq_total_us`：
- start：`PacketListener::callback()` 入口
- end：`sendVerdict()` 返回之后

当 `PERFMETRICS=1` 时，系统 MUST 对每个进入 `PacketListener::callback()` 的包采集 1 个 `nfq_total_us` 样本（与 `BLOCK` 当前值无关）。

#### Scenario: nfq_total_us samples increase under traffic
- **GIVEN** `PERFMETRICS=1`
- **WHEN** 设备产生可进入 NFQUEUE 的网络包流量
- **THEN** 后续调用 `METRICS.PERF` 时 `perf.nfq_total_us.samples` SHALL 大于等于 1

### Requirement: dns_decision_us measures decision+reply time only
系统 MUST 按固定边界采集 `dns_decision_us`：
- start：DNS 请求体（`len/domain/uid`）已读完且 `App/Domain` 已构造完成之后
- end：`verdict/getips` 写回完成之后

系统 SHALL NOT 将后续 IP 上传阶段纳入 `dns_decision_us`。

#### Scenario: dns_decision_us samples increase under DNS requests
- **GIVEN** `PERFMETRICS=1`
- **WHEN** 客户端触发至少 1 次 DNS 判决请求
- **THEN** 后续调用 `METRICS.PERF` 时 `perf.dns_decision_us.samples` SHALL 大于等于 1

### Requirement: Reset semantics are stable
- `PERFMETRICS 0→1` MUST 自动清零聚合数据
- `METRICS.PERF.RESET` MUST 清零聚合数据，且 MUST NOT 改变 `PERFMETRICS` 当前值
- `RESETALL` MUST 清零聚合数据并恢复 `PERFMETRICS=0`

#### Scenario: METRICS.PERF.RESET clears samples
- **GIVEN** `PERFMETRICS=1`
- **AND** `perf.nfq_total_us.samples` 大于 0
- **WHEN** 客户端调用 `METRICS.PERF.RESET`
- **THEN** 后续调用 `METRICS.PERF` 时 `perf.nfq_total_us.samples` SHALL 为 0

#### Scenario: RESETALL disables perf metrics
- **GIVEN** `PERFMETRICS=1`
- **WHEN** 客户端调用 `RESETALL`
- **THEN** 后续调用 `PERFMETRICS` 时返回值 SHALL 为 `0`
- **AND** 后续调用 `METRICS.PERF` 时 `perf.nfq_total_us.samples` SHALL 为 `0`
