## ADDED Requirements

### Requirement: D layer perf metrics are runtime-toggleable
系统 MUST 通过控制面暴露以下命令：
- `PERFMETRICS [<0|1>]`
- `METRICS.PERF`
- `METRICS.PERF.RESET`

`PERFMETRICS` MUST 在无参数时返回 `0|1`，在带参数时返回 `OK`。

#### Scenario: PERFMETRICS can be toggled
- **WHEN** 客户端调用 `PERFMETRICS`
- **THEN** 返回值 SHALL 为 `0` 或 `1`
- **WHEN** 客户端调用 `PERFMETRICS 1`
- **THEN** 返回值 SHALL 为 `OK`

### Requirement: METRICS.PERF returns fixed JSON shape in microseconds
系统 MUST 在 `METRICS.PERF` 返回一个顶层对象，固定包含两个 key：
- `nfq_total_us`
- `dns_decision_us`

每个 key 的 value MUST 为对象，且 MUST 固定包含字段（单位 `us`）：
`samples/min/avg/p50/p95/p99/max`（全部为 number，`samples` 为 uint64）。

当 `samples=0` 时，其他字段 MUST 为 `0`。

#### Scenario: METRICS.PERF returns required keys
- **WHEN** 客户端调用 `METRICS.PERF`
- **THEN** 返回值 SHALL 为有效 JSON
- **AND** 返回值 SHALL 包含 key `nfq_total_us`
- **AND** 返回值 SHALL 包含 key `dns_decision_us`

### Requirement: nfq_total_us measures PacketListener callback service time
系统 MUST 按固定边界采集 `nfq_total_us`：
- start：`PacketListener::callback()` 入口
- end：`sendVerdict()` 返回之后

#### Scenario: nfq_total_us samples increase under traffic
- **GIVEN** `BLOCK=1`
- **AND** `PERFMETRICS=1`
- **WHEN** 设备产生可进入 NFQUEUE 的网络包流量
- **THEN** 后续调用 `METRICS.PERF` 时 `nfq_total_us.samples` SHALL 大于等于 1

### Requirement: dns_decision_us measures decision+reply time only
系统 MUST 按固定边界采集 `dns_decision_us`：
- start：DNS 请求体（`len/domain/uid`）已读完且 `App/Domain` 已构造完成之后
- end：`verdict/getips` 写回完成之后

系统 SHALL NOT 将后续 IP 上传阶段纳入 `dns_decision_us`。

#### Scenario: dns_decision_us samples increase under DNS requests
- **GIVEN** `PERFMETRICS=1`
- **WHEN** 客户端触发至少 1 次 DNS 判决请求
- **THEN** 后续调用 `METRICS.PERF` 时 `dns_decision_us.samples` SHALL 大于等于 1

### Requirement: Reset semantics are stable
- `PERFMETRICS 0→1` MUST 自动清零聚合数据
- `METRICS.PERF.RESET` MUST 清零聚合数据
- `RESETALL` MUST 清零聚合数据并恢复 `PERFMETRICS=0`

#### Scenario: METRICS.PERF.RESET clears samples
- **GIVEN** `PERFMETRICS=1`
- **AND** `nfq_total_us.samples` 大于 0
- **WHEN** 客户端调用 `METRICS.PERF.RESET`
- **THEN** 后续调用 `METRICS.PERF` 时 `nfq_total_us.samples` SHALL 为 0
