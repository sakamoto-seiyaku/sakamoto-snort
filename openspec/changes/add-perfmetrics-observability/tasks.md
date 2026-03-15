## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（本目录下 `specs/`）
- [x] 1.2 `openspec validate add-perfmetrics-observability --strict` 通过

## 2. Implementation (D layer)
- [ ] 2.1 新增 `PerfMetrics` 模块：低开销 enable/disable、分桶聚合、`samples/min/avg/p50/p95/p99/max`
- [ ] 2.2 Packet/NFQ：在 `PacketListener::callback()` 实现 `nfq_total_us` 口径采集（entry → `sendVerdict()` return）
- [ ] 2.3 DNS：在 `DnsListener::clientRun()` 实现 `dns_decision_us` 口径采集（App/Domain 构造完成 → verdict/getips 写回完成）
- [ ] 2.4 Control：新增 `PERFMETRICS` / `METRICS.PERF` / `METRICS.PERF.RESET`，并更新 `HELP`
- [ ] 2.5 `RESETALL`：恢复到默认关闭状态，并清空 D 层指标

## 3. Docs & tooling
- [ ] 3.1 更新 `docs/INTERFACE_SPECIFICATION.md`：补齐新命令与 JSON shape
- [ ] 3.2 更新 `tests/integration/perf-nfq-latency.sh`：用 `METRICS.PERF` 输出 `nfq_total_us`（不再解析 RTT）
- [ ] 3.3 更新 `tests/integration/README.md`：perf lane 的口径说明

## 4. Verification
- [ ] 4.1 Host：新增/更新单测覆盖分桶/分位数计算的基本正确性
- [ ] 4.2 Device：跑 `ctest -L perf`，验证 `PERFMETRICS/METRICS.PERF*` 可用且 `nfq_total_us.samples` 可增长
