## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（本目录下 `specs/`）
- [x] 1.2 `openspec validate add-perfmetrics-observability --strict` 通过

## 2. Implementation (D layer)
- [x] 2.1 新增 `PerfMetrics` 模块：低开销 enable/disable、分桶聚合、`samples/min/avg/p50/p95/p99/max`
- [x] 2.2 Packet/NFQ：在 `PacketListener::callback()` 实现 `nfq_total_us` 口径采集（entry → `sendVerdict()` return）
- [x] 2.3 DNS：在 `DnsListener::clientRun()` 实现 `dns_decision_us` 口径采集（App/Domain 构造完成 → verdict/getips 写回完成）
- [x] 2.4 Control：新增 `PERFMETRICS` / `METRICS.PERF` / `METRICS.PERF.RESET`，并更新 `HELP`
- [x] 2.5 `RESETALL`：恢复到默认关闭状态，并清空 D 层指标

## 3. Docs & tooling
- [x] 3.1 更新 `docs/INTERFACE_SPECIFICATION.md`：补齐新命令与 JSON shape
- [x] 3.2 新增 `tests/integration/perf-network-load.sh`：
  - 在设备侧用 `curl`/`wget`（若无则尝试 `toybox wget`）对稳定 URL 做 download（输出到 `/dev/null`），产生真实网络 I/O 负载，并用 `METRICS.PERF` 输出 `perf.nfq_total_us`（不再解析 RTT）
  - URL/bytes/时长/并发可参数化；默认 URL 建议按顺序尝试：
    - `https://speed.cloudflare.com/__down?bytes=<N>`（CDN；`bytes` 可控）
    - `https://fsn1-speed.hetzner.com/100MB.bin`（固定大文件）
  - 若所有 URL 都不可达（离线/受限网络），测试 SHOULD 明确 `SKIP`（而不是误报 fail）
- [x] 3.3 更新 `tests/integration/README.md`：perf lane 的入口与口径说明（与新脚本一致）
- [x] 3.4 集成到 CTest：新增 `perf-network-load`（label `perf`）

## 4. Verification
- [x] 4.1 Host：新增/更新单测覆盖分桶与 nearest-rank 分位数计算的基本正确性（含 percentile clamp，但 `max/avg` 仍保留真实样本值）
- [x] 4.2 Device：跑 `ctest -L perf`，验证 `PERFMETRICS/METRICS.PERF*` 可用且 `perf.nfq_total_us.samples` 可增长
- [x] 4.3 Device：跑 `ctest -L perf`，验证在产生 DNS 判决请求时 `perf.dns_decision_us.samples` 可增长
- [x] 4.4 Device：验证 `PERFMETRICS=0` 时在有流量情况下仍返回全 `0`（`samples=0`）
- [x] 4.5 Control：验证 `PERFMETRICS` 非法参数返回 `NOK`，且幂等（`1→1` / `0→0` 不触发清零）
