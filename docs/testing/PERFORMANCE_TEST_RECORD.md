# 性能测试记录（sucre-snort）

更新时间：2026-03-16

本文用于记录“可重复执行”的真机性能/负载测试结果（按日期追加），用于：
- 证明热路径在关键开关关闭时不引入额外成本（或尽可能接近 0 成本）。
- 证明关键开关开启时的额外成本可控、可解释、可回归。
- 为后续优化提供对照基线（避免“感觉变快/变慢”）。

> 说明：不同网络环境/后台流量会显著影响结果；本文记录的是“当时真机+网络”的实测快照。

---

## 1. 关键原则（影响验收口径）

- **禁用必须近似零成本**：例如 `PERFMETRICS=0`、`IPRULES=0` 时，热路径不应做额外 snapshot/caches/统计更新（除了既有逻辑）。
- **开启必须成本可控**：开启后允许有开销，但必须可量化（`METRICS.PERF`）、且不出现明显的队列堆积/卡死。
- **percentile 口径**：`p50/p95/p99` 是 **bucket 上界**（离散桶近似）而不是精确分位点；`max/avg` 保持真实值用于暴露卡顿尖峰。

---

## 2. 测试入口（可复现）

- 负载触发 + `METRICS.PERF`：
  - `bash tests/integration/perf-network-load.sh --skip-deploy --serial <serial>`
  - 该脚本会在设备侧优先用 `curl/wget`，没有则退化到 `nc` 做 HTTP GET 到 `/dev/null`。
  - 脚本会校验：`PERFMETRICS=0` 时 `METRICS.PERF` 全 0；开启后 `samples` 增长、且非法参数被拒绝。

- IPRULES 功能 + stats（非纯性能但用于验证热路径链路）：
  - `bash tests/integration/iprules.sh --skip-deploy --serial <serial>`

---

## 3. 环境快照（当前记录对应）

- Device：Pixel 6a（bluejay），serial `28201JEGR0XPAJ`
- Android：16（SDK 36）
- Fingerprint：`google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`
- Kernel：`6.1.134-android14-11-g66e758f7d0c0-ab13748739`

---

## 4. 结果记录

### 2026-03-16：PERFMETRICS 基线与下载负载

- Commit：`1988f2c`（`iprules: enforce TCP/UDP-only port predicates`）
- 命令：
  - `bash tests/integration/perf-network-load.sh --skip-deploy --serial 28201JEGR0XPAJ`
- 关键参数（脚本默认值）：
  - `BYTES=20000000`（仅用于 Cloudflare URL；本次实际使用 HTTP 下载 URL）
  - `TIMEOUT_SEC=25`
  - `CONCURRENCY=1`
  - `IDLE_SEC=3`
- Device downloader：`nc_http`
- 实际负载 URL：`http://speedtest.tele2.net/10MB.zip`

检查点：
- `PERFMETRICS=0`：在下载流量下 `METRICS.PERF` 返回全 0 ✅
- `PERFMETRICS=1`：`perf.nfq_total_us.samples` 增长 ✅
- `PERFMETRICS 1->1` 幂等：不会清零 samples ✅
- `PERFMETRICS` 非法参数拒绝 ✅

采样输出（脚本打印的 `METRICS.PERF` JSON）：
```json
{"perf":{"nfq_total_us":{"samples":16,"min":94,"avg":324,"p50":239,"p95":767,"p99":767,"max":715},"dns_decision_us":{"samples":1,"min":73,"avg":73,"p50":79,"p95":79,"p99":79,"max":73}}}
```

备注：
- 该次 idle 窗口 `samples=0`（设备没有产生可观测 NFQUEUE 流量），因此脚本对比项会跳过；这是预期行为（不把“无流量”误判为 perf 退化）。

---

## 5. TODO（后续补齐并持续追加结果）

- IPRULES 热路径开销对比（同一负载下）：
  - `IPRULES=0` vs `IPRULES=1`（少量规则、典型规则集、接近上限的复杂度）
  - 同时记录：
    - `METRICS.PERF.nfq_total_us` 分布变化
    - `/proc/net/netfilter/nfnetlink_queue` 是否出现 backlog/丢包迹象
    - CPU（若需要，后续补充统一采集方式）

