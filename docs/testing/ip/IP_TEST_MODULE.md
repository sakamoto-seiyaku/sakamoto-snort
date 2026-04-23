# IP Test Module (real-device, controlled Tier‑1)

> 这是 IP 真机测试模组的“精简可维护版”说明文档：只保留稳定结论、入口与口径。  
> 详细的实验过程与中间数据已归档：`docs/testing/ip/archive/2026-03-24-IP_TEST_MODULE.md`。

目标：在 rooted Android 真机上为 `IPRULES/IFACE_BLOCK` 提供 **可重复执行** 的功能回归与 perf baseline，并包含对 legacy 冻结项（`BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）的 fixed/no-op 语义 sanity check。  
原则：不追求模拟真实网络，优先追求 **稳定、可复现、能拉开差距**（用于后续任何大改动的对比基线）。

## 1. 入口（推荐）

前置：主机可用 ADB；真机需要 `su 0`。

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL="28201JEGR0XPAJ"   # 例：Pixel 6a

# 部署（可选；若已在机上运行可用 --skip-deploy）
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-build
bash dev/dev-deploy.sh --serial "$ADB_SERIAL"

# IP 模组 smoke/perf（Tier‑1: netns+veth）
bash tests/device-modules/ip/run.sh --serial "$ADB_SERIAL" --profile smoke
bash tests/device-modules/ip/run.sh --serial "$ADB_SERIAL" --profile perf --skip-deploy

# 全量功能矩阵 / 并发压力（best-effort；环境不满足会 SKIP）
bash tests/device-modules/ip/run.sh --serial "$ADB_SERIAL" --profile matrix --skip-deploy
bash tests/device-modules/ip/run.sh --serial "$ADB_SERIAL" --profile stress --skip-deploy

# Tier-1 longrun（control-plane churn + traffic + health assertions；record-first）
IPTEST_LONGRUN_SECONDS=600 \
  bash tests/device-modules/ip/run.sh --serial "$ADB_SERIAL" --profile longrun --skip-deploy
```

说明：
- `tests/device-modules/ip/` 是“真机测试模组”，不是 unit/integration 的替代品（历史纲领见 `docs/testing/archive/TEST_COMPONENTS_MANIFESTO.md`）。
- 结果记录默认写到 `tests/device-modules/ip/records/`（该目录已被 `tests/device-modules/ip/.gitignore` 排除，不进 git）。
  - `--profile longrun` 产物目录形如 `tests/device-modules/ip/records/ip-longrun-<ts>_<serial>/`，包含 `meta.txt`、`longrun.log`、`snort_proc_before/after/delta` 与 `traffic.txt`。
- 建议频率（口径保守，先不把 perf 变成 hard gate）：
  - 任意 `IPRULES/IFACE_BLOCK` 语义改动：至少跑 `smoke + matrix`
  - 若触及 legacy 冻结项（`BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）：至少确保 `smoke` 通过（相关用例验证 fixed/no-op 语义）
  - 热路径/性能/并发相关改动：再补 `perf + stress`（perf 推荐用本文固定口径的 UDP baseline）
  - 需要更强稳定性/长期运行信心时（例如 release candidate）：再补 `longrun`（best-effort；环境不满足会 SKIP）

## 2. Tier‑1（netns+veth）受控拓扑

Tier‑1 的目的：在真机内创建封闭网络拓扑，避免公网/DNS/CDN 抖动，获得更强可复现性。

当前范围：
- 本模组目前只实现 Tier‑1（设备内 `netns+veth` 自建对端）；Tier‑2/Tier‑3 暂不做。

关键点：
- Android 常见 policy routing：不同 UID 的出站流量会走 `wlan0/rmnet` 等 table。Tier‑1 setup 需要把测试子网路由注入“client UID 实际使用的 table”，否则 `ip route get <peer> uid 2000` 可能不会走 veth。
- Tier‑1 server 统一使用 `nc -L cat /dev/zero`（见 §5）。

## 3. Perf baseline v1（UDP cache‑buster）

### 3.1 为什么用 UDP（而不是 TCP）

我们要放大的是 “rule-eval 成本”，而不是 “握手/accept/拥塞控制” 等 TCP 成本。实践中：
- TCP（即使短连接）很容易让连接/握手成本淹没 rule-eval，导致 `2k vs 4k` 拉不开或顺序效应很强。
- UDP_STREAM 更容易把瓶颈推到 per-packet 路径，从而稳定拉开 `off > 2k > 4k`。

### 3.2 baseline v1 的固定口径（Pixel 6a）

主指标：neper `remote_throughput`（单位 **bits/s**）。  
perfmetrics：推荐 `PERFMETRICS=0`（避免观测本身成为瓶颈；只把 `/proc/net/netfilter/nfnetlink_queue` 作为 guardrail）。

固定 knobs：
- `threads=8 flows=1024 bytes=64 perfmetrics=0 delay-ns=43000`
- CPU 定频（best-effort，runner 会 restore）：
  - `policy0=1328000 policy4=1328000 policy6=1426000`
  - governor: `performance`（并写入 `scaling_min_freq = scaling_max_freq = <freq>`）
- matrix mode：`scenario`（每个样本独立 `RESETALL + warmup`，降低顺序 bias）

推荐窗口：
- 快速方向：`seconds=30 rounds-per-scenario=3`
- 稳定回归：`seconds=60 rounds-per-scenario=3`
- 严格 gate：`seconds=60 rounds-per-scenario=5`

### 3.3 一键运行命令（baseline v1）

```bash
bash tests/device-modules/ip/neper_udp_perf_fixedfreq_matrix.sh \
  --serial "$ADB_SERIAL" \
  --adb "$ADB" \
  --matrix-mode scenario \
  --settle 10 \
  --freq0 1328000 --freq4 1328000 --freq6 1426000 \
  -- \
  --rounds-per-scenario 5 \
  --seconds 60 \
  --warmup 10 \
  --cooldown-job 10 \
  --threads 8 \
  --flows 1024 \
  --bytes 64 \
  --delay-ns 43000 \
  --perfmetrics 0
```

产物目录形如：
- `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-<ts>_<serial>/`

### 3.4 baseline v1（冻结记录：原始样本表）

严格复核（`seconds=60 × rounds-per-scenario=5`，`delay-ns=43000`）：
- 设备：Pixel 6a（Android `16` / SDK `36`；serial=`28201JEGR0XPAJ`）
- 产物（不进 git）：`tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260324T000344Z_28201JEGR0XPAJ/`
- 说明：
  - warmup `warmup_off` 已排除（仅统计 `iprules_off/iprules_2k/iprules_4k`）
  - neper `remote_throughput` 单位为 **bits/s**（表中同时给出 Mb/s）

CPU 定频快照（`snapshot_after_pin.txt`）：

| policy | governor | cur_khz | min_khz | max_khz |
|---|---|---:|---:|---:|
| policy0 | performance | 1328000 | 1328000 | 1328000 |
| policy4 | performance | 1328000 | 1328000 | 1328000 |
| policy6 | performance | 1426000 | 1426000 | 1426000 |

原始样本（每行对应 1 个独立 job 的 scenario 结果）：

| scenario | sample | remote_throughput_bps | remote_throughput_Mb/s | nfq_seq_total | nfq_queue_dropped_total | nfq_user_dropped_total | records_dir |
|---|---:|---:|---:|---:|---:|---:|---|
| off | 1 | 11624335 | 11.624 | 1364249 | 0 | 0 | neper-udp-perf-3way-20260324T000527Z_28201JEGR0XPAJ |
| off | 2 | 11705030 | 11.705 | 1374103 | 0 | 0 | neper-udp-perf-3way-20260324T000651Z_28201JEGR0XPAJ |
| off | 3 | 11958127 | 11.958 | 1403288 | 0 | 0 | neper-udp-perf-3way-20260324T001919Z_28201JEGR0XPAJ |
| off | 4 | 12182696 | 12.183 | 1430551 | 0 | 0 | neper-udp-perf-3way-20260324T002348Z_28201JEGR0XPAJ |
| off | 5 | 11908125 | 11.908 | 1397785 | 0 | 0 | neper-udp-perf-3way-20260324T002513Z_28201JEGR0XPAJ |
| 2k | 1 | 11391782 | 11.392 | 1336982 | 0 | 0 | neper-udp-perf-3way-20260324T000358Z_28201JEGR0XPAJ |
| 2k | 2 | 11048183 | 11.048 | 1296664 | 0 | 0 | neper-udp-perf-3way-20260324T001023Z_28201JEGR0XPAJ |
| 2k | 3 | 11090753 | 11.091 | 1301399 | 0 | 0 | neper-udp-perf-3way-20260324T001455Z_28201JEGR0XPAJ |
| 2k | 4 | 11644796 | 11.645 | 1367176 | 0 | 0 | neper-udp-perf-3way-20260324T001624Z_28201JEGR0XPAJ |
| 2k | 5 | 11894243 | 11.894 | 1396630 | 0 | 0 | neper-udp-perf-3way-20260324T001751Z_28201JEGR0XPAJ |
| 4k | 1 | 9882440 | 9.882 | 1160342 | 0 | 0 | neper-udp-perf-3way-20260324T000851Z_28201JEGR0XPAJ |
| 4k | 2 | 10079179 | 10.079 | 1183515 | 0 | 0 | neper-udp-perf-3way-20260324T001151Z_28201JEGR0XPAJ |
| 4k | 3 | 10278973 | 10.279 | 1206806 | 0 | 0 | neper-udp-perf-3way-20260324T001323Z_28201JEGR0XPAJ |
| 4k | 4 | 10101956 | 10.102 | 1186093 | 0 | 0 | neper-udp-perf-3way-20260324T002043Z_28201JEGR0XPAJ |
| 4k | 5 | 10033588 | 10.034 | 1177752 | 0 | 0 | neper-udp-perf-3way-20260324T002216Z_28201JEGR0XPAJ |

汇总（mean/stdev/cv/min/max；`delta_vs_off` 为 mean 的相对差异）：

| scenario | n | mean_bps | stdev_bps | cv% | min_bps | max_bps | delta_vs_off |
|---|---:|---:|---:|---:|---:|---:|---:|
| off | 5 | 11875662.60 | 220456.76 | 1.86% | 11624335.00 | 12182696.00 | baseline |
| 2k | 5 | 11413951.40 | 361491.51 | 3.17% | 11048183.00 | 11894243.00 | -3.89% |
| 4k | 5 | 10075227.20 | 142428.16 | 1.41% | 9882440.00 | 10278973.00 | -15.16% |

验收口径：
- 单调性：`off > 2k > 4k` by index `5/5`
- guardrails：`nfq_queue_dropped_total=0` 且 `nfq_user_dropped_total=0`（`15/15` 样本）

### 3.4.1 baseline v1（cache-off 诊断：iprules decision cache disabled）

前置：部署 cache-off 诊断二进制（仅禁用 `IpRulesEngine::evaluate()` 内部 per-thread decision cache；不改变规则语义）。

```bash
bash dev/dev-build.sh
bash dev/dev-deploy.sh --serial "$ADB_SERIAL" --variant iprules-nocache
```

严格复核（同 baseline v1 knobs；`seconds=60 × rounds-per-scenario=5`，`delay-ns=43000`）：
- 设备：Pixel 6a（Android `16` / SDK `36`；serial=`28201JEGR0XPAJ`）
- 产物（不进 git）：`tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260324T023234Z_28201JEGR0XPAJ/`

原始样本（每行对应 1 个独立 job 的 scenario 结果）：

| scenario | sample | remote_throughput_bps | remote_throughput_Mb/s | nfq_seq_total | nfq_queue_dropped_total | nfq_user_dropped_total | records_dir |
|---|---:|---:|---:|---:|---:|---:|---|
| off | 1 | 11566169 | 11.566 | 1357848 | 0 | 0 | neper-udp-perf-3way-20260324T023416Z_28201JEGR0XPAJ |
| off | 2 | 11791505 | 11.792 | 1383959 | 0 | 0 | neper-udp-perf-3way-20260324T023541Z_28201JEGR0XPAJ |
| off | 3 | 11576794 | 11.577 | 1359383 | 0 | 0 | neper-udp-perf-3way-20260324T024737Z_28201JEGR0XPAJ |
| off | 4 | 11815719 | 11.816 | 1386776 | 0 | 0 | neper-udp-perf-3way-20260324T025207Z_28201JEGR0XPAJ |
| off | 5 | 11760032 | 11.760 | 1380119 | 0 | 0 | neper-udp-perf-3way-20260324T025332Z_28201JEGR0XPAJ |
| 2k | 1 | 11200949 | 11.201 | 1315118 | 0 | 0 | neper-udp-perf-3way-20260324T023248Z_28201JEGR0XPAJ |
| 2k | 2 | 11347429 | 11.347 | 1332343 | 0 | 0 | neper-udp-perf-3way-20260324T023838Z_28201JEGR0XPAJ |
| 2k | 3 | 11229448 | 11.229 | 1317910 | 0 | 0 | neper-udp-perf-3way-20260324T024313Z_28201JEGR0XPAJ |
| 2k | 4 | 11177968 | 11.178 | 1312149 | 0 | 0 | neper-udp-perf-3way-20260324T024441Z_28201JEGR0XPAJ |
| 2k | 5 | 11110675 | 11.111 | 1304395 | 0 | 0 | neper-udp-perf-3way-20260324T024608Z_28201JEGR0XPAJ |
| 4k | 1 | 10034056 | 10.034 | 1178288 | 0 | 0 | neper-udp-perf-3way-20260324T023705Z_28201JEGR0XPAJ |
| 4k | 2 | 9468190 | 9.468 | 1111575 | 0 | 0 | neper-udp-perf-3way-20260324T024006Z_28201JEGR0XPAJ |
| 4k | 3 | 9905271 | 9.905 | 1163309 | 0 | 0 | neper-udp-perf-3way-20260324T024139Z_28201JEGR0XPAJ |
| 4k | 4 | 9530180 | 9.530 | 1119135 | 0 | 0 | neper-udp-perf-3way-20260324T024901Z_28201JEGR0XPAJ |
| 4k | 5 | 9404189 | 9.404 | 1104406 | 0 | 0 | neper-udp-perf-3way-20260324T025035Z_28201JEGR0XPAJ |

汇总（mean/stdev/cv/min/max；`delta_vs_off` 为 mean 的相对差异）：

| scenario | n | mean_bps | stdev_bps | cv% | min_bps | max_bps | delta_vs_off |
|---|---:|---:|---:|---:|---:|---:|---:|
| off | 5 | 11702043.80 | 120869.21 | 1.03% | 11566169.00 | 11815719.00 | baseline |
| 2k | 5 | 11213293.80 | 86867.91 | 0.77% | 11110675.00 | 11347429.00 | -4.18% |
| 4k | 5 | 9668377.20 | 282315.62 | 2.92% | 9404189.00 | 10034056.00 | -17.38% |

对比 cache-on baseline v1（`3.4`）：
- mean throughput（off/2k/4k）相对 cache-on：`-1.46% / -1.76% / -4.04%`
- 规则规模差距放大：`4k_vs_off=-17.38%`（cache-on: `-15.16%`），`4k_vs_2k=-13.78%`（cache-on: `-11.73%`）

### 3.5 Guardrails（必须满足）

每个样本必须满足（否则说明打流已把 NFQUEUE 打爆，结果不可比）：
- `nfq_queue_dropped_total=0`
- `nfq_user_dropped_total=0`

这些值由脚本在每个样本前后读取 `/proc/net/netfilter/nfnetlink_queue` 并计算 delta。

### 3.6 额外采集（best-effort；不做 gate）

为帮助定位 “吞吐差距不大但热路径成本变化” 的情况，每个 scenario 额外采集 `sucre-snort` 进程的 `/proc/<pid>` 快照并计算 delta：
- `*_snort_proc_before.txt` / `*_snort_proc_after.txt`
- `*_summary.txt` 中会额外出现（示例）：
  - `snort_cpu_ticks_delta`
  - `snort_cpu_ticks_per_pkt`（UDP/ICMP 等按 NFQ 包数归一）
  - `snort_cpu_ticks_per_txn`（`tcp_crr` 按事务数归一）
  - `snort_vm_rss_kb_delta`

说明：
- 这是 **best-effort** 诊断指标：若无法定位 PID 会回退为 `0`；不作为通过/失败 gate。
- tick→时间换算依赖 `CLK_TCK`（脚本会记录 `snort_clk_tck`，避免假设 HZ）。

### 3.7 其他 mode（可选；非 baseline）

除 UDP_STREAM baseline 外，还保留一个更偏 “短连接/事务” 的 TCP_CRR runner（用于 spot-check；不作为 baseline gate）：

```bash
bash tests/device-modules/ip/neper_perf_fixedfreq_matrix.sh \
  --serial "$ADB_SERIAL" \
  --adb "$ADB" \
  --matrix-mode scenario \
  --settle 10 \
  --freq0 1328000 --freq4 1328000 --freq6 1426000 \
  -- \
  --rounds-per-scenario 5 \
  --seconds 60 \
  --warmup 10 \
  --cooldown-job 10 \
  --threads 8 \
  --flows 1024 \
  --bytes 1 \
  --num-ports 16 \
  --perfmetrics 0
```

## 4. 规则集与场景语义（perf 口径）

baseline v1 采用 3 个场景（对同一台设备、同一组 knobs）：
- `off`：`IPRULES=0`（bypass）
- `2k`：`IPRULES=1` + traffic UID 下 2048 条规则
- `4k`：`IPRULES=1` + traffic UID 下 4096 条规则

规则语料设计目标：
- 强化 rule-eval 成本，但不改变实际 verdict（使用 `would-block`：`action=block enforce=0 log=1`）。
- deterministic：固定 seed + 固定生成规则形态，便于长期回归对比。

### 4.1 规则规模扫描（可选；METRICS.PERF + /proc delta）

用于观察 “规则规模→延迟/吞吐趋势”（**先记录**，不作为硬阈值 gate）：

```bash
bash tests/device-modules/ip/perf_ruleset_sweep.sh \
  --serial "$ADB_SERIAL" \
  --seconds 30 \
  --load-mode mix
```

## 5. 已知环境问题（必须规避）

Pixel 6a（toybox `nc`）存在已复现的 kernel panic：
- 触发组合：`nc -L sh -c "cat /dev/zero"` + client 真实读取 payload
- 证据与最小复现：`docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`
- workaround：Tier‑1 server 统一使用 `nc -L cat /dev/zero`（不派生 `sh`）

## 6. 错误路径（已明确不采用）

这些方向已验证“不适合作为 baseline”，这里只记录结论与原因（细节见归档文档）：
- **单长连接 stream**：很快退化成热缓存路径，更像测“热缓存单流吞吐”，对 rule-eval 不敏感。
- **TCP 为主的 perf baseline**：容易被握手/accept 等成本主导，`2k vs 4k` 不稳定、顺序效应强。
- **heavy ruleset 用 allow-hit/enforce**：会改变后续路径（短路 legacy/host/domain），出现 “heavy 比 empty 更快” 的失真。
- **把 `METRICS.PERF` 当主指标**：在高 PPS 场景下观测可能反客为主；因此 baseline v1 以 neper throughput 为主、`PERFMETRICS=0`，只用 NFQ drop 做 guardrail。

## 7. 何时需要重做 sweep / 升级 baseline

仅在以下情况重新 sweep（否则保持 baseline v1 不变，保证长期可比）：
- 设备/Android 版本变化导致 DVFS/内核行为变化
- tuple-space 或规则语料形态发生实质变化（例如新增关键 match 维度、bucket 策略变化）
- 观测到单调性/方差显著劣化（例如 `off>2k>4k` 经常失败或 CV 明显上升）
