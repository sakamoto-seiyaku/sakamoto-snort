# IP Test Module (real-device, controlled Tier-1)

> Archived on 2026-03-24. Superseded by `docs/testing/ip/IP_TEST_MODULE.md`.  
> This file keeps the full experiment log (including failed paths and intermediate sweeps).

这个文档描述 `tests/device-modules/ip/`：一个长期维护的 **IP/L3-L4 firewall 真机测试模组**（不是开发期 unit/integration 的替代品）。

## 1. 入口与使用

前置：
- 一台 rooted Android 真机（需要 `su 0`）
- 主机侧可用 ADB（建议显式设置 `ADB=`，避免误用 `adb.exe`）

示例（Pixel 6a）：

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL="28201JEGR0XPAJ"

# 先确保守护进程为最新（可跳过）
bash dev/dev-build.sh
bash dev/dev-deploy.sh --serial "$ADB_SERIAL"

# 最小闭环（Tier-1：netns+veth）
bash tests/device-modules/ip/run.sh --skip-deploy --profile smoke

# perf（默认：traffic UID=2000 下 2K rules + Tier-1 TCP load）
bash tests/device-modules/ip/run.sh --skip-deploy --profile perf

# native replay POC（先验证设备侧 replayer 闭环）
bash dev/dev-build-iptest-replay.sh
bash tests/device-modules/ip/native_replay_poc.sh --skip-deploy

# native replay 3-way（第一轮 no-rule / empty-rule / heavy-rule 分离实验）
bash tests/device-modules/ip/native_replay_3way.sh --skip-build

# neper perf baseline（off vs 2k vs 4k, TCP_CRR；主指标=txns/s）
# 注意：推荐 PERFMETRICS=0（只用 nfnetlink_queue 作为 guardrail），并使用 warmup/cooldown 降低 DVFS/热状态影响
bash tests/device-modules/ip/neper_perf_3way.sh --seconds 30 --warmup 10 --cooldown 30 \
  --threads 8 --flows 1024 --bytes 1 --num-ports 16 --perfmetrics 0

# neper perf baseline（off vs 2k vs 4k, UDP_STREAM；主指标=remote_throughput bits/s）
# 推荐：用 fixed-freq + scenario matrix 固化口径（降低方差），再去 sweep delay-ns 找分离度更好的区间
# 当前阶段 baseline v1（Pixel 6a）：`--delay-ns 43000`；更严 gate 可用 `--seconds 60 --rounds-per-scenario 5`
bash tests/device-modules/ip/neper_udp_perf_fixedfreq_matrix.sh --matrix-mode scenario \
  --serial "$ADB_SERIAL" --adb "$ADB" --settle 10 --freq0 1328000 --freq4 1328000 --freq6 1426000 -- \
  --rounds-per-scenario 3 --seconds 30 --warmup 10 --cooldown-job 10 \
  --threads 8 --flows 1024 --bytes 64 --delay-ns 43000 --perfmetrics 0
```

`dev/dev-build-iptest-replay.sh` 当前优先走一个快速路径：
- 直接复用 `LINEAGE_ROOT/out-kernel/.../prebuilts/ndk-r23/...` 里的 NDK toolchain
- 直接编译 `tests/device-modules/ip/native/iptest_replay.cpp`
- 若该 toolchain 不存在，再回退到原来的 Soong 路径

`tests/device-modules/ip/native_replay_poc.sh` 当前默认不是“单 peer 单端口”：
- `THREADS=112`
- `TRACE_ENTRIES=16384`
- `TRACE_HOST_COUNT=8`
- `TRACE_PEER_COUNT=16`
- `TRACE_PORT_COUNT=16`
- `TRACE_SHUFFLE=1`
- `TRACE_SEED=1`
- 即默认会在一个小规模、确定性的 `srcIp/dstIp/dstPort/srcPort` 组合上做 replay，并用固定 seed 打散顺序，用来先打出最基础的 tuple churn

## 2. Tier-1 受控拓扑（netns+veth）

`smoke/perf` 默认优先走 Tier‑1：在真机上创建封闭拓扑（`ip netns` + `veth`），避免公网/DNS/CDN 抖动。

Android 注意点：很多设备会对不同 UID 使用独立路由表（如 `table wlan0`）。Tier‑1 setup 会：
- 用 `ip route get <peer> uid <uid>` 解析出该 UID 实际命中的 table
- 把 `10.200.1.0/24 dev <veth>` 注入该 table

Tier‑1 的 TCP load server 当前使用：
- `nc -L cat /dev/zero`（避免 server-side 派生 `/system/bin/sh`，Pixel 6a 上观察到 `sock_ioctl` kernel panic，见 `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`）

若需要继续复现实验/跑最小定位矩阵，使用：
- `bash tests/device-modules/ip/repro/run_kernel_panic_sock_ioctl_host.sh`
- `bash tests/device-modules/ip/repro/run_kernel_panic_sock_ioctl_matrix.sh`

## 3. Profiles（当前已落地）

- `smoke`：Tier‑1 ICMP enforce 命中 + `IPRULES=0` bypass（stats 不增长）
  - 现在额外包含 `native replay POC`：设备侧 replayer → Tier‑1 TCP listeners → `PKTSTREAM`/`METRICS.PERF`
- `perf`：Tier‑1 TCP load + ruleset baseline（默认 traffic UID=2000 下 `N=2000`）
  - load mode：`stream | chunk | mix`
  - 可调：`IPTEST_PERF_TRAFFIC_RULES` / `IPTEST_PERF_BG_TOTAL` / `IPTEST_PERF_BG_UIDS` / `IPTEST_PERF_BYTES`
  - `mix` 额外可调：`IPTEST_PERF_MIX_WORKERS` / `IPTEST_PERF_MIX_CONN_BYTES` / `IPTEST_PERF_MIX_HOST_COUNT` / `IPTEST_PERF_MIX_PEER_COUNT` / `IPTEST_PERF_MIX_PORT_COUNT`
  - 约定：background rules 以 round‑robin 分摊到 `IPTEST_PERF_BG_UIDS` 个 UID（默认 `BG_UIDS=BG_TOTAL`，即 1 rule/UID）
  - 长跑入口：
    - `tests/device-modules/ip/perf_overnight_matrix.sh`：宿主机后台编排 `warmup + 多 duration + 多 scenario` 长跑，并持续写 `status/results/summary`
    - `tests/device-modules/ip/perf_overnight_summarize.py`：对夜跑 `results.jsonl` 做分组汇总
- `native_replay_3way.sh`：基于设备侧 native replayer 的三场景对照
  - `iprules_off_empty`
  - `iprules_on_empty`
  - `iprules_on_heavy`
  - 当前用于验证“native sender 提升后，场景分离度是否开始出现”

## 4. Perf baseline（当前探索中的固定口径）

这部分不是“最终定稿”，而是把当前阶段已经确认的原则、候选 workload 和被放弃的方向先固定在文档里，避免后续上下文丢失。总原则见 `docs/testing/TEST_COMPONENTS_MANIFESTO.md` 的 `4.4.3`；这里补充当前落地到 `tests/device-modules/ip/` 的具体形态。

### 4.1 当前追求的 baseline 目标

- 同一场景独立重复多轮时，结果要尽量稳定；否则不能作为 baseline。
- 不同场景之间要能拉开差距；否则后续优化/回归没有比较价值。
- 当前先固定一组“单场景 workload + 固定 ruleset”，先验证它是否稳定、是否有区分度；不追求一开始覆盖全部真实流量。

### 4.2 已放弃/暂不采用的方向

- 单长连接 `stream` 不是当前主 baseline 候选。
  - 原因：它很快退化成 exact-cache 热路径；更像是在测“热缓存下单流吞吐”，不足以代表 rule engine 的判决成本。
- heavy ruleset 用 `action=allow enforce=1` 也不是当前主 baseline 候选。
  - 原因：一旦命中 ALLOW，会提前短路 legacy/domain 路径；不同场景的最终执行路径不再可比，甚至会出现“heavy 比 empty 更快”的失真。

### 4.3 当前冻结的 workload 候选（继续围绕它做实验）

当前主候选是 `IPTEST_PERF_LOAD_MODE=mix`，目标是让 tuple churn 起来，同时仍保持足够可控：

- client：设备侧多 worker 短连接循环；
- server：Tier‑1 netns 内多个 `nc -L cat /dev/zero` listener；
- tuple 变化维度：`srcPort` / `dstIp` / `dstPort`；
- 当前候选参数：
  - `IPTEST_PERF_MIX_WORKERS=16`
  - `IPTEST_PERF_MIX_CONN_BYTES=4096`
  - `IPTEST_PERF_MIX_HOST_COUNT=4`
  - `IPTEST_PERF_MIX_PEER_COUNT=16`
  - `IPTEST_PERF_MIX_PORT_COUNT=8`
- 当前主要观察的场景：
  - `iprules_off_empty`：`BLOCK=1, IPRULES=0, empty rules`
  - `iprules_on_empty`：`BLOCK=1, IPRULES=1, empty rules`
  - `iprules_on_heavy`：`BLOCK=1, IPRULES=1, heavy ruleset`

### 4.4 当前 heavy ruleset 口径

当前 perf heavy ruleset 暂时固定为“traffic UID 下 4K 条、以 `would-block` 为主”的语料，而不是 allow-hit 语料：

- 规则动作：`action=block log=1 enforce=0`
- 目标：保留 `IPRULES` 判决与统计成本，但尽量不改变最终 accept 语义，避免 short-circuit 把比较口径带偏
- 当前语料形态（2026-03-20 实测）：
  - `rulesTotal=4000`
  - `rangeRulesTotal=1002`
  - `subtablesTotal=8`
  - `maxRangeRulesPerBucket=21`
- 当前暂不叠加 background rules，先把“单一 traffic UID + 4K rules”这个基线候选磨稳定；等基线站稳后，再逐步引入 `2K/4K + multi-UID background` 对照。

### 4.5 当前已经得到的判断

- `mix` 比单长连接更像一个合格候选：它至少能持续 churn `srcPort/dstIp/dstPort`，不会过早退化成单一热流。
- 但“三场景串行跑一遍再直接横比”目前还不够稳定：`iprules_off_empty` 和 `iprules_on_empty` 会随着执行顺序出现翻转，说明顺序效应/温控/系统状态仍然很强。
- `iprules_on_heavy` 在两次不同顺序的实验里相对更稳定，说明当前 `mix + 4K would-block` 方向可能是对的，但还不能直接宣布 baseline 已定稿。

### 4.6 下一轮实验的判断标准

下一轮不优先继续做“三场景串行比较”，而是先做“单场景重复多轮”：

- 同一场景连续独立跑 `5-10` 轮，确认方差是否可接受；
- 先分别测：
  - `iprules_off_empty`
  - `iprules_on_empty`
  - `iprules_on_heavy`
- 如果单场景本身稳定，再回头比较不同场景均值能否稳定拉开；
- 只有当这两条都满足，当前 workload/ruleset 才能升级成后续所有 IP 大改的 perf baseline。

## 5. 清理与排障

若异常中断导致残留 netns/veth，可在设备侧清理（root）：

```bash
adb -s "$ADB_SERIAL" shell "su 0 sh -c '
ip netns pids iptest_ns 2>/dev/null | while read -r pid; do
  kill -9 \"$pid\" 2>/dev/null || true
done
ip route del 10.200.1.0/24 dev iptest_veth0 table wlan0 2>/dev/null || true
ip link del iptest_veth0 2>/dev/null || true
ip netns del iptest_ns 2>/dev/null || true
'"
```

## 6. Run records（持续追加）

### 2026-03-18 / Pixel 6a (Android 14) / serial 28201JEGR0XPAJ

- `smoke`: `passed=2 failed=0 skipped=0`
- `perf` (default): `passed=2 failed=0 skipped=0`
  - `IPRULES.PREFLIGHT.summary`: `rulesTotal=2000 rangeRulesTotal=0 subtablesTotal=9 maxSubtablesPerUid=9`
  - `METRICS.PERF.perf.nfq_total_us.samples`: `2`（record-first；不作阈值 gate）

### 2026-03-19 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ

- `smoke`: `passed=2 failed=0 skipped=0`
- `perf`（Tier-1 empty-ruleset baseline，`IPRULES=1` 且未加载任何规则）:
  - command shape:
    - Tier-1 `netns+veth` + `nc -L cat /dev/zero`
    - duration `30s`, chunk `2000000`
  - summary:
    - `bytes=390000000 samples=44440`
    - `nfq_total_us`: `min=30 avg=188 p50=103 p95=575 p99=1279 max=8667`
- `perf`（Tier-1 duration compare，`cat_zero` server）: `passed=2 failed=0 skipped=0`
  - command:
    - `IPTEST_PERF_SECONDS=30 IPTEST_PERF_COMPARE=1 IPTEST_PERF_BG_TOTAL=2000 IPTEST_PERF_BG_UIDS=200 bash tests/device-modules/ip/run.sh --skip-deploy --profile perf`
  - `IPRULES.PREFLIGHT.summary`:
    - `rulesTotal=4000 rangeRulesTotal=0 subtablesTotal=209 maxSubtablesPerUid=9`
  - `PERF_PHASE_SUMMARY`:
    - `tag=iprules_on iprules=1 bytes=384000000 samples=40813`
    - `tag=iprules_off iprules=0 bytes=390000000 samples=42798`
  - result:
    - full duration load completed without ADB disconnect / device reboot
    - `METRICS.PERF` returned valid JSON in both phases

### 2026-03-20 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ

- 目标调整：
  - 不再把“单长连接 + allow-hit heavy ruleset”作为主 baseline 候选
  - 转向 `mix` workload + `would-block` heavy ruleset，优先验证“单场景可重复、跨场景可分离”

- `perf_3way`（第一轮，默认顺序）：
  - command:
    - `PERF_LOAD_MODE=mix HEAVY_TRAFFIC_RULES=4000 HEAVY_BG_TOTAL=0 HEAVY_BG_UIDS=0 IPTEST_PERF_MIX_WORKERS=16 IPTEST_PERF_MIX_CONN_BYTES=4096 bash tests/device-modules/ip/perf_3way.sh --seconds 30`
  - scenario `iprules_off_empty`:
    - `bytes=11681792 connections=2852 samples=95470`
    - `nfq_total_us: avg=1189 p50=175 p95=6655 p99=14335 max=53171`
  - scenario `iprules_on_empty`:
    - `bytes=9711616 connections=2371 samples=81565`
    - `nfq_total_us: avg=1776 p50=175 p95=10239 p99=20479 max=52973`
  - scenario `iprules_on_heavy`:
    - `bytes=12087296 connections=2951 samples=100814`
    - `nfq_total_us: avg=1152 p50=159 p95=6655 p99=14335 max=58549`
  - heavy preflight:
    - `rulesTotal=4000 rangeRulesTotal=1002 subtablesTotal=8 maxRangeRulesPerBucket=21`
  - 观察：
    - heavy 场景形态可用，但 `off_empty` vs `on_empty` 还不稳定

- `perf_3way`（第二轮，交换顺序验证 order bias）：
  - command:
    - `PERF_LOAD_MODE=mix HEAVY_TRAFFIC_RULES=4000 HEAVY_BG_TOTAL=0 HEAVY_BG_UIDS=0 IPTEST_PERF_MIX_WORKERS=16 IPTEST_PERF_MIX_CONN_BYTES=4096 bash tests/device-modules/ip/perf_3way.sh --seconds 30 --order iprules_on_empty,iprules_off_empty,iprules_on_heavy`
  - scenario `iprules_on_empty`:
    - `bytes=10514432 connections=2567 samples=86300`
    - `nfq_total_us: avg=1543 p50=175 p95=9215 p99=18431 max=51457`
  - scenario `iprules_off_empty`:
    - `bytes=9748480 connections=2380 samples=81445`
    - `nfq_total_us: avg=1718 p50=191 p95=9215 p99=20479 max=47349`
  - scenario `iprules_on_heavy`:
    - `bytes=11730944 connections=2864 samples=95390`
    - `nfq_total_us: avg=1164 p50=175 p95=6655 p99=14335 max=45128`
  - heavy preflight:
    - `rulesTotal=4000 rangeRulesTotal=1002 subtablesTotal=8 maxRangeRulesPerBucket=21`
  - 观察：
    - `off_empty` 和 `on_empty` 的相对快慢发生翻转，说明 3-way 串行跑仍受顺序影响
    - `on_heavy` 两轮的形态相对接近，说明 workload 候选本身值得继续沿着“单场景重复”方向验证

- 单场景重复（先只看 empty 两组）：
  - workload 固定：
    - `IPTEST_PERF_LOAD_MODE=mix`
    - `IPTEST_PERF_MIX_WORKERS=16`
    - `IPTEST_PERF_MIX_CONN_BYTES=4096`
    - `IPTEST_PERF_MIX_HOST_COUNT=4`
    - `IPTEST_PERF_MIX_PEER_COUNT=16`
    - `IPTEST_PERF_MIX_PORT_COUNT=8`
    - `trafficRules=0`
    - `backgroundRules=0`

- `iprules_off_empty`（`IPRULES=0`，`6 x 45s`）：
  - summary:
    - `rate_mib_s mean=0.2579 cv=17.08%`
    - `avg mean=1915us cv=14.14%`
    - `p95 mean=10580us cv=10.00%`
    - `p99 mean=20820us cv=7.40%`
  - 去掉首轮后的 `runs 2-6`：
    - `rate_mib_s mean=0.2732 cv=9.49%`
    - `avg mean=1968us cv=13.49%`
    - `p95 mean=10853us cv=8.44%`
    - `p99 mean=20889us cv=8.20%`
  - 记录文件：
    - `/tmp/iprules_off_empty.jm8PMU/summary.json`

- `iprules_on_empty`（`IPRULES=1 + empty rules`，`6 x 45s`）：
  - summary:
    - `rate_mib_s mean=0.2616 cv=13.25%`
    - `avg mean=2243us cv=14.19%`
    - `p95 mean=11604us cv=10.69%`
    - `p99 mean=22186us cv=9.08%`
  - 去掉首轮后的 `runs 2-6`：
    - `rate_mib_s mean=0.2481 cv=4.68%`
    - `avg mean=2365us cv=5.17%`
    - `p95 mean=12082us cv=3.79%`
    - `p99 mean=22937us cv=3.99%`
  - 记录文件：
    - `/tmp/iprules_on_empty.ruadgg/summary.json`

- `180s` 长窗口复核（与上面的短窗口重复结果对照）：
  - `iprules_off_empty`:
    - `rate=0.2859 MiB/s`
    - `avg=1909us p95=10239us p99=20479us`
    - log: `/tmp/iprules_off_empty_180.QMx0FE.log`
  - `iprules_on_empty`:
    - `rate=0.2636 MiB/s`
    - `avg=2179us p95=11263us p99=22527us`
    - log: `/tmp/iprules_on_empty_180.no2iZy.log`
  - 对比结论：
    - `180s` 长窗口没有推翻前面的方向，仍然是 `on_empty` 比 `off_empty` 更慢
    - `on_empty vs off_empty`（180s）：
      - 吞吐 `-7.78%`
      - `avg +14.14%`
      - `p95 +10.00%`
      - `p99 +10.00%`
    - 与 `45s` 重复实验去首轮后的均值方向一致，说明当前 `mix` workload 至少已经能稳定区分 `IPRULES=0` 与 `IPRULES=1 + empty`

- `iprules_on_heavy`（`IPRULES=1 + 4K would-block rules`，`6 x 30s`）：
  - command shape:
    - `IPTEST_PERF_LOAD_MODE=mix`
    - `IPTEST_PERF_MIX_WORKERS=16`
    - `IPTEST_PERF_MIX_CONN_BYTES=4096`
    - `IPTEST_PERF_MIX_HOST_COUNT=4`
    - `IPTEST_PERF_MIX_PEER_COUNT=16`
    - `IPTEST_PERF_MIX_PORT_COUNT=8`
    - `IPTEST_PERF_TRAFFIC_RULES=4000`
    - `IPTEST_PERF_BG_TOTAL=0`
    - `IPTEST_PERF_BG_UIDS=0`
  - summary:
    - `rate_mib_s mean=0.3816 cv=0.88%`
    - `avg mean=1136us cv=1.73%`
    - `p95 mean=6570us cv=3.18%`
    - `p99 mean=14335us cv=0.00%`
  - preflight:
    - `rulesTotal=4000 rangeRulesTotal=1002 subtablesTotal=8 maxRangeRulesPerBucket=21`
  - 记录文件：
    - `/tmp/iprules_on_heavy.uqb7KD/summary.json`

- `iprules_on_heavy`（`180s` 长窗口）：
  - summary:
    - `rate=0.3056 MiB/s`
    - `avg=1755us p95=10239us p99=20479us`
    - `rulesTotal=4000 rangeRulesTotal=1002`
  - log:
    - `/tmp/iprules_on_heavy_180.XLzwyJ.log`
  - 当前观察：
    - `30s` 重复窗口下，heavy 场景本身非常稳（CV 明显低于 empty 两组）
    - 但 `180s` 长窗口与 `30s` 均值差异较大，尚不能说“短窗口均值”和“长窗口单次结果”已经完全复现一致
    - `heavy 180s` 相对 `heavy 30s mean`：
      - 吞吐 `-19.91%`
      - `avg +54.44%`
      - `p95 +55.85%`
      - `p99 +42.86%`
    - 这更像是长时运行下出现了额外的热/频率/系统状态漂移，而不是 heavy 规则集本身在 30s 窗口内不稳定

- 截至目前的阶段性判断（仅记录，不下最终结论）：
  - `off_empty` vs `on_empty`：
    - 短窗口重复和 `180s` 长窗口方向一致，已经具备“可区分”的雏形
  - `on_heavy`：
    - `30s` 短窗口重复稳定性最好
    - 但拉长到 `180s` 后，结果明显下沉；说明 baseline 是否采用“短窗口多轮均值”还是“单次长窗口”仍需要继续定口径

### 2026-03-21 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ

- 夜跑矩阵：
  - runner:
    - `tests/device-modules/ip/perf_overnight_matrix.sh`
    - `tests/device-modules/ip/perf_overnight_summarize.py`
  - records:
    - `tests/device-modules/ip/records/perf-overnight-20260320T155024Z_28201JEGR0XPAJ`
  - shape:
    - warm-up: `60s x 3 scenarios`
    - main: `10` 个完整 block
    - total main runs: `120`
    - total warm-up runs: `3`
    - 每个组合（`3 scenarios x 4 durations`）各有 `10` 个样本
  - outcome:
    - 全部 main job 成功完成，无设备重启、无 ADB 断连、无脚本中途失败

- `30s`（每组 `n=10`）：
  - `off_empty`:
    - `rate=0.2835 MiB/s cv=8.87%`
    - `avg=1980us cv=11.88%`
    - `p95=10956us cv=9.90%`
    - `p99=21093us cv=7.99%`
  - `on_empty`:
    - `rate=0.2731 MiB/s cv=9.11%`
    - `avg=2007us cv=8.58%`
    - `p95=11161us cv=6.77%`
    - `p99=21298us cv=6.72%`
  - `on_heavy`:
    - `rate=0.3496 MiB/s cv=3.31%`
    - `avg=1421us cv=6.61%`
    - `p95=7935us cv=6.97%`
    - `p99=16895us cv=8.69%`

- `90s`（每组 `n=10`）：
  - `off_empty`:
    - `rate=0.2497 MiB/s cv=7.23%`
    - `avg=2350us cv=8.68%`
    - `p95=12185us cv=6.20%`
    - `p99=22527us cv=4.29%`
  - `on_empty`:
    - `rate=0.2473 MiB/s cv=5.53%`
    - `avg=2395us cv=6.81%`
    - `p95=12287us cv=6.80%`
    - `p99=22527us cv=4.29%`
  - `on_heavy`:
    - `rate=0.3173 MiB/s cv=2.07%`
    - `avg=1675us cv=3.43%`
    - `p95=9522us cv=5.19%`
    - `p99=18841us cv=4.58%`

- `180s`（每组 `n=10`）：
  - `off_empty`:
    - `rate=0.2422 MiB/s cv=6.51%`
    - `avg=2451us cv=8.31%`
    - `p95=12697us cv=6.80%`
    - `p99=23141us cv=5.97%`
  - `on_empty`:
    - `rate=0.2370 MiB/s cv=4.39%`
    - `avg=2542us cv=5.55%`
    - `p95=13106us cv=4.94%`
    - `p99=24165us cv=3.57%`
  - `on_heavy`:
    - `rate=0.2732 MiB/s cv=1.07%`
    - `avg=2079us cv=1.61%`
    - `p95=11263us cv=0.00%`
    - `p99=21298us cv=4.97%`

- `300s`（每组 `n=10`）：
  - `off_empty`:
    - `rate=0.2368 MiB/s cv=3.13%`
    - `avg=2536us cv=4.63%`
    - `p95=12901us cv=4.10%`
    - `p99=23756us cv=4.45%`
  - `on_empty`:
    - `rate=0.2321 MiB/s cv=1.88%`
    - `avg=2609us cv=3.01%`
    - `p95=13209us cv=2.45%`
    - `p99=24370us cv=2.66%`
  - `on_heavy`:
    - `rate=0.2532 MiB/s cv=0.96%`
    - `avg=2319us cv=1.44%`
    - `p95=12287us cv=0.00%`
    - `p99=22527us cv=0.00%`

- 这轮夜跑后可以确认的现象：
  - 同一 duration 内：
    - `off_empty` 与 `on_empty` 方向稳定一致：`on_empty` 总是略慢、尾延迟总是略差
    - `on_heavy` 在所有 duration 内都显著快于 empty 两组，且稳定性最好
  - 随 duration 变长：
    - 三个场景都会表现为吞吐下降、`avg/p95/p99` 上升
    - `on_heavy` 也会下沉，不再只是在单次 `180s` 上看到；说明这是 workload/设备长时运行的系统性现象，而不是那一次单独异常
  - 稳定性（CV）：
    - empty 两组在 `30s` 时 CV 大约在 `6%~12%`
    - 到 `300s` 时，empty 两组大多收敛到 `2%~5%`
    - heavy 在所有 duration 都最稳，`rate`/`avg` 的 CV 基本都在 `1%~3%`

- 当前阶段结论（仍然是 runbook 口径，不是最终 spec 结论）：
  - 如果目标是“同场景重复稳定 + 不同场景可分离”，这套 `mix` baseline 已经基本满足：
    - `off_empty` vs `on_empty`：差距较小但方向稳定
    - `on_heavy` vs empty：差距明显且稳定
  - 但“比较口径”仍需要明确：
    - `30s`、`90s`、`180s`、`300s` 不是同一个基线，它们会给出不同的绝对值与分离度
    - 若后续要固化一个标准 baseline，需要再明确到底采用哪一个 duration 作为主 gate，哪一些作为补充曲线

- 固定频率控制实验（`90s x 3 scenarios`）：
  - runner:
    - `tests/device-modules/ip/perf_fixedfreq_3way.sh`
  - records:
    - `tests/device-modules/ip/records/perf-fixedfreq-20260321T014636Z_28201JEGR0XPAJ`
  - pinning:
    - `policy0=1328000`
    - `policy4=1328000`
    - `policy6=1426000`
    - governor 全部切到 `performance`
  - restore:
    - 实验结束后已恢复到原始 `sched_pixel` + 原始 `min/max`
    - 见 `snapshot_after_pin.txt` 与 `snapshot_restored.txt`
  - result:
    - `off_empty`: `rate=0.2604 MiB/s avg=2229us p95=12287us p99=22527us`
    - `on_empty`: `rate=0.2606 MiB/s avg=2267us p95=12287us p99=22527us`
    - `on_heavy`: `rate=0.2597 MiB/s avg=2241us p95=12287us p99=22527us`
  - 与夜跑 `90s` 均值对比：
    - `off_empty` / `on_empty` 只出现小幅改善，量级约 `rate +4%~+5%`、`avg -5%`
    - 原来明显更快的 `on_heavy` 在 fixed-freq 下不再领先，反而与 empty 两组几乎完全重合
    - `on_heavy vs off_empty`（fixed-freq）：
      - `rate -0.27%`
      - `avg +0.54%`
      - `p95/p99` 完全相同
  - 当前判断：
    - “heavy 场景更快”主要不是 IPRULES workload 本身造成，更像是 governor / DVFS / 热状态与该 workload 相互作用后的结果
    - 如果要把这套测试固化成长期 baseline，后续应优先采用“固定频率 + 固定窗口 + 固定流量模板”的口径

### 2026-03-21 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ / native replay POC

- command:
  - `bash tests/device-modules/ip/native_replay_poc.sh --skip-deploy --serial 28201JEGR0XPAJ --adb "$HOME/.local/android/platform-tools/adb"`
- build path:
  - `dev/dev-build-iptest-replay.sh` fast-path succeeded
  - toolchain: `out-kernel/google/gs-6.1/prebuilts/ndk-r23/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang++`
- current default replay shape:
  - `THREADS=112`
  - `TRACE_ENTRIES=16384`
  - `SRC_PORT_SPAN=16384`
  - `TRACE_HOST_COUNT=8`
  - `TRACE_PEER_COUNT=16`
  - `TRACE_PORT_COUNT=16`
  - `TRACE_SHUFFLE=1`
  - `TRACE_SEED=1`
- latest smoke result:
  - `REPLAY_BYTES=1120000`
  - `REPLAY_CONNECTIONS=4375`
  - `REPLAY_FAILURES=0`
  - `PERF_SAMPLES=71118`
  - `PKTSTREAM_MATCH=1`
  - `METRICS.PERF.perf.nfq_total_us`: `avg=1014 p50=575 p95=3583 p99=7167 max=44256`
- conclusion:
  - native replayer 二进制已能在真机上运行
  - Tier-1 `netns+veth` 流量可由该 replayer 触发
  - `PKTSTREAM` 与 `METRICS.PERF` 都在同一轮 replay 后给出有效观测，最小闭环已跑通
  - 把 tuple-space 扩大到 `8 hosts x 16 peers x 16 dst ports`、并固定 `seed=1` 后，单纯增加 churn 本身没有显著推高吞吐，说明当前阶段的主要瓶颈更像 sender 侧发包能力，而不是 trace 规模本身
  - 当前阶段先不追求“场景分离”，而是先把 sender 发流能力尽量打高；在这个目标下，默认值已进一步提升到 `112 threads`

- early thread sweep（单轮 `10s`，同一 trace 形状）:
  - `threads=8`: `connections=2732 samples=36399 avg=1087us p95=4095us p99=7167us`
  - `threads=16`: `connections=2567 samples=37472 avg=1467us p95=5119us p99=8191us`
  - `threads=32`: `connections=3432 samples=51896 avg=1127us p95=4095us p99=7167us`
  - 当时临时选择：`32 threads`

- repeatability check（上一阶段默认场景 `5 x 10s`，固定 `TRACE_SEED=1`）:
  - `connections mean=3287.8 cv=2.22%`
  - `bytes mean=841676.8 cv=2.22%`
  - `samples mean=49759.8 cv=2.66%`
  - `avg mean=1190us cv=2.89%`
  - `p50 mean=715.8us cv=6.69%`
  - `p95 mean=4504.6us cv=4.55%`
  - `p99 mean=7167us cv=0.00%`

- sender retune（单轮 `10s`，`IPRULES=0`，用于单纯抬高 replay 压力）:
  - `threads=32 connBytes=256`: `connections=3176 samples=48037 avg=1260us p95=4607us p99=7679us`
  - `threads=64 connBytes=256`: `connections=4257 samples=68208 avg=960us p95=3583us p99=6655us`
  - `threads=96 connBytes=256`: `connections=4085 samples=67329 avg=1065us p95=3839us p99=7167us`
  - `threads=64 connBytes=64`: `connections=3876 samples=61338 avg=1049us p95=3839us p99=6655us`
  - current choice at that stage: `threads=64 connBytes=256`

- sender max-first sweep（单轮 `10s`，`IPRULES=0`，目标改为优先最大化 `samples/s`）:
  - first sweep:
    - `threads=64`: `samples=69065`（`6906.5/s`）
    - `threads=96`: `samples=69976`（`6997.6/s`，当前最高单次观察值）
    - `threads=128`: `samples=67600`（`6760.0/s`）
    - `threads=160`: `samples=66275`（`6627.5/s`）
    - `threads=192`: `samples=69649`（`6964.9/s`）
    - `threads=256`: `samples=65935`（`6593.5/s`）
  - round-robin repeat（`64/80/96/112` 各跑 3 次，交错顺序以减轻热漂移）:
    - `64`: `samples/s mean=5938.53 cv=5.62%`
    - `80`: `samples/s mean=6069.63 cv=4.59%`
    - `96`: `samples/s mean=6093.57 cv=5.69%`
    - `112`: `samples/s mean=6237.33 cv=3.00%`
  - edge check（`112/120/128`）:
    - `112`: `samples/s mean=5976.55`
    - `120`: `samples/s mean=5952.10`
    - `128`: `samples/s mean=5888.75`
  - current choice:
    - 为了“先把流量打高”，当前默认 sender 取 `threads=112 connBytes=256`
    - 这是当前最好的折中：不是最高单次尖峰，但在交错重复下均值最高，且抖动最小

- topology sweep（单轮 `10s`，固定 `threads=112 connBytes=256`）:
  - `8x16x16`（当前默认）: `samples=72733`（`7273.3/s`）
  - `8x32x32`: `samples=70259`（`7025.9/s`）
  - `8x32x64`: `samples=70864`（`7086.4/s`）
  - `16x32x32`: `samples=70364`（`7036.4/s`）
  - `16x64x32`: `samples=67409`（`6740.9/s`）
  - `16x64x64`: `samples=69616`（`6961.6/s`）
  - reading:
    - 单纯把 `host/peer/port` 组合继续放大，并没有把速率再推高
    - 当前更像是 sender / listener 路径本身先到瓶颈，而不是 tuple-space 不够大

- small-payload sweep（双轮交错，固定 `threads=112`，目标是把“小包”继续压到极限）:
  - `connBytes=1`: `samples/s mean=6464.70`
  - `connBytes=16`: `samples/s mean=6404.85`
  - `connBytes=32`: `samples/s mean=6517.25`
  - `connBytes=64`: `samples/s mean=6572.50`
  - `connBytes=128`: `samples/s mean=6447.80`
  - `connBytes=256`: `samples/s mean=6700.75`
  - reading:
    - 在当前 harness 下，把 payload 压得更小并没有带来更高的 `samples/s`
    - 相反，`256B` 仍然最好；说明当前极限已经不在“payload 还不够小”，而更可能在连接建立/监听端处理开销

- dropped experiment（原生 zero server）:
  - 试过用设备侧 native zero server 替代 `nc -L cat /dev/zero`
  - 实测 `samples` 只有约 `18k~20k / 10s`，明显差于当前 `nc` 路径的 `65k~72k / 10s`
  - 结论：这条实现路线当前不值得继续，已回退，维持 `nc` 作为 native replay 的 listener

- native replay 3-way（第一轮 `30s`，`threads=32`）:
  - runner:
    - `bash tests/device-modules/ip/native_replay_3way.sh --skip-build --serial 28201JEGR0XPAJ --seconds 30 --rules 4000`
  - records:
    - `tests/device-modules/ip/records/native-replay-3way-20260321T114646Z_28201JEGR0XPAJ`
  - result:
    - `iprules_off_empty`: `conn=9288 samples=141248 avg=1272us p95=4607us p99=7679us`
    - `iprules_on_empty`: `conn=9420 samples=143158 avg=1273us p95=4607us p99=7167us`
    - `iprules_on_heavy`: `conn=9468 samples=144004 avg=1267us p95=4607us p99=7679us`
  - reading:
    - 三组几乎重合，说明 `32-thread native replay` 还不足以把 `no-rule / empty-rule / heavy-rule` 拉开

- native replay 3-way（第二轮 `30s`，`threads=64`）:
  - runner:
    - `THREADS=64 bash tests/device-modules/ip/native_replay_3way.sh --skip-build --serial 28201JEGR0XPAJ --seconds 30 --rules 4000`
  - records:
    - `tests/device-modules/ip/records/native-replay-3way-20260321T115232Z_28201JEGR0XPAJ`
  - result:
    - `iprules_off_empty`: `conn=11941 samples=189378 avg=1050us p95=3839us p99=7167us`
    - `iprules_on_empty`: `conn=11272 samples=179767 avg=1095us p95=4095us p99=7167us`
    - `iprules_on_heavy`: `conn=12215 samples=195677 avg=1014us p95=3839us p99=6655us`
  - reading:
    - `on_empty` 相对 `off_empty` 已经出现可见差异（大约 `connections -5.6%`、`avg +4.3%`）
    - 但 `on_heavy` 仍然比 `off_empty` 更快，方向不对，说明这套 native replay workload 还没有成为可直接 gate 的 baseline

- native replay 3-way（第三轮 `30s`，`threads=112`，先把 sender 打高后再看分离）:
  - runner:
    - `bash tests/device-modules/ip/native_replay_3way.sh --skip-build --serial 28201JEGR0XPAJ --seconds 30 --rules 4000`
  - records:
    - `tests/device-modules/ip/records/native-replay-3way-20260321T122220Z_28201JEGR0XPAJ`
  - result:
    - `iprules_off_empty`: `conn=12313 samples=197953 avg=1069us p95=4095us p99=7679us`
    - `iprules_on_empty`: `conn=10621 samples=171454 avg=1229us p95=4607us p99=8191us`
    - `iprules_on_heavy`: `conn=12238 samples=200293 avg=1067us p95=4095us p99=7167us`
  - reading:
    - 把 sender 提升到 `112 threads` 后，`on_empty` 相对 `off_empty` 的差异被明显放大（约 `connections -13.7%`、`samples -13.4%`、`avg +15.0%`）
    - 但 `on_heavy` 仍几乎回到 `off_empty`，说明“先把流量打高”这个方向是对的，但当前 heavy ruleset 语料仍不足以形成稳定、方向正确的慢化

- current reading:
  - native sender 这条线已经跑通，并且当前优先级应先放在“把流量打高”
  - 按这个口径，`112 threads` 是当前更合理的默认值；后续所有场景分离实验都应先建立在这组更强 sender 上
  - sender 上限顶高以后，`off_empty -> on_empty` 的差距已经开始足够明显；接下来应聚焦 why `on_heavy` 没有继续变慢
  - 换句话说，当前矛盾已经从“流量不够强”转成了“heavy 规则语料/命中形态不对”

### 2026-03-21 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ / neper POC（udp_stream / tcp_crr）

- 目标：
  - 把短流量（尤其是 UDP 小包）推到足够高，能“打穿”现有 `iptest-replay + nc` harness 的 sender ceiling
  - 用更强的 replayer 把 NFQUEUE / D-layer 的真实瓶颈暴露出来
  - 顺便确认 neper 自带统计口径是否可作为“只看打流端结果”的 baseline（暂不依赖 sucre-snort 的 METRICS）

- neper 能力确认（结论：大体满足，但我们的 harness 还没把 knobs 全用起来）：
  - 自带统计：neper 会输出 `key=value` 统计（如 `remote_throughput`、`throughput`、`num_transactions`，以及 rr/crr 的直方图/percentiles；并支持 `-A/--all-samples` 导出 CSV、`--log-rtt` 导出逐 transaction RTT）。
  - 大量短 TCP：`tcp_crr` 的语义就是“每次 transaction 建立新连接”，符合“短连接/短请求”的 workload；并且支持 `-T/--num-threads` + `-F/--num-flows` 放大并发。
  - 五元组变化：
    - 已有：多 flows 会天然引入不同 `sport`（TCP/UDP），UDP 还会按 flow 分配连续 `dport`（server side）。
    - 可用但尚未接入脚本：`-L/--local-hosts` 可按 flow round-robin bind 不同源 IP；TCP 的 `--num-ports` 可 round-robin 连接不同 `dport`（需要 server 同时 listen 多个端口）。
    - 不内置：单进程内“每个 flow 不同 dst IP”不支持（`-H` 只有一个 host）。要覆盖 `dip` 维度需跑多进程（多组 server/client，每组绑定不同 peer IP）。
  - UID 变化：neper 不会自己变 UID（这是进程属性）；需要在 Android 上通过 `su <uid> ...` 并行/串行起多个 client 进程（同时要为每个 uid 做 tier1 的 policy routing 注入）。

- runner（UDP，小包优先）：
  - `bash tests/device-modules/ip/neper_poc.sh --skip-deploy --serial 28201JEGR0XPAJ --adb "$HOME/.local/android/platform-tools/adb" --mode udp --seconds 10 --threads 8 --flows 1024 --bytes 64 --iprules 0`
  - records: `tests/device-modules/ip/records/neper-poc-*_28201JEGR0XPAJ`

- current finding（“offered load vs 可完整观测”的分界）：
  - `neper_poc.sh` 输出的 `perf/seq_ratio` 本质是“观测覆盖率”：
    - `perf_samples` = `METRICS.PERF.perf.nfq_total_us.samples`（D-layer 实际观测到的包数）
    - `nfq_seq_total` = `/proc/net/netfilter/nfnetlink_queue` 里 per-queue `seq` 的增量汇总（进入 NFQUEUE 的包数）
    - `perf/seq_ratio ~= 1`：基本能完整观测，`METRICS.PERF` 分布有意义
    - `perf/seq_ratio << 1`：进入过载区，大量包未被 D-layer 完整观测（不适合作为性能 baseline）
  - overload 示例（UDP offered load 极高，覆盖率极低）：
    - command:
      - `bash tests/device-modules/ip/neper_poc.sh --skip-build --skip-deploy --serial 28201JEGR0XPAJ --adb "$HOME/.local/android/platform-tools/adb" --mode udp --seconds 1 --threads 8 --flows 1024 --bytes 64 --delay-ns 0 --iprules 0`
    - result（`summary.txt`）：
      - `perf_samples=6482`
      - `nfq_seq_total=529819`
      - `perf/seq_ratio=0.012234`
      - `nfq_top=q7:529792,...`
  - 可完整观测示例（通过 `--delay-ns` 降低 offered load，把覆盖率拉回 1 左右）：
    - command:
      - `bash tests/device-modules/ip/neper_poc.sh --skip-build --skip-deploy --serial 28201JEGR0XPAJ --adb "$HOME/.local/android/platform-tools/adb" --mode udp --seconds 1 --threads 2 --flows 4 --bytes 64 --delay-ns 60000 --iprules 0`
    - result（`summary.txt`）：
      - `perf_samples=12470`
      - `nfq_seq_total=12496`
      - `perf/seq_ratio=0.997919`
      - `nfq_top=q7:12476,...`

- notes：
  - `neper_poc.sh` 会保存 `/proc/net/netfilter/nfnetlink_queue` 的 before/after（`nfq_before.txt` / `nfq_after.txt`）用于判断是否出现 queue drop / fail-open / bypass 类“过载非线性”。
  - 当进入过载区时，“瓶颈”可能已经不是流量发生器，而是 NFQUEUE + D-layer 处理链路（其中也包括 `PERFMETRICS` 的每包 `clock_gettime()` + 原子直方图更新开销）；因此当前阶段把 `--delay-ns` 作为“把系统拉回可测范围”的第一手旋钮。

- status（当前瓶颈怀疑点：统计/观测链路跟不上）：
  - 现象：在极高 offered load 下，`nfq_seq_total` 可以到几十万/秒量级，但 `perf_samples` 只有几千/秒；`perf/seq_ratio` 急剧下降。
  - 解读：这更像是“系统已进入过载区”而不是“流量发生器不够强”；此时 `METRICS.PERF` 统计口径很可能已经被 D-layer / 统计更新开销本身所限，不能直接用作 baseline gate。
  - 影响：接下来要同时追两个目标：
    - 继续把 sender ceiling 往上推（已通过 neper 明显提升）
    - 同时把系统拉回“可完整观测区”（`perf/seq_ratio ~= 1`）并在这个区间内找一个尽量高的稳定 baseline

- next（用于回答“是不是 PERFMETRICS/统计组件跟不上”）：
  - `/proc/net/netfilter/nfnetlink_queue` 字段语义确认（man7 `proc_pid_net(5)`）：(6) `queue_dropped`、(7) `user_dropped`、(8) `sequence number`（最近一次排队的包 ID），最后一列恒为 `1`；`neper_poc.sh` 已按该语义解析并在 `summary.txt` 输出 `nfq_queue_dropped_total` / `nfq_user_dropped_total`，用于区分 drop vs fail-open/bypass。
  - PERFMETRICS A/B：同一 neper workload 下对比 `PERFMETRICS=0` vs `PERFMETRICS=1`（`neper_poc.sh --perfmetrics 0|1`），观察（1）`nfq_*_dropped_total` 是否显著变化（2）系统是否能进入更高的“可完整观测”阈值（3）CPU 占用/吞吐是否显著变化（PERFMETRICS=0 时 `METRICS.PERF` 为全 0，ratio 仅作为“关闭态”标记）。
  - 队列分布：当前 overload 示例里 `nfq_top` 极度倾斜到单队列（`q7`）；需要通过（flows/tuple 随机化、端口策略等）把 `balance 4:7` 的分布打散，再重新测 “可完整观测上限”。

- baseline 合约（共识，用于后续 gate；不是“真实流量模拟”）：
  - 目标：用“打穿 cache 的极限短 TCP/UDP 流量模型”稳定拉开 `IPRULES=0`、`IPRULES=1 + 2k rules`、`IPRULES=1 + 4k rules` 的性能差距，用于评估后续功能/优化改动（相对变化为主）。
  - 判定原则：
    - **稳定性优先**：在 CPU 定频、背景负载可控、内存状态接近的前提下，同一场景多次重复的吞吐/txns 波动应显著小于不同场景之间的差距。
    - **单调性**：期望 `off > 2k > 4k`，且差距越明显越好（便于作为长期回归基线）。
  - cache-buster 口径（避免“热缓存掩盖差异”）：
    - IpRulesEngine 的 thread-local 决策 cache 为 `1024` 直映（`PacketKeyV4`：uid/dir/ifaceKind/proto/ifindex/srcIp/dstIp/srcPort/dstPort）。
    - 因此 workload 必须保证每个处理线程看到的 `PacketKeyV4` 基数显著大于 `1024`（例如通过大量 flows、端口/地址池、以及短连接不断更换 srcPort 等），否则很容易出现“2k/4k 拉不开”的假阴性。

### 2026-03-22 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ / neper perf 3-way（off vs 2k vs 4k，TCP_CRR）

- 目的（这不是“真实流量模拟”）：
  - 追求一个 **cache-buster 极限短流量基线**，用来稳定拉开 `off > 2k > 4k`，便于后续任何改动（功能/并发/优化）都能在同一口径下比较差异。
  - 主指标优先选择“打流端”的真实吞吐（txns/s），避免把 `PERFMETRICS`/直方图本身的开销混进 baseline（后续可以再单独做 A/B）。

- runner:
  - quick smoke（5s，主要用于验证脚本闭环）：
    - `bash tests/device-modules/ip/neper_perf_3way.sh --seconds 5 --threads 8 --flows 1024 --bytes 1 --num-ports 16 --perfmetrics 0`
  - baseline candidate（>=30s；推荐 warmup/cooldown 降低顺序效应）：
    - `bash tests/device-modules/ip/neper_perf_3way.sh --seconds 30 --warmup 10 --cooldown 30 --threads 8 --flows 1024 --bytes 1 --num-ports 16 --uid 2000 --perfmetrics 0`
  - cache-buster strengthen（扩大 `srcIp` 基数，优先用于放大 `off vs 2k`）：
    - `bash tests/device-modules/ip/neper_perf_3way.sh --seconds 30 --warmup 10 --cooldown 30 --threads 8 --flows 1024 --bytes 1 --num-ports 16 --uid 2000 --local-host-count 8 --perfmetrics 0`
  - knobs（`neper_perf_3way.sh --help`）：
    - `--seconds`：每个场景的测量窗口（建议 `30s/90s`；`5s` 更像是 smoke）
    - `--warmup`：在测量前跑一段 `iprules_off` warmup（不作为对比数据，只用于把系统拉到较稳定状态）
    - `--cooldown`：场景间 sleep（降低 DVFS/热状态导致的顺序效应）
    - `--uid`：traffic UID（默认 `2000`）
    - `--local-host-count`：扩展 `srcIp` 基数（Tier‑1 会把额外 IP 加到 veth；client 用 neper `-L` 按 flow 轮换 bind）
  - records:
    - `tests/device-modules/ip/records/neper-perf-3way-*_28201JEGR0XPAJ`

- workload（TCP_CRR，短连接/短请求）：
  - 流量发生器：neper `tcp_crr`（每次 transaction 建立新连接，天然 churn `srcPort`，更适合作为“打穿 cache 的短流量”）。
  - offered load 旋钮（都在 runner 参数里）：
    - `--threads`：neper threads（客户端/服务端都使用该值）
    - `--flows`：并发 flows
    - `--num-ports`：server data ports 数量；client 以 `flow_idx % num_ports` round-robin 连接不同 `dstPort`
    - `--bytes`：`request_size/response_size`（尽量小，避免 payload 吞吐主导）
  - tuple 维度（对应 `PacketKeyV4`）：
    - 当前 baseline 固定：`uid`（默认 `2000`）、`proto=tcp`、`ifindex=veth`、`dstIp=10.200.1.2`
    - 当前 churn：`srcPort`（短连接 + 多 flows）、`dstPort`（`--num-ports`）
    - 可扩展（部分已并入 baseline runner）：
      - `srcIp`：`neper_perf_3way.sh --local-host-count N [--local-host-base-octet X]`（Tier‑1 通过 `IPTEST_HOST_IP_POOL` 把额外 IP 加到 veth；client 通过 neper `-L` 每 flow bind 不同源 IP）
      - `dstIp`：需要多进程/多 peer IP（neper `-H` 单进程只有一个 host）
      - `uid`：需要多进程 `su <uid>` 并行（同时要为每个 uid 做 Tier‑1 policy route 注入）

- guardrails（避免“过载区/非线性”污染 baseline）：
  - 每个场景保存 `/proc/net/netfilter/nfnetlink_queue` before/after，并输出增量：
    - `nfq_queue_dropped_total` / `nfq_user_dropped_total` 应当为 `0`
    - `nfq_top` 不应长期极端倾斜到单队列（否则容易出现“单队列瓶颈/调度噪声”）

- 设计要点：
  - **统计口径**：主指标用 neper 自带 `throughput (tps)`，不依赖 `METRICS.PERF`（本轮 `PERFMETRICS=0`），NFQUEUE 只作为 guardrail（`/proc/net/netfilter/nfnetlink_queue` 的 `seq/qdrop/udrop` 增量）。
  - **规则语料 shape（为“拉开差距”而非模拟真实）**：
    - 受限于硬上限：`maxRangeRulesPerBucket <= 64`、`maxSubtablesPerUid <= 64`。
    - 2K：`32 subtables * 64 range candidates/bucket = 2048 rules`
    - 4K：`64 subtables * 64 range candidates/bucket = 4096 rules`
    - subtable 形状（为什么能稳定“按规则规模线性变慢”）：
      - subtable 的 mask 由 `(srcPrefix,dstPrefix)` 组合构成（从 `8x8=64` 个组合里取前 N 个）。
      - traffic packet 在每个 subtable 里都会落到同一个 bucket（maskedKey 可命中），从而每个 subtable 都有稳定的 per-packet 扫描成本。
      - 每个 subtable 的 `maxWouldPriority` 相同，因此 `lookupBestWould()` 不会因为已有 bestPriority 而提前 break，强制遍历所有 subtables（2K=32 subtables，4K=64 subtables）。
    - 每个 bucket 内：
      - `63` 条永不命中的 range 规则：`dport=1-19999`（traffic 端口 base>=20000）
      - `1` 条兜底命中规则：`dport=0-65535`
      - 通过 `priority` 让兜底规则排在最后，从而逼迫每次判决扫描完整 `64` 个 range candidates。
    - rule 语义：全部为 would-block（`action=block log=1 enforce=0`），避免改变网络语义（不真实 DROP）。
      - 这样可以只引入判决成本，不改变最终 accept/drop；同时避免 `enforce allow` 导致路径短路（曾出现 “heavy 反而更快” 的失真）。
  - **加速加载**：使用单连接 batch 控制客户端 `tests/device-modules/ip/tools/snortctl.py`（避免每条 rule 一个 python+socket 的慢路径）。

- records 目录结构（`neper-perf-3way-*`）：
  - `results.jsonl`：每场景一行 JSON（便于后续汇总/画图；若启用 `--warmup` 还会额外包含 `warmup_off`）
    - line shape（示例）：
      - `{"scenario":"iprules_off","knobs":{"seconds":30,"threads":8,"flows":1024,"num_ports":16,"bytes":1,"uid":2000,"local_host_count":1,"local_host_base_octet":101},"neper":{"throughput_tps":3235.07,"num_transactions":97052},"nfq":{"seq_total":123456,"queue_dropped_total":0,"user_dropped_total":0}}`
  - per-scenario：
    - `${scenario}_client.txt` / `${scenario}_server.txt`：neper stdout
    - `${scenario}_nfq_before.txt` / `${scenario}_nfq_after.txt`：NFQUEUE 采样
    - `${scenario}_summary.txt`：关键指标提取（neper + nfq delta）
  - per-install：
    - `${label}_preflight_before.json` / `${label}_preflight_after.json`：复杂度报告快照（确认 subtables/bucket 形状）

- 快速汇总（从 `results.jsonl` 计算 deltas/单调性；替换 records_dir 即可）：

  - 推荐：对多轮 records 直接汇总（mean/cv + 单调性比例）：
    - `python3 tests/device-modules/ip/tools/summarize_neper_perf_3way.py tests/device-modules/ip/records/neper-perf-3way-*_28201JEGR0XPAJ`

```bash
python3 - <<'PY'
import json
from pathlib import Path

records_dir = Path("tests/device-modules/ip/records/neper-perf-3way-20260322T072145Z_28201JEGR0XPAJ")
rows = [json.loads(line) for line in (records_dir / "results.jsonl").read_text().splitlines() if line.strip()]
by = {r["scenario"]: r for r in rows}

def pct(a, b):
    return None if b == 0 else (a - b) / b * 100.0

off = by["iprules_off"]["neper"]["throughput_tps"]
k2 = by["iprules_2k"]["neper"]["throughput_tps"]
k4 = by["iprules_4k"]["neper"]["throughput_tps"]
print("throughput_tps:", {"off": off, "2k": k2, "4k": k4})
print("delta_pct:", {"2k_vs_off": pct(k2, off), "4k_vs_off": pct(k4, off), "4k_vs_2k": pct(k4, k2)})
print("monotonic_off_gt_2k_gt_4k:", (off > k2 > k4))
PY
```

- 结果（neper throughput, tps；越高越好）：
  - `off (IPRULES=0)`：`3166.99`
  - `2k (IPRULES=1 + 2048 rules)`：`3102.64`
  - `4k (IPRULES=1 + 4096 rules)`：`2997.05`
  - reading：
    - 单调性：`off > 2k > 4k`
    - 差距（该参数/窗口下，约）：`2k_vs_off -2%`、`4k_vs_off -5%`（差距仍偏小，后续目标是把“差距/稳定性比”继续拉大）

- follow-up（更高 offered load，短窗口可能进入噪声区）：
  - runner:
    - `bash tests/device-modules/ip/neper_perf_3way.sh --seconds 5 --threads 16 --flows 2048 --bytes 1 --num-ports 64 --perfmetrics 0`
  - records:
    - `tests/device-modules/ip/records/neper-perf-3way-20260322T072437Z_28201JEGR0XPAJ`
  - throughput：
    - `off`：`3363.30`
    - `2k`：`3425.02`（轻微反转，疑似短窗口噪声/热状态/调度影响）
    - `4k`：`3182.18`
  - reading：当把 offered load 拉高后，`off vs 2k` 在 `5s` 级别的窗口可能被噪声吞没；应切到更长窗口（>=30s）并配合定频/冷却，才能作为长期 baseline。

- 30s 窗口复跑（同一组 offered load，观察 off vs 2k 是否仍会被噪声吞没）：
  - runner:
    - `bash tests/device-modules/ip/neper_perf_3way.sh --seconds 30 --threads 8 --flows 1024 --bytes 1 --num-ports 16 --perfmetrics 0`
  - records:
    - `tests/device-modules/ip/records/neper-perf-3way-20260322T092843Z_28201JEGR0XPAJ`
  - throughput：
    - `off`：`3235.07`
    - `2k`：`3239.36`（仍然非常接近，且再次轻微反转）
    - `4k`：`2960.57`
  - reading：
    - `off vs 2k` 目前仍在噪声/漂移量级（<0.2%），需要重复 N 轮统计 + 定频/冷却 +（可能）打乱场景顺序来稳定结论。
    - `4k` 在该窗口下已能显著变慢（约 `-8.5%`），说明 ruleset shape 本身确实在产生可测成本。

- multi-round 复核（本轮尝试把 `srcIp` 基数扩大到 8，观察是否更容易拉开差距）：
  - runner:
    - `bash tests/device-modules/ip/neper_perf_matrix.sh --rounds 3 --seconds 30 --warmup 10 --cooldown 30 --threads 8 --flows 1024 --bytes 1 --num-ports 16 --local-host-count 8 --perfmetrics 0`
  - output:
    - `tests/device-modules/ip/records/neper-perf-matrix-20260322T095913Z_28201JEGR0XPAJ`
  - summary（throughput_tps；mean/cv；越高越好）：
    - `off`: `mean=2921.75 cv=3.90%`
    - `2k`: `mean=3089.45 cv=3.40%`
    - `4k`: `mean=3061.54 cv=4.38%`
    - monotonic `off > 2k > 4k`: `1/3`
  - reading：
    - 在 DVFS 未固定的情况下，`IPRULES=1` 场景会触发更高频率/更积极调度，从而出现 “2k/4k 反而更快” 的现象；这会掩盖规则判决成本。
    - 这进一步确认：若要把该 baseline 固化为长期 gate，必须优先引入 **CPU 定频**（并保留 cooldown/顺序随机化），否则 “off > 2k > 4k” 无法稳定成立。

- CPU 定频实验（先验证“定频后，方差能否显著收敛”，再看分离度）：
  - runner（wrapper 会 pin freq + 运行 matrix + 结束后 restore）：
    - `bash tests/device-modules/ip/neper_perf_fixedfreq_matrix.sh --matrix-mode scenario --serial 28201JEGR0XPAJ --settle 10 --freq0 1328000 --freq4 1328000 --freq6 1426000 -- --rounds-per-scenario 2 --seconds 30 --warmup 10 --cooldown-job 10 --threads 8 --flows 1024 --bytes 1 --num-ports 16 --local-host-count 8 --perfmetrics 0`
  - output:
    - `tests/device-modules/ip/records/neper-perf-fixedfreq-matrix-20260322T102821Z_28201JEGR0XPAJ`
  - summary（throughput_tps；mean/cv）：
    - `off`: `mean=1640.38 cv=0.49%`
    - `2k`: `mean=1636.57 cv=0.24%`
    - `4k`: `mean=1658.35 cv=0.58%`
  - reading：
    - 定频后 CV 会显著收敛（<1%），说明“控制变量”这条路是对的。
    - 但在该 offered load 下，`2k/4k` 的差距仍然很小，且 `4k` 甚至略快；需要继续做 offered load sweep，找一个能把规则判决成本放大的区间（否则无法把 `2k > 4k` 稳定拉开）。

### 2026-03-22 / Pixel 6a (Android 16) / serial 28201JEGR0XPAJ / neper perf 3-way（off vs 2k vs 4k，UDP_STREAM）

- 为什么需要这条线（相对 TCP_CRR）：
  - TCP_CRR 的“每次 transaction 建新连接”会引入大量 TCP/epoll/accept/握手等成本；当 rule-eval 成本不够大时，容易被这些成本淹没，导致 `2k vs 4k` 难以稳定拉开。
  - UDP_STREAM 更接近“每包/每次 send 的 rule-eval 成本”，更容易放大差距（代价是需要通过 `--delay-ns` 把系统拉回可测范围，避免 NFQUEUE/D-layer 过载非线性）。

- runner（初始参数；5s 主要用于 smoke + 快速看方向，后续必须拉长窗口并多轮统计）：
  - `bash tests/device-modules/ip/neper_udp_perf_3way.sh --seconds 5 --threads 8 --flows 1024 --bytes 64 --delay-ns 60000 --perfmetrics 0`
- records：
  - `tests/device-modules/ip/records/neper-udp-perf-3way-20260322T105728Z_28201JEGR0XPAJ`
- 指标口径（重要，避免误读）：
  - `neper.remote_throughput`（或 `local_throughput`）是 **raw bits/s**（见 neper `control_plane.c` 的注释 “bits/s or trans/s”）。
  - `throughput_opt=Mb` 只是“显示单位”的选项；但在 `udp_stream` 下我们主要读取 `remote_throughput`，因此建议阅读时把它换算成 `Mb/s = bps / 1e6`。
- result（bps；括号内为 Mb/s）：
  - `off`: `10167101`（`10.167`）
  - `2k`: `9465358`（`9.465`）
  - `4k`: `9170903`（`9.171`）
  - deltas：
    - `2k_vs_off`: `-6.90%`
    - `4k_vs_off`: `-9.78%`
    - `4k_vs_2k`: `-3.11%`
  - monotonic：`off > 2k > 4k`
  - guardrails：三组场景 `nfq_queue_dropped_total=0` 且 `nfq_user_dropped_total=0`（未进入 drop/非线性区）

- current reading：
  - 在“同一组 knobs + 同一设备状态”的前提下，UDP_STREAM 已经能更稳定地产生“方向正确 + 差距更明显”的 3-way 分离（相对 TCP_CRR）。
  - 因此下一步应把 **UDP_STREAM** 提升为主 baseline 候选，并用“定频 + scenario matrix + 多轮统计”确认它是否满足长期 gate 的稳定性要求。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=60000`）：
  - runner:
    - `bash tests/device-modules/ip/neper_udp_perf_fixedfreq_matrix.sh --serial 28201JEGR0XPAJ --matrix-mode scenario --settle 10 --freq0 1328000 --freq4 1328000 --freq6 1426000 -- --rounds-per-scenario 3 --seconds 30 --warmup 10 --cooldown-job 10 --threads 8 --flows 1024 --bytes 64 --delay-ns 60000 --perfmetrics 0`
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T111436Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=9252299 cv=1.36%`（`9.252`）
    - `2k`: `mean=9010229 cv=0.47%`（`9.010`）
    - `4k`: `mean=8813448 cv=0.64%`（`8.813`）
    - deltas：
      - `2k_vs_off`: `-2.62%`
      - `4k_vs_off`: `-4.74%`
      - `4k_vs_2k`: `-2.18%`
  - reading：
    - “定频 + scenario matrix”下方差已经足够低（CV 基本 < 2%），且方向稳定为 `off > 2k > 4k`。
    - 但差距还不够大（off vs 4k ~5%）；下一步优先做 `delay-ns` sweep，把 offered load 往上推、同时维持 `nfq_*_dropped_total=0`，争取把差距进一步拉大。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=30000`；更高 offered load）：
  - runner:（同上，只调整 `--delay-ns 30000`）
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T112704Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=16049401 cv=2.34%`（`16.049`）
    - `2k`: `mean=15612350 cv=2.56%`（`15.612`）
    - `4k`: `mean=15622460 cv=1.57%`（`15.622`）
    - deltas：
      - `2k_vs_off`: `-2.72%`
      - `4k_vs_off`: `-2.66%`
      - `4k_vs_2k`: `+0.06%`（几乎重合）
    - `monotonic_off_gt_2k_gt_4k_by_index`: `2/3`
  - reading：
    - `delay-ns=30000` 虽然吞吐更高，但 `2k vs 4k` 差距几乎消失，且单调性不稳定；说明“最大化吞吐”并不等价于“最大化分离度”。
    - 结论：`delay-ns=30000` 暂不适合作为长期 baseline；后续 sweep 应更关注“分离度/稳定性”而非单纯吞吐。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=45000`；中间档复测）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T150245Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=10484511 cv=0.48%`（`10.485`）
    - `2k`: `mean=10342302 cv=0.50%`（`10.342`）
    - `4k`: `mean=9559234 cv=0.78%`（`9.559`）
    - deltas：
      - `2k_vs_off`: `-1.36%`
      - `4k_vs_off`: `-8.83%`
      - `4k_vs_2k`: `-7.57%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `3/3`
  - reading：
    - 中间档 `delay-ns=45000` 重新恢复并显著放大了 `2k vs 4k` 的差距，同时保持低 CV（< 1%）与单调性（`3/3`）。
    - 截止目前，这组参数是 UDP baseline 最有希望固化为长期 perf gate 的候选（比 `60000` 分离度更大，且没有 `30000` 的塌缩问题）。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=50000`；围绕 45000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T151247Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=9879724 cv=0.98%`（`9.880`）
    - `2k`: `mean=9537626 cv=1.98%`（`9.538`）
    - `4k`: `mean=9360759 cv=0.24%`（`9.361`）
    - deltas：
      - `2k_vs_off`: `-3.46%`
      - `4k_vs_off`: `-5.25%`
      - `4k_vs_2k`: `-1.85%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `3/3`
  - reading：
    - `delay-ns=50000` 的分离度更“均衡”（`off vs 2k` 更明显，但 `2k vs 4k` 变小），CV 仍可接受。
    - 与 `45000` 相比：`45000` 更像是在放大“规则规模（2k→4k）差异”，`50000` 更像是在放大“开关/规则开销（off→2k）差异”。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=40000`；继续围绕 45000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T152212Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=11945789 cv=1.52%`（`11.946`）
    - `2k`: `mean=11867877 cv=2.74%`（`11.868`）
    - `4k`: `mean=10835130 cv=5.98%`（`10.835`）
    - deltas：
      - `2k_vs_off`: `-0.65%`
      - `4k_vs_off`: `-9.30%`
      - `4k_vs_2k`: `-8.70%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `1/3`
  - reading：
    - `4k` 的 slow-down 很明显（~9%），但 `off vs 2k` 过近，且 per-round 单调性较差、`4k` 的 CV 偏大（~6%）。
    - 截止目前，这组 knobs 更像是“能放大 4k”但稳定性不足；目前优先考虑 `delay-ns=43000/45000` 这种 CV 更低且单调性更好的点。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=42000`；继续围绕 43000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260323T010643Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=11206815 cv=1.14%`（`11.207`）
    - `2k`: `mean=10831021 cv=3.83%`（`10.831`）
    - `4k`: `mean=10105198 cv=0.81%`（`10.105`）
    - deltas：
      - `2k_vs_off`: `-3.35%`
      - `4k_vs_off`: `-9.83%`
      - `4k_vs_2k`:  `-6.70%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `2/3`
  - reading：
    - 分离度与单调性都不如 `43000/45000`，且 `2k` 的 CV 偏高；该点不适合作为主 baseline。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=43000`；继续围绕 45000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T154343Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=11052113 cv=0.72%`（`11.052`）
    - `2k`: `mean=10840225 cv=0.98%`（`10.840`）
    - `4k`: `mean=9602234 cv=1.37%`（`9.602`）
    - deltas：
      - `2k_vs_off`: `-1.92%`
      - `4k_vs_off`: `-13.12%`
      - `4k_vs_2k`: `-11.42%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `3/3`
  - reading：
    - 截止目前最“理想”的点：方差低（CV ~1%）+ 单调性满分（`3/3`）+ `2k→4k` 分离度最大（~11%）。
    - 先把它作为 UDP baseline 的主候选（后续再用更多 rounds/更长窗口复核）。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=5`，`delay-ns=43000`；稳定性复核）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T155402Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=10968766 cv=2.47%`（`10.969`）
    - `2k`: `mean=10794200 cv=1.58%`（`10.794`）
    - `4k`: `mean=9697174 cv=1.32%`（`9.697`）
    - deltas：
      - `2k_vs_off`: `-1.59%`
      - `4k_vs_off`: `-11.59%`
      - `4k_vs_2k`: `-10.16%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `4/5`
  - reading：
    - 分离度保持在 ~10% 量级，并且 per-round 单调性满足 `>=80%` 的预期目标（`4/5`）。
    - 这轮 `off` 的 CV 偏高（~2.5%），更像是某一次 sample 受系统瞬态影响；已补一轮 `seconds=60` 复核（见下方），`off` 的 CV 收敛到 ~1%。

- CPU 定频 + scenario matrix（`60s`，每个场景 `n=3`，`delay-ns=43000`；长窗口复核）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260323T005014Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=11089214 cv=1.05%`（`11.089`）
    - `2k`: `mean=10789044 cv=0.59%`（`10.789`）
    - `4k`: `mean=9716761 cv=0.94%`（`9.717`）
    - deltas：
      - `2k_vs_off`: `-2.71%`
      - `4k_vs_off`: `-12.38%`
      - `4k_vs_2k`:  `-9.94%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `3/3`
  - reading：
    - 60s 窗口下仍保持“低方差 + 单调 + 大分离度”（`off > 2k > 4k` 且 `3/3`），说明 `delay-ns=43000` 不只是 30s 的偶然点。

- CPU 定频 + scenario matrix（`60s`，每个场景 `n=5`，`delay-ns=43000`；更严的稳定性复核）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260323T013903Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=11075923 cv=0.56%`（`11.076`）
    - `2k`: `mean=10811018 cv=1.41%`（`10.811`）
    - `4k`: `mean=9969492 cv=1.73%`（`9.969`）
    - deltas：
      - `2k_vs_off`: `-2.39%`
      - `4k_vs_off`: `-9.99%`
      - `4k_vs_2k`:  `-7.78%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `5/5`
  - reading：
    - 这轮把 “60s + 多轮” 都拉满后仍保持低 CV 与 `5/5` 单调性；可以把 `delay-ns=43000` 视为当前阶段的 baseline v1。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=44000`；继续围绕 43000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260323T011738Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=10508123 cv=0.50%`（`10.508`）
    - `2k`: `mean=10378755 cv=0.92%`（`10.379`）
    - `4k`: `mean=9462473 cv=1.64%`（`9.462`）
    - deltas：
      - `2k_vs_off`: `-1.23%`
      - `4k_vs_off`: `-9.95%`
      - `4k_vs_2k`:  `-8.83%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `3/3`
  - reading：
    - 稳定且单调性 OK，但 `2k→4k` 分离度明显小于 `43000`；因此仍优先 `43000`。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=47000`；继续围绕 45000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260322T153350Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=10130950 cv=0.66%`（`10.131`）
    - `2k`: `mean=9664344 cv=1.79%`（`9.664`）
    - `4k`: `mean=9402050 cv=1.39%`（`9.402`）
    - deltas：
      - `2k_vs_off`: `-4.61%`
      - `4k_vs_off`: `-7.19%`
      - `4k_vs_2k`: `-2.71%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `2/3`
  - reading：
    - `off vs 2k` 的差距比 `45000` 更明显，但 `2k vs 4k` 差距明显变小，且单调性不如 `45000/50000` 稳。
    - 整体更接近“放大 off→2k（开关/规则开销）差异”的点，而不是“放大 2k→4k（规则规模）差异”的点。

- CPU 定频 + scenario matrix（`30s`，每个场景 `n=3`，`delay-ns=48000`；继续围绕 43000 的局部 sweep）：
  - output:
    - `tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260323T012738Z_28201JEGR0XPAJ`
  - summary（bps；括号内为 Mb/s；mean/cv）：
    - `off`: `mean=10109751 cv=2.78%`（`10.110`）
    - `2k`: `mean=9744964 cv=1.11%`（`9.745`）
    - `4k`: `mean=9454902 cv=1.44%`（`9.455`）
    - deltas：
      - `2k_vs_off`: `-3.61%`
      - `4k_vs_off`: `-6.48%`
      - `4k_vs_2k`:  `-2.98%`
    - `monotonic_off_gt_2k_gt_4k_by_index`: `3/3`
  - reading：
    - offered load 偏低导致 `2k→4k` 分离度明显塌缩（~3%）；该点不适合作为 baseline。

- next（按当前 plan 继续：先把 baseline contract 写清楚，再跑更多数据）：
  - 1) 基线口径（推荐）：把“主 baseline”切到 UDP_STREAM，并补齐对应的 matrix runner：
    - `neper_udp_perf_scenario_matrix.sh`：每个场景独立 job（fresh `RESETALL` + warmup），并做 deterministic shuffle，避免顺序 bias。
    - `neper_udp_perf_fixedfreq_matrix.sh`：pin freq + 跑 scenario matrix + restore（降低方差；把差距留给 rule-eval）。
  - 2) 稳定性判定（建议先用 record-first 口径，不先写死阈值 gate）：
    - 定频后，同一场景重复多轮的 `throughput` CV 应明显小于跨场景差距（目标：CV < 1%~2%）。
    - 多轮中 `off > 2k > 4k` 的比例应足够高（目标：>= 80%），否则 baseline 不够稳。
      - 说明：对 `scenario matrix`（每个样本只包含单一场景），用 `summarize_neper_perf_3way.py` 输出的 `monotonic_off_gt_2k_gt_4k_by_index` 作为该比例的 best-effort 估计。
    - 全部样本必须满足 guardrails：`nfq_*_dropped_total=0`（进入 drop 区直接判为“该 knobs 无效”）。
  - 3) offered load sweep（优先扫 `delay-ns`）：
    - 在 guardrails 满足下逐步降低 `delay-ns`，把吞吐推到“尽量高但仍可测”的区间；目标是同时放大 `2k vs 4k` 差距与保持低 CV。
    - 经验：`delay-ns` 与分离度的关系并非单调（`30000` 反而塌缩），应围绕“分离度更好的点”做局部 sweep。
    - 已完成围绕 `45000` 的局部 sweep：`50000/48000/47000/45000/44000/43000/42000/40000`（见上方记录）；目前倾向把 `43000` 作为主 baseline 候选。
    - 已完成 `seconds=60` 的方差收敛验证（见上方记录）；当前 `43000` 作为主 baseline 候选的信心更高。
    - 已完成围绕主候选 `43000` 的补点：`42000/44000/48000`；未出现比 `43000` 更强的点。
    - 已完成更严的长期 gate 复核：`seconds=60 + rounds-per-scenario=5`（见上方记录）。
    - next：把 `delay-ns=43000` 冻结为 baseline v1，后续只在“设备/Android 版本变化”或“tuple-space/规则语料发生大改”时再重新 sweep。
  - 4) 扩大 tuple-space（进一步打穿 cache）：
    - 继续用 `srcIp` 池（neper `-L` + Tier‑1 `IPTEST_HOST_IP_POOL`），并按需扩展到多进程 `uid/dstIp`（进一步提高 `PacketKeyV4` 基数，避免落入 1024 直映 cache 的假阴性）。
