# IP Test Module (real-device, controlled Tier‑1)

> 这是 IP 真机测试模组的“精简可维护版”说明文档：只保留稳定结论、入口与口径。  
> 详细的实验过程与中间数据已归档：`docs/testing/ip/archive/2026-03-24-IP_TEST_MODULE.md`。

目标：在 rooted Android 真机上为 `IPRULES/IFACE_BLOCK` 提供 **可重复执行** 的功能回归与 perf baseline。  
legacy 冻结项（`BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）当前仅保留 archive 回查脚本 `tests/archive/device/30_ip_leak.sh`（不纳入 active profiles）。  
原则：不追求模拟真实网络，优先追求 **稳定、可复现、能拉开差距**（用于后续任何大改动的对比基线）。

## 1. 入口（推荐）

前置：主机可用 ADB；真机需要 `su 0`。

```bash
export ADB="$HOME/.local/android/platform-tools/adb"
export ADB_SERIAL="28201JEGR0XPAJ"   # 例：Pixel 6a

# 部署（可选；若已在机上运行可用 --skip-deploy）
cmake --preset dev-debug
cmake --build --preset dev-debug --target snort-build-ndk
bash dev/dev-deploy.sh --serial "$ADB_SERIAL"

# IP 模组 smoke/perf（Tier‑1: netns+veth）
bash tests/device/ip/run.sh --serial "$ADB_SERIAL" --profile smoke
bash tests/device/ip/run.sh --serial "$ADB_SERIAL" --profile perf --skip-deploy

# 全量功能矩阵 / 并发压力（best-effort；环境不满足会 SKIP）
bash tests/device/ip/run.sh --serial "$ADB_SERIAL" --profile matrix --skip-deploy
bash tests/device/ip/run.sh --serial "$ADB_SERIAL" --profile stress --skip-deploy

# Tier-1 longrun（control-plane churn + traffic + health assertions；record-first）
IPTEST_LONGRUN_SECONDS=600 \
  bash tests/device/ip/run.sh --serial "$ADB_SERIAL" --profile longrun --skip-deploy
```

说明：
- `tests/device/ip/` 是“真机测试模组”，不是 unit/integration 的替代品（历史纲领见 `docs/testing/archive/TEST_COMPONENTS_MANIFESTO.md`）。
- profiles 语义：`smoke/matrix/stress/perf/longrun` **全部**走 vNext control（`60607 + sucre-snort-ctl`）；legacy/mixed 仅作为回查入口保留在 `tests/archive/**`（例如 `tests/archive/device/ip/run_legacy.sh`），不会被 `tests/device/ip/run.sh` 间接执行。
- 结果记录默认写到 `tests/device/ip/records/`（该目录已被 `tests/device/ip/.gitignore` 排除，不进 git）。
  - `--profile longrun` 产物目录形如 `tests/device/ip/records/ip-longrun-<ts>_<serial>/`，包含 `meta.txt`、`longrun.log`、`snort_proc_before/after/delta` 与 `traffic.txt`。
- 建议频率（口径保守，先不把 perf 变成 hard gate）：
  - 任意 `IPRULES/IFACE_BLOCK` 语义改动：至少跑 `smoke + matrix`
  - legacy 冻结项（`BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）：默认不纳入 active；如需回查再跑 `bash tests/archive/device/30_ip_leak.sh`
  - 热路径/性能/并发相关改动：再补 `perf + stress`（perf 推荐用本文固定口径的 Tier‑1 baseline：`tests/device/ip/perf_fixedfreq_3way.sh`）
  - 需要更强稳定性/长期运行信心时（例如 release candidate）：再补 `longrun`（best-effort；环境不满足会 SKIP）

## 2. Tier‑1（netns+veth）受控拓扑

Tier‑1 的目的：在真机内创建封闭网络拓扑，避免公网/DNS/CDN 抖动，获得更强可复现性。

当前范围：
- 本模组目前只实现 Tier‑1（设备内 `netns+veth` 自建对端）；Tier‑2/Tier‑3 暂不做。

关键点：
- Android 常见 policy routing：不同 UID 的出站流量会走 `wlan0/rmnet` 等 table。Tier‑1 setup 需要把测试子网路由注入“client UID 实际使用的 table”，否则 `ip route get <peer> uid 2000` 可能不会走 veth。
- Tier‑1 server 统一使用 `nc -L cat /dev/zero`（见 §5）。

## 3. Perf baseline v1（Tier‑1 TCP mix；vNext-only）

目标：给 `IPRULES` datapath 提供一个可重复执行的“相对对比”基线，优先服务回归与大改动前后对比，而不是追求贴近真实公网环境。

主指标（建议）：
- `rate_mib_s`：Tier‑1 真实读取的 payload bytes / seconds
- `METRICS.GET(name=perf).result.perf.nfq_total_us`：NFQUEUE 端到端耗时分布（`avg/p50/p95/p99/max`）

固定口径（默认值；Pixel 6a 推荐）：
- 负载：`IPTEST_PERF_LOAD_MODE=mix`（默认；多 worker + 多 IP/port + 短连接 churn）
- Duration：`DURATION_S=90`（更快方向可改 `30`）
- Heavy ruleset：`HEAVY_TRAFFIC_RULES=4000`（可调；保持长期一致以便对比）
- CPU 定频（best-effort，runner 会 restore）：`policy0=1328000 policy4=1328000 policy6=1426000`

### 3.1 一键运行（推荐；定频 + records）

```bash
bash tests/device/ip/perf_fixedfreq_3way.sh \
  --serial "$ADB_SERIAL" \
  --freq0 1328000 --freq4 1328000 --freq6 1426000 \
  --duration 90 \
  --cooldown 60 \
  --order iprules_off_empty,iprules_on_empty,iprules_on_heavy
```

产物目录形如：
- `tests/device/ip/records/perf-fixedfreq-<ts>_<serial>/`
  - `summary.json`：3 个 scenario 的结构化结果（含 `latency_us` 分布）
  - `runs/*.log`：每个 scenario 的原始日志（含 `PERF_RESULT_JSON ...`）

### 3.2 快速方向（不定频）

```bash
bash tests/device/ip/perf_3way.sh --serial "$ADB_SERIAL" --seconds 60
```

### 3.3 历史 neper baseline（已归档）

早期基于 `neper + snortctl(legacy)` 的 UDP/TCP perf baseline 已归档（仅供回查）：
- 入口：`tests/archive/device/ip/neper_*`
- 记录：`docs/testing/ip/archive/2026-03-24-IP_TEST_MODULE.md`

## 4. 场景与规则语义（perf 口径）

baseline v1 固定 3 个场景：
- `iprules_off_empty`：`IPRULES=0`，空 ruleset
- `iprules_on_empty`：`IPRULES=1`，空 ruleset
- `iprules_on_heavy`：`IPRULES=1`，heavy ruleset（默认 traffic uid 4000 条；可选 background rules）

规则语料设计目标：
- 不改变实际 verdict：使用 would-block（`action=block enforce=0 log=1`）构造 miss rules；同时包含 1 条 hit rule
- deterministic：规则由 `tests/device/ip/cases/60_perf.sh` 内部生成器按固定形态生成

### 4.1 规则规模 sweep（可选；records + /proc delta）

用于观察规则规模与 perf 指标的趋势（先记录，不作为硬阈值 gate）：

```bash
bash tests/device/ip/perf_ruleset_sweep.sh \
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

这些方向已明确不作为“主 baseline”（只在必要时临时使用/排障）：
- **公网/外部网络当 baseline**：DNS/CDN/信号波动过大；baseline 统一走 Tier‑1（netns+veth）。
- **在 socket 上派生 shell**：已复现 Pixel 6a kernel panic；Tier‑1 server 必须使用 `nc -L cat /dev/zero`（不派生 `sh`）。
- **active 入口混入 legacy 控制面**：会让口径分裂；legacy/mixed 覆盖仅允许在 `tests/archive/**` 回查。

## 7. 何时需要重做 sweep / 升级 baseline

仅在以下情况重新 sweep / 重建 baseline（否则保持 baseline v1 不变，保证长期可比）：
- 设备/Android 版本变化导致 DVFS/内核行为变化
- Tier‑1 拓扑或打流模型发生实质变化（例如 `IPTEST_PERF_LOAD_MODE` 口径调整）
- tuple-space 或规则语料形态发生实质变化（例如新增关键 match 维度、bucket 策略变化）
