# IP Test Module (real-device, controlled Tier‑1)

> 这是 IP 真机测试模组的“精简可维护版”说明文档：只保留稳定结论、入口与口径。  
> 详细的实验过程与中间数据已归档：`docs/testing/ip/archive/2026-03-24-IP_TEST_MODULE.md`。

目标：在 rooted Android 真机上为 `IPRULES/IFACE_BLOCK/BLOCKIPLEAKS` 提供 **可重复执行** 的功能回归与 perf baseline。  
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
```

说明：
- `tests/device-modules/ip/` 是“真机测试模组”，不是 unit/integration 的替代品（见 `docs/TEST_COMPONENTS_MANIFESTO.md`）。
- 结果记录默认写到 `tests/device-modules/ip/records/`（该目录已被 `tests/device-modules/ip/.gitignore` 排除，不进 git）。

## 2. Tier‑1（netns+veth）受控拓扑

Tier‑1 的目的：在真机内创建封闭网络拓扑，避免公网/DNS/CDN 抖动，获得更强可复现性。

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

### 3.4 baseline v1（冻结记录，关键数据）

严格复核（`seconds=60 × rounds-per-scenario=5`，`delay-ns=43000`）：
- 设备：Pixel 6a（Android 16 / SDK 36）
- CPU 定频：`policy0=1328000 policy4=1328000 policy6=1426000`（governor=`performance`，min=max）
- 产物（不进 git）：`tests/device-modules/ip/records/neper-udp-perf-fixedfreq-matrix-20260323T013903Z_28201JEGR0XPAJ/`
- 主指标：neper `remote_throughput`（bps；括号内为 Mb/s；mean/cv）：
  - `off`: `mean=11075923 cv=0.56%`（`11.076`）
  - `2k`: `mean=10811018 cv=1.41%`（`10.811`；vs off `-2.39%`）
  - `4k`: `mean=9969492  cv=1.73%`（`9.969`；vs off `-9.99%`；vs 2k `-7.78%`）
- 单调性：`off > 2k > 4k` by index `5/5`
- guardrails：所有样本 `nfq_queue_dropped_total=0` 且 `nfq_user_dropped_total=0`

解释：场景差距（~2%/~10%）显著大于单场景方差（~1% 量级），因此足以作为后续优化/回归的对比基线。

### 3.5 Guardrails（必须满足）

每个样本必须满足（否则说明打流已把 NFQUEUE 打爆，结果不可比）：
- `nfq_queue_dropped_total=0`
- `nfq_user_dropped_total=0`

这些值由脚本在每个样本前后读取 `/proc/net/netfilter/nfnetlink_queue` 并计算 delta。

## 4. 规则集与场景语义（perf 口径）

baseline v1 采用 3 个场景（对同一台设备、同一组 knobs）：
- `off`：`IPRULES=0`（bypass）
- `2k`：`IPRULES=1` + traffic UID 下 2048 条规则
- `4k`：`IPRULES=1` + traffic UID 下 4096 条规则

规则语料设计目标：
- 强化 rule-eval 成本，但不改变实际 verdict（使用 `would-block`：`action=block enforce=0 log=1`）。
- deterministic：固定 seed + 固定生成规则形态，便于长期回归对比。

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
