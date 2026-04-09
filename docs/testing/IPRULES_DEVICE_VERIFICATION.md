# IPRULES v1 真机验证矩阵（L3/L4 Firewall）

目的：在 **真机** 上验证 `IPRULES v1` 的端到端行为（控制面下发 → NFQUEUE 真实流量 → 判决/统计/PKTSTREAM 可观测），覆盖 TCP/UDP/ICMP 与关键组合/边界条件。  
说明：host-side gtest 只能验证引擎/解析/确定性，不足以作为最终验收；本文保留为 IPRULES v1 已归档 change 的真机验证记录。

## 1. 前置条件

- 真机已部署 `sucre-snort-dev`，并可通过 control socket 通讯（`HELLO` 返回 `OK`）
- 网络可用（至少能对 `1.1.1.1` 发起流量）
- 设备侧工具：
  - `ping`（ICMP 触发）
  - `nc`/`netcat`（Toybox netcat，TCP/UDP 触发）
  - （可选）`curl`/`wget`/`toybox wget`（用于持续 TCP 下载触发；已有脚本可复用）

## 2. 相关脚本

- 基线回归：`tests/integration/run.sh`
- IPRULES 基础验收（控制面 + 少量 ICMP）：`tests/integration/iprules.sh`
- IPRULES 真机矩阵（ICMP/TCP/UDP 大量组合）：`tests/integration/iprules-device-matrix.sh`

## 3. 流量触发策略（尽量确定性）

优先使用 **IP literal**（避免 DNS/CDN 不确定性）：

- ICMP：`ping -4 1.1.1.1`
- TCP：`nc -4 -n -z -w 2 1.1.1.1 443`（仅用于产生 SYN/握手流量，不以“连接成功”作为断言）
- UDP：`printf x | nc -4 -n -u -w 1 -q 0 1.1.1.1 12345`（只要求产生出站 UDP 包）

注意：当前 iptables 规则对 `lo` 与 DNS 端口（`53/853/5353`）会 `RETURN`，不进入 NFQUEUE；矩阵测试避免使用这些端口/接口。

可选（用于“更大流量 + 更长时间”的 sanity，非语义覆盖主手段）：直接复用 `tests/integration/perf-network-load.sh` 的 download 触发逻辑（它会在真机侧优先用 `curl`/`wget`，不存在则尝试 `toybox wget`），可用于对比空闲 vs 下载阶段的 `METRICS.REASONS` / per-rule stats 变化是否符合预期。

## 4. 必覆盖维度（最小闭环）

### 4.1 协议与方向
- `proto=icmp`：`dir=out` 与 `dir=in`（通过 echo request/echo reply 覆盖 in/out）
- `proto=tcp`：至少覆盖 `dir=out`；`dir=in` 可通过阻断 `SYN-ACK/RST`（`src=1.1.1.1 sport=443`）验证
- `proto=udp`：至少覆盖 `dir=out`（`dir=in` 依赖外部回包环境，允许 best-effort）
- `proto=any`：至少覆盖 “同一条规则对 ICMP + TCP 都能命中”（矩阵脚本可用 ping + tcp probe 验证）
- `dir=any`：至少覆盖 “同一条规则对 in/out 均可能命中”（推荐用 `proto=icmp`）

### 4.2 Match 维度组合
- `src/dst`：`any`、`/32`、`/24`（match 与 no-match）
- `sport/dport`（TCP/UDP）：`exact`、`range`、以及 range 边界（包含/不包含）
- `iface` / `ifindex`：
  - 从 PKTSTREAM 抽样确定当前出站接口（`interface` name），再映射到 `IFACES.PRINT` 的 `{ifindex,kind}`
  - 覆盖 `ifindex=<actual>`、`ifindex=0(any)`、`ifindex=<wrong>`（no-match）
  - 覆盖 `iface=<actualKind>` 与 `iface=<wrongKind>`（no-match）
  - 覆盖 `iface=any`（显式 any token）

说明：`ifaceKind` 的 v1 token 为 `wifi|data|vpn|unmanaged|any`（见 spec）；`ifindex=0` 视为 “不限定 ifindex”。

### 4.3 规则系统语义
- `priority`：高优先级压低优先级（allow vs block）
- 同优先级 tie-break：重复编译/查询下 winner 稳定（至少做一次设备侧 sanity）
- `enabled=0`：不影响 verdict、不会更新 stats
- `enforce=0 log=1`（would-block）：
  - would-only：`wouldHitPackets` 增长且不改变 verdict
  - enforce-first：存在 enforce 命中时 MUST suppress would-hit / would overlay
- 全局开关：
  - `IPRULES=0`：完全 bypass（不命中、stats 不增长、reason 不出现 `IP_RULE_*`）
  - `BLOCK=0`：更高层总开关 bypass（本仓库已有单独覆盖）

### 4.4 并发与稳定性（best-effort）
- 控制面（ADD/UPDATE/ENABLE/REMOVE）与真实流量并发时：
  - 守护进程不 crash、不死锁（`HELLO` 持续可用）
  - 不出现明显语义绕过（例如开启规则后长时间完全无命中；或关闭规则后仍持续命中）
- 该部分属于 best-effort：目标是尽早暴露竞态/死锁/资源泄漏，而不是证明不存在所有竞态窗口。

## 5. 运行方式

在主机侧运行（示例设备：`28201JEGR0XPAJ`）：

```bash
bash tests/integration/run.sh --skip-deploy --serial 28201JEGR0XPAJ
bash tests/integration/iprules.sh --skip-deploy --serial 28201JEGR0XPAJ
bash tests/integration/iprules-device-matrix.sh --skip-deploy --serial 28201JEGR0XPAJ
```

建议记录输出（并重复至少 3 次）：

```bash
bash tests/integration/iprules-device-matrix.sh --skip-deploy --serial 28201JEGR0XPAJ | tee -a /tmp/iprules-device-matrix.$(date +%F).log
```

## 6. 结果判定（验收口径）

- 每个 enforce case：`METRICS.REASONS` 对应 `IP_RULE_ALLOW|IP_RULE_BLOCK` 计数增长，且 `IPRULES.PRINT RULE <id>` 的 `hitPackets` 增长
- 每个 no-match case：`IP_RULE_ALLOW/IP_RULE_BLOCK` 计数保持 0，且规则 `hitPackets` 保持 0（fallback 到 legacy，通常为 `ALLOW_DEFAULT`）
- would-block case：仅当最终 ACCEPT 时 `wouldHitPackets` 增长；存在 enforce 命中时 `wouldHitPackets` 必须保持 0

## 7. 结果记录（提交前必须补齐）

将每次矩阵运行的结果追加到这里（至少 3 次；失败要记录失败 case 与真机环境信息）：

- 日期：
- 设备信息（model / Android 版本 / build fingerprint）：
- 守护进程版本（git sha 或构建产物标识）：
- 运行命令（含 `--serial`，以及是否 `--skip-deploy`）：
- 结果汇总（PASSED/FAILED/SKIPPED）：
- 备注（失败 case、环境不确定性、是否做过并发 best-effort）：

### 2026-03-23 / Pixel 6a / Android 16

- 设备信息：
  - serial: `28201JEGR0XPAJ`
  - model: `Pixel 6a`
  - release/sdk: `16 / 36`
  - fingerprint: `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`
- 守护进程版本：
  - host git: `bcb3541db0dafd1c1e8c41d1affd942a233009c0`（working tree dirty）
  - build-output binary build-id: `b8115be650ceea9810943cf11ce7410d`
- run #1（functional matrix）：
  - command: `bash tests/integration/iprules-device-matrix.sh --skip-deploy --serial 28201JEGR0XPAJ`
  - summary: `passed=252 failed=0 skipped=1`
  - notes: `ICMP in echo-reply not attributable to uid=2000`（device 差异，允许 SKIP）
- run #2（functional matrix）：
  - command: `bash tests/integration/iprules-device-matrix.sh --skip-deploy --serial 28201JEGR0XPAJ`
  - summary: `passed=252 failed=0 skipped=1`
  - log: `build-output/iptest/iprules-device-matrix-20260323T021815Z-run2.log`
- run #3（functional matrix）：
  - command: `bash tests/integration/iprules-device-matrix.sh --skip-deploy --serial 28201JEGR0XPAJ`
  - summary: `passed=252 failed=0 skipped=1`
  - log: `build-output/iptest/iprules-device-matrix-20260323T021903Z-run3.log`
- run #4（best-effort stress, `STRESS_SECONDS=5`）：
  - command: `STRESS_SECONDS=5 bash tests/integration/iprules-device-matrix.sh --skip-deploy --serial 28201JEGR0XPAJ`
  - summary: `passed=258 failed=0 skipped=1`
  - log: `build-output/iptest/iprules-device-matrix-20260323T022232Z-stress5.log`
