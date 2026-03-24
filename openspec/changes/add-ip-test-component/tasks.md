> 状态对齐（2026-03-24）：
> - `tests/device-modules/ip/run.sh` + Tier‑1 已落地；当前稳定承载 `smoke` / `perf`，并已具备 `matrix` 的核心用例入口。
> - `IPRULES`/`IFACE_BLOCK` 的主要 functional matrix 已迁入 `tests/device-modules/ip/cases/*`；`tests/integration/iprules-device-matrix.sh` 暂保留为 legacy 对照入口。
> - `stress` 已落地（控制面 churn + 真实流量并发）；Tier-2/Tier-3 流量源暂不做；`longrun` 仍为 staged（runner 已预留，缺 case 时会 SKIP）；因此本 change 维持 `17/18` 任务完成度。

## 0. OpenSpec docs
- [x] 0.1 新增纲领：`tests/TEST_COMPONENTS_MANIFESTO.md`（包含 IP test component 的范围/原则/入口约定）
- [x] 0.2 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（本目录下 `specs/`）
- [x] 0.3 `openspec validate add-ip-test-component --strict` 通过

## 1. Runner & structure
- [x] 1.1 新增 `tests/device-modules/ip/run.sh`：支持 `--profile smoke|matrix|stress|perf|longrun` 与 `--group/--case`
- [x] 1.2 抽取/复用现有 adb/control 辅助（可复用 `tests/integration/lib.sh` 作为实现细节），统一日志与 skip 语义

## 2. Functional coverage (matrix; pending migration from `tests/integration/iprules-device-matrix.sh`)
- [x] 2.1 `IPRULES` matrix（Tier-1，受控流量）：proto/dir/iface/ifindex/CIDR/ports/priority/tie-break/enable/enforce/would 的主要组合与边界
  - [x] 2.1.1 新增 `tests/device-modules/ip/cases/20_matrix_l3l4.sh`（覆盖 IPRULES 核心语义；优先使用 Tier-1 peer）
  - [x] 2.1.2 runner wiring：`tests/device-modules/ip/run.sh --profile matrix` 默认包含该 case
- [x] 2.2 `IFACE_BLOCK`（Tier-1）：优先级与 gating（含 `BLOCK=0` bypass）
  - [x] 2.2.1 新增 `tests/device-modules/ip/cases/40_iface_block.sh`（断言 `reasonId=IFACE_BLOCK`，并验证不携带 `ruleId/wouldRuleId`）
  - [x] 2.2.2 runner wiring：`--profile matrix` 默认包含该 case
- [x] 2.3 `BLOCKIPLEAKS`（best-effort；必要时允许 SKIP）：最小闭环回归（含 would overlay suppression on DROP）
  - [x] 2.3.1 新增 `tests/device-modules/ip/cases/30_ip_leak.sh`（复用 `example.com` 流程；解析失败或无 mapping 时 SKIP）
  - [x] 2.3.2 runner wiring：`--profile matrix` 默认包含该 case（或至少 `--profile smoke` 可选开启）

## 3. Stress (best-effort; pending migration into device-module runner)
- [x] 3.1 control-plane 变更（ADD/UPDATE/ENABLE/REMOVE/RESET）与真实流量并发时不 crash、不死锁
- [x] 3.2 输出最小证据：`HELLO` 可用性 + 关键 counters/stream 抽样
  - [x] 3.2.1 新增 `tests/device-modules/ip/cases/50_stress.sh`（默认短窗口；可通过 env 配置时长）
  - [x] 3.2.2 runner wiring：`tests/device-modules/ip/run.sh --profile stress` 默认包含该 case

## 4. Perf (record-first)
- [x] 4.1 设计并实现“可复现流量”优先级（当前仅 Tier-1；Tier-2/Tier-3 deferred）：
  - [x] Tier-1：真机 `netns+veth` 封闭拓扑（若支持）
    - [x] Android：识别 client UID 实际使用的路由表（如 `wlan0`），将测试子网路由注入该 table（并在 teardown 删除）
    - [x] 记录并规避已知环境 bug：toybox `nc -L sh -c ...` 触发 kernel panic（见 `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`）
  - Tier-2：局域网固定 server（HTTP/iperf）— deferred
  - Tier-3：公网 fallback（仅记录，不作严格 gate）— deferred
- [x] 4.2 规则规模扫描（两轴）：
  - traffic UID（默认 shell=2000）rules N：`0/10/100/500/1000/2000`
  - background total rules N（其它 UID 分布式铺开）：`0/500/1000/2000`
  - 记录：`IPRULES.PREFLIGHT` + `METRICS.PERF`/吞吐/CPU（先记录与对比，不作硬阈值 gate）
  - [x] 新增 sweep runner：`tests/device-modules/ip/perf_ruleset_sweep.sh`（基于 `cases/60_perf.sh`；产出 JSONL + snort `/proc` delta）
- [x] 4.2.1 cache-buster baseline（neper）：
  - `tests/device-modules/ip/neper_perf_3way.sh`（TCP_CRR；off/2k/4k；records+summarizer）
  - `tests/device-modules/ip/neper_udp_perf_3way.sh`（UDP_STREAM；off/2k/4k；records+summarizer）
  - `tests/device-modules/ip/neper_udp_perf_fixedfreq_matrix.sh`（固定频率 + scenario matrix；用于固化长期 perf baseline 口径）
- [x] 4.2.2 baseline 额外采集 snort `/proc/<pid>` delta（CPU ticks / VmRSS；best-effort，不做 gate）
- [x] 4.3 将结果以可追加方式记录到 runbook（不要求阈值 gate；标注 traffic tier 与环境信息）

## 5. Optional: dev/CI hooks
- [ ] 5.1 （可选）提供一个轻量 `ip-smoke` 入口接入现有 CTest（仅在运行时长与稳定性满足时）

## 6. Runbook & result recording
- [x] 6.1 新增 `docs/testing/ip/IP_TEST_MODULE.md`：运行方式、环境要求、结果记录模板、常见失败排障
- [x] 6.2 明确“关闭 change / 大改动必跑”的口径与建议频率
  - [x] 6.2.1 更新 `docs/testing/ip/IP_TEST_MODULE.md`：补齐 matrix/stress 入口与“必跑集合”说明
