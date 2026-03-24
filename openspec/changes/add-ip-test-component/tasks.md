## 0. OpenSpec docs
- [x] 0.1 新增纲领：`docs/testing/TEST_COMPONENTS_MANIFESTO.md`（包含 IP test component 的范围/原则/入口约定）
- [x] 0.2 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（本目录下 `specs/`）
- [x] 0.3 `openspec validate add-ip-test-component --strict` 通过

## 1. Runner & structure
- [x] 1.1 新增 `tests/device-modules/ip/run.sh`：支持 `--profile smoke|matrix|stress|perf|longrun` 与 `--group/--case`
- [x] 1.2 抽取/复用现有 adb/control 辅助（可复用 `tests/integration/lib.sh` 作为实现细节），统一日志与 skip 语义

## 2. Functional coverage (matrix)
- [ ] 2.1 `IPRULES`：proto/dir/iface/ifindex/CIDR/ports/priority/tie-break/enable/enforce/would 的主要组合与边界
- [ ] 2.2 `IFACE_BLOCK`：优先级与 gating（含 `BLOCK=0` bypass）
- [ ] 2.3 `BLOCKIPLEAKS`：最小闭环回归（含 would overlay suppression on DROP）

## 3. Stress (best-effort)
- [ ] 3.1 control-plane 变更（ADD/UPDATE/ENABLE/REMOVE/RESET）与真实流量并发时不 crash、不死锁
- [ ] 3.2 输出最小证据：`HELLO` 可用性 + 关键 counters/stream 抽样

## 4. Perf (record-first)
- [ ] 4.1 设计并实现“可复现流量”优先级：
  - [x] Tier-1：真机 `netns+veth` 封闭拓扑（若支持）
    - [x] Android：识别 client UID 实际使用的路由表（如 `wlan0`），将测试子网路由注入该 table（并在 teardown 删除）
    - [x] 记录并规避已知环境 bug：toybox `nc -L sh -c ...` 触发 kernel panic（见 `docs/testing/ip/BUG_kernel_panic_sock_ioctl.md`）
  - [ ] Tier-2：局域网固定 server（HTTP/iperf）
  - [ ] Tier-3：公网 fallback（仅记录，不作严格 gate）
- [ ] 4.2 规则规模扫描（两轴）：
  - traffic UID（默认 shell=2000）rules N：`0/10/100/500/1000/2000`
  - background total rules N（其它 UID 分布式铺开）：`0/500/1000/2000`
  - 记录：`IPRULES.PREFLIGHT` + `METRICS.PERF`/吞吐/CPU（先记录与对比，不作硬阈值 gate）
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
- [ ] 6.2 明确“关闭 change / 大改动必跑”的口径与建议频率
