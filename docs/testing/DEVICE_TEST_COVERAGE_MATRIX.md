# Device / DX 测试覆盖矩阵（vNext；smoke + diagnostics）

更新时间：2026-04-25

范围与目的：
- 范围：仅本仓库 `sucre-snort` 的 **Device / DX** 真机测试（host/WSL 侧脚本通过 ADB 驱动 rooted Android 真机）。
- 目的：把“当前已经覆盖到什么 / 还有哪些可测但没测”系统化整理出来，便于把 **第一阶段能测的尽量测全**。
- 边界与现状单一真相：`docs/IMPLEMENTATION_ROADMAP.md`
- 组织原则（active 只保留 smoke/diagnostics）：`docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`

符号说明（表格单元格）：
- `✅`：稳定覆盖（失败通常意味着代码/契约问题，需要修复）。
- `◐`：部分覆盖 / best-effort / 环境依赖强（可能 SKIP/BLOCKED）。
- `—`：不覆盖（或仅间接触达，不作为断言）。

> 备注：vNext 协议面契约见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`；对应 Host 侧的纯协议/shape/strict-reject 覆盖主要在 `tests/host/control_vnext_*_tests.cpp`。

---

## 1) 当前 active 入口（Device / DX）

Smoke（gate；fail-fast；vNext-only）：
- `dx-smoke`：总入口（platform → control → datapath），脚本 `tests/integration/dx-smoke.sh`
- `dx-smoke-platform`：平台 gate，脚本 `tests/integration/dx-smoke-platform.sh`
- `dx-smoke-control`：控制面基线（wrapper），脚本 `tests/integration/dx-smoke-control.sh` → `tests/integration/vnext-baseline.sh`
- `dx-smoke-datapath`：数据面 gate（wrapper），脚本 `tests/integration/dx-smoke-datapath.sh` → `tests/device/ip/run.sh --profile smoke`

Diagnostics（非 gate；观测/对比；vNext-only）：
- `dx-diagnostics`：总入口（当前只聚合 perf-network-load），脚本 `tests/device/diagnostics/dx-diagnostics.sh`
- `dx-diagnostics-perf-network-load`：真实下载负载 + `METRICS.GET(name=perf)`，脚本 `tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
- IP 模组 profiles（受控 Tier-1：netns+veth）：
  - `tests/device/ip/run.sh --profile matrix|stress|perf|longrun`
  - 说明与 records：`docs/testing/ip/IP_TEST_MODULE.md`、`docs/testing/PERFORMANCE_TEST_RECORD.md`

Optional Casebook（非 gate；显式运行；vNext-only）：
- `dx-casebook-other`：`DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2，脚本 `tests/device/diagnostics/dx-casebook-other.sh`

Archive（仅回查；不算 active 覆盖）：
- legacy/mixed baseline：`tests/archive/integration/*.sh`
- legacy 冻结项回查：`tests/archive/device/30_ip_leak.sh`

---

## 2) 覆盖矩阵

### 2.1 Smoke 覆盖矩阵（Device / DX）

| Feature / 断言点 | `dx-smoke-platform` (`tests/integration/dx-smoke-platform.sh`) | `dx-smoke-control` (`tests/integration/vnext-baseline.sh`) | `dx-smoke-datapath` (`tests/device/ip/run.sh --profile smoke`) | Host gtest（参考；不等同真机覆盖） |
| --- | --- | --- | --- | --- |
| rooted device preflight +（可选）deploy | ✅（`device_preflight` + `dev/dev-deploy.sh`） | ◐（在 `dx-smoke` 下默认 `--skip-deploy`） | ◐（在 `dx-smoke` 下默认 `--skip-deploy`） | — |
| host 工具链（`python3` + `sucre-snort-ctl`） | ✅（集中检查；缺失→BLOCKED） | ✅（依赖；platform 已前置暴露） | ✅（依赖；platform 已前置暴露） | — |
| socket namespace（control-vnext + netd） | ✅（检查 `/dev/socket/sucre-snort-control-vnext`、`/dev/socket/sucre-snort-netd`） | — | — | — |
| iptables/ip6tables hooks + NFQUEUE 规则 | ✅（链/规则存在性断言） | — | — | — |
| SELinux runtime + AVC denials | ✅（`getenforce` + `logcat -s AVC`） | — | — | — |
| lifecycle restart（kill → restart → redeploy） | ✅（仅 `DO_DEPLOY=1` 时） | — | — | — |
| inetControl gating（TCP:60607 不应暴露） | — | ✅（`/data/snort/telnet` 缺失时：tcp:60607 不可达） | — | ◐（session/codec tests 侧重协议，不测真机 gating） |
| vNext handshake（HELLO fields） | ✅（HELLO sanity） | ✅（`HELLO` shape + reconnect/QUIT） | ✅（`HELLO` 可用） | ✅（`tests/host/control_vnext_*_tests.cpp`） |
| 并发连接语义（last-write-wins） | — | ✅（两连接并发 `CONFIG.SET`） | — | ✅（多 handler/codec 覆盖） |
| strict reject / error model（未知 args key/命令等） | — | — | — | ✅（例如 `tests/host/control_vnext_{metrics,iprules,stream,domain}_surface_tests.cpp`） |
| stream: activity start→event→stop | — | ✅（`STREAM.START type=activity` + started notice + STOP ack barrier） | — | ✅（`tests/host/control_vnext_stream_surface_tests.cpp`） |
| stream: pkt 事件字段（reasonId/ruleId/wouldRuleId） | — | — | ✅（Tier-1 打流 + `STREAM.START type=pkt` 抓到 `reasonId/ruleId` / overlay / IFACE_BLOCK） | ◐（host 侧更偏 surface/state，不产出真实 pkt） |
| stream: dns 事件字段（端到端） | — | ✅（netd inject → `DnsListener` → `STREAM.START type=dns`；`VNT-10b*` + `VNT-DOM-03/04/06/07/09`） | — | ◐（host 侧可测 START/STOP/state；不等于真机 DNS 链路） |
| inventory: `APPS.LIST` shape/sort/limit | — | ✅（apps[]、uid 排序、limit/truncated） | ✅（IP 模组用于挑选 `uid>=10000` 的测试 app） | ✅（control surface tests） |
| inventory: `IFACES.LIST` shape/sort | — | — | ✅（IFACE_BLOCK 场景需要 `IFACES.LIST` + ifindex→kind） | ◐ |
| config: `CONFIG.GET/SET`（device/app keys） | — | ✅（`block.enabled`、`perfmetrics.enabled`、`tracked` 等） | ✅（`block.enabled/iprules.enabled/tracked/block.ifaceKindMask`） | ✅ |
| domain surface：`DOMAINRULES/DOMAINPOLICY/DOMAINLISTS` | — | ✅（GET/APPLY/IMPORT 基线 + `VNT-DOM-01a~01b` 负向契约） | — | ✅（domain surface tests 覆盖更多错误/边界） |
| domain observability：`METRICS.GET(domainSources)` 增长/RESET 边界 | — | ✅（`DEV.DOMAIN.QUERY` gating + `VNT-DOM-02~09` bucket 级 e2e） | — | ✅（`tests/host/domain_policy_sources_tests.cpp` + vNext metrics surface） |
| domain casebook：Domain Case 1–9 | — | ✅（`tests/integration/vnext-domain-casebook.py`：`VNT-DOM-01a~09`；Case 8 hook 缺失→BLOCKED） | — | ◐（Host 覆盖组件契约，不替代真机 e2e） |
| IP casebook：IP Case 1–8 + Conntrack Case 1 | — | — | ✅（`VNX-03~05` + `VNXDP-05~13` + `VNXCT-01~12c`；Conntrack 仅最小 L4 state 闭环） | ◐（Host 覆盖组件契约，不替代真机 e2e） |
| iprules surface：`IPRULES.PREFLIGHT/APPLY/PRINT` | — | ✅（shape + mapping + PRINT 排序/字段） | ✅（smoke 基线 + datapath 场景使用） | ✅（`tests/host/control_vnext_iprules_surface_tests.cpp`） |
| datapath correctness：verdict + per-rule stats + reasons | — | — | ✅（allow/block/would-match/IFACE_BLOCK、`block.enabled=0`、`iprules.enabled=0`、payload bytes、conntrack allow/block；stats `hitPackets/hitBytes`） | ◐（host 侧不具备 NFQUEUE/iptables 真实链路） |
| metrics surface：`METRICS.GET`（perf/reasons/traffic/conntrack） | — | ✅（shape + 部分 best-effort traffic 触发/RESET） | ✅（IP Case 2–8 对 reasons/traffic 做 bucket 级断言；`VNXCT` 对 conntrack create/no-create 做断言） | ✅ |
| traffic metrics：受控触发 + RESET（per-app） | — | ◐（baseline 中有 best-effort 触发；可能 skip） | ✅（Tier-1 `nc` + payload；`traffic.txp/rxp/rxb` bucket 与 reset 断言） | ✅（metrics surface tests 覆盖 shape + reset 语义） |
| `RESETALL` baseline | — | ✅（RESETALL + HELLO；best-effort conntrack 清零） | ◐（各 case 内会先 RESETALL 做干净基线） | ✅ |

### 2.2 Diagnostics 覆盖矩阵（Device / DX）

| Feature / 断言点 | `dx-diagnostics-perf-network-load` (`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`) | IP `matrix` (`tests/device/ip/run.sh --profile matrix`) | IP `stress` (`--profile stress`) | IP `perf` (`--profile perf`) | IP `longrun` (`--profile longrun`) |
| --- | --- | --- | --- | --- | --- |
| 真实网络负载触发（curl/wget/nc 下载） | ✅（下载到 `/dev/null`；并发/超时可调） | — | — | — | — |
| perfmetrics.enabled=0 时“近似零成本”断言 | ✅（流量下 `METRICS.GET(perf)` 全 0） | — | — | ◐（perf 场景会对比 off/on，但更偏相对趋势） | — |
| perfmetrics.enabled=1 时 samples 增长 | ✅（下载流量下 samples 增长） | — | — | ✅（Tier-1 受控打流 + 记录 latency/rate） | ✅（长跑持续观测） |
| DNS perf（`dns_decision_us`） | ◐（依赖 netd resolv hook；不活跃时会 SKIP DNS 断言） | — | — | — | — |
| IPRULES 功能矩阵（L3/L4/conntrack/iface） | — | ✅（`20_matrix_l3l4.sh`、`22_conntrack_ct.sh`、`40_iface_block.sh`） | — | — | — |
| 并发/压力（规则 churn + 打流） | — | — | ✅（`50_stress.sh`） | — | — |
| perf baseline（3-way / fixedfreq / ruleset sweep） | — | — | — | ✅（`60_perf.sh`、`62_perf_ct_compare.sh` + records） | ◐（长跑更偏稳定性/退化观察） |
| longrun（600s+；record-first） | — | — | — | — | ✅（`70_longrun.sh` + records） |

---

### 2.3 Optional Casebook 覆盖矩阵（Device / DX）

| Feature / 断言点 | `dx-casebook-other` (`tests/device/diagnostics/dx-casebook-other.sh`) | 默认 `dx-smoke` 主链 |
| --- | --- | --- |
| `perfmetrics.enabled=0` under Tier‑1 payload | ✅（`VNXOTH-01b~01d`；非公网依赖） | — |
| `perfmetrics.enabled=1` samples 增长 + 1→1 幂等 | ✅（`VNXOTH-01e~01i`） | — |
| `perfmetrics.enabled=2` 非法值拒绝 | ✅（`VNXOTH-01j~01k`） | — |
| `dns_decision_us` perf | ◐（`VNXOTH-01l`；仅 optional/non-gate，不强依赖 netd hook） | — |
| `DOMAINLISTS.IMPORT` under/over limits + `HELLO` recovery | ✅（`VNXOTH-02a~02f`；optional limits sanity） | — |
| `IPRULES.APPLY` recommended/hard limits + all-or-nothing + recovery | ✅（`VNXOTH-02g~02n`；optional limits sanity） | — |

---

## 3) “第一阶段尽量测全”的推荐顺序（单机）

前置：
- 需要 rooted Android 真机 + ADB 可用。
- vNext 控制面默认通过 adb forward 到 `127.0.0.1:60607`（`localabstract:sucre-snort-control-vnext`）。

推荐顺序（从“功能完整性 gate”到“观测/性能”）：
1) `dx-smoke`（主 gate；固定顺序 platform→control→datapath）
   - `cmake --preset dev-debug -DSNORT_ENABLE_DEVICE_TESTS=ON`
   - `cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-smoke$`
2) `dx-diagnostics-perf-network-load`（真实负载 + perf metrics）
   - `cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-diagnostics-perf-network-load$`
   - 若只想复用 `dx-smoke` 刚 deploy 的守护进程：也可直接跑脚本并加 `--skip-deploy`
3) `dx-casebook-other`（可选；casebook `## 其他`，建议上线前/大改后显式跑）
   - `cd build-output/cmake/dev-debug && ctest --output-on-failure -R ^dx-casebook-other$`
   - 或直接：`bash tests/device/diagnostics/dx-casebook-other.sh --skip-deploy`
4) IP 模组扩面（受控 Tier‑1；建议复用守护进程）
   - `bash tests/device/ip/run.sh --profile matrix --skip-deploy`
   - `bash tests/device/ip/run.sh --profile stress --skip-deploy`
   - `bash tests/device/ip/run.sh --profile perf --skip-deploy`
   - `IPTEST_LONGRUN_SECONDS=600 bash tests/device/ip/run.sh --profile longrun --skip-deploy`

已知“可能 BLOCKED/SKIP”的两类点（先记录，不要硬塞进 smoke）：
- `dx-diagnostics-perf-network-load` 的 DNS 断言：依赖 netd resolv hook；缺失时脚本会明确 `SKIP:`（见 `docs/testing/PERFORMANCE_TEST_RECORD.md`）。
- `dx-casebook-other` 的 optional limits sanity：可能因 Tier‑1 前置、host/daemon request-size 上限或设备资源差异明确 `SKIP/BLOCKED`；这不影响默认 `dx-smoke` 主 gate。
- IP perf 大 ruleset apply：默认 `IPTEST_PERF_TRAFFIC_RULES=2000` 可能触发 `IPRULES.APPLY transport failed`；可临时降到 `IPTEST_PERF_TRAFFIC_RULES=200` 验证链路（见 `docs/testing/README.md` 与 `docs/testing/PERFORMANCE_TEST_RECORD.md`）。

---

## 4) 当前缺口（可测但未测）与建议归类

> 归类规则（与讨论一致）：失败若基本等价于“功能契约/完整性被破坏，需要修代码”，则应进入 smoke；否则进 diagnostics（或先留在 host）。

### Gap-01：Device 侧缺失的协议/shape/strict-reject（但 Host 已覆盖）
- 现状：vNext 的 strict reject、`STATE_CONFLICT`、selector errors、limits shape 等大量边界已在 Host gtest 覆盖（见 `tests/host/control_vnext_*_surface_tests.cpp`），Device/DX 侧 smoke 未重复覆盖。
- 为什么这不是“真机缺口”：这些用例的失败通常属于 **协议/数据面契约**，不依赖真机平台（iptables/NFQUEUE/netd/SELinux），Host 更稳定、更快、更适合作为 gate。
- 建议归类：**保持在 Host（gate）**；仅当某条契约与真机接线强相关（例如 forward/gating、socket namespace、NFQUEUE 热路径）时，再在 Device 侧补一条 end-to-end 断言。
- flake / 前置：无（Host lane）。

### Gap-02（已补齐）：DNS stream 端到端事件（不依赖公网）
- 现状（已解决）：`dx-smoke-control` 通过 **netd inject** 直接触发 `DnsListener`，并在 `STREAM.START(type="dns")` 下断言收到匹配事件、字段、suppressed notice、`traffic.dns` 与 `domainSources` bucket。
- 入口：
  - 注入工具源码：`tests/device/dx/native/dx_netd_inject.cpp`
  - 构建脚本：`dev/dev-build-dx-netd-inject.sh`
  - smoke 用例：`tests/integration/vnext-baseline.sh` 的 `VNT-10b3`（dns stream e2e）与 `tests/integration/vnext-domain-casebook.py` 的 `VNT-DOM-03/04/06/07/09`

### Gap-03（已补齐）：`METRICS.GET(name="traffic")` 的稳定可控触发
- 现状（已解决）：`dx-smoke-datapath`（IP Tier‑1）已在受控打流下断言：
  - `METRICS.RESET(name=traffic,app)` 能清零
  - `nc -z` 打流后 `txp.allow/txp.block` 等 verdict 维度增长
  - `block.enabled=0` 时 traffic 不增长
  - 固定 payload 读 `65536` bytes 后 `rxb.allow` 与 rule `hitBytes` 达到阈值
- 入口：`tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`（`VNXDP-05d~13n`）

### Gap-04（Domain smoke 已接入）：真实系统 resolver hook（netd resolv patch）闭环
- 现状：`dx-smoke-control` 的 `VNT-DOM-08` 在 hook 就绪时触发真实 DNS lookup 并断言 dns stream、`traffic.dns.block` 与 `domainSources`；hook 不活跃时明确 `BLOCKED` 并提示 `dev/dev-netd-resolv.sh status|prepare`。
- 仍需注意：netd hook 的挂载/触发在部分设备/环境下不稳定，因此 `BLOCKED` 属于环境前置不足，不等同于 sucre-snort 本体 FAIL。

### Gap-05（Optional 已接入）：大 payload / limits 在 Device 侧的覆盖
- 现状：Host 已覆盖 `DOMAINLISTS.IMPORT` limits（`maxImportBytes/maxImportDomains`）与 `IPRULES.APPLY` preflight hard-limit 的结构化错误；Device 侧通过 `dx-casebook-other` 的 `VNXOTH-02*` 做 optional sanity。
- 归类：**不补进默认 smoke**；保留在 optional casebook runner，断言限定为 `error.code` + `error.limits/error.preflight` shape + 失败后 `HELLO` 可用。
- flake / 风险点：payload 太大导致运行时间不可控、设备存储/内存差异导致非确定性失败；runner 遇到 request-size/资源前置不足时应明确 `SKIP/BLOCKED`。
