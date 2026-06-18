# Design: IP real-device test module (full regression + perf)

## 0. Scope

本设计仅涉及 **真机测试模组的结构与口径**（runner、分组、断言、结果记录、流量复现与性能评估），不引入产品功能实现。

## 1. Design constraints

- **可重复**：每个用例必须自行拉到已知基线（至少 `RESETALL` + 关键开关归位）。
- **可子集运行**：支持 `--profile smoke|matrix|stress|perf|longrun`，并支持 `--group/--case` 精确运行。
- **可诊断**：失败时输出最小关键证据（控制面响应 / counters / stream sample），不要只给“失败”。
- **尽量确定性**：优先 IP literal + 固定端口；对环境不确定性场景使用 `SKIP` 而非误报失败。
- **维护友好**：新增 case 只需添加一个脚本/函数并注册，不改动大量胶水代码。
- **流量可复现**：性能用例必须优先使用“可控流量源”（见 §3）。

## 2. Module layout (proposed)

```
tests/device-modules/ip/
  run.sh                 # 模组统一入口（profile/group/case）
  cases/
    00_env.sh            # preflight / tool detection / baseline restore
    10_iprules_smoke.sh  # 快集：IPRULES 关键语义
    20_matrix_l3l4.sh    # 全集：组合/边界矩阵（TCP/UDP/ICMP）
    30_ip_leak.sh        # ip-leak 相关回归（BLOCKIPLEAKS）
    40_iface_block.sh    # IFACE_BLOCK/全局 BLOCK gating
    50_stress.sh         # 并发窗口（best-effort）
    60_perf.sh           # perf（规则规模扫描 + 指标采集 + 记录）
    70_longrun.sh        # 长期稳定性（可选）
docs/testing/ip/
  IP_TEST_MODULE.md      # runbook + 结果记录模板
```

说明：
- 模组 runner 可复用 repo 内现有的 control/adb 辅助（例如 `tests/integration/lib.sh`），作为实现细节。
- 每个 case 自己负责 “setup → trigger → assert → teardown/best-effort restore”。
- case 的“断言数据源”优先使用 `PKTSTREAM`（归因）与 `METRICS.REASONS`（聚合），per-rule stats 用于补强。

## 3. Reproducible traffic strategy (核心)

性能测试不可能完全脱离环境波动，但可以把“不可控因素”降到最低。模组应按以下优先级提供流量源：

### 3.1 Tier-1: on-device controlled topology (preferred)

在真机上创建封闭拓扑，避免公网与 DNS/CDN：

- 使用 `ip netns` 创建 `ts_server` namespace
- 使用 `veth` 连接 root namespace 与 `ts_server`
- 配置固定 IPv4（例如 `10.200.1.1/24` ↔ `10.200.1.2/24`）
- 在 `ts_server` 内启动简单 TCP/UDP server（可以是 `nc`/自带 tiny server）
- 在 root namespace 用 shell UID 作为 client 产生流量（确保 uid-owner 规则可命中）

优点：最可复现、吞吐可控（主要受设备 CPU 影响）。  
缺点：依赖 root 与 netns/veth 支持；若环境不支持，必须降级为 Tier-2/Tier-3 并明确标注。

#### 3.1.1 Android / Pixel 6a 特别注意：policy routing 与路由表注入

在 Android 上（尤其是连着 Wi‑Fi/蜂窝数据时），`netd` 往往会为每个网络维护独立路由表（如 `wlan0`/`rmnet_data0`），并通过 `ip rule`
让不同 UID 的本地出站流量走对应 table。结果是：

- 即使 main table 已经有 `10.200.1.0/24 dev veth_ts0`，`shell`（uid=2000）的 `ip route get 10.200.1.2 uid 2000`
  仍可能走 `table wlan0`，从而把 `10.200.1.2` 误路由到真实网关（导致 Tier‑1 ping/TCP 不通）。

因此 Tier‑1 setup 必须把测试子网路由注入“client UID 实际使用的 table”（并在 teardown 删除），而不是只写 main table。

建议的最小策略（伪代码）：

1) 创建 netns + veth，并在 root ns 配置：
   - `veth_ts0 = 10.200.1.1/24`
   - `ts_server:veth_ts1 = 10.200.1.2/24`
2) 选择 client UID（默认 `2000`，确保流量来自 shell UID，便于 uid-owner 规则命中）。
3) 解析 table：
   - `route_get="$(ip route get 10.200.1.2 uid "$CLIENT_UID")"`
   - `CLIENT_TABLE="$(echo "$route_get" | awk '{for (i=1;i<=NF;i++) if ($i=="table") {print $(i+1); exit}}')"`
   - 若解析不到 `table`（少数环境），可视作 `main`；但必须再做一次 `ip route get` 验证是否真的走 `veth_ts0`。
4) 注入路由：
   - `ip route add 10.200.1.0/24 dev veth_ts0 table "$CLIENT_TABLE"`（若已存在则忽略）
5) 验证：
   - `ip route get 10.200.1.2 uid "$CLIENT_UID"` 必须显示 `dev veth_ts0` 且 `src 10.200.1.1`
6) teardown（best-effort）：
   - kill `ip netns pids ts_server`（避免残留 server 进程）
   - `ip route del 10.200.1.0/24 dev veth_ts0 table "$CLIENT_TABLE"`
   - `ip link del veth_ts0` + `ip netns del ts_server`

备注：
- Android 的 `ping` 选项不统一，避免依赖 `-4`；直接使用 IPv4 literal 即可。
- `nc` 通常来自 toybox（`nc --help`），参数集与传统 netcat 不完全一致；模组应做 tool detection 并使用最兼容的参数子集。

### 3.2 Tier-2: LAN fixed server (recommended for more realistic throughput)

实验网/局域网提供固定 server（HTTP/iperf）。模组接受：
- `LAN_SERVER_IP`（IP literal）
- `LAN_SERVER_PORT`
- `LAN_SERVER_URL`（HTTP 优先；HTTPS 若需 pin 可用 `curl --resolve`）

### 3.3 Tier-3: public internet fallback (record-only)

用于“能跑通 + 记录趋势”，不用于严格 gate。必须记录：
- URL
- 实际解析到的 IP（以及是否 pin）
- 失败/抖动时的环境信息

## 4. Profiles

- `smoke`：最小闭环，必须快、必须稳定。
- `matrix`：语义覆盖全集（组合/边界），允许更慢，但必须可重复与可比。
- `stress`：并发窗口（control-plane 与真实流量并发），只要求不 crash/不死锁/不出现明显 bypass。
- `perf`：规则规模扫描 + 固定流量源下采集 `METRICS.PERF`/吞吐/CPU；先以“记录+对比”为主，不把阈值写死为硬失败，避免环境波动误报。
- `longrun`：长时间运行 + 周期采样（可选），用于捕获泄漏/抖动/尾延迟回归。

## 4.1 Perf ruleset model (2 axes)

IPRULES v1 是 **per-UID** 的：每个 packet evaluation 只会进入 `byUid[k.uid]` 的子表（其它 UID 的规则不会参与该包匹配）。因此真机 perf 的 ruleset 需要把两个维度分开看：

1) **Per-UID active rules（热路径匹配成本的主要维度）**  
   把大量规则集中到“产生流量的 UID”（默认 `shell=2000`）用于评估最坏/近最坏路径。

2) **Total active rules（控制面/编译/内存维度）**  
   通过在大量“其它 UID”下铺开规则，模拟真实设备上“很多 app 各自少量规则”的总量与分布，主要影响 snapshot 编译、持久化 IO、以及整体内存占用。

因此 `perf` profile 至少应该覆盖两类扫点（先保守，后续可扩展）：
- **UID-hot sweep**：固定 background rules = 0，扫描 traffic UID 的 rules N（建议：`0/10/100/500/1000/2000`）
- **Background sweep**：固定 traffic UID rules = 2000，扫描 background total rules（建议：`0/500/1000/2000`）

### 4.1.1 Recommended baseline: 2K rules for the traffic UID

建议把“性能基线场景”固定为：
- `TRAFFIC_UID=2000`（可覆盖 `uid-owner` 语义且稳定；若设备支持 `su <uid>` 也可切换）
- `N_TRAFFIC_RULES=2000`（>recommended 但 <hard，用于暴露边界趋势）
- traffic UID 下的 2K rules 使用 **当前已支持字段**（后续 L4/stream 上线再扩展）；并且保持：
  - deterministic（固定 seed、固定顺序）
  - 不触发 hard preflight violations（subtables/rangeCandidates 等）

建议把 traffic UID 的规则组做成“**少量 hit + 大量 miss**”的确定性组合：
- 1 条 strict hit（允许 perf TCP load 流量，避免落入 legacy/host/domain 慢路径）
- 少量 “hot” 规则（仍为 allow，但覆盖不同 mask：`dir/proto/src/dst/ifindex/ports(any|exact)` 等），用于确保组合分支被编译并可观测
- 其余为 deterministic filler（多数不命中），用于把规则规模稳定凑到 2K，并覆盖更多字段组合

背景 rules（其它 UID）用于模拟“很多 app 各自少量规则”的总量与分布：  
建议用 **round‑robin** 把 `N_BG_TOTAL` 分摊到 `N_BG_UIDS` 个 UID（例如 `N_BG_UIDS=200`，每 UID ≈ 10 条），从而更贴近真实设备生态。

初期为了稳定与可诊断，建议 perf ruleset **避免**：
- 端口 range（会触发 range candidates 扫描与阈值，且受包类型影响更复杂）
- 大量 ifindex/ifaceKind 变化（容易把 subtables 推到 hard limit）

后续若需要明确上界，可额外提供一个 `perf-worstcase` ruleset（接近 hard limit 的 subtables + range candidates），但不作为第一阶段硬验收门槛。

## 4. Assertions (policy)

必须避免“只依赖单一信号”：
- enforce/allow/block：`PKTSTREAM.reasonId + ruleId` 与 `METRICS.REASONS` 同时验证；必要时补 `IPRULES.PRINT` stats。
- would-block：验证 overlay（`wouldRuleId/wouldDrop`）仅在最终 ACCEPT 时出现；DROP 时 suppress。
- bypass（`IPRULES=0` / `BLOCK=0`）：必须验证 counters/stats 不增长 + PKTSTREAM 不出现 IP_RULE 归因。

## 5. Relationship to dev tests

该模组不以 CTest/CI 为主要入口（运行时长与环境要求更高）。  
是否额外提供一个“轻量 smoke”接入 CTest，取决于后续运行时长与稳定性；但不作为本模组的核心约束。
