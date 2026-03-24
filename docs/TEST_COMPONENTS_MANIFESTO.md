# Test Modules Manifesto (real-device regression)

目标：把“测试”从零散脚本升级为**可重复执行的真机测试模组（real-device test modules）**：每个模组都有明确的覆盖范围、运行入口、结果口径与维护约束。  
其中 **IP 模组**（本次关注点）必须能在真机上覆盖 L3/L4 firewall 的核心语义与回归风险，并在后续任何大改动时作为必跑套件反复执行，用于评估 **功能/稳定性/性能**。

> 说明：本文是纲领（原则 + 模组边界 + 入口约定），不是某个 change 的实现细节。实现应由对应的 OpenSpec change 逐步落地。

## 1. 这类模组和单元测试/集成测试的关系

这里的“真机测试模组”并不是开发过程中的单元测试，也不是常规的“小而快”的真机集成测试入口。它更像是：
- **面向回归与评估**：在真机上尽可能完整覆盖某个子系统（如 IP）的功能与边界；
- **面向性能与稳定性**：包含规则规模扫描、压力与长期运行；
- **面向可复现**：必须能重复得到可比结果（至少在同一真机/同一网络环境下）。

这些模组可以复用 repo 内的工具/库（例如控制协议发送、adb 封装），但它们的存在目的和运行频率与开发期的 unit/integration 并不相同。

## 2. 为什么要“模组化”

我们要解决的不是“某个 change 的验收”，而是长期的工程问题：

- **回归成本可控**：IP 相关逻辑改动后，能一键重跑同一套测试并得到可比结果。
- **覆盖可累积**：新增 bug/边界 case 时，把它加入组件，不靠人肉记忆。
- **结果可解释**：每条断言都有统一数据源（control reply / PKTSTREAM / METRICS / stats）和口径。
- **可持续维护**：脚本风格、分组、skip 规则、日志/结果记录方式统一。

## 3. 通用原则（所有模组）

1) **可重复**：每次运行都要从干净基线开始（如 `RESETALL`），并在结束时 best-effort 恢复全局开关。  
2) **可子集运行**：支持按“分组/用例”跑子集，支持 `-v`/debug 输出。  
3) **不把环境问题当功能失败**：缺工具/缺权限/设备不满足前置时要明确 `SKIP`（并带原因）。  
4) **尽量确定性**：优先使用 IP literal 与固定端口，避免 DNS/CDN 造成的偶发不稳定。  
5) **小而清晰**：优先拆成多个小用例；失败时能快速定位到具体语义点。

## 4. IP 模组（L3/L4 firewall + IP-side policy）

### 4.1 覆盖范围（what）

IP 模组覆盖“真实 NFQUEUE 流量 → 判决 → 可观测”的闭环，至少包含：

- `IPRULES v1`（per-UID IPv4 L3/L4 rules）
- `IFACE_BLOCK`（接口拦截）
- `BLOCKIPLEAKS`（ip-leak）
- 全局 `BLOCK` gating（`BLOCK=0` 一律 bypass）
- 可观测性与归因：
  - `METRICS.REASONS`（reason counters）
  - `PKTSTREAM`（reasonId/ruleId/wouldRuleId/wouldDrop + src/dst）
  - `IPRULES.PRINT` per-rule stats（hit/wouldHit）
  - （可选）`METRICS.PERF`（perfmetrics，回归/趋势）

明确不在 IP 模组里做（可另立模组）：
- 域名系统（DNSSTREAM/DomainPolicy）本体的完整行为矩阵
- UI/前端联动、远程控制面编排等

### 4.2 运行入口（how）

IP 模组应提供至少两类入口（快/全），并额外提供 perf/stress 能力：

- **ip-smoke（快）**：< 2 分钟，覆盖关键开关与最核心的 enforce/would/no-match。用于开发期高频回归。
- **ip-matrix（全）**：覆盖主要组合与边界（proto/dir/iface/ifindex/CIDR/ports/priority/tie-break/enable）。用于“大改动后必须全跑”。
- （可选）**ip-stress（并发窗口）**：control-plane 变更与真实流量并发，验证不 crash、不死锁、不出现明显 bypass。
- **ip-perf（性能）**：规则规模扫描（N 条规则的代表性集合）+ 固定流量配置下采集 `METRICS.PERF`/吞吐/CPU。
- （可选）**ip-longrun（长期稳定性）**：长时间运行 + 周期采样，捕获泄漏/抖动/尾延迟回归。

### 4.3 断言数据源（assertions）

IP 模组的断言优先级建议：

1) **判决归因**：`PKTSTREAM`（ruleId/wouldRuleId + reasonId）  
2) **聚合计数**：`METRICS.REASONS`（packets/bytes）  
3) **规则级统计**：`IPRULES.PRINT RULE <id>` 的 `stats.*`  
4) **辅助排障**（不作为主要断言）：`HOSTS`、设备侧 `iptables -v`、logcat

### 4.4 流量触发与“可复现流量”（traffic generators）

性能测试要“可复现”，本质上要求**流量源可控**。建议分层设计，优先使用最可控的方案：

1) **本机可控拓扑（最推荐，最可复现）**  
   在真机上用 `ip netns` + `veth` 创建一个本地封闭网络，跑 client/server 产生 TCP/UDP 流量（不依赖公网、不依赖 DNS/CDN）。  
   优点：可复现性最佳；缺点：依赖 root、`ip` 工具与内核特性（netns/veth）。  
   **Android 特别注意**：Android（netd）常用“按网络的路由表”（如 `wlan0`/`rmnet_data0`）做 policy routing。即使你在 main table 里
   配了 `10.200.1.0/24 dev veth_ts0`，`shell` UID 的 `ip route get <dst> uid 2000` 仍可能走 `table wlan0`，从而把
   `10.200.1.2` 误路由到真实网关（导致 ping/TCP 失败）。  
   建议：在 Tier-1 setup 里**动态解析 client UID 对应的 table**，并把测试子网路由注入该 table（并在 teardown 时删除）。

#### 4.4.1 Tier-1（netns+veth）在 Pixel 6a 的可行性结论（已实测）

以下结论基于 **Pixel 6a / Android 14**（示例 serial：`28201JEGR0XPAJ`）在 2026-03-18 的 ADB 实机探测，目的仅是回答：
“Tier-1 的前置条件是否满足？最小可复现流量（HTTP GET/下载）是否能在设备上稳定跑起来？”  
（后续仍要验证：基于该流量的 IPRULES/IFACE_BLOCK 判决语义与统计口径是否满足预期，以及 perf/stress 采样是否稳定。）

- 前置条件：满足
  - 有 root（Magisk）：`adb -s 28201JEGR0XPAJ shell 'su 0 sh -c id'`
  - 有 `iproute2`：`adb -s 28201JEGR0XPAJ shell 'su 0 sh -c \"ip -V\"'`
  - `ip netns` 可用：`adb -s 28201JEGR0XPAJ shell 'su 0 sh -c \"ip netns list\"'`
  - `veth` 可创建：`adb -s 28201JEGR0XPAJ shell 'su 0 sh -c \"ip link add v0 type veth peer name v1; ip link del v0\"'`

- 关键坑点 1：Android policy routing 会让 “不指定接口的 socket” 走 `table wlan0`
  - 现象：即便 `main` 里有 `10.200.1.0/24 dev <veth>`，`ping 10.200.1.2`/`wget http://10.200.1.2/...` 仍可能失败；
    但 `ping -I <veth>` 会成功。
  - 解决：把测试子网路由注入到 **client UID 实际命中的 table**（此机为 `wlan0`）：
    - `adb -s 28201JEGR0XPAJ shell 'su 0 sh -c \"ip route add 10.200.1.0/24 dev iptest_veth0 src 10.200.1.1 table wlan0\"'`
    - teardown：`adb -s 28201JEGR0XPAJ shell 'su 0 sh -c \"ip route del 10.200.1.0/24 dev iptest_veth0 table wlan0\"'`

- 关键坑点 2：Magisk 的 `busybox` 默认路径对 `shell` 不可见
  - 现象：`adb shell /data/adb/ap/bin/busybox ...` 会 “inaccessible or not found”
  - 解决：由 root 拷到 `/data/local/tmp/`（对 `shell` 可执行）：
    - `adb -s 28201JEGR0XPAJ shell 'su 0 sh -c \"cp /data/adb/ap/bin/busybox /data/local/tmp/busybox && chmod 755 /data/local/tmp/busybox\"'`
    - 验证：`adb -s 28201JEGR0XPAJ shell '/data/local/tmp/busybox wget --help | head -n 3'`

- 最小可复现：netns 内跑 HTTP server + main ns 做 HTTP GET（需注入路由）
  - server（root）：`ip netns exec <ns> /data/local/tmp/busybox httpd -f -p 8080 -h <dir>`
  - client（shell）：`/data/local/tmp/busybox wget -q -O /dev/null http://10.200.1.2:8080/payload.bin`

- NFQUEUE 可观测性（PKTSTREAM）：OK（此流量可在 NFQ 中被观测到）
  - 背景：当前设备侧 iptables 把 `INPUT/OUTPUT`（排除 `lo` 与 DNS 端口）送入 `NFQUEUE --queue-balance ...`，因此 veth 上的 TCP/ICMP 也会进入 NFQ。
  - 验证：在 host 侧打开 `PKTSTREAM` 采样，并在设备侧跑 Tier-1 HTTP GET，能看到 `interface=<veth>` + `srcIp/dstIp` 为 `10.200.1.1/10.200.1.2` 的事件，例如：
    - `{\"interface\":\"iptest_veth0\",\"protocol\":\"tcp\",\"srcIp\":\"10.200.1.1\",\"dstIp\":\"10.200.1.2\",\"dstPort\":18080,\"accepted\":1,\"reasonId\":\"ALLOW_DEFAULT\" ...}`

- UID 可控：OK（可用于 per-UID 规则验证）
  - 背景：Tier-1 setup 需要 root，但若设备的 `su` 支持 `su <uid> ...`，client 流量可以在指定 UID 下产生，用于验证 `IPRULES` 的 per-UID 隔离语义；若不支持，则至少可稳定使用 `shell=2000`。
  - 验证：对同一条 `wget`/`nc` 流量，`PKTSTREAM.uid` 会随 `su <uid>` 改变（本机已观测到 `uid=2000` 与 `uid=12345` 两种情况）。

> 注：这台机子上 `toybox` 没有 `curl/wget`，但有 `nc/ping`；`busybox wget/httpd` 可用。

#### 4.4.2 性能规则集（perf ruleset）的口径补充

`IPRULES` 是 per-UID 的，因此 perf 模组建议把规则规模分成两轴记录：
- traffic UID（产生流量的 UID）下的规则规模（推荐 baseline：`N=2000`）
- background（其它 UID）下的规则总量与分布（更贴近真实“很多 app 各自少量规则”）

traffic UID 的 `N=2000` 建议按“少量命中 + 大量不命中”的确定性组合生成（避免 perf 流量落入 legacy/host/domain 慢路径）：
- 1 条 strict hit（推荐 would-block）：确保 perf workload 覆盖到命中路径，同时避免 `enforce ALLOW` 提前短路导致对比口径失真
- 少量 hot rules：覆盖不同 mask 组合（`dir/proto/src/dst/ifindex/ports(any|exact)` 等），提升覆盖面
- 其余 filler rules：多数不命中，用于把规模稳定凑到 2K（固定 seed/顺序）

background rules 建议用 round‑robin 分摊到多个 UID（例如 `N_BG_UIDS=200`，每 UID ≈ 10 条），更贴近真实设备上“几百 app 各自少量规则”的分布。

#### 4.4.3 Perf baseline 的原则（当前阶段先固定）

IP 模组的 perf baseline 当前追求的是一个**稳定、可复现、可比较**的真机基线，而不是“穷举所有可能流量/规则组合”。原则先固定为：

1) **单场景可重复**  
   同一台真机、同一套 workload、同一套规则集，独立重复运行多轮后，核心指标应当只在可接受的小范围内波动。  
   口径建议：优先使用“打流端”吞吐/txns（例如 neper `throughput`），并用 `/proc/net/netfilter/nfnetlink_queue` 的 drop/seq 增量作为 guardrail；`METRICS.PERF avg/p95/p99` 可作为补充曲线，但不建议在统计组件可能成为瓶颈时作为硬 gate。若同一场景自身都不稳定，则不能作为 baseline。

2) **跨场景可拉开差距**  
   baseline 不只是要“能跑”，还要能让典型场景之间出现可观察的差异。当前关注的场景包括：`BLOCK=0`、`IPRULES=0`、`IPRULES=1 + empty rules`、`IPRULES=1 + 2K rules`、`IPRULES=1 + 4K rules`。  
   如果不同场景之间长期几乎无差异，则这套 baseline 对后续优化/回归的诊断价值有限。  
   但也要接受一个现实：当 rule engine 的 cache 很有效时，**cache-on 的真实热路径**在 `2k vs 4k` 下可能只差几个百分点，这并不一定代表“baseline 失败”，而是代表“实际使用时 cache 在工作”。此时需要额外引入 “cache-off / cold-cache” 的诊断口径来放大算法差异（见第 6 点）。

3) **先追求固定 workload，再追求覆盖面**  
   当前阶段不追求把“所有真实流量形态”和“所有规则组合”都塞进 baseline。先冻结一组固定 workload 和固定 ruleset，确认它具备稳定性与区分度；后续再逐步增加额外 workload/ruleset 作为补充，而不是一开始就做成一个无法解释的大杂烩。

4) **流量应优先打到 rule engine 的真实热路径**  
   baseline 应尽量避免被“单长连接 exact cache 热起来”或“enforce ALLOW 提前短路 legacy path”这类现象主导。  
   更推荐使用固定参数的多流、短连接、tuple churn 流量，以及不会改变最终 accept/drop 语义的规则语料（例如 `would-block`）来测量判决成本。
   - 经验补充：若在 TCP（即使是短连接）下仍然无法稳定拉开 `2k vs 4k`，通常意味着“连接/握手/accept”等成本淹没了 rule-eval；此时应考虑切换到更高 pps 的 UDP micro-benchmark（仍遵循 guardrails：`nfq_*_dropped_total=0`），详见 `docs/testing/ip/IP_TEST_MODULE.md` 的 neper baseline 记录。

5) **结果记录要保留探索痕迹**  
   在 baseline 尚未完全定型前，需要把“为什么放弃某条路径、为什么保留某个候选 workload/ruleset”记入 runbook。这样即使后续对话被压缩、上下文丢失，也能从文档恢复思路演进过程。

6) **分层：cache-on baseline + cache-off 诊断（目的不同）**  
   我们需要两套 perf 口径，分别回答不同问题：
   - **cache-on baseline（默认）**：尽量贴近真实线上路径；允许差异只有几个百分点，只要稳定、可复现、能长期对比即可（用于“回归/趋势”）。
   - **cache-off / cold-cache 诊断**：人为放大 “规则规模/匹配策略/数据结构” 的成本，用于评估算法复杂度、验证优化是否真实有效（用于“诊断/对比/放大差距”）。  
   为了避免在每个包的热路径上引入任何额外判断成本，建议以 **DEV-only 的 cache-off 二进制变体**落地：一次构建产出两份二进制（cache-on 默认 + cache-off 诊断版），通过“部署/重启切换二进制”的方式选择模式，而不是运行时 toggle。

2) **局域网固定 server（推荐，用于更真实吞吐）**  
   在实验网/局域网提供固定 IP 的 HTTP/iperf server；模组以 IP literal 访问并做下载/吞吐。  
   优点：更接近真实网络；缺点：需要稳定的实验网环境。  

3) **公网 fallback（仅用于“能跑通”，不用于严格性能 gate）**  
   使用固定 URL 下载（可能配合 `curl --resolve` pin IP），只做记录与趋势观察；不建议作为硬阈值 gate。

优先使用设备侧内建工具生成真实网络流量：

- ICMP：`ping -c 1 -W 1 <ip>`（使用 IPv4 literal 即可；部分 Android ping 不支持 `-4`）
- TCP：`nc -4 -n -z -w 2 <ip> <port>`（只要求产生包，不要求握手成功）
- UDP：`printf x | nc -4 -n -u -w 1 -q 0 <ip> <port>`
- 大流量（用于 perf/stress）：`curl`/`wget`/`toybox wget` 下载固定 URL（尽量复用现有 `perf-network-load` 的策略）

约束：
- 避免 `lo` 与 `53/853/5353`（当前 iptables 会 `RETURN`，不进 NFQUEUE）
- 入站（`dir=in`）与 UDP 回包可能不稳定：允许 best-effort，但必须把“无法观测到回包”归为 `SKIP` 而不是误判失败。

### 4.5 结果记录（长期回归）

对 ip-matrix / ip-stress / ip-perf，建议保存：

- 设备信息：model / Android version / fingerprint
- 守护进程版本：git sha 或构建标识
- 执行命令与关键环境变量（serial / target ip / ports）
- PASSED/FAILED/SKIPPED 汇总
- 若失败：失败用例的最小复现步骤 + 关键输出（control reply / counters / stream sample）

## 5. 目录与命名建议（实现约束）

建议把 IP 模组实现为独立目录（不与 unit/integration 的入口混用），例如：

- `tests/device-modules/ip/`（推荐，表达“真机回归模组”语义）
- 或 `tools/device-modules/ip/`（若更偏向诊断/评估工具链）

并提供一个统一 runner（可子集运行）：

- `tests/device-modules/ip/run.sh`（总入口：`--profile smoke|matrix|stress|perf|longrun` 或 `--group/--case`）
- `tests/device-modules/ip/cases/*.sh`（小用例，按字母/编号运行）
- `docs/testing/ip/`（runbook + 结果记录）

是否接入 CTest/CI 取决于运行时长与环境稳定性：原则上该模组是“手工/回归评估必跑”，不强制作为 CI gate。
