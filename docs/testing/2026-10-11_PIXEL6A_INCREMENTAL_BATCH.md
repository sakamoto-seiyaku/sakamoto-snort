# Pixel 6a：逐项批处理与 B0／B1／B2／B2r／B3 比较

> **2026-10-11 已撤回实验改动。** 用户明确要求撤回收益未成立的 B1／B2／B3，
> 保留为文档及实测证据。源码和 Pixel APK 均已回到本轮入口代码加独立 Root
> ENOBUFS 恢复修正；没有实施此前建议的空规则缓存函数优化。以下性能表描述
> 历史实验版本，不代表当前部署。撤回证据和 VPP 机制核对见文末。

2026-10-11 用户要求小步推进，每改一项就跑一次基准，并保留过程记录。
执行顺序为 B1：VPN egress 出口批量提交；B2：再增加 policy 存活包批量提交；
B3：再增加 Root／TUN 本回调入口 frame 聚合。每轮是累积版本，新增项分别比较
上一轮和原始 [B0](2026-10-09_PIXEL6A_QUICK_BASELINE_AND_HOTSPOTS.md)。

## 有效结果与结论

三个批处理项在实验中均曾实现，B1、B2、隔离恢复修正 B2r、实验 B3 分别完成原固定八组真机测量；现已撤回这三个批处理项。
最终 B3 完整耗时 **105.444 秒**，errors 空。与 B0 比较，VPN 固定 TCP／UDP
交付约 **−2.16%／−2.73%**，新 TCP 完成率 **−0.33%**；当前单次快测没有明确提速证据。
Root 固定 TCP 波动范围 149–466 Mbps，最终 311 Mbps 与 B0 接近，不能将对前一轮的
大幅回升归因于入口聚合。实验曾将 frame/helper 调用组织改为批量，端点收益尚未证实，因此该改动不保留在当前实现。

[完整比较表及 JSON](../../build-output/pixel-batch-incremental-20261011/comparison/index.html)、
[构建及运行资格清单](../../build-output/pixel-batch-incremental-20261011/qualification.json)、
[包含端点、归因、容量、CPU 与延迟的资格样本](../../build-output/pixel-batch-incremental-20261011/qualified-scores.json)。

下表为端点交付 Mbps；只有 TCP-new 行使用成功完成 CPS。UDP-new 的交付来自许多
新 tuple 的尝试，不能当作全部已建立／被策略处理的会话吞吐。

| 模式／负载 | 单位 | B0 | B1 出口 | B2 policy | B2r 恢复 | B3 入口 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| root / tcp-fixed | Mbps | 310.45 | 365.99 | 465.88 | 148.97 | 311.11 |
| root / udp-fixed | Mbps | 547.04 | 543.81 | 356.51 | 417.42 | 507.78 |
| root / tcp-new | CPS | 1480.98 | 1396.76 | 1410.00 | 1457.99 | 1581.86 |
| root / udp-new | Mbps | 424.10 | 434.38 | 436.69 | 427.28 | 474.69 |
| vpn / tcp-fixed | Mbps | 104.90 | 103.15 | 102.90 | 102.64 | 102.64 |
| vpn / udp-fixed | Mbps | 244.34 | 241.17 | 240.02 | 231.50 | 237.67 |
| vpn / tcp-new | CPS | 972.88 | 999.50 | 953.04 | 973.62 | 969.70 |
| vpn / udp-new | Mbps | 3.85 | 3.85 | 3.84 | 3.83 | 3.81 |

UDP-new 的发生器输入 tuple/s 另列；这些数值不是 VPP Flow creates 或对端新连接成功率。

| 模式 | B0 | B1 | B2 | B2r | B3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| root | 51167 | 49544 | 45921 | 47307 | 48325 |
| vpn | 6399 | 6537 | 6337 | 6304 | 6431 |

VPP process CPU seconds 为采样首尾的实际线程 CPU 计数差，涵盖 VPP 主线程、worker
和 HEV 线程；首尾通常覆盖约 4.8／5 秒，原始结果另保留按窗口外推的估计。
多线程累计 CPU 秒可大于墙钟秒，不含手机其它进程及电气功耗。不能仅比较 CPU
总秒数而忽略实际交付量和 bypass。

| 模式／负载 | B0 CPU s | B1 | B2 | B2r | B3 |
| --- | ---: | ---: | ---: | ---: | ---: |
| root / tcp-fixed | 3.05 | 3.27 | 3.41 | 2.21 | 3.14 |
| root / udp-fixed | 4.73 | 4.74 | 4.62 | 4.82 | 4.62 |
| root / tcp-new | 3.16 | 3.07 | 3.09 | 3.11 | 3.27 |
| root / udp-new | 4.26 | 4.28 | 3.08 | 4.39 | 4.34 |
| vpn / tcp-fixed | 4.78 | 4.60 | 4.73 | 4.73 | 4.58 |
| vpn / udp-fixed | 9.23 | 9.25 | 9.21 | 9.23 | 9.23 |
| vpn / tcp-new | 4.93 | 6.39 | 4.92 | 4.98 | 4.99 |
| vpn / udp-new | 4.97 | 5.14 | 5.14 | 5.06 | 5.10 |

最终新建窗口仍存在大量 Flow capacity misses。它们与 Root 未 admission ACCEPT
及 VPN Flow Stack session 上限独立于 frame 聚合，当前未改变容量或 fail-open 合同。
最终窗口的实际归因如下；原始 JSON 保留所有前序版本。

| 模式／负载 | Flow creates | Capacity misses | Root unadmitted ACCEPT | 成功 p99 上界 ms | 成功延迟样本 |
| --- | ---: | ---: | ---: | ---: | ---: |
| root / tcp-fixed | 68 | 0 | 18801 | 319.9 | 231 |
| root / udp-fixed | 67 | 0 | 64735 | 132.2 | 3 |
| root / tcp-new | 1899 | 35448 | 20645 | 111.7 | 7920 |
| root / udp-new | 2030 | 81391 | 42415 | 156.0 | 13 |
| vpn / tcp-fixed | 71 | 0 | 0 | 814.2 | 60 |
| vpn / udp-fixed | 66 | 0 | 0 | 129.6 | 2 |
| vpn / tcp-new | 1928 | 17956 | 0 | 256.5 | 4856 |
| vpn / udp-new | 2024 | 117648 | 0 | 149.7 | 691 |

固定 UDP 的最终 Root／VPN 延迟只有 3／2 个成功样本，不能用于稳定 p99 或收益判断；
timeout、错误与窗口结束取消仍在 client JSON 单独记账。表中 p99 仅覆盖成功样本。
捕获守卫要求有 native 进展，它不证明所有端点流量经过完整策略链。


## 固定条件与产物

沿用 B0 的 Pixel 6a、LAN 对端 `192.168.4.5:41320`、W2、零规则 revision 907、
发生器及其二进制、4 线程、64 固定流／TCP-new 窗口槽、1200 B UDP、
八组各 5 秒、199 Hz 同窗 profiling 和完整入口 120 秒 deadline。
各次正常清理，失败记录独立保留；不将未完成运行并入性能比较。

产物根目录：[逐项构建及验证记录](../../build-output/pixel-batch-incremental-20261011/)。
进入本轮前的源码、既有 dirty diff 和 SHA 已保存于 `before/`、
`before-worktree.diff`、`before-source-sha256.json`，后续只记录本轮新增改动。

使用固定生产 VPP pin 与 B0 同一运行库 stage，仅重建 Product 插件；其余11个 native
payload 保留 B0 的逐字节内容，APK assembler 使用既有 `--apk-only` 校验入口。
每轮检查 `classes.dex` 和全部 native payload，要求唯一变化为 Product 插件。
保留与该轮安装插件匹配的 unstripped ELF、源码快照、构建日志和 APK SHA。

## 执行记录

- B1：已将 VPN egress 的逐包输入／metadata 更新保留在原循环，循环末一次提交
  所有原包到唯一 terminal next。Flow Stack return callback 仍使用原即时 native
  scheduling；原包不在循环中释放。生产 native 构建、APK payload 比对和既有
  `product_vpp_contract.sh` 通过。真机八组完成，耗时 **105.775 秒**，errors 空；
  [原始结果](../../build-output/pixel-batch-incremental-20261011/B1/run/result.json)、
  [与 B0 比较](../../build-output/pixel-batch-incremental-20261011/B1/comparison/index.html)、
  [逐组火焰图索引](../../build-output/pixel-batch-incremental-20261011/B1/graphs/index.json)。
  VPN 固定 TCP／UDP 交付相对 B0 为 −1.67%／−1.30%，新 TCP 完成率 +2.74%；
  新 TCP VPP CPU 同时从 4.93 s 增到 6.39 s，不能报告为明确效率提升。
  Root TCP 固定交付 +17.89%，但该路径不执行本次改动，作为跨日快速测量的波动提示。
- B2：仅追加 policy 存活包输出聚合。stale 包仍按原路径释放；逐包状态、snapshot、
  Flow/CT/LPI 和 attribution 顺序保留。每个 next frame 的首包即时发布，剩余容量
  内聚合提交，满后重新即时发布首包。这样保留原来的 pending-frame 顺序，包括
  后续 packet evaluation 所发布的独立 FlowEnd frames。当前生产构建和 payload
  比对通过，进入独立真机测量。
- 构建准备记录：初次缺少 `ply` 搜索路径，改用系统已有包；B2 初次变量声明位置
  错误由 native 编译发现，修正后编译通过。两次失败构建日志分别保留于
  `B1-build-preparation-failed/` 与 `B2-build-declaration-failed/`；它们没有安装到手机，
  不属于性能样本。
- B2 第一轮：入口完成八组，原工具输出 `COMPLETE`／105.372 s，但 Root 新 TCP
  有 11,848 次端点完成，VPP Flow creates、CPU 与捕获计数增量均为零；固定 UDP
  的 CPU 也在窗口后段停止。此轮标为 **INVALID_CAPTURE**，保留于
  [原始异常记录](../../build-output/pixel-batch-incremental-20261011/B2/run-invalid-capture/result.json)，
  [有效性判断](../../build-output/pixel-batch-incremental-20261011/B2/run-validity.json)。
  native 仍显示 lane ready、债务为零，这些状态不能替代实际捕获进展。此轮成绩
  不用于判断批处理收益；当时证据没有确定故障根因，后续取证与修正见下文。
- 测量工具修正：使用原有 before/after CLI 检查 Root generation 与 datagrams
  进展；新建窗口还要求实际 Flow creates 增加。无进展时保留失败窗口，并在
  正常清理前读取内核 NFQUEUE／hook 诊断；有效窗口不增加设备操作。report 对
  旧结果也重新检查，B0／B1 通过，异常 B2 被拒绝。新增捕获守卫回归先失败再
  通过，日志保留于产物目录。这是工具资格修正，**没有宣称修复 Root 产品故障**。
- 短复现：同一 B2 新开正常 Root 生命周期，250 ms TCP 暖机 → 5 s UDP 固定
  → 1 s TCP 新建均有捕获进展；新 TCP 完成 1,735 次。内核队列／hook 读回与
  图内债务已保留于
  [诊断记录](../../build-output/pixel-batch-incremental-20261011/capture-repro-B2-1791702628601322208/result.json)。
  原异常未在此短循环复现，不能据此给根因定性。随后对同一 APK、同一固定配置
  重跑 B2 完整基准；第 3 项此时仍未修改。
- B2 重跑准备：一次因旧手机目录已存在而在测量前停止（1.240 s，0 组），一次
  暖机无交付停止（11.846 s，0 组）。均保留独立失败目录。随后使用已保存 APK
  做 B1／B2 短对照：5 s TCP 固定 → 5 s UDP 固定 → 1 s TCP 新建均能推进
  捕获计数、清理债务；新 TCP 完成 294／1,548 次。它们属于诊断，窗口不同，
  不加入性能表；内核队列与 hook 均有原始读回，当时未确定异常根因。
- B2 有效重跑：同一 APK、原固定参数八组完成，**105.375 s**，errors 空，
  [原始结果](../../build-output/pixel-batch-incremental-20261011/B2/run/result.json)、
  [B0／B1／B2 比较](../../build-output/pixel-batch-incremental-20261011/B2/comparison/index.html)。
  VPN 固定 TCP 102.90 Mbps、固定 UDP 240.02 Mbps、TCP-new 953.04 CPS，
  相对 B1 约 −0.24%、−0.48%、−4.65%。Root 固定 TCP 465.88 Mbps、固定 UDP
  356.51 Mbps，方向相反，当前单次快测没有一致收益证据。
- B3：仅追加 callback-local native frame builder。Root／TUN 内部回调逐包做原来的
  参数／generation 检查、metadata 准备、obligation 与 buffer 记账，聚合已取得的
  buffer indices；外层回调在正常、EAGAIN、budget 和故障返回时统一 flush。
  保留 64 次非阻塞接收预算，没有等待未来包或新增跨回调队列。HEV return 仍走
  立即 scheduling 的原 single-packet API；TUN write／NFQUEUE verdict 没有改成
  I/O batch。native 构建、payload 比对和已有构建契约通过。
- B3 故障排空：正常 Root 入口在真实 packet 1 已 admission、pending=1 后触发
  一次性 listener fault。回调返回前 flush 的 frame 仍完成该 packet 的 verdict
  syscall（result=32／errno=0），本代 ready mask、buffer、obligation、handoff、
  completion frames 全部归零，residue clean，规则 SHA 不变。
  [证据](../../build-output/pixel-batch-incremental-20261011/B3/ingress-fault/result.json)
  记录 generation 1839；故障原因显示 lane errno 9 属预期注入，随后正常停机。
  完整 B3 基准此后单独运行。
- B3 初版基准：Root 固定 TCP 418.82 Mbps 后，固定 UDP 全窗口无接收计数进展，
  新守卫拒绝此轮：32.949 s／1 组，`INCOMPLETE`。清理时一次 adb 查询超时；
  后续最终审计和独立读回均确认 stopped、mayBeActive=false、无 VPP、规则未变，
  native stop 日志债务全零。原始 B3 构建、故障检查和失败基准保留原目录，
  不作为有效性能版本。
- 新取证：失败现场内核 queues 176–179 存在，队列 176 outstanding=0、ID sequence
  已达 2,641,152；VPP datagrams 却停在 40,804。hook 的 UID 为 12632，UDP NFQUEUE
  规则命中约 235 万包，图内债务为零。这排除了该现场的 hook 缺失与图内未结清；
  不直接等同于已经读出了内核私有 congestion bit。
- 回调审查排除 edge-triggered 假设：实际 flags=0，为 level-triggered。发现旧
  error callback 在 `SO_ERROR=ENOBUFS` 时仅分类并返回，不再进入 recv。
  [Linux 6.1 Netlink](https://github.com/torvalds/linux/blob/v6.1/net/netlink/af_netlink.c)
  的 overrun 设置 congestion bit；recvmsg 的退出路径调用 `netlink_rcv_wake`，
  在空接收队列时清理该位。仅消费 SO_ERROR 缺少这个恢复步骤，机制与现场吻合。
  手机实际 kernel 为 `6.1.134-android14-11-g66e758f7d0c0-ab13748739`；上述引用为
  官方 6.1 机制依据，不冒充该手机二进制内存状态的直接观测。
- 独立修复版本 **B2r**：临时仅恢复本轮保存的 B2 源码，再单独加入 ENOBUFS
  分类成功后调用同 lane 的既有 bounded read callback。没有扩容、轮询、迁移
  ownership 或忽略其它永久错误。宿主回归直接编译实际 error callback body，
  在 SO_ERROR／接收后端 seam 验证错误消费后仍执行一次接收；旧版断言失败，
  修复版通过，并检查永久错误、SO_ERROR=0、stale generation 与 draining。
  该后端为 stub，真实内核效果仍以随后设备压力结果检验。
- 为遵守逐项比较，B2r 先独立测量；入口聚合随后重新加入，最终 B3 构建保存在
  `B3-final/`。比较标签为 B0／B1／B2／B2r／B3；原 `B3/` 是未修复恢复缺口的
  初版及其失败证据，不覆盖。
- 构建资格修正：恢复快照保留了旧 mtime，复用 Ninja 目录曾跳过 graph／TUN
  的重编，导致首次 `B2r/` binary 仍包含 snapshot 中不存在的 batch API。
  已保存 symbol 反证及 `build-validity.json`，该轮标 **INVALID_BUILD_IDENTITY**，
  不能作为隔离修复／批处理比较。随后构建在每轮强制刷新四个本轮源输入的 mtime，
  并比对源码与 unstripped binary 是否含 batch API；相关对象明确重编。
  正确产物改用 `B2r-final/` 与 `B3-final2/`，旧产物全部保留；比较仍用 B2r／B3
  标签。这是本次构建流程错误及修正，原 B1／B2 为直接编辑后构建，不受此快照
  恢复问题影响。

- 正确隔离版本 `B2r-final/`：源码与 binary 均无 entry batch API；四个本轮
  C/H 输入及其依赖明确重编，payload 校验仅 Product 插件变化。第一次正确构建
  的测量在暖机停止（0 组），随后同一 APK 重跑八组完成 **105.034 s**，errors 空，
  Root 捕获守卫、两个正常 Root 生命周期零债务与最终规则身份检查全部通过。
  [原始结果](../../build-output/pixel-batch-incremental-20261011/B2r-final/run/result.json)、
  [隔离比较](../../build-output/pixel-batch-incremental-20261011/B2r-final/comparison/index.html)。
  这支持恢复后的实际捕获仍可推进；一次完整通过不构成长期可靠性证明，也不能
  将此前每次异常均归为同一原因。
- 最终入口版本 `B3-final2/`：在上述有效测量完成后重新加入 B3 的同一 entry
  实现，并保留完全相同的 Root 恢复修正。源码与 binary 均含 batch API，native
  编译日志确认 graph、Root、TUN 重新编译；classes.dex 与其余 11 个 native
  payload 仍与 B0 相同。真机八组完成 **105.444 s**，errors 空，Root 捕获与最终清理／规则守卫通过。
  [最终原始结果](../../build-output/pixel-batch-incremental-20261011/B3-final2/run/result.json)。

## 最终同窗火焰图

最终各组保留实际窗口内 perf 数据、匹配的 unstripped Product ELF 与交互火焰图。
[按采样 period 加权的原始分析](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/period-analysis.json)
由 [离线脚本](../../build-output/pixel-batch-incremental-20261011/analyze-final-perf.py) 产生，
没有追加设备负载或改动发生器。以下 inclusive 份额包含嵌套调用，**不能相加**。

| 最终窗口 | kernel period 份额 | 主要调用链证据 | 火焰图 |
| --- | ---: | --- | --- |
| Root TCP fixed | 83.71% | sendto 67.56% → netlink_sendmsg → NFQUEUE verdict/reinject | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/root-tcp-fixed-flamegraph.html) |
| Root UDP fixed | 74.95% | sendto 62.34%，nf_reinject 44.01% 为同链重叠 | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/root-udp-fixed-flamegraph.html) |
| Root TCP new | 84.43% | sendto 77.68%，netlink_sendmsg 72.54% 为同链重叠 | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/root-tcp-new-flamegraph.html) |
| Root UDP new | 83.94% | sendto 70.63%，nf_reinject 53.33% 为同链重叠 | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/root-udp-new-flamegraph.html) |
| VPN TCP fixed | 65.01% | write 46.94% → tun_chr_write_iter 42.26% | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/vpn-tcp-fixed-flamegraph.html) |
| VPN UDP fixed | 55.41% | __sendmsg 38.29%，仍有 HEV／socket 发送链 | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/vpn-udp-fixed-flamegraph.html) |
| VPN TCP new | 70.90% | write 21.46% → tun_chr_write_iter 18.66% | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/vpn-tcp-new-flamegraph.html) |
| VPN UDP new | 39.83% | vlib_file_poll 28.78%，udp_input 16.62% | [打开](../../build-output/pixel-batch-incremental-20261011/B3-final2/graphs/vpn-udp-new-flamegraph.html) |

入口／节点 frame 聚合没有改变 NFQUEUE verdict syscall、TUN write 或 HEV socket
发送合同。这些路径仍占较大份额，与本轮缺少明确端点提升相符，但采样份额本身
不能换算成未来优化承诺。最终 zero-rule UDP fixed 的 `product_l4_policy_match_cached`
self period 为 Root **4.17%**、VPN **4.58%**，是仍可讨论的独立准备开销；本轮未改它。
B0 的插件是 stripped，不能将旧 unknown 样本强行归入该函数做函数级前后差值。

## 验证与最终状态

- 最终生产插件构建通过；源码 batch API 与 binary 一致，四个本轮输入及依赖重新
  编译；`classes.dex` 与其余 11 个 native payload 对 B0 逐字节一致。
- `product_vpp_contract.sh`、Root SO_ERROR／recv 进展回归、捕获资格守卫回归通过，
  `git diff --check` 无问题。真实 Root 故障排空证据来自初版 B3：最终沿用完全
  相同的入口 wrapper，仅另加已隔离的 ENOBUFS 修正，没有重复整套故障活动。
- 最终八组均通过捕获检查；两个正常 Root 生命周期分别验证 native 零债务及
  residue clean，最后独立读回确认 stopped、mayBeActive=false、无 VPP 进程。
  [最终身份审计](../../build-output/pixel-batch-incremental-20261011/final-device-audit/result.json)
  检查 app UID、规则、发生器和安装 APK，源码与最终构建快照一致。
- 最终 APK 为
  [B3-final2](../../build-output/pixel-batch-incremental-20261011/B3-final2/apk/sakamoto-runtime-debug.apk)，
  SHA256 `3debabe2a1a552aa15262084be807bbb2bf9055af9870b47f832c60ad9a9cbea`，
  在实验结束时曾安装到 Pixel，现已被下文的 R0-recovery 撤回版本替换。仅停止本轮拥有的 LAN peer；手机规则未修改。
- [累计补丁](../../build-output/pixel-batch-incremental-20261011/final-increment.patch)
  对照进入本轮时的工作树，不把先前 Android Root fault／runtime 等修改归入本轮。
  保留全部失败与失效产物，没有创建 Plane 任务或提交 git commit。

这轮是零规则、单次快速测量，覆盖实际 Root 与普通 VPN；没有增加 rules／capacity、
rate sweep、热稳态活动或整机能耗验收；每个合格版本只取一轮有效样本，失效重试
和短诊断单独保留。后续投资应使用这里的有效样本，
避免把失效捕获或混入旧对象的构建当成收益。

## 用户要求后的撤回与留存

用户明确要求：收益未成立的改动撤回，实验保留为文档；下一轮关注目前没有充分
利用的 VPP 批处理机制，不继续单个缓存函数的小幅优化。执行结果：

- `product_packet_graph.c`、`product_packet_graph.h`、`product_vpn_tun_adapter.c`
  逐字节恢复为本轮入口快照，撤回 egress、policy 及 callback-local frame 改动。
- Root adapter 同样恢复入口快照，再保留独立的 ENOBUFS 恢复修正。相对于本轮
  入口快照，仅留下这一个恢复分支；原有 Root fault/runtime 改动仍保留。
  [源码撤回证明](../../build-output/pixel-batch-incremental-20261011/rollback/source-proof.json)、
  [仅保留的产品补丁](../../build-output/pixel-batch-incremental-20261011/rollback/retained-product-change.patch)。
- 重建并安装
  [R0-recovery APK](../../build-output/pixel-batch-incremental-20261011/R0-recovery/apk/sakamoto-runtime-debug.apk)，
  SHA256 `d4aab5dbeecab3cfabc204de29212da45f78be65227abfea4201df6b88228974`。
  源码／binary 均无新增 batch API，classes.dex 与另 11 个 native payload 仍与 B0
  相同。安装保留 app UID、规则与已上传 helper。
- Root 与普通 VPN 正常启动／停止各一次通过；Root native 债务全零、residue clean；
  最后 stopped、无 VPP，安装 APK／源码／UID／规则／helper 身份通过。
  [撤回烟测](../../build-output/pixel-batch-incremental-20261011/rollback/runtime-valid/result.json)。
  初次烟测脚本读取了不存在的日志路径，正常停止后保留失败记录；修正为现有
  `s242-last-stop.log` 后完成两模式验证。这是检查脚本修正，没有追加性能样本。
- 原始测量、火焰图、构建失败、无捕获和错配对象证据继续留存；捕获资格守卫与
  Root 恢复回归也保留。`product_vpp_contract.sh`、Root 进展回归和 diff check 通过。

## 撤回后：实际使用了哪些 VPP 批处理机制

这里区分框架已经做的工作与产品 node 调用方式，避免再次把减少 helper 调用
写成完整机制优化。实际核对使用本产品固定 VPP pin
`9258530f3804a152578ce11cc7c8a1e9eab88ed0`，并逐字节对照其 Git HEAD；
[一手源码身份](../../build-output/pixel-batch-incremental-20261011/rollback/vpp-mechanism-sources.json)。

| 层次 | 当前事实 | 没有充分使用的机制 |
| --- | --- | --- |
| VPP graph 调度与 next frame | 产品已注册 vector nodes，next-frame cache 会聚合后续元素 | 不能将这层描述成完全没有批处理；B1／B2 主要省 helper，原下游已经能聚合 |
| Root／TUN → admit | 每包创建 `n_vectors=1` external frame | 入口 frame形成曾在 B3 试验；单独加入未显示明确收益，现撤回 |
| admit／policy／consumer 主循环 | 每包获取 buffer、准备数据，再逐包完整执行；没有 frame-level `vlib_get_buffers`、x2/x4 或显式预取流水线 | 在节点中按 frame 准备独立输入，提前取得后续 buffer／hash bucket／记录；state mutation 仍保持原包顺序 |
| native primary handoff 发布 | `product_primary_handoff` 每次 retained enqueue 的 count 为 1 | 对同一 node 已准备、同目的 worker 的 indices 整批发布，减少实际 queue 槽位与 publication 操作 |
| native completion return 发布 | `product_completion_return_try` 同样 count=1 | completion buffers 按 origin worker 整批发布；失败集合逐项保留／排队，成功后不再访问 buffer |
| native frame queue 接收 | 上游 dequeue 将多个 queue elements 合并为一个 graph frame | 接收端有聚合，不能把发送端 count=1 等同于接收 node 必然只收到一包；发布开销仍是逐项 |
| 规则与 Flow 查询 | 产品 interface 是单 packet／assignment，Flow bucket 链逐项查找；规则单 key 已有编译器 NEON 证据 | 尚无跨独立查询的分阶段准备／查找流水线；单 key SIMD 不代表跨包 classifier |

具体产品入口：
[admit 与 primary handoff](../../src/product/vpp/product_packet_graph.c#L1185)、
[policy](../../src/product/vpp/product_packet_graph.c#L1587)、
[completion return](../../src/product/vpp/product_packet_graph.c#L1851)、
[external scheduling](../../src/product/vpp/product_packet_graph.c#L4043)。

固定上游的
[ACL node](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L243)
先整 frame 获取 buffer pointers，以短窗口准备 tuple／hash，随后流水预取 session
的 bucket、data 和记录。其复杂状态处理仍按包执行，并处理前包创建新 session 对
后包预测结果的影响。这说明 VPP 批执行不要求把整个规则解释器改成跨包 SIMD；
它要求调用者把独立准备、访存与发布组织成一段完整数据路径。该源码是执行组织
的依据，不是本产品速度收益证据；不会导入 POC、移植已移除 C++ 或替换既有规则语义。

同 pin 的
[frame queue 发送与接收](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L290)
确认两种机制不同：同目的数组可在一次发布中压缩为一个 queue element；dequeue
又会将多个已发布 element 聚成 graph frame。当前产品的 count=1 没利用前者，
框架仍提供后者；不能因 bulk interface 存在就称产品已采用整批 publication。

下一项的审查单位应是 **整段节点输入准备 → owner-local 处理 → native 发布**，
而非零规则哈希函数。需要连同实际 vectors/call、vectors/publication、queue
拒绝与 credit、节点成本一起验证，确认机制在真实流量中被使用。Root 的 kernel
verdict/reinject 与 VPN 的 TUN／socket 工作仍在批处理之外；当前证据不支持预先
承诺吞吐倍数。没有在本次撤回中实施新的批处理方案，也没有创建新的 tracker 任务。
