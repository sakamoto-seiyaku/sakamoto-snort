# 临时讨论：Pixel 6a 两分钟 TCP／UDP 快速基准

日期：2026-10-08；实测与分析更新至2026-10-09。状态：工具与八组真机B0已完成，整轮105.886秒；最终冻结每组5秒。[结果与热点](../testing/2026-10-09_PIXEL6A_QUICK_BASELINE_AND_HOTSPOTS.md)。本文替换此前过大的多档／多协议方案。旧草稿留在 `/tmp/sakamoto-baseline-discussion-before-120s.md`，历史性能证据没有改动。

## 1. 用户确定的首版范围

**每次完整运行最多约 120 秒，必须同时覆盖实际 Pixel 6a 的 Root 和普通 Product VPN。** 每模式跑四组：TCP 固定多流、TCP 大量新建连接、UDP 固定多流、UDP 大量新五元组。并发压力尽量打满当前配置的 VPP workers，数据和 CPU 从手机取得；LAN 机器只作为受控对端。

首版排除 TLS、SNI、QUIC、PCAP 混合、规则规模矩阵、额外档位和每组重复三次。当前测试规则／观察配置及 worker layout 固定并记录，不用修改 VPP worker 数、系统内核参数或增加运行期容量来制造收益。

这里“新建 UDP”是新五元组／新 flow 压力，没有 TCP 式握手。并发 socket、五元组数和发生器 I/O 线程数分别记录；线程更多不等于 VPP 压力更大。

## 2. 每模式四组，每组固定 5 秒

| 组 | 负载 | 首要成绩 |
| --- | --- | --- |
| TCP fixed | 固定多条持久 TCP，多个 I/O 线程／连接并发持续传输；首版采用类似多线程下载的方向 | 对端与手机实际交付 Mbps、CPU／GiB、负载下小请求 RTT p99 |
| TCP new | 固定上限的并发窗口不断 connect → 小请求／响应 → close，持续产生不同源端口和新五元组 | 成功完成连接／秒、尝试／失败、connect＋首个响应 p99；实际 VPP Flow 创建另列 |
| UDP fixed | 固定多条五元组，多个 I/O 线程持续尽力发包，固定 payload 尺寸与方向 | 实收 pps／Mbps、loss／duplicate、CPU／packet、probe RTT p99 |
| UDP new | 不断使用新五元组发送带序号的小批数据并换下一组，由少量 I/O 线程管理大量 socket | 不同五元组输入／秒、实收 pps、新 Flow 创建／容量 miss、响应 p99 |

固定流数／并发窗口在首次短校准时选到发生器与对端有余量、当前所有 VPP workers 能取得负载的参数，然后冻结为 B0 的配置。手机发生器和 VPP 的各线程 CPU 分开记录；后续版本不得改变并发参数后仍当成同一基准。首版不做完整并发度扫描。

每组只执行一次固定的尽力加压，取消多档、三次重复和额外预设速率曲线。每天／每次优化累积的 B0、B1、B2…就是版本曲线；收益不清楚时才由用户选择额外复跑，不塞入默认两分钟入口。

实际顺序为固定TCP→固定UDP→新TCP→正常停止／重启→新UDP，每模式两次生命周期。新建两组不共享满流表；测量前占用必须低于容量10%，每组起止占用逐项记录。正常native清理和VPP退出后关闭测试App，再启动下一代，避免Android Service的异步回调交接。现有TCP CLOSED／UDP FIRST超时为30／60秒，不等待自然到期，不引入另一套Flow权威或reset shortcut。[当前超时](../../src/product/vpp/product_flow_timeout.h)

## 3. 整轮预算：40 秒负载，其余至多80秒用于采集与生命周期

```text
Root：4 × 5秒 = 20秒
VPN ：4 × 5秒 = 20秒
启动、暖机、状态隔离、诊断、模式切换和收尾：最多80秒
已完成B0：105.886秒，包含上述所有日常步骤
整轮目标／deadline：120秒
```

预算从日常入口开始到停止负载、正常收尾并输出机器可读结果计算；不能把切模式、暖机或 drain 隐藏在负载时长之外。首次构建／安装测试工具、准备 LAN 对端与授权属于一次性环境准备，显式单列；每次重跑使用已安装产物与已准备对端，不重新构建。

工具记录各阶段wall time并管理全局deadline。10／8／6秒是建立B0前的校准配置；8秒方案只完成七组，6秒方案遇到Service交接；均保留INCOMPLETE记录。最终5秒在成功B0前固定，后续不运行时缩窗、漏组或延长时间。超预算仍走正常有界清理并标INCOMPLETE，不能留下活动NFQUEUE／TUN或未结清native资源。

不得给每组另加30秒 profile轮、长 cooldown、人工点击／截图或全量历史分页。CPU／资源和 RTT 与压力负载同时采集。profile模式如果保留，使用同一批八组的时间窗同时记录，不增加一整套负载；B0与Bn比较时profiling开关一致，并明确采样成本。重型火焰图渲染可在保留raw后另行离线执行，耗时单列，不假称它也已被证明包含在120秒；轻量summary属于日常入口预算。

## 4. 结果只保留必要字段

每组输出：`profile / case / 实际时长 / 负载参数 / 有效交付Mbps或pps或成功CPS / p99及样本数 / 失败或丢包 / 未入图及容量bypass / VPP与发生器CPU / 内存`。

- 吞吐以实际交付／处理计数为准，不把 App send成功、TRex offered量或内核旁路交付直接当 VPP 有效处理成绩。
- TCP new 的完成CPS与 VPP Flow创建分开；UDP new 的新五元组速率与 Flow创建分开。饱和后的容量 miss／绕过路径是压力结果，照实显示。
- fixed组 p99先采用同一手机clock的小请求→对应响应 RTT；TCP new用connect→首个有效响应。超时／错误单列，样本少时标明，不能只删掉失败样本后称延迟更好。
- 每次固定 APK／native身份、手机与profile、规则、负载参数和采集开关。Root／VPN及四组各自与 B0／上一版比较，不混画成一个成绩。

提升直观定义：有效吞吐／成功新建速率更高；同配置下p99更低；每有效处理量的VPP CPU更少。失败、旁路、内存与发生器成本一起列。5秒快速轮只支持日常趋势，不声称热稳态极限、正式p99资格或电气能耗结论；本轮固定UDP响应样本仅Root5／VPN1，不能据此下稳定p99结论。

## 5. 接入和工具收口

普通VPN由手机客户端的实际 TCP／UDP sockets产生流量，经TUN/VPP/HEV与保护的underlay连接到LAN对端；Root由符合实际捕获UID的手机客户端运行。已找到的TRex ASTF TCP程序可作对端／负载组织参考，但 TRex不是首版必需依赖，外部双端模拟不会自动经过Pixel。[模板研究](2026-10-08_TREX_PIXEL6A_BASELINE_RESEARCH.md)

新工具为 [tests/benchmark](../../tests/benchmark/README.md) 的原生并发／churn客户端、LAN对端、120秒调度和同窗采集；固定64数据流／TCP新建并发窗口、4个I/O线程。旧单flow／限速helper仅保留历史身份。工具不作为产品packet-domain实现，保持VPP-native C与ADR-0006/0007/0008边界。

旧 `run_vpn_tcp.py`固定历史地址／输出目录，不能直接重跑覆盖证据；新run必须唯一目录、拒绝覆盖。所有Android操作使用 `./dev/adb`，明确选Pixel6a serial，不误选其他设备。KernelSU授权、profile、真实PID／`:runtime`和队列／TUN状态按实际事实核对。

## 6. 已有证据与当前状态

候选历史原始perf的MetaInfo已直接确认 `Google:Pixel 6a:bluejay`、Android16/SDK36、aarch64；Linux／Host数据不进入主曲线。[Pixel历史吞吐](../testing/2026-09-28_VPN_ROOT_THROUGHPUT_PROFILE.md)、[修复后VPN TCP](../testing/2026-09-28_VPN_RUNTIME_MODE_FIX.md)

Root历史557／333Mbps队列失效，恢复后的176.43Mbps仍混有未入图accept，不能作为新B0。[Root恢复与边界](../testing/2026-09-28_ROOT_NFQUEUE_RECOVERY.md) 新基准压力达到旁路／容量／listener拐点时显示该事实，不将它包装成策略处理提升。

已取得 [八组B0](../../build-output/pixel-quick-baseline-20261008-final/result.json) 与 [同窗火焰图](../../build-output/pixel-quick-baseline-20261008-graphs/index.html)，105.886秒通过，收尾stopped／VPP不存在／规则源不变。VPN固定UDP两worker约96%；Root单IPv4对端输入集中lane0，记录了实际不均衡而未宣称全worker饱和。Root未入图accept和新建组的容量miss仍是当前行为，成绩不包装成完整策略路径上限。没有实现产品优化，也不恢复TLS/SNI/QUIC、多档或三重复范围。
