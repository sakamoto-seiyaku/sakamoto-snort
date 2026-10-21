# 普通 VPN 新基线与 UDP ready-send 实验

日期：2026-10-21。继续普通 Product VPN 性能优化。当前安装物的新基线完成，随后实现并测试了同 session 的有界 UDP `sendmmsg` 候选。独立生命周期的 ABBA 共16个窗口全部完成；固定 UDP 端点交付均值237.23→357.22 Mbps，单位交付的 VPP CPU 估计下降33.81%。**候选保持默认 OFF，未采用为新默认，也未保留实验 APK。** TCP-new 出现较低完成率和更多超时，不能确认没有回归。

这里的 Mbps 是端点交付，仍有 primary／packet-credit 拒绝及大量输入丢失。两次窗口／版本的尽力加压结果不是完整策略路径吞吐、匹配 offered rate 的 CPU/p99 资格、稳态功耗或发布验收。

## 当前安装物的独立基线

从 HEAD `c32729e7` 开始，工作区最初干净。设备仍是 Pixel 6a，原运行态为 generation2063／Stopped。安装 APK SHA256 为 `844b339d7d848dee854ffc54b9e685bdf158f52f8d9720ef088c45ddc4531a03`，全部12个原生载荷匹配[October13采用物](2026-10-13_ROOT_COMPOSITE_DEFAULTS.md)。当时相对其1339文件源码闭包只有6个构建／缓存相关输入变化，没有新的包路径改动。

精确插件符号 SHA256 `fb00f9e3d5d8e1e097f7f4c854bef2bc54cd65ede8f2bf81d63143e6b30554cf`，重新 strip 后匹配 APK 插件 `ed96e840481de5fa9055ef933eaa3ba433400e5efcc4e48347b2d9bd2f339785`。手机 libc 也重新核对；离线解析按记录中的 ELF build ID 核验。没有套用旧 B0 的未知地址或其它版本符号。

新 `ordinary-vpn-v1` 明确冻结为普通 VPN 四组、两个生命周期、每组5秒、总 deadline120秒；4线程×16 sockets、1200 B UDP、199 Hz cpu-clock 与既有 helper 行为保持。它是独立配置，不是删除 Root 后重命名的旧八组 B0。规则源 SHA256 `5bd3d78401ddfa51e162a0167c0413eae6de826b4ecf7ca2d11dfa19c98a7b35`，本轮未写规则、未扩容量。启动仍要求 `protectionRunning=true`，没有 controlled/validation extras。

首次当前网络不能到达 LAN peer。用户同意直接通过 ADB 切换后，确认 Openwrt_5G 与 LAN 可达，再开始测量。所有设备操作都经过 `./dev/adb`。

| 当前安装物负载 | 端点交付／完成 | 主要同代观察 |
| --- | ---: | --- |
| TCP fixed | 107.04 Mbps | primary拒绝13,419；owner1 OUTPUT_CAPACITY 5,202；Flow capacity miss0 |
| UDP fixed | 241.16 Mbps | 两 worker约96%单核；accepted originals125,620、rejected175,720，拒绝均为 PACKET_CREDIT |
| TCP new | 1008.00 completed CPS | Flow capacity miss19,031；端点完成数不能当作完整跟踪的新建数 |
| UDP new | 6416.51 input tuples/s；3.84 Mbps交付 | Flow capacity miss117,648；PCB_CAPACITY拒绝123,588，两个owner实际PCBs均达到258 |

精确 CPU-only 剖析中，固定 TCP 的 `write` inclusive46.997%，TUN completion路径45.567%；固定 UDP 的 Direct send链39.907%，内核56.418%；新 UDP 的 `udp_input` self15.770%，内核38.833%。这些窗口执行路径不同，inclusive比例相互重叠。当前新 UDP 的同代拒绝原因实际是 PCB_CAPACITY，不能沿用旧 B0 的 session容量推断替代它。

基线 `COMPLETE`，50.905秒，generation2064/2065。两个生命周期都保留该 generation 的两条 `owner_stopped` 和一条 TUN `stop`，核实 sessions/input/pbuf/socket及native buffer/obligation/frame结算。采集器在**测量之后、停止之前**打开原生日志 inode，正常退出后再读取，因此不依赖停止时被删除的普通 VPN profile 或历史 Root/validation 归档。

[只读身份检查](../../build-output/vpn-baseline-preflight-20261021/result.json) · [原始基线](../../build-output/vpn-baseline-20261021-attempt1/result.json) · [基线热点与逐owner计数](../../build-output/vpn-baseline-analysis-20261021/analysis.json) · [基线HTML／火焰图导航](../../build-output/vpn-baseline-analysis-20261021/index.html)

## 候选、实现边界与正确性

按实测热点，先选择固定 UDP 的 underlay 发送链。源码已有 session 私有的有界待发队列，但每次任务轮转只发送一个 datagram；另两个调查方向是 TUN 返回路径集中负担、churn满池时的无效查找。本次没有实现这两个方向或扩大池。

`SAKAMOTO_PRODUCT_VPN_UDP_BATCH_EXPERIMENT=ON` 使一次任务轮转最多发送同一已授权、已连接 socket 上的8个现成 datagram，总共最多64个 pbuf spans，然后继续 receive／yield。不等待未来包，不跨 session／owner 聚合，不增加 payload copy、packet queue、session／PCB／Flow／credit容量。默认 OFF 的 scalar control 每次最多一包。

实现通过新的 HEV fork patch `0013-bounded-direct-udp-send.patch`，没有修改 offline upstream export，也没有导入 POC 源码。正返回只消费成功前缀，未发送尾部保留原队列所有权；EAGAIN/EINTR不消费队列；terminal错误进入现有session关闭／排空。owner的 input_packets/direct_sent按实际成功包数结算。新 `flow_stack.udp_send` 输出实际 calls/requested/datagrams/partial/blocked 和 lifetime max，不能对 max 求差。

Host先加入真实队列测试，观察旧实现因期望8、实际1而失败，再应用候选。最终 batch与scalar各36项检查通过，包括IPv4/IPv6、真实 socket、保护／绑定／underlay失败、容量、半关闭、停止及回收。额外覆盖零长度／多段datagram、总64-span上限，以及真实本地socket剩余两个槽时只发送2包、保留6包再恢复的正前缀语义。terminal socket错误仍由正常destructor结清。未声称这些Host检查是Android性能或ASan资格。

Android／Host builders均校验、传递并记录开关；APK assembly拒绝与请求开关不符的stage。scalar／batch源码闭包同为 `fe66609a6b95d7519a98e7aaf1b939dc79b08c9ec82a48b951b8a1a4bb43a768`，1345个文件，DEX完全一致，12个native载荷中只有插件不同。两者各自符号重新strip后匹配对应APK。

| 编译模式 | APK SHA256 |
| --- | --- |
| scalar／OFF | `1d6c321dd7cd549be3f1159b9383a0bef3f7a513d7742e32618d0354bd3d745f` |
| batch／ON | `b6fd7598db8dd051d65091994965a5baa9685442a7a123899d8a8a50dbc29faa` |

构建复用持久 Product cache；原生unchanged第二次构建0.704秒、零编译、12个payload逐字节一致。Host HEV fixture使用独立持久 `build-output/host-hev-tests`，重复构建也为 no work；没有在每个窗口下重建依赖。Android native-stage contract、错误开关和stage不匹配检查通过。

[红灯记录](../../build-output/vpn-udp-send-batch-20261021/host-red.log) · [batch36项](../../build-output/vpn-udp-send-batch-20261021/host-batch-tests.log) · [scalar36项](../../build-output/vpn-udp-send-batch-20261021/host-scalar-tests.log) · [额外边界检查](../../build-output/vpn-udp-send-batch-20261021/host-final-target-tests.log) · [成对构建身份](../../build-output/vpn-udp-send-batch-20261021/paired-build-identity.json) · [warm reuse](../../build-output/vpn-udp-send-batch-20261021/scalar-warm.json)

## 失败的两生命周期对照

首次冻结 A→B→B→A、复用基线的两个生命周期。A1完成TCP fixed和UDP fixed后，进入TCP-new前看到229项Flow，占用超过2048容量的10%护栏，采集器保留 `INCOMPLETE` 并中止整个计划，未执行B1/B2/A2，没有重试该计划。原APK恢复。其两个窗口不混入下面的四生命周期统计。

计数显示测试固定流之外也有TLS/DNS/QUIC等自然背景Flow；不能将229项全归为发生器。后续选择每组新建生命周期，是隔离前序组保留状态与背景积累的配置改变，没有放宽占用护栏、重置live Flow或扩大容量。

[冻结协议](../../build-output/vpn-udp-send-batch-20261021/protocol.json) · [中止结果](../../build-output/vpn-udp-send-batch-20261021/campaign-result.json) · [原始A1及错误](../../build-output/vpn-udp-send-batch-20261021/run-A1/result.json)

## 独立四生命周期 ABBA

重新、单独冻结 `ordinary-vpn-fresh-v1`：每个负载都普通启动、warmup、完整5秒测量、正常停止；四类负载与初始占用／容量／120秒护栏保留。A1/B1/B2/A2分别64.834／64.977／65.048／65.413秒，16个generation2067–2082均完成，全部有本代原生停止证据。没有重跑负载窗口。

固定UDP窗口如下。VPP CPU秒／GiB是按实际监控覆盖时间外推的单位端点交付成本，不是整机CPU或电能。两worker持续接近满载，因此单位成本降低主要随交付增加出现，不等于进程总CPU下降34%。

| 窗口 | 端点Mbps | VPP CPU秒／GiB | UDP包／实际发送调用 | primary拒绝 | Flow Stack accepted／rejected | 成功延迟样本／timeout |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A1 scalar | 234.92 | 69.77 | 1.000 | 6,029 | 122,410／168,704 | 3／16 |
| B1 batch | 364.06 | 45.28 | 7.196 | 13,740 | 189,646／74,743 | 2／16 |
| B2 batch | 350.38 | 46.56 | 5.617 | 8,311 | 182,542／81,158 | 4／16 |
| A2 scalar | 239.54 | 68.99 | 1.000 | 11,111 | 124,820／177,868 | 1／16 |

本组Flow capacity misses均0；Flow Stack拒绝均为PACKET_CREDIT，未靠扩大容量或省略拒绝取得端点提升。B两窗累计372,183个UDP datagram／58,855次实际发送调用，平均6.324包，最大均8；每datagram调用数下降84.19%。Phone这些窗口没有positive partial或blocked，异常语义由上述真实Host socket案例另外覆盖。

算术均值交付提高50.58%，单位交付VPP CPU下降33.81%，是本次四窗口的描述性观察。固定UDP仍有每窗约484万–507万输入丢失、不同实际offered rate、primary拒绝和1–4个成功延迟样本；p99不能作为稳定收益判据。端点增长不能改称完整策略吞吐或全量跟踪能力。

精确CPU-only剖析显示scalar UDP内核占56.50%／55.94%，batch占62.42%／61.02%；`hev_task_system_schedule` inclusive分别5.03%／4.88%与1.93%／2.31%。batch的`__sendmmsg`链实际存在，更多CPU比例落到UDP发送链不代表每个已交付包的内核成本增加，inclusive比例不能相加。16份记录均报告lost0；原始perf、各自匹配build ID和周期加权分解均保留。

其它三类负载全部保留：

| 窗口 | TCP fixed Mbps | TCP-new completed CPS | TCP-new p99上界ms／成功样本／timeout | TCP-new Flow capacity misses | UDP-new Mbps |
| --- | ---: | ---: | --- | ---: | ---: |
| A1 | 107.27 | 976.80 | 314.5／4,888／5 | 17,602 | 3.82 |
| B1 | 124.68 | 809.94 | 468.3／4,054／8 | 12,535 | 3.64 |
| B2 | 108.19 | 952.67 | 263.5／4,770／45 | 16,973 | 3.75 |
| A2 | 108.71 | 976.15 | 397.9／4,890／0 | 17,493 | 3.81 |

TCP-new完成率的B均值较A低约9.75%，B2有45次timeout；本轮不能确认因果，也不能宣称TCP没有回归。TCP-new仍有Flow容量旁路，新UDP仍触及既有PCB容量，两者不是固定UDP吞吐测量。候选保留实验状态，尚未建立匹配offered rate的CPU／延迟资格或一般双向UDP负载资格，不据此修改默认值。

[新冻结协议](../../build-output/vpn-udp-send-batch-fresh-20261021/protocol.json) · [四轮结果](../../build-output/vpn-udp-send-batch-fresh-20261021/campaign-result.json) · [全部计数与描述性汇总](../../build-output/vpn-udp-send-batch-fresh-20261021/summary.json) · [16窗口HTML对照](../../build-output/vpn-udp-send-batch-fresh-20261021/comparison/index.html) · [A1加权剖析](../../build-output/vpn-udp-send-batch-fresh-20261021/analysis-A1/analysis.json) · [B1](../../build-output/vpn-udp-send-batch-fresh-20261021/analysis-B1/analysis.json) · [B2](../../build-output/vpn-udp-send-batch-fresh-20261021/analysis-B2/analysis.json) · [A2](../../build-output/vpn-udp-send-batch-fresh-20261021/analysis-A2/analysis.json)

离线首次拉取遇到WSL interop `UtilAcceptVsock`失败，原错误和空输出目录保留。后续只重新拉取原perf文件、离线解析，没有重跑测量窗或切换Wi-Fi。

## 最终状态

恢复October13原APK，核对全部12个native载荷、UID12632和Root grant；规则字节hash不变。generation2082为Stopped，VPP／本轮generator／monitor／simpleperf均无残留，独占LAN peer核对exe／argv／hash后退出。用户随后明确“adb wifi 别切换了”，因此覆盖原先恢复Wi-Fi的计划，**保持Openwrt_5G**，没有执行网络切换回CU_7WFb_5G。

[最终只读检查](../../build-output/vpn-udp-send-batch-fresh-20261021/final-device/final-readonly.json) · [原APK恢复安装](../../build-output/vpn-udp-send-batch-fresh-20261021/install-restore-original/result.json) · [peer退出](../../build-output/vpn-udp-send-batch-fresh-20261021/peer-cleanup.json)

## 固定流火焰图继续分析

同日用户进一步明确：后续性能主线是已有TCP连接与固定UDP流；新建／session问题边做边排查，不用TCP-new的CPS变化单独阻挡固定流优化。这是后续工作范围调整，旧协议、旧失败和原始窗口保留。本次仅离线分析已有8份固定流CPU记录，没有操作设备、切换Wi-Fi、修改默认开关或重新采样。

按每个窗口的sample period加权，而非直接平均火焰图百分比；单位交付成本按实际端点字节与监控覆盖外推的VPP CPU计算。下列调用链是inclusive且会重叠，**不得相加**；它们仍不代表完整策略Q或全机能耗。

| 固定UDP调用链 | scalar CPU占比 | batch CPU占比 | scalar→batch VPP CPU秒／交付GiB |
| --- | ---: | ---: | ---: |
| Direct underlay发送 | 41.33% | 50.38% | 28.67→23.13 |
| HEV任务调度 | 4.95% | 2.12% | 3.44→0.97 |
| HEV输入复制／lwIP分发 | 12.70% | 10.35% | 8.81→4.75 |
| 共享policy graph | 13.59% | 12.52% | 9.42→5.75 |

发送链比例上升与单位交付成本下降同时成立：batch每轮送出更多有效datagram，调度／接收探测和被packet-credit拒绝包的占比改变。收益不应只归为“系统调用少84%”；本轮同时减少每包任务轮转和重复接收探测，accepted/rejected originals也改变。当前batch剩余主要成本仍是underlay发送及内核网络栈，内核总体61.72%。

batch UDP的`queue_work_on` self约11.55%，已沿caller解析到`dhd_lb_tx_dispatch → dhd_lb_sendpkt → dhd_start_xmit`发送链；它属于本机Wi-Fi驱动提交工作，不是我们的HEV调度器。`ipt_do_table`沿内核Netfilter链，不能当作产品零规则情况下的规则匹配热点。dynamic TLS resolver self1.86%、memmove self1.59%、Flow `find_entry` self1.67%，目前都是次级单点。`find_entry`调用分别来自Flow prefetch、UID/incarnation查询和observe；复用查找是有具体调用栈支持的候选，但不是首要CPU大头。

固定TCP的scalar／batch热点形状基本一致。batch加权内核占65.85%，TUN返回completion链46.24%，其中`tun_get_user`42.50%；HEV underlay receive／TCP splice14.72%，policy graph9.23%，HEV调度5.40%。TUN是最大的单条已解析链，但两个worker平均仅约54%–59%与41%–43%单核，CPU-only图不能解释它们未执行期间的等待，不能据此认定CPU算力已构成全部吞吐上限。

`_raw_spin_unlock_irqrestore`约10%的TCP self成本，代表性caller是`__wake_up_sync_key → sock_def_readable → tcp_data_ready → tcp_data_queue`，属于内核收到返回包后通知socket的路径；不是已证明的产品共享锁争用。TCP返回集中到唯一TUN lane，owner1在四窗都有OUTPUT_CAPACITY拒绝，而owner0没有，对应当前返回／推进边界值得优先观察。这个fault本身未区分return credit耗尽与VPP buffer分配失败，边界快照的in_use=0也不是峰值，不据此先扩容。

源码另显示当前TCP splice每次`tcp_write`按一个协商MSS提交，然后回到任务调度。这是已有的事务／资源边界；后续可验证“已有ring数据是否在每次yield时被留待下一轮、是否限制推进”，再评估有界多次小提交，而不是直接改成大块事务。对TCP，下一轮诊断优先区分返回credit／buffer失败、ring／sndbuf等待、native待办与任务推进；对UDP，保留ready-send主线，继续区分有效包与PACKET_CREDIT拒绝路径在输入／policy中的成本。session／新建压力保留为伴随观察。

[归一化CPU与原始caller链](../../build-output/vpn-fixed-flow-drilldown-20261021/analysis.json) · [代表性固定TCP火焰图](../../build-output/vpn-udp-send-batch-fresh-20261021/graphs2-B1/vpn-tcp-fixed-flamegraph.html) · [代表性固定UDP火焰图](../../build-output/vpn-udp-send-batch-fresh-20261021/graphs2-B1/vpn-udp-fixed-flamegraph.html)

随后按用户要求只继续固定TCP，完成[互斥CPU成本、Root结构差异与内层大分段候选研究](../reviews/2026-10-21_VPN_FIXED_TCP_PATH_COST_AND_LARGE_SEGMENTS.md)。四个TCP窗口加权插件自身22.14%、内核66.12%；TUN completion46.27%是包含内核子调用的inclusive路径。研究将内层MTU/MSS增大列为减少整条每包开销的待验证方向，并核对普通Android TUN的GSO接口限制，没有新增设备样本或改变产品配置。
