# 普通 VPN：长连接 TCP 下载的大分段、推进与缓冲

日期：2026-10-21。用户限定性能基线为 TCP 长下载；本记录没有 UDP、CPS 或 Root 性能负载。参考依据见[源码调查](../reviews/2026-10-21_VPN_TCP_REFERENCE_OPTIMIZATIONS.md)。

本页保留前三阶段的历史默认值；后续MTU10000修复已完成，当前普通VPN构建默认MTU10000/MSS9940，见第四阶段。readiness、TCP batch及65528-byte缓冲仍各自默认OFF。

## 大分段实现与结果

新增默认 OFF 的 `SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT`：内层 MTU1500/MSS1360 对照 MTU3000/MSS2940。Android Builder、owner netif/packet limit、lwIP MSS 和 APK stage 属性一致校验。两处独立存储拷贝、canonical owner、正常共享图和单 TUN lane 保持原有契约。pbuf pool element2048 可以组成大包，返回 spans 复制到独立连续 VPP buffer。

`SAKAMOTO_PRODUCT_VPN_BUFFER_DATA_BYTES` 只允许2048/3072；大段要求3072。对照两版都使用3072，使实际可用池容量一致；标准默认仍是2048。每 worker/session/return credit 数量及 `TCP_WND`、sndbuf/ring32768均保持不变，TCP batch 两边 ON、UDP batch 两边 OFF。

同一 Pixel/Openwrt_5G、规则、worker placement和64条持续下载连接，每窗20000ms，四个独立普通 VPN lifetime，ABBA2094/2095/2096/2097。窗口包含每条流的一次初始建立，不是 CPS 负载。两边实际 VPP buffer 都为1517，接口分别证实 MTU1500/3000；实际协商 MSS1360/2940，成功 TUN write 最大 IPv4 包1400/2980字节。

| 窗口 | 分段 | 端点Mbps | VPP CPU秒/交付GiB |
| --- | --- | ---: | ---: |
| A1 /2094 | 1360 | 102.48 | 66.46 |
| B1 /2095 | 2940 | 204.73 | 35.47 |
| B2 /2096 | 2940 | 207.96 | 34.83 |
| A2 /2097 | 1360 | 102.16 | 67.95 |

| 合并指标 | 小段 | 大段 | 变化 |
| --- | ---: | ---: | ---: |
| 端点吞吐算术均值Mbps | 102.32 | 206.35 | +101.67% |
| VPP CPU秒/端点交付GiB | 67.20 | 35.15 | −47.70% |
| 成功TUN write/交付GiB | 821601 | 392259 | −52.26% |
| TCP readv/交付GiB | 98340 | 77706 | −20.98% |
| TCP receive轮次/交付GiB | 347213 | 242506 | −30.16% |

CPU按合计估计VPP进程CPU秒除以合计端点GiB；不是整机CPU或电能。匹配符号的 inclusive TUN completion 成本33.56→15.80 CPU秒/GiB，其中 `tun_get_user`30.16→14.38；shared policy6.42→3.21。inclusive路径会重叠，不能相加。四个perf最终日志均 lost0，精确插件符号/Build ID核对通过。

四窗primary拒绝34787/20803/19254/38092，OUTPUT_CAPACITY55/267/0/148；不能把端点吞吐解释成完整策略Q。探测成功样本12/253/373/388，对应timeout7/3/1/0，不构成匹配负载的延迟资格。CLI窗口含设置和自然背景，TCP累计计数未按发生器tuple过滤。

本次证实“增大实际分段→每GiB TUN包数下降→该固定下载CPU成本下降并增吞”。它不是所有网络/协议或产品发布资格，也没有采用为默认。对照的小段版本使用共同3072-byte pool，其池容量与原2048-byte默认不同；历史原APK不是本次隔离MSS比较的control。

[四窗与火焰图](../../build-output/vpn-large-common-pool-20261021/index.html) · [原始结果](../../build-output/vpn-large-common-pool-20261021/campaign-result.json) · [可重算汇总](../../build-output/vpn-large-common-pool-20261021/summary.json) · [冻结协议](../../build-output/vpn-large-common-pool-20261021/protocol.json)

## 4KiB页上的容量陷阱与失败证据

最初 MTU3500/MSS3440、VPP data3584 的候选没有通过。Pixel普通页4096；VPP pinned allocator把 `sizeof(header)+data` 向128对齐，再强制奇数cacheline stride，并跳过跨页slot。因此“单个buffer装得进一页”不意味着每页产生一个可用buffer。

| data | 实际分配stride | 相同8192页/32MiB reservation的可用buffer |
| ---: | ---: | ---: |
| 2048 | 2432 | 5605 |
| 3584 | 3968 | 264–265 |
| 3072 | 3456 | 1517 |

模型与设备 `show buffers` 对应；[算法/源码SHA与容量计算](../../build-output/vpn-large-common-pool-20261021/allocator-geometry.json)。没有修改VPP allocator或导入POC实现，也未使用hugepages作为普通VPN前提。

完整保留以下失败：

- [初始采集目录](../../build-output/vpn-large-progress-20261021/)：复制脚本旧arm名称在安装前退出；修正后2088在测量前被新增接口查询的shell权限拒绝。两者不计性能窗口，原APK恢复。
- [3500尝试](../../build-output/vpn-large-tcp20-native-20261021/campaign-result.json)：2089小段20s完成，2090大段中途退出，不能用作完整A/B。
- [同负载7s诊断2091](../../build-output/vpn-large-tcp20-native-20261021/diagnostic-pool/native.log)：`allocator_returned_zero total=264 available=0 owner_cached=0`，随后FlowEnd `fatal_allocation_failure exit_code=70`。UI的UID channel错误属于后续表现；没有把它当作授权问题。
- [修正后同负载2093](../../build-output/vpn-large-common-pool-20261021/diagnostic-pool/native.log)：运行期保持普通VPN ready、无fatal、正常停止且两owner/native debts均零。随后才开始20s正式对照。

## 推进观测与测试边界

新增owner聚合 `flow_stack.tcp_progress`：ring/sndbuf/window/cwnd阻塞、空推进、pending与flight峰值及MSS范围，均明确为receive轮次入口观测，**不是时间加权占用率**。`flow_stack.driver`记录ready→node延迟、轮次、空step、timer arm；`tun.return_detail`区分credit/stamp/buffer拒绝，`tun.write_size`记录实际大包/字节。

大段B1/B2中owner1约68–70%的receive入口sndbuf满、约74–76%无字节推进，而owner0相应sndbuf满观测为零。owner0 ready→node均值约4.2–4.4ms、owner1约33–35µs。该差异仍含TUN lane工作、内核和CPU调度影响；不能只凭平均CPU或流数把等待归因于某一段代码。完整逐owner计数及新增peer tuple分布保留在汇总中。

真实HEV host TCP fixture现在在SYN协商MSS，验证逐字节流、checksum、大于2KiB的真实包、ring wrap、SYN重传、返回拒绝/丢包恢复、内核sendmsg背压、FIN、underlay失效及packet/pbuf容量拒绝。3000候选的10个双栈用例通过。早期故意1KiB小突发压力用例误套大包断言的失败日志保留，修正测试前提后通过；没有掩盖产品错误。

Android native stage contract通过；非法buffer配置、请求/已stage属性不符均拒绝。persistent Product cache重复构建零编译、12个native载荷字节一致；触碰内容未变的HEV fork文件会重新检查CMake/stage，但没有编译。没有新建每实验依赖构建目录。

采集器在测量前通过阻塞FIFO持有日志inode，停止后或fatal cleanup后再复制；测量期间没有日志reader轮询。host测试实际执行这条shell路径并在unlink后校验内容。TCP套件保留 `show buffers`、startup.conf和root只读接口事实，并在压力前检查冻结的最低池容量。没有放松120s/ordinary-ready/native-zero要求。

## 身份与阶段末状态

源码闭包 `2a030d3d5f1fbfa2e23459d855e97896b7c8f06d2d4fb7dce875893404a669b1`；小段APK `43c8102833556aa5934525ac1bc352e4a627f877e58a3e9809d32dc6579a669f`，大段APK `bdc0142d51dc11df001656169849fb5fed88dd1705add1885d81dc8ca406060e`。同DEX及11个相同native载荷，仅插件不同；[精确身份](../../build-output/vpn-large-common-pool-20261021/paired-build-identity.json)、各build.json与匹配symbols保留。

第一阶段末恢复原October13 APK `844b339d7d848dee854ffc54b9e685bdf158f52f8d9720ef088c45ddc4531a03`，核对12个native、规则hash、Root grant及libc符号；Stopped2097、设备无VPP/load/monitor/simpleperf残留，Openwrt_5G保持不变。[只读审计](../../build-output/vpn-large-common-pool-20261021/final-readonly/result.json)。LAN peer仍由本任务独占，用于同一授权范围内的后续对照，不是设备残留。

## 第二阶段：按ring容量门控socket readiness

默认 OFF 的 `SAKAMOTO_PRODUCT_VPN_TCP_PROGRESS_EXPERIMENT` 在Direct连接完成后维护实际interest：ring满时不订阅POLLIN，仅在upload queue有数据时订阅POLLOUT；interest未变不调用 `epoll_ctl`。EPOLLERR/HUP仍可达，connect原有订阅不变。

ACK仍由原owner的 `tcp_sent` 回调释放ring并唤醒任务；**每次被唤醒的round都会先尝试非阻塞readv，再决定下一轮interest**，即便POLLIN此前被暂停。kernel已有数据不需要等下一条外部edge。没有增加payload队列、helper transport执行或迁移owner；quanta8/max200µs及全部容量保持不变。

新增双栈 `hold-ack` fixture：冻结所有内层download ACK（包括upload上的piggyback ACK）250ms，允许远端发送完整73728字节。释放ACK前以真实 `FIONREAD` 断言socket内有排队字节、server不再发送新payload；释放后须在200ms内读完，不能等1秒TCP poll救援。gated版还要求read暂停与恢复计数均发生。两侧12个TCP回归通过，加强的两个ACK用例再次通过；[gated真实执行输出](../../build-output/vpn-tcp-progress-20261021/host-gated-queued-details.log)、[control输出](../../build-output/vpn-tcp-progress-20261021/host-control-queued-details.log)及两侧host fixture二进制身份保留。

本阶段两边都用MTU3000/MSS2940、3072-byte buffer/1517池、32KiB sndbuf/ring、TCP batch ON与UDP batch OFF。独立20s ABBA2098–2101：

| 窗口 | readiness | Mbps | VPP CPU秒/GiB |
| --- | --- | ---: | ---: |
| A1 /2098 | 原订阅 | 205.04 | 35.03 |
| B1 /2099 | 门控 | 206.26 | 33.08 |
| B2 /2100 | 门控 | 208.30 | 32.80 |
| A2 /2101 | 原订阅 | 208.05 | 34.78 |

合并VPP CPU/GiB34.91→32.94，下降5.63%；吞吐均值206.54→207.28Mbps（+0.36%），没有建立增吞证据。TCP receive轮次/GiB229254→109101（−52.41%），空推进/GiB156868→39398（−74.88%），driver node/GiB107097→33159，readiness callback/GiB89203→4543。实际新增interest变化约1139/GiB；没有用高频 `epoll_ctl` 交换原有每次唤醒。

TUN write/GiB392628→391777（−0.22%，基本不变）。inclusive HEV scheduling成本0.894→0.487 CPU秒/GiB，TUN completion15.71→16.31，说明这项主要减少无效推进；不能宣称已解决TUN返回或owner间等待差异。OUTPUT_CAPACITY103→25，primary拒绝17464/19090/20520/20364仍保留。该阶段同样不是完整策略Q或延迟资格。

源码闭包 `8cdb2e3d75e744670fc47eab166d27b7b9d8ac8f66f034eea3e6028f54978dd2`；control APK `04d915f140a38f9ac6d919dc64d58ca8733a2d4d5fd661d80b34fa3e5c40a626`，gated APK `b60f2e39f664731051022a4b766171f13aca5189cfd865e2e8227bf8893ba102`。同DEX/11个native，仅插件不同；新flag非法值与APK stage不匹配均拒绝。warm build0.79s，999个编译输出mtime不变、零编译且12个native相同。四窗native-zero、精确symbols与lost0均通过；结束恢复原APK/规则/Root grant/Stopped2101及Openwrt_5G，[审计](../../build-output/vpn-tcp-progress-20261021/final-readonly/result.json)。

[第二阶段汇总与火焰图](../../build-output/vpn-tcp-progress-20261021/index.html) · [计数与CPU重算](../../build-output/vpn-tcp-progress-20261021/summary.json) · [冻结协议](../../build-output/vpn-tcp-progress-20261021/protocol.json)

## 第三阶段：独立扩大发送缓冲

在第一/二阶段已观测到ring/sndbuf受限后，新增默认 OFF 的 `SAKAMOTO_PRODUCT_VPN_TCP_BUFFER_EXPERIMENT`，只把 `TCP_SND_BUF` 和同一Direct ring从32768扩大到65528字节。`TCP_WND=32768`不变；MTU3000/MSS2940、readiness门控、batch、VPP pool1517及每owner128返回credit两边相同。运行期不resize、不跨owner借资源。

每session增加32760字节ring payload容量，64条流名义增加约2MiB；512个session上限对应约16MiB额外ring payload，不包括其它transport开销。实际容量通过native `buffer_bytes`核对。host暂缓ACK场景的ring峰值32768/65528，内核剩余队列40960/8200字节；两版均在ACK恢复后完成73728字节的逐字节/checksum、wrap、FIN与资源结清检查。两侧12个真实双栈TCP回归通过；expanded资格运行前后可执行文件digest一致并保留二进制。[Host身份](../../build-output/vpn-tcp-buffer-20261021/host-expanded-identity.json)、[实际测试输出](../../build-output/vpn-tcp-buffer-20261021/host-expanded-details.log)。首次测试启动与构建重叠的记录单独保留，未用于资格结论。

本阶段仍为同一64流、20s固定下载ABBA2102–2105：

| 窗口 | sndbuf/ring | Mbps | VPP CPU秒/GiB | 进程RSS采样峰值MiB |
| --- | ---: | ---: | ---: | ---: |
| A1 /2102 | 32768 | 204.67 | 32.88 | 123.20 |
| B1 /2103 | 65528 | 217.63 | 31.87 | 125.57 |
| B2 /2104 | 65528 | 218.63 | 31.88 | 125.85 |
| A2 /2105 | 32768 | 206.49 | 33.08 | 123.43 |

吞吐均值205.58→218.13Mbps（+6.10%），合并VPP CPU/GiB32.98→31.87（−3.37%）。成功TUN write/GiB392052→377639（−3.68%），所以不能将收益全部归因于减少等待：MSS虽不变，实际小段/分段packing也发生变化。inclusive TUN completion16.40→15.74 CPU秒/GiB，HEV receive/splice6.35→6.01；这些路径仍重叠。

RSS采样峰值的两窗均值增加2454KiB（约2.40MiB）。这是同一个VPP进程在测量窗内的 `/proc/.../stat` RSS采样，**每时刻只取主tid一份，不累加三个线程共享的RSS**；不是全部额外内存的逐项归因或整机峰值保证。

代价明确：OUTPUT_CAPACITY从39→1620次，按端点GiB归一化40.72→1594.22，约39倍。新分原因计数证实它们全部是**返回credit不足**，stamp和VPP buffer allocation拒绝均为零。primary拒绝为15366/38200/40054/17378，也增加了。没有扩大返回allowance来掩盖这一代价。四窗均正常停止且native debts零，但这些拒绝不能因端点多交付了字节而省略；完整策略Q和匹配负载延迟仍未取得资格。延迟成功样本259/337/127/211，timeout3/1/4/4原样保留。

因此64KiB保留为**默认关闭的条件候选**，没有根据这组小幅增吞直接采用为默认。返回credit背压是这组额外容量的实测代价，不是全局buffer池再次耗尽。大段是本轮最明显的增吞来源；readiness门控主要省CPU。三个阶段是独立对照，不把跨阶段比例相乘充作同一组配对实验。

源码闭包 `2089511501687412466f1853efddb32ea04864dae0e2e93bab6f576e456f3f7f`；control APK `31f5eda70662cf3243ee58c8eb279ecaee00c5084a9f3f424b68d1aa6a08e3b0`，expanded APK `0de7ba2f250abfa4554f1d9b221ba71807d586e0de06b20fc8adcf8571005a83`。同DEX/11个native，仅插件不同；新flag非法值与buffer stage不符均拒绝。persistent native重复构建零编译、编译mtime和12个载荷一致。最终native stage contract通过，四个perf lost0、精确符号及native-zero通过。

[第三阶段汇总与火焰图](../../build-output/vpn-tcp-buffer-20261021/index.html) · [CPU/计数/RSS重算](../../build-output/vpn-tcp-buffer-20261021/summary.json) · [冻结协议](../../build-output/vpn-tcp-buffer-20261021/protocol.json)

## 前三阶段结束状态

三个新优化开关均默认OFF；未做UDP/CPS/Root性能扩展。最终恢复原October13 APK、全部12个native、原规则hash和Root grant，Stopped2105，Openwrt_5G不变，设备无VPP/load/monitor/simpleperf残留。[最终只读审计](../../build-output/vpn-tcp-buffer-20261021/final-readonly/result.json)。

12个成功窗口的阻塞日志reader均已完成，FIFO gate已删除；本任务LAN peer在核对PID、exe、argv、启动时间和hash后退出。[reader审计](../../build-output/vpn-tcp-buffer-20261021/retained-reader-audit.json) · [peer退出](../../build-output/vpn-tcp-buffer-20261021/peer-cleanup.json)。所有失败尝试、原始perf、源码闭包、APK与精确符号保留。

## 后续授权范围：MTU10000

用户要求先记录选型结论，再解决连续VPP buffer的普通页限制，使本地TUN MTU达到NetGuard/PCAPdroid同档的10000字节。[库选型补查](../reviews/2026-10-21_VPN_TCP_REFERENCE_OPTIMIZATIONS.md#2026-10-21-补查竞品使用哪些库是否优于-hev)已记录：当前保留HEV/lwIP；sing-tun新栈属于未来可比较的候选，没有以换库替代本次容量修复。

本阶段目标为真实Android Builder MTU10000、双栈实际大TCP段、普通4KiB页下足够且可核对的VPP池容量；不依赖hugepages，不仅修改MTU常量。上一阶段的buffer size大于page size拒绝和3584-byte步长导致池缩小是保留的失败基线。先验证分配布局及真实TCP正确性，再使用相同Openwrt_5G上的64流、20秒TCP长下载ABBA比较；两侧保持相同分配布局、实际池容量、sndbuf/ring、readiness和返回credit，区分段长收益与扩容收益。实现、测试与设备结果未完成前不宣称达到该目标或采用为默认。

## 第四阶段：MTU10000在普通页上实际运行

已完成。新增[Product VPP core patch 0007](../../src/product/vpp/patches/core/0007-vlib-virtual-buffer-pool.patch)，显式 `buffers { virtual-only }` 模式允许纯软件包buffer跨普通物理页，保留真实physmem页表；公开buffer物理地址接口在该模式直接拒绝DMA用途。普通物理池保留原有跨页约束。没有伪报大物理页、依赖hugepages、导入POC源码或改用链式包处理，owner、两处独立拷贝、正常策略图及单TUN lane保持原契约。

Android实际配置为 `buffers { virtual-only buffers-per-numa 2048 default data-size 10240 }`。128-byte对齐下alloc stride10624，普通4KiB页共5318页（20.77MiB），精确提供2048个buffer。`show physmem`证实 `default-page-size 4K / lookup-page-size 4K / subpage-size 4K / no-pagemap`，不是用逻辑大页绕过物理限制。对照与候选都使用这同一布局和容量；旧3072-byte/1517池的历史结果不是本阶段control。

原有 `SAKAMOTO_PRODUCT_VPN_LARGE_SEGMENT_EXPERIMENT` 名称保留，构建默认改为ON，选择MTU10000/MSS9940；`SAKAMOTO_PRODUCT_VPN_TUN_MTU=3000`保留前一档，legacy开关OFF回到1500/MSS1360。buffer override允许2048/3072/10240且必须大于MTU，data10240要求明确的virtual-only属性。Java `VpnPacketProfile`校验打包native/MTU/MSS/buffer属性并生成启动配置；Root使用原2048-byte普通池。`TCP_WND`与默认sndbuf/ring仍为32768，返回额度仍每owner128个包，未通过扩容掩盖拒绝。

**未覆盖构建选项的默认APK**另跑一窗普通VPN、64流、20秒TCP下载，generation2106：实际 `tun0 MTU10000`、两owner协商MSS9940、IPv4返回IP包最大9980字节，端点519.32Mbps，估计VPP CPU20.53秒/GiB。返回credit/stamp/buffer不足均0，正常停止且native debts零。该版本TCP batch/readiness仍OFF；它是单窗默认配置运行证据，不并入下面的优化配置A/B估计。[默认窗口](../../build-output/vpn-mtu10000-20261021/smoke-run-default/result.json) · [默认火焰图](../../build-output/vpn-mtu10000-20261021/graphs-default/vpn-tcp-fixed-flamegraph.html)。

### 同池容量的20秒TCP长下载ABBA

冻结[协议](../../build-output/vpn-mtu10000-20261021/protocol.json)后只跑A1/B1/B2/A2，无重试或扫参。两边都用虚拟池2048/data10240、sndbuf/ring32768、TCP_WND32768、TCP batch与readiness ON、UDP batch OFF，唯一配置差异为MTU3000/MSS2940和MTU10000/MSS9940。

| 窗口 | MTU | Mbps | VPP CPU秒/GiB | 返回credit不足 | primary拒绝 |
| --- | ---: | ---: | ---: | ---: | ---: |
| A1 /2107 | 3000 | 208.04 | 32.75 | 20 | 17756 |
| B1 /2108 | 10000 | 516.49 | 18.12 | 0 | 3655 |
| B2 /2109 | 10000 | 526.54 | 18.04 | 0 | 4622 |
| A2 /2110 | 3000 | 205.11 | 33.01 | 20 | 14028 |

吞吐均值206.58→521.51Mbps（+152.46%）；合并VPP CPU/端点GiB32.88→18.08（−45.01%）；成功TUN write/GiB392229→136415（−65.22%）。这是单位交付字节的CPU成本，不能称作总CPU占用或整机功耗下降45%。返回credit不足40→0，stamp与VPP buffer不足始终0。更大的内层包减少相同下载字节所需的返回包名额；本次没有扩大上游ring。

每进程RSS采样峰值的两窗均值114458→114632KiB，仅增加174KiB；每时刻只取主tid一份，不累计线程共享RSS。inclusive TUN completion成本16.47→6.24 CPU秒/GiB，其中 `tun_get_user`15.01→5.69；HEV receive/splice5.93→5.56。路径重叠，不能相加。kernel比例约68.90%→69.43%，比例相近不等于每GiB内核成本未变。

仍有代价与范围限制：readv/GiB70775→263646（+272.51%），receive轮次/GiB110813→284556（+156.79%），inclusive HEV scheduling0.49→0.99 CPU秒/GiB。大段带来的TUN成本下降没有解决全部空推进/调度工作；CPU-clock不提供off-CPU归因。primary拒绝仍非零，不能把端点吞吐当作完整策略Q。四窗probe p99上界735.6/357.1/330.7/483.4ms，timeout4/0/0/2，原样保留；两侧实际交付负载不同，不能宣称匹配负载延迟通过。默认单窗p99上界360.5ms也不是延迟资格。

### 正确性、构建身份与保留失败

- 真实VPP allocator函数在带guard页的普通4KiB mmap上执行，覆盖64/128-byte对齐、所有buffer同时写满/读回、精确数量、普通模式大buffer拒绝及release态DMA accessor拒绝。[旧逻辑失败](../../build-output/vpn-mtu10000-20261021/allocator-red.log)、[修复后通过](../../build-output/vpn-mtu10000-20261021/allocator-green.log)。旧Host VPP启动也复现buffer10560大于page4096；其进程exit0不能代替pool/ready判断，[原始诊断](../../build-output/vpn-mtu10000-20261021/before-virtual-pool/result.json)保留。
- 默认MTU10000、batch/readiness OFF的38个HEV host回归全部通过；3000/10000对照配置各12个真实双栈TCP回归通过。覆盖字节流、checksum、真实>8KiB段、暂缓ACK恢复、ring wrap、返回拒绝及后续丢包恢复、真实sendmsg背压、FIN、underlay失效和容量拒绝。最大段见证放在已排队全部peer字节的暂缓ACK场景；早期把该断言套到故意SO_SNDBUF4KiB的基础背压用例，以及仍要求至少两次commit的失败记录保留，原4KiB echo行为恢复后按协商MSS校验提交数量。没有更改Product传输逻辑来迎合测试。[三配置测试身份](../../build-output/vpn-mtu10000-20261021/host-large-profile-identity.json)。
- Java真实profile gate、非法MTU/小buffer/属性冲突、APK请求与已stage MTU不符、core patch composition及native stage contract通过。全仓旧 `product_platform_boundary_test.py` 的19个Root源码字符串检查失败和1个错误，在本轮前HEAD上同样复现；其VPN检查通过，本次没有改动Root适配器或把该旧检查称为通过。[HEAD基线记录](../../build-output/vpn-mtu10000-20261021/platform-boundary-head-baseline.log)。
- Android VPP依赖构建改用Product持久缓存；API生成器无import depfile导致的重复编译与CMake LTO probe重复编译均已修复并保留失败日志。实际重复VPP构建零Ninja动作、553个编译输出mtime未变、9个runtime ELF相同；Product重复构建零编译、669个编译输出mtime未变、12个native载荷相同。[VPP复用证明](../../build-output/vpn-mtu10000-20261021/vpp-warm.json) · [Product复用证明](../../build-output/vpn-mtu10000-20261021/warm.json)。

源码闭包 `ff63c92a7dd7d0d29d08790a4aa24953931d37bf4a72181cc62aef5cc8d1a8ed`；core patch count7/SHA `76aa5f7657ff0f2a4bea2fd6ec5e81c10074ea9a1b30ff3ddbf9cb4f3281deb7`。对照APK `80b0a3b55cb88b114ad1f22eb946cdeded2a30341939f68f3f24188bbba99792`，大段APK `39adbe7ef0cb106df3ccd4ff683bd9fa5b0b39c0f1d934f3f6f023078236a7f2`，默认APK `571de18c8af88f71eadebad8806a24489cb60af31a84dce0e690e8acb869ea10`。同源码、同DEX及11个相同native，插件按冻结配置变化；插件与全部9个VPP runtime均有精确未剥离符号和strip后SHA证明，采样涉及的ELF另核对Build ID，五窗perf lost0、unknown leaf0。全部原始失败、perf、APK、源码快照和符号保留。

[四窗汇总与火焰图](../../build-output/vpn-mtu10000-20261021/index.html) · [计数/CPU/RSS重算](../../build-output/vpn-mtu10000-20261021/summary.json) · [配对身份](../../build-output/vpn-mtu10000-20261021/paired-build-identity.json) · [VPP符号身份](../../build-output/vpn-mtu10000-20261021/vpp-symbol-identity.json)。

### 第四阶段结束状态

当前源码普通VPN默认MTU10000，32KiB sndbuf/ring保留；TCP batch、readiness、65528-byte缓冲仍默认OFF。设备恢复原October13 APK及全部12个native、原规则hash和Root grant，Stopped2110，Openwrt_5G保持不变，无VPP/load/simpleperf残留。[最终审计](../../build-output/vpn-mtu10000-20261021/final-readonly/result.json)。五个阻塞reader完成、FIFO gate删除且remote日志SHA与本地停止证据一致；本任务LAN peer经exe/argv/starttime/hash核对后用pidfd终止。[reader审计](../../build-output/vpn-mtu10000-20261021/retained-reader-audit.json) · [peer退出](../../build-output/vpn-mtu10000-20261021/peer-cleanup.json)。本次没有扩大UDP/CPS/Root性能或产品发布资格。

## 第五阶段：已有500Mbps窗口的推进诊断

工作跟踪：[SAKAMOTO-292](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/work-items/0a35cbe1-ce1e-4531-b413-d6d8edc8a94c)。本节记录可重算事实与证伪过程，不把热点直接认定为吞吐上限。

使用 [`vpn_progress.py`](../../tests/benchmark/vpn_progress.py) 重读第四阶段B1/B2原始CLI和同generation停止证据，无设备访问、无新流量。两窗都出现：owner0每次非EAGAIN读取约30–31KiB，owner1约4.5–4.7KiB且读取EAGAIN比例约40%；owner1无数据推进146412/147001轮，ring/sndbuf满的入口观察23958/26828次。它们是次数，不代表等待时间占比；非EAGAIN分母可能包含EOF。

[重算结果及输入SHA](../../build-output/vpn-mtu10000-20261021/progress-recomputed.json)，复现命令：

```sh
rtk proxy python3 tests/benchmark/vpn_progress.py \
  build-output/vpn-mtu10000-20261021/run-B1 \
  build-output/vpn-mtu10000-20261021/run-B2 \
  --output build-output/vpn-mtu10000-20261021/progress-recomputed.json
```

owner0的pending-to-node均值2.33/2.48ms，owner1为40.4/44.1μs。源码 `schedule()` 在socket/timer/broker通知、输入包处理及继续推进时均可调用；时间戳由首次pending请求设定，在input node入口清除。因此原 `ready_delay` 名称不能解释成socket可读到执行的延迟。两owner的轮次、读取粒度与调度时序不同已复现，但还不是缺陷根因。

两窗on-CPU火焰图中TUN completion含子调用约34–35%，HEV receive约31%（其中readv约24%），policy node约7.7%，HEV scheduling约5.5%；调用链重叠不能相加。约69%采样在内核；spin-unlock的self热点不能单独证明锁竞争。工作线程平均各51–58%单核，CPU-clock不记录off-CPU，尚不能认定500Mbps为CPU或链路上限。

本次冻结的排查假设按优先顺序为：①TUN工作回合推迟同worker的flow-stack推进，缩小该回合应降低pending-to-node时延；②过密重试导致owner1碎片读取，限制无数据重试应降低EAGAIN/交付GiB且保留ACK后恢复；③primary credit或入队拒绝延迟ACK，消除该拒绝应减少sndbuf-full观察；④链路/off-CPU限制吞吐，若CPU成本下降但交付不变，则需要独立等待/链路测量。新比较保持MTU10000、2048/data10240池、32KiB ring/sndbuf、返回额度128和Openwrt_5G，性能变量逐项改变，不以扩大全部容量替代诊断。
