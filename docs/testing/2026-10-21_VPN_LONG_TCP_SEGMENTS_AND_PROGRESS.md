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

状态纠正：此前将这些阶段测量视为任务完成并关闭SAKAMOTO-292过早，现已重新打开。三个参数对照、热点和有丢样的off-CPU线索尚未说明HEV每类无进展回合的阻塞条件、唤醒来源及CPU未推进的因果链。整体诊断仍未完成；需要在实际调用链上复现、给出可证伪的原因并验证针对性修复，不能再以热点列表或设备清理完成代替根因结论。

使用 [`vpn_progress.py`](../../tests/benchmark/vpn_progress.py) 重读第四阶段B1/B2原始CLI和同generation停止证据，无设备访问、无新流量。两窗都出现：owner0每次未遇暂时错误的读取约30–31KiB，owner1约4.5–4.7KiB且暂时错误读取比例约40%；owner1无数据推进146412/147001轮，ring/sndbuf满的入口观察23958/26828次。它们是次数，不代表等待时间占比；`read_blocked`实际合计EAGAIN/EWOULDBLOCK/EINTR，不能单独解释为EAGAIN；非blocked分母可能包含EOF。

[重算结果及输入SHA](../../build-output/vpn-mtu10000-20261021/progress-recomputed.json)，复现命令：

```sh
rtk proxy python3 tests/benchmark/vpn_progress.py \
  build-output/vpn-mtu10000-20261021/run-B1 \
  build-output/vpn-mtu10000-20261021/run-B2 \
  --output build-output/vpn-mtu10000-20261021/progress-recomputed.json
```

owner0的pending-to-node均值2.33/2.48ms，owner1为40.4/44.1μs。源码 `schedule()` 在socket/timer/broker通知、输入包处理及继续推进时均可调用；时间戳由首次pending请求设定，在input node入口清除。因此原 `ready_delay` 名称不能解释成socket可读到执行的延迟。两owner的轮次、读取粒度与调度时序不同已复现，但还不是缺陷根因。

两窗on-CPU火焰图中TUN completion含子调用约34–35%，HEV receive约31%（其中readv约24%），policy node约7.7%，HEV scheduling约5.5%；调用链重叠不能相加。约69%采样在内核；spin-unlock的self热点不能单独证明锁竞争。工作线程平均各51–58%单核，CPU-clock不记录off-CPU，尚不能认定500Mbps为CPU或链路上限。

本次冻结的排查假设按优先顺序为：①TUN工作回合推迟同worker的flow-stack推进，缩小该回合应降低pending-to-node时延；②过密重试导致owner1碎片读取，限制无数据重试应降低blocked reads/交付GiB且保留ACK后恢复；③primary credit或入队拒绝延迟ACK，消除该拒绝应减少sndbuf-full观察；④链路/off-CPU限制吞吐，若CPU成本下降但交付不变，则需要独立等待/链路测量。新比较保持MTU10000、2048/data10240池、32KiB ring/sndbuf、返回额度128和Openwrt_5G，性能变量逐项改变，不以扩大全部容量替代诊断。

### 诊断计数与Host反馈

`show product primary`新增 `primary.rejection credit/enqueue`，分别在真实reserve失败和retained enqueue失败处计数，覆盖scalar与batch实现；既有 `rejected` 总数和处理语义保留。`show product tun`新增 `tun.capture_io`，报告实际capture budget、callback次数、预算退出及callback单调墙钟时间。`show product flow-stack`新增 `flow_stack.step_timing`，报告HEV step墙钟总时长、峰值及超过1ms次数；它包含OS抢占，不能替代CPU时间或独立off-CPU归因。对照和候选使用相同观测代码。

实际Product batch函数的Host回归通过unordered enqueue拒绝与32-credit耗尽，且分别断言两类计数准确；external batch和policy batch回归通过。external batch harness在本轮前遗漏此前拆出的 `submit_external_batch_internal`，其旧提取编译失败已保留，更新为执行真实internal及wrapper；没有修改该Product提交函数来迎合测试。[Host原始日志](../../build-output/vpn-progress-20261021/host-product_packet_batch_test.py.log)。这些回归证明计数与有界拒绝行为，不证明更小TUN回合能改善实机性能。

### Capture budget64/16：拒绝减少，但吞吐没有提高

冻结[四窗协议](../../build-output/vpn-progress-20261021/protocol.json)，两APK源码唯一差异为 `TUN_CAPTURE_BUDGET 64→16`，DEX及11个其他native相同，插件精确匹配未剥离符号；[配对证明](../../build-output/vpn-progress-20261021/paired-build-identity.json)。持久缓存重复构建0.73秒、669个编译产物mtime不变、12个native相同。无重试或扫参，两边TCP batch/readiness ON，其余与第四阶段大MTU配置相同；普通构建默认的batch/readiness仍OFF。

| 窗口 | capture budget | Mbps | VPP CPU秒/GiB | credit拒绝 | enqueue拒绝 |
| --- | ---: | ---: | ---: | ---: | ---: |
| A1 /2111 | 64 | 505.13 | 18.43 | 2895 | 0 |
| B1 /2112 | 16 | 489.92 | 16.00 | 134 | 0 |
| B2 /2113 | 16 | 487.87 | 15.69 | 56 | 0 |
| A2 /2114 | 64 | 519.52 | 17.24 | 2367 | 0 |

均值512.32→488.90Mbps（−4.57%），CPU/GiB17.83→15.84（−11.14%），readv/GiB248892→73235（−70.58%），receive rounds/GiB268831→116747（−56.57%）。拒绝合计5262→190且全部为credit不足，enqueue为0；这区分了32个在途credit和64个队列槽位，不能称作handoff队列槽位不足。更小回合减少突发压力，但尚不能把所有拒绝归于单个64包callback：A1只有14/8400个callback读满64包，跨回合的在途占用也可能耗尽credit。

inclusive HEV receive成本5.31→4.09 CPU秒/GiB、调度0.90→0.40；TUN completion6.20→6.23基本不变，policy node1.57→1.62。owner0 pending-to-node均值由2.13/2.32ms降至1.76/1.81ms，仍非socket-ready延迟。两侧ring/sndbuf-full入口观察没有随拒绝同步消失。该取舍没有证明吞吐改善，因此候选16不采用，源码保持capture budget64；返回credit128、primary credit32及64槽均不改。[汇总与火焰图](../../build-output/vpn-progress-20261021/index.html) · [精确计数](../../build-output/vpn-progress-20261021/progress.json)。四窗无probe timeout、停止native债务零；不是匹配负载延迟资格。

### 独立off-CPU窗口：TUN worker在回注路径被抢占

另用同一control64 APK跑generation2115、20秒64流，增加simpleperf `--trace-offcpu`，其465.50Mbps不混入上述ABBA。on-CPU分析明确选择on-cpu模式；[`vpn_waits.py`](../../tests/benchmark/vpn_waits.py)选择off-cpu模式，把sched_switch区间裁剪到端点实际开始/结束时间，保留raw prev_state和完整热点调用链。[等待归因](../../build-output/vpn-progress-20261021/waits.json) · [精确符号/独立CPU图](../../build-output/vpn-progress-20261021/analysis-wait64/analysis.json)。

最终日志显示该独立窗口记录165370条、丢失1738条kernel记录，userspace lost0；分析器标记 `profile_integrity=LOSSY / complete_wait_accounting=false`。以下均为保留记录中的区间归因，丢失可能造成偏差，不能当作完整等待账本；不重跑替换该窗口。

worker0保留区间中的off-CPU约9.09秒，其中raw prev_state256的约8.44秒位于 `preempt_schedule → tun_rx_batched → tun_get_user → write → product_vpn_tun_complete_from_graph`；另约0.58秒在UID通知sendto路径被抢占。保留的VPP epoll等待为0.032秒，Android fwmark等待约0.029秒。worker1保留区间的off-CPU约12.99秒，其中VPP epoll等待11.65秒。worker0切出时紧接着调度 `socket-load` 的区间合计约8.44秒，负载客户端自身CPU为8.59秒；next_comm仅标识切出时的下一线程，不能把整个离CPU区间全算成它的CPU时间。

这补充并修正了对平均CPU的解释：worker0平均只用约53%单核，不代表它在剩余时间等待网络或没有CPU调度压力。该窗口提供单TUN lane在回注路径被抢占、另一owner在epoll等待的线索，不能完整量化二者占比；CPU热点和推进节奏须结合调度解释。跟踪会增加开销，且此窗存在lost，不能证明所有抢占成因、一般应用的CPU分布或整机吞吐上限。

### 客户端CPU亲和性：排除同核消费没有提高吞吐

按[独立协议](../../build-output/vpn-progress-20261021/affinity-protocol.json)，使用完全相同的control64 APK，只将测量客户端的允许CPU mask由ff（CPU0–7）改成8（CPU3），不修改VPP的mainCPU0/workerCPU1、2。两侧warmup保持原状，实际测量的UID2000及exec前继承的 `Cpus_allowed` 均保留在每窗 `client-affinity.txt`。只读sysfs确认CPU1与CPU3容量均160、同属policy0（CPU0–3，最大1803000kHz），没有强制使用大核。

| 窗口 | 客户端CPU | Mbps | VPP CPU秒/GiB | primary credit拒绝 |
| --- | --- | ---: | ---: | ---: |
| C1 /2116 | 0–7 | 507.65 | 18.43 | 2734 |
| D1 /2117 | 3 | 502.01 | 24.18 | 66 |
| D2 /2118 | 3 | 521.34 | 23.61 | 49 |
| C2 /2119 | 0–7 | 519.54 | 17.98 | 2615 |

均值513.59→511.68Mbps（−0.37%），CPU/GiB18.20→23.89（+31.26%），成功TUN writes/GiB137426→193416（+40.74%），readv/GiB+44.39%，receive rounds/GiB+35.66%。worker0在CPU3客户端窗平均CPU约76–77%单核，高于共享窗约58%，但没有获得交付收益。D1有2次返回credit不足/OUTPUT_CAPACITY，D2为0；两窗stamp和VPP buffer不足均0。primary拒绝5349→115且credit额度仍32，说明压力也受处理节奏影响；所有enqueue拒绝为0。这否定了“只把消费者搬走即可提速”的简单预测，不能把多用CPU当成效率改善。[独立汇总与火焰图](../../build-output/vpn-progress-20261021/index-affinity.html)。

### primary credit32/48：小幅吞吐取舍，未证明队列槽位不足

此前实际拒绝均为credit耗尽，因此再按[单容量协议](../../build-output/vpn-progress-20261021/credit-protocol.json)只比较32与现有诊断接口支持的48个primary credit，不增加其他候选值。两边同一个control64 APK，capture budget64、primary64槽、completion128槽、返回额度128及普通客户端CPU继承均不变。在warmup前仅一次调用现有 `product capacity`，要求active-empty graph并核对同generation配置；不重试该设置。

| 窗口 | primary credit | Mbps | VPP CPU秒/GiB | credit拒绝 | enqueue拒绝 |
| --- | ---: | ---: | ---: | ---: | ---: |
| E1 /2120 | 32 | 515.35 | 17.08 | 1962 | 0 |
| F1 /2121 | 48 | 539.72 | 18.73 | 2383 | 0 |
| F2 /2122 | 48 | 533.33 | 17.88 | 1888 | 0 |
| E2 /2123 | 32 | 516.31 | 18.28 | 3939 | 0 |

均值515.83→536.53Mbps（+4.01%），CPU/GiB17.68→18.31（+3.55%），readv/GiB+6.60%，receive rounds/GiB+7.69%；TUN writes/GiB基本不变（+0.09%）。credit拒绝5901→4271（−27.62%），没有消失，enqueue始终0；返回credit/stamp/buffer不足均0。存在局部headroom收益，但不是MTU修复那样的数量级变化，也未证明64个handoff槽位不足。[独立汇总与火焰图](../../build-output/vpn-progress-20261021/index-credit.html)。

三个对照分别回答捕获回合、客户端放置与credit大小，不跨组混算；每组固定四窗，无重试或参数扫描。端点五元组与owner负载分布可变化，原始分布保留，2窗/配置不足以给出一般统计显著性或发布资格。现有证据支持把TUN回注的按包内核成本和HEV接收/推进粒度作为主要成本，而不是把500Mbps上限归因于单一队列常量；既未采用capture16，也未修改primary默认credit32、队列64槽或产品CPU放置。

### 第五阶段身份、检查与测量后恢复状态

最终Product源码闭包为control64的 `6ede6ce5f0f647122065f57a6e8b7f209062a0f0ec600c88fef31fc127299a07`，核心patch及9个VPP runtime与第四阶段相同；这里只增加可观测计数，不改变传输/容量默认行为。control64 APK `c765faee149621939f76258bf6139c481274ab6e447260a781ca01492f7c8ca8`；被否决的candidate16 APK `cdc85e9d80a8e211c88c40a17ae0a062870e703e44f4b0e21c9eb78caad81b0a`及源码快照均保留。四个collector版本按各自manifest SHA保存，12个on-CPU窗口lost0/unknown leaf0；独立off-CPU窗口1738 lost明确保留。[13窗审计](../../build-output/vpn-progress-20261021/sampler-final.json) · [全部推进计数](../../build-output/vpn-progress-20261021/progress-all.json)。最初final日志尚在post-processing阶段，最终原始日志另存为 `perf-final.log`；审计器最初只匹配另一种lost日志格式的解析失败同样保留，格式修正后才发现并记录off-CPU lost，没有重采样。

Host真实primary/completion批量回归、external batch及policy batch通过；普通VPN collector的generation/推进/native debts/保留删除日志检查通过。13窗停止均满足generation对应的native债务零，阻塞reader完成、FIFO gate移除、remote日志SHA与本地停止日志相同。最终恢复原October13 APK及12个native、规则hash、Root grant和Stopped2123，Openwrt_5G全程保持，VPP/socket-load/simpleperf无残留；本轮LAN peer经PID/starttime/exe/argv/hash核对后由pidfd关闭。[设备最终审计](../../build-output/vpn-progress-20261021/final-readonly/result.json) · [专用peer清理](../../build-output/vpn-progress-20261021/peer-cleanup.json)。

以上为阶段测量和清理结果，不代表SAKAMOTO-292完成。后续诊断须分别解释用户态无进展调度、逻辑等待条件、已被唤醒但尚未运行的时长及内核off-CPU区间，保留已有失败和候选被证伪的记录。

## 第六阶段：按等待与唤醒原因定位

真实HEV调度器最小复现确认了一个额外系统调用：external schedule已做一次非阻塞I/O扫描，随后pick_current_task在同时存在RUNNING/WAITING任务时再次扫描。一个任务quantum包含入口及yield后的扫描即可，修复前实测3次，修复后2次。[RED](../../build-output/vpn-wait-cause-20261021/scheduler-red.log) · [GREEN及I/O回归](../../build-output/vpn-wait-cause-20261021/scheduler-coverage.log)。补丁0015只跳过external路径中紧接着的重复扫描，standalone调度器保留阻塞I/O与timer扫描；回归实际运行混合任务、真实pipe事件、standalone timer唤醒及清理。

这是已证实的局部CPU空耗，尚未证明它是整体吞吐瓶颈。设备侧原始症状仍须用相同插桩的对照和等待账本验证，SAKAMOTO-292保持进行中。另一个曾考虑的“上传队列空时返回1而busy-yield”假设，经完整已应用源码核对被排除：实际空队列返回0，不能根据不完整patch片段修改它。

### 首次唤醒与逻辑等待账本

仅在现有TCP progress诊断开关启用时，记录WAITING→RUNNING的首次唤醒（I/O、ACK、inner recv、TCP poll、timer、other），区分正进展后的runnable continuation。每次yield记录互斥原因并把等待条件满足前、首次唤醒后到执行的墙钟区间分开；snapshot折入尚未闭合区间，避免跨采样边界丢失。这是各session的墙钟和，不能解释成CPU百分比。实际tcp_receive rounds、idle与首次来源逐项对账；[分析器](../../tests/benchmark/vpn_task_waits.py)在五个设备窗口全部通过。[原始协议](../../build-output/vpn-wait-cause-20261021/protocol.json) · [账本](../../build-output/vpn-wait-cause-20261021/task-waits.json)。

重复poll的ABBA G1/H1/H2/G2使用完全相同的插桩、MTU10000、capture64、ring32768及primary32/64槽，只有patch0015的external guard不同，11个native与DEX相同。吞吐均值518.43→519.35Mbps（+0.18%），CPU秒/GiB19.01→18.00（−5.28%），poll/GiB−50.07%。这证明减少了实际系统调用空耗，没有证明吞吐上限已解除。

四窗合计651533个idle round中，569590（87.42%）紧接正进展后的continuation；该round发现无进展后进入WAITIO，源码与计数共同排除了“无进展仍不断自我yield”的busy loop。另81071（12.44%）由ACK首次唤醒，其余主要是TCP poll。I/O首次唤醒后的idle只有13次。后续应验证ACK在没有解除ring/pending限制时是否造成无用唤醒，不能把所有idle都算作同一种问题。

owner0的runnable任务从yield到再执行的合计时长/该类yield数约39.80ms，owner1约0.40ms；此处是session调度间隔，不是每个VPP input node的待运行延迟。owner0基本保持可运行，主要不是等上游数据或ACK；owner1同时有大量upstream与inner ACK逻辑等待。它解释了为什么两个owner的推进形态不同，但不是独立的端到端延迟分布。

### 无报告丢失的off-CPU补充

独立I1窗口使用FP栈与每CPU4096 mmap pages，先核对实际ELF中HEV关键函数的frame pointer prologue；采集器等owned profiler退出后才读取最终日志和停止VPP。五窗最终lost均0，I1的SDK元数据185057条记录、kernel/userspace lost与truncated-stack均0；完整Build ID与symbols核对通过。它保留并补充此前1738 lost窗口，不替换原始记录。[最终采集/reader检查](../../build-output/vpn-wait-cause-20261021/sampler-final.json) · [精确调用链](../../build-output/vpn-wait-cause-20261021/waits.json)。

I1 worker0记录off-CPU8.668秒，其中8.143秒在TUN write的tun_rx_batched抢占栈、0.471秒在UID sendto抢占栈；VPP epoll等待仅0.042秒。worker1 off-CPU11.366秒，其中VPP epoll约9.824秒。worker0的长runnable间隔因此须与单TUN lane上的graph工作、OS抢占结合解释，不能宣称“HEV在无数据时烧满CPU”。FP链省略inline helper，分类器依据实际外层VPP/HEV scheduler区分epoll，原始完整栈仍保留。无报告丢失也不能恢复记录末尾尚未闭合的off-CPU区间，故不宣称完整等待占比。

38项真实HEV Host回归通过，含held-ACK/loss/backpressure/FIN；普通VPN证据校验通过。真实Android unchanged repeat为0 Rust编译、0 Ninja actions、823个编译文件mtime保持及12个native字节一致（两次约0.76秒）。五窗native零债务和reader/gate检查通过，设备自动恢复原APK、规则和Root grant，Openwrt_5G保持。这是ACK对照前的阶段结果；其后验证和最终取舍见下节。

### ACK过滤：局部RED/GREEN成立，整条路径无收益，撤回

新真实TCP fixture让上游只回传4096字节、保留充分ring空间，待任务读空并WAITIO后再注入纯ACK。控制版多执行一次空receive round（[RED](../../build-output/vpn-wait-cause-20261021/idle-ack-red-executed.log)）；候选保持满ring、pending与EOF唤醒，只跳过不解锁工作的一类ACK，IPv4/IPv6均降为0且字节与最终释放正确（[GREEN](../../build-output/vpn-wait-cause-20261021/idle-ack-green.log)）。候选40项Host回归通过，也验证了实验开关关闭时的40项默认回归。局部成立没有被当作整条路径收益。

按[独立ACK协议](../../build-output/vpn-ack-wake-20261021/protocol.json)再做J1/K1/K2/J2，同样的single-poll与插桩，唯一差别是ACK predicate。候选两窗分别跳过31388、36101次等待态ACK通知，ACK首次唤醒后的idle均为0。但均值518.29→504.90Mbps（−2.58%），CPU秒/GiB18.38→18.61（+1.25%）。I/O首次唤醒/GiB增加26.56%，整体idle/GiB只减少1.75%，poll/GiB反增1.77%；事件节奏发生替换，不能由单个idle来源消失推出效率提高。两窗/配置及owner负载差异限制更强的统计结论，因此不采用该候选，不修改原ACK语义。[完整汇总](../../build-output/vpn-ack-wake-20261021/summary.json)。

候选补丁、精确source/APK/symbols、测试源码、RED/GREEN及全部四窗保存在证据目录；Product中的ACK过滤、跳过计数及其专属测试均已撤回。最终Product没有这段行为；当前patch0017是下面的read结果计数补丁，不能与候选的归档同编号补丁混淆。

### 最终代码的read结果核对与恢复

旧read_blocked包括EAGAIN/EWOULDBLOCK/EINTR，故此前“upstream”账本不是单独的errno统计。最终补丁0017-direct-tcp-read-results拆分EAGAIN/EWOULDBLOCK、EINTR和EOF，仅把实际EAGAIN归为upstream，EINTR进入other。读取、提交、yield条件及ACK唤醒语义保持原样。

在最终代码的独立20秒L1窗口中，owner0/1分别记录2072/163130次EAGAIN，共165202次；EINTR均0，EOF合计2，read_blocked逐owner等于EAGAIN+EINTR，首次唤醒/idle总数也完全对账。这直接验证了该窗口的read失败确实是非阻塞读空。466.86Mbps、20.93 CPU秒/GiB是单窗最终源码见证，不与上述ABBA混算，不能当作性能增益的估计或回填以前记录的errno。[账本](../../build-output/vpn-read-reasons-20261021/task-waits.json) · [精确ELF/CPU记录](../../build-output/vpn-read-reasons-20261021/analysis-L1/analysis.json)。

最终源码闭包为8318c4c9eb778517157eff41d52f0743cc1dec97e631eb720d9fa9387986e50c，APK为ae2882215b1e22376fb31f1d0b888882b18e1d498b2c4aa93e69bb94227257c5；[完整构建身份](../../build-output/vpn-read-reasons-20261021/read-reasons/build.json)。最终默认配置与batch/progress诊断配置各38/38 Host回归通过；Host unchanged build为no work。Android unchanged repeat为0 Rust编译、0 Ninja actions、1087个编译文件mtime保持和12个native字节一致，约0.88秒。普通VPN evidence校验和10个新设备窗口的round/idle对账、native零债务、reader/gate完成、最终perf lost0全部通过；旧lossy窗口保持原样。

最终恢复原October13 APK及12个native、规则hash和Root grant，设备Stopped2133，Openwrt_5G保持，VPP/socket-load/simpleperf无残留。两次专用LAN peer均按PID/starttime/exe/argv/hash核对并由pidfd结束。[最终设备审计](../../build-output/vpn-read-reasons-20261021/final-readonly/result.json) · [peer清理](../../build-output/vpn-read-reasons-20261021/peer-cleanup.json)。

本轮因果结论是：大部分idle是实际推进后的最后一次读空探测，随后进入WAITIO；不是无进展持续自我调度。等待条件与首次I/O/ACK/poll唤醒已分开，owner0主要保持runnable并在单TUN lane工作及抢占之间等待再次执行，owner1有大量真实I/O/ACK等待。已证实并修复的是external调度器的重复epoll扫描，其配对CPU成本下降5.28%；ACK过滤未获整条路径收益而被撤回。以上完成了这些现象的可重复定位与修复验证，没有把500Mbps当作已经被唯一归因或解除的吞吐上限。
