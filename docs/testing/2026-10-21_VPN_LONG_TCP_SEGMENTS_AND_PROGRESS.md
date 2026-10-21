# 普通 VPN：长连接 TCP 下载的大分段与推进观测

日期：2026-10-21。用户限定性能基线为 TCP 长下载；本记录没有 UDP、CPS 或 Root 性能负载。参考依据见[源码调查](../reviews/2026-10-21_VPN_TCP_REFERENCE_OPTIMIZATIONS.md)。

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
