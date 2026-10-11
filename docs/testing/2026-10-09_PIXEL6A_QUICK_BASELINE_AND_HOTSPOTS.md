# Pixel 6a B0：两分钟基准与第一轮热点分析

采样：2026-10-08 深夜；分析：2026-10-09。**八组真机负载全部完成，日常入口实测 105.886 秒。** 最终固定每组 5 秒、共 40 秒负载；其余时间包含身份读回、暖机、诊断、四次正常生命周期和收尾。此前 10／8／6 秒方案属于失败或不完整校准，没有混入 B0。

## 基线确认与后续比较

**2026-10-11，用户确认采用本轮作为性能优化基线 B0。** 这是当前配置下的真机快速压力基线；确认同时保留本报告记录的未入图 accept、容量饱和、拒收、稀疏延迟样本和符号精度边界。

| 固定项 | B0 配置 |
| --- | --- |
| 设备与模式 | Pixel 6a；Root 与普通 Product VPN 均跑 |
| 测量窗与总预算 | 八组各 5 秒；完整入口 deadline 120 秒；B0 实测 105.886 秒 |
| 并发 | 4 个 I/O 线程；固定组 64 数据流；TCP-new 并发窗口 64 |
| UDP 数据 | 1200 B；UDP-new 每个新五元组四包 |
| VPP 布局与容量 | 两个 worker，lcore 1／2；Flow 每 owner 1024 |
| 规则 | revision 907，零 direct rules／groups／bindings；源 SHA 见下文 |
| 对端与采集 | LAN `192.168.4.5:41320`；profiling 开启，199 Hz cpu-clock，同窗采样 |

后续产品优化版本记为 B1、B2……，Root／VPN及四类负载分别与B0比较，不合并为一个总分。保持发生器、窗口、并发、数据尺寸、规则、worker／容量、对端和采集开关一致；APK身份随产品优化更新并重新记录。工具行为、设备／系统或测试条件出现影响可比性的变化时，单独建立新基线系列。原始B0与失败校准记录不覆盖、不改名为优化结果。

比较吞吐／完成率时同步列出Flow创建、容量miss、未入图accept、拒收、丢包、CPU和延迟样本数。减少处理或增加绕过不能记作处理性能收益；本轮固定UDP的稀疏p99不作为稳定收益判据。

使用已准备工具重跑的入口如下；先确认手机授权、安装身份及LAN对端可用，输出目录必须是新目录。命令是复现说明，本次基线确认没有重跑设备测试。

```sh
rtk proxy build-output/pixel-quick-prepared-20261008/socket-load-host server 192.168.4.5 41320
# 在另一终端执行；对端已运行时不用重复启动。
rtk proxy python3 tests/benchmark/pixel_quick.py run \
  --manifest build-output/pixel-quick-prepared-20261008/manifest.json \
  --output build-output/pixel-quick-B0-repeat-<unique-run-id>
```

更换优化APK后按[工具说明](../../tests/benchmark/README.md)生成对应的准备manifest，保持上述参数。用 `report.py compare` 比较完整的B0／Bn结果；只完成部分组或超过120秒的运行仍标 `INCOMPLETE`。

## 证据与固定条件

- [原始结果与操作时间](../../build-output/pixel-quick-baseline-20261008-final/result.json)、[八张交互火焰图与 CPU 总览](../../build-output/pixel-quick-baseline-20261008-graphs/index.html)、[热点分解](../../build-output/pixel-quick-baseline-20261008-graphs/detailed-hotspots.json)。
- 设备是 Pixel 6a，serial `28201JEGR0XPAJ`，Android 16／bluejay；发生器、Root NFQUEUE、普通 Product VPN、VPP CPU／RSS 和所有 perf 都来自手机。`192.168.4.5` 是 LAN 收发对端。八份 perf 的 metadata 均核对 Pixel 6a。
- 安装 APK SHA-256 为 `653b7ea3ec1b53f0aa5b2a7206bebda99740ecbec478382220fecda0d89447ca`，沿用 Root recovery 安装包，没有安装新产品、修改 worker 数或扩大容量。实际 workers 在 lcore 1／2，main 在 0。
- [规则源头部读回](../../build-output/pixel-quick-baseline-20261008-final/rule-source-header.json)确认 revision 907、direct rules／groups／bindings 均为 **0**；规则 SHA 在整轮前后不变。UI 的旧规则投影不能代替这个源文件事实。
- 4 个发生器 I/O 线程；固定组为 64 条数据连接／五元组，TCP-new 为 64 个并发窗口槽，UDP-new 每个新 tuple 发四个 1200 B 包。四个独立延迟探针另计。固定 TCP 是手机接收持续下载，UDP 是手机向 LAN 发送。
- `simpleperf cpu-clock -f 199 -g --clockid monotonic` 同窗采样；八份记录均 `Samples lost: 0`。火焰图按 helper 的实际 monotonic 起止裁剪；离线拉取与渲染另耗约 2.46 秒，不计作 105.886 秒日常入口的一部分。
- [工具说明](../../tests/benchmark/README.md)、[已准备的可重跑 manifest](../../build-output/pixel-quick-prepared-20261008/manifest.json)。所有 Android 操作使用 `./dev/adb`。每模式按固定 TCP → 固定 UDP → 新 TCP → 正常重启 → 新 UDP；新建两组不共享满表。每组记录实际起止 Flow 占用。

## 四类基础成绩

下表吞吐是**端点实际交付**，新建速率是完成连接或手机成功发送的新五元组；它们分别与 VPP Flow 创建、旁路和拒收核账。

| 负载 | Root | 普通 VPN | 本轮最直接的观察 |
| --- | ---: | ---: | --- |
| TCP 固定 64 流下载 | 310.45 Mbps | 104.90 Mbps | Root 有未入图 accept；VPN 有跨 worker admission 拒绝和较高探针延迟 |
| UDP 固定 64 流 | 547.04 Mbps／56,983 pps | 244.34 Mbps／25,452 pps | 尽力发送下丢包 88.76%／97.38%；VPN 两个 worker 接近满载 |
| TCP 大量新连接 | 1,480.98 completed CPS | 972.88 completed CPS | 成功 7,414／4,871 次；对应 VPP 新建仅 1,896／1,930 个，流表碰顶 |
| UDP 大量新五元组 | 输入 51,167 tuple/s；交付 424.10 Mbps | 输入 6,399 tuple/s；交付 3.85 Mbps | 对端分别看到 63,121／505 个 underlay tuple；VPN 后半程主要表现为拒收 |

各模式是相同工具配置下的各自尽力加压，不是相同 offered rate：固定 UDP 的手机 send-success 约 Root 50.7 万 pps、VPN 97.3 万 pps。不能把丢包百分比当作同输入速率的比较。LAN peer CPU 约 0.4%–10.4% 单核，本轮没有 peer CPU 打满的迹象；这不证明 Wi-Fi 物理链路无限余量。

UDP 对端计数在负载停止后的有界读回取得，Mbps／pps 按手机发送窗归一化，包含该组的尾部交付；这不是严格接收侧同一5秒窗口的瞬时速率。CPU／GiB按VPP采样覆盖时长外推整窗，是快速估计，保留原始覆盖时间，不作为精密能耗结论。

## Root：主要成本在判决返回／内核继续处理

Root 四组 VPP on-CPU 的内核时间占比约 **83.65%、74.39%、84.16%、82.10%**。这是采样 VPP 进程自身的 CPU 时间，不是全手机 CPU，也不包含全部异步 softirq／驱动线程成本。

固定 TCP 的已解析调用链为 `sendto → netlink_sendmsg → netlink_unicast → nfqnl_recv_verdict → nf_reinject`。`sendto` inclusive 约 **70.74%**，`nfqnl_recv_verdict` inclusive **56.73%**，`nf_reinject` inclusive **54.53%**。这些是同一链上的重叠比例，不能相加。其它 Root 组的 `sendto` inclusive 约 60.6%–76.3%。内核叶节点还包括 `queue_work_on`、`ipt_do_table`、IRQ 锁和 skb／slab 操作。

因此，当前证据把 Root 的重点指向 NFQUEUE 判决返回、内核 reinjection 和来源 lane 的集中负担。`ipt_do_table` 是内核 iptables 成本，不能把它叫作零规则下产品统一规则引擎的匹配热点；`queue_work_on` 也不能直接当成 VPP 用户态 wakeup 成本。

| Root 负载 | worker 0 CPU | worker 1 CPU | 未入图 accept 增量 |
| --- | ---: | ---: | ---: |
| TCP fixed | 56.0% | 7.3% | 14,172 |
| UDP fixed | 87.3% | 10.8% | 64,074 |
| TCP new | 59.2% | 6.4% | 19,829 |
| UDP new | 81.0% | 7.5% | 38,642 |

本轮单 LAN IPv4 对端的实际 NFQUEUE 输入集中在 lane 0。Flow 可以分到两个 canonical owners，但收到 verdict 的 origin lane 仍承担最终返回。因此“已有两个 worker”没有转化为均衡 CPU 利用。Root 的高端点交付还包含未入图 accept；不能将 547 Mbps 当成全量策略路径处理上限。

## VPN：两个场景的热点与边界不同

**固定 TCP 下载**：约 63.24% on-CPU 在内核，`write` inclusive 约 **44.07%**，其下 `tun_chr_write_iter / tun_get_user` 约 **39.9%／39.4%**。当前下载方向的 TUN 返回写入及内核继续处理占显著成本。窗口中还出现 14,085 次 primary admission 拒绝／runtime drops。两个 workers 约 55.4%／43.8%；本轮不能仅凭这张图认定 HEV 某个未解析函数是最大热点。

**固定 UDP 发送**：两个 workers 约 **96.0%／95.7%**，确实把 W2 压到接近满载；`__sendmsg` inclusive 约 **38.56%**，内核 on-CPU 约 56.93%。窗口的 Flow Stack accepted／rejected originals 分别为 127,290／160,228。真实交付 244.34 Mbps 与总输入／拒收一起看，反映当前 CPU、I/O 和 admission 的过载拐点。已解析 `memmove` self 约 1.5%，动态 TLS resolver self 约 2.1%；两者都不足以单独解释整个瓶颈，inline/unknown 部分仍需符号支持。

**新 UDP 五元组**：手机输入 31,999 个不同 tuple，只有 **505** 个 underlay tuple 抵达对端；实际收到 2,003 包、约 3.85 Mbps。VPP Flow 创建 2,024 个、capacity misses 117,856；Flow Stack 另有 **123,829** 次 rejected originals。内核 on-CPU 降到 38.18%，产品插件未知叶增加到约 41%，说明当前窗口与固定 UDP 的实际执行路径不同，不能称为单纯发送吞吐测量。

源码 [Flow Stack 默认限制](../../src/product/vpp/product_vpn_flow_stack.c:35)为每 owner 256 sessions，合计约 512；[UDP session admission](../../third_party/hev/product/hev-owner.c:402)在该容量满时拒绝。对端 505 tuples 与该上限高度吻合，**这是有源码支持的容量瓶颈推断**。本轮没有 `show product flow-stack` 的逐原因 faults 快照，不能把全部拒收都认定为 `SESSION_CAPACITY`；packet credit、socket/PCB 和其它失败需要细分确认。

## 新建成绩已混入容量饱和路径

两个 owner 的 VPP Flow 容量均为 1,024；[无空闲 slot 时的处理](../../src/product/vpp/product_flow_entry.c:589)记录 capacity miss。四个新建窗口的 misses 为：Root TCP 32,196、Root UDP 91,979、VPN TCP 18,004、VPN UDP 117,856。

Root TCP 的 7,414 个成功请求只有 1,896 次 VPP Flow 创建；VPN 为 4,871／1,930。这些数明确证明 completed CPS 不能当作完整新 Flow tracking 的处理速率。UDP tuple/s 同样不能当作已创建并成功转发 session/s。本轮保留它们作为当前容量下的实际压力行为，没有用扩容、强制 flow reset 或另一套 flow authority 隐藏上限。

## p99 与符号精度

TCP-new 的完成样本相对充足：Root empirical p99 upper 125.2 ms（7,414 样本）、VPN 267.6 ms（4,871 样本）；另有 5／2 timeout 和各 64 个截止时未完成请求，成功请求 p99 不代表这些未完成请求的延迟。固定 TCP 为 277.5／977.8 ms，但 VPN 只有 64 个有效探针样本。固定 UDP Root／VPN 只有 **5／1** 个有效探针响应，不能将其 p99 用于稳定的优化收益判断；大量 timeout／loss 本身就是结果。

产品插件 GNU build-id 为 `a0887342d3b3b3ea53d03a75a64c4ac2bf40efd5`。符号 cache 使用与安装 APK 完全一致的 native payload、手机精确 libc 读回；旧 mode-fix 的 unstripped 插件 build-id 为 `ff7e9df...`，没有套用到新样本。当前插件／部分 VPP 库是 stripped，未知叶占各窗口约 11.9%–45.8%。热点表的“插件 unknown 41%”是多个地址的汇总，**不是一个函数**，不能据此给规则哈希、parser、HEV allocator 的具体优先级排名。

## 本轮支持的分析方向与收尾

优先把 Root 的 verdict／reinjection、单 origin lane 成本，与 VPN 的 TUN/underlay 系统调用、primary/return admission 和 session 容量分开评估。现有代码中 frame/queue 每包提交的批处理债务仍是候选，但本轮不能量化其修改收益；也没有证据把 SIMD/FNV/prefetch 定为这些窗口的首要 CPU 热点。

一次性构建/上传不进入日常入口，SDK 火焰图离线处理不另跑负载。八组结束后 native debt/residue audit 通过，VPP 进程不存在，App 已在正常 native 清理后 force-stop，最终 stopped／mayBeActive=false；规则 SHA 不变。校准时观察到 Android Service 交接触发 owner-live，工具通过完整 App 进程边界避免它；这不是产品生命周期修复或正式可靠性资格。保留失败校准，未修改产品 C／Java，也未 Git 提交或 Plane 操作。
