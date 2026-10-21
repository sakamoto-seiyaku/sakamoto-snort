# 固定 TCP 下载：VPN 的额外路径与大分段候选

日期：2026-10-21。按用户本轮要求，只分析已有 TCP 连接的固定下载，解释火焰图的大块、与 Root 的结构差别，以及可能产生较大收益的方向。本轮没有产品代码改动、设备操作或重新采样。新建连接与 UDP 结论仍见[原实验记录](../testing/2026-10-21_ORDINARY_VPN_BASELINE_AND_UDP_SEND.md)，不作为本轮固定 TCP 研究的阻挡条件。

## 实际 CPU 花在哪里

沿用原实验四个固定 TCP 窗口 A1/B1/B2/A2，generation2067/2071/2075/2079，端点107.27/124.68/108.19/108.71 Mbps。A/B 区别是 UDP send 开关，不能把这四个 TCP 窗口解释为某个 TCP 优化的前后对照。精确 APK、源码闭包、匹配符号及原始 perf 身份见原实验。

将每个采样的叶子 DSO 分类、按 sample period 汇总，得到下面**互斥、合计100%**的进程 on-CPU 成本。内核列包含 kernel modules；插件静态包含 HEV/lwIP，不能把整个插件等同于规则匹配。

| 叶子执行位置 | 四窗加权占比 |
| --- | ---: |
| 内核及内核模块 | 66.12% |
| Product 插件自身，包括 HEV/lwIP | 22.14% |
| VPP 库 | 5.62% |
| libc | 4.06% |
| linker | 1.49% |
| 其它 | 0.56% |

[可重算脚本](../../build-output/vpn-fixed-flow-drilldown-20261021/exclusive_dso.py)读取原逐窗剖析，逐窗断言分类周期总和等于原周期总和；[结果](../../build-output/vpn-fixed-flow-drilldown-20261021/tcp-exclusive-dso.json)包含每窗 perf SHA256。四窗插件自身分别23.31%、22.28%、21.82%、21.14%。

以下则是**inclusive 调用链，会重叠，不能相加**；同样汇总四个固定 TCP 窗口：

| 调用链 | CPU占比 | 解释 |
| --- | ---: | --- |
| TUN return completion | 46.27% | 最大分支，包括 syscall 后面的内核协议处理 |
| 其中 `tun_get_user` | 42.42% | 属于上一行内部，不是另一份42% |
| HEV underlay receive / TCP splice | 14.89% | 包含 protected socket 读取、ring/lwIP 提交及其子调用 |
| shared policy graph | 9.22% | 包括图内子调用，不是纯 matcher self |
| HEV task scheduling | 5.30% | 不等于所有内核调度成本 |
| HEV input copy / lwIP dispatch | 5.90% | 包括 ACK 等输入协议处理，不是纯 memcpy |

来源：[固定流原始调用链与分组脚本](../../build-output/vpn-fixed-flow-drilldown-20261021/analysis.json)、[代表性 TCP 火焰图](../../build-output/vpn-udp-send-batch-fresh-20261021/graphs2-B1/vpn-tcp-fixed-flamegraph.html)。

最大分支具体是 `product_vpn_tun_complete_from_graph → write → tun_get_user → tun_rx_batched → netif_receive_skb → IP/Netfilter/TCP → socket readable wakeup`。代表窗 B1 的 `_raw_spin_unlock_irqrestore` self约9.98%，其主要 caller 包括 `__wake_up_sync_key → sock_def_readable → tcp_data_ready → tcp_data_queue`。不能据函数名字断言为我们的共享锁争用。`ipt_do_table` self约4.99%属于内核 Netfilter，也不能算成 Product matcher。

`memmove` self四窗加权约0.98%，Flow `find_entry`约0.75%，dynamic TLS resolver约1.42%。消除这些单点不能单独解释或消除最大的返回内核路径。即使假设插件22.14%的执行全部免费，而其它工作完全相同，纯 CPU 工作模型也只有约1.28倍改善；这不是吞吐上限，因为当前还有等待与背压。

## 与 Root 差距的结构原因

固定下载的主要字节路径可简化为：

```mermaid
flowchart LR
    A[远端 TCP 数据] --> B[Android 内核 TCP / protected socket]
    B --> C[readv / HEV ring]
    C --> D[lwIP 重新产生内层 TCP 包]
    D --> E[VPP 共享策略图]
    E --> F[TUN write]
    F --> G[Android 内核 TCP / 应用 socket]
    G --> H[下载应用]
```

Root 保留原应用的内核 TCP 连接，Product 在包的 NFQUEUE 路径中给 verdict；普通 Direct VPN 还要维护 protected socket 和内层 TCP 的桥接、重建与确认。插件的可执行映射因此多了 HEV/lwIP 工作，TUN write 还在调用线程中执行一段内核接收路径。该内核同步执行机制可见 [Android common 6.1 `tun_rx_batched`](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/net/tun.c#1537)。

两张**进程级**火焰图的百分比还会受工作记在哪个 task 上影响。应用线程、softirq/ksoftirqd 等进程外成本未被这里完整涵盖，不能把 Root 图中较小的插件宽度直接换算成整机效率倍数。本轮未做同条件 Root/VPN 配对，因此只确认结构差别，不给一个新的模式间倍率。

这是当前 [ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)明确承认的 packet-to-flow 重建成本。删掉整套本地 transport reconstruction 通常需要 Root 或远端 L3 网关等拓扑变化；它们改变本轮普通、本地 Direct VPN 的前提。将 HEV 换成另一个用户态 TCP 栈，本身也没有消除这条桥接路径。

## 最有潜力的大方向：增大本地内层 TCP 分段

这是一项**待证实的机制假设**：让更多下载字节共用一次 lwIP 产包、图执行、TUN write 和内核接收，而不是只把现有小包的几个函数改快。

当前配置有三道明显限制：

- Android [`VpnTunPlatformSession`](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VpnTunPlatformSession.java#L20)的 TUN MTU 为1500。
- [`lwipopts.h`](../../third_party/hev/product/lwipopts.h#L13)的 `TCP_MSS=1360`，`TCP_WND/TCP_SND_BUF=32768`，`PBUF_POOL_BUFSIZE=2048`。
- [`product_vpn_flow_stack.c`](../../src/product/vpp/product_vpn_flow_stack.c#L38)的 `max_packet_bytes=1500`；[`product_vpn_tun_submit_return`](../../src/product/vpp/product_vpn_tun_adapter.c#L122)只接受能装入一个默认 VPP data buffer 的输出。输入、解析和 reassembly 的连续存储假设也要核对，不能只放宽出口长度。

Android 提供公开的 [`VpnService.Builder.setMtu`](https://developer.android.com/reference/android/net/VpnService.Builder#setMtu(int))。TCP MSS 与有效 MTU 的关系见 [RFC6691](https://www.rfc-editor.org/rfc/rfc6691.html#section-2)。本地 Direct TCP proxy 的内外两段是两个 TCP 连接，因此内层可以研究更大的 MTU/MSS，物理 Wi-Fi 仍由 protected socket 的内核 TCP 按其路径分段；这不是要求 Wi-Fi 支持 jumbo frames。这里的可行性判断来自当前桥接结构，尚无本产品的大 MTU 设备证据。

例如内层 MTU8192、IPv4不带选项时的 MSS 上限8152，比当前1360约大6倍。若实际 payload 充分填满，可把该方向的数据包次数降到约1/6；**不意味着吞吐提高6倍**。以仅46.27%的工作能同比缩减、其余不变为示意，CPU 工作加速约 `1 / (1 - 0.4627 + 0.4627 / 6) = 1.63`。这是模型，不是测量值，字节复制、checksum等成本不会按包数完整缩减。

较小的验证台阶也成立：若实际默认 VPP data buffer 足够，MTU2000、IPv4 MSS1960可先测试“分段增大是否降低 TUN writes/交付GiB”，减少一次跨越大 buffer 边界的改动。实际协商 MSS、segment payload 分布必须观测，不能只检查配置常量。8192方向则需要明确选择大 buffer 或端到端的 chain 支持，并结算相同内存预算，不能顺手把所有池放大。

这个方向须同时处理双栈、UDP大datagram、ICMP/PMTU和策略解析的兼容性。全局 TUN MTU 会影响其它协议；不能通过只跑 TCP 成功便宣称发布兼容。保留共享图和独立复制所有权不需要撤销 ADR，但实现不能让大包绕过现有校验和策略。

## GSO/GRO：机制有吸引力，当前普通 VPN 接口没有闭合

[Linux segmentation offloads 文档](https://www.kernel.org/doc/html/latest/networking/segmentation-offloads.html)说明 GSO/TSO 用 metadata 描述一个大 buffer 中的多个 TCP segment。这与实际协商大 MSS不同，若平台支持，可保持逻辑 segment size 而减少边界搬运次数。

但 [AOSP VPN native 创建代码](https://android.googlesource.com/platform/frameworks/base/+/master/services/core/jni/com_android_server_connectivity_Vpn.cpp#63)使用 `IFF_TUN | IFF_NO_PI`，没有 `IFF_VNET_HDR`。所查 Android common `android14-6.1` 中：

- `tun_get_user`只在 `IFF_VNET_HDR` 开启时读取 virtio segmentation metadata。
- 对已有 attached fd再次 `TUNSETIFF`返回 `EEXIST`，不能用它直接更换该 fd 的 flags。
- `TUNSETVNETHDRSZ`只设置 header size；`TUNSETOFFLOAD`只设置相关 features，二者本身都不启用 `IFF_VNET_HDR`。
- 另开 fd重新 attach还涉及现有单队列、TUN security与Android权限边界，不能当作普通 Builder 已承诺的功能。

来源：[Android common 6.1 tun.c](https://android.googlesource.com/kernel/common/+/refs/heads/android14-6.1/drivers/net/tun.c)，相关本地行1769、3110、3244、3294；[下载源码及SHA256清单](../../build-output/vpn-fixed-flow-drilldown-20261021/references/manifest.json)。这些源码是平台机制参考，**不是本次 Pixel vendor kernel 的逐字节构建来源证明**。因此 GSO保留为平台可行性调查，不能承诺“加一个 ioctl 就行”。

## 另一项值得验证的结构问题：每轮推进量与返回背压

当前 [`0011-direct-tcp-session.patch`](../../third_party/hev/patches/0011-direct-tcp-session.patch#L119)把每次 `tcp_write`限制到一个协商 MSS；通常一个连续 ring span 只提交一段，然后 `tcp_output`并回到 [`tcp_session_task`](../../third_party/hev/product/hev-owner.c#L568)的 yield。边界上有两个 ring span 时存在两次提交的例外，因此不是绝对每轮只一包。

可研究每次轮转对**已有数据**做有界多次小提交，并在合适边界统一 `tcp_output`/图发布，减少轮转和推进空隙。每个 write 的事务资源边界仍须保留，不能把一段任意大的 ring直接改成大事务。仅减少yield而不改变分段，仍然保留逐包 TUN/内核处理，所以这条路与大 MSS的作用不同。

四窗 owner1的 OUTPUT_CAPACITY分别1623/2622/8874/4744，owner0均0。它目前没有区分 return credit、stamp或VPP allocation不足；窗口边界 in_use=0不代表窗口中无峰值。这使“多推进一点”既可能提高有效推进，也可能更快撞满返回边界，不能无证据增加预算。

两个 worker的窗口平均 CPU约53%–59%和41%–43%单核，CPU-only图没有等待时长。固定下载还应区分 `ring非空但未提交`、sndbuf等待、return拒绝、helper唤醒至owner执行，以及单TUN lane的短时峰值。必要的观测应统计真实推进量与分原因背压，避免高频日志改变负载。

本轮的工程判断是：**优先验证本地内层大分段能否减少整条每包路径；有界 TCP推进作为独立候选；GSO先过普通 Android平台可行性；零拷贝、TLS和lookup单点不承担解释当前大差距的任务。** 验证应同时给出实际协商 MSS、TUN writes/交付GiB、VPP CPU秒/交付GiB、拒绝、重传和停止结算，吞吐与CPU分开解释。以上是研究结论及可证伪预测，不是已实施或已采用的默认值。
