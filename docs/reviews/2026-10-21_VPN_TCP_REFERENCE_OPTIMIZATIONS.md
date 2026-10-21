# 普通 VPN 固定 TCP 下载：外部实现可借鉴的优化

日期：2026-10-21。研究基线：`50395e96de900134abe093bbd092f913ec807c64`。本轮只读源码和既有证据；没有实现、构建、设备操作、Wi-Fi 切换或性能复测。

**确实还有办法。证据最强的是增大本地内层 TCP 段；第二条是让 socket readiness、ACK 和 completion 更及时地推动原 owner，同时抑制重复通知和无变化的事件维护。** 这两条都不要求更换 HEV。内层大 MTU 已用于真实无 root Android 本地 TCP 桥接，不只是 Linux/root 示例：NetGuard 和 PCAPdroid 均配置 10000 字节。

这里区分三种结论：外部源码实际采用某机制；该机制可能减少本产品某项成本；它是否提升当前 Pixel 固定下载。前两项可由本次调查支持，第三项仍须限定实验。

## 当前证据与可用边界

[已完成的批处理实验](../testing/2026-10-21_VPN_FIXED_TCP_BATCH.md)证明 readv/GiB 降 62.0%、TCP receive 轮次/GiB 降 53.0%、VPP CPU 秒/GiB 降 6.17%，但吞吐没有提升。TUN write/GiB 基本不变。batch 的 TUN completion 为 49.4% inclusive、HEV TCP receive/splice 为 11.7%、HEV 调度为 3.6%；这些路径会重叠，不能相加。内核占 69.3%，也不能把整个内核分支当作一次 syscall 入口成本。两 worker 平均未满，off-CPU、短时队列和推进延迟仍未解释。

产品保持 [ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md) 的 canonical FlowOwner、owner-inline 非阻塞推进、独立 copy-based VPP/lwIP 边界、正常共享图、单 TUN lane 和每 worker 隔离返回 allowance。以下机制须在这些约束下实现；不从外部项目或 POC 导入代码，不恢复 [ADR-0008](../adr/0008-remove-snort-cpp-mainline.md) 删除的 C++ 路径。

## 实际参考了什么

| 一手实现与固定身份 | 源码做了什么 | 对本产品的意义与限制 |
| --- | --- | --- |
| [NetGuard `166df969c3`](https://github.com/M66B/NetGuard/tree/166df969c3cedd7023c13613d9816c185702c6c9) | [`ip.c:26`](https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/ip.c#L26) 返回 MTU=10000，MSS 减去 IP/TCP 头；[Java Builder](https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/java/eu/faircode/netguard/ServiceSinkhole.java#L1463) 把 JNI MTU 交给 `setMtu`。[`tcp.c:555`](https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L555) 按 `min(send_window,mss)` 从 socket 读取，再合成返回包。 | 是 Android 本地 Direct 桥接的大段实例；不能据此宣称其性能优于我们，也不能复制其传输正确性简化或内存管理。 |
| [PCAPdroid `66f7b35145`](https://github.com/emanuele-f/PCAPdroid/tree/66f7b3514540c20add8655a74dfee93d00a9563b) + 实际子模块 zdtun `c2a2674a41` | [`CaptureService.java:110`](https://github.com/emanuele-f/PCAPdroid/blob/66f7b3514540c20add8655a74dfee93d00a9563b/app/src/main/java/com/emanuelef/remote_capture/CaptureService.java#L110) 的 `VPN_MTU=10000`，[:511](https://github.com/emanuele-f/PCAPdroid/blob/66f7b3514540c20add8655a74dfee93d00a9563b/app/src/main/java/com/emanuelef/remote_capture/CaptureService.java#L511) 调 `setMtu`；[`capture_vpn.c:455`](https://github.com/emanuele-f/PCAPdroid/blob/66f7b3514540c20add8655a74dfee93d00a9563b/app/src/main/jni/core/capture_vpn.c#L455) 同步给 zdtun。其 [`handle_tcp_reply`](https://github.com/emanuele-f/zdtun/blob/c2a2674a411efdd71f7595e5395d8b49c52ab347/zdtun.c#L1728) 也是窗口/MSS 有界 recv；[回调](https://github.com/emanuele-f/PCAPdroid/blob/66f7b3514540c20add8655a74dfee93d00a9563b/app/src/main/jni/core/capture_vpn.c#L116) 仍逐包 write TUN。 | 第二个独立 Android 实例，证明“大 MTU”和“普通逐包 TUN write”可以共存。不是必须 GSO 才能放大本地段。 |
| [HEV 2.18.0 `d9dca26c7a`](https://github.com/heiher/hev-socks5-tunnel/tree/d9dca26c7ad0e494492244f0309e80ee583e739e) + lwIP `e22c9d2873` | [`conf/main.yml:9`](https://github.com/heiher/hev-socks5-tunnel/blob/d9dca26c7ad0e494492244f0309e80ee583e739e/conf/main.yml#L9) 与 [`hev-config.c:473`](https://github.com/heiher/hev-socks5-tunnel/blob/d9dca26c7ad0e494492244f0309e80ee583e739e/src/hev-config.c#L473) 为 MTU=8500；[lwipopts](https://github.com/heiher/lwip/blob/e22c9d2873cd5a8aade9deb2e518b75dab05170e/src/ports/include/lwipopts.h#L389) 为 MSS8191、WND/SND_BUF 各 8×MSS=65528。[`tcp_splice_b`](https://github.com/heiher/hev-socks5-tunnel/blob/d9dca26c7ad0e494492244f0309e80ee583e739e/src/hev-socks5-session-tcp.c#L85) readv 到 ring，再 tcp_write/tcp_output；ACK callback 回收 ring。 | 与当前 HEV/lwIP 家族直接相关；但其 MTU 配置本身不能证明某个 Android APK 实际 Builder 设置。也不能照搬其整段 tcp_write/error 路径，覆盖本产品已验证的小事务和所有权修复。 |
| [sing-box v1.12.0 `2dcb86941f`](https://github.com/SagerNet/sing-box/tree/2dcb86941f5db01bbe296acae555a3b1f38c0441) 与 [SFA `bc73504fcb`](https://github.com/SagerNet/sing-box-for-android/tree/bc73504fcb858400a939140ad785ed92f4c9f429) | [tagged inbound](https://github.com/SagerNet/sing-box/blob/2dcb86941f5db01bbe296acae555a3b1f38c0441/protocol/tun/inbound.go#L134) 在普通平台未配置 MTU 时选 65535；Network Extension 选 4064。GSO 条件明确要求 `platformInterface==nil`。[SFA Builder](https://github.com/SagerNet/sing-box-for-android/blob/bc73504fcb858400a939140ad785ed92f4c9f429/app/src/main/java/io/nekohasekai/sfa/bg/VPNService.kt#L64) 使用 `options.mtu`；[v1.12.0 Android 功能表](https://github.com/SagerNet/sing-box/blob/2dcb86941f5db01bbe296acae555a3b1f38c0441/docs/clients/android/features.md#L14) 明列 MTU 可用、GSO 无权限。 | 不能继续把文档示例 9000 当作当前统一默认；也不能把 native Linux GSO 当 Android VpnService 能力。这两份源码不是同一版本组合，不能视作精确 APK 的构建身份。 |
| [sing-tun `f8d5b54dbd`](https://github.com/SagerNet/sing-tun/tree/f8d5b54dbd711a812858a403f505ee7e8fd350ee) | [新 Go engine](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack_go_engine.go#L250) 把 flush、TUN burst、socket events、ACK 和 timers 放进同轮推进；[processBurst](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack_go_engine.go#L624) 同时按帧数和字节数限额，余量设置 pending。 | 可借鉴事件/预算机制。此处读的是独立 dev commit，不是上行 sing-box v1.12.0 的依赖，不宣称该新 engine 的 Android 发布资格或性能。 |

未找到足够一手证据确认本次所查 Android 项目统一采用 **16KiB 内层 MTU**。8KiB 附近有 HEV 家族配置依据，10KB 有 NetGuard/PCAPdroid 实际 Builder 依据；9000 是可配置示例而非本次固定版本的统一默认。选择本产品试验值仍需自己的容量与正确性证据。

## 候选一：内层 MTU/MSS 放大，真正减少 TUN 包数

**潜力最高，机制可信度高，当前吞吐收益未知。** 建议第一档以 MTU8500 / MSS8191 为上限方向做受控候选；也可先用约4KiB排查包长支持。外部案例支持的是机制可行，具体数值不是产品默认建议。

这是两条独立 TCP：Android 应用↔本地 lwIP 的内层链，和 protected socket↔原远端的外层链。Direct socket 传递字节，外层内核按真实网络 MSS 分段。因此这里的大内层包无需 Wi-Fi 支持 jumbo frame。远端 L3 VPN 则把原 IP 包封装后送网关，受外层 PMTU/封装影响；不能把它与本地 Direct 桥接混为一谈。[Android `setMtu`](https://developer.android.com/reference/android/net/VpnService.Builder#setMtu(int)) 配置的是本地 VPN interface。

当前 [product lwipopts](../../third_party/hev/product/lwipopts.h) 是 MSS1360、WND/SND_BUF32768、pbuf pool element2048；[Flow Stack limits](../../src/product/vpp/product_vpn_flow_stack.c) 是 `max_packet_bytes=1500`；[Java MTU](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VpnTunPlatformSession.java) 为1500。[TUN adapter](../../src/product/vpp/product_vpn_tun_adapter.c) 返回分配和 capture 都受 VPP default data size 约束。**只改 Builder 或 TCP_MSS 会失败或不生效。** 需要一并审计 netif MTU、双栈 MSS 协商、VPP 有效 buffer size、parser 连续长度、输出 callback 的 spans 拷贝以及 capture 上限。保留两个所有权拷贝、正常图与单 TUN lane；不以借用 pbuf 或旁路策略解决大包。

最低验证与可证伪预测：

1. 先做同一真实 HEV fixture 的 TCP 双栈字节流及边界检查，覆盖协商大 MSS、ring wrap、ERR_MEM/返回拒绝、FIN 和停止结清。检查每个大 IP 包长度、checksum 和新 VPP buffer 容量；容量失败应明确计数。
2. 只跑原固定 TCP 下载，候选开/关各至少两窗、ABBA、相同 Wi-Fi/并发/规则/返回数量上限；批处理开关在两边相同。新连接才重新协商 MSS。
3. 预测：实际下行 payload/packet 显著增大，TUN 成功 write/GiB 显著下降。理想满段约为原来的1360/8191≈16.6%，不是保证值；kernel CPU/GiB 与 completion CPU/GiB 应下降。总吞吐不承诺按此倍率增长。
4. 若只有配置变化而实际包长仍约1360，候选机制没有生效；若包数下降而 CPU/GiB 不降，要查大包分配、cache/copy 或内核分段成本。若 CPU 降而吞吐不变，说明当前增吞仍受推进/等待等因素影响。

与 ADR 兼容，但实现量高于配置调参；8K buffer 是否整体增加内存预算，要独立记录，不能把增加缓冲容量的收益偷偷计为 MSS 收益。保持32768字节 sndbuf 可先隔离变量；同时采用上游65528会混入第二个实验因素。

## 候选二：按真实可推进状态门控事件，合并唤醒并改善同 owner 公平推进

**潜力中等，外部机制可信度高，本地瓶颈归因未闭合。** 重点不再是把8段盲目扩大成更多段，而是让已有工作不等下一轮无关事件，并且不会让持续 socket/TUN readiness 独占同一个 owner。

两个具体参考：

- NetGuard [`monitor_tcp_session:117–166`](https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L117) 仅在发送窗口有空间时订阅 socket EPOLLIN，且 interest 未变化不做 `epoll_ctl`。zdtun 在[窗口耗尽时移除 socket read 集合](https://github.com/emanuele-f/zdtun/blob/c2a2674a411efdd71f7595e5395d8b49c52ab347/zdtun.c#L1795)，在[应用 ACK 释放窗口后重新加入](https://github.com/emanuele-f/zdtun/blob/c2a2674a411efdd71f7595e5395d8b49c52ab347/zdtun.c#L1332)。可借鉴“消费能力决定关注事件”，不复制其 TCP 简化。
- sing-tun 的[同轮推进顺序](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack_go_engine.go#L276)及[字节+帧预算](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack_go_engine.go#L624)，避免只以包数衡量不同包长的工作。其 [TUN runtime poller 分离](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/tun_linux.go#L680) 还专门处理双 poller 的重复唤醒；后者是 Go 特有实例，不能直接说本产品也有同一问题。

本产品适用的窄方向：检查 pending ready 通知是否可按 owner/generation 去重；timer 的绝对 deadline 未变时不重新 arm；只有在 ring/sndbuf 与返回资源均允许时继续 socket 消费；ACK/credit 释放之后把已有 pending 数据安排到该 owner 的下一次正常 node 调用。字节预算和轮次预算都要有界。每 worker allowance 仍隔离，不能借另一个 worker 的额度，不能迁移 flow 或让 helper 执行 lwIP。

这些是**审计和候选机制**，不是宣称现有代码完全没有门控/flush。现有 HEV reactor 使用 `EPOLLET`，TCP在连接前订阅读/写事件，不能把 NetGuard 的 interest 策略当作本产品已存在 writable level-trigger 空转的证据。若抑制读取或改变订阅，必须保留 pending readiness，并在 ACK/credit 恢复后显式继续有界消费，避免数据一直可读却没有新 edge 的停顿。已提交批处理已有 credit 耗尽前 frame flush 和重试，不应把它描述成固定的“32 credits 未 flush 死锁”。返回资源不足也须区分 credit、stamp、VPP allocation，不用总 OUTPUT_CAPACITY 推断单个根因。

最低验证与预测：先在原固定下载增加每 owner 的 ready→node 延迟、node 执行间隔、连续 runnable 时间、空推进、timer rearm、eventfd/epoll/readv 调用、ring pending/sndbuf 阻塞与返回拒绝原因。按同一下载 tuple 比较 owner 流数、交付字节及 per-flow rate，并记录每线程 off-CPU/调度等待，避免平均CPU掩盖瞬时停顿。

现有留存快照已有值得追查的不均衡：[新增测试 tuple 的 owner 分布](../../build-output/vpn-tcp-reference-research-20261021/retained-owner-distribution.json)中，A1 两 owner 各34 flows，`reply_bytes`约7.59/60.36MB；A2为39/29 flows，但约8.33/67.54MB。owner0还承担唯一TUN I/O lane。这里68条包含4条probe，字节是共享图的前后快照差分，不是端点交付计量，也未排除CPU调度、频率或应用竞争。因此它支持逐flow推进调查，不能证明单TUNlane、owner0或某次唤醒就是根因。

若重复事件维护是主要问题，门控后无效调用/GiB、空推进与重复唤醒应下降；若公平推进是主要问题，原 owner 的 ready 等待长尾与低速流占比应改善。TUN write/GiB 在 MSS 不变时应基本不变。若这些计数原本已低、两个 owner 工作延迟相当，或新门控只降 syscall 而不改变等待/交付，增吞假设被削弱，应停止加复杂调度器。

普通 Android 的 poll/epoll、socket readiness 和既有通知机制不要求 root。适用的是状态与通知策略；不要求新 thread、全局 transport 调度器或共享 payload 队列。

## 条件候选三：只在证实发送端缓冲受限后增大 sndbuf/ring

HEV 上游 SND_BUF65528 和本产品32768确有差异；sing-tun 的 [gVisor buffer profile](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack_gvisor_tcpbuf_default.go#L12) 允许大得多的上限，但不是实际分配量，也不能把另一个栈的 MiB 上限移植为我们的推荐值。

固定下载方向的 lwIP 是**内层发送端**：重点是 `snd_buf`、ring 未ACK占用、`snd_wnd`、`cwnd` 和 ACK 及时性。单独提高 `TCP_WND` 主要扩大 lwIP 接收应用上行数据的窗口，不会自动放大它的下载发送窗口。[lwIP pcb 初始化](https://github.com/heiher/lwip/blob/e22c9d2873cd5a8aade9deb2e518b75dab05170e/src/core/tcp.c#L1914)也明确分开 `snd_buf` 与 `rcv_wnd`。

最低量：先测 ring/sndbuf 满的时间占比、未ACK字节、inner RTT 与应用 advertised window；只在数据待发且 sndbuf/ring 持续为限制时，用一个约64KiB候选与32KiB对照，保持MSS和批处理相同。预测是每次ACK间的空转/停顿下降、未ACK利用率或吞吐提升；若它们原本不满，则不应为“上游更大”而增加容量。记录每会话/owner占用与停止结算。当前是低至中可信的条件实验，不是已发现的根因。

## 不列为普通无 root Android 的现成优化

| 方案 | 一手约束及结论 |
| --- | --- |
| TUN `writev` 一次写多个 IP 包 | Android common kernel 的 [`tun_chr_write_iter`](https://android.googlesource.com/kernel/common/+/5d72892f267735f397659fb6cc5dbca3c5018157/drivers/net/tun.c#2030) 一次调用 `tun_get_user`，后者取整个 `iov_iter_count` 作为一个包长度；iov 是一个包的片段，不是多包边界。sing-tun [`BatchWrite`](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/tun_linux.go#L635) 在无 vnet header 时也逐包 `Write`。可以用 writev 避免**同一包**的 gather copy，不能消除多个包的 write 次数；本产品现有连续 VPP buffer 无此明显收益。 |
| TUN GSO/GRO/TSO | [AOSP Android14 JNI](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-14.0.0_r1/services/core/jni/com_android_server_connectivity_Vpn.cpp#65) 创建 `IFF_TUN|IFF_NO_PI`，没有 `IFF_VNET_HDR`。sing-tun [`enableGSO`](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/tun_linux.go#L234) 要求先有 vnet header，再设置 offload。更直接的是 [AOSP Android16_r4 app_neverallows](https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r4/private/app_neverallows.te#199)：普通 app 不能直接 open tun_device，ioctl 仅允许 FIOCLEX/FIONCLEX/TUNGETIFF。因此不能拿到 fd 就假定可 TUNSETIFF/TUNSETOFFLOAD。root/server 的可行方案不构成普通 VPN 优化。 |
| io_uring 批量 TUN write | Google 作者的[安全说明](https://www.openwall.com/lists/oss-security/2023/06/17/2)明确当时 Android 应用被 seccomp-bpf 阻止访问 io_uring；[Android16_r4策略](https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r4/private/app_neverallows.te#325)也对普通 app 的 domain anon_inode 使用施加强限制。本次未读目标设备实际策略、未执行 syscall 探测，不能泛化为所有历史/定制Android绝对不可用；普通产品不能假定可用。即使可用也不自动减少每包TCP内核处理，还引入异步buffer生命周期，当前不建议实现。 |
| `sendmmsg`、`splice`、所谓全链零拷贝 | 普通 VpnService 给的是 TUN字符设备fd，不能把 socket 多报文接口直接套用。上游函数名 `tcp_splice_b` 实际是 readv→ring→tcp_write，并非 Linux splice 系统调用。完整路径还需解析/策略与TCP重建。移除ADR选定的两处拷贝不在本次建议范围。 |
| 盲目禁 Nagle、缩短TCP timer或强制ACK | HEV/lwIP [`tcp_output`](https://github.com/heiher/lwip/blob/e22c9d2873cd5a8aade9deb2e518b75dab05170e/src/core/tcp_out.c#L1335) 确有Nagle判断；但连续满MSS下载不等于小写等待ACK问题。NetGuard/zdtun的 TCP_NODELAY 作用在**外层socket发送**，不能直接解决本地下行TUN包数。[HEV lwIP timer](https://github.com/heiher/lwip/blob/e22c9d2873cd5a8aade9deb2e518b75dab05170e/src/include/lwip/priv/tcp_priv.h#L116)是250ms fast / 500ms slow；本产品也是沿用250ms `tcp_tmr`调用，但这不是每段下行必须等待250ms的证据。没有ACK间隔、partial segment与timer等待证据前不调这些参数。 |

内层大 MSS 是普通有效 IP/TCP 包，无需 virtio offload metadata，因而不被上述 GSO限制否定。平台源码核对没有使用目标设备 root状态作为普通 app权限证明。

## 建议顺序与证据局限

先补齐每 owner 推进/阻塞的限定观测，同时准备内层大段的容量审计；最先有望显著降低TUN成本的是大段候选。调度候选先定位事件延迟和空转，再做一个窄变更。32→64KiB缓冲只在被实测限制时独立做。保持唯一固定TCP下载套件、原Wi-Fi和相同并发；不混入UDP/CPS/Root负载，不以另一个项目的速度宣传代替AB证据。

本次已确认外部机制和限制，没有证明任何外部项目在当前设备/同策略上的吞吐，也没有证明替换HEV会更快。源码版本是调查时冻结的样本，不是建议常规升级vendor。可复查材料在 [research evidence](../../build-output/vpn-tcp-reference-research-20261021/)：各repo的commit/tree元数据、选取源码、实际submodule源码和AOSP文本；没有创建依赖构建目录或运行编译。

## 2026-10-21 补查：竞品使用哪些库，是否优于 HEV

**竞品确实也要把应用侧包流与外连 socket 字节流接起来，但实现不只有一种。没有本机同条件证据能认定其中某个比当前 HEV 更快。最新 sing-tun 自有 TCP 栈是值得追踪的新对照；zdtun 更轻，却不满足我们现有的返回丢包恢复语义；system 则是另一种内层终止拓扑。**

| 项目／固定版本 | 实际传输实现 | 对当前固定 TCP 下载的判断 |
| --- | --- | --- |
| HEV，本产品 pinned family／上文 2.18.0 对照 | **lwIP 是内层 TCP/IP 栈；HEV task/reactor 是调度与 I/O 桥接层。** `tcp_write`、ACK、重传由 lwIP 处理，protected socket由外层内核处理。[上游 receive/ACK 路径](https://github.com/heiher/hev-socks5-tunnel/blob/d9dca26c7ad0e494492244f0309e80ee583e739e/src/hev-socks5-session-tcp.c#L85)可见这个分工。 | “换掉 HEV 调度”和“换掉 lwIP TCP”是两个不同变更。减少无效轮转无需重写 TCP。 |
| PCAPdroid `66f7b35145`，zdtun `c2a2674a41` | **自研 C 库 zdtun**，部分 TCP/IP 状态与窗口/序号转换；[README明确不实现 TCP 重传](https://github.com/emanuele-f/zdtun/blob/c2a2674a411efdd71f7595e5395d8b49c52ab347/README.md#L5)。 | 很适合观察其轻量桥接办法，但不能直接替代本产品。外层 kernel TCP 的重传不能追回“已经从外连socket读走、合成内层包后被共享图/返回容量丢弃”的字节。PCAPdroid 自己的[代码注释](https://github.com/emanuele-f/PCAPdroid/blob/66f7b3514540c20add8655a74dfee93d00a9563b/app/src/main/jni/core/capture_vpn.c#L110)也明确：返回包被阻断必须关闭连接，zdtun无法处理这种丢包。更轻不等于同等语义下更快。 |
| NetGuard `166df969c3` | **项目自己的 C TCP 实现**，在 [`tcp.c`](https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c)管理状态、序号、窗口、socket和返回包；不是 lwIP，也不是一个可直接替换的通用栈API。 | 可借鉴大MSS及事件策略，但没有同设备性能对照；本次未建立它与本产品全部丢包/乱序/资源拒绝语义等价的证据，不把它称作更好的通用库。 |
| sing-box **v1.12.0** → [`sing-tun v0.7.0-beta.1`](https://github.com/SagerNet/sing-box/blob/2dcb86941f5db01bbe296acae555a3b1f38c0441/go.mod) | [选择器](https://github.com/SagerNet/sing-tun/blob/v0.7.0-beta.1/stack.go#L41)：`gvisor`使用Go用户态netstack；`system`使用系统内核TCP；[`mixed`](https://github.com/SagerNet/sing-tun/blob/v0.7.0-beta.1/stack_mixed.go)为**system TCP＋gVisor UDP**。默认还受构建是否含gVisor、GSO及IncludeAllNetworks影响。 | 仅测TCP时，mixed的TCP仍是system，不能拿mixed当第三种TCP栈。gVisor是完整用户TCP候选，但增加Go runtime/并发与生命周期整合工作，没有证据保证比lwIP省CPU。 |
| sing-box **v1.15.0-alpha.3** 文档／sing-tun当前冻结源码 `f8d5b54dbd` | [alpha版文档](https://github.com/SagerNet/sing-box/blob/v1.15.0-alpha.3/docs/configuration/inbound/tun.md#stack)引入 **sing-tun 自有 Go TCP/IP 栈**，计划废弃旧stack选项；当前源码[空值/`go`选择NewGo](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack.go#L59)，[engine](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/stack_go_engine.go#L250)把packet、socket、ACK/timer集中有界推进。 | **最值得新增的外部研究对照**，因为它也针对用户TCP桥接调度成本设计。官方声称性能/能效改善，尚非我们的实测；alpha文档、冻结dev源码与稳定Android APK不能视为同一发布物，未证明当前已安装/稳定SFA使用该commit。Linux multi_queue能力也不能移作普通Android收益。 |
| xjasonlyu/tun2socks **v2.6.0** | **gVisor netstack＋Go桥接**：[`core/stack.go`](https://github.com/xjasonlyu/tun2socks/blob/v2.6.0/core/stack.go)创建协议栈；[`core/tcp.go`](https://github.com/xjasonlyu/tun2socks/blob/v2.6.0/core/tcp.go)通过 `tcp.NewForwarder/CreateEndpoint/gonet.NewTCPConn`得到内层流；[`tunnel/tcp.go`](https://github.com/xjasonlyu/tun2socks/blob/v2.6.0/tunnel/tcp.go)再dial外连并双向copy。 | 是成熟的另一种桥接实例，仍保留内层重建、外连socket及TUN交付，不消除目前的大头。README的性能宣传不是Android、同MTU、同策略、同owner模型的比较。 |

**system 需要特别说明。** 它不是把原应用连接直接交给真实远端内核栈：[`stack_system.go`](https://github.com/SagerNet/sing-tun/blob/v0.7.0-beta.1/stack_system.go)先创建本地TCP listener，把捕获包的地址/端口改写后写回TUN，让内核在listener终止内层TCP；accept后再由handler桥接外连，反向包也经TUN读出、还原和写回。它可能借助内核TCP实现，但也增加本地socket/包循环的工作，不能无测量就称作“去掉用户TCP所以最快”。这是普通TUN重注入/本地listener机制，与root iptables重定向或直接内核转发原远端连接不同。对本产品属于需要重新审查adapter/provenance/owner边界的拓扑候选，非ADR-0007现有lwIP模块的直接库替换。

许可证只记录已读到的声明，不据项目语言或依赖名推断：zdtun的[源头声明](https://github.com/emanuele-f/zdtun/blob/c2a2674a411efdd71f7595e5395d8b49c52ab347/zdtun.c#L7)对应 `LGPL-3.0-or-later`；sing-tun当前[LICENSE](https://github.com/SagerNet/sing-tun/blob/f8d5b54dbd711a812858a403f505ee7e8fd350ee/LICENSE)为 `GPL-3.0-or-later`；xjasonlyu/tun2socks v2.6.0的[LICENSE](https://github.com/xjasonlyu/tun2socks/blob/v2.6.0/LICENSE)为 `MIT`。这些是对应项目的声明，未替代逐依赖/逐文件核对。

采用判断：**目前继续优化HEV/lwIP的段长和推进最有依据；若另开库比较，先对照最新sing-tun自有栈与gVisor，保留system作为拓扑研究，zdtun不作为等价替换。** 后续比较必须先对齐MTU/MSS、socket/内层缓冲和同一固定下载，分别测端点吞吐、CPU/GiB、TUN包/GiB和off-CPU；先通过返回丢包/拒绝恢复、字节流、双栈与stop结清，再讨论替代。外部库自己的goroutine、全局栈或直写TUN不能直接绕过本产品owner-inline、copy ownership与正常策略图约束。此次补查没有实现或性能验证。
