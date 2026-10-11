# Android VPN DNS 接入：成熟实现与 KISS 候选

2026-10-07。**候选研究，不是正式架构决定或已实现能力。**
只做联网第一方源码与 Android API 核对；未构建、移植、运行或操作设备。
首版范围是 Root/NFQ 与 VPN；KSU 只保留未来扩展位置。
没有读取本仓 ADR-0008 删除的 Snort C++ 主线、模型、归档，也没有导入 POC。

## 结论

**共用应落在 DNS 消息处理与上游连接上；应用侧 TCP/UDP 的交付责任不能凭普通系统 socket 消失。**
Intra、NetGuard、RethinkDNS 的实际 VPN 路径都把 TUN 包转换成用户态会话，再处理 DNS 或转发到普通上游 socket。
其中 Intra 的虚拟 DNS 用进程内调用接入 resolver，没有再经本地内核监听端口；它同时接管 UDP 与 TCP DNS。[I1][I2][I3]
因此，已有 HEV/lwIP 的本仓优先考察“复用既有会话交付 + 直接调用共用 DNS 核心”，符合减少新增协议责任的 KISS 方向。
这是依赖当前仓库已有会话栈的设计推论；外部 Go/gVisor 实现只说明机制，不构成引入它们的建议。

## 固定源码身份

| 核对项目 | 固定 commit | 本轮用途 |
| --- | --- | --- |
| M66B/NetGuard | `166df969c3cedd7023c13613d9816c185702c6c9` | Android 全流量防火墙，C 用户态 TCP/UDP 与普通 socket 分工 |
| Jigsaw-Code/Intra | `7bc64a4867ea7531d5f9b27c8169efedb3baea8d` | DNS 加密产品，当前实现接入 lwIP 且默认 IPv4 全路由，不是仅 UDP DNS 的薄 VPN |
| celzero/rethink-app | `3d92d38268d6e1a76b4a6e9c4f6b4c6428b2721f` | Android VPN DNS 地址与 DNS-only/full VPN 路由设置 |
| celzero/firestack | `75cfc671860f60fe9dad9003eb63744f4371e518` | Rethink 网络后端，会话、过滤、缓存、DoT/DoH 职责 |

rethink-app 与 firestack 分别固定用于静态核对；未验证这两个 HEAD 对应同一发行制品或依赖 pin。
以下源码链接都固定到上述 commit，Android API 引用是本次读取的官方接口说明。

## 1. Intra：虚拟 DNS → lwIP 会话 → 直接 resolver

`GoVpnAdapter.java:161-175` 同时设置 VPN 本地地址、`0.0.0.0/0` 路由和独立虚拟 DNS 地址，取得 TUN fd。[I1]
`intra/tunnel.go:85-99` 给 `lwip2transport.ConfigureDevice` 提供 stream dialer 和 packet proxy：lwIP 承担内侧 IP/TCP/UDP 到会话的转换。[I2]
UDP 目的地等于虚拟 DNS 时，`packet_proxy.go:119-141` 直接把 payload 交给共用 `Resolver.Query`，再通过原 UDP response receiver 回答。[I3]
TCP 目的地等于虚拟 DNS 时，`stream_dialer.go:64-85` 返回进程内 `net.Pipe`，另一端交给 `doh.Accept`，没有创建本地 TCP listener。[I4]
`doh/doh.go:495-560` 读取 DNS TCP 长度帧，调用同一 `Query`，将答案加上长度前缀送回流。[I5]
`Resolver.Query` 输入/输出是完整 DNS wire message；HTTP/TLS 上游另由 `http.Transport` 和 dialer 承担。[I6][I7]

```text
addDnsServer(fake IP) → TUN IP 包 → lwIP
  UDP payload ───────────────→ Resolver.Query → 原 UDP 会话回复
  TCP stream → DNS 长度帧 ──→ Resolver.Query → 原 TCP 会话回复
                                      ↓
                               普通 dialer + HTTP/TLS
```

这证明 UDP/TCP 可以复用一个 DNS resolver；“用了系统 socket”指上游，不能反推内侧 TCP 已由内核 listener 处理。
本轮不把 Intra 当完整缓存方案：所读源码的 IPMap/TLS session cache 与通用 DNS 答案缓存是不同概念。
也不照搬其 TCP 帧实现：当前 `Accept` 使用单次 `Read` 检查每帧长度；职责可借鉴，完整流读取与并发答复正确性仍需独立实现和验证。[I5]

## 2. NetGuard：C 会话与上游系统 socket 是两段

`ServiceSinkhole.java:1290-1297` 在过滤模式设置 DNS server，路由配置决定 DNS 和其他流量是否进入 TUN。[N1]
`ip.c:342-349` 分派到 `handle_udp` / `handle_tcp`；UDP 会话保存原地址/端口，再创建上游 socket。[N2]
`udp.c:378-435` 使用 `SOCK_DGRAM` 并调用 socket protection；答复从上游 socket 读出，经 `write_udp` 重新封成包回 TUN。[N3][N7]
TCP 使用 `SOCK_STREAM` 上游 socket，但原应用侧 seq/ACK 与封包仍由 native TCP 会话处理。[N4][N8]
TCP53 回答也进入 DNS 检查，所以此例不是“只支持 UDP，然后把 TCP53 排除掉”。[N5]

其 DNS 域名阻断发生在返回回答的处理里；不能把它当作本产品“查询进入缓存/上游之前过滤”的实现依据。[N3][N6]
本轮未在这些接入路径确认 DoT/DoH 或完整答案缓存；NetGuard 只作为会话与 socket 分工证据。

## 3. RethinkDNS：DNS-only 与全流量都复用后端会话

Android 侧设置虚拟 IPv4/IPv6 DNS；DNS-only 模式仅添加相应 DNS 地址路由，全流量模式则添加更多路由。[R1]
后端 `tunnel/tunnel.go:179-201` 将 TUN fd 接到 gVisor netstack，`intra/tunnel.go:247-254` 注册 TCP/UDP handler。[R2][R7]
TCP 和 UDP handler 命中 DNS 地址后都调用 `dnsOverride`，向同一个 `resolver.Serve(proto, conn, uid, fid)` 交付会话。[R3][R8][R9]
`Serve` 仅按 UDP/TCP 选择内侧消息读取方式；过滤/上游选择与答案处理放在 resolver 和 transports 内。[R4][R12]
缓存是 transport 的装饰层，DoT/DoH 各自实现上游，不把答案缓存放进 TUN 包处理。[R5][R10][R11]

```text
VPN DNS 配置 + 路由 → TUN → gVisor TCP/UDP conn
                                     ↓
                    resolver.Serve(proto, conn, uid, fid)
                                     ↓
                    查询政策 / 缓存 / DoT 或 DoH transport
                                     ↓
                              原会话 → TUN 回答
```

其配置明确区分“捕获指定虚拟 DNS 地址”与“捕获全部 port53”：`addDnsServer` 不等于应用自选 DNS 也都被接管。[R6]
复杂 proxy、ALG、多上游等能力不是本仓首版建议；只借鉴同一 resolver 接两种内侧会话和上游职责分离。

## 候选比较与本仓最小职责

| 候选 | DNS 共用形状 | 新增责任 | KISS 判断 |
| --- | --- | --- | --- |
| A：Root listener / VPN 既有会话直接交付 | 一个 DNS 消息核心 + 普通上游 socket | 两个薄入口，VPN 在现有 HEV/lwIP 增加本地 DNS 会话出口 | 优先候选；Intra 展示了进程内直达 resolver 的相同分工 |
| B：VPN 会话再连接共用本地 listener | 同一 listener 与核心 | 仍需 VPN 会话转换，再加内部 socket、会话关联、回环与关闭处理 | 有现成进程边界时可比较；本仓未要求新进程，暂缺收益证据 |
| C：VPN 直接交内核 listener、替代会话栈 | 假设能复用 Root listener | 必须证明真实内核投递、路由与回复路径；标准 TUN fd 只读写 IP 包 | 本轮三个项目未发现这种 DNS 路径；未找到不能证明不可行 |
| D：自行解析 TUN UDP、TCP 不做或透传 | UDP 接共用核心 | UDP 封包/分片等责任；完整 DNS TCP 仍缺 | 不符合完整 UDP/TCP53 接管，不能因代码短就当等价首版 |

候选 A 下，入口只负责交付 DNS 消息、原会话与已有应用身份上下文，并将答案送回；不要再分别实现 Root/VPN DNS 缓存或 TLS/HTTP。
核心集中持有查询事务、按应用过滤、wire 答案缓存、DoT/DoH、关联事实与观察输出；TCP DNS 长度帧层可以复用，但它不是 TCP 协议栈。
上游 socket 使用同一创建/收发实现，将 Root 排除自身重定向与 VPN protect/选网接入既有平台准备步骤。
Android 官方 `protect` 是把自建 socket 流量排除 VPN，`establish` fd 是包接口；两者没有承诺把读到的 TUN 包直接投递本地 listener。[A1][A2]
不需要给用户新增“DNS 是否经过 VPN”开关：在首版产品策略明确后，由内部固定配置 DNS 入口与上游 bypass；这是一项候选设计取舍。
实际应用身份能否可靠带入及未知身份处理沿 ADR-0011；以上外部源码不保证 Android 所有系统 DNS 请求都可归属原应用。

## 第一方证据索引

[A1]: https://developer.android.com/reference/android/net/VpnService.Builder#establish()
[A2]: https://developer.android.com/reference/android/net/VpnService#protect(int)
[I1]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/main/java/app/intra/net/go/GoVpnAdapter.java#L161-L189
[I2]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/intra/tunnel.go#L85-L109
[I3]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/intra/packet_proxy.go#L119-L141
[I4]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/intra/stream_dialer.go#L64-L85
[I5]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/doh/doh.go#L495-L560
[I6]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/doh/doh.go#L81-L88
[I7]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/doh/doh.go#L207-L224
[N1]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/java/eu/faircode/netguard/ServiceSinkhole.java#L1290-L1297
[N2]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/ip.c#L342-L349
[N3]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/udp.c#L110-L143
[N4]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L1038-L1058
[N5]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L595-L610
[N6]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/dns.c#L178-L192
[N7]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/udp.c#L378-L435
[N8]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L1176-L1289
[R1]: https://github.com/celzero/rethink-app/blob/3d92d38268d6e1a76b4a6e9c4f6b4c6428b2721f/app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt#L3540-L3594
[R2]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/tunnel/tunnel.go#L179-L201
[R3]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/common.go#L521-L541
[R4]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/dnsx/transport.go#L933-L955
[R5]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/dnsx/cacher.go#L95-L118
[R6]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/settings/tunopts.go#L19-L25
[R7]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/tunnel.go#L247-L254
[R8]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/tcp.go#L311-L326
[R9]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/udp.go#L292-L297
[R10]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/dns53/dot.go#L174-L218
[R11]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/doh/doh.go#L424-L449
[R12]: https://github.com/celzero/firestack/blob/75cfc671860f60fe9dad9003eb63744f4371e518/intra/dnsx/transport.go#L670-L785
