# VPN/TUN Packet Capture Adapter 调查报告

日期：2026-06-21
状态：调查报告 / 讨论输入。本文不是 ADR，也不是实现任务列表。

## 1. 问题

我们需要确认 Sakamoto Snort 是否能在当前 root/NFQUEUE 模式之外，继续支持非 root 的 Android VPN/TUN 模式。

这个问题不只是“ TUN 能不能给我们包”。它能。真正的问题是：

- NFQUEUE 与 TUN 是否能共用同一套 L3/L4 parser 和未来的 `PacketFacts` pipeline？
- NFQUEUE 当前提供了哪些 metadata，未来还能提供哪些 metadata？
- TUN 模式缺哪些 metadata，尤其是 complete Linux UID 和 observed interface？
- HEV/tun2socks 这类转发引擎应该放在 policy/drop/log 的哪一侧？
- SNORT-12 在长出 packet path 之前，哪些边界必须先改成 Adapter 中立？

## 2. 简短结论

parser 方向是可行的：当前 root NFQUEUE 的 INPUT/OUTPUT 包和 Android VPN/TUN 包都是 L3 IP 包，不是 Ethernet frame。共享 bounded IP packet parser 是合理的。

真正困难的是 metadata，不是解析。

NFQUEUE 在配置为 packet copy 时，可以携带 packet id、hook、UID/GID、ifindex、mark、timestamp、payload length/capture length 和 packet bytes。TUN 包本身没有这些 NFQUEUE 风格 metadata。Android VPN 模式里，TUN FD 给的是 IP 包；UID 归因必须由 Snort 的 platform-specific attribution provider 从 socket ownership / connection ownership 反查。

正确架构应该是：

- 具体 packet capture Adapters：`NFQUEUE Adapter`，未来的 `TUN Adapter`；
- 一个共享的 PacketFacts builder：输入是 `Adapter metadata + bounded L3 packet prefix`；
- 一个共享 packet processor / verdict pipeline，只消费 PacketFacts；
- Adapter-specific egress/verdict：NFQUEUE 发送 `NF_ACCEPT` / `NF_DROP`；TUN 模式按 drop、forward 或 reinject 处理；
- VPN owner 继续拥有 VPN/TUN 创建、route、`protect()`、app allow/disallow list 和生命周期；以 VPN mode 启动的 Snort 接收外部提供的 `tun-fd`。
- UID attribution 属于 Snort 的 packet input/facts 构造职责；Android 环境通过 JNI 调 Java framework API，Linux 环境通过 socket ownership 查询。

不要把 TUN/VPN 分支塞进 IPRULES、Conntrack、Traffic Windows、Flow Telemetry 或 ControlServer。

## 3. 当前 Active Code 事实

当前 active `src/` 是 pre-SNORT-12。它启动 dual-stack NFQUEUE pass-through runtime 和 vNext control server，但还没有完整 packet pipeline。

- 当前 roadmap 说明 active `src/` 只保留 pre-SNORT-12 daemon/control/NFQUEUE pass-through base；SNORT-12 才开始 bounded copy、PacketFacts、parser status 和 packet processor seam。
  见 `docs/IMPLEMENTATION_ROADMAP.md`。
- 当前 base 只支持 `HELLO`、`RESETALL`、`QUIT` 和 pass-through hook readiness。
  见 `docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md`。
- active runtime 目前配置 NFQUEUE 为 metadata-only：
  `src/datapath/nfqueue/NfqueuePassThroughRuntime.cpp` 使用 `NFQNL_COPY_META, 0`。
- active callback 只读取 `NFQA_PACKET_HDR`，取 `packet_id` 和 `hook`，然后 fail-open accept。
- 当前 active code 不读取 `NFQA_PAYLOAD`、`NFQA_UID`、`NFQA_IFINDEX_*`、mark、timestamp 或 GSO/capture-length metadata。

所以当前 active code 不能当作完整 parser/policy 参考。它只是 base runtime readiness slice。

## 4. 历史代码证据

归档的 current-head 实现有参考价值，但不能作为 active compatibility layer 恢复。

它以前做过：

- 配置 `NFQNL_COPY_PACKET`；
- 启用 `NFQA_CFG_F_UID_GID`；
- 读取 `NFQA_PAYLOAD`；
- 读取 `NFQA_UID`；
- 读取 `NFQA_IFINDEX_INDEV` / `NFQA_IFINDEX_OUTDEV`；
- 从 NFQUEUE hook 推导 direction；
- 解析 IPv4/IPv6 L3/L4；
- 把事实传给 `PacketManager::make`。

这说明 root/NFQUEUE 模式现实上可以提供哪些 metadata。但它不定义新的 SNORT-12 架构。

## 5. 外部平台事实

Android `VpnService.Builder.establish()` 会创建 VPN interface 并返回 file descriptor。Android 文档说明这个 interface 工作在 IP packet 层：read 读到被 route 到该 interface 的 outgoing packet；write 会把 packet 注入系统，看起来像从该 interface 收到的 incoming packet。

Linux TUN 也工作在 network layer。Kernel 文档区分 TUN 和 TAP：TUN read/write IP packets，TAP read/write Ethernet frames。如果启用了 packet-information header，raw protocol frame 前面可能有一个小的 PI header；Android `VpnService` 暴露的是 IP-packet level 的 VPN interface FD。

HEV `hev-socks5-tunnel` 是 tun2socks engine。它的公开 API 可以从 config 和 `tun_fd` 启动，README 也描述了 Android VPN 用例。这说明它可能适合作为 egress engine，但不能自动等价于 policy interception point。

Android `ConnectivityManager.getConnectionOwnerUid()` 可以返回 active VPN app tunnel 中 TCP/UDP connection 的 UID owner。它当前支持 TCP 和 UDP。找不到 connection、权限/可见性不足时可能返回 invalid UID。它不是 ICMP、fragment、非 TCP/UDP、或 connection ownership 尚未可见的早期包的通用 per-packet UID 字段。

重要外部参考：

- Android `VpnService.Builder.establish()`：https://developer.android.com/reference/android/net/VpnService.Builder#establish()
- Android `VpnService.protect()`：https://developer.android.com/reference/android/net/VpnService#protect(int)
- Android `ConnectivityManager.getConnectionOwnerUid()`：https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress)
- Linux TUN/TAP docs：https://docs.kernel.org/networking/tuntap.html
- libnetfilter_queue queue mode and flags：https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html
- HEV socks5 tunnel README/API：https://github.com/heiher/hev-socks5-tunnel

### 5.1 UID attribution 深挖

结论：TUN FD 本身没有“这个 packet 属于哪个 UID”的字段。可用路径不是从 FD 读 metadata，而是 Snort 从 packet 解析出 TCP/UDP tuple 后调用平台 UID attribution provider 反查 owner UID。Android 环境下 provider 通过 JNI 调 `ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)`；Linux 环境下 provider 可通过 socket ownership 查询获取 socket UID。Android 接口的输入形状是 `protocol + local InetSocketAddress + remote InetSocketAddress`，也就是逻辑上的 5-tuple：transport protocol、local IP、local port、remote IP、remote port；其中 IP family 由 `InetAddress` 类型隐含，不额外传 interface 或 direction。

官方 API 约束很关键：

- API 从 Android 10 / API 29 开始提供。
- `protocol` 当前只支持 TCP 和 UDP。
- `local` / `remote` 必须是 connection 的 local / remote `InetSocketAddress`。
- 找到 connection 且调用者有权限观察时返回 UID。
- 找不到 connection 时返回 `Process.INVALID_UID`。
- 调用者不是当前 user 的 active `VpnService` 时抛 `SecurityException`。
- 请求不支持的 protocol 会抛 `IllegalArgumentException`。

本地 Android / Lineage 源码和 CTS 进一步确认：

- `VpnService` FD 的契约只是 IP packet FD：read 得到 routed outgoing packet，write 注入 incoming packet；packet 从 IP header 开始，没有 per-packet UID metadata。
- `ConnectivityService.getConnectionOwnerUid()` 最终先按 TCP/UDP tuple 查 socket owner，再做可见性过滤。
- 底层实现走 `InetDiagMessage.getConnectionOwnerUid()`，即用 inet_diag/netlink 按 local/remote address/port + protocol 查询 socket UID；这进一步说明 UID 来源是 socket attribution，不是 TUN metadata。
- 非 NetworkStack 调用者只有在“该 UID 的流量正经过调用者自己的 `VpnService` VPN”时才能看到 owner UID。
- Platform VPN、wrong user、非当前 VPN service owner 等场景会返回 `INVALID_UID`，不是返回真实 UID。
- CTS 同时覆盖 TCP 和 UDP 查询；UDP 测试使用 connected `DatagramSocket`，所以不能直接推导所有无连接 UDP packet 都稳定可归因。
- CTS 还有多线程查询测试，说明 API 设计上允许并发调用；但这不等于可以把 binder 查询放进 native per-packet hot path。

因此，VPN/TUN 模式下需要 Snort 内部的 `UidAttributionProvider`，按平台选择后端，但它只能是 best-effort：

1. 对 outbound TCP/UDP 包：
   - 从 TUN packet 解析 IP + L4。
   - `local = srcIP:srcPort`。
   - `remote = dstIP:dstPort`。
   - Android backend 调 `getConnectionOwnerUid(proto, local, remote)`；Linux backend 做 socket ownership 查询。
   - 返回有效 UID 时写入 `{uidKnown=true, uid}`。

2. 对 inbound TCP/UDP response：
   - 如果 packet 方向已经是 inbound，需要用 connection 视角反转。
   - `local = dstIP:dstPort`。
   - `remote = srcIP:srcPort`。
   - 更推荐从已有 flow attribution cache 里查 UID，而不是每个 response 都反查系统。

3. 对 ICMP / ESP / other protocol：
   - 官方 API 不支持。
   - 不能伪造 UID。
   - 只能 `{uidKnown=false}`，或依赖已有 flow 的派生归因，但这必须带来源标记。

4. 对 fragment：
   - 非首片没有 ports，不能构造 TCP/UDP socket tuple。
   - 首片即使能看到 L4，也不应让后续 fragment 每包调用系统 API。
   - 第一版建议 fragment 归因 unknown，或只在已有 flow cache 命中时继承 UID。

5. 对 UDP：
   - API 支持 UDP，但 UDP connection ownership 是否稳定取决于系统能否按 local/remote 找到对应 socket/connection。
   - DNS、QUIC、普通 UDP 都要真机验证。
   - 对无连接 UDP，不能假设每个 packet 都能成功归因。

6. 对 TCP early / late packet：
   - SYN 理论上已有 socket tuple，但仍可能因为 race 或系统状态返回 invalid UID。
   - FIN/RST 或 close 后 late packet 也可能查不到。
   - 所以需要 flow-level attribution cache：首个成功归因的 tuple 绑定 UID，后续同 flow 优先走 cache。

hot path 设计建议：

- 不要在 native packet hot path 里同步 binder 调 `getConnectionOwnerUid()`。
- Android 官方稳定入口是 Java framework API `ConnectivityManager.getConnectionOwnerUid()`，不是 NDK C/C++ API。
- Snort C++ 可以通过 JNI 调这个 Java API，前提是 native runtime 在持有当前 `VpnService` 的 Android app 进程/环境里运行，或由 Android owner 注入可用的 Java bridge / `Context` / `ConnectivityManager` 引用。
- 更清晰的边界是：Snort 拥有 `UidAttributionProvider` 抽象；Android backend 通过 JNI 调 Java framework，Linux backend 通过 socket ownership 查询。
- Android 非 root VPN mode 不建议让 C++ 绕过 framework 直接走 inet_diag/netlink 复刻系统实现；它不享受 SDK/NDK 稳定性，也可能被 SELinux、权限、multi-user/VPN 可见性规则卡住。
- Snort 的 attribution worker 负责 UID 查询。
- TUN Adapter 看到 TCP/UDP 新 flow 时，可以先走小型 cache；miss 时交给 Snort-owned attribution provider。
- 第一版为了简单，可以在 TUN Adapter 线程同步查询，但必须把它当作 prototype / measurement item，不能默认进入长期 hot path。
- cache key 必须包含 family、protocol、local endpoint、remote endpoint 和 direction normalization 后的 connection tuple。
- cache value 必须是 `{uidKnown, uid, source}`，source 例如 `android-connection-owner`、`cache`、`unknown`。
- `uidKnown=false` 必须是一等状态：不能用 VPN app UID、root UID、appId 或 package guess 替代。

### 5.2 UID metadata 注入、有效期和 zero-copy 约束

为了和当前 packet pipeline 融合，VPN/TUN Adapter 不应把 UID 查询做成“每包都问 Android”。更合适的形状是：

1. TUN Adapter 从 FD 读入 packet 到 native buffer pool。
2. Parser 只在 buffer view 上解析 IP/L4 header，生成 `FlowKey` 和基础 `PacketFacts`。
3. `UidAttributionCache` 用 normalized `FlowKey` 查询 `{uidKnown, uid, source, generation, expiresAt}`。
4. cache hit 时，把 UID 作为 sidecar metadata 注入本次 packet 的 `PacketFacts`。
5. cache miss 时，调用 Snort-owned `UidAttributionProvider`，用 `protocol + local endpoint + remote endpoint` 查询 UID。
6. 查询结果写回 flow cache，再注入当前 packet 的 `PacketFacts`。
7. 规则引擎只消费 `PacketFacts`，不关心 UID 来自 NFQUEUE metadata 还是 Android socket attribution。

这里的“注入”不是改 packet bytes，也不是给 packet prepend 自定义 header，而是在进入 policy / telemetry / CT 前形成一个 `PacketEnvelope`：

- `packetView`：指向 native buffer 的只读 view。
- `facts`：Adapter-neutral metadata，包括 `uidKnown`、`uid`、`direction`、`family`、L3/L4 facts。
- `adapterHandle`：Adapter-specific handle，例如 NFQUEUE packet id 或 TUN buffer handle。

有效期不能只靠一个固定 TTL，需要按协议分层：

- TCP attribution：首个成功归因的 flow 绑定 UID；看到 FIN/RST 后进入短 grace，再删除；没有看到关闭事件时按 idle timeout 回收。
- UDP attribution：按 idle timeout 回收；DNS、QUIC、普通 UDP 要分场景实测，不能假设永久稳定。
- negative result：`INVALID_UID` 只能做很短的 negative cache，避免 TCP early packet race 被长期缓存成 unknown。
- fragment：只有已有 flow cache 命中时继承 UID；否则 `uidKnown=false`。
- generation：VPN service restart、native runtime reinit、app allow/disallow list 改变、profile/user 改变、network topology 改变时递增 generation 或清空 cache，旧 attribution 不能继续复用。

zero-copy 目标需要说清楚边界：

- TUN FD read 到用户态 buffer 的一次 copy 无法避免。
- 用户态内部应避免 packet payload 再复制：parser、policy、telemetry、egress 都拿 `packetView` / span。
- JNI UID 查询只传 tuple 标量和地址对象，不传 packet byte array。
- metadata 使用 sidecar struct，不改 packet buffer。
- cache miss 时第一版不等待 UID：当前 packet 标记 `uidKnown=false`，per-app action 不命中，直接 fail-open/forward。
- 如果 CT 开启，cache-miss packet 仍可进入 CT；CT flow identity 不因 UID unknown 而拆成另一套 key。
- UID 查询在旁路 warm cache；后续 packet 进来时如果 cache 已经命中，再把 UID 注入 `PacketFacts`，per-app policy / subject-scoped caps 才能生效。
- cache-miss 第一包可能绕过 per-app block，这是明确的产品语义，用来换取 packet path 不等待 JNI/binder 查询。

对产品能力的影响：

- 若 UID 归因成功，VPN/TUN mode 可以进入 per-app IPRULES、Traffic Windows、Flow Telemetry、CT。
- 若 UID 归因失败，per-app policy 应 no-match/fail-open；Traffic Windows 不能计入某个 app；Flow Telemetry 可输出 `uidKnown=false`；CT 可以继续维护 L4 flow/session state，但不能把未知 UID 伪造成某个 app subject。
- 如果我们想承诺 VPN mode 下完整 per-app policy，就必须先做真机矩阵验证：TCP、UDP、QUIC/DNS、ICMP、fragment、IPv6、multi-user/profile、app allow/disallow list、VPN app 自身 protected sockets。

## 6. Metadata 矩阵

| Fact | NFQUEUE/root mode | VPN/TUN mode | 兼容影响 |
|---|---|---|---|
| L3 packet bytes | 使用 bounded `NFQNL_COPY_PACKET` 时可获得；active base 当前不 copy | 从 TUN FD read 获得 | parser 可共享 |
| L2/Ethernet header | INPUT/OUTPUT NFQUEUE IP path 里不应出现 | TUN 没有 | PacketFacts 不应围绕 L2 设计 |
| Packet family | listener family 或 IP header | IP header | 可共享 |
| Direction | NFQUEUE hook，目前是 `LOCAL_IN` / `LOCAL_OUT` | TUN read path 表示 outgoing；write/inbound path 取决于 egress engine | 归一化成 `packetDirection`，不要用 `nfqueueHook` 表达 |
| UID | 启用且可用时来自 `NFQA_UID` | packet 自身不带；需要 Android attribution provider，例如可用时的 `getConnectionOwnerUid()` | 必须保留 `uidKnown`；不能伪造 |
| userId | 从 complete Linux UID 派生 | 从归因 UID 派生 | 取决于 UID 是否可用 |
| ifindex | 可来自 `NFQA_IFINDEX_*` | 可知道 logical TUN ifindex；underlay wifi/mobile 不是 packet fact | 只记录 observed iface |
| ifaceKind | 从 observed ifindex 派生 | 通常是 TUN logical interface 的 `vpn` | 不推断 underlay |
| packet id | NFQUEUE verdict handle | 无 | Adapter-specific transport handle，不进 PacketFacts |
| verdict operation | 按 packet id 发送 `NF_ACCEPT` / `NF_DROP` | 按 egress 设计 drop、forward 或 inject/write | VerdictSink 必须 Adapter-specific |
| mark / skb info / cap len | NFQUEUE-specific attrs | 没有 NFQUEUE attrs | 只做 diagnostics |
| timestamp | NFQUEUE attr 或 daemon clock fallback | daemon clock fallback | 可共享，但需要来源/known 语义 |
| queue id / worker id | NFQUEUE diagnostics | TUN worker diagnostics 另算 | 只做 diagnostics |
| nfqueueHook | NFQUEUE diagnostics | 不适用 | common diagnostic packet shape 不能强依赖它 |

## 7. 现有 Downstream 需要什么

未来 packet-side pipeline 已经假设 `PacketFacts` 是共享输入。

规划中的 `PacketFacts` 字段包括：

- `uid / uidKnown`；
- `family`；
- `direction`；
- `src/dst IP`；
- `remote IP`；
- `proto / l4Status / portsAvailable`；
- `src/dst port`；
- `ifindex / ifaceKind`；
- `original IP packet bytes`；
- `timestamp`。

下游影响：

- Basic IPRULES 需要 UID subject、family、direction、iface/ifindex、proto、address 和 ports。
- Stateful IPRULES 需要稳定 flow identity 和可用的 subject attribution。Conntrack flow identity 不包含 UID；complete Linux UID 属于 PacketFacts/session attribution，用于 subject caps 与 policy stage。
- Traffic Windows 需要 complete Linux UID、direction、最终 verdict 和 original IP bytes。
- Flow Telemetry 输出 UID/userId、direction、ifindex/iface known flags、verdict/reason/rule attribution，以及可用时的 CT facts。
- Packet Diagnostics 需要 packet facts 加 Adapter diagnostics。当前 interface 示例里有 `nfqueueHook`，但如果支持 TUN mode，它必须变成 Adapter-specific 或 optional。
- DNS/domain association 仍然是独立模块。Flow records 不应携带 domain hint 或 DNS/IP join。

所以，TUN 模式不能简单说“所有包都属于 VPN app”，除非我们明确放弃该模式下的 per-app policy 和 per-app telemetry。

## 8. 必须新增的边界

### 8.1 Packet Capture Adapter

在 datapath 下增加 Adapter 边界。它负责 capture-mode 细节，并产出 normalized packet input。

可能的 concrete Adapters：

- NFQUEUE Adapter：queue setup、netlink recv、NFQUEUE attrs、verdict packet id。
- TUN Adapter：TUN FD read/write lifecycle、外部 `tun-fd` handoff、egress integration、TUN-specific metadata。

common packet processor 不应该知道 netlink attrs、TUN FDs、iptables chains 或 HEV API 细节。

### 8.2 PacketFacts Builder

builder 输入应该是：

- bounded L3 packet prefix；
- 可靠时的 original packet length；
- normalized Adapter metadata；
- parse budget 和 parser result。

输出应该是 stack-only `PacketFacts`，或者 fail-open / no-facts result。

### 8.3 Verdict / Egress Sink

NFQUEUE verdict 很简单：按 packet id accept 或 drop。

TUN verdict 不是同一个 primitive：

- block/drop：不转发 outbound packet；
- allow：通过 HEV/tun2socks 或其它 egress path forward；
- inbound response：通过 TUN FD 或等价路径 inject 回系统；
- observe/log：记录 attribution，但仍然 forward。

所以 shared pipeline 应该返回 logical verdict；每个 Adapter 自己负责怎么执行这个 verdict。

### 8.4 VPN owner 与 Snort 边界

VPN owner / Android frontend service layer 应该拥有：

- `VpnService` lifecycle 和用户授权；
- TUN `ParcelFileDescriptor`；
- routes 和 DNS config；
- app allow/disallow lists；
- tunnel/egress sockets 的 `protect()`；
- 向以 VPN mode 启动的 Snort handoff `tun-fd`；
- lifecycle restart 和 shutdown。

Snort 不自行创建 Android VPN state，也不自行通过 Android API establish VPN FD。Snort 的职责是消费外部提供的 `tun-fd`，执行 TUN Adapter、PacketFacts、CT、policy、telemetry、egress integration 和 UID attribution。

### 8.5 Attribution Provider

TUN mode 需要 Snort 内部有一个明确的 attribution provider。

对 TCP/UDP 来说，provider 按平台选择实现：

- Android backend：通过 JNI 调 Java framework `ConnectivityManager.getConnectionOwnerUid()`。
- Linux backend：通过 socket ownership 查询获取 socket UID。

Android backend 有边界：

- 只支持 TCP/UDP；
- 需要 active VPN service 权限；
- 可能返回 invalid UID；
- 如果每包调用，hot path 成本可能太高，需要缓存；
- 早期包、fragments、ICMP、ESP 和 malformed packets 可能无法归因。

输出必须是 `{uidKnown, uid}`。归因未知时就保持 unknown。

## 9. HEV / tun2socks 放置位置

HEV 可以解决 egress forwarding，但不是自动解决 packet policy。

如果我们把 TUN FD 直接交给 HEV 独占，HEV 就成了 packet owner。除非 HEV 暴露合适的 callback/filter API，或者我们用某种方式包住 FD 让 daemon 在 HEV 之前看到 packet，否则 Sakamoto 没法逐包 inspect/drop/log。

可能的集成形态：

1. HEV 直接拥有 TUN FD。
   - forwarding 最简单。
   - 对 policy inspection 不友好，除非 HEV 有合适 hook。

2. Sakamoto 拥有 TUN FD，先 parse/verdict，再把 allowed packets 交给 egress engine。
   - policy 语义正确。
   - 需要明确如何把 allowed packets 喂给 HEV，或实现等价 forwarding。

3. 双 FD 或 virtual queue 设计。
   - 更灵活。
   - 必须先 prototype 证明，因为很容易变复杂。

调查建议：不要默认 HEV 解决整个 datapath。先证明 HEV 能不能作为 Sakamoto verdict 之后的 egress engine；如果它的 API 迫使它先独占 TUN FD，那这条路要重新评估。

## 10. Failure / Degradation 规则

第一版安全规则：

- 如果 IP envelope 不能解析，fail-open accept/forward，不更新普通 policy 或 traffic counters。
- 如果 UID unknown，不要把包当成 root、VPN app 或 appId 来套 per-app policy。per-app policy 应 no-match/fail-open；如果未来有明确 device-scope rules，可以只应用 device-scope rules。
- 如果 ifindex unknown，`ifindex`-specific rules 不匹配。`ifaceKind` rules 只有在 observed logical interface 已知时才匹配。
- VPN/TUN mode 下，observed iface 通常是 VPN logical interface。不要在 packet facts 里推断 underlay wifi/mobile。
- 不要双重统计 inner app packets 和 outer VPN transport packets。VPN app 自己的 upstream sockets 必须 `protect()`，或用其它方式排除，避免又被 route 回同一个 TUN path。
- Adapter-specific diagnostics 可以记录 NFQUEUE hook/queue 或 TUN FD/session，但 common PacketFacts 不能依赖这些字段。

## 11. Interface / Documentation 影响

后续可能需要同步：

- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md`
  - 把 PacketFacts 来源从 NFQUEUE-only 改成 Adapter metadata + bounded L3 prefix。
  - 保留 NFQUEUE-specific section，但不要让 NFQUEUE 成为唯一 packet input model。

- `docs/INTERFACE_SPECIFICATION.md`
  - `diagnostic.packet.packet.nfqueueHook` 应变成 Adapter-specific 或 optional。
  - 只有在前端/debug 真需要时，才增加 `adapter.kind` / `captureMode`。
  - 保留 `uidKnown` 和 `ifindexKnown` flags。

- `CONTEXT.md`
  - 本轮讨论已把 `PacketFacts` 更新为通过 active packet capture Adapter metadata 定义，而不是 NFQUEUE-only metadata。
  - 已新增 canonical term：`Packet capture Adapter`。

## 12. 适配报告

Parser 兼容性：高。

NFQUEUE INPUT/OUTPUT 和 Android TUN 都提供 L3 IP packet input。parser 应共享。

Policy 兼容性：中，取决于 UID attribution。

IPRULES 是 per complete Linux UID。若 TUN mode 不能可靠恢复 UID，该 packet 的 per-app policy 会 degraded 或不可用。只支持 device-scope policy 的 VPN mode 是可能的，但这是产品/架构决策。

Interface 兼容性：中。

TUN mode 下 observed interface 是 VPN logical interface，不是 underlay wifi/mobile。现有 docs 已经说 underlay attribution 后置，这是好的。匹配 `iface=vpn` 的规则可以有意义；期望匹配物理 underlay interface 的规则，不能从 TUN packet facts 诚实支持。

Telemetry 兼容性：中。

Flow Telemetry 仍可以从 PacketFacts 报 flow，但 UID 和 ifindex known flags 更重要。`uidKnown=false` 和 `ifindexKnown=false` 必须是一等状态。

CT 兼容性：有条件。

CT 模型本身可以在 VPN/TUN mode 下工作，因为 CT flow identity 来自 L3/L4 flow，而不是 UID。UID attribution 影响的是 subject-scoped CT acquisition gate、Stateful IPRULES 是否可评估，以及 telemetry/policy attribution 是否能归到具体 app。

HEV 兼容性：未知。

HEV 已证明可以作为 tun2socks engine，并接受 TUN FD。但还没证明它可以放在 Sakamoto verdict 之后，而不是先独占 TUN FD。

## 13. 建议优先决策

1. SNORT-12 packet foundation 从一开始围绕 Adapter-neutral `PacketFacts` 定义。
2. root NFQUEUE mode 和 non-root VPN/TUN mode 作为 startup/runtime capture modes；不要做同一 daemon 实例里的热切换。
3. 明确要求 `{uidKnown, uid}` metadata。unknown UID 是支持的 degraded state，不是猜一个 UID。
4. TUN/HEV forwarding 留在 Adapter egress 边界外侧，不进入 IPRULES/CT/Telemetry。
5. 在承诺完整 VPN mode 前，先 prototype UID attribution 和 HEV placement。

## 14. 已收口问题

SNORT-12 是否从一开始就把 packet foundation 定义成 Adapter-neutral：`PacketFacts = PacketCaptureMetadata + bounded L3 packet prefix`，即使第一版只接 NFQUEUE Adapter？

结论：是。

原因：现在 PacketFacts 还没完全实现，调整成本很低；这样能防止 hook、queue、packet id、iptables chain 这些 NFQUEUE-only 名称泄漏进 IPRULES、CT、Traffic Windows 和 diagnostics。它不要求我们马上实现 TUN；只是让 shared packet processor 在 TUN mode 准备好时可以复用。

本轮还收口了两个 VPN/TUN UID 语义：

- UID 不是 TUN FD metadata，而是 socket attribution。Snort 拥有 platform-specific `UidAttributionProvider`；Android backend 通过 JNI 调 Java framework API `ConnectivityManager.getConnectionOwnerUid()`，Linux backend 通过 socket ownership 查询。
- UID cache miss 时第一版不等待查询结果。当前 packet `uidKnown=false`，per-app action no-match / fail-open；如果 CT 开启，仍可进入全局 CT A++ flow/session；旁路 warm cache 后，后续包再注入 UID。

## 15. 剩余问题评估

### 15.1 unknown UID 与 CT acquisition 的关系

当前决策允许 cache-miss packet 先进 CT；同时已确认 CT 是跨 worker 的全局 A++ table，flow identity 不包含 UID。UID 是 packet/session attribution 与 subject-scoped policy/caps 输入，不是 CT key 的一部分。

结论：

- VPN/TUN 模式下，如果当前 packet `uidKnown=false`，且 CT 已开启，则该 packet 直接进入全局 CT A++ flow/session 更新。
- CT 更新后，该 packet 直接放行。
- 当前 packet 不执行 per-app Basic/Stateful IPRULES action，因为没有 complete Linux UID subject。
- 后续 packet 若 UID attribution cache 命中，则用同一个 CT entry 产出的 `CtFacts`，再结合 complete Linux UID 做 subject caps 与 Stateful IPRULES。

边界：

- 这不是普通 NFQUEUE mode 的无条件全局 CT；它只定义 VPN/TUN `uidKnown=false` 降级路径。
- CT entry 不因 UID unknown 拆分，也不需要 rekey/promote。
- `uidKnown=false` 的包不能被统计到某个 app，也不能产生 per-app rule hit attribution。

### 15.2 TUN egress / HEV 放置

TUN allow 不是 NFQUEUE accept。TUN read 得到的是 app outbound IP packet；允许它继续走网络，需要 tun2socks、userspace TCP/IP stack、SOCKS egress 或其它 forwarding engine。

结论：

- HEV 不拥有 TUN FD。
- Sakamoto / TUN Adapter 从 TUN FD 收包。
- 每个 outbound packet 先进入 Sakamoto packet processing path。
- packet path 产出 allow/drop/log/observe 结果。
- 只有 allow/forward 的 packet 才交给 HEV 或等价 egress engine。
- HEV 的回包也不能直接写回 TUN；必须先进入 Sakamoto packet processing path，再由 TUN sink 写回 TUN FD。

这个决策让 Sakamoto 保持真正的 policy interception point，而不是 HEV 旁边的 observer。后续 prototype 需要证明的是 HEV 能不能以这种方式接收 allowed packet 并交回 inbound response；如果 HEV API 不能支持，就需要 egress adapter 或替代 engine，而不是让 HEV 反向拥有 TUN FD。

### 15.3 bidirectional packet visibility

Android `VpnService` FD 的 read 是 outgoing，write 是 incoming injection。一个完整 packet pipeline 需要明确 outbound 和 inbound 是否都经过 Sakamoto。

结论：

- outbound：TUN FD -> TUN Adapter -> PacketEnvelope -> PacketFacts / CT / policy / telemetry -> HEV egress or drop。
- inbound：HEV response -> PacketEnvelope -> PacketFacts / CT / policy / telemetry -> TUN sink write/inject or drop。
- outbound 和 inbound 都必须经过 shared packet processor。

TUN Adapter 的 contract 因此需要两个入口：`read outbound from TUN` 和 `receive inbound from egress before write-to-TUN`。两者都构造 `PacketEnvelope`，走同一 PacketFacts / CT / telemetry path，再由 Adapter-specific sink 执行 forward、drop 或 write injection。

### 15.4 VPN owner 与 Snort native 边界

VPN mode 不是 Snort 单独能创建 VPN 的模式。Android app / foreground service / `VpnService` 拥有授权、TUN FD 创建、route、app allow/disallow list、`protect()` 和 lifecycle；以 VPN mode 启动的 Snort 需要外部提供可用 `tun-fd`。

结论：

- Snort 不自行创建 VPN，也不自行 establish TUN FD。
- Snort 以 VPN mode 启动时必须拿到外部 owner 提供的 `tun-fd`。
- UID attribution 属于 Snort 职责：Android 环境下 Snort provider 通过 JNI 调 Java framework；Linux 环境下 Snort provider 通过 socket ownership 查询。
- 外部 owner 仍负责 VPN lifecycle、route、app allow/disallow list、`protect()` 和 Snort runtime lifecycle。

边界：native control plane 不应表达“由 Snort 创建 VPN”。它只能报告 VPN-mode adapter 是否拿到了可用 `tun-fd`、UID attribution provider 是否可用、egress/protect bridge 是否可用，以及当前 runtime health。

### 15.5 failure / health reporting

`packet-pass-through` 是 runtime capability，不应写死 NFQUEUE。VPN mode 会有不同失败点：缺少或无效 `tun-fd`、UID attribution provider 不可用、JNI bridge 不可用、egress engine 不可用、protect bridge 不可用、外部 VPN owner lifecycle 中断。

推荐方向：HELLO 仍只暴露可用 capability，例如 `packet-pass-through`；具体失败进入 Runtime health reason code，并允许 Adapter-specific reason。

### 15.6 interface 和 diagnostics

Common `PacketFacts` 不能包含 `nfqueueHook`、queue id、TUN fd id 或 HEV session id。它们只能作为 Adapter diagnostics。

推荐方向：diagnostic packet schema 增加 `adapter.kind` 和可选 `adapter.details`，但 policy / CT / telemetry 不依赖它。

### 15.7 prototype 验证矩阵

在承诺完整 VPN mode 前，至少要验证：

- Android UID attribution：TCP、UDP、connected UDP、DNS、QUIC、ICMP、fragment、IPv6、multi-user/profile。
- cache miss 语义：第一包 fail-open、后续 cache hit、negative cache TTL、VPN restart generation。
- HEV placement：Sakamoto 是否能在 HEV 前 inspect/drop/log；inbound response 是否能回到 Sakamoto。
- `protect()`：egress sockets 不回流 TUN，不双重统计 VPN app outer sockets。
- zero-copy：packet bytes 只在 TUN read/write 与必要 egress 边界复制，JNI 不传 packet byte array。
