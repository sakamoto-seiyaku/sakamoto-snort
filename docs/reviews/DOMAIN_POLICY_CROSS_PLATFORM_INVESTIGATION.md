# 跨平台域名策略调查

## 背景

当前包处理链路逐步从 Android/root NFQUEUE 扩展到 Android VPN/TUN、Linux、以及可能的 macOS。域名策略不能只靠包内信息天然得到：L3/L4 包里没有域名，TLS SNI/HTTP Host 也不总是可见，并且 DoH/DoT/QUIC/ECH 会继续降低可见性。

本调查回答一个核心问题：

> 在不同平台上，如果我们能拿到整机或应用的包流，应该如何把“域名规则”映射到连接/包动作？

## 当前初步判断

域名策略通常不是在每个数据包上“临时查域名”，而是依赖以下几类路径：

1. 控制 DNS：把系统 DNS 指向本地/受控 resolver，在 DNS 查询时做域名规则判断。
2. DNS 结果注入元数据：把 `domain -> resolved IP -> TTL -> client/app/uid` 记录下来，后续连接命中时关联。
3. 系统 flow 元数据：在支持的平台，用 OS API 拿到 app/uid/hostname/flow 信息。
4. 明文协议提示：HTTP Host、TLS SNI、QUIC Initial 中可见字段可作为补充，不应作为唯一基础。
5. IP 集合落地：Linux/路由器常把域名解析结果写入 `ipset`/`nftset`，再由防火墙执行。
6. 加密 DNS 治理：如果应用绕过系统 DNS，域名策略会失效或降级到 IP/行为策略，因此常见产品会阻断/接管外部 DNS。

## 推荐架构边界

域名能力不应该做成 packet path 里的同步查询，也不应该假设一个 L3/L4 flow 天然有唯一域名。推荐把系统拆成三层：

```text
Domain Observation Plane
  DNS proxy / DNS monitor / OS DNS extension / SNI parser
  -> domain observation event

Flow Metadata Plane
  CT/session table + UID/app/client attribution + TTL cache
  -> flow metadata enrichment

Packet Enforcement Plane
  NFQUEUE / VPN-TUN / VPP / Network Extension / nftables
  -> allow / block / log / mark / route
```

`Domain Observation Plane` 负责产生事实或候选事实：

- DNS 查询：`qname, qtype, answer rrset, ttl, resolver, client/app/uid/process`。
- OS flow metadata：`uid/package`、`audit token/process`、`remoteHostname`。
- TLS/QUIC 可见字段：SNI/QUIC Initial hostname，只作为补充。
- 手工 IP/网段规则：不伪装成域名规则。

`Flow Metadata Plane` 负责把观察结果注入 session：

- key 可以是五元组、conntrack id、client IP/MAC/VLAN、UID、socket cookie 或平台 flow id。
- 域名关联必须带来源和置信度，例如 `dns-derived`、`os-hostname`、`sni-derived`、`manual-ip`、`unknown`。
- DNS TTL、CNAME、IPv4/IPv6、共享 IP、CDN、连接复用都必须进模型，不能把 `IP -> domain` 写死成确定事实。

`Packet Enforcement Plane` 只做执行：

- 对已知 block domain，优先在 DNS 层返回阻断结果。
- 对已有 CT/session 元数据的连接，在包路径执行 allow/block/log。
- 对未知域名连接，不要在热路径里反查 DNS；可按 IP/策略默认值处理，并异步补充观测。
- 对 DoH/DoT/DoQ/ECH，应明确降级为“域名不可见”或单独策略化加密 DNS resolver。

## 不推荐路线

- 不推荐把 SNI/QUIC 解析当成域名策略主路径。ECH、QUIC、代理、连接复用都会破坏可靠性。
- 不推荐用反向 DNS 做 enforcement。PTR 不是用户访问的 FQDN。
- 不推荐在包处理线程里同步 DNS 查询。会引入阻塞、递归、污染和竞态。
- 不推荐把 `domain -> IP` 映射当成全局永久事实。必须有 TTL、来源、client/app 维度和失效机制。
- 不推荐为了 URL/path 级规则默认做 HTTPS MITM。平台限制、证书固定和隐私成本都很高。

## 后续设计问题

- Android VPN 模式下，UID 查询失败时的策略：默认放行、默认阻断、还是只记录 unknown。
- DNS 观察事件和 CT/session 表之间的注入 API：同步注入还是异步队列。
- 多 worker 场景下，domain metadata 如何跨 worker 共享并避免锁竞争。
- `allowlist` 是否要求 hostname 二次确认，避免共享 CDN IP 误放行。
- DoH/DoT/DoQ 的默认产品策略：提示、阻断、只记录、还是引导走本地 DNS proxy 的 encrypted upstream。
- 路由器场景是否区分设备/VLAN profile，而不是尝试追踪远端应用 UID。

## 工程模式对照

| 模式 | 核心做法 | 准确性 | 侵入性 | 适配口径 |
| --- | --- | --- | --- | --- |
| DNS 代理/本地 resolver | 接管 DNS，DNS 阶段做 allow/block，并记录 answer/TTL | DNS 判决高，映射到包中等 | 中等 | 主线。产出 `DomainObservation` 和 `DNS_DECISION` |
| 域名到 IP set/nftset | resolver 把答案 IP 写入集合，防火墙快路径匹配 | 中等，共享 IP 会误伤 | 低到中等 | 路由器/PBR 后端；不替代 association store |
| TLS SNI/HTTP Host/DPI | 解析 Host、TLS ClientHello、QUIC Initial | 可见时高，ECH 后低 | 高 | future `DpiFacts`，按 consumer gate 开启 |
| OS flow metadata | 平台给 UID/app/hostname/flow metadata | app/UID 高，hostname 视平台 | 中等，依赖权限 | Adapter metadata sidecar |
| app/UID 级代理 | per-app VPN/App Proxy/UID routing | subject 高 | 可控 | subject caps 和 egress policy 输入 |
| 接管/限制加密 DNS | 强制 53 到本地 resolver，阻断或管理 DoT/DoQ/DoH | 提升 DNS 覆盖 | 较高 | 严格 DNS 模式，不默认强制 |

最终策略口径：

- `DNS verdict` 是域名策略最权威、最低成本的执行点。
- `Resolved-IP Policy` 是带 TTL、来源、置信度和 subject 维度的包侧补强。
- `DPI/OS metadata` 是提高置信度的高级事实，不是默认热路径负担。
- `PacketFacts` 不直接承载域名事实；域名通过 CT/session metadata 或 adapter sidecar 进入策略层。

## 候选数据结构草案

```text
DomainObservation {
  source: dns-proxy | os-dns | sni | http-host | manual | resolver-feed
  qname_or_hostname
  qtype
  answers[]
  ttl
  observed_at
  subject: uid | app | process | client_ip | mac | vlan | unknown
  verdict: allow | block | observe
  confidence
}

DomainAssociation {
  subject_key
  ip_family
  ip
  domains[]
  expires_at
  source
  confidence
}

FlowDomainMetadata {
  flow_key | ct_id
  subject_key
  hostname
  source
  confidence
}
```

## 平台问题拆分

### Android

阶段结论：

- Android 上“基于域名”的控制不是内核级真实域名防火墙，而是 `VpnService` 抓包、DNS 代理/缓存、TLS/QUIC ClientHello 解析、UID 归因 API 组合出来的工程方案。
- `ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)` 是关键 UID API，API 29 起可用，输入是协议、本地地址、远端地址，支持 TCP/UDP。
- 该 API 只有当前用户的 active `VpnService` 能查其 VPN 范围内的连接；连接不存在、权限不足或不在可观察范围内会返回 `Process.INVALID_UID` 或抛异常。
- 这解决的是活跃连接 UID 归因，不是“域名请求属于哪个 App”的官方全局订阅接口。

VPN/TUN 下的域名可见性：

- `VpnService` 提供 TUN fd，读写的是 L3 IP 包，没有 L2 头。
- 可通过 `VpnService.Builder.addDnsServer()` 把 VPN DNS 指向自己的本地 DNS proxy。
- DNS proxy 解析 UDP/TCP 53 查询，产生 `qname, rrtype, answer, ttl, uid/client` 观察事件，并维护 `domain -> IP` 候选映射。
- Android Private DNS、浏览器 DoH/DoT、App 自带 DoH/DoQ 生效时，VPN 通常只能看到到解析器的加密连接，看不到 qname。
- TCP TLS ClientHello 的 SNI、QUIC Initial 中的 TLS ClientHello 可作为补充来源；ECH 后真实 SNI 不可靠。
- URL/path 级规则需要 HTTPS MITM；Android 7+ 默认 App 不信任用户 CA，证书固定也会破坏 MITM，因此不应作为默认能力。

产品路线：

- NetGuard：无 root，本地 `VpnService`；域名阻断使用 hosts 文件，允许 DNS 流量通过以建立“域名和 IP 地址列表”，再阻断到解析 IP 的连接。
- RethinkDNS：`VpnService + DNS client + firewall/proxifier`；Android 10+ 使用 ConnectivityService owner API 做 per-app connection mapping，Android 9- 读 `/proc/net`。
- AdGuard for Android：本地 VPN，DNS 规则/hosts/domains-only；高级模式可做 HTTPS filtering、本地证书 MITM、部分 secure DNS/HTTP3 处理。
- Blokada：经典形态是本地 VPN/DNS blocker，主要过滤 DNS。
- personalDNSfilter：Java DNS filter proxy，Android 上通过 local VPN 基于 blocklist 拦 DNS 请求，被过滤 host 返回 loopback，支持 DoH/DoT upstream。

Android 建议：

- Android 专属逻辑放在 Java/Kotlin VPN shim：建立 TUN、配置 DNS/route/app allowlist、调用 `protect()` 防自循环、API 29+ 调 `getConnectionOwnerUid()`。
- native snort/vpp packet pipeline 消费 UID/package/hostname 等元数据，不直接依赖 netd 私有接口。
- 域名能力分三层：本地 DNS proxy、TLS/QUIC ClientHello parser、IP/五元组规则。
- 规则命中必须标注来源：`dns-derived`、`sni-derived`、`manual-ip`、`unknown`。
- blocklist 优先 DNS 层拦，IP 层只作补充；allowlist 不应只靠 DNS->IP 放行共享 CDN，最好要求 SNI/QUIC hostname 匹配。
- Private DNS/DoH/DoT/ECH 情况下明确降级为“不可见域名”，可提供阻断加密 DNS、引导关闭浏览器 secure DNS、或本地 DNS proxy 再使用 DoH/DoT upstream。

来源：

- ConnectivityManager `getConnectionOwnerUid`: https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress)
- Android VPN guide: https://developer.android.com/develop/connectivity/vpn
- VpnService API: https://developer.android.com/reference/android/net/VpnService
- VpnService.Builder API: https://developer.android.com/reference/android/net/VpnService.Builder
- Android DNS Resolver module: https://source.android.com/docs/core/ota/modular-system/dns-resolver
- NetGuard: https://github.com/M66B/NetGuard
- NetGuard FAQ: https://github.com/M66B/NetGuard/blob/master/FAQ.md
- RethinkDNS Android app: https://github.com/celzero/rethink-app
- AdGuard Android local VPN integration: https://adguard.com/kb/adguard-for-android/features/integration-with-vpn/
- Blokada architecture note: https://community.blokada.org/t/how-does-blokada-work/116

### Linux / 路由器

阶段结论：

- Linux 内核、`iptables`、`nftables`、`conntrack`、`NFQUEUE` 都不天然维护“连接属于哪个域名”的语义。
- `conntrack` 的核心是 original/reply 两个 L3/L4 tuple，不包含 FQDN。
- NFQUEUE 只是把包交给用户态；用户态可以解析 DNS、SNI、HTTP Host，但这不是内核语义。
- 现实路线是 DNS 阶段生成 `domain -> A/AAAA -> TTL -> client/app`，后续包处理消费这个近似映射。

主流实现：

- `dnsmasq --ipset=/domain/set` 可把匹配域名解析出的 IP 写入 Netfilter ipset。
- `dnsmasq --nftset=/domain/4#family#table#set` 可写入 nftables set；集合需预先存在。
- OpenWrt `fw4` 场景常用 `dnsmasq-full + nftset + firewall4/nftables`。
- AdGuard Home 支持 `dns.ipset`/`ipset_file`，把指定域名答案 IP 加入既有 ipset，Linux only。
- Pi-hole 主要是 DNS sinkhole：在 DNS 响应层返回阻断结果，而不是天然驱动包过滤。

eBPF 可做增强：

- 本机场景可以用 cgroup BPF、socket cookie、`bpf_get_current_uid_gid()` 之类机制增强进程/UID 归因。
- 路由器转发场景看不到 LAN 客户端本机 socket，归因 key 更现实地应是 `(client IP/MAC/VLAN, qname, answer IP, TTL)`。
- eBPF 可以提升“谁发起 DNS、谁连接 IP”的关联质量，但不能把 IP 连接还原成确定域名事实。

主要误差来源：

- 同一 IP 承载多域名、CDN、Anycast、共享证书。
- DNS 缓存、预解析、CNAME 链、Happy Eyeballs、IPv4/IPv6 混用。
- 连接复用、HTTP/2/HTTP/3 多域名共连。
- 应用自带 DoH/DoT、直接连 IP、本机 hosts。
- QUIC 连接迁移、多个客户端共享 NAT。

Linux/路由器建议：

- 不要让包处理路径同步查域名。
- 建立 `domain-observation` 服务：监听或代理 DNS，生成带 TTL 的域名观察事件。
- 建立 `flow-policy-enrichment`：把 DNS 观察事件注入 CT/session 元数据，记录置信度。
- 对 OpenWrt/路由器，优先 DHCP/RA/RDNSS 下发本地 resolver；只有受管网络再强制 DNAT TCP/UDP 53。
- DoT 可按端口 853 做策略；DoH 不能可靠透明代理，除非 TLS MITM，不建议作为默认方案。

来源：

- nftables manual: https://www.netfilter.org/projects/nftables/manpage.html
- conntrack manual: https://www.netfilter.org/projects/conntrack-tools/conntrack-manpage.html
- kernel conntrack netlink spec: https://docs.kernel.org/netlink/specs/conntrack.html
- libnetfilter_queue docs: https://netfilter.org/projects/libnetfilter_queue/doxygen/html/
- nftables userspace queue: https://wiki.nftables.org/wiki-nftables/index.php/Queueing_to_userspace
- dnsmasq manual: https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html
- OpenWrt DNS IP set filtering: https://openwrt.org/docs/guide-user/firewall/filtering_traffic_at_ip_addresses_by_dns
- OpenWrt PBR dnsmasq nftset notes: https://docs.openwrt.melmac.ca/pbr/1.1.6-16/
- AdGuard Home configuration: https://github.com/AdguardTeam/Adguardhome/wiki/Configuration
- Pi-hole blocking mode: https://docs.pi-hole.net/ftldns/blockingmode/
- eBPF socket cookie: https://docs.ebpf.io/linux/helper-function/bpf_get_socket_cookie/
- eBPF cgroup program types: https://docs.kernel.org/bpf/libbpf/program_types.html

### macOS

阶段结论：

- macOS 上基于域名的拦截/放行/归因不能只靠 packet pipeline 做准。
- 更合理的组合是 `NEDNSProxyProvider` 做域名观察，`NEFilterDataProvider` 做 L4 拦截和 app/process 归因，SNI 只做增强信号。
- `NEPacketTunnelProvider`/`utun` 看到的是 IP 包，默认没有 hostname、URL、进程归因；适合 VPN，不适合作为本地域名防火墙主入口。
- `pf` 只能做 IP/port/interface/table 级过滤，没有 app、hostname、URL、SNI；Apple 也不建议把 packet filter 当产品 API。

Network Extension 能力：

- `NEDNSProxyProvider`：最适合做域名真相源，接管 DNS query，记录 `qname/qtype/answer/TTL`，公开实践中也常用于带进程归因的 DNS monitor。
- `NEFilterDataProvider`：最接近本机防火墙，可在新 flow 到来时 pass/drop/need-more-data；可以使用 `remoteEndpoint`、部分情况下的 `remoteHostname`、`sourceAppAuditToken/sourceProcessAuditToken`。
- `remoteHostname` 只覆盖 connect-by-name 的 flow；直接连 IP、应用自带 resolver、部分代理场景不会有 hostname。
- `NEFilterControlProvider` 是控制面/规则面，不是数据面 parser；需要 SNI 时应在 DataProvider 请求更多 outbound bytes 后解析。
- `NEAppProxyProvider`/`NETransparentProxyProvider` 适合代理化路线，可拿 TCP/UDP flow、remote endpoint、connect-by-name hostname 和部分 source metadata。
- macOS 26 的 `NEURLFilter` 可做系统级 full URL 判定，但 Apple 的设计是不把 URL traffic 直接暴露给 app；旧系统若要 URL/path 级规则，通常只能浏览器扩展、显式代理或 HTTPS MITM。

产品路线：

- Little Snitch：v5 后从 Network Kernel Extension 转向 Network Extension；路线大概率是 Content Filter/System Extension + DNS/reverse-DNS/规则库。
- LuLu：outbound firewall，Big Sur 后切到 Network Extension Framework，本质是 Content Filter 路线。
- AdGuard for Mac：Network Extension mode / Automatic Proxy mode / 旧 Kernel Extension mode；结合本地代理、DNS 过滤和可选 HTTPS MITM。
- NextDNS / Control D：主要是 DNS 层产品，可做域名策略和云端日志，但通常不能做本机 per-process flow 归因，也挡不住 app 自带 DoH/直连 IP。

macOS 建议：

- 不要把 PacketTunnel 当本地域名防火墙主路径，除非产品本来就是 VPN。
- 主路径应是 `NEDNSProxyProvider` 产生 `domain -> answers -> TTL -> source process`。
- 执行路径用 `NEFilterDataProvider` 对新 flow 做 app 归因；优先用 `remoteHostname`，否则查 DNS TTL 映射，再用 SNI 补洞。
- 对 DoH/DoT/DoQ，维护已知 resolver 域名/IP 列表，在 Content Filter 层单独策略化。
- `pf` 只作为辅助兜底或调试工具，不进入核心产品设计。

来源：

- NEPacketTunnelFlow: https://developer.apple.com/documentation/networkextension/nepackettunnelflow
- TN3120 Packet Tunnel expected use cases: https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers
- NEFlowMetaData: https://developer.apple.com/documentation/networkextension/neflowmetadata
- NEFilterDataProvider: https://developer.apple.com/documentation/networkextension/nefilterdataprovider
- WWDC25 Filter and tunnel network traffic: https://developer.apple.com/videos/play/wwdc2025/234/
- NEFilterSocketFlow remoteHostname: https://developer.apple.com/documentation/networkextension/nefiltersocketflow/remotehostname
- NEFilterFlow sourceAppAuditToken: https://developer.apple.com/documentation/networkextension/nefilterflow/sourceappaudittoken
- DNS proxy provider: https://developer.apple.com/documentation/networkextension/dns-proxy-provider
- NEDNSProxyProvider: https://developer.apple.com/documentation/networkextension/nednsproxyprovider
- Objective-See DNSMonitor: https://github.com/objective-see/DNSMonitor
- NETransparentProxyProvider: https://developer.apple.com/documentation/NetworkExtension/NETransparentProxyProvider
- TN3165 Packet Filter is not API: https://developer.apple.com/documentation/technotes/tn3165-packet-filter-is-not-api
- Little Snitch support: https://www.obdev.at/support/littlesnitch
- LuLu: https://objective-see.org/products/lulu.html
- AdGuard for Mac Big Sur issues: https://adguard.com/kb/adguard-for-mac/solving-problems/big-sur-issues/

## 对当前架构的初步影响

我们可能需要把“域名策略”拆成两个层次：

1. `domain-observation`：DNS/SNI/OS flow metadata 产生域名观察事件。
2. `flow-policy-enrichment`：把观察事件按 TTL、UID/client、五元组、方向注入到 CT/session 元数据。

包处理链路只消费已归因的元数据，不应该在每个包路径里同步执行域名查询。

## 阶段收口

本轮调查暂时收束为一个架构判断：

- 域名策略不是 packet parser 的职责。
- DNS/OS flow/SNI/DPI 产生的是观察事件或候选事实。
- CT/session metadata 负责把这些观察事件关联到连接。
- NFQUEUE、VPN/TUN、VPP、Network Extension 等 packet path 只消费已注入的元数据并执行动作。

这意味着后续实现域名策略时，应先设计 `DomainObservation`、`DomainAssociation`、`FlowDomainMetadata` 这类中间模型，再讨论各平台 adapter 如何填充它们。不要先从 VPP buffer、NFQUEUE packet 或 TUN packet 中硬塞域名字段。

## 资料与结论记录

后续按时间追加调查记录、来源链接、实验结论和未决问题。
