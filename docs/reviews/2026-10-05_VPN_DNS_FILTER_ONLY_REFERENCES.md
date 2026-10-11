# VPN DNS 只过滤一期：固定源码参考

日期：2026-10-05。范围是现有 VPN 转发中的明文 QNAME allow/deny；自建 DNS wire/TTL cache 与 DoT/DoH 上游客户端延期至二期或增强。
本记录只读官方文档与固定源码，不执行构建、设备、基准或模块脚本；以下是静态行为核对，未建立产品兼容性或性能结论。
NetGuard 固定官方 master 提交 [`166df969c3cedd7023c13613d9816c185702c6c9`][ng-pin]；DNS66 固定官方 HEAD/main [`3e80e35915dd9a501ba99779b01f53e906c2fffd`][d66-pin]。
DNS66 仅核对 README、DnsPacketProxy、AdVpnThread、AdVpnService、RuleDatabase、app/build.gradle 六个文件；不扩展项目或 DNS 库排行。

可借鉴的结论：DNS 过滤可以附着现有转发路径，过滤本身不要求自建缓存或加密解析客户端。
两者的拦截时机不同：NetGuard hosts 过滤改写上游回复；DNS66 在请求转发前检查 QNAME，命中后本地回应。
用户要求“过滤相关域名 DNS 请求”，因此 DNS66 的 query-side 顺序更直接；不能把 NetGuard 描述成被拒请求不会出网。

## NetGuard：现有全流量转发中的回复过滤

官方说明要求启用流量过滤、域名阻断并导入 hosts；忽略 hosts 中 IP、不支持通配符；加密 DoT/DoH QNAME 不可见。
官方也说明 Android 代应用解析时不能为单一 App 设置 adblock 例外。这是该项目限制，不能替代 Sakamoto 已确认的 origApp 语义。[官方说明][ng-doc]

| 核对项 | 固定源码的实际行为 |
| --- | --- |
| UDP QNAME 位置 | `recv()` 上游数据后，仅原会话目的端口 53 调用 `parse_dns_response()`，随后 `write_udp()` 回 TUN；请求侧没有 hosts QNAME 预判。[UDP 回程][ng-udp-response] |
| UDP allow | 无显式 redirect 时，`sendto()` 用原目标 IPv4/IPv6、原端口和原 DNS payload；不会为 hosts 过滤主动替换 server。[UDP 出程][ng-udp-send] |
| TCP QNAME 位置 | 普通 TCP 字节先发送到上游；返回 `recv()` 数据中，原目标 53 且 bytes>2 才跳过两字节前缀调用同一 response parser。[TCP 数据路径][ng-tcp-data] |
| TCP allow | 无 redirect/SOCKS5 配置时连接原目标；显式代理/端口转发是独立功能，不能当过滤前提。[TCP 目标][ng-tcp-target] |
| deny | 就地改写收到的正答：清空 answer/authority/additional 数量，修改 flags 与 rcode，UDP 缩为 header+首 question 后回送；不是请求时新建回复，也不是单纯丢弃。[拒绝改写][ng-deny] |
| rcode | 来自运行参数；Java 默认配置值为 3（NXDOMAIN）。该默认不自动决定 Sakamoto 拒绝回复的产品语义。[启动参数][ng-rcode] |
| hosts 匹配 | 导入 map，回调做精确字符串查找；无 wildcard 扩展。源码不能支持“已有所有域名规则语义”的外推。[hosts 导入][ng-hosts]、[查找][ng-domain] |

FAQ 63 说允许 DNS 流量以建立 domain/IP 关系，即使域名在 hosts 中；源码与“请求可出网、返回正答可被改写”相符。
`dns_resolved()` 在 hosts 判定之前记录 A/AAAA 与 TTL，因此“DNS allowed”日志不等于客户端获得原正答，也不等于后续 IP 流量允许。[FAQ 63][ng-faq]、[回复解析][ng-parse]

实际覆盖有明显限制，不能从广告过滤文档推导完整 DNS 兼容：

- parser 仅处理 `QR=1、opcode=0、qcount>0、ans_count>0`；空答、负答及其他 opcode 不进入 hosts 改写。
- 仅实际解析首 question；多个 question 只是警告，不构成多 question 正确性证据。
- hosts 判定无 A/AAAA QTYPE 限制：其他类型在满足正答和解析条件时也可命中；A/AAAA 分支主要用于 name/IP 记录。
- 带 IN SVCB/HTTPS answer 会触发独立的无条件改写，即使 hosts 未命中；不能照搬为“只过滤命中域名”。[parser 条件与 RR 分支][ng-parse]、[拒绝条件][ng-deny]
- TCP caller 未校验/累积两字节长度指示的完整 DNS frame，未循环解析同次 recv 的多个 frame；parser 返回缩短的 dlen 也未回写前缀或 `bytes`。
  此为静态分帧/长度限制，未实测客户端结果，不能声称完整 TCP DNS 支持。[TCP 回程][ng-tcp-response]
- DNS parser 入口是原目的端口 53；UDP 5353 mDNS 不走该入口。普通 UDP multicast socket 支持也不能证明 mDNS QNAME 过滤。[UDP 回程][ng-udp-response]

NetGuard 存在 DNS 记录库，但它存 QName/AName/IP/时间/TTL，服务 IP 规则和归因；默认最小保留期还被抬至 259200 秒。
这与按原 wire/TTL 回答重复 DNS 查询的 resolver cache 不同；核对的过滤转发路径没有从该库生成缓存 DNS answer。[记录回调][ng-domain]、[数据库][ng-db]
同样，项目 `tls.c` 是 ClientHello SNI 读取器，不能因文件名推导它具有 DoT 上游 TLS 客户端。[SNI 源码][ng-tls]

## DNS66：请求侧只过滤的直接对照

`handleDnsRequest()` 从 UDP payload 解析 Message，取首 question 的 QNAME、去尾点并转小写，再查 hosts 集合。
allow 分支直接使用原 `dnsRawData` 创建 DatagramPacket；deny 分支不调用 upstream forward。[请求判定][d66-query]、[集合匹配][d66-rules]
deny 在原 Message 上设置 QR、RCODE=NOERROR，附 authority SOA，TTL/minimum=5 秒，再合成本地 IP/UDP 回包。
这是正常空答式拒绝（常称 NODATA），不是 NXDOMAIN、FakeIP 或把域名映射到 localhost；5 秒 SOA 供客户端负缓存使用。[拒绝与 SOA][d66-query]、[SOA 定义][d66-soa]

| 核对项 | 固定源码的实际边界 |
| --- | --- |
| 上游目的 | proxy 支持原目的地址或 alias→上游地址；实际 configure 通常为系统/自选上游分配 VPN DNS alias，再按 alias 索引映射，DNS 端口保留。[目的映射][d66-target]、[VPN DNS 配置][d66-config] |
| 保留 wire | allow 发送原 query bytes，未重新序列化查询；返回通过原请求构造 IP/UDP 头，并装入上游 payload。[请求判定][d66-query]、[回包构造][d66-reply] |
| TCP | 入口直接 cast 为 UDP，失败即丢弃；无 TCP DNS 流/长度分帧处理，不能作为 Sakamoto TCP 支持的实现证明。[请求入口][d66-entry] |
| 非 A/AAAA | hosts 判定前不检查 QTYPE/QCLASS，可按 QNAME 过滤 TXT/MX 等；仅取首 question，不能证明多 question、所有 opcode 或非法报文都符合预期。[请求判定][d66-query] |
| 大报文 | 上游读取固定 1024 字节缓冲，并把整个数组交给回包构造，未按 DatagramPacket 实际长度裁切；不能声称 EDNS/大答复完整透传。[UDP 上游读写][d66-io] |
| cache/TLS | 每个放行请求用普通 DatagramSocket 与有界 pending socket 队列等回复；队列年龄是等待超时，不是 DNS TTL cache，也未要求 TLS client。[UDP 上游读写][d66-io]、[等待队列][d66-pending] |
| 路由/5353 | 仅 DNS 地址/alias 的 VPN 路由，不是全流量 VPN；不覆盖默认未进入这些路由的硬编码 DNS、mDNS multicast 等。入口也不是通用 mDNS proxy。[VPN DNS 配置][d66-config] |

## 对 Sakamoto 一期的含义

保留现有 VPP-native C packet domain 与 owner-local HEV/lwIP；可借鉴“读取可见 QNAME→现有规则判定→allow 交现有转发/deny 本地回应”的顺序。
这只是过滤位置参考，不移植两个项目的 Java/C 源码，也不恢复或借用 ADR-0008 删除的 Snort C++、archives 或 POC 实现。[当前主线](../current/README.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)
用户已确认未知 origApp 的 DNS 先 allow，不等待 UID；参考项目的全局 hosts、DNS-only App bypass 或 UID 特例不能覆盖这一决定。
固定 DNS 入口曾获认可，可保留为入口候选；它是否用于 alias/上游选择需说明具体用途，不能被自动取消，也不意味着必须做完整 resolver。
自建 cache、DoT/DoH client 延期，不影响既有 QUIC Initial/SNI 加密原语；系统/应用已启用的 Private DNS 可以保留，只需明确其加密 QNAME 在本过滤路径不可见。
一期不引入 FakeIP、新 Rust DNS runtime 或 mDNS proxy 前提；TCP 分帧、非 A/AAAA、malformed query 和本地拒绝 rcode 需在实际产品边界中明确，不能以参考项目名义宣称已完成。

[ng-pin]: https://github.com/M66B/NetGuard/commit/166df969c3cedd7023c13613d9816c185702c6c9
[ng-doc]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/ADBLOCKING.md#L6-L53
[ng-udp-response]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/udp.c#L104-L142
[ng-udp-send]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/udp.c#L332-L374
[ng-tcp-data]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L470-L613
[ng-tcp-target]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L1038-L1119
[ng-deny]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/dns.c#L180-L194
[ng-rcode]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/java/eu/faircode/netguard/ServiceSinkhole.java#L1547-L1568
[ng-hosts]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/java/eu/faircode/netguard/ServiceSinkhole.java#L1633-L1676
[ng-domain]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/java/eu/faircode/netguard/ServiceSinkhole.java#L1994-L2021
[ng-faq]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/FAQ.md#L676-L692
[ng-parse]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/dns.c#L78-L178
[ng-tcp-response]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tcp.c#L551-L613
[ng-db]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/java/eu/faircode/netguard/DatabaseHelper.java#L815-L867
[ng-tls]: https://github.com/M66B/NetGuard/blob/166df969c3cedd7023c13613d9816c185702c6c9/app/src/main/jni/netguard/tls.c#L22-L44
[d66-pin]: https://github.com/julian-klode/dns66/commit/3e80e35915dd9a501ba99779b01f53e906c2fffd
[d66-query]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/DnsPacketProxy.java#L190-L213
[d66-rules]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/db/RuleDatabase.java#L99-L110
[d66-soa]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/DnsPacketProxy.java#L49-L63
[d66-target]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/DnsPacketProxy.java#L223-L240
[d66-config]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/AdVpnThread.java#L366-L511
[d66-reply]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/DnsPacketProxy.java#L99-L134
[d66-entry]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/DnsPacketProxy.java#L142-L165
[d66-io]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/AdVpnThread.java#L328-L359
[d66-pending]: https://github.com/julian-klode/dns66/blob/3e80e35915dd9a501ba99779b01f53e906c2fffd/app/src/main/java/org/jak_linux/dns66/vpn/AdVpnThread.java#L550-L592
