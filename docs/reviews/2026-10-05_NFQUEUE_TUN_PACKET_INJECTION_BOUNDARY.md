# NFQUEUE 与 TUN：修改原包、独立注入的机制边界

2026-10-05。只读机制核对，未运行网络／设备测试、未改产品。
本轮只比较NFQUEUE verdict与TUN读写，不恢复整套Android VPN设计，也不改变当前产品的packet owner／返回路径合同。
内核源码固定看Linux `v6.12`；它证明该版本机制，不声明本机／设备内核版本与配置相同。

## 直接回答

**NFQUEUE能丢弃／放行／替换已有排队包，但其verdict API不能在没有排队包时独立发一个新包。TUN写入则可以提交用户态构造的新IP包，不要求对应一个原始packet ID。**[NFQ官方API][A1]、[内核verdict入口][K1]、[TUN文档][A2]

“NFQUEUE不能独立发新包”不等于“Linux Root环境不能发新包”。Root程序可另用raw socket、AF_PACKET或TUN等发送入口，权限、层级与方向各不同。[raw socket][A3]、[packet socket][A4]

| 机制 | 控制对象 | 可替换字节 | 不依赖原包新增包 | 进入网络栈的位置 |
| --- | --- | --- | --- | --- |
| NFQUEUE verdict | 当前queue里已有的packet ID | 可提交替换IP datagram | 此API不提供 | 原queue entry保存的hook路径继续执行 |
| TUN fd write | 用户提交的IP包 | 用户负责构造整包 | 可以 | 作为TUN虚拟接口收到的包进入内核RX |
| IPv4 raw socket send | 用户提交／构造的IP datagram | 按IP_HDRINCL等合同 | 可以 | IP发送／路由路径 |
| AF_PACKET send | 用户提交的链路层包／帧 | 按SOCK_RAW／DGRAM合同 | 可以 | 指定接口设备发送路径 |

表述来自对应接口合同，不表示任意构造的数据都能被应用接收或被外网接受。[NFQ替换API][A5]、[内核继续路径][K2]、[TUN驱动][K3]、[raw][A3]、[AF_PACKET][A4]

## NFQUEUE：替换的是那个已有queue entry

1. 官方verdict函数携带netfilter分配的`id`；新API的`nfq_nlmsg_verdict_put_pkt`明确叫replacement packet content，不是独立发送包。[verdict与替换][A5]
2. 内核`nfqnl_recv_verdict`先找到queue及发送者，再执行`find_dequeue_entry(queue, id)`；ID不存在返回`-ENOENT`，并不拿payload创建一个新queue entry。[入口][K1]、[查找出队][K4]
3. 携带`NFQA_PAYLOAD`时，`nfqnl_mangle`对原entry的skb裁短／扩长、复制新内容。空间不够可能分配新skb，但会释放旧skb并替换`entry->skb`：这是存储替换，不是额外新增一个可发送的包。[mangle][K5]
4. 随后`nfqnl_reinject → nf_reinject`使用原entry的network namespace、协议族、hook和hook index；ACCEPT可做reroute，再继续后续hook或原`okfn`；DROP释放该包。[继续路径][K2]

因此一次verdict可以大幅改写包内容，包括IP头，而不只是应用层payload。**但它仍是原包位置的一次处理结果，不能“原包drop以后，再用同一个ID独立发任意多个新包”。** batch verdict也只是对已排队包批量给决定。[内核入口][K1]、[官方batch说明][A1]

**推论**：把源／目的地址对调，不自动变成通用的反向收包API。原hook、接口／路由、conntrack等上下文仍要成立；`nf_reroute`也不等于重新从任意RX入口注入。某些路径可通过替换／改路由完成特定效果，但不能把这种可能性说成NFQUEUE提供通用新增答复接口。[保留上下文][K2]

## TUN：可以合成，但写入方向要说准确

Linux TUN为用户态提供IP层虚拟接口；读fd得到内核经该接口发出的包，写fd让内核把用户字节视作这个接口收到的IP包。TAP对应Ethernet frame，而非同一格式。[官方TUN说明][A2]

源码`write_iter → tun_get_user`从用户缓冲创建／填入skb，设置网络头与接收队列，再交给RX／NAPI路径；没有要求引用NFQUEUE packet ID。它可以提交用户态新构造的DNS响应等包。[write入口][K3]、[创建skb][K6]、[RX交付][K7]

“可以合成”更准确，“任意注入到任何地方”过强。必须有有效fd／设备与匹配的包格式；可选PI／virtio头、设备状态、长度／校验和、IP路由、防火墙及UDP／TCP状态都会影响实际接收。写TUN本身也不是直接从物理网卡向外发送。[TUN格式][A2]、[驱动输入检查][K8]

对持有已建立VPN TUN fd的程序，同样要区分“能写回内侧虚拟接口”与“另向真实网络发送”。本报告不以这一机制推导某个平台能任意绕过系统路由、其他应用或当前产品返回规则。

## 当前Product与参考fork的实际集成

当前Root adapter的verdict message只有`NFQA_VERDICT_HDR`，未带`NFQA_PAYLOAD`；结果仅映射NF_ACCEPT／NF_DROP。因此**底层NFQUEUE可替换原包，而当前Product还没有提供替换字节或独立注入能力**。[verdict构造][P1]、[verdict映射][P2]

当前VPN adapter的TUN返回入口要求generation、FLOW_STACK_RETURN provenance、INPUT direction等；只有通过返回检查的包才写TUN，FLOW_STACK output callback再进入统一graph。**TUN底层可接收合成包，不意味着产品模块被授权直接任意写fd。**[返回准入][P3]、[写TUN][P4]、[FLOW_STACK返回][P5]

外部VPP fork的DNS合成答复另走其发送机制：security enforcer创建IPv4／IPv6 raw socket，在system-route注入方式使用`sendto`。这不是用NFQUEUE无中生有创建答复的证据。[raw socket创建][F1]、[独立发送][F2]

## 追加：VPN也使用本地内核DNS listener，能复用到哪里

2026-10-05用户继续询问VPN的内核NAT／socket路线。本节按普通无Root Android `VpnService`理解；只比较局部DNS入口，不恢复整个VPN设计。

| 路线 | 已知边界 |
| --- | --- |
| 无Root VPN直接设iptables／DNAT | VPN授权给TUN及有限Builder配置，不授予普通App管理内核firewall／NAT所需的CAP_NET_ADMIN。[VpnService][V1]、[App sandbox][V2]、[capabilities][V3] |
| TUN→HEV内侧会话→普通loopback socket→本地DNS listener | 可作为复用候选：内侧TCP终止／UDP会话仍需适配，再把完整DNS消息经内核socket送同一server。多一轮本地socketI/O／缓冲／调度；原App身份、原tuple与reply context须另外传递，listener看到桥接进程socket不等于原调用者。当前Direct代码没有此DNS目的重定向。[当前HEV连接原目的][V4] |
| 改TUN包后write，让RX交给本地kernel listener | TUN写入确实进入RX，不能凭ADR断言物理上不可能；但这不是公开VPN API保证的任意本地再投递。目的本地地址、回程路由、source validation与系统防火墙必须成立；127/8涉及route_localnet，原本地source涉及accept_local／rp_filter。本轮未验证Android可用组合。[VPN方向][V1]、[Linux输入限制][V5] |

ADR-0007限制的是把原TUN包直接送入普通外网TCP／UDP egress／NAT，选择HEV/lwIP终止内侧并用受保护socket对外；它没有证明所有kernel本地delivery都不可能。反过来，上表候选也没有改变当前Direct原目的及统一返回graph合同。[ADR-0007][V6]

**研究建议**：优先共用完整DNS消息处理模块：政策判断、cache、上游解析与答复内容统一；Linux内核socket入口和VPN内侧UDP／TCP会话入口只做运输适配，使用同一请求context与异步答复合同。VPN端保留必要的内侧TCP framing／会话及既有返回路径。这样复用核心逻辑，不必为了统一listener强制增加loopback往返。

若已有成熟socket型DNSserver且其改造成本更高，loopback桥接仍值得比较；收益是原样复用server入口，成本是上述额外I/O与身份／关联状态。无论选哪种，真正外网上游socket仍按VPN protect／underlay合同处理；protect不会把原TUN包变成内核TCP连接。[protect API][V1]、[ADR-0007][V6]

以上是基于接口与当前代码的有限可行性分析，未实现、未测试、未接受为新设计。

## 本轮结论的含义

原包控制与新包发送应分别说明：NFQUEUE负责已有包的verdict／替换；需要新增答复时，必须另有明确发送／注入入口。TUN确有这种用户态写包入口，但方向、网络合同与当前产品owner约束仍然成立。本轮只确认接口边界，不选择DNS接入或新增注入方案。

[A1]: https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html
[A2]: https://docs.kernel.org/networking/tuntap.html
[A3]: https://man7.org/linux/man-pages/man7/raw.7.html
[A4]: https://man7.org/linux/man-pages/man7/packet.7.html
[A5]: https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__nfq__verd.html
[K1]: https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nfnetlink_queue.c#L1406
[K2]: https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nfnetlink_queue.c#L312
[K3]: https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c#L2039
[K4]: https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nfnetlink_queue.c#L209
[K5]: https://github.com/torvalds/linux/blob/v6.12/net/netfilter/nfnetlink_queue.c#L1060
[K6]: https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c#L1830
[K7]: https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c#L1985
[K8]: https://github.com/torvalds/linux/blob/v6.12/drivers/net/tun.c#L1748
[P1]: /home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_root_nfqueue_adapter.c:629
[P2]: /home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_root_nfqueue_adapter.c:914
[P3]: /home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_vpn_tun_adapter.c:101
[P4]: /home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_vpn_tun_adapter.c:220
[P5]: /home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_vpn_flow_stack.c:95
[F1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:2205
[F2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:309
[V1]: https://developer.android.com/reference/android/net/VpnService
[V2]: https://source.android.com/docs/security/app-sandbox
[V3]: https://man7.org/linux/man-pages/man7/capabilities.7.html
[V4]: /home/js/Git/sakamoto/sakamoto-snort/third_party/hev/product/hev-owner.c:259
[V5]: https://www.kernel.org/doc/html/latest/networking/ip-sysctl.html
[V6]: /home/js/Git/sakamoto/sakamoto-snort/docs/adr/0007-owner-local-lwip-direct-egress.md:8
