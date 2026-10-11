# KSU修改libnetd_resolv，如何配合共用DNS模块

2026-10-05讨论，2026-10-06用户确认职责范围。此处指KSU对`libnetd_resolv`的修改，不是仅用KSU部署NFQUEUE。
本文承接已认可的Linux／VPN共用DNS核心方向；KSU系统入口的过滤、关系采集与NFQ端口放行已确认，具体Interface、安装与生命周期适配尚未冻结，未实施／部署。
只读现有合同与AOSP固定`android-16.0.0_r1`源码；未改产品、模块、设备或网络，未做效率测试。

**2026-10-07首版范围更新：** 用户将KSU/libnetd明确留作未来扩展，首版只实现Root/NFQ与VPN的共用DNS核心。本稿保留未来系统入口的职责设计；当前不实施hook、安装适配或政策投影通路，也不将53／5353放行套用到首版普通Root DNS入口。本轮先收敛模块方案，未开始代码实施。

**2026-10-07正式设计更新：** [ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md)对齐Root/NFQ与VPN的按应用DNS过滤政策及查询／连接两种控制阶段。本文已确认的KSU职责与该路线53／5353放行范围保持，不据此扩大为所有Root入口免DNS处理。

## 2026-10-06已确认设计

用户明确“KSU修改libnetd只负责解析是否应该拒绝，以及获取IP—域名关系；NFQ放行53和5353”，并随后确认此设计。

- **解析前判断：** 系统入口负责允许／拒绝判断，复用DNS政策和域名匹配代码；VPP仍是唯一配置／编译权威。保留原系统权限检查，在其允许后执行产品判断。
- **解析结果采集：** 从系统实际返回的名字与地址结果构建IP—域名关系，为观察与后续连接提供更多信息。前置bool callback没有答案，结果采集须接在解析结果路径或已验证的结果事件上，不能仅安装判断callback便宣称关系采集完成。[handler与结果][A2]、[既有结果事件研究][L7]
- **系统负责解析：** 允许后继续Android原resolver、缓存与系统配置的加密解析。KSU入口不实现自有DoT／DoH客户端，不管理DNS答案缓存，不把Linux／VPN的完整解析后端搬入netd。IP—域名关系存储是观察状态，不是给App返回DNS答案的缓存。
- **NFQ放行：** 此KSU系统hook路线放行普通DNS的TCP／UDP53及mDNS的UDP5353，不重复做DNS重定向／过滤。此决定覆盖该路线的端口放行；入队后ACCEPT还是入队前旁路，具体接入位置与其他显式包规则的关系，留待实现合同定义，不能把讨论当已部署规则。
- **其他入口：** Linux／VPN继续共用查询解析、过滤、响应缓存和加密上游；KSU共用过滤政策／匹配逻辑及关系信息语义，不要求三种入口共用同一解析客户端。

关系只记录实际取得的证据，保留可获得的请求App／UID、网络、名字、地址及时间等上下文；缺失TTL、CNAME链或地址时不能补造，不把共享IP提升为唯一域名，也不自动把映射用于阻断。[关系证据边界][L7]

端口放行不证明所有DNS都经过libnetd：App独立DNS库、自己发出的53查询或5353多播仍可能绕过此入口。Android系统resolver参与部分`.local`解析，不等于覆盖全部mDNS／NSD发现。此次确认采用系统入口控制与端口放行，不另行选定包层DNS补充代理，也不宣称全部DNS覆盖。[53／5353与系统入口范围][L8]

## 2026-10-06复用约束

用户进一步要求域名比较与Linux／VPN的缓存、DoH／DoT注意复用，避免重复实现。域名规范化／匹配与DNS政策判断维护一份可复用实现，KSU只链接本地判断所需部分；VPP管理／编译规则并发布只读投影，不把规则复制成netd内另一份可编辑模型。系统结果经Adapter转换后进入统一解析关系Interface／既有观察通路。

Linux／VPN共用完整DNS处理，DoH／DoT共用DNS报文、答案缓存、查询生命周期与TLS基础；各自只适配实际不同的运输协议。共用代码不要求共用全局可变缓存，KSU也不因此引入自有解析后端。完整职责与后续细节范围见[复用职责与架构收敛](2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md#2026-10-06复用职责与架构收敛)。

## 2026-10-05讨论依据

以下保留确认前的候选比较；当前职责以以上2026-10-06确认项为准。完整解析接管方案二不是当前KSU路线。

## 核心结论

**KSU系统hook可以成为第三种DNS入口，但“共用DNS代码”不要求三种入口都换成同一解析客户端。** 可以先共用政策、域名匹配逻辑和配置资料，系统hook允许后继续Android原resolver；Linux／VPN消息入口使用自有cache／DoT／DoH核心。

如果要求系统hook也使用同一自有cache／上游解析核心，那是另一种接管合同：需要把系统解析请求送到核心并转换结果，不能仅在现有bool callback里调用客户端。[callback合同][A1]、[实际handler][A2]

KSU是部署／权限载体，不是DNS解析引擎；systemless不等于未替换系统实际加载组件。当前适配／安装方式没有因为共用代码而获得新的受支持热更新API。[既有替换范围][L1]、[晚挂接点][L2]

## 两种组合的历史比较

| 职责 | 方案一：本地前置判断，继续原系统解析 | 方案二：系统请求交自有DNS核心 |
| --- | --- | --- |
| 系统入口 | 原网络许可后，读取只读DNS政策投影 | 保留原网络许可，在合适的handler接点接管解析 |
| 共用部分 | VPP权威配置、DNS政策语义、匹配代码／资料、命中归属 | 上述政策与自有答案cache、上游client、答复逻辑 |
| 实际解析 | Android resolver、系统cache、Private DNS | 产品自有核心；保留哪些系统能力需明确适配 |
| 每查询IPC | 可避免；snapshot异步发布，查询本地有界判断 | 分进程部署时需要请求／结果通路与生命周期处理 |
| 返回形态 | callback bool，拒绝沿系统错误路径 | addrinfo／hostent／raw DNS等分别转换并保留API合同 |
| 2026-10-05判断 | 符合前轮小hook方向，接点较窄，推荐先讨论；10-06已确认此职责范围并增加结果采集 | 若必须共用全部解析后端，再作为独立方案评估；10-06未采用 |

表中保留确认前的工程比较，不是当前已实现功能，也不是性能排名。[前轮hook讨论][L3]、[共用DNS入口分析][L4]

## 方案一：政策统一，系统cache与Private DNS继续使用

AOSP的`evaluate_domain_name`带`android_net_context`与hostname，在lookup前执行；hostname可能未完全限定，反向查询可能传null。回调返回false会中止解析，返回true继续原路径。它可并发调用，**不得sleep或RPC**。[合同][A1]、[调用覆盖][A2]

因此建议由VPP将当前有效DNS阶段政策编译／发布为已验证、不可变、只读投影，hook只执行本地判断；更新、验证与观察消费异步进行。不能每次进callback同步询问App／VPP，也不能把完整HEV、TLS与DNS缓存复制进netd。[权威配置][L5]、[hook约束][L3]

共用匹配代码意味着同一窄的判断实现可用于产品DNS核心及hook投影执行；**权威规则管理与编译仍在VPP**，netd不获得第二份可编辑模型或另一套优先顺序。只有本阶段真实取得的hostname、UID、network等事实可以用于判断；含尚未知连接条件的whole rule不能只摘出域名强行拦截。[ADR-0009][L5]、[投影语义][L3]

原系统／OEM callback拒绝必须继续拒绝；原系统允许后才能增加产品判断。`getaddrinfo`的当前拒绝结果为`EAI_SYSTEM`，不是我们生成了一条wire NXDOMAIN／REFUSED。[原许可][A3]、[结果路径][A2]

允许时仍走Android原cache与解析、选网／Private DNS。**系统hook在名字进入系统解析前判断，因而不必先解密系统DoT包**；这一覆盖只针对实际经过该resolver入口的请求，不自动覆盖App自有cache、直接IP或自带DoH／独立DNS库。[Private DNS上下文][A4]、[handler顺序][A2]

这种组合满足“业务连接前已发生DNS控制”，也可以免逐查询NFQUEUE包复制／HEV内侧重建成本；但适配读投影、并发与系统调用本身仍有成本，未经测量不能称最高效率。[callback位置][A2]

## 方案二：把完整解析交自有核心，需要新增系统API适配

当前callback只有允许／拒绝结果，不能携带cache答案或让resolver收下自有DNS wire reply；官方禁RPC。因此要接管完整解析，应另选handler／解析执行接点，不能用“共享一个库”直接越过这个合同。[A1][A1]、[A2][A2]

跨进程实现至少须明确请求身份／netId、hostname及hints／service、query type与flags、答复关联、期限／取消、错误转换与失联处理；`getaddrinfo`返回地址链，raw query返回DNS报文，不能视为同一种字节接口。[getaddrinfo输入][A5]、[raw输入][A6]

还需保留系统网络许可、选网、Private DNS要求及系统API行为，处理同一请求被hook与消息入口再次判断的重复／重入。核心在启动或解析自己的加密上游时不能再同步依赖同一个被接管系统resolver。这里不冻结具体IPC或结果格式。

**推荐保持自有cache／上游状态仍由原产品owner管理**，netd若做此入口只保留必要适配，而非再启动一套独立可变DNS引擎。这是复用方向，不是已可运行的系统接管方案。

iodé已有研究不能作为方案二的完成证据：其getaddrinfo handler询问verdict／getips，实际解析仍由原Android resolver完成；地址年龄映射不是完整DNS答案cache。它的同步RPC位于handler，不能搬入禁止RPC的callback。[既有固定源码评估][L1]

## 启用、回退与当前实现边界

用户此前允许系统正常启动，App后台防护／权威有效政策就绪后才启用。建议hook安装与政策启用分别核验：政策未就绪／停用／失联时只退出产品附加判断，沿用原系统结果；具体失联策略尚未冻结。关闭界面不应等同停止后台Runtime。[已有生命周期讨论][L3]

“晚启用政策”与“晚加载／安装hook”仍不同；KSU挂载整库、原进程已映射库、实际Build ID／APEX适配不能由同一DNS模块解决。本轮不恢复早期启动部署调查，也不声明完成安装。[晚安装边界][L2]

当前Root NFQUEUE包入口与此系统解析入口也独立：已有NFQUEUE UID是包的socket事实，系统hook可取得系统解析请求context。二者不因KSU或共用代码自动变成同一归属来源；需要分别记录取得的事实与实际控制机会。[Root UID采集][L6]、[系统context][A5]

2026-10-05曾建议仅让系统resolver上游免再次重定向，另研究App独立DNS的包层补充。**此建议已由10-06的KSU路线端口放行决定取代：53／5353不重复DNS接管／过滤。** 端口放行与完整DNS覆盖是不同事实，来源识别与额外补充代理未被选定。

系统cache与Private DNS不等于自有cache与可选择的DoT／DoH上游。10-06已确认KSU入口不负责这两项，由系统继续承担；完整解析接管保留为历史比较，不是当前待选路线。

当前已确认的复用层级是**共用过滤政策／匹配逻辑，保留系统解析，追加IP—域名关系采集**。VPP配置权威保持不变，不因后端不同建立另一份用户规则。

[A1]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/include/netd_resolv/resolv.h#96
[A2]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#915
[A3]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/main.cpp#98
[A4]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#112
[A5]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#1010
[A6]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#1057
[L1]: /home/js/Git/sakamoto/sakamoto-snort/docs/reviews/2026-10-04_IODE_DNS_REFERENCE_ASSESSMENT.md:42
[L2]: /home/js/Git/sakamoto/sakamoto-snort/docs/reviews/2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md:20
[L3]: /home/js/Git/sakamoto/sakamoto-snort/docs/reviews/2026-10-03_LIBNETD_HOOK_DESIGN_DISCUSSION.md:41
[L4]: /home/js/Git/sakamoto/sakamoto-snort/docs/reviews/2026-10-05_NFQUEUE_TUN_PACKET_INJECTION_BOUNDARY.md:53
[L5]: /home/js/Git/sakamoto/sakamoto-snort/docs/adr/0009-unified-rules-and-vpp-owned-configuration.md:16
[L6]: /home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_root_nfqueue_adapter.c:728
[L7]: /home/js/Git/sakamoto/sakamoto-snort/docs/reviews/2026-10-03_ANDROID_DNS_PLATFORM_RESEARCH.md:60
[L8]: /home/js/Git/sakamoto/sakamoto-snort/docs/reviews/2026-10-03_ANDROID_STANDARD_DNS_DISCUSSION.md:45
