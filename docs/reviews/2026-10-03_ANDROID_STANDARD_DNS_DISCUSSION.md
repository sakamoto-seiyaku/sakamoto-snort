# Android标准防护：DNS、SNI与地址关联讨论

2026-10-03。状态：普通使用与三种防护模式的大致方向已获用户确认；本文中的Android技术选择与默认策略继续讨论。本轮只核查文档、平台源码与早期Android模块材料，没有修改产品、设备、原型或正式执行合同。

**后续用户更新：** 系统hook确认为libnetd；VPN DNS进入TUN记录过滤，放行后由应用转到加密远程上游，配合阻止常见外部加密DNS服务。用户澄清“doc”为DoQ后，明确产品自身对外请求可以不支持DoQ，当前上游范围收窄为DoT／DoH。用户撤下Android资源开关，认为当前已过度设计；下方资源章节为此前阶段材料，不再作为当前待推进方向。新的查询／缓存推演见[VPN DNS讨论](2026-10-03_VPN_DNS_RELAY_DISCUSSION.md)。

## 已确认的产品起点

用户确认大致按照标准／增强／自定义或高级的方向推进，并要求写入Markdown。标准是大多数普通用户最常使用的模式：首次授权后由产品按系统能力适配，选择标准即可后台守护；误伤时由引导排查提出恢复措施，验证正常后保留例外。标准和增强的过滤由产品维护，自定义提供完整编写能力。具体名称、名单、切换与排查步骤仍未冻结，见[确认记录](../product/NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-03-确认防护模式方向并转入android域名过滤)。

本轮用户提出系统hook、仅Root和VPN三种Android能力路线，系统hook加SNI通常足够、IP映射误差更大、DNS接管可选及Android能力开关是待判断的技术想法，不因产品方向确认而自动成为执行合同。

## 先区分三个不同能力

| 能力 | 直接取得的事实或控制 | 边界 |
| --- | --- | --- |
| 系统解析调用hook | 在实际被改造的解析入口读取域名，视改造协议在解析前／返回前参与决定 | 只覆盖经过该入口的调用；不能凭安装KernelSU就声称hook已生效 |
| 系统解析结果通知 | 查询主机名、返回地址、UID、netId等 | 是结果观察，不能返回allow/deny，也不能保证先于首次连接建立关联 |
| 包层DNS／TLS／QUIC解析 | 对实际捕获的明文DNS或可读握手获取域名证据 | 加密DNS、ECH及未进入捕获路径的流量留有缺口 |

KernelSU、Magisk等提供Root与模块装载条件；真正决定方案的是hook、事件监听及捕获能力是否验证可用。具有KernelSU但未启用DNS改造的设备，在这里仍属于仅Root能力路线。[KernelSU模块机制](https://kernelsu.org/guide/module.html)

## 早期Android模块实际找到了什么

本机早期Sucré Android16工具链中，`framework.jar`和`services.jar`补丁将前台应用UID经Binder及LocalSocket发送为`TOPACTIVITY`。这份smali不能单独作为DNS请求hook的证明。[工具链架构](</home/js/Git/sucre/sucre-android16-toolkit/README.md:43>)、[对应smali](</home/js/Git/sucre/sucre-android16-toolkit/patches/ams_methods.smali:95>)

DNS另有`overlay.d/sbin/libnetd_resolv.so`：部署脚本生成开机脚本，将改造库绑定到`/apex/com.android.resolv*/lib64/libnetd_resolv.so`。这证明早期模块包含resolver库覆盖路径，不证明当前设备已加载、完整协议覆盖或资源排名。[部署脚本](</home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:239>)、[模块材料记录](</home/js/Git/sucre/KSU/sucre-module/SUPPLEMENTAL_CHANGES.md:12>)

Android官方说明DNS Resolver作为`com.android.resolv` APEX提供，承担系统解析与缓存；其版本和厂商改动不能只按framework版本猜测。因而系统hook路线应以实际解析模块和功能探测为边界。早期工具链的设备／版本说明仅是历史材料，本轮没有运行其部署、反编译或测试脚本，也没有读取或使用旧Snort C++ daemon作为实现参考。[AOSP DNS Resolver](https://source.android.com/docs/core/ota/modular-system/dns-resolver)

系统入口有机会更早阻止不需要的解析及后续连接，值得评估处理量与资源收益；“效果最好／最省资源”仍是待测假设。Root、模块加载或一个旧单机成功声明，都不能替代DNS延迟、CPU、电量、兼容性及误伤对照。

## 仅Root：有解析结果路径，但不是通用广播

已核查Android16固定tag的两条路径，详情及完整许可链见[平台研究](2026-10-03_ANDROID_DNS_PLATFORM_RESEARCH.md)：

- `IpConnectivityMetrics.addNetdEventCallback`要求调用者UID恰为1000，UID0不通过；只有三个系统用途槽，注册会替换对应槽。[UID guard](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/connectivity/IpConnectivityMetrics.java#342)
- `IDnsResolver.registerEventListener`走网络栈权限检查，AOSP许可链支持真正UID0辅助进程；监听集合可增加成员而不替换系统监听者。普通App获得su授权不改变它自身的Binder UID；SELinux、服务可达性、接口和模块版本还需要设备验证。[注册](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolverService.cpp#132)、[监听集合](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/ResolverEventReporter.cpp#113)
- DPM确有DNS网络日志与日志就绪广播，但要求device/profile owner或委派身份，广播通知的是批次就绪，不能当逐条实时DNS广播。[Android网络日志](https://developer.android.com/work/dpc/logging)

直接resolver事件在结果已送给客户端之后上报，且是oneway；可以为观察和地址关联提供证据，不能当成前置DNS拦截。事件地址数组最多10项，没有TTL和完整CNAME链；不能保证映射已更新时App才首次连接。[结果时序](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#951)、[事件负载](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/staticlibs/netd/binder/android/net/metrics/INetdEventListener.aidl#24)

因此，仅Root可以研究“SNI＋已验证的系统解析结果＋实际捕获的明文DNS”，不必预设系统事件一定不可用；也不能把事件通知当成系统hook或DNS解析前拒绝。

## 53、5353与NFQUEUE放行

普通DNS使用UDP与TCP的53；5353主要是本地链路UDP mDNS，IPv4/IPv6多播及`.local`发现。5353不应作为普通上游DNS一起转发到公共DoH／DoT解析器。Android系统resolver也可能参与`.local`解析，不能据此推成所有mDNS都可被系统hook覆盖。[RFC1035传输](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2)、[RFC6762](https://www.rfc-editor.org/rfc/rfc6762)、[AOSP mDNS支持](https://source.android.com/docs/core/ota/modular-system/dns-resolver#mdns-local-resolution)

“放行”必须具体说明：

1. DNS包进入产品捕获路径，观察后按适用政策允许：仍可观察明文查询／答案，但承担入队与处理成本。
2. 在对应NFQUEUE规则前直接接受该流量：这些包不进入这处队列，不能同时承诺由该队列产生DNS记录；还须判断是否跳过本应适用的其他规则。

上述是执行路径推论，不是已接受的bypass设计。现有[统一规则合同](../product/UNIFIED_RULE_ENGINE_SPEC.md)不能通过新增端口直通被悄悄改变。可评估系统hook充分工作时减少重复DNS处理，但性能捷径需要保持正在使用的控制语义。

## VPN：可以看到明文DNS，不只有SNI

VPN读取实际进入TUN的IP包，所以在应用与路由覆盖正确时，也可解析明文UDP/TCP53。读取问题和答案不要求把上游改成DoH／DoT；受控本地DNS代理与上游替换是额外动作。`addDnsServer`仅配置DNS地址，不会创建代理、完成拦截或合成拒绝响应。[VPN Builder](https://developer.android.com/reference/android/net/VpnService.Builder#addDnsServer(java.net.InetAddress))

系统Private DNS可使用DoT，也有官方发布的DoH3；App还可能自己做加密DNS。进入TUN不会解密其中的查询，看到解析服务的SNI不能当成知道每一个被查询业务域名；开启VPN也不保证自动关闭Private DNS。[Google官方DoH3发布](https://security.googleblog.com/2022/07/dns-over-http3-in-android.html)、[平台研究](2026-10-03_ANDROID_DNS_PLATFORM_RESEARCH.md#private-dns与应用自带加密dns)

因此“SNI可用”和“受控DNS可用”应分开探测。用户选择DNS接管后，需要完整处理响应、上游连接、重试、缓存与原系统DNS的关系；这些责任不能由设置DNS地址推导为已完成。

## 直接域名与IP映射的精确性

查询的QNAME是该次DNS请求的直接域名事实；可见SNI是连接握手的名字，均比“此IP曾由某域名解析得到”更直接。过滤名单仍可能包含误伤目标，DNS层拦截也可能影响不止用户想限制的连接；来源直接不等于名单或策略必然正确。

ECH会加密真实ClientHello，外层名字不能冒称真实目标；HTTP/2允许多源复用连接，握手名字也不等于每个请求的域名。由此不能把“SNI＋系统hook通常够用”的经验扩大为覆盖全部HTTPS行为。[RFC9849](https://www.rfc-editor.org/rfc/rfc9849.html)、[RFC9113 §9.1.1](https://datatracker.ietf.org/doc/html/rfc9113#section-9.1.1)

地址关联的额外不确定性包括共享IP、多个候选域名、TTL／时间、网络切换、不同应用／用户及首次连接事件时序。实际报文可提供RR TTL，结果事件缺失的TTL不能补造；即使关联带UID/netId，仍不能证明某次连接实际使用了哪个候选域名。

本轮建议是：标准模式优先直接名字，地址关联可供观察；基于弱地址关联的阻断另行选择开启，避免把一个广告域名的共享地址扩大为全部业务阻断。它不能覆盖已有直接目标事实。这是待确认的保守默认，不是用户已经批准的执行合同。

DNS、SNI、地址关联是不同时间的事实取得与处理机会，不为规则新增优先级。DNS只决定完整域名限制确实可在该查询上下文成立的政策；包含协议、端口等尚未知条件的规则留到相应连接事实可用时判断，保留[完整规则与统一优先顺序](../product/UNIFIED_RULE_ENGINE_SPEC.md)。

## Android资源开关的讨论方向

本节已被用户后续要求撤下，保留讨论历史，不继续作为当前设计事项。

用户提出Android可提供部分匹配开关减少开销。本轮建议先由当前模式与有效规则决定实际需要的解析、关联和深度记录能力，避免全量常驻；高级设置再允许明确改变额外功能。需要区分“不做弱关联阻断”和“不收集任何解析信息”，两者成本和产品效果不同。

某条正在使用的规则依赖被关闭的事实时，不能静默删条件或显示完整生效。已有必要事实、流归属和实际结果仍应保持可靠；具体裁剪、提示与测量属于后续设计。Linux开源参考项目尚未指明，本轮不猜选项目，也不据此省略后续Linux适配与资源核查。

## 当前可继续讨论的工作选择

1. 系统hook可用：优先评估系统解析入口的直接名单控制与可见握手补充；地址推断阻断保持可选，53／5353重复处理与旁路需明确。
2. 仅Root：优先可见握手与明文DNS证据，探测直接resolver结果监听；结果监听补关联，不当解析前veto。
3. VPN：按用户后续明确的DNS接管方向推进；进入TUN的查询记录过滤后，由产品缓存或转到DoT／DoH上游。前述“单独作为可选功能”仅是此前建议，已由本次方向取代。

普通用户仍选择“标准防护”；后端在授权范围内使用已验证能力，少数改变DNS行为或扩大地址阻断的选择再单独说明。具体默认、覆盖承诺与性能排名继续决定，本轮不自动制作新原型或实现平台适配。
