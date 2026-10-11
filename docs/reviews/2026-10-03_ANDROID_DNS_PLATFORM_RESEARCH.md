# Android DNS事件、Root与VPN处理边界

2026-10-03。本轮重新读取Android官方API、AOSP源码与RFC；未操作设备，未修改产品代码，未读取已删除的Snort C++实现或归档。
源码主要固定在`refs/tags/android-16.0.0_r1`，作为可复核快照，**不声称等于所有设备当前系统/厂商修改/Mainline模块版本**。本文的产品建议均为待验证提案，不自动进入正式模式合同。

## 结论

1. 系统确有“主机名→地址、UID、网络”的DNS结果事件，但通常是Binder回调，不是普通App订阅的逐条解析广播。
2. `IpConnectivityMetrics.addNetdEventCallback`要求调用者UID恰好为1000；**UID0也不通过此项检查**。它只有三个系统用途槽，不能作为普通订阅扩展点。[源码guard](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/connectivity/IpConnectivityMetrics.java#342)
3. **另有不同路径**：`IDnsResolver.registerEventListener`检查网络栈权限；AOSP权限链允许真正UID0调用者，监听者集合可以加成员而不替换系统监听者。因此“任何Root都保证能监听”和“Root必须hook才能监听”都过强。[resolver注册](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolverService.cpp#132)、[多监听者](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/ResolverEventReporter.cpp#113)
4. 这些事件是**解析完成后的观察**，没有allow/deny返回值；不能据它保证解析前阻止、修改返回答案，或阻止解析后立即出现的首次连接。[结果发送与事件上报顺序](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#951)
5. VPN可处理实际路由进TUN的明文TCP/UDP DNS；`addDnsServer`只是配置解析器地址，不会实现DNS代理。DoT/DoH的加密内容并不因通过TUN而变成明文。[VPN指南](https://developer.android.com/develop/connectivity/vpn)、[Builder API](https://developer.android.com/reference/android/net/VpnService.Builder#addDnsServer(java.net.InetAddress))

## 四种机制不可混称“系统DNS广播”

| 机制 | 进入条件 | 得到什么 | 能否解析前决定 |
| --- | --- | --- | --- |
| ConnectivityMetrics的`INetdEventCallback` | Binder调用UID=1000，合法系统callerType | 系统DNS结果与UID/netId等 | 否，oneway结果通知 |
| DnsResolver的`INetdEventListener` | 网络栈权限链；UID0辅助进程仍需设备访问许可 | resolver调用事件，包含hostname/IP/UID/netId | 否，oneway结果通知 |
| DPM `DnsEvent`/日志就绪广播 | device owner、managed-profile owner或获委派应用 | 批量日志；就绪广播只带批次信息 | 否，取证用途与批处理延迟 |
| VPN TUN中的明文DNS | VPN授权、应用覆盖、路由和地址族覆盖 | 实际DNS报文，含问题/响应资源记录 | 可以在转发/返回前处理，前提是该查询实际受控 |

表格最后一行是由VPN读写IP包与DNS协议结合得出的能力推论；本轮没有实现或性能实测。DPM企业管理身份不等于Sakamoto产品词汇里的“标准托管保护”。

## ConnectivityMetrics：硬UID检查与固定槽

`enforceNetdEventListeningPermission()`读取`Binder.getCallingUid()`，不等于`Process.SYSTEM_UID`即抛`SecurityException`；注册、移除都调用它。`SYSTEM_UID=1000`，`ROOT_UID=0`。[guard](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/connectivity/IpConnectivityMetrics.java#342)、[UID定义](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/os/Process.java#71)

`NetdEventListenerService`只接受ConnectivityService、DevicePolicy、NetworkWatchlist三个callerType；`mNetdEventCallbackList[callerType]=callback`是替换该槽。即使以额外系统身份注册，也不能不加分析地占用现有用途槽。[槽与注册实现](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/connectivity/NetdEventListenerService.java#110)

`INetdEventCallback`是隐藏AIDL的`oneway`接口；Android16快照的DNS字段为netId、eventType、returnCode、hostname、IP数组、地址总数、timestamp、UID。它不是一个可返回阻止决定的解析钩子。[接口](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/net/INetdEventCallback.aidl#20)

## DnsResolver直接监听：Root可行路径的精确边界

`DnsResolverService.registerEventListener`执行`ENFORCE_NETWORK_STACK_PERMISSIONS`，接受`NETWORK_STACK`或`MAINLINE_NETWORK_STACK`，然后加入`ResolverEventReporter`。此处不是ConnectivityMetrics的UID1000专检；两者不能互相套用。[注册与权限宏](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolverService.cpp#49)

实际许可链如下，全部在本轮读取同一tag核对：

1. resolver `checkAnyPermission`对UID1000直接放行，其他UID调用netd提供的`check_calling_permission`。[resolver检查](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolverService.cpp#151)
2. netd `main.cpp`将该回调绑定到`android::checkCallingPermission`。[netd绑定](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/main.cpp#84)
3. libbinder取原调用PID/UID，向`permission`服务的`IPermissionController.checkPermission`查询。[native调用链](https://android.googlesource.com/platform/frameworks/native/+/refs/tags/android-16.0.0_r1/libs/binder/IServiceManager.cpp#474)
4. AMS PermissionController调用AMS `checkPermission`，最终进入`ActivityManager.checkComponentPermission`；后者对root/system appId放行。[AMS](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/am/ActivityManagerService.java#6045)、[root/system特判](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/app/ActivityManager.java#5207)

因此，在这份AOSP中，**真正由UID0辅助进程发起直接resolver Binder注册**有许可依据；“App被su授权”本身不把它所有进程和Binder调用变成UID0。native的`PermissionCache`另有root短路，但本条netd链用的是`android::checkCallingPermission`，本文没有拿错误的短路函数作证明。

`ResolverEventReporter`使用监听者集合。系统默认`netd_listener`加入同一集合；新增不同Binder会`insert`，相同Binder重复返回`EEXIST`，死亡时移除。**直接resolver订阅是可加的，不等于覆盖系统唯一监听者。**[默认监听者与集合](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/ResolverEventReporter.cpp#55)

仍不能承诺所有Root设备：SELinux对UID0同样执行强制访问控制；service查找、Binder调用与回调、接口版本、Mainline更新和厂商实现都须检测。本文未验证KernelSU/某OEM是否实际允许这些操作。[官方SELinux说明](https://source.android.com/docs/security/features/selinux)

这种结果订阅不必修改framework；framework/应用库/netd钩子若改变调用行为、阻止原解析或改答案，则是另一机制。具备Root启动能力与已安装特定系统钩子不能写成同一种能力。

## 事件负载与domain→IP推导限制

直接`INetdEventListener.onDnsEvent`字段为netId、eventType、returnCode、latencyMs、hostname、IP数组、总地址数、UID；数组最多10项。**接口没有TTL、完整CNAME链、每项RR类型/生命周期或原始DNS答案。**[Android16接口](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/staticlibs/netd/binder/android/net/metrics/INetdEventListener.aidl#24)

callback的timestamp由framework转发层读取当前时间加入；直接resolver接口本身没有同一timestamp字段。把两个接口的负载混用会掩盖来源差异。[转发实现](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/core/java/com/android/server/connectivity/NetdEventListenerService.java#214)

`DnsProxyListener`在resolver函数返回、向客户socket发送结果之后才调用`reportDnsEvent`。上报还经过oneway Binder，不能保证消费者先更新映射、App才发首次连接。缓存命中仍可能经过resolver调用而被上报；绕过该调用的App内部缓存、直接IP或自带DNS实现不能据此保证覆盖。[上报顺序](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#951)、[系统解析器范围](https://source.android.com/docs/core/ota/modular-system/dns-resolver)

产品推论：这些事件可作为带UID/netId/时间的解析关联证据；不能从无TTL事件创建“永久且唯一”的IP→域名事实，也不能把共享IP上的其他访问全部自动归属于最近一次域名。wire DNS答案能提供RR TTL，事件接口则不能补造该信息。[DNS RR与TTL定义](https://datatracker.ietf.org/doc/html/rfc1035#section-3.2.1)

`onPrivateDnsValidationEvent`报告DNS提供者验证状态，里面的hostname是验证对象，不是每一个应用正在访问的业务域名。[接口说明](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/staticlibs/netd/binder/android/net/metrics/INetdEventListener.aidl#58)

## DPM日志：存在广播，但不是逐条DNS广播

公开API限定device owner（Android8起）、其委派应用（Android10起）、managed-profile owner及其委派应用（Android12起）；profile owner日志只包含工作资料活动。开启网络日志不是普通device-admin激活或Root授权的同义词。[API合同](https://developer.android.com/reference/android/app/admin/DevicePolicyManager#setNetworkLoggingEnabled(android.content.ComponentName,%20boolean))

AOSP服务另外核对调用者确为default device owner、managed-profile owner或network-logging delegate；不是任意收到action字符串的App就能取日志。[DPMS授权检查](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/devicepolicy/java/com/android/server/devicepolicy/DevicePolicyManagerService.java#18834)

`ACTION_NETWORK_LOGS_AVAILABLE`通知批次就绪；接收者取得batch token，再`retrieveNetworkLogs`。AOSP handler批量上限1200，时间阈值90分钟，另有30分钟alarm窗口，最多留5批；不可承诺每次解析即时送到。它向owner/profile owner（或委派接收者）发送通知，并非全局公开DNS地址广播。[开发指南](https://developer.android.com/work/dpc/logging)、[handler阈值与通知](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/devicepolicy/java/com/android/server/devicepolicy/NetworkLoggingHandler.java#49)

公开`DnsEvent`包含主机名、IP列表/总数、包名、时间和事件ID；不是原始报文。`NetworkLogger`转换时不把netId/returnCode/latency传入DnsEvent。日志API适合审计，不能借此给每次解析实时allow/deny。[DnsEvent API](https://developer.android.com/reference/android/app/admin/DnsEvent)、[转换源码](https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/services/devicepolicy/java/com/android/server/devicepolicy/NetworkLogger.java#59)

## VPN：配置DNS服务器、捕获DNS与代理DNS是三个动作

`VpnService`建立本地TUN文件描述符，读取路由到VPN的IP包，写回包交给系统。应用覆盖、IPv4/IPv6路由与绕过配置决定什么流量实际进入；不能把“VPN已启动”直接替换为“所有DNS可见”。[官方VPN指南](https://developer.android.com/develop/connectivity/vpn)

`Builder.addDnsServer`把numeric DNS地址写入VPN网络配置，未设置时使用默认网络DNS；它不会自动创建UDP/TCP监听器、上游转发器或响应合成器。地址族允许与路由覆盖还须正确设置。[Builder API](https://developer.android.com/reference/android/net/VpnService.Builder#addDnsServer(java.net.InetAddress))

若明文UDP/53或TCP/53确实进入TUN，可以解析问题并在发往上游前应用策略；也可解析响应中的A/AAAA与TTL。TCP DNS有长度前缀和流语义，不能只把UDP处理套用到单个TCP包。[RFC1035运输](https://datatracker.ietf.org/doc/html/rfc1035#section-4.2)、[RFC7766 TCP要求](https://datatracker.ietf.org/doc/html/rfc7766)

若VPN选择本地虚拟DNS地址并自行转发，才构成受控DNS代理；如何响应拒绝、上游socket的`protect()`、超时/重试与缓存均是额外实现合同。本轮没有证明只设置一个DNS地址就完成这些工作。[VPN socket与TUN职责](https://developer.android.com/develop/connectivity/vpn)

## Private DNS与应用自带加密DNS

DoT的DNS在TLS内，通常TCP/853；DoH把DNS封装在HTTPS内。TUN外层能看到连接地址/端口不等于能读QNAME；TLS连接的SNI若可见，通常指DNS解析服务，不是加密查询里的目标域名。[RFC7858](https://datatracker.ietf.org/doc/html/rfc7858#section-3.1)、[RFC8484](https://datatracker.ietf.org/doc/html/rfc8484#section-4)

Android不能笼统写“Private DNS只有DoT”：Google官方已在2022发布DoH3，经模块更新用于支持服务器；Android16 DnsManager也有`dohParams`配置。该历史发布不能证明每台设备今天启用相同提供者或协议。[Google官方发布](https://security.googleblog.com/2022/07/dns-over-http3-in-android.html)、[DnsManager配置](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/connectivity/DnsManager.java#503)

也不能宣称VPN一开Private DNS就必然关闭：当前ConnectivityService按network capabilities决定Private DNS配置，判定并非简单排除全部VPN网络；实际模式、网络能力及版本须测。[配置入口](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/service/src/com/android/server/ConnectivityService.java#5350)、[判定函数](https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/staticlibs/device/com/android/net/module/util/NetworkMonitorUtils.java#71)

系统resolver结果事件在加密传输之后仍知道主机名/地址，故“网包看不到明文”不等于“被授权的系统结果监听看不到”。相反，App独立DoH绕过系统resolver，不能保证出现在这些系统事件里。[系统resolver职责](https://source.android.com/docs/core/ota/modular-system/dns-resolver)、[DoH协议](https://datatracker.ietf.org/doc/html/rfc8484)

## mDNS是另一作用域

mDNS主要用UDP/5353，IPv4多播224.0.0.251与IPv6 ff02::fb，`.local`具有本地链路语义。不能把它当普通上游UDP/53统一重定向或默认阻断；发现、局域网设备与IPv6路径应另作合同。[RFC6762](https://datatracker.ietf.org/doc/html/rfc6762#section-3)

Android16 resolver可对`.local`走mDNS路径，源码也单独标记相关事件统计；因此本报告没有声称“所有mDNS都永远无系统事件”。应用自己发多播、系统NSD发现与resolver域名查询仍须分开核对。[Android16实现](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#323)

## 对标准保护候选的约束，尚未确认实现

- 可保留“普通Root默认用可见TLS/SNI及被动明文DNS证据”的候选，但明文DNS不保证覆盖；事件订阅应按设备探测增加能力，不能无证据当作所有Root的保底。
- “DNS名单在请求发出前决定”要求实际持有查询转发/返回路径；结果监听可补关联与观察，不能代替前置拦截。framework或resolver调用钩子属于另一个能力层。
- VPN DNS代理可以提供受控查询入口，但协议覆盖、Private DNS/自带DoH、旁路、mDNS与上游生命周期都要明确；不能由`addDnsServer`推导完成。
- 源码证明的是guard、负载和时序；没有测量Root Binder监听、TUN DNS代理、映射维护的CPU/电量/延迟，任何“更快/零额外开销/覆盖全域名”的结论仍待验证。

最小后续验证应分别检查真实helper UID、resolver服务/双向Binder访问、重启后监听恢复、系统与自带加密DNS、缓存命中与事件时序，以及只影响A而保留B/C的域名误伤案例；本轮未启动这些实验。
