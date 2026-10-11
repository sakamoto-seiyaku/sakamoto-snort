# DNS 首版 KISS 候选设计核对

2026-10-07。用户要求三席子代理联网核查候选，重新检验暂定方案。
本文是研究与设计建议，不接受新的正式架构、不修改产品代码，也不声明实现或设备验收完成。
首版范围仍是Root/NFQ与VPN；KSU/libnetd是未来扩展。未读取ADR-0008删除的Snort C++或导入POC源码。

**调查交付后的用户确认：** 继续维持原方案A，即Root socket入口／VPN既有内侧会话接同一DNS核心，上游共用系统socket与VPP事件推进。本文保留候选与证据；替代路线未被选定，A1／A2的内部运输实现也未在本轮冻结。当前方案见[首版模块记录](2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md#2026-10-07首版范围与模块草图)。

## 结论

**共用DNS核心与普通系统socket上游有源码依据；VPN应用侧接入方式仍需单独比较。**
核心不必依赖HEV/lwIP，也不必要求所有查询都从一个IP监听端口进入。
过滤、查询事务、答案缓存、DoT/DoH和结果处理维护一份实现；原应用侧传输及平台socket准备由Adapter承担。
普通系统socket负责内核网络收发；TLS/HTTP、完整DNS答案缓存和查询生命周期仍是核心的实现职责。

当前优先保留“两种入口交付同一DNS核心”的整体路线，理由是本仓已有VPN会话栈，第一方项目也采用这种分工。
VPN内部的直接消息交付与私有socketpair值得定点比较；本轮不冻结哪个实现更少代码、状态或故障路径。
“为了共用而必须同一个kernel listener”没有足够收益依据；非loopback本地listener也不能被笼统宣判不可行。

## KISS 比较依据

- 优先复用实际已有、能够保留同等行为的实现，核算新增协议责任与生命周期，而不是只数目录、库名或代码行。
- 保留完整UDP/TCP DNS处理、已知应用事实和正确回送；省略TCP或将已知UID变成Unknown不能算等价简化。
- 一套政策权威、一套DNS处理实现；代码共用不要求全局可变缓存或跨owner共享运输状态。
- 使用现有VPP owner／事件推进与观察通路，避免为Root初始化整个VPN会话栈或新增运行时／守护进程。

这些是本轮评估依据；没有新的吞吐、CPU、内存或功耗测量。

## 候选比较

| 候选 | 共用位置与主要变化 | KISS判断 |
| --- | --- | --- |
| A：Root内核socket／VPN既有会话分别交消息 | 同一个DNS核心；VPN新增本地DNS会话接点，Root新增重定向与listener | **整体优先。** 复用现有会话与回程，避免另建IP桥。真实local TCP适配仍需实现 |
| A1：VPN直接交消息／stream | 内侧UDP payload、TCP stream直接交核心，答案返回原会话 | fd与内核缓冲较少；需要本地回压、暂停／恢复和关闭处理，不能先认定总代价最小 |
| A2：VPN进程内socketpair交付 | 复用HEV已有fd收发和ring；核心端仍是VPP内的私有Adapter | 可能少改运输代码，无对外listener／新进程；增加pair两端及关闭状态，尚未验证 |
| B：VPN会话桥接同一IP listener | HEV仍处理内侧会话，再连接共用本地监听端口 | 有现成完整socket型DNS服务时才可能省改动；本仓尚无该服务，另增连接、身份关联及平台准备 |
| C：配置DNS直接命中本机非loopback listener | 给VPN本地地址同时配置DNS，尝试使用内核本地投递终止UDP/TCP | 有机制基础，**仍需验证**端口与平台行为；只覆盖该服务地址，不能替代全部自选DNS的TUN接入 |

A1／A2是A内部的运输选择，不是两套DNS核心。socketpair不是新的DNS守护进程，也不是再次连接对外端口。
自行特判VPN UDP、TCP另走会话的方案会增加一套UDP回程与停止状态；首版暂不优先。

## 第一方实现提供了什么证据

| 项目 | 实际路径 | 可借鉴范围 |
| --- | --- | --- |
| Intra | TUN→lwIP；UDP直接`Resolver.Query`，TCP经进程内`net.Pipe`→DNS framing→同一resolver | **消息核心与内侧会话分离有实际实现。** 不需要内部IP listener |
| NetGuard | native TCP/UDP会话→protected系统socket→封包回TUN | 上游socket与应用侧会话是两段；响应阶段域名改写不能当查询前过滤证据 |
| RethinkDNS | 虚拟DNS／port53捕获→gVisor会话→同一resolver→缓存／DoT／DoH | 同一核心接两种运输；配置DNS地址不等于捕获所有自选DNS |

根代理独立读取固定Intra [UDP入口][I1]和[TCP入口][I2]，确认前者直接调用`Query`，后者使用进程内`net.Pipe`而非kernel listener。
这些项目只提供职责分工证据，不建议引入Go/gVisor或移植其源码；Intra的TCP单次Read实现也不作为正确拆帧范本。
各项目完整pin、实际范围及限制见[开源实现报告](2026-10-07_VPN_DNS_UPSTREAM_DESIGN_PATTERNS.md)。

## 需要修正的本地listener判断

Android的`addDnsServer`拒绝loopback／any-local地址，不能直接把VPN DNS设为`127.0.0.1`。[地址检查][A1]
但它不拒绝一个非loopback的VPN本地地址；`addAddress`可以给接口分配这种地址。
根代理独立读取Android16r1 [RouteController.cpp][A2]：`flushRules`保留priority 0的local-input规则。
因此“配置DNS地址命中本机kernel listener”的C候选具有本地路由机制基础，不能从TUN是包接口推导它必然不可能。

这仍不是完整无Root闭环证明：Builder仅配置DNS IP，不能指定任意高端口；本地DNS listener必须能够服务53。
普通应用的端口绑定权限、目标系统路由／防火墙及接口生命周期需要核验；Linux端口权限由namespace阈值与capability决定，不能用一种默认值概括全部Android。[端口合同][K1]
根代理亦核对固定Android16r1 [Zygote能力授予][A3]：`CAP_NET_BIND_SERVICE`授予Bluetooth／NetworkStack等特定UID，不能把VPN DNS配置当普通应用获得此能力的依据。这仍不替代目标系统端口阈值的核验。
即使C成功，它也只处理发到该服务地址的查询；App直接查询其他服务器仍可能进TUN，继续需要A或B一类接入。
C还改变此前“VPN查询经TUN接入”的路线，不能在研究中自动选定或将它当现有运行事实。

TUN包改写后再投递kernel listener是另一个候选，涉及来源准入与回程；本轮不据此新增一套NAT／包注入机制。[既有内核路径核对](2026-10-05_NFQUEUE_TUN_PACKET_INJECTION_BOUNDARY.md)

## 当前代码如何支撑A

Root已有NFQUEUE捕获和verdict；DNS mark／重定向、上下文关联及kernel listener仍待增加。
VPN已有HEV/lwIP TCP/UDP、原应用事实、owner、停止及正常VPP返回图；现有任务连接原目的地，没有现成local DNS会话。
根代理核对[UDP Direct实现](../../third_party/hev/patches/0004-direct-udp-session.patch)：fd的sendmsg／recvmsg不携带sockaddr；A2可作为私有运输候选，但owner的连接、授权与两端关闭分支仍需扩展。
当前[VPP文件接口](../../build-output/pinned-vpp-clean/src/vppinfra/file.h)具有worker定位及读／写／错误回调，[既有驱动](../../src/product/vpp/product_vpn_flow_stack.c)具有timerfd和有界推进；普通DNS上游可以沿用此模式。
这不要求Root初始化／驱动整个HEV owner或lwIP；HEV scheduler是否带来净简化应由具体库接入证明，不能为复用比例先引入。

域名匹配、VPP配置编译、Flow判断和Rust／SQLite观察基础可以复用；DNS阶段事实、关联消费及查询记录仍需新增。
现有Mbed TLS只有密码原语，完整TLS/HTTP／答案缓存也未因“使用系统socket”获得。c-ares有限复用与同Mbed TLS补全方向保留。
执行需要的关联状态留在VPP，SQLite继续是异步历史；查询与业务连接分别判断、分别记录，未知原应用沿ADR-0011允许。
源码复用与未实现接点详见[产品接入报告](2026-10-07_DNS_KISS_PRODUCT_INTEGRATION.md)。

## 本轮建议的收敛层次

继续把A作为首版模块主线：Root socket入口／VPN本地会话入口→同一DNS核心→同一系统socket上游。
保留A1／A2在VPN内部的实现比较，重点看哪种能复用已有TCP收发、保留已知上下文并正确停止；当前不冻结字段或容量。
B与C保留为有明确收益或平台证据时可复议的候选；C的部分系统查询简化不能自动替代完整TUN DNS接管。
KSU未来扩展、mDNS／内网与失败行为的后续设计范围不变；本轮没有开始代码实施或设备验证。

[I1]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/intra/packet_proxy.go#L119-L141
[I2]: https://github.com/Jigsaw-Code/Intra/blob/7bc64a4867ea7531d5f9b27c8169efedb3baea8d/Android/app/src/go/intra/stream_dialer.go#L64-L85
[A1]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/net/VpnService.java#711
[A2]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/RouteController.cpp#1253
[A3]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/jni/com_android_internal_os_Zygote.cpp#2219
[K1]: https://docs.kernel.org/networking/ip-sysctl.html#ip-unprivileged-port-start
