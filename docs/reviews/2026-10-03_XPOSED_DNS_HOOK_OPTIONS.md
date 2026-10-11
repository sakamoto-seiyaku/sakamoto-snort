# Xposed/LSPosed 能否替代 libnetd 整库改造

2026-10-03。有限研究，承接[晚安装 hook](2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)；AOSP 固定 `android-16.0.0_r1`，LSPosed实现证据固定 `v1.9.2`，当前状态另查官方仓库/API/Wiki。
未操作设备、安装或测试框架/模块、编译系统、修改产品/ADR/Plane、读取旧Snort daemon；以下是功能边界与候选，不是稳定实现结论。

## 直接回答

**可以研究Xposed路线，通常能省掉APK反编译和系统resolver整库替换，但它主要是在被注入的App进程中拦解析调用。**
LSPosed基于ART和Riru/Zygisk，具有App及system_server的注入入口；独立由init启动的 `/system/bin/netd` 不在这两个入口内。[官方定位][X1]、[注入入口][X2]、[netd启动][A1]
Native Hook API是在已加载模块的目标进程内hook native函数；官方例子从目标App的load-package回调 `System.loadLibrary`，不是全系统native服务的远程注入器。[Native Hook][X3]
因此“用LSPosed native API”不等于直接进入netd/libnetd_resolv；若仍要改独立netd，上一份研究的远程注入/版本绑定约束不会消失。
KSU和Xposed也不互斥：KSU可提供Root，另一个Zygote注入框架负责Xposed能力；不能说换成Xposed就无需Root或不会bootloop。

## 官方版本与组合证据

截至本轮读取，LSPosed官方latest stable为 `v1.9.2`，发布于2023-10-11；README标示Android8.1–14，不是Android16支持声明。[官方发布][X4]、[支持范围][X1]
GitHub API显示仓库 `archived=false`；默认master最新commit为2024-01-07。2026的pushed_at/Wiki编辑不等于新的稳定版本或Android16适配完成。[仓库状态][X5]、[master提交][X6]
因此本轮不把它说成“已归档”，也不把官方文档仍可访问说成当前Android16已获维护和支持；未推荐未经源码核对的fork。
KernelSU官方FAQ明确没有内建Zygisk，并提到外部ZygiskNext配合LSPosed；必须按KSU、外部Zygisk、LSPosed、Android/ART及进程ABI的具体版本验证。[KSU FAQ][X7]
本轮访问FAQ所指ZygiskNext仓库返回404，未取得其当前发布身份；这只是此次访问限制，不能据此断言项目不存在，更不能宣布该组合已经可用。

| API类别 | 官方接口/入口区别 | 本题影响 |
| --- | --- | --- |
| 传统XposedBridge API | `IXposedHookLoadPackage` 等，`assets/xposed_init`；旧Native Hook例子使用 `assets/native_init` | 可在load-package时选目标；不能把SDK与现代接口混用。[传统API][X8]、[Native例子][X3] |
| 现代Xposed API | `XposedModule`、interceptor chain；`META-INF/xposed/java_init.list`/`native_init.list`与scope.list，声明min/target API | 应以实际框架支持的API版本选择；现代Wiki不是v1.9.2已支持全部新签名的证明。[现代文档][X9] |

## DNS拦截层与实际缺口

| 候选入口，均要求目标进程已加载hook | 能取得/判断什么 | 明确漏掉什么 |
| --- | --- | --- |
| Java `InetAddress.getByName/getAllByName`及network-specific入口 | Java调用的hostname，原路径继续时保留缓存/解析 | JNI直接调用libc、自带解析器；只hook默认两个方法还漏`Network`调用路径。[InetAddress][A2]、[Network][A3] |
| Java `DnsResolver.query/rawQuery`各重载 | 名字/类型或原始DNS问题；显式Network/flags | libc/NDK直调、独立DoH/DoT/UDP客户端；raw字节入口需正确理解问题，不能只查String重载。[DnsResolver][A4] |
| App内native `getaddrinfo` | 经过该公开libc入口的JNI/native域名解析 | Java自身cache命中、直接fornet路径、raw DNS API及自带DNS/IP路径。[libc调用][A5] |
| native `res_query`及实际使用的res_n*路径 | 经过旧libc resolver函数的名字/问题 | 它不是所有getaddrinfo/NDK解析的共同入口；还须核对实际导出名与调用链。[旧resolver][A6]、[符号表][A7] |
| 公共NDK `android_getaddrinfofornetwork`、`android_res_nquery/nsend` | 显式network handle，地址查找或raw请求 | 未经这些入口的自带解析；仅hookgetaddrinfo不能覆盖这些独立入口。[NDK合同][A8]、[实现][A9] |

注意名字不同：`android_getaddrinfofornetwork` 是公共NDK接口，内部调用libc的 `android_getaddrinfofornet`；后者在libc map中标为APEX用途，不当通用App SDK。[NDK实现][A9]、[libc表][A7]
固定AOSP中，App libc通过 `dnsOpenProxy` 连接 `/dev/socket/dnsproxyd`，向netd发请求；这个路径不经system_server的Java `InetAddress`。[App请求][A10]、[socket连接][A11]
**只在system_server勾一个系统scope，不能拦所有App-native DNS。** 它只能影响system_server自身或确实被所选Java服务入口处理的调用，不能把每个系统网络服务都当解析入口。

`Inet6AddressImpl`先查(host,netId)的Java AddressCache，再调用 `Libcore.os.android_getaddrinfo`。[缓存时序][A12]
所以App Java入口先判政策可覆盖仍经过该方法的缓存命中；只在native层拦截会漏这些命中。允许后执行原方法，不必重做cache或TLS/DNS客户端。
App自己的地址cache、已经持有的IP/连接、直接IP访问不产生这些新解析调用；切换政策不会自动撤销它们。
自带DoH/DoT可能只在启动时为解析器地址调用一次系统解析，业务QNAME在其加密载荷中；自带UDP DNS也可完全绕过上述入口。SNI/包层补充仍须显示其可见范围，不能承诺全部域名。

## Scope、归属和网络上下文

LSPosed要求scope，可提供推荐包名列表，但用户/框架实际启用范围决定模块注入哪些App；推荐scope不等于全设备覆盖。[scope文档][X10]
固定实现按processName+uid取模块，scope数据库含package和user_id，system_server单独处理。[scope实现][X11]
新增App、其他用户/工作资料、辅助/isolated/SDK sandbox进程必须分别确认覆盖；不可从一个主进程成功推导所有进程被注入。
已有运行进程也不能仅因后来勾scope便承诺自动热插；当前正常注入发生于进程specialize/模块装载阶段，重新启动需求依具体框架判断。[装载入口][X2]
native模块须覆盖实际目标进程ABI；官方例子使用multiArch，不能从手机为arm64推成每个App进程都是64位。[native打包][X3]

App内可直接取得该执行进程 `getuid`/`Process.myUid`，比“前台App是谁”可靠，也不把AID_DNS误当普通业务App。[进程UID][A13]
它仍不是唯一包名或原始委托调用者：共享UID、隔离进程和代别人工作的服务要单独归属；system_server内取到的1000不是所有请求App的UID。
`Network`/NDK显式参数可保留真实已知上下文；默认InetAddress或nullable Network入口当下未确定实际网络时记unknown，保留原系统选网。
network handle与netId不是同一个数字；process DNS/network binding会影响原解析，不用前台App/当前Wi-Fi猜值。[Network handle][A3]、[NDK绑定合同][A8]

## 本题建议的窄路线

1. 先选择已证支持的框架组合和App scope，研究Java公共解析入口；安装hook后默认不启用产品判断，待后台防护Runtime generation ready才使用本地政策。
2. 政策来自[ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md)下VPP已编译active配置的只读DNS阶段投影；每个进程不维护第二份editable规则或priority engine。
3. 放行继续原resolver/cache/PrivateDNS/原上游；本路线不在每个被hook App里建HEV、c-ares请求channel、新DNSclient或TLS连接。
4. 只对已验证的native调用补公共libc/NDK符号hook，严格按进程ABI、框架native API及实际调用链适配；不追求改一个函数便覆盖所有native clients。
5. 配置/生命期异步传递，本地查询判断有界；关闭UI不等于后台Runtime停止，Runtime失联/政策未就绪时建议原系统行为，不能回退绕开原网络权限限制。

Java异常、异步executor/callback、取消与native errno/返回值是不同合同；拒绝需要各入口适配，不能统一return null或把产品拒绝塞进共享上游答案cache。本轮不冻结拒绝码或IPC字段。
App入口提前拒绝时请求没有到netd，系统结果listener不会替产品生成该次阻断原因；本地记录应有界、非阻塞，异步送回产品，消费者失败不能挂住App解析。
反射类/方法与公开native符号通常不要求反编译APK、重签APK或替换系统.so；仍需API重载、ART优化/inlining、模块API和native hook适配。[传统hook][X12]、[现代deopt文档][X9]
Xposed框架本身接入Zygote/system_server启动链，仍有ART/注入/框架启动风险；App-only scope可缩小本产品hook范围，但不是“装Xposed没有bootloop”的保证。[框架入口][X2]
native hook的CFI/BTI与实际映射约束仍见[前轮研究](2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)，不能被Native Hook API这个名称消除。

本轮判断：**Xposed更适合免整库替换的逐App系统DNS调用控制候选；不等于单点libnetd全局hook。** Android16组合、各scope覆盖和native补充未验证时，应报告有限能力；不宣布实现稳定或资源最省。

[X1]: https://github.com/LSPosed/LSPosed#supported-versions
[X2]: https://github.com/LSPosed/LSPosed/blob/v1.9.2/magisk-loader/src/main/jni/api/zygisk_main.cpp#L312
[X3]: https://github.com/LSPosed/LSPosed/wiki/Native-Hook
[X4]: https://api.github.com/repos/LSPosed/LSPosed/releases/latest
[X5]: https://api.github.com/repos/LSPosed/LSPosed
[X6]: https://github.com/LSPosed/LSPosed/commit/df74d83eb03a44cc6ad268841ac2ada28d077c77
[X7]: https://kernelsu.org/guide/faq.html#does-kernelsu-support-xposed
[X8]: https://api.xposed.info/reference/de/robv/android/xposed/IXposedHookLoadPackage.html
[X9]: https://github.com/LSPosed/LSPosed/wiki/Develop-Xposed-Modules-Using-Modern-Xposed-API
[X10]: https://github.com/LSPosed/LSPosed/wiki/Module-Scope
[X11]: https://github.com/LSPosed/LSPosed/blob/v1.9.2/daemon/src/main/java/org/lsposed/lspd/service/ConfigManager.java#L738
[X12]: https://api.xposed.info/reference/de/robv/android/xposed/XposedHelpers.html
[A1]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/netd.rc#1
[A2]: https://android.googlesource.com/platform/libcore/+/refs/tags/android-16.0.0_r1/ojluni/src/main/java/java/net/InetAddress.java#1103
[A3]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/framework/src/android/net/Network.java#144
[A4]: https://android.googlesource.com/platform/packages/modules/Connectivity/+/refs/tags/android-16.0.0_r1/framework/src/android/net/DnsResolver.java#196
[A5]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/dns/net/getaddrinfo.c#561
[A6]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/dns/resolv/res_data.cpp#109
[A7]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/libc.map.txt#1474
[A8]: https://developer.android.com/ndk/reference/group/networking
[A9]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/native/android/net.c#125
[A10]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/libc/dns/net/getaddrinfo.c#425
[A11]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/client/NetdClient.cpp#305
[A12]: https://android.googlesource.com/platform/libcore/+/refs/tags/android-16.0.0_r1/ojluni/src/main/java/java/net/Inet6AddressImpl.java#115
[A13]: https://android.googlesource.com/platform/frameworks/base/+/refs/tags/android-16.0.0_r1/core/java/android/os/Process.java#890
