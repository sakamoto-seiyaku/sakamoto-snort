# libnetd_resolv 跨版本稳定性：窄接点与二进制复用分开判断

2026-10-03。抽查 `android-10.0.0_r1`、`android-12.0.0_r1`、`android-14.0.0_r1`、`android-16.0.0_r1` 的官方源码。
未操作设备、编译或安装模块、修改产品/ADR/Plane，未读旧Snort C++/POC；这是发布源码抽查，不能代表全部厂商、Mainline更新构建或实机加载结果。
承接[启动研究](2026-10-03_LIBNETD_KSU_HOOK_RESEARCH.md)与[晚安装研究](2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)。

## 判断

**用户直觉有合理部分：已有DNS决策callback是较窄、持续保留的接点，适合维护一份小政策逻辑并跨版本移植。**
相对此前改framework/services私有smali的大补丁，它需要理解的调用合同更小；这是设计判断，不是“所有Framework公共API都不稳定”的结论。
但“源码小改动可以复用”与“一个替换.so/一组私有偏移在多系统通用”是两件事。抽查支持前者的可行性，不能仅由此保证后者。

## 四个固定快照

实际结构名为 `ResolverNetdCallbacks`，不是另一个可动态注册的App接口。

| 快照 | callback结构与context | 决策入口/公开导出 |
| --- | --- | --- |
| Android10 r1，`system/netd/resolv` | callbacks只有permission/context/log三项；context为app/dns netId/mark、uid、flags六个数据成员 | **没有evaluate_domain_name**；map导出has_nameservers/init。[头][H10]、[map][M10] |
| Android12 r1，`packages/modules/DnsResolver` | 原三项后追加tagSocket/evaluate，共五项；context尾部增加pid | evaluate签名为bool(context const引用,host指针)；map增加gethostbyaddr_from_cache。[头][H12]、[map][M12] |
| Android14 r1，同模块 | 五项callback顺序/签名保持；context数据成员同12，增加toString方法不等于新增数据成员 | 同三公开入口；callback职责扩展到网络访问检查。[头][H14]、[map][M14]、[实现][P14] |
| Android16 r1，同模块 | 五项callback与context数据成员继续保持 | 同三公开入口，保留上述检查。[头][H16]、[map][M16]、[实现][P16] |

12/14/16头文件的callback合同一致：lookup前同步判断，false使查询失败，未提供callback时默认允许；多线程调用、不得sleep或RPC。[H12][H12]、[H14][H14]、[H16][H16]
这为“本地只读政策判断”提供真实的跨版本源码基础；Android10初始快照不具备这个接点，不能直接声称同一方案从10到16都一样。

## 稳定边界确实存在，不能笼统否定ABI

官方Mainline架构要求模块经stable C API/stable AIDL通信；DNS Resolver自Android10以APEX提供。稳定性是模块可独立更新的重要设计条件。[Mainline][D1]、[resolver说明][D2]
12/14/16构建的 `libnetd_resolv` 都声明 `stubs.versions:["1"]`，并启用 `header_abi_checker`、关联公开symbol_file。[构建12][B12]、[构建14][B14]、[构建16][B16]
四份map使用 `LIBNETD_RESOLV` 导出边界，`resolv_init(const ResolverNetdCallbacks*) -> bool` 的公开签名持续存在；增加cache入口没有删除原两入口。[各版map][M10]、[12头][H12]、[16头][H16]
因此不能说“C++实现/不同hash，所以公开ABI必然不兼容”，也不能忽略官方做的接口约束和兼容处理。

头文件“no ABI stability guarantees”注释指resolver依赖的libbinder等库；其方案是把调用留在netd，经callback函数指针传入。[10注释][H10]、[16注释][H16]
它不是一句“整个callback/public ABI毫无保证”的声明；反过来，也没有在这四份结构定义中看到任意未来字段变化的通用承诺。
`ResolverNetdCallbacks`/`android_net_context`没有size/version成员、显式保留槽或动态协商方法；真实兼容依据是已知前缀、追加字段及实现中的条件读取。

10的 `resolv_init` 复制整个三字段结构；12/14/16改为逐字段复制，且仅在设备API>=30时读取tagSocket/evaluate两个尾部字段。[初始化10][I10]、[初始化12][I12]、[初始化14][I14]、[初始化16][I16]
这明确避免在旧API29的netd三字段输入上无条件读新增尾部，是实在的向后兼容处理；不能把它当作支持任意大小结构或任意新callback的机制。
12/14的库min_sdk_version为29，16升为30；公开入口仍在不代表16原样产物仍以API29为支持目标。[B12][B12]、[B14][B14]、[B16][B16]

## 相同签名也要保留变化后的语义

Android12 netd默认evaluate只返回true；14/16先 `isUidAllowed(app_netid,uid)`，源码要求OEM保留该分支。[netd12][N12]、[netd14][N14]、[netd16][N16]
14/16 resolver注明U起该callback也判断UID对网络的访问；反向解析会以host=nullptr调用，以保留网络检查。[P14][P14]、[P16][P16]
移植时应先链式保持原callback结果，再叠加产品政策；不能把12的“默认true”逻辑原样覆盖14/16而放开原系统deny。
普通名字lookup的bool veto仍相似，所以业务判断代码可保持很小；网络权限、nullptr、context字段和实际调用覆盖属于版本适配，不是另建规则引擎。

## 哪一种跨版本复用有证据

| 做法 | 有依据的稳定部分 | 仍需核对的边界 |
| --- | --- | --- |
| 按目标源码维护小callback补丁 | 12/14/16同签名与同步合同；原政策逻辑可共用 | 相应系统/OEM源码、原检查、构建/发布；不能直接跨过10缺少入口的问题 |
| 使用公开入口、满足支持范围的适配库 | Mainline的接口稳定设计、stubs/ABI检查、API门控 | 完整依赖闭包、minSDK、ABI与运行行为；源码证据不宣布某自制.so已通过兼容验证 |
| 同一个整库替换所有版本/APEX | 公开符号可能兼容，不应预设必失败 | 它还替换cache/PrivateDNS/Binder/安全修复等整份实现；需证明保留原模块能力/OEM行为与更新适配 |
| 用私有字段/函数偏移晚安装hook | 内部概念持续存在 | 隐藏符号、优化后的函数、数据布局位置、CFI/BTI及进程映射；没有固定地址/偏移合同 |

`gResNetdCallbacks`虽在各版内部存储，但map均把其他符号设为local；公开入口稳定没有把这个变量或static包装函数变成公开安装接口。[M10][M10]、[M12][M12]、[M14][M14]、[M16][M16]
12/16的包装函数都逐次读取该内部指针；这证明决策点持续存在，不证明私有地址、线程安全热写或某个函数体在所有ELF都可按同样方式定位。[调用12][P12]、[调用16][P16]
`resolv_init`在这些版本都继续启动resolver服务，不能为了热更新callbacks重复调用；前轮[晚安装研究](2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)已核查其服务生命周期副作用。

## Mainline改变的是支持单位

Android10起Mainline允许模块在正常Android发布周期之外更新；同一OS大版本可能遇到不同active resolver版本，厂商也可通过OTA交付。[Mainline更新][D1]
所以适配单位应是“受支持OS/API范围＋实际resolver/APEX构建及OEM接口语义”，不只是Android12/14/16一个整数；不能凭一条OS标签推断私有挂点不变。
只读对照原模块版本/Build ID及接口特征，再对已验证相同的构建扩大支持，是候选维护方式；不同hash只说明产物不同，不自动等于公开ABI冲突。
当前官方还注明Android11及以下Mainline支持已于2025Q4结束；本轮10快照用于历史兼容抽查，不是承诺旧设备今天仍获得模块更新。[官方当前说明][D1]

本轮结论：可以把12–16的现有callback当较稳定的**源码移植接点**；受管理的公开APEX/netd接口也有真实稳定设计。整库通刷和私有hook通用则需要另外的二进制/模块验证，不能由前两点自动得出。

[H10]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-10.0.0_r1/resolv/include/netd_resolv/resolv.h#70
[H12]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-12.0.0_r1/include/netd_resolv/resolv.h#59
[H14]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-14.0.0_r1/include/netd_resolv/resolv.h#60
[H16]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/include/netd_resolv/resolv.h#68
[M10]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-10.0.0_r1/resolv/libnetd_resolv.map.txt#21
[M12]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-12.0.0_r1/libnetd_resolv.map.txt#21
[M14]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-14.0.0_r1/libnetd_resolv.map.txt#21
[M16]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/libnetd_resolv.map.txt#21
[I10]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-10.0.0_r1/resolv/DnsResolver.cpp#27
[I12]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-12.0.0_r1/DnsResolver.cpp#29
[I14]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-14.0.0_r1/DnsResolver.cpp#31
[I16]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolver.cpp#31
[B12]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-12.0.0_r1/Android.bp#153
[B14]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-14.0.0_r1/Android.bp#182
[B16]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/Android.bp#250
[N12]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-12.0.0_r1/server/main.cpp#91
[N14]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-14.0.0_r1/server/main.cpp#99
[N16]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/main.cpp#98
[P12]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-12.0.0_r1/DnsProxyListener.cpp#599
[P14]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-14.0.0_r1/DnsProxyListener.cpp#701
[P16]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#774
[D1]: https://source.android.com/docs/core/ota/modular-system
[D2]: https://source.android.com/docs/core/ota/modular-system/dns-resolver
