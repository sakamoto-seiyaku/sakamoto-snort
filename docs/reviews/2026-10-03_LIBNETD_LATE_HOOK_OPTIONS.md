# libnetd：晚启用政策与晚安装 hook 的选择

2026-10-03。有限追加研究，复用[启动风险报告](2026-10-03_LIBNETD_KSU_HOOK_RESEARCH.md)；AOSP 固定 `android-16.0.0_r1`。未操作设备、安装模块、编译、修改产品/ADR/Plane或读取旧 Snort C++。
用户新约束：不要求 App 防护 Runtime 就绪前拦截 DNS；重点避免 KSU 整库早期覆盖把系统启动带进故障链。
本轮研究的是系统 resolver 前置本地判断，继续使用其 cache、Private DNS 和原上游；已接受的 VPN HEV/MbedTLS/c-ares 路线不搬进 netd。

## 先把“晚”分成两个不同动作

| 方案 | App/Runtime 就绪后发生什么 | 对早期整库加载风险的效果 |
| --- | --- | --- |
| 开机已加载替换库/shim，默认直通 | 只打开政策开关 | 避免早期政策阻断；不消除早期ELF、依赖、constructor、resolver初始化错误 |
| 原系统照常启动，后来才给当次netd PID安装小hook | 定位、注入/补丁，再发布本地政策 | 可避开本次开机的外部整库加载；安装失败仍可能当场击穿netd |
| 可信ROM内原生callback集成 | 控制面异步发布有效政策 | 可提供受维护的同步/生命周期接口；需要ROM源码与平台发布能力 |

**本轮建议**：优先验证第二条能否在已知 resolver build 上成立；它符合新约束，但目前只有源码接点证据，没有目标设备可成功晚安装的证据。
第一条只是“晚启用”，应保留为另行选择的适配方案，不能作为避免早期整库覆盖风险的默认答案。
晚 bind APEX 路径不会改变 netd 已映射的 inode；为使新库生效而重启 netd 又会触发 zygote 重启，不能把它包装成无影响的晚安装。[映射][R1]、[netd.rc][R2]

## 固定源码允许定位到哪里

`gResNetdCallbacks` 在 resolver 内是普通全局结构；`resolv_init` 在初始化时复制字段，每次 `evaluate_domain_name` 再读取其中函数指针。[存储/初始化][R3]、[调用][R4]
这说明存在进程内决策接点，**不说明并发写这个字段是受支持的 API**；源码读取不是 atomic load，也没有热更新 setter 的发布/回收协议。
resolver map 只导出三个 `resolv_*`，其余 `local:*`；`gResNetdCallbacks` 不属于可通过普通 `dlsym` 使用的动态公开符号。[导出表][R5]
resolver 包装函数是 `static`，netd 原 `evaluateDomainNameCallback` 位于匿名 namespace；源码名字不能当发行 ELF 中可直接按名查找的入口。[包装][R4]、[netd 源码][R6]
是否保留 `.symtab`、独立函数体或可定位数据布局，必须检查实际原库/netd ELF；隐藏、strip、优化后的地址和结构偏移本轮都未证。
`IDnsResolver` 没有注册决策 callback 的 setter；只有结果listener等方法。监听事件不能升格为前置veto。[Binder接口][R7]

**公开 `resolv_init` 也不能当 late setter**：它先改多项 callbacks，随后调用 `DnsResolver::start()` 启动 socket listener 和 Binder service，后者再 `addService`。
这不是单字段热更新或失败时回滚的事务；重复调用有服务生命周期副作用，本轮没有安全重入保证。[init/start][R3]、[Binder启动][R8]
在进程已启动后只 hook `resolv_init` 的入口，也不会自动介入后续每次查询，因为其正常初始化调用已经完成。[netd初始化][R6]

## 小 shim 晚安装的两种候选接点

| 候选 | 必须解决的具体工作 | 可得的最窄判断 |
| --- | --- | --- |
| 找到实际callback字段，保存原值后改为shim | 原库Build ID/映射基址/私有布局定位；将shim加载进netd；安装时线程静止与安全发布；原函数和shim生命周期 | 可不改resolver文本，但不是“写一个指针就安全”；普通结构的并发读写没有源码合同 |
| 找到原netd callback或保留的resolver包装函数，做函数hook | 实际函数地址/签名；代理与原函数trampoline；正在执行线程、指令修改和回收；厂商原callback链 | 不依赖公开setter；接点可能被隐藏或优化，须按build验证，不能假定PLT导出入口存在 |

shim必须真的运行于netd地址空间；Root helper自己 `dlopen` 或App加载库不会改变另一进程的callback。
没有现成可信进程内装载入口时，需要远程注入/ptrace一类侵入动作，包含进程控制和loader执行；不能承诺无暂停、无崩溃或“Root即可”。
还需核对注入helper实际SELinux权限、netd加载payload的文件标签/映射许可；固定policy限制netd对App的Binder交互，Root授权不自动建立控制通路。[netd policy][R9]
函数hook改可执行映射还涉及 execmod 等政策约束，不能从su能运行推导netd有同一权限。[domain policy][R10]

固定源码的resolver和netd都声明 `sanitize.cfi:true`；代理签名与跨DSO调用目标必须核对，类型错误可abort。真实厂商ELF是否启用同一构建要求仍待检查。[resolver构建][R11]、[netd构建][R12]、[CFI说明][R13]
AArch64 linker按实际GNU property决定应用 `PROT_BTI`；间接目标/跳板须与真实保护状态一致，不能断言所有arm64都开启或都不受约束。[BTI加载][R14]
仅参考一个工具的边界：ShadowHook官方支持arm32/arm64的进程内地址/名字hook，调用前要在该进程初始化；其“CFI unwind兼容”不是netd远程注入和所有CFI调用目标的保证。本轮不选库或安装。[工具官方说明][R15]

以上是已知接点的安装约束，不是要求关闭系统防护的建议；若目标无法在保留原检查的条件下可靠适配，就不启用该hook。

## 判定与生命周期应保持很小

原callback返回false立即保持false；原callback允许后才做产品DNS阶段判断。必须保留 `isUidAllowed` 和设备已有OEM行为，Runtime失联回退不能解除系统原deny。[原检查][R6]
callback合同要求并发安全且禁止sleep/RPC；查询中只做有界本地判断，配置、通知、记录消费在外部异步完成。[合同][R16]
候选输入是当前VPP已编译有效政策的只读DNS阶段投影；[ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md)仍由VPP管理/编译active配置，App不复制另一份editable规则或第二priority engine。
含尚未知连接条件的规则不在此处猜测成立；未就绪、投影损坏/过期、Runtime停止/失联时，建议只退出产品判断、沿用原callback结果。此默认尚未冻结。
开启依据是后台防护generation ready；关闭UI不等于停止Runtime。状态/租期检测在本地完成，不每次DNS询问App；字段ABI、代际协议、时限数值本轮不设计或冻结。
停止可先把已驻留shim变成直通；安全卸载仍需处理执行中调用和跳板，不能直接卸库使现有指针悬空。
netd若自行重启，新PID先保持原系统行为；待Runtime确认新实例并完成适配才重新启用，不使用旧PID/地址继续写入。

## 阻断记录不能只靠系统结果事件

原callback false并非必然“没有结果事件”：getaddrinfo把错误设为 `EAI_SYSTEM`，发送失败结果后仍调用 `reportDnsEvent`。[顺序][R17]
gethostbyname也在拒绝路径之后上报；raw resnsend失败只对A/AAAA上报，其他查询类型有真实缺口。[raw缺口][R18]、[gethostbyname][R19]
事件传递的是普通返回码/名字/UID等，不携带产品policy代际、命中规则和“哪段callback拒绝”的原因；不能把所有 `EAI_SYSTEM` 当产品block。[事件发送][R20]
因此shim建议自产有界、非阻塞决策记录，溢出可丢观察并记丢失；日志消费者不可阻塞callback，已有system事件作为补充而不是产品拒绝账本。

## 下一步只需验证一个已知 build

1. 标准模块启动只准备载体/必要权限；**目标是不早注入、不覆盖APEX、不修改resolver文件、不重启netd**。这是一项设计目标，目前没有已实现机制证据。
2. 防护Runtime ready后，先核对当次原netd/resolver Build ID、映射、callback/函数可定位性和注入权限；先研究哪一个晚安装接点确实成立。
3. 成立后先只观察、链式调用原callback；安装成功不等于能安全卸载、重装或跨版本，需另验证并发/失联/进程重启。
4. 接点不能可靠成立就保留原系统：使用已验证Root结果listener＋可见SNI，并显示前置DNS控制未生效/能力有限；不得静默切到开机整库覆盖，也不声称等同系统hook。

这种路线能把风险从“下一次系统早期加载未知整库”移到“Runtime就绪后的当次进程适配”；它降低前者的暴露，但晚安装崩溃仍可能连带zygote。没有实机原始ELF，本轮不能宣布已选定安全可用的接点。

[R1]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_phdr.cpp#863
[R2]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/netd.rc#11
[R3]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolver.cpp#31
[R4]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#777
[R5]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/libnetd_resolv.map.txt#21
[R6]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/main.cpp#78
[R7]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/binder/android/net/IDnsResolver.aidl#41
[R8]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolverService.cpp#80
[R9]: https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r1/private/netd.te#196
[R10]: https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r1/private/domain.te#1324
[R11]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/Android.bp#340
[R12]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/Android.bp#167
[R13]: https://source.android.com/docs/security/test/cfi#troubleshooting
[R14]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_phdr.cpp#206
[R15]: https://github.com/bytedance/android-inline-hook/blob/main/doc/manual.md#initialization
[R16]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/include/netd_resolv/resolv.h#96
[R17]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#932
[R18]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#1164
[R19]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#1352
[R20]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#349
