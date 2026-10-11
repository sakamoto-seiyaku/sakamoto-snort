# libnetd_resolv 系统 hook：KernelSU 启动风险与较小接入点

2026-10-03。只读研究，承接[系统 DNS 讨论](2026-10-03_ANDROID_STANDARD_DNS_DISCUSSION.md)、[平台研究](2026-10-03_ANDROID_DNS_PLATFORM_RESEARCH.md)与[VPN DNS 讨论](2026-10-03_VPN_DNS_RELAY_DISCUSSION.md)。
本轮未操作设备、运行安装/部署/开机脚本、改模块或产品、更新 tracker、提交 commit；未读取、执行或参考旧 Snort daemon 源码。
读取范围仅为独立 Android 模块材料、resolver ELF 元数据和官方源码；产品包域仍受 [ADR-0008](../adr/0008-remove-snort-cpp-mainline.md) 的 VPP-native C 边界约束。
AOSP 固定 `android-16.0.0_r1`；KernelSU 源码固定 `v3.3.0`，另核对 `v3.0.0` 变更。设备实际 Android/APEX/KSU 版本与厂商补丁**未测**。

**研究后用户收窄要求：** 不追求从系统启动开始拦截所有请求，App正常启动并就绪后能拦截即可。此前启动／加载风险核查仍有效，但产品不要求早期DNS等待App。可将启用判断放在App就绪后；是否可连hook安装／加载也延后仍需单独确认，晚启用不能消除早期替换库本身的加载风险。停止／失联后的原系统行为回退是后续建议，未定义具体实现。

用户确认VPN DNS路线后继续讨论本系统hook；最新[设计讨论](2026-10-03_LIBNETD_HOOK_DESIGN_DISCUSSION.md)和[晚安装接点研究](2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)区分早期默认直通与App就绪后的真正晚挂，不把`resolv_init`重入当公开热更新接口。

## 结论

整库覆盖确实可能影响系统启动，因为 resolver 在 netd 进程内运行，失败不一定止于某次 DNS 查询。
但没有本轮设备日志，不能断言某次启动失败已经由某个符号、SELinux 拒绝或 hook 阻塞造成。
旧工具链还同包覆盖 `framework.jar`、`services.jar`；应先拆开变量，不能把整包故障全部归给 resolver。

AOSP 已有较小的 `evaluate_domain_name` 前置判断 seam：同步、进程内、读取实际请求 UID/netId/名字。
它由 netd 初始化，**不是 App/Root helper 可经 Binder 注册的 veto**；官方明确禁止 callback 睡眠和 RPC。[callback 合同][A1]、[netd 初始化][A2]
适合研究的是“保留原系统检查，再做有界本地判断”；实际接入仍需可信 OEM/netd 集成或绑定具体二进制版本的修改，代码少不等于通用安全模块。

较稳的第一步是先用已验证权限的独立结果监听观察；真正 hook 试验先验证原样库/挂载链，再只观察，最后才启用极小范围的同步政策。
`service.sh` 晚启动、`boot-completed` 回退和 App 看门狗均不能保证整库替换后的系统能启动。

## 旧材料究竟证明了什么

| 材料/只读结果 | 可以确认的事实 | 不能推导的结论 |
| --- | --- | --- |
| [toolkit README](/home/js/Git/sucre/sucre-android16-toolkit/README.md:9) | 自述 Android16、Pixel6a、历史单机验证 | 所有 Android16、最新 Mainline APEX 与 KSU 兼容 |
| [04-deploy.sh](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:244) | 生成 `post-fs-data.sh`，把模板 resolver 绑定到 `/apex/com.android.resolv*/lib64/` | 当前设备已安装该生成物、netd 已加载该库 |
| [现存 KSU 补充记录](/home/js/Git/sucre/KSU/sucre-module/SUPPLEMENTAL_CHANGES.md:12) | 包含 `overlay.d/sbin/libnetd_resolv.so` 和 Magisk init 材料 | KernelSU 自动处理 `overlay.d` |
| 现存 `/home/js/Git/sucre/KSU/sucre-module/` | 本轮枚举未见 `post-fs-data.sh` 或 `system/etc/init/` 文件 | 与生成器输出相同，或 resolver 覆盖必然启用 |
| [现存 overlay init](/home/js/Git/sucre/KSU/sucre-module/overlay.d/init.sucre.rc:8) | 使用 `u:r:magisk:s0`、`${MAGISKTMP}`，硬编码 APEX `@350090000` | 这套命名空间/属性/版本路径能原样用于 KSU |

对现存 KSU 库执行 `readelf -h -d -n -l -V`：ELF64/AArch64，SONAME `libnetd_resolv.so`，Build ID `a19eaf8ec174eb41445dc005711e2355`。
Android ident note 为十六进制 `0x22`（34）；这不是 resolver 源码版本、设备 Android16 匹配或实际 hook 行为的证明。
`DT_NEEDED` 包含 `libbinder_ndk.so`、`libcrypto.so`、`libssl.so`、`libstatssocket.so` 等；有 `BIND_NOW` 和 `.init_array`，所以不能假设所有加载错误都等到第一次查询才出现。
ELF 元数据只识别样本，不能从中证明内部 IPC、超时、锁和拒绝逻辑。本轮未反编译其实现。

两份库的 SHA-256 **不同**，不可混作同一已验证构建：

- [现存 KSU 库](/home/js/Git/sucre/KSU/sucre-module/overlay.d/sbin/libnetd_resolv.so)：`983afc70603ab5b993ff9203859ea40eddb02ae1bae631e1875554517b05d493`。
- [toolkit 模板库](/home/js/Git/sucre/sucre-android16-toolkit/module-template/sucre-blocker-magisk/overlay.d/sbin/libnetd_resolv.so)：`457ae58fa9182822d23a7308fca65b69249a8929ee898942a45a7dadd61fef0b`。

## 从启动、APEX 到实际加载

DNS Resolver 是 `com.android.resolv` APEX，动态链接进入 netd；不是独立可随意重启而不影响 netd 的代理进程。[官方模块说明][A3]
固定 tag 的 netd 构建声明 `libnetd_resolv` shared dependency；`netd.rc` 的 `updatable` 保证 APEX 就绪前延迟启动。[构建依赖][A4]、[启动配置][A5]
`resolv_init` 会启动 DNS socket listener 和 Binder 服务；失败返回 false，netd `main` 随即 `exit(1)`。[resolver 启动][A6]、[netd 失败处理][A7]

`netd.rc` 没有 `critical` 标记；它有 `onrestart restart zygote` 和 `zygote_secondary`。
因此 resolver 加载/初始化崩溃 → netd 退出/重启 → zygote 重启，是有源码支持的风险链；不能写成“netd 标为 critical，所以必然立即重启整机”。[netd.rc][A5]
init 还监视默认 mount namespace 内含可更新组件的异常退出；重复失败可报告 `sys.init.updatable_crashing`。[init 退出处理][A8]
APEX 的更新恢复机制处理其包/更新状态；外部 KSU bind payload 不因此自动成为受签名校验和回滚管理的 APEX 内容。回滚 APEX 后仍盲覆盖同一坏库，是风险推论。

Android16 `post-fs-data` 中启动 apexd，后续等待 activated，再配置 APEX；同名 `post-fs-data` 不能证明某 KSU 脚本执行时 resolver 已激活。[init 时序][A9]
apexd 为激活版本创建挂载，并把最新有效版本绑定到稳定名 `/apex/<package_name>`；不应通过 glob 把稳定名和所有版本路径都当独立目标。[APEX 激活][A10]
init 有 bootstrap/default mount namespace，`/apex` 为 private；KSU shell 看得到某路径，不等于 netd namespace 看到同一覆盖。[namespace 实现][A11]
文件 bind 成功、shell `ls` 成功、日志打印成功，都不足以证明 netd 已使用替换库。

bionic 从打开的文件描述符映射 ELF segment；**已有映射不因后来覆盖路径或卸载 bind 自动换回另一库**。[ELF 映射][A12]
在 netd 启动之后才 mount，可能当前进程仍用旧 inode，下一次重启才用新库；这会造成“当次看似正常、重启后失败”的假象。
验证应同时记录 APEX active 身份、netd mount namespace、`mountinfo`、映射的设备/inode/Build ID；不能只比较路径字符串。
也不能把在线重启 netd 当无影响验证：上述 zygote 重启链真实存在。

## 兼容性需要绑定哪些身份

固定 AOSP resolver APEX 以 `multilib.first` 安装库；决定因素是 netd 主架构，不是某业务 App 为 32 位还是 64 位。[APEX 构建][A13]
旧脚本只有 `lib64`，样本为 arm64；没有证明能用于 32 位 netd、x86/x86_64，或任何不匹配 ELF 的系统。
应绑定完整系统 build/APEX active 版本与原库 hash、netd ABI、页大小/ELF 装载要求；“API=36”或“存在 lib64 目录”都不够。

固定 tag 保留三个版本化公开 `resolv_*` 符号并做 ABI 检查，这为既有边界提供约束，不能据此保证任意整库可互换。[符号表][A14]、[构建约束][A15]
`ResolverNetdCallbacks` 明说部分依赖没有 ABI 稳定保证，以 netd 提供函数指针绕开；私有结构/地址/内部符号不属于可供 App 稳定调用的接口。[callback 结构][A1]
依赖闭包应以 `Android.bp`、实际 ELF 和设备 `/linkerconfig` 为准；官方介绍页的依赖概括不能覆盖固定源码中 shared libraries 的实际清单。[构建依赖][A15]
Android11 起 linker config 随设备/APEX 生成；在普通 su 测试进程里 `dlopen` 成功不证明 netd 的 linker namespace 也允许同一依赖。[linker 文档][A16]
Android15 起 VNDK 已弃用，旧 vendor image 可保留较早 VNDK；不能拿“同一 VNDK/API”当 resolver 私有 ABI 的通用兼容凭据。[VNDK 变化][A17]

Binder AIDL 有冻结版本，但版本化不消除实际 permission、SELinux 和服务生命周期约束。[AIDL 构建][A18]
netd SELinux 限定 DNS 服务发现和对 App 的 Binder 调用；Root UID不等于任意 domain 可以双向调用。[netd policy][A19]
bind 不会自动赋予 payload 原 APEX 文件的正确 SELinux 标签；旧 `post-mount.sh` 的 chcon 修的是另一个可执行文件，不能证明 resolver 可被 netd 映射。[旧 chcon](/home/js/Git/sucre/KSU/sucre-module/post-mount.sh:9)

## 旧生成脚本逐步审计

以下“可能结果”均为条件推论，未声称它们已在用户设备发生。

| 步骤/源码 | 问题与可能结果 |
| --- | --- |
| [复制模板](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:51) | 复制预制 `.so`，没有在这里对设备 resolver 重建或核对符号。未知模板/厂商/APEX → loader/init 失败风险。 |
| [同包 JAR](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:80) | 同时覆盖 framework/services；DEX、framework/Binder 补丁不兼容也能影响 zygote/system_server，必须独立归因。 |
| [customize 配置](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:121) | MINAPI/MAXAPI 是注释；没有模块 hash/netd 架构/APEX 版本准入。MMT 接受安装不等于 resolver 兼容。 |
| [post-fs-data bind](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:254) | 只检查 lib64 目录，glob 多个版本；APEX尚未就绪/namespace不对可无效果，成功加载错误库可击穿 netd。 |
| [结果记录](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:257) | `mount ... \| tee` 后无论 mount 状态都写 Mounted；生成脚本内无可靠失败传播。日志不能当成功证据。 |
| [晚启动 helper](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:203) | 等 boot_completed 才启动；若早期 hook 同步等它，则依赖成环。库是否实际如此等待未测。 |
| [生成 init RC](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:279) | 放 `/system/etc/init/` 不证明被 init 导入；AOSP通常早已解析此目录。若确实加载，还要核对 service/domain/重复启动。 |
| [校验清单](/home/js/Git/sucre/sucre-android16-toolkit/scripts/modules/04-deploy.sh:436) | 检查文件存在/文本规则，没有真实 ELF加载、APEX身份、netd存活或DNS验证；也未列生成 post-fs-data 的关键闭包检查。 |

AOSP `LoadBootScripts` 早期解析 `/system/etc/init`，不能把后来的 systemless overlay 当自动重新导入。[init 解析][A20]
旧 post-fs-data 段本身没有 `setprop` 或等待 boot_completed；不能把“这些写法会死锁”指认为该段已存在的错误。
init RC 内的 `setprop` 是 init action，不等于 post-fs-data shell 里调用 setprop 的官方禁用情形。
helper/App 失败且 callback 有真正本地回退时，可能只是观察/过滤停止；DNS政策全拒绝通常先表现为解析失败，不凭此断言 kernel/init 崩溃。
callback 内存错误/constructor 崩溃、`resolv_init` 卡住，与单次查询被拒绝是不同故障等级。

## KernelSU 版本、阶段和救援边界

官方 `v3.0.0` 引入 metamodule，移除内建 OverlayFS，并要求升级后重装模块；旧材料的“0.6.6+”不能涵盖这次变更。[发布记录][K1]
当前普通 `system/` 自动挂载依赖 metamodule；没有 metamodule 时脚本型模块仍可能运行，脚本自己的 bind 不能据此认为被阻止。[metamodule 文档][K2]
当前顺序是 post-fs-data scripts → metamount → post-mount；不能假设库挂载天然跟随 system overlay/APEX 激活。[阶段文档][K3]
post-fs-data 是阻塞阶段，文档给约10秒等待上限并禁止 shell setprop；service 非阻塞推荐用于一般后台任务。[固定阶段说明][K4]
这个上限针对脚本阶段，不是 netd 的 loader、constructor、callback、RPC 或系统 DNS 的统一超时，不能用它论证“最多卡10秒”。

当前 `initrc/` 注入发生在 post-fs-data 前，安全模式检查不能保证抹掉已执行的坏 RC；旧 `overlay.d` 与新 `initrc/` 不能互当。[RC 机制][K5]、[救援说明][K6]
`late-load` 在系统已启动后加载 KSU，固定文档写明跳过音量键安全模式和 initrc 注入；它也不是把新库安全热替换进已运行 netd 的机制。[late-load 差异][K7]

恢复入口须在目标设备/具体 KSU 构建上可达，以下是条件建议，**本轮未执行**：

1. 系统能进入 Manager：禁用该独立模块并按该版本要求重启；当前 disable 会记录禁用并重新生成下一次启动的模块 RC，不会自动卸掉现有 netd 映射。[disable 实现][K8]
2. 当前官方 built-in/LKM 安全模式：首屏后的有限时间内重复按放音量减；文档写超过三次，并说明 non-GKI 可能需额外集成。不要当所有 KSU/fork/设备统一按键流程；late-load 不适用。[救援条件][K6]
3. ADB仍可取得Root且对应CLI可用：先 `./dev/adb shell su -c 'ksud module list'`，再按确定的模块ID使用该版本的 disable/uninstall；不能假定启动失败时 ADB 或 su 一定可用。[CLI入口][K9]
4. 系统/ADB不可达：官方当前手动恢复依赖可用 Recovery、挂载/必要解密 data，并在适用时处理 metadata 上的注入 RC；须确认这台设备真正具备该入口，不能只写“TWRP救一下”。[手动恢复][K6]

“还原 stock boot”属于匹配设备、分区、启动方式的 KSU 救援材料，不是所有 LKM/模块故障的一个通用命令；不从 Magisk 推导 KSU 恢复流程。
试验设备应能通过已核对的独立入口阻止**下次**加载坏模块；仅在 Android App 中做恢复按钮不能满足这一条件。

## 更小的 hook 设计候选

`evaluate_domain_name` 在 getaddrinfo/gethostbyname/raw resnsend 查询前执行；反向查询在新版本也可能以 nullptr 调用，不能把 host 当永远有效字符串。[实际调用][A21]
它返回 false 时 getaddrinfo 用 `EAI_SYSTEM`，raw resnsend 当前用 `-EAI_SYSTEM`；不是自动合成 wire DNS NXDOMAIN/REFUSED，App可见语义还需验证。[拒绝路径][A22]
netd `evaluateDomainNameCallback` 先保留 `isUidAllowed`；AOSP明确留出 OEM customization 区。产品增量必须在系统原判断允许后才判定，绝不能把原 deny 改成 allow。[OEM seam][A2]

| 候选 | 权限/接入条件 | 稳定性限制 |
| --- | --- | --- |
| 独立 helper 注册结果 listener | 真UID0/许可链、双向Binder与SELinux均实测 | 只观察结果，不能前置拒绝；helper失败不直接执行在netd内。见[已有许可研究](2026-10-03_ANDROID_DNS_PLATFORM_RESEARCH.md)。 |
| OEM/netd 源码内使用既有 callback | 能构建和部署匹配系统netd，保留厂商/系统行为 | 判断范围小，但替换netd本身仍在启动关键进程；不能称通用Root安全方案。 |
| 在匹配 resolver 中包装传入 callback | 固定源码/原库/系统ABI，审查所有原行为 | 保留三公开入口及原callbacks；若仍靠整库替换，加载风险没有消失。 |
| 二进制注入/inline patch callback | 精确Build ID/布局、SELinux、CFI/BTI及并发适配 | 没有公开稳定注册API；按版本改少量字节也可能使netd崩溃，不能作为全机型自动探测后的盲注入。 |

`IDnsResolver` 只有事件注册和配置等方法，没有安装该决策函数的 setter；结果 listener不能升格为前置 veto。[Binder接口][A23]
可研究把当前统一政策的**只读、已验证 DNS 阶段投影**预装到本地；hook只做有界查找，不建第二规则优先引擎、不执行网络、不等App/控制面启动。
更新、校验、记录发送在 callback 外；并发读取用不可变代际，缺失/损坏/未就绪时回到原系统允许结果，并明确报告产品过滤未生效。这是候选策略，未获实现/默认策略批准。
callback 内不得 sleep/RPC；即使加RPC超时，也不符合官方合同，且无法兜住死锁/内存错误。查询 limiter只能限并发，不能保证卡住的callback恢复。[合同][A1]、[limiter/执行顺序][A21]

同步问App可能形成：DNS请求 → hook等App → App为初始化/解析上游等待DNS → 同一hook；helper只在boot_completed启动时还有启动环。
任何新上游都须独立 bootstrap；回调内部不能调用自身系统解析，不能靠公共解析器域名全局放行绕过政策。
自身助手/启动关键系统解析的豁免应按可信请求归属与必要范围设计，并保留原系统网络权限检查；不能用前台UID猜测请求者。
未知政策允许/熔断能恢复“决策数据失效”情况下的查询，不能恢复未进入函数前的ELF加载错误、崩溃、任意锁死或已损坏内存。

## 可执行的最窄试验顺序（未部署）

1. **先观察**：保留原库，验证独立listener及重启后恢复；取得实际系统build、APEX active身份、netd/原库hash、KSU kernel/userspace/runtime mode/metamodule身份和可达救援入口。
2. **再核验加载链**：只对已知匹配设备，在独立resolver模块中使用设备原样库副本检查挂载/标签/namespace；不捆绑JAR、initrc或其他旧功能。原样副本仍有挂载/时序风险，不能称零风险。
3. **只观察hook**：匹配源码构建保留原回调结果；记录采集有界、失败丢观察，禁止阻塞netd。验证缓存、raw查询、nullptr、PrivateDNS、网络切换和辅助进程停止。
4. **小范围控制**：仅启用已能正确判定的DNS政策投影，验证两App例外、原系统deny保留、超时/损坏回退及停止控制面；之后再决定设备支持边界。

独立测试进程的ELF加载检查可提前发现部分依赖错误，不能取代目标netd namespace、真实callbacks和启动验证；本轮没有完成这些实验。
可靠“不加载即回退”只发生在**覆盖前**：身份不匹配、实验未武装或外部禁用标记存在就完全跳过覆盖，让原库继续加载。
一旦坏库已进入netd依赖、constructor或替换路径，就不能保证其自身wrapper还能加载原库；同SONAME、namespace、初始化次序也需适配，不应承诺“坏了自动dlopen原库”。
独立早期监督者可尝试撤销下次覆盖；在线卸载bind不能换回已有映射，重启netd又会影响zygote。
`boot-completed` 回退只有系统已到达该阶段才能运行；`service.sh` 非阻塞只说明脚本不阻塞init，不说明其造成的netd崩溃/循环不会影响启动。
因此第一步应保留原库和系统启动链，通过观察与身份核验缩小不确定性；“整库替换后靠晚启动看门狗保底”不是可靠启动保障。

[A1]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/include/netd_resolv/resolv.h#96
[A2]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/main.cpp#98
[A3]: https://source.android.com/docs/core/ota/modular-system/dns-resolver
[A4]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/Android.bp#98
[A5]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/netd.rc#1
[A6]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsResolver.cpp#88
[A7]: https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/main.cpp#184
[A8]: https://android.googlesource.com/platform/system/core/+/refs/tags/android-16.0.0_r1/init/service.cpp#362
[A9]: https://android.googlesource.com/platform/system/core/+/refs/tags/android-16.0.0_r1/rootdir/init.rc#715
[A10]: https://android.googlesource.com/platform/system/apex/+/refs/tags/android-16.0.0_r1/apexd/apexd.cpp#1201
[A11]: https://android.googlesource.com/platform/system/core/+/refs/tags/android-16.0.0_r1/init/mount_namespace.cpp#86
[A12]: https://android.googlesource.com/platform/bionic/+/refs/tags/android-16.0.0_r1/linker/linker_phdr.cpp#863
[A13]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/apex/Android.bp#33
[A14]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/libnetd_resolv.map.txt#21
[A15]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/Android.bp#250
[A16]: https://source.android.com/docs/core/architecture/vndk/linker-namespace
[A17]: https://source.android.com/docs/core/architecture/vndk#deprecation
[A18]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/Android.bp#70
[A19]: https://android.googlesource.com/platform/system/sepolicy/+/refs/tags/android-16.0.0_r1/private/netd.te#166
[A20]: https://android.googlesource.com/platform/system/core/+/refs/tags/android-16.0.0_r1/init/init.cpp#337
[A21]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#929
[A22]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#1143
[A23]: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/binder/android/net/IDnsResolver.aidl#41
[K1]: https://github.com/tiann/KernelSU/releases/tag/v3.0.0
[K2]: https://kernelsu.org/guide/metamodule.html
[K3]: https://github.com/tiann/KernelSU/blob/v3.3.0/website/docs/guide/module.md#boot-scripts
[K4]: https://github.com/tiann/KernelSU/blob/v3.3.0/website/docs/guide/module.md#L339
[K5]: https://kernelsu.org/guide/module.html#initrc-injection
[K6]: https://github.com/tiann/KernelSU/blob/v3.3.0/website/docs/guide/rescue-from-bootloop.md#L23
[K7]: https://github.com/tiann/KernelSU/blob/v3.3.0/website/docs/guide/module.md#L448
[K8]: https://github.com/tiann/KernelSU/blob/v3.3.0/userspace/ksud/src/module.rs#L750
[K9]: https://github.com/tiann/KernelSU/blob/v3.3.0/userspace/ksud/src/cli.rs#L284
