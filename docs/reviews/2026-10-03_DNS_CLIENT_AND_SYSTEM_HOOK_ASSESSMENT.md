# DNS库资源与libnetd系统hook：本轮研究取舍

2026-10-03。用户要求两席专门研究，分别核查DNS客户端资源／缓存／接入成本，以及libnetd／KernelSU的启动风险。本文汇合研究与实际仓库核查；DNS侧的HEV复用路线已获用户确认，具体接口与参数尚未定稿。系统hook继续讨论，不更新正式执行合同或声明完成设备验证。

## 用户约束

- 自身加密上游为DoT／DoH；DoQ已排除。
- 库选择优先资源占用、缓存和现有架构接入，性能不要求特别高。
- **新增Rust运行时不可行。** 依赖Tokio的Hickory TLS／HTTPS路线退出候选；这不是移除已有Rust控制面的决定。
- Android资源功能开关已撤下；本轮讨论的是库与必需功能的成本，不重开模式裁剪或后台优化开关。
- libnetd研究需正面说明加载失败、启动依赖与恢复限制；本轮没有部署或操作设备。
- 用户进一步明确：系统正常启动、App启动并就绪后开始拦截即可，不要求拦截App就绪前的所有请求。
- 用户进一步要求少集成库，优先复用现有HEV，并比较改造c-ares与小型替代。此前c-ares＋完整TLS＋libcurl组合降为比较项，不再作为当前首选。

## DNS：优先复用HEV，减少新增组件

最新[HEV复用与c-ares fork研究](2026-10-03_HEV_DNS_REUSE_AND_CARES_FORK_RESEARCH.md)按少依赖重排，用户已确认：**在现有HEV原owner内补小型DNS模块，沿用调度、fd／timer、授权和内侧TCP／UDP会话；TLS扩充同一个Mbed TLS上游。** DNS报文与缓存有限范围复用／改造c-ares，不先深改整个channel。

本轮未找到可证实满足完整响应缓存及DoT／DoH的现成HEV专用客户端。HEV的mapped-DNS生成Fake IPv4地址，task-DNS调用系统getaddrinfo；两者不提供这里的完整上游DNS答案缓存。当前Product未启用mapped-DNS和lwIP DNS，也没有调用task-DNS解析路径。已有I/O与会话基础可以复用，DNS协议职责仍需补。[固定mapped-DNS](https://github.com/heiher/hev-socks5-tunnel/blob/3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70/src/hev-mapped-dns.c)、[当前构建](../../third_party/hev/CMakeLists.txt#L24)

| 路线 | 当前判断 |
| --- | --- |
| HEV私有DNS模块＋同Mbed TLS＋c-ares wire/cache窄改 | 优先探索；复用成熟DNS解析，补TTL／外部cache／容量接口，先验证改动能保持局部 |
| HEV私有DNS模块＋公开c-ares wire API | 窄cache改造无法局部完成时采用；缓存留在产品模块，减少对c-ares内核的维护 |
| c-ares channel深fork，内置DoT／DoH | 第二顺位；复用ID／retry／TCP framing，但还要改授权、TLS状态、HTTP交换及cache插入时机 |
| 原c-ares＋libcurl＋完整TLS组合 | 成熟传输后备，当前不默认一起引入 |

c-ares socket hooks可接现有事件循环，但不能使DoH变成透明TLS字节流；开放DoT PR也新增了conn/process状态与crypto backend，且当前只有OpenSSL／Schannel。窄改与深改的边界、缓存channel/query耦合见专项报告；本轮没有fork或导入该PR。[socket合同](https://c-ares.org/docs/ares_set_socket_functions_ex.html)、[开放PR](https://github.com/c-ares/c-ares/pull/1252)

现有Mbed TLS目录实际只有8个原语源文件，SSL／X.509源文件和header都未保留。扩充同一上游可避免增加第二个TLS项目，但要补export/hash、构建与配置、CA／RNG和真实运行占用，不能只开一个宏。

少库DoH可评估固定端点、HTTP/1.1、一个连接一个在途交换的有界客户端；先验证端点兼容，仍需完整处理HTTP framing、状态、增量读写、取消与Age。若用picohttpparser这样的微型语法parser，它只替代手写HTTP语法，不是额外完整客户端；是否采用按实际维护成本决定，不自动叠加多个库。[HTTP版本合同](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.2)、[picohttpparser](https://github.com/h2o/picohttpparser)

## DNS：当前倾向原owner内的C组件

**现成组件存在，不是只有c-ares可用。** c-ares提供DNS报文／UDP-TCP resolver能力；getdns提供现成C DoT客户端；libcurl提供HTTPS传输，可直接发送DoH wire请求。Hickory有DoT／DoH传输，但所需新Rust运行时被排除。下面推荐的是现成组件与产品适配的组合，不表示DoT／DoH都要从头实现。[getdns发布传输定义](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns.h.in#L197)、[curl二进制POST](https://curl.se/libcurl/c/CURLOPT_POSTFIELDS.html)

当前未确认的是：一个同时覆盖DoT／DoH、合适的完整响应缓存／字节硬限，并直接适配当前异步socket broker的现成C库。协议传输已有组件，缓存与平台接入仍有工作；“尚未找到满足整个组合的单库”不等于“加密DNS没有现成库”。

此前组合是：**c-ares报文层＋产品有界wire响应缓存＋完整C TLS后端的DoT事务＋共用TLS后端的libcurl multi DoH**。用户随后强调少依赖与HEV复用，本组合降为比较项，不是当前首选，也不是已测得最小RSS的排名。最新方向见[HEV复用与c-ares fork研究](2026-10-03_HEV_DNS_REUSE_AND_CARES_FORK_RESEARCH.md)。

当前原生FlowOwner已有非阻塞fd／timer驱动，Android已有异步socket保护／绑定broker。Rust product-core没有Tokio／HTTP依赖；另开运行时既不满足用户约束，也不能计为现有成本。库研究给出实际文件、调用点与所需适配：[DNS资源与接入报告](2026-10-03_DNS_CLIENT_RESOURCE_INTEGRATION_RESEARCH.md)。

现有mbedTLS目标只编译AES／GCM／SHA256等原语用于QUIC Initial，并未构建SSL握手和X.509。DoT／DoH需要完整TLS／证书能力，不能以依赖目录存在就认定已经具备。[配置](../../third_party/mbedtls/product_config.h#L1)、[构建列表](../../third_party/mbedtls/CMakeLists.txt#L2)

| 组件 | 此前组合的职责与比较 | 资源与接入含义 |
| --- | --- | --- |
| c-ares wire API | 报文编解码候选，保持C接口 | 不创建无用途的UDP／TCP resolver channel；外部DoH响应不能自动使用其channel cache |
| 产品wire响应缓存 | 保存完整响应及TTL元数据，明确总字节与条数硬限 | 不依赖c-ares私有qcache／TTL helper；查询先判当前政策，再复用有效答案 |
| C TLS／DoT | 使用维护成熟的完整TLS底层，补有限DNS事务 | 不手写TLS；与DoH尽量共用后端，避免两套完整TLS依赖 |
| libcurl multi／DoH | 作为成熟HTTPS传输候选，对接当前fd／timer循环 | 仍需适配异步socket授权；不是调用`CURLOPT_DOH_URL`就完成TUN代理 |
| getdns stub-only | 保留DoT专门备选 | 不覆盖DoH，OpenSSL与缓存接入有额外成本，不作当前完整组合首选 |
| Hickory TLS／HTTPS | 排除 | 所需Tokio运行时违反用户硬约束；现成cache也不能直接当完整上下文的透明响应缓存 |

缓存必须区分会改变答案的查询／flags／EDNS与上游网络上下文，按TTL到期并扣除DoH HTTP `Age`；正常负答案、上游错误和本地阻止结果分别处理。OPT字段不是普通RR TTL，不能统一递减。有限在途事务、等待者、响应大小和连接数属于这个小客户端的基本边界，不需要以高吞吐为目标扩大结构。[DNS库报告](2026-10-03_DNS_CLIENT_RESOURCE_INTEGRATION_RESEARCH.md)、[RFC8484缓存](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)

有两个具体接入缺口：

1. libcurl打开socket的callback必须立即返回fd或失败，现有broker则异步返回保护／绑定结果；须先取得授权再让curl使用fd，不能在VPP owner内同步等待。有限预授权fd的方案仍需核验地址族、重连、关闭与underlay epoch。[curl合同](https://curl.se/libcurl/c/CURLOPT_OPENSOCKETFUNCTION.html)、[现有broker](../../src/product/vpp/product_vpn_socket_broker.h#L48)
2. 当前broker回复路径面向HEV transport；新增DNS事务要有原owner内的身份路由和停止／代际失效处理。DNS响应经原会话与正常返回图交回TUN，不给库直接写TUN的能力，不跨Rust传递活跃VPP包缓冲。

DNS本地会话模式还须在连接原目的DNS服务器前选定，尤其不能先建立原Direct TCP连接再接管查询。graph丢弃原包与完整查询取得后的DNS拒绝应答是不同处理机会，衔接和返回码需在后续合同中明确。

因此“尽量接入现有架构”意味着复用原owner、事件循环、授权与返回生命周期，仍需一个小型DNS客户端／缓存适配层。Hickory功能更多不抵消新运行时成本；C组件也不能凭语言就保证更低内存。

隔离的主机构建与c-ares报文读写检查可证明部分编译／API闭包；它们不能替代Android的增量RSS、线程／fd、空闲唤醒和受保护上游验证。详细版本、构建结果和保留的失败见专项报告，本轮没有进行吞吐基准或设备测试。

## libnetd：先缩小接入与加载的不确定性

用户确认DNS路线后继续讨论系统hook。最新[讨论](2026-10-03_LIBNETD_HOOK_DESIGN_DISCUSSION.md)将功能限定为本地DNS判断、原系统解析和异步控制；[晚安装研究](2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)明确没有公开late setter，App就绪后对原进程挂钩仍需按实际build验证。

用户随后提出Xposed以减少不同ROM的反编译／系统改造。追加[Xposed候选研究](2026-10-03_XPOSED_DNS_HOOK_OPTIONS.md)把入口放在scope内App Java／native解析调用，通常可免resolver整库替换；不等于进入独立netd，也不能仅勾system_server覆盖全部App-native DNS。App侧候选与集中netd路径继续比较，框架／作用域／Android16组合尚未验证。

按用户最新范围，系统启动及App未就绪时保留原系统DNS行为，App／防护服务就绪后再启用拦截即可。建议停止或失联后也恢复原系统行为，具体生命周期继续定义。这样无需让早期DNS同步等待App；但“晚启用判断”与“晚安装／加载hook”是两件事，早期整库覆盖的加载风险仍需避免或验证。

整库替换的风险超出DNS查询。AOSP Android16的resolver动态进入netd，初始化失败可使netd退出；`netd.rc`的重启行为连带zygote。源码没有把netd标为`critical`，所以不能将这条链描述成必然立即整机重启。[resolver模块](https://source.android.com/docs/core/ota/modular-system/dns-resolver)、[netd启动配置](https://android.googlesource.com/platform/system/netd/+/refs/tags/android-16.0.0_r1/server/netd.rc#1)

独立研究核查了旧工具链、两份不同hash的resolver ELF、固定AOSP和KernelSU源码：[libnetd／KernelSU报告](2026-10-03_LIBNETD_KSU_HOOK_RESEARCH.md)。主要发现如下：

- 旧生成器在post-fs-data绑定库，辅助进程却等boot_completed；若hook同步等它，会形成启动依赖环。尚未读取其内部实现或取得设备故障日志，不能说该环已经发生。
- 同包还覆盖framework／services JAR；现存KSU目录与生成器输出、两份resolver二进制也不同，旧单机声明不是当前模块匹配证据。
- APEX版本、netd ABI／namespace、依赖和SELinux标签都影响实际加载；glob覆盖所有版本路径或shell中的mount成功不能证明netd使用了目标库。
- 已映射库不会因卸掉bind立即换回；晚启动看门狗和boot_completed回退无法兜住早期loader／constructor／初始化失败。

AOSP存在更小的`evaluate_domain_name`同步入口，已带请求UID／netId；合同要求并发安全，禁止sleep／RPC。可研究在保留原系统网络许可后读取有界、只读的DNS政策投影，更新与记录发送放在callback外。[callback合同](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/include/netd_resolv/resolv.h#96)

但这个入口由netd私有初始化，外部App没有Binder veto注册API；OEM源码集成、匹配resolver包装或精确二进制修改各有部署风险。代码更少不代表能做成所有Root设备通用的安全模块。政策数据不可用时的本地回退可以恢复查询，不能修复尚未加载成功的坏库。

建议先保留原库，用独立Root结果监听核对可见性和归属；若确需前置控制，再对已知匹配设备分开验证原样加载、只观察hook和小范围控制。结果监听只观察，不能冒充解析前拒绝。这一顺序缩小变量，不承诺零风险。

KernelSU的安全模式、CLI禁用与Recovery入口都有版本／加载模式／设备条件。当前官方文档还说明坏initrc可能在安全模式仍执行，late-load模式没有相同的音量键安全模式；不能以“有救砖功能”替代覆盖前的身份准入和实际可达恢复入口。[官方救援](https://kernelsu.org/guide/rescue-from-bootloop.html)、[加载模式](https://kernelsu.org/guide/module.html#late-load-mode)

## 当前结论的范围

DNS当前主线是现有HEV owner／reactor上的小型客户端、同一Mbed TLS完整能力与有界缓存，优先比较c-ares wire/cache窄改；深channel fork和libcurl组合为后备，排除新增Rust运行时。TLS／HTTP与会话／授权适配尚未实现。系统hook侧有值得研究的同步入口，但整库覆盖的加载风险没有消失，先保留原库观察与匹配身份核验。

DNS实现路线已确认；具体版本、缓存容量、TLS配置、DNS接入合同仍需定义和验证。系统hook安装、设备支持与默认回退继续讨论；本轮没有改生产代码、模块、设备、原型、ADR或tracker。
