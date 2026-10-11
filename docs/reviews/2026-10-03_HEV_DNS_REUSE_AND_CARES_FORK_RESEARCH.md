# HEV DNS复用与c-ares集中改造

2026-10-03。用户进一步要求“有基于HEV的吗／改造c-ares／不可集成太多库”。本轮按**实际新增组件、已有HEV复用、缓存正确性与维护成本**重排，前轮[wire+TLS+libcurl建议](2026-10-03_DNS_CLIENT_RESOURCE_INTEGRATION_RESEARCH.md)降为比较项。

**报告交付后用户已确认本路线，要求接下来讨论libnetd hook。** 已确认HEV原owner复用、小型DNS模块、同Mbed TLS补全与c-ares有限报文／缓存改造；接口、容量、HTTP端点兼容及正式运行合同仍留待具体设计与验证。本轮后的[系统hook讨论](2026-10-03_LIBNETD_HOOK_DESIGN_DISCUSSION.md)不改变这条VPN DNS路线。
仍只做DoT／DoH上游，不引入Rust运行时、另一executor、后台DNS worker或资源模式开关；按用户方向在App ready后接hook。本轮仅新增本文件，未修改产品、依赖、旧报告、ADR/API，未操作设备或进行新build/benchmark。

## 本轮排序

**首推：在现有HEV原FlowOwner中增加私有DNS模块，补全同一Mbed TLS上游export；DNS侧考虑小范围复用／改造c-ares wire与cache接口，DoH用有界HTTP/1.1事务层。**
这不是把HEV现有Fake-IP DNS改成万能parser，也不先把整个c-ares channel深改成TLS/HTTP客户端。保留成熟DNS wire核心；按实际需要补TTL修改/位置、外部响应cache及资源计量seam，cache内部结构是否复用要先拆掉channel/query依赖。
新增完整TLS能力不可避免；扩充已经使用的Mbed TLS不会增加第二个TLS项目，但会增加真实的TLS/X.509/RNG/CA/算法代码及运行占用。HTTP/1.1路线以所选DoH endpoint确实支持它为前提，不因此删除DoH要求。
**第二顺位是c-ares channel集中fork**：若确实需要它的复杂retry/多server/事务管理，可保留这些核心；TLS/DoH/cache/Android授权改造依然要做，且合并维护面更大。
**libcurl multi保留成熟传输后备**，不再默认同时带c-ares+curl+完整TLS；也不因把几个组件vendor进同一目录就把依赖成本算成一个。

## HEV到底已有哪一种DNS

本项目pin来自 [README](../../third_party/hev/README.md#L9)与[manifest](../../third_party/hev/upstream-manifest.json)：tunnel `3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70`，task-system `b1afa0e21fb4ed5a69560e78e54baf0efdebe171`，lwIP `8c69dfbe537835d5f2a5fd8c08c859f667b108ea`。
实际构建由[Product CMake](../../third_party/hev/CMakeLists.txt#L24)与[Product lwipopts](../../third_party/hev/product/lwipopts.h#L8)决定，不能把上游整个应用的能力算进当前owner路径。

| 名称 | 固定源码实际做什么 | 当前Product是否启用／适用 |
| --- | --- | --- |
| `hev-mapped-dns` | A/IN问题得到虚拟IPv4 `net\|index`；LRU/name→index、index→name反查；生成RR的TTL固定1秒 | CMake没有编入mapped-dns.c/tunnel.c/utils.c；不是远程解析、完整RR答案cache、SOA负缓存或DoT/DoH |
| `hev-task-dns` | 暴露getaddrinfo/getnameinfo，懒建当前scheduler的proxy；把系统调用送到aide执行 | task源GLOB会编译相关.c，但当前Product owner/session无调用；返回地址/名字，不是原始DNS query/response |
| `hev-task-aide` | 进程全局pthread、mutex、独立reactor；在该线程执行proxy handler与libc解析 | 调用task-DNS会懒启动该线程；不是原owner上的DNS协议状态机，不能当已存在且已获准的DNS运行路径 |
| lwIP `core/dns.c` | UDP hostname→A/AAAA地址解析，dns_table有TTL/IP条目；部分配置可合并地址查询 | 未列入Product lwIP target，`LWIP_DNS=0`；即使开启，也不提供任意wire响应/DoT/DoH |

mapped-DNS证据：[固定源码](https://github.com/heiher/hev-socks5-tunnel/blob/3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70/src/hev-mapped-dns.c#L175)、[本地LRU/反查](../../third_party/hev/upstream/src/hev-mapped-dns.c#L99)。其中“cache-size”限制映射数量，并没有缓存上游应答或按其TTL过期。
task-DNS证据：[getaddrinfo wrapper](../../third_party/hev/upstream/third-part/hev-task-system/src/lib/dns/hev-task-dns.c#L20)、[proxy真实libc调用](../../third_party/hev/upstream/third-part/hev-task-system/src/lib/dns/hev-task-dns-proxy.c#L84)、[全局aide pthread](../../third_party/hev/upstream/third-part/hev-task-system/src/kern/aide/hev-task-aide.c#L22)。有源码/编入archive不等于运行中已初始化proxy/aide。
当前Direct Product由sockaddr/IP直接创建socket；上游hostname解析出现在未纳入本次session source list的 `hev-socks5-misc.c`，不能据此推断Product正经过系统resolver。[Direct task](../../third_party/hev/product/hev-owner.c#L253)、[hostname helper](../../third_party/hev/upstream/src/core/src/hev-socks5-misc.c#L257)、[session构建列表](../../third_party/hev/CMakeLists.txt#L72)
lwIP证据：[DNS开关](../../third_party/hev/product/lwipopts.h#L37)、[实际target](../../third_party/hev/CMakeLists.txt#L40)、[pin的dns_table/IP/TTL](https://github.com/heiher/lwip/blob/8c69dfbe537835d5f2a5fd8c08c859f667b108ea/src/core/dns.c#L220)。`LWIP_DNS_SECURE`是DNS ID/source-port等防护选项，不是TLS加密。

## 有没有现成“基于HEV的DoT／DoH client库”

本轮做了作者官方repo/README与针对 `heiher + DoH/TLS/DNS`、`hev-task-system + DoH` 的定向检索，未找到可证实满足完整wire响应、TTL缓存与DoT/DoH的现成专用client。
作者官方讨论仍把普通DNS代理描述为TCP/UDP透传；mapped-DNS的具体实现与其Fake IP用途吻合。官方task-system列的是scheduler/I/O/同步能力，并非加密DNS模块。[官方讨论#257](https://github.com/heiher/hev-socks5-tunnel/discussions/257)、[task-system](https://github.com/heiher/hev-task-system)、[官方作者repo入口](https://github.com/heiher)
这是检索范围内**没有找到**，不是断言社区绝不存在实现；本题不把普通curl示例、HTTPS服务端或Fake-IP DNS冒称专用client。

## 真正可直接复用的HEV seam

- [owner scheduler/context](../../third_party/hev/product/hev-owner.c#L734)、[bounded step与最近timer](../../third_party/hev/product/hev-owner.c#L920)：新DNS任务可运行在既有owner，不另建运行时；任务栈/数量仍要有限。
- [socket/broker状态](../../third_party/hev/product/hev-owner.c#L282)与[completion](../../third_party/hev/product/hev-owner.c#L852)：沿用异步protect/bind，再connect；增加DNS token路由，Java不执行DNS/TLS回调。
- [现有VPP reactor/timer驱动](../../src/product/vpp/product_vpn_flow_stack.c#L54)：驱动TLS的fd兴趣、deadline与内部已缓冲数据，idle无常驻轮询。
- [lwIP UDP/TCP session及输出](../../third_party/hev/product/hev-owner.c#L188)→[Product output](../../src/product/vpp/product_vpn_flow_stack_hev.c#L38)→[return graph](../../src/product/vpp/product_vpn_tun_adapter.c#L101)：保留原应用会话的封包/序号/事实/owner，不另写一套内侧TCP。

缺少的是DNS payload/session模式：在UDP `create_session`或TCP `tcp_session_task`建立原目的Direct socket**之前**选择本地DNS会话，再接完整UDP datagram/TCP 2-byte message；不能先连原目的53再接管，也不能每个TCP packet都当一个query。[现状](../../third_party/hev/product/hev-owner.c#L406)
graph packet DROP仍结清原包；query取得后DNS拒绝应答由本地会话生成，两者不能混为一次DROP。过滤调用同一VPP规则实现，cache只保存上游结果；活跃buffer/PCB/pbuf不跨语言异步借用，遵守 [ADR-0006/0007/0008](../decisions/README.md#L8)。

## c-ares 1.34.8 socket hooks能复用什么

新版 `ares_socket_functions_ex` v1提供asocket/aclose/asetsockopt/aconnect/arecvfrom/**asendto**等；老接口才有asendv。callbacks须表现为BSD socket等价操作，可EAGAIN；使用它们时不开 `ARES_OPT_EVENT_THREAD`。[固定header](https://github.com/c-ares/c-ares/blob/v1.34.8/include/ares.h#L627)、[公开合同](https://c-ares.org/docs/ares_set_socket_functions_ex.html)
手动 `sock_state_cb`＋`ares_process_fds`＋`ares_timeout`可接HEV/VPP已有fd/timer；c-ares thread-safety编译支持不等于必须开启event线程。[事件API](https://c-ares.org/docs/ares_process_fd.html)、[timeout](https://c-ares.org/docs/ares_timeout.html)
**DoT可以复用DNS-over-TCP核心**：强制USEVC，保留2-byte frame、partial I/O、query ID、TCP多事务、timeout/retry/callback；TLS shim提供解密后的byte stream。但“把send/recv换成SSL”不足以完成下列事项。

| 接点 | 必须适配的状态／限制 |
| --- | --- |
| protect/bind | `ares_set_socket_callback`在connect之后，太晚；configure callback虽在connect前，也是同步返回。不能在worker等Java；需要有限预授权fd或改conn为显式AUTH_PENDING |
| TCP与TLS ready | 普通TCP writability不代表TLS身份验证已完成；只有授权→connect→TLS认证完成才可发DNS明文payload |
| TLS兴趣 | SSL write可WANT_READ、SSL read可WANT_WRITE；需要取c-ares需求与TLS需求并集、正确重试原操作，而非固定读/写方向 |
| 内部pending | 解密数据可能已在TLS内部，内核fd不再产生新read event；必须主动安排有限进度，否则卡住；避免WANT状态造成永久writable轮询 |
| 生命周期 | 握手deadline、CA/hostname、断线重连、旧fd/epoch/generation、close-notify、取消后的late response都有独立责任 |

依据：[1.34.8 conn framing/flush](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_conn.c#L234)、[conn创建/configure/connect顺序](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_conn.c#L340)、[creation callback](https://c-ares.org/docs/ares_set_socket_callback.html)、[Mbed TLS读写合同](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.7/include/mbedtls/ssl.h)。

**DoH不是透明TLS socket**：channel期待DNS datagram或2-byte DNS/TCP frame，HTTP头/状态/chunked/H2 frame直接喂给它必然不成立。
若不改channel核心，shim必须缓冲完整DNS request→一次HTTP exchange→验证body→重构channel期待的DNS frame，并用逻辑fd/就绪信号表达结果；这已经是完整DoH适配层，Age元数据还必须进入cache之前处理。
channel先cache insert、后用户completion；在用户callback里扣Age已来不及修正内置cache。需要输入body先减TTL、cache插入前hook，或关闭内置cache交给外层。[response/cache顺序](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_process.c#L1021)、[DoH交换合同](https://www.rfc-editor.org/rfc/rfc8484.html#section-4)
普通query接口保留ID关联却不提供本轮证实的单问题single-flight；`ares_cancel`取消整channel，返回qid也不等于有公开per-query cancel。若只撤一个waiter，要保留有限pending直到真实结清，或新增精确取消接口。[send](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_send.c#L128)、[cancel](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_cancel.c#L29)

## 开放DoT PR提供的是改造范围证据

2026-10-03核对 [PR#1252](https://github.com/c-ares/c-ares/pull/1252/files)仍为Open；refs/pull/1252/head固定为 `108178f98689bc1035a6dd210d5a34184cb4cf94`，它不属于1.34.8发布能力，本轮没有导入。
其修改并非一组send/recv hooks：新增crypto backend、conn握手/读写状态、process兴趣/pending进度、server配置与析构，还处理TLS session复用与early-data。明确有READ_WANTWRITE/WRITE_WANTREAD四种状态。[固定crypto header](https://github.com/c-ares/c-ares/blob/108178f98689bc1035a6dd210d5a34184cb4cf94/src/lib/crypto/ares_crypto.h#L39)、[固定conn](https://github.com/c-ares/c-ares/blob/108178f98689bc1035a6dd210d5a34184cb4cf94/src/lib/ares_conn.c#L233)
backend选择只有OpenSSL／Windows Schannel；非Windows默认OpenSSL≥3，**没有Mbed TLS backend或DoH**。直接使用它会增加本题不愿默认带入的第二crypto项目；改为Mbed TLS是另一适配与认证/生命周期验证工作。[固定CMake](https://github.com/c-ares/c-ares/blob/108178f98689bc1035a6dd210d5a34184cb4cf94/CMakeLists.txt#L722)
所以它说明DoT channel fork可行的结构工作，不能证明发布版或本项目已有轻量、完整、安全、Android-ready实现。

## 两种fork与原HEV模块的维护比较

| 路线 | 实际复用 | 新增责任与维护面 | 本轮位置 |
| --- | --- | --- | --- |
| c-ares wire/cache窄改＋HEV传输 | wire parser/write、RR/SOA语义；可评估复用cache容器/expiry | 补公开TTL/offset或外部cache/计量接口；拆cache对channel/query依赖；HEV层做TLS/DoT/HTTP和生命周期 | **优先探索**，同时回应少依赖、DNS解析复用与缓存复用 |
| 深fork c-ares channel内置TLS/DoH | ID、TCP framing、retry、timeout、callbacks、现有qcache | 新Mbed TLS backend、AUTH_PENDING/TLS状态、HTTP事务、Age/cache修正、byte cap/per-query cancel；同时维护通用channel与HEV两套状态衔接 | 第二顺位；不能以“一处代码”证明更小 |
| 只用公开wire API＋HEV私有DNS模块 | 成熟parser/encoder无需改上游；HEV owner/会话/调度 | 有限pending、wire cache、TTL位置与HTTP语义由模块承担；避免维护channel内核fork | 窄cache改造不能保持小范围时采用 |
| 前轮c-ares＋libcurl multi＋完整TLS | 成熟DNS codec与成熟HTTP/连接管理 | 三类组件、curl同步open与异步broker适配；若H2再有nghttp2 | 成熟传输后备，当前不默认增加 |

现有qcache保存解析树、哈希/到期结构，insert需要channel/query，key取opcode/RD/CD/question；没有cache字节/条数硬限。TTL递减函数在private header，外部响应也没有公开insert入口，**不能直接把私有qcache抽成独立cache**。[qcache](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_qcache.c#L26)、[insert](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_qcache.c#L426)、[TTL private API](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/record/ares_dns_private.h#L56)
窄改须先定义有界owned response与完整key：缓存wire还是解析树、record树分配如何计量、外部Age如何注入；SOA负TTL、NODATA、TC、未知EDNS及响应尺寸仍需核对。若为此改遍send/process/conn，就已经偏离窄改，应回到HEV层有限wire cache。
正/负TTL校验、wire压缩指针/未知RR/报文长度是复杂协议面；不建议拿mapped-DNS的A-only、修改request缓冲的parser扩成完整RR库。[mapped实现](../../third_party/hev/upstream/src/hev-mapped-dns.c#L197)、[c-ares完整parser](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/record/ares_dns_parse.c)

## 少库DoH也需要真正的HTTP client合同

最小范围建议为固定HTTPS endpoint、POST `application/dns-message`、显式bootstrap IP＋认证hostname、HTTP/1.1、每连接一个在途exchange、有限待发queue；不为低吞吐目标增加H2/HTTP3/QUIC或连接multiplex引擎。
只有endpoint接受HTTP/1.1才成立；DoH推荐HTTP/2但并不强制最低只能H2。若用户选的endpoint只接受H2，必须重新计入相应协议实现，不能悄悄取消DoH或退明文。[RFC8484 §5.2](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.2)
ALPN只能协商本实现确实支持的协议，hostname/CA照常验证；不把“连到IP”当证书认证。当前Mbed TLS连SSL/X.509源/header都未保留，须扩充同pin的export/hash/config/CMake，不能只开一个宏。[当前export](../../third_party/mbedtls/README.md#L1)、[实际8文件target](../../third_party/mbedtls/CMakeLists.txt#L1)
HTTP层至少处理增量status/header、1xx/最终状态、Content-Length、chunked/trailers及合法结束方式、TE/CL歧义拒绝、Content-Type、Age、body/header/行数硬限、EOF/部分读写/timeout/cancel、连接重用与失效。
明确不自动跟redirect、不做代理、不请求压缩即可缩小范围，但要报告相应HTTP失败；这些范围不能靠TLS透明socket省掉，也不能把收到的200响应body全收进无界buffer。[HTTP framing RFC9112 §6](https://www.rfc-editor.org/rfc/rfc9112.html#section-6)、[chunked §7.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-7.1)、[DoH errors/Age](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)

本轮只补看一个更小输入：H2O官方 **picohttpparser**，固定commit `465a7ff09fbd3432fe56c673451f5460154d1f07`。`.c+.h`提供response/header parser与in-place chunked decoder；stateless、不自行分配内存、MIT/Perl双许可，官方源码有维护修复。[固定README](https://github.com/h2o/picohttpparser/blob/465a7ff09fbd3432fe56c673451f5460154d1f07/README.md)、[固定修复commit](https://github.com/h2o/picohttpparser/commit/465a7ff09fbd3432fe56c673451f5460154d1f07)
它只省HTTP**语法parser**，不提供TLS、socket、client事务、连接池、DNS或TTL缓存；借用指针指向输入buffer，生命周期/硬限由owner模块控制。可作为替代手写HTTP语法的窄选项，不能冒称一个现成HEV DoH client。[固定header](https://github.com/h2o/picohttpparser/blob/465a7ff09fbd3432fe56c673451f5460154d1f07/picohttpparser.h)

## 最小数据方向与缓存预算

```text
App防护就绪 / 当前generation → 启用原owner的DNS本地会话模式
内侧UDP/TCP完整query → VPP同一DNS政策 → 允许后cache／有限single-flight
→ HEV任务：broker授权 → TLS → DoT frame或有界HTTP/1.1 exchange
→ 完整wire response + Age/时间/上游epoch → cache候选 → 原owner内侧session
→ 现有output/独立copy/return graph → Android TUN
```

cache条数N、实际字节B、单条尺寸L、pending/waiter数和bytes、连接/任务栈/TLS buffer分别有界；按owner预算之和算总量。无论窄fork还是自有cache，都缓存上游数据，每个新查询重走当前policy，不能cache allow。
正TTL按经过时间减；DoH先扣Age；负缓存依SOA TTL与MINIMUM；OPT不当TTL改。保留全wire/原QTYPE/QCLASS/EDNS语义，原ID/内侧TCP framing按waiter恢复；不拿地址列表合成简化答案。[RFC2308](https://www.rfc-editor.org/rfc/rfc2308.html#section-5)、[RFC8484](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)
同问题合并由有限owner模块或明确窄cache/transaction接口负责；c-ares cache或HEV任务存在本身不是已证实single-flight。epoch/stop取消后响应必须拒绝旧token，内侧原包按现有completion完成，不等上游才释放buffer。

## 当前可决定与小集合未知

可决定的是**路线排序与owner复用**：现有HEV＋同Mbed TLS完整能力＋私有DNS职责优先；c-ares窄wire/cache改造优先于channel深fork；libcurl从默认降为后备。DNS/HTTP codec是否需要小外部parser按维护总成本选，不堆高层resolver。
仍需后续证明：①选定DoH endpoint的HTTP/1.1/ALPN兼容；②Mbed TLS完整export/config/符号/CA/RNG闭包；③c-ares cache接口能否保持窄改、bytes/TTL/Age正确；④HEV DNS本地会话与protect/epoch/取消/stop/return图闭环。
本轮是固定源码与公开合同研究；未新建host验证，未测NDK/ARM64/RSS/电量。现有 `/tmp` c-ares源码只用于阅读，开放PR只作工作范围证据；正式API、VPN运行合同与实现均未冻结。
