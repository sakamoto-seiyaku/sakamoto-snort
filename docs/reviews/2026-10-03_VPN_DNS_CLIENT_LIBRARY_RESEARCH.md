# VPN DNS客户端与缓存库：收窄可行方向

2026-10-03。已读项目官方文档、固定版本源码、发布记录；未安装依赖、编译、测量、操作设备或修改产品代码。研究目标是TUN内DNS的记录/过滤、允许查询转发到加密上游所需的**stub/forwarder组件**，不是从根服务器开始递归。
比较c-ares、getdns、Hickory三个真实候选，另核对复用传输的边界。用户已进一步收窄：**产品自身加密上游只需DoT、DoH，不需要DoQ**。外部App的DoQ/DoH3拦截是另一问题，不构成本客户端引入QUIC的理由。

**后续用户硬约束：Rust引入新运行时不可行。** 专门架构研究确认Hickory的TLS／HTTPS路线需要Tokio，因此该路线已退出当前候选；下文保留其组件能力证据和此前条件分析。当前比较转到现有C事件循环、socket broker与小型缓存层，不把语言选择与新运行时成本混为一谈。

详见后续[资源与接入专项研究](2026-10-03_DNS_CLIENT_RESOURCE_INTEGRATION_RESEARCH.md)及[两席研究取舍](2026-10-03_DNS_CLIENT_AND_SYSTEM_HOOK_ASSESSMENT.md)。

## 结论先行

- C侧c-ares报文层可以保留，但加密请求需另外接入TLS／HTTPS客户端；它本身不是完整加密方案。Hickory组件虽覆盖DoT／DoH，其TLS／HTTPS所需新运行时已被用户排除。
- getdns stub-only是C/DoT专门备选，已发布版不能覆盖所需DoH。不要为缓存顺手引入完整递归解析器。
- 本轮没有“最小二进制/最低内存/最快”的实测证据；轻量应由启用feature、请求/响应上限、缓存占用、连接复用和已有依赖决定。
- 自身上游DoT/DoH需求已明确，DoQ已排除；库版本、C/Rust模块归属、缓存具体容量尚未选定。Android资源切换优化已排除，不在本报告重新扩展。

## 固定版本与能力对照

| 候选 | 本轮读的版本 | 编解码/请求 | 缓存 | 已证据化加密传输 | Android与license |
| --- | --- | --- | --- | --- | --- |
| c-ares | v1.34.8，2026-07-07发布 | C wire API；异步UDP/TCP stub | channel query cache、TTL上限、NXDOMAIN+SOA | 发布版未提供所需DoT/DoH；DoT仍开放PR，需要额外TLS/HTTPS传输方案 | 官方支持Android，有JNI初始化要求；MIT |
| getdns | v1.7.3，2022-12-22发布 | C异步stub；wire↔dict；任意RR请求 | 本轮未确认stub-only提供可限容量的响应缓存 | DoT；发布说明把DoH列为后续新增 | 未确认当前Android NDK支持/测试；BSD-new |
| Hickory | v0.26.3，2026-09-10发布 | Rust proto编解码、net传输、resolver高层解析 | resolver `ResponseCache`，正/负TTL与条数容量 | net的TLS/HTTPS feature提供所需DoT、DoH | 官方列Android，源码有Android JNI配置路径；MIT OR Apache-2.0，MSRV1.88 |

版本来自[c-ares发布主页](https://c-ares.org/)、[getdns发布](https://github.com/getdnsapi/getdns/releases/tag/v1.7.3)、[Hickory发布](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3)。能力依据分述如下，表格不是实机兼容保证。

## c-ares：C解析候选好，但不能把解析器缓存当任意DoH报文缓存

官方把它定义为异步C stub resolver，提供UDP/TCP请求与事件循环集成。`ares_dns_parse`、`ares_dns_write`、record API可直接处理DNS报文、问题、各段RR、TTL；可用于TUN内查询检查和响应解析，不必只用`getaddrinfo`。[v1.34.8 README](https://github.com/c-ares/c-ares/blob/v1.34.8/README.md)、[wire API](https://c-ares.org/docs/ares_dns_parse.html)、[RR API](https://c-ares.org/docs/ares_dns_rr.html)

内建query cache默认启用、最大TTL3600秒；成功结果和包含SOA的NXDOMAIN可缓存。源码对NXDOMAIN取SOA TTL与MINIMUM较小值，不存TC截断响应；查询缓存结构是哈希表+到期索引+max_ttl。[官方缓存说明](https://c-ares.org/features/#query-cache)、[v1.34.8缓存源码](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_qcache.c)

**TTL上限不是容量上限。** 本轮读到的公开配置仅提供`qcache_max_ttl`，未确认条数/字节硬限，也未证明相同在途查询会合并。它的cache用于通过channel发出的查询，不能假设只使用parser、外部HTTP发包后会自动进入该cache。[配置API](https://c-ares.org/docs/ares_init_options.html)、[发送与内部cache入口](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_send.c)

加密能力必须按版本写：DoT PR#1252目前是**Open**，官方后续issue谈的是这项提案的后续工作；本轮核对main源文件列表也没有合入其TLS实现。不能把issue正文里的“initial implementation”当作稳定版能力，也不能宣称这个项目永远不做DoT。[开放PR](https://github.com/c-ares/c-ares/pull/1252)、[后续issue](https://github.com/c-ares/c-ares/issues/1255)、[main源列表](https://github.com/c-ares/c-ares/blob/main/src/lib/Makefile.inc)

Android系统DNS配置读取有明确JNI步骤与`ACCESS_NETWORK_STATE`要求；这是官方Android支持证据，却不等于DNS客户端socket已经绕过产品VPN或按选定网络绑定。应用显式配置加密上游时，也不应无意回到系统DNS配置。[Android初始化](https://c-ares.org/docs/ares_library_init_android.html)

适用结论：可作为C侧wire parser/builders，以及纯UDP/TCP请求发动机备选。所需DoT/DoH由另一层负责认证、复用、超时和报文交换；不能仅选parser就声称加密请求和响应cache齐全。

## getdns：可裁成C/DoT客户端，完整协议需求不宜靠它推断

v1.7.3 README明确：`ENABLE_STUB_ONLY=ON`去掉libunbound；`USE_LIBIDN2=OFF`去掉IDN转换依赖，余下必需库为OpenSSL。额外event-loop扩展分别支持libevent/libuv/libev，不必全部带入；不要把默认完整构建的依赖误算为最小stub-only构建。[固定README](https://github.com/getdnsapi/getdns/blob/v1.7.3/README.md)

它有`getdns_general`任意请求类型及wire↔message dict工具，返回内容不是仅A/AAAA地址。但C dict/list接口与报文转换自身是集成工作，不能因为“C API”就称更小或零复制。[general API定义](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns.h.in)、[wire工具定义](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns_extra.h.in)

已发布transport list枚举只有UDP、TCP、TLS。stub源码有上游连接状态、query ID索引、写队列和idle timeout，可复用TLS连接并处理多个在途事务；**多事务复用不是相同问题合并**。发布说明明确说先发布修复再加DoH，不能把研究/未发布工作写成v1.7.3功能。[transport枚举](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns.h.in#L197)、[stub请求与连接源码](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/stub.c)、[发布说明](https://github.com/getdnsapi/getdns/releases/tag/v1.7.3)

还有`limit_outstanding_queries`与idle timeout配置，前者控制并发事务，后者控制空闲TCP/TLS连接保留；二者都不能当作响应cache容量或同问题去重合同。[固定扩展API](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns_extra.h.in#L968)

本轮没有找到stub-only容量可控的正/负响应cache合同；旧演讲中的“context包含cache”明确指libunbound，不能当作去掉libunbound之后仍有同等cache的证据。故若采用stub-only，本题响应cache和重复请求合并仍先按外层责任评估。[作者演讲，cache指libunbound](https://getdnsapi.net/slides/getdns-a-new-stub-resolver-vbsdcon-2015-expanded.pdf)、[context源码](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/context.c)

Android方面，固定README明确列出的平台没有Android；本轮没有NDK构建/实机证据。CMake与OpenSSL可交叉编译只是候选可行性，不可宣称拿来即用。它适合**DoT部分且已有OpenSSL/event-loop**时做备选；不能单库覆盖已明确的DoT/DoH集合。

## Hickory：区分报文、网络传输、stub缓存与递归

0.26已经分层：`hickory-proto`是报文编码/解码；`hickory-net`提供网络传输，本题使用其中TLS/HTTPS连接；`hickory-resolver`是高层stub及缓存；`recursor`是可选feature。**只依赖proto不会自动得到加密请求和缓存**，也无需引入server二进制才可使用这些库。[官方分层](https://hickory-dns.org/)、[v0.26.3 proto manifest](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/proto/Cargo.toml)、[net manifest](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/Cargo.toml)

net按feature选择`tls-{ring,aws-lc-rs}`、`https-*`。DoH加h2/http，TLS使用rustls/tokio-rustls。本题按DoT/DoH裁剪；库虽另有DoQ/DoH3扩展，**不为自身上游启用QUIC、quinn、h3，也不顺手带入DNSSEC或recursor**。删去未要求功能是配置取舍，不是体积/内存实测结论。[固定feature与依赖](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/Cargo.toml#L22)

resolver `ResponseCache`公开提供capacity（响应条数）、每记录类型正/负TTL边界、到期读取更新TTL，底层是moka。negative缓存只处理有语义的`NoRecordsFound`，不是把所有网络失败都当不存在；默认cache_size8192条。**条数限仍非字节硬限**，若响应尺寸大仍需外层输入/占用限制。[cache源码](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/cache.rs)、[默认与选项](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/config.rs#L532)

高层resolver还做搜索域、CNAME追随、特殊域处理与结果整理；TUN转发器不应只调用`lookup_ip`再拼一个简化答案而丢掉原查询/响应信息。选择低层Message/DnsHandle还是高层stub cache，应依据需要保留的QTYPE/QCLASS/flags/EDNS等合同；本轮未证明该低层路线已有同问题在途合并。[高层职责](https://docs.rs/hickory-resolver/0.26.3/hickory_resolver/)、[caching client](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/caching_client.rs)

官方列Android支持；系统配置源码确实经JNI/ndk-context读ConnectivityManager，说明不是仅桌面resolv.conf。它仍要求应用正确初始化Android context，不能假设daemon环境自动拥有Java context。上游socket保护、runtime接入及NDK各ABI也未实测。[Android源码](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/system_conf/android.rs)、[runtime扩展点](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/runtime.rs)

版本与构建限制：v0.26.3声明MSRV1.88、MIT OR Apache-2.0；0.26.2/0.26.3修了cache、parser及传输问题。应按固定manifest选择feature，不照抄API页中仍出现的旧feature名字；“Rust内存安全”也不意味着没有协议/资源耗用漏洞。[workspace manifest](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/Cargo.toml)、[官方发布记录](https://github.com/hickory-dns/hickory-dns/releases)

## 复用TLS/HTTPS传输：不是另一份DNS缓存

后续架构核查进一步确认：根[CMakeLists.txt](../../CMakeLists.txt#L5)虽然纳入`third_party/mbedtls`，实际只构建AES／GCM／SHA256等原语为`sakamoto_quic_crypto`；[配置](../../third_party/mbedtls/product_config.h#L1)明确标注用于QUIC Initial、没有TLS栈。因此不能将它计为已有SSL握手、证书验证或HTTPS客户端，也不能把本节提到的libcurl等候选写成项目已有依赖。[实际构建列表](../../third_party/mbedtls/CMakeLists.txt#L2)

若应用已经有可复用连接的HTTPS客户端，可发送DoH wire query、接收wire response，再由DNS库处理。libcurl普通POST支持指定二进制长度；应用必须明确DNS Content-Type等合同。无需为了这一点引入完整递归库。[POST API](https://curl.se/libcurl/c/CURLOPT_POSTFIELDS.html)、[DoH格式](https://datatracker.ietf.org/doc/html/rfc8484#section-4)

`CURLOPT_DOH_URL`是libcurl为**自己的目标主机名**选DoH解析器，不是“把任意TUN DNS报文交给它转发”的API；其内部DoH请求不继承`OPENSOCKETFUNCTION`也须注意。普通传输复用与libcurl内部名字解析是不同路径。[官方DoH option](https://curl.se/libcurl/c/CURLOPT_DOH_URL.html)

libcurl内部DNS cache更不能直接当本题响应cache：官方说明它不使用DNS TTL，而使用设定的时间窗口；这是HTTP客户端解析目标地址的缓存，不是完整RR、负答案及透明转发缓存。[内部DNS cache合同](https://curl.se/libcurl/c/CURLOPT_DNS_CACHE_TIMEOUT.html)

Android也提供平台HTTPS/TLS API，但可用API不等于本轮已证明其异步调度、socket保护、连接池及原始DNS响应路径满足产品要求。具体复用哪套传输，要先确认项目已经使用什么，不在此另装一套。[平台HTTPS API](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection)

## 此前的条件性方向与后续收窄

**此前Rust候选，现已排除其TLS／HTTPS路线。** Hickory-proto负责wire，hickory-net启用DoT/DoH transport；runtime需要接入或引入，不能假定应用已有Tokio。响应cache还要核对resolver ResponseCache的适配成本，或保持一个小且有界的外层cache。用户后续明确拒绝新增Rust运行时，因此这份功能证据不再构成当前推荐，不能凭删去QUIC宣称已无运行时成本。

**若DNS客户端采用C，wire层+实际TLS/HTTPS传输。** c-ares提供解析与构建；DoT需TLS事务层，DoH需HTTPS客户端，再由外层管理有限事务及TTL响应缓存。现有mbedTLS目标只有QUIC Initial所需加密原语，完整TLS／证书及HTTPS仍是新增集成。此方向可避免完整递归；相对Hickory仍有传输集成缺口，选择取决于模块归属与实际可复用依赖。

getdns仅保留为C侧DoT部分备选，固定发布版不能独自覆盖已要求的DoH。自身DoQ已排除；外部App的DoQ/DoH3 SNI拦截应另行分析，不反向扩大这里的客户端依赖。

## 本轮能确认与仍需实测的部分

可确认：组件职责、固定版协议列表、TTL/负缓存源码、容量参数是否存在、license、声明的平台与工具链。不能确认：在本项目NDK/VPP/Rust组合中的增量体积、RSS、Android唤醒、首查延迟、证书路径或请求取消质量。

下一步若获实现授权，按已确认的DoT/DoH集合保持同一查询与容量约束，核对冷/热查、同问题并发、正负TTL、超时取消、连接复用及受保护上游socket；**缓存命中仍不能跳过当前应用过滤决定**，库不替产品决定策略。具体owner、选库和cache key/大小先不冻结。
