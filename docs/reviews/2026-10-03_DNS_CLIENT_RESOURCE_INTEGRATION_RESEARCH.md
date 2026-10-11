# DNS 客户端：资源、缓存与当前架构接入

2026-10-03。基于[前轮选库](2026-10-03_VPN_DNS_CLIENT_LIBRARY_RESEARCH.md)与[VPN DNS讨论](2026-10-03_VPN_DNS_RELAY_DISCUSSION.md)，本轮重新核对固定发布源码和当前 Product；只作选择建议，未批准或实现新的 DNS 转发合同。
用户约束：自身上游仅 **DoT／DoH**；缓存与资源占用优先于峰值性能；**引入新的 Rust 运行时不可行**。Android资源开关、预先模式优化不重开。

后续澄清：本报告的组合推荐不是“只有c-ares可用”或“DoT／DoH没有现成客户端”。getdns是现成C DoT候选，libcurl可发送DoH报文；推荐优先比较资源、完整响应缓存与现有异步平台接入的总成本。职责区别见[研究取舍](2026-10-03_DNS_CLIENT_AND_SYSTEM_HOOK_ASSESSMENT.md#dns当前倾向原owner内的c组件)。

**后续用户再次收窄：少集成库、优先复用HEV，也考虑改造c-ares。** 下文的c-ares＋完整TLS＋libcurl组合保留为此前比较项，不继续作为当前首选。新增[HEV复用与c-ares fork研究](2026-10-03_HEV_DNS_REUSE_AND_CARES_FORK_RESEARCH.md)单独评估原HEV基础、DNS功能差别和集中改造的维护成本；本报告中的固定源码与主机证据仍保留。
本轮只新增本文件；已有 dirty 改动保留。未读被移除的 Snort C++、历史 daemon／host／archive 源码，未操作设备、Plane、产品依赖或正式 ADR／API。

## 明确建议

**首选 C 组合：c-ares 1.34.8 的公开 wire API + Product 自己的有限 wire 响应缓存；DoT 使用完整 C TLS 后端与小型事务层，DoH 使用裁剪后的 libcurl 8.22.0 multi。**
TLS 后端优先验证同一套完整 Mbed TLS 供两种传输使用；当前仓库的 Mbed TLS 3.6.7 只是 primitive subset，补全客户端 TLS／证书／随机源属于新增依赖工作，并非现成复用。
DNS模块放在 **VPP-native C 的原 FlowOwner 内**，由现有 fd／timer 驱动；不另起 DNS executor，不把查询送入 Rust ProductCore 的控制 session。
理由是复用已存在的 owner、reactor、Android保护路径，缓存数据和硬限可直接收紧；不是已证明 C 的 RSS 或电量最低，也不是 c-ares 自动提供了 DoT／DoH／外部响应缓存。
**Hickory TLS／HTTPS 路线排除**：发布 feature 与实现都需要 Tokio，违反最新约束。getdns 仅能承担 DoT 部分，还引入 OpenSSL、缺 DoH 与本题缓存，不能替代整个组合。
固定发布入口：[c-ares 1.34.8](https://github.com/c-ares/c-ares/releases/tag/v1.34.8)、[Hickory 0.26.3](https://github.com/hickory-dns/hickory-dns/releases/tag/v0.26.3)、[getdns 1.7.3](https://github.com/getdnsapi/getdns/releases/tag/v1.7.3)、[curl 8.22.0 发布表](https://curl.se/docs/releases.html)。

## 当前真正拥有和缺少什么

| 能力 | 当前源码证据 | 接入含义 |
| --- | --- | --- |
| TLS 基础 | [Mbed TLS CMake](../../third_party/mbedtls/CMakeLists.txt#L1)仅编译 AES/GCM/SHA256 等8个文件；[配置](../../third_party/mbedtls/product_config.h#L1)明确无 TLS/PSA/分配；[pin说明](../../third_party/mbedtls/README.md#L1)明确无 X.509/RNG | 不存在可直接调用的完整 TLS 客户端；不能把当前 QUIC Initial 解密算作握手、证书或 DoT |
| HTTP／HTTPS | [Product plugin 链接](../../src/product/vpp/CMakeLists.txt#L274)为 HEV/LPI/QUIC crypto；[Rust manifest](../../crates/product-core/Cargo.toml#L9)只有 idna/rusqlite/serde/json | 当前闭包没有 libcurl、H2、rustls、Tokio 或通用 HTTPS 客户端；Android 平台 API 可用不等于项目已经集成 |
| C reactor／timer | [Flow Stack driver](../../src/product/vpp/product_vpn_flow_stack.c#L54)注册 owner-local fd/timerfd；[bounded turn](../../src/product/vpp/product_vpn_flow_stack.c#L350)推进 HEV、安排最近 deadline | 可作为 C DNS 状态机和 curl multi 的调度基础；不是把 HEV poll fd 当任意库的通用接口 |
| socket protect／bind | [C broker](../../src/product/vpp/product_vpn_socket_broker.h#L6)异步 SCM_RIGHTS + generation/session/owner；[Java broker](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VpnSocketBroker.java#L97)先 protect 再 Network.bindSocket | 已有实际 socket 授权能力；DNS fd/token 路由仍需接线，不能假设任意库新建的 socket 自动受到保护 |
| 网络失效 | [Java underlay更新](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/VpnSocketBroker.java#L165)串行发送 invalidation；[driver invalidate](../../src/product/vpp/product_vpn_flow_stack.c#L128)目前交给 HEV | DNS连接、未使用的预授权 fd、pending事务和缓存解析上下文必须接入相同 epoch 失效 |
| DNS wire／缓存 | [当前 DNS/mDNS recognition](../../src/product/vpp/product_flow_lpi.c#L47)和[协议目录](../../src/product/vpp/product_protocol_catalog.h#L36)不是 relay/cache | 尚无完整普通 DNS 转发、HTTP Age、正负响应缓存或同问题合并；FlowEntry policy cache 不能代替答案缓存 |
| typed control | [接口路由](../INTERFACE_SPECIFICATION.md#L15)、[Java协议](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java#L3)、[Rust session](../../crates/product-core/src/session.rs#L90)、[VPP API](../../src/product/vpp/product_core.api#L1) | 可继续承担启停、配置、状态；当前没有 DNS 数据面请求协议，不应把逐查询转发塞进控制 session |

约束仍是 [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)：VPP worker不等 socket／protect／解析；传输回调在原 owner；活跃 `vlib_buffer_t`、FlowEntry、PCB/pbuf 不跨语言或异步借用。
现有 [Flow Stack界面](../../src/product/vpp/product_vpn_flow_stack.h#L9)和[metadata约束](../decisions/VPP_PACKET_METADATA_OWNERSHIP.md)提供独立存储与少量按值事实；本建议沿用它们，不建立第二策略引擎或全局 transport authority。

## c-ares：合适的 wire 层，缓存与传输不能冒领

1.34.8公开 `ares_dns_parse/write`、question、各 RR section、ID、flags、SOA及SVCB/HTTPS字段；未知 response RR可保留为 RAW_RR，不需走 `getaddrinfo` 地址列表。它分配解析对象和序列化输出，须显式销毁，不能称零分配。
源码只接受一个 question；RR总数会先按剩余 wire最短记录长度校验，再预分配。普通 QUERY适配是合理起点，不能据此宣布任意多question／UPDATE／DSO透明代理已成立。[公开header](https://github.com/c-ares/c-ares/blob/v1.34.8/include/ares_dns_record.h)、[parser](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/record/ares_dns_parse.c#L1230)、[unknown type映射](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/record/ares_dns_mapping.c#L82)

固定源码的 native channel仍是UDP／TCP，没有本题加密传输；只调用wire API不创建channel、不启动resolver事件线程，也不读取Android系统DNS配置。[构建源列表](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/Makefile.inc)、[初始化](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_init.c)
其 query cache是channel内部能力：`ares_send_nolock`先查cache，再各自建立query对象；内部cache insert需要channel/query。外部 libcurl 或 TLS收到的响应没有公开cache插入入口。[send](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_send.c#L128)、[cache](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_qcache.c#L426)
内部cache有TTL上限、SOA-based NXDOMAIN、拒绝TC；结构没有条数／字节上限，key只取opcode、RD/CD、question，并不包含EDNS或网络上下文。NODATA不能仅类推NXDOMAIN；其NOERROR路径排除SOA后取其他RR最小TTL。[cache结构/key](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_qcache.c#L26)、[TTL逻辑](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/ares_qcache.c#L245)、[options](https://github.com/c-ares/c-ares/blob/v1.34.8/include/ares.h#L371)
**公开API也没有批量TTL递减入口**：`ares_dns_record_ttl_decrement`在私有header；不能调用私有qcache或偷用其TTL字段形成Product合同。[private header](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/record/ares_dns_private.h#L56)、[writer](https://github.com/c-ares/c-ares/blob/v1.34.8/src/lib/record/ares_dns_write.c#L1222)
所以首选使用它做验证／语义提取／构造；cache存**独立wire**和校验过的TTL位置，不长期保存c-ares对象树。TTL位置收集和有限parser临时内存是产品小层的实质工作，不能省略。
`ares_library_init_mem`可替换malloc/free/realloc，但函数指针是库级初始化而非每cache的allocator；若用来限定临时解析分配，应在启动时一次安装并正确归属所有c-ares分配，不在worker轮流改全局allocator。[初始化API](https://c-ares.org/docs/ares_library_init.html)

## DoT／DoH：保持现有reactor，补真实传输

**DoT**：完整Mbed TLS客户端做证书链、hostname/SNI、随机源与非阻塞TLS读写；外层只做2-byte长度framing、ID/问题关联、deadline、连接生命周期和有限pending。`WANT_READ/WRITE`回到现有fd订阅，不在worker内循环等待。[Mbed TLS 3.6.7 SSL API](https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6.7/include/mbedtls/ssl.h)、[DoT RFC7858 §3](https://www.rfc-editor.org/rfc/rfc7858.html#section-3)
Mbed TLS补全不能盲目再链接一份默认配置：当前target把 `MBEDTLS_CONFIG_FILE=product_config.h`设为PUBLIC，完整TLS的header/ABI/config与同名crypto符号要统一或隔离验证。仅把库名相同算作“免重复依赖”是不成立的。[当前CMake](../../third_party/mbedtls/CMakeLists.txt#L6)

**DoH**：libcurl普通HTTPS POST传 `application/dns-message` wire，并限制headers/body；读HTTP状态、Content-Type和Age，然后交给DNS层。`CURLOPT_DOH_URL`只负责curl自己的名字解析，本题不用该内部路径。[POST长度](https://curl.se/libcurl/c/CURLOPT_POSTFIELDSIZE.html)、[DoH option](https://curl.se/libcurl/c/CURLOPT_DOH_URL.html)、[RFC8484 §4](https://www.rfc-editor.org/rfc/rfc8484.html#section-4)
采用multi socket/timer callbacks映射到当前owner fd registry/timerfd，事件到达再调用 `curl_multi_socket_action`；不创建libuv、Tokio或独立executor。[固定multi API](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/curl_multi_socket_action.md)
curl有active连接数、连接cache数、connect/request timeout；**内部排队easy handles仍需产品总pending上限**，连接cache更不是DNS答案cache。DoH body callback超限即中止，不能先完整收下再量长度。[active连接限](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/opts/CURLMOPT_MAX_TOTAL_CONNECTIONS.md)、[保活连接限](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/opts/CURLMOPT_MAXCONNECTS.md)、[WRITEFUNCTION](https://curl.se/libcurl/c/CURLOPT_WRITEFUNCTION.html)
资源上有一个可复用点：8.22.0文档说明transfer接收buffer默认16KB，8.7起由同一multi的easy handles共享，在有active transfer时保留；`BUFFERSIZE`只是请求，不能当硬限。TLS记录buffer、证书链、H2流缓存与应用wire缓冲仍须分别计量。[固定buffer合同](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/opts/CURLOPT_BUFFERSIZE.md)

**同步open callback对异步broker是真缺口。** curl的opensocket回调必须立即交fd或失败，不能在里面等Java protect/bind；已有 `request/reply`也只接HEV session。
最窄适配建议是每owner持有有限的、未连接的**预授权fd**：先通过现有broker完成protect/bind，校验generation/epoch后才允许curl启动该连接；opensocket只领取匹配family/epoch的fd，容量不足留在产品有限等待队列。
这不是现成能力：须增加owner-local DNS授权token分发、close callback、重连补充与epoch失效；禁止复用失效fd，也不以新线程／阻塞worker绕过。socket仍由其C owner持有，Java只处理duplicate。[curl open callback合同](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/opts/CURLOPT_OPENSOCKETFUNCTION.md)、[当前driver request/reply](../../src/product/vpp/product_vpn_flow_stack.c#L107)
上游bootstrap用显式地址与证书hostname分别配置；curl `CURLOPT_RESOLVE`可保留URL hostname/SNI却给定目标IP。关闭curl异步resolver后尤其不能让一次遗漏触发阻塞 `getaddrinfo`；所有endpoint必须验证已提供地址。[固定RESOLVE API](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/opts/CURLOPT_RESOLVE.md)

curl的 `CONNECT_ONLY` + `easy_send/recv`也能交换TLS内任意字节，但它不提供DoT framing/ID管理、connect-only不能复用普通HTTP连接cache。这里只记为复用同TLS后端的备选接口，不将它当已完成DoT库；ALPN与DoT认证仍要明确。[CONNECT_ONLY](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/opts/CURLOPT_CONNECT_ONLY.md)、[send](https://github.com/curl/curl/blob/curl-8_22_0/docs/libcurl/curl_easy_send.md)

## 最小依赖／feature裁剪

以下是固定manifest可核对的配置方向，不是已经通过NDK链接的产品依赖清单。协议裁剪不等于削弱TLS认证。

| 组件 | 保留 | 移除或必须补的项 |
| --- | --- | --- |
| c-ares 1.34.8 | static/PIC公开wire API；库级init/cleanup | `CARES_SHARED=OFF, CARES_BUILD_TOOLS=OFF, CARES_BUILD_TESTS=OFF, CARES_INSTALL=OFF`；没有官方“只编parser”target，靠正常静态链接裁未用对象；不实例化channel/event thread |
| 完整C TLS | 客户端握手、X.509验证、hostname、随机源、必要算法 | 当前primitive config不能使用；DoT与curl尽量同后端，CA信任材料与config/symbol一致性需补；不引入服务器/DTLS职责 |
| libcurl 8.22.0 | HTTPS普通POST、multi；`CURL_USE_MBEDTLS=ON, CURL_USE_OPENSSL=OFF`作为单后端验证组合；所选DoH endpoint支持的HTTP版本 | `HTTP_ONLY=ON`；关闭工具/tests/examples/docs、proxy/cookies/HSTS/alt-svc/内部DoH；`ENABLE_ARES=OFF, ENABLE_THREADED_RESOLVER=OFF`；关libpsl/libssh2/zlib/brotli/zstd；关NGTCP2/QUICHE/ECH；HTTP/2若保留则需要nghttp2 |
| Hickory proto 0.26.3 | codec可独立 `default-features=false, features=["std"]` | 不自动带TLS/runtime/cache；Android仍有manifest中的target JNI依赖；本轮不再开另一codec路线 |
| Hickory net 0.26.3（排除） | `default-features=false, features=["tls-ring","https-ring"]`可去掉QUIC/H3/DNSSEC | TLS仍强制Tokio net/rt/time/rt-multi-thread + rustls/tokio-rustls/ring；HTTPS加bytes/h2/http，不能删掉运行时还保留原实现 |
| Hickory resolver 0.26.3（排除） | 关闭default可去system-config，recursor/DNSSEC/QUIC/H3均可不启用 | moka(sync)/parking_lot/小容器仍是非optional依赖；加入resolver会启用proto access-control；`cache_size=0`不删cache代码/依赖 |
| getdns 1.7.3（DoT部分备选） | `ENABLE_STUB_ONLY=ON, USE_LIBIDN2=OFF`；关event扩展/工具/Stubby/tests | 去libunbound与IDN后仍依赖OpenSSL SSL+Crypto；不能换成现有mbedTLS primitives；禁native stub DNSSEC的本轮host组合编译失败，见下 |

表的源头：[c-ares CMake](https://github.com/c-ares/c-ares/blob/v1.34.8/CMakeLists.txt#L36)、[curl CMake](https://github.com/curl/curl/blob/curl-8_22_0/CMakeLists.txt)、[Hickory workspace](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/Cargo.toml)、[proto](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/proto/Cargo.toml)、[net](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/Cargo.toml)、[resolver](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/Cargo.toml)、[getdns CMake](https://github.com/getdnsapi/getdns/blob/v1.7.3/CMakeLists.txt#L122)。
HTTP/2是DoH的推荐最低HTTP版本，不是“去HTTP/2就不可能DoH”；若考虑HTTP/1.1裁nghttp2，必须先验证选定endpoint兼容性，不能以少一个依赖牺牲实际可用性。[RFC8484 §5.2](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.2)

## Hickory为什么不能靠cache或自定义provider留下来

`RuntimeProvider.connect_tcp`是不错的异步socket授权seam，但0.26.3 `h2::connect`直接 `tokio::spawn`连接driver，TLS/HTTPS还直接使用Tokio timeout/tokio-rustls；替换provider不能去除这些依赖。自行重写TLS/H2 runtime适配是另一实现项目，本题不走。[runtime trait](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/runtime.rs#L251)、[H2 connect](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/h2.rs#L245)、[TLS](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/tls.rs)
启用rt-multi-thread feature不等于一定运行多线程调度器，但本题**新运行时本身不可行**；即使current-thread runtime也不能绕过约束。
其 `DnsResponse`同时拥有解析后的Message和wire Vec；`ResponseCache`存完整Message或有语义的NoRecords错误，命中clone Message并递减TTL，确实不是仅IP cache。[response](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/proto/src/op/dns_response.rs#L25)、[cache](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/cache.rs#L24)
不过cache key是 `Query(name,type,class)`；不能直接覆盖RD/CD/DO/EDNS、上游/网络上下文。正负TTL默认最小0、最大86400秒，可配置且不应人为上调TTL；默认8192条也不是本题资源预算。[Query](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/proto/src/op/query.rs#L65)、[TTL边界](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/cache.rs#L405)、[默认cache](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/config.rs#L698)
`ResponseCache::new`未设Moka weigher；容量是响应条数，Moka本身是best-effort eviction，不提供本题“插入前拒绝超字节预算”的硬限。Moka 0.12.15由上游lockfile固定；它**没有专门维护线程**，由调用者触发维护，write channel满时可能等待维护，不能把它描述成必然后台线程也不能直接放进预算严格的VPP turn。[builder调用](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/cache.rs#L39)、[Moka容量](https://docs.rs/moka/0.12.15/moka/sync/struct.Cache.html)、[维护源码说明](https://github.com/moka-rs/moka/blob/v0.12.15/src/lib.rs#L170)、[upstream lock](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/Cargo.lock)
H2客户端有request timeout，body累计在65535 bytes前拒绝超限，但它并未读取HTTP Age；这个协议尺寸限也不等于可选择的更小响应/解析heap预算。[H2 response](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/h2.rs#L331)、[body cap](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/http.rs#L163)
DoT multiplexer默认32个active请求、5秒timeout、可配置且会清理取消的请求；这不是同问题合并。CachingClient走“cache miss→各自lookup→insert”，没有使用Moka get_with单飞；本轮不声称Hickory已经去重。[multiplexer](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/src/xfer/dns_multiplexer.rs#L102)、[cache miss](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/resolver/src/caching_client.rs#L172)

## getdns：仅DoT也没有本项目无缝优势

1.7.3 transport仅UDP/TCP/TLS，发布说明仍把DoH列为后续；stub-only可去libunbound，OpenSSL仍必需。[固定transport](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns.h.in#L197)、[release](https://github.com/getdnsapi/getdns/releases/tag/v1.7.3)、[依赖裁剪](https://github.com/getdnsapi/getdns/blob/v1.7.3/README.md#L113)
可挂自定义eventloop vtable；支持 outstanding query limit、timeout/cancel、连接idle timeout及多事务TLS复用，但默认outstanding与idle均0，必须显式设置。它在stub内部自己socket/connect，没有本轮确认的、可等待Android异步broker的公开socket创建seam。[eventloop](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns_extra.h.in#L192)、[defaults](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/context.c#L1438)、[socket/connect](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/stub.c#L470)
本轮stub/context源码没有找到容量可控的完整正负答案cache或同问题单飞合同；多事务连接复用不等于这两者。去libunbound之后按外层cache评估，不能引用完整recursive context的cache作证明。
因此它会增加OpenSSL闭包、socket接线、dict/list/wire转换，同时DoH和有限cache仍要另一层；对当前推荐组合没有足够收益，不选为主依赖。[一般查询/响应界面](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/getdns/getdns.h.in)、[stub](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/stub.c)

## 有限缓存应是什么

这是产品小层建议，不设尚未获批准的具体数值。各库现有cache都不能直接满足这里的完整键、HTTP Age与硬字节限。

| 约束 | 建议的可检查行为 |
| --- | --- |
| 缓存对象 | 保存有效**上游wire响应**、插入时间、TTL位置与解析上下文；不缓存“某UID获准”、本地拒绝或超时；不走lookup_ip重造答案 |
| 键 | 规范question name/type/class + 改变答案的RD/CD/DO/EDNS + 选定上游及underlay/解析配置epoch；未知/有事务身份的EDNS先不共享缓存，原查询仍按明确传输合同处理 |
| 容量 | 条数N、总实际cache存储字节B、单条wire长度L同时硬限；key/TTL索引/metadata也计入B；先腾位或拒绝cache插入，不能只设置最大TTL |
| 响应大小 | 网络body/frame的输入限先于parser；超过cache单条限但满足传输限的有效答案可以应答而不缓存；传输限、cache限、临时parser预算分别记录 |
| TTL | 到期不用；hit按elapsed递减每个真正RR TTL，OPT里的EDNS字段不是TTL；完整wire采用保守过期，不用仍存活A记录掩盖已过期CNAME/附加记录 |
| 负缓存 | NXDOMAIN/NODATA取SOA TTL与MINIMUM较小者，并受负TTL上限约束；无有效SOA不假设可负缓存；SERVFAIL/timeout/本地policy refusal不能混成不存在 |
| DoH Age | 接收时先扣HTTP Age，再扣本地elapsed；不能以HTTP max-age延长DNS TTL；Age耗尽TTL不插入有效cache |
| 同问题合并 | 同owner、同完整key的pending事务共享上游交换；每个waiter先过本次政策，分别保存ID/原question/transport session；waiter数与其字节也有独立硬限 |
| 取消 | waiter取消只释放自身；最后waiter取消、generation结束或epoch失效结清pending；旧响应不能命中新transaction/session；连接ID复用需防迟到回应 |
| 空闲 | 只对当前选用上游按有限数保活，明确idle关闭；cache过期可读时懒删或复用现有最近deadline，不另开周期维护线程；不预热未使用协议 |

TTL与Age依据：[RFC8484 §5.1](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)、[RFC2308 §5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5)、[EDNS OPT格式](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.1.3)。缓存wire的TTL位置处理必须验证压缩指针/记录长度，避免RAW RDATA移动后破坏原压缩引用；c-ares公开RR getter不是wire offset API。
每owner分配cache预算，**总预算是各owner之和**；允许重复答案以保持现有FlowOwner，不为提高命中率增加第二哈希分派或全局锁。N/B/L与连接/pending/waiter上限一起作为后续验证参数，不照搬库默认值。

## 最窄接入草图：接实际文件／函数

```text
TUN → shared graph / original FlowOwner / 当前政策 → product_vpn_egress_node
    → product_vpn_flow_stack_driver_input → input_copy → owner-local lwIP
    → 新的有限 DNS datagram／TCP message hook → 记录/调用同一Product DNS政策
    → 允许后：wire cache / 合并pending → C DoT状态机或 curl multi DoH
    → 原owner的generation+session+incarnation结果 → lwIP原UDP/TCP会话
    → output_packet → Product output callback → product_vpn_tun_submit_return
    → 新VPP buffer / FLOW_STACK_RETURN → shared graph → Android TUN
```

入口定位是 [product_vpn_egress_node](../../src/product/vpp/product_packet_graph.c#L1790)与[driver input](../../src/product/vpp/product_vpn_flow_stack.c#L295)；前者当前只做post-policy普通TCP/UDP handoff，**并没有DNS拦截**。
建议新增私有 `product_dns_client` C模块，由 `product_vpn_flow_stack.c`每owner实例持有，保存独立DNS wire、cache、pending、transport，不暴露VPP/HEV dependency类型；step/deadline加入既有bounded turn。
目前 [product_vpn_flow_stack_hev.c](../../src/product/vpp/product_vpn_flow_stack_hev.c#L79)只映射L3 input/output；[HEV receive_input/session_task](../../third_party/hev/product/hev-owner.c#L355)只有Direct UDP队列与socket，[TCP task](../../third_party/hev/product/hev-owner.c#L466)只有Direct桥接。
因此**尚缺解码后的DNS payload hook和响应注入hook**：需在现有owner-local Flow Stack内部接UDP datagram和TCP的2-byte message framing/分段/多message；不能把每个TCP packet当一条DNS请求，也不能只做UDP53就称闭环。
DNS会话必须在 `create_session/tcp_session_task`建立原始Direct socket之前选入本地DNS会话模式；尤其不能先连接原目的端口53，再接管已解码查询。TCP仍由原owner的lwIP维护内侧握手/分段，这个本地会话模式是新增hook的一部分。[当前Direct socket创建](../../third_party/hev/product/hev-owner.c#L283)、[当前TCP创建/连接](../../third_party/hev/product/hev-owner.c#L491)
graph对原始packet的DROP按既有completion结清；它不会自动变成DNS拒绝应答。完整query取得后，DNS query-level拒绝才可由本地会话生成明确答案，两者的政策衔接与拒绝返回合同仍待单独定义。
hook只按值交可靠UID/unknown、网络epoch及有限return token；策略仍由当前VPP配置/共同规则实现决定，DNS库不存另一份allow名单。[当前配置所有权](../adr/0009-unified-rules-and-vpp-owned-configuration.md)、[包/会话事实](../../src/product/vpp/product_vpn_flow_stack.h#L87)
响应先回原lwIP会话，使TCP序号/重传和UDP封装继续由现有栈负责；其 [output_packet](../../third_party/hev/product/hev-owner.c#L188)→[Product output](../../src/product/vpp/product_vpn_flow_stack_hev.c#L38)→[submit_return](../../src/product/vpp/product_vpn_tun_adapter.c#L100)已有复制、provenance、incarnation与正常graph scheduling，不从库直接写TUN。
原始VPP buffer照现有completion结清，不持有至DNS上游响应；异步pending持有独立wire和token。旧session/epoch/generation返回拒绝，stop先取消/排空DNS债务再让既有stopped闭包成立。
Java仍只供underlay/protect/bind与监督；Rust仍只承载粗粒度typed配置/状态。新增DNS配置/状态字段需后续单独设计，本轮不冻结API或普通DNS Direct边界。

## /tmp固定版本主机证据与剩余验证

仅使用已存在的GCC 12.2、CMake/Ninja，全部在 `/tmp/dns_resource_integration`，未安装系统或repo依赖：

- c-ares tag tar SHA256 `ddf8be8b179ef6ff656e7413da93cf0f3038c627aca29ce9aae30f66e5b32bc1`；MinSizeRel/static/PIC、关shared/tools/tests/install，正常构建 `libcares.a` **PASS**；库级init + 29-byte QUERY parse/write/destroy smoke **PASS**。
- 该host archive为461100 bytes；smoke `size`为text144543/data2016/bss8，空main为1209/528/8。它包括本次静态链接闭包，不包括TLS、curl、cache、VPP或Android；不据此推导RSS、唤醒、耗电或本产品最终增量。
- getdns官方tar SHA256 `f1404ca250f02e37a118aa00cf0ec2cbe11896e060c6d369c6761baea7d55a2c`与release一致。stub-only、关IDN/event扩展/tools/tests、MinSizeRel，使用host OpenSSL3.0.20构建静态库 **PASS**；未做网络查询或Android证书测试。
- 相同getdns配置再设 `ENABLE_NATIVE_STUB_DNSSEC=OFF` **FAIL**：context.c的ub_setup_stub重复变量r及未屏蔽unbound_ctx引用。恢复默认ON后PASS，未修改源码；故不能声称所有不需DNSSEC的代码可由该选项可靠裁掉。[固定出错源码](https://github.com/getdnsapi/getdns/blob/v1.7.3/src/context.c#L3421)
- Hickory读取固定tag manifest/lock/source，未构建；libcurl／完整Mbed TLS未构建。依赖裁剪是源码证据，host ARM64／NDK／实机、完整组合体积/RSS/电量均未测。

后续只需一个范围小的集成验证集合：①完整C TLS/curl闭包与mbedTLS config/symbol一致性及CA路径；②既有reactor上的pre-authorized fd、broker迟到/失败、重连/epoch/stop；③完整wire、TTL/Age、NXDOMAIN/NODATA、EDNS key、N/B/L及pending/waiter硬限；④UDP与TCP分段/并发/取消/旧session回应、return graph归属。
上述是检验推荐组合是否成立的工作，不是新增运行时或设备测试的授权；峰值吞吐benchmark与资源模式开关不在此范围。
