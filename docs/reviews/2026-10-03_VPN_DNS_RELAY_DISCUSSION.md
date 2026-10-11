# VPN DNS：记录、过滤、缓存与加密上游

2026-10-03。继续Android标准防护讨论；记录用户明确的方向、平台证据和本轮建议。未选择依赖、修改产品代码、操作设备或更新正式运行合同。

**2026-10-05后续：** 用户要求先收敛VPN模式，确认原请求App归属未知时先允许解析，以及VPN内固定DNS服务地址；固定入口不是Fake-IP方案。放行查询继续缓存／加密上游，后续业务流按实际事实控制。用户明确mDNS／5353和内网查询兼容还需继续讨论；[最新行为讨论](2026-10-05_VPN_DNS_BEHAVIOR_DISCUSSION.md)将这些问题与已确认项分开，HEV／Mbed TLS／c-ares路线不再重排候选。

## 用户已明确的范围

- 系统DNS hook是`libnetd_resolv`改造路线，纠正此前framework入口的记忆。
- VPN DNS需要进入TUN，由产品记录和过滤；允许的查询由应用转到远程加密DNS上游，需要范围很小的DNS请求与缓存能力。
- “doc”已澄清为DoQ；用户随后明确**我们自身对外请求可以不要DoQ**。当前上游范围收窄为**DoT／DoH**，不为这一职责引入QUIC／DoQ客户端。
- 配合可见SNI阻止常见外部加密DNS服务，帮助域名过滤；这与产品自身选择哪种上游协议是两个问题。
- Android资源开关与提前优化已撤下，不继续推进模式自动裁剪、资源开关或资源排名。

本轮延续[普通使用与模式方向](../product/NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-03-确认防护模式方向并转入android域名过滤)。以下缓存顺序、返回方式和模块分工是建议，不能当作用户已经批准的全部实现细节。

**后续研究约束：** 用户进一步要求资源占用与缓存优先于高吞吐，尽量接入现有架构，并启动DNS库与libnetd／KernelSU专项研究。用户随后明确**新增Rust运行时不可行**；下表中的Hickory TLS／HTTPS路线因需要Tokio退出当前候选，C传输与缓存接入继续核对。系统hook研究需重点说明启动失败链和恢复边界。

最新[研究取舍](2026-10-03_DNS_CLIENT_AND_SYSTEM_HOOK_ASSESSMENT.md)汇合两席证据与本轮推荐，分别链接库接入和系统hook报告。

## 建议只承担一个小型DNS转发职责

```text
查询进入TUN → 记录查询和已取得的归属 → 判断当前适用的DNS政策／例外
  阻止 → 记录原因 → 返回明确的DNS拒绝结果
  允许 → 查有效响应缓存 → 命中则应答
                       → 未命中则经DoT／DoH上游请求 → 缓存有效答案 → 应答
```

入口保留实际捕获的普通UDP／TCP DNS，不只支持UDP53；5353的链路本地mDNS另行处理，不能送到公共上游。应用使用自带加密DNS时，TUN中看到的是其加密连接，不能从中直接读取每个业务查询。[Android VPN](https://developer.android.com/develop/connectivity/vpn)、[RFC1035传输](https://www.rfc-editor.org/rfc/rfc1035.html#section-4.2)、[RFC6762](https://www.rfc-editor.org/rfc/rfc6762)

这里需要向选定远程解析器转发的stub／forwarder，不需要从根服务器递归。报文组件保留原查询类型和响应语义，包含CNAME、HTTPS／SVCB等，不用`lookup_ip`或`getaddrinfo`的地址列表重造简化答案。请求关联、响应ID、截断与TCP语义由转发职责处理，不交给缓存猜测。

名单和例外仍由产品当前政策决定；DNS库负责报文、事务、传输与答案缓存，不持有另一套可编辑规则。DNS阶段只判断该阶段事实足以成立的政策，连接条件继续按统一合同处理，不新增“DNS天然更高”的优先级。[统一规则合同](../product/UNIFIED_RULE_ENGINE_SPEC.md)

## 缓存答案，每次查询重新判断政策

建议缓存有效上游响应数据，**不缓存“某应用已获允许”的决定**。新查询先经过当前过滤与例外判断，即使即将命中缓存也一样。

例如A应用获准访问某域名、B仍被阻止：A可以复用相同解析上下文的答案，B不能因缓存已有答案而获准。新增例外后，下一次进入TUN的查询按新政策处理；原有历史记录保持原结果。

一个小缓存仍需要以下基本正确性：

- 查询名、类型、class及会改变答案的flags／EDNS、上游和网络解析上下文正确区分；不是只用域名作key。
- 响应TTL按经过时间递减，过期不用；DoH还需扣除HTTP `Age`，不能用HTTP新鲜度延长DNS TTL。[RFC8484 §5.1](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)
- 正常NXDOMAIN／NODATA按SOA负缓存语义处理；网络超时、上游故障和本地政策拒绝不是同一种“不存在”。[RFC2308 §5](https://www.rfc-editor.org/rfc/rfc2308.html#section-5)
- 有明确响应尺寸、事务数量及缓存占用上限；条数上限和TTL上限都不等于字节上限。

本地阻止生成的答案不进入跨应用共享的上游答案缓存。系统或App可能在查询进入TUN前已经缓存答案或拒绝结果，所以保存例外不等于立即清空所有外部缓存。拒绝返回码、TTL和复测行为还需一起选定；本轮倾向明确应答，避免用纯丢包制造长时间等待。

相同问题的在途合并与上游连接复用是适合该职责的小功能，但不能仅凭库有cache或多事务连接就假定两者已经提供。

## 自身上游与外部加密DNS服务分开处理

产品上游socket必须避免重新进入自己的VPN，按需要绑定底层网络；Android提供`VpnService.protect`作为避免循环的机制。解析上游服务器地址也要有不依赖自身待建立DNS通路的启动办法。[Android VPN socket保护](https://developer.android.com/develop/connectivity/vpn)

这应是产品所创建上游事务的受控通路，不能把某个解析服务域名对所有App整体放行。上游身份验证、超时、取消与连接失效属于客户端基本职责。上游不可用时应记录“解析服务失败”；建议不静默退回未经选择的明文DNS，是否使用备用加密上游继续讨论。

外部服务拦截建议表达为“阻止可识别的常见外部加密DNS服务”。可见SNI可以提供名单匹配事实，但ECH会隐藏真实ClientHello；自建服务、无可用SNI及未命中名单的连接仍可能通过，不能承诺所有查询都会回到本产品。[RFC9849](https://www.rfc-editor.org/rfc/rfc9849.html)

产品自身不做DoQ，不意味着外部App不做DoQ或DoH3。若补充识别这些外部服务，可读QUIC握手事实仍有意义；这不要求运行一个DoQ请求客户端。DoQ本身是QUIC上的DNS协议，与DoH3不同。[RFC9250](https://www.rfc-editor.org/rfc/rfc9250.html)

阻止某App的严格加密DNS可能导致其联网失败，不保证自动回退。排查需要能呈现“解析服务连接被阻止”，让验证后的必要例外与普通业务域名例外保持准确。

## 轻量库：按DoT／DoH重新收窄

固定版本能力、源码及缓存证据见[客户端库研究](2026-10-03_VPN_DNS_CLIENT_LIBRARY_RESEARCH.md)。本轮没有体积或内存实测，不能宣称哪个候选最小。

| 方向 | 能承担的职责 | 剩余选择 |
| --- | --- | --- |
| C报文层：c-ares | DNS wire编解码；自身channel的UDP／TCP请求及query cache | 发布版不直接提供所需DoT／DoH；需要TLS／HTTPS传输和适用于外部响应的有界cache，不能假设parser会自动缓存外部DoH响应 |
| 此前Rust候选：Hickory | proto报文、net的TLS／HTTPS传输；resolver有TTL缓存组件 | TLS／HTTPS需要Tokio；用户已明确新增Rust运行时不可行，此路线退出当前候选 |
| C／DoT专门备选：getdns stub-only | 去掉libunbound后提供TLS stub请求 | 固定发布版不覆盖DoH；缓存容量和Android接入也未实测，不能单库作为完整DoT／DoH方案 |

后续核查确认，现有mbedTLS目标只编译QUIC Initial所需加密原语，并没有TLS栈；完整TLS／证书及HTTPS不能计为现有能力。[实际配置](../../third_party/mbedtls/product_config.h#L1)、[构建列表](../../third_party/mbedtls/CMakeLists.txt#L2)。c-ares报文API和Hickory功能开关有官方证据；排除新Rust运行时后，当前C方向仍需核对传输与缓存的实际接入成本。[c-ares wire API](https://c-ares.org/docs/ares_dns_parse.html)、[Hickory v0.26.3 feature](https://github.com/hickory-dns/hickory-dns/blob/v0.26.3/crates/net/Cargo.toml)

## 应用归属与后续需要决定的事

VPN查询归属不能靠前台App猜。AOSP记录OEM的`enforceDnsUid`可能将DNS包标为`AID_DNS`而非原App UID；因此从查询socket取得的UID不总是原请求者。能取得可靠归属时可用于应用例外，否则记录实际未知范围，不能把公共解析器UID冒称业务应用。[Android16固定源码](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp#715)

继续讨论的重点是：拒绝答案与复测、上游失败时的加密备用、准确应用例外的可用范围，以及DNS客户端放在哪个模块。缓存具体大小和选库随后决定；Android资源开关不重新开题。

本产品包域仍是ADR-0006／0007的VPP-native C主线。新的DNS代理职责将改变此前普通DNS直通边界，待设计明确后更新正式合同；不借选库恢复旧C++ daemon、另建包策略引擎或跨语言传递活跃包缓冲。[决策入口](../decisions/README.md)
