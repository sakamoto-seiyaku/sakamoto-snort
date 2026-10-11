# 临时讨论：VPP fork 的 DPI 功能可能性

日期：2026-10-06。用户希望先讨论 DPI 能带来的产品功能，本报告保持在功能层面，不展开处理流程、接口或实施方案。

**状态：临时讨论／参考材料，不是正式产品文档或已确认需求。** 用户明确当前是在讨论可能性与取舍，可反驳、可辩论；后续观点不因写入此处而自动成为决定。本稿已从正式产品入口撤下。下面保留fork能力调查，供讨论取舍，不把能力清单当作产品推荐清单。

参考工作树为 `/home/js/backup/backup/Git/vpp`，HEAD 为 `837432be3b6cf496755cfa27b7cca439734eb726`。以下是外部 fork 的静态源码证据，不表示 Sakamoto 已实现、默认启用或接受全部功能；没有构建、运行、设备操作或代码导入。

## 功能地图

| 功能方向 | fork 中能确认的能力 | 可以讨论的产品功能与边界 |
| --- | --- | --- |
| 协议／业务分类控制 | LPI 与 qDPI 提供协议／应用签名结果，appsketch 将结果送入 `APPLICATION_OBJECT`／`APP_ID` 对象匹配。[A1]、[A2]、[A3] | 按识别到的业务协议制定政策，如文件传输、远程访问或通信协议。这里的“应用”是流量分类，不能直接解释为本机进程／Android App 身份；不能由 qDPI 名字推成完整 IDS、漏洞检测或病毒查杀链。 |
| HTTP 路径与请求条件控制 | URL／解码 URL 有 `URL_OBJECT` 扫描入口；请求／响应 header 有正则与关键词入口，body 有关键词入口。HTTP method、请求行、Host、User-Agent 等也能解析／记录，但本轮不把每个独立字段都宣称为现成规则条件。[H1]、[H2]、[H3] | 可细化到同一网站的特定路径，以及可见请求／响应内容条件，而不只封锁整个域名。method 独立规则条件仍未确认。适用明文 HTTP，或已成功终止 TLS 的代理通路。 |
| 可见内容匹配与条件改写 | HTTP body、邮件正文／附件内容、FTP 内容有关键词扫描入口；HTTP proxy 有拒绝、替代回应、文字／文件替换、页面元素编辑及 JS／CSS 插入分支。[C1]、[C2]、[C3] | 可讨论敏感关键词阻止、上传／下载内容限制、条件页面改写；HTTP enforcer 还有自定义回应／重定向，阻止动作可选 TCP reset 等终止回应。[C4]、[C5] 不据此承诺完整 DLP、任意文件类型识别、文件哈希信誉或恶意软件查杀。 |
| TLS／QUIC 指纹与握手诊断 | TLS JA3／JA3S／JA4／JA4S、QUIC JA3／JA4 有关键词对象入口；TLS ECH、完整 ClientHello 无 SNI、malformed ClientHello 有布尔对象入口。版本、证书 CN／SAN、握手时延等也有提取／记录字段。[T1]、[T2]、[T3] | 可讨论按握手指纹或明确异常事实控制，并展示连接特征、异常和加密情况。不能把所有证书／版本字段都说成已接规则；指纹是识别线索，不是软件身份或恶意行为的唯一证明。 |
| 其他协议的对象与行为 | FTP 账号／路径／内容、邮件账号／收发件人／主题／附件名／内容、SIP 主叫／被叫有对象扫描入口；SSH banner、RDP 主机名／安全协商等有记录字段。[O1]、[O2]、[O3]、[O4] | 可讨论账号／通信对象／传输对象政策及协议详情展示。SSH／RDP 字段提取不能直接扩大成任意命令、屏幕内容或文件内容控制；加密后的内部业务仍受可见性限制。 |
| DNS 查询阶段控制 | QNAME 对象匹配后可丢弃查询，或生成／修改 DNS 答复；独立 HTTP proxy 中也有 DoH 查询匹配／答复操纵路径。[D1]、[D2] | 查询阶段阻止域名、返回配置答案。该能力已另行研究，不能把它等同完整本机 resolver、答案缓存或自己的 DoH／DoT 上游客户端。[DNS 专项](2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md) |
| 协议事务洞察 | scanner 可生成 HTTP、DNS、邮件、SIP 等事务记录；字段包含请求／响应信息、状态码、响应时延、握手时延及通话时长等。[I1]、[I2]、[I3] | 可展示“这次请求访问了什么、是否有响应、耗时多少”等协议活动，帮助解释规则和诊断。记录／导出是观测功能，不自动形成阻止条件，也不保证所有事务都被完整记录。 |

“有字段”与“能控制”要分别描述。本报告将已见对象扫描入口列为匹配候选，将只有 `log_name` 的字段列为提取／记录；具体部署是否启用、规则是否配置及运行效果仍未验收。HTTP Host、TLS 版本／证书字段、SSH／RDP 信息尤其不能因为 decoder 能读就统一宣称可用于封锁。[H1]、[T1]、[O4]

## 加密可见性决定功能范围

被动识别 TLS／QUIC 握手元数据，不意味着能读取 HTTPS 的 URL path、header、body 或邮件／文件密文。fork 确有 TLS 中间人代理与 HTTP 操纵代码：用自己的 CA 签发替代证书，并分别与客户端、真实服务器建立 TLS；客户端必须接受此证书，证书 pinning、双向认证等可能阻止代理处理。存在这条代码路径也不代表默认启用。[V1]、[V2]、[V3]、[既有代理核对](2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md#4-缓存上游加密与应用身份已确认和未确认)

TLS 1.3 中 ServerHello 后的握手消息已加密，因此被动观察不能普遍读取服务端证书。ECH 保护 ClientHelloInner；外层可见名字可以是公共名称，识别到 ECH 扩展不能还原真实目标域名。它也不能把“本轮尚未取得 SNI”直接当作“完整 hello 没有 SNI”。[RFC 8446 §1.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-1.2)、[RFC 9849 §6.1.2](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.2)、[完整 hello 判定][T2]

## 对当前功能讨论的意义

SNI 之外有三类明确扩展空间：**更细的匹配对象**（协议、URL、账号、内容、指纹），**协议层回应／内容改写**，以及**更丰富的活动与诊断信息**。功能选择应保留上述可见性和证据层级；本轮不决定优先级，不把参考 fork 的功能清单升级为 Sakamoto 需求或架构决定。

已有专项材料：[LPI／SNI 处理参考](2026-09-23_LPI_SNI_FORK_PROCESS_REVIEW.md)、[观测与导出边界](2026-09-15_OBSERVABILITY_VPP_FORK_RESEARCH.md)、[DNS 功能参考](2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md)。

[A1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:574
[A2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_qdpi_detector/stellar_qdpi_detector_node.c:111
[A3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_node.c:326
[H1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:422
[H2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:480
[H3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:1342
[C1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:503
[C2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:742
[C3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_proxy/manipulation/http_proxy_manipulation.c:2348
[C4]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:1121
[C5]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:1809
[T1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:964
[T2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:1005
[T3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:1187
[O1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:1202
[O2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:637
[O3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:1260
[O4]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:1390
[D1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:1408
[D2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_proxy/manipulation/http_proxy_doh.c:614
[I1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:308
[I2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:600
[I3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:954
[V1]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_proxy/proxied_conn/proxied_conn.c:2370
[V2]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_proxy/tls/tls_key_keeper.c:907
[V3]: /home/js/backup/backup/Git/vpp/src/plugins/stellar_proxy/proxied_conn/proxied_conn.c:2469
