# 协议补充识别：公开参考与替换边界

研究日期：2026-09-25。设计讨论材料，不改变正式规格、ADR、Plane 或实施 Goal。用户已确认保留启发式／补充识别；本文比较其来源与接入选择，不重新讨论是否保留。

## 结论及证据强度

**有值得超过现有 fork 补充层的公开参考，首选考察 nDPI 的逐协议 detector；Zeek 和 Suricata 更适合借鉴“候选→解析确认／失败”的过程，Wireshark 适合核对结构校验和反例。** 这不等于建议立即替换 LPI，也不等于任意项目整体更准或手机上更快。下面的能力判断来自官方文档／源码，强度较高；移植成本与优先级是针对本项目合同的工程推断，尚无同流量基准。

当前 [T12 合同](../interfaces/T12_PUBLISHED_PROTOCOL_FACTS.md) 使用官方 LibtraceTeam `97a8efecd257ec09f652374399f27b3a65db7d0a`，公开 DNS、HTTP、TLS、QUIC、SSH 五类事实；QUIC v1/v2 Initial 头由产品补充识别。预算为每 Flow 20 次有 payload 尝试、32 KiB 检查额度；已有 56 字节状态、同步借用 payload、无逐包分配。预算和 published facts 累积方式是比较替代方案的约束，不是待套用的第三方默认值。[T12 验收](../testing/2026-09-25_T12_PUBLISHED_PROTOCOL_FACTS.md)

## Geedge：记忆的年份正确，但“更全／同源”尚不能证实

InterSecLab 原始调查页日期是 **2025-09-09**；GFW Report 的 FOCI 2026 原始研究明确记载原始材料于 **2025-09-11** 对公众发布。前者是调查发布，后者是资料公开，不能混成同一天。因此以今天计，“去年”确实是 2025 年。[InterSecLab 原始调查](https://interseclab.org/research/the-internet-coup/)、[GFW Report 原始研究 §2.1](https://gfw.report/publications/foci26b/en/)

资料含源码、内部文档、部署包等，但**公开披露不等于获得开源许可**。本轮仅看公开报告和元数据，没有下载／镜像泄漏包，没有将泄漏源码列为可移植依赖。GFW Report 研究的是域名集合与审查测量，并指出客户规则名单在泄漏中相对少见；域名数量不能证明协议检测器覆盖率或准确率。现有主源不足以核实 Geedge 与本地 `stellar_lpi` fork 的代码亲缘、相同版本，或“检测规则更全面”。这些保留为未证实说法。[研究范围与限制](https://gfw.report/publications/foci26b/en/)、[公开事件综述](https://gfw.report/blog/geedge_and_mesa_leak/en/)

## 可行候选

| 来源 | 识别依据、状态与覆盖方向 | Unknown／端口与纠错 | 接入形态、许可和维护判断 |
| --- | --- | --- | --- |
| **libprotoident 官方 upstream** | 双向前四字节、长度等有限特征；通用应用协议分类。适合保留低状态基线 | 个别规则可用端口；输出需要产品映射，未识别不代表流最终不属于任何协议 | 已接入；库源码 LGPL-3.0-or-later。官方 README 显示 2.0.15；本轮未取得可靠最新提交日期，不能称已停更，也不能假定现代 TLS/QUIC 都已覆盖。[仓库](https://github.com/LibtraceTeam/libprotoident)、[库头／许可](https://github.com/LibtraceTeam/libprotoident/blob/master/lib/libprotoident.h) |
| **nDPI** | C DPI 库，逐协议 detector、跨包状态、TLS/QUIC 元数据；最接近可单独评估的分类引擎 | 多种证据来源与置信度；有猜测和停止／give-up 行为。端口、IP 或域名推断不能无差别当作 payload 确认 | 可评估完整库，也可研究单 detector；LGPL-3.0-or-later。TLS/QUIC 主线仍有现代版本逻辑。完整接入要测每 Flow 状态、可选分配、加密依赖和 CPU，不能沿用 LPI 的 56 字节结论。[内部说明](https://www.ntop.org/ndpi-internals-and-frequent-questions/)、[源码与许可](https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/wireguard.c) |
| **Zeek DPD / analyzers** | payload 签名启动 analyzer，后者继续解析；可按连接启停多个 analyzer，覆盖通用及专用协议 | 能超越端口识别，也能在解析不成立时停用 analyzer；适合借鉴“弱命中不是最终确认” | 完整 Zeek 带连接、事件与脚本框架，不是直接塞进 VPP 的规则数组。BSD 三条款主体许可，具体依赖另核；优先参考过程及签名。[DPD 原理（历史官方文档）](https://old.zeek.org/development/howtos/dpd.html)、[当前签名框架](https://docs.zeek.org/en/current/frameworks/signatures.html)、[许可](https://github.com/zeek/zeek/blob/master/COPYING) |
| **Suricata app-layer detection** | 协议检测引擎与 parser 配合，方向和协议切换有独立表达；通用网络服务解析 | 官方区分尚未识别的 `unknown` 与检测失败／退出的 `failed`，以及 original/final、双向不一致；这比一个 Unknown 值信息更完整 | C/Rust 引擎及流还原状态，不是下载 IDS 攻击规则就能替换 LPI。GPLv2 许可体系，文件／依赖另核；整引擎引入须重新核算状态和线程所有权。[引擎](https://docs.suricata.io/en/latest/devguide/internals/engines/)、[状态语义](https://docs.suricata.io/en/suricata-8.0.0/rules/app-layer.html)、[许可](https://github.com/OISF/suricata/blob/main/LICENSE) |
| **Wireshark heuristic dissectors** | 结构、长度、类型和保留位组合校验，覆盖协议细节丰富；识别后可绑定 conversation | 启发式优先级与端口分发表影响结果；官方明确提醒 RTP 启发式可能误认，不能当绝对真值 | 更适合反例和离线交叉核对。完整 libwireshark 带 dissection/conversation 框架；GPLv2 许可体系，具体文件另核。不能把 dissector 数量当自动识别能力。[启发式开发说明](https://github.com/wireshark/wireshark/blob/master/doc/README.heuristic)、[协议分派](https://www.wireshark.org/docs/wsug_html_chunked/ChCustProtocolDissectionSection.html)、[许可](https://github.com/wireshark/wireshark/blob/master/COPYING) |

本表是源码许可标识盘点，不替代发行方式的逐依赖核对；复制检测代码与独立依据协议规范实现是不同接入方式。TLS/QUIC 的后续维护需要跟踪版本、握手和加密可见性，不能仅维护一个协议名称表。可在线查看的分支链接是 2026-09-25 的研究入口，若开展实施，应固定 commit 与对应测试语料。

## 比 fork 补充层更具体的三个改进点

本地参考 HEAD 为 `837432be3b6cf496755cfa27b7cca439734eb726`。`stellar_lpi_extend.c:1021` 是固定顺序的 16 个 first-match 检查；含 TLS、FTPS、QUIC、DNS、IMAP、OpenVPN、SMTP/FTP 纠错、DTLS、Stratum、GBT32960、SOCKS、RDP、RTP、SIP 和 common_ports。它只替换**本次**库结果再映射，不能撤销已累计 facts。[已有过程核对](2026-09-23_LPI_SNI_FORK_PROCESS_REVIEW.md)

1. **WireGuard 的跨包结构确认。** nDPI 校验保留字节、握手 148/92 字节长度，并核对双向 sender/receiver index；也有 cookie 与 transport 状态路径。它给出比单包魔数／端口更丰富的证据；该 fork 的 16 项补充链没有 WireGuard 专项。这里只比较补充层，不宣称整个 fork 加底层 LPI 都不认识 WireGuard；nDPI 本身也有重传等较弱确认分支，不应将所有结果宣传成完整握手验证。[官方 detector](https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/wireguard.c)
2. **QUIC v2 与 Initial 解析。** fork 补充层 `is_specific_quic_version` 列到 RFC9000 v1／旧草案，未见 v2 `0x6b3343cf`；nDPI 主线明确包含 v2 及 Initial 加解密相关路径。现代维护是实质可比较的差异。但当前产品 T12 已补 v1/v2 头识别，剩余收益应看结构验证与后续解析，不能把 v2 再列作产品缺失，也不能混淆 fork 另有的 QUIC decoder。[nDPI QUIC 源码](https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/quic.c)、[fork decoder 专项](2026-09-23_FORK_TLS_QUIC_PROCESS.md)
3. **命中后验证、失败后退出。** Zeek 的签名负责启动解析，解析器可否定错误候选；Suricata 将暂未识别、退出失败、方向冲突和协议变化分开。这比 first-match 加端口兜底提供了更明确的纠错过程，但不是可直接导入的几行规则。[Zeek DPD](https://old.zeek.org/development/howtos/dpd.html)、[Suricata app-layer 状态](https://docs.suricata.io/en/suricata-8.0.0/rules/app-layer.html)

## 对现有架构的两条路径（供决策，均未实施）

**保留 LPI，加有界补充 detector：** 与用户保留启发式的决定兼容，也最接近当前 T12 seam。建议先用公开来源筛选目标检测器和反例；端口作为候选先验，结构／方向证据决定发布。当前 facts 只增不减，因此“纠正本次 LPI 猜测”应发生在发布前；一旦误判已发布，后续追加正确协议并不会消除误判。需要撤回历史 facts 时必须明确改合同，不能把 fork 的本次替换说成已有撤回能力。这是由 T12 union 语义推导的设计限制。[T12 合同](../interfaces/T12_PUBLISHED_PROTOCOL_FACTS.md)

**完整替换分类引擎：** nDPI 是值得优先做对照实验的库形态候选，但是否值得替换取决于目标协议的净增益。Zeek／Suricata／Wireshark 整体接入会额外带入流、解析或运行时框架；在 owner-local Flow、统一 TCP 缓存和不扣包的边界内应先证明适配可行。不能因为“协议更多”就宣布替换。

两条路径用同一组有真值的流量比较：常用／非标准端口、短包与分段、单向抓包、随机／相似头负例、STARTTLS、QUIC v1/v2；记录误报、漏报、Unknown／预算停止、首次可信结果包数、每 Flow 内存和 ARM64 CPU／吞吐。外部工具结论只作交叉证据。20 包／32 KiB 内未完成应保留停止原因，不伪造协议阴性；SNI 仍由自己的有界消费者取得，不把更多 detector 的元数据自动并入公开事实。

## 后续协议清单核对

用户已明确不接入完整 nDPI，只选择性借鉴检测规则。固定核对官方
`4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b` 的注册器和实际 detector，
而非只依据协议枚举；下面是可参考范围，不是本产品已实现清单。

### 用户确认的取舍

用户明确：“32960 不需要他了，我们是个人终端不是新能源汽车，其他两个可以，适当补充吧。”
本轮因此排除 GB/T 32960；以 nDPI 检测逻辑为主要参考，选择性补充 fork 的
同协议特征和有用标签细分。SMTP/FTP banner 纠错、非标准端口或短首包特征，
以及 SOCKS 版本等细分属于可评估范围，不表示逐条照搬或未经验证就宣称支持。
标签粒度更细不等于新增可靠识别能力，例如 fork 的 Stratum 弱猜测仍需样本验证。
下文 GB/T 32960 的源码发现保留为研究事实，不再是产品候选。
本决定收敛了此前“保留启发式”的范围，并不要求维护全部 fork 行为或其原有优先级。
未接受复杂的跨包误判撤回机制，也不接入完整 nDPI 引擎。

### 源码覆盖事实

- Web／安全传输：HTTP、明文 HTTP/2 preface、TLS、QUIC、DTLS、SSH。
- DNS／发现：DNS、mDNS、DHCP/DHCPv6、NTP、SSDP。
- 邮件／文件：SMTP、IMAP、POP3及相关 TLS 升级、FTP 控制／数据、FTPS、SMB。
- 隧道／代理：OpenVPN、WireGuard、SOCKS4/5、IKE/IPsec、GRE、GTP-C/GTP-U。
- 实时通信：STUN、RTP、RTCP、SIP。
- 物联网／服务：MQTT、CoAP、RESP、MySQL、PostgreSQL。

[固定注册器](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c)、
[固定 detector 目录](https://github.com/ntop/nDPI/tree/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols)。
其中 GRE/ESP/AH 包含 IP protocol 分类路径，不应称为 TCP/UDP payload detector；
QUIC 也不等于已独立确认 HTTP/3。DoH/DoT 有合并标签及域名／端口等关联规则，
不能据名称声称能解析加密的 DNS 内容。

fork 补充链的输出绝大部分已有 nDPI 对应检测器。明确差异包括：

- 在该固定 nDPI 全部 `src` 中未找到 GB/T 32960 的 ID／注册／detector；
  fork 有 `##`、长度和 XOR 校验，属于额外协议候选。
- nDPI 已有独立 FTPS，不能误记为只有 FTP_CONTROL+TLS；其 `ftp_control.c`
  包含 AUTH TLS/SSL 响应后的升级路径。
- nDPI 识别 Stratum v1 后输出 Mining，SOCKS4/5统一为SOCKS，TCP/UDP RDP
  统一为RDP；这些是标签粒度差异，不应重复计为新增协议。
- fork 的 SMTP/FTP banner 纠错、非标准端口 RDP、短首包 HTTP 和端口兜底
  可作为补充样例，但尚无同流量证据证明准确率收益。其首字节 `{` 的 Stratum
  猜测尤其不能因标签更细就称为更可靠识别。

[fork GB/T32960](</home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_extend.c:714>)、
[nDPI FTPS](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/ftp_control.c#L209-L236)、
[Stratum](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/mining.c#L61-L76)、
[SOCKS](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/socks45.c)、
[RDP](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/rdp.c#L137-L200)。
