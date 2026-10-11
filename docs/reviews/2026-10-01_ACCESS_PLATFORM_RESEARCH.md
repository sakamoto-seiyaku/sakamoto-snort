# 访问意图默认方案：平台事实研究

日期：2026-10-01。仅使用官方文档、平台源码与 RFC；事实经在线核对。本文是设计输入，不是设备验收或新 ADR。未操作设备、安装模块、改产品或 tracker。

结论：可以把“限制这个应用联系这个域名”作为默认创作语言，由产品组合能力；需要把**意图、当前执行覆盖、实际观察到的结果**分开。平台资料支持这个目标的研究价值，不能支持“有 Root/KernelSU 就能准确识别并阻断全部域名访问”的保证。

## 四项能力必须分别证明

| 能力 | 能证明什么 | 不能直接推出什么 |
| --- | --- | --- |
| 看见 DNS 包 | 捕获范围内出现了某名称查询/回答 | 原调用 app、实际访问已经发生 |
| 知道调用 app | 在特定接口/连接上得到 UID 或调用身份 | UID 唯一对应包名、所有 profile 均已覆盖 |
| 干预名称解析 | 在覆盖的解析路径拒绝/改变查询结果 | 缓存、已有连接、自带解析器全部失效 |
| 按域名限制访问 | 在声明的名称证据、身份与流量范围执行限制 | 任意加密流量、所有 HTTP 请求目标均已辨识 |

这些区别由以下平台事实导出；界面不必把四种机制做成四份规则库，但后端 contract 必须保留区别。

## Android 与 KernelSU：事实

1. **KernelSU 是权限/模块基座。**官方描述的是内核模式授予 userspace root；模块支持启动脚本、SELinux 规则、属性与 systemless 修改，系统文件挂载由 metamodule 提供。文档并未定义 DNS 查询语义、原 app UID 或域名访问拦截接口；“因此 KSU 自带 DNS hook”没有来源支持。[KernelSU 简介](https://kernelsu.org/guide/what-is-kernelsu.html)、[模块合同](https://kernelsu.org/guide/module.html)
2. **具名 DNS module 尚未提供。**“某 KSU 模块可直接 DNS”只能列为待识别候选；需明确仓库/版本、hook 点、支持 Android/APEX 版本、调用身份、缓存覆盖与故障行为，然后实证。不能把任意 module、hosts 修改或 resolver 重定向当成同一种能力。这是本轮资料缺口，不是否定未来接入。
3. **系统解析具有语义入口与缓存。**AOSP Resolver 支持 Java `InetAddress`、`Network` 与 native 解析，发送查询并缓存回答；Android 10 后为 `com.android.resolv` APEX，通过 `/dev/socket/dnsproxyd` 服务。查询入口与实际出站 DNS 包是不同观察点。[AOSP Resolver 架构](https://source.android.com/docs/core/ota/modular-system/dns-resolver)
4. **调用 UID 有事实基础，但包层不总等价。**Android 16 `DnsProxyListener` 从 `cli->getUid()` 建立网络 context；同一源码说明 OEM `enforceDnsUid` 可使 DNS 包标记为 `AID_DNS` 而非应用 UID。因此不能说系统 DNS 一定无法归属，也不能说所有出站 DNS 包必定带原 app UID。该文件中的 `evaluate_domain_name` 是 resolver callback，不是 KernelSU 提供的 public API。[固定 Android 16 源码](https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-16.0.0_r1/DnsProxyListener.cpp)
5. **Root/NFQUEUE 可获取 socket UID，但字段可能缺失。**`NFQA_CFG_F_UID_GID` 请求 socket UID/GID；`nfq_get_uid` 明确可返回无 UID，碎片还有字段覆盖条件。这个身份是 socket owner，不自带原 resolver 调用 app、包名或查询语义；Android 的上述差异仍需逐设备核对。[队列元数据](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html)、[UID 提取](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Parsing.html)
6. **VPN 能读被送入 TUN 的 IP 包。**API 29 的 `getConnectionOwnerUid` 支持 TCP/UDP；调用者需是当前用户 active VpnService，连接不存在时返回 `INVALID_UID`。可获得 app/UID 与 IP 事实，但 API 没有保证提供 DNS 原调用身份或所有包均有归属。[VPN 数据路径](https://developer.android.com/develop/connectivity/vpn)、[owner UID API](https://developer.android.com/reference/android/net/ConnectivityManager#getConnectionOwnerUid(int,%20java.net.InetSocketAddress,%20java.net.InetSocketAddress))
7. **VPN DNS 配置可用，覆盖需另证。**`addDnsServer` 配置 VPN DNS；应用选择、路由、地址族与 `allowBypass` 决定流量是否进入 VPN。`addDisallowedApplication` 是绕过 VPN，不是产品“禁止联网”。不能由配置 DNS 推出任意 app 的自带 DoH 都受该 resolver 控制。[VpnService.Builder](https://developer.android.com/reference/android/net/VpnService.Builder)
8. **工作资料与共享 UID 是真实范围。**每用户/profile 只有一个 active VPN；工作资料为次用户，UID 包含 userId；`sharedUserId` 可使多个包同 UID，虽已 deprecated，既有 app 仍有迁移限制。因此身份合同须包含 profile、UID 与可对应多个包的集合，不能用 app 图标遮蔽共同影响。[VPN 生命周期](https://developer.android.com/develop/connectivity/vpn)、[工作资料身份](https://source.android.com/docs/devices/admin/managed-profiles)、[共享 UID](https://developer.android.com/guide/topics/permissions/defining#user-ids-and-file-access)、[deprecated 属性](https://developer.android.com/guide/topics/manifest/manifest-element#uid)

## 名称与访问之间的事实缺口

- **DoT/DoH 隐藏查询内容，Root 不等于解密。**DoT 默认 TCP 853，并允许协商其他端口；DoH 加密查询，可与其他 HTTPS 共用 443/连接。识别 resolver 连接或拦整个 resolver 不等于知道每个 QNAME；阻断加密 DNS 也可能破坏正常解析。[RFC 7858 §3](https://www.rfc-editor.org/rfc/rfc7858.html#section-3)、[RFC 8484 §8.1](https://www.rfc-editor.org/rfc/rfc8484.html#section-8.1)
- **Private DNS 与 ECH 分别作用于 DNS 和握手。**加密 DNS 不逻辑必然消除普通 TLS/QUIC 的明文名称证据；ECH 才加密 `ClientHelloInner`，外层 SNI 通常是 `public_name`，不能当实际目标名称。不能把外层公名命中当成隐藏目标命中。[RFC 9849 §6.1](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1)
- **明文 SNI 也不完整代表请求目标。**HTTP/2 与 HTTP/3 允许在满足 authority/certificate 条件时，一个既有连接用于多个 URI authority；因此一次连接名称识别不足以证明连接内所有实际 HTTP 域名。[RFC 9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1)、[RFC 9114 §3.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.3)
- **缓存会绕开新的出站查询。**系统 resolver 已缓存回答；DNS RR 有 TTL 与别名语义。推论：新增解析阻断不能自动撤销 app 已取得的地址或已经建立的传输，关联表需明确来源、时间、TTL、CNAME/A/AAAA 与 network/profile 边界。[AOSP 缓存](https://source.android.com/docs/core/ota/modular-system/dns-resolver)、[RFC 1034 §3.6–3.7](https://www.rfc-editor.org/rfc/rfc1034.html#section-3.6)
- **共享 IP 是范围问题。**DNS 名称与地址不是唯一映射；HTTP 连接复用进一步显示同一 endpoint 可服务多个名称。推论：按某 app 阻断关联 IP，仍可能影响该 app 的其他域名；它不是无需说明的“更强同义执行”。[RFC 1034](https://www.rfc-editor.org/rfc/rfc1034.html)、[RFC 9113 §9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-9.1.1)

## Linux：接入点不能用一个标签概括

- `systemd-resolved` 提供 D-Bus、glibc NSS 与 loopback stub，含缓存、hosts/synthetic、本地 mDNS/LLMNR 与按 link/domain 路由。推论：只抓外网 DNS 不能看到全部解析；resolver 出站 socket 的 owner 也不能替代原 client 身份。应识别实际入口与 namespace/interface 范围。[上游 systemd 手册源码](https://raw.githubusercontent.com/systemd/systemd/main/man/systemd-resolved.service.xml)
- NetworkManager 支持直接维护 `resolv.conf`，或接入 `dnsmasq`、`systemd-resolved`、`dnsconfd` 等本地 caching resolver。它是 DNS 配置管理角色，不能默认视为每次查询语义与 per-app 执行入口。[NetworkManager 配置合同](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html)
- 原始 DNS、自带 DoH、IPC/NSS 解析、loopback stub 与 LAN discovery 可走不同路径。抓包能看见受覆盖路径上的协议；若想控制 resolver 调用与原应用身份，须增设并实证对应语义 adapter。Linux UID 也不天然是一项 GUI 应用的唯一身份；此处是设计推论，不是现有实现声明。

## 能力、证据、产品承诺与新增合同

| 候选能力 | 证据层级 | 可承诺的后果 | 需要新增/明确的 contract |
| --- | --- | --- | --- |
| PRE/POST 自动规划 | [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md) 与 [统一规范](../product/UNIFIED_RULE_ENGINE_SPEC.md) 已 accepted；不是本报告的实施验收 | 相同输入下保留完整规则赢家 | 现有 placement 合同；未来 semantic planner 不能仅凭 placement 宣称完整域名控制 |
| Android Root/VPN app+IP、TLS/QUIC 名称 | 平台 API/source 支持；产品需绑定具体 artifact/profile 证据 | 对实际捕获、可归属、可用名称证据执行规则 | 身份 unknown/shared/profile；名称来源；缺失/加密/预算/复用；执行结果 |
| 系统 resolver / 具名 KSU adapter | resolver 有 caller UID 事实；module 尚未识别或验证 | 对覆盖的解析请求实施策略 | 查询语义、原调用身份、缓存、版本、故障、可恢复接管；不得新增独立权威规则库 |
| DNS 查询过滤、DNS→IP 关联 | 当前统一规范明确本版 Out of Scope；本轮用户要求研究 future first版 | 未来可观察解析与关联，并执行有明确范围的策略 | 关联 provenance/TTL/network/UID；冲突、过期、shared-IP 影响与动作；默认选择待设计 |
| Linux resolver/capture adapter | 官方入口差异已证；该产品语义接入未在本报告验收 | 对已识别、已验证入口兑现限定后果 | resolver/NSS/namespace、UID→应用、loopback/LAN、split DNS 与恢复 |
| “更省电/更快/更强”方式 | 无本轮等语义对照测量 | 可提供待测候选与明确 coverage 差异 | 同设备/网络/负载/覆盖比较，统计唤醒、copies、CPU、重试、radio、吞吐/延迟/功耗；不能按 Root/module 排序 |

现版的 future association `default-off` 是**现 accepted baseline**，不是否决用户本轮新 target 的理由。未来默认可重审；自动组合必须先声明影响范围，并证明执行不悄悄变成整个 resolver、共享 IP 或共享 UID 的扩大限制。[当前 scope](../product/UNIFIED_RULE_ENGINE_SPEC.md#out-of-scope)

实施边界保持 [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)/[0007](../adr/0007-owner-local-lwip-direct-egress.md)/[0008](../adr/0008-remove-snort-cpp-mainline.md)/[0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md)：VPP-native C packet domain、单一权威 source/configuration；前端提交意图与查看计划，不维护 DNS/SNI/IP 多份权威规则。本文未审计最新全产品实现，不将 accepted spec 或平台能力当成已交付验收。

## 给设计讨论的可行推论与未证事项

- 日常可以展示应用、观察到的名称、协议与已执行动作，并把未识别目标的流量保留下来。查询记录表示“查询过”；握手名称表示“连接声明名称”；IP 关联表示“解析关联”；三个来源不能统一升级为全部实际访问事实。
- “已保存”“当前执行中”“本次确实拦了某请求/包”“未观察到访问”应由不同证据驱动；未知身份、未知名称或未捕获不是“允许过/没拦住这个域名”的证据。可以用简短后果说明，机制放到详情。
- 默认组合和初始化导引可减少日常负担；能力撤销、profile/网络改变、模块失效、影响范围扩大时须重评当前计划，不能只靠首次导引永久证明覆盖。
- 广告/跟踪名称列表可承诺对已声明范围执行名单策略；LAN 发现预设需定义具体协议/方向/接口。不能由列表命中或 mDNS 识别承诺消除所有广告、跟踪或 LAN 通信。Android 官方 `.local` 路径另排除 VPN/mobile。[AOSP mDNS 边界](https://source.android.com/docs/core/ota/modular-system/dns-resolver#mdns-local-resolution)
- 未证：指定模块兼容与语义能力、各 profile 真覆盖、缓存/DoH/ECH/复用场景端到端限制、shared-IP collateral、用户列表实际收益、功耗与延迟排序。本报告不编用户比例或电池数字。

讨论交叉验证：设计席回答使用中的意图需绑定 active plan、真实身份/profile 与能力；查询拒绝、连接 DROP 与允许连接各有独立 actual-action 证据，未知名称保留 IP/协议/字节，并用覆盖短句表达。补充澄清：全文件 saved/active 不一致仍可有旧 active 意图继续执行，不能仅因此否认其当前后果。整体席回答默认不自动扩大共享 IP/UID 范围，并认可未来关联默认可重审。上述事实支持继续建设意图默认方案，同时要求用实际 consequence evidence 证明其可兑现程度。
