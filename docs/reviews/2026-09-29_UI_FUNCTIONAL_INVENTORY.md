# 当前功能与旧 UI 原型对应清单（2026-09-29）

状态：供产品与 UI 设计使用的功能盘点。用户已确认先梳理功能，并在后续讨论明确了第 1.1 节的范围与跨平台方向；后续已形成可走查的双平台 HTML 设计稿；[当前完整原型](../../app/design/prototypes/2026-09-29-interaction-directions/complete/README.md)覆盖手机、平板与桌面。以下能力状态仍指产品实现，不因原型可操作而改变。

关联讨论：[原型审视、九项问题优先级与设计顺序](2026-09-29_UI_PROTOTYPE_DESIGN_REVIEW.md)。

## 1. 盘点范围与判断方法

本次覆盖 Android/Linux 共享产品设计相关的运行、应用、规则、协议与域名、活动与统计、配置管理、恢复诊断及设置，核对当前源代码、可达调用路径、接口契约和已有验收记录。最初入口核对偏重 Android；第 1.2 节补充平台适用范围，避免把 Android 的目录、权限与生命周期直接当成双端共同能力。底层 worker、队列、缓存等实现机制仅在影响产品行为时进入本表。

读取基线：本仓库 HEAD 为 `d5f014d9346ebe8f9426192f0d49884626ed6ff4`，同时包含当前未提交的 Root 恢复等改动；这是工作区盘点，不是只针对该 commit 的结论。本次未操作设备、重跑功能验收或检查实时 Plane 状态，引用的真机结果保持原报告的范围。

能力状态含义：

- **已有**：找到当前实现与可用调用路径；具体设备证明以引用的验收为准。
- **部分**：构成此用户任务的一部分已存在，但缺少明确的数据、接口或完整交互。
- **未接通**：本次核对的当前产品入口没有提供该功能；旧原型或旧模型中出现，不等于当前可用。
- **另议**：旧探索或产品设想，尚不能作为当前功能承诺。

这些是实现就绪程度，不代表产品价值或是否进入首版。产品定位按第 1.1 节单独记录，未接通的前端功能仍可成为正式设计对象。表中功能编号用于讨论引用，实施工作仍由 Plane 管理。

当前 Android 界面是 `DebugControlActivity`，提供启动、停止、应用选择、网络禁用、诊断规则输入、查询和本地诊断导出。下文的“已有”不代表正式产品 UI 已完成。旧原型位于相邻 checkout 的 `../sakamoto-app/prototypes/`，所有旧页面均只作为设计参考。

### 1.1 用户后续确认：产品价值、首版范围与实现状态分开

| 对象 | 已确认的产品定位 | 当前实现与后续设计含义 |
| --- | --- | --- |
| 策略 checkpoint | 有价值，**首版不做** | 保留后续方向；不将旧 checkpoint 页面接入首版。本条不自动排除未提交输入的撤销或取消 |
| 规则预演 | 有价值，保留在产品设计范围 | 明确预演输入、结果和所需事实；不能将“预演”只理解成历史重放，也不能因历史数据不足就整体排除 |
| 面向用户的 debug 模式 | 有价值，保留在产品设计范围 | 设计独立的诊断操作与结果表达；当前 DebugControlActivity 和开发探针是实现材料，不等于完成的产品体验 |
| 地图与地理呈现 | 有价值，保留在产品设计范围 | 属于前端呈现及产品数据组织能力；地址、地理标签、时间范围和聚合数据分别核对，不要求每项都对应新增数据面机制 |
| Android 与 Linux | **本轮同时设计的两个目标平台** | 共享 Rust 产品能力和产品语义，采用既定共享 UI 方向；分别考虑触控小屏和桌面窗口，不把 Linux 仅列为移动版之后的附加页面 |

用户未在本轮指定预演/debug/地图的首版完整深度，也未要求双端同日发布。保留设计范围不自动开启实现。计费、限速、定时等其他项目不因这次澄清而获得相同范围结论。

用户进一步确认：以可交互 HTML 原型先完成本轮功能设计，覆盖 Android 与 Linux，并以借鉴乔布斯的聚焦、直觉、精确、克制与完成度原则把控。功能清单是设计输入；各项能力要进入可走查的页面、操作与状态，原型确认后再接真实产品实现。详细流程与评审标准见 [原型设计讨论](2026-09-29_UI_PROTOTYPE_DESIGN_REVIEW.md)。

### 1.2 跨平台适用范围

[ADR-0002](../adr/0002-tauri-android-runtime-service-boundary.md) 已选择 Android/Linux 共享 Tauri UI、共享 Rust 产品能力与平台生命周期适配。当前仓库已有 Rust `product-core`、Linux Host API/CLI 和 Android runtime 接入；本次检查未发现正式 Tauri 前端工程入口。产品方向与当前落地程度分别记录，不因界面尚未接通而降低 Linux 的设计地位。

| 层面 | 可以共享的内容 | Android 需要处理的差异 | Linux 需要处理的差异 |
| --- | --- | --- | --- |
| 规则与数据 | 条件语义、规则/组/绑定、保存生效结果、配置格式、观测记录与历史解释 | 平台事实与可用性接入 | 同一产品语义，但不能默认每个 Android 平台事实都有等价来源 |
| 控制对象 | 规则作用范围与身份的表达方式 | 包名、图标、用户/profile 与完整 UID；共享 UID 的边界 | 当前规则/Flow 主要携带 UID，未见 PID/可执行文件作为稳定规则身份；不能据 UID 自动宣称可独立控制同用户的各程序 |
| 网络条件 | 类型、接口与已知/未知语义 | ConnectivityManager、underlay 和 Android VPN 生命周期 | 内核接口快照，包含 Wired 等条件；不能原样固定为 Wi-Fi/Mobile/VPN 三列 |
| 生命周期与权限 | 运行、停止、故障与恢复的用户含义 | RuntimeService/VpnService、授权、前台通知、关闭 Activity 后继续运行 | 本地运行承载、权限提升、桌面退出/后台行为与安装启动需要单独设计；Host runner 不等于正式桌面监督入口 |
| 布局与操作 | 产品对象、文案语义、设计语言、规则和诊断结果 | 触控、窄屏、逐级详情和适合手机的操作密度 | 可变窗口、鼠标键盘、列表与详情并排、规则或诊断结果比较；具体布局待原型验证 |
| 地图、预演和 debug | 用户目标、输入/结果语义与产品数据接口 | 在小屏下组织地图与列表、预演条件和结果 | 利用较宽空间并排关联地图/列表、规则/结果，不能仅放大手机画面 |

Linux 平台事实依据：[S235 网络快照](../testing/2026-09-13_S235_LINUX_NETWORK_SNAPSHOT.md)、[Root NFQUEUE UID 读取](../../src/product/vpp/product_root_nfqueue_adapter.c)、[当前 Flow 查询字段](../../src/product/include/sakamoto_product_flow_query.h)、[规则身份字段](../../src/product/include/sakamoto_product_rule_config.h)。Linux 程序身份的具体方案尚未选择，本记录不据此新增第二套规则模型。

## 2. 产品功能总图

| 功能领域 | 用户想完成的事情 | 相比旧原型的主要变化 |
| --- | --- | --- |
| A. 运行与授权 | 启动、暂停、切换模式，知道运行是否正常 | Android Root/VPN 与 Linux 运行承载分别设计，共享状态含义 |
| B. 应用管理与快捷控制 | 找到正确的控制对象，管理网络访问 | Android 应用 UID 路径已有；Linux 程序身份另需明确，快捷禁用使用统一规则 |
| C. 规则与复用 | 创建、维护、组合规则并分配给应用 | 已超出 exact block；支持条件组合、规则组、复用和 observe |
| D. 协议与域名 | 理解和控制识别到的协议及目标域名 | 有 20 个有效协议目录项及 TLS/QUIC SNI 条件，适用边界明确 |
| E. 活动与统计 | 查看访问、阻止原因及一段时间内的效果 | 当前连接、近期记录、规则归属、协议统计和分层历史已经形成不同数据视图 |
| F. 配置管理 | 保存、生效、导入导出和修正失败配置 | VPP 统一管理；保存与生效有不同结果；导入是完整替换 |
| G. 健康、恢复与诊断 | 理解故障影响并恢复使用 | 多来源健康、有限自动恢复已有；面向用户的 debug 进入设计，checkpoint 首版暂缓 |
| H. 产品设置与扩展设计 | 管理偏好、数据、地图、预演和平台呈现 | 同时记录产品价值、首版边界与实现状态，避免把缺少接口等同于没有产品价值 |

这些领域不直接等于八个页面或八个导航入口。

## 3. 功能对应明细

### A. 运行与授权

本节 A01–A06 的已接通入口主要指 Android；Linux 的对应运行承载与权限流程按第 1.2 节单独核对。

主要依据：[RuntimeService](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java)、[初始化步骤模型](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeProfileInitializationPlan.java)、[S289 普通 VPN 验收](../testing/2026-09-28_S289_VPN_NORMAL_START.md)、[VPN 身份与回包决策](../decisions/VPN_ASYNC_UID_AND_RETURN_LINEAGE.md)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| A01 | 选择 Root 或 VPN | **已有**：模式选择持久化，Debug 下拉选择；Root 使用授权后的本地运行路径，普通 VPN 使用 Android 授权及 TUN/Flow Stack | setup、runtime-access、settings | 选中的模式与实际运行模式分别表达；不沿用 Root-only 或 Shizuku 已就绪文案 |
| A02 | 完成权限与首次初始化 | **已有基础**：通知、Root/VPN 授权、启动与 readiness 检查；有步骤模型，正式引导页未完成 | setup-root、setup-notification、setup-start 等 | 按真实当前步骤给动作；授权取消、权限缺失可恢复 |
| A03 | 启动与停止 | **已有**：可见 Start/Stop，启动后核对运行与捕获状态；Stop 执行清理 | home、status | 点击启动不立即等于运行成功；停止完成与清理失败分别显示 |
| A04 | 主动暂停与恢复 | **已有**：service 与控制入口有 pause/resume；暂停走停止运行与释放资源路径，保留配置 | home 开关、recovery 的 Pause IP rules | 暂停与“仅观察”含义不同；不能保留旧稿“暂停后继续记录流量”的说明 |
| A05 | 切换运行模式 | **已有**：实际切换先停旧模式、核对清理，再启动新模式；规则配置共享 | settings、runtime-access | 选择偏好不等于立即完成切换；过程、授权与失败需要界面反馈 |
| A06 | 了解网络变化对 VPN 的影响 | **已有**：underlay 可用状态与 `dnsRestartRequired` 可查询；重启更新启动时绑定的 DNS 配置 | status、recovery、旧网络选择 | 显示网络不可用与需重启更新 DNS 的区别；不承诺连接无缝迁移或实时 DNS 漫游 |
| A07 | 关闭界面后继续运行和记录 | **已有架构路径**：运行与 Rust 观测由 RuntimeService 一侧维护，查询 UI 不拥有消费循环 | home、activity | 页面关闭不能被表现成停止；后台功耗和所有设备保活仍不是本次盘点新增的验收结论 |

### B. 应用管理与快捷控制

本节应用目录与包身份的当前实现是 Android 路径；Linux 程序/用户/进程的呈现不能直接套用，见第 1.2 节。

主要依据：[应用目录提供者](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/PackageManagerApplicationCatalogProvider.java)、[应用身份](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationSubjectId.java)、[目录条目](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationCatalogEntry.java)、[T05 网络禁用](../interfaces/T05_NETWORK_DISABLE.md)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| B01 | 查看和选择应用 | **已有**：目录含名称、包名、图标引用、完整 UID、用户/profile 和可用性；Debug 使用选择器 | control、应用行、connection | 需要正式列表与详情；目录来自 Android 可见范围，不能据此承诺列出所有用户的所有应用 |
| B02 | 区分多用户和共享 UID | **已有身份基础**：完整 UID 区分用户；同 UID 的包共享控制身份 | 应用过滤、Shared UID、scope | 相同应用的不同用户实例应能区分；共享 UID 的包不能被宣称可独立执行不同 UID 规则 |
| B03 | 禁用或解除某应用的网络访问 | **已有**：Debug Wi-Fi/Mobile/VPN 按钮走当前普通 DROP 配置入口 | control 三列、Quick policies | “解除快捷禁用”后其他规则继续判断；不能等同于保证放行。网络上下文含义也需说明，不能把 VPN 模式与每包网络条件混为一谈 |
| B04 | 处理应用归属未知的访问 | **已有**：Unknown UID 是明确状态；VPN 异步查询不等待冷包，且有已接受的 live UDP tuple 复用歧义 | Unknown traffic、view-only | 未知身份不能自动归入某应用；从记录建规则时作用范围要明确 |
| B05 | 搜索、排序、过滤和批量控制应用 | **部分**：目录与单应用控制基础可复用；当前 Debug 没有旧原型那套产品交互或专用批量事务入口 | control-filters、control-sort、control-select、batch | 需要设计产品查询与批量结果；不能把循环单项操作默认为整体原子成功 |
| B06 | 从活动生成规则 | **部分**：新活动数据和配置能力已有；旧 `ActivityL4RuleDraft` 辅助仍在，但旧 L4 写入口已停用 | block-flow、Create from Activity、句子候选 | 必须把当前记录字段连接到新规则编辑与生效流程；不能直接复用旧完成路径 |

### C. 规则与复用

主要依据：[当前配置 ABI](../../src/product/include/sakamoto_product_rule_config.h)、[T02](../interfaces/T02_RULE_CONFIGURATION.md)、[T04](../interfaces/T04_RULE_GROUPS.md)、[T06](../interfaces/T06_STATIC_EXPRESSIONS.md)、[T07](../interfaces/T07_CT_EXPRESSIONS.md)、[统一规则规格](../product/UNIFIED_RULE_ENGINE_SPEC.md)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| C01 | 查看、新增、修改、删除规则 | **已有后端**：完整配置查询与替换承载这些操作；Debug 有完整规则文本输入，不是正式编辑器 | control-rules、rules、rule-create | 为单条操作组织安全的完整配置提交；保留其他规则、绑定、列表与元数据 |
| C02 | 给规则命名、保留来源 | **已有**：规则和域名列表有持久化 name/source 元数据；配置导入导出支持 | rule 列表、未来 control asset | 列表可以使用用户名称；来源标签是描述信息，不自动变成订阅 URL |
| C03 | 设置允许或阻止 | **已有**：ALLOW/DROP；完整匹配无命中默认 ALLOW；默认拒绝可用低优先级 DROP 表达 | Allow/Block、Default access | 区分配置动作、实际动作与默认结果；默认结果不是用户创建的规则对象 |
| C04 | 决定规则优先顺序 | **已有**：priority、explicit order、稳定身份共同决定胜者 | rules-sort、未来排序编辑 | “按命中数查看列表”不能改变执行顺序；如何编辑执行顺序尚需交互设计 |
| C05 | 按地址、端口、网络和方向控制 | **已有**：IPv4/IPv6、源/目的 CIDR、IP 协议、端口范围、设备方向、网络上下文和接口条件 | 旧 exact block、CIDR later | 旧 future 标签需校正；普通条件与高级条件分层呈现 |
| C06 | 组合多个条件 | **已有**：有界 AND/OR/NOT；不可用事实有独立语义 | 句子编辑器 Target 等槽位 | 可读摘要不能丢失逻辑分组；未知事实不应被 NOT 包装成已证实匹配 |
| C07 | 按连接状态和流方向控制 | **已有**：NEW/ESTABLISHED/INVALID 及 ORIG/REPLY 条件 | 旧稿覆盖有限 | 与设备输入/输出方向区别清楚，适合高级条件入口 |
| C08 | 复用规则、建立规则组并应用到多个应用 | **已有后端**：可复用规则、嵌套组、组成员与应用绑定；有引用和循环检查 | future library、Scope、rule group | 应用详情与共享资产应相互可达；组结构不是另一套独立规则优先级 |
| C09 | 仅观察某组规则的效果 | **已有**：绑定的 enforce/observe 模式；observe 保留胜者和声明动作，实际 ALLOW | Shadow Test 等探索 | 当前模式可作为设计输入；不能据此宣称完整历史预演、试运行向导或自动回滚已存在 |
| C10 | 给共享规则组命名、描述 | **部分**：组结构已有，但当前 ABI 的组为数值 ID；name/source 元数据仅覆盖规则和域名列表 | named control asset | 友好的组名称/描述需要数据契约设计，不能只在原型填写后就视为能持久化 |
| C11 | 暂时停用一条普通规则 | **部分**：可修改配置与绑定，但当前规则源没有独立 enabled 字段 | 活跃控制、开关设想 | “禁用规则”的保存方式需要明确；observe 仍参与胜者判断，不能直接当成禁用 |

### D. 协议与域名

主要依据：[有效协议目录](../../resources/application-protocol-catalog/catalog.tsv)、[R1](../interfaces/R1_RECOGNITION_COVERAGE.md)、[R2](../interfaces/R2_MAIL_FILE_RECOGNITION.md)、[R3](../interfaces/R3_PROXY_VPN_RECOGNITION.md)、[R4](../interfaces/R4_REALTIME_RECOGNITION.md)、[T12](../interfaces/T12_PUBLISHED_PROTOCOL_FACTS.md)、[T13](../interfaces/T13_TLS_SNI_FACTS.md)、[T15](../interfaces/T15_QUIC_INITIAL_SNI.md)、[T16](../interfaces/T16_QUIC_CRYPTO_ASSEMBLY.md)、[T18](../interfaces/T18_DOMAIN_LISTS.md)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| D01 | 查看识别到的应用协议 | **已有**：当前目录 20 个 active 项，Flow 可同时具有多个已发布协议标签 | 端口提示、Traffic shape、协议筛选 | 从端口提示升级为有来源与可用性的协议事实；标签不证明应用品牌、认证成功或连接成功 |
| D02 | 使用协议作为规则条件 | **已有**：按稳定协议身份匹配，支持条件组合 | 协议规则探索 | 复用同一个编辑器和规则模型；目录 category 是展示分组，不是当前原生匹配条件 |
| D03 | 查看活跃连接的 SNI | **已有独立查询**：有身份校验的 TLS/QUIC SNI 查询；普通 Flow 页提供身份和结果状态，名字需相关查询 | 访问详情、域名目标设想 | 需要详情层数据接入；与完整历史域名记录区别开 |
| D04 | 按域名或域名列表控制 | **已有**：精确名称、名称及其所有下级域名、列表成员条件；整条规则要求已发布 TLS/QUIC 事实 | exact IP、域名扩展设想 | 名称语义要准确；不暗示通配符、正则或所有网络协议都适用 |
| D05 | 区分未识别、识别不可用与确认无 SNI | **已有**：协议与 SNI 均有可用性/结果状态 | Unknown traffic | 不等待信息补齐后重判已经完成的包；数据不足不应显示成安全或明确不匹配结论 |
| D06 | 理解 Root/VPN 的协议支持范围 | **已有明确边界**：普通 VPN Direct Egress 的产品基础是 IPv4/IPv6 TCP/UDP；其他协议的规则判断和实际转发能力须区分 | Root-only 旧说明 | 规则 ALLOW 不保证该模式具有对应转发能力；见 [ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md) |

当前目录的 20 个标签：DNS、HTTP、TLS、QUIC、SSH、mDNS、SMTP、FTP control、FTP data、FTPS、OpenVPN、WireGuard、SOCKS4、SOCKS5、RDP、STUN、RTP、RTCP、SIP、DTLS。识别覆盖是各 R1–R4 合同限定的报文形式与启发式范围；QUIC 标签不自动等于 HTTP/3，DTLS 标签不提供 TLS SNI。

### E. 活动与统计

主要依据：[T21](../interfaces/T21_FLOW_OBSERVATION.md)、[E02](../interfaces/E02_SQLITE_OBSERVATION.md)、[T23](../interfaces/T23_DIRECTIONAL_ATTRIBUTION.md)、[T24](../interfaces/T24_BLOCKED_OBSERVATION.md)、[T25](../interfaces/T25_PROTOCOL_WINDOWS.md)、[T26](../interfaces/T26_RECENT_RULE_HISTORY.md)、[T27](../interfaces/T27_OBSERVATION_RETENTION.md)、[T28](../interfaces/T28_DASHBOARD_QUERY.md)、[当前观测投影](../../crates/product-core/src/observation.rs)、[存储查询](../../crates/product-core/src/observation_store.rs)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| E01 | 查看当前连接 | **已有**：分页查询当前 Flow；Debug 可 Query health and flows / Next flows | Live flows、app-detail-live | 多页是动态采样，不能显示成某一时刻冻结的全量快照 |
| E02 | 查看一次连接的详细事实 | **已有数据**：地址、端口、UID、网络、首末活动、双向包/字节、协议与当前方向归属 | flow detail、raw record | 先展示用户关心的对象、结果和原因；ORIG/REPLY 不能未经转换直接标成上传/下载 |
| E03 | 查看在建 Flow 前就被阻止的访问 | **已有**：独立 Blocked Observation，与 Flow 一起进入统计 | blocked records、Activity | 没有 Flow 不等于没有拦截；阻止记录也不能伪装成成功建立的连接 |
| E04 | 查看近期结束的访问 | **已有**：有界近期 END 记录；默认保留期与数量受限制 | recent/live-ended 列表 | 与当前连接区分；不是每个包一条记录，也不是完整逐规则变更时间线 |
| E05 | 查看总体和应用流量 | **已有**：基本计数与观测窗口分别提供，应用窗口按 UID 与实际动作归集 | home 统计、Traffic by apps | 表明时间范围、单位和覆盖；包数、连接数、规则命中数不能互换 |
| E06 | 查看规则效果与阻止原因 | **已有**：规则版本、当时名称、声明/实际动作、模式、方向计数和可证明的历史条件 | Rules hits、Execution、Explain | 默认允许没有规则命中；旧条件不可取得时明确说明，不替换成最新条件 |
| E07 | 查看协议流量分布 | **已有**：L4 和多标签 L7 窗口、占比与未知部分 | 协议统计、Traffic Explorer 扩展 | 一个流可计入多个 L7 标签，其占比之和可能超过 100%；不直接画成互斥饼图 |
| E08 | 查看不同时间尺度的历史 | **已有**：分钟、小时、日聚合；默认粒度保留为 48 小时、30 天、180 天，近期 END 为 24 小时 | 时间范围、滑块、Custom | 选时间时匹配实际粒度和保留覆盖；算法验收不等于已跑过真实 180 天设备测试 |
| E09 | 了解记录完整性与保存状态 | **已有**：覆盖缺口、淘汰、查询截断、最新/旧查询、未提交增量和存储错误 | telemetry degraded/error | 缺失数据不填成零；记录问题与包处理状态分别说明 |
| E10 | 按应用、结果、时间搜索筛选并画图 | **部分**：已有维护窗口和有界查询；当前入口主要返回固定投影及 Flow cursor，缺少旧原型那套完整产品查询交互 | filters、sort、time range、图表 | 页面内筛选已返回数据不能冒充全库搜索；任意历史范围、分页、趋势与排名需定义产品查询契约 |
| E11 | 停止保护后继续浏览历史 | **部分**：SQLite 历史跨停机保留；当前 Android observation 请求要求 `productCoreSession`，无会话返回 management_unavailable | Activity 持续可查看的预期 | 独立的停机历史浏览路径需产品化，不能将数据保留等同于入口已可用 |
| E12 | 按网络或目的地址查看历史流量排行 | **部分**：明细有网络和地址，规则窗口有网络维度；当前长期维护视图主要按总体、应用、规则、协议组织，没有完整的应用按网络窗口或目的地址排行契约 | home 的 Wi-Fi/Mobile/VPN 数字、Traffic Explorer 的 Top destinations | 不能从有界近期明细推导全量历史排行；需要明确新增聚合或限定展示范围 |

### F. 配置保存与导入导出

主要依据：[T02](../interfaces/T02_RULE_CONFIGURATION.md)、[T03](../interfaces/T03_STARTUP_REPAIR.md)、[T19](../interfaces/T19_CONFIGURATION_IMPORT.md)、[配置导入源码](../../crates/product-core/src/rule_import.rs)、[ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| F01 | 保存并使修改生效 | **已有**：先保存后编译发布；返回 saved/active 身份和不同错误 | Direct apply、Review、Apply | 已保存但未生效有独立状态；按钮组织可讨论，底层结果不能合并成笼统成功 |
| F02 | 处理冲突与失败重试 | **已有**：保存版本前提、规则身份与引用检查、保存/编译容量错误；回复丢失需先查询 | 原型覆盖不足 | 指向受影响规则或配置问题；不盲目重复创建、不把失败后的旧生效规则隐藏 |
| F03 | 导出配置并重新导入 | **已有**：完整规则、组、绑定、列表与元数据导出；导入为完整替换；Android 有入口，当前文件选择/分享交互未完成 | Storage、import/export 占位 | 显示替换范围与生效结果；没有自动合并语义 |
| F04 | 导入外部域名列表 | **已有限定格式**：native、plain-exact，以及明确的 Adblock/Clash 域名子集；支持导入规范化 | 导入列表设想 | 不兼容的语法明确报错；不承诺完整第三方配置、自动订阅更新或正则规则 |
| F05 | 在配置错误后修正并重新启动 | **已有**：无有效快照时可以保留健康管理通道修配置；修好后显式 Start；进程/控制通道故障另论 | recovery、status | “配置可编辑但保护未启动”是必须设计的状态；正常完全停机时离线规则管理不在当前要求内 |

### G. 健康、恢复与诊断

主要依据：[T28](../interfaces/T28_DASHBOARD_QUERY.md)、[Root 恢复](../testing/2026-09-28_ROOT_NFQUEUE_RECOVERY.md)、[S289](../testing/2026-09-28_S289_VPN_NORMAL_START.md)、[RuntimeService](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java)、[诊断导出](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ReleaseDiagnosticsExport.java)。

| 编号 | 用户功能 | 当前能力与界面接入 | 旧原型对应 | 设计所需处理 |
| --- | --- | --- | --- | --- |
| G01 | 看懂运行、规则、网络和记录是否正常 | **已有**：运行平台、VPP/配置、Rust 观测状态分别可查询 | home、status、diagnostics | 汇总为明确影响和动作；保护状态不由非空流量列表推断 |
| G02 | 故障后自动恢复 | **已有**：Root 永久故障有限重启及停止取消；VPN 有有限恢复路径 | recovery、错误页 | 正在恢复、恢复成功、需人工介入分开；内部预算不必变成普通设置 |
| G03 | 手动停止、重启或修复授权 | **已有基础**：Start/Stop、授权检查、模式切换与错误信息 | emergency actions、runtime-access | 根据具体原因提供入口；不能用“恢复”一词掩盖实际执行的是停止还是重启 |
| G04 | 导出诊断给自己或支持人员 | **部分**：Debug 可写本地文本，包含 runtime、所选应用等信息；仍使用部分旧目录/详情投影 | support package、feedback | 更新为当前权威状态并设计预览与分享；现有导出不含 payload/keys，但仍含 UID、包名等信息，不等于匿名 |
| G05 | 获得帮助、反馈和版本说明 | **部分**：有错误原因、恢复提示、反馈类别和仓库材料；未确认正式帮助中心、反馈投递或用户分享流程 | about、help、feedback | 产品文案与真实行为对齐；反馈类别文本不是已接通的提交渠道 |
| G06 | 使用深入诊断工具 | **已有开发能力**：CLI/调试入口、流量探针、故障注入、受控观测暂停等；用户确认面向用户的 debug 有产品价值 | raw record、Match Probe、debug 探索 | 作为 H11 的实现输入，继续设计用户操作与结果；不能直接把开发开关当成完整 debug 产品模式 |

### H. 产品设置与扩展设计

判断范围为当前 `app/android-runtime`、Rust 产品控制面和 C/VPP 主线；不是对相邻旧 App 全部功能的判断。依据：[Android manifest](../../app/android-runtime/src/main/AndroidManifest.xml)、[DebugControlActivity](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java)、[当前存储](../../crates/product-core/src/observation_store.rs)、[统一规格范围](../product/UNIFIED_RULE_ENGINE_SPEC.md)。

| 编号 | 功能或设想 | 当前判断 | 旧原型对应 / 后续设计含义 |
| --- | --- | --- | --- |
| H01 | 开机自动启动 | **未接通**：当前 manifest 没有相应 boot receiver/权限路径；运行中的故障恢复不等于开机自启 | 开机启动属于单独产品流程，不能从 supervisor 已有推导 |
| H02 | 主题、动态色、语言选择 | **未接通**：当前是固定主题的调试 Activity，未提供正式偏好系统 | settings-theme、Color 和双语规划可作为设计输入 |
| H03 | 用户调整保留期、清空或导出历史 | **部分**：自动保留、空间回收与使用量已有；当前可调整保留文件是验证用途，未见正式管理入口 | Storage 需要产品契约，不能直接暴露测试配置作为用户设置 |
| H04 | IP 国家、地图、服务商和端口标签 | **地图产品价值已确认，保留设计；数据接入待补**：当前有地址事实，地理 enrichment 与所需聚合尚未接通 | 地图按双端前端能力设计；地区、服务商、端口标签分别确定数据范围，未知位置保留未知，不把地理位置当安全评级 |
| H05 | 付费、订阅与恢复购买 | **未接通**：当前无产品计费入口；旧 Free plan 为占位 | 不因旧设置首项是 Plan 就保留在新产品首屏 |
| H06 | 限速、定时规则、定时放行 | **另议**：未在当前规则动作、条件或运行控制中找到完整产品路径 | 句子模型的 Limit、Duration、Timed restore 不能当作当前选项 |
| H07 | 策略 checkpoint 与历史版本恢复 | **有价值，用户明确首版不做**；旧 Java 类保留相关逻辑，当前配置不维护完整旧条件归档 | 保留后续方向；本条不等于取消未提交输入的撤销/取消，也不自动授予已生效配置一键回滚能力 |
| H08 | 规则预演与结果查看 | **产品价值已确认，保留设计；完整流程待设计**：observe 已有，历史不具备重放任意规则的全部事实 | 明确用户输入及事实来源，区分历史预演、合成匹配和真实 observe；界面可组织条件与结果，精确判断须保持权威规则语义 |
| H09 | DNS 请求过滤、DNS-IP 关联、通用解密/抓包 | **另议或现行范围之外**：SNI 条件不等于这些功能；普通记录不保存 payload | 不能从“域名规则”“协议识别”推导为 DNS 防火墙或完整流量分析器 |
| H10 | Android/Linux 共享产品 UI | **双平台设计目标已明确，正式 UI 待接通**：共享 Rust 主线已有，现有 Android Debug 与 Linux Host 工具不等于正式界面 | 同时设计触控和桌面体验，共享产品语义；不固定沿用手机底部导航和单栏结构 |
| H11 | 面向用户的 debug 模式 | **产品价值已确认，保留设计；产品会话与交互待定义**：已有诊断查询和开发工具可作为基础 | 与 Root/VPN 运行方式、规则 enforce/observe 模式分别表达；遵守已接受的独立有界通道、单会话和真实证据约束，具体查看/采集/导出能力另行确定 |

## 4. 不能误用的旧接口和术语

本次核对发现以下区别，它们会影响功能判断与新 UI 数据接线：

1. `RuntimeService.onStartCommand` 对旧 `product_bind_app`、`product_unbind_app`、`product_set_l4_rule` 返回 `legacy_authoring_retired`。这不否定新 VPP 配置中的应用绑定能力；二者属于不同路径。
2. `LocalProductBackend`、`ProductPolicyTransactions` 等类仍能看到 draft/commit/checkpoint 方法，不能仅凭类或方法存在就认定它们是当前规则入口。
3. `CapabilitySet.androidL4` 仍固定 `protocolRules=false`；实际协议规则已经通过新配置路径实现。正式 capability 投影需与当前权威能力对齐。
4. 旧 `AppDetail`、`RuleView`、`ProductActivityProjectionStore` 等不能直接视作新规则和历史的完整产品模型。新的配置与观测来自 VPP/Rust；现有诊断导出使用旧投影的部分也需区别。
5. SQLite 的 WAL checkpoint 是存储维护，和用户恢复策略的 checkpoint 无关。

这些观察保存在本次功能审视中，不在本轮进行代码重构或创建修复排期。

## 5. 影响页面设计的状态

正常、加载、空、失败只是基础分类。下面这些业务状态必须能被新设计区分：

| 场景 | 需要表达的状态 |
| --- | --- |
| 启动与停止 | 待授权、通知条件未满足、启动中、运行中、主动暂停、停止中、异常停止、清理未完成 |
| 配置修改 | 未提交输入、提交处理中、保存失败、保存成功但未生效、修改已生效、版本冲突、管理不可用 |
| 启动时配置有误 | 管理可用但保护未启动、配置修复成功但仍需启动、控制进程本身不可用 |
| 应用与协议事实 | 已知应用、共享 UID、未知归属；协议已发布/不可用；SNI 有名字/确认无名字/不可用 |
| 规则效果 | 实际允许、实际阻止、observe 下声明阻止但实际允许、没有规则命中的默认允许、运行故障 |
| 活动与历史 | 没有记录、记录尚未加载、查询失败、旧查询结果、部分覆盖、结果截断、记录已淘汰、旧规则条件不可取得 |
| 网络与恢复 | underlay 不可用、需要重启更新 DNS、正在有限恢复、恢复成功、需人工介入 |

状态名称是讨论用语，尚未固定最终用户文案。原型中的成功、失败和空数据应来自这些真实语义。

## 6. 本轮梳理得到的设计输入

- **可以沿用任务方向**：应用快捷控制、访问详情、从访问进入规则、时间范围、状态与恢复。
- **需要重新组织**：统一规则编辑、共享规则组与绑定、observe 模式、保存/生效反馈、当前连接与分层历史。
- **需要补齐产品数据路径**：规则组名称、普通规则停用表达、当前活动到规则编辑的连接、正式应用详情、完整筛选查询及停机历史浏览。
- **保留并继续设计**：规则预演、面向用户的 debug 模式、地图；分别明确前端体验、产品数据与所需执行能力。
- **首版暂缓**：策略 checkpoint 与完整历史版本恢复。
- **其他范围仍需讨论**：计费、定时/限速，以及尚未接通的产品偏好和数据管理。
- **双端共同设计**：Android 与 Linux 共享产品对象和核心语义，同时处理平台身份、网络、生命周期和交互差异。

以上不自动删减任何已有能力，也不把所有底层能力都提升为首屏功能。后续以 HTML 原型具体组织应用、规则、共享资产、活动、预演、debug、地图与状态，覆盖确认的功能范围及双端差异；优先级决定设计顺序，不替代完整的功能设计。

## 7. 证据与验证边界

主线组合功能参考 [T29 联合验收](../testing/2026-09-27_T29_COMBINED_RESULTS.md)，普通 VPN 的后续变化参考 [S289](../testing/2026-09-28_S289_VPN_NORMAL_START.md)，Root 恢复参考 [2026-09-28 报告](../testing/2026-09-28_ROOT_NFQUEUE_RECOVERY.md)。各接口文档中的更早阶段描述按后续契约校正，例如 E02 替代 T22 的 JSON 存储、T23–T27 扩展 T21 的早期观测范围。

本次完成源代码与文档交叉核对及本文件链接检查，不新增运行、性能、设备兼容性或发布验收结论。实施状态与下一阶段任务仍以 Plane 为准。
