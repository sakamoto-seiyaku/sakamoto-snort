# Android L4 产品计划与 UI 基线

状态：产品目标与 current-head contract 基线；S171-S196 已交付 VPP-native Product Core
实现与当前 APK/device evidence，release gate 仍以独立准入条件为准。

> ADR-0008 移除的 Android C++ daemon、host model 和 APK daemon artifact 仍然不得恢复、
> 移植或作为 compatibility fallback。当前 Android RuntimeService 使用 staged
> `libvpp_runtime.so` 与 `libproduct_core_plugin.so`；历史实现/验收描述必须按历史证据理解。

范围：第一个 Android L4 产品版、第二阶段 libprotoident 阶段性发版，以及两阶段共同使用的
产品 UI、内容、帮助、发布和社区反馈体系。

架构事实和 POC 证据仍以 `docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md` 为准；per-worker
flow ownership 以 `docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md` 为准；VPN Direct Egress 以
ADR-0007 及 SAKAMOTO-114..117 evidence frontier 为准；policy stage 边界以
`docs/adr/0001-policy-bundle-staged-enforcement.md` 为准。本文不定义底层 VPP Interface
字面量，也不是 Plane 工作清单。

## 1. 产品结果

第一个明确目标不是继续证明 VPP 技术可行，而是交付一款能够被安装、理解、配置、验证和
恢复的 Android L4 防火墙产品：

> 在 Android 上以 Root 或 VPN 模式运行，按应用控制 IP、协议和端口访问，并清楚解释
> 实际发生的允许或阻止结果。

近期先服务希望直接控制每个 Android 应用是否能够联网、同时需要多用户支持和基础 L4
证据的用户。AFWall+ 是第一版最直接的产品参照，但目标是用更现代、更易理解的交互完成
同类核心任务，而不是复制其页面或一次追齐全部功能。第一版不以“完整 NGFW”“流量分析器”
或“专业企业网关”作为产品承诺。

第一版的控制主心智是 **App-first Control**：应用控制、活动、统计和 L4 规则围绕同一个应用
组织。它不规定 App 启动后必须先显示应用列表、Overview 或 Activity；默认落点属于后续线框
和使用验证问题，不是当前产品原则。独立规则库存不能取代应用成为控制资产的主要上下文。

## 2. 已确认的阶段边界

### 2.1 Android L4 Product Release

第一阶段只发布 Android 产品，Root 与 VPN 是同一个产品中的两个互斥 Runtime Profile。
两种 Profile 共享产品 UI、Authoring Policy Bundle、完整 Linux UID subject identity、policy revision
和 VPP worker graph；Network Gate、L4 和后续 protocol policy 保留各自的规则族与 stage-local priority。

实现顺序固定为先完成 Root/NFQUEUE vertical slice，再将 VPN/TUN 接入同一个共享数据面合同。
这只是工程顺序，不拆分产品阶段：只有 Root 与 VPN 两种 Runtime Profile 都完成相同的基础 L4
产品闭环，Android L4 Product Release 才能宣告完成。

两种 Profile 的完成判定使用同一份 Packet capture Adapter Conformance Contract：允许存在不同
性能基线和明确的平台限制，但不允许产生两套 PacketFacts、策略 verdict、worker ownership、
PacketLease completion、异常恢复或 Profile 切换语义。

VPN Profile 的第一版 transport contract 强制覆盖 IPv4/IPv6 TCP 与 UDP，并要求通过真实外网
TCP 连接和 UDP Direct Egress 的端到端验收。当前 external HEV child/SOCKS fixture 只属于旧
correctness evidence；真实 product path 必须等待 SAKAMOTO-114..117 选择的 VPN Userspace Flow
Stack boundary 和 SAKAMOTO-98..102 closure。ICMP Echo 只有在 Sakamoto HEV Fork 与真机测试证明后才作为
capability 发布；其它 IP protocol 仍可由 VPP 匹配、阻止和记录，但不承诺 allow 后可转发。
Policy verdict 与 transport completion 必须分别记录：`ALLOW` 后发生的 `UNSUPPORTED` 或
`FAILED` 不能伪装成 policy `DROP`。第一版不扩张已选择的 VPN Userspace Flow Stack 来补齐任意
IP protocol。

用户可见能力：

- Root/VPN 运行方式选择、授权、启动、停止和健康状态；
- 完整 Linux UID 和 Android 多用户语义下的应用列表、直接控制和应用详情；
- 每个应用实例的 Wi-Fi/Mobile/VPN Network Gate；
- 基于五元组的 advanced L4 Traffic Rule：IPv4/IPv6、source/destination CIDR、
  source/destination port 或 port range、IP protocol、packet direction、optional interface
  context，以及 allow/block action；
- 规则命中、基础活动记录和最终 verdict 归因；
- 配置持久化、导入导出、明确失败和恢复路径。

内部基础：

- NFQUEUE 与 TUN Packet Capture Adapter 进入同一个 FlowSteering Module；
- 第一版使用最小 Adapter I/O Topology：VPN/TUN 从单一 fd input lane 开始，Root/NFQUEUE 使用
  满足正确性的最小 queue/netlink lane 布局；completion I/O 可按 Adapter 分别实现。只有测得
  throughput、latency、drop 或 power 瓶颈后才增加 lane，不预建通用 RX thread pool；
- worker 数量、Canonical Flow Key mapping、per-worker flow/session pool 与 cache capacity 在启动时
  固定，运行中不 reshard；
- Primary Software Distribution 只按包含 IP protocol 的 direction-independent canonical 五元组
  计算最终 owner、按 worker 组成 batch/frame，并第一次直接投递正确 worker；complete Linux
  UID、Network Gate、interface、queue 和 Root/VPN Profile 都不参与 worker 选择；
- 正反包第一次分流即保证进入同一 worker。worker 入口在任何私有 state 更新前执行 Owner
  Guard；错误时只允许一次 Corrective Handoff，纠偏后仍不匹配立即丢弃；
- IP 分片参考 fork VPP handoff 的两阶段结构：先 co-locate 到 bounded reassembly worker，初始分片
  记录 canonical 五元组的最终 owner，成功重组后必要时再 handoff；Gate/L4 只处理最终 owner 上
  的 policy-ready packet；该阶段转换不是 Corrective Handoff；
- 现有 Android POC 未在 Root/NFQUEUE 或 VPN/TUN 真机路径观察到可用于验收的多 packet fragment
  序列，这是设备 hook/流量生成的证据缺口，不是否定或移除上述设计。第一版继续直接参考 fork
  中已有的简单 fragment co-location/reassembly/handoff 机制，不另建新的分片架构。Release
  evidence 以确定性 IPv4/IPv6 packet vectors、VPP graph 注入以及可控 TUN fd 或 netns/NFQUEUE
  注入为主，覆盖乱序、重复、重叠、超时和容量边界；Android 真机自然 fragment 只在设备路径
  可观察时作为补充，不作为特定 Pixel/kernel 上的强制发布条件；
- 同一双向 flow 的 `FlowEntry` 稳定归属于 canonical 五元组选择的一个 worker；
- Device Packet Direction (`INPUT/OUTPUT`) 与 Flow Direction (`ORIG/REPLY`) 是独立事实：
  FlowEntry 创建包定义 `ORIG`，反向 endpoint 定义 `REPLY`，并另外保存创建包的 device direction
  为 `flowOriginDir`。Canonical endpoint A/B 只服务 key/owner，不具有方向语义；libprotoident 使用
  `ORIG/REPLY`，不能直接使用 `INPUT/OUTPUT` 或 endpoint 字典序；
- Gate/L4 `DROP` 在完整 flow/session allocation 之前发生，只更新精确 app/rule counters，并可写入
  fixed-capacity、loss-tolerant、worker-private ActivityAccumulator；淘汰只损失 UI detail；
- 只有 `PASS_NEXT` 流量 lookup/create worker-private、bounded `FlowEntry`，支撑 allowed-flow
  activity 聚合并为下一阶段保留 attachment seam；
- 早期 DROP 没有 FlowEntry，因此没有 `ORIG/REPLY`；若后续 packet 首次通过并创建 entry，该包
  才定义 `ORIG`。midstream pickup 可作为诊断事实，但不反推或改写已经建立的 flow direction；
- `FlowEntry` 只保存 flow identity、UID、首末时间、包/字节、verdict 和 policy epoch 等
  有界事实，不实现完整 TCP Conntrack 状态机；
- Android VPN 的 UID attribution 不暂存、等待或重放首包。packet metadata 或 worker-local cache
  命中时直接使用 UID；miss 时本包立即以 Unknown Application 执行。只有本包通过并建立
  FlowEntry 后，异步 resolver 结果才可回填原 owner worker，并从后续包开始按已解析应用重新
  匹配。已完成的 verdict 不追溯修改；早期 DROP 没有 FlowEntry，也不为它建立 per-flow
  attribution state；
- 所有平台和识别阶段统一采用 No Recognition Hold：不为等待应用、协议、DNS correlation 或
  后续 L7 metadata 暂存普通 packet，也不承诺识别前零泄漏；短流可能在识别完成前结束。只有
  IP fragment reassembly 等网络协议自身要求的有界 packet retention 属于例外；缓存 flow facts
  或识别结果不属于 packet 缓存；
- Local Product Backend 只保存一份 Authoring Policy Bundle；其中 GateMatrix 与 L4RuleList 是
  两个 typed rule family，由一次 Apply 分别编译为 GateTable 与 Packet/L4 Compiled Policy View；
  后续 ProtocolRuleList 由同一 bundle/revision 编译给独立的 Protocol Policy Matcher，而不是
  塞进 L4 matcher；该 matcher 为项目自有模块，不依赖 MAAT；
- Packet/L4 Compiled Policy View 通过稳定的 L4PolicyMatcher Interface 执行，产品、UI 和 source
  schema 不依赖 priority context、mask pool、hash 或 range residual check 的物理结构。

第一阶段不包含：

- `ct.state` / `ct.direction` 等 Stateful IPRULES；
- TCP stream reassembly；
- HTTP、TLS 或 QUIC 元数据解析；
- QUIC CID、NAT rebinding 或连接迁移适配；
- 首包等待、识别前 hold 或“零泄漏”协议阻止；
- Linux 产品发布、gateway/NAT、IDS/IPS；
- 面向普通用户的 worker、queue、timeout、Session 容量或识别阈值设置。

#### L4 classifier 基线

第一阶段只建设一个 L4PolicyMatcher implementation。2026-09-11 校准：当前保留 UID 分组内
按优先级有界扫描，结构重构以后独立设计，不是 S229/FlowRuntime 前置条件。下列 mask/hash
布局仅为此前讨论的设计方向，不是已实现或冻结的未来方案；匹配和 precedence 契约不变：

- 先按 complete Linux UID 查一次 L4 SubjectView；其中包含 Wi-Fi/Mobile/VPN blocked bit mask 和
  独立 IPv4/IPv6 classifier，缺少 SubjectView 时返回 `PASS_NEXT`；
- 先按 L4 Priority Level 分组，较小 priority 数值先评估；
- 同 level 按 explicit rule order、stable rule ID 决胜，编译为连续 `WinnerRank`；
- 物理布局可以跨 priority level 按 mask shape 扁平组织 masked-key hash，每个 subtable 记录
  `bestPossibleRank` 以安全早停，port range 使用有界 residual check；
- direction、Network/interface kind、optional ifindex、protocol、CIDR 和 ports 留在 UID 桶内的
  matcher key/mask，不继续拆成外层 context；
- matcher 只返回 `DROP` 或 `PASS_NEXT`，不拥有 FlowEntry/session，也不启用 ACL `permit+reflect`；
- mask/pool 的物理遍历顺序不得成为同 priority level 的隐式 winner 语义。

第一版测量 rules per UID、priority level 数量、mask shape、port-range candidate、IPv4/IPv6、
packet cost、memory 和 apply cost；只有该实现出现可复现的正确性或性能阻塞，才立项第二个
matcher，而不是首发同时建设两个 backend。

Policy Apply 在控制面完成整个 bundle revision 的编译和 validation，再以一个 Runtime Snapshot
revision 发布 Gate/L4 views。已有 FlowEntry 不做主动断流；具体 worker publication 与 revision
cache invalidation 机制留给实现设计。新启用的 protocol consumer 不能补回旧 flow 已错过的
早期 payload。

### 2.2 Protocol Identification Release

第二阶段以 libprotoident 完成为阶段性发版目标。它在同一个 worker-private `FlowEntry` 上
增加双向协议识别状态，不引入另一张 flow/session 表。

用户可见增量：

- Activity 和应用详情显示 `识别中 / 已识别 / 未识别`；
- 显示 application protocol 和 category；
- 增加与 L4 RuleList 分离、但位于同一应用详情和 Authoring Policy Bundle 中的 ProtocolRuleList；
- libprotoident 在当前 VPP graph、Adapter completion 之前识别成功时，立即把该结果作为本阶段
  的最终协议识别事实，并对当前 packet 应用协议
  allow/block 规则；completion 后才到达的异步结果只影响后续 packet。协议 allow 不能重新放行
  已被 Network Gate 或 L4 policy 丢弃的流量。

协议身份由项目自有的 Application Protocol Catalog 统一管理。libprotoident 的名称和未来其他
识别器的结果都归一化到同一 catalog identity，识别来源作为独立 evidence 保存，不进入规则
身份。检查过的 VPP fork 中 `DNS=32`、`HTTP=67`、`SSL=199`、`QUIC=2521` 来自商业
Qosmos/qDPI 的私有 `Q_PROTO_*` 编号空间，并非 RFC/IANA 的通用应用协议编号；本项目既不依赖
Qosmos/qDPI，也不使用 MAAT，因此不继承这些数字。RFC/IANA 值只在各自明确的类型空间内使用，
例如 IP protocol number、service/port、ALPN token 或 QUIC version，不拼成一个通用 AppID。
项目维护一份权威、声明式的 Application Protocol Catalog 源文件；每项同时定义项目全局稳定的
整数 `ApplicationProtocolId` 和小写符号 `ApplicationProtocolKey`，例如 `http`、`dns`、`quic`，
不携带 `lpi:` 等 provider 前缀。构建时从该文件生成 C、Rust 和接口 schema 所需的常量与映射，
避免多个模块手写重复编号。packet path 和内部 Activity record 可直接比较或保存
`ApplicationProtocolId`；authoring、导入导出、诊断和产品 API 使用可读的
`ApplicationProtocolKey`，并在 Apply/ingest 边界解析成相同的全局 ID，不再创建
snapshot-local `RuntimeProtocolHandle`。

Catalog 是版本控制下的构建输入，不是允许运行时改号的用户配置。协议项一旦进入已发布版本，
其 ID 与 key 的映射都必须保持稳定：后续只追加新项，删除项保留 tombstone/reserved ID，不能
重编号、复用或把已有 ID 改指另一协议。确需名称迁移时增加显式 alias/migration，而不是修改
旧映射；否则旧 policy、Activity、checkpoint 和跨版本数据会被静默解释成另一协议。Catalog
不支持运行时热加载；新增协议随软件构建和发布进入系统，并要求重启 runtime。重启后旧
FlowEntry 不保留，Policy 使用新 Catalog 重新编译，不设计运行中 AppID 注入或 FlowEntry 迁移。

FlowEntry 的 `LpiRecognitionState` 只保存按发现顺序去重的精确 `ApplicationProtocolId` 序列和
最新 ID，不保存推导出的父协议。Catalog 可以为 authoring 与 UI 定义 `Web`、`Messaging` 等
Application Protocol Category，但 category 不是识别结果或运行时继承树；category selector 在
Policy Apply 时展开成该 revision 对应的精确 ID 集合，packet path 仍只做整数集合匹配。类似
qDPI protocol path、tunnel/STARTTLS transition 的顺序由识别结果序列表示，不借 category
表达；第一版也不加入 `HTTPS` 自动继承 `HTTP` 规则之类的隐式语义。

Authoring Policy Bundle 与 Checkpoint 保存 `category=web` 这样的规则意图，不冻结 Apply
当时的 category 成员 ID，也不 pin Catalog 版本。Policy Apply、Checkpoint Restore 和软件升级
后的 runtime 重建都使用当前内置 Catalog 重新展开；因此 Catalog 后续把新协议加入 `web` 时，
下一次编译后的 “Web” 规则自然覆盖它。已经发布的精确 ID/key 映射仍保持不变，正在运行的
immutable Runtime Snapshot 也不会在没有 Apply 或 runtime 重建时被 Catalog 元数据原地改变。
Catalog 版本可用于诊断和发布说明，但第一版不构成策略兼容机制。

第一版 Catalog 只收录对目标用户最有价值、能够形成规则或 Activity 价值的少量常用协议，
不以覆盖 pinned libprotoident 的全部输出为完成条件。未映射的 libprotoident 结果不创建临时
AppID、不进入 Protocol Policy，也不增加 `unsupported protocol` 等产品状态；若 flow 到达识别
终态仍没有任何已映射结果，统一显示“未识别”。后续只根据真实用户需求和流量证据向 Catalog
追加协议，不为长尾协议预先投入分类、文案、规则和测试成本。

ProtocolRule 使用两阶段策略，而不是退化成 AppID-only 开关：
早期 Network Gate/L4 stage 先处理只需要静态 packet facts 的规则；识别结果出现后，Protocol
Policy stage 的复合规则以精确协议或 category selector 为必选条件，并可同时约束当时已经存在的
application subject，以及 FlowEntry 上归一化、稳定的 ORIG/REPLY endpoint IPv4/IPv6 CIDR、
ports 和 IP protocol。规则仍属于独立 ProtocolRuleList 和 stage-local priority；早期 `DROP`
不能被晚阶段 allow 推翻。第一版 ProtocolRule 不匹配当前 packet 的 INPUT/OUTPUT、当前
ORIG/REPLY direction 或其它逐包变化的 context；这些条件继续由 L4Rule 处理。

这里参考的是 fork 将 L3/L4 与后来 AppID facts 累积后完成复合匹配的语义，不复制 MAAT、
`APP_SIG_RULE`、通用动态对象表或其 Security Enforcer。第一版 Protocol Policy 也不接受尚未
实现的 Conntrack、HTTP、TLS、QUIC metadata 字段；未来某个 decoder/CT 产品阶段真正加入时，
再把适合作为稳定 flow/session fact 的 typed predicate 接入该晚阶段规则族。Protocol Policy
从当前 FlowEntry 已累计、且本阶段支持的稳定事实中选择一个当前 stage winner：所有已满足的
ProtocolRule 共同按照 `priority asc, explicit order asc, stable rule ID asc` 竞争，而不是让每个
新 AppID 单独产生一个不可与旧命中比较的 verdict。application subject、policy revision 或累计
事实改变后，下一次选择必须使用当时全部可用的受支持事实，并保持相同的 winner 语义；已经完成
的 packet verdict 不追溯修改。winner cache、候选索引、epoch、cursor、matched-set、全量扫描
或增量更新都属于实现与 benchmark 决策，本文不规定其中任何一种表示或算法。

该版本采用 **Recognize-then-enforce**：L4 allow 返回 `PASS_NEXT`，识别完成前不缓存或等待
packet；libprotoident 在当前 graph 内更新 flow facts 后，Protocol Policy stage
可立即对当前 packet 返回 `DROP`；异步事实则从后续 packet 生效。产品必须明确说明，少量早期
流量可能已经通过，短连接也可能在识别前结束；
“默认阻止、仅在识别为某协议后放行”需要未来的 hold 或 controlled probe，不属于前两版。

第二阶段不把 libprotoident 当作后续 Decoder 的预识别器：没有 candidate/decoded 两级结果，
也不等待更深解析确认。它仍不包含完整 Conntrack、TCP stream reassembly、HTTP/TLS/QUIC
metadata、具体协议 Decoder、QUIC 迁移适配或复杂识别设置。

每个 FlowEntry 的 `LpiRecognitionState` 有界保存按首次出现顺序去重的识别结果，以及各结果的
payload-packet sequence。普通协议可以在识别后结束检测；tunnel、NAT、STARTTLS 等
libprotoident continue-recognition 情况可以继续追加新的最终结果。新结果加入当前累计稳定事实；
它可以让新的、更高优先级规则成为 winner，但不会绕过仍然满足的
旧规则。只有当前 winner 是 enforce `DROP` 时才终止该 flow；“任一历史或新增结果曾匹配 DROP
就无条件终止”不是本阶段语义。例如累计结果为 `[SOCKS, Telegram]` 时，priority 10 的
`ALLOW SOCKS` 与 priority 20 的 `DROP Telegram` 同时满足，当前 winner 仍是前者；若
`DROP Telegram` 的 priority 为 5，则它在 Telegram 结果加入后成为 winner 并终止 flow。
Protocol allow 不停止 libprotoident 自身按预算继续识别，也不复制 fork 的
`continue_scanning_flag` 产品开关。没有新结果且 revision/subject 未变时，Protocol Policy
必须产生相同的语义结果；是否复用缓存由实现决定。
Activity 保留识别顺序，UI 默认以最后一个结果作为摘要，并可展示完整顺序；发现顺序不参与规则
优先级。

识别采用固定内部预算，只统计提交给 libprotoident 的 payload-bearing packet；空 payload packet
不消耗预算。libprotoident 正常停止时状态为 `done`，达到预算时为 `exhausted`，两者都不在该
flow 上重试。终态且没有结果时产品显示“未识别”；已有结果时仍显示“已识别”，即使后续
continue-recognition 因预算耗尽。预算不进入第一版 UI，具体默认值由 POC/benchmark 决定，先
以 fork 的 20 个 payload packets 作为测试基线而不是既定产品常量。

### 2.3 后续顺序

Protocol Identification Release 发布并获得真实产品反馈后，再在 Stateful CT、DNS/domain、
Linux 产品化或更深 L7 metadata 中选择下一项。当前不把它们同时承诺为近期主线。

## 3. UI 放在哪里

UI 是产品的一部分，不是 dataplane 完成后的包装层。规划采用以下归属：

```text
docs/product/
  产品定位、用户流程、线框、文案、帮助、发布与社区口径

app/                         # 实现开始时建立
  src/                       # Android/Linux 共享 UI
  src-tauri/                 # Rust 产品控制面与 UI-facing state
  design/                    # tokens、repo-native prototype、视觉资产

src/ + future VPP plugin/
  packet runtime；不拥有页面、导航或用户文案
```

采用同仓库产品层的原因：

- 一个人加 AI 工作时，减少跨仓库版本、契约和文案同步成本；
- UI、Rust control plane 和 VPP Interface 可以随同一个 vertical slice 评审；
- Android first 不会把 UI 写死在 Android platform callback 上；Linux 后续复用相同 UI；
- 产品文档与可运行实现可以互相校验，避免只有外部设计稿没有真实状态覆盖。

外部 Figma、Penpot 或图片可以作为视觉讨论工具，但仓库中的流程、状态矩阵、文案和
可运行 UI 才是发布真相。

Product UI 是 Local Product Backend 的薄客户端：

- Local Product Backend 是本地共享代码，不是远端账号或服务器；
- backend 暴露应用、策略、活动、统计、runtime health 和 mutation result 的产品投影；
- UI 只保存语言、主题、导航恢复、未提交输入等少量 presentation state；
- UI 不维护第二份权威 policy/config/history 数据库，也不直接拼 VPP message；
- Android 与后续 Linux UI 使用同一产品 Interface，平台差异通过 capability 和 platform
  Adapter 表达。

Android 的 Local Product Backend、Telemetry Consumer 与单一 Activity Store writer 归属
RuntimeService 一侧，以普通应用身份运行；Tauri Activity/WebView 被关闭或回收时仍继续消费
bounded runtime records。VPP 只导出 facts/counters，不写产品数据库，Root runtime 也不得以
root 身份写 Activity Store。Store 只保存有界 Activity facts 和派生查询所需数据，不保存 packet
payload，并按 age 与 storage budget 滚动清理。Linux 后续复用同一 product-core consumer/store，
只改变承载进程。

第一版只实现一个简单的 embedded Product Store 和一个 backend-side writer。Policy/config 与
Activity 使用不同 tables 和 repository APIs，以表达权威事务数据与有界可丢失数据的语义差异；
但不预建独立数据库服务、多个 physical stores、event sourcing 或 analytics pipeline。只有实际
测得 contention、capacity 或 reliability 问题后才拆分物理存储。

旧 `sakamoto-app` 的 Compose/Room/Control 实现和大量原型作为交互与失败经验参考；其中
“Android App 侧数据库拥有 Rule/Policy 长期资产”的旧决定不进入当前共享后端基线。

## 4. UI 怎么设计

当前讨论顺序暂缓详细 UI 设计。此阶段只保留 App-first Control、Progressive Control Disclosure、
共享 Product Interface、Root/VPN 初始化参考和 UI 不拥有权威数据库等已确认原则；不决定默认
落点、顶层导航、页面数量、具体布局或视觉样式。旧 `sakamoto-app` 继续作为交互经验和失败
案例参考。详细 Android/Linux 共享 UI 在核心产品接口与 Android L4 vertical slice 稳定后集中
设计，但仍属于 Android L4 Product Release 的交付条件，不因讨论后移而移出发布范围。

顺序是任务与文字优先，视觉润色随后：

1. 确定用户任务、状态和恢复路径；
2. 为核心流程写低保真线框和真实文案；
3. 使用 mock product state 做可点击原型，不等待 VPP backend；
4. 用少量真实用户走查首次启动、建规则、看结果和恢复；
5. 固定最小 design tokens 和可复用 UI pattern；
6. 再通过 Tauri Rust Adapter 接入真实 runtime。

第一版只提供一套 Product UI，采用 **Progressive Control Disclosure**：应用列表承载常用
控制，应用详情逐步出现 L4 规则、统计、证据和诊断；不提供全局“简单模式/高级模式”，也不
维护两套功能或文案。

UI 只依赖稳定的 product-facing view model，例如：

```text
RuntimeSummary
AppSummary / AppDetail
RuleDraft / RuleView
ActivityItem
HealthIssue
CapabilitySet
```

原型阶段由 Mock Product Adapter 提供这些 view；接线阶段由 Tauri Product Adapter 提供。
页面不理解 VPP worker、NFQUEUE packet ID、TUN fd 或 binary API message。

## 5. 第一版信息架构

信息架构必须先服务 App-first Control。下面的页面职责仍需通过线框验证；它们不预先等于五个
同权重的底部导航入口。

### 首页

回答：保护是否生效、当前 Runtime Profile、是否健康、最近发生了什么。VPP、worker、queue
等技术细节只进入诊断信息。

### 应用

应用列表是第一版主工作台，必须保留完整 Linux UID 与多用户区别。用户先从应用行直接控制
Wi-Fi/Mobile/VPN Network Gate，再进入应用详情查看策略摘要、近期活动和 advanced L4
Traffic Rule。第二阶段的协议识别结果仍进入同一详情，不新建孤立的 DPI 产品区。

### 活动

第一阶段显示应用、时间、远端 IP、TCP/UDP、端口、方向、包/字节、allow/block 和 winner。
它用于验证和细化 App-first Control。blocked detail 来自 bounded ActivityAccumulator，允许因
容量淘汰而丢失旧 detail；app/rule counters 仍是精确来源。是否作为启动落点由后续线框和使用
验证决定。第二阶段在同一 ActivityItem 上追加协议识别状态、application protocol 和 category。

### 规则

第一阶段既要支持从 Activity evidence 预填，也要支持在应用上下文中完整创建：

```text
应用实例 → IPv4/IPv6 → source/destination CIDR
→ protocol → source/destination port或range
→ direction/interface → 允许/阻止 → review → apply
```

这些是 Android L4 Product Release 的正式范围，不推迟到后续 CIDR/Ports 版本。UI 可以通过
默认值、预填和 Progressive Control Disclosure 降低常用路径复杂度，但不能删减底层表达能力。
第二阶段在同一应用上下文中增加 ProtocolRuleList，不把协议字段并入 L4 RuleList。近期不做
跨 L4/Protocol Policy 的通用表达式编辑器，也不向用户展示内部 Enforcement Stage。

L4 冲突顺序固定为 `priority 数值升序 → explicit rule order 升序 → stable rule ID 升序`。
mask shape、CIDR 前缀或 pool traversal 都不能成为隐式 winner 语义。规则包含关系只用于
shadow/redundancy warning 和 UI auto-placement，不建立 Strict Specificity 或跨 stage Semantic
Rank。普通产品交互是否直接暴露 priority 数字仍由后续线框决定。
规则库存用于维护已存在资产，不与应用列表争夺第一主入口。

### 设置

近期只包含 Runtime Profile、开机启动、通知、日志保留、导入导出、语言/主题、帮助、隐私和
版本。内部性能与容量参数保留在开发诊断层。

## 6. Root/VPN 产品语义

Root 与 VPN 只在首次引导、权限、运行健康和已验证限制上不同。选择完成后共享首页、应用、
活动和规则；切换 Profile 不复制、不迁移也不删除 Authoring Policy Bundle。

首次启动必须经过可恢复的三步 Runtime Profile Initialization，而不是直接弹出一次权限请求：

1. 检测 Root 与 VPN 能力以及当前授权状态；Root 可用时推荐 Root，否则推荐 VPN，但由用户
   确认互斥 Profile 并完成对应授权；
2. 请求并验证 Visible Runtime Notification；这是产品就绪的必需 Gate，即使部分 Android
   版本在拒绝通知权限时仍可能允许底层 runtime 启动，也不能因此跳过；
3. 启动并验证对应 Adapter、双栈 packet runtime 与 Runtime health，再明确显示初始化成功。

每个页面只显示当前步骤、一个主要动作和针对当前失败的恢复入口；完成步骤折叠，diagnostics
与其它高级信息留在次级入口。初始化不创建额外策略，空策略按正常缺省语义运行。

后续切换 Profile 必须先停止当前 runtime，再重新完成目标 Profile 的权限和 readiness 检查；
切换过程保留同一 Authoring Policy Bundle。

active VPP runtime 非预期退出时，RuntimeService 先清理当前 Profile 的 hook、fd、socket 与
partial state，再按有界 retry/backoff 自动恢复。恢复窗口内重复失败达到阈值后停止重启、释放
Root/VPN 资源并通过 Visible Runtime Notification 和产品状态要求用户介入。次数与退避时间由
真机 release 测试确定，不作为普通用户设置，也不允许形成无限 crash loop。

UI 必须区分：

- 用户主动暂停保护；
- runtime 未运行；
- Packet Capture Adapter 或 VPP runtime 异常；
- Root/VPN 权限缺失；
- policy apply 失败但旧 Runtime Snapshot 仍在运行。

这些状态不能统一收敛成没有行动建议的“启动失败”。

用户主动暂停保护时执行当前 Runtime Profile 的 clean stop，而不是让 VPP 继续以 pass-through
方式运行。Root Profile 停止 VPP Runtime 并移除其 NFQUEUE hooks；VPN Profile 停止包含 VPN
Userspace Flow Stack 的 VPP Runtime、关闭 TUN
并释放系统 VPN slot。暂停保留用户选择的 Profile、Authoring Policy Bundle 和最后成功应用的策略
状态，以便恢复时重新启动；暂停期间没有 packet Activity。“只观察、不阻止”由策略表达，不能
复用暂停生命周期状态。异常 runtime down 也不能伪装为用户暂停。

Network Gate 是 Authoring Policy Bundle 中独立于 L4RuleList 的 GateMatrix rule family。某应用
实例的 Wi-Fi、Mobile 或 VPN Gate 为 blocked 时，GateTable 返回 `DROP`，任何 L4 allow rule 都
不能恢复该网络访问；Gate open 返回 `PASS_NEXT` 并继续匹配适用的 L4 或后续规则。Gate、L4、
Protocol Policy views 共享一次 Apply、policy revision 和 source attribution，但不共享 priority
space。Protocol Policy 的规则、应用对象和匹配实现均不依赖 MAAT。

## 7. Content Design

产品文字与代码同时接受验收。第一轮建立：

- 产品一句话定位和目标用户说明；
- 中英文术语与 i18n key；
- 页面标题、按钮、空状态、确认和错误文本；
- Root/VPN 权限、影响和恢复说明；
- Recognize-then-enforce 限制说明；
- 隐私、日志和诊断数据说明；
- 已知限制与兼容性表达。

错误文案统一回答：发生了什么、保护受到什么影响、用户现在可以做什么。正常产品页面使用
用户语言；VPP reason code、worker index 等只在可复制的诊断详情中出现。

## 8. 发布与社区

每个公开版本同时交付产品和运营材料：

- 产品首页/README、安装和快速开始；
- Root/VPN 模式说明；
- 规则、Activity 和恢复指南；
- 隐私说明、已知限制和设备兼容性表；
- Changelog 与 Release Notes；
- Bug、设备兼容性、协议误识别、功能建议和使用帮助反馈入口；
- 可脱敏导出的诊断信息格式。

近期只维护一个主要社区入口和一个主要发布渠道。Release channel 依次使用 Alpha、Beta、
Stable；每个名称表达产品成熟度，不表达底层 VPP milestone。

## 9. Product Definition of Done

一个阶段只有同时具备以下结果才算完成：

1. 用户能够完成一个端到端任务；
2. 有可安装 APK；
3. UI 覆盖正常、空、加载、权限、失败和恢复状态；
4. 有帮助和已知限制；
5. 有 Host/Device/兼容性证据；
6. 有 Release Notes；
7. 有用户能够找到的反馈入口。

Android L4 Product Release 的首条完整场景是：

```text
安装 → 选择 Root/VPN → 启动保护 → 找到正确 Android 用户下的应用
→ 直接改变该应用联网控制 → 验证访问结果 → 查看基础统计与阻止原因
→ 恢复该应用控制 → 验证访问恢复
```

per-worker dispatch、VPP plugin 或 policy compiler 单独完成，都只是该场景的 enabler，不是
产品阶段完成。

## 10. 下一轮 UI 讨论输入

接下来优先收口而不是编码：

- Android L4 版目标用户和最常见的三个使用场景；
- Root/VPN 首次引导与权限恢复流程；
- 首页、应用详情、建规则和 Activity 四条低保真流程；
- Product view model 与 mock data；
- 中文第一版文案和产品语气；
- Alpha 发布页、帮助目录和反馈入口。

这些结果稳定后，才将第一条端到端场景拆成 Plane vertical slices。
