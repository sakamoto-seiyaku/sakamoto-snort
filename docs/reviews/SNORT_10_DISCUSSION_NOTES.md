# SNORT-10 讨论记录

状态：工作笔记，随 SNORT-10 架构讨论更新
最后更新：2026-06-20
范围：记录讨论主题、已确认边界、待专题展开的问题；不作为实现任务队列
关联：
- Plane `SNORT-10`
- `docs/reviews/NFQUEUE_PERFORMANCE_ARCHITECTURE_REVIEW.md`
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md`
- `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`

## 使用规则

这份文档只记录“讨论地图”和还没成熟到决策文档的中间结论。

约束：
- 不替代 Plane work item。
- 不维护 TODO / backlog 队列。
- 已经形成稳定结论的内容，应同步到 `docs/decisions/` 或 `CONTEXT.md`。
- 未决问题要标成“待讨论”，不能写成已经决定。

## 当前交接状态

本轮已收口：
- Packet-side `observe` / `enforce` 规则执行模式。
- Rule counters、Rule stats reset、Traffic Windows 与 observe-block 的关系。
- Packet diagnostics / Diagnostic Focus 的第一版边界。
- 旧 `wouldRuleId` / `wouldDrop`、`tracked`、generic `STREAM.*`、activity stream、replay 参数的去留。
- Packet diagnostic event 的主要字段口径与 stage pipeline。
- Traffic Windows 第一版设计闭环：配置 / 查询接口、basic/detail tier、reset/time 语义、hot-path 数据结构与 Top-K 边界。
- Hot-path Capability Summary / Advanced Prefilter 的第一轮边界：64-bit primary mask、lazy secondary masks、subject/app 粒度、CT/DPI 高级能力 gate。
- Conntrack A++ runtime 在 A 方案内的 baseline：全局共享 authoritative CT table、自研专用 fixed-bucket intrusive table、当前 field-mix hash、`liburcu-qsbr`、不重叠 shard/bucket bit slices。
- Policy decision cache 第一版两级模型：L1 Base policy cache 与 L2 Post-CT policy cache；L2 只在 L1 `PassToAdvanced` 后启用，使用完整 packet projection + CT facts + DPI key。
- L1/L2 cache hit 必须等价于直接扫描 stage result：cache entry 保存 winner attribution 与 stats handle，hit 后仍更新 rule counters / attribution；完整 diagnostics candidate list 不进入 hot-path cache。
- L1/L2 第一版物理形态都是 per-worker TLS fixed-size direct-mapped exact cache；L2 不挂 CT entry，不做共享表，不把 policy scan result 写回 CT session。
- L2 允许缓存 no-winner / default allow；DPI 未识别时 key 使用 `unknown`，DPI 识别出具体结果后 key 变化并自然 miss。
- IPRULES Authoring Layer v1：规则 / 规则组 / complete UID binding / Draft / Commit / Apply / Checkpoint / Restore / Runtime Snapshot 生效模型已收口。

已同步：
- `CONTEXT.md` 已加入 `Rule execution mode`、`Rule hit counters`、`Diagnostic Focus`、`Packet Diagnostics` 等术语。
- `CONTEXT.md` 已同步 CT 收口术语：`PacketFacts`、`CtFacts`、`DpiFacts`、`CT acquisition gate`、`Unified CT entry`、`DPI / L7 Policy` 与更新后的 `ct consumer`。
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md` 已加入 packet diagnostics 与高级观测边界。
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md` 已加入 Traffic Windows 第一版完整边界。
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md` 已同步 CT / DPI pipeline 边界与 CT A++ runtime baseline。
- `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md` 已加入 CT acquisition、decision cache、`liburcu-qsbr` 与 A++ hash table 方向。
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md` 与 `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md` 已同步两级 policy decision cache 边界。
- `docs/IMPLEMENTATION_ROADMAP.md` 已同步 CT A++ runtime 为下一实现切片，并把 `shared-flow-pool` / owner handoff 降为后续候选变量。
- `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 已标注旧 Conntrack smoke case 的 create-on-accept / block-no-create 语义属于 pre-SNORT-10 历史验收口径。

仍待专题讨论：
- DNS / Domain diagnostics：DNS stream 当前冻结，后续整理 Domain/DNS 线时重做。
- 诊断 / 尝试 / 救援恢复这些工作流如何衔接。

下一轮建议继续拆 Conntrack A++ implementation work items，并单独展开 DPI adapter / classifier 选型边界。

## 已形成的主边界

- `block.enabled` 是组件 / 策略 gate，不是 daemon lifecycle。
- Traffic Windows 是普通用户可长期启用的 online 观测层，只支持 trailing windows，并共享同一组 device-scope window 配置。
- Traffic Windows basic tier 常驻，维护低基数 app/device/window/direction counters 与 app ranking。
- Traffic Windows detail tier 默认开启但可由用户/前端关闭，维护 remote IP / protocol / protocol-port Top-K；它必须被设计成适合长期常开，不能退化成诊断级高成本路径。
- Traffic Windows 的目标之一是摆脱 Conntrack / Flow Telemetry consumer 聚合依赖；basic tier 与 detail tier 都必须基于 `PacketFacts` 与最终 verdict 更新，不得为了 Traffic Windows 启用 Conntrack。
- Traffic Windows 不依赖 Domain-IP Association，也不存储或输出 domain hint。前端如果需要把 remote IP 显示成域名，应独立调用 Domain-IP Association batch lookup。
- Conntrack 从普通用户默认路径剥离，作为 Stateful IPRULES、完整流观测、未来 DPI/L7、未来 FORWARD 的高级 primitive。
- CT acquisition 的 gate 是 subject/app 级高级能力 gate，不是同一 app 内按单条规则逐包细分；Basic enforce block 可以在 CT 前短路，Basic allow / observe-final-allow 下仍应更新 CT。
- CT 状态更新与最终 verdict 解耦；CT entry 由自身 timeout / eviction 管理，后续 Stateful / DPI block 不回滚 CT。
- Conntrack A++ runtime 在 A 方案内采用全局共享 authoritative CT table、自研专用 fixed-bucket intrusive table、当前 field-mix hash 与 `liburcu-qsbr`；`cds_lfht` 只作为 benchmark / reference，不作为默认 CT 表。
- IPRULES 概念上分为 Basic IPRULES 与 Stateful IPRULES。
- Hot-path capability summary 采用 64-bit primary mask + lazy secondary masks。
- Domain-IP Association 独立于 DomainPolicy，可独立 gate。
- `ip-leak` / `IP link` 旧名不再作为新架构术语；新术语为 Resolved-IP Policy。
- RDNS 降级为诊断 enrichment，不能在 packet verdict path 同步执行。
- `Host` 不应继续作为 packet verdict hot path 的核心对象。
- 当前尚未正式上架，本轮重构不为旧 stream / record / control ABI 背兼容成本；旧字段可直接删除或替换，避免为兼容旧模型增加热路径或概念复杂度。
- Packet diagnostics 的规则归因只输出可回溯 ref；完整规则组 / APP 生效链条由 daemon control-plane 基于 Authoring Policy Bundle 重建，前端负责查询并展示该链条，不持有独立规则数据库。

## 后续讨论块

### 1. Observability / Debug Stream / Shadow Evaluation

需要讨论：
- Debug Stream、Flow Telemetry、would/shadow evaluation 的边界。
- 哪些是事实记录，哪些是调试证据，哪些是策略模拟结果。
- 是否共享统一 transport。
- 如果统一 transport，record type 如何分层。
- 策略发布前后的 shadow / would workflow 如何表达。
- 诊断、策略试运行、救援恢复这些工作流如何共享 evidence，但在用户体验上保持顺滑切换。

当前状态：
- Packet diagnostics 与 observe / enforce 归因模型已初步收口；IPRULES Authoring Layer v1 已收口；DNS / Domain diagnostics、救援 / 尝试工作流仍待专题讨论。
- 临时原则：不要在完整设计前让 Debug Stream 和 FlowRecord 互相吞并。
- 已确认业务语义先分三类：Fact Records、Explain Evidence、Shadow Evaluation。
- 诊断 / 尝试 / 救援暂不定模块名；后续需要作为工作流专题继续拆。
- Packet-side rules 需要统一的 effective rule execution mode：`enforce` / `observe`。该 mode 不是 rule 自身的 authoring 状态，而是从 complete Linux UID 直接绑定到 rule / rule group 的 `bindingMode` 继承；`disabled` 属于 source / apply status，不进入 runtime mode。
- `observe` 规则参与与 `enforce` 相同的扫描路径；winner 为 `observe` 时记录 observe hit，不执行 action，并按相同扫描退出点结束。
- `observe` winner 必须 short-circuit 后续规则与后续 stage；不能因为 observe 不执行 action 就继续扫描。
- 第一版保持简单：`observe` 与 `enforce` 使用同一套 winner 归因格式；差异只在 `ruleMode` 以及 action 是否真正执行。
- 如果规则命中进入 Fact Record / Flow Record，`observe` 不走单独的 shadow-hit 格式，而是携带相同的 `reasonId/ruleId` 归因，并用显式 `verdict` 表达实际结果。
- 第一版 record 字段只新增 `ruleMode`；不新增 `declaredAction` / `actionApplied`。source rule 声明动作由 rule attribution 表达，实际结果由显式 `verdict` / `accepted` 与 `reasonId` 表达。
- `reasonId` 跟随 actual packet verdict，而不是跟随 observe winner 的 declared action；例如 observe-block 命中时最终仍是 allow，declared action 通过 rule attribution 表达。
- 规则自己的低成本 counters 仍然常态存在；第一版按声明 action 分桶为 `allowHits` / `blockHits`，不按 `ruleMode` 分桶。
- `blockHits` 表示 block 规则作为 winner 命中次数，不等于实际拦截次数；observe-block 命中时 `blockHits++`，但实际 `verdict=allow`。
- Rule stats 绑定到 rule 当前语义版本与产生该 runtime RuleRef 的 binding mode；第一版在 source rule `action` / `match` 或 direct binding mode 改变时直接 reset 受影响 stats，不引入 rule revision 复杂度。
- record export 是同一语义的导出形态，不是第二套概念。
- Traffic Windows 只统计真实执行结果；observe-block 不增加 blocked count，按实际 allow 计入 accepted usage。
- `wouldRuleId` / `wouldDrop` 属于旧 would-match 模型；重构后的 packet-side observe 不保留这套平行字段。
- Debug Trace / Debug Stream 的逐包 explain、stages、skipped reason、rule snapshot、候选规则等宽调试面必须显式开启；它不是常态 Flow/Fact Record 的一部分，可以接受明显性能损耗。
- Packet diagnostics 的普通前端调试 scope 第一版以 app / UID 为主；不把 `duration` / `maxRecords` 暴露成普通用户需要理解的调试参数。
- 后端仍必须保留内部 bounded queue / drop 语义作为保护机制；这些 cap 是实现安全边界，不是前端产品模型。
- 旧 `tracked` 的新模型术语定为 Diagnostic Focus；配置名倾向 `diagnostics.focused`，表示某个 app / UID 被选为重诊断焦点。
- Diagnostic Focus 不等于常态观测；Traffic Windows、Flow/Fact Record 不依赖它。
- Diagnostic Focus 第一版只允许单个 app / UID；诊断是前端用户显式开启的当前操作，不支持多个 UID 同时 focus。
- Diagnostic Focus 应由诊断 stream / session 持有；`DIAGNOSTICS.STOP`、socket detach 或 session close 必须释放 focus。它不应作为持久 app 配置长期常驻。
- 当前代码需要重构：旧 `tracked` 是 app 持久配置；tracked=1 时即使没有 active subscriber，仍会构造 explain 并写 bounded replay ring。新模型应避免无 consumer 时承担重诊断成本。
- 新模型不支持“先开启诊断并缓存、后消费”的 replay 语义；Diagnostic Focus 只有在 active consumer 存在时才产生重诊断数据。
- 新模型删除 `horizonSec` / `minSize` 这类 replay 参数；诊断 stream 只输出订阅建立之后的新事件。
- 第一版 Diagnostic Focus 主要服务 packet / IPRULES 诊断；DNS stream 暂不扩展、不新增联动能力。
- DNS stream 暂时冻结：本轮不并入 `DIAGNOSTICS.*`，不扩展，也不删除；后续整理 Domain/DNS 线时重新设计。
- 单次诊断只开启一个 channel，不支持同时开启 packet + DNS 的组合 session。
- Packet diagnostics 删除 `suppressed notice`；新模型按 UID 显式诊断，其他 UID 不属于 scope，不需要按旧 tracked-stream 模型报告 suppressed traffic。
- Packet diagnostics 保留 `dropped notice`，仅表示诊断通道自身因 bounded queue / consumer 慢等原因丢失诊断事件。
- Packet diagnostics 删除 `started notice`；`DIAGNOSTICS.START` 的 command response 直接返回生效配置，随后连接进入事件输出模式。
- Packet diagnostics 使用 vNext socket JSON event stream；不进入 Flow/Fact Record 的 shared-memory telemetry ABI。
- `DIAGNOSTICS.START(channel=packet, ...)` 第一版要求 `block.enabled=true` 且 `iprules.enabled=true`；过滤或 IPRULES 未开启时直接返回明确错误，不进入诊断模式，也不为 engine-off 快速路径增加额外 packet 处理。
- 已启动的 packet diagnostics 若运行中遇到 `block.enabled=false` 或 `iprules.enabled=false`，必须立即结束 session、释放 Diagnostic Focus，并尽量向连接发送 stopped / error reason 后关闭。
- 诊断连接进入事件模式后，不允许同一连接执行普通 control command；除停止诊断或断开连接外，前端应使用另一条连接做控制操作。
- `DIAGNOSTICS.STOP` 返回 ack 后关闭该连接，不回到普通 control mode；socket close / detach 也必须自动释放 Diagnostic Focus。
- 不允许抢占 active diagnostic session；已有 Diagnostic Focus 时新的 `DIAGNOSTICS.START` 返回 conflict，前端必须先 stop / close 再切换对象。
- Packet diagnostic event 保留完整 explain 信息，包括 inputs、final、stages、skipped reason、rule snapshots、候选规则等；该通道本身就是显式高成本诊断模式，不在事件字段上过度节省。
- Packet diagnostic event 的 inputs 中输出相关 component gates，并集中在 `gates` 对象内，例如 `blockEnabled`、`iprulesEnabled`、`resolvedIpPolicyEnabled`，用于解释 disabled / skipped。
- Packet diagnostic event 保留 app identity，包括 `uid` / `userId` / app name，帮助用户直接阅读诊断结果。
- Packet diagnostic event 输出包大小时使用 `originalIpBytes`，与 Traffic Windows basic tier 的 bytes 口径一致；不沿用旧的含糊 `length` 字段，也不使用 copied prefix length。
- Packet diagnostic event 的方向字段拆开表达：`packetDirection=in|out` 表示逐包设备方向；`nfqueueHook=local_in|local_out|forward...` 表示底层 hook 来源；`conntrack.direction=orig|reply|any|unknown` 只在 CT 被评估时出现。
- Packet diagnostic event 可输出 queue / worker 上下文，例如 `queueId`、`workerId` / `threadId`，用于排查 NFQUEUE 分配和 worker 行为；这些字段只属于 diagnostics，不进入常态 record。
- Packet diagnostic event 可输出 parser / bounded-copy 边界信息，例如 `copiedBytes`、`originalIpBytes`、`l4Status`、`portsAvailable`、`l4HeaderComplete`、`truncated`，用于排查 copy prefix 或 parser 限制造成的不可用。
- Packet diagnostic event 面向用户排查策略问题，不输出 raw hot-path capability mask、secondary bitset、compiler table 等开发者内部结构；用户可见的是 stage enabled/evaluated/matched/winner、skipped reason、rule snapshot 与最终归因。
- 开发者性能调试 / 内部 trace 后续走独立路径，不与用户可见 Diagnostic Focus / packet diagnostics 混用。
- Packet diagnostic rule snapshot 是 attribution ref，不展开完整高层规则图；第一版字段为 `ruleId`、`clientRuleId` / source ref、`matchKey`、`family`、`action`、`ruleMode`、`priority`。
- Packet diagnostics 的候选 / 扫描路径信息按完整诊断输出，不做每个 stage 的 candidate 数量裁剪；winner、被跳过项、优先级输掉的候选都应尽量完整输出。诊断通道整体仍保留 dropped notice 作为传输保护。
- Diagnostic explain stage 名称必须移除旧 `iprules.enforce` / `iprules.would` 模型，改为新 pipeline。当前实际 event 输出 `ifaceBlock`、`basicIprules`、`statefulIprules`、`resolvedIpPolicy`、`defaultAllow`；未来 DPI 模块启动后再在 `statefulIprules` 与 `resolvedIpPolicy` 之间加入 `dpiPolicy`。observe/enforce 由 winner 的 `ruleMode` 表达。
- `defaultAllow` 作为显式 stage 输出；完整 pipeline 尽量输出，未评估 stage 使用 skipped reason（例如 short-circuited）表达。
- `ifaceBlock` 是最高优先级 gate，不是 packet-side rule；不携带 `ruleMode` 或 `ruleId`，命中时用 `reasonId=IFACE_BLOCK` 与 stage evidence 解释。
- `ifaceBlock` 命中后仍输出后续 stages，并标记为 short-circuited，明确说明后续 packet-side policy 没有被评估。
- `statefulIprules` 只有在该 UID / family 存在 CT-consuming rules 时才 evaluated；没有 CT consumer 时 skipped reason 为 `noConsumer`。
- 若存在 CT consumer 但 CT facts 不可用，`statefulIprules` 仍视为 evaluated，并输出 conntrack unavailable / invalid 的明确原因；这是该 stage 的输入异常，不是 skipped。
- `resolvedIpPolicy` 诊断 stage 临时口径：gate 关闭为 `skipped:disabled`；gate 开启但无 consumer 为 `skipped:noConsumer`；有 consumer 但当前 IP 无 association 为 `evaluated, matched=false, reason=noAssociation`；命中时成为 winner。后续实现该能力时再细化 association 证据。
- Packet diagnostic event 不输出 legacy `host` / domain 字段；IP 到域名的显示由前端按需调用后端 Domain-IP Association 查询，不在 packet diagnostic event 中 join。
- 新接口命名从泛化 `STREAM.*` 收窄为诊断语义，倾向 `DIAGNOSTICS.START` / `DIAGNOSTICS.STOP`，参数使用 `channel=packet` 与 app selector。
- 重构时同步替换旧 `tracked` / generic stream 相关变量、结构体、字段命名，避免新语义继续挂在旧名称上。
- 现有 `activity stream` 只输出 `blockEnabled` 状态，不属于 packet diagnostic；新模型不迁移该能力，后续清理时删除或注释掉。前端需要状态时使用 `CONFIG.GET(block.enabled)`。
- DomainPolicy 暂不纳入 rule execution mode；域名侧匹配保持简单。

### 2. Traffic Windows 具体设计（第一版已收口）

状态：第一版设计已经形成闭环，以下内容作为后续实现拆分输入，不再作为当前轮次的未决字段清单。

已收口范围：
- trailing windows 配置模型。
- heavy-hitter 算法与误差表达。
- per app / direction / protocol / port / remote IP 的内存布局。
- blocked packet count 只作为 app/window/direction 下的总计数；不做 reason/rule/remote IP/port 细分。
- 热路径无分配、固定成本、低锁争用设计。
- 前端查询 API。

当前状态：
- 第一版只支持 `last N` trailing windows。
- 第一版默认四个窗口：`last 15m`、`last 1h`、`last 5h`、`last 24h`。
- 用户可以替换这 4 个窗口的 duration；第一版不支持超过 4 个 active Traffic Windows。
- Traffic Windows 配置始终保留 `1..4` 个 windows；第一版不支持 `windows=[]` 特殊状态。`enabled` 只控制是否更新 runtime state。
- 每个窗口 duration 的合法范围为 `60..86400` 秒，同一配置内不允许重复 duration。
- `last 24h` 是 trailing 24 小时语义；不引入 `today` / 本地自然日窗口。
- Traffic Windows 的 `now`、bucket index、coveredSec 与 trailing window 判断都基于 monotonic time，不使用 wall-clock、本地时区或自然日边界；系统时间调整、NTP 校时或时区变化不影响窗口。
- 第一版统一使用 `60s` bucket，查询结果是分钟级 trailing summary；更长 retention 或更细粒度窗口留给后续高级能力。
- Traffic Windows 配置是 device-scope；启用后所有 app 都从该窗口启用时开始累计，per-app 查询读取该 app 在同一窗口里的独立贡献。
- Traffic Windows 配置支持 KISS 的 top-level partial patch；`enabled`、`detailEnabled` 与 `windows` 可单独提交。`windows` 字段一旦出现，按完整窗口数组替换处理，不支持 per-window merge patch。patch 先归一化和校验；只有归一化后的配置实际变化才 reset。完全 no-op patch 返回成功但不清空 runtime state。任何有效配置变更，包括 `enabled` / `detailEnabled` 切换或 duration 变化，都会清空当前窗口数据，新窗口组从变更完成时重新累计。
- `enabled=0` 生效时同样立即清空 existing runtime state；它不是暂停并保留当前计数。之后 packet 不更新 Traffic Windows。后续 `enabled` 从 `0` 切回 `1` 时，按新的 `epochStartMonoSec` 从零重新累计。
- Traffic Windows 配置作为用户偏好持久化；Traffic Windows state 不持久化。daemon 重启、`RESETALL`、Traffic Windows 配置变更都会清空窗口计数和 Top-K，并按当前持久化配置重新累计。普通规则 / policy 变化不 reset Traffic Windows；已有窗口数据继续表示这些 packet 发生时的实际 verdict 与流量。
- Traffic Windows 使用独立控制命令族，不塞入 `METRICS.GET`：`TRAFFIC_WINDOWS.CONFIG.GET`、`TRAFFIC_WINDOWS.CONFIG.SET`、`TRAFFIC_WINDOWS.GET`、`TRAFFIC_WINDOWS.APPS`、`TRAFFIC_WINDOWS.RESET`。`GET` 必须用 `durationSec` 指定一个 active window，一次只返回该窗口的数据；第一版不引入独立 `windowId`。`TRAFFIC_WINDOWS.APPS` 用于首屏 app ranking，第一版只接受 `durationSec` 与 `limit`，固定按 total `acceptedBytes` 排序，并返回每个 app 的 in/out basic counters。
- Traffic Windows 接口不表达 daemon / dataplane lifecycle。若 daemon 未运行或控制平面连不上，则 `TRAFFIC_WINDOWS.*` surface 本身不可用；前端按 runtime / daemon 连接状态处理，不在 `TRAFFIC_WINDOWS.GET` / `APPS` response 中增加 lifecycle 字段。`TRAFFIC_WINDOWS.CONFIG.GET/SET` 也属于同一个 daemon control surface，不提供离线读写语义。
- Traffic Windows 配置只通过 `TRAFFIC_WINDOWS.CONFIG.GET/SET` 管理，不进入通用 `CONFIG.GET/SET`。
- `TRAFFIC_WINDOWS.CONFIG.GET/SET` 的 request / response 风格与通用 `CONFIG.GET/SET` 保持一致。`CONFIG.GET` args 使用 `keys:[...]`，response 使用 `values:{...}`；`keys:[]` 合法并返回 `values:{}`。`CONFIG.SET` args 使用 `set:{...}` 包一层，成功只返回 `ok`。`TRAFFIC_WINDOWS.CONFIG.SET` 是 Traffic Windows 专属 partial patch，不进入通用 `CONFIG.SET`。空 `set:{}` 合法，返回 `ok` 且不 reset；未出现字段保持原值。若 `set` 中出现 `windows[]`，则必须提交完整新窗口数组并按整组验证。response 不返回 `reset` 字段；是否 reset 是后端内部状态边界，不作为前端 contract。
- `TRAFFIC_WINDOWS.RESET` 只支持全局 reset，清空 device aggregate 与所有 per-app Traffic Windows runtime state，不修改持久化配置；reset 完成后按当前配置重新累计。不支持 per-app reset，避免 device aggregate 与 per-app contribution 不一致。
- `TRAFFIC_WINDOWS.APPS.limit` 默认 50，最大 200。
- `TRAFFIC_WINDOWS.APPS` 是 accepted traffic ranking，不是 inventory；只返回该 window 内 `totalAcceptedBytes > 0` 或 `totalAcceptedPackets > 0` 的 app。只有 blockedPackets、没有实际 accepted traffic 的 app 不进入 ranking。完整 app 清单仍使用 `APPS.LIST`。
- `TRAFFIC_WINDOWS.APPS` 排序 key 为 `totalAcceptedBytes = directions.in.acceptedBytes + directions.out.acceptedBytes`，response item 应返回该 total 以及 in/out basic counters。
- `TRAFFIC_WINDOWS.APPS` ranking 的排序必须稳定：先按 `totalAcceptedBytes` 降序，再按 `totalAcceptedPackets` 降序，最后按 `uid` 升序。
- `TRAFFIC_WINDOWS.APPS` 第一版只返回 total ranking，不提供 per-direction ranking。
- `TRAFFIC_WINDOWS.CONFIG.SET` 与 `TRAFFIC_WINDOWS.RESET` 必须提供严格边界：命令返回 `ok` 后，后续 packet 只能进入新 Traffic Windows state，不允许半旧半新。实现可采用 epoch/bank swap 并延迟释放旧 state。
- Traffic Windows 配置包含 `enabled` 与 `detailEnabled`，二者与通用 `CONFIG.GET/SET` 的 toggle 类型保持一致，使用 `0|1`（u32）传输，默认均为 `1`。产品预期 basic tier 与 detail tier 都可以长期常开，但前端必须能分别关闭 Traffic Windows 整体或只关闭 detail tier；任一开关切换都按配置变更处理并 reset 全部 Traffic Windows state。`detailEnabled` 变化不只清 detail tier，basic counters 也一起清空，保持 basic/detail epoch 一致。
- Traffic Windows 同时维护 device aggregate state 与 per-app state；device 查询读全局汇总，app 查询读指定 app 的独立贡献。
- per-app Traffic Windows state 以 complete UID 为单位管理。Android 设备 app 数量本身是产品边界。第一版 per-app state pool 预分配 1024 个 complete UID slots，不作为用户可配置项。优先在配置启用、reset、package/user 变更等非 packet hot path 上准备 state；如果 pool 用尽，为保证 per-app 数据完整性允许扩容并创建新 state。扩容按固定 chunk 进行，每次增加 256 个 complete UID slots，不逐个 slot 分配，也不指数翻倍。触发扩容的 packet 等扩容完成后继续更新新 per-app state，不跳过统计。扩容属于 rare slow path，可以接受短暂阻塞，但正常 packet hot path 不应承担大对象分配。
- uid 到 per-app state 的热路径查找使用只读 `UidStateIndex` snapshot。packet worker 原子读取当前 snapshot，并执行无锁 UID -> `TrafficAppState*` lookup；不得在正常 packet hot path 上持有全局 map 锁、rehash、移动 vector 或分配大对象。package/user 变更、Traffic Windows reset、Traffic Windows config change、pool 扩容等慢路径构建完整新 snapshot 后原子发布；旧 snapshot 与旧 state 通过 epoch/RCU/quiescent 机制延迟释放，确保 worker 和查询线程不会读到半初始化或已释放对象。
- per-app Traffic Windows 的身份 key 是 complete Linux UID；同一个 appId 在不同 Android user/profile 下分开计数。
- Traffic Windows 是常态可观测能力，不依赖 `block.enabled` 或 `iprules.enabled`。只要 Traffic Windows 自身 `enabled=1` 且 packet 进入 dataplane，就按最终实际 verdict 更新；`block.enabled=0` 时仍统计流量，通常按实际 allow 计入 accepted traffic。
- `iprules.enabled=0` 同样不影响 Traffic Windows；它只影响规则评估，不影响窗口观测。
- 每个 packet 只在最终 verdict 确定后更新 Traffic Windows 一次：device aggregate state 与对应 complete UID 的 per-app state 各更新一次。不得在 policy stage 中间更新。
- basic tier 在最终 verdict 后同步更新，且只能做固定维度、近似零额外成本的 counter 更新，用作首屏 app ranking 与 counters 的近实时基础。
- basic tier 采用 per-worker/per-shard `60s` bucket ring 的模型，而不是每个 active window 各写一份 counter，也不是所有 worker 共同争用同一组 atomic counters。packet hot path 只写当前 worker/shard 的当前 minute bucket；`15m`、`1h`、`5h`、`24h` 等窗口在查询时按 `durationSec` 合并相关 shard/bucket。这样 hot path 成本不随 active window 数量增长，也避免高流量下跨线程 atomic RMW 和 cache-line contention。
- basic tier bucket rollover 不依赖后台定时清理，也不维护 per-window sliding total。每个 bucket 存自己的 monotonic `bucketMinute` index；写当前 monotonic minute 时，如果目标 slot 的 `bucketMinute` 不是 current minute，先清空该 slot 并写入新的 `bucketMinute`。查询只汇总 `bucketMinute` 落在目标 trailing window 内的 buckets。
- Traffic Windows 不依赖 Conntrack，不需要 Flow Telemetry consumer active，也不使用 flow lifecycle records 作为输入。
- Traffic Windows 是 pull API，不向前端推送窗口更新；前端按页面需要主动查询，刷新可由前端以数秒级节奏控制。
- 旧 `METRICS.GET(name=traffic)` 不进入 SNORT-10 后的新接口；Traffic Windows 独立命令族承载 basic tier 与 detail tier，不沿用旧 DNS / rxp / rxb / txp / txb / allow / block 混合 shape。
- `HELLO.capabilities[]` 应加入 `traffic-windows`，前端据此发现 `TRAFFIC_WINDOWS.*` surface；旧 `METRICS.GET(name=traffic)` 能力应随新 surface 清理。
- 第一版 Traffic Windows 不统计 DNS decision / DNS traffic；旧 `traffic.dns` 语义不迁入 Traffic Windows。
- 基础窗口 counters 按 `direction=in|out` 输出 `acceptedPackets`、`acceptedBytes`、`blockedPackets`；`blockedPackets` 只作为总计数，不存储或输出 `blockedBytes`，也不按 reason/rule/remote IP/port 细分。
- `TRAFFIC_WINDOWS.GET` 的 device aggregate 与 app scope 都包含 `blockedPackets`；只有 `TRAFFIC_WINDOWS.APPS` ranking 排除 blocked-only app。
- Traffic Windows 的 `acceptedBytes` 使用 original IP packet bytes：IPv4 使用 IP total length，IPv6 使用 payload length + 40 bytes；不使用 NFQUEUE copied prefix length，也不使用 L4 payload-only bytes。
- 如果 original IP packet bytes 无法可靠取得，则该 packet 不更新 Traffic Windows。
- 第一版不暴露 Traffic Windows skip/drop health counters；这类实现健康信息不进入 `TRAFFIC_WINDOWS.GET` / `APPS` 产品结果。
- Top-K 按 `direction=in|out` 分开维护。
- accepted traffic Top-K 只统计 accepted packets；blocked packet 不进入 remote IP / protocol / protocol-port Top-K。
- remote IP Top-K 可用 approximate heavy-hitter。
- protocol + remote port Top-K 的 key 为 `{protocol, remotePort}`；是否进入该 Top-K 由 parser facts 的 `portsAvailable` 决定，不硬编码 TCP/UDP 协议集合。无可用远端端口的包不进入该 Top-K。
- `remotePort` 永远表示对端端口：`direction=out` 时取 `dstPort`，`direction=in` 时取 `srcPort`。
- protocol-port heavy-hitter 的内部 key 使用固定二进制 struct：`{protocol:u8, remotePort:u16}`。`remotePort` 使用 parser 阶段归一化后的 host-order numeric value；Traffic Windows 不在后续更新或查询路径反复做 network/host byte-order 转换。对外输出同样使用这个 numeric value。
- `TRAFFIC_WINDOWS.GET` 可接受前端提供的 Top-K 返回数量参数 `topKLimit`；默认返回 10 个 leaders，最大 64，内部 capacity 与返回数量分开。
- `topKLimit` 只是查询参数，不进入 Traffic Windows 持久化配置；后端实现只需要固定最大返回值与默认值。
- 第一版 `TRAFFIC_WINDOWS.GET` 不支持字段选择；一次返回该 window/scope 下的 counters、remote IP Top-K、protocol Top-K、protocol-port Top-K。
- `TRAFFIC_WINDOWS.GET` 返回按 direction 固定对象分组：`directions.in` 与 `directions.out` 必须总是出现。
- `TRAFFIC_WINDOWS.GET` 返回 `coveredSec`，表示当前结果实际覆盖的秒数；新启用或 reset 后未填满的窗口会小于 `durationSec`。每次 state reset / config effective 时记录 `epochStartMonoSec`；查询时 `coveredSec = min(durationSec, nowMonoSec - epochStartMonoSec)`，再按 bucket 实际可用范围聚合。`coveredSec` 使用 monotonic 秒级近似，范围为 `0..durationSec`，只是前端覆盖提示；counters 仍是 60s bucket summary，不承诺审计级时间边界。不返回 wall-clock `startedAt`，也不返回 snapshot/generated time。
- `TRAFFIC_WINDOWS.APPS` 也返回同一语义的 `coveredSec`。
- `TRAFFIC_WINDOWS.GET` 不传 `app` 时返回 device aggregate；传 vNext `app` selector 时返回该 complete UID 的 per-app state。
- 当 `detailEnabled=1` 时，device aggregate scope 与 app scope 都提供 detail Top-K；device scope 返回全局窗口 Top-K，app scope 返回该 app 的窗口 Top-K。
- app scope response 返回 `uid`、`userId`、`app` identity fields；device aggregate response 不返回 app identity fields。
- `TRAFFIC_WINDOWS.APPS` item 返回已有 app identity（`uid`、`userId`、`app` canonical/package name）即可；不返回 launcher label / displayName，前端自行按 UID/package join 本地 app label。
- app selector 不存在时返回 vNext selector error；selector 成功解析但该 app 没有 Traffic Windows 数据时返回 ok + zero-filled window result，用于区分“app 没安装/不可解析”和“app 已存在但没有流量”。zero-filled result 仍返回固定 `directions.in/out`，counters 为 0，Top-K 数组为空。
- 当 Traffic Windows `enabled=0` 时，`TRAFFIC_WINDOWS.GET` 返回 `{"enabled":0}` 即可，不返回 zero-filled window result。
- 当 Traffic Windows `enabled=0` 时，`TRAFFIC_WINDOWS.APPS` 同样返回 `{"enabled":0}`，不返回空 ranking。
- 当 `enabled=1` 且 `detailEnabled=0` 时，`TRAFFIC_WINDOWS.GET` 正常返回 basic counters，并携带 `detailEnabled:0`；Top-K 数组返回空数组。
- 该规则同时适用于 device aggregate scope 与 app scope。
- `detailEnabled` 只控制 detail tier 的 Top-K 更新与返回，不影响 basic counters，也不影响 `TRAFFIC_WINDOWS.APPS` app ranking。
- 当 `enabled=1` 但 `TRAFFIC_WINDOWS.GET.durationSec` 不属于当前 active windows 时，返回 `INVALID_ARGUMENT`。
- 当 `enabled=1` 但 `TRAFFIC_WINDOWS.APPS.durationSec` 不属于当前 active windows 时，同样返回 `INVALID_ARGUMENT`。
- `remoteIpTopK[]` 使用统一字符串字段 `remoteIp`，并携带 `ipVersion=4|6` 供前端区分 IPv4/IPv6；不拆成 IPv4/IPv6 两套数组。
- `remoteIp` 永远表示对端 IP：`direction=out` 时取 `dstIp`，`direction=in` 时取 `srcIp`。
- Top-K item 都返回 `acceptedBytes` 与 `acceptedPackets`；remote IP 排名主权重为 accepted bytes，protocol 与 protocol-port 同时提供 bytes/packets 供前端展示。
- Top-K 输出排序必须稳定：先按 `acceptedBytes` 降序，再按 `acceptedPackets` 降序，最后按 key 的稳定二进制顺序升序。这样同值项不会在多次查询之间随机抖动。
- `protocolTopK[]` 和 `protocolPortTopK[]` 的 protocol 字段使用 IP header / terminal L4 protocol number，例如 TCP=6、UDP=17、ICMP=1、ICMPv6=58；不使用字符串 token。对 L4 invalid/unavailable 但 IP envelope 和 remote IP 可用的 accepted packet，`protocolTopK[]` 使用 reserved sentinel `protocol=255` 归入 unknown/error bucket；Traffic Windows 输出里 `255` 一律表示 unknown/error bucket，不再区分真实 header value 255。这类 packet 不进入 `protocolPortTopK[]`。
- remote IP Top-K 可用 approximate heavy-hitter，但对外接口不暴露误差字段；前端只按展示型排行使用。
- remote IP heavy-hitter 的内部 key 使用固定二进制 endpoint key：`ipVersion` / address family 加 16-byte address buffer。IPv4 与 IPv6 共用同一结构，IPv4 只填充约定的 4-byte 部分，其余部分必须归零；key 比较和 hashing 必须包含 family，避免 IPv4 与 IPv6 或 IPv4-mapped IPv6 产生歧义。地址字节保持 parser 得到的网络字节序；packet hot path 不构造 IP 字符串，输出阶段才格式化 `remoteIp` 与 `ipVersion`。
- detail tier 内部 Top-K capacity 第一版固定为 64，不提供配置；后续根据性能数据再调整。
- detail tier 的 shard bucket 内部不使用会扩容的 hash map 做精确统计。remote IP / protocol-port 的候选维护采用固定容量 heavy-hitter table；packet hot path 不做 heap allocation，不触发表扩容。新 key 只能在固定槽内命中、插入、竞争或替换；查询时合并各 shard/bucket 的候选再排序截断。
- 固定容量 heavy-hitter table 采用 Space-Saving / Metwally 风格替换规则：key 命中时累加 counters；存在空槽时插入；满表且新 key 未命中时，替换当前最小 counter 的槽，新 key 继承 `min + delta` 作为估计值，并在内部记录该 slot 的误差。remote IP 与 protocol-port heavy-hitter 的主权重是 `acceptedBytes`；替换最小槽和输出排序都按 bytes，`acceptedPackets` 只是随附展示 counter。误差不进入 `TRAFFIC_WINDOWS.GET` response；输出仍只暴露展示用 Top-K item。
- `protocolTopK` 是 detail tier 的例外：公开 protocol 字段是 IP protocol / IPv6 terminal next-header 的 8-bit wire value，因此 shard bucket 内部使用固定 256-slot exact counter array，按 protocol 下标 O(1) 更新。`protocol=255` 仍按 Traffic Windows 输出约定保留为 unknown/error bucket；不尝试区分真实 header value 255。未来 DPI / L7 protocol ID 如果进入产品，应作为独立维度设计，不能复用 `protocolTopK.protocol`。
- Traffic Windows 的对外接口保持 KISS，但内部设计的第一原则是最小化 packet hot path 的时间成本；这一原则同时适用于 basic tier 与 `detailEnabled=1` 的 detail tier。正常 packet hot path 的算法复杂度必须低且有明确上界，并且不得被查询、聚合、排序、维护、Traffic Windows reset 或 Traffic Windows config change 阻塞。可以接受更多内存占用、查询侧聚合成本、异步/延迟聚合、预分配 / memory pool 和更复杂的数据结构，以换取更低的每包时间成本。所有预分配 / pool 必须有明确的初始规模与扩容策略；正常路径依赖预分配，极少数扩容路径为数据完整性服务，可以比普通 packet path 慢。若内部复杂度更高的方案能显著降低热路径成本，应优先选择热路径成本更低的方案。
- detail tier 采用 per-worker/per-shard staging + 查询/维护时合并的方向。`detailEnabled=1` 时，packet worker 只写自己 shard 的当前 `60s` bucket；不得在 packet hot path 维护全局 Top-K、执行全局排序、扫描全局 app state，或获取跨 worker 大锁。排序、Top-K 合并、过期 bucket 清理可放到查询时或 bounded maintenance 中完成。接口不承诺审计级实时性，只承诺 bounded 当前窗口摘要。
- `TRAFFIC_WINDOWS.APPS` ranking 在查询时计算和排序；packet hot path 不维护 app ranking heap。查询线程可以扫描已有 app window state 并排序截断，但不得阻塞 packet worker。
- 查询线程读取 shard/bucket 时必须使用 best-effort snapshot 规则，不为强一致结果锁住 packet worker。实现可以使用 relaxed atomic counters、per-bucket sequence/version copy 或等价机制避免 C++ data race；如果读到 bucket 正在 rollover，可以跳过该 bucket 或重读一次。查询结果允许轻微并发误差。
- Traffic Windows 查询返回 best-effort snapshot；允许数秒级陈旧或并发下的轻微不一致，不追求纳秒级一致性，也不承担运营商计费系统式精确审计语义。设计不得为了强一致查询引入会阻塞 packet worker 的复杂同步。
- Hot-path capability summary 必须为 Traffic Windows 分配两个 primary bits：`needsTrafficWindowsBasic` 与 `needsTrafficWindowsDetail`。默认通常两者都开启，但 packet path 必须能在 `enabled=0` 或 `detailEnabled=0` 时按 bit 跳过对应更新。
- 初始方向：默认 `displayK=10`，内部 heavy-hitter `capacity=64`。

### 3. Hot-path Capability Summary / Advanced Prefilter

需要讨论：
- primary mask bit 分区。
- secondary masks 的结构。
- Basic / Stateful / DPI / Resolved-IP 的 PacketFacts-only prefilter。
- 如何避免每个模块重复判断自己是否工作。
- capability summary 的 subject 粒度。

当前状态：
- 64-bit primary mask 已确认。
- DPI 只占 primary 里的粗粒度 `needsDpi` bit。
- 允许 lazy secondary masks。
- capability summary 服务 stage/pipeline 调度，目标是在热路径上避免 Conntrack、DPI、Traffic Windows、Diagnostics 各模块重复做 subject/app lookup。
- CT / DPI 是 subject/app 级高级能力 gate；不在同一 app 内按单条 CT 规则的 cheap precondition 决定每个 packet 是否进入 CT。
- Policy decision cache 第一版拆成 L1 Base cache 与 L2 Post-CT cache；L2 只处理 L1 `PassToAdvanced` 的 packet，不处理 L1 final allow / observe-final-allow。
- L1/L2 cache entry 不能只保存 verdict，必须保存 rule attribution 与 stats handle，保证 cache hit 与重新扫描的 counters / diagnostics 归因一致。
- L2 Post-CT cache 是 per-worker policy cache，不是 CT entry attachment；CT session 只保存 flow/session state 与 flow-level facts。
- L2 的 no-winner / default allow 可以缓存；DPI unknown 是 key 的一部分，不需要特殊禁止。

### 4. PacketFacts / Bounded Copy / Parser

需要讨论：
- `512` bytes bounded copy 下的 parser 边界。
- original IP packet bytes 的提取与校验。
- IPv6 extension header walker 与预算。
- `PacketFacts` 栈上模型。
- 从 packet path 移除 Host materialization。

当前状态：
- bounded copy 第一版默认 `512` bytes。
- bytes 口径为 original IP packet bytes，不是 copied prefix length。

### 5. Domain-IP Association / Resolved-IP Policy / RDNS

需要讨论：
- Association store 的 TTL、cap、source、confidence。
- DNS verdict producer 与未来 DNS observation producer 的接口。
- batch lookup API。
- Resolved-IP Policy stage 的输入与输出。
- RDNS 后台队列、cache 与诊断接口。

当前状态：
- Domain-IP Association 独立 gate 已确认。
- DNS Observation Source 只作为 future producer contract，不进当前第一轮实现。
- RDNS 降级为诊断 enrichment。

### 6. IPRULES Compiler 分层

需要讨论：
- Basic IPRULES 与 Stateful IPRULES 是否继续共用 engine。
- CT-consuming / DPI-consuming rules 的 preflight 与 compile。
- 高级规则如何拆 cheap precondition 与 expensive condition。
- 前端如何得知某条规则会启用高级成本。

当前状态：
- 概念上分 Basic / Stateful。
- 实现上保留一个统一 IPRULES compiler / engine / compiled snapshot authority：一次 apply / restore 输入一组 rules，发布同一个 snapshot epoch。
- 同一 snapshot epoch 内派生多个 hot views：`basicView4/6`、`statefulView4/6`、`dpiProjectionView4/6` / future `dpiView4/6`、`SubjectHotPathCaps` 与 preflight/cost summary。
- `RuleStore` / committed rules 是慢路径权威集合，用于 `PRINT`、apply mapping、rule identity、stats lifetime 与 diagnostics attribution。
- 不把 Basic / Stateful / DPI 拆成多个独立 engine 或多个不同步发布的 snapshot；hot views 与 subject caps 必须同 epoch 发布。
- 当前 local-device 模式下，`SubjectHotPathCaps` key 固定为 `{complete Linux UID, IP family}`；IPv4 / IPv6 caps 分开。caps 只由 compiled-active rules 与 active observation consumers 贡献，disabled / compile-inactive / validation-failed / entitlement-failed rules 不贡献 caps。当前阶段不规定 caps 的物理存储形态；实现可沿用当前 `uid + family` gate/cache 方向并按测量决定布局。
- `basicView4/6` 与 `statefulView4/6` 复用当前 mask/subtable/bucket 编译技术，但必须是独立 compiled views；Basic view 不包含 `ctState` / `ctDir` mask，不扫描 Stateful bucket。
- 当前 enforce / would 双通道候选组织不能照搬为 SNORT-10 语义；compiled `RuleRef.mode=enforce|observe` 来自 complete Linux UID direct binding mode，并在同一 stage 内按 `priority desc, ruleId asc` 竞争同一个 winner。
- bucket 内改成 unified candidate model：`exactRules` + `rangeRules`，`RuleRef` 携带 effective mode 与 source rule action，两类列表都按 `priority desc, ruleId asc` 排序；subtable 剪枝需要维护 `{maxPriority, minRuleIdAtMaxPriority}` 这类 best-possible key，不能只看 `maxPriority`。
- `dpiProjectionView4/6` / future `dpiView4/6` 先作为 DPI / L7 后续专题的架构占位和讨论基准；当前只确定 `dpi.*` 不污染 Basic / Stateful views，具体 DPI projection 字段、classifier 时机、result schema 与 cache 细节后置。
- `compile-inactive` 只适用于规则本身通过 validation、且产品 / build / entitlement 支持该能力，但当前配置未启用对应 runtime capability 的情况。例如合法 active `dpi.*` 规则在 DPI 未开启时可 per-rule compile-inactive，整批 apply 仍可成功，其它规则进入新 snapshot。compile-inactive 规则可保留在后端规则组 / committed `RuleStore` / checkpoint 中，但不得降级编入 Basic / Stateful、不得参与 `SubjectHotPathCaps`、不得进入 hot views，也不得静默丢弃。runtime plane 必须等价于这条规则不存在：无 `RuleRef`、无 runtime stats、无 hit / would-hit counters、无 diagnostics/cache attribution、无扫描或 verdict 痕迹。响应必须带 `ruleId` / `clientRuleId`、compile status 与 reason 供前端展示。规则 validation 失败、产品 / build / entitlement 不支持或付费能力未授权时，apply / preflight 失败。
- compiler / control plane 必须能报告每条 committed rule 的结构化 compile status，语义至少包含 `active`、`disabled`、`compile-inactive`；每条结果至少能稳定定位规则并携带 status / stable reason code。具体 API shape 后续 authoring/API 设计时再定。

### 7. Conntrack / DPI 长期路线

需要讨论：
- Conntrack 作为高级 primitive 的生命周期与资源模型。
- DPI 库 vendor / pin 策略。
- DPI result 的稳定 ID、category、规则匹配方式。
- libprotoident / nDPI 这类库如何通过 adapter 隔离。
- 未来 FORWARD / hotspot gateway mode 的约束。

当前状态：
- Conntrack A++ runtime 在 A 方案内已选 baseline：自研专用 fixed-bucket intrusive CT table + 当前 specialized field-mix hash + `liburcu-qsbr`。
- `liburcu-qsbr` 负责 read-side lifetime / deferred reclamation；`cds_lfht` 是通用 lock-free RCU hash table，只作为 benchmark / reference，不作为默认 CT 表。
- C/owner handoff 与 NFQUEUE / userspace 分流仍是未来单独架构，不混入当前 A++ baseline。
- DPI 需要二级 matcher。
- 第三方库 enum ordinal 不应作为长期稳定 API。

### 8. RuntimeService / 前端 Gate Contract

需要讨论：
- 哪些能力由普通 UI 长期启用。
- 哪些能力只在诊断 session 开启。
- 哪些配置 next-start-only，哪些可热更新。
- 不同前端版本如何通过 gate 选择能力，而不是要求后端 product profile。

当前状态：
- 后端不引入 Google Play / full build profile 枚举。
- 前端版本通过启用 / 隐藏能力形成产品形态。

### 9. Measurement / Perf 验收矩阵

需要讨论：
- baseline、Traffic Windows、CT、DPI、Domain-IP Association、Debug Stream 分别怎么测。
- idle current、scheduler wakeups、NFQUEUE queue stats。
- verdict p50 / p95 / p99。
- 各模块启用前后的预算。

当前状态：
- 原 review 已提出 power audit 和 perf matrix 方向。
- 具体矩阵待后续整理。

### 10. IPRULES Authoring Layer

状态：v1 概念边界已收口。后续只拆具体 API schema、持久化格式、实现 work items 与前端展示细节，不再重新打开本节概念边界。

已收口范围：
- Authoring layer 统一使用四个相互关联的状态点：`Draft`、`Committed Policy Revision`、`Checkpoint`、`Runtime Snapshot`。`Draft` 是 daemon control-plane / persisted store 中的草稿 Authoring Policy Bundle，包含可复用规则、规则组、规则组嵌套与 complete Linux UID 生效绑定；前端只通过 daemon 命令读写它，不拥有独立规则数据库。v1 规则组嵌套上限固定为 3 层，后续高级 / 付费能力可以提高该限制，但不影响当前模型。`Committed Policy Revision` 是从 Draft commit 出来的全局已保存 Authoring Policy Bundle revision；`Checkpoint` 是每次 Apply 一个 committed revision 成功后产生并保留的全量 Authoring Policy Bundle 快照，包含该次 Apply 当时的 per-rule apply status；`Runtime Snapshot` 是从 source bundle 编译出的内存态 datapath 视图。
- 状态流是 `Edit Draft -> Commit Draft -> Apply Commit -> Checkpoint + Runtime Snapshot`。Commit Draft 只更新全局已保存策略版本，不产生 Checkpoint，也不改变 Runtime Snapshot；Commit 不得自动触发 Apply。Apply 只作用于当前 committed revision；若 Draft 存在未 commit 修改，Apply 应拒绝并要求先 commit 或丢弃修改。
- Commit 必须原子化。它先对 Draft 完成策略合法性校验，包括 schema / normalization / rule reference / rule-group cycle detection / v1 group nesting depth <= 3 / product-build support / entitlement / policy binding mode conflict 等控制面约束；只有全部成功后才替换当前 Committed Policy Revision，并让 Draft 回到 clean 状态。Commit 失败时不得更新 Committed Policy Revision，也不得清理 Draft 的未 commit 修改；用户仍可继续编辑或丢弃 Draft。当前 runtime capability 是否启用不属于 Commit 成败条件；stale UID binding 也不属于 Commit validation failure。例如合法且已授权的 `dpi.*` 规则可以 commit，即使当前 DPI runtime 未启用，后续 Apply / Restore 再报告为 `compile-inactive`。Commit / preflight 还必须返回 non-blocking warnings，例如 duplicate match warning；warning 必须明确给出可回溯 source refs 供前端提示用户，但不得把合法策略变成 commit failure，也不要求 `confirmWarnings` / confirmation token 之类的 daemon/control-plane 二次确认状态。
- 单条 rule 是可复用实体，允许被多个 rule group 引用，也允许被某个 complete Linux UID 直接绑定。只有 complete Linux UID 直接绑定到 rule 或 rule group 时携带 `bindingMode=enforce|observe`；rule group 内部的 `group -> rule` 与 `group -> subgroup` 引用只表达结构关系，不携带 observe/enforce mode。同一 complete Linux UID 展开后若让同一个 source `ruleId` 同时获得 `enforce` 与 `observe` effective mode，则这是 policy binding mode conflict，Commit / preflight 必须失败并返回冲突的 UID、ruleId 与 direct binding refs；不得自动选择 enforce、自动选择 observe，或在 runtime 中保留两个不同 mode 的同 rule occurrence。若同一 rule 经多个路径以相同 effective mode 到达同一 subject，则允许通过，Apply 编译时必须按 complete Linux UID 生效路径展开 group graph，并在同一 subject / stage / ruleId / effective mode 维度去重，只保留一个 runtime RuleRef，避免同一 rule 因多条引用路径重复进入同一个 runtime hot view 或被扫描多次。去重不改变 ruleId、priority、source rule action 或从 direct binding 继承的 effective mode。若同一 complete Linux UID 展开后存在多个不同 source `ruleId` 拥有相同 `matchKey`，包括 action / priority 也完全相同的情况，这只是 duplicate match warning，不是 source graph conflict；Commit 可以成功，但响应必须明确提示相关 UID、matchKey、ruleIds 与 source refs。runtime 不对这些不同 ruleId 做隐藏 dedupe，最终 winner 仍只由固定 pipeline、stage、`priority desc, ruleId asc` 决定。
- rule group 也是可复用实体，允许被多个 complete Linux UID 绑定，也允许被其它 rule group 引用，受 v1 嵌套深度上限约束。Authoring / UI 可以保存并显示 package name、app label、user/profile 等辅助 metadata，但这些 metadata 不参与策略身份判断、编译去重或 hot-path key；daemon 策略生效 key 必须是 complete Linux UID，不能用 appId 或 packageName 作为 runtime identity。Apply 编译时每个 complete Linux UID subject 独立展开、独立去重、独立生成 hot views 与 `SubjectHotPathCaps`；同一个 group 被多个 complete Linux UID 使用不得造成跨 subject runtime coupling。
- complete Linux UID 当前不存在时，对应绑定标记为 stale UID binding。stale binding 是合法保存配置，不自动删除，仍保留在 Draft / Committed Policy Revision / Checkpoint 中供控制面展示和用户清理；Apply 可在 per-binding / apply status 中报告 stale，但编译时该 binding 不展开 runtime rules，不生成 hot views，不贡献 `SubjectHotPathCaps`，也不影响 packet path。
- KISS 原则下，runtime hit / diagnostics attribution 只需要输出足够稳定的回溯 ref，例如 snapshot / checkpoint identity、subject、stage、ruleId 或 ruleRefId；hot-path RuleRef 不携带完整 group path 列表。daemon control-plane 必须能基于这些 ref 与 Authoring Policy Bundle 重建完整 source chain，让前端可以追溯到 rule 本体、携带 binding mode 的直接 complete Linux UID 绑定、以及所有有效 rule group 路径。同一 rule 经多条路径到达同一 subject 时，前端应能看到完整路径集合；runtime 不需要为命中选择唯一 group 来源。
- packet hot path 只读取 Runtime Snapshot，不读取 Draft、Committed Policy Revision 或 Checkpoint。Checkpoint 里的规则 / 规则组数量和 Runtime Snapshot 里的 hot RuleRef 数量不要求一致；Runtime Snapshot 只包含当前 compile 后 active 的热路径规则。合法 compile-inactive 规则可保留在 Checkpoint 的 per-rule status 中，但 runtime plane 等价不存在。Checkpoint 不包含 Runtime Snapshot hot views、policy caches、runtime counters 或 telemetry state。
- v1 固定保留最近 5 个 Checkpoints，数量不做用户配置。每个 Checkpoint 语义上都是可独立 restore 的 Authoring Policy Bundle full snapshot，而不是依赖 diff 链的增量记录；物理持久化可以选择压缩或内容去重，但 Restore 不得依赖重放历史 diff。
- Apply 只有成功时才切换 datapath 并产生新的 Checkpoint，且必须原子化：先基于当前 Committed Policy Revision 的 Authoring Policy Bundle 完成 validation / entitlement / compile，生成 Checkpoint source snapshot 与 Runtime Snapshot，只有全部成功后才写入新 Checkpoint、更新当前 Checkpoint 选择并切换 Runtime Snapshot。Apply 失败时 Committed Policy Revision 保持当前 head，不回滚到旧 Checkpoint；失败只表示该 committed revision 当前未生效。不产生新的 Checkpoint，Runtime Snapshot 保持旧版本，packet hot path 不受影响；不得清空 runtime，不得发布部分 hot views，也不允许 hot views 与 subject caps 跨 epoch。
- Restore Checkpoint 要求 Draft 没有未 commit 修改；若工作区不干净，应拒绝 restore。Restore 不是新的 Apply：它不生成新 Checkpoint，不重新计算或覆盖 Checkpoint 中保存的 per-rule apply status。Restore 可以覆盖当前 committed-but-unapplied 的全局策略版本，但必须原子化：先确认选中 Checkpoint 的 Authoring Policy Bundle 可用于重建与其 apply-time result 一致的 Runtime Snapshot，只有成功后才把该 source snapshot 恢复为当前 Draft 与 Committed Policy Revision、更新当前 Checkpoint 选择并切换 Runtime Snapshot。Restore 成功后 `uncommitted changes=false`、`unapplied changes=false`。
- Restore 失败时，Draft、Committed Policy Revision、当前 Checkpoint 选择与 Runtime Snapshot 全部保持不变，并返回明确 restore failure；不得静默发布空策略，也不得进入半恢复状态。
- daemon 的 control-plane / persisted store 持久化 Draft、当前 Committed Policy Revision 与最近 5 个 Checkpoints。Commit 成功后 `uncommitted changes=false`；Commit 失败时 `uncommitted changes=true` 且 committed head 不变。Apply 成功后新 Checkpoint 持久化成功才淘汰超过 5 个限制的最旧 Checkpoint。Apply 成功且当前 committed revision 与当前 Checkpoint 对应时 `unapplied changes=false`；Apply 失败时不回滚 Committed Policy Revision，`unapplied changes=true`，并返回 apply errors / per-rule status。
- Packet diagnostic event 不展开高层规则图，只输出足够前端回溯的 ref。
