# SNORT-10 讨论记录

状态：工作笔记，随 SNORT-10 架构讨论更新
最后更新：2026-06-19
范围：记录讨论主题、已确认边界、待专题展开的问题；不作为实现任务队列
关联：
- Plane `SNORT-10`
- `docs/reviews/NFQUEUE_PERFORMANCE_ARCHITECTURE_REVIEW.md`
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md`

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

已同步：
- `CONTEXT.md` 已加入 `Rule execution mode`、`Rule hit counters`、`Diagnostic Focus`、`Packet Diagnostics` 等术语。
- `docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md` 已加入 packet diagnostics 与高级观测边界。

仍待专题讨论：
- DNS / Domain diagnostics：DNS stream 当前冻结，后续整理 Domain/DNS 线时重做。
- 诊断 / 尝试 / 救援恢复这些工作流如何衔接。
- IPRULES Authoring Layer：规则组、规则生效关系、checkpoint 是否由后端统一保存。
- Traffic Windows 具体数据结构与热路径更新流程。

下一轮建议从 `Traffic Windows 具体设计` 开始。

## 已形成的主边界

- `block.enabled` 是组件 / 策略 gate，不是 daemon lifecycle。
- Baseline accounting 常驻，只统计 app/device packet totals 与 original IP packet bytes。
- Traffic Windows 是普通用户可长期启用的 online 观测层，只支持 trailing windows。
- Conntrack 从普通用户默认路径剥离，作为 Stateful IPRULES、完整流观测、未来 DPI/L7、未来 FORWARD 的高级 primitive。
- IPRULES 概念上分为 Basic IPRULES 与 Stateful IPRULES。
- Hot-path capability summary 采用 64-bit primary mask + lazy secondary masks。
- Domain-IP Association 独立于 DomainPolicy，可独立 gate。
- `ip-leak` / `IP link` 旧名不再作为新架构术语；新术语为 Resolved-IP Policy。
- RDNS 降级为诊断 enrichment，不能在 packet verdict path 同步执行。
- `Host` 不应继续作为 packet verdict hot path 的核心对象。
- 当前尚未正式上架，本轮重构不为旧 stream / record / control ABI 背兼容成本；旧字段可直接删除或替换，避免为兼容旧模型增加热路径或概念复杂度。
- Packet diagnostics 的规则归因只输出可回溯 ref；无论高层 IP 规则组未来由前端还是后端管理，完整规则组 / APP 生效链条的回溯责任仍由前端完成。

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
- Packet diagnostics 与 observe / enforce 归因模型已初步收口；DNS / Domain diagnostics、救援 / 尝试工作流、未来 authoring layer 仍待专题讨论。
- 临时原则：不要在完整设计前让 Debug Stream 和 FlowRecord 互相吞并。
- 已确认业务语义先分三类：Fact Records、Explain Evidence、Shadow Evaluation。
- 诊断 / 尝试 / 救援暂不定模块名；后续需要作为工作流专题继续拆。
- Packet-side rules 需要统一的 rule execution mode：`disabled` / `enforce` / `observe`。
- `observe` 规则参与与 `enforce` 相同的扫描路径；winner 为 `observe` 时记录 observe hit，不执行 action，并按相同扫描退出点结束。
- `observe` winner 必须 short-circuit 后续规则与后续 stage；不能因为 observe 不执行 action 就继续扫描。
- 第一版保持简单：`observe` 与 `enforce` 使用同一套 winner 归因格式；差异只在 `ruleMode` 以及 action 是否真正执行。
- 如果规则命中进入 Fact Record / Flow Record，`observe` 不走单独的 shadow-hit 格式，而是携带相同的 `reasonId/ruleId` 归因，并用显式 `verdict` 表达实际结果。
- 第一版 record 字段只新增 `ruleMode`；不新增 `declaredAction` / `actionApplied`。规则声明动作由 `reasonId` 表达，实际结果由显式 `verdict` / `accepted` 表达。
- `reasonId` 跟随 winner 规则的声明动作，而不是跟随实际 verdict；例如 observe-block 命中时可以是 `verdict=allow, reasonId=IP_RULE_BLOCK, ruleMode=observe`。
- 规则自己的低成本 counters 仍然常态存在；第一版按声明 action 分桶为 `allowHits` / `blockHits`，不按 `ruleMode` 分桶。
- `blockHits` 表示 block 规则作为 winner 命中次数，不等于实际拦截次数；observe-block 命中时 `blockHits++`，但实际 `verdict=allow`。
- Rule stats 绑定到 rule 当前语义版本；第一版在 `ruleMode` / `action` / `match` 改变时直接 reset stats，不引入 rule revision 复杂度。
- record export 是同一语义的导出形态，不是第二套概念。
- Traffic Windows 只统计真实执行结果；observe-block 不增加 blocked count，按实际 allow 计入 accepted usage。
- `wouldRuleId` / `wouldDrop` 属于旧 would-match 模型；重构后的 packet-side observe 不保留这套平行字段。
- Debug Trace / Debug Stream 的逐包 explain、stages、skipped reason、rule snapshot、候选规则等宽调试面必须显式开启；它不是常态 Flow/Fact Record 的一部分，可以接受明显性能损耗。
- Packet diagnostics 的普通前端调试 scope 第一版以 app / UID 为主；不把 `duration` / `maxRecords` 暴露成普通用户需要理解的调试参数。
- 后端仍必须保留内部 bounded queue / drop 语义作为保护机制；这些 cap 是实现安全边界，不是前端产品模型。
- 旧 `tracked` 的新模型术语定为 Diagnostic Focus；配置名倾向 `diagnostics.focused`，表示某个 app / UID 被选为重诊断焦点。
- Diagnostic Focus 不等于常态观测；Baseline accounting、Traffic Windows、Flow/Fact Record 不依赖它。
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
- Packet diagnostic event 输出包大小时使用 `originalIpBytes`，与 Baseline accounting 口径一致；不沿用旧的含糊 `length` 字段，也不使用 copied prefix length。
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

### 2. Traffic Windows 具体设计

需要讨论：
- trailing windows 配置模型。
- heavy-hitter 算法与误差表达。
- per app / direction / protocol / port / remote IP 的内存布局。
- blocked packet count 与 reason/rule bucket。
- 热路径无分配、固定成本、低锁争用设计。
- 前端查询 API。

当前状态：
- 第一版只支持 `last N` trailing windows。
- remote IP Top-K 可用 approximate heavy-hitter。
- 初始方向：`displayK=10, capacity=64`。

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
- 实现可继续共用 engine / snapshot。

### 7. Conntrack / DPI 长期路线

需要讨论：
- Conntrack 作为高级 primitive 的生命周期与资源模型。
- DPI 库 vendor / pin 策略。
- DPI result 的稳定 ID、category、规则匹配方式。
- libprotoident / nDPI 这类库如何通过 adapter 隔离。
- 未来 FORWARD / hotspot gateway mode 的约束。

当前状态：
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

需要讨论：
- IP 规则组、规则、APP 生效关系、checkpoint 是否由后端统一保存。
- 如果后端保存高层配置，如何编译成 per-UID runtime ruleset。
- `clientRuleId` / source ref 如何保证前端能回溯完整规则组与 APP 生效链条。
- 后端 authoring store 与 packet datapath runtime 的边界。

当前状态：
- 暂不展开，后续专题讨论。
- 临时原则：无论高层规则图由前端还是后端保存，packet hot path 只接触编译后的 per-UID ruleset。
- Packet diagnostic event 不展开高层规则图，只输出足够前端回溯的 ref。
