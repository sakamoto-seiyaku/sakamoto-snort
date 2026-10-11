# 可观测性调查综合：当前基线与需求梳理

日期：2026-09-15。性质：支持性调查及需求讨论材料，不是 ADR、最终规格、实现授权或新验收报告。

2026-09-18 讨论层次更新：用户确认个人设备定位及常态概况 / 按需详细诊断，但要求先讨论领域能力的后端归属与架构分工，不先进入 UI 流程或逐字段规格。用户倾向后端支持完整规则组 / 集合、编译与执行，前端负责编辑。最新记录见[讨论文档第 21 节](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)；旧体系的参考价值补充在[旧版调查](2026-09-15_OBSERVABILITY_LEGACY_RESEARCH.md)。

本轮用户要求先调查旧非 VPP 版本的可观测性设计来源和本地 VPP fork，分别保存报告，再结合当前主线梳理需求，之后才讨论具体实现。明确关注规则执行状态，以及接口、不同流量等维度的统计；需求范围不限于活动列表。

## 1. 证据入口与效力

| 材料 | 回答的问题 | 不能据此声称 |
| --- | --- | --- |
| [旧非 VPP 版本调查](2026-09-15_OBSERVABILITY_LEGACY_RESEARCH.md) | 为什么逐步区分流记录、统计、规则解释和性能诊断；哪些实际实现过 | 所有后来整理的设计均已落地，或旧 C++ 能力已在当前产品恢复 |
| [本地 VPP fork 调查](2026-09-15_OBSERVABILITY_VPP_FORK_RESEARCH.md) | VPP / 插件怎样产生和导出计数、session、规则和包级证据 | 网关统计就是个人终端产品所需语义，或看到 exporter 就证明端到端可靠性 |
| 本文第 2 节 | 当前 C / Android 源码真正具备的观测基础 | 已有完整可观测性产品闭环 |
| [规则引擎讨论记录](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md) | 本轮最新的完整 Rank、前后置、输入可用性、缓存及 SNI 共识 | 讨论中的通用引擎、LPI / SNI 已全部实现 |

当前仓库源码检查固定于 `e9356b1111c80ade013dc66052ba4cb28da91860`；产品 VPP 固定版本文件为 `9258530f3804a152578ce11cc7c8a1e9eab88ed0`。本轮只读源码与已有证据，没有构建、运行设备或新测量。fork 有自己的版本，不能混同。[当前主线](../current/README.md)、[VPP pin](../../src/product/vpp/pinned-vpp-revision.txt)

用户本轮明确授权调查历史设计及必要的旧实现事实；不恢复、移植或将旧 C++ 当作当前产品实现模板。正式产品仍受 ADR-0006/0007/0008 约束。[决策地图](../decisions/README.md)

## 2. 当前主线具备哪些基础

### 2.1 已存在的事实与读取能力

| 范围 | 源码观察 | 适用限制 |
| --- | --- | --- |
| 运行及策略发布状态 | typed status 包含 generation、artifact、adapter readiness、requested / active revision、snapshot identity、worker revision、apply 状态 | 能回答当前运行 / 发布身份，不等于每条规则的执行历史 |
| 策略归因 | Gate / L4 的累计 match / no-match / drop 数及最近 winner、ruleId、revision、reason 等；L4 还暴露 probes、candidate count、关联 probe key | 多数字段是整体计数或最近证据，不能推导完整 per-rule / per-app 台账 |
| Flow 事实 | owner-local FlowEntry 保存 first / last seen、包 / 字节、ORIG / REPLY 分方向累计、policy identity、winner、CT 状态及 incarnation | 当前最终值不能自动还原整条 Flow 内历次规则或事实变化 |
| 提前 DROP | `product_flow_entry_observe` 在查找 / 创建 entry 之前增加 early-drop 计数并返回 | 没有 FlowEntry、ORIG / REPLY 和正常生命周期；可见性必须考虑这类路径 |
| FlowEnd | 无包内容的原生 END 信号携带 owner / generation / incarnation，经过 consumer、terminal 和最终释放 | `product_flow_end_consume` 明确当前没有 DPI / telemetry attachments；生命周期接点不是完整导出实现 |
| 资源与故障证据 | 接收、owner 分流、completion、TUN、Flow Stack、expiry 等具备 CLI / 状态计数和有界 trace | 主要支撑工程核验，不能把日志存在等同于可查询的产品活动历史 |

源码依据：[C ABI / status](../../src/product/include/sakamoto_product_abi.h)、[VPP API](../../src/product/vpp/product_core.api)、[graph 状态类型](../../src/product/vpp/product_packet_graph.h)、[graph producer / reader](../../src/product/vpp/product_packet_graph.c) 中的 `product_packet_graph_record_l4_view_match`、`product_packet_graph_record_l4_view_no_match`、`product_packet_graph_flow_status`、[FlowEntry](../../src/product/vpp/product_flow_entry.h)、[Flow observe](../../src/product/vpp/product_flow_entry.c)、[FlowEnd consumer](../../src/product/vpp/product_flow_end.c)。

graph 的最近匹配字段还包含为 S192 验证保留相关 probe 结果的逻辑：无关背景流量的 no-match 不一定覆盖最近匹配。它是有特定解释边界的证据面，不能当作“最近每个包”的通用事件流。Flow pool 的汇总读取在控制 / CLI worker barrier 下进行，普通包只更新当前 owner 的 Flow 统计；这不证明所有现存观测计数均已采用相同布局。[graph 实现](../../src/product/vpp/product_packet_graph.c)

### 2.2 Android 留存的数据结构不等于当前 native 链路已经打通

- `BoundedActivityStore` 当前是容量有界的内存 `ArrayList`，默认 256 条；容量淘汰记录 `evictedRecords`。这不是已实现的按时间及磁盘容量保留的全历史数据库。[源码](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/BoundedActivityStore.java)
- `ProductActivityProjectionStore` 将一个选中应用的 `AppDetail` 投影保存为 properties 文件；其持久化不能证明全部应用的后台 Activity 已持续入库。[源码](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductActivityProjectionStore.java)
- `RuntimeService.ingestLatestNativeActivity` 仍向旧 vNext socket 请求 `NFQUEUE.STATUS / VPN_TUN.STATUS`，读取 `policyDropActivity / allowedFlowActivity` 的 `totalRecords + last...`，再调用 Java ingestor。本次搜索当前 `src/product/`、`crates/product-core/` 与 native bridge，没有找到对应旧 JSON producer；当前接口地图也明确旧 netstring 接口属于历史。[RuntimeService](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java)、[旧调用客户端](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlFdClient.java)、[现行接口地图](../INTERFACE_SPECIFICATION.md)
- 即使孤立看该 ingestor，它按总数推进摄取最近一条，而不是完整拉取中间全部记录；timestamp 由 Java 摄取时传入，DROP 行填写 1 包、0 字节和 `detailLossy=true`。这些不能充当完整的事件时间及字节统计。[ingestor](../../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductNativeActivityIngestor.java)

因此，本轮结论是“现有 Java 类型与投影不能证明当前 C 产品的完整活动采集闭环”，不是一次设备运行失败诊断。本轮没有启动运行时核验这些路径，也不在研究中修改它们。

### 2.3 接口与完成结果已有明确边界

Root 从 NFQUEUE 的 INDEV / OUTDEV 及 hook 取得当前包的 Linux ifindex、方向，再映射网络上下文。当前 VPN packet 的 Linux ifindex 则明确不可用，TUN attachment 的网络分类是独立上下文，不能假装它就是包的真实物理出口。[Root adapter](../../src/product/vpp/product_root_nfqueue_adapter.c)、[TUN adapter](../../src/product/vpp/product_vpn_tun_adapter.c)

Policy Verdict、Runtime Disposition、Adapter Completion 和 VPN transport outcome 已有区分。现有联合验证报告将 processing bypass、policy DROP、transport admission rejection 和 transport failure 分开计数；这些不能统一改名为“规则阻止”。`ALLOW` 和 Adapter 操作成功也不证明远端实际收到或应用请求成功。[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[联合验证的容量与结果边界](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md)、[Packet 状态](../../src/product/vpp/product_packet.h)

## 3. 比较时应保留的主要结论

1. **旧设计的模块分离来自不同问题。** 流量总览、长期事实、单次规则解释和数据面性能诊断，所需精度、时间尺度、成本及生命周期不同。不能把这些旧模块的最终名称当成“已经实现的统一平台”。详见[旧版调查](2026-09-15_OBSERVABILITY_LEGACY_RESEARCH.md)。
2. **fork 的规则统计单位不同。** `policy_sketch` 的 hit 是 session context 首次登记规则 UUID；后续统计可把 session 的 RAW 流量差值加给其中已登记的多条规则。这不能直接作为本轮“完整 Rank 的逐包赢家次数”或“该规则实际阻止字节”。此外，正常结束伪包本身也会被标为 pseudo-packet-dropped 并走 drop 节点，因此通用 node/error-drop 总数不能当作实际网络阻止数。详见[fork 调查](2026-09-15_OBSERVABILITY_VPP_FORK_RESEARCH.md)。
3. **当前产品的问题不只是增加几个字段。** 主线已有状态、归因与生命周期基础，但通用规则、识别事实、完整导出、产品存储和查询之间仍需以明确需求衔接。此处不选择新的导出协议、数据库或统计算法。
4. **本轮规则语义改变了旧统计解释。** 自动前后置只有一个逻辑赢家；缓存不能少算或另归因；后来的 LPI / SNI 可以改变后续包的赢家，却不能改写已经完成的包。可观测性必须解释这一过程，而不是用一个最终 flow verdict 覆盖全部历史。[讨论记录第 5—9、17 节](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)

| 用户问题 | 旧版调查 | fork 调查 | 当前主线的证据边界 |
| --- | --- | --- | --- |
| 接口 / 应用用了多少流量 | 旧基础 counters 没有接口维度；后来的窗口设计也不是完整接口台账 | 有 VPP 接口计数及 session / chart 聚合，计量点不同 | 有平台网络事实、包 / Flow / Adapter 计数；完整产品统计仍需定义 |
| 哪条规则起了作用 | per-packet rule stats 与 tracked explain；后续统一 mode 又有设计变化 | ACL 包命中、session UUID 命中、实际动作计数并存 | typed status 提供部分赢家与最近证据；不是全部规则历史 |
| 普通界面能看到哪些阻止尝试 | 曾依赖 Flow，后来 pre-CT 决策取消部分覆盖 | session 聚合之外有受控逐包 telemetry，但不是所有尝试的常驻明细 | 提前 DROP 不创建 Flow；完整记录导出和后台消费未由现有类型证明 |
| 数据是否保存完整 | ring 写失败、覆盖、consumer 缺口不同 | 多种 queue / Kafka / file 完成点，结束通知也可能遗漏 | 现有工程状态与 Java 有界投影不能证明完整持久 Activity |

该对照表只归纳上述三个证据范围，不作为新能力完成度或实施优先级表。

## 4. 需求面：先回答用户问题

以下是讨论用分类，不是拟建的模块清单。状态含义：**本轮明确**来自本轮用户要求或已确认规则共识；**现有产品意图**有正式产品 / 领域记录；**需细化**表示精度、覆盖或展示范围仍待本轮确认。保留某个问题不等于同意其全部高成本实现。

| 需求面 | 要回答的具体问题 | 当前依据及状态 |
| --- | --- | --- |
| 流量统计 | 哪个应用、哪个网络 / 接口，在何种时间范围内产生了多少入 / 出流量、允许 / 阻止包；当前速率如何 | 接口及不同流量统计为本轮明确；具体维度、窗口和组合需细化 |
| 规则部署状态 | 我保存 / 修改的规则是否适用于该应用；编译和发布是否成功；当前使用哪版 | 现有产品意图，已有部分 typed status；与“是否曾命中”分开 |
| 规则执行效果 | 哪条逻辑规则赢了多少次、何时生效、声明动作是什么、实际执行是什么 | 本轮明确；统一赢家及缓存归因已经确认；计数和时间口径需细化 |
| 活动与流事实 | 谁在何时访问哪里，哪些尝试被挡，哪些包通过，过程中事实或结果如何变化 | 现有产品意图；提前 DROP 无 Flow、短流无识别的情况必须纳入讨论 |
| 规则解释 / 诊断 | 为什么这次由该规则获胜；预期规则为什么没有生效；哪些输入当时不可用 | 本轮明确及旧设计目标；需要保留多少解释细节、是否只在诊断时采集需细化 |
| 识别结果与来源 | 当时知道什么协议 / SNI，何时取得；没取得是尚未完成、没有字段还是预算 / 解析原因 | 本版 LPI / SNI 范围已定；可观测状态与匹配值的映射需细化 |
| 运行与传输健康 | 连不上是规则 DROP、处理旁路、资源不足、Adapter 失败，还是 VPN transport 失败 | 现有架构约束及验证证据；展示层级需细化 |
| 观测数据质量 | 记录是否完整、是否采样 / 覆盖 / 淘汰、统计从何时开始、数据有多旧 | 旧设计和有界产品目标；具体可见程度与恢复语义需细化 |
| 性能与资源诊断 | 观测和策略分别消耗多少 CPU / 内存 / 队列 / 延迟；是否影响个人设备正常使用 | 现有 PerfMetrics 意图；常驻程度、诊断范围和预算需实证确定 |
| 本地保留与查询 | UI 关闭后仍能看到什么；何时清理；能按哪些条件查历史或导出诊断 | 现有 Product Store / Activity 意图；保留时长、容量和查询承诺未定 |

产品依据：[Android 产品计划的产品结果、后端归属及活动范围](../product/ANDROID_L4_PRODUCT_PLAN.md)、[领域可观测性术语](../../CONTEXT.md)、[本轮规则记录的可观测性要求](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)。旧文档的 Traffic Windows、Packet Diagnostics、Telemetry Plane 等名称在这里帮助追溯需求，不作为必须复建的物理组件。

## 5. “规则执行状态”需要进一步拆清

### 5.1 三类状态和一类解释

| 问题 | 应能区分的事实 | 不应混淆 |
| --- | --- | --- |
| 配置是否生效 | 已保存、适用关系、编译 / 发布结果、运行 generation 与 policy revision | UI 中启用不等于数据面已切到对应版本 |
| 规则是否决定过结果 | 对当前应用有效视图的逻辑赢家、规则来源、发生时间、统计范围 | 被索引为候选、某个子表达式成立、完整赢家是不同事实 |
| 决定产生了什么效果 | declared action、effective enforce / observe、actual verdict，以及后续独立完成结果 | observe 的声明 DROP 不是实际 DROP；策略 ALLOW 不是端到端成功 |
| 为什么会这样 | 当时输入、可用性、优先级 / 竞争关系、实际处理位置，以及可用的解释证据 | 未执行的规则不能假装已求值为 false；没有历史证据不能伪造完整回放 |

这是需求语义分解，不是增加一套规则运行状态机。已确认的统一 Rank、前后置和 effective mode 约束见[规则讨论](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)；历史 Fact Records / Explain Evidence / Shadow Evaluation 的区分见[CONTEXT](../../CONTEXT.md)。

### 5.2 计数需要表达确定的单位

- “规则命中 100 次”应明确数的是赢得 100 个包，还是出现在 100 个 Flow；本轮已接受的是逻辑赢家统一归因，不能直接继承 fork 的 session hit 定义。
- 正常匹配和决策缓存命中应按同一产品语义归因。索引片段、OR 分支、factor 半命中不各算一条用户规则。[已确认缓存约束](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)
- 零次获胜不能解释为“从未执行”或“规则无效”：可能没有相应流量、输入不可用，或有更高优先级赢家。要具体解释哪个原因，必须有相应证据。
- 多个应用引用同一规则时，需要明确展示单应用效果还是汇总效果；同源去重不能造成重复计数。是否提供全量交叉维度仍未决定。
- 规则编辑、删除、重新发布、运行重启后，累计从哪里继续、历史归属哪个版本需要明确；不能用最新规则文本解释旧版动作。

计数维度、计数重置和历史规则快照的具体保存办法留待实现讨论。这里不要求运行时为每个未获胜规则执行额外完整匹配，也不引入第二套 shadow 引擎。

## 6. 流量统计必须先定口径

### 6.1 “接口”与“方向”

需要分别讨论物理 / 平台网络接口、捕获接口 / Adapter、VPP 内部接口三种对象。NFQUEUE queue、worker 和 FlowOwner 是处理位置，不是用户应用正在使用的物理网络。VPN 已知网络分类也不等同于逐包物理 ifindex。[当前 Adapter 事实](#23-接口与完成结果已有明确边界)

in / out 相对设备，ORIG / REPLY 相对首次创建 Flow 的方向，两者不能互换。提前 DROP 无 Flow 时，仍可有设备方向，但不能伪造 ORIG / REPLY。[本轮方向共识](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)

### 6.2 “包 / 字节 / 流量”

需要为展示的每类统计回答：

1. 计量点是进入捕获、完成解析、得出策略 verdict，还是 Adapter / transport 完成。
2. 单位是原始 IP 包 / 字节、重组后的数据报、TCP 流字节、应用 payload，还是平台接口流量。
3. DROP 字节、重传、分片、重组结果和内部 END 信号怎样归类；内部 handoff、解析数据拷贝不能无意增加用户流量。
4. 未被产品捕获的系统流量是否在范围内；缺少 UID / 端口 / 接口的包如何表达，不能静默消失或猜测归属。
5. “允许流量”是否只代表策略 ALLOW；不能据此宣称已经上传 / 下载成功。

这些是需澄清的统计合同，不是已经选择了一个计量点。旧 Traffic Windows 将 blockedPackets 与 usage 区分的意图可作参考；fork 的 RAW / APP 统计和当前 C 的 `packet_length` 也各有自己的计算位置，不应直接拼成一个总数。[旧版报告](2026-09-15_OBSERVABILITY_LEGACY_RESEARCH.md)、[fork 报告](2026-09-15_OBSERVABILITY_VPP_FORK_RESEARCH.md)、[当前 Flow 观察入口](../../src/product/vpp/product_packet_graph.c)

### 6.3 时间与数据质量

- 累计、最近窗口、速率、时间线和任意历史区间是不同查询承诺。不能因为有累计 counter 就声称可以查询过去任意一分钟。
- 事件发生时间、采集时间和 UI 刷新时间需要区分。启用统计前的缺口不能补成零，重启后的新 generation 不能与旧累计直接相减。
- 每个结果应有可解释的覆盖和精度：精确计数、近似排行、有界明细、诊断样本不能共用“完整记录”的承诺。
- 累计操作的准确性与读取快照的一致性分开：多个 worker / 模块的值可能在不同时间读取或刷新，不能默认它们组成同一瞬间的事务快照。fork 的 per-worker combined counter 与 stats epoch 已展示这种区别。[fork 统计读取边界](2026-09-15_OBSERVABILITY_VPP_FORK_RESEARCH.md)
- 事件导出丢失、consumer 未连接、存储淘汰、读取过慢和源数据不可用是不同缺口。仅一个总 dropped 数未必能解释它们。

例如：一个区间计数为 100 包、活动列表只保留 3 条明细，这两项可以同时成立；不能把 3 条列表当成总量，也不能把剩余 97 包都归给最后一条规则。这个例子用于约束结果解释，不指定底层结构。

## 7. 用具体场景检查需求是否完整

以下是讨论样例，不是本轮已运行的测试或实施任务清单：

| 场景 | 需求上必须澄清的问题 |
| --- | --- |
| 静态规则在 Flow 前连续 DROP | 用户怎样看到尝试、计数和规则原因；无需创建 CT Flow 的明细能保留多少 |
| 某 TCP 已经通过若干包，随后取得 SNI 并由另一规则 DROP | 怎样解释结果变化及时间；如何避免把先前包重标为被该域名规则阻止 |
| 规则实际赢家来自决策缓存 | 计数和来源是否与完整匹配一致；是否有必要向普通用户展示缓存细节 |
| 更高优先级规则获胜，低优先级预期规则为零次 | 常驻资料能说明到哪一步；何时需要主动诊断才能确定原因 |
| 同一 Flow 中途发布新策略 | 统计 / 活动怎样关联实际 revision；旧规则已被删除时还能解释多少 |
| VPN 策略 ALLOW，protected socket / transport 失败 | 如何区分策略效果与连通性故障，避免报告成规则 DROP |
| 应用或接口暂时未知，后来取得相关事实 | 早期未知记录怎样保留来源及可用性；是否 / 如何补充展示信息而不改写旧 verdict |
| 大量不同目标使明细容量耗尽 | 哪些总量仍可信；用户能否知道明细不完整及覆盖区间 |
| UI 关闭、consumer 断开、进程崩溃或设备重启 | 采集 / 导出 / 存储各自保留什么，如何标识缺口，是否影响包处理 |
| TCP 重传、IP 分片、FlowEnd 与多 worker handoff | 哪些计数可增加、哪些只是内部处理；源层统计与应用层统计如何比较 |

## 8. 下一步讨论的收敛顺序

按 2026-09-18 的用户澄清，先参考旧体系，确定规则资产、运行事实、常态统计、历史记录、详细诊断和本机保存 / 查询各自的责任边界。第 4—7 节保留为后续核对需求覆盖和语义的材料，不作为要求用户立即逐项确认字段、计数与时间窗口的顺序。

随后才讨论常驻 / 按需边界、记录形式、聚合、导出、存储及性能方案。是否使用 VPP stat segment、ring、特定哈希 / sketch、数据库、轮询频率和容量常量，本轮均未选择；fork 中的 Kafka / PCAPNG 和旧版 shared-memory ABI 也不自动成为产品依赖。

已有产品意图要求普通 Activity 不保存包 payload、观测资源有界、UI 关闭不丢失后台能力，且 VPP 不成为产品数据库 writer。具体实现仍需适配当前 C / Rust / RuntimeService 边界，不能靠恢复旧代码解决。[产品后端与存储意图](../product/ANDROID_L4_PRODUCT_PLAN.md)

本轮没有修改正式领域 / ADR / 产品规格，没有建立第二份任务 backlog，也没有以研究报告宣称可观测性已实现。以上需求拆分供下一轮逐项确认。
