# Flow Telemetry（流记录导出层）：工作决策与原则（收口版）

更新时间：2026-04-29
状态：工作纲领收口版（用于指导后续 OpenSpec change 与接口文档同步；本文不代表已实现）
相关既有能力：`docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`、`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`、`docs/INTERFACE_SPECIFICATION.md`（vNext stream/metrics）
兼容性前提：当前尚无已发布前端应用与既有稳定 ABI，因此本阶段**不需要**为“向前兼容”保守设计；允许 breaking changes。待 spec 收口并进入发布阶段后，再把 ABI/版本化作为硬约束。

---

## 0. 背景：为什么“再加几个 metrics”不对

前端需要的 `Top destinations / Top dstPort / timeline` 等能力，本质上需要的是**可持久化/可查询的原始观测数据**，而不是 daemon 内部临时聚合出来的一组“口径不稳定、维度不全”的 counters。

当前后端的观测体系主要由两类组成：

- **Metrics（拉取式 counters）**：适合固定维度、低基数、低成本统计（例如 traffic/reasons/domainSources）。
- **Stream（订阅式事件流）**：适合深诊断与逐事件追溯，但它天然高吞吐、高带宽压力；并且目前和 `tracked` 绑定，容易把“基础可视化”误绑成“深诊断开关”。

结论：我们缺的不是“再加 Top-K 的后端接口”，而是一个明确的**Telemetry Plane（流记录导出层）**，用于把 dataplane 的关键事实以**有边界**的方式导出，让前端（或上层组件）完成存储/查询/聚合。

---

## 1. 总体模型：三个平面分离

本文把系统拆成三个平面（必须在设计上显式区分）：

1. **Dataplane（执行面 / firewall）**
   - 目标：不阻塞热路径；完成判决；只维护极少量必要的 in-memory 状态与固定维度计数器。

2. **Telemetry Plane（流记录导出层）**
   - 目标：把高基数问题（destinations/ports/timeline/规则命中解释）转化为“可消费的 record 流”。
   - 约束：导出必须 bounded；允许丢弃，但必须可解释（drop counters / 原因码）。

3. **Control Plane（配置与调试面）**
   - 目标：配置策略、开关观测细节、提供少量即时调试查询。
   - 约束：不承担长期数据存储；不要求提供高基数查询（那是 telemetry consumer 的责任）。

> 注：`STREAM.START(type=pkt|dns)` 属于 Control Plane 的调试工具；Flow Telemetry 属于 Telemetry Plane。两者可以复用 ring/drop 的实现技巧，但语义与定位必须分离。

---

## 2. 核心决策：以 “Flow/Session Record” 为观测原子，而非 per-packet event

### 2.1 为什么不用 per-packet event 做基础观测

- per-packet event 的吞吐与带宽天然不可控；一旦流量上来，只能靠丢弃，导致“看起来有数据但不可用”。
- per-packet event 更适合**短时深诊断**，而不是 cockpit 常态数据面。

### 2.2 Flow/Session Record 的目标语义

Flow Telemetry 的 record 应类似于对现有 `L4 conntrack` 的泛化：

- **创建**：首包建立一个 flow（或第一次观测到某个 flow key）。
- **状态变化**：例如 conntrack state/direction 变化、策略最终判决变化等。
- **周期导出（active timeout）**：长连接/长会话必须周期性导出累计快照，避免“只在结束时才看到数据”。
- **不活跃结束（inactive/idle timeout）**：一段时间无包则导出终结 record，并释放 entry。
- **显式结束（end detected）**：例如 TCP FIN/RST（若语义可得）触发结束导出。
- **强制结束/资源压力**：例如 telemetry disabled、resource evicted、RESETALL/session rebuild；必须导出或至少计数并可解释。

record 的消费方（前端或上层组件）基于这些 record 去计算：
- Top destinations / Top ports；
- timeline（最近拦截、最近命中规则等）；
- 规则命中次数、命中窗口、常态聚合视图；
- 任意自定义聚合（按 app、按网络、按策略源等）。

---

## 3. 原则（必须优先于接口细节锁定）

### 3.1 非阻塞与有界性（必须）

Dataplane 写 telemetry 必须满足：

- **不得阻塞 verdict**：允许 best-effort enqueue；ring/slot 不可写则丢弃。
- **内存有上限**：所有队列、ring、flow table（若新增）必须 hard cap。
- **丢弃可解释**：至少提供 dropped counters 与 drop reason（ring 覆盖/consumer absent/record too large/disabled/resource pressure 等）。

### 3.2 “事实输出”而非“解释输出”（边界清晰）

后端导出的 record 只应包含**可验证的原始事实**与必要的判决元数据：

- 原始事实：五元组/uid/userId、方向、ifaceKind/ifindex、ipVersion、proto、ports、packets/bytes、时间戳等。
- FlowRecord 判决元数据：accept/drop/default allow、reasonId、命中的 IP ruleId（若存在）。
- DnsDecisionRecord 判决元数据：blocked DNS query、domain policySource/domainRuleId（若可稳定归因）。

明确不在后端做的事情（由前端/消费层完成）：

- GEO / ASN / 目的地注释（这些是“派生数据”，并且需要外部数据源/缓存策略）。
- Top-K 计算本身（除非为了减压而做 bounded heavy-hitter 摘要，但这应是后续权衡项，不是前提）。

### 3.3 Flow Telemetry 等级必须窄而清晰

Flow Telemetry 只定义常态 records 的开关，不承载 Debug Stream 或 Summary 聚合模式：

- **Off**：不导出 Flow/DNS records，仅保留必要的低成本 counters/state。
- **Flow**：导出 `FLOW` / `DNS_DECISION` records（bounded、best-effort、可丢弃）。

`Debug` 属于 vNext Debug Stream，不是 Flow Telemetry level。`Summary` 不进入 MVP；前端需要的 Top-K/timeline/history 由 consumer 基于 records 自行计算。

> 关键：`tracked` 与 Flow Telemetry 完全解耦；tracked 只保留为 Debug Stream 降噪与更细粒度 Metrics 的门控。

### 3.4 与现有 conntrack 的关系（优先复用语义）

我们已经在仓库内实现了 userspace conntrack core；Flow Telemetry 的设计应：

- 尽量复用 conntrack 的 key/state/timeout/sweep 机制；
- 不把 conntrack 的“策略匹配语义”与“telemetry 导出语义”耦合到不可拆分；
- 保持 conntrack 热路径的 best-effort sweep/try_lock 风格（不引入全局锁、无界扫描）。

### 3.5 Export 通道形态：fixed-slot shared-memory ring + polling

在“热路径不得阻塞、允许丢弃、必须 hard cap”的约束下，Flow Telemetry 的 export 通道 SHOULD 采用：

- **数据面**：fixed-size slot overwrite shared-memory ring（固定 slot、固定容量，producer 只做 best-effort write；冲突/超限则 drop，并增加 dropped counters）。
- **控制/信令面**：vNext control/LocalSocket 用于 OPEN/CLOSE/抢占/RESETALL 等 session 事件，不承载普通 telemetry payload，也不对每条 record 做唤醒信号。

关键边界：

- export 通道 MUST 与 vNext control/stream 语义分离（避免把常态 telemetry 退化成 JSON stream）。
- producer 侧写入 MUST 避免动态分配与锁等待（实现细节在后续设计与基准测试中细化）。
- 普通 consumer 使用 polling 读取 ring；默认 `pollIntervalMs = 1000`，可由控制面配置。

#### Android consumer 可行性（Kotlin/Java；无需 NDK）

前端作为 Android app（Kotlin/Java）实现 consumer 是可行的，不要求引入 NDK：

- `android.os.SharedMemory` 可将共享内存映射为 `ByteBuffer` 并进行读写。
- `android.net.LocalSocket` 支持通过 ancillary message 传递 file descriptors（用于握手把 shared-memory fd 交给 consumer）。
- 同一条 `LocalSocket` 可承载 control/session 事件；普通 record payload 全在 shared memory，consumer 轮询读取。

> 注：consumer 的落盘、查询、索引与聚合（包括 GEO/ASN/注释）属于上层职责；后端只输出事实 record。

### 3.6 参考项目（必须明确写入，避免自研走偏）

Flow Telemetry 的“shared memory + control/signaling socket + drop semantics”总体思路，以 Perfetto 为主要参考项目：

- Perfetto buffers & dataflow（shared memory buffer + ring buffer 策略、丢包语义等）：https://perfetto.dev/docs/concepts/buffers
- Perfetto heapprofd wire protocol（shared memory buffer + signaling socket 的工程化细节）：https://perfetto.dev/docs/design-docs/heapprofd-wire-protocol
- Perfetto API/ABI（producer/service/consumer 分层与 SMB 相关约定）：https://perfetto.dev/docs/design-docs/api-and-abi

---

## 4. 命名：不要叫 “event system”，先锁定术语

为了避免和现有 `STREAM` 混淆，建议先统一术语：

- **Flow Record**：一条可被存储/查询/聚合的观测记录（可能是 create/update/end）。
- **FlowRecord kind**：`FLOW` record payload 内部的 `BEGIN / UPDATE / END` 语义；它不是三个顶层 record type。
- **Export**：从 daemon 导出 record 的动作（best-effort，允许 drop）。
- **Consumer**：接收 record 并负责持久化/查询/聚合的组件（Android 上可能落在前端/manager）。
- **Debug Stream**：现有 vNext `STREAM`（逐事件 tail）。

---

## 5. 风险与取舍（先记录，避免后续争论回滚）

- [Risk] 过早把 Top-K/注释塞回 daemon，会导致热路径开销与口径复杂度失控。
  → 本文要求“事实输出”，派生数据由 consumer 负责。

- [Risk] Flow record 仍可能量大（例如大量短流/UDP）。
  → 必须有 hard cap + drop 语义；必要时后续可引入 sampling 或更严格的 level/threshold/cap 策略，但 MVP 不把 `tracked` 作为 Flow Telemetry 过滤条件。

- [Risk] Android 前端/服务端持久化与后台运行限制。
  → 设计上必须允许“consumer 不在线时 drop”，并提供最小可用 counters 兜底；不以“永不丢”为目标。

---

## 6. 已收口问题摘要

1. Flow identity 采用 L4-first 的 `flowInstanceId`；5-tuple 只作为 key，不作为 identity。
2. 顶层 MVP record type 只有 `FLOW` 与 `DNS_DECISION`；`FLOW` 内部再区分 `BEGIN / UPDATE / END`。
3. FlowRecord 使用累计 counters（`totalPackets/totalBytes`）；窗口增量由 consumer 依据前后累计值计算。
4. 导出触发由包驱动：create、decision/CT state change、threshold、max export interval、idle/end/resource retire。
5. FlowRecord 只记录最终执行结果；Debug Stream 承担深度解释链条，不把 `wouldRuleId`/候选规则写入常态 records。
6. DNS 与 IP/flow 在常态 records 中不做 join；DNS blocked timeline 使用独立 `DnsDecisionRecord`。
7. Export 通道是单 consumer、全局 MPSC、fixed-slot overwrite shared-memory ring；普通 records 由 consumer polling 读取。
8. RESETALL 重建 telemetry session；前端必须清空本地 records 与活跃组装状态后重新 OPEN。

---

## 7. 设计收口结论

本节按 A-E 记录已经收口的设计结论，作为后续 OpenSpec change、接口文档与实现任务拆分的输入。

### A. 观测对象与语义（Flow 是什么）

1. Flow identity：采用 `flowInstanceId`（L4/会话实例）；5-tuple 只作为 key。
2. Record types：顶层 `FLOW / DNS_DECISION`；`FLOW` payload 内部使用 `BEGIN / UPDATE / END`。
3. UPDATE 口径：使用累计 snapshot；active timeout / max export interval 触发 `UPDATE`。
4. 与 L4 conntrack 的关系：L4-first；UDP/ICMPv6/OTHER 复用 conntrack 的基础 entry/timeout 语义。

#### A 段已收口结论

- 我们倾向 **L4-first**，且 Flow 模式 record **必须携带 `flowInstanceId`**；5-tuple 仅作为 key（可复用/可冲突），不作为 identity。
- `flowInstanceId` 生成采用“**分配式**”：在 telemetry flow instance 开始时一次性生成并写入 entry；若 telemetry session boundary 后复用既有 CT entry，必须开启新的 telemetry flow instance。records 中单独携带 timestamp 字段用于排序/时间线；不要求 `flowInstanceId` 可排序。
- Flow record 的导出应尽量“包驱动”：create/state-change/count-threshold/expire-retire 触发；不引入一个为了“定期上报还活着”的额外扫描线程（扫描仅作为 bounded GC/timeout 的实现细节）。
- Conntrack（状态/实例跟踪）常开；records 导出与 consumer/telemetry level 绑定（未连接 consumer 时不写 records，只计数/记录 drop reason）。
  - Flow Telemetry 是 conntrack observation consumer；只要 `level=flow` consumer active，就必须为可追踪 L4 包采集 CT state/direction，不能依赖 `iprules.enabled=1`。
  - `iprules.enabled` 只控制 IP rules policy evaluation / explainability；telemetry-only CT observation 不得改变 packet verdict。
  - 性能要求：避免在多个深层路径反复判断导出开关。倾向在每包处理的上层一次性读取 `exporter` 指针/开关并向下透传，使“是否导出”至多是**每包一次**的极薄判断。

- TCP mid-stream pickup（strict vs loose）结论：
  - 默认采用 **loose pickup**：允许未见 SYN 的 TCP 包触发“拾取已建立连接”的 tracking（更符合 Android/daemon 可能后启动的现实）。
  - 对 loose pickup 的 entry：需要配套更短的超时，并在 records 中带一个明确标记位（例如 `pickedUpMidStream=1`），以便 consumer 与策略层能区分这类 entry。
  - 提供可选配置 **strict 模式**：禁用 mid-stream pickup，把非 SYN 的“新流”视为 INVALID/不建表（用于更强硬的安全策略或调试）。

#### A2（Record types）已收口结论

- 顶层 record type 最小集合为 `FLOW` / `DNS_DECISION`。
- `FLOW` payload 内部使用 `BEGIN / UPDATE / END` 表达生命周期，不再引入额外顶层 `STATE_CHANGE` type。
- CT state/direction 变化、`decisionKey` 变化、计数阈值、max export interval 都映射为 `UPDATE`；idle timeout、TCP end detected、resource evicted、telemetry disabled 映射为 `END`。
- active timeout / max export interval 触发的是 `UPDATE`，不是 `END`。

#### A3（Raw facts completeness / 前端 Activity 缺口）新增结论

- Flow Telemetry MVP 已打通 bounded records 与真实 producer，但前端 Activity 对“理论完整的 flow telemetry 原始事实”提出了新增要求；这些要求属于 **FlowRecord raw facts completeness**，不是 Debug Stream explainability，也不是前端自行推导即可完全补齐的字段。
- 下一轮 FlowRecord 扩展采用 **直接替换现有 `FLOW` payload v1 布局**：
  - 不新增 `FLOW v2`，不保留旧 102-byte layout 兼容窗口，不双写旧/新 records。
  - daemon、native telemetry consumer、前端 consumer、OpenSpec spec 与 `docs/INTERFACE_SPECIFICATION.md` 必须同轮更新。
  - 旧 consumer 读取新 payload 的行为视为不兼容；发布前仍可这样处理，因为当前尚无稳定前端 ABI。
- Fragment / invalid / unavailable L4 不应伪造成正常 TCP/UDP/ICMP flow：
  - 对这类包使用同一 `FLOW` 顶层 record 表达 `L3_OBSERVATION` / special flow 口径。
  - 这类 records 只用于流量、方向与异常统计，不参与正常 L4 lifecycle 解释，不宣称存在可用端口或完整 L4 会话。
  - 它们仍必须遵守 telemetry best-effort、bounded、不可影响 verdict 的原则。

### B. 记录内容边界（Schema：facts 输出）

5. 必备字段清单（最小）：timestamp、五元组、方向、uid/userId、ifaceKind/ifindex、ipVersion、proto、bytes/packets、verdict。
6. 归因策略：FlowRecord 记录最终 `reasonId/ruleId`；DnsDecisionRecord 记录 DNS blocked 侧归因。
7. DNS↔IP join：常态 records 不做 join；如需深度关联，由 Debug Stream 后续独立补齐。

#### B 段已收口结论

- 常态 FlowRecord 只记录**最终执行结果**，不承载 Debug Stream 的取证字段。
  - `wouldRuleId`、would-block、候选规则、shadow/why-not 等解释链条不进入 FlowRecord，也不进入 `decisionKey`。
  - 这些能力若需要补齐，应在 vNext Debug Stream 上补齐，不在常态 records 里重复实现。

- Flow segment / UPDATE 的 `decisionKey` 采用：
  - `ctState`
  - `ctDir`
  - 显式 `verdict` / action
  - `reasonId`
  - `ruleId`（optional；仅最终执行结果有稳定 ruleId 时携带）

- `decisionKey` 变化时才表示该 flow 的执行状态段发生变化；计数增长本身不切段，只按 packets/bytes/time 阈值触发 UPDATE。

- FlowRecord 必须补齐前端无法可靠推导的 raw facts：
  - ICMP/ICMPv6：`icmpType`、`icmpCode`、`icmpId`。
  - L4 parse：`l4Status`、`portsAvailable`，明确区分“端口真为 0”“协议无端口”“解析失败/不可用”。
  - 方向：真实 packet 方向 `packetDir` / `input`，以及 flow 首包归属方向 `flowOriginDir`。
  - 时间：`firstSeenNs`、`lastSeenNs`；`timestampNs` 仍表示该 record 的导出/事件时间，END 的 `timestampNs` 不得被消费端误认为最后一包时间。
  - 结束：`endReason`，最小枚举见 D 段。
  - 判决：显式 `verdict` / `action`，`reasonId` 只解释原因，不作为 allow/block 的唯一推导源。
  - Known flags：`uidKnown`、`ifindexKnown`，避免 `uid=0` / `ifindex=0` 与真实 root / any / unknown 混淆。
  - Lifecycle flags：`pickedUpMidStream` 必须从预留状态变为可用语义，用于标记 loose pickup / incomplete lifecycle。

- `IFACE_BLOCK` 保持最高优先级 verdict，但不作为 telemetry 的旁路系统：
  - 包进入后先进入统一 Flow/CT 观测载体，再按策略优先级判定 `IFACE_BLOCK`。
  - `IFACE_BLOCK` 作为 `reasonId=IFACE_BLOCK, ruleId=null` 的最终执行结果写入 FlowRecord。
  - 这意味着 `IFACE_BLOCK` 可形成 `NEW + IFACE_BLOCK` 等 flow 段；该语义表示 daemon 观察到的 flow/attempt，不表示该连接已被允许建立。

- BLOCK/IFACE_BLOCK entry 采用一套 Flow/CT 表，不拆 deny-flow table：
  - 首包/当前段为 BLOCK（含 `IFACE_BLOCK`）时使用短 TTL。
  - 后续包如果仍为 BLOCK，则刷新 TTL 时最多刷新到 block 短 TTL。
  - 后续包如果变为 ALLOW / DEFAULT_ALLOW，则切换到正常 CT/flow 语义与正常 TTL。

- FlowRecord 的 counters 只携带累计值：
  - 使用 `totalPackets/totalBytes`，不在 record 中额外携带 since-last-export delta。
  - 新增 per-direction cumulative counters：`inPackets/inBytes` 与 `outPackets/outBytes`，用于前端 RX/TX、上/下行与方向拆分统计。
  - consumer 如需窗口增量，可基于同一 `flowInstanceId` 的前后累计值自行计算；gap 由 per-flow `recordSeq` 暴露。

- FlowRecord 只携带 `ruleId`，不携带 `rulesEpoch`、`clientRuleId` 或规则文本。
  - 前置约束：前端/控制面必须保证 `ruleId` 在可追溯历史内不被重用；规则修改若会改变历史解释，应分配新的 `ruleId`，或先执行 RESETALL 并清空 records。
  - 该约束同样适用于 Debug Stream 的规则解释语义。

- DNS 常态 records 与 packet/CT FlowRecord 是**两套 record 格式**：
  - DNS 拦截 timeline 使用独立的 `DnsDecisionRecord`（blocked-only）。
  - `DnsDecisionRecord` 可携带 bounded inline `queryName`（长度上限/截断）；不携带解析返回的 IP 明细/数量。
  - `domainRuleId` 只属于 DNS 侧 record，不进入 packet/CT FlowRecord。

- DNS 与 IP/flow 在常态 records 中不做 join：
  - FlowRecord 不携带 `domainHint`、domain name、domainRuleId 或 domain->IP 映射信息。
  - 深度调试时，DNS/IP 关联、域名规则解释、packet verdict 证据链应由 Debug Stream 自身提供完整信息；常态 records 不作为 Debug Stream 取证链条的依赖。

- Interface 归因本轮只记录 observed interface：
  - FlowRecord 继续导出观测到的 `ifindex` 与 `ifaceKindBit`，并新增 `ifindexKnown` 表明该值是否来自 netfilter attr。
  - VPN logical iface、underlay wifi/mobile 承载网络归因后置；不得在本轮用不稳定推断混入 FlowRecord 原始事实。

### C. 导出通道与 ABI（Android 可行、可演进）

8. 共享内存 ABI：header、record framing、version 字段与扩展策略。
9. Handshake/session signaling：LocalSocket 传 FD；断连/consumer 不在线时 producer 直接 drop。
10. Session 与 RESETALL：RESETALL 强制重建 telemetry session（通道断开 + 重新 handshake）；前端侧必须清库/清内存态。
11. 丢失可见性：transport-level `ticket` 检测 ring 覆盖/慢读；per-flow `recordSeq` 检测单 flow record 链条 gap。

#### C 段已收口结论

- Export 通道采用 **fixed-size slot overwrite ring**：
  - `slotBytes = 1024`
  - 默认 `ringDataBytes = 16 MiB`，即 `slotCount = 16384`
  - 一个 shared-memory ring 只有一个 consumer。
  - 单个全局 MPSC ring，多 producer 写同一个 ring。
  - 不支持跨 slot record；一条 record 超过 `slotBytes - slotHeaderBytes` 则 drop 并计入 `recordTooLarge`。

- Ring 写入模型：
  - producer 使用全局 `writeTicket.fetch_add(1)` 选择 slot：`slotIndex = ticket % slotCount`。
  - 覆盖旧 `COMMITTED` slot 是允许的；不得覆盖正在写的 `WRITING` slot。
  - 若目标 slot 正在写，则不等待、不自旋，直接 drop 并计入 `slotBusy/resourcePressure`。
  - 写成功发布后，该 record 才算成功进入 ring。

- Consumer 读取模型：
  - `TELEMETRY.OPEN` 时 consumer 从当前 `writeTicket` 开始读，只读取 OPEN 之后的新 records。
  - consumer 通过 transport-level `ticket` 发现 ring 覆盖/慢读造成的 gap。
  - per-flow `recordSeq` 保持独立：用于发现同一 `flowInstanceId` 的 record 链条 gap。

- Polling 与 consumer absent：
  - 普通 records 不做逐条唤醒；consumer 使用 polling 读取 ring（默认 `pollIntervalMs = 1000`，可配置）。
  - control/session 事件仍可通过 control path / socket 通知；普通 telemetry payload 不走通知通道。
  - consumer absent 时 producer 直接 drop，不写 ring，并计入 `consumerAbsent`，以节省热路径成本。
  - RESETALL 必须重建 telemetry session；旧 ring 作废，前端清库后重新 OPEN。

- Slot header / record payload / ABI：
  - slot header 只承载 transport/framing 元数据；`timestampNs` 放在具体 record payload 中。
  - session/ring header 承载 ABI version；普通 record 不重复携带完整 ABI version。
  - 每条 record 通过 `recordType + payloadSize` 定界；各 record payload 维护自己的 `payloadVersion`。
  - 字段演进只允许 append；旧 consumer 可根据 `payloadSize` 跳过尾部新增字段。
  - Raw facts completeness 这轮例外：允许直接替换现有 `FLOW` payload v1，旧 102-byte layout 不再视为兼容契约；替换完成后，OpenSpec spec 与 `docs/INTERFACE_SPECIFICATION.md` 必须成为唯一权威 offset 表。

- `TELEMETRY.OPEN`：
  - OPEN 请求同时设置/确认 `telemetryLevel`。
  - daemon 返回实际生效 level、`sessionId`、`abiVersion`、`slotBytes`、`slotCount`、`ringDataBytes`、`maxPayloadBytes`、`writeTicketSnapshot` 与 `sharedMemoryFd`。
  - consumer 从 `writeTicketSnapshot` 开始读取，不补读 OPEN 前的旧 records。

- 单 consumer ownership：
  - 同一时间只有一个有效 consumer。
  - 新 `TELEMETRY.OPEN` 抢占旧 session；后来者为准。
  - 被抢占的旧 session/ring 作废。

- shared memory 生命周期：
  - 每次 OPEN 新建一块 shared memory/ring，并通过 LocalSocket 传 fd。
  - CLOSE、抢占、RESETALL 或 session rebuild 后，旧 fd/ring 逻辑作废；即使旧 consumer 仍 mmap 着旧内存，也不再有合法数据语义。

- 跨语言 binary layout：
  - ABI 固定 little-endian。
  - 所有整数使用显式宽度（u8/u16/u32/u64）。
  - 以明确字段 offset 定义 wire layout，不依赖 C++ `sizeof(struct)` 或编译器 padding。
  - payload 按固定对齐规则处理（实现阶段细化 4/8 字节对齐）。
  - IP 地址固定 16 bytes；IPv4 使用前 4 bytes，其余置 0。

### D. 性能与资源上限（热路径预算）

10. Hard caps：固定 slot/ring 大小、record 最大 payload、flow table cap、触发阈值。
11. Drop 可解释性：通过 telemetry state/metrics 暴露最小 drop counters 与 last drop reason；不新增 records 类型。
12. 验收与基准：通过 consumer absent/connected、ring full/drop、RESETALL、resource pressure、IPv4/IPv6 等场景验证热路径常数开销。

#### D 段已收口结论

- Flow/CT 表 hard cap 基线：
  - 采用 `global maxFlowEntries + per-uid maxEntriesPerUid`。
  - 资源压力下不承诺复杂 LRU、多级配额或 BLOCK/IFACE_BLOCK 优先驱逐；先做 bounded sweep，仍满则拒绝创建新的 telemetry/flow entry。

- TTL 默认值与可配置性：
  - `blockTtl = 10 s`（适用于 BLOCK / IFACE_BLOCK 段；持续 BLOCK 刷新 TTL 时最多刷新到该短 TTL）。
  - `pickupTtl = 30 s`（适用于 loose mid-stream pickup entry）。
  - `invalidTtl = 1 s` 或不入表（实现阶段按热路径和解析边界再定）；若导出，则按 `L3_OBSERVATION` / special flow 口径，不伪造正常 L4 flow。
  - 正常 ALLOW TCP/UDP/ICMP/OTHER timeout 复用现有 Conntrack timeout。
  - 上述 TTL 必须经控制面分别可配置；默认值仅作为发布基线。

- 默认导出触发阈值（更保守）：
  - `bytesThreshold = 128 KiB`
  - `packetsThreshold = 128`
  - `maxExportInterval = 5 s`（包驱动检查：仅在该 flow 有包到达时评估；若距离上次导出已超过该值则导出一次 UPDATE）
  - 计数口径：CT/flow entry 内部维持**累计计数**（导出后不清零）。阈值判断使用
    `packetsSinceLastExport/bytesSinceLastExport`（由 `total - lastExportedTotal` 得出）。

- 导出 ring 的 drop 语义：
  - 写 ring 失败不得阻塞 verdict。
  - drop counters 至少区分 `flow` / `dns` records，并记录原因（例如 `ringFull`、`consumerAbsent`、`recordTooLarge`、`disabled`、`resourcePressure`）。
  - FlowRecord 的 `recordSeq` 只在“该 flow 的 record 成功写入共享内存 ring”后递增；导出尝试失败不递增 `recordSeq`。
  - `lastExportedTotalPackets/Bytes` 只在成功写入后更新；写失败时保留累计差值，避免 silent undercount。

- Ring 与 record 尺寸默认值：
  - `slotBytes = 1024`
  - `ringDataBytes = 16 MiB`
  - `slotCount = 16384`
  - `maxPayloadBytes = slotBytes - slotHeaderBytes`
  - `DnsDecisionRecord.queryNameMaxBytes = 255`
  - 上述值必须经控制面可配置；默认值仅作为发布基线。
  - FlowRecord 理论上不应超过 `maxPayloadBytes`；若超限则 drop 并计入 `recordTooLarge`。
  - DnsDecisionRecord 的 `queryName` 先按上限处理；若 record 仍超限则 drop 并计入 `recordTooLarge`。

- 资源压力下的降级原则：
  - telemetry/Flow/CT 资源压力不得阻塞 verdict，也不得把写 record 失败转化为 packet verdict 失败。
  - 表满时先做 bounded sweep / 回收 expired entries。
  - 若仍然满，可在 bounded budget 内选择已在当前 telemetry session 成功导出过 record 的 entry 做资源驱逐，并在驱逐前 best-effort 导出 `END(endReason=RESOURCE_EVICTED)`。
  - 若没有可驱逐 entry、驱逐失败或 ring write 失败，则拒绝创建新的 telemetry/flow entry，并增加 `resourcePressure` counter；已有 entry 的更新照常进行。
  - 不在本阶段承诺复杂 LRU、全表扫描、多级配额驱逐或 block-entry 优先驱逐算法；后续只有在真实压力数据证明需要时再引入。
  - 若 IP rules 需要 CT state 但当前无法提供有效 CT 状态，则按既定 fallback 暴露 `ctState=INVALID`；策略如何处理 `INVALID` 由规则本身决定。

- END reason 口径：
  - END reason 保持少而稳；细粒度资源原因放在 counters/metrics 中，不让 END reason 枚举膨胀。
  - 最小枚举：`IDLE_TIMEOUT`、`TCP_END_DETECTED`、`RESOURCE_EVICTED`、`TELEMETRY_DISABLED`。
  - active timeout / max export interval 触发的是 UPDATE，不是 END。
  - RESETALL、`TELEMETRY.CLOSE`、session rebuild 已定义为 telemetry session boundary；daemon 可在作废旧 session 前做 bounded cleanup，并对已经成功导出过 record 的 entry best-effort 写 `END(endReason=TELEMETRY_DISABLED)`。
  - `TELEMETRY_DISABLED` cleanup 的预算按 scanned buckets / scanned entries 计算；ring write 失败也消耗 scanned entry budget，不能因为成功 END 数为 0 而继续扫完整张表。
  - 不要求为每个 active flow 逐条发送 `TELEMETRY_DISABLED` END；前端仍需把 session boundary 当作截断活跃状态的硬边界。

- 热路径写 record 的预算：
  - 每包最多一次读取 exporter/config 指针并向下透传。
  - 不做动态分配、不做阻塞锁等待、不做字符串格式化/JSON、不做 DNS/domain 反查、不做全局 sequence atomic 热争用。
  - 写 ring 只能是 best-effort reserve/copy/commit；失败计数后返回。
  - entry 内 counters/metadata 更新允许使用 relaxed atomics；当前线程数量与 NFQUEUE 分配策略已经为同一 flow 的写入争用做过优化。

- 控制面参数更新语义：
  - `slotBytes`、`ringDataBytes`、ABI/version/framing 相关变更需要重建 telemetry session。
  - `telemetryLevel`、`bytesThreshold`、`packetsThreshold`、`maxExportInterval`、`blockTtl`、`pickupTtl`、`invalidTtl`、`maxFlowEntries`、`maxEntriesPerUid` 可热更新。
  - cap 降低时不要求同步清表；影响后续 create/sweep。

- 验收/benchmark 标准：
  - 采用相对目标：固定压测下，Flow Telemetry On 相比 Off 的吞吐下降目标不超过 5%-10%。
  - 若测试环境无法稳定测吞吐，则至少报告 p50/p95/p99 verdict path 延迟对比，不作为硬 fail。
  - 必须覆盖：consumer absent、consumer connected、ring full/drop、RESETALL session rebuild、resource pressure、per-flow `recordSeq` gap、IPv4/IPv6、TCP/UDP/ICMP/unknown L4/fragment/extension header、allow/default allow/block/iface block/DNS blocked record。

#### C/D 段已收口结论

- RESETALL 的硬语义：
  - RESETALL 发生时，Telemetry Plane 视为进入一个**全新 session**；要求重建 telemetry session（断开旧通道/旧 shared-memory ring，ACK 后重新 handshake 新 ring）。
  - 前端在发送 RESETALL 前，必须先停止 ingest、清空本地持久化的 records（全量删除）、并清空 in-memory 的活跃组装状态；ACK 后从新 session 重新 ingest。

- 丢失可见性（sequence）：
  - 使用 **per-flow recordSeq（u64）**：每个 `flowInstanceId` 独立维护序号。
  - producer 侧：每当“成功把一条该 flow 的 record 写入共享内存 ring”就 `recordSeq++`；不依赖 consumer 是否读取。
  - consumer 侧的组装/查询策略不在后端规范范围内；唯一要求是：当 consumer 观察到同一 `flowInstanceId` 的 `recordSeq` 跳号时，可据此判定该 flow 的 records 存在 gap。

### E. 与现有体系的关系（Stream/Metrics/控制面）

13. Stream 的定位：长期 Debug-only，用于深度取证，不服务常态 UI 观测。
14. Metrics 的定位：低基数 daemon 自检/运行态健康指标为主；前端常态 cockpit 统计由 consumer 从 records 计算。
15. 控制面开关：Flow Telemetry 只提供 `Off / Flow`，Debug Stream 与 Metrics 独立控制。

#### E 段已收口结论

- Stream：长期保留为 Debug-only 能力，不服务常态 UI 观测、timeline、Top-K 或 dashboard 数据。
- Stream 的用途是短时间深度调试/取证：排查策略是否生效、策略之间是否互相覆盖、用户自定义策略是否写错、拦截路径哪里出现异常等。
- Stream（调试）依赖 `tracked` 门控：其主要价值是降噪与减少干扰；调试场景下由上层选择性开启 tracked 来获取指定 app/对象的 per-pkt / per-dns debug trace。
- Legacy/边缘功能（例如 `IP_LEAK`）：保持冻结状态，不作为本设计需要扩展或重新解释的能力。
- Metrics：继续保留，并通过 vNext 接口允许前端查询；但其定位首先是后端自检/运行态诊断/低基数状态快照。
- Metrics 可包含 traffic/reason/rule hit/drop/resource/telemetry health 等快速计数；前端可将其作为快速状态参考，但高基数 timeline/Top-K/历史查询应以 records 为原始数据自行计算与定义口径。
- `tracked` 与 Flow Telemetry 完全解耦：tracked 不影响 FlowRecord / DnsDecisionRecord 是否产生。
- `tracked` 只影响 Debug Stream 与更细粒度 Metrics；例如 tracked app 可获得 per-pkt 处理延迟 p95/p99 等更重的性能数据。

- 控制面开关保持分离：
  - Flow Telemetry records 只提供 `Off / Flow`，没有 Debug level。
  - Debug Stream 由 `STREAM.START(type=pkt|dns, ...)` 独立控制。
  - Metrics 由 metrics 查询接口独立拉取。
  - 不引入一个同时改变 records/stream/metrics 的全局 debug 开关。

- Debug Stream 的完善属于后续独立任务：
  - 本文只确认 Debug Stream 是深度调试/取证的长期承载，不在本文定义其完整字段与实现任务。
  - Flow Telemetry 不依赖 Debug Stream；Debug Stream 也不依赖 FlowRecord 作为取证链条的一部分。
  - 后续独立任务需要补齐“策略链条证据”（explainability）字段/语义，以支持定位“规则 A 为何未生效/被覆盖”等问题。
  - 深度溯源的目标是：在 Debug 场景下尽量做到“只靠 Stream 即可还原每个 DNS 请求与每个 packet verdict 的证据链”；常态 records 不作为深度取证的必要依赖。

- Legacy / IP_LEAK / 旧 stats 边界：
  - `IP_LEAK` 已处于冻结状态，不作为本设计需要扩展或重新解释的能力。
  - 旧 stats/metrics 中明确无用或与新边界冲突的部分，后续实现阶段可以精简、冻结或标记 deprecated。
  - 有用的低基数 stats/metrics 继续作为后端状态/健康参考保留。

- 最终 record type MVP：
  - `FLOW`
  - `DNS_DECISION`
  - 不提供 `TelemetryHealthRecord` / `TelemetryStatsRecord`；records 数据库只存业务事实。
  - `FLOW` payload 内部再区分 `BEGIN / UPDATE / END`，不是三个顶层 record type。

- 最小 telemetry state（vNext state/metrics 查询）：
  - `enabled`
  - `consumerPresent`
  - `sessionId`
  - `slotBytes`
  - `slotCount`
  - `recordsWritten`
  - `recordsDropped`
  - `lastDropReason`
  - `lastError`（optional）
  - 该状态只服务 telemetry 通道健康判断，不承载业务统计，不复制 records 可计算出的数据。

- Flow Telemetry MVP 范围：
  - 包含：ring/session ABI、`FLOW` record、`DNS_DECISION` record、control params、minimal telemetry state、测试。
  - 不包含：Debug Stream explainability、前端持久化/查询库、复杂 metrics cleanup、DNS↔IP/domain join、Summary mode。
  - MVP 已于 2026-04-30 落地；前端 Activity 新需求暴露出的 raw facts completeness 属于后续 `FLOW` record 扩展，不改变 Flow Telemetry 与 Debug Stream / Metrics 的分层。

- 文档与接口同步：
  - 本文件是工作纲领；正式接口与命令/字段细节后续通过 OpenSpec change 与 `docs/INTERFACE_SPECIFICATION.md` 同步。
  - 前端仓库需要使用的接口约定，以同步后的 `docs/INTERFACE_SPECIFICATION.md` 为准。

- 后续 change 拆分与测试要求：
  - 第一个 change 应聚焦 ring/session ABI POC：先打通 shared-memory fixed-slot ring、OPEN/CLOSE/抢占、fd 传递与 polling reader，不接真实业务热路径。
  - 后续再拆 FlowRecord producer、DnsDecisionRecord producer、control/state/metrics integration。
  - Debug Stream explainability 是独立 change，不属于 Flow Telemetry MVP。
  - 每个 change 都必须包含对应单元测试与真机测试；第一步至少要有模拟前端读取 mmap 的真机通路验证。
