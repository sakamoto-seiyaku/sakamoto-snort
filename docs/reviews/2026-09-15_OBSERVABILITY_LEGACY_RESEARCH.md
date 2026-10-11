# 非 VPP 旧版可观测性：需求来源、设计演进与实现证据

日期：2026-09-15。范围：旧 NFQUEUE/C++ daemon 的观测设计及其历史演进，供本轮**先明确需求、再讨论实现**使用。

配套：[可观测性调查汇总与需求整理](2026-09-15_OBSERVABILITY_REQUIREMENTS_REVIEW.md)。

本轮依用户明确要求，只读检查历史文档和 Git 对象；没有恢复、编译、运行、移植旧源码。ADR-0008 的产品边界不变。这里的旧算法、ABI、线程模型、计数器实现和容量值均不是当前 VPP-native C 主线的实现输入。当前主线能力需另查其生产者与实际通路，不能由本报告推定。

## 1. 调查结论

旧版的需求并不是“把规则引擎打几条日志”，而是逐渐分清了五种不同问题：**流量用了多少、规则实际上怎样执行、最近发生过什么、为什么这样执行、运行代价与观测通道是否健康**。它们分别推动了 counters、Flow Telemetry、Debug Explain、Traffic Windows 与 PerfMetrics 的设计。高基数历史查询与用户界面持久化被交给 consumer，没有继续塞进 daemon 的即时 metrics 接口。[D1 §0–3、§E；D2 §1、§2、§9]

必须把两个年代拆开：

- **2026 年 3–6 月的真实旧 daemon**已有固定维度 traffic/reason metrics、per-rule stats、tracked Debug Stream、shared-memory Flow Telemetry、bool PerfMetrics；有历史测试记录与部分具体结果。
- **6 月 20 日 SNORT-10 的收口设计**明确了独立 Traffic Windows、session-owned Packet Diagnostics、统一 observe/enforce winner、Perf off/basic/detail/profiling，以及 Base-before-CT 的阻止行为。这些并不等于上述旧 daemon 已经全部实现；该日重建主线时，旧 producer 被整体归档，待各 owning slice 重新引入。[H1、H2、H7]

对本轮最有影响的反转是：**4–5 月实现会把 IFACE_BLOCK 阻止尝试放进统一 Flow 观测；6 月设计决定这些包在 CT 前结束，不再生成正常 FLOW record。** 后者仅以 reason metrics、Traffic Windows blockedPackets 与显式 Packet Diagnostics 补足可见性。因此旧版“Flow record 可做阻止时间线”的证明，不能覆盖当前“前置 DROP 没有 Flow”的全部用户需求。[H2 `PacketManager.hpp:452–490`；D1 A/B；D2 §1–2]

## 2. 证据边界与版本身份

文中 `[D…]` 是现存文档，`[H…]` 是只读 Git 历史证据。现存决策文件经过多次更新，须结合其明确标注的年代阅读。尤其不能把 `FLOW_TELEMETRY_WORKING_DECISIONS.md` 的“已落地”标题理解成当前 C/VPP 已实现。

H3–H5 的 OpenSpec 材料仅用于追溯当时的需求、实施声明与验收记录，没有当前规范效力，也不恢复 OpenSpec 工作流。

| 标记 | 证据与用途 |
| --- | --- |
| D1 | [Flow Telemetry 工作决策](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)，4 月起源与 6 月覆盖说明；需求、边界、后续 raw facts 变更 |
| D2 | [SNORT-10 讨论记录](SNORT_10_DISCUSSION_NOTES.md)，§1 Observability、§2 Traffic Windows、§9 PerfMetrics、§10 Authoring Layer；设计收口证据 |
| D3 | [旧版接口规范存档](../archived/pre-vpp/INTERFACE_SPECIFICATION.md)，§2.8；描述 SNORT-10 目标接口，不单独证明 producer 实现 |
| D4 | [2026-06-16 NFQUEUE 性能与架构审计](NFQUEUE_PERFORMANCE_ARCHITECTURE_REVIEW.md)，静态审计与问题背景；该文明确未执行真机 benchmark |
| D5 | [历史性能测试记录](../testing/PERFORMANCE_TEST_RECORD.md)，3 月 16 日与 4 月 24 日的执行记录及限制 |
| D6 | [当前接口导航](../INTERFACE_SPECIFICATION.md)，明确旧 v3.10 daemon 接口整体归档；[Android 产品计划](../product/ANDROID_L4_PRODUCT_PLAN.md) §3 的 consumer/store owner 仅作后来产品边界说明 |
| H1 | Git 提交演进：`6642b78`、`5c5b7b5`、`e321544`、`a399c64`、`57bb862`、`df9d239`、`0122570`、`85ace47`、`6239ccb`、`7c44e34`、`52dc093`；提交日期/变更内容证据 |
| H2 | 删除前历史对象 `969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/`；归档的旧 daemon 实现，重点文件见下表 |
| H3 | `df9d2392feebdfcc194aacc3167f147aef134045:openspec/changes/archive/2026-04-30-add-flow-telemetry-plane/tasks.md`；历史完成记录，含具体 device/ASAN/UBSAN/perf 结果 |
| H4 | `85ace471cfbae146f43d66cef3e4d0ad113fa1b6:openspec/changes/archive/2026-05-04-add-flow-telemetry-raw-facts-completeness/{proposal.md,tasks.md}`；Activity 需求来源、变更范围、打勾的验收记录 |
| H5 | `0122570a92801decce1d50004eb227e5b9b10fb1:openspec/changes/archive/2026-04-30-add-debug-stream-explainability/tasks.md`；Debug Explain 历史实施/验收记录 |
| H6 | `969b19be…:tests/host/{flow_telemetry_ring_tests.cpp,flow_telemetry_records_tests.cpp,conntrack_tests.cpp,control_vnext_telemetry_surface_tests.cpp}` 与 `tests/device/ip/cases/18_flow_telemetry_smoke.sh`；断言存在与覆盖范围，单凭源码不代表本轮执行通过 |
| H7 | `52dc093:archive/current-head/README.md`，2026-06-20 归档说明；旧 runtime/CT/Flow Telemetry producer 不再属于当时新主线默认构建 |

历史源码定位表，路径均相对于 H2 的 `archive/current-head/src/`：

| 文件 / 入口 | 可核查事实 |
| --- | --- |
| `TrafficCounters.hpp::observePacket/observeDns`；`ControlVNextSessionCommandsMetrics.cpp::handleMetricsCommand` | 固定五维 traffic、按 app 查询与 device 求和、reset、各 metric 名称 |
| `PacketListener.cpp::callback`，特别是 434–506 行；`PacketManager.hpp::make` | 旧 block gate、实际 verdict 后计数、IFACE_BLOCK 的 Flow 观测、tracked 与 would 路径 |
| `IpRulesEngine.cpp` 2658–2698、2824–2845 行 | cache hit 保留 ruleId/stats；enforce 与 would 的独立计数入口 |
| `FlowTelemetry.hpp::Config/HealthSnapshot/HotPath`；`FlowTelemetry.cpp::open/close/exportRecordHot` | owner、single consumer、配置、共享内存、health 计数含义 |
| `FlowTelemetryRing.cpp::tryWrite` | 全局 ticket、允许覆盖 committed slot、busy/oversize 失败、成功 publish |
| `FlowTelemetryRecords.hpp::FlowV1Fields`，70–166 行 | 5 月后实际 160-byte FLOW 布局，不含后来增加的 ruleMode |
| `Conntrack.cpp::observeFlowTelemetry`，3182–3367 行及 IPv6 对称路径 | blocked attempts 累计、导出触发、成功后推进 sequence 和已导出累计量 |
| `ControlVNextStreamManager.cpp::observePktTracked/pushPending` 及 ring/replay/session 方法 | tracked event 的 replay/pending 生命周期、suppressed/drop notice |
| `PerfMetrics.hpp::setEnabled/reset/snapshotForControl` | bool gate、16 shards、atomic histogram、关闭时返回零形状 |

复核命令示例（只输出历史对象，不恢复文件）：

```sh
rtk proxy git show 969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/PacketManager.hpp
rtk proxy git show df9d2392feebdfcc194aacc3167f147aef134045:openspec/changes/archive/2026-04-30-add-flow-telemetry-plane/tasks.md
rtk proxy git log --all --since=2026-03-01 --until=2026-07-01 --format='%h %as %s' -- src archive/current-head
```

## 3. 设计是怎样长出来的

| 时间 | 需求 / 发现的问题 | 当时的回应及证据等级 |
| --- | --- | --- |
| 2026-03-15 | 知道 daemon verdict 代价及最终阻止原因 | `6642b78` 加 PerfMetrics；`5c5b7b5` 加 reason metrics 与 packet stream schema。真实实现，有 3/16 真机记录。[H1；D5] |
| 2026-03-16 | 具体 IP 规则是否命中、执行还是 would-match | `e321544` 的 IPRULES 和 per-rule runtime stats；随后 cache/端口/CT 修复持续影响归因正确性。[H1；H2] |
| 2026-04-22 | 用一致的 control surface 读取状态与消费事件 | `a399c64` vNext metrics、`57bb862` vNext stream。真实 `METRICS.GET(traffic)` 与 tracked stream。[H1；H2] |
| 2026-04-29/30 | 前端需要 Top destinations、Top ports、timeline；临时 counters 维度不足，per-packet stream 吞吐太大 | 确立 Dataplane / Telemetry / Control 三个平面；`df9d239` 实现 Flow Telemetry bounded records。设计文档把 Perfetto 作为 shared-memory + control socket 思路的主要参考，但没有证据说明移植了 Perfetto 实现。[D1 §0–3；H3] |
| 2026-04-30 | 用户需要解释命中、未命中、优先级覆盖和 gate 短路 | `0122570` 增加 tracked packet/DNS explain，包括 inputs、final、ordered stages、候选与规则快照；继续与常态 Flow records 分离。[H5] |
| 2026-05-04 | Activity 页无法从 102-byte Flow payload 可靠还原端口是否可用、方向、ICMP、最后一包时间与结束原因 | `85ace47` 原地替换 FLOW v1，补 raw facts、方向累计量和 L3_OBSERVATION；没有通过 Debug Stream 或前端猜测补字段。[H4；H2 `FlowTelemetryRecords.hpp`] |
| 2026-05-11 / 06-02 | 同流并发导出会出现累计量回退；Android 共享内存实现需修正 | `6239ccb` 修复 counter rollback 并加回归测试；`7c44e34` 使用 Android shared memory。说明“API 已有”之后仍需数据一致性与设备通路验证。[H1；H6] |
| 2026-06-16—20 | 手机常态成本、tracked 无 subscriber 仍工作、CT 与观测互相拉起、用户统计与重诊断混杂 | 审计提出模块边界问题；SNORT-10 将 Traffic Windows、Packet Diagnostics、Perf tiers 收口，改成 Base-before-CT，并统一 observe/enforce。属于后一代设计，不能把上阶段通过记录搬来证明。[D4；D2；H7] |

这条演进同时包含两次需求校正：第一次承认**常态历史需要可持久化的原始事实**；第二次承认**普通流量概览不能要求开启完整 Flow/CT 观测，也不能依赖显式诊断**。[D1 §0、A；D2 §2]

## 4. 各类观测实际回答什么

| 问题 | 3–6 月真实实现 | 6 月 SNORT-10 设计 | 仍不能据此推定的内容 |
| --- | --- | --- | --- |
| 某 app / device 允许、阻止了多少 | traffic 为 `dns/rxp/rxb/txp/txb × allow/block`，低基数累计 counters；device 通过 app 求和 | Traffic Windows，app/device、in/out、acceptedPackets/acceptedBytes/blockedPackets | 任意历史时间范围、全部物理接口的准确用量、全部系统流量覆盖 |
| 具体规则执行状态 | IP enforce `hitPackets/hitBytes/lastHitTsNs`，另有 would stats；reason metrics 表示最终原因 | 同一 winner + `ruleMode`；rule counters 按声明 allow/block 分桶，Traffic Windows 按实际结果 | 命中次数等于实际阻止次数；零命中就等于规则未安装 |
| 最近发生什么、去向排行 | consumer 从 FLOW/DNS_DECISION records 做派生查询；daemon 无完整历史库 | Traffic Windows 服务普通窗口，Flow records 服务更高基数事实 | UI 有数据就等于 daemon 数据完整；Flow 覆盖所有被阻止尝试 |
| 为什么命中、为什么没执行后续规则 | tracked Debug Explain stages/candidates/snapshots，有有界 replay | active session 持有单 UID Diagnostic Focus，只输出订阅后的 Packet Diagnostics | 常态每个事件都有完整 explain；无诊断 session 也保存过往解释 |
| daemon 慢在哪里、队列是否异常 | bool PerfMetrics：NFQUEUE callback 到 verdict 返回及 DNS decision histogram | 默认 sampled basic；detail 更密采样；profiling 才记录内部 stage；附 NFQUEUE health | 用户网络 RTT、kernel queue wait、完整网络端到端时延 |
| 记录是否完整、系统是否保留了它 | exporter health、transport ticket、flow recordSeq、session boundary | 保持 loss 与 bounded export 原则 | recordsDropped 是全部观测丢失量；记录保留等于持久化成功 |

依据：[H2]、[D1]、[D2]、[D3]。以上是语义对照，不是本轮选择的模块清单。

### 4.1 普通统计与“各接口 / 不同流量”的实际范围

旧 `TrafficCounters` 没有接口维度，也没有时间窗口、remote IP、port 排行；五个维度是 DNS decision 次数、入站包/字节、出站包/字节。旧 rule key、FlowRecord、packet explain 虽携带 `ifaceKind/ifindex`，**携带接口事实不等于已经有稳定的接口统计产品**。[H2 `TrafficCounters.hpp`、`ControlVNextSessionCommandsMetrics.cpp`、`FlowTelemetryRecords.hpp`]

旧 callback 仅在 `blockEnabled` 为真且通过 control-traffic 例外后进入 `PacketManager::make`。因此那套 per-app traffic/reason/Flow 更新不覆盖 gate 关闭时经过 callback 的所有包。SNORT-10 明确要求 Traffic Windows 独立于 `block.enabled/iprules.enabled`，就是对这种耦合的修正。[H2 `PacketListener.cpp:443`；D2 §2]

字节口径也发生了修正：旧 `make` 接收的 `payloadLen` 来自 `NFQA_PAYLOAD`，即当时 copy 到用户态的 IP packet 长度；它不能在改成 bounded prefix copy 后继续代表 original packet bytes。SNORT-10 要求使用 IPv4 total length 或 IPv6 payload length + 40；无法可靠取得时不更新窗口。这个变化不是字段改名，它决定统计到底测量什么。[H2 `PacketListener.cpp:233,257,504–506`；D2 §2；D4 bounded-copy 讨论]

6 月 Traffic Windows 明确的设计边界：

- 同一 device 配置 1–4 个 trailing windows，默认 15m/1h/5h/24h；60 秒 bucket、monotonic time、`coveredSec` 表示当前覆盖，不是自然日计费账单。
- app key 是 complete Linux UID；每包在最终 verdict 后对 device 与 app 各更新一次，独立于 CT、Flow Telemetry consumer 和 Diagnostic Focus。
- accepted traffic 可有 remote IP、IP protocol、protocol + remote port Top-K；排行可近似，非审计级。blocked 只有 app/window/direction 总 `blockedPackets`，没有 blockedBytes 或 reason/rule/remoteIP/port 分解。
- `APPS` 是 accepted usage ranking，blocked-only app 不上榜；这不能替代完整 app inventory 或被阻止应用列表。
- 配置持久化、窗口状态不持久化；reset、daemon restart、有效配置变更会重开 epoch。普通 policy 变更不清窗口，保留当时实际结果。
- 该第一版定义没有把 `ifaceKind/ifindex` 加成 Traffic Windows 查询维度，也明确不迁入旧 `traffic.dns`。[D2 §2；D3 §2.8]

这些旧边界帮助识别本轮用户所说“各种接口、不同流量统计”仍需精确化的部分：所指的是包入口/出口、underlay 网络、网络类型，还是网络上下文；是 accepted usage、blocked attempts，还是转发/传输成功量。历史材料不能替用户决定这些需求。

### 4.2 “规则执行状态”至少有四种不同含义

| 状态 | 历史明确区分的事实 | 混为一谈的后果 |
| --- | --- | --- |
| 配置是否生效 | source rule enabled/disabled、commit/apply/runtime snapshot、per-rule apply status；SNORT-10 中 disabled 属于 source/apply 状态 | UI 保存成功被当成 dataplane 已生效 |
| 本包是否评估到该 stage | enabled/evaluated/skipped、short-circuited、noConsumer、facts unavailable | 零命中无法区分规则未被走到、输入不足、条件不匹配 |
| 哪条逻辑规则赢了 | ruleId/source ref、priority、winner、mode；候选或内部缓存不是第二条规则 | cache 命中被误算成没执行规则，或解释来源丢失 |
| 最终实际做了什么 | explicit verdict/accepted 与 reason；source declared action 单独解释 | observe-block 的 rule hit 被展示成真的阻止 |

来源：[D2 §1、§10]；这些是后代需求语言，不能说 4 月旧 source 都已经按此实现。

旧实现实际存在的是 `ALLOW/BLOCK/WOULD_BLOCK`：enforce winner 调用 `observeEnforceHit`；would winner 只有最终 ACCEPT 时才调用 `observeWouldHitIfAccepted`，输出 `wouldRuleId` overlay。它与后来“observe 和 enforce 同一扫描路径，observe winner 也 short-circuit”的语义不同。[H2 `IpRulesEngine.cpp:2824–2845`、`PacketManager.hpp:649,733–737`；D2 §1]

缓存归因已被旧实现认真处理：exact cache entry 保存 decision kind、ruleId、stats 指针；cache hit 仍回到共同的 hit-accounting 入口，因此 per-rule hits 统计的是包上的 winner 结果，而不是仅 classifier 真正扫描的次数。其 snapshot/epoch 与 lifetime 处理属于旧实现证据，不能直接采用为 VPP 方案。[H2 `IpRulesEngine.cpp:2658–2698`、`IpRulesEngine.hpp::Decision`]

SNORT-10 另规定：`allowHits/blockHits` 按规则声明 action 分桶；observe-block winner 也增加 blockHits，但实际 verdict 为 allow，Traffic Windows 不增加 blockedPackets。rule action/match 或 bindingMode 改变时 reset 受影响 stats。**“规则命中计数”与“实际阻止计数”从定义上不是同一个量。** 实际 160-byte 旧 FLOW source 没有 `ruleMode` 字段，D3 中带 ruleMode 的布局属于后续契约。[D2 §1；H2 `FlowTelemetryRecords.hpp::FlowV1Fields`]

### 4.3 常态事实与逐包解释

Flow Telemetry 的原始动机是让上层有足够事实做 Activity 与历史，而非让 daemon 维护任意 Top-K。它定义 `flowInstanceId` 而不是把五元组当永久 identity，使用 BEGIN/UPDATE/END 与累计 packets/bytes；长流按包驱动检查阈值与最长导出间隔。consumer 用前后累计差值计算窗口增量。[D1 §2、§6、A/D；H2 `Conntrack.cpp::observeFlowTelemetry`]

5 月补全后的真实字段包括 packet direction、flow origin direction、first/lastSeen、export timestamp、explicit verdict、ICMP、portsAvailable、l4Status、UID/ifindex known flags、midstream pickup、方向累计量与 END reason。fragment/invalid L4 用 L3_OBSERVATION，不伪造普通 TCP/UDP lifecycle。DNS_DECISION 是 blocked-only 独立 record，不与 FLOW 自动 join，不包含完整 DNS response IP 关系。[H4；H2 `FlowTelemetryRecords.hpp`]

这解决了“前端猜不出的事实”问题，但仍然是累计快照：丢了中间 record 时，后来累计值可能挽回总量，不能据此重建丢失区间内的准确时间分布、每次规则切换顺序或完整解释链。最后记录也丢失时，尾部用量同样无法由前端凭空恢复。这个限制是由累计快照与 best-effort 导出推得，不是历史测试已证明“永不丢失”。[D1 A/D；H2 `Conntrack.cpp` 成功导出更新规则]

旧 Debug Explain 解决的是另一类问题：packet/DNS 的 inputs、final、stages、skip reasons、候选规则和规则快照。实际旧版本以持久 `tracked` 为 gate，仍有 bounded prebuffer/replay；每 stage 候选上限 64，保留 winner，返回 truncation 标记。6 月重新决定由 active diagnostic consumer 持有单 UID focus，无订阅不构造重解释、没有先缓存后消费的 replay，去除 suppressed notice，保留 dropped/stopped，候选输出也不再沿用旧逐 stage 数量裁剪。**不能把两代 diagnostics 特征拼成一个从未存在过的完整实现。**[H5；H2 `ControlVNextStreamManager.cpp`；D2 §1]

### 4.4 导出、丢失、消费与保留是不同边界

真实旧 exporter 同时只允许一个 consumer，OPEN 新建 shared memory，后来的 OPEN 抢占旧 session，CLOSE/detach/RESETALL 作废旧 ring。普通 records 走 mmap polling，Unix control socket 负责 fd handoff 与 session；TCP/adb-forward 不具备 fd passing。owner 由 control session key 约束。热路径读取一次 exporter/session view，写失败不改变 verdict。[H2 `FlowTelemetry.hpp/.cpp`；H3]

真实 ring 允许覆盖已 COMMITTED 的 slot，拒绝正在 WRITING 的 slot；ticket 分配发生在 payload-size 检查之前。因此需分清：

| 量 / 事件 | 精确含义 | 不代表什么 |
| --- | --- | --- |
| `recordsWritten` | producer 成功 publish 的 records | consumer 已读取、UI 已显示、store 已落盘 |
| `recordsDropped` / `lastDropReason` | exporter 被调用后遇到的 absent、busy、oversize、pressure 等失败；实现是总量 + 最后原因 | 所有被覆盖未读 records 的总数；每原因完整分布；Flow/DNS 各自丢失分布 |
| transport ticket gap | consumer 没有取得某些 ticket 对应的位置；可能涉及写失败、覆盖、慢读 | 必然等量的业务流丢失 |
| per-flow `recordSeq` gap | 已成功写出的同流序列，consumer 没读全 | producer 每次导出尝试失败都有 gap；失败不会递增 recordSeq |
| 未连接 consumer | packet producer 发现 hotPath absent 后直接跳过 flow 观测 | `consumerAbsent` 自动计入全部没记录的包/尝试；该 counter 只有进入 export 失败入口才增长 |
| END 或 session boundary | 生命周期终结/截断信息；cleanup 为 bounded best-effort | 所有活跃流必有 END；旧 ring 可继续作为完整事实源 |

上述差别可以直接从 `FlowTelemetryRing::tryWrite`、`FlowTelemetry::exportRecordHot`、`PacketManager::make` 的 `telemetryActive` gate、`Conntrack::observeFlowTelemetry` 的成功更新分支复核。[H2]

历史设计提出更丰富的 loss reason 与 flow/dns 区分，但实际 `HealthSnapshot` 的公开形状只有总 `recordsWritten/recordsDropped` 与 `lastDropReason`。ring 覆盖 COMMITTED 被当作成功写，不增加 exporter drop。故“有 drop counter”不能直接推出“用户能准确知道全部缺失记录数量”。[D1 D/E；H2 `FlowTelemetry.hpp::HealthSnapshot`、`FlowTelemetryRing.cpp::tryWrite`]

consumer 持久化、查询、GEO/ASN、派生排行从 Flow Telemetry MVP 起就明确排除在 daemon 范围之外；RESETALL 时停止 ingest、清本地记录和活跃组装再重新 OPEN 是**消费端契约**，本仓库 native smoke reader 的存在不证明完整 Android store 已实现此生命周期。后来产品计划把 consumer 和单 writer 放在 RuntimeService 普通 app 身份，按 age/storage budget 有界保留，这是产品意图的进一步明确，不能倒推为 4 月 MVP 的落地结果。[D1 §3.2、§3.5、D/E；D6]

### 4.5 PerfMetrics 的范围为何独立

旧 PerfMetrics 默认关闭，开启后采每个经过计时路径的样本，输出 NFQUEUE callback 开始至 sendVerdict 返回的 `nfq_total_us` 和 `dns_decision_us`。16 shards 仍使用 atomic sample/sum/bucket/min/max；p50/p95/p99 是 bucket 上界，不是精确分位数。它测不到进入 callback 前的 kernel queue wait/copy，也不等于 app RTT。[H2 `PerfMetrics.hpp`、`PacketListener.cpp`；D5]

6 月设计将默认层改为 sampled basic（默认 period=1024，先决定采样再读时钟），明确 eligible/sample counters 和 epoch；detail 增加总延迟采样，内部 stage breakdown 只属于 profiling。NFQUEUE queue depth/drop/recv/verdict error/skew 是另一类运行健康信号。设计动因是**观测本身也占热路径成本，默认层又必须能发现明显退化**，而非让一个全局 debug 开关同时打开所有观察手段。[D2 §9；D4]

这套 NFQUEUE-specific latency 与 queue health 不能直接作为 VPP 指标定义。这里保留的是“说明测量起止边界、采样覆盖、观察开销”的历史需求，具体 VPP 埋点不在本调查决策范围。

## 5. 前置 DROP 的历史反转与实际空白

4 月 MVP 任务 `4.5` 明确写入“IFACE_BLOCK / IP BLOCK attempts 进入统一 flow table，使用 blockTtlMs，不建第二张 deny-flow 表”；5 月 raw facts `4.4` 延续这项行为。删除前归档 source 中 IFACE_BLOCK 分支确实在计数后执行 CT inspection 并调用 Flow Telemetry，Conntrack 累计 blocked attempts，并缩短 blocked segment 的 expiry。[H3；H4；H2]

6 月 SNORT-10 则明确要求：IFACE_BLOCK / Basic enforce block 在 CT 前结束，即使 consumer active 也不创建正常 Flow record。为了不让观察阻止尝试强制产生 CT 成本，旧“全都变成 Flow”的覆盖方式被撤销。[D1 开头覆盖说明、A/B；D2 §1]

当时留给 blocked visibility 的三种手段各有限制：

- reason metrics 给低基数最终原因计数，没有目的地/完整时间线。
- Traffic Windows 给 app/window/direction 的 blockedPackets，没有按规则、目的地、端口分解；blocked-only app 还不进入 accepted usage 排行。
- Packet Diagnostics 能解释具体尝试，但必须先由用户开启对应 UID session，没有日常历史回放。[D1 A/B；D2 §1–2；D3 §2.8]

所以，**旧 SNORT-10 设计并没有仅凭这三者就证明“无诊断时也能看到每次前置阻止尝试的应用、目的地、规则、时间”已经闭环。** 这是本轮需要精确确认的用户任务与覆盖要求，尚不意味着选择 deny-flow、packet event、聚合桶或任何新的实现方案。

## 6. 实现与验收证据分级

| 能力 | 实现证据 | 已记录验证 | 本轮能得出的结论 |
| --- | --- | --- | --- |
| bool PerfMetrics | 旧源码、控制面、callback 计时 | D5 3/16：关时零、开时 samples 增长、幂等设置不清零、非法参数拒绝；有 JSON 样例 | 旧环境通路测过；该记录不是 VPP performance evidence |
| Flow ring / session / records MVP | `df9d239` 的 encoder、ring、producer、Unix fd handoff、native consumer | H3 记 ASAN/UBSAN 各 214/214，device FLOW matrix、blocked-only DNS、tiny-ring recordSeq gap | 有具体历史完成记录与断言；本轮没有重新运行，也没有重新核验全部原始测试产物 |
| Flow Off/On 成本 | device 比较脚本和 H3 数值 | H3 记两组完成 20,000,000 bytes，`drop_pct=0.00`；off p50/p95/p99 79/479/1151µs，on 87/479/959µs | 一次旧场景证据；不能当作所有流量下固定开销，不能证明 VPP/电耗/常态长测预算 |
| raw facts completeness | `85ace47` 明确 160-byte FLOW 及真实 producer | H4 任务记录 host、sanitizer、device、Off/On 项均勾选；没有像 H3 一样列出具体结果数值 | 证据强度低于完整原始日志；字段与断言存在可独立确认 |
| 同流累计量单调 | `6239ccb` 修复；`FlowTelemetryConcurrentSameFlowExportsDoNotRollBackCounters` | H6 有并发同流与序列/累计量断言 | 有回归用例，表明数据一致性曾出实际问题；未在本轮执行 |
| tracked Debug Explain | `0122570` source + JSON tests + device smoke | H5 所列 host/sanitizers/device 验收打勾；stage/candidate/truncation 断言可查 | 证明旧 tracked 模型，有别于 session-owned Packet Diagnostics |
| Traffic Windows、统一 observe-mode、Perf tiers、session-owned Packet Diagnostics | D2/D3 完整收口契约；H7 同日归档旧 runtime | 本调查没有找到上述整套能力在旧归档 producer 中实现和配套通过记录 | 应标“历史设计收口”，不能写“旧版已完整实现” |
| 长期 Activity consumer/store | D1 明确 consumer 职责及 MVP 排除项 | daemon 本仓库的 native mmap reader smoke，不是全产品 store 验收 | 不能据此认定后台消费、存储、retention、查询完整闭环 |

另外，D5 4/24 记录 DNS hook 未活跃时 DNS 采样断言会 SKIP；大 ruleset perf 遇到 `IPRULES.APPLY` transport failure 为 BLOCKED。跳过和阻塞不是测试通过，不应把“有测试入口”写成“所有场景验证完成”。

## 7. 给下一轮需求讨论的准确输入

本轮可以从历史中保留这些问题，不提前承诺其实现形态：

1. **解释规则状态要到哪一层？** 用户是否需要区分保存/应用、stage 是否评估、winner、声明动作、实际 verdict、Adapter/transport 最终结果？旧设计已经证明仅有 hit counter 不足以解释这些差别。[D2 §1、§10]
2. **普通界面必须覆盖哪些未进入 Flow 的尝试？** 尤其前置 DROP、Unknown app、fragment/invalid facts、资源拒绝。旧 pre-CT 设计的普通计数与显式诊断覆盖不同。[D1 A/B；D2 §2]
3. **“流量”统计单位和覆盖面是什么？** original IP bytes、accepted packet bytes、blocked attempts、DNS decision 次数是不同量；包入口接口、网络类型、underlay 上的外发用量也不能自然等同。[H2；D2 §2]
4. **时间粒度与保存期待是什么？** 即时计数、分钟窗口、最近明细、持久历史是不同任务；旧 60 秒窗口和 best-effort Flow 更新均不承诺完整逐包审计。[D1；D2 §2]
5. **数据不完整时用户应知道什么？** disabled、无 consumer、写失败、ring 覆盖、session 截断、consumer 未落盘、age/容量清理需要区分；既有 recordsDropped 不能替所有层回答。[H2；D1 D/E]
6. **常态开销与显式诊断之间的产品界限是什么？** 是否必须始终能查到当前状态、最近阻止，以及性能退化信号；哪些宽解释允许用户主动开启后才产生。[D2 §1、§9]

这些是需要收敛的需求语义与研究限制，**不是新增 issue 列表、实现方案或对旧能力的全量移植承诺**。VPP fork、本仓库 C 主线的现有事实由对应报告单独核对，再共同判断哪些需求已有基础、哪些缺证据。

## 8. 对当前架构的参考价值（2026-09-18）

旧设计最值得保留的是**按用户问题区分事实、概况、历史和解释，并让后端对规则执行与归因负责**。这些可以帮助梳理当前需求；旧模块名称、进程边界和实现方式不因此成为新的最终架构。本节只定向复核既有一手文档，不追加源码实现调查。

### 8.1 可保留的职责、需求与语义原则

| 观察面 | 可供当前讨论参考的职责 / 原则 | 证据及限制 |
| --- | --- | --- |
| 当前 status 与 metrics | status 说明当前配置、生效版本和能力状态；metrics 说明一定范围内的累计量或健康信号。规则已保存、已应用、被评估、成为 winner、实际阻止必须分别解释；零命中不能代替状态查询。 | [SNORT-10 §1、§10](SNORT_10_DISCUSSION_NOTES.md)；[旧接口 §2.8](../archived/pre-vpp/INTERFACE_SPECIFICATION.md)。 |
| live flow 表 | “现在还存在什么 flow”是运行态读取问题，需与历史 records 的消费结果分清；不能因消费端保有记录就宣称它仍是 live flow。 | 旧接口明确列出 CT 汇总 metrics 与 telemetry records，本次复核**未找到完整独立 live-flow 列表/查询契约**；不把它写成旧版已有能力。[旧接口 §2.8](../archived/pre-vpp/INTERFACE_SPECIFICATION.md)；[Flow Telemetry §2、A](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)。 |
| Traffic Windows | 普通用户需要低成本、可持续使用的流量概况；这不应要求启动详细追踪或完整 Flow Telemetry。窗口覆盖、统计单位、实际 verdict 与 reset 边界应清楚。 | [SNORT-10 §2](SNORT_10_DISCUSSION_NOTES.md)。这是后期收口设计；第 6 节已说明其未在旧归档 producer 中整套实现。 |
| Flow Telemetry / 历史记录 | 有界导出业务事实供历史、时间线及后续查询；原始事实应足以解释方向、身份是否已知、执行结果与结束原因，不能让 UI 猜测。记录导出、读取、落盘和保留是不同成功边界。 | [Flow Telemetry §0–3、A–E](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)。真实早期 producer 有证据，完整产品历史库不在其 MVP 验收范围。 |
| 按需 Packet Diagnostics | 常态界面先给概况；用户主动排障时再针对对象查看详细 inputs、stages、winner 与 skipped reason。诊断观察真实执行，不改变判决；停止诊断后应释放重观察状态。 | [SNORT-10 §1](SNORT_10_DISCUSSION_NOTES.md)。保留需求与生命周期原则，不自动继承旧 channel、selector 或命令限制。 |
| PerfMetrics | 常态应能发现明显退化；详细性能分析按需启用，并说明测量起止、采样覆盖和观察自身的成本。性能慢、策略阻止、观测记录丢失是不同问题。 | [SNORT-10 §9](SNORT_10_DISCUSSION_NOTES.md)；[旧接口 §2.8](../archived/pre-vpp/INTERFACE_SPECIFICATION.md)。NFQUEUE 的计时边界不能直接等同 VPP 执行成本。 |
| 本机 consumer / store | packet runtime 产生事实；本机产品服务负责消费、查询、聚合和有界保留。UI 关闭不应被理解成用户主动停止历史消费；UI 查询产品数据，不拥有第二份权威规则或历史数据库。 | 旧职责来源是 [Flow Telemetry §3.2、§3.5、E](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)；当前 owner 意图见 [产品计划 §3](../product/ANDROID_L4_PRODUCT_PLAN.md)。**consumer 契约不等于数据库已完成。** |

规则归因尤其值得延续：**后端拥有完整规则、规则组、绑定关系以及集合编译和执行链；前端编辑与展示这些对象。** 执行证据保留可回溯来源，后端据此解释规则本体和生效路径，不要求 UI 自建第二个规则引擎，也不把编译后的内部片段误当用户独立规则。[SNORT-10 §10](SNORT_10_DISCUSSION_NOTES.md) 已明确 source graph、runtime ref 与后端重建完整 source chain 的分工；当前自动编排意图见 [规则引擎讨论记录](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)。具体规则顺序、编译阶段与归因字段仍以当前讨论为准。

同样可保留的是语义诚实：声明动作、实际 verdict、规则 hit 与实际阻止量分开；未知、未采集、没有发生、记录已丢失分开；缓存复用仍应保有逻辑 winner 与来源。它们是解释用户遭遇所需的事实边界，不要求复用旧统计结构或 observe 模型。[SNORT-10 §1](SNORT_10_DISCUSSION_NOTES.md)；本报告 §4.2、§4.4。

### 8.2 需要按 VPP 与个人设备重新分工的旧边界

- **daemon 不等于整个后端。** 旧文“consumer / 前端承担历史”应拆解为 UI 和本机产品服务；“Control Plane 不做历史库”也不能被读成当前 Local Product Backend 不负责存储。VPP、控制与产品服务之间如何承载上述职责，需要结合当前边界讨论。[Flow Telemetry §1、§3.5](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)；[当前产品计划 §3](../product/ANDROID_L4_PRODUCT_PLAN.md)。
- **概况、live flow 和历史分别有覆盖面。** 当前 FlowEntry 在前置策略通过后才创建，pre-DROP 不在 flow 表中；既不能只靠 live flow 表，也不能只靠 Flow lifecycle records 声称覆盖全部阻止尝试。普通概况要回答到哪里、主动诊断再追到哪里，须按用户任务确定。[Flow Telemetry 的 SNORT-10 覆盖说明及 A/B](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)；[当前 FlowEntry 定义](../../CONTEXT.md)。
- **统计观察点和性能边界须重定。** 接口、网络类型、设备方向、Flow 方向、策略结果及传输结果不能因都叫“流量”就合并；VPP counters、产品窗口与记录如何分工，应由要回答的问题决定，不机械复制旧 NFQUEUE metrics 分类。[旧接口 §2.8](../archived/pre-vpp/INTERFACE_SPECIFICATION.md)；本报告 §4.1、§4.5。
- **按个人终端组织成本与体验。** 常态概况和主动排障的详细追踪是有用的旧分层；不据此引入网关式持续逐包采集、外部分析平台或无界历史。观察须照顾手机资源和用户联网，同时不把实现配额变成普通用户先要理解的配置。[SNORT-10 §1、§9](SNORT_10_DISCUSSION_NOTES.md)；[个人终端部署范围](../../CONTEXT.md)；[产品计划](../product/ANDROID_L4_PRODUCT_PLAN.md)。

### 8.3 不作为当前参考的具体实现与过时语义

- 不恢复旧 C++ daemon、CT/telemetry 数据结构、shared-memory ABI、vNext 命令面、旧采样/聚合算法或容量常量。前述职责参考不是源码移植授权；当前产品接口导航已明确旧 surface 归档。[当前接口导航](../INTERFACE_SPECIFICATION.md)。
- 不沿用持久 `tracked`、无 consumer 仍构造重解释、would-match 平行引擎、让前置 DROP 为了观测进入 CT，或把固定旧 stages / 排序语义当作当前编译器契约。[SNORT-10 §1、§10](SNORT_10_DISCUSSION_NOTES.md)；[Flow Telemetry 覆盖说明](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)。
- 不把旧“consumer 可计算”当作完整数据库已验收，不把 Traffic Windows 等后期设计标成现成产品，也不把旧 Flow 导出覆盖或测试结果扩展成当前 VPP 完成证明。本报告保留的是已记录需求与经验，当前实现状态另由 [综合调查](2026-09-15_OBSERVABILITY_REQUIREMENTS_REVIEW.md) 核对。

## 9. 旧常态快照、阈值输出与 debug 通道的定向核对（2026-09-18）

**用户记忆中的主线是对的：旧常态方案在 flow 中累计事实，达到条件后输出轻量快照，由应用侧 consumer 做历史存储与派生统计；详细 debug 是另一个观察层。** 这不等于 daemon 内预建多维统计，也不等于常态输出完整 session/debug trace。以下只读核对 H2，即 `969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/`；文件行号均属于该 Git 对象，没有恢复或运行旧实现。

### 9.1 输出累计值；阈值判断使用相对上次成功导出的增量

`Conntrack::observeFlowTelemetry` 先增加 flow 的 `totalPackets/totalBytes` 与 in/out 累计量，再决定是否输出；`FlowV1Fields` 与 `encodeFlowV1` 写入的仍是累计值，**不是 delta，也不在导出后清零**。consumer 按相同 `flowInstanceId` 的前后快照求差。`recordSeq`、last-export counters/time 只在成功写入 ring 后推进；失败不消耗待导出的累计差值。[H2 `Conntrack.cpp:3182–3195,3346–3370`；`FlowTelemetryRecords.hpp::FlowV1Fields`；`FlowTelemetryRecords.cpp::encodeFlowV1`；[决议 §6、B、D](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)]

| 记录 | 实际触发条件 | 需要限定的含义 |
| --- | --- | --- |
| BEGIN | 本 telemetry flow instance 尚无成功导出（`lastExportTsNs==0`）；下一次可导出的观测生成 BEGIN | 首次写失败后仍可重试 BEGIN，不能把“首包已发生”视为 consumer 必已收到。 |
| UPDATE：计数 | `totalPackets-lastExportPackets` 或 `totalBytes-lastExportBytes` 达到对应阈值 | 阈值属于**这个 flow**，不是某条规则跨 flow 的累计 hit 阈值。 |
| UPDATE：时间 | 当前 flow 有包进入 producer 时，检查距上次成功导出的间隔 | **包驱动的最长间隔检查**，不是无流量时定时扫描所有 flow、按时强制上报。 |
| UPDATE：执行状态 | 对照上次成功导出，decision key 或 ruleId / known 状态变化 | 旧 key 包含 CT state/direction、verdict、reason、ifaceKind、ruleId；没有后来契约中的 ruleMode。 |
| END | 过期 sweep 退役、资源驱逐、关闭/禁用 telemetry 的有界 cleanup | 仅 best-effort；TCP 进入 closing 后的过期退役可标 TCP_END_DETECTED，不应写成“每个 FIN/RST 当场保证发送 END”。 |

触发源码：[H2 `Conntrack.cpp:61–74,626–642,642–740,785,803–829,919–1060,3238–3310`；IPv6 的 `observeFlowTelemetry` 对称路径]。旧 `FlowTelemetry.hpp::Config` 的默认阈值是 128 包、128 KiB、5 秒；consumer polling 默认 1 秒，**polling 读取节奏与 producer 导出节奏不是一回事**。这些仅是历史参数，不是本轮建议值。决议也明确“不另设为了定期上报还活着的扫描线程”。[H2 `FlowTelemetry.hpp:27–42`；[决议 A、D](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)]

### 9.2 没有独立的“规则命中达到次数后批量导出”记录

核对的 shared-memory 顶层类型只有 `FLOW`、`DNS_DECISION`；没有 `RULE_HIT_BATCH` 一类规则批量记录。规则命中有自己的低成本 `hitPackets/hitBytes/lastHitTsNs`（及旧 would 计数），但 `observeEnforceHit` 只更新这些 counters，不触发 telemetry 导出。常态 Flow 中的 ruleId 是执行结果归因；其变化或 Flow 计数/时间条件促使 UPDATE。[H2 `FlowTelemetryAbi.hpp::RecordType`；`IpRulesEngine.cpp:2824–2845`；`Conntrack.cpp:3225–3264`]

所以“多次包处理后才输出一条快照”有源码证据；“按规则收集 N 次 hit 后输出独立批量记录”在本次核对范围内没有证据。DNS_DECISION 也保持独立的 blocked DNS decision 事实，不是规则 hit 批量格式。[H2 `FlowTelemetryRecords.hpp` 的 DNS_DECISION 定义；[决议 §6、E](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)]

### 9.3 普通与 debug 不共用 payload 通道；不能据此断言必须两个 socket 或已共用数据库

| 路径 | 真实承载方式 | 证据 |
| --- | --- | --- |
| 常态 FLOW / DNS_DECISION | `TELEMETRY.OPEN` 经 Unix vNext socket 传共享内存 fd；records 写 `FlowTelemetryRing`，consumer mmap/poll 读取 | H2 `ControlVNextSessionCommandsTelemetry.cpp:230–266`、`FlowTelemetry.cpp::open/exportRecordHot`、`FlowTelemetryRing.cpp::tryWrite`。 |
| 旧 tracked debug | `ControlVNextStreamManager` 的进程内 `deque` replay/pending 保存事件；session 取出后由 `ControlVNextStreamJson` 构造 JSON，经 netstring socket writer 输出 | H2 `ControlVNextStreamManager.cpp:46–63,342–367`；`ControlVNextSession.cpp:676–715`。这不是 telemetry 的 mmap ring。 |

二者共用 vNext 控制基础设施，不等于共用普通 records 的物理数据通道。静态 dispatch 中，`TELEMETRY.OPEN` 不把连接切为 stream mode，随后 `STREAM.START` 没有检查 telemetry owner 冲突；因此也不能武断说旧代码必需两个独立 socket。进入 stream mode 后，同连接普通 control commands 会被拒绝。这里仅核对代码分支，**没有执行同连接联用验证，也没有证明 UI 实际这样连接**。[H2 `ControlVNextSession.cpp:326–365,398–402,470–479`]

“最后是不是进入同一数据库”没有由上述 daemon 通道决定。本次核对的 native consumer 是读取、解码、输出与 gap 检查工具，不能证明 Android 已把两类数据入同一库；Flow Telemetry MVP 明确不含前端持久化/查询库。因此“同库”只能作为未验证的消费端记忆，不能记录成已实现事实。[H6 `tests/device/telemetry/native/telemetry_consumer.cpp::emitFlow/emitDns`；[决议 E 的 MVP 范围](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)]

### 9.4 业务历史聚合归 consumer；后期 Traffic Windows 是另一轮选择

4 月 Flow Telemetry 的动机就是让 consumer 对原始记录落盘、查询、求窗口差值以及计算 Top destinations / ports / timeline；daemon 仍保有必要 flow 累计量、规则 counters 和健康 metrics，但不因此拥有这些高基数历史聚合。[决议 §0–3、E](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)。6 月 Traffic Windows 才另外提出从 PacketFacts + 最终 verdict 直接维护普通窗口、摆脱 Flow consumer 依赖；**不能用这个后期设计覆盖用户记忆中的早期 consumer 聚合方案，更不能视作本轮已接受 VPP 内建多维聚合。**[SNORT-10 §2](SNORT_10_DISCUSSION_NOTES.md)；本报告 §3、§6。

### 9.5 状态变化输出新快照，不等于已拥有精确的按规则分段账本

旧 producer 的顺序是：先累加本包，更新当前 decision/rule，再检测变化，最后输出“flow 累计 counters + 当前归因”。该分支没有先用旧 rule 输出一条截至切换前的快照，也没有额外 segment counters 或每条规则的 delta。文档所说 decisionKey 变化“切段”，不能扩大理解为源码已经提供完整的按规则字节分账。[H2 `Conntrack.cpp:3182–3244,3273–3352`；`FlowTelemetryRecords.hpp::FlowV1Fields`；[决议 B](../decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md)]

例如，在稳定条件下上次导出为 `rule=A,totalPackets=10`，之后 5 包仍命中 A 且未达导出条件，再有 1 包变为 B，则可输出 `rule=B,totalPackets=16`。**16 是 flow 总量，不是 B 的命中数；差值 6 也不能全部归 B。** 这是源码顺序说明的简化例子，不是本轮运行的复现。写失败、记录缺口和并发更不能自动补齐准确归因。旧记录确实能携带当前状态、累计量和变化证据，但不能据此保证 consumer 已可精确重建所有 rule/state 段的 packets/bytes；独立 rule counters 的存在也不等于它们已通过此记录流导出。

旧 `FlowV1Fields.proto` 是 IP protocol 数值；该 payload 没有本轮 L7 识别结果或 SNI 事实，不能直接宣称旧记录形状已满足新的 L7 查询需求。[H2 `FlowTelemetryRecords.hpp::FlowV1Fields`]

### 9.6 累计快照如何归入时间窗口：旧契约的确定项与空白（2026-09-23）

用户在接受 Rust 后台维护常态窗口后，要求核对原非 VPP 方案对此如何设计。本节定向复核现存 D1 / D2 / D3 文档及本报告既有实现调查，不追加旧源码读取、恢复或运行；不改变当前第 21.16 节的窗口归属。

**早期 Flow Telemetry 明确了累计求差与消费层职责，但本次核对的旧契约没有规定差值跨时间窗口的具体分配算法。** D1 §6、B 明确同一 `flowInstanceId` 的前后累计量可由 consumer 求窗口增量；C/D 又明确 consumer 的组装 / 查询策略不在后端规范范围内。它没有据此选定全部记入后一次快照时间、按区间均摊、插值或精确切桶。D1 E 明确前端持久化 / 查询库不在 Flow Telemetry MVP 中，既有 native reader 证据也不证明完整窗口聚合已实现。

旧时间字段区分 `timestampNs`（事件 / 导出时间）、`firstSeenNs` 和 `lastSeenNs`（首末包时间），特别禁止把 END 导出时间当作最后一包时间。它们能解释记录覆盖与生命周期，不能单独提供两次累计快照之间每个时间桶的流量分布。[D1 B；D3 FLOW 布局；本报告 §9.1]

**后期 SNORT-10 的 Traffic Windows 有另一套具体的时间桶设计，输入直接来自包处理：**

- 只支持 `last N` trailing windows，历史默认 `15m / 1h / 5h / 24h`；使用 monotonic time，统一 `60s` bucket，不按自然日划分。
- 每包在最终 verdict 后更新所属 worker / shard 的当前分钟桶，维护 device 与 app 的贡献；不要求 Flow Telemetry consumer active，也不使用 Flow records 作为窗口输入。
- basic tier 不为四个窗口各维护一套滑动总量；查询时合并目标范围内的 shard / minute buckets。槽位以 `bucketMinute` 标识，写入新分钟时按需复用，读取时排除过期桶，不依赖专门的后台定时清理。
- UI 调用 pull 查询；窗口是分钟级摘要，并不承诺任意时间边界的精确分割。`coveredSec` 说明启用 / reset 后的覆盖时间，不代表消除了分钟桶误差。
- 配置持久化，窗口状态不持久化；daemon 重启、RESETALL 或有效窗口配置变更重新累计，普通策略变化不重置过去按实际结果累计的数据。

以上来自 [SNORT-10 §2](SNORT_10_DISCUSSION_NOTES.md#2-traffic-windows-具体设计第一版已收口)，属于后期设计收口；本报告 §6 未找到其整套旧 producer 实现及通过证据。尤其不能说旧版曾“先消费 Flow 累计快照，再按已定 60 秒算法精确恢复各分钟”：那会把两轮不同数据来源的方案拼在一起。

对当前讨论的意义：早期方案提供事实导出 / 应用侧聚合的职责依据，后期方案提供分钟摘要与查询合并的历史思路；它们都没有替当前 Rust consumer 决定累计区间跨窗口的分配语义。历史阈值、窗口和桶长也不是本轮已接受的参数。

用户随后补充回忆：Traffic Windows 当时应是因为前端每次计算太卡而提出。此处保留为用户提供的动机背景；本次定向核对没有找到该次卡顿的直接复现或测量记录，不能将它扩写成已经定位某个 UI 线程、数据库查询或 consumer 吞吐瓶颈。现存 D2 能印证的是：持续维护时间桶，查询仅合并汇总桶 / app state，而不从原始 Flow records 重新聚合；排行仍允许在查询时计算，因此“UI 直接查询”也不等于内部所有结果均已预先算完。

对当前方案，应保留避免重复全量计算的目标。Rust 后台增量维护必须形成可复用的汇总结果；仅将同一全量 records 扫描搬到 Rust 或后台线程，并不解决重复工作与总成本。时间桶合并或结果缓存的具体选择仍待设计，不由这段历史直接冻结。
