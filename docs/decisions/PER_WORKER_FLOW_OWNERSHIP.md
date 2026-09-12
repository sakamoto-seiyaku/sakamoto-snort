# Per-worker single-owner flow runtime

状态：accepted，2026-07-19；worker distribution 约束更新于 2026-07-20，conditional-wake 证据更新于 2026-08-04，Canonical Owner Key、namespace discriminator、metadata 与 Worker Placement 边界更新于 2026-09-04。

Sakamoto 的目标 VPP dataplane 使用 per-worker single-owner execution 与 per-flow single-owner state：
Root/NFQUEUE 与 VPN/TUN Packet Capture Adapter 对每个合法 IPv4/IPv6 packet 执行稳定分流，
得到一个 VPP logical `ExecutionOwner`。其中完整 TCP/UDP 和受支持 ICMP Echo query 的 ExecutionOwner 同时提供其
`FlowOwner` identity；同一双向 flow 的 `FlowEntry`、后续 protocol identification、Conntrack 和 stream
state 由该 worker 私有拥有。其他合法协议仍有稳定 ExecutionOwner，但不会因此伪造端口或创建
TCP/UDP FlowEntry。选择该模型是为了参考已验证的 VPP/session-manager 架构，避免共享
authoritative flow table 的跨 worker update、锁和 cache-line ownership 成为长期基础。

### 2026-09-11 FlowRuntime 参考范围

FlowRuntime 使用本产品的职责、术语与 Interface，不将外部参考项目名称、模块名或本地
源码路径作为设计契约。设计复用不等于代码导入，也不以 upstream VPP session 子系统
替代产品流生命周期。端点规模通过启动容量配置适配，不因此简化正确的结束与回收流程。

FlowRuntime 协调当前 owner 上的查找、创建、更新和结束；内部 table 负责索引，pool 负责
存储与槽位分配回收，协议 tracker 更新状态并确定 timeout/结束判断，Expiry 管理 deadline
并触发统一结束，FlowEnd 承载下游结束处理。调用方不分别操作 table/timer/pool 拼装关闭。
协议 tracker 的状态与 timeout 语义继续取自 OVS。

FlowEntry 容量独立配置、启动预分配、重启生效，运行中不自动扩容。旧 64 槽/owner 仅为
历史基础实现事实，不作为正式默认值或隐藏上限。S221 使用 opaque、统一 TCP/UDP/ICMP_QUERY
runtime，table/pool/free-list 不暴露给 packet caller；1024/worker 是可替换的开发设置。
正式默认值根据完整 entry、索引、timer 等内存
占用、worker 数量和端点流量验证确定，计入等待超时及等待 FlowEnd 回收的占用。
配置非法、溢出或预分配失败明确启动失败，不静默缩小容量。已有流不因新流满池被驱逐，
不跨 owner 借位；普通满池保留 Gate/L4 结果，允许包跳过依赖 FlowEntry 的处理并记录
capacity bypass，策略 DROP 仍 DROP。回收后自然恢复建表，不因此停止 VPP。

正常 close 先移除查找索引与 timer，再保留旧 entry 供 FlowEnd 消费，最后由 native buffer
free callback 归还槽位。同 tuple 可以在另一空闲槽建立新流，不提前覆盖旧槽。
FlowEnd 使用独立无 payload buffer，不长期保留 NFQ/TUN 首包，不带 AdapterObligation。

FlowEnd buffer 分配失败属于 runtime 级致命故障，而非普通流表满；可能是 VPP buffer 池
耗尽，不等于已证明整机 OOM。停止 ingress，通过现有监督层有界清理并退出故障 runtime。
个人终端以联网连续性为先：NFQ 撤销本产品捕获规则并清理队列，VPN 撤销本产品 VPN/TUN
接管与路由，不能留下死队列或无人读取的 TUN。恢复系统联网不等待 VPP 重启；后续功能
恢复使用新 generation，连续失败限制重启频率并明确报告保护停止。不得伪称全部原始包、
verdict 或 FlowEnd 已完成；故障瞬间个别包可能丢失，不能持续黑洞。平台强制的 VPN lockdown
等外部约束仍有效，产品不能绕过或把受其阻止的联网报告为已恢复。

Expiry 在没有新包时也须推进，有界批量回收以免长时间占住 worker；逻辑到期后 lookup
不得复用旧流，物理回收统一走 FlowEnd。min-heap 只是候选，具体容器与 polling/唤醒方式
由后续验证选择。下文约 1 秒的正常负载实验目标不变，不是任意负载下的硬实时承诺。
该校准保留唯一 owner、运行期容量冻结、无迁移/借位和明确生命周期的约束。

Owner Selector 只使用 direction-independent typed Canonical Owner Key。三种显式 shape 都包含
key kind、IP family、terminal IP protocol 和 canonical address pair：`L4_PORTS` 在完整 TCP/UDP
具备 typed ports 时包含 canonical port pair；`ICMP_QUERY` 包含归一化 Echo query class 与
identifier，request/reply 共用 identity，sequence 只属于 PacketFacts/trace；其他合法协议或
valid L3 with unavailable transport identity 使用 `L3`。缺失端口不能伪造为零端口五元组。
Canonical Flow Key 是可供后续 FlowEntry/tracker 消费的 `L4_PORTS` 或 `ICMP_QUERY` identity；
assignment 本身不创建 entry；S221 可按该 identity 创建 ICMP_QUERY entry，仍不代表 ICMP tracker。
complete Linux UID、Android user/profile、Network Gate、interface、capture queue、CPU 和 Root/VPN
Runtime Profile 都不进入 handoff hash，也不进入 FlowEntry identity。

当前 Android 与 Linux 本地端点的一个 VPP Runtime 只处理其 Adapter 所在网络命名空间可见的
流量，因此 Canonical Owner Key、Canonical Flow Key 和 Owner Selector 不包含额外 numeric
`flow_domain`。Linux
network namespace 是内核隔离和部署边界，不是 Root NFQUEUE packet 上需要再次区分的字段；
未来若产品明确运行多个 namespace，应先确定相应的 runtime/Adapter 拓扑，而不是现在把假想
namespace、网卡、queue 或 AF_XDP lane 混入五元组或 owner hash。

Canonical endpoint A/B 只用于无方向 key/owner，不定义语义方向；`L3`/`ICMP_QUERY` 比较 address，`L4_PORTS`
比较 address-and-port endpoint。OwnerAssignment 可保留 source 是否为 endpoint A，但该字段
也不定义语义方向。Adapter 同时提供设备相对的
`INPUT/OUTPUT`；FlowEntry 创建包独立定义 flow-relative `ORIG`，反向 packet 为 `REPLY`，并保存
创建包的 device direction 为 `flowOriginDir`。后续 libprotoident 使用 `ORIG/REPLY`，不是设备
方向或 endpoint 字典序。Gate/L4 之前被丢弃的 packet 没有 FlowEntry，因此没有 flow direction。

Worker Layout 在 runtime 启动、接收流量之前一次性确定：VPP logical worker 数量、Canonical
Owner Key hash/seed 到 worker 的等权映射、每个 worker 的 flow/session pool，以及 worker-private
packet/cache 区域容量在运行期保持固定。Policy Apply 不改变 Worker Layout；第一版不支持在线
增加 worker、修改 owner mapping 或把存量 FlowEntry reshard 到其他 worker。

Worker Placement 与 Worker Layout 分离。实验性产品设置允许用户在启动前选择每个 VPP worker
使用的 distinct online Linux CPU ID，CPU 可以连续或不连续；VPP runtime 据此生成并验证
`corelist-workers`。产品只提供选择、校验、启动和实际 affinity 证据，不自动分类大小核、不推荐
最优组合、不做加权分流或 live migration。变更 placement 必须 clean restart；CPU ID、CPU 类型与
placement 顺序不进入 Canonical Owner Key 或 Owner Selector。

Root/NFQUEUE 与 VPN/TUN 都必须经过同一个 Primary Software Distribution，但 Adapter 的
Initial Execution Placement 可以不同。VPP-native Root Adapter 将多个 NFQUEUE queue lane
直接分摊到 ingress execution contexts，不先汇聚到 main thread；VPN 受单一 TUN fd 限制，先由
一个 native Platform I/O Lane 接收。
该初始位置只提供 receive parallelism，不是 Flow owner。软件分流器在当前 ingress context 上从
Canonical Owner Key 计算最终 ExecutionOwner：命中当前 worker 时原地继续，否则只移动 buffer
index 与 side metadata，执行一次 Primary Handoff。由于 Canonical Owner Key 与 Worker Layout
都是 direction-independent 且固定的，同一 flow 的正反包以及其他协议的对称地址 pair 最终进入
同一 owner 是正确性保证，不是
kernel queue affinity 的 best-effort 结果。

Primary Software Distribution 只产生一次 OwnerAssignment，并以该结果决定 local continuation 或唯一
一次 Primary Handoff。handoff 后的 owner-sensitive graph 直接使用当前 VPP worker 的私有 counter、
cache、ActivityAccumulator、FlowEntry 与 session runtime；不再运行二次 owner guard、重新解析、
canonicalize、hash、owner 改写或 corrective dispatch。fault/evidence build 可以断言实际接收 worker
等于已选 ExecutionOwner；不一致属于实现错误并确定性 runtime-drop，不能通过第二次分流掩盖。
目标 queue 拥塞时不得改投其他 worker。NFQUEUE verdict 返回与 VPN/TUN/transport fd 写回属于
Adapter completion routing，不计为 Primary Handoff。

Root completion 采用 native origin-lane ownership：每条 NFQUEUE Platform I/O Lane 独占其
netlink queue/socket 的 receive 与 verdict operation，并与一个 VPP ingress execution context
共址，但 queue/lane identity 本身不定义 FlowOwner。owner 命中当前 ingress execution context 时
原地完成；owner
不匹配时，原始 live buffer identity、completion identity 和有界 side metadata 被投递给 canonical
FlowOwner，terminal intent 再通过预留 completion credit 返回 Origin Adapter Lane。只有 origin lane
能在原 queue generation 上用原 packet ID 提交每包唯一一次 verdict。FlowOwner 不调用共享
`nfq_q_handle`，也不通过 shared-TX/trylock 绕过 return。

NFQUEUE completion 与 VPP buffer return 是两个动作：origin lane 向 kernel 提交 verdict，但不把
VPP storage 交给 NFQUEUE；`nfq_set_verdict(..., NF_ACCEPT/NF_DROP, ...)` 是 NFQ-defined
terminal operation，非负函数返回表示该 Adapter operation 成功完成，因此产生
`SUCCEEDED`；负/native error 或 deterministic pre-backend rejection 产生 `FAILED_DEFINITE`。
`OUTCOME_UNKNOWN` 只用于未取得可信 terminal result 的 genuinely ambiguous operation path，
不用于已观察到的普通非负返回。NFQUEUE
不提供独立 ACK，`SUCCEEDED` 只表示 terminal operation 完成，不证明后续 network delivery
或 downstream traffic success。物理尝试产生上述 outcome 后，同一 native lane 才走 VPP 原生
buffer return 生命周期。每个 decided buffer 在此之前保持 live；Completion Frame 只移动 buffer
indexes、completion identity 与 terminal metadata，不复制 packet bytes，不建立第二个 packet
buffer、LeaseSlot table、return object 或热路径动态内存。真实 verdict syscall failure 后的 FAILED
debt 结算和 clean teardown 仍是 release gate。

VPN 首版从一个 native TUN Platform I/O Lane 接收并完成 Android TUN I/O。Android 仍负责创建
VpnService TUN、执行 `protect()` 所需的受控 broker 操作，并把平台资源交给受监督的 VPP Runtime；
运行中的 TUN packet I/O、Adapter Completion 和 native buffer return 留在 C-only Adapter plugin。
允许的 TUN-origin packet 在 canonical FlowOwner 进入独立的 VPN Flow Stack Packet Boundary，
flow-stack-origin return packet 回到同一 shared graph 后才由 TUN lane 完成。Flow Stack admission、
Adapter Completion 与 Transport Outcome 是不同事实。ADR-0007 的 OI 证据已选择 owner-inline
topology；2026-09-05 共识保留双 copy 与独立存储，transport session 不持有原 VPP buffer 或
FlowEntry 指针。回调、停止和旧事件清理复用既有 owner/generation，不新增同步管理体系；具体
instance/shard 数量、容量和调用时序仍须真实依赖与真机证据。

Android Root、Android VPN 与 Linux NFQUEUE 的 PacketLease 继续由 live VPP buffer 与内联固定
metadata 承载。解析得到的 PacketFacts、Adapter 归一化的 Platform Packet Facts、OwnerAssignment
与 AdapterObligation 是不同语义；VPN Packet Provenance 是 Platform Packet Facts 内的强类型字段。
queue/lane/completion handle 不进入
PacketFacts、policy key 或 Owner Selector。Platform Packet Facts 对 UID、Linux ifindex、
NetworkContextId 等字段使用显式 available/unknown 状态，不能把零值解释为已知事实。VPN 首版
Linux ifindex 固定为 unknown；Root/Linux NFQUEUE 只从对应 hook 的 NFQA ifindex attribute 取得
Linux ifindex，不能用 VPP `sw_if_index`、lane 或 queue 代替。

物理布局遵循 pinned VPP buffer subgraph lifetime，而不是把 `opaque`/`opaque2` 当作永久全局
property bag。产品可在经过审计的私有 graph 区间使用固定 inline overlay，但进入 full reassembly
等会复用 VNET opaque union 的节点前，必须保存仍需存活的 Platform Packet Facts，并在重组完成后
恢复。当前本地端点不引入 packet exdata、动态分配、独立 lease table，也不照搬运营商路由器 fork
扩大的 `opaque2/opaque3` 布局；未来路由器部署需要新的容量证据和显式架构决定。
重组后的平台事实以 offset=0 首片为准，首片缺失保持 unknown，不做跨片拼补；这不合并或
替代每片独立的 NFQUEUE completion identity。详细规则与 overlay 生命周期见
`VPP_PACKET_METADATA_OWNERSHIP.md`。

任何 detached task 都不得保留裸 buffer index；teardown 在关闭 Adapter generation 前必须
quiesce ingress，并在 completion channel 仍可用时有界排空全部 obligated buffers。

Rust 不进入 packet hot path、VPP graph、worker handoff 或 Adapter Completion。Rust 仅通过粗粒度、
non-unwinding compatibility ABI 管理 lifecycle、configuration、immutable policy snapshot、status 与
diagnostics。packet bytes 和 live VPP buffer ownership 不跨 Rust boundary；系统始终只有 VPP 原生
buffer pool，正常 graph、handoff、completion 与 return 都在 C/VPP ownership domain 内完成。

第一版 Adapter I/O Topology 不要求物理对称：VPN/TUN 从单一 fd owner 开始；Root/NFQUEUE 保留
多 queue 并行能力，每个 native queue lane 独占其 socket，并把 ingress batch 直接放到一个 Initial
Execution Placement，避免 main-thread fan-in。两者共享 Primary Software Distribution 和
owner-worker graph，但 queue 数量、ingress placement 与 completion I/O 按 Adapter 特性独立测量。

Root 第一版 queue range 使用 `shared-flow-pool`：IPv4 与 IPv6 仍各自独立，但同一 family 的
`INPUT`/`OUTPUT` 规则指向同一 range。旧 `split-in-out` 用独立 listener/thread partition 推断
方向的理由已经消失；Device Packet Direction 必须从每包 NFQUEUE hook 归一化。共享 range 只减少
queue/socket/reserve 数量并改善可能的 ingress locality，不改变 OwnerSelector correctness。

Root 使用 connection-stable kernel `queue-balance`，不启用 CPU fanout。`Q=W` 是第一轮 production
capacity matrix 的起点而不是已证明常量；具体 queue/worker 数由目标设备 throughput、latency、drop、
CPU、power 与 thermal evidence 选择，只能在重启并重建 queue ranges 时改变。Pixel 6a P2 在
address-diverse UDP 上测得 Q2/Q4 Initial Placement 与 canonical owner 约有 50% mismatch，证明
queue-balance 能提供 receive parallelism，但不能替代 Primary Software Distribution，也不能保证
省掉多数软件 handoff。该比例是设备/规则/流量范围内的证据，不是跨平台常数。

P4 已拒绝 shared-TX/trylock：mixed 与 all-remote direct-hit median 仅约 52.6%/60.9%，且 aggregate
CPU/context activity 比 canonical return 更差。选定的 hybrid topology 保留 owner-local fast path，
只对 mismatch 使用 bounded canonical processing + Canonical Return。POC 中 32/128 descriptor depth
只证明 credit sizing 是一等容量参数，不构成生产常量。

历史 P5/P6 conditional-wake 实现继续保持 HOLD。P5 早期诊断曾观察到 sleep-confirmed publish-to-terminal p99 约
44% 改善，但 P6d final campaign-21 的 32 个 formal arms 全部有效后，idle C-A 单侧 95% 上界仍为
`+0.091950 pp`（门槛 `<=+0.05 pp`，失败），sleep-confirmed p99 改善下界为 `-3.110%`（门槛
`>=20%`，失败）；p50 回归上界约 `+0.054%` 通过，功耗因无外部功率仪 inconclusive。当前 wake
patch 和 mode3 persistent wake 都不得进入 release；只有新的机制假设、新 hashed artifact 和新的
预注册 idle/latency campaign 同时通过，才可更新本决策的调度实现。

2026-09-12 用户确认新的完整通知合并协议进入实现及真机验证，见
[ADR-0006 的事件驱动通知决定](../adr/0006-vpp-native-packet-io-adapters.md#2026-09-12-event-driven-worker-notification-decision)。
继续固定 VPP 26.02，复用 native frame、现有 worker eventfd 与 LT，并用有序 pending
latch 合并通知；确认通知后复查 remote/local runnable work，已有本地待执行帧不得阻塞休眠。
该决定不恢复旧 wake 补丁，不要求可选内核 membarrier，不改变 owner/copy/credit 约束。
第一轮必须完整覆盖竞争、故障和生命周期；更极端的优化等待真实热点，不凭经验预判热点。
设计批准与 Pixel/性能验收分别记录，不能以本次共识将旧 P6 失败改写为通过。

IP 分片采用 fork VPP handoff 的两阶段结构，但不照抄其 hash 实现：

1. 非初始分片没有可靠端口，先用所有分片都可取得的 fragment-safe key 把同一 datagram
   co-locate 到一个 reassembly worker；
2. 初始分片同时计算完整 Canonical Flow Key 的最终 owner，并把该 owner 作为临时 packet
   metadata 随 reassembly state 保留；
3. bounded reassembly 成功后， reconstructed packet 必要时执行第二次 handoff，再在最终
   owner 上进入 Network Gate、L4 policy 和 FlowEntry 路径。

fork 当前 `src/vnet/handoff.c` 的 `symmetric CRC32/Toeplitz` L4 路径实际只混入地址与端口，
没有把 IP protocol 混入 hash。Sakamoto 不继承这个偏差；正常路径和分片重组后的最终 owner
选择都必须使用包含 IP protocol 的 Canonical Owner Key。分片 co-location/reassembly key 只服务
临时重组，不得成为 FlowEntry key；重组后的合法 packet 仍由唯一 Canonical Owner Selector 取得
ExecutionOwner。

## Flow expiry timing — 2026-09-05 experiment target

Flow 的协议 deadline 与实际清理完成时间分开：deadline 到期即逻辑过期，后续 lookup 不得把
尚未清理的旧 entry 当作有效 flow 复用；owner 后续通过 FlowEnd 完成结算与释放。协议 timeout
秒数继续使用同一 pinned OVS 默认表，不为容纳清理延迟而延长。

SAKAMOTO-226 第一轮 A/B 接受正常负载下到期后 **约 1 秒内完成实际清理**作为实验目标。
这是秒级清理尺度，不是已证明的硬实时上限或正式发版承诺。运行前仍须固定正常负载定义、
计时端点、统计口径、容差与 GO/NO-GO 阈值；不能把“约 1 秒”在运行后解释为任意延迟。
实际清理完成须覆盖 FlowEnd 结算和 entry 释放，不能只记录 timeout node 被调用。

同批大量到期单独评估 backlog、oldest overdue 和全部清空时间，不把单 flow 的正常负载目标
直接当作任意批量的保证。screen-off/Doze 仍按任务矩阵独立记录证据，不推导设备休眠时的
硬实时保证。两臂保持相同协议 timeout、flow set、清理 budget 与 FlowEnd consumer graph。

指定 VPP fork 的 timeout input node 常驻 polling，但以清理周期控制到期处理；查阅时默认
`expire_period_ms=1000`、`expire_batch_max=100`，只作为实验参考，不冻结产品参数。polling 与
nearest-deadline/interrupt wake 的选择仍由 S226 真机 A/B 决定，S227 消费其结果；本目标不重开
全局 packet conditional-wake 决策。

2026-09-13 实施补充：上述实验现已完成，S226 选择 owner-local one-shot deadline wake，
S227 将其接入正常 UDP runtime。索引每 entry 至多一项，批量最多 100 END、间隔至少
100 ms；空表 disarm，generation 关闭先 quiesce timer，再 drain。这个补充记录实测选择，
不把原实验目标改写为发行保证。见 [S226](../testing/2026-09-12_S226_EXPIRY_AB.md) 与
[S227](../testing/2026-09-13_S227_UDP_EXPIRY.md)；TCP/ICMP 完整矩阵仍在 S236 范围。

## Consequences

- queue ID、INPUT/OUTPUT 拆分或 Packet Capture Adapter 拓扑不能代替 flow ownership；
- Canonical Owner Key、Canonical Flow Key 与 Owner Selector 不接受 `flow_domain`、network namespace、interface、
  provenance 或其它部署拓扑 discriminator；
- Adapter I/O lane 是按平台测量扩展的实现拓扑，不是共享 policy/runtime 语义；
- correctness 依赖明确的 Canonical Owner Key、启动时冻结的 Worker Layout、唯一一次 Primary
  Software Distribution、bounded queue、overload 和 teardown 语义；
- 普通报文只做一次 Canonical Owner Key software distribution；正确到达后没有第二次 owner
  计算或 corrective dispatch；
- 分片允许 reassembly worker 与最终 flow owner 不同；这是显式 Fragment Steering 阶段转换，
  不属于普通报文的第二次分流；
- Network Gate 与 port-aware L4 classifier 只评估 policy-ready packet；非初始分片不得以
  ports unavailable 的降级事实绕过端口规则；
- immutable policy snapshot、配置 epoch 和只读产品字典可以跨 worker 共享；flow/session
  mutable state 默认不能共享；
- 同一 Authoring Policy Bundle 编译出的 stage-owned runtime views 共享一个 policy revision 和
  source attribution，但保留各自 priority space；具体结构见
  `docs/adr/0001-policy-bundle-staged-enforcement.md`；
- 控制面和查询聚合各 worker 的 bounded snapshot，不直接读取正在变化的 worker state；
- Android L4 Product Release 可以只建立 bounded `FlowEntry`，不因此承诺完整 Conntrack；
- Network Gate/L4 `DROP` 在 FlowEntry allocation 之前终止，只更新精确 counters 与 bounded
  worker ActivityAccumulator；只有 `PASS_NEXT` 流量进入 FlowEntry；
- Protocol Identification Release 在相同 `FlowEntry` 上附加 libprotoident 状态，不新建平行表；
- Runtime Snapshot 发布不遍历 worker-private FlowEntry；entry 在下一包发现 policy revision
  mismatch 后保留 flow facts、清除 policy decision 并懒重评估；
- QUIC CID/migration、TCP stream reassembly 和 full Stateful CT 不属于前两个版本。

本决策取代 `L4_CONNTRACK_WORKING_DECISIONS.md` 和
`NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md` 中把全局共享 A++ CT table 作为未来 runtime
baseline、把 owner/handoff 仅作为性能实验的结论。两份旧文档中的 PacketFacts、consumer-
driven facts、policy stage、bounded observability 和 stateful semantics 仍然有效。

## S207 assignment storage — 2026-09-08

唯一 `product_owner_assign` Interface 只接受已解析 PacketFacts 与冻结 Worker Layout。生成的
typed key、64-bit canonical hash、ExecutionOwner 和 source-side projection 在下游不再计算。
固定 opaque2 保存 key kind、query class、validity、hash 和 projection；地址由不可变 native
span 按已保存的 source-side projection 还原，不重新比较端点。去掉 opaque2 中重复的 obligation
token 后仍为 56 bytes，唯一 token 保留在 opaque 的 AdapterObligation。invalid L3 assignment
保持 invalid/owner unknown/hash zero，在当前 execution context runtime-drop 并结清原 obligation。
