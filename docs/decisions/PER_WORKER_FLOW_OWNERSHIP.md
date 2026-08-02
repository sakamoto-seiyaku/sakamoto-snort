# Per-worker single-owner flow runtime

状态：accepted，2026-07-19；worker distribution 约束更新于 2026-07-20。

Sakamoto 的目标 VPP dataplane 使用 per-worker、per-flow single-owner 模型：Root/NFQUEUE
与 VPN/TUN Packet Capture Adapter 在进入需要 flow state 的 worker graph 前执行稳定分流，
同一双向 flow 的 `FlowEntry`、后续 protocol identification、Conntrack 和 stream state 由
一个 worker 私有拥有。选择该模型是为了参考已验证的 VPP/session-manager 架构，避免共享
authoritative flow table 的跨 worker update、锁和 cache-line ownership 成为长期基础。

普通 IPv4/IPv6 报文只用 direction-independent Canonical Flow Key 选择 worker：IP protocol
加 canonicalized source/destination address-and-port endpoint pair，即完整五元组。complete Linux
UID、Android user/profile、Network Gate、interface、capture queue 和 Root/VPN Runtime Profile
都不进入 handoff hash，也不进入 FlowEntry identity。

Canonical endpoint A/B 只用于无方向 key/owner，不定义语义方向。Adapter 同时提供设备相对的
`INPUT/OUTPUT`；FlowEntry 创建包独立定义 flow-relative `ORIG`，反向 packet 为 `REPLY`，并保存
创建包的 device direction 为 `flowOriginDir`。后续 libprotoident 使用 `ORIG/REPLY`，不是设备
方向或 endpoint 字典序。Gate/L4 之前被丢弃的 packet 没有 FlowEntry，因此没有 flow direction。

Worker Layout 在 runtime 启动、接收流量之前一次性确定：worker 数量、Canonical Flow Key 到
worker 的映射、每个 worker 的 flow/session pool，以及 worker-private packet/cache 区域的
容量在运行期保持固定。Policy Apply 不改变 Worker Layout；第一版不支持在线增加 worker、
修改映射或把存量 FlowEntry reshard 到其他 worker。

Root/NFQUEUE 与 VPN/TUN 都必须经过同一个 Primary Software Distribution，但 Adapter 的
Initial Execution Placement 可以不同。VPP-native Root Adapter 将多个 NFQUEUE queue lane
直接分摊到 ingress execution contexts，不先汇聚到 main thread；VPN 受单一 TUN fd 限制，先由
一个 native Platform I/O Lane 接收。
该初始位置只提供 receive parallelism，不是 Flow owner。软件分流器在当前 ingress context 上从
Canonical Flow Key 计算最终 owner：命中当前 worker 时原地继续，否则只移动 buffer index 与
side metadata，执行一次 Primary Handoff。由于 Canonical Flow Key 与 Worker Layout 都是
direction-independent 且固定的，同一 flow 的正反包最终进入同一 owner 是正确性保证，不是
kernel queue affinity 的 best-effort 结果。

每个 owner-sensitive worker graph 在任何 worker-private counter、cache、ActivityAccumulator、
FlowEntry 或 session state 更新前执行 Owner Guard：

1. 当前 worker 与计算出的 owner 一致时走 local fast path，不发生 worker-to-worker enqueue；
2. 不一致时只允许一次 Corrective Handoff，直接投递计算出的 owner；
3. 纠偏后的报文重新校验仍不一致时立即 `DROP`，记录 fault reason/counter，不继续跳转。

Primary Software Distribution 与 Owner Guard 必须使用同一个 Owner Selector、Canonical Flow Key
编码、hash seed 和 Worker Layout。目标 queue 拥塞时不得改投其他 worker。Corrective Handoff
发生在 Primary Handoff 已完成之后，仍应接近零；持续命中表示 parser/canonicalization、worker
mapping 或投递路径错误，而不是正常负载均衡行为。NFQUEUE verdict 返回与 VPN/TUN/transport fd
写回属于 Adapter completion routing，不计为 Primary 或 Corrective Handoff。

Root completion 采用 native origin-lane ownership：每条 NFQUEUE Platform I/O Lane 独占其
netlink queue/socket 的 receive 与 verdict operation，并与一个 VPP ingress execution context
共址，但 queue/lane identity 本身不定义 FlowOwner。owner 命中当前 ingress execution context 时
原地完成；owner
不匹配时，原始 live buffer identity、completion identity 和有界 side metadata 被投递给 canonical
FlowOwner，terminal intent 再通过预留 completion credit 返回 Origin Adapter Lane。只有 origin lane
能在原 queue generation 上用原 packet ID 提交每包唯一一次 verdict。FlowOwner 不调用共享
`nfq_q_handle`，也不通过 shared-TX/trylock 绕过 return。

NFQUEUE completion 与 VPP buffer return 是两个动作：origin lane 向 kernel 提交 verdict，但不把
VPP storage 交给 NFQUEUE；物理尝试产生 `SUCCEEDED`、`FAILED_DEFINITE` 或 `OUTCOME_UNKNOWN` 后，
同一 native lane 才走 VPP 原生 buffer return 生命周期。每个 decided buffer 在此之前保持 live；
Completion Frame 只移动 buffer indexes、completion identity 与 terminal metadata，不复制 packet
bytes，不建立第二个 packet buffer、LeaseSlot table、return object 或热路径动态内存。真实 verdict
syscall failure 后的 FAILED debt 结算和 clean teardown 仍是 release gate。

VPN completion 首版采用一个 native VPN Platform I/O Lane。Android 仍负责创建 VpnService TUN、
执行 `protect()` 并把所需 descriptors 交给受监督的 VPP runtime；运行中的 TUN/HEV packet I/O、
completion 和 native buffer return 留在 Adapter plugin。允许的 outbound packet 交给 HEV，return
packet 写回 TUN，policy drop 在同一 native ownership domain 完成。HEV 接受 ownership 后的失败只
属于 Transport Outcome。除非真机证据证明单 I/O owner 是瓶颈，首版不拆 TUN/HEV owners。

Root/VPN 的 PacketLease 继续由 live VPP buffer 与内联固定 metadata 承载。公共字段保存 Adapter
type/generation、Origin Adapter Lane、terminal intent 与 obligation state；Adapter 私有字段保存
NFQUEUE completion identity 或 VPN completion target。这些字段不使用 packet exdata、动态分配或
独立 lease table。任何 detached task 都不得保留裸 buffer index；teardown 在关闭 Adapter generation
前必须 quiesce ingress，并在 completion channel 仍可用时有界排空全部 obligated buffers。

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

Conditional wake 方向单独保留为 HOLD：sleep-confirmed publish-to-terminal p99 的正式结果改善约
44%，但 diagnostics-disabled final handshake 相对 exact-unpatched 的 idle CPU gate 失败。当前 wake
patch 和 mode3 persistent wake 都不得进入 release；只有优化后的新 artifact 同时通过预注册 idle
non-regression 与 latency regression，才可更新本决策的调度实现。

IP 分片采用 fork VPP handoff 的两阶段结构，但不照抄其 hash 实现：

1. 非初始分片没有可靠端口，先用所有分片都可取得的 fragment-safe key 把同一 datagram
   co-locate 到一个 reassembly worker；
2. 初始分片同时计算完整 Canonical Flow Key 的最终 owner，并把该 owner 作为临时 packet
   metadata 随 reassembly state 保留；
3. bounded reassembly 成功后， reconstructed packet 必要时执行第二次 handoff，再在最终
   owner 上进入 Network Gate、L4 policy 和 FlowEntry 路径。

fork 当前 `src/vnet/handoff.c` 的 `symmetric CRC32/Toeplitz` L4 路径实际只混入地址与端口，
没有把 IP protocol 混入 hash。Sakamoto 不继承这个偏差；正常路径和分片重组后的最终 owner
选择都必须使用真正的五元组。分片 co-location/reassembly key 只服务临时重组，不得成为
FlowEntry key。

## Consequences

- queue ID、INPUT/OUTPUT 拆分或 Packet Capture Adapter 拓扑不能代替 flow ownership；
- Adapter I/O lane 是按平台测量扩展的实现拓扑，不是共享 policy/runtime 语义；
- correctness 依赖明确的 Canonical Flow Key、启动时冻结的 Worker Layout、Primary Software
  Distribution、Owner Guard、bounded queue、overload 和 teardown 语义；
- 普通报文只做一次 canonical five-tuple software distribution；正确到达后没有 normal-path
  handoff。最多允许一次 Corrective Handoff，第二次 owner mismatch 直接丢弃；
- 分片允许 reassembly worker 与最终 flow owner 不同；这是显式 Fragment Steering 阶段转换，
  不属于分流错误，也不消耗 Corrective Handoff 的一次纠偏额度；
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
