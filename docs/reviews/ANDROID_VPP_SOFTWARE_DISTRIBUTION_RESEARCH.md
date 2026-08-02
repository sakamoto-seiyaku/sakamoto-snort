# Android VPP 软件分流与 ingress 线程拓扑研究

状态：point-in-time research，2026-07-20。本文提供证据与推荐，不是 standing authority；经确认的结论应再提升到 `docs/decisions/`。

## 1. 结论先行

Root/NFQUEUE 与 VPN/TUN 应共享同一个 `OwnerSelector` 和 Primary Software Distributor，但不能强行共享同一种收包线程拓扑：

- Android `VpnService` 给产品的是一个非阻塞 L3 packet fd。第一版把它视为一个 TUN ingress lane；不能把普通 Linux `IFF_MULTI_QUEUE` 能力假定为 Android API 能力。VPN 的 transport-return fd 是另一个逻辑 ingress lane，也必须重新计算 owner，不能直接绕过 worker 写回 TUN。
- NFQUEUE 可以提供多个 kernel queue/socket lane，但 queue number 只负责增加 ingress 并行度。它不能成为 policy worker id，也不能成为 flow ownership 的正确性来源。
- `clib_file` 可以用 `polling_thread_index` 把 fd 直接固定给一个标准 VPP polling thread。callback/input pump 必须 bounded，并在该 VLIB-managed 执行上下文内完成 `read/recv -> VLIB buffer -> steering parse -> owner batch`。thread 0 readiness fan-out 只作为已验证 POC 的兼容形状，不是必经中转。
- 不建议第一版增加普通外部 pthread，让它直接调用 VLIB buffer/graph API；若通过 raw-packet ring 接回 VPP，又会增加一层 ownership、copy、backpressure 和 teardown 协议。
- Primary Software Distribution 必须按 target worker 成批、第一次直接投到最终 owner。queue 选错、CPU fanout、固定 ingress worker 都不得退化成正常路径的第二次 worker handoff。
- NFQUEUE 的 verdict 必须回到拥有相应 queue/socket 的 adapter completion lane；这是 completion routing，不是 worker handoff。

暂定的生产形状是：**每个 ingress lane 的 Primary Distributor 与 fd owner 共置；fd owner 是固定的 VLIB-managed polling context。** 第一轮从 `compact` profile 开始，让 bounded pump 在 thread 0 运行；若 thread 0/main-loop 数据成为瓶颈，再把 fd 移到一个标准 VPP worker，必要时将该 worker 保留为 I/O-only 并排除出 WorkerMap。普通外部 pthread 不是第一步。`compact` 与 I/O-only 形状必须通过真机 throughput、p95/p99、screen-off power、wakeup 和 thermal 数据决定默认值，不能靠线程数量直觉决定。

## 2. 需要分开的五个概念

| 概念 | 职责 | 是否决定 flow owner |
| --- | --- | --- |
| Capture source | 一个 TUN/transport fd，或一个 NFQUEUE queue/socket | 否 |
| Ingress lane | 独占一个 capture source 的读取与 lease；包含一个 Primary Distributor instance | 否 |
| I/O polling thread | 承载一个或多个 lane 的 fixed VLIB polling context | 否 |
| Primary Software Distributor | 用统一 Canonical Flow Key/Fragment Key 计算最终 owner，按 target 组织 frame | 是 |
| Adapter completion lane | NFQUEUE verdict、TUN/transport write 与 adapter handle 生命周期 | 否 |

因此 lane、I/O thread 与 policy worker 数量不能互相推导：

```text
ingress_lane_count >= io_polling_thread_count
io_polling_thread_count independent of policy_worker_count
```

每个 capture source 恰好有一个 ingress lane/owner；多个 lane 可以串行共用一个 I/O polling thread，但那不会获得并行 receive。它们都在启动时固定。`WorkerMap` 只包含允许拥有 flow/session state 的 policy workers；专用 I/O thread 不应出现在该映射中。

## 3. 已确认的外部事实

### 3.1 Android VpnService/TUN

Android 官方文档定义 `Builder.establish()` 返回一个 fd：每次 read 取得一个发往 VPN interface 的 outgoing IP packet，每次 write 注入一个 incoming IP packet；fd 默认是 non-blocking。AOSP 当前 native create path 以 `IFF_TUN | IFF_NO_PI` 创建该 fd，没有 `IFF_MULTI_QUEUE`；AOSP SELinux policy 也禁止普通 app 自行 open TUN device 或执行 `TUNSETIFF`/`TUNSETQUEUE`。由此可得：

- Android 产品接口天然适合 readiness + bounded drain，不适合永久 polling；
- fd 上是 L3 IP packet，不应假造 Ethernet/RSS metadata；
- Android API 没有向 app 暴露“为同一个 VpnService TUN 再创建 N 个 queue fd”的契约。

Linux 通用 TUN/TAP 确实从 3.8 起支持 multiqueue，但其接口要求 userspace 以相同设备名多次执行 `TUNSETIFF + IFF_MULTI_QUEUE` 获得多个 fd。这个机制不能自动投射到 `VpnService.Builder.establish()` 返回的 fd；除非后续在具体 Android 内核、权限和 API 上另行验证，VPN profile 必须按单 fd 设计。

`dup()`/`ParcelFileDescriptor.dup()` 也不会产生新 TUN queue：新 fd 仍指向同一个 open file description、`tun_file` 与 packet ring。多个 reader 只会竞争下一包，没有 flow affinity，并可能引入完成乱序。TUN `readv()` 一次也仍只消费一个 packet；它可把单包 scatter 到 VLIB buffer chain，但不是 `recvmmsg()` 式 packet burst。有效的 batching 来自 non-blocking readiness 后多次 read，直到 packet/time budget 或 `EAGAIN`，再一次 vector enqueue。

### 3.2 NFQUEUE

`--queue-balance` 会把 packet 分到一个 queue range，man page 表述为同一 connection 留在同一 NFQUEUE；`--queue-cpu-fanout` 则直接以 CPU id 映射 queue。上游 Linux 当前 `nfqueue_hash()` 的实现也不是 Sakamoto 的 canonical five-tuple：IPv4 路径使用 canonical address pair + IP protocol，未混入 ports；当前 IPv6 路径甚至只抽取部分 address words。由此可得：

- kernel queue selection 可以减少 ingress 争用，但不是我们的 owner hash；
- queue stickiness 即使在某个目标 Android kernel 上成立，也只能是性能提示，不能是 session correctness 前提；
- 必须在实际 vendor kernel 上记录版本并验证 hash/queue 行为，不能只引用当前 upstream；
- `queue-cpu-fanout` 与 direction-independent flow ownership 目标不一致，第一版不应作为默认；
- 同一 remote pair 上的大量连接可能集中到少量 queue，随后仍需统一软件分流到 policy workers。

第一版默认候选是 `--queue-balance`，因为它至少提供粗粒度的双向/分片 lane locality；`--queue-cpu-fanout` 只进入真机 benchmark。前者仍不是 correctness guarantee，若 vendor kernel、NAT/hook placement 或地址变化破坏 locality，统一软件分流与 Fragment Coordinator 必须照常正确。

Root hook 应让同一 IP family 的 INPUT/OUTPUT 使用同一个 queue range，减少正反包跨 lane；这仍只是性能优化。同一 flow 若从多个 lanes 并发到达同一 owner，VPP worker 只能保证“进入 worker queue 之后”的串行处理，不能恢复两个 producers 之间原本的全局到达顺序。第一版 L4 stateless policy 要记录该现象；未来 Stateful CT/TCP reassembly 必须显式容忍或约束 bounded reordering，不能把 single-owner 误写成 automatically ordered。

kernel 中每个 NFQUEUE instance 绑定一个 netlink `peer_portid`，从不同 portid 发送 verdict 会被拒绝。libnetfilter_queue 没有为共享 handle 声明线程安全，其 queue-handle list 也没有内部锁。因此第一版推荐一个 queue instance、一个 netlink socket、一个 ingress/completion lane owner；policy worker 不直接操作 `nfq_handle`。

libnetfilter_queue 明确允许 verdict 异步返回，因为 packet id 足以标识待决 packet；同时 kernel queue 有 bounded max length，应用读取不及时会出现 `ENOBUFS`，queue 满时 kernel 会 drop，除非显式配置 fail-open。packet id 是每个 queue instance 内的 32-bit sequence，不是全局 id；产品 lease token 至少是 `{laneGeneration, queueNum, packetId}`。kernel 没有逐 packet verdict timeout，socket/instance teardown 会把 pending entries 以 DROP 收口，所以 deadline、credit、stale completion 和 shutdown drain 都是 userspace 责任。

三个故障开关必须分开：iptables `--queue-bypass` 只处理 queue/listener 不存在；`NFQA_CFG_F_FAIL_OPEN` 处理 kernel queue full 或 netlink delivery failure；`workerBackpressurePolicy` 处理我们自己的 frame/completion capacity。它们不能压成一个 `failOpen`。对防火墙而言 fail-closed 是安全默认候选，但仍需作为产品/runtime decision 明确确认。

`nfq_set_verdict_batch(id)` 也不是一般的 multi-verdict syscall batching；它会把同 queue 中所有 `packetId <= id` 的 pending packet 设成相同 verdict。异步 workers 不能直接使用，除非 lane 已证明形成连续且 verdict 相同的完成前缀。

### 3.3 VPP 执行模型

VPP input node 可以在 interrupt mode 下被唤醒，frame queue API 可以按每个 packet 的 thread index 将一个 vector 压缩成 target-specific groups，再入对应 worker queue。fork 本地源码还显示：

- `clib_file_t` 含 `polling_thread_index`，Linux epoll 层为各 VPP main/thread 管理 polling context；callback 可直接在选定标准 VPP thread 的 `unix-epoll-input` 上执行；
- input node runtime 会复制到各 VLIB thread；
- `vlib_node_set_interrupt_pending(vlib_get_main_by_index(i), node)` 可以精确唤醒 thread `i` 上的 input node；
- 跨线程 interrupt 使用 atomic pending bit；
- `vlib_buffer_enqueue_to_thread()` 已能在一次调用中按 `thread_indices[]` 对 vector 分组，不需要逐包调用。

这支持两个不额外增加 raw-packet ring 的形状：优先把 fd 直接固定给目标 VLIB polling thread；若特定平台/版本不能这样绑定，则由 thread 0 callback 只设置 lane pending bit并唤醒目标 VLIB RX thread。二者都应由 VLIB context 直接分配 buffers、读取 packet、计算 owner，再批量 enqueue。

还要注意标准 `vlib_buffer_enqueue_to_thread(..., drop_on_congestion=1)` 的语义：失败的 buffer 会在函数内部被 free，调用者只得到成功数量，拿不到具体失败 buffer identity。这对普通 packet drop 足够，对仍欠 kernel verdict 的 NFQUEUE `PacketLease` 不够。生产 NFQUEUE distributor 需要 completion-aware enqueue：要么扩展 helper 返回失败 descriptors，要么预准入 homogeneous target batch，要么使用 adapter-owned descriptor queue；不能盲用内部 auto-free。

## 4. 本地代码审计

### 4.1 TUN POC 已证明和未证明的部分

`experiments/vpp-nfq-poc/overlay/src/plugins/tun_poc/tun_poc.c` 当前行为是：

```text
clib_file callback on thread 0
  -> signal input node on thread 0
  -> read TUN into shared rx_buf
  -> allocate one VLIB buffer
  -> memcpy packet
  -> per-packet enqueue to fixed target thread
```

它已证明 TUN fd readiness、interrupt input、VLIB buffer 和 frame-queue handoff 可行，也已在 POC 中观察到 packet 从 thread 0 到 worker。它没有证明生产软件分流，因为：

- 先读入共享 `rx_buf` 再 copy 到 VLIB buffer；
- 一次只分配、解析、enqueue 一个 packet；
- target 是固定 thread，不是 canonical five-tuple owner；
- worker 还可以再次 redirect，形状更像“固定入口后纠偏”；
- 没有多 target batch、owner guard、completion lane 与 teardown barrier。

生产实现应直接 read 到预分配 VLIB buffer data area（或已证明安全的 chain），在一个 bounded burst 内生成 `buffer_indices[] + target_threads[]`，只调用一次批量 enqueue。Android MTU 与单 buffer capacity 必须在 startup preflight 中校验；不满足时显式使用 buffer chain 或拒绝配置，不能截断 packet。

### 4.2 NFQUEUE POC 已证明和未证明的部分

当前 `nfqueue_poc.c` 是一个 family、一个 queue、一个 handle/socket；fd callback drain netlink 消息，packet callback 内同步决定并发送 verdict。它证明基础 ACCEPT/DROP、bounded prefix 和 epoll idle 行为，不证明：

- 双栈/多 queue 并发；
- NFQUEUE packet 进入统一 VLIB owner graph；
- verdict completion 跨 worker 返回；
- per-lease terminal outcome、at-most-once verdict intent 与 shutdown drain；
- queue overload、owner frame queue congestion 和 pending verdict 的组合语义。

### 4.3 fork handoff 不应原样复制

fork 的 `stellar-worker-handoff` 无条件调用 `vlib_buffer_enqueue_to_thread()`，既承担软件首次分流，也承担 hybrid/hardware 分错后的修正。Sakamoto 已确认要把两者拆开：

- Primary Software Distribution：正常路径，第一次直接投最终 owner；
- Corrective Handoff：Owner Guard 发现 mismatch 后最多一次；
- Fragment Steering transition：fragment owner 到 flow owner 的阶段转换，不消耗纠偏额度；
- Adapter completion routing：返回 queue/fd owner，不计入 worker handoff。

## 5. 候选拓扑比较

| 方案 | 优点 | 主要问题 | 判断 |
| --- | --- | --- | --- |
| thread 0 完成 bounded RX + direct distribution | 最少线程与 wakeup；当前 POC 最近；无额外 raw ring | packet burst 会占用 VPP main/control；多 NFQUEUE fd 扩展性有限 | 第一实现基线与 `compact` profile |
| 普通外部 pthread 直接操作 VLIB | fd ownership 清楚；容易绑核 | VLIB buffer/graph/thread registration 安全边界不清；生命周期复杂 | 第一版不采用 |
| 普通外部 pthread -> raw packet ring -> VLIB | 与 VLIB API 解耦 | 多一次 copy/ownership/backpressure；正好抵消软件分流效率目标 | 第一版不采用 |
| fd 用 `polling_thread_index` 绑定标准 VPP worker | 不增加 packet copy/中转 wakeup；buffer/node/thread 都在 VLIB 边界内；隔离 main | 占用一个标准 worker；callback/pump 必须 bounded；需验证目标 Android build | main 成瓶颈后的首选扩展 |
| thread 0 仅 fan-out readiness 到指定 VLIB RX lane | 适配不能直接移动 fd 的平台；仍无 raw packet ring | 多一次 interrupt wakeup和 pending 协议 | 兼容备选，不作默认必经路径 |
| 每个 NFQUEUE queue 直接绑定一个 policy worker | 少一次 cross-worker enqueue 的机会 | kernel queue hash != OwnerSelector；VPN 单 fd 无法复用；correctness 依赖拓扑 | 禁止作为语义模型 |

这里的“一个 ingress lane”不等于“一个 OS thread”。每个 fd/queue 都有自己的 distributor instance 和唯一 owner，但多个实例可以落在同一个 VPP polling thread 上串行执行；若使用 fan-out 兼容形状，则通过 pending-fd bitmap 做 bounded round-robin drain。NFQUEUE 若要获得真正并行 RX，推荐每 queue 使用独立 netlink socket并落到独立 owner context；仍从 1/2 个小数量开始，避免按 `hardware_concurrency()` 为每个 family 自动扩张线程。

## 6. 推荐的数据路径

### 6.1 共用模块

```text
FdReadinessFanout
  -> AdapterRxLane::drainBounded()
  -> SteeringParser::buildKey()
  -> OwnerSelector::select()
  -> PrimarySoftwareDistributor::enqueueBatch()
  -> OwnerGuard
  -> policy / flow / session graph
  -> AdapterCompletionRouter
```

`SteeringParser` 只解析 owner 所需的最小 L3/L4 envelope，不提前做 UID lookup、policy lookup、telemetry 或 DPI。它与 Owner Guard 必须复用同一 key encoder、hash seed 与 immutable WorkerMap。

一次 RX invocation 的建议行为：

1. 在 packet 数量和 wall-clock budget 两方面 bounded drain；
2. TUN 优先直接 read 到预分配 VLIB buffer/chain；NFQUEUE 必须先接收完整 netlink message，再把所需 payload/sidecar 做一次明确的固定池 copy，不能假装是 NIC zero-copy；
3. 逐包构造 normalized steering key 和 target thread index；
4. 对 malformed/truncated/fragment 输出明确 parser status；
5. 对正常 packet 一次调用 vector enqueue，由 VPP 按 target 分组；NFQUEUE 必须使用能保留失败 lease identity 的 completion-aware 变体；
6. target frame queue 拥塞时不改投其他 worker；执行 adapter-specific overload completion；标准 VPP auto-free/drop 返回值不足以实现 NFQUEUE per-lease terminal outcome；
7. burst 达到上限且 fd 仍 readable 时重新 arm/pending，避免独占执行线程。

### 6.2 VPN/TUN profile

```text
Android TUN fd (outbound) -------+
                                  +-> common Primary Software Distributor -> N policy workers
HEV/transport-return fd ----------+
                                                              |
                         +------------------------------------+-------------------+
                         v                                                        v
       allowed outbound to HEV/transport egress owner          allowed return to TUN write owner
```

TUN fd 与每个 transport-return fd 都只有一个 reader/owner；它们可以共用同一 VPP I/O polling thread，但每一方向都调用相同的 direction-independent OwnerSelector。VPN profile 不因 Linux TUN multiqueue 文档创建虚假的多 queue 抽象。以后若 platform adapter 真正获得多个 fd，只增加 ingress lanes，不改变 OwnerSelector、policy worker 或 FlowEntry identity。

### 6.3 Root/NFQUEUE profile

```text
Q kernel NFQUEUE queues
  -> Q Rust queue/socket Platform I/O Lanes
  -> VPP Initial Execution Placements
  -> common Primary Software Distributor
  -> N policy workers
  -> Completion Frames carrying {buffer, lane, queue, packet-id, verdict}
  -> original Rust lane batches verdicts and returns buffers
```

每个 queue handle/socket 在运行期由一个 Rust Platform I/O Lane 独占 receive 与 verdict。Rust 将
packet 直接物化到 VPP buffer，再批量投递 Initial Execution Placement；VPP worker 不直接操作
NFQUEUE fd。多个 Flow owners 回到同一 lane 时，只移动预分配 Completion Frames，不复制 payload。
lane 无 input/completion 时在 readiness wait 中睡眠；armed 后只允许 empty→nonempty 的一次合并
`eventfd` wake，不得 per-packet wake 或忙轮询。Completion Frame 的具体 SPSC/MPSC 物理拓扑仍待
独立决定，不能由本研究先行写死。ingress enqueue 必须保留
`{buffer, laneGeneration, queueNum, packetId}` 对应关系直到 worker 接收。每个已接收 packet 最多
发送一次 verdict intent；Netlink send 成功不等于 end-to-end ACK。completion capacity、missing
packet id、worker fault 和 shutdown 都不能静默悬挂 packet。

TUN/HEV 路径也不能让多个 policy workers 无契约地同时写共享 shim/transport fd。允许 packet 应进入单写者 egress/completion lane，或使用已经证明支持多 writer 且维持 packet framing 的接口。

## 7. Overload 与 teardown 是第一版边界，不是后补优化

至少需要固定以下容量：

- per-lane VLIB buffer budget；
- 每次 RX 的 packet/time burst；
- per-target frame queue capacity；
- NFQUEUE pending packet/verdict capacity；
- per-worker/per-lane completion capacity；
- fragment/reassembly capacity。

目标 worker queue 满时禁止 alternate-worker fallback。VPN packet 可按 overload policy drop；NFQUEUE lane 必须生成配置好的 overload verdict。listener-missing bypass、kernel queue 的 `NFQA_CFG_F_FAIL_OPEN` 与 userspace worker/completion overload 是三个不同层次，必须分别配置和观测。

建议 teardown 顺序：

1. 停止安装新 hook/route，并把 runtime 标记为 quiescing；
2. 从 readiness set 移除 fd，禁止新的 RX batch；
3. 等待所有 RX node 离开 drain 临界区；
4. drain/cancel owner frames 与 completion frames；
5. 对所有仍持有的 NFQUEUE packet id 给出明确 verdict；
6. 关闭 queue handles/fds；
7. 最后释放 frame queues、buffers、WorkerMap 和 worker-private state。

## 8. 分片仍有一个独立未决问题

Primary Software Distributor 对非初始分片拿不到 ports，因此仍按已接受的 Fragment Steering 两阶段处理：先按 fragment-safe key co-locate，完成 bounded reassembly 后再切到完整 five-tuple flow owner。这个阶段转换不是 Corrective Handoff。

但 NFQUEUE 与 VPN 对“完整重组”的资源语义不同：NFQUEUE full reassembly 可能需要同时保留一个 datagram 的多个 kernel packet ids，并最终逐个返回 verdict；VPN 已经拥有 packet bytes。本文不改变现有分片决策，但要求在 production NFQUEUE Adapter 之前单独验证 retained-id capacity、timeout verdict、overlap/malformed 处理、512-byte prefix 是否足够，以及 shutdown 时如何处理未完成 datagram。

## 9. 建议的验证顺序

1. **Rust event-driven RX POC**：验证 Rust 独占 TUN/NFQUEUE fd，readiness 后 bounded drain 直接物化到 VPP buffers；idle 不 polling，关闭时无 race。
2. **Vector distributor POC**：Rust ingress burst 构造多 target arrays 并批量投递 VPP；验证正反向同 flow 必到同 owner，正常 corrective handoff 为零，同时验证 VPP workers 在无 work 时能被唤醒并重新休眠。
3. **NFQUEUE multi-lane completion POC**：至少双栈、两个 queue/socket/Rust lanes；证明 queue id 与 owner id 解耦，Completion Frames 带 lane generation 回原 lane，多个独立 verdict messages 能拼入一个 Netlink datagram，并保持 at-most-once verdict intent。
4. **Fault/overload POC**：target frame queue full、completion queue full、ENOBUFS、missing packet id、worker crash、adapter shutdown 和第二次 owner mismatch。
5. **Android profile matrix**：比较 Rust I/O Lane 数、VPP worker 数和 queue 数组合，不直接从 CPU 数推导默认值；同时记录 idle wakeups、screen-off power 与满载 thermal behavior。

必须采集：

- ingress pps/bps、per-lane backlog/drop/ENOBUFS；
- RX burst size、target-group count、frame fill ratio；
- owner distribution skew、corrective handoff count/reason；
- completion latency、pending verdict high-watermark、duplicate/stale/missing terminal-outcome faults；
- end-to-end verdict p50/p95/p99；
- thread 0 与每个 RX/policy worker CPU time；
- scheduler wakeups、CPU frequency residency、screen-off current、thermal throttling；
- shutdown drain time与 residue。

## 10. 当前建议提升为 decision 的内容

以下结论证据已经足够，但仍等待本轮讨论确认：

1. capture source 与 ingress lane 一对一；多个 lanes 可共享 polling context；polling-context 与 policy-worker 数量独立且启动时固定；
2. queue/fd/lane 只属于 adapter ingress，不进入 WorkerMap，不决定 flow owner；
3. fd callback/pump 固定在一个 VLIB polling context，不执行无界 read/recv 或 packet policy；允许直接绑定目标 VPP thread，thread 0 fan-out 仅是兼容实现；
4. packet bytes 进入 VPP 后只走 VLIB-managed buffer/node/frame queue；第一版没有 external raw-packet pthread ring；
5. Primary Software Distributor vectorized direct-to-owner；normal path 不先投固定 worker；
6. NFQUEUE handle/socket 单 lane 独占，ingress enqueue 保留 lease identity，policy result 经 completion routing 回原 lane；标准 `drop_on_congestion=1` 不能直接承担这项契约；
7. `compact` 与 `io-worker` 是 startup topology profiles，correctness 和 policy semantics 完全相同；先实现 compact，只有测量表明 main 是瓶颈时才保留标准 VPP I/O-only worker。

## 11. Sources

外部一手资料：

- Android `VpnService`: <https://developer.android.com/reference/android/net/VpnService>
- Android `VpnService.Builder.setBlocking`: <https://developer.android.com/reference/android/net/VpnService.Builder#setBlocking(boolean)>
- AOSP VPN TUN creation: <https://android.googlesource.com/platform/frameworks/base/+/master/services/core/jni/com_android_server_connectivity_Vpn.cpp>
- AOSP app TUN neverallows: <https://android.googlesource.com/platform/system/sepolicy/+/db60355f9483acaad0dc4de52a0df67ea96d9326/private/app_neverallows.te>
- Android common kernel TUN driver: <https://android.googlesource.com/kernel/common/+/refs/tags/android14-5.15-2023-06_r9/drivers/net/tun.c>
- Linux TUN/TAP multiqueue: <https://docs.kernel.org/networking/tuntap.html#multiqueue-tuntap-interface>
- iptables NFQUEUE target: <https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html>
- Linux NFQUEUE hash source: <https://codebrowser.dev/linux/linux/include/net/netfilter/nf_queue.h.html>
- Linux nft queue source: <https://codebrowser.dev/linux/linux/net/netfilter/nft_queue.c.html>
- Linux nfnetlink_queue source: <https://codebrowser.dev/linux/linux/net/netfilter/nfnetlink_queue.c.html>
- Linux NFQUEUE target source: <https://codebrowser.dev/linux/linux/net/netfilter/xt_NFQUEUE.c.html>
- libnetfilter_queue documentation: <https://netfilter.org/projects/libnetfilter_queue/doxygen/html/>
- FD.io VPP input interrupt API: <https://docs.fd.io/vpp/19.04.3/d8/dd1/node__funcs_8h_source.html>

本地证据：

- `experiments/vpp-nfq-poc/overlay/src/plugins/tun_poc/tun_poc.c`
- `experiments/vpp-nfq-poc/overlay/src/plugins/nfqueue_poc/nfqueue_poc.c`
- `experiments/vpp-nfq-poc/EXPERIMENT_LOG.md` sections 54-56
- `/home/js/backup/backup/Git/vpp/src/vnet/handoff.c`
- `/home/js/backup/backup/Git/vpp/src/vlib/buffer_funcs.c`
- `/home/js/backup/backup/Git/vpp/src/vlib/node_funcs.h`
- `/home/js/backup/backup/Git/vpp/src/vlib/threads.c`
- `/home/js/backup/backup/Git/vpp/src/vlib/unix/input.c`
- `/home/js/backup/backup/Git/vpp/src/vppinfra/file.h`
- `/home/js/backup/backup/Git/vpp/src/vnet/dev/runtime.c`
- `docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md`
- `docs/reviews/VPP_CORE_DATAPATH_FEASIBILITY_INVESTIGATION.md`
- `docs/reviews/VPN_TUN_DATAPATH_ADAPTER_INVESTIGATION.md`
- `docs/reviews/NFQUEUE_PERFORMANCE_ARCHITECTURE_REVIEW.md`
