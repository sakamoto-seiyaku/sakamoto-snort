# 当前 C 主线的 VPP 批量、流水线与并行机制审查

2026-10-11。产品基线：`54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6`；VPP pin：`9258530f3804a152578ce11cc7c8a1e9eab88ed0`。四个子代理分别审查 node、handoff、I/O/Flow Stack、查表/布局，主代理交叉核对关键实现并汇总。此记录是静态审查，优先级表示机制依赖和实现完整性，不是实测 CPU 热点排序；没有新性能数字或加速比例。

**主要缺口是批量路径没有贯通。** 当前已使用 VPP graph 和两个固定 owner worker，但入口将 read burst 拆成 singleton frame，node 主要一包准备到底，跨 worker producer 又逐包发布。可以同时利用的工作是独立包的准备、内存访问和发布；Flow/CT/UID/LPI/SNI 的状态更新仍必须按 owner 上原包顺序执行。官方 VPP 本身也是把整 vector 交给 node，再在 node 中逐包处理，并非把同一 flow 的所有状态更新同时执行。[官方 graph 说明](https://docs.fd.io/vpp/22.10/aboutvpp/extensible.html)、[固定 pin 的 ACL 准备与状态循环](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L243)。

## 最值得一起设计的五处缺口

| 优先面 | 当前实现的具体限制 | 可利用的 VPP 机制及结构性效果 |
| --- | --- | --- |
| 1. 入口真正成帧 | NFQUEUE/TUN 一次 readiness 最多进行 64 次读取，但每包都分配一个 `n_vectors=1` 的 external frame | 把本次已接纳的 indices 放入 native 多向量 frame，让后面的 node 有实际 batch；不等待下一次流量凑满 |
| 2. node 的准备与内存访问流水线 | admit/policy 等逐包取 buffer，完成该包准备、查询、更新后才开始下一包；没有 bulk pointer preparation 或显式 lookahead | `vlib_get_buffers`、短 x2/x4 准备窗口、header/data/bucket/record 分层预取，重叠独立包的访存延迟 |
| 3. 查表接口与热索引布局 | Flow 链的 `next` 位于大 entry 之后；条件 VPN 路径对同 tuple 可查表六次 | runtime 内的紧凑索引、受检查询结果复用和安全 prefetch 接口；命中后才读完整协议状态 |
| 4. 实际跨 worker publication | primary、completion、fragment retained enqueue 的 `count` 均为 1 | 在当前 dispatch 内按既定 target 批量发布；减少 ring reservation、valid publication 与通知 latch 操作，失败仍逐包结算 |
| 5. VPN 输入与 owner drain 的协调 | 每包独立进入 HEV/lwIP、分配/复制输入；输入调用只 schedule，后续 input node 用 8 quanta/200 μs bounded step 推进 | owner 内有界输入批次和 drain 协作，结合容量反馈组织工作；保持必要复制和非阻塞执行 |

第一、二、四、五项应作为一条路径评估。入口有了 batch，却没有查表流水线和及时 drain，可能只是一次更大的 admission burst；只改 enqueue helper，也无法补齐入口 singleton 的限制。第三项提供这条路径需要的查表接口和局部性，不要求先换 hash 算法。

```mermaid
flowchart LR
  A[同一次 read readiness] --> B[已接纳 indices 形成 native frame]
  B --> C[短窗口解析与 assignment 准备]
  C --> D[需要时按 target 批量 primary handoff]
  D --> E[owner 上预取查表并按序更新 policy / Flow]
  E --> F[VPN owner 输入与有界 drain]
  E --> G[terminal]
  F --> G
  G --> H[按 origin 批量 completion return]
```

图表示候选组织方式；已有 local 分支不需要 handoff，只有适用的 VPN 包进入 Flow Stack。

### 1. 入口 frame 是确定的单包，不会自动合并

Root/TUN 的读取预算分别见 [Root adapter](../../src/product/vpp/product_root_nfqueue_adapter.c#L1027)、[TUN adapter](../../src/product/vpp/product_vpn_tun_adapter.c#L317)。共用的 [external submit](../../src/product/vpp/product_packet_graph.c#L4043) 每包执行 `get_frame_to_node → n_vectors=1 → put_frame_to_node`。固定 pin 的 [get/put 实现](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/main.c#L99) 每次取得独立 frame、追加独立 pending entry；[dispatcher](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/main.c#L1613) 逐 entry dispatch，没有在这里合并。

因此，单独把 admit 改成 x4，常常仍无四包可处理。适合按已有 readiness budget 收集成功子集，逐包设置 facts、generation、origin obligation，再提交 frame；部分读取失败和 pregraph return 仍立即结算。TUN 的 `vlib_buffer_alloc(...,1)` 也可在这个边界考虑有界批量分配，但 Root 已有 receive pool，不能笼统称两边都欠缺池化。保持 Android TUN 的既有单 I/O lane、Root origin-lane confinement 和 callback 非递归。[I/O 专项](vpp-practices-20261011/io-flow-stack.md)。

### 2. 最直接的上游范例是 ACL 的准备加有序状态循环

当前 [admit](../../src/product/vpp/product_packet_graph.c#L1254) 和 [policy](../../src/product/vpp/product_packet_graph.c#L1596) 是逐包完整调用。固定 ACL node 则先整帧取得 pointers，分组准备 tuple/hash；状态循环再提前预取 bucket、索引数据、session。它保留 scalar 更新，并在创建/删除 session 后修正下一包相同 tuple 的预测。[ACL 准备](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L243)、[分层预取](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L352)、[创建后修正](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L527)。

产品可采用这种机制，设计自身短窗口接口；现有 parse-only helper 是 private，不能假定已有可直接调用的批量 API。先准备只读输入和做 prefetch，提交时按原序执行查找与 mutation。不要缓存全帧权威 miss、裸 entry pointer 或 POST verdict：前包建流、UID 冲突关闭、TCP replacement、expiry 都会改变后包结果；非相邻同 flow 也一样。规则的 CT/LPI/SNI 动态事实必须在当包更新后形成，snapshot 相关准备必须有有效 bank lifetime。[node 专项](vpp-practices-20261011/vector-nodes.md)。

### 3. Flow 查表值得同时做接口复用和冷热分离

当前 [flow slot](../../src/product/vpp/product_flow_entry.c#L8) 是完整 entry 后接 `next`；[lookup](../../src/product/vpp/product_flow_entry.c#L72) 比较前部 hash/key，链继续时再读远端的 `next`。TCP SNI 缓存的 `bytes[2][4096]` 本身已有 8192 bytes，这只是数组下界，不能据此声称每次 lookup 都读取 8 KiB。[entry](../../src/product/vpp/product_flow_entry.h#L100)、[SNI 缓存](../../src/product/vpp/product_sni.h#L21)。适合在 opaque FlowRuntime 内保留紧凑的 hash/key/next/slot 索引，命中后再访问协议状态；维持启动预分配、容量上限和原 FlowEnd 生命周期。

在 VPN product mode、OUTPUT、完整 TCP/UDP assignment、已有未过期流、UID known、没有替换/冲突、策略允许观察且 driver enabled 的路径，可到达六次同 tuple 查表：UID resolver current、graph current、enrich find、observe find、refresh current、egress current。这个条件和六个源位置已在 [查表专项](vpp-practices-20261011/lookup-data-layout.md) 逐项列出。应先合并同一同步 policy 操作的查询，返回有 owner/generation/slot/incarnation 身份的受检结果；跨 node 复用需要再次验证 linked、incarnation 和逻辑 deadline。避免新增 tuple side table 或将裸指针序列化进 buffer metadata。

### 4. Producer 批量发布与 receiver 合并是两件事

[Primary](../../src/product/vpp/product_packet_graph.c#L1213)、[completion](../../src/product/vpp/product_packet_graph.c#L1865)、[fragment](../../src/product/vpp/product_packet_fragment_graph.inc#L275) 的实际 retained publication 都是一包调用。固定 pin 的 [enqueue](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L303) 每次调用按 target 取得并发布一个 element；现有 [retained core patch](../../src/product/vpp/patches/core/0001-vlib-nonblocking-retained-enqueue.patch) 已接受 arrays 和 failed-index 集合，缺少的是产品完整调用路径。

另一方面，[receiver](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L471) 已把多个 element 合成 graph frame；普通 [`single_next`](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L195) 也向已有 next frame 追加。因此 `count=1` 不能统一解释成“每包跑整张图”。这里可减少的是 producer 操作，不是重建 receiver。

批量必须同时覆盖 primary 与 completion/retry，fragment 两阶段保持原 owner。保留各 target/origin 内顺序，每个失败 index 由发送方继续持有并结算，成功发布后不再访问 buffer。32 个 primary credits 的单位是 packet，在 policy receive 时归还；64/128 ring slots 的单位是 element。批量 packing 不会自动增大 packet credit 上限。不要把“扩大 capacity”混成同一机制收益。[handoff 专项](vpp-practices-20261011/handoff-scheduling.md)。

### 5. VPN 的 admission 和 drain 要共同组织

当前 [driver input](../../src/product/vpp/product_vpn_flow_stack.c#L296) 逐包 copy 后 schedule；[owner input node](../../src/product/vpp/product_vpn_flow_stack.c#L320) 后续接收 broker 消息并执行 8 quanta/200 μs 的 bounded step。这里的 quanta 是协程调度单位，不等于八个 packet。owner-local、fd/timer notification 和 bounded execution 都已实现；欠缺的是 frame 输入与这些服务预算的协作，以及摊薄每包独立进入/退出 HEV/lwIP context 的接口。

已有失败 batch 记录中的 `PACKET_CREDIT` 拒绝只能说明要核对 admission/drain/capacity，不能证明修改预算就会加速。HEV 的 packet credit 与 VPP primary handoff credit 也是两种不同账本。尤其不能在 full-copy 之前草率丢包：input 路径还可能有 incarnation/UID 不匹配时关闭旧 session 的副作用。候选接口应保持这些副作用和拒绝结果，保留两次所有权边界复制、owner 内执行和 graph 非递归返回。[I/O 与 Flow Stack 专项](vpp-practices-20261011/io-flow-stack.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md#2026-09-05-kiss-copy-and-ownership-contract)。

## 已利用、受约束和次级机会

| 分类 | 审查结论 |
| --- | --- |
| 已利用 | vector graph、native next-frame 累积、FQ receiver 合并、W2 私有 Flow/HEV、固定 affinity、解析/assignment 复用、56-byte inline metadata、worker policy cache、预分配 Flow 池、expiry 与 bounded completion backlog |
| 已利用 | Android worker notification latch 已合并 eventfd syscall；建议批量 publication 可以减少 latch 次数，但不能重建为每包 syscall、busy spin 或依赖 sleep flag |
| 受约束 | policy 每包 SC reader claim/release 是 bank 生命周期保护；改成每帧一次会改变 Apply 可见粒度，不能作为顺手优化 |
| 次级机会 | consumer/terminal 只读 routing/terminal 小视图，减少完整 lease 和重复 platform projection；保持 span/generation 校验、trace 和 END 分支 |
| 受平台与领域约束 | Android 单 TUN lane、origin-only NFQUEUE verdict、固定 canonical owner；不默认套用 DPDK/RSS/NUMA、多 TUN lane、跨 owner spill 或增加 worker 数量 |

前三行的依据分别见各专项、[metadata 恢复](../../src/product/vpp/product_packet_graph.c#L782)、[Android notification patch](../../src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch)、[snapshot claim/release](../../src/product/vpp/product_packet_graph.c#L435)。规则单 key 已有[编译器 NEON 证据](../testing/2026-10-11_PIXEL6A_INCREMENTAL_BATCH.md#L296)；没有显式 intrinsics 不等于二进制没有 SIMD。本审查的重点是跨独立包的工作组织。

上述建议限定于 [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md) 的 VPP-native C 主线。上游 C 代码是机制证据，POC 和已删除 C++ 不作为实现模板。

## 怎样判断后续实现真的使用了这些机制

验收应观察机制本身：admit 的 frame-size 分布、准备窗口、每次 publication 的 vectors/elements、每包查表次数、owner input/drain 的待处理量与年龄，以及各账本的拒绝原因。只统计 helper 调用减少不足以证明路径贯通。

正确性覆盖同帧及非相邻同 flow、首次创建/替换/expiry、UID 冲突、PRE/POST 动态事实、部分成功、fragment/END、配置发布、stop drain 和 exactly-once settlement。保持已有 ownership/capacity/timeout 契约后，再用稳定负载判断收益；本审查没有把已撤回的 batch 代码写成当前能力或证明它更快。[撤回记录](../testing/2026-10-11_PIXEL6A_INCREMENTAL_BATCH.md)。

## 并行专项报告

- [Node/frame 准备与查表流水线](vpp-practices-20261011/vector-nodes.md)
- [Handoff、completion 和 worker 排程](vpp-practices-20261011/handoff-scheduling.md)
- [Root/TUN I/O 与 owner Flow Stack](vpp-practices-20261011/io-flow-stack.md)
- [查表复用、索引布局和 metadata 投影](vpp-practices-20261011/lookup-data-layout.md)

只新增研究记录及索引；没有修改产品、运行设备或新增基准。专项中的候选接口和优先级尚未成为接受决策或 Plane 工作项。
