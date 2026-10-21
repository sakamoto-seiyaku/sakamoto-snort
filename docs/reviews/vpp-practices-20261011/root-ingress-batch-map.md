# Root ingress 与 admit preparation：代码级批处理缺口地图

日期：2026-10-11。范围是当前 C/VPP 产品的接收成帧与独立解析准备；本文提出接口草图，没有实现、票据或新基准测试。约束取自 ADR-0006/0007/0008、`PER_WORKER_FLOW_OWNERSHIP.md` 与 `VPP_PACKET_METADATA_OWNERSHIP.md`；不使用已删除 C++、deprecated NFQ 或 POC 作为产品实现模板。

## 1. 源码身份与证据层次

产品 HEAD 为 `54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6`，本图三份产品执行源与 HEAD 字节一致；参考 fork `/home/js/backup/backup/Git/vpp` 的 HEAD 为 `837432be3b6cf496755cfa27b7cca439734eb726`。逐字节比较 `git show HEAD:<path>` 与工作树，fork 的 `src/plugins/stellar_dissector/dissector_node.c`、`dissector.c`、该目录 `CMakeLists.txt`、`src/vnet/handoff.c`、`src/vnet/CMakeLists.txt`、`src/vnet/unix/tuntap.c` 均一致。两个执行源的 HEAD SHA-256 分别为 `c13ab946584eafda97de8991ac350bd299e226b9a53174042b73a5e08a9bac7a`、`80c8686aa8b8cac6a2e384a62576acfb2a125a7168a74ac1c584fde0ca4048b4`。

官方基线从 `build-output/pinned-vpp-clean` 的 **git 对象** `9258530f3804a152578ce11cc7c8a1e9eab88ed0:<path>` 读取。此轮核对的 `src/vnet/handoff.c`、`src/vlib/buffer_funcs.c`、`src/vlib/buffer_node.h` 工作树与官方对象相同；产品 retained API 则是仓库 core patch 的能力，不能归到未修改官方源码。

以下“已用”指进入已注册节点的源码控制流。“可用”指 pinned API/构建声明具备该能力；没有 fork ELF、启用配置、实际 frame 分布或 Android ISA 运行证据，因此不声称 fork 已部署这些路径，也不声称预取有性能收益。

## 2. fork 已用什么，产品缺什么

| 实践 | fork 的确切位置与控制流 | 当前产品 |
| --- | --- | --- |
| x4 与下一组预取 | [dissector_node.c:96](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:96) 的 `flow_dissector_node_fn`；:117 在输入至少 8 项且 next 有 4 槽时处理 4 项，:127–143 预取后 4 项 header/data，:179–182 仍是四次独立 `flow_dissector`，:283 使用 `vlib_validate_buffer_enqueue_x4`，:289 有 scalar 尾部 | [product_packet_graph.c:1254](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1254) 每包 `vlib_get_buffer`、构造 ingress、调用一次 `product_packet_admit`；没有 x2/x4 或 lookahead |
| 整帧指针准备、短组 owner 准备 | [handoff.c:439](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:439) 的 `worker_handoff_node`，:456 一次 `vlib_get_buffers`，:464 x4，:468–479 预取下一组，:498–510 四路 parser/hash，:528 scalar 尾部 | admit 在 :1257 取一个 buffer，:1263 建一次相同 layout，:1318 单包 parse/owner；可外提固定 layout/worker，复用已取得 frame |
| bulk 出口与计数 | fork handoff :584 一次传 `frame->n_vectors` 给线程 enqueue；dissector :338 put next、:342–345 汇总两个 parser counter | admit :1392 传 count=1 到 next helper；primary :1213 也传 count=1。next helper 能聚合后续 frame，但 helper/准备调用仍逐包；第一跳 external 则明确每包新 frame |
| 实际注册与构建 | dissector :350/357/363 节点函数调用同一核心，:370/384/398 注册，:412–445 注册 feature arcs；[dissector.c:138](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector.c:138) 实际 enable features。其 [CMakeLists.txt:14](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/CMakeLists.txt:14) 列 SOURCES 与 MULTIARCH_SOURCES。handoff :597 注册 `stellar-worker-handoff`，:1227/1229 enable device/port arcs；[vnet/CMakeLists.txt:48](/home/js/backup/backup/Git/vpp/src/vnet/CMakeLists.txt:48)、:67 分别列普通和 multiarch 源 | [产品 CMakeLists.txt:228](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/CMakeLists.txt:228) 普通 SOURCES 包含 packet、graph 与 Root adapter；未声明这些源为 MULTIARCH。构建声明不能代替机器码或执行证据 |

这些是展开、访存准备与 bulk API 使用，四次 scalar parser 不等于四包 SIMD。官方 pinned [handoff.c:110](/home/js/Git/sakamoto/sakamoto-snort/build-output/pinned-vpp-clean/src/vnet/handoff.c:110) 已整帧取指针，:148 已 bulk 线程提交，但 :115–141 仍 scalar hash；应把通用 VPP 能力和 fork 的 x4 增量分开。fork `tuntap_rx` 的 [tuntap.c:287](/home/js/backup/backup/Git/vpp/src/vnet/unix/tuntap.c:287) `readv` 是一个 packet 向多个 buffer 的 scatter，:370 提交一个 packet，不能作为 multi-packet receive 依据。

## 3. Root 成帧出口：应改接收循环与提交接口

当前链为 `product_root_nfqueue_read_ready` → 一个 native receive buffer → NFQ envelope 验证/平台事实归一化 → `product_root_nfqueue_reserve` → `product_packet_graph_submit_external` → 新建 `n_vectors=1` admit frame。接收预算在 [adapter:1027](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_root_nfqueue_adapter.c:1027) 为 64；:1115–1129 明确只接受单 packet datagram，异常 envelope、reserve buffer、超长报文走 `accept_unadmitted`。:1227 预留独立 pending，:1275 提交；[graph:4089](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:4089) 每次 get frame、写一个 index、put frame。64 次 read 不是 64 项 graph frame。

拟议添加按值描述项与批量入口，保留原单项 API 作为 `n=1` 包装，避免同时改坏 VPN TUN 与 Flow Stack return 调用语义：

```c
/* 示意契约，不是产品补丁。facts/obligation 均对应这一 bi。 */
typedef struct {
  u32 bi;
  product_platform_packet_facts_t platform;
  product_adapter_obligation_t obligation;
} product_external_item_t;
u32 product_packet_graph_submit_external_batch(
  vlib_main_t *vm, const product_external_item_t *items,
  u32 n, u8 accepted[]);
```

`accepted[i]` 表示该项已进入 native scheduling，拒绝项仍由 Adapter 持有。helper 对每项保留 [graph:4061–4075](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:4061) 的 origin/thread、kind、generation、enabled/accepting 和 VPN return 特例检查；只压缩合法项到一个至多 `VLIB_FRAME_SIZE` 的 frame。写每包 overlay、平台事实和 lifecycle debt，紧接着 `vlib_put_frame_to_node`，接受点不得被提前解释为完成 verdict/free。不能用首项 obligation 或平台事实覆盖全批。

Root 回调只聚合本次已经收到的正常项，局部固定数组最多覆盖当前 64 read budget；保留 `receive_slot`、pending identity 和拒绝回退所需 envelope 长度。满窗口、预算结束或 read 遇 EAGAIN/ENOBUFS 都同步 flush，不等待下一包，不跨回调保留局部指针。每个拒绝项仍执行 :1280–1287 的 pending 撤销、fail-open verdict、receive-slot 归还；成功项只用本地身份副本记账，不能再借用已移交 buffer。`product_root_receive_pool.h:12–15` 的 64 normal + 8 reserve 仍是预分配边界，reserve 项不进入 graph。

异常提前退出是必需改动点：:1066 discard 错误、:1098 recv 错误、:1302 listener 故障都不能把已 reserve 而未发布的项遗留在局部数组。统一出口在标记 fault 前 flush/逐项退回；`mark_lane_fault` :269 保留 verdict FD 供已接纳义务排空。CLI 的 `listener_fault_after_submit` 明确是一个真实接纳包，设置时必须强制单项 flush，接纳后立即触发原故障，不能先多读一批才注入。

## 4. admit 的纯 prepare x2/x4：改 node 外壳，不重写 parser

`product_packet.c` 已有纯准备边界：[parse_ingress:331](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet.c:331) 校验输入、按包生成 facts/错误终态；[admit:386](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet.c:386) 加一次 `product_owner_assign` 和 local/remote 判定。它们不操作 flow、credit 或 graph publication。可给同一语义添加短窗口包装：

```c
void product_packet_admit_prepare_n(
  const product_worker_layout_t *layout,
  const product_packet_ingress_t in[], product_packet_lease_t out[],
  product_packet_result_t result[], u32 n); /* n = 1/2/4 */
```

首版可以内部四次现有 `product_packet_admit`；进一步交错时，先对 n 项运行 `product_packet_parse_ingress`，再只对成功项运行 `product_owner_assign` 与原 distribution 赋值，初始化和每项 result 保持原语义，不宣称新 SIMD。node 一次取得 frame 指针，外提固定 layout/logical_worker；对尚未消费的下一短组预取 header 与 **`vlib_buffer_get_current` 所指 L3 区域**。Root buffer 的 `current_data` 在 adapter :1187 被推进到 NFQA payload，机械预取 `b->data` 可能只暖到 netlink envelope。只在下一组确实存在时 lookahead，1–3 项尾部立即执行；不为 x4 填造 packet。adapter :687 的 NFQ attribute parser 只快速读取 family/protocol 作接收观测，不能替代共享 bounded parser 或拿它的 IPv6 基础 next-header 直接选 owner。

处理顺序为“短组识别普通/fragment/prepared bundle → 普通项纯 prepare → 按原 index 提交各项副作用”。[fragment_dispatch:376](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_reassembly_graph.inc:376) 会改 overlay、排重组节点或远程发布，不能作为 speculative prepare；应拆出只读 fragment probe 与按序 dispatch，或遇异常项先结束普通短组再执行现有 dispatch。`fragment_bundle_count` 项继续 :1312 的 `product_lease_from_metadata`，沿用保存的 OwnerAssignment，不能又 parse/hash 选 owner。ordinary malformed L3 保留每包 runtime-drop reason；IPv6 extension walk、L4 unavailable 与 ICMP_QUERY 的现有语义不因批次统一化。混合 family、fragment、错误、本地/远程 owner 可在同一 frame 中逐项出不同 next。

## 5. 与 downstream publication 的依赖

admit 本地/terminal 项可紧凑收集到 `indices[]/nexts[]`，一次调用 `vlib_buffer_enqueue_to_next`；只收集仍持有的项，不把 fragment、remote 已接受或已 free 项塞回输出。数组遵守官方 [buffer_node.h:353](/home/js/Git/sakamoto/sakamoto-snort/build-output/pinned-vpp-clean/src/vlib/buffer_node.h:353) 的 `VLIB_BUFFER_ENQUEUE_MIN_SIZE` 可读 padding；bulk getter 同样审查 :186–217 的取整读取，不能拿裸 4 项栈数组假设所有 helper 都只读 count 项。

primary handoff 是另一个明确 seam：[graph:1185](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1185) 当前先逐项 reserve credit，再 count=1 retained enqueue。credit 默认在 :47 为每目标 owner 32；:970–1005 管理每包 reserve/release 与 lifecycle debt。Root 的 64 receive window 不能成为“先 reserve 64，再统一 publish”的 owner 窗口，那会让尚未发布的半批耗尽 credits。拟议提交窗口至多 32，逐项取得 credit、在已准备窗口内及时发布；credit 不足保持当前 bypass 结果，不等待、不借其他 owner。窗口更小也不是吞吐保证，仍需考虑真实并行消费时序。

bulk retained 接口的失败 indices 必须映射回原项，清 credit bit、release 本项 credit 并走原 terminal；成功发布之后不能读取该 buffer/header。预取也只能面向尚未转移的项。fork 的 `drop_on_congestion=1` 和整帧 `goto done` 不符合产品逐义务 settlement，不能照搬。completion return、policy/Flow/POST 的后续成批出口需与此接口对齐，但 prepare 不提前读取/冻结同 flow 的可变事实、不改变同 flow 原序，也不把 graph frame 当成共同终态。

本图建立了可改函数与必要前置条件：入口实际成帧让 x2/x4 有输入，admit 保住 frame 后才有 bulk next/publication 条件；这些步骤不自动减少逐包 `recv` 或 NFQ verdict 系统调用。落地前须核对混合异常、partial publication、credit 耗尽、stop/restart 和恰好一次清偿；本轮只有静态源码证据，没有性能、功耗或部署结论。
