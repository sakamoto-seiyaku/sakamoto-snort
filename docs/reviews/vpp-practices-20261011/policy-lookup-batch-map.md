# Flow、规则查询与 owner policy 的批执行改动地图

日期：2026-10-11。范围是代码级 gap assessment；未修改产品、运行测试或建立性能结论。产品 HEAD 为 `54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6`，官方 VPP pin 为 `9258530f3804a152578ce11cc7c8a1e9eab88ed0`，参考 fork HEAD 为 `837432be3b6cf496755cfa27b7cca439734eb726`。遵守 ADR-0006/0007/0008、per-worker Flow ownership 与 metadata ownership：只讨论 C/VPP 产品，不导入 POC、恢复已移除 C++、扩大 buffer overlay 或改变 canonical owner。

**确定的缺口是跨查询的准备、访存与 snapshot 摊薄，以及 Flow 索引与大型状态的布局耦合。** 当前已有 parse/key/hash 复用、owner-local runtime、完整规则缓存、识别停止条件和单 key NEON，不能描述成“没有 VPP 批处理”或“没有 SIMD”。[`product_lease_from_metadata:852`](../../../src/product/vpp/product_packet_graph.c#L852) 沿用保存的 canonical hash/source projection 还原 typed key，没有再次 canonicalize/hash。Root 普通 TCP/UDP 通常每包仅一次 Flow key lookup；VPN 身份分支的重复查询应独立处理。

## 1. 当前调用链：先看 Root

[`product_packet_policy_node:1587`](../../../src/product/vpp/product_packet_graph.c#L1587) 逐包取 buffer、恢复 lease，然后调用 [`product_packet_graph_policy_on_owner:3899`](../../../src/product/vpp/product_packet_graph.c#L3899)。后者每包 acquire snapshot，执行 PRE，并在同一 snapshot 下完成 Flow/POST、decision 和 attribution，再 release。

| Root 普通完整 TCP/UDP 分支 | 实际 Flow 查询 |
| --- | --- |
| PRE NoMatch | PRE `3937` → `flow_observe:3949` → `product_flow_entry_observe:2713` → `find_entry:494` → POST `3958/3960`；一次 |
| PRE 完整 ALLOW | PRE → `policy_stage_snapshot:3960` → `flow_observe:3965` → 同一 `find_entry:494`；一次 |
| PRE 完整终态 DROP | 不进入 Flow observe；零次 |
| 无合格 typed Flow identity | `flow_observe:2675` 提前返回；零次 |

规则缓存命中不取消必要的 Flow 更新。逻辑 expiry 或 TCP replacement 还可能调用 [`product_flow_runtime_close:254`](../../../src/product/vpp/product_flow_entry.c#L254)，沿 bucket 链寻找 unlink 点 `265–272`；这是额外的依赖访存，不是第二次 `find_entry`。Root 不执行下面的 VPN UID lookup/enrichment/refresh/egress 查询，因此不能以 VPN 的次数推导 Root 热点。

VPN 已知 UID、既有未过期允许 TCP/UDP、Product direct egress 的正常分支可达六次 `find_entry`：[`resolver_lookup:229`](../../../src/product/vpp/product_vpn_uid_resolver.c#L229)、graph 的 [`current_incarnation:1676` 与 `enrich_uid:1673`](../../../src/product/vpp/product_packet_graph.c#L1673)、observe `494`、[`resolver_refresh:260`](../../../src/product/vpp/product_vpn_uid_resolver.c#L260)、[`egress:1809`](../../../src/product/vpp/product_packet_graph.c#L1809)。这不是每个 VPN 包的固定次数；未知 UID、DROP、无 incarnation 等会跳过部分查询，observation 无 entry 时还有 `4011` 的条件查询。broker response 的 `117/132` 属于异步结果处理，不能计入这六次逐包链。

## 2. 参考 fork 已做了哪些机制

本轮直接核对 fork 工作文件与 HEAD Git blob 相同，并读 caller、CMake 和 node/feature registration；旧研究文档只作索引。

* **自定义 ACL 是批量 node 外壳、单包 matcher。** [`stellar_acl/node.c:122`](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:122) 的 `acl_node_fn` 一次 `vlib_get_buffers:130`，每包 `acl_fill_pkt_info` → `acl_lc_search_by_pkt_info:137`，末尾整 frame enqueue `179`。[`look_context.c:307`](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/look_context.c:307) 遍历 context/mask，对一条 40B key 做五个 u64 AND，再单 key bihash `333`，命中后检查 collision rules 的端口区间 `294/343`；没有跨包 lane scheduler 或分阶段 hash prepare。注册 `node.c:186/225/240` 接到 dissector 后、session manager 前；`CMakeLists.txt:15` 列入 SOURCES，未列 MULTIARCH_SOURCES。
* **单 key SIMD 是真实原语能力。** [`bihash_40_8.h:82`](/home/js/backup/backup/Git/vpp/src/vppinfra/bihash_40_8.h:82) 提供 128/256/512-bit compare 与 scalar fallback；`61` 的 hash 按编译能力选择 CRC32c 或 XOR/xxhash。它不能证明该 fork 二进制实际选择哪个 ISA，更不能称其所有规则已批量 SIMD。
* **LPI 有预取和条件停止。** [`stellar_lpi_plugin.c:676`](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:676) 整 frame 获取 pointers `687`，提前一包预取 exdata/header `701–702`，随后单包调用 `stellar_lpi_on_vlib_buffer:715`。该函数 `578/601` 跳过无 payload，并用 stop/次数 guard 限制检测；[`stellar_lpi_core.c:287`](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_core.c:287) 调单 context guess 并设置停止。`plugin.c:462/468/729` 的 session feature/node registration 与 CMake SOURCES 链闭合；MULTIARCH 区为空。
* **scanner 必须区分两个 node。** [`stellar_scanner_node.c:1028`](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1028) 的 transaction node 整 frame 取 pointers、预取下一包 `1046–1047`，HTTP tag guard `1066` 后才做 transaction work；主 `stellar_scanner_node_fn:1118` 在 `1142` 逐包 get_buffer，没有这段预取。[`scanner_on_vlib_buffer:3752`](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3752) 用首次/周期 guard `3774` 保护静态字段扫描，decoder 按当前 decoded-as 执行，FQDN 用 `scanned_fqdn:3810`。二者分别注册于 `1088/1166`，session features 在 `954–996`，CMake 将 node/plugin 列入 SOURCES。外部 maatframe 的批量/ISA 能力没有本轮证据。

**官方 ACL 才是三级 lookup pipeline 的直接参考。** 从本地 pinned repository 的 `git show <pin>:src/plugins/acl/dataplane_node.c` 读到：[`prepare_fn:243`](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L243) 整 frame pointers，x4 tuple/hash 准备与提前 12 包 buffer/data 预取 `219/261`；[`inner_node_fn:352`](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L352) 对未来第 5 包预取 bucket、第 3 包预取 hash data、第 1 包查询并预取 session record `387–400`，复杂状态仍顺序执行。前包删除或创建 session 后，`441–449/527–533` 修正下一包的同 tuple 预测。官方 CMake 同时列 dataplane_node 为 SOURCES/MULTIARCH_SOURCES；这些是成熟的执行组织证据，不是本产品收益证据。

## 3. Flow 索引：当前 → 两个布局方向

[`flow_slot_t:9`](../../../src/product/vpp/product_flow_entry.c#L9) 将整个 entry 放在前、`next` 放在后；[`find_entry:72`](../../../src/product/vpp/product_flow_entry.c#L72) 从 bucket 读取 slot，再读 entry 的 linked/hash/typed key，未中时读取远处的 next。entry 的 TCP byte cache 含 `2×4096` bytes，见 [`product_sni.h:6/21`](../../../src/product/vpp/product_sni.h#L6)；tracker union 又位于它之后，见 [`product_flow_entry.h:126–139`](../../../src/product/vpp/product_flow_entry.h#L126)。**查询并不读取完整 8KiB**；问题是索引 stride、next 与所需状态的分散，以及依赖 load 的串行链。

| 布局方向 | 具体改法与代价 |
| --- | --- |
| 窄改：新增 runtime 私有 compact index，保留现有 entry pool | `index[slot]` 可保存 40B typed key、64-bit hash、next；slot 由数组位置隐含，预计约 56–64B/slot，必须以实际 alignment/sizeof guard 核定。显式保存 slot 适用于独立 bucket-node pool，但增加字段及映射管理。full key 在 index 与 entry 重复时，entry 身份保持唯一权威，index 是建立一次的不可变派生投影，create/unlink/release 同步维护；不能出现两份可独立修改的 key。另一窄方案只存 hash/next/slot，约 16B，再去 entry 复核完整 key：省复制与内存，hash 相同的候选仍有第二次 load。 |
| 深改：compact identity/hot state 与大块识别存储分离 | key/hash/next 保持一份权威身份；incarnation/deadline/方向/counters/CT tracker/识别结果组成 hot state，TCP/QUIC bytes 等进入预分配 cold pool。lookup 后仅按所需 feature 访问大块存储。需要同步改 `identify`、SNI/QUIC、Expiry、FlowEnd、diagnostic/export accessor，不是换一个 struct 就完成。全部启动预分配时主要收益是 locality，不能承诺总内存下降。 |

窄改保留 entry 在 slot offset 0，可继续使用 [`product_flow_entry_set_decision:700`](../../../src/product/vpp/product_flow_entry.c#L700) 的地址/stride 验证 `708–712`。把 header 直接挪到 entry 前、或将 entry 移到新 pool，都必须重构此验证，最好改为 generation/incarnation 验证的 owner operation。独立于 cold pool，亦可先将 `protocol_state` 移到 byte cache 之前以聚集常用 CT 状态；保持 entry offset 0 不代表其字段布局自动无需复核。

## 4. prepare/prefetch 接口必须保持 FlowRuntime 深度

caller 不读取 buckets/slots。建议增加 **opaque synchronous prepare hint**：输入已经存在的 typed assignment/hash，prepare 计算 bucket 并预取；随后在短窗口中读取 bucket head、预取 compact index，再预取匹配候选所需 hot state。这是 `buffer → bucket → index → state` 的依赖流水；仅在未来包上预取一个 entry pointer，不能完全隐藏前面未知 bucket/head 的 load。

消费当前包时仍执行权威查询或验证。已有 `observation.slot`、runtime generation、entry incarnation 可以构成 bounded handle；`identify:575` 与 `observe_existing:689` 已按 generation/incarnation 拒绝旧实例。handle 要同时验证当前 owner、linked/in_use、full typed key、incarnation 和当前 timestamp/deadline；generation 只区分 runtime 重启，不能检测同 generation 的 unlink/replacement。slot/incarnation 对已预测命中有用，**不能使预测 miss 永久成立**。

因此，短窗口只保存 bucket/slot hint 或 identity，不保存整帧权威 miss 或裸 entry pointer。前包可建流、close、expiry、UID replacement，也可能经 `product_flow_end_before_observe:2697` 推进回收；后一包必须看见新链与新实例。可采用每 bucket mutation sequence 或保守的当前包重查来废弃预测；sequence 仅在 runtime 内实现，不交给 caller 拼接 table/timer/pool。slot 复用始终以 incarnation 区分，过期检查仍用消费时刻。VPN 同包的重复查询可通过 owner-local validate/query/enrich 的统一 handle operation 摊薄；一旦 enrichment close 或 observe replacement，重新解析当前状态。跨 policy→egress node 不携带裸 pointer，也不能未经 metadata lifetime 审计塞入新的长期 handle。

## 5. owner policy 与规则查询的具体改法

[`product_policy_snapshot_acquire:435`](../../../src/product/vpp/product_packet_graph.c#L435) 的 SC reader claim/sequence 验证和 [`release:482`](../../../src/product/vpp/product_packet_graph.c#L482) 每包执行。用户已允许 bounded batch snapshot：将 `policy_on_owner` 拆成 batch-owned immutable bank reference 与 per-packet context，在当前 node 的有界窗口 acquire 一次，逐包完成 PRE→必要 Flow→POST→归因，全部同步借用结束后 release。ct/protocols/SNI/domain memberships/flow incarnation 每包重置和读取；不可复用上包 context。writer `3500–3508` 仍须等待旧 bank readers 后才销毁 domains/复用 bank；新 batch 重新 acquire，已完成 publication 应对其生效。batch 不跨 node、callback 或 future arrivals，工作预算同时限制 writer 等待。`policy_workers.acquired/released:3915/4022` 的计数要明确改成 batch 次数，逐包 revision/归因检查仍保留，不能继续用旧计数解释 packet visibility。

规则准备应改在 [`product_packet_graph_l4_packet_projection:2581`](../../../src/product/vpp/product_packet_graph.c#L2581)、[`l4_view_evaluate:3027`](../../../src/product/vpp/product_packet_graph.c#L3027) 与 [`product_l4_policy_match_position:901`](../../../src/product/vpp/product_l4_policy.c#L901)：一次投影包的 addresses/ports/platform availability，准备 42B index key、subject 和 static guard，PRE/POST 共享静态部分；POST 再填当前 CT/LPI/SNI/domain facts。Root 平台 UID 可提前使用；VPN subject 准备必须在该包 resolver/enrichment 之后，不能把依赖 owner 状态的 UID 固定成 frame 初值。

[`match_cached:1087`](../../../src/product/vpp/product_l4_policy.c#L1087) 先二分 subject，miss 后 `match_position:932` 再二分；`match_position:953` 又扫描整个 view 的 subtables 才过滤 subject。新增私有 prepared query 后应复用已验证 subject；compiler `build_index:391` 给 UID bucket 建 contiguous subtable range，matcher 只访问该 range。空 view、未知 UID、无 subject 可在保持既有 NoMatch reason、probe 语义与后续 Flow 维护的条件下直接结束，无需构造/哈希完整 cache guard。剩余独立查询可交错 mask→hash→head/index prefetch；candidate rank pruning、checked-rule 去重、factorized/residual 完整求值仍保留。prepared query 不让 caller 操作 subtables，也不把候选当成最终 winner。

[`place_rules:258`](../../../src/product/vpp/product_l4_policy.c#L258) 会将有动态依赖的整条规则及与更高 rank POST 重叠的静态规则放到 POST；不能把静态 leaf 的“匹配”当作 PRE winner。可在 compiled rule 保存 dependencies，并分别汇总 PRE/POST bucket dependencies，避免 residual `expression_matches:735` 重新扫描 bytecode；完整 AND/OR/NOT 与 unknown 三值逻辑 `745–809` 保持。cache identity `generation/revision/hash/incarnation`、position、全部必要 availability 和 dynamic facts继续参与；index key 本身不足以代替 guard。当前 masked-key 已有编译器 NEON 证据，见 [现有批处理记录:296](../../testing/2026-10-11_PIXEL6A_INCREMENTAL_BATCH.md#L296)，跨查询流水不能被宣传成首次引入 SIMD。

## 6. 识别 guard 与实施前验证点

产品 [`product_flow_entry_identify:607`](../../../src/product/vpp/product_flow_lpi.c#L607) 先独立观察 SNI，再由 `615` 的 stop/no-payload guard 决定 LPI；[`product_flow_sni_observe:157`](../../../src/product/vpp/product_flow_sni.c#L157) 亦有独立 stop 与预算。fork 的条件扫描可借鉴，但不能在 LPI stop 后跳过尚可完成的 SNI，或把策略无动态需求解释为不再维护 Flow/识别合同。

实施顺序宜先做受保护的 batch snapshot、static projection/subject 复用与空查询 bypass，再建立 opaque prepare 与 compact index，最后根据真实负载决定深层 hot/cold split 和跨查询 SIMD。前置核对包括 Root 的实际 batch 形状/链长、各方案新增预分配字节、短窗口 hint 对同 tuple 建立/结束/替换/slot reuse 的失效、逻辑 expiry、FlowEnd 仍保留旧槽、capacity bypass、同包 PRE/POST 同 revision、下一 batch 新 revision、cache winner/NoMatch/availability/归因不变。没有这些 workload 和 artifact 证据，不能给预取距离、布局收益或瓶颈占比排序。

本轮身份核对：fork ACL node/look_context/CMake 的 blob 分别为 `51ec0136195e641a251a807994d24fcfa35669e0`、`afcfeb93af4d4d18f27d77731fc82784c905b898`、`d8be91dbd7b74d66ba3c41b9f9650cf3fe3d416f`；LPI plugin/core/CMake、scanner node/plugin/CMake 和 bihash_40_8 的工作文件均与 HEAD blob 相同。官方 dataplane_node blob 为 `471228726c52b9f8ed74d6f30b3118a3b45cc34b`，通过 pin 的 Git object 读取，未以参考 fork 的近似实现替代。
