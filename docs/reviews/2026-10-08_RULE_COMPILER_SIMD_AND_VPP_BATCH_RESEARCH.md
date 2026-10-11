# 规则编译、SIMD 与 VPP frame 批处理专项调查

日期：2026-10-08。承接 [CCP / Coralflow 深源码调查](2026-10-08_CCP_CORALFLOW_RULE_MATCHING_SOURCE_RESEARCH.md)。问题：现有规则引擎实际利用了多少 VPP batching；更适合的编译与 SIMD 参考是什么；如何保持当前统一规则语义并改善执行组织。

结论：**现有引擎已经接入 VPP frame，并有编译器生成的单查询 NEON 操作；尚无显式多查询执行内核。值得进一步研究的是“规则编译表示与执行器协同设计”，不限于给现有循环加几条 intrinsic。** 首先可参考 VPP ACL 的访存流水线，再参考 DPDK ACL 的编译布局与 lane scheduler；whole Rank、availability、packet 顺序及完整 snapshot 继续约束全部计划。

本次未改变产品代码、编译选项、规则规格或资源预算。以下分别标明固定上游源码事实、现有本地代码事实、独立代码生成观察和待验证设计。

后续证据审查补充：本文件讨论可用执行机制，不作当前热点投入排名。[已有火焰图与最佳实践专项](2026-10-08_VPP_BEST_PRACTICES_AND_FLAMEGRAPH_AUDIT.md)核实有效吞吐窗口规则为零、主要规则成本是空视图cache准备，并发现适配器入口主动提交singleton admit frames。当前投入判断应结合该证据审查，不能由本文件的SIMD机制介绍推出候选匹配已是主瓶颈。

## 1. 固定来源与三个不同层次

| 来源 | 身份 | 使用范围 |
| --- | --- | --- |
| VPP | 当前产品 pin `9258530f3804a152578ce11cc7c8a1e9eab88ed0` | acl/classify、bihash、node 和 multiarch 构建源码 |
| DPDK | v24.11，commit `1b3bf1128d9bda5595861814792f74b8f57160c8` | ACL build/gen、scalar/NEON/AVX2/AVX512 运行内核 |
| DPDK 在线文档 | guides-24.11 当前展示 24.11.7 | API/概念补充；实际实现以固定 commit 为准 |
| Android 工具链 | 本机 NDK `29.0.14206865`、Clang 21.0.0 | 当前 C policy 单独翻译单元的 ARM64 汇编观察 |
| Sakamoto | 与前一调查相同的 policy/graph 文件 SHA-256 | 当前实际接口、query、snapshot 和预算 |

来源：[VPP pin](../../src/product/vpp/pinned-vpp-revision.txt)、[DPDK 固定源码](https://github.com/DPDK/dpdk/tree/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl)、[DPDK 文档](https://doc.dpdk.org/guides-24.11/prog_guide/packet_classif_access_ctrl.html)。本调查没有沿用旧入口文档中的 VPP 版本名代替当前 pin。

需要区分：

1. **软件批处理/交错**：一次函数接收多个查询，提前准备/preload，交错推进独立访存；即使全部指令是 scalar 也可能有收益。
2. **单查询内 SIMD**：一条 key 的多个字节/字段同时 AND、XOR、比较；一条 128-bit 指令不等于同时匹配多个包。
3. **多查询 SIMD**：每个 lane 是独立 packet/query，数据和执行进度适合并行，保持每输入的完整结果。

也有两种“编译”：规则编译器将配置变成执行表示；C 编译器将内核生成机器指令。前者决定可消除哪些运行工作、内存布局和可并行结构；后者无法仅凭 `-O3` 把任意有状态解释器自动变成多包分类器。[LLVM vectorizer 说明](https://llvm.org/docs/Vectorizers.html)

## 2. 我们当前适配到哪一步

### 2.1 Frame 内仍是逐包完整调用

`product_packet_policy_node` 从 frame 取 buffer indexes，然后 `for(index < frame->n_vectors)`，逐包构造 lease/platform facts，调用 `product_packet_graph_policy_on_owner`，最后逐包 `enqueue_to_single_next(...,1)`。[product_packet_graph.c](../../src/product/vpp/product_packet_graph.c)，1587–1723。

owner 调用的顺序为 acquire snapshot → PRE → 必要的 Flow/CT/LPI/SNI facts → POST/decision → attribution → release。matcher 接口接受单个 normalized packet，没有 frame/bulk 参数或多个独立查询上下文。[同文件](../../src/product/vpp/product_packet_graph.c)，3899–4040；[product_l4_policy.h](../../src/product/vpp/product_l4_policy.h) 的 `match_position/match_cached`。

因此已经享有 VPP 按 frame 调度节点的环境，也有一定局部性；规则查询自身没有显式跨包交错或 SIMD lane scheduler。不能因为使用 `VLIB_NODE_FN` 就认为批量分类已经完成。

### 2.2 已有真实的单查询 NEON

本次用现有 NDK 对当前 `product_l4_policy.c` 分别执行 `--target=aarch64-linux-android31 -O2/-O3 -S`，两次退出码均为 0。`product_l4_policy_match_position` 汇编存在 NEON vector AND：O2 可见 `.8b` 操作，O3 可见 `.16b` 和尾部较窄操作。O3 的 SLP remarks 对 masked-key 循环报告向量化；O2 未对该处输出同类 remark，但实际汇编已有向量操作。

这里不能只数成功的 optimization remarks，也不能看到 vector load/store 就断言多包并行。这些操作对应单个 key 的投影/局部操作。证据保留在 [verification.json](assets/2026-10-08-rule-simd-batch/verification.json)、[汇编片段](assets/2026-10-08-rule-simd-batch/arm64-key-mask-excerpts.txt)、[O2](assets/2026-10-08-rule-simd-batch/arm64-O2-remarks.txt)/[O3 remarks](assets/2026-10-08-rule-simd-batch/arm64-O3-remarks.txt)。

这是独立翻译单元的代码生成观察，未链接真实 Product plugin、未运行该 ARM64 代码，也不是设备速度/能耗比较。Android arm64 的 NEON 可作为支持基线；CRC/SVE 等不能从“arm64”笼统推断。[Android ABI](https://developer.android.com/ndk/guides/abis#arm64-v8a)

### 2.3 仍有不规则和串行工作

当前每个子表计算42字节masked key，再用FNV-1a逐字节递推，沿collision chain追索引，按候选检查完整表达式。单hash的`(hash ^ byte) * constant`依赖上一字节，不会因masked AND向量化就消失。完整表达式还依赖opcode、availability和早期候选失败等分支。[product_l4_policy.c](../../src/product/vpp/product_l4_policy.c)，298–304、731–814、912–1005。

优先值得测的是：多个独立hash状态交错、减少无关字段和子表访问、减少指针/索引依赖、密集candidate检查。给已有AND循环再加intrinsic不一定触及主要成本。

## 3. VPP ACL：最贴近现有结构的参考

### 3.1 先准备整 frame，再流水预取，保持逐包状态顺序

固定pin的ACL先取buffers，以四项小批次填tuples/hashes并预取未来buffer。第二阶段仍逐包处理，分阶段预取未来session bucket、data、record；最后一次提交frame的next数组。`fill_5tuple_xN/make_session_hash_xN`本体是独立标量调用循环，不应称为四包SIMD分类。[dataplane_node.c](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L219)，219–308、353–484、646。

该路径可参考到我们：纯packet输入准备、可达表/索引预取、短窗口交错、frame enqueue摊销。CT/LPI/SNI、应用身份解析和完整cache validity仍在当前包的语义位置读取。

ACL明确修正同flow前瞻：当前包删除旧session后纠正下一包已有预测；当前包建立session后纠正下一包此前的miss。这是预先lookup也会遇到数据依赖的直接实例。[同文件](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L441)，441–455、529–536。

### 3.2 规则查找仍单tuple，定长key比较是真SIMD

新session路径的ACL匹配针对单tuple遍历mask partitions、hash查询和完整collision检查；用`first_rule_index`界限避免继续访问无法改善winner的partition。[public_inlines.h](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/public_inlines.h#L526)，526–638。

真正定长SIMD在`bihash_48_8`的一条48-byte key比较中：128-bit三组XOR/OR，256/512-bit有相应路径。hash可以使用CRC32c特殊指令；CRC指令加速与多查询SIMD是不同机制。函数名`search_inline_2`表示分离search_key/valuep参数，一次查询一个key。[bihash_48_8.h](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/bihash_48_8.h#L51)，51–108；[template](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/bihash_template.h#L536)；[crc32](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vppinfra/crc32.h#L10)。

另一个更直接的mask/hash/compare原语参考是VPP classify。它准备独立packet hash和bucket预取，定长candidate使用vector AND/XOR/OR；它并不承担我们的Boolean、availability或whole Rank。[ip_classify.c](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vnet/classify/ip_classify.c#L76)、[vnet_classify.h](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vnet/classify/vnet_classify.h#L250)，250–340、422–519。

## 4. DPDK ACL：编译器和执行器协同设计的参考

### 4.1 编译会消除运行时步骤

固定v24.11的ACL编译器将mask/prefix/range条件构建、合并为byte-stride trie，去掉始终通配的输入组，生成各trie的输入offset；节点增长过大时拆分为多棵trie。显式runtime memory limit下可降低构建阈值重试。这意味着执行器实际少读字段、少走transition，而不只是换更宽比较指令。按wildness排序的是规则，不应误说它任意重排用户定义的字段。[acl_bld.c](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_bld.c#L948)，build_trie、acl_rule_stats、sort_rules、acl_build_index、rte_acl_build。

生成器把构建期图变为连续64-bit transition数组，选择SINGLE、四个cuts的QRANGE或DFA表示，压缩重复分组。每棵trie可采用不同input groups；更多trie可能减少表示内存却增加遍历工作。拆分的是源规则集合，不保证packet匹配域互斥，同一个包仍可能命中多棵trie再归约结果。[acl_gen.c](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_gen.c#L221)，acl_count_trie_types、acl_gen_node、rte_acl_gen。

我们可以借鉴的是“编译为适合某种kernel执行的物理计划”：压缩相关字段、紧凑候选metadata、规则形状分组、必要时column layout。byte trie只是可比较的计划之一，不能由服务器ACL的实现推定它优于我们的128-rule小视图。

### 4.2 NEON究竟并行了什么

v24.11入口在输入数>=8时使用8路scheduler，4..7使用4路，<4 scalar。8路是两组4个32-bit lane，不是8-wide NEON。向量操作计算QRANGE比较/地址，但下一transition仍由四次标量indexed load获取；x86 AVX2则使用gather。NEON循环一次读四个输入字节，再做四次8-bit transition。[acl_run_neon.c](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run_neon.c#L8)、[acl_run_neon.h](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run_neon.h#L102)、[AVX2](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run_avx2.h#L67)。

向量宽度没有消除依赖访存。不同stream交错、table cache命中、lane利用率、输入装填和match/refill共同决定收益。不能把AVX2/AVX512的gather表现投射到Android NEON。

### 4.3 Lane完成后补下一项，而非固定大块一齐完成

scheduler将packet×trie工作装入空闲slot，每packet独立completion与输出位置；一项完成后立即补下一工作，末尾idle排空。因此9个输入进入8路内核后，不等于尾部1个必然调用scalar。入口小批才直接scalar。scalar自身已经交错两条独立stream，所以可以先验证访存并行，再讨论显式SIMD。[acl_run.h](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run.h#L128)，acl_start_next_trie、acl_match_check；[scalar](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run_scalar.c#L110)。

AVX512还有trie-by-trie遍历、临时match数组、随后统一priority归约的不同实现，wrapper将输入切为最多256项以约束scratch。它说明不同ISA可能适合不同执行组织，不是仅替换同一段intrinsic。[AVX512入口](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run_avx512.c#L140)、[两阶段执行](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run_avx512x16.h#L291)。

### 4.4 原生最高tuple结果不能直接作为我们的通用candidate接口

DPDK的leaf消解和runtime reduction保留每category的最高priority userdata。若Rank1和Rank2静态tuple都匹配，Rank1还有SNI residual，Rank1失败后普通ACL输出里可能已没有Rank2。编码唯一完整Rank只解决排序，不能恢复被消解的较低候选；有限category也是独立winner通道，不是任意top-k列表。[acl_bld.c的acl_resolve_leaf](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_bld.c#L518)、[runtime reduction](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_run.h#L203)。

安全适配有两类：完整规则已能在该输入/tuple表示中求值，且与其他计划合并仍保持whole Rank，则可以返回完整winner；否则必须保留保守candidate集合/有界Rank排序列表，或者让该规则走现有完整residual计划。不能把普通top-only ACL当作无损前置过滤。

## 5. 更大的执行层发展空间

以下是由源码和本地需求推导的设计候选，未实施或测性能。逻辑配置/排序不变，编译产物可有多种物理表示。

### 5.1 编译器选择不同形状的执行计划

一个应用视图可以包含：少量规则的紧凑ordered扫描、现有same-mask索引、范围factor、适合SIMD的固定字段组、保留复杂逻辑的residual。选择依据应包含字段宽度/需求、mask数、预估candidate密度、表达式复杂度、预算及测量，不按“所有规则一律用最宽SIMD”。

所有计划需要同一logical rule引用、完整Rank、whole PRE/POST position、mode和attribution；源模型只有一份，compiled products在一个snapshot中发布。计划之间共享索引工作，不折叠不同业务身份。

### 5.2 两个SIMD方向，适合不同流量

| 方向 | lane含义 | 适用性与成本 |
| --- | --- | --- |
| 多packet对同一predicate/表 | packet 0..3的相同字段 | frame中相关query足够集中时有效；需要装填/transpose、application/snapshot/position分组或保守混合处理 |
| 一个packet对多条规则 | rule 0..3的端口界限、protocol等 | 即使frame只有一个包也可用；需要紧凑列式compiled metadata，候选仍保留完整Rank/residual |

当前source rule约216B，把端口界限等散在AoS里，跨规则SIMD需要gather或重排。编译到SoA/AoSoA字段列可以令该kernel连续读取，但会增加表示和更新成本，需由compiler budget约束。不能把64-byte表达式任意扩展成无界DNF。

### 5.3 三值逻辑本身可以用mask表达

对当前三值truth table，一个query集合可用T/F两个mask，未知lane没有置入两者：

```text
AND: T = Ta & Tb       F = Fa | Fb
OR:  T = Ta | Tb       F = Fa & Fb
NOT: T = Fchild        F = Tchild
U = active & ~(T | F)
```

这样NOT不会把unknown变true，true OR unknown仍true。整条SNI/domain适用性需要另外按既有规则施加；来源、confirmed absence、producer error也不能挤成同一个false bit。这是可用于有界表达式执行器的数学表示，不代表已经选定vector AST实现。lane准备、不同规则表达式、临时mask数量、事实获取时间可能比Boolean指令本身更贵。[当前表达式求值](../../src/product/vpp/product_l4_policy.c)，731–814；[统一规范](../product/UNIFIED_RULE_ENGINE_SPEC.md)，§3–5。

### 5.4 第一项batch改进可保留原顺序提交

较保守的路线是frame内纯输入准备 → 小窗口mask/hash/prefetch → 原packet顺序完整PRE/Flow/POST/cache/归因和completion。只提前计算不可变packet输入和受保护view的纯函数；应用身份解析、Flow事实和cache guards不能盲目冻结为frame开始时的值。

若进一步同时推进多个完整查询，需要证明其事实依赖已经满足，或明确处理同flow冲突及结果提交顺序；不能简单把全frame PRE做完、再全部Flow、再全部POST。同flow第一包可能改变后续包的CT/LPI/SNI/身份甚至资源状态。对于动态规则，首先做单查询内SIMD也可以获得收益，不要求越过这些语义边界。

bulk接口应是现有同步matcher的内部/native执行选择，逐输入有独立result/best/checked/availability/identity，frame内现有输入用完就排空；没有凑批等待、跨frame新队列或第二套规则权威。初版保留现有snapshot acquisition；若改为共享frame claim，需明确其 acquisition时点和发布/reader寿命证明。

## 6. C编译、ISA与runtime选择

VPP ACL把dataplane文件显式放入`MULTIARCH_SOURCES`，build为启用且compiler支持的arch variants，node注册后选择适用函数。[ACL CMake](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/CMakeLists.txt#L14)、[plugin.cmake](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/cmake/plugin.cmake#L98)、[cpu.cmake](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/cmake/cpu.cmake#L268)、[node选择](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/node.c#L258)。

我们的plugin当前只有`SOURCES`；node变体也不自动使独立`product_l4_policy.c`非内联调用按同arch重编。现有host builder没有显式传`CMAKE_BUILD_TYPE`；Android runtime stage脚本明确Release并关闭所列特定march variants，但它构建的是VPP stage。不能用这个脚本或独立O3 probe代替实际Product plugin的compile commands/binary审计。[Product CMake](../../src/product/vpp/CMakeLists.txt)、[host builder](../../tools/product/build-host-artifact.sh)，193–205；[Android stage](../../src/product/vpp/android/build-stage.sh)，185–209。

DPDK共用rule runtime表示，但ISA文件仍分别编译，runtime支持检查/dispatch决定可用kernel；选“最宽可用”并没有按实际小批次/规则成本测最优。[meson.build](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/meson.build)、[rte_acl.c](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/rte_acl.c#L112)。

建议编译的是少量固定C kernel，不引入JIT/user scripts。Android先以NEON实际测；host可补AVX2路径，SVE/AVX512按目标能力、体积及实测收益决定。scalar和vector路径使用同compiled plan/full-result合同。`-O3`、LTO、PGO或intrinsic都是独立实验变量；编译成功、指令存在不等于净收益。

## 7. 当前预算也约束“更适合SIMD”的布局

前一调查实测compiled view 63,512B、compiler publication representation subtotal 386,932B、384KiB子预算余6,284B。DPDK max_size仅约束runtime allocation，不含全编译scratch/source/old-new overlap，不能替代我们的预算。[前一探针](assets/2026-10-08-rule-engine-source/verification.txt)、[DPDK生成器](https://github.com/DPDK/dpdk/blob/1b3bf1128d9bda5595861814792f74b8f57160c8/lib/acl/acl_gen.c#L449)。

当前key42B不能直接做三次16B load假装48B：需要安全tail，或显式补齐并计入所有副本。若entry key和subtable mask各补6B，256份固定数组×四份view仅这两项理论增量即12,288B，超过现余量；实际alignment/padding和scratch还需重新测。这是表示规划的示例，不是已采用的改动。

batch scratch也不能无条件把现有整套query workspace复制256份。短窗口、复用prepared-key空间、流式候选推进和受限temp masks都应进入完整峰值核算。

## 8. 验证顺序与仍未证明的收益

研究优先级是：

1. **VPP式软件流水线**：frame内纯输入准备、短窗口prefetch/交错、整frame enqueue。保留状态顺序，测是否减少访存等待及调用/提交成本。
2. **定长query kernel**：当前hash依赖、mask/key compare、区间candidate checks；比较baseline/autovectorized、scalar interleave、NEON。确认已有生成代码后再决定手写intrinsic。
3. **编译布局与query批入口**：紧凑可达计划、SoA/AoSoA、逐lane独立状态；研究小批、混应用和one-packet/multi-rule路径。
4. **替代物理计划**：trie、向量表达式等只有在完整候选语义、预算和已有baseline比较闭合后才考虑。

以现有完整ordered oracle比较winner、Rank、mode、declared/actual action、归因和availability；还要验证真实packet事实更新、snapshot切换、same-flow序列和cache guard。单纯ACL userdata一致不是我们的完整语义证明。

成本实验至少覆盖batch=1/2/3/4/7/8/9/16/32、同/混应用、IPv4/IPv6、少/多mask、early winner/miss/residual false、cache hot/cold/pressure、单flow和多flow；测compile时间、cycles/query、p50/p95/p99、cache miss、lane利用率、runtime表示/发布峰值和worker scratch。ARM64大小核、频率/持续温升和实际frame分布要保留，不能只跑满批服务器吞吐。

本次完成固定上游源码追踪及ARM64独立代码生成检查；没有运行SIMD/batch速度比较、设备部署、功耗/热测量或新产品验收。原有语义测试与历史性能记录不自动验证新内核。

## 附录：本次可重复代码生成命令

```sh
rtk proxy /home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-linux-android31 -std=c11 -O2 -Isrc/product/vpp -Rpass=loop-vectorize -Rpass=slp-vectorizer -S src/product/vpp/product_l4_policy.c -o /tmp/sakamoto-policy-arm64-O2.s
rtk proxy /home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/clang --target=aarch64-linux-android31 -std=c11 -O3 -Isrc/product/vpp -Rpass=loop-vectorize -Rpass=slp-vectorizer -S src/product/vpp/product_l4_policy.c -o /tmp/sakamoto-policy-arm64-O3.s
```

原始运行将stderr分别保存为`/tmp/sakamoto-policy-arm64-O2-remarks.txt`和O3对应文件；commands/source/assembly hashes和exit codes已记录于资产manifest。它们未宣称复刻实际Product plugin的全部构建flags。
