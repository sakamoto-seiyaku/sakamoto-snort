# VPP 编程最佳实践与已有火焰图专项审查

日期：2026-10-08。范围：当前 Product C packet execution、规则查询、Root/TUN 接入及 owner-local HEV；对照固定 VPP 实现和已有有效设备采样。

## 1. 投入判断

**值得投入一个有边界的 VPP 数据路径执行优化专项。现有资料足够决定首批方向，不需要先启动新的大规模采样。** 最先处理已证明无收益的空视图缓存准备、适配器入口主动生成的一包一 admit frame、重复证据/平台数据准备及未启用诊断的原子操作。HEV 重复 TLS 上下文访问也有明确采样依据，可以独立作为子项。

**现有图不支持把通用规则候选/表达式 SIMD 重写排为首项。** 有效吞吐窗口读取到的 active rule count 全部为零，最明确的规则相关 CPU 工作是给空视图的 cache guard 做逐字节 FNV。语义保持不变的无用工作消除，比新建另一套匹配后端更有直接投入依据。

更准确的结构发现也修正了前一轮说明：不只是“VPP 给我们 N 个包、内部没充分批量化”；`submit_external` 自己每包单独创建、提交 `n_vectors=1` 的输入 frame。后续 next frame 能重新聚合，但最初 admit dispatch 已被拆散。

本次没有修改产品、原始 `build-output`、设备状态或 Plane。完成的是现有证据重分析、匹配 ELF 指令定位、源码/最佳实践审查和实施边界判断；新实现的净收益与回归仍需在变更后验证。

## 2. 审查方法：实践、现状、火焰图三者交叉

“违反最佳实践”在本文指确定的性能组织偏离或可避免工作，不意味着调用非法或正确性合同已违反。逐包处理、未显式 SIMD、缺 prefetch 本身均不自动构成问题。

| 实践基线 | 适用审查问题 | 一手依据 |
| --- | --- | --- |
| 用已有工作向量摊薄 frame/dispatch 成本 | 已读到的多个包是否仍主动拆成 singleton frames | [VLIB架构](https://docs.fd.io/vpp/25.10/developer/corearchitecture/vlib.html)、固定pin `main.c` |
| 批量取buffer、准备、enqueue；小窗口隐藏依赖访存 | helper是否每包重复进入，纯输入能否提前准备 | [固定ACL节点](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L219) |
| worker-local状态与计数，适当汇总 | 可本地处理的诊断是否每包写共享原子 | 同ACL节点570–589及当前owner结构 |
| 把固定配置与冷分支留在冷路径 | 禁用功能是否仍消耗RMW，错误分支是否扩大常态workspace | 当前mode/trace/hold/empty-view源码与匹配ELF |
| 结合profiling定位访存/内核，不机械加prefetch/SIMD | 热指令究竟是hash、比较、状态还是I/O | 现有原始perf、匹配symbols；固定ACL真实执行路径 |
| 状态顺序和native所有权仍优先 | batch是否改变同flow事实观察、partial-transfer和settlement | 固定ACL441–455、529–536；ADR-0006/0007/0009 |

官方架构文档提供原则，具体API语义以产品pin `9258530f3804a152578ce11cc7c8a1e9eab88ed0` 为准。本次读取官方 `src/vlib/main.c`、`buffer_funcs.h`、`buffer_node.h`，身份哈希保留在 [manifest](assets/2026-10-08-vpp-practice-audit/manifest.json)。

## 3. 采用的性能证据与排除项

### 3.1 主窗口用已经修复 getenv 的 TCP 原始图

主证据为 [mode-fix TCP火焰图](../../build-output/vpn-mode-fix-20260928/vpn/vpp-tcp25-first20-flamegraph.html) 和同目录 `tcp25.perf.data`，正式负载前20秒。sender monotonic start为 `1448741721188548`，结束裁剪到 `1448761721188548`；VPP PID29120，3,954样本，period合计19,869,344,250ns，其中2,299个样本在kernel，3,953个属于`vpp_wk_0`。

匹配插件pre-strip GNU build-id为 `ff7e9df8628e8423936c58644e9247f9d59e68ce`，symbol ELF SHA-256为`dbdd15e289e9c919e0ddb6e89a6be344a98133763b529504f44b762821e3d615`；[ELF identity](../../build-output/vpn-mode-fix-20260928/elf-identity.json)记录27个可加载节与APK/stage相同。未使用当前重建ELF冒充旧样本。

### 3.2 UDP交叉窗口有独立分母

有效VPN UDP前22秒为1,994 VPP样本，Root UDP前22秒为2,096；取[原matched22摘要](../../build-output/vpn-throughput-profile-20260928/vpn/udp25-matched22.hotspots.json)及[Root对应摘要](../../build-output/vpn-throughput-profile-20260928/root/udp25-matched22.hotspots.json)。它们来自之前的带符号APK，不能与mode-fix混合计数或认作同一性能比较。

以下不作为当前优化收益：

- 旧TCP的`getenv` self277/3938约7%：已在[mode修复](../testing/2026-09-28_VPN_RUNTIME_MODE_FIX.md)中消除，当前getter只读启动固定模式，修复后self为0。
- Root持续TCP的557/333Mbps：队列176缺失、端点与VPP字节不符，是[失效证据](../testing/2026-09-28_VPN_ROOT_THROUGHPUT_PROFILE.md)，不是正常全路径性能。后续[恢复修复](../testing/2026-09-28_ROOT_NFQUEUE_RECOVERY.md)没有使旧轮次追溯变有效。
- 低速HTTP窗口产品函数最高self仅5样本，以及早期大量未知产品叶的stripped采样：可提供背景，不覆盖本次较清晰TCP指令证据。

### 3.3 计量解释

本文百分比默认是**该窗口VPP样本份额**。self是采样PC所在函数，inclusive是该符号出现在该样本任一帧；inclusive重叠不可相加。on-CPU样本不代表off-CPU等待、锁竞争、wall latency、调用次数或每包成本。

原始栈有明显截断：197个含L4 view的样本中171个只保留两帧，15个三帧、8个单帧；与policy-node500个样本仅2个相交。其去重union695/3954=17.58%，只是已识别policy相关样本下界，不能把12.65% policy-node减4.98% L4视为完整分解。

## 4. 投入排序与证据强度

| 项目 | 当前证据 | 判断 |
| --- | --- | --- |
| 空规则/无subject还构造cache guard并hash | 原始PC+匹配ELF+typed零规则+现代码 | **第一优先：明确的无收益准备工作** |
| callback内每包独立创建admit frame | 当前代码+固定VPP allocation/pending语义 | **第一批：恢复本来已有的输入聚合机会**；比例未单独量化 |
| 重复policy/evidence投影与hash | 已见相关self PC+当前完全重复路径 | **第一批：局部去重复**；matched重复不能用零规则图量化 |
| 禁用trace仍RMW、未arm hold仍exchange | 当前默认状态和无条件操作 | **第一批：消除关功能开销**；保留控制/诊断能力 |
| 节点每包enqueue helper | self/inclusive样本+固定next-frame语义 | **第一批：摊销调用**；不能称必然下游singleton |
| HEV动态TLS/context getter | 明确resolver调用栈，互斥self6.07% | **值得独立投入**；保owner-local语义、审加载ABI |
| consumer完整lease恢复/重复platform读 | 当前不必要字段构造+lease1.16% inclusive | **可随第一批处理的局部项**，收益较小且需span语义保留 |
| cold fallback造成约64KiB函数frame | 匹配ELFprologue+当前自动empty_view | **应整理热冷布局与可观测性**；不称64KiB每包清零 |
| 一般prefetch/x2/x4和multiarch | 官方示例+当前机会 | 在上述准备/提交路径上局部采用；不作无证据的全插件改写 |
| snapshot SC协议、全部双体系copy | 正确合同，现图未证可省 | **不列为简单浪费** |
| 通用候选/表达式SIMD重写 | 现有有效吞吐窗口均零规则 | **暂不作为主要投入方向**；此前SIMD调查是机制参考，不是热点排名 |

## 5. 最明确项：零规则还付cache散列

[修复后TCP暖机typed读回](../../build-output/vpn-mode-fix-20260928/flows/vpn-tcp25-warmup/attempt0-page0.json)为 `policy_source.active_rule_count=0`、`vpp.policy_rule_count=0`，revision907、snapshot hash13236810628840110106。旧有效TCP、VPN UDP、Root UDP前后读回也为零规则；采样没有证据支持“大规则匹配导致这一热点”。

`product_l4_policy_match_cached` self156/3954=3.95%。其中128个样本在下列**匹配ELF**循环，占VPP3.24%、该函数self82.05%：

```text
0x7599c  ldrb w13, [x11, x9]
0x759a0  add  x9, x9, #1
0x759a4  cmp  x9, #0x80
0x759a8  eor  x10, x10, x13
0x759ac  mul  x10, x10, x12
0x759b0  b.ne 0x7599c
```

PC归属为mul74、cmp20、xor20、load14。当前[source](../../src/product/vpp/product_l4_policy.c)1087–1106仍先找bucket，再构造guard、对整个对象逐byte FNV；没有bucket也这样做。当前本地布局探针同样测得guard128B，文件hash与前一调查相同。

这里cache没有规则查询工作可供节约，却保留了固定定位成本。建议在既有参数/状态校验后，对空view或没有适用subject走**原direct matcher完整NoMatch路径**，跳过cache准备。保UID/family/direction等reason顺序、完整result、snapshot与归因；后续Flow/CT/LPI/SNI维护和completion仍执行。不能改成未经校验的“空规则就直接ALLOW”。

有规则时，完整guard比较仍是正确合同；可另研究word/hash定位、静态prefix预计算、miss复用subject lookup，不能只保旧winner字段。当前cache按worker私有，不能称为共享cache争用。

3.24%是已发生循环的样本份额，足以说明值得局部投入，不是承诺吞吐提升3.24%。

## 6. Frame最先被浪费在适配器入口

当前[source](../../src/product/vpp/product_packet_graph.c)4043–4093每包调用`vlib_get_frame_to_node`、写`to[0]`、设置`n_vectors=1`，再`vlib_put_frame_to_node`。Root读取callback有64次nonblocking预算，TUN也有最多64次read，但每项仍分别调用此函数。[Root](../../src/product/vpp/product_root_nfqueue_adapter.c)1027–1287；[TUN](../../src/product/vpp/product_vpn_tun_adapter.c)317–383。

固定[VPP main.c](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/main.c#L99)99–104每次分配独立FREE_AFTER_DISPATCH frame，133–152每次添加独立pending entry，next_frame_index为NO_NEXT_FRAME。allocator可复用pool，但没有自动将这些external frames合并为同一个目标frame。这里的singleton是代码事实，不是从火焰图猜平均frame大小。

这违背了利用已到达工作摊薄dispatch的性能组织原则。首项实施可以收集**本次callback已经接收并建立有效obligation的包**，到capacity、EAGAIN、budget exit或fault时flush；没有等待新包凑批、没有跨callback新队列。若本callback有N个有效包，frame提交可从N次变为该有界集合的少数次；实际N分布与净CPU收益没有从现有图伪造。

必须保持每项transfer/ledger、loan/credit、generation和partial失败归属。HEV return另有“callback返回前完成native scheduling”的合同，不跨callback攒输出或保留pbuf借用指针。

现有吞吐证据未保存对应`show runtime` calls/vectors表；CPU采样和sender send调用数不能反推实际frames/packets。这个缺失限制百分比收益，不阻止确认结构偏离及投入判断。

## 7. 单元素enqueue：能聚合next，但仍重复helper

policy1720、consumer1777、egress1821分别使用`enqueue_to_single_next(...,1)`。固定[VPP get/put-next](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/main.c#L296)允许追加已有pending next frame；因此这些调用**不意味着每包都单独dispatch下一节点**，与external submit需要分开。

但N次helper的函数选择、get/copy/put工作未摊薄。修复后图中`vlib_buffer_enqueue_to_single_next_fn` self17、inclusive44；get-next self19、put-next self14。三种互斥self落点共50/3954=1.26%，仅是可见helper指令份额，不是全部frame成本或可全部消除的收益。

policy可收集未被stale分支free的live buffers，整批送唯一consumer next；egress可整批送terminal。consumer有FlowEnd free及不同next，需要live indices/nexts；admit还有fragment/remote handoff，不能把所有from原样enqueue。状态判断仍按原packet顺序执行。

固定[buffer_node.h](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_node.h#L353)要求bulk数组具有`round_pow2(count,64)`可读padding，helper可能读count之后的元素。采用native批入口时必须遵循实际数组合同，并回归free/retained rejection/side-event和native发布次序。

## 8. 常态热路径里的诊断与重复准备

### 8.1 关闭trace不等于停止计数

普通Product VPN启动设置`trace_limit=0`，但submit4077先无条件共享`fetch_add(trace_packets,1)`再比较limit。无trace仍每包执行RMW是明确的无用工作。`policy_on_owner`3912–3914也每包SC exchange `hold_next_us`，未arm的普通路径仍写回0。

应让关闭诊断的路径不执行相关RMW，并保CLI并发启用、限额、慢读者测试的行为。**不能顺手改snapshot reader SC协议**；诊断fixture atomic与bank保护不是同一个合同。[graph源码](../../src/product/vpp/product_packet_graph.c)，2325、3912–3914、4077。

### 8.2 完整结果后的重复散列和共享status

match记录3113算probe evidence key，3156的remember在2988用完全相同参数再算一次，另算subject key；每次都重新投影lease并逐字段FNV。snapshot固定generation/revision/hash的policy prefix也反复算。NoMatch路径3176同样有evidence key工作。

已有图看到evidence_key self32、policy_key self24、packet projection self14；它们与cache覆盖的样本去重union243/3954=6.15%。该union不是可全部优化掉的份额。**零规则图没有证明matched重复分支执行占比**；完全重复的matched key由源码确认，NoMatch和固定身份准备有当前采样支持。

先共用一次投影、固定prefix、相同probe key，保持原key定义及commit-marker顺序；后续再研究worker-local诊断汇总。当前match/stage发布数十个共享原子status字段，Root也有共享统计；大部分累计诊断可按worker/节点汇总，但last-match typed查询和一致读取必须保留。[graph](../../src/product/vpp/product_packet_graph.c)，2929–3027、3083–3203、3761–3772。

真实lifecycle债务、credit和exactly-once counters不能当普通diagnostic延迟记账。火焰图主要单worker，也没有硬件cache-coherence/off-CPU数据，本报告不宣称已经测得多核cacheline ping-pong或锁竞争。

### 8.3 恢复完整lease，只为读取少数字段

`product_lease_from_metadata`恢复整lease、地址、typed key和platform；policy/consumer在它末尾已get platform后又读一次。consumer主要使用provenance与terminal状态选next，完整transport/canonical-key构造可避免。[graph](../../src/product/vpp/product_packet_graph.c)，782–871、1631–1635、1762–1775。

修复后lease inclusive46/3954=1.16%，self38；不是主要尖峰，但属于可以具体消掉的重复。最小访问仍要保span/generation失效所导致的runtime-drop行为，不能跳过校验。submit中重复get buffer和opaque读改写也可合并，是否被compiler融合需看生成代码。

不能把`memset`53个样本都归给Product清零：重分析看到它们在kernel skb路径；47个libc memmove里23个属于pbuf入栈copy、7个上层lease、1个上层projection。基础函数名字不能替代调用者归因。

## 9. HEV/lwIP上下文访问有直接ABI成本

修复后`tlsdesc_resolver_dynamic` self157/3954=3.97%，直接调用者全部为`hev_lwip_*`，不是规则cache的thread-local读。再加context_current self46、ip_data self37，三个互斥self位置合240=6.07%。主要路径可见`context_current/ip_data → tcp_input/ip4_input → hev_owner_input_copy`。

当前[hev-lwip-context.c](../../third_party/hev/product/hev-lwip-context.c)9–12、39–48通过`_Thread_local current`和外部getter重复访问。正确的owner-local隔离要保留；可审查一次owner驱动取得context并复用、内联/可见性/链接边界等减少重复resolver和call，而不改成共享global。TLS model优化需先核Android加载/线程生命周期约束，不能盲换initial-exec。

6.07%说明值得独立投入，不是说上下文hoist能消除整个份额。它也不由VPP matcher SIMD自动解决。

## 10. 冷分支的大栈对象影响正常函数布局

当前`l4_view_evaluate`3031声明自动`product_l4_policy_view_t empty_view`，只在bank-generation不匹配时init使用。匹配ELF正常函数prologue仍固定保留`0x60 + 0xf000 + 0x930 = 63,888 B`栈frame，见[汇编原件摘录](assets/2026-10-08-vpp-practice-audit/profile-elf-excerpts.txt)。

这是将冷fallback的大对象留在热函数布局的具体实例。可移到独立cold helper或适当immutable empty representation，保持原generation fallback和峰值合同。**不是每包memset63KiB，也没有证明仅调SP就是CPU主要热点。** 大frame与大量L4短callchain同时出现，但未核实simpleperf dump上限及因果，只列为可观测性/worker栈余量问题。

## 11. I/O路径很热，但不能用frame batching解释全部成本

| 有效窗口 | 路径 | inclusive / 分母 | 判断 |
| --- | --- | ---: | --- |
| 修复后VPN TCP20秒 | TUN complete |1200/3954=30.35%|含write及kernel协议工作；值得边界审查，不是30%纯helper浪费 |
| VPN UDP22秒 | HEV UDP direct-send |545/1994=27.33%|传输/系统调用路径；与规则空视图成本分开 |
| Root UDP22秒 | NFQUEUE send-verdict |930/2096=44.37%|高权重路径，但每个原packet ID结果必须保持 |

当前TUN逐packet write，Root逐obligation netlink verdict；frame提交与I/O聚合是两层。不能把多packet bytes简单拼进一次TUN write，也不能用累计verdict替代任意逐packet动作。若进一步优化，应审查合法batch系统接口和partial-send/故障/settlement合同；本次没有改它们，也没有把inclusive全算为可消除成本。

## 12. 哪些现有实践应保留

- Root直接recv到loaned native storage，再调整current_data到payload，没有多复制完整packet。
- callback最多64次非阻塞读，owner-inline Flow Stack预算仍必要，不能为凑大batch无限drain。
- parser/owner assignment在admit只做一次；后节点恢复字段不等于完整重解析或二次owner hash。
- metadata用inline storage和memcpy遵守alignment；不能直接强转opaque破坏合同。
- worker policy/cache已有cache-line对齐和owner-local访问，不泛称所有状态false sharing。
- snapshot claim/revalidation覆盖PRE、Flow、POST、domain及归因；不能为降低atomics随意弱化或改frame共享claim。
- ADR-0007保留VPP→lwIP和lwIP→新VPP buffer两次所有权接口copy。它们不是这次要删除的“冗余复制”。

普通Product VPN默认trace=0，Root首批有界trace和explicit诊断另有行为；源码有fprintf不代表稳态每包打印。multiarch/prefetch属于明确热kernel的后续工具，不是当前“未用最宽ISA所以浪费”的证据。

## 13. 建议首批改动边界与验收

本审查建议首批围绕四类已有证据：空view/无subject cheap完整查询路径；Root/TUN本callback内native frame形成；节点bulk enqueue及局部重复准备；禁用诊断无RMW。HEV上下文和冷fallback可独立评估。未新增另一份任务backlog，实施状态仍在Plane。

如果实施，先用现有最高seam验证full winner/NoMatch reason、mode/归因和cache计数口径；Root/TUN验证loan、stale/free、FlowEnd特殊buffer、partial handoff拒绝、fault/EAGAIN、stop/restart与exactly-once。native helper数组padding、packet顺序和graph side-event发布顺序要包括在内。

变更后做窄范围同条件复核即可，不需要先新建大benchmarkcampaign来决定第一批是否值得。规则候选/表达式SIMD的进一步投资则需要含规则负载证据；本次零规则图不能替代它。

## 14. 原始/派生证据与复现

原始输入均只读。派生结果保留于 [profile-analysis.json](assets/2026-10-08-vpp-practice-audit/profile-analysis.json)，包含self/inclusive、PC、callchain、去重union和精确时间窗；[manifest.json](assets/2026-10-08-vpp-practice-audit/manifest.json)保存原始perf/JSON/ELF、当前源码及上游文件hash。

已执行离线重分析及匹配ELF反汇编，退出码均0；结果复核与原hotspot摘要的N=3954、getenv=0一致。未跑新设备负载、未改变旧样本或生成新的性能提升结论。

```sh
rtk proxy python3 docs/reviews/assets/2026-10-08-vpp-practice-audit/analyze_existing_profile.py --output /tmp/vpp-practice-profile-analysis-new.json
rtk proxy /home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump --disassemble-symbols=product_l4_policy_match_cached,product_packet_graph_l4_view_evaluate build-output/vpn-mode-fix-20260928/symbols/libproduct_core_plugin.so
```

分析工具拒绝覆盖输出；复现请选择新路径。工具使用既有NDK simpleperf ReportLib与symbol cache，仅处理已有原始记录。
