# Root 整链 VPP 批量执行与预取优化规格

确认日期：2026-10-11。本文由已确认的设计访谈综合形成；描述目标与验收合同，不代表产品已实现或已获得性能收益。工作和验收状态以发布到 Plane 的规格项为准。

Plane 规格：[SAKAMOTO-291](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e03a4efc-32c0-4b7a-b529-12e06ee730bc)。发布时为 `Todo`、`high`、`ready-for-agent`，完整正文、标签与状态已回读核对；本地正文保留发布快照。

设计阶段澄清，2026-10-11：用户随后指出具体改造方案尚未形成共同理解。此前确认的是目标、验收原则与候选方向；不能将发布记录视为所有 Interface/布局方案已经选定。先完成[现状到改法的设计走读](../reviews/2026-10-11_VPP_ROOT_BATCH_DESIGN_MAP.md)，再补齐具体方案并评审拆票；本轮没有发布实施子票或修改父项。以下正文仍保留原发布快照。

后续用户选择，2026-10-13：完成[容量调参诊断](../testing/2026-10-13_ROOT_NFQUEUE_CAPACITY_TUNING.md)后，用户确认采用组合参数。当前Root启动默认改为128个普通接收／pending槽、48 primary credits、read budget16、1MiB socket请求（Pixel有效2MiB）及maxlen4096，默认构建batch＋packed；VPN仍为32 credits，产品原队列分配保持。见[实现与真机回归](../testing/2026-10-13_ROOT_COMPOSITE_DEFAULTS.md)。这是后来明确选择的容量变更，不是下文固定预算CPU验收通过的声明，也不把测试双lane夹具视为通用产品分流。原规格正文与历史失败保持原样。

## Problem Statement

个人本机端点防火墙需要在正确执行规则、维护 Flow 状态和释放每个捕获义务的同时，减少 Root 流量处理的 CPU 成本。当前 VPP-native C 主线已使用共享 graph、固定 FlowOwner、native frame queues 和通知合并，但入口将 readiness burst 拆成单包 frame，节点缺少相互配合的准备/预取流水线，primary 与 completion 的 producer publication 仍逐包执行。

孤立地替换 helper 或优化一个 node，不一定能让完整路径获得收益：上游无法提供 batch、下游仍逐项发布，或者其他阶段成为限制时，必要前置机制的作用可能不会出现在单点指标中。Root 的 fail-open 还允许部分未充分执行策略的包继续交付，因此端点 Mbps 或 admitted packets 不能直接证明策略处理效率。

## Solution

以 Root 为首个验收场景，形成从 NFQUEUE readiness、native ingress frame、admit preparation、primary handoff、owner-local policy/Flow、consumer/terminal、completion return/retry 到 origin-lane completion 与 buffer 归还的完整候选。独立包的准备、访存、查表和发布共同组织为有界批次；同 owner 上的状态更新按原包顺序执行。

保持既有 worker、credits、队列与池容量上限。各实施步骤先通过正确性、生命周期和机制验证，累积到同一候选；不要求每个步骤独立显示性能提升。完整候选通过整链 CPU 效率收益验收后，才进入默认实现。

主指标是相同负载与资源预算下的 **VPP CPU 时间 / Policy-Qualified Packet 数量**。正常 ALLOW/DROP、且 Adapter Completion 为 `SUCCEEDED` 的包计入；fail-open/bypass、未接纳流量、没有 Policy Verdict 的 runtime drop，以及 END/completion 内部 carrier 不计入。吞吐、尾延迟、拒绝、旁路、idle CPU 与结算同时验证。

规则快照的包级或有界批级获取在整链实现时依据收益、批次耗时和并发证据选择。单包内的规则版本一致性必须保持；个人用户的规则发布不冻结为发布瞬间逐包切换的硬限制。

## User Stories

1. 作为 Root 用户，我希望防火墙处理相同流量时消耗更少 CPU，以减少运行开销。
2. 作为 Root 用户，我希望多应用同时联网时整条处理链共同利用批量执行，以获得组合后的收益。
3. 作为 Root 用户，我希望低流量时已经收到的包立即得到处理，以保持交互响应。
4. 作为 Root 用户，我希望正常允许的流量继续按原规则放行，以保持应用连接行为。
5. 作为 Root 用户，我希望正常拒绝的流量仍被原规则拒绝，以保留实际防护效果。
6. 作为 Root 用户，我希望容量或基础设施故障继续按既有 fail-open 语义处置，以保留明确的连接恢复行为。
7. 作为 Root 用户，我希望故障旁路被单独记录，以区分连接成功和实际策略覆盖。
8. 作为 Root 用户，我希望同一 flow 的连续包看到前包更新的状态，以保持 conntrack 和识别判断正确。
9. 作为 Root 用户，我希望新建、结束、替换和过期 flow 不使用陈旧查询结果，以避免错误策略和错误归属。
10. 作为 Root 用户，我希望 UID 的已知/未知状态与冲突行为保持一致，以正确执行应用规则。
11. 作为 Root 用户，我希望规则使用当包适用的 CT、协议和域名事实，以保持规则胜出关系。
12. 作为 Root 用户，我希望修改规则后后续批次可靠使用新配置，以避免旧 verdict 长期保留。
13. 作为 Root 用户，我希望一个包的各策略阶段使用同一受保护规则版本，以避免混合配置产生错误结果。
14. 作为 Root 用户，我希望已经开始执行的小批次可以按一致的旧快照完成判定，以给整体性能优化留出空间。
15. 作为 Root 用户，我希望 IPv4/IPv6 与当前支持的传输协议保留原有行为，以避免批量优化缩窄兼容性。
16. 作为 Root 用户，我希望分片、END 和异常包与普通包混合时都正确结算，以避免漏包或资源泄漏。
17. 作为 Root 用户，我希望每个捕获包只完成一次平台义务，以避免重复 verdict 或重复回收。
18. 作为 Root 用户，我希望平台 completion 失败不会被错误重试或伪装为成功，以保留可解释的故障结果。
19. 作为 Root 用户，我希望停止和重启时在途批次全部得到有界结算，以避免遗留队列、buffer 和 hook。
20. 作为 Root 用户，我希望本轮优化保持现有资源容量，以避免通过扩大在途流量换取表面收益。
21. 作为 VPN 用户，我希望共享 graph 的变化保留已有 VPN 行为，以安全复用改进后的执行机制。
22. 作为维护者，我希望必要前置机制通过正确性验证后能够接入同一候选，以完成整链优化。
23. 作为维护者，我希望真正的 publication 和 frame-size 证据覆盖完整路径，以确认批量机制已经贯通。
24. 作为维护者，我希望完整策略判定与真实 Adapter Completion 能关联计数，以计算合格的每包 CPU 成本。
25. 作为维护者，我希望稳态多流和建流/结束负载都参与验收，以覆盖不同查表与状态更新行为。
26. 作为维护者，我希望基线与候选采用同一负载和采集条件，以获得可比较的整体结果。
27. 作为维护者，我希望测量协议在开测前冻结且执行次数有界，以避免不停重试直到出现有利数字。
28. 作为维护者，我希望失败、无收益和不可比较的结果保持原样留存，以保留可靠的后续设计依据。
29. 作为维护者，我希望实测未证明整体收益的候选不被宣布为默认优化完成，以保持实现和结论一致。
30. 作为维护者，我希望接口隐藏 Flow 索引、快照保护和失败结算的复杂度，以便在现有 Module 上维护与测试。

## Implementation Decisions

1. **首轮范围。** Root 普通未分片包是首个优化和收益验收场景，覆盖双向处理及 primary/completion 两端。共享 graph 仍服务 Root/VPN；VPN 保留代表性回归。分片、END 和其他现有路径的混合输入、结算与 teardown 正确性属于回归要求，专门优化这些旁支不是默认性能前置条件。

2. **完整候选。** ingress、准备、lookup、publication、consumer/terminal、return/retry 与 origin completion 一起设计。步骤之间可以有实现依赖；孤立环节没有显示吞吐提升，不能自动阻塞或撤回必要前置机制。整体正确性失败必须修复；整体收益不成立则候选不得作为已完成的默认优化。

3. **Native frame 是 carrier。** Root Adapter 在同一次有界 readiness 中利用现有 receive pool 收集成功子集，按需一次或分段提交多向量 native frame。提交之前由当前 holder 负责失败结算，接受之后由 graph 负责。每个 callback 出口都处理已经准备的子集；不为凑满 batch 等待后续流量，不建立独立 payload queue、packet map 或第二套 dispatcher。

4. **准备 Module。** Packet Module 提供产品自身的有界准备 Interface，批量取得 buffer pointers，短 x2/x4 窗口交错独立包的解析、canonical key/hash 准备，并提前加载后续 header/data。保持当前 typed key、seed、hash 值、owner mapping 和错误判定；parse-only private helper 不是已经存在的公共批量能力。工作区按 worker/dispatch 固定有界，不保存全帧完整 PacketLease，不引入 per-packet heap。

5. **Primary publication。** 按既定 target 组织已准备 indices，真实调用现有 retained bulk enqueue。每包仍独立 reserve 原 packet credit，达到准备窗口或 credit 边界时及时发布，避免先占尽整帧 credits 才首次发布。成功子集不再读写 buffer；failed-index 子集继续由发送方持有，回滚对应 credit 并按原 runtime/fault policy 结算。

6. **资源预算。** 正常候选和收益基线保持 W2、每目标 owner 32 个 primary packet credits、现有 primary/completion ring 深度，以及 Flow、receive、completion/backlog 容量上限。ring element 与 packet credit 是不同单位，packing 不提高 packet 上限。批次窗口、预取距离、服务预算和发布时点由工程设计联合确定。已有故障诊断可以在独立标记的正确性案例中施加压力，不作为扩容后的性能比较。

7. **FlowRuntime Interface。** 紧凑查表索引和 bucket/index/state 分层预取由 FlowRuntime 私有实现；node 不取得 pool/table 所有权。保留启动预分配、逻辑 expiry、incarnation、unlink/FlowEnd/归槽生命周期。先提供无 mutation 的准备/预取，在逐包 commit 时查找或验证受检结果；不缓存全帧权威 miss，也不跨 node 传裸 entry 指针或新增 tuple side table。冷热分离保持原固定容量，并计入额外有界工作区/索引的实际内存成本。

8. **规则查询准备。** Policy Module 在受保护 snapshot 中组织静态 projection、guard/key/hash 与 cache/index prefetch。保持完整 residual 判定、winner ordering、mode、已知/未知事实及 cache guard。POST 查询所需 CT/LPI/SNI 等事实必须在当包 Flow 更新后形成；相邻和非相邻同 flow 都看到前包产生的变化。已有单 key 编译器 NEON 不是跨包流水线证据，本轮不以换 hash 或添加 intrinsics 替代整链设计。

9. **快照粒度。** 包级或有界 policy frame/短窗口级 claim 在完整实现时选择，不冻结逐包取得新配置。批级候选只保护当前已经开始执行的工作，窗口内每包使用同一合法快照完成适用阶段；后续批次读取最新 active snapshot，existing-flow decision/cache 按所用 revision 重新判断。禁止 PRE/POST 混版、bank reuse race、旧快照跨未来批次保留和旧 verdict 延续到 expiry。记录实际 hold duration 与发布并发结果，并同步规则可见性合同及其测试；不在设计阶段猜定不可证明的微秒上界。

10. **有序提交。** Flow/CT/UID/LPI/SNI mutation 保持 canonical owner 上原包顺序，前包 create/close/replacement/expiry 即时对后包可见。同一待发布数组内同 target/origin 的顺序保持；不新建跨 worker 的全局排序或 live-flow migration。

11. **Consumer/terminal 投影。** 按 stage 提供真正需要的 routing/terminal 视图，配合整帧 pointer/metadata 预取，形成既有 completion carrier。保留 span/generation 检查以及 END、fragment、trace 分支；不扩大 opaque，不重新解析或选择 owner，不将内部信号伪装成网络包。

12. **Completion return/retry。** 当前 dispatch 和现有 bounded backlog 内按 origin worker 批量 retained publication，部分成功逐 carrier 结算。Routing retry 维持当前 holder 和原容量；不增加 payload queue、异步借用指针或平台 verdict 重试。跨线程发布前已建立正确 debt，回收后才释放对应资源。

13. **Origin completion。** 整帧预取/投影、按 origin lane 组织准备和回收；原 lane 独占 NFQUEUE fd、queue generation 与 packet-id authority。每包保留独立 verdict 和一次平台操作尝试。Root buffer 归还既有 receive pool，适用的其他 buffer 才交给 VPP free。若使用 syscall batching，必须证明逐 packet identity、部分/不确定结果和一次尝试语义；不得将不同 verdict 简单折叠为一个 packet-id 范围 verdict。平台操作粒度可以依证据选择，不能省略最后一段的生命周期设计。

14. **已有机制继续复用。** Native next-frame 累积、FQ receiver 合并、固定 affinity、owner-private state 和 Android notification latch 已实现。减少 producer publication 可以减少 latch 操作，不能破坏 publication/wake 顺序。批内纯统计可以聚合；真实跨线程 credits/debt 的同步点必须保持正确，避免 stop/teardown 误判为空。

15. **测量 Interface。** 提供有界的策略处理与 origin-completion 关联计数，以及 packet/batch/publication/credit 分类。Policy-Qualified Packet 必须同时具有完整适用 Policy Verdict 和 `SUCCEEDED` Adapter Completion。保持 generation/origin/obligation 来源身份，排除 replay、GRAPH_INJECTED 与内部 carrier 对真实 NFQUEUE 计数的污染。平台函数“已处理并归还 buffer”的布尔结果不是 verdict 成功证明。尽量使用 owner/lane 私有计数与有界采样，避免新增常态逐包日志或共享统计争用。

16. **实现依据。** 唯一产品目标是现有 VPP-native C 主线及固定 VPP 源码机制。遵循已接受的 ownership、metadata 和 Root fault contracts。POC 和撤回候选仅为证据输入；不导入其 source，不恢复、翻译或参考已删除 C++ 实现。

## Testing Decisions

1. **测试 Interface 已在设计草案中确认。** 共享语义优先通过现有 Adapter-neutral VPP graph 契约验证，从真实 packet ingress 到 policy/Flow outcome 和 terminal/settlement；不新增为了逐个 helper 测试而存在的公共 seam。FlowRuntime 与 Policy Module 的内部变化可沿其已有 Interface 做有意义的语义回归。

2. **测试观察行为和所有权。** 验证实际 verdict、规则版本一致性、前包状态对后包的可见性、incarnation/expiry、一次 settlement 和 debt conservation。测试不锁定 x4 等具体循环写法。独立的有界机制证据检查 native frame、真实 queue publication 和预取/准备作用点，不能以 helper 名称或调用计数代替正确性。

3. **Root 平台验收。** 使用真实 NFQUEUE capture、原 origin lane 和真实 verdict syscall，验证完整 identity、ALLOW/DROP、容量旁路、partial publication、stale/duplicate carrier、真实 verdict failure、pool return 和 clean stop/restart。沿用现有 source/artifact/request/raw/verifier 证据链，不放宽旧 verifier 的原始适用范围。Host/GRAPH_INJECTED 可支持语义，不能满足 NFQ wire claim。

4. **共享语义矩阵。** 覆盖短/长/混合 frame、同帧及非相邻同 flow、首次创建、结束、替换、逻辑 expiry、UID 冲突、PRE/POST 动态事实、完整 winner/residual/cache guard、配置发布与 bank reuse、END/fragment/异常包混合、部分接受和所有 callback/dispatch 的提前退出。

5. **发布与生命周期。** 验证 primary 和 completion/retry 两个方向均实际多包 publication，packet credits 和 ring elements 分类正确，成功后无 buffer 访问，失败集合全部留在合法 holder。Native free、Root receive-pool return、FlowEnd 槽位归还与 Stop drain 分别按其真实语义证明。

6. **VPN 回归。** 共享 graph 变化必须通过代表性 VPN ingress/return、owner-local flow stack、必要复制和普通 start/stop 回归。此次不把 VPN HEV drain 调优或 VPN 性能收益作为 Root 默认采用的前置性能门槛。

7. **双栈和来源分层。** 共享已支持语义覆盖 IPv4/IPv6 和适用 TCP/UDP/其他类型。设备 wire 证据逐 profile、协议、family 和输入来源明确标注；无法从真实网络确定重现的边界用明确标记的契约证据支持，不扩大实网覆盖声明。

8. **计数资格。** 完整判定和成功 Adapter Completion 在同 generation 与 immutable obligation 上关联，ALLOW/DROP 分开审计，再合成合格分母。验证旁路、runtime fault、completion failed/unknown、replay 和内部 carrier 的排除。校验分母与 policy、verdict、pool/debt 守恒；资格失败的窗口不能参与主要 CPU 收益结论。

9. **收益只验收完整候选。** 多流稳态与建流/结束负载采用非空有效策略，使准备、Flow/rule lookup 和两个 handoff 方向实际执行。轻负载检验响应和 idle CPU。基线/候选保持相同资源、规则、流分布、包大小、offered load、worker placement 和采集成本；ALLOW/DROP 工作构成与策略覆盖率必须可比较。

10. **CPU 主指标。** 对合格窗口测完整 VPP runtime CPU 时间与 Policy-Qualified Packet 数量。不能仅使用 admitted packets、endpoint bytes、单 node clocks 或 generator 发包速度。增加拒绝/旁路、漏掉昂贵策略处理或改变判定工作构成，不得算作收益。

11. **有界、冻结的对照协议。** 在开测前冻结负载、窗口、warmup、顺序、资格条件、统计规则、护栏及总执行上限。完整候选的 CPU 效率改善须可复现并能够区别于噪声/漂移；5%/10% 仅为参考目标，不是单点硬门槛。不得事后选择窗口、改变负载或不断延长采集直到得到有利结果。未取得稳定结论时保留不可判定结果，候选不进入已完成的默认优化。

12. **护栏和证据身份。** 同时报告有效处理吞吐、endpoint 交付、尾延迟及样本资格、拒绝/旁路、batch hold duration、资源高水位、idle CPU 与 lifecycle 结果。结合现有相同-ELF profile 手段定位限制；APK/native/source/VPP pin、设备、generation、rules/helper/config/collector 身份与原始失败一并留存。当前旧 endpoint benchmark 不被重新命名为策略覆盖合格的基线。

## Out of Scope

- VPN HEV/lwIP 输入/drain 专项调优及其性能收益验收。
- worker、credits、ring、pool/backlog 扩容，以及 live-flow migration、overload spill 或 shared NFQUEUE TX。
- 恢复 C++ 主线、导入 POC source、增加 per-packet Rust bridge 或第二套 packet implementation。
- hash 算法替换、单 key SIMD 微优化、zero-copy/lwIP memory-model 重设计或仅为采用名称而替换为动态扩容索引。
- 新 DNS/规则/识别产品能力、UI 改版、网关即时切断 SLA、完整产品发布与电气能耗认证。
- 把每个 syscall 都必须改成 bulk 作为未经语义验证的先决条件，或要求每个实施步骤独立显示性能提升。

## Further Notes

产品起点为 `54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6` 的恢复后 C 主线；VPP pin 为 `9258530f3804a152578ce11cc7c8a1e9eab88ed0`。此次规格确认及发布没有修改产品、操作设备或启动新的性能采集。

官方 [packet graph 说明](https://docs.fd.io/vpp/22.10/aboutvpp/extensible.html) 支持 vector 经过各 node、node 内逐包处理的执行模型；具体准备、预取和状态顺序依据 [固定 pin 的 ACL node](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/plugins/acl/dataplane_node.c#L243)，publication/receiver 行为依据 [固定 pin 的 VLIB enqueue/dequeue](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L291)。这些是机制证据，不是对本产品收益的预测。

设计与事实来源：[已确认的访谈记录](../reviews/2026-10-11_VPP_BATCH_DESIGN_DISCUSSION.md)、[四个子代理及主代理的源码审查](../reviews/2026-10-11_VPP_BEST_PRACTICES_AUDIT.md)、[现有 benchmark 的范围](../../tests/benchmark/README.md)。约束来源：[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)、[ownership](../decisions/PER_WORKER_FLOW_OWNERSHIP.md)、[metadata](../decisions/VPP_PACKET_METADATA_OWNERSHIP.md)。历史失败和撤回证据继续保留，不能作为现行能力或默认 source 模板。

后续 implementation tickets 应按贯通的纵向切片及其依赖拆分；实现步骤可提交完整候选中的必要前置机制，但父规格的默认采用门槛只能由整链资格、正确性和收益证据共同满足。
