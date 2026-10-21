# VPP 批量闭环设计访谈

日期：2026-10-11。依据：[当前 C 主线的 VPP 实践审查](2026-10-11_VPP_BEST_PRACTICES_AUDIT.md)。本文记录 `grill-with-docs` 访谈中逐项明确的目标和取舍。用户曾要求进入规格阶段，随后明确指出具体改造仍未形成可理解的方案；因此目标/验收共识继续有效，Interface/布局方案须先完成[设计走读](2026-10-11_VPP_ROOT_BATCH_DESIGN_MAP.md)，再评审拆票。[已发布规格](../product/VPP_ROOT_BATCH_EXECUTION_SPEC.md)与 [SAKAMOTO-291](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e03a4efc-32c0-4b7a-b529-12e06ee730bc) 保留发布事实与工作状态。本文是访谈证据，不是独立工作清单。

## 已明确的本轮范围

用户选择 **Root 先行**：以 Root 普通未分片包为首个验收场景，设计从 ingress 成帧、admit 准备、primary publication、owner 按序处理到 completion return 的完整批量闭环。

共享 VPP graph 的接口仍兼容 VPN，保留 VPN 回归验证；VPN Userspace Flow Stack 的 HEV 输入/drain 协调留到后续切片。Root 先行是实施与验收顺序，不建立另一条 Root 专用 packet mainline，也不改变既有 Canonical Flow Key、FlowOwner 或 origin-lane Adapter Completion 约束。分片等已有路径继续受原有正确性和结算契约约束。

该顺序可随证据调整，没有引入新的长期架构边界，因此不新建 ADR。此项确认也不代表整个设计已经达成共享理解或开始产品实现。

## 默认实现的收益门槛

用户选择 **B：收益验收**。批量闭环须先通过正确性、策略覆盖、资源有界和 exactly-once settlement 验证；此外必须证明可复现的 CPU 成本降低或有效策略处理能力提升，才进入默认实现。

主收益指标见下文，具体负载和阈值尚待设计访谈明确。Root fail-open/bypass 保持既有故障语义；增加旁路、遗漏策略处理或将更多包判定为容量失败，不能作为性能收益。当前 endpoint delivered Mbps 不自动等于完整策略处理吞吐。

性能验证安排在设计与实现之后。未达收益门槛的候选可以保留证据，不作为已完成的默认优化，也不以既有波动测量宣布收益或回归。

### 收益验收的粒度

用户进一步明确：**收益门槛针对完整 Root 批量执行链路，不针对孤立的 helper、node 或实施步骤。** 入口成帧、节点准备与预取、规则/Flow 查表、primary publication、completion return/retry 和 origin-lane 结算应作为相互配合的候选设计；局部机制可能是后续批处理的必要条件，其独立测量不一定能显示整条路径的收益。

分阶段实现可以先凭正确性、生命周期和机制证据接入同一候选。不能因为单点没有显示吞吐提升就撤回必要的前置机制，也不能将各阶段的独立性能筛选设成默认阻塞条件。完整候选形成后，统一进行 B 所要求的收益验收；整体收益仍须可复现，不凭批量 API 名称或理论推断宣布成功。

各段共同组织独立 packet 的准备、访存与发布；Flow/CT/UID/LPI/SNI mutation 保持 canonical owner 上的原包顺序。批量机制不要求改变 NFQUEUE 逐 packet 的 verdict 语义，也不以等待新包凑满批次换取平均指标。

## 一致资源预算

用户选择 **A：保持现有资源上限**。首个完整候选保持 worker 数量、packet credits、native frame queue 深度、Flow/receive/completion 等池或 backlog 的容量上限，与产品基线一致。批次大小、预取距离、发布时点及各段服务预算可以联合设计；这些可调执行参数不等于允许扩容。

特别区分：当前每个目标 owner 的 primary handoff 上限为 32 个 packet credits，policy receive 时归还；FQ ring slots 按 element 计数。Packing 多包进一个 element 不改变 packet credit 上限，也不能将 32 个 packet credits 重新解释为 32 个 frames。方案需要适应相同资源预算下的占用时序，保留非阻塞拒绝、Root 故障处置与完整结算。

此项限定整链收益比较的资源条件，不要求逐阶段独立收益验收。

## 主收益指标

用户选择 **A：CPU 效率**。在相同负载和资源预算下，以完整 Root 链路的 **VPP CPU 时间 / 有效策略处理包数** 为主收益指标。适用于该包的策略判定已完成、且 Adapter Completion 为 `SUCCEEDED`，才计为一个有效策略处理包；正常 ALLOW/DROP 都计入，fail-open/bypass、未接纳包、没有 Policy Verdict 的 runtime drop、内部 END/completion carrier 不计入。

吞吐、尾延迟、拒绝、旁路与结算结果同时作为护栏，具体护栏和收益阈值尚未确定。单纯提高端点交付速率不能替代所选的 CPU 效率收益门槛。现有脚本的 admitted packets 和 endpoint delivery 不自动满足这个分母，需要用完整策略判定与成功 Adapter Completion 的关联证据验证计数口径；该口径是接受的测量目标，不是现有 collector 已实现的能力。

### 收益幅度与组合效应

用户对 5%/10% 参考幅度均可接受，强调必要机制可能在组合后才产生共同收益，并授权常规执行组织遵循 VPP 最佳实践。因此不以这两个百分比作为孤立环节或设计推进的硬门槛；先形成完整 Root 候选，保留整体可复现 CPU 效率改善的默认实现门槛和正确性护栏。

批次窗口、预取距离等常规实现参数由工程设计依据固定 VPP 源码和现有约束确定，不逐项要求用户预测收益。最终测量协议须在收益测试开始前冻结，不能看结果后倒推通过条件；候选未证明整体收益时仍不得宣布默认优化完成。

## 规则发布可见性的粒度

用户明确不将“必须逐包取得当前规则快照”设为硬约束。包级或批级快照可在完整实现时结合收益和批次耗时选择；不为发布瞬间的逐包可见性提前排除整批优化。适用场景仍是已有领域模型中的个人本机端点，未引入网关式即时切断承诺。

现行 `policy_on_owner` 每包 claim/release protected bank。批级候选在一个已经开始执行的 policy frame 或有界短窗口内固定规则版本，后续批次取得新的 active snapshot；窗口内每个包仍在同一 protected snapshot 下完成其适用策略阶段，不允许 PRE/POST 混用不同规则版本，也不保留旧规则跨越未来批次。用户允许的取舍是有限在途工作的版本可见时点，不是遗漏新规则、保留旧 flow verdict 到 expiry 或绕开 snapshot lifetime 保护。

批级方案的额外可见性延后取决于**当前已开始批次的剩余策略处理时间**。以稳定 owner 服务速率粗略换算，剩余包数 `N` 与处理速率 `R` 给出 `N/R`：剩余 64 包、10 万包/秒约 0.64 ms，100 万包/秒约 64 μs。这只是量级示例，不是当前 Pixel 实测或时延上界；实际分支、识别工作和调度可改变耗时，实施时应直接记录 batch hold duration。不能拿输入发包间隔或端点 Mbps 代替内部处理速率推断延后。

具体可见性粒度在整链实现时确定，并与 Policy Apply、Policy Revision Re-evaluation 和 snapshot 并发测试的措辞保持一致；目前不创建冻结包级或批级语义的 ADR。

## 整链候选草案

以下是依据已明确目标形成的设计草案，供共享理解确认后转成规格。没有产品代码变更。各段共同组成一条候选；实施步骤可以依赖正确性和机制证明累积，默认收益门槛只施加于完整候选。

| 执行段 | 拟定机制 | Interface 的核心契约 |
| --- | --- | --- |
| Root ingress | 在同一次 read readiness 内，用既有 receive pool 收集已接纳 indices，一次或分段提交 native 多向量 frame | 每包独立 facts/obligation；所有 callback 出口都提交或结算已准备子集；不等待新流量凑满 batch |
| Admit preparation | bulk buffer pointers、header/data lookahead、短 x2/x4 parse/canonical/hash 准备 | 新设计产品 C 的准备接口；typed key、seed/hash 值、owner mapping 与解析结果保持一致；不重新计算 owner |
| Primary publication | 按既定 target 组织 indices，在有界窗口内实际调用 retained bulk enqueue | 按包 reserve 原 credits，达到窗口或 credit 边界时及时发布；failed-index 子集由发送方继续持有并结算，成功后不访问 buffer |
| Owner Flow/rule lookup | Module 内的紧凑 Flow 索引与 bucket/index/state 分层 prefetch；静态 projection/key/hash 批量准备 | pool/table 保持 opaque；准备不固定全帧 miss 或裸 entry 指针；逐包提交时看到前包 create/close/replacement/expiry |
| Policy execution | 在 protected snapshot 内组织查询流水线，包级/有界批级 claim 结合证据选择 | 同 owner 上 Flow/CT/UID/LPI/SNI mutation 保序；POST facts 在当包更新后形成；cache/residual/winner 语义一致 |
| Consumer/terminal | 整帧 pointer/metadata 准备；提供 stage 所需的较小投影视图，形成原 completion carrier | 保持 span/generation 校验、END/fragment/trace 分支；不扩大 opaque，不引入 per-packet heap 或假 IP 包 |
| Completion return/retry | 当前 dispatch 和既有 bounded backlog 内按 origin worker 实际 bulk retained publication | 部分成功逐 carrier 结算；维持现有持有者和容量，不新增 payload queue；routing retry 不变成平台 verdict retry |
| Origin completion | frame 内预取/投影、按 origin lane 组织准备与回收；每个 packet 保持自己的 NFQUEUE verdict | 原 lane 独占 fd/packet-id authority；每个 obligation 只有一次平台操作尝试；Root buffer 归还 receive pool，适用的其他 buffer 才交给 VPP free |

上表将 prepare、lookup、publication、return 和实际回收一起设计，不仅替换 enqueue wrapper。批次窗口需要与 32 packet credits 和 receiver 进度共同适配，避免先占尽整帧 credits 再第一次发布。小 frame 立即执行；异常包、END 与分片可沿既有分支结算，但混合 frame 仍不能丢掉已准备的普通包。

已有 native next-frame 累积、FQ receiver 合并和 Android notification latch 继续使用。批内可合并纯统计更新；跨线程 credits 和真实 lifecycle debt 必须保持正确的发布前/回收后同步时点，不能用计数滞后让 stop/teardown 误判为空。

Origin 段当前每包构造并发送 NFQUEUE verdict，见 [complete_from_graph](../../src/product/vpp/product_root_nfqueue_adapter.c#L894)。设计会连同最后一段准备与回收一起组织；若进一步采用 syscall batching，必须先证明逐 packet identity、一次尝试和部分/不确定结果的结算。不能把一组不同 verdict 的包简单替换为按 packet-id 范围决定同一 verdict，也不假称当前已有可用的批量平台 completion Interface。

## 验证草案

共享语义通过当前 VPP-native C graph/Module Interface 验证；Root 在实际 NFQUEUE ingress/completion 上验证，VPN 保留代表性回归。覆盖同帧及非相邻同 flow、首次建流/结束/替换/expiry、静态与动态规则事实、ALLOW/DROP、部分 publication、stale/duplicate identity、真实 verdict failure、配置发布、END/fragment 混合分支以及 stop drain。

机制证据覆盖整条链：input/policy 的 vectors per frame、prepare/lookahead 作用点、primary/completion vectors per physical publication、查表与 snapshot claim 次数、真实批次 hold duration、credit 占用/拒绝、origin success 与 pool return/debt conservation。缺少完整策略处理和成功 Adapter Completion 的关联证据时，CPU 分母不合格；source 中 `complete_from_graph` 返回值表示是否处理并归还 Root buffer，即使 verdict syscall 失败也可能返回真，不能拿该布尔值直接当作 `SUCCEEDED`。

收益测试在完整候选形成后进行。拟覆盖非空有效策略下的多流稳态和建流/结束负载，让 Flow/rule lookup 与两个 handoff 方向均实际执行；轻负载作为时延/idle CPU 护栏。基线与候选采用相同资源、规则、流分布、包大小、负载和采集方式，测量协议在开测前冻结；既有 quick runner 的 endpoint 指标保留为旁证，不作为已取得策略覆盖资格的主指标。具体计数关联、负载参数、时长和统计判定由实施证据收敛，当前未开始新的性能采集。

## 术语与约束依据

沿用 [CONTEXT.md](../../CONTEXT.md) 的 Runtime Profile、FlowOwner、Platform I/O Lane、Adapter Completion 和 VPN Userspace Flow Stack。`frame`、`batch`、`prefetch` 是通用实现术语，不作为新的领域概念写入词汇表。

架构约束保持 [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)、[per-worker ownership](../decisions/PER_WORKER_FLOW_OWNERSHIP.md) 和 [packet metadata ownership](../decisions/VPP_PACKET_METADATA_OWNERSHIP.md)。
