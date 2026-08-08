# Android Functional Closure Contract 与 Evidence Matrix

状态：accepted working contract，2026-08-08。来源：SAKAMOTO-65。本文是可由新 POC、正式代码和受控真机证据显式修订的工作合同，不是首次发版的最终冻结规格。

## 1. 目的与权威边界

本文固定 Android Root/NFQUEUE 与 VPN/TUN 第一条共同功能闭环的外部行为、证据分层和通过条件。它把已经接受的 ADR 与领域语义转成可执行验收边界，但不提前决定核心 policy/control 内部实现、最终持久化、容量常量或发布级平台策略。

冲突时按以下顺序处理：

1. 已接受 ADR 和 `CONTEXT.md` 中的领域不变量；
2. 本工作合同的当前验收边界；
3. Plane implementation ticket 中受当前代码和证据约束的具体方案。

如果 POC、正式实现或受控真机结果与本文冲突，暂停受影响 gate，记录证据，并显式更新本文；若冲突触及 hard-to-reverse 架构边界，则同时更新或新增 ADR。不得为保留绿色结果而静默降低断言、扩大 skip 或把有效失败改写成环境无效。

## 2. 固定不变量与证据驱动变量

### 2.1 固定不变量

- Android 任一时刻只有一个由 RuntimeService 监督的 VPP runtime；Root 与 VPN 是互斥 Runtime Profile。
- Root/NFQUEUE 与 VPN/TUN packet I/O 位于 VPP-native C/C++ Adapter plugin；Rust 不接收、返回或拥有逐包数据和 live VPP buffer。
- 两种 Profile 共享 VPP parser、PacketFacts、FlowOwner、policy stage、policy revision 和 verdict 语义；平台 Adapter 不能成为第二套 parser 或 policy engine。
- PacketLease 由 live VPP buffer 与内联固定 metadata 承载；每个有效 obligation 只允许一次 Adapter Completion physical attempt。
- Policy Verdict、Runtime Disposition、Adapter Completion、VPN Transport Outcome 与 Infrastructure Fault 是不同事实，任何一层不得改写另一层。
- User-Space Single Materialization、VPP Packet Byte-Movement Contract、Packet Byte Mutation Authority 和 bounded resource/teardown obligations 保持有效。
- Root 与 VPN 的最终 closure 必须由 e2e 结果和跨 Profile parity 证明；Root-only pass-through 或 POC counters 不构成 closure。
- conditional wake 的现有实现为 non-GO，不进入本合同或 release 实现。

### 2.2 证据驱动变量

以下事项由 implementation ticket、POC 与测量继续收敛，不在 SAKAMOTO-65 中冻结：

- C ABI/VAPI 的具体 message、类型和文件布局；
- queue、worker、buffer、ring、completion credit、Fail-Open Reserve 的具体数量；
- capacity、latency、CPU、power、thermal 与长期 soak 的最终发布阈值；
- policy/control 的最小内部实现步骤、存储引擎、checkpoint 与迁移方式；
- Runtime health 的锁存、自动清除、自动 restart/backoff 和最终 Product UI 呈现；
- release signing、升级/回滚、OEM/Android 版本矩阵和 Activity Store retention。

这些变量可以调整，但调整不得绕过固定不变量或改变已经产生的 packet outcome attribution。

## 3. Functional Closure 范围

### 3.1 本闭环包含

- 一个受控目标 Android 设备上的 Root 与 VPN Runtime Profile；
- 一个真实安装应用的 complete Linux UID，以及显式 Unknown Application fallback；
- IPv4/IPv6、TCP/UDP、Wi-Fi/Mobile Network Gate 和最小 stateless L4 policy；
- 同一 Authoring Policy 的可观察 policy revision、winner、verdict 与 reason；
- VPP-native ingress、Flow ownership、completion、transport、fault、health 和 teardown；
- 最小 Debug Control Activity：选择 Profile、启动/停止、操作最小测试 policy、查看 bounded current/recent runtime 与 verdict evidence；
- clean lifecycle、profile switch、process/runtime failure recovery 和 residue 检查；
- Host、Adapter conformance、Android 真机与 e2e 联合证据。

### 3.2 本闭环不要求

- 完整 App Catalog、完整 Product UI 或持久化 Activity Store；
- Checkpoint、import/export、完整 authoring CRUD 或最终数据库方案；
- Linux Product、Protocol Identification、full Stateful Conntrack、DNS/domain 能力；
- release signing、最终升级/回滚策略、长期 soak 门槛或完整 OEM/OS matrix；
- conditional wake、Linux GSO/jumbo、chain-aware parser 或未由新证据批准的 full-packet copy fallback。

Out-of-scope 表示不作为本闭环交付承诺，不表示禁止复用现有测试或采集额外真机证据。任何额外运行发现的有效产品失败仍需记录和处理，不能因该 case 不属于当前 gate 而隐去。

## 4. 联合 e2e 通过条件

一个 nominal packet case 只有在以下联合结果全部符合预期时才通过：

1. 输入身份与 normalized platform hints 正确；
2. PacketFacts/parser status 与 FlowOwner 正确；
3. 预期 policy stage、winner、Policy Verdict、reason 和 policy revision 正确；
4. Runtime Disposition 正确；
5. Adapter Completion 执行一次且 outcome 为 `SUCCEEDED`；
6. VPN allow case 的 Transport Outcome 成功，或 Root case 的真实 kernel/network 行为与 verdict 一致；
7. 真实业务流量表现与预期一致；
8. 没有未预期 Infrastructure Fault、duplicate completion、packet replay、resource residue 或 health degradation。

因此：

- UI 显示正确 `ALLOW`/`DROP` 但 completion、transport 或真实流量错误，case 失败；
- VPN policy allow 后 HEV/网络失败，Policy Verdict 仍为 allow，但 nominal e2e case 失败并记录独立 Transport Outcome；
- 一个有效真机失败不能由 Host/synthetic pass 豁免；
- 实验室外部依赖不可用时该次 run 标记为 invalid 并重跑，而不是 pass 或 product fail；长期无法执行的必需场景必须显式修改合同。

Fault-injection case 只有在 fault 分类、Policy Verdict 是否存在、Runtime Disposition、Completion/Transport outcome、bounded evidence、health 和 exactly-once 行为全部符合预期时才通过。

## 5. Closure Evidence Matrix

### 5.1 Layer A：共享 VPP 语义

Adapter-neutral Host/VPP graph vectors 穷举共享语义。至少覆盖：

- IPv4/IPv6 parsing、valid L3 with unavailable L4、malformed/truncated envelope；
- direction-independent Canonical Flow Key、正反向同 owner、Primary Handoff、一次 Corrective Handoff 与 repeated mismatch；
- Fragment Steering 的乱序、重复、冲突/overlap、timeout、capacity、reassembly-to-final-owner transition；
- complete UID/unknown subject、NetworkContext、Device Packet Direction 与 Flow Direction 的职责分离；
- Network Gate、L4 precedence/winner、policy revision 和 no-match continuation；
- bounded capacity、teardown、generation、stale/duplicate completion 和 exactly-once terminal accounting；
- Policy Verdict、Runtime Disposition、Completion、Transport 与 Infrastructure Fault 的独立归因。

共享语义只穷举一次，不把全部组合机械复制到两条物理 Profile 路径。

### 5.2 Layer B：Adapter conformance

Root 与 VPN 分别证明各自的平台边界，同时消费 Layer A 的同一语义合同。

| 维度 | Root/NFQUEUE | VPN/TUN/HEV |
| --- | --- | --- |
| ingress | dual-stack INPUT/OUTPUT、queue generation、packet ID、original/captured length、完整 L3 | TUN outbound/transport-return、descriptor generation、完整 L3 |
| materialization | netlink receive into VPP-owned ingress storage，无 Adapter-to-VPP full-packet copy | direct read/readv into VPP buffer/chain，无 Adapter-to-VPP full-packet copy |
| initial placement | 多独占 NFQUEUE lane；queue 只决定 Initial Execution Placement | 单一首版 Platform I/O Lane |
| completion | terminal intent 回 Origin Adapter Lane；原 generation/packet ID 唯一 verdict | HEV ownership transfer 或 terminal TUN write |
| fault | queue/listener/identity/verdict failure、fail-open 与 bounded evidence | fd/HEV/TUN/completion/transport failure 与 bounded evidence |
| teardown | quiesce → bounded drain → close verdict channel → remove hook/queue | quiesce → bounded drain → close transport/TUN → release VPN slot |

Adapter-specific performance 限制可以不同，但两者不得产生不同 parser、owner、policy verdict 或 revision 语义。

### 5.3 Layer C：受控 Android 真机 parity

新增 device evidence 默认在现有可完全控制的目标设备上执行，并优先使用真实安装应用、真实 Root/VPN runtime 与真实 Wi-Fi/Mobile path。保留并复用有价值的现有 unit/integration fixtures；只有无法稳定从外部注入的内部边界才使用 Host/synthetic harness。

Root 与 VPN 按顺序运行同一 complete Linux UID 和同一 Authoring Policy revision。固定最低覆盖为：

| 维度 | 最低真机覆盖 |
| --- | --- |
| family/protocol/action | IPv4 TCP、IPv4 UDP、IPv6 TCP、IPv6 UDP；每种组合至少一个 allow 和一个 L4 drop |
| Root direction | INPUT 与 OUTPUT；每个 family 至少有代表性双向证据，不要求与全部 protocol/action 做笛卡尔积 |
| VPN direction | outbound 与 transport-return；每个 family 至少有代表性双向证据，不要求与全部 protocol/action 做笛卡尔积 |
| Network Gate | Wi-Fi 与 Mobile 各至少一个 allow 和一个 drop |
| identity | 真实 complete Linux UID 命中；另有明确 `uidKnown=false`/Unknown Application fallback，packet 不等待、不缓存、不重放 |
| policy attribution | 相同语义 case 的 stage、winner、verdict、reason、revision 在 Root/VPN 间一致 |
| policy lifecycle | apply 后生效；删除/替换最小测试 policy 后真实流量恢复或按新 revision 执行 |
| observability | Debug Control Activity 能查询当前/最近 runtime health 与联合 outcome 所需的 bounded evidence |

受控测试应用可以产生确定性流量；普通真实安装应用补一个小型 integration smoke，证明 package/UID/product control 没有只对测试流量源成立。该要求不强制重写已有测试夹具。

## 6. Fault 与 outcome 最低矩阵

以下行为来自现有 accepted ADR/domain contract；implementation ticket 负责给出可重复注入方式和证据位置。

| 场景 | Policy Verdict | Runtime/平台结果 | 必须证据 |
| --- | --- | --- | --- |
| missing Ingress Completion Identity | 不存在 | 不创建 PacketLease、不进入 VPP、不伪造 Completion；kernel 可能独立 bypass | `INGRESS_IDENTITY_MISSING` bounded fault + health reason |
| invalid L3 envelope | 不存在 | VPP validation runtime drop | parser/validation reason、terminal completion、无 rule attribution |
| valid L3、L4 fact unavailable/unsupported | 由其余可求值 stage 决定；不因 fact 缺失自动 DROP | 依赖缺失 fact 的 predicate no-match，其余 stage 继续 | parser status、available facts、最终联合 outcome |
| ordinary pre-policy capacity fault | 不存在 | Root 在可完成时 ACCEPT；VPN bypass policy 进入正常 transport | capacity fault、health、无 policy attribution |
| Fail-Open Reserve exhaustion | 不存在 | 允许明确 loss | bounded loss counter + degraded health，不动态增长或等待 |
| fragment conflict/timeout/capacity failure | 不存在 | retained obligations runtime drop | fragment reason、全部 obligation terminal、无 fail-open |
| repeated owner mismatch | 不存在 | 一次 Corrective Handoff 后仍错则 runtime drop | owner fault、health、无 redirect loop |
| stale/duplicate completion request | 保持原事实 | 不执行第二次 physical completion | generation/duplicate counter、exactly-once ledger |
| Completion `FAILED_DEFINITE` | 不改写 | 不 retry、不重新进入 VPP | bounded outcome/reason counter、first/last diagnostics、health |
| Completion `OUTCOME_UNKNOWN` | 不改写 | 不伪报成功或确定失败，不 retry | 与 definite failure 分离的 bounded evidence + health |
| VPN post-handoff transport failure | allow 保持 | Transport Outcome `FAILED`/`UNSUPPORTED` | completion 与 transport 分离、真实流量失败 |
| teardown deadline | 已有 verdict 照常完成；普通未求值 packet 按 profile contract 收口 | 不跨 generation replay；fragment/repeated-owner fault 不改成 fail-open | drain/terminal/residue ledger |

Nominal 真机 case 中出现任何未预期 fault、`FAILED_DEFINITE`、`OUTCOME_UNKNOWN` 或 Transport failure 都判失败。

## 7. Lifecycle 与恢复证据

Functional Closure 不因首次发版策略尚未最终确定而延后当前可执行的真实证据。至少验证：

- Root、VPN 各自 start、clean stop、再次 start 和重复 lifecycle；
- 关闭/重建 Debug Control Activity 不停止 active runtime；
- user pause/resume 保留所选 Profile 和当前最小 policy 意图；
- `Root → VPN → Root` clean switch，任一时刻只有一个 VPP runtime；
- app process death、runtime crash、control disconnect 的 bounded cleanup 与 fresh manual recovery；
- 基础 Doze 与 reboot 行为；
- 每轮后的 process、socket、NFQUEUE hook/queue、TUN fd、VPN slot、VPP shared-memory/runtime directory 和 profile-owned residue 检查。

已有真机脚本能够复用的直接复用；缺少但容易自动化的 device gate 在对应 implementation ticket 中补齐。测试发现当前实现缺陷时立即处理或显式阻塞受影响 gate，不能以“首次发版再考虑”为理由跳过。

首次发版阶段仍需重新决定自动 restart/backoff、长期后台/soak 承诺、OEM/OS matrix、release signing/upgrade/rollback 和持久化 Activity Store；这些未来决策不取消当前 lifecycle correctness evidence。

## 8. 现有证据的使用方式

以下资产是迁移输入或 harness 基线，不自动满足 production VPP closure：

- `tests/host/{flow_steering,fragment_steering,packet_capture_adapter,nfqueue_*adapter,vpp_graph_injection}_tests.cpp`：当前 C++ 语义和测试向量基线；不得机械翻译为生产模块形状。
- `tests/android/runtime-contract-test.sh` 与 `tests/integration/android-runtime-lifecycle.sh`：实验 RuntimeService lifecycle/health 基线；正式实现应复用可证明的 contract 与 device-driving pattern。
- `tests/device/ip/run.sh` 及 active DX smoke：真实设备、受控 topology 和 L3/L4 流量生成基线；不得把当前 raw-daemon pass 误报为 VPP-native Adapter pass。
- `experiments/vpp-nfq-poc/`：架构 POC 与测量证据；overlay、固定 queue/worker/pool 数量和 copied-prefix path 均非生产合同。

implementation ticket 必须在评论中记录：source revision、artifact identity、设备/网络环境、命令、原始结果路径、有效/无效判定、失败归因和残留检查。摘要不能替代可复查原始证据。

## 9. Plane 执行顺序

- SAKAMOTO-65：本文固定的 Functional Closure Contract 与 Evidence Matrix。
- SAKAMOTO-66：在本文不变量下收敛共享 Flow/Lease/Adapter 领域语义，并明确旧 SAKAMOTO-47..49 代码的迁移/证据地位。
- SAKAMOTO-67：交付统一 VPP Runtime 与 Debug Control Activity/Control Shell；其内部控制接口由实现证据收敛。
- SAKAMOTO-68：Root/NFQUEUE 最小 Gate+L4 e2e slice。
- SAKAMOTO-69：VPN/TUN parity slice。
- SAKAMOTO-70：profile switch 与 failure recovery。
- SAKAMOTO-71：按本文矩阵执行双 Profile Closure Gate。

SAKAMOTO-65 完成后，SAKAMOTO-66 与 SAKAMOTO-67 的设计/实现工作均解除该合同 blocker；二者不互相阻塞。SAKAMOTO-68 必须等待 65、66、67 全部完成。单线推进时，第一张正式编码票是 SAKAMOTO-67；SAKAMOTO-66 的共享语义审查必须在进入 SAKAMOTO-68 前完成。

SAKAMOTO-48/49 保留为 C++/NFQUEUE/fragment baseline evidence；Android Root/VPN 产品验收归属 SAKAMOTO-66、68、69 和最终 closure gate，不再从旧 POC ticket 直接启动生产实现。

## 10. SAKAMOTO-66 semantic audit / C++ migration status

审查日期：2026-08-08。结论：**共享语义合同 PASS；生产实现迁移仍是后续准入条件。**

### 10.1 Authority and migration rule

本审查沿用本文第 1 节的权威顺序：已接受的 `docs/decisions/` 与 `CONTEXT.md` 定义不变量；本文定义 Functional Closure 验收边界；Plane implementation ticket 记录实现和原始证据；旧 C++/NFQUEUE 代码与测试只作为可复用的语义向量和迁移输入。不得把旧类、旧 enum、POC copied-prefix 或 POC counters 机械提升为 VPP-native production contract。

| Target contract | Current C++ evidence | S66 disposition |
| --- | --- | --- |
| VPP parses one complete L3 packet and builds shared `PacketFacts` | `src/core/flow/PacketCaptureAdapter.*` parses in the Adapter and defaults to a 512-byte prefix | Migration input only; production parser/validation stays in the shared VPP graph and closure does not assume 512 bytes. |
| One per-worker FlowOwner; buffer index/metadata handoff only | `src/core/flow/FlowSteering.*` and `FlowGraphInjection.*` use C++ descriptors and `PacketLease` values | Host/graph semantic baseline; not proof of live VPP buffer ownership, Primary Handoff, Completion Frame, or no-copy operation. |
| Bounded Fragment Steering with final-owner transition and runtime-drop failures | `src/core/flow/FragmentSteering.*`, `NfqueueFlowAdapter.cpp`, and `NfqueueFragmentLeaseBook.*` use copied vectors and an independent lease table; failure paths currently use `FailOpen` | Reuse vectors and capacity tests only; production reassembly is the named mutation exception, and malformed/conflict/timeout/capacity failures drop all retained obligations without fail-open. |
| Buffer-resident PacketLease, origin-lane completion, tri-state completion outcome | `NfqueuePacketLeaseAdapter.*` and `NfqueuePassThroughRuntime.*` use pending/history registries, two-state policy outcomes, and a per-verdict temporary buffer | Evidence only; production keeps inline VPP metadata, one physical attempt, `SUCCEEDED`/`FAILED_DEFINITE`/`OUTCOME_UNKNOWN`, native return after completion, and bounded health evidence. |
| Shared Root/VPN conformance | `tests/host/{flow_steering,fragment_steering,packet_capture_adapter,nfqueue_*adapter,vpp_graph_injection}_tests.cpp` | Migration vectors; Root and VPN product acceptance remains in S66/S68/S69 and the final closure gate. |

The old `SAKAMOTO-47..49` acceptance wording therefore cannot be used to infer production readiness. Existing accepted architectural decisions do not need reversal; the required change is to migrate implementation shape and record the evidence below.

### 10.2 Compact shared conformance vectors

The following vectors run once at the adapter-neutral Host/VPP graph layer. Root and VPN wrappers then prove only their platform ingress, completion, transport, fault, and teardown boundaries against the same expected result. Vector F is retained as a future Adapter conformance gate for SAKAMOTO-68/69/71; SAKAMOTO-66 records its owner and evidence handoff but does not execute or claim those platform/e2e runs.

| ID | Vector | Required result |
| --- | --- | --- |
| A — Flow identity | IPv4/IPv6 TCP/UDP forward and reverse packets across Root and VPN, with changed UID, NetworkContext, queue, interface, and Runtime Profile | Protocol is part of the direction-independent five-tuple; reverse packets select the same owner. UID/context/queue/profile do not select owner. Device `INPUT`/`OUTPUT` is independent from Flow `ORIG`/`REPLY`; first observed packet sets `ORIG` and `flowOriginDir`, reverse is `REPLY`, and a midstream first observation is not rewritten. Unknown UID uses the explicit fallback without wait, cache, replay, or retroactive verdict. |
| B — Distribution and guard | Owner-local packet; remote initial placement; target queue congestion; first and second owner mismatches | Local path has no worker enqueue. Remote path performs exactly one Primary Handoff of buffer index/metadata. Congestion never redirects to another worker. One mismatch permits one Corrective Handoff; a repeated mismatch is a runtime `DROP`/owner fault with no redirect loop or fail-open. Worker Layout, selector, seed, and capacities are runtime-fixed. |
| C — Parser, facts, and ingress identity | Complete valid L3; invalid version/header/declared length; valid L3 with unavailable or unsupported L4; oversize envelope; missing NFQUEUE completion identity | Shared VPP parser accepts valid complete L3 and preserves parser status/facts. Invalid L3 is a runtime drop with no Policy Verdict. Missing L4/ports no-match only predicates requiring them while other stages continue. Envelope overflow has no partial parse and follows the contract's bounded evidence. Missing queue generation/packet ID is `INGRESS_IDENTITY_MISSING`: no PacketLease, VPP entry, Policy Verdict, or fabricated completion. |
| D — Fragment transition | Non-initial fragment; IPv4/IPv6 out-of-order fragments; identical duplicate; overlap/conflict; malformed/reserved/length error; timeout; datagram/fragment capacity; successful reassembly | Non-initial fragments never fabricate ports. All fragments co-locate under a temporary fragment key; the initial fragment's final owner is retained. Reassembly-to-final-owner transition does not consume Corrective Handoff. Duplicate is idempotent. Conflict, malformed, timeout, and capacity failure runtime-drop every retained obligation, produce no Policy Verdict, and never fail-open. |
| E — Lease, completion, and teardown | Policy allow/drop; pre-policy capacity and reserve exhaustion; stale/duplicate completion; definite send rejection; ambiguous receiver; Root/VPN teardown; post-HEV transport failure | Each decided packet has one physical Adapter Completion attempt and then native buffer return. Completion is `SUCCEEDED`, `FAILED_DEFINITE`, or `OUTCOME_UNKNOWN`; no retry, graph re-entry, or policy re-evaluation. Stale/duplicate requests do not issue a second attempt. Teardown is quiesce → bounded drain → channel close: existing verdicts complete, ordinary unevaluated Root leases accept when identity remains completable, VPN records completion/transport failure separately, and fragment/owner-fault drops do not become fail-open. HEV post-handoff failure leaves Policy allow and Adapter completion intact while recording Transport failure. |
| F — Adapter parity and evidence (future S68/S69/S71 conformance gate) | Run A–E once through VPP graph injection; replay controlled vectors through Root NFQUEUE/netns and VPN TUN/HEV | Both Adapters supply equivalent normalized facts and consume the same owner/policy/revision semantics. Queue/fd/packet handles remain platform-private. Evidence proves direct materialization into VPP-owned storage, index/ownership handoff without packet-byte copies, origin-lane completion, bounded counters/health, and no generation or residue leak. |

### 10.3 Plane disposition

- `SAKAMOTO-47` is already **Done** (2026-07-28). Retain it as the C++ FlowSteering/graph-gate baseline, but clarify in the work item that Done means evidence/harness completion, not production VPP closure.
- `SAKAMOTO-48` and `SAKAMOTO-49` are **Cancelled** in Plane with superseded/baseline-only scope recorded. Their production ownership has moved to SAKAMOTO-68/69 and the SAKAMOTO-71 closure gate; the retained C++ assets remain migration evidence only.
- SAKAMOTO-66 review is complete only when the Plane comment records this disposition, the reviewed source revision, and ownership/locations for the semantic vectors and evidence. This semantic-only review does not require or claim execution of VPP-native materialization or Root/VPN parity evidence: SAKAMOTO-68 produces and records Root/NFQUEUE evidence, SAKAMOTO-69 produces and records VPN/TUN evidence, and SAKAMOTO-71 records the joint closure result. SAKAMOTO-66 must record that handoff rather than treating those later artifacts as complete. A green C++ test run alone does not satisfy Functional Closure.
