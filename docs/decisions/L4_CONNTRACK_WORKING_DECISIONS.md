# L4 Conntrack：工作决策与原则

更新时间：2026-06-20
状态：纲领性工作结论（历史设计回执；能力已落地，SNORT-10 A++ runtime 重构仍应对照本文）
对应历史主规格：`archive/openspec/specs/l4-conntrack-core/spec.md`
对应历史 change：`archive/openspec/changes/archive/2026-03-30-add-iprules-conntrack-core/`

---

## 0. 目标与范围

本文件用于固化 `sucre-snort` 下一阶段在 **L4 stateful / conntrack** 方向上的上位原则，避免后续讨论再次退回“要不要做、做到哪一层、是否直接依赖系统 conntrack”这些基础问题。

本文回答的是：
- 在当前项目里，什么才算“真正的 L4”；
- 我们要移植/重写的到底是什么；
- 这件事和现有 `IPRULES v1`、`DomainPolicy`、observability 的边界在哪里；
- 哪些东西明确不做，避免范围失控。

本文不回答：
- 具体 Plane work item / implementation slice 的任务拆分、接口字面量、类图与测试清单；
- NAT / ALG / DPI / HTTP 识别这类已超出当前产品边界的话题；
- “如何一步到位做成通用防火墙”的泛化设计。

---

## 1. 为什么要做：当前 L3/L4 还不是真正的 stateful L4

当前仓库已经有：
- per-UID 的 IPv4 L3/L4 规则引擎；
- `proto/src/dst/sport/dport/iface/direction` 这类**单包字段**匹配；
- exact cache + classifier snapshot + per-rule stats。

这些能力已经足够构成一个可用的 L3/L4 packet policy，但它仍然是 **stateless packet filtering**，而不是严格意义上的 **stateful L4 firewall semantics**。

在本项目里，“真正的 L4”至少意味着：
- 系统对一条流/连接有稳定的 **flow identity**，而不是只看单个包；
- 系统能区分 **orig / reply direction**；
- 系统能判断最基本的 **new / established / invalid**；
- TCP 不只是“有个端口”，而是有最基本的握手/关闭/异常状态语义；
- UDP / ICMP / other 虽不需要 TCP 那么重，但也要有最小可解释的 pseudo-state；
- 状态有超时、回收、失效边界，而不是永久缓存。

结论：下一阶段如果要把 `IPRULES` 从“包规则”补全到“专业意义上的 L4”，核心缺口不是再加几个 match 字段，而是补上 **userspace conntrack core**。

---

## 2. 单一方向：这是“语义移植/重实现”，不是重新设计

本阶段的核心共识：

1. **语义母本选 OVS userspace conntrack**
   - 不是因为要照抄 OVS 工程结构；
   - 而是因为它已经把 userspace conntrack 的核心问题拆得很清楚：`ConnKey`、双向 key、协议 tracker、更新结果、超时与清理生命周期。

2. **实现方式选 C++ 原生重实现**
   - 不把 OVS 的 C 代码整块搬进仓库；
   - 不把 OVS 的 `dp_packet` / OVS threading / NAT / dump/export 基础设施一起拖进来；
   - 要把 conntrack core 语义移植到更贴合当前 `sucre-snort` 结构的 C++ 实现上。

3. **重实现不等于重新发明语义**
   - 可以改表达方式、数据结构细节、对象生命周期管理；
   - 不能借“重写”为名改掉已经成熟的 conntrack 语义边界；
   - 尤其不能把“简化实现”变成“退化成另一个 ad-hoc packet cache”。

这里的关键词不是 “copy code”，而是 **preserve semantics, adapt implementation**。

---

## 3. 协议范围：第一阶段只做 `TCP / UDP / ICMP / other`

第一阶段明确范围：
- `TCP`
- `UDP`
- `ICMP`
- `other`

第一阶段明确不做：
- `SCTP`
- NAT
- ALG / helper / expectation
- fragment reassembly
- 依赖系统 `conntrack` / `NFQA_CT`
- L7 / DPI / HTTP body 之类更高层识别

说明：
- `UDP` 在这里不追求“像 TCP 一样复杂”，而是接受 pseudo-state + timeout 的模型；
- `ICMP` 也只需要满足本项目真正需要的 request/reply 级别语义；
- `other` 不是“什么都不做”，而是要有受控的最小状态模型，避免所有非 TCP/UDP/ICMP 流量退化成完全裸包判断。

---

## 4. 什么算“本项目里的 L4 完整度”

在 `sucre-snort` 里，L4 完整度的最低标准不是“支持端口匹配”，而是以下几项同时成立：

### 4.1 流标识与双向归一化

- 必须有稳定的 `ConnKey` / reverse key 模型；
- 必须能把同一条连接/流的正反向包收敛到同一个 entry；
- reply direction 不能靠调用方猜，必须由 conntrack 自己判定。

### 4.2 基础状态语义

- 至少有 `new / established / invalid` 这一级别的可解释状态；
- `new` 不能等价于“第一次看到这个五元组”这么粗糙；
- `invalid` 必须是真正的异常/不合法/不满足协议状态条件，而不是简单 miss。

### 4.3 TCP 要有真正的 transport 语义

- 至少覆盖握手建立、双向确认、关闭/超时等基础状态迁移；
- 至少保留 OVS 这一档的“不是只看 SYN 位”的严肃度；
- 不要求第一阶段就把所有导出状态完全对外暴露，但内核语义必须成立。

### 4.4 UDP / ICMP / other 要有轻量但真实的状态

- UDP：至少区分单向首次、多次、双向回复，并有对应 timeout；
- ICMP：至少处理 request/reply 这一级别的基本往返关系；
- other：至少保留“first / multiple / bidir”这类轻量状态模型，避免完全失去跨包语义。

### 4.5 生命周期完整

- 状态必须有 timeout；
- 必须有清理/回收；
- 必须有可控的容量边界；
- 必须考虑 entry 过期后的下一次重建语义，而不是只关心命中时快不快。

---

## 5. 与现有 IPRULES v1 的边界

这件事是 **在现有 IPRULES v1 之上补齐 stateful 语义**，不是推翻 v1。

已落地的 v1 结论继续成立：
- exact cache / classifier snapshot 是当前 stateless fast path 的主结构；
- `IPRULES=0` 时仍必须 zero-cost disable；
- 当前 correctness 不依赖系统 conntrack；
- 本文写作时控制面尚拒绝 `ct` 条件；当前仓库已通过独立 conntrack change 落地 `ct.state/ct.direction`，因此这条只应视为 v1 历史背景，而非现状约束。

L4 conntrack 和 v1 的关系应理解为：
- **conntrack core** 提供新的判决输入维度；
- **rule engine** 再决定是否、何时把这些维度暴露成 `ct.*` 匹配语义；
- **observability** 再决定如何把 flow state / direction / invalid 等信息输出出来。

也就是说，conntrack 不是为了替换现有 classifier，而是为了给它补一个以前不存在的状态层。

### 5.1 与 pipeline / decision cache 的关系：`ct.*` 会改变 stateful stage 输入

当前 IPRULES v1 的 hot-path 结构包含：
- exact decision cache（TLS）
- 编译后的 classifier snapshot（按 `uid` 分 view）

一旦规则允许匹配 `ct.*`，同一五元组在不同时间可能对应不同的 `ct.state`（例如 `new → established`）。因此 stateful stage 的 policy decision cache 若存在，key 必须包含当前包实际取得的 `ct.state/ct.direction`；cache 只能跳过重复 matcher scan，不能决定是否进入 CT，也不能改变 stage order。

否则会出现“缓存命中但 `ct.state` 已变化”的错误判决。

SNORT-10 后的 CT runtime 口径不再采用旧的 “preview miss -> verdict accept 后 commit new entry” 作为通用模型。新的边界是：
- Interface policy 与 Basic IPRULES 先用 `PacketFacts` 评估；若产生 enforce block，该 packet 可在进入 CT 前 short-circuit。
- 若 subject/app 已启用 CT / DPI / flow-level 高级能力，且前序 Basic stage 没有产生 block，则 packet 进入 CT，CT 按自身 L4 状态机 lookup / create / update，并产出 `CtFacts`。
- CT 更新与最终 verdict 解耦。后续 Stateful / DPI stage 若命中 block，只影响本 packet verdict，不回滚 CT entry，也不把 CT 当作 accepted-flow 账本。
- Basic allow 或 observe winner 产生最终 allow 时，后续 Stateful / DPI evaluator 仍按 short-circuit 不再扫描；但该 packet 仍可进入 CT 并更新统一 flow/session entry，保证后续 flow attachments、DPI state 与 flow-level observation 不断裂。
- Policy decision cache 必须被定义为 stage evaluator 的纯函数结果缓存；cache hit / miss 不得改变 fact acquisition 顺序。

SNORT-10 后的 policy decision cache 采用两级口径：
- L1 Base policy cache 缓存 Interface / Basic IPRULES stage result；它不含 CT / DPI facts。
- L2 Post-CT policy cache 只在 L1 result 为 `PassToAdvanced` 后启用；它使用完整 packet projection + `CtFacts` + `DpiFacts` key 缓存 Stateful / DPI stage scan result。
- L1 `FinalBlock` 不进入 CT；L1 `FinalAllow` / observe-final-allow 在需要 CT 时只更新 CT / flow attachments，不查 L2。
- L2 逻辑上独立于 CT core，不把 CT entry 变成永久 verdict 存储；CT entry 只提供 flow/session state 与 flow-level facts。
- L2 可以缓存 no-winner / default allow。DPI 未识别时 `DpiFacts` key 为 `unknown`；DPI 出现具体识别结果后 key 变化并自然 miss，再按完整 facts 重新扫描。
- L1/L2 第一版物理形态均为 per-worker TLS fixed-size direct-mapped exact cache。L2 不挂 CT entry，不做共享表，不把 policy scan result 写回 CT session；CT A++ hot entry / cold attachments 不承担 policy cache 写入、失效或并发竞争。
- L1/L2 hash 可以复用完整 base projection hash，并在 L2 增量 mix CT / DPI / epoch 字段；cache hit 必须比较完整 logical key 与 epoch，不能只比较 hash。
- cache hit 的结果必须与直接扫描 stage 得到的结果等价：entry 至少保存 result kind、winning `ruleId`、rule mode、declared action、stats handle / pointer 与 snapshot lifetime handle；cache hit 后仍按正常路径更新 rule counters 与 attribution。

---

## 6. 热路径与 Android 约束

这件事能不能成立，不取决于“语义上对不对”，还取决于它是否适合 Android 上当前这个 userspace NFQUEUE 模型。

后续任何 change 都必须遵守以下约束：

1. **不能把热路径从“快速 verdict”做成“重量级连接管理器”**
   - 允许增加 state lookup/update；
   - 但不接受无界扫描、复杂锁争用、频繁动态分配、跨模块重对象链路。

2. **必须有明确的 zero-cost/near-zero-cost disable 边界**
   - 当前 v1 的 `IPRULES=0` 语义不能被 stateful 扩展反向污染；
   - 若未来 conntrack 需要单独总开关，也要做到关闭后不在每包路径上残留不必要成本。

2.1 **Conntrack gating（subject/app 级）是必需的性能边界**
   - conntrack update 不应成为“无条件的全局每包成本”；
   - 普通用户 / 普通 app 不应为 CT 付费；
   - 但一旦某 subject/app 启用了 `ct.*` policy / observe rule、`dpi.*` policy / observe rule、完整 Flow Telemetry consumer 或未来 gateway consumer，该 subject/app 的 eligible packets 就进入 CT；
   - 不在同一 app 内按单条 CT 规则的 cheap precondition 决定“这个 packet 是否需要 CT”。这种过细 gate 会把 pipeline、cache、DPI state 与 flow attachments 搅复杂，得不偿失。

这里的 “ct consumer” 必须按高级能力 gate 理解：
- `ct.*` enforce / observe 规则都是 consumer；
- `dpi.*` enforce / observe 规则隐含 CT consumer，因为 DPI state / result 绑定在 CT flow/session entry 上；
- Flow Telemetry `level=flow` 是 observation consumer，但启用 CT 不等于启用 Flow Telemetry；
- `ct.state=any` 且 `ct.direction=any`、或根本未声明 `ct.*` 的 Basic rule，不构成 CT consumer。

2.2 **Gating 的“查询方式”需要合并：避免每包多次 UID→能力查询**
   - 目标：在热路径上避免出现“为了判断需不需要 Conntrack、DPI、Traffic Windows、Diagnostics，各模块分别做一次 `uid → compiled view/caps` 查询”的重复工作。
   - 后续默认方向是 `Hot-path capability summary`：慢路径把 subject/app 的 policy / observation capabilities 预编译进只读 snapshot；packet path 合成 `GlobalHotPathCaps | SubjectHotPathCaps` 后按 bit 决定 stage/fact acquisition。
   - per-UID `App + epoch` 缓存仍可作为某些实现切片的局部技巧，但它不是最终抽象；最终抽象应是一次 subject caps lookup 供所有高级模块复用。
   - 如果全局 caps 已证明没有任何 subject-scoped policy / expensive fact consumer，packet path 可以跳过 subject caps lookup。

3. **内存模型必须可控**
   - 连接表容量、timeout、清理策略都必须明确；
   - Android 设备上不能假定“像服务器一样内存够用、线程够多”。

3.1 **Timeout 取值：完全沿用 OVS 默认表**
   - 各协议（`TCP/UDP/ICMP/other`）在不同状态下的 timeout 数值（包含 TCP 各状态、UDP 单/双向、ICMP/other pseudo-state）**不在本项目重新拍脑袋定值**；
   - 第一阶段实现中，timeout 数值 **MUST 直接沿用 OVS userspace conntrack 的默认 timeout policy 表**（loose 语义）；
   - 目的：避免 “我们自创一套 timeout，结果语义不再是 OVS 等价” 的隐性分叉。

3.2 **容量上限：设一个足够大的硬上限 + 明确 overflow 行为**
   - conntrack table MUST 有硬上限（不能无界增长）。
   - Android 单机设备不是服务器 conntrack 场景；设计中心应按 active flows 万级以内理解，不能用百万级 flow 作为普通手机热路径优化前提。
   - Android 常态流量下预期不会触顶；因此上限应结合 `sizeof(entry)`、统一 CT attachments、真机观察与电量/内存预算确定。默认 hard cap 可以偏保守地服务万级 flow，并允许诊断/高级模式配置更高上限，但不得把 1M 级表项作为默认设计目标。
   - 但仍必须定义 overflow 行为（避免触顶时崩溃或进入不确定状态）：
     - 优先尝试回收已过期 entry（受限预算、不得扫描全表）。
     - 若仍无法创建新 entry：该包的 conntrack 输出 SHALL 退化为 `ct.state=invalid`（并记录计数），且不创建/不插入 entry。

4. **并发模型必须先于实现细节被钉住**
   - 哪些路径只读、哪些路径更新、是否分片/shard、如何 sweep；
   - 这些问题不是实现后再补的“优化项”，而是 correctness 与成本模型的一部分。

---

## 7. 并发模型：correctness 不依赖 NFQUEUE 拓扑

### 7.1 当前 NFQUEUE 线程模型的事实

当前 `sucre-snort` 的 packet worker 拓扑应命名为 `split-in-out`：
- queue 数量来自 `hardware_concurrency()`，最少 4，且强制偶数；
- 每个 IP family（IPv4 / IPv6）各占一段独立 queue range；
- 在每个 IP family 内，当前实现把 queue **硬拆成一半 `INPUT`、一半 `OUTPUT`**；
- `INPUT` 链的 iptables 规则使用 input queue range；
- `OUTPUT` 链的 iptables 规则使用 output queue range；
- kernel 在对应 `--queue-balance` range 内选择具体 queue；
- daemon 为每个 queue 启动一个 listener thread；
- OS scheduler 再决定 listener thread 实际跑在哪个 CPU；当前没有显式 CPU affinity；
- `direction` 当前通过 thread-local `_inputTLS` 从 queue/thread 分区传入判决路径。

这意味着：
- 当前实现下，同一条连接/流的正向与反向数据包**不能假设落在同一个 worker**；
- 同一个双向 flow 在 `INPUT` / `OUTPUT` 分区下可以被两个 listener thread 并发处理；
- 因此 future conntrack 的 correctness **绝不能依赖** “同流同线程”。

### 7.2 设计原则：NFQUEUE 拓扑只是运行模式，不是语义前提

后续至少保留两类运行拓扑：
- `split-in-out`：当前/default 行为，`INPUT` 与 `OUTPUT` 使用不同 queue ranges；
- `shared-flow-pool`：计划中的实验模式，同一 IP family 内 `INPUT` 与 `OUTPUT` 使用同一个 queue range，让 kernel 的 NFQUEUE connection stickiness 尽量把同一 flow 的双向包放到同一个 queue/listener thread。

两者都只能视为：
- perf / contention / cache locality 的运行时变量；
- debug / experiment / deployment profile 的切换项；

而不能视为：
- conntrack state correctness 的基础；
- 内部是否需要并发保护的前提判断。

结论：
- conntrack core 必须在 **split topology** 与 **shared topology** 下都正确工作；
- queue affinity 只能作为性能优化收益来源，不能作为唯一保险丝。
- 即使启用 `shared-flow-pool`，也只能降低同一 flow 跨线程并发概率，不能移除 conntrack 内部并发保护；
- `shared-flow-pool` 下 `direction` 不能再来自 `_inputTLS`，必须从每包 NFQUEUE header 的 hook 推导：`LOCAL_IN` 对应 input，`LOCAL_OUT` 对应 output。

### 7.3 线程安全目标形态

本项目的目标不是“绝对无锁”，而是：
- **lookup 无全局锁**
- **update 无全局锁**
- **create/delete 才触及有限范围的结构锁**
- **内存回收延迟进行，不阻塞热路径读者**

换句话说，目标是：
- correctness 依赖成熟的并发模型；
- 低竞争时，线程安全开销尽量接近零；
- 双向分裂到不同线程时，竞争仍然被控制在很小范围内。

### 7.4 推荐并发骨架

后续实现应优先采用接近 Linux conntrack / OVS conntrack 这一类的经典形态：

1. **表结构分 shard**
   - shard 数不绑定 NFQUEUE worker 数；
   - shard 用于控制锁域、回收域和 sweep 域；
   - 不允许整张 conntrack table 只有一个全局锁。

2. **read-mostly lookup**
   - 常态 lookup 不拿全局锁；
   - 命中路径尽量只做 hash/bucket 遍历与 key 比较；
   - 读者不得因为后台 sweep / delete 被长时间阻塞。

3. **entry 级短临界区更新**
   - entry 的 immutable 与 mutable 字段必须拆开看待；
   - 命中后真正需要变更的状态（如 expiration / reply-seen / protocol state）应限制在 entry 自身的小临界区内；
   - 不允许命中包在常态路径上持有表级大锁。

4. **create path 的 double-check insert**
   - miss 后才能进入创建路径；
   - 在 shard 级结构锁下再次 double-check，避免并发插入重复 entry；
   - create 是慢路径，允许比命中更新更重，但范围必须只局限在所属 shard。

5. **deferred reclamation**
   - delete / expire 不应立即 free 正在被读者可能持有的 entry；
   - 必须采用延迟回收（epoch/RCU/hazard-pointer 同类思想中的一种）；
   - 热路径只负责“让 entry 不再可见/可命中”，真正 free 由安全时点完成。

6. **后台 sweep**
   - expiration 常态上应支持 cheap update；
   - 过期清理由后台/分片 sweep 执行；
   - 不允许把“检查并清理大量过期连接”塞进每包热路径。

### 7.5 明确反对的方案

以下方案不应成为主实现方向：

- 用单个 `std::shared_mutex` 或同等级全局读写锁包住整张 ct 表；
- 把 queue stickiness 当成“已经天然串行”的前提，因此省略内部并发保护；
- 把 conntrack 写成“读多写少”的缓存模型；
- 把过期回收放进常态每包路径；
- 为了追求表面上的 lock-free，把实现复杂度推高到超出本项目可维护范围。

说明：
- conntrack 与普通 cache 的不同点在于：命中包通常也要更新状态，因此它不是典型的“读多写少”对象；
- 更准确的目标是 **read-mostly structure + tiny write-set**。

### 7.6 与 NFQUEUE 拓扑实验的关系

后续可以允许至少两种运行拓扑并存：
- `split-in-out`
- `shared-flow-pool`

但两者都应满足：
- 功能 correctness 一致；
- 控制面与规则语义一致；
- 只有性能画像、竞争分布、cache locality 不同。

其中 `shared-flow-pool` 的预期形态是：
- 对同一个 IP family，`INPUT` 与 `OUTPUT` iptables rules 使用相同的 `--queue-balance` queue range；
- kernel 负责在该 range 内做 queue 选择，并利用 NFQUEUE connection stickiness 尽量保持同一 connection 同 queue；
- daemon 仍然保持“一个 queue 一个 listener thread”的现有 worker 基本形态；
- 不再通过 queue/thread 分区判断包方向，而是从每包 NFQUEUE hook 推导方向。

当 per-packet direction 推导正确时，两种模式下的业务语义应保持一致：
- `remoteIp` 选择一致；
- traffic rx/tx counters 一致；
- IPRULES `dir` 匹配一致；
- Flow Telemetry `packetDir` / `flowOriginDir` 一致；
- Debug Stream packet direction 一致。

计划中的控制面形态：
- 未来通过 vNext device config 提供 string enum：`nfqueue.topology`；
- 初始值保持 `split-in-out`；
- 可选值先限定为 `split-in-out` 与 `shared-flow-pool`，避免 bool 配置限制后续模式扩展；
- 配置持久化到现有 settings 存储，daemon 下次启动读取后生效；
- 不要求、不设计热切换；前端/RuntimeService 负责 stop daemon 后重新 start daemon；
- 后续实现时可另行暴露 active mode 供诊断，但在接口真正落地前不把它写入对外契约。

因此，后续评估顺序应是：
1. 先把 conntrack core 做成对拓扑无关的线程安全实现；
2. 再实现 `nfqueue.topology=shared-flow-pool` 作为独立 perf / stability 变量做真机比较；
3. 最后才决定默认运行模式。

### 7.7 Sweep 调度（baseline）

本项目第一阶段的 baseline 策略：**不引入专门的 sweep 线程**，而是使用“预算化 + 节流触发”的方式完成过期回收与容量保护，避免把扫表成本塞进热路径。

**原则：**
- sweep 的单次工作量必须有明确预算上限（bucket/entry 数），避免长尾抖动；
- sweep 的触发必须节流（interval + try_lock），避免与热路径竞争；
- 优先在 create-path（慢路径）承担 sweep 成本，热路径只做极低频 best-effort。

**具体建议：**
1. **lazy expire on hit**
   - lookup 命中后先比较 `entry.expirationNs`；
   - 若已过期：当场视为 miss，不进入协议状态机；并把“删除/回收”交给 sweep/delete 慢路径（不得继续使用过期 entry 作判决依据）。

2. **预算化 sweep（per-shard cursor）**
   - 每个 shard 维护一个 `cursorBucketIndex`；
   - 每次 sweep 只扫描固定预算（例如 N 个 bucket 或最多 K 个 entry），并推进 cursor；
   - 目标是把“全表扫描”摊平成多次小步，避免 O(N) 抖动。

3. **触发方式：create-path 优先 + hot-path 低频 best-effort**
   - **create-path 触发（优先）**：当 miss 需要创建 entry、或接近/达到容量上限时，在 shard 结构锁下先执行一小段 sweepBudget，优先回收过期 entry。
   - **hot-path 触发（可选）**：在不影响判决的前提下，允许低频（例如每 shard 间隔 >= X ms）`try_lock` 成功才执行一小段 sweepBudget。失败则直接跳过，不得阻塞热路径。

说明：
- 若未来 perf/真机验证显示该 baseline 仍不足（例如过期堆积严重），再引入 dedicated sweep thread 作为后续优化 change；第一阶段不默认上线程。

### 7.8 QSBR/SMR 落点（A++ baseline）

conntrack 需要延迟回收（deferred reclamation）以避免并发下的 UAF。SNORT-10 A++ runtime 的 baseline 是 **`liburcu-qsbr`**：
- 不继续维护项目自研 epoch/QSBR 作为主方案；
- `liburcu-qsbr` 用于 read-side lifetime 与 deferred reclamation；
- CT hash table 仍是项目自研专用表，不直接切到通用 `cds_lfht`；
- QSBR 选择不改变 OVS 级 conntrack 语义，只改变 entry lifetime / reclaim 机制。

**核心约束：**
- unlink（删除可见性）与 free（释放内存）必须解耦；
- 热路径读者不应因 free 逻辑而阻塞或承担不可控成本；
- correctness 不依赖 “同流同线程”，因此 SMR 必须对多线程并发 update 成立。

**建议落点：**
1. **read-side boundary：优先放在 worker packet loop / packet batch**
   - listener / worker thread 初始化时注册到 `liburcu-qsbr`；
   - 阻塞等待 NFQUEUE 消息或长时间不处理 packet 时应处于 offline / quiescent；
   - 处理 packet 或 packet batch 时进入 online/read-side，CT lookup/update 在该边界内执行；
   - packet/batch 完成后报告 `rcu_quiescent_state()`，让 retire/free 能及时推进。
   - 不把 `rcu_read_lock()` / `rcu_read_unlock()` 写成 CT 内部每个小函数重复进入/退出的成本；边界应尽量外提到 worker loop。

2. **retire list + grace period free**
   - entry 被 expire/delete 后：
     - 先从 hash table/bucket unlink，使其对新 lookup 不可见；
     - 通过 `call_rcu` / 等价 QSBR callback 延迟释放或归还 pool；
   - unlink 在 shard writer lock 下完成；free / pool recycle 不得在读者仍可能持有 entry pointer 时发生。
   - 不允许在持有 shard lock 时同步等待 grace period，避免 writer 与 QSBR reader/worker 死锁或长尾阻塞。

3. **线程注册**
   - 所有可能进入 CT read-side 的 packet worker、测试 worker 和查询/维护线程都必须注册；
   - 线程退出前必须 unregister，并确保不再持有 CT entry pointer；
   - 长时间阻塞或执行无关 I/O 的线程必须 offline，避免阻塞 grace period。

说明：
- `liburcu-qsbr` 是为了降低自研 SMR 正确性风险，同时把 read-side 成本压到很低；引入它后，不应再保留另一套并行自研 epoch 作为默认路径。

### 7.9 CT A++ hash table 方向（A 方案内的极限化）

本节只讨论 **A 方案**：全局共享 authoritative CT table。它不尝试解决 C 方案 / owner handoff / per-flow single-owner 的问题。A 方案的剩余不可消除成本是同一 flow 被多个 worker 更新时的 cache-line bouncing；这只能由 owner/handoff 类架构继续降低。

A++ 的主线是：**自研专用 fixed-bucket intrusive CT table + 当前 specialized field-mix hash + `liburcu-qsbr`**。

默认不采用通用 hash map：
- 不用 `std::unordered_map`、Folly F14、Abseil flat_hash_map、uthash 作为 CT authoritative table；
- 不把 DPDK `rte_hash` 作为默认依赖；
- 不把 `liburcu-cds` 的 `cds_lfht` 作为主实现。

`cds_lfht` 的定位：
- `cds_lfht` 是 `liburcu-cds` 提供的通用 lock-free RCU hash table；
- 它可用于 benchmark / reference / sanity check；
- 但 CT table 的 key 固定、容量可预分配、entry intrusive、state hot/cold 可控，专用表更容易压低常数项和 cache footprint。

A++ 表结构约束：
1. **canonical key 一次构造**
   - packet 进入 CT 后构造方向无关 canonical key，同时得到本包相对 orig/reply 的方向；
   - entry 不再依赖 `key + revKey` 双存储 / 双比较作为热路径常态；
   - 命中候选后仍必须 full-key compare，hash/fingerprint 只做快速筛选。

2. **hash 只算一次并复用**
   - 默认继续使用当前 specialized field-mix hash 路线；
   - 不把 VPP 自加 session manager 的表驱动 32-bit CRC stacking 原样迁入；
   - `hash64` 应同时服务 shard index、bucket index、worker-local hot cache fingerprint / index；
   - 若未来引入 ARMv8 CRC32C intrinsic，只作为目标机 benchmark 后的候选，不改变 full-key compare 约束。

3. **shard/bucket bit slice 不重叠**
   - shard 数与 bucket 数必须是 power-of-two；
   - shard index 与 bucket index 必须使用不同 hash bit slice，例如 `bucket = low bits`、`shard = next bits` 或等价方案；
   - 不允许 `shard = h % shardCount` 与 `bucket = h & bucketMask` 共享同一批低位，避免每个 shard 实际只使用少量 bucket。

4. **read hit 无结构锁**
   - bucket head 使用 RCU-safe atomic pointer；
   - hit path 在 QSBR read-side 内遍历短链、比较 fingerprint/hash、full-key compare；
   - 命中后只更新 entry-local hot fields，不触碰全表 LRU、全局 list 或需要跨 entry 的结构。

5. **create/delete/expire 只锁 shard**
   - miss/create 在 shard writer lock 下 double-check 后插入；
   - unlink/delete/expire 在 shard lock 下从 bucket 链移除；
   - free / recycle 通过 QSBR grace period 延迟。

6. **per-shard pool / free-list**
   - create path 不应常态调用 `new/delete`；
   - entry 从 per-shard pool 或固定 chunk allocator 获取；
   - pool recycle 必须经过 QSBR grace period，避免 worker-local hot cache 或读者持有旧 pointer 时 UAF。

7. **worker-local hot cache**
   - 稳定 flow 命中先查 worker-local direct-mapped / small set-associative cache；
   - cache entry 至少保存 hash/fingerprint、generation 与 entry pointer / pool handle；
   - 命中后仍验证 generation/fingerprint 与 full canonical key，不能因 retire/reuse 产生 UAF 或误命中。

8. **稳定状态少写**
   - TCP established 后普通 ACK/data 包不应反复 CAS 已稳定状态；
   - expiration / last-seen 可做 coarse refresh，只有超过刷新阈值才写；
   - per-packet stats、Flow Telemetry counters、DPI result 等应放在 attachment / cold path，不污染 CT core hot cache line。

9. **hot/cold entry split**
   - CT core hot entry 只放 lookup/update 必要字段：key/hash、next、expiration、协议状态、方向/状态摘要；
   - Flow Telemetry、DPI、debug/export、长统计等作为 consumer-specific attachments 或 cold extension；
   - 启用 CT 不等于所有 attachments 都存在或都更新。

10. **GC 从常态 hot path 拿走**
   - 常态 packet hit path 不做 sweep；
   - create path 可以在容量压力下做 bounded per-shard reclaim；
   - 后台/维护路径负责常态 expire/sweep；若使用 hot-path best-effort sweep，也必须是低频 `try_lock` 且失败直接跳过。

### 7.10 参考实现与替代方案（用于 sanity check）

本节用于回答两类问题：
- 我们的并发模型是不是社区的经典最佳实践；
- 有没有“更好/更优秀”的现成开源库可以直接拿来用。

结论（先写在前面）：
- “shard + read-mostly lookup + entry 级短锁 + deferred reclamation + 后台 sweep”属于 conntrack 这类状态表的经典做法；
- 能“本质更好”的路线通常不是换锁，而是换架构（例如强制 per-flow single-owner），但这需要更强的 flow steering 前提；
- 现成能直接复用的 userspace conntrack library 并不多，OVS 是最接近本项目需求且成熟的参考母本；其余常见库多为“查询内核 conntrack”的 netlink wrapper，不提供 userspace state machine。

**社区/经典参考：**
- Linux conntrack 的经典总结（lockless/RCU lookups + hashed locks + hash table）：  
  - Florian Westphal, Netdev 2.1: https://netdevconf.info/2.1/slides/apr8/florian_westphal_conntrack.pdf
- OVS userspace conntrack（线程安全 + per-conn lock 的结构）：  
  - `conntrack_execute()` 可多线程并发调用（头文件注释），并使用 `conn->lock` / `ct_lock` 等粒度控制并发：  
    - https://sources.debian.org/src/openvswitch/3.1.0-2%2Bdeb12u1/lib/conntrack.h  
    - https://sources.debian.org/src/openvswitch/3.1.0-2%2Bdeb12u1/lib/conntrack-private.h
- OVS 对 conntrack 多线程可扩展性的改进方向（减少全局锁域、把成本集中在 create path 等）：  
  - Patch series: https://mail.openvswitch.org/pipermail/ovs-dev/2022-March/392767.html  
  - Benchmark/背景文章（OVS 3.0 conntrack perf）：https://developers.redhat.com/articles/2022/11/17/benchmarking-improved-conntrack-performance-ovs-300

**与本项目 NFQUEUE 的关系：**
- `NFQUEUE --queue-balance` 的 connection-level queue stickiness（同一 connection 的包会落到同一 queue）：  
  - iptables-extensions: https://man7.org/linux/man-pages/man8/iptables-extensions.8.html

**替代方案（不一定更好，且有明确代价）：**
1. **依赖系统 conntrack（内核）**
   - 方式：使用 `NFQA_CT` 元数据或通过 netlink 查询内核表（如 `libnetfilter_conntrack` / ti-mo/conntrack 这类 wrapper）。
   - 优点：语义成熟、由内核维护。
   - 代价：Android 设备侧内核能力与权限差异大；接口与可用性不可控；引入额外依赖与排障成本；并且“可用”不等于“成本可控/可测”。
   - 结论：可作为可选加速/诊断手段，但不应作为本项目 correctness 的前提。

2. **per-flow single-owner（尽量消除 entry lock）**
   - 方式：通过稳定的 flow steering 把同一 flow 永久映射到同一 worker，conntrack table 做 per-worker 私有。
   - 优点：命中更新无需跨线程锁竞争，吞吐上限更高。
   - 代价：强依赖 steering 前提（拓扑、hash、一致性、以及双向汇聚）；一旦前提破裂会出现 correctness 问题或需要复杂的迁移/同步机制。
   - 结论：适合作为 perf mode 的上限探索，但仍需 thread-safe baseline；并且在 NFQUEUE/userspace 模型下不应优先押注。

3. **通用并发 map 直接复用**
   - 方式：引入大型第三方并发容器（C++ concurrent hash map / hazard pointer / epoch GC）。
   - 优点：少写底层并发代码。
   - 代价：依赖体积、可移植性、Android 构建复杂度、调试复杂度显著上升；且这些库不提供 TCP/ICMP/other 的 conntrack 语义与状态机。
   - 结论：不作为 CT authoritative table 的默认方向；CT 表采用专用 intrusive fixed-bucket 结构。

**可复用的 SMR/并发构件（只解决“安全回收/并发容器”，不提供 conntrack 语义）：**
- `liburcu-qsbr`（Userspace RCU QSBR flavor）：A++ baseline 的 read-side lifetime / deferred reclamation 支撑。
  - https://liburcu.org/
- `liburcu-cds` / `cds_lfht`：通用 lock-free RCU hash table，可作为 benchmark / reference baseline；不作为默认 CT 表。
- Concurrency Kit（`ck_epoch` / `ck_ht` 等）：可作为对照或 fallback 研究对象；默认不引入。
  - https://github.com/concurrencykit/ck
- `libcds`（Concurrent Data Structures）：功能强但引入成本与复杂度更高；默认不引入。
  - https://github.com/khizmax/libcds

说明：
- `liburcu-qsbr` 解决的是 lifetime / grace period，不替代 CT 表结构或协议状态机；
- 但它们不能替代 conntrack 的协议状态机与语义实现；
- 通用 hash table / map 是否更快必须用目标 Android 设备 benchmark 证明，不能凭库名决定。

**结论（回答“是否已是最优解 / liburcu 何时引入”）：**
- 在“不依赖内核 conntrack/ebpf”、“在当前 NFQUEUE 多线程现实下 correctness 成立”、“热路径开销尽量低”的约束下，本文推荐的并发骨架属于**工程意义上的最优折中（Pareto 最优）**：若不改变前提（例如强 flow steering/per-flow single-owner，或把 state 下沉到内核），很难出现“本质更低开销”的新方案。
- `liburcu-qsbr` 已选为 A++ baseline；引入动机不是“有库就用库”，而是把自研 SMR 正确性风险从 CT hot-path 重构中移出，同时保持 QSBR read-side 低成本。
- `cds_lfht` 不是 `liburcu-qsbr` 的同义词。前者是通用 hash table，后者是 RCU flavor / lifetime 机制。本项目只默认采用后者。

---

## 8. OVS 语义里哪些要保留，哪些不要跟着带进来

### 8.1 应保留的核心

优先保留以下抽象：
- `ConnKey` / forward-reverse key
- `ConnEntry`
- `ct_l4_proto` 这类按协议分派的 tracker interface
- `new_conn / valid_new / conn_update` 这类生命周期分工
- 协议独立 timeout policy
- reply-direction fast path
- TCP / ICMP / other(含 UDP pseudo-state) 的核心状态机思路

补充两条实现约束（与 OVS 语义一致）：
- `ct.direction` 采用 **首包创建方向**（orig/reply）的口径；不做“端点排序/字典序归一化”式的重新定义。
- conntrack key **包含 `uid`**（Android per-app firewall 语义），但 **不包含接口信息**（`ifindex/ifaceKind`），避免因接口切换把同一连接拆成多条 entry。

补充两条“输入解析”约束（后续实现必须对齐 OVS 的需求强度）：
- **TCP 不能只解析端口**：为了保持 OVS 级的 TCP conntrack 语义，conntrack core 必须获得 TCP header 的关键原始字段（至少包含 `flags/seq/ack/window/dataOffset`，并按需解析 `wscale` 选项与 payload length）。这些字段应在解析端口的同一阶段被提取出来并传给 conntrack update（不是让上层猜）。
- **IPv4 fragment 本阶段不做重组**：若遇到分片包（MF 或 frag offset 非 0），conntrack 视角应按“无法建立可靠 L4 语义”处理（例如 `ct.state=invalid` 且 `ct.direction=any`），并保持行为可预测、不会崩溃。

补充一条“模式选择”约束：
- TCP 追踪采用 **OVS 同级别的宽松（loose）语义**：不额外引入“必须从 SYN 开始/严格握手”的 strict 模式；保持 OVS 对 `valid_new`/midstream 的接受边界与状态机口径一致。

### 8.2 明确不带入第一阶段的部分

第一阶段不应把这些一起搬进来：
- NAT
- expectation / ALG
- OVS `dp_packet` 抽象本身
- OVS zone / mark / label / export/dump 全套管理面
- fragment reassembly
- 任何要求系统已有 conntrack 的前提

原则很简单：**只移植 conntrack core，不引入无关子系统。**

---

## 9. 规则语义的预期方向：先有 conntrack core，再开放 `ct` 匹配

当前阶段先记录一个上位顺序，避免后面倒装：

1. 先把 conntrack core 作为内部能力做扎实；
2. 再决定哪些 `ct` 语义值得暴露给规则系统；
3. 再决定这些语义如何进入控制面与 observability。

从专业 L3/L4 firewall 视角，未来真正有价值的 `ct` 语义大概率至少包括：
- `ct.state`
- `ct.direction`
- `ct.proto`（更多是规范化后的状态视角，而不是替代原始 `proto` 字段）

本阶段仅锁死最小枚举取值（与 OVS 对齐），避免后续实现阶段再次反复讨论“值域到底是什么”：
- `ct.state`：`any | new | established | invalid`
- `ct.direction`：`any | orig | reply`

但仍然不在纲领文件里锁死控制命令的具体格式/示例（这些属于后续具体 change 的工作）。

### 9.1 `ct.state/ct.direction` 的“token 口径”与 OVS 对齐（基础语义钉死）

本项目采用最小枚举以降低接口复杂度，但**语义口径必须等价于 OVS 的 conntrack 输出**（只是把 OVS 的 bitset 压缩成更少的可用值）：

- `ct.direction=reply` 对齐 OVS 的 `ct_state=+rpl`（reply direction）
- `ct.direction=orig` 对齐 OVS 的 `ct_state=-rpl`（非 reply 即 orig；前提是该包已被 conntrack 追踪）
- `ct.state=new` 对齐 OVS 的 `ct_state=+new`（并隐含 `+trk`）
- `ct.state=established` 对齐 OVS 的 `ct_state=+est` 或 `ct_state=+rel`（本项目把 OVS 的 `rel` 折叠进 `established`；并隐含 `+trk`）
- `ct.state=invalid` 对齐 OVS 的 `ct_state=+inv`（以及其它导致 OVS 判为 invalid 的情形，例如解析失败/不满足协议状态要求等；并隐含 `+trk`）

注意：
- `ct.state/ct.direction` 是 conntrack 视角的 flow 元数据；与现有 `dir=in|out`（netfilter 链方向）是不同维度。
- 本阶段不引入 OVS 的其它 flags（如 `trk/rel/snat/dnat`）到控制面；需要时另起 change。

---

## 10. 与 DomainPolicy / 更高层识别的边界

这个方向的定位必须说清楚，否则后续很容易继续失焦：

- `DomainPolicy` 继续是域名/语义层；
- `IPRULES + conntrack` 继续是 L3/L4 packet/flow enforcement 层；
- 两者未来需要融合和仲裁，但不是一方吞并另一方。

同样要明确：
- 这里讨论的 conntrack，不等于未来要做 DPI；
- 它解决的是“DNS 不够时，L3/L4 还能更强地表达和判决什么”；
- 它不是为了把项目带成一个通用 L7 检测引擎。

SNI / QUIC Initial / authority 之类 future backup signal 可以作为后续产品思考保留，但不属于本文件的实现范围。

---

## 11. 当前阶段的明确非目标

以下内容在本阶段一律视为非目标，避免讨论发散：

- 直接依赖 Linux / Android 系统 conntrack
- 直接把 OVS C 代码原样嵌入 `sucre-snort`
- 围绕 NAT/ALG 把项目做成通用网关防火墙
- 顺势引入 L7 / DPI / HTTP 内容识别
- 为了“先跑起来”而牺牲掉成熟 conntrack 语义
- 把当前 `IPRULES v1` 已收敛的 exact cache / classifier / stats 重新推翻重做
- 在 IPRULES 控制面引入 device-wide/global scope 的“全局规则”（该需求另起 change 讨论；本阶段仅聚焦 per-UID + `ct.*`）

---

## 12. 实现后仍需持续对照的检查点

后续在 code review、缺陷修复与重构阶段，至少要持续回答以下问题：

1. 这个实现是在**保持 OVS 级 conntrack 语义**，还是在偷偷变成新的 ad-hoc cache？
2. 它是 **C++ 适配式重实现**，还是把 OVS 工程杂质一起搬进来了？
3. 它是否真的补上了 `new/established/invalid + direction + timeout`，还是只新增了若干字段？
4. 它关闭时是否真的不污染当前热路径？
5. 它启用时的 CPU / 内存 / sweep 成本是否可解释、可测量、可回归？

如果这些问题里有任何一条答不稳，就说明当前实现或后续重构还没有真正收敛。

---

## 13. 当前结论（一句话版本）

`sucre-snort` 已按本文方向把 IP 规则补全到最小可用的 stateful L4：以 **OVS userspace conntrack 语义**为母本，落地了一个 **C++ 原生、Android 约束下可控的 conntrack core 重实现**；范围收敛在 `TCP / UDP / ICMP / other`，并明确未把 NAT / ALG / system conntrack / DPI 一起带进来。
