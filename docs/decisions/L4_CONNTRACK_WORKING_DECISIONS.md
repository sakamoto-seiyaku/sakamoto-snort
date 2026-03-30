# L4 Conntrack：工作决策与原则

更新时间：2026-03-28  
状态：纲领性工作结论（当前用于约束后续 change；不是实现 spec，也不是任务清单）
对应 OpenSpec change（草案/待评审）：`openspec/changes/add-iprules-conntrack-core/`

---

## 0. 目标与范围

本文件用于固化 `sucre-snort` 下一阶段在 **L4 stateful / conntrack** 方向上的上位原则，避免后续讨论再次退回“要不要做、做到哪一层、是否直接依赖系统 conntrack”这些基础问题。

本文回答的是：
- 在当前项目里，什么才算“真正的 L4”；
- 我们要移植/重写的到底是什么；
- 这件事和现有 `IPRULES v1`、`DomainPolicy`、observability 的边界在哪里；
- 哪些东西明确不做，避免范围失控。

本文不回答：
- 具体 change 的任务拆分、接口字面量、类图与测试清单；
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
- 当前控制面拒绝 `ct` 条件，是合理的，因为后端语义尚未存在。

下一阶段 L4 conntrack 和 v1 的关系应理解为：
- **conntrack core** 提供新的判决输入维度；
- **rule engine** 再决定是否、何时把这些维度暴露成 `ct.*` 匹配语义；
- **observability** 再决定如何把 flow state / direction / invalid 等信息输出出来。

也就是说，conntrack 不是为了替换现有 classifier，而是为了给它补一个以前不存在的状态层。

### 5.1 与 decision cache 的关系：`ct.*` 会改变“同五元组”的判决输入

当前 IPRULES v1 的 hot-path 结构包含：
- exact decision cache（TLS）
- 编译后的 classifier snapshot（按 `uid` 分 view）

一旦规则允许匹配 `ct.*`，同一五元组在不同时间可能对应不同的 `ct.state`（例如 `new → established`）。因此：
- **必须先做 conntrack preview/update**，得到当前包的 `ct.state/ct.direction`
- 再把 `ct.state/ct.direction` **纳入 hot-path key**（例如扩展 `PacketKeyV4`）
- 再进入 decision cache / classifier snapshot

否则会出现“缓存命中但 `ct.state` 已变化”的错误判决。

补充约束：
- 对 miss/new 的首包，preview 阶段不得在 verdict 未知时提前创建 entry；
- 只有最终 verdict=ACCEPT 时才允许 commit 新 entry；
- 否则会出现“`ct.state=new` 的 DROP 污染后续重传、导致连接绕过 block”的错误语义。

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

2.1 **Conntrack gating（按 UID）是必需的性能妥协**
   - conntrack update 不应成为“无条件的全局每包成本”；
   - gating SHOULD 至少做到按 `uid` 粒度：仅当该 `uid` 的 active rules 使用 `ct.*` 时才对该 `uid` 的包执行 conntrack update；
   - 该妥协带来的语义后果是可接受且必须明确记录：当某 `uid` 之前没有 `ct` consumer（未 tracking），后续才新增 `ct.*` 规则时，**既有连接在一段时间内会被视为 `new/invalid` 等非理想状态**；本项目接受这是 Android 上为降低常态成本付出的代价。

这里的 “使用 `ct.*` / ct consumer” 必须严格定义为：
- 仅当某 `uid` 的 active rules 中 **至少存在一条规则** 具有非平凡 `ct` 约束时，才视为该 `uid` 需要 conntrack。
- “非平凡” 的判定规则：
  - `ct.state != any` **或** `ct.direction != any` → 视为 consumer
  - `ct.state=any` 且 `ct.direction=any`（或根本未声明 `ct.*`）→ 视为 **无 consumer**（不应触发 conntrack update）

2.2 **Gating 的“查询方式”需要优化：避免每包多一次 UID→规则集能力查询**
   - 目标：在热路径上避免出现“为了判断需不需要 conntrack，又做一次额外的 `uid → compiled view` 查找”的重复工作。
   - 这是工程/性能折中的问题，不是语义问题。我们需要明确可选方案与各自代价（实现时以其中一个为主，其它留作备选/对照）：

| 方案 | 热路径每包额外成本 | 规则更新时成本 | 实现复杂度 | 风险点 | 备注 |
|---|---:|---:|---:|---|---|
| A. 直接查 snapshot：`uidUsesCt(uid)` | 1 次 map/hash 查找（每包） | 无 | 低 | 常态开销偏大，且容易和 evaluate() 重复查找 | 仅作为最小可行 baseline |
| B. per-UID 缓存在 `App`（带 epoch） | 2 个原子读（epoch+caps），常态无查找 | epoch 变化时做一次查找并刷新 | 中 | 需要在 `App` 引入 iprules capabilities；要处理并发刷新 | **推荐默认**：规则变更频率低，适合 amortize |
| C. 引擎 API 合并：单次查找同时给出 `UidView* + caps` 并复用 | 0 次额外查找（复用同一次 view 定位） | 无 | 中/高 | 需要改动引擎对外 API / TLS cache 边界 | 适合在 baseline 仍不够好时再做 |

推荐结论（用于后续 change 实现默认路线）：
- 优先采用 **B（App+epoch 缓存）** 作为 gating 的主实现策略：在规则 epoch 稳定时，gating 近似“零额外开销”；epoch 变化很少发生时刷新一次即可。

3. **内存模型必须可控**
   - 连接表容量、timeout、清理策略都必须明确；
   - Android 设备上不能假定“像服务器一样内存够用、线程够多”。

3.1 **Timeout 取值：完全沿用 OVS 默认表**
   - 各协议（`TCP/UDP/ICMP/other`）在不同状态下的 timeout 数值（包含 TCP 各状态、UDP 单/双向、ICMP/other pseudo-state）**不在本项目重新拍脑袋定值**；
   - 第一阶段实现中，timeout 数值 **MUST 直接沿用 OVS userspace conntrack 的默认 timeout policy 表**（loose 语义）；
   - 目的：避免 “我们自创一套 timeout，结果语义不再是 OVS 等价” 的隐性分叉。

3.2 **容量上限：设一个足够大的硬上限 + 明确 overflow 行为**
   - conntrack table MUST 有硬上限（不能无界增长）。
   - Android 常态流量下预期不会触顶；因此上限可设置得相对大（第一版可先取一个较大的常量，并在实现后结合 `sizeof(entry)` 与真机观察再微调）。
   - 但仍必须定义 overflow 行为（避免触顶时崩溃或进入不确定状态）：
     - 优先尝试回收已过期 entry（受限预算、不得扫描全表）。
     - 若仍无法创建新 entry：该包的 conntrack 输出 SHALL 退化为 `ct.state=invalid`（并记录计数），且不创建/不插入 entry。

4. **并发模型必须先于实现细节被钉住**
   - 哪些路径只读、哪些路径更新、是否分片/shard、如何 sweep；
   - 这些问题不是实现后再补的“优化项”，而是 correctness 与成本模型的一部分。

---

## 7. 并发模型：correctness 不依赖 NFQUEUE 拓扑

### 7.1 当前 NFQUEUE 线程模型的事实

当前 `sucre-snort` 的 packet worker 拓扑是：
- queue 数量来自 `hardware_concurrency()`，最少 4，且强制偶数；
- 每个 IP family（IPv4 / IPv6）各占一段独立 queue range；
- 当前实现把 queue **硬拆成一半 `INPUT`、一半 `OUTPUT`**；
- 每个 queue 绑定一个独立 listener thread；
- `direction` 当前通过 thread-local `_inputTLS` 传入判决路径。

这意味着：
- 当前实现下，同一条连接/流的正向与反向数据包**不能假设落在同一个 worker**；
- 因此 future conntrack 的 correctness **绝不能依赖** “同流同线程”。

### 7.2 设计原则：NFQUEUE 拓扑只是运行模式，不是语义前提

后续无论保留当前 `in/out split`，还是改成 shared queue pool，都只能视为：
- perf / contention / cache locality 的运行时变量；
- debug / experiment / deployment profile 的切换项；

而不能视为：
- conntrack state correctness 的基础；
- 内部是否需要并发保护的前提判断。

结论：
- conntrack core 必须在 **split topology** 与 **shared topology** 下都正确工作；
- queue affinity 只能作为性能优化收益来源，不能作为唯一保险丝。

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
- `split in/out queues`
- `shared queue pool`

但两者都应满足：
- 功能 correctness 一致；
- 控制面与规则语义一致；
- 只有性能画像、竞争分布、cache locality 不同。

因此，后续评估顺序应是：
1. 先把 conntrack core 做成对拓扑无关的线程安全实现；
2. 再把 NFQUEUE 拓扑作为独立 perf 变量做真机比较；
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

### 7.8 QSBR/SMR 落点（baseline）

conntrack 需要延迟回收（deferred reclamation）以避免并发下的 UAF。第一阶段 baseline 采用 **最小化自研 epoch/QSBR**（不引入第三方依赖），并把 “quiescent” 的落点收敛到 conntrack update 的天然边界。

**核心约束：**
- unlink（删除可见性）与 free（释放内存）必须解耦；
- 热路径读者不应因 free 逻辑而阻塞或承担不可控成本；
- correctness 不依赖 “同流同线程”，因此 SMR 必须对多线程并发 update 成立。

**建议落点：**
1. **read-side boundary：以 conntrack.update 调用为单位**
   - 在进入 `conntrack.update(...)` 时进入 read-side（记录 thread-local / per-thread slot 的 active epoch）；
   - 在 update 返回时立刻标记 quiescent（退出 read-side）。
   - 这样可以避免在包处理链路的多个层次插入 SMR 标记点。

2. **retire list + grace period free**
   - entry 被 expire/delete 后：
     - 先从 hash table/bucket unlink，使其对新 lookup 不可见；
     - 将其加入 shard 的 `retireList`（记录 retireEpoch），不得立即 free；
   - sweep/慢路径在合适时机推进 epoch，并在满足 grace period 后批量 free retireList 中的 entry。

3. **线程注册**
   - 参与 conntrack.update 的线程在首次调用时注册一个 epoch slot；
   - 测试环境下允许线程动态创建/退出，但必须保证退出前处于 quiescent，避免阻塞回收。

说明：
- 如果未来需要更强的工具/语义支持（或自研 SMR 维护风险过高），再评估引入 `liburcu`；第一阶段 baseline 以最小依赖为目标。

### 7.9 参考实现与替代方案（用于 sanity check）

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

3. **通用并发 map/RCU 库直接复用**
   - 方式：引入大型第三方并发容器（C++ concurrent hash map / hazard pointer / epoch GC）。
   - 优点：少写底层并发代码。
   - 代价：依赖体积、可移植性、Android 构建复杂度、调试复杂度显著上升；且这些库不提供 TCP/ICMP/other 的 conntrack 语义与状态机。
   - 结论：除非证明我们维护不起最小化自研并发骨架，否则不作为首选。

**可复用的 SMR/并发构件（只解决“安全回收/并发容器”，不提供 conntrack 语义）：**
- `liburcu`（Userspace RCU）：提供多种 RCU 变体（含 QSBR），以及延迟回收机制；适合作为“lookup lockless + deferred free”的底层支撑，但引入新依赖与 Android 构建/部署成本。  
  - https://liburcu.org/
- Concurrency Kit（`ck_epoch` / `ck_ht` 等）：提供 epoch-based reclamation 与并发数据结构，适合作为最小化 SMR 支撑；同样需要评估依赖引入成本与可维护性。  
  - https://github.com/concurrencykit/ck
- `libcds`（Concurrent Data Structures）：C++ 并发数据结构库，包含 hazard pointer / user-space RCU 等多种回收策略与 map 实现；功能强但引入成本与复杂度更高。  
  - https://github.com/khizmax/libcds

说明：
- 这些库能减少我们在 “deferred reclamation / RCU/epoch” 层的自研代码量；
- 但它们不能替代 conntrack 的协议状态机与语义实现；
- 是否引入应以“工程风险 vs 依赖成本”评估为准，而不是默认“有库就用库”。

**结论（回答“是否已是最优解 / liburcu 何时引入”）：**
- 在“不依赖内核 conntrack/ebpf”、“在当前 NFQUEUE 多线程现实下 correctness 成立”、“热路径开销尽量低”的约束下，本文推荐的并发骨架属于**工程意义上的最优折中（Pareto 最优）**：若不改变前提（例如强 flow steering/per-flow single-owner，或把 state 下沉到内核），很难出现“本质更低开销”的新方案。
- `liburcu` **不是只在需要更高性能时才引入**；更准确的引入动机包括：降低自研 SMR 的正确性/维护风险，或需要更完整的 userspace RCU 语义与工具支持。  
  但它会带来依赖与 Android 构建/部署成本，因此默认仍应优先选择“最小化自研 QSBR/epoch”或轻量 vendor（如 `ck_epoch`），在性能剖析或维护风险证明必要时再引入 `liburcu`。

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

## 12. 后续进入具体 change 前，需要持续对照的检查点

后续一旦从纲领进入具体 change，至少要持续回答以下问题：

1. 这个实现是在**保持 OVS 级 conntrack 语义**，还是在偷偷变成新的 ad-hoc cache？
2. 它是 **C++ 适配式重实现**，还是把 OVS 工程杂质一起搬进来了？
3. 它是否真的补上了 `new/established/invalid + direction + timeout`，还是只新增了若干字段？
4. 它关闭时是否真的不污染当前热路径？
5. 它启用时的 CPU / 内存 / sweep 成本是否可解释、可测量、可回归？

如果这些问题里有任何一条答不稳，就说明方案还没有准备好进入实现。

---

## 13. 当前结论（一句话版本）

`sucre-snort` 下一阶段若要把 IP 规则补全到“真正的 L4”，正确方向不是继续堆单包字段，而是以 **OVS userspace conntrack 语义**为母本，做一个 **C++ 原生、Android 约束下可控的 conntrack core 重实现**；范围先收敛在 `TCP / UDP / ICMP / other`，并明确不把 NAT / ALG / system conntrack / DPI 一起带进来。
