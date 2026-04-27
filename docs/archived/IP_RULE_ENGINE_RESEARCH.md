# TASK PROMPT — IPv4 L3/L4 规则引擎联网调研（sucre-snort）

> 本文件是“给另一个 LLM 直接读取并执行”的任务说明。  
> 规则：不要写散文；按要求输出结构化结论；不要修改仓库代码（可在本文件 `RESULTS` 区追加结论）。

<!-- TASK_PROMPT_START -->

## 0) 任务背景

你是后端/数据平面架构调研助手。仓库：`/home/js/Git/sucre/sucre/sucre-snort`。

我们在 Snort + iptables + NFQUEUE dataplane 上新增能力：**按 App(UID) 的 IPv4 L3/L4 精细规则原语**（IPv4 精确/CIDR + dstPort 精确/ANY + 协议 + 接口/方向/上下文维度），并保持 NFQUEUE 热路径性能与并发约束。

你需要联网搜索“高质量 C/C++ 开源实现/论文/工程实践”，并给出对我们约束下可落地的推荐路线与索引设计草案。

## 1) 硬约束（必须满足）

- **不修改仓库代码**（只读调研）。允许：
  - 阅读本仓库文件；
  - 联网检索与阅读文档；
  - 如环境允许：下载/clone 参考项目到 `/tmp` 阅读（若下载受限，使用网页直接读源码文件即可）。
- **NFQUEUE 热路径**：不新增锁、不做重 IO；查询尽量 O(1)/近似常数；数据面只读不可变快照（RCU/atomic shared_ptr 风格）。
- **P0/P1 共识**（当作需求输入）：
  - P0 仅做 **黑名单**（block），不做 allow 语义。
  - 新规则语义先覆盖 **IPv4**；IPv6 新规则后置（IPv6 默认放行/不提示）。
  - 不做 **全局** safety-mode；可观测性复用现有 `PKTSTREAM` + 轻量 stats（避免新增通路）。

## 2) 本仓库事实入口（先快速读一遍）

- 现状决策/事实语义：`docs/archived/P0P1_BACKEND_WORKING_DECISIONS.md`
- 既有 change 参考：`openspec/changes/add-app-ip-blacklist/`
- 热路径入口：`src/PacketListener.cpp`、`src/PacketManager.hpp`
- PKTSTREAM 风险点：`src/Streamable.cpp`、`src/SocketIO.cpp`

### 你要先输出（<= 10 行）

用 10 行以内复述：现有热路径/控制面/持久化/PKTSTREAM 的关键约束 + 我们将新增的匹配维度。

## 3) 联网调研（重点：经典而高质量的实现）

你要找的不是“怎么写 iptables/nftables 规则”，而是 **数据结构/算法/工程实现**（适合嵌入式/高性能 dataplane），并且能映射到：

- 维度：`uid` + `(dir, iface, proto, ipExact/ipCidr, dstPortExact/ANY)`（可补充 local/remote 语义对齐方式）
- 更新：控制面编译快照；数据面 lock-free 读取
- 可解释：命中稳定 ruleId/reasonId；可做 per-rule hit/lastHit

建议组合搜索（可自行扩展）：

- packet classification tuple space search C++ library
- firewall rule matching hypersplit
- DPDK ACL rte_acl
- VPP classify table
- pf rule matching implementation / ipfw rule matching
- LC-trie / poptrie / DIR-24-8 LPM implementation C
- immutable snapshot / RCU rule table
- ClassBench firewall benchmark

至少覆盖 3 条“不同风格路线”：

1) **ACL/多维分类库**（例如 DPDK `rte_acl`、VPP classify）
2) **LPM/IP 前缀匹配库**（例如 LC-trie、poptrie、DIR-24-8）
3) **通用防火墙/内核实现思路**（OpenBSD pf、FreeBSD ipfw、Linux nftables set/map/interval 等）
4)（加分）学术：Tuple Space Search / HyperSplit / HiCuts / EGT-PC 等的工程落地前提
5) 如果有更好的方案 绝对不限于以上这 3 个维度

## 4) 源码快读（可选但强烈建议）

挑你觉得值得参考的项目/库（优先：DPDK ACL、VPP classify、pf/ipfw、一个 LPM 实现）：
- 不限制数量,但是需要 高质量

- 若可下载：clone 到 `/tmp/...`；否则直接在线读源码文件。
- 只需要提炼结构，不要贴大段代码。回答：
  - 规则表示（fields、mask、range、prefix）
  - 构建/编译阶段（排序/分桶/decision tree/bitset）
  - 查询阶段复杂度与内存布局（cache-friendly？SIMD？）
  - 更新策略（全量重建/增量/多版本/RCU）
  - 命中优先级与稳定 tie-break 如何保证

## 5) 你必须输出的“可执行结论”（严格按此结构）

### A) 候选路线对比（表格）

列：路线名｜核心思想｜查询复杂度/常数因子｜构建成本｜更新模型｜是否天然支持 CIDR｜是否容易加 UID 维度｜是否容易做 ruleId/reasonId 稳定命中｜工程风险

### B) 给 sucre-snort 的推荐方案（P0/P1 可落地）

- 推荐 1 条主路线 + 1 条备选路线（并明确为什么不选其它路线）。
- 给出 **具体索引设计草案**（到数据结构级别，不写代码）：
  - 示例形式：`uid -> (dir, iface, proto) -> {dstPortIndex} -> {ipExactHash + ipCidrLpm}`（可提出更优方案）
  - 命中优先级（确定性）：exact vs CIDR、长前缀优先、端口精确优先、tie-break（priority 字段/插入序/ruleId 小优先等）
  - 统计字段：per-rule hitCount/lastHit 如何热路径无锁（原子/分片/采样）与代价
  - log-only / safety-mode（would-drop）如何不改变 verdict 仍输出 reason（对 PKTSTREAM 的影响与控制建议）

### C) 验证点与基准测试建议

- micro-bench：每包查询 ns、cache miss、规则数 1k/10k 吞吐；更新频率与 rebuild 时间；PKTSTREAM 开关影响
- 正确性：CIDR 覆盖、端口 ANY/精确、proto ANY/精确、UID 不存在默认行为、IPv4/IPv6 分流策略

### D) 参考资料清单（必须带链接）

每条：标题｜来源（论文/项目/博客/文档）｜1 句关键结论｜与我们关联点

<!-- TASK_PROMPT_END -->

---

# RESULTS（在此处追加，不要改动上面的 TASK PROMPT）

## 2026-03-03 — IPv4 L3/L4 规则引擎联网调研（NFQUEUE/RCU 可落地）

- 本仓库约束摘要（<=10 行）：
  - NFQUEUE 热路径在 `PacketListener::callback -> PacketManager::make`，要求不新增锁、避免重 IO。
  - 现状 `settings.blockEnabled()` 为总 gating；关闭时直接 `NF_ACCEPT`，无法天然做全局 dry-run。
  - 当前判决核心是 `BLOCKIPLEAKS`（域名映射后）+ `blockIface`，其它默认放行。
  - `PacketManager::make` 在 `mutexListeners` shared lock 下执行；临界区必须保持短且无阻塞。
  - `PKTSTREAM` 通过 `Streamable::stream -> SocketIO::print` 同步写 socket，慢消费者会反压热路径。
  - 可观测性方向已定：复用 `PKTSTREAM + 轻量 stats`，不新增独立观测通路。
  - P0/P1 先做 IPv4 规则语义；IPv6 新规则后置（默认放行/不提示）。
  - 新增维度目标：`uid + (dir, iface, proto, ipExact/ipCidr, dstPortExact/ANY)`，且命中需稳定 `ruleId/reasonId`。

- A) 路线对比表格：

| 路线名 | 核心思想 | 查询复杂度/常数因子 | 构建成本 | 更新模型 | 是否天然支持 CIDR | 是否容易加 UID 维度 | 是否容易做 ruleId/reasonId 稳定命中 | 工程风险 |
|---|---|---|---|---|---|---|---|---|
| DPDK `rte_acl`（多维 ACL） | 将 bitmask/mask/range 字段编译为多 bit-tries，查询可走 SIMD 分类函数 | 近似 `O(trie steps)`，常数低（批量/向量化友好） | 中-高（规则 compile 成本明显） | 控制面 compile 新 context，数据面只读 classify；典型双缓冲发布 | 是 | 中（可把 UID 作为 32-bit 字段，但会扩大维度） | 高（`priority + userdata` 可稳定返回） | 中（需引入较重模型并适配现有判决链） |
| VPP Classify（mask+hash 分桶） | 按 mask 组织 classify table，键按 skip/match 做哈希和桶匹配 | 平均近似 `O(1)`，冲突时退化为桶内比较 | 中 | 表结构重建/替换，多表协同 | 是（prefix 可编码为 mask） | 中（可扩展字段） | 中（可挂 metadata，但需自定义稳定规则） | 中-高（体系复杂，运维/调试门槛较高） |
| **分层自研：`uid -> context -> port -> (ipExactHash + ipCidrLpm)`** | 先按业务强选择性维度分桶，再做 exact 哈希与 LPM（DIR-24-8/LC-trie） | exact 近似 `O(1)`；CIDR 近似常数（DIR-24-8 通常 1~2 次访存） | 中（编译逻辑可控） | COW 构建不可变 snapshot，atomic 发布 | 是 | **高（UID 置于顶层天然适配）** | **高（在编译期固化 tie-break，命中直接返回 ruleId/reasonId）** | **低-中（与当前架构最契合）** |
| nftables set/map/interval 思路（内核式） | 表达式链 + set/map/interval；规则集事务化替换 | set exact 常数好；interval 依后端可能 `O(logN)` | 若直接用内核低；若移植到用户态则高 | 事务提交，支持原子替换 | 是 | 低-中（UID 语义需额外桥接） | 中（需额外映射层） | 中-高（与现有 NFQUEUE 用户态引擎语义错位） |
| 学术树/元组族（HiCuts/HyperSplit/TSS） | 决策树切分或 tuple-space 分组减少匹配集合 | 通常 `O(tree depth)`/`O(tuple probes)`，大表可快 | 高（建树/重平衡重） | 常见全量重编译或复杂增量 | 是 | 中 | 中（需自建优先级稳定层） | 高（P0/P1 过重） |

- B) 推荐方案（主/备选 + 索引草案 + tie-break + stats + log-only）：
  - **主路线（推荐）**：分层自研索引（`uid/context` 强分桶 + `dstPort` 二级索引 + `ipExactHash + IPv4 LPM`）。
  - **备选路线**：DPDK `rte_acl`（当后续维度显著增加、规则规模上升到 5w+ 且需 SIMD 分类吞吐时切换）。
  - **不选其它路线原因**：
    - VPP classify：能力强但体系复杂、和当前代码形态耦合成本高。
    - nftables/pf/ipfw：更偏内核路径与规则语言，不直接匹配当前 NFQUEUE 用户态判决形态。
    - HiCuts/HyperSplit/TSS：研究价值高，但构建/更新复杂度不适合 P0/P1 快速落地。
  - **具体索引设计草案（数据结构级别）**：

```text
RuleSnapshot (immutable, atomic-published)
  byUid: flat_hash_map<uid, UidView>

UidView
  byCtx: flat_hash_map<CtxKey, PortView>
  CtxKey = (dir, ifaceClass, protoBucket)         // ifaceClass: WIFI/DATA/VPN/UNMANAGED/ANY
                                                   // protoBucket: TCP/UDP/OTHER/ANY

PortView
  exactPort: flat_hash_map<uint16_t, IpView>
  anyPort: IpView

IpView
  exactIp: flat_hash_map<uint32_t, SmallVec<RuleRef>>   // IPv4 host exact
  cidrLpm: DIR24_8_or_LCTrie<RuleRef>                   // IPv4 prefix

RuleRef
  { ruleId, reasonId, priority, prefixLen, portSpecific, ipSpecific, enforce, log, runtimeSlot }
```

  - **命中优先级（确定性）**：
    1. `uid` 精确桶（无桶则默认放行，保留既有系统判决）。
    2. context 顺序：`iface exact > iface ANY`，`proto exact > proto ANY`。
    3. port 顺序：`dstPort exact > dstPort ANY`。
    4. IP 顺序：`ip exact > CIDR`；CIDR 内 `longest prefix wins`。
    5. 最终 tie-break：`priority`（高优先）> `ruleId`（小者优先，确保稳定）。
  - **更新模型（控制面编译 + 数据面只读）**：
    - 控制面在新对象上编译 snapshot（按 uid 局部重建），完成后 `atomic store(shared_ptr<const Snapshot>)` 一次发布。
    - 数据面只 `atomic load` 当前 snapshot 指针，不加锁、不改结构；只会看到“旧或新”完整版本。
  - **per-rule 统计（热路径无锁）**：
    - `RuleRuntime[ruleId]` 放在 snapshot 外，字段至少：`hitPackets`、`hitBytes`、`lastHitTs`、`wouldDropHits`。
    - 计数器使用原子（`memory_order_relaxed`）；高热点规则用分片计数（按 NFQUEUE 线程/哈希分片）降争用。
    - `lastHitTs` 可用原子 max 或低频采样更新，避免每包重写大缓存线。
  - **log-only / safety-mode（would-drop）**：
    - 命中且 `enforce=0, log=1`：保持 `NF_ACCEPT`，输出 `wouldRuleId` + `wouldDrop=1`（并保持 `reasonId` 解释实际 verdict）。
    - 命中且 `enforce=1`：按规则 `DROP`（可选 `log=1` 输出命中事件）。
    - 对 PKTSTREAM 的控制建议：仅在“命中新规则”时附加最小字段（`reasonId/ruleId/wouldRuleId/wouldDrop`），并支持采样或速率阈值，避免慢 socket 放大临界区阻塞。

- C) 验证点与 micro-bench：
  - **micro-bench（匹配器纯函数）**：
    - 数据集：规则数 `1k/10k`（可加 `50k` 压测），`exact:cidr` 比例分别测 `100:0`、`70:30`、`30:70`。
    - 指标：`ns/lookup`（p50/p95/p99）、`cycles`、`cache-misses`、`branch-misses`（`perf stat`）。
    - 维度覆盖：UID 桶数量（1/100/1k）、端口 exact/ANY、proto exact/ANY、iface exact/ANY。
  - **dataplane 端到端基准**：
    - 对比“改动前基线 vs 新引擎”，在 PKTSTREAM `off/on` 两种模式下测吞吐（pps）与 CPU。
    - 观测新增规则启用后 NFQUEUE 回调耗时增量；目标是维持“查询近似常数 + 无锁读取”特性。
  - **更新性能**：
    - 测 `100/1k/10k` 规则批量更新的 compile 时间、snapshot publish 时间、并发读期间抖动。
    - 验证频繁更新场景下仍无部分可见状态（仅旧/新版本二选一）。
  - **正确性矩阵**：
    - CIDR：长前缀优先（`/32` 覆盖 `/24`）。
    - 端口：`dstPort exact` 优先于 `ANY`。
    - 协议：`proto exact` 优先于 `ANY`。
    - UID 不存在：默认不命中新规则（沿用既有默认行为）。
    - IPv4/IPv6：新规则仅作用 IPv4；IPv6 保持当前默认放行/不提示策略。
    - safety-mode：`would-drop` 不改变 verdict，但必须输出稳定 `ruleId/reasonId` 并更新统计。

- D) 参考资料清单（带链接）：
  - DPDK Programmer’s Guide — Packet Classification and Access Control｜项目文档｜ACL 规则字段支持 bitmask/mask/range，编译为多 bit-tries，命中返回最高优先级｜用于备选路线的多维分类能力与优先级模型。  
    链接：https://doc.dpdk.org/guides-1.8/prog_guide/packet_classif_access_ctrl.html
  - DPDK `rte_acl.h` API｜项目源码/API｜`rte_acl_rule_data` 提供 `priority/category/userdata`，可把 `ruleId/reasonId` 作为稳定返回值载荷｜支撑可解释命中设计。  
    链接：https://doc.dpdk.org/api/rte__acl_8h_source.html
  - DPDK LPM Library (`rte_lpm`)｜项目文档｜采用 DIR-24-8，常见前缀可在 tbl24 一次读取命中，深前缀再走 tbl8，并提供与 RCU QSBR 集成说明｜支撑 IPv4 CIDR 近似常数查找与快照更新。  
    链接：https://doc.dpdk.org/guides/prog_guide/lpm_lib.html
  - Linux Kernel `fib_trie` 文档｜内核文档｜说明 level compression + path compression，并给出 RCU 读路径与重平衡策略｜为“只读快照 + 后台重构”提供内核级先例。  
    链接：https://docs.kernel.org/networking/fib_trie.html
  - FD.io VPP N-tuple Classifier 说明｜项目文档｜按 mask 组织表并使用 skip/match/bucket 进行分类，属于工程化多维匹配实现｜作为 ACL/哈希分桶路线参考。  
    链接：https://wiki.fd.io/view/VPP/Introduction_To_N-tuple_Classifiers
  - OpenBSD `pf.conf` 手册｜系统手册｜默认是“最后匹配规则生效”，`quick` 可变成第一命中即停｜用于比较不同防火墙优先级语义。  
    链接：https://man.openbsd.org/pf.conf
  - FreeBSD Handbook (IPFW)｜官方文档｜IPFW 默认 first-match 规则流水线（少数动作如 `count/skipto/tee` 可继续）｜用于 tie-break 与 rule order 语义对照。  
    链接：https://docs.freebsd.org/pl/books/handbook/firewalls/
  - nftables Manpage｜官方文档｜set/map/interval 提供高效匹配结构，支持 `policy performance` 等选项｜用于“内核式集合匹配”路线评估。  
    链接：https://www.netfilter.org/projects/nftables/manpage.html
  - nftables Wiki — Atomic rule replacement｜官方 Wiki｜支持规则集原子替换事务，避免运行时中间态｜与 snapshot 原子发布思想一致。  
    链接：https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
  - Srinivasan et al., Packet classification using tuple space search (SIGCOMM CCR 1999)｜论文｜提出 tuple-space 分解以减少多字段匹配开销｜学术备选路线之一。  
    链接：https://doi.org/10.1145/316194.316216
  - Gupta & McKeown, Classifying packets with hierarchical intelligent cuttings (IEEE Micro 2000)｜论文｜HiCuts 通过分层切分降低分类深度，是决策树路线代表｜用于评估大规则集下的构建/查询权衡。  
    链接：https://doi.org/10.1109/40.820051
  - Taylor, Packet Classification Algorithms: From Theory to Practice (INFOCOM 2009)｜论文｜系统比较多类分类算法的复杂度、内存与工程可实现性｜用于“为何 P0/P1 不选重型树算法”的证据。  
    链接：https://doi.org/10.1109/INFCOM.2009.5061972
  - Asai & Ohara, Poptrie (SIGCOMM 2015)｜论文｜压缩 trie + population count 提升软件路由查找吞吐与可扩展性｜为 IPv4 CIDR 高性能 LPM 提供先进实现方向。  
    链接：https://doi.org/10.1145/2785956.2787474
  - Taylor & Turner, ClassBench: a packet classification benchmark (INFOCOM 2005)｜论文｜提供可重复的规则/流量基准生成方法｜用于本项目 micro-bench 数据集构建。  
    链接：https://doi.org/10.1109/INFCOM.2005.1498483


  # TASK PROMPT (ROUND 2, ACTIVE) — IP 策略引擎：多维通配匹配与“无回溯”分类

  > 目标：解决 sucre-snort 的 IP 规则引擎“核心组织方式”问题：当规则在多个维度允许 ANY/CIDR 时，如何在热路径避免回溯/枚举爆炸，同时保持语义确定（reasonId/ruleId 稳定）、更新原子（RCU
  snapshot）和统计无锁。

  ## 0) 背景与现状事实（必须先读）
  仓库：`/home/js/Git/sucre/sucre/sucre-snort`

  先阅读并用 <= 12 行复述关键约束（作为你输出的第一段）：
  - `docs/archived/P0P1_BACKEND_WORKING_DECISIONS.md`
  - `docs/IP_RULE_ENGINE_RESEARCH.md`（已有 Round1 结果）
  - 热路径链路：`src/PacketListener.cpp`、`src/PacketManager.hpp`
  - 现有接口事实：`PacketListener` 目前传给 `PacketManager::make` 的 IP 是 `addr = IN ? saddr : daddr`（direction 折叠为 remote IP）
  - PKTSTREAM 风险：`Streamable::stream` 同步写 socket，慢消费者会拖慢热路径（但本轮重点是规则引擎，不要求解决 stream）

  ## 1) 本轮要明确的问题定义（先“思路”，后“案例”）
  我们要设计一个可落地的 **IPv4 L3/L4 per-app** 规则引擎，要求支持：
  - 规则维度（至少）：`uid + direction + ifaceClass + proto + src/dst port + (remoteIP 或 srcIP+dstIP) CIDR`
  - 任意维度允许 ANY（通配），IP 允许 CIDR（前缀）
  - 输出必须可解释：命中必须返回稳定 `ruleId/reasonId`，用于 PKTSTREAM 与 per-rule 统计归因
  - 更新必须原子：控制面构建新快照，数据面只读，切换一次 `atomic publish`
  - 热路径不加锁、不做动态分配、不做重 IO

  你需要在输出中先把“核心冲突”讲清楚（用最少数学/最直观方式）：
  - 为什么 1D LPM（只 remoteIP）容易；为什么 2D（srcCIDR + dstCIDR）会出现“候选组合”从而引出回溯/枚举；
  - 业界如何把这类“回溯”问题推到编译期/数据结构（分类器）里解决。

  ## 2) 必须覆盖的“解决方案全景”（尽量穷举）
  你要把方案按“思路类别”列全（至少 6 类），每类给：
  - 核心思想（1–3 句）
  - 运行时查询复杂度（最坏/典型）与常数因子
  - 构建/编译成本与更新策略（是否支持 RCU/snapshot）
  - 如何保证命中唯一（priority/first-match/last-match/most-specific）以及对 ruleId/reasonId 的影响
  - 对我们场景（NFQUEUE 用户态、规则量预计不大、UID 维度、接口分类、端口维度）的适配度

  至少包含这些类别（可增加更多）：
  1) 固定 pipeline / 分层索引（uid->ctx->ports->ip），通过“词典序具体性”避免全局搜索
  2) Tuple-space / mask 分组表（按 mask 形状分 subtable；运行时按表集合查找）
  3) 编译式 ACL 分类器（例如 DPDK `rte_acl` 那类：多维字段编译为 trie/状态机/向量化 classify）
  4) 决策树类（HiCuts/HyperSplit 等）
  5) 位图/集合求交（每维生成候选集合 bitset，运行时做 AND 收敛）
  6) 内核式集合/区间结构启发（nftables set/map/interval、ipset、tc flower 等，重点学数据结构与事务/原子替换思想，而不是照搬内核接口）
  7) （加分）OVS/OpenFlow classifier（这是用户态多维通配匹配的经典工程实现；必须研究）

  ## 3) 联网检索：必须查的“高质量实现/资料”
  除 DPDK/VPP 之外，本轮必须重点补齐：
  - Open vSwitch classifier / megaflow / subtable-by-mask 设计（工程实现与论文/博客）
  - Linux nftables sets/maps/interval 与“atomic ruleset replacement”（事务语义）
  - ipset（hash:ip, hash:net 等）数据结构与适用边界
  - tc flower / clsact / eBPF（尤其 Android/内核里“UID 维度”如何组织）
  - Android UID firewall（netd、eBPF maps、cgroup hooks 等）——哪怕规则能力更弱，也要总结“UID 索引与更新”实践
  - 论文：Tuple-space search、ClassBench、HiCuts、HyperSplit、Poptrie（至少每类 1–2 篇“最权威”的）

  要求：
  - 优先 primary sources（官方文档、源码、论文）
  - 每条资料必须给链接 + 1 句“对我们有用的结论”

  ## 4) 源码快读（不限数量，但要高质量）
  允许下载到 `/tmp` 或在线读源码。至少要“快读并提炼”以下两类之一：
  - OVS classifier 相关源码（subtable、mask、priority、lookup 路径、更新策略）
  - DPDK `rte_acl` 或同级别 ACL 库/实现
  （如果做不到下载，就在线读关键文件并引用路径）

  输出要回答（不要贴大段代码）：
  - 规则表示（fields/mask/range/prefix/priority）
  - 编译阶段产物是什么（subtable、trie、decision nodes、vector tables…）
  - lookup 路径是固定步数还是需要枚举多候选？如何“避免回溯”
  - 更新是全量重建还是增量？如何保证读写并发与原子可见性

  ## 5) 你必须输出的结论结构（严格按此格式）
  ### A) 问题重述（含“回溯/候选组合”为何出现）+ 语义模型对比
  - first-match / last-match / priority / most-specific 各自的利弊
  - 哪一种最适合“可解释 + 稳定 ruleId + 统计归因”

  ### B) 方案全景表格（>= 6 类）
  列：方案类｜代表实现｜运行时复杂度｜构建/更新模型｜内存｜是否天然支持双CIDR｜是否易支持 UID｜可解释性与 tie-break｜工程风险

  ### C) 对 sucre-snort 的推荐（主路线 + 备选）
  - 推荐 1 条主路线 + 1 条备选路线，并明确“不选其它路线”的原因
  - 给出“落地到我们仓库”的索引草案（到数据结构级别，不写代码）
  - 明确 tie-break（priority/顺序/具体性）如何定义，确保命中唯一、reasonId/ruleId 稳定

  ### D) 验证与基准（micro-bench + e2e）
  - micro-bench 数据集建议（规则规模、CIDR比例、mask种类）
  - e2e 在 NFQUEUE 热路径的指标与对比方式
  - 更新频率/批量更新下的 publish 抖动与正确性检查

  ### E) 参考资料清单（带链接）
  每条：标题｜来源｜一句结论｜与我们关联点

  ## 6) 约束提醒
  - 不要提出引入大而重的新运行时依赖（除非作为“备选路线”且给出理由）
  - 不要泛泛而谈，输出必须能直接指导 OpenSpec change 的设计与任务拆分
  - 控制上下文：不贴大段源码，提炼结构 + 指向关键文件/函数即可

# RESULTS2（在此处追加，不要改动上面的 TASK PROMPT）

## 2026-03-03 — Round2：多维通配匹配与“无回溯”分类器调研

- 本仓库关键约束复述（<=12 行）：
  - NFQUEUE 热路径是 `PacketListener::callback -> PacketManager::make`，要求不新增锁、不做重 IO。
  - 当前 `settings.blockEnabled()` 是总开关，关掉即直接 `NF_ACCEPT`（无全局 dry-run）。
  - 现有判决主因子仍是 `BLOCKIPLEAKS` 与 `blockIface`；新增引擎需并入但不能拖慢热路径。
  - `PacketListener` 当前传递的是 `addr = IN ? saddr : daddr`（direction 折叠成 remote IP 视角）。
  - `PacketManager::make` 在 `mutexListeners` shared lock 内，临界区要保持纯计算。
  - `PKTSTREAM` 通过 `Streamable::stream -> SocketIO::print` 同步写 socket，慢消费者会反压。
  - P0/P1 仍以 IPv4 规则为先，IPv6 新语义后置（默认放行/不提示）。
  - 新引擎必须返回稳定 `ruleId/reasonId`，支持 per-rule hit/lastHit，更新用 immutable snapshot + atomic publish。

### A) 问题重述（含“回溯/候选组合”为何出现）+ 语义模型对比

- **核心冲突（为什么会回溯）**：
  - 1D（仅 remoteIP）的 LPM 很“直线”：只需最长前缀优先，天然单调。
  - 2D（`srcCIDR + dstCIDR`）后，两个维度都有“更具体/更泛化”层级；再叠加 `proto/port/iface/direction` 的 ANY，单调顺序不再唯一。
  - 一个包可同时命中多条“不同维度各自更具体”的规则（例如 A 规则 src 更具体、B 规则 dst 更具体），若无预先定义的全局优先语义，运行时就会出现候选组合与回溯/枚举。
  - 工程上通常把“冲突消解”前移到编译期：按 mask 形状分组、预排序优先级、构造分类器/子表；运行时仅做固定流程 lookup（不回溯）。

- **语义模型对比（命中唯一性）**：

| 模型 | 优点 | 缺点 | 对 `ruleId/reasonId` 稳定性的影响 |
|---|---|---|---|
| first-match（按顺序） | 实现简单、可解释 | 规则重排会改变语义；插入位置敏感 | 中（顺序变动即结果变） |
| last-match（如 pf 默认） | 规则覆盖直观 | 调试时更难局部推断；同样依赖顺序 | 中 |
| most-specific（最长前缀/更具体） | 对 IP 维度自然 | 跨维度“具体性”定义不唯一（src vs dst vs port） | 中-低（需额外规则） |
| **priority（推荐）** | 唯一、稳定、可编译期固化 | 需管理优先级空间 | **高（最适合稳定归因）** |

- **结论**：对 sucre-snort 最稳妥的是 **`priority` 主导**，并固定二级/三级 tie-break（具体性分数、`ruleId`）保证全局确定性。

### B) 方案全景表格（>= 6 类）

| 方案类 | 代表实现 | 运行时复杂度 | 构建/更新模型 | 内存 | 是否天然支持双CIDR | 是否易支持 UID | 可解释性与 tie-break | 工程风险 |
|---|---|---|---|---|---|---|---|---|
| 固定 pipeline / 分层索引 | 自研 `uid->ctx->ports->ip` | 典型近似 O(1)+LPM；最坏看候选桶数 | COW 构建 snapshot，atomic 发布 | 低-中 | 中（要人为定义 src/dst 顺序） | 高 | 高（规则顺序可编译固化） | 低 |
| Tuple-space / mask 分组 | OVS `classifier`、TSS 论文 | 典型 O(候选子表数)；最坏 O(全部 mask 形状) | 按 mask 分 subtable，增量插删 + 向量发布/RCU 风格可见性 | 中 | 高 | 高（UID 先分区即可） | 高（priority + subtable max-prio 可早停） | 中 |
| 编译式 ACL 分类器 | DPDK `rte_acl` | 近似 O(trie 步数)，常数低（可 SIMD 并行） | `add_rules -> build`，运行时只读 classify；双缓冲发布 | 中-高 | 高 | 中（把 UID 当字段会放大维度） | 高（最高 priority + userdata） | 中 |
| 决策树类 | HiCuts / HyperSplit / 后续变体 | 典型 O(tree depth)，最坏与树形状相关 | 构建重、增量更新难；常见全量重编译 | 中-高 | 高 | 中 | 中（需额外稳定规则） | 高 |
| 位图/集合求交 | Packet Classification on Multiple Fields（位图思想） | 运行时约 O(候选位图 AND + 首位扫描) | 编译期生成每维候选集合；更新需维护多索引 | 高（规则多时位图膨胀） | 高 | 高 | 高（最终按 priority/ruleId 选） | 中-高 |
| 内核式 set/map/interval 启发 | nftables sets/maps/interval、ipset | exact 常见 O(1)；interval 常见 O(logN) | 事务/原子替换思想成熟 | 低-中 | 高 | 中（需额外 UID 组织层） | 中-高（事务语义强） | 中 |
| OVS 用户态缓存分层（加分） | OVS EMC/megaflow + dpcls | cache 命中近似 O(1)，miss 回落分类器 | 前端 cache + 后端分类器并行演化 | 中 | 高 | 高 | 高（后端仍走确定性 classifier） | 中 |

### C) 对 sucre-snort 的推荐（主路线 + 备选）

- **主路线（推荐）**：`UID 分区 + OVS 风格 mask-subtable 分类器`（每个 UID/上下文内按 mask 形状分子表，子表内 masked-key 哈希命中）。
- **备选路线**：`固定 pipeline（uid->ctx->port->ip）`，仅在规则语法被限制为“单侧 IP 主导（如 remoteIP）”或 mask 形状很少时使用。
- **不选其它路线的原因**：
  - 纯决策树（HiCuts/HyperSplit）构建与增量更新成本偏高，不适合当前规则量与迭代节奏。
  - 纯位图交集在规则维度增长时内存/更新成本上升快。
  - 直接搬内核 nft/ipset/tc 不契合当前 NFQUEUE 用户态判决路径；应借鉴其数据结构与事务思想而非接口语义。

- **落地到本仓库的索引草案（数据结构级）**：

```text
EngineSnapshot (immutable, atomic-published)
  byUid: flat_hash_map<uid, UidView>

UidView
  byCtx: flat_hash_map<CtxKey, MaskClassifier>
  CtxKey = (direction, ifaceClass, protoBucket)   // 先强分桶降低候选规模

MaskClassifier
  subtables: vector<Subtable*>                    // 按 subtable.maxPriority 降序
  byMaskSig: flat_hash_map<MaskSig, Subtable*>

Subtable
  maskSig: {srcIPMask, dstIPMask, srcPortMask/rangeTag, dstPortMask/rangeTag, ...}
  maxPriority: int32
  bucket: flat_hash_map<MaskedKey, SmallVec<RuleRef>>

RuleRef
  { ruleId, reasonId, priority, specificityScore, enforce, log, runtimeSlot }
```

- **查询路径（无回溯）**：
  1. 从 snapshot 取 `uid -> ctx`（miss 即默认放行，沿用现有策略）。
  2. 顺序扫描 `subtables`：对每个子表做一次 `masked-key` 计算 + 哈希查找。
  3. 一旦已有 `best.priority >= subtable.maxPriority`，后续子表可提前终止。
  4. 在候选 `RuleRef` 上应用固定 tie-break 得到唯一命中，不做递归/回溯。

- **tie-break（保证唯一、稳定）**：
  - 主键：`priority`（高优先）
  - 次键：`specificityScore`（例如：`srcPrefixLen + dstPrefixLen + exactPortBonus + exactProtoBonus + exactIfaceBonus`）
  - 终键：`ruleId`（小者优先，保证全局稳定）
  - 命中输出：`reasonId/ruleId` 直接取最终 RuleRef。

- **更新与并发**：
  - 控制面：将规则归一化后构建新 `EngineSnapshot`（子表、哈希桶、排序、maxPriority）。
  - 数据面：`atomic_load(shared_ptr<const Snapshot>)` 只读查表。
  - 发布：`atomic_store` 一次切换，保证读路径仅见“旧版或新版”。

- **统计与 log-only（无锁）**：
  - `RuleRuntime` 独立于 snapshot，按 `runtimeSlot` 索引，字段：`hitPackets/hitBytes/lastHit/wouldDropHits`。
  - 计数采用分片原子（按 NFQUEUE 线程）+ 周期汇总，避免热点写争用。
  - `enforce=0, log=1` 返回 `wouldDrop=1` 且 verdict 仍 `ACCEPT`，并输出稳定 `reasonId` 与 `wouldRuleId`。

- **源码快读提炼（本轮重点）**：
  - OVS `classifier.c`：按 minimask 组织 subtable；lookup 维护 `hard_pri`，可跳过低优先子表；含 trie 上下文做剪枝（`n_tries`）。
  - OVS `dpif-netdev.c`：dpcls 按 mask 建 subtable，支持子表专用 lookup 函数（含 SIMD 变体），命中后对该 key 提前停止；并明确不实现 priority，依赖 datapath flow 的非重叠性。
  - DPDK `rte_acl`：规则字段支持 mask/range/bitmask，`rte_acl_build()` 生成多 bit-tries，`rte_acl_classify()` 返回最高优先级规则 userdata。

### D) 验证与基准（micro-bench + e2e）

- **micro-bench 数据集建议**：
  - 规则规模：`256 / 1k / 5k / 10k`。
  - mask 形状数量：`4 / 16 / 64`（观察 subtable 爆炸临界点）。
  - CIDR 组合：`src-only`、`dst-only`、`src+dst`；前缀分布 `/32,/24,/16,/8`。
  - ANY 比例：`10% / 50% / 80%`（模拟“宽规则”增多场景）。
  - UID 桶规模：`1 / 100 / 1k`；每 UID 规则数偏斜（Zipf）与均匀两类。

- **micro 指标**：
  - `ns/lookup`（p50/p95/p99）、`cycles`、`cache-misses`、`branch-misses`。
  - 每包访问子表数量（平均/95 分位）与早停命中率。
  - snapshot 编译时间、峰值内存、publish 耗时。

- **e2e（NFQUEUE 热路径）**：
  - 对比基线：`engine off` vs `engine on`（规则规模分层）+ `PKTSTREAM off/on`。
  - 指标：pps、CPU、`PacketListener::callback` 耗时分位、队列 backlog/drop。
  - 目标：在 `1k~10k` 规则下保持“近似常数查找”，无锁读取，且不存在写路径阻塞读路径。

- **更新抖动与正确性检查**：
  - 批量更新：`1/10/100/1000` 条变更，测 compile/publish 尾延迟。
  - 并发一致性：高频发包 + 高频发布，验证只见旧/新规则，不出现混合状态。
  - 语义回归：同包命中多规则时，`priority -> specificity -> ruleId` 结果恒定，`reasonId` 稳定。

### E) 参考资料清单（带链接）

- The Design and Implementation of Open vSwitch（NSDI 2015）｜论文/官方会议页｜OVS 采用分层 fast path + classifier 组织，强调用户态高性能实现｜为“用户态多维匹配 + 工程可落地”提供直接先例。  
  链接：https://www.usenix.org/conference/nsdi15/technical-sessions/presentation/pfaff
- Open vSwitch `classifier.c`｜项目源码｜按 mask 分 subtable，lookup 中维护优先级上界并可跳过低价值候选｜直接对应“无回溯 + 优先级稳定命中”。  
  链接：https://github.com/openvswitch/ovs/blob/main/lib/classifier.c
- Open vSwitch `classifier.h`（comment）｜项目源码｜解释“按 mask 分 subtable + subtable 按最高 priority 排序 + 早停跳过”的核心机制｜可直接映射到本轮推荐的 mask-subtable 分类器。  
  链接：https://github.com/openvswitch/ovs/blob/main/lib/classifier.h
- Open vSwitch FAQ design（megaflow cache）｜项目文档｜说明 megaflow cache miss 时走 slow path/用户态处理的分层路径｜用于理解“cache 层 + 分类器层”的工程分层。  
  链接：https://github.com/openvswitch/ovs/blob/main/Documentation/faq/design.rst
- Open vSwitch `dpif-netdev.c`（dpcls）｜项目源码｜subtable-by-mask + 子表专用 lookup（含 SIMD），并通过向量发布更新可见性｜可借鉴 mask 形状分组与热路径固定步查找。  
  链接：https://github.com/openvswitch/ovs/blob/main/lib/dpif-netdev.c
- Open vSwitch `dpif-netdev-private-dpcls.h`｜项目源码｜明确 `dpcls_subtable`、`dpcls_rule`、按 mask 建子表的数据结构｜可映射到我们的 `MaskSig/Subtable/RuleRef` 设计。  
  链接：https://github.com/openvswitch/ovs/blob/main/lib/dpif-netdev-private-dpcls.h
- DPDK ACL Programmer’s Guide｜项目文档｜`rte_acl_build()` 把规则编译成多 bit-tries，运行时按最高优先级返回｜证明“把复杂性放到编译期”的可行路径。  
  链接：https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html
- DPDK `rte_acl.h`｜项目源码/API｜`rule_data` 含 `priority/userdata`，天然支持稳定 `ruleId/reasonId` 载荷返回｜适合做备选编译式分类器。  
  链接：https://doc.dpdk.org/api/rte__acl_8h_source.html
- DPDK LPM Library｜项目文档｜DIR-24-8 风格 IPv4 LPM，常见前缀一次命中，支持与 RCU QSBR 协作｜适合作为 IP 前缀子组件。  
  链接：https://doc.dpdk.org/guides/prog_guide/lpm_lib.html
- nftables Sets｜官方文档｜set/map 元素内部可用哈希与红黑树等性能结构表示｜可借鉴“统一集合抽象 + 多后端结构”。  
  链接：https://wiki.nftables.org/wiki-nftables/index.php/Sets
- nftables Maps｜官方文档｜map 可视为“返回值的 set”，与 set 共用通用集合基础设施｜可借鉴为“命中直接返回 ruleId/reasonId”的映射表思路。  
  链接：https://wiki.nftables.org/wiki-nftables/index.php/Maps
- nftables Intervals｜官方文档｜interval 支持区间元素（IP/port 范围等），并可与 set/vmap 组合表达｜用于评估 port-range/interval 的数据结构支持边界。  
  链接：https://wiki.nftables.org/wiki-nftables/index.php/Intervals
- nftables Atomic rule replacement｜官方文档｜整套规则在内存构建后一次替换，避免中间态｜与 snapshot 原子发布完全同构。  
  链接：https://wiki.nftables.org/wiki-nftables/index.php/Atomic_rule_replacement
- ipset manual｜官方文档｜`hash:ip/hash:net/bitmap` 等类型揭示 exact 与 prefix 集合的结构边界｜可借鉴为 `exact hash + prefix index` 混合策略。  
  链接：https://ipset.netfilter.org/ipset.man.html
- tc-flower(8)｜官方手册｜支持 `src_ip/dst_ip + src_port/dst_port + ip_proto + indev` 等多维匹配与掩码｜说明 Linux 侧多维 wildcard 的字段组织方式。  
  链接：https://man7.org/linux/man-pages/man8/tc-flower.8.html
- tc-bpf(8)｜官方手册｜描述 eBPF classifier/action 在 ingress/egress 挂载与 direct-action 语义，并可通过 bpf(2) 更新 map｜用于理解 tc/eBPF 路径的更新与匹配组织。  
  链接：https://man7.org/linux/man-pages/man8/tc-bpf.8.html
- Android netd eBPF `netd.h`｜AOSP 源码｜`uid_owner_map` + 配置位图实现 UID 规则快速判定（eBPF map lookup）｜对“UID 先索引、规则位编码”有直接启发。  
  链接：https://github.com/msft-mirror-aosp/platform.system.netd/blob/main/bpf_progs/netd.h
- Android netd `TrafficController.cpp`｜AOSP 源码｜通过 `replaceUidOwnerMap()` 批量增删 `uid_owner_map` 条目，并用 `configuration_map` 位开关启用/禁用 match 类型（单次写配置）｜可借鉴 UID 索引与控制面批量更新实践。  
  链接：https://github.com/msft-mirror-aosp/platform.system.netd/blob/main/server/TrafficController.cpp
- HyperSplit（kun2012）｜开源实现｜实现 INFOCOM 2009 HyperSplit，并附带吞吐测试入口｜可用于快速对照数据结构与查询路径。  
  链接：https://github.com/kun2012/HyperSplit
- Packet classification using tuple space search（SIGCOMM CCR 1999）｜论文｜提出按 mask/tuple 分组降低多维匹配搜索复杂度｜是 mask-subtable 思路的经典理论基线。  
  链接：https://doi.org/10.1145/316194.316216
- Packet classification on multiple fields（SIGCOMM CCR 1999）｜论文｜系统讨论多字段分类与候选组织（含位图/交集等思路）｜用于位图求交类方案的理论依据。  
  链接：https://doi.org/10.1145/316194.316217
- Classifying packets with hierarchical intelligent cuttings（IEEE Micro 2000）｜论文｜HiCuts 代表决策树族，查询快但构建/更新权衡明显｜用于解释“为何不作为本期主路线”。  
  链接：https://doi.org/10.1109/40.820051
- Packet Classification Algorithms: From Theory to Practice（INFOCOM 2009, HyperSplit）｜论文｜提出/描述 HyperSplit，并讨论多类算法的工程取舍｜作为本轮“决策树类/HyperSplit”权威来源。  
  链接：https://doi.org/10.1109/INFCOM.2009.5061972
  PDF：https://tsinghua-nslab.org/assets/files/infocom09-hypersplit-2dc9cce9ef565d9803151bb771d48417.pdf
- Survey and taxonomy of packet classification techniques（ACM CSUR 2005）｜论文｜系统总结 tuple-space、cutting、bitmap 等分类器家族与工程权衡｜用于方案全景与术语对齐。  
  链接：https://doi.org/10.1145/1108956.1108958
- Packet classification using multidimensional cutting（SIGCOMM 2003, HyperCuts）｜论文｜经典决策树族代表，展示多维 cutting 的查询/构建权衡｜用于决策树类方案的权威来源。  
  链接：https://doi.org/10.1145/863955.863980
- ClassBench: a packet classification benchmark（INFOCOM 2005）｜论文｜给出可重复规则与流量基准生成方法｜直接用于本轮 micro-bench 数据集设计。  
  链接：https://doi.org/10.1109/INFCOM.2005.1498483
- Poptrie（SIGCOMM 2015）｜论文｜压缩 trie + popcount 提升软件 LPM 吞吐｜对前缀匹配子结构优化有参考价值。  
  链接：https://doi.org/10.1145/2785956.2787474
