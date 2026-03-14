# IP 规则引擎：工作决策与原则（P0/P1）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


更新时间：2026-03-12  
状态：纲领性工作结论（可迭代修订；实现与验收以 OpenSpec change 为准）

---

## 0. 目标与范围

本文件的目标：把 IP 相关功能的**上位原则**与**已决定的关键语义**固化成“纲领”，用于后续实现/细化时反复对照，避免细节讨论把系统带偏。

范围包含：
- per‑App(UID) 的 IPv4 L3/L4 规则引擎（语义 + 性能/并发约束 + 控制面协议）。
- 可解释性与观测契约（reasonId/ruleId/would‑match + per‑rule stats）的**边界与口径**。

范围不包含（明确后置）：
- `ip-leak` 与 IP 规则的合流语义；该部分当前视为附属功能，暂时剥离并记为 TBD。
- 域名系统的独立开关语义（DOMAINPOLICY/DOMAINMAP/DNS `getips` 等）与“最终融合”形态。
- IPv6 新规则语义（本期 IPv6 默认放行且不提示）。

---

## 1. 单一真相（权威入口）

为避免“讨论摘录/二手结论”互相打架，权威以以下文档为准：

1) IP 规则引擎（语义/算法/控制面）：  
`openspec/changes/add-app-ip-l3l4-rules-engine/`

2) PKTSTREAM schema + reasonId/would‑match 契约（字段与口径）：  
`openspec/changes/add-pktstream-observability/`

3) 原始讨论摘录（只用于追溯决策背景，不作最终规范）：  
`docs/archived/IP_RULE_POLICY_DISCUSSION_RAW_EXCERPTS_019cad3d-d9ba-7b21-9dc8-ae0f84c12ba1.md`

辅助材料（调研/事实语义）：
- `docs/P0P1_BACKEND_WORKING_DECISIONS.md`
- `docs/archived/IP_RULE_ENGINE_RESEARCH.md`

---

## 2. 决策原则（做取舍时的上位约束）

1) **在现状基础上，NFQUEUE 热路径不引入新的锁/重 IO/动态分配**  
热路径只允许纯计算、只读快照查询与固定维度的 `atomic++(relaxed)`；不得新增阻塞点。

2) **更新必须原子：snapshot + atomic publish（RCU 风格）**  
热路径只能看到“旧或新”完整版本，不存在中间态；控制面在新快照上编译并一次性发布。

3) **可解释必须确定且唯一**  
同一时刻同一包命中多条规则时，必须按固定规则选出唯一“最终命中”，稳定输出 `reasonId + ruleId`，并让 per‑rule stats 归因不漂移。

4) **表达力受控 + 预检（preflight）硬保护**  
不追求“任意组合的防火墙”；允许的语义必须能被编译为受控的最坏复杂度，并用硬上限拒绝超限配置。

5) **不新增观测通路**  
事件复用 PKTSTREAM；常态统计通过控制面拉取（per‑rule stats），不引入新的存储/查询系统。

6) **分层推进：后端骨架可扩展，前端按 P0/P1 逐步开放**  
后端先把“字段全集 + 分类器骨架 + 可解释/预检”钉死；前端按阶段只开放子集，附属融合功能后置，避免后续因接口形态返工。

7) **当前未发正式版：不预设历史迁移/兼容包袱，但接口变更仍须克制**  
当前仓库尚未发布正式版本，因此不需要为了“历史发布版本迁移/兼容”预先引入额外约束；但这不意味着控制协议、字段形态或语义可以随意改动。任何接口层调整都必须有明确、可复述的理由——例如修复重大语义问题、消除原则冲突、或为满足已确认需求而别无选择——并且必须同步更新权威文档，避免接口漂移。

---

## 3. 已决定：当前阶段的判决边界

### 3.1 系统边界
- **IP 规则系统**：新增 per‑UID IPv4 L3/L4 规则引擎，支持 `ALLOW/BLOCK` + 显式 `priority` + `enforce/log`。
- **`ip-leak` 相关功能**：当前阶段从本 change 暂时剥离；不定义其与 IP 规则的合流语义，也不将其作为本 change 的实现/验收前提。

### 3.2 不可覆盖的硬原因
- `IFACE_BLOCK` 保持 hard‑drop：命中必 DROP，IP 规则不得覆盖（无论 allow/priority）。
- 命中 `IFACE_BLOCK` 的数据包，其实际 `reasonId` 必须仍为 `IFACE_BLOCK`，且不得再附带来自 IP 规则引擎的 `ruleId`/`wouldRuleId` 归因。

### 3.3 当前阶段的 Packet 判决顺序
- 先应用现有硬原因：`IFACE_BLOCK`；该预检查应尽量前移到 host/domain 等潜在慢路径之前，命中后直接终止后续 IP 规则与 legacy 判决。
- 仅当数据包未命中 `IFACE_BLOCK` 且 `IPRULES=1` 时，才进入 IP 规则引擎的 fast path；其顺序固定为：`exact-decision cache -> classifier snapshot`。
- `exact-decision cache` 缓存的是 **IP 规则引擎这一层** 的结果（`NoMatch/Allow/Block/WouldBlock`），而不是整个系统的最终 verdict；只有 cache miss 才进入 classifier。
- 仅当 IP 规则引擎给出 `NoMatch` 时，数据包才允许继续进入后续 legacy/domain 路径；新引擎与旧路径的边界必须显式保持，避免语义揉成一个不可解释的大 verdict。
- `ip-leak` 的启用方式、优先级与是否参与合流，统一留到后续独立讨论；当前不作为本 change 的一部分。

---

## 4. 已决定：IP 规则引擎语义（对外可见的关键点）

### 4.1 规则模型（v1）
每条规则至少包含：
- 归属：`uid`
- 动作：`ALLOW|BLOCK`
- 开关：`enabled`、`enforce`、`log`
- 优先级：显式 `priority`
- 匹配维度（IPv4）：
  - `direction`（in/out/any）
  - `ifaceKind`（wifi/data/vpn/unmanaged/any）+ 可选 `ifindex` 精确匹配
  - `proto`（tcp/udp/icmp/any）
  - `src/dst IPv4 CIDR`（`/0..32`）
  - `src/dst port`（any / 精确 / range）
- `ct`：当前 v1 不纳入控制面可配置语义；若客户端传入 `ct` 条件，控制面应直接拒绝，避免出现“看起来配置了、实际上不生效”的假语义

匹配语义（避免歧义）：
- `src/dst` 与 `srcPort/dstPort` 均指数据包 IPv4/L4 头部字段（`saddr/daddr`、TCP/UDP `source/dest`）。
- `direction=in|out` 仅表示包来自 `INPUT/OUTPUT` 链（入站/出站），不改变上述字段含义。

其中：
- 当前 v1 控制面只接受数值 `uid`，不接受包名字符串 selector。
- 当前 v1 要求 `priority` 显式提供；若缺失则控制面直接拒绝。
- `IPRULES.ADD` 若未显式提供 `enabled/enforce/log`，则其 v1 缺省值固定为 `1/1/0`。
- `IPRULES.UPDATE` 采用 patch/merge 语义：仅更新请求中提供的 key；未提供的 key MUST 保持原值（不得回落到缺省值）。
- `enabled=0` 表示该规则仍保留在控制面/持久化/打印视图中；对热路径必须等价于“该规则不存在”。
- `enabled=0` 的规则不得进入 active matcher，不得产生 `ruleId`/`wouldRuleId`，不得更新 stats，也不得计入 active preflight 复杂度。

### 4.2 热路径 `PacketKey` 与 exact cache（v1）
- 当前阶段只定义 `PacketKeyV4`；不为了“看起来统一”而提前引入 IPv4/IPv6 共享 key。IPv6 仍按本期边界保持默认放行。
- `PacketKeyV4` 的最小字段集合固定为：`uid`、`direction`、`ifindex`、`ifaceKind`、`proto`、`srcIp`、`dstIp`、`srcPort`、`dstPort`。
- `PacketKeyV4` 必须使用稳定的标量表示（例如 host-byte-order 的整数），不得把 `timestamp`、`len`、NFQUEUE `packet_id`、`App/Host/Domain` 指针或其他每包波动字段纳入 key。
- `ifaceKind` 与 `ifindex` 在 key 中同时保留：前者承载规则语义，后者承载精确接口约束；两者都属于命中判定输入，不得互相替代。
- v1 的 `exact-decision cache` 为 IP 规则引擎前置的精确命中加速层；entry 至少应随 `rulesEpoch` 一起缓存引擎层结果（`NoMatch/Allow/Block/WouldBlock`）及对应规则归因信息。
- 该 cache 的 correctness 前提是“相同 `PacketKeyV4` + 相同 `rulesEpoch` => 相同引擎层结果”；它不是 flow tracker，也不是整个系统的最终 verdict cache。
- v1 的 exact cache / classifier correctness **明确不依赖** `NFQA_CT`、内核 conntrack 可见性或用户态自研 full flow tracking；若未来使用 `NFQA_CT`，其也只能作为可选增强，而不能成为当前语义成立的前提。

### 4.3 命中唯一性（稳定归因）
同一包命中多条规则时，必须先按 `priority` 选出最高优先级候选；若同优先级仍有多条重叠命中，则由**编译后的 classifier 表示与查询路径**定义唯一胜者。

约束：
- 对同一份 active ruleset，重复编译后对同一包的唯一胜者必须保持一致。
- 唯一胜者的确定必须来自稳定的编译结果（例如 subtable / bucket / rangeCandidates 的规范化顺序），而不是依赖不稳定的容器迭代顺序。
- `ruleId` 用于标识与观测，不再作为对外承诺的语义 tie-break 规则。

### 4.4 `ruleId` 生命周期（v1）
- 空规则集上的第一条规则使用初始 `ruleId = 0`。
- 常态增量管理下，`ruleId` 采用从 `0` 开始的单调递增整数分配。
- 单条 `UPDATE` / `ENABLE` / `DISABLE` 不改变该规则的 `ruleId`。
- 单条 `REMOVE` 不得导致其余规则重新编号；被移除的 `ruleId` 在当前规则集生命周期内不复用。
- 持久化恢复后，已保存规则应恢复其原有 `ruleId`。
- `RESETALL` 视为彻底丢弃当前整套规则集：所有规则被清空，后续新一轮规则集的 `ruleId` 计数器从初始值 `0` 重新开始。
- 除 `RESETALL` 这种“整套规则集清空后重开”之外，当前 change 不暴露“保留现有规则但整体重排 `ruleId`”的控制面；若未来引入该能力，应将其视为一轮新的规则集 epoch：旧 stats / log 关联整体作废并清空。

### 4.5 safety‑mode（逐条/批次规则；每包最多 1 条 would‑match）
- `enforce=1`：命中时实际执行 `ALLOW/BLOCK` 改变 verdict，并输出 `ruleId`。
- `action=BLOCK, enforce=0, log=1`：表示 would-block dry-run；仅当该包未被任何 `enforce=1` 规则作为最终命中接管时，才输出 would‑match（`wouldRuleId + wouldDrop=1`）；其命中不得改变 IP 规则引擎本身给出的实际 verdict，且每包最多 1 条。
- `enforce=0` 的原意仅限调试/试运行；不承担“禁用规则”的职责。
- 其他 `enforce=0` 组合（尤其 `action=ALLOW, enforce=0` 与 `enforce=0, log=0`）不作为现行语义，控制面应直接拒绝。

### 4.6 per‑rule stats（常态可查，不依赖 PKTSTREAM）
- 每条规则维护 `hit*` 与 `wouldHit*`（since boot，不持久化；重启归零）。
- 若需要跨重启保留/做长期分析，由前端周期性读取并自行持久化；后端不承担存储职责。
- 统计只归因到“最终胜出规则”和“最终 would‑match 规则（若有）”，避免一包多记。
- `enabled=0` 的规则不得更新任何 hit/wouldHit 计数。
- 规则内容一旦被 `UPDATE` 改写并生效，其 runtime state（含 `hit*`/`wouldHit*`）必须直接清零；不保留旧语义下的历史 state。
- 规则从 `enabled=0` 再次切回 `enabled=1` 时，其 runtime state 也必须清零，避免“禁用前（`enabled=1` 时）累计的历史命中”干扰重新启用后的观察（禁用后计数不再增长但仍会保留在控制面视图中；重新启用必须从 0 开始）。

### 4.7 控制面输出契约（v1）
- `IPRULES.PRINT` 固定返回顶层对象 `{"rules":[...]}`；即使当前无规则、或过滤后无命中，也返回 `{"rules":[]}`，而不是 `NOK`。
- `rules` 数组按 `ruleId` 升序输出，避免前端在无额外排序信息时出现不稳定抖动。
- `ruleId/uid/priority/stats.*` 在 JSON 中统一使用 number，不得输出为带引号字符串；`ifindex` 也使用 number，其中 `0` 表示“不限定精确 ifindex”。
- `enabled/enforce/log` 在 JSON 中统一使用 `0|1` number，延续当前控制面既有布尔风格，而不是 `true|false`。
- `action/dir/iface/proto` 使用规范化 string token；`src/dst` 使用规范化 string token（`any` 或标准 IPv4 CIDR）；`sport/dport` 使用规范化 string token（`any`、单端口十进制字符串、或 `lo-hi`）。控制面应尽量保证这些字段可直接 round-trip 回 `IPRULES.ADD/UPDATE` 的输入语法。
- `IPRULES.PREFLIGHT` 固定返回顶层对象 `{"summary":...,"limits":...,"warnings":...,"violations":...}`；其中 `summary` 为 number 字段对象，`limits` 为固定对象，`warnings/violations` 为对象数组，空时返回 `[]`。
- `limits` 至少固定为 `{ "recommended": {...}, "hard": {...} }` 两层；`warnings/violations` 的每项至少固定包含 `metric:string`、`value:number`、`limit:number`、`message:string`。
- `IFACES.PRINT` 固定返回顶层对象 `{"ifaces":[...]}`；若当前枚举失败或暂时没有可返回接口，允许返回 `{"ifaces":[]}`。
- `IFACES.PRINT` 的数组元素至少包含 `ifindex:number`、`name:string`、`kind:string`；若存在 `type`，其也应为 number，并仅作为调试增强信息。

### 4.8 IPv4/IPv6 边界
- 本期新规则语义仅作用于 IPv4。
- IPv6 流量不受新规则影响（默认放行且不提示“被规则检查过”）。

### 4.9 开关语义
- `IPRULES=0` 时，IP 规则引擎必须做到 zero‑cost disable：热路径不做 snapshot load/lookup。
- 规则级 disable 统一使用 `enabled=0`：其语义同样必须是 zero-cost/inert，而不是通过 `enforce=0` 间接表达。
- 规则定义与 `IPRULES` 全局开关应支持重启恢复；但 per-rule runtime stats 仍保持 since-boot、不跨重启恢复。
- `RESETALL` 必须同时清空规则持久化状态、内存快照以及下一次分配用的 `ruleId` 计数器；其后新建规则从初始 `ruleId = 0` 重新开始。
- `ip-leak` 相关功能当前不纳入本 change 的控制面与验收范围。

---

## 5. 已决定：实现基线（所有细节必须与此一致）

1) **Snapshot 模型**：immutable snapshot + atomic publish  
`atomic<shared_ptr<const EngineSnapshot>>`；控制面编译新快照并一次性发布；热路径只读查询。active snapshot 只编译 `enabled=1` 的规则；`enabled=0` 的规则留在控制面视图中，但不得进入 matcher。现有仓库里 `DomainList` 的聚合快照发布与 `PacketManager::ifaceBit()` 的只读快照读取，已经证明这类模式可直接复用于 classifier snapshot；但它们不替代前置 exact cache。

2) **前置加速层**：per-thread exact‑decision cache  
IP 规则引擎在 classifier 前必须有一层固定大小、线程本地（per-thread）的 exact cache；其 key 为 `PacketKeyV4`，entry 绑定 `rulesEpoch`。cache 允许缓存 `NoMatch`（negative cache），以避免大量不命中流量重复落入 classifier。该层只缓存“IP 规则引擎结果”，不缓存整个系统最终 verdict。

3) **分类器路线**：OVS 风格 mask‑subtable classifier  
按 `MaskSig`（字段 mask 形状）分子表；`UidView` 内 subtables 按 `subtable.maxPriority` 降序；lookup 顺序扫描并用 `maxPriority` 早停。

4) **端口 range**：bucket 内 predicate 扫描（不做展开）  
range 规则进入 bucket 的 `rangeCandidates`（按 priority 降序）；lookup 线性扫描直到首个命中；必须有硬上限保护最坏耗时。

5) **Preflight（复杂度预检）**：推荐告警 + 硬上限拒绝  
至少输出并校验：`rulesTotal/rangeRulesTotal/subtablesTotal/maxSubtablesPerUid/maxRangeRulesPerBucket`（可选内存估算）。其中 active complexity 仅统计 `enabled=1` 的规则。  
超推荐阈值：允许 apply 但给 warning；超硬上限：拒绝 apply（`NOK` + report）。

6) **`NFQA_CT` / conntrack 立场**：不是当前引擎前提  
当前 change 的 correctness、可解释性与性能基线，不得建立在 `NFQA_CT` 可用、某个 Android 内核配置已开启、或用户态额外实现一套 full conntrack/多协议 flow tracking 之上；这些若未来引入，只能作为独立收敛的增强项。

7) **zero‑cost disable**：`IPRULES=0` 时热路径不得做任何 snapshot load/lookup。

---

## 6. 明确延后/非目标（避免误当结论）

- `ip-leak` 与 IP 规则的合流策略、启用时机、控制面形态：推迟到最终融合阶段再决定。
- 域名系统独立开关（DOMAINPOLICY/DOMAINMAP）与 DNS `getips` 行为：推迟到最终融合阶段再决定。
- IPv6 的新规则语义：后置。
- 不把 `NFQA_CT`、内核 conntrack 元数据暴露，或自研 full flow tracker 作为当前 change 的前置条件；相关能力若未来用于 flow observability 或状态语义，另开议题收敛。
- 不实现全局 checkpoint/rollback；safety‑mode 仅限规则引擎内 `enforce/log`。
- 不在 P0/P1 强行重构域名系统内部（DomainList/自定义名单与规则链保持原样）。

---

## 7. 与原始讨论摘录的差异/澄清（以权威入口为准）

1) **would‑match 不使用独立 reasonId**  
早期讨论中出现过 `IPRULE_WOULD_BLOCK` 一类表述；当前契约为 `wouldRuleId + wouldDrop=1`，`reasonId` 始终解释实际 verdict（见 `openspec/changes/add-pktstream-observability/`）。

2) **reasonId 命名以 PKTSTREAM change 为准**  
统一使用 `IP_RULE_ALLOW/IP_RULE_BLOCK`（而非 `IPRULE_*` 等变体）。

3) **端口 range 走 predicate 扫描 + 硬上限**  
讨论中曾出现“编译期展开”的备选；当前确定不展开，避免 expanded‑entries 爆炸（见 `openspec/changes/add-app-ip-l3l4-rules-engine/design.md`）。

4) **早期出现过的 `POLICY.ORDER` / ip-leak 覆盖讨论，当前不作为现行结论**  
这部分已重新拍板为 TBD；当前 change 先完成主规则引擎，`ip-leak` 相关部分后续再单独收敛。

5) **当前缺失的一环是 exact cache，不是先补 full flow tracking**  
本轮已明确：v1 先补的是 `PacketKeyV4 + per-thread exact-decision cache + classifier snapshot` 这一前后两层结构；`NFQA_CT` 或自研状态跟踪不作为当前语义与性能成立的前提。
