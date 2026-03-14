# Design: App-level IPv4 L3/L4 rules engine (per-UID)

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


## 0. Scope
本设计仅定义“规则引擎 + 控制面 + 观测/可解释性”的落地方式，目的是支撑 P0/P1 以及后续维度扩展（例如可选 CT 增强）。

明确不在本 change 里决策/实现：
- `ip-leak` 与 IP 规则的合流策略、`POLICY.ORDER`、域名系统独立开关（DOMAINMAP/DNS getips）与其性能语义（留到最终融合阶段）。
- IPv6 新规则语义（IPv6 本期默认放行且不提示）。

## 1. Constraints (non-negotiable)
- 在现状基础上，NFQUEUE 热路径不得新增锁、不得新增磁盘/网络 IO、不得新增动态分配或其他阻塞点；只允许纯计算与只读快照查询。
- 更新模型：控制面构建新快照并一次性发布（atomic publish），热路径只见旧/新之一，不存在中间态。
- 可观测性：不新增通路，仅复用 `PKTSTREAM` + 轻量聚合统计；慢消费者可能反压是已知风险点。
- 现有 `IFACE_BLOCK` 保持最高优先级 hard-drop；当前阶段不允许由 IP 规则覆盖。

## 2. Terminology
- **IP rule engine**：按 `(uid, 5-tuple, ctx)` 匹配产生 `ALLOW/BLOCK` 的规则系统。
- **safety-mode**：规则引擎内的逐条/批次试运行：仅对 `action=BLOCK` 支持 `enforce=0,log=1`，表示 would-block dry-run；命中时只输出 would-match，不实际 DROP。
- **disabled rule**：`enabled=0` 的规则；仅保留在控制面/持久化视图中，不进入 active snapshot 与热路径匹配。

## 3. Public control interface
### 3.1 Global switches
- `IPRULES [<0|1>]`
  - 0：规则引擎完全停用；Packet 热路径不得进行任何 snapshot load/lookup。
  - 1：启用规则引擎。

### 3.2 Current verdict boundary
- `IFACE_BLOCK` 保持在 IP 规则引擎之前执行，命中后直接 DROP；该预检查应尽量前移到 host/domain 等潜在慢路径之前。
- 仅当数据包未命中 `IFACE_BLOCK` 且 `IPRULES=1` 时，才进入 IP 规则引擎的 fast path；其顺序固定为 `exact-decision cache -> classifier snapshot`。
- `exact-decision cache` 只缓存 IP 规则引擎这一层的结果（`NoMatch/Allow/Block/WouldBlock`），不是整个系统最终 verdict cache；只有 `NoMatch` 才允许继续回落到 legacy/domain 路径。
- `ip-leak` / `POLICY.ORDER` 不属于本 change；当前阶段相关后端路径不作为实现与验收前提。

### 3.3 Interface enumeration
新增命令：`IFACES.PRINT`，返回对象：

```json
{"ifaces":[{"ifindex":123,"name":"tun0","kind":"vpn","type":65534}]}
```

- 顶层 shape 固定为 `{"ifaces":[...]}`；即使当前枚举失败或暂时没有可返回接口，也返回 `{"ifaces":[]}`，而不是 `NOK`。
- `kind`：`wifi|data|vpn|unmanaged`，复用 `PacketManager::ifaceBit()` 的分类语义。
- `ifindex` 与可选 `type` 在 JSON 中均使用 number。
- `type`：可选，来自 `/sys/class/net/<ifname>/type`，仅用于排障；客户端不得依赖其存在与否来定义正式语义。

### 3.4 Rule management (v1)
命令族（当前 v1 仅接受数值 `<uid>`，不支持包名字符串 selector）：
- `IPRULES.ADD <uid> <kv...>` → 返回 `ruleId`
- `IPRULES.UPDATE <ruleId> <kv...>` → `OK|NOK`
- `IPRULES.REMOVE <ruleId>` → `OK|NOK`
- `IPRULES.ENABLE <ruleId> <0|1>` → `OK|NOK`
- `IPRULES.PRINT [UID <uid>] [RULE <ruleId>]` → JSON
- `IPRULES.PREFLIGHT` → JSON（复杂度统计与阈值）

kv 语法：每项为 `key=value` token（Control 的空格分词可直接支持），当前 v1 要求的最小字段与语义如下：
- `action=allow|block`
- `priority=<int>`（`IPRULES.ADD` 当前必须显式提供；`IPRULES.UPDATE` 省略则保持原值）
- `enabled=0|1`（缺省 1）
- `enforce=0|1`（缺省 1）
- `log=0|1`（缺省 0）
- `dir=in|out|any`
- `iface=wifi|data|vpn|unmanaged|any`
- `ifindex=<int>|any`
  - 控制面输出归一化时，`IPRULES.PRINT` 使用 numeric `ifindex`；其中 `0` 表示“不限定精确 ifindex”
- `proto=tcp|udp|icmp|any`
- `src=any|A.B.C.D/<0..32>`
- `dst=any|A.B.C.D/<0..32>`
- `sport=any|<0..65535>|<lo>-<hi>`
- `dport=any|<0..65535>|<lo>-<hi>`
- `ct`：当前 v1 不接受；若传入则返回 `NOK`

`IPRULES.UPDATE` 语义（v1）：
- 当前 v1 `IPRULES.UPDATE` 采用 patch/merge：仅更新请求中提供的 key；未提供的 key MUST 保持原值（不得回落到缺省值）。
- `enabled/enforce/log` 的 `1/1/0` 缺省值仅适用于 `IPRULES.ADD`（创建时省略字段）。

字段语义（避免歧义）：
- `src/dst` 与 `sport/dport` 均指数据包 IPv4/L4 头部字段（`saddr/daddr`、TCP/UDP `source/dest`）。
- `dir=in|out` 仅表示包来自 `INPUT/OUTPUT` 链（入站/出站），不改变上述字段含义。

补充约束：
- 空规则集上的第一条规则使用初始 `ruleId = 0`；`ruleId` 在当前增量管理模型下使用从 `0` 开始的单调递增整数；`UPDATE` / `ENABLE` / `DISABLE` 不改变该规则 `ruleId`，`REMOVE` 后不复用已删除 id。
- `enabled=0` 的规则 MUST 仅保留在控制面规则集/持久化与 `IPRULES.PRINT` 中；不得进入 active snapshot、subtables、buckets、`rangeCandidates`、runtime stats 或 would-match 归因。`IPRULES.PREFLIGHT` 的复杂度统计仅统计 `enabled=1` 的 active rules。
- `enforce=0` 仅用于 `action=BLOCK, log=1` 的 would-block safety-mode；`action=ALLOW, enforce=0` 或 `enforce=0, log=0` 均返回 `NOK`。
- `RESETALL` 清空整套规则集后，后续新一轮规则集的 `ruleId` 计数器从初始值 `0` 重新开始。
- 除 `RESETALL` 这种“整套规则集清空后重开”之外，当前 change 不暴露“保留现有规则但整体重排 `ruleId`”的控制面；若未来引入该能力，应整体清空旧 stats / log 关联，并作为新的规则集 epoch 单独定义。

## 4. PacketKey, exact cache & PKTSTREAM schema
### 4.1 PacketKey (IPv4)
为支持双 CIDR（src/dst）与完整 5 元组，当前阶段只定义 `PacketKeyV4`；Packet 热路径必须具备：
- `uid`
- `direction`（in/out）
- `ifindex`
- `ifaceKind`
- `proto`
- `srcIp,dstIp`（IPv4）
- `srcPort,dstPort`

约束：
- `PacketKeyV4` 必须使用稳定的标量表示（例如 host-byte-order 的整数），避免把字节序转换散落在 cache/classifier/统计路径中。
- `PacketKeyV4` 不得纳入 `timestamp`、`len`、NFQUEUE `packet_id`、`App/Host/Domain` 指针或其他每包波动字段。
- `ifaceKind` 与 `ifindex` 在 key 中同时保留：前者承载规则语义，后者承载精确接口约束；两者都属于命中判定输入。
- `ifaceKind` 通常由 `ifindex -> ifaceBit()` 的只读快照推导得到；当系统网络栈变化导致同一 `ifindex` 的分类发生变化时，`PacketKeyV4` 也会变化并触发 cache miss——这是为保证“规则语义随接口分类变化而生效”的正确性取舍。
- 当前 v1 correctness 明确不依赖 `NFQA_CT`；`ctInfo` 不属于 v1 `PacketKeyV4` 字段集合。

### 4.2 Exact-decision cache (v1)
- exact cache 位于 classifier 之前，是 IP 规则引擎数据面的第一层。
- key 固定为 `PacketKeyV4`；entry 至少绑定 `rulesEpoch`，并缓存引擎层结果（`NoMatch/Allow/Block/WouldBlock`）及对应规则归因（至少包含 `ruleId` 或 `wouldRuleId`，而不是仅缓存内部索引）。
- cache 允许缓存 `NoMatch`（negative cache），以避免大量未命中流量重复进入 classifier。
- 该 cache 的 correctness 前提是“相同 `PacketKeyV4` + 相同 `rulesEpoch` => 相同引擎层结果”；它不是 flow tracker，也不是整个系统最终 verdict cache。
- v1 的 exact cache 必须可在不依赖 `NFQA_CT`、内核 conntrack 元数据暴露或用户态自研 full flow tracking 的前提下独立成立。

### 4.3 PKTSTREAM observability contract
PKTSTREAM 的 schema（`reasonId/ruleId/wouldRuleId/wouldDrop`、`ipVersion/srcIp/dstIp` 等）由 `add-pktstream-observability` 定义。本引擎仅负责在命中时按该契约填充 `reasonId/ruleId`（enforce）与 `wouldRuleId/wouldDrop`（would-block log-only）；would-match 仅在该包无 `enforce=1` 最终命中时输出，并保证每包最多 1 条。

约束：
- `reasonId` 始终解释实际 verdict。
- 若数据包在进入规则引擎前已被 `IFACE_BLOCK` 判定为 DROP，则本引擎不产生 `ruleId/wouldRuleId`。

## 5. Rule engine data structures
### 5.1 Snapshot model
- `std::atomic<std::shared_ptr<const EngineSnapshot>>` 持有当前只读快照。
- 控制面：基于旧快照构建新快照（含 preflight），并生成新的 `rulesEpoch`；随后一次性 store 发布。
- active snapshot 仅编译 `enabled=1` 的规则；`enabled=0` 的规则留在控制面存储/打印视图中，但对热路径表现为“该规则不存在”。
- 热路径：一次 atomic load 拿到 `shared_ptr` 并只读查询。
- 现有仓库里 `DomainList` 的聚合快照发布与 `PacketManager::ifaceBit()` 的只读快照读取，证明“atomic publish + 热路径 acquire load”的模式可直接复用于 classifier snapshot；但它们不替代前置 exact cache。

### 5.2 Exact cache model
- exact cache 必须为 per-thread（NFQUEUE worker 本地），避免把多 queue worker 重新耦合到共享锁或共享 LRU 上。
- 每个 entry 绑定 `PacketKeyV4 + rulesEpoch`；epoch 不一致时视为 miss，无需全表同步清空。
- cache miss 才回落到 classifier；classifier 给出的结果（包括 `NoMatch`）回填当前线程 cache。
- 该层只缓存 IP 规则引擎结果，不缓存整个系统最终 verdict；因此不会提前固化未来 `ip-leak`/legacy 合流语义。
- v1 不要求 cache 具备 conntrack/flow-state 语义；`NFQA_CT` 若未来可用，也只能作为增强信息，而不能成为本层成立前提。

### 5.3 Classifier: mask-subtable (OVS style)
按 `MaskSig`（字段 mask 形状）分子表：
- `UidView` 下包含多个 `Subtable`，按 `subtable.maxPriority` 降序。
- lookup：顺序扫描 subtables，计算 `MaskedKey` 并哈希查 bucket；使用 `maxPriority` 进行早停。
- classifier 是 exact cache miss path，而不是每包必经路径。

### 5.4 Port range support (predicate scan, no expansion)
端口 range 不做编译期拆分展开，避免子表形状爆炸：
- bucket 内维护 `rangeCandidates`（按 priority 降序）
- lookup：线性扫描直到首个命中

硬上限（偏保守，后续压测可放开）：
- `HARD_MAX_RANGE_RULES_PER_BUCKET = 64`（推荐阈值 16）

### 5.5 Deterministic match
命中唯一性由“`priority` + 编译后 classifier 的稳定查询路径”共同定义：
- 首先按 `priority` 选出最高优先级候选。
- 若同优先级仍存在重叠命中，则由编译后 `subtable / bucket / rangeCandidates` 的规范化组织与查询路径定义唯一胜者。
- 对同一份 active ruleset，重复编译必须得到相同的唯一胜者；实现不得依赖不稳定的容器迭代顺序。
- `ruleId` 用于标识、输出与控制面引用，不作为当前对外承诺的语义 tie-break。

实现提示（保证稳定查询路径的一种简单方式）：
- `UidView.subtables`：按 `maxPriority` 降序；若相同则按 `MaskSig` 的稳定序（例如字节序比较）排序。
- bucket 内 exact 匹配列表：按 `priority` 降序；若相同则按 `ruleId` 升序做稳定排序（`ruleId` 仅作为实现层面的稳定 tie-break，不构成对外语义承诺）。
- `rangeCandidates`：同上，确保线性扫描的“首个命中”在重复编译下稳定。

### 5.6 Would-match selection (enforce-first)
为保证 “would-match 不改变实际 verdict” 且 “每包最多 1 条 would-match”，选择逻辑必须明确为两阶段：

1) **先求 enforce 命中**：仅在 `enabled=1 && enforce=1` 的规则子集内，按 §5.5 的确定性规则选出唯一胜者；若胜者存在，则该包的引擎层结果为 `Allow/Block`，并禁止产生 would-match。  
2) **仅当无 enforce 命中**：才在 `enabled=1 && action=BLOCK && enforce=0 && log=1` 的 would-drop 规则子集内，按 §5.5 的确定性规则选出唯一胜者；若胜者存在，则引擎层结果为 `WouldBlock`（实际 verdict 仍为 ACCEPT）。  

说明：
- enforce 规则永远优先于 would-drop（即使 would-drop `priority` 更高），否则 would-drop 可能“压过”真实策略并改变实际 verdict。
- “每包最多 1 条 would-match”即由上述“子集内唯一胜者”保证；同优先级的 would-drop 重叠命中也必须通过稳定查询路径得到唯一胜者。

## 6. Preflight & limits
`IPRULES.PREFLIGHT` 的 v1 最小输出 shape 固定为顶层对象，至少包含：
- `summary`
- `limits`
- `warnings`
- `violations`

其中：
- `summary` 输出 active ruleset 的 number 统计字段，至少包含：
  - `rulesTotal`
  - `rangeRulesTotal`
  - `subtablesTotal`
  - `maxSubtablesPerUid`
  - `maxRangeRulesPerBucket`
  - 内存估算（可选）
- `limits` 固定为对象 `{ "recommended": {...}, "hard": {...} }`
- `warnings` 与 `violations` 固定为对象数组；无项时返回 `[]`
- `warnings/violations` 的每个元素至少包含：`metric:string`、`value:number`、`limit:number`、`message:string`

阈值（先偏保守）：
- `HARD_MAX_SUBTABLES_PER_UID = 64`（推荐 32）
- `HARD_MAX_RULES_TOTAL = 5000`（推荐 1000）
- `HARD_MAX_RANGE_RULES_PER_BUCKET = 64`（推荐 16）

因此 `limits` 的最小固定字段至少为：
- `limits.recommended.maxRulesTotal = 1000`
- `limits.recommended.maxSubtablesPerUid = 32`
- `limits.recommended.maxRangeRulesPerBucket = 16`
- `limits.hard.maxRulesTotal = 5000`
- `limits.hard.maxSubtablesPerUid = 64`
- `limits.hard.maxRangeRulesPerBucket = 64`

超推荐：允许 apply 但返回 warning；超硬上限：拒绝 apply（`NOK` + report）。

## 7. Per-rule runtime stats
为每条规则维护：
- `hitPackets/hitBytes/lastHitTsNs`
- `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`

语义：
- `hit*`：该规则作为最终 enforce 命中规则时更新（每包最多 1 条）。
- `wouldHit*`：该规则作为最终 would-match（`action=BLOCK, enforce=0, log=1`，且无 enforce 命中）规则时更新（每包最多 1 条）。
- `enabled=0` 的规则不得更新 `hit*`/`wouldHit*`。

生命周期：
- since boot（进程内计数），不要求持久化；重启后归零。
- 若需要跨重启保留/做长期分析，由前端周期性拉取并自行持久化；不在本 change 范围内。
- 当规则被 `UPDATE` 覆盖为新定义并生效时，该规则的 runtime stats MUST 清零（避免旧命中混入新语义）；当前不保留修改前历史 state 的兼容语义。
- 当规则从 `enabled=0` 重新切回 `enabled=1` 时，该规则的 runtime stats MUST 同样清零，避免禁用前的历史命中影响重新启用后的观察。

对外输出：
- `IPRULES.PRINT` 的 v1 最小输出 shape 固定为顶层对象 `{"rules":[...]}`；即使当前无规则、或过滤后无命中，也返回 `{"rules":[]}`。
- `rules` 数组按 `ruleId` 升序输出。
- 每个 rule 对象至少包含：`ruleId/uid/action/priority/enabled/enforce/log/dir/iface/ifindex/proto/src/dst/sport/dport/stats`。
- `ruleId/uid/priority/stats.*` 在 JSON 中使用 number；`ifindex` 也使用 number，其中 `0` 表示“不限定精确 ifindex”；`enabled/enforce/log` 在 JSON 中使用 `0|1` number，不使用 `true|false`。
- `action/dir/iface/proto` 输出规范化 string token。
- `src/dst` 输出规范化 string token：`any` 或标准 IPv4 CIDR 字符串。
- `sport/dport` 输出规范化 string token：`any`、单端口十进制字符串、或 `lo-hi`。
- `stats` 字段输出上述 counters。

实现约束：
- 热路径只对“最终命中规则”和“最终 would-match 规则（若有）”做无锁原子更新（`atomic++ relaxed`）；不得新增锁/IO/分配。

### 7.1 Suggested implementation sketch (correctness-first)
> 本节为实现建议（非对外接口承诺），目的是降低落地时的并发/一致性踩坑概率。

- **Stats 存储应独立于 snapshot（以便保留未变更规则的历史 stats）**：推荐维护控制面视图 `ruleId -> RuleState{def, enabled, statsPtr}`；编译后的 `ruleRef` 携带 `ruleId` 与热路径可直接更新的 `statsPtr`（raw pointer），并由 snapshot 持有 `shared_ptr` 以延长其生命周期。这样重编 snapshot 只会替换匹配结构，未变更规则的 stats 可自然延续。
- **UPDATE/ENABLE 的“stats 清零”以 publish 边界生效（避免 in-flight 旧 snapshot 污染新 stats）**：
  - `IPRULES.UPDATE` 生效：为该 `ruleId` 分配新的零值 `statsPtr` 并在控制面替换，再发布新 `rulesEpoch`/snapshot；旧 snapshot 仍指向旧 stats，但 `IPRULES.PRINT` 只读当前控制面视图，因此更新后立即可见清零。
  - `IPRULES.ENABLE 0→1`：同样为该 `ruleId` 分配新的零值 `statsPtr` 并发布，避免禁用前历史命中混入重新启用后的观察。
- **runtimeSlot/索引不得复用（ABA 规避）**：若实现选择使用 `runtimeSlot`（而非直接用 `ruleId`）索引 stats，则该 slot 在一次规则集生命周期内不得被新规则复用；否则并发读线程仍可能持有旧 snapshot 并更新到“复用后的新规则”。最简单的实现是令 `runtimeSlot == ruleId`，并配合 `nextRuleId` 单调递增（见持久化小节）。
- **exact-decision cache 与 stats**：cache entry 必须绑定 `rulesEpoch`，并缓存最终归因信息（至少包含 `ruleId`/`wouldRuleId`）；只有 epoch 匹配时才允许复用 cached decision 并更新对应规则 stats，避免对已失效规则集计数。`rulesEpoch` 必须在每次规则集 apply（含 `RESETALL`）时单调递增，不得在进程生命周期内回退或重置。
- **Bytes 口径**：`hitBytes/wouldHitBytes` 推荐计入“该包的全包长度”（NFQUEUE payload length / IPv4 packet bytes），与 `METRICS.REASONS` 的 bytes 口径保持一致。

## 8. Persistence & RESETALL
- 新增持久化文件（实现阶段确定具体路径；为与现有 `settings.saveRules` 等全局 saver 一致，推荐使用 `/data/snort/save/iprules` 一类的全局文件路径）。
- 持久化格式必须同时包含：rules 列表 + `nextRuleId`（下一个待分配的 `ruleId` 高水位计数器）。重启恢复时必须以该计数器恢复分配状态，避免“删除最高 ruleId 后重启导致复用已删除 id”。
- `RESETALL`：清空持久化记录、清空内存规则集并发布空 snapshot；后续重启应保持为空状态，不再恢复旧规则；同时将后续分配使用的 `ruleId` 计数器重置到初始值。
- 当前仓库尚未发版，因此本 change 不要求为既有发布版本设计迁移/兼容策略；实现阶段只需新增持久化字段，并保证当前开发期内规则定义与 `IPRULES` 全局开关的读写/恢复自洽。若未来出现已发布版本兼容需求，再以独立 change/实现决策补充迁移策略。

## 9. Open questions (TBD)
- `ip-leak` 与 IP 规则的合流策略是否恢复、何时恢复，以及是否需要 `POLICY.ORDER`。
- 域名系统的独立开关：是否引入 `DOMAINPOLICY` / `DOMAINMAP`，以及 DNS `getips` 行为如何随开关变化。
