# Design: App-level IPv4 L3/L4 rules engine (per-UID)

## 0. Scope
本设计仅定义“规则引擎 + 控制面 + 观测/可解释性 + 与 ip-leak 的合流策略”的落地方式，目的是支撑 P0/P1 以及后续维度扩展（例如 CT）。

明确不在本 change 里决策/实现：
- 域名系统的独立开关（DOMAINMAP/DNS getips）与其性能语义（留到最终融合阶段）。
- IPv6 新规则语义（IPv6 本期默认放行且不提示）。

## 1. Constraints (non-negotiable)
- NFQUEUE 热路径：不得新增锁、不得做磁盘/网络 IO、不得做动态分配；只允许纯计算与只读快照查询。
- 更新模型：控制面构建新快照并一次性发布（atomic publish），热路径只见旧/新之一，不存在中间态。
- 可观测性：不新增通路，仅复用 `PKTSTREAM` + 轻量聚合统计；慢消费者可能反压是已知风险点。

## 2. Terminology
- **IP rule engine**：按 `(uid, 5-tuple, ctx)` 匹配产生 `ALLOW/BLOCK` 的规则系统。
- **DomainPolicy output**：域名系统在 Packet 侧的可观测结果，本期只使用 `IP_LEAK_BLOCK`（由 `BLOCKIPLEAKS` 驱动）。
- **Combiner**：将 `IP rule engine` 结果与 `DomainPolicy output` 在 Packet 判决处合并的策略。
- **safety-mode**：规则引擎内的逐条/批次试运行：`enforce=0,log=1` 只输出 would-match，不实际 DROP。

## 3. Public control interface
### 3.1 Global switches
- `IPRULES [<0|1>]`
  - 0：规则引擎完全停用；Packet 热路径不得进行任何 snapshot load/lookup。
  - 1：启用规则引擎。

### 3.2 Combiner mode
新增命令：`POLICY.ORDER [DOMAIN_FIRST|IP_FIRST|PRIORITY]`

语义（均在 `IFACE_BLOCK` 之后执行，iface 仍 hard-drop）：
- `DOMAIN_FIRST`：先应用 `IP_LEAK_BLOCK`，若需 DROP 则直接 DROP；否则应用 IP 规则（若命中则用其 verdict）。
- `IP_FIRST`：先应用 IP 规则（命中则用其 verdict）；否则再看 `IP_LEAK_BLOCK`。
- `PRIORITY`：两边都计算候选，按统一 tie-break 选胜者：
  - IP 规则使用其 `priority`；
  - `IP_LEAK_BLOCK` 作为“域名系统的一部分”参与比较，但其 `priority` 为内部常量（不对外暴露数值）。

> 注：是否引入域名系统开关（DOMAINPOLICY/DNS getips）留 TBD，本 change 仅保证 IPRULES 的 zero-cost disable。

### 3.3 Interface enumeration
新增命令：`IFACES.PRINT`，返回对象：

```json
{"ifaces":[{"ifindex":123,"name":"tun0","kind":"vpn","type":65534}]}
```

- `kind`：`wifi|data|vpn|unmanaged`，复用 `PacketManager::ifaceBit()` 的分类语义。
- `type`：可选，来自 `/sys/class/net/<ifname>/type`，便于排障。

### 3.4 Rule management (v1)
命令族（建议先仅接受 `<uid>`，不支持包名字符串以避免歧义）：
- `IPRULES.ADD <uid> <kv...>` → 返回 `ruleId`
- `IPRULES.UPDATE <ruleId> <kv...>` → `OK|NOK`
- `IPRULES.REMOVE <ruleId>` → `OK|NOK`
- `IPRULES.ENABLE <ruleId> <0|1>` → `OK|NOK`
- `IPRULES.PRINT [UID <uid>] [RULE <ruleId>]` → JSON
- `IPRULES.PREFLIGHT` → JSON（复杂度统计与阈值）

kv 语法：每项为 `key=value` token（Control 的空格分词可直接支持），未出现字段默认为 `ANY/默认值`：
- `action=allow|block`
- `priority=<int>`（缺省：按创建顺序递增）
- `enabled=0|1`（缺省 1）
- `enforce=0|1`（缺省 1）
- `log=0|1`（缺省 0）
- `dir=in|out|any`
- `iface=wifi|data|vpn|unmanaged|any`
- `ifindex=<int>|any`
- `proto=tcp|udp|icmp|any`
- `src=any|A.B.C.D/<0..32>`
- `dst=any|A.B.C.D/<0..32>`
- `sport=any|<0..65535>|<lo>-<hi>`
- `dport=any|<0..65535>|<lo>-<hi>`
- 预留：`ct=any|...`（本期允许解析但可不参与匹配）

## 4. PacketKey & PKTSTREAM schema
### 4.1 PacketKey (IPv4)
为支持双 CIDR（src/dst）与完整 5 元组，Packet 热路径必须具备：
- `uid`
- `direction`（in/out）
- `ifindex` + `ifaceKind`
- `proto`
- `srcIp,dstIp`（IPv4）
- `srcPort,dstPort`
- 预留：`ctInfo`

### 4.2 PKTSTREAM observability contract
PKTSTREAM 的 schema（`reasonId/ruleId/wouldRuleId/wouldDrop`、`ipVersion/srcIp/dstIp` 等）由 `add-pktstream-observability` 定义。本引擎仅负责在命中时按该契约填充 `reasonId/ruleId`（enforce）与 `wouldRuleId/wouldDrop`（log-only），并保证每包最多 1 条 would-match。

## 5. Rule engine data structures
### 5.1 Snapshot model
- `std::atomic<std::shared_ptr<const EngineSnapshot>>` 持有当前只读快照。
- 控制面：基于旧快照构建新快照（含 preflight），一次性 store 发布。
- 热路径：一次 atomic load 拿到 `shared_ptr` 并只读查询。

### 5.2 Classifier: mask-subtable (OVS style)
按 `MaskSig`（字段 mask 形状）分子表：
- `UidView` 下包含多个 `Subtable`，按 `subtable.maxPriority` 降序。
- lookup：顺序扫描 subtables，计算 `MaskedKey` 并哈希查 bucket；使用 `maxPriority` 进行早停。

### 5.3 Port range support (predicate scan, no expansion)
端口 range 不做编译期拆分展开，避免子表形状爆炸：
- bucket 内维护 `rangeCandidates`（按 priority 降序）
- lookup：线性扫描直到首个命中

硬上限（偏保守，后续压测可放开）：
- `HARD_MAX_RANGE_RULES_PER_BUCKET = 64`（推荐阈值 16）

### 5.4 Deterministic match
命中唯一性 tie-break（固定）：
1) `priority`（高者胜）
2) `specificityScore`（编译期计算：prefixLen 累加 + exact bonus；仅用于同 priority）
3) `ruleId`（小者胜，保证稳定）

## 6. Preflight & limits
控制面在每次 apply/update 后输出并校验：
- `rulesTotal`
- `rangeRulesTotal`
- `subtablesTotal`
- `maxSubtablesPerUid`
- `maxRangeRulesPerBucket`
- 内存估算（可选）

阈值（先偏保守）：
- `HARD_MAX_SUBTABLES_PER_UID = 64`（推荐 32）
- `HARD_MAX_RULES_TOTAL = 5000`（推荐 1000）
- `HARD_MAX_RANGE_RULES_PER_BUCKET = 64`（推荐 16）

超推荐：允许 apply 但返回 warning；超硬上限：拒绝 apply（`NOK` + report）。

## 7. Per-rule runtime stats
为每条规则维护：
- `hitPackets/hitBytes/lastHitTsNs`
- `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`

语义：
- `hit*`：该规则作为最终 enforce 命中规则时更新（每包最多 1 条）。
- `wouldHit*`：该规则作为最终 would-match（`enforce=0, log=1`，且无 enforce 命中）规则时更新（每包最多 1 条）。

生命周期：
- since boot（进程内计数），不要求持久化；重启后归零。
- 当规则被 `UPDATE` 覆盖为新定义时，该规则的 runtime stats SHOULD 清零（避免旧命中混入新语义）。

对外输出：
- `IPRULES.PRINT` 的 rule 对象中包含 `stats` 字段（输出上述 counters）。

实现约束：
- 热路径只对“最终命中规则”和“最终 would-match 规则（若有）”做无锁原子更新（`atomic++ relaxed`）；不得新增锁/IO/分配。

## 8. Persistence & RESETALL
- 新增持久化文件（实现阶段确定具体路径，推荐在 `/data/snort/save/system/` 下新增 `iprules` 文件）。
- `RESETALL`：清空持久化记录、清空内存规则集并发布空 snapshot；重启后恢复。
- 需要通过 `Settings::_savedVersion` 做向前兼容（默认 IPRULES=0 或 1 的默认值在实现阶段明确）。

## 9. Open questions (TBD)
- 域名系统的独立开关：是否引入 `DOMAINPOLICY` / `DOMAINMAP`，以及 DNS `getips` 行为如何随开关变化。
- `PRIORITY` 模式下 `IP_LEAK_BLOCK` 的内部常量优先级具体取值与与 UI 交互的呈现方式（不对外暴露数值，仅保证语义一致）。
