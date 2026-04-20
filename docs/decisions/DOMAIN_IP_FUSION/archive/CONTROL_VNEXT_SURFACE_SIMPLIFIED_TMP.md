# vNext Control：命令面重设计（简化提案，临时）

更新时间：2026-04-17  
状态：临时提案（用于“尽可能简单直接优雅”的重设计；确认后再回写 `CONTROL_COMMANDS_VNEXT.md` 作为单一真相）

> 前提：vNext 已经选定 **netstring + JSON envelope**（见 `CONTROL_PROTOCOL_VNEXT.md`），因此：
> - 不再讨论 legacy token 语法（`<pkg> USER <userId>` 等）；
> - 不再“原封不动搬运” legacy control 命令名/命令族；
> - 以“规则少、命令少、无歧义、可解释、可实现”为第一目标。

---

## 0. 设计目标（我们要的到底是什么）

1) **命令数量显著少于 legacy**：避免几十上百条命令族把 vNext 重新做成“需要背手册”的控制面。  
2) **不靠猜**：所有分支都由显式字段决定（scope/app/action），禁止“缺参回退/位置参数推断”。  
3) **更偏“API”而不是“shell 命令”**：人肉调试由 `sucre-snort-ctl` 解决；协议本身追求稳定与可测试。  
4) **易落地**：允许先做“thin mapping 到现实现”，但对外 surface 不继承历史包袱。

---

## 1. 总方向（已确认：A）

你已确认选择 **A：资源化 + 少量动词**（命令最少，schema 最清晰）。

核心想法：把命令收敛成少量“动词 + 资源”，其余都在 `args` 的显式字段里表达。

建议命令集合（第一版就够用；按“必须能力”保留，不为精简而精简）：

- `HELLO`
- `APPS.LIST`
- `CONFIG.GET` / `CONFIG.SET`（device 或 app）
- `DOMAINRULES.GET` / `DOMAINRULES.APPLY`（域名规则“规则库”；**保留 ruleId**，用于持久化/备份/可观测 join）
- `DOMAINPOLICY.GET` / `DOMAINPOLICY.APPLY`（device 或 app；引用 `ruleId`，不再靠 pattern 推断）
- `DOMAINLISTS.GET` / `DOMAINLISTS.APPLY`（domain list 执行配置 + 订阅元信息落盘；refresh 由前端驱动，daemon 不做 HTTP）
- `DOMAINLISTS.IMPORT`（向某个 listId 导入域名集合；vNext 用 JSON/可压缩 payload，不再走 `;` 拼接）
- `IPRULES.PREFLIGHT` / `IPRULES.PRINT` / `IPRULES.APPLY`
- `METRICS.GET` / `METRICS.RESET`（统一入口，替代 `METRICS.*.*` 大量分裂命令）
- `STREAM.START` / `STREAM.STOP`（`type=dns|pkt|activity`）
- `RESETALL`
- `QUIT`

优点：
- 命令族少，前端实现分支少（一个 parser + 少数 switch）
- 与 netstring framing 天然契合（大 payload 不靠“单行限制/转义技巧”）
- “device vs app”“allow vs block”等歧义都由字段显式表达

缺点：
- 需要一次性设计清楚 `CONFIG`/`DOMAINPOLICY`/`METRICS` 的 key/schema（但这是一次性成本）

---

## 2. 建议的最小 schema（只写关键钉子；A 路线）

### 2.1 `APPS.LIST`

request（示例）：

```json
{"id":1,"cmd":"APPS.LIST","args":{"query":"com.","userId":0,"limit":200}}
```

response：

```json
{"id":1,"ok":true,"result":{"apps":[{"uid":10123,"userId":0,"app":"com.example","allNames":["..."]}]}}
```

说明：
- `allNames` 仅展示，不参与 selector resolve（selector 仍以 canonical pkg 为准）。

### 2.2 `CONFIG.GET` / `CONFIG.SET`

统一用一个“key/value 配置表”，减少 `BLOCK/BLOCKMASK/BLOCKIFACE/...` 这种专用命令爆炸。

- device：`{"id":1,"cmd":"CONFIG.GET","args":{"scope":"device","keys":["block.enabled","rdns.enabled"]}}`
- app：`{"id":2,"cmd":"CONFIG.SET","args":{"scope":"app","app":{"uid":10123},"set":{"tracked":1,"domain.custom.enabled":1}}}`

建议支持的 key（第一批）：
- device：
  - `block.enabled`（0|1）
  - `iprules.enabled`（0|1）
  - `rdns.enabled`（0|1）
  - `perfmetrics.enabled`（0|1）
  - `block.mask.default`（u8）
  - `block.ifaceKindMask.default`（u8；bitmask；与现代码 `blockIface` 语义一致）
- app：
  - `tracked`（0|1；持久化；前端开启必须提示性能影响）
  - `block.mask`（u8）
  - `block.ifaceKindMask`（u8；bitmask；与现代码 `blockIface` 语义一致）
  - `domain.custom.enabled`（0|1；替代 `CUSTOMLIST.ON/OFF`）

response（统一 object；避免有的 GET 回 int、有的回 object）：

```json
{"id":1,"ok":true,"result":{"values":{"block.enabled":1,"rdns.enabled":0}}}
```

### 2.3 `DOMAINRULES.GET` / `DOMAINRULES.APPLY`（保留 ruleId；供备份/restore/可观测 join）

背景（来自现代码事实，不强行统一掉）：
- 域名规则（regex/wildcard/domain）在后端是一个全局 `RulesManager` 规则库，`CustomRules`/app custom rules 都是引用 **ruleId**（见 `src/RulesManager.cpp`、`src/CustomRules.cpp` 的 save/restore）。
- 因此 vNext 需要一个“可被前端备份/restore 的规则库接口”，不能只靠“pattern 字符串”隐式当 ID。

#### `DOMAINRULES.GET`

request：

```json
{"id":1,"cmd":"DOMAINRULES.GET","args":{}}
```

response（示例）：

```json
{"id":1,"ok":true,"result":{"rules":[{"ruleId":12,"type":"regex","pattern":"..."}]}}
```

#### `DOMAINRULES.APPLY`

语义：原子 replace（路线 1）。一次提交同时定义“规则库内容 + 哪些规则被引用”，但引用关系仍由 `DOMAINPOLICY.APPLY` 管理。

request（示例；保留 ruleId，支持 upsert；允许 `ruleId` 缺失表示新建）：

```json
{"id":2,"cmd":"DOMAINRULES.APPLY","args":{"rules":[
  {"ruleId":12,"type":"regex","pattern":"^a\\\\.example\\\\.com$"},
  {"type":"wildcard","pattern":"*.ads.example.com"}
]}}
```

response（示例；回传映射，便于前端把“新建项”拿到 ruleId）：

```json
{"id":2,"ok":true,"result":{"rules":[
  {"ruleId":12,"type":"regex","pattern":"^a\\\\.example\\\\.com$"},
  {"ruleId":13,"type":"wildcard","pattern":"*.ads.example.com"}
]}}
```

错误（最小集合）：
- `INVALID_ARGUMENT`：type/pattern 非法；或 payload 内重复（同 type+pattern 重复）
- `STATE_CONFLICT`：如果实现不允许在“被引用中”的 ruleId 上做破坏性变更（是否允许由实现阶段定）

> 注：这里“保留 ruleId”并不意味着强行跨设备复用同一 ruleId；  
> 它的作用是：1) 本机持久化/restore；2) 本机 observability join；3) 前端备份时不需要再发明第二套 ID 体系。

### 2.4 `DOMAINPOLICY.GET` / `DOMAINPOLICY.APPLY`（引用 ruleId；不再靠 pattern 推断）

目标：用“apply 一坨 policy”的方式替代：
`BLACKLIST.* / WHITELIST.* / BLACKRULES.* / WHITERULES.* / RULES.*` 的组合复杂度。

request（device）：

```json
{"id":1,"cmd":"DOMAINPOLICY.APPLY","args":{"scope":"device","policy":{
  "allow":{"domains":["a.com"],"ruleIds":[1,2]},
  "block":{"domains":["c.com"],"ruleIds":[3]}
}}}
```

request（app）：

```json
{"id":2,"cmd":"DOMAINPOLICY.APPLY","args":{"scope":"app","app":{"uid":10123},"policy":{
  "allow":{"domains":[],"ruleIds":[]},
  "block":{"domains":["example.com"],"ruleIds":[12,13]}
}}}
```

说明（关键点）：
- `ruleIds[]` 引用 `DOMAINRULES` 规则库里的 `ruleId`
- apply 是 replace 语义：一次提交覆盖旧 policy（成功则全量生效；失败不污染现有）
- 冲突/非法规则：用 `INVALID_ARGUMENT` + 可选 `conflicts[]`（但别把规则系统又做成第二个 IPRULES）

### 2.5 `METRICS.GET` / `METRICS.RESET`（统一入口：perf/traffic/reasons/domainSources/conntrack）

request：

```json
{"id":1,"cmd":"METRICS.GET","args":{"name":"traffic"}}
{"id":2,"cmd":"METRICS.GET","args":{"name":"domainSources","app":{"uid":10123}}}
```

其中 `name`（第一批）：
- `perf`
- `reasons`
- `domainSources`
- `traffic`
- `conntrack`

好处：把 `METRICS.DOMAIN.SOURCES.RESET.APP` 这种命令名爆炸收敛回 2 条命令。

### 2.6 `STREAM.START` / `STREAM.STOP`

request：

```json
{"id":1,"cmd":"STREAM.START","args":{"type":"dns","horizonSec":0,"minSize":0}}
{"id":2,"cmd":"STREAM.STOP","args":{}}
```

约束沿用已裁决：
- 每 streamType 同时只允许 1 条连接订阅
- 同一连接同一时间只允许 1 个 streamType
- `*.START` 成功：先 response，再 `notice="started"`，再 replay→realtime
- `*.STOP` response 是 ack barrier

---

## 3. 对现代码的“可落地映射”（只列大方向）

- `CONFIG.*`：映射到 `Settings` + `App` 的现有 setter/getter（`blockEnabled/blockMask/blockIface/reverseDns/ipRulesEnabled/perfmetrics/tracked/useCustomList`）。
- `DOMAINPOLICY.*`：内部可复用 `DomainManager::addCustomDomain/removeCustomDomain` 与 `CustomRules`/`RulesManager` 的编译/匹配机制；对外通过 `DOMAINRULES` 暴露/引用 `ruleId`（用于持久化/restore/可观测 join）。
- `DOMAINLISTS.*`：映射到 `BlockingListManager` + `DomainManager::{addDomainsToList,enableList,disableList,...}`，但对外命令名与 args 重新收敛。
- `METRICS.*`：映射到现有 `PerfMetrics`、`DomainPolicySourcesMetrics`、以及新增的 `TRAFFIC/CONNTRACK` counters。
- `STREAM.*`：映射到 DNS/PKT/ACTIVITY stream pipeline；连接拓扑/ack barrier 维持现裁决。

---

## 4. 需要你确认/补一句口径的点（避免“又长回去”）

你已确认：
- 方向选 A；
- “可观测性入口尽量统一”（IP+域名收敛到同一套 metrics/streams 命令面）；
- 需要保留 `ruleId`（用于持久化/备份/可观测 join）。

已确认：
1) **metrics 入口统一**：仅提供 `METRICS.GET` / `METRICS.RESET`；不再提供 `METRICS.REASONS` / `METRICS.DOMAIN.SOURCES.*` 等专用命令名。  
2) **stream 入口统一**：仅提供 `STREAM.START` / `STREAM.STOP`（通过 `args.type` 区分）；不再提供 `DNSSTREAM.* / PKTSTREAM.* / ACTIVITYSTREAM.*` 专用命令名。  
3) **域名规则保留 ruleId 且支持 upsert**：`DOMAINRULES.APPLY` 允许客户端携带 `ruleId` 做 upsert（用于 restore/备份回灌），只要最终规则库不冲突。

“不冲突”的最小口径（v1，避免实现阶段摇摆）：
- 同一次 `DOMAINRULES.APPLY` payload 内：
  - `ruleId`（若提供）必须唯一；不得重复出现；
  - `(type, pattern)` 必须唯一；不得重复出现（避免同一规则被多个 id 表达）。
- apply 的最终结果（新基线）里：
  - `ruleId` 唯一；
  - `(type, pattern)` 唯一；
  - `pattern` 必须是可打印字符串；regex 失败时应拒绝（`INVALID_ARGUMENT`），不要 silent publish empty regex。
- **参照完整性（已确认；2.2‑A）**：不得移除任何仍被 `DOMAINPOLICY`（device 或任意 app）引用的 `ruleId`。删除规则的推荐顺序是：先 `DOMAINPOLICY.APPLY` 移除引用，再 `DOMAINRULES.APPLY` 移除规则。
