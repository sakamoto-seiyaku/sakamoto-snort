# Control Commands vNext（命令目录）

更新时间：2026-04-17  
状态：已收敛（命令面单一真相；不继承 legacy 命令体系；实现/落盘到 change 另行拆分）

> - 线协议（framing / JSON envelope / error model / selector）见：`CONTROL_PROTOCOL_VNEXT.md`  
> - stream events 的字段语义见：`OBSERVABILITY_WORKING_DECISIONS.md`  
> - `IPRULES.APPLY` 契约见：`IPRULES_APPLY_CONTRACT.md`

---

## 0. 通用约定（跨命令一致）

### 0.1 Envelope

- request：`{"id":<u32>,"cmd":"...","args":{...}}`
- response：
  - success：`{"id":...,"ok":true,"result":...}` 或 `{"id":...,"ok":true}`
  - error：`{"id":...,"ok":false,"error":{...}}`

### 0.2 selector（多用户）

所有“作用于某个 app”的命令统一使用 `args.app`（二选一）：

- `{"uid":<linux_uid>}`
- `{"pkg":"<canonical_pkg>","userId":<u32>}`

> `pkg` 仅匹配 canonical `App::name()`；歧义/不存在必须结构化报错（`SELECTOR_AMBIGUOUS/SELECTOR_NOT_FOUND + candidates[]`）。

### 0.3 toggle

“配置开关/启用态”等 toggle 统一用整数 `0|1`（例如 `enabled/tracked/...`）。

### 0.4 strict reject

vNext 全局 strict：
- 未知 `cmd` → `UNSUPPORTED_COMMAND`
- request 顶层未知 key、或 `args` 未知 key → `SYNTAX_ERROR`

### 0.5 scope

需要区分 device/app 的地方统一用：

- `args.scope="device"`（不允许出现 `args.app`）
- `args.scope="app"`（必须出现 `args.app`）

### 0.6 apply（原子 replace）

所有 `*.APPLY`（包括 `DOMAINRULES.APPLY` / `DOMAINPOLICY.APPLY` / `DOMAINLISTS.APPLY` / `IPRULES.APPLY`）默认语义：
- 一次请求要么整体成功、要么整体失败（禁止部分成功）。
- 成功返回后，后续查询/判决必须看到新基线；失败不污染现有基线。

---

## 1. 命令总览（v1）

### 1.1 Meta

- `HELLO`
- `QUIT`
- `RESETALL`

### 1.2 Inventory

- `APPS.LIST`
- `IFACES.LIST`

### 1.3 Config

- `CONFIG.GET`
- `CONFIG.SET`

### 1.4 Domain（域名腿）

- `DOMAINRULES.GET`
- `DOMAINRULES.APPLY`（支持携带 `ruleId` upsert；用于 restore/备份回灌）
- `DOMAINPOLICY.GET`
- `DOMAINPOLICY.APPLY`（引用 `ruleIds[]`）
- `DOMAINLISTS.GET`（lists 配置 + 订阅元信息查询；refresh 由前端维护）
- `DOMAINLISTS.APPLY`（lists 配置 + 订阅元信息 upsert/remove）
- `DOMAINLISTS.IMPORT`（向 listId 导入域名集合；大 payload）

### 1.5 IP（IP 腿）

- `IPRULES.PREFLIGHT`
- `IPRULES.PRINT`
- `IPRULES.APPLY`

### 1.6 Observability（统一入口）

- `METRICS.GET`
- `METRICS.RESET`
- `STREAM.START`
- `STREAM.STOP`

---

## 2. 命令契约（v1）

### 2.1 `HELLO`

request：

```json
{"id":1,"cmd":"HELLO","args":{}}
```

response（最小字段集合建议）：

```json
{"id":1,"ok":true,"result":{"protocol":"control-vnext","protocolVersion":4,"framing":"netstring","maxFrameBytes":123456}}
```

### 2.2 `QUIT`

request：`{"id":1,"cmd":"QUIT","args":{}}`  
response：`{"id":1,"ok":true}`（随后 server close）。

### 2.3 `RESETALL`

request：`{"id":1,"cmd":"RESETALL","args":{}}`  
response：`{"id":1,"ok":true}`

必须清理（摘要）：
- 观测：清零 metrics、断开 stream 订阅、清空 ring/pending、重置 `tracked=false`
- 配置：重置 settings（含 block/iprules/rdns 等开关）
- 域名腿（domain）：清空 `DOMAINRULES` 规则库、清空 device/app 两层 `DOMAINPOLICY`、清空 `DOMAINLISTS` 元数据与其落盘的 domains 文件（含 enabled/disabled 文件）
- IP 腿（iprules）：清空所有 app 的 IPRULES（含 stats/epoch）、重置 iprules 引擎内部状态
- 缓存/映射：清空 DNS‑learned Domain↔IP bridge、清空 reverse‑dns 缓存（若存在）
- 遗留：删除历史遗留落盘/兼容残留（若存在；例如旧版本 save tree）

### 2.4 `APPS.LIST`

用途：
- 列出 app（device-wide）
- substring 搜索（按 canonical pkg + aliases 展示）
- 可选按 `userId` 过滤

request（示例）：

```json
{"id":1,"cmd":"APPS.LIST","args":{"query":"com.","userId":0,"limit":200}}
```

response（示例）：

```json
{"id":1,"ok":true,"result":{"apps":[{"uid":10123,"userId":0,"app":"com.example","allNames":["..."]}]}}
```

约束：
- `allNames` 仅展示，不参与 selector resolve。

### 2.5 `IFACES.LIST`

request：`{"id":1,"cmd":"IFACES.LIST","args":{}}`

response（示例）：

```json
{"id":1,"ok":true,"result":{"ifaces":[{"ifindex":1,"name":"wlan0","kind":"wifi","type":1}]}}
```

### 2.6 `CONFIG.GET` / `CONFIG.SET`

#### 2.6.1 支持的 keys（v1）

device keys：
- `block.enabled`（0|1）
- `iprules.enabled`（0|1）
- `rdns.enabled`（0|1）
- `perfmetrics.enabled`（0|1）
- `block.mask.default`（u8）
- `block.ifaceKindMask.default`（u8；bitmask；与现代码 `blockIface` 语义一致）

app keys：
- `tracked`（0|1；持久化；前端开启必须提示性能影响）
- `block.mask`（u8）
- `block.ifaceKindMask`（u8；bitmask；与现代码 `blockIface` 语义一致）
- `domain.custom.enabled`（0|1；对应现代码 `App::_useCustomList`）

值域提示（实现期强校验；避免前端“猜”）：
- `block.mask.default` / `block.mask`：必须满足现代码 `Settings::isValidAppBlockMask()`（仅允许 list bits `1|2|4|8|16|32|64` 的任意组合，允许额外包含 `customListBit=128`；并对 `reinforcedListBit=8` 自动蕴含 `standardListBit=1`）。
- `block.ifaceKindMask.default` / `block.ifaceKindMask`：bitmask；按现代码口径：
  - WiFi=1 / Data=2 / VPN=4 / Unmanaged=128（可组合）。

#### 2.6.2 `CONFIG.GET`

request（device）：

```json
{"id":1,"cmd":"CONFIG.GET","args":{"scope":"device","keys":["block.enabled","rdns.enabled"]}}
```

request（app）：

```json
{"id":2,"cmd":"CONFIG.GET","args":{"scope":"app","app":{"uid":10123},"keys":["tracked","block.mask"]}}
```

response：

```json
{"id":1,"ok":true,"result":{"values":{"block.enabled":1,"rdns.enabled":0}}}
```

#### 2.6.3 `CONFIG.SET`

request（device）：

```json
{"id":1,"cmd":"CONFIG.SET","args":{"scope":"device","set":{"block.enabled":1,"iprules.enabled":1}}}
```

request（app）：

```json
{"id":2,"cmd":"CONFIG.SET","args":{"scope":"app","app":{"uid":10123},"set":{"tracked":1,"domain.custom.enabled":1}}}
```

response：`{"id":...,"ok":true}`

错误：
- key 不支持：`INVALID_ARGUMENT`
- 值域非法：`INVALID_ARGUMENT`

### 2.7 `DOMAINRULES.GET` / `DOMAINRULES.APPLY`

背景：
- 现代码里域名规则是全局规则库（`RulesManager`），custom rules 引用 `ruleId` 并且会 save/restore（见 `src/RulesManager.cpp`、`src/CustomRules.cpp`）。
- 因此 vNext 必须保留 `ruleId`，用于：持久化/备份/restore，以及 observability join。

#### 2.7.1 `DOMAINRULES.GET`

request：`{"id":1,"cmd":"DOMAINRULES.GET","args":{}}`

response（示例）：

```json
{"id":1,"ok":true,"result":{"rules":[{"ruleId":12,"type":"regex","pattern":"..."}]}}
```

`type`（v1）：
- `domain`：按 regex 解释（不转义元字符；与现实现一致；`.` 仍是“任意字符”）。**语义上与 `regex` 等价**，主要用于表达“域名腿的规则”。
- `wildcard`：纯 glob（仅 `*`/`?` 有特殊含义；其它 regex 元字符会被转义），用于人类友好的通配表达。
- `regex`：按 regex 解释（不转义元字符；与现实现一致；`.` 仍是“任意字符”）。语义上与 `domain` 等价，建议用于“明确就是正则”的场景。

#### 2.7.2 `DOMAINRULES.APPLY`

语义：原子 replace（路线 1），允许客户端携带 `ruleId` 做 upsert（用于 restore/备份回灌）。

request（示例；`ruleId` 可选）：

```json
{"id":2,"cmd":"DOMAINRULES.APPLY","args":{"rules":[
  {"ruleId":12,"type":"regex","pattern":"^a\\\\.example\\\\.com$"},
  {"type":"wildcard","pattern":"*.ads.example.com"}
]}}
```

response（示例；回传最终基线，便于拿到新分配的 ruleId）：

```json
{"id":2,"ok":true,"result":{"rules":[
  {"ruleId":12,"type":"regex","pattern":"^a\\\\.example\\\\.com$"},
  {"ruleId":13,"type":"wildcard","pattern":"*.ads.example.com"}
]}}
```

不冲突（v1 最小口径）：
- payload 内 `ruleId`（若提供）必须唯一；
- payload 内 `(type, pattern)` 必须唯一；
- 最终基线里 `ruleId` 唯一、`(type, pattern)` 唯一；
- regex 编译失败必须拒绝（`INVALID_ARGUMENT`），不得 silent publish empty regex。
- **参照完整性（已确认；2.2‑A）**：不得移除任何仍被 `DOMAINPOLICY`（device 或任意 app）引用的 `ruleId`。  
  - 规则删除/清理的推荐顺序：先 `DOMAINPOLICY.APPLY` 移除引用 → 再 `DOMAINRULES.APPLY` 移除规则。
  - 若违反，必须整体拒绝（`INVALID_ARGUMENT`），并尽量返回结构化冲突列表（例如 `conflicts=[{"ruleId":12,"refs":[{"scope":"device"},{"scope":"app","app":{"uid":10123}}]}]`）。

### 2.8 `DOMAINPOLICY.GET` / `DOMAINPOLICY.APPLY`

作用：定义 device/app 两个 scope 下的 allow/block policy（custom domains + custom rules 引用）。

#### 2.8.1 `DOMAINPOLICY.GET`

request（device）：

```json
{"id":1,"cmd":"DOMAINPOLICY.GET","args":{"scope":"device"}}
```

request（app）：

```json
{"id":2,"cmd":"DOMAINPOLICY.GET","args":{"scope":"app","app":{"uid":10123}}}
```

response（示例）：

```json
{"id":1,"ok":true,"result":{"policy":{
  "allow":{"domains":["a.com"],"ruleIds":[1,2]},
  "block":{"domains":["b.com"],"ruleIds":[3]}
}}}
```

#### 2.8.2 `DOMAINPOLICY.APPLY`

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

约束：
- `ruleIds[]` 必须引用 `DOMAINRULES` 当前基线内存在的 ruleId；不存在 → `INVALID_ARGUMENT`（并给出 hint）。
- 同一 scope 内 allow/block 允许相交（按现代码优先级：allow wins）；不得因为相交或重复而拒绝 apply。
- **不做 canonicalization（已确认）**：`domains[]` 按原始字符串解释（大小写敏感；不保证自动 trim/lowercase/去尾点）。客户端若希望稳定命中，应自行统一输入形式（建议 lower-case 且无 trailing `.`）。
- **gating（现实现一致）**：某个 app 是否参与 device/app 两个 scope 的 custom domain policy，受 `CONFIG.SET(scope=app, set={"domain.custom.enabled":0|1})` 控制；当该开关为 0 时，该 app 的 domain 判决将直接走 `MASK_FALLBACK`（忽略 device/app 两层 custom domains/rules）。
- 判决顺序（现实现一致；用于解释“allow wins”）：
  - 当 `domain.custom.enabled=1`：app allow → app block → app allow rules → app block rules → device allow → device block → `MASK_FALLBACK`（即 `block.mask & DOMAINLISTS(block)`；其中 `DOMAINLISTS(allow)` 仅在该 fallback 内表现为 blockMask=0 的 override）。
  - 当 `domain.custom.enabled=0`：直接走 `MASK_FALLBACK`（不检查任何 custom domains/rules）。

### 2.9 `DOMAINLISTS.GET` / `DOMAINLISTS.APPLY` / `DOMAINLISTS.IMPORT`

用途：管理 domain lists 的执行配置 + 订阅元信息/状态落盘 + 导入域名集合（refresh/拉取远端内容由前端驱动；daemon 不做 HTTP 拉取；对应现代码 `BlockingListManager` + `DomainManager::{blacklist,whitelist}`）。

#### 2.9.1 listKind

- `listKind="block" | "allow"`
- `listId`：建议使用 GUID（仅允许 hex digits 与 `-`；长度 1..64），避免路径注入与实现分歧（与现代码 `DomainList::validListId()` 口径一致）。
- `mask`（u8）：必须是单 bit selector，且满足现代码 `Settings::isValidBlockingListMask()`：`1|2|4|8|16|32|64`。

mask 语义（重要）：
- `listKind="block"`：`mask` 是参与 app `block.mask` 选择的 bit（命中后最终由 `app.block.mask & domain.mask` 决定是否生效）。
- `listKind="allow"`：allow list 是 device-wide override（命中即 allow，**不参与** per-app mask 选择）；`mask` 仍必填但只作为“list 标签/链路编号”（与现代码一致）。

订阅字段（落盘于 daemon，供前端 refresh/恢复 UI 使用；**前端维护其语义**，daemon 不做远端拉取/不自动推断）：
- `url`（string）：订阅地址（daemon 不做 HTTP 拉取；仅持久化）。
- `name`（string）：展示名称（仅持久化）。
- `updatedAt`（string）：该订阅在远端的“最后更新时间/版本时间戳”（格式建议 `YYYY-MM-DD_HH:MM:SS`；由前端从远端响应推导并写入）。
- `etag`（string）：远端 ETag（由前端写入，供下一次 conditional fetch 使用）。
- `outdated`（`0|1`）：是否“远端已更新但本机尚未导入”（由前端驱动刷新流程并写入）。
- `domainsCount`（u32）：该 list 的 domains 数量（用于 UI；由前端在导入后写入，或实现侧也可在导入时维护）。

#### 2.9.2 `DOMAINLISTS.GET`

request：`{"id":1,"cmd":"DOMAINLISTS.GET","args":{}}`

response（示例）：

```json
{"id":1,"ok":true,"result":{"lists":[
  {"listId":"01234567-89ab-cdef-0123-456789abcdef","listKind":"block","mask":1,"enabled":1,
   "url":"https://example.com/blocklist.txt","name":"Example Blocklist",
   "updatedAt":"2026-04-19_12:34:56","etag":"W/\\\"abc\\\"","outdated":0,"domainsCount":1234}
]}}
```

#### 2.9.3 `DOMAINLISTS.APPLY`

语义：原子 replace（路线 1），包含 upsert + remove。

request（示例）：

```json
{"id":2,"cmd":"DOMAINLISTS.APPLY","args":{
  "upsert":[{"listId":"01234567-89ab-cdef-0123-456789abcdef","listKind":"block","mask":1,"enabled":1,
             "url":"https://example.com/blocklist.txt","name":"Example Blocklist",
             "updatedAt":"2026-04-19_12:34:56","etag":"W/\\\"abc\\\"","outdated":0,"domainsCount":1234}],
  "remove":["89abcdef-0123-4567-89ab-cdef01234567"]
}}
```

response：`{"id":2,"ok":true}`

`enabled` 语义（与现实现一致；摘要）：
- `enabled=0`：该 list 不参与域名匹配链路（从内存快照中移除；若存在 on‑disk enabled 文件，应切换为 disabled 形式）。
- `enabled=1`：该 list 参与域名匹配链路（若存在 on‑disk disabled 文件，应切换为 enabled 形式并载入/重建内存快照）。

remove 语义（摘要）：
- `remove[]` 必须同时移除：list 配置 + 该 list 的 domains 文件（enabled/disabled 两种）+ 内存快照中的该 list 条目。

`listKind` 可变性（按现代码现状；2.11‑B）：
- 允许同一个 `listId` 在 `block` 与 `allow` 之间切换（高风险；前端应显式提示/二次确认）。  
- 为保持现有域名实现不动（不引入额外“重标注/重导入”规则）：若一次 `upsert[]` 中发生 `listKind` 变更，则该条目 `mask` 必须保持不变；若同时变更 `mask` → `INVALID_ARGUMENT`（建议分两步操作：先切 kind，再改 mask）。  
- 当 `upsert[].listId` 已存在且 `upsert[].listKind` 与当前元数据不一致时：daemon 必须将该 `listId` 的 domains 集合整体迁移到新的 kind（不丢失域名集合）。  
- 随后 `DOMAINLISTS.IMPORT` 的 `listKind/mask` 校验以新元数据为准（见 2.9.4）。

#### 2.9.4 `DOMAINLISTS.IMPORT`

用途：向某个 `listId` 导入域名集合（大 payload；vNext 不再使用 `;` 拼接）。

request（示例）：

```json
{"id":3,"cmd":"DOMAINLISTS.IMPORT","args":{
  "listId":"01234567-89ab-cdef-0123-456789abcdef","listKind":"block","mask":1,"clear":1,
  "domains":["a.com","b.com"]
}}
```

response（示例）：`{"id":3,"ok":true,"result":{"imported":2}}`

约束：
- `domains[]` 只做**最小保护性校验**（保持现有域名匹配实现不动）：必须是非空字符串、长度上限（例如 `<= HOST_NAME_MAX`）、且不得包含 `\0`/换行；不做“DNS 语法合法性”校验。出现非法条目必须整体拒绝（`INVALID_ARGUMENT`），不得部分成功。
- **不做 canonicalization（已确认）**：`domains[]` 按原始字符串解释（大小写敏感；不保证自动 trim/lowercase/去尾点）。若客户端希望稳定命中/去重，应自行统一输入形式（建议 lower-case 且无 trailing `.`）。
- `listKind/mask` 仅用于一致性校验（已确认；2.10‑B）：必须与后端已存该 `listId` 的元数据一致；不一致 → `INVALID_ARGUMENT`。  
  - `listId` 不存在也必须拒绝（`INVALID_ARGUMENT`，提示先 `DOMAINLISTS.APPLY` 创建/启用该 list）。
- 实现侧需受 `maxFrameBytes` 约束；若 request frame 本身已超出 `maxFrameBytes`，按 `CONTROL_PROTOCOL_VNEXT.md` 断连策略处理（客户端应先 `HELLO` 预检查并分批导入）。
- 同时必须有命令级上限（例如 `maxImportDomains`/`maxImportBytes`）：在未超过 `maxFrameBytes` 但超出命令级上限时，必须返回结构化错误（`INVALID_ARGUMENT`），明确提示“payload 太大/请分批导入”，并尽量回显上限数值（便于前端做 chunk）。

### 2.10 `IPRULES.PREFLIGHT` / `IPRULES.PRINT` / `IPRULES.APPLY`

命令名保持 `IPRULES.*`（避免与 `DOMAINRULES` 混淆）；细节见 `IPRULES_APPLY_CONTRACT.md`。

request（示例）：

```json
{"id":1,"cmd":"IPRULES.PREFLIGHT","args":{}}
{"id":2,"cmd":"IPRULES.PRINT","args":{"app":{"uid":10123}}}
{"id":3,"cmd":"IPRULES.APPLY","args":{"app":{"uid":10123},"rules":[...]}}
```

### 2.11 `METRICS.GET` / `METRICS.RESET`

入口统一：所有 metrics 都通过这两条命令访问（域名腿与 IP 腿共用）。

request：

```json
{"id":1,"cmd":"METRICS.GET","args":{"name":"traffic"}}
{"id":2,"cmd":"METRICS.GET","args":{"name":"domainSources","app":{"uid":10123}}}
{"id":3,"cmd":"METRICS.RESET","args":{"name":"traffic","app":{"uid":10123}}}
```

`name`（v1）：
- `perf`
- `reasons`
- `domainSources`
- `traffic`
- `conntrack`

result shape：见 `OBSERVABILITY_WORKING_DECISIONS.md`（命令面只负责入口统一，不在此重复字段细节）。

reset 约束（v1）：
- 支持 reset：`perf` / `reasons` / `domainSources` / `traffic`
- `conntrack`：不提供独立 reset；仅 `RESETALL` 清零

### 2.12 `STREAM.START` / `STREAM.STOP`

入口统一：dns/pkt/activity 都通过 `STREAM.*` 访问（用 `args.type` 区分）。

request（示例）：

```json
{"id":1,"cmd":"STREAM.START","args":{"type":"dns","horizonSec":0,"minSize":0}}
{"id":2,"cmd":"STREAM.STOP","args":{}}
```

约束摘要（以 `OBSERVABILITY_WORKING_DECISIONS.md` 与 `CONTROL_PROTOCOL_VNEXT.md` 为准）：
- 每 streamType 同一时间只允许 1 条连接订阅；同一连接同一时间只允许 1 个 streamType
- `STREAM.START` 成功：先 response，再 `notice="started"`，再 replay→realtime
- `STREAM.STOP` response frame 是 ack barrier：ack 后不得再输出任何 event/notice，直到下一次 `STREAM.START`
