# Domain + IP Fusion：方案挑刺（临时审核意见）

更新时间：2026-04-17  
状态：非规范性（挑刺用；用于帮我们“刻意找茬/去复杂化/防过度设计”；不等于最终裁决）

> 说明：
> - 本文件刻意“唱反调”：优先提出可能的缺陷、过度设计点、落地风险与替代方案。
> - 它不负责给出最终决定；最终决定仍以本目录的“单一真相”文档为准（尤其是 `CONTROL_PROTOCOL_VNEXT.md`、`OBSERVABILITY_WORKING_DECISIONS.md`、`IPRULES_APPLY_CONTRACT.md`）。
> - 文中出现 “建议撤销/改回/更简化” 的点，可能与当前已确认裁决相冲突——这是故意的：目的是把潜在问题提前摆在台面上，避免实现后才发现“当初不该这么定”。

---

## 0. 一句话结论（先把最刺耳的说出来）

当前融合方案的主方向是对的（“严格可解析 + 可解释 + 不靠猜 + 不在热路径做 I/O”），但存在三类高风险：

1) **协议/语法层的“半结构化”（已大幅缓解）**：这条风险在 2026-04-17 已通过方案 D（netstring + JSON envelope）基本消除；但仍需关注 `maxFrameBytes`、strict-unknown、以及“必须配套 CLI/工具”的工程边界，否则容易在落地阶段重新长出隐式规则。
2) **`tracked` 的语义膨胀 + 持久化**：这是典型“升级后隐式变重”的坑，最容易引发线上性能问题与用户困惑（且前端提示很可能覆盖不到“升级前已 tracked=true”的用户）。
3) **“为了消歧”引入的规则过多**：`<pkg> <userId>` 简写规则、裸 `USER` 白名单、dual-form 命令关键字化、one-streamType-per-connection……每一条单独都合理，但叠起来会让协议变得“学不会/难实现/难测试”。

---

## 0.1 vNext Control（不含 stream）“减法”方案（给你选 A/B/C）

> 目标：把当前 vNext 那堆规则压缩成“更少的规则、更少的例外、更少的白名单”。  
> 前提：本段**只讨论 vNext control request/response**；stream/observability 的订阅协议另开讨论（不要把 stream 的复杂度算到 control 里）。
>
> 下面 3 个方案都满足：严格可解析、严格拒绝、结构化错误、可观测性可回溯、且不要求兼容 legacy 语法。

### 方案 A（推荐）：NDJSON framing + 请求也用 JSON（彻底取消 token 语法）

- **framing**：一行一个 JSON object（request/response 都是 NDJSON）。
- **请求**：固定最小 schema（无 JSON‑RPC；无 Content‑Length）：

```json
{"cmd":"BLACKLIST.ADD","args":{"scope":"app","uid":10123,"domain":"example.com"}}
```

- **响应**：固定 envelope（让客户端永远只写一种 parser）：

```json
{"ok":true,"result":...}
{"ok":true}
{"ok":false,"error":{"code":"...","message":"...","hint":"...","candidates":[...]}}
```

优点：
- 直接砍掉：`<pkg> <userId>` 简写规则、裸 `USER` 白名单、dual-form token 消歧规则、trailing token 规则……
- “按 schema 严格拒绝”比“按 token 规则集严格拒绝”更容易收敛：规则更少、测试更少

缺点：
- 人肉用 `socat` 交互会变得更像“发 JSON”而不是敲命令（但可以用一个小 CLI 做翻译）
- 仍有“单行过大”的潜在限制（需要 `maxLineBytes` + 超限错误）
- 需要引入（或自写）JSON parser（但你们本来就为了 `IPRULES.APPLY` 迟早要做）

### 方案 B（折中）：命令名 + 行尾 JSON（人肉更好敲；仍然没有 token 语法树）

- **请求**：第一段是命令名，其余整段当作 JSON（不解析 token）：

```text
BLACKLIST.ADD {"scope":"app","uid":10123,"domain":"example.com"}
```

- **响应**：同方案 A 的 envelope。

优点：
- 比方案 A 更“像命令”，调试时更顺手
- 后端 parsing 更简单：split 一次，后面全交给 JSON parser

缺点：
- 仍需要 JSON parser
- 仍有单行上限（同 A）

### 方案 C（最小侵入）：命令 + `key=value`（只在“必须结构化的地方”用 JSON）

- **请求**：仍是文本命令，但参数只允许显式命名（没有 positional selector）：

```text
BLACKLIST.ADD scope=app uid=10123 domain=example.com
BLACKLIST.ADD scope=device domain=example.com
APP.UID userId=10
```

- **遇到需要大 payload 的命令**（例如 apply），才用 `--` 把行尾 JSON 托管出去：

```text
IPRULES.APPLY uid=10123 -- {"rules":[...]}
```

优点：
- 最保留“手敲命令”的体验
- 可以在不引入“全量 JSON request”前提下，砍掉大部分歧义规则（因为参数命名后就不需要推断语法树）

缺点：
- 仍然会有“每条命令支持哪些 key”的维护成本（但比 “token 规则+白名单”好很多）
- 要非常克制：不允许引入第二套“神奇简写”，否则又回到复杂化

### 方案 D（更像“C/C++ 世界的朴素最佳实践”）：Netstrings framing + JSON payload

> 关键点：把“分帧”从“换行/一行”里抽离出来，用最简单的 length‑delimited framing。

- **framing**：netstring：`<len>:<payload>,`
  - 任何 bytes 都允许（包括 `\n`/`\0`），因为边界由 `len` 决定
  - 可以在读 payload 前先做 `maxBytes` 上限检查（避免 OOM/DoS）
- **payload**：UTF‑8 JSON object（建议固定 envelope 与 schema；同 A）

示例（写出来看就懂）：

```text
27:{"cmd":"HELLO","args":{}},
```

为什么“不适合直接 socat 手敲”：
- `len` 必须是 **payload 的 byte 数**；你每改一个字符、一个空格、一个转义，`len` 都要重新算
  - `len` 偏大：服务端会继续等更多 bytes（看起来像“卡住/没响应”）
  - `len` 偏小：服务端会在错误边界处读到“不是逗号/不是完整 JSON”，直接报错并可能断连
- `socat` 的交互习惯是“敲一行按回车”，但 netstring 的终止符是 **`,`** 不是 `\n`：
  - 你回车带来的 `\n` 会变成“下一条消息的开头”（而 netstring 规范要求下一条以数字开头），除非我们额外定义“允许跳过空白”
- 所以 netstring 更适合：用一个小工具/脚本计算长度并封装 framing，然后把 JSON 打印给你看（仍然可以很方便调试，只是不靠手敲裸字节）

优点：
- 直接消灭 “one-line response”/“禁止 pretty” 这类被 framing 绑架出来的规则
- 也消灭 “JSON 里不能出现 raw newline” 这种 NDJSON 的硬约束（因为 framing 不靠 `\n`）
- 解析/实现非常小（netstring 规格甚至自带极短的 C sample code）

缺点：
- 人肉调试更不友好（需要算 `len`；必须靠小工具/CLI）
- payload 仍然需要 JSON parser（但你们无论如何都躲不开）

---

## 0.2 如果采用方案 D：好处 / 坏处 / 对当前 vNext 方案的影响

> 本节只讨论 vNext control（不含 stream）。

### 0.2.1 好处（为什么它能“把方案缩回去”）

1) **协议层规则会显著变少（这就是最大收益）**
- 现在 vNext 的复杂度，很大一部分来自“token 语法 + NDJSON 分帧”叠加后不得不补的规则：
  - `<pkg> <userId>` 简写到底允许哪些命令（白名单）
  - 裸 `USER <userId>` 到底允许哪些命令（白名单）
  - dual-form 命令如何消歧（APP/DOMAIN/RULE 关键字化）
  - trailing tokens 一律报错（否则 silent ignore）
  - “one-line response”/禁止 pretty/禁止 raw newline（否则分帧坏）
- 方案 D 直接把“分帧”抽出来，且请求也不再走 token 语法树：上述大部分细则会自然消失，只剩“JSON schema 校验 + 结构化错误”。

2) **从根上解决“大 payload/大响应”与 NDJSON 的冲突**
- NDJSON 的核心限制是“每条消息必须是一行”；所以要么你强行约束所有响应必须单行紧凑、要么你引入分页/截断/多条 done marker，最终又长出很多规则。
- 方案 D 的 framing 不靠换行，所以响应既可以 compact，也可以 pretty（哪怕多行），也可以自然变大（只要有 `maxBytes` 上限）。

3) **更容易做“强边界 + 强上限”（工程上更稳）**
- 解析流程天然是：先读长度 → 先检查 `maxBytes` → 再读 payload → 再 parse JSON。
- 这比“读到换行/NUL/超时”更容易写成可证明不会 OOM/不会无界增长的代码路径。

4) **更容易让 server 做到“实现与调试互不污染”**
- 你们现在为了 NDJSON 不被破坏，必须约束 pretty 与字符串换行等输出细节；这会把大量“调试便利性”变成协议层约束。
- 方案 D 下，wire 不怕换行；是否 pretty 变成纯“客户端/工具选择”，协议本身不必承诺禁止它。

5) **未来兼容扩展更自然（不靠再发明 token 规则）**
- 新增命令/新增参数只是在 JSON schema 里加字段；旧客户端按“unknown field ignore/strict reject”策略即可（你们可以选其一并写死）。
- 这比每次新增都要思考“token 的位置参数是否会与旧语法冲突”简单很多。

---

### 0.2.2 坏处（真实代价，不能粉饰）

1) **必须有 CLI/小工具（但这是可控代价）**
- 不再适合“裸 socat 手敲”，因为 netstring 需要算 `len`，且终止符是 `,` 不是回车。
- 解决方式就是提供一个很小的 `sucre-snort-ctl`（或同名脚本）：
  - 输入：人类友好（甚至继续支持 legacy 的 token 命令作为“前端语法糖”）
  - 输出：帮你打包成 netstring + JSON，并把响应解包/pretty

2) **需要 JSON parser（你们现在其实也已经绕不开）**
- 当前 vNext 已经引入 `IPRULES.APPLY` 行尾 JSON；一旦要严格校验/转义/大 payload，你迟早要上 JSON parser。
- 方案 D 的差别只是：把“JSON parser 的必要性”提到最前面承认，而不是继续在 token 语法上打补丁。

3) **抓包/日志直读会变差**
- NDJSON 的优势是“`tail -f` 直接能看”；netstring 的 payload 需要先解包。
- 但考虑到你们是本项目自控前端/自控脚本，且你也接受 CLI，这个代价通常可接受。

4) **要定一套“版本/兼容策略”**
- 以前 token 命令靠“人类直觉”迁移；JSON schema 需要更明确的兼容策略（新增字段可否忽略？未知 cmd 何种错误？）。
- 这不是大问题，但必须写清楚，否则实现阶段会各写各的。

---

### 0.2.3 对当前 vNext 方案的影响（哪些会消失，哪些会保留）

把当前 vNext 文档里“最重的细则”拆成三类看：

**A) 会被方案 D 直接消灭的复杂度（建议删掉而不是迁就）**
- token 语法树相关：
  - D1 `<pkg> <userId>` 简写规则（以及“哪些命令允许”的限制）
  - D2/D30/2.32 裸 `USER <userId>` 白名单
  - D16 dual-form 命令关键字化（`APP/DOMAIN/RULE`）——会被 JSON `args.scope` 取代
  - 2.11 trailing tokens / mutate silent no-op 这些“token parser 防御性规则”
- NDJSON 分帧强绑定出来的规则：
  - “每请求仅一行响应（one-line response）”
  - “禁止 pretty”
  - “字符串必须把 newline 编成 `\\n`（否则分帧坏）”

**B) 仍然需要保留的设计（与 framing/语法无关）**
- D3：歧义严格拒绝 + `candidates[]` + structured errors（只是载体从 token 输出变成 JSON response）
- 错误码最小枚举（2.25‑A / D37）
- selector 的核心语义（per‑UID、同包多 user 的歧义拒绝、candidates 升序等）——只是从“解析 token”变成“校验 JSON fields”
- 你们的“legacy endpoint 保留→vNext 稳定判据→删除 60606”的迁移策略

**C) 需要改写但可以“更短更清晰”的部分**
- `CONTROL_PROTOCOL_VNEXT.md` 已按方案 D 重写：从“token 命令 + NDJSON”收敛为 “netstring + JSON request/response”。
- `IPRULES_APPLY_CONTRACT.md` 大部分可保留（规则语义/冲突/回显/稳定性都不变），但：
  - `IPRULES.APPLY` 不再是“特殊行尾 JSON”命令；它只是普通 `cmd:"IPRULES.APPLY"` 的 JSON args。
  - “maxBytes/超限错误”从“单行长度限制”变成“netstring frame 上限”。
- `HELLO`/版本探测仍然保留，但建议把 `framing="netstring"` 写进响应，避免未来又出现第二种 framing。

---

### 0.2.4 对实现代码的影响（以你们现代码为基线）

这里给一个“改动面现实评估”（不是任务拆分，只是帮你判断会不会太大）：

- `SocketIO`：当前写出会追加 NUL；vNext 需要一条“不追加 NUL、直接写 bytes”的路径（可以新类，也可以给 `SocketIO` 增加模式）。
- `Control` 主循环：当前是 `read()`→按 NUL 分帧→token 解析→`OK/NOK`；vNext 会变成：
  - 读 netstring header（数字到 `:`）→读 N bytes payload→读 `,`
  - parse JSON → dispatch → build JSON response → wrap netstring → write
- 命令 handler：可以保留“命令名体系”，但参数解析从 `std::stringstream` 读取 token 改成读 JSON fields。
  - 你们现在为了解决歧义写了很多 parser 规则；方案 D 下这些规则基本都可以删掉（参数变成显式字段）。
- CLI：新增一个很小的工具，负责：
  - 连接 socket/tcp（复用现有地址体系）
  - 打包/解包 netstring
  - 输出 pretty JSON
  - （可选）提供 token 兼容输入作为语法糖：把 `BLACKLIST.ADD APP ...` 翻译成 JSON（方便开发者迁移）

---

## 0.3 方案 D 的最小协议草案（只写 10 个核心命令族）

> 目的：给你一个“足够具体、能实现、但规则极少”的 vNext control 草案。  
> 范围：只讨论 control request/response；不含 stream。

### 0.3.1 Wire framing（netstring）

- 一条消息是一个 netstring：`<len>:<payload>,`
  - `<len>`：十进制数字串（ASCII digits），给出 `<payload>` 的 **byte length**
  - 禁止前导 0（除非 `<payload>` 为空：`0:,`）
  - `<payload>`：任意 bytes；本协议要求其为 UTF‑8 JSON（见下）
- 建议 server 暴露硬上限 `maxFrameBytes`（例如 256KiB/1MiB；具体值实现时再定），超限直接返回结构化错误或断连（避免 OOM/DoS）。

### 0.3.2 Payload（JSON envelope）

**Request（client → server）**

```json
{"id":1,"cmd":"BLOCK","args":{}}
```

- `id`：u32（客户端生成；用于把响应与请求对齐）
- `cmd`：string（命令名；建议继续沿用 legacy 名字体系，便于迁移）
- `args`：object（可空 `{}`；不允许 array/string/number 顶层 args，避免歧义）

**Response（server → client）**

成功（可带结果）：

```json
{"id":1,"ok":true,"result":{...}}
```

成功（仅 ack）：

```json
{"id":1,"ok":true}
```

失败：

```json
{"id":1,"ok":false,"error":{"code":"SYNTAX_ERROR","message":"...","hint":"...","candidates":[...]}}
```

规则（尽量少，但必须写死）：
- 顶层 `ok` 永远是 boolean；失败必须有 `error`；成功禁止出现 `error` key（保留字）。
- `error.code` 复用你们已锁的最小枚举（`SYNTAX_ERROR/MISSING_ARGUMENT/INVALID_ARGUMENT/...`）。
- **unknown field 策略**（二选一，建议先选严格）：  
  A) 严格：request 顶层出现未知 key → `SYNTAX_ERROR`  
  B) 宽松：忽略未知 key（更利于向前兼容，但更难排障）

裁决（你确认，2026-04-17）：选择 A（严格）。

### 0.3.3 共同类型（避免再生“裸 USER 白名单/简写规则”）

**App selector（仅在需要“选 app”时出现）**

```json
{"uid":10123}
```

或

```json
{"pkg":"com.example","userId":0}
```

约束：
- 二选一：要么提供 `uid`，要么提供 `pkg+userId`；禁止混用
- resolve 规则与 D3 保持一致：不存在/歧义 → 结构化错误（`SELECTOR_NOT_FOUND/SELECTOR_AMBIGUOUS` + `candidates[]`）

**Scope**
- `scope="device" | "app"`（替代 dual-form token 的推断）

---

### 0.3.4 10 个核心命令族（只列最小 args/result；其余命令照此套路扩展）

#### 1) `HELLO`（协议探测/能力）

request：

```json
{"id":1,"cmd":"HELLO","args":{}}
```

response（建议）：

```json
{"id":1,"ok":true,"result":{"protocol":"control-vnext","protocolVersion":4,"framing":"netstring","maxFrameBytes":123456}}
```

#### 2) `PASSWORD` / `PASSSTATE`（密码相关设置；非鉴权协议）

> 注：现代码里的 `PASSWORD/PASSSTATE` 是设置项读写，不参与权限校验。  
> 如果未来要做真正的 control 鉴权，建议另起 `AUTH.*` 命令族，避免把“设置项”与“连接鉴权”混在一起。

request（示例）：

```json
{"id":2,"cmd":"PASSWORD","args":{}}
{"id":3,"cmd":"PASSWORD","args":{"password":"..."}}
{"id":4,"cmd":"PASSSTATE","args":{}}
{"id":5,"cmd":"PASSSTATE","args":{"passState":0}}
```

response：`{"id":...,"ok":true,"result":...}` 或 `{"id":...,"ok":true}`

#### 3) `QUIT`（优雅断开）

request：`{"id":3,"cmd":"QUIT","args":{}}`  
response：`{"id":3,"ok":true}`（server 随后 close）

#### 4) `BLOCK`（读取/设置总开关）

- GET：省略 `enabled`
- SET：提供 `enabled`（`0|1`）

request：

```json
{"id":4,"cmd":"BLOCK","args":{}}
{"id":5,"cmd":"BLOCK","args":{"enabled":1}}
```

response（建议 GET 返回当前状态）：

```json
{"id":4,"ok":true,"result":{"enabled":1}}
{"id":5,"ok":true,"result":{"enabled":1}}
```

#### 5) `RESETALL`（回到干净基线）

request：`{"id":6,"cmd":"RESETALL","args":{}}`  
response：`{"id":6,"ok":true}`

#### 6) `APP.UID` / `APP.NAME`（枚举 app）

说明：这两条属于 legacy 历史包袱；如果你愿意更“优雅”，可以在 vNext 直接合并为 `APPS.LIST`（一次返回 `{uid,userId,app,allNames?}` 列表），但这里先按兼容理解保留。

request（带可选 userId filter）：

```json
{"id":7,"cmd":"APP.UID","args":{}}
{"id":8,"cmd":"APP.UID","args":{"userId":10}}
```

response（建议统一返回 objects，别再返回裸数组/裸字符串）：

```json
{"id":7,"ok":true,"result":{"apps":[{"uid":10123,"userId":0,"app":"com.example"}]}}
```

#### 7) `BLACKLIST.*` / `WHITELIST.*`（自定义域名名单）

关键点：不再靠 token 消歧；一律显式 `scope` +（可选）`selector`。

示例：

```json
{"id":10,"cmd":"BLACKLIST.ADD","args":{"scope":"device","domain":"example.com"}}
{"id":11,"cmd":"BLACKLIST.ADD","args":{"scope":"app","selector":{"uid":10123},"domain":"example.com"}}
{"id":12,"cmd":"BLACKLIST.PRINT","args":{"scope":"device"}}
{"id":13,"cmd":"BLACKLIST.CLEAR","args":{"scope":"app","selector":{"pkg":"com.example","userId":0}}}
```

#### 8) `BLACKRULES.*` / `WHITERULES.*`（自定义 ruleId 名单）

同上：显式 `scope` +（可选）`selector`，避免 token 语法树。

```json
{"id":20,"cmd":"BLACKRULES.ADD","args":{"scope":"device","ruleId":123}}
{"id":21,"cmd":"BLACKRULES.ADD","args":{"scope":"app","selector":{"uid":10123},"ruleId":123}}
```

#### 9) `IPRULES.APPLY`（原子 replace，下发 ruleset）

request（直接把 `IPRULES_APPLY_CONTRACT.md` 的 request JSON 放到 args 里）：

```json
{"id":30,"cmd":"IPRULES.APPLY","args":{"uid":10123,"rules":[...]}}
```

response：成功时回传 `clientRuleId->ruleId->matchKey` 映射（保持你们已锁的契约）。

#### 10) `METRICS.*`（常态 metrics）

先给最小集合（其余照套路加）：

```json
{"id":40,"cmd":"METRICS.REASONS","args":{}}
{"id":41,"cmd":"METRICS.DOMAIN.SOURCES","args":{"scope":"device"}}
{"id":42,"cmd":"METRICS.DOMAIN.SOURCES","args":{"scope":"app","selector":{"uid":10123}}}
```

---

### 0.3.5 采用 D 后，原 vNext 文档里“可以直接删掉”的规则清单（便于你核对）

- `<pkg> <userId>` 简写允许/禁止与“哪些命令允许”的白名单
- 裸 `USER <userId>` 白名单
- dual-form 命令的 token 消歧规则（APP/DOMAIN/RULE）
- trailing tokens 相关的 parser 规则（因为不再有 token）
- one-line response / 禁止 pretty / “字符串换行必须转义” 等分帧绑架出来的输出规则

（保留不变的：D3 结构化错误 + candidates、错误码枚举、selector 语义、legacy endpoint 迁移判据。）

---

## 1. 最高优先级挑刺（建议先讨论这 7 条）

### 1.1 `tracked`：持久化 + 语义变重（升级风险）

**现状/设计**  
- 已决定：`tracked` 默认 false、且持久化；并且 tracked 的含义已经从“轻量状态”扩展到可能包含更重的统计/延迟等（并要求前端提示性能影响）。

**挑刺点**  
- 你反馈：更重的统计/延迟你们实测并不会造成“重大性能影响”，但确实会给每个包引入一点额外开销；且**前端必须明确提示**这是强要求。  
- 即便如此，升级路径里“旧版本落盘的 `tracked=true`”仍可能在新版本里自动变成“开启了更广义的 tracked”，用户未主动确认、也未看到提示——风险更多在 **升级/UX**，而不在纯性能本身。

**更保守的替代（建议至少在文档里留一个兜底策略）**  
A) 引入 `trackedSchemaVersion`/migrate：旧 tracked 值在升级后先降级为 “legacyTracked”（仅启用旧语义），需要用户在 UI 里再次确认才进入“重 tracked”。  
B) 把 tracked 拆成两级：`tracked`（轻量、可持久化）与 `perfTracked`（重、默认关、可持久化、强提示）。  
C) 如果坚持单一 tracked：那就必须在 daemon 启动时记录 “tracked=true 的 app 数量/uid 列表（截断）” 并强提示前端（让前端在第一次连接 vNext 时能告知用户“你有 N 个 app 处于 tracked 状态”）。

---

### 1.2 “one-line response per request” 可能是过度约束（大输出/大 payload 风险）

**现状/设计**  
- vNext 除 streams 外：每请求“必须且仅能”输出一行 NDJSON。

**挑刺点**  
- 这会把“输出规模问题”从网络层推回到内存/构造层：一旦某个命令需要返回很大的数组/对象（例如大量 app 列表、大量规则、未来更多 metrics 维度），后端要么构造巨型 JSON（高峰内存/延迟），要么被迫引入更多“分页/限制”细节，最终又是一堆规则。

**更简化的替代思路**  
A) 保留 NDJSON，但允许“多行 response”（每行仍是 JSON），并用一个极简 envelope：  
   - `{"type":"reply","more":true,...}` / `{"type":"reply","more":false,...}`  
   - 或者直接 `{"type":"item",...}` + 末尾 `{"type":"done"}`  
   这样不必引入 requestId，也能让大输出自然流式发送。  
B) 如果坚持 one-line：建议至少锁一个 `maxResponseBytes`，并在超限时返回结构化错误（含 `maxBytes`），避免 silent truncation。

---

### 1.3 vNext 仍保留 token 命令语法：对“严格拒绝”是双刃剑

**现状/设计**  
- 请求仍是 legacy 风格 token；只有 `IPRULES.APPLY` 引入“行尾 JSON”。

**挑刺点**  
- token 语法的“歧义/吞 token/回退”的坑非常多，你们已经用 D3/D16/D30/D31 等在补洞了，但这意味着：**协议的复杂度没有消失，只是变成了越来越多的规则**。

**更简化的替代思路**  
A) 如果 vNext 真的要“甩包袱”：考虑把“所有 mutate”改成 JSON request（哪怕只改 mutate，query 仍 token）。  
B) 或者至少定义一个统一规则：凡是需要结构化参数/可扩展 payload 的命令都采用 `CMD <json>`（行尾 JSON），避免未来再发明第二个“特殊命令例外”。

---

### 1.4 dual-form 命令关键字化：可能“为了消歧引入 2 套 API”

**现状/设计**  
- `BLACKLIST/WHITELIST/BLACKRULES/WHITERULES` 改为 `APP/DOMAIN/RULE` 关键字固定语法树。

**挑刺点**  
- 这是正确但侵入性极强的 API 改动；如果 vNext 还要长期与 legacy 共存一段时间，会导致脚本/调试心智分裂（同一个概念两套写法）。

**更简化的替代思路**  
A) 接受关键字化，但同时提供 “兼容别名” 仅在 vNext 的迁移期存在（例如允许旧 form，但在 response 中返回 `hint` 提示 canonical form）。  
B) 或者保留旧 form，但要求显式分隔符（例如 `BLACKLIST.ADD @app <selector> <domain>`），尽量减少 token 规则数量。

---

### 1.5 `error` 作为顶层保留字段：需要明确“成功响应禁止出现同名字段”

**现状/设计**  
- 失败统一 `{"error":{...}}`；成功 shape 按命令各自决定（可能是 object/array/string/number）。

**挑刺点**  
- 只要有任意一个“成功响应”未来恰好需要返回 `{"error": ...}`（作为数据字段，而不是错误），就会让客户端误判。

**建议补一句最小契约（不改变任何已定设计）**  
- vNext：**成功响应顶层 object 不得包含 key `error`**（保留字）。  
- 或者统一 success envelope（`{"ok":true,"result":...}`），但这会破坏 legacy 输出风格；是否值得需要再权衡。

---

### 1.6 `JSS/JSF` 与严格 JSON：实现难点可能被低估（但这是设计层该承认的成本）

**现状/设计**  
- vNext 要求严格 JSON escape；现代码大量使用 `#define JSS(s) "\"" << s << "\""`（无转义）。

**挑刺点**  
- 这不只是“换个函数”这么简单：一旦要支持严格 escape + optional 字段省略 + bool/number 统一类型，几乎所有 print 路径都要动。  
- 如果不提前承认成本，容易在实现阶段出现“为了赶进度偷偷放宽协议约束”，最终导致 vNext 变成 “看起来 NDJSON，但其实不严格”。

**建议**  
- 文档里把“严格 JSON encoder 是 gate”写得更像不可退化契约（不满足就不叫 vNext），避免实现阶段打折。

---

### 1.7 one-streamType-per-connection：协议简单，但前端复杂度上升

**现状/设计**  
- 2.27-A：每种 streamType 独立连接；同连接只允许一种 streamType。

**挑刺点**  
- 前端实现会出现“连接池/重连/backoff/权限/握手”重复三份；如果再加 debug stream/未来扩展，会继续膨胀。  
- 这条决定的真正价值是保证 STOP ack barrier 不被其它 stream 输出打破；但如果未来我们能做“每条连接一个 writer + 每个 streamType 一个子队列”，理论上也可以在同连接里做到 barrier（只是实现更复杂）。

**建议（不是要推翻 2.27，而是给未来留后路）**  
- 明确写一句：2.27 选择是“实现复杂度 vs 前端复杂度”的交换；如果未来前端成本过高，可以引入 `STREAMS.START {"types":["dns","pkt"]...}` 的单连接复用方案（但需 requestId 或 done marker）。

---

## 2. 中优先级挑刺（不一定错，但值得再压缩）

### 2.1 `<pkg> <userId>` 简写规则：收益不大但规则很贵

**挑刺点**  
- 这个规则本身就需要再引入“哪些命令允许”的白名单；白名单再叠加裸 `USER` 白名单，会让 parser 与文档都变复杂。

**更极端的简化**  
- vNext 直接禁止 `<pkg> <userId>`，一律要求 `USER <userId>`（或更推荐直接用 `<uid>`）。  
  - 代价：迁移期需要改脚本。  
  - 收益：少一整类歧义与白名单规则。

---

### 2.2 “冻结但不删”是好策略，但要小心对外心智模型的污染

**挑刺点**  
- `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP` 冻结、vNext 不提供接口，这是正确的；但 legacy 仍存在一段时间。  
- 若前端/脚本误连 legacy，会看到这些开关仍可被设置，且落盘/restore 还会生效（即使“无作用”），这会造成“我改了但为什么没影响”的混乱。

**建议**  
- legacy 在迁移期最好也逐步加“显式 warning”（哪怕只是日志/HELP 文案），否则冻结策略对用户是不可见的。

---

### 2.3 `notice="suppressed"` 的字段可能过多（也许只要一个计数就够）

**挑刺点**  
- suppressed notice 里带 `traffic{rxp/rxb/txp/txb -> {allow,block}}` 很酷，但实现上要么在热路径累计细分 counter、要么在 writer 做额外读/聚合。  
- 如果 suppressed 的主要目的只是告诉前端“当前事件被抑制了”，那一个计数器 + hint 文案可能就够了。

**建议**  
- 把 suppressed notice 的字段最小化为：`type/notice/stream/windowMs/suppressedEvents`（或仅 `suppressed=true`），其余字段作为“可选扩展”，避免把它做成一个强契约。

---

### 2.4 `matchKey` 过长：可读性很好，但错误/映射 payload 会变大

**挑刺点**  
- `matchKey` 同时出现在冲突错误与 apply 成功映射里；规则很多时 payload 会很大。  

**建议（不破坏现有契约）**  
- 允许 `matchKeyShort`（例如 hash/缩写）作为可选字段；前端展示优先用短的，排障时再用完整 matchKey。  
- 或者在 `rules[]` 映射里允许省略 matchKey（但这会降低“apply 成功后不必 PRINT join”的价值）。

---

## 3. 低优先级挑刺（偏风格/一致性）

### 3.1 vNext 内部类型一致性：控制面 0|1 vs stream boolean

**挑刺点**  
- vNext 已经是新协议了，仍保留 control 返回 `0|1` numbers 而 stream 用 boolean，会让客户端写很多“兼容分支”。

**建议**  
- vNext 中“新命令/新字段”优先用 boolean；老命令如果要兼容旧客户端再保留 `0|1`。  
- 或者在 vNext 的 control 侧也统一 boolean（代价是前端/脚本迁移）。

---

### 3.2 `protocol` 字段类型未锁死（建议尽早选定：string vs number）

**挑刺点**  
- `protocol` 若用 string（tcp/udp/icmp）可读性好；若用 number（IPPROTO_*）更接近内核。  
- 不锁死会导致前端/测试摇摆。

**建议**  
- 倾向 string（对用户/前端更友好），并明确 `unknown` 值（避免 `"n/a"`）。

---

### 3.3 “版本号=4” 的来源与升级策略

**挑刺点**  
- `HELLO` 返回 version=4，但没有解释为何是 4（这不是问题本身，只是长期维护时会混乱）。

**建议**  
- 写一句：version=4 只是 control-vnext 的协议版本号（与 legacy 无关），未来只增不减；并在 breaking change 时 bump。

---

## 4. 我建议的“减法清单”（如果要把复杂度砍到最小）

如果你希望 vNext 真正“可学、可实现、可测试”，我建议优先砍掉/推迟以下内容（按收益/成本比排序）：

1) 禁止 `<pkg> <userId>` 简写（统一要求 `USER <userId>` 或 `<uid>`）。  
2) 保留 one-streamType-per-connection，但把 `notice="suppressed"` 的 payload 最小化。  
3) 给 response 规模加硬约束：`maxLineBytes/maxResponseBytes` + 超限结构化错误。  
4) tracked 拆成两级或做升级迁移兜底（否则它会成为最早的线上性能事故点）。  
5) 统一定义一个“行尾 JSON payload”的通用规则（避免未来出现 N 个特殊命令）。
