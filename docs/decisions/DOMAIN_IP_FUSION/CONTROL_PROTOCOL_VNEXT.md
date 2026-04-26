# Control Protocol vNext（Netstrings + JSON）

更新时间：2026-04-20  
状态：已收敛（仅在 `docs/decisions/DOMAIN_IP_FUSION/` 内生效；实现与落盘到 change 另行拆分）

> 本文定义 vNext 的线协议：endpoint、framing、request/response envelope、错误模型与通用类型。  
> 命令面（有哪些 `cmd`、各自的 args/result/errors）见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`。  
> 事件字段语义（DNS/PKT/ACTIVITY）见 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`；  
> `IPRULES.APPLY` 的语义/错误 shape/回显要求见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`。

---

## 1. Endpoints 与迁移策略（已确认）

### 1.1 vNext endpoints（新增）

- Unix socket：`sucre-snort-control-vnext`
  - filesystem：`/dev/socket/sucre-snort-control-vnext`
  - abstract：`@sucre-snort-control-vnext`
- TCP：`60607`
  - 受 `inetControl()` gating（与 legacy 口径一致；`/data/snort/telnet`）
  - `inetControl()` 开启时：PacketListener 豁免 60606 + 60607（迁移期避免 control traffic 被 blocking/干扰）
  - 备注（已确认）：v1 阶段**不收敛**显式鉴权/权限模型（如 `PASSWORD/PASSSTATE`/token 等）；安全边界先依赖现有 `inetControl()` 与部署策略。`PERMISSION_DENIED` 在 v1 中仅作为**保留错误码**（reserved；见 4.1）。

### 1.2 legacy endpoints（迁移期保留，后续删除）

- legacy：`sucre-snort-control` / `60606`
  - 继续保持当前基础 wire shape（NUL terminator + `OK/NOK` + `!` pretty）
  - legacy `DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 已冻结为 no-op；实时观测使用 vNext `STREAM.START/STREAM.STOP`
- 删除判据（“vNext 稳定”）（已确认）：
  - 前端/脚本默认迁到 vNext；
  - 回归/真机基线通过；
  - 至少一个发布周期无回滚；
  - 且 App 对外发布后，连续超过 **两个小版本更新** 的用户反馈中未出现“控制平面（连接/解析/命令响应/stream）”相关问题；  
  然后关闭并删除 legacy endpoints（`sucre-snort-control` / `60606`）。

---

## 2. Wire framing：netstring（方案 D；已确认）

vNext 连接上传输的是一串 netstring：

```text
<len>:<payload>,
```

- `<len>`：十进制 ASCII digits，表示 `<payload>` 的 **byte length**
  - 禁止前导 0（除非 `0:,`）
- `<payload>`：UTF‑8 JSON **object**（顶层必须是 object）
- `,`：netstring 终止符；紧接着下一条 netstring（无额外分隔符）

### 2.1 上限与错误处理

- server 必须设置硬上限（实现常量；用于防 OOM/DoS）：
  - `maxRequestBytes`：client → server 的单帧上限（request frame）
  - `maxResponseBytes`：server → client 的单帧上限（response/event frame）
- `HELLO` 必须回显 `maxRequestBytes/maxResponseBytes`（便于前端/脚本在本地提前拦截并提示用户）。
- 备注（已确认）：v1 阶段**不引入**通用分页/分块/游标协议；实现期应把 `maxRequestBytes/maxResponseBytes` 设得足够大以覆盖常见 `GET/PRINT` 输出；超大输入/集合操作由命令面定义“分批”与命令级上限（例如 `DOMAINLISTS.IMPORT`）。
- 若 `len > maxRequestBytes`（已确认；2.37‑A）：立即断开连接（不返回 response frame；可记录 server log）。
- 备注（易用性）：由于 `id` 在 payload 内，`len>maxRequestBytes` 时无法返回带 `id` 的结构化 response；  
  但实现可选在断连前输出一条不带 `id/ok` 的 `type="notice"` 事件（例如 `notice="frameTooLarge"`，回显 `len/maxRequestBytes`），用于提升排障体验（不改变安全边界）。
- 若 server 侧将要发送的 response/event `len > maxResponseBytes`：应视为实现错误或不合理的上限配置；最小行为允许直接断开连接（同样可选输出 `type="notice"` 便于排障）。

### 2.2 framing 错误

若出现 framing 级错误（例如非 digits 开头、缺失 `:` / `,`、len 与实际 bytes 不匹配），server 应直接断开连接（不保证返回可解析错误）。

---

## 3. Payload envelope（JSON）

### 3.1 Request（client → server）

```json
{"id":1,"cmd":"HELLO","args":{}}
```

字段：
- `id`：u32（客户端生成；用于把 response 与 request 对齐）
- `cmd`：string（命令名；命令集合与各自契约以 `CONTROL_COMMANDS_VNEXT.md` 为准）
- `args`：object（允许空 `{}`；禁止其它 JSON 类型以避免歧义）

严格 JSON（已确认；2.10‑A）：
- vNext 的所有对外 JSON 输出必须是**严格 JSON**（正确 escape `\" \\ \n \r \t` 等）；禁止手写拼接“看起来像 JSON”的字符串。

严格性（已确认；0.3.2‑A）：
- 顶层出现未知 key → `SYNTAX_ERROR`。
- `args` 中出现未知 key → 默认 `SYNTAX_ERROR`（除非该命令明确声明允许扩展字段）。
- 未知 `cmd` → `UNSUPPORTED_COMMAND`。

扩展与演进策略（已确认；R-012=A）：
- vNext **不**预留统一 `ext{}` 扩展容器；strict reject 规则保持不变。
- 若需要新增/调整任何 request 字段（包括“可选字段”），必须 bump `protocolVersion`；client 必须通过 `HELLO.result.protocolVersion` 做版本协商，仅向匹配版本的 daemon 发送该版本定义的字段集合。

### 3.2 Response（server → client）

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

规则：
- 顶层 `ok` 永远是 boolean。
- `ok=true`：禁止出现 `error`。
- `ok=false`：必须出现 `error`，且禁止出现 `result`。
- **每条 request 必须且仅必须对应 1 个 response frame**（成功或失败）：  
  - 例外：若连接因 framing 级错误或 `len>maxRequestBytes` 被 server 直接断开，则不保证能返回可解析 response。  
  - stream 的 event/notice frames 不算 response（它们必须不包含 `id/ok`；见 3.3）。

### 3.3 Stream events（server → client；异步）

事件 payload 也是 JSON object，但它不是 response，因此：
- 必须包含 `type`（如 `dns|pkt|activity|notice`；语义见 observability 文档）
- **不得包含** `id/ok`（避免与 response 混淆）
- 仍然使用 netstring framing（与 request/response 完全一致）

---

## 4. 通用类型（跨命令一致）

### 4.1 错误对象（D3 单一真相）

最小 shape：

```json
{"code":"SYNTAX_ERROR","message":"human readable"}
```

可选字段：
- `hint`：给用户/前端的修复提示
- `candidates`：仅在“可修复且必要”时返回（尤其是 selector 歧义）
- 其它结构化细节：仅在 `INVALID_ARGUMENT` 等场景按命令扩展（例如 `conflicts[]`；见 `IPRULES_APPLY_CONTRACT.md`）

`error.code` 最小稳定枚举（后续只增不改）：
- `SYNTAX_ERROR`
- `MISSING_ARGUMENT`
- `INVALID_ARGUMENT`
- `UNSUPPORTED_COMMAND`
- `SELECTOR_NOT_FOUND`
- `SELECTOR_AMBIGUOUS`
- `STATE_CONFLICT`
- `PERMISSION_DENIED`
- `INTERNAL_ERROR`

说明（已确认）：
- v1 阶段未定义显式鉴权/权限模型，因此 `PERMISSION_DENIED` 属于**保留错误码**（reserved）。在权限模型落盘前，实现期不应“临时塞 if”随意返回该码。

`candidates[]` item（歧义时优先返回）：

```json
{"uid":10123,"userId":0,"app":"com.example"}
```

约束：
- `app` 必须是 canonical package name
- `candidates[]` 必须按 `uid` 升序排序

### 4.2 App selector（多用户语义；已确认）

vNext 不再使用 token 语法 `<uid>` / `<pkg> USER <userId>`；统一用结构化 selector：

```json
{"uid":10123}
```

或

```json
{"pkg":"com.example","userId":0}
```

约束：
- 二选一：要么提供 `uid`，要么提供 `pkg+userId`；禁止混用。
- `pkg` 仅匹配 canonical `app`（`allNames` 仅用于展示，不参与 resolve）。
- resolve 不唯一/不存在 → 必须结构化报错（`SELECTOR_AMBIGUOUS/SELECTOR_NOT_FOUND` + `candidates[]`）。

### 4.3 toggle 值的 JSON 类型（已确认；D12）

- 规则/开关类 toggle 统一用整数 `0|1`（例如 `enabled/enforce/log` 等）。
- 协议 envelope 的 `ok` 是 JSON boolean（不受上述约束）。

---

## 5. 连接拓扑与状态机（摘要）

- control 平面不独占：允许并发多条 control 连接（例如前端常驻 + 临时调试）。
- 备注（已确认）：v1 不引入 revision/CAS；并发 mutate 的结果按**最后写入生效**（last‑write‑wins）。调试脚本应自行避免 lost‑update。
- 需要限制的是 stream 订阅（每种 streamType 同一时间只允许 1 条连接订阅；见 observability 文档）。
- stream connection 上（命令入口统一为 `STREAM.START/STREAM.STOP`）：
  - 进入 stream 模式后，禁止执行非 stream 控制命令（返回 `STATE_CONFLICT`），避免输出交织与心智分裂；
  - `STREAM.START` 成功（已确认；2.36‑A）：先返回该 request 的 response frame（`{"id":...,"ok":true}`），再输出 `type="notice", notice="started"` 作为该 session 的第一条 event，之后才允许输出 replay/realtime events（细节见 observability 文档）；
  - `STREAM.STOP` 的 response frame 是 ack barrier：daemon 必须先停止该连接订阅并清空待发队列（允许丢弃未发送尾部），再输出 STOP response；**response 之后**不得再输出任何事件/notice，直到下一次 `STREAM.START`（或连接关闭）。  
    - 注：若某个 netstring frame 已经开始写出（partial write），为保持 framing 正确，daemon 可能需要先完成该 frame 才能输出 STOP response；但仍必须保证 STOP response 之后不再输出任何 frame。

---

## 6. 必需的连接级命令（最小集合）

### 6.1 `HELLO`（能力探测）

request：

```json
{"id":1,"cmd":"HELLO","args":{}}
```

response（建议最小字段集合）：

```json
{"id":1,"ok":true,"result":{"protocol":"control-vnext","protocolVersion":1,"framing":"netstring","maxRequestBytes":123456,"maxResponseBytes":123456}}
```

> `protocolVersion` 从 `1` 开始；在 strict reject 前提下，任何新增/调整 request 字段都会导致旧 daemon 拒绝，因此需要 bump `protocolVersion`（见 3.1 扩展策略）。
> 其它命令的 args/result/errors 见 `CONTROL_COMMANDS_VNEXT.md`（协议文档不重复定义命令面细节）。

---

## 7. 调试与工具（重要）

netstring 的 `len` 是 byte length，因此 vNext **不再适合**用 `socat` “手敲一行回车”的方式交互调试。  
建议提供一个小工具（例如 `sucre-snort-ctl`）负责：

- 输入：人类友好（可选兼容 legacy token 命令作为语法糖）
- 输出：netstring + JSON 打包/解包，并对 response/event 做 pretty 输出
- help：提供 `--help` / `help` 子命令，输出命令目录、示例与常见错误解释（help 属于工具的人机工程，不要求 daemon 侧提供 `cmd="HELP"`）
