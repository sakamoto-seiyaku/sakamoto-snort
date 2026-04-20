# Domain + IP Fusion：最终挑刺清单（临时）

更新时间：2026-04-17  
状态：非规范性（只用于“刻意找茬/去复杂化”；逐条回复用）

> 读法建议：你可以按编号逐条回复“接受/不接受/改成 X”，我再据此回写到对应“单一真相”文档。  
> 本文件不替代规范：协议以 `CONTROL_PROTOCOL_VNEXT.md` 为准，命令面以 `CONTROL_COMMANDS_VNEXT.md` 为准。

---

## 0. 先说结论（还可能踩坑的点）

1) vNext 已用 **netstring + JSON envelope** 把“token 规则堆叠/歧义推断”砍掉；但目录内仍有大量 legacy 讨论笔记（尤其 `archive/DOMAIN_IP_FUSION_AUDIT_TMP.md`）——实现期需要强约束“只信单一真相”，否则很容易把复杂度又实现回去。  
2) 即便命令面已选 **A（资源化 + 少量动词）**，仍有两类“会把系统重新做复杂”的高风险点：  
   -（a）为兼容手敲/脚本而把“语法糖”塞回 wire protocol；  
   -（b）把 domain 与 ip 的观测/配置入口拆回多套命令族（metrics/stream/list/rules 重新分裂）。  
3) `DOMAINRULES` 与 `DOMAINPOLICY` 拆成两条 `APPLY` 虽然清晰，但天然存在“跨命令一致性/restore 顺序”的坑，需要提前钉死规则（见 2.2）。

---

## 1. 已修正/已吸收的硬矛盾（无需你再拍板，只做记录）

1.1 `HELLO` 字段歧义：已把 `version` 改为 `protocolVersion`（避免与 daemon/settings version 混淆）。  
1.2 vNext `CONFIG` 的 iface 字段：已从错误的 `block.ifindex*` 改为 `block.ifaceKindMask*`（与现代码 `blockIface` 语义一致，避免把 kind-bit 当 ifindex）。  
1.3 `DOMAINRULES` 的 `type`：已补齐 `domain|wildcard|regex`（对齐现代码 `Rule::Type`）。  
1.4 `IPRULES.PRINT` 的 selector：已统一为 `args.app={...}`（避免和 selector 统一约定打架）。  
1.5 `OBSERVABILITY_IMPLEMENTATION_TASKS.md` 与 checklist：已同步到统一入口 `METRICS.GET/RESET(name=...)` + `STREAM.START/STOP(type=...)`（避免“working decisions vs tasks vs checklist”三份口径互相矛盾）。

---

## 2. 仍建议你拍板/钉死的点（有潜在返工风险）

### 2.1 vNext 是否需要覆盖 `HELP/PASSWORD/PASSSTATE`（能力完整性 vs 心智污染）

现状：
- 现代码 legacy control 有 `HELP/PASSWORD/PASSSTATE`；但 vNext 命令目录目前没纳入（刻意收敛，避免把“像鉴权但不是鉴权”的概念带进 vNext）。

风险：
- 若未来要删除 legacy endpoint，vNext 必须覆盖“确实被前端/脚本依赖”的能力；否则迁移无法闭环。  
- 但把 `PASSWORD/PASSSTATE` 直接搬进 vNext，会引入强烈误导（看起来像鉴权协议，但实际上只是设置项读写）。

可选方案（建议你选一个并写死）：
- A（推荐）：vNext **不提供** `PASSWORD/PASSSTATE`；未来若真要鉴权，另起 `AUTH.*` 命令族；legacy endpoint 在“稳定判据达成前”继续提供这些命令。  
- B：vNext 提供，但**重命名**并收敛到 `CONFIG`（例如 `auth.password`/`auth.passState`），且默认不允许读取明文（只允许 set）。  

当前结论（你已回复“先不做”）：
- 暂按 A：vNext 不引入 `HELP/PASSWORD/PASSSTATE`；迁移期仍由 legacy endpoint 覆盖。
- 若未来确实要“灌进 vNext/做鉴权”，必须做更严格的校验与语义收敛（避免“看起来像鉴权但不是鉴权”的长期心智污染）。
 - 但 **CLI 仍需支持 help**：例如 `sucre-snort-ctl --help` / `sucre-snort-ctl help` 输出命令目录与示例（help 属于工具的人机工程，不要求 daemon 侧提供 `cmd="HELP"`）。

### 2.2 `DOMAINRULES.APPLY` 与 `DOMAINPOLICY.APPLY` 的“跨命令一致性”钉子

问题：
- 两条 `APPLY` 都是原子 replace，但它们组合起来不是单事务：restore/回灌时天然会出现“先 rules 后 policy”或“先 policy 后 rules”的顺序问题。

必须明确的最小规则（建议写进命令目录或 working decisions）：
- `DOMAINPOLICY.APPLY` 必须严格校验 `ruleIds[]` 存在于当前 `DOMAINRULES` 基线；否则 `INVALID_ARGUMENT`。  
- restore/回灌的推荐顺序：先 `DOMAINRULES.APPLY`（拿到最终 `ruleId`），再 `DOMAINPOLICY.APPLY`（引用）。  

可选增强（不一定要做，但要决定“不做”也写明）：
- A：保持两条命令，但加“参照完整性”约束：`DOMAINRULES.APPLY` 也必须校验“移除的 ruleId 不得仍被任何 policy 引用”，否则拒绝并返回结构化错误（列出被引用的 `ruleId` 以及引用来源 scope/app）。  
  - 优点：daemon 状态永远自洽（不会出现“policy 引了不存在的 ruleId”导致 silent bypass）。  
  - 代价：删除规则时需要先更新 policy（先 policy→再 rules）；但这是可解释且可控的操作顺序。  
- B：允许 dangling：policy 里引用不存在的 ruleId 时“忽略该引用”，并在 `DOMAINPOLICY.GET` 回显 `missingRuleIds[]` 或 `warnings[]`。  
  - 优点：restore 顺序无要求、客户端更省事。  
  - 代价：极易产生“以为 block 生效但其实没生效”的安全/排障事故（不推荐）。  
- C：提供一个组合命令（例如 `DOMAIN.APPLY`）一次提交 rules+policy，保证跨资源一致性；代价是命令面更复杂、payload 更大。  
当前结论（你已确认）：
- 选 A（参照完整性）：daemon 状态必须始终自洽；不接受 dangling 引用。

### 2.3 `DOMAINLISTS.IMPORT` 大 payload：超过 `maxFrameBytes` 时的用户体验

现状：
- vNext 已裁决：`len > maxFrameBytes` 直接断连，不回 response（安全/实现简单）。

风险：
- `IMPORT` 很容易超限；前端看到的是“连接断了/无响应”，排查要靠日志或抓包。

建议钉子（无需改裁决也能显著降低排查成本）：
- A（推荐）：server log 打固定关键字 + 关键信息（len/maxFrameBytes/cmd）便于定位；前端在 `HELLO.maxFrameBytes` 基础上预检查并提示用户。  
- B：后续若真需要大导入，另起“分块导入/压缩导入”方案（不在本轮 fusion）。

你补充的口径（建议落实到命令契约）：
- `maxFrameBytes` 需要足够大（至少覆盖“正常规模的导入/restore”场景）；前端/使用者必须控制单次导入数量（分批/分页导入）。  
- 对“命令级超限”（例如 domains 数量上限、或 import bytes 上限，但仍未超过 `maxFrameBytes`）：
  - server 必须返回结构化错误（`ok=false`，`error.code=INVALID_ARGUMENT`），明确提示“payload 太大/请分批”。  
  - （建议）`HELLO` 或错误对象里回显上限（例如 `maxImportDomains`），避免前端只能靠经验猜。

### 2.4 `DOMAINLISTS` 的“订阅字段”：前端驱动 refresh，daemon 负责落盘与回读

你刚补充的真实约束（更关键）：
- 前端**不维护自己的独立 DB**；订阅相关的元信息/状态需要落在 daemon 侧持久化，并通过 control API 回读。
- 但“订阅/刷新/拉取远端内容”这个流程仍由前端负责；daemon **不做 HTTP 拉取**，也不决定刷新策略。

因此风险点不再是“这些字段不该进 daemon API”，而是“进了以后谁来维护、如何避免二义来源”：
- 同一份字段既可能被前端写，也可能被调试 CLI 写；如果没有明确所有权，就会出现 state 漂移与排障困难。

可选方案：
- A（推荐）：订阅字段**进入** daemon API，但明确“所有权在前端/脚本（refresh 驱动方）”，daemon 只负责持久化与最小校验。  
  - `DOMAINLISTS.GET` 必须回传：`url/name/updatedAt/etag/outdated/domainsCount`（以及执行配置 `listKind/mask/enabled`）。  
  - `DOMAINLISTS.APPLY` 允许更新上述字段；daemon 不做远端一致性推断（不自动拉取/不自动判定 outdated）。  
  - 这样前端重启后可以完整恢复订阅 UI/刷新所需条件（etag/时间戳等）。
- B：订阅字段不进 daemon API，要求前端自己持久化。  
  - 与你刚说明的“前端不维护 DB”冲突，本轮不适用。

当前结论（按你刚澄清的真实约束修正）：
- 选 A：订阅字段进入 daemon API，但 refresh 仍由前端驱动（daemon 不做 HTTP）。

### 2.5 `DOMAINLISTS` 的 `mask` 语义（block vs allow 是否对称？）

代码事实：
- block lists（blacklist）通过 `domain.blockMask & app.blockMask` 生效（mask 对 app 可选）。
- allow lists（whitelist）目前是 **device-wide override**：只要命中 whitelist，就把该 domain 的 `blockMask` 置 0（对所有 app 生效），与 app mask 无关。

风险：
- vNext 若继续要求 allow list 也带 `mask`，用户很容易误解“allow list 也能按 mask 选择性生效”，但现代码并不是。

可选方案（建议你选一个口径并写死）：
- A（推荐/最贴合现代码）：`listKind="allow"` 时 `mask` 仍是必填但仅作为“list 标签/链路编号”（不参与 per-app mask 选择）；文档明确：allow list 是 device-wide override。  
- B：让 allow list 也变成“按 app mask 选择性生效”（需要改实现与仲裁，工作量更大，但语义更对称）。

当前结论（你已确认）：
- 选 A：allow list 为 device-wide override；`mask` 不参与 per-app 选择语义。

### 2.6 `DOMAINPOLICY.APPLY` 的自洽性校验：同 scope 内冲突应尽量早拒绝

现状：
- policy 结构是 `allow{domains,ruleIds}` + `block{domains,ruleIds}`。
- 但文档还没锁死“同 scope 内 allow 与 block 的冲突如何处理”。

你已确认的口径（按现代码优先级；允许重复/冲突共存）：
- 同一 scope 内：
  - `allow.domains` 与 `block.domains` 允许相交；若相交，按现代码心智：**allow 优先**（allow wins）。  
  - `allow.ruleIds` 与 `block.ruleIds` 允许相交；若相交同样 allow 优先。  
  - 列表内重复项允许存在（不得因为重复而拒绝 apply）。
- 注意：这会把“冲突配置”留到运行期解释；因此 stream/metrics 的解释字段必须清晰（否则用户会质疑“我明明写了 block 为什么没生效”）。

### 2.7 domain 字符串 canonicalization（大小写/尾点/空白）是否要统一（强烈建议钉死）

代码事实：
- DNS/domain 名称本质上大小写不敏感，但现代码的数据结构/匹配基本都是 **case-sensitive string**。
- 现代码只在 `DomainList::blockMask()` 做了“查询时去掉 trailing dot（`a.b.` → `a.b`）”，但不会统一 lower-case；`CustomRules`/`CustomList` 也不会做任何规范化。

风险：
- 同一个域名可能出现 `Example.COM`/`example.com`/`example.com.` 多个形式，导致：
  - policy/list/rule 命中不稳定（看起来配了但没生效）；
  - DomainManager 内出现多个 Domain object（stats/映射/自定义列表引用断裂）。

可选方案：
- A（推荐）：vNext 对所有“域名字符串输入”（`DOMAINPOLICY.* domains[]`、`DOMAINLISTS.IMPORT domains[]`、`DOMAINRULES` 的 `type=domain|wildcard` pattern 等）统一做 canonicalization：
  - trim 空白；
  - lower-case；
  - 去掉末尾 `.`（若只剩 `.` 则视为非法）。
  - `GET` 回显也统一返回 canonical 形式。
- B：不做 canonicalization（保持现状），但必须在文档/前端强约束“输入必须已经是 lower-case 且无尾点”，否则行为不保证。

当前结论（你已确认）：
- 不做 canonicalization（保留现实现行为与风险暴露，不做后端“偷偷规范化”）。

### 2.8 `DOMAINRULES.type="domain"` 的语义（当前实现存在明显陷阱）

代码事实：
- `CustomRules` 里最终用 `std::regex_match(domain->name(), compiledUnionRegex)`。
- 当前 `Rule::create()` 对 `DOMAIN` 规则 **不转义** regex 元字符：例如 `example.com` 会把 `.` 当作“任意字符”，而不是字面量点。

风险：
- 用户以为是“精确域名匹配”，实际是 regex 行为（极易误配，且很难排障）。

可选方案：
- A（推荐）：vNext 规定 `type="domain"` 是“字面量精确匹配”（内部必须转义 regex 元字符）；并配合 2.7 的 canonicalization。  
- B：保留现行为（把 `domain` 当 regex），但必须在文档里明确“`type=domain` 仍按 regex 解释，`.` 需要手动转义”，并且前端输入层必须自动 escape（非常不推荐）。  
- C：对外不再暴露 `type=domain`（只保留 `wildcard|regex`）；迁移期仍允许读到旧 `domain`，但内部当成 `wildcard`（等价“精确匹配”）。

当前结论（你已确认）：
- 不改：`type="domain"` 继续保持现行为（`pattern` 直接按 regex 解释，**不转义**元字符；`.` 仍是“任意字符”）。

### 2.9 `domain.custom.enabled`（`App::_useCustomList`）是否应该继续 gate device-wide DomainPolicy？

代码事实：
- `App::blockedWithSource()` 中，device-wide 的 `GLOBAL_AUTHORIZED/GLOBAL_BLOCKED`（即 device-wide custom domains/rules）只在 `_useCustomList==true` 时才会被检查。

风险：
- vNext 若把 `DOMAINPOLICY(scope=device)` 叙事成“device-wide”，但它实际只对开启了 `domain.custom.enabled=1` 的 app 生效，会造成严重心智偏差。

可选方案：
- A（最贴合现代码/性能直觉）：继续保持 gate：`domain.custom.enabled` 一旦关闭，该 app 完全不参与 device-wide custom domains/rules（只剩 mask/list bit 的路径）。文档必须明确这是“opt-in 的共享策略”，不是“强制 device-wide”。  
- B（语义更直观但更改实现）：device-wide DomainPolicy 对所有 app 生效；`domain.custom.enabled` 只 gate per-app custom（不 gate device-wide）。  
- C：移除 `domain.custom.enabled`（全部 app 都参与 DomainPolicy；用别的方式控制成本，例如只对“非空 policy 的 app”检查）。

当前结论（你已确认）：
- 选 A：继续保持 gate（device-wide policy 只对 `domain.custom.enabled=1` 的 app 生效）。

### 2.10 `DOMAINLISTS.IMPORT` 是否需要重复携带 `listKind/mask`（冗余 vs 自洽）

现状（命令目录口径）：
- `DOMAINLISTS.IMPORT` 目前要求请求里同时携带：`listId + listKind + mask`。

风险：
- 这三个字段本质上属于 list 元数据，而元数据已由 `DOMAINLISTS.APPLY` 管理；重复携带会制造“二义来源”：
  - 若客户端传的 `listKind/mask` 与后端已存元数据不一致：到底信谁？
  - 若后端直接信 request：实现期容易出现“导入进了错误 kind / 使用了错误 mask”的事故，排障困难。

可选方案（建议你拍板一个并写死）：
- A（推荐）：`DOMAINLISTS.IMPORT` **只接受** `listId`（+ `clear/domains[]`），后端从已存元数据读取 `listKind/mask`。  
  - 若 list 不存在：`INVALID_ARGUMENT`（提示先 `DOMAINLISTS.APPLY` 创建/启用该 list）。  
  - 好处：彻底消灭“IMPORT 的 listKind/mask 与元数据打架”的可能性。
- B：保留 request 里的 `listKind/mask`，但它们只用于“自洽校验”：必须与已存元数据一致，否则 `INVALID_ARGUMENT`。  
  - 好处：请求更自解释；坏处：协议字段更冗余、前端更易写错。
- C：把 `IMPORT` 变成“隐式创建/更新元数据 + 导入 domains”的组合命令（本质上把 `APPLY+IMPORT` 合并）。  
  - 不推荐：会重新做大命令面（与“资源化+少动词”方向冲突）。

当前结论（你已确认）：
- 选 B：`DOMAINLISTS.IMPORT` 仍要求携带 `listKind/mask`，但仅用于“与已存元数据做一致性校验”，不得作为写入来源。

### 2.11 `DOMAINLISTS` 的 `listId` 全局唯一与 `listKind` 可变性（防“同 id 两种语义”）

代码事实：
- `BlockingListManager` 以 `id` 为唯一 key 存储 lists（不区分 kind），因此 **同一 `listId` 不可能同时存在 block/allow 两个 list**。
- 当前 legacy control 实际**允许**“同 id 改 kind”：
  - `Control::cmdUpdateBlockingList(..., color)` 会在更新时检测 `currentColor != color`，并调用 `domManager.switchListColor(id, color)`（见 `src/Control.cpp`）。
  - 这意味着“同一个 listId”的磁盘 domains 文件会在 blacklist/whitelist 之间被重新解释（以及被重新纳入不同的匹配链路），属于高风险操作，且很难让用户意识到其影响范围。

可选方案：
- A（推荐）：`listId` 全局唯一；**`listKind` 对同一个 `listId` 不可变**。  
  - 若需要从 block 改为 allow（或反之）：要求新建一个新的 `listId`，再迁移/导入域名。  
  - `mask/enabled` 仍允许更新（按 `DOMAINLISTS.APPLY` 契约）。
- B：允许 `listKind` 变更（把它视为“删除旧 list + 新建另一 kind 的同 id list”）。  
  - 不推荐：实现与运维风险太高，且对用户几乎没有必要性（新建新 id 更安全）。

当前结论（你已确认；按现代码现状）：
- 选 B：允许 `listKind` 变更（vNext 保持与 legacy 一致的“同 `listId` 可在 allow/block 间切换”的能力）。
- 挑刺提醒（仍成立）：这是高风险操作，前端应显式提示/二次确认（否则一条误操作就可能把 block list 变成 device‑wide allow override）。

### 2.12 `DOMAINLISTS`：职责边界（订阅由前端维护）

你补充的原则（已澄清）：
- “订阅/刷新/拉取远端内容”的流程由前端维护；daemon **不做 HTTP 拉取**、不决定刷新策略。  
- 但前端不维护独立 DB：订阅元信息/状态需要落盘在 daemon，并通过 control API 回读。

因此 vNext 收敛（与命令目录保持一致）：
- `DOMAINLISTS` 同时承载两类字段：
  - 执行配置（daemon 真正用于匹配/执行）：`listId/listKind/mask/enabled`；
  - 订阅元信息/状态（供前端 refresh 流程回读/续传）：`url/name/updatedAt/etag/outdated/domainsCount`（由前端写入；daemon 持久化）。
- 关键边界：daemon 不根据 `url/etag/updatedAt` 自动拉取或推断 `outdated`；这些都是**前端驱动**的流程与状态。

#### 2.12.1 `DOMAINLISTS.APPLY` 对“订阅字段”的更新语义：patch 还是 replace？

问题：
- vNext 目前用 `DOMAINLISTS.APPLY(upsert/remove)` 承载 list 配置与订阅字段；但必须钉死：
  - upsert 时订阅字段是否 **必填**？
  - upsert 是否允许 **只更新其中几个字段**（其余保持不变）？
- 若不写死，会出现：
  - 前端只是想 toggle `enabled`，结果不小心把 `etag/updatedAt/url/name` 清空；
  - “创建新 list 但还没 refresh”时，必须硬填一个 `updatedAt`，否则后端校验失败。

可选方案：
- A（推荐）：**patch 语义**（缺省字段=保持不变；创建时有明确默认值）
  - `listId/listKind/mask/enabled` 必填；
  - `url/name/updatedAt/etag/outdated/domainsCount` 全部可选：未提供则保持后端已有值；
  - 创建新 list 时的默认值建议锁死为：
    - `url=""`、`name=""`、`etag=""`、`domainsCount=0`、`outdated=1`、`updatedAt=""`（或 `"1970-01-01_00:00:00"`，二选一但必须写死）。
  - 优点：前端写起来更安全；不会因为“没带全字段”误清状态。
  - 代价：实现侧需要做一次“merge old + new”，并在 strict reject 下明确哪些 key 允许缺省。
- B：**replace 语义**（upsert 必须携带所有订阅字段；缺一个就拒绝）
  - 优点：协议更“数学化”；实现更简单（少 merge 逻辑）。
  - 代价：前端必须先 GET 再完整回写；否则容易误操作；对 CLI 也更不友好。
- C：拆分命令：`DOMAINLISTS.APPLY` 只管执行配置；另加 `DOMAINLISTS.META.SET` 专门更新订阅字段
  - 优点：所有权更清晰；避免“配置变更”和“订阅状态写入”互相踩。
  - 代价：命令面增加（与“少命令”方向冲突）。

建议：
- 选 A（patch）更符合“前端 refresh、后端落盘”且不增加命令面；并且最能避免误清元信息。

### 2.13 `listKind` 切换与 `mask`（按“域名实现不动”收敛）

已确认：
- 允许同 `listId` 在 allow/block 间切换（2.11‑B）。

为保持实现不动并避免一次操作里引入复杂仲裁：
- 若一次 `DOMAINLISTS.APPLY.upsert[]` 中发生 `listKind` 变更，则该条目 `mask` 必须保持不变；若同时变更 `mask` → 拒绝 `INVALID_ARGUMENT`（分两步做：先切 kind，再改 mask）。
- kind 变更时只要求“迁移该 listId 的 domains 集合到新 kind”（不要求重导入/重写 domains）。
- `DOMAINLISTS.IMPORT` 继续按 2.10‑B 做一致性校验：request 的 `listKind/mask` 必须与当前元数据一致。

### 2.14 `DOMAINRULES`：`domain` vs `regex`（保持现行为）

已确认（2.8）：
- `type="domain"` 与 `type="regex"` 都是“按 regex 解释且不转义元字符”，语义等价。

为保持实现不动：
- vNext 保留两种 type；冲突/去重仍按 `(type,pattern)`（不把 domain/regex 当等价类型去重）。
- 风险：同 pattern 可出现两条等价规则（domain+regex）；行为不变但会污染规则库。建议前端避免生成这类冗余。

### 2.15 `DOMAINPOLICY.domains[]` 的校验（保持现行为）

为保持匹配/规则实现不动：
- 不做 canonicalization，不做严格域名合法性校验；按原始字符串工作。
- 仅做最小保护（可选）：非空、长度上限（例如 `<= HOST_NAME_MAX`），避免异常 payload。
- 其余输入清洗/去重/大小写统一由前端负责。

---

## 3. 继续挑刺（不一定要立刻改，但建议保持警惕）

3.1 **strict reject 的扩展性**：全局 `args` 未知 key → `SYNTAX_ERROR` 很干净，但会让“无痛扩展字段”变难；若未来要做灰度字段，可能需要一个明确的 `ext{}` 容器或版本协商规则。  
3.2 **stream 限制应只限制订阅，不限制 control 并发**：实现时非常容易偷懒成“整个 control socket 单连接”，需要在实现 checklist 里写 MUST（你前面已经认可这条原则）。  
3.3 **`STREAM.STOP` 清空 ring 的语义**：目前 working decisions 选择“STOP 清空 ring，下一次 START 视为新 session”；这很一致，但请注意它会影响“临时 stop 再 start 看回放”的排障手感（属于取舍，不是对错）。
