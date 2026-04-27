# Domain + IP Fusion（DOMAIN_IP_FUSION）临时审核笔记

更新时间：2026-04-17  
状态：临时审阅输出（便于逐条回复/裁决；已记录 2026-04-14/2026-04-16 裁决 + 2026-04-17 审核补充；不代表最终决议）

> 背景：本目录文档仍处于“设计/讨论→落盘到 change 之前”的阶段；当前代码是事实参考。本笔记专注于：**文档内部自洽性** + **与现有代码/接口规范/OpenSpec 的冲突点** + **潜在设计缺口/踩坑点**。  
> Roadmap/阶段边界的权威记录：`docs/IMPLEMENTATION_ROADMAP.md`。
>
> 注（2026-04-17）：vNext control/stream 的线协议已从“LF+NDJSON+token”重收敛为“netstring + JSON envelope”（方案 D）。本文件中仍提及 NDJSON 的段落若未同步更新，视为历史审阅记录；以 `CONTROL_PROTOCOL_VNEXT.md` 为准。  
> 另：方案 D 下 vNext request 不再采用 token 命令语法，因此 D1/D2 等关于 `<pkg> <userId>`/裸 `USER` 的讨论在 vNext 中不再是“实现必须遵守的语法规则”，最多作为 legacy endpoint 或 CLI sugar 的参考；vNext 命令面以 `CONTROL_COMMANDS_VNEXT.md` 为准。

---

## 0. 总体判断（简要）

- `DOMAIN_IP_FUSION_CHECKLIST.md` 第 1 节“按代码事实”的描述整体准确；本目录 4 份文档之间也基本自洽。
- 主要问题不在“目录内部互相打架”，而在：**这些决策与仓库现有“权威接口/规格/实现”存在多处硬冲突**。如果不先裁决，后续落到 change 时会反复返工。

## 0.5 已收到裁决（你回复，2026-04-14/2026-04-16）

- D1（`<pkg> <userId>` 位置参数简写）：**不强制禁止**。如果单独禁止牵连甚广则允许该简写；要求整体接口自洽。
- D2（裸 `USER <userId>` 过滤）：**不再强行禁止**；以接口逻辑自洽为准，后续遇到问题再修复。
- D3（错误模型/严格拒绝）：接受把“歧义严格拒绝 + candidates[] + structured errors”作为 **vNext 的单一真相**；但**暂不要求**同步更新 change 与 `docs/INTERFACE_SPECIFICATION.md`（它们描述的是当前代码现状，而非未来设计）。
- D4（control 协议，重新收敛为方案 D）：升级 **整个** control 协议（不仅仅是 stream），并确认：
  - vNext endpoints：`sucre-snort-control-vnext` / `60607`
  - wire framing：netstring（`<len>:<payload>,`）
  - payload：UTF‑8 JSON object；request/response 统一 envelope（见 `CONTROL_PROTOCOL_VNEXT.md`）
    - request：`{"id":...,"cmd":"...","args":{...}}`
    - response：`{"id":...,"ok":true,"result":...}` / `{"id":...,"ok":true}` / `{"id":...,"ok":false,"error":{...}}`
    - unknown field 策略：严格（顶层未知 key → `SYNTAX_ERROR`；见 0.3.2‑A）
  - help：vNext daemon **不要求**提供 `cmd="HELP"`；help 属于 `sucre-snort-ctl` 等 CLI 的人机工程（输出命令目录/示例/错误解释）。
  - legacy endpoints：`sucre-snort-control` / `60606` 仅迁移期保留；当 vNext 稳定后关闭并删除（不长期维护两套协议）
- D5（STOP）：改为 **有响应**（对齐“STOP 返回 response frame（`{"id":...,"ok":true}`）”的口径）。
- D6（兼容/落盘）：按“不兼容 + 删除遗留落盘/兼容 restore”处理（放弃旧行为/旧落盘）。
- D7（`tracked` 默认）：接受 `tracked=false`（默认关闭）。
- D8（`tracked` 持久化 & UX）：`tracked` **持久化**；但前端必须明确提示用户“开启跟踪/统计可能带来性能影响”。
- D9（`ifindex`）：`ifindex=0` 与 `ifindex=any` **语义等价**。
- D10（统一性原则）：在 D9 前提下尽量统一表示/类型；核心目标是让前端能基于后端日志/输出清晰解释“发生了什么、为什么”。
- D11（`policySource` 命名）：确认这是一组 breaking change；但**暂不要求**同步更新 `docs/archived/DOMAIN_IP_FUSION/` 目录外的文档（先把融合讨论彻底完成）。
- D12（`matchKey`/toggle 归一化）：`matchKey` 字段 key **全小写**；`ifindex=0` 作为 canonical；toggle 类型统一为 `0|1`。
- D14（stream START 默认）：确认改为默认 `0/0`（不回放历史）。
- D15（ACTIVITYSTREAM）：确认纳入 vNext，并与 DNS/PKT 保持统一协议/语义风格。
- D16（2.5 dual-form 命令消歧）：vNext 不背兼容包袱；在方案 D 下通过 JSON `args` 显式消歧：
  - device-wide vs per-app：是否存在 `args.selector`
  - domain vs rule：由 `cmd` 命令族区分（`*LIST*`/`*RULES*`），不做 token 推断与缺参回退
- D17（2.17 replay/ring）：选择方案 A：保留强 replay 语义；对 tracked app 即使无订阅者也维护进程内 ring，用于 `*.START horizon/minSize` 回放；未 tracked 不入 ring。
- D18（stream START feedback）：`DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM.START` 成功先返回 response frame（`{"id":...,"ok":true}`），随后必须输出一次 `type="notice", notice="started"`（至少一条，避免“无流量=无反馈”；不入 ring/不回放/不落盘）；然后才进入回放（若有）与实时事件输出。
- D19（2.7 vNext 输出硬约束）：vNext 除 streams 事件流外，**每条 request 必须返回且仅返回 1 个 response frame**（成功或失败），避免客户端靠超时猜测（事件/notice 属于 event stream，不算 response）。
- D20（2.9 STOP ack barrier）：采用方案 B：`*.STOP` 先禁用订阅并清空 pending queue（允许丢弃尾部未发送事件/notice），再输出该 STOP 的 response frame（`{"id":...,"ok":true}`）；该 response 必须是该 STOP 的最后一个输出 frame，ack 后不得再输出任何事件/notice，直到下一次 `*.START`。
- D21（2.10 严格 JSON）：采用方案 A：vNext 必须引入统一 JSON string encoder（正确 escape `\" \\ \n \r \t` 等），所有对外 JSON 输出必须生成严格 JSON（禁止手写拼接假 JSON）。
- D22（2.11 严格拒绝补齐）：采用方案 A：vNext 全局启用 strict reject：
  - request/args 出现未知字段默认 `SYNTAX_ERROR`（0.3.2‑A）
  - mutate 命令禁止 silent no-op（selector 不存在/歧义必须结构化报错）
- D23（2.12 drop 策略与口径）：采用方案 A：pending queue/ring 满时使用 drop-oldest；`droppedEvents` 口径按“被丢弃的逐条事件条数”（不按 bytes）；`notice="dropped"` 最多 1 条/秒/streamType，`windowMs` 输出实际聚合窗口。
- D24（2.14 vNext endpoint 部署策略）：选择 A/A/A：
  - DEV fallback 同时暴露 filesystem + abstract（`/dev/socket/sucre-snort-control-vnext` + `@sucre-snort-control-vnext`）
  - TCP 60607 受 `inetControl()` gating（与 legacy 同策略）
  - `inetControl()` 开启时同时豁免 60606+60607（迁移期避免 control traffic 被 blocking/干扰）
- D25（2.15 framing 解析策略）：选择 A（方案 D）：
  - 按 netstring 解析（支持 partial read 与一次 read 多帧）
  - vNext 输出链路不得混入 legacy 的 NUL terminator
- D26（2.16 QUIT）：选择 A：vNext 保留 `QUIT`；返回 response frame（`{"id":...,"ok":true}`）后 server close；连接断开视为订阅终止并释放相关队列/状态（允许丢尾部事件）。
- D27（2.13 IPRULES apply 契约补齐）：选择 B/B/A：
  - `ruleId` 对 `clientRuleId` 稳定复用；新增 `clientRuleId` 分配新 `ruleId`（单调递增），删除的 `ruleId` 不复用；apply 成功响应回传 `clientRuleId->ruleId->matchKey` 映射。
  - stats：幂等 apply 不清 stats；仅当规则新增/删除/定义变化时 reset（与 v1 UPDATE 心智一致）。
  - PKTSTREAM：保持只输出 `ruleId/wouldRuleId`（不回显 `clientRuleId`，避免高频 string 成本）。
- D28（2.18 dual-form 命令族语法树）：在方案 D 下不再需要 token keyword；通过 JSON `args` 显式区分：
  - per-app：`args.selector` 存在
  - device-wide：`args.selector` 缺失
  - domain/rule 由 `cmd` 命令族与 `args.domain/args.ruleId` 字段类型区分
- D29（2.19 多用户 selector）：选择 A/A/A：
  - `<pkg>` 仅匹配 canonical `app->name()`（`allNames` 仅展示，不参与 resolve）
  - `candidates[]` 按 `uid` 升序排序
  - 以 `_byUid` 扫描生成 candidates（不把 `_byName` 当真相）
- D30（2.20 userId filter）：选择 A：逐命令白名单（只允许明确标注支持的 device-wide list/stats 命令接受 `args.userId`；其它命令若出现 `args.userId` 一律 `SYNTAX_ERROR`）。
- D31（2.21 `BLOCKIPLEAKS`）：冻结并强制关闭；在 fusion/vNext 口径中视为“无作用能力”（不做 reasonId/metrics/stream 叙事，不再讨论并入仲裁；后续若要删除另开 change）。
- D32（2.22 `GETBLACKIPS/MAXAGEIP`）：选择 A：全部冻结；强制 `GETBLACKIPS=0`；`MAXAGEIP` 不对外；vNext 不提供接口/HELP 不展示。
- D33（2.23 legacy domain path）：选择 A：保留 Domain↔IP 映射但仅用于 observability/可读性；packet verdict/reasonId 不依赖 DomainPolicy，并把 DomainPolicy 判决从 packet 热路径移出（按需计算）。
- D34（2.23.2 PKTSTREAM 名称字段）：选择 B：新增 `domain`（bridge），保留 `host`（reverse‑dns）；两者独立可选输出。
- D35（2.23.3 `domain/host` 输出线程与 validIP）：选择 A：`domain/host` 仅作为可读性字段，在 writer/序列化线程 best-effort 输出；`validIP` 判定也在 writer；并明确 `domain/host` 不承诺判决时快照。
- D36（2.24 stream schema 类型/缺失表示）：选择 A：optional 字段缺失就省略（不输出 `"n/a"`）；`wouldDrop` 为 JSON boolean；`timestamp` 格式必须写死。
- D37（2.25 vNext error codes）：选择 A：锁死最小稳定 `error.code` 枚举（后续只增不改）。
- D38（2.26 packet stats domain/color 归因）：选择 A：本阶段不再做 packet stats 的 domain/color 归因（先冻结行为、不要求删代码；后续稳定后再专题讨论）。

## 0.6 仍待裁决 / 待细化

- P1-细化（已完成）：legacy domain path（DNS‑learned Domain↔IP bridge）已裁决 2.23.1‑A（保留映射但仅用于 observability/可读性）+ 2.23.2‑B（PKTSTREAM 同时提供 `domain`=bridge 与 `host`=reverse‑dns），并已通过 2.33‑A 锁死对外解释口径（best-effort label；缺失=未知；不得归因/仲裁）。同时已在 observability 文档明确：不得为补 `domain/host` 把 DomainPolicy 判决拉回 packet 热路径（`domain.validIP()` 建议在 writer/序列化线程判定）。
- 2.17 已裁决 A；已同步修订 `OBSERVABILITY_WORKING_DECISIONS.md` / `DOMAIN_IP_FUSION_CHECKLIST.md` 的“ring 只在 stream 开启期间维护”表述。
- D11/D12/D14/D15 已裁决且已同步进本目录文档。
- D4-补充（已确认）：vNext “稳定”的判据包含“App 对外发布后，连续超过两个小版本更新，用户反馈中未出现控制平面相关问题”（以及迁移/回归/无回滚等条件），再关闭并删除 legacy endpoints。
- 2.32/2.33/2.34/2.35 已确认并同步进本目录“单一真相”文档（control/observability/iprules apply）。
- 2.36/2.37 已裁决 A/A（见 2.36/2.37）；本目录内已无其它待裁决点。
- 剩余主要是 **进入实现阶段时的目录外同步**（`docs/INTERFACE_SPECIFICATION.md` + `openspec/specs/*` + 前端），见 `DOMAIN_IP_FUSION_CHECKLIST.md` 的 0.2。

---

## 1. P0 硬冲突（建议先裁决；否则实现阶段必返工）

### 1.1 多用户 selector：语法/拒绝策略冲突（文档 vs 接口规范 vs OpenSpec vs 代码）

**文档主张（fusion）**
- 仅允许：`<uid>` 或 `<pkg> [USER <userId>]`
- 禁止：`<pkg> <userId>`（位置参数简写）（D1 已裁决：不强制禁止；若牵连甚广可允许，接口需自洽）
- selector 不唯一/不存在：一律拒绝并返回可修复错误（含 candidates），禁止 best-effort
- 裸 `USER <userId>`（无 app）过滤语法：D2 已裁决为“不再强行禁止”，以接口逻辑自洽为准（建议：明确列出哪些命令支持 user-filter；不支持的命令对 `USER` token 报错，避免 silent ignore）。  
  参考：`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:240`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:246`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:249`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:264`

**现有“权威”与实现**
- 接口规范允许 `<str> <userId>` 简写，且大量命令支持裸 `USER <userId>` 过滤（list/stats）。  
  参考：`docs/INTERFACE_SPECIFICATION.md:27`、`docs/INTERFACE_SPECIFICATION.md:31`、`docs/INTERFACE_SPECIFICATION.md:33`、`docs/INTERFACE_SPECIFICATION.md:68`、`docs/INTERFACE_SPECIFICATION.md:134`
- OpenSpec multi-user 同样允许 `<str> <userId>` 简写，并把 `<str>`（无 USER）定义为“只匹配 user 0”。  
  参考：`openspec/specs/multi-user-support/spec.md:153`、`openspec/specs/multi-user-support/spec.md:167`
- 代码已实现：`readAppArg(..., allowBareUserId=true)` 会吞掉 `<str> <userId>`；也支持裸 `USER <userId>`。  
  参考：`src/Control.cpp:556`、`src/Control.cpp:563`、`src/Control.cpp:598`
- **重要实现细节（会影响“严格拒绝”可落地性）**：
  - STR selector 默认直接按 `userId=0` resolve（不会先检查“是否存在多个 userId 同名包”再拒绝）：`src/Control.cpp:627`
  - 多个“设置类命令”对 selector not-found 采取 silent no-op + `OK`，而不是报错（例如 `TRACK/UNTRACK/BLOCKMASK`）：`src/Control.cpp:1460`、`src/Control.cpp:1540`
  - 部分“设置类命令”对 UID 允许 **隐式创建** App 对象（例如 `BLOCKIFACE` set mode）：`src/Control.cpp:1499`
  - HELP 文字还提示：某些命令即使出现 `USER <userId>` token 也不会作为 per-user filter 解释（保持 device-wide 语义），这与“严格语法错误”路线冲突：`src/Control.cpp:2109`

**需要你裁决的问题**
- D1（已裁决）：不强制禁止 `<str> <userId>` 简写（若保留需定义与 `<str>`/`<pkg> [USER ...]` 的优先级/歧义策略，避免“同包多用户”场景误选）
- D2（已裁决）：不再强行禁止裸 `USER <userId>` 过滤（以接口逻辑自洽为准）。
- D3（已裁决）：把“歧义严格拒绝 + candidates[] + structured errors”作为 vNext 单一真相；但暂不要求同步更新 change 与 `docs/INTERFACE_SPECIFICATION.md`（它们描述当前代码现状）。

> （本段 D1/D2/D3 已记录裁决；后续主要工作是把结论同步进本目录其它文档，并在实现阶段落到 code/spec/change 上。）

---

### 1.2 Streams：线协议/STOP 语义/持久化策略冲突（fusion 文档 vs 接口规范 vs 代码 vs OpenSpec）

**文档主张（stream vNext）**
- framing：netstring（见 `CONTROL_PROTOCOL_VNEXT.md`；不使用 NUL terminator）
- request/response：统一 JSON envelope（`id/cmd/args` 与 `id/ok/result/error`）
- `*.STOP` 返回 response frame（`{"id":...,"ok":true}`）；失败返回 `{"id":...,"ok":false,"error":{...}}`
- 进入 stream 模式后禁止同一连接执行非 stream 控制命令（避免输出交织）
- 事件 envelope：`type="dns|pkt|activity|notice"`；`notice="suppressed|dropped"`；NOTICE 仅实时，不进 ring，不回放，不落盘（suppressed 仅对 dns/pkt 有意义）  
  参考：`docs/archived/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md:101`、`docs/archived/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md:103`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:364`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:367`

**现有“权威”与实现**
- 接口规范（v3.6）定义控制通道请求/响应以 NUL 结尾，`!` 允许 pretty；并且 `PKTSTREAM.STOP/ACTIVITYSTREAM.STOP` “无响应”。  
  参考：`docs/INTERFACE_SPECIFICATION.md:16`、`docs/INTERFACE_SPECIFICATION.md:17`、`docs/INTERFACE_SPECIFICATION.md:150`
- 实现确实是 NUL + pretty + 同步写 socket：  
  - `SocketIO::print` 写 `outStr.size()+1`（含 NUL）并在 pretty 时格式化：`src/SocketIO.cpp:30`、`src/SocketIO.cpp:58`
  - `Streamable::stream` 在调用线程构造 JSON 并同步 flush：`src/Streamable.cpp:29`
- **重要实现细节（会影响 vNext 设计是否真的解决性能/噪音问题）**：
  - 当前 `Streamable::stream()` **总是**把事件 push 进 `_items`（ring），不依赖是否有 stream 连接存在；因此即使从未 `*.START`，仍可能在热路径承担分配与锁开销：`src/Streamable.cpp:29`
  - 当前 `PKTSTREAM` 事件在 packet 热路径**无条件构造并入 ring**（不受 `tracked` gating 影响）：`src/PacketManager.hpp:124`、`src/PacketManager.hpp:195`、`src/PacketManager.hpp:242`
  - 当前 `DNSSTREAM` 事件只在 `settings.blockEnabled() && app->tracked()` 时构造，但仍与 stream 是否开启无关（tracked app 的 DNS 事件会持续入 ring）：`src/DnsListener.cpp:241`
  - 当前 `DNSSTREAM` 事件字段并非“判决时快照”：
    - `domMask/appMask` 在打印时读取（引用 `Domain/App` 当前值），会随配置变化而漂移：`src/DnsRequest.cpp:26`
    - 且当前事件不包含 `policySource/useCustomList/scope/getips` 等可解释字段（fusion 文档要求补齐并快照）
  - 当前 `PKTSTREAM` 事件 schema 也与 vNext 目标有差距：缺少 `type` envelope、`ifindex/ifaceKindBit`，且 `interface` 仅输出 name（不可作为唯一标识）：`src/Packet.cpp:32`
  - 当前 stream replay 默认参数是 `horizon=600s` 且 `minSize` 非零（DNS=500、PKT=100），与 vNext “默认 `0/0`”相反：`src/Settings.hpp:136`
  - 当前 `DNSSTREAM` 存在落盘 save/restore（`Settings::saveDnsStream`），与 vNext “不落盘/允许升级丢弃”冲突：`src/Settings.hpp:112`、`src/DnsListener.cpp:276`
- STOP 行为当前不一致：  
  - `DNSSTREAM.STOP` 发送 `OK`：`src/Control.cpp:1566`
  - `PKTSTREAM.STOP` 无响应：`src/Control.cpp:1582`
  - `ACTIVITYSTREAM.STOP` 无响应：`src/Control.cpp:1596`
- 兼容/落盘：OpenSpec multi-user 还要求“旧 stream restore 兼容（至少 DNS 流旧事件默认 user 0）”；当前代码也做了这一点：`src/DnsRequest.cpp:70`。  
  参考：`openspec/specs/multi-user-support/spec.md:196`、`openspec/specs/multi-user-support/spec.md:201`
- fusion 文档同时主张“允许升级丢弃历史缓存文件/删除遗留落盘 stream 文件”。  
  参考：`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:362`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:385`
- **规格层的缺口**：既有 OpenSpec `openspec/specs/pktstream-observability/spec.md` 目前未描述 `type` envelope / NOTICE（suppressed/dropped）事件；`docs/INTERFACE_SPECIFICATION.md` 也仍按旧 schema 展示示例。若 vNext 要落地，需同步更新这些“单一真相”，否则会出现“实现/设计已升级，但权威 spec 仍旧”的文档打架。

**需要你裁决的问题**
- D4（已裁决）：升级 **整个** control 协议（不仅限 stream）；需补充 framing/versioning/compat 细节（见 0.6）。
- D5（已裁决）：`PKTSTREAM.STOP`/`ACTIVITYSTREAM.STOP` 改为 **有响应**（JSON ack；至少对齐 `DNSSTREAM.STOP`）。
- D6（已裁决）：按 fusion 文档走“**不兼容** + **删除遗留落盘/兼容 restore**”；需同步修订 OpenSpec/接口规范中关于 restore/兼容的承诺。

---

### 1.3 `tracked`：默认值与持久化策略冲突（fusion 文档 vs 代码/接口）

**文档主张（fusion）**
- `tracked` 默认 `false`
- `tracked` 持久化（D8）：daemon 重启后保持原值；默认 `tracked=false`；前端显式开启 tracked 时必须提示“可能带来性能影响”。
- `tracked` 只 gating 逐条事件 + heavy stats，不 gating always-on counters  
  参考：`docs/archived/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md:403`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:354`

**现有实现**
- `_tracked` 默认 `true`：`src/App.hpp:51`
- `tracked` 会落盘（App saver 会保存/恢复）：`src/App.cpp:233`、`src/App.cpp:262`

**需要你裁决的问题**
- D7（已裁决）：接受“默认 tracked=false”这个对外行为变化。
- D8（已裁决）：`tracked` **持久化**（与现代码一致），但前端需明确提示用户“开启跟踪/统计可能影响性能”（tracked 含义已扩展到更重的统计，如延迟等）。

**落盘后的文档自洽性问题（已同步修订）**
- 已将本目录内关于 “tracked 不持久化/observability 默认不持久化” 的表述修订为：`tracked` 属于 **observability config** 且需持久化；stream/ring/queue 属于 **observability session state** 且不持久化。

---

### 1.4 IPRULES apply 契约：`matchKey`/字段类型与现有 v1 契约冲突

**apply 契约（fusion）当前写法**
- `matchKey` 格式 `mk1|...|ifindex=0|...`，且明确 `ifindex=0` 为 any 的 canonical。  
  参考：`docs/archived/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md:77`、`docs/archived/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md:90`、`docs/archived/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md:103`
- 冲突示例中 `enabled/enforce/log` 已统一为 `0|1`（与 `IPRULES.PRINT` 保持一致）。  
  参考：`docs/archived/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md:132`

**现有 v1 “单一真相”（OpenSpec + 接口规范 + 实现）**
- IPRULES v1 规定 `ifindex` 在 PRINT 中是 JSON number，`0` 表示 any；并且 toggle 输出为 `0|1` number。  
  参考：`openspec/specs/app-ip-l3l4-rules/spec.md:431`、`openspec/specs/app-ip-l3l4-rules/spec.md:456`
- 实现也符合：`IPRULES.PRINT` 输出 `ifindex` 数字：`src/Control.cpp:1217`；toggle 使用 `JSB()`：`src/sucre-snort.hpp:15`

**需要你裁决的问题**
- D9（已裁决）：`ifindex=0` 与 `ifindex=any` 视为 **等价**；两种写法均可接受（建议选一个 canonical 形式输出/存储以减少困惑）。
- D10（已裁决，原则）：在 D9 前提下尽量统一表示/类型；重点是让前端能清晰解释日志/输出。建议优先与既有 `PRINT/OpenSpec` 对齐（numbers），但如需为了可解释性做微调也可接受。

**文档内部不自洽点（已按 D12 修订）**
- `docs/archived/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`：matchKey key 已统一为全小写；`ifindex=0` 作为 canonical；toggle 已统一为 `0|1`。

> 额外提醒：apply 契约要求 CIDR 网络地址归一化（如 `1.2.3.4/24 → 1.2.3.0/24`）。当前引擎解析不会做“写入时归零 host bits”（`src/IpRulesEngine.cpp:271`），但匹配语义本身通过 mask 仍正确。`matchKey` 若要做“等价去重/冲突检测”，就必须实现 canonicalizer（这是后续实现任务，不是现状 bug）。

---

### 1.5 `policySource` 对外命名：fusion 口径 vs 既有 OpenSpec/域名观测规格冲突（新增）

**fusion 文档主张**
- 禁止对外使用 white/black/global；统一收敛为 `ALLOWED/BLOCKED` 叙事，并把 device-wide 从 `GLOBAL_*` 改名为 `DOMAIN_DEVICE_WIDE_*`；且“不做 alias/双写”。  
  参考：`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:31`、`docs/archived/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md:239`
  - 命名直观性补充（你反馈）：`BLOCKED/AUTHORIZED` 相比 `BLACK/WHITE` 不直观；建议最终落地用 `ALLOWED/BLOCKED`（更直接；且 `authorized` 易被误解为“鉴权/权限”）。命令层（`BLACKLIST/WHITELIST/...`）可继续保留黑白心智，不必强绑到 `policySource` 的枚举值上。

**现有“单一真相”**
- `docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`：仍使用 `CUSTOM_WHITELIST/CUSTOM_BLACKLIST/CUSTOM_RULE_WHITE/CUSTOM_RULE_BLACK`（仅 device-wide 使用 `DOMAIN_DEVICE_WIDE_*`）。  
  参考：`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md:64`
- `openspec/specs/domain-policy-observability/spec.md`：仍使用 `CUSTOM_WHITELIST/CUSTOM_BLACKLIST/CUSTOM_RULE_WHITE/CUSTOM_RULE_BLACK/GLOBAL_AUTHORIZED/GLOBAL_BLOCKED/MASK_FALLBACK`。  
  参考：`openspec/specs/domain-policy-observability/spec.md:22`

**这会带来的问题**
- 如果 fusion 口径要落地且“不做 alias/双写”，就必须同步修改 OpenSpec + 既有域名观测规格（以及任何前端/测试）；否则会出现“同一字段在不同权威文档里枚举不一致”的硬冲突。
- 若不想在现阶段承担 breaking rename 的成本，则 fusion 文档里“禁止 alias/双写”需要撤销或改成“对外保持旧枚举，内部命名可重构”。

**需要你裁决的问题**
- D11（已裁决）：确认 `policySource` 是 breaking rename（white/black/global → authorized/blocked/domain_device_wide）；但暂不要求同步更新 `docs/archived/DOMAIN_IP_FUSION/` 目录外文档（先把融合讨论彻底完成，再拆 task/change 并统一更新 OpenSpec/接口规范/前端）。

---

## 2. P1 风险/缺口（不一定矛盾，但不锁死会难实现/难验收）

### 2.1 “禁止裸 USER 过滤”可能过度收紧
- 现有 spec 与实现把裸 `USER <userId>` 当作 list/stats 的核心能力；如果禁掉，需要明确替代方案（否则会明显降低可用性）。  
  参考：`docs/INTERFACE_SPECIFICATION.md:68`、`src/Control.cpp:563`
（已裁决：见 2.20 / D30 + 2.20.2：vNext 采用“逐命令白名单”）

### 2.2 Stream drop/queue/ring 的口径尚未锁死
- “drop newest vs drop oldest”、`droppedEvents` 的计数口径（按事件/按条/按 bytes）、NOTICE 的窗口边界等，需要在文档层锁死，否则实现与测试会摇摆。
- 你回复：这类缺口按既定原则把对应文档补齐即可（应不复杂）。
（已裁决：见 2.12 / D23）

### 2.3 IPRULES 原子 apply 没锁死 ruleId/stats 的策略

（已裁决：见 2.13 / D27，且已同步进 `docs/archived/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`）

- apply 是 replace 语义，但仍需裁决：ruleId 是否复用/如何映射（例如是否按 `clientRuleId` 稳定映射）、apply 后 per-rule stats 是否全清零等。否则容易与现有 v1 的“ruleId 稳定性”契约冲突。  
  参考：`openspec/specs/app-ip-l3l4-rules/spec.md:202`
- 你回复：需要按“融合之后的原则”决定；接下来可专题讨论。

### 2.4 多用户下 `(name -> App)` 单键索引的实现陷阱
- 当前 `AppManager` 仍维护 `name -> App` 的 map：`src/AppManager.hpp:24`。在多用户同包共存时天然非唯一；selector 的“歧义拒绝 + candidates”如果要做对，需要明确实现侧改造要求（例如 key=(userId,name) 或对 STR selector 改为扫描+拒绝）。  
- 现状实现层面的“额外坑”（需要设计文档显式承认并给出落地方向，否则 D3 很难落干净）：
  - `AppManager::findByName(name, userId)` 只做 **canonical name 精确匹配**（不匹配 alias/`allNames`）：`src/AppManager.cpp:30`
  - `_byName` 是 `std::map<string, App>`，key 只有 name：同名 package 跨 user 时，后插入的 app 会被 **直接丢失**（`emplace` 不会覆盖），导致 `APP.NAME` 列表不全：`src/AppManager.cpp:55`、`src/AppManager.cpp:225`
  - 现有 `printAppList(..., subname)` 的 substring filter 也只基于 `app->name()`；如果 vNext 文档允许 `<pkg>` 匹配 `allNames`，那么“谁算 candidates / 谁算 matchedName”必须被明确定义（否则前端无法稳定解释）：`src/AppManager.cpp:264`
- 你补充：这个单键映射最初用于“工程还不支持多用户”时的兼容；在引入多用户后，语义等价于 `userId=0` 下的映射（后续如有疑问可专题讨论）。

### 2.5 “双形态命令（global vs app-specific）”会放大 selector 语法歧义

（已裁决：见 D16 + 2.18.1 / D28：vNext 必须使用 `APP/DOMAIN/RULE` Fully-spelled 语法树）

这部分不是“命令名字/协议 framing”的问题，而是**语法树的歧义**：同一个 `CMD` 的第一个参数既可能是 domain/ruleId，也可能是 app selector（且 selector 自身又可能包含 `USER <userId>` 子句）。在 D1/D2/D3 放宽/收敛后，这类命令会成为最先踩雷的一组。

#### 2.5.1 受影响命令族（当前代码事实）
- custom domains（domain list）：
  - `BLACKLIST.ADD/REMOVE`、`WHITELIST.ADD/REMOVE`：dual-form（global vs app-specific，靠“是否存在第二个参数”分支）。  
    参考：`src/Control.cpp:1717`、`src/Control.cpp:1754`
  - `BLACKLIST.PRINT`、`WHITELIST.PRINT`：optional selector（不是真 dual-form，但同样会被 D2 的裸 `USER` 语法污染）。  
    参考：`src/Control.cpp:1753`
- custom rules（rule list）：
  - `BLACKRULES.ADD/REMOVE`、`WHITERULES.ADD/REMOVE`：dual-form（global vs app-specific）。  
    参考：`src/Control.cpp:1784`
  - `BLACKRULES.PRINT`、`WHITERULES.PRINT`：app-specific only（也会受 selector 解析/严格拒绝策略影响）。  
    参考：`src/Control.cpp:1829`
- 共同点：都通过 `readAppArg()` 读取“可能是 selector 的第一个参数”。  
  参考：`src/Control.cpp:556`

#### 2.5.2 当前实现的核心歧义点（为什么放大）
`readAppArg()` 当前支持三种“第一参数形态”：
1) `<uid>`（INT）：直接视为 app selector（userId 从 uid 派生）  
2) `<pkg>`（STR）：可带 `USER <userId>` 子句；缺省 `userId=0`  
3) **裸 `USER <userId>`**：被解析成“无 app，但带 user-filter”（`parg.arg=NONE, parg.hasUserClause=true`）

而 `BLACKLIST.ADD/REMOVE`、`BLACKRULES.ADD/REMOVE` 的 dual-form 逻辑又是：
- `parg = readAppArg(...)`
- `x = readSingleArg(...)`（x 是 domain 或 ruleId）
- 若 `x` 不存在 → 走 global 分支；若 `x` 存在 → 走 app-specific 分支

因此会出现两类“非常危险”的误判：
- **漏写最后一个参数** 会从 app-specific **掉回** global 分支（而且还会 `OK`）。  
- 裸 `USER <userId>` 会被当成“selector 的一种形态”，但这些命令本身并没有 user-filter 语义，于是变成 silent no-op / 甚至对空字符串生效。

#### 2.5.3 典型踩雷输入（vNext 必须严格拒绝；不能 silent OK）
（以下示例均基于当前实现可推导出的行为；在 vNext 应统一改为结构化 `SYNTAX_ERROR/INVALID_ARGUMENT/SELECTOR_NOT_FOUND`）

1) **用户本意是 app-specific，但漏写 domain/ruleId**
- `BLACKLIST.ADD com.example.app USER 10`  
  - 当前：因为“没有第二参数”，会走 global 分支，把 `com.example.app` 当作 domain 去加全局列表（语义错位，且 `OK`）。  
  - 根因：dual-form 仅靠“第二参数是否存在”判定，而不是靠“用户是否显式进入 app-specific 语法”判定。
- `BLACKRULES.ADD com.example.app USER 10`  
  - 当前：走 global 分支但 `parg.arg` 是 STR，不满足 `ruleId` 期望类型；最终 silent no-op + `OK`。

2) **裸 `USER <userId>` 被错误接受**
- `BLACKLIST.ADD USER 10 example.com`  
  - 当前：进入 app-specific 分支，但 `arg2app(parg)` 为空 → silent no-op + `OK`。
- `BLACKLIST.PRINT USER 10`  
  - 当前：`parg.arg=NONE` → 打印全局 list（忽略 userId），且不会报错。  
  - 与 D2/D3 冲突：`USER <userId>` 不是“全局可加的语法糖”，必须逐命令定义；未定义则必须报错。

3) **D1 的 `<pkg> <userId>` 简写在 ruleId 为 INT 的命令上天然不安全**
- `BLACKRULES.ADD com.example.app 10 42`（用户想表达 userId=10, ruleId=42）  
  - 若允许 `<pkg> <userId>` 简写：第二个 INT “10” 既可能是 userId，也可能是 ruleId，必然歧义。  
  - 结论：`*RULES.*` 这类“selector 后面还有 INT 参数”的命令，应继续强制显式 `USER`（与 D1 的受限简写原则一致）。

#### 2.5.4 推荐解法（强烈推荐：显式消歧，而不是继续靠 token 个数猜）
目标：让“global vs app-specific”成为**可被机器稳定解析**的语法分支，同时与 D3 的严格拒绝一致。

推荐 vNext 语法（示例；关键在显式 keyword）：

- custom domains：
  - global：`BLACKLIST.ADD DOMAIN <domain>` / `WHITELIST.ADD DOMAIN <domain>`
  - app-specific：`BLACKLIST.ADD APP <uid|pkg> [USER <userId>] <domain>`
  - 对应 remove/print 同理（`REMOVE`/`PRINT`）
- custom rules：
  - global：`BLACKRULES.ADD RULE <ruleId>` / `WHITERULES.ADD RULE <ruleId>`
  - app-specific：`BLACKRULES.ADD APP <uid|pkg> [USER <userId>] <ruleId>`

好处：
- 彻底消除“漏参数掉回 global”“裸 USER 被吃掉”等误判路径。
- 对齐现有风格：仓库里已有 `IPRULES.PRINT [UID <uid>] [RULE <ruleId>]` 这类 keyword 消歧模式。
- 让 D1/D2 变成“语法层明确可控”：  
  - `APP <pkg> <userId>` 是否允许简写，变成局部决策；  
  - 裸 `USER <userId>` 在这类命令里可直接判为 `SYNTAX_ERROR`。

代价：
- 这组命令在 vNext 上会有语法变更（但我们已经有 vNext endpoint + 计划下线 legacy endpoint，整体迁移成本可控）。

#### 2.5.5 备选（不引入新 keyword，但必须加硬约束；否则无法满足 D3）
如果坚持保留现有形式（例如 `BLACKLIST.ADD [<selector>] <domain>`），则至少要在 vNext 规定：
- 一旦解析到 selector（尤其出现 `USER <userId>` 子句），就**必须**要求剩余参数完整；缺参必须报错，禁止回退到 global 分支。
- 裸 `USER <userId>` 在本命令族必须报 `SYNTAX_ERROR`（这些命令没有 user-filter 语义）。
- 对 `*RULES.*`：继续不允许 `<pkg> <userId>` 位置简写（与 D1 “selector 后接 INT”冲突）。

#### 2.5.6 已裁决（采用方案 A）
- vNext 为该命令族引入显式 keyword 消歧：`APP/DOMAIN/RULE`（不改变表达能力，彻底无歧义）。
- global 分支也强制显式（避免“uid 被当 ruleId/域名”等危险输入）。
- 该命令族禁止裸 `USER <userId>`（无 user-filter 语义；必须先进入 `APP <selector>` 分支）。

### 2.6 stream `*.START` 的“启动确认”与 started NOTICE（收敛后口径）

- 方案 D（netstring + JSON envelope）下：`*.START` 会先返回 response frame（`{"id":...,"ok":true}`），因此不会再出现“无流量=无任何输出”的解析歧义。
- 仍保留 `type="notice", notice="started"`（不进 ring、不回放、不落盘），用于：
  - 明确 session 已进入 running；
  - echo clamp 后的实际 `horizonSec/minSize`（避免前端误解）。

### 2.7 vNext 控制面：必须锁死“每条 request 恰好 1 个 response frame”的硬约束

现状代码里，“命令无响应（server 完全不写 socket）”并不是少数边角，而是一个系统性模式；这也是 D4 要升级整个 control 协议的根因之一。

**现状证据（legacy）**
- `QUIT`：只设置标志位，不写任何响应，见 `src/Control.cpp:674`。
- `TOPACTIVITY`：只更新状态，不写任何响应，见 `src/Control.cpp:1699`。
- `DNSSTREAM.START/PKTSTREAM.START/ACTIVITYSTREAM.START`：不写 `OK`，完全依赖后续事件流，见 `src/Control.cpp:1558`、`src/Control.cpp:1574`、`src/Control.cpp:1589`。
- `PKTSTREAM.STOP/ACTIVITYSTREAM.STOP`：不写 `OK`，见 `src/Control.cpp:1582`、`src/Control.cpp:1596`（DNS 的 STOP 反而会写 `OK`，见 `src/Control.cpp:1566`）。
- 还有一类更危险：**GET 模式遇到“selector 不存在”会导致“无任何输出”**，例如：
  - `BLOCKMASK <uid|pkg>`：app 不存在则不输出，见 `src/Control.cpp:1464`。
  - `BLOCKIFACE <uid|pkg>`：app 不存在则不输出，见 `src/Control.cpp:1506`。
  - `APP.CUSTOMLISTS <uid|pkg>`：app 不存在则不输出，见 `src/Control.cpp:1654`。

**这会如何伤害 vNext**
- 如果 vNext 允许“某些 request 没有 response frame”，客户端仍无法区分：  
  `请求未被处理 / 请求被处理但返回空 / server 崩了 / 协议不匹配 / 网络断了`。
- 这会把“解析可靠性”拉回到 legacy 的“靠超时猜测”。

**vNext 硬约束（已确认；D19）**
- 除 streams 事件流外：每条 request 必须返回且仅返回 1 个 response frame（成功或失败）。
- 对于 `*.START`：除 response frame 外，必须额外输出 1 条 `notice="started"` event（见 2.6）。
- “selector 不存在”的 GET/SET：必须返回结构化错误（`SELECTOR_NOT_FOUND`），禁止“空输出”。

### 2.8 stream 的 ring buffer / queue 与“多连接”语义目前存在潜在自相矛盾（已裁决：方案 A）

当前 working decisions 同时写了两条容易冲突的原则：
- `*.START` 的回放参数“不得影响已存在的其它连接/流”，见 `docs/archived/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md:208`（已按 2.8-A 修订为“不得影响其它 stream 类型”）。
- `*.STOP` 对 dns/pkt “清空 ring buffer；下次 START 视为全新 session”，见 `docs/archived/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md:198`。

如果允许**多个连接**同时订阅同一类 stream（dns/pkt），那“某个连接 STOP 清空 ring”会天然影响其它连接；除非我们其实只允许“同一时间最多一个订阅者/一个 session”。

**裁决（你确认，2026-04-16）**
- 采用方案 A：**同一时间每种 stream 只允许 1 条连接（1:1 前端↔后端）**。
  - 已有连接存在时，新的 `*.START` 返回 `STATE_CONFLICT`。
  - `*.STOP` 可以无条件清空 ring（因为没有其它订阅者被影响）。

**你提出的调试场景（前端在跑 + 想临时调配置）怎么解？**
- 2.8-A 的“1:1”**只限制 stream 订阅**，不限制 control 平面的并发连接：
  - stream 连接：长连接，只跑 `*.START/STOP` 与事件输出（避免输出交织）。
  - control 连接：短命令/单响应；允许另开连接并发下发配置与查询（即使 stream 正在运行）。
- 推荐模式：前端**天然就使用两条连接**（control + stream）；调试时再额外开第三条 control 连接（例如 adb/socat）临时改配置，不影响前端 stream。
- 只有一种能力会被 2.8-A 限制：当 UI 正在订阅 `PKTSTREAM/DNSSTREAM/...` 时，你无法再从外部开第二条同类 stream 来“旁路偷看事件”。（如果真需要，可在前端做 stream relay/tee，或者提供一个 bounded 的 `*.DUMP` 快照命令作为调试替代。）

**顺带回答你的问题：现有实现是否支持多连接？**
- 是的，现状实现允许多个连接同时订阅同一类 stream：
  - `Streamable<Item>` 内部维护 `std::unordered_map<SocketIO::Ptr, const bool> _sockios;`，`startStream()` 只是 `_sockios.emplace(sockio, pretty)`，没有做“仅允许 1 个订阅者”的限制，见 `src/Streamable.hpp:17`、`src/Streamable.cpp:53`。
  - control 本身也允许很多 client 连接并发：每个 accept 都 `std::thread(... clientLoop ...)`，见 `src/Control.cpp:216`、`src/Control.cpp:336`。

因此 vNext 的“单连接”不是现状已有行为，而是**明确的 vNext breaking 约束**（需要落到实现：第二个订阅者必须报 `STATE_CONFLICT`）。

**为什么 legacy “看起来没遇到这些问题”？（解释）**
- 现实使用上往往天然是 1:1：前端通常只开一条 stream 连接，不会同时再开第二条订阅者；因此“多订阅者互相影响”的坑没有被触发。
- legacy 当前也**没有**把“STOP”定义成“清空 ring / 新 session”：  
  `Streamable<Item>::stopStream()` 只是把订阅者从 `_sockios` 移除，并不会清空 `_items` ring，见 `src/Streamable.cpp:70`。  
  这使得多订阅者场景下，即便某个连接 STOP，也不会破坏其它订阅者的 replay/ring 语义。
- legacy 的 framing 是“每条消息 NUL 结尾”（而不是 NDJSON/LF），即使事件与命令响应穿插，客户端也更容易按 NUL 边界解析；因此“输出交织”更多是**状态机/UI 心智**问题，不一定会变成解析层面的立即故障。

> vNext 之所以必须把这些写死，是因为 vNext 同时引入：NDJSON/LF、结构化错误、STOP JSON ack、以及我们计划新增的“STOP 清 ring / session”语义；这些叠加后，多订阅者会变成设计与实现复杂度的大头。

### 2.9 `*.STOP` 的 ack 顺序与“ack 后不得再有事件”需要写进契约（否则仍可能交织）

即便我们禁止“stream 连接跑非 stream 命令”，`*.STOP` 本身也要返回 `{"ok": true}`。因此必须明确：
- `*.STOP` 处理完成后，**`{"ok":true}` 必须是该连接上该 stream 的最后一行输出**；ack 之后不得再出现任何该 stream 事件（包括被排队的旧事件）。
- 为了达成上面这一点，`STOP` 必须“先停止生产 + 清空该连接 pending queue + 再写 ack”（或者等价的顺序保证）。

否则前端会遇到：`STOP` 收到 `{"ok":true}` 之后仍刷出几行旧事件，导致状态机与 UI 提示混乱。

**裁决（你确认，2026-04-16；方案 B）**
- `*.STOP` 作为 ack barrier：
  - 先禁用该连接的订阅（后续事件不得再入该连接队列）
  - 清空该连接 pending queue（允许丢弃尾部未发送事件/notice）
  - （dns/pkt）按既定语义清空 ring（定义新 session 边界）
  - 再输出 `{"ok":true}`，并保证这是该 STOP 的**最后一行**
  - ack 后不得再输出任何事件/notice，直到下一次 `*.START`

### 2.10 NDJSON 的前提是“输出必须是严格 JSON”；但当前代码的 JSON string 并不做 escape（实现风险）

vNext 文档把 control/stream 的 framing 升级为 NDJSON，并强调“每一行必须是有效 JSON”。这个目标要落地，还需要补一个“被现代码隐藏的前提”：

- 当前代码的 JSON 字符串拼接宏是：
  - `#define JSS(s) "\"" << s << "\""`，不做任何转义，见 `src/sucre-snort.hpp:13`。
- 这意味着：只要字符串里出现 `"`、`\`、`\n`、`\r` 等字符，就会立刻产生**非法 JSON**；而这类字符在某些字段中并非不可能（尤其是规则/文本类字段）。
- 现状之所以“基本能用”，主要是因为当前输出字段大多来自 package/domain/IP 等受限字符集；但 vNext 的 `HELP`（你已确认要返回 `{"help":"...\\n..."}`）本身就需要正确 escape，否则会直接破坏 NDJSON 的行边界。

**建议补一条实现前置约束（需要你确认，但我强烈建议写进 vNext 文档）**
- vNext 必须引入**统一的 JSON string encoder**（正确处理 `\" \\ \n \r \t` 等），并把所有对外 JSON 输出从“手写拼接”迁移到该 encoder（或切到成熟 JSON 库）。
- 或者（不推荐）：把对外协议降级为“JSON-ish（字符串不转义）”，同时把所有字符串字段的允许字符集写死为安全子集（这会很难长期保证，也会与 `HELP` 目标冲突）。

> 这是 NDJSON 能否成立的基本前提，否则“新 framing + 新解析器”会在极端输入下直接崩。

**裁决（你确认，2026-04-16；方案 A）**
- vNext 必须实现统一 JSON string encoder，并强制用于所有对外 NDJSON 输出（control 响应 + stream 事件 + `HELP`），确保每一行都是严格 JSON；禁止 raw newline 破坏分帧。

### 2.11 vNext 的“严格拒绝”需要覆盖：trailing tokens + silent no-op（否则仍不自洽）

现状控制面有大量“成功但什么也没做”的路径，或者“输入多了/错了仍然 OK/无输出”的路径；如果 vNext 要作为新的单一真相（D3），这些必须在协议层收敛为一致规则。

**现状证据（silent no-op / 或者无输出）**
- `TRACK/UNTRACK`：先 `OK`，但 app selector 找不到时什么也不做，见 `src/Control.cpp:1540`。
- `CUSTOMLIST.ON/OFF`：先 `OK`，但 app selector 找不到时什么也不做，见 `src/Control.cpp:1708`。
- `BLACKLIST.ADD/REMOVE`（app-specific 分支）：先 `OK`，但 app selector 找不到时什么也不做，见 `src/Control.cpp:1717`、`src/Control.cpp:1740`。
- 多个 GET 命令在 selector 不存在时会“写 0 行”（2.7 已列出部分例子）。

**隐患**
- 用户/前端无法区分：命令成功生效 vs 目标不存在/没生效。
- 这会直接破坏“严格错误模型 + 可修复错误”的目标（D3）。

**建议给 vNext 加两条全局规则（强烈建议写入 control vNext 文档）**
1) **trailing tokens 一律报错**：命令解析完成后若还有未消费 token → `SYNTAX_ERROR`（防止拼错参数/多打一段导致 silent ignore）。
2) **mutate 命令禁止 silent no-op**：凡是“写配置/改状态”的命令：
   - selector 不存在 → `SELECTOR_NOT_FOUND`
   - selector 歧义 → `SELECTOR_AMBIGUOUS` + `candidates[]`
   - 禁止“OK 但没改任何东西”

> “list/filter 类命令输出空集合”可以保留，但必须明确它们属于“查询过滤”，而不是“唯一 selector 目标”。

**裁决（你确认，2026-04-16；方案 A）**
- 采纳上述两条规则作为 vNext 全局约束：
  - trailing tokens 一律 `SYNTAX_ERROR`
  - mutate 命令禁止 silent no-op（含非法/不完整的 `USER` 子句：必须报 `SYNTAX_ERROR`，禁止像现状那样“恢复位置/吞掉当没发生”）

### 2.12 dropped/backpressure 的 drop 策略与 `droppedEvents` 口径（已锁死；避免实现摇摆）

当前文档已经承诺了 `notice="dropped"`，但尚未锁死以下细节：
- drop policy：queue 满时 drop oldest 还是 drop newest？
- `droppedEvents` 口径：按“事件条数”计，还是按“输出行数/bytes”计？
- notice 的窗口边界：`windowMs=1000` 是固定窗口还是实际窗口？窗口内多次 drop 如何累加？

**建议（最小可实现、也最符合调试直觉）**
- pending queue 与 ring 都采用 **drop-oldest**（保留最新事件，避免越积越旧）。
- `droppedEvents` 固定为“被丢弃的逐条事件条数”（不按 bytes）；同窗口内累加。
- notice 频率继续维持“最多 1 条/秒/streamType”，并把 `windowMs` 写成实际聚合窗口（便于前端对齐 rate）。

> 在 2.8-A（单订阅者）前提下，这套口径更容易实现且不会引入 per-subscriber 分歧。

**裁决（你确认，2026-04-16；方案 A）**
- 锁死上述口径为 vNext 单一真相：drop-oldest；`droppedEvents` 按事件条数；`notice="dropped"` 1Hz/streamType 且输出实际 `windowMs`。

### 2.13 IPRULES 原子 apply 仍缺关键契约：`ruleId` 映射 + stats 生命周期 + PKTSTREAM 归因（否则前端难自洽）

`IPRULES_APPLY_CONTRACT.md` 已锁死 `clientRuleId/matchKey/conflicts[]`，但要让前端在“apply 后继续操作（UPDATE/ENABLE/REMOVE）”与“解释 PKTSTREAM 命中来源”时不需要瞎猜，还必须再锁死三件事：

- apply 成功后 `ruleId` 是否稳定 / 如何分配 / 是否回传映射
- apply 对 per-rule stats 的 reset 规则
- PKTSTREAM 事件里需要哪些字段做归因（只给 ruleId 是否足够）

现有代码事实：
- `UPDATE` 会 reset 该 rule 的 stats；`ENABLE 0->1` 会 reset stats：`src/IpRulesEngine.cpp:1244`、`src/IpRulesEngine.cpp:1275`。
- `ruleId` 是当前引擎对外“可操作”的唯一句柄（UPDATE/REMOVE/ENABLE），并且 PKTSTREAM 会输出 `ruleId/wouldRuleId`。

#### 2.13.1 apply 的 `ruleId` 策略（已确认：B）

A) `ruleId` 不承诺稳定（apply 可重新编号）
- 行为：每次 apply 重新给该 `<uid>` 的 ruleset 分配一批新的 `ruleId`（可以从 `0` 重启，也可以继续单调递增；需要再补一句口径）。
- 必须：apply 成功响应回传 `rules[]: [{clientRuleId, ruleId, matchKey}]` 映射（否则前端必须再 PRINT 扫一遍）。
- 优点：实现最简单；不需要在服务端维护 `clientRuleId->ruleId` 的长期映射。
- 缺点：持续 PKTSTREAM 场景下会出现“同一条 UI 规则的 ruleId 变来变去”；若 ruleId 被复用（例如每次从 0 开始），还会产生跨时间归因歧义（除非同时引入 epoch/version）。

B) `ruleId` 对 `clientRuleId` 稳定复用（推荐）
- 行为：同一 `<uid>` 下，若 apply payload 中某条 `clientRuleId` 在当前 ruleset 已存在，则复用其原 `ruleId`；新增 `clientRuleId` 才分配新 `ruleId`（继续 `_nextRuleId++`）；被删除的 `ruleId` 不被复用。
- 必须：apply 成功响应同样回传 `rules[]` 映射（前端可用来校验/刷新本地缓存）。
- 优点：对 PKTSTREAM/调试最友好；也最贴近既有 OpenSpec “ruleId 稳定”的心智；避免 ruleId 复用带来的时间歧义。
- 缺点：实现需要在规则结构里引入并持久化 `clientRuleId`；apply 逻辑需要做一次 join。

#### 2.13.2 apply 的 stats reset 规则（已确认：B）

前置：现有增量语义是 `UPDATE` 一律 reset stats，`ENABLE 0->1` reset stats。

A) apply 成功后：该 `<uid>` 下 **全量 reset stats**（最简单）
- 优点：实现简单；语义“apply 是新基线”直观。
- 缺点：如果前端/脚本做“幂等 apply”（同一份配置重复下发），stats 会被频繁清零，影响观察体验。

B) apply 成功后：按 `clientRuleId/ruleId` 逐条决定（推荐）
- 新增 rule：reset stats
- 删除 rule：stats 消失
- 复用 ruleId 且规则定义完全一致：保留 stats
- 复用 ruleId 但规则定义变化：reset stats（对齐 UPDATE 心智）
- 优点：对幂等 apply 友好；不会因“重发同配置”把数据抹掉。
- 缺点：实现稍复杂（需要比较 RuleDef）。

#### 2.13.3 PKTSTREAM 归因字段（已确认：A）

A) 继续只输出 `ruleId/wouldRuleId`（推荐，性能最好）
- 前提：2.13.1 需要选 B（ruleId 稳定复用）或引入额外 epoch/version，否则 UI 很难做可靠 join。

B) PKTSTREAM 事件额外回显 `clientRuleId`
- 优点：前端无需 join；解释最直接。
- 缺点：每包多一段 string，输出/解析成本明显上升（高频流会痛）。

**我的建议（推荐组合）**
- 2.13.1：选 B（`ruleId` 对 `clientRuleId` 稳定）
- 2.13.2：选 B（幂等 apply 不清 stats）
- 2.13.3：选 A（pkt 只带 `ruleId`；避免每包 string）

**裁决（你确认，2026-04-16）**
- 2.13.1：B
- 2.13.2：B
- 2.13.3：A

### 2.14 control vNext endpoint 的“地址形态/权限/并存策略”需要补一句（否则实现阶段容易走偏）

D4 已锁死了 vNext endpoint 的“名字与端口”（`sucre-snort-control-vnext` / `60607`），但实现上还隐含了几个必须讲清的点：

**现状实现的 endpoint 形态很特殊**
- 生产路径依赖 init.rc 的 RESERVED socket（`android_get_control_socket()`）：`src/Control.cpp:197`。
- DEV fallback 会同时暴露 filesystem socket + abstract socket：`src/Control.cpp:225`。
- TCP control server 只有在 `inetControl()` 为 true 才会启动（由 `/data/snort/telnet` 文件控制）：`src/Control.cpp:191`、`src/Settings.hpp:24`、`src/Settings.hpp:148`。
- 另外一个“隐藏耦合”：当 `inetControl()` 开启时，PacketListener 会**豁免**当前 `controlPort(60606)` 的 TCP 流量不走 blocking/streaming（避免把控制面 traffic 自己拦了）：`src/PacketListener.cpp:351`。
  - 这意味着：如果 vNext 真的启用 `60607`，但不做对应豁免，那么在开启 blocking 的情况下，**vNext 的 TCP control 很可能被当作普通流量拦截/影响**（尤其是 debug 场景）。

#### 2.14.1 DEV fallback（abstract socket）策略（已确认：A）

A) vNext 在 DEV fallback 也暴露 filesystem + abstract 两种地址（推荐）
- `/dev/socket/sucre-snort-control-vnext`（filesystem）
- `@sucre-snort-control-vnext`（abstract）
- 优点：socat/nc/adb 调试与旧生态最兼容；与 legacy 的调试习惯一致。
- 缺点：地址形态更多；需要避免 client 误连 legacy（但名字不同已足够区分）。

B) vNext 在 DEV fallback 只暴露 filesystem socket
- 优点：形态更少；实现更简单。
- 缺点：如果某些调试/历史客户端只支持 abstract，会需要额外适配。

#### 2.14.2 TCP 60607 的 gating 策略（已确认：A）

A) 60607 与 legacy 一样受 `inetControl()` gating（推荐）
- 即：只有 `/data/snort/telnet` 存在时才启动 TCP server。
- 优点：不扩大默认攻击面；迁移期风险更小。

B) 60607 默认启动（不受 gating）
- 优点：外部工具更容易连。
- 缺点：默认暴露额外端口；与现有安全边界不一致。

#### 2.14.3 PacketListener 对 control port 的豁免（必须补齐；已确认：A）

A) 当 `inetControl()` 开启时，同时豁免 60606 与 60607（推荐）
- 理由：迁移期可能双端口并存；否则调试 vNext 时会出现“端口开了但连不上/被拦了”的错觉。

B) 当 `inetControl()` 开启时，仅豁免当前实际启用的 control port
- 优点：更精确。
- 缺点：实现上需要知道“哪个端口已启用”（迁移期可能两者都启用）；更容易踩坑。

**我的建议（推荐组合）**
- 2.14.1：A（DEV fallback 双栈）
- 2.14.2：A（受 `inetControl()` gating）
- 2.14.3：A（豁免 60606+60607）

> 这条不是“协议语义”，但它决定了 vNext 在真机/调试/迁移期是否会频繁遇到“客户端连不上/连错”的定位成本。

**裁决（你确认，2026-04-16）**
- 2.14.1：A
- 2.14.2：A
- 2.14.3：A

### 2.15 vNext request framing=LF 后，服务端必须改成“按行解析 + 支持 partial read”（否则仍会偶发卡死/误解析）

现状 `Control::clientLoop()` 是“一次 `read()` 就当成一条完整命令”，并且把 buffer 当 C-string 用（遇到 NUL 就截断），见 `src/Control.cpp:412`。  
这对 legacy 的“每条命令 NUL 结尾 + 客户端每次只发一条”还能勉强工作，但对 vNext 的 LF framing：

- 如果一次 read 收到半行（常见），就会误判为截断/无效命令。
- 如果一次 read 收到多行（也常见），后续行会被吃掉（因为只解析第一条）。

因此 vNext 实现必须显式改为：buffer 累积 → 按 `\\n` 切行 → 逐行解析（并处理 `\\r\\n`）。

同时注意：现有 `SocketIO::print()` 会在每次 write 时附带 NUL terminator（`size()+1`），见 `src/SocketIO.cpp:27`。vNext 如果采用 LF framing，则 output 路径也必须分离或重写，避免把 NUL 混入 NDJSON。

#### 2.15.1 空行/多行的处理（已确认：A）

A) 空行视为 no-op（返回 `{"ok":true}`），多行逐行处理（推荐）
- 优点：更适配交互式调试（不小心多敲回车不会进入错误状态机）。
- 缺点：更宽松；但不影响“mutate 禁 silent no-op”（空行不是 mutate）。

B) 空行返回 `SYNTAX_ERROR`，多行逐行处理
- 优点：更严格（有利于发现 client bug）。
- 缺点：交互体验更差；并且空行并不一定是 bug（例如某些 transport 会产生 keepalive newline）。

**我的建议**
- 2.15.1：A（空行 no-op，仍返回一行 JSON）

> 这属于“协议升级的实现前置条件”，否则 vNext 会出现“偶发卡死/偶发命令丢失”，很难定位。

**裁决（你确认，2026-04-16）**
- 2.15.1：A

### 2.16 QUIT/STOP 等“连接级命令”的响应与关闭顺序需要在 vNext 写死（避免客户端状态机摇摆）

现状：
- `QUIT` 没有任何响应，直接 close 连接，见 `src/Control.cpp:674`。
- `*.STOP` 在 legacy 中行为不一致（DNS 有 OK，PKT/ACTIVITY 无响应）。

vNext 如果要做到“可靠解析 + 明确状态机”，需要把连接级命令也纳入“每请求必有一行 NDJSON 响应（D19）”的约束。

#### 2.16.1 QUIT 在 vNext 是否保留（已确认：A）

A) 保留 `QUIT`（推荐）
- 语义：`QUIT` 返回 `{"ok":true}`，然后 server 主动 close 连接。
- 优点：交互式/脚本更明确；可以把“收到 ack”作为完成条件。
- 备注：即使 client 也可以直接 close socket，保留 `QUIT` 仍然有价值（尤其是在“半双工/不方便主动 close”的客户端封装里）。

B) vNext 废弃 `QUIT`（只靠 client close）
- 语义：发送 `QUIT` → `SYNTAX_ERROR`（或 `INVALID_ARGUMENT`）。
- 优点：状态机更小。
- 缺点：交互式调试不方便；以及 legacy 迁移时更容易踩“发送 QUIT 但没响应”的坑（与 D19 目标相悖）。

#### 2.16.2 STOP/连接 close 的资源释放（已部分裁决；补一句即可）

- `*.STOP`：已按 2.9-B 裁决为 ack barrier（STOP 的最后一行输出 `{"ok":true}`；ack 后不得再输出事件/notice）。
- client 直接断开连接（FIN/RST）：server 必须视为“该连接上的订阅已结束”，并释放该连接的订阅状态与 pending queue（允许丢尾部事件）；不需要额外 ack（因为连接已不存在）。

**我的建议**
- 2.16.1：A（保留 QUIT，并 ack 后 close）

**裁决（你确认，2026-04-16）**
- 2.16.1：A

### 2.17 `*.START <horizonSec> <minSize>` 的“回放”在 vNext 组合决策下可能变成弱语义（已裁决：A）

现状（代码事实）下，`DNSSTREAM/PKTSTREAM.START` 的 horizon/minSize 之所以有意义，是因为：
- `Streamable::stream()` 会**无条件**把事件 push 进 ring（即使从未 `*.START`、也没有订阅者），见 `src/Streamable.cpp:29`。
- `Streamable::startStream()` 会遍历 ring，把“时间窗内事件”∪“最近 minSize 条”回放给新订阅者，见 `src/Streamable.cpp:47`。

（此前）本目录 vNext 文档曾同时写了三条偏“性能优先/语义更干净”的决策，导致 horizon/minSize 变成弱语义：
- stream 关闭时不记录/不构造逐条事件与 ring
- `*.STOP` 对 dns/pkt 清空 ring，下次 `START` 视为全新 session
- 2.8-A：同一时间每种 stream 只允许 1 条连接订阅（单订阅者）

这三条叠加后，horizon/minSize 会出现“语义被削弱甚至近似无效”的风险：
- 如果“未 started 时不记录 ring”→ 那么**首次 START 的 replay 一定为空**（ring 没有历史），即使显式传了 horizon/minSize 也回放不到“START 之前”的事件。
- 单订阅者约束下，也无法用 horizon 支持“第二个订阅者 late-join 回放”（因为第二个订阅者 START 会直接 `STATE_CONFLICT`）。
- 若 STOP 清 ring 且 stopped 期间不记录 ring → 则“断开/重连/临时关闭 UI”期间发生的事件无法通过 horizon 回补。

**裁决（你确认，2026-04-16）**
- 采用方案 A：保留强 replay 语义；ring capture 与订阅解耦，但不引入新的 `CAPTURE/REPLAY` 命令：
  - `tracked` 是 capture gate：未 `tracked` 的 app 不构造逐条事件/不入 ring（无论是否订阅 stream）。
  - 对 tracked app：即使无订阅者也维护进程内 ring（不落盘），从而使 `*.START horizon/minSize` 在“首次 START/断线重连/UI 临时关闭”场景下仍有意义。
  - `*.STOP` 仍可清空 ring（定义 session 边界）；STOP 不改变 `tracked`，因此后续仍会继续 capture 新事件并积累 ring。
- 同步修订点：
  - 已同步修订 `OBSERVABILITY_WORKING_DECISIONS.md` / `DOMAIN_IP_FUSION_CHECKLIST.md`，删除/改写“ring 只在 stream 开启期间维护”的表述（避免与该裁决冲突）。

### 2.18 vNext：dual-form 命令族的“具体语法树”仍需锁死（避免实现期摇摆）

注（2026-04-17 已裁决方案 D）：vNext wire request 不再采用 token 命令语法，因此本节只作为 legacy endpoint 或 `sucre-snort-ctl` 的 CLI sugar 参考；vNext 命令面以 `CONTROL_COMMANDS_VNEXT.md` 为准。

D16 已经裁决了“dual-form（global vs app-specific）必须显式消歧”，但目前仍缺一个“落到命令行 token 层的最终语法”，否则：

- `HELP`/前端无法生成可靠提示（用户不知道该怎么写）。
- 实现阶段会反复争论“这个 token 到底是 domain 还是 selector”，进而引入临时兼容分支（破坏 vNext 的单一真相）。
- trailing tokens / mutate 禁 silent no-op 虽然能兜住错误，但无法避免“用户不知道正确写法”的体验问题。

受影响命令（当前代码事实）：
- custom domains：`BLACKLIST.*` / `WHITELIST.*`（ADD/REMOVE/CLEAR/PRINT）
- custom rules：`BLACKRULES.*` / `WHITERULES.*`（ADD/REMOVE/PRINT）

共同硬约束（已裁决，vNext 一致）：
- 禁止该命令族使用裸 `USER <userId>`（它们没有 user-filter 语义）。
- selector 采用 `<uid>` 或 `<pkg> [USER <userId>]`（受 D1/D2/D3/D22 约束）。
- trailing tokens 一律 `SYNTAX_ERROR`；mutate 禁 silent no-op。

#### 2.18.1 推荐最终语法（已确认：A）

A) Fully-spelled（推荐：更统一、更不易写错；global 分支也显式）

custom domains：
- `BLACKLIST.ADD DOMAIN <domain>`
- `BLACKLIST.ADD APP <selector> DOMAIN <domain>`
- `BLACKLIST.REMOVE DOMAIN <domain>`
- `BLACKLIST.REMOVE APP <selector> DOMAIN <domain>`
- `BLACKLIST.CLEAR DOMAIN`
- `BLACKLIST.CLEAR APP <selector>`
- `BLACKLIST.PRINT DOMAIN`
- `BLACKLIST.PRINT APP <selector>`
- `WHITELIST.*` 同构（把 BLACK 替换为 WHITE）

custom rules：
- `BLACKRULES.ADD RULE <ruleId>`
- `BLACKRULES.ADD APP <selector> RULE <ruleId>`
- `BLACKRULES.REMOVE RULE <ruleId>`
- `BLACKRULES.REMOVE APP <selector> RULE <ruleId>`
- `BLACKRULES.PRINT RULE`
- `BLACKRULES.PRINT APP <selector>`
- `WHITERULES.*` 同构

B) Compact（只在首个分支处显式，APP 分支里不再重复 `DOMAIN/RULE`）
- `BLACKLIST.ADD DOMAIN <domain>` / `BLACKLIST.ADD APP <selector> <domain>`
- `BLACKRULES.ADD RULE <ruleId>` / `BLACKRULES.ADD APP <selector> <ruleId>`
- 其它同理

**我的建议**
- 2.18.1：A（Fully-spelled）

**裁决（你确认，2026-04-16）**
- 2.18.1：A

### 2.19 多用户 selector：`<pkg>` 匹配范围、candidates[] 生成与实现数据结构需要锁死（数据结构专题）

这块是“文档已宣称，但实现上不可能自动得到”的典型缺口：D3 要求 `SELECTOR_AMBIGUOUS` 返回 `candidates[]`，且 2.5/2.11 要求严格拒绝；但当前实现存在两个硬事实：

- `AppManager::_byName` 的 key 只有 `name`（不含 userId），并且用 `emplace`：同包跨 user 同时存在时，后插入的 app **不会进 index**（`APP.NAME`/按名查找会丢失候选）。  
  参考：`src/AppManager.hpp:24`、`src/AppManager.cpp:55`
- `findByName(name,userId)` 仅匹配 canonical `app->name()`（不匹配 alias/`allNames`）；若未来要让 `<pkg>` 支持 alias，则必须补齐 `matchedName`/候选去重/歧义解释等规则。本轮已裁决 `<pkg>` **仅匹配 canonical**，因此该点选择与现实现保持一致。  
  参考：`src/AppManager.cpp:30`、`docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md:251`

因此如果不先锁死“selector 的匹配范围 + candidates 的构造规则 + index 结构”，实现阶段会出现：
- 文档承诺的 `candidates[]` 做不出来（或做出来但不全/不稳定）
- alias 匹配与“严格拒绝”互相打架（前端无法解释“为什么这个输入命中了/没命中”）

#### 2.19.1 `<pkg>` selector 的匹配范围（已确认：A）

A) 仅匹配 canonical `app`（推荐：最稳、最不易歧义）
- `<pkg>` 只等价于 `app->name()`（canonical pkg）。
- `allNames` 仅用于输出展示/列表，不参与 selector resolve。
- 优点：实现简单；歧义最少；对 D3 candidates 更容易做真。
- 缺点：用户若习惯用 alias，需要改用 canonical pkg 或直接用 `<uid>`。

B) 匹配 `canonical + allNames`（更友好但复杂；与本轮裁决相反）
- `<pkg>` 允许命中任意一个别名（`allNames`）。
- 必须补齐：
  - `matchedName` 回显规则（输入命中了哪个别名）
  - candidates 的去重规则（同一个 app 多个别名命中时只出现一次）
- 优点：更“用户友好”。
- 缺点：实现复杂；更容易出现 alias 冲突导致歧义；需要更严谨的 candidates 输出策略。

#### 2.19.2 candidates[] 的排序/稳定性（已确认：A）

A) 按 `uid` 升序排序（推荐）
- 优点：确定性强；实现简单；uid 也是最终可操作句柄。

B) 按 `userId` 升序、再按 `appId` 升序排序
- 优点：更贴近“多用户视角”。
- 缺点：仍需稳定 tie-break；实现复杂度略增。

#### 2.19.3 实现数据结构（已确认：A）

A) 彻底移除 `_byName` 作为“查找真相”，统一用 `_byUid` 扫描生成 candidates（推荐；control 不在热路径）
- 查找成本：O(number_of_apps)，但 control 命令量很低，且 vNext 本就强调“可解释性/可修复错误”优先。
- 优点：不会因为 index 丢 entry 造成候选不全；实现更不易出错。

B) 保留 name index，但改成多值结构（例如 `name -> vector<App>`，或 `(userId,name)->App` + alias 反向索引）
- 优点：按名查找更快。
- 缺点：实现更复杂；install/remove/upgradeName/restore 都要维护一致性；更容易出现“候选缺失但不自知”的 bug。

**我的建议（推荐组合）**
- 2.19.1：A（canonical only）
- 2.19.2：A（uid 升序）
- 2.19.3：A（用 `_byUid` 扫描做真相）

**裁决（你确认，2026-04-16）**
- 2.19.1：A
- 2.19.2：A
- 2.19.3：A

### 2.20 裸 `USER <userId>` 过滤：逐命令白名单需要补齐（D2 的“自洽”落盘）

D2 的裁决是“不再强行禁止裸 `USER <userId>`”，但 vNext 若要做到“严格拒绝 + 可修复错误”，仍需要一个可执行的规则，否则实现时会反复摇摆：

- 哪些命令把 `USER <userId>` 解释为 **filter**（并且输出可能为空是正常结果）
- 哪些命令遇到 `USER` 必须直接 `SYNTAX_ERROR`（避免 silent ignore 或误走 global 分支）

#### 2.20.1 推荐策略（已确认：A）

A) 白名单策略（推荐）
- 仅允许以下类型命令使用裸 `USER <userId>`：
  - device-wide list/stats（输出天然是集合/聚合）：`APP.*(LIST/PRINT/STATS/DOMAINS...)`、`DOMAINS.*`、`METRICS.*` 中明确标注支持者
- 其它所有命令（mutate、需要唯一 selector、dual-form 命令族等）遇到裸 `USER`：一律 `SYNTAX_ERROR`
- 优点：实现简单；可解释；不会误把 `USER` 吞成别的参数。

B) 全局允许（不推荐）
- 所有出现 selector 的地方都允许裸 `USER <userId>` 作为 filter 或默认 userId。
- 缺点：极容易制造语法树歧义；会逼迫大量“best-effort”分支，与 D3/D22 冲突。

**我的建议**
- 2.20.1：A（白名单策略）

**裁决（你确认，2026-04-16）**
- 2.20.1：A

#### 2.20.2 vNext 裸 `USER <userId>` 白名单（已确认）

> 目标：把 2.20.1 的“白名单策略”落到可执行规则，避免实现时摇摆。

**允许（user-filter；无 app selector 时）**
- `APP.UID [USER <userId>]`
- `APP.NAME [USER <userId>]`
- `APP.<stats/list>`（所有“device-wide 输出 app 列表/聚合 stats”的命令族，若保留到 vNext：允许 `...[USER <userId>]` 作为过滤器）

**禁止（遇到裸 `USER` 一律 `SYNTAX_ERROR`）**
- 所有 mutate 命令（例如 `TRACK/UNTRACK/BLOCKMASK/BLOCKIFACE/...`）
- 所有必须先 resolve 唯一 selector 的命令（例如 `METRICS.DOMAIN.SOURCES.APP`、`IPRULES.*`、`APP.CUSTOMLISTS` 等）
- dual-form 命令族：`BLACKLIST.* / WHITELIST.* / BLACKRULES.* / WHITERULES.*`（已在 D16/D28 里明确：必须进入 `APP <selector>` 分支）
- stream 命令族：`DNSSTREAM.* / PKTSTREAM.* / ACTIVITYSTREAM.*`

**解析边界（建议写死）**
- 裸 `USER <userId>` 仅在上面“允许”的命令上有意义；其它命令不得把它当作“默认 userId”或“忽略掉当没发生”。
- `USER` 子句格式不完整（例如只有 `USER` 没有数字）→ 必须 `SYNTAX_ERROR`（D22）。

**裁决（你确认，2026-04-16）**
- 2.20.2：OK（按上述白名单执行）

### 2.21 legacy `BLOCKIPLEAKS` overlay 与 legacy domain path：本轮裁决（冻结并强制关闭）

现状与风险：
- 当前 packet 判决链路包含 `legacy domain path` 与 `BLOCKIPLEAKS`（见 `DOMAIN_IP_FUSION_CHECKLIST.md:1.2`）。若把它们当作长期能力，会让 reasonId/policySource 的对外解释模型变得难闭合，并把遗留语义带入 fusion 主叙事。
- 如果不锁死其长期定位，会出现：
  - reasonId / policySource 叙事无法闭合（“为什么 drop/allow”解释不完整）
  - 前端展示会混入“短期遗留能力”导致用户误解为长期稳定语义

#### 2.21.1 `BLOCKIPLEAKS` 的定位（已确认：C）

A) 保持 legacy overlay（推荐：最小成本）
- 继续作为链路中最后一道 gate（不并入 IPRULES/DomainPolicy 语义）。
- 若 overlay 导致最终 DROP：使用固定 `reasonId=IP_LEAK_BLOCK`（不输出 `ruleId`）。
- 文档明确：该能力是 legacy 兼容桥，后续可能删除/替代；fusion 的主叙事不围绕它展开。

B) 并入融合主叙事（不推荐：容易变大工程）
- 把 overlay 的“判定条件”重构为 IPRULES/IFACE_BLOCK/DomainPolicy 的正式规则来源之一（需要定义 scope 与优先级）。
- 优点：叙事统一。
- 缺点：实现与验收面会膨胀；风险高。

C) 冻结并强制关闭（你选择；最强收敛）
- 在 fusion/vNext 口径中视为“无作用能力”：不再参与 packet verdict，也不做 reasonId/metrics/stream 叙事。
- vNext 不提供开启/关闭接口；legacy 即使残留开关也视为永久关闭（无效果）。
- 优点：叙事最干净；不会让遗留能力污染融合后的解释模型。
- 缺点：如果历史上有人依赖它的实际拦截行为，需要提前确认影响面（并给出替代路径，例如 IPRULES/IFACE_BLOCK）。

**我的建议**
- 2.21.1：A（legacy overlay，明确 reasonId 与非主语义）

**裁决（你确认，2026-04-16）**
- 2.21.1：C（冻结并强制关闭：无论控制面如何设置都视为关闭；不再参与 packet verdict，也不做 reasonId/metrics/stream 叙事）

**落地提醒（否则“冻结”会被历史落盘/legacy 设置穿透）**
- 现代码会把 `BLOCKIPLEAKS` 落盘并在启动时 restore：`src/Settings.cpp:45`、`src/Settings.cpp:70`。
- 因此实现上必须确保：无论 legacy 控制面如何设置，运行期都视为 `blockIPLeaks=false`（并且相关命令在 vNext 中返回结构化错误）。

---

### 2.22 `GETBLACKIPS/MAXAGEIP` 与 Domain↔IP bridge：在“冻结 ip‑leak”后仍存在对外口径缺口（建议锁死）

这块通常与 `ip-leak/BLOCKIPLEAKS` 一起出现，但当前 fusion 文档主要讨论了 `BLOCKIPLEAKS`，对其配套开关与数据链路仍有缺口。

**现状（代码事实）**
- DNS 侧：`getips = verdict || settings.getBlackIPs()`；`getips=1` 时会读取并写入 Domain↔IP 映射（bridge）。  
  参考：`src/DnsListener.cpp:200`、`src/DnsListener.cpp:216`
- 控制面存在对应开关：`GETBLACKIPS [<0|1>]`、`MAXAGEIP [<int>]`。  
  参考：`src/Control.cpp:96`、`src/Control.cpp:95`
- Packet 侧 legacy path：读取 `host->domain()` 并调用 `app->blocked(domain)`；仅在 `settings.blockIPLeaks()==1 && blocked && validIP` 时才会最终 DROP（`reasonId=IP_LEAK_BLOCK`）。  
  参考：`src/PacketManager.hpp:203`、`src/PacketManager.hpp:216`

**缺口/矛盾**
- 本目录 target/observability 强调 `getips` 是关键排障字段（“DNS verdict 正确但后续包未绑定域名”），但 vNext/control 文档尚未说明：
  - `GETBLACKIPS/MAXAGEIP` 是否保留/是否对外暴露/默认值与持久化；
  - 在 D31（`BLOCKIPLEAKS` 冻结关闭）之后，`GETBLACKIPS=1` 是否仍被允许（否则会产生“有成本但无效果”的遗留行为，并可能误导用户以为它会影响最终 verdict）。

#### 2.22.1 建议决策（已确认：A）

A) 随 `BLOCKIPLEAKS` 一起冻结（推荐：叙事最干净）
- 视为 legacy 链条的一部分：强制 `GETBLACKIPS=0`（`MAXAGEIP` 维持默认但不再对外作为可调能力）；vNext 不提供接口/HELP 不展示。
- `getips` 字段仍可保留为判决快照（allowed 时通常为 1），但不再支持“blocked 也 getips”的 legacy 行为。

B) 保留为 legacy debug knob（不推荐但可行）
- vNext 不暴露 UI，但允许 legacy 端口继续配置。
- 文档必须显式声明：开启 `GETBLACKIPS/MAXAGEIP` 只影响 Domain↔IP map（bridge）的行为与成本，不影响最终 packet verdict（在 D31 前提下）。

**裁决（你确认，2026-04-16）**
- 2.22.1：A（全部冻结：强制 `GETBLACKIPS=0`；`MAXAGEIP` 不对外；vNext 不提供接口/HELP 不展示）

**落地提醒（否则会破坏“冻结”的单一真相）**
- 现代码会把 `GETBLACKIPS/MAXAGEIP` 落盘并在启动时 restore：`src/Settings.cpp:45`、`src/Settings.cpp:70`。
- 因此“冻结”不能只靠“vNext 不暴露命令/HELP 不展示”；还必须在后端启动/restore 后 **强制覆盖**：
  - `getBlackIPs=false`（确保 DNS 侧 `getips = verdict || getBlackIPs` 退化为 `getips==verdict`）
  - `maxAgeIP` 固定为默认值（当前代码默认 4h），避免历史配置残留造成行为漂移。

### 2.23 legacy domain path（DNS‑learned Domain↔IP bridge）：冻结“ip‑leak/GETBLACKIPS”后仍残留定位缺口（建议继续收敛）

你已裁决：
- `BLOCKIPLEAKS`：冻结并强制关闭（无作用）
- `GETBLACKIPS/MAXAGEIP`：全部冻结（强制 `GETBLACKIPS=0`；`MAXAGEIP` 不对外）

但这并不自动解决 `legacy domain path` 的两个现实问题：**热路径成本**与**对外解释口径**。

**现状（代码事实）**
- DNS 侧仍会在 `getips=1` 时维护 Domain↔IP 映射（allowed 时 `getips=verdict`，因此对 allowed domain 仍会写入映射）：`src/DnsListener.cpp:200`、`src/DnsListener.cpp:216`。
- Host 侧会在创建/更新时把 IP 关联到 Domain（`host->domain(domManager.find(ip))`）：`src/HostManager.hpp:48`。
- Packet 侧在 `IFACE_BLOCK/IPRULES` 未命中时仍会走：
  - `host->domain()` → `domain->validIP()` → `app->blocked(domain)`  
    参考：`src/PacketManager.hpp:203`、`src/PacketManager.hpp:209`、`src/Domain.cpp:19`
  - 即便 `BLOCKIPLEAKS` 被强制关闭，**`app->blocked(domain)` 仍会被执行**（只是最终 verdict 不再因为 ip‑leak overlay 而 DROP）。

**这带来的问题**
- P0 性能风险：`app->blocked(domain)`（DomainPolicy 判决）属于 packet 热路径的一部分；在“ip‑leak 冻结无作用”前提下，它变成“可能有成本但没有最终裁决收益”的遗留路径。
- 口径风险：如果 PKTSTREAM/metrics/日志中仍能看见来自 DomainPolicy 的影子（例如 `domain/host` 可读性、或 legacy stats 颜色等），前端很容易误解为“域名策略影响了最终 packet verdict”。

#### 2.23.1 vNext 对 legacy domain path 的定位（已确认：A）

A) 维持映射，但把 packet 侧 DomainPolicy 判决降级为“仅 observability/可读性”（推荐折中）
- 仍允许 DNS 侧维护 allowed domain 的 Domain↔IP 映射（`getips=verdict`）；`host`/`domain` 仅作为 PKTSTREAM 可选字段（可读性/排障）。
- packet 最终裁决与 reasonId **不得**依赖 DomainPolicy（在 D31 前提下固定不依赖）。
- 实现要求（需写进 change）：把 `app->blocked(domain)` 这类 DomainPolicy 判决从 packet 的“每包必经”路径移除；packet 侧若需要可读性字段，仅允许读取 bridge/reverse‑dns 缓存（例如仅对 `tracked==true` 的观测路径输出 `domain/host`；且 `domain.validIP()` 判定在 writer/序列化线程执行），并明确 **不做** packet stats 的 domain/color 归因（见 2.26‑A）。

B) 全量冻结/移除 bridge（最干净、也最省成本）
- vNext 不再维护 Domain↔IP 映射（`getips` 恒为 `false` 或该字段直接移除）；packet 侧不再读取 `host->domain()`。
- PKTSTREAM 不输出 `domain/host`（或永远为空），只输出五元组 + `reasonId/ruleId/wouldRuleId`。
- 优点：热路径最轻；解释模型最简单。
- 缺点：失去 “packet 事件显示域名” 的可读性；也失去部分 legacy domain‑colored stats 的可能扩展空间。

C) 升级为融合主线能力（不推荐）
- 把 Domain↔IP 映射作为长期能力，定义其与 IPRULES/IFACE_BLOCK 的正式优先级，并把它纳入 reasonId/metrics/stream 叙事闭环。
- 缺点：会把一个遗留模块变成长期承诺，且热路径/验收成本显著膨胀。

**我的建议**
- 2.23.1：A（保留映射但降级为 observability/可读性；把 DomainPolicy 判决从 packet 热路径里移出去）

**裁决（你确认，2026-04-16）**
- 2.23.1：A

#### 2.23.2 PKTSTREAM 的“名称字段”：`domain`（bridge） vs `host`（reverse‑dns）（已确认：B）

2.23.1‑A 的价值主要体现在“事件可读性/排障”：用户能从 packet 事件里看到一个**可解释的名字**。但当前实现的 `PKTSTREAM.host` 是 reverse‑dns（`Host::_name`），而 legacy bridge 维护的是 `Host::_domain`（来自 DNS‑learned Domain↔IP 映射）。

因此仍需要锁死：vNext 的 packet 事件里，到底输出哪一种“名字”，以及字段名是什么。

**选项（历史备选；已确认 B）**

A) 保持字段名 `host`，但语义改为“best-effort name”（推荐折中）
- 输出优先级：`domain(from bridge)` → `reverseDnsHost` → 不输出。
- 优点：字段数量不膨胀；前端只要渲染一个“名字”；更贴近用户心智（多数时候关心 domain 而不是 PTR 结果）。
- 缺点：字段名 `host` 语义变宽；若有人严格依赖 “host=reverse-dns” 会被打破（但 vNext 本就 breaking）。

B) 增加新字段 `domain`（bridge），保留 `host`（reverse‑dns）（更清晰）
- `domain`：仅当 bridge 命中且 `domain.validIP()==true` 时输出。
- `host`：仅当 reverse‑dns 有结果时输出。
- 优点：语义最清晰；前端可分别展示/调试。
- 缺点：schema 更大；前端要多一套展示逻辑。

C) 不在 packet 事件里输出任何名字（最省成本）
- 仅输出五元组 + `reasonId/ruleId/wouldRuleId`；名字定位完全交给 “另查 HOSTS/DNSSTREAM”。
- 优点：热路径最轻；不引入隐私/输出体积问题。
- 缺点：调试体验明显下降；2.23.1‑A 的收益大幅缩水。

**我的建议**
- 2.23.2：B（更清晰；避免把两个来源硬塞进一个字段导致解释混乱）

**裁决（你确认，2026-04-16）**
- 2.23.2：B

#### 2.23.3 `domain/host` 的“快照时刻 / validIP 判断 / 热路径成本”仍需锁死（新增）

2.23.2‑B 只锁死了 **schema**（`domain`=bridge、`host`=reverse‑dns）。但如果不再进一步锁死“何时计算/在谁的线程计算”，实现阶段很容易又把成本塞回 hot path（甚至回退到 `app->blocked(domain)` 的旧链路），从而违反 2.8 的 ACA 红线。

**关键代码事实（为什么这是 P0 级别）**
- 当前 packet 链路会做：`domain->validIP()`（内部调用 `time(nullptr)`）+ `app->blocked(domain)`（DomainPolicy 判决）。  
  参考：`src/PacketManager.hpp`、`src/Domain.cpp:18`

**建议锁死的落地约束（推荐 A）**

A) `domain/host` 只作为“可读性字段”，在 writer/序列化线程 best-effort 计算（推荐）
- hot path / `mutexListeners` 锁内：不得为了 `domain/host` 做任何额外工作（尤其不得调用 DomainPolicy 判决；也不应 per‑packet 调 `time(nullptr)`）。
- 事件对象只需携带 `Host::Ptr`（以及必要的五元组/裁决字段）。writer 在输出时：
  - `host`：若 reverse‑dns 有结果则输出，否则省略（不输出该 key）。
  - `domain`：读取 `host->domain()`，并且仅当 `domain!=nullptr && domain.validIP()==true` 时输出（validIP 判定在 writer 侧做，避免热路径 `time()`）。
- 对外口径同步写死：`domain/host` **不是判决快照字段**，属于 best‑effort 可读性字段；允许轻微漂移（例如 reverse‑dns 结果延迟出现）。

B) hot path 直接把 `domain/host` 字符串快照写入事件（不推荐）
- 缺点：每包多一次 string 复制与可能的 `time()`；很容易压垮高频场景；也会放大 ring 内存占用。

C) 输出 `domain` 但不做 `validIP` 防陈旧检查（不推荐）
- 缺点：会把 4h 之前的映射也输出出来，误导用户；2.23.2 的“避免陈旧映射误导”目标失效。

**我建议**
- 2.23.3：A（writer 侧 best‑effort；validIP 判定也在 writer；并明确 `domain/host` 不承诺判决时快照）

**裁决（你确认，2026-04-17）**
- 2.23.3：A

### 2.24 stream schema 的字段类型/缺失表示仍有缺口（建议尽早锁死）

本目录 working decisions 已列出 `type="dns|pkt|activity|notice"` 的最小字段集合，但对 **字段类型** 与 **缺失表示** 尚未写死；而当前代码里存在一批“不太适合长期契约”的历史习惯（例如输出 `"n/a"`、`wouldDrop=1` 用 number 表示 true、timestamp 用字符串等）。

**现状（代码事实）**
- `PKTSTREAM`：`host` 与 `interface` 始终输出，缺失时用字符串 `"n/a"`；`wouldDrop` 用 number `1`（不是 JSON boolean）。  
  参考：`src/Packet.cpp:55`、`src/Packet.cpp:63`
- `DNSSTREAM`：`timestamp` 也是字符串（`"sec.nsec"`）。  
  参考：`src/DnsRequest.cpp:41`

**建议（更适合 vNext 的稳定契约）**

A) optional 字段“缺失即缺失”，不要输出 `"n/a"`（推荐）
- 对 `domain/host/interface/ct/ruleId/wouldRuleId/...` 这类可选字段：
  - 缺失时直接 **省略该 key**（已确认；vNext 锁死；不输出 `"n/a"`/空字符串/`null`）。
- 对 `wouldDrop`：建议改为 JSON boolean（与 `accepted/blocked` 同类语义），避免 number/bool 混乱。
- 对 `timestamp`：至少需要在 vNext 文档里写死一种格式（当前是字符串 `"sec.nsec"`；若要改成 `timestampNs`/`timestampMs` 数字，也应在 vNext 一次性切换并明确类型）。
  - 注：本节约束只适用于 stream 事件 schema；控制面里“开关类命令”的返回值仍可维持 legacy `0|1`（numbers），两者不强行统一。

B) 维持现状（兼容 legacy 输出习惯；不推荐）
- 继续输出 `"n/a"` 与 `wouldDrop=1`；优点是改动少，缺点是 vNext 会继承一批“对机器不友好”的历史债。

**我建议**
- 2.24：A（vNext 明确：optional 字段缺失就省略；`wouldDrop` 为 boolean；timestamp 格式写死）

**裁决（你确认，2026-04-17）**
- 2.24：A

### 2.25 vNext 的 error `code` 枚举仍未锁死（建议先锁“最小稳定集合”）

当前 `CONTROL_PROTOCOL_VNEXT.md` 已引入结构化错误对象，但 `error.code` 仍是 `...` 占位；如果不尽早锁死，落地阶段很容易出现：
- 同一类错误在不同命令里 code 不一致（前端难写统一修复逻辑）
- legacy 的 `NOK`/无响应语义回潮（靠 message 解析）
- “冻结能力”（例如 `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）到底算 unknown command 还是 invalid argument，产生分歧

**建议（推荐 A）**

A) 锁死“最小稳定集合”，其余后续只增不改（推荐）
- `SYNTAX_ERROR`：解析失败 / trailing tokens / 禁止 pretty `!` / 非法 `USER` 子句
- `MISSING_ARGUMENT`：缺少必需参数
- `INVALID_ARGUMENT`：参数值不合法（范围/格式/语义冲突）；apply 冲突用 `conflicts[]`
- `SELECTOR_NOT_FOUND`：selector resolve 为空
- `SELECTOR_AMBIGUOUS`：selector resolve 多个；必须带 `candidates[]`
- `STATE_CONFLICT`：状态机冲突（例如 stream 已 started、同类型 stream 已被其它连接订阅、stream 连接上执行非 stream 命令）
- `PERMISSION_DENIED`：密码/权限相关（若保留 PASS 体系）
- `UNSUPPORTED_COMMAND`：命令存在但在 vNext 被明确禁用/冻结（例如 `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）
- `INTERNAL_ERROR`：后端 bug/异常

并锁死 `candidates[]` 的最小字段集合：`uid/userId/app`（canonical pkg）。

B) 只保证 `message` 可读，不锁 code（不推荐）
- 缺点：前端/脚本无法做可靠的自动修复与 UI 引导；违背 D3 的“可修复”目标。

**我建议**
- 2.25：A（先锁最小 code 集合；后续只增不改）

**裁决（你确认，2026-04-17）**
- 2.25：A

### 2.26 legacy domain path 的“packet stats/颜色归因”仍有设计缺口（建议补齐）

你已经裁决 2.23.1‑A：bridge 保留但仅用于 observability/可读性，且 DomainPolicy 判决要从 packet 热路径移出。

但当前实现里，legacy domain path 除了影响（已冻结）`BLOCKIPLEAKS` 外，还承担了一个隐含职责：**给 packet stats 上 domain/color**（即便最终 verdict 仍是 allow）。

**现状（代码事实）**
- 在 legacy domain path 分支里，每包会做：
  - `domain->validIP()`（含 `time()`）
  - `app->blocked(domain)`（DomainPolicy 判决，产出 `blocked` + `cs(color)`）
  - `appManager.updateStats(domain, app, !verdict, cs, ...)`（把 domain+color 参与 packet stats）  
  参考：`src/PacketManager.hpp:190`
- 而 `BLOCKIPLEAKS` 已冻结为无作用后，`blocked/cs` 对最终 verdict/reasonId 没贡献，只剩“stats 归因/可读性”用途。

**风险**
- 若实现时“为了移出热路径”直接把 `app->blocked(domain)` 去掉，但仍继续更新 stats：就必须回答“stats 还能不能带 domain/color？带的话来自哪里？不带的话是否可接受？”。
- 若继续保留 domain‑colored stats，又很容易让前端误解为“DomainPolicy 参与了 packet 仲裁”（尤其当 `color` 仍在 stats/hosts 输出里出现）。

**建议补齐一个明确口径（推荐 A）**

A) vNext 明确：packet stats 不再做 domain/color 归因（推荐：最干净）
- packet 侧 stats/metrics 的核心叙事收敛为：`reasonId` + `ruleId/wouldRuleId`（IP 腿）与 `IFACE_BLOCK`；不再把 DomainPolicy 的 color 混入 packet stats。
- 实现上：legacy domain path 不再调用 `app->blocked(domain)`；packet stats 统一以 `domain=null, color=GREY` 记账（与 IPRULES 分支一致）。
- 代价：丢失“按 domain/color 看 packet stats”的 legacy 能力；但你已把该路径降级为 observability/readability，因此可接受。

B) 仅在 `tracked==true` 时保留 domain‑colored packet stats（可行但复杂）
- 仍禁止把 DomainPolicy 判决放回“每包必经”的默认路径；只有当用户显式开启 `tracked`（并已被前端提示性能影响）时才允许做额外判决/归因。
- 仍需进一步锁死：这部分归因是在 hot path 里做，还是异步在 writer/统计线程做（否则会反复摇摆）。

**我的建议**
- 2.26：A（packet stats 不再做 domain/color 归因；DomainPolicy 只在 DNS 侧与可读性字段中出现）

**裁决（你确认，2026-04-17）**
- 2.26：A（本阶段先“移除/冻结该归因行为”，但不要求删代码；等其它能力稳定后再单独讨论颜色相关语义是否要回归/如何回归）

### 2.27 stream 连接模型：STOP ack barrier 与“同连接多 streamType”的冲突（新增审阅点）

本目录已锁死：
- vNext stream 使用 NDJSON（事件是一行一个 JSON object，含 `type`）。
- `*.STOP` 有 **ack barrier**：`{"ok":true}` 是 STOP 的最后一行；ack 后不得再输出任何事件/notice，直到下一次 `*.START`。（2.9‑B）
- **单连接约束（2.8‑A）**：同一时间每种 stream 只允许 1 条连接订阅。

但目前仍缺一句“连接拓扑”约束：**同一条 stream 连接能否同时订阅 dns+pkt+activity？**

如果允许“同连接多 streamType”，那么：
- `DNSSTREAM.STOP` 的 ack barrier 将被 `PKTSTREAM` 的后续事件打破（ack 不可能是“最后一行”）。
- 或者实现者会被迫把 barrier 解释成“只对该 streamType 生效”，但这需要文档明确，否则前端/脚本会各自猜。

**建议补齐一个明确约束（推荐 A）**

A) vNext 强制：**一条 stream 连接只允许订阅一种 streamType**（推荐，最简单）
- 连接级状态机：连接一旦 `DNSSTREAM.START`，则该连接后续只允许 `DNSSTREAM.STOP`（以及可能的 `QUIT`）；任何其它 streamType 的 `*.START/STOP` 一律 `STATE_CONFLICT`。
- 好处：ack barrier 保持“连接级最后一行”的强保证；不会出现跨 streamType 的事件交织；客户端实现最简单。
- 代价：前端如果想同时看 dns+pkt，需要开两条 stream 连接（这是可接受的：control 平面本就允许并发连接）。

B) 允许同连接多 streamType，但把 barrier 明确为“**仅对该 streamType 生效**”
- 需要修改/补充协议：STOP ack 必须带 `{"ok":true,"stream":"dns|pkt|activity"}`（或等价字段），并明确“ack 后不得再输出该 streamType 的事件/notice”，但允许其它 streamType 继续输出。
- 好处：客户端连接数少。
- 缺点：协议复杂度上升；事件交织更常见；更容易出现实现边界 bug（尤其是 STOP 与 pending queue 的清理边界）。

C) 允许同连接多 streamType，但任一 STOP 直接停掉该连接上**所有** stream
- 好处：保持连接级 barrier。
- 缺点：语义不直观（STOP 一个会停全部）；容易误伤其它订阅。

**我的建议**
- 2.27：A（每种 streamType 使用独立连接；同连接不做多 streamType 订阅），以保证 ack barrier 与实现复杂度可控。

**你反馈/疑问（2026-04-17）**
- 你倾向选 A，但担心前端为了“把事件串起来/做联动解释”，会不会不得不把所有 stream 都订阅起来，从而让前端更麻烦；希望更详细比较 A/B/C 的利弊。

#### 2.27 进一步利弊分析（补齐）

这里先明确一个前提：vNext 的 stream 不是“强一致审计日志”，而是 **best‑effort 调试事件流**；因此“需要同时订阅所有 stream 才能工作”不是目标。默认应当是：
- 常态解释靠 metrics（`METRICS.REASONS`、`METRICS.DOMAIN.SOURCES*`、`METRICS.TRAFFIC*` 等）；stream 只用于“逐条看发生了什么/快速定位”。
- 前端 **按需开启**：想看 packet → 只开 PKT；想看 DNS → 只开 DNS；想看 toggle/activity → 只开 ACTIVITY。不是“一开就全开”。

在这个前提下再比较连接模型：

**A) 一条连接只承载一种 streamType（推荐；你倾向）**
- 后端复杂度：
  - 最低：连接上只需要维护 1 个 stream 的订阅状态机（START/STOP/pending queue/ring replay）。
  - `*.STOP` 的 ack barrier 可以保持“连接级强保证”：ack 后这个连接不会再有任何输出（直到下一次 START）。
  - 反压与 drop 的实现也更简单：每条连接一个 queue；不会出现不同 streamType 共享一个 queue 时的公平性/饥饿问题。
- 前端复杂度：
  - 需要维护多条 socket（通常 0~3 条：pkt/dns/activity），但逻辑可高度复用：
    - 同一套 NDJSON 逐行解析器；
    - 同一套 reconnect/backoff；
    - 按连接的“预期 type”做轻量校验（例如 pkt 连接只接受 `type="pkt|notice"`）。
  - 事件“串起来”的方式：
    - 绝大多数 UI 不需要严格跨 streamType 的 total ordering；
    - 若需要统一时间线，用 `timestamp` 合并排序即可（DNS/pkt 都是 `sec.nsec`，可转为 64-bit ns 排序；轻微乱序可接受）。
- 资源开销：
  - 多几个 FD/连接；但本地 Unix socket 成本可接受（且控制面 clients 上限很高，见 `settings.controlClients`）。
- Debug 体验：
  - 用 `socat` 订阅时更清晰：一个窗口一类事件，不会混。

**B) 同一条连接可同时订阅多个 streamType；ack barrier 退化为“对该 streamType 生效”**
- 后端复杂度：
  - 需要 per‑streamType 的订阅状态 + per‑streamType 的 pending queue（否则 STOP 清理边界不清晰）。
  - ack barrier 必须重写成“ack 后不得再输出该 streamType 的事件”，但允许其它 streamType 继续输出；这要求：
    - ack 需要带 `stream` 字段或隐式与命令绑定（前端必须实现更复杂的状态机）。
    - 输出交织会成为常态：同一条连接上 `pkt`/`dns`/`notice` 混杂，客户端更难做 backpressure 与丢包定位。
- 前端复杂度：
  - 连接数少，但状态机更复杂：必须正确处理“一个 STOP 只停一种事件，其它事件仍在刷”的场景。
  - 一旦前端/脚本写错，很容易出现“以为停了但其实另一个 stream 还在输出”的假象。
- 总结：用连接数换协议复杂度；对本项目目前“先收敛、先可解释、先少坑”的目标不划算。

**C) 同一条连接多 streamType，但任一 STOP 直接停掉该连接上所有 stream**
- 后端复杂度：
  - 比 B 简单（STOP 直接清空连接级 queue/ring），ack barrier 仍是连接级强保证。
- 前端复杂度/用户直觉：
  - 最不直观：停 pkt 顺带把 dns 也停了；会让 UI/脚本出现“互相误伤”，尤其当不同页面/模块各自订阅时。
  - 很难做模块化：任一模块调用 STOP 都会影响其它模块。

**结论（维持建议）**
- 仍建议 2.27 选 A：用“多连接”换“协议/状态机简单”，并且与 2.9‑B 的 ack barrier 设计完全一致。
- 需要补齐到文档的关键一句（面向前端的承诺）：**前端不需要订阅所有 stream 才能工作**；常态解释以 metrics 为主，stream 是按需工具。

**裁决（你确认，2026-04-17）**
- 2.27-A（每种 streamType 使用独立连接；并补齐“前端按需订阅、非全订阅”的说明）

### 2.28 `tracked` gating 与“逐条事件构造成本”仍需写死（新增审阅点）

本目录已强调红线：逐条事件输出必须异步化，hot path 只做有界 enqueue；且 `tracked` 是用户显式 opt‑in（默认关闭、持久化、前端提示性能影响）。

但如果不进一步把“**何时构造逐条事件对象**”写死，实现阶段很容易出现“为了 ring/回放/订阅，仍然每包 `new Packet(...)`”的隐性成本回潮。

**现状（代码事实）**
- packet：无论 `tracked` 与否，都会 `Streamable<Packet>::stream(make_shared<Packet>(...))`，并且在无订阅者时仍把 item 推入 ring（`_items.push_back`）：`src/PacketManager.hpp`、`src/Streamable.cpp`。
- dns：同样使用 `Streamable<DnsRequest>` 机制，ring 默认常开并可能落盘/restore（与 vNext “不落盘”相冲突）。

**建议补齐一个明确约束（推荐 A）**

A) vNext 写死：**逐条事件只为 `tracked==true` 的 app 构造并入 ring**（推荐，最符合 D8）
- 无订阅者时：tracked app 仍入 ring（用于回放）；untracked app 不构造逐条事件。
- 有订阅者时：依然只输出 tracked app 逐条事件；untracked app 用 `type="notice", notice="suppressed"` + 常态 metrics 提示用户 `TRACK`（与现 working decisions 的 hint 一致）。
- 好处：把“逐条事件的 per‑packet 分配/序列化成本”从默认路径剥离；符合“前端明确提示性能影响”的产品叙事。

B) 有订阅者就为所有 app 构造事件（不推荐）
- 缺点：PKTSTREAM/DNSSTREAM 一旦被打开就把成本拉回全量热路径；与“默认 tracked=false”心智冲突。

C) 维持现状（ring 常开、无订阅者也构造事件）（不推荐）
- 缺点：与 2.8 的 ACA 红线直接冲突；也让 D8 的“tracked 性能提示”失去意义（因为成本不是 tracked 带来的）。

**我的建议**
- 2.28：A（逐条事件与 ring capture 的成本严格受 `tracked` gating；untracked 只走 counters + notice）。

**裁决（你确认，2026-04-17）**
- 2.28：A

### 2.29 “冻结能力”必须是后端全局冻结（legacy endpoint 并存期的 backdoor 风险）（新增审阅点）

本目录已裁决冻结：
- `BLOCKIPLEAKS`：强制关闭、冻结无作用（D31）
- `GETBLACKIPS/MAXAGEIP`：全部冻结（D32）
- packet stats 的 domain/color 归因：本阶段移除/冻结（2.26‑A）

但 D4 同时裁决：legacy control endpoint（`sucre-snort-control` / `60606`）在 vNext 稳定前仍会并存一段时间。

**风险**
- 如果冻结只体现在“vNext HELP 不展示 / vNext 不提供命令”，而 legacy 仍允许设置这些开关：
  - 任何老客户端/临时调试连接都可以把 `BLOCKIPLEAKS` 打开，导致 packet 路径重新进入 `app->blocked(domain)` + `IP_LEAK_BLOCK` 叙事，直接破坏 fusion 的“单一心智模型”。
  - `GETBLACKIPS/MAXAGEIP` 也会导致 bridge 维护与 `domain.validIP()` 行为漂移（尤其是它们会落盘/restore）。
- 这会让 vNext 的“冻结假设”变成**脆弱的约定**：只要有人用 legacy endpoint 调了一次，就会出现“前端按 vNext 解释但后端行为被 legacy 改写”的不可解释 bug。

**建议补齐一个明确约束（推荐 A）**

A) 冻结是**后端全局冻结**（推荐）
- 无论 vNext/legacy 哪个 endpoint，后端都必须在启动/restore 后强制覆盖冻结项到固定值，并且忽略后续来自任何 control 连接的修改请求（可以返回结构化错误/或返回固定值但 no-op）。
- 这样 vNext 的文档与前端逻辑才能把这些能力视为“本阶段不存在”。

B) 冻结仅限 vNext（不推荐）
- 只要 legacy 还在，就相当于保留一个随时能把系统拉回旧叙事的后门；会显著增加排查成本。

**我的建议**
- 2.29：A（冻结项必须是 daemon 内部强制覆盖与强制 no-op；不依赖 HELP/接口是否暴露）。

**你补充（2026-04-17）**
- legacy control endpoint 会存在较长一段时间；但前后端均自控，不存在“外部未知客户端把开关打开”的风险；若发生即视为调试误操作。

> 备注：即便风险主要来自“自己调试时误操作”，全局冻结仍是更安全的做法（把 footgun 变成不可能），且还能避免历史落盘/restore 穿透。

**裁决（你确认，2026-04-17）**
- 2.29：A

### 2.30 `IPRULES` 原子 apply 的“请求 wire 语法/大小预算”仍是缺口（新增审阅点）

`IPRULES_APPLY_CONTRACT.md` 已锁死了 apply 的语义与返回 shape（`clientRuleId/matchKey/conflicts[]/ruleId` 策略等），但它刻意“不定义具体命令名与请求编码方式”。

而 vNext control 协议（D4）又锁死了：
- 请求是“每条命令一行”的 ASCII token 风格（不是 JSON‑RPC）。
- framing 是 LF + NDJSON（响应/事件是一行一个 JSON value）。

因此仍需要补一句“apply 的请求怎么在一行里表达”，否则实现阶段很容易各写各的（或出现不可调试的转义/长度问题）。

**现状（代码事实）**
- control 输入有长度上限：`settings.controlCmdLen = 20000`：`src/Settings.hpp:133`。
  - 原子 apply payload 很容易超过 20KB（尤其包含多条规则 + `clientRuleId`），如果不提前裁决，最终会变成“客户端偶发 SYNTAX_ERROR/截断”的难排查问题。

**建议补齐一个明确约束（推荐 A）**

A) apply 请求采用“前缀 tokens + 行尾 JSON”模式（推荐）
- 示例（仅示意；命令名可后置统一）：  
  `IPRULES.APPLY UID <uid> <json>`  
  其中 `<json>` 是该行剩余部分，按严格 JSON 解析（允许空白；禁止 raw newline；字符串内必须正确 escape）。
- 好处：
  - 保持 vNext “请求仍是命令行”风格，不需要全局升级到 JSON‑RPC；
  - payload 本身就是 JSON，前端不需要再把 rule 列表拆成 kv tokens；
  - 仍然可被 `socat/nc` 调试（至少可以直接粘贴 compact JSON）。
- 需要补齐的配套约束：
  - 明确最大 payload（至少要高于 20KB，或把控制面输入上限提升到可接受区间）；
  - 超限/截断时返回什么 error.code（建议 `INVALID_ARGUMENT` 或 `SYNTAX_ERROR`，但必须稳定）。

B) base64 JSON payload（不推荐）
- 形式：`IPRULES.APPLY UID <uid> B64 <payload>`。
- 缺点：不可读不可调试；体积膨胀；对错误定位不友好。

C) 全量升级为 JSON‑RPC（不推荐，超出 D4 范围）
- 这会推翻 vNext 已锁死的“token 命令生态”，影响面过大。

**我的建议**
- 2.30：A（行尾 JSON payload），并把“control 输入上限/超限错误”写成显式契约，避免实现/前端各自猜。

**裁决（你确认，2026-04-17）**
- 2.30：A

### 2.31 ring/pending queue 的“有界”必须落到可验证的 cap（否则 2.12 的 drop 决策无法落地）（新增审阅点）

本目录已经裁决：
- hot path 只能做 **有界 enqueue**（不得同步写 socket）。
- queue/ring 满时 drop-oldest；`droppedEvents` 口径按事件条数；`notice="dropped"` 1Hz/streamType。（2.12‑A）

但目前缺的不是“drop 策略”，而是：**什么叫“满”？cap 在哪里？**  
如果 ring/queue 没有明确 cap，那么：
- ring 会在高频 `tracked` 场景下无限增长（直到 horizon 触发过期；而 horizon 仍可能很大），导致内存不可控；
- pending queue 也可能因为 writer 落后持续增长；
- 2.12 的 `droppedEvents/notice="dropped"` 永远不会触发或触发条件不一致（实现者各自猜）。

**现状（代码事实）**
- `Streamable<Item>` 的 ring 是 `deque<shared_ptr<Item>>`，仅按“maxHorizon 过期”弹出旧项，没有 size cap：`src/Streamable.cpp`、`src/Packet.hpp`、`src/DnsRequest.hpp`。
- 这在 vNext 引入“tracked app 即使无订阅者也入 ring”的设计下，会把内存风险放大（尤其是 PKTSTREAM）。

**建议补齐一个“可验证的 cap 规则”（推荐 A）**

A) 必须引入 cap（不锁具体数值，但锁口径与行为）（推荐）
- 为每种 streamType 定义两个上限（数字可在实现/基线阶段定，文档先锁“必须存在”）：
  1) `maxRingEvents`：ring 最多保留 N 条事件（超出时 drop-oldest；影响 replay 但不影响实时）。
  2) `maxPendingEvents`：pending queue 最多 N 条待发送事件（超出时 drop-oldest，并计入 `droppedEvents`，触发 `notice="dropped"`）。
- 同时锁死参数夹逼：
  - `*.START horizonSec/minSize` 允许请求更大，但服务端必须 clamp 到能力上限（例如 `minSize` 不得超过 `maxRingEvents`；horizonSec 不得超过 `maxHorizonSec`），并把实际生效值通过 `notice="started"` echo 回去（避免前端误以为“我请求了 10 万条就一定会回放 10 万条”）。
- 优点：真正做到“可证明有界”；并且 drop/notice 的语义可测、可验收。

B) 只 cap pending queue，不 cap ring（不推荐）
- 缺点：无订阅者时（或 tracked ring capture）仍可能把 ring 撑爆内存；与“有界 enqueue”目标不一致。

C) 只依赖 horizon 过期，不做任何 cap（不推荐）
- 缺点：horizon 再小也能在高 PPS 下累计巨大 ring（例如 10s * 50kpps = 50 万条）；不可控。

**我的建议**
- 2.31：A（cap 必须存在；数值可后置，但口径必须先锁死）

**裁决（你确认，2026-04-17）**
- 2.31-A

### 2.32 裸 `USER <userId>` 白名单：明确哪些命令支持 user-filter（承接 D30；已确认）

D30 已裁决“逐命令白名单”，但目前本目录还缺一张“白名单表”。没有这张表，实现阶段会出现：
- 前端以为某条命令支持 `USER`，后端却按 `SYNTAX_ERROR` 拒绝（或反过来）
- parser 逻辑分散在各个 cmd handler（后续难维护）

**需要你裁决的问题**
- vNext 最小白名单到底包含哪些命令族？

**选项**

A) 白名单与 legacy 现状对齐（推荐，迁移成本最低）
- 允许 bare `USER <userId>` 的命令仅限“device-wide list/stats（含 reset）”：
  - `APP.UID [USER <userId>]`
  - `APP.NAME [USER <userId>]`
  - `APP<v> [USER <userId>]` / `APP.<TYPE><v> [USER <userId>]` / `<COLOR>.APP<v> [USER <userId>]`
  - `APP.RESET<v> ALL [USER <userId>]`（若保留该语义；仅 reset 目标范围，不改变其它开关）
- 其它命令遇到裸 `USER <userId>` 一律 `SYNTAX_ERROR`（严格拒绝；不 silent ignore）。

B) 精简白名单（更严格，但前端需要额外枚举）
- 只保留 `APP.UID/APP.NAME/APP<v>` 的 bare `USER`；其余一律不支持。

C) 扩展白名单到更多“查询类”命令（不推荐）
- 例如对 metrics/domain/hosts 也支持 bare `USER`；实现与解释成本更高，且容易和 selector 语法混淆。

**我的建议**
- 2.32：A（先对齐 legacy 便于迁移；之后如需收紧再另开 change）

**裁决（你确认，2026-04-17）**
- 2.32-A

### 2.33 legacy Domain↔IP bridge：`domain/host` 缺失与“可能不准”的对外解释口径（完成 0.6 P1-细化；已确认）

我们已经裁决：
- bridge 保留但仅用于 observability/可读性（2.23.1‑A）
- PKTSTREAM 输出 `domain`（bridge）+ `host`（reverse‑dns）（2.23.2‑B）
- `domain.validIP()` 判定在 writer；字段 best‑effort；不承诺判决时快照（2.23.3‑A）
- packet stats 不做 domain/color 归因（2.26‑A）

但还缺一句“前端如何解释 `domain/host` 缺失/不一致”的 **明确口径**，否则 UI 容易误解为 bug 或误当作强归因。

**需要你裁决的问题**
- vNext 是否明确写死：`domain/host` 只是“可读性标签”，可能缺失、可能不准（例如 CDN/多域名共享 IP），前端不得用它做归因或仲裁解释？

**选项**

A) 口径最小化（推荐）
- `domain/host` 的缺失 = “未知/不可得”，不是错误；前端直接省略展示或显示 `-`。
- `domain` 即使存在，也只是“该 IP 当前关联到的一个 domain 标签”，不保证与本包真实业务域名一致；不得用于归因/仲裁解释。
- 若需要更强的排障：
  - 看 `DNSSTREAM`（以及其 `getips/domMask/appMask/policySource` 等字段）
  - 或看常态 metrics（`METRICS.DOMAIN.SOURCES*`/`METRICS.TRAFFIC*`）

B) 增加显式解释字段（不推荐，schema 变大）
- 例如 `nameState/nameSource`（`bridge_hit/bridge_stale/reverse_dns_off/...`），让前端能解释“为什么缺失”。

C) 增加 on-demand 查询命令（不推荐，扩面）
- 例如 `BRIDGE.PRINT <ip>`：返回当前映射与 age；用于在不订阅 stream 时排障。

**我的建议**
- 2.33：A（先把“best-effort label”口径写死；不要把 bridge 变成长期强承诺）

**裁决（你确认，2026-04-17）**
- 2.33-A

### 2.34 `IPRULES.APPLY`：命令名 + 请求 JSON schema + 最大 payload 策略（方案 D；已确认）

2.30（行尾 JSON）是基于“token 命令 + LF/NDJSON”阶段的收敛；在方案 D（netstring + JSON envelope）下已被覆盖：

- 不再存在“前缀 tokens + 行尾 JSON”：`IPRULES.APPLY` 是普通 `cmd`，payload 统一是 JSON。
- 命令名：`cmd="IPRULES.APPLY"`
- request `args` 最小 shape：
  - `{"uid":10123,"rules":[ ... ]}`（规则 item 字段与 `IPRULES_APPLY_CONTRACT.md` 对齐）
- 成功 response：按 `IPRULES_APPLY_CONTRACT.md` 第 5 节回传完整映射（`clientRuleId/ruleId/matchKey`），放在 `result` 内。
- 最大 payload：
  - 由 `HELLO.result.maxFrameBytes` 决定（netstring 上限；见 `CONTROL_PROTOCOL_VNEXT.md`）。
  - 超限行为（2.37‑A）：检测到 `len > maxFrameBytes` 立即断连（不返回 response frame；可记录 server log）。

**裁决（你确认，2026-04-17）**
- 2.34-A

### 2.35 vNext `HELLO`（协议探测）是否要锁死 shape（可选；已确认）

当前 vNext endpoint 已通过“不同 socket/port”与 legacy 分离；严格说不需要 `HELLO` 才能分辨协议。
但实现一个稳定的 `HELLO` 回包有利于前端/脚本自检与诊断。

**选项**

A) 保留 `HELLO`，并返回协议/版本（推荐）
- `{"id":X,"ok":true,"result":{"protocol":"control-vnext","protocolVersion":4,"framing":"netstring","maxFrameBytes":...}}`

B) `HELLO` 只回 ack（也可）
- `{"id":X,"ok":true}`

C) 不提供 `HELLO`（不推荐）

**我的建议**
- 2.35：A

**裁决（你确认，2026-04-17）**
- 2.35-A

### 2.36 stream `*.START` 是否也要有 response frame（已确认；2.36‑A）

背景：
- 方案 D 下，我们把 request/response 与 events 彻底分离：
  - response：`{"id":...,"ok":...,"result"/"error":...}`
  - event：`{"type":...}`（不得包含 `id/ok`）
- D19（硬约束）倾向于：每条 request 必须有且仅有 1 个 response frame（避免客户端靠超时猜）。

这里要锁死的是：`DNSSTREAM.START/PKTSTREAM.START/ACTIVITYSTREAM.START` 成功时，是否也必须先回一个 response frame；以及 started NOTICE 的地位。

**选项**

A) `*.START` 成功：先回 response frame（推荐），再输出 `notice="started"` event（保留 D18）
- 顺序（强建议锁死）：
  1) response：`{"id":X,"ok":true}`（或带 `result`）
  2) event：`{"type":"notice","notice":"started",...}`（必须是本 session 的**第一条 event**）
  3) replay（若有）→ realtime events
- 失败：仅返回 response frame（`ok=false`），不得输出 started NOTICE。

好处：
- **最少的客户端特殊分支**：客户端永远先等 response frame，再进入“读 events”的循环。
- **满足 D19**：每条 request 恰好一个 response frame；started NOTICE 是 event，不占用 response 配额。
- **保留 D18 的用户体验**：started NOTICE 可以作为“session 边界标记”，也可以 echo clamp 后的实际 `horizonSec/minSize`。

代价/影响：
- 每次 START 会产生 2 个输出 frame（1 response + 1 notice），比“只回 response”略啰嗦。
- 实现上需要保证：started NOTICE 不会被 replay/events 抢在前面输出（需 writer 侧明确序列）。

B) `*.START` 成功：只回 response frame；不再要求 `notice="started"`（把 D18 降级为可选）
- 成功：response 可在 `result` 中携带 `effectiveHorizonSec/effectiveMinSize`（用于解释 clamp）。
- 失败：同 A。

好处：
- **输出最少**：一次 START 只有 1 个 response frame（更“像普通命令”）。
- started 的语义全部归入 response，event stream 没有额外“仪式感”。

代价/影响：
- raw stream pipe（例如未来 CLI 的 `--raw`）不再天然看到“started 分隔”，需要由工具自己打印提示。
- 若我们仍希望 started NOTICE 承载“echo clamp 值”，则 B 会把这些字段搬到 response `result`（schema 需要更明确）。

C) `*.START` 成功：不回 response frame；started NOTICE 作为第一条 event（把 D19 做成例外）

好处：
- 延续 legacy/NDJSON 阶段的“START 直接转入流模式”的心智模型。

代价/影响（很大）：
- **客户端必须特殊处理 START**：不能再用“每条 request 等一个 response”作为统一状态机。
- 若未来同连接还要支持更多 stream session 命令（例如 RESET/PAUSE），例外会扩散，测试也更难写。

**我的建议**
- 2.36：A（保持 D19 的统一性，同时保留 D18 的 started NOTICE 作为 event 边界标记）。

**裁决（你确认，2026-04-17）**
- 2.36-A

### 2.37 netstring `len > maxFrameBytes` 的超限行为（已确认；2.37‑A）

背景：
- 方案 D 用 netstring 做 framing：先读 header 得到 `len`，再读 payload N bytes。
- 若 `len` 超限，我们通常**无法读取 payload**，也就无法解析 `id`，因此无法可靠返回“带 id 的结构化 error response”。

**选项**

A) 超限立即断连（推荐）
- 行为：检测到 `len > maxFrameBytes` → 立即 close（不返回 response frame；可记录 server log）。

好处：
- **最安全/最简单**：不分配大 buffer、不尝试 drain、不存在被超大 payload 拖死的风险。
- 与 netstring framing 的常见实践一致：framing 层错误/超限属于“连接级错误”。

代价/影响：
- 客户端只能通过“连接被关闭”感知错误（但 well-behaved 客户端可先通过 `HELLO.result.maxFrameBytes` 自检；CLI 也应在本地预检并提示）。

B) 超限后 best-effort 输出一个 `type="notice"` 再断连（不推荐）
- 行为：输出 `{"type":"notice","notice":"frameTooLarge","maxFrameBytes":...}`（无 `id/ok`），然后 close。

好处：
- 对人肉/调试更友好：至少能看到“为什么断了”。

代价/影响：
- 协议复杂度上升：需要明确“在未进入 stream session 时也可能收到 notice”。
- notice 不带 `id`，客户端仍然无法把它归因到某个 request；实现上也不保证对端能收到（对端可能未读就被 close）。

C) 超限后 drain/skip payload 并继续读下一帧（不推荐）

好处：
- 同一连接可能“自愈”，不用重连。

代价/影响（很大）：
- 存在 DoS 风险（攻击者可持续发送超大 len，迫使 server 做无意义 drain）。
- 复杂且很难写对（skip 过程中还要处理断连/半包/并发写等）。

**我的建议**
- 2.37：A（超限属于 framing 级错误：立即断连；把可读错误提示放到 CLI 的“发送前预检”里做）。

**裁决（你确认，2026-04-17）**
- 2.37-A

## 3. 建议的下一步（把冲突一次性打掉）

- S1：在 `docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md` 增加一段“本目录决策将覆盖哪些既有单一真相”的声明，并点名至少：`docs/INTERFACE_SPECIFICATION.md` 与 `openspec/specs/multi-user-support/spec.md` 的相关章节需要同步更新。
- S2：D4 已锁死（endpoints/HELP/requestId/STOP + “vNext 稳定后删除 legacy endpoints”）；建议下一轮把“稳定判据/下线节奏”写成一句可执行的约束（见 0.6），然后再开始拆 change/task。
- S3：下一轮建议优先收敛：
  - 2.23.* 的落地边界：哪些观测路径允许读取/输出 `domain/host`；`domain.validIP` 判定与字段输出放在哪个线程（避免 hot path 每包 `time()`）；以及缺失映射时的对外解释口径
  - 2.24：stream optional 字段缺失表示（省略 vs `"n/a"`）与 `timestamp/wouldDrop` 的类型收敛
  - 2.25：vNext `error.code` 最小稳定枚举（前端/脚本统一修复逻辑的前提）
