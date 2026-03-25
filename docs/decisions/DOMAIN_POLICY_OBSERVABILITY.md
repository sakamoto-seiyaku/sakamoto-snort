# 域名策略可观测性（DomainPolicy）：`policySource` 归因与常态 counters（DNS 口径）

> 当前状态（2026-03-25）：A/C/D、IPRULES v1 与 IP 真机测试模组已落地；本文件对应 observability 的 **B 层**，是当前下一步功能主线。  
> 当前尚未实现；本文应作为后续 OpenSpec change、接口文档与测试用例的落地基线。
> 对应 OpenSpec change：`openspec/changes/add-domain-policy-observability/`

> 本文档用于固化“域名策略（现有功能已完成）”在可观测性上的**归因模型**与**常态 counters**设计，避免后续 IP 规则方向变化导致域名侧返工。  
> 约束：不新增观测通路；常态统计必须不依赖 `PKTSTREAM`；不做全局 safety-mode；不做域名规则 per-rule counters。

---

## 0. 背景与目标

域名侧当前已经具备完整的决策链路（自定义名单/规则、全局名单/规则、blocking list、mask fallback 等）。  
但缺少“可解释归因（policySource）”与“默认可查的命中次数（counters）”，导致前端在排障/调试策略时只能依赖 `DNSSTREAM`（调试型事件流）或现有 stats（偏流量/粗粒度）；当前 `PKTSTREAM` 侧并不承载域名策略的 `policySource` 语义。

本文目标是：

1. 明确一个稳定、可枚举的 **`policySource`**（命中来源归因），与当前 `App::blocked()` 的分支顺序一一对应。
2. 定义一组 **常态 counters（拉取式）**：按 `policySource` 的 allow/block 计数（**按 DNS 请求口径**），支持 **device-wide + per-app(UID)**。
3. 明确接口/RESET/测试口径，使该能力可以直接进入后续实现而不再回到“概念讨论”状态。
4. 明确非目标：域名规则 per-rule counters（regex/wildcard/listId 级别）延后。

---

## 1. 现状事实（代码语义）

### 1.1 DNS 决策链路（域名策略本体）

- DNS listener 收到 `(domain, uid)` 后构造 `app` 与 `domain`，并调用 `app->blocked(domain)` 得到 DNS verdict。  
  参考：`src/DnsListener.cpp#L160`（`clientRun` 内对 `app->blocked(domain)` 的调用路径）。

- 注意：现有 DNS 的 stats/stream 更新被 gating：
  - 仅当 `settings.blockEnabled()==true && app->tracked()==true` 才更新 stats 并输出 DNSSTREAM。  
    参考：`src/DnsListener.cpp#L222`。

本文的 counters（metrics）**不应**依赖 `tracked`；它属于“默认可查”常态信息。
当前代码中也**不存在** domain policy source 维度的常态 counters；因此本文件定义的是新增能力，而不是对现有 `APP.DNS.*` / `DNSSTREAM` 的改名包装。

### 1.2 `App::blocked()` 的优先级链路（归因来源）

`App::blocked(domain)` 的实现已经隐含了“命中来源优先级”，但对外只返回 `(blocked, color)`：  
参考：`src/App.cpp#L90`。

关键 gating：

- `domain == nullptr` 或 `BLOCK=0` 时直接返回 allow（`blocked=false, color=GREY`）。  
  参考：`src/App.cpp#L90`。
- 若 `_useCustomList == false`：跳过自定义名单/规则/全局名单判断，直接走 mask fallback。  
  参考：`src/App.cpp#L95` 起。

全局（device-wide）名单/规则由 `DomainManager` 决定：  
参考：`src/DomainManager.cpp#L74`（`authorized/blocked`）。

> 术语：本文中的 “全局 / `GLOBAL_*`” 仅指 **域名策略（DomainPolicy）层** 的 device-wide 名单/规则；  
> 它不覆盖 IPRULES、Packet `reasonId` 等其它维度。域名+IP 的统一命名与融合在后续阶段处理。

---

## 2. `policySource`（域名策略命中来源）模型

### 2.1 枚举定义（固定、可扩展）

`policySource` 取值（字符串枚举）：

1. `CUSTOM_WHITELIST`（app 级自定义白名单命中）
2. `CUSTOM_BLACKLIST`（app 级自定义黑名单命中）
3. `CUSTOM_RULE_WHITE`（app 级自定义白规则命中）
4. `CUSTOM_RULE_BLACK`（app 级自定义黑规则命中）
5. `GLOBAL_AUTHORIZED`（domain-only device-wide 授权命中：域名侧全局白名单/白规则）
6. `GLOBAL_BLOCKED`（domain-only device-wide 拦截命中：域名侧全局黑名单/黑规则）
7. `MASK_FALLBACK`（最终回退：`app.blockMask & domain.blockMask`）

> 说明：这套枚举只做“来源归因”，**不细到具体 ruleId / listId**；细粒度定位属于后续独立功能线（会牵涉到域名规则匹配结构变化）。

### 2.2 命中唯一性与优先级（与现状实现一致）

在给定 `domain != nullptr` 且 `BLOCK=1` 的前提下，`policySource` 的决策顺序（从高到低）与 `App::blocked()` 一致：

1. `CUSTOM_WHITELIST` → allow
2. `CUSTOM_BLACKLIST` → block
3. `CUSTOM_RULE_WHITE` → allow
4. `CUSTOM_RULE_BLACK` → block
5. `GLOBAL_AUTHORIZED` → allow
6. `GLOBAL_BLOCKED` → block
7. `MASK_FALLBACK` → allow 或 block（按 bit 与结果）

当 `_useCustomList == false` 时，`policySource` 永远为 `MASK_FALLBACK`（并且不会访问其它分支）。

### 2.3 per-rule 域名 counters 为什么不做（明确记录）

现状 `CustomRules` 会把多条规则合并成一条大 regex，匹配时只返回 bool，无法回溯“命中哪条规则”：  
参考：`src/CustomRules.cpp#L64`。

因此域名规则 per-rule hit 统计（regex/wildcard）需要改匹配结构，属于更大的重构，明确延后。

---

## 3. 常态 counters（B 层）：按 DNS 请求的 `policySource` allow/block 计数

### 3.1 口径（已定）

- **统计单位：DNS 请求**（每次 DNS 判决更新一次）。
- **先不考虑 ip-leak**：ip-leak 属于 Packet 侧附加功能（Domain↔IP 映射 + `BLOCKIPLEAKS`），不把它混入域名策略 counters，避免因小事大。
- counters **不依赖** `PKTSTREAM/DNSSTREAM` 是否开启（拉取式）。
- counters **不依赖** `tracked`（默认可查）。
- gating：与现状一致，只有在 `BLOCK=1` 时更新（不做全局 dry-run）。
- 更新时点：以 **DNS verdict 已算出** 为准更新一次；不得依赖后续 `getips` / IP 映射读回是否完成，也不得依赖 `DNSSTREAM` 是否输出成功。
- 语义边界：这里统计的是 **DomainPolicy 决策来源**，不是 socket I/O 成功次数，也不是 domain->IP 映射更新次数。

### 3.2 对外接口（控制命令）

新增命令族（拉取式）：

- `METRICS.DOMAIN.SOURCES`
  - 返回：device-wide 汇总（since boot）
- `METRICS.DOMAIN.SOURCES.APP <uid|str> [USER <userId>]`
  - 返回：该 app 的 counters（since boot）
- `METRICS.DOMAIN.SOURCES.RESET`
  - 行为：清空所有 device-wide 与 per-app counters
- `METRICS.DOMAIN.SOURCES.RESET.APP <uid|str> [USER <userId>]`
  - 行为：仅清空指定 app 的 counters

> 多用户语义：参数解析沿用 control 现有 `<uid|str> USER <userId>` 约定（见 `docs/INTERFACE_SPECIFICATION.md` 的多用户参数约定）。
> 落地时需同步更新 `docs/INTERFACE_SPECIFICATION.md`。

补充约束：

- `METRICS.DOMAIN.SOURCES` 与 `METRICS.DOMAIN.SOURCES.APP ...` 都必须返回**固定 wrapper JSON**，而不是裸对象或文本。
- 参数非法时返回 `NOK`。
- `METRICS.DOMAIN.SOURCES.APP ...` / `...RESET.APP ...` 在 app 未匹配时返回 `NOK`；不得沿用部分 legacy GET 命令“无响应（0 bytes）”的历史行为。
- 只读查询不得创建新 app、不得引入持久化副作用。

### 3.3 JSON shape 与兼容性

device-wide：

```json
{
  "sources": {
    "CUSTOM_WHITELIST":  {"allow": 0, "block": 0},
    "CUSTOM_BLACKLIST":  {"allow": 0, "block": 0},
    "CUSTOM_RULE_WHITE": {"allow": 0, "block": 0},
    "CUSTOM_RULE_BLACK": {"allow": 0, "block": 0},
    "GLOBAL_AUTHORIZED": {"allow": 0, "block": 0},
    "GLOBAL_BLOCKED":    {"allow": 0, "block": 0},
    "MASK_FALLBACK":     {"allow": 0, "block": 0}
  }
}
```

per-app：

```json
{
  "uid": 10123,
  "userId": 0,
  "app": "com.example.app",
  "sources": { "...": {"allow": 0, "block": 0} }
}
```

约束：

- 所有 7 个 `policySource` key 必须始终出现，即使值全为 `0`。
- 顶层 wrapper 名称固定为 `sources`，风格与 `METRICS.REASONS` / `METRICS.PERF` 一致。
- 客户端应容忍未来新增的顶层 metadata 字段，但当前 7 个 source key 的含义和顺序必须稳定。

### 3.4 RESET 语义（必须先定）

- `METRICS.DOMAIN.SOURCES.RESET` 与 `...RESET.APP ...` 必须提供**严格 reset 边界**：
  - `OK` 返回之后，后续新发生的 DNS 判决只能记入 reset 之后的 counters；
  - 不允许出现“部分 shard 已清零、部分未清零、边界请求随机丢失/保留”的不确定语义。
- 实现可选：
  - 与当前 `METRICS.REASONS.RESET` 一样，通过 exclusive listener quiesce 保证边界；
  - 或者使用 epoch/bank swap 达到等价效果。
- 无论采用哪种实现，接口层语义都应视为“严格 reset”，测试也必须按严格口径验收。

### 3.5 更新点（实现指引，非本轮实现）

为避免改变现有语义，建议新增一个内部 API（名字仅示意）：

`App::blockedWithSource(domain) -> {blocked, color, policySource}`

其内部逻辑必须与 `App::blocked()` 等价，并保证：
- `policySource` 总是被填充为上述 7 类之一
- 决策顺序完全一致

在 DNS listener 做判决时（且 `BLOCK=1`）：
- 更新 device-wide counters：`global.observe(source, blocked)`
- 更新 per-app counters：`app.observe(source, blocked)`

实现层约束：
- counters 存储应为**固定维度数组 / enum index**；热路径上不做按 source 的 map 查找。
- counters 仅允许固定维度的 `atomic++ (relaxed)`；不做 map 插入/分配。
- per-app counters 应直接挂在 `App` 或等价固定生命周期对象上；不得为了首次命中某个 source 再分配子结构。
- since boot（不持久化）；RESET 命令清零即可。

---

## 4. 与其它可观测性的关系（避免割裂）

- A 层（Packet `reasonId` counters）与 C 层（IP per-rule stats）会在各自 change 中落盘（OpenSpec change），本文仅固化域名侧 B 层。
- B 层是当前下一步功能主线；实现时应新建独立 OpenSpec change，而不是直接绕过 spec 流程修改接口。
- 未来如需把 ip-leak 纳入“域名观测”，建议以 **单独维度**追加（例如 `METRICS.IPLEAK.*`），不要混进 `METRICS.DOMAIN.SOURCES`，避免语义混乱。

---

## 5. 验收与测试口径

最小功能验收：

1. 构造命中 app 自定义白名单的 DNS 请求：`CUSTOM_WHITELIST.allow += 1`
2. 构造命中 app 自定义黑名单：`CUSTOM_BLACKLIST.block += 1`
3. 构造命中 app 自定义白规则/黑规则：对应 `CUSTOM_RULE_*` 增长
4. 构造命中全局 authorized/blocked：对应 `GLOBAL_*` 增长
5. 关闭 `_useCustomList`：所有命中都落在 `MASK_FALLBACK`（allow 或 block）
6. `BLOCK=0` 时 counters 不增长
7. `tracked=0` 时 counters 仍正常增长
8. `METRICS.DOMAIN.SOURCES.RESET` 后所有 device-wide/per-app 计数归零；随后重新发送 DNS 请求可再次增长
9. `METRICS.DOMAIN.SOURCES.RESET.APP ...` 只清空目标 app，不影响其它 app 与 device-wide 总量之外的独立 app 视图

建议测试分层：

- host/unit：对 `App::blockedWithSource()` 或等价 source classifier 做优先级与 `_useCustomList=0` 的纯逻辑测试。
- host-driven integration：通过控制口 + DNS listener 闭环验证 `METRICS.DOMAIN.SOURCES*`、`RESET` / `RESET.APP`、`BLOCK=0`、`tracked=0`。
- 回归口径：至少要覆盖 device-wide 与 per-app 结果一致性，以及 reset 边界的严格语义。
