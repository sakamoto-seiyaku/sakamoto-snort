# Design: DomainPolicy `policySource` counters (B layer)

> 目标：在不改变现有域名判决语义的前提下，为每次 DNS 判决提供稳定的来源归因与常态 counters，并满足热路径约束与严格 reset 语义。

## 1. Source model（与代码语义对齐）
`policySource` 只做“命中来源归因”，与 `App::blocked()` 分支顺序一一对应：

1) `CUSTOM_WHITELIST` → allow  
2) `CUSTOM_BLACKLIST` → block  
3) `CUSTOM_RULE_WHITE` → allow  
4) `CUSTOM_RULE_BLACK` → block  
5) `GLOBAL_AUTHORIZED` → allow（domain-only device-wide）  
6) `GLOBAL_BLOCKED` → block（domain-only device-wide）  
7) `MASK_FALLBACK` → allow/block（按 `appMask & domainMask`）

约束：
- `_useCustomList==false` 时：不访问任何 custom/global 分支，直接 `MASK_FALLBACK`。
- `domain==nullptr` 或 `BLOCK=0`：维持现状为 allow；B 层 counters 的更新 gating 由上层决定（仅 `BLOCK=1` 更新）。

## 2. API shape（不改变现有行为）
为避免破坏现有逻辑，新增一个内部 API（名字示意）：
- `App::blockedWithSource(domain) -> {blocked, color, policySource}`

要求：
- 与 `App::blocked(domain)` 的判决结果严格等价；
- `policySource` 必填且只可能为 7 类之一；
- 当未来 `App::blocked()` 调整顺序时，必须同步调整 `blockedWithSource()`（并更新 spec + tests）。

## 3. Counters 数据结构（固定维度，无分配）
### 3.1 Device-wide
- 固定维度二维数组：`counters[source][allow|block]`
- `uint64_t` 原子累加：`fetch_add(1, std::memory_order_relaxed)`
- since boot（不持久化）；reset 仅清零

### 3.2 Per-app
把同样的固定维度数组挂到 `App`（或等价稳定生命周期对象）上：
- 不允许按首次命中来源动态分配子结构
- 不允许为每次更新做 map lookup

## 4. Update 时点与 gating
更新口径按 “DNS 请求（一次判决）”：
- 在 DNS listener 完成 `blockedWithSource()` 判决后更新一次
- `BLOCK=1` 才更新（与现状 philosophy 一致：BLOCK=0 不做额外处理/统计）
- 不依赖 `tracked`（避免现有 `DnsListener` 的 `blockEnabled && tracked` gating 影响常态 metrics）

## 5. 控制面与 JSON 输出
命令族：
- `METRICS.DOMAIN.SOURCES`
- `METRICS.DOMAIN.SOURCES.APP <uid|str> [USER <userId>]`
- `METRICS.DOMAIN.SOURCES.RESET`
- `METRICS.DOMAIN.SOURCES.RESET.APP <uid|str> [USER <userId>]`

输出要求：
- 固定 wrapper：device-wide `{"sources":{...}}`；per-app `{"uid":...,"userId":...,"app":...,"sources":{...}}`
- 7 个 source key 始终存在，即使全为 0
- 参数非法或 app 不存在：`NOK`
- 只读查询不得创建 app 或引入持久化副作用（需要一个 “find-only” 的 app lookup）

## 6. Reset semantics（严格边界）
需求：`OK` 返回后，后续新发生 DNS 判决只能计入 reset 之后的 counters。

实现策略（首选）：
- `...RESET*` 在 `Control` 层使用 **exclusive `mutexListeners`**（quiesce）执行清零：
  - DNS/packet 热路径均在 shared lock 下运行
  - reset 在 exclusive lock 下执行，提供清晰的边界

可选策略（若未来需要更低 pause）：
- epoch/bank swap：控制面切换到新 bank，再异步清零旧 bank（保证边界语义）

无论实现采用哪种策略，spec 的接口语义视为严格 reset，tests 按严格口径验收。

## 7. Tests（分层）
- host/unit：
  - `blockedWithSource()` 的分支与优先级覆盖
  - `_useCustomList=0` 的退化行为
  - counters snapshot 的 JSON shape、keys 常驻
- integration：
  - 真机触发 DNS 判决 → `METRICS.DOMAIN.SOURCES*` 增长
  - `RESET` / `RESET.APP` 严格归零并可再次增长
  - `BLOCK=0` 场景 counters 不增长；`tracked=0` 仍增长

