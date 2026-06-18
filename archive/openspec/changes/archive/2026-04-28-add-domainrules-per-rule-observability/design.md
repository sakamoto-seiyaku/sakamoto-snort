## Context

现状域名侧已经具备：

- **B 层**（DomainPolicy）`policySource` 归因与常态 counters：`METRICS.GET(name=domainSources)`（见 `docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`）。
- vNext `STREAM.START(type=dns)` 的逐条事件（tracked gating）。

但 domain rules 侧仍缺少 per-rule 归因与统计。主要技术障碍在于：

- `CustomRules` 当前为热路径使用“聚合 regex snapshot”（`r1|r2|...`）做 `any-match`，匹配结果仅有 bool，**无法恢复命中的 ruleId**。
- 若改成对每条 rule 逐个 `std::regex_match()`，可得到 ruleId，但在规则数较大或规则很“宽”（近似全匹配）时会显著增加 DNS 判决成本。

本 change 的目标是在 **不改变现有 verdict / policySource 语义** 的前提下，补齐：

1. dns stream / DEV query 的 ruleId 级别归因。
2. `METRICS.GET(name=domainRuleStats)` 拉取式 per-rule counters（since-boot；可 reset）。

## Goals / Non-Goals

**Goals:**

- **不改变** DomainPolicy 的 verdict 与 `policySource` 优先级/枚举集合。
- 在不引入新外部依赖的前提下，实现 **deterministic 的 ruleId 归因**（同一输入在同一规则集下应得到稳定结果）。
- 默认情况下不显著增加 DNS 热路径开销；新增开销仅在 `app.tracked=1` 且命中规则分支时出现。
- `METRICS.GET(name=domainRuleStats)` 提供 per-rule counters（以 baseline ruleset 为输出集合；计数口径为 tracked-only），并支持 `METRICS.RESET(name=domainRuleStats)`。
- tracked dns stream 事件补齐 `ruleId` 字段，使前端无需“猜测”即可 join 到 DomainRule。
- **计数口径为 tracked-only**：仅当 `app.tracked=1` 的真实 DNS verdict 才会计算 ruleId 并更新 per-rule counters，以避免对默认热路径产生回退。

**Non-Goals:**

- 不做 domain list（`DOMAINLISTS.*`）的 per-listId/per-entry 归因与统计。
- 不引入 PCRE2/RE2 等新的 regex 引擎依赖（Android 体积/维护成本与一致性风险过高）。
- 不重定义 `Rule::DOMAIN`/`Rule::REGEX` 的语义（当前匹配语义保持不变；本 change 只补齐 observability）。
- 不提供 per-app 的 domainRuleStats 拉取式统计（内存维度不可控；per-app 细节以 dns stream 过滤/统计承接）。

## Decisions

1. **把“归因能力”做成与 fast-path 分离的 lock-free snapshot。**

   - 保留现有 `CustomRules` 的聚合 regex snapshot 用于 `any-match`（bool），确保现有判决路径的基本性能特征不被改变。
   - 新增一份 **归因用 snapshot**：按 `ruleId` 升序保存“单条规则的已编译 matcher”（例如 `std::regex`），用于在需要时解析出 `firstMatchRuleId`。
   - 两份 snapshot 都通过 `atomic_store/std::atomic_load(std::shared_ptr<...>)` 发布，DNS 热路径不引入额外锁。

   归因策略：选择 **ruleId 最小**的那条匹配规则作为 `ruleId`（deterministic；避免“同一条 DNS 被多个重叠规则同时计数”的二义性）。

2. **只在“规则分支命中”时做归因；其余 policySource 不做额外工作。**

   - 仅当 `policySource ∈ {CUSTOM_RULE_WHITE, CUSTOM_RULE_BLACK, DOMAIN_DEVICE_WIDE_AUTHORIZED, DOMAIN_DEVICE_WIDE_BLOCKED}` 时尝试解析 `ruleId`。
   - 对于 device-wide 分支，进一步区分“名单命中 vs 规则命中”：若 decision 来自 device-wide custom list（`CustomList.exists()`），则 `ruleId` 为空；仅在确认为规则命中时填充 `ruleId`。
   - `policySource=CUSTOM_WHITELIST/CUSTOM_BLACKLIST/MASK_FALLBACK` 不填 `ruleId`，也不做额外匹配。

3. **Tracked-only：仅在 `app.tracked=1` 时进行 ruleId 归因与计数更新。**

   - 真实 DNS 热路径：仅当 `settings.blockEnabled()` 且 `app.tracked=1` 时，才会为规则分支计算 `ruleId` 并更新 `domainRuleStats` counters。
   - `DEV.DOMAIN.QUERY`：作为调试/排障命令，可计算并返回 `ruleId`，但**不得**更新 `domainRuleStats` counters（避免 DEV 工具污染统计口径）。

4. **per-rule counters 直接挂载在 `Rule` 对象上，使用 `atomic<uint64_t>`。**

   - 每条 baseline ruleId 的 counters 与该 `Rule` 对象同生命周期，避免全局 `unordered_map` 插入/分配带来的热路径成本与复杂 reset 行为。
   - `RulesManager::updateRule/upsertRuleWithId` 修改 pattern/type 时，规则语义已变化，必须清零该 rule 的 counters（避免旧语义计数污染新规则）。
   - `METRICS.GET(name=domainRuleStats)` 以 `RulesManager` 的 baseline 快照为“输出集合”，对每条规则读取其 counters 并输出（按 `ruleId` 升序）。

5. **重置语义：提供 `METRICS.RESET(name=domainRuleStats)`，并保证与 DNS 并发的一致性边界可解释。**

   - 最低要求：reset 为“尽力而为”的原子清零（`store(0)`），并在文档中明确并发窗口可能造成极少量边界误差。
   - 若需要严格边界：reset handler 在清零 counters 时短暂获取 `mutexListeners` 独占锁（DNS 判决窗口持有 shared 锁），形成清晰的 happens-before 边界；清零本身应是纯内存操作，独占窗口应保持极短。

   （是否要强制严格边界，以 specs 的 REQUIREMENTS 为准；实现上优先选择“独占锁短窗口”而不是引入 epoch/bank swap 的复杂结构。）

## Risks / Trade-offs

- [Risk] 规则集合很大且高度命中（宽泛 regex）时，归因扫描会在规则分支上形成额外 CPU 成本  
  → Mitigation：归因只在 `app.tracked=1` 且规则分支命中时发生；选择 `firstMatchRuleId` 并在命中后提前退出；在测试/文档中给出“规则数/命中率 vs 成本”的基线，必要时增加 policy 侧软上限/告警。

- [Risk] `std::regex` 的性能与 Android libc++ 实现相关，极端规则可能出现 pathological 行为  
  → Mitigation：保持现有 `any-match` 路径不变；归因路径仅在 `app.tracked=1` 的命中分支触发；host/device 增加极端规则回归（至少覆盖“全匹配/长输入/高频”场景），并在 `dx` 用例中纳入观察。

- [Risk] device-wide `authorized/blocked` 当前把 “名单/规则” 混在同一个 `policySource` 下，ruleId 仅在规则命中时出现可能让客户端误解  
  → Mitigation：在接口文档中明确：`policySource=DOMAIN_DEVICE_WIDE_*` 时 `ruleId` 可能缺失（表示来自名单而非规则）；客户端 UI 应按 `ruleId` 是否存在决定展示“具体规则”还是展示“device-wide list”。

- [Risk] reset 严格边界若采用独占锁，会短暂阻塞 DNS 判决  
  → Mitigation：清零过程必须是纯内存、线性扫描 baseline rules；保持在毫秒级；并将 reset 视为运维/调试命令，不在高频路径调用。

## Migration Plan

- 分阶段落地（同一 change 内按任务拆解）：
  1. 先落地 `CustomRules` 归因 snapshot + `DEV.DOMAIN.QUERY` 输出字段（便于 host/unit 验证）。
  2. 再落地 dns stream 事件字段扩展（tracked path），并补齐 casebook。
  3. 最后落地 `METRICS.GET/RESET(name=domainRuleStats)` 与 counters（含 reset 语义与回归）。

- 回滚策略：
  - 若发现性能回退或异常，可先保留接口字段但在实现上返回空（`ruleId` 缺失、counters 全 0），或通过编译期开关禁用归因 snapshot 构建；不影响原始 verdict。

## Open Questions

- `METRICS.RESET(name=domainRuleStats)` 是否必须提供“严格边界”（独占锁）还是允许 best-effort？需要在 specs 中明确。
- `ruleId` 的归因是否需要暴露“匹配集合”而非单一 `firstMatchRuleId`？当前选择单一 ruleId 是为了稳定与性能；若未来需要多匹配集，需要单独评估 UI/性能与输出 shape。
