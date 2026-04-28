## 1. Interface & Docs

- [x] 1.1 更新 `docs/INTERFACE_SPECIFICATION.md`：补齐 `METRICS.GET/RESET(name=domainRuleStats)` 的 name、返回 shape 与 reset 说明
- [x] 1.2 更新 `docs/INTERFACE_SPECIFICATION.md`：补齐 dns stream `type=dns` 事件的 `ruleId` 字段与出现条件（tracked-only）
- [x] 1.3 更新 `docs/INTERFACE_SPECIFICATION.md`：补齐 `DEV.DOMAIN.QUERY` 的 `ruleId` 字段与出现条件（不得更新 counters）

## 2. Rule Counters

- [x] 2.1 在 `Rule` 增加 since-boot runtime counters（`allowHits/blockHits`），并提供清零 API（线程安全、无锁读写）
- [x] 2.2 `Rule::update()`/规则语义变更时清零该 rule 的 counters（避免旧统计污染新规则）
- [x] 2.3 在 `RulesManager` 增加“按 baseline 顺序枚举 rule + 读取 counters”的 helper（供 metrics 与测试使用）

## 3. CustomRules 归因 Snapshot

- [x] 3.1 扩展 `CustomRules`：在保持现有聚合 regex `any-match` snapshot 的同时，新增归因 snapshot（按 `ruleId` 升序的 per-rule matcher）
- [x] 3.2 为 `CustomRules` 增加归因 API（例如 `matchFirstRuleId(domain)`），并保证 lock-free 读路径（atomic snapshot load）
- [x] 3.3 增加 host/unit 覆盖：多条规则同时命中时选择最小 `ruleId`

## 4. DomainPolicy 归因 Plumbing（dns / DEV）

- [x] 4.1 扩展 `DomainManager`：为 device-wide allow/block ruleset 提供可选 `ruleId` 归因（区分名单命中与规则命中；不改变现有 `authorized/blocked` 语义）
- [x] 4.2 扩展 `App`：新增返回 `{blocked,color,policySource,ruleId?}` 的判决 helper（仅在 tracked dns stream / DEV query 路径调用；默认热路径不调用）
- [x] 4.3 更新 `DnsListener`：仅在 `block.enabled=1 && app.tracked=1` 时对规则分支命中更新 per-rule counters；在 tracked dns event 中填充 `ruleId`
- [x] 4.4 更新 `ControlVNextStreamManager::DnsEvent` 与 `ControlVNextStreamJson::makeDnsEvent()`：序列化新增字段且不破坏现有字段语义
- [x] 4.5 更新 `DEV.DOMAIN.QUERY`：返回新增归因字段，与 dns stream 字段口径保持一致

## 5. vNext Metrics：domainRuleStats

- [x] 5.1 更新 metrics name 校验：`METRICS.GET/RESET` 支持 `name=domainRuleStats` 且禁止 `args.app`
- [x] 5.2 实现 `METRICS.GET(name=domainRuleStats)`：按 baseline 输出全量 `rules[]`（排序稳定；包含 `allowHits/blockHits`）
- [x] 5.3 实现 `METRICS.RESET(name=domainRuleStats)`：清零全部 rule counters，并按规格决定是否需要 `mutexListeners` 独占短窗口保证严格边界
- [x] 5.4 确保 `RESETALL` 同样清零 domainRuleStats（回归测试覆盖）

## 6. Tests & Smoke

- [x] 6.1 Host tests：补齐 `METRICS.GET/RESET(name=domainRuleStats)` 的 shape、排序、reset 语义与 `args.app` 拒绝
- [x] 6.2 Host tests：补齐 `DEV.DOMAIN.QUERY` 在规则分支输出 `ruleId` 的契约（且不增长 domainRuleStats）
- [x] 6.3 Device smoke：更新 `dx-smoke-control` 的 Domain Case 9，断言 dns event 输出 `ruleId` 且 domainRuleStats counters 增长/可 reset

## 7. Verification

- [x] 7.1 跑 host test 子集（domain surface + metrics + 归因 unit），确认无回归
- [x] 7.2 跑真机 Domain 冒烟（至少 Case 9），确认 ruleId 与 domainRuleStats 行为符合规格
