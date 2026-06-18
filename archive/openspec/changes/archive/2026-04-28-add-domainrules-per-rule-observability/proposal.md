## Why

当前域名侧可观测性已经补齐了 `policySource`（`METRICS.GET(name=domainSources)`）这类 **coarse attribution**，但仍无法回答更常见、更“可操作”的问题：**到底是哪一条 DomainRule（ruleId）在命中、在放行/拦截、在被覆盖（would‑match）**。

根因是现状 `CustomRules` 通过“聚合 regex snapshot（`r1|r2|...`）”做热路径匹配，天然丢失 per-rule 归因；导致前端/排障只能靠手工二分规则集或开着 dns stream 逐条猜测，无法做规则清理、冲突定位与效果量化。

## What Changes

- vNext 在 **tracked 观测场景**（`app.tracked=1`）下，补齐 **ruleId 级别归因**：
  - `STREAM.START(type=dns)` 的 tracked 事件补齐 `ruleId` 字段，使前端可以把一次 DNS verdict 精确 join 到某条 DomainRule。
  - `DEV.DOMAIN.QUERY` 在规则分支命中时返回 `ruleId`（用于调试/排障；不影响热路径统计）。
- `METRICS.GET(name=domainRuleStats)` 暴露拉取式 per-rule counters（since-boot；支持 `METRICS.RESET(name=domainRuleStats)` 清零；`RESETALL` 同样清零）。
- 内部实现上，补齐“可归因的规则匹配结构”：在不改变现有 verdict 语义的前提下，使规则集合既能保持现有 fast-path 的 `any-match`，又能在需要时解析出“命中的是哪条 ruleId”。
- 补齐 host / device 回归用例，覆盖 ruleId 归因、tracked-only 计数口径、`RESETALL` 清零边界与协议 shape 的稳定性。

## Capabilities

### New Capabilities

- `domainrules-per-rule-observability`: 域名规则 per-rule 归因与 counters（tracked dns stream + DEV query + `METRICS.domainRuleStats` 的 shape 与语义约束）

### Modified Capabilities

- `control-vnext-metrics-surface`: 增加 `METRICS.GET/RESET` 的新指标名 `domainRuleStats`（不允许 app selector）
- `dx-smoke-domain-casebook`: 增补真机/host 冒烟用例，覆盖 per-rule 归因与 reset 边界

## Impact

- Affected code:
  - DomainPolicy 判决路径（`App::blocked*` / `DomainManager::*` / `CustomRules`）
  - vNext dns stream 事件结构（`ControlVNextStreamManager::DnsEvent` + JSON 序列化）
  - vNext domain handler（`DEV.DOMAIN.QUERY` 输出）
  - vNext metrics handler（`METRICS.GET/RESET`）
- Affected docs/specs: `docs/INTERFACE_SPECIFICATION.md`、本 change 的新规格与对应的 smoke/casebook spec。
- 性能影响：
  - 默认（`app.tracked=0`）不应引入任何额外 per-rule 匹配/归因开销。
  - 仅在 `app.tracked=1` 且命中规则分支时，才会发生归因扫描与 per-rule 计数更新（需在 design/tasks 中给出 gating 与基线验证）。
