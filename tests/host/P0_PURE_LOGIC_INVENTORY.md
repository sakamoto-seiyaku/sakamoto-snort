# P0 host-side pure-logic inventory

这份清单采用“先对照文档/设计，再决定是否补测”的原则，避免给错误语义补测试。

## 已覆盖 / 本轮补齐

- `PackageState`
  - 文档依据：`tests/host/README.md`、`openspec/specs/multi-user-support/spec.md`
  - 审计结论：实现已经覆盖 `packages.list`、文本 XML、ABX `package-restrictions.xml` 解析语义。
  - P0 处理：保留既有文本解析测试，并补上 ABX 正向/反向样例，覆盖文档明确要求的 ABX 支持。

- `Rule`
  - 文档依据：`openspec/project.md`、`docs/INTERFACE_SPECIFICATION.md`
  - 审计结论：`WILDCARD` 的 `*`/`?` 语义与 `REGEX` 的原样正则语义是明确的；但 `DOMAIN` 是否应当“字面量精确匹配”，还是继续保持当前“直接透传到 regex”的历史实现，现阶段存在歧义。
  - 历史事实：规则能力在 2023-10-18 的 `add wildcards/regex` 中引入，当时实现即为“仅 `WILDCARD` 做转换，其他类型原样进入 regex”。
  - P0 处理：不在测试 change 中私自改动 `DOMAIN` 产品语义；当前仅为 `WILDCARD` 转义规则与现有 `DOMAIN/REGEX` 行为补 host-side gtest，并把 `DOMAIN` 语义澄清留给后续独立决策。

- `Settings` 纯 helper
  - 文档依据：`docs/INTERFACE_SPECIFICATION.md`、`openspec/specs/multi-user-support/spec.md`
  - 审计结论：`blockMask`/`appMask` 约束，以及 per-user 持久化路径布局，都有明确文档约束。
  - P0 处理：补 helper 级 gtest，验证掩码约束、reinforced => standard 归一化，以及 user0/非 0 用户路径布局。
- `Stats` / `AppStats` / `DomainStats`
  - 文档依据：`tests/host/README.md`、`openspec/project.md`、`docs/INTERFACE_SPECIFICATION.md`
  - 审计结论：P0 适合覆盖“计数、DAY0/WEEK/ALL 视图、reset 后聚合值变化”这些纯逻辑语义。
  - P0 处理：补 host-side gtest，验证计数更新、汇总桶与 reset 语义。

## 当前暂缓

- `CustomRules`
  - 文档依据：`openspec/project.md`、`docs/DOMAIN_POLICY_OBSERVABILITY.md`
  - 审计结论：当前实现把多条规则汇总成单一 regex 快照并只返回 bool；文档也明确 per-rule 归因与 counters 延后。
  - 暂缓原因：若要进一步验证规则归因或更细粒度行为，会触及 `Domain`/快照组合路径，容易超出 P0“最小改动”边界。

- `Control` 参数解析辅助逻辑
  - 文档依据：`openspec/project.md`、`openspec/specs/multi-user-support/spec.md`、`docs/INTERFACE_SPECIFICATION.md`
  - 审计结论：语义明确，但当前 helper 深嵌在 `Control.cpp` 内，并与 `App`、`SocketIO`、manager 图强耦合。
  - 暂缓原因：若现在强行 host-side 化，基本会变成 parser 抽取/解耦重构，不符合 P0 约束。

## P0 关闭条件

- 只有当上面“已覆盖 / 本轮补齐”的模块都完成 host-side 验证，且“当前暂缓”项的原因被清楚记录后，`P0` 才能再次标记完成。
- 集成验证、真机 smoke 与真机调试不吸收这些 pure-logic 责任；后续仅补端到端/平台专项验证与调试链路。
