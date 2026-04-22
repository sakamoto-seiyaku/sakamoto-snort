# Change: Roll up deferred verification/docs (post domain+IP fusion)

## Why
`add-multi-user-support` 与 `add-combinable-blockmask-chains` 两个 change 已完成主要实现与本地验证，但仍有少量“验证/文档/回归沉淀”类任务散落在两个 change 的尾部，容易在归档时遗漏。

同时，IP 真机测试模组 (`add-ip-test-component`) 已完成核心 runner/matrix/stress/perf，但 `longrun` 与可选 CI hook 这类“晚点再跑/晚点再接”的工作不适合在当前域名主线推进中穿插。

为降低风险与减少工作面分散，本 change 将上述“**不适合当下立刻做的剩余任务**”合并到同一处追踪（并明确这些任务将放在域名与 IP 融合阶段收尾时再做），保持 OpenSpec 视图整洁。

## What Changes
- 本 change **不引入新的运行时行为变更**（目标是验证与文档同步 + 测试入口收尾）。
- 合并并追踪以下未完成任务（post domain+IP fusion）：
  - `add-combinable-blockmask-chains`：剩余验证
  - `add-multi-user-support`：剩余验证 + 文档/用例沉淀
  - `add-ip-test-component`：Tier-1 `longrun` 与可选 CI hook

## Impact
- Affected OpenSpec:
  - Archive: `add-combinable-blockmask-chains`, `add-multi-user-support`（已完成）
  - Archive: `add-ip-test-component`（近期完成；本 change 仅接手其 deferred tasks）
  - New tracking change: `update-post-domain-ip-fusion-rollup`
- Affected docs (non-exhaustive):
  - `openspec/project.md`（多用户现状、数据源、监听描述）
  - 其他与多用户/组合链相关的接口与设计文档（按需要最小改动）
