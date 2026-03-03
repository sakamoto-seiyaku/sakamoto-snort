# Change: Roll up remaining verification + docs (multi-user + blockmask chains)

## Why
`add-multi-user-support` 与 `add-combinable-blockmask-chains` 两个 change 已完成主要实现与本地验证，但仍有少量“验证/文档/回归沉淀”类任务散落在两个 change 的尾部，容易在归档时遗漏。

为降低风险与减少工作面分散，本 change 将两个 change 的**剩余任务合并**到同一处追踪；同时将原两个 change 归档，保持 OpenSpec 视图整洁。

## What Changes
- **不引入新的运行时行为变更**（目标是验证与文档同步）。
- 将以下 change 的未完成任务迁移并合并到本 change：
  - `add-combinable-blockmask-chains`（验证 4.x）
  - `add-multi-user-support`（验证 1.11~1.13、2.6）
- 同步更新与校对项目文档 / OpenSpec main specs，确保“文档描述”与“当前代码行为”一致。

## Impact
- Affected OpenSpec:
  - Archive: `add-combinable-blockmask-chains`, `add-multi-user-support`
  - New tracking change: `update-multi-user-and-blockmask-chains-rollup`
- Affected docs (non-exhaustive):
  - `openspec/project.md`（多用户现状、数据源、监听描述）
  - 其他与多用户/组合链相关的接口与设计文档（按需要最小改动）

