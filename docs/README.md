# Docs Index

`docs/` 根目录只保留总入口与权威汇总；其余文档按类型分层收纳，避免主线文档继续堆在同一层。

## Repo-level entrypoints

- `CONTEXT.md`：项目术语表与领域语言入口
- `CLAUDE.md` / `AGENTS.md`：agent 启动指令；包含 `## Agent skills` 块
- `docs/agents/`：Matt skills / Plane / 文档消费规则

## Root entrypoints

- `docs/IMPLEMENTATION_ROADMAP.md`：当前实现主线、阶段状态与优先级
- `docs/INTERFACE_SPECIFICATION.md`：对外控制面 / stream 接口汇总
- `docs/testing/HOST_TEST_SURVEY.md`：当前 Host 端测试现状、sanitizer lane 与覆盖缺口

## Subdirectories

- `docs/decisions/`：设计原则、工作决策、上位约束
- `docs/testing/README.md`：测试文档入口（Host / Device / perf）
- `docs/testing/`：测试纲领、runbook、结果记录
- `docs/tooling/`：开发、调试、工作流
- `docs/reviews/`：点状审查产物；按需查证，不作为默认权威入口
- `docs/reference/`：背景对比与参考材料；按需阅读
- `docs/archived/`：已归档的历史讨论与过程记录；不作为默认 agent 上下文
- `archive/openspec/`：OpenSpec 历史归档；不作为当前流程约束

## Suggested reading order

1. `CONTEXT.md`
2. `docs/agents/domain.md`
3. `docs/IMPLEMENTATION_ROADMAP.md`
4. `docs/INTERFACE_SPECIFICATION.md`
5. `docs/decisions/`
6. `docs/testing/README.md` or `docs/tooling/` when the task touches tests/build/debug
7. `docs/reviews/`, `docs/reference/`, `docs/archived/`, and `archive/openspec/` only when the user asks for historical context or the active docs explicitly point there
