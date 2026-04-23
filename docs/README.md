# Docs Index

`docs/` 根目录只保留总入口与权威汇总；其余文档按类型分层收纳，避免主线文档继续堆在同一层。

## Root entrypoints

- `docs/IMPLEMENTATION_ROADMAP.md`：当前实现主线、阶段状态与优先级
- `docs/INTERFACE_SPECIFICATION.md`：对外控制面 / stream 接口汇总
- `docs/testing/HOST_TEST_SURVEY.md`：当前 Host 端测试现状、ASAN 结果与覆盖缺口

## Subdirectories

- `docs/decisions/`：设计原则、工作决策、上位约束
- `docs/testing/README.md`：测试文档入口（Host / Device / perf）
- `docs/testing/`：测试纲领、runbook、结果记录
- `docs/tooling/`：开发、调试、工作流
- `docs/reference/`：背景对比与参考材料
- `docs/archived/`：已归档的历史讨论与过程记录

## Suggested reading order

1. `docs/IMPLEMENTATION_ROADMAP.md`
2. `docs/INTERFACE_SPECIFICATION.md`
3. `docs/testing/HOST_TEST_SURVEY.md`
4. `docs/decisions/`
5. `docs/testing/`
6. `docs/tooling/`
