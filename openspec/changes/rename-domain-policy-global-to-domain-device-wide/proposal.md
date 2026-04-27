## Why

当前 DomainPolicy（域名策略）的 `policySource` / `domainSources` 对外暴露 `GLOBAL_AUTHORIZED` / `GLOBAL_BLOCKED`，但其真实语义仅为 **domain-only 的 device-wide**（设备级域名名单/规则），并非“系统全局（domain+IP / IPRULES / packet 侧）”的全局来源。

在进入后续 domain+IP 语义边界收敛与 dual-stack 工作之前，这个命名歧义已经开始干扰心智与文档口径（例如权威决策文档已使用 `DOMAIN_DEVICE_WIDE_*`，但代码/spec/test 仍输出 `GLOBAL_*`）。本变更用于把接口命名与语义边界对齐，避免后续扩展继续放大歧义。

## What Changes

- **BREAKING**：将 DomainPolicy 的 device-wide 来源从 `GLOBAL_AUTHORIZED` / `GLOBAL_BLOCKED` 重命名为 `DOMAIN_DEVICE_WIDE_AUTHORIZED` / `DOMAIN_DEVICE_WIDE_BLOCKED`。
- **BREAKING**：vNext dns stream 的 `policySource` 字段输出值随之变更（仅名称变更，判决语义不变）。
- **BREAKING**：`METRICS.GET(name=domainSources)`（及相关输出）中 `sources{}` 的 key 随之变更（仅名称变更，计数语义不变）。
- 同步 OpenSpec 规格与 dx-smoke casebook 的断言口径，确保 spec/test/docs 统一。
- 明确本变更只做“命名与语义边界对齐”，不做 domain+IP 融合与接口大重构。

## Capabilities

### New Capabilities
- （无）

### Modified Capabilities
- `domain-policy-observability`：`policySource` / `domainSources` 的 device-wide 来源命名从 `GLOBAL_*` 改为 `DOMAIN_DEVICE_WIDE_*`。
- `dx-smoke-domain-casebook`：casebook 及 smoke 断言同步更新为 `DOMAIN_DEVICE_WIDE_*`。

## Impact

- 对外接口（vNext）：
  - dns stream 的 `policySource` 枚举值
  - `domainSources` counters 的 JSON keys
- 代码影响面（预计一次性全替换）：
  - DomainPolicySource 枚举与字符串映射
  - vNext stream JSON 组装
  - vNext metrics 输出
- 测试与文档：
  - host / integration 测试用例断言
  - `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 等示例与说明

