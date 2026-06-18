# Change: DomainPolicy B-layer observability (policySource counters)

## Why
域名侧当前判决链路（自定义名单/规则、全局名单/规则、mask fallback）已经可用，但缺少：
- **可解释归因**：每次 DNS 判决究竟命中哪一层（policySource）。
- **默认可查 counters**：无需订阅 `DNSSTREAM`，即可拉取“命中次数”用于排障与回归对比。

这会导致：
- 前端在排障时只能依赖调试型 stream（易丢、噪声高、且可能被 `tracked` gating 影响）；
- 无法在不改动 UI 的前提下快速回答“当前策略命中分布是什么”。

本 change 负责把 observability 的 **B 层（DNS 口径）**落地为稳定接口与可验收的测试基线。

权威决策文档：`docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`。

## What Changes
- 新增 `policySource` 归因模型（字符串枚举），与 `App::blocked()` 的分支顺序一一对应（不细到 ruleId/listId）。
- 新增常态 counters（拉取式）：
  - device-wide 汇总 + per-app(UID) 视图
  - 统计单位：**DNS 请求**（每次 DNS 判决更新一次）
  - gating：仅在 `BLOCK=1` 时更新；**不依赖** `tracked`
- 新增控制面命令（固定 wrapper JSON）：
  - `METRICS.DOMAIN.SOURCES`
  - `METRICS.DOMAIN.SOURCES.APP <uid|str> [USER <userId>]`
  - `METRICS.DOMAIN.SOURCES.RESET`
  - `METRICS.DOMAIN.SOURCES.RESET.APP <uid|str> [USER <userId>]`
- RESET 语义：提供**严格 reset 边界**（`OK` 返回后，新的 DNS 判决只能计入 reset 之后的 counters）。

## Relationship to existing changes
- 本 change 属于 observability 的 **B 层**；与 A（Packet reasons）、C（IP per-rule stats）、D（perf metrics）语义独立。
- `GLOBAL_*` 在本 change 中仅指 **域名策略（DomainPolicy）层的 device-wide 名单/规则**，不等价于 domain+IP 的真正全局；统一命名/融合后置。

## Non-Goals
- 不做域名规则 per-rule counters（regex/wildcard/listId 归因）。
- 不把 ip-leak 统计混入 `METRICS.DOMAIN.SOURCES*`。
- 不新增新的 stream、存储系统或每请求日志。
- 不改变现有 `App::blocked()` 的对外语义（新增的 source 归因 API 必须与现状判决等价）。

## Impact
- Affected code（实现阶段）：
  - `src/App.cpp`, `src/App.hpp`
  - `src/DnsListener.cpp`
  - `src/Control.cpp`, `src/Control.hpp`
  - （可能）新增 `*Metrics*` 小模块/类（对齐 `ReasonMetrics` / `PerfMetrics` 风格）
- Affected tests（实现阶段）：
  - `tests/host/*`（policySource 归因与 counters 单测）
  - `tests/integration/*`（控制面命令 + DNS 触发闭环）
- Affected docs（实现阶段）：
  - `docs/INTERFACE_SPECIFICATION.md`

