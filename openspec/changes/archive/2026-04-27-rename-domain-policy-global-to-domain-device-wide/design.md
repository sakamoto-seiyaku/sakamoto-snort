## Context

当前域名策略（DomainPolicy）的可观测性与 vNext dns stream 会对外输出 `policySource`（以及 `domainSources` counters 的 keys）。其中 device-wide 的命中来源使用了 `GLOBAL_AUTHORIZED` / `GLOBAL_BLOCKED` 这组历史命名，但它们只覆盖 **domain-only 的 device-wide 名单/规则**。

这个命名在 domain+IP 语义边界逐步清晰、IPRULES 能力推进（以及后续 dual-stack）之后会被自然误读为“系统全局来源”，导致：

1. 接口心智负担：`GLOBAL_*` 看起来比 `scope=DEVICE_WIDE` 更像“跨域全局”。
2. 文档/规格漂移：权威决策文档已使用 `DOMAIN_DEVICE_WIDE_*`，但实现/spec/test 仍输出 `GLOBAL_*`。
3. 后续扩展风险：继续堆叠“例外解释”会让 domain-only 与 domain+IP 的边界更难收敛。

约束：

- 不做接口大重构，仅做命名与语义边界对齐。
- 不考虑向前兼容（不做 alias / 双写 / 兼容解析）。

## Goals / Non-Goals

**Goals:**

- 将 DomainPolicy 的 device-wide 来源命名从 `GLOBAL_*` 收敛为 `DOMAIN_DEVICE_WIDE_*`，并在 spec/test/docs 中形成唯一口径。
- 仅变更“名称”，不改变判决链路、优先级、scope 语义与 counters 的统计口径。
- 通过一次性全替换，避免出现同一版本内同时存在新旧命名造成混淆。

**Non-Goals:**

- 不引入 domain+IP 融合（不改变 DomainPolicy 与 IPRULES/packet reason 的边界）。
- 不调整 vNext / control 协议结构（只改枚举字符串）。
- 不改 legacy LAS/文本协议接口与返回格式（如仍存在）。

## Decisions

1. **采用 `DOMAIN_DEVICE_WIDE_AUTHORIZED` / `DOMAIN_DEVICE_WIDE_BLOCKED` 作为对外枚举值**
   - 理由：明确“domain-only + device-wide”语义边界，且与现有权威决策文档一致。
   - 备选：`DOMAIN_DEVICE_WIDE_ALLOWED`。未选用原因：现有语义与实现中更接近 “authorized/blocked” 的对偶，并且减少文档/实现分歧。

2. **内部枚举同名重命名，保持底层 ordinal 不变**
   - 目标：不改变 counters 的固定维度数组 index 与持久化假设（如有），仅替换符号与输出字符串。
   - 具体：保留原 numeric value（例如仍为 4/5）以避免无意义的结构性变更。

3. **不提供兼容层（无 alias/双写）**
   - 理由：用户明确“不需要考虑向前兼容”；同时该变更本质是接口枚举名收敛，兼容层只会在同一语义上制造二义性并拖累后续收口。
   - 影响：所有消费方（前端、集成测试、脚本）必须同步更新。

4. **一次性更新所有输出面与断言面**
   - 输出面：dns stream `policySource`、metrics `domainSources` keys。
   - 断言面：host tests、integration tests、device smoke casebook 文档/脚本、OpenSpec specs。

## Risks / Trade-offs

- [Risk] 接口 breaking 导致前端/工具链无法解析旧值 → Mitigation：同一变更内更新所有 repo 内消费方；并在发布说明/commit message 中明确这是 breaking rename。
- [Risk] 漏改导致同时出现新旧 key → Mitigation：以 `GLOBAL_` / `DOMAIN_DEVICE_WIDE_` 全局 grep 作为验收步骤；并以 host/integration tests 覆盖 dns stream 与 domainSources buckets。
- [Risk] 未来 domain+IP 语义收敛仍可能引入新的命名讨论 → Mitigation：本变更仅把 domain-only 语义边界做“先收口”，后续融合变更应另开 change 并显式描述跨域语义。

## Migration Plan

1. 修改实现：重命名枚举与输出字符串，并更新 vNext stream/metrics 输出路径。
2. 同步更新所有测试与文档断言。
3. 运行 host tests + vNext integration（domain casebook）验证输出一致。
4. 合并发布：该变更应作为单一版本的 breaking rename 交付，不拆分为多版本过渡。

## Open Questions

- 无（本变更仅做命名收敛；命名已选定并与权威决策文档对齐）。

