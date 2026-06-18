## Why

`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## 域名` 章节已经把 Domain smoke 的人话验收口径拆成 Case 1–9，但当前 `dx-smoke-control` 只覆盖了部分 surface 与基础 domainSources 行为，尚未把“触发 → stream/metrics/domainSources → 可解释字段”的完整闭环落实到测试中。

本 change 以 casebook 的 Domain 章节为唯一范围，把这些缺口补齐到 active vNext smoke，避免 domain 侧回归只能依赖人工排查或旧脚本经验。

## What Changes

- 将 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 域名` 下的 Case 1–9 落实为 `dx-smoke-control` 的可重复测试责任：
  - Case 1–2：强化现有 Domain surface / DomainSources 断言，补负向契约与 bucket 级校验。
  - Case 3–4：补齐 `dx-netd-inject` DNS e2e 的 dns stream 字段、`traffic.dns`、`domainSources` 与 `notice.suppressed` 断言。
  - Case 5–7：新增 `domain.custom.enabled`、APP vs DEVICE_WIDE 优先级、DomainLists enable/disable 与 allow 覆盖 block 的端到端断言。
  - Case 8：新增真实 resolver hook DNS e2e；hook 不活跃时按 casebook 报告 `BLOCKED`，而不是静默通过或误报 PASS。
  - Case 9：新增 `DOMAINRULES(ruleIds)` 端到端，覆盖 `CUSTOM_RULE_WHITE` / `CUSTOM_RULE_BLACK` buckets。
- 保持 active smoke 入口不变：不新增 `dx-smoke*` 名称，默认仍通过 `dx-smoke-control` / `tests/integration/vnext-baseline.sh` 承接。
- 只做测试、脚本与文档对齐；不顺带实现产品功能，不修改控制协议语义。
- 所有新增测试必须有明确的状态清理与 restore 策略，避免污染后续 case 或开发者设备状态。

## Capabilities

### New Capabilities
- `dx-smoke-domain-casebook`: 定义 `dx-smoke-control` 对 `DEVICE_SMOKE_CASEBOOK.md` Domain Case 1–9 的测试承接范围、必测断言、BLOCKED/FAIL 语义与清理要求。

### Modified Capabilities
- （无）

## Impact

- `tests/integration/vnext-baseline.sh`：补齐 Domain Case 1–9 的自动化断言与 helper。
- `tests/integration/lib.sh`：可选抽取 JSON、stream、metrics 或 restore helper，前提是只服务 vNext active smoke。
- `docs/testing/DEVICE_SMOKE_CASEBOOK.md`：把 Domain 章节的“现有覆盖/缺口”更新为实际测试 check id。
- `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`：同步 Domain smoke 覆盖矩阵与真实 resolver hook 的 BLOCKED 语义。
- 不影响 `src/` 产品逻辑、控制协议向后兼容性、CMake 入口命名或 IP/Conntrack smoke 责任。
