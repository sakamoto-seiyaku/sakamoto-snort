## Why

`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 已经把 `## 其他` 的两个收尾 Case 写清楚，但当前 active DX 入口还没有承接这些 smoke 口径：`perfmetrics.enabled` 的可用性验证仍主要停留在公网下载 diagnostics，极端规模下发也只停留在 host/文档层面。

本 change 补齐 roadmap 中 `complete-device-smoke-casebook-other` 的 OpenSpec 计划，使“其他”casebook 有明确的可选真机验收入口与断言边界，同时保持默认 `dx-smoke` 主链快速、稳定、fail-fast。

## What Changes

- 将 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2 落实为可选真机验收责任：
  - Case 1：`perfmetrics.enabled` off/on/幂等/非法值语义，使用 vNext `CONFIG.*` 与 `METRICS.GET(name=perf)`，并复用 Tier‑1 payload 流量避免公网依赖。
  - Case 2：`DOMAINLISTS.IMPORT` 与 `IPRULES.APPLY` 极端规模/limits sanity，要求失败结构化、可解释，且失败后 daemon 仍可 `HELLO`。
- 新增“可选运行”的 casebook-other 覆盖口径；默认不进入 `dx-smoke` 总入口，也不新增 `dx-smoke*` CTest 名称或改变现有主入口组。
- 复用现有 vNext 控制面、IP Tier‑1 netns+veth helper、diagnostics/check id 语义；不引入 legacy 文本协议路径。
- 只做测试、脚本与文档对齐；不修改 C++ 产品逻辑、不改变 vNext wire shape、不新增持久化语义。
- 明确极端规模 case 的目标是 limits/error/恢复性 sanity，不做真实大流量性能测试，不要求默认高频运行。

## Capabilities

### New Capabilities
- `dx-smoke-other-casebook`: 定义 `DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2 的可选真机验收范围、断言、入口边界、BLOCKED/SKIP/FAIL 语义与文档回查要求。

### Modified Capabilities
- （无）

## Impact

- `tests/device/ip/` 或 `tests/device/diagnostics/`：新增或复用可选 runner/case，用于运行 perfmetrics smoke-style checks 与 limits sanity；不得纳入默认 `dx-smoke` 主链。
- `tests/integration/CMakeLists.txt`：如注册 CTest，只能使用非 `dx-smoke*` 名称，且不得改变现有 `dx-smoke` / `dx-diagnostics` 主入口组语义。
- `docs/testing/DEVICE_SMOKE_CASEBOOK.md`：更新 `## 其他` 的现有覆盖、缺口与 check id。
- `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`：标注 optional casebook-other 覆盖与默认 smoke/diagnostics 的边界。
- `docs/IMPLEMENTATION_ROADMAP.md`：将该 follow-up 从 NEXT/NOW 更新到实际状态。
- `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`：若真机验证暴露 Snort daemon/product 行为偏差，记录复现、期望/实际与关键日志；测试脚本自身错误不记入该文件。
- 不影响 `src/` 产品逻辑、C++ ABI、控制协议兼容性、默认 `dx-smoke` 顺序、IP matrix/stress/perf/longrun 责任或现有 diagnostics 下载负载入口。
