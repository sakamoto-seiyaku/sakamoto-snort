## Why

`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 已经把 `## IP - Conntrack` 的 smoke 验收口径写清楚，但当前 active `dx-smoke-datapath` / `tests/device/ip/run.sh --profile smoke` 仍未承接 conntrack state/direction 的最小闭环；现有覆盖停留在 matrix profile 的 `22_conntrack_ct.sh`。

本 change 补齐 roadmap 中 `complete-device-smoke-casebook-conntrack` 的 OpenSpec 计划，使 conntrack smoke 能以 Tier‑1 可重复方式进入 active datapath gate，同时不扩展产品语义或新增入口。

## What Changes

- 将 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1 落实为 active datapath smoke 责任：
  - allow 阶段覆盖 `ct.state=new,ct.direction=orig` 与 `ct.state=established,ct.direction=reply`。
  - block 阶段覆盖 `ct.state=new,ct.direction=orig` 的 enforce block。
  - 验证真实 TCP payload 读写、per-rule stats、`reasons.IP_RULE_BLOCK`、以及 `METRICS.GET(name=conntrack)` 的 create-on-accept / block-does-not-create-entry 语义。
- 复用现有公开入口：`dx-smoke-datapath` 与 `tests/device/ip/run.sh --profile smoke`；不新增 `dx-smoke*` 名称或 profile 名称。
- 以现有 Tier‑1 netns+veth 拓扑和 vNext control path 为准，保持 smoke 可重复、可解释。
- 只做测试、脚本与文档对齐；不修改 C++ 产品逻辑、不改变 vNext 控制协议或 conntrack wire shape。
- 明确排除更强 flow-state 扩展、perf/matrix/stress/longrun 责任，以及 `complete-device-smoke-casebook-other` 中的 perfmetrics/规模 sanity。

## Capabilities

### New Capabilities
- `dx-smoke-conntrack-casebook`: 定义 active datapath smoke 对 `DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1 的测试承接范围、必测断言、BLOCKED/FAIL 语义与文档回查要求。

### Modified Capabilities
- （无）

## Impact

- `tests/device/ip/run.sh`：将 conntrack smoke case 纳入 active `smoke` profile，保持 matrix profile 可继续显式回查。
- `tests/device/ip/cases/22_conntrack_ct.sh`：强化或复用现有 Tier‑1 conntrack 用例，使其满足 smoke 级断言与退出语义。
- `tests/device/ip/lib.sh`：可选复用或抽取 conntrack metrics、rule stats、payload TCP helper，前提是保持 vNext-only active smoke。
- `docs/testing/DEVICE_SMOKE_CASEBOOK.md`：更新 `## IP - Conntrack` 的“现有覆盖/缺口”和脚本索引。
- `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`：同步 datapath smoke 对 conntrack casebook 的覆盖矩阵。
- `docs/IMPLEMENTATION_ROADMAP.md`：将该 follow-up 从 NEXT/NOW 更新到实际状态。
- `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`：若真机验证暴露 Snort daemon/product 行为偏差，记录复现、期望/实际与关键日志；测试脚本自身错误不记入该文件。
- 不影响 `src/` 产品逻辑、C++ ABI、控制协议兼容性、CMake/CTest smoke 入口命名或 diagnostics/stress/perf/longrun 责任。
