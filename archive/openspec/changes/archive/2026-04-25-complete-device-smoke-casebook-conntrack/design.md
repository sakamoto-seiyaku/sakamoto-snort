## Context

`dx-smoke-datapath` 当前通过 `tests/integration/dx-smoke-datapath.sh` 调用 `tests/device/ip/run.sh --profile smoke`，该 profile 已承接 IP Case 1–8。`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## IP - Conntrack` 仍标记为缺口：现有 `tests/device/ip/cases/22_conntrack_ct.sh` 能在 matrix profile 中覆盖 CT allow/block，但还没有进入 active smoke，也缺少 smoke 级 conntrack metrics 断言。

本 change 的设计目标是把已有 Tier‑1 conntrack 用例提升为 active smoke gate，并补齐 casebook 指定的解释闭环；不重新设计 conntrack core，也不扩展 `ct.state/ct.direction` 语义。

## Goals / Non-Goals

**Goals:**
- `dx-smoke-datapath` 覆盖 `## IP - Conntrack` Case 1，并输出可回查 check id。
- 所有 conntrack smoke 断言都走 vNext control path 与 Tier‑1 netns+veth 真实 TCP payload。
- allow 阶段验证 `new/orig` 与 `established/reply` 两条规则都命中，并确认 TCP payload 读到固定 N bytes。
- block 阶段验证 `new/orig` enforce block 真实阻断连接，并确认 reasons 与 per-rule stats 命中。
- 用 `METRICS.GET(name=conntrack)` 验证 allow 会 create entry、block 不会 create entry；用 `RESETALL` 作为 conntrack 清理边界。

**Non-Goals:**
- 不新增 `dx-smoke*`、CTest target 或 IP profile 名称。
- 不修改 C++ conntrack core、IPRULES classifier、vNext protocol schema、C++ ABI 或持久化格式。
- 不扩展更强 flow-state、TCP strict mode、UDP/ICMP CT smoke 或 multi-flow matrix。
- 不把 perf/stress/longrun/diagnostics 责任混入 active smoke。
- 不处理 `complete-device-smoke-casebook-other` 的 perfmetrics 或规模 sanity。

## Decisions

1) **conntrack case 进入现有 smoke profile**
   - 选择：将 `22_conntrack_ct.sh` 或等价 conntrack case 纳入 `tests/device/ip/run.sh --profile smoke`，由 `dx-smoke-datapath` 间接执行。
   - 理由：`dx-smoke-workflow` 已规定 datapath smoke 使用 active vNext IP smoke profile；新增入口会重新制造 smoke 心智分叉。
   - 备选：新增 `dx-smoke-conntrack` 或 `--profile conntrack-smoke`；拒绝。

2) **复用并强化现有 Tier‑1 case**
   - 选择：以 `tests/device/ip/cases/22_conntrack_ct.sh` 为实现基础，补 check id、metrics 与 smoke 级退出语义。
   - 理由：该脚本已使用 netns+veth、vNext `IPRULES.APPLY/PRINT` 与固定 TCP payload，最接近 casebook 口径。
   - 备选：把 CT 逻辑内联到 `16_iprules_vnext_datapath_smoke.sh`；拒绝，避免让 IP Case 1–8 脚本继续膨胀。

3) **conntrack metrics 只通过 RESETALL 建立基线**
   - 选择：每个 CT 阶段前使用 `RESETALL`，随后读取 `METRICS.GET(name=conntrack)`；不调用 `METRICS.RESET(name=conntrack)`。
   - 理由：v1 规格明确 conntrack 不支持独立 metrics reset；smoke 应验证真实清理边界而不是引入不支持入口。
   - 备选：依赖 metric delta 而不 reset；拒绝，因为 `conntrack` 是全局指标，背景噪声会降低可解释性。

4) **payload bytes 继续作为功能面判据**
   - 选择：allow 阶段固定读取 `IPTEST_CT_BYTES`（默认 `65536`），block 阶段要求读取结果为 `0` 或连接失败，并把前置不可用区分为 `BLOCKED/SKIP`。
   - 理由：CT state/direction 必须通过真实连接生命周期验证；只看 stats 不能证明功能面通断正确。
   - 备选：只做 `nc -z` 短连接；拒绝，无法稳定证明 `established/reply` payload 路径。

5) **文档以 check id 对齐 casebook**
   - 选择：实现后更新 `DEVICE_SMOKE_CASEBOOK.md`、coverage matrix 与 roadmap，只移除已完成缺口，并保留更强 CT 语义为后续能力边界。
   - 理由：casebook 是本阶段验收口径；文档必须能从人话 case 回查到具体 smoke check。
   - 备选：只改脚本不改文档；拒绝。

## Risks / Trade-offs

- [部分设备缺少可联网 app uid 或 Tier‑1 TCP 前置] → 保持 `BLOCKED(77)` / `SKIP(10)` 语义，并提示设置 `IPTEST_APP_UID`。
- [conntrack metrics 是全局指标，可能受背景流量影响] → 在 CT 阶段前立即 `RESETALL`，并尽量紧邻读取 metrics 与触发 payload。
- [把 matrix case 纳入 smoke 会增加运行时间] → 只纳入最小 CT case，不引入 multi-flow matrix、perf compare 或 stress 覆盖。
- [脚本重复 rule stats / metrics parsing] → 可局部复用 `tests/device/ip/lib.sh` helper，但不做大规模 runner 重构。
- [真机暴露产品行为偏差] → 记录到 `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`，不在测试 change 中隐式修改产品逻辑。

## Migration Plan

- 先补强 `22_conntrack_ct.sh` 的 smoke check id、conntrack metrics 与退出语义。
- 再把 conntrack case 加入 `tests/device/ip/run.sh --profile smoke`，同时保持 matrix profile 仍可显式运行该 case。
- 最后同步 `DEVICE_SMOKE_CASEBOOK.md`、`DEVICE_TEST_COVERAGE_MATRIX.md` 与 `IMPLEMENTATION_ROADMAP.md`。
- 若设备前置不足，smoke 报告 `BLOCKED/SKIP`；若前置满足但 CT 行为不符，报告 `FAIL`。

## Open Questions

- 无。范围以 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP - Conntrack` Case 1 为准。
