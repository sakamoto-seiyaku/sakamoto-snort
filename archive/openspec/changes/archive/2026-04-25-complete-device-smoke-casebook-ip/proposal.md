## Why

`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## IP` 章节已经把 IP smoke 的人话验收口径拆成 Case 1–8，但当前 `dx-smoke-datapath` 仍有若干断言缺口：部分真实连通性结果被吞掉、traffic/reasons 只看粗粒度 total、`iprules.enabled=0` correctness 与稳定 bytes 触发尚未纳入 smoke。

本 change 只创建并落实 IP casebook 的 smoke 承接计划，确保 active vNext datapath smoke 能覆盖 `## IP` 下所有 case，并且每条 case 都能通过 check id 回查。

## What Changes

- 将 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP` 下的 Case 1–8 落实为 `dx-smoke-datapath` / `tests/device/ip/run.sh --profile smoke` 的可重复测试责任：
  - Case 1：保留并强化 `IPRULES.PREFLIGHT/APPLY/PRINT` surface 与输出 shape 断言。
  - Case 2–5：补齐 allow/block/would/IFACE_BLOCK 的硬 verdict、pkt stream、reasons、dimension-level traffic 与 rule stats 断言。
  - Case 6：补齐 `block.enabled=0` 对 reasons、traffic 与 pkt stream 的 gating 断言。
  - Case 7：新增 `iprules.enabled=0` correctness，证明规则存在但不命中并回落 `ALLOW_DEFAULT`。
  - Case 8：新增固定 payload bytes 触发，稳定断言 `traffic.*b`、per-rule `hitBytes` 与 reasons bytes。
- 保持 active smoke 入口不变：不新增 `dx-smoke*` 名称，不改变 `tests/device/ip/run.sh --profile smoke` 的调用方式。
- 只做测试、脚本与文档对齐；不顺带修改产品功能、不改变 vNext 控制协议语义。
- 明确排除 `## IP - Conntrack`，该章节后续另开 change。

## Capabilities

### New Capabilities
- `dx-smoke-ip-casebook`: 定义 active datapath smoke 对 `DEVICE_SMOKE_CASEBOOK.md` IP Case 1–8 的测试承接范围、必测断言、BLOCKED/FAIL 语义与文档回查要求。

### Modified Capabilities
- （无）

## Impact

- `tests/device/ip/cases/14_iprules_vnext_smoke.sh`：强化 IPRULES surface 输出契约断言。
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：补齐 IP Case 2–8 的 datapath、metrics、stream 与 payload bytes 断言。
- `tests/device/ip/lib.sh`：可选抽取或复用 Tier‑1 payload / stream / metric helper，前提是保持 vNext-only active smoke。
- `docs/testing/DEVICE_SMOKE_CASEBOOK.md`：把 IP 章节的“现有覆盖/缺口”更新为实际 check id。
- `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`：同步 IP casebook smoke 覆盖矩阵与剩余边界。
- `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`：测试过程中发现的 Snort 本体/守护进程行为偏差时，记录复现步骤、期望/实际结果与关键日志；测试脚本自身错误不记入该文件。
- 不影响 `src/` 产品逻辑、C++ ABI、控制协议向后兼容性、CMake/CTest smoke 入口命名或 Conntrack smoke 责任。
