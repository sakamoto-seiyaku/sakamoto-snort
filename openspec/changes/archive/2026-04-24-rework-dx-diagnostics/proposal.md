## Why

当前 `Device / DX` 的 active `smoke` 已收敛为 `dx-smoke*` 且严格走 `vNext`；但 diagnostics 仍分散在多条历史路径中，且存在“脚本入口看起来是 diagnostics，但实际仍依赖 legacy 文本协议/latency 路径”的问题。这会让真机回归无法形成一致的心智模型，也阻碍后续彻底切换到 `vNext`。

因此需要一个与 `rework-dx-smoke` 对称的 diagnostics 重组：把 diagnostics 的对外入口、目录位置与执行链路收敛到 `vNext`，同时把 legacy/兼容路径明确降级为“仅供按需回查”的迁移源/归档材料（仍可在索引中可见，但不再进入默认运行入口）。

## What Changes

- 暴露稳定的 DX diagnostics 主入口组（`CTest/VS Code Testing` 可发现）：
  - `dx-diagnostics`（总入口）
  - `dx-diagnostics-perf-network-load`（真机真实下载负载下的 `METRICS(perf)` 观测）
- 将 diagnostics 入口与脚本移动到最终位置（一步到位，不保留兼容 wrapper）：
  - 新增 `tests/device/diagnostics/` 并把 diagnostics 主入口脚本放入该目录
- 将 diagnostics 的默认执行链路收敛为 `vNext`（禁止回退 legacy/latency 文本协议）：
  - `perf-network-load` 迁移为 `vNext`：用 `CONFIG.* + METRICS.GET/RESET(name=perf)` 替代 legacy `PERFMETRICS/METRICS.PERF*`
  - IP 真机测试模组的 diagnostics profiles（`perf/matrix/stress/longrun`）迁移为 `vNext` 控制面（`60607 + sucre-snort-ctl`），不再依赖 `send_cmd` 文本协议
- **BREAKING**：移除旧入口名/旧路径在默认体系中的可运行性（仍保留索引可见性）：
  - 旧 `perf-network-load` 入口名与脚本路径不再作为对外入口继续存在
  - legacy-only 覆盖（例如冻结项 `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP`）若无 `vNext` 等价 surface，将移动到 archive/迁移源，默认不运行
- 同步更新文档索引与路线图：`docs/testing/*`、`docs/IMPLEMENTATION_ROADMAP.md`

## Capabilities

### New Capabilities
- `dx-diagnostics-workflow`: 定义 DX 真机 diagnostics 的主入口命名、`CTest` 可发现性、`PASS/FAIL/BLOCKED/SKIP` 语义，以及 active diagnostics 必须 `vNext-only` 的约束。
- `ip-test-component`: 定义 IP 真机测试模组在 diagnostics 体系下的职责、profiles 与 `vNext-only` 约束（含目录归位与 legacy-only case 的迁移/归档规则）。

### Modified Capabilities

（无）

## Impact

- `tests/integration/CMakeLists.txt`：新增/调整 diagnostics 的 `CTest` 入口与 labels；移除旧 `perf-network-load` 入口名。
- `tests/integration/perf-network-load.sh`、`tests/device-modules/ip/**`：将发生物理移动与 `vNext` 迁移（并更新所有引用路径）。
- 文档与索引：`docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`、`docs/testing/README.md`、`tests/integration/README.md`、`docs/testing/ip/IP_TEST_MODULE.md`、`docs/IMPLEMENTATION_ROADMAP.md`。
