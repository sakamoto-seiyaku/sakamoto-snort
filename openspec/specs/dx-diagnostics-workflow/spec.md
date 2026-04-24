# dx-diagnostics-workflow Specification

## Purpose
TBD - created by archiving change rework-dx-diagnostics. Update Purpose after archive.

## Requirements

### Requirement: DX diagnostics 暴露稳定的主入口组
项目 MUST 以开发者可见、可稳定引用的方式暴露 DX 真机 `diagnostics` 的主入口组，且主入口组 MUST 只包含以下 2 个入口名：

- `dx-diagnostics`
- `dx-diagnostics-perf-network-load`

旧入口名（例如 `perf-network-load`）若仍保留历史回查价值，MUST 作为迁移源/归档材料存在，且 MUST NOT 注册到 `CTest/VS Code Testing` 的默认可发现入口集合中。

#### Scenario: 在 CTest/VS Code Testing 中可发现 DX diagnostics 主入口
- **WHEN** 开发者枚举可运行的测试入口（例如通过 `ctest -N` 或 VS Code Testing 视图）
- **THEN** SHALL 能看到上述 2 个 `dx-diagnostics*` 主入口名
- **AND** SHALL NOT 看到旧 `perf-network-load` 入口名

### Requirement: DX diagnostics 必须区分 PASS/FAIL/BLOCKED/SKIP 且 BLOCKED 不等于通过
DX `diagnostics` 入口 MUST 至少区分四种结果语义：

- `PASS`：入口执行并通过所有断言
- `FAIL`：入口执行但断言失败
- `BLOCKED`：ADB/真机/root/vNext forward/deploy 等前置不满足，导致入口无法开始或无法产生可信结论
- `SKIP`：环境可运行但外部条件不满足（例如离线网络、URL 不可达、缺少 downloader），因此本次观测不产生结论

其中：
- `BLOCKED` MUST NOT 被视为“通过”
- `SKIP` MUST NOT 被视为“通过”，但 MUST 以显式语义呈现（而不是误报 FAIL）

#### Scenario: 前置条件不足时报告 BLOCKED
- **GIVEN** 当前环境不满足真机执行前置（例如缺少 ADB 或设备不可用）
- **WHEN** 开发者运行任一 `dx-diagnostics*` 入口
- **THEN** 系统 SHALL 报告为 `BLOCKED`（而非 `PASS`）

### Requirement: active DX diagnostics 主线一律使用 vNext
所有 active `dx-diagnostics*` 主入口 MUST 以 `vNext` 控制面接口为准，且 MUST NOT 混用 legacy/compat 文本协议命令作为默认执行路径。

最低限度，`dx-diagnostics-perf-network-load` MUST 使用 vNext `CONFIG.*` 与 `METRICS.*` surface 完成 perfmetrics toggle 与 perf metrics 采样/重置。

#### Scenario: perf-network-load 通过 vNext 采样 perf metrics
- **WHEN** 开发者运行 `dx-diagnostics-perf-network-load`
- **THEN** 入口 SHALL 通过 vNext 控制面完成 perfmetrics 的启用/禁用与 metrics 采样/重置
- **AND** SHALL NOT 调用 legacy 文本协议 `PERFMETRICS` / `METRICS.PERF*`

