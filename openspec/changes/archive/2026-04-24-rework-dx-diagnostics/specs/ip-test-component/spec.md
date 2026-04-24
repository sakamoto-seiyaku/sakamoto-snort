## ADDED Requirements

### Requirement: IP test component 位于稳定入口且可在真机上重复运行
系统（仓库）MUST 提供一个可重复执行的 IP 真机测试模组，用于在 rooted Android 真机上回归验证 IP/L3-L4 datapath 的端到端行为（控制面下发 → NFQUEUE 真实流量 → 判决/归因/统计）。

该模组的稳定入口 MUST 为：
- `tests/device/ip/run.sh`

#### Scenario: Run the IP smoke profile
- **WHEN** 开发者运行 `bash tests/device/ip/run.sh --profile smoke`
- **THEN** 组件 SHALL 尝试触发最小真实网络流量（ICMP/TCP/UDP 至少其一）
- **AND** SHALL 对关键 datapath 行为给出明确断言（PASS/FAIL/BLOCKED/SKIP）

### Requirement: IP test component 支持按 profile/group/case 运行子集并输出稳定汇总
IP 测试模组 MUST 支持按 `profile/group/case` 运行子集，并输出稳定的汇总（passed/failed/skipped/blocked 计数），用于回归比较与快速定位。

#### Scenario: Run a single case
- **WHEN** 开发者通过参数选择仅运行一个 case
- **THEN** 组件 SHALL 仅运行该 case
- **AND** SHALL 输出包含 passed/failed/skipped/blocked 的汇总行

### Requirement: active profiles 一律使用 vNext 控制面（legacy 仅供回查）
IP 测试模组的 active profiles MUST 一律以 `vNext` 控制面接口为准，且 MUST NOT 依赖 legacy 文本协议命令作为默认执行路径。

至少以下 profiles MUST 视为 active 并遵守 vNext-only：
- `smoke`
- `matrix`
- `stress`
- `perf`
- `longrun`

如需保留历史 mixed/legacy 覆盖，MUST 通过 `tests/archive/**` 下的显式回查入口存在（例如 `tests/archive/device/ip/run_legacy.sh`），且 MUST NOT 被 `dx-smoke` 或默认 diagnostics 入口间接执行。

#### Scenario: perf/matrix profiles do not use legacy text protocol
- **WHEN** 开发者运行 `bash tests/device/ip/run.sh --profile perf` 或 `--profile matrix`
- **THEN** 组件 SHALL 通过 vNext 控制面与 daemon 交互（例如使用 `sucre-snort-ctl`）
- **AND** SHALL NOT 调用 legacy 文本协议 `send_cmd`/`60606` 命令作为默认路径

### Requirement: legacy-only 覆盖不得混入 active profiles
任何依赖 legacy-only 命令且无 `vNext` 等价 surface 的覆盖责任，MUST NOT 继续混入 IP 模组的 active profiles。该类覆盖若仍有回查价值，MUST 进入 archive/迁移源，并在索引中保持可见。

#### Scenario: active matrix does not depend on legacy-only commands
- **WHEN** 开发者运行 `bash tests/device/ip/run.sh --profile matrix`
- **THEN** 组件 SHALL 不依赖 legacy-only 命令（例如冻结项 `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP` 或 legacy-only HOSTS cache 断言）
