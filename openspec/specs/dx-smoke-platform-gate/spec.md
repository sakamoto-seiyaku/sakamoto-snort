# dx-smoke-platform-gate Specification

## Purpose
TBD - created by archiving change complete-device-smoke-casebook-platform. Update Purpose after archive.

## Requirements

### Requirement: dx-smoke-platform 在进入后续段前明确前置是否满足
`dx-smoke-platform` MUST 在进入 `dx-smoke-control/dx-smoke-datapath` 之前，完成 host+device 的最小前置检查，并以 `PASS/FAIL/BLOCKED` 的语义给出可解释结论（`BLOCKED` 语义与 `openspec/specs/dx-smoke-workflow/spec.md` 一致）。

#### Scenario: 前置不足时报告 BLOCKED
- **GIVEN** 当前环境不满足真机执行前置（例如缺少 ADB、设备不在线、无 root、缺少 `python3`、或缺少 `sucre-snort-ctl`）
- **WHEN** 开发者运行 `dx-smoke-platform`
- **THEN** 入口 SHALL 报告为 `BLOCKED`（例如以退出码 77 呈现）
- **AND** SHALL 输出可执行修复提示（例如如何 build `sucre-snort-ctl`、如何 deploy、或如何指定 serial）

### Requirement: dx-smoke-platform 在 --skip-deploy 场景下不误报 FAIL
当开发者使用 `--skip-deploy` 复用设备上既有守护进程时，`dx-smoke-platform` MUST 把“守护进程不存在/不可用”视为前置不足并报告 `BLOCKED`，而不是误报为产品断言失败。

#### Scenario: skip-deploy 且守护进程不可用时报告 BLOCKED
- **GIVEN** 开发者使用 `--skip-deploy` 运行
- **AND** 设备上 `sucre-snort-dev` 不存在或 vNext 控制面不可用
- **WHEN** 开发者运行 `dx-smoke-platform`
- **THEN** 入口 SHALL 报告为 `BLOCKED`
- **AND** SHALL 提示可执行修复路径（例如去掉 `--skip-deploy` 或先执行 deploy）

### Requirement: dx-smoke-platform 覆盖 socket namespace 与 vNext HELLO 连通性
`dx-smoke-platform` MUST 同时验证：
- 设备侧 socket namespace 就绪（至少包含 `/dev/socket/sucre-snort-control-vnext` 与 `/dev/socket/sucre-snort-netd`）
- host→device 的 vNext 控制面最小连通性成立（通过 vNext `HELLO` 握手验证）

#### Scenario: platform 就绪时 sockets 存在且 HELLO 成功
- **GIVEN** 设备前置满足且守护进程处于可用状态
- **WHEN** 开发者运行 `dx-smoke-platform`
- **THEN** 平台 gate SHALL 验证上述 sockets 存在
- **AND** SHALL 验证一次 vNext `HELLO` 握手成功

### Requirement: dx-smoke-platform 覆盖 firewall hooks 与 SELinux 健康
`dx-smoke-platform` MUST 验证以下平台关键路径处于健康状态：
- `iptables/ip6tables` hooks 与 `NFQUEUE` 规则存在
- SELinux 模式/上下文可读，且不存在与 sucre 相关的 AVC denials（至少在可配置的最近窗口内）

#### Scenario: firewall hooks 缺失时报告 FAIL
- **GIVEN** 设备前置满足且入口可以开始执行
- **WHEN** `iptables/ip6tables` hooks 或 `NFQUEUE` 规则缺失
- **THEN** `dx-smoke-platform` SHALL 报告为 `FAIL`

#### Scenario: 发现 AVC denials 时报告 FAIL
- **GIVEN** 设备前置满足且入口可以开始执行
- **WHEN** 发现与 sucre 相关的 SELinux AVC denials
- **THEN** `dx-smoke-platform` SHALL 报告为 `FAIL`

### Requirement: netd resolv hook 检查保持为非 gate（SKIP/提示）
`dx-smoke-platform` MAY 检查 `netd resolv hook` 的前置（例如 `libnetd_resolv.so` 是否已挂载），但该项默认 MUST NOT 作为 `dx-smoke` 主链的硬 gate；缺失时应以可解释的 `SKIP/提示` 呈现，并给出准备命令。

#### Scenario: netd resolv hook 缺失时不阻塞 platform 通过
- **GIVEN** 除 netd resolv hook 外其余 platform 前置均满足
- **WHEN** `dx-smoke-platform` 检测到 `libnetd_resolv.so` 未挂载
- **THEN** 入口 SHALL 输出 `SKIP/提示`（包含 `bash dev/dev-netd-resolv.sh status|prepare`）
- **AND** 入口 SHALL 仍允许本次 `dx-smoke-platform` 通过（不将其升级为 FAIL/BLOCKED）

