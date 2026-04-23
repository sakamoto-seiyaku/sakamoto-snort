## ADDED Requirements

### Requirement: DX smoke 暴露稳定的主入口组
项目 MUST 以开发者可见、可稳定引用的方式暴露 DX 真机 `smoke` 的主入口组，且主入口组 MUST 只包含以下 4 个入口名：

- `dx-smoke`
- `dx-smoke-platform`
- `dx-smoke-control`
- `dx-smoke-datapath`

#### Scenario: 在 CTest/VS Code Testing 中可发现 DX smoke 主入口
- **WHEN** 开发者枚举可运行的测试入口（例如通过 `ctest -N` 或 VS Code Testing 视图）
- **THEN** SHALL 能看到上述 4 个 `dx-smoke*` 主入口名

### Requirement: dx-smoke 按固定顺序执行并 fail-fast
`dx-smoke` 总入口 MUST 按固定顺序执行子入口：`platform -> control -> datapath`，且 MUST 采用 fail-fast 策略：

- 若 `dx-smoke-platform` 失败，则 `dx-smoke` MUST NOT 继续执行 `dx-smoke-control` 与 `dx-smoke-datapath`
- 若 `dx-smoke-control` 失败，则 `dx-smoke` MUST NOT 继续执行 `dx-smoke-datapath`

#### Scenario: platform 失败时停止后续段
- **WHEN** `dx-smoke-platform` 执行失败
- **THEN** `dx-smoke` SHALL 立即结束且 SHALL NOT 执行 `dx-smoke-control` 与 `dx-smoke-datapath`

#### Scenario: control 失败时停止 datapath
- **WHEN** `dx-smoke-control` 执行失败
- **THEN** `dx-smoke` SHALL 立即结束且 SHALL NOT 执行 `dx-smoke-datapath`

### Requirement: dx-smoke 必须区分 PASS/FAIL/BLOCKED 且 BLOCKED 不等于通过
DX `smoke` 入口 MUST 至少区分三种结果语义：

- `PASS`：`platform/control/datapath` 三段全部通过
- `FAIL`：在前置条件满足且可开始执行的前提下，任意一段执行失败
- `BLOCKED`：ADB/真机/root/deploy 等前置不满足，导致入口无法开始或无法产生可信结论

`BLOCKED` MUST NOT 被视为“通过”。

#### Scenario: 前置条件不足时报告 BLOCKED
- **GIVEN** 当前环境不满足真机执行前置（例如缺少 ADB 或设备不可用）
- **WHEN** 开发者运行任一 `dx-smoke*` 入口
- **THEN** 系统 SHALL 报告为 `BLOCKED`（而非 `PASS`）

#### Scenario: 段内失败时报告 FAIL
- **GIVEN** 前置条件满足且入口可以开始执行
- **WHEN** 任意一段执行失败
- **THEN** 系统 SHALL 报告为 `FAIL`

### Requirement: active DX smoke 主线一律使用 vNext
所有 active `dx-smoke*` 主入口 MUST 以 `vNext` 接口为准，且 MUST NOT 混用 legacy/compat 入口作为其默认执行路径。

最低限度，入口职责映射 MUST 满足：

- `dx-smoke-platform` MUST 覆盖真机平台 gate（现有平台 smoke 能力）
- `dx-smoke-control` MUST 覆盖 `vNext` 控制面基线（包含必要的 domain surface / metrics surface 基线）
- `dx-smoke-datapath` MUST 覆盖 `vNext` datapath 最小闭环，并在最终形态调用 IP 模组 active `smoke` profile（该 profile 本身 MUST 是 vNext smoke 语义）

“以 `vNext` 接口为准”不仅要求入口名切换，也要求 active smoke 的断言路径不得回退调用 legacy 文本协议命令。若某个 smoke 责任需要 deterministic DEV trigger，项目 MUST 提供 vNext DEV-only trigger 或等价机制，而不是从 active smoke 中调用 legacy DEV 命令。

#### Scenario: dx-smoke-control 不依赖 legacy baseline
- **WHEN** 开发者运行 `dx-smoke-control`
- **THEN** active 执行路径 SHALL 以 `vNext` 控制面入口为准（而非 legacy 文本协议 baseline）

#### Scenario: dx-smoke-datapath 使用 active vNext smoke profile
- **WHEN** 开发者运行 `dx-smoke-datapath`
- **THEN** active 执行路径 SHALL 使用 IP 模组的 active `smoke` profile
- **AND** 该 profile SHALL 只执行 vNext smoke cases（而非混合职责的 legacy smoke profile）

### Requirement: active smoke 必须承接旧 smoke 的主 gate 覆盖责任
DX smoke 转换完成的判定标准 MUST 是“旧 smoke 中仍属于主功能 gate 的覆盖责任已被 vNext active smoke 接住”，而不是“存在新的最小 smoke 入口”。

`dx-smoke-control` MUST 至少覆盖：

- vNext meta / inventory / config / stream / reset 基线
- vNext domain surface：`DOMAINRULES` / `DOMAINPOLICY` / `DOMAINLISTS`
- vNext metrics surface：`perf` / `reasons` / `domainSources` / `traffic` / `conntrack`
- domainSources 行为：reset 后为零、`block.enabled=0` 不增长、`block.enabled=1` 增长、per-app/tracked=0 仍可增长

`dx-smoke-datapath` MUST 至少覆盖：

- Tier-1 真实流量下 IPRULES allow verdict
- Tier-1 真实流量下 IPRULES block verdict
- would-match overlay 在最终 ACCEPT 时出现，且在最终 DROP 时不污染最终归因
- IFACE_BLOCK 优先级高于 IPRULES，且不增加被遮蔽规则的 stats
- `BLOCK=0` 时 datapath reasons 不增长
- 对应的 `reasonId/ruleId/wouldRuleId` 与 per-rule stats 断言

#### Scenario: control smoke 承接 domainSources 行为
- **WHEN** 开发者运行 `dx-smoke-control`
- **THEN** 测试 SHALL 通过 vNext control path 触发 deterministic domain verdict
- **AND** SHALL 验证 `domainSources` reset/gating/growth/per-app 行为
- **AND** SHALL NOT 调用 legacy 文本协议 `DEV.DNSQUERY`

#### Scenario: datapath smoke 承接 IP verdict 行为
- **WHEN** 开发者运行 `dx-smoke-datapath`
- **THEN** 测试 SHALL 在 Tier-1 真实流量下验证 allow/block/would-match/IFACE_BLOCK/BLOCK=0
- **AND** SHALL 验证 pkt stream attribution 与 per-rule stats

### Requirement: IP module smoke profile 不得保留 legacy/mixed 默认语义
`tests/device-modules/ip/run.sh --profile smoke` MUST 表示 active vNext IP smoke，且 MUST NOT 默认执行 legacy/mixed smoke case。

#### Scenario: IP module smoke profile uses active vNext cases
- **WHEN** 开发者运行 `tests/device-modules/ip/run.sh --profile smoke`
- **THEN** runner SHALL 执行 active vNext smoke cases
- **AND** SHALL NOT 执行 legacy/mixed smoke cases unless they are explicitly invoked for migration review

### Requirement: legacy 脚本作为迁移源可回查但不进入默认主入口
仍有覆盖价值但尚未被 `vNext` 完整承接的 legacy 入口 MUST 作为“迁移源”保留并可按需回查，但 MUST 满足：

- 迁移源 MUST NOT 被 `dx-smoke` 默认入口引用或间接执行
- 迁移源 MUST 在文档索引中可见（便于追踪迁移状态与责任承接）
- 迁移源 MUST 只能通过显式点名方式运行（例如直接执行脚本路径或显式指定测试名/正则）

#### Scenario: dx-smoke 默认不运行迁移源
- **WHEN** 开发者运行 `dx-smoke`
- **THEN** 系统 SHALL 只执行 `dx-smoke-platform/control/datapath` 三段
- **AND** SHALL NOT 执行任何被定义为迁移源的 legacy 入口

#### Scenario: 迁移源需要显式点名运行
- **WHEN** 开发者需要做迁移核对或历史回查
- **THEN** SHALL 可以通过显式点名方式运行迁移源入口

### Requirement: legacy 入口归档必须满足 vNext 承接硬门槛
任何 legacy 入口在被归档（archive，物理目录迁移）前 MUST 满足：

- 已存在对应的 `vNext` 测试版本
- 对应的 `vNext` 测试版本已真正接住 legacy 入口原先承担的覆盖责任

若上述任一条件不满足，则该 legacy 入口 MUST NOT 被归档。

#### Scenario: vNext 未承接时禁止归档
- **GIVEN** 某 legacy 入口覆盖责任尚未被 `vNext` 接住
- **WHEN** 开发者尝试将其归档
- **THEN** 该入口 SHALL NOT 被归档

### Requirement: active 入口不得继续使用 p1/p2/ip-smoke 历史命名
active DX `smoke` 的主入口名与对外展示 MUST NOT 继续使用 `p1`、`p2`、`ip-smoke` 等历史命名（不作为未来入口名/分类名/长期别名）。

#### Scenario: active DX smoke 入口不包含历史 lane 命名
- **WHEN** 开发者查看 active DX `smoke` 的主入口列表
- **THEN** SHALL 只看到 `dx-smoke*` 入口，而不包含 `p1/p2/ip-smoke` 等历史命名
