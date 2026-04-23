> 执行约束：本文件用于追踪 `rework-dx-smoke` 的补充范围与完成度。本 change **不包含归档操作**（不做物理移动到 `tests/archive/device/`）。
>
> 状态说明：1-6 是上一轮已完成的入口骨架与最小闭环；它们不再代表本 change 的最终完成标准。最终完成标准以 7-8 的完整 smoke 转换与验证为准。

## 1. 入口与责任对照

- [x] 1.1 盘点现存 DX 相关入口（`tests/integration/*`、`tests/device-modules/ip/*`），并形成“active vs 迁移源”对照表（入口级，不展开到 case 级）
- [x] 1.2 明确 `dx-smoke-platform/control/datapath` 三段各自的最小调用链与前置条件（确保主线以 `vNext` 为准）

## 2. 收敛 dx-smoke 入口脚本

- [x] 2.1 落地 `dx-smoke-platform` 入口（复用/包装现有平台 gate 脚本，确保输出与退出码稳定）
- [x] 2.2 落地 `dx-smoke-control` 入口（复用/包装 `vNext` 控制面基线脚本，确保不走 legacy lane）
- [x] 2.3 落地 `dx-smoke-datapath` 入口（调用 IP 模组 active `--profile smoke`；vNext-only）
- [x] 2.4 落地 `dx-smoke` 聚合入口：固定顺序 `platform -> control -> datapath`、fail-fast、并区分 `PASS/FAIL/BLOCKED`

## 3. CTest / VS Code Testing 分组与展示

- [x] 3.1 在 `tests/integration/CMakeLists.txt` 中新增/改名 DX `smoke` tests 为 `dx-smoke*`（保证可发现、可筛选、可稳定引用）
- [x] 3.2 移除 active 体系中的 `p1/p2/ip-smoke` 历史命名与 label（不提供长期 alias；仅保留迁移源按需回查）
- [x] 3.3 统一 `BLOCKED` 的表达方式（例如固定退出码 + `SKIP_RETURN_CODE`），确保其不被误认成 PASS

## 4. 迁移源与归档落地

- [x] 4.1 把仍有价值但未被 `vNext` 完整承接的 legacy 入口明确为“迁移源”：默认不跑、文档可见、仅显式点名运行
- [x] 4.2 本 change 不做物理归档到 `tests/archive/device/`（defer）；仅固定归档硬门槛与迁移源可见性规则，物理归档留到后续 change 再做

## 5. 文档与路线图同步

- [x] 5.1 更新 `docs/testing/README.md`：补齐 DX `smoke` 新入口的运行方式、职责解释与最小 quick start
- [x] 5.2 更新 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`：同步主入口名、执行语义与迁移源总表状态（不展开到 case 级映射）
- [x] 5.3 校验 `docs/IMPLEMENTATION_ROADMAP.md`：确认本 change 与后续 `diagnostics` change 的边界、顺序与描述一致

## 6. 验证与回归

- [x] 6.1 验证 `ctest -N/-R/-L` 下 `dx-smoke*` 的可发现性与分组效果（即使无真机也应可明确报告 BLOCKED）
- [x] 6.2 在至少一台 rooted 真机上跑通 `dx-smoke-platform`，并确认 `PASS/FAIL/BLOCKED` 报告形态符合预期
- [x] 6.3 在至少一台 rooted 真机上跑通 `dx-smoke-control` 与 `dx-smoke-datapath` 的最小闭环，并确认不引用迁移源入口

> 说明：6.3 只证明最小闭环可跑，不再视为本 change 的最终完成标准。以下任务用于补齐完整 smoke 转换矩阵与验证；最终完成标准以 7-8 为准。

## 7. 完整 smoke 覆盖转换

- [x] 7.1 将 `tests/device-modules/ip/run.sh --profile smoke` 收敛为 active vNext smoke profile；不得再默认执行 legacy/mixed smoke case（旧 case 仅允许显式回查）。
- [x] 7.2 将 `dx-smoke-datapath` 对齐到 IP 模组 active `--profile smoke`，并确保默认执行路径不经过 legacy `IPRULES.*` 文本协议。
- [x] 7.3 补齐 `dx-smoke-control` 的 vNext control smoke 覆盖：domain surface、metrics shape/reset、stream start/stop、RESETALL 与 config validation 均不得依赖 legacy baseline。
- [x] 7.4 为 domainSources 行为测试补齐 vNext deterministic DNS verdict trigger（如 DEV-only vNext seam 或等价机制）；active smoke 不允许调用 legacy `DEV.DNSQUERY`。
- [x] 7.5 在 `dx-smoke-control` 中补齐 domainSources 行为断言：reset 后为零、`block.enabled=0` 不增长、`block.enabled=1` 增长、per-app/tracked=0 仍增长。
- [x] 7.6 在 `dx-smoke-datapath` 中补齐 Tier-1 IP datapath smoke：allow、block、would-match overlay、reason metrics、per-rule hit/wouldHit stats。
- [x] 7.7 在 `dx-smoke-datapath` 中补齐 IFACE_BLOCK 与 BLOCK=0 smoke：IFACE_BLOCK 优先于 IPRULES 且不污染 rule stats；BLOCK=0 时 reasons 不增长。
- [x] 7.8 更新迁移源总表：把 `tests/integration/run.sh`、`tests/integration/iprules.sh` 从“待补 vNext”调整为“已接住/仅回查”；并将旧 mixed smoke 收敛为 `tests/device-modules/ip/run.sh --profile legacy-smoke` 仅供回查。

## 8. 完整 smoke 验证

- [x] 8.1 运行 `bash -n` 覆盖新增/修改的 DX smoke shell 脚本。
- [x] 8.2 运行 `ctest -N/-R/-L` 验证 `dx-smoke*` 展示仍符合分组规则，且不重新暴露 `p1/p2/ip-smoke`。
- [x] 8.3 在 rooted 真机上运行 `dx-smoke` 总入口，确认完整 smoke 矩阵通过或明确报告 `BLOCKED/FAIL`。
- [x] 8.4 明确记录未纳入 smoke 的 diagnostics/matrix 项（例如 perf/stress/longrun/IP full matrix），防止审核时误判为遗漏。
