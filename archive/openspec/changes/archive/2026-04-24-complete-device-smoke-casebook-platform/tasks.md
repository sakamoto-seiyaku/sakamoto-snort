## 1. 强化 dx-smoke-platform（可解释 gate）

- [x] 1.1 在 `tests/integration/dx-smoke-platform.sh` 增加 host 工具就绪检查：`python3` 可用、可定位并执行 `sucre-snort-ctl`；缺失时报 `BLOCKED(77)` 且输出 build hint
- [x] 1.2 在 `tests/integration/dx-smoke-platform.sh` 增加 daemon/vNext 预期状态检查：`--skip-deploy` 下守护进程不存在或不可用时报告 `BLOCKED(77)` 并提示“去掉 --skip-deploy 或先 deploy”
- [x] 1.3 在 `tests/integration/dx-smoke-platform.sh` 增加 vNext `HELLO` 连通性 sanity（adb forward + `sucre-snort-ctl HELLO` + JSON 握手字段断言）；deploy 模式失败应为 `FAIL`，skip-deploy 模式失败应为 `BLOCKED`
- [x] 1.4 将 platform 脚本里的 socket namespace 检查与 vNext sanity 的失败语义对齐：deploy 模式缺失/不可用→`FAIL`；skip-deploy 模式缺失/不可用→`BLOCKED`
- [x] 1.5 `netd resolv hook` 前置检查改为 `nsenter` mount namespace 优先；缺失保持为 `SKIP/提示`（不升级为 gate），并输出 `bash dev/dev-netd-resolv.sh status|prepare` 指引

## 2. 文档对齐（casebook）

- [x] 2.1 更新 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 Platform 模块：把“host 工具就绪 + vNext HELLO sanity + skip-deploy BLOCKED”纳入“现有覆盖/缺口”的描述
- [x] 2.2 （如需要）更新 `docs/testing/DEVICE_TEST_COVERAGE_MATRIX.md`：把 platform gate 新增断言点映射到对应脚本/检查点

## 3. 验证

- [x] 3.1 `bash -n tests/integration/dx-smoke-platform.sh`
- [x] 3.2 `ctest -N -R dx-smoke-platform` 确认入口仍可发现且未新增 `dx-smoke*` 名称
- [x] 3.3 真机验证：分别运行 `bash tests/integration/dx-smoke-platform.sh` 与 `bash tests/integration/dx-smoke-platform.sh --skip-deploy`，确认 `PASS/FAIL/BLOCKED` 语义符合 `dx-smoke-platform-gate` 规格
