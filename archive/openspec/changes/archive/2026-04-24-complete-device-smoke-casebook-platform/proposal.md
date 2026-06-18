## Why

当前 `dx-smoke-platform` 已覆盖 socket/iptables/SELinux 等平台前置，但 **host 工具就绪** 与 **vNext 控制面连通性（尤其 `--skip-deploy`）**未在 platform gate 阶段明确校验，导致很多 smoke 失败会在后续 `control/datapath` 才暴露，排障成本高且结论不够“人话”。

本 change 以 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 Platform 模块为调查口径，把“真机端到端能不能测”的前置条件固化为可重复、可解释的平台 gate。

## What Changes

- 强化 `tests/integration/dx-smoke-platform.sh` 的 gate（不新增任何 `dx-smoke*` 入口名）：
  - 增加 host 侧工具就绪检查：`python3` + `sucre-snort-ctl`
    - 缺失时以 `BLOCKED(77)` 退出，并给出明确 build hint（例如 `cmake --build --preset dev-debug --target sucre-snort-ctl`）
  - 增加最小 vNext 连通性 sanity：adb forward + `HELLO` 握手断言
    - 特别覆盖 `--skip-deploy`：当守护进程不存在或控制面不可用时，报告 `BLOCKED(77)` 并给出可执行修复提示（去掉 `--skip-deploy` 或先 deploy）
  - `netd resolv hook` 前置检查更可靠（优先 `nsenter` mount namespace），但仍保持为 **SKIP/提示**（不把外部环境问题升级为默认 gate）
  - 保持现有平台检查项的语义与边界：device/root preflight、socket namespace、iptables/ip6tables hooks + NFQUEUE 规则、SELinux AVC、（deploy 时）lifecycle restart
- 文档对齐：更新 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 Platform 模块“现有覆盖/缺口”，确保与脚本行为一致。

## Capabilities

### New Capabilities
- `dx-smoke-platform-gate`: 定义 `dx-smoke-platform` 平台 gate 的最小必测项、BLOCKED/SKIP 语义与可解释输出约束（对齐 casebook 的 Platform 模块）。

### Modified Capabilities
- （无）

## Impact

- 影响范围（工程化 / 测试与文档）：
  - `tests/integration/dx-smoke-platform.sh`（平台 gate 强化）
  - （可选）`tests/integration/lib.sh`（复用 `sucre-snort-ctl` 探测/JSON 断言 helper）
  - `docs/testing/DEVICE_SMOKE_CASEBOOK.md`（Platform 模块对齐）
- 不改动 `src/` 产品逻辑；不引入新的 CTest 可发现入口名；不新增 “发包→看 NFQUEUE 计数器增长” 这类易抖动断言。
