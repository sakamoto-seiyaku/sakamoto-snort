## Context

- Roadmap slice: `docs/IMPLEMENTATION_ROADMAP.md` → `stabilize-control-transition-surface`。
- 当前代码仍保留 legacy control（`sucre-snort-control` / `60606`，NUL terminator + `OK/NOK`），且以下 legacy knobs 仍可被设置并落盘：
  - `BLOCKIPLEAKS` ↔ `Settings::_blockIPLeaks`（packet 路径可触发 `IP_LEAK_BLOCK`）
  - `GETBLACKIPS` ↔ `Settings::_getBlackIPs`（DNS `getips = verdict || GETBLACKIPS`）
  - `MAXAGEIP` ↔ `Settings::_maxAgeIP`
- 在 domain+IP fusion 的当前裁决中，上述模块属于历史链条，必须冻结为“强制关闭且无作用”（见 `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md` §3.6/4.1）。
- repo 脚本与回归用例仍存在“隐式绑定 legacy lane（60606 文本协议）”的问题，导致：
  - 调试/回归容易误连 legacy，从而形成错误心智模型；
  - 冻结项语义在脚本与文档中持续漂移（仍被当作可调能力）。

## Goals / Non-Goals

**Goals:**

- 在 daemon 内将 `BLOCKIPLEAKS/GETBLACKIPS/MAXAGEIP` 收敛为全局固定语义：
  - query 恒定（`BLOCKIPLEAKS=0`, `GETBLACKIPS=0`, `MAXAGEIP=14400`）
  - set ack 兼容旧客户端（返回 `OK`），但不产生任何效果
  - 任何历史落盘/restore/RESETALL 都不能改变固定语义
- 更新 legacy `HELP` 文案：显式标注冻结项为 frozen/no-op，并提示 vNext 端点与推荐工具（`sucre-snort-ctl`）。
- 工程化收敛：脚本/测试明确 legacy lane vs vNext lane；冻结项回归从“roundtrip”改为“fixed/no-op 语义验证”，同时保留必要的 legacy 对照 lane。

**Non-Goals:**

- 不移除 legacy endpoints（删除 `sucre-snort-control` / `60606` 属于后续 `migrate-to-control-vnext`）。
- 不重新设计或重新启用 ip-leak（`BLOCKIPLEAKS` 的产品定位与仲裁属于后续独立 change）。
- 不引入新的 vNext 接口来控制这些冻结项（vNext 不暴露该能力）。
- 不改变 packet 热路径仲裁顺序/语义（仅通过冻结 settings 消除历史分支的可变性）。

## Decisions

1) **冻结在 `Settings` 层实现（single source of truth）**

- 在 `Settings` 的 setter/save/restore 上强制固定值：
  - `Settings::getBlackIPs(bool)` / `blockIPLeaks(bool)` / `maxAgeIP(time_t)` 变为 no-op 写入固定值。
  - `Settings::save()` 固定写入冻结值（避免未来误读“落盘可变”）。
  - `Settings::restore()` 兼容读取旧字段，但读完后强制覆盖为冻结值。
- 好处：所有调用点（legacy control、DNS、packet）自动获得固定语义，无需在多处加分支。

2) **legacy control 命令保持 wire 兼容（ack OK），语义固定**

- 兼容性目标：旧脚本/旧客户端仍能成功执行 `BLOCKIPLEAKS 1` 等命令（返回 `OK`），但后续 query 仍返回固定值，且不影响行为。
- legacy `HELP` 明确说明 frozen/no-op，减少“OK=生效”的误解。

3) **为 host gtest 增加最小 test seam（Settings save file override）**

- 现状：`Saver::save/restore` 在 host 上无法写入 `/data/snort/settings`，且失败会被吞掉，导致无法测试“旧落盘值被忽略”的语义。
- 方案：为 `Settings` 提供 test-only 的 save file override（与现有 `saveDirDomainListsOverrideForTesting` 风格一致），用于在 gtest 中写入临时文件并验证 restore 后固定值不变。

4) **脚本分轨以“显式 lane + 复用 `sucre-snort-ctl`”为原则**

- legacy lane：继续用 `tests/integration/lib.sh` 的 NUL-terminated 文本协议（默认保持）。
- vNext lane：统一通过 `sucre-snort-ctl` 驱动（避免另写 netstring/JSON framing），并复用现有的 adb forward helper（`tcp:<port>` ↔ `localabstract:sucre-snort-control-vnext`）。
- 公共脚本/runner 必须能显式选择 lane（例如通过 env 或 flag），避免隐式绑定单一 60606。

## Risks / Trade-offs

- [旧客户端误判“OK=生效”] → legacy `HELP`/文档明确 frozen/no-op；integration/device-module 用例从 roundtrip 改为 fixed/no-op，避免进一步强化错误心智。
- [冻结语义被未来改动回退] → 在 Settings 层集中实现 + 增加 host 单测覆盖 setter/save/restore/RESETALL 不变式。
- [脚本改动影响面大] → 保留 legacy lane 默认行为；仅在需要 vNext 的链路显式切换；逐步替换并在 P2 保持最小双轨回归。

