## Why

vNext control 的协议/命令面已在 `docs/decisions/DOMAIN_IP_FUSION/` 收敛成单一真相，并且上一切片已落地 shared codec + `sucre-snort-ctl`；但 daemon 仍只有 legacy control（NUL terminator + `OK/NOK`），导致 vNext 无法在真机上形成可用的最小闭环与回归基线。

本 change 将 vNext listener 与最小命令集落地到 daemon，使后续 domain/iprules/metrics/stream 切片可以在同一条 vNext 控制面上逐步扩展，而不再重复造轮子或在协议边界上漂移。

## What Changes

- 新增 daemon vNext endpoints（与 legacy 并存）：
  - Unix socket `sucre-snort-control-vnext`（filesystem + abstract；production 由 `sucre-snort.rc` 声明，dev fallback 自动创建）
  - TCP `60607`（受 `inetControl()` gating；与 legacy 口径一致）
- 实现 vNext I/O 协议栈（复用 `src/ControlVNextCodec.*`）：
  - netstring read/write + `maxRequestBytes/maxResponseBytes` 硬上限
  - strict JSON parse/encode + shared envelope 校验 + strict reject + structured errors
  - 明确边界：vNext **不发送** NUL terminator；不得复用 legacy `SocketIO::print()` 的 “size()+1（含 NUL）” 语义
- 落地 vNext v1 最小命令集（Meta/Inventory/Config）：
  - `HELLO/QUIT/RESETALL`
  - `APPS.LIST/IFACES.LIST`
  - `CONFIG.GET/CONFIG.SET`（对齐 `CONTROL_COMMANDS_VNEXT.md` 的 keys 与校验规则）
- 迁移期 dataplane 约束：当 `inetControl()` 开启时，PacketListener 豁免 `60606 + 60607`，避免 control traffic 被 blocking/干扰
- 工程回归底座：
  - `dev/dev-android-device-lib.sh` 增加 vNext adb forward（`localabstract:sucre-snort-control-vnext`）
  - `tests/integration/` 增加 vNext baseline case（优先复用 `sucre-snort-ctl`，不再依赖 legacy `HELP` 心智）

## Capabilities

### New Capabilities

- `control-vnext-daemon-base`: daemon 侧 vNext listener + 协议执行 + v1 最小命令集（Meta/Inventory/Config），含上限/错误模型/并发语义的最低可验收基线

### Modified Capabilities

- _None._

## Impact

- Affected code (new/modified): daemon control 监听与 session loop、Settings/PacketListener 端口豁免、`sucre-snort.rc` 新 socket、dev forward 脚本与 integration baseline
- Affected build: Android.bp/Soong 将把 vNext daemon 相关实现纳入 `sucre-snort` 编译（并复用已 vendor 的 RapidJSON headers）
- Affected tests: host P0 单测覆盖 vNext request/validator 边界；真机 integration 新增 vNext baseline（HELLO + inventory + config）

