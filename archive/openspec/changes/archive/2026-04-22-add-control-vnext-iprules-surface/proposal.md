## Why

vNext control 平面已完成 codec/ctl、daemon base 与 domain surface，但 IPRULES 仍停留在 legacy 控制面（token + `OK/NOK`），无法与 vNext 的 envelope/selector/strict reject/error model 统一。进入 domain+IP fusion 主线后，需要把 `IPRULES.PREFLIGHT/PRINT/APPLY` 迁移到 vNext，并把 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md` 已收敛的 apply 契约落盘为可测试、不可漂移的接口。

## What Changes

- 在 vNext daemon 落地 IP 腿命令面（不改动包判决热路径语义；聚焦控制面与输出契约）：
  - `IPRULES.PREFLIGHT`
  - `IPRULES.PRINT`
  - `IPRULES.APPLY`
- 严格对齐 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md` 与 `CONTROL_COMMANDS_VNEXT.md`：
  - request/response envelope、selector（`args.app`）、strict reject（unknown key）
  - 结构化错误模型（`SYNTAX_ERROR/INVALID_ARGUMENT/...`）
- 严格对齐 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`：
  - 原子 replace apply（单 UID；all-or-nothing）
  - `clientRuleId` 持久化与回显（PRINT 必须包含；冲突错误必须回显）
  - `matchKey`（mk1 canonical；CIDR network-address 规范化）
  - 冲突错误 shape（`INVALID_ARGUMENT` + `error.conflicts[]` + `truncated`）
  - apply 成功回传 `clientRuleId -> ruleId -> matchKey` 映射
  - apply 因 preflight/hard limits 失败时返回结构化 `error.preflight`
- 增加 P0/P1/P2 覆盖，避免实现期输出 shape 漂移：
  - P0：host 单测（schema、冲突、映射、canonicalization）
  - P1：integration（vNext baseline：preflight→apply→print→verify）
  - P2：device module（vNext control 驱动的 iprules 验收 profile）

## Capabilities

### New Capabilities

- `control-vnext-iprules-surface`: vNext IPRULES surface（`IPRULES.PREFLIGHT/PRINT/APPLY` + apply contract：`clientRuleId/matchKey/conflicts/mapping`）。

### Modified Capabilities

- (none)

## Impact

- Affected runtime areas (implementation phase):
  - vNext control session/dispatch (`src/ControlVNextSession*.cpp`)
  - IPRULES vNext command handler（新增 `ControlVNextSessionCommands*` 模块）
  - IPRULES state/persistence (`src/IpRulesEngine.*`；save/restore format bump)
- Affected tests (implementation phase):
  - Host P0 unit tests under `tests/host/`（新增 vNext iprules surface tests）
  - Host-driven integration under `tests/integration/`（扩展 `vnext-baseline.sh`）
  - Device modules under `tests/device-modules/ip/`（新增 vNext 驱动 profile）

