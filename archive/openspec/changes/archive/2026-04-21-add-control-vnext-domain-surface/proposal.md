# Change: add-control-vnext-domain-surface

## Why

vNext control 平面已完成 codec/ctl 与 daemon base（`HELLO/APPS.LIST/IFACES.LIST/CONFIG.*` 等），但“域名腿”的控制面仍停留在 legacy command 体系。进入 domain+IP fusion 主线后，需要把 `DomainRules/DomainPolicy/DomainLists` 迁移到 vNext：统一 envelope/strict reject/selector/error model，并为后续前端默认迁移与 legacy 下线准备稳定契约。

## What Changes

- 在 vNext daemon 落地域名腿命令面（不改动域名匹配/裁决链路；只做入参校验、落盘形态、返回口径与错误模型）：
  - `DOMAINRULES.GET` / `DOMAINRULES.APPLY`
  - `DOMAINPOLICY.GET` / `DOMAINPOLICY.APPLY`（ack-only）
  - `DOMAINLISTS.GET` / `DOMAINLISTS.APPLY` / `DOMAINLISTS.IMPORT`
- 严格对齐 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md` 与 `CONTROL_COMMANDS_VNEXT.md`：
  - strict reject（unknown key / unknown cmd）
  - 输出稳定排序（`DOMAINRULES` 按 `ruleId`；`DOMAINLISTS` 按 `listKind`→`listId`）
- `DOMAINLISTS.IMPORT` 命令级上限（当 request frame 未超过 `maxRequestBytes` 但超过命令级上限时，必须结构化报错，禁止 silent truncation）：
  - `maxImportDomains=1_000_000`
  - `maxImportBytes=16MiB`
- Import 元数据策略：`DOMAINLISTS.IMPORT` 成功后 daemon **只自动维护 `domainsCount`**（不隐式修改 `outdated/updatedAt/etag`，避免分批导入时误判“已完整同步”）。
- 增加 P0 host 单测与 P1 integration baseline 覆盖（P2 device-smoke 按需追加）。

## Capabilities

### New Capabilities

- `control-vnext-domain-surface`: vNext Domain surface（`DOMAINRULES/DOMAINPOLICY/DOMAINLISTS` + `DOMAINLISTS.IMPORT` limits/error shape）。

### Modified Capabilities

- (none)

## Impact

- Affected runtime areas (implementation phase):
  - vNext control session/dispatch (`src/ControlVNextSession*.cpp`)
  - Domain state managers (`src/RulesManager*`, `src/DomainManager*`, `src/DomainList*`,
    `src/BlockingListManager*`, `src/App*`)
- Affected tests (implementation phase):
  - Host P0 unit tests under `tests/host/`
  - Host-driven integration under `tests/integration/` (vNext domain surface baseline)

