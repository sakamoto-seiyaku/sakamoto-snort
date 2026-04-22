## Why

vNext control 已完成 daemon base + domain + iprules 三条 surface，但“可观测性 metrics”仍分散在 legacy `METRICS.*` 命令（`METRICS.PERF*` / `METRICS.REASONS*` / `METRICS.DOMAIN.SOURCES*`），且缺少 vNext 统一入口与 `traffic/conntrack` 两个 always-on counters，阻碍前端/脚本迁移与稳定回归（见 `docs/IMPLEMENTATION_ROADMAP.md` 与 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`）。

本 change 落地 vNext `METRICS.GET` / `METRICS.RESET`，把 metrics 入口收敛为单一命令目录，并补齐 `traffic` 与 `conntrack` 的固定 shape 与 reset 边界。

## What Changes

- 新增 vNext `METRICS.GET` 与 `METRICS.RESET` 命令（严格 envelope + strict reject + structured selector errors），并接入 daemon vNext control session。
- 支持 v1 `name` 集合（见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`）：
  - `perf`：复用现有 `PerfMetrics` 快照与 reset 语义。
  - `reasons`：复用现有 packet per-reason counters（device-wide），并提供 reset。
  - `domainSources`：复用现有 DomainPolicy source counters（device-wide + per-app），并提供 reset。
  - `traffic`：新增 DNS + packet 轻量 counters（device-wide + per-app），支持 reset（device-wide + per-app）。
  - `conntrack`：新增 conntrack health counters（device-wide），**不提供独立 reset**（仅 `RESETALL` 清零；`METRICS.RESET(name=conntrack)` 返回 `INVALID_ARGUMENT`）。
- 新增 host P0 单测覆盖 metrics shape、reset 边界、selector 语义；新增/扩展 integration P1 case 验证“产生少量流量→metrics 增长→reset 清零”的最小闭环。

## Capabilities

### New Capabilities

- `control-vnext-metrics-surface`: vNext `METRICS.GET/RESET` 命令面（name dispatch、selector/错误模型、strict reject、reset 边界）。
- `traffic-observability`: metrics `name=traffic`（DNS + packet 的轻量 always-on counters；device-wide + per-app；reset 语义）。
- `conntrack-observability`: metrics `name=conntrack`（conntrack health counters；仅 `RESETALL` 清零）。

### Modified Capabilities

_None._

## Impact

- Affected code: vNext control command handlers（新增 metrics handler 与 dispatch）、DNS/packet 热路径的固定维度 counters（`atomic++(relaxed)`）、conntrack metrics snapshot 读口。
- Affected interfaces: 新增 vNext `METRICS.GET/RESET`（不移除 legacy metrics 命令；迁移在后续 `migrate-to-control-vnext` 处理）。
- Affected tests: `tests/host/` 增加 vNext metrics surface P0 单测；`tests/integration/` 增加 metrics 的最小闭环验证段落。

