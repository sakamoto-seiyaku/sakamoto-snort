## Context

本 change 对应 `docs/IMPLEMENTATION_ROADMAP.md` 的切片 **3.2.1(5)**：`add-control-vnext-metrics`（metrics vNext：`traffic` / `conntrack`）。  
vNext control 的协议与命令目录已收敛为单一真相：

- wire/envelope/strict reject/errors：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
- 命令目录（含 `METRICS.GET/RESET`）：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`

现状：

- vNext 已落地 daemon base + domain surface + iprules surface（见 `openspec/specs/control-vnext-*/spec.md` 与对应归档 change）。
- metrics 仍主要通过 legacy 命令暴露（如 `METRICS.PERF*` / `METRICS.REASONS*` / `METRICS.DOMAIN.SOURCES*`），且缺少 vNext 的统一入口与 `traffic/conntrack` 两个 always-on counters。
- `OBSERVABILITY_WORKING_DECISIONS.md` 已锁死 `METRICS.GET(name=traffic|conntrack)` 的口径与 JSON shape，并强调 hot path 只能做固定维度 `atomic++(relaxed)`（不得新增锁/IO/动态分配）。

约束（工程与架构红线）：

- NFQUEUE/DNS 热路径不得引入阻塞 I/O 或长临界区；只能做固定维度原子计数更新。
- `mutexListeners` 的 shared/exclusive 语义必须保持：`RESETALL` 等 mutating 命令必须在独占锁下完成，避免观测与状态重置撕裂。
- selector/错误模型必须复用既有 vNext codec（`ControlVNextCodec.*`）与 selector 解析（`ControlVNextSessionSelectors.hpp`），避免 shape 漂移。

## Goals / Non-Goals

**Goals:**

- 在 vNext 控制面实现 `METRICS.GET` / `METRICS.RESET`，按 `name` 统一暴露 v1 metrics：
  - 既有：`perf` / `reasons` / `domainSources`
  - 新增：`traffic` / `conntrack`
- 为 `traffic` 与 `conntrack` 建立 stable contract（固定字段/固定 shape/明确 reset 边界），并以 host P0 单测锁住。
- 满足 always-on counters 的设计目标：不依赖 stream、不依赖 `tracked`、不引入重型 `StatsTPL/*Stats` 成本。

**Non-Goals:**

- 不实现 vNext stream（`STREAM.START/STOP`、异步 pipeline、NOTICE）；该切片属于 `add-control-vnext-stream`。
- 不移除 legacy metrics 命令；迁移/下线在后续 `migrate-to-control-vnext` 处理。
- 不改变 allow/drop 判决语义；本 change 仅增加观测维度与控制面入口。
- 不引入持久化/集中存储；metrics 生命周期仍为 since boot（进程内），reset 清零。

## Decisions

1) **以独立 vNext handler 落地 `METRICS.GET/RESET`**
   - 选择：新增 metrics handler（与 daemon/domain/iprules handler 并列），由 `ControlVNextSession` 统一 dispatch。
   - 理由：metrics 涉及 `perfMetrics/pktManager/domManager/appManager` 多模块；独立 handler 更便于保持 strict reject 与 name 分派逻辑清晰。
   - 备选：把 metrics 混入 daemon handler（拒绝：职责膨胀，且更容易在后续 stream 切片引入交织依赖）。

2) **vNext `METRICS.GET` 的输出 shape 复用既有 wrapper key**
   - 选择：
     - `name=perf` → `result.perf{...}`（复用现有 `METRICS.PERF` 的 wrapper `perf`）
     - `name=reasons` → `result.reasons{...}`（复用现有 `METRICS.REASONS` 的 wrapper `reasons`）
     - `name=domainSources` → `result.sources{...}`（复用现有 `METRICS.DOMAIN.SOURCES` 的 wrapper `sources`；per-app 额外带 `uid/userId/app`）
     - `name=traffic` → 按 working decisions 的 `result.traffic{dns/rxp/rxb/txp/txb -> {allow,block}}`（per-app 同上带 `uid/userId/app`）
     - `name=conntrack` → `result.conntrack{totalEntries,creates,expiredRetires,overflowDrops}`
   - 理由：保持现有指标语义不变、避免重复命名与前端展示漂移；并与 `CONTROL_COMMANDS_VNEXT.md` 的“入口统一、shape 由权威文档定义”原则一致。
   - 备选：统一为 `{name,data}` 的通用 wrapper（拒绝：会与既有 docs/spec 冲突，且迁移成本更高）。

3) **selector 语义复用 `resolveAppSelector`**
   - 选择：对 `args.app` 解析与错误（`SELECTOR_NOT_FOUND/AMBIGUOUS + candidates[]`）完全复用 `ControlVNextSessionSelectors.hpp::resolveAppSelector`。
   - 理由：vNext selector 是跨命令一致的契约；重复实现容易造成 error shape 漂移。

4) **Traffic counters 采用 per-app 固定维度原子计数（device-wide 查询时聚合）**
   - 选择：在每个 `App` 上维护 `traffic` counters（固定维度、`std::atomic<uint64_t>`、`memory_order_relaxed`），always-on；`METRICS.GET(name=traffic)` device-wide 通过遍历 app 快照汇总。
   - 理由：热路径每包只增加少量 relaxed atomic；避免维护额外 device-wide 全局原子导致更高争用；也避免复用 `StatsTPL`（其包含 shift/time/map 更新）。
   - 备选：同时维护 device-wide sharded counters（拒绝：热路径每次更新增加更多原子操作；后续如有需要再引入）。

5) **Traffic 的更新点严格遵循事实 gating**
   - 选择：
     - DNS：在 `settings.blockEnabled()==true` 的 DNS verdict 路径中更新 `dns.{allow|block} += 1`（不依赖 `tracked`）。
     - packet：仅在进入 NFQUEUE 判决链路时更新 `rxp/rxb/txp/txb`（bytes 口径为 NFQUEUE payload 长度，与 PKTSTREAM `length` 一致）。
   - 理由：与 `OBSERVABILITY_WORKING_DECISIONS.md` 的 gating 与 bytes 口径锁死一致。

6) **Conntrack metrics 仅暴露健康计数；reset 仅允许 `RESETALL`**
   - 选择：`METRICS.GET(name=conntrack)` 返回 `Conntrack::metricsSnapshot()` 的固定字段；`METRICS.RESET(name=conntrack)` 返回 `INVALID_ARGUMENT`（提示用 `RESETALL`）。
   - 理由：working decisions 已锁死 “v1 不提供独立 reset”；独立 reset 会引入并发与热路径语义复杂度（尤其是 “清表+清计数” 与 in-flight update 的关系）。

7) **并发与锁：`METRICS.RESET` 走独占锁 lane**
   - 选择：将 `METRICS.RESET` 视为 mutating 命令，纳入 vNext session 的 exclusive-lock dispatch 集合；`METRICS.GET` 走 shared-lock lane。
   - 理由：保证 reset 与 `RESETALL`/规则 apply 同步，避免出现“读到撕裂的半清零快照”或与 apply 并发导致不可解释状态。

## Risks / Trade-offs

- [Risk] 每包新增原子计数可能影响热路径延迟 → Mitigation：仅少量 `fetch_add(relaxed)`，对齐现有 `ReasonMetrics/DomainPolicySourcesMetrics` 模式；并维持 `BLOCK=0` 时 dataplane bypass 不计数。
- [Risk] device-wide `traffic` 查询成本为 O(#apps) → Mitigation：仅控制面拉取触发；如后续证明压力过大，再引入可选 device-wide sharded counters。
- [Risk] vNext metrics 与 legacy metrics 并存导致文档/实现漂移 → Mitigation：在 `control-vnext-metrics-surface` spec 中明确“shape 等价/字段不变”，并在迁移切片中统一对外推荐入口。

## Migration Plan

- 本 change 仅新增 vNext `METRICS.GET/RESET` 与 `traffic/conntrack` counters；legacy metrics 命令继续保留。
- 后续迁移（`migrate-to-control-vnext`）：前端/脚本默认切换到 vNext `METRICS.GET/RESET`；再评估 legacy 命令冻结与下线窗口。

## Open Questions

- `METRICS.GET(name=traffic)` 的 device-wide 汇总是否需要额外提供 `appsCount`/`truncated` 等辅助字段（当前 working decisions 未要求，默认不加）。
- 在真机 integration 中“稳定产生可控流量”的最小手段选择（优先复用既有脚本/用例，避免引入脆弱的外网依赖）。

