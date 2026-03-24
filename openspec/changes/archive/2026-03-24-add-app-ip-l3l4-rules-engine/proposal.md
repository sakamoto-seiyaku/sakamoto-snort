# Change: App-level IPv4 L3/L4 rules engine (per-UID)

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


## Why
现有 sucre-snort 的数据包判决主要依赖域名系统（DomainList/自定义名单与规则）与 `BLOCKIPLEAKS` 的联动：
- Packet 热路径无法对“无域名/无 DNS 映射”的流量做 per-app 精确控制；
- 仅靠 `BLOCKIPLEAKS` 会把“域名判决”间接投射到 IP，但缺少可控的 L3/L4 原语（src/dst IP、端口、协议、接口、方向等）；
- 在引入多维 IPv4 L3/L4 规则后，若每包都直接落入 classifier，将显著放大热路径成本；当前缺失的一环是位于 classifier 之前的 exact-decision cache；
- P0/P1 需要最小可解释性（reasonId/ruleId）与逐条/批次 safety-mode（当前仅指 `BLOCK` 规则的 would-block dry-run），且必须保持 NFQUEUE 热路径性能与并发约束。

因此需要引入一个专用的 IPv4 L3/L4 规则引擎：面向 App(UID) 提供可扩展的 5 元组规则能力，先完成主规则能力、可解释性与性能边界；`ip-leak` 相关融合暂不纳入本 change。

## What Changes
- 新增 IPv4 L3/L4 per-app 规则引擎（内部支持 `ALLOW`/`BLOCK`、规则级 `enabled`、显式 `priority`、`src/dst CIDR`、`src/dst port(ANY/精确/range)`、`proto`、`direction`、`ifaceKind` 与可选 `ifindex` 精确匹配；当前 v1 控制面为 uid-only，不接受包名字符串 selector，也不接受 `ct` 条件。`enabled=0` 的规则保留在控制面，但不进入 active matcher）。
- 引擎采用“两层数据面”结构：前置 `PacketKeyV4` 驱动的 per-thread exact-decision cache，后置 immutable classifier snapshot；cache 允许缓存 `NoMatch`，仅缓存 IP 规则引擎层结果，不缓存整个系统最终 verdict。
- 引擎采用 immutable snapshot + atomic publish（RCU 风格），热路径只读查询；控制面编译新快照并执行 **preflight 复杂度评估**，超出硬上限则拒绝 apply。该设计的 correctness 与性能基线明确不依赖 `NFQA_CT`、内核 conntrack 可见性或用户态自研 full flow tracking。
- 控制面新增命令：
  - `IPRULES`（开关）
  - `IPRULES.ADD/UPDATE/REMOVE/ENABLE/PRINT/PREFLIGHT`（规则管理与预检；`IPRULES.PRINT` 固定返回 `{"rules":[...]}`，空结果返回空数组）
  - `IFACES.PRINT`（固定输出 `{"ifaces":[...]}`；元素至少包含 `{ifindex,name,kind}`，允许空数组，支持多 VPN/多网卡场景的精确匹配）
- 可解释性与观测：依赖 `add-pktstream-observability`（PKTSTREAM schema + `reasonId/ruleId/wouldRuleId` 契约）。本引擎在命中时填充相应 `reasonId` 与 `ruleId/wouldRuleId`，并提供固定 v1 形态的 per-rule stats（`hitPackets/hitBytes/lastHitTsNs` + `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`）。
- 保持现有 `IFACE_BLOCK` 为最高优先级 hard-drop；`ip-leak` 与 IP 规则的合流语义改记为 TBD，不在本 change 内启用。

## Relationship to existing changes
本 change **supersedes** `openspec/changes/add-app-ip-blacklist/`：
- 旧 change 仅覆盖 `(uid, remoteIP)` 的补充黑名单能力；
- 新 change 将其吸收为更通用的 L3/L4 引擎能力（内部仍可表达“remoteIP block”子集），并加入端口/协议/接口/方向与 `ALLOW` 语义。

## Non-Goals (this change)
- 不新增新的观测通路（仅复用 `PKTSTREAM` + 统计）。
- 不实现全局 checkpoint/rollback；safety-mode 仅针对规则引擎的 `enforce/log`。
- 不在 P0/P1 强行重构域名系统内部（DomainList/自定义规则/名单的判决链保持原样）。
- IPv6 新规则后置：本 change 的新规则语义仅覆盖 IPv4；IPv6 规则匹配与提示不在本期范围。
- `ip-leak`、`POLICY.ORDER`、DOMAINMAP（DNS `getips`/映射维护）等融合语义暂不决策，留作后续融合阶段的独立 change 或扩展。

## Impact
- 主要影响模块（实现阶段）：`PacketListener`（`PacketKeyV4` 提取、`IFACE_BLOCK` 前移、cache/classifier/legacy 路径调度）、`PacketManager`（legacy 判决与现有观测路径收口）、`Control`（新命令）、`Settings`（新增持久化字段）。PKTSTREAM schema 变更由 `add-pktstream-observability` 定义与实现。
- 性能与并发：热路径必须保持无新锁/无重 IO；规则引擎以前置 exact cache + snapshot classifier + 预检硬上限控制最坏复杂度。
