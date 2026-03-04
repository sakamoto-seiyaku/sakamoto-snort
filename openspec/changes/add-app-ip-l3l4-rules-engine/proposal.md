# Change: App-level IPv4 L3/L4 rules engine (per-UID)

## Why
现有 sucre-snort 的数据包判决主要依赖域名系统（DomainList/自定义名单与规则）与 `BLOCKIPLEAKS` 的联动：
- Packet 热路径无法对“无域名/无 DNS 映射”的流量做 per-app 精确控制；
- 仅靠 `BLOCKIPLEAKS` 会把“域名判决”间接投射到 IP，但缺少可控的 L3/L4 原语（src/dst IP、端口、协议、接口、方向等）；
- P0/P1 需要最小可解释性（reasonId/ruleId）与逐条/批次 safety-mode（log-only / would-drop），且必须保持 NFQUEUE 热路径性能与并发约束。

因此需要引入一个专用的 IPv4 L3/L4 规则引擎：面向 App(UID) 提供可扩展的 5 元组规则能力，并与现有域名系统（含 ip-leak）在 Packet 判决处以可控策略合流。

## What Changes
- 新增 IPv4 L3/L4 per-app 规则引擎（内部支持 `ALLOW`/`BLOCK`、显式 `priority`、`src/dst CIDR`、`src/dst port(ANY/精确/range)`、`proto`、`direction`、`ifaceKind` 与可选 `ifindex` 精确匹配；预留 CT 字段）。
- 引擎采用 immutable snapshot + atomic publish（RCU 风格），热路径只读查询；控制面编译新快照并执行 **preflight 复杂度评估**，超出硬上限则拒绝 apply。
- 控制面新增命令：
  - `IPRULES`（开关）
  - `POLICY.ORDER`（域名系统 ip-leak 结果与 IP 规则结果的合流优先级：`DOMAIN_FIRST|IP_FIRST|PRIORITY`）
  - `IPRULES.ADD/UPDATE/REMOVE/ENABLE/PRINT/PREFLIGHT`（规则管理与预检）
  - `IFACES.PRINT`（输出 `ifindex -> {name,kind}` 映射，支持多 VPN/多网卡场景的精确匹配）
- 可解释性与观测：依赖 `add-pktstream-observability`（PKTSTREAM schema + `reasonId/ruleId/wouldRuleId` 契约）。本引擎在命中时填充相应 `reasonId` 与 `ruleId/wouldRuleId`，并提供 per-rule 计数（hit/lastHit/wouldHit/lastWouldHit）。

## Relationship to existing changes
本 change **supersedes** `openspec/changes/add-app-ip-blacklist/`：
- 旧 change 仅覆盖 `(uid, remoteIP)` 的补充黑名单能力；
- 新 change 将其吸收为更通用的 L3/L4 引擎能力（内部仍可表达“remoteIP block”子集），并加入端口/协议/接口/方向、ALLOW 语义与合流策略。

## Non-Goals (this change)
- 不新增新的观测通路（仅复用 `PKTSTREAM` + 统计）。
- 不实现全局 checkpoint/rollback；safety-mode 仅针对规则引擎的 `enforce/log`。
- 不在 P0/P1 强行重构域名系统内部（DomainList/自定义规则/名单的判决链保持原样）。
- IPv6 新规则后置：本 change 的新规则语义仅覆盖 IPv4；IPv6 规则匹配与提示不在本期范围。
- DOMAINMAP（DNS getips/映射维护）等“最终融合开关语义”暂不决策，留作后续融合阶段的独立 change 或扩展。

## Impact
- 主要影响模块（实现阶段）：`PacketManager`（热路径合流与规则引擎接入）、`Control`（新命令）、`Settings`（新增持久化字段）。PKTSTREAM schema 变更由 `add-pktstream-observability` 定义与实现。
- 性能与并发：热路径必须保持无新锁/无重 IO；规则引擎以 snapshot + 预检硬上限控制最坏复杂度。
