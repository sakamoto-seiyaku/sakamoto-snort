## ADDED Requirements

### Requirement: Per-app IPv4 L3/L4 rules exist and are deterministic
系统 MUST 提供按 App(UID) 的 IPv4 L3/L4 规则能力，规则匹配维度至少包含：
- `uid`
- `direction`（in/out/any）
- `ifaceKind`（wifi/data/vpn/unmanaged/any）与可选 `ifindex` 精确匹配
- `proto`（tcp/udp/icmp/any）
- `src IPv4 CIDR` 与 `dst IPv4 CIDR`（`/0..32`）
- `srcPort` 与 `dstPort`（any / 精确 / range）

命中语义 MUST 全局确定：同一数据包在同一时刻命中多条规则时，系统 SHALL 以 `priority` 为主键选取唯一命中规则，并使用固定 tie-break（例如 `specificityScore`、`ruleId`）保证稳定性。

#### Scenario: Highest priority rule wins
- **GIVEN** 针对同一 `uid` 存在两条均可命中的规则，且它们 `priority` 不同
- **WHEN** NFQUEUE 收到该 `uid` 的 IPv4 数据包
- **THEN** 系统 SHALL 选择 `priority` 更高的规则作为唯一命中，并输出对应的 `ruleId`

### Requirement: Rule actions include ALLOW and BLOCK
系统 MUST 支持规则动作 `ALLOW` 与 `BLOCK`。当 IP 规则引擎启用且命中：
- `ALLOW` SHALL 使该包最终 verdict 为 ACCEPT
- `BLOCK` SHALL 使该包最终 verdict 为 DROP

#### Scenario: ALLOW rule accepts a packet
- **GIVEN** `IPRULES=1` 且存在一条命中该包的 `ALLOW` 规则
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 ACCEPT

#### Scenario: BLOCK rule drops a packet
- **GIVEN** `IPRULES=1` 且存在一条命中该包的 `BLOCK` 规则
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 DROP

### Requirement: Per-rule safety-mode via enforce/log (would-match)
系统 MUST 为每条规则提供 `enforce` 与 `log` 控制：
- `enforce=1`：命中时按 `ALLOW/BLOCK` 实际执行
- `enforce=0, log=1`：命中时不得实际 DROP/ACCEPT 改变全局策略，仅产生 **would-match** 可观测结果

`enforce=0` 的 would-match 事件在 `PKTSTREAM` 中每包最多输出 1 条（包含 `wouldRuleId` 与 `wouldDrop=1`）。

#### Scenario: Would-block does not drop the packet
- **GIVEN** `IPRULES=1` 且存在一条命中该包的规则，且 `action=BLOCK`、`enforce=0`、`log=1`
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 ACCEPT
- **AND** PKTSTREAM SHALL 输出该包的 would-match（包含该规则的 `wouldRuleId` 与 `wouldDrop=1`）

### Requirement: Per-rule runtime stats are maintained and exposed
系统 MUST 为每条 IP 规则维护并对外暴露 runtime stats（不依赖 PKTSTREAM 是否开启）：
- `hitPackets:uint64` / `hitBytes:uint64` / `lastHitTsNs:uint64`
- `wouldHitPackets:uint64` / `wouldHitBytes:uint64` / `lastWouldHitTsNs:uint64`

系统 MUST 通过控制面 `IPRULES.PRINT` 在 rule 对象中输出上述 `stats` 字段。

约束：
- `hit*` 仅在该规则作为最终 enforce 命中规则时更新（每包最多 1 条规则被计为 hit）。
- `wouldHit*` 仅在该规则作为最终 would-match 规则时更新（每包最多 1 条 would-match）。
- stats 生命周期为 since boot（重启后归零），不要求持久化。

#### Scenario: Enforce hit updates hitPackets and lastHitTsNs
- **GIVEN** `IPRULES=1` 且存在一条 `enforce=1` 的规则可命中某 IPv4 包（其 `ruleId` 为 R）
- **WHEN** 发送该包
- **THEN** 后续调用 `IPRULES.PRINT RULE R` 时，返回的 `stats.hitPackets` SHALL 大于等于 1
- **AND** `stats.lastHitTsNs` SHALL 大于 0

#### Scenario: Would-match updates wouldHitPackets without dropping
- **GIVEN** `IPRULES=1` 且存在一条 `action=BLOCK,enforce=0,log=1` 的规则可命中某 IPv4 包（其 `ruleId` 为 W）
- **AND** 该包未命中任何 `enforce=1` 的规则
- **WHEN** 发送该包
- **THEN** 系统 SHALL 返回 ACCEPT
- **AND** 后续调用 `IPRULES.PRINT RULE W` 时，返回的 `stats.wouldHitPackets` SHALL 大于等于 1

### Requirement: Engine can be disabled with zero behavioral impact
系统 MUST 提供全局开关 `IPRULES`。当 `IPRULES=0` 时：
- IP 规则引擎 SHALL 不参与 Packet 判决；
- 对外行为 SHALL 与未配置 IP 规则时一致（除去 PKTSTREAM 新增字段的兼容性扩展）。

#### Scenario: Disabling IPRULES restores baseline behaviour
- **GIVEN** 配置了可命中某包的 IP 规则
- **WHEN** 将 `IPRULES` 设为 0 并再次发送该包
- **THEN** 系统 SHALL 不再因该 IP 规则而改变该包的 verdict

### Requirement: Domain ip-leak result participates via POLICY.ORDER
系统 MUST 允许调用方控制“域名系统的 ip-leak 判决结果”与“IP 规则引擎结果”的合流顺序，通过 `POLICY.ORDER` 提供至少三种模式：
- `DOMAIN_FIRST`
- `IP_FIRST`
- `PRIORITY`

其中 ip-leak 仍被视为**域名系统的一部分**（其 reasonId 属于域名系统），其是否被 `ALLOW` 覆盖取决于 `POLICY.ORDER` 的定义。

#### Scenario: POLICY.ORDER changes whether ALLOW can override ip-leak
- **GIVEN** 某包同时满足 ip-leak 的 DROP 条件
- **AND** 该包也命中一条 `ALLOW` 的 IP 规则
- **WHEN** `POLICY.ORDER=DOMAIN_FIRST`
- **THEN** 系统 SHALL 按 `DOMAIN_FIRST` 的定义决定 verdict（例如优先应用 ip-leak）
- **WHEN** `POLICY.ORDER=IP_FIRST`（或 `PRIORITY`，按定义允许覆盖）
- **THEN** 系统 SHALL 按新的合流模式决定 verdict

### Requirement: Preflight rejects overly complex rule sets
系统 MUST 在控制面提供 `IPRULES.PREFLIGHT` 输出复杂度统计，并对超过硬上限的规则集拒绝 apply（返回 `NOK`），以保证 NFQUEUE 热路径最坏复杂度可控。

#### Scenario: Too many range rules in a bucket is rejected
- **GIVEN** 规则集合导致某个 bucket 的 `rangeCandidates` 数量超过硬上限
- **WHEN** 客户端尝试 apply/update 该规则集合
- **THEN** 系统 SHALL 拒绝该变更并返回 `NOK`，并在 preflight 报告中指出超限项

### Requirement: IFACES.PRINT exposes ifindex mapping for precise matching
系统 MUST 提供 `IFACES.PRINT` 输出当前网络接口信息，使调用方可在需要时对 `ifindex` 做精确匹配。

#### Scenario: IFACES.PRINT returns at least one interface
- **WHEN** 客户端调用 `IFACES.PRINT`
- **THEN** 返回值 SHALL 是合法 JSON
- **AND** 至少包含一个 `{ifindex,name,kind}` 结构

### Requirement: IPv6 is not affected by new IPv4 rules
本 change 引入的 L3/L4 规则语义仅覆盖 IPv4。IPv6 流量 MUST 不受这些新规则影响（默认放行且不提示规则命中）。

#### Scenario: IPv6 packet is not dropped by IPv4 rules
- **GIVEN** 存在会匹配某 IPv4 流量的 IP 规则
- **WHEN** 发送同 uid 的 IPv6 流量
- **THEN** 系统 SHALL 不因这些 IPv4 规则而改变 IPv6 的 verdict
