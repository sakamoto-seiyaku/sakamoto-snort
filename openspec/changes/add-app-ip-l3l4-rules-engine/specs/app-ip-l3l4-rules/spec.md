## ADDED Requirements

### Requirement: Per-app IPv4 L3/L4 rules exist and are deterministic
系统 MUST 提供按 App(UID) 的 IPv4 L3/L4 规则能力，规则匹配维度至少包含：
- `uid`
- `direction`（in/out/any）
- `ifaceKind`（wifi/data/vpn/unmanaged/any）与可选 `ifindex` 精确匹配
- `proto`（tcp/udp/icmp/any）
- `src IPv4 CIDR` 与 `dst IPv4 CIDR`（`/0..32`）
- `srcPort` 与 `dstPort`（any / 精确 / range）

系统 MUST 将 `src/dst` 与 `srcPort/dstPort` 解释为数据包 IPv4/L4 头部字段（`saddr/daddr`、TCP/UDP `source/dest`）。`direction=in|out` 仅表示包来自 `INPUT/OUTPUT` 链（入站/出站），不改变上述字段含义。

命中语义 MUST 全局确定：同一数据包在同一时刻命中多条规则时，系统 SHALL 先以 `priority` 为主键选取最高优先级候选；若同优先级仍有多条重叠命中，则 SHALL 由编译后的 classifier 稳定查询路径选出唯一命中规则。对同一份 active ruleset，重复编译后对同一包的唯一命中结果 MUST 保持一致。

#### Scenario: Highest priority rule wins
- **GIVEN** 针对同一 `uid` 存在两条均可命中的规则，且它们 `priority` 不同
- **WHEN** NFQUEUE 收到该 `uid` 的 IPv4 数据包
- **THEN** 系统 SHALL 选择 `priority` 更高的规则作为唯一命中，并输出对应的 `ruleId`

#### Scenario: Same-priority overlap uses deterministic compiled winner
- **GIVEN** 针对同一 `uid` 存在两条 `priority` 相同且均可命中的规则
- **WHEN** 系统以同一份 active ruleset 对该规则集重复编译并处理同一 IPv4 数据包
- **THEN** 系统 SHALL 在两次处理中选出同一条唯一命中规则

### Requirement: Current v1 control surface is uid-only and rejects unsupported match dimensions
系统 MUST 将当前 v1 规则控制面限定为数值 `uid` 选择器；包名字符串 selector MUST NOT 作为本 change 的输入语义。系统 MUST 要求 `IPRULES.ADD` 创建规则时 `priority` 显式提供；缺失 `priority` 的创建请求 MUST 返回 `NOK`。对于 `enabled/enforce/log`，系统 MUST 将其 v1 缺省值固定为 `1/1/0`（仅适用于 `IPRULES.ADD` 创建时省略字段）。系统 MUST 将 `IPRULES.UPDATE` 定义为 patch/merge：仅更新请求中提供的 key；未提供的 key（包含 `priority`）MUST 保持原值（不得回落到缺省值）。系统 MUST 将 `enforce=0` 限定为 `action=BLOCK, log=1` 的 would-block safety-mode；其它 `enforce=0` 组合（例如 `action=ALLOW, enforce=0` 或 `enforce=0, log=0`）MUST 返回 `NOK`。系统 MUST 同时拒绝当前未纳入 v1 语义的控制面字段（例如 `ct`），避免出现“看起来已配置、实际上不生效”的假语义。系统 MUST NOT 将 `NFQA_CT`、内核 conntrack 元数据或用户态自研 full flow tracking 作为当前 v1 匹配语义成立的前提。

控制面 MUST 为“输入合法性”保持严格与原子性：
- 对 `IPRULES.ADD/UPDATE/REMOVE/ENABLE`，若输入包含未知 key、无法解析的值、或违反本 spec 的组合约束，则系统 MUST 返回 `NOK`。
- 对上述返回 `NOK` 的请求，系统 MUST NOT 改变当前规则集（含 active snapshot 与持久化内容），且 `IPRULES.ADD` MUST NOT 消耗新的 `ruleId`（不得出现“失败的 ADD 也推进了 ruleId 计数器”的洞）。

#### Scenario: Package-name selector is rejected
- **GIVEN** 客户端尝试以包名字符串而非数值 `uid` 创建或查询规则
- **WHEN** 控制面校验该请求
- **THEN** 系统 SHALL 返回 `NOK`

#### Scenario: Missing priority on ADD is rejected
- **GIVEN** 客户端尝试通过 `IPRULES.ADD` 创建规则，但未提供 `priority`
- **WHEN** 控制面校验该请求
- **THEN** 系统 SHALL 返回 `NOK`

#### Scenario: Failed ADD is atomic and does not consume ruleId
- **GIVEN** 当前无任何规则
- **WHEN** 客户端调用 `IPRULES.ADD 10000 action=block`（缺失 `priority`）
- **THEN** 返回值 SHALL 为 `NOK`
- **AND** 后续 `IPRULES.PRINT` SHALL 返回 `{"rules":[]}`
- **WHEN** 客户端调用 `IPRULES.ADD 10000 action=block priority=10`
- **THEN** 返回值（`ruleId`）SHALL 为 `0`

#### Scenario: Unsupported ct field is rejected
- **GIVEN** 客户端尝试创建或更新规则，并传入 `ct=...`
- **WHEN** 控制面校验该规则
- **THEN** 系统 SHALL 返回 `NOK`

#### Scenario: Invalid enforce combinations are rejected
- **GIVEN** 客户端尝试创建或更新规则，并传入 `enforce=0`
- **AND** 该规则不满足 `action=BLOCK, log=1`
- **WHEN** 控制面校验该请求
- **THEN** 系统 SHALL 返回 `NOK`

#### Scenario: v1 matching semantics do not depend on conntrack metadata
- **GIVEN** 当前环境未向 NFQUEUE 暴露 `NFQA_CT` 或其他 conntrack 元数据
- **AND** 已配置一条仅依赖 v1 已定义字段（`uid/direction/iface/proto/src/dst/ports`）的规则
- **WHEN** NFQUEUE 收到可命中该规则的 IPv4 数据包
- **THEN** 系统 SHALL 仍按这些 v1 字段完成匹配并得出一致的 IP 规则结果

#### Scenario: Omitted toggle fields use v1 defaults
- **GIVEN** 客户端创建一条规则时未显式提供 `enabled/enforce/log`
- **WHEN** 后续客户端调用 `IPRULES.PRINT RULE R` 查看该规则
- **THEN** 返回的该规则对象 SHALL 体现 `enabled=1`
- **AND** 返回的该规则对象 SHALL 体现 `enforce=1`
- **AND** 返回的该规则对象 SHALL 体现 `log=0`

#### Scenario: UPDATE preserves omitted fields (patch semantics)
- **GIVEN** 已存在一条规则 `R`，其 `log=1` 且 `dport=80`
- **WHEN** 客户端调用 `IPRULES.UPDATE R dport=443`（未提供 `log`）
- **THEN** 后续客户端调用 `IPRULES.PRINT RULE R` 时，该规则对象 SHALL 仍体现 `log=1`
- **AND** 该规则对象 SHALL 体现 `dport=443`

### Requirement: Omitted match fields default to ANY and are normalized
系统 MUST 允许在 `IPRULES.ADD` 省略除 `action/priority` 以外的 match 字段；省略时控制面 MUST 归一化为 `any`，并在 `IPRULES.PRINT` 中按归一化值输出。最小归一化集合至少包括：
- `dir=any`
- `iface=any`
- `ifindex=0`（表示 any）
- `proto=any`
- `src=any`
- `dst=any`
- `sport=any`
- `dport=any`

系统 MUST 将控制面输入中的 `ifindex=0` 视为 `ifindex=any` 的同义。

系统 MUST 拒绝会产生“看起来配置了但永远不匹配”的假语义：当 `proto=icmp` 时，`sport/dport` MUST 为 `any`；否则 `IPRULES.ADD/UPDATE` MUST 返回 `NOK`。

#### Scenario: Omitted match fields normalize to ANY on PRINT
- **GIVEN** 客户端通过 `IPRULES.ADD` 创建规则时仅提供 `action/priority`（未提供 match 字段），并获得返回的 `ruleId=R`
- **WHEN** 客户端调用 `IPRULES.PRINT RULE R` 查看该规则
- **THEN** 返回的该规则对象 SHALL 体现 `dir=any`
- **AND** 返回的该规则对象 SHALL 体现 `iface=any`
- **AND** 返回的该规则对象 SHALL 体现 `ifindex=0`
- **AND** 返回的该规则对象 SHALL 体现 `proto=any`
- **AND** 返回的该规则对象 SHALL 体现 `src=any`
- **AND** 返回的该规则对象 SHALL 体现 `dst=any`
- **AND** 返回的该规则对象 SHALL 体现 `sport=any`
- **AND** 返回的该规则对象 SHALL 体现 `dport=any`

#### Scenario: ifindex=0 is accepted as ANY
- **GIVEN** 客户端通过 `IPRULES.ADD` 创建规则，并显式提供 `ifindex=0`
- **WHEN** 控制面校验该请求
- **THEN** 系统 SHALL 接受该规则创建请求（不返回 `NOK`）

#### Scenario: ICMP with non-any ports is rejected
- **GIVEN** 客户端尝试创建或更新规则，且 `proto=icmp`
- **AND** 同时提供 `sport` 或 `dport` 为非 `any`
- **WHEN** 控制面校验该请求
- **THEN** 系统 SHALL 返回 `NOK`

### Requirement: Port predicates only apply to TCP/UDP packets
系统 MUST 将 `sport/dport` 解释为 TCP/UDP 的 L4 头部字段。对于 `proto` 不是 `tcp` 也不是 `udp` 的数据包（例如 `icmp`），规则仅当 `sport=any` 且 `dport=any` 时才允许因端口维度通过匹配；若规则包含任一非 `any` 的端口约束，则该规则 MUST NOT 匹配该非 TCP/UDP 数据包（即使该规则的 `proto=any`）。

#### Scenario: ICMP does not match proto=any rule with port constraint
- **GIVEN** `BLOCK=1` 且 `IPRULES=1`
- **AND** 存在一条规则 `R`，其 `proto=any` 且 `dport=53`（其余字段均为 any，且该规则 `enforce=1`）
- **WHEN** NFQUEUE 收到一个 `proto=icmp` 的 IPv4 数据包
- **THEN** PKTSTREAM SHALL NOT 包含来自该规则的 `ruleId`
- **AND** 若该事件包含 `reasonId`，则其 SHALL NOT 为 `IP_RULE_ALLOW` 或 `IP_RULE_BLOCK`

### Requirement: Rule actions include ALLOW and BLOCK
系统 MUST 支持规则动作 `ALLOW` 与 `BLOCK`。当 `BLOCK=1` 且数据包未命中更高优先级硬原因、且 IP 规则引擎启用并命中：
- `ALLOW` SHALL 使该包最终 verdict 为 ACCEPT
- `BLOCK` SHALL 使该包最终 verdict 为 DROP

#### Scenario: ALLOW rule accepts a packet
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 存在一条命中该包的 `ALLOW` 规则
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 ACCEPT

#### Scenario: BLOCK rule drops a packet
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 存在一条命中该包的 `BLOCK` 规则
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 DROP

### Requirement: Enforce hits are attributed in PKTSTREAM
当 `BLOCK=1` 且数据包未命中更高优先级硬原因、且 `IPRULES=1` 下最终由某条 `enforce=1` 规则决定实际 verdict 时，系统 MUST 在 PKTSTREAM 中输出与该实际 verdict 一致的 `reasonId`，并输出唯一胜出规则的 `ruleId`：
- `ALLOW` 命中时，`reasonId` SHALL 为 `IP_RULE_ALLOW`
- `BLOCK` 命中时，`reasonId` SHALL 为 `IP_RULE_BLOCK`

#### Scenario: Enforce ALLOW emits IP_RULE_ALLOW and ruleId
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 某条 `ALLOW,enforce=1` 规则作为最终胜出规则命中该包
- **WHEN** 系统输出该包的 PKTSTREAM 事件
- **THEN** 事件 SHALL 包含该规则的 `ruleId`
- **AND** `reasonId` SHALL 为 `IP_RULE_ALLOW`

#### Scenario: Enforce BLOCK emits IP_RULE_BLOCK and ruleId
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 某条 `BLOCK,enforce=1` 规则作为最终胜出规则命中该包
- **WHEN** 系统输出该包的 PKTSTREAM 事件
- **THEN** 事件 SHALL 包含该规则的 `ruleId`
- **AND** `reasonId` SHALL 为 `IP_RULE_BLOCK`

### Requirement: ruleId is stable under incremental rule management
系统 MUST 为每条规则分配 `ruleId`，并在当前增量管理模型下保持其稳定性：
- 空规则集上的第一条规则 MUST 使用初始 `ruleId = 0`
- `IPRULES.ADD` MUST 为新规则分配从 `0` 开始单调递增的整数 `ruleId`
- `IPRULES.UPDATE` 与 `IPRULES.ENABLE` MUST 保留原有 `ruleId`
- `IPRULES.REMOVE` MUST NOT 触发其余规则重新编号
- 已删除 `ruleId` 在当前规则集生命周期内 MUST NOT 被后续 `ADD` 复用
- 持久化恢复后，已保存规则 MUST 保持原有 `ruleId`
- 持久化恢复后，`IPRULES.ADD` 的分配状态 MUST 继续保持单调递增（即使重启前删除了最高 `ruleId`，也不得在重启后复用已删除的 id）
- `RESETALL` 清空整套规则集后，后续第一条新规则 MUST 从初始 `ruleId = 0` 重新开始分配

#### Scenario: UPDATE preserves ruleId
- **GIVEN** 已存在一条规则，其 `ruleId` 为 `R`
- **WHEN** 客户端执行 `IPRULES.UPDATE R ...` 并使新定义生效
- **THEN** 后续 `IPRULES.PRINT RULE R` SHALL 仍以 `R` 标识该规则

#### Scenario: REMOVE does not renumber surviving rules
- **GIVEN** 已存在两条规则，其 `ruleId` 分别为 `R1` 与 `R2`
- **WHEN** 客户端移除 `R1`
- **THEN** 后续 `R2` SHALL 仍保持原有 `ruleId`

#### Scenario: RESETALL restarts ruleId allocation from the initial value
- **GIVEN** 先前规则集内已经分配过多个 `ruleId`
- **WHEN** 客户端调用 `RESETALL` 并随后重新添加第一条规则
- **THEN** 该新规则 SHALL 使用初始 `ruleId = 0`

#### Scenario: Restart does not reuse deleted highest ruleId
- **GIVEN** 已存在三条规则，其 `ruleId` 分别为 `0/1/2`
- **AND** 客户端移除 `ruleId=2`（当前最高 id）
- **WHEN** 进程重启并恢复持久化状态
- **AND** 客户端再次调用 `IPRULES.ADD ...` 添加新规则
- **THEN** 该新规则 SHALL 分配到 `ruleId=3`（不得复用已删除的 `2`）

### Requirement: IFACE_BLOCK remains the highest-priority hard drop
系统 MUST 保持 `IFACE_BLOCK` 为高于 IP 规则引擎的 hard-drop 原因。在 `BLOCK=1` 时命中 `IFACE_BLOCK`，系统 SHALL 直接 DROP，并 SHALL NOT 让 `ALLOW`/`BLOCK`/would-match 改写该包的实际原因，也 SHALL NOT 输出来自 IP 规则引擎的 `ruleId`/`wouldRuleId` 归因。

#### Scenario: ALLOW rule cannot override IFACE_BLOCK
- **GIVEN** `BLOCK=1`
- **AND** 某包命中 `IFACE_BLOCK`
- **AND** 该包也命中一条 `ALLOW` 的 IP 规则
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 DROP
- **AND** 该包的实际 `reasonId` SHALL 为 `IFACE_BLOCK`
- **AND** PKTSTREAM SHALL NOT 包含来自 IP 规则引擎的 `ruleId` 或 `wouldRuleId`

### Requirement: Only enforce ALLOW/BLOCK short-circuit legacy/domain
当 `BLOCK=1` 且 `IPRULES=1` 时，系统 MUST 遵循以下判决边界：
- 若某条 `enforce=1` 规则作为最终胜出规则命中，则系统 SHALL 使用该规则决定实际 verdict（`ALLOW`→ACCEPT，`BLOCK`→DROP），并 SHALL NOT 再回落到 legacy/domain 路径。
- 若不存在任何 `enforce=1` 的最终命中，则系统 SHALL 继续进入 legacy/domain 路径；此时 IP 规则层可能给出 `NoMatch` 或 `WouldBlock` overlay 候选，但二者都 SHALL NOT 短路 legacy/domain。

其中：
- `NoMatch` 表示 IP 规则层无任何命中；该层 SHALL NOT 产生 `ruleId`、`wouldRuleId` 或 `IP_RULE_*` 归因。
- `WouldBlock` 表示存在 would-drop overlay 候选（`action=BLOCK,enforce=0,log=1` 的最终胜出规则）；其不得改变系统最终 verdict，且仅当最终 verdict 为 ACCEPT 时才允许输出 would-match（`wouldRuleId/wouldDrop`）。

该 change 不定义 legacy/domain 路径的详细判决语义。

#### Scenario: No matching IP rule yields no IP-rule attribution and falls through
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 当前 active ruleset 中没有任何规则命中该包
- **WHEN** NFQUEUE 收到该包
- **THEN** PKTSTREAM SHALL NOT 包含来自 IP 规则引擎的 `ruleId` 或 `wouldRuleId`
- **AND** 若该事件包含 `reasonId`，则其 SHALL NOT 为 `IP_RULE_ALLOW` 或 `IP_RULE_BLOCK`
- **AND** 该包 SHALL 继续进入后续 legacy/domain 路径

#### Scenario: Would-block is an overlay and still falls through to legacy/domain
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 某条 `action=BLOCK,enforce=0,log=1` 规则作为最终 would-drop overlay 候选命中该包
- **WHEN** NFQUEUE 收到该包
- **THEN** 该包 SHALL 继续进入后续 legacy/domain 路径（不被 would-block 短路）

### Requirement: Per-rule safety-mode via enforce/log (would-match)
系统 MUST 为规则提供 `enforce` 与 `log` 控制，其中当前 safety-mode 仅适用于 `BLOCK` 规则：
- `enforce=1`：命中时按 `ALLOW/BLOCK` 实际执行
- `action=BLOCK, enforce=0, log=1`：表示 would-block；仅当该包未被任何 `enforce=1` 规则作为最终命中接管时，才产生 **would-match** 可观测结果；其命中不得改变系统最终 verdict，仅用于观测 overlay；并且仅当最终 verdict 为 ACCEPT 时才允许输出 would-match
- 控制面 MUST 拒绝其他 `enforce=0` 组合（包括 `action=ALLOW, enforce=0` 与 `enforce=0, log=0`）

`enforce=0` 的 would-match 事件在 `PKTSTREAM` 中每包最多输出 1 条（包含 `wouldRuleId` 与 `wouldDrop=1`）。

#### Scenario: Would-block does not drop the packet
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 存在一条命中该包的规则，且 `action=BLOCK`、`enforce=0`、`log=1`
- **AND** 后续 legacy/domain 路径对该包最终 verdict 为 ACCEPT
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 ACCEPT
- **AND** PKTSTREAM SHALL 输出该包的 would-match（包含该规则的 `wouldRuleId` 与 `wouldDrop=1`）

#### Scenario: Would-block is suppressed when final verdict is DROP
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 存在一条命中该包的规则，且 `action=BLOCK`、`enforce=0`、`log=1`（其 `ruleId` 为 W）
- **AND** 该包未命中任何 `enforce=1` 的规则
- **AND** 后续 legacy/domain 路径对该包最终 verdict 为 DROP
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 DROP
- **AND** PKTSTREAM SHALL NOT 输出该包的 would-match（不得包含 `wouldRuleId` 或 `wouldDrop`）
- **AND** 后续调用 `IPRULES.PRINT RULE W` 时，返回的 `stats.wouldHitPackets` SHALL 不增加

#### Scenario: Enforce match suppresses would-match regardless of priority
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 存在一条命中该包的 `ALLOW,enforce=1` 规则
- **AND** 同时存在一条也可命中的 `BLOCK,enforce=0,log=1` would-drop 规则（其 `priority` 更高）
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 返回 ACCEPT
- **AND** PKTSTREAM SHALL 包含 `ruleId`（来自 `ALLOW,enforce=1` 规则）
- **AND** PKTSTREAM SHALL NOT 包含 `wouldRuleId`

#### Scenario: Multiple would-drop candidates pick a single deterministic winner
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1` 且该包未命中 `IFACE_BLOCK`
- **AND** 该包未命中任何 `enforce=1` 的规则
- **AND** 存在两条均可命中的 would-drop 规则（`action=BLOCK,enforce=0,log=1`），且 `priority` 不同
- **AND** 后续 legacy/domain 路径对该包最终 verdict 为 ACCEPT
- **WHEN** NFQUEUE 收到该包
- **THEN** PKTSTREAM SHALL 仅输出 1 个 `wouldRuleId`
- **AND** 该 `wouldRuleId` SHALL 对应 `priority` 更高的那条规则

#### Scenario: ALLOW rule cannot use enforce=0 safety-mode
- **GIVEN** 客户端尝试创建或更新一条规则，且其 `action=ALLOW`、`enforce=0`
- **WHEN** 控制面校验该规则
- **THEN** 系统 SHALL 返回 `NOK`

### Requirement: Disabled rules are inert and zero-cost
系统 MUST 支持规则级 `enabled` 开关。`enabled=0` 的规则 MUST 继续保留在控制面、持久化与 `IPRULES.PRINT` 输出中，但 MUST NOT 参与 active snapshot、Packet 判决、PKTSTREAM `ruleId/wouldRuleId` 归因、runtime stats 更新或 `IPRULES.PREFLIGHT` 的 active complexity 统计。热路径对 disabled rules SHALL 仅承担“该规则不存在”同等成本。

#### Scenario: Disabled rule does not affect packet or observability
- **GIVEN** `BLOCK=1`
- **AND** `IPRULES=1`
- **AND** 存在一条本可命中该包的规则，但其 `enabled=0`
- **WHEN** NFQUEUE 收到该包
- **THEN** 系统 SHALL 不因该规则改变该包的 verdict
- **AND** PKTSTREAM SHALL NOT 输出该规则的 `ruleId` 或 `wouldRuleId`
- **AND** 该规则的 `stats.hitPackets` 与 `stats.wouldHitPackets` SHALL 保持不变

#### Scenario: Disabled rule is excluded from active preflight complexity
- **GIVEN** 存在一条 `enabled=0` 的 range 规则
- **WHEN** 客户端调用 `IPRULES.PREFLIGHT`
- **THEN** 返回的 active complexity 统计 SHALL NOT 将该规则计入 `rangeRulesTotal` 或相关 bucket 负载

#### Scenario: Disabled rule remains visible in IPRULES.PRINT
- **GIVEN** 已存在一条规则 `R`，并通过 `IPRULES.ENABLE R 0` 将其禁用
- **WHEN** 客户端调用 `IPRULES.PRINT RULE R`
- **THEN** 返回值 SHALL 仍包含该规则
- **AND** 该规则对象 SHALL 体现 `enabled=0`

### Requirement: Per-rule runtime stats are maintained and exposed
系统 MUST 为每条 IP 规则维护并对外暴露 runtime stats（不依赖 PKTSTREAM 是否开启）：
- `hitPackets:uint64` / `hitBytes:uint64` / `lastHitTsNs:uint64`
- `wouldHitPackets:uint64` / `wouldHitBytes:uint64` / `lastWouldHitTsNs:uint64`

系统 MUST 通过控制面 `IPRULES.PRINT` 在 rule 对象中输出上述 `stats` 字段。

约束：
- `hit*` 仅在该规则作为最终 enforce 命中规则时更新（每包最多 1 条规则被计为 hit）。
- `wouldHit*` 仅在该规则作为最终 would-match 规则时更新（每包最多 1 条 would-match）。
- `enabled=0` 的规则 MUST NOT 更新 `hit*`/`wouldHit*`。
- 当规则被 `UPDATE` 改写并生效时，该规则的 `hit*`/`wouldHit*` MUST 清零。
- 当规则从 `enabled=0` 重新切回 `enabled=1` 时，该规则的 `hit*`/`wouldHit*` MUST 清零。
- stats 生命周期为 since boot（重启后归零），不要求持久化。

#### Scenario: Enforce hit updates hitPackets and lastHitTsNs
- **GIVEN** `IPRULES=1` 且存在一条 `enforce=1` 的规则可命中某 IPv4 包（其 `ruleId` 为 R）
- **WHEN** 发送该包
- **THEN** 后续调用 `IPRULES.PRINT RULE R` 时，返回的 `stats.hitPackets` SHALL 大于等于 1
- **AND** `stats.lastHitTsNs` SHALL 大于 0

#### Scenario: Would-match updates wouldHitPackets without dropping
- **GIVEN** `IPRULES=1` 且存在一条 `action=BLOCK,enforce=0,log=1` 的规则可命中某 IPv4 包（其 `ruleId` 为 W）
- **AND** 该包未命中 `IFACE_BLOCK`
- **AND** 该包未命中任何 `enforce=1` 的规则
- **WHEN** 发送该包
- **THEN** 系统 SHALL 返回 ACCEPT
- **AND** 后续调用 `IPRULES.PRINT RULE W` 时，返回的 `stats.wouldHitPackets` SHALL 大于等于 1

#### Scenario: Updating a rule resets its runtime stats
- **GIVEN** 存在一条规则 `R`，且其 `stats.hitPackets` 或 `stats.wouldHitPackets` 已大于 0
- **WHEN** 客户端通过 `IPRULES.UPDATE R ...` 改写该规则内容并使新定义生效
- **THEN** 后续调用 `IPRULES.PRINT RULE R` 时，返回的 `stats.hitPackets` SHALL 为 0
- **AND** 返回的 `stats.wouldHitPackets` SHALL 为 0

#### Scenario: Re-enabling a rule resets its runtime stats
- **GIVEN** 存在一条规则 `R`，其 `enabled=0`，且禁用前 `stats.hitPackets` 或 `stats.wouldHitPackets` 已大于 0
- **WHEN** 客户端通过 `IPRULES.ENABLE R 1` 将其重新启用
- **THEN** 后续调用 `IPRULES.PRINT RULE R` 时，返回的 `stats.hitPackets` SHALL 为 0
- **AND** 返回的 `stats.wouldHitPackets` SHALL 为 0

### Requirement: Engine can be disabled with zero behavioral impact
系统 MUST 提供全局开关 `IPRULES`。当 `IPRULES=0` 时：
- IP 规则引擎 SHALL 不参与 Packet 判决；
- Packet 热路径 SHALL 不执行该引擎的 snapshot load/lookup；
- 对外行为 SHALL 与未配置 IP 规则时一致（仅允许出现 `add-pktstream-observability` 已定义的新字段输出）。

系统 MUST 通过控制面暴露命令 `IPRULES [<0|1>]`：
- `IPRULES` MUST 在无参数时返回 `0|1`。
- `IPRULES <0|1>` MUST 在成功设置时返回 `OK`，且 MUST 仅接受 `0` 或 `1`；其他参数 MUST 返回 `NOK`。
- `IPRULES` 的设置语义 MUST 为幂等：`IPRULES 1→1` / `IPRULES 0→0` MUST NOT 产生除重复确认以外的副作用（例如不得触发 rulesEpoch 变化从而导致热路径 cache 全量失效）。
- `IPRULES` 的默认值 MUST 为 `0`（全新启动/无持久化状态时默认关闭）。

#### Scenario: Disabling IPRULES restores baseline behaviour
- **GIVEN** 配置了可命中某包的 IP 规则
- **WHEN** 将 `IPRULES` 设为 0 并再次发送该包
- **THEN** 系统 SHALL 不再因该 IP 规则而改变该包的 verdict

#### Scenario: IPRULES rejects invalid values
- **WHEN** 客户端调用 `IPRULES 2`
- **THEN** 返回值 SHALL 为 `NOK`

### Requirement: Global BLOCK gates IPRULES and IFACE_BLOCK
系统 MUST 遵循全局开关 `BLOCK`：当 `BLOCK=0` 时，IP 规则引擎与 `IFACE_BLOCK` MUST 不参与该包判决；即使存在可命中该包的 IP 规则或接口拦截条件，系统也 SHALL 返回 ACCEPT。并且该包 MUST NOT 触发 per-rule runtime stats 的更新。

#### Scenario: BLOCK=0 bypasses enforce rules and does not update stats
- **GIVEN** `BLOCK=0`
- **AND** `IPRULES=1`
- **AND** 存在一条可命中某 IPv4 包的 `BLOCK,enforce=1` 规则（其 `ruleId` 为 R）
- **WHEN** 发送该 IPv4 包
- **THEN** 系统 SHALL 返回 ACCEPT
- **AND** 后续调用 `IPRULES.PRINT RULE R` 时，该规则的 `stats.hitPackets` SHALL 不增加
- **AND** 后续调用 `IPRULES.PRINT RULE R` 时，该规则的 `stats.wouldHitPackets` SHALL 不增加

#### Scenario: BLOCK=0 bypasses IFACE_BLOCK hard-drop
- **GIVEN** `BLOCK=0`
- **AND** 某 App/UID 配置了会在 `BLOCK=1` 时触发 `IFACE_BLOCK` 的接口拦截条件
- **WHEN** NFQUEUE 收到该 App/UID 的数据包
- **THEN** 系统 SHALL 返回 ACCEPT

### Requirement: IPRULES.PRINT returns a structured v1 rule list
系统 MUST 将 `IPRULES.PRINT` 的当前 v1 输出固定为顶层 JSON 对象，并包含 key `rules`。即使当前无规则、或过滤后无命中，系统也 MUST 返回 `{"rules":[]}`，而不是 `NOK`。`rules` 数组 MUST 按 `ruleId` 升序输出。`rules` 数组中的每个 rule 对象 MUST 至少包含：`ruleId/uid/action/priority/enabled/enforce/log/dir/iface/ifindex/proto/src/dst/sport/dport/stats`。其中 `stats` 对象 MUST 至少包含 `hitPackets/hitBytes/lastHitTsNs/wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`。`ruleId/uid/priority/stats.*` MUST 使用 JSON number；`ifindex` 也 MUST 使用 JSON number，其中 `0` 表示“不限定精确 ifindex”；`enabled/enforce/log` MUST 使用 `0|1` JSON number，不得输出为 `true|false` 或带引号字符串。`action/dir/iface/proto` MUST 输出规范化 string token；`src/dst` MUST 输出规范化 string token（`any` 或标准 IPv4 CIDR 字符串）；`sport/dport` MUST 输出规范化 string token（`any`、单端口十进制字符串、或 `lo-hi`）。

`IPRULES.PRINT` MUST 支持以下过滤参数（v1）：
- `IPRULES.PRINT`：输出所有规则；
- `IPRULES.PRINT UID <uid>`：仅输出该 `uid` 的规则；
- `IPRULES.PRINT RULE <ruleId>`：仅输出该 `ruleId` 的规则（若不存在则输出空数组）；
- `IPRULES.PRINT UID <uid> RULE <ruleId>`：仅当该规则同时满足两者时输出；否则输出空数组。

#### Scenario: IPRULES.PRINT returns normalized rule objects
- **GIVEN** 已存在至少一条规则
- **WHEN** 客户端调用 `IPRULES.PRINT`
- **THEN** 返回值 SHALL 是合法 JSON 对象
- **AND** 返回值 SHALL 包含 key `rules`
- **AND** `rules[0]` SHALL 至少包含 `ruleId` 与 `stats`

#### Scenario: IPRULES.PRINT returns an empty rules array when nothing matches
- **GIVEN** 当前无规则，或客户端提供的过滤条件未命中任何规则
- **WHEN** 客户端调用 `IPRULES.PRINT`
- **THEN** 返回值 SHALL 是 `{"rules":[]}`

#### Scenario: IPRULES.PRINT orders rules by ascending ruleId
- **GIVEN** 已存在多条规则，且它们的 `ruleId` 不同
- **WHEN** 客户端调用 `IPRULES.PRINT`
- **THEN** 返回值中的 `rules` SHALL 按 `ruleId` 升序排列

#### Scenario: IPRULES.PRINT uses numeric ids and numeric toggle fields
- **GIVEN** 已存在至少一条规则
- **WHEN** 客户端调用 `IPRULES.PRINT`
- **THEN** 返回的 rule 对象中的 `ruleId/uid/priority/ifindex` SHALL 为 JSON number
- **AND** 若该规则未限定精确 `ifindex`，则其 `ifindex` SHALL 为 `0`
- **AND** `enabled/enforce/log` SHALL 为 `0|1` JSON number

#### Scenario: IPRULES.PRINT uses normalized match tokens
- **GIVEN** 已存在至少一条规则
- **WHEN** 客户端调用 `IPRULES.PRINT`
- **THEN** 返回的 rule 对象中的 `action/dir/iface/proto` SHALL 为规范化 string token
- **AND** `src/dst` SHALL 为 `any` 或标准 IPv4 CIDR 字符串
- **AND** `sport/dport` SHALL 为 `any`、单端口十进制字符串、或 `lo-hi`

### Requirement: Rule definitions persist across restart, but runtime stats do not
系统 MUST 持久化 IP 规则定义与 `IPRULES` 全局开关，使其在进程重启后可恢复；但 per-rule runtime stats MUST 保持 since-boot 语义，不得跨重启恢复。`RESETALL` MUST 同时清空该规则持久化状态、内存快照与后续分配使用的 `ruleId` 计数器。

#### Scenario: Restart restores rules but not stats
- **GIVEN** 已配置至少一条 IP 规则，且某条规则的 `stats.hitPackets` 已大于 0
- **WHEN** 进程重启并恢复持久化状态
- **THEN** 该规则定义 SHALL 仍可通过 `IPRULES.PRINT` 查询到
- **AND** 其 `stats.hitPackets` 与 `stats.wouldHitPackets` SHALL 从 0 重新开始

#### Scenario: RESETALL clears persisted rules and active snapshot
- **GIVEN** 已配置至少一条 IP 规则
- **WHEN** 客户端调用 `RESETALL`
- **THEN** 后续 `IPRULES.PRINT` SHALL 返回 `{"rules":[]}`
- **AND** 后续 `IPRULES` SHALL 返回 `0`
- **AND** 后续重启 SHALL 不再恢复这些规则
- **AND** 后续新规则集的第一条新规则 SHALL 从初始 `ruleId = 0` 重新开始分配

### Requirement: IPRULES.PREFLIGHT returns a structured v1 report
系统 MUST 将 `IPRULES.PREFLIGHT` 的当前 v1 输出固定为顶层 JSON 对象，并至少包含 `summary/limits/warnings/violations` 四个 key。其中：
- `summary` MUST 至少包含：`rulesTotal/rangeRulesTotal/subtablesTotal/maxSubtablesPerUid/maxRangeRulesPerBucket`，且这些字段 MUST 为 JSON number
- `limits` MUST 固定为对象 `{ "recommended": {...}, "hard": {...} }`
- `limits.recommended` MUST 至少包含：`maxRulesTotal/maxSubtablesPerUid/maxRangeRulesPerBucket`
- `limits.hard` MUST 至少包含：`maxRulesTotal/maxSubtablesPerUid/maxRangeRulesPerBucket`
- `warnings` 与 `violations` MUST 为数组；空时 MUST 返回 `[]`
- `warnings/violations` 的每个元素 MUST 至少包含：`metric:string`、`value:number`、`limit:number`、`message:string`

#### Scenario: IPRULES.PREFLIGHT exposes fixed summary keys
- **WHEN** 客户端调用 `IPRULES.PREFLIGHT`
- **THEN** 返回值 SHALL 是合法 JSON 对象
- **AND** 返回值 SHALL 包含 `summary/limits/warnings/violations`
- **AND** `summary` SHALL 包含 `rulesTotal` 与 `maxRangeRulesPerBucket`

#### Scenario: IPRULES.PREFLIGHT exposes fixed limits objects
- **WHEN** 客户端调用 `IPRULES.PREFLIGHT`
- **THEN** 返回值中的 `limits` SHALL 包含 `recommended` 与 `hard`
- **AND** `limits.recommended.maxRulesTotal` SHALL 为 JSON number
- **AND** `limits.hard.maxRulesTotal` SHALL 为 JSON number

#### Scenario: IPRULES.PREFLIGHT returns empty warning arrays when clean
- **GIVEN** 当前 active ruleset 未触发任何推荐阈值或硬上限问题
- **WHEN** 客户端调用 `IPRULES.PREFLIGHT`
- **THEN** 返回值中的 `warnings` SHALL 为 `[]`
- **AND** 返回值中的 `violations` SHALL 为 `[]`

#### Scenario: IPRULES.PREFLIGHT warning items use normalized objects
- **GIVEN** 当前 active ruleset 超过推荐阈值但未超过硬上限
- **WHEN** 客户端调用 `IPRULES.PREFLIGHT`
- **THEN** `warnings[0]` SHALL 至少包含 `metric/value/limit/message`

### Requirement: Preflight rejects overly complex rule sets
系统 MUST 在控制面提供 `IPRULES.PREFLIGHT` 输出复杂度统计，并对超过硬上限的规则集拒绝 apply（返回 `NOK`），以保证 NFQUEUE 热路径最坏复杂度可控。

#### Scenario: Too many range rules in a bucket is rejected
- **GIVEN** 规则集合导致某个 bucket 的 `rangeCandidates` 数量超过硬上限
- **WHEN** 客户端尝试 apply/update 该规则集合
- **THEN** 系统 SHALL 拒绝该变更并返回 `NOK`，并在 preflight 报告中指出超限项

### Requirement: IFACES.PRINT exposes ifindex mapping for precise matching
系统 MUST 提供 `IFACES.PRINT` 输出当前网络接口信息，使调用方可在需要时对 `ifindex` 做精确匹配。返回值 MUST 为顶层对象，且包含 `ifaces` 数组；即使当前枚举失败或暂时没有可返回接口，系统也 MUST 返回 `{"ifaces":[]}`，而不是 `NOK`。数组元素至少包含 `ifindex:number`、`name:string`、`kind:string`，并 MAY 包含调试用的 `type:number` 字段。若 `type` 出现，系统 SHALL 将其视为排障增强信息；客户端 MUST NOT 依赖其存在与否来决定正式语义。

#### Scenario: IFACES.PRINT returns a structured interface list
- **WHEN** 客户端调用 `IFACES.PRINT`
- **THEN** 返回值 SHALL 是合法 JSON 对象
- **AND** 返回值 SHALL 包含 key `ifaces`
- **AND** `ifaces` SHALL 为数组

#### Scenario: IFACES.PRINT may return an empty array
- **GIVEN** 当前接口枚举失败，或暂时没有可返回接口
- **WHEN** 客户端调用 `IFACES.PRINT`
- **THEN** 返回值 SHALL 是 `{"ifaces":[]}`

#### Scenario: IFACES.PRINT uses numeric ifindex and optional numeric type
- **GIVEN** `IFACES.PRINT` 返回至少一个接口对象
- **WHEN** 客户端读取该对象
- **THEN** `ifindex` SHALL 为 JSON number
- **AND** 若存在 `type`，则 `type` SHALL 为 JSON number

### Requirement: IPv6 is not affected by new IPv4 rules
本 change 引入的 L3/L4 规则语义仅覆盖 IPv4。IPv6 流量 MUST 不受这些新规则影响（默认放行且不提示规则命中）。

#### Scenario: IPv6 packet is not dropped by IPv4 rules
- **GIVEN** 存在会匹配某 IPv4 流量的 IP 规则
- **WHEN** 发送同 uid 的 IPv6 流量
- **THEN** 系统 SHALL 不因这些 IPv4 规则而改变 IPv6 的 verdict
