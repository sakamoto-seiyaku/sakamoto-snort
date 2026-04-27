## MODIFIED Requirements

### Requirement: Per-app IPv4 L3/L4 rules exist and are deterministic
系统 MUST 提供按 App(UID) 的 IP（IPv4/IPv6）L3/L4 规则能力，并将 IPv4 与 IPv6 视为同级规则模型。规则匹配维度至少包含：
- `uid`
- `family`（`ipv4|ipv6`；规则与数据包 family 必须一致才可能匹配）
- `direction`（in/out/any）
- `ifaceKind`（wifi/data/vpn/unmanaged/any）与可选 `ifindex` 精确匹配
- `proto`（tcp/udp/icmp/other/any）
- `src CIDR` 与 `dst CIDR`
  - 当 `family=ipv4`：CIDR 为 IPv4（`/0..32`）
  - 当 `family=ipv6`：CIDR 为 IPv6（`/0..128`）
- `srcPort` 与 `dstPort`（any / 精确 / range；仅在端口可用时生效，见相关 requirement）

系统 MUST 将 `src/dst` 与 `srcPort/dstPort` 解释为数据包 L3/L4 头部字段（IPv4/IPv6 `saddr/daddr`、TCP/UDP `source/dest`）。`direction=in|out` 仅表示包来自 `INPUT/OUTPUT` 链（入站/出站），不改变上述字段含义。

命中语义 MUST 全局确定：同一数据包在同一时刻命中多条规则时，系统 SHALL 先以 `priority` 为主键选取最高优先级候选；若同优先级仍有多条重叠命中，则 SHALL 由编译后的 classifier 稳定查询路径选出唯一命中规则。对同一份 active ruleset，重复编译后对同一包的唯一命中结果 MUST 保持一致。

#### Scenario: Highest priority rule wins
- **GIVEN** 针对同一 `uid` 与同一 `family` 存在两条均可命中的规则，且它们 `priority` 不同
- **WHEN** NFQUEUE 收到该 `uid` 的该 `family` 数据包（IPv4 或 IPv6）
- **THEN** 系统 SHALL 选择 `priority` 更高的规则作为唯一命中，并输出对应的 `ruleId`

#### Scenario: Same-priority overlap uses deterministic compiled winner
- **GIVEN** 针对同一 `uid` 与同一 `family` 存在两条 `priority` 相同且均可命中的规则
- **WHEN** 系统以同一份 active ruleset 对该规则集重复编译并处理同一 `family` 数据包（IPv4 或 IPv6）
- **THEN** 系统 SHALL 在两次处理中选出同一条唯一命中规则

### Requirement: Port predicates only apply to TCP/UDP packets
系统 MUST 将 `sport/dport` 解释为 TCP/UDP 的 L4 头部字段，并且仅当端口可用时才允许端口谓词参与匹配。对于满足任一条件的数据包：
- `proto` 不是 `tcp` 也不是 `udp`（例如 `icmp`/`other`）
- 或该包的 L4 端口不可用（例如 fragment，或 L4 头部长度/字段异常导致无法安全解析端口）

规则仅当 `sport=any` 且 `dport=any` 时才允许因端口维度通过匹配；若规则包含任一非 `any` 的端口约束，则该规则 MUST NOT 匹配该数据包（即使该规则的 `proto=any`，或该包 declared proto 为 TCP/UDP 但端口不可得）。

#### Scenario: ICMP does not match proto=any rule with port constraint
- **GIVEN** `BLOCK=1` 且 `IPRULES=1`
- **AND** 存在一条规则 `R`，其 `proto=any` 且 `dport=53`（其余字段均为 any，且该规则 `enforce=1`）
- **WHEN** NFQUEUE 收到一个 `proto=icmp` 的 IP 数据包（IPv4 ICMP 或 IPv6 ICMPv6）
- **THEN** vNext packet stream SHALL NOT 包含来自该规则的 `ruleId`
- **AND** 若该事件包含 `reasonId`，则其 SHALL NOT 为 `IP_RULE_ALLOW` 或 `IP_RULE_BLOCK`

### Requirement: IPv6 is not affected by new IPv4 rules
系统 MUST 将 `family` 作为一等语义字段：`family=ipv4` 的规则 MUST NOT 匹配 IPv6 数据包，`family=ipv6` 的规则 MUST NOT 匹配 IPv4 数据包。IPv6 流量不再被 IPRULES 绕过；当 `IPRULES=1` 且存在匹配的 `family=ipv6` 规则时，系统 MUST 允许其像 IPv4 一样参与判决与归因。

#### Scenario: IPv6 packet is not dropped by IPv4 rules
- **GIVEN** 存在一条 `family=ipv4` 的规则 `R4`，其会匹配某 IPv4 流量并执行 `BLOCK`
- **WHEN** 发送同 `uid` 的 IPv6 流量
- **THEN** 系统 SHALL 不因该 `family=ipv4` 规则而改变该 IPv6 包的 verdict

## ADDED Requirements

### Requirement: `proto=other` matches only legal terminal other-protocol packets
系统 MUST 支持规则 `proto=other`，用于匹配“合法 terminal 且不属于 TCP/UDP/ICMP-family”的数据包：
- IPv4：IP protocol 字段为非 TCP/UDP/ICMP 的合法 terminal protocol 时视为 `other-terminal`。
- IPv6：ext header walker 找到的 terminal protocol 既不是 TCP/UDP/ICMPv6，且该 header chain 合法结束时视为 `other-terminal`（例如 ESP、No Next Header、未知但合法的 terminal protocol）。

系统 MUST NOT 将“无法安全获得 L4/terminal protocol”的情形归类为 `other-terminal`，且 `proto=other` MUST NOT 匹配这类包（例如 IPv6 header chain 预算耗尽、长度异常、TCP/UDP 头部过短或 TCP doff 异常导致的端口不可获得）。

#### Scenario: invalid-or-unavailable L4 does not match proto=other rule
- **GIVEN** `BLOCK=1` 且 `IPRULES=1`
- **AND** 存在一条规则 `R`：`proto=other action=block enforce=1`（其余字段为 any）
- **WHEN** NFQUEUE 收到一个 declared proto 非 TCP/UDP/ICMP-family 且无法安全确认其为 legal terminal 的数据包
- **THEN** 系统 SHALL NOT 命中规则 `R`

#### Scenario: Legal terminal other-protocol can match proto=other rule
- **GIVEN** `BLOCK=1` 且 `IPRULES=1`
- **AND** 存在一条规则 `R`：`family=ipv6 proto=other action=block enforce=1`（其余字段为 any）
- **WHEN** NFQUEUE 收到一个 IPv6 数据包，其 ext header chain 合法结束且 terminal protocol 为 ESP（或 No Next Header）
- **THEN** 系统 SHALL 命中规则 `R` 并返回 DROP
