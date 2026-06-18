## MODIFIED Requirements

### Requirement: Current v1 control surface is uid-only and rejects unsupported match dimensions
系统 MUST 将规则控制面限定为数值 `uid` 选择器；包名字符串 selector MUST NOT 作为输入语义。系统 MUST 要求 `IPRULES.ADD` 创建规则时 `priority` 显式提供；缺失 `priority` 的创建请求 MUST 返回 `NOK`。对于 `enabled/enforce/log`，系统 MUST 将其缺省值固定为 `1/1/0`（仅适用于 `IPRULES.ADD` 创建时省略字段）。系统 MUST 将 `IPRULES.UPDATE` 定义为 patch/merge：仅更新请求中提供的 key；未提供的 key（包含 `priority`）MUST 保持原值（不得回落到缺省值）。系统 MUST 将 `enforce=0` 限定为 `action=BLOCK, log=1` 的 would-block safety-mode；其它 `enforce=0` 组合（例如 `action=ALLOW, enforce=0` 或 `enforce=0, log=0`）MUST 返回 `NOK`。

系统 MUST 接受本 spec 定义的最小 conntrack 匹配维度（`ct.state/ct.direction`），并拒绝其它未纳入语义的控制面字段，避免出现“看起来已配置、实际上不生效”的假语义。系统 MUST NOT 将 `NFQA_CT`、内核 conntrack 元数据或用户态自研 full flow tracking 作为匹配语义成立的前提；相反，系统 SHALL 使用本项目内的 userspace conntrack core 提供 `ct` 视角。

控制面 MUST 为“输入合法性”保持严格与原子性：
- 对 `IPRULES.ADD/UPDATE/REMOVE/ENABLE`，若输入包含未知 key、无法解析的值、或违反本 spec 的组合约束，则系统 MUST 返回 `NOK`。
- 对上述返回 `NOK` 的请求，系统 MUST NOT 改变当前规则集（含 active snapshot 与持久化内容），且 `IPRULES.ADD` MUST NOT 消耗新的 `ruleId`。

#### Scenario: Unsupported ct field value is rejected
- **GIVEN** 客户端尝试创建或更新规则，并传入 `ct=...` 但值无法解析
- **WHEN** 控制面校验该规则
- **THEN** 系统 SHALL 返回 `NOK`

#### Scenario: System conntrack metadata is not required
- **GIVEN** 当前环境未向 NFQUEUE 暴露 `NFQA_CT` 或其他 conntrack 元数据
- **AND** 已配置一条依赖 `ct.*` 维度的规则
- **WHEN** NFQUEUE 收到可命中该规则的 IPv4 数据包
- **THEN** 系统 SHALL 仍能通过 userspace conntrack core 完成 `ct.*` 语义并做出一致判决

## ADDED Requirements

### Requirement: Rules MAY match on minimal conntrack dimensions
系统 MUST 支持在规则中声明最小 conntrack 匹配维度：
- `ct.state`：`any|new|established|invalid`
- `ct.direction`：`any|orig|reply`

其中：
- `ct.state/ct.direction` 的计算与含义以 userspace conntrack core 为准；
- `ct.direction` 与现有 `dir=in|out` 不同：前者描述 flow 内 orig/reply，后者描述 netfilter 链方向（INPUT/OUTPUT）。

并且（语义口径钉死为 OVS 等价，只是把 OVS bitset 压缩成最小枚举）：
- `ct.direction=reply` MUST 等价于 OVS `ct_state=+rpl`
- `ct.direction=orig` MUST 等价于 OVS `ct_state=-rpl`（在本项目里，conntrack 被应用到该包时即视为 tracked）
- `ct.state=new` MUST 等价于 OVS `ct_state=+new`
- `ct.state=established` MUST 等价于 OVS `ct_state=+est` 或 `ct_state=+rel`（本项目把 OVS 的 `rel` 折叠进 `established`）
- `ct.state=invalid` MUST 等价于 OVS `ct_state=+inv`（以及其它 OVS 判为 invalid 的情形，例如解析失败/不满足协议状态要求）

#### Scenario: Established reply packets can be matched via ct.*
- **GIVEN** `BLOCK=1` 且 `IPRULES=1`
- **AND** 已存在一条规则 `R`：`action=allow enforce=1 priority=10 ct.state=established ct.direction=reply`（其它字段为 any）
- **WHEN** NFQUEUE 收到一个属于已建立连接的 reply-direction IPv4 数据包
- **THEN** 系统 SHALL 命中规则 `R` 并返回 ACCEPT

#### Scenario: New inbound packets can be blocked via ct.*
- **GIVEN** `BLOCK=1` 且 `IPRULES=1`
- **AND** 已存在一条规则 `R`：`action=block enforce=1 priority=10 dir=in ct.state=new`（其它字段为 any）
- **WHEN** NFQUEUE 收到一个新连接的入站 IPv4 数据包
- **THEN** 系统 SHALL 命中规则 `R` 并返回 DROP
