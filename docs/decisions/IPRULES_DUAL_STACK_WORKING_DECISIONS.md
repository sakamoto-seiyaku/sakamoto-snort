# IPRULES 双栈规则模型：工作决策与原则

更新时间：2026-04-26
状态：纲领性讨论结论（未实现；后续 OpenSpec/change 以本文为输入）

---

## 0. 目标与范围

本文用于固化 IPRULES 从 IPv4-only 规则引擎升级为 IPv4/IPv6 双栈规则模型时的上位原则。

本文回答：
- IPv6 是否应该提前进入当前后端主线；
- IPv6 在 IPRULES 中是同级规则能力，还是 IPv4 规则模型上的附加特例；
- 后续控制面、matchKey、datapath、conntrack 与观测应遵守什么方向。

本文不回答：
- 具体 OpenSpec change 的任务拆分；
- 具体类图、函数签名、测试脚本实现；
- `ip-leak`、device-wide/global IP rules、L7/DPI 等其它后置议题。

---

## 1. 为什么现在提前 IPv6

当前 roadmap 中 IPv6 新规则语义仍在 backlog，而 IPRULES v1 已经落地为 IPv4 L3/L4 + per-rule stats + userspace conntrack。

如果继续把 IPv6 放到文档收尾之后，后续前端、配置生成器、vNext 契约和测试口径很可能先围绕 IPv4-only 模型固化。等发布前或发布后再补 IPv6，就会迫使系统把 IPv6 当成额外兼容层处理，导致：
- 规则对象语义不纯；
- `src/dst=any` 等字段出现隐式 family 歧义；
- `matchKey`、冲突检测、stats 和 packet stream join 需要二次返工；
- 前端心智变成“IPv4 是主模型，IPv6 是例外”。

因此，IPv6 提前不是为了补齐一个协议字段，而是为了在正式发布前把 IPRULES 的规则模型升级为真正的 IP 双栈模型。

---

## 2. 上位原则

1. **IPv4 与 IPv6 必须同级**
   - IPRULES 后续应表达“IP 规则”，而不是“IPv4 规则 + IPv6 特例”。
   - 控制面、打印、冲突检测、stats 与观测归因都必须能自然表达两种 family。

2. **规则模型优先于最小改动**
   - 不为了减少代码改动而用隐式推断、默认值或特殊分支掩盖模型问题。
   - 如果接口层需要修正，应在正式发布前修正，而不是保留一个会长期污染心智的兼容形态。

3. **family 是一等语义字段**
   - 每条规则必须显式声明 `family`。
   - `family` 不从 `src/dst` 推断。
   - `family` 不允许省略。

4. **热路径仍遵守既有 IPRULES 原则**
   - `IPRULES=0` 必须继续 zero-cost disable。
   - 热路径不得新增锁、重 IO 或每包动态分配。
   - 控制面继续通过编译后快照原子发布，热路径只能看到旧或新完整版本。

5. **观测通路不新增**
   - 继续复用 vNext packet stream、reason metrics、per-rule stats 和现有 metrics 查询。
   - 不为 IPv6 单独新增另一套事件或统计通道。

6. **外部模型统一，内部允许按 family 优化**
   - 对外必须是同一个 IPRULES 规则模型；不得暴露成 IPv4 主模型 + IPv6 特例。
   - 对内可以使用 family-discriminated key / compiled view / cache，避免 IPv4 热路径被迫改成通用 128-bit 慢路径。

---

## 3. 已决定的规则模型

后续 IPRULES 规则对象必须包含：
- `family`: `"ipv4" | "ipv6"`
- `uid`
- `action`: `"allow" | "block"`
- `priority`
- `enabled/enforce/log`
- `dir`
- `iface`
- `ifindex`
- `proto`
- `ct.state/ct.direction`
- `src/dst`
- `sport/dport`
- `clientRuleId`

其中：
- `family="ipv4"` 时，`src/dst` 为 `any` 或 IPv4 CIDR（`/0..32`）。
- `family="ipv6"` 时，`src/dst` 为 `any` 或 IPv6 CIDR（`/0..128`）。
- `src/dst=any` 的含义由显式 `family` 限定，不存在跨 family 的隐式 any。
- `proto` 的公开 token 为 `any|tcp|udp|icmp|other`。
- `proto="icmp"` 保持用户语义 token；在 IPv4 下对应 ICMP，在 IPv6 下对应 ICMPv6。
- `proto="other"` 表示同一 family 下合法结束、但不是 TCP/UDP/ICMP-family 的 terminal protocol。
- IPv4 下，`proto="other"` 对应 IP protocol 字段中非 TCP/UDP/ICMP 的合法 terminal。
- IPv6 下，`proto="other"` 对应合法 IPv6 header chain 结束后的非 TCP/UDP/ICMPv6 terminal，例如 ESP、No Next Header 或未知但合法的 terminal protocol。
- 异常、截断、长度非法或预算耗尽导致的 L4 不可获得，不属于 `proto="other"`。
- `sport/dport` 仍只对 TCP/UDP 有意义；`icmp/other` 规则必须保持端口为 `any`。
- `proto=any` 携带端口约束时，只可能匹配 TCP/UDP 包；不得让 ICMP/ICMPv6/other 因端口约束误命中。
- IPv6 CIDR 输入必须经解析、prefix mask 后再规范化输出；`PRINT` 与 `matchKey` 使用稳定的 `inet_ntop` 输出形态。
- IPv6 CIDR 不接受 `%zone` / scope 后缀；link-local 作用域由 `ifindex/iface` 表达，避免地址字段与接口字段产生双重语义。
- IPv4-mapped IPv6 地址（例如 `::ffff:192.0.2.1/128`）在 `family=ipv6` 下仍按 IPv6 地址处理，不映射成 IPv4 规则。
- `clientRuleId` 继续唯一标识一条后端 rule；如果上层要表达同一个 UI 概念规则的 IPv4 + IPv6 覆盖，必须生成两条不同 `clientRuleId` 的后端 rules。

明确不采用：
- 不用 `family=any` 表示双栈规则；需要双栈覆盖时由上层生成两条规则。
- 不从 `src/dst` CIDR 字符串推断 family。
- 不让省略 `family` 默认成 IPv4。
- 不允许同一 UID 下用同一个 `clientRuleId` 隐式表示跨 family 的 sibling rules。

---

## 4. 控制面与协议口径

vNext 命令名保持不变：
- `IPRULES.PREFLIGHT`
- `IPRULES.PRINT`
- `IPRULES.APPLY`

协议版本口径：
- 当前尚未正式发布，因此后续可直接修正 vNext `protocolVersion=1` 下的 IPRULES schema。
- 不为了兼容旧 no-family 请求保留隐式默认。
- 旧的 no-family `IPRULES.APPLY` 请求在新 schema 下应被视为非法请求。

`IPRULES.APPLY`：
- 每条 rule item 必须包含 `family`。
- 禁止客户端提交 `ruleId/matchKey/stats` 的既有约束不变。
- `clientRuleId` 继续作为前端稳定身份，但身份粒度是单条后端 rule；同一 UID 的 apply payload 内仍必须唯一。
- `IPRULES.APPLY` 继续是整 UID replace：一次 apply 替换该 UID 下全部 IPv4/IPv6 rules，不提供按 family 局部替换。
- `rules: []` 表示清空该 UID 下全部 IPv4/IPv6 rules。
- apply 成功响应继续保持最小映射 `{clientRuleId, ruleId, matchKey}`，不额外新增 `family`；`family` 已由请求 rule 与 `mk2` 表达。
- apply 成功响应中的 `result.rules[]` 按 `ruleId` 升序输出，不按 family 分组。
- 同一 `clientRuleId` 在新旧 ruleset 中复用时继续复用原 `ruleId`；如果 `family` 发生变化，视为规则定义变化并 reset stats。

`IPRULES.PRINT`：
- 每条 rule 必须回显 `family`。
- `src/dst` 必须按对应 family 规范化输出。
- `stats` 字段继续按 rule 输出，不因 family 拆成两套统计对象。
- 不新增 `family` filter；`IPRULES.PRINT` 按 app selector 返回该 UID 下全部 IPv4/IPv6 rules，由每条 rule 的 `family` 字段表达归属。
- `IPRULES.PRINT` 的 `result.rules[]` 继续按 `ruleId` 升序输出，不按 family 分组。

`IPRULES.PREFLIGHT`：
- `IPRULES.PREFLIGHT` 继续只接受空 args，报告当前 active ruleset；拟下发 payload 的 preflight 由 `IPRULES.APPLY` 内部完成。
- 继续保留现有总量 summary，用于判断整份规则集是否可 apply。
- 新增 `byFamily.ipv4/ipv6` 分项，用于解释复杂度压力来自哪一类规则。
- `byFamily.ipv4/ipv6` 总是同时输出，并完整 mirror 当前 `summary` 的字段集合；即使某 family 为 0，也输出完整 0 值对象。
- `byFamily.<family>.*` 的各字段统计口径必须按该 family 的 `enabled=1` active rules / compiled views 计算；不得用 raw rule 数、raw rule 字段叠加或其它近似替代。
- `summary` 与 `byFamily` 都只统计 `enabled=1` 的 active rules / compiled views；disabled rules 不计入热路径复杂度或 limits。
- `summary` 是跨 family 的权威总口径；`byFamily` 是解释来源，不要求所有字段都能简单相加。例如 `ctUidsTotal` 这类去重字段可以出现 `summary.ctUidsTotal != byFamily.ipv4.ctUidsTotal + byFamily.ipv6.ctUidsTotal`。
- `rulesTotal/rangeRulesTotal/ctRulesTotal/subtablesTotal` 的总口径按 active rules / compiled views 跨 family 汇总。
- `byFamily.<family>.ctUidsTotal`：该 family 下存在非平凡 `ct.*` consumer 的 distinct UID 数（`ct.state=any` 且 `ct.direction=any` 不构成 CT consumer）。
- `ctUidsTotal` 的总口径按 UID 去重；同一 UID 同时拥有 IPv4 与 IPv6 `ct.*` consumer 时，总数仍只计 1。
- `maxSubtablesPerUid/maxRangeRulesPerBucket` 的总口径取所有 family hot view 的最大值，不把两个 family 的 max 相加。
- hard/recommended limits 继续按 `summary` 总口径判断；`byFamily` 只用于解释压力来源。
- summary warning / violation 是 apply gating 的权威；family-specific warning / violation 只在需要解释来源时输出，不要求每个 summary issue 都重复 family issue。
- family-specific warning / violation 不新增 issue 字段；继续使用现有 `{metric,value,limit,message}` 结构，并通过 metric 路径表达来源，例如 `byFamily.ipv6.maxSubtablesPerUid`。

规则合法性：
- `proto=other` 与 `proto=icmp` 一样要求 `sport/dport=any`，避免端口维度形成永不匹配的假语义。
- `proto=other` 允许搭配 `ct.state=new/established`，使用 Conntrack other pseudo-state。
- `ct.state=invalid` 必须搭配 `ct.direction=any`；`ct.state=invalid` 与 `ct.direction=orig|reply` 的组合应被拒绝。

`matchKey`：
- 后续应从 `mk1` 升级为 `mk2`。
- `mk2` 必须包含 `family`，并且 `family` 是冲突检测的一部分。
- `mk2` 只表达匹配维度，不包含 `uid`、`clientRuleId`、`ruleId`、`action`、`priority` 或 stats。
- `mk2` 冲突检测覆盖同一 UID apply payload 内所有 rules，包括 `enabled=0` 的规则；不因 disabled 状态放宽唯一性。
- `mk2` 冲突错误保持现有最小 shape，不在 `conflicts[].rules[]` 额外回显 `family`；冲突来源由 `conflicts[].matchKey=mk2|family=...` 表达。
- `mk2` 字段顺序固定为：

```text
mk2|family=<ipv4|ipv6>|dir=<...>|iface=<...>|ifindex=<...>|proto=<...>|ctstate=<...>|ctdir=<...>|src=<...>|dst=<...>|sport=<...>|dport=<...>
```

- 示例形态：

```text
mk2|family=ipv6|dir=out|iface=any|ifindex=0|proto=tcp|ctstate=any|ctdir=any|src=any|dst=2001:db8::/32|sport=any|dport=443
```

持久化：
- 当前无正式发布版本、无已编码前端，因此不把旧开发期 save 兼容作为设计约束。
- 后续实现可以直接升级 IPRULES save format，使落盘结构与含 `family` 的双栈规则模型一致。
- 双栈 save format 中 rules 写入顺序按 `ruleId` 升序，便于确定性落盘与排障。
- 双栈 save format 必须 bump 到 `formatVersion=4`（当前实现为 `3`）；restore 只接受当前显式包含 `family` 的双栈格式（v4）。
- 任意不符合当前双栈格式的 IPRULES save 都视为 IPRULES restore failure；不区分旧版本、未知版本或损坏文件。
- IPRULES restore failure 不是 daemon 致命错误：daemon 继续启动，IPRULES 为空规则集，热路径发布空 snapshot。
- 后续 `IPRULES.APPLY` 成功后按当前双栈格式重新写入；不做旧格式识别、迁移、默认 IPv4、立即清理或部分恢复。
- IPRULES restore failure 必须写 warning/error log 便于排障；不新增 `HELLO`、`INVENTORY`、`IPRULES.PRINT` 等控制面字段暴露该状态。

---

## 5. datapath / conntrack / observability 口径

datapath：
- IPv4 与 IPv6 都应进入 IPRULES 判决层。
- `IFACE_BLOCK` 继续是高于 IPRULES 的 hard-drop。
- IPRULES 未命中时继续回到后续 legacy/domain 路径。
- datapath parser 应产出统一的栈上解析结果，至少包含 `family`、`src/dst`、terminal 或 declared `proto`、端口可用性、fragment 标志与 `l4Status`。
- IPv6 不能只解析 40 字节 base header；目标设计必须解析可跳过的 extension header，找到 terminal TCP/UDP/ICMPv6/other。
- IPv6 header walker 的发布级预算固定为最多 8 个 extension headers / 256 bytes；超过预算时给出稳定的“不可获得 L4”结果，不得越界读或猜测端口。
- IPv6 header walker 跳过 Hop-by-Hop、Destination Options、Routing、AH；Fragment 单独分类；ESP、No Next Header 与未知协议作为合法 `other-terminal`。
- IPv6 Routing Header 只作为可跳过 extension header；规则 `src/dst` 与 Conntrack key 均使用外层 IPv6 header 的 `src/dst`。
- 不解析 Routing Header 内部地址作为策略身份，也不因 Routing Header 存在直接判为 invalid。
- IPv4/IPv6 fragments 统一不做 reassembly。
- fragment 可按 `family/src/dst/dir/iface/proto` 参与规则判决；IPv4 使用 IP protocol 字段，IPv6 使用 Fragment header 中可安全取得的 declared next-header。
- fragment 带端口约束的规则不得匹配；即使首片中实际携带 L4 header，也不为端口或 conntrack 开特殊通道。
- fragment 的 `ct.state` 固定视为 `invalid`、`ct.direction` 固定视为 `any`，不创建也不更新 conntrack entry。
- IPRULES datapath 应把包解析结果统一归为四类：
  - `known-l4`：IPv4 为 TCP/UDP/ICMP 且必要头部可安全解析；IPv6 为 header walker 找到 TCP/UDP/ICMPv6 且必要头部可安全解析。
  - `other-terminal`：合法但非 TCP/UDP/ICMP-family 的 terminal protocol；这类才匹配 `proto=other`。
  - `fragment`：不做 reassembly；端口不可用；`ct.state` 视为 `invalid`。
  - `invalid-or-unavailable-l4`：L3 envelope 可用，但 declared L4 或 IPv6 header chain 无法安全得到可用 L4。
- IPv4 下，合法 IP header + 非 TCP/UDP/ICMP protocol 是 `other-terminal`；declared TCP/UDP/ICMP 但头部过短、TCP doff 异常或长度不一致是 `invalid-or-unavailable-l4`。
- IPv6 下，ESP、No Next Header、未知合法 terminal protocol 是 `other-terminal`；header chain 长度异常、无法安全继续或 walker 预算耗尽是 `invalid-or-unavailable-l4`。
- `invalid-or-unavailable-l4` 仍进入 IPRULES 判决：端口不可用，不匹配普通 `proto=other`，但可由 `ct.state=invalid` 规则接管。
- 对 declared L4 头部过短、TCP `doff` 异常或长度不一致等 `invalid-or-unavailable-l4` 情形，listener 层不得直接 `NF_DROP`；必须以“可判决输入”继续流经 IPRULES/后续路径，并按本文口径产出端口不可用与 `ct=invalid/any` 结果。
- `invalid-or-unavailable-l4` 若能安全获得 declared / terminal proto，则规则层 `proto=tcp|udp|icmp` 可按该 proto 匹配。
- `proto=any` 匹配所有 L3 key 可构造的 `invalid-or-unavailable-l4` 包。
- `proto=other` 只匹配合法 `other-terminal`，不得匹配 `invalid-or-unavailable-l4`。
- 对 `invalid-or-unavailable-l4`，端口一律视为不可用；带 `sport/dport` 约束的规则不得匹配；如实际执行 CT 维度匹配，其结果固定为 `invalid/any`。
- `invalid-or-unavailable-l4` 不创建、不更新 conntrack entry。
- 如果连 L3 envelope 都无法安全解析到构造 IPRULES key 所需的 family/src/dst，则不属于规则层 invalid 接管范围，listener 层保持 fail-open 策略。
- IPRULES 内部应按 family 编译 hot view/key/cache；外部 schema 统一，内部保留 IPv4 轻路径并新增 IPv6 view/key。

conntrack：
- IPv6 必须与 IPv4 同级支持 `ct.state/ct.direction`。
- 不接受“IPv6 先 stateless，IPv4 才有 conntrack”的发布级半成品模型。
- 后续实现可以复用现有 userspace conntrack 语义母本，但 key/address 表示必须支持 IPv6。
- Conntrack 对外输入模型保持统一，对内按 family 分表，避免 IPv4 CT 热路径被迫使用 128-bit 地址 key。
- `maxEntries` 保持全局共享上限，两张 family 表共享同一个总 entry 预算，不设置 per-family 配额或公平性策略。
- timeout policy 与状态机按 L4 语义共用，不按 family 分叉。
- Conntrack hot-path gating 应从当前 UID 粒度升级为 `uid+family` 粒度。
- 只有当前 packet family 的 active rules 存在非平凡 `ct.*` consumer 时，才执行对应 family 的 conntrack；另一 family 不应因此承担额外 CT 成本。
- `ct.state=any` 且 `ct.direction=any` 不构成 CT consumer。
- 实现上可以在 rules epoch 下缓存每个 UID 的 family CT consumer bitmask，避免热路径重复扫描规则。
- ICMPv6 conntrack 对齐当前 IPv4 ICMP 能力层级：只支持 Echo Request / Echo Reply pseudo-state，type `128/129`、code `0`。
- ND/RA/RS、MLD、ICMPv6 error 等不借本轮双栈改造扩展 related 语义，也不创建 conntrack entry；如后续需要，应另行作为 L4 conntrack 增强讨论。
- `proto=other` 使用现有 other pseudo-state 心智：按 first/multiple/bidir 压缩为 `new/established`，无法建立可靠状态时为 `invalid`。
- IPv6 的 ESP、No Next Header、未知但合法 terminal protocol 都进入同一套 `other` pseudo-state；key 使用 `uid + family + proto + src/dst`，不含端口。
- Conntrack 输入模型必须区分 family 或按 family 分表，避免 IPv4 地址与 IPv4-mapped IPv6 地址产生同一 flow 身份。
- IPv6 传入 Conntrack 的 L4 payload length 必须从 terminal L4 header 开始计算，不得使用 IPv6 base header 后的原始 payload 长度。
- preview / commit 语义沿用现有设计：策略前可 inspect，只有最终 accepted 的 `new/orig` miss 才 commit 创建 entry。

observability：
- vNext packet stream 继续使用 `ipVersion`、`srcIp`、`dstIp`、`reasonId`、`ruleId/wouldRuleId` 表达包事件。
- vNext packet stream 新增 `l4Status`，取值为 `known-l4|other-terminal|fragment|invalid-or-unavailable-l4`。
- `type="pkt"` 逐包事件必须 always-present 输出 `l4Status`；`notice="suppressed"|"dropped"|"started"` 不新增 `l4Status`。
- `l4Status` 是 packet parser 结果，不只属于 IPRULES 命中；只要构造 `type="pkt"` 事件，即使 `IPRULES=0` 或未命中 IPRULES，也必须输出。
- `l4Status` 只暴露稳定状态枚举，不暴露 parser 内部 reasonCode。
- packet stream 的 `protocol` 不新增 `invalid/unavailable` token；能识别 declared/terminal 为 TCP/UDP/ICMP-family 时填对应 token，否则填 `other`。
- `protocol=other` 不再单独表示“合法 other”，前端必须结合 `l4Status=other-terminal` 判断合法 other terminal。
- 端口不可用时，packet stream 的 `srcPort/dstPort` 仍保持 always-present number，并输出 `0`；由 `l4Status` 解释这是端口不可用，而不是端口 0 规则命中。
- `ct{state,direction}` 继续为可选字段，只在该包因当前 UID+family 存在 active CT consumer 而实际执行 CT inspect 时输出；不要求最终 winner rule 自身带 `ct.*`。
- fragment / invalid / unavailable 在执行 CT inspect 时输出 `ct.state=invalid`、`ct.direction=any`。
- `METRICS.GET(name=conntrack)` 继续保留现有总字段 `totalEntries/creates/expiredRetires/overflowDrops`。
- `METRICS.GET(name=conntrack)` 新增 `byFamily.ipv4/ipv6`，每个 family 分项完整包含 `totalEntries/creates/expiredRetires/overflowDrops`。
- Conntrack overflow 按当前创建失败包的 family 归因到 `byFamily.<family>.overflowDrops`，同时增加总 `overflowDrops`。
- `totalEntries` 语义上是 IPv4 + IPv6 entries 总数；conntrack metrics 是 best-effort snapshot，并发更新时不承诺总字段与 `byFamily` 逐字段强一致。
- `conntrack` 仍不提供独立 reset；`METRICS.RESET(name=conntrack)` 保持拒绝，只有 `RESETALL` 清空 conntrack table 与 counters。
- `IP_RULE_ALLOW` / `IP_RULE_BLOCK` reasonId 不按 family 分裂。
- 除 `METRICS.GET(name=conntrack).byFamily` 与 `IPRULES.PREFLIGHT.byFamily` 外，不为 reasons / traffic metrics 增加 family 维度。
- 前端仍通过 `ruleId -> clientRuleId` join 解释规则来源。
- per-rule stats 继续归属于具体 rule；family 是 rule 的字段，不是 stats 的外层维度。

---

## 6. 明确不做

本纲领不把以下内容纳入本轮 IPv6 双栈规则模型：
- legacy 控制面扩展；
- `family=any`；
- no-family 请求的 IPv4 默认兼容；
- 旧开发期 IPRULES save 文件的兼容迁移或隐式清理策略；
- device-wide/global IP rules；
- `ip-leak` 与 IPRULES 的合流策略；
- L7 / HTTP / HTTPS 被动识别；
- 把 IPv6 作为只支持 stateless L3/L4 的临时能力交付。

---

## 7. 后续 OpenSpec / 文档 / 验收入口

后续 IPv6 支持应由一个总 OpenSpec change 承接，change 名称固定为 `add-iprules-dual-stack-ipv6`，避免出现“控制面已双栈、datapath/conntrack/observability 尚未双栈”的半成品规格状态。

该 change 的 tasks 内部可以分阶段，但必须覆盖同一条交付线：
- vNext IPRULES schema：`family`、IPv6 CIDR、`proto=other`、`mk2`、`PREFLIGHT.byFamily`；
- IPRULES engine：按 family 编译 hot view/key/cache，保留 IPv4 轻路径；
- datapath parser：统一栈上解析结果、IPv6 header walker、fragment / invalid / `l4Status`；
- Conntrack：IPv6 支持、按 family 分表、全局共享 `maxEntries`、`byFamily` metrics；
- observability：packet stream `l4Status`、conntrack metrics、per-rule stats 与 reasonId 口径；
- tests/docs：host 单测、真机 Tier-1、active docs/specs/roadmap 同步。

旧文档同步边界：
- active OpenSpec specs、roadmap 与当前会被引用的设计文档必须更新为双栈口径；
- `archive/` 下的历史 change 记录不重写，避免破坏归档语境。

默认验收边界：
- host 单测必须覆盖 schema/canonicalization、IPv4 回归、IPv6 CIDR、`mk2`、parser/walker、fragment/invalid、conntrack key/state、metrics shape、restore failure；
- 真机 Tier-1 必须覆盖 IPv4 回归、IPv6 allow/block、IPv6 `ct.state/ct.direction`、fragment/invalid 或 `l4Status` 可观测性、`PREFLIGHT.byFamily` 与 `METRICS.GET(name=conntrack).byFamily`；
- perf longrun / overnight matrix 不作为该 change 的默认必过项；若发现热路径回归风险，应另行记录并补 perf 验证。
