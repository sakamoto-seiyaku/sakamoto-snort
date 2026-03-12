## 1. OpenSpec docs (this change)
- [ ] 1.1 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（本目录下 `specs/`）
- [ ] 1.2 `openspec validate add-app-ip-l3l4-rules-engine --strict` 通过

## 2. Implementation gate (ordering)
- [ ] 2.1 本 change 的代码实现以前，先确认 A 层基座（`add-pktstream-observability`）的字段/契约已可用或已同步落地：`reasonId/ruleId/wouldRuleId/wouldDrop/ipVersion/srcIp/dstIp` + `METRICS.REASONS`
- [ ] 2.2 本 change 的实现顺序按 `docs/IMPLEMENTATION_ROADMAP.md` 执行：先 `IP rules core`，再 `C`（per-rule runtime stats），不要让 B 层 DomainPolicy counters 阻塞本 change 主线

## 3. Control surface & rule model
- [ ] 3.1 新增控制命令：`IPRULES`、`IFACES.PRINT`
- [ ] 3.2 新增规则管理命令：`IPRULES.ADD/UPDATE/REMOVE/ENABLE/PRINT/PREFLIGHT`，并固定当前 v1 的 `IFACES.PRINT/IPRULES.PRINT/IPRULES.PREFLIGHT` JSON 输出形态（含空结果返回空数组、numeric id/计数字段、toggle 使用 `0|1`、规范化 match token、固定 `limits/warnings/violations` shape）
- [ ] 3.3 定义 RuleDef/RuleId/priority/enabled/enforce/log 模型与解析（kv token）；当前 v1 保持 uid-only、`priority` 显式提供、`enabled/enforce/log` 缺省值固定为 `1/1/0`、拒绝 `ct` 与无效组合（如 `action=ALLOW,enforce=0`）
- [ ] 3.4 Settings/持久化新增 `IPRULES` 开关，并保证当前开发期内读写/恢复自洽（当前不要求为未发版历史状态设计迁移/兼容逻辑）
- [ ] 3.5 `HELP` 更新：准确描述新增命令与参数语义

## 4. Packet inputs & hot-path boundaries
- [ ] 4.1 在 Packet 热路径提取 `PacketKeyV4` 所需字段（含双端点 `src/dst`、`ifindex`、`ifaceKind`、`proto`、`src/dst port`），避免继续沿用仅 remote-endpoint 视角的单地址输入
- [ ] 4.2 将 `IFACE_BLOCK` 预检查前移到 host/domain 等潜在慢路径之前；命中后直接终止后续 IP 规则与 legacy 判决，且不得输出 `ruleId/wouldRuleId`
- [ ] 4.3 明确当前 v1 fast path 不以 `NFQA_CT` / conntrack 元数据为前提；即使环境未暴露相关元数据，也必须按既定字段完成匹配

## 5. Rule engine core
- [ ] 5.1 实现 preflight：仅统计 `enabled=1` 的 active rules 的 subtables/buckets/rangeCandidates，并执行阈值校验（推荐告警+硬拒绝）
- [ ] 5.2 实现 snapshot：immutable EngineSnapshot + atomic publish + `rulesEpoch`；`enabled=0` 规则不得进入 active snapshot，但必须继续保留在控制面存储/持久化与 `IPRULES.PRINT` 输出中
- [ ] 5.3 实现 classifier lookup：mask-subtable + maxPriority 早停 + rangeCandidates 线性扫描（硬上限）；disabled rules 在热路径视为不存在；同优先级重叠命中的唯一胜者由稳定的编译结果/查询路径定义
- [ ] 5.4 实现 per-thread exact-decision cache：key 为 `PacketKeyV4`，entry 绑定 `rulesEpoch`，支持 `NoMatch` negative cache；cache 只缓存 IP 规则引擎结果，不缓存整个系统最终 verdict

## 6. Hot-path integration
- [ ] 6.1 接入 `exact-decision cache -> classifier snapshot` 的 fast path；仅当未命中 `IFACE_BLOCK` 且 `IPRULES=1` 时评估 IP 规则
- [ ] 6.2 仅当 IP 规则引擎给出 `NoMatch` 时才回落到后续 legacy/domain 路径；`Allow/Block/WouldBlock` 不再回落；当前不启用 `ip-leak` 合流语义
- [ ] 6.3 确保 `IPRULES=0` 时热路径不做 snapshot load/lookup（zero-cost disable）

## 7. Observability integration
- [ ] 7.1 enforce 命中：按 `add-pktstream-observability` 契约填充 `reasonId=IP_RULE_ALLOW|IP_RULE_BLOCK` 与 `ruleId`
- [ ] 7.2 log-only/would-block 命中：仅对 `action=BLOCK,enforce=0,log=1` 填充 `wouldRuleId` 与 `wouldDrop=1`；保持 `accepted=1` 且 `reasonId` 仍解释实际 verdict；同时保证每包最多 1 条 would-match（不改变 verdict）

## 8. C layer: per-rule runtime stats
- [ ] 8.1 实现 per-rule runtime stats（`hitPackets/hitBytes/lastHitTsNs` + `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`，since boot 不持久化），并在 `IPRULES.PRINT` 输出 `stats`
- [ ] 8.2 disabled rules 不得更新 stats，也不得进入 active complexity 口径
- [ ] 8.3 规则 `UPDATE` 生效后必须清零该规则 stats；规则 `ENABLE 0→1` 时也必须清零该规则 stats

## 9. Persistence & RESETALL
- [ ] 9.1 规则集持久化与恢复（新增 saver 文件），重启后恢复规则定义与既有 `ruleId`；per-rule stats 保持 since-boot 语义，不持久化
- [ ] 9.2 `RESETALL` 清理持久化、内存快照与 `ruleId` 计数器；其后新一轮规则集从初始 `ruleId = 0` 重开

## 10. Verification (device)
- [ ] 10.1 控制面：缺失 `priority` / 传入包名 selector / 传入 `ct` 时返回 `NOK`；省略 `enabled/enforce/log` 时按 `1/1/0` 归一化；disabled 规则仍可通过 `IPRULES.PRINT` 查询
- [ ] 10.2 输出：`IFACES.PRINT` 固定返回 `{"ifaces":[...]}`；枚举失败或无接口时返回 `{"ifaces":[]}`；`ifindex/type` 为 number
- [ ] 10.3 输出：`IPRULES.PRINT` 在无规则或过滤无命中时返回 `{"rules":[]}`；`rules` 按 `ruleId` 升序；`ruleId/uid/priority/stats.*` 为 number；`ifindex` 为 number 且未限定时为 `0`；`enabled/enforce/log` 为 `0|1`
- [ ] 10.4 输出：`IPRULES.PRINT` 中 `action/dir/iface/proto` 使用规范化 string token；`src/dst` 为 `any` 或标准 IPv4 CIDR；`sport/dport` 为 `any`、单端口十进制字符串、或 `lo-hi`
- [ ] 10.5 输出：`IPRULES.PREFLIGHT` 固定返回 `summary/limits/warnings/violations`；`limits` 含 `recommended/hard`；`warnings/violations` 为空时返回 `[]`，有项时每项至少含 `metric/value/limit/message`
- [ ] 10.6 行为/环境：在未暴露 `NFQA_CT` 元数据的环境下，v1 规则仍可按既定字段完成匹配；若环境提供相关元数据，也不得改变既定 v1 语义
- [ ] 10.7 行为：ALLOW/BLOCK 基本匹配（CIDR、端口 exact/range、proto、iface/ifindex、dir）
- [ ] 10.8 行为：`IFACE_BLOCK` 高于 ALLOW/BLOCK/would-match，且 `IFACE_BLOCK` 包不带 `ruleId/wouldRuleId`；`IPRULES=0` 时行为与基线一致且不做 lookup
- [ ] 10.9 行为：仅 `NoMatch` 回落到 legacy/domain，`Allow/Block/WouldBlock` 不再回落；当前不启用 `ip-leak` 合流语义
- [ ] 10.10 行为：safety-mode would-block 归因正确；每包最多 1 条 would-match；would-block 不改变实际 verdict
- [ ] 10.11 行为：disabled 规则不影响 verdict/PKTSTREAM/stats/preflight；同优先级重叠命中的唯一胜者在重复编译后保持稳定；增量 `UPDATE/ENABLE` 不改变既有 `ruleId`
- [ ] 10.12 C 层：per-rule stats 归因正确；`UPDATE` 生效后清零该规则 stats；`ENABLE 0→1` 时也清零该规则 stats
- [ ] 10.13 生命周期：`RESETALL` 后所有规则被彻底清空；后续新一轮规则集从初始 `ruleId = 0` 重开
- [ ] 10.14 性能冒烟：规则 0/100/1000 下，在 cache hit-heavy 与 `NoMatch`-heavy 两类流量中 pps/CPU/队列 backlog 不显著回退；PKTSTREAM 关闭作为基线
