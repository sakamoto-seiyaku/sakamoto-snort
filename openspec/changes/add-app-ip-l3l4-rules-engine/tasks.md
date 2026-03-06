## 1. OpenSpec docs (this change)
- [ ] 1.1 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（本目录下 `specs/`）
- [ ] 1.2 `openspec validate add-app-ip-l3l4-rules-engine --strict` 通过

## 2. Control & Settings
- [ ] 2.1 新增控制命令：`IPRULES`、`POLICY.ORDER`、`IFACES.PRINT`
- [ ] 2.2 新增规则管理命令：`IPRULES.ADD/UPDATE/REMOVE/ENABLE/PRINT/PREFLIGHT`
- [ ] 2.3 Settings 持久化新增字段（`IPRULES` 开关、`POLICY.ORDER`），维护 `_savedVersion` 迁移默认值
- [ ] 2.4 `HELP` 更新：准确描述新增命令与参数语义

## 3. Rule engine core
- [ ] 3.1 定义 RuleDef/RuleId/priority/enforce/log 模型与解析（kv token）
- [ ] 3.2 实现 preflight：统计 subtables/buckets/rangeCandidates 并执行阈值校验（推荐告警+硬拒绝）
- [ ] 3.3 实现 snapshot：immutable EngineSnapshot + atomic publish
- [ ] 3.4 实现 lookup：mask-subtable + maxPriority 早停 + rangeCandidates 线性扫描（硬上限）
- [ ] 3.5 实现 per-rule runtime stats（`hitPackets/hitBytes/lastHitTsNs` + `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`，since boot 不持久化），并在 `IPRULES.PRINT` 输出 `stats`

## 4. Hot path integration
- [ ] 4.1 `PacketManager` 接入规则引擎 lookup（依赖 `add-pktstream-observability` 已提供 src/dst 5-tuple 输入）
- [ ] 4.2 `PacketManager` 引入 combiner：`IFACE_BLOCK` hard-drop + `POLICY.ORDER` 合流
- [ ] 4.3 确保 IPRULES=0 时热路径不做 snapshot load/lookup（zero-cost disable）

## 5. Observability integration
- [ ] 5.1 enforce 命中：按 `add-pktstream-observability` 契约填充 `reasonId=IP_RULE_ALLOW|IP_RULE_BLOCK` 与 `ruleId`
- [ ] 5.2 log-only 命中：填充 `wouldRuleId` 与 `wouldDrop=1`；保持 `accepted=1` 且 `reasonId` 仍解释实际 verdict；同时保证每包最多 1 条 would-match（不改变 verdict）

## 6. Persistence & RESETALL
- [ ] 6.1 规则集持久化与恢复（新增 saver 文件），重启后恢复规则（per-rule stats since boot，不持久化）
- [ ] 6.2 `RESETALL` 清理持久化与内存快照

## 7. Verification (device)
- [ ] 7.1 行为：ALLOW/BLOCK 基本匹配（CIDR、端口 exact/range、proto、iface/ifindex、dir）
- [ ] 7.2 行为：`POLICY.ORDER` 三模式与 `BLOCKIPLEAKS`/ip-leak 的组合回归
- [ ] 7.3 行为：safety-mode would-match + per-rule stats 归因正确
- [ ] 7.4 性能冒烟：规则 0/100/1000 下 pps/CPU/队列 backlog 不显著回退；PKTSTREAM 关闭作为基线
