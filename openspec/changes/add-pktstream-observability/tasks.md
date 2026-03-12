## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（`specs/pktstream-observability/spec.md`）
- [x] 1.2 `openspec validate add-pktstream-observability --strict` 通过

## 2. OpenSpec cleanup (in this iteration)
- [x] 2.1 归档 superseded change：`add-app-ip-blacklist`
- [x] 2.2 修订 `add-app-ip-l3l4-rules-engine`：移除/下沉 PKTSTREAM schema 与 src/dst 5-tuple plumbing 描述，改为依赖本 change

## 3. Implementation (DEFERRED)
- [ ] 3.1 PKTSTREAM：在 Packet 判决收口处新增 `reasonId/ruleId/wouldRuleId/wouldDrop`，并确保 `IFACE_BLOCK` 事件不携带更低优先级规则层的 `ruleId/wouldRuleId`
- [ ] 3.2 PKTSTREAM：升级为输出 `ipVersion/srcIp/dstIp` 并移除 `ipv4|ipv6`；同时保持既有 `host` 字段语义为 remote endpoint（入站对应 `srcIp`，出站对应 `dstIp`）
- [ ] 3.3 Control：新增 `METRICS.REASONS` / `METRICS.REASONS.RESET` 命令注册与处理，并更新 `HELP`
- [ ] 3.4 METRICS：实现 `METRICS.REASONS`（per-reason `packets/bytes`）与 `METRICS.REASONS.RESET`，并确保 `RESETALL -> pktManager.reset()` 也会清空这些 counters
- [ ] 3.5 文档：更新 `docs/INTERFACE_SPECIFICATION.md`，覆盖 PKTSTREAM 新事件格式、`host` 语义说明，以及 `METRICS.REASONS*` 命令与 JSON shape
- [ ] 3.6 开发冒烟：扩展 `dev/dev-smoke.sh`，验证 `HELP` 暴露 `METRICS.REASONS*`、`METRICS.REASONS` 返回有效 JSON、`METRICS.REASONS.RESET` 可清零，且 `RESETALL` 后 reason counters 归零
- [ ] 3.7 开发冒烟：扩展 `dev/dev-smoke.sh` 的 `PKTSTREAM` 采样，验证事件包含 `ipVersion/srcIp/dstIp/reasonId`，且不再包含 legacy `ipv4|ipv6`
- [ ] 3.8 设备验证：在当前 A 层验收基线（可理解为 `BLOCKIPLEAKS=0`）下，`reasonId` baseline（iface / default allow）与字段齐全
- [ ] 3.9 设备验证：在当前 A 层验收基线（可理解为 `BLOCKIPLEAKS=0`）下，`METRICS.REASONS` 计数增长与 reset 生效（不依赖 PKTSTREAM 是否开启）
- [ ] 3.10 设备验证：`METRICS.REASONS` 不依赖 `tracked`，即 `tracked=0` 的 app 仍会计入 reason counters
