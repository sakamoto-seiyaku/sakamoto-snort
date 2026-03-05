## 1. OpenSpec docs (this change)
- [x] 1.1 完成 `proposal.md/design.md/tasks.md` 与 capability spec delta（`specs/pktstream-observability/spec.md`）
- [x] 1.2 `openspec validate add-pktstream-observability --strict` 通过

## 2. OpenSpec cleanup (in this iteration)
- [x] 2.1 归档 superseded change：`add-app-ip-blacklist`
- [x] 2.2 修订 `add-app-ip-l3l4-rules-engine`：移除/下沉 PKTSTREAM schema 与 src/dst 5-tuple plumbing 描述，改为依赖本 change

## 3. Implementation (DEFERRED)
- [ ] 3.1 PKTSTREAM：Packet 事件新增 `reasonId/ruleId/wouldRuleId/wouldDrop`
- [ ] 3.2 PKTSTREAM：升级为输出 `ipVersion/srcIp/dstIp` 并移除 `ipv4|ipv6`
- [ ] 3.3 文档：更新 `docs/INTERFACE_SPECIFICATION.md` 的 PKTSTREAM 事件格式
- [ ] 3.4 设备验证：`reasonId` baseline（iface / ip-leak / default allow）与字段齐全
- [ ] 3.5 METRICS：实现 `METRICS.REASONS`（per-reason `packets/bytes`）与 `METRICS.REASONS.RESET`
- [ ] 3.6 设备验证：`METRICS.REASONS` 计数增长与 reset 生效（不依赖 PKTSTREAM 是否开启）
