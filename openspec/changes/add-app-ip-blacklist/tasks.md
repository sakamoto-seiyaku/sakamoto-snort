## 1. Snapshot &判决路径
- [ ] 1.1 引入 `IpBlockSnapshot` 及管理类：定义 `(uid → {IPv4, IPv6})` 的只读视图与 COW 更新接口，不依赖具体持久化。  
- [ ] 1.2 在 `PacketManager::make` 中集成 snapshot 查询：在沿用现有 `BLOCKIPLEAKS` / 接口判决与域名白名单/黑名单逻辑的前提下，仅对那些未被上述规则明确 ACCEPT 或 DROP 的包，查询 `(uid, 对端 IP)` 黑名单并在命中时 DROP；保持统计/stream 逻辑沿用最终 `verdict`。  
- [ ] 1.3 确认 NFQUEUE 热路径性能：通过简单压力测试验证在无 IP 黑名单、少量 IP 黑名单、多 uid 多 IP 黑名单三种场景下延迟与 CPU 开销无明显回退。  

## 2. Control & persistence
- [ ] 2.1 设计并实现 `IPBLACKLIST.ADD/REMOVE <uid> <ip>`、`IPBLACKLIST.CLEAR/PRINT <uid>` 控制命令，参数仅接受完整 UID，不支持包名字符串，语义仅为黑名单。  
- [ ] 2.2 实现 per-app IP 黑名单持久化与恢复：在保存/恢复过程中与现有 `Settings`/`App` 存储对齐，重启后 snapshot 自动重建。  
- [ ] 2.3 将 IP 黑名单纳入 `RESETALL`：在 `cmdResetAll` 中确保持久化记录被清除，并发布空 snapshot。  

## 3. 验证
- [ ] 3.1 行为验证：  
  - 无域名流量（无 DNS 记录）命中 `(uid, IP)` 黑名单时，包 MUST 被 DROP；  
  - 同一 IP 对不同 uid 的决策独立；  
  - 域名白名单产生的允许不受 IP 黑名单影响；被 `BLOCKIPLEAKS` 或接口策略判定为 DROP 的流量不会被 IP 黑名单放行；在 `BLOCK` 打开且 `BLOCKIPLEAKS` 关闭时，命中 `(uid, 对端 IP)` 黑名单的包仍会被 DROP。  
- [ ] 3.2 兼容性与回归：  
  - 未配置 IP 黑名单时，行为与当前版本一致；  
  - 现有控制命令与统计/流事件输出不发生破坏性变化。  
