# Design: App-level IP blacklist

## Overview
- 判决语义：key 为 `(uid, 对端 IP)`（出站为目的 IP，入站为源 IP）。IP 黑名单作为现有判决链路的补充：只有当某数据包在域名规则（含白名单/黑名单、自定义规则）、`BLOCKIPLEAKS` 与接口策略处理后仍未被这些规则明确 ACCEPT 或 DROP 时，命中 `(uid, 对端 IP)` 黑名单才会将最终判决置为 DROP；由域名白名单产生的允许以及由 `BLOCKIPLEAKS` 或接口策略产生的丢弃不受 IP 黑名单影响。  
- 决策位置：在 `PacketManager::make` 中扩展现有判决逻辑，保持 NFQUEUE 回调结构不变、不引入新的全局锁。  
- 数据结构：使用不可变 snapshot + copy-on-write，避免在 NFQUEUE 热路径上加锁或做重 IO。  

## Hot path design
- `PacketListener::callback` 不变，继续在持有 `mutexListeners` 的 shared lock 下调用 `pktManager.make(...)`。  
- `PacketManager::make` 逻辑扩展为：  
  - 使用现有流程计算 `blocked` / `cs`（`App::blocked(domain)`）、`ipLeaksBlocked` 与 `ifaceBlocked`，保持当前 `BLOCKIPLEAKS` 与接口判决语义不变。  
  - 识别“域名白名单允许”分支（例如 `domain != nullptr && !blocked && cs == Stats::WHITE`）：在该分支下，只要没有被接口策略/其他规则要求 DROP，即直接 ACCEPT，不进行 IP 黑名单检查。  
  - 若 `ipLeaksBlocked` 或 `ifaceBlocked` 为真，则视为已有规则已明确要求 DROP，直接复用现有判决，不进行 IP 黑名单检查。  
  - 仅当上述规则未对该包给出明确 ACCEPT/DROP 结论时，才通过 snapshot 查询 `(uid, 对端 IP)`，命中则将 verdict 置为 DROP，否则保持 ACCEPT。`BLOCKIPLEAKS` 的开关不影响 IP 黑名单本身是否参与判决。  
- snapshot 查找约束：  
  - 单次调用内最多一次 atomic load 获取 `shared_ptr<const Snapshot>`；  
  - 使用两层 `unordered_map` / `unordered_set` 查找 `(uid, 对端 IP)`，不进行字符串解析、不做动态分配。  

## Snapshot & COW
- Snapshot 结构：  
  - 顶层：`unordered_map<uid, AppIpSet>`；  
  - `AppIpSet`：`unordered_set<Address<IPv4>>` 与 `unordered_set<Address<IPv6>>`。  
- 读路径（NFQUEUE 热路径）：  
  - 通过 `std::atomic<std::shared_ptr<const Snapshot>>` 的 load 获取只读视图；  
  - 在该视图上执行查找，无锁、无写入。  
- 写路径（控制命令线程）：  
  - 基于当前 snapshot 创建新的可变副本，仅复制必要的 uid 项；  
  - 在副本上执行 ADD/REMOVE/CLEAR；  
  - 完成后通过单次 store 发布新的 `shared_ptr`，旧 snapshot 由引用计数回收。  
- `RESETALL`：写路径中创建空 snapshot 并发布，保持行为与当前重置语义一致。  

## Control & persistence
- 控制协议新增 per-app IP 黑名单命令，仅接受 `<uid>` 形式的 App 选择参数，不做包名解析，仅支持黑名单，不支持 IP 白名单。  
- 持久化：  
  - 将每个 App 的 IP 黑名单保存到现有配置存储中（具体挂载点在实现阶段细化），按 uid 归档；  
  - 恢复时重建 snapshot；  
  - `RESETALL` 时清除所有 IP 黑名单持久化记录，并重置 snapshot。  
