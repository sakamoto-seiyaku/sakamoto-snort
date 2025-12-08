# Design: App-level IP blacklist

## Overview
- 判决语义：key 为 `(uid, IP)`，命中即 DROP；不依赖域名、域名黑/白名单或 `BLOCKIPLEAKS`。  
- 决策位置：仅在 `PacketManager::make` 中增加一条 IP 黑名单检查，保持 NFQUEUE 回调结构不变。  
- 数据结构：使用不可变 snapshot + copy-on-write，避免在 NFQUEUE 热路径上加锁或做重 IO。  

## Hot path design
- `PacketListener::callback` 不变，继续在持有 `mutexListeners` 的 shared lock 下调用 `pktManager.make(...)`。  
- `PacketManager::make` 开头增加：  
  - `ipBlockedApp = snapshot.isBlocked(uid, ip)`；  
  - 最终 `verdict` 组合为：`!(ipBlockedApp || ipLeaksBlocked) && !ifaceBlocked`，其中 `ipLeaksBlocked` 与 `ifaceBlocked` 保持现有语义。  
- snapshot 查找约束：  
  - 单次调用内最多一次 atomic load 获取 `shared_ptr<const Snapshot>`；  
  - 使用两层 `unordered_map` / `unordered_set` 查找 `(uid, IP)`，不进行字符串解析、不做动态分配。  

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
