# Change: App-level IP blacklist

## Why
当前仅支持“域名维度”的黑名单与 IP 泄漏联动拦截：  
- NFQUEUE 热路径只能根据 `Domain` 与 `App::blocked(domain)` 做决策；  
- `BLOCKIPLEAKS` 依赖 DNS 先成功解析并建立 Domain↔IP 映射；  
- 无法对“无域名流量”或“仅知道 IP 而未知域名”的场景实施 per-app 精确封禁。  

随着精细化控制需求增加，需要为每个 App 提供独立的 IP 黑名单能力，使其可以在不依赖域名、规则和列表的前提下，对指定 IP 直接 DROP，同时保持 NFQUEUE 热路径的性能与并发约束。

## What Changes
- 新增“按 App + IP 维度”的黑名单能力，key 为 `(uid, 对端 IP)`（出站为目的 IP，入站为源 IP），在全局阻断开启时仅作为域名/接口规则之后的一道补充过滤：当现有域名规则（含白名单/黑名单、自定义规则）、`BLOCKIPLEAKS` 与接口策略未对某个包给出明确 ACCEPT/DROP 结论时，若其命中该黑名单，则 NFQUEUE 热路径 MUST 将其判为 DROP；由域名白名单产生的允许以及由 `BLOCKIPLEAKS` 或接口策略产生的丢弃不受该黑名单影响。  
- 在 `PacketManager::make` 中引入只读 snapshot 结构：  
  - 使用 `std::shared_ptr<const Snapshot>` + atomic load 承载 `(uid → {IPv4, IPv6})` 集合；  
  - NFQUEUE 热路径仅做一次 snapshot 指针加载和最多两次哈希查找，不引入新锁。  
- 在控制协议中增加 per-app IP 黑名单管理命令（例如 `IPBLACKLIST.ADD/REMOVE/CLEAR/PRINT <uid> <ip>`），仅按完整 UID 选择 App，不支持包名字符串，仅支持黑名单语义，不引入 IP 白名单。  
- 将 `(uid, IP)` 黑名单持久化到现有配置存储中，保证重启后规则可恢复，`RESETALL` 时统一清理。  

## Impact
- 新增 spec 能力：`app-ip-blacklist`，定义 per-app IP 黑名单行为、优先级与性能约束。  
- 主要影响组件：`PacketManager`（判决热路径）、`Control`（新命令）、`Settings/App` 或辅助管理类（snapshot 管理与持久化）。  
