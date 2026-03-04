## ADDED Requirements

### Requirement: Per-app IP blacklist as supplementary filter
系统 MUST 支持以 `(uid, 对端 IP)` 为 key 的 App 级 IP 黑名单，其中“对端 IP”定义为出站流量的目的 IP、入站流量的源 IP。本黑名单在 NFQUEUE 判决链路中作为现有域名/接口规则之后的一道补充过滤：当全局阻断已启用且某数据包经由域名规则（含白名单/黑名单、自定义规则）、`BLOCKIPLEAKS` 与接口策略处理后仍未被这些规则明确 ACCEPT 或 DROP 时，若其 `(uid, 对端 IP)` 命中该黑名单，则最终判决 MUST 为 DROP。由域名白名单产生的允许判决以及由 `BLOCKIPLEAKS` 或接口策略产生的丢弃判决 SHALL 不受 IP 黑名单影响。

#### Scenario: Packet without domain is dropped by app IP blacklist
- **WHEN** NFQUEUE 收到某 App 的数据包，该包对应的对端 IP 未能映射到任何 `Domain`（例如未经历 DNS 或 DNS 未被监听）  
- **AND** 全局阻断 (`BLOCK`) 已启用，且该包未被接口策略或其他现有规则明确 DROP  
- **AND** `(uid, 对端 IP)` 已被加入该 App 的 IP 黑名单  
- **THEN** `PacketManager` 在判决时 SHALL 将该包判为 DROP  

#### Scenario: Domain whitelist bypasses app IP blacklist
- **WHEN** 某 App 对某域名被判定为“允许”（例如命中白名单或其它授权规则）  
- **AND** 该域名解析得到的某个对端 IP 被加入该 App 的 IP 黑名单  
- **THEN** 在全局阻断已启用且该包未被接口策略等规则要求 DROP 的前提下，针对该 IP 的数据包 SHALL 继续被 ACCEPT，IP 黑名单 SHALL 不改变这一允许判决  

#### Scenario: IP blacklist active when BLOCKIPLEAKS is disabled
- **WHEN** 某 App 的 `(uid, 对端 IP)` 被加入 IP 黑名单  
- **AND** 针对该 IP 的流量不命中域名白名单，且未被接口策略要求 DROP  
- **AND** `BLOCK` 已启用但 `BLOCKIPLEAKS` 被关闭  
- **THEN** 针对该 `(uid, 对端 IP)` 的数据包 SHALL 仍然被 IP 黑名单判为 DROP  

### Requirement: Snapshot-based lookup on hot path
NFQUEUE 判决热路径 MUST 仅通过只读 snapshot 结构查询 `(uid, IP)` 黑名单，不得在 `PacketManager::make` 中执行加锁、磁盘访问或复杂数据结构重构；每次判决对 IP 黑名单的查询开销 MUST 限于一次 snapshot 指针加载和有限次哈希查找。

#### Scenario: Hot path uses immutable snapshot
- **WHEN** `PacketListener::callback` 调用 `PacketManager::make` 进行判决  
- **THEN** IP 黑名单查询 SHALL 通过不可变 snapshot 完成，使用原子加载获得只读视图，在该视图上执行查找，不获取任何互斥锁，也不修改 snapshot 内容  

#### Scenario: IP blacklist updates via copy-on-write
- **WHEN** 控制命令为某 App 添加、移除或清空 IP 黑名单项  
- **THEN** 系统 SHALL 基于当前 snapshot 生成新的副本，在副本上完成变更后一次性发布更新的 snapshot 指针；NFQUEUE 热路径上的判决 SHALL 只看到旧 snapshot 或新 snapshot 中之一，不存在部分更新状态  

### Requirement: Control commands for per-app IP blacklist
控制协议 MUST 提供仅针对 IP 黑名单的 per-app 管理命令，命令参数 MUST 仅接受完整 UID 形式的 `<uid>`，不得接受包名字符串，不引入 IP 白名单命令。

#### Scenario: IPBLACKLIST.ADD attaches IP to selected app
- **WHEN** 客户端调用 `IPBLACKLIST.ADD <uid> <ip>`，且 `<uid>` 为某 App 实例的完整 Linux UID  
- **THEN** 系统 SHALL 将 `<ip>` 加入该 App 的 IP 黑名单集合，并更新 snapshot，使后续针对该 `(uid, IP)` 的数据包被 DROP  

#### Scenario: IPBLACKLIST.REMOVE and CLEAR update snapshot
- **WHEN** 客户端调用 `IPBLACKLIST.REMOVE <uid> <ip>` 或 `IPBLACKLIST.CLEAR <uid>`，且 `<uid>` 为某 App 实例的完整 Linux UID  
- **THEN** 系统 SHALL 从对应 App 的 IP 黑名单集合中移除指定 IP 或清空全部 IP，并通过 copy-on-write 发布新的 snapshot  

### Requirement: Persistence and reset of app IP blacklist
App 级 IP 黑名单 MUST 支持持久化与恢复，并与 `RESETALL` 保持一致语义：重启后黑名单配置可恢复，RESETALL 后黑名单 MUST 被完全清除。

#### Scenario: Blacklist survives restart
- **WHEN** 某 App 的 `(uid, IP)` 被加入 IP 黑名单并成功保存  
- **AND** sucre-snort 进程重启  
- **THEN** 系统 SHALL 在恢复阶段重建 IP 黑名单 snapshot，使后续针对该 `(uid, IP)` 的数据包继续被 DROP  

#### Scenario: RESETALL clears all app IP blacklists
- **WHEN** 客户端执行 `RESETALL` 命令  
- **THEN** 系统 SHALL 清除所有 App 的 IP 黑名单持久化记录，并发布空的 IP 黑名单 snapshot，使后续所有数据包不再因 IP 黑名单而被 DROP（除非重新配置）  
