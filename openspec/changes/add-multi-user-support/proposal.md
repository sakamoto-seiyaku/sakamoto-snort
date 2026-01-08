# Change: Multi-user support for sucre-snort

## Why
当前实现中，sucre-snort 在内部对 UID 使用 `% 100000` 取模，只保留 appId 部分：  
- 不同 Android 用户（`userId > 0`）下的同一应用会被折叠到同一个 App 实例，无法区分不同用户的策略与统计；  
- 所有控制命令中 `<uid>` 实际语义是“appId”，与 Android/Linux UID 的概念不一致；  
- `/data/snort/save` 下的持久化仅面向单用户场景，缺少对多用户数据的隔离与清理能力。  

随着多用户设备与多用户安装场景的增多，需要升级后端模型，使其在内部完整感知 Linux UID、按用户分层持久化，同时保持对现有单用户调用方式的兼容。

## What Changes
- 统一内部模型为“完整 Linux UID + 系统文件聚合数据源”，移除核心路径上对 UID 的 `% 100000` 截断：  
  - `/data/system/packages.list` 提供全局 `packageName ↔ appId`/shared-UID 信息；  
  - `/data/system/users/<userId>/package-restrictions.xml` 提供 per-user 安装状态（例如 `inst` 等）。  
- 在 `Settings` 中引入按用户分层的保存目录（`user<userId>/packages` / `user<userId>/system`），user 0 继续沿用当前根目录，保证向后兼容。  
- 重构 `PackageListener` 和 `AppManager` 的安装/删除/恢复逻辑：通过 `packages.list` + per-user `package-restrictions.xml` 聚合出 `uid -> names[]`，为每个 `(package, userId)` 生成独立的 App 实例；不依赖 `pm` 命令。  
- 在控制协议层统一实现 AppSelector：  
  - `<uid>` 始终解释为完整 Linux UID；  
  - `<str>` 解释为包名，可选追加 `USER <userId>` 子句；  
  - 不带 `userId` 的字符串默认指向主用户（user 0）实例，保持现有行为。  
- 扩展 DNS/Packet/Activity 流事件 JSON，增加 `uid` 与 `userId` 字段，便于前端按照用户维度展示与过滤。  
- 扩展 `RESETALL` 语义：在保持设备级“恢复初始状态”的同时，统一清理 `/data/snort/save` 下所有用户（含 `user<userId>` 子目录）的持久化数据。  

## Impact
- Affected specs:  
  - `multi-user-support` 能力（新增）：定义完整 UID 模型、多用户持久化与控制协议多用户语义。  
- Affected code (high level):  
  - 身份与持久化相关：`Settings`, `App`, `AppManager`, `PackageListener`, `Saver`。  
  - 控制协议与选择逻辑：`Control` 及所有接受 `<uid|str>` 的命令实现。  
  - 数据路径与流事件：`DnsListener`, `PacketListener`, `PacketManager`, `Activity`, `Streamable`。  
  - 全局重置逻辑：`Control::cmdResetAll` 及相关 `reset()` 实现。  
