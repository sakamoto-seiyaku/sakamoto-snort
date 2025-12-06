## 1. Implementation
- [x] 1.1 引入 UID helper 与 App 标识 API：为 `App` 增加 `uid()/userId()/appId()` 访问器，在不改动行为的前提下于代码中集中使用这些 helper。
- [x] 1.2 在核心路径上移除 `% 100000`：更新 `AppManager::make`、`Control::arg2app` 等位置，统一以完整 Linux UID 作为内部主键，保持单用户设备行为不变。
- [x] 1.3 为多用户持久化增加 Settings helper：在 `Settings` 中实现 `userSaveRoot/userSaveDirPackages/userSaveDirSystem/ensureUserDirs` 等函数，但尚不在生产路径中使用。
- [x] 1.4 调整 `AppManager::create` 的保存路径选择：在不改变 user 0 持久化位置的前提下，为 `userId > 0` 的 App 使用 `Settings` 提供的 per-user 目录。
- [x] 1.5 重写 `PackageListener::updatePackages`：仅依赖 `/data/system/packages.list`，按 `(name, uid)` 解析，过滤非应用 UID，采用"匿名 App → 命名 App" 升级语义维护 `_names` 与 `AppManager`。
- [x] 1.6 优化 `AppManager::install/remove/restore`：
  - `install/remove` 只按完整 UID 操作索引与保存文件；
  - `restore` 以现有 `_byUid` 为主，避免通过文件名隐式创建新 App。
- [x] 1.7 在 `Control` 中实现 AppSelector：统一解析 `<uid|str>` 参数（含 `USER <userId>` 扩展），并迁移所有相关命令使用 AppSelector（不改命令名）。
- [x] 1.8 扩展控制协议 HELP 文档：更新 `HELP` 输出中对 `<uid|str>` 与 `USER <userId>` 的说明，保证前端可以根据文本了解多用户语义。
- [x] 1.9 扩展 DNS/Packet/Activity 流事件 JSON：在 `App::print` 和 `Activity::print` 中补充 `uid/userId/appId` 字段，在 `DnsRequest::print` 与 `Packet<IP>::print` 顶层补充 `uid/userId` 字段，保持历史字段不变。
- [x] 1.10 多用户化 `RESETALL`：在 `Settings` 中实现 `clearSaveTreeForResetAll()`，并在 `Control::cmdResetAll` 中在持有 `mutexListeners` 写锁的前提下调用该 helper 清理 `/data/snort/save` 下所有用户的保存树。
- [ ] 1.11 单用户回归验证：在单用户设备上执行已有后端冒烟用例（HELLO/HELP/APP 查询/统计、DNS/PKT/ACTIVITY 流、RESETALL 等），确认输出与当前版本一致或仅在新增字段层面变化。
- [ ] 1.12 多用户场景验证：在存在多个 Android 用户的设备上，准备典型场景（同一包在不同用户下安装、不同用户下自定义黑白名单与 TRACK 设置），验证控制命令和流事件中 `uid/userId` 区分正确。
- [ ] 1.13 文档更新：在 `docs/SNORT_MULTI_USER_REFACTOR.md` 中标记已实现部分，并根据最终实现细节更新或补充测试用例；确保 OpenSpec spec 与该设计文档保持一致。

