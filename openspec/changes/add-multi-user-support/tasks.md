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

## 2. Multi-user 安装状态聚合（修正数据源假设）

> 背景：`/data/system/packages.list` 在 AOSP 写入端仍标注“未处理多用户”，其第二列为 user 0 的 UID（等价 appId），不表达 “某包安装在哪些 userId”。  
> 多用户安装状态以 `/data/system/users/<userId>/package-restrictions.xml` 为准（tag 为 `<pkg>`，字段名如 `inst`，缺省为 true）。

- [ ] 2.1 明确数据源与兼容边界（只读文件聚合，零命令依赖）：
  - 明确 `packages.list` 的职责：`packageName -> appId` 与 `appId -> names[]`（shared UID/别名集合），不承载 per-user 安装状态；
  - 明确 `package-restrictions.xml` 的职责：per-user `inst` 状态（缺省 true）；
  - 明确 user 枚举策略：优先枚举 `/data/system/users/` 下的数字目录，必要时再读 `userlist.xml` 作为补充；
  - 输出到 OpenSpec spec/design 的 “source of truth” 表述保持一致（避免后续再误用）。

- [ ] 2.2 Settings：补齐包状态相关路径常量与 helper（集中管理，便于审计权限）：
  - 目标文件：`src/Settings.hpp`、`src/Settings.cpp`
  - 增加 `/data/system/users/` 根目录常量与 per-user `package-restrictions.xml` 路径拼接 helper；
  - 明确这些 helper 仅用于读系统文件，不引入任何 shell/pm/binder 依赖；
  - **验证**：在单用户与多用户设备上通过 `dev/dev-diagnose.sh` 确认 SELinux/权限允许读取这些路径（若拒绝，记录 AVC 并在基础模块/策略层修复）。

- [ ] 2.3 解析层：实现“可单测、无副作用、强校验”的两类 parser（内存安全优先）：
  - 目标文件：新增 `src/PackageState.*`（或等价新模块），并在 `src/PackageListener.cpp` 调用
  - `packages.list` parser：
    - 仅读取每行前两个 token（`<packageName> <uid>`），将 `<uid>` 解释为 appId（user 0 uid）；
    - 对 `packageName` 做长度与字符集校验（拒绝控制字符、NUL、`/`、`..` 等）；
    - 对 `appId` 做范围校验（仅保留应用 UID 范围）；
    - 产出：`packageName -> appId` 与 `appId -> names[]`（收集 shared UID 的别名集合）。
  - `package-restrictions.xml` parser：
    - 仅解析 `<pkg name="...">` 以及 `inst` 布尔字段（缺省 true）；
    - 解析时采用“线性扫描 + 严格边界检查”的实现（避免正则灾难与越界），并对 `name` 做同样的包名校验；
    - 明确：解析失败 MUST 返回错误而不是返回空集合（用于上层的“保持旧快照”策略）。
  - **验证**：用内置样例（最小/异常/恶意输入）跑一轮离线解析自测（可通过 `dev/` 脚本或临时测试入口），确认不会崩溃/死循环/超内存。

- [ ] 2.4 聚合层：重写 `PackageListener::updatePackages()` 为“构建新快照 → 原子提交 → diff 应用”的安全流程：
  - 目标文件：`src/PackageListener.cpp`、`src/PackageListener.hpp`
  - 构建 `newNames: fullUid -> names[]`：
    - 遍历用户集合（目录枚举或 userlist），对每个 user 读取其 `package-restrictions.xml`，取 `inst=true` 的包；
    - 用 `packageName -> appId` 映射计算 `fullUid = userId * 100000 + appId`；
    - 用 `appId -> names[]` 填充 `newNames[fullUid]`（shared UID 自动聚合）。
  - 原子提交规则（避免误卸载/误删持久化）：
    - 任一必要输入读取/解析失败 → **不更新** `_names`，不调用 `appManager.remove`，仅记录日志并等待下次重试；
    - 仅当完整快照构建成功时，才进行 install/remove diff。
  - 并发/死锁约束：
    - `updatePackages()` 不持有 `mutexListeners`；与 `AppManager` 交互仅依赖其内部锁；
    - 不在解析阶段持有任何跨模块锁，避免与 DNS/NFQUEUE 热路径形成锁环。
  - **验证**：通过人为制造“文件原子替换/短暂不可读”场景，确认不会把大量 App 判为卸载并触发持久化删除。

- [ ] 2.5 监听层：扩展 inotify 监听范围并保证鲁棒性（避免漏更与抖动）
  - 目标文件：`src/PackageListener.cpp`
  - 监听对象至少包括：
    - `Settings::packagesList`（包名↔appId 映射变化）；
    - `/data/system/users/` 目录（新增/删除用户目录、userlist 变化）；
    - 各 user 的 `package-restrictions.xml`（per-user 安装状态变化）。
  - 约束：
    - 必须处理原子替换（`IN_MOVE_SELF`/`IN_DELETE_SELF`）导致的 inode 变化，并能自动重建 watch；
    - watch 构建失败时不得进入 busy loop；需要退避与重试；
    - 需要有节流/去抖，避免短时间内频繁触发全量重扫造成性能抖动。
  - **验证**：在多用户设备上“安装/卸载/切换用户/新增用户”场景中，App 列表能稳定收敛到正确状态，且无死锁/卡顿。

- [ ] 2.6 阶段性验证用例补全（与 dev 脚本对齐，确保回归可重复）
  - 目标文件：`dev/dev-smoke.sh`（或 `docs/tests/BACKEND_DEV_SMOKE.md`，按现有约定落点）
  - 覆盖场景：
    - 同一包在 user 0 与 work profile(user 10) 同时安装 → `APP.UID` 出现两个不同 uid；
    - 某包只在 work profile 安装 → `APP.UID` 仅出现 user 10 的 uid（不出现 user 0）；
    - 在某个 user 卸载包（`inst=false`）→ 对应 uid 被移除，且不会影响其他 user；
    - 连续触发包状态文件更新（原子替换）→ 不出现“误卸载风暴”与持久化误删。
