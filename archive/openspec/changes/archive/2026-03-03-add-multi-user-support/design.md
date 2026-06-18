## Context
当前 sucre-snort 内部以 UID 为 App 标识，但在多个核心入口（例如 `AppManager::make`、`Control::arg2app`）中对 UID 进行了 `% 100000` 取模，只保留 appId 部分：  
- 同一应用在不同 Android 用户下的实例被折叠到同一个 App；  
- 控制命令中 `<uid>` 实际语义与 Android/Linux UID 不一致；  
- `/data/snort/save` 下的持久化目录没有 per-user 隔离，多用户场景下难以清理与迁移。  

`docs/SNORT_MULTI_USER_REFACTOR.md` 已给出了相对完整的多用户设计与分阶段实施计划，本设计文档仅对关键决策做摘要，并作为 OpenSpec 变更的技术背景引用该文件。

## Goals / Non-Goals
- Goals:  
  - 内部统一使用完整 Linux UID，消除 `% 100000` 带来的多用户信息丢失；  
  - 基于系统文件聚合（`/data/system/packages.list` + `/data/system/users/<userId>/package-restrictions.xml`），为每个 `(package, userId)` 建立独立 App 实例；  
  - 引入 per-user 保存目录，实现多用户统计与配置的物理隔离；  
  - 在不新增控制命令的前提下，通过参数扩展支持多用户选择（UID 模式与包名 + userId 模式）；  
  - 为 DNS/Packet/Activity 流事件补充 `uid/userId` 维度，使上层 UI 可以按用户视角展示。  
- Non-Goals:  
  - 不改变“全局列表/配置”的设备级语义，例如全局黑白名单、规则、总览统计仍按设备级视角工作；  
  - 不在本次改动中引入新的网络协议；不依赖 `pm` 命令或 Binder 查询，安装状态与 UID 映射仅来自系统已有持久化文件。  

## Decisions
- UID 模型：  
  - 统一以完整 Linux UID 作为内部主键，`App` 暴露 `uid()/userId()/appId()` helper，`AppManager`、`DnsListener`、`PacketListener` 等所有入口不再对 UID 做取模。  
  - 对外 API 中 `<uid>` 的含义升级为完整 Linux UID；旧客户端仅在 user 0 上使用 appId 范围的 UID 时行为不变。  
- 数据源与安装状态：  
  - `/data/system/packages.list` 作为全局 `packageName -> appId` / `appId -> names[]`（shared UID）映射来源；解析时限制只使用前两个 token（`name uid`），其余丢弃；对 appId 使用 helper 过滤非应用 UID，对 name 做基础合法性检查。  
  - per-user 安装状态来自 `/data/system/users/<userId>/package-restrictions.xml`（读取 `<pkg name="...">` 的 `inst` 等字段；文件可能为 ABX 二进制 XML 或文本 XML），用户集合来自 `/data/system/users/userlist.xml`（或 users 目录枚举兜底）。  
  - `PackageListener` 通过上述两类文件聚合出 `fullUid -> names[]`，再驱动 `AppManager.install/remove`。  
- 持久化路径：  
  - user 0 沿用当前的 `saveDirPackages/saveDirSystem/saveDirDomainLists`；  
  - 对 `userId > 0` 的 App，通过 `Settings::userSaveRoot/userSaveDirPackages/userSaveDirSystem` 生成 `user<userId>/...` 目录，并集中在 Settings 层创建。  
- 控制协议与 AppSelector：  
  - 数字参数一律解释为完整 UID；  
  - 字符串参数解释为包名，可选跟随 `USER <userId>` 子句；  
  - 不带 userId 的字符串默认指向主用户（user 0），保持现有行为；  
  - 统一在 `Control` 内实现 AppSelector，所有接受 `<uid|str>` 的命令复用这一逻辑。  
- 流事件 JSON：  
  - 在 `App::print` 与 `Activity::print` 中为 App 对象增加 `uid/userId/appId` 字段；  
  - 在 `DnsRequest::print` 与 `Packet<IP>::print` 顶层增加 `uid/userId` 字段，不移除现有字段；  
  - 持久化格式（`Saver`）保持不变，仅在计算与输出时使用新的 UID 模型。  
- RESETALL 行为：  
  - 在 Settings 中集中实现清理 `/data/snort/save` 下所有用户保存树的 helper，由 `Control::cmdResetAll` 在持有全局监听锁的前提下一次性调用；  
  - 各业务模块仍负责自己的逻辑 reset（清空内存结构与已知文件），两者结合保证多用户场景下 RESETALL 仍然是“设备级恢复初始状态”。  

## Risks / Trade-offs
- 风险：  
  - 对控制协议语义的扩展可能影响旧客户端的解析逻辑，需要通过兼容测试确保原有 `<uid>` 与 `<str>` 用法不受影响；  
  - per-user 持久化目录引入后，错误的路径拼接或清理策略可能导致旧版本无法正确回滚或读取数据。  
- 权衡：  
  - 选择不新增控制命令，而是扩展参数解析与 JSON 字段，减少前端改造成本，但后端需要更加严格地保证兼容性；  
  - 不在本次改动中拆分 capability，而是在单一 `multi-user-support` 能力下集中描述 UID 模型、控制协议和持久化行为，后续如有需要可以再按能力细分。  

## Implementation Constraints
为避免实现偏离设计文档中的边界约束，在编码阶段需要遵守以下关键规则（对应 `docs/SNORT_MULTI_USER_REFACTOR.md` 中的若干条目）：  

- UID 绝不再做截断或取模：  
  - 仅允许在包安装状态聚合阶段（`packages.list` 与 per-user `package-restrictions.xml`）通过 `isAppUid(uid)`/appId 范围校验过滤非应用 UID；  
  - 其它所有路径（NFQUEUE 的 `NFQA_UID`、netd socket UID、控制命令显式传入的 `<uid>` 等）都必须将 UID 视为“内核事实”，不再执行 `% 100000` 或其它形式的截断。  
- App 集合的唯一来源是“包安装状态聚合 + 运行期 UID”：  
  - `AppManager::restore()` 只能在已有 `_byUid` 集合基础上恢复内容，**不得创建新的 App**；  
  - App 的生命周期仅由 `PackageListener::updatePackages()`（安装/卸载）和运行期的 `AppManager::make(uid)` 驱动，任何额外的数据源都不得独自创建 App。  
- 所有 `<uid|str>` 命令统一走 AppSelector：  
  - 控制层不得在单个命令内部重新解析 `CmdArg` 或再次对 UID 做截断；  
  - 所有接受 `<uid|str>` 的命令都必须通过 AppSelector 落到 `AppManager::find(uid)` / `findByName(name, userId)` 上，保持行为一致。  
- TOPACTIVITY 严格只接受 `<uid>`：  
  - 命令参数必须被直接视为完整 Linux UID 并传入 `appManager.make(uid)`，禁止再通过包名字符串查找 App；  
  - 不允许为 `TOPACTIVITY` 增加 `USER` 子句或字符串选择形式。  
- 流事件的 `uid/userId` 必须来自 App 对象：  
  - `DnsRequest` / `Packet` / `Activity` 的 `print` 顶层新增的 `uid` / `userId` 字段必须通过 `_app->uid()` / `_app->userId()` 获取，不能在流对象内部维护第二份 UID；  
  - `save/restore` 继续保持旧格式，仅基于名称恢复历史数据，恢复出的旧事件统一视为 user 0。  
- RESETALL 的文件系统清理集中在 Settings：  
  - `Control::cmdResetAll` 在持有 `mutexListeners` 写锁时，必须调用 Settings 提供的 helper 一次性清理 `/data/snort/save/` 整棵保存树；  
  - 各模块新增的 `reset()` 只负责清内存状态和已知文件，不直接遍历或删除 per-user 目录。  

## Migration Plan
- 参考 `docs/SNORT_MULTI_USER_REFACTOR.md` 中的分阶段计划，从内部 UID 完整化开始，逐步引入 per-user 目录、PackageListener 重构、控制协议改造与 RESETALL 扩展。  
- 每个阶段都要求在单用户设备上进行回归测试，确保输出与当前版本兼容；多用户用例只在后期阶段逐步启用。  

## Open Questions
- 是否需要在控制协议的 JSON 输出中显式标记协议版本或能力标志，以便前端区分“已支持多用户”的后端？  
- 是否需要在未来将多用户相关的测试用例正式纳入自动化测试流水线，而不仅仅是文档化的手工用例？  
