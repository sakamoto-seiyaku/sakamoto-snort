## ADDED Requirements

### Requirement: Full UID-based app identity
系统内部 MUST 以完整 Linux UID 作为 App 的唯一一等主键，不再在核心逻辑中对 UID 做取模或其他截断；每个 `(package, userId)` 实例对应一个独立的 App 对象与统计视图。

#### Scenario: NFQUEUE packet mapped to App by full uid
- **WHEN** `PacketListener` 从 NFQUEUE 收到带有 `NFQA_UID` 元数据的数据包  
- **THEN** 系统 SHALL 使用该完整 UID 调用 `AppManager` 查找或创建 App，并在判决与统计中始终使用该 UID 标识该 App 实例  

#### Scenario: DnsListener maps DNS uid to App by full uid
- **WHEN** `DnsListener` 从 `sucre-snort-netd` 连接收到带 UID 的 DNS 查询信息  
- **THEN** 系统 SHALL 使用该完整 UID 查找或创建对应的 App，并在后续 DNS 统计与 Activity 流中始终使用该 UID  

### Requirement: Install-state aggregation from system files
系统 MUST 通过读取系统持久化文件聚合得到多用户下的 App 安装状态与 UID 映射，而不是依赖 `pm` 命令或其他运行时命令执行；聚合的数据源至少包括：  
- `/data/system/packages.list`：提供全局 `packageName -> appId` 与 `appId -> names[]`（shared UID/别名集合）映射；解析时仅使用每行前两个 token（`<packageName> <uid>`），其中 `<uid>` 视为 user 0 的 UID（等价 appId），其余内容忽略。  
- `/data/system/users/<userId>/package-restrictions.xml`：提供 per-user 安装状态；该文件可能为文本 XML 或 ABX（二进制 XML，magic 为 `ABX\0`）；实现 MUST 支持两者并解析 `<pkg name="...">` 的 `inst` 布尔属性（缺省视为 `true`）。  
系统 MUST 通过 `fullUid = userId * 100000 + appId`（或等价 helper）构建每个 user 下的实例，并为每个 `(package, userId)` 生成独立 App 实例。

#### Scenario: Work-profile-only install creates only that user instance
- **GIVEN** 某包在 `packages.list` 中存在且其 `appId` 为有效应用 UID  
- **WHEN** 该包在 user 10 的 `package-restrictions.xml` 中 `inst=true`，且在 user 0 的对应文件中 `inst=false`（或不存在该 user）  
- **THEN** 系统 SHALL 仅创建/维护 `uid = 10*100000 + appId` 对应的 App 实例，而不会错误创建 user 0 的实例  

#### Scenario: Same package installed in multiple users yields multiple uids
- **GIVEN** 某包在 `packages.list` 中存在且其 `appId` 为有效应用 UID  
- **WHEN** 该包在多个 user 的 `package-restrictions.xml` 中均为 `inst=true`  
- **THEN** 系统 SHALL 为每个 userId 生成各自的 `fullUid` 并创建多个独立 App 实例（UID 不同），从而实现多用户隔离  

#### Scenario: Transient parse/read failure does not uninstall apps
- **WHEN** `PackageListener` 在一次更新中无法读取或解析某个必要输入文件（例如 `package-restrictions.xml` 正在原子替换导致短暂不可读）  
- **THEN** 系统 SHALL 保持上一份已知的聚合快照不变，并在后续重试更新；不得因为本次失败而将大量 App 误判为卸载并触发 `appManager.remove`  

#### Scenario: Malformed input is ignored safely
- **WHEN** `PackageListener` 遇到格式错误、包名包含非法字符、appId/uid 非应用范围、或 XML 中出现无法解析的 `<pkg>` 条目  
- **THEN** 系统 SHALL 安静跳过该条目，不创建任何 App，也不破坏已有映射  

### Requirement: Security constraints for package-state parsing and path construction
为防止利用包状态文件或持久化路径的输入构造进行注入或路径遍历攻击，系统 MUST 在解析 `/data/system/packages.list` 与 `/data/system/users/<userId>/package-restrictions.xml` 时对包名与数值字段执行安全约束，并在构造 per-user 路径时执行安全约束。

#### Scenario: Package name with control characters is rejected
- **WHEN** `PackageListener` 在 `packages.list` 或 `package-restrictions.xml` 中遇到包名包含换行符、NUL 或其他控制字符  
- **THEN** 系统 SHALL 安静跳过该条目，不创建 App，也不更新现有映射，以防止注入与解析混淆类攻击  

#### Scenario: Per-user path construction validates userId and prevents traversal
- **WHEN** 系统为 `userId > 0` 的 App 构造持久化路径  
- **THEN** SHALL 先验证 `userId` 在预设的合理范围内（例如 `0 ≤ userId < 10000`），并通过前缀检查或 `realpath` 等方式确保最终路径仍位于 `/data/snort/` 根目录下，不允许通过恶意 userId 或字符串组合构造出越界路径，从而规避路径遍历攻击  

### Requirement: Per-user persistence directories
系统 MUST 在保持 user 0 持久化路径不变的前提下，为 `userId > 0` 的 App 使用单独的 per-user 保存目录，例如 `/data/snort/save/user<userId>/packages/` 与 `/data/snort/save/user<userId>/system/`，并集中由 `Settings` 层负责目录生成与创建。

#### Scenario: User 0 persists to legacy paths
- **WHEN** 系统在 user 0 下为 App 持久化统计或配置  
- **THEN** SHALL 继续使用当前的 `saveDirPackages/saveDirSystem/saveDirDomainLists` 路径，不引入额外的 `user0` 子目录，以保证旧版本可以读取这些文件  

#### Scenario: Non-zero user persists to per-user paths
- **WHEN** 系统需要为 `userId > 0` 的 App 持久化统计或配置  
- **THEN** SHALL 使用 `Settings` 提供的 per-user helper，在 `/data/snort/save/user<userId>/...` 下创建并写入对应文件，而不会与 user 0 的文件混用  

### Requirement: Control AppSelector semantics for multi-user
控制协议中所有接受 `<uid|str>` 的命令 MUST 统一遵循以下选择规则：  
- 纯数字参数始终解释为完整 Linux UID；  
- 字符串参数解释为包名，可选后跟 `USER <userId>` 子句以指向特定用户下的实例；  
- 未显式附带 `userId` 的字符串参数默认匹配主用户（user 0）下的实例。

#### Scenario: Numeric uid selects exact app instance
- **WHEN** 客户端调用形如 `APP.UID <uid>` 的命令，且 `<uid>` 为某个应用实例的完整 Linux UID  
- **THEN** 控制层 SHALL 直接使用该 UID 查找 App（不进行取模），并仅对该实例返回或修改状态  

#### Scenario: Package name without userId defaults to user 0
- **WHEN** 客户端调用形如 `APP.NAME <package>` 的命令且未附带 `USER <userId>` 子句  
- **THEN** 控制层 SHALL 在主用户（user 0）下按子串匹配查找对应的 App，并对该实例执行查询或操作；如果 user 0 下不存在匹配，则 SHALL 不隐式跨用户选择其它实例  

#### Scenario: Package name with USER clause selects user-specific app
- **WHEN** 客户端调用形如 `APP.NAME <package> USER <userId>` 的命令  
- **THEN** 控制层 SHALL 仅在给定 `userId` 下按子串匹配选择 App，并对该实例执行查询或操作，而不会跨其它用户合并结果  

### Requirement: Stream events expose uid and userId
DNS、数据包以及 Activity 流事件的 JSON 表示 MUST 在不移除现有字段的前提下，新增 `uid` 与 `userId` 字段，使上层调用者可以按用户维度过滤或聚合事件。

#### Scenario: DNS stream includes uid and userId
- **WHEN** 客户端使用 `DNSSTREAM.START` 订阅 DNS 事件  
- **THEN** 每条 DNS 事件 SHALL 在顶层对象中包含与该请求关联的 App 的 `uid` 与 `userId` 字段，并与 App 查询命令中的值保持一致  

#### Scenario: Packet stream includes uid and userId
- **WHEN** 客户端使用 `PKTSTREAM.START` 订阅数据包事件  
- **THEN** 每条数据包事件 SHALL 在顶层对象中包含与该流量关联的 App 的 `uid` 与 `userId` 字段，并与对应统计命令（例如 `APP.A`）中的视图一致  

#### Scenario: Activity stream includes uid and userId for foreground app
- **WHEN** 客户端使用 `ACTIVITYSTREAM.START` 订阅前台 Activity 事件  
- **THEN** 对于存在前台 App 的事件，顶层对象 SHALL 包含该 App 的 `uid` 与 `userId` 字段，使前端可以准确区分不同用户下的前台应用  

### Requirement: RESETALL clears multi-user persisted state
控制命令 `RESETALL` MUST 在保持设备级“恢复初始状态”语义的前提下，清理 `/data/snort/save` 根目录下所有 user 0 与 `user<userId>` 子目录中的持久化数据，并在完成后保证基础目录仍然存在以供继续运行。

#### Scenario: RESETALL clears all user save trees
- **WHEN** 客户端通过控制协议执行 `RESETALL` 命令  
- **THEN** 系统 SHALL 在持有全局监听锁的前提下，依次重置各 Manager 的内存状态，并调用 Settings 提供的 helper 递归删除 `/data/snort/save` 下的所有 per-user 持久化文件与目录，随后重新创建必需的基础目录  

### Requirement: App JSON exposes uid, userId and appId
所有返回 App 对象的控制命令（例如 `APP.UID` / `APP.NAME` / `APP<v>` / `APP.DNS<v>` 等）MUST 在 JSON 中同时暴露 `uid`、`userId` 和 `appId` 字段，其中：  
- `uid` 表示完整 Linux UID（含 userId 高位）；  
- `userId` 为从 `uid` 推导出的 Android 用户 ID；  
- `appId` 为从 `uid` 推导出的 per-user 应用 ID。  
旧有字段（如 `name`、`blocked`、`blockIface`、`tracked`、`useCustomList` 等）MUST 保持存在并保持含义不变。

#### Scenario: APP.UID lists all apps with uid/userId/appId
- **WHEN** 客户端调用 `APP.UID`（无参数）  
- **THEN** 系统 SHALL 列出当前所有 App 实例（跨所有用户），并对每个 App 对象输出 `uid`（完整 UID）、`userId`（从 UID 推导的用户 ID）以及 `appId`（从 UID 推导的 per-user appId）字段  

#### Scenario: APP.NAME returns single app with full identity
- **WHEN** 客户端调用 `APP.NAME <uid>`，且 `<uid>` 为某个应用实例的完整 Linux UID  
- **THEN** 返回数组中至多包含一个 App 对象，并且该对象的 `uid` 字段等于传入 UID，对应的 `userId`/`appId` 字段与 Android UID 公式一致  

### Requirement: App list commands support USER filters
命令 `APP.UID` 与 `APP.NAME` MUST 在默认情况下提供跨所有用户的设备级列表视图，并且 MAY 接受可选的 `USER <userId>` 子句以按用户过滤列表；`USER` 子句仅作为过滤条件，不改变单个 App 对象的含义。

#### Scenario: APP.UID USER filters app list by userId
- **WHEN** 客户端调用 `APP.UID USER <userId>`  
- **THEN** 系统 SHALL 仅列出给定 `userId` 下的所有 App 对象，每个对象仍然包含完整的 `uid` / `userId` / `appId` 字段，其中 `userId` 字段等于传入的 `<userId>`  

#### Scenario: APP.NAME USER filters app list by userId
- **WHEN** 客户端调用 `APP.NAME USER <userId>`  
- **THEN** 系统 SHALL 仅列出给定 `userId` 下的所有 App 对象，并按 `app->name()` 的字典序排序；返回的每个 App 对象的 `userId` 字段等于传入的 `<userId>`  

### Requirement: Stats commands preserve device-wide view and support user filters
统计类命令 MUST 在默认情况下保持“设备级视图”（跨所有用户的合计语义），并在需要时通过显式 `USER <userId>` 子句提供按用户过滤的视图：  
- `ALL<v>` / `<TYPE><v>` 等总览命令在当前阶段仅提供设备级视图，不接受 `USER` 子句；  
- `APP<v> [<uid|str>]` / `APP.DNS<v> [<uid|str>]` / `BLACK.APP<v> [<uid|str>]` 等命令在默认情况下跨所有用户统计，但允许追加 `USER <userId>` 子句以限制在指定用户下的 App；  
- `APP.RESET<v> [<uid|str>|ALL]` 在设备级语义基础上扩展 `ALL USER <userId>` 形式，仅重置指定用户下的所有 App 统计。

#### Scenario: APP.A shows device-wide totals by default
- **WHEN** 客户端调用 `APP.A`（无参数）  
- **THEN** 系统 SHALL 返回跨所有用户的 App 数组，每个对象包含各自的统计视图，但整体视图代表“设备级总览”，而不是单一用户  

#### Scenario: APP.A USER filters stats to single user
- **WHEN** 客户端调用 `APP.A USER <userId>`  
- **THEN** 系统 SHALL 只返回给定 `userId` 下的 App 数组，其统计仅计入该用户下的流量，而不包含其他用户  

#### Scenario: APP.RESET supports ALL USER form
- **WHEN** 客户端调用 `APP.RESET.0 ALL USER <userId>`  
- **THEN** 系统 SHALL 仅重置该 `userId` 下所有 App 的 DAY0 统计，而不影响其他用户或 ALL 视图的历史累积  

### Requirement: Custom lists and per-app rules respect AppSelector
所有涉及 per-app 自定义黑白名单与自定义规则的控制命令（例如 `CUSTOMLIST.ON/OFF`、`BLACKLIST.ADD/REMOVE/CLEAR`、`WHITELIST.*`、`BLACKRULES.*`、`WHITERULES.*` 等）MUST 通过 AppSelector 选中具体 App 实例：  
- 数字 `<uid>` 参数始终指向单个 App（完整 UID）；  
- 字符串 `<str>` 不带 `USER` 时仅匹配主用户（user 0）；  
- 字符串带 `USER <userId>` 时仅匹配指定用户下的实例。  
不带 `<uid|str>` 的命令（例如纯全局黑白名单操作）MUST 保持设备级语义，对所有用户生效。

#### Scenario: CUSTOMLIST.ON toggles per-app flag for selected instance
- **WHEN** 客户端调用 `CUSTOMLIST.ON <package> USER <userId>`  
- **THEN** 系统 SHALL 仅对 `(package, userId)` 对应的 App 实例设置 `useCustomList = true`，不会影响其他用户下同名应用或全局自定义名单  

#### Scenario: BLACKLIST.ADD without uid acts as device-wide list
- **WHEN** 客户端调用 `BLACKLIST.ADD <domain>`（不带 `<uid|str>`）  
- **THEN** 系统 SHALL 将该域名加入设备级全局黑名单，对所有用户的所有 App 生效，而不是仅对某个单一用户的自定义名单  

### Requirement: Command argument safety for name + userId
对于 `<uid|str>` 参数之后仍然接受整数参数的命令（例如 `BLOCKMASK <uid|str> [<mask>]`、`BLOCKIFACE <uid|str> [<mask>]`、`BLACKRULES.ADD <uid|str> <ruleId>` 等），第二个整数参数 MUST 一律视为命令自身参数（掩码、规则 ID 等），不得被解释为 `userId`。  
只有在 `<uid|str>` 之后本身不再接受其他整型参数的命令（例如 `APP.UID` / `APP.NAME` / `APP<v>` / `APP.RESET<v>` / `TRACK` / `UNTRACK` / `APP.CUSTOMLISTS` 等）才允许将 `<str> <userId>` 解释为 `(name, userId)`。

#### Scenario: BLOCKMASK interprets second int as mask, not userId
- **WHEN** 客户端调用 `BLOCKMASK <package> 5`  
- **THEN** 控制层 SHALL 将 `5` 解释为 blockMask 数值，而不是 userId；如需按用户选择 App，客户端 MUST 使用 `BLOCKMASK <package> USER <userId> <mask>` 的形式  

### Requirement: TOPACTIVITY only accepts uid
控制命令 `TOPACTIVITY` MUST 仅接受 `<uid>` 形式的参数，并且该 UID SHALL 被视为完整 Linux UID；命令实现不得接受包名字符串或在内部对 UID 进行取模。

#### Scenario: TOPACTIVITY uses full uid to select foreground app
- **WHEN** 客户端调用 `TOPACTIVITY <uid>`，且 `<uid>` 为某个 App 实例的完整 Linux UID  
- **THEN** 系统 SHALL 使用该 UID 调用 `appManager.make(uid)` 更新前台 Activity，并通过 Activity 流推送包含对应 `uid`/`userId` 信息的事件  

### Requirement: Device-wide views reject USER filters
仍然保持设备级视图语义的命令（例如 `ALL<v>` / `<TYPE><v>`、`DOMAINS<v>`、`DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 等）MUST 不接受 `USER <userId>` 子句；如客户端传入 `USER` 子句，系统可以忽略该子句或返回错误，但不得 silently 改变这些命令的设备级语义。

#### Scenario: ALL.A ignores USER clause
- **WHEN** 客户端调用 `ALL.A USER <userId>`  
- **THEN** 系统 SHALL 仍然返回设备级总览统计（跨所有用户），而不是仅统计某个 `userId` 的流量，并且文档中 MUST 明确该命令不支持 `USER` 过滤  

### Requirement: HELP documents multi-user argument forms
控制命令 `HELP` MUST 准确描述多用户相关参数语义，保证调用方可以仅通过 HELP 文本理解 `<uid|str>` 与 `USER <userId>` 的用法：  
- 对所有标注为 `<uid|str>` 的位置，HELP 输出 SHALL 明确：`<uid>` 为完整 Linux UID、`<str>` 默认为 `(packageName, userId=0)`，以及在命令本身不再接受额外整型参数时允许使用 `<str> <userId>` 与 `<str> USER <userId>` 形式；  
- 对仍然保持设备级视图语义且不支持 `USER` 过滤的命令（例如 `ALL<v>` / `<TYPE><v>`、`DOMAINS<v>`、`DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 等），HELP 输出 MUST 明确这些命令不接受 `USER <userId>` 子句。

#### Scenario: HELP shows uid/str and USER forms
- **WHEN** 客户端调用 `HELP` 并查看与 `<uid|str>` 相关的命令说明  
- **THEN** 文本 SHALL 同时描述 `<uid>` 为完整 UID、`<str>` 默认为主用户实例、`<str> <userId>` 与 `<str> USER <userId>` 的扩展写法，以及哪些命令不支持 `USER` 过滤，从而使调用方可以据此正确构造多用户相关调用  

### Requirement: Backward-compatible stream restore
历史 DNS / Packet / Activity 流的持久化格式 MUST 保持兼容：  
- 旧版本保存的流事件仅基于名称信息恢复时，系统 SHALL 将这些事件视为来自主用户（user 0）；  
- 实现不得尝试从旧格式流数据中推断非 0 用户 ID，以避免产生不一致的状态。

#### Scenario: Restored DNS stream events default to user 0
- **WHEN** 系统从旧版本遗留的 DNS 流持久化文件中恢复事件  
- **THEN** 每条恢复出的事件 SHALL 在对外 JSON 中带有 `userId = 0`，并被视为来自主用户，而不会被错误地映射到其他用户  
