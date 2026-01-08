# sucre-snort 多用户重构设计文档

## 0. 设计原则（核心约束）

- **核心以 UID 为唯一一等主键**：内部模块（`App`、`AppManager`、`DnsListener`、`PacketListener`、`Activity` 等）统一以完整 Linux UID 作为唯一主键，不再在核心逻辑中解析 `<uid|str>` 或依赖包名；包名与 userId 的解析、兼容逻辑集中在适配/兼容层（例如 `Control`、`PackageListener`、持久化路径生成）。
- **App 级接口的主用户兼容**：所有以 App 为目标并接受 `<uid|str>` 的既有命令，`<uid>` 一律解释为完整 Linux UID；字符串 `<str>` 不带 userId 时默认指向主用户（user 0）下的实例。如需访问其它用户下同名应用，必须显式传递完整 UID 或 `(packageName, userId)` 组合。
- **“全局”列表/配置保持设备级语义**：黑/白名单、规则、全局统计、Host 视图等命令仍按设备级视角工作，多用户只会增加数据来源的 App/流量，而不改变命令本义。持久化路径继续以 `saveDirPackages` / `saveDirSystem` / `saveDirDomainLists` 为 user 0 的兼容根目录，其它用户通过 `user<userId>/...` 子目录扩展，不改变既有目录含义。
- **多用户能力通过“显式选择”暴露**：多用户相关语义只通过显式选择生效，例如传递完整 UID、传递 `(packageName, userId)` 组合，或在部分命令中追加 `USER <userId>` 子句。旧的无参数视图和仅有 `<str>` 的写法在多用户设备上仍然有效，只是自然扩展为“看见更多 UID / App”，不隐式改变命令名。

## 1. 最终方案（当前结论）

- 内部统一使用完整 Linux UID，不再对 UID 取模；`App::_uid`、`AppManager` 等全部以完整 UID 为唯一键。
- 数据源与职责拆分（均为系统文件，只读解析聚合，不依赖执行 `pm` 等命令）：
  - `/data/system/packages.list`：提供全局 `packageName ↔ appId`（以及 shared UID 的别名集合等）信息；**不表达 per-user 安装状态**。
  - `/data/system/users/<userId>/package-restrictions.xml`：提供 per-user 的包安装状态（AOSP 字段名例如 `inst`）；用户集合来自 `/data/system/users/userlist.xml`（或枚举 `/data/system/users/` 数字目录兜底）。
- 所有现有“传 UID”参数的命令保持不变，只是 UID 的取值从“appId”升级为“完整 Linux UID（含 userId 高位）”：  
  - 对于旧客户端，仍然可以像过去一样只在 user 0 上使用 appId 范围内的 UID，行为不变；  
  - 对于新客户端，如果传入完整 Linux UID，则可以显式指向任意用户下的实例，这一能力只在新调用方有意识使用时才生效。
- 所有接受 `<uid|str>` 的命令扩展为：
  - 数字参数：始终解释为完整 UID；
  - 字符串参数：解释为包名，可选跟一个 `userId` 参数；
  - 未显式给出 `userId` 时，字符串路径默认为主用户（user 0），与当前行为保持一致。
- 仅在字符串模式下 `userId` 才有意义；UID 模式下不再依赖包名或 userId。
- 持久化路径按 user 分层设计：user 0 继续沿用现有路径，其它用户进入 `/data/snort/save/user<userId>/...` 等子目录；具体迁移方案后续细化。
- 不新增新的控制命令，只在现有命令的参数解析与返回 JSON 中增加对完整 UID / userId 的支持。

## 2. 决策过程记录（精简版）

### 2.1 现状确认

- 阅读 `sucre-snort/src`：所有入口（NFQUEUE、DnsListener、Control）拿到的是完整 Linux UID。
- 在 `AppManager::make` 与 `Control::arg2app` 中统一做了 `% 100000`，仅保留 appId。
- 结果：同一应用在不同 Android 用户下的流量统计与策略全部按 appId 聚合，多用户信息在 SNORT 层被主动丢弃。

### 2.2 数据源调研与事实确立

- `/data/system/packages.list` 的定位：全局 `packageName ↔ appId`（以及 shared UID 的别名集合）索引；写入端在 AOSP 仍标注“未处理多用户”，因此该文件**不承载 per-user 安装状态**，也不能直接用于判断某包“安装在哪些 userId”。
- per-user 安装状态的权威来源：`/data/system/users/<userId>/package-restrictions.xml`（其中 `<pkg name="...">` 的 `inst` 等字段描述该 user 下的安装/隐藏/停用状态）。
- 结合公开资料与设备验证，确认 UID 公式：
  - `linuxUid = userId * 100000 + appId`，系统应用与普通应用一致。
- 结论：多用户下需要通过 `packages.list` + per-user `package-restrictions.xml` 做文件级聚合，才能得到正确的 `(userId, package, uid)` 安装视图；并保留“运行期先见 UID、后补全名称”的兜底路径。

### 2.3 方案空间与取舍

- 方案 A：内部完全 UID 化，外部接口也只接受 UID，不再支持包名 / appId 写操作。
- 方案 B：内部完全 UID 化，但对外保持现有接口形态，在 UID 基础上为字符串路径增加可选 `userId`，字符串缺省 userId 时等价于当前“主用户”语义。
- 分析结果：
  - 两种方案在“内部重构”的成本相近（完整 UID + 持久化分层是共同必做项）。
  - 方案 A 简化后端接口，但要求前端与用户立即切换到“只用 UID”模型。
  - 方案 B 在后端多维护一层“主用户兼容”分支，但可以让所有现有仅传包名的用法在 user 0 上保持稳定。

### 2.4 最终决策理由

- 统一内部模型为“完整 UID + 文件聚合数据源（`packages.list` + per-user `package-restrictions.xml`）”，保证多用户安装状态与 UID 信息不丢失。
- 保留现有命令集，通过扩展参数而非新增命令来支持多用户：
  - 兼容旧用法（仅给包名 → 默认 user 0），保证单用户设备和主用户行为完全不变。
  - 允许新客户端通过完整 UID 或“包名 + userId”访问任意用户实例。
- 明确排除“另起一套全新命令族”的方向，后续多用户接口设计一律在现有命令上演进。
- 该方案在不牺牲兼容性的前提下，为后续大规模重构（AppManager 索引、持久化布局、接口文档更新）给出了清晰的目标状态，因此作为当前唯一实现方向。

### 2.5 外部引用（事实来源）

- Android 多用户 UID 公式与包安装状态文件：
  - UID 公式来源为 AOSP 文档与设备验证：同一 appId 在不同 userId 下形成不同 Linux UID（高位 userId 不同）。
  - `packages.list`：全局 `packageName ↔ appId`/shared-UID 信息；不提供 per-user 安装状态。
  - `package-restrictions.xml`：per-user 安装状态权威来源（例如 `inst`/hidden/stopped 等）。

## 3. 兼容性与安全约束（固定前提）

- 向前兼容范围：
  - 仅保证 org.sucre.app 的对接接口，以及 sucre-snort 的对外控制协议保持向前兼容（命令名与基本语义不变）。
  - 不承诺旧版本生成的本地保存文件（统计快照、应用配置等）在新版本下完全可用；会尽量兼容，但不做保证。

- `packages.list` / `package-restrictions.xml` 解析安全：
  - 已知存在与 `packages.list` 相关的换行注入安全漏洞（CVE-2024-0044 系列，2024 年起在 AOSP 中修复）。
  - 读取 `/data/system/packages.list` 与 `/data/system/users/<userId>/package-restrictions.xml` 时必须对包名做格式校验（拒绝包含换行符、NUL 等控制字符），并对 appId/UID 与 userId 做范围校验（仅接受合法应用 UID）。
  - 本文后续讨论默认“UID 与包名已在单点完成严格校验”，不再在各处重复展开。

- userId 用于构建路径的约束：
  - userId 只能在受控范围内用于构建保存路径（例如 `/data/snort/save/user<userId>/...`），必须先验证 userId 合法性（数值范围）。
  - 任何由 userId 拼接出的路径在使用前都必须确保解析后的真实路径仍位于 `/data/snort/` 根目录下，以规避路径遍历风险。
  - 后续设计中如涉及按 userId 分层的持久化目录，均隐含遵守上述约束。

## 接口兼容与行为变化

与 [[INTERFACE_SPECIFICATION.md]] 相比

### 1. App 级命令（`<uid|str>`）

- 统一规则：`<uid>` 始终为完整 Linux UID，精确指向某个用户下的单个 App；字符串 `<str>` 不带 userId 时只匹配 user 0 下的实例。如需访问其它用户：
  - 对于在 `<uid|str>` 之后**不再接受额外整型参数**的命令（例如 `APP.UID` / `APP.NAME` / `APP<v>` / `APP.RESET<v>` / `TRACK` / `UNTRACK` / `APP.CUSTOMLISTS` 等），可以使用 `<str> <userId>` 或 `<str> USER <userId>` 两种形式；
  - 对于在 `<uid|str>` 之后还接受自身整型参数的命令（例如 `BLOCKMASK <uid|str> [<mask>]`、`BLOCKIFACE <uid|str> [<mask>]`、`BLACKRULES.ADD <uid|str> <ruleId>` 等），**仅**支持 `<str> USER <userId>` 形式，避免与后续整数参数含义冲突。
- `APP.UID` / `APP.NAME`：语义保持“列出所有 App”不变，多用户下会出现更多 UID；JSON 中 `uid` 升级为完整 Linux UID，并补充 `userId` / `appId` 字段。
- `APP<v>` / `APP.<TYPE><v>` / `<COLOR>.APP<v>`：无参数视图继续表示“所有 App 的总览”（跨所有用户），按 UID 维度聚合；带 `<uid|str>` 时遵循统一规则，可以通过 `<uid>` 或 `<str> USER <userId>` / `<str> <userId>` 精确选中单个用户下的实例。
- `APP.RESET<v>`：`<uid>` / `<str>` / `<str> USER <userId>` / `<str> <userId>` 按统一规则选中单个 App 并重置其统计；`ALL` 在多用户下被解释为“重置所有 App 的对应视图”（跨所有用户）。
- `BLOCKMASK` / `BLOCKIFACE`：保留 `BLOCKMASK <uid|str> [<mask>]` / `BLOCKIFACE <uid|str> [<mask>]` 语义，引入可选子句 `USER <userId>`，仅在 `<str>` 模式下用于指定 `(packageName, userId)`；`<uid>` 模式不需要 `USER`，且不解析 `<str> <userId>` 简写。
- `TRACK` / `UNTRACK` / `APP.CUSTOMLISTS`：按统一规则支持 `<uid>`、`<str>`、`<str> USER <userId>` 和（在不跟随额外整型参数的前提下）`<str> <userId>`，不改变命令本义。
- `CUSTOMLIST.*` / `BLACKLIST.*` / `WHITELIST.*`：全局列表（无 `<uid|str>`）语义不变，多用户下对所有用户生效；带 `<uid|str>` 形式按统一规则精确作用于某个用户下的 App。字符串形式如需指向非 0 用户，必须使用 `USER <userId>` 子句。
- `BLACKRULES.*` / `WHITERULES.*`：内部仍以 UID 作为唯一标识，多用户下通过完整 UID 区分用户；控制命令层面支持：
  - `<ruleId>`：仅以域名层面启用/禁用规则（全局）；
  - `<uid> <ruleId>`：对指定 UID 的 App 启用/禁用规则；
  - `<package> USER <userId> <ruleId>`：通过 `(packageName, userId)` 选中 App，再启用/禁用规则。  
  不支持 `<package> <userId> <ruleId>` 简写，避免与 `<ruleId>` 参数冲突。

### 2. 流命令

- `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START`：语义保持为“设备级流视图”，多用户环境下包含所有用户的事件，**不支持 `USER <userId>` 子句**。  
  用户级过滤职责完全交由前端：客户端可在接收到的事件 JSON 中按 `userId` 字段自行筛选。
- 流事件 JSON 中补充 App 的 `uid` / `userId` / `appId` 字段，便于前端在客户端按用户过滤或分组展示。

### 3. 全局统计与域名统计

- `ALL<v>` / `<TYPE><v>`：语义保持“全局统计”不变，多用户下统计所有用户的流量总和，不拆 per-user 视图，不引入 `USER` 子句。
- `DOMAINS<v>` / `<BLACK|WHITE|GREY><v> [<str>]`：继续表示域名层面的全局视图，多用户下按域名聚合所有用户的贡献；`[<str>]` 仅作为名称过滤，不携带 userId 语义。

## 实现细节草案（待讨论）

> 本节是基于当前代码阅读与目标方案抽出来的“实现草案”，按步骤从内部模型 → I/O → 控制协议 → 迁移与测试分解。  
> 这些内容是讨论材料，不代表已经拍板的最终设计；后续讨论结果再同步回前面的“最终方案”章节。

### 第一部分（条目 1–7）：内部模型与 App/AppManager 基础

1. 内部 UID 模型与取值约束
   - `App::Uid` 在整个进程内统一表示“完整 Linux UID”（含 userId 高位），类型仍为 32 位无符号整型，禁止在任何内部逻辑中再对 UID 做 `% 100000` 或其它压缩映射。
   - 约定 Android 应用 UID 满足 `uid = userId * AID_USER + appId`，其中 `AID_USER`、`AID_APP_START`、`AID_APP_END` 等常量统一来源于 AOSP 提供的系统头文件（例如 `android_filesystem_config.h`），`userId >= 0`。
   - 针对离线数据源（`/data/system/packages.list` 与 per-user `/data/system/users/<userId>/package-restrictions.xml`），在解析/聚合时对 appId/userId 做范围校验（仅接受合法应用 UID），并结合包名的长度/字符检查来抵御注入类问题。
   - NFQUEUE 的 `NFQA_UID`、netd socket 等运行时 UID 来源不再额外做合法性过滤，直接视为“内核事实”，交由 `AppManager::make(uid)` 按完整 UID 处理。
   - `App`、`AppManager`、`Activity`、`DnsRequest` 等内部对象中的 UID 语义全部切换为“完整 Linux UID”；任何地方如需 appId，需要显式通过 helper 从 UID 反推，不能再假定 `uid` 本身就是 appId。

2. UID → userId/appId 解析与辅助函数
   - 在 C++ 层定义一组基于 AOSP 系统常量的纯函数式 helper，用于在不依赖全局状态的前提下从 `App::Uid` 计算出 `userId` 与 `appId`，并判断某个 UID 是否属于“应用 UID”：
     - `userId(uid) = uid / AID_USER`；
     - `appId(uid) = uid % AID_USER`；
     - `isAppUid(uid)`：仅当 `appId` 落在 `[AID_APP_START, AID_APP_END]` 时认为该 UID 属于“应用 UID”。
   - 上述 helper 作为多用户相关逻辑的唯一来源：所有需要 userId 的地方（持久化路径、JSON 输出、控制命令解析等）统一通过该 helper 计算，避免在多个模块中重复写公式。
   - helper 不直接暴露给外部控制协议，只作为内部实现细节；对外仍然只暴露“完整 UID”与“userId”两个概念。

3. App 对象上的 UID / userId 访问接口
   - `App` 保持 `_uid` 成员为构造时传入的完整 Linux UID，并提供只读访问方法，例如 `uid()` / `userId()` / `appId()`，内部实现使用第 2 条中的 helper。
   - 为简化上层逻辑，在 `App` 上新增轻量级布尔接口，例如 `isSystemApp()`（多 package 共享 UID，内部 `_names.size() > 1`）与 `isUserApp()`（普通单包应用），用于区分后续持久化路径与展示逻辑。
   - Activity 流、DNS 请求流、数据包流等所有引用 App 的结构体不再自行保存 UID，而是在需要时访问 `App::uid()` / `App::userId()`，保证 UID 语义在所有输出路径上一致。

4. App JSON 输出中 UID 与 userId 的字段约定
   - 现有 `App::print` 输出字段保持兼容：继续输出 `name`、`uid`、`blocked`、`blockIface`、`tracked`、`useCustomList` 等字段，字段名不变，顺序尽量保持。
   - `uid` 字段的含义从“appId（旧行为）”提升为“完整 Linux UID”：旧客户端如果只在 user 0 设备上运行，则行为保持兼容（user 0 情况下 `uid == appId`）。
   - 在 `App::print` 及所有以 App 为主体的 JSON 输出中新增两个只读整数字段：
     - `userId`: 从 `uid` 反推得到的 Android 用户 ID；
     - `appId`: 从 `uid` 反推得到的 per-user appId。
   - 新增字段作为 App JSON 的顶层字段；推荐紧跟在 `uid` 之后输出，便于前端读取。旧客户端可以忽略；文档中说明对于多用户场景，前端应优先使用 `uid` + `userId` 组合，而不再假定 `uid` 与 appId 同义。

5. App 统计视图在多用户下的语义
   - `App` 级别统计（`AppStats`、每 App 的域名统计等）以“完整 UID 对应的单个 App 实例”为粒度，即每个 `(userId, appId)` 拥有独立的统计与策略配置。
   - `AppStats` 的全局聚合（`appManager.printStatsTotal` 等）在当前阶段仍然是“所有 App 实例的总和”，不按 userId 进一步拆分；如需按 userId 聚合，后续可以通过增加视图参数或新增命令实现，但不在本轮重构的必做范围内。
   - 文档中明确：多用户重构后，“某包在不同用户下的使用统计”在 App 维度会显示为多条独立记录（按 UID 区分），不会在 SNORT 层自动合并；全局统计仍然是“所有用户总和”的视图。

6. AppManager::make / find 的 UID 行为
   - `AppManager::make(uid)` 改为直接将传入的 `uid` 视为完整 Linux UID：不再做 `% 100000`，首先在 `_byUid` 中按完整 UID 查找，找不到时再创建新的 `App`。
   - `AppManager::find(uid)` 同样以完整 UID 为键查找，保证从所有入口（DNS、NFQUEUE、Control）拿到同一 UID 时命中同一个 `App` 实例。
   - 对于明显不应出现的 UID（例如 `uid == 0` 等特殊情况），可以通过调用 `isAppUid` 作为防御性检查并在日志中记录，但默认行为是：
     - NFQUEUE / DNS 热路径仍然直接调用 `make(uid)`，不在判决路径上增加复杂判断；
     - 是否将异常 UID 聚合到一个特殊 App（如 `system_unknown`）仅作为调试辅助选项，而不是本轮重构的必做项。

7. AppManager 名称索引与多用户下的查找语义
   - 在逻辑层面提供“按 `(name, userId)` 查找 App” 的接口：例如 `findByName(name, optional<userId>)`，主要用于控制命令（兼容旧用法）和旧数据恢复（例如旧版 DNS 流文件只保存 name），不参与 DNS/NFQUEUE 判决热路径。
   - 具体实现以 UID 索引为唯一真实来源：`findByName` 可以通过遍历 `_byUid` 中的 App，比较 `app->name()` 与 `app->userId()` 组合来完成匹配，而不是依赖单独维护的 `_byName` 主索引，避免 UID↔name 双向索引的复杂一致性问题。
   - 约定：
     - 当显式给出 `userId` 时，按 `(name, userId)` 精确查找，仅匹配该用户下的 App，不再出现“不同用户共享同一 name 的隐式合并”。
     - 当未给出 `userId` 时，仅在主用户（user 0）范围内查找；找不到则返回空结果，不在其它用户中回退匹配。
   - 保留现有 `find(const std::string &name)` 接口作为兼容层包装，语义等价于 `findByName(name, /*no userId*/)`；强调该接口仅用于兼容场景，核心热路径只使用 UID 相关接口（`make(uid)` / `find(uid)`）。

### 第二部分（条目 8–14）：多用户持久化与包安装状态聚合协同

8. AppSelector / Control::arg2app 的统一选择规则
   - 在 `Control` 层抽象出“App 选择器”的概念：针对所有使用 `<uid|str>` 的命令，统一走一条解析路径，避免各命令自行解析 `<uid|str>` 并把字符串逻辑渗透到核心模块。
   - 解析规则（仅在 `Control` 层内使用）：
     - 单个整数参数：始终解释为“完整 Linux UID”，映射为 `ByUid(uid)`，后续直接调用 `appManager.find(uid)` 或 `make(uid)`；
     - 单个字符串参数：解释为包名，隐含 `userId = 0`，映射为 `ByName(name, userId=0)`，仅针对主用户查找 App（兼容现有“字符串只表示主用户”的行为）；
     - “字符串 + 整数”两个参数：在该命令的 `<uid|str>` 之后本身不再接受其他整型参数语义时，方可解释为 `(packageName, userId)`，映射为 `ByName(name, thatUserId)`，整数为 Android 用户 ID，用于精确匹配 `(name, userId)`。
     - “字符串 USER 整数”三个 token：统一解释为 `(packageName, userId)`，映射为 `ByName(name, thatUserId)`，其中整数为 Android 用户 ID；这种写法适用于所有支持 `<uid|str>` 的命令，不与第二个整数参数原有语义（例如掩码）冲突。
   - AppSelector 的解析结果统一通过内部接口（例如 `findByUid` / `findByName(name, optional<userId>)`）与 `AppManager` 交互；核心模块（`AppManager`、`DnsListener`、`PacketListener` 等）只暴露 UID 形态的接口，不感知 `<uid|str>` 或 `CmdArg`。
   - 对于可选 `<uid|str>` 的命令（如 `APP<v>`、`BLOCKMASK` 等），统一约定：
     - 0 个参数：对所有符合命令语义的 App 生效（列表或全局操作），是否“只针对 user 0 还是跨所有用户”在第三部分的具体命令条目中单独定义；
     - 1 个参数：按照上述两种单参数解析规则处理；
     - 2 个参数：如果第一个是字符串且第二个是整数，并且该命令在 `<uid|str>` 之后本身没有其他整型参数含义，则可视为 `(name, userId)`；在其他命令中（例如第二个整数本身代表掩码的 `BLOCKMASK` / `BLOCKIFACE` 等）保持原有“第一个是 `<uid|str>`、第二个是其他参数”的含义，此时如需指定 `(name, userId)` 应使用 `<str> USER <userId>` 形态。

9. Settings 中多用户相关路径 helper
   - 在 `Settings` 中保留现有 `_snortDir = "/data/snort/"` 与 `_saveDir = "/data/snort/save/"` 的定义，作为所有持久化路径的根。
   - 现有 `saveDirPackages = _saveDir + "packages/"` 与 `saveDirSystem = _saveDir + "system/"` 显式约定为 **user 0 专用目录**，用于保持旧版本的数据布局与行为完全兼容。
   - 新增一组仅供内部使用的 helper，用于为 `userId > 0` 构造按用户分层的保存目录，例如：
     - `userSaveRoot(userId) = _saveDir + "user" + std::to_string(userId) + "/"`；
     - `userSaveDirPackages(userId) = userSaveRoot(userId) + "packages/"`；
     - `userSaveDirSystem(userId) = userSaveRoot(userId) + "system/"`。
   - helper 在构造路径时强制验证 userId 为非负整数且在合理上限内（例如 `< 10000`），并在拼接完成后通过前缀检查/`realpath` 保证最终路径仍位于 `/data/snort/` 根下，满足前文第 3 章的安全约束；这些 helper 只在持久化相关代码中使用，不参与 DNS/NFQUEUE 判决逻辑。

10. 多用户下 App 保存文件路径规则
   - 对于 user 0：
     - 共享 UID 的系统应用（`_names.size() > 1`）继续使用 `settings.saveDirSystem + std::to_string(appId)` 作为保存文件（其中 `appId` 为通过第 2 条 helper 从完整 UID 推导出的应用 ID），与旧布局一致；
     - 普通单包应用使用 `settings.saveDirPackages + packageName` 作为保存文件路径，与旧版本完全一致。
   - 对于 `userId > 0`：
     - 在构造 `App` 的持久化路径前，通过 `ensureUserDirs(userId)` 确保 `userSaveRoot(userId)` 及其 `packages/`、`system/` 子目录存在；
     - 系统应用使用 `userSaveDirSystem(userId) + std::to_string(appId)` 作为保存路径，使得同一共享 UID 在不同用户下拥有独立的系统 App 配置；
     - 普通单包应用使用 `userSaveDirPackages(userId) + packageName` 保存，与 user 0 同结构但放在各自的 `user<userId>/packages/` 子目录下。
   - 上述规则保证：
     - 旧版本仅存在 user 0 的数据在新版本下无需迁移即可继续被识别；
     - 新增用户的数据不会污染旧目录，也不会与 user 0 下的配置混淆。

11. Settings::start 与按 userId 创建目录的时机
   - `Settings::start()` 仍只负责创建基础目录：`_saveDir`、`saveDirPackages`、`saveDirSystem`、`saveDirDomainLists`，不在启动时遍历或创建所有可能的 `user<userId>` 子目录。
   - 针对 `userId > 0` 的目录，由一个新的 helper（例如 `ensureUserDirs(userId)`) 在首次需要保存该用户数据时按需创建（包括 `userSaveRoot`、`userSaveDirPackages`、`userSaveDirSystem` 等）。
   - App / AppManager 在构造 `Saver` 时不得假定目录已存在：在生成保存文件路径前必须调用上述 helper，确保目录存在后再调用 `Saver`，避免因目录不存在而 silently 丢弃保存操作。
   - `saveDirDomainLists` 当前用于存放设备级的域名列表（黑/白名单与订阅列表），其内容对所有用户生效；本轮重构不引入 per-user 域名列表目录。如后续需要为其它用户提供独立的域名列表，可在各自的 `user<userId>/domains_lists/` 子目录下扩展新的持久化布局。

12. AppManager::save / restore 在多用户下的职责
   - `save()` 行为基本不变：遍历 `_byUid` 中的所有 App，调用各自的 `save()`；每个 App 按第 10 条的路径规则写入自己的配置与统计。该接口仅由守护进程生命周期管理代码（例如 `snortSave()`）调用，不通过控制协议直接暴露。
   - `restore()` 需要扩展为多目录扫描，但遵循“先由 `PackageListener` 通过 `packages.list` + per-user `package-restrictions.xml` 建立 UID ↔ name 映射，再根据已有 App 恢复内容”的原则：
     - 首先恢复 `_stats` 全局统计；
     - 针对 user 0：
       - 扫描 `saveDirSystem`，文件名为 appId：利用第 2 条 helper 推出完整 UID，在 `_byUid` 中存在对应 UID 时调用 `App::restore` 恢复系统 App 内容；
       - 扫描 `saveDirPackages`，文件名为包名：仅当 `_byUid` 中存在某个 App 与该 name 匹配时才恢复，否则视为孤儿文件并可按当前行为清理；
     - 针对其他用户：
       - 遍历 `_saveDir` 下形如 `user<userId>/system/` 与 `user<userId>/packages/` 的子目录；`system/` 下的文件名仍为 appId，利用 helper 推出完整 UID，并对已存在的 App 对象调用 `restore`；`packages/` 目录按 `(userId, packageName)` 匹配已有 App 后再恢复。
   - 为避免在 `restore()` 阶段与 `PackageListener::updatePackages()` 互相踩踏，`restore()` 仅负责“已有 App 对象对应文件的内容恢复”，不主动创建新的 UID；App 对象可以在运行期由 `AppManager::make(uid)`（例如 NFQUEUE/DNS 热路径首次遇到某 UID 时）或 `PackageListener::updatePackages()` 创建，**UID ↔ 包名映射以 `PackageListener` 的聚合结果为准**（包名/appId 来自 `packages.list`，per-user 安装状态来自 `package-restrictions.xml`），AppManager 内部始终以 UID 为唯一主键。

13. PackageListener::updatePackages 的多用户语义
   - 数据源由两部分组成（均为读文件解析，不执行 `pm`）：  
     - `Settings::packagesList`（`/data/system/packages.list`）：提供全局 `packageName -> appId` 以及 `appId -> names[]`（shared UID / 别名集合）映射；解析时仅使用每行前两个 token（`name uid`），其中 `uid` 视为 user 0 的 UID（等价 appId），其余字段丢弃。  
     - `/data/system/users/<userId>/package-restrictions.xml`：提供 per-user 的已安装包集合；读取 `<pkg name="...">` 的 `inst` 属性（缺省视为 true），并以用户集合（`/data/system/users/userlist.xml` 或 users 目录枚举）为范围进行聚合。  
   - `updatePackages()` 的输出仍然是 `_names: fullUid -> names[]`（键始终是完整 Linux UID）：  
     - 对每个 `(userId, packageName)` 的 installed 实例，通过 `packages.list` 查到 `appId`，再计算 `fullUid = userId * 100000 + appId`；  
     - 将该 `appId` 对应的 `names[]` 赋给 `_names[fullUid]`，从而自然支持 shared UID（多个包共享同一 appId）。  
   - 在完成一次完整聚合后，与旧快照做 diff：  
     - 对每个新的 `(fullUid, names)` 调用 `appManager.install(fullUid, names)` 安装新 App；  
     - 对旧快照中已不存在的 UID 调用 `appManager.remove(fullUid, names)` 卸载对应 App。  
   - 多用户情况下：  
     - 同一包在多个 user 下都 installed → 生成多个不同 `fullUid` 条目（userId 不同）；  
     - 某包只在工作空间/某个 user 下 installed → 仅生成该 user 的条目，不会错误落到 user 0。

14. PackageListener 与 AppManager 的协同顺序
   - 启动阶段仍先由 `PackageListener::updatePackages()` 基于 `packages.list` + per-user `package-restrictions.xml` 初始化基础 App 集合，再由 `AppManager::restore()` 从磁盘恢复各 App 的持久化内容；两者均在守护进程初始化阶段由 `sucre-snort` 主函数统一调度。
   - 运行期当包相关文件更新时（`packages.list`、`/data/system/users/userlist.xml`、任一 user 的 `package-restrictions.xml` 发生变化），`PackageListener` 重新聚合 UID ↔ 包名映射并调用 `appManager.install/remove`，不直接操作任何持久化文件；持久化文件的读写由各模块的 `save/restore` 负责，`AppManager` 仍然只以 UID 为主键管理 App 实例。
   - 对于 race 情况（例如 DNS/Packet 在某 UID 第一次出现前先于聚合完成），保持当前行为：允许临时存在“没有名称的 App”（由 `AppManager::make(uid)` 创建并挂在 `_byUid` 上），一旦 `PackageListener` 的聚合结果中出现该 UID，即通过 `install(uid, names)` 补全名称和别名；在多用户场景下，同一包在不同用户下拥有不同 UID，这一行为按 UID 自然区分，不需要额外的 userId 分支处理。

### 第三部分（条目 15–21）：控制协议与命令语义

15. `<uid|str>` 控制命令的统一参数文档
   - 所有在帮助文本中使用 `<uid|str>` 的命令，其真正支持的参数形态在文档中统一描述为：
     - `<uid>`：完整 Linux UID，十进制整数；
     - `<str>`：包名字符串，默认等价于 `(packageName, userId=0)`；
     - `<str> <userId>`：包名 + Android 用户 ID 组合，精确指向某个用户下的实例，仅适用于在 `<uid|str>` 之后本身不再接受其他整型参数的命令（例如 `APP.UID` / `APP.NAME` / `APP.RESET<v>` 等）；
     - `<str> USER <userId>`：包名 + Android 用户 ID 组合，推荐写法，适用于所有支持 `<uid|str>` 的命令，不会与第二个整数参数原有语义（例如掩码）冲突。
   - 文档中明确指出：旧客户端如果仅在主用户（user 0）上使用，原有只传 `<uid>` 或 `<str>` 的写法在新版本下行为等价；新客户端如需访问其它用户，必须显式传入 `userId`（通过 `<str> <userId>` 或 `<str> USER <userId>`）。
   - 对于 APP.RESET 这类复合语义命令，额外文档化 `ALL` 与 `(name, userId)` 的优先级与冲突处理规则，保证 CLI 行为可预期。

16. APP.UID / APP.NAME 命令在多用户下的行为
   - `APP.UID`：
     - 无参数时，按 UID 升序列出所有用户下的所有 App（设备级视图）；
     - `USER <userId>` 时，列出该 userId 下的所有 App；
     - `APP.UID <uid>` 参数时，视为完整 Linux UID，仅输出该 UID 对应的单个 App 对象（或空数组），不受 `USER` 子句影响；
     - `APP.UID <str>` 时，按子串匹配主用户（user 0）下 name 包含 `<str>` 的 App；
     - `APP.UID <str> <userId>` 或 `APP.UID <str> USER <userId>` 时，仅在给定 userId 下按子串匹配 name。
   - `APP.NAME`：
     - 无参数时，以 “`app->name()` 的字典序排序”列出所有用户下的所有 App（设备级视图）；
     - `USER <userId>` 时，以相同方式列出该 userId 下的所有 App；
     - `APP.NAME <uid>` 时，语义等价于 `APP.UID <uid>`：将参数视为完整 Linux UID，仅输出该 UID 对应的单个 App 对象（或空数组），不受 `USER` 子句影响；
      - `APP.NAME <str>` 时，仅在主用户（user 0）下按子串匹配 name；
      - `APP.NAME <str> <userId>` 或 `APP.NAME <str> USER <userId>` 时，仅在给定 userId 下按子串匹配 name。
   - 两条命令的 JSON 输出格式尽量保持现有字段不变，通过新增 `userId` 等字段表达多用户信息；原有“无参数”调用仍然表示“所有 App”的列表视图，多用户环境下仅会多出 `userId > 0` 的条目。

17. APP.<v> / BLACK.APP 等统计命令的参数语义
   - 所有形如 `APP<v> [<uid|str>]`、`APP.DNS<v> [<uid|str>]`、`BLACK.APP<v> [<uid|str>]` 等命令，统一采用第 8 条的 AppSelector 规则。
   - 无参数时，统计针对所有用户下的所有 App（设备级总览）：返回数组中的每项带 `uid`/`userId` 字段。
   - 追加 `USER <userId>` 子句时（例如 `APP.DNS.0 USER 10`、`BLACK.APP.A USER 10`），表示在相同语义下仅对给定 userId 下的所有 App 进行统计。
   - 带 `<uid>` 时，只对指定 UID 的 App 输出对应统计（可指向任意用户）；
   - 带 `<str>` 或 `<str> USER <userId>` 时，只对 AppSelector 选中的单个 App 做统计，字符串形式默认在主用户（user 0）范围查找。
   - 这一层语义不改变统计本身的定义，只改变“如何从控制协议中选中某个 App 实例”；默认视图即为跨所有用户的总和，如需按用户拆分则通过 `USER <userId>` 子句实现。

18. APP.RESET<v> [<uid|str>|ALL] 的细节
   - `ALL` 参数表示“对所有用户下的所有 App 执行 reset”，按设备级语义重置对应视图的统计数据。
   - `ALL USER <userId>` 扩展语法表示“仅对给定 userId 下的所有 App 执行 reset”，相当于在该用户范围内调用一次 `ALL`。
   - 当参数为 `<uid>` 时，按完整 UID 查找并仅重置该 App 的统计。
   - 当参数为 `<str>` 或 `<str> USER <userId>` 时：
     - `<str>` 兼容现有行为：等价于“user 0 下 name 匹配的 App”，找不到则无操作；
     - `<str> USER <userId>` 精确指向 `(name, userId)` 对应的 App；实现上禁止在一次调用中混用 `ALL` 与 `<uid|str>` 这两类参数。
   - 为避免歧义，APP.RESET 的实现需要特别处理字符串 `ALL`：仅当它是单独参数且 `CmdArg::STR` 时才解释为全局，否则走普通包名解析路径。

19. CUSTOMLIST.ON/OFF 与黑白名单相关命令
   - `CUSTOMLIST.ON <uid|str>` / `CUSTOMLIST.OFF <uid|str>`：按 AppSelector 解析目标 App，仅对选中 App 切换“使用自定义列表”开关；字符串形式默认仅作用于主用户（user 0）下的 App。
   - `BLACKLIST.ADD [<uid|str>] <domain>` / `WHITELIST.ADD [<uid|str>] <domain>`：
     - 单参数 `<domain>` 时保持现有“全局自定义列表”的语义，其效果为设备级全局自定义黑/白名单，对所有用户生效；
     - 两个参数时，如果第一个参数解析为 `<uid>` 或 `<str>`/`<str> USER <userId>` 形式，则仅对选中 App 的自定义黑/白名单生效，严格以 UID 区分不同用户下的同名应用，不做跨用户合并；
     - 多用户扩展点：允许使用 `<package> <userId> <domain>` 这种三参数形式，其中前两个参数组合成 AppSelector，第三个参数为域名。
   - `BLACKLIST.REMOVE` / `BLACKLIST.CLEAR` / `WHITELIST.*` 等命令沿用相同模式：不带 `<uid|str>` 时始终作用于设备级全局列表；带 `<uid|str>` 时，所有涉及 App 的位置统一用 AppSelector 描述，字符串默认仅匹配主用户（user 0），如需其它用户需显式提供 `userId`。

20. TRACK / UNTRACK 与 TopActivity 的行为
   - `TRACK <uid|str>` / `UNTRACK <uid|str>` 直接通过 AppSelector 选中具体 App，按 UID 粒度控制“是否统计该 App 的流量”，默认字符串形式仍只作用于 user 0。
   - `TOPACTIVITY <uid>` 控制命令在多用户下仍只接受 UID 形式，由前端负责传递完整 Linux UID；内部通过 `appManager.make(uid)` 获取 App 并更新 ActivityManager。
   - Activity JSON 输出中增加 `uid` 与 `userId` 字段（通过 `_app->uid()` / `_app->userId()`），前端在展示最近前台应用列表时可直接按照用户分组或过滤。
   - Activity 对象的 JSON 结构约定为：顶层始终包含 `blockEnabled` 字段；当存在前台应用 `_app` 时，再增加顶层的 `uid` / `userId` 字段以及一个嵌套的 `app` 字段，其中 `app` 内部的 App 对象遵循第 4 条的 `uid` / `userId` / `appId` 字段约定，保证前端既可以用顶层字段快速按用户过滤，也可以读取完整的内嵌 App 信息。

21. DNSListener / PacketListener 中 UID 的使用
   - `DnsListener::clientRun` 在读取 UID 时，不再对其做任何取模或裁剪，直接以完整 UID 调用 `appManager.make(uid)`，并据此选择 App 实例。
   - `PacketListener::callback` 在 NFQUEUE 报文中读取到的 `NFQA_UID` 同样被视为完整 UID，直接传入 `appManager.make(uid)`。
   - 不针对 UID 做额外的“异常值防御”或特殊聚合处理；未通过包安装状态聚合（`packages.list` + per-user `package-restrictions.xml`）建立名称映射的 UID 如有出现，仅在统计和配置层面表现为“无名称的 App”，不会影响其它 App 的行为。

### 第四部分（条目 22–26）：流数据、RESETALL 与兼容策略

22. 流命令的语义与持久化  
   - `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 在多用户下保持“设备级视图”：  
     - `DNSSTREAM.START [<horizon> [<minSize>]]` 订阅所有用户产生的 DNS 事件；  
     - `PKTSTREAM.START [<horizon> [<minSize>]]` 订阅所有用户产生的网络包事件；  
     - `ACTIVITYSTREAM.START` 订阅所有用户的前台应用事件。  
     对应的 `*.STOP` 命令保持无参数形式，只作用于当前连接上的该类流。  
   - 流的用户过滤职责交给前端：每个事件携带完整的 `uid` / `userId` / `appId` 字段，客户端如需 per-user 视图，必须在本地根据这些字段进行过滤或分组，守护进程不为每个连接维护 `filterUserId` 或类似状态。  
   - JSON 输出在保持现有字段的基础上新增多用户字段：  
     - `App::print` 中 `uid` 升级为完整 Linux UID，并新增 `userId` / `appId` 字段；  
     - DNS / Packet / Activity 流输出中在事件 JSON 顶层增加 `uid` / `userId` 字段，其数值与内嵌 App 的数值一致，原有 `app` 名称字段保持不变，确保前端可以在不解析内层结构的情况下按用户过滤。  
   - `DnsRequest::save/restore` 保持现有基于 `appName + domainName` 的文件格式不变。旧格式中的所有历史记录视为主用户（user 0）的 DNS 流，只在默认视图中回放。非 0 用户的流数据在本轮仅要求运行期可用，不要求与主用户共用同一持久化格式。  
   - DNS / Packet / Activity 流统一视为短期调试数据，不提供严格的向前兼容保证。格式调整或实现变更导致历史流丢失是可接受的，但不能影响 App 阻断策略和配置本身。

23. RESETALL 的设备级语义（唯一跨用户特例）  
   - `RESETALL` 表示“将守护进程恢复到初始状态”，包括：  
     - 重置 `Settings` 中所有全局开关为默认值；  
     - 清空所有 App 的统计与自定义规则；  
     - 清空所有域名列表与 IP 绑定；  
     - 清空 DNS / Packet / Activity 流的内存队列与持久化文件；  
     - 让 `BlockingListManager` / `RulesManager` / `HostManager` / `DnsListener` / `PacketManager` / `PackageListener` 等内部状态回到启动时的干净状态。  
   - 多用户下，`RESETALL` 按设备级语义执行：  
     - 在 `/data/snort/save` 根目录下递归清理所有用户的数据，包括 `saveDirPackages` / `saveDirSystem` / `saveDirDomainLists` 以及 `user<userId>/packages/`、`user<userId>/system/` 等子目录；  
     - 即一次 `RESETALL` 会清掉所有 userId 对应的 App / 域名 / 流数据。  
   - `RESETALL` 是本设计中唯一会同时重置所有用户配置与统计数据的命令特例；其它命令（含 `APP.RESET<v>` 系列）按前文约定的 AppSelector / `USER <userId>` 语义工作。  
   - `RESETALL` 完成后，`PackageListener::updatePackages()` 基于 `packages.list` + per-user `package-restrictions.xml` 重新聚合 UID ↔ 包名映射，多用户 App 集合在后续流量到达时按完整 UID 重新创建。

24. 兼容性与迁移策略  
   - 不在守护进程内部实现复杂迁移逻辑。旧数据能按当前格式解析则继续使用，解析失败时直接丢弃。跨版本、跨用户的精细迁移由前端管理 APP 的导出/导入负责。  
   - 对 user 0：  
     - `<uid>` / `<str>` 的旧语义在主用户场景下保持不变：`<uid>` 升级为完整 UID，但在 user 0 情况下数值等于原 appId；`<str>` 只在 user 0 范围查找 App；  
     - 旧版本生成的 `packages/` 与 `system/` 文件在结构和内容合法时按原格式恢复为主用户配置；非法或损坏文件直接删除，不尝试迁移或修复；  
     - App 统计、DNS/Packet 流视为临时调试数据，不保证升级后仍可读取。  
   - 对非 0 用户：  
     - 旧版本没有任何 `user<userId>/...` 下的数据，新版本可直接在这些目录内按新布局保存配置与统计，无需考虑历史迁移；  
     - 旧客户端仅按包名、不传 userId 时，只操作 user 0 下的实例，其他用户在旧客户端中自然“不可见”。  
   - 对控制协议：  
     - 不新增命令名，仅扩展已有命令的参数解析规则与 JSON 字段；  
     - 对于原本即为设备级视图的命令（如无参数的 `APP.UID` / `APP.NAME`、`ALL<v>` / `<TYPE><v>`、`DOMAINS<v>` 以及 `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 等），默认语义保持“跨所有用户”的设备级视图不变；  
     - 多用户能力通过显式选择暴露：对于 App 级命令，新客户端使用完整 UID 或 `(packageName, userId)` 组合以及 `USER <userId>` 子句访问特定用户实例；对于流命令，多用户信息通过事件中的 `uid` / `userId` 字段显式暴露，由前端在客户端侧选择性过滤；旧客户端在多用户设备上仍然可以像以前一样通过 `<uid>` 或 `<str>` 管理主用户（user 0）下的 App，同时在设备级视图中自然看到所有用户的聚合效果。  

25. 测试与验证要点  
   - 用户级视图与隔离：  
     - 在 user 0 与某个非 0 用户（如 user 10）下分别安装同一包，验证：默认 `APP.UID` / `APP.NAME` 会同时列出两个实例（`userId` 分别为 0 和 10），`APP.UID USER 10` / `APP.NAME USER 10` 仅列出 user 10 下的实例；  
     - 通过 `<uid>` / `<str> USER <userId>` 分别对两个实例设置不同的 `BLOCKMASK` / `TRACK` / 自定义黑白名单，检查互不影响；  
     - `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 默认输出所有用户事件；在客户端侧按 `userId` 过滤出 user 0 或 user 10 的事件，验证事件 JSON 中的 `uid` / `userId` 字段与预期一致。  
   - RESET 行为与兼容性：  
     - 在多用户设备上执行 `APP.RESET<v> ALL`，确认所有用户下所有 App 的对应视图统计都被清空；执行 `APP.RESET<v> ALL USER 10` 时仅清空 user 10 下 App 的统计，user 0 的统计保持不变；  
     - 在已存在 `user<userId>/...` 子目录时执行 `RESETALL`，确认 `/data/snort/save` 下所有用户数据被清理，`Settings` 全局开关回到默认值，后续通过包安装状态聚合自动重建 App 集合；  
     - 在仅有主用户的设备上，对比旧版本与新版本下 `RESETALL` 的行为，确认用户感知上仍然等价于“一键恢复到初始状态”。  
   - 持久化、回滚与安全：  
     - 从旧版本升级到新版本后，在 user 0 下验证旧配置（自定义列表、阻断配置等）仍按预期生效；  
     - 在新版本下为非 0 用户创建配置后回滚到旧版本，确认旧版本仅访问原有主用户目录，忽略 `user<userId>/...`，不会因多出子目录而崩溃；  
     - 构造包含非法 UID、异常包名（超长、包含控制字符、包含换行符）的 `packages.list`，验证 parser 能跳过异常行且不影响合法 UID 的处理；  
     - 在高并发 DNS/NFQUEUE 流量下执行 `RESETALL`，验证在收紧 `mutexListeners` 锁窗口后，重置过程无明显阻塞或死锁。

26. 控制端 HELP 文档与接口一致性  
   - `HELP` 命令输出的控制协议帮助文本必须与本设计中的参数语义保持严格一致：  
     - 所有标注为 `<uid|str>` 的位置，都要说明 `<uid>` 为完整 Linux UID、`<str>` 默认为 `(packageName, userId=0)`，以及 `<str> <userId>` / `<str> USER <userId>` 的扩展写法；  
     - 对仍然是设备级视图的命令（如无参数的 `APP.UID` / `APP.NAME`、`ALL<v>` / `<TYPE><v>`、`DOMAINS<v>`、`DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 等），明确在帮助文本中不支持 `USER` 子句，避免与 App 级命令混淆。  
   - 当 `INTERFACE_SPECIFICATION.md` 与本设计文档中的接口章节更新后，`Control.cpp` 中的 HELP 字符串必须同步更新，禁止出现“文档说明和实际行为不一致”的情况。

## 3. 代码实现分解（草案）

> 本章按模块拆分具体代码改动，对应前文 1–26 条语义约束。  
> 目标是让每一处修改都有“落点文件/函数 + 对应条目”的清晰映射，便于后续逐步实现和代码评审。

在进入各模块细节前，补充几条**实现期必须严格遵守的关键约束**，避免在编码时偏离设计：

- **UID 绝不再做截断或取模**：  
  - 现有代码中只有两处对 UID 做了 `% 100000`：`AppManager::make` 与 `Control::arg2app`。重构时必须**全部移除**，并确保其它任何新代码中都不再出现类似逻辑；  
  - 唯一允许“过滤 UID”的地方是在包安装状态解析/聚合阶段（`packages.list` 与 per-user `package-restrictions.xml`）使用 `isAppUid(uid)` / appId 范围校验，其余路径一律把 UID 视为内核事实。
- **App 集合的唯一来源是“包安装状态聚合 + 运行期 UID”**：  
  - `AppManager::restore()` 只能在已有 `_byUid` 集合基础上恢复内容，**不得创建新的 App**；  
  - App 的生命周期只由 `PackageListener::updatePackages()`（安装/卸载）和运行期的 `AppManager::make(uid)` 驱动。
- **所有 `<uid|str>` 命令统一走 AppSelector**：  
  - 控制层不得在单个命令内部各自解析 `CmdArg` 或再次对 UID 取模；  
  - 所有 `<uid|str>` 位置都必须通过 3.4.1 定义的 AppSelector 落到 `AppManager::find(uid)` / `findByName(name, userId)` 上。
- **`TOPACTIVITY` 严格只接受 `<uid>`**：  
  - 该命令实现中禁止再通过包名字符串查找 App；  
  - 数字参数必须被直接视为完整 Linux UID 并传入 `appManager.make(uid)`。
- **流事件的 `uid/userId` 必须来自 App 对象**：  
  - `DnsRequest` / `Packet` / `Activity` 的 `print` 顶层新增的 `uid` / `userId` 字段必须通过 `_app->uid()` / `_app->userId()` 获取，不能在流对象内部维护一份独立 UID；  
  - `save/restore` 仍然保持旧格式（仅基于名称），恢复出的历史流事件统一视为 user 0。
- **RESETALL 的文件系统清理集中在 Settings**：  
  - `Control::cmdResetAll` 在持有 `mutexListeners` 写锁时，必须调用 `Settings::clearSaveTreeForResetAll()` 一次性清理 `/data/snort/save/` 整棵树；  
  - `DnsListener` / `ActivityManager` / `PacketManager` 新增的 `reset()` 只负责清内存状态和流队列，不关闭 socket 或监听线程。

### 3.1 App / AppManager（对应条目 1, 2, 3, 4, 5, 6, 7, 10, 12）

目标：在保持现有整体结构的前提下，让 `App` / `AppManager` 完整落实“以完整 Linux UID 为唯一主键”的模型，并为后续多用户持久化和控制协议提供统一的 UID / userId / appId 语义。

#### 3.1.1 UID helper 与 App 上的 UID API（条目 1, 2, 3）

1) UID helper 的职责与位置  
- 在 C++ 层引入一组专门处理 Android UID 的 helper，用于：  
  - 从 `uid` 推导 `userId` / `appId`；  
  - 判断某个 UID 是否属于“应用 UID”（`isAppUid`）；  
  - 统一引用 AOSP 的常量（如 `AID_USER`、`AID_APP_START`、`AID_APP_END`），避免在各模块中重复写魔法数。  
- 推荐做法：  
  - 新增一个轻量头文件（如 `UidUtils.hpp`），提供：  
    - `uint32_t userId(App::Uid uid);`  
    - `uint32_t appId(App::Uid uid);`  
    - `bool isAppUid(App::Uid uid);`  
  - 或直接放在 `App.hpp` 中的一个命名空间里（例如 `namespace AndroidUid`），由 `App` / `AppManager` / `PackageListener` 等模块共同使用。

2) App 中的 UID API  
- 在 `App` 类上补齐面向多用户的 UID 访问接口：  
  - `Uid uid() const`：返回完整 Linux UID（含 userId 高位）；  
  - `uint32_t userId() const`：通过 UID helper 计算 Android 用户 ID；  
  - `uint32_t appId() const`：通过 UID helper 计算 per-user appId。  
- 为后续展示和持久化逻辑预留布尔接口：  
  - `bool isSystemApp() const`：例如定义为 `_names.size() > 1`，表示共享 UID 的系统应用；  
  - `bool isUserApp() const`：`_names.size() == 1` 的普通单包应用。  
- 要求：所有需要 userId/appId 的地方统一调用这些接口，不再在零散代码处重新写 UID 算法。

#### 3.1.2 App JSON 与统计粒度（条目 4, 5）

1) App JSON 字段升级  
- 在 `App::print` 及基于它的输出中（包括 `App::printAppStats` / `printAppNotif` 等），统一采用以下字段约定：  
  - 保留原有字段：`name`、`uid`、`blocked`、`blockIface`、`tracked`、`useCustomList` 等；  
  - 将 `uid` 的含义从“appId（旧语义）”升级为“完整 Linux UID”；  
  - 追加两个字段：  
    - `userId`：通过 `userId()` 得到；  
    - `appId`：通过 `appId()` 得到。  
- 建议将 `userId` / `appId` 紧跟在 `uid` 后输出，方便前端按用户/实例分组，同时保持旧字段顺序尽量不变，减少客户端改动范围。

2) App 统计视图的粒度  
- 以“完整 UID → 单个 App 实例”为统计单元：  
  - 每个 `(userId, appId)` 对应一个独立的 `App` 对象；  
  - 同一包名在 user 0 和 user 10 下会显示为两条独立记录（`uid` 和 `userId` 不同）；  
  - 多包共享 UID（系统/共享 UID）仍然归属一个 `App` 对象，其 `_names` 中保存所有别名。  
- 全局统计（`AppStats _stats`）仍保留设备级总览语义：  
  - `AppManager::printStatsTotal` 输出所有 App 实例（跨所有用户）的总和；  
  - 若后续需要按 userId 聚合，可在控制协议层添加新的视图命令，本轮重构不拆这一层。

#### 3.1.3 AppManager 的 UID / name 索引（条目 6, 7）

1) UID 索引 `_byUid` 完整 UID 化  
- 保持 `_byUid` 为 `std::map<App::Uid, App::Ptr>`。  
- 修改 `AppManager::make(const App::Uid uid)` 等入口逻辑：  
  - 将传入的 `uid` 直接视为完整 Linux UID；  
  - 不再对 UID 做 `% 100000` 或其它压缩映射；  
  - 查找顺序为：  
    - 若 `_byUid` 中已有该 UID，则直接返回现有 App；  
    - 否则调用 `create(uid, ...)` 按完整 UID 创建新 App。  
  - 对于“异常 UID”（例如非应用 UID）：  
  - DNS / NFQUEUE 热路径仍允许创建对应的“无名称 App”，避免丢统计；  
  - 如需防御性记录，可在入口调用 `isAppUid(uid)` 判定并写日志，但不要阻断创建流程。
- **实现提示**：重构时应在代码中全局搜索 `% 100000`，确认只在旧的 `AppManager::make` / `Control::arg2app` 中存在，并在实现新逻辑时彻底删除；后续任何新增代码都不得再引入类似“UID→appId”的截断。

2) 名称查找 `findByName(name, optional<userId>)`  
- 在 AppManager 提供按 `(name, userId)` 查找的接口，仅用于控制协议兼容和旧数据恢复：  
  - `App::Ptr findByName(const std::string &name, std::optional<uint32_t> userId);`  
  - `App::Ptr find(const std::string &name);` 作为兼容包装，语义等价于 `findByName(name, /*no userId*/)`。  
- 实现上以 `_byUid` 为唯一真实索引：  
  - 遍历 `_byUid`，比较 `app->name()` 和 `app->userId()`：  
    - 显式给出 `userId` 时，仅匹配 `(name, userId)`；  
    - 未给出 `userId` 时，仅在主用户（user 0）范围查找。  
  - `_byName` 的角色弱化为辅助索引或兼容使用，避免把 name 作为“第二主键”：可以只在 user 0 App 上维护 name → App 的映射，或仅用于按名称排序输出；  
  - DNS / NFQUEUE 判决等性能敏感路径必须只依赖 `_byUid`，不能依赖 `_byName`。  
- 为避免兼容路径误用：  
  - `find(const std::string &name)` 仅作为 user 0 兼容接口使用（包括例如 `DnsRequest::restore` 等只保存 name 的旧数据恢复）；  
  - 多用户场景下如需精确定位实例，必须通过 UID 或 `(name, userId)` 调用 `findByName`，而不是用简单的 `find(name)`。

3) 匿名 App 与 `install(uid, names)` 的协同语义  
- 运行期可能出现 “先在 DNS/NFQUEUE 路径中看到某个 UID，后在包安装状态聚合中看到对应包名” 的顺序：  
  - 第一次在 DNS/NFQUEUE 中看到该 UID 时，通过 `AppManager::make(uid)` 创建一个“匿名 App”，此时只知道 UID，不知道包名；  
  - 之后 `PackageListener::updatePackages()` 通过聚合（`packages.list` + per-user `package-restrictions.xml`）得到该 UID 的 `names`，并通过 `appManager.install(uid, names)` 补全该 App 的名称与别名集合。  
- 为避免出现“匿名 App 永远停留在占位名称（例如 `system_<uid>`）”的情况，`install(uid, names)` 的语义约定为：  
  - 若 `_byUid` 中不存在该 UID：按第 1 条中的规则调用 `create(uid, names...)`，直接创建一个带完整名称信息的新 App；  
  - 若 `_byUid` 中已经存在该 UID：**复用现有 App 实例**，仅更新其名称相关元数据，而不是忽略新的 `names`：  
    - 将 `App::_name` 更新为 canonical 包名（通常为 `names[0]`），将 `_names` 更新为完整别名集合；  
    - 由此 `App::isSystemApp()` / `isUserApp()` 的判断结果也会随之更新，用于后续持久化路径选择；  
    - 对于已经存在的 `_saver` 路径，允许实现采用“路径一旦确定则保持不变”的策略，避免在运行期复杂迁移历史文件；新的通过 `PackageListener` 聚合直接创建的 App 则严格遵守 3.1.4 中的 per-user 保存路径规则。  
- 上述约定保证：  
  - DNS/NFQUEUE 热路径可以在不知道包名的情况下立即开始按 UID 统计，不丢事件；  
  - 一旦聚合结果中出现该 UID，对应 App 会被“升级”为带正确名称/别名的实例，后续 Control / HELP 等视图看到的都是规范化后的名称；  
  - `PackageListener::updatePackages()` 与 `AppManager` 的协同具体行为在本小节定义，3.3.2 中将 `appManager.install(uid, names)` 作为黑盒调用引用这里的语义。
- 实现提示：  
  - 为了支持 “匿名 App → 命名 App” 的升级语义，需要将 `App` 内部的 `_name` / `_names` 从只读成员调整为可更新字段，并将 `UidMap` / `NamesMap` 的 `mapped_type` 从 `const App::Ptr` 调整为 `App::Ptr`，由 `AppManager::install` 负责在保持 `_byUid` 为唯一主索引的前提下维护 `_byName` 的一致性；  
  - `install(uid, names)` 的典型伪代码应类似于：  
    ```c++
    void AppManager::install(Uid uid, const NamesVec &names) {
        const std::scoped_lock lock(_mutexByUid, _mutexByName);
        if (auto it = _byUid.find(uid); it == _byUid.end()) {
            // 新 UID：使用 create(uid, ...)，构造带正确持久化路径的新 App
            (names.size() == 1) ? create(uid, names[0]) : create(uid, names);
        } else {
            // 已存在的匿名/占位 App：在原 App 对象上更新名称/别名及 _byName 索引
            auto app = it->second;
            updateNamesAndIndexes(app, names);
        }
    }
    ```  
    实现时应避免在 “UID 已存在” 分支里再次调用 `create(uid, ...)` 生成新的 App，从而保证 `_byUid` 始终以 UID 为唯一主键，没有重复实例。

#### 3.1.4 App 持久化路径与 AppManager::save/restore（条目 10, 12）

1) Saver 路径的统一构造  
- 当前实现中，`App` 构造函数直接基于 uid/name 拼接保存路径：  
  - 系统应用：`saveDirSystem + std::to_string(uid)`；  
  - 普通应用：`saveDirPackages + name`。  
- 多用户重构后，保存路径规则改为：  
  - user 0：  
    - 系统应用：`saveDirSystem + std::to_string(appId)`；  
    - 普通应用：`saveDirPackages + packageName`。  
  - `userId > 0`：  
    - 系统应用：`userSaveDirSystem(userId) + std::to_string(appId)`；  
    - 普通应用：`userSaveDirPackages(userId) + packageName`。  
- 为了统一实现与便于演进，建议在 `AppManager::create(uid, names...)` 中集中构造：  
  - 利用 UID helper 得到 `userId` / `appId`；  
  - 根据 `names.size()` 判断是否系统应用（多包共享 UID）；  
  - 通过 `Settings` 的 helper 生成具体路径（user 0 使用 `saveDirSystem/saveDirPackages`，其它 user 使用 `userSaveDirSystem/userSaveDirPackages`）；  
  - 将“canonicalName + allNames + saveFile 路径 + 默认阻断配置”等参数传入 `App` 的内部构造函数。  
- 要求：  
  - user 0 的保存路径保持与旧版本布局兼容，不引入迁移逻辑；  
  - 非 0 用户的数据严格落在各自 `user<userId>/...` 目录内，与 user 0 相互隔离。

2) AppManager::save 与 restore 的职责划分  
- `save()`：  
  - 继续遍历 `_byUid` 中所有 App，调用各自 `save()`；  
  - `App` 内部基于自身 `_saver` 路径写入配置与统计，无需感知 userId。  
- `restore()`：遵循“先由 PackageListener 建立 App 集合，再恢复内容”的顺序：  
  - 启动阶段由主函数保证：  
    1. 先执行 `PackageListener::updatePackages()` 基于包安装状态聚合创建 UID 对应的 App；  
    2. 再调用 `AppManager::restore()` 从磁盘恢复各 App 的内容。  
  - `restore()` 具体行为：  
    - 先恢复 `_stats` 全局统计；  
    - 针对 user 0：  
      - 扫描 `saveDirSystem`：  
        - 文件名视为 appId；  
        - 利用 UID helper 组合出完整 UID（userId=0）；  
        - 若 `_byUid` 中存在对应 UID，则调用 `App::restore` 恢复系统 App 内容；  
        - 解析失败或找不到 App 时，按当前策略删除孤儿文件。  
      - 扫描 `saveDirPackages`：  
        - 文件名视为包名；  
        - 在 `_byUid` 中查找 `app->name() == filename && app->userId() == 0` 的 App；  
        - 找到则调用 `restore`，否则删除该文件。  
    - 针对其它用户：  
      - 遍历 `_saveDir` 下的 `user<userId>/system/` 与 `user<userId>/packages/` 子目录；  
      - `system/`：  
        - 文件名视为 appId，目录名解析出 userId；  
        - 通过 helper 组合出完整 UID；  
        - 若 `_byUid` 中存在 UID，则 `restore`，否则删除。  
      - `packages/`：  
        - 文件名视为包名，目录名解析出 userId；  
        - 在 `_byUid` 中查找 `(app->name() == filename && app->userId() == userId)` 的 App；  
        - 找到则 `restore`，找不到则删除。  
- 整体约束：  
  - `restore()` 不自行创建新的 App 对象，不修改 UID 集合；  
  - App 对象的生命周期由 `PackageListener::updatePackages()` 与运行时的 `AppManager::make(uid)` 驱动，UID ↔ 包名映射以 `PackageListener` 的聚合结果为准；  
  - 恢复过程中遇到无法匹配的旧文件一律视为孤儿，优先保持运行时状态干净，而不是尝试复杂迁移。  
  - 为落实上述约束，**现有 `AppManager::restore()` 中基于 `saveDirSystem` / `saveDirPackages` 调用 `make()` 创建 App 的逻辑将被完全移除**（即不再通过扫描保存文件名来隐式创建 App）；新实现仅对已经存在于 `_byUid` 的 App 调用 `App::restore`。

### 3.2 Settings / 持久化目录 / UID 常量（对应条目 1, 2, 9, 10, 11, 23, 24）

目标：在不打破现有配置文件格式的前提下，为多用户持久化提供统一的根目录与 per-user 子目录 helper，同时为 UID helper 提供统一的常量来源，并确保 `RESETALL` 能在文件系统层面彻底清理多用户数据。

#### 3.2.1 Settings 中的路径约束与 UID 常量

- 保持现有的根目录定义不变：  
  - `_snortDir = "/data/snort/"`、`_saveDir = "/data/snort/save/"`；  
  - `saveDirPackages = _saveDir + "packages/"`、`saveDirSystem = _saveDir + "system/"`、`saveDirDomainLists = _saveDir + "domains_lists/"`；  
  - `Settings::packagesList = "/data/system/packages.list"` 作为全局 `packageName ↔ appId` 映射数据源（不承载 per-user 安装状态）。  
- UID helper 所需的 Android 常量（`AID_USER`、`AID_APP_START`、`AID_APP_END` 等）统一从 AOSP 头文件引入（例如 `android_filesystem_config.h`），不在 Settings 内重复定义。Settings 自身只负责路径字符串，不参与 UID 计算。  
- 对于路径安全约束：  
  - 所有基于 `userId` 拼接出的路径（`userSaveRoot`/`userSaveDirPackages`/`userSaveDirSystem` 等）在使用前必须：  
    - 校验 `userId` 在合理范围内（例如 `0 <= userId < 10000`）；  
    - 通过 `realpath` 或前缀检查，确认最终路径仍位于 `/data/snort/` 根目录下，规避路径遍历和符号链接攻击；  
  - 这些检查逻辑集中在 Settings 的 helper 内部，调用方只拿到已经验证过的路径。

#### 3.2.2 多用户保存目录 helper（条目 9, 10, 11）

- 在 Settings 中新增一组仅供内部使用的 helper，用于为 `userId > 0` 构造 per-user 保存目录：  
  - `userSaveRoot(userId) = _saveDir + "user" + std::to_string(userId) + "/"`；  
  - `userSaveDirPackages(userId) = userSaveRoot(userId) + "packages/"`；  
  - `userSaveDirSystem(userId)   = userSaveRoot(userId) + "system/"`。  
- 新增一个按需创建目录的 helper（例如 `ensureUserDirs(userId)`）：  
  - 负责在第一次需要保存该用户数据时创建 `userSaveRoot(userId)` 以及 `packages/`、`system/` 子目录；  
  - 内部完成 userId 合法性校验和路径安全检查；  
  - 只在真正需要持久化该用户数据时调用，而不是在启动时为所有潜在用户预建目录。  
- `Settings::start()` 的职责保持最小化：  
  - 仍然只创建 `_saveDir`、`saveDirPackages`、`saveDirSystem`、`saveDirDomainLists` 等基础目录；  
  - 不枚举或预创建任何 `user<userId>` 子目录；  
  - 保证旧版本只存在 user 0 数据时，启动行为完全兼容。
- 实现约束：所有 `user<userId>` 相关目录的创建与路径拼接必须集中通过 `Settings` 提供的这些 helper 完成，其他模块（包括 `AppManager`、`PackageListener` 等）不得直接对 `/data/snort/save/` 进行 `mkdir` 或手工拼接 `user<userId>` 子目录，从而避免路径散落和安全检查缺失。

#### 3.2.3 Settings::reset / save / restore 与 RESETALL（条目 23, 24）

- `Settings::reset()` 继续只负责内存中的全局开关和参数（`_blockEnabled`、`_blockMask`、`_blockIface`、`_reverseDns` 等），不对磁盘上的任何目录或文件做操作。  
- `Settings::save()` / `Settings::restore()` 继续使用单一的 `_saveFile`（`/data/snort/settings`）保存/恢复全局配置，不区分用户。  
- `RESETALL` 在 Settings 维度的扩展（设备级语义）：  
  - 控制命令 `RESETALL` 被定义为**设备级“恢复到初始状态”**操作：在调用 `settings.reset()` 后，必须在文件系统层面清理 `/data/snort/save/` 下的**所有**持久化数据，无论属于 user 0 还是非 0 用户；  
  - 包括但不限于：  
    - 根目录下的 `saveDirPackages` / `saveDirSystem` / `saveDirDomainLists` 中的全部文件（主用户数据）；  
    - 所有 `user<userId>/packages/`、`user<userId>/system/` 等 per-user 目录及其内容（多用户数据），保证非 0 用户与 user 0 在 RESETALL 下获得一致的清理效果；  
  - 实现上集中由 Settings 层提供一个名为 `clearSaveTreeForResetAll()` 的专用 helper，由 `Control::cmdResetAll` 在持有全局监听器独占锁的前提下一次性调用，用于从 `_saveDir` 根起递归删除整棵保存树（包含主用户与所有 per-user 目录及潜在遗留文件）；各业务模块的 `reset()` 仍保留对自身“已知文件”（如 App 保存文件、设备级域名列表等）的清理职责，二者配合保证 `/data/snort/save/` 整棵保存树在 RESETALL 后处于干净状态且职责边界清晰。
- 对于“回滚到旧版本”的场景：  
  - 新版本创建的 `user<userId>/...` 目录必须对旧版本透明：旧版本只访问 `saveDirPackages` / `saveDirSystem` / `saveDirDomainLists`，忽略多出来的 `user<userId>/...`；  
  - 因此 Settings 在生成路径和处理错误时不能假定 `user<userId>` 目录存在或有特定结构，避免旧版本因额外文件/目录崩溃。

### 3.3 PackageListener / 包安装状态聚合（对应条目 2, 13, 14, 24）

目标：通过读取系统文件（`/data/system/packages.list` + `/data/system/users/<userId>/package-restrictions.xml`）在内存中构建“完整 UID → 包名/别名集合”的映射，驱动 App 的 install/remove；避免执行 `pm` 命令，引入最小不确定性。

#### 3.3.1 数据源与解析安全（条目 2, 13, 24）

- `/data/system/packages.list`：读取路径固定为 `Settings::packagesList`，用于建立全局 `packageName -> appId` 与 `appId -> names[]`（shared UID）映射；解析时每行仅使用前两个 token（`name uid`），其中 `uid` 视为 user 0 UID（等价 appId），其余内容通过 `ignore(..., '\n')` 丢弃。  
- `/data/system/users/<userId>/package-restrictions.xml`：用于确定每个 user 下哪些 package 处于 installed 状态；至少读取 `<pkg name="...">` 的 `inst` 属性（缺省视为 true）。  
- 用户枚举：优先读取 `/data/system/users/userlist.xml`；也可以枚举 `/data/system/users/` 下的数字目录作为兜底。  
- 安全约束（对两类来源统一执行）：  
  - 对包名：限制长度、拒绝控制字符/NUL/换行、拒绝路径穿越（`..`、`/`）；  
  - 对 appId/UID：通过 `isAppUid(appId)` 或等价范围校验过滤非应用 UID；对 userId 做合理范围校验；  
  - 对 XML：如使用通用 XML 库，必须禁用外部实体等易引入不确定性的特性。  

#### 3.3.2 updatePackages 与 AppManager 的协同（条目 13, 14）

- `_names` 的类型保持为 `std::map<App::Uid, std::vector<std::string>>`，键始终是完整 UID。  
- `PackageListener::updatePackages()` 的工作流程：  
  1. 将旧的 `_names` 快照搬到局部变量 `old` 中，并清空 `_names`；  
  2. 读取 `packages.list`，构建临时的 `packageName -> appId` 与 `appId -> names[]` 映射；  
  3. 遍历用户集合并读取每个 user 的 `package-restrictions.xml`，对每个 installed `(userId, packageName)`：  
     - 通过 `packageName -> appId` 取到 appId；  
     - 计算 `uid = userId * 100000 + appId`；  
     - 用 `appId -> names[]` 填充 `_names[uid]`；  
  4. 对新快照中的每个 `(uid, names)`：  
     - 若 `old` 中不存在该 UID，则调用 `appManager.install(uid, names)` 安装新 App（其具体行为包括“复用并升级已有匿名 App”的语义，见 3.1.3 第 3 点）；  
     - 若 `old` 中存在该 UID，则从 `old` 中移除（表示仍然有效，不需卸载）；  
  5. 对 `old` 中剩余的 `(uid, names)`：  
     - 调用 `appManager.remove(uid, names)` 卸载对应 App；  
     - 由 `AppManager::remove` 负责删除对应 App 的持久化文件。  
- 多用户场景下：  
  - 同一 packageName 在不同 userId 下均 installed → `_names` 中会出现多个不同 UID 条目（userId 不同）；  
  - 仅在某个 user 下 installed → 只会生成该 user 的 UID 条目，不会错误落到 user 0。  
- 线程模型与协同顺序：  
  - 启动阶段：  
    - 主线程在持有 `mutexListeners` 的锁下启动 `pkgListener.start()`；  
    - `updatePackages()` 首次运行完毕后，主线程再调用 `appManager.restore()` 恢复 App 内容；  
  - 运行期：  
    - `listen()` 线程通过 inotify 监控 `packages.list` 与 `/data/system/users/` 下的用户/包状态文件（例如 `userlist.xml` 与各 user 的 `package-restrictions.xml`），在任一更新时调用 `updatePackages()`；  
    - `updatePackages()` 内部不操作全局 `mutexListeners`，仅与 `AppManager` 的内部锁交互，保证与 DNS/NFQUEUE 热路径相互独立。

### 3.4 Control / AppSelector / HELP（对应条目 8, 15, 16, 17, 18, 19, 20, 22, 26）

目标：在 `Control` 层收敛所有 `<uid|str>` 解析逻辑，引入统一的 AppSelector 表达 `(uid)` 或 `(name, userId)`，并在不改变命令名的前提下补足多用户语义，同时保证 HELP 文档与实际行为严格一致。

#### 3.4.1 CmdArg 与 AppSelector 统一解析（条目 8, 15）

- 保留现有 `CmdArg` / `readCmdArgs` / `readCmdArg` 的基础结构，用于把输入行切分为 token 序列。  
- 在 `Control` 内部新增一层 AppSelector 概念（可以是内部 struct 或 helper 函数），统一解析所有 `<uid|str>` 形态：  
  - 单个整数 token：解释为完整 Linux UID，对应 `ByUid(uid)`；  
  - 单个字符串 token：解释为包名，隐含 `userId = 0`，对应 `ByName(name, userId=0)`；  
  - 形如 `<str> USER <userId>` 的三个 token：统一解释为 `(packageName, userId)`，对应 `ByName(name, thatUserId)`，适用于所有支持 `<uid|str>` 的命令；  
  - 对于 `<str> <userId>` 这种“字符串 + 整数”的二元组合，**仅在该命令在 `<uid|str>` 之后本身不再接受其他整型参数时**允许解释为 `(name, userId)`（比如 `APP.UID` / `APP.NAME` / `APP<v>` / `APP.RESET<v>` / `TRACK` / `UNTRACK` / `APP.CUSTOMLISTS` 等）；对于诸如 `BLOCKMASK <uid|str> [<mask>]`、`BLOCKIFACE <uid|str> [<mask>]`、`BLACKRULES.ADD <uid|str> <ruleId>` 等在 `<uid|str>` 之后还有自身整型参数的命令，第二个整数参数一律视为该命令自身参数（掩码、规则 ID 等），**不再解析 `<str> <userId>` 作为 `(name, userId)`，如需多用户选择必须显式使用 `<str> USER <userId>` 形式。**  
- AppSelector 只在 `Control` 内部使用，对外通过以下两种方式与 `AppManager` 交互：  
  - `ByUid(uid)`：直接调用 `appManager.find(uid)` 或 `make(uid)`；  
  - `ByName(name, optional<userId>)`：调用 `appManager.findByName(name, userId)`。  
- 所有 `<uid|str>` 参数的命令（`APP.UID` / `APP.NAME` / `APP<v>` / `BLOCKMASK` / `TRACK` / `CUSTOMLIST.*` / `BLACKLIST.*` / `WHITELIST.*` / `APP.RESET<v>` 等）统一使用 AppSelector，而不是各自重复解析 `<uid|str>`。  
- 实现约束：完成重构后，`Control` 中不应再出现对 UID 的 `% 100000` 或直接调用 `appManager.find(arg.number)` 这类旧逻辑，所有命令都必须经由这一层 AppSelector 进行解析。

#### 3.4.2 各类命令中 `<uid|str>` 的应用（条目 16, 17, 18, 19, 20）

- App 列表命令：  
  - `APP.UID`：无参数时按 UID 升序列出所有 App；`USER <userId>` 时只列出该用户下 App；带 `<uid>` 时返回单个 UID 的 App；带 `<str>` 或 `<str> USER <userId>` 时按 name 子串匹配。  
  - `APP.NAME`：无参数按名称排序列出所有 App；`USER <userId>` 时只列出该用户下 App；带 `<str>` / `<str> USER <userId>` 时按子串匹配。  
- App 统计命令（`APP<v>` / `APP.DNS<v>` / `BLACK.APP<v>` / `WHITE.APP<v>` / `GREY.APP<v>` 等）：  
  - 无参数时输出所有用户的设备级统计，总览视图中每条结果包含 `uid` / `userId`；  
  - 追加 `USER <userId>` 时对指定用户范围内所有 App 统计；  
  - 带 `<uid>` 时仅对该 UID 的 App 统计；  
  - 带 `<str>` / `<str> USER <userId>` 时对 AppSelector 选中的单个实例统计。  
- `APP.RESET<v> [<uid|str>|ALL]`：  
  - `ALL` 表示跨所有用户重置对应视图；  
  - `ALL USER <userId>` 仅重置该 user 下所有 App 的对应视图；  
  - `<uid>` 精确匹配一个 UID 的 App；  
  - `<str>` / `<str> USER <userId>` 按前述规则解析并重置单个实例。  
  - 自定义列表与黑白名单命令：  
  - `CUSTOMLIST.ON/OFF <uid|str>`：按 AppSelector 选中目标 App，切换其“使用自定义列表”开关，字符串默认只作用于 user 0。  
  - `BLACKLIST.*` / `WHITELIST.*`：无 `<uid|str>` 时始终作用于设备级全局列表，带 `<uid|str>` 时只作用于选中 App 的自定义列表，严格按 UID 区分不同用户下的同名应用。  
- `TRACK` / `UNTRACK` / `TOPACTIVITY`：  
  - `TRACK <uid|str>` / `UNTRACK <uid|str>` 使用 AppSelector 精确选中实例，按 UID 粒度控制是否统计流量；  
  - `TOPACTIVITY <uid>` 保持只接受 UID 形式，由前端负责传递完整 UID，内部通过 `appManager.make(uid)` 选中 App，并按第 20 条输出 Activity JSON；实现上严禁给 `TOPACTIVITY` 保留按包名字符串查找 App 的路径（不能复用 AppSelector 的 `ByName` 分支）。  

- 实现提示：  
  - `APP.UID` / `APP.NAME` 等列表命令在实现时必须以 `_byUid` 为唯一真实索引来源：先从 `_byUid` 收集所有 App，再在内存中按 `uid` 或 `name` 排序、按 `userId` 过滤后输出；  
  - 不允许直接遍历 `_byName` 作为主索引，以保证同名应用在不同用户下能够作为多个独立实例出现在列表中。

#### 3.4.3 HELP 文档与接口一致性（条目 26）

- 在 `Control::cmdHelp` 输出中同步更新所有涉及 `<uid|str>` 的命令说明：  
  - 明确 `<uid>` 是完整 Linux UID；  
  - 明确 `<str>` 默认为主用户（user 0）下的包名；  
  - 为需要的命令补充 `<str> <userId>` 和 `<str> USER <userId>` 的写法说明。  
- 对于仍保持设备级视图的命令（`ALL<v>` / `<TYPE><v>` / `DOMAINS<v>` / `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 等），在 HELP 中明确不支持 `USER` 子句，避免与 App 级命令混淆。  
- 每次更新控制协议语义（包括本设计文档与 `INTERFACE_SPECIFICATION.md`）后，必须同步检查并更新 HELP 输出，确保“文档 ↔ HELP ↔ 实际行为”三者一致。

### 3.5 DnsListener / PacketListener / 网络热路径（对应条目 1, 5, 6, 21, 22）

目标：在 DNS 与 NFQUEUE 热路径中全面切换为“完整 UID → App 实例”的模型，不再对 UID 做裁剪或再解释，同时保持判决路径只依赖 App 对象，不直接操作包名或 userId。

#### 3.5.1 DnsListener::clientRun（条目 1, 5, 6, 21）

- 从 netd socket 读取域名和 UID 时：  
  - 直接将 `uid` 作为完整 Linux UID 传入 `appManager.make(uid)`，不再做 `% 100000` 或其他映射；  
  - 由 `AppManager` 根据完整 UID 返回对应的 App 实例。  
- 判决流程保持两阶段结构：  
  - 阶段 1：在不持有 `mutexListeners` 的情况下构造 `Domain`、`App` 等对象；  
  - 阶段 2：在持有共享锁的短窗口内调用 `app->blocked(domain)`、更新统计、推送流事件。  
- 统计与 streaming：  
  - 所有统计通过 `appManager.updateStats(domain, app, ...)` 完成，以 App（即 UID）为粒度；  
  - DNS 流事件（`DnsRequest`）持有 `App::Ptr`，打印时通过访问 App 的 UID 接口在事件 JSON 中附加 `uid` / `userId` / `appId` 字段。

#### 3.5.2 PacketListener::callback 与 PacketManager（条目 1, 5, 6, 21, 22）

- 在 NFQUEUE 回调中：  
  - 从 `NFQA_UID` 中读取 UID 后，直接视为完整 Linux UID 传给 `appManager.make(uid)`；  
  - 不再对 UID 做取模或压缩映射。  
- 对每个数据包：  
  - 解析 IP / 传输层头，提取 `srcPort` / `dstPort` / 接口索引等信息；  
  - 构造 `Address<IP>` 和 `Host::Ptr`，通过 `hostManager.make<IP>(addr)` 获取 Host，并可选进行反向解析；  
  - 当前接口/协议判决由 `PacketManager::make<IP>(addr, app, host, ...)` 完成，返回布尔 verdict。  
- Packet 流数据：  
  - 若需要输出流事件，由 `PacketManager` 构造 `Packet<IPv4>` 或 `Packet<IPv6>` 对象并交给 `Streamable`；  
  - `Packet::print` 中输出 `app` 名称、方向、长度、接口、协议、时间戳等字段，并在顶层追加 `uid` / `userId` 字段（与第 22 条保持一致），便于前端按用户过滤。

### 3.6 Activity / Streamable / DnsRequest / 流输出（对应条目 3, 4, 5, 20, 22）

目标：让所有流式调试数据（Activity、DNS 流、网络流）在保持原有语义的前提下输出足够的多用户信息（`uid` / `userId` / `appId`），并将用户级过滤权下放到前端。

#### 3.6.1 Activity 与 ActivityManager（条目 3, 4, 20, 22）

- `Activity` 持有 `App::Ptr`，不单独保存 UID：  
  - UID 相关信息一律通过 `_app->uid()` / `_app->userId()` 访问；  
  - 避免在 Activity 内部重复保存或推导 UID。  
- Activity JSON 输出：  
  - 顶层结构保持包含 `blockEnabled` 字段；  
  - 当 `_app` 非空时：  
    - 顶层增加 `uid` / `userId` 字段，直接从 `_app` 读取；  
    - 再增加一个 `app` 字段，其内部使用 `App::printAppNotif` 输出 App 的 JSON（包含 `uid` / `userId` / `appId` 等字段）。  
- ActivityManager：  
  - 继续使用单一 `_topApp` 记录最近前台 App，并通过 `stream(activity)` 推送 Activity 事件；  
  - `startStream` 在开始时立即推送一次当前 `_topApp`，保证新连接能立刻看到前台应用及其 `uid` / `userId` 信息。

#### 3.6.2 Streamable / DnsRequest / Packet / DNSSTREAM & PKTSTREAM（条目 3, 4, 5, 22）

- `Streamable<Item>` 保持现有的 `socket -> pretty` 映射，不新增 per-socket `userId` 状态：  
  - 流命令 `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START` 始终提供设备级视图；  
  - 每个连接只决定是否 pretty-print，不在后端进行按用户过滤。  
- `DnsRequest`：  
  - 内部持有 `App::Ptr` 和 `Domain::Ptr`，不单独保存 UID；  
  - `print` 中输出 App 名称、域名、mask、阻断标记、时间戳等字段；  
  - 按第 22 条要求在事件 JSON 顶层追加 `uid` / `userId` 字段（通过 `_app->uid()` / `_app->userId()`），便于前端按用户过滤 DNS 事件，且不在 `DnsRequest` 内部维护 UID 的副本。  
  - `save/restore` 保持旧格式（基于 `appName + domainName`），所有恢复出来的历史记录视为主用户（user 0）的 DNS 流；实现时禁止尝试从旧流数据中反推非 0 用户 ID，以免引入不一致状态。  
- `Packet<IP>`：  
  - 持有 `App::Ptr`、`Host::Ptr` 和各种网络字段；  
  - `print` 中输出 `app` 名称、方向、长度、接口、协议、时间戳、IP/主机、端口等信息；  
  - 需要时在顶层追加 `uid` / `userId` 字段（通过 `_app->uid()` / `_app->userId()`），以便前端在 PKTSTREAM 中按用户过滤，同样不在 `Packet` 内部缓存 UID。  
- 统一约束：DNS / Packet / Activity 流视为短期调试数据，本轮重构只要求新格式向前兼容主用户旧数据，不保证跨版本流数据严格可读。

### 3.7 RESETALL / snortSave / 监听器锁（对应条目 11, 23, 24, 25）

目标：确保 `RESETALL` 在多用户环境下能一致地“恢复到初始状态”，包括内存状态和磁盘持久化数据，同时避免与 DNS/NFQUEUE 热路径产生死锁或长时间阻塞。

#### 3.7.1 Control::cmdResetAll 与 snortSave（条目 23, 24）

- `Control::cmdResetAll` 的职责：  
  - 在获得 `mutexListeners` 的写锁（独占锁）后执行，以冻结 DNS / Packet / Activity / Control 等对内部状态的并发访问（实际持锁点位于 `Control::clientLoop`，在调用 `cmdResetAll` 之前已经获取独占锁）；  
  - 按以下顺序重置各模块（仅负责各自“逻辑状态 + 已知文件”的清理）：  
    - `settings.reset()` 重置内存中的全局开关和参数（不直接删除任何磁盘文件）；  
    - `appManager.reset()` 清除所有 App 对象，并移除当前 `_byUid` 集合中每个 App 对应的持久化文件；  
    - `domManager.reset()` 清理域名集合，并删除主用户下 `saveDirDomainLists` 中的域名列表文件；  
    - `blockingListManager.reset()` / `rulesManager.reset()` / `pktManager.reset()` / `hostManager.reset()` / `dnsListener.reset()` / `activityManager.reset()` 等，使各自内部状态回到“刚启动未统计”的状态（其中 `dnsListener.reset()` 主要负责调用 `Streamable<DnsRequest>::reset()` 清空 DNSSTREAM 队列，不关闭 netd socket 或监听线程；`activityManager.reset()` 调用 `Streamable<Activity>::reset()` 清空 ACTIVITYSTREAM 队列，不关闭监听线程）。  
  - 在上述模块级 reset 完成后，通过 Settings 层提供的专用 helper（3.2.3 中提到的 `clearSaveTreeForResetAll()`）**集中清理 `/data/snort/save/` 整棵保存树**：  
    - 包括 user 0 的 `saveDirPackages` / `saveDirSystem` / `saveDirDomainLists`；  
    - 以及所有 `user<userId>/packages/`、`user<userId>/system/` 等 per-user 目录及其内容；  
    - 各业务模块无需分别遍历 per-user 目录，避免多处散落的目录删除逻辑，与 3.2.3 的职责划分保持一致：模块级 `reset()` 负责清理自身已知文件，Settings 级 helper 负责清理多用户布局及遗留文件。  
  - 最后调用 `snortSave()` 触发一次同步保存当前全局状态（包括 Settings 和空白的统计/列表），并在需要时根据参数决定是否退出进程。  
- 多用户扩展：  
  - 在完成 `/data/snort/save` 整棵目录树的清理后，通过调用一次 `pkgListener.reset()`（内部再次触发 `PackageListener::updatePackages()`）基于包安装状态聚合重新构建 App 集合（包含所有用户），保证 RESETALL 之后的 App 集合与当前系统安装状态一致；  
  - 对于 user 0 与非 0 用户，RESETALL 的语义完全一致：所有用户的数据（统计、阻断配置、自定义列表等）都被清空，后续行为仅由当前系统实际安装的应用决定。

#### 3.7.2 监听器锁与并发（条目 21, 23, 25）

- 全局 `mutexListeners` 用于在 `RESETALL` 与业务热路径之间提供粗粒度的同步：  
  - DNS / Packet / Activity 路径在需要访问共享结构（如 `domManager`、`appManager`、流队列）时只持有共享锁（`std::shared_lock`），确保常规统计和流输出不会互相阻塞；  
  - `RESETALL` 获取独占锁（`std::lock_guard`）后，禁止新的决策或持久化操作进入，从而确保重置过程中的文件删除与内存状态修改一致。  
- 测试要点：  
  - 在高并发 DNS/NFQUEUE 流量下执行 `RESETALL`，验证在保持锁窗口尽量小的前提下不会出现明显长时间阻塞或死锁；  
  - 确保在 RESETALL 完成后，新流量会在基于新构建的 App 集合上重新统计。

### 3.8 测试与验证实现建议（对应条目 25）

目标：在不改变条目 25 中测试场景定义的前提下，从实现角度给出测试组织方式和重点检查点，便于在代码层面验证多用户语义与兼容性。

- 单元级测试建议：  
  - 针对 UID helper：构造不同 `userId/appId` 组合，验证 `userId(uid)` / `appId(uid)` / `isAppUid(uid)` 行为正确；  
  - 针对 Settings 路径 helper：验证合法/非法 `userId` 的路径生成与安全检查；  
  - 针对 PackageListener：在内存中伪造多种 `packages.list` 与 per-user `package-restrictions.xml` 内容，验证聚合后的 `_names` 以及 `appManager.install/remove` 行为符合预期。  
- 集成级测试建议：  
  - 启动序列测试：在多用户设备上启动守护进程，检查 `pkgListener.start()` → `appManager.restore()` → 各模块 `restore()` 的顺序与日志是否匹配设计；  
  - 控制协议测试：通过自动化脚本调用 `APP.UID` / `APP.NAME` / `APP<v>` / `BLOCKMASK` / `TRACK` / `CUSTOMLIST.*` 等命令，验证 `<uid|str>` / `USER <userId>` 组合在单用户和多用户下的行为；  
  - 流测试：在多用户环境下开启 `DNSSTREAM.START` / `PKTSTREAM.START` / `ACTIVITYSTREAM.START`，对照事件中的 `uid` / `userId` 字段做前端过滤，验证 per-user 视图正确性。  
- 回滚与兼容性测试：  
  - 从旧版本升级到新版本后，检查 user 0 下旧配置仍能被新版本正确恢复；  
  - 在新版本下为非 0 用户生成配置，并回滚到旧版本，验证旧版本忽略 `user<userId>/...` 子目录且不会崩溃；  
  - 构造恶意或异常的 `packages.list` 与 `package-restrictions.xml`，验证 parser 能跳过异常输入且合法 UID 不受影响。  
- 重置与稳定性测试：  
  - 在高流量场景下多次执行 `APP.RESET<v> ALL` 和 `RESETALL`，观察 CPU/内存/响应时间，确保实现遵守“短锁窗口、无死锁”的原则。  

## 4. 实现与验证计划（草案）

### 4.1 阶段划分

- 阶段 0：基线固化  
  - 在当前可工作的版本打 tag（例如 `pre-multiuser-v0`），完整跑一遍 `docs/tests/BACKEND_DEV_SMOKE.md` 已有用例，在单用户设备上记录典型输出（`APP.UID` / `APP.NAME` / `APP.A` / DNS/PKT/ACTIVITY 流）。

- 阶段 1：UID helper + 内部 UID 完整化  
  - 实现：引入 UID helper（3.1.1），在 `App` 上补齐 `uid()/userId()/appId()`，移除 `AppManager::make` 与 `Control::arg2app` 中的 `% 100000`，其余行为不变。  
  - 验证：在单用户设备上重跑 `BACKEND_DEV_SMOKE` 的基础用例（HELLO/HELP/APP 查询/统计），对比阶段 0 的输出，确认所有 `uid` 数值与统计结果保持不变。

- 阶段 2：Settings 多用户目录 helper + App 保存路径  
  - 实现：在 `Settings` 中增加 `userSaveRoot/userSaveDirPackages/userSaveDirSystem/ensureUserDirs`，在 `AppManager::create` 内按 3.1.4/3.2.2 的规则为 user 0 与非 0 用户构造保存路径，其它逻辑不动。  
  - 验证：在单用户设备上产生统计后重启守护进程，确认 `APP.DNS.0 <uid>` 等应用统计仍能恢复；在存在非 0 用户但未在该用户安装应用的设备上启动，检查 `/data/snort/save` 仅包含 user 0 目录，不自动创建 `user<id>`。

- 阶段 3：PackageListener 多用户化 + AppManager.install/remove/restore  
  - 实现：按 3.3.1 调整 `PackageListener::updatePackages()`（解析 `packages.list` 构建 `packageName->appId`/`appId->names[]`，再结合 per-user `package-restrictions.xml` 聚合出 `uid->names[]`，并做 `isAppUid`/name 校验），按 3.1.3 实现 `install/remove` 的“匿名 App → 命名 App”升级语义，并重写 `AppManager::restore()` 只在已有 `_byUid` 集合上恢复内容，不再通过保存文件名创建新 App。  
  - 验证：  
    - 单用户：重启后执行 `APP.UID` / `APP.NAME` / `APP.A`，与阶段 2 行为一致。  
    - 多用户：在 user 0 与某个非 0 用户上安装同一包，启动守护进程后通过 `APP.UID` + `APP.UID <pkg> USER <userId>` 检查同包在不同用户下被拆分为不同 UID 与 `userId`。

- 阶段 4：Control AppSelector + `<uid|str>` 命令统一改造  
  - 实现：在 `Control` 内实现 AppSelector（3.4.1），并将所有 `<uid|str>` 命令（`APP.UID` / `APP.NAME` / `APP<v>` / `APP.DNS<v>` / `BLACK.APP<v>` / `APP.RESET<v>` / `CUSTOMLIST.*` / `BLACKLIST.*` / `WHITELIST.*` / `TRACK` / `UNTRACK` 等）改为统一使用 AppSelector，`TOPACTIVITY` 保持只接受 `<uid>`；同步更新 HELP 文案。  
  - 验证：  
    - 单用户：完整回归 `BACKEND_DEV_SMOKE` 中涉及 `<uid|str>` 的用例，确保旧写法（仅 `<uid>` 或 `<str>`）行为不变。  
    - 多用户：编写并执行补充用例（建议加到 `BACKEND_DEV_SMOKE` 的“多用户扩展”章节），覆盖：`APP.UID USER <userId>`、`APP.NAME USER <userId>`、`<package> USER <userId>` 精确选中实例、按用户维度的 `TRACK` / `CUSTOMLIST` / `BLACKLIST.ADD/PRINT` 区分不同用户下同名应用的行为。

- 阶段 5：流输出 JSON 补全 `uid/userId`  
  - 实现：按 3.1.2/3.6.1/3.6.2 在 `App::print` 输出 `userId/appId`，在 `Activity::print` 顶层补充 `uid/userId`，在 `DnsRequest::print` 与 `Packet<IP>::print` 顶层补充 `uid/userId` 字段，值统一来自 `_app->uid()` / `_app->userId()`，`save/restore` 格式保持不变。  
  - 验证：重跑 `BACKEND_DEV_SMOKE` 中 DNS/PKT/ACTIVITY 流用例，检查事件 JSON 中新增的 `uid/userId` 字段；在多用户设备上切换不同用户前台应用与网络流量，确认流事件的 `userId` 与对应用户匹配。

- 阶段 6：RESETALL 多用户化与保存树清理  
  - 实现：在 `Settings` 中实现 `clearSaveTreeForResetAll()`，在持有 `mutexListeners` 写锁的 `Control::cmdResetAll` 中按 3.7.1 的顺序依次调用各模块 `reset()`（含 `activityManager.reset()` 与 `dnsListener.reset()`）再调用 `settings.clearSaveTreeForResetAll()`，最后调用 `snortSave()`；`clearSaveTreeForResetAll()` 清理 `/data/snort/save/` 下所有 user 0 与 `user<userId>` 的持久化文件，并在结束时保证基础目录存在。  
  - 验证：  
    - 单用户：执行 `RESETALL` 前后对比 `APP.A` / `APP.DNS.0` 与 `/data/snort/save` 内容，确认统计与持久化文件被清空但守护进程仍可继续工作。  
    - 多用户：在多个用户下产生统计与自定义配置后执行 `RESETALL`，确认 `/data/snort/save` 下所有 `user<id>` 目录被清理，重建后的 `APP.UID` 由包安装状态聚合决定，统计从 0 开始重新累积。

- 阶段 7：全量回归与多用户用例沉淀  
  - 实现：在 `docs/tests/BACKEND_DEV_SMOKE.md` 中追加“多用户扩展”章节，固化阶段 3/4/6 中使用的多用户测试用例。  
  - 验证：  
    - 单用户：完整回归 `BACKEND_DEV_SMOKE` 全部用例，确保多用户改造不破坏旧行为。  
    - 多用户：执行新增的多用户用例集合，并在至少一台多用户设备上随机抽查部分基础用例（如 `APP.UID` / `ALL.A` / DNS/PKT 流 / `RESETALL`），确认多用户逻辑与设备级语义同时成立。
