# Project Context

## Purpose
sucre-snort 是 sucre 阻止器的系统守护进程部分，运行在 Android system_ext 分区上，通过内核 netfilter/iptables NFQUEUE 拦截 IPv4/IPv6 流量，并结合域名列表、自定义规则和应用级策略，对广告、跟踪器和恶意域名进行精细化拦截与统计。  
项目目标是提供一个高性能、低依赖、与界面解耦的网络过滤内核，长期稳定运行于手机系统中，为上层 UI 和服务提供统一的控制与观测接口。

## Tech Stack
- 主要语言: C++20（`Android.bp` 中使用 `-std=c++2a`，启用 `-Wall -Wextra -Werror`）
- 运行环境: Android  Magisk / KernelSU 模块刷入 or ROM 集成，system_ext 下的 `cc_binary` 守护进程，通过 `sucre-snort.rc` 由 init 启动
- 内核/网络: Linux Netfilter + iptables NFQUEUE，拦截 IPv4/IPv6 包并回送裁决；使用 `/sys/class/net` 获取接口类型（WiFi/数据/VPN）
- Android 依赖库: `libmnl`, `libnetfilter_queue`, `libnfnetlink.system_ext`, `libcutils`, `liblog`, `libbase`
- IPC 协议: Unix 域套接字和可选 TCP（60606 端口）文本协议，协议细节见 `docs/INTERFACE_SPECIFICATION.md`
- 持久化: 自定义二进制序列化工具 `Saver`，所有状态保存在 `/data/snort` 目录（配置、统计、域名列表、规则、阻止列表等）

## Project Conventions

### Code Style
- 使用根目录 `.clang-format` 管理 C++ 代码风格；所有改动在提交前需要经过 `clang-format`。
- 编译选项开启大部分警告并将其视为错误（`-Wall -Wextra -Werror`），保持无警告编译。
- 优先使用 RAII、标准库容器与算法；异常仅在边界处捕获（例如 `main()`／线程入口），内部代码尽量保持异常安全。
- 热路径（例如 `PacketListener::callback`, `PacketManager::make`）中禁止引入阻塞 I/O（磁盘、DNS、socket）和重锁，尽量缩小锁作用域，必要时拆成“无锁准备阶段 + 短临界区”。
- 日志使用 `android-base/logging.h` 的 `LOG(INFO/WARNING/ERROR)`；避免在热路径频繁打印高频日志。

### Architecture Patterns
- 单进程、多线程守护程序架构：
  - `sucre-snort.cpp` 中启动多个线程：`PacketListener<IPv4/IPv6>`（iptables/NFQUEUE）、`DnsListener`（与 netd 配合）、`PackageListener`（监控 `/data/system/packages.list`）、`Control`（控制 socket）、以及阻止列表和各 Manager 的恢复逻辑。
  - 全局单例对象用于跨模块共享状态：`Settings`, `AppManager`, `DomainManager`, `HostManager`, `PacketManager`, `DnsListener`, `ActivityManager`, `BlockingListManager`, `RulesManager`, `Control` 等。
- 域名与规则管理：
  - `DomainManager` 负责域名对象、黑白名单列表、自定义名单与规则映射，并通过 `_byName`、`_byIPv4`、`_byIPv6` 建立域名和 IP 的双向索引。
  - `DomainList` 将多个屏蔽列表文件聚合为内存快照 `_aggSnapshot`，支持按域名及其后缀（子域名）查询 blockMask。
  - `BlockingListManager` 管理屏蔽列表元信息（id/name/url/color/blockMask/etag/updatedAt/启用状态/域名数）并持久化，域名实际内容通过 `DomainManager` 加载到 `DomainList` 中。
  - `Rule` + `RulesManager` 提供域名/通配符/正则规则，支持全局和按 App 作用，自定义规则会在 `DomainManager`/`App` 构建对应的匹配器。
- 应用与主机模型：
  - `PackageListener` 持续监听 `/data/system/packages.list` 变化，增量维护 UID → 包名列表，再通过 `AppManager` 创建/删除 `App` 实例。
  - `App` 维护每个 UID 的全局/按域名统计（`AppStats` + per-domain `DomainStats`）、拦截掩码（`blockMask`）、接口掩码（`blockIface`）、是否追踪（`tracked`）以及自定义黑白名单和规则。
  - `HostManager` 维护 IP → `Host` → 可选域名映射，并在启用 `reverseDns` 时通过 `getnameinfo` 做反向 DNS。
- 数据路径与判决：
  - `PacketListener` 通过 NFQUEUE 收到数据包，在不持有全局锁的情况下解析 IP/端口/UID/接口/时间戳和部分 L4 头部；然后在持有 `mutexListeners` 的共享锁时调用 `PacketManager::make` 做判决和统计。
  - `DnsListener` 通过 `sucre-snort-netd` 接收前端 DNS 解析结果（域名、UID 及对应 IP 列表），在短暂持有 `mutexListeners` 共享锁的窗口内更新 `DomainManager` 的 IP 映射和统计，并向订阅者推送 `DnsRequest` 事件。
  - `PacketManager::make` 根据当前域名有效性（`Domain::validIP`）、App 阻止规则（`App::blocked`）、IP 泄漏开关（`blockIPLeaks`）、接口掩码（`blockIface` + `ifaceBit`）得出最终 verdict，同时更新统计并通过 `Streamable<Packet>` 推送事件。
- 控制与流式接口：
  - `Control` 通过 Unix 域 socket `sucre-snort-control` 和可选 TCP 端口 60606 暴露文本命令协议，对应实现集中在 `Control::clientLoop` 与各 `cmd*` 方法中，协议详见 `docs/INTERFACE_SPECIFICATION.md`。
  - `Streamable<T>` 为 DNS 请求、数据包和 Activity 提供统一的事件队列与订阅模型，通过 `startStream/stopStream/stream` 在控制连接上以 JSON 片段形式推送增量事件。
- 全局同步约束：
  - `mutexListeners` 是“监听器世界状态”的全局读写锁：热路径（DNS/packet 判决）在共享锁下运行，`RESETALL` 等重置操作在独占锁下暂停一切判决，任何需要持有独占锁的逻辑必须避免长时间阻塞。
  - 各 Manager 自身还维护细粒度的 `std::shared_mutex`/`std::mutex`，避免在热路径上产生锁级联或死锁。

### Testing Strategy
- 当前仓库未包含单元测试或集成测试目录，主要依赖以下手段保障质量：
  - 编译通过（Soong 构建 `cc_binary`，本地可通过 `compile_commands.json` 配合 clangd/静态分析）。
  - 手动验证控制协议：使用 `nc` 或自定义工具连接 `sucre-snort-control`，调用 `BLOCK`, `APP.*`, `DNSSTREAM.*`, `BLOCKLIST.*` 等关键命令验证行为。
  - 通过日志与统计输出（`Stats`、`Activity` 流、`DnsRequest`/`Packet` 流）观察行为是否符合预期。
- 对新的代码改动有如下要求/建议：
  - 尽量保持变更局限在单模块，避免一次修改多个核心路径（`PacketListener`, `PacketManager`, `DnsListener`, `Control` 同时大改）。
  - 对并发或持久化相关改动，优先添加防御性检查（断言、LOG）和临时“可开关”的调试路径，而不是直接改变持久化格式。
  - 如需引入临时测试/调试脚本，放在 `dev/` 目录或外部，提交前删除或在 MR 中明确标记。

### Git Workflow
- 新功能、行为变化或架构调整需要先通过 OpenSpec 建立变更提案：
  - 在 `openspec/changes/<change-id>/` 下创建 `proposal.md`、`tasks.md` 以及对应的 spec delta，`change-id` 使用动词开头的 kebab-case（如 `add-blocking-list-refresh`）。
  - 使用 `openspec validate <change-id> --strict` 保证规范与变更描述一致，再开始编码。
- 纯 bug 修复、注释/格式调整或依赖更新可以直接修改，不强制创建 proposal，但仍建议在 commit message 中简要说明问题与影响范围。
- 推荐的分支与提交习惯：
  - 每个逻辑变更使用独立 feature 分支，小步提交，便于 code review 与回滚。
  - 提交信息使用英文动词短语（如 `fix domainlist snapshot race`, `refactor packet listener buffer`），并在需要时引用相关 spec/issue。

## Domain Context
- 项目定位与边界：
  - 这是 sucre 阻止器的“系统内核”组件，不负责 UI、HTTP 下载或用户配置管理；这些任务由上层应用完成，通过控制协议与本守护进程交互。
  - 当前实现以“单用户设备”为假设：`AppManager::make` 仍对 UID 取模（`uid % 100000`），不同 Android 用户下的同一包名会被折叠到同一逻辑 App 中；多用户支持的详细设计在 `docs/SNORT_MULTI_USER_REFACTOR.md` 中，但尚未在代码里落地。
- 网络与拦截模型：
  - iptables 建立专用链 `sucre-snort_INPUT`/`sucre-snort_OUTPUT`，通过 NFQUEUE 将除 DNS（53/853/5353）外的流量送入用户态处理。
  - DNS 解析由系统 `netd`/`DnsResolver` 完成，通过 Unix 域 socket `sucre-snort-netd` 把域名与 UID 以及解析出的 IP 列表发送给 `DnsListener`。
  - 数据包判决逻辑集中在 `PacketManager::make`：结合域名是否在黑/白名单中、App 的 blockMask 和 blockIface、是否启用 IP 泄漏防护（`blockIPLeaks`）、以及 IP 是否仍在有效期（`maxAgeIP`）得出最终 ACCEPT/DROP。
- 规则来源与优先级（按代码实现）：
  - 域名黑/白名单来自 `DomainList` + `BlockingListManager`：每个订阅列表对应一个 listId，域名的 blockMask 由所有列表的掩码合并而成。
  - 自定义名单：
    - 全局自定义黑/白名单：`DomainManager::_customBlacklist/_customWhitelist`。
    - 按 App 自定义黑/白名单：`App::_customBlacklist/_customWhitelist`。
  - 自定义规则：
    - `Rule` 支持 `DOMAIN`（精确匹配）、`WILDCARD`（`*`/`?` glob）和 `REGEX`；WILDCARD 会被安全地转为正则。
    - `RulesManager` 维护全局规则集合以及各规则关联的全局/按 App 定制绑定。
  - `App::blocked` 的决策顺序（简化版）：
    - 若未启用阻止或域名为空 → 不阻止。
    - 若启用 per-app 自定义列表：优先检查该 App 的自定义白名单/黑名单，再检查全局自定义规则/名单。
    - 否则根据 App 的 `blockMask` 与 Domain 的 `blockMask`（由标准/强化列表位决定）综合判断。
- 统计与观测：
  - `Stats`/`AppStats`/`DomainStats` 提供按天滚动窗口和“ALL/WEEK”视图，支持 DNS 请求数以及 RX/TX 包、字节数等。
  - 统计可通过 `ALL.*`, `APP.*`, `BLACK/WHITE/GREY.*` 等命令查看，事件则通过 `DNSSTREAM`, `PKTSTREAM`, `ACTIVITYSTREAM` 推送。
- Activity 模型：
  - `ActivityManager` 将最近前台 App 抽象为 `Activity` 对象，通过 `ACTIVITYSTREAM.*` 命令向订阅者推送，主要用于 UI 展示“当前活跃应用”与拦截状态变化。

## Important Constraints
- 性能与并发：
  - NFQUEUE 回调和 DNS 回调是极端热点，不得在这些路径中增加新的磁盘访问、网络访问或长时间持锁操作。
  - 访问 `mutexListeners` 的代码必须遵循既有模式：热路径使用 `std::shared_lock`，重置/全局操作在 `Control::cmdResetAll` 等处使用独占锁，并尽快完成。
  - `DomainList`、`BlockingListManager`、`DomainManager`、`AppManager` 等管理类已经为并发访问加上细粒度锁与快照逻辑，新代码在访问这些结构时应优先复用现有 API，避免绕过锁直接操作内部容器。
- 持久化格式兼容：
  - 所有持久化由 `Saver` 完成，包含严格的长度与格式检查（如域名最小长度、GUID 长度、阻止列表 URL 长度等）；任何修改持久化结构的改动都需要通过 OpenSpec 设计并慎重考虑升级/回滚场景。
  - `Settings::_version/_savedVersion` 已用于简单的迁移逻辑（如 V4→V5 统计迁移），新增字段时需要维护版本与相应迁移路径。
- 接口与向后兼容性：
  - 控制协议命令和返回 JSON 结构已经被上层 UI 依赖；对已有命令只允许兼容性扩展（新增字段），不允许随意改变字段含义或删除字段。
  - socket 名称（`sucre-snort-control`, `sucre-snort-netd`）、路径（`/data/snort/...`）、iptables 链名称等常量均被多个组件硬编码依赖，修改前必须更新相关规范与上游调用方。
- 多用户约束：
  - 目前代码仍按“单用户”实现，不支持真正的 per-user 规则/统计隔离；`docs/SNORT_MULTI_USER_REFACTOR.md` 描述的是未来演进方向，新功能在设计时可以参考但不得假定其已经实现。

## External Dependencies
- Android / 内核依赖：
  - Linux 内核 Netfilter 子系统（NFQUEUE）、iptables 命令行工具（`/system/bin/iptables`, `/system/bin/ip6tables`）。
  - `cutils` 提供的 `android_get_control_socket`，用于从 init 继承预创建的 Unix 域 socket。
- 上游服务与系统组件：
  - 系统 DNS 组件（netd / DnsResolver），通过 `sucre-snort-netd` socket 与 `DnsListener` 交互。
  - Android 包管理与 `packages.list`：`PackageListener` 依赖 `/data/system/packages.list` 作为 App UIDs 的权威来源。
  - 上层 sucre UI / 管理应用：负责向 `sucre-snort-control` 发送命令（例如管理 Blocking Lists、切换 App 拦截策略、开启流式订阅）并持久化用户配置。
- 外部列表/网络服务：
  - 屏蔽列表的下载与更新由上层应用负责；本守护进程只管理本地元信息和域名文件，不直接发起 HTTP 请求。
