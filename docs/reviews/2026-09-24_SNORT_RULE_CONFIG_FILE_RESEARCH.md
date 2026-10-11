# 旧版与开源 Snort 的配置文件、读写与运行合同

核对日期：2026-09-24。用户要求回看旧版及开源来源的实际文件方式，先说明谁写、谁读和怎样运行，不继续扩大实体 / 持久化设计。本报告将项目沿革中的 **iodé-snort / sucre-snort** 与另一个独立项目 **官方 IDS/IPS Snort 3** 分开。

## 1. 直接结论

文件方式有明确依据，但查到的是两种过程，不能混成一个“前后端都直接读写同一文件”的历史合同：

| 范围 | 已核实过程 | 证据性质 |
| --- | --- | --- |
| iodé-snort 上游 | daemon 启动从私有保存文件恢复规则，在内存中维护；通过控制 socket 提供规则增删改查，再由 daemon 保存文件 | 本轮读取固定公开源码 |
| 我们旧非 VPP 版本 | 留存文档记录控制命令、daemon 内存状态与 save tree；后续 SNORT-10 设计也明确由 daemon 持有 authoring bundle，前端通过命令读写 | 保留的历史文档；不同年代的设计与实施声明分别解释 |
| 官方 IDS/IPS Snort 3 | 读取外部准备的 Lua 配置和文本规则，建立内存检测结构；修改文件后显式重载并验证切换 | 官方文档与源码，详见第 4 节；不是本项目已证实的上游 |

可以据此讨论当前产品采用一份约定格式的持久配置文件，再加载为 VPP 内存实体与编译快照。**文件的单一写入职责、生效入口与 UI 交互并未被这项核对自动决定**；没有证据要求先建立 Rust 与 VPP 两套可独立修改的完整配置系统。

## 2. iodé-snort：daemon 维护实体并读写文件

来源为官方项目 [`os/public/blocker/iode-snort`](https://gitlab.iode.tech/os/public/blocker/iode-snort)，固定到此前沿革调查使用的公开提交 `5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9`。本次从官方 GitLab REST API 的 file/raw 端点读取对应文件；不声称它是今日最新提交。该来源身份另见[既有上游调查](2026-09-15_DOMAIN_MATCHER_UPSTREAM_RESEARCH.md)。未读取、恢复或移植本项目已移除的 C++ 实现。

- **路径与绑定。** `Settings` 定义 `/data/snort/settings`、`/data/snort/save/rules`，以及应用保存目录等。`RulesManager` 的 `_saver` 直接绑定 `settings.saveRules`，因此规则保存 / 恢复由 daemon 中的管理器负责。[Settings.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Settings.hpp#L15)、[RulesManager.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/RulesManager.hpp#L34)
- **启动恢复。** 主入口调用 `settings.start()`，然后恢复规则、域名、应用等状态；`RulesManager::restore()` 读取 ID 分配计数、规则数量及逐条规则的 ID / 类型 / 内容，并创建内存对象。[入口](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/iode-snort.cpp#L49)、[规则恢复](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/RulesManager.cpp#L115)
- **运行修改。** `Control` 启动 Android Unix control socket，注册 `RULES.ADD/REMOVE/UPDATE/PRINT`；相应 handler 直接调用 `RulesManager`。更新规则后，管理器重建受影响的自定义规则匹配结构。这能证明有明确的控制命令入口，不是仅靠前端改文件后等待引擎发现。[命令注册与 socket](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Control.cpp#L92)、[命令处理](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Control.cpp#L650)、[更新与重建](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/RulesManager.cpp#L50)
- **保存。** 主循环调用 `snortSave()`，后者保存 settings、rules、domains、apps 等；正常退出信号路径也调用保存。固定版本的周期为 60 分钟，不能据此说每个规则修改命令都立即完成耐久落盘。[保存入口](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/iode-snort.cpp#L120)、[周期设置](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Settings.hpp#L25)
- **文件格式。** `Saver` 是二进制读写辅助，字符串包含长度，保存时写 `.tmp` 后 rename。它不是 SQLite，也不是一个已公布、前后端都必须实现的 JSON 配置协议；本轮未验证其掉电耐久性或错误恢复。[Saver.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Saver.cpp#L20)、[Saver.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Saver.hpp#L67)

另有一类 **预置名单输入文件**：`/system_ext/etc/iode-snort/domains-black` 与 `domains-white`。`DomainList` 从中读取 hostname 和 mask 的文本对。这与上述可修改规则的私有二进制保存文件不同，不能把两种文件混成同一种合同。[路径](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/Settings.hpp#L45)、[文本名单加载](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/DomainList.cpp#L44)

```text
私有保存文件 → daemon 启动恢复 → 内存规则对象 → 匹配结构
                                   ↑
                          RULES.* 控制命令
                                   ↓
                          daemon 保存回文件
```

本轮没有全面审计 iodé 图形客户端，所以不声称它绝不读取任何文件；能核实的是上述 daemon 自管文件和控制命令流程，没有据此找到“双端必须直接解析同一保存文件”的公共协议。

## 3. 我们旧版保留文档中的文件与控制职责

旧接口存档列出 `/data/snort/settings`、`/data/snort/save/rules`、`blocking_lists`、`domains_lists/` 与策略检查点文件，同时明确 Unix socket 控制协议以及 `IPRULES.PRINT/APPLY`、域名规则命令等。[历史接口：控制协议](../archived/pre-vpp/INTERFACE_SPECIFICATION.md:9)、[规则命令](../archived/pre-vpp/INTERFACE_SPECIFICATION.md:93)、[保存路径](../archived/pre-vpp/INTERFACE_SPECIFICATION.md:375)

2026-04-26 的 RESETALL 并发记录描述 daemon 的 `snortSave()`、内存 Manager、save tree 以及周期保存之间的协调，支持“旧 daemon 自己保存 / 恢复运行配置”的历史职责判断。它不是今天产品的锁或线程模板。[历史记录](../archived/pre-vpp/RESETALL_RUNTIME_CONCURRENCY.md:7)

2026-03-24 的 IPRULES 设计要求保存规则定义和 `nextRuleId` 高水位，路径举例为 `/data/snort/save/iprules`；该文把具体路径留给实施，不能单凭它将这个示例升级为本轮已核实的实际文件名。2026-04-30 的 checkpoint 设计则明确 slot bundle 是 daemon 私有格式，非对外导入 / 导出协议。[IPRULES 保存设计](../../archive/openspec/changes/archive/2026-03-24-add-app-ip-l3l4-rules-engine/design.md:259)、[checkpoint 设计](../../archive/openspec/changes/archive/2026-04-30-add-policy-bundle-checkpoints/design.md:18)

之后的 SNORT-10 Authoring 讨论明确由 daemon control-plane / persisted store 保存源配置，前端通过命令操作而不拥有独立规则数据库；packet path 只读编译后的 Runtime Snapshot。这是后期设计收口，不能与更早实现或当时重建主线的交付状态混同。[SNORT-10 §10](SNORT_10_DISCUSSION_NOTES.md:435)

因此，保留证据支持的是“有约定路径和保存格式，daemon 维护实体并提供控制命令”。它没有证明我们旧版已经采用“两端直接共同编辑同一配置文件”的架构。本轮只读这些历史文档，未读取已删除的产品 C++ 源码。

## 4. 官方 IDS/IPS Snort 3：外部文件输入与重载对照

本节范围仅为官方 IDS/IPS [Snort 3](https://github.com/snort3/snort3)；下列源码链接指向本次核对的 `master`，会随上游更新。本节不将它视为 `sakamoto-snort` 已证实的上游，也不将其行为套用于 iodé-snort / sucre-snort。仅作文件模式对照，不构成本项目规格或实现建议；未读取本项目已移除的 C++ 实现，未构建或实验。

**直接回答：有明确的配置和规则文件格式，以及引擎加载它们的约定；本次查阅的官方材料没有给出“独立前端与引擎双方必须读取同一个文件”的协议。** 官方写作指南明确指定 Snort 怎样消费这些输入，但没有指定前端、编辑器或持久化服务应怎样实现。[配置入口](https://docs.snort.org/start/configuration)、[规则入口](https://docs.snort.org/start/rules)

| 问题 | 官方材料能确认的事实 |
| --- | --- |
| 启动读什么？ | `-c snort.lua` 指定主配置；Snort 不默认寻找某个固定配置文件。发行版提供基础配置 `snort.lua`、`snort_defaults.lua`。具体还读什么由配置引用决定：官方示例包含 defaults，并为文件类型识别指定 `file_magic.rules`。[配置说明](https://docs.snort.org/start/configuration)、[官方示例 `lua/snort.lua`](https://github.com/snort3/snort3/blob/master/lua/snort.lua) |
| 配置和规则如何分开？ | Lua 配置负责模块、变量、日志和规则路径等；检测规则通常放在独立文本文件，通过 `ips = { include = 'local.rules' }` 或 `-R local.rules` 加载。也能把规则直接放进 `ips.rules`，或用 include 引入多份规则；并非强制只有一个文件。[配置说明](https://docs.snort.org/start/configuration)、[规则说明](https://docs.snort.org/start/rules) |
| 谁创建、写入？ | 官方提供默认配置；用户可以自己编写规则，也可以取得 Talos 等来源的规则；官方站点提供 Snort 3 Community Rules 下载。手册演示的是外部修改配置文件后通知 Snort 重载，没有指定必须由某个前端负责写入。[手册 §1.2.1、§4.10](https://github.com/snort3/snort3/blob/master/doc/user/snort_user.text)、[官方下载页](https://www.snort.org/downloads) |
| 引擎如何执行文件？ | 主配置是加载时执行的 Lua 脚本。源码中的 `SnortConfig::setup()` 调用 `ParseRules()`，完成规则校验后建立快速检测结构；`fpCreateFastPacketDetection()` 创建规则组与映射，并准备/编译模式匹配器。因此数据包处理使用引擎内存中的检测结构。[手册 §1.2.1](https://github.com/snort3/snort3/blob/master/doc/user/snort_user.text)、[`SnortConfig::setup()`](https://github.com/snort3/snort3/blob/master/src/main/snort_config.cc)、[`fpCreateFastPacketDetection()`](https://github.com/snort3/snort3/blob/master/src/detection/fp_create.cc) |
| 改文件怎样生效？ | 手册给出修改配置后发送 `SIGHUP` 的流程。源码 `main_reload_config()` 调用 `get_reload_config()`，后者重新解析、验证并执行 setup；成功后广播配置切换。解析/校验失败不进入切换；部分设置不能热改，需要重启。[手册 §3.7.1、§4.10](https://github.com/snort3/snort3/blob/master/doc/user/snort_user.text)、[`Snort::get_reload_config()`](https://github.com/snort3/snort3/blob/master/src/main/snort.cc)、[`main_reload_config()`](https://github.com/snort3/snort3/blob/master/src/main.cc) |

按上述官方入口和实现，普通文件模式可以概括为：

```text
用户/规则发布者准备配置与规则文件
                  ↓
Snort 启动读取 → 解析/校验 → 建立内存检测结构 → 处理流量
                  ↑
外部修改文件 → 显式触发 reload → 校验成功后切换运行配置
```

这里须区分两个层次：**文件格式规定“引擎接受什么”；集成产品另外决定“谁提供编辑界面、谁读写文件”。** 前端读取同一文件以显示和编辑，是可以采用的产品设计，但属于这一事实基础上的推论，不能宣称官方 Snort 已定义了这样的前后端协议。磁盘文件已修改，也不等于正在运行的引擎已经采用它；官方的重载和失败保留机制正体现了两者的区别。[规则文件入口](https://docs.snort.org/start/rules)、[手册 §3.7.1、§4.10](https://github.com/snort3/snort3/blob/master/doc/user/snort_user.text)
