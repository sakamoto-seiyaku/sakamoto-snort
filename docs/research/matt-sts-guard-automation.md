# Matt 工作流与 Stop That Shit Guard 自动化研究

> 2026-11-02 实施及验收更新：全局规则与默认 Guard 补充层已安装，12 项隔离检查通过；用户随后确认主线程和子代理均收到真实 Hook block。Skill 自动读取已配置，但新对话及子代理的实际读取记录尚未核实。最终配置、验证方法和能力边界以[操作记录](../agents/stop-that-shit.md)为准；下文保留实施前研究，其中阶段接口、独立角色机器隔离等未作为本次实现交付。

日期：2026-11-02。范围：当前 WSL Codex、已安装 STS 0.2.5、当前 Matt skills 与仓库授权规则。仅研究与隔离协议实验；未修改插件、Hook、Matt skills、配置或当前会话契约；未启动子代理或调用 Plane。

## 结论

可以自动化流程入口的契约建立，但当前版本不能仅靠一段 AGENTS.md 或一个额外 Hook，可靠覆盖「goal → 实施者 → 双轴审查 → 修复 → handoff」全链。需要显式的流程阶段接口，以及对 RTK、子线程身份和生命周期的适配。此前关于轻量 Hook 即可自动串起全链的判断过于乐观。

建议沿用 Matt 主流程，在其阶段边界加入一个共用的 Guard 适配层。阶段接口由模型按流程自动调用，Hook 执行机器约束；用户不需要每次添加 STS 前缀。接口只能在已授权范围内选择或收紧契约，不能以「进入 implement」或「创建 goal」自行制造授权。

本结论区分三件事：流程是否自动报出阶段、STS 是否返回拒绝、宿主是否实际阻止动作。下述实验只证明前两者涉及的当前协议行为，未验证宿主真实阻断。

## 已核对的一手来源

- [Codex Hooks 官方文档](https://learn.chatgpt.com/docs/hooks)：生命周期事件、Hook 并发、配置合并、子代理使用父 session_id、PreToolUse 输入、信任审核与 code mode 嵌套工具覆盖。
- [本机 STS skill](/home/js/.codex/plugins/cache/stop-that-shit/stop-that-shit/0.2.5/skills/stop-that-shit/SKILL.md)：初始观察模式、显式契约、Guard 与工程判断的边界。
- [契约解析](/home/js/.codex/plugins/cache/stop-that-shit/stop-that-shit/0.2.5/src/contracts.cjs:9)：默认 unconfirmed/watch；只解析正式 STS 指令与有限自然语言纠正，不识别 Matt workflow。
- [Codex 适配器](/home/js/.codex/plugins/cache/stop-that-shit/stop-that-shit/0.2.5/src/adapters/codex-hooks.cjs:27)：当前以 session_id 传给核心，未转换 agent_id 为独立角色契约；仅识别指定的 UUID spawn/wait 完成形状。
- [工具分类](/home/js/.codex/plugins/cache/stop-that-shit/stop-that-shit/0.2.5/src/adapters/codex-tool-classifier.cjs:66)、[决策](/home/js/.codex/plugins/cache/stop-that-shit/stop-that-shit/0.2.5/src/decision.cjs:95)：只读模式拒绝未知操作、文件边界要求可见写入目标、有限预算要求生命周期证据。
- [ask-matt](/home/js/.agents/skills/ask-matt/SKILL.md)、[implement](/home/js/.agents/skills/implement/SKILL.md)、[code-review](/home/js/.agents/skills/code-review/SKILL.md)、[handoff](/home/js/.agents/skills/handoff/SKILL.md)、[to-spec](/home/js/.agents/skills/to-spec/SKILL.md)、[to-tickets](/home/js/.agents/skills/to-tickets/SKILL.md)、[grill-with-docs](/home/js/.agents/skills/grill-with-docs/SKILL.md)。ask-matt 提到的 implement-spec 在当前全局技能目录没有实际文件，不能当成已安装入口。
- [仓库 AGENTS.md](../../AGENTS.md)：默认主线程；启用实施子代理需要用户明确授权；同任务唯一实施者；已授权实施中的双轴只读审查、固定基线和临时目录 handoff。

判断以本机安装版本为准，不将上游 main 的新功能当成 0.2.5 已具备的能力。

## 隔离实验

复现：`rtk proxy node /tmp/matt-sts-research-uJwTNL/probe.cjs`。

[实验脚本](/tmp/matt-sts-research-uJwTNL/probe.cjs) 与 [原始结果](/tmp/matt-sts-research-uJwTNL/results.json)。脚本直接调用本机插件真实适配器，使用独立 dataDir 和虚构 session/tool id；所有待检查的读写、派工和 Plane 命令均仅作为数据传入，没有执行。运行 exit 0，协议断言全部通过。

| 输入场景 | 观察到的结果 | 对接入方案的意义 |
| --- | --- | --- |
| 提交 `$implement -- …` 后检查补丁 | 保持 unconfirmed，未返回拒绝 | Matt 调用不等于 Guard 启用 |
| 显式 STS change / review 检查同一补丁 | change 未拒绝，review 返回 deny | 当前核心可实施模式约束 |
| 同 session、附 reviewer agent_id 的写入，父为 change | 未拒绝 | 当前适配器没有按角色隔离 |
| 同 session 的 reviewer 提交 review 契约 | 父状态也变 review，父补丁被拒绝 | 不可用全局切模式模拟并行角色 |
| 独立、未初始化的子 session 检查写入 | unconfirmed，未拒绝 | 分 session 也必须初始化及绑定父授权 |
| review 中检查 `cat` | read，未拒绝 | 正向对照 |
| review 中检查 `rtk proxy cat`、`rtk git diff`、`rtk proxy rg` | unknown，返回 deny | 与本仓库必须使用 RTK 的规则冲突 |
| review 中检查示例 Python Plane CLI 列表命令 | unknown，返回 deny | CLI 的只读操作需显式识别，不能放行任意 Python |
| 检查 create_goal / update_goal | 被按名称归类 write | goal 元数据操作需单独分类，不能等同产品修改 |
| 锁 docs/** 后检查 Python 文档写入命令 | 返回 deny，写入路径不明 | 文档白名单需要路径可见的工具 |
| agents=1；V2 spawn 返回 task_name，wait 返回 message/timed_out；再 spawn | AGENT_BUDGET_EXHAUSTED | V2 邮箱结果不是当前适配器认可的完成证据 |
| 上述有限预算下 followup_task | DELEGATION_LIFECYCLE_UNPROVEN | 与仓库要求优先复用原实施者发生冲突 |

这些是合成事件实验，不证明当前宿主在每条真实子代理工具事件上携带哪些身份字段，也不证明目标文件实际受到宿主阻断。

## 工作流应如何映射

以下是建议配置，不是当前已启用功能。

| Matt 阶段 | 允许的责任 | 建议 Guard 配置 |
| --- | --- | --- |
| ask-matt / 纯讨论 | 读取、解释、选择已有流程 | answer；默认无新增派工 |
| grill-with-docs | 讨论并维护已授权 glossary / ADR | 文档写入配置；源代码不可写 |
| to-spec / to-tickets | 产出规格、拆票；确认后写入 Plane | 本地文档路径与指定 Plane 操作分别授权；不自动开启产品实施 |
| implement / tdd / 已授权修复 | 完整实施、必要测试和运行验收 | change；沿用任务范围、提交限制、数据与设备边界 |
| Standards / Spec 审查 | 读取受审源码、返回报告 | review；若须落盘报告，单独允许精确的临时报告文件 |
| 修复完成后的复核 | 只检查受影响结论 | 同上；保留有效的旧证据 |
| handoff | 引用已有材料，写临时交接文档 | 仅允许确定的临时交接文件，不开放产品源码 |
| 同 goal 的已授权下一票 | 沿用授权、恢复对应流程阶段 | 从已保存的任务状态进入，不能继承上一角色的任意写权限 |

原生 review 会拒绝所有 write，包括临时报告。需要落盘时，可在父授权允许的前提下采用 change + 精确报告路径锁，使源码保持不可写；报告写入须通过能显示路径的工具。不得为了保存报告开放整个 /tmp 或整个仓库。

Plane 操作不能只用本地 files= 白名单表达。其 CLI 操作、对象和项目范围要单独确认；guard 放行不替代用户授权和既有 Plane skill 规则。

## 推荐的最小设计

### 1. 一个共用的阶段入口

增加内部结构化接口，例如 `workflow_enter(phase, task_ref, role, report_path)`，由 Matt skills 的薄前置步骤和 goal 续行约定自动调用。名字仅为设计示例，当前没有该工具。

用户直接调用明确的 Matt skill 时，UserPromptSubmit 可按固定映射建立对应初始配置。模型在同一轮中调用下一个 skill、从 goal 自动续行时，通过阶段入口表达切换。读取某个 SKILL.md 只是取资料，不能作为进入阶段或获得权限的证据。官方事件列表没有 SkillEnter 事件。

纯自然语言 goal 不携带可靠的任务权限类型；适配层需要已确认的任务授权记录或结构化目标配置。无法确定时保持当前权限，只在确实缺少授权时询问。不能靠关键词猜测后默认给所有 goal change。

阶段入口必须校验任务与用户授权上限：新 skill、handoff 建议、模型自报的角色不能增加外部写入、产品修改或派工授权。审查者不能调用阶段入口将自己提升为实施者。

### 2. 根任务与执行角色分别存状态

根任务保存授权上限、任务引用与既有限制；实施者、Standards、Spec 各有角色约束。只读审查开始时不修改父实施者契约；审查结束后原实施者仍保留处理已授权修复的权限。

当前适配器按 session_id 建契约，而官方文档说明子代理 Hook 使用父 session_id。因此完整角色隔离需要宿主在每条受控动作上提供可验证的当前线程身份，并关联到实际派工请求。仅在 SubagentStart 知道一个 agent_id，不足以区分其后每个并发 PreToolUse。当前文档对 PreToolUse 的字段表未承诺该身份字段；落地前必须核实当前宿主的真实载荷或补充宿主适配。不得用 task_name 文本顺序、提示词或模糊 transcript 解析代替身份关联。

如果当前宿主无法提供上述身份，全链角色 Guard 是明确的适配阻塞；可先做主线程范围内自动契约，不能宣称独立审查已被机器隔离。

### 3. 一个有序的 Hook 执行链

建议在可维护的本地派生插件或上游扩展中实现「阶段解析 → 授权校验 → 角色定位 → STS 核心判断 → 宿主响应」，复用固定版本核心。不要直接修改安装 cache；也不要让原插件与新插件重复处理同一委派事件。

Codex 多来源 Hook 会合并，且同事件 Hook 并发执行。另加一个“先设状态”的独立 Hook 不能保证它先于原 STS 检查；重复处理 delegation 还可能污染预算。后续安装应保证事件只有一个处理入口，并正常重新审核 Hook 信任。

### 4. 补齐当前实际工具适配

- RTK：识别批准的 RTK 形式并继续检查被包装的命令；不能把所有 rtk、python、node 命令归为只读。
- goal：区分目标元数据控制与产品/外部数据写入；目标创建和状态更新不产生新任务授权。
- Plane：识别实际 CLI 的只读与写入子命令；对象授权仍来自任务与既有规则。
- 子代理：先解决当前线程关联和 V2 确切完成/重启证据，才承诺有限任务预算；不能清空账本或扩大 agents=N 掩盖不兼容，也不能把原生线程并发上限当成同等语义的替代。
- 文档与报告：使用显式路径写入入口；构建缓存、报告输出和源码修改按实际责任分别处理，避免提前锁死未知的实施文件清单。

## 落地顺序与验收边界

1. 先在临时工程打通主线程：用户明确 Matt 入口 → 自动 Guard → RTK 正常读 → 越权写实际被宿主拒绝 → 授权写成功。
2. 接入结构化阶段转换与 goal 续行，验证压缩/恢复沿用契约、新任务不继承无关写权限、用户收紧权限立即生效。
3. 在已授权的实施链中核实真实线程身份与完成事实，再贯通唯一实施者 → Standards/Spec 源码只读 → 完整报告 → 原实施者修复/复核 → 临时 handoff → 下一票。不用现有主线程单测冒充独立审查或真实宿主验收。

当前研究已定位的问题全部映射到上述自动化目标。无需新造调度器、增加审查轮次或修改产品代码。STS 的 Guard 仍只约束可识别动作；“是否过度设计”“验证是否足够”继续由 Stop Ladder 和项目验收规则判断。

## 无感使用的具体接法与两条模拟链

补充要求：用户维持日常自然语言、直接 `$implement` 或明确授权主线程调度子代理的用法。所有阶段声明由代理和适配层内部完成，不增加用户命令、前缀或逐阶段确认。

### 一次性配置分工

1. **全局 AGENTS.md 的简短规则**：每个主/子线程自动读取并应用已安装 stop-that-shit skill；日常任务与 Matt 流程均适用；遵守已确认的任务授权；内部阶段变化自动通知适配层；Guard 不可用时如实报告，不以文字约束声称机器拦截。
2. **一个共用的阶段调用约定**：普通主线程由全局规则驱动；grill-with-docs、to-spec、to-tickets、implement、code-review、handoff 的入口引用同一约定。声明由代理自动完成，不要求用户额外调用。阶段声明不是权限授予。
3. **集成后的 Hook 适配器**：SessionStart/compact 恢复默认约束并注入 Skill 应用规则；UserPromptSubmit 接收新任务及用户纠正；PreToolUse 定位执行角色、处理受限的阶段声明、调用 STS；PostToolUse 记录有身份关联的实际结果。SubagentStart 只能在可验证身份关联成立时初始化角色，不凭该事件推断完成。

上述为待实现方案。当前 0.2.5 没有 `always_on`、`matt_auto` 或 `workflow_enter` 配置开关；其 defaultContract 硬编码 unconfirmed/watch。不能将这些设计词直接写入 config.toml 并声称生效。会话默认 Guard 策略应由适配层显式配置初始化，不应伪造用户发送过 STS 指令。

### 场景 1：日常主线程 → grill-with-docs → to-spec → to-tickets

用户只需表达原任务，例如“讨论这个方案，整理规格，再拆票”。主线程自动应用 STS Skill，按当前授权进入讨论；采用 Matt 流程时自动发出内部阶段声明。纯讨论保持只读，grill-with-docs 允许相关 glossary/ADR，to-spec/to-tickets 在已有批准条件下允许指定 Plane 操作，产品源码始终不因此获得写权限。需要的业务决定仍按现有技能处理，系统不再单独询问是否开启 STS。

内部阶段可以表达为 discussion → planning-docs → spec-publish → tickets-publish。这些名称是适配层配置，不是额外用户命令。发布到 Plane 必须识别真实 CLI 子命令和对象，不能用文件白名单伪装成已覆盖外部系统。

### 场景 2：主线程调度 → 子线程 implement → code-review → 修复

用户仅给出一次原本就需要的实施/子代理授权。主线程根据该授权调度唯一实施者；实施者自动应用 STS Skill、进入 implement 配置、执行必要验证。code-review 时，仅为两个真实审查线程应用 review 配置；父实施者不跟着切成 review。若报告需落盘，为每个审查者绑定单独的精确报告输出路径，不开放源码。原实施者依据报告继续修复和必要复核，再写临时 handoff。每一步均不要求用户添加 STS 调用。

### 本轮候选配置模拟

[脚本](/tmp/matt-sts-research-uJwTNL/scenarios.cjs)、[结果](/tmp/matt-sts-research-uJwTNL/scenarios-results.json)。使用本机 STS `decide` 核心直接求值，10 项断言通过；候选契约由测试数据提供，线程身份与阶段未由宿主实际捕获。没有执行受检动作、创建真实子代理或修改当前运行状态。

| 候选配置 | 受检行为 | 核心结果 |
| --- | --- | --- |
| 主线程 discussion | 读取 | allow |
| 主线程 planning，限定文档路径 | 写 glossary / 写源码 | allow / deny |
| 实施者 implement | 修改源码 | allow |
| 审查者 review | 读取 / 修改源码 | allow / deny |
| 审查报告配置，仅精确临时输出路径 | 写报告 / 修改源码 | allow / deny |
| 审查后实施者 implement | 继续修复 | allow |
| 实施者 implement，hash=deny | 引入未授权 hash | deny |

此模拟说明 STS 核心能表达这些候选约束，不说明无感阶段识别、线程路由、RTK 分类、Plane 授权或真实宿主阻断已经实现。完整验收仍按前述落地顺序进行。
