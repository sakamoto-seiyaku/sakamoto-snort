# Stop That Shit：全局默认约束与 Guard

记录日期：2026-11-02。适用环境：当前 WSL Codex、STS 0.2.5、全局 Matt skills。

## 使用方式

用户维持原有用法：普通主线程对话、`$implement`、已授权的主线程调度、子线程实施与 `$code-review`，以及 goal 续行。无需每次添加 STS 指令或再调用一层包装技能。`$code-review` 的专用 Standards／Spec 审查子代理现为 STS 例外，见下文；主线程与实施者继续使用 STS。

本次采用全局指令与默认 Guard 补充层；没有实现此前研究提出的阶段接口或新的调度框架，没有修改原版插件源码和 Matt skills。

## 已安装配置

| 文件 | 作用 |
| --- | --- |
| `/home/js/.codex/AGENTS.md` | 要求主线程、子线程及 goal 续行自动读取并应用 STS Skill；约束范围扩张、无用防御、重复验证及完成后继续打转 |
| `/home/js/.codex/hooks.json` | 为 SessionStart、SubagentStart、PreToolUse 注册全局 Hook |
| `/home/js/.codex/hooks/sts-default-guard.cjs` | 调用本机 STS 决策核心，为原插件尚无明确契约时补上默认基础 Guard |
| `/home/js/.codex/config.toml` | 保留原 STS 插件启用、版本固定和原有模型配置；本次没有修改该文件 |

原版插件固定为 `stop-that-shit@stop-that-shit` 0.2.5。新增脚本直接依赖其安装目录：

```text
/home/js/.codex/plugins/cache/stop-that-shit/stop-that-shit/0.2.5
```

全局 Hook 使用的 Node 路径：

```text
/home/js/.nvm/versions/node/v24.14.0/bin/node
```

升级插件、切换 Node 或迁移机器时，需要相应调整路径。以上属于本机实际配置，不是 STS 原生提供的 `always_on` 配置项。

## Skill 与 Guard 如何分别参与

**STS Skill 是模型遵循的工程规则。** 全局 AGENTS 要求自动读取并应用；SessionStart 与 SubagentStart 再次注入提醒，并明确专用 code-review 审查子代理的例外。其他普通对话与 Matt 流程均适用，已存在于上下文时直接沿用。Hook 不会替模型读取 SKILL.md 全文，也不保证模型一定遵从每条工程判断规则。

**Guard 是工具执行前的机器检查。** 新增 PreToolUse Hook 读取原版插件的现有契约：

- 契约仍为默认来源、`mode=unconfirmed` 且未关闭时，用 `change + guard`、`hash=deny`、`deps=ask` 调用真实 STS `decide` 核心。
- 核心要求拒绝或重新授权时，返回宿主支持的 PreToolUse deny。`deps=ask` 在本补充层表现为拒绝并说明原因，不声称自动弹出许可问题。
- 已有显式原生契约、显式 watch/off 或恢复状态时，补充层不重复决定，由原插件处理。
- 不写原插件的状态、不增加第二份派工预约，也不清空其账本。

### 必要哈希的一次动作许可（2026-11-02 更新）

针对“功能补丁中的必要哈希被拒绝，代理随后绕成更慢算法”的实际反馈，补充层增加了一次动作许可。默认仍为 `hash=deny`，不把整个任务或会话切为 `hash=allow`。

代理自动处理以下流程，用户无需额外输入 STS 指令：

1. 遇到 hash 拒绝时，从返回信息取得 `Hash request` 文件。
2. 检查当前已授权需求与真实调用链，写一份临时 JSON 理由，包含 `requirement`、`purpose`、`consumer: {path, line}` 和 `effect`。消费者应是请求产生前已存在的源码或已批准规格；不能用新增的理由文件、无关行号或额外 verifier 循环证明用途。
3. 按拒绝给出的实际文件路径执行内部命令：

   ```text
   rtk proxy node /home/js/.codex/hooks/sts-default-guard.cjs --permit-hash <request文件> <理由文件>
   ```

4. 许可只放行原来的完整工具动作一次；代理在同一轮重试该动作，不另行修改会话策略。

Hook 核对需求说明字段、证据文件和行号存在，且证据没有在请求之后新建或修改；许可绑定宿主提供的 session、actor（agent_id 或不解析内容的 transcript_path）、turn、cwd 与完整工具参数，十分钟过期、原子消费一次。字段缺失、证据缺失、动作变化、跨上下文或重放均不获得许可。许可文件放在 `/home/js/.codex/hooks/sts-hash-requests/`，与原插件状态分开；过期记录在读取相应 session 目录时清理，已消费许可立即移除。

命令行哈希还须带不超过60秒的 `timeout`，使用明确输入；递归、通配符及复合 shell 命令不在自动许可范围。普通 commit/push 不自动授权额外 checksum；有效结果应直接复用。依赖、显式原生 STS 契约和其他 Guard 约束没有因此放宽。

这不是独立的语义审核器：Hook 不能证明某个消费者行号真的支持模型陈述的必要性，任务相关性与证据真实性仍由模型根据 STS Skill 判断。机器部分保证的是许可范围、时效和一次消费；许可通过不能反过来证明该哈希有用。

更新前的脚本与全局 AGENTS 备份位于 `/home/js/.codex/backups/sts-scoped-hash-20261102T065004Z-_9cscfua`。更新没有改动 Hook 命令注册或信任记录；若宿主提示代码变更需重新信任，在 `/hooks` 正常审核。

默认 `change` 只用于基础 Guard 求值，不增加用户的任务修改或派工授权。这个补充层主要补上可识别 hash、依赖添加等基础检查；不会自动推导某段代码是否属于用户需求。

## Matt 流程中的行为约束

| 场景 | 自动应用的规则 |
| --- | --- |
| 普通主线程对话 | 使用直接方案，尽早交付可验证结果；不自行增加规格、拆票、ADR 或证明材料 |
| grill-with-docs → to-spec → to-tickets | 沿用 STS；文档与 Plane 发布遵循已有任务授权及原技能的必要确认；讨论不自动扩大为产品实施 |
| implement / TDD / 修复 | 补齐必要调用链与验收；普通选择不重复请示；有效证据直接复用 |
| 主线程调度子线程 | 传递任务范围、角色、规格与验收；子线程同样自动应用 STS；派工仍需符合项目授权 |
| code-review / Standards / Spec | 专用审查子代理不应用 STS Skill 和全局默认 Guard；保持源码只读、分别报告；调度者与原实施者继续使用 STS |
| handoff / goal 续行 | 引用已有证据、写指定临时交接材料，连续完成已授权步骤；不产生额外用户操作 |

以上角色规则来自全局指令和既有技能。本次没有为每个角色建立独立的机器权限契约，不能将它们描述为已完成源码写权限的硬隔离。

### code-review 审查子代理例外（2026-11-02 更新）

用户要求专用 Standards／Spec 审查不受 STS 的工程判断和默认 Guard 过滤。已更新本机与 u22s 的全局 AGENTS、`code-review/SKILL.md` 及补充 Hook；原版 STS 源码和显式契约未改变。

调用 `$code-review` 后，由分派模板在两个子代理消息首行分别加入：

```text
STS_CODE_REVIEW_REVIEWER=standards
STS_CODE_REVIEW_REVIEWER=spec
```

Hook 记录该固定角色分派；专用审查子代理跳过 STS Skill，并在每轮审查前自动执行当前主机上的内部登记命令：

```text
rtk proxy node /home/js/.codex/hooks/sts-default-guard.cjs --reviewer-exempt standards
```

Spec 角色使用 `spec`。u22s 的技能模板已使用实际 Node 与 `/home/u22s` 脚本路径。用户无需增加任何调用。

登记要求同一 session 存在匹配的角色分派、登记 actor 与分派父 actor 不同、cwd 相同且分派记录未过期。例外匹配该 actor、turn 和 cwd；下一轮需要重新登记，分派与例外记录最长24小时有效。父线程、实施兄弟线程和其他会话不因该登记自动获得例外。普通消息出现 review 字样不会产生角色分派；未标记分派或父线程给自己登记会被拒绝。

以 PreToolUse 返回的“Dedicated code-review child registered”确认为准，CLI 普通完成信息本身不证明已豁免。登记记录位于当前用户 `.codex/hooks/sts-reviewer-exemptions/`；不修改共享原生契约，不清除派工账本。关联依据是固定分派标记和宿主提供的执行上下文，不是独立身份认证或源码写入沙箱。不得复用该专用审查者承担实施工作。

例外覆盖 STS Skill 与本方案的全局默认 Guard，包括哈希/依赖的默认拦截；源码只读、审查标准、Spec 覆盖与宿主权限仍然有效。用户显式设置的原生 STS 契约仍由原插件执行，不在此例外内。审查调度主线程、原实施者与普通子线程继续使用 STS。

本机与 u22s 的隔离验证均通过：专用角色登记、父/兄弟线程保留 Guard、两轴独立、跨轮/跨会话不沿用，以及显式原生契约保留；必要哈希许可检查与原有12项检查也仍通过。`code-review` 技能校验通过。没有为此启动真实审查子代理，尚未声称新登记链完成真实子代理验收。更新 Hook 后若宿主提示变更，按 `/hooks` 正常审核信任。

本机备份：`/home/js/.codex/backups/sts-reviewer-exemption-20261102T111136Z-nmm38ou2`；u22s 备份：`/home/u22s/.codex/backups/sts-reviewer-exemption-20261102T111159Z-t9akiyhj`。本机隔离验证材料：`/tmp/sts-reviewer-exemption-S5pN9f`；远端材料：`/tmp/sts-reviewer-verification-5gkuzrh4`。

## 验证结果及证据边界

| 项目 | 已有证据 |
| --- | --- |
| 全局指令加载 | 修改后的 AGENTS 内容已重新注入当前会话 |
| 默认 Guard 逻辑 | 12 项隔离检查通过，覆盖主/子线程提醒、普通 RTK 读取、补丁放行、直接及 RTK 包装的 hash/依赖拦截、显式契约保留与账本不变 |
| 安装产物 | 已安装脚本与受测源码一致；语法检查通过；直接输入测试事件会返回预期 HASH_NOT_AUTHORIZED |
| 一次动作许可隔离验证 | 必要补丁、完整动作匹配、单次消费、过期、不同上下文、重放拒绝、证据缺失、限时 shell、依赖约束及原生契约保留均通过；原有12项检查仍通过 |
| 一次动作许可真实宿主验证 | 当前主线程的 `rtk proxy timeout 5s sha256sum /dev/null` 先被拦截；提交任务验收用途和现有测试依据后获许可并实际执行；同一命令再次被拦截，证明没有转成会话级放行 |
| 主线程真实宿主拦截 | 用户在新对话验证后确认收到 Hook block |
| 子代理真实宿主拦截 | 用户确认子代理也收到 Hook block |
| STS Skill 实际读取 | 当前主线程已读取；上述新对话与子代理的读取记录尚未核实，不能由 block 结果推导 |

用户确认的宿主验证来自本次对话，没有另行保存该新对话和子代理的原始工具输出。隔离检查使用真实 STS 核心与临时状态，没有执行受检的命令。

一次动作许可的隔离脚本为 `/tmp/sts-scoped-hash-d3e0Md/verify.cjs`，原有检查复用 `/tmp/sts-scoped-hash-d3e0Md/baseline-verify.cjs`；这些是临时验证材料。当前主线程的新增许可链由本次实际工具记录验证；尚未声称子代理的新增正向许可链也完成真实验收。原先主/子线程 block 的用户确认仍然有效。

## 新对话复核

新增或变更 Hook 后，在 Codex `/hooks` 中审核并信任对应命令一次。不要手工修改信任记录。[官方 Hook 说明](https://learn.chatgpt.com/docs/hooks)

在新对话中，不添加 STS 前缀，先完成普通仓库状态读取，再要求通过工具做一次负向测试：

```text
rtk proxy sha256sum /dev/null
```

收到拒绝即停止，不重试、不换方法、不改契约。默认补充层的预期拒绝包含：

```text
Global STS default Guard: HASH_NOT_AUTHORIZED
```

打印出哈希结果或出现 `could not check this action` 都不算通过。子代理可在明确授权下执行相同的负向测试。要验证 Skill 是否自动读取，应检查各线程实际读取 `stop-that-shit/SKILL.md` 的工具记录，而不是仅询问模型是否启用。

原插件仍显示 `unconfirmed/watch-only` 不足以否定补充层；以真实工具拒绝及其来源判断。对新会话而言，默认来源且未确认的契约才进入该补充层。

## 已知边界与回退

- 原版 STS 显式 review 模式对部分 RTK 读取的分类限制仍存在；本次普通 RTK 读取通过，不代表已修复原版 review 适配。
- 未实现独立角色机器隔离、自动阶段契约及 V2 有限派工预算的生命周期适配。主/子线程收到基础 block，不等于这些能力已完成。
- Hook 运行失败不是成功拦截的证据；新增脚本会返回失败原因，配置路径变化时应修复具体原因。

修改前文件保存在 `/home/js/.codex/backups/sts-default-20261102T022318Z-mquj84pa`。回退时只撤销此次新增的全局规则、三个事件中指向 `sts-default-guard.cjs` 的注册及该脚本，保留后来新增的其他配置；原插件无需卸载。

实施前的候选设计与协议实验保留于[研究记录](../research/matt-sts-guard-automation.md)。其中阶段接口等属于研究方案，不是本次已安装能力。

## u22s 部署记录（2026-11-02）

已通过既有 SSH 别名 `u22s`（经 laptop 跳板）安装同套方案。远端用户目录为 `/home/u22s`；Codex 0.164.0、Node 24.18.0、RTK 0.43.0 均沿用已有安装，没有升级客户端或修改模型、reasoning、tier 设置。

- 使用远端 Codex 原生命令注册 `lennney/stop-that-shit --ref 0.2.5`，安装 `stop-that-shit@stop-that-shit`；插件发现结果为 installed/enabled。
- 将本机同版本的20个 Matt skills 更新至 `/home/u22s/.agents/skills/`，保留其他已有技能及额外资源；旧目录先备份。核心入口包括 ask-matt、grill-with-docs、to-spec、to-tickets、implement、tdd、code-review 和 handoff，相关研究、领域、架构及诊断技能一起更新。
- 安装 `/home/u22s/.codex/AGENTS.md`、`hooks.json`、`hooks/sts-default-guard.cjs`，包含必要哈希的一次动作许可。现有 RTK 说明文件保留。
- Hook 使用 `/home/u22s/.nvm/versions/node/v24.18.0/bin/node`；拒绝反馈中的内部许可命令也使用实际 Node 绝对路径，适应非交互 SSH 缺少 NVM PATH 的情况。
- 未传输本机认证、用户 config.toml、派工状态、许可记录或 Hook 信任记录。

备份位置：`/home/u22s/.codex/backups/sts-matt-install-20261102T072058Z`，包含修改前全局配置、原 Matt 目录与技能安装记录。远端隔离验证材料位于 `/tmp/sts-matt-verification-99v3r5w_`。

验证结果：安装脚本与受测源码字节一致；路径不再引用 `/home/js`；语法检查、原有12项检查及一次动作许可的正负检查全部通过；原模型设置不变，Codex 原生插件列表能发现 STS 0.2.5。没有启动远端模型对话，也没有声称远端真实宿主或子代理已经完成拦截验收。

启用时在 u22s 新开 Codex，通过 `/hooks` 审核并信任原插件及全局补充 Hook，再按本文“新对话复核”执行实际主/子线程测试。每个宿主的信任需要在当地正常确认，不能复制本机 trusted_hash/trusted_content_hash 来代替。

## Goal Pulse 本机试装（2026-11-02）

按用户同意的先本机试用方案，安装了 HERO 的独立 Goal Pulse 技能与 Python 程序。上游固定为 `92686ca5c7dc9f4852cd323e2852219b7e86a8ea`，目录为 `/home/js/.codex/skills/goal-pulse`；独立 `.venv` 安装唯一声明依赖 `websockets==15.0.1`。本次未在 u22s 安装 Goal Pulse。

全局 AGENTS 只保留一段 `HERO-GOAL-PULSE` 激活规则，指向本机技能，不重复粘贴通用实施或审查要求。技能入口已缩短为计时器的启停与身份约束：仅主线程在用户创建或恢复已有 Goal 时启动/复用一个 watcher；普通聊天和子代理不启动，用户关闭提醒时沿用该选择。不为安装或测试创建 Goal。

实际启动固定使用 `--interval-minutes 30 --poll-seconds 60 --message-file /home/js/.codex/skills/goal-pulse/reminder.txt`。提醒文件为一条中文消息：

> 回到当前 Goal：依据交接摘要，推进下一项已授权的交付或验收；没有实质进展时按项目既有规则纠偏。复用有效结果。本提醒无需回复，也不新增检查或报告。

没有采用上游双语默认消息或“两轮就接管”的额外阈值；分工、故障纠偏、审查例外及验收继续服从项目既有规则。相同 Goal 的重复启动保持原 watcher 与冷却时间，不把 status 轮询、重复登记或确认回复加入正常工作。每次提醒不要求模型单独向用户报告。

验证：技能格式校验通过，固定版本的18项上游隔离测试全部通过，覆盖单 watcher 锁、间隔去重、未知发送结果不重试、暂停/等待静默、Goal 替换及模拟 Unix WebSocket 传输。真实宿主只读 `tick` 成功返回 `{"action":"skip","reason":"no-goal"}`；当前没有 Goal，未创建真实 watcher 或发送提醒。首次真实 Goal 的消息送达仍需在该 Goal 运行时确认，不以隔离测试代替。

修改前全局 AGENTS 与上游技能入口备份在 `/home/js/.codex/backups/goal-pulse-20261102T120857Z-sex2hkl2`。临时验证材料位于 `/tmp/goal-pulse-setup-PtFsx7`。已安装技能可在下一轮发现；需要停止当前 Goal 的提醒时使用该技能的 `stop` 命令，不影响 Goal 本身。
