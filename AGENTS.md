## 执行方式与子代理

本节规定执行分工和技能衔接，不扩大项目、设备、数据或外部系统的操作授权。

- 默认由主线程端到端完成任务，对整体正确性、验证和交付负责。
- 仅当用户明确要求，或用户设定／确认且当前有效的 goal 明确要求使用子代理时，才在相应任务与角色范围内委派。开启 goal、任务复杂、工具可用、技能或模板中的分工描述，不单独构成授权；不得自行改写 goal 制造或扩大授权。此条件也适用于研究、审查代理及继续调用已有代理。
- 已授权的连续步骤不重复请示。技能中的分工要求服从上述启用条件，技术验证和验收要求不因此取消；主线程自检不得标为独立审查。仅授权审查时，不顺带委派实施。
- 启用实施子代理时，同一交付任务只有一名端到端实施者，负责代码、必要测试、调试、构建、实际运行验证及交付。不得按 implementation／runtime／诊断／验收等阶段拆出多个执行者，即使串行也不允许；同一任务优先复用原实施者。
- 主线程负责整体调度、及时纠偏、审查汇总与最终验收，以子代理的简要回报和交接摘要为主要输入，不要求全面读取所有返回内容。仅在具体阻塞、结论矛盾、覆盖缺口或数据安全问题需要核实时，定向读取相关 handoff 段落、报告、源码或验证证据；不另起并行实施或重复接管共享运行链。必要更换实施者时，先安全收束并清晰交接。
- 用户暂停或撤回相关授权时，停止新增调度，安全收束在途操作并保留现场。授权结束后不向新任务自动延伸，也不因存在旧代理或 handoff 而恢复旧队列。

## 已授权实施子代理的技能链

以下流程仅在实施子代理已获授权时启用。实施子代理使用 `$implement` 和 `$handoff`；双轴审查子代理只执行对应的只读审查，不再调用 `$implement` 或递归启动实施流程。

1. 主线程分派任务前查看上一任务的交接摘要（如有），明确任务范围、规格来源、验收条件、共享资源与操作边界，并把 handoff 路径交给实施者；需要核实具体问题时再定向读取，不要求通读完整 handoff。审查基线优先使用用户指定的固定点；未指定时，在任务开始固定并记录当时的 HEAD，供本任务复审使用，不在复审时重新选择基线。
2. 实施者先读取相关 handoff，再使用 [$implement](/home/js/.agents/skills/implement/SKILL.md) 贯通实施全链。测试及其他实施细则引用技能与项目要求，不另造重复流程。
3. 本仓库对 `$implement` 的提交／复审顺序明确为：形成仅含本任务变更的候选提交，再调用 [$code-review](/home/js/.agents/skills/code-review/SKILL.md)，随后由原实施者修复、形成必要修复提交并复核。遵守用户当前的提交限制，保留无关改动，不擅自 push／打 tag；不得为凑复审而违反提交限制，也不得把未覆盖工作区改动的空 diff 当作审查通过。
4. `$code-review` 使用固定基线与实际候选 HEAD，先确认引用有效、差异非空且包含本任务应审改动，再并行启动全新上下文的 Standards／Spec 两个只读审查子代理。这是已授权实施流程的一部分，无须逐次申请；审查者只例外于“实施者唯一”的数量限制，不构成其他任务自动启用子代理的入口。完整报告分别保留并引用，不混合两轴结论，不以零问题摘要代替覆盖证据；缺失的审查或不足的覆盖如实标明，不记为通过。
5. 原实施者处理本任务及数据安全的阻塞发现，按实际变化完成必要验证和复核，保证交付源码已被审查覆盖。完成任务后使用 [$handoff](/home/js/.agents/skills/handoff/SKILL.md)：写入操作系统临时目录，不写当前工作区；引用已有规格、提交、双轴报告、构件与验证记录，包含 suggested skills，脱敏且不重复堆积已有内容。未闭合项、失败累计和继续工作所需状态也须通过现有记录传递。向主线程返回简要交接摘要，包含交付版本、两轴审查各自结论、验收覆盖、未闭合项和 handoff／证据路径，不复制完整材料。
6. 主线程依据交接摘要中的受审源码／交付版本对应关系、两轴审查结论、验收覆盖与未闭合项作出结论；信息缺失、矛盾或出现具体风险时，要求原实施者补充说明，或定向读取相关材料，不要求通读完整 handoff、审查报告或全部验证输出。缺失的审查或验收仍须如实标明，不以摘要省略视为通过。若下一任务已在授权范围内，连续启动下一任务，要求下一实施者先读上一份 handoff 再使用 `$implement`；不逐票重复请示，也不把 handoff 的建议当成新增任务授权。

## 实施效率与主线程纠偏

以下要求适用于主线程及所有子代理，服务生命周期、数据安全和构建缓存等既有约束继续有效。

- 开始前快速核对交付终点、不变量、相关入口和完整因果链，包括适用的读取、排队、提交、通知与恢复。按任务需要读取资料，复用已有验证入口，尽早贯通首个可验证的最小交付链，不先堆静态检查。
- 每个失败先区分产品、断言／验收脚本和环境问题，核实业务前置。保留原失败及已成功部分，修复后验证同一操作和核心断言；不重放已提交成功的操作，不通过弱化断言制造通过，验收脚本故障不得自动扩大产品范围。
- 新发现先映射到当前验收条件。已证实阻断当前验收或数据安全的问题必须修复；维护建议、假设性边界及未来能力另记，不追加为完成门槛，不删除或降低原验收条件。
- 主线程在进展回报及关键节点核对工作是否仍服务于原目标、验收条件与完整因果链；关键节点包括首个可验证的交付进展、关键失败或阻塞、方案／范围变化、新一轮大构建／回归及最终交付。不等到 handoff 后才检查方向，也不以转发消息代替监控。
- 发现范围漂移、故障归因错误、无新证据的反复局部修补、额外增加完成门槛、证据不足以支持结论或共享资源冲突时，及时介入；数据安全或越权风险立即制止，不等待失败阈值。纠偏须指出具体偏离、判断依据和需要恢复的目标或调整的路径，不能只泛泛要求“加快”或“注意大局”。
- 纠偏仍由原实施者落实。主线程不逐步解锁，不频繁终止或更换代理；在后续回报中核对纠偏是否实际生效。未落实或继续原循环时进一步干预，不以“已经提醒”代替处理。
- 同类问题第3轮仍未解决，或该问题累计耗时达到1800秒，必须停止局部“修补→构建→补验”循环。下一步只允许统一诊断：核对共享模块、关联入口、正负场景和真实运行状态，收齐问题后形成共同修复方案。统一诊断完成前不再逐点补丁或重跑大矩阵；因果与方案齐备后，唯一实施者在既有授权内自主续行。该阈值不是此前无需纠偏的理由，也不自动暂停 goal、换人或扩大范围。
- 同类问题的失败次数和耗时跨入口、脚本、代理更换与上下文交接累计，改名或复开不得重置；并行 Standards／Spec 计为一轮。在现有执行记录中维护，不另建计数或调度体系。
- 每轮新构建、大回归或全量复审前，明确要解决哪项现有阻塞，以及旧证据为何不足；无法说明则不执行。按实际变化验证，未变输入的有效证据直接复用，纯文档或注释修改不重启完整构建、回归或全量复审。
- 只维护现有任务记录中的简短阻塞清单与必要证据。不为证明遵守本节而另造审计脚本、大量文档或持续增加“再证明一次”的任务。

## Agent skills

### 子代理配置（启用后适用）

实施与审核子代理默认使用 `gpt-6.1-sol`、`high`，禁止 Fast（`service_tier = "default"`）。遇到误判导致对话无法继续时，仅该轮可以改用 `gpt-5.6-sol`，其余配置与任务约束不变；后续轮次恢复默认模型。创建前核实实际配置，不以提示词代替配置。

### 本仓库实施补充

- 以完成已确认的可操作交付为目标，不降低正确性、安全或验收要求。每票尽早贯通适用的 UI、宿主、统一提交与独立读取；不以多轮静态审核或单元通过替代真实入口验收。
- 同类问题按稳定类别、单调钟累计；耗时包含复现、修复、回归及复审等待。统一诊断须覆盖全部关联入口、正负场景和真实观测，先收齐问题清单，再共同修复。
- 启用实施子代理时，主线程等待结果期间可继续消费已有结果、核对证据、合并阻塞、准备后续调度和验收，结果到达后及时续行。不为填充等待而重复检查、启动竞争写入者、接管实施或另造审计材料；没有可安全推进的独立事项时可以等待。
- 实施者自行完成授权范围内的检查、构建、真实链和证据整理，不把可执行步骤逐项退回主线程代跑，不因等待例行回执而空转；仅实质设计缺口需用户决策。
- 既有生命周期、数据安全与信号安全约束继续有效。

### 编译与空间

- 复用 Product 共享缓存和稳定 Host 构建树；禁止逐任务／轮次重建依赖树、复制 SDK/NDK 或例行清缓存。
- 只构建受影响目标。零编译复跑仅用于构建机制、缓存身份变化或复用异常；已有有效证明直接复用。
- 每任务一个输出根；发布复用只读副本，同缓存写入串行，不链接可变编译输出。
- 原始采集仅供当前验收／诊断；任务结束默认只留精简结果与可回溯源码，清理本任务临时二进制、抓包、数据库及重复备份。
- 保护缓存及其依赖、当前交付和一份有效恢复基线；未闭合问题、明确复核或用户要求所需原件保留。
- 用 `tools/product/clean-build-output.py` 预览后清理，保护项显式 `--keep`；只量相关目录，权限阻塞及时报告，不反复扫描。见[细则](docs/agents/build-cache.md)。

### Issue tracker

Issues and PRDs are tracked in Plane through the global `plane-ops` skill, using its default project. Do not use Plane MCP. See `docs/agents/issue-tracker.md`.

### Triage labels

Use the default five-role triage vocabulary in Plane. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context repo; read root/domain docs plus `docs/decisions/` before architectural work. OpenSpec is historical archive only. See `docs/agents/domain.md`.

### Android device operations

Use repo-local `./dev/adb` for all Android device and app operations. Do not call Windows `adb.exe` directly or depend on the sibling `sakamoto-app` checkout. Existing device helpers select this wrapper automatically. See `dev/README.md`.
For KernelSU root acceptance, remember that uninstall/reinstall can reset the
app's Superuser grant. Confirm or restore the grant in KernelSU Manager before
treating `root_authorization_required` as a product failure; use `./dev/adb`
screenshots and UIAutomator XML for the CLI-guided flow.

### Product implementation boundary

The Snort C++ daemon, host model, tests, NDK artifact, and archived source were removed by ADR-0008. Do not recreate, port, use as a reference, or add a C++ compatibility fallback for them. The only product packet-domain target is the VPP-native C mainline defined by ADR-0006 and ADR-0007. C/VPP POCs are evidence inputs, not source to import directly.
