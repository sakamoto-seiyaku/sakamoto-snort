
## Agent skills

### 子代理配置

实施与审核子代理统一使用 `gpt-5.6-sol`、`high`，禁止 Fast（`service_tier = "default"`）。创建前核实实际配置，不以提示词代替配置。

### 实施与验证效率

适用于已授权实施，主线程与所有子代理均须遵守。
以完成已确认的可操作交付为目标，不降低正确性、安全或验收要求。

- 每票尽早跑通最小真实链，覆盖适用的 UI、宿主、统一提交与独立读取；不得以多轮静态审核或单元通过替代入口验收。
- 代码与断言同审：核实业务前置和真实失败，以同一操作、核心断言验证修复；区分产品、断言、环境问题，保留原失败，不盲重试或弱化断言。
- 同类问题第 3 轮未解决，或复现、修复、回归及复审等待累计 1800 秒，先到即扩大范围。Standards／Spec 并行算一轮；按稳定类别、单调钟累计，换名、换入口、复开均不清零。
- 扩围须覆盖共享模块、全部关联入口、正负场景和真实观测；先统一问题清单，再批量修复，不只增静态审核或逐个补洞。
- 已授权的常规实施、检查和验证连续推进，直至完成、遇到需要用户决策的实质缺口，或按安全约束收束；不得因等待逐步许可、代跑或例行回执而空转。实现代理自行完成授权范围内的检查、构建、真实链和证据整理，不把可执行步骤逐项退回主线程。
- 主线程负责调度、审查汇总与验收。等待在途子代理时，继续推进不与所有权冲突的结果消费、证据核对、阻塞合并、后续调度和验收准备，结果到达后及时续调度；不得为填充等待而重复检查、启动竞争写入者、越过 scheduler-only 边界，或另造审计材料。若无可安全推进的独立事项，可以等待，不以重复工作制造进度。
- 用户暂停时停止新增调度，安全收束在途操作并保留现场；既有生命周期、数据安全与信号安全约束继续有效。
- 按变化范围检查、构建；输入未变的通过证据复用，构件遵守下文缓存规则。注释等无行为修正不重启完整审核；仅实质设计缺口需用户决策。

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
