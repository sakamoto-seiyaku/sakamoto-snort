
## Agent skills

### 子代理配置

实施与审核子代理统一使用 `gpt-6.1-sol`、`high`，禁止 Fast（`service_tier = "default"`）。创建前核实实际配置，不以提示词代替配置。

### 实施与验证效率

适用于已授权实施，主线程与所有子代理均须遵守。

- 每票尽早跑通最小真实链，覆盖适用的 UI、宿主、统一提交与独立读取；不得以多轮静态审核或单元通过替代入口验收。
- 代码与断言同审：核实业务前置和真实失败，以同一操作、核心断言验证修复；区分产品、断言、环境问题，保留原失败，不盲重试或弱化断言。
- 同类问题第 3 轮未解决，或复现、修复、回归及复审等待累计 1800 秒，先到即扩大范围。Standards／Spec 并行算一轮；按稳定类别、单调钟累计，换名、换入口、复开均不清零。
- 扩围须覆盖共享模块、全部关联入口、正负场景和真实观测；先统一问题清单，再批量修复，不只增静态审核或逐个补洞。
- 主线程负责调度、审查汇总与验收；实现代理连续完成已授权检查和构建，不逐步等许可或代跑；遵守既有生命周期与信号安全约束。
- 按变化范围检查、构建；输入未变的通过证据复用，构件遵守下文缓存规则。注释等无行为修正不重启完整审核；仅实质设计缺口需用户决策。

### Build cache and disk usage

Compilation caches must be reused across repeated builds and experiment output
directories. Use the Product builders' persistent cache; do not create fresh
CMake/Cargo dependency builds under each `/tmp` or evidence directory. Verify an
unchanged second build has no compilation before repeating expensive work.
Preserve raw evidence and exact artifact identities during cleanup. See
`docs/agents/build-cache.md` for cache isolation, verification and retention rules.

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
