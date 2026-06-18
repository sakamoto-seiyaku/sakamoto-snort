# Device / DX：Snort 本体问题证据索引

更新时间：2026-06-18

目的：
- 只记录在执行 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` / `dx-smoke*` / `dx-diagnostics*` 过程中发现的 **sucre-snort 本体**问题（daemon 行为/契约/热路径/控制面）。
- **不记录**测试脚本/文档本身的问题（脚本 bug 另开 PR/commit 修；或在变更说明里记录）。
- 本文件不是 issue tracker。开放问题、状态与分派以 Plane project `SNORT` 为准；本文只保留复现、环境和证据摘录。

使用规则（每条新问题必须先创建 Plane work item）：
- 在 Plane `SNORT` 创建 work item，并用 `needs-triage` 标记未复现项。
- 关联到具体 Case：用「模块 / Case N」或脚本 check id（例如 `VNT-01`、`VNXDP-05c`）。
- 给出最小复现命令（尽量 `bash tests/integration/...` 或 `ctest -R ...`）。
- 贴关键输出（最多 20 行）+ 指向更完整日志路径（例如 `/data/local/tmp/sucre-snort-dev.log`）。
- 写清楚期望/实际、影响面、临时 workaround（如果有）。

证据模板（Plane item 创建后再追加）：
```md
### SNORT-N：一句话描述（影响：smoke fail / wrong output / crash）
**发现时间**：YYYY-MM-DD
**关联 Case**：<Platform/Domain/IP/... / Case N>；<check id>
**环境**：<设备/ROM>；<root 方案>；<是否 --skip-deploy>；<commit/branch>
**Plane**：SNORT-N

**复现步骤**
1) ...
2) ...

**期望**
- ...

**实际**
- ...

**关键输出（节选）**
```
...
```

**初步定位**
- 可能模块/文件：...
- 可能原因：...

**Workaround**
- ...
```

---

## Evidence migrated to Plane

### Historical evidence：daemon 有时不响应 SIGTERM，deploy 需强制 SIGKILL
**发现时间**：2026-04-24
**关联 Case**：Platform / Case 1（`dx-smoke-platform` → `dev/dev-deploy.sh`）
**环境**：28201JEGR0XPAJ；Magisk root；deploy（非 `--skip-deploy`）；commit `6cdab3c55ccbf5615e1fefcce3bef27563b38ba8`
**Plane**：旧迁移项 `SNORT-2` 已取消；如 current-head 仍复现，先纳入 `SNORT-10` 架构/生命周期讨论再决定是否拆出独立 bug。

**复现步骤**
1) `bash tests/integration/dx-smoke-platform.sh --serial 28201JEGR0XPAJ`
2) 观察 deploy 阶段（`dev/dev-deploy.sh`）停止现有进程的输出

**期望**
- `killall sucre-snort-dev`（SIGTERM）后进程在宽限期内退出，不需要 `killall -9`

**实际**
- 多次出现需要强制终止：
  - deploy 输出包含 `⚠️  进程未能在宽限期内退出，强制终止...`

**关键输出（节选）**
```
[1/6] 停止现有进程...
⚠️  进程未能在宽限期内退出，强制终止...
```

**初步定位**
- 可能模块/文件：daemon shutdown path（待定位）；`dev/dev-deploy.sh` 仅是触发点
- 可能原因：SIGTERM 处理/退出路径被阻塞（例如某线程卡住或等待不可中断资源）

**Workaround**
- 当前 `dev/dev-deploy.sh` 会自动 fallback 到 `killall -9`，可继续开发，但会掩盖“优雅退出”问题
