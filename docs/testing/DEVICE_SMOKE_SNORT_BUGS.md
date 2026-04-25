# Device / DX：真机冒烟过程中发现的 Snort 本体问题记录

更新时间：2026-04-25

目的：
- 只记录在执行 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` / `dx-smoke*` / `dx-diagnostics*` 过程中发现的 **sucre-snort 本体**问题（daemon 行为/契约/热路径/控制面）。
- **不记录**测试脚本/文档本身的问题（脚本 bug 另开 PR/commit 修；或在变更说明里记录）。

使用规则（每条问题必须“可复现 + 可定位”）：
- 关联到具体 Case：用「模块 / Case N」或脚本 check id（例如 `VNT-01`、`VNXDP-05c`）。
- 给出最小复现命令（尽量 `bash tests/integration/...` 或 `ctest -R ...`）。
- 贴关键输出（最多 20 行）+ 指向更完整日志路径（例如 `/data/local/tmp/sucre-snort-dev.log`）。
- 写清楚期望/实际、影响面、临时 workaround（如果有）。

模板（复制一份填）：
```md
### BUG-XXX：一句话描述（影响：smoke fail / wrong output / crash）
**发现时间**：YYYY-MM-DD
**关联 Case**：<Platform/Domain/IP/... / Case N>；<check id>
**环境**：<设备/ROM>；<root 方案>；<是否 --skip-deploy>；<commit/branch>

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

**状态**
- [ ] open
- [ ] fixed（指向修复 commit/PR）
```

---

## Open

### BUG-001：daemon 有时不响应 SIGTERM，deploy 需强制 SIGKILL
**发现时间**：2026-04-24
**关联 Case**：Platform / Case 1（`dx-smoke-platform` → `dev/dev-deploy.sh`）
**环境**：28201JEGR0XPAJ；Magisk root；deploy（非 `--skip-deploy`）；commit `6cdab3c55ccbf5615e1fefcce3bef27563b38ba8`

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

**状态**
- [ ] open

## Fixed

（暂无）
