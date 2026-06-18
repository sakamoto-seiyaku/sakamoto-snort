## Context

DX `smoke` 的主入口组已经收敛为 `dx-smoke-platform/control/datapath`，且 `dx-smoke` 采用 `platform -> control -> datapath` 的 fail-fast 顺序（见 `openspec/specs/dx-smoke-workflow/spec.md`）。

当前 `dx-smoke-platform` 已覆盖较多 device-side 平台前置（socket/iptables/SELinux 等），但仍存在两类常见“看起来像坏了、其实是前置没满足”的问题：

- **host 工具链**缺失（`python3` / `sucre-snort-ctl`）：往往在后续 `dx-smoke-control` 才暴露，导致定位慢。
- **vNext 控制面连通性**未在 platform 阶段明确校验，尤其在 `--skip-deploy` 场景下容易出现“socket 存在但不可用/daemon 不在”的误判。

本 change 的设计目标是把 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` 中 Platform 模块的调查结论，落到 `dx-smoke-platform` 的可重复 gate 语义上：**能测就继续；不能测就明确 BLOCKED 并给出可执行修复提示**。

## Goals / Non-Goals

**Goals:**
- `dx-smoke-platform` 作为 `dx-smoke` 的第一段，能在 1 次运行里把“host+device 前置是否满足”讲清楚。
- `--skip-deploy` 下当 daemon/控制面不可用时，报告 `BLOCKED(77)`（而不是误导性的 FAIL），并提示下一步操作。
- 不引入易抖动断言：不做“发包→看 NFQUEUE 计数器增长”之类依赖网络/计数器的强约束。

**Non-Goals:**
- 不新增 `dx-smoke*` / `dx-diagnostics*` 入口名；不改变 `dx-smoke` 的执行顺序与入口集合。
- 不改动 `src/` 产品逻辑；不为测试引入新的产品行为。
- 不把 “真实系统 resolver hook（netd resolv）” 变成默认 gate；该项只作为平台/环境排障提示。

## Decisions

1) **host 工具就绪检查放在 `dx-smoke-platform`**
   - 选择：在 `dx-smoke-platform` 内强校验 `python3` 与 `sucre-snort-ctl`；缺失直接 `BLOCKED(77)`。
   - 理由：更早暴露“本机没准备好”，避免后续段失败时误以为是设备/daemon 问题。
   - 备选：留在 `dx-smoke-control`；拒绝（暴露太晚，且 platform 阶段“看起来通过”会误导）。

2) **`dx-smoke-platform` 增加最小 vNext `HELLO` 连通性 sanity**
   - 选择：platform 阶段通过 adb forward + `sucre-snort-ctl HELLO` 做一次握手断言。
   - 理由：补齐“socket 文件存在但不可用”的缺口，特别是 `--skip-deploy` 下需要明确区分“可用 vs 前置不足”。
   - 备选：只在 `dx-smoke-control` 校验；拒绝（platform 阶段仍可能放行无意义的后续运行）。

3) **vNext 连通性检查使用 `sucre-snort-ctl`（而不是重复实现 netstring 客户端）**
   - 选择：以 `sucre-snort-ctl --tcp 127.0.0.1:<port> --compact HELLO` 为标准路径，再用 `python3` 做 JSON 字段断言。
   - 理由：统一 vNext 控制面访问方式，避免脚本内再复制一份协议客户端实现；同时倒逼 host 工具链就绪。
   - 备选：脚本内用 `python3` 直接实现 netstring RPC；拒绝（重复实现、维护成本高、与工具链收敛方向相悖）。

4) **`--skip-deploy` 下“不可用”统一视为 BLOCKED**
   - 选择：当 `--skip-deploy` 且 daemon 不存在或 vNext `HELLO` 不通时，输出 `BLOCKED:` 并 exit 77。
   - 理由：这是前置条件不满足，不是功能断言失败；应避免污染 FAIL 信号。
   - 备选：直接 FAIL；拒绝（会把环境问题误报为产品问题）。

5) **`netd resolv hook` 仍保持 SKIP/提示**
   - 选择：hook 检查更可靠（优先 `nsenter -t 1 -m -- mount`），但缺失仍输出 `SKIP` 并提示 `bash dev/dev-netd-resolv.sh status|prepare`。
   - 理由：真实 resolver hook 属于“平台环境闭环”，不应阻塞默认 smoke 主链（除非未来明确把 DNS 真实解析端到端纳入 gate）。
   - 备选：缺失即 BLOCKED；拒绝（会把外部环境问题升级为默认 gate，造成大量无意义 BLOCKED）。

6) **不加入 NFQUEUE counters 增长断言**
   - 选择：仅校验 hooks/链/规则存在，不强制发包观测计数器增长。
   - 理由：计数器断言容易受网络、并发与历史状态影响，且对“能不能继续跑 control/datapath”不是必需前置。

## Risks / Trade-offs

- [Platform 变得更“严格”，更容易 BLOCKED] → Mitigation：所有 BLOCKED 都必须给出可执行修复提示（构建命令/去掉 `--skip-deploy`/先 deploy）。
- [HELLO 可能受启动时序影响而偶发失败] → Mitigation：在 deploy 后增加短重试窗口（例如 5 次 * 0.5s），并在失败时打印最近一次输出摘要。
- [adb forward 端口可能与开发者本机已有 forward 冲突] → Mitigation：复用 `check_control_vnext_forward`；必要时允许通过环境变量/参数覆盖端口（若选择引入则需在 specs 中明确）。
