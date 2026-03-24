# Change: IP real-device test module (full regression + perf)

## Why

现有测试入口主要用于开发期的回归与冒烟（unit / 小型真机集成 / baseline smoke）。但对 **IP/L3-L4 firewall** 这一条主线来说，我们还缺一套“真机上可重复执行、覆盖非常全面、并且包含性能评估”的测试模组。

关键原因：
- IP 逻辑改动频率高、热路径敏感、组合维度多（proto/dir/iface/ifindex/CIDR/ports/priority/enable/enforce/would）。
- host-side 单元测试只能覆盖引擎与解析，无法替代 NFQUEUE 真机闭环。
- 我们需要一个长期复用的 **IP 真机测试模组**：以后任何“大修改”（功能/性能/并发）都必须完整重跑这一整套模组来评估 bug/稳定性/性能趋势。

因此需要把“IP 真机矩阵/压力/性能评估”从单个 change 的局部验收中抽离出来，作为项目级 **real-device test module** 独立维护与演进（不把它混同为 unit/integration 的开发期入口）。

## What Changes

- 新增一个项目级 **IP 真机测试模组**（host-driven、真机执行）：
  - 明确的组件边界与原则（见纲领 `docs/testing/TEST_COMPONENTS_MANIFESTO.md`）
  - 统一 runner（可按 profile/group/case 运行子集，输出可机器解析的 summary）
  - 覆盖 ip-smoke / ip-matrix / ip-stress / ip-perf 四类入口（快/全/并发/性能；可选 longrun）
  - 使用统一断言数据源：`PKTSTREAM` / `METRICS.REASONS` / `IPRULES.PRINT(stats)` / `METRICS.PERF`
  - 提供“可复现流量”方案（优先 netns+veth，其次局域网固定 server，最后公网 fallback 仅记录）
- 将现有与 IP 相关的零散验收脚本逐步纳入该模组（必要时重命名/拆分/去重）。是否提供额外的 CTest/CI hook 作为可选项（仅限轻量 smoke）。

## Non-Goals

- 不在本 change 内引入新的产品功能逻辑（只做 test/debug/tooling）。
- 不尝试用 host 侧模拟替代真机网络环境；入站/UDP 回包等不确定性场景以 best-effort + SKIP 为主。
- 不把阈值型性能 gate 过早固化为硬失败（先记录与对比，必要时再逐步引入阈值）。

## Impact

- 影响目录：
  - `tests/device-modules/ip/`（新增/重构 IP 模组脚本；长期入口）
  - `docs/`（IP 模组 runbook/结果记录；纲领文件）
- 受益：
  - IP 主线未来改动的回归闭环更清晰、成本更可控、覆盖可持续累积。
