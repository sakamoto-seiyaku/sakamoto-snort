# Design: Real-device native debug lane for sucre-snort

## 0. Scope
本 change 只关注 `P3` 的真机原生调试与 crash 复盘入口：
- LLDB attach / run
- VS Code + CodeLLDB 调试准备
- tombstone 拉取与 `stack` 符号化

## 1. Constraints
- 当前目标环境统一为 Android 真机。
- 不要求修改 `sucre-snort` 主程序架构。
- 不把 P3 的调试脚本和 P1 集成测试脚本混在同一入口。
- 当前 change 只解决 debug / crash / symbolization 工作流，不授权实现产品功能。
- 若确需 debug seam，只允许最小、可解释、可审计的范围，且不得顺势扩展为功能重构。

## 2. Implementation decisions
- 复用 AOSP `development/scripts/lldbclient.py` 作为主入口。
- 复用 AOSP `development/scripts/stack` 进行 tombstone 符号化。
- 仓库脚本只负责：目标选择、PID 解析、参数拼装、运行前检查与常用命令落地。
- 对 VS Code 的支持通过 `lldbclient.py --setup-forwarding vscode-lldb --vscode-launch-file ...` 收敛。

## 3. Boundary with P1
- `P1` 负责真机集成测试和功能正确性回归。
- `P3` 负责 live debug / crash dump / 平台专项排障。
- 两者都运行在真机上，但入口、目的和验收标准不同。
