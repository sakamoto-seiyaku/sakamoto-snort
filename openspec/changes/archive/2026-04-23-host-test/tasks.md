## 1. Host 工作流边界

- [x] 1.1 确认本 change 只修改 host-only 测试入口、host-only preset、`tests/host/` 与相关文档
- [x] 1.2 确认不修改真机测试注册/运行路径，包括 `tests/integration/` 与 `tests/device-modules/`
- [x] 1.3 将 host 测试文档中的主要口径统一为 `Host` 与 `Device / DX`，避免继续把历史 `p0/p1/p2` 当路线图阶段名

## 2. Host 普通入口与 ASAN 入口

- [x] 2.1 保持普通 host `gtest/CTest` 单测作为独立可运行入口
- [x] 2.2 保持同一套 host `gtest/CTest` 单测的 ASAN 独立可运行入口
- [x] 2.3 增加一个 host-only 聚合 gate，使其按清晰顺序运行普通 host 单测与 ASAN 单测
- [x] 2.4 验证普通 host 入口、ASAN 入口、聚合 gate 的输出能明确区分失败来源

## 3. Clang 覆盖率产物链路

- [x] 3.1 新增 Clang/LLVM coverage 专用 host-only 配置，避免与 ASAN 配置混用
- [x] 3.2 让 coverage 配置使用 LLVM source-based coverage instrumentation 构建 host tests
- [x] 3.3 运行 coverage host test suite 后生成并合并 profile 数据
- [x] 3.4 使用 `llvm-cov` 生成可读覆盖率报告与机器可消费的覆盖率产物
- [x] 3.5 确认 coverage 产物写入 build/output 目录，不写入 source-controlled 路径
- [x] 3.6 记录 coverage workflow 的命令、产物位置与“暂不作为数值阈值 gate”的边界

## 4. Host 单测覆盖补齐

- [x] 4.1 为 `DnsRequest` 补充 host 单测
- [x] 4.2 为 `Saver` 补充 host 单测
- [x] 4.3 为 `Timer` 补充 host 单测
- [x] 4.4 为 `SocketIO` 补充 host 单测
- [x] 4.5 为 `AppManager` 补充可观察行为测试
- [x] 4.6 为 `HostManager` 补充可观察行为测试
- [x] 4.7 为 `Packet` 补充 host 单测
- [x] 4.8 为 `PacketManager` 补充可观察行为测试
- [x] 4.9 为 `Streamable` 补充 host 单测
- [x] 4.10 对 `Activity`、`ActivityManager`、`CmdLine` 先明确可测语义与 seam，再决定最小 host 测试覆盖
- [x] 4.11 如需 test seam，确保 seam 是模块局部的，且不改变产品可见行为

## 5. 文档与验证

- [x] 5.1 更新 `docs/testing/` 中 host 单测、ASAN 与 coverage workflow 的说明
- [x] 5.2 更新 host 测试覆盖调查文档，标记新增测试覆盖到的模块与仍保留的缺口
- [x] 5.3 运行普通 host 单测并确认通过
- [x] 5.4 运行 ASAN host 单测并确认通过
- [x] 5.5 运行 coverage workflow 并确认产物生成
- [x] 5.6 最终检查本 change 没有修改真机测试相关 CMake 与脚本
