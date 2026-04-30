# Flow Telemetry 真机/集成测试计划（mmap reader POC）

目标：在真机上模拟“前端 Telemetry consumer”，通过 vNext Unix domain socket 执行 `TELEMETRY.OPEN(level=flow)` 收到 `SCM_RIGHTS` fd，`mmap` 后轮询 fixed-slot ring，并验证至少一条 synthetic record 能被读到。

约束：
- 只走 vNext **Unix domain** 端口（需要 fd passing），不测试 TCP。
- 本阶段只验证 export channel + ABI POC，不接入真实 datapath/conntrack/DNS。

## 1. 前置准备

1. 设备 rooted，SELinux 允许当前测试链路所需操作（遵循 `tests/integration/dx-smoke-platform.sh` 的平台 gate）。
2. 通过现有 deploy 流程启动 daemon（例如 `bash dev/dev-deploy.sh` 或 `ctest -R ^dx-smoke-control$`）。
3. 确认 vNext Unix socket 可连通（`HELLO` 通过）。

## 2. 新增一个真机侧 consumer 工具（建议）

新增一个小型 device-side 可执行文件（例如 `tests/device/telemetry/telemetry_consumer.cpp`，后续由任务实现）：

1. `socket(AF_UNIX, SOCK_STREAM)` 连接到 vNext Unix socket（`/dev/socket/<controlVNextSocketPath>` 或 abstract `@<name>`，与当前 daemon 一致）。
2. 发送 `TELEMETRY.OPEN` 请求：
   - `{"id":1,"cmd":"TELEMETRY.OPEN","args":{"level":"flow"}}`
3. `recvmsg()` 读取响应帧，并从 ancillary data 提取 `SCM_RIGHTS` fd（只取第一个 fd）。
4. `mmap(fd, ringDataBytes)` 映射 ring。
5. 从 `writeTicketSnapshot` 开始读取 slot（`ticket % slotCount`），轮询 slot `state==COMMITTED` 后解析 header：
   - `recordType == FLOW`
   - `payloadSize` 合理
6. 触发 synthetic record：
   - 方案 A（推荐）：新增一个 vNext 测试命令或内部测试 hook（后续任务实现），由 daemon 写入一条固定 payload。
   - 方案 B：在 daemon 侧临时开启一个仅测试用 export（不建议长期保留）。
7. consumer 读到至少 1 条 synthetic record 后退出并返回 0。

## 3. Host 驱动脚本（建议）

新增 `tests/device/telemetry/run.sh`（后续由任务实现）：

1. `adb push` 上述 consumer 工具到设备（如 `/data/local/tmp/sucre-snort-telemetry-consumer`）。
2. `adb shell` 执行 consumer：
   - 失败时打印 daemon logcat 关键片段（只抓必要信息）。
3. 成功条件：consumer 返回 0，且输出至少包含一次 `FLOW` record 的 header 解析结果（ticket/recordType/payloadSize）。

## 4. 通过标准

1. `TELEMETRY.OPEN(level=flow)` 成功返回，并且 consumer 收到 fd。
2. consumer `mmap` 成功并能轮询到 `COMMITTED` slot。
3. 至少 1 条 synthetic record 被读取并解析为 `recordType=FLOW`。
4. 测试过程不得触发设备重启；如出现重启，记录触发命令与环境信息并加入已知问题文档。
