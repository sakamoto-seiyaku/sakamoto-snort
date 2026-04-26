## Context

当前 daemon 的 packet/DNS 判决热路径已经通过 reset epoch、控制面 mutation 边界和 vNext stream 异步队列降低了数据面阻塞风险，但 lifecycle 层仍存在三个同源缺口：

- `SIGINT` / `SIGTERM` 只设置 flag，main loop 在 60 分钟周期 sleep 后才可能观察到退出。
- vNext stream reset 将 subscriber fd 作为 raw int 交给 reset caller shutdown，fd 生命周期不归 stream manager 所有。
- legacy/vNext control 与 DNS listener 仍按 client 创建 detached thread，缺少 active session budget；慢读 client 仍可能长期占用 worker。

出版级交付需要把这些行为收敛成明确 ownership：main owns process exit，session owns fd，runtime owns resource budget。

## Goals / Non-Goals

**Goals:**
- 终止信号和 legacy `DEV.SHUTDOWN` 都通过统一 shutdown coordinator 请求退出。
- final save 与进程退出只在 main runtime owner 上执行。
- vNext stream reset 不跨线程操作 bare fd。
- control/DNS client worker 数量和阻塞发送时间有明确上限。
- 保持现有 wire protocol、命令响应格式和 packet/DNS verdict 语义。

**Non-Goals:**
- 不把本轮重写成完整 event-loop server。
- 不要求 join 当前所有 listener/client detached 线程。
- 不改变 Android init service 声明、socket 名称或 vNext/legacy command shape。

## Decisions

1. **Main-owned shutdown coordinator**
   - 选择：启动早期通过 `pthread_sigmask()` block `SIGINT` / `SIGTERM`，专用 signal waiter 使用 `sigwait()`，并通过 mutex + condition variable 唤醒 main loop。
   - 理由：这避免信号投递到任意 detached worker 后无法唤醒 main；handler 内无需执行非 async-signal-safe 操作。
   - 替代方案：缩短 `saveInterval` 或继续用 signal handler + flag。拒绝原因：仍是轮询，最坏延迟不具备发布级上界。

2. **Exit only from main**
   - 选择：`snortSave(true)` 不再从任意线程 `std::exit`；shutdown request 让 main 执行 final save 后返回 `main()`。
   - 理由：进程退出、final save 和 runtime cleanup 的 ownership 必须集中，避免 worker thread 在持有局部资源或锁时终止进程。
   - 替代方案：保留 `std::exit` 但加锁。拒绝原因：解决不了 owner 混乱。

3. **Session-owned stream fd**
   - 选择：stream manager 只保存 subscriber identity，不保存或返回 fd；reset 发布取消状态，session loop 观察取消后关闭自己的 fd。
   - 理由：fd reuse 是 OS 级生命周期问题，非 owner thread 不能安全 shutdown bare fd。
   - 替代方案：在 reset 时 `dup()` fd 后 shutdown 副本。拒绝原因：可降低误伤概率，但仍让 stream manager 参与 fd 控制，不如 session owner 简洁。

4. **Bounded thread-per-client**
   - 选择：保留现有 detached thread-per-client，但用 RAII token 限制 active control session 与 DNS client 数量，并给发送路径增加总 deadline。
   - 理由：比重写 event loop 更小、更可回归，同时从根上消除无限 thread/fd 占用。
   - 替代方案：本轮改成统一 epoll/event-loop。拒绝原因：影响面大，容易引入新的协议行为漂移。

## Risks / Trade-offs

- [Risk] 慢 client 在发送 deadline 到期后被断开，可能影响异常慢的调试客户端 → Mitigation：deadline 只限制阻塞发送，不改变正常响应格式；日志记录断开原因。
- [Risk] Active session budget 可能拒绝突发连接 → Mitigation：accept 后立即 close，保持 daemon 可用；listen backlog 仍保留现有配置。
- [Risk] detached threads 仍不能被统一 join → Mitigation：本轮通过 budget/deadline 将其资源占用上界化；完整 supervised thread model 留给后续大重构。
