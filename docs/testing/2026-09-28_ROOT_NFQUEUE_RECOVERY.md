# Root NFQUEUE listener 故障恢复（2026-09-28）

Root NFQUEUE 必需 lane 发生永久监听错误时，Adapter 现在立即撤销完整捕获可用状态、锁存本代 lane/errno，并主动通知 Android 生命周期层。生命周期层先执行原有有限排空和 Root profile 清理，再按 1、5、15 秒最多三次整体重启 Root VPP；第四次故障停机并保留人工介入原因。连续健康 60 秒才重置预算，主动 Stop 取消旧通知和待执行重启。正常运行没有新增周期健康轮询，NFQUEUE 既定 fail-open 和 9000 B contiguous parser envelope 没有改变。

## 故障判断与边界

[此前的 TCP 失效证据](2026-09-28_VPN_ROOT_THROUGHPUT_PROFILE.md)显示两轮 25 秒 Root TCP 后队列 176 从 `/proc` 消失，端点实收远大于 VPP Flow 计数，而管理 health 仍为 `ok`。检查 pinned VPP `src/vlib/file.c` 后确认：read callback 的 `clib_error` 只记录并释放；`EPOLLERR` 若未注册 `error_function`，VPP 会直接关闭 FD。此前 Root listener 只注册了 read callback。这是一条明确的静默失效路径，**但历史两轮缺少触发时的 errno/EPOLLERR 证据，不能据此断言已找出当时队列消失的唯一根因**。

Adapter 现在注册 EPOLLERR 回调，区分 `EAGAIN`、`EINTR`、netlink `ENOBUFS` 等暂时错误与永久错误。永久错误从 epoll 注销 ingress listener，保留原 netlink FD 让已接收包继续做 verdict；同代 ready mask 与 Adapter availability 随即撤销，重复故障只发送一个代际事件。通知走单用途、非阻塞的 Unix datagram 控制通道，不经过可丢失的 observation 队列。仅在发送失败后启用一次性 timer；最多 30 次 100 ms 发送重试，通道持续不可用时 VPP main 线程按既有 Root `stop_step` 作最多 20 次 100 ms 排空步，然后有状态地退出，由现有进程退出监视接管。没有通知 socket 的 Host 路径直接进入同一有界停机兜底；该 Host 分支本轮仅通过编译和代码检查，没有单独真机验收。

Android receiver 使用本代 `Process`、channel、generation 和当前显式请求 epoch 过滤旧事件，并在满载生命周期队列上等待关键事件入队。显式 Start/Stop 也有序地进入原串行执行器；满队列时在后台等待，公平队列避免后到请求长期抢占。重复同代 Start 不提前重置 Root 预算。60 秒健康确认只定一次；若此时进程、会话或 Adapter 失效，则进入既有故障清理，旧代的迟到 timer 不再重复消耗预算。Root 授权缺失、清理失败或不可恢复错误保持停机与人工处理，旧资源未清时不启动新 generation。

## 验证

主机端 `android-runtime-contract-test.sh`（包括严格事件解析、旧 generation 拒绝、满队列关键事件/Stop 保序与并发生产者）、`product_platform_boundary_test.py`、`product_plugin_init_contract.sh`、Android VPP stage 和 APK 构建均通过。历史 `s172-product-lifecycle-contract-test.sh` 的硬编码 `/tmp/sakamoto-172-vpp-official...` 源码目录不存在，脚本在首个文件检查即退出；本轮没有把它当作修复回归结果。

最终已安装 APK：[产物](../../build-output/root-recovery-20260928/apk/sakamoto-runtime-debug.apk)，SHA-256 `653b7ea3ec1b53f0aa5b2a7206bebda99740ecbec478382220fecda0d89447ca`；[安装后读回](../../build-output/root-recovery-20260928/final-device.json)与本地文件一致。设备是原有 Pixel 6a，产品 App UID 12632 的 KernelSU grant 在每次安装后核对。以下故障均用真实 Root VPP 运行和诊断 CLI 注入，UI 返回 HOME 后仍由 RuntimeService 自主处理：

| 验证 | 结果 |
| --- | --- |
| 暂时错误 | `listener-fault 0 105`（`ENOBUFS`）返回 `fatal=0, ready_mask=15`；同代仍运行，四队列仍在。此项在早期同 C 分类实现的 APK 上完成。 |
| 永久错误与三次预算 | lane 0 `EBADF` 故障后旧代 `native_root_drain=true`、residue clean，下一代恢复。上一 APK（SHA `af210784c88176118b9083b3b628f7e3f6f1422ddc9fc68eab5183002b1d4bce`，同 Java 恢复逻辑、同生产 C listener 路径，缺最终一次性诊断开关）连续故障分别记录 `attempt=1 delay_ms=1000`、`attempt=2 delay_ms=5000`、`attempt=3 delay_ms=15000`；第四次后状态 `runtime_recovery_intervention_required`、`protectionRunning=false`、`mayBeActive=false`，错误文本保留 lane 0 / epoll / errno 9。 |
| 60 秒重置 | 上述 APK 的恢复代 1799 运行后 60.036 秒记录 `root_recovery=healthy_reset`；随后的故障重新从 `attempt=1` 开始。 |
| 旧包排空 | [一次性在途故障日志](../../build-output/root-recovery-20260928/final-inflight-root-last-failure.log)记录真实 TCP packet 1 `submit_external` 后 `pending=1` 才触发 listener fault；同 packet 1 随后完成 `NF_ACCEPT` syscall（`result=32 errno=0`），退役时 verdict/return 各 1，最终 pending、buffer、obligation、handoff、completion frame 均为 0。新代恢复后门闸放行的 3 秒 TCP 发送与接收同为 97,730,560 B。 |
| Stop 取消 | 最终包在代 1808 的第二次故障明确发布 `attempt=2`、5 秒待重启时收到 Stop；代 1808 变为 stopped，超过原 timer 截止时间仍无代 1809。 |

最终包之前、同一生产 C listener 逻辑的 [8 秒 Root TCP 诊断](../../build-output/root-recovery-20260928/tcp8-after-cli.txt)中，UID 12632 两端均交付 177,143,808 B，四个 listener/FD 始终 ready，原图和完成债务归零。但同 tuple VPP Flow `orig_bytes=118,503,156`，Adapter 记录 34,114 次未入图包的 NF_ACCEPT（其中 6,751 次 reserve 路径）；因此 176.43 Mbps 只描述端点交付，**不是完整策略路径吞吐成绩**。既有 envelope、NFQUEUE 拥塞和内核 bypass 需要分开核账，本次没有扩展 GSO/链式 buffer 或变更规则。

尝试从 `run-as` 诊断 helper 向当前私有 socket 发送旧 generation datagram 时，SELinux 返回 `Permission denied`；未改变产品权限或增加调试接口。主机事件解析测试验证旧 generation 不匹配会被拒绝，服务 handler 还检查绑定的 `Process` 和当前 epoch。此项没有独立真机注入成功证据。

收尾后状态为 stopped、无产品 VPP/`:runtime`/UI 进程，产品 residue audit 为 `productRootNfqueueResidueClean=true`，临时设备 helper 已删；规则文件 SHA-256 仍是 `f9e8c4ffef5a6a20b81e4092cc83a7c56b8359605b1a78f35b94fbc284438f0b`，observation SQLite 文件保留。由于当前 adb shell 的 KernelSU 上下文没有 netfilter 读取能力，最终 `/proc/net/netfilter/nfnetlink_queue` 和 iptables 没有独立直接读回；这里以产品清理审计与进程读回为证据，不扩大主张。入口 48 个已有 dirty 路径的 SHA-256 均未变，未做 Git 提交或 Plane 操作。
