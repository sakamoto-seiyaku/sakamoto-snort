# S119 HEV/lwIP 单 worker 设计备忘

状态：2026-08-20，实验结论已形成；没有把临时 seam 当成生产实现。

## 要回答的问题

在未来的 VPP plugin 里，能否让一个 VPP worker 同时承载 HEV task system，以及该
worker 上多个独立 owner/lwIP context？

## 已确认

- 单个 OS worker 可以承载一个 HEV task system；两个 owner 的 task、session、netif
  output 和各自 lwIP context 可以保持在同一 worker thread。
- Host 与 Pixel 6a Android 16/aarch64 的真实受保护 TCP、UDP owner smoke 均通过；两个
  owner/lwIP 地址不同，TCP/UDP 的 credit、pbuf、socket、release 清理通过。
- 现有 `hev_task_system_run()` 不能直接放进 VPP worker node。它会接管 worker 控制流，
  直到 task 全部停止；takeover runner 在 Host/Android 都复现了约 125/127ms 的阻塞。
- 临时 bounded `hev_task_system_step()` 原型可以让 worker 每次 node turn 推进一个 HEV
  quantum，并在 Host/Android 的实际 TCP/UDP owner smoke 中通过；本轮每个 smoke 观察到
  8 个 step quantum。
- 真实 VPP plugin seam 已通过：VPP thread 1 的 worker node 中，HEV event/io/timer task
  和两个独立 lwIP owner context 全部记录到同一个 pthread；27 个 bounded step 后 task/fd
  residue 均为 0。

## 设计含义

当前阻塞点是 scheduler seam，不是 lwIP 多 worker 或 zero-copy。若坚持“HEV task 与
VPP worker 同线程”，需要一个正式的 external-driver API，至少明确：

1. 一次调用最多推进多少 quantum，绝不在 reactor 上无限阻塞；
2. task yield、timer、fd wakeup 后如何返回 VPP；
3. 返回时 `current_task`/kernel context 的生命周期不跨越调用栈；
4. worker 停止、owner 销毁、task residue 和错误返回的顺序；
5. VPP worker affinity 断言，以及禁止从别的线程触碰 owner/lwIP context。

临时 step seam 只是证明方向可行，不等于 API 已经设计完成，也没有进入仓库生产代码。

## 尚未证明

- 真实 VPP graph/plugin 的 worker frame-queue 调度已证明，但只证明 bounded lifecycle；
  本轮 `local_io_result=-1`，因为探针没有完成 wire-output 计数，不能当作完整 VPP
  packet ingress/egress proof。
- VPP node 的 buffer ownership、跨 node/frame queue、packet ingress/egress 接缝。
- 所有 lwIP global mutable state、timer/socket callback 在真实 VPP 多 worker 配置下的
  完整隔离。
- multi-worker、多实例 sharding、zero-copy、外部网络、吞吐/功耗。

## 当前决策边界

| 事项 | 当前判定 |
| --- | --- |
| 单 worker + 多 owner/lwIP context | POC GO，允许进入真实 VPP worker seam |
| 直接调用 `hev_task_system_run()` | NO-GO |
| bounded external-driver step + 真实 VPP worker node | seam GO；仍需正式 API 化与 packet path 验证 |
| 先改 lwIP 做多 worker | 暂缓；不是当前 blocker |
| zero-copy / pbuf 消拷贝 | 暂缓；本轮明确未验证 |

## 下一步

下一步不是改 lwIP，而是把临时 seam 收敛成正式 external-driver 合约，并补一个真正的
VPP packet ingress/egress 证明（buffer ownership、frame-queue 回程、wire-output）。在此
之前不进入 multi-worker、zero-copy 或 lwIP 原版级改造；若正式 API 设计失败，回到
scheduler seam，不扩展其他 POC。

附带注意：本轮 VPP 旧安装/新插件混用时，交互式 SIGINT teardown 曾出现 shutdown
SIGSEGV 栈；它没有发生在 seam 的 worker/HEV 调用路径，最终重跑的 PASS 只依据运行中
日志，不把退出路径当作通过依据。

## 复核输入

固定 pins、原始日志和最终库哈希见
`S119_EXECUTION_JOURNAL.md`；原始日志保留在 `/tmp/s119-evidence-20260820/`。
临时源码只存在 `/tmp/hev-3911f79`，相关文件哈希：

```text
hev-task-system.h       df47391442ec9908f1081cab53d000451faa457479e205328e0da6517b842b55
hev-task-system-schedule.c
                         23b6c31d0114f3cbe492239bd937527f17206532a6599a31f09efa2c46de95d0
hev-socks5-tunnel.c     520d4f8293dfdf271bdb79f5b8a6448eb53ea51a3a6f12776ac79204ae5613ec
TCP smoke                e0d7da64462054650cac7494f74aa73d625273b8f966597302db2f5117a1da99
UDP smoke                b6ba624764b6f94057832ec08b07773bcf81a25638f7f57b74f129988efa014b
```
