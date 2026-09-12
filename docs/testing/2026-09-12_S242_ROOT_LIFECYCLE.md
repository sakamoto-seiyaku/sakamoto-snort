# S242 Root Q2/W2 生命周期证据

验收通过：同源 Linux/Pixel 原生主矩阵、真实 Android supervisor、反向证据检查
及受影响回归均已完成。范围仅为 S242 Root 生命周期，不扩大 readiness。
任务状态以 Plane SAKAMOTO-242 为准。

## 实现边界

- `product_root_nfqueue_adapter_stop_step` 在 VPP worker barrier 内停止四条 lane
  的接收；存在已接纳的 buffer、obligation、handoff、completion debt 时返回
  draining，保留原 verdict fd。后续 step 才停止 graph、清空 owner flow、逆序
  关闭 lane 并归还固定接收池。每步本身不在 barrier 内等待。
- 新增 typed `product_core_root_stop` VAPI，经 C bridge、Rust FFI、JNI 到
  `RuntimeControlNative.Session.stopRootStep`。普通 query/disconnect 不触发 stop。
  generation 不匹配不得更改当前 runtime。C bridge 沿用请求退役、dispatch fence
  和未发送请求回收规则，不扩展 status struct。
- `RuntimeService` 的 Root stop 在关闭平台订阅、控制 session 和 native process
  前调用上述接口。native drain 预算为 2 秒，最多再包含一次 1 秒 UDS dispatch；
  正常结果归档到 `files/product-state/s242-last-stop.log`。外部 native 死亡另记
  OS reclamation，不能声称旧包成功或 native debt 已逐项排空。
- 每 lane 的 definite verdict fault 对同一真实 fd 执行一次 `sendto(MSG_OOB)`，
  记录实际 `result=-1, errno=EOPNOTSUPP`；先消费 identity，失败也不再物理重试。
  非负 syscall 结果只表示 operation 成功，端点送达另由独立 echo 证明。
- 合成 `verdict_outcome_unknown` 启动注入不再伪造计数；旧 S179 oracle 保留为
  历史证据，不充当当前 Q2/W2 验收。stale/duplicate 使用完成记录的显式 replay。
- 修正 replay 的 origin worker 选择；修正 mandatory NFQA_PACKET_HDR identity
  以存在性而非 `packet_id != 0` 判断。ID 0 的证据是实际 parser 的 host vectors，
  不声称设备已跑过 2³² 个包。

## 同源构建

所有下列 native/app 运行使用 Product source C：

```text
source_sha256=d1fcc51c049fff5bbe72cbed7353db2c923de3a1e0d9d353ff9d31dbd1566e4a
api=product_core.api/1.0.0@7477ac3b
Linux plugin=b2abe45cb60ec7bb4a5b1d03e58ddc03af487eded9a3199c8475dd86ff42ed71
Pixel plugin=0019c50035c3c35c3a53fb0a4306a1f95b0e685e93cc625000d3b21c068bf7f1
Pixel core=27d7b112fcdd605faf67ab2ac284afc5c69b110350c835944f4229b48cff2f10
Pixel APK=5114bdc3c627fe860677857b8dde2453aad686417b1e4dd2308d6a173212a141
```

构建、完整输入、frozen dirty diff、编译器和 native 部署读回见
`build-output/s242-20260912/{linux,pixel}-build-c/build.json`。
独立端点及 lifecycle 客户端见同目录 `{linux,pixel}-helpers-j/helpers.json`；
只有 policy/stop 客户端链接 Product Core，TCP/UDP/queue-holder 不链接 packet 实现。

## 主矩阵与判据

`tests/device/s242-root-lifecycle.py` 在 Linux 独立 user+network namespace 和
Pixel 独立私有 hook 下运行相同五阶段；只有真实 `NFQ_CAPTURED` 是收包证据。

| 阶段 | 必须核验 |
| --- | --- |
| partial-start | 外部 helper 持有 queue 179，Product 前三 lane 配置成功、第四实际配置失败；逆序释放本代池/fd，外部 holder 不受影响 |
| faults-stop | 四 lane 各有 local/remote owner；既定 policy DROP、真实 syscall failure、新 packet 恢复；duplicate/stale 各四个 carrier 无额外 verdict |
| restart | 真实旧代 identity 字段可追溯；旧 generation 请求被隔离；已观测 remote-owner hold 时调用 stop，实际先 draining 后 stopped |
| abnormal | 在真实已接纳 policy 工作中杀死 native；保留未观测 terminal result 的 identity，核验原 hook 尚在时的新流 bypass，不伪造 native zero |
| recovery | 新代重新捕获和执行 policy，计数/ledger 不继承旧代，持续双栈 TCP/UDP 后正常排空 |

每完整代有 24 个独立 kernel TCP/UDP 客户端。普通 stop/recovery 要求全部 24 条
流在 stop 前通过 NFQUEUE 并有成功 echo，stop 后仍有新的成功请求。刻意提前停止
或杀进程的 backlog 阶段只把实际 capture 的客户端计入 NFQUEUE；其他客户端的
kernel bypass 不重标为 native 完成。

verifier 核对实际 W2 LWP、四个不同 socket inode、worker/queue/fd 映射、capture
原始字节与端点 tuple、canonical owner、唯一 syscall、原 buffer return、replay
独立 carrier，以及 cutoff → terminal → fd close 的次序。正常停止后 native
buffer/flow/frame/obligation debt 为零，handoff credits 全部归还；旧 socket inode
不在 native fd table。语义反例重算 raw hashes 后仍必须失败，不能靠 hash 改动兜底。

主矩阵：`{linux,pixel}-c-9/{result,verified,negative}.json`，每平台五阶段及
25 个语义反例通过。以下计数依次为 faults-stop / restart / abnormal / recovery：

| 平台 | capture | syscall | 明确失败 / 异常代未观测结果 |
| --- | --- | --- | --- |
| Linux | 206 / 41 / 41 / 189 | 206 / 41 / 40 / 189 | 4 / 1 |
| Pixel | 560 / 29 / 21 / 530 | 560 / 29 / 16 / 530 | 4 / 5 |

带真实 backlog 的 stop 均先返回 draining 再 stopped：Linux 约 502 ms，Pixel
约 516 ms，包含显式 500 ms policy hold。该 native-only 范围不替代 supervisor。

## Android supervisor 单独核验

`s242-pixel-supervisor.py` 使用实际生产 Root hooks，执行正常 stop、重新启动后
stop、外部 native crash、恢复后 stop。PID 从实际 executable 和 durable
generation/token/runtime/profile 验证；UI 的 `pid=-1` 不用来定位 native。
策略 revision 从当前 snapshot 前进，Root helper 的临时文件不写入 app profile。

`verify-s242-supervisor.py` 另核对真实 JNI drain 日志与 archived native zero、
normal/OS-reclaim 分类、应用状态、生产规则、queue/process 残留及持续端点时间线。
进程检查不把包含 executable 文本的短暂 `sh` ownership audit 误当成 VPP。
`pixel-supervisor-c-7/{result,verified,negative}.json` 的四代矩阵及 15 个语义反例通过：

| generation | 场景 | capture / syscall | native drain |
| --- | --- | --- | --- |
| 1328 | 正常 stop | 950 / 950 | JNI 36 ms，native zero |
| 1329 | 重启后 stop | 921 / 921 | JNI 30 ms，native zero |
| 1330 | 外部 native crash | 1177 / 1143 | 34 个未完成 capture，明确 OS reclaim，不声称 native zero |
| 1331 | 恢复后 stop | 848 / 848 | JNI 35 ms，native zero |

每代全部 24 个持续客户端都有真实 NFQUEUE capture，以及应用 stop/异常清理后
新的成功 echo。此前在 1 秒截止退出的 TCP 流改为记录等待点后，在同一 socket
恢复；例如重启代三个客户端分别完成 104/104、104/104、106/106 个请求。

## 内核回收与端点窗口

保留的 `kernel-close-b` 独立探针不启动 Product：一个真实 queued SYN 的 queue
holder 退出后，queue table 已空，新 TCP 连接约 1.4 ms 建立，旧 socket 约
3.03 s 才建立。旧 socket 在 2 秒处仍为 SYN-SENT、`total_retrans=0`；同时观察到
`TCPSpuriousRtxHostQueues` 增量。Pixel 的 `enable_rcu_lazy=Y` 未被修改。

上游 Linux 6.1 的 queue instance 在 RCU callback 才 flush 队列包；TCP 对仍被
host queue 持有的 clone 可推迟 retransmission。这解释路径与实测一致，但这里
没有追踪 Pixel 的实际 RCU callback，也没有宣称其精确延时已被证明。
参见 [NFQUEUE teardown](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nfnetlink_queue.c)
和 [TCP host-queue retransmission guard](https://github.com/torvalds/linux/blob/v6.1/net/ipv4/tcp_output.c)。

旧端点程序的 50 ms UDP/1 s TCP 截止会提前抛弃晚到回包或退出旧 TCP 流。
当前 observer 保留 TCP 1 秒等待点及 TCP_INFO，最多在同一未完成请求上等待 20 秒，
不再次 send；UDP 等待 1 秒并逐请求记结果。supervisor 的 30 秒端点窗口覆盖其
应用进程清理时间。以上都不放宽 Product 的 2 秒 drain 预算，不构成性能验收。

## 已完成回归及保留失败

- host parser：ID 0/1/MAX 的 12 个正常 identity vectors、12 个缺失/截断拒绝。
- VAPI root-stop 成功/draining/错误回复/未发送/缺 callback/retired-session vectors，
  normal 与 sanitizers；Rust 26 个实际 UDS 测试及 Java contract 已通过。
- 当前 C 的 Linux S233：`rl1/verification.json`，94 个端点案例及 14 个反例。
- 当前 C 的 Linux S231：`fl3/verification-current-reassembly.json`，120 个包及
  五个 fragment ownership 反例；保持 kernel/Product reassembly 来源的区别。
- 当前 C 的 Pixel S233：`rp1/verification.json`，76 个端点案例及 14 个反例。
- 当前 C 的 Pixel S231：`fp1/verification-current-reassembly.json`，generation
  1332–1335、114 个包通过；这些 raw fragments 均由 Pixel kernel 先重组，不能
  冒称走过 Product fragment 分支。每代生产 16 条规则的 bypass 检查也通过。

早期失败原始目录保留，不改名为 PASS：source B 的错误 replay origin 已由 C 修复；
Linux/Pixel 的长 Unix socket 路径、ADB staging 权限/瞬断、source-port owner
采样相关性、未观测 backlog、端点过短窗口，以及 supervisor 的 PID 表示、policy
revision/临时目录和请求/回复识别错误均保留对应记录。测试误建的两个空 profile
目录已按确切路径 rmdir；由应用自己的 STOP 完成其余清理，没有删除业务数据。

最终 Pixel 实测：generation 1335，Root stopped，`mayBeActive=false`、`pid=-1`、
error 为空；测试 native/端点进程、queue、私有 hook、veth、临时路由均已清理。
19:18 再次读取 queue/rules/links，结果仍干净，`wifi_on=1` 未改变。

后续仍为 S225 等已排定切片及 S248/联合发布门槛；本切片不宣称零丢包、所有历史
测试通过、VPN transport 的新能力或正式发布 ready。

2026-09-12 交接：用户要求在 S242 后暂停并讨论现状；S225 尚未进行源码修改，
已退回待办。已完成切片的实现、测试和相关决策/验收文档在本次交接整理提交。
