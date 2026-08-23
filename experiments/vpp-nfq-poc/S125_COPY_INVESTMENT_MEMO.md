# S125 / POC-7 copy-investment memo

## Current status

阶段性真机结论：**TCP packet-path gate 已短时通过，UDP closed correctness 也已
通过；总体仍为 `INCONCLUSIVE`**。S124 的真实闭环只能证明路径正确，S125 短
pilot 也还不足以回答 copy 是否值得投入，因此不能据此冻结 lwIP、多 worker 或
zero-copy 方向。

UDP 短 pilot（单次、短 steady、尚无控制组和 3-repeat 矩阵）得到：

- 早期 200 ms closed timeout pilot：worker=1 `copy_share≈0.095%`，worker=2
  `copy_share≈0.105%`，但各有 4 个 app timeout；当时没有把它当作最终数字。
- 新的预注册 timeout/drain 回归（closed 1000 ms，saturating 200 ms）：worker=1
  `sent=5464 received=5464 errors=0 late=0`，`copy_share≈0.1423%`；worker=2
  `sent=5681 received=5681 errors=0 late=0`，`copy_share≈0.1492%`。
- 新回归两格均 `parse-errors=0`、`foreign=1 packet/48 B`、checksum errors=0；
  worker=2 的单 flow 只落在 owner 0，这是 tuple hash 的预期，不能证明两个
  owner 都被使用。
- 8-flow 双 worker 短检查先暴露了全局 output u64 计数的数据竞争；修成原子累计
  后重跑，两个 owner 分别处理 `12952/7426` packets，`pbuf-bytes` 与
  `write-bytes` 完全相等，app `19086/19086`。这验证了多 worker 数据链路，
  但仍不是 3-repeat 性能样本。
- TCP 8-flow 双 worker 又发现 Android 偶数 ephemeral port 使原始 FNV 低位 hash
  全落到一个 owner；加入 test-only final avalanche 后，两个 owner 处理
  `7885/11741` packets，app `19348/19348`，`tcpCopyBytes == tcpWriteCopyBytes`
  (`647130`)，output bytes 完全闭合。w1/w2 多 worker 结构现在有可验证的分布
  证据；这仍只是短检查，不是最终性能样本。

foreign 包是 IPv6/ICMPv6 背景流量，已单独计数，不混入目标 IPv4 TCP/UDP 路径。
这些百分比只说明当前短样本的测量结果，不能作为最终投资门槛的样本。

TCP gate 短回归已在真实 TUN 完成 connect、首个 echo 和 SYN → SYN-ACK → ACK →
data/output-data：`sent=6963 received=6963 errors=0`，checksum errors=0，
`copy_share_tcp≈0.1568%`。这只是单次短 gate cell；还没有 3-repeat calibration、
payload slope 或 control 对齐，不能作为 TCP 投资结论。

本轮设计加固后，下一次正式真机 run 会把以下项目作为硬证据而不是备注：64-bit
run-id/flow/sequence 防串格，setup/teardown 边界，VPP ingress/output 的
bytes/calls/errors，HEV copy bytes 与 TCP successful-write bytes 的一致性，
CPU/RSS/context-switch/thermal-limit 资源记录，以及 payload 33↔1400 的
copy-byte slope。缺任何一项，parser 只给 `INCONCLUSIVE`。

## What the next run will establish

- UDP：`full` 与 `udp-reflect`/`ingress-only`/`memcpy-cal` 在同一 TUN、queue、
  worker 边界上对齐；可计算 ingress copy、HEV submit/UDP pbuf copy 和 path
  区间的 `copy_share_udp`。
- TCP：下一轮会得到 `tcp_write_ns` envelope、`tcp_write_copy_bytes`、以及
  pinned lwIP 三个真实 `TCP_WRITE_FLAG_COPY` 点的 test-only `tcp_copy_ns`/
  `tcp_copy_bytes`；同时保留 owner/lwIP pool/credit、RTT/吞吐和 simpleperf。
  `tcp_copy_ns` 不包含 pbuf 分配、TCP header、`tcp_output` 或 kernel/TUN residual，
  所以仍按保守的 copy-share 解释，不把 envelope 冒充纯 copy。
- 所有协议：可同时看到 queue wait、TUN write errno、CPU/RSS/thermal、
  `observe=off/sample64/full` 校准和 UDP/TCP 代表格 simpleperf，避免把 queue、
  系统调用、HEV 测量成本或热降频误判成 memcpy。注意 HEV perf 累计计数与
  VPP sampled stage 不在同一包集合；只有 `observe=full` 进入 copy attribution，
  off/sample64 只做 overhead 对照，TCP 还要求 full/sample64 ≤3%（fire-and-count
  arm 用 send PPS）。

下一轮正式数据的前置条件是重复通过 TCP packet-path gate：同一 flow 必须出现
SYN → SYN-ACK → ACK，并完成至少一个带 payload 的 echo；同时保留包头、checksum、
端口和 TUN/VPP output 原始记录。UDP closed 使用 1000 ms timeout，并在 drain
主动记录 late echo；closed 有 timeout 仍判 invalid。gate 通过后，再跑 UDP/TCP
的 Tier 0 controls、payload/flow/burst/workers repeats、resource/thermal 和
simpleperf，才足以支撑投资判断。

## Decision rule

只有 Tier 0 calibration、steady window、correctness/control、resource 和
simpleperf 条件都有效，才允许写 `DEFER`、`TARGETED` 或 `MUST_INVEST`。任一
条件失败保持 `INCONCLUSIVE`，先补仪器，不调整门槛。

TCP 的纯 copy seam 已作为 POC-7 test-only patch 固定下来；真机执行前仍须
验证 APK 中导出两个符号、TCP `tcp-copy-metric=1`，以及 copy bytes 随 payload
斜率一致。parser 还要求 8 个 matched full UDP control key、每 key 至少 3 个
valid repeat、代表 UDP/TCP simpleperf 都存在。任一项缺失，run-summary 保持
`INCONCLUSIVE`。

执行前 artifact gate 已通过：Android arm64 plugin、HEV 两个 TCP seam symbol
和 APK packaging 均已核验。短回归已安装并运行 APK；正式 Tier 0/Tier 1 尚未
开始。当前不输出 `DEFER`、`TARGETED` 或 `MUST_INVEST`。

## Control-arm closure before the formal run

控制臂的第一轮回归发现了两个必须先修的执行问题：失败 flow 的 `sent=0` 会让
解析器除零；更重要的是，VPP handoff helper 在 `drop_on_congestion=1` 时已经
释放 dropped buffer，插件再次 free 导致 double-free 和 VPP `SIGSEGV`。这两项
都已修复，并保留了原始失败目录，不能把它们混入性能样本。

修复后，100µs、1ms、5ms 的 fire-and-count 都仍会填满 64-frame handoff queue，
所以没有把那些数据当成结果。将 pacing 预注册为 10ms/包后，真实 Pixel 6a 上
ingress-only 和 memcpy-cal 各自的 w1/w2、observe=off/full 共 8 个控制 cell 全部
通过：`fatalFlows=0`、`errors=0`、`enqueue-drops=0`，steady offered rate
约 91.7–92.7 pps；TCP packet gate 同轮也通过（`6492/6492`）。这只证明控制源
现在有一个可复现、无丢包的校准点，不代表高负载吞吐，也不改变总体
`INCONCLUSIVE` 状态。

因此下一轮正式矩阵可以提供所需的 per-cell 数据（app sent/received/errors/RTT、
VPP stage/queue/output counters、owner deltas、copy bytes/ns、CPU/RSS/context
switch/thermal、TCP copy seam 和 simpleperf）。真正的 copy 投资结论仍要等
Tier 0 三重复、Tier 1 worker/flow/payload 矩阵和资源/火焰图证据全部有效后再写。

## Formal Tier-0 rerun audit

`/tmp/s125-tier0-rerun-20260822-044826` 已完成真实 Pixel 6a Tier-0，但不能
作为最终投资结论：298 个 cell 中 220 个有效、78 个无效。TCP packet-path
gate 通过；无效项一部分是高 burst udp-reflect 的 thermal guard，另一部分是
fire-and-count 控制的 burst=32 queue drop。

后审计发现控制源实现与设计约束不一致：`runUdpBatch`/`runTcpBatch` 在整批
32 包发送完才 sleep，导致微突发，虽然平均发送率被限制为 10ms/包，仍会击穿
VPP handoff queue。这个问题会把控制臂测成 queue capacity，而不是 ingress/
memcpy 成本，因此旧控制 cell 不纳入 copy 分析。

已修复为包间 10ms pacing，并在匹配 VPP runtime/plugin 的 APK 上做真机修复
smoke：`/tmp/s125-control-repair2-20260822-104623` 的 16/16 个 burst=32
短 cell 全部 `valid=true`、`enqueue-drops=0`、`fatalFlows=0`、app errors=0。
这验证了修复方向，但仍不是正式三重复；需要先补齐控制三重复，再补 thermal
失效的 udp-reflect cells，之后重新生成完整 Tier-0 summary。

因此当前 memo 结论仍为 **INCONCLUSIVE**：现有正式 run 证明了数据采集链路和
TCP gate，但没有证明 copy 是否值得投入；下一步先完成修复后的 formal
control/thermal recovery，再决定是否进入 Tier-1/Tier-2。

## 长时 UDP 校准后的阶段性判断（2026-08-22）

新计时器（一次校准的 VPP CPU counter）已在 Pixel 6a 上跑完补充长时组：
`full`/`udp-reflect`、worker=1、UDP 33B、burst=1、60 秒 steady、
off/sample64/full 各三次，共 18 格，18/18 有效、无 enqueue drop/fatal，
温度 45–49°C。它证明计时器改动没有破坏真实 TUN 闭环。

这组数据对 copy 的信号很明确但范围有限：full arm 的 HEV UDP copy-share
中位数约 `0.0643%`（P05/P95 `0.0581–0.0683%`）；每格约 3.4–4.0 MB、
9.4–10.8 ms 的 UDP copy 计数。full 与 udp-reflect 的 full-observation
路径中位差为 `318,956,947 ns`，约 0.32 秒/60 秒 steady；这更像当前
整条路径中的小残差，而不是首要瓶颈。`pbuf-bytes == write-bytes` 且
`output-copy-bytes=0`，所以没有证据表明 output 侧还暗含第二次 copy。

但这还不是投资结论：full 臂 off→sample64 为 `3.7339%`，超过 3% 仪器门槛；
本组没有 1400B 对照、TCP gate、simpleperf 或 ingress/memcpy-cal 控制臂。
因此总体仍是 **INCONCLUSIVE**。目前较稳妥的方向是先把 UDP 33B 的 copy
列为低优先级候选瓶颈，继续用 p1400、TCP 和控制臂验证；不因这组数字冻结
zero-copy/lwIP 设计，也不提前写 `DEFER`/`MUST_INVEST`。

## 1400B 与 TCP 校准后的阶段性判断（2026-08-22）

同一计时器和 APK 又完成了 UDP 1400B、以及 TCP 33B 的真机校准：TCP gate
通过，UDP 18 格和 TCP 9 格全部有效。1400B 的 full UDP copy-share 为
`0.1788–0.1999%`，TCP 33B copy-share 为 `0.1367–0.1434%`；对应的
copy bytes 与实际 payload 斜率一致。把前一组 UDP 33B 长样本合并后，UDP
copy-bytes/pkt 斜率 `1400/33=42.4242` 通过，说明目前观测到的 copy seam
确实随 payload 增长，而不是固定计时假象。

这让“copy 是否可能是首要瓶颈”更偏向否：目前可见的 HEV/lwIP copy 区间
在 UDP/TCP 代表格都低于整条 observed path 的 0.2%。但仍不能写最终投资结论：
TCP 还没有 1400B slope，ingress-only/memcpy-cal 控制臂和 simpleperf 尚未
与这批新 artifact 对齐；并且 off→sample64 的 3% 仪器门槛在 TCP、UDP 1400B
和部分 full/reflect 格都失败（约 5.8–6.2%，full→sample64 亦有一格 9.1%）。

因此当前仍为 **INCONCLUSIVE**，但下一轮的重点不应是立即改 zero-copy，而是
先解决观测门槛：做同设备状态下的 paired/随机化 observe 对照或进一步削减
非 copy 观测扰动，再补 TCP 1400B、控制臂和代表性 simpleperf。只有这些门槛
通过后，才值得跑完整 Tier-0/Tier-1 矩阵。

## 代表性 simpleperf 阶段信号（2026-08-22）

修正 simpleperf 的 Android arm64 工具链和报告调用后，真机上得到一格有效的
高并发样本：worker=2、32 flows、1400B、burst=1、full UDP、30 秒 steady。
两个 owner 都有 steady 包（`117988/114603`），无 enqueue drop、mismatch 或
unexpected；计时 copy-share 为 `0.03596%`。

20 秒 VPP callgraph 的主要 CPU 样本是：`s124_checksum_sum 20.07%`、内核
`_raw_spin_unlock_irqrestore 11.25%`、`ipt_do_table 5.48%`、worker node
`2.41%`；memmove/memcpy 相关合计约 `2.11%`。这不是把“2.11% CPU 样本”
直接等同于 HEV copy-share，而是独立的热点证据：当前设备/路径下 checksum、
锁竞争和内核过滤明显排在 memcpy 前面。

因此阶段方向进一步清晰：copy 暂不像第一优先级瓶颈；若要优化，先看 checksum
重复计算、锁/队列调度和 netfilter/kernel 路径。但该格仍只是代表性 Tier-2
样本，不能替代完整 control、TCP 1400B slope、仪器门槛和多矩阵重复，因此
总状态仍为 **INCONCLUSIVE**，不冻结 zero-copy/lwIP 设计。

## Paired observe 阶段性判断（2026-08-22）

paired 观测已在真实 Pixel 6a 上跑通，并修正了一个会污染测量的工具问题：完整
`show s124-vpn-tun` 会调用 HEV/lwIP pool/credit 诊断，负载下可能让 CLI 读数延迟
20–30 秒。现在 paired 使用只读 VPP 计数的 test-only `show s124-vpn-tun-lite`，
完整 show 仍保留给 cell 结束解析。

两轮 closed UDP 1400B 都是有效闭环，`sent=received`、无 enqueue drop、thermal
max 47°C。正序的 full 段约 `1645.5 pkt/s`，反序 full 段约 `1648.3 pkt/s`，说明
full 观测段本身重复性尚可；同一正序中 sample64 约 `1686.8 pkt/s`，相对 full
约 2.5%。不过 off 首段明显受设备/状态 ramp 影响，反序 sample 又发生一次
33.9 秒 CLI 调度延迟，因此不能把这几格升级为正式的 off→sample64 ≤3% gate。

当前判断保持：轻量 snapshot 解决了诊断回调污染，但 paired 仍需更多稳定窗口或
设备内调度方案才能成为正式仪器门槛。copy-share 仍处于低于整条 observed path
约 0.2% 的量级；本轮没有证据支持立即投入 zero-copy/lwIP 改造，也没有足够证据
把观测扰动写成最终性能结论。总体仍为 **INCONCLUSIVE**。

## TCP payload-slope 阶段性判断（2026-08-22）

同一匹配 artifact 的 Pixel 6a 真机 TCP closed 校准已完成 `19/19` 有效单元，
握手 gate 通过，且没有 app/VPP 错误、丢包或 checksum 错误。full path 的
TCP copy-share 中位数为：33 B `0.1297%`，1400 B `0.3812%`；每包 copy
字节从 `32.9931` 增至 `1399.6501`，斜率 `42.4272x`，与 payload 增长一致。

这进一步支持“当前可见 lwIP/TCP copy 不是首要 CPU 瓶颈”的方向，但不能把它写成
最终投资结论：本轮是 closed、只有 full TCP，没有注册要求的 saturating TCP、
UDP 对照臂、完整 instrumentation gate 或多 worker 控制数据。当前总状态仍为
**INCONCLUSIVE**；下一步先补正式 saturating TCP pair 和修复后的 Tier-0 控制臂，
不提前改 zero-copy、lwIP 或多 worker 生产架构。

## Saturating TCP 阶段性判断（2026-08-22）

同一 artifact 的 saturating TCP p33/p1400 三重复已完成，`19/19` 真机单元有效，
握手 gate 与 p33 的 off/sample64/full 仪器门槛通过。full copy-share 中位数为
`0.1233%`（33 B）和 `0.3508%`（1400 B），copy bytes/pkt 斜率为 `42.4305x`。
这让“可见 TCP copy 不是当前第一优先级瓶颈”的判断更稳，但 p1400 的 off 基线
仍有 `5.95%` 仪器偏差，且 UDP 控制臂尚未与该 artifact 对齐。

因此总状态仍为 **INCONCLUSIVE**。现在缺的不是 TCP 路径可行性，而是同 artifact
的 UDP 四控制臂、thermal recovery、控制差分和资源/火焰图闭环；在这些证据完成前，
不冻结 zero-copy、lwIP 或多 worker 生产设计。

## 阶段决策：暂停补充矩阵，转入现有路径优化（2026-08-22）

现有真机资料足够支持工程方向，但不足以宣称正式投资门槛已经闭合。当前可见
copy-share 在代表性 UDP/TCP 样本约 `0.1%–0.4%`，TCP p33→p1400 copy
斜率约 `42.43x`；simpleperf 代表格中 memcpy/memmove 约 `2.11%`，低于
checksum、锁竞争和 netfilter 热点。因此下一阶段先优化现有双 copy 路径的
时序、批量、队列/锁和 checksum 细节，不启动 zero-copy、lwIP 内存模型或多
worker 生产架构重构。

Tier-0 控制矩阵已按用户决定暂停，未完成部分不算失败也不阻塞上述工程优化；
后续有时间再用同一 artifact 续跑。记录状态仍为 **INCONCLUSIVE（阶段方向已定）**，
不写 `DEFER` 作为正式统计结论。
