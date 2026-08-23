# S125 / POC-7：真机 VPN copy 投资判定设计

状态：**阶段性结论已形成；补充 Tier-0 暂停，正式统计仍未闭合**（2026-08-22）。

已在 Pixel 6a 完成长时 UDP 33B、UDP 1400B/TCP 33B 校准补充、同一 artifact
下 TCP 33B/1400B closed 与 saturating 三重复、一格有效 32-flow simpleperf，以及
paired observe 的轻量 snapshot 补充；预注册的完整 Tier 0/Tier 1 正式矩阵仍未启动。
补充结果显示 copy-share 很低，但 observe off→sample64 仪器门槛尚未稳定通过，
不能把补充组升级为最终投资结论。UDP 的观测链路已经能产出有效的短样本；TCP
packet-path gate 和 closed payload-slope 校准均已通过，但 saturating TCP、
控制臂和正式多矩阵证据仍缺；saturating TCP p33 gate/slope 已通过，但 p1400
off 基线仍未通过 3% 仪器门槛，因此不能把现有 TCP 数字当作最终 copy 投资结论。

最新短回归使用 closed UDP 1000 ms timeout 和主动 drain：TCP gate、UDP worker=1/2
 closed correctness 均通过；这只证明执行链路已稳定，仍不改变 POC 的最终状态。

本 POC 的问题不是“能不能把包跑通”，而是要在 Pixel 6a 的真实
`VpnService TUN → VPP → worker-local HEV/lwIP → TUN` 路径上，回答：

> VPP/lwIP 边界的 copy 是否已经足够大，值得投入 zero-copy、pbuf 适配或
> 更深的内存布局改造？

POC-6 的 owner/worker seam 保持不动；POC-7 只增加 test-only 的测量 seam、
控制组和流量发生器，不改变生产所有权契约，也不据此冻结 lwIP 多 worker
API。

## 1. 为什么 S124 数据还不能直接下结论

S124 已证明真实 TUN、单/双 worker 和 UDP/TCP echo 正确，但还缺以下闭环：

1. 多 flow 目前是顺序开关，elapsed 包含建连、关闭和超时，不能代表 steady-state。
2. `output-copy-bytes` 只是命名，当前 output callback 没有实际的额外 copy；
   TUN read、VPP buffer alloc/copy、queue wait/dequeue、TUN write 没有完整计时。
3. HEV 已有 pbuf/copy 计数，但没有和同一包的 TUN/VPP 时间对齐，也没有
   `pbuf`、TCP PCB/SEG、credit 的 high-water 证据。
4. 没有同一流量发生器下的 TUN/VPP 控制组，因此无法把“copy 慢”与
   queue、系统调用、lwIP/TCP stack 慢区分开。
5. 没有 instrumentation-off 对照；若每包 `clock_gettime` 改变了调度，数据本身
   就不能用于性能判定。
6. 没有 steady-state 的 CPU、RSS、thermal 和 simpleperf 样本，无法判断 wall time
   占比是否真的对应设备 CPU 瓶颈。

所以，下一轮若只重复 S124 的 flow probe，数据仍不足；必须先补齐本协议。

## 2. 判定对象与非目标

### 判定对象

- 真实 Pixel 6a，真实 Android `VpnService.establish()` TUN fd。
- UDP 与 TCP；IPv4、无 IP options/fragment，payload 33/512/1400 B。
- 1、8、32 个**同时存活**的 flow，VPP worker 为 1 与 2。
- VPP main → worker frame queue → owner-local HEV/lwIP 这条 seam。

### 非目标

- 不在本 POC 改生产 lwIP、改多 worker 拓扑、引入 zero-copy 或 VPP native TCP。
- 不把 x86 synthetic S123 的数字和 S125 的真机数字直接混为一个样本。
- 不把 kernel/TUN 内部不可观测的 copy 假装成已测量的 copy；它只能进入 residual。
- 不用顺序建连/重启 app 的耗时替代 steady-state packet cost。

## 3. 实验臂和控制组

所有 arm 使用同一 APK 流量发生器、同一 TUN 配置、同一 payload/flow/burst，
只替换 VPP test-only packet path：

| arm | 路径 | 能回答什么 |
| --- | --- | --- |
| `full` | TUN read → VPP buffer → owner queue → HEV/lwIP → TUN write | 真实目标路径总成本 |
| `udp-reflect` | TUN read → VPP buffer → owner queue → UDP tuple/checksum reflect → TUN write | 去掉 lwIP 的 UDP 控制，隔离 TUN/VPP/queue/write；仍回 echo 做 payload 校验 |
| `ingress-only` | TUN read → parse →（可选 VPP buffer alloc+copy）→ drop | read/parse/alloc/copy 的下界；使用 fire-and-count 发生器 |
| `memcpy-cal` | 保留同一 TUN→VPP ingress/queue，在 worker 复用固定 scratch buffer 做一次受控 copy，不启动 HEV、不写回 TUN | 设备上的单次 memcpy 斜率；与 `ingress-only` 的差值是受控 copy 对照 |

`udp-reflect`、`ingress-only` 和 `memcpy-cal` 是 test-only mode；若某一 arm 尚未实现，
该 arm 对应的结论必须标为 `INCONCLUSIVE`，不能用经验补齐。

TCP 没有伪造 TCP responder 控制臂；TCP 结论依赖 full path 的逐段计时、
HEV `tcp_write` copy 计数、simpleperf 和 UDP 控制臂给出的 TUN/VPP 基线。
这比写一个新的 TCP 反射器更少引入第二套 TCP 语义。

## 4. 必须记录的时间和计数

计时使用 `CLOCK_MONOTONIC`；所有值按 steady phase 的增量记录，不读“从 VPP
启动以来的累计值”当作 cell 数据。每个 stage 同时有 `ns`、`bytes`、`packets`、
`errors`，避免只看一个总数。

### 4.1 VPP main / ingress

- `tun_read_calls`, `tun_read_eagain`, `tun_read_errors`，`tun_read_ns`，
  `tun_read_bytes`。
- `buffer_alloc_calls`, `buffer_alloc_errors`, `buffer_alloc_ns`。
- `vpp_ingress_copy_ns`, `vpp_ingress_copy_bytes`（TUN rx scratch → VPP buffer）。
- parse success/error；目标路径只接受 IPv4 TCP/UDP。IPv6 或其它合法但非目标的
  TUN 输入单独记为 `foreign-packets/foreign-bytes`，并保留最后一个包的
  version/proto；`parse-errors` 仍必须为 0。
- 对 IPv4 TCP/UDP 输入和输出做 checksum 校验；`*-checksum-errors` 必须为 0。
  这不是性能计时，只是把“包已经正确离开 lwIP”与“Android 没有完成回程”分开。
- `enqueue_calls`, `enqueue_ns`, `enqueue_packets`, `enqueue_drops`。
- `foreign_packets`, `foreign_bytes`，以及 `parse_error_bytes` 和最后一个
  parse/foreign 包的长度、IP version、协议号；这些字段用于证明背景流量没有被
  混入目标 TCP/UDP 统计。
- TCP/UDP input/output checksum `checks/errors`，以及 TCP 的
  `input-syn/input-ack/input-data/output-syn-ack/output-data` 事件计数；这些是
  TCP handshake gate 的 correctness evidence，不计入 copy-share。
- 每个目标 worker 的 queue `head/tail` 深度样本、`queue_depth_max`、
  `dequeue_packets`、`queue_wait_ns`。

queue 深度只读 VPP frame queue 的 atomic `tail-head`；不能把未应用的 wake patch
字段当作协议依赖。每个 buffer 的 ingress timestamp/owner/采样标记放在
`vlib_buffer_t::opaque[]` 的 test-only 保留槽位，不分配 side table。

### 4.2 worker / HEV-lwIP seam

- `dequeue_to_submit_ns`、`submit_total_ns`、`submit_errors`。
- HEV 已有并必须导出的：
  `submit_pbuf_alloc_ns/allocs/frees`、`submit_copy_ns/bytes`。
- UDP：`udp_echo_pbuf_alloc_ns/allocs/frees`、`udp_echo_copy_ns/bytes`、
  `udp_echo_stack_ns`（pbuf copy 之外的 `udp_sendto_ctx` 区间）。
- TCP：`tcp_write_ns`（`tcp_write` envelope）、`tcp_write_copy_bytes`、
  `tcp_write_calls`，以及 POC-7 HEV seam 在 lwIP `tcp_out.c` 三个真实
  `TCP_WRITE_FLAG_COPY` 写入点记录的 `tcp_copy_ns`/`tcp_copy_bytes`。
  该区间包含 `TCP_CHECKSUM_ON_COPY` 时和 copy 同步发生的 checksum 工作，
  但不包含 pbuf 分配或 `tcp_output`；只有被 VPP `observe` 选中的包开启计时，
  `observe=off` 不付出两次 `clock_gettime` 的测量成本。它仍是 test-only
  归因，不是生产 lwIP API。
- 每个 owner 的 runtime identity：session/tcp-session/udp-session count，
  TCP PCB/PCB-listen/SEG、PBUF/PBUF-payload、UDP PCB used/free，四类 credit
  limit/used/high-water/rejects，`last_limit_error`。

`submit_total_ns` 是 worker 从 dequeue 到路径操作完成的包级 envelope；`full`
arm 中它具体是包进入 HEV 到返回，control arm 中对应 reflect/calibration/drop
完成。copy ns、`udp_echo_stack_ns` 和 output callback 都是 full arm 的嵌套诊断
区间。当前 pinned HEV 没有独立的 `tcp_output_ns`，它留在
`tcp_write_ns`/owner residual 中；分析时不得把父区间和子区间相加两次。

### 4.3 output / TUN completion

- `netif_output_calls`, `netif_output_ns`, `output_pbuf_bytes`（pbuf chain 的
  `tot_len`）。
- `tun_write_calls`, `tun_write_ns`, `tun_write_bytes`。
- `partial_write`, `EAGAIN`, `EINTR`, 其它 errno 分开计数；禁止把所有失败
  合并成一个 `output-errors`。
- 明确 `output_copy_bytes=0`，除非实现了并实际执行了第二次 output copy。

### 4.4 app 和设备资源

每个 cell 还要有：

- app：setup/warmup/steady/drain/teardown 的时间戳，发送/接收/丢失/乱序/
  payload mismatch、每 flow RTT p50/p95/p99、发送 PPS、接收 PPS、goodput；TCP
  还要记录每 flow 的 connect 成功、首个 echo、connect latency，以及聚合的
  `tcpConnectedFlows/tcpFirstEchoFlows/tcpHandshakeReady`。
- VPP 与 app 的 `/proc/<pid>/stat` CPU ticks、`VmRSS`/`VmHWM`、线程数、
  每线程 affinity/current CPU/context switch。
- 每个 owner 的 packet/byte delta；workers=2 且 flows≥8 的正式 cell 必须看到
  两个 owner 都有 steady packet，避免把“开启两个 worker 但流量全落在一个
  owner”误当成多 worker 证据。flows=1 的校准格允许单 owner，这是 tuple hash
  的预期结果。
- app payload 固定使用 `S125-v2` 格式：magic/flow + 64-bit run id + 64-bit
  sequence（最小 21 B）；flow/done 记录必须带同一 run id，防止前一格的
  late echo 或旧日志污染当前 cell。
- steady phase 前后 `dumpsys thermalservice`、thermal zone 温度、CPU policy
  频率/限频状态。
- 选定代表 cell 的 simpleperf callgraph；至少能区分 `memcpy`/`memmove`、
  `clib_memcpy_fast`、HEV pbuf alloc、lwIP input/output、VPP queue 和 `write`。

app 的 `System.nanoTime()` phase 边界与 VPP CLI 原始记录中的
`cli_monotonic_ns` 使用同一 monotonic 时钟域；parser 只取 steady 区间内的
show 快照，不能把 VPP 启动以来的累计值直接当作 cell 值。

## 5. 流量发生器协议

现有 `runUdpFlowProbe`/`runTcpFlowProbe` 必须保留作旧 smoke，不得冒充 POC-7。
新增 test-only action（建议 `ACTION_L4_STRESS_PROBE`），一次 action 只跑一个
cell，避免多次 `am start` 的竞态。

参数固定写入 cell manifest：

```text
protocol=udp|tcp
flows=1|8|32
payloadBytes=33|512|1400
burst=1|32
load=closed|saturating
workers=1|2
warmupSeconds=10
steadySeconds=30
drainSeconds=10
reconnectEvery=0|N
observe=off|sample64|full
expectEcho=true|false
```

实现约束：

1. 先建立全部 socket，再用 barrier 同时进入 warmup；setup/teardown 不计入
   steady 吞吐。
2. UDP 每 flow 使用确定的 local port；TCP 让内核分配 ephemeral local port；两者都记录
   实际端口、flow id 和 sequence。payload 带 `run_id/flow_id/sequence`，echo 必须逐包
   校验，不能只比长度。
3. UDP 每 flow 有发送与接收逻辑；TCP 每 flow 保持一个连接，写入与读取并行，
   `burst=32` 表示最多连续写/发 32 个 payload 后再收取对应 echo，不表示 32 次
   顺序建连。
4. `closed` 为每 flow 一个 outstanding request，测正确性和 RTT；`saturating` 为
   固定 window（默认 32）尽可能发送，记录实际 offered/received rate。不要用
   `Thread.sleep` 的毫秒精度控制 PPS。
5. `reconnectEvery=0` 是 steady connection reuse；单独的 close/reuse cell 在
   steady 中每 N 秒同时关闭并重建所有 flow，记录 setup/close errors 和 owner
   session high-water。它不与基础 cell 混在一起。
6. `ingress-only` 使用 fire-and-count：发送端不等待 echo，但仍记录 offered packets；
   该 arm 只用于 ingress 成本，不能拿来和 full 的 receive goodput 直接比较。
   `memcpy-cal` 也使用 `expectEcho=false` 的 fire-and-count；它不是“无 TUN”的
   合成测试，而是把同一 ingress/queue 边界加上一份可复用 scratch copy，避免
   把 kernel/TUN 成本误算成 memcpy。两者都使用预注册的
   `fireAndCountPacingNsPerPacket=10000000`（每包 10 ms）限速；不得用无界 tight
   loop 施压，否则控制臂测到的是 VPP 队列溢出/崩溃而不是路径成本。`enqueue-drops`
   或 flow fatal 均使该 control cell 失败，raw 仍保留用于诊断。
   `udp-reflect` 保持 `expectEcho=true`，用于验证 control arm 的 tuple/checksum
   和 TUN write 闭环。
7. action 结束前必须等待 drain；若仍有 outstanding request、后台 flow、HEV
   session 或 VPP queue，cell 失败，不静默进入下一格。

`closed` cell 要求 sent=received 且无 error/mismatch；UDP closed receive timeout
预注册为 1000 ms，saturating timeout 为 200 ms。`saturating` cell 允许把 loss
作为容量结果，但仍要求 echo payload 不得 mismatch/reorder/unexpected，并把
loss rate 单独写入 summary，不能把它伪装成 correctness PASS。窗口中，超时后仍
到达、且能通过同一 flow/run-id 校验的 echo 记为 `late`（容量/排队证据），不记
为 `unexpected`；closed 中同样记录 `late`，但只要发生 timeout，closed 仍然失败。
handoff `enqueue-drops` 的判定与 load 对齐：closed 和两个 fire-and-count control
arm 必须为 0；full/udp-reflect 的 saturating cell 将其作为容量损失保留在 summary，
不因此失效，但仍要求 echo payload 无 mismatch/reorder/unexpected，并单独报告 app
loss rate 和 output byte accounting。
只有曾经明确 timeout 的 sequence 才能记为 `late`；重复包或未追踪的 sequence
仍是 `unexpected`。drain 阶段必须主动接收并记录 late echo，不能只 sleep。

## 6. 预注册矩阵和执行分层

### Tier 0：仪器/控制校准

正式 Tier 0 之前必须先通过真实 packet-path gate：UDP 至少完成一个 closed 和一个
  saturating smoke；TCP 必须同时满足：

1. app 侧所有 flow 的 `connect()` 成功，并收到至少一个带 `S125-v2` payload 的 echo；
2. VPP raw 计数观察到同一批流量的 SYN、SYN-ACK、ACK、TCP data 和 output data；
3. IPv4/TCP checksum errors 为 0，且没有 output write/error、parse、queue 或
   credit failure。

TCP gate pilot 已通过，但它只有短时单次样本；正式校准仍要求预注册的 3 次
off/sample64/full 重复，并由 parser 检查握手事件、checksum 和 app counters。

- `full` UDP、`udp-reflect`、`ingress-only`、`memcpy-cal`：payload 33/1400，
  burst 1/32，workers 1/2，3 repeats。
- 每个代表 cell 跑 `observe=off`、`observe=sample64` 与 `observe=full`；
  off/sample64 吞吐中位数差异必须 ≤3%，full UDP 的 HEV owner/runtime/lwIP
  快照必须可读。只有 `observe=full` 的 cell 进入时间/拷贝归因，因为 HEV
  submit/UDP perf 累计计数覆盖所有包，而 VPP stage timer 按 observe 采样。
- 四个 arm 的 full-observation key 必须一一匹配（workers 1/2 × payload 33/1400
  × burst 1/32）；缺一个就不能用 control delta 做最终判定。
  `ingress-only`/`memcpy-cal` 的 off/sample64 overhead 用 offered send PPS，不能
  用必然为零的 receive goodput。
- 额外跑一个 TCP full `flows=1,payload=33,burst=1,saturating` 的
  off/sample64/full 校准；off/sample64 和 full/sample64 的吞吐差异都必须 ≤3%，
  确认 test-only TCP copy timer 与 full attribution 不改变 steady 结果。
- 先完成，不通过就不跑 Tier 1。

### Tier 1：full path 决策矩阵

- UDP/TCP × workers 1/2 × flows 1/8/32 × payload 33/512/1400 × burst 1/32
  × load `closed/saturating` × 3 repeats。
- 每格 10 s warmup + 30 s steady + 10 s drain；每 6–8 格插入 thermal/resource
  guard，状态不干净就暂停并重做该批。
- `observe=sample64` 覆盖全矩阵；`observe=full` 覆盖所有代表 cell（至少
  `flows=1/32 × payload=33/1400 × burst=1/32 × workers=1/2`，UDP/TCP 各一组）。

### Tier 2：生命周期/火焰图

- UDP/TCP，各 workers 1/2，flows 8/32，payload 33/1400，`reconnectEvery=5s`，
  3 repeats。
- UDP/TCP 各选 `flows=32,payload=1400,burst=32,saturating` 做 simpleperf，
  采样只覆盖 steady 20 s，不把启动和 drain 录进火焰图。

如果 Tier 0 或 Tier 1 已经满足“必须投入”/“明确可暂缓”的判定门槛，Tier 2
仍用于确认资源/生命周期，不改变门槛；如果数据互相矛盾，结果必须是
`INCONCLUSIVE`，补仪器后重跑，不能凭经验选方向。

## 7. 统计、残差和判定门槛

每格取 3 次的 median、p95、IQR；steady 期间按增量计算。核心派生量：

```text
observed_copy_ns_udp = vpp_ingress_copy_ns
                     + submit_copy_ns
                     + udp_echo_copy_ns

tcp_write_copy_bytes = successful TCP_WRITE_FLAG_COPY request bytes
tcp_copy_bytes = bytes copied at the three real lwIP TCP_WRITE_FLAG_COPY sites

observed_path_ns = ingress_total_ns       # read→enqueue 完成
                 + queue_wait_ns           # enqueue timestamp→dequeue
                 + submit_total_ns         # dequeue→path operation complete

copy_share_udp = observed_copy_ns_udp / observed_path_ns

observed_copy_ns_tcp = vpp_ingress_copy_ns
                     + submit_copy_ns
                     + tcp_copy_ns

copy_share_tcp = observed_copy_ns_tcp / observed_path_ns
```

`submit_copy_bytes`/`udp_copy_bytes`/`tcp_copy_bytes`/`tcp_write_copy_bytes`、
`ingress_copy_bytes`、`parse_packets`、`enqueue_packets/drops` 和
`tun_write_bytes` 必须与对应的 ns/calls 同格出现。full-observation 的
payload 33/1400 配对中，copy bytes/packet 必须随 payload 单调上升；TCP
还必须满足 `tcp_copy_bytes <= tcp_write_copy_bytes`。缺字段、计数不一致、
parse/queue/output error 或 payload 斜率不成立，均为 `INCONCLUSIVE`，不能
用零填充。

其中 `ingress_total_ns` 不是一个额外的父计时，而是同一采样集合上的非重叠
阶段和：`tun_read_ns + parse_ns + buffer_alloc_ns + ingress_copy_ns + enqueue_ns`。
`memcpy-cal - ingress-only` 只比较 worker 的受控 copy 斜率，不把两臂的总时延
直接当成 HEV 成本。

`netif_output_ns`、`tun_write_ns`、`udp_echo_stack_ns` 和 TCP `tcp_write_ns` 是
`submit_total_ns` 内的 nested attribution，只用于说明 owner 区间，不能再加到
`observed_path_ns`。若需要 residual，按同一边界计算：

```text
owner_unattributed_ns = submit_total_ns
                      - measured_non_overlapping_owner_subranges
```

TCP 现在可以使用 `copy_share_tcp`，但它仍是保守值：`tcp_copy_ns` 只覆盖
lwIP 的真实 payload copy；pbuf 分配、TCP header、`tcp_output` 和 kernel/TUN
内部不可观测 copy 留在 envelope/residual，不能从中推断为已测量的 copy。TCP
进入 `TARGETED`/`MUST_INVEST` 仍须同时满足 `tcp_write_copy_bytes` 的 payload
斜率、TCP envelope、UDP/TUN 控制组和 simpleperf。若出现负 residual 或 bytes
斜率不一致，cell 的时间分解无效。

最终只允许四种状态：

- **DEFER**：UDP `copy_share_udp` 的 95% 上界 <5%，TCP 的 copy 相关 simpleperf
  样本 <10%，且
  payload 斜率/吞吐变化由 queue 或 stack/residual 解释；目前没有证据值得马上
  做 zero-copy。
- **TARGETED**：UDP `copy_share_udp` 在 5–15%，或任一协议 copy 样本 10–20%，且随 payload/burst
  稳定上升；做 batch、pool、拷贝布局等局部优化，再测，不直接改所有权模型。
- **MUST_INVEST**：UDP `copy_share_udp` 的 95% 下界 ≥15%，或 TCP/UDP copy 样本 ≥20%，并且
  `full - udp-reflect`/memcpy-cal 的差值与 copy bytes/packet 具有一致斜率，
  同时无 queue/资源/thermal 主导因素；才进入 zero-copy/pbuf 适配专项。
- **INCONCLUSIVE**：任一 correctness、instrumentation-overhead、thermal、pool
  或控制组条件失败；POC-7 未结束，先补设计/仪器。

门槛是本 POC 的预注册工作门槛，不是生产 SLA；不得在看到结果后调整。

## 8. 结果文件和流水账边界

每个 cell 目录至少有：

```text
manifest.json             # 配置、阶段、hash、设备和工具版本
app.log                   # app 原始 phase/flow/RTT 记录
vpp-show.raw              # show s124/s125 原始输出
resource-before.raw
resource-steady.raw
resource-after.raw
thermal-limit.millic       # 本次 run 的预注册热上限
simpleperf.data           # Tier 2 代表格
simpleperf.report         # host-readable symbol attribution
cell-summary.json         # 机器可读派生数据和 validity

run-manifest.json         # device/artifact/run identity
run-summary.json          # all-cell controls and provisional decision
```

- `S125_EXECUTION_JOURNAL.md`：只追加时间顺序的命令、原始计数、hash、失败事实；
  不写解释性结论。
- `S125_COPY_INVESTMENT_MEMO.md`：只写可回顾的阶段结论、残差、风险、门槛命中和
  下一步；不复制整段流水账。
- 任何 cell 若 invalid，保留 raw，不在 summary 中伪装成 PASS。

## 9. 执行前 gate（当前均需完成）

- [x] S124 plugin 增加上述 stage counters、queue depth、output errno/partial write
      和 HEV runtime identity 导出。
- [x] 修正 `output-copy-bytes` 语义，增加 instrumentation `off/sample64/full`。
- [x] 多 worker 下 output/checksum/TCP-event/control counters 使用原子累计与快照，
      避免跨 worker 的 u64 更新制造假 byte shortfall。
- [x] canonical tuple hash 增加 test-only final mix，避免 Android 偶数 TCP
      ephemeral port 让 workers=2 低位 hash 塌缩到单一 owner。
- [x] 增加 `udp-reflect`、`ingress-only`、`memcpy-cal` test-only modes。
- [x] APK 增加并发 UDP/TCP stress action、barrier、steady/drain、sequence 校验、
      RTT histogram、close/reuse。
- [x] runner 使用 repo-local `./dev/adb`，生成 manifest/raw/resource/simpleperf，
      不依赖人工复制命令。
- [x] 矩阵包含 `full` 时，APK 内必须有 POC-7 HEV TCP metric symbol；包含 control
      arm 时，必须有 `hev_external_driver_poc_plugin.so`。Tier 2 默认强制
      `SIMPLEPERF=1`，避免生成无法判定的半套矩阵。
- [x] `scripts/s125-parse-results.py` 对代表性 raw 做 golden test；`git diff --check`、
      shell/Java/C 编译通过。
- [x] Pinned HEV 应用 `patches/hev-poc7-tcp-copy-timing.patch`，并由
      `android-build-hev-poc7.sh` 生成同时导出
      `flow_stack_owner_tcp_copy_metrics` 与
      `flow_stack_owner_tcp_copy_timing_enable` 的 arm64 library。
- [x] fire-and-count 控制臂固定为 `10000000 ns/packet`，并在真机 ingress-only/
      memcpy-cal 的 w1/w2、observe=off/full 短校准中验证 `enqueue-drops=0`、
      `fatalFlows=0`；VPP handoff dropped-buffer double-free 已修复。
- [ ] TCP full cell 的 `tcp-copy-metric=1`、copy bytes 与 payload 斜率一致；
      否则 TCP 保持 `INCONCLUSIVE`，不能用 `tcp_write_ns` 代替。
- [x] TCP packet-path gate 已在真机短回归通过：每个 gate flow connect/首个 echo
      成功，SYN、SYN-ACK、ACK、data/output-data 事件齐全，IPv4/TCP checksum
      errors 为 0；正式矩阵仍需重复校准。
- [ ] workers=2 且 flows≥8 的 cell 的 owner packet delta 覆盖全部 owner；否则该
      cell 保留 raw 但标为 `worker-distribution-incomplete`，不得用于多 worker
      结论。
- [ ] Tier 0 calibration、resource/thermal guard、correctness、UDP/TCP 代表格
      simpleperf 和 run-summary 全部通过（包括 off vs sample64，以及 TCP
      full vs sample64 均 ≤3%）；否则禁止
      Pixel 正式矩阵。parser 还要求每个注册 key 至少 3 个 valid repeat，并且
      8 个 matched full control key 全部存在；control path delta 必须非负，
      full-observation 的 UDP/TCP payload 33↔1400 copy-byte slope 必须通过。

在以上 gate 全部打勾之前，POC-7 只能保持阶段性 `INCONCLUSIVE`，不应宣称
“copy 已经不是瓶颈”，也不应据此冻结 lwIP、多 worker 或 zero-copy 设计。
