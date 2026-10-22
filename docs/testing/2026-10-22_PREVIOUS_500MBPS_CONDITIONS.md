# 昨日约 500 Mbit/s 的实际达成条件

日期：2026-10-22。回应“昨天 500M 是什么条件，尽量全面”。本次历史调查只读
2026-10-21 的原始 Product 记录，没有设备操作、构建、测试 campaign 或 Product
修改；以下为历史条件与证据的定稿复原。

## 先回答最关键的区别

**昨天确实有普通默认构建、VPP 主线程/两个 worker/下载 helper 均约束在小核
CPU0–3、32 KiB ring/sndbuf、没有定频的约 500 Mbit/s 单条下载流记录。**
它们是 `496.62 / 535.54 Mbit/s`，不是“64 KiB 才能达到”，也不是中核定频的
`470.91 / 480.68`。但旧 helper 同时有 **1 条 bulk 下载连接 + 1 条轻量 echo
probe 连接**；不能叫严格“全程只有一个 TCP connection、无 probe”。

该普通默认构建的角色是 **N2：main CPU0，owner0 + TUN CPU1，下载 owner1
CPU2，helper CPU3**。它不是今天已测的 **N1：main CPU0 / owner0 CPU1 / dedicated-I/O CPU2 /
receiver CPU3**，更不是刚选择的 65,528 B 新默认；昨天成功记录的 ring/sndbuf 是
**32,768 B**。本轮用户选择 64 KiB 级安全档是新的配置决定，不回写成历史前提。

“均小核”也只覆盖这里明确绑定的 VPP 与 benchmark 角色：Java/control/观测消费、
系统后台及 IRQ 并没有全部绑到小核；原始 `/proc/stat` 明确记录了中大核上的
IRQ/softirq CPU 时间。因此不能说“整部手机全靠四个小核做完了全部工作”。

核心证据为下述各 cohort 的 `protocol.json`、实际 `run-*/result.json`、
`vpn-tcp-fixed/{startup.conf,after-cli.txt,*affinity.txt,system-cpu-*.txt,native-stop.txt}`，
不是仅引用旧总结。新索引位于
`build-output/previous-500mbps-conditions-20261022/`。

## 1. 最接近用户所问的普通单流约 500：b92e 默认构建

[冻结协议](../../build-output/vpn-client-placement-default-20261021/protocol.json)
· [四窗 campaign](../../build-output/vpn-client-placement-default-20261021/campaign-result.json)
· [B1 原始结果](../../build-output/vpn-client-placement-default-20261021/run-B1-client-cpu3/result.json)
· [B2 原始结果](../../build-output/vpn-client-placement-default-20261021/run-B2-client-cpu3/result.json)。

| 窗口 / generation | helper 允许 CPU | bulk 源端口 / probe 源端口 | bulk 实际 owner | 20 秒下载 Mbit/s | 小核簇驻留均频 GHz |
| --- | --- | --- | --- | ---: | ---: |
| A1 /2179 | 自由继承 | 31152 /31153 | owner1 | 251.93 | 1.1471 |
| B1 /2180 | `08` = CPU3 | 31156 /31157 | owner1 | 496.62 | 1.3936 |
| B2 /2181 | `08` = CPU3 | 31160 /31161 | owner1 | 535.54 | 1.4794 |
| A2 /2182 | 自由继承 | 31164 /31165 | owner1 | 265.39 | 1.2000 |

每窗是独立普通 VPN lifetime；profiling=false、path_probe=false，无临时逐包
探针。worker 固定 CPU1、2；主线程 CPU0。只对正式测量 helper 使用 `taskset 8`，
并没有永久更改系统/App 的全局放置策略。B1/B2 的 probe 实际属于 **owner0**，
bulk 属于 **owner1**，均从实际 UID2000 FlowEntry 查得，不仅是 hash 推算。

### 精确构建与参数

| 项目 | 昨日普通约 500 的实际条件 |
| --- | --- |
| 设备 | Pixel 6a，`28201JEGR0XPAJ`；CPU0–3 capacity160、小核；4–5 capacity498；6–7 capacity1024 |
| APK | `b92e51202821d64e2a5571dea02998fcee19eaceaa1370e9348e407964a94a78` |
| Product source closure | `8318c4c9eb778517157eff41d52f0743cc1dec97e631eb720d9fa9387986e50c` |
| 构建基点 | `283a9ec9aba3d8fc6430635eae90395a683cdca1`；记录的 dirty diff 为空 |
| Product plugin SHA256 | `65f33fae5451f6218f2c8cd974f2f1d13a088352e0f3316cfae1e2fae2df2f0f` |
| 匹配符号 ELF Build ID | `86d2eba24f483ce759bcc55182b40cf26b42679d`；符号 SHA 与 build.json 相符 |
| 拓扑 | 固定两个 flow owners；main0，worker0/owner0 CPU1，worker1/owner1 CPU2 |
| TUN 归属 | `origin_thread=1`，即 worker0/CPU1，同时承担 owner0；没有独立第三个 I/O worker |
| 下载归属 | bulk owner1/worker1/CPU2，跨线程交给 TUN worker0；probe owner0/CPU1 |
| 内层 MTU / MSS | 10000 /9940；返回 IPv4 IP 包最大9980 B；不是物理 Wi-Fi 帧大小 |
| VPP buffer | virtual-only，2048 个，data10240 B；普通 B1 `show buffers` stride10496 B |
| HEV ring / lwIP TCP_SND_BUF | 各32768 B，ACK 才释放 no-copy ring 字节 |
| lwIP TCP_WND | 32768 B，另一个接收方向的窗口，不是 ring 或 Linux SO_RCVBUF |
| capture | callback read budget64；**submission 是逐包 scalar1**，实际 `tun.capture_batch max=1` |
| primary | 默认每 owner32 packet credits；native queue element 配置64 |
| completion | queue element 配置128；正常 publication/reclaim 窗口16；已有 retry 窗口64 |
| return | 每 owner128 return packet credits / stamp 容量；不是32 KiB 的字节单位 |
| flags | LARGE_SEGMENT=ON；TCP_BATCH / TCP_PROGRESS / TCP_BUFFER 均OFF；UDP_BATCH=OFF |
| 其他 flags | ROOT_BATCH=ON；ROOT_VERDICT_BATCH=ON、packed（旧窗口16）；policy qualification counters=ON |
| HEV driver | cooperative `step(8,200µs)`；不是固定200µs睡眠或硬抢占预算 |
| 规则 | `5bd3d78401ddfa51e162a0167c0413eae6de826b4ecf7ca2d11dfa19c98a7b35`；目标 UID2000，实际 decision=ALLOW/rule0 |

上述 flags/MTU/缓冲来自 **实际 APK 内 `assets/product-stage.properties`**；native
ZIP 成员与冻结 build.json 的12个 SHA 全部对上。实际源文件从该基点的 Git blob
提取，并逐 SHA 对上该 build.json 的 `files`，只取 VPP-native C/HEV 配置，没有
参考被移除的 C++ 或 POC。特别避免把 `PRODUCT_COMPLETION_BATCH_SIZE=64` 误当
旧版正常 flush64：旧 append 的阈值仍为 `PRODUCT_PACKET_BATCH_SIZE=16`。

[构建身份](../../build-output/vpn-client-placement-default-20261021/default/build.json)
· [B1 启动配置](../../build-output/vpn-client-placement-default-20261021/run-B1-client-cpu3/vpn-tcp-fixed/startup.conf)
· [B1 实际 CLI](../../build-output/vpn-client-placement-default-20261021/run-B1-client-cpu3/vpn-tcp-fixed/after-cli.txt)
· 新 `selected-conditions.json` 的 `artifacts` / `sourceproof` 保留完整 native、符号、
源 SHA 与历史源快照。

### 业务流、预热和亲和性：旧记录真正证明了什么

- 数据方向是 Host server 持续发送，Pixel helper `recv` 计有效 bulk 字节：真实 `D`
  下载，不是上传或 echo 字节冒充下载；bulk 的 echo probe 字节不计入下载 bytes。
- `threads=1, flows_per_thread=1` **不等于只有1条 TCP 连接**。冻结源 SHA
  `99bd217bef6171bc03bd2d0d88497e49fe767a598c120095c46244f7f330a690`
  的 `tcp_worker` 明确 `total=flows+(mode==0)`：1 条 D + 1 条 E；E 每次回复后约
  20ms 再发。B1/B2 实际 attempts=offered_connections=2，latency_samples=438/450。
- Host `192.168.4.5:41722`；Pixel Wi-Fi 地址192.168.4.151，虚拟 TUN 地址10.111.0.2。
  B1 实际 FlowEntry 为 `10.111.0.2:31156 →192.168.4.5:41722`、UID2000/owner1；
  `31157` 是 probe/owner0；B2 对应31160/31161。
- 每窗先单独执行 **250ms，2 helper threads ×8 bulk +2 probe** 的 warmup，返回并
  join 后再取 before CLI、启动 monitor、执行正式20s helper。预热 bytes 不混入
  正式 bytes，20s 内仍包含新连接建立；不是建立完成后再量20s。
- 旧 warmup 没套正式 helper 的 `taskset 8`；旧 UID/peer proof 是随后 CLI 中的
  FlowEntry。它不是今天改进后的“2s live warm、运行中采 UID/peer、join 后开窗”流程。
- B1/B2 `client-affinity.txt` 的确是 `Cpus_allowed=08 / Cpus_allowed_list=3`，
  **08 是单独 CPU3，不是 CPU0–3 的集合 mask**。它是 exec 前 shell 的实测亲和性；
  helper 不修改 affinity，pthread 继承该约束，支持其 receiver 被限制在 CPU3。
  但普通窗没有保存运行中 receiver TID 的独立 `/proc/.../task/TID/status` 或 processor
  快照；只另外记录了 receiver TID23883/24391。不能升级为今天逐 TID 实测同等级证据。
- VPP worker 的实际 lcore 和 `worker-0/1-affinity.txt` 对上 CPU1/2；main-core0 也在
  startup/show-threads 与系统快照中。未证明其他 App/control/observer 用户线程全小核。

[冻结 collector](../../build-output/vpn-client-placement-default-20261021/collector.py)
· [helper 构建与源码 SHA](../../build-output/vpn-path-scheduler-20261021/helper-build.json)
· [B1 warmup](../../build-output/vpn-client-placement-default-20261021/run-B1-client-cpu3/vpn-tcp-fixed/warm.json)
· [B1 client-affinity](../../build-output/vpn-client-placement-default-20261021/run-B1-client-cpu3/vpn-tcp-fixed/client-affinity.txt)。
新目录中的 `socket_load-99bd217bef61.c` 按上述 SHA 从历史 Git blob 恢复，只读分析。

### CPU、拒绝和结束状态

| 普通窗口 | VPP 总% | worker0/TUN CPU1% | worker1/bulk owner CPU2% | helper CPU秒（另计） |
| --- | ---: | ---: | ---: | ---: |
| B1 /2180 | 135.16 | 61.79 | 73.32 | 6.594721 |
| B2 /2181 | 136.66 | 62.46 | 74.09 | 6.691126 |

100%=一核；main 另有约0.05/0.10%。VPP raw CPU为26.62/26.91s，覆盖19.6950/
19.6914s，不能把它当与20s bytes 完全同界的整窗精确 CPU。helper 约33%一核，未含
入 VPP 总数。RSS 峰值115466240/115339264 B。不同吞吐、helper/probe、拓扑和频率
下，不据此与今天 N1 总 CPU约95%直接作纯绑定或同速效率比较。

两个普通成功窗 before/after CLI 的 credit/enqueue rejects、policy/runtime drops、
TUN errors/rejections/write failures 均0，native stop 的 pending/buffers/frames/
obligations 全0；client errors/timeouts 均0。**不等于 TCP 重传或物理网络丢包0**：
helper 未采 TCP_INFO/重传。lifetime health 中仍有 warm/background CONNECT_REFUSED，
不能把整个 generation 所有健康事件一概称为无错；上述目标流正常且相关 timed-bracket
Product drop/reject 为0。[B1 stop](../../build-output/vpn-client-placement-default-20261021/run-B1-client-cpu3/vpn-tcp-fixed/native-stop.txt)
· [B2 stop](../../build-output/vpn-client-placement-default-20261021/run-B2-client-cpu3/vpn-tcp-fixed/native-stop.txt)。

## 2. 503.10 /504.62：诊断探针构建，不能与普通默认混为同一 APK

[协议](../../build-output/vpn-path-client-placement-20261021/protocol.json)
· [campaign](../../build-output/vpn-path-client-placement-20261021/campaign-result.json)
· [逐包汇总](../../build-output/vpn-path-client-placement-20261021/path-summary.json)。

| 窗口 /generation | helper | 20s Mbit/s | 独立1s trace Mbit/s | TUN write wall /非线程时间 µs | 回程至 ACK 完成 µs |
| --- | --- | ---: | ---: | --- | ---: |
| A1 /2173 | 自由 | 153.71 | 126.35 | 241 /130 | 1692 |
| B1 /2174 | CPU3 | 503.10 | 494.79 | 42 /1.1 | 375 |
| B2 /2175 | CPU3 | 504.62 | 542.50 | 37 /1.0 | 344 |
| A2 /2176 | 自由 | 103.38 | 87.82 | 282 /153 | 2020 |

相同 N2/workers1、2、bulk owner1/TUN worker0、32KiB、MTU10000 和 CPU3 条件，
但 APK 为 `0c84921daf3ac78d00efeea0ea5a6f8c93a2d334bdacaf861fa528f7b6fd1883`，
source closure `a3737344b0f5ac3bdf9f154bf93e2bcb77ba88fe9899ee34f02ff9a2eeca5975`；
**TCP_BATCH=ON、TCP_PROGRESS=ON、TCP_BUFFER=OFF**，并有临时 path probe。
plugin SHA `f97db6eb56c821b4e3d636b6dd02054a1713ff92ccaaf1c68df4fc7bf9d1e61e`；
符号 Build ID `06e6902fb83b89325a8ef3d3cd6f0c18d5d437ad`。

正式20s窗口不跑 simpleperf，但在第8秒后开1秒预分配逐包 trace gate（每owner
65536条记录），所以不称“完全没有探针”。trace 和 whole-window 吞吐都原样保留，
542.50不是 B2 的20s平均。源端口31128/31132/31136/31140；B1/B2仍是1D+1E，
旧 helper SHA a2132783… 使用源码980f426d…，尚未输出 receiver worker_tids。

两 B 窗小核簇均频1.38855/1.40358GHz；不是1.803GHz定频，亦不是普通 B 窗的
1.39363/1.47936GHz。client affinity 证明级别与普通窗同样是 exec 前 singleton mask。

另两窗 FP/off-CPU 机制记录使用同32KiB探针 APK，关闭逐包 probe、加独立 profiling，
吞吐138.23/387.62 Mbit/s。实际 receiver TID21775/22523已从新 helper输出取出：
自由窗41706次 TUN-path切出，其中41538次下一线程正是该 receiver；CPU3窗107次、
下一线程为 receiver 的0次。两个 profile lost0、匹配 ELF；它们证明旧慢场景中的
调度耦合，而不能把138/388代入无 profiling 的154/503/505。

[实际 TID/切换原始分析](../../build-output/vpn-path-scheduler-20261021/scheduler.json)
· [机制协议](../../build-output/vpn-path-scheduler-20261021/protocol.json)。off-CPU区间还可能
含其他任务，不把整段时间都记给 receiver，也不照搬该因果到今日新拓扑。

## 3. 定频到底在哪些窗口使用过

新 [frequency 重算](../../build-output/previous-500mbps-conditions-20261022/frequency-conditions.json)
直接从14窗 before/after residency 与 guard receipts 计算，未借用后续默认值。

### 普通/诊断小核约 500 窗口：没有强制定频

B1/B2 的小核 residency 分布横跨10–11个频率档，不是固定1.803GHz。协议/campaign
没有调用 frequency guard；policy0 最大档1.803GHz驻留分别只有：普通3.54%/4.84%，
诊断3.54%/4.21%。普通 B 的中核簇平均仅0.4318/0.4362GHz，诊断0.4374/0.4393GHz；
不能把中核均频当小核频率，也不能由低均频说中核没有执行工作。

这些成功 cohort **未逐窗保存 governor/scaling_min/scaling_max 的完整快照**。
相邻有 guard 的记录直接显示 `sched_pixel`，policy0原min/max为300000/1803000kHz、
policy4为400000/2253000kHz；不能冒充普通 B 每窗都重新实测了相同配置。温度在这些
cohort 的已保存快照/receipts中**缺失**，无法声称 thermal-equivalent 或无温控影响。

### 中核定频接近链路控制：470.91 /480.68

[独立协议](../../build-output/vpn-diagnosis-default-frequency-20261021/protocol.json)
· [summary及直连 bracket](../../build-output/vpn-diagnosis-default-frequency-20261021/summary.json)。

- 同普通 b92e APK、32KiB、1D+1E、20s、无 profile，但 **workers 在 CPU4/5 中核**；
  bulk owner1/CPU5，TUN owner0/CPU4，main0；helper自由继承，未限定 CPU3。
- 仅把 policy4 的 minimum 从400000提高到原maximum2253000kHz；maximum、governor、
  thermal 控制不改。每窗有45s设备端 FIFO watchdog，结束恢复原 min/max/governor，
  所有有效窗 watchdog_expired=false。
- 两窗 policy4 residency **100%在2253MHz**；小核仍动态，约1.348/1.347GHz均值。
- 两侧恢复设置后的原生直连分别484.28/510.28 Mbit/s；VPN均值475.79、直连均值
  497.28，约95.7%。这是有限时间 bracket，不是硬上限或生产绑核方案。

**这不是全部小核的500证据。**

### 小核/中核最低频率干预：不是“定到最高就必达500”

[frequency-v2协议](../../build-output/vpn-diagnosis-frequency-v2-20261021/protocol.json)
· [combined协议](../../build-output/vpn-diagnosis-frequency-combined-20261021/protocol.json)。

在另一诊断 APK、workers固定1/2、bulk owner1、helper自由继承的条件下：

| 仅改变频率条件 | Mbit/s | 重算实际 residency |
| --- | ---: | --- |
| policy0 min提升至原max1803MHz | 372.27 | 小核100%在1803MHz，中核仍动态 |
| policy4 min提升至原max2253MHz | 263.39 | 中核100%在2253MHz，小核仍动态 |
| 全部恢复，自动调频 | 161.79 | 小核约0.830GHz |
| 两簇 min都提升至各自原max | 355.54 | 小核1803/中核2253MHz各100% |

不能把这些未固定 receiverCPU3 的诊断窗，与后来的普通CPU3成功窗合成“只差频率”
A/B。它们证明频率会参与影响，不证明全部差距由主频决定；组合收益也不相加。

## 4. 64条 bulk 的约500：另一类负载，不能代替单流证据

原 helper 每 thread另开1条probe，所以 `4 threads×16 flows` 实际为
**64 bulk D +4 probe E**。未固定源端口的早期窗还存在 tuple/owner分布漂移。
各窗都是20s、独立VPN lifetime，端点bulkbytes不含probe echo bytes。

| 组别 | 20s Mbit/s | 关键条件 /不能混同的地方 |
| --- | --- | --- |
| MTU10000默认 smoke /2106 | 519.32 | TCP_BATCH/PROGRESS OFF，32KiB；**有199Hz profile**；APK571de18c…，不是b92e |
| MTU3000/10000同池 ABBA 的10000侧 /2108,2109 | 516.49 /526.54 | batch/progress ON，2048×10240虚拟池，32KiB；有profile；不能和默认smoke拼均值 |
| capture64控制 /2111,2114 | 505.13 /519.52 | batch/progress ON、primary32/queue64；有profile |
| capture16候选 /2112,2113 | 489.92 /487.87 | 降读预算减少拒绝但未提速；未采用为默认 |
| helper自由/CPU3/CPU3/自由 /2116–2119 | 507.65 /502.01 /521.34 /519.54 | **64D+4E**，有profile；CPU3并没有带来吞吐增长，不能拿它否定后面单流因果 |
| primary32/48/48/32 /2120–2123 | 515.35 /539.72 /533.33 /516.31 | 只改credits；native queue槽位没改；各窗仍有credit拒绝 |
| single-poll G/H/H/G | 519.89 /524.19 /514.51 /516.97 | 相同插桩，external poll guard的独立干预；不是单连接 |
| ACK通知过滤 J/K/K/J | 516.37 /507.90 /501.90 /520.22 | 独立候选，未有整体收益而撤回 |
| 直连/VPN/直连重启控制 | 545.77 /526.48 /524.08 | 同网络/helper；中间VPN无profile，原生两侧停止VPN；说明约500也会出现在非VPN链路控制 |

[MTU阶段原始campaign](../../build-output/vpn-mtu10000-20261021/campaign-result.json)
· [capture组](../../build-output/vpn-progress-20261021/campaign-result.json)
· [affinity组](../../build-output/vpn-progress-20261021/affinity-campaign-result.json)
· [credit组](../../build-output/vpn-progress-20261021/credit-campaign-result.json)
· [single-poll组](../../build-output/vpn-wait-cause-20261021/campaign-result.json)
· [ACK组](../../build-output/vpn-ack-wake-20261021/campaign-result.json)
· [直连bracket协议](../../build-output/vpn-diagnosis-reset-20261021/protocol.json)。

64流的约500不能解释当时单bulk仅137.40（同日单bulk直连537.86）的差距。大MTU
早期窗亦有 primary credit拒绝及个别OUTPUT_CAPACITY，吞吐不等于完整策略Q或无丢包
资格。例如516.49/526.54两窗primary拒绝3655/4622，但返回credit/stamp/buffer不足0；
后面的539.72/533.33也仍有2383/1888 credit拒绝，enqueue拒绝0。它们没有证明所有
数据通路故障/拒绝消失。

## 5. 原生链路、硬件和缺失观测

- 受控server绑定PC `192.168.4.5`，上述后期单流统一端口41722；peer exe/argv/PID/
  binary SHA留存在每个 `peer-identity.json`。当日报告明确记录PC使用网线；保存的
  `host-adapters.json` 是空文件，本次不能由它独立重核物理网卡状态，故不额外臆测
  Host网卡/交换机/AP型号或以太网速率。
- 重启诊断preflight直接保存：Pixel连 `Openwrt_5G`、5GHz5180MHz、11ax、RSSI−52dBm、
  IP192.168.4.151；reported link1729Mbps、Rx link2401Mbps。这是preflight点，不是
  每个后期单流窗的逐秒无线条件；不把PHY link速率当实际TCP带宽。
- 普通CPU3成功组紧邻的 **直接507.15**：VPN停止、同peer、同旧helper、CPU3，20s，
  仍是1D+1E；不是今日0-probe helper的直接基线。另一次单bulk直接537.86、固定源端口
  helper直接531.99、独立Python server+toybox nc直接514.21，是不同cohort/工具。
- 旧 `vpn-tun-io/campaign2` 还保留509.71/509.80的不同直接helper控制；不与b92e或
  主表原生控制合并。全部保留在新20s目录索引，不为复现500挑最高结果。
- 64流早期没有现今同等级的逐窗频率、温度、实际receiver TID/affinity证据；不倒填。
  用户若要求下一轮固定频率，这应新冻结，不是“照昨天500的已固定频率值”。

[原生507.15原始结果](../../build-output/vpn-path-final-20261021/direct-cpu3/result.json)
· [preflight无线快照](../../build-output/vpn-diagnosis-reset-20261021/preflight/result.json)
· [实际server身份](../../build-output/vpn-client-placement-default-20261021/peer-identity.json)。

### 中大核实际参与：已有反证，不能说整机全小核

普通B1/B2 system-bracket 中，CPU4+5合计 IRQ+softirq CPU 时间约12.02/12.60s；
CPU6+7合计约2.73/2.93s。诊断B1/B2相应约11.98/11.87s和2.65/2.74s。
这些是外层快照区间的累计执行时间，不是某一条flow的成本，也不是中大核频率被
固定。它们证明有小核外 interrupt-context工作，**但缺每CPU softirq类别/设备IRQ
映射，不能直接全部归给Wi-Fi NET_RX**。也没有证明全部Product Java/控制线程CPU0–3。

频率均值含idle、共享policy与后台；system快照/采样/CLI有不同bracket，不能拿它们
填成精确20s整机CPU账本。没有温度数据就不声称热条件相同；没有TCP_INFO/RTT、
重传、receiver活跃亲和快照就保留这些缺口。

## 6. 32KiB扩容反例与真正的旧因果证据

在503/504以前，同source/worker1、2、owner1做过
**32768 /65528 /65528 /32768 B** 的诊断反事实：

| ring/sndbuf | 20s Mbit/s | 独立trace Mbit/s | trace回程至ACK处理均值µs |
| --- | ---: | ---: | ---: |
| 32768前控制 | 159.22 | 151.77 | 1414 |
| 65528第一次 | 134.73 | 129.70 | 2986 |
| 65528第二次 | 136.01 | 142.85 | 2728 |
| 32768回切 | 149.91 | 135.20 | 1590 |

[逐包原始汇总](../../build-output/vpn-path-buffer-v2-20261021/path-summary.json)。这不否定
用户本轮选择65,528B；它只说明**历史500的必要条件不是扩容**，而“满ring”本身也不能
证明扩容会提速。实验中扩大flight/排队未改善那个旧慢场景；自动频率仍变化，不能
推广为所有环境容量都无关。

旧单bulk证据较强的因果链是：保持workload/worker/APK/ring，只改变receiver放置，
20s吞吐、逐包TUN非线程时间/串行frame等待与ACK回路同时改变；随后用准确receiver
TID的off-CPU记录证实旧自由调度窗常在TUN write途中切到接收线程。**频率也随放置
变化**，所以不能把全部改善只记为纯context switch成本，更不能把其因果无验证地
迁移到今天独立I/O的新路径。

## 7. 可复现旧普通500的清单，以及与当前测量的精确差异

这里的“复现”是可审核的旧条件清单，不保证不同时间无线环境必重现同一数字，也
不是本轮允许启动设备campaign的指令。

1. 用精确 **b92e APK** 及其native/source/flags，保持32,768B、默认scalar capture1、
   primary32、normalcompletion/reclaim16、retry64、nativequeues64/128；不能用今天
   新默认65,528或unified64冒充同artifact。
2. N2，main0、owner0+TUN CPU1、owner1 CPU2；目标bulk端口31156或31160、peer41722，
   确认实际UID2000/owner1，probe是base+1/owner0；helper整个process通过mask08限CPU3。
3. 用冻结Android helper5321c45d…、host helperebac6c3f…和旧250ms warm流程；正式
   1D+1E、20s。保留不同端口而不是在TIME_WAIT时悄悄随机替换；旧collector未采用
   今日固定120s端口wait门，不能倒称已通过新门。
4. 使用同规则SHA5bd3…、Openwrt_5G、同Host与服务身份；记录新一轮实际无线/温度/
   residency。昨天普通成功组未强制定频；若按用户现在要求固定小核频率，应标成
   **新实验条件**，不要声称是复制昨天定频。
5. 核对完整bytes/单调时钟、worker与helper约束、probe数、background/lifecycle错误、
   drop/reject/retry、逐generation零债stop。原生控制要同helper/CPU/连接数，不混另一个
   0-probe/多流或不同时间的最高值。

| 项目 | 昨日普通约500 | 今日已测单bulk全小核窗口（fbb5…） |
| --- | --- | --- |
| flow owners /I/O | N2；owner0同时是TUN lane | N1；I/O独立且不作flow owner |
| 主/数据角色 | main0，TUN+owner0 CPU1，bulk owner1 CPU2 | main0，owner0 CPU1，I/O CPU2 |
| receiver | mask08限CPU3；旧证明级别见上 | 主/receiver实际逐TID allowed_list3及processor3 |
| bulk /probe | 1D+1E；probe在另一个owner0 | 1D+0E，0 latency samples |
| tuple/peer | 31156或31160→41722，bulk owner1 | 31000→41723，唯一owner0 |
| 预热 | 250ms，2×8D+2E；结束后UID/peer CLI | 2s live UID/peer门，join后开测 |
| capture /normalpublication | scalar1 /16 | capture64 /unified64，ready部分不等满 |
| primary credits | 32/owner | 48/owner |
| HEV ring/sndbuf | 32768 B | 该已测artifact仍32768 B；新65,528默认不在此旧测量中 |
| MTU/MSS /buffer数据 | 10000/9940 /10240 B×2048 | 相同这些值；不是隔离其他差异的保证 |
| 规则 | 5bd3d784… | 2b24ea263… |
| source/native | b92e /65f33fae…；旧getenv/topology路径 | fbb5 /798c1f42…；immutable topology及新return调度 |
| 频率 | 动态；B1/B2小核1.394/1.479GHz驻留均值 | 动态；三轮约1.341/1.353/1.358GHz，bracket不同 |

所以不能直接把今天约310–327与昨日约497–536称为某一个参数的回归，也不能由
昨日500推断今天开64KiB、定频或排列核之后必达500。用户已选的新缓存默认与后续
小核定频/排列组合资格，应分别保留新artifact和实验身份。

## 8. 新证据索引、范围和交付

- `selected-conditions.json`：普通4窗、逐包诊断4窗、中核定频2窗的原始关键字段、
 90个输入SHA、2套实际APK/native/ELF、精确旧C源码SHA匹配与快照。
- `frequency-conditions.json` / `frequency-findings.md`：14窗频率/中大核IRQ执行重算、
 104个输入SHA、完整8核字段和原始时间bracket；脚本 `frequency-recompute.py` 可离线重跑。
- `all-20s-records.json`：扫描同日命名Product VPN/direct目录得124条20s tcp-fixed记录的
 路径、client bytes/interval、flows、profile、artifact等字段及result SHA。它是目录索引，
 **没有把不同cohort合并估计**；含慢控制与失败/不完整状态，不能当124个资格PASS。
- `socket_load-{99bd217bef61,980f426dd189}.c`：按manifest SHA核对的历史纯C helper源码；
 `ordinary-source-283a9ec9/`只保存匹配普通build manifest的VPP-native C与HEV配置。

旧raw、protocol、报告、APK、symbols未修改；新raw索引与历史符号/APK仍是本地
 gitignored证据，没有可移植archive。本文为历史复原的定稿证据；新65,528B默认配置
另见[本地实现与验证](2026-10-22_TCP_SEND64_DEFAULT.md)，其资格限于本地验证，未新增
设备性能量测，不代表新64KiB级默认已测得500。
