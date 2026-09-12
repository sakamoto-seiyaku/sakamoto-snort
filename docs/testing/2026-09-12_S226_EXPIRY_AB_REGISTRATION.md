# S226 — Flow expiry 驱动 A/B 预注册

状态：REGISTERED，结果尚未采集。登记日期 2026-09-12；父任务 S199。
本项只选择 FlowRuntime 的 wake contract，不是 S248 全局 packet-wake 性能评选、
完整 S227 production scheduler、续航声明或发行验收。

## 1. 固定实现与两臂

基线 commit `34267e03ac4c1e9fbcd75ecfa2837546dfd2bf35`；两臂必须使用同一份
本项 source closure 构建的 Linux 插件／Pixel APK。build.json 保存完整 source/dirty
files、pinned VPP、native、APK 与 helper hashes；runner 冻结本登记文件及源文件。
测试前再记录实际安装／运行的 hash，不能混用 S225/S234 的旧 artifact。

共用一个 owner-local FlowRuntime、预分配 indexed binary min-heap、UDP tracker、
独立原生 END buffer、共享 consumer 与 native free callback。每个 slot 至多一个 timer；
heap 容量等于 entry 容量，refresh 原位重排，不积攒 stale timers。选择此候选做比较，是
因为 peek O(1)、更新/删除 O(log N)、空间固定，且 deadline 缩短无需扫表；本项不宣称
它比所有 timer wheel 都快。两臂不比较不同容器。

- A：`product-flow-expiry-experiment` 常驻 POLLING input node，无到期工作时快速返回。
- B：相同节点为 INTERRUPT，已有 VPP per-worker file polling 接收 one-shot timerfd；
  仅通知当前 owner。空表 disarm，下一次唤醒对齐最近 deadline。
- 相同 work pacing：每 owner 每次最多 100 个 END；做过一个 batch 后至少隔 100 ms
  才运行下一 batch。两臂检查同一个 `max(nearest_deadline, next_budget_time)`，
  不持续 self-requeue，不设全局 timer thread，不改变 packet wake patch。
- fork 的 1000 ms 扫描周期只作参考，不作为本实验常量。这里将相同 next-check 时点
  固定在两臂，使比较只改变 wake/执行驱动，而不是悄悄让一臂更早检查或预算更多。
- 实验入口默认关闭，必须显式选 arm、active generation 与测试 UDP 端口。
  实验只给匹配端口的真实 UDP entries 挂定时；不会制造 flow、变造 packet 时间，
  或触碰其他应用的 flow。初始化由各 owner 自己执行；控制面只发布配置。

UDP 使用 pinned OVS `3c2bea086ef8912d57331173af266f21d36740a0` 的真实默认值：
FIRST/MULTIPLE 60 s，BIDIR 30 s；deadline 为最后一次有效 observation + 默认 timeout。
不为批量同步、测试加速或驱动容差延长/缩短协议 timeout。不发包的期间仍须自然到期。
lookup 在 deadline 已过时先正常 END，再尝试新建；旧 END 占槽时不能覆盖旧 entry。

## 2. 固定设备和环境

Pixel serial `28201JEGR0XPAJ`，bluejay，Android 16
`google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`，
kernel `6.1.134-android14`。Root 原生 Product artifact，W2/Q4，main CPU 0、workers
CPU 1/2；记录每个实际 TID 的 affinity。Root/VPN App 测试前停止，不清 app data。
只安装测试专用双栈 loopback INPUT/OUTPUT NFQUEUE rules；结束删除自己的规则、地址、进程。
Linux 为独立 rootless network namespace 的真实 UDP sockets + NFQUEUE，同一插件 source；
W2 固定本次启动的实际 affinity 并记录。不是 host graph injection。

Pixel USB 保持连接，100% 充电状态保持；不写 battery override、charging sysfs、CPU governor
或频率锁，不关闭别的 app 来美化结果。配对之间要求相同屏幕状态、供电状态、thermal
status 0；电池温度起点 25–35°C，每对起点温差 ≤2°C。thermal status 非 0 或终点温度
>38°C 的测量无效，保留原始数据；每个无效 pair 最多重做 2 次，否则 HOLD。
测试期间不运行其他构建／ADB 轮询；待测窗口只在端点前后采样。

板载 `/sys/bus/iio/devices/iio:device0/energy_value` 提供 CPUCL0/1/2 累计能量。
只读起终点差；三个 CPU rails 的和作为主能量指标，MIF/INT/SLC 与另一个 PMIC 分列。
单位和格式来自 [Google ODPM driver](https://android.googlesource.com/kernel/google-modules/soc/gs/+/204078758737776959ecc85c527a00fd2cabb62f/drivers/iio/power/odpm-whi.c)：
时间为 ms、累计值为 µW·s。该 source 用于计数器格式，不声称独立验证设备传感器校准。
USB 电池电流/charge counter 只记录环境，不作为整机能耗。ODPM 不是整机续航计。
计数器不可读、倒退、rail 名称变化，或不能得到有效配对差，能量结论 HOLD。

## 3. 固定矩阵与时长

每个 case 两臂各 3 次，配对顺序固定 AB、BA、AB。停止当前 generation 后启动下一臂，
保持同一 artifact。每个窗口前至少 10 s 安静期；两臂控制／采样方式一致。

| case | 每 owner 的测试 flows | idle/观测窗口 | 含义 |
| --- | ---: | ---: | --- |
| empty | 0 | 60 s | 空表、屏幕亮，无测试报文 |
| long | 2 | 前 45 s idle，继续至 65 s | 仅 ORIG 的 FIRST 60 s，无续期 |
| bulk100 | 100 | 最后发包后 40 s | 双向 UDP，30 s deadline |
| bulk1000 | 1000 | 最后发包后 40 s | 同上，大 batch |
| maximum | 4096 | 最后发包后 45 s | 配置容量 4096/owner 的满容量批量 |
| screen-off | 2 | 65 s | FIRST 60 s，屏幕关闭、供电不变 |
| forced-doze | 2 | 65 s | 同上，显式 force-idle；真实状态另记 |

两种 IP family 各占每个 owner 的一半，owner 用独立 typed-key oracle 选元组。
长 deadline idle 统计仅用前 45 s，之后的到期处理不能污染 idle 统计。
bulk 的实际 deadline spread 必须记录；同一 owner 的 spread ≤1 s 才归为同批压力。
若最大 case seed spread >1 s，仍记录为分散到期功能证据，但最大同批门槛不算通过。
不把“最后一个 deadline 后很快清完”替代每个 entry 从自己 deadline 起计的延迟。

4096/owner 是本轮启动容量上限，不是手机物理极限或正式产品容量。
开始 maximum 前要求 MemAvailable ≥512 MiB，整个测试 RSS <256 MiB、无 allocator failure、
无 flow capacity bypass；预算无法满足则 maximum 为 HOLD，不调低后冒称通过。
每个案例使用相同正常 VPP buffer pool，不能使用 S234 的 512 小池。

Linux 重复 empty、long、bulk100、bulk1000、maximum 各一对（A/B），相同 timeout 和预算。
Linux 能量不参与 Pixel 决策；真实端点 functional/latency、FlowEnd 与 stop residue 必须通过。

## 4. 统计端点与门槛（结果后不修改）

每条 expiry 延迟 = owner `vlib_time_now` 微秒域的 **entry 完成 release** − 同 entry 的
deadline。必须来自 native free callback 调用 FlowRuntime release 成功之后；记录
generation/owner/slot/incarnation/class，和 seed snapshot 一一对应。node called、unlink、
END allocated 不算 release。统计采用 nearest-rank p50/p95/p99，并报告最大值和样本数。

正常负载是每 owner 同时到期 ≤100、无其他测试流量的 case：p99 ≤1100 ms、max ≤1500 ms，
目标约 1 s；这包含 100 ms 实验预算间隔及实际 graph 回收，而非硬实时保证。
bulk1000 要求各 owner 最老 overdue ≤2000 ms，maximum ≤6000 ms；两者全体 entry
release 分别在最早 deadline 后 3 s/7 s 内结束。记录每 batch 数量、剩余 timer、下一
deadline/oldest overdue、全部清空时间，不能拿平均数掩盖尾部。

screen-off/forced-doze 独立报告 CLOCK_MONOTONIC 与 CLOCK_BOOTTIME、系统 idle 状态和
release 延迟。观察窗口内没有 suspend 差时沿用正常负载门槛；发生真正 suspend 时
只要求恢复执行后 ≤1500 ms 清理在该 monotonic 时间域中已经到期的 entry，另列暂停长度。
CLOCK_MONOTONIC 不计 suspend 的时长；本项不把 suspend 期间的墙上时间算成该域的 overdue。
强制 Doze + USB 不等于
证明了拔线深睡，不能据此承诺休眠中的硬实时到期。

correctness 全部 case 要求：无真实 packet 期间主动到期；每个 seeded instance 恰好一个
EXPIRED END 和最终 release；每 batch ≤100；间隔 ≥100 ms；无 peer mutation；
捕获包 completion 原 identity 唯一结算；最终 timer/entry/pending-END/packet obligation
均为零；停止后测试 hooks/queues/fds 清零。任何实际 fatal、丢失 END、提前释放、stale
generation mutation 都是 NO-GO，不把 OS reclaim 冒充正常 expiry。

idle 指标：原生 VPP 全进程 CPU-seconds/window（100%=一个核）以及各 worker 单独值；
`/proc/.../schedstat` 或 stat ticks 为原始来源。记录 voluntary/nonvoluntary context
switches、VPP worker sleep/notification counters（若该 artifact 暴露）、expiry timerfd
read wake 数与 node calls。context switches 标作代理，不能冒称硬件 wakeup 数。
graph loop/节点 calls 与 CPU 同报：忙转不睡的 A 不能凭“timerfd wake=0”宣称更省电。

生产选择候选必须同时满足：

- 所有适用两平台 correctness/latency 门槛通过。
- Pixel empty/long 的每个有效 idle 窗口原生 VPP 总 CPU ≤5% 单核，两个 worker 合计 ≤2%。
- empty 的 expiry timerfd wakes=0；long 前45 s不得有 expiry timer wake 或 END；
  每个 quiet window 中 voluntary context switches 增速 ≤20/s（两 worker 合计）。
- 在 empty 与 long 的各 3 个有效配对中，候选三个 CPU rail 能量总和的平均功率均比另
  一臂低至少 20%；同时把逐对比值、均值和范围完整报告，不只选择最有利的样本。
  此项以相同 USB/屏幕/温度条件下的相对计数器证据选驱动，不量化电池续航收益。

只有一个候选通过上述门槛时选它；均不通过、证据不完整或能量差没有稳定满足门槛为
HOLD，停下审视而不是选“失败较轻”的臂。若两候选都符合各自绝对门槛，以满足逐对
能量优势者决定；不存在可靠优势仍 HOLD。本登记不替 S248 接受任何全局 packet-wake
性能变化。后续 S227 只消费本项明确选中的 owner-local wake contract。

## 5. 必须保留的证据

source/APK/native/VPP/helper hashes；设备/kernel/CPU affinity；完整 launch configuration；
独立 endpoint nonce 和真实 NFQUEUE ledger；seed entry/UDP phase；每个 deadline/release；
expiry/node/thread/runtime counters；energy raw readings、thermal/battery/display/Doze；
process CPU/context stats；MemAvailable/RSS/native pool；stop/drain residue；失败与无效尝试。
普通 packet trace 保留默认前 256 个的完整 identity ledger；大批量不为逐包日志放大热路径。
超出样本的捕获／唯一 completion 使用原生累计 ledger、每条 flow 的双向计数与全部独立
endpoint nonce 相互核对，并明确是全量守恒加有界 identity 样本，不伪称逐包日志全覆盖。
runner 只采集 RAW_COMPLETE，独立 verifier 决定 PASS/NO-GO/HOLD，并用语义负向数据
验证它会拒绝缺 END、伪到期、改 owner/gen、放宽门槛、错能量、资源残留等。

## 结果

待本登记固定、实际 artifact 部署和采集后追加；不得回改上述门槛。
