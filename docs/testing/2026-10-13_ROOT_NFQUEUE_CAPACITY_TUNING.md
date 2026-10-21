# Root NFQUEUE 容量、节奏与实际分流对照

日期：2026-10-13。Pixel 6a，普通 Android Root/NFQUEUE、实际 IPv4 LAN；继续被上一会话服务端流式错误中断的通用调参实验。只使用现有 VPP-native C 主线及 generation 级诊断入口，不修改系统 sysctl、driver、GSO、默认 hook 或产品默认参数。

**37 个预注册窗口全部执行，37 次正常停止清理全部通过。组合 Z 的一个 16kpps 档窗口通过完整策略、交付、顺序和内核守恒检查，实际 payload 15,866.85pps / 152.32Mbps；另一个 Z 窗只因 2 个 native 成功包不计入 Q 未通过严格 100% 资格。未证明稳定容量或整体 CPU 优势。**
默认 A 的两个 8kpps 锚点都通过。所有单项 16k 调参、32k/64k 压力点和 TCP 窗均未通过完整资格；TCP 的 M/Z 测量窗实际只承载于一条 lane，没有双 lane TCP 性能结论。

## 冻结协议与身份

同一个 APK `4acc6ddf5177c9a3829b645a46a909af56a5a7d2222d0ab37792b5a35693cec9`，Product 源码闭包 `b6b43fa118591bbf7c4c6d511b439c7b7f0dec12f42e7129c3fb5e27c5593f24`。对应 unstripped 插件重新 strip 后与安装载荷逐字节一致；37 个 record 的 APK/plugin Build ID 和原始数据 SHA 均核对。安装期间保留 UID12632 和 KernelSU grant。

每窗 6 秒、预热 1 秒、固定排空 1 秒；W2，producer mask9（CPU0/3），4 线程 ×16 连接，UDP payload1200B、global burst16。16k 的 A/P/C/R/T/S/B/Q/M/H/Z 顺序及其逆序在首窗前冻结，随后固定 32k A/P/M/Z、64k A/M/Z、TCP A/M/Z 与逆序、最后 8k A。总上限 37，无替换、无重采样、无根据结果追加采样。generation2018–2054 各自独立启动；原生退出、队列与 hook 不存在后才 force-stop 测试 app，下一窗重新启动。

默认 A 为 normal/pending64、credits32、read budget64、socket effective327680B、maxlen1024、原队列平衡。ring 深度及 Flow 每 worker1024 均固定；P/C/Z 的诊断资源扩张明确属于不同容量配置，不当作原固定预算 batch 规格的默认采用验收。flags9、trace0、packed origin window16、规则 revision969 及两条实际适用 ALLOW 的身份固定。

**双 lane 是实验连接的固定、对称 source-port 分类**：UDP 32000–32031 → queue176，32032–32063 →177，probe 范围亦分列；只在当前 generation 的产品链和原 UID/地址范围内插入。不是通用生产分流器或默认 NFQUEUE 地址 hash 的改变。实际 lane0/1 增量同时大于0才认定分流被执行。

协议 SHA `21f4ae263041036d7f7b3c0509f009b91c559d179ae02d861694604fad9316d3`。身份、原始失败及清理检查与性能资格分开；23 窗因 peer per-tuple 乱序被采集器记为 INCOMPLETE，也全部保留 CPU、Q、原始流量与 profile。采集器 COMPLETE 不等于完整性能资格。

[冻结协议](../../build-output/root-capacity-tuning-20261013/protocol.json) · [全部窗口](../../build-output/root-capacity-tuning-20261013/summary.json) · [实际顺序与失败](../../build-output/root-capacity-tuning-20261013/campaign-result.json) · [真机配置/ALLOW/DROP/故障语义](../../build-output/root-capacity-tuning-20261013/semantic-android-current/result.json)

## 16kpps 所有正反窗口

下表每个值均按 forward / reverse 列出。CPU 为完整 VPP 进程 `CLOCK_PROCESS_CPUTIME_ID` 与 Q 同 CLI 边界的 µs/Q，含诊断边界开销。Q 是实际普通主体 L4 判定且 native SUCCEEDED 的结算，包含延迟探针，不等于 payload PPS。不同覆盖或旁路工作量的 CPU 比值不作为因果效率结论。

| 配置 | 入口直接 ACCEPT | primary 拒绝 | 未计入 Q 的成功包 | peer 乱序 | UDP loss % | CPU µs/Q | p99 上界 ms | 完整通过 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| A 默认 | 29 / 0 | 115 / 30 | 145 / 30 | 18 / 2 | 0.000 / 0.096 | 52.88 / 52.52 | 77.9 / 162.1 | 0/2 |
| P 接收/身份 128 槽 | 0 / 0 | 14 / 49 | 14 / 49 | 10 / 19 | 0.776 / 0.000 | 52.39 / 52.53 | 163.8 / 69.6 | 0/2 |
| C primary credits 48 | 16 / 0 | 28 / 2 | 48 / 3 | 21 / 2 | 0.000 / 0.000 | 52.99 / 53.77 | 79.8 / 15.0 | 0/2 |
| R read budget 32 | 9 / 0 | 20 / 20 | 29 / 20 | 14 / 4 | 0.000 / 1.000 | 52.98 / 52.25 | 76.3 / 176.3 | 0/2 |
| T read budget 16 | 0 / 0 | 138 / 127 | 139 / 127 | 12 / 18 | 0.000 / 0.000 | 53.44 / 53.13 | 14.8 / 75.3 | 0/2 |
| S effective socket 640 KiB | 24 / 0 | 58 / 56 | 82 / 56 | 26 / 20 | 0.000 / 0.107 | 53.28 / 53.15 | 75.9 / 143.1 | 0/2 |
| B effective socket 2 MiB | 8 / 28 | 35 / 40 | 44 / 68 | 16 / 2 | 0.212 / 0.067 | 53.42 / 53.34 | 146.2 / 76.1 | 0/2 |
| Q NFQUEUE maxlen 4096 | 11 / 10 | 93 / 49 | 108 / 59 | 42 / 25 | 0.000 / 0.000 | 53.07 / 53.05 | 72.2 / 23.0 | 0/2 |
| M 固定 UDP tuple 双 lane | 3 / 0 | 0 / 0 | 3 / 0 | 2 / 0 | 0.528 / 1.301 | 68.56 / 69.69 | 166.2 / 162.7 | 0/2 |
| H 2 MiB + maxlen 4096 | 68 / 20 | 43 / 20 | 111 / 41 | 27 / 20 | 0.000 / 0.000 | 53.22 / 53.19 | 17.4 / 78.0 | 0/2 |
| Z 128 槽 + credits48 + budget16 + 2 MiB + 4096 + 双 lane | 0 / 0 | 0 / 0 | 2 / 0 | 0 / 0 | 0.000 / 0.000 | 72.16 / 72.29 | 78.1 / 19.6 | 1/2 |

Z 两窗均没有入口旁路、primary 拒绝、丢包或 per-tuple 乱序，Q/native 分别为99.997953%与100%。前者的2个包按预注册资格保持未通过；没有把 native 成功等同于 Q 或为此放宽100%要求。后者95336个 payload 全部送达，Q并不只含payload：实际Q=97690，Q/s=16258.63；p99为19.6ms，1条可选分段时间戳无效仍计入完整RTT histogram，p50/p95保留 null。

Z 的 CPU/Q 观测为72.16/72.29µs，默认 A为52.88/52.52µs；描述性中位比为约1.371。默认 A 两窗本身均不完整，因此该比值不是相同完整工作量下的效率回退估计，也不建立正式置信区间。组合改善覆盖伴随更高 CPU 开销；没有整体 CPU 效率采用结论。

P 的入口旁路归零，但 primary 拒绝14/49仍在，且两窗都有乱序。`u16-forward-P`的14个 Q 缺口与14次 primary 拒绝完全对应。T 的入口旁路也归零，却有138/127次 primary 拒绝；扩大池或缩小read预算不能单独保证完成全部策略。C的primary拒绝下降到28/2，但64槽首窗仍有16次入口旁路。一般 primary 拒绝涵盖credit和publication失败，现有计数不能逐包拆分两者；不得把全部拒绝都断言为 ring full。

B/Q/H 的 socket/内核队列扩张未产生完整通过窗口。16k各窗实际200ms队列占用与Rmem观测峰值见原始表；采样会错过瞬时峰值，不能据此宣称内核队列从未接近上限。P/C/T/M/Z改变不同限制，保留其实际批密度、read callback与publication计数。

## 高压与 TCP 资格

| 窗口 | 端点 Mbps | Q/s | 入口直接 ACCEPT | primary 拒绝 | UDP loss % | p99 上界 ms | 完整资格 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| u08-start-A | 76.70 | 8382 | 0 | 0 | 0.000 | 21.7 | 通过 |
| u32-A | 305.41 | 32034 | 117 | 546 | 0.104 | 105.1 | 未全通过 |
| u32-P | 265.69 | 31870 | 0 | 391 | 12.994 | 227.6 | 未全通过 |
| u32-M | 301.69 | 31838 | 0 | 0 | 0.091 | 29.0 | 未全通过 |
| u32-Z | 300.99 | 31905 | 0 | 0 | 0.675 | 103.9 | 未全通过 |
| u64-A | 602.85 | 33531 | 63438 | 648 | 1.432 | 84.9 | 未全通过 |
| u64-M | 551.83 | 63827 | 4 | 15 | 9.631 | 112.1 | 未全通过 |
| u64-Z | 568.87 | 63720 | 0 | 0 | 6.729 | 203.1 | 未全通过 |
| tcp-forward-A | 351.55 | 10138 | 21936 | 601 | TCP | 351.4 | 未全通过 |
| tcp-forward-M | 227.39 | 8200 | 21029 | 1570 | TCP | 796.2 | 未全通过 |
| tcp-forward-Z | 396.43 | 16852 | 0 | 324 | TCP | 353.8 | 未全通过 |
| tcp-reverse-Z | 190.28 | 13540 | 0 | 2 | TCP | 842.4 | 未全通过 |
| tcp-reverse-M | 429.43 | 10876 | 27399 | 1519 | TCP | 376.9 | 未全通过 |
| tcp-reverse-A | 347.66 | 9757 | 27789 | 2601 | TCP | 346.3 | 未全通过 |
| u08-end-A | 76.69 | 8308 | 0 | 0 | 0.000 | 135.7 | 通过 |

64k的默认A约33.53k Q/s，双lane M/Z约63.83/63.72k Q/s。Z入口与primary拒绝均为0，但送达355614/381268、丢失6.729%，Q还比native成功少4；其高策略处理速率没有通过完整交付资格。不能把A约603Mbps（含大规模旁路）或Z约569Mbps直接称为完整策略goodput。32k Z也送达188423/189704、丢失0.675%，没有通过。

**TCP名义双lane未在测量窗实际执行。** 原冻结fixture按临时源端口32768–46999/47000–60999分两组，而每窗连接集中于一组；M的两个测量窗都仅lane0进展，Z正向仅lane1、逆向仅lane0。实际lane增量判据全部失败，按原样保留，不是重复试验替换后的双lane结论。六个TCP窗还均有非零内核ID缺口及Q不足；Z无入口旁路并不代表内核已捕获且完整判定所有包。TCP完整策略吞吐上限仍未建立。

两个8k锚点均无旁路、primary拒绝、失包或乱序，端点约76.70/76.69Mbps，但p99为21.7/135.7ms；这说明本环境短窗尾延迟变化显著。16k及TCP的某个较低p99不能自动解释为配置的可复现延迟收益。

## CPU、计时与证据边界

所有37张火焰图只保留实际client monotonic起止内的on-CPU样本；off-CPU等待不混入比例。每组self分母是所有VPP CPU，inclusive调用范围相互重叠。sample period估算CPU执行时间，不是单次函数耗时或锁等待；`_raw_spin_unlock*`不构成锁争用证明。独立 `/proc` utime/stime另列，其窗口和量法不与sample period强行等同。

| 组 | kernel on-CPU % | 独立 /proc 用户 CPU s | 内核 CPU s | 合并采样覆盖 s | 相当于单核 CPU % |
| --- | ---: | ---: | ---: | ---: | ---: |
| UDP-8000-A | 75.97 | 2.23 | 6.55 | 11.774 | 74.57 |
| UDP-16000-A | 67.37 | 3.46 | 6.39 | 11.748 | 83.85 |
| UDP-16000-Z | 71.15 | 3.18 | 10.49 | 11.766 | 116.18 |
| UDP-64000-A | 74.66 | 1.40 | 4.72 | 5.651 | 108.31 |
| UDP-64000-Z | 71.07 | 3.72 | 7.27 | 5.842 | 188.11 |
| TCP-A | 82.36 | 1.64 | 7.44 | 11.584 | 78.39 |
| TCP-Z | 79.02 | 2.24 | 8.02 | 11.718 | 87.56 |

多窗的CPU秒及覆盖秒在各组内累加，上表不是每窗数值。高压Z的额外两核工作不能因为kernel百分比下降就叫作内核总工作减少。完整函数self/inclusive表、batch密度、每lane进展、高水位和CPU布局都在交互页中。

RTT主值使用完整phone monotonic histogram，p99为100µs粒度的上界；p50/p95只在UDP逐样本分段包含全部成功RTT时计算，不完整时保留null，TCP helper没有导出该逐样本分段。无效行没有从RTT histogram删掉，超时与overflow另列。各窗battery预热前读数31.7–33.6°C，未建立热稳态、功耗、长时、跨设备或IPv6 wire结论。新增pressure helper改变了采集条件，这轮CPU不与旧helper的历史点作直接前后收益比较。

[交互表格与全部37张火焰图](../../build-output/root-capacity-tuning-20261013/index.html) · [逐窗CPU](../../build-output/root-capacity-tuning-20261013/profile-summary.json) · [分组CPU](../../build-output/root-capacity-tuning-20261013/profile-weighted.json) · [原始完整资格检查](../../build-output/root-capacity-tuning-20261013/summary.json)

## 恢复与结论

恢复原APK `c76f5c257b5abdf846dd062b5550422506e4d6bc7e9e0ab092184096f14ab289`，核对全部原生库及UID12632/KernelSU grant；原完整空配置经正常API由原revision966恢复为saved/active970，保留正常retained历史1903，没有回写旧二进制配置。generation2055正常Stopped，原生债务0、产品队列与hook不存在、无本次VPP/generator/monitor/simpleperf残留。独占LAN peer核对exe/argv/hash后SIGTERM退出，Openwrt_5G和192.168.4.151保持。

结论范围是：**容量/节奏/实际分流有改善策略覆盖的空间，组合Z的一个16k档通过完整检查；单项设置没有完整通过，组合没有证明整体CPU效率收益，32k/64k和TCP也没有完整吞吐通过。** 固定37窗原始资格不改，TCP分流未执行保留为明确限制；所有扩大资源的档仅为诊断，没有修改默认配置或宣布默认优化采用。

[原配置恢复](../../build-output/root-capacity-tuning-20261013/final-restoration/result.json) · [最终只读设备核对](../../build-output/root-capacity-tuning-20261013/final-device-readonly/result.json) · [独占peer退出](../../build-output/root-capacity-tuning-20261013/peer-cleanup.json) · [证据闭包检查（非性能PASS）](../../build-output/root-capacity-tuning-20261013/final-proof.json)
