# 普通 VPN 固定 TCP 下载批处理实验

日期：2026-10-21。用户要求推进减少轮转与批处理，**设备性能验证只聚焦固定 TCP 下载**。实现了默认关闭的候选，完成同源码开／关版本的四个独立生命周期 ABBA。没有运行 UDP、新建连接 CPS 或 Root 性能负载，也没有改变 MTU/MSS、容量、规则或 Wi-Fi。

**结果：批处理机制成立，单位端点交付的 VPP CPU 估计下降6.17%，未证明吞吐提升。** 本轮两窗／版本的端点吞吐均值110.44→103.48 Mbps（−6.31%）；样本短且存在时间变化，不能把这个差值认定为稳定的因果退化，但它不支持采用为增吞方案。候选保持默认 OFF，原 APK 已恢复，最终 Stopped。

## 候选与所有权边界

`SAKAMOTO_PRODUCT_VPN_TCP_BATCH_EXPERIMENT=ON`同时开启以下三项，A/B比较的是整个候选，不能单独归因到某一项：

1. HEV每次 Direct TCP receive读取一次现成socket数据，最多进行8次已有ring数据的小提交。每次 `tcp_write`仍不超过一个协商MSS，不扩大整个write事务；到轮次边界再 `tcp_output`。不等待未来数据，不增加ring、sndbuf、pbuf或返回credit容量。ERR_MEM不推进未成功的ring范围，成功前缀保留，已提交字节仍由原ACK回收路径释放。
2. Flow Stack输出回调在创建独立VPP buffer后，使用**当前生产node的原生next frame**提交到正常admit图。原生VPP调度接受所有权后回调才返回；不引入私有待发包队列，不递归执行共享图，不将借用的lwIP spans留到回调以后，也不绕过策略或TUN completion。driver只在当前同步node调用中保存其node/next，调用结束清空；其它上下文保留既有singleton提交。
3. TUN read-ready原有最多64次非阻塞读取保留；将已经读到的capture描述符按批提交到共享图。即使最后一次read或allocation失败，前面成功读取的包仍被发布；逐项被拒绝的buffer与capture obligation在caller侧结清。TUN出口仍逐IP包 `write`。

候选通过新的 [HEV patch0014](../../third_party/hev/patches/0014-bounded-direct-tcp-batch.patch)及VPP-native C调用点实现，没有导入POC代码。现有UDP批处理开关在两个版本中都为OFF。MTU1500、MSS1360、TCP_WND/TCP_SND_BUF32768和全部既有资源数量上限不变；只增加计数和有界描述符，没有新的payload队列。

新增 `flow_stack.tcp_receive`记录真实receive轮次、readv尝试／暂不可读、小提交次数／字节、ERR_MEM、tcp_output调用和每轮提交最大值。这里的rounds是TCP receive轮次，`tcp_output`是lwIP函数，二者都不能误称进程的内核context switch或syscall总数。`tun.capture_batch`记录图发布调用、包数和lifetime max。最大值不能作窗口差分；`show runtime`提供实际admit调用／vectors。

## 构建与正确性

HEAD为 `c32729e7`，保留此前未提交的UDP候选及采集器工作。本次开／关构建的1346文件Product源码闭包均为 `96fe72fc5d115084a53a63794f064657239e1ae4462ba18e03f695be1f28afa0`。DEX一致，12个native载荷中只有插件不同；各自精确符号重新strip后匹配对应APK。

| 版本 | APK SHA256 |
| --- | --- |
| scalar／OFF | `5735df8c74298d9d97b0e1a173a1504fac78f3521a194502247838fee2aab216` |
| batch／ON | `456912e14615e4d0a425c63daf3b527f6a56a6354c43a1e08f9e64a6669d44d1` |

Android／Host builders均校验、传递并记录开关；APK assembly检查stage模式，缺少旧可选字段时按OFF解释。错误开关和stage模式不匹配均被拒绝。Android native-stage contract通过。使用持久Product cache；unchanged Android第二次发布0.688秒、零编译、12个native逐字节一致；Host持久 `build-output/host-hev-tests`重复构建为no work。

在既有真实HEV/lwIP／kernel TCP fixture中先加入批处理机制检查，旧实现因 `max_commits >= 4`失败。第一次sandbox执行因netlink权限失败，另行保留；在fixture原有临时user/network namespace内得到真正的红灯，随后候选通过。scalar与batch各12项TCP检查通过，覆盖双栈、完整字节流、真实sendmsg背压、返回拒绝／丢失恢复、FIN、underlay结束、packet／pbuf资源不足及回收。这里的故障测试支持候选正确性，不是Android性能或一般VPN发布资格。

一个Host IPv4 owner传完同样73,728字节：scalar154个receive轮次／154次readv，其中135次暂不可读；batch48轮／48次readv，其中29次暂不可读，最大每轮8次提交。两个版本都逐字节验证全部数据并结清原生资源。机制计数没有代替真实流数据检查。

[成对构建身份](../../build-output/vpn-tcp-batch-20261021/paired-build-identity.json) · [原始构建记录](../../build-output/vpn-tcp-batch-20261021/build.log) · [warm reuse](../../build-output/vpn-tcp-batch-20261021/scalar-warm.json) · [机制红灯](../../build-output/vpn-tcp-batch-20261021/host-red-network.log) · [batch12项](../../build-output/vpn-tcp-batch-20261021/host-batch-tests.log) · [scalar12项](../../build-output/vpn-tcp-batch-20261021/host-scalar-tests.log) · [native-stage contract](../../build-output/vpn-tcp-batch-20261021/native-stage-contract.log) · [负面stage检查](../../build-output/vpn-tcp-batch-20261021/negative-stage/result.json)

## 两次测量前中止与传输修正

第一次四窗计划在A1的Activity启动及后续state读取时ADB超时，未进入下载或profiling，generation没有推进；计划中止，原APK恢复。[第一次完整失败](../../build-output/vpn-tcp-batch-20261021/campaign-result.json)。

第二次单独冻结15秒控制调用timeout，仍在A1进入测量之前遇到 `WSL UtilAcceptVsock: accept4 failed 110`；generation2083正常停止的可见状态已确认，但没有完整测量窗或本代native-zero资格，不能借用后续日志补齐。[第二次完整失败](../../build-output/vpn-tcp-batch-fixed-20261021/campaign-result.json)。两次都不混入后面的吞吐／CPU统计。

只读检查确认现有本机ADB服务可通过TCP访问。后续仍全部经过仓库 `./dev/adb`，通过其既有 `SAKAMOTO_ADB`入口选择已有Linux客户端，连接原有本机ADB服务，避开Windows executable的WSL桥接。没有切Wi-Fi、修改ADB wrapper、重启手机或调整数据面。第三次独立冻结记录该传输、client hash和原失败链接；四个负载窗口无重试。不能将其表述为最初两次计划成功。

[ADB服务检查](../../build-output/vpn-tcp-batch-20261021/start-diagnosis/adb-server.json) · [成功计划协议](../../build-output/vpn-tcp-batch-native-adb-20261021/protocol.json)

## 固定下载 ABBA

新 `ordinary-vpn-tcp-fixed-v1`套件冻结为普通VPN的**唯一一格tcp-fixed**：正常start、250ms实际LAN warmup、原有UID／Flow与占用护栏、完整5秒下载、正常stop及本代native日志审计。4线程×16 sockets、199Hz cpu-clock保持；不使用controlled／validation extras。它是新的限定套件，不是从旧四格协议中删掉失败或不利格子后沿用旧名称。控制命令最长15秒、每次run总deadline仍120秒。

| 窗口 | generation | 端点Mbps | VPP CPU秒／GiB | TUN capture包／图发布 | admit vectors／实际调用 | OUTPUT_CAPACITY |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A1 scalar | 2084 | 104.31 | 76.80 | 1.00 | 1.00 | 2,708 |
| B1 batch | 2085 | 103.66 | 70.38 | 56.37 | 22.11 | 166 |
| B2 batch | 2086 | 103.29 | 70.44 | 57.11 | 21.42 | 11 |
| A2 scalar | 2087 | 116.58 | 73.47 | 1.00 | 1.00 | 5,081 |

四次run分别14.590／14.370／14.366／14.760秒，均COMPLETE。每个generation都验证两owner与TUN stop的sessions/input/pbuf/socket/native buffers/obligations/frames结算。四份perf均lost0，按实际helper monotonic测量边界过滤，核对各APK对应ELF build IDs和符号；unknown leaf周期约2.3%–3.4%保留。

按两个窗口端点交付字节合并归一化：

| 指标 | scalar | batch | 变化 |
| --- | ---: | ---: | ---: |
| 端点吞吐算术均值Mbps | 110.44 | 103.48 | −6.31% |
| VPP CPU秒／交付GiB | 75.04 | 70.41 | −6.17% |
| TCP readv尝试／交付GiB | 314,175 | 119,287 | −62.03% |
| TCP receive轮次／交付GiB | 1,335,567 | 628,110 | −52.97% |
| TUN成功write／交付GiB | 827,167 | 831,173 | +0.48% |

batch实际每轮提交最大8，scalar最大2（ring wrap的两个短span）。合计TUN capture图发布平均56.74包，admit平均21.76 vectors／调用，证明两个批量边界真实生效。额外核对每窗所有admit vectors差分严格等于capture submitted加return submitted，未通过少送入共享图来减少node调用。

OUTPUT_CAPACITY总数7,789→177，按端点GiB归一化下降97.58%；仍未区分返回credit、stamp或VPP allocation原因，因此不将它改称已证明的credit耗尽。四窗primary拒绝仍为12,504／11,125／10,244／13,581，Flow capacity miss均0。端点速率不是完整策略Q。

上述计数取自测量前后CLI快照，区间包含采样器启动及少量自然背景；TCP计数属于该generation的全部owner TCP工作，不是只按发生器tuple过滤。VPP CPU由实际监控覆盖外推到负载窗后除以端点GiB，既不是整机CPU，也不是电能。p99仅45／68／44／33个成功样本，对应3／1／3／4次timeout，不能据此建立匹配负载的延迟资格。两窗／版本的结果仅为描述性观察。

[四窗原始结果](../../build-output/vpn-tcp-batch-native-adb-20261021/campaign-result.json) · [全部计数与重算脚本](../../build-output/vpn-tcp-batch-native-adb-20261021/summary.json) · [四窗与火焰图导航](../../build-output/vpn-tcp-batch-native-adb-20261021/index.html) · [采集器对照](../../build-output/vpn-tcp-batch-native-adb-20261021/comparison/index.html)

## 为什么还没有增吞

CPU调用链按sample period加权；下表为inclusive，会重叠，不能相加。单位成本按各窗CPU覆盖与交付字节加权。

| 调用链 | scalar→batch占比 | scalar→batch VPP CPU秒／交付GiB |
| --- | ---: | ---: |
| HEV任务调度 | 4.86%→3.58% | 3.65→2.52 |
| TCP Direct receive／splice | 14.39%→11.73% | 10.81→8.26 |
| TUN返回completion | 45.16%→49.40% | 33.89→34.78 |
| 其中tun_get_user | 41.34%→44.99% | 31.02→31.68 |

减少轮转、读取探测与小frame的作用确实可见。但同样数据仍以原有小IP包逐包写TUN，write次数／GiB基本不变，返回路径单位成本没有减少；它在剩余CPU中的比例反而更大。batch内核比例69.28%。因此不能把46%左右整个分支当作可通过减少syscall入口一次消掉的开销。

batch两个worker平均约54%和31%单核，仍有明显未执行时间；这里只采CPU，未解释等待、唤醒、ACK推进和单TUN lane的短时峰值，不能据此宣称已证明内核算力硬上限。本次证据支持“批处理省了一部分CPU并减少返回拒绝”，不支持“固定下载已变快”或“可直接采用为默认”。

## 最终状态

恢复October13原APK `844b339d7d848dee854ffc54b9e685bdf158f52f8d9720ef088c45ddc4531a03`，核对全部12个native载荷、原规则hash、Root grant和当前libc匹配符号；generation2087／Stopped，无VPP／发生器／monitor／simpleperf残留。Wi-Fi始终保留Openwrt_5G。独占LAN peer按PID、starttime、exe、argv和hash重新核对后退出。

候选默认OFF，未采用、未保留实验APK，未执行commit或push。此前UDP候选和全部原始证据保留，没有运行额外UDP／新建／Root性能验证。

[最终只读审计](../../build-output/vpn-tcp-batch-native-adb-20261021/final-readonly/result.json) · [原APK恢复](../../build-output/vpn-tcp-batch-native-adb-20261021/install-restore-original/result.json) · [peer结清](../../build-output/vpn-tcp-batch-native-adb-20261021/peer-cleanup.json)
