# Android VPP POC Execution Journal

本文件是 Android POC 的本地执行流水账。Plane 工单是工作状态的 source of truth；
Plane 项目页面 `Android VPP POC 技术备忘录` 只保留可复用的坑、失败方法和结论；
原始命令输出保存在 `results/`。

执行约束：

- 只有一台 Android 真机，因此一次只运行一个 POC。
- 前一个 POC 得出明确结论后，才开始后一个。
- 每个 POC 必须区分设备事实、运行身份、原始现象和推导结论。
- POC 代码允许丢弃；日志、失败表现和 go/no-go 结论必须保留。

## SAKAMOTO-2：普通 app UID 无 su 完整 VPN 链路复验

状态：通过。

问题：当前 `VpnService -> packaged VPP -> HEV -> SOCKS5` 路径能否由普通 app
UID 完整启动和运行，并在全程不调用 `su` 的条件下完成 IPv4/IPv6、TCP/UDP、
UID allow/drop 矩阵？

### 2026-07-18：范围校正

最初工单写成“从未 root 真机复验”。当前只有一台已解锁、做过 root POC 的 Pixel 6a，
但本轮要回答的是运行身份，而不是设备历史。因此工单改成普通 app UID / no-su 复验；
“从未 root 设备”保留为最终发布环境的未覆盖项，不阻塞当前 POC。

设备预检：

```text
model=Pixel 6a
android=16
api=36
abi=arm64-v8a
build.type=user
build.tags=release-keys
ro.boot.flash.locked=0
ro.boot.verifiedbootstate=orange
adb shell id: uid=2000(shell), context=u:r:shell:s0
package=com.sakamoto.snort.vpnlite
package_uid=12540
versionName=0.1-debug
```

关键发现：历史 Experiment 66-79 的数据面进程本身已在 app UID 下运行，但旧 harness
使用 `adb_su` 完成三类辅助操作：在 `/data/local/tmp` 启动 SOCKS smoke server、读取
`/data/user/0/<package>` 私有日志、检查残留进程。这个 harness 不能直接作为“实验命令
全程无 su”的证据。

处理：新增 `scripts/android-run-app-uid-no-su-matrix-poc.sh`。辅助 server 由 ADB shell
UID 启动；debug APK 私有日志通过 Android `run-as` 读取；运行中通过 `ps -A -n -Z`
记录 APK、VPP、HEV 的 UID、PID、PPID 和 SELinux domain。脚本覆盖：

```text
IPv4 TCP allow / drop
IPv6 TCP allow / drop
IPv4 UDP allow / drop
IPv6 UDP allow / drop
```

执行命令：

```sh
bash experiments/vpp-nfq-poc/scripts/android-run-app-uid-no-su-matrix-poc.sh
```

### 2026-07-18：执行结果

运行身份：

```text
ADB shell: uid=2000, SELinux u:r:shell:s0
APK:       uid=12540, SELinux u:r:untrusted_app:s0:...
VPP child: uid=12540, SELinux u:r:untrusted_app:s0:...
HEV child: uid=12540, SELinux u:r:untrusted_app:s0:...
SOCKS POC server: uid=2000, SELinux u:r:shell:s0
```

构建身份：

```text
APK SHA-256: 0e8ed343f0dcde63ed81a275ce19f935c6909977b2e7f41b3d0a5a0d373c8117
VPP SHA-256: e439686e741cc9066e0e3ace8392c22df5ad943c075715f786180d2cd91f5d35
```

矩阵：

| Case | 结果 | 判定证据 |
| --- | --- | --- |
| IPv4 TCP allow | 通过 | HTTP 200；SOCKS connect `0 -> 1`；UID block 为 0 |
| IPv4 TCP drop | 通过 | 5 秒超时；SOCKS connect 不变；VPP UID block 3 packets |
| IPv6 TCP allow | 通过 | HTTP 200；SOCKS connect `0 -> 1`；UID block 为 0 |
| IPv6 TCP drop | 通过 | 5 秒超时；SOCKS connect 不变；VPP UID block 3 packets |
| IPv4 UDP allow | 通过 | app send 成功；VPP 解析 proto 17；UID block 为 0 |
| IPv4 UDP drop | 通过 | app send 成功；VPP UID block 1 packet / 52 bytes |
| IPv6 UDP allow | 通过 | app send 成功；VPP 解析 IPv6 proto 17；UID block 为 0 |
| IPv6 UDP drop | 通过 | app send 成功；VPP UID block 1 packet / 72 bytes |

原始证据：

```text
results/sakamoto-2-app-uid-no-su-20260718-113816/
```

执行结束后，APK、VPP 和 SOCKS POC server 均无残留进程。

重要观察：TCP allow 中，同一 tuple 的早期 owner 查询返回 UID 12540，连接后期查询可能
返回 `-1`。因此不能只看 VPP 状态里的最终 `last-uid`；正确判定必须联合逐次 resolver
日志、UID verdict counter 和外部流量结果。UDP send 成功只证明 app API 已发送以及 VPP
做出 allow/drop verdict，不证明 HEV 已实现 UDP ASSOCIATE end-to-end。

结论：普通 app UID、SELinux `untrusted_app`、无 `su` 的 Android VPP/HEV 数据面成立，
允许继续下一个 Android POC。未覆盖项仍是从未 root、bootloader locked 的发布设备复验。

## SAKAMOTO-3: VpnService protect() 上游防回环

状态：通过。

实验问题：HEV 创建的 SOCKS5 上游 socket 能否在 `connect()` 前交给仍持有
`VpnService` 实例的 app 父进程调用真实 `protect(fd)`，并在失败时显式终止连接。

已确认边界：

- 上游 TCP socket 创建于 HEV `hev_socks5_client_connect()`。
- 当前 HEV 跑在 app UID 的 fork 子进程，子进程不能直接安全调用父进程 JVM 对象。
- POC 采用 Unix `SOCK_SEQPACKET` + `SCM_RIGHTS`：HEV 子进程发送 fd 副本，app
  父进程调用 `VpnService.protect(fd)` 后返回结果；原 fd ownership 始终留在 HEV。
- 保护必须发生在 socket 创建之后、bind/connect 之前；失败即关闭原 fd 并返回错误。
- 原 SOCKS server 仅监听 `127.0.0.1`，无法证明防回环；本次改为监听设备 WLAN
  地址可达的 `0.0.0.0:41080`。

设备与路由：Pixel 6a、Android 16，WLAN `192.168.4.151/24`。IPv4 外部目标经
`wlan0` 网关路由，IPv6 外部目标经 `wlan0` RA 路由。

成功矩阵：

| 目标族 | 次数 | HTTP 结果 | protect 结果 | SOCKS accept |
| --- | ---: | ---: | ---: | ---: |
| IPv4 (`142.251.13.94:80`) | 3 | 3 | 3 | 3 |
| IPv6 (`2606:4700:4700::1111:80`) | 3 | 3 | 3 | 3 |

六个 HEV 上游 socket 均记录 `protect result=1`。HEV 配置明确使用
`192.168.4.151:41080`，但 VPP TUN tuple 日志中没有 `:41080`，说明上游连接没有
递归进入 VPN。SOCKS POC server 记录了六个外部目标 CONNECT 请求；HTTP 200 响应由
该 POC server 生成，因此本实验验证防回环和 IPv4/IPv6 目标承载，不宣称 SOCKS server
已真实中继到公网。

强制失败：在 app 私有目录创建 `force-protect-failure` 后，Java 返回 false；native
记录 `protect result=0`；HEV 记录 `socks5 client protect fd` 错误并关闭 socket；app 在
584 ms 收到 `Connection reset`；SOCKS accept 计数保持 `6 -> 6`。失败路径可观测、快速
终止，未继续 connect，也未形成无限回环。

原始证据：

```text
results/sakamoto-3-vpn-protect-20260718-120056/
```

结论：GO。产品实现可以沿用“HEV socket hook + app 父进程 fd broker + Java
VpnService.protect”边界。POC 的同步 broker、固定 `wlan0` 地址发现和测试 SOCKS server
不是最终产品实现。

## SAKAMOTO-4: VPP/HEV 连续 50 次启停

状态：通过。

固定条件：沿用 SAKAMOTO-3 APK、Pixel 6a、普通 app UID、
`vpp-hev-owner-resolver`、IPv4 HTTP 单流探针和设备 WLAN SOCKS endpoint。每轮记录
active app/VPP/HEV PID、RSS、fd 数、流量结果、关键日志；停止后检查残留进程、`tun0`
和 VPN 路由规则，并保留逐轮 CSV。

第一次正式运行在第 33 轮出现 HTTP 失败，但 protect、停止清理和路由恢复继续成功。
根因是 POC SOCKS server 自身硬编码最多接受 32 个连接，第 32 次后正常退出；不是
VPP/HEV 故障。已把 server 改为持续 accept，并废弃该次失真运行，完整 50 轮从头重跑。

完整重跑结果：

```text
cycles=50
start rc=0: 50/50
HTTP probe: 50/50
protect result=1: 50/50
critical errors: 0
stopped residual APK/VPP/HEV processes: 0/50
stopped tun0 present: 0/50
stopped ip rules equal baseline: 50/50
SOCKS accepts: 50
```

资源趋势：

| 进程 | RSS min / avg / max KB | RSS first -> last | fd min / avg / max | fd first -> last |
| --- | --- | --- | --- | --- |
| app parent | 151540 / 153228.5 / 154700 | 154028 -> 152328 | 120 / 120 / 120 | 120 -> 120 |
| VPP | 126456 / 126756.4 / 127136 | 126852 -> 126880 | 24 / 24 / 24 | 24 -> 24 |
| HEV | 45968 / 46075.8 / 46208 | 46124 -> 46024 | 121 / 121 / 121 | 121 -> 121 |

原始证据：

```text
有效 50 轮：results/sakamoto-4-vpp-hev-50-cycle-20260718-121742/
废弃的 server 上限运行：results/sakamoto-4-vpp-hev-50-cycle-20260718-121124/
```

结论：GO。固定配置和短 HTTP 探针下未发现启动失败、崩溃、fd/RSS 增长、进程残留或
TUN/路由残留。该结论不覆盖长连接、并发流、Android 网络切换、系统杀进程或长时间
运行后的 teardown。

## SAKAMOTO-5: 网络切换与上游故障恢复

状态：通过，部分 GO。

设备网络能力：Pixel 6a / Android 16 当前仅确认一条可控上游：Wi-Fi
`Openwrt_5G`，IPv4 `192.168.4.151/24`，IPv6 `fd76:d462:c4e3:0:3b9a:e320:779f:e3f1/64`。
未发现可在本次 POC 中独立控制的第二条蜂窝、USB tether 或其他 Wi-Fi 网络，因此“不同
上游网络切换”未宣称通过。

场景结果：

| 场景 | 失败表现 | 进程状态 | 恢复结果 |
| --- | --- | --- | --- |
| 正常 IPv4/IPv6 基线 | 无 | app/VPP 存活 | IPv4/IPv6 均 HTTP 200 |
| 代理不可达：停止 SOCKS server | IPv4 `Connection reset`，app 日志约 3.5 s | app/VPP PID 仍存在 | 重启 server 后 IPv4/IPv6 均 HTTP 200 |
| 短时黑洞：`kill -STOP` SOCKS server | 无 HTTP 响应，后续 app timeout 记录在 logcat | app/VPP 存活 | `kill -CONT` 后 IPv4 HTTP 200 |
| Wi-Fi 断开 | `ip route` 和 IPv6 route 均为空，IPv4 `Connection reset` | app/VPP PID 仍存在 | Wi-Fi 恢复后 IPv4/IPv6 均 HTTP 200 |

每个恢复请求都在同一已安装 APK 和同一 VPN service 上完成，不需要重装、重启 app 或
人工清理。每次上游 socket 仍记录真实 `VpnService.protect(fd)=true`，没有发现 HEV/VPP
崩溃、无限重试或失控进程。

原始证据：

```text
results/sakamoto-5-network-recovery-20260718-123309/
```

注意：第一次脚本运行使用不兼容的 `date +%s%3N` 打印耗时，字段不可信；判定使用 app
自身 epoch 日志、HTTP 结果、PID、路由和 logcat。脚本已改为秒级 lower-bound 字段，原始
结果不回写。

结论：代理不可达、短时黑洞、当前 Wi-Fi 断开/恢复均 GO；第二条真实上游网络切换仍
OPEN，不能从本次单网络设备实验外推。

## SAKAMOTO-6: 熄屏空闲与唤醒流量恢复

状态：通过，GO（不是长期功耗认证）。

实验修正：初始尝试发现 USB 供电会污染 Doze 观察；随后使用
`dumpsys battery unplug` 模拟断开电源，确认 `AC/USB/Wireless powered=false` 后从头
重跑。另发现屏幕会在前置流量探针期间自动熄灭，因此脚本在采样 0 前再次确认
`mWakefulness=Awake`，只有确认亮屏后才发送关屏事件。

固定条件：Pixel 6a / Android 16 / 电量 100% / USB 模拟断电 / Wi-Fi 保持连接 / 当前
APK SHA-256 `c6f60a59431be006a0d13caa92cf35c97f45b2a003d7b84be86b9f87aecaaf00` / VPP
SHA-256 `e439686e741cc9066e0e3ace8392c22df5ad943c075715f786180d2cd91f5d35`。

结果：

```text
screen-off window: 600 seconds
Dozing + screen-off samples: 20/20
app/VPP/HEV alive samples: 22/22 (pre, 20 idle, wake)
pre-wake IPv4/IPv6: 2/2 HTTP 200
post-wake IPv4/IPv6: 2/2 HTTP 200
```

CPU tick（`/proc/<pid>/stat` utime+stime）：

| 进程 | 熄屏前 | 唤醒后 | 窗口增量 |
| --- | ---: | ---: | ---: |
| app | 479 | 499 | +20 |
| VPP | 933 | 971 | +38 |
| HEV | 1 | 1 | +0 |

RSS：app `155252 -> 155464 KB`，VPP 固定 `127448 KB`，HEV 固定 `46480 KB`。
设备级 batterystats 记录 `Time on battery 13m57s`、`screen off 12m33s`、
`Device full idling 11m57s`、`Total partial wakelock 11.092s`；该等效指标包含启动和
唤醒前后，不应当作单独 app 的精确功耗归因。未发现 app/VPP/HEV 崩溃或退出。

原始证据：

```text
results/sakamoto-6-idle-wake-20260718-124742/
```

结论：当前 idle profile 可以继续进入下一阶段；它在熄屏 Doze 窗口保持数据面进程存活，
并能在唤醒后恢复 IPv4/IPv6 流量。仍不等同于长期电池认证、不同温度/电量曲线或真实
物理拔线实验。

## SAKAMOTO-7: 5 分钟持续流量风险基线

状态：测试通过；资源稳定 GO，熄屏 TCP 延迟 HOLD 发版。

实验目的：在同一 Android 真机、同一 VPP/HEV 配置下，分别执行 3 轮 300 秒 TCP 和
UDP 持续负载，观察 Doze 场景中的延迟、发包量、错误、CPU、RSS、CPU placement 和
温度。该 POC 不是公网带宽认证：当前设备本地 SOCKS smoke server 只返回固定 HTTP
200，UDP 也没有 UDP ASSOCIATE relay，因此 TCP 字节量代表路径/连接 churn，UDP 字节量
代表 app UID 发包和 VPP 路径负载，不代表公网有效吞吐。

### 固定条件与执行修正

- Pixel 6a / Android 16 / Wi-Fi `Openwrt_5G`；APK SHA-256
  `575cf3f2eb23f19dc60614563f3ccd282a998f7a77e4bbd6c47cba85179fc3f3`；VPP SHA-256
  `e439686e741cc9066e0e3ace8392c22df5ad943c075715f786180d2cd91f5d35`。
- 每次正式测量前执行 `dumpsys battery unplug`，并确认 `USB powered: false`；屏幕关闭后
  进入 `mWakefulness=Dozing`，采样中 `deviceidle mState=IDLE`。结束后执行
  `dumpsys battery reset`，恢复 `Awake`。
- TCP：`142.251.13.94:80`，HTTP/1.0 短连接循环，300 秒，warm-up 15 秒，15 秒采样。
  UDP：`8.8.8.8:53`，25 字节 payload tight loop，同样 300 秒和采样周期。
- 每个采样保存进程表、`/proc` CPU tick/processor/cpuset、RSS、电池、thermalservice、
  power、deviceidle、VPP CLI、HEV、应用日志和 logcat；流水账为结果目录下的 `run.log`。
- 冒烟阶段发现两个 harness 问题：Activity 没有转发 `durationSeconds`，导致 stream
  extra 不会进入 Service；已补齐 Activity -> Service 传递。WSL2 下未引用的
  `/proc/cpuinfo` 被 Windows `adb.exe` 改写成本机路径；已改为远端 shell 字符串后再正式运行。

### 正式结果

| 轮次 | TCP requests/success | TCP error | TCP response bytes/s | p50/p95/p99 ms |
| --- | ---: | ---: | ---: | ---: |
| 1 | 75/75 | 0 | 9.987 B/s | 4043/4063/4071 |
| 2 | 76/76 | 0 | 10.051 B/s | 4030/4054/4063 |
| 3 | 76/76 | 0 | 10.086 B/s | 4042/4067/4077 |

| 轮次 | UDP packets | UDP error | UDP bytes/s |
| --- | ---: | ---: | ---: |
| 1 | 6,938,262 | 0 | 578,188.500 |
| 2 | 6,970,444 | 0 | 580,870.333 |
| 3 | 6,892,774 | 0 | 574,395.919 |

三轮 TCP 均稳定出现约 4 秒级延迟；这是在 USB 已模拟断电且设备处于熄屏 Doze 的
重复现象，不是单轮异常。当前证据只能确认与该 Doze/后台条件相关，不能单凭本 POC
断言根因是 Android 调度、HEV、VPP 或 mock SOCKS server，需用屏亮/前台 service 对照
实验拆分。

稳定性与资源：

- app/VPP/HEV 存活样本 `96/96`；TCP、UDP 六轮应用层 error 均为 `0`。
- 电池温度正式样本固定 `342`（约 34.2 C）；reset 后设备回到 USB powered，结束温度
  `346`（约 34.6 C）。
- TCP 采样 RSS 范围：app `154088..158012 KB`，VPP `127556..127724 KB`，HEV
  `46380..46436 KB`。UDP：app `153632..157004 KB`，VPP `127332..127516 KB`，
  HEV `46372..46400 KB`。
- 每轮 CPU tick 增量（app/VPP/HEV）：TCP `216/69/61`、`128/37/40`、`215/71/63`；
  UDP `25570/16932/439`、`25692/17017/436`、`25630/16978/435`。UDP 的高 app tick
  是 tight-loop 发包负载的直接表现；当前允许 CPU 集合为 `0-3`，未固定单核。
- 停止后无 app/VPP/HEV 残留，屏幕恢复 Awake，battery override 已 reset。

原始证据：

```text
results/sakamoto-7-throughput-risk-20260718-131158/
```

结论：可以继续 Android POC，当前 VPP/HEV 在 30 分钟级持续 TCP/UDP 负载下未出现
崩溃、进程退出、RSS 持续泄漏或 app send error；但不能据此放行熄屏后台 TCP 发版。
下一步应先做“屏亮 vs 熄屏/Doze、前台 service/后台 service”的对照，定位约 4 秒延迟
来自系统调度还是数据面路径，再决定产品 keepalive/前台服务策略。

## SAKAMOTO-8：Android 打包 VAPI C ABI 与 typed control

状态：通过，GO（Android 普通 app UID typed control 已成立）。

实验目的：把现有 `tun_poc_control_shim` 和 VPP VAPI client 依赖放入 APK，VPP 在
`files/vpp/runtime/api.sock` 提供 app-private `socksvr`，由 Android app UID JNI 调用
typed `status -> owner policy set -> status -> clear -> status`，确认不依赖 CLI 解析和
`su`。

### 固定条件

- Pixel 6a / Android 16 / arm64-v8a / package UID `12540`。
- 每次执行前 `dumpsys battery unplug`，正式运行确认 `USB powered: false`；结束执行
  `dumpsys battery reset`，最终快照确认 `USB powered: true`、Awake。
- APK SHA-256：
  `bf4220c69b3be0dabcd36253538bd12c79d2a640fb7ca38937004b952898a309`。
- VPP runtime stage：`work/android-vpp-api-stage`；VPP SHA-256：
  `ebbb2c1bdfe20bbde1123e8182144911fe9ab6a83f01b898ee75b2fc745ff0dd`。
- 5 轮，每轮新建一次 VAPI client handle；每轮都读取初始状态、设置
  `owner_cache_enabled=1/block_owner_uid=12540`、读取确认、清除并读取确认。

### 过程中的关键失败与修正

第一次使用旧的优化 Android stage 时，VAPI socket 可以连接，但 typed status 返回
`-5`，VPP 日志出现 `no handler for msg id 65535`。继续检查发现 APK 中的
`tun_poc_plugin.so` 与生成 VAPI client 不是同一构建产物；configure tree 也曾只构建
client，未重编当前 plugin，且 Android plugin target 缺少 `vlibmemory` 链接依赖。

修正顺序：

1. 在 `overlay/src/plugins/tun_poc/CMakeLists.txt` 为 Android plugin 增加
   `vlibmemory` 链接依赖。
2. 重新应用 overlay，重配置 Android configure tree，构建
   `vapiclient vlibmemoryclient tun_poc_plugin`。
3. 从同一 configure tree 重新生成 `android-vpp-api-stage`，让 VPP core、plugin、
   generated VAPI header 和 client libraries 同源。
4. Android overlay 固化 `vapiclient` 的 bionic 平台链接差异，移除不可用的独立
   `pthread/rt` 链接，后续可由 CMake 直接重建，不再依赖手工链接。
5. VPP startup config 新增 app-private：
   `socksvr { socket-name <files>/vpp/runtime/api.sock }`。

### 正式结果

```text
API socket: ready
rounds: 5/5 pass
status_before_rc: 0 (5/5)
policy_set_rc/vpp_retval: 0/0 (5/5)
status_set: owner_cache=1 block_uid_set=1 block_uid=12540 (5/5)
policy_clear_rc/vpp_retval: 0/0 (5/5)
status_after: owner_cache=0 block_uid_set=0 block_uid=-1 (5/5)
client uid: 12540
su: not used
cleanup: no app/VPP residual process; battery override reset
```

原始证据：

```text
results/sakamoto-8-vapi-control-20260718-231537/
```

结论：Android 普通 app UID 已能加载打包的 VAPI C client，通过 app-private UDS 对同一
UID 的 VPP 执行 typed control；API socket、C ABI shim、generated VAPI、VPP plugin 的
构建一致性是硬前提。当前仍是 POC：头文件来自本地 VPP build tree，尚未进入 Rust SDK、
Tauri command 或版本化发布包。

## SAKAMOTO-9：Android 打包 Rust FFI 与 typed control

状态：通过，GO（Android 普通 app UID 的 Rust -> C ABI -> VAPI 路径已成立）。

实验目的：把 Rust 控制层编译为 `aarch64-linux-android` staticlib，放入同一 APK，
由 JNI 只负责路径和调度；Rust 仅调用稳定 C ABI opaque client，不接触 generated VAPI
类型，完成 `status -> owner policy set -> status -> clear -> status`。

### 固定条件

- Pixel 6a / Android 16 / arm64-v8a / package UID `12540`。
- Rust target：`aarch64-linux-android`；APK 内 Rust staticlib 与 C JNI、VAPI client、
  VPP plugin 同一轮构建。
- 每次执行前 `dumpsys battery unplug`，正式运行确认 `USB powered: false`；结束执行
  `dumpsys battery reset`，最终确认 `USB powered: true`、Awake。
- APK SHA-256：
  `e6f8963fbd9ec8d6b8192b2194ad56d4b13f7d42a7baf4f9d3dbda9510bd5973`。
- VPP runtime stage：`work/android-vpp-api-stage`；VPP SHA-256：
  `ebbb2c1bdfe20bbde1123e8182144911fe9ab6a83f01b898ee75b2fc745ff0dd`。

### 关键实现边界

- Rust FFI 只声明 `tun_poc_client_*`、`tun_poc_status_out_t` 和
  `tun_poc_owner_policy_t`；generated VAPI 仍隐藏在 C shim 内。
- JNI 不实现控制逻辑，只生成 app-private socket/log 路径并调用 Rust 导出函数。
- Rust 每轮新建并关闭一个 opaque client；本票不宣称异步、自动重连、并发访问或
  Tauri command 语义。

### 正式结果

```text
API socket: ready
rounds: 5/5 pass
Rust abi_version: 1
Rust client uid: 12540
status_before_rc: 0 (5/5)
policy_set_rc/vpp_retval: 0/0 (5/5)
status_set: owner_cache=1 block_uid_set=1 block_uid=12540 (5/5)
policy_clear_rc/vpp_retval: 0/0 (5/5)
status_after: owner_cache=0 block_uid_set=0 block_uid=-1 (5/5)
su: not used
cleanup: no app/VPP residual process; battery override reset
```

原始证据：

```text
results/sakamoto-9-rust-control-20260718-232721/
```

结论：Android 普通 app UID 内的 Rust 控制层可以通过稳定 C ABI 调用 packaged VAPI，
对 app-private VPP 执行 typed read/write/rollback。当前仍是 POC：Rust staticlib 尚未
进入版本化 SDK、异步/重连模型或真实 Tauri command。
