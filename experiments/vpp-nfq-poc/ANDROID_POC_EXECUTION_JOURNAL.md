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

## SAKAMOTO-10：Android VPP 异常退出与 stop/restart

状态：通过，GO（普通 app UID 下的 VPP child 异常退出、socket 清理和显式重启边界已成立）。

实验目的：验证 VPP child 被 app UID 直接终止后，父进程是否回收 child、运行时 socket 是否
留下 stale 文件，以及 `VpnService stop -> start` 是否能获得新 VPP child 并恢复 typed control。

### 固定条件

- Pixel 6a / Android 16 / arm64-v8a / package UID `12540`。
- 每次执行前 `dumpsys battery unplug`；正式运行确认 `USB powered: false`；结束执行
  `dumpsys battery reset`，最终确认 `USB powered: true`。
- kill 使用 `run-as com.sakamoto.snort.vpnlite /system/bin/kill -TERM <vpp-pid>`，
  不使用 `su`。
- APK SHA-256：
  `c5621f57f44fd496120e747934850f54389d7c0e91442c62f390da73e64bff9e`。
- VPP runtime stage：`work/android-vpp-api-stage`；VPP SHA-256：
  `ebbb2c1bdfe20bbde1123e8182144911fe9ab6a83f01b898ee75b2fc745ff0dd`。

### 首次失败与定位

- 首次运行 `results/sakamoto-10-abnormal-restart-20260718-233443/`：app UID
  `SIGTERM` 已成功，Rust control 在异常退出后按预期失败，但旧 VPP PID 变为
  `State: Z (zombie)`，`api.sock` 仍存在；原因是原 monitor 只做有限次 CLI 轮询，
  没有持续 `waitpid`，stop 之前不会回收 child，也没有清理 runtime socket。
- 中间两次假回归使用了错误的 APK VPP stage：APK 实际打入
  `release-no-multiarch-no-ipsec-idle-stage`（SHA `e439...`），而正式 S8/S9 使用
  `android-vpp-api-stage`（SHA `ebbb...`）；表现为 API socket 可连接但 typed status
  无回包。结论：APK 内 VPP、generated VAPI client 和记录中的 runtime stage 必须同轮
  对齐，不能只看 socket `ready`。

### 最小修复

- `vpp_monitor_thread` 在 CLI 轮询结束后继续存活，周期性执行
  `waitpid(pid, WNOHANG)`，直到显式 stop 或检测到 child 退出。
- 检测到 child 退出后回收 PID，并清理 `api.sock`、`cli.sock`、`statseg.sock`。
- `nativeStopVppProbe` 对已经被 monitor 回收的 child 处理 `ECHILD/ESRCH`，随后仍
  关闭辅助 FD、join 线程并清理运行时 socket。

### 正式结果

```text
run_id: 20260718-235841
package_uid: 12540
initial_app_pid: 5294
initial_vpp_pid: 5330
app-UID SIGTERM: accepted; vpp_exit=observed
after kill: old VPP PID absent; State Z absent; api_socket=absent
after kill Rust control: open_rc=-3 / result=fail (expected dead-child boundary)
after stop: no VPP process
restart_vpp_pid: 5613 (new PID)
after restart Rust typed control: pass
cleanup: no UID 12540 residual VPP/app process; battery override reset
```

原始证据：

```text
results/sakamoto-10-abnormal-restart-20260718-235841/
```

结论：Android app UID 下，VPP child 异常退出可以被父进程回收，stale API/runtime
socket 不再残留；显式 stop/restart 后新 child 可恢复 Rust -> C ABI -> VAPI typed control。
当前只验证 `SIGTERM + explicit stop/restart`，未覆盖 crash signal、Android service/process
death、自动重启策略和 stop/child-exit 并发竞态。

## SAKAMOTO-11：Android Rust persistent client stale-handle reconnect

状态：通过，GO（persistent Rust opaque client 的 stale-handle 与 fresh-handle reconnect
边界已成立）。

实验目的：同一 Rust client 在 VPP stop 前后保持不变，验证旧连接不会假成功；VPP 重启后
沿用同一 app-private API socket 创建 fresh client 并恢复 typed status。

### 固定条件

- Pixel 6a / Android 16 / arm64-v8a / package UID `12540`。
- Rust staticlib 通过稳定 C ABI opaque client 调用 generated VAPI；marker 文件由
  `run-as` 创建，未使用 `su`。
- 每次执行前 `dumpsys battery unplug`，正式运行确认 `USB powered: false`；结束执行
  `dumpsys battery reset`，最终确认 `USB powered: true`。
- APK SHA-256：
  `ba01c6e898f9c732b50ddbed34ce9c8fadaf71005a622769393f219d63e5bdc5`。
- VPP runtime stage：`work/android-vpp-api-stage`；VPP SHA-256：
  `ebbb2c1bdfe20bbde1123e8182144911fe9ab6a83f01b898ee75b2fc745ff0dd`。

### 首次失败与修正

- 首次运行 `results/sakamoto-11-rust-reconnect-20260719-000654/`：旧 client
  `stale_status_rc=-5` 已按预期失败，但 `stale_close_rc=-7` 使 probe 过早判失败，
  没有进入 reopen 阶段。
- `-7` 是 VAPI disconnect 关闭错误，不是 stale status 假成功；修正为记录并接受该
  预期断连结果，继续等待 fresh handle。

### 正式结果

```text
run_id: 20260719-000932
package_uid: 12540
initial_app_pid: 7009
initial_vpp_pid: 7045
initial_open_rc: 0
initial_status_rc: 0
stale_status_rc: -5 (same client, after VPP stop)
stale_close_rc: -7 (expected disconnect close error)
restart_vpp_pid: 7205 (new PID)
fresh_open_rc: 0
fresh_status_rc: 0
fresh_close_rc: 0
result: pass
cleanup: no UID 12540 residual VPP/app process; battery override reset
```

原始证据：

```text
results/sakamoto-11-rust-reconnect-20260719-000932/
```

结论：Rust 控制层必须把 stale status error 作为连接丢失信号；旧 handle 的 close 也可能
返回 disconnect error，不能把它误判为数据面失败。恢复策略应关闭旧 handle、等待新 API
socket ready、创建 fresh handle；当前未定义自动 backoff、in-flight command recovery、
command replay 或并发 reconnect ownership。

## SAKAMOTO-12：APK-native daemon packaging 与 RuntimeService HELLO gate

状态：通过，GO（APK 打包、root handoff、HELLO 合同和停止清理边界已成立）。

实验目的：把 `build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so` 放入 APK，验证
普通 APK Service 能否定位 `nativeLibraryDir` 中的 ELF，经 root 路径启动 daemon，并在启动
成功前用 vNext `HELLO` 校验 ABI、build id 和 capability；随后验证停止不留下 root daemon。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 每次执行前 `dumpsys battery unplug`，正式运行确认 `USB powered: false`；结束执行
  `dumpsys battery reset`，最终确认 `USB powered: true`。
- APK 打包路径：`lib/arm64-v8a/libsucre_snortd.so`；运行时路径：
  `${applicationInfo.nativeLibraryDir}/libsucre_snortd.so`。
- daemon artifact SHA-256：
  `fe2b15dc87d28404e4c6c912ecbc9dea658104b0666e604519b8113a22f00b57`。
- APK SHA-256：
  `9309b5d6dcac3509fc4da585a0e33469e720b93ed13d0f68325b401b4cc8a21c`。
- KernelSU Superuser grant：必须由 KernelSU Manager 对该 APK 显式授权；这是本轮设备前置
  条件，不是 APK 自己可以绕过的权限。

### 失败方法与定位

1. `ProcessBuilder("su", ...)`：app UID 的 PATH 中没有 `su`，直接得到
   `Cannot run program "su": error=2`。
2. 改成 `/system/bin/su`：在 KernelSU 尚未给 APK 授权时，app mount namespace 中仍看不到
   该路径，同样得到 `error=2`。ADB shell 能看到该文件不能证明 app 进程能看到。
3. 在 KernelSU Manager 开启 APK 的 Superuser 后，root launch 和 HELLO 成功；这确认问题
   是 root 授权/namespace 前置条件，不是 APK-native ELF 缺失。
4. 初版 harness 以行首匹配 `runtime_start_result`，但 RuntimeService 每行都有毫秒时间戳，
   造成启动成功后的假失败；改为匹配带时间戳的行尾字段。
5. 初版 root daemon 过滤只匹配 `ps` 的用户列 `root`，Android 实际输出数字 UID `0`，
   造成 daemon 已运行时的假失败；过滤器改为接受 `0` 和 `root`。
6. 初版停止只调用 Java `Process.destroy()/waitFor()`。`su` 已 `exec` daemon 后，Java
   wrapper 不可靠地反映真实 daemon 生命周期，导致 daemon 残留；修正为 root launch 写入
   daemon PID，再由 stop 通过 root shell 执行 TERM、等待、必要时 KILL。

### 正式结果

```text
run_id: 20260719-004405
package_uid: 12540
root_daemon_pid: 11367
native_library_dir: present, executable
hello_protocol: control-vnext
hello_artifact_abi: arm64-v8a
hello_daemon_build_id: ndk-r29-7c897161e637
hello_capability_snort10_base: true
hello_capability_nfqueue_pass_through: true
hello_result: pass (attempt=12)
runtime_start_result: pass
runtime_stop: pass; no root libsucre_snortd.so after stop/cleanup
USB powered after unplug: false
USB powered after reset: true
```

原始证据：

```text
results/sakamoto-12-runtime-service-20260719-004405/
```

结论：Android debug APK 已能承载同一 NDK daemon artifact，并以 RuntimeService 完成
`APK -> KernelSU root -> daemon -> HELLO` 最小纵向切片。后续仍需单独验证 Android
Service/process death、自动重启/backoff、前台服务通知、release signing、升级/回滚和
crash/tombstone 采集；本轮不宣称最终 Tauri UI 或 release packaging。

## SAKAMOTO-13：RuntimeService process-death 与 root daemon orphan boundary

状态：实验通过，产品判定 HOLD（已证明当前 root handoff 在 APK 进程死亡后不能自动收敛）。

实验目的：启动 S12 的 APK-native root daemon，强制停止 APK 进程，观察 daemon 是否随
Service 一起退出；随后只用显式 root cleanup 清理，再验证 RuntimeService 是否能重新启动。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 正式运行使用 `dumpsys battery unplug`，确认 `USB powered: false`；结束 reset 后确认
  `USB powered: true`。
- APK SHA-256：
  `9790f36d93045f5f2843b522553d1a4aad05b0119e7edb9959c688ff74f525e6`。
- daemon artifact SHA-256：
  `fe2b15dc87d28404e4c6c912ecbc9dea658104b0666e604519b8113a22f00b57`。

### 正式结果

```text
run_id: 20260719-004844
baseline_root_daemon_pid: 11861
after_force_stop: APK absent; root libsucre_snortd.so still alive as PID 11861, PPID 1
explicit_root_cleanup: no daemon
recovery_root_daemon_pid: 12044
recovered_runtime_stop: no daemon
result: observation pass
decision: HOLD automatic recovery; explicit root cleanup required
```

原始证据：

```text
results/sakamoto-13-runtime-process-death-20260719-004844/
```

### 结论与阻塞

`am force-stop com.sakamoto.snort.vpnlite` 会杀掉 APK/Service，但不会杀掉已由
`/system/bin/su` exec 的 root daemon；daemon 被 reparent 到 PID 1，继续占用控制 socket
和 NFQUEUE 相关资源。当前只能依赖外部 root `killall` 清理，随后 fresh RuntimeService
可以恢复。这个结果阻塞 Android release handoff；继续做前台服务、升级/回滚或长稳 POC
之前，必须先决定并验证 root supervisor、daemon 自清理握手或可接受的系统级 lifecycle
契约。本轮没有把外部 killall 伪装成自动恢复。

## SAKAMOTO-14：daemon parent-death containment 与 orphan cleanup 边界

状态：部分通过，进程回收 GO；NFQUEUE/iptables cleanup HOLD。

实验目的：在不做人工 root cleanup 的条件下，验证 APK 被 `am force-stop` 后，root
daemon 是否能自行退出、控制 socket 是否消失、规则残留是否可接受，以及 fresh
RuntimeService 是否能恢复。正式运行仍模拟 USB 断电，原始快照保留在本地结果目录。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 正式 run `20260719-094838`；`dumpsys battery unplug` 后 `USB powered: false`，结束
  cleanup/reset 后恢复为 `USB powered: true`。
- APK SHA-256：
  `14dbf9fa022ba503c7a78b57b0da18d4714fc760b8c062a77439993c4fabe845`。
- daemon artifact SHA-256：
  `5e2c6da707cf2c8cf2c9a11a5d152cb1b145c2ef3cdd7f1cb7db77db7023c198`。
- HELLO build id：`ndk-r29-f0c2da8f030e`。

### 失败方法与定位

1. 首次 `20260719-092709` 使用了旧 APK-native artifact，daemon 没有打印 parent-death
   guard；该 run 判为构建身份错误，不计入结论。先执行 `bash dev/dev-build-ndk.sh`，再
   打包 APK，并在结果中同时记录 APK/artifact hash。
2. 仅在 daemon 内调用 `prctl(PR_SET_PDEATHSIG, SIGTERM)`：正式前置 run
   `092955`、`093442`、`093643` 中 guard 日志存在，但 force-stop 后 daemon 仍为
   `PPID=1`，没有 `shutdown signal received`。把控制 socket 的无限 `poll` 改为 250ms
   超时没有改变结果。
3. 将 Java `snort-runtime-start` 线程改为在 HELLO 后 `Process.waitFor()`，使其在 daemon
   存活期间保持运行；`094511` 仍未观察到 PDEATHSIG。临时将信号换为不可捕获的
   `SIGKILL` 也未改变 orphan 结果，说明问题不是 SIGTERM handler 或 graceful loop。
4. 最终保留 PDEATHSIG 作为第一层保护，并增加每 100ms 一次的 `getppid()` monitor：记录
   创建时 parent PID；发现 parent 变化（本机表现为 reparent 到 PID 1）后设置同一
   shutdown flag，让控制 server、NFQUEUE worker 和 main-owned cleanup 收敛。

### 正式结果

```text
run_id: 20260719-094838
baseline_root_daemon_pid: 21895
baseline_parent_pid: 21857
after_force_stop: APK absent
after_force_stop: daemon absent without manual root cleanup
after_force_stop: abstract control socket absent
after_force_stop: sucre-snort_INPUT/OUTPUT and NFQUEUE rules remain
evidence: runtime log contains "parent monitor detected reparenting"
recovery_root_daemon_pid: 22123
recovered_runtime_stop: no root daemon
result: process containment pass
decision: HOLD network hook cleanup
```

原始证据：

```text
results/sakamoto-14-runtime-pdeath-20260719-094838/
```

### 结论与后续

S14 已解决“APK 死亡后 root daemon 孤儿化并继续占用控制 socket”的进程边界问题；
恢复链也已成立。它没有解决 iptables/NFQUEUE 规则的生命周期：`after-force-stop/hooks.txt`
仍包含 IPv4/IPv6 两组 `sucre-snort_INPUT/OUTPUT` 链及 queue-balance 规则。下一张 Android
POC 应只验证 daemon shutdown 时的 hook uninstall/rollback 顺序、部分安装失败和重复启动
幂等性；在该 POC 通过前，Android release handoff 继续 HOLD。

## SAKAMOTO-15：Android daemon shutdown 的 NFQUEUE hook cleanup

状态：实验通过；双栈 hook cleanup GO。Android release handoff 仍受 foreground service、
release signing、升级/回滚和 crash/tombstone 口径约束。

实验目的：在单台 Android 设备上验证 daemon 正常停止和 APK `am force-stop` 触发的
`getppid()` orphan monitor 都能完成 IPv4/IPv6 NFQUEUE hook 的 detach、flush、delete；
过程中不做人工 root cleanup，并验证 fresh RuntimeService 可恢复。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 正式 run `20260719-101700`；开始时执行 `dumpsys battery unplug`，所有关键快照均为
  `USB powered: false`；run 后发现初版 harness 未注册 `EXIT` cleanup，立即手工执行
  battery reset，`post-run-manual-reset.txt` 记录最终 `USB powered: true`。
- APK SHA-256：
  `31ba5429550070ba7943668fff5613f9b0d55d0a34b08e2d749e9786bd1a2c04`。
- daemon artifact SHA-256：
  `16e45499c0d9aa93af9b720b8c7db21db223fb2a9b34604e4e2f3e003bcdee58`。
- HELLO build id：`ndk-r29-7e61fe3f68b6`。

### 实现与验证

1. 新增独立 cleanup plan：按 IPv4、IPv6 顺序分别删除 INPUT/OUTPUT jump，flush 并删除
   `sucre-snort_INPUT` / `sucre-snort_OUTPUT`；不存在的 `-D/-F/-X` 对象按幂等成功处理。
2. `Ipv4PassThroughRuntime` 与 `DualStackPassThroughRuntime` 在 worker join 后执行 cleanup，
   因而 normal stop 和 orphan monitor shutdown 走同一条 main-owned destructor 路径。
3. host NFQUEUE 测试 13/13 通过，覆盖双栈命令顺序及缺失链 cleanup。
4. 正式 Android 流程依次验证：normal start hooks present；normal stop daemon/hooks absent；
   fresh restart hooks present；APK force-stop 后不做手工 root cleanup，daemon、control socket、
   hooks 均 absent，日志包含 `parent monitor detected reparenting` 和
   `Dual-stack NFQUEUE pass-through hook cleanup=pass`；最后 fresh recovery 与 stop 通过。

### 正式结果

```text
run_id: 20260719-101700
normal_start: IPv4/IPv6 chains and NFQUEUE rules present
normal_stop: no root daemon; no NFQUEUE hooks/chains; cleanup=pass
force_stop: daemon absent without manual cleanup; control socket absent
force_stop: no NFQUEUE hooks/chains; parent monitor detected reparenting
recovery: fresh RuntimeService start and stop passed; no daemon/hooks remained
result: pass
decision: SAKAMOTO-15 cleanup GO; product release handoff remains gated by separate lifecycle POCs
```

原始证据：

```text
results/sakamoto-15-runtime-hook-cleanup-20260719-101700/
```

### 失败方法与边界

- 启动阶段日志中的 `Chain already exists` 属于重复安装的幂等分支，不影响启动结果；正式
  stopped/force-stopped 快照确认链和 jump 最终均已消失。
- 正式 run 通过后发现 harness 初版定义了 cleanup 函数但没有注册 `trap cleanup EXIT`，因此
  自动 reset 未执行；该设备状态已立即手工恢复并留存 `post-run-manual-reset.txt`，随后补上
  `EXIT` trap，后续失败时也会恢复电源模拟状态。这个 harness 问题不影响本轮的断电快照结论。
- 本轮只覆盖一台 Pixel 6a、当前 KernelSU 授权和当前双栈 pass-through 规则；未覆盖部分
  安装后进程崩溃、权限拒绝、重复 jump、升级/回滚及 release APK。
- `HookCommandExecutor` 当前只返回 bool，因此缺失对象的错误按命令类型归类为幂等清理；
  后续若需要区分 permission denied，必须扩展命令结果，而不是继续扩大忽略范围。

## SAKAMOTO-16：Android RuntimeService repeated lifecycle residue baseline

状态：实验通过；短周期重复启停与 force-stop/recovery GO。长稳、foreground service、Doze、
升级/回滚和 SIGKILL cleanup 不在本轮范围内。

实验目的：在单台 Android 设备上用 5 次短 normal start/stop 验证 lifecycle 与 hook cleanup
可重复；先预置 IPv4/IPv6 私有链和顶层 jump，确认安装逻辑不会叠加重复 jump；最后执行一次
APK force-stop 和 fresh RuntimeService recovery。全程不做人工 root cleanup，结束由 harness
自动恢复 USB 电源模拟。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 正式 run `20260719-104415`；关键快照为 `USB powered: false`，结束快照为
  `USB powered: true`。
- APK SHA-256：
  `170d9623fd85211c9ef076a7c0039b1b2e9b8cf8e6c135c47c7e730c3543c062`。
- daemon artifact SHA-256：
  `44b34d15b601029fe2434f1358939163dc829f6f0d3e27913fa9597c06f52dd0`。
- HELLO build id：`ndk-r29-93b6441aa676`。

### 正式结果

```text
run_id: 20260719-104415
preexisting_state: IPv4/IPv6 private chains and 4 top-level jumps present
cycle_1_to_5: HELLO pass; exactly 4 top-level jumps while running
cycle_1_to_5_stop: no root daemon; no control socket; no NFQUEUE hooks/chains; cleanup=pass
force_stop: daemon absent without manual cleanup; hooks/socket absent
force_stop: parent monitor detected reparenting
recovery: fresh RuntimeService start/stop passed; no residue
result: pass
decision: SAKAMOTO-16 short lifecycle repeatability GO
```

原始证据：

```text
results/sakamoto-16-runtime-repeat-20260719-104415/
```

### 失败方法与定位

1. `20260719-103437` 在预置链阶段因 harness 多行 `adb_su` quoting 提前退出；`EXIT` trap
   已恢复设备，未计入结论。改为逐条 root command，并将原始输出落盘。
2. `20260719-103608` 的 5 次 normal cycle 全部通过，但旧预置命令未真正生效，force-stop
   场景还暴露了前一轮 delayed `runtimeStop` intent 与下一次 `runtimeStart` 的竞态；不计入
   正式结果。独立 fresh start 复验通过。
3. `20260719-104053` 的 5 次 normal cycle 全部通过；在清空 Activity 进程前直接进入最后
   force-stop 场景时 HELLO gate 超时。最终 harness 在该场景前先 force-stop Activity、等待
   进程状态收敛，并在每次 stop 后等待 delayed intent 排空。
4. 正式 run 验证预置状态归一化为每个 family 一个 INPUT/OUTPUT jump；5 次 normal stop 和
   force-stop 均通过 cleanup，不把上述 harness 失败误报为产品失败。

## SAKAMOTO-17：Android daemon SIGTERM/SIGKILL cleanup boundary

状态：实验完成；SIGTERM cleanup GO，SIGKILL 自动 cleanup HOLD。该 POC 只判断退出信号与
网络 hook 残留边界，不把人工 root cleanup 计入自动清理能力。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 正式 run `20260719-105412`；运行中关键快照为 `USB powered: false`，结束 reset 后为
  `USB powered: true`。
- APK SHA-256：
  `6c1c374af2a7124c95b421f7fc648c7d233f28d74c2784539d2cc1aeb450d7dd`。
- daemon artifact SHA-256：
  `12eaba5c376fdb7a629dce937500faefde3730115cfcee3a42596cfc5719df7f`。
- `versionName=0.1-debug`。

### 正式结果

```text
run_id: 20260719-105412
SIGTERM: daemon exits; control socket absent; NFQUEUE hooks absent; destructor cleanup log=pass
SIGTERM recovery: fresh RuntimeService start/stop and hook cleanup pass
SIGKILL: daemon and control socket exit; NFQUEUE hooks remain before manual cleanup
SIGKILL: destructor cleanup log absent, as expected for uncatchable signal
manual root cleanup: hooks removed; fresh RuntimeService recovery and final stop pass
result: graceful cleanup pass; forced-kill cleanup boundary HOLD
```

原始证据：

```text
results/sakamoto-17-daemon-signal-boundary-20260719-105412/
```

### 失败方法与定位

1. `20260719-105036` 使用无 `-W` 的 `am start`，启动阶段受 Android Activity 返回时序影响而
   超时；手工使用 `am start -W` 后运行正常，不计入产品结论。
2. `20260719-105216` 已观察到 SIGKILL 后 hook 残留，但 harness 的多行 `adb_su` 清理命令
   未实际执行；恢复阶段随后清掉了设备，不能把该轮当作手工清理证据。
3. 最终 harness 改为逐条 root 命令，并使用 `am start -W`；正式 run 完整记录了 SIGKILL
   后残留、无 destructor cleanup log、显式清理及 fresh recovery。

### 技术结论

SIGTERM 路径可以依赖 daemon destructor 完成 NFQUEUE cleanup；SIGKILL 路径不能运行析构函数，
因此 daemon/socket 消失并不等价于网络 hook 已清理。后续 Android handoff 必须在 supervisor、
service stop 或独立 root cleanup 边界上补齐异常终止兜底，再进入 release 评估。

## SAKAMOTO-18：RuntimeService foreground/background lifecycle smoke

状态：实验完成；短周期后台/锁屏存活与数据面 smoke GO，foreground service 能力 HOLD。

实验目的：确认 RuntimeService 在 Activity 退到后台、短暂锁屏期间是否保持 daemon、控制 socket、
双栈 NFQUEUE hook 与一次数据面探针一致，并判断当前实现是否已经满足 Android foreground-service
的基本状态要求。

### 固定条件

- Pixel 6a / Android 16 / `arm64-v8a` / package UID `12540`。
- 正式 run `20260719-110315`；后台与锁屏快照期间为 `USB powered: false`，结束 reset 后为
  `USB powered: true`。
- APK SHA-256：
  `b8f7f26ec2b75ef38a3855409ac93cb2246a51bf4c0249968a3312c0fa5f1ba1`。
- daemon artifact SHA-256：
  `646d1697c25cd0e98cefd56ba3ee40c2c580971e5a09a26a57c1afa4f293755e`。
- HELLO build id：`ndk-r29-aa4c8b15f7ac`；`versionName=0.1-debug`。

### 正式结果

```text
run_id: 20260719-110315
RuntimeService start/HELLO: pass
started: daemon/socket/NFQUEUE hooks present; foreground_service=absent; notification=absent
data_plane: adb reverse 127.0.0.1:18080 -> host one-shot HTTP 200, elapsedMs=9
background after HOME + 3s: daemon/socket/NFQUEUE hooks present
locked for 5s: daemon/socket/NFQUEUE hooks present; foreground_service=absent; notification=absent
controlled stop: no daemon; socket absent; NFQUEUE hooks absent
result: lifecycle smoke pass; foreground-service product requirement HOLD
```

原始证据：

```text
results/sakamoto-18-runtime-foreground-20260719-110315/
```

### 失败方法与定位

1. `20260719-110053` 首轮使用外部 `142.251.13.94:80` 作为 HTTP 目标，5 秒连接超时；
   RuntimeService 的 HELLO、hook、后台/锁屏和停止状态均正常，但外部网络可达性不应混入本
   POC，因此该轮不作为数据面结论。
2. 最终 run 改用 `adb reverse` 连接主机一次性 HTTP server，收到 `HTTP/1.0 200 OK`，
   消除了外部网络变量。

### 技术结论

当前普通 `Service` 可在短暂 HOME 与锁屏期间保持 root daemon、抽象控制 socket 和双栈
NFQUEUE hook，短数据面链路也可用；但 manifest/service 没有 foreground-service 实现，
`dumpsys activity services` 显示 `startForegroundCount:0`，未观察到本包通知。因而后台短 smoke
不能替代正式 Android foreground-service；需要补齐 `startForeground`、notification channel、
manifest 类型及对应停止/升级策略后，才能解除 release handoff 的 HOLD。
