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
