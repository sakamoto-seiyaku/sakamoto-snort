# Android VPN fd -> VPP -> HEV Experiment Log

日期：2026-06-22
分支：`research/vpp-nfq-poc`

本文记录 Android VPN mode POC 的原始过程。记录按时间顺序追加，避免重复踩坑。

## 1. 实验启动

目标：

```text
构建一个非常简易的 Android VPN 客户端。
申请 full-route VPN。
把 VPN tun-fd 交给 native/VPP。
VPP 做 packet interception。
allow packet 进入 HEV shim。
HEV 回包先回到 VPP，再写回 tun-fd。
```

三阶段拆分：

```text
Phase 1: VPN app + fd lifecycle，不启动 VPP/HEV。
Phase 2: VPN fd -> VPP main tun fd，不启动 HEV。
Phase 3: VPN fd -> VPP -> HEV shim -> VPP -> VPN fd。
```

## 2. 当前仓库状态

命令：

```sh
git status --short --branch
```

结果：

```text
## research/vpp-nfq-poc
```

结论：

```text
进入 Android VPN 实验前工作区干净。
```

## 3. 设备状态

命令：

```sh
source dev/dev-android-device-lib.sh
adb_target_desc
adb shell getprop ro.build.version.sdk
adb shell getprop ro.product.model
adb_su id
```

结果：

```text
serial: 28201JEGR0XPAJ
api: 36
model: Pixel 6a
root: uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0
```

结论：

```text
仍使用此前 Android VPP POC 的 Pixel 6a / Android 16 / root 设备。
```

## 4. 本机 Android 构建环境观察

已观察：

```text
Java 17 可用。
adb 可用。
NDK r29 位于 /home/js/.local/share/android-sdk/ndk/29.0.14206865。
未在当前常规 SDK 路径中发现 Gradle。
未在当前常规 SDK 路径中确认 aapt2 / apksigner / d8 build-tools。
系统有 /usr/bin/zipalign。
```

另有：

```text
/home/js/android/lineage/prebuilts/r8/d8
/home/js/android/lineage/prebuilts/sdk/36/public/android.jar
/home/js/android/lineage/prebuilts/sdk/tools/linux/bin/aapt2
/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/d8.jar
/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/apksigner.jar
```

判断：

```text
优先参考 miopunch 的无 Gradle APK 打包方式。
当前可以直接使用 Lineage prebuilts 中的 Android SDK 工具。
```

## 5. miopunch control-lite 参考

参考目录：

```text
/home/js/Git/miopunch/android/control-lite
```

关键文件：

```text
README.md
RUNBOOK.md
scripts/build-debug-apk.sh
scripts/install-debug-apk.sh
src/main/AndroidManifest.xml
src/main/java/com/miopunch/controlite/MainActivity.java
```

可复用做法：

```text
1. 不依赖 Gradle。
2. build-debug-apk.sh 直接调用 javac / d8 / aapt2 / zipalign / apksigner。
3. native payload 放进 lib/arm64-v8a/libmiopunch.so。
4. AndroidManifest.xml 使用 android:extractNativeLibs="true"。
5. Activity 通过 getApplicationInfo().nativeLibraryDir 找到 payload。
6. install-debug-apk.sh 只负责 adb install -r。
```

对本实验的映射：

```text
miopunch libmiopunch.so
  -> vpn-lite libsnort_vpn_poc.so 或 libvpn_fd_probe.so

miopunch Activity 启动 child process
  -> vpn-lite Activity 启动 VpnService，Service detach fd 后启动 native helper

miopunch 无 Gradle packaging
  -> vpn-lite 也先无 Gradle，避免工具链扩张
```

## 6. 下一步

```text
1. 创建 experiments/vpp-nfq-poc/android/vpn-lite 骨架。
2. 复用 miopunch build 脚本结构，先让空 Activity APK 可构建/安装。
3. 增加 VpnService.prepare()/establish()/detachFd()。
4. 增加 native vpn_fd_probe，只读取 packet header 并打印日志。
5. 在真机上验证 Phase 1。
```

## 7. Phase 1 实现决策

Phase 1 先使用 JNI 而不是 child process：

```text
原因：
  Java ProcessBuilder 不适合可靠继承任意 detached tun-fd 给子进程。
  Phase 1 只需要证明 fd lifecycle 和 L3 packet 可读，不需要启动 VPP。

形态：
  VpnService.establish() -> ParcelFileDescriptor.detachFd()
    -> JNI nativeStartProbe(fd, logPath, maxPackets)
    -> native thread read(fd) 并记录 packet header
```

这和 miopunch 的共同点仍然是：

```text
无 Gradle APK 打包。
native payload 打进 lib/arm64-v8a。
extractNativeLibs=true。
```

不同点：

```text
miopunch 的 native payload 是可执行 CLI。
vpn-lite Phase 1 的 native payload 是 JNI shared library。
Phase 2 再解决 raw fd 交给 VPP child process / wrapper 的问题。
```

## 8. Phase 1 APK 构建结果

命令：

```sh
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

结果：

```text
building JNI probe
compiling Java sources
dexing
linking APK
zipalign
signing
ok: experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk
```

结论：

```text
无 Gradle APK 构建链路可用。
JNI probe 已打包进 lib/arm64-v8a/libvpnfdprobe.so。
```

## 9. Phase 1 真机安装结果

命令：

```sh
bash experiments/vpp-nfq-poc/android/vpn-lite/scripts/install-debug-apk.sh
```

结果：

```text
Performing Incremental Install
Success
ok: installed experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk
```

结论：

```text
APK 可安装到 Pixel 6a / Android 16 设备。
```

## 10. Phase 1 VPN 授权与 fd probe 结果

启动命令：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true
```

系统弹出 Android VPN 授权窗口：

```text
package: com.android.vpndialogs
title: 网络连接请求
requester: Snort VPN Lite
```

授权后 connectivity 关键状态：

```text
VPN CONNECTED extra: VPN:com.sakamoto.snort.vpnlite
InterfaceName: tun0
LinkAddresses: [ 10.111.0.2/32 ]
Routes: [ 0.0.0.0/0 -> 0.0.0.0 tun0 ... ]
Uids: <{0-99999}>
```

native logcat 关键输出：

```text
I SnortVpnLite: nativeStartProbe fd=125 rc=0 log=/data/user/0/com.sakamoto.snort.vpnlite/files/logs/vpn-fd-probe.log
I SnortVpnLiteNative: probe start fd=125 max_packets=32
I SnortVpnLiteNative: packet=1 len=76 ipv6 next=0 fe80::335f:911f:e82e:92f -> ff02::16
I SnortVpnLiteNative: packet=4 len=60 ipv4 proto=6 10.111.0.2 -> 74.125.195.188
I SnortVpnLiteNative: packet=8 len=84 ipv4 proto=1 10.111.0.2 -> 1.1.1.1
```

probe 文件：

```text
/data/data/com.sakamoto.snort.vpnlite/files/logs/vpn-fd-probe.log
```

结论：

```text
Phase 1 通过。
Android VpnService 建立的是 L3 tun-fd。
detachFd() 后 JNI/native thread 可以直接 read(fd) 得到 IPv4/IPv6 L3 packet。
full-route VPN 未接转发时会黑洞流量；实验结束后已 force-stop app，VPN 状态清空。
```

## 11. Phase 2 入口

下一步目标：

```text
把同一个 Android VpnService detached fd 交给 VPP/tun_poc。
第一轮只做 count-only，验证 VPP 能消费 Android VPN tun-fd。
暂不接 HEV。
暂不要求设备外网可用。
```

## 12. Phase 2 准备：Android tun_poc plugin

变更：

```text
overlay/src/plugins/tun_poc/CMakeLists.txt
  SUPPORTED_OS_LIST Linux Android

scripts/android-stage-vpp-core.sh
  stage nfqueue_poc_plugin.so 和 tun_poc_plugin.so
  startup.conf 中启用所有已 stage 的 POC plugin
```

构建命令：

```sh
cd experiments/vpp-nfq-poc
VPP_PLUGINS="nfqueue_poc;tun_poc" ./scripts/android-configure-vpp-probe.sh
./scripts/android-build-vpp-probe.sh
TARGET=vppctl ./scripts/android-build-vpp-probe.sh
TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh
TARGET=tun_poc_plugin ./scripts/android-build-vpp-probe.sh
./scripts/android-stage-vpp-core.sh
```

构建结果：

```text
cmake_rc=0
vpp build_rc=0
vppctl build_rc=0
nfqueue_poc_plugin build_rc=0
tun_poc_plugin build_rc=0
stage size: 186M
plugins:
  nfqueue_poc_plugin.so: 72K
  tun_poc_plugin.so: 21K
```

root 启动验证：

```text
VPP pid: 22952
vppctl show version: rc=0
vpp v26.02-release built by js on Main at 2026-06-22T02:38:52
```

`show tun-poc`：

```text
enabled 0 fd -1 mode count-only
rx 0 bytes 0 tx 0 bytes 0
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 write-errors 0
```

结论：

```text
Android VPP runtime 已可加载 tun_poc plugin。
这一步只验证插件存在与 CLI 可用，尚未把 Android VpnService fd 传给 VPP。
```

## 13. Phase 2 下一步：APK 内 fd -> VPP

下一步最小实现：

```text
1. vpn-lite APK 打包 VPP runtime：
   - libvpppoc.so 作为 executable payload，对应 staged bin/vpp；
   - libvppctlpoc.so 可选，第一轮 JNI 可不依赖 vppctl；
   - VPP dependent libs 和 plugin .so 放进 nativeLibraryDir。
2. SnortVpnService 增加 VPP probe 模式：
   - establish() -> detachFd();
   - native fork();
   - child dup2(rawFd, 3);
   - child execve(nativeLibraryDir/libvpppoc.so, ... -c app files startup.conf);
   - startup.conf plugin path 指向 nativeLibraryDir；
   - 启动后执行/注入 tun-poc enable fd 3 mode count-only。
3. 第一轮验收只看：
   - VPP 进程由 app/VpnService 启动；
   - tun-poc enable fd 3 成功；
   - 产生流量后 show tun-poc rx 增长；
   - 停止服务能杀掉 VPP，VPN 清空。
```

待确认风险：

```text
app UID 下 VPP shm/runtime 目录是否能稳定创建。
app context 下 exec nativeLibraryDir 中的 VPP executable 是否被 SELinux 允许。
VPP CLI socket 由 app 自己使用时是否需要 vppctl，还是 native 内直接写 startup exec file。
```

## 14. Phase 2 实现：APK 内 fd -> VPP count-only

实现变更：

```text
vpn-lite build-debug-apk.sh:
  如果存在 work/android-vpp-core-stage，则把 VPP runtime 打包进 APK：
    libvpppoc.so        <- staged bin/vpp
    libvppctlpoc.so     <- staged bin/vppctl
    libvnet/libvlib/... <- VPP dependent libs
    tun_poc_plugin.so   <- VPP plugin

SnortVpnService:
  新增 mode=vpp。
  默认 mode=native 保留 Phase 1 行为。

vpn_fd_probe.c:
  nativeStartVppProbe(fd, nativeLibraryDir, filesDir)
  fork child:
    dup2(detached tun-fd, 3)
    LD_LIBRARY_PATH=nativeLibraryDir
    SAKAMOTO_ANDROID_SHM_DIR=files/vpp/shm
    exec nativeLibraryDir/libvpppoc.so -c files/vpp/runtime/startup.conf
  startup-config 自动执行：
    tun-poc enable fd 3 mode count-only
  monitor thread 通过 VPP CLI socket 周期性执行：
    show tun-poc
```

Android 特有修正：

```text
1. app UID 不能写 /data/local/tmp/vpp-shm。
   处理：Android shm file backend 支持 SAKAMOTO_ANDROID_SHM_DIR 环境变量。

2. untrusted_app seccomp 禁止 arm64 syscall 236 get_mempolicy。
   处理：Android 下禁用 VPP NUMA get/set_mempolicy 路径，固定使用 numa node 0。

3. APK extracted native dir 可以包含 tun_poc_plugin.so。
   实机确认 package manager 会提取非 lib* 前缀的 .so entry。
```

构建与安装：

```text
building JNI probe
packaging VPP runtime
compiling Java sources
dexing
linking APK
zipalign
signing
ok: experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk

Performing Incremental Install
Success
```

启动命令：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp
```

关键 logcat：

```text
I SnortVpnLiteNative: started VPP pid=23811 fd=126 conf=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/startup.conf
I SnortVpnLite: nativeStartVppProbe fd=126 rc=0
I SnortVpnLiteNative: vpp monitor start pid=23811 cli=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/cli.sock
I SnortVpnLiteNative: vpp monitor stop
```

`show tun-poc` 采样：

```text
enabled 1 fd 3 mode count-only
rx 7 bytes 472 tx 0 bytes 0
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 write-errors 0

enabled 1 fd 3 mode count-only
rx 10 bytes 664 tx 0 bytes 0
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 write-errors 0

enabled 1 fd 3 mode count-only
rx 11 bytes 724 tx 0 bytes 0
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 write-errors 0
```

结论：

```text
Phase 2 count-only 通过。
Android VpnService detached L3 tun-fd 可以通过 fork/exec 传给 APK 内 VPP。
VPP/tun_poc 可以在 app context 下 enable fd 3，并从该 fd 读到 VPN packet。
当前模式只读不转发，因此 full-route VPN 期间设备流量仍会被黑洞；实验结束已 force-stop app。
```

## 15. Phase 3 入口：VPP -> HEV -> VPP

下一步目标：

```text
保留当前 main tun-fd -> VPP owner 模型。
在 VPP 内把 allow packet 写入 HEV shim fd。
HEV 回包从 shim fd 回到 VPP。
VPP 再写回 Android main tun-fd。
```

下一步最小验收：

```text
1. VPP mode 增加 forward-to-shim，而不是 count-only。
2. APK/native 创建 SOCK_SEQPACKET socketpair。
3. HEV 使用 socketpair 一端作为 external tun_fd。
4. VPP/tun_poc 使用另一端作为 HEV shim fd。
5. 观测 outbound rx、shim tx、shim rx、main tun tx 均增长。
```

## 16. Linux Phase 3 前置结果同步

Android 真机实验前，先在 Linux/Docker 完成了三组前置验证。

```text
POC-C1:
  synthetic packet driver -> SOCK_SEQPACKET shim -> HEV -> SOCKS5 -> HEV -> SOCK_SEQPACKET shim
  已通过。

POC-C2:
  main TUN fd -> VPP/tun_poc forward-fd -> SOCK_SEQPACKET shim
  SOCK_SEQPACKET shim -> VPP/tun_poc forward-fd -> main TUN fd
  已通过。

POC-C3:
  curl/Linux TCP -> main TUN fd -> VPP -> HEV -> SOCKS5 -> HEV -> VPP -> main TUN fd -> curl
  已通过一次完整 HTTP flow。
```

POC-C3 关键结果：

```text
curl output:
  OK

SOCKS event:
  connect 93.184.216.34:80
  payload includes GET /probe HTTP/1.0

show tun-poc after curl:
  enabled 1 fd 53 shim-fd 54 mode forward-fd
  rx 7 bytes 390 tx 6 bytes 284
  shim-rx 6 bytes 284 shim-tx 7 bytes 390
  errors all 0
```

保留风险：

```text
HEV stderr/stdout:
  free(): invalid size

当前判断：
  datapath 已经成立。
  但 HEV lifecycle/memory 行为不能视为干净，需要在 Android 3A 单独验证。
```

## 17. Android Phase 3 执行计划

```text
Step 3A：Android HEV 打包和最小 lifecycle probe
  目标：
    HEV Android .so 进入 vpn-lite APK。
    JNI 能启动 HEV main_from_str(socketpair fd)。
    先验证依赖、符号、启动、停止、stderr/log。
  不接 VPP 主 fd，不承诺 datapath。

Step 3B：Android VPP forward-fd bridge
  目标：
    VpnService fd -> VPP main fd。
    socketpair VPP 端 -> tun_poc shim-fd。
    使用本地 probe/driver 或受控 packet 验证四向计数。
  不先把 HEV 混进来。

Step 3C：Android VPP + HEV full datapath
  目标：
    VpnService fd -> VPP -> HEV -> SOCKS5/upstream -> HEV -> VPP -> VpnService fd。
    先用受控 SOCKS5 endpoint。
    再处理 Android VpnService.protect()，防止 HEV upstream socket 被 VPN 自己截回。
```

## 18. Android Phase 3A：HEV 打包和 lifecycle probe

目标：

```text
只验证 HEV Android .so 能进入 APK，并能在 Android app context 下由 JNI 启动/停止。
不申请 VPN。
不接 VPP。
不验证 datapath。
```

实现：

```text
新增 scripts/android-build-hev.sh：
  使用 HEV upstream Android.mk。
  NDK ndk-build APP_ABI=arm64-v8a APP_PLATFORM=android-31。
  stage:
    work/android-hev-stage/lib/arm64-v8a/libhev-socks5-tunnel.so

vpn-lite build-debug-apk.sh：
  如果 android-hev-stage 存在，把 libhev-socks5-tunnel.so 打进 APK。

vpn-lite native：
  nativeStartHevProbe(nativeLibraryDir, filesDir)
    socketpair(AF_UNIX, SOCK_SEQPACKET)
    fork child
    child dlopen libhev-socks5-tunnel.so
    dlsym hev_socks5_tunnel_main_from_str
    传 socketpair child fd 作为 HEV external tun_fd
  nativeStopHevProbe()
    close parent socketpair fd
    wait / SIGTERM / SIGKILL child

Activity:
  支持 mode=hev，不走 VpnService.prepare()。
  支持 --ez stop true，方便 adb 触发 Stop。
```

构建：

```text
make android-hev-build

结果：
  work/android-hev-stage/lib/arm64-v8a/libhev-socks5-tunnel.so
  size: 313.7K
  ELF: ARM aarch64 shared object, stripped
  dynamic deps: libc.so, libm.so, libdl.so
```

APK：

```text
experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh

关键输出：
  building JNI probe
  packaging VPP runtime
  packaging HEV runtime
  compiling Java sources
  dexing
  linking APK
  zipalign
  signing
  ok: .../snort-vpn-lite-debug.apk

APK 内容确认：
  lib/arm64-v8a/libhev-socks5-tunnel.so
```

设备验证：

```text
设备：
  28201JEGR0XPAJ
  Pixel 6a / Android 16

安装：
  experiments/vpp-nfq-poc/android/vpn-lite/scripts/install-debug-apk.sh
  Success

启动 HEV probe：
  adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode hev

logcat:
  I SnortVpnLiteNative: started HEV pid=24901 log=/data/user/0/com.sakamoto.snort.vpnlite/files/logs/hev-probe.log
  I SnortVpnLite: nativeStartHevProbe rc=0

进程：
  app parent exists
  HEV child exists under same app uid

HEV log:
  [2026-06-22 11:47:01] [I] set limit nofile

停止：
  adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez stop true

logcat:
  I SnortVpnLiteNative: stopped HEV pid=24901 log=/data/user/0/com.sakamoto.snort.vpnlite/files/logs/hev-probe.log
  I SnortVpnLite: VPN stopped

停止后：
  HEV child 不再存在。
  最后 force-stop app 清理 Activity parent。
```

结论：

```text
Android Phase 3A 通过。
HEV Android .so 可以构建、打包、dlopen、启动并停止。
本轮没有观察到 Linux C3 中的 free(): invalid size。
但 3A 没有流量，不代表 HEV Android datapath/lifecycle 已完全干净。
下一步进入 3B：Android VPP forward-fd bridge。
```

## 19. Android Phase 3B：VPP forward-fd bridge

目标：

```text
验证 Android VpnService fd -> VPP main fd -> SOCK_SEQPACKET shim fd 的双向桥接。
本阶段不接 HEV。
shim 另一端由 native probe 持有，只记录 packet，并对 IPv4 ICMP echo 做本地反射。
```

实现：

```text
新增 mode：
  vpp-forward

Java:
  mode=vpp-forward 仍走 VpnService.prepare() 和 full-route VPN。
  nativeStartVppProbe(fd, nativeLibraryDir, filesDir, forwardMode=true)

native:
  socketpair(AF_UNIX, SOCK_SEQPACKET)
  VPP child:
    fd 3 = Android VpnService detached tun-fd
    fd 4 = socketpair VPP end
  VPP startup.exec:
    tun-poc enable fd 3 mode forward-fd shim-fd 4
    show tun-poc
  parent:
    shim driver thread reads socketpair peer
    logs packets into files/vpp/logs/vpp-shim.log
    reflects IPv4 ICMP echo requests back into socketpair
```

构建：

```text
重新同步 overlay：
  scripts/apply-vpp-overlay.sh
  scripts/apply-vpp-android-overlay.sh

重新构建 Android tun_poc_plugin：
  TARGET=tun_poc_plugin ./scripts/android-build-vpp-probe.sh

重新 stage：
  ./scripts/android-stage-vpp-core.sh

重新构建 APK：
  android/vpn-lite/scripts/build-debug-apk.sh
```

Android 启动：

```text
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp-forward
```

关键 logcat：

```text
I SnortVpnLiteNative: started VPP pid=25099 fd=126 forward=1 conf=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/startup.conf
I SnortVpnLite: nativeStartVppProbe fd=126 forward=true rc=0
I SnortVpnLiteNative: vpp shim driver start fd=125
I SnortVpnLiteNative: vpp monitor start pid=25099 cli=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/cli.sock
```

shim driver 观察到 VPP 转出的真实 VPN 包：

```text
packet=4 len=60 ipv4 proto=6 10.111.0.2 -> 74.125.135.188
packet=7 len=1278 ipv4 proto=17 10.111.0.2 -> 216.239.34.223
...
```

ICMP 反射测试：

```text
adb shell ping -c 1 -W 2 1.1.1.1

结果：
  1 packets transmitted, 1 received, 0% packet loss
  64 bytes from 1.1.1.1: icmp_seq=1 ttl=64

shim log:
  packet=38 len=84 ipv4 proto=1 10.111.0.2 -> 1.1.1.1
  shim reflected icmp len=84 written=84
```

实时 VPP 计数：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 41 bytes 20867 tx 1 bytes 84
shim-rx 1 bytes 84 shim-tx 41 bytes 20867
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

停止：

```text
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez stop true

logcat:
  I SnortVpnLiteNative: vpp shim driver stop packets=43
  I SnortVpnLite: VPN stopped

停止后：
  无 VPP child 残留。
  最后 force-stop app 清理 Activity parent。
```

结论：

```text
Android Phase 3B 通过。
Android VpnService fd 可以由 VPP/tun_poc forward-fd 桥到 SOCK_SEQPACKET shim。
main rx -> shim tx 成立：真实 VPN 包进入 shim driver。
shim rx -> main tx 成立：shim driver 写回 ICMP reply，VPP 写回 main tun-fd，ping 收到 reply。
下一步进入 3C：把 shim driver 替换为 HEV。
```

## 20. Android Phase 3C：VPP + HEV full datapath

目标：

```text
把 3B 的 native shim driver 替换为 HEV。
验证 Android 真机上完整路径：
  Android TCP client
    -> VpnService main tun-fd
    -> VPP/tun_poc forward-fd
    -> SOCK_SEQPACKET shim
    -> HEV
    -> SOCKS5 server
    -> HEV
    -> VPP/tun_poc forward-fd
    -> main tun-fd
    -> Android TCP client
```

实现：

```text
新增 mode：
  vpp-hev

Java:
  mode=vpp-hev -> nativeStartVppProbe(..., vppMode=2)

native:
  VPP child:
    fd 3 = Android VpnService detached tun-fd
    fd 4 = socketpair VPP end
    startup.exec:
      tun-poc enable fd 3 mode forward-fd shim-fd 4
  HEV child:
    socketpair HEV end as external tun_fd
    dlopen libhev-socks5-tunnel.so
    hev_socks5_tunnel_main_from_str(config, fd)
    SOCKS5 upstream:
      127.0.0.1:41080
```

重要路径调整：

```text
原计划先尝试 adb reverse tcp:41080 tcp:41080，让 HEV 连接设备 127.0.0.1:41080 到宿主机 SOCKS5。
实际验证中，该设备/ADB 组合下 adb reverse 没有打到宿主机监听端口。
因此改为设备本机 SOCKS5 smoke server：
  scripts/android-socks5-smoke-server.c
  scripts/android-build-socks5-smoke-server.sh
  make android-socks5-smoke-server-build
```

设备 SOCKS5 smoke server：

```text
监听：
  127.0.0.1:41080

行为：
  接 SOCKS5 no-auth。
  记录 CONNECT 目标和 payload。
  返回固定：
    HTTP/1.0 200 OK
    Content-Length: 2

    OK
```

验证命令摘要：

```text
make android-socks5-smoke-server-build
adb push build/android-socks5-smoke-server /data/local/tmp/sakamoto-socks5-smoke
adb shell chmod 755 /data/local/tmp/sakamoto-socks5-smoke
adb shell 'nohup /data/local/tmp/sakamoto-socks5-smoke > /data/local/tmp/sakamoto-socks5-smoke.log 2>&1 < /dev/null &'

android/vpn-lite/scripts/install-debug-apk.sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp-hev

printf 'GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n' |
  adb shell nc -w 5 -W 5 93.184.216.34 80
```

HTTP client 结果：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
```

logcat：

```text
I SnortVpnLiteNative: started VPP HEV pid=26026 log=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp-hev.log
I SnortVpnLiteNative: started VPP pid=26025 fd=126 mode=2 conf=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/startup.conf
I SnortVpnLite: nativeStartVppProbe fd=126 vppMode=2 rc=0
I SnortVpnLiteNative: vpp monitor start pid=26025 cli=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/cli.sock
```

SOCKS5 smoke server log：

```text
android socks5 smoke server ready 127.0.0.1:41080

accepted
greeting ok
connect 74.125.142.188:5228
payload-len 532
  background Google/mtalk TLS flow

accepted
greeting ok
connect 93.184.216.34:80
payload-len 43
GET /probe HTTP/1.0
Host: example.test
```

VPP/tun_poc 计数：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 21 bytes 1650 tx 11 bytes 556
shim-rx 11 bytes 556 shim-tx 21 bytes 1650
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

HEV log：

```text
[2026-06-22 13:14:18] [I] set limit nofile
[2026-06-22 13:14:21] [I] ... socks5 client tcp -> [74.125.142.188]:5228
[2026-06-22 13:14:23] [I] ... socks5 client tcp -> [93.184.216.34]:80
```

停止：

```text
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez stop true
adb shell am force-stop com.sakamoto.snort.vpnlite
adb shell pkill -f sakamoto-socks5-smoke

logcat:
  I SnortVpnLiteNative: stopped HEV pid=26026 log=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp-hev.log
  I SnortVpnLite: VPN stopped

停止后：
  无 VPP / HEV / app / socks5 smoke server 残留。
```

结论：

```text
Android Phase 3C 通过。
Android 真机上，VpnService fd + VPP forward-fd + HEV + SOCKS5 的完整 datapath 已经成立。
本轮未观察到 Linux C3 中的 free(): invalid size。

仍需后续单独设计：
  1. 正式 upstream socket protect() 路径，而不是测试用设备本机 SOCKS5。
  2. HEV lifecycle 压测和多连接场景。
  3. 将 POC 经验回收进正式 runtime/owner 边界，而不是直接搬实验代码。
```

## 21. Android Phase 3C 在 VPP idle profile 下复测通过

时间：2026-06-23

背景：

```text
VPP Android runtime 后续增加了 SAKAMOTO_VPP_ANDROID_IDLE_PROFILE。
该 profile 会调整 VLIB timer tick、idle epoll max timeout，并禁用一组默认 process timer。
需要确认它没有破坏 VPN/TUN/HEV datapath。
```

复测入口：

```text
VPP_STAGE_DIR=$PWD/experiments/vpp-nfq-poc/work/android-vpp-release-no-multiarch-no-ipsec-idle-stage \
  experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh

experiments/vpp-nfq-poc/android/vpn-lite/scripts/install-debug-apk.sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp-hev
```

HTTP probe：

```text
printf 'GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n' |
  adb shell nc -w 5 -W 5 93.184.216.34 80
```

结果：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
```

VPP/tun_poc：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 15 bytes 1359 tx 5 bytes 252
shim-rx 5 bytes 252 shim-tx 15 bytes 1359
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

idle CPU after request：

```text
VPP child:
  avg=0.030% over 60s

HEV child:
  avg=0.000% over 60s
```

结论：

```text
Android Phase 3C 在 VPP idle profile 下仍通过。
完整 VPN datapath 未被 idle profile 破坏。
详细原始记录见 ANDROID_TRIM_EXPERIMENT_LOG.md 的 Round 4J。
```
