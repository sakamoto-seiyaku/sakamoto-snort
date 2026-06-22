# Android VPN fd -> VPP -> HEV Experiment Plan

日期：2026-06-22
分支：`research/vpp-nfq-poc`
状态：Phase 1 已实现并在 Pixel 6a / Android 16 上通过；Phase 2 待开始。

## 1. 目标

验证 Android VPN mode 下的完整包路径是否可行：

```text
Android VpnService 建立 full-route VPN
  -> detach 出 tun-fd
  -> native/VPP 消费主 tun-fd
  -> VPP 先做 packet processing / verdict
  -> allow packet 进入 HEV-side SOCK_SEQPACKET shim
  -> HEV 通过 SOCKS5/upstream egress
  -> HEV response 回到 VPP path
  -> VPP 写回主 tun-fd
```

关键边界：

```text
Android app / VpnService owner 负责 VPN 授权、route、lifecycle、protect()。
VPP/Snort 负责主 tun-fd 的 packet interception。
HEV 不直接拥有 Android 主 tun-fd。
HEV 只接收 VPP allow 后送入的 shim fd。
```

## 2. 参考实现

参考 `/home/js/Git/miopunch/android/control-lite`：

```text
不用 Gradle。
脚本直接调用 javac / d8 / aapt2 / zipalign / apksigner。
native payload 按 lib/arm64-v8a/lib*.so 打进 APK。
AndroidManifest.xml 设置 extractNativeLibs=true。
Activity 通过 getApplicationInfo().nativeLibraryDir 找到 payload。
```

这条路径适合当前环境，因为本机已有 Java / NDK / adb，但未确认有 Gradle。

## 3. 三阶段实验

### Phase 1：最小 VPN app + fd lifecycle

目标：

```text
只证明 Android VpnService 能申请 full-route VPN，并把 tun-fd 交给 native probe。
不启动 VPP。
不启动 HEV。
不承诺转发能力。
```

实现形态：

```text
experiments/vpp-nfq-poc/android/vpn-lite/
  scripts/build-debug-apk.sh
  scripts/install-debug-apk.sh
  src/main/AndroidManifest.xml
  src/main/java/.../MainActivity.java
  src/main/java/.../SnortVpnService.java
  native/vpn_fd_probe.c
```

最小行为：

```text
1. Activity 调 VpnService.prepare()。
2. 用户授权后启动 SnortVpnService。
3. VpnService.Builder:
   - addAddress 使用实验地址；
   - addRoute("0.0.0.0", 0)；
   - 后续再加 IPv6 ::/0，第一轮可先 IPv4。
4. establish() 得到 ParcelFileDescriptor。
5. detachFd() 把 raw fd 交给 native helper。
6. native helper 只读少量 packet header 并写日志。
7. Stop 按钮关闭 helper 与 VPN fd。
```

验收：

```text
APK 可安装。
系统弹出 VPN 授权。
授权后系统显示 VPN active。
native helper 收到至少一个 L3 IPv4 packet。
停止后 VPN 关闭，设备网络恢复。
```

风险和保护：

```text
full-route VPN 如果不转发，会让设备流量临时不可达。
Phase 1 必须有明确 Stop 按钮，并保留 adb force-stop 回滚命令。
ADB 走 USB，不依赖 VPN 数据面；优先用 adb/logcat 验证。
```

### Phase 2：Android VPN fd -> VPP main tun fd

目标：

```text
把 Phase 1 的 raw tun-fd 交给 Android VPP runtime。
VPP 只做最小 packet handling，不接 HEV。
```

实现形态：

```text
复用 Linux POC-B 的 tun_poc 思路。
Android VPP overlay 增加 tun_poc_plugin Android 构建支持。
APK 启动 native wrapper，把 detached tun-fd 作为继承 fd 传给 VPP。
VPP CLI 执行 tun-poc enable fd <n> mode count-only 或 reflect-icmp。
```

验收：

```text
VPP 在 app/root/native 环境内启动。
tun_poc 能 enable Android VpnService fd。
show tun-poc 看到 rx packet 增长。
第一轮只要求 count-only。
如果 reflect-icmp 可控，再验证写回主 fd。
```

边界：

```text
Phase 2 仍不接 HEV，不要求真实外网可用。
只证明 VPP 可以成为 Android 主 tun-fd owner。
```

### Phase 3：VPP main tun fd + HEV shim

目标：

```text
验证完整 VPN mode 数据面：
main tun-fd -> VPP -> HEV shim -> SOCKS5/upstream -> HEV shim -> VPP -> main tun-fd
```

已知前置证据：

```text
Linux/Docker POC-C1 已证明：
HEV external tun_fd 可以是 SOCK_SEQPACKET socketpair。
HEV 能从 shim fd 收 synthetic IPv4/TCP packet。
HEV 能通过 SOCKS5 CONNECT 转发。
HEV 能把 upstream response 写回 shim fd。
```

Android Phase 3 实现方向：

```text
1. APK/VpnService 建立主 tun-fd。
2. native 创建 SOCK_SEQPACKET socketpair。
3. HEV 子进程/线程拿 socketpair HEV 端作为 tun_fd。
4. VPP/tun_poc 拿主 tun-fd 与 socketpair VPP 端。
5. outbound packet:
   main tun-fd -> VPP -> HEV shim fd
6. inbound packet:
   HEV shim fd -> VPP -> main tun-fd
7. HEV upstream socket 必须由 Android VPN owner protect()。
```

验收：

```text
从 VPN 内 app 发起 TCP 请求。
VPP outbound 计数增长。
HEV SOCKS5 CONNECT / payload 可观测。
VPP inbound 计数增长。
请求端收到 response。
停止后 VPN、VPP、HEV 均退出，无残留进程。
```

## 4. 当前执行入口

先创建记录文档和实验骨架，不立即改主线 daemon：

```text
experiments/vpp-nfq-poc/ANDROID_VPN_EXPERIMENT_PLAN.md
experiments/vpp-nfq-poc/ANDROID_VPN_EXPERIMENT_LOG.md
```

后续每一步都按时间顺序追加到 log，包含：

```text
命令
设备状态
成功输出
失败输出
判断
下一步
```
