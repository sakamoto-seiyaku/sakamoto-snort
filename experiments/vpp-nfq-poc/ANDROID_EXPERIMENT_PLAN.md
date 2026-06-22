# Android VPP NFQUEUE Experiment Plan

日期：2026-06-21
分支：`research/vpp-nfq-poc`
状态：Phase E Android 短 idle CPU 采样已通过；本组 POC 的核心问题已闭环。

## 1. 背景

第一组 Linux / Docker POC 已经证明：

- VPP `v26.02` 可以加载本地 `nfqueue_poc_plugin.so`。
- VPP 可以持有 Linux NFQUEUE fd。
- `accept-all` / `drop-all` / `drop-ratio=50` verdict 都能正确反馈到内核。
- `nfqueue-poc enable` 后 idle CPU 没有出现单核 100% 忙轮询。

第二组实验转到真实 Android 设备。这里不再重新证明 Snort 的 Android NFQUEUE 可用性；此前完整 Snort 已在真机上跑过 NFQUEUE。

## 2. 本组实验目标

只回答 Android 真机上的 VPP 接入问题：

1. VPP 能否被构建为 Android arm64 可运行产物。
2. VPP 能否在 root / su 环境下启动 minimal runtime。
3. VPP 能否加载 `nfqueue_poc_plugin.so`。
4. VPP 能否通过 Android iptables NFQUEUE 收到 INPUT 和 OUTPUT packet。
5. VPP 能否对 Android NFQUEUE packet 正确返回 `NF_ACCEPT` / `NF_DROP`。
6. 启用 NFQUEUE 后，VPP idle CPU 是否仍然不是单核 100% 忙轮询。

## 3. 非目标

本组实验暂不做：

- 接入主线 Snort runtime。
- CT A++ / policy / telemetry 移植。
- Android VPN `tun-fd` / HEV 接入。
- UID attribution 设计落地。
- 多 worker / graph datapath 正式设计。
- 长时间压测或性能优化。

## 4. 设备侧目录

固定使用：

```text
/data/local/tmp/vpp-nfq-poc/
  bin/
  lib/
  plugins/
  runtime/
  logs/
```

原因：

- 不依赖系统分区写权限。
- 便于 adb push / su 启动。
- 便于一次性清理实验产物。

## 4.1 队列策略

首次 preflight 时设备上还有旧 `sucre-snort-dev` 测试进程，占用：

```text
IPv4 INPUT:  queue-balance 0:1
IPv4 OUTPUT: queue-balance 2:3
IPv6 INPUT:  queue-balance 4:5
IPv6 OUTPUT: queue-balance 6:7
```

该进程已停止，`/proc/net/netfilter/nfnetlink_queue` 已为空。

VPP Android POC 仍默认使用实验队列：

```text
OUTPUT queue: 42
INPUT queue: 43
```

原因：

- 不把 VPP POC 和 Snort 主线队列约定混在一起。
- 便于插入和清理窄范围测试规则。
- 保留以后对比 Snort `0..7` 多队列策略的空间。

## 5. 实验顺序

### Phase A: Android Preflight

脚本：

```sh
make android-preflight
```

采集：

- 设备 serial / root id / SELinux。
- ABI / Android API / kernel。
- `iptables` / `ip6tables` / `toybox` / `busybox` / `nsenter` 可用性。
- NFQUEUE target 帮助和 `/proc/net/netfilter/nfnetlink_queue` 状态。
- VPP runtime 目录创建结果。

### Phase B: Android VPP Build Feasibility

目标：

- 尝试用 Android NDK r29 构建 VPP `v26.02` minimal binary。
- 第一验收只要求能得到可推送的 arm64 Android VPP 产物。

当前结果：

```text
已完成。
已产出 Android arm64 PIE executable：
  work/vpp-android-configure-probe/bin/vpp
  work/vpp-android-configure-probe/bin/vppctl

该产物依赖：
  libvnet.so
  libvlibmemory.so
  libvlibapi.so
  libvlib.so
  libsvm.so
  libvppinfra.so
```

注意：

- VPP upstream 主要面向 glibc/Linux，Android bionic 可能需要 patch。
- 先不要求所有 plugin 都能编译。
- `nfqueue_poc` 已进入 Android 构建。Android 分支使用 repo 内 vendored
  `third_party/netfilter` 源，静态编进 `nfqueue_poc_plugin.so`。
- 当前 Android overlay 需要把 `VLIB_PROCESS_LOG2_STACK_SIZE` 设为 `18`。默认 `15`
  在 Pixel 6a 上会让 minimal daemon 于 VLIB process startup 阶段 SIGSEGV。
- 如果完整 VPP 太重，后续再缩小到 minimal startup + `nfqueue_poc`。

### Phase C: Minimal Startup On Device

目标：

- 推送 VPP binary / required `.so`。
- 通过 `su 0 sh -c` 启动。
- 先验证 `vpp -v`。
- 再用 minimal startup 验证 CLI socket、`show version`。
- `show plugins` 只作为 core 插件路径检查；`nfqueue_poc` 要等 Android libnetfilter_queue 接入后再验证。

当前结果：

```text
已完成 vpp -v：
  /data/local/tmp/vpp-nfq-poc/bin/vpp -v
  version_rc=0

已完成 daemon minimal startup：
  vpp 以 startup.conf 启动
  CLI socket 可连接
  vppctl show version 成功
  show plugins 可看到 nfqueue_poc_plugin.so

关键条件：
  VLIB_PROCESS_LOG2_STACK_SIZE=18
  启动参数必须带 plugin_path /data/local/tmp/vpp-nfq-poc/plugins

尚未完成：
  无
```

### Phase D: Android NFQUEUE Verdict

先只做窄规则，不污染全局流量：

- OUTPUT：指定目标 IP / ICMP。
- INPUT：指定源 IP / ICMP，必要时由 host 或另一端制造流量。

验收：

- `accept-all`：目标流量通过，VPP `accept` 计数增加。
- `drop-all`：目标流量被阻断，VPP `drop` 计数增加。
- `drop-ratio=50`：外部观察接近 50% 丢包，VPP 计数匹配。

当前结果：

```text
已完成 IPv4 ICMP OUTPUT：
  accept-all: ping 1.1.1.1 4/4 success，VPP accept 计数增加。
  drop-all: ping 1.1.1.1 100% loss，VPP drop 计数增加。

已完成 IPv4 ICMP INPUT：
  accept-all: 来自 1.1.1.1 的 reply 通过，VPP accept 计数增加。
  drop-all: 来自 1.1.1.1 的 reply 被丢弃，ping 100% loss，VPP drop 计数增加。

临时 iptables 规则均已删除。
```

### Phase E: Idle CPU

目标：

- `nfqueue-poc enable` 后无流量采样。
- 有少量流量后再次停流采样。
- 确认没有单核 100% 忙轮询。

当前结果：

```text
已完成短采样。

nfqueue-poc enable queue 42 mode accept-all，无测试规则/无流量：
  ps %CPU 约 7.4%。

短 OUTPUT ICMP 流量后删除规则并停流：
  ps %CPU 约 7.0%。

对照：只启动 VPP 并加载 nfqueue_poc_plugin.so，但不执行 nfqueue-poc enable：
  ps %CPU 约 7.5%，与 enable 后同量级。

结论：
  当前 Android 真机短采样没有出现单核 100% 忙轮询。
  这个 7%左右更像当前 VPP minimal runtime 基线，而不是 NFQUEUE 收包忙轮询。
  这不是长期压测或正式性能结论。
```

## 6. 记录要求

所有步骤按时间顺序记录到：

```text
ANDROID_EXPERIMENT_LOG.md
```

每条记录至少包含：

- 命令。
- 关键输出。
- 结论。
- 失败原因和绕坑方式。

脚本输出放在：

```text
results/
```

`results/` 默认不进 git，只在日志里摘录关键结果。

## 7. 停止条件

以下任一情况发生，本组实验先停止并写结论：

- VPP 无法以 Android arm64 产物启动 minimal runtime。
- VPP 插件无法在 Android 上加载，且需要大规模改 VPP core。
- Android NFQUEUE packet id / verdict 生命周期无法可靠闭环。
- 必须永久 polling 才能收到 NFQUEUE packet，导致 idle CPU 单核 100%。
- iptables 规则无法做到窄范围、可清理、可恢复。
