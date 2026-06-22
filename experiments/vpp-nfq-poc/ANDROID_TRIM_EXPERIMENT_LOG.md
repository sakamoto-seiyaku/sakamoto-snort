# Android VPP Trim Experiment Log

日期：2026-06-22
分支：`research/vpp-nfq-poc`

本文记录第三组 Android VPP 裁剪实验。目标是确认在只把 VPP 当包处理框架使用时，
裁掉不需要的 VPP 插件后，Android 产物大小和 idle CPU 基线能否下降。

## 1. 已知基线

第二组 Android POC 的 stripped stage：

```text
stage total: 186M
bin/vpp: 214K
bin/vppctl: 13K
plugins/nfqueue_poc_plugin.so: 72K
lib/libvnet.so: 175M
lib/libvlib.so: 8.3M
lib/libvppinfra.so: 1.2M
```

CPU 短采样：

```text
只启动 VPP 并加载 nfqueue_poc_plugin.so，不执行 nfqueue-poc enable:
  ps %CPU 稳定到约 7.5%

nfqueue-poc enable queue 42 mode accept-all，无测试规则、无流量:
  ps %CPU 约 7.4%

短流量后停流:
  ps %CPU 约 7.0%
```

当前判断：

```text
7% 左右更像当前 VPP minimal runtime 基线，不是 NFQUEUE fd 忙轮询。
```

## 2. Round 1：只保留 nfqueue_poc 插件

实验假设：

```text
配置 VPP_PLUGINS=nfqueue_poc 后，VPP CMake 只把 nfqueue_poc 加入插件构建列表。
这会减少插件构建和插件产物，但未必明显减少 Android stage 大小。
原因是当前 stage 已只复制 nfqueue_poc_plugin.so，真正的大头是 libvnet.so。
```

新增 Make target：

```text
android-vpp-configure-trim-nfqueue
android-vpp-build-trim-nfqueue
android-vpp-stage-trim-nfqueue
android-vpp-push-trim-nfqueue
android-vpp-minimal-trim-nfqueue
```

使用独立目录：

```text
work/vpp-android-trim-nfqueue
work/android-vpp-trim-nfqueue-stage
```

验收：

```text
1. Android configure summary 的 Plugins 只包含 nfqueue_poc。
2. vpp / vppctl / nfqueue_poc_plugin.so 能构建。
3. stage size 与第二组基线对比。
4. 真机 minimal startup + show plugins 通过。
5. 采样 idle CPU，与第二组 7% 左右基线对比。
```

执行记录：

```text
2026-06-22 08:10 左右
  make android-vpp-configure-trim-nfqueue
  configure log: vpp_plugins=nfqueue_poc, cmake_rc=0
  build.ninja 中只看到 nfqueue_poc_plugin.so，未看到 acl/memif/abf 等其他插件目标。

2026-06-22 08:10-08:17
  make android-vpp-build-trim-nfqueue
  vpp / vppctl / nfqueue_poc_plugin.so 构建成功。

2026-06-22 08:17
  make android-vpp-stage-trim-nfqueue
  stripped stage total 仍为 186M。
```

Round 1 stripped 文件大小：

```text
bin/vpp: 213.9K
bin/vppctl: 13.3K
plugins/nfqueue_poc_plugin.so: 72.0K
lib/libvnet.so: 175.0M
lib/libvlib.so: 8.4M
lib/libvppinfra.so: 1.3M
lib/libvlibmemory.so: 386.7K
lib/libvlibapi.so: 139.8K
lib/libsvm.so: 198.8K
```

Android 真机结果：

```text
设备：Pixel 6a / Android 16 / root via su

不执行 nfqueue-poc enable:
  PID 18609
  RSS: 321016 KB
  ps %CPU: 7.0, 7.0, 6.9, 6.9, 6.9, 6.9, 6.9, 6.9, 6.9, 6.7

执行 nfqueue-poc enable queue 42 mode accept-all，无测试规则、无流量:
  show nfqueue-poc:
    enabled 1 queue 42 mode accept-all drop-ratio 50 fd 12
    seen 0 accept 0 drop 0 missing-id 0
    handle-errors 0 recv-errors 0 enobufs 0
  RSS: 321016 KB
  ps %CPU: 6.7, 6.7, 6.7, 6.7, 6.7, 6.7, 6.7, 6.7, 6.6, 6.6
```

Round 1 结论：

```text
VPP_PLUGINS=nfqueue_poc 确实只构建 nfqueue_poc 插件，但对 Android stage 体积、
RSS 和 idle CPU 基线几乎没有帮助。

原因不是插件列表，而是原版 bin/vpp 自身 NEEDED libvnet.so；libvnet.so 是 175M。
vppctl 和 nfqueue_poc_plugin.so 都不依赖 libvnet.so，依赖 libvnet.so 的是 bin/vpp。
```

## 3. Round 2：实验性 vlib-only runtime

实验假设：

```text
如果我们只把 VPP 当包处理 runtime 使用，而 nfqueue_poc 插件只依赖 vlib/vppinfra，
可以尝试构建一个不链接 libvnet.so 的 vpp_lite executable。

这个实验不是最终架构，只是确认去掉 libvnet.so 后体积和启动边界。
```

新增文件与 target：

```text
minimal-runtime/vpp_lite_main.c
scripts/android-build-vpp-lite.sh
scripts/android-stage-vpp-lite.sh

android-vpp-build-lite
android-vpp-stage-lite
android-vpp-push-lite
android-vpp-minimal-lite
```

vpp_lite 动态依赖：

```text
libvlibmemory.so
libvlibapi.so
libvlib.so
libsvm.so
libvppinfra.so
libdl.so
libm.so
libc.so

明确没有 libvnet.so。
```

Round 2 体积：

```text
stripped stage total: 11M
stripped bin/vpp: 83K
stripped bin/vppctl: 13K
stripped nfqueue_poc_plugin.so: 72K

unstripped debug stage total: 27M
```

已踩到的问题：

```text
1. 复用 android-run-vpp-minimal.sh 时，push 脚本会重新调用 core stage，
   导致 lite stage 被覆盖回 186M。
   已增加 STAGE_SCRIPT 参数，让 core/lite 共用 push/run 流程。

2. lite startup 复用完整 VPP 配置时，api-segment 配置失败：
   vlib_call_all_config_functions: unknown input `api-segment prefix vpp-nfq-poc'
   处理：lite startup 暂时移除 api-segment/statseg，只保留 unix/buffers/plugins。

3. 移除 libvnet.so 后，VLIB 的 handoff_trace 节点引用 `error-drop` 失败：
   vlib_node_main_init: node `handoff_trace' refers to unknown node `error-drop'
   关键发现：`error-drop` 不是 vlib/drop.c 里的 `drop` 节点，而是 libvnet 的
   vnet/interface_output.c 提供的节点。
   处理：在 vpp_lite_main.c 中补一个最小 `error-drop` 兼容节点。

4. 补 `error-drop` 后，即使完全关闭 plugins section 且不传 plugin_path，
   纯 VLIB lite runtime 仍在创建 CLI socket 前 SIGSEGV：
     vpp: received signal SIGSEGV, faulting address 0x18
   因此当前崩溃不是 nfqueue_poc 插件导致，而是 vlib-only runtime 自身还缺
   原版 VPP app/libvnet 初始化上下文。
```

Round 2 结论：

```text
去掉 libvnet.so 后，Android stripped stage 可以从 186M 降到 11M。
但 vpp_lite 尚不能启动到 CLI，因此不能采集 idle CPU/RSS 基线。

下一步应先做符号化定位：
1. 禁用或改造 VPP signal handler，让 Android tombstone 正常产生；
2. 或在 VLIB 初始化路径加临时阶段日志；
3. 定位 SIGSEGV 后，再决定是补更小的兼容节点/初始化，还是保留一部分 vnet。
```
