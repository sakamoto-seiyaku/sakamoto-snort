# Android VPP Trim Experiment Log

日期：2026-06-22
分支：`research/vpp-nfq-poc`

本文记录第三组 Android VPP 裁剪实验。目标是确认在只把 VPP 当包处理框架使用时，
裁掉不需要的 VPP 插件后，Android 产物大小和 idle CPU 基线能否下降。

## 0. 当前可运行状态

截至 2026-06-22，第二组 Android POC 已证明原版 VPP runtime 可以在真机运行：

```text
设备：Pixel 6a / Android 16 / root via su

已通过：
  1. minimal VPP daemon 启动成功。
  2. vppctl 通过 CLI socket 执行 show version 成功。
  3. nfqueue_poc_plugin.so 加载成功。
  4. nfqueue-poc enable queue 42 mode accept-all 成功。
  5. Android IPv4 OUTPUT NFQUEUE allow/drop 实验通过。
  6. Android IPv4 INPUT NFQUEUE allow/drop 实验通过。

当前基线：
  stripped stage total: 186M
  lib/libvnet.so: 175M
  RSS: 约 321M
  无流量 idle CPU: 约 6.6% - 7.5%
```

因此当前结论不是“Android VPP 不能跑”，而是“能跑，但原版 runtime 体积和 idle
CPU 基线偏重”。本日志后续的 `vpp_lite` 是裁剪探索分支；它目前还不能替代已跑通的
原版 Android VPP POC。

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

## 4. Round 3：libvnet.so 依赖和体积分解调查

本轮先做只读调查，不改构建脚本和 VPP 源码。目标是回答：

```text
1. libvnet.so 的 175M 是不是 debug 信息或压缩问题？
2. 哪些 vnet 模块是当前 Android POC 的体积大头？
3. 如果要裁剪，先从哪里动风险最低、收益最大？
```

### 4.1 关键事实

stage 中的 `libvnet.so` 已经 strip，体积仍然主要来自代码段：

```text
stripped libvnet.so: 183,480,048 bytes，约 174.98 MiB
.text:               180,289,520 bytes，约 171.94 MiB
.rodata:               1,448,840 bytes
.eh_frame + hdr:         913,696 bytes
.data + .bss:            333,312 bytes
```

所以这不是“把 debug 信息去掉”能解决的问题。APK/ZIP/xz 可以降低分发体积，但运行时
仍需要解压或 mmap 出实际 native library；当前要降 installed/runtime 体积，需要减少
编进 `.text` 的代码。

另一个更关键的问题是：当前 Android VPP 配置没有启用 release 优化。

```text
configure summary:
  Build type:
  C flags: -g -DANDROID -fdata-sections -ffunction-sections -funwind-tables

CMakeCache:
  CMAKE_BUILD_TYPE:STRING=
```

实际编译命令里也没有 `-O2`、`-O3`、`-Os` 或 `-Oz`。这意味着当前基线更接近
O0/debug 编译后再 strip。下一轮实验应优先修正这个基线，否则后面的模块裁剪数据会偏大。

### 4.2 multiarch 是当前最大放大器

当前 Android ARM64 构建启用了 5 个 AArch64 multiarch 变体：

```text
octeontx2
thunderx2t99
cortexa72
neoversen1
neoversev2
```

这些变体会把 `VNET_MULTIARCH_SOURCES` 中的节点函数按多个 CPU 目标重复编译。

未 strip `libvnet.so` 的符号尺寸聚合：

```text
generic_multiarch_fn: 28.2 MiB
thunderx2t99:         25.4 MiB
octeontx2:            25.4 MiB
cortexa72:            25.3 MiB
neoversev2:           25.2 MiB
neoversen1:           25.2 MiB
other_symbols:        17.5 MiB
```

对象级 `.text` 统计同样显示，5 个 CPU 变体合计约 137MB object text。这个数字不能
直接等同最终可节省体积，但足以说明第一优先级不是先裁 TCP/UDP，而是先关掉不需要的
ARM multiarch 变体。

当前更保守的 Android 策略应是：

```text
先保留 baseline armv8-a+crc 路径，关闭 octeontx2/thunderx2t99/cortexa72/neoversen1/neoversev2。
如果后续确认某个设备族需要单独优化，再只打开一个明确需要的变体。
```

### 4.3 模块体积分布

按 link 进 `libvnet.so` 的 object `.text` 聚合，top 模块如下：

```text
ip:       80,968,432 bytes
ipsec:    48,572,968 bytes
tcp:       6,822,672 bytes
l2:        5,550,504 bytes
bonding:   5,361,760 bytes
span:      5,216,852 bytes
devices:   4,295,424 bytes
sfdp:      3,377,692 bytes
udp:       2,474,600 bytes
dpo:       2,428,056 bytes
session:   1,406,280 bytes
mpls:        778,276 bytes
adj:         565,672 bytes
fib:         419,756 bytes
interface:    88,088 bytes
tls:          60,164 bytes
```

top 源文件：

```text
ipsec/esp_decrypt.c.o:       34,424,460 bytes
ip/reass/ip4_sv_reass.c.o:   23,045,632 bytes
ip/reass/ip6_sv_reass.c.o:   19,237,116 bytes
ip/reass/ip4_full_reass.c.o: 16,050,392 bytes
ip/reass/ip6_full_reass.c.o: 10,591,448 bytes
ipsec/esp_encrypt.c.o:        9,471,908 bytes
tcp/tcp_input.c.o:            5,624,768 bytes
span/node.c.o:                5,186,308 bytes
bonding/device.c.o:           5,068,064 bytes
ip/ip4_forward.c.o:           3,899,696 bytes
ip/ip6_forward.c.o:           3,414,208 bytes
sfdp/lookup/node.c.o:         2,870,732 bytes
```

解释：

```text
1. ip 模块大，主要不是普通 IP header 解析，而是 IP fragment reassembly。
2. ipsec 模块大，主要是 ESP encrypt/decrypt 节点。
3. tcp/udp/session/tls 是 VPP host stack / session 层，当前 POC 大概率不需要，
   但它们不是当前最大体积来源。
4. fib/dpo/adj/interface 是 VPP graph 和 L3 转发基础，单独体积不大，且耦合风险高。
```

### 4.4 裁剪分层判断

第一层，先修构建基线：

```text
必须优先验证 CMAKE_BUILD_TYPE=release。
VPP upstream 对 release 会加 -O3，并可能启用 LTO。

如果目标是最小体积，再单独实验 -Os/-Oz；但 VPP 的 CMake 明确声明的 build type 是
release/debug/coverity/gcov，MinSizeRel 不能直接当稳定方案。
```

第二层，关 multiarch：

```text
关闭所有非必要 AArch64 multiarch variants。
这是当前最大、最少侵入的裁剪点。
验收标准：vpp 能启动、CLI 可用、nfqueue_poc 插件可加载、Android OUTPUT/INPUT allow/drop 仍通过。
```

第三层，高概率可裁功能：

```text
ipsec/crypto:
  当前 NFQUEUE/VPN 包处理不等于需要 VPP IPsec。
  若只做 policy/verdict，优先裁 ipsec/esp/ah。
  注意 IP feature arc 中有 ipsec 相关 feature 名，裁剪时要同步清理注册路径。

tcp/session/tls:
  这是 VPP 用户态 TCP/session/TLS 栈。
  当前我们只需要解析 packet 并做策略，不需要 VPP 终止 TCP 连接。
  可以作为明确可裁候选。

udp:
  如果只解析 UDP header，不需要 VPP udp local/encap/decap graph。
  可以跟 tcp/session/tls 分开裁，避免一次改太多。

bonding/span/gso/virtio/mpls/srv6/ipip/teib/pg/syslog/bfd/sfdp:
  当前 Android NFQUEUE/VPN POC 没有直接需求。
  可逐组裁剪，但每组都要过最小启动和 NFQUEUE smoke。
```

第四层，高风险或暂缓：

```text
ip 基础 input/forward、feature、buffer/interface、fib/dpo/adj/error-drop。

这些是未来把 NFQUEUE/VPN packet 真正灌入 VPP graph 时的基础。
直接删这些比收益更容易破坏启动顺序、feature arc、drop/punt、lookup 和 interface metadata。
```

IP reassembly 单独处理：

```text
ip/reass/* 是最大功能级体积来源之一，但不是简单“肯定可裁”。
如果裁掉，分片包语义会改变：后续策略只能看到 fragment，不能看到完整 L4 信息。
第一版如果选择不支持 fragmented packet deep inspection，可以先裁；否则需要保留或设计自己的
分片处理策略。
```

### 4.5 建议的下一轮实验顺序

```text
Round 4A: release build
  只加 CMAKE_BUILD_TYPE=release，不裁功能。
  记录 libvnet.so、stage total、RSS、idle CPU、NFQUEUE smoke。

Round 4B: release + disable ARM multiarch variants
  在 4A 基础上关闭 octeontx2/thunderx2t99/cortexa72/neoversen1/neoversev2。
  先保留 baseline armv8-a+crc。

Round 4C: release + no multiarch + no ipsec
  裁 ipsec/esp/ah/crypto 相关 vnet 段。

Round 4D: release + no multiarch + no host stack
  裁 tcp/session/tls；udp 单独决定是否裁。

Round 4E: release + no multiarch + no obvious device/features
  裁 bonding/span/gso/virtio/mpls/srv6/ipip/teib/pg/syslog/bfd/sfdp 等。

Round 4F: reassembly policy decision
  决定是否保留 ip/reass/*。这个需要产品语义确认，不应跟普通“无用模块裁剪”混在一起。
```

暂定结论：

```text
当前最划算的路径不是先手写 vpp_lite，也不是先裁 TCP/UDP。
应该先把原版 VPP Android 构建变成 optimized baseline，然后关闭无关 ARM multiarch variants。
这两步完成后，再看 libvnet.so 还剩多大，再进入 ipsec/host-stack/设备功能裁剪。
```
