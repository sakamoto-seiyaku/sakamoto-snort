# Android VPP Trim Experiment Log

日期：2026-06-22
分支：`research/vpp-nfq-poc`

本文记录第三组 Android VPP 裁剪实验。目标是确认在只把 VPP 当包处理框架使用时，
裁掉不需要的 VPP 代码和插件后，Android 产物大小、RSS 和 idle CPU 基线能否下降。

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

截至 Android Phase 3C，另一个更重要的可运行基线已经成立：

```text
Android TCP client
  -> VpnService L3 tun-fd
  -> VPP/tun_poc forward-fd
  -> SOCK_SEQPACKET shim
  -> HEV
  -> device-local SOCKS5 smoke server
  -> HEV
  -> VPP/tun_poc forward-fd
  -> VpnService L3 tun-fd
  -> Android TCP client

HTTP client 已收到:
  HTTP/1.0 200 OK
  Content-Length: 2

  OK

VPP/tun_poc:
  enabled 1 fd 3 shim-fd 4 mode forward-fd
  rx 21 bytes 1650 tx 11 bytes 556
  shim-rx 11 bytes 556 shim-tx 21 bytes 1650
  parse/read/write/shim errors all 0
```

所以后续裁剪的主验收不再只是“VPP 能启动”或“NFQUEUE allow/drop 能过”，而是：

```text
裁剪后的 VPP runtime 必须仍能跑通 Android 3C 的 L3 VPN datapath。
```

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
  可逐组裁剪，但每组都要过最小启动和 Android 3C VPN smoke。
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
  记录 libvnet.so、stage total、RSS、idle CPU。
  验收 Android 3C L3 VPN datapath。

Round 4B: release + disable ARM multiarch variants
  在 4A 基础上关闭 octeontx2/thunderx2t99/cortexa72/neoversen1/neoversev2。
  先保留 baseline armv8-a+crc。
  验收 Android 3C L3 VPN datapath。

Round 4C: release + no multiarch + no ipsec
  裁 ipsec/esp/ah/crypto 相关 vnet 段。
  验收 Android 3C L3 VPN datapath。

Round 4D: release + no multiarch + no host stack
  裁 tcp/session/tls；udp 单独决定是否裁。
  验收 Android 3C L3 VPN datapath。

Round 4E: release + no multiarch + no obvious device/features
  裁 bonding/span/gso/virtio/mpls/srv6/ipip/teib/pg/syslog/bfd/sfdp 等。
  验收 Android 3C L3 VPN datapath。

Round 4F: reassembly policy decision
  决定是否保留 ip/reass/*。这个需要产品语义确认，不应跟普通“无用模块裁剪”混在一起。
```

暂定结论：

```text
当前最划算的路径不是先手写 vpp_lite，也不是先裁 TCP/UDP。
应该先把原版 VPP Android 构建变成 optimized baseline，然后关闭无关 ARM multiarch variants。
这两步完成后，再看 libvnet.so 还剩多大，再进入 ipsec/host-stack/设备功能裁剪。
```

## 5. Android 3C 后的裁剪验收边界

新的裁剪目标：

```text
在不破坏 L3 VPN datapath 的前提下，降低 VPP Android runtime 的体积、RSS 和 idle CPU。
```

后续每一轮裁剪都必须记录同一组数字：

```text
1. stripped stage total。
2. bin/vpp、libvnet.so、libvlib.so、libvppinfra.so、plugin .so 的尺寸。
3. APK 中 native payload 增量，必要时记录安装后 nativeLibraryDir 尺寸。
4. VPP 进程 RSS。
5. 无流量 idle CPU 短采样。
6. Android 3C HTTP smoke 是否通过。
7. 停止后 VPP / HEV / app / SOCKS5 smoke server 是否有残留。
```

Android 3C smoke 的最低验收：

```text
1. vpn-lite app 能以 mode=vpp-hev 启动。
2. VPP CLI socket 可用。
3. startup.exec 能执行：
     tun-poc enable fd 3 mode forward-fd shim-fd 4
4. HEV 能连接测试 SOCKS5 endpoint。
5. Android nc HTTP client 能收到固定 OK response。
6. show tun-poc 中 main rx/tx 与 shim rx/tx 均增长。
7. parse/read/write/shim error 计数保持 0。
8. stop / force-stop 后无子进程残留。
```

当前两个体积端点：

```text
可用上限:
  full Android VPP stage: 186M
  libvnet.so:             175M
  Android 3C datapath:    已通过

不可用下限:
  vpp_lite stage:         11M
  libvnet.so:             无
  Android 3C datapath:    未通过，当前甚至不能稳定启动到 CLI
```

因此 `vpp_lite` 只能作为“理论下限”参考，不能作为主线裁剪路径。主线应从已通过
Android 3C 的 full runtime 开始，每轮只改变一个变量。

## 6. 下一阶段任务拆分

### 6.1 Round 4A：优化构建基线

任务：

```text
只把 Android VPP 构建切到 release 或等价优化构建。
不裁 VPP 功能。
不改 tun_poc / HEV / vpn-lite datapath。
```

需要调查并记录：

```text
1. VPP upstream Android CMake 下 CMAKE_BUILD_TYPE=release 是否稳定可用。
2. release 默认是 -O3、是否启用 LTO。
3. 如需最小体积，-Os/-Oz 是否可以作为单独实验，而不是直接混入 4A。
4. release 后 libvnet.so 的 .text 是否明显下降。
5. release 后 Android 3C 是否仍通过。
```

已定位源码：

```text
work/vpp/src/CMakeLists.txt
  CMAKE_BUILD_TYPE 支持 release/debug/coverity/gcov。
  release 分支会添加：
    -O3 -fstack-protector -fno-common
    _FORTIFY_SOURCE=2
  release 下如果 check_ipo_supported 通过，VPP_USE_LTO option 默认 ON。

实验入口优先用 CMake 参数：
  -DCMAKE_BUILD_TYPE=release
  -DVPP_USE_LTO=ON/OFF

4A 只做 release 默认行为。
如果要比较体积优化，单独做 4A.1：release + VPP_USE_LTO=OFF。
如果要试 -Os/-Oz，单独做 4A.2，不混入 4A。
```

预期判断：

```text
如果 4A 失败，先修构建方式，不继续做功能裁剪。
如果 4A 通过，4A 成为新的所有后续裁剪基线。
```

### 6.2 Round 4B：关闭 Android ARM multiarch variants

任务：

```text
在 4A 基础上关闭不需要的 AArch64 multiarch variants：
  octeontx2
  thunderx2t99
  cortexa72
  neoversen1
  neoversev2

先保留 baseline armv8-a+crc 路径。
```

原因：

```text
当前 libvnet.so 的体积被 multiarch 重复编译明显放大。
这一步比先裁 TCP/UDP 更可能有大收益，且对 datapath 语义影响较小。
```

已定位源码：

```text
work/vpp/src/cmake/cpu.cmake
  AArch64 默认 baseline:
    VPP_DEFAULT_MARCH_FLAGS=-march=armv8-a+crc

  Android 当前可显式关闭的 ON variants:
    VPP_MARCH_VARIANT_OCTEONTX2
    VPP_MARCH_VARIANT_THUNDERX2T99
    VPP_MARCH_VARIANT_CORTEXA72
    VPP_MARCH_VARIANT_NEOVERSEN1
    VPP_MARCH_VARIANT_NEOVERSEV2

  qdf24xx 和 neoversen2 默认已经 OFF。

实验入口优先用 CMake 参数：
  -DVPP_MARCH_VARIANT_OCTEONTX2=OFF
  -DVPP_MARCH_VARIANT_THUNDERX2T99=OFF
  -DVPP_MARCH_VARIANT_CORTEXA72=OFF
  -DVPP_MARCH_VARIANT_NEOVERSEN1=OFF
  -DVPP_MARCH_VARIANT_NEOVERSEV2=OFF
```

暂不优先使用：

```text
VPP_BUILD_NATIVE_ONLY

原因：
  Android 是 cross compile，native CPU 是构建机而不是真机。
  这里要的是稳定 AArch64 baseline，不是 host native。
```

验收：

```text
Android 3C 必须通过。
如果只影响性能、不影响功能，记录 idle CPU 和 smoke latency 的粗略变化即可。
```

### 6.3 Round 4C：裁 IPsec/crypto

任务：

```text
在 4B 基础上裁 VPP IPsec/ESP/AH/crypto 相关代码路径。
```

原因：

```text
当前 datapath 只需要 L3 packet interception、policy/verdict 和交给 HEV 发包。
不需要 VPP 自己做 IPsec tunnel 或 ESP encrypt/decrypt。
```

风险：

```text
IP feature arc 中可能注册了 ipsec 相关 feature。
不能只删 object，必须同步处理注册和依赖。
```

已定位源码入口：

```text
work/vpp/src/vnet/CMakeLists.txt
  ipsec/ipsec*.c
  ipsec/esp_*.c
  ipsec/ah_*.c
  ipsec/ipsec*.api

这些目前直接编入 libvnet.so，不是普通 plugin 开关。
所以 4C 需要 overlay patch 或上游源码改动，不是单纯 VPP_PLUGINS 能解决。
```

### 6.4 Round 4D：裁 VPP host stack

任务：

```text
在 4B 或 4C 基础上裁 tcp/session/tls。
udp 是否裁剪要单独拆一轮。
```

原因：

```text
HEV 使用自己的 lwIP/转发逻辑。
当前 VPP 只作为包处理框架，不需要 VPP 终止 TCP 连接，也不需要 VPP session/TLS。
```

注意：

```text
不能把“能解析 TCP/UDP header”和“需要 VPP TCP/UDP host stack”混在一起。
策略匹配需要的是 header metadata，不代表要保留 VPP host stack。
```

已定位源码入口：

```text
work/vpp/src/vnet/CMakeLists.txt
  tcp/tcp*.c
  session/session*.c
  session/application*.c
  tls/tls*.c

这些同样直接编入 libvnet.so。
4D 需要源码级开关或 overlay patch，并要注意 VPP app/vlibmemory 是否间接依赖 session。
```

### 6.5 Round 4E：裁无关 device/L2/MPLS 等功能

候选：

```text
bonding
span
gso
virtio
mpls
srv6
ipip
teib
pg
syslog
bfd
sfdp
```

原则：

```text
这些先按组裁，不一次性全删。
每组都要过 Android 3C。
如果某组和 VPP 启动、interface、buffer、feature arc 强耦合，先退回并记录原因。
```

### 6.6 Round 4F：L3 fragment/reassembly 产品语义

这是单独决策，不只是体积优化：

```text
ip/reass/* 是大头之一。
但裁掉后，fragmented packet 只能按 fragment 处理，无法稳定恢复完整 L4 flow。
```

需要先回答：

```text
第一版是否允许“不支持 fragmented packet deep inspection”？
如果允许，可以裁 reassembly，并把 fragment 行为定义为 allow/log/drop 中的一种明确策略。
如果不允许，就要保留 reassembly 或另做更小的 fragment 处理实现。
```

暂定判断：

```text
4F 不应该早于 4A/4B。
如果 release + no multiarch 已经把体积压到可接受范围，reassembly 可以先不动。
```

## 7. Round 4A 执行记录：release build

目标：

```text
只切 Android VPP release build。
不裁功能。
不关闭 ARM multiarch。
不改 Android 3C datapath。
```

新增入口：

```text
scripts/android-configure-vpp-probe.sh:
  VPP_CMAKE_BUILD_TYPE
  VPP_USE_LTO
  VPP_EXTRA_CMAKE_ARGS

Makefile:
  android-vpp-configure-release
  android-vpp-build-release
  android-vpp-stage-release
  android-vpp-push-release
  android-vpp-minimal-release
```

### 7.1 configure

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-configure-release
```

关键结果：

```text
build_dir: work/vpp-android-release
Build type: release
Plugins: nfqueue_poc tun_poc
Multiarch variants: octeontx2 thunderx2t99 cortexa72 neoversen1 neoversev2
cmake_rc=0
```

注意：

```text
configure summary 的 C flags 行没有直接展示 -O3。
实际编译命令中确认存在：
  -O3 -fstack-protector -fno-common
```

### 7.2 release build 踩坑

release 打开了 `-Werror -Wall`，Android NDK headers 和既有 Android shim 暴露了几个
debug build 没遇到的问题。

已修正：

```text
1. vppinfra/maplog.c
   open(path, O_RDWR/O_RDONLY, 0600) 没有 O_CREAT。
   Android fortify 报：
     'open' has superfluous mode bits
   修正：去掉无效 mode 参数。

2. vppinfra/linux/mem.c
   Android NUMA syscall shim 跳过 get_mempolicy 后，nodemask/maxnode/flags/va/mode
   在 release 下变成 unused。
   修正：Android 分支显式 (void) 标记。

3. svm/svm.c
   open(a->backing_file, O_RDWR, 0777) 没有 O_CREAT。
   修正：去掉无效 mode 参数。

4. vnet/sfdp/timer/timer.h
   字段名 u32 __unused 在 Android headers 下会出问题。
   修正：改为 u32 unused。
```

这些修正都放进 `scripts/apply-vpp-android-overlay.sh`，不是只改临时 `work/vpp`。

命令：

```sh
make -C experiments/vpp-nfq-poc apply-vpp-android-overlay
make -C experiments/vpp-nfq-poc android-vpp-build-release
```

结果：

```text
vpp / vppctl / nfqueue_poc_plugin / tun_poc_plugin 全部构建成功。
```

### 7.3 stage size

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-stage-release
```

结果：

```text
release stage total: 29M

bin/vpp:                         103,040 bytes
bin/vppctl:                       10,624 bytes
lib/libsvm.so:                   110,992 bytes
lib/libvlib.so:                1,921,800 bytes
lib/libvlibapi.so:                67,992 bytes
lib/libvlibmemory.so:            158,672 bytes
lib/libvnet.so:               27,169,424 bytes
lib/libvppinfra.so:              467,744 bytes
plugins/nfqueue_poc_plugin.so:    52,120 bytes
plugins/tun_poc_plugin.so:        18,136 bytes
```

对比旧基线：

```text
debug/O0-ish stripped stage: 186M
release stripped stage:      29M

debug/O0-ish libvnet.so:     183,480,048 bytes
release libvnet.so:           27,169,424 bytes

debug/O0-ish libvnet .text:  180,289,520 bytes
release libvnet .text:        24,152,008 bytes
```

判断：

```text
Round 4A 单独就把 stage 从 186M 降到 29M。
这说明之前 175M libvnet.so 的最大问题确实是非 release 优化构建，而不是必须先裁模块。
```

### 7.4 release minimal 真机启动

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-minimal-release
```

修正记录：

```text
第一次手动给 android-vpp-minimal-probe 传 STAGE_DIR 时，Makefile 变量没有传进脚本环境，
导致 push 流程重新用默认 core stage 覆盖了 release stage。

已增加专门的 android-vpp-push-release / android-vpp-minimal-release target。
```

真机结果：

```text
设备：Pixel 6a / Android 16 / root via su

remote pushed release stage:
  libvnet.so: 26M
  libvlib.so: 1.8M
  libvppinfra.so: 457K

vppctl show version:
  vpp v26.02-release built by js on Main at 2026-06-22T06:50:22
  vppctl_rc=0

root minimal VPP RSS:
  138,688 KB
```

### 7.5 Android 3C release datapath 验收

APK 构建：

```sh
VPP_STAGE_DIR=/home/js/Git/sakamoto/sakamoto-snort/experiments/vpp-nfq-poc/work/android-vpp-release-stage \
  experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

APK 结果：

```text
snort-vpn-lite-debug.apk: 8.1M
APK uncompressed entries total: 30,445,995 bytes
lib/arm64-v8a/libvnet.so: 27,169,424 bytes
lib/arm64-v8a/libhev-socks5-tunnel.so: 321,232 bytes
```

启动：

```text
mode=vpp-hev

logcat:
  started VPP pid=26866 fd=126 mode=2
  started VPP HEV pid=26867
  nativeStartVppProbe fd=126 vppMode=2 rc=0
```

说明：

```text
vpp monitor stop 是 vpn-lite 当前固定采样线程结束，不代表 VPP 退出。
后续 ps 和 vppctl 确认 VPP 仍在运行。
```

HTTP probe：

```sh
printf 'GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n' |
  adb shell nc -w 5 93.184.216.34 80
```

结果：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
```

SOCKS5 smoke server：

```text
connect 93.184.216.34:80
payload-len 43
GET /probe HTTP/1.0
Host: example.test
```

最终 `show tun-poc`：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 24 bytes 1794 tx 11 bytes 556
shim-rx 11 bytes 556 shim-tx 24 bytes 1794
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

release app context VPP 资源短采样：

```text
RSS: 159,764 KB
CPU samples: 1, 1, 5, 3, 3
```

清理：

```text
Stop intent + force-stop app。
kill device-local sakamoto-socks5-smoke。
确认无 vpp / vpnlite / sakamoto-socks5 / HEV 残留。
```

额外观察：

```text
VPP plugin loader 会扫描 app nativeLibraryDir 下所有 .so，
因此 logcat 中有 “Not a plugin: libvnet.so/libhev-socks5-tunnel.so/...” 噪音。
当前不影响 datapath；后续如果要清理日志，可以把 VPP plugin path 指向单独 plugin-only 目录。
```

Round 4A 结论：

```text
release build 已通过 Android 3C L3 VPN datapath 验收。
29M stage / 8.1M APK 已经比原始 186M 基线小很多。

下一步应继续 Round 4B：
  release + 关闭 ARM multiarch variants。

这一步仍不裁 VPP 功能，只验证 multiarch 关闭后体积、RSS、CPU 和 Android 3C 是否继续成立。
```

## 8. Round 4B 执行记录：release + no ARM multiarch

目标：

```text
在 Round 4A release 基础上关闭 AArch64 multiarch variants。
不裁 VPP 功能。
不改 tun_poc / HEV / vpn-lite datapath。
```

新增入口：

```text
Makefile:
  ANDROID_RELEASE_NOMARCH_BUILD_DIR
  ANDROID_RELEASE_NOMARCH_STAGE_DIR
  ANDROID_RELEASE_NOMARCH_CMAKE_ARGS

  android-vpp-configure-release-no-multiarch
  android-vpp-build-release-no-multiarch
  android-vpp-stage-release-no-multiarch
  android-vpp-push-release-no-multiarch
  android-vpp-minimal-release-no-multiarch
```

关闭的 CMake option：

```text
-DVPP_MARCH_VARIANT_OCTEONTX2=OFF
-DVPP_MARCH_VARIANT_THUNDERX2T99=OFF
-DVPP_MARCH_VARIANT_CORTEXA72=OFF
-DVPP_MARCH_VARIANT_NEOVERSEN1=OFF
-DVPP_MARCH_VARIANT_NEOVERSEV2=OFF
```

### 8.1 configure

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-configure-release-no-multiarch
```

关键结果：

```text
build_dir: work/vpp-android-release-no-multiarch
Build type: release
Plugins: nfqueue_poc tun_poc
Multiarch variants: <empty>

CMakeCache:
  VPP_MARCH_VARIANT_OCTEONTX2=OFF
  VPP_MARCH_VARIANT_THUNDERX2T99=OFF
  VPP_MARCH_VARIANT_CORTEXA72=OFF
  VPP_MARCH_VARIANT_NEOVERSEN1=OFF
  VPP_MARCH_VARIANT_NEOVERSEV2=OFF
```

### 8.2 build and stage

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-build-release-no-multiarch
make -C experiments/vpp-nfq-poc android-vpp-stage-release-no-multiarch
```

结果：

```text
release no-multiarch stage total: 11M

bin/vpp:                         103,040 bytes
bin/vppctl:                       10,624 bytes
lib/libsvm.so:                   104,184 bytes
lib/libvlib.so:                  683,216 bytes
lib/libvlibapi.so:                67,992 bytes
lib/libvlibmemory.so:            158,672 bytes
lib/libvnet.so:                9,167,104 bytes
lib/libvppinfra.so:              467,744 bytes
plugins/nfqueue_poc_plugin.so:    52,120 bytes
plugins/tun_poc_plugin.so:        18,136 bytes
```

对比：

```text
debug/O0-ish stripped stage:       186M
release stripped stage:             29M
release no-multiarch stripped stage: 11M

release libvnet.so:             27,169,424 bytes
release no-multiarch libvnet.so:  9,167,104 bytes

release libvnet .text:          24,152,008 bytes
release no-multiarch .text:      6,478,808 bytes
```

判断：

```text
关闭 ARM multiarch 在 release 基础上仍有明显收益。
当前 full VPP runtime 仍保留所有功能，但 Android stage 已经从 186M 降到 11M。
```

### 8.3 no-multiarch minimal 真机启动

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-minimal-release-no-multiarch
```

真机结果：

```text
设备：Pixel 6a / Android 16 / root via su

remote pushed no-multiarch stage:
  libvnet.so: 8.7M
  libvlib.so: 667K
  libvppinfra.so: 457K

vppctl show version:
  vpp v26.02-release built by js on Main at 2026-06-22T07:51:07
  vppctl_rc=0

root minimal VPP RSS:
  116,664 KB
```

### 8.4 Android 3C no-multiarch datapath 验收

APK 构建：

```sh
VPP_STAGE_DIR=/home/js/Git/sakamoto/sakamoto-snort/experiments/vpp-nfq-poc/work/android-vpp-release-no-multiarch-stage \
  experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

APK 结果：

```text
snort-vpn-lite-debug.apk: 3.6M
APK uncompressed entries total: 11,198,283 bytes
lib/arm64-v8a/libvnet.so: 9,167,104 bytes
lib/arm64-v8a/libhev-socks5-tunnel.so: 321,232 bytes
```

启动：

```text
mode=vpp-hev

logcat:
  started VPP pid=27591 fd=126 mode=2
  started VPP HEV pid=27592
  nativeStartVppProbe fd=126 vppMode=2 rc=0
```

HTTP probe：

```sh
printf 'GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n' |
  adb shell nc -w 5 93.184.216.34 80
```

结果：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
```

SOCKS5 smoke server：

```text
connect 93.184.216.34:80
payload-len 43
GET /probe HTTP/1.0
Host: example.test
```

最终 `show tun-poc`：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 23 bytes 1746 tx 11 bytes 556
shim-rx 11 bytes 556 shim-tx 23 bytes 1746
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

release no-multiarch app context VPP 资源短采样：

```text
RSS: 126,388 KB
CPU samples: 3, 5, 0, 0, 0
```

清理：

```text
Stop intent + force-stop app。
kill device-local sakamoto-socks5-smoke。
确认无 vpp / vpnlite / sakamoto-socks5 / HEV 残留。
```

Round 4B 结论：

```text
release + no ARM multiarch 已通过 Android 3C L3 VPN datapath 验收。

当前最重要的体积结论：
  186M -> 29M -> 11M

当前最重要的 APK 结论：
  release APK:              8.1M
  release no-multiarch APK: 3.6M

当前 VPP 仍保留 libvnet 中的 IPsec、host stack、reassembly、device/L2/MPLS 等功能。
下一步 Round 4C 再开始源码级功能裁剪。
```

## 9. Round 4C: release + no-multiarch + no IPsec 源码级裁剪

目标：

```text
在 Round 4B 基线上继续裁剪 libvnet 中当前用不到的 IPsec 模块。
先只裁 IPsec，保留 crypto。
原因：BFD 等非 IPsec 模块也引用 vnet crypto，crypto 不能和 IPsec 第一刀一起砍。
```

新增入口：

```text
Makefile:
  ANDROID_RELEASE_NOIPSEC_BUILD_DIR
  ANDROID_RELEASE_NOIPSEC_STAGE_DIR
  ANDROID_RELEASE_NOIPSEC_CMAKE_ARGS

  android-vpp-configure-release-no-multiarch-no-ipsec
  android-vpp-build-release-no-multiarch-no-ipsec
  android-vpp-stage-release-no-multiarch-no-ipsec
  android-vpp-push-release-no-multiarch-no-ipsec
  android-vpp-minimal-release-no-multiarch-no-ipsec
```

overlay 变更：

```text
新增 CMake option:
  -DSAKAMOTO_VPP_NO_IPSEC=ON

开启后：
  1. vnet/CMakeLists.txt 不编译 ipsec/* source、header、API 和 ipsec_test.c。
  2. 定义 SAKAMOTO_VPP_NO_IPSEC=1。
  3. ip4/ip6/interface-output feature arc 不注册 IPsec feature。
  4. ip4/ip6 前序 feature 直接 runs_before 到下一个非 IPsec 节点。
```

### 9.1 configure 失败记录和修正

第一轮 configure 失败：

```text
CMake Error at cmake/library.cmake:121 (cmake_parse_arguments):
  cmake_parse_arguments must be called with at least 4 arguments.

原因：
  overlay 用 perl 生成 add_vat_test_library(vnet ${SAKAMOTO_VNET_VAT_TEST_SOURCES}) 时，
  ${...} 被 perl replacement 当成变量吃掉，导致 CMake 实际看到：

    add_vat_test_library(vnet

    )

修正：
  在 perl replacement 中转义为 \${SAKAMOTO_VNET_VAT_TEST_SOURCES}。
  同时增加一次修复分支，自动修复已经被坏 overlay 改写过的 work/vpp 源码。
```

### 9.2 feature arc 残留引用修正

第一轮 minimal 启动成功，但 stdout 有 feature warning：

```text
feature node 'ipsec6-output-feature' not found (after 'gso-ip6', arc 'ip6-output')
feature node 'ipsec6-input-feature' not found (after 'ip6-full-reassembly-feature', arc 'ip6-unicast')
feature node 'ipsec4-output-feature' not found (after 'gso-ip4', arc 'ip4-output')
feature node 'ipsec4-input-feature' not found (after 'ip4-full-reassembly-feature', arc 'ip4-unicast')
vppctl_rc=0
```

判断：

```text
只旁路 ip4_forward/ip6_forward/interface_output 不够。
GSO 和 full reassembly 也有 runs_before 到 IPsec feature 的排序约束。
这些不是 IPsec 模块本体，但 no-IPsec 构建不能留下 dangling feature 名称。
```

修正：

```text
vnet/gso/node.c:
  no-IPsec 时 gso-ip4 / gso-ip6 runs_before interface-output。

vnet/ip/reass/ip4_full_reass.c:
  no-IPsec 时 ip4-full-reassembly-feature runs_before ip4-lookup 和 ip4-sv-reassembly-feature。

vnet/ip/reass/ip6_full_reass.c:
  no-IPsec 时 ip6-full-reassembly-feature runs_before ip6-lookup。
```

修正后 minimal stdout 为空，VPP log 只有启动和 vppctl 命令记录，没有 feature warning。

### 9.3 build and stage

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-configure-release-no-multiarch-no-ipsec
make -C experiments/vpp-nfq-poc android-vpp-build-release-no-multiarch-no-ipsec
make -C experiments/vpp-nfq-poc android-vpp-stage-release-no-multiarch-no-ipsec
```

结果：

```text
release no-multiarch no-IPsec stage total: 9.4M
stage du -sb: 9,789,841 bytes

bin/vpp:                         103,040 bytes
bin/vppctl:                       10,624 bytes
lib/libsvm.so:                   104,184 bytes
lib/libvlib.so:                  683,216 bytes
lib/libvlibapi.so:                67,992 bytes
lib/libvlibmemory.so:            158,672 bytes
lib/libvnet.so:                8,103,096 bytes
lib/libvppinfra.so:              467,744 bytes
plugins/nfqueue_poc_plugin.so:    52,120 bytes
plugins/tun_poc_plugin.so:        18,136 bytes
```

对比：

```text
release no-multiarch stage:          11M
release no-multiarch no-IPsec stage: 9.4M

release no-multiarch libvnet.so:          9,167,104 bytes
release no-multiarch no-IPsec libvnet.so: 8,103,096 bytes
delta:                                   -1,064,008 bytes

release no-multiarch libvnet .text:          0x62dbd8
release no-multiarch no-IPsec libvnet .text: 0x55e980
delta:                                      -0xcf258 bytes
```

符号检查：

```text
nm -D libvnet.so | grep -E " (ipsec|esp|ah)_| ipsec|esp_encrypt|esp_decrypt|ah_encrypt|ah_decrypt"
结果为空。

nm -D libvnet.so | grep -i ipsec 仍可看到 flow_match_ip4_ipsec_ah/esp。
这是 flow 匹配里的协议枚举/格式化符号，不是 IPsec datapath 模块。
```

### 9.4 no-IPsec minimal 真机启动

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-minimal-release-no-multiarch-no-ipsec
```

结果：

```text
设备：Pixel 6a / Android 16 / root via su

vppctl show version:
  vpp v26.02-release built by js on Main at 2026-06-22T08:23:15
  vppctl_rc=0

root minimal VPP RSS:
  102,396 KB

stdout:
  <empty after feature arc fix>
```

### 9.5 Android 3C no-IPsec datapath 验收

APK 构建：

```sh
VPP_STAGE_DIR=/home/js/Git/sakamoto/sakamoto-snort/experiments/vpp-nfq-poc/work/android-vpp-release-no-multiarch-no-ipsec-stage \
  experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

APK 结果：

```text
snort-vpn-lite-debug.apk: 3.3M
APK file size: 3,511,883 bytes
APK uncompressed entries total: 10,134,275 bytes
lib/arm64-v8a/libvnet.so: 8,103,096 bytes
```

启动：

```text
mode=vpp-hev

logcat:
  started VPP HEV pid=28115
  started VPP pid=28114 fd=127 mode=2
  nativeStartVppProbe fd=127 vppMode=2 rc=0
```

HTTP probe：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
```

SOCKS5 smoke server：

```text
connect 93.184.216.34:80
payload-len 43
GET /probe HTTP/1.0
Host: example.test
```

最终 `show tun-poc`：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 22 bytes 1698 tx 11 bytes 556
shim-rx 11 bytes 556 shim-tx 22 bytes 1698
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

app context VPP 资源短采样：

```text
RSS: 111,704 KB
CPU samples: 0, 5, 0, 0, 0
```

清理：

```text
Stop intent + force-stop app。
kill device-local sakamoto-socks5-smoke。
确认无 vpp / vpnlite / sakamoto-socks5 / HEV 残留。
```

Round 4C 结论：

```text
release + no ARM multiarch + no IPsec 已通过 Android 3C L3 VPN datapath 验收。

体积链路：
  debug/O0-ish stripped stage:              186M
  release stripped stage:                    29M
  release no-multiarch stripped stage:       11M
  release no-multiarch no-IPsec stage:      9.4M

APK 链路：
  release APK:                              8.1M
  release no-multiarch APK:                 3.6M
  release no-multiarch no-IPsec APK:        3.3M

no-IPsec 第一刀收益明确但不巨大：
  libvnet.so 少约 1.06MB。
  APK 少约 0.3MB。

下一步如果继续裁剪，更大的候选不是 IPsec，而是 host stack/session/tcp、L2/MPLS/device/virtio、reassembly/GSO、API/VAT/test 等更大块。
```

## 10. Round 4D: Android idle CPU 复测

目的：

```text
重新确认 Android 真机空闲时 VPP 自身 CPU 占用。
早期日志里的 6.6% - 7.5% 来自 ps %CPU 短观察；4A/4B/4C 后续又只有 5 秒短采样。
本轮改用 /proc/<pid>/stat tick delta，以 5 秒窗口连续采样 12 次，约 60 秒。
```

采样公式：

```text
clk = getconf CLK_TCK
process_ticks = utime + stime from /proc/<pid>/stat
cpu% = (delta_ticks / clk) / elapsed_seconds * 100
```

注意：

```text
这里的 CPU% 是单进程相对单核的占用。
Android 设备后台仍可能产生少量系统流量；app idle 场景只表示我们没有主动发 HTTP probe。
```

### 10.1 release + no-multiarch root minimal

场景：

```text
stage: work/android-vpp-release-no-multiarch-stage
启动方式: android-run-vpp-minimal.sh
STOP_AFTER=0
不启用 tun_poc，不启用 nfqueue_poc，不走 VpnService/HEV。
```

结果：

```text
pid=28490 clk=100
RSS: 116,616 KB

5 秒窗口 CPU samples:
  2.756, 2.348, 1.949, 2.148, 2.153, 2.740,
  2.729, 1.961, 2.724, 2.559, 2.153, 2.941

avg: 2.430%
min: 1.949%
max: 2.941%
```

### 10.2 release + no-multiarch + no-IPsec root minimal

场景：

```text
stage: work/android-vpp-release-no-multiarch-no-ipsec-stage
启动方式: android-run-vpp-minimal.sh
STOP_AFTER=0
不启用 tun_poc，不启用 nfqueue_poc，不走 VpnService/HEV。
```

结果：

```text
pid=28696 clk=100
RSS: 102,612 KB

5 秒窗口 CPU samples:
  2.569, 2.353, 2.549, 2.544, 2.554, 2.353,
  1.754, 2.344, 2.745, 1.969, 2.549, 2.144

avg: 2.369%
min: 1.754%
max: 2.745%
```

per-thread 10 秒采样：

```text
pid=28696 elapsed=10.08 clk=100
tid=28696 cpu=2.381 comm=vpp_main
```

判断：

```text
空闲 CPU 主要来自 vpp_main。
没有看到 worker/plugin 线程占满 CPU。
```

### 10.3 release + no-multiarch + no-IPsec app idle

场景：

```text
APK: no-IPsec stage 打包后的 vpn-lite debug APK
启动方式: mode=vpp-hev
不主动发送 HTTP probe。
VpnService、VPP、HEV 已启动。
```

启动：

```text
started VPP HEV pid=28286
started VPP pid=28285 fd=126 mode=2
nativeStartVppProbe fd=126 vppMode=2 rc=0
```

结果：

```text
pid=28285 clk=100
RSS: 113,916 KB

5 秒窗口 CPU samples:
  2.761, 2.734, 2.935, 2.941, 2.941, 2.157,
  2.549, 2.750, 2.539, 2.157, 3.143, 2.554

avg: 2.680%
min: 2.157%
max: 3.143%
```

Round 4D 结论：

```text
当前 release/no-multiarch 系列在 Android 真机 idle 时，VPP 自身不是 6% - 7% 基线。
更可信的 tick-delta 复测结果是：

  4B root minimal: 约 2.43%
  4C root minimal: 约 2.37%
  4C app idle:     约 2.68%

no-IPsec 对 idle CPU 没有明显帮助，主要收益仍是体积和 RSS。
当前 idle CPU 来源集中在 vpp_main，下一步如果要继续压 CPU，应优先研究 VPP main loop/timer/poll-sleep 行为，而不是继续裁 IPsec。
```

## 11. Round 4E: Android idle CPU simpleperf 火焰图

目的：

```text
不再推测 idle CPU 来源，直接对 Android 真机上的 VPP idle 进程抓 simpleperf 调用栈。
```

场景：

```text
stage: release + no-multiarch + no-IPsec
启动方式: android-run-vpp-minimal.sh
poll-sleep-usec: 1000
VPP pid: 29855
流量: 无主动流量
```

采样命令：

```sh
simpleperf record \
  -e cpu-clock \
  -f 1000 \
  -p 29855 \
  --call-graph dwarf \
  --duration 30 \
  -o /data/local/tmp/vpp-idle.perf.data
```

采样结果：

```text
Recorded for 30.0128 seconds.
Samples recorded: 2,551
Samples lost: 0
```

本地 artifacts：

```text
experiments/vpp-nfq-poc/results/simpleperf-vpp-idle/vpp-idle.perf.data
experiments/vpp-nfq-poc/results/simpleperf-vpp-idle/report.html
experiments/vpp-nfq-poc/results/simpleperf-vpp-idle/report-children.txt
experiments/vpp-nfq-poc/results/simpleperf-vpp-idle/report-callgraph.txt
```

文本聚合关键结果：

```text
Children  Self    Symbol
99.02%    3.10%   vlib_main
73.50%    1.33%   vlib_file_poll
65.15%    2.31%   nanosleep
42.85%    9.88%   __arm64_sys_nanosleep
31.79%    10.00%  do_nanosleep
17.29%    1.84%   schedule
13.37%    13.09%  finish_task_switch
6.94%     0.71%   __epoll_pwait
2.16%     0.59%   __arm64_sys_epoll_pwait
```

完整调用图中的主路径：

```text
clib_calljmp
  -> vlib_main
    -> vlib_file_poll
      -> nanosleep
        -> __arm64_sys_nanosleep
          -> do_nanosleep
            -> schedule

clib_calljmp
  -> vlib_main
    -> vlib_file_poll
      -> __epoll_pwait
        -> __arm64_sys_epoll_pwait
          -> do_epoll_wait
```

代码位置：

```text
work/vpp/src/vlib/file.c

if (is_main && um->poll_sleep_usec)
  {
    nanosleep(...poll_sleep_usec...);
    goto epoll;
  }

epoll:
  epoll_wait(..., timeout_ms);
```

Round 4E 结论：

```text
火焰图确认：当前 idle CPU 主要不是 tun_poc/nfqueue_poc 包路径轮询。
CPU 时间集中在 VPP main thread 的 vlib_file_poll：
  1. 显式 poll-sleep-usec 触发的 nanosleep syscall 路径。
  2. 随后的 epoll_wait/epoll_pwait 路径。

因此当前剩余 idle CPU 的直接原因，是 VPP main loop 在 idle 下仍周期性执行
nanosleep + epoll_wait + syscall/调度开销。

这和包 fd 是否事件驱动是两件事：
  tun_poc/nfqueue_poc 已用 clib_file_add/read_function 挂到 VPP epoll。
  但 vpp_main 自己仍按主循环节奏醒来。
```

下一步建议：

```text
不要继续猜。
下一轮应加 VPP main loop 计数器或 trace：
  - 每秒 vlib_file_poll 调用次数
  - 每秒 nanosleep 次数
  - 每秒 epoll_wait 次数
  - epoll_wait 返回 0 / >0 / error 的次数
  - timeout_ms 分布

这样可以区分：
  A. poll-sleep-usec 固定 sleep 导致的周期唤醒。
  B. epoll_wait timeout/timer wheel 导致的周期唤醒。
  C. 其它 VPP process/timer/API/statseg/CLI 事件不断唤醒 main loop。
```

## 12. Round 4F: Android 默认删除 poll-sleep-usec

目的：

```text
把上轮 flamegraph 结论落成当前 Android 默认配置。

不再在 Android startup.conf 中设置 poll-sleep-usec 1000。
原因：poll-sleep-usec 会让 vlib_file_poll 先 nanosleep，再进入 epoll_wait。
这会引入固定周期 nanosleep syscall/调度开销，而且 fd ready 不能打断 nanosleep。
```

修改：

```text
删除以下 Android 路径里的 poll-sleep-usec 1000：

experiments/vpp-nfq-poc/scripts/android-stage-vpp-core.sh
experiments/vpp-nfq-poc/scripts/android-stage-vpp-lite.sh
experiments/vpp-nfq-poc/android/vpn-lite/native/vpn_fd_probe.c
```

不修改：

```text
host POC configs 和历史实验说明暂不改。
它们记录的是早期 Linux/host 实验结论，不代表当前 Android 默认策略。
```

### 12.1 no-IPsec root minimal 验证

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-stage-release-no-multiarch-no-ipsec
grep -n "poll-sleep-usec" \
  experiments/vpp-nfq-poc/work/android-vpp-release-no-multiarch-no-ipsec-stage/runtime/startup.conf
make -C experiments/vpp-nfq-poc android-vpp-minimal-release-no-multiarch-no-ipsec
```

结果：

```text
stage startup.conf:
  0 matches for 'poll-sleep-usec'

root minimal:
  VPP process WCHAN: do_epoll_wait
  vppctl show version: rc=0
  stdout: <empty>
```

判断：

```text
删除 poll-sleep-usec 后，VPP idle 进入 do_epoll_wait 路径，而不是 __arm64_sys_nanosleep。
```

### 12.2 no-IPsec app 3C datapath 验证

APK 构建和安装：

```sh
VPP_STAGE_DIR=/home/js/Git/sakamoto/sakamoto-snort/experiments/vpp-nfq-poc/work/android-vpp-release-no-multiarch-no-ipsec-stage \
  experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh

experiments/vpp-nfq-poc/android/vpn-lite/scripts/install-debug-apk.sh
```

app 生成的 startup.conf：

```text
unix {
  nodaemon
  nobanner
  runtime-dir /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime
  log /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp.log
  cli-listen /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/cli.sock
  startup-config /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/startup.exec
}
```

启动：

```text
mode=vpp-hev

logcat:
  started VPP HEV pid=31270
  started VPP pid=31269 fd=126 mode=2
  nativeStartVppProbe fd=126 vppMode=2 rc=0
```

HTTP probe：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
```

最终 `show tun-poc`：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 22 bytes 1698 tx 9 bytes 476
shim-rx 9 bytes 476 shim-tx 22 bytes 1698
short 0 non-ipv4 0 non-icmp 0 non-echo 0
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

app idle tick-delta 短采样：

```text
pid=31269 clk=100
RSS: 111,584 KB

5 秒窗口 CPU samples:
  2.367, 2.161, 1.961, 2.353, 1.953, 2.344

avg: 2.190%
min: 1.953%
max: 2.367%
```

对比 Round 4D：

```text
poll-sleep-usec 1000 app idle avg: 2.680%
unset poll-sleep-usec app idle avg: 2.190%
```

Round 4F 结论：

```text
当前结果策略：
  Android 默认不设置 poll-sleep-usec。

原因：
  1. 包路径仍然是 clib_file/epoll read callback，不引入包 fd 轮询。
  2. vpp_main idle 从 nanosleep 固定睡眠路径回到 epoll_wait 路径。
  3. no-IPsec Android 3C datapath 仍通过。
  4. app idle CPU 短采样从约 2.68% 降到约 2.19%。

这不是最终极限优化，但它是当前证据支持的最小正确改动。
更激进的 epoll timeout / timer wheel 修改应作为下一轮 VPP main loop 定点优化，而不是 Android 默认先上。
```

## 13. Round 4G: Android idle CPU 深挖结果

目的：

```text
确认 unset poll-sleep-usec 后，为什么 root minimal / app idle 仍有约 2% CPU。
用户预期是：无流量时应该只有极少 CPU 占用。
```

### 13.1 纯 root minimal 复测

先排除 vpn-lite / HEV / app 监控线程干扰：

```text
stage: release + no-multiarch + no-IPsec
启动方式: root minimal
不启用 tun_poc，不启用 nfqueue_poc，不走 VpnService/HEV
poll-sleep-usec: unset
```

60 秒 tick-delta：

```text
pid=31728 clk=100
Name: vpp_main
Threads: 1
RSS: 102,612 KB

5 秒窗口 CPU samples:
  1.935, 2.151, 2.332, 2.348, 1.952, 2.141,
  1.953, 2.348, 2.156, 2.333, 1.958, 2.351

avg: 2.163%
min: 1.935%
max: 2.351%
```

结论：

```text
2% idle 不是 vpn-lite / HEV / app 监控线程导致。
纯 VPP root minimal、单线程、无主动流量时也存在。
```

### 13.2 unset poll-sleep-usec 后的 simpleperf

采样：

```text
simpleperf record -e cpu-clock -f 1000 -p 31728 --call-graph dwarf --duration 30
Samples recorded: 1,088
Samples lost: 0
```

关键热点：

```text
vlib_main          97.79%
vlib_file_poll     45.68%
__epoll_pwait      42.74%
do_epoll_wait      30.61%
schedule           23.71%

process_expired_timers / vlib_tw_timer_expire_timers:
  libvlib.so+0x3c8c4
  libvppinfra.so+0x5f55c / +0x5f560 / +0x5f568 ...
```

符号化后确认：

```text
libvlib.so+0x3c8c4:
  vlib_tw_timer_expire_timers
  process_expired_timers

libvppinfra.so+0x5f55c 等:
  tw_timer_expire_timers_internal_1t_3w_1024sl_ov
```

### 13.3 临时计数器结果

在实验 worktree 的 `vlib/file.c` 加临时 `show file-poll-debug` 计数器。

unset poll-sleep-usec 且未设置 timer floor 时，10 秒左右观测：

```text
calls 11969
skip_vectors 0
skip_polling_nodes 0
skip_api_queue 0
pending_interrupts 0
epoll_calls 11969
epoll_timeout_zero 10035
epoll_timeout_positive 1934
epoll_return_zero 11962
epoll_return_ready 7
timeout_min 0
timeout_max 1000
timeout_avg 1.667
```

关键结论：

```text
不是 polling input node 导致忙轮询。
也不是 api_queue 或 pending interrupt。

直接原因是：
  VPP timer wheel 返回的正 ticks 小于 1ms；
  vlib_file_poll 中 ticks -> timeout_ms 使用整数除法；
  小于 1ms 的正 timeout 被截断成 0；
  epoll_wait(timeout=0) 变成非阻塞轮询。
```

### 13.4 timer floor 实验

实验性修改：

```c
timeout_ms = ticks / (VLIB_TW_TICKS_PER_SECOND / 1000);

// Android 实验：正 timeout 不小于 N ms
if (timeout_ms < N && ticks != 0)
  timeout_ms = N;
```

结果：

```text
N = 1ms:
  epoll_timeout_zero 降为 0
  epoll 平均 timeout 约 8.6ms
  CPU avg: 1.706%

N = 100ms:
  epoll 平均 timeout 约 102ms
  CPU avg: 1.527%

N = 1000ms:
  epoll 平均 timeout 1000ms
  CPU avg: 1.479%
  simpleperf samples: 495 / 30s
```

对比：

```text
unset poll-sleep-usec baseline:
  CPU avg: 2.163%
  simpleperf samples: 1,088 / 30s

timer floor 1000ms:
  CPU avg: 1.479%
  simpleperf samples: 495 / 30s
```

### 13.5 结论

```text
只改 epoll timeout 不够。

poll-sleep-usec 删除解决了 nanosleep 固定唤醒问题。
timer floor 解决了 sub-ms timer 被截成 epoll timeout 0 的问题。
但完整 libvnet runtime 仍会注册大量默认 process/timer：
  ip4/ip6 full reassembly expire walk
  ip4/ip6 sv reassembly expire walk
  ip6 mld / ra
  fib-walk
  statseg collector
  以及其它 vnet 默认 process

在 1Hz epoll 下，simpleperf 剩余热点仍主要是：
  process_expired_timers
  vlib_tw_timer_expire_timers
  tw_timer_expire_timers_internal_1t_3w_1024sl_ov

所以当前可证结论是：
  使用完整 libvnet 的 VPP Android runtime，即使不处理任何包，也不是低功耗 idle 形态。
  要达到“无流量时极少 CPU”，必须继续裁掉或禁用不需要的 vnet 默认 process/timer，
  或推进 vlib-only / vpp_lite runtime，而不是继续只调 poll-sleep-usec。
```

当前不建议把 timer floor 作为最终提交：

```text
它能减少 wake 次数，但没有把 CPU 压到目标量级。
而且 100ms/1000ms floor 会延后 VPP 内部 timer，属于策略取舍，不应在没有更完整
datapath 验证前作为默认 runtime 行为。
```
