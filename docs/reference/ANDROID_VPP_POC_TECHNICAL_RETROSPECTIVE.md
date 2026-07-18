# Android VPP POC 技术复盘

状态：截至 2026-06-29 的 point-in-time 技术证据，不是产品架构决策。

基线：upstream VPP `v26.02`，Android NDK r29，编译 API 31；实机为已 root 的 Pixel 6a、Android 16 / API 36、arm64、SELinux Enforcing。VPN POC 的 VPP 运行在普通 app UID / `untrusted_app` sandbox，进程路径不调用 `su`；但尚未在一台从未 root 的设备上重复整套实验。

本文只回答：遇到了什么、如何定位、哪些尝试失败、最终怎样跑通、结论到哪里为止。原始数据以文末日志为准。

## 0. 演进顺序

```text
Linux/Docker NFQUEUE 基线
  -> Android 交叉编译
  -> root 下 VPP daemon + NFQUEUE verdict
  -> app UID 下 VpnService TUN fd -> VPP
  -> VPP -> HEV -> SOCKS5 -> VPP 完整 VPN 链路
  -> release / no-multiarch / no-IPsec 体积收缩
  -> Android idle profile 降低空闲 CPU
  -> worker handoff、VPP 内 UID verdict、owner cache
  -> VPP binary API / C shim / Rust 控制面 POC
```

开始 Android 工作前，Linux/Docker 已证明两件事：VPP `v26.02` 可以构建；VPP 插件可以持有 NFQUEUE fd，并对同一 queue 逐包返回 `NF_ACCEPT` / `NF_DROP`。Android 阶段不再重新证明 VPP/NFQUEUE 的基本模型，只处理 Android 平台差异。

## 1. 从不能编译到 Android 真机 daemon

### 1.1 上游 configure 直接拒绝 Android

表现：NDK clang 已识别 arm64，但 VPP 顶层 CMake 在 configure 阶段报 `Unsupported system: Android`。

原因：VPP `v26.02` 只有 Linux/FreeBSD 平台分支，没有 Android 平台入口。

处理：建立可重复应用的 Android overlay，而不是直接维护一份不可追踪的 VPP fork：

- cross-compile 分支接受 Android；
- 保留 NDK toolchain 已设置的 compiler target；
- minimal subdirs 将 Android 视为 Linux-like 平台；
- POC 插件允许 `SUPPORTED_OS_LIST Android`。

过程中的脚本错误：最初用 Perl 重写 CMake 时，`${CMAKE_SYSTEM_NAME}` 被当成 Perl 变量插值并写空。修正为按 section 替换并显式转义 CMake 变量。

结果：CMake configure 通过，但 OpenSSL、libunwind、libnetfilter_queue 等缺失功能被自动禁用。此时只证明“能生成构建系统”。

### 1.2 bionic 与 glibc/Linux API 不兼容

构建继续后，错误按以下顺序暴露：

| 失败表现 | 原因 | POC 修正 | 保留风险 |
| --- | --- | --- | --- |
| 缺 `pthread_mutex_consistent`、`pthread_mutexattr_setrobust`、`PTHREAD_MUTEX_ROBUST` | bionic 没有 glibc robust mutex API | Android-only no-op shim，集中到 SVM queue 公共头 | 不提供跨进程 owner-death recovery；产品若依赖 SVM robust 语义必须重设计 |
| `struct dlmallinfo` incomplete | Android configure 条件没有得到 dlmalloc 自带定义 | Android 下取消错误的已声明状态，使用 dlmalloc 自有 `dlmallinfo` | POC 兼容层，不代表上游支持 |
| `malloc_usable_size` 类型冲突 | bionic 参数是 `const void *` | Android 分支匹配 bionic 声明 | 无额外语义变化 |
| `libvppinfra.so` 缺 Linux memory/sysfs/netns/ELF 符号 | Android 未进入 Linux platform source 集合 | Android 构建纳入所需 Linux source | 只纳入实际链接所需部分 |
| SVM 缺 `shm_open` / `shm_unlink` | Android 没有可直接复用的 POSIX shm 形态 | 用目录中的普通文件模拟 shm，root 默认 `/data/local/tmp/vpp-shm` | 不是正式 Android IPC/shared-memory 设计 |
| 链接找不到 `-lrt` / `-lpthread` | Android 将这些能力并入 bionic libc | Android SVM 不再显式链接 `rt` / `pthread` | Android 专用构建规则 |
| 缺 `index()`、`bzero()` | NDK 未暴露这些 BSD 接口 | 映射为 `strchr()`、`memset()` | 纯兼容替换 |
| `libvlib.so` 缺 PCI/VFIO/VMBus 符号 | VLIB 平台源选择不完整 | 纳入必要 Linux platform source | 后续仍应按实际 Android runtime 裁剪 |

线程亲和性最初也因缺少 `pthread_setaffinity_np` 而临时做成 no-op。这个办法只用于尽快验证启动；后续已替换为 `pthread_gettid_np + syscall(SYS_sched_setaffinity)`，并在 VPP main/worker 上实机确认绑核生效。

结果：`bin/vpp` 和核心动态库成功构建为 Android arm64 ELF，动态解释器为 `/system/bin/linker64`。

### 1.3 binary 能执行，但 daemon 启动崩溃

第一步只运行：

```text
LD_LIBRARY_PATH=<stage>/lib <stage>/bin/vpp -v
```

结果成功，说明动态链接成立。第一次 ADB push 曾因目标目录由 root 创建、shell 用户无写权限而失败；push 前临时放宽具体 stage 目录权限，完成后恢复 755。

随后启动 minimal daemon 时：

```text
进程很快退出
vppctl: Connection refused
前台 rc=139
日志只有 Start 行
```

插桩确认 core init 和 main-loop 前置初始化已经完成，崩溃集中在 VLIB process startup/dispatch，且加重 tracing 后崩溃点会在不同 reassembly process 间移动。

原因：默认 `VLIB_PROCESS_LOG2_STACK_SIZE=15`，每个 VLIB process 栈只有 32 KiB；Android/bionic 组合下不足。

修正：Android 构建固定 `VLIB_PROCESS_LOG2_STACK_SIZE=18`，即 256 KiB。移除临时 tracing 后，minimal daemon 持续运行，`vppctl show version` 通过。

这是“VPP binary 能运行”到“VPP daemon 真正运行”的分界点。

### 1.4 NFQUEUE 插件不能构建

表现：core 已能启动，但 configure 报 `libnetfilter_queue headers not found`，`nfqueue_poc` 被禁用。

处理：复用仓库内 Android netfilter userspace 源，静态构建 `libmnl`、`libnfnetlink`、`libnetfilter_queue` 后链接进插件。

期间遇到三次失败：

1. include path 先命中了项目里的低层 wrapper header，缺 `nfq_open` 等高层 API。修正为只使用 upstream `libnetfilter_queue/include`，单独生成 `config.h`。
2. NDK 与 vendored `nfnetlink` kernel header 重复定义 enum/struct。修正为统一转发到 NDK sysroot 的 `<linux/netfilter/nfnetlink.h>`。
3. Android shared library 使用 `--no-undefined`，不能像 Linux POC 一样把 VPP core 符号留到运行时解析。修正为插件显式链接 `vlib`、`vppinfra`。

结果：Android `nfqueue_poc_plugin.so` 构建成功。

### 1.5 插件存在，但 early init 再次 SIGSEGV

表现：加入插件后 VPP 在 early startup `SIGSEGV`；tombstone 落在 `strlen -> format -> vlib_plugin_early_init`。

原因：VPP early plugin init 在解析 `startup.conf` 之前读取全局 `vlib_plugin_path`。只在配置文件的 `plugins { path ... }` 中设置路径太晚，early init 得到空路径。

修正：将 `plugin_path <dir>` 作为 VPP 进程启动参数传入；配置文件继续负责插件 enable/disable。

结果：插件加载，`show nfqueue-poc` 可用。

### 1.6 root/NFQUEUE 闭环

在 queue 42 上插入窄范围临时 iptables 规则，避免复用正式 Snort queue 0..7：

- IPv4 OUTPUT：`accept-all` 时 ping 4/4；`drop-all` 时 0/4；VPP 计数分别为 4 accept / 4 drop。
- IPv4 INPUT：回包同样可由 VPP accept/drop。
- 后续真实 App TCP 已验证 package UID allow/block；IPv6 exact-destination block 也已验证。

已确认：root 模式下 VPP 可以直接拥有 Android NFQUEUE verdict。

未确认：root 双栈最终 queue 拓扑仍是实验形态；NFQUEUE、iptables 和 root 权限属于 root 模式约束，不是 VPP binary 本身只能以 root 运行。

## 2. 从 root/NFQUEUE 到无 root VPN 数据面

### 2.1 为什么换到 VpnService

root/NFQUEUE 已跑通，但它要求 root 安装规则和持有 NFQUEUE。面向普通 Android 设备，需要使用系统允许的 `VpnService`：Android framework 创建 full-route L3 TUN fd，VPP 作为 app 子进程消费该 fd。

目标边界始终是：VPP 是 packet interception/verdict owner；HEV 只负责允许流量的 egress，不直接拥有主 TUN fd。

### 2.2 Phase 1：先证明 TUN fd

没有可直接使用的 Gradle/build-tools 环境，因此复用 Lineage prebuilts，以 `javac + d8 + aapt2 + zipalign + apksigner` 构建无 Gradle APK。

第一版不启动 VPP：

```text
VpnService.establish()
  -> ParcelFileDescriptor.detachFd()
  -> JNI native thread read(fd)
```

结果：native 直接读到 IPv4/IPv6 L3 packet。未接转发时 full-route VPN 会黑洞全部流量，这是预期现象，不是 fd 失败。

### 2.3 Phase 2：让 VPP 在 app UID 下读 TUN

采用 `fork + dup2 + execve`：主 TUN 固定继承为 fd 3，VPP/tun_poc 先运行 `count-only`。

暴露两个 Android app sandbox 问题：

| 失败表现 | 原因 | 修正 |
| --- | --- | --- |
| app UID 不能写 `/data/local/tmp/vpp-shm` | root POC 的 shm backing 路径不属于 app | 增加 `SAKAMOTO_ANDROID_SHM_DIR`，指向 app files 目录 |
| untrusted_app seccomp 禁止 arm64 `get_mempolicy` syscall | VPP NUMA 探测不适用于普通 app sandbox | Android 下禁用 VPP NUMA get/set_mempolicy，固定 NUMA node 0 |

Android package manager 可以从 APK native 目录提取 VPP binary、依赖库和 POC plugin。VPP 在 app UID 下启动，`tun_poc` 的 packet/byte 计数持续增长。

结论：最初“只能 root 运行”只适用于当时的 root stage/NFQUEUE 路径。经过 shm 和 NUMA 适配后，VPP daemon 已在普通 app UID / `untrusted_app` context 下运行并读取 VpnService fd，全程未调用 `su`。测试设备本身仍已 root，因此这里证明的是 app sandbox 可运行性，不是未 root 设备矩阵。

### 2.4 Phase 3：把允许流量交给 HEV

先在 Linux/Docker 分拆验证：

1. HEV 能把 `SOCK_SEQPACKET` 一端当 external TUN fd；
2. VPP 能在主 TUN fd 与 shim fd 间双向转发；
3. Linux TCP flow 能走 `TUN -> VPP -> HEV -> SOCKS5 -> HEV -> VPP -> TUN` 并收到 HTTP 响应。

失败信号：Linux 完整链路结束时 HEV 输出 `free(): invalid size`。它没有阻断单次 HTTP，但意味着 lifecycle/memory 未通过。Android 因此先单独验证 HEV `.so` 的 `dlopen/start/stop`，未直接把所有组件一次接上。Android 运行中未复现该错误，但多连接和长期生命周期仍未验证。

Android 侧继续分两步：

- 3B：VPP 将真实 VPN packet 写到 shim；native shim 反射 ICMP，再由 VPP 写回主 TUN。ping 成功，证明双向桥接。
- 3C：用 HEV 替换 native shim，接 SOCKS5，HTTP 返回 `200 OK`，四向计数增长且错误计数为 0。

曾尝试 `adb reverse tcp:41080` 将设备 HEV 连接导回宿主 SOCKS5，但该设备/ADB 组合没有命中宿主监听端口。最终改用设备本地受控 SOCKS5 smoke server。这个方案只验证数据面，没有解决正式 upstream socket 的 `VpnService.protect()`。

### 2.5 IPv6、App 选择和 UID 归因

完整链路之后又补了：

- `VpnService.Builder` 的 package include/exclude；
- VPN IPv6 address/route 和公网 IPv6 转发；
- VPP 内静态 IPv4/IPv6 destination drop；
- `ConnectivityManager.getConnectionOwnerUid()` 对 IPv4/IPv6、TCP/UDP tuple 的 owner UID 查询。

UDP 首次查询返回 `-1`，原因是测试 socket 发送后立即关闭，查询时连接记录已消失。让 connected UDP socket 保持 3 秒后，查询得到真实 package UID。TCP/IPv6 后续包也可能从 UID 变成 `-1`，说明 API 存在可见窗口，必须缓存首个成功结果。

IPv6 parser 当前只覆盖无 extension header 的基线。

### 2.6 一次重要的范围纠正

早期 owner gate 的实际路径是：

```text
real TUN -> parent native gate -> VPP -> HEV
```

它证明 Android 能查 UID 并拦截，但 verdict 不在 VPP。对应的 TCP/UDP/IPv4/IPv6 gate 和 64-slot cache POC 被明确降级为 mis-scoped，不能作为 VPP 内部过滤证据。

修正后的路径：

```text
real TUN
  -> VPP parses tuple
  -> Android resolver bridge returns UID
  -> VPP worker decides drop/forward
  -> HEV
```

### 2.7 worker handoff 问题

表现：即使 VPP 启动两个 worker，`clib_file` TUN/shim fd callback 仍全部运行在 thread 0；软件 fd 不会自动获得 worker 分流。

失败假设：仅配置 `workers 2` 不会让 TUN packet 自动进入 worker graph。

修正：main thread 的 input node 读取 packet、分配 `vlib_buffer_t`，通过 frame queue 显式 handoff 给 worker。随后验证：

- worker 能写 shim fd，完整 ping/HTTP 链路继续成立；
- worker 能做 IPv4/IPv6 static drop；
- worker 1 能再次 handoff 给 worker 2；
- redirected worker 仍能查询 Android owner UID 并执行 verdict。

最终证据：VPP 内部 UID drop 已覆盖 IPv4/IPv6 TCP/UDP send packet，包括 worker-to-worker redirect；单 tuple owner cache 已验证；20 包 UDP burst 只查询一次 resolver，并在 VPP 内 drop 20 包。

未解决：生产级 worker sharding、顺序、拥塞、cache 容量/过期/反向流/并发和异步 resolver。

## 3. 从 186 MB 到 9.4 MB

### 3.1 初始误判：插件太多

初始 stripped stage 为 186 MB，其中 `libvnet.so` 约 175 MB；RSS 约 321 MB。

第一次尝试只构建 `nfqueue_poc` 插件。结果 stage、RSS、idle CPU 几乎不变。

原因：stage 原本就只复制少量插件；真正的大头是 `bin/vpp` 的必需依赖 `libvnet.so`。减少 plugin 列表不等于减少 VPP core。

### 3.2 失败方向：vlib-only `vpp_lite`

实验性 `vpp_lite` 不链接 `libvnet.so`，stage 立即降到 11 MB。

但启动连续暴露缺失上下文：

- 完整配置中的 `api-segment/statseg` 不存在；
- VLIB `handoff_trace` 引用由 libvnet 提供的 `error-drop`；
- 补最小 `error-drop` 后，即使关闭全部插件，仍在 CLI socket 创建前 `SIGSEGV`，fault address `0x18`。

结论：11 MB 只是理论下限。vlib-only runtime 缺少 VPP app/libvnet 初始化上下文，不能作为可运行基线。

### 3.3 找到真正放大器

对 stripped `libvnet.so` 分解后确认：约 172 MiB 都是 `.text`，不是 debug symbol 或压缩问题。

两个主要放大器：

1. `CMAKE_BUILD_TYPE` 为空，实际接近 O0/debug 编译后再 strip，没有 `-O2/-O3`。
2. 默认启用五套 ARM server multiarch variant：`octeontx2`、`thunderx2t99`、`cortexa72`、`neoversen1`、`neoversev2`，大量 VNET node 被重复编译。

所以正确顺序不是先删 TCP/UDP，而是先修 build type，再关闭不匹配手机 SoC 的重复 variant。

### 3.4 有效裁剪链

| 阶段 | Stage | `libvnet.so` | APK | Root minimal RSS | 验收 |
| --- | ---: | ---: | ---: | ---: | --- |
| O0-ish + strip | 186 MB | 183.5 MB | 未作为有效 APK 基线 | 约 321 MB | daemon/NFQUEUE 通过 |
| release | 29 MB | 27.2 MB | 8.1 MB | 138.7 MB | 完整 VPN 3C 通过 |
| release + no multiarch | 11 MB | 9.17 MB | 3.6 MB | 116.7 MB | 完整 VPN 3C 通过 |
| release + no multiarch + no IPsec | 9.4 MB | 8.10 MB | 3.3 MB | 102.4 MB | 完整 VPN 3C 通过 |

Release 打开 `-O3/-Werror` 后还修正了 Android fortify/unused 警告：没有 `O_CREAT` 的 `open()` 不再传 mode，NUMA no-op 参数显式标记 unused，冲突字段名 `__unused` 改名。这些是 release 才暴露的真实构建问题。

关闭 multiarch 保留的是通用 `-march=armv8-a+crc` baseline；关闭的是 ARM server variant 的重复代码和 dispatch，不是关闭所有 ARM 优化。它可能损失某些峰值专用实现，但默认 variant 本来也不匹配 Pixel 6a 的 A55/A76/X1 核。

裁 IPsec 时，单纯移除 `ipsec/*` 不够。GSO、IPv4/IPv6 forward 和 full reassembly 的 feature ordering 仍引用已删除的 IPsec feature，启动出现 `feature node ... not found`。修正所有 dangling `runs_before` 后，warning 消失，完整 VPN 仍通过。

### 3.5 为什么停在 9.4 MB

no-IPsec 只再节省约 1.06 MB `libvnet.so` 和 0.3 MB APK。更大候选是 host stack/session/TCP、L2/MPLS/device、reassembly/GSO 等，但耦合和语义风险明显提高。

特别是 reassembly：删除后分片包无法提供完整 L4 facts，这不是纯体积问题，必须先决定产品语义。因此当前 9.4 MB 是“已跑完整 VPN 回归的可运行基线”，不是理论最小值。

## 4. 从约 7% idle 到约 0.03%

### 4.1 先排除 NFQUEUE busy loop

早期 `ps %CPU` 短采样约 6.6%-7.5%。只加载插件但不 enable NFQUEUE，与 enable queue 后的数值接近，因此不是 NFQUEUE fd 忙轮询。

换成 `/proc/<pid>/stat`、5 秒窗口连续 60 秒的 tick-delta 后，更可信基线为：

```text
release + no-multiarch root minimal: 2.43%
+ no-IPsec root minimal:             2.37%
完整 VPN app idle:                   2.68%
```

no-IPsec 没有明显降低 CPU，说明体积裁剪和 idle 问题不是同一件事。

### 4.2 `poll-sleep-usec 1000` 是第一层问题

simpleperf 显示 CPU 集中在：

```text
vlib_main -> vlib_file_poll -> nanosleep -> schedule
                             -> epoll_wait
```

Android 配置中的 `poll-sleep-usec 1000` 会让每轮先 nanosleep，再进入 epoll；fd ready 也不能打断前面的 nanosleep。

删除后：WCHAN 从 nanosleep 变为 `do_epoll_wait`，完整 VPN 回归通过，app idle 从约 2.68% 降到约 2.19%。但仍未达到目标。

### 4.3 epoll timeout 被截断成 0

计数器显示 10 秒约 11969 次 `epoll_wait`，其中 10035 次 timeout 为 0；没有 polling node、API queue 或 pending interrupt。

原因：VLIB timer wheel 默认 `100000 ticks/s`，即 10 us/tick；小于 1 ms 的正 ticks 转成整数毫秒后得到 0，`epoll_wait(timeout=0)` 退化为非阻塞轮询。

尝试给正 timeout 加 floor：

```text
1 ms floor:    idle 约 1.71%
100 ms floor:  idle 约 1.53%
1000 ms floor: idle 约 1.48%
```

有改善但不够，而且强行把真实短 timer 推迟到 100/1000 ms 会改变 VPP timer 语义，因此没有直接作为最终方案。

### 4.4 禁用明显 process timer 仍不够

插桩确认主要真实周期 timer 是：

- IPv4/IPv6 full reassembly expire walk，约各 100 次/5 秒；
- IPv4/IPv6 shallow virtual reassembly；
- IPv6 MLD/RA；
- FIB walk；
- statseg collector。

将八个 process 改为纯 event wait 后，真实 expired timer 基本归零，但 idle 仍约 1.75%；再放宽最大 epoll timeout 到 1000 ms，仍约 1.72%。

这推翻了“只要关掉几个默认 process 就够”的假设。没有 timer 真正过期时，主循环仍反复检查 timer wheel、计算 timeout、进入/退出 epoll。

### 4.5 只延长 sleep 也失败

在八个 process 已禁用的前提下，强制 1000 ms sleep 后 loops/sec 降到约 1，但 idle 仍约 1.3%-1.4%。simpleperf 几乎全部落在 `process_expired_timers/vlib_tw_timer_expire_timers`。

原因：默认 10 us tick 下，每睡 1 秒，timing wheel 醒来后要 catch up 约 100000 个 tick。问题从“频繁醒”变成“低频醒、每次大量追赶”。

### 4.6 最终有效组合

把 Android minimal runtime 的 timer tick 从 10 us 粗化到 1 ms后，catch-up 从约 100000 tick/s 降到约 1000 tick/s，idle 立即降到约 0.03%-0.05%。

随后拆掉危险的“短 timer 一律强推到 1 秒”逻辑，得到最终显式 profile：

1. 八个不需要的默认 process timer 改为 event wait；
2. `VLIB_TW_TICKS_PER_SECOND` 从 `1e5` 改为 `1e3`；
3. `vlib_file_poll()` 最大 sleep 从 10 ms 放宽到 1000 ms；
4. 保留 `min(computed_timer_timeout, max_timeout)`，真实短 timer 仍按计算时间醒来。

对照实验：只保留 1 ms tick、仍使用默认 10 ms 最大 sleep，idle 约 0.44%-0.50%；因此 1 ms tick 解决每轮成本，1000 ms 最大 sleep 解决无近端 timer 时的唤醒频率，两者都有效。

### 4.7 回归结果和边界

显式 `SAKAMOTO_VPP_ANDROID_IDLE_PROFILE` 默认关闭，只在 Android minimal profile 构建中启用。

实机 60 秒结果：

```text
root minimal:                       约 0.047%
NFQUEUE enabled、无流量:            约 0.016%
完整 VPN/VPP/HEV 跑过 HTTP 后 VPP: 约 0.030%
同一窗口 HEV:                       0.000% 可见占用
```

NFQUEUE OUTPUT accept/drop 和完整 VPN/TUN/HEV HTTP 都重新通过。

这个 profile 不是通用 VPP 配置。八个 process 进入纯 event wait 后，不能再假设 VPP 自带 reassembly expiry、IPv6 MLD/RA、FIB walk 和 statseg collector 仍具备原始周期行为；当前 POC datapath 没有依赖这些行为。

尚不能下结论：1 ms timer 对持续吞吐、尾延迟、CT timer、worker handoff、CLI/API latency、锁屏功耗和其它 VPP plugin 的影响。当前结果只证明短时 idle 与现有 POC datapath 不冲突。

## 5. 同期完成但不属于四条主线的 POC

### 5.1 CPU placement

Android affinity 从 no-op 改成真实 syscall 后，Pixel 6a 已验证：

```text
little: cpu 0-3
mid:    cpu 4-5
big:    cpu 6-7
```

VPP main/worker 可精确绑定到指定 core，`vppctl show threads` 与 `/proc/<pid>/task/*/status` 一致；little/mid/big 三种 placement 下 NFQUEUE accept/drop 均正确。没有持续吞吐、功耗或热稳定性结论。

### 5.2 VPP 控制面

Linux POC 已验证：

```text
Rust -> thin C ABI shim -> generated VAPI -> VPP binary API -> tun_poc
```

覆盖 typed status、owner-policy mutation、stage/rollback/commit、持久 connection、VPP 重启后的 stale handle 错误、新连接恢复，以及多个 Rust 线程通过 mutex 串行共享 client。

它没有在 Android 打包，也没有正式 compiled policy schema、稳定 C ABI、Tauri command、自动重连或 command replay。

## 6. 当前可以确认与不能确认的边界

### 已确认

- VPP `v26.02` 可以交叉构建，并在 Android root 以及普通 app UID / `untrusted_app` context 下作为 daemon 运行；后者在已 root 测试机上完成，但进程路径未使用 root。
- root 模式下 VPP 可以拥有 NFQUEUE verdict。
- VPN 模式下 VPP 可以消费 `VpnService` TUN fd，并在 HEV 前后保持双向 packet path。
- VPP worker 内可以按 Android owner UID 对 IPv4/IPv6 TCP/UDP send packet drop。
- 可运行 Android stage 已从 186 MB 降到 9.4 MB，完整 VPN 回归保持通过。
- Android idle profile 下短时空闲 CPU 已降到约 0.03%-0.05%，现有 NFQUEUE/VPN smoke 保持通过。

### 未确认

- 正式 upstream socket `VpnService.protect()`。
- sustained throughput、latency、battery、thermal、screen-off、多设备兼容性。
- HEV 多连接、长时间运行、异常退出和恢复。
- IPv6 extension header、fragment/reassembly 的产品语义。
- production worker sharding、packet ordering、backpressure。
- production owner cache、异步 resolver、反向流和 `uidKnown=false` 语义。
- compiled policy snapshot、epoch/generation、正式 VPP plugin API。
- Domain/DNS policy 和产品级 UI/telemetry。

## 7. 原始证据入口

- Android 编译、daemon、NFQUEUE、affinity：[ANDROID_EXPERIMENT_LOG.md](../../experiments/vpp-nfq-poc/ANDROID_EXPERIMENT_LOG.md)
- Android VPN/TUN/HEV：[ANDROID_VPN_EXPERIMENT_LOG.md](../../experiments/vpp-nfq-poc/ANDROID_VPN_EXPERIMENT_LOG.md)
- 体积与 idle CPU：[ANDROID_TRIM_EXPERIMENT_LOG.md](../../experiments/vpp-nfq-poc/ANDROID_TRIM_EXPERIMENT_LOG.md)
- 完整实验编号与后续 worker/UID/API 过程：[EXPERIMENT_LOG.md](../../experiments/vpp-nfq-poc/EXPERIMENT_LOG.md)
- 当前证据矩阵：[POC_STATUS.md](../../experiments/vpp-nfq-poc/POC_STATUS.md)
- Linux TUN/HEV 前置实验：[TUN_HEV_EXPERIMENT_LOG.md](../../experiments/vpp-nfq-poc/TUN_HEV_EXPERIMENT_LOG.md)

`android/vpn-lite/README.md` 停留在早期 Phase 1/2，不能代表后续 HEV、worker handoff 和 UID verdict 的最终 POC 状态。
