# Android VPP NFQUEUE Experiment Log

日期：2026-06-21
分支：`research/vpp-nfq-poc`

本文记录第二组 Android 真机 VPP NFQUEUE 实验的原始过程。记录按时间顺序追加。

## 1. 实验启动

背景：

```text
第一组 Linux / Docker POC 已证明 VPP 能通过 NFQUEUE 收包，并对 ACCEPT / DROP verdict 正确回写。
Android 真机 NFQUEUE 可用性此前已由完整 Snort 真机运行验证过，本组实验不再重复证明这一点。
```

本组目标：

```text
验证 VPP 在真实 Android 设备上能否启动、加载 nfqueue_poc 插件，并通过 Android NFQUEUE 的 INPUT / OUTPUT 包执行 allow / drop。
```

新增文档：

```text
ANDROID_EXPERIMENT_PLAN.md
ANDROID_EXPERIMENT_LOG.md
```

新增脚本入口计划：

```text
make android-preflight
```

第一步只采集设备与运行环境，不改 iptables 规则。

## 2. Android preflight 通过

命令：

```sh
make -C experiments/vpp-nfq-poc android-preflight
```

结果日志：

```text
results/android-preflight.log
```

设备信息：

```text
serial: 28201JEGR0XPAJ
model: Pixel 6a
abi: arm64-v8a
arch: aarch64
Android release: 16
Android API: 36
kernel: 6.1.134-android14-11-g66e758f7d0c0-ab13748739
root: uid=0(root), context=u:r:ksu:s0
SELinux: Enforcing
```

工具状态：

```text
/system/bin/iptables
/system/bin/ip6tables
/system/bin/toybox
/data/adb/ksu/bin/busybox
/system/bin/nsenter
/system/bin/setenforce
/system/bin/getenforce
iptables v1.8.11 (legacy)
ip6tables v1.8.11 (legacy)
```

`iptables -j NFQUEUE -h` 显示设备支持：

```text
--queue-num
--queue-balance
--queue-bypass
--queue-cpu-fanout
```

这和当前 Snort Android NFQUEUE 运行经验一致。

当前设备上已有 Snort NFQUEUE 规则：

```text
IPv4 INPUT:  sucre-snort_INPUT  -> NFQUEUE --queue-balance 0:1 --queue-bypass
IPv4 OUTPUT: sucre-snort_OUTPUT -> NFQUEUE --queue-balance 2:3 --queue-bypass
IPv6 INPUT:  sucre-snort_INPUT  -> NFQUEUE --queue-balance 4:5 --queue-bypass
IPv6 OUTPUT: sucre-snort_OUTPUT -> NFQUEUE --queue-balance 6:7 --queue-bypass
```

`/proc/net/netfilter/nfnetlink_queue` 当前显示 queue `0..7` 活跃。

相关进程：

```text
root 2916 ... sucre-snort-dev
```

结论：

```text
Android 真机 NFQUEUE、iptables legacy、su root、实验目录都可用。
当前 Snort 仍在运行并占用 queue 0..7。
后续 VPP 实验不能复用 0..7，除非先停止 Snort 并清理链。
```

处理策略：

```text
第一版 VPP Android verdict 测试默认使用 queue 42/43。
为了避免干扰现有 Snort 全局链，后续要么：
1. 先停止 sucre-snort-dev 并清理 sucre-snort_* 链；
2. 要么在 INPUT / OUTPUT 顶部插入更窄的 VPP 专用测试规则，命中测试流量后直接进入 queue 42/43。
```

设备侧实验目录已创建：

```text
/data/local/tmp/vpp-nfq-poc/
  bin/
  lib/
  plugins/
  runtime/
  logs/
```

下一步：进入 Android VPP build feasibility，先回答 VPP `v26.02` 能否被 NDK r29 构建成可启动的 arm64 Android 产物。

## 3. 停止旧 Snort 测试进程

用户确认当前 `sucre-snort-dev` 是之前测试进程，可以直接停止。

命令摘要：

```sh
source dev/dev-android-device-lib.sh
adb_su "pidof sucre-snort-dev ..."
adb_su "kill -TERM <pid>; sleep 1; kill -9 <pid-if-needed>"
adb_su "cat /proc/net/netfilter/nfnetlink_queue"
```

停止前：

```text
pid: 2916
root 2916 ... sucre-snort-dev
```

停止后：

```text
pidof sucre-snort-dev: empty
/proc/net/netfilter/nfnetlink_queue: empty
```

结论：

```text
旧 Snort 测试进程已停止。
queue 0..7 已释放。
iptables 中 sucre-snort_* 链可能仍存在，但因为规则带 --queue-bypass，当前无 queue owner 时不会卡住流量。
```

后续 VPP Android POC 仍优先使用 queue `42/43`，避免把实验队列和 Snort 主线队列约定混在一起。

## 4. Android VPP configure probe：失败于 Unsupported system

新增脚本：

```text
scripts/android-configure-vpp-probe.sh
make android-vpp-configure-probe
```

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-configure-probe
```

环境：

```text
VPP source: experiments/vpp-nfq-poc/work/vpp/src
NDK: /home/js/.local/share/android-sdk/ndk/29.0.14206865
Android ABI: arm64-v8a
compile API: android-31
device API: 36
```

第一次运行额外遇到：

```text
fatal: detected dubious ownership in repository ...
```

原因：`work/vpp` 是之前 Docker build 生成的 root-owned tree。处理方式是在 probe 脚本里通过环境变量临时注入：

```sh
GIT_CONFIG_COUNT=1
GIT_CONFIG_KEY_0=safe.directory
GIT_CONFIG_VALUE_0="$VPP_DIR"
```

没有写入用户全局 git config。

第二次运行的主失败点：

```text
CMake Error at cmake/misc.cmake:27 (_message):
  Unsupported system: Android
Call Stack (most recent call first):
  CMakeLists.txt:275 (message)
```

同时观察到：

```text
CMAKE_HAVE_LIBC_PTHREAD: Failed
compiler accepts -pthread: yes
HAVE_FCNTL64: Failed
```

结论：

```text
VPP upstream v26.02 顶层 CMake 没有 Android 分支。
NDK/CMake 能启动并识别 arm64 clang，但 VPP configure 阶段直接拒绝 CMAKE_SYSTEM_NAME=Android。
下一步需要最小 Android CMake overlay，先把 Android 作为 Linux-like 平台进入 minimal subdirs，再逐个处理 bionic/API 差异。
```

额外绕坑：

```text
不要对整个 work/vpp 递归 chmod。
build-root/external 中存在大量容器/挂载权限特殊文件，递归 chmod 会产生大量 Operation not permitted 噪音。
后续只读 src，或只处理必要目录。
```

## 5. Android CMake overlay 后 configure 通过

新增脚本：

```text
scripts/apply-vpp-android-overlay.sh
make apply-vpp-android-overlay
```

overlay 内容：

```text
1. 顶层 CMake cross compiling 分支增加 Android。
2. Android 下不覆盖 NDK toolchain 已设置的 compiler target。
3. 顶层 subdirs 条件从 Linux|FreeBSD 扩到 Linux|FreeBSD|Android。
4. nfqueue_poc plugin SUPPORTED_OS_LIST 从 Linux 扩到 Linux Android。
```

脚本 bug 与修复：

```text
第一次脚本使用 perl replacement 时没有转义 ${CMAKE_SYSTEM_NAME}，
导致 Perl 把它当变量插值为空，写坏 CMake 条件。

修复：按 section 重写 cross compiling block，并在 replacement 中写成 \${CMAKE_SYSTEM_NAME}。
```

重新运行：

```sh
make -C experiments/vpp-nfq-poc apply-vpp-android-overlay
make -C experiments/vpp-nfq-poc android-vpp-configure-probe
```

结果：

```text
cmake_rc=0
Build files have been written to:
experiments/vpp-nfq-poc/work/vpp-android-configure-probe
```

关键观察：

```text
C compiler: Android NDK clang 21.0.0
Target processor: aarch64
Library dir: lib/aarch64-linux-android
VPP version: 26.02-release
```

缺失依赖 / 自动禁用：

```text
OpenSSL not found
libunwind not found
libiberty not found
af_packet / tap / vhost: unsupported OS
libnetfilter_queue headers not found - nfqueue_poc plugin disabled
snort plugin disabled because libdaq headers not found
```

结论：

```text
最小 Android CMake overlay 可以让 VPP v26.02 完成 NDK configure。
这还不代表能编译或能启动。
nfqueue_poc 目前没有被构建，因为 Android NDK sysroot 里没有 libnetfilter_queue；后续需要把 third_party/netfilter 的 Android 产物接入 VPP CMake。
```

下一步：尝试 build core `vpp` target，记录第一个真实 bionic 编译/链接失败点。

## 6. Android vpp build probe：失败于 pthread_mutex_consistent

新增脚本：

```text
scripts/android-build-vpp-probe.sh
make android-vpp-build-probe
```

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-build-probe
```

目标：

```text
TARGET=vpp
JOBS=4
```

失败点：

```text
src/svm/message_queue.h:367:7:
error: call to undeclared function 'pthread_mutex_consistent'

src/svm/message_queue.h:386:7:
error: call to undeclared function 'pthread_mutex_consistent'
```

原因：

```text
Android bionic pthread.h 没有 pthread_mutex_consistent()。
VPP SVM message queue 的 robust mutex recovery 路径直接调用该函数。
```

当前判断：

```text
这是第一个真实 Android/bionic API 差异点。
为了继续推进 POC，可以先加 Android-only shim：pthread_mutex_consistent(...) 返回 0。
这不是最终正确设计，只是为了继续暴露后续编译/链接问题。
最终如果 VPP/SVM 真的依赖 robust mutex owner-death 语义，需要重新评估 Android 上的等价机制或避开该路径。
```

处理：

```text
apply-vpp-android-overlay.sh 增加 Android-only pthread_mutex_consistent shim。
```

## 7. Android vpp build probe：失败于 dlmallinfo incomplete type

重新应用 overlay 并构建：

```sh
make -C experiments/vpp-nfq-poc apply-vpp-android-overlay
make -C experiments/vpp-nfq-poc android-vpp-configure-probe
make -C experiments/vpp-nfq-poc android-vpp-build-probe
```

本次进展：

```text
pthread_mutex_consistent 错误已越过。
build 进入 vppinfra，执行到约 544/1492。
```

失败点：

```text
src/vppinfra/mem_dlmalloc.c:214:21:
error: variable has incomplete type 'struct dlmallinfo'

src/vppinfra/mem_dlmalloc.c:220:
error: calling 'mspace_mallinfo' with incomplete return type 'struct dlmallinfo'
```

同类错误还出现在：

```text
mem_dlmalloc.c:267
mem_dlmalloc.c:345
```

当前判断：

```text
这是第二个 Android/bionic API/配置差异点。
VPP 的 dlmalloc.h 声明了 mspace_mallinfo() 返回 struct dlmallinfo，但当前 Android configure 下 struct dlmallinfo 没有完整定义。
下一步需要检查 dlmalloc.h 的 mallinfo 宏条件，选择打开 dlmalloc 自带 mallinfo struct，或加 Android-only dlmallinfo shim。
```

处理：

```text
apply-vpp-android-overlay.sh 增加 Android-only:
  #undef STRUCT_MALLINFO_DECLARED

让 dlmalloc.h 使用自身的 struct dlmallinfo 定义。
```

## 8. Android vpp build probe：进入 vppinfra/svm 后的新失败点

重新应用 overlay 并构建后：

```text
dlmallinfo incomplete type 错误已越过。
build 进入 vppinfra / svm，执行到约 58/972。
```

当前失败点 1：

```text
src/vppinfra/mem_intercept.c:240:
error: conflicting types for 'malloc_usable_size'

bionic malloc.h:
size_t malloc_usable_size(const void* ptr);

VPP mem_intercept.c:
malloc_usable_size(void *p)
```

当前失败点 2：

```text
src/svm/message_queue.c:45:
error: call to undeclared function 'pthread_mutexattr_setrobust'
error: use of undeclared identifier 'PTHREAD_MUTEX_ROBUST'

src/svm/queue.c:42:
error: call to undeclared function 'pthread_mutexattr_setrobust'
error: use of undeclared identifier 'PTHREAD_MUTEX_ROBUST'

src/svm/queue.c:91 / 99:
error: call to undeclared function 'pthread_mutex_consistent'
```

结论：

```text
Android bionic 缺少 Linux/glibc robust mutex API:
  pthread_mutexattr_setrobust
  PTHREAD_MUTEX_ROBUST
  pthread_mutex_consistent

这不是单个 include 问题，而是 VPP SVM robust mutex 语义和 Android bionic 的差异。
POC 可继续用 Android-only no-op shim 推进编译，但最终设计必须评估 SVM 在 Android 单进程/多进程场景下是否需要 robust owner-death 语义。
```

## 9. Android overlay 扩展：连续越过 bionic / CMake 平台差异

后续多轮 `android-vpp-build-probe` 逐步暴露并处理以下问题。

### 9.1 robust mutex 与 malloc_usable_size

处理：

```text
1. 将 pthread_mutex_consistent / pthread_mutexattr_setrobust / PTHREAD_MUTEX_ROBUST
   的 Android-only no-op shim 收口到 svm/queue.h。
2. 移除早期临时插在 svm/message_queue.h 的单点 shim。
3. 将 vppinfra/mem_intercept.c 的 malloc_usable_size 参数适配为 Android bionic
   声明使用的 const void *。
```

风险记录：

```text
robust mutex no-op 只是为了推进 POC 编译。
如果后续 Android 形态需要跨进程 SVM owner-death recovery，必须重新设计。
```

### 9.2 vppinfra Linux 平台源与 Android shm_open 文件后端

失败点：

```text
libvppinfra.so 链接缺 clib_mem_vm_* / clib_sysfs_* / elf symbol formatter 等符号。
svm.c / ssvm.c 缺 shm_open / shm_unlink。
```

处理：

```text
1. Android 下将 vppinfra 平台源临时并入：
   elf_clib.c
   linux/mem.c
   linux/sysfs.c
   linux/netns.c
2. 在 svm/svm_common.h 增加 Android-only shm_open/shm_unlink 文件后端：
   /data/local/tmp/vpp-shm/<sanitized-name>
```

风险记录：

```text
shm_open 文件后端足够用于 root 真机 POC。
它不是正式 Android IPC/shared-memory 设计。
```

### 9.3 Android 链接库与线程亲和性

失败点：

```text
libsvm.so 链接失败：unable to find library -lrt / -lpthread。
vlib/threads.c 缺 pthread_setaffinity_np。
```

处理：

```text
1. Android 下 SVM CMake 不再传 rt / pthread，依赖 bionic libc。
2. vppinfra/unix.h 增加 Android-only pthread_setaffinity_np no-op shim。
```

风险记录：

```text
线程绑核当前被降级为 no-op。
这会影响性能实验，但不影响先验证能否启动和收发包。
```

### 9.4 BSD 兼容函数与 vlib 平台源

失败点：

```text
vlibmemory 使用 index()，Android NDK 没有暴露该 BSD 函数。
vnet/session 使用 bzero()。
libvlib.so 缺 vlib_pci_* / linux_vfio_init。
```

处理：

```text
1. Android 下将 index(s,c) 映射为 strchr(s,c)。
2. vppinfra/clib.h 增加 Android-only bzero(p,n) -> memset(p,0,n)。
3. Android 下将 vlib 平台源临时并入：
   linux/pci.c
   linux/vfio.c
   linux/vmbus.c
```

## 10. Android arm64 vpp target 编译成功

命令：

```sh
make -C experiments/vpp-nfq-poc apply-vpp-android-overlay
make -C experiments/vpp-nfq-poc android-vpp-build-probe
```

结果：

```text
[1003/1003] Linking C executable bin/vpp
build_rc=0
```

关键产物：

```text
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/bin/vpp
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/lib/aarch64-linux-android/libvppinfra.so
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/lib/aarch64-linux-android/libsvm.so
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/lib/aarch64-linux-android/libvlib.so
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/lib/aarch64-linux-android/libvlibapi.so
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/lib/aarch64-linux-android/libvlibmemory.so
experiments/vpp-nfq-poc/work/vpp-android-configure-probe/lib/aarch64-linux-android/libvnet.so
```

`file` 检查：

```text
bin/vpp:
ELF 64-bit LSB pie executable, ARM aarch64, interpreter /system/bin/linker64

libvnet.so:
ELF 64-bit LSB shared object, ARM aarch64
```

`vpp` 动态依赖：

```text
libvnet.so
libdl.so
libvlibmemory.so
libvlibapi.so
libvlib.so
libsvm.so
libvppinfra.so
libm.so
libc.so
```

仍未完成：

```text
nfqueue_poc plugin 仍被 configure 禁用：
  libnetfilter_queue headers not found - nfqueue_poc plugin disabled

下一步需要：
1. 先把当前 Android vpp core 产物 push 到真机，验证能否在 su/root 环境启动。
2. 再把 third_party/netfilter 的 Android libmnl/libnfnetlink/libnetfilter_queue
   接入 VPP CMake，使 nfqueue_poc 插件参与 Android 构建。
3. 最后再做 Android NFQUEUE INPUT/OUTPUT allow/drop 实机 verdict 测试。
```

## 11. Android 真机 vpp -v 验证通过

新增脚本：

```text
scripts/android-stage-vpp-core.sh
scripts/android-push-vpp-core.sh
scripts/android-run-vpp-version.sh
```

新增 Make target：

```text
make android-vpp-stage-core
make android-vpp-push-core
make android-vpp-version-probe
```

stage 结果：

```text
work/android-vpp-core-stage
  bin/vpp
  lib/libsvm.so
  lib/libvlib.so
  lib/libvlibapi.so
  lib/libvlibmemory.so
  lib/libvnet.so
  lib/libvppinfra.so

strip 后总大小约 186M。
```

第一次 push 失败：

```text
adb: remote couldn't create file: Permission denied
```

原因：

```text
远端目录由 su/root 创建，普通 adb push 使用 shell 用户写入，不能写 root-owned 755 目录。
```

处理：

```text
push 前临时 chmod 777:
  /data/local/tmp/vpp-nfq-poc
  /data/local/tmp/vpp-nfq-poc/bin
  /data/local/tmp/vpp-nfq-poc/lib

push 后恢复 chmod 755。
```

重新运行：

```sh
make -C experiments/vpp-nfq-poc android-vpp-version-probe
```

push 结果：

```text
bin/vpp: 214K
lib/libsvm.so: 199K
lib/libvlib.so: 8.3M
lib/libvlibapi.so: 140K
lib/libvlibmemory.so: 387K
lib/libvnet.so: 175M
lib/libvppinfra.so: 1.2M
```

真机执行：

```sh
LD_LIBRARY_PATH=/data/local/tmp/vpp-nfq-poc/lib \
  /data/local/tmp/vpp-nfq-poc/bin/vpp -v
```

结果：

```text
vpp v26.02-release built by js on Main at 2026-06-21T15:49:53
version_rc=0
```

结论：

```text
Android arm64 VPP core 产物可以在 Pixel 6a / Android 16 / API 36 / su root 环境动态链接并执行。
这一步只证明 binary 可运行，不证明 daemon startup、CLI socket、plugin load 或 NFQUEUE verdict。
```

## 12. Minimal daemon startup 初始失败：VLIB process 栈不足

新增脚本：

```text
scripts/android-run-vpp-minimal.sh
make android-vpp-minimal-probe
```

同时补充构建并推送：

```text
bin/vppctl
```

初始现象：

```text
vpp 进程启动后很快退出。
vppctl 连接 runtime/cli.sock 失败：
  connect: Connection refused
前台运行时进程返回：
  rc=139
```

设备侧日志只出现启动行：

```text
2026/06/22 00:xx:xx:xxx: ***** Start: PID <pid> *****
```

当时的默认构建参数：

```text
VLIB_PROCESS_LOG2_STACK_SIZE=15
VLIB process stack size = 32 KiB
```

临时插桩结论：

```text
1. VPP core init functions 已经走完。
2. main loop enter 前后的初始化也已走完。
3. 崩溃发生在 VLIB process startup / dispatch 阶段。
4. 最早稳定观察到的失败点靠近 ip4-full-reassembly-expire-walk。
5. 增加更重的 tracing 后，崩溃会提前到另一个 reassembly process。
```

判断：

```text
这不像动态链接、SVM 目录或 startup.conf 错误。
更像 Android/bionic + 当前 VPP 构建下，默认 32 KiB VLIB process 栈太小。
```

处理：

```text
Android overlay 在 vlib/CMakeLists.txt 中为 Android 设置：
  VLIB_PROCESS_LOG2_STACK_SIZE=18

android-configure-vpp-probe.sh 显式传入：
  -DVLIB_PROCESS_LOG2_STACK_SIZE=18

对应 VLIB process stack size：
  256 KiB
```

备注：

```text
调试用 tracing 已从 overlay 和 work/vpp source 中移除。
当前保留下来的不是调试插桩，而是 Android minimal daemon 必需的 process 栈配置。
```

## 13. Minimal daemon startup 通过

重新 clean configure：

```sh
make -C experiments/vpp-nfq-poc android-vpp-configure-probe
```

关键输出：

```text
vlib_process_log2_stack_size=18
CMakeCache.txt:
  VLIB_PROCESS_LOG2_STACK_SIZE:STRING=18
```

重新构建：

```sh
make -C experiments/vpp-nfq-poc android-vpp-build-probe
env TARGET=vppctl make -C experiments/vpp-nfq-poc android-vpp-build-probe
```

重新 stage / push 后运行 minimal probe：

```sh
env WAIT_SECS=3 make -C experiments/vpp-nfq-poc android-vpp-minimal-probe
```

结果：

```text
## process
15106
root         15106     1   29024268 320512 __arm64_sys_nanosleep 0 S vpp

## vpp stdout
[empty]

## vpp log
2026/06/22 00:54:16:011: ***** Start: PID 15106 *****

## vppctl show version
vpp v26.02-release built by js on Main at 2026-06-21T16:45:48
vppctl_rc=0
```

结论：

```text
Pixel 6a / Android 16 / API 36 / su root 环境下，Android arm64 VPP core
可以用 minimal startup.conf 作为 daemon 启动，并通过 CLI socket 执行 show version。

当前必要条件：
  VLIB_PROCESS_LOG2_STACK_SIZE=18
```

停止后复查：

```text
vpp/snort/sakamoto 相关进程为空。
```

## 14. 当前缺口：Android nfqueue_poc plugin 尚未构建

当前 Android configure 仍会输出：

```text
libnetfilter_queue headers not found - nfqueue_poc plugin disabled
```

含义：

```text
Phase C 已证明 VPP core 能在 Android 真机启动。
Phase D 还不能开始，因为 Android 产物里没有 nfqueue_poc_plugin.so。
```

下一步：

```text
1. 为 Android 交叉构建或 vendoring libmnl / libnfnetlink / libnetfilter_queue。
2. 把这些 headers/libs 接入 VPP Android CMake 配置。
3. 构建并推送 nfqueue_poc_plugin.so。
4. 在 Android 真机上验证 queue 42/43 的 INPUT / OUTPUT accept/drop verdict。
5. 再采样启用 NFQUEUE 后的 idle CPU，确认没有单核 100% 忙轮询。
```

## 15. Android nfqueue_poc plugin 构建通过

处理方式：

```text
不新增上游源码。
复用 repo 内已有 vendored netfilter userspace 源：
  third_party/netfilter/libmnl
  third_party/netfilter/libnfnetlink
  third_party/netfilter/libnetfilter_queue
```

VPP plugin CMake Android 分支新增：

```text
nfqueue_poc_mnl              static lib
nfqueue_poc_nfnetlink        static lib
nfqueue_poc_netfilter_queue  static lib
nfqueue_poc_plugin.so        VPP plugin
```

第一个构建失败：

```text
libnetfilter_queue/src/libnetfilter_queue.c 误包含了
third_party/netfilter/cmake_config/libnetfilter_queue/libnetfilter_queue/libnetfilter_queue.h。

这个 wrapper 只适合主线 daemon 的低层 nlmsg API，不适合 nfq_open /
nfq_create_queue / nfq_set_verdict 这套高层 API。
```

修正：

```text
Android VPP plugin 构建只使用 upstream libnetfilter_queue/include。
config.h 单独在 CMake binary dir 生成，避免 cmake_config 目录遮蔽真实头文件。
```

第二个构建失败：

```text
NDK sysroot 的 linux/netfilter/nfnetlink.h 和 vendored
libnfnetlink/linux_nfnetlink.h 同时进入同一编译单元，导致 enum / struct
重复定义。
```

修正：

```text
在 CMake binary dir 生成：
  netfilter_config/libnfnetlink/linux_nfnetlink.h

内容转向：
  #include <linux/netfilter/nfnetlink.h>

这样 libnfnetlink/libnetfilter_queue 在 Android 下统一使用 NDK sysroot
的 nfnetlink kernel header。
```

第三个构建失败：

```text
Android 链接 shared library 使用 --no-undefined。
nfqueue_poc_plugin.so 引用的 VPP core 符号不能像 Linux POC 那样留到
运行时解析。
```

修正：

```text
nfqueue_poc_plugin 显式链接：
  vlib
  vppinfra
```

构建命令：

```sh
make -C experiments/vpp-nfq-poc android-vpp-configure-probe
make -C experiments/vpp-nfq-poc android-vpp-build-nfqueue-plugin
make -C experiments/vpp-nfq-poc android-vpp-build-probe
env TARGET=vppctl make -C experiments/vpp-nfq-poc android-vpp-build-probe
```

结果：

```text
lib/aarch64-linux-android/vpp_plugins/nfqueue_poc_plugin.so
ELF 64-bit LSB shared object, ARM aarch64
```

stage / push 后设备侧新增：

```text
/data/local/tmp/vpp-nfq-poc/plugins/nfqueue_poc_plugin.so  72K
```

## 16. 插件加载：plugin_path 必须作为启动参数传入

第一次启用插件后 minimal startup 失败：

```text
vpp 前台运行返回 rc=139。
stdout / vpp.log 为空。
```

tombstone：

```text
Fatal signal 11 (SIGSEGV)
#00 libc.so __strlen_aarch64
#02 libvppinfra.so
#05 libvlib.so
#07 /data/local/tmp/vpp-nfq-poc/bin/vpp
```

addr2line：

```text
libvppinfra.so:
  va_format at vppinfra/format.c:376
  format at vppinfra/format.c:400

libvlib.so:
  vlib_plugin_early_init at vlib/unix/plugin.c:1045
  vlib_unix_main at vlib/unix/main.c:724

bin/vpp:
  main at vpp/vnet/main.c:413
```

原因：

```text
VPP 的 early plugin init 会先读取全局 vlib_plugin_path。
startup.conf 里的 plugins { path ... } 要到后续配置解析阶段才生效，
对 early init 来说太晚。
```

修正：

```text
android-run-vpp-minimal.sh 默认启动参数增加：
  plugin_path /data/local/tmp/vpp-nfq-poc/plugins

startup.conf 仍保留：
  plugins {
    path /data/local/tmp/vpp-nfq-poc/plugins
    plugin default { disable }
    plugin nfqueue_poc_plugin.so { enable }
  }
```

验证：

```sh
make -C experiments/vpp-nfq-poc android-vpp-minimal-probe
```

结果：

```text
## vppctl show version
vpp v26.02-release built by js on Main at 2026-06-21T17:08:08
vppctl_rc=0
```

插件列表：

```text
Plugin path is: /data/local/tmp/vpp-nfq-poc/plugins

Plugin                                   Version        Description
nfqueue_poc_plugin.so                    26.02-release  NFQUEUE verdict POC
```

插件状态：

```text
show nfqueue-poc
enabled 0 queue 0 mode accept-all drop-ratio 0 fd -1
seen 0 accept 0 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

## 17. Android IPv4 OUTPUT NFQUEUE verdict 通过

启动 VPP 后启用 queue 42：

```sh
vppctl nfqueue-poc enable queue 42 mode accept-all
```

状态：

```text
enabled 1 queue 42 mode accept-all drop-ratio 50 fd 12
seen 0 accept 0 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

临时 OUTPUT 规则：

```sh
iptables -w -I OUTPUT 1 -p icmp -d 1.1.1.1 \
  -j NFQUEUE --queue-num 42 --queue-bypass
```

accept-all 结果：

```text
ping 1.1.1.1 -c 4:
  4 packets transmitted, 4 received, 0% packet loss

show nfqueue-poc:
  seen 8 accept 8 drop 0 missing-id 0
```

切换 drop-all：

```sh
vppctl nfqueue-poc disable
vppctl nfqueue-poc enable queue 42 mode drop-all
```

drop-all 结果：

```text
ping 1.1.1.1 -c 4:
  4 packets transmitted, 0 received, 100% packet loss

show nfqueue-poc:
  seen 4 accept 0 drop 4 missing-id 0
```

清理确认：

```text
iptables -S OUTPUT:
  临时 1.1.1.1 NFQUEUE rule 已删除。
```

结论：

```text
Android 真机 OUTPUT IPv4 ICMP 可以进入 VPP nfqueue_poc_plugin.so。
VPP 返回 NF_ACCEPT 时流量通过；返回 NF_DROP 时流量被阻断。
```

## 18. Android IPv4 INPUT NFQUEUE verdict 通过

临时 INPUT 规则：

```sh
iptables -w -I INPUT 1 -p icmp -s 1.1.1.1 \
  -j NFQUEUE --queue-num 42 --queue-bypass
```

accept-all 结果：

```text
ping 1.1.1.1 -c 4:
  4 packets transmitted, 4 received, 0% packet loss

show nfqueue-poc:
  seen 8 accept 8 drop 0 missing-id 0
```

drop-all 结果：

```text
ping 1.1.1.1 -c 4:
  4 packets transmitted, 0 received, 100% packet loss

show nfqueue-poc:
  seen 4 accept 0 drop 4 missing-id 0
```

清理确认：

```text
iptables -S INPUT:
  临时 1.1.1.1 NFQUEUE rule 已删除。

iptables -S OUTPUT:
  临时 1.1.1.1 NFQUEUE rule 已删除。
```

结论：

```text
Android 真机 INPUT IPv4 ICMP reply 可以进入 VPP nfqueue_poc_plugin.so。
VPP 返回 NF_ACCEPT 时回包通过；返回 NF_DROP 时 ping 观察到 100% 丢包。
```

## 19. 本轮清理状态

实验结束后停止 VPP：

```text
pidof vpp: empty
/proc/net/netfilter/nfnetlink_queue: empty
```

仍保留的设备侧产物：

```text
/data/local/tmp/vpp-nfq-poc/
  bin/
  lib/
  plugins/
  runtime/startup.conf
  logs/
```

下一步：

```text
Phase E: 带 nfqueue_poc enable 的 idle CPU 采样。
后续可再补 drop-ratio=50 和 IPv6；当前 Phase D 的 IPv4 INPUT/OUTPUT
accept/drop verdict 已经闭环。
```

## 20. Android nfqueue_poc idle CPU 短采样通过

重新启动 VPP 并启用 queue 42：

```sh
make -C experiments/vpp-nfq-poc android-vpp-minimal-probe \
  SKIP_PUSH=1 STOP_AFTER=0 WAIT_SECS=3

vppctl nfqueue-poc enable queue 42 mode accept-all
```

初始状态：

```text
enabled 1 queue 42 mode accept-all drop-ratio 50 fd 12
seen 0 accept 0 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

无测试规则、无流量时采样：

```text
pid=15758
PID   NAME  STAT  %CPU  RSS
15758 vpp   S      7.5  320556
15758 vpp   S      7.5  320556
15758 vpp   S      7.5  320556
15758 vpp   S      7.4  320556
15758 vpp   S      7.4  320556
15758 vpp   S      7.4  320556
```

随后插入临时 OUTPUT ICMP 规则，ping `1.1.1.1` 四次后删除规则。

VPP 计数：

```text
enabled 1 queue 42 mode accept-all drop-ratio 50 fd 12
seen 8 accept 8 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

短流量后停流采样：

```text
PID   NAME  STAT  %CPU  RSS
15758 vpp   S      7.1  320556
15758 vpp   S      7.0  320556
15758 vpp   S      7.0  320556
15758 vpp   S      7.0  320556
15758 vpp   S      7.0  320556
15758 vpp   S      7.0  320556
```

清理确认：

```text
iptables -S OUTPUT:
  临时 1.1.1.1 NFQUEUE rule 已删除。

pidof vpp: empty
/proc/net/netfilter/nfnetlink_queue: empty
```

结论：

```text
Android 真机上，nfqueue_poc enable 后的短 idle 采样没有出现单核 100%
忙轮询。当前观测约 7% CPU。

这是短采样，只回答“是否立即表现为单核 100%”。
它不替代后续长期压测、不同 governor、锁屏/息屏、不同设备和真实业务流量
下的性能评估。
```

## 21. 对照采样：只加载插件但不 enable NFQUEUE

目的：

```text
确认 7% 左右 CPU 是否来自 nfqueue_poc enable 后的 NFQUEUE 收包路径，
还是当前 VPP minimal runtime 自身基线。
```

启动：

```sh
env SKIP_PUSH=1 STOP_AFTER=0 WAIT_SECS=3 \
  make -C experiments/vpp-nfq-poc android-vpp-minimal-probe
```

状态：

```text
VPP 启动成功。
nfqueue_poc_plugin.so 已加载。
未执行 nfqueue-poc enable。
```

采样：

```text
pid=18365
PID   NAME  STAT  %CPU  RSS
18365 vpp   S      8.6  321080
18365 vpp   S      8.5  321080
18365 vpp   S      8.4  321080
18365 vpp   S      8.3  321080
18365 vpp   S      8.1  321080
18365 vpp   S      7.9  321080
18365 vpp   S      7.5  321080
18365 vpp   S      7.5  321080
18365 vpp   S      7.5  321080
18365 vpp   S      7.6  321080
```

清理：

```text
pidof vpp: empty
/proc/net/netfilter/nfnetlink_queue: empty
```

结论：

```text
只启动 VPP 并加载插件、不 enable NFQUEUE 时，CPU 也稳定到约 7.5%。
因此前一节 nfqueue_poc enable 后约 7.0% - 7.5% 的短 idle 观测，
更像当前 Android VPP minimal runtime 基线，而不是 NFQUEUE fd 忙轮询。
```
