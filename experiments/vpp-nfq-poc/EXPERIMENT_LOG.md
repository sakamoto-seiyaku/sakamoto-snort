# VPP NFQUEUE POC 实验原始记录

状态：按时间顺序追加的实验流水。这里记录真实执行路径、问题和当前进度，避免后续重复踩坑。

## 2026-06-21

### 01. 创建实验分支和任务文档

分支：

```text
research/vpp-nfq-poc
```

起点提交：

```text
792ab80 docs: capture runtime and VPP datapath research
```

新增任务文档：

```text
docs/reviews/VPP_NFQUEUE_POC_EXPERIMENT_TASKS.md
```

提交：

```text
c434b47 docs: define VPP NFQUEUE POC tasks
```

结论：第一阶段只验证 Linux/Docker NFQUEUE verdict 和 idle CPU，不直接进入 Android/VPN/HEV/UID。

### 02. 创建纯 C NFQUEUE smoke harness

新增目录：

```text
experiments/vpp-nfq-poc/
```

主要入口：

```text
make docker-shell
make build-smoke
make smoke-accept
make smoke-drop
make smoke-ratio
make idle-cpu
```

提交：

```text
05f67d5 experiments: add NFQUEUE smoke POC harness
```

### 03. 宿主机直接编译 smoke 失败

命令：

```sh
make -C experiments/vpp-nfq-poc build-smoke
```

结果：

```text
libnetfilter_queue development package not found. Run: make docker-shell
```

处理：不污染宿主机安装依赖，改走 Docker lane。

### 04. Docker smoke 权限问题

最初只给：

```text
--cap-add NET_ADMIN
--cap-add NET_RAW
```

执行：

```sh
make smoke-accept
```

失败：

```text
mount --make-shared /run/netns failed: Operation not permitted
```

原因：Docker 内 `ip netns add` 需要 mount namespace 相关能力。

处理：smoke 容器加入：

```text
--cap-drop ALL
--cap-add NET_ADMIN
--cap-add NET_RAW
--cap-add SYS_ADMIN
--security-opt apparmor=unconfined
--security-opt seccomp=unconfined
--tmpfs /run
```

### 05. 纯 C NFQUEUE verdict smoke 通过

命令：

```sh
make smoke-accept
make smoke-drop
make smoke-ratio
make idle-cpu
```

结果：

```text
accept-all:     ping 20/20, seen=20 accept=20 drop=0
drop-all:       ping 0/20,  seen=20 accept=0  drop=20
drop-ratio=50:  ping 10/20, seen=20 accept=10 drop=10
idle-cpu:       nfq-smoke sampled at 0.0% CPU before and after traffic
```

踩坑：最初 `drop-ratio=50` 算法按 100 包窗口前半段 drop，20 个 ping 全落在 drop 区间，表现成 100% loss。已改为小样本也均匀交错的 deterministic ratio。

当前 metadata 观察：

```text
packet_id: present
hook: present, OUTPUT = 3
payload_len: present
outdev: present, 数字随容器网络模式变化
uid/gid: present, 当前为 root -> 0
timestamp: current config 下未出现
```

结论：Linux/Docker NFQUEUE harness 可用，足够进入 VPP adapter POC。

### 06. 引入 VPP fetch/build 脚本

新增脚本：

```text
scripts/fetch-vpp.sh
scripts/build-vpp.sh
```

默认 VPP 目录：

```text
experiments/vpp-nfq-poc/work/vpp
```

`work/` 已加入 `.gitignore`，VPP 源码和 build output 不进仓库。

### 07. VPP clone 第一次失败：work 目录权限

命令：

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh make fetch-vpp
```

失败：

```text
fatal: could not create work tree dir '.../experiments/vpp-nfq-poc/work/vpp': Permission denied
```

原因：host 创建的 bind mount 目录对容器 root 不可写。

处理：`run-container.sh` 创建 `VPP_WORK_ROOT` 后执行：

```sh
chmod 0777 "$VPP_WORK_ROOT"
```

### 08. VPP v26.02 clone 成功

命令：

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh make fetch-vpp
```

结果：

```text
VPP_DIR=.../experiments/vpp-nfq-poc/work/vpp
9258530
HEAD is now at 9258530 misc: VPP 26.02 Release Notes
```

宿主侧注意事项：因为 clone 是容器 root 做的，宿主直接跑 `git -C work/vpp status` 会触发 Git dubious ownership 保护。这不影响容器内 build。需要宿主侧 git 操作时使用 safe.directory 或修正 ownership。

### 09. VPP install-dep 第一次失败：cap-drop 下 sudo 不可用

命令：

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

失败：

```text
sudo: PERM_SUDOERS: setresuid(-1, 1, -1): Operation not permitted
sudo: no valid sudoers sources found, quitting
```

原因：smoke lane 默认 `--cap-drop ALL`，VPP upstream `make install-dep` 硬编码 `sudo -E apt-get`。

处理：增加 `DOCKER_CAP_PROFILE=default`。smoke lane 继续用收紧 caps；VPP build lane 使用 Docker 默认 capabilities。

### 10. VPP install-dep 第二次失败：apt 交互确认

命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

失败：

```text
Do you want to continue? [Y/n] Abort.
```

原因：VPP Makefile 的 `install-dep` 需要 `UNATTENDED=y` 才会传 `-y`。

处理：`build-vpp.sh` 对 install-dep 使用：

```sh
DEBIAN_FRONTEND=noninteractive make -C "$VPP_DIR" UNATTENDED=y install-dep
```

### 11. 当前进行中：VPP install-dep / build-release

当前命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

状态：

```text
VPP install-dep 已开始安装依赖。
计划安装 229 个包，下载约 251 MB，解包约 1335 MB。
```

等待结果：依赖安装完成后脚本会继续执行 upstream `make build-release -j 4`。

### 12. VPP install-dep 已通过，build-release 进入 external deps

状态更新：

```text
install-dep 已完成。
build-release 已进入 build-root/build-vpp-native/external 阶段。
```

观察到的非致命输出：

```text
fatal: ambiguous argument 'v26.02-rc0..': unknown revision or path not in the working tree.
```

推测原因：当前 VPP 是 `git clone --depth 1 --branch v26.02`，浅 clone 里没有 `v26.02-rc0` tag/history。VPP external build 里的版本/变更检测命令引用了 `v26.02-rc0..`。目前该输出没有立即终止 build，但后续如果造成失败，需要改 `fetch-vpp.sh` 从 shallow clone 改为 fetch 足够 tags/history。

当前 external deps 进度：

```text
DAQ 3.0.21 下载、checksum、extract、patch、configure 已通过。
正在下载/构建 intel-ipsec-mb v2.0。
```

### 13. external deps 继续推进

状态更新：

```text
DPDK 25.11 下载、checksum、extract、patch 已通过。
RDMA core 60.0 configure/build/install 已通过。
ipsec-mb 2.0 正在 build。
```

观察到 warning：

```text
Minimum required NASM version for SM3/SM4/SHA512-NI: 2.16.02
SM3/SM4/SHA512-NI code not compiled - update NASM.
```

当前容器 Debian bookworm 提供 NASM `2.16.01`。目前这只是禁用部分 crypto optimized code，build 仍继续；若后续 POC 不需要这类路径，可先接受。

### 14. external deps 进入 DPDK configure

状态更新：

```text
ipsec-mb 2.0 install 已通过。
DPDK 25.11 进入 meson configure。
```

观察到 warning：

```text
WARNING: Location '/root/Downloads' is ignored
```

这是 VPP external build 下载 Python wheel 时检查本地 fallback 目录，目录不存在；随后已从网络下载 `meson==0.57.2`、`pyelftools==0.33`、`wheel`、`setuptools` 等，当前不构成失败。

### 15. DPDK external build 继续推进中

状态更新：

```text
DPDK 25.11 meson configure 已通过，进入 ninja build。
当前观察到的最高进度约为 [1496/2170]。
```

当前没有新的 fatal error。前面出现的 `v26.02-rc0..` shallow clone 输出、NASM 版本 warning、`/root/Downloads` warning 仍按非阻塞问题处理，等待 build 的最终结果确认。

### 16. DPDK external build/install 已通过，进入 xdp-tools

状态更新：

```text
DPDK 25.11 ninja build 已跑完 [2170/2170]，headers/libs/pkgconfig/bin tools 已 install 到 build-root/install-vpp-native/external。
quicly 0.1.5-vpp install 已通过。
xdp-tools 1.5.5 下载、checksum、extract、patch、configure 已通过，正在 build。
```

观察到的非致命输出：

```text
Warning: Got more output options than URLs
```

该 warning 出现在下载 xdp-tools 后，但 checksum 通过，后续 patch/config/build 已继续推进；当前不视为阻塞。

### 17. external deps 完成，VPP 本体 configure/build 开始

状态更新：

```text
xdp-tools 1.5.5 install 已通过。
libcbor 0.13.0 install 已通过。
VPP configure 成功，进入 VPP 本体 ninja build。
当前观察到的 VPP 本体 build 进度约为 [776/3040]。
```

configure 关键信息：

```text
VPP version: 26.02-release
Build type: release
C compiler: Clang 14.0.6
Host/Target processor: x86_64
Plugins: snort 插件存在；未看到 upstream nfqueue 插件。
```

实验含义：当前原版 VPP 能在容器内完成配置并进入本体编译；NFQUEUE 接入大概率仍需要我们按 POC 目标新增/魔改 VPP 插件或 input node。

### 18. VPP core binaries 已开始产出，进入插件编译阶段

状态更新：

```text
VPP 本体 build 已越过基础库和一批 core tool。
已观察到 vppctl、vpp_get_stats、vpp_get_metrics、vat2、vpp_api_test 等目标完成链接。
当前进入 vpp_plugins 编译阶段，进度约为 [1741/3040]。
```

当前正在编译的相关插件包括：

```text
af_packet_plugin
af_xdp_plugin
```

实验含义：原版 VPP 的 Linux 包输入相关插件可以正常参与 build。后续 NFQUEUE POC 可以参考这些插件的 input/device/CLI 组织方式，但 NFQUEUE verdict 语义仍需要单独验证。

### 19. `bin/vpp` 已链接成功，插件编译继续

状态更新：

```text
VPP 主可执行文件 bin/vpp 已在 [1869/3040] 链接成功。
libvnet.so 已完成。
dpdk_plugin.so、af_packet_plugin.so、af_xdp_plugin.so 等已完成链接。
当前插件编译继续推进，进度约为 [2033/3040]。
```

实验含义：即使后续某个非关键插件失败，当前已经可以进一步确认最小 VPP binary 的启动/参数/idle 行为。不过本轮仍等待 upstream `make build-release` 完整结束后再做结论。

### 20. 构建进入 `snort_plugin`

状态更新：

```text
插件编译继续推进，已越过 sflow、sfdp_services 等插件。
当前进入 snort_plugin 编译，观察到 cli.c、format.c、interface.c、socket.c、snort_api.c、main.c 正在构建。
当前进度约为 [2720/3040]。
```

实验含义：VPP 26.02 的 `snort_plugin` 可以在本容器配置下参与 build，前面的 `libdaq.a` 依赖也已被 configure 找到。这个事实只说明 VPP 内置 Snort/DAQ 插件路径能编译，不代表 NFQUEUE 收包/verdict adapter 已存在。

### 21. VPP build-release 完整成功

最终结果：

```text
[3040/3040] Linking C shared library lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
@@@@ Installing vpp @@@@
...
Successfully installed vpp_papi-2.3.2
VPP build completed
```

命令退出码：

```text
0
```

观察到的非阻塞 warning：

```text
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager.
```

这是 install 阶段构建/安装 `vpp_papi` wheel 时的 pip root warning。当前 Docker build lane 是一次性实验容器，暂不作为阻塞问题处理。

阶段结论：在 Docker/amd64/Linux 下，VPP v26.02 原版源码可以完成 `make build-release`，并成功构建 `snort_plugin.so`、`af_packet_plugin.so`、`af_xdp_plugin.so`、`tap_plugin.so`、`dpdk_plugin.so` 等关键插件。下一步需要确认产物路径、最小启动参数和 idle CPU 行为，然后再进入 NFQUEUE adapter POC。

### 22. 确认 VPP 产物路径和版本命令

踩坑：

```text
rtk find ... 不是 GNU find，会走 rtk 自己的 find 子命令。
后续要查本地文件树时使用 rtk /usr/bin/find ...
```

确认到的 VPP binary：

```text
experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/bin/vpp
experiments/vpp-nfq-poc/work/vpp/build-root/build-vpp-native/vpp/bin/vpp
```

确认到的 `snort_plugin.so`：

```text
experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
experiments/vpp-nfq-poc/work/vpp/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
```

版本命令：

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/bin/vpp -v
```

输出：

```text
vpp v26.02-release built by root on f2a0f575d39a at 2026-06-21T14:45:41
```

结论：host 侧直接执行 `vpp -v` 可以返回版本。下一步可以基于 install tree 尝试最小 `unix { nodaemon }` 启动和 idle CPU 采样。

### 23. 同步 README / NOTES 的当前状态

更新内容：

```text
README.md: 增加 VPP Build Result，记录 v26.02 build 成功、产物路径、版本输出。
NOTES.md: 将 Next Checkpoint 从“先 clone/build VPP”改为“最小启动、idle CPU、nfqueue_poc 插件”。
```

构建命令示例统一为：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

### 24. 最小 VPP 启动第一次试跑

新增文件：

```text
experiments/vpp-nfq-poc/configs/minimal-startup.conf
experiments/vpp-nfq-poc/scripts/run-vpp-minimal.sh
```

启动命令：

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/scripts/run-vpp-minimal.sh
```

结果：

```text
exit code 124
```

解释：`timeout` 到 5 秒后发送 SIGTERM，VPP 收到 SIGTERM 后退出；这说明最小配置下 VPP 可以常驻运行，不是立即启动失败。

观察到的非阻塞输出：

```text
pre-allocating 19 additional 2048K hugepages on numa node 0
falling back to non-hugepage backed buffer pool
vat_plugin_register: ... plugin not loaded
received SIGTERM ... exiting
```

当前判断：

```text
hugepage fallback 不阻塞最小启动，但后续可以尝试用 buffers page-size default 收掉噪声。
vat plugin 提示来自 plugin default disable 后 vat/vat2 侧仍扫描注册，不阻塞最小启动。
```

### 25. 最小启动配置收掉 hugepage fallback

配置调整：

```text
minimal-startup.conf 增加 buffers { page-size default }
```

再次执行：

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/scripts/run-vpp-minimal.sh
```

结果：

```text
exit code 124
```

观察：

```text
hugepage prealloc/fallback 输出消失。
仍有 vat_plugin_register: ... plugin not loaded 提示。
VPP 收到 timeout SIGTERM 后正常退出。
```

当前判断：最小 VPP 启动已经可重复；后续 idle CPU 采样可以用这个 config 作为基线。

### 26. 最小 VPP idle CPU 采样

新增脚本和 target：

```text
scripts/run-vpp-idle-cpu.sh
make vpp-idle-cpu
```

第一次采样方法：

```text
ps -L -p <pid> -o pid,tid,psr,pcpu,comm
```

结果约为：

```text
23.5%, 16.0%, 12.9%, 10.6%, 9.5%
```

问题：`ps %CPU` 是进程生命周期平均值，会被 VPP 启动阶段拉高，不能代表 idle 稳态。

脚本调整：改用 `/proc/<pid>/task/<tid>/stat` 的 `utime+stime` tick delta 计算瞬时 CPU，并增加 `WARMUP=3`。

在没有 `poll-sleep-usec` 时，瞬时 idle 约为：

```text
2.956%, 2.978%, 3.973%, 2.978%, 2.979%
```

配置调整：

```text
unix { poll-sleep-usec 1000 }
```

再次采样结果：

```text
0.992%, 0.992%, 1.985%, 0.993%, 0.993%
```

当前判断：最小 VPP 在没有收发流量时不是单核 100% busy loop；通过 `poll-sleep-usec 1000` 可以把当前宿主上的 idle CPU 降到约 1% 单线程。后续 NFQUEUE adapter 仍要验证启用 fd/input node 后 idle 是否保持这个量级。

### 27. 同步最小启动和 idle CPU 文档

更新内容：

```text
README.md: 增加 make vpp-idle-cpu 入口和最小 VPP idle 结果。
NOTES.md: 将 Next steps 更新为 nfqueue_poc 插件、VPP verdict smoke、NFQUEUE fd/input idle 复测。
```

当前明确结论：

```text
VPP v26.02 build 成功。
最小 VPP 可以启动。
最小 VPP 在 poll-sleep-usec 1000 下 idle 约 1% CPU，不是单核 100% busy loop。
尚未验证 VPP NFQUEUE adapter 的收包/verdict/idle。
```

### 28. 开始 `nfqueue_poc` overlay，宿主写入 VPP tree 权限失败

新增 overlay：

```text
experiments/vpp-nfq-poc/overlay/src/plugins/nfqueue_poc/
experiments/vpp-nfq-poc/scripts/apply-vpp-overlay.sh
make apply-vpp-overlay
```

首次在宿主执行：

```sh
make -C experiments/vpp-nfq-poc apply-vpp-overlay
```

失败：

```text
cp: cannot create directory '.../work/vpp/src/./plugins/nfqueue_poc': Permission denied
cp: preserving times for '.../work/vpp/src/./plugins': Operation not permitted
```

原因：`work/vpp` 是之前 Docker 容器 root clone/build 出来的，宿主用户没有写权限。

处理策略：不修改整个 VPP tree owner；后续用同一个 Docker lane 里的 root 执行 overlay apply/build：

```sh
DOCKER_CAP_PROFILE=default ./scripts/run-container.sh make apply-vpp-overlay
```

### 29. 容器 apply overlay 第二次失败：`cp -a` preserve ownership

容器内执行：

```sh
./scripts/run-container.sh make apply-vpp-overlay
```

失败：

```text
cp: failed to preserve ownership for '.../nfqueue_poc/*.c': Operation not permitted
```

原因：`cp -a` 会保留 owner/timestamp，当前 bind mount 不允许容器对这些目标执行 chown/utime。

处理：`apply-vpp-overlay.sh` 改为：

```sh
cp -R --no-preserve=ownership,timestamps "$OVERLAY_DIR/src/." "$VPP_DIR/src/"
```

### 30. overlay apply 成功

命令：

```sh
./scripts/run-container.sh make apply-vpp-overlay
```

结果：

```text
Applied overlay to .../experiments/vpp-nfq-poc/work/vpp
```

下一步：运行 VPP 增量 build，验证 `nfqueue_poc` CMake 和 C 代码是否能编译。

### 31. overlay 后第一次增量 build 失败：容器没有持久化 VPP build deps

命令：

```sh
./scripts/run-container.sh env JOBS=4 make build-vpp
```

失败：

```text
/usr/bin/bash: line 1: cmake: command not found
make[2]: *** [Makefile:644: vpp-configure] Error 127
```

原因：前一次 `VPP_INSTALL_DEPS=1` 是在一次性 Docker container 内安装 apt 包，容器退出后依赖没有固化到 `sakamoto-vpp-nfq-poc:dev` image。VPP build output 留在 bind mount，但重新 configure/build 仍需要 cmake/ninja/clang 等工具。

处理策略：本轮先重跑带网络的 build lane：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

后续可选优化：把 VPP build deps 烘进专用 Docker image，避免每次增量 build 都重新 apt install。

### 32. 子代理源码调查结论：原版无 NFQUEUE 插件，POC 先 CLI-only

Pauli 调查结论：

```text
原版 VPP tree 里没有现成 libnetfilter_queue / nfq_* 插件。
add_vpp_plugin() 支持 LINK_LIBRARIES。
最小 CLI-only 插件不需要 .api、API_FILES、node、multiarch。
```

建议参考路径：

```text
src/plugins/snort/      外部队列/fd/回注关系最接近
src/plugins/netmap/     简单 fd -> input node 参考
src/plugins/af_packet/  新式 interface/rx queue/fd-ready 参考
src/plugins/af_xdp/     新式 interface/rx queue/fd-ready 参考
src/plugins/tap/        fd-ready/rx queue 参考
src/plugins/memif/      fd-ready/connection lifecycle 参考
```

当前本轮 POC 选择：

```text
第一刀只做 CLI-only nfqueue_poc。
VPP clib_file read callback 直接 drain NFQUEUE fd，并在 libnetfilter_queue callback 中直接 NF_ACCEPT/NF_DROP。
暂不创建 VPP interface，不分配 vlib_buffer，不接 graph node。
```

原因：这个切片最小化变量，先验证 VPP 进程是否能持有 NFQUEUE fd 并给出 verdict。若通过，再进入 fd-ready -> input node -> buffer/graph 的第二刀。

### 33. 重跑 build 命令位置错误：Docker env 传进了容器内

错误命令：

```sh
./scripts/run-container.sh env DOCKER_NETWORK=bridge VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

失败：

```text
sudo: PERM_SUDOERS: setresuid(-1, 1, -1): Operation not permitted
```

原因：`DOCKER_NETWORK=bridge` 和 `DOCKER_CAP_PROFILE=default` 必须作为 `run-container.sh` 的宿主环境变量传入；放在 `env ... make build-vpp` 后面只会进入容器内部，不会影响 Docker run 参数。于是容器仍用了默认 `DOCKER_CAP_PROFILE=smoke`，cap-drop 下 sudo 失败。

正确命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

### 34. 正确 build lane 已启动

命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

当前状态：

```text
install-dep 重新开始。
计划安装 229 个包，下载约 251 MB，解包约 1335 MB。
```

等待结果：依赖安装后会重新 configure/build VPP，并验证 `nfqueue_poc` overlay 是否被 CMake 发现和编译。

### 35. overlay 插件随 VPP build 成功安装

命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

结果：

```text
VPP build completed
```

安装产物确认：

```text
work/vpp/build-root/install-vpp-native/vpp/include/vpp_plugins/nfqueue_poc/nfqueue_poc.h
work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/nfqueue_poc_plugin.so
```

结论：第一版 CLI-only `nfqueue_poc` overlay 已被 VPP CMake 发现，并完成编译、链接、安装。

下一步：做更小的启动验证，确认 VPP 能加载 `nfqueue_poc_plugin.so`，并且 CLI 命令可见；之后再进入真正 NFQUEUE verdict smoke。

### 36. 插件 CLI 检查前的运行时依赖检查

目的：在真正跑 NFQUEUE 前，先验证 VPP 能加载 `nfqueue_poc_plugin.so`，并且 `show nfqueue-poc` CLI 可见。

先检查主机依赖：

```sh
ldd work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/nfqueue_poc_plugin.so
```

结果：

```text
libnetfilter_queue.so.1 => not found
```

结论：主机不能直接加载这个插件，CLI/queue 验证应在实验 Docker image 中跑，因为 image 内已安装 `libnetfilter-queue-dev`。

随后检查容器内 VPP 运行时依赖：

```sh
./scripts/run-container.sh ldd .../bin/vpp
```

结果：

```text
libunwind.so.8 => not found
```

处理：把 `libunwind8` 加入 `experiments/vpp-nfq-poc/Dockerfile`。这属于运行时依赖，不应该只依赖一次性 build container 里的 `make install-dep`。

额外坑：`run-container.sh` 使用固定容器名 `sakamoto-vpp-nfq-poc`，并发执行两个 `run-container.sh` 会冲突：

```text
Conflict. The container name "/sakamoto-vpp-nfq-poc" is already in use
```

当前处理：后续容器实验串行执行。

### 37. 增加插件 CLI 启动检查入口

新增：

```text
configs/nfqueue-poc-startup.conf
scripts/run-vpp-nfqueue-cli-check.sh
make vpp-nfqueue-cli-check
```

检查范围：

```text
1. 用只启用 nfqueue_poc_plugin.so 的 startup config 启动 VPP。
2. 等待 /tmp/sakamoto-vpp-nfq-poc/cli.sock 出现。
3. 用 vppctl 执行 show plugins。
4. 用 vppctl 执行 show nfqueue-poc。
```

当前状态：正在重建 Docker image，并运行：

```sh
./scripts/run-container.sh make vpp-nfqueue-cli-check
```

### 38. 插件 CLI 检查第一次运行失败：results 目录权限

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-cli-check
```

失败点：

```text
./scripts/run-vpp-nfqueue-cli-check.sh: line 39:
/work/sakamoto-snort/experiments/vpp-nfq-poc/results/vpp-nfqueue-cli-check.log:
Permission denied
```

原因：`results/` 在宿主侧是 `0755 js:js`。当前 Docker 环境下容器 root 不能直接写这个 bind mount 目录。之前部分结果文件已有 `root:root`，说明这条路径容易产生权限不一致。

处理：`run-container.sh` 在宿主侧启动容器前执行：

```sh
mkdir -p "$POC_DIR/results"
chmod 0777 "$POC_DIR/results"
```

这样后续实验脚本可以稳定写入 `results/`。

### 39. 插件 CLI 检查通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-cli-check
```

结果：

```text
1. nfqueue_poc_plugin.so  26.02-release  NFQUEUE verdict POC
enabled 0 queue 0 mode accept-all drop-ratio 0 fd -1
seen 0 accept 0 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

结论：

```text
VPP 可以加载 nfqueue_poc_plugin.so。
CLI 注册成功：show nfqueue-poc 可用。
当前还没有验证 nfqueue-poc enable、NFQUEUE fd、verdict、真实包通过/丢弃。
```

下一步：把已有 plain C NFQUEUE smoke 的 netns/iptables 拓扑复用起来，改为由 VPP 插件持有 queue 42 并给出 accept/drop/drop-ratio verdict。

### 40. VPP NFQUEUE smoke 入口新增

新增：

```text
scripts/run-vpp-nfqueue-smoke.sh
make vpp-nfqueue-accept
make vpp-nfqueue-drop
make vpp-nfqueue-ratio
```

设计：

```text
1. 复用 setup-netns.sh 创建 nfq-host <-> nfq-peer，并插入 OUTPUT NFQUEUE 规则。
2. 启动只加载 nfqueue_poc_plugin.so 的 VPP。
3. vppctl: nfqueue-poc enable queue 42 mode <mode>。
4. ping -I nfq-host -c 20 10.200.42.2。
5. vppctl: show nfqueue-poc，读取 seen/accept/drop。
6. 根据 mode 检查 ping 返回码和 VPP verdict 计数。
```

### 41. VPP NFQUEUE accept-all 第一次运行：功能通过，脚本断言失败

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-accept
```

实际包处理结果：

```text
20 packets transmitted, 20 received, 0% packet loss
seen 20 accept 20 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

结论：VPP 插件已经能持有 NFQUEUE queue 42，并返回 `NF_ACCEPT` verdict。

脚本失败点：

```text
./scripts/run-vpp-nfqueue-smoke.sh: line 114: ping_rc: unbound variable
```

原因：脚本主体包在 `{ ... } | tee "$LOG"` 管道里执行，`ping_rc` 在 subshell 中赋值，管道结束后外层 shell 读不到。

处理：改为：

```sh
exec > >(tee "$LOG") 2>&1
```

主体流程不再放入管道，变量作用域保持在当前 shell。

### 42. VPP NFQUEUE accept-all 重跑通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-accept
```

结果：

```text
20 packets transmitted, 20 received, 0% packet loss
seen 20 accept 20 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
ping_rc=0
```

结论：`accept-all` 路径完整通过。VPP 插件能接收 queue 42 上的 ICMP OUTPUT 包，并给出 `NF_ACCEPT` verdict。

### 43. VPP NFQUEUE drop-all 通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-drop
```

结果：

```text
20 packets transmitted, 0 received, 100% packet loss
seen 20 accept 0 drop 20 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
ping_rc=1
```

结论：`drop-all` 路径完整通过。VPP 插件给出的 `NF_DROP` verdict 会让对应 NFQUEUE 包被内核丢弃。

### 44. VPP NFQUEUE drop-ratio=50 通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-ratio
```

结果：

```text
20 packets transmitted, 10 received, 50% packet loss
seen 20 accept 10 drop 10 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
ping_rc=0
```

结论：混合 verdict 路径通过。VPP 插件可以对同一个 NFQUEUE queue 中的包逐包选择 `NF_ACCEPT` 或 `NF_DROP`。

当前 POC 已证明：

```text
1. 原版 VPP 加 overlay 后可以加载 Linux-only nfqueue_poc 插件。
2. VPP 进程可以持有 NFQUEUE fd。
3. VPP clib_file read callback 可以接收 queued packet。
4. VPP 插件 callback 可以对 packet id 调用 nfq_set_verdict。
5. accept/drop/ratio 三个行为都能反馈到内核转发结果。
```

下一步：在 `nfqueue-poc enable` 且无流量时重新测 VPP idle CPU，确认 fd-ready 路径没有退化成单核忙轮询。

### 45. VPP NFQUEUE enabled idle CPU 通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-idle-cpu
```

配置：

```text
nfqueue-poc enable queue 42 mode accept-all
SAMPLES=5 DELAY=1 WARMUP=3
```

无流量采样：

```text
vpp_main CPU%: 0.996, 1.993, 0.997, 0.997, 1.993
```

插入 5 个 ping 包：

```text
5 packets transmitted, 5 received, 0% packet loss
seen 5 accept 5 drop 0 missing-id 0
```

流量后再次空闲采样：

```text
vpp_main CPU%: 1.993, 0.996, 1.993, 0.000, 1.993
```

结论：在当前 `clib_file` fd-ready 直 verdict POC 中，`nfqueue-poc enable` 后 VPP 空闲 CPU 没有出现单核 100% 忙轮询，观测值和 minimal VPP 大致同量级。

这不等于最终性能结论；后续进入 vlib_buffer/graph/worker 版本后仍需重测。
