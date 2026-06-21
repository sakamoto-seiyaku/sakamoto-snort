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
