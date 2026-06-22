# VPP TUN / HEV Experiment Log

日期：2026-06-22
分支：`research/vpp-nfq-poc`

本文记录 Docker 内模拟 Android VPN mode 的下一组实验。上一阶段已经证明：

```text
1. Linux/Docker NFQUEUE 可以由 VPP 插件持有 fd 并返回 allow/drop verdict。
2. Android 真机上原版 VPP runtime 可以启动并通过 NFQUEUE allow/drop。
3. 当前 Android trim 方向已经收口；此处回到 Linux/Docker 验证 VPN/TUN 数据面。
```

## 1. 目标

最终目标：

```text
Android/VPN owner 提供 tun-fd
  -> VPP 从 tun-fd 收 L3 packet
  -> VPP/Snort 处理 allow/drop/log/CT/policy
  -> allow packet 交给 HEV 或等价 egress engine
  -> HEV response 回到 VPP/Snort packet path
  -> VPP 写回 tun-fd，模拟 inbound injection
```

关键边界：

```text
HEV 不拥有主 tun-fd。
VPP/Snort 才是 policy interception point。
outbound 和 inbound 都必须经过同一个 packet processing path。
```

## 2. 分阶段验证

### POC-B：external TUN fd -> VPP -> write back

先不接 HEV，验证 external fd 生命周期和双向读写：

```text
Linux helper 创建 /dev/net/tun fd
  -> fd 继承给 VPP process
  -> tun_poc 插件通过 CLI 接收 fd number
  -> clib_file / epoll 监听 fd readiness
  -> VPP 读 L3 IPv4 ICMP echo request
  -> POC 模式生成 ICMP echo reply
  -> VPP 写回同一个 TUN fd
  -> ping 成功
```

这不是最终 datapath，只是证明 Android `VpnService` fd 模型可以被 VPP 插件消费。

验收：

```text
1. Docker 容器能访问 /dev/net/tun。
2. helper 能创建 TUN interface 并把 fd 继承给 VPP。
3. VPP 能启动并加载 tun_poc_plugin.so。
4. tun-poc enable fd <n> 成功。
5. ping -I tun-poc0 198.18.0.2 成功。
6. show tun-poc 中 rx/tx packet 计数增长。
7. idle CPU 仍不能出现单核 100% 忙轮询。
```

### POC-C：VPP + HEV egress

POC-B 成功后再接 HEV：

```text
TUN fd outbound
  -> VPP path
  -> allow packet 送入 HEV-side adapter
  -> HEV 负责 upstream egress
  -> HEV response 回到 VPP path
  -> VPP 写回 TUN fd
```

此阶段需要单独调查 HEV API 是否支持 packet I/O callback、socketpair/shim fd 或其它非独占
主 TUN fd 的集成方式。如果 HEV API 强制独占主 TUN fd，则不能直接作为当前架构的 egress
engine，需要替代 adapter 或魔改。

## 3. 当前执行记录

```text
2026-06-22
  提交 e9a1adb 后，research/vpp-nfq-poc 工作区干净。

2026-06-22
  容器默认没有 /dev/net/tun。
  主机存在 /dev/net/tun。
  新增 DOCKER_TUN_DEVICE=1，让 run-container.sh 按需传入 --device /dev/net/tun:/dev/net/tun。

2026-06-22
  验证命令：
    DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh \
      sh -lc "ls -l /dev/net/tun; ip tuntap add dev tun-poc-test mode tun; ip link show tun-poc-test; ip link del tun-poc-test"

  结果：
    /dev/net/tun 可见。
    ip tuntap add dev tun-poc-test mode tun 成功。

2026-06-22
  首次执行：
    DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh make vpp-tun-poc-build

  结果：
    失败于 VPP configure：
      /usr/bin/bash: line 1: cmake: command not found

  判断：
    这不是 tun_poc 插件编译错误，而是 Dockerfile 没有包含可重复增量构建 VPP 所需的 cmake。
    之前完整 VPP build 依赖 VPP_INSTALL_DEPS=1 在一次性容器里安装依赖，容器退出后不会持久化。

  处理：
    Dockerfile 补入 cmake、ninja-build、ccache。

2026-06-22
  第二次执行 vpp-tun-poc-build 继续失败：
    The CMAKE_C_COMPILER:
      /usr/lib/ccache/clang
    is not a full path to an existing compiler tool.

  判断：
    VPP build 默认选择 clang，并通过 ccache wrapper 查找 /usr/lib/ccache/clang。
    Dockerfile 只有 gcc/g++，没有 clang。

  处理：
    Dockerfile 补入 clang。

2026-06-22
  第三次执行 vpp-tun-poc-build 继续失败：
    The CMAKE_CXX_COMPILER:
      /usr/lib/ccache/c++
    is not a full path to an existing compiler tool.

  判断：
    这是 VPP build-root 复用 ccache wrapper 路径时的容器环境问题。
    Debian ccache 安装后已有 /usr/lib/ccache/clang，但当前镜像没有 /usr/lib/ccache/c++。

  处理：
    Dockerfile 增加单独 layer：
      ln -sf /usr/bin/ccache /usr/lib/ccache/c++

2026-06-22
  第四次执行 vpp-tun-poc-build 继续失败：
    ModuleNotFoundError: No module named 'ply'
    The "ply" Python3 package is not installed.

  判断：
    VPP API generator 需要 Python ply。

  处理：
    Dockerfile 补入 python3-ply。

2026-06-22
  第五次执行 vpp-tun-poc-build 进入 VPP build 阶段，configure summary 已出现：
    Plugins: ... nfqueue_poc ... tun_poc ...

  失败：
    ninja: error: '/usr/lib/x86_64-linux-gnu/libunwind.so',
    needed by 'lib/x86_64-linux-gnu/libvppinfra.so.26.02', missing

  判断：
    Dockerfile 只有 libunwind8 runtime 包，没有 libunwind-dev 提供的 linker .so。

  处理：
    Dockerfile 补入 libunwind-dev。

2026-06-22
  第六次执行 vpp-tun-poc-build 继续失败：
    ninja: error: '/usr/lib/x86_64-linux-gnu/libiberty.a',
    needed by 'lib/x86_64-linux-gnu/libvlib.so.26.02', missing

  判断：
    VPP native build 需要 libiberty static archive。

  处理：
    Dockerfile 补入 libiberty-dev。

2026-06-22
  后续判断：
    继续补完整 VPP build-release 的 test/API 依赖会污染 POC-B。
    当前目标只是验证 tun_poc_plugin，不需要重建 vapi_c_test 等不相关目标。

  处理：
    新增 scripts/build-vpp-plugin.sh。
    Makefile 的 vpp-tun-poc-build 改为：
      1. apply-vpp-overlay.sh
      2. cmake --build 已配置的 VPP build tree --target tun_poc_plugin
      3. 将 tun_poc_plugin.so 复制到 install-vpp-native/vpp/lib/.../vpp_plugins/

2026-06-22
  单目标构建进入 tun_poc 编译，失败：
    vlib/file.h: unknown type name 'vlib_main_t'

  判断：
    tun_poc.h 先 include 了 vlib/file.h，后 include vlib/vlib.h。
    file.h 中声明使用 vlib_main_t，需要先包含 vlib/vlib.h。

  处理：
    调整 tun_poc.h include 顺序：先 vlib/vlib.h，再 vlib/file.h。

2026-06-22
  重新执行单目标构建：
    DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh make vpp-tun-poc-build

  结果：
    成功构建 tun_poc_plugin.so。
    成功安装到：
      work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/

  结论：
    当前 overlay、CMake 接入、单插件增量构建路径可用。

2026-06-22
  执行 TUN fd smoke：
    DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-poc-smoke

  核心输出：
    ping -I tun-poc0 -c 5 -W 1 198.18.0.2
    5 packets transmitted, 5 received, 0% packet loss

    show tun-poc:
      rx 7 bytes 516 tx 5 bytes 420
      parse-errors 0 write-errors 0

  结论：
    POC-B 通过。
    VPP 插件可以消费外部创建并继承进程的 TUN fd。
    VPP 可以从该 fd 收到 L3 packet，处理后写回同一个 fd。
    这证明 Android VpnService 提供 tun-fd 的生命周期模型，至少可以被 VPP 插件形式接入。
    HEV egress 尚未验证；下一阶段不能假设 HEV 能直接按这个模型工作。
```

## 4. 新增 POC-B 文件

```text
overlay/src/plugins/tun_poc/
  CMakeLists.txt
  plugin.c
  tun_poc.h
  tun_poc.c

configs/tun-poc-startup.conf
scripts/tun-vpp-wrapper.py
scripts/run-vpp-tun-poc-smoke.sh
```

`tun_poc` 当前只实现两个模式：

```text
count-only:
  只读 TUN fd 并计数。

reflect-icmp:
  读 IPv4 ICMP echo request，构造 echo reply 写回同一个 TUN fd。
```

POC-B 状态：

```text
已通过：
  external TUN fd -> VPP plugin -> packet handling -> write back same TUN fd
```

下一步：

```text
1. 调查 HEV 是否支持非独占主 TUN fd 的 packet I/O 接入。
2. 若 HEV 只能独占 TUN fd，设计 socketpair/shim fd 或替代 egress adapter。
3. 验证 allow packet 从 VPP 送入 HEV，HEV response 再回到 VPP path。
4. 验证 inbound 回包由 VPP 写回主 TUN fd。
```
