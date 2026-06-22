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

### POC-C1：HEV external fd + socketpair shim

先不接 VPP，验证 HEV 是否能消费非 `/dev/net/tun` 的 packet-oriented fd：

```text
test driver
  -> SOCK_SEQPACKET socketpair one end
  -> HEV external tun_fd receives the other end
  -> test driver sends synthetic IPv4/TCP packets
  -> HEV lwIP accepts the TCP flow
  -> HEV connects to local test SOCKS5 server
  -> SOCKS5 server returns HTTP payload
  -> HEV writes response packet back to socketpair
  -> test driver observes inbound IPv4/TCP packet
```

这个阶段只回答 HEV placement 是否有不魔改的通路，不证明 VPP plugin 已经接好。

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

2026-06-22
  HEV 上游源码/API 调查：
    拉取：
      https://github.com/heiher/hev-socks5-tunnel
    本次验证版本：
      2.15.0-3-g3911f79
      commit 3911f79

  公开 API：
    hev_socks5_tunnel_main(config_path, tun_fd)
    hev_socks5_tunnel_main_from_file(config_path, tun_fd)
    hev_socks5_tunnel_main_from_str(config_str, config_len, tun_fd)
    hev_socks5_tunnel_quit()
    hev_socks5_tunnel_stats(...)

  源码观察：
    src/hev-socks5-tunnel.c tunnel_init(extern_tun_fd >= 0)：
      只对 fd 设置 FIONBIO，然后保存为 tun_fd。
      不强制 ioctl(TUNSETIFF)，不校验 fd 必须来自 /dev/net/tun。

    src/hev-tunnel.h Linux 分支：
      hev_tunnel_read 使用 hev_task_io_read(fd, ...)，返回 lwIP pbuf。
      hev_tunnel_write 使用 write/writev(fd, ...)，把 lwIP output 写回 fd。

    src/hev-socks5-tunnel.c：
      lwip_io_task_entry 从 tun_fd 读 packet 并喂给 netif.input。
      netif_output_handler 把 lwIP output 写回同一个 tun_fd。

  结论：
    HEV 没有公开 packet callback API。
    但 external tun_fd 分支实际上只需要一个可 poll/read/write 的 packet fd。
    因此 SOCK_SEQPACKET socketpair 具备作为 HEV-side shim fd 的可能性。

2026-06-22
  新增实验脚本：
    scripts/fetch-hev.sh
    scripts/build-hev.sh
    scripts/hev-socketpair-probe.py
    scripts/run-hev-socketpair-probe.sh

  新增 Makefile 目标：
    fetch-hev
    build-hev
    hev-socketpair-probe

  说明：
    fetch-hev 默认 pin 到 HEV commit 3911f79，避免后续 upstream main 漂移导致实验不可复现。

2026-06-22
  宿主机执行：
    cd experiments/vpp-nfq-poc
    make hev-socketpair-probe

  结果：
    成功。

  关键输出：
    packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x12 len=0
    packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x10 len=0
    packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x18 len=40
    SOCKS event: ('greeting', b'\x05\x01\x00')
    SOCKS event: ('connect', '93.184.216.34', 80)
    SOCKS event: ('payload', b'GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n')
    response payload: b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK'

  结论：
    HEV 可以从 SOCK_SEQPACKET socketpair 收到 synthetic outbound IPv4/TCP packet。
    HEV 会通过 SOCKS5 CONNECT 访问对应远端地址。
    HEV 会把 upstream response 重新封装成 inbound IPv4/TCP packet 写回 socketpair。

2026-06-22
  Docker 内执行：
    DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh \
      make build-hev hev-socketpair-probe

  第一次结果：
    probe 成功，但 build log 出现 Git dubious ownership 噪声。

  处理：
    scripts/build-hev.sh 增加 safe.directory 配置，覆盖 HEV root 和 submodules。

  第二次结果：
    build-hev 与 hev-socketpair-probe 均成功，且无 dubious ownership 噪声。

  Docker 关键输出：
    packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x12 len=0
    packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x10 len=0
    packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x18 len=40
    SOCKS event: ('greeting', b'\x05\x01\x00')
    SOCKS event: ('connect', '93.184.216.34', 80)
    SOCKS event: ('payload', b'GET /probe HTTP/1.0\r\nHost: example.test\r\n\r\n')
    response payload: b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK'

  日志：
    results/hev-socketpair-probe.log

2026-06-22
  重要限制：
    probe 使用 Python ctypes 直接在线程里调用 hev_socks5_tunnel_quit() 时，
    HEV task-system cleanup 曾触发 free()/munmap_chunk() abort。

  处理：
    probe 改为 fork 子进程运行 HEV，父进程持有 driver 端 socketpair。
    实验结束时由父进程 terminate HEV 子进程。

  判断：
    这不影响 socketpair shim 的 datapath 结论。
    但后续 native/JNI 集成必须单独验证 HEV lifecycle/quit，不能从 Python ctypes 线程结果外推。
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
scripts/run-vpp-tun-forward-fd-smoke.py
```

`tun_poc` 当前实现三个模式：

```text
count-only:
  只读 TUN fd 并计数。

reflect-icmp:
  读 IPv4 ICMP echo request，构造 echo reply 写回同一个 TUN fd。

forward-fd:
  主 TUN fd 与 shim fd 分离。
  outbound 从主 fd 读，写入 shim fd。
  inbound 从 shim fd 读，写回主 fd。
```

POC-B 状态：

```text
已通过：
  external TUN fd -> VPP plugin -> packet handling -> write back same TUN fd
```

POC-C1 状态：

```text
已通过：
  synthetic packet driver -> SOCK_SEQPACKET shim -> HEV -> SOCKS5 -> HEV -> SOCK_SEQPACKET shim
```

POC-C2 状态：

```text
已通过：
  main TUN fd -> VPP/tun_poc forward-fd -> SOCK_SEQPACKET shim
  SOCK_SEQPACKET shim -> VPP/tun_poc forward-fd -> main TUN fd

尚未通过：
  main TUN fd -> VPP/tun_poc -> HEV -> SOCKS5 -> HEV -> VPP/tun_poc -> main TUN fd
```

下一步：

```text
1. 把 HEV 子进程接到 forward-fd shim 的另一端。
2. 用 synthetic TCP/HTTP 或真实 TUN TCP flow 验证 HEV SOCKS5 egress。
3. 单独验证 native/JNI 下 HEV quit/lifecycle，不使用 Python ctypes 线程结果做结论。
```

## 5. POC-C2：VPP forward-fd shim bridge

```text
2026-06-22
  修改 tun_poc：
    新增 mode forward-fd。
    CLI：
      tun-poc enable fd <main_fd> mode forward-fd shim-fd <shim_fd>
    show tun-poc 额外输出：
      shim-rx / shim-tx
      read/write/shim-read/shim-write errors

  行为：
    main fd read  -> shim fd write
    shim fd read  -> main fd write
    不做策略、不做 CT、不管理 HEV 生命周期。

  新增脚本：
    scripts/run-vpp-tun-forward-fd-smoke.py

  新增 Makefile target：
    vpp-tun-forward-fd-smoke
```

验证：

```text
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-poc-smoke
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-forward-fd-smoke
```

结果：

```text
vpp-tun-poc-build:
  tun_poc_plugin.so 构建成功。

vpp-tun-poc-smoke:
  reflect-icmp 旧路径仍通过。
  ping -I tun-poc0 -c 5 -W 1 198.18.0.2:
    5 transmitted, 5 received, 0% packet loss

vpp-tun-forward-fd-smoke:
  tun ifname=tun-poc-forward tun-fd=53 shim-fd=54

  before ping:
    enabled 1 fd 53 shim-fd 54 mode forward-fd
    rx 1 bytes 48 tx 0 bytes 0
    shim-rx 0 bytes 0 shim-tx 1 bytes 48
    errors all 0

  shim observed:
    198.19.0.1 -> 198.19.0.2 icmp_type=8 len=84

  ping:
    1 transmitted, 1 received, 0% packet loss

  after ping:
    enabled 1 fd 53 shim-fd 54 mode forward-fd
    rx 2 bytes 132 tx 1 bytes 84
    shim-rx 1 bytes 84 shim-tx 2 bytes 132
    errors all 0
```

结论：

```text
VPP/tun_poc 可以作为 main TUN fd 与 HEV-side packet fd 之间的双向桥。
这一步只证明 adapter 形状成立。
尚未证明 HEV 接在 shim 后、完整 TCP/SOCKS5 egress 在 VPP 两侧都可用。
```
