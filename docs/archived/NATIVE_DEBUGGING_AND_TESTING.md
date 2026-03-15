# sucre-snort 原生调试与测试工作流（WSL2 / VS Code / Codex CLI）

更新时间：2026-03-14  
状态：已核实的工作文档（以 AOSP / VS Code 官方文档为准）；作为当前 `P0/P1/P2/P3` 测试 / 调试路线的权威补充文档，其中 `P3 真机原生 Debug / crash / LLDB` 是本文重点。该路线与 `A/B/C`、可观测性、`IPRULES` 等功能实现无关。

---

## 0. 这份文档解决什么问题

目标不是把 `sucre-snort` 先改造成“完全脱离 Android/Lineage 的普通 Linux 项目”，而是先建立一条**可实际使用的原生调试与测试 lane**：

- 遇到问题时，可以像普通 C/C++ 项目那样做 **attach / run / breakpoint / step / backtrace / watch**；
- 不是只靠 log 反推；
- 在**不要求先做大重构**的前提下，补出一部分单元测试、集成测试和崩溃定位能力。

---

## 1. 已核实的官方事实

### 1.1 Android 平台原生调试：现在应使用 LLDB，不是 GDB

已核实：AOSP 官方文档明确说明，**GDB 已不再支持/不再提供**，平台原生调试使用 **LLDB**。

这意味着后续所有“像普通 C/C++ 项目一样断点调试”的主线，都应围绕：

- `lldbclient.py`
- `lldbserver`
- VS Code + CodeLLDB

而不是围绕老的 `gdbserver` / `gdb` 工作流。

### 1.2 AOSP 官方支持两类核心 LLDB 工作流

已核实：AOSP 官方文档直接给出两种常用流程：

1. **调试一个你刚 push 到设备上的二进制**：`lldbclient.py -r ...`
2. **附加到已运行的 native daemon / process**：`lldbclient.py -p <pid>`

官方还明确说明：

- `-p` 是 **PID**；
- `--port` 是 **调试端口**；
- `lldbclient.py` 会自动做 **port forwarding、启动远端 stub、配置符号、连接 host 端调试器**。

### 1.3 AOSP 官方支持 VS Code 调试 Android 平台原生代码

已核实：AOSP 官方文档专门有一节 `Debug with VS Code`，明确说明：

- Android 平台原生代码可以用 **Visual Studio Code** 调试；
- 官方推荐安装 **CodeLLDB** 扩展；
- 通过 `lldbclient.py --setup-forwarding vscode-lldb --vscode-launch-file ...` 可以自动生成 `launch.json` 片段并完成连接准备。

这不是“野路子”，而是 AOSP 官方支持的工作流。

### 1.4 VS Code Remote / WSL 是官方支持的远程开发模型

已核实：VS Code 官方文档说明：

- Remote Development 扩展可以把命令与扩展直接运行在 **WSL** / 容器 / 远端主机中；
- 在远程工作区中，**Workspace Extensions** 会运行在远端环境（这里就是 WSL）里的 **Remote Extension Host / VS Code Server** 中；
- 这意味着在 WSL 打开的工程里，调试相关扩展可以运行在 WSL 环境本身。

基于这些官方文档，**在 VS Code WSL 窗口内使用 CodeLLDB 调试 Android native 代码是成立的**。

### 1.5 崩溃后等待调试器 / tombstone / 符号化 也是官方支持能力

已核实：AOSP 官方文档明确说明：

- 崩溃时更完整的 tombstone 会写到 `/data/tombstones/`；
- Android 11 之后可以设置：

```bash
adb shell setprop debug.debuggerd.wait_for_debugger true
```

让崩溃进程挂起，等待调试器附加；

- 若已持有未剥离符号，可使用 `stack` 对 tombstone / crash dump 做符号化。

同时官方也特别提醒：**如果进程已经被 `lldb` 或 `strace` 之类工具附加，crash dumper 可能无法再附加**，因此“live debug”和“取系统 tombstone”有时需要分开做。

### 1.6 内存错误定位：AOSP 当前主推 HWASan

已核实：AOSP 官方文档说明：

- Android 平台开发者用 **HWASan** 查 C/C++ 内存错误；
- 在 AArch64 平台上，**ASan 在 Android 11 之后已被官方标注为不推荐，建议改用 HWASan**；
- 若只能做局部 sanitizer，单模块启用 `sanitize` 仍然是可行路径。

这意味着：对 `sucre-snort` 这类 native daemon，**sanitizer 构建是很高价值的 debug lane**，即使它不是“单元测试”。

---

## 2. 当前仓库与这些官方能力的映射

当前仓库已经具备不少前提条件：

- 开发构建目标是 `userdebug`：见 `dev/dev-build.sh`
- 编译参数里已经带 `-g`：见 `Android.bp`
- 当前开发部署目标是独立二进制：`/data/local/tmp/sucre-snort-dev`
- 当前开发流程已经把守护进程与系统镜像内正式版本隔离

这意味着：

- **最适合先调试的是 `/data/local/tmp/sucre-snort-dev`**；
- 不必一开始就和 `init.rc` / 正式系统服务生命周期绑定死；
- 可以先把“断点调试体验”做起来，再决定是否需要更深的系统服务级调试。

> 注：当前仓库脚本在 WSL 下会优先选择 Lineage tree 自带的 Linux `adb`，只有显式覆盖时才退回其他 `adb` / `adb.exe`。这样可以避开 Windows `adb.exe` 在后台 helper / mDNS 设备发现上的不稳定行为。

---

## 3. 推荐的调试工作流（不要求先重构代码）

## 3.1 方案 A：附加到正在运行的 `sucre-snort-dev`

适合场景：

- 守护进程已经能跑起来；
- 某条控制命令、某类流量、某段运行期状态会触发问题；
- 想看线程、锁、栈、变量、条件断点。

推荐步骤：

```bash
# 1) 在 AOSP tree 里进入已 setup 的 shell
cd ~/android/lineage
source build/envsetup.sh
lunch lineage_bluejay-bp2a-userdebug

# 2) 确保已部署并运行 dev binary
cd /home/js/Git/sucre/sucre-snort/dev
bash dev-build.sh
bash dev-deploy.sh

# 3) 取得 PID（建议找 sucre-snort-dev）
adb shell su -c 'pidof sucre-snort-dev'

# 4) 附加调试器
lldbclient.py -p <PID>
```

说明：

- 这是 AOSP 官方支持的 attach 模式；
- `lldbclient.py` 会自动处理符号与远端连接；
- 适合大多数“跑一会儿才出问题”的场景。

## 3.2 方案 B：启动即断点（run-under-debugger）

适合场景：

- 启动阶段就失败；
- socket / iptables / listener 初始化阶段有问题；
- 想在 `main()`、构造函数、初始化路径最早处下断点。

推荐步骤：

```bash
cd ~/android/lineage
source build/envsetup.sh
lunch lineage_bluejay-bp2a-userdebug

# 停旧进程并清理遗留 socket（按需要增减）
adb shell su -c 'killall sucre-snort-dev 2>/dev/null || true'
adb shell su -c 'rm -f /dev/socket/sucre-snort-control /dev/socket/sucre-snort-netd'

# 推送 dev binary
adb push /home/js/Git/sucre/sucre-snort/build-output/sucre-snort /data/local/tmp/sucre-snort-dev
adb shell su -c 'chmod 755 /data/local/tmp/sucre-snort-dev'

# 直接在调试器下启动
lldbclient.py --port 5039 -r /data/local/tmp/sucre-snort-dev
```

说明：

- 官方文档明确支持 `-r` 模式；
- `-r` 后面跟的是“要在设备上启动的命令行”，因此**`-r` 应放在 `lldbclient.py` 可选参数的最后**，不要再把别的 `lldbclient.py` 选项写在它后面；
- 若命中入口断点后程序停住，按需 `continue`；
- 这是取代“启动失败只能看 log”的最直接路径。

## 3.3 方案 C：VS Code（WSL 窗口）图形化断点调试

适合场景：

- 你主要在 VS Code WSL2 开发；
- 想获得接近普通 Linux/C++ 项目的调试体验；
- 需要可视化线程、变量、断点、条件断点、watch 表达式。

推荐步骤：

### 第一步：在 VS Code 的 **WSL 窗口** 打开仓库

- 使用 `WSL: New Window`
- 在 WSL 窗口内打开 `sucre-snort` 工程
- 在这个 **WSL 窗口** 中安装 **CodeLLDB**

> 这里的“在 WSL 窗口安装”是基于 VS Code Remote 官方机制做出的工作结论：在远程工作区里，workspace 类扩展运行在远端环境中。

### 第二步：直接使用 checked-in `.vscode` 工作流

当前仓库已经提供：

- checked-in `.vscode/launch.json`
- checked-in `.vscode/tasks.json`
- `dev/dev-vscode-debug-task.py` 作为 VS Code task helper
- `dev/dev-native-debug.sh` 作为底层 Android / `lldbclient.py` backend

因此现在的推荐方式不再是“手工准备一个最小 `launch.json` 壳子，再手敲脚本”，而是直接在仓库根目录使用 checked-in F5 工作流。

### 第三步：在 VS Code 中按 `F5`

当前可用的配置是：

- `Sucre Snort: Attach (real device)`
- `Sucre Snort: Run (real device)`

执行过程：

1. `preLaunchTask` 会先进入 checked-in VS Code task；该 task 先执行 `cmake --preset dev-debug`，再通过 `cmake --build --preset dev-debug --target snort-debug-*-workflow` 调到真正的 debug backend；
2. `Run` 配置会顺序执行：cleanup → incremental build → stage-only deploy → prepare run；`Attach` 配置会执行 cleanup → prepare attach；
3. helper 再调用 `dev/dev-native-debug.sh vscode-helper-attach` 或 `vscode-helper-run`；
4. backend 会继续处理当前真机工作流里的几个兼容点：
   - 对 `/data/local/tmp/sucre-snort-dev` 这类开发态二进制，优先使用 host 侧 `build-output/sucre-snort.debug`；若默认 host binary 已 strip，则按 Build ID 自动回退到 Soong `unstripped` 产物；
   - 在 `attach` / `run` 前先清理设备侧残留的 `lldb-server` / `gdbserver` / `TracerPid`；`run` 模式下还会额外停掉旧的 `sucre-snort-dev` 与旧 socket，避免上一次异常调试把环境卡脏；
   - `Run` 场景下不会再先正常启动 daemon 再立刻杀掉，而是通过 `stage-only deploy` 只把新二进制推到设备，再直接进入 run-under-debugger；
   - `Run` 模式会保留启动时的 `SIGSTOP`（让进程先停在入口），以便 VS Code/CodeLLDB 有机会在真正执行前安装断点；同时会屏蔽 `SIGCHLD` 噪音，避免被频繁的子进程信号打断；
   - `Run` 模式还会设置 `target.skip-prologue=false`，这样 `main` 入口这类源码断点可以停在函数入口，而不是被默认挪到序言后的首个可执行位置；
   - helper 会把编译时源码前缀 `system/sucre-snort` 映射回当前工作区根目录，确保 VS Code 下使用工作区绝对路径设置的源码断点可以正确绑定；
   - VS Code helper 会直接在设备上拉起 `arm64-lldb-server`、建立 `adb forward tcp:<port> tcp:<port>`，并生成 CodeLLDB 所需的 launch 片段，不再依赖 `lldbclient.py` 那条更慢的前置链路。
5. helper 会把生成出的 launch 片段物化成稳定的 `.lldb` 命令文件，并把实际 `sourceMap` 物化进去，避免 checked-in `launch.json` 直接依赖 `${env:LINEAGE_ROOT}`；
6. `launch.json` 里的 `preRunCommands` 会把 VS Code 的 `Restart` 生命周期接到真实真机流程：
   - `Run` 模式下，`Restart` 会执行一轮新的 incremental build → stage-only deploy → 真机 `lldb-server` 重建，然后再重新连接；
   - `Attach` 模式下，`Restart` 会先清理当前 attach 残留，再重新附加到当前运行中的 `sucre-snort-dev`；
   - `Stop` 则由 `postDebugTask` 做最终收尾。
7. 最终由 checked-in `launch.json` 里的 CodeLLDB 配置连接到真机上的 `lldb-server`。

### 第四步：结束调试

调试结束后，由 `postDebugTask` 执行 `dev/dev-vscode-debug-task.py cleanup`，向后台 helper 发送换行并完成最终清理。

额外提醒：如果上一次调试异常中断，设备上可能残留 `lldb-server`，把 `sucre-snort-dev` 停在 `tracing stop`。当前 `dev/dev-deploy.sh` 已经会在 redeploy 时检查 `TracerPid` 并自动清理这类残留 debugger；若仍怀疑有残留，可先跑：

```bash
bash dev/dev-diagnose.sh --serial <serial>
```

### 手工 fallback

如果需要绕过 VS Code task helper，仍然可以直接调用底层 backend：

```bash
bash dev/dev-native-debug.sh vscode-attach --serial <serial>
bash dev/dev-native-debug.sh vscode-run --serial <serial>
```

---

## 4. 崩溃优先场景：不要只看 log

如果问题是“很快 crash，来不及 attach”，推荐优先走这条线：

```bash
adb shell setprop debug.debuggerd.wait_for_debugger true
```

然后复现问题，再按 logcat / debuggerd 给出的提示附加调试器。

同时保留下面这套兜底能力：

```bash
# 抓 tombstone
adb shell su -c 'ls -lt /data/tombstones | head'
adb shell su -c 'cat /data/tombstones/tombstone_xx' > /tmp/tombstone_xx

# 在已 lunch 的 shell 里做符号化
stack < /tmp/tombstone_xx
```

建议把问题分成两类：

- **live attach / breakpoint 场景**：优先 LLDB
- **野外 crash / 一次性崩溃复盘**：优先 tombstone + `stack`

不要强行把两套机制混在一次运行里，因为官方文档已明确说明：若 `lldb` / `strace` 已附加，crash dumper 可能拿不到机会。

---

## 5. 对 `sucre-snort` 特别有价值的附加能力

## 5.1 dev-only 编译选项：建议补 `-fno-omit-frame-pointer`

当前仓库已有 `-g`，但若希望：

- backtrace 更稳定；
- sanitizer 报告更好读；
- 断点与单步更接近源码直觉；

建议为 **debug/dev 变体** 追加：

```text
-O0
-fno-omit-frame-pointer
```

这是 AOSP 官方 ASan 文档里也特别强调的方向：更好的栈信息依赖 frame pointers。

## 5.2 对内存破坏类问题：优先考虑 HWASan

若你遇到的是：

- use-after-free
- heap overflow
- stack scope 相关问题
- “日志看起来像别处坏了，但根因不在崩点”

那么 **HWASan build / image** 往往比纯日志或普通断点更高效。

对 Android 平台组件，AOSP 当前官方建议优先用 **HWASan**，而不是 arm64 上的旧式 ASan。

## 5.3 对 syscall / 权限 / socket / 文件问题：`strace` 很有帮助

当问题集中在：

- bind / connect / listen / accept
- open / rename / chmod / unlink
- `iptables` / `execv`
- SELinux / seccomp / 权限边界

可以考虑对进程使用 `strace`。AOSP 官方也保留了这条调试路径。

但要记住：`strace` 与 crash dump / LLDB 一样，可能会和其他调试机制相互影响。

---

## 6. 当前项目的 phase 顺序与目标环境

当前项目的 `P0/P1/P2/P3` 是 **测试 / 调试路线编号**，不是功能实现编号，也不对应 `A/B/C`、可观测性或 `IPRULES` 主线。

顺序固定为：

- `P0`：host-side 单元测试（不连设备，优先 low-coupling `gtest`）
- `P1`：host-driven 集成测试（测试代码跑在 host / WSL，由 host 驱动真机）
- `P2`：真机集成 / smoke / 兼容性验证（更贴近 NFQUEUE / `iptables` / `netd` / SELinux / 权限 / 性能场景）
- `P3`：真机原生 debug / crash 复盘 / LLDB / VS Code CodeLLDB

这意味着：

- 当前不再为模拟器 / 虚拟设备维护单独流程；
- `P1/P2/P3` 都以 Android 真机为目标环境；
- `P3` 与 `P1/P2` 的区别在于：前者解决 live debug / crash / native 排障，后两者解决自动化验证与回归；
- `A/B/C`、`add-pktstream-observability`、`add-app-ip-l3l4-rules-engine` 属于独立功能线，统一排在整个 test / debug 路线之后。

---

## 7. 那么单元测试、集成测试到底有没有办法？

有，而且**不必先大重构**；只是要接受“测试分层”。

## 7.1 单元测试：有办法，但覆盖面有限

AOSP 官方明确支持：

- **平台 GoogleTest（native tests）**
- **host-side deviceless gtest**
- 通过 Tradefed 的 **HostGTest** 在 host 上跑 native gtest

如果测试本身**不需要设备**，官方建议直接跑 host-side gtest，因为会更快。

按 AOSP 官方文档，host-side gtest 在 Soong 中通常通过 `host_supported: true` 暴露为 host 变体；随后可用 `atest --host <module>` 运行，或由 Tradefed 的 `HostGTest` 自动生成配置并执行。

这类测试适合放在：

- 解析器
- 规则匹配
- 计数器
- package / UID / userId 处理逻辑
- 控制命令参数解析

对 `sucre-snort` 而言，这类测试当然不是“主要目标”，但它仍然有价值：

- 能把一些低级回归挡在进入设备前；
- 能让规则/解析类 bug 更快复现；
- 成本相对低。

## 7.2 集成测试：有，而且这是更值得优先做的方向

AOSP 官方明确支持两条非常适合当前项目的路：

### 路线 A：device-side native gtest

适用场景：

- 想在 Android 环境中直接跑 native test binary；
- 测试对象需要设备上的 Android 用户态环境；
- 但还不需要完整 UI / App 自动化。

官方路径是：

- 写平台 GTest；
- 通过 `atest <module>` 或 Tradefed 运行；
- AOSP 文档也覆盖模拟器/AVD 路径，但对当前仓库一律不纳入工作流；当前实践统一收敛到真实 Android 设备。

### 路线 B：host-driven tests（更适合 `sucre-snort`）

AOSP 官方明确支持 **host-driven test**：

- 测试代码跑在 host；
- 由 host 去驱动设备状态、推送文件、执行 shell、收集结果；
- 适合需要 reboot、push binary、改设备状态、调用 adb 的集成测试。

这条路和 `sucre-snort` 当前开发模式非常贴合，因为你们现在本来就已经在做：

- push dev binary
- 启动守护进程
- 建控制 socket
- 发送命令
- 查日志 / 查 socket / 查状态

换句话说：**你们离“正式的 host-driven integration test”其实只差一步封装，不差架构重写。**

## 7.3 对当前项目最现实的 `P0/P1/P2/P3` 分层建议

### `P0`：host-side deviceless tests

目的：快速挡住纯逻辑回归。

建议覆盖：

- `PackageState` 解析
- `Rule` / `CustomRules` 匹配
- `Stats` / `AppStats` / `DomainStats` 计数
- `Control` 参数解析辅助逻辑

### `P1`：host-driven integration tests

目的：验证“守护进程 + 真机 + 控制面”整体行为，但测试驱动仍运行在 host / WSL。

建议覆盖：

- push `sucre-snort-dev`
- 启动 / 停止 daemon
- `HELLO` / `HELP`
- `BLOCK` / `BLOCKMASK` / `RESETALL`
- `APP.*` 查询
- `DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 基础行为
- save / restore / reset 语义

这层本质上就是把现有 smoke 路径里的关键路径，逐步沉淀为位于 `tests/integration/` 的**可自动跑、可并入 CI、可筛选模块运行**的测试模块。

### `P2`：真机 smoke / compatibility / integration

目的：把必须依赖 rooted Android 真机的专项验证单独收敛出来。

建议继续保留：

- NFQUEUE 行为
- `iptables` 链初始化
- `netd` 相关交互
- SELinux / 权限问题
- 生命周期、性能回归、backlog、极端流量行为

### `P2` 补充：APatch 下的开发态快路径（已实机验证）

对于当前这台 rooted 真机，已经验证存在一条**不必先刷完整模块**的开发态快路径，适合日常真机联调 / 冒烟 / 集成验证：

```bash
# 1) 准备开发态依赖：推送并临时挂载 libnetd_resolv.so，必要时切到 permissive
bash dev/dev-netd-resolv.sh prepare

# 2) 运行 P2
bash tests/integration/device-smoke.sh --serial <serial> --skip-deploy --cleanup-forward
```

关键点：

- `libnetd_resolv.so` 不再要求每次都通过完整模块刷入；可以直接推到 `/data/local/tmp/` 后，临时 bind mount 到 `/apex/com.android.resolv*/lib64/libnetd_resolv.so`。
- 在当前 APatch 环境里，直接 `adb shell su -c 'setenforce 0'` 可能失败；已验证可通过 **`nsenter -t 1 -m -- setenforce 0`** 切换到 `Permissive`。
- 这条快路径本质上属于 **dev-only 临时状态**：设备重启后需要重新执行，不应当被误认为持久部署方案。
- 若只是为了跑 `P2`、复现问题或提高真机联调效率，应优先走这条快路径；完整模块仍保留为更重的兜底方案。

当前仓库中，这条快路径已经收敛为：

- `dev/dev-netd-resolv.sh`
- `dev/README.md`
- `tests/integration/device-smoke.sh`

因此，`P2` 中与 `netd` / SELinux 相关的验证，不再要求先把设备改造成完整模块态；在 APatch 真机上，开发态快速准备即可满足测试前置。

### `P3`：真机 native debug / sanitizer / crash lane

目的：抓“肉眼最难查”的 native 问题，并提供日常断点调试能力。

建议补：

- LLDB attach / run-under-debugger
- VS Code + CodeLLDB 调试准备
- tombstone + `stack` 归档流程
- dev-only `sanitize` 变体
- 有条件时优先 HWASan

---

## 8. 对当前项目的推荐推进顺序

按当前已经确认的 roadmap，顺序固定为：

1. **`P0`：先补 host-side 单元测试**
   - 只挑高价值、低耦合模块，不追求“全覆盖”

2. **`P1`：再把现有 smoke 收敛为 host-driven integration tests**
   - 测试代码在 host / WSL，目标是真机

3. **`P2`：随后补真机专项的 integration / smoke / compatibility**
   - 解决 NFQUEUE / `iptables` / `netd` / SELinux / 权限 / 性能等真实环境差异

4. **`P3`：最后固化真机 native debug / crash lane**
   - LLDB attach / run-under-debugger
   - VS Code WSL 图形化断点调试
   - tombstone / `stack` / sanitizer

这个顺序的核心是：

- 先建立最基础、最便宜的自动化保护；
- 再把 host 驱动真机的回归跑通；
- 再补必须依赖真机环境的专项验证；
- 最后把高效率 native 调试链完整补齐。

---

## 9. 结论

对于 `sucre-snort`，在**不先做大重构**的前提下，下面这些都是现实可行的：

- 用 **LLDB** 而不是 GDB，对设备上的 native daemon 做断点调试；
- 在 **VS Code WSL2** 里用 **CodeLLDB** 获得接近普通 Linux/C++ 项目的调试体验；
- 用 `debuggerd.wait_for_debugger`、tombstone、`stack` 解决“来不及 attach 就 crash”的问题；
- 通过 **host-driven integration tests** 把现有设备烟测逐步正规化；
- 通过少量 **host-side gtest** 和 **device-side gtest** 补充测试层；
- 通过 **HWASan / sanitizer** 增强内存错误定位能力。

真正不现实的是：

- 期待“完全不依赖 Android/Lineage，就把整个 daemon 当纯 Linux 项目一样完整开发与验证”；
- 或者期待“非真机环境可以完全替代真实 Android 设备”。

现实可行、性价比最高的目标是：

**保留当前 Android 构建链，但把调试链、测试链、崩溃定位链补齐。**

---

## 10. 官方参考链接（2026-03-13 核实）

- AOSP `Use debuggers`: https://source.android.com/docs/core/tests/debug/gdb
- AOSP `Debug native Android platform code`: https://source.android.com/docs/core/tests/debug
- AOSP `Debug native memory use`: https://source.android.com/docs/core/tests/debug/native-memory
- AOSP `AddressSanitizer`: https://source.android.com/docs/security/test/asan
- AOSP `Hardware-assisted AddressSanitizer`: https://source.android.com/docs/security/test/hwasan
- AOSP `GoogleTest`: https://source.android.com/docs/core/tests/development/gtest
- AOSP `Write a host-side deviceless test in TF`: https://source.android.com/docs/core/tests/tradefed/testing/through-tf/host-side-deviceless-test
- AOSP `Write a host-driven test in Trade Federation`: https://source.android.com/docs/core/tests/tradefed/testing/through-tf/host-driven-test
- AOSP `Work with devices in TF`: https://source.android.com/docs/core/tests/tradefed/fundamentals/devices
- VS Code `Remote Development`: https://code.visualstudio.com/docs/remote/remote-overview
- VS Code `Supporting Remote Development and GitHub Codespaces`: https://code.visualstudio.com/api/advanced-topics/remote-extensions
