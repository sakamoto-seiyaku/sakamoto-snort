# Android / VPP 当前现状与架构交接

状态：当前权威交接文档，2026-07-19。

范围：Android 优先的产品基础、VPP 引入、root/NFQUEUE 与
VpnService/TUN 两种运行路径。Linux 的实现和功能验证暂缓，除非后续设计决策明确恢复。

证据基线：分支 `dev/vpp-base`，提交 `c572874`。本文只总结事实和边界，不把 POC
代码提升为产品代码。

## 1. 本文怎么用

新对话先读本文，再按需读实验流水账。发生冲突时，权威顺序如下：

1. `docs/decisions/` 中已接受的设计决策。
2. `docs/INTERFACE_SPECIFICATION.md` 中的当前契约，以及 `CONTEXT.md` 中的术语。
3. 本文与 `docs/IMPLEMENTATION_ROADMAP.md` 中的当前状态。
4. Plane 中的开放工作状态。当前相关项是 `SAKAMOTO-1`、`SAKAMOTO-32`。
5. `experiments/vpp-nfq-poc/` 中的实验过程和证据。
6. `archive/current-head/`、`archive/openspec/` 中的历史材料。

Plane `SAKAMOTO-1` 是最初的高影响 POC 计划。它仍包含“继续大量 POC”和“部分问题先在
Linux 验证”的旧顺序，已不再代表下一阶段执行方式。当前要求是停止扩展 POC 队列，先完成
架构对齐和实现计划。未完成的 NFQUEUE 插件准入问题仍由 `SAKAMOTO-32` 跟踪。

## 2. 一页结论

已经在 Pixel 6a、Android 16/API 36、arm64-v8a 上证明：

- VPP v26.02 可以使用 NDK r29 交叉编译、裁剪、部署、启动、控制和停止。
- 同一套裁剪后的 VPP runtime 可以分别支撑 root/NFQUEUE POC 与普通 app UID 的
  VpnService/TUN POC。
- 当前 VPP stage 约 9.4 MB；使用该 stage 的 VPN POC APK 约 3.3-3.4 MB。
- opt-in Android idle profile 把无流量 VPP 的 60 秒短采样从百分之几降到约 0.05%，
  同时保住了已测 NFQUEUE 和 TUN/HEV 路径。
- 普通 app UID 可以执行 Rust -> 薄 C ABI shim -> generated VAPI -> VPP binary API，
  app、VPP、HEV 均不调用 `su`。
- root RuntimeService 可以打包、校验、启动、监督当前 native daemon，并在已测 Android
  生命周期故障后清理 daemon、control socket 和双栈 NFQUEUE hook。
- 实验性 VPP `nfqueue_poc` 插件可以在 Android 上完成基础 IPv4/IPv6
  INPUT/OUTPUT verdict 和 queue teardown。

但尚未证明一个完整产品 runtime。上述事实来自三套彼此独立的 POC：

- active `sucre-snort` root daemon 及其原生 NFQUEUE pass-through；
- `vpn-lite` 的 VPP/TUN/HEV 普通 app UID harness；
- 独立 root VPP 加实验性 `nfqueue_poc` 插件。

当前 APK RuntimeService 启动的是 `libsucre_snortd.so`，不是 9.4 MB 的 VPP runtime。
`SAKAMOTO-32` 则从 root 临时目录直接启动 VPP，没有经过 RuntimeService。VPN harness
只是 debug shell，不是 Tauri 产品应用。

因此当前发版结论是 **No-Go**。剩余问题已经不是“VPP 能不能跑”，而是如何把三套边界
收敛成一个具有明确进程、权限、Adapter、控制、生命周期和故障语义的产品架构。

## 3. 已经对齐的产品方向

以下方向已记录在 Plane，且与 POC 证据一致：

- VPP 是目标 dataplane runtime，拥有 packet verdict。
- Tauri/Rust 是产品 control plane，拥有持久化、校验、策略创作、生命周期意图、
  UI-facing state 和错误映射。
- 正式控制链路为 Tauri/Rust -> 版本化薄 C ABI -> generated VAPI -> VPP binary API
  -> Sakamoto VPP plugin。VPP CLI 只用于开发和紧急诊断。
- Android 只提供平台资源和事实，包括 VpnService TUN ownership、`protect()`、
  tuple-to-UID lookup、foreground service 和特权进程启动。Android 层不拥有 allow/drop
  策略。
- Android RuntimeService 拥有平台生命周期边界。它把产品的生命周期意图转换为
  process start/stop、artifact handoff、health、crash cleanup 和 Android service state。
  UI 不直接管理 root/VPP process。
- 策略更新采用 immutable compiled snapshot、epoch/generation，以及显式
  stage/commit/rollback。UI 不发送大量逐条 packet rule mutation。
- 在并发安全独立证明之前，由一个持久 VAPI client 串行执行命令。重连替换 stale opaque
  handle；完成状态未知的 in-flight mutation 不得自动重放。
- 每个 queue 和 cache 都必须有界且可观测，之后才能称为 production-shaped。
- POC artifact 在通过准入门之前不进入正式模块。

尚未对齐的是：这些原则以什么进程拓扑落地，以及正式 Packet Capture Adapter 的契约。

## 4. 当前仓库地图

| 区域 | 当前职责 | 成熟度 |
| --- | --- | --- |
| `src/main`、`src/control/vnext`、`src/datapath/nfqueue` | active reconstructed root daemon；负责 shutdown、`HELLO`/`RESETALL`/`QUIT`、原生双栈 NFQUEUE hook/listener 和 pass-through verdict。 | active pre-SNORT-12 基线；不是 VPP。 |
| `src/core/packet`、`src/core/metrics`、`src/app` | mainline reconstruction 后保留的小型基础 helper。 | active helper；没有 active `PacketFacts`、policy、CT、diagnostics 或 telemetry pipeline。 |
| `archive/current-head/src/` | 旧 feature-rich daemon。 | 迁移参考；禁止整体恢复。 |
| `experiments/vpp-nfq-poc/overlay/` | Android VPP platform overlay、`tun_poc`、`nfqueue_poc`。 | throwaway POC code。 |
| `experiments/vpp-nfq-poc/android/vpn-lite/` | 包含 VpnService、VPP/HEV child lifecycle、fd broker、JNI/Rust/VAPI probe 和 root RuntimeService 实验的 debug APK。 | 测试 harness；不是产品 app。 |
| `experiments/vpp-nfq-poc/scripts/` | 可重复的 Android build、stage、deploy、lifecycle、traffic 和 audit harness。 | 证据工具；后续只能选择性迁移。 |
| `experiments/vpp-nfq-poc/results/` | 真机原始结果，包括 `SAKAMOTO-32` 正式 run。 | 证据，不是契约。 |
| Plane `SAKAMOTO-2..31` | 已完成的 Android POC。 | Done。 |
| Plane `SAKAMOTO-32` | VPP experimental NFQUEUE plugin audit/hardening。 | Backlog；继续 POC 暂停，生产准入 HOLD。 |

active daemon 明确停在 SNORT-12 之前。当前 executable 不包含 bounded packet copy、
`PacketFacts`、policy cache、Conntrack、Traffic Windows、Packet Diagnostics、IPRULES
Authoring、PerfMetrics、Flow Telemetry 或 DNS/domain policy。接口规格中对应章节是目标契约，
不是当前 executable 的能力声明。

## 5. 按演变顺序整理的技术事实

### 5.1 VPP 在 Android 上编译和启动

最初的表现和失败：

1. upstream VPP v26.02 直接拒绝 `CMAKE_SYSTEM_NAME=Android`，报
   `Unsupported system: Android`。
2. 允许 Android 进入 Linux-like cross target 后，连续暴露 bionic 差异：缺少 robust
   mutex API、`dlmallinfo` 形态不同、缺少 `shm_open`/`shm_unlink`、错误依赖
   `rt`/`pthread`、BSD helper 不可用、thread affinity API 不同。
3. 第一次真机 daemon startup 在 reassembly process 附近耗尽默认 32 KiB VLIB
   process stack。
4. 第一次 push 直接写 root 创建的设备目录，ADB shell 无写权限。
5. NDK sysroot 不提供所需 userspace netfilter 库，导致 `nfqueue_poc` 最初没有参与构建。

POC 中的解决办法：

- 使用可重复的 Android CMake overlay，不手工修改 fetched VPP tree。
- 增加 bionic compatibility shim，并把 Android SVM 名称映射到
  `/data/local/tmp/vpp-shm` 的 file-backed 路径，使构建和 POC IPC 可以继续。
- Android VLIB process stack 提高到 256 KiB。
- 早期 affinity no-op shim 后来被真实 scheduler affinity 实现替换，并在 VPP
  main/worker thread 上验证。
- 将 `libnfnetlink`、`libnetfilter_queue` 源码接入 Android plugin build。
- staging/push 改为从 ADB 可写路径逐文件复制。
- `plugin_path` 作为 VPP startup 参数显式传入，不依赖 host 安装目录布局。

最后确定的边界：

- VPP v26.02 在 root 与普通 app UID 两种 POC 布局中均能启动，并可通过 `vppctl` 或
  binary API 控制。
- 若干 compatibility patch 只是 POC enabler，不是已经审核的产品语义。尤其是 robust
  mutex owner-death、SVM 存储/清理和完整 Android platform patch set，发版前必须逐行
  评审并建立 upstream compatibility 策略。

主要证据：`experiments/vpp-nfq-poc/ANDROID_EXPERIMENT_LOG.md`、
`ANDROID_ARM_MULTIARCH_MEMO.md`。

### 5.2 Runtime 体积收缩

有效裁剪从已经通过 Android 3C VPP/TUN/HEV datapath 的 full runtime 开始。曾尝试去掉
`libvnet` 的 `vpp_lite`，虽然 stage 约 11 MB，但无法稳定启动所需 datapath，因此只保留为
理论下限，未作为主线。

| 步骤 | Stage 体积 | 结果 |
| --- | ---: | --- |
| debug/O0-like stripped full runtime | 186 MB | Android datapath 通过，但不可接受。 |
| release build | 29 MB | datapath 通过；证明原体积主要来自 build mode，不是都来自必要功能。 |
| release + 关闭 ARM multiarch variants | 11 MB | datapath 通过；APK 约 3.6 MB。 |
| release + no-multiarch + 移除 IPsec sources | 9.4 MB | datapath 通过；APK 约 3.3 MB；root minimal RSS 约 102 MB。 |

需要保留的解释：

- no-multiarch 移除的是 Cortex-A72、Neoverse 等 server-oriented 重复 variant。VPP
  v26.02 本身没有 Pixel 6a A55/A76/X1 的 per-worker variant，因此不是关闭已有的
  手机 core 专用路径。
- AArch64 baseline、NEON 和 CRC codegen 仍保留。
- VPP multiarch 是 process-global startup selection，不会随 big.LITTLE worker 当前所在
  core 切换实现。
- no-IPsec 只使 `libvnet.so` 再减少约 1.06 MB；它有收益，但不是最大降幅来源。
- host stack/session/TCP、L2/MPLS/device、reassembly、GSO、API/test 等尚未批准继续裁。
  这些是功能和维护决策，不是单纯的体积开关。

主要证据：`ANDROID_TRIM_EXPERIMENT_LOG.md` 的 Round 4A-4C 与 section 20。

### 5.3 无流量 CPU 收缩

演变过程：

1. 早期 full/minimal Android VPP 约 7%，仅加载但不 enable NFQUEUE plugin 也相近，
   因此不是 NFQUEUE fd busy loop。
2. 去掉错误的固定 poll sleep 路径、禁用不需要的默认 VNET process timer 后，仍有约
   1.3%-1.7%。
3. 插桩显示几乎没有真实 expired event，CPU 主要消耗在通用 VLIB timer wheel 与
   file-poll maintenance。
4. Android/minimal timer wheel 从 10 us 粗化到 1 ms 是主降幅；允许 epoll 最长睡眠
   1000 ms 进一步降低 wakeup。
5. 中间曾试过把所有正的短 timeout 强行抬到 1000 ms。该方法会延迟真实 timer，已明确
   否决并移除。

当前 opt-in profile：

- 8 个当前不需要的默认 process timer 改为 event wait；
- `VLIB_TW_TICKS_PER_SECOND` 从 `1e5` 调到 `1e3`；
- `vlib_file_poll()` 保留正常 computed timeout，只把最大 sleep 从 10 ms 放宽到
  1000 ms。

正式短采样结果：

- root minimal VPP：60 秒 tick-delta 平均约 0.047%；
- NFQUEUE fd enabled 且无流量：对应样本约 0.016%；
- NFQUEUE accept/drop 与 VpnService -> VPP -> HEV smoke 均继续通过。

这证明了明确的因果路径，但不是发版功耗结论。timer precision、policy/CT timer、active
latency、throughput、长时间 screen-off、thermal 和 battery 必须在同一个预算下重新验收，
在此之前 profile 只能 opt-in。

主要证据：`ANDROID_TRIM_EXPERIMENT_LOG.md` section 12-18。

### 5.4 普通 app UID 的 VpnService/TUN 路径

`SAKAMOTO-2..11` 与早期 Experiment 33-89 已确定：

- VpnService TUN -> packaged VPP `tun_poc` -> HEV -> SOCKS5 可以在
  `untrusted_app` 身份运行，app/VPP/HEV 不调用 `su`。
- HEV 的 upstream fd 在 connect 前交给 Android parent，真实
  `VpnService.protect(fd)` 成功；故意让 protect 失败时会在 upstream connect 前终止。
- 50 次受控 start/traffic/stop 未观察到 fd/RSS 趋势或 process/TUN/rule residue。
- proxy refusal、短时 upstream blackhole、Wi-Fi off/on 后无需重装或手工清理即可恢复。
- 模拟 USB 断电后进入 600 秒 Doze，app/VPP/HEV 保持，唤醒后流量恢复。
- 6 轮各 300 秒 TCP/UDP 的进程和资源稳定性通过；background TCP p95/p99 仍约 4 秒，
  因此 release latency HOLD。
- VPP 可以解析 IPv4/IPv6 TCP/UDP tuple，向 Android 查询 owner UID，并在 VPP worker
  内保留 verdict ownership。lookup 失败必须保持 `uidKnown=false`。
- TUN fd callback 当前在 VPP thread 0 执行。扩展 worker 必须显式 software handoff。
  worker-to-worker redirect 与 Android UID verdict 只证明可行性，未证明 ordering、
  backpressure 和性能。
- Android APK 已打包 generated VAPI library 与稳定形状的 C shim；Android Rust
  staticlib 可通过 app-private VPP `socksvr` 做 typed status 和 POC policy mutation。
- VPP 退出后 stale persistent client 会失败，必须创建 fresh handle 重连。这支持
  “unknown mutation 不盲目 replay”的控制原则。

证据限制：

- 设备本身已经 root 且 bootloader unlocked。结论证明运行身份和“不调用 su”，不等于
  never-rooted、bootloader-locked 发版设备。
- SOCKS endpoint 和大量流量是受控 fixture，不是完整公网 relay 认证。
- 早期部分 owner gate/cache 在 VPP 之前做判决，已明确降级。只有后续 VPP-internal
  experiment 支持“VPP 拥有 verdict”的结论。
- 仍没有 Tauri command surface、production owner cache、compiled policy snapshot、
  长期公网负载和 release HEV lifecycle。

主要证据：`ANDROID_VPN_EXPERIMENT_LOG.md`、`POC_STATUS.md`、
`ANDROID_POC_EXECUTION_JOURNAL.md`。

### 5.5 Root APK/RuntimeService 路径

`SAKAMOTO-12..31` 操作的是 active native daemon，不是 VPP。必须按时间看，因为多个早期
HOLD 已被后续 POC 关闭：

| 问题 | 首次表现 | 当前结果 |
| --- | --- | --- |
| APK-native artifact 与 root launch | RuntimeService 打包 `libsucre_snortd.so`，经 KernelSU 启动，并检查 HELLO ABI/build/capabilities。 | debug POC GO。 |
| app force-stop 后 daemon 孤儿化 | 首版 daemon 被 reparent 到 PID 1 后继续运行。 | parent-death guard 与 reparent monitor 现可使其退出；S13 孤儿问题不是当前 blocker。 |
| parent-death 后 iptables hook 残留 | process/socket 退出，chain 仍在。 | daemon shutdown 与 supervisor cleanup 现可删除双栈 hook；S14 HOLD 被 S15/S22 关闭。 |
| SIGKILL 无法执行 destructor | daemon/socket 消失，NFQUEUE hook 残留。 | RuntimeService supervisor 观察非预期退出并执行特权 hook cleanup；S17 原始失败由 S22 收口。 |
| background service 不是 foreground | 首轮 HOME/锁屏存活，但 `startForegroundCount=0`。 | S21/S31 已实现并验证 foreground service、notification channel、`specialUse` 和 notification denial。 |
| artifact ABI/protocol mismatch | wrong ABI、HELLO mismatch fail closed；伪造非空 build ID 可通过。 | APK 携带 expected daemon SHA-256，并在 root launch 前校验；解决 accidental/partial mismatch，不解决 APK signing compromise。 |
| root permission denied | app UID 无法执行 `su`，startup 失败。 | 明确 fail result、无 residue、恢复授权后 fresh recovery 通过。 |
| KernelSU live revocation | 不重启修改 allow byte，已缓存授权没有立即撤销。 | 已知平台边界；运行中撤权 UX/策略尚未决定。 |
| crash/restart | SIGABRT 被观察并完成清理；5 秒内不自动重启。 | cleanup 已证实；自动 restart/backoff policy 有意留待设计。 |

另外通过了 5 次重复 lifecycle、短 Doze、同 debug 签名 upgrade/rollback、直接 kill app
process、reboot residue/recovery、alternate-signature update rejection，以及 notification
permission denial。

证据限制：

- 这是显式 KernelSU 授权的 debug harness，不是 release root onboarding/permission UX。
- release signing lineage/key rotation、OEM process management、长 Doze、crash loop/backoff、
  tombstone、interrupted install、data migration 和更多设备均未覆盖。
- 最重要的是，被监督的 artifact 是当前 daemon。上述 POC 不自动证明 VPP、VPP plugin、
  HEV 以及它们组合后的 cleanup order。

主要证据：`ANDROID_POC_EXECUTION_JOURNAL.md` 与 `POC_STATUS.md` 的
SAKAMOTO-12..31。

### 5.6 实验性 VPP NFQUEUE plugin 审核

`SAKAMOTO-32` 正式 Android run 使用 VPP v26.02 commit `9258530f...`、9.4 MB
stage，并在同一 Pixel 6a 上模拟 USB 断电。

已通过：

- `vpp`、`vppctl`、`nfqueue_poc_plugin` build/load；
- IPv4/IPv6 INPUT/OUTPUT ACCEPT 与 DROP；
- IPv4/IPv6 OUTPUT 各 20 包 50% mixed verdict，均为 10 accept/10 drop；
- active plugin disable 后 kernel queue 立即释放；
- 最终 VPP process、queue、iptables/NFQUEUE residue 均为 0；
- copy range 从 `0xffff` full copy 改为 512-byte bounded prefix；
- `ENOBUFS` 不再在 read-ready callback 内连续 spin；
- disabled/enabled 短 idle 样本没有出现 NFQUEUE busy loop。

未关闭的 finding：

| Finding | 阻塞原因 |
| --- | --- |
| callback 内同步 `fprintf` 且每包 `fflush` | verdict hot path 存在 blocking I/O；必须移除或改成 bounded async telemetry。 |
| missing packet ID 没有 verdict strategy | packet 可能没有明确结论；必须定义 offline/fail-open/fail-closed 和 fault injection。 |
| copied prefix 被当成 payload length | 没有 original packet length 与 truncation，parser/telemetry 语义不完整。 |
| 一个 instance 只绑定一个 family、一个 queue | 正式双栈测试通过重启 instance 完成，不证明单个产品 runtime 的 dual-stack/multi-queue concurrency。 |
| IPv6 parser 假定固定 header | extension header、malformed、truncated L4 不符合目标 parser-status contract。 |
| 没有 overload/lifecycle envelope | 缺 backlog/ENOBUFS recovery、exactly-one verdict、crash/reboot cleanup、verdict p50/p95/p99、持续 CPU/power/thermal。 |
| provenance/compatibility 未关闭 | experimental/deprecated plugin 与本地 platform patch 需要 version、license、API/ABI 和维护矩阵。 |

结论：Android 基础 verdict 是 Conditional-Go；正式 Packet Capture Adapter 是
No-Go/HOLD。原始证据位于
`experiments/vpp-nfq-poc/results/sakamoto-32-nfqueue-plugin-audit-20260719-141956/`。

## 6. VPP 迁移后仍应保留的 datapath 决策

以下契约约束 VPP 设计，不能随着当前 raw NFQUEUE 实现一起丢弃：

- runtime lifecycle 与 component gate 分离。`block.enabled` 之类策略开关不负责启停
  dataplane process。
- Packet Capture Adapter 负责平台 ingress metadata 和 normalized packet boundary。
  NFQUEUE、TUN 是 Adapter，不是 policy engine。
- packet processor 接收 original L3 bytes 与 bounded copied-prefix 语义。
  `copiedPrefixBytes` 不能冒充 original packet length。
- `PacketFacts` 是 packet-local、轻量、once-parse，只包含 normalized L3/L4 fact 与 parser
  status，不包含 CT/DPI/domain handle。
- 无有效 L3 envelope 时 fail open，且不生成伪记录。L3 有效但 L4 不可用时保留
  `l4Status`、`portsAvailable=false` 和 original-byte accounting。
- expensive fact 由 coarse hot-path capability bit 按 consumer 驱动。
- verdict stage order 决定正确性；NFQUEUE queue/thread topology 不决定正确性。
- CT 是后续显式 consumer，不是 basic packet rule 或 Traffic Windows 的前置条件。
  NFQUEUE topology 不能成为 CT correctness guarantee。
- normal telemetry 使用 bounded record；focused Packet Diagnostics 是独立显式 session。
  两者都不能阻塞 packet verdict。
- Authoring 使用 Draft -> Commit -> Apply -> Checkpoint 加 Runtime Snapshot，不恢复旧
  direct `IPRULES.APPLY`。

## 7. 当前最先要解决的架构冲突

仓库中有两条都有效、但尚未连接的基线：

- reconstructed daemon 已定义清晰的 SNORT-10 module boundary 和 Android lifecycle，
  但 dataplane 是 raw NFQUEUE，active feature set 也被刻意压到最小；
- VPP POC 已证明 common dataplane 和 typed control 方向可行，但仍是 overlay code，
  platform/Adapter 语义未获批准。

第一个设计决定是 production process topology。实际只有三个候选：

### Option A：RuntimeService 监督 VPP，VPP 内使用平台 Adapter

RuntimeService 监督一个 VPP process。root profile 加载 production NFQUEUE Adapter；
VPN profile 加载 TUN Adapter。二者进入同一个 Sakamoto VPP graph 与 policy engine。
Tauri/Rust 经版本化 shim/VAPI 控制。

它最符合已经对齐的产品方向，也复用了最多 POC 证据。但仍需明确 privilege mode、
VPP/HEV process ownership、Android socket/file、root 与 app-UID packaging，以及一个 APK
如何提供两种 deployment profile。

### Option B：当前 daemon 拥有 ingress，再把 packet 交给 VPP

现有 root daemon 保留 NFQUEUE/lifecycle ownership，把 packet work 交给独立 VPP process
或 embedded graph。

优点是保留更多现有 daemon；代价是 packet handoff、copy/backpressure、两个 health
domain，以及 exactly-one-verdict coordination。当前没有 POC 证明这条边界。只有存在明确的
privilege/isolation 必要性时才应选择。

### Option C：保留两套独立 dataplane

当前 daemon 继续负责 root/NFQUEUE，VPP 只负责 VpnService/TUN。

短期迁移最少，但会复制 policy、parser、metrics、control 和 correctness 工作，也违背
“基于 VPP 的 Linux/Android 统一基础”目标。它只能是过渡 fallback，不应是默认架构。

现有证据指向 Option A，但这只是下一轮讨论的工作候选，不是本文新接受的决策。

## 8. 进入实现计划前的设计顺序

下一轮按以下依赖顺序做决定，不再从某个独立 POC 或实现 ticket 开始。

### D0. Deployment 与 process topology

确定 Option A/B/C；定义 Android root/VPN profile、process UID、executable/library
packaging、socket、writable directory、HEV placement 和唯一 lifecycle owner。

输出：一张 process/privilege 图，以及 startup/stop/crash state machine。

### D1. Packet Capture Adapter contract

定义 NFQUEUE/TUN ingress metadata、original length 与 copied prefix、parser status、
exactly-one verdict ownership、missing-ID、queue offline、fail-open/fail-closed 和 Adapter
health。

输出：不依赖 libnetfilter_queue 或 VPP callback 内部类型的 C/C++ contract，以及
malformed/truncated 示例。

### D2. VPP graph 与 threading model

定义 callback-to-node、buffer allocation、flow sharding、ordering、dual-stack/multi-queue、
bounded frame queue、backpressure、worker handoff 和 teardown barrier。同步 UID lookup、
packet logging 均不得在无预算时停留在 hot path。

输出：node graph、ownership table、queue capacity、overload policy 和 counters。

### D3. Control、policy 与 health

定义 HELLO/status、compiled policy stage/commit/rollback、epoch reconciliation、runtime
health、Adapter health 和 conservative reconnect 的 versioned C ABI/VAPI。明确哪些
control-vNext concept 仍是产品 contract，哪些改为 VPP API message。

输出：version handshake、command/error table、policy snapshot schema、stale/in-flight
recovery rule。

### D4. Android lifecycle 与 security

把已证明的 RuntimeService pattern 映射到 VPP/HEV：artifact hash、signing trust、
KernelSU authorization、foreground service、parent death、supervisor cleanup、crash
policy、reboot、upgrade/rollback、socket/SVM cleanup 和 notification。

输出：lifecycle ownership matrix 与 release threat/failure model。

### D5. Module migration 与 admission gate

只有 D0-D4 完成后，才把 reconstructed module order 映射到 VPP：

1. Packet Capture Adapter 与 bounded PacketFacts foundation。
2. Hot-path capability 与 policy cache。
3. basic dual-stack IPRULES verdict slice 与 compiled policy authoring。
4. CT A++ 作为后续显式 consumer。
5. Traffic Windows、Diagnostics、PerfMetrics、Flow Telemetry。
6. UID/IP control 和 lifecycle 稳定后再恢复 DNS/domain。

同时定义 size、RSS、idle/active CPU、timer precision、verdict latency、throughput、packet
loss、queue occupancy、power、thermal 和 recovery budget。Plane implementation ticket
应从已接受设计生成，不从旧 POC 清单直接生成。

## 9. 不得从 POC 推导出的结论

- Android build 成功不代表当前 VPP platform overlay 已通过产品审核。
- 9.4 MB stage 不代表可以继续任意裁功能，也不是最终 installed APK size。
- 0.05% 短 idle 不代表 battery life，也不证明 1 ms timer 对 CT/policy/active traffic 安全。
- rooted phone 上 app UID 不调用 `su`，不等于 never-rooted release device 通过。
- 基础 NFQUEUE ACCEPT/DROP 不代表 experimental plugin 可作为 production Adapter。
- 通过重启 single-family queue instance 完成双栈 case，不等于 dual-stack/multi-queue
  runtime 成立。
- RuntimeService 对当前 daemon 的 cleanup 结论，不会自动覆盖 VPP/HEV。
- POC direct owner-policy knob 不定义 compiled policy contract。
- archived daemon 不是实现计划。
- Linux/Docker 可以辅助 build 和源码诊断，但不能替代当前 Android 功能证据要求。

## 10. 新对话的第一个目标

不要先运行新 POC、拆 ticket 或修改 production code。先选择并完整定义 D0。建议从
Option A 作为待证伪候选开始：

> 一个由 Android RuntimeService 监督的 VPP runtime；root NFQUEUE Adapter 与 app-UID
> TUN Adapter 进入同一个 Sakamoto VPP packet graph；Tauri/Rust 通过版本化 C ABI/VAPI
> 作为产品 control plane；HEV 是被显式监督的 VPN transport dependency。

第一轮讨论要用 privilege separation、process death、packaging、control reconnect、
exactly-one verdict 和双 profile 代码共享去挑战或修正它。D0 接受后先写入
`docs/decisions/`，再进入 D1。

## 11. 新对话启动提示词

```text
我们继续 Sakamoto 的 Android/VPP 架构工作。先依次阅读：

1. docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md
2. CONTEXT.md
3. docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md
4. docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md
5. docs/INTERFACE_SPECIFICATION.md

Plane 是 tracker，使用 plane-ops，不使用 Plane MCP。SAKAMOTO-2..31 是已完成的 Android
POC；SAKAMOTO-32 是未完成的 production-admission audit，不能据此把 nfqueue_poc 当成
产品代码。Linux 暂缓，Android 是近期发版优先平台。

本轮不要运行新 POC、创建 implementation ticket 或修改 production code。先处理设计阶段
D0：比较交接文档中的三种 process topology，重点挑战 Option A，并给出具体的 Android
process、privilege、packaging、startup、stop、crash、recovery 模型。回答时严格区分：
已证明事实、已接受决策、尚未证明的假设、本轮新决策。
```
