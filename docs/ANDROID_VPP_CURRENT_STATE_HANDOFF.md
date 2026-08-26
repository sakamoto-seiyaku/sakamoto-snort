# Android / VPP 当前现状与架构交接

状态：当前权威交接文档；Android/VPP 基线 2026-07-19，handoff POC 决策更新于
2026-08-10，protocol-identification pre-decision 证据更新于 2026-08-12，VPN Direct Egress
fixed-spec 与 evidence frontier 更新于 2026-08-14。

范围：Android 优先的产品基础、VPP 引入、root/NFQUEUE 与
VpnService/TUN 两种运行路径。Linux 的实现和功能验证暂缓，除非后续设计决策明确恢复。

证据基线：分支 `dev/vpp-base`，提交 `c572874`。本文只总结事实和边界，不把 POC
代码提升为产品代码。

2026-08-14 权威说明：本文较早章节中的 VPP/TUN/HEV child、SOCK_SEQPACKET、SOCKS fixture、
单一 HEV owner 和 HEV ownership-transfer completion 描述只保留为当时运行证据。当前目标由
ADR-0006、ADR-0007、SAKAMOTO-103..113 与 SAKAMOTO-114..117 frontier 约束：一个
RuntimeService-supervised VPP Runtime、C-only VPP Packet I/O Adapter、独立 VPN Flow Stack Packet
Boundary，以及由真实 POC 选择的 instance isolation、state partition、buffer/copy 和执行拓扑。

2026-08-26 POC 更新：Android VPN E2 仍未升级为可直接导入主栈的完成态。F074 已关闭
OI3/VPP worker idle CPU hotspot；S231--S236 把 Direct/OI3 foreground/device-state
count-bounded CPU evidence 推进到 count512。随后 S237 发现一个有效低 CPU 的 count64
same-owner deferred SYN p99 tail，S237--S244 通过 owner-local re-arm drive 修正该 POC seam；
S244 完整 Direct/OI3 count64 repeat 通过，OI3 p99 为 `65/76/70/77/82ms`。S241 的一次
VPP initial worker barrier abort 被记录为低频 repeat-start lifecycle risk，S243/S244 未复现。
当前主栈含义仍是：可以把 same-owner re-arm 本地驱动作为导入设计输入，但不能把 throwaway
POC runner/APK 直接导入产品；正式导入仍受 EG-17 的 HEV-baseline disposition、formal p99/tail
tolerance、broader throughput/capacity、thermal/power/soak gates 约束。S245
`experiments/vpp-nfq-poc/S245_ANDROID_VPN_MAIN_STACK_IMPORT_READINESS.md`
进一步把导入边界固定为：先导入 Flow Stack Boundary Interface、host fake 和 same-owner
re-arm invariant，不导入 OI3/vpn-lite/runner 代码。随后首个主栈切片已落到
`src/datapath/tun/VpnFlowStackBoundary.*` 和
`tests/host/vpn_flow_stack_boundary_tests.cpp`：same-owner deferred re-arm 现在有 host
regression 固定为本地有界 drive，不通过 cross-owner wake 自投递。第二个切片继续把
`FlowGraphIngressResult.acceptedOwner` 与
`VpnTunFlowAdapter::lastAcceptedPacketHandoff()` 接上，使 VPN egress 后续可直接消费 shared graph
产生的 canonical owner、facts、policy revision 和 TUN/FlowStack provenance，不需要在 VPN transport
adapter 里重新 parse/hash。第三个切片把现有 transport-fd outbound 占位实现收进
`VpnFdFlowStackBoundary`，`VpnTunFdRuntime` 改为通过 `VpnFlowStackAdmissionRequest` 入栈；
fd 缺失和 fd backpressure 仍分别记录为 transport unsupported/failed，不伪装成 policy drop。第四个
切片继续把 transport-return poll/read 路径收进 `VpnFlowStackBoundary::receiveReturnPacket()`；
`VpnTunFdRuntime` 不再直接读取 `transportFd_`，而是从 Flow Stack seam 获取回包，再通过共享
`VpnTunFlowAdapter` 图路径检查后写回 TUN。当前仍未导入 HEV/lwIP/OI3 产品实现；下一步应在该
Interface 后替换 fd-backed 占位 Adapter。

后续产品与架构决策（2026-07-19）：

- 第一目标已收敛为 `docs/product/ANDROID_L4_PRODUCT_PLAN.md` 中的 Android L4 Product
  Release；Linux 不阻塞该版本；
- Root/VPN 仍是同一产品的互斥 Runtime Profile；
- production process topology 已确认采用 Option A：Android RuntimeService 监督当前
  Runtime Profile 唯一的 VPP runtime；root 加载 NFQUEUE Adapter，VPN 加载 TUN Adapter，
  两者共享同一 Sakamoto VPP graph、worker runtime 与 policy engine，不保留平行数据面；
- ADR-0006 已用 P0-P5 证据取代逐包 Rust–VPP–Rust bridge：NFQUEUE/TUN platform packet I/O、
  live-buffer ownership、canonical handoff、origin-lane completion 与 native buffer return 留在
  当前 pinned VPP 的 C-only Packet I/O Adapter plugin；VPN post-policy transport 经过独立的 VPN
  Flow Stack Packet Boundary。Rust 只保留 lifecycle、configuration、policy snapshot、status、
  diagnostics 与版本化 compatibility ABI；
- VPP flow runtime 采用 `docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md` 的 per-worker
  single-owner 模型；Worker Layout 与 per-worker pool/cache capacity 启动时固定。普通报文由
  Primary Software Distribution 严格按包含 IP protocol 的 direction-independent canonical
  五元组第一次直接投递最终 owner，正反包保证同 worker，UID 不参与分流；Owner Guard 只允许
  一次 Corrective Handoff，第二次 mismatch 丢弃。IP 分片参考 fork 的 fragment co-location、
  bounded reassembly 与重组后最终 owner handoff，该阶段转换不属于纠偏；
- 第二阶段以 libprotoident Protocol Identification Release 为阶段性目标，采用
  Recognize-then-enforce，不做首包 hold、full CT、stream reassembly 或复杂 QUIC 适配。

本文第 8-11 节保留实现前约束；其中曾描述 Rust Platform I/O Lane、逐包 Completion Frame 跨
Rust ABI 和 Rust buffer-return wrapper 的段落已由 ADR-0006 取代，不再是当前 contract。

### 2026-08-02 handoff POC 收口

- P2：multi-NFQUEUE 与 kernel `queue-balance` 作为 Initial Placement **GO（scoped）**。Pixel 6a
  address-diverse UDP 的 canonical mismatch 约为 Q2 `50.40%`、Q4 `51.18%`；因此 queue balance
  不能替代 canonical FlowOwner，也不能保证省掉多数软件分流。port-only 变化还产生全流量单 queue
  反例，elephant/mice 则证明 flow balance 不等于 packet/work balance。
- P3：W2/Q2 bounded canonical-owner processing + origin-lane verdict return 的 zero-error correctness
  **GO（scoped）**。正常、overload、stale/duplicate 与 lifecycle ledger 均闭合；真实
  `nfq_set_verdict()` failure 后的 FAILED debt settlement 在当时仍未证明。后续 SAKAMOTO-77
  已补齐 exactly-once 三态 outcome、definite rejection、UNKNOWN、no-retry 与 debt/buffer
  settlement 的 host POC 证据；该证据不改写本节对 2026-08-02 P3 当时结论的历史记录。
- P4：选择 hybrid：owner-local packet 留在 origin fast path，mismatch 才进入 bounded canonical
  processing 与 Canonical Return。shared-TX/trylock direct-hit median 仅约 `52.6%` mixed、`60.9%`
  all-remote，且 CPU/context 更差，正式拒绝。pool128 只证明 credit depth 需要定容，不是产品常量。
- P5 的早期诊断曾观察到 sleep-confirmed p99 `505332→282672` cycles、约 `44.06%` 改善；这只是
  机制方向证据，不是产品收益结论。diagnostics-disabled final patch 当时已经未通过 idle CPU gate。
- P6d 最终正式 campaign-21 在 Pixel 6a / Android 16/API 36 上完成 32/32 个有效 arms，但协议结果为
  **non-GO**：idle C-A 的单侧 95% 上界 `+0.091950 pp`（门槛 `<=+0.05 pp`）失败，sleep-confirmed
  p99 改善下界 `-3.110%`（门槛 `>=20%`）失败；p50 回归上界约 `+0.054%` 通过。功耗没有外部功率仪，
  仍为 **INCONCLUSIVE**。逐臂数据、环境审计、恢复记录和 hash 见
  `experiments/vpp-nfq-poc/P6_CONDITIONAL_WAKE_EXPERIMENT_JOURNAL.md` 及其 campaign-21 result directory。
- 因此当前 conditional-wake patch 和 mode3 persistent wake 不进入产品实现，也不再给旧 artifact 追加
  样本。只有新的机制假设、新 hashed artifact 和独立预注册协议，才可能重新开启这条研究路径。

## 1. 本文怎么用

新对话先读本文，再按需读实验流水账。发生冲突时，权威顺序如下：

1. `docs/decisions/` 中已接受的设计决策。
2. `docs/INTERFACE_SPECIFICATION.md` 中的当前契约，以及 `CONTEXT.md` 中的术语。
3. 本文与 `docs/IMPLEMENTATION_ROADMAP.md` 中的当前状态。
4. Plane 中的开放工作状态。当前相关项包括 Android L4/Protocol 主线
   `SAKAMOTO-59`、`SAKAMOTO-61`，以及已 Done 的 POC 证据链
   `SAKAMOTO-72..81`。
5. `experiments/vpp-nfq-poc/` 中的实验过程和证据。
6. `archive/current-head/`、`archive/openspec/` 中的历史材料。

Plane `SAKAMOTO-1` 是最初的高影响 POC 计划。它仍包含“继续大量 POC”和“部分问题先在
Linux 验证”的旧顺序，已不再代表下一阶段执行方式。`SAKAMOTO-32` 是历史 VPP
experimental NFQUEUE plugin audit；后续 `SAKAMOTO-72..81` 已把 live-buffer ownership
POC 收口并返回主设计流，但仍不等同于完成 `SAKAMOTO-68` Gate/L4 产品切片。

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
| `experiments/vpp-nfq-poc/results/` | 真机原始结果，包括 `SAKAMOTO-32` 正式 run 与 `SAKAMOTO-80` Android live-buffer parity run。 | 证据，不是契约。 |
| Plane `SAKAMOTO-2..31` | 已完成的 Android POC。 | Done。 |
| Plane `SAKAMOTO-32` | VPP experimental NFQUEUE plugin audit/hardening。 | Done；历史 audit 证据。 |
| Plane `SAKAMOTO-72..81` | VPP-native NFQUEUE live-buffer ownership closure POC。 | Done；返回主设计流的 POC 证据，不是产品实现。 |

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

> 以上是历史 POC 证据；其中 512-byte bounded-prefix/callback storage 结果不属于 Functional Closure。当前闭环以 S65、ADR-0003 和 `CONTEXT.md` 为准：完整 L3 直接物化到 VPP-owned storage，解析在共享 VPP graph 内完成。

未关闭的 finding：

| Finding | 阻塞原因 |
| --- | --- |
| callback 内同步 `fprintf` 且每包 `fflush` | verdict hot path 存在 blocking I/O；必须移除或改成 bounded async telemetry。 |
| missing packet ID 没有 verdict strategy | 已定为 Adapter-boundary `INGRESS_IDENTITY_MISSING`：不创建 PacketLease、不进入 VPP、不伪造 completion；依赖 kernel fail-open/bypass，并要求 fault injection 证明有界证据。 |
| copied prefix 被当成 payload length | 没有 original packet length 与 truncation，parser/telemetry 语义不完整。 |
| 一个 instance 只绑定一个 family、一个 queue | 正式双栈测试通过重启 instance 完成，不证明单个产品 runtime 的 dual-stack/multi-queue concurrency。 |
| IPv6 parser 假定固定 header | extension header、malformed、truncated L4 不符合目标 parser-status contract。 |
| 没有 overload/lifecycle envelope | 缺 backlog/ENOBUFS recovery、exactly-one verdict、crash/reboot cleanup、verdict p50/p95/p99、持续 CPU/power/thermal。 |
| provenance/compatibility 未关闭 | experimental/deprecated plugin 与本地 platform patch 需要 version、license、API/ABI 和维护矩阵。 |

结论：Android 基础 verdict 是 Conditional-Go；正式 Packet Capture Adapter 是
No-Go/HOLD。原始证据位于
`experiments/vpp-nfq-poc/results/sakamoto-32-nfqueue-plugin-audit-20260719-141956/`。

### 5.7 SAKAMOTO-72..81 live-buffer ownership POC 收口

`SAKAMOTO-72` 是 parent closure ticket；`SAKAMOTO-73..81` 已全部 Done。权威
return handoff 是 `experiments/vpp-nfq-poc/SAKAMOTO-81_HANDOFF.md`，并引用
`SAKAMOTO-73..79` handoff、`SAKAMOTO-80` Android result directory 与 LLDB repair
evidence。该 POC 验证的是 `SAKAMOTO-68` 的前置 ownership 机制，不实现正式
Network Gate/L4、Debug Activity、VPN parity、release packaging 或产品容量 gate。

五项 closure 结论：

| Obligation | Result | 当前含义 |
| --- | --- | --- |
| Direct materialization | PASS | Host 与 Android 均证明 NFQUEUE datagram 可直接进入 VPP-owned buffer storage，并原地投影 L3 payload。 |
| One-buffer-per-obligation | PARTIAL | 单 message datagram 是一个 live VPP buffer 对一个 admitted obligation；multi-message datagram 采用 admission 前安全拒绝，不支持一个 buffer 内多 obligation 的 no-copy materialization。 |
| Worker handoff | PASS | host 证明 owner-local/remote，Android 证明真实 remote mismatch；handoff 只传 buffer index 与 inline metadata。 |
| Origin completion | PASS | origin lane 使用原 generation/packet id 执行唯一 verdict attempt；duplicate/stale token 只记 ledger，不产生第二次 physical attempt。 |
| Native return | PASS | buffer 保持 live 直到 completion classification，并通过 VPP native lifecycle 归还；clean/fresh restart path 最终 residue 为零。 |

必须随设计返回的限制：

- Android `SAKAMOTO-80` final evidence 使用 `buffer-data-size 2048`，只证明 measured
  ICMP envelopes 适配 Android 实测 buffer，不证明 Android 9000-byte capacity。
- host pinned-VPP POC 证明了 9000-byte patch/envelope path；production Android buffer
  size、pool count、credit depth 与 Fail-Open Reserve 数量仍必须由 release/capacity
  matrix 决定。
- process death 是 explicit live-obligation fault evidence 加 external cleanup/fresh
  restart，不是 clean in-process teardown。

## 6. VPP 迁移后仍应保留的 datapath 决策

以下契约约束 VPP 设计，不能随着当前 raw NFQUEUE 实现一起丢弃：

- runtime lifecycle 与 component gate 分离。`block.enabled` 之类策略开关不负责启停
  dataplane process。
- Packet Capture Adapter 负责平台 ingress metadata 和 normalized packet boundary。
  NFQUEUE、TUN 是 Adapter，不是 policy engine。
- 当前 Adapter contract 携带 `originalLength`、`capturedLength` 与完整 received L3 span；
  Functional Closure 不截断 packet。bounded-prefix truncation 仅是需要重新测量和显式决策的未来
  优化，历史 `copiedPrefixBytes` 不能冒充 original packet length 或当前可用 payload。
- Functional Closure 要求 user-space single materialization：TUN 预分配 VPP buffer/chain 并
  直接读取，NFQUEUE 将 netlink datagram 直接接收到 VPP-owned ingress storage 后投影其 L3
  span；不得先进入 Adapter full-packet scratch buffer 再全量复制进 VPP。现有 `tun_poc` 的
  `rx_buf -> clib_memcpy_fast(VPP buffer)` 与 `nfqueue_poc` callback-scoped recv buffer 只算
  POC evidence，不是 production topology。若 platform/API 实证无法直接物化，必须提交 POC、
  measured cost 与新的显式决策，不能静默加入 full copy。
- VPP graph 内的 parsing、policy、observation、Primary Distribution、owner handoff 和一次
  Corrective Handoff 只能移动 buffer index/ownership 与 side metadata，不得 clone、copy 或
  reserialize 全包。已检查的 `stellar_lpi` baseline 直接原地读取 L4 payload，只保存少量派生
  session feature/id/counter，不是 packet-copy exception。fragment/TCP reassembly 或未来
  recognizer 实证需要保留 selected payload 时，必须作为 named bounded exception 定义
  capacity/lifetime budget 并单独测量；不能借此保存无界 packet history。
- normal parser/policy/session/recognition/distribution/observation node 对 packet bytes 只读。
  Root `ACCEPT` 不提交 NFQUEUE replacement payload；VPN policy 将同一份未修改 L3 bytes
  交给 VPN Flow Stack Packet Boundary。只有 named graph node（fragment/TCP reassembly、未来显式 NAT、packet
  synthesis）可获得 mutation authority，并负责 checksum/length/capacity/evidence；普通节点
  临时 mutate-then-restore 也禁止。
- 第一版沿用魔改 `flow_dissector` 的 contiguous-buffer envelope，不提前实现 chain-aware
  parser，也禁止 full-packet linearization。已核实 fork 在 commit `2634598b3a` 将
  `VLIB_BUFFER_DEFAULT_DATA_SIZE` 从 2048 改为 9000；host pinned-VPP POC 已证明
  9000-byte patch/envelope path。Android `SAKAMOTO-80` final evidence 则观察到
  `buffer-data-size 2048`，并只证明 measured ICMP envelopes 适配该 Android buffer。
  Functional Closure 首版不得把 Android 9000-byte capacity 当成已证明事实；VPP
  data size、pool buffer count、RSS、occupancy 与 overload policy 需由目标 Root/VPN
  device release/capacity matrix 决定。VPP pool buffer 按并发 occupancy 循环复用，不随累计流量增长。
  Android Functional Closure 通过目标 Root/VPN 设备验证最终选择的 envelope；VPN 首版将 Android
  TUN MTU 固定为 1500，Flow Stack boundary 的兼容 packet envelope 由真实依赖 POC 选择。1280 仅作为
  未来由具体 device/path 实测问题触发的 IPv6-compatible fallback，dual-stack profile 不支持
  低于 1280 的 1250/1200。当前不动态跟随 underlay MTU。本轮不选择 `NFQA_CFG_F_GSO` policy，也不修改系统
  或网卡 offload。若仍出现超限，长度检查禁止 partial parse，不产生 Policy Verdict；Root 以
  `ACCEPT` fail open，并累计 generic `UNSUPPORTED_CONTIGUOUS_ENVELOPE`。Linux GSO/jumbo 与
  关闭 interface GSO 等 workaround 等真实部署出现问题后再重新决策。
- `PacketFacts` 是 packet-local、轻量、once-parse，只包含 normalized L3/L4 fact 与 parser
  status，不包含 CT/DPI/domain handle。
- 共享 VPP graph 按魔改 VPP 的 validation 语义处理 packet content：无效 L3 envelope
  runtime drop，不生成 Policy Verdict 或伪记录。L3 有效但 L4 不可用或不支持时保留
  `l4Status`、`portsAvailable=false` 和 original-byte accounting；依赖缺失 fact 的
  predicate no-match，其余可求值 stage 继续执行。
- expensive fact 由 coarse hot-path capability bit 按 consumer 驱动。
- verdict stage order 决定正确性；NFQUEUE queue/thread topology 不决定正确性。
- CT 是后续显式 consumer，不是 basic packet rule 或 Traffic Windows 的前置条件。
  NFQUEUE topology 不能成为 CT correctness guarantee。
- normal telemetry 使用 bounded record；focused Packet Diagnostics 是独立显式 session。
  两者都不能阻塞 packet verdict。
- Authoring 使用 Draft -> Commit -> Apply -> Checkpoint 加 Runtime Snapshot，不恢复旧
  direct `IPRULES.APPLY`。

## 7. 已解决的 production process topology

仓库曾有两条都有效、但尚未连接的基线：

- reconstructed daemon 已定义清晰的 SNORT-10 module boundary 和 Android lifecycle，
  但 dataplane 是 raw NFQUEUE，active feature set 也被刻意压到最小；
- VPP POC 已证明 common dataplane 和 typed control 方向可行，但仍是 overlay code，
  platform/Adapter 语义未获批准。

以下三个候选用于记录当时的取舍；当前已接受 Option A，Option B/C 不再是并列候选：

### Option A：RuntimeService 监督 VPP，VPP 内使用平台 Adapter

RuntimeService 监督一个 VPP process。root profile 加载 production NFQUEUE Adapter；
VPN profile 加载 TUN Adapter。二者进入同一个 Sakamoto VPP graph 与 policy engine。
Tauri/Rust 经版本化 shim/VAPI 控制。

它最符合已经对齐的产品方向，也复用了最多 POC 证据。但仍需明确 privilege mode、
VPP Runtime/Flow Stack native packaging、Android socket/file、root 与 app-UID packaging，以及一个 APK
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

Option A 已确认为 production topology：任何时刻只有当前 Runtime Profile 的一个 VPP
runtime；Root/NFQUEUE 与 VPN/TUN 共享 dataplane、worker graph、policy 和 control semantics，
只替换 Packet Capture Adapter、权限与 profile-owned I/O/lifecycle。Option B/C 仅保留为历史
取舍背景，不应在后续讨论中重新作为默认候选。

## 8. 进入实现计划前的设计顺序

下一轮按以下依赖顺序做决定，不再从某个独立 POC 或实现 ticket 开始。

### D0. Deployment 与 process topology（已完成）

已确定 Option A 与唯一 lifecycle owner。Android root/VPN profile 的具体 process UID、
executable/library packaging、socket 与 writable directory 在正式实现切片中收敛；VPN Flow Stack
位于受监督的 VPP Runtime 内，但其 instance/state/thread layout 必须先由 SAKAMOTO-114..117 选择。
这些变量不改变单 VPP Runtime、互斥 profile 和共享 dataplane 的已接受语义。

输出：一张 process/privilege 图，以及 startup/stop/crash state machine。

### D1. Packet Capture Adapter contract

定义 NFQUEUE/TUN ingress metadata、`originalLength`、`capturedLength`、完整 received L3 span、parser status、
exactly-one completion ownership、missing-ID、queue offline、fail-open/fail-closed 和 Adapter
health。NFQUEUE 不提供独立 ACK；`nfq_set_verdict(..., NF_ACCEPT/NF_DROP, ...)` 是 NFQ-defined
terminal operation。一次 completion operation 在第一版只执行一次物理操作，并以
`SUCCEEDED`、`FAILED_DEFINITE` 或 `OUTCOME_UNKNOWN` 三态结束：非负函数返回表示该 NFQUEUE
Adapter operation 已成功完成，因此是 `SUCCEEDED`，但不证明后续 network delivery、下游
traffic success 或 receiver ACK；负/native error 或 deterministic pre-backend rejection 是
`FAILED_DEFINITE`。`OUTCOME_UNKNOWN` 只保留给未取得可信 terminal result 的 genuinely
ambiguous operation path；已观察到普通非负返回后不得再将其降级为 UNKNOWN。三态均不
触发自动 retry。后两类按低基数
outcome、Adapter/channel 与稳定 reason 累计 bounded counter、保留有界 first/last
diagnostics，并向 Runtime health 暴露 failure reason；Functional Closure 暂不规定 health
锁存/自动恢复时序或详细 UI 展示。不得
逐包同步写日志、保留无界失败历史、重新进入 VPP 或重新执行 policy。

NFQUEUE ingress 缺少 queue instance/generation 或 packet ID 等 mandatory completion identity
时，在 Adapter boundary 记录 bounded `INGRESS_IDENTITY_MISSING` fault，不创建 PacketLease、
不进入 VPP，也不产生 Policy Verdict 或伪造 Adapter Completion outcome。kernel queue
fail-open/bypass 可以独立释放 packet，但产品不得宣称自己提交或证明了 `ACCEPT`。

ADR-0007 已撤销“HEV admission 自身定义 outbound Adapter Completion”的旧推断。VPN Flow Stack
admission、Adapter Completion 与后续 Transport Outcome 分别记录；selected VPP-native TUN
Adapter contract 必须定义自己的 terminal operation，不能从尚待 POC 收敛的 Flow Stack ABI 倒推。
返回 App 的 packet 仍以最终 TUN write 作为 Adapter Completion。Root/NFQUEUE completion 按
`nfq_set_verdict` 返回值记录 NFQ terminal operation 本身的结果；非负返回是 `SUCCEEDED`，
不证明后续 host/network delivery、下游 traffic success 或另一个 ACK。

Adapter teardown 先 quiesce 新 ingress，再在 completion/transport 尚可用时对已有 PacketLease
做固定短期限 drain，最后才拆 channel。已有 Policy Verdict 照常完成；deadline 时普通、尚未求值
的 Root lease 在 identity 仍可完成时 `ACCEPT`，VPN lease 记录 completion/transport failure 后
释放。fragment reassembly failure 与 repeated owner mismatch 等已分类的 non-fail-open runtime
fault 仍 runtime drop。不得跨 Adapter generation 排队、重放或重新求值。

为使普通 pre-policy capacity fail-open 在 single-materialization 约束下可执行，每条 active
ingress lane 从既有 VPP pool 中保留一组 startup-fixed、worker-local、bounded buffer，作为
Fail-Open Reserve；不另建 pool，也不跨 worker 共享。首版 buffer data size 独立继承
Contiguous Parser Envelope 的最终产品选择；host POC 已证明 9000-byte patch path，Android
S80 只证明 2048-byte small-ICMP envelope。每 lane reserve 数量与 data size 必须由
production capacity matrix 的 peak concurrent occupancy、burst、exhaustion、RSS、latency
与目标 profile 实测确定，任何 POC 数量都不是 contract。normal ingress buffer 耗尽时，
packet 直接物化到 reserve 且不进入 parser/flow/policy graph：Root 仅凭 completion identity
提交 `ACCEPT`，VPN 只能经过正常 VPN Flow Stack Packet Boundary 及其已选择的 capacity-fault
contract，不能建立 direct HEV bypass。reserve 不动态增长、不等待容量；它也耗尽时允许明确丢包，
累计 bounded capacity-fault evidence 并降低 Adapter/runtime health。buffer 由适用的平台或 Flow
Stack boundary exactly once 结算。该机制只吸收瞬时压力，不承诺在内存耗尽或
transport failure 下仍能保持联网。

输出：当前 pinned VPP 使用不依赖 libnetfilter_queue 或 VPP callback 内部类型的 C contract，以及
malformed/truncated 示例。

### D2. VPP graph 与 threading model

定义 callback-to-node、buffer allocation、flow sharding、ordering、dual-stack/multi-queue、
bounded frame queue、backpressure、worker handoff 和上述 bounded teardown barrier。同步 UID lookup、
packet logging 均不得在无预算时停留在 hot path。

Adapter Initial Execution Placement 与最终 FlowOwner 明确分离。Root/NFQUEUE 的独立 queue lane
由 VPP-native Adapter plugin 独占收取并直接映射到 ingress execution contexts，不允许把所有 queue
汇聚到 main thread。VPN/TUN 从 Android 转交的单一 fd owner 开始。两者随后调用同一 OwnerSelector：
命中 owner 时 local continue，否则只移动 live buffer index 与 side metadata，执行一次 Primary
Handoff。NFQUEUE queue ID 只决定初始位置，不能成为最终 FlowOwner。

Root 保留多个 connection-stable `queue-balance` queues，不启用 CPU fanout。每条 native lane 独占
自身 queue/socket 的 receive 与 verdict；FlowOwner 不调用共享 `nfq_q_handle`。local packet 在 origin
lane 完成；remote packet 由 canonical owner 产生 terminal intent，再通过 bounded Canonical Return
回到 origin。origin 使用原 queue generation 与 packet ID 进行唯一一次物理 verdict，记录三态
Adapter Completion，随后走 VPP 原生 buffer return。Completion Frame 不复制 packet bytes，也不
建立 Rust packet owner、第二个 buffer、LeaseSlot table 或 per-packet heap object。

`Q=W` 是 production capacity matrix 的初始候选，不是 POC 已证明常量。Pixel 6a 的 scoped P2
结果显示 address-diverse Q2/Q4 与 canonical owner 约有 50% mismatch；multi-queue 提供 receive
parallelism，但不能替代 Primary Software Distribution。P4 已拒绝 shared-TX/trylock，并选择
owner-local fast path + mismatch-only bounded canonical processing/return。queue、worker、pool、ring、
completion credit 和 Fail-Open Reserve 均需由目标 throughput、burst、latency、drop、CPU、power 与
thermal matrix 定容；POC 的 pool32/128 或 reserve32 都不是产品常量。

VPN 首版使用一个 native TUN Platform I/O Lane。Android 仍负责 VpnService TUN 创建、权限与
`protect()` 所需的受控 broker 操作，然后把平台资源交给受监督的 VPP Runtime；运行中的 TUN
packet I/O、Adapter Completion 与 native buffer return 位于 C-only Adapter plugin。允许的
TUN-origin packet 在 canonical FlowOwner 进入 VPN Flow Stack Packet Boundary；flow-stack-origin
return packet 回到同一 shared graph 后才由 TUN lane 完成。本段不固定 HEV/lwIP instance 数、
state partition、shard count 或 owner-inline/paired topology。

Root/VPN PacketLease 仍由 live VPP buffer 与内联固定 metadata 承载；normal path 只有 VPP 原生
buffer pool，所有 graph、handoff、completion 与 return 都在 C/VPP ownership domain。Rust 不接收
逐包 callback，不拥有 platform packet fd 或 live VPP buffer，只通过粗粒度 non-unwinding ABI 管理
lifecycle、configuration、immutable policy snapshot、status 与 diagnostics。teardown 必须先 quiesce
ingress，在 completion channel 仍可用时有界排空 obligated buffers，再关闭 Adapter generation。

conditional wake 的机制方向保留为历史研究，但当前实现未接受：P6d final campaign-21 的 32 个 arms
全部有效，仍未通过预注册 idle CPU 与 sleep-confirmed p99 gates。当前 patch 与 persistent/per-packet
wake 不得成为 release 实现；只有新机制假设、新 hashed artifact 和新的预注册协议同时通过，才可重新
讨论调度实现。


buffer allocation/ingress 还必须证明 user-space single materialization：包括 TUN direct
read/readv into VPP buffer chain、NFQUEUE netlink receive into VPP-owned storage，以及不存在
Adapter-to-VPP full-packet memcpy 的代码与性能证据。还必须分别测量 normal ingress pool 与
per-ingress-lane Fail-Open Reserve 的耗尽路径，证明 reserve bypass 不进入 graph、不阻塞或动态扩容，
并在 reserve exhaustion 时产生明确 loss counter 与 health evidence。

worker distribution/handoff evidence 必须同时证明只传 VPP buffer index/ownership，不复制或
clone packet bytes；任何 fragment/recognition content-retention exception 需要独立 counter、
容量边界和压力结果。

graph review 还必须列出全部 Packet Byte Mutation Authority node；未列出的 node 视为 read-only，
并验证 Root 无 replacement payload、VPN policy-to-Flow-Stack-boundary bytes unchanged。

Android acceptance 要证明目标 Root/VPN device path、固定 1500-byte TUN MTU 与实证选择的 Flow
Stack packet envelope 位于最终 contiguous parser envelope，并验证通用长度检查不会 silent partial parse；测试至少覆盖
IPv4/IPv6、Wi-Fi、移动网络与大包 TCP/UDP，同时记录所选 buffer/default-pool baseline 的
RSS、峰值 occupancy 和 exhaustion evidence。Linux GSO/jumbo acceptance 延后到真实
部署证明需要时定义。

输出：node graph、ownership table、queue capacity、overload policy 和 counters。

### D3. Control、policy 与 health

定义 HELLO/status、compiled policy stage/commit/rollback、epoch reconciliation、runtime
health、Adapter health 和 conservative reconnect 的 versioned C ABI/VAPI。明确哪些
control-vNext concept 仍是产品 contract，哪些改为 VPP API message。

输出：version handshake、command/error table、policy snapshot schema、stale/in-flight
recovery rule。

### D4. Android lifecycle 与 security

把已证明的 RuntimeService pattern 映射到 VPP Runtime 与 VPN Userspace Flow Stack：artifact hash、signing trust、
KernelSU authorization、foreground service、parent death、supervisor cleanup、crash
policy、reboot、upgrade/rollback、socket/SVM cleanup 和 notification。

输出：lifecycle ownership matrix 与 release threat/failure model。

### D5. Module migration 与 admission gate

只有 D0-D4 完成后，才把 reconstructed module order 映射到 VPP：

1. Packet Capture Adapter 与 bounded PacketFacts foundation。
2. Hot-path capability 与 policy cache。
3. basic dual-stack IPRULES verdict slice 与 compiled policy authoring。
4. bounded worker-private FlowEntry；完整 Stateful CT 作为更后的显式产品阶段。
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
- RuntimeService 对当前 daemon 的 cleanup 结论，不会自动覆盖 VPP Runtime 或 VPN Userspace Flow Stack。
- POC direct owner-policy knob 不定义 compiled policy contract。
- archived daemon 不是实现计划。
- Linux/Docker 可以辅助 build 和源码诊断，但不能替代当前 Android 功能证据要求。

## 10. 新对话的第一个目标

不要重新讨论是否采用两个 dataplane，也不要把已经完成的 ingress/worker POC 当成待验证
架构。以已接受的 Option A 和 per-worker single-owner 决策为起点，先执行
SAKAMOTO-114 → 115 → 116 → 117，选择真实 HEV/lwIP isolation、VPP↔Flow Stack C boundary、
buffer/copy envelope 与 Android execution topology；在这些证据闭合前，不启动或复用 S98
production-shaped 实现。privilege、packaging、control reconnect、exactly-one settlement 和
profile-owned cleanup 仍是后续产品切片约束。

## 11. 新对话启动提示词

```text
我们继续 Sakamoto 的 Android/VPP 架构工作。先依次阅读：

1. docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md
2. CONTEXT.md
3. docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md
4. docs/decisions/NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md
5. docs/INTERFACE_SPECIFICATION.md

Plane 是 tracker，使用 plane-ops，不使用 Plane MCP。SAKAMOTO-2..31 是已完成的 Android
POC；SAKAMOTO-32 是已完成的历史 VPP experimental NFQUEUE audit；SAKAMOTO-72..81
已完成 throwaway live-buffer ownership closure POC，读
experiments/vpp-nfq-poc/SAKAMOTO-81_HANDOFF.md 后再讨论 Root Adapter。不能据此把
nfqueue_poc/live-buffer prototype 当成产品代码。Linux 暂缓，Android 是近期发版优先平台。

不要重新比较 Option A/B/C；Option A、Root/VPN 互斥、单 VPP runtime、共享 dataplane 和
per-worker single-owner 已接受。下一步从 Android L4 Product Release 的第一条端到端
vertical slice 制定正式实现计划。回答时严格区分：已证明事实、已接受决策、尚未证明的假设、
本轮新决策。
```
