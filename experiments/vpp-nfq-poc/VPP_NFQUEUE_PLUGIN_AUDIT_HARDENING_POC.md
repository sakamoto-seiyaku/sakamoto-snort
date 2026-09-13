# VPP experimental NFQUEUE plugin audit and hardening POC

> 参考命名说明（2026-09-13）：本机参考仓库绝对路径已抽象；外部插件、API、CLI、环境变量和证据标识保留原名，仅用于溯源，不是 Sakamoto 领域术语。下文是标注日期的历史观察；命令能否重跑须核对现行入口，旧结果不证明当前 Product 实现。

状态：Android 基线与首轮硬化已执行；生产准入 HOLD；Android-only

Plane：`SAKAMOTO-32`

## 1. 目标

当前使用的 NFQUEUE VPP 插件来自实验性/deprecated 原型，已证明“NFQUEUE packet 可以进入
VPP graph 并回写 verdict”，但这不等于它具备正式平台 Adapter 的正确性、兼容性和长期维护条件。

本 POC 专门回答：

1. 当前插件的源码、版本、依赖和许可证是否可以被项目正式接管。
2. 插件是否完整实现 Snort 所需的 NFQUEUE packet/verdict/metadata/teardown 语义。
3. 插件是否能在选定 VPP 版本和 Android arm64 真机上稳定构建与运行。
4. 暴露的问题能否修复并形成项目自有、可测试、可维护的 NFQUEUE Adapter。
5. 修复后是否满足 Android 性能、功耗、队列背压和故障边界，能够进入主线设计。

本 POC 结束前，插件只能称为实验输入，不能称为正式 NFQUEUE Adapter。

## 2. 被审计对象

历史参考插件：

```text
<reference-root>/src/plugins/stellar_netfilter_queue_deprecated/
```

具体源文件、commit/tag、VPP API 版本和本仓库使用的 patch 必须在第一阶段冻结并记录。不能只
审查当前编译出来的二进制，也不能默认历史 `deprecated` 目录代表稳定接口。

## 3. 阶段与顺序

### Phase A：来源、许可证和版本审计

- 固定 VPP upstream tag/commit、插件来源 commit 和本地 patch。
- 记录插件与 VPP 内部 API、libnetfilter_queue、libmnl、libnfnetlink 的依赖关系。
- 检查许可证、版权声明、第三方代码边界和是否允许随 Android 产物发布。
- 对比 deprecated 插件与选定 VPP 版本的 API/ABI，列出所有本地修改点。
- 产出 provenance、license、dependency 和 compatibility matrix。

**硬失败：** 来源无法追溯、许可证无法确认、依赖版本无法冻结，停止后续真机验证。

### Phase B：源码和并发审计

逐函数检查：

- fd 注册、epoll/interrupt 唤醒、VPP node 生命周期和线程归属。
- `nfq_handle`、queue、netlink fd、VPP buffer、sidecar metadata 的所有权与释放。
- partial read/write、EINTR、EAGAIN、queue reset、fd close 和异常退出路径。
- packet copy 长度、original length、truncation、非线性 buffer 和 malformed packet。
- `packet_id`、queue number、family、hook、UID/ifindex/mark/timestamp 等 metadata 的来源和失效语义。
- verdict 是否恰好一次、重复 verdict、漏 verdict、超时和 queue backlog 行为。
- 多 queue、多线程、worker handoff、共享状态、锁、内存序和 teardown race。
- IPv4/IPv6、INPUT/OUTPUT、NF_ACCEPT/NF_DROP/NF_REPEAT/NF_STOLEN 边界。

静态检查至少包括 warning-as-error、clang-tidy 或等价规则、ASan/UBSan/TSan 可行性评估，以及
对 VPP graph node contract 的人工 review。

### Phase C：修复和边界收敛

- 不在 deprecated 目录上继续叠加不可追踪 patch；将可保留部分迁入项目自有 Adapter 边界。
- 明确 `PacketFacts`/sidecar 与 NFQUEUE transport handle 的分离。
- 明确平台 Adapter 只负责收包、metadata、verdict 和 teardown，不承载 CT/policy/telemetry 业务。
- 固定 bounded copy 与 original packet length 口径，禁止把 copied prefix 当作 packet byte count。
- 固定错误策略：哪些错误 fail-open，哪些错误 fail-closed，哪些错误直接使 Adapter offline。
- 为 queue、fd、listener、worker handoff 和 shutdown 建立显式状态机。
- 所有修复必须有单独 commit、测试和变更原因，不接受只为让 smoke 通过的局部 workaround。

### Phase D：Android arm64 真机 NFQUEUE 语义验收

所有功能验证只在 Android 真机执行，不在 Linux、Docker 或 network namespace 上执行等价验收。
Host/Linux 只允许承担源码审计、交叉编译和脚本打包辅助，不产生 POC 通过证据。

沿用 Pixel 6a / Android 16 / arm64-v8a，至少完成：

- root NFQUEUE 启停、双栈 hook 安装和实际 ACCEPT/DROP。
- IPv4/IPv6、INPUT/OUTPUT、单 queue/多 queue。
- 固定 packet 数下每个 packet 恰好一次 verdict，无漏 verdict、重复 verdict 或 queue 卡死。
- truncated/malformed/large packet、EAGAIN/EINTR、fd close、queue reset、插件重启。
- VPP graph/node/worker 计数与 Android 内核 NFQUEUE 计数相互核对。

### Phase E：Android 生命周期和故障验收

- RuntimeService stop、App process death、daemon crash、reboot 的 hook/queue 清理。
- root 权限拒绝、artifact mismatch、daemon restart 和 supervisor cleanup 边界。
- USB 断电、屏幕关闭、短 Doze 下无流量和有流量行为。
- APK 中实际插件/daemon artifact 与构建 commit、VPP tag、插件 patch 一致。

### Phase F：性能、功耗和准入结论

正式运行前冻结测量口径和预算，至少采集：

- verdict latency p50/p95/p99。
- queue backlog、queue drop、user drop、packet loss 和异常 verdict 数。
- 单 queue/多 queue、queue 数量、worker 数量和 Android CPU placement 对比。
- 无流量 idle CPU、scheduler wakeup、RSS、短时电流/热状态。
- bounded copy 与较大 copy range 的吞吐、延迟和功耗差异。

阈值必须在正式测试前写入 run manifest；不得测试后根据结果倒推通过标准。

## 4. 硬性失败门槛

任一条件成立，POC 结论为 No-Go：

- provenance、license 或 VPP 版本兼容性无法追溯。
- packet 漏 verdict、重复 verdict、queue 卡死或 verdict 超时没有明确且可接受的策略。
- malformed/truncated packet 导致越界、崩溃、未定义行为或错误 packet length。
- 正常停止、异常退出或重启留下不可接受的 NFQUEUE hook/queue/rule 残留。
- 多线程/worker handoff 下 correctness 依赖未证明的 queue 偶然 stickiness。
- Android 不同 queue/family/hook/生命周期路径产生未记录的语义差异，导致 Adapter contract 不成立。
- 关键路径引入无界 copy、阻塞 I/O、动态分配或锁，且没有性能预算证据。
- 只能依靠 deprecated VPP API 的未维护 patch 运行，无法冻结可维护版本边界。

## 5. 交付物

- `NFQUEUE_PLUGIN_AUDIT.md`：逐项 finding，严重性、证据、修复状态和剩余风险。
- provenance/license/dependency/VPP-version compatibility matrix。
- 项目自有 Adapter 的 fix commits 和 patch 说明。
- Android 真机测试矩阵与每次 run manifest；不得以 Linux/Docker 结果替代真机证据。
- 原始 log、计数器快照、性能/功耗数据和失败复现脚本。
- 明确的 Go / Conditional-Go / No-Go 结论。

## 6. 结论解释

只有当源码审计、修复、Android arm64 真机语义验收、Android 生命周期验收和性能/功耗预算全部
通过，才能把该插件作为 VPP 统一数据面的正式 NFQUEUE Adapter。Linux/Host 结果只能作为辅助
证据，不能替代 Android 结论。否则 VPP core 的设计可以继续，但产品必须保留 VPN/TUN Adapter
或其它已验证入口，不能把实验插件当成架构已闭合的事实。

## 7. Android 执行记录

### 7.1 固定构件与设备

正式硬化复测：`20260719-141956`。

```text
device: Pixel 6a / Android 16 / arm64-v8a / adb 28201JEGR0XPAJ
USB: dumpsys battery unplug；结束由 trap reset
VPP: 9258530f3804a152578ce11cc7c8a1e9eab88ed0 / v26.02
plugin source SHA-256: 6e02160066a504ded4b1e75eb3a182bb70fad7847158adfce1254aa4438e0492
plugin CMake SHA-256: ada3277cbebe8624e41e88c2215843ddc6758505c7acd11461c5286b402a79ff
Android plugin artifact SHA-256: eebc350f9eb95562a8cbbd6df981edf7eb6cd0c88b6730d23d64ff0395766ce0
staged payload: 9.4M
raw result: experiments/vpp-nfq-poc/results/sakamoto-32-nfqueue-plugin-audit-20260719-141956/
```

### 7.2 已验证事实

- Android arm64 交叉编译 `vpp`、`vppctl`、`nfqueue_poc_plugin` 均成功，插件在真机正确加载。
- IPv4/IPv6 的 INPUT/OUTPUT `ACCEPT`、`DROP` 各通过；IPv4/IPv6 OUTPUT 的 20 包 `drop-ratio 50`
  均得到 `seen=20 accepted=10 dropped=10`。
- 每个 verdict case 的 `show nfqueue-poc` 均报告 `copy-range 512`，并且
  `handle-errors=0 recv-errors=0 enobufs=0 event-write-errors=0`。
- 保持 iptables NFQUEUE 规则有效时执行 `nfqueue-poc disable`，Android
  `/proc/net/netfilter/nfnetlink_queue` 立即变为 0 行；最终 VPP、queue、NFQUEUE hook 全部为 0。
- 无流量 10 秒 `/proc` 采样：plugin disabled 的 `utime/stime` 增量为 `1/0` jiffy，enabled 为
  `0/0`；两组 `VmRSS` 均为 `102984 kB`。这是短时 idle 基线，不是功耗或长期 CPU 预算结论。
- IPv4 event log 记录了 packet ID、family、proto、payloadLen、UID、目标地址和 verdict；4/4
  放行事件完整写入。

### 7.3 首轮失败方法与修正

- `20260719-140840`：Windows/WSL adb wrapper 对目录 push 产生了嵌套 `bin/bin` 等路径，VPP
  无法启动。修正 `android-push-vpp-core.sh` 为逐文件 push，并在设备端列出最终路径。
- `20260719-141157`：功能矩阵已通过，但 harness 删除规则使用错误的 `-I` 变换，造成重复
  NFQUEUE 规则并误报 residue。修正为显式 `-D` 删除循环，并补齐 IPv6 `ping6` 与 50% ratio
  断言；修正后的正式 run 为 `20260719-141956`。

### 7.4 Finding 与准入状态

| ID | Finding | 状态 | 影响 |
| --- | --- | --- | --- |
| F-01 | 原实现向内核请求 `0xffff` full copy；本轮改为 bounded `512`。`nfq_get_payload()` 现在只能代表 copied prefix，original packet length 仍未单独保留。 | 部分修复 | Parser/telemetry 不能把 `payloadLen` 当 original length；需要明确 truncation/original-length contract。 |
| F-02 | `recv()` 遇到 `ENOBUFS` 原来在 read-ready 回调内 `continue`，可能形成忙循环；本轮改为计数后退出本次回调。 | 已修复，需压力复测 | 仍缺 kernel drop/backlog 压力与恢复预算。 |
| F-03 | event log 在 packet callback 中多次 `fprintf` 并逐包 `fflush`，属于同步 I/O 热路径。 | 未修复 | 不能在生产路径开启；必须改为异步、有界 telemetry 或明确移除。 |
| F-04 | 缺失 `packet_id` 时只能计数并返回，无法安全发 verdict；当前行为可能使该 packet 没有明确结论。 | 未修复 | 必须定义 Adapter offline/fail-open/fail-closed 策略并加入 fault injection。 |
| F-05 | 一个 plugin instance 只绑定一个 address family、一个 queue；当前 dual-stack 验证通过重启实例完成，不代表单实例双栈/多 queue。 | 未修复 | 正式 Adapter 拓扑和并发模型尚未成立。 |
| F-06 | IPv6 parser 只读取固定头部，未处理 extension header；malformed/truncated 路径目前存在 default-allow 语义。 | 未修复 | 需要 parser status、truncation/original length 和产品 fail-open/fail-closed 决策。 |

结论：本轮是 **Android NFQUEUE 基线 Conditional-Go**，证明当前构件可以在真机完成基本
verdict 和 teardown；对正式 NFQUEUE Adapter 仍是 **No-Go/HOLD**。F-01/F-02 的修复已在
overlay 中，并完成真机回归，但 F-03 至 F-06 以及 backlog、latency、crash/reboot、malformed
packet、multi-queue 和长时 CPU/功耗证据仍未通过，不得进入统一 VPP 数据面准入。

下一轮仍只在 Android 真机执行：先完成异步 event path、parser/original-length contract 和
missing-ID fault policy，再做 queue overflow、daemon/plugin crash、reboot、dual-stack/multi-queue
拓扑与 p50/p95/p99 latency 测量。Linux/Docker 继续只承担源码、交叉编译和打包辅助。
