# VPP experimental NFQUEUE plugin audit and hardening POC

状态：已登记，未开始正式执行

Plane：`SAKAMOTO-32`

## 1. 目标

当前使用的 NFQUEUE VPP 插件来自实验性/deprecated 原型，已证明“NFQUEUE packet 可以进入
VPP graph 并回写 verdict”，但这不等于它具备正式平台 Adapter 的正确性、兼容性和长期维护条件。

本 POC 专门回答：

1. 当前插件的源码、版本、依赖和许可证是否可以被项目正式接管。
2. 插件是否完整实现 Snort 所需的 NFQUEUE packet/verdict/metadata/teardown 语义。
3. 插件是否能在选定 VPP 版本、Linux 和 Android arm64 上稳定构建与运行。
4. 暴露的问题能否修复并形成项目自有、可测试、可维护的 NFQUEUE Adapter。
5. 修复后是否满足性能、功耗、队列背压和故障边界，能够进入主线设计。

本 POC 结束前，插件只能称为实验输入，不能称为正式 NFQUEUE Adapter。

## 2. 被审计对象

历史参考插件：

```text
/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/
```

具体源文件、commit/tag、VPP API 版本和本仓库使用的 patch 必须在第一阶段冻结并记录。不能只
审查当前编译出来的二进制，也不能默认历史 `deprecated` 目录代表稳定接口。

## 3. 阶段与顺序

### Phase A：来源、许可证和版本审计

- 固定 VPP upstream tag/commit、插件来源 commit 和本地 patch。
- 记录插件与 VPP 内部 API、libnetfilter_queue、libmnl、libnfnetlink 的依赖关系。
- 检查许可证、版权声明、第三方代码边界和是否允许随 Android/Linux 产物发布。
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

### Phase D：Linux 真实 NFQUEUE 验收

在隔离 network namespace/Docker 环境先完成：

- accept-all、drop-all、固定比例 verdict。
- IPv4/IPv6、INPUT/OUTPUT、单 queue/多 queue。
- 固定 packet 数下每个 packet 恰好一次 verdict，无漏 verdict、重复 verdict 或 queue 卡死。
- truncated/malformed/large packet、EAGAIN/EINTR、fd close、queue reset、插件重启。
- 进程正常停止、SIGTERM、SIGKILL、VPP restart 后 hook、queue、socket 和 rule 的状态。
- VPP graph/node/worker 计数与内核 NFQUEUE 计数相互核对。

### Phase E：Android arm64 真机验收

沿用 Pixel 6a / Android 16 / arm64-v8a，但只把 Android 作为 Adapter 和交付环境验证：

- root NFQUEUE 启停、双栈 hook 安装和实际 ACCEPT/DROP。
- app UID、UID/ifindex/hook metadata 能力和未知值语义。
- RuntimeService stop、App process death、daemon crash、reboot 的 hook/queue 清理。
- USB 断电、屏幕关闭、短 Doze 下无流量和有流量行为。
- APK 中实际插件/daemon artifact 与构建 commit、VPP tag、插件 patch 一致。

Android 真机通过不能替代 Linux 语义测试；Linux 通过也不能替代 Android ABI、root 和电量边界。

### Phase F：性能、功耗和准入结论

正式运行前冻结测量口径和预算，至少采集：

- verdict latency p50/p95/p99。
- queue backlog、queue drop、user drop、packet loss 和异常 verdict 数。
- 单 queue/多 queue、queue 数量、worker 数量和 CPU placement 对比。
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
- Android 与 Linux 使用不同未记录的语义，导致同一 Adapter contract 不成立。
- 关键路径引入无界 copy、阻塞 I/O、动态分配或锁，且没有性能预算证据。
- 只能依靠 deprecated VPP API 的未维护 patch 运行，无法冻结可维护版本边界。

## 5. 交付物

- `NFQUEUE_PLUGIN_AUDIT.md`：逐项 finding，严重性、证据、修复状态和剩余风险。
- provenance/license/dependency/VPP-version compatibility matrix。
- 项目自有 Adapter 的 fix commits 和 patch 说明。
- Linux、Android 真机测试矩阵与每次 run manifest。
- 原始 log、计数器快照、性能/功耗数据和失败复现脚本。
- 明确的 Go / Conditional-Go / No-Go 结论。

## 6. 结论解释

只有当源码审计、修复、Linux 语义验收、Android arm64 真机验收和性能/功耗预算全部通过，才能
把该插件作为 VPP 统一数据面的正式 NFQUEUE Adapter。否则 VPP core 的设计可以继续，但产品必须
保留 VPN/TUN Adapter 或其它已验证入口，不能把实验插件当成架构已闭合的事实。
