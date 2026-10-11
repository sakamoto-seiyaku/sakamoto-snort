# 可观测性双通道：移动端开源 IPC 调查汇总

日期：2026-09-23。本轮按用户要求联网调查，目标为 Android ARM64 手机（项目 minSdk 31）及 Linux，生产者为 VPP-native C，消费者为 Rust。普通记录与 debug 独立、有界，VPP 不等待消费或确认；当前是设计讨论，没有接入候选库或进行设备实验。

## 当前确认：三项候选，实验后选型

用户在讨论后确认将选择范围收敛为以下三项。**VPP `svm_msg_q` 与 Aeron C ring 均保留为复用候选，手动实现 ring + eventfd 作为最后的兜底方案；最终选择必须经过实验。** 前两项未确定胜出者，也未确定普通 / debug 分别使用不同实现。

| 当前候选 | 定位 | 后续实验与接入重点 |
| --- | --- | --- |
| VPP `svm_msg_q` | 复用已有 VPP 共享消息队列 | 非阻塞操作与通知、槽位容量利用、C/Rust 封装及版本协调 |
| Aeron C SPSC ring 子集 | 复用外部 C 变长记录队列 | 小型源码子集构建、Android 共享区 / 通知接入及 ARM64 发布顺序 |
| 手动实现共享内存 ring + eventfd | 前两项不合适时的最后方案 | 在当前 VPP C / Rust 边界实现最小通道，自行验证并发、通知、生命周期及维护成本 |

第三项承接用户指出的旧非 VPP 版本“手写 ring + eventfd”方案类别。后续面向当前 VPP-native C 主线实现，遵守 ADR-0008：不恢复、移植或参照已移除的非 VPP C++ 源码，不建立 C++ 兼容路径。[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)

三项使用相同的普通 / debug 独立有界通道要求、记录工作量与容量预算比较。实验需覆盖 Android 实际运行下的正确性、满队列 / 消费暂停 / 重启行为，以及 worker 发送成本、内存利用、空闲唤醒和能耗；不能仅按桌面吞吐或静态代码形状裁决。本轮确认候选与实验裁决原则，不开始实现或运行实验，不冻结具体 ring 布局、容量或通知节奏。

后续讨论进一步明确：**debug 开启后，以完整实际动作追踪、正确性和故障定位优先，性能退居其次**；可以接受为充分诊断增加开销。实验应分别评价常态成本与 debug 诊断能力，不能为得到更好性能数字而缩减 debug 所需证据。独立有界通道与 VPP 不等待消费的约束继续有效，实际缺口必须可见。[讨论确认 §21.31](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md#2131-debug-追踪包的完整动作链正确性与故障定位优先用户确认)

**debug 数据仅服务一次调试会话，不长期持久化。** 普通通道支撑常态记录与历史汇总，debug 通道支撑会话内临时消费、关联和查看；共用 Rust 后台不意味着两路都进入长期观测记录库。详细轨迹与必要解释资料按本次会话管理。[用户修正 §21.35](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md#2135-debug-仅服务一次调试会话不长期持久化用户明确修正)

`SOCK_SEQPACKET`、CK 等保留为已完成的调查资料，不属于当前确认的三项，也不设为必须增加的第四个实验方案。候选收敛不等于已有性能证据证明其他方案更差。[讨论确认 §21.29](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md#2129-记录通道收敛为三项候选最终由实验选择用户确认)

## 调查覆盖的组件与证据

本轮没有找到同时开箱满足 Android 跨进程、轻量 C 接口、简单有界 producer 路径、低接入成本的完整框架。并发队列可以复用，fd 交接、进程生命周期、记录约束及唤醒仍需产品接入。下表保留调查覆盖范围，当前候选集合以上节为准。

| 候选 | 值得复用的部分 | Android 与接入限制 | 本轮判断 |
| --- | --- | --- | --- |
| **Aeron C SPSC ring，1.53.2** | 有界变长记录、调用方提供内存、队列满立即返回；正常写入不分配、不加互斥锁 | 是底层组件，未发现本候选的 Android 验收依据；需共享区 / 唤醒接入及很小的错误处理适配 | **确认候选**，不引入整套 Aeron |
| **VPP `svm_msg_q`，项目 pin** | 固定槽位 / 大小类别、record descriptor、现有 Android `libsvm` 交付基础 | Rust 侧仍需 C 封装；锁、通知及 Android patch 语义需审查，不能盲用所有 nowait helper | **确认候选** |
| **Concurrency Kit `ck_ring`** | 小型 C SPSC、typed value slots、共享区可在不同地址映射 | 更适合固定大小记录；变长 debug 需槽位策略或额外存储；还需 Android 构建与跨进程验证 | 保留调查，未入选当前三项 |
| **NNG 1.12.4** | C 消息 API、连接管理、明确 Android NDK 构建路径 | 上游 Android 测试自称有限；NONBLOCK 仍有内部锁 / AIO，后台线程与分配成本需控制 | 可以用，但本需求暂不优先 |
| **iceoryx2 0.10.0** | shared-memory pub/sub、配置容量及丢弃策略 | Android 当前仅线程间 local 变体，C bindings 未支持 Android，IPC 后端存在缺口 | 暂不进入本产品短名单 |
| **libmemif / `svm_fifo`** | 前者提供完整包接口 IPC，后者提供 VPP 字节 FIFO | 前者引入包接口语义；后者需要 framing 与 segment / chunk 管理 | 当前 record 通道不优先 |
| **Perfetto / FMQ** | tracing 生态 / Android 平台共享队列 | Perfetto 带 tracing runtime；FMQ 非一般 App 可直接依赖的公开 NDK 库 | Perfetto 可另作诊断工具，均不优先作常态通道 |

表中库级事实来自固定版本一手源码与官方文档，完整证据、许可证及路径限定分别见 [C ring 调查](2026-09-23_OBSERVABILITY_IPC_C_RING_RESEARCH.md)、[VPP 调查](2026-09-23_OBSERVABILITY_IPC_VPP_RESEARCH.md)、[框架调查](2026-09-23_OBSERVABILITY_IPC_FRAMEWORK_RESEARCH.md)和 [Android 原生设施调查](2026-09-23_OBSERVABILITY_IPC_ANDROID_RESEARCH.md)。不把支持 Linux ARM64 自动解释为支持 Android App。

## Aeron C ring 的复用边界

**Aeron 整个项目本来就支持共享内存 IPC。** 官方 `aeron:ipc` 通过共享的 Log Buffers 传递消息，并由 Media Driver / client 管理通道。Media Driver 有 C 实现，可独立运行或嵌入，因此不能把完整 Aeron 描述成必需 Java 的系统。不过，本文候选是内部的 `aeron_spsc_rb` 组件，采用它不等于采用完整 `aeron:ipc` 产品接口，也不会自动获得完整通道管理。这里的“外部首选”只表示外部 ring 组件的审查优先级，不表示比已有 VPP 队列更省总接入工作。[共享内存协议](https://github.com/aeron-io/aeron/wiki/Transport-Protocol-Specification)、[Media Driver](https://aeron.io/docs/aeron/media-driver/)、[C driver 配置与嵌入](https://github.com/aeron-io/aeron/wiki/Configuration-Options)

这里候选是 `aeron_spsc_rb`，不是 Aeron Media Driver、Java client 或整套消息运行时。其进程本地 handle 引用调用方提供的 buffer，shared buffer 使用计数位置和 record header。`write` 复制完整记录并发布，容量不足返回 FULL；`read` 可以限定每批消息数。它适合每个 owner 一位 writer、Rust 一位 reader 的角色分配，支持 normal 与 debug 复用实现而使用不同容量。共享内存中传记录值，不传 FlowEntry 或 packet buffer 指针。[1.53.2 ring 源码](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_spsc_rb.c)、[接口与布局](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/concurrent/aeron_spsc_rb.h)

**复用成本不能省略。** 它并不是独立发布的一文件 Android IPC 库：初始化失败路径引用 Aeron 错误设施，完整错误实现又关联更大客户端代码。小型接入需要维护明确的源码子集和错误适配，保留上游版本与许可证声明；映射、fd 传递、通知和进程代际仍由产品负责。Rust 可经同一 C 实现读取，避免另写一套原子发布算法。这是接入建议，尚未编译验证。[错误实现](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/util/aeron_error.c)、[客户端公共实现](https://github.com/aeron-io/aeron/blob/664f58e705f850dfb926f6293707b204ba804726/aeron-client/src/main/c/aeronc.c)

检查版本也有实际意义：较早 1.50.4 的 wrap / capacity 路径有后续修复，1.53.2 包含该修复。CK 的当前源码也包含晚于 0.7.2 的 consumer ordering 修正。上述是审查版本的理由，不能推导这次已经复现手机错误；尤其 CK 上游将其描述为理论问题，不应写成已观察到的 ARM 损坏。[Aeron 修复](https://github.com/aeron-io/aeron/commit/12e16428e006ae283ae256f4c82c9bd29f84fcda)、[CK 修复](https://github.com/concurrencykit/ck/commit/c7945fe3a7817549f573b0cb902f797c7df071a0)

## VPP 消息队列的接入条件

`svm_msg_q` 与记录需求相符，也已有项目 Android patch 和 `libsvm` artifact 基础；它是有价值的备选。当前结构支持以本地 wrapper 和共享索引接入不同映射地址，不能沿用“全部 SVM 都要求相同虚拟地址”的旧印象。但它带 VPP ABI / `vppinfra` 依赖，producer lock、数据槽位释放和 eventfd 都需正确选择。

固定版本静态检查还发现部分 convenience API 的可疑异常路径，以及默认创建阻塞 eventfd 的行为。可用的组合 admission API 与这些路径有区别。因此建议仅通过小 C 封装暴露审过的非阻塞操作，不将 `nowait` 命名当作完整保证。这些是未复现的候选接入问题，不是当前产品失败报告。[固定版本 message queue](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/svm/message_queue.c)、[VPP 详细限定](2026-09-23_OBSERVABILITY_IPC_VPP_RESEARCH.md)

用户随后要求具体解释锁、槽位利用率及依赖耦合。按候选的每 owner 独占 producer queue、Rust 单 consumer 拓扑，三者的影响应限定如下；不能把它们直接列成否决理由。

- **锁**：eventfd 模式使用进程私有的多 producer spinlock；未配置 eventfd 时使用共享 pthread mutex。前一种模式中，Rust 的 raw dequeue 不竞争 producer 私有锁。每 owner 独占自己的 queue，并禁止其他线程并发写该 queue，可避免多 worker 争锁；非阻塞组合 admission 只 try-lock，失败或容量满立即返回。此时锁主要是额外原子操作，不是等待 Rust 消费的机制。底层另有 raw API，但直接绕过锁需要明确维护调用前提，不因存在 raw API 就声称已证明整个接入无锁正确。通知 fd 仍需非阻塞，不能只审核队列锁。[锁选择及消费合同](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/svm/message_queue.h#L217-L406)、[组合 admission](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/svm/message_queue.c#L228-L250)
- **槽位**：假设已编码记录为 100 B，放入 128 B 槽就有 28 B 空余；600 B 记录放入 1024 B 槽就有 424 B 空余。这是示意，不是容量默认。可配置多个大小类别，但大消息不能自动合并若干小槽；小消息可由合适的分配策略使用空闲大槽，代价是空余更多。Aeron ring 同样预留有界总内存，区别是按记录实际长度加 header / alignment 占用连续 ring 空间，因此应比较同一预算下的容量利用，而不是把“预分配”本身当成 SVM 独有缺点。常态记录大小接近时影响可能较小，debug 长度跨度决定是否值得优化。普通/debug 必须使用独立 queue，大小类别不替代通道隔离。[布局](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/svm/message_queue.h#L19-L94)、[按大小找槽](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/svm/message_queue.c#L253-L272)
- **耦合**：Rust 若通过 C 复用队列，将依赖 `libsvm` / `vppinfra` 的构建与分发；共享结构还含 native / pthread 布局，因此同一设备两端应使用匹配的库、布局和 Android patches。小 C 封装可让 Rust 业务只接触项目自己的记录与操作接口，但底层版本协调仍存在。该耦合属于实现与构建，不使 Rust 统计语义归 VPP 所有。项目已有 Android 库基础，使这部分成本可能低于引入并维护新外部组件；尚未测量的锁成本或假定的槽位浪费不足以推翻这项复用优势。[库依赖](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/svm/CMakeLists.txt)、[项目 Android 库交付](../../src/product/vpp/android/build-stage.sh)

## 手机限制如何改变选择

Android 有公开共享内存能力：`ASharedMemory_create` 从 API 26 可用，官方支持 `mmap` 和 `SCM_RIGHTS` 传 fd；Bionic 的 `memfd_create` wrapper 从 API 30 提供。本项目 API 31 可以以这些接口为平台基础。同时 Bionic 缺少 `shm_open/shm_unlink` 及 robust mutex 能力，使用桌面 POSIX 后端的库需要逐项核对。[NDK Memory](https://developer.android.com/ndk/reference/group/memory)、[固定版本 Bionic 状态](https://android.googlesource.com/platform/bionic/+/8ba5f4890751863c94c2178be9468f1cd7871a19/docs/status.md)

iceoryx2 的筛除正是实际平台限制：0.10.0 的 Android 文档只支持 local / local_threadsafe，C/C++ bindings 不可用。NNG 的 Android 文档提供构建路线，但测试程度有限；它的 nonblocking 不能消除内部 mutex / AIO runtime。这两者都不应仅凭桌面延迟曲线入选。[iceoryx2 Android 文档](https://github.com/eclipse-iceoryx/iceoryx2/blob/135d09dd8b29f321f1725920d434864c4e512378/doc/development-setup/android.md)、[NNG Android 文档](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/docs/BUILD_ANDROID.adoc)、[NNG 发送实现](https://github.com/nanomsg/nng/blob/d504cf08ae8c87885d3dc07214b47a6b9a95c4bc/src/nng.c)

**唤醒与队列分开评价。** ring 没有后台线程，不等于完整接入没有唤醒开销；socket 有 syscall，也不等于低频合批一定不可接受。建议消费者空闲时可睡眠，数据合批处理，debug 关闭时没有持续诊断工作；具体通知合并或低频 polling 留给接入比较，不预设忙轮询、固定一秒轮询或常驻 wakelock。Android 消费延后时，producer 继续遵守有界丢失语义。[eventfd](https://man7.org/linux/man-pages/man2/eventfd.2.html)、[Android Doze](https://developer.android.com/training/monitoring-device-state/doze-standby)

原生 Unix `SOCK_SEQPACKET` 保留消息边界，非阻塞发送容量不足返回错误，没有新增消息中间件依赖。调查阶段曾建议以它作工程对照；用户随后将当前候选收敛为上述三项，因此这里仅保留已有技术资料，不要求额外增加 socket 实验。其非阻塞语义也不保证无内核锁或硬实时耗时。[unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)、[send(2)](https://man7.org/linux/man-pages/man2/send.2.html)

## 对当前讨论的影响与证据边界

- 双通道已接受；候选 ring 路线可让每个 owner 分别拥有 normal / debug queue，由同一 Rust 后台有界消费。通道不是新增两套统计，也不默认每条 queue 对应一个线程或 socket。
- 普通与 debug 不能只在同一 FIFO 中加类型字段就称为容量隔离；独立队列仍需要有界 CPU / 写入份额。
- C ring 是可复用的并发组件，完整 IPC 需要薄接入。优先采用普通 record copy API 即可，不因库提供 claim / commit 就默认增加跨处理阶段的借用状态。
- 三项候选已经确认，最终选型留给实验。后续需用确切 Android artifact 检查构建 / 链接、跨进程发布、满队列、消费暂停与重启，并比较实际工作量下的 CPU、内存、唤醒及能耗；手动 ring + eventfd 保持最后方案定位。本轮没有执行这些实验，也不提出未经讨论的性能阈值。

本轮仅调查一手资料、固定版本源码和当前仓库，形成报告与讨论记录；没有修改产品代码、添加依赖、运行设备或修改正式 ADR / domain / interface spec。所有性能判断均限于待验证的工程推导，最终 transport 与库仍待选。

完整支撑资料：[平台基线](2026-09-23_OBSERVABILITY_IPC_MOBILE_BASELINE.md)、[C rings](2026-09-23_OBSERVABILITY_IPC_C_RING_RESEARCH.md)、[VPP](2026-09-23_OBSERVABILITY_IPC_VPP_RESEARCH.md)、[NNG / iceoryx2](2026-09-23_OBSERVABILITY_IPC_FRAMEWORK_RESEARCH.md)、[Perfetto / FMQ](2026-09-23_OBSERVABILITY_IPC_ANDROID_RESEARCH.md)。
