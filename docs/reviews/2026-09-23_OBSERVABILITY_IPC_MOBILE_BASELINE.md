# 可观测性 IPC：Android / ARM64 平台基线与直接系统接口

日期：2026-09-23。范围：为 VPP-native C 向 Rust 发送常态与 debug records 的通道选型提供移动端约束；只读调查，不是已选依赖或性能验收。

本报告只用当前仓库和平台一手资料。库级调查另见本目录同日的 VPP、C ring 与 IPC framework 报告；最终取舍见汇总报告。

## 1. 项目边界

- 当前工作区核对基线为 `e9356b1111c80ade013dc66052ba4cb28da91860`，VPP pin 为 `9258530f3804a152578ce11cc7c8a1e9eab88ed0`。[VPP pin](../../src/product/vpp/pinned-vpp-revision.txt)
- Android Manifest 的 `minSdkVersion=31`、`targetSdkVersion=36`；构建脚本默认 native API 31。当前研究以 ARM64 手机及 Linux 为目标，不把桌面 Linux 兼容性自动当作 Android 兼容性。[Manifest](../../app/android-runtime/src/main/AndroidManifest.xml)、[构建脚本](../../app/android-runtime/scripts/build-debug-apk.sh)
- 包域仍为 owner-local VPP C。普通与 debug 为两个独立有界数据通道，VPP 不等待消费确认，满时允许丢失并计数；Rust 保持简单消费。共享的是记录副本，不能跨进程直接借用 FlowEntry 或 live packet buffer。[主讨论](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)、[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)
- 当前 C bridge 经 `vapi_connect_ex(..., VAPI_MODE_BLOCKING, true, true)` 建立控制会话；typed API 尚不能被当成已有的非阻塞 worker records 通道。该控制面行为也不是要求把控制模式改为非阻塞的理由。[当前 VAPI bridge](../../src/product/native/sakamoto_product_vapi.c:903)、[接口地图](../INTERFACE_SPECIFICATION.md)

## 2. Android 与普通 Linux 的关键差别

### 2.1 不应直接依赖桌面 POSIX IPC 名称空间

AOSP Bionic 的固定版本状态文档明确列出 `shm_open` / `shm_unlink` 缺失，以及 robust mutex 和 `pthread_cancel` 等能力缺口。因此，库标注支持 Linux/aarch64，仍不足以证明它的 Android 跨进程路径可用；需要继续查它实际调用的共享内存、同步、目录和进程清理接口。[Bionic status，commit `8ba5f4890751863c94c2178be9468f1cd7871a19`](https://android.googlesource.com/platform/bionic/+/8ba5f4890751863c94c2178be9468f1cd7871a19/docs/status.md)

这不是说 Android 不支持共享内存。官方 NDK 提供 `ASharedMemory_create`（API 26 起），返回可 `mmap` 的 fd，并明确支持通过 Unix domain socket 的 `SCM_RIGHTS` 将 fd 交给其他进程。它在本项目 API 31 下具有公开 API 基础；实际应用身份、SELinux、VPP artifact 链接和设备通路仍需项目验证。[Android NDK Memory](https://developer.android.com/ndk/reference/group/memory)

Bionic 从 API 30 提供 `memfd_create` wrapper；Linux 的该接口创建可映射的匿名 RAM-backed fd。两平台可以共享 queue/record 逻辑，同时让共享内存区域创建留在小的平台 Adapter 中。fd/mmap 本身不提供记录格式、队列发布顺序或消费者生命周期。[Bionic API 30 additions](https://android.googlesource.com/platform/bionic/+/8ba5f4890751863c94c2178be9468f1cd7871a19/docs/status.md)、[Linux memfd_create](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

### 2.2 跨进程不是跨线程

两进程不应被要求映射到相同虚拟地址。共享区中需要的是值、索引或相对 offset；进程本地 handle 可以持有本进程映射地址，但不能让另一个进程解引用该指针。库若只提供 `void *` 指针队列，可能仍可传数字 offset，但会把对象存储与回收工作留给接入层。这是候选审查条件，不是对所有 pointer API 的一概否定。

SPSC 也只解决一个 producer、一个 consumer 之间的队列组织。Linux 文档说明需用正确的发布 / 读取顺序，才能在 producer 与 consumer 并行时避免共享锁；不能把示例中的 Linux 内核同步宏直接抄为 C/Rust 跨进程 ABI。对于本项目，单个 owner 写自己的队列、Rust 消费该队列，能满足 SPSC 的角色前提；控制线程不能另行成为第二个 producer。[Linux circular buffers](https://docs.kernel.org/core-api/circular-buffers.html)

## 3. 两个应保留的直接系统接口基线

### 3.1 Unix domain `SOCK_SEQPACKET`

Linux Unix-domain seqpacket 是连接式、保留消息边界并保持发送顺序的本机 IPC。系统接口同时支持 fd 传递，因此既可作为 records 通道候选，也可只用于共享区建立。[unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html)

`MSG_DONTWAIT` / `O_NONBLOCK` 使发送在需要等待发送缓冲时返回 `EAGAIN` / `EWOULDBLOCK`；过大的原子消息返回 `EMSGSIZE`，而不是强制调用方等待。API 的 nonblocking 语义不等于无系统调用、无内核锁或硬实时延迟保证。缓冲配置、错误路径和最大消息必须有界，满时的重试不能变成 VPP busy-spin。[send(2)](https://man7.org/linux/man-pages/man2/send.2.html)

**工程推导**：它应保留为最小依赖对照方案。队列同步和断开处理由内核承担，应用仍需 record 编码、容量 / 错误语义和 owner 接入。代价是每个导出批次的 syscall 与数据复制；当前没有本产品测量，不能断言这个成本不可接受，也不能保证它优于共享内存。

### 3.2 `ASharedMemory` / `memfd` + 可复用的有界 ring

共享内存让记录 payload 由两侧映射直接交换。可以按 normal/debug 隔离空间，再按 owner 划分 producer queue；Rust 保持一个逻辑消费入口。fd 传递、映射、进程身份、record framing、发布原子性、满时行为、关闭和代际生命周期仍需由小范围接入负责，不能把一个 queue 库当成已完成的产品 IPC。[Android NDK Memory](https://developer.android.com/ndk/reference/group/memory)、[memfd_create(2)](https://man7.org/linux/man-pages/man2/memfd_create.2.html)

**工程推导**：对不应逐记录进入内核的 worker 路径，这个候选值得优先比较。若现成 C SPSC record ring 能直接处理调用方提供的字节区域，可复用其并发与 framing；无需因此引入整个消息中间件、共享堆或自动服务发现。具体库可否独立使用，由库级报告核对。

## 4. 移动端需要单独审查的成本

### 4.1 通道与唤醒策略分开选择

shared memory 不会自动唤醒另一进程。固定轮询可能引入无数据时的唤醒；忙轮询更不应从服务器默认配置直接带入手机。这是需要检查的成本，不是本次已经测得的耗电结论。

`eventfd` 是可由 poll/epoll 等待的内核计数通知，支持非阻塞读写。其通知只表示可能有工作，不是 Rust 已消费或持久化 records 的确认；正确读取仍需检查队列。[eventfd(2)](https://man7.org/linux/man-pages/man2/eventfd.2.html)

可以比较低频批量 polling 与合批通知，但不能机械地每条记录唤醒一次，也不能让调度协议丢掉尚未消费的工作。若采用通知，应使用专属的 consumer 通知资源；不能把 VPP worker 自己的 wake fd 交给 Rust 竞争读取。本次没有选定新的 latch、eventfd 数量或 reader 周期。

### 4.2 Android 休眠行为属于兼容性约束

Android 的 Doze / App Standby 会限制或延后部分后台 CPU、网络和定时工作，且前台服务与 Doze 不是同一个概念。通道可用不能推导消费者在深度休眠时按桌面节奏运行。设计应允许消费迟滞、队列有界和明确缺口，不依靠持续 wakelock 将观测变成常驻唤醒负担。[Android Doze / App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby)

这里没有声称本项目 Root/VPN 在每个设备或省电配置下受完全相同限制；具体资格须由实际 artifact 的运行证据确认。也不将 FCM 或远程服务引入本机观测。

### 4.3 依赖成本要看整体

候选比较应同时记录共享区大小、元数据、线程 / 栈、后台服务、轮询和通知行为、C/Rust glue、断开清理与特殊系统调用。低消息时延数字不能代替手机空闲成本；小 payload 的 syscall 与共享内存维护开销都应保留为待测比较项。以上为本项目选型标准，不是候选库的既有性能排名。

## 5. 证据边界

本次只核对一手文档、固定版本源码和项目现状；没有安装依赖、修改产品代码、编译候选、运行 Android 设备或测量吞吐 / 电量。报告证明平台接口与静态适配条件，不证明任一候选已在本产品 Android 通路通过。普通队列与 debug 队列分开这一方向已接受，具体库和传输仍待本次调查汇总后讨论。
