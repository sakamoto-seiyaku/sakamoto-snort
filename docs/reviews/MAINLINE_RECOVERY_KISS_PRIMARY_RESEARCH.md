# VPP-native mainline recovery：KISS 一手资料校验

日期：2026-08-27  
状态：`to-spec` 输入；校验既定恢复方向，不是新的架构决策或实现来源

## 研究问题与边界

本轮只回答一个问题：现有七个 Mainline Recovery Slice 在写成可实施规格时，
还需要锁定哪些**最小约束**，才能让后续小模型按新架构重写产品代码，而不会把
POC、历史 C++ 路线或过度设计带回主线？

资料只取 Android Developers/AOSP、FD.io VPP、Rust 官方文档、Linux/Netfilter 与
libnetfilter_queue 官方文档/源码。官方资料只能证明平台机制和边界；Sakamoto 的
模块划分、恢复顺序与证据判定仍由仓库 ADR 和 Wayfinder 决策负责。

## 结论

现有方向基本正确。规格需要比 Wayfinder 决策更详细，但详细度应停在
**行为、所有权、失败语义、测试 seam 和完成证据**，不应提前固定类、函数、文件、
crate 数量或内部数据结构。

KISS 形状是：

```text
唯一产品验收入口
Device Evidence Harness
  -> 已安装的真实 debug APK / 最小产品控制接口
  -> Android Runtime Supervisor
  -> Rust Product Core / coarse FFI / persistent serialized VAPI
  -> Shared VPP Packet Runtime
  -> Root NFQUEUE 或 VPN TUN + Flow Stack
  -> 真实 Wi-Fi 上的 Controlled LAN endpoint
  -> response + product status + bounded counters + OS/resource residue

补充而非替代：
Host Semantic  -> 快速、穷举、故障语义
Product VPP Graph -> 当前产品 C 源码运行在真实 pinned VPP graph
```

这里的“唯一”指一条产品级验收路径和一套证据格式，不是把所有测试都塞进一个巨大
E2E。Android 官方建议选择能够提供所需反馈的最低测试层，并保持大量小测试、少量
高保真大测试；同时明确承认有些平台事实无法由 unit test 验证。因而，网络/lifecycle
事实应尽早做 Device-native Micro-validation，纯语义与边界组合应留在 Host/VPP Graph
层快速覆盖。[Android testing strategies](https://developer.android.com/training/testing/fundamentals/strategies)

## 应进入恢复规格的最小约束

### 1. 一个真实构建产物，而不是并行“测试产品”

- 恢复期只需要一个官方可安装、可调试的产品 build variant；Host/VPP/device harness
  驱动的必须是同一份产品候选逻辑，不能另建仅供验收的 packet/runtime 实现。
- 构建必须产出可定位的 APK、ABI、VPP/core/plugin/control identity，并在安装后验证实际
  选择的 ABI 和 native artifact。Android Gradle Plugin 将 build variant 定义为 build
  type/flavor 的组合；NDK 库由 Package Manager 从 APK 的 `lib/<abi>/lib<name>.so` 选择，
  因此“构建成功”不能替代 APK 内 artifact 与设备 ABI 的检查。
  [Build variants](https://developer.android.com/build/build-variants),
  [Android ABIs and native packaging](https://developer.android.com/ndk/guides/abis)
- 恢复规格只锁定 debug 产品 lane。release signing、Play 发布、ABI 扩展矩阵和 minified
  release candidate 属于后续 release closure。

### 2. Android Runtime Supervisor 是唯一 lifecycle authority

- Runtime 必须由 started foreground service 拥有；Activity/UI 只是可断开、可重连的
  控制客户端。Android 明确区分 started 与 bound 生命周期：started service 不因发起它的
  Activity 被销毁而停止；纯 bound service 在最后一个客户端解绑后会被销毁。
  [Services overview](https://developer.android.com/develop/background-work/services),
  [Bound services](https://developer.android.com/develop/background-work/services/bound-services)
- `start(profile)`、`switch(profile)`、`stop()` 和状态观察必须进入同一个串行 lifecycle
  状态机。官方资料不规定这个 API，但 Android 可能终止 app process，且 Service 默认仍在
  其进程 main thread 上运行；VPP 启动、握手、drain 和清理必须离开 main thread。
  [Processes and threads](https://developer.android.com/guide/components/processes-and-threads),
  [Service threading warning](https://developer.android.com/develop/background-work/services)
- FGS 启动必须来自 Android 允许的上下文，先 `startForegroundService()`，再及时 promote
  并显示 notification；manifest/runtime 使用的 service type 和权限必须匹配目标 API。
  [Launch a foreground service](https://developer.android.com/develop/background-work/services/fgs/launch),
  [FGS start restrictions](https://developer.android.com/develop/background-work/services/fgs/restrictions-bg-start)
- 规格应要求“为 Root/VPN 各自选择并验证合法 FGS type”，但不应把一个 type 写成跨 Profile
  常量。`systemExempted` 只有列举的资格可以使用，其中包括经系统设置配置的 VPN app；
  不满足条件会抛出 `ForegroundServiceTypeNotAllowedException`。`specialUse` 则要求 manifest
  subtype 说明并进入商店审查。
  [Foreground service types](https://developer.android.com/develop/background-work/services/fgs/service-types)

### 3. VPN 恢复必须遵守 Android 的真实 TUN/socket 生命周期

- `VpnService.prepare()` 是授权 gate；权利可随时撤销。`Builder.establish()` 返回 TUN fd，
  `onRevoke()` 时应关闭 fd 并完成 graceful shutdown。
- `protect()` 只让 app 创建的 socket 绕过 VPN，防止它重新进入 TUN；它不会把一个 TUN
  packet 变成可转发的 kernel flow。这支持现有“VPN Flow Stack + protected socket”边界，
  不支持 Java/Rust 逐包转发或直接把原包交给 `protect()`。
  [VpnService API](https://developer.android.com/reference/android/net/VpnService),
  [VPN developer guide](https://developer.android.com/develop/connectivity/vpn)
- Direct socket 必须在 connect/first send 前绑定当前 `Network` 并成功 protect；
  `Network.bindSocket()` 要求 socket 尚未 connected。网络变化通过有序的
  `NetworkCallback` 参数建立新 underlay snapshot，不能在 callback 内同步反查并假设结果仍
  最新。Wi-Fi off/on 因而是一个真实 network-epoch Micro-validation，而不是普通 reconnect
  单元测试。
  [Network.bindSocket](https://developer.android.com/reference/android/net/Network),
  [NetworkCallback ordering and loss](https://developer.android.com/reference/android/net/ConnectivityManager.NetworkCallback),
  [Read network state](https://developer.android.com/develop/connectivity/network-ops/reading-network-state)

### 4. 一个产品 VPP plugin；“已加载”不等于 ready

- 正式数据面应是一个 `add_vpp_plugin()` 产品 target，包含 C source、必要的 graph node 和
  一个小型版本化 `.api`。FD.io 的插件构建本身已把 source、API 与 API tests 组织在同一
  plugin target 中；没有平台依据要求按 Adapter/Parser/Policy 再拆多个 `.so`。
  [Adding a VPP plugin](https://docs.fd.io/vpp/24.06/developer/plugindoc/add_plugin.html)
- init 只注册能力和最小静态状态；queue、pool、process 等动态资源应在显式配置/enable 时
  创建。FD.io 插件指南明确反对在 `VLIB_INIT_FUNCTION` 中无条件创建动态结构。
  [VPP plugin strategic choices](https://docs.fd.io/vpp/22.06.1/developer/plugindoc/add_plugin.html#strategic-choices)
- plugin loader 成功、PID 存在、API socket 存在都只能证明局部事实。恢复规格必须保留一个
  **plugin-owned coarse readiness/status API**，至少能把 artifact/API identity、runtime
  generation、selected Adapter、Adapter state、last stable error 和 outstanding residue 与
  `ready` 分开。字段集合是 Sakamoto 选择；FD.io 只提供生成的 typed request/reply、context
  matching 和 API semantic version 机制。
  [VPP API module](https://docs.fd.io/vpp/25.06/interfacing/binapi/vpp_api_module.html),
  [VPP API language](https://docs.fd.io/vpp/25.06/interfacing/binapi/vpp_api_language.html)
- `ready` 只能在当前 generation 的 Adapter 资源已接入并能完成其 origin obligation 后发布；
  VAPI connect 或 `show_version` 只证明 core/API transport，不证明 NFQUEUE/TUN/Flow Stack
  能收发。

### 5. Rust/C 边界保持 coarse、typed、non-unwinding

- Rust Product Core 每个 active runtime generation 只持有一个 opaque VAPI client handle，
  初版保持 persistent + serialized + blocking。VPP 官方说明 blocking high-level C API 在请求
  内等待 reply，且 outstanding request queue 最多一个；non-blocking 模式需要应用自行 dispatch
  或增加专用 dispatch thread。当前恢复没有引入后者的必要。
  [VPP API blocking and non-blocking modes](https://docs.fd.io/vpp/25.06/interfacing/binapi/vpp_api_module.html)
- ABI 只传固定宽度 scalar、显式长度的 POD、integer status/tag 和 opaque handle；不传 Rust
  默认布局的对象、trait object、String/Vec、live VPP buffer 或 packet bytes。Rust Reference
  说明默认 Rust layout 可变化，`#[repr(C)]` 才提供 C layout；它也警告用 Rust fieldless enum
  直接表示可含任意整数值的 C enum 经常是错误的。
  [Rust type layout](https://doc.rust-lang.org/reference/type-layout.html),
  [Rust opaque FFI types](https://doc.rust-lang.org/nomicon/ffi.html#representing-opaque-structs)
- ordinary failure 使用明确返回值；panic/foreign exception 不跨 `extern "C"`。Rust 官方说明
  wrong unwinding ABI 会产生 undefined behavior，`catch_unwind` 也不是普通错误处理机制。
  [Rust FFI unwinding](https://doc.rust-lang.org/reference/panic.html#unwinding-across-ffi-boundaries),
  [`catch_unwind`](https://doc.rust-lang.org/std/panic/fn.catch_unwind.html)
- coarse synchronous seam 也避免异步 foreign callback 生命周期：Rustonomicon 要求外部库在
  Rust 对象销毁后绝不能继续回调，并要求跨线程 callback 显式同步。恢复基线没有必要为 VAPI
  引入这一套额外生命周期。
  [Rust asynchronous FFI callbacks](https://doc.rust-lang.org/nomicon/ffi.html#asynchronous-callbacks)

### 6. NFQUEUE completion 要求 at-most-one physical verdict + exactly-once internal settlement

- Netfilter 为 queue 内 packet 提供 packet ID；userspace 必须为每个已排队 packet 提交
  verdict，accept/drop verdict 会把 packet 从 queue 取走。queue 满时新 packet 由 kernel
  丢弃。这要求 queue、credit 与 outstanding obligation 从第一步就有界。
  [libnetfilter_queue overview](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/),
  [queue and verdict API](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__Queue.html),
  [Linux NFQUEUE UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/netfilter/nfnetlink_queue.h)
- Kernel 以 packet ID 查找并 dequeue 一项；queue instance 销毁时会将尚未结算的项 flush 为
  `NF_DROP`。这支持“origin lane 独占 queue/verdict、generation + packet ID ledger、stop 时
  先 quiesce 再 drain/flush”的实现约束。
  [Linux `nfnetlink_queue.c`](https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink_queue.c)
- 官方接口没有提供 Sakamoto 的 exactly-once abstraction。libnetfilter_queue 的 verdict
  message 使用 packet ID，但其发送路径不是一项可安全重放的业务事务；官方 API 只返回本次
  调用成功或错误。因此规格必须自行规定：一个 origin obligation 最多一次 physical verdict
  attempt；其内部 ledger 恰好一次落入 `SUCCEEDED`、`FAILED_DEFINITE` 或
  `OUTCOME_UNKNOWN`；duplicate/stale 不重发；ambiguous outcome 也不自动 retry。
  [libnetfilter_queue verdict implementation](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/libnetfilter__queue_8c_source.html),
  [verdict message builder](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__nfq__verd.html)
- “哪一个 errno/teardown race 属于 definite 或 unknown”必须由 pinned kernel/device fault tests
  固定，不能仅从通用文档推断。

### 7. 最高产品验收 seam 与三层证据各司其职

恢复规格应只暴露一套产品级控制/观察 seam：

1. Harness 构建、安装并核对当前 APK/artifact identity；
2. 通过普通产品控制入口启动或切换 Profile，而不是直接调用内部 graph node；
3. 等待 versioned product readiness；
4. 从真实 device application/fixture 产生目标流量；
5. Controlled LAN endpoint 与产品状态共同判定结果；
6. stop/fault 后检查 Android、kernel、VPP 与 product ledger residue。

Android 将使用 deployable debuggable binary 的 application test 与在接近生产环境运行的
release-candidate test 归为高保真测试；VPP 自己的 functional framework 则通过真实 VPP
packet-generator/graph 注入并捕获 packet。这共同支持三层 Product Evidence Stack，而不是
用 mock/历史 POC 替代产品行为。
[Android testing strategies](https://developer.android.com/training/testing/fundamentals/strategies),
[VPP Test Framework](https://docs.fd.io/vpp/21.06/vpp_make_test/html/),
[VPP packet generator](https://docs.fd.io/vpp/25.06/aboutvpp/featurelist.html#pg)

KISS 分工：

- **Host Semantic**：纯 parser、key、winner、state transition、failure partition、ledger model；
- **Product VPP Graph**：同一产品 C source、真实 pinned VPP init/API/node/buffer/handoff；
- **Android Device**：artifact、Service/FGS、root/NFQUEUE、VpnService/TUN、protected socket、
  Wi-Fi epoch、CPU affinity 与 OS residue；
- 一个 claim 只携带其必要证据层。Host PASS 不能覆盖有效 Device FAIL。

### 8. Controlled LAN 是当前最小、确定性的 device network oracle

Android 官方建议关键 E2E 使用真实 deployable binary 和受控 staging backend，并指出大型
异步测试必须通过同步和确定性避免 flake；它没有规定 Sakamoto 必须使用公网或 LAN。
[Android testing strategies](https://developer.android.com/training/testing/fundamentals/strategies),
[Big test stability](https://developer.android.com/training/testing/instrumented-tests/stability)

结合当前单机、单设备、真实 Wi-Fi 环境，恢复规格应固定以下**项目选择**：

- blocking matrix 为 IPv4 TCP、IPv4 UDP、IPv6 TCP、IPv6 UDP；每格都由受控 endpoint
  先发布 readiness，再完成带唯一 nonce 的 request/response；
- 保存 artifact/revision、Profile/generation、family/protocol/direction、双方 tuple、nonce、
  bytes、product reason/status 和 residue；超时前先证明 endpoint 与 Wi-Fi fixture 仍 ready；
- Root 至少覆盖 device OUTPUT 与 LAN host -> device INPUT；VPN 覆盖
  TUN-origin -> protected Direct socket -> LAN endpoint -> return TUN；
- LAN IPv6 只证明双栈 packet/transport 路径，不声称公网 IPv6；公共 IPv4 HTTPS 是后续
  narrow smoke，公共 IPv6 在环境不提供时记 `NOT RUN`，不阻塞；
- 不用 device loopback 证明 underlay，不用 DNS 代替 UDP，不依赖不受控公共 UDP echo。

nonce/tuple/双向字节是测试 oracle，不是 product telemetry schema。Android `DatagramSocket`
本身只提供 datagram endpoint，packet 可能乱序；一次真实 nonce response 才能把 UDP cell 与
本次请求关联。
[Android DatagramSocket](https://developer.android.com/reference/java/net/DatagramSocket)

### 9. 每个 Microstep 只证明一个可运行事实

- Android 官方建议尽早加入测试，并选择能提供正确反馈的最低层；大 E2E 更高保真但成本更
  高。因此每个 Microstep 应有：一个 claim、一个 seam、最小 input/output、一个决定性
  oracle、一个 residue/failure boundary、一个 next unlock。
  [Android testing strategies](https://developer.android.com/training/testing/fundamentals/strategies)
- 当平台事实第一次可运行时立刻做 Device-native Micro-validation，例如：真实 APK 启动 VPP、
  第一条 Root IPv4 OUTPUT、第一条 VPN UDP return、Wi-Fi epoch、profile switch。不要等整个
  Slice 完成，也不要把普通 unit test 搬到手机上冒充 device evidence。
- Microstep 是规格内有序梯子，不自动成为 Plane issue。只有能独立领取，或形成真实 blocking
  edge 时才拆票；单设备串行只是调度约束。

### 10. telemetry 只保留完成判定所需的低基数事实

- 恢复基线只要求固定状态、last stable error、少量 reason counters、outstanding/high-watermark
  和 stop 后 residue。VPP 已有 node/error/system counters 与只读 stats segment，无需先造通用
  telemetry pipeline。
  [VPP statistics](https://docs.fd.io/vpp/19.04.2/stats_doc.html),
  [VPP startup `statseg` configuration](https://github.com/FDio/vpp/blob/master/src/vpp/conf/startup.conf)
- VPP Host Stack Test Framework 也把 memory trace 前后比较作为独立 leak test；这支持把
  resource/residue 作为 cross-cutting obligation，而不是为恢复期搭建 dashboard。
  [VPP Host Stack test memory-leak support](https://docs.fd.io/vpp/25.06/developer/extras/hs_test.html#memory-leak-testing)

## 应延后

以下内容不增加当前“能真实启动、收发、停止并恢复”的决定性证据，应明确放在 Out of Scope：

- 完整 UI/视觉设计、广泛 Tauri command catalog、用户级 telemetry dashboard；恢复期只需最小
  start/profile/status/stop/apply/query 控件或由 harness 走相同产品接口。
- async/non-blocking VAPI、多个 VAPI session、连接池、通用 retry/backoff framework、跨
  generation 自动 replay。
- full Conntrack、LPI、DNS/domain policy、复杂 Traffic Windows/diagnostics、全量 Activity
  pipeline。
- public UDP service、公网 IPv6 blocking gate、多 endpoint/multi-network 并行；当前单设备按
  Controlled LAN 串行运行。
- 动态 plugin discovery/hot reload、多个 product plugin、per-module health framework、运行时
  worker resize、自适应 capacity。
- 电量、温度、Doze、长 soak、多 OEM、release signing/Play policy closure、正式 SLO 和最终
  queue/worker/buffer/timeout tuning。
- 以“最佳实践”为名引入 Kotlin、额外进程、AIDL framework、DI framework、mock framework 或
  新数据库。平台官方允许这些机制，但没有事实说明它们是本次恢复的必要条件。

## 官方资料不能决定、必须保留为项目选择

| 项目选择 | 官方资料能确定什么 | 规格中应如何处理 |
|---|---|---|
| `RuntimeService` 与 `VpnService` 是一个类还是两个薄入口 | started/bound/VpnService 生命周期规则 | 只锁一个 supervisor authority 和一个 active Profile，不锁 class count |
| runtime 是否独立 Android process | manifest 可选择 process；多数 app 默认同一 process | 不作为恢复 blocking gate，除非故障隔离证据要求 |
| Root/VPN 的具体 FGS type | type/permission/资格规则 | 对目标 API/安装形态做独立合法性测试，不跨 Profile 猜同一答案 |
| JNI/Binder/Unix socket 的精确组合 | Android/Rust 只给各自机制与安全约束 | 只锁 coarse non-packet control seam、version、generation 和 failure contract |
| Rust crate 数、Java class 数、C 文件数 | 无 | 让接口保持深，按独立 artifact/unsafe boundary 才拆 |
| plugin status 字段、timeout、capacity、queue/worker/core 数 | VPP 提供机制，不提供 Sakamoto 常量 | 规格锁 required observations；数值由 current-head measurement 选择 |
| NFQUEUE errno 的 definite/unknown 分类 | API、packet ID、kernel queue/flush 语义 | 用 pinned kernel/device fault injection 固定，不从通用文档猜 |
| Controlled LAN endpoint 的语言/进程和端口 | Android 只要求测试策略确定且高保真 | Harness 私有；只锁 readiness、nonce、tuple、bytes、双栈 TCP/UDP oracle |
| 外部 ADB harness 还是 instrumentation runner | Android 两者都可支持 device test | 优先复用 repo `./dev/adb` 与现有 harness；不新建第二控制面 |
| 每个 Microstep 是否独立成票 | 无 | 只按独立可领取或真实 blocker 拆票 |

## 对 `to-spec` 的直接建议

规格不需要再做一轮 Wayfinder。它应把七个 Slice 各自写成同一组字段：

1. exact capability claim；
2. authority/ownership 与不得跨越的 seam；
3. ordered Recovery Microsteps；
4. readiness、failure、generation 与 cleanup contract；
5. Recovery Acceptance Card：Required Evidence / Cases / Oracle / Non-claims；
6. POC 只允许带入的事实、vectors、failure modes 与明确禁止导入的 source shape；
7. 本 Slice 完成后唯一 next unlock。

这样给实现模型的指导足够具体：它不能误解所有权和完成语义，也不能用 mock/旧 POC 冒充
产品证据；同时仍保留局部实现自由，避免在没有 current-head feedback 前设计整个产品。
