# 当前 HEAD C++ 并发 / 内存安全专项审查

审查目标：原始仓库 HEAD `67477db`；后续修复状态按当前工作树更新。

审查模式：原始报告只审查，不修代码、不重构、不提交 patch。后续标记为 `[FIXED]` 的 finding 表示已在当前工作树中修复，并补充实际修复方式。

修复状态摘要：

- `[FIXED]` 两项 CRITICAL 已通过 reset/save coordinator + reset epoch 边界修复。
- `[FIXED]` 一项 HIGH 已通过冻结 legacy `Streamable` 输出修复；vNext `STREAM.START(type=...)` 是受支持的实时观测入口。
- 未标记 `[FIXED]` 的 HIGH / MEDIUM / LOW 仍按原 finding 处理，尚未在本轮修复。
- 本轮属于运行期并发边界设计收敛：对外 `RESETALL` 语义不变，但内部从“仅依赖 `mutexListeners`”调整为“save/reset coordinator + reset epoch + 短共享锁发布窗口”。
- reset 并发边界设计文档已新增：`docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md`。

## 审查地图

### 锁图

- 全局静默锁：`mutexListeners`，定义于 `src/SnortRuntime.cpp:10`。
  - 启动阶段在 restore manager 与启动 listener 时持有独占锁。
  - Packet / DNS 热路径使用 reset epoch 先读后校验；只有判决、状态更新、manager 对象发布窗口持有共享锁。
  - legacy / vNext `RESETALL` 不再由各自 dispatch 外层直接持有该锁，而是统一进入 `snortResetAll()`。
  - vNext control 对 `CONFIG.SET`、domain apply/import、`IPRULES.APPLY`、`METRICS.RESET` 仍使用独占锁。
- reset/save coordinator：
  - `g_snortSaveResetMutex` 定义于 `src/sucre-snort.cpp:47`，串行化周期性 `snortSave()` 与完整 `snortResetAll()`。
  - reset epoch 定义于 `src/SnortRuntime.cpp:14`；偶数表示稳定，奇数表示 reset 进行中。
  - `snortResetAll()` 的锁顺序固定为 `g_snortSaveResetMutex` → `mutexListeners` 独占锁。
- Manager 内部锁：
  - `AppManager`：`_mutexByUid`、`_mutexByName`。
  - `DomainManager`：`_mutexByName`、`_mutexByIP`；单个 domain 的 IP set 使用 `Domain::_mutexIP`。
  - `HostManager`：`_mutexHosts`、`_mutexName`、`_mutexIP`。
  - `BlockingListManager`、`RulesManager`、`DomainList`、`CustomList`、`CustomRules` 各自有内部锁。
- Stream 锁：
  - legacy `Streamable`：`_mutexItems` 与 `_mutexSockios`。
  - vNext stream manager：DNS / PKT / activity 各自独立 mutex，并配合 atomic subscribed flag。
- Conntrack：
  - 每个 shard 的 `std::mutex` 保护结构性 insert / unlink。
  - 无锁读者通过 atomic bucket / next 指针遍历，并用 epoch guard 延迟回收。
- Socket 写：
  - legacy `SocketIO::_mutex` 串行化阻塞式 `write()`。
  - vNext `FrameWriter` 使用 non-blocking fd write，但命令响应的 `flushBlocking()` 仍可能等待写缓冲 drain。

### 所有权图

- 长生命周期全局对象在 `src/sucre-snort.cpp:25` 到 `src/sucre-snort.cpp:39` 构造。
- 大多数 listener / control / client worker 都是 detached thread，并捕获 `this` 或 raw fd。
- `App`、`Domain`、`Host`、`Rule`、stream event、IPRULES snapshot 主要通过 `shared_ptr` 持有。
- Conntrack entry 是 raw `Entry *` 节点，由 shard bucket / retired list 拥有，并通过 epoch 机制回收。
- legacy control session 持有 `SocketIO::Ptr`；vNext session 持有 `UniqueFd`，但 stream manager 只保存 raw subscriber fd。
- thread-local cache 分布在 Conntrack epoch slot、IPRULES decision cache、metrics shard、packet listener queue state 中。

## Findings

### [CRITICAL][FIXED] `RESETALL` 与周期性 `snortSave()` 竞态，可能把已清空状态重新写回磁盘

修复状态：已修复。

性质判断：实现问题触发的设计边界缺口。`RESETALL` 的产品语义本来要求 reset / clear / final save 原子化，但原实现没有把完整 pipeline 与周期性 save 串行化，因此需要补一条明确的运行期边界。

实际修复：

- 新增统一 reset/save coordinator：`snortSave()` 与 `snortResetAll()` 共用 `g_snortSaveResetMutex`，使周期保存与完整 reset pipeline 串行化。
- `snortResetAll()` 在同一临界区内完成 stream reset、settings / managers reset、save tree 清理与最终 clean save，避免 reset 后旧 snapshot 重新落盘。
- legacy `Control::cmdResetAll()` 与 vNext `RESETALL` 均改为调用 `snortResetAll()`，不再各自维护 reset 列表。
- `Settings::reset()` 已在修改 `_password` / `_passState` 时持有 `_mutexPassword`，消除与 `Settings::save()` 的密码字段 data race。
- 已验证：`cmake --build --preset dev-debug --target snort-build`、`cmake --build --preset dev-debug --target snort-host-tests`、`cmake --build --preset dev-debug --target snort-host-tests-asan` 通过。

修复后影响：

- 对 packet / DNS 热路径没有新增锁；新增的 `g_snortSaveResetMutex` 只覆盖 `snortSave()` 与 `snortResetAll()`。
- 周期保存与 `RESETALL` 现在会互斥，预期影响只出现在低频 save/reset 窗口；这正是避免旧 snapshot 回写的必要语义。
- `Settings::reset()` 新增密码锁只影响 reset 控制路径，不进入 packet / DNS 判决路径。

- 当前修复位置：`src/sucre-snort.cpp:47`、`src/sucre-snort.cpp:152`、`src/sucre-snort.cpp:157`、`src/ControlVNextSessionCommandsDaemon.cpp:108`、`src/Control.cpp:1385`、`src/Settings.hpp:196`、`src/Settings.hpp:202`。
- 原始代码事实：main loop 会周期性调用 `snortSave()`，且不持有 `mutexListeners`；`RESETALL` 在最终调用 `snortSave()` 前会 mutate settings / managers 并清空 save tree。`g_snortSaveMutex` 只串行化 `snortSave()` 调用本身，不保护 reset / clear 阶段。
- 触发 interleaving：
  - Thread A：周期性 main loop 进入 `snortSave()`，在 `AppManager::save()` 中 snapshot app 指针，或在 `Settings::save()` 中读取 `_password`。
  - Thread B：control thread 处理 `RESETALL`，调用 `settings.reset()`、`Settings::clearSaveTreeForResetAll()`、`appManager.reset()`，但这些操作发生在取得 `g_snortSaveMutex` 之前。
  - Thread A：继续用旧 snapshot 写 app 文件；或在 `settings.reset()` 无锁清空 `_password` 时并发读取 `_password`。
- 失败模式：`Settings::_password` data race；持久化撕裂；被 `RESETALL` 删除的 app / domain / rule 状态可能重新落盘。
- 影响面：保存 / 重置、控制面、后续 restore 状态；`RESETALL` 可能表面成功但旧状态残留。
- 原始修复方向：把 reset 与 save 做成同一个串行化 pipeline。例如新增 `snortResetAllAndSave()`，在同一把 save/reset mutex 下完成所有 reset mutation、save-tree 删除与最终 save；同时让 `Settings::reset()` 在修改 `_password` 时持有 `_mutexPassword`。
- 验证建议：增加 host stress：循环 `snortSave()` 并同时触发 legacy / vNext `RESETALL`；用 TSan 与 ASAN 跑；每次 reset 后断言 save 目录没有旧 app / rule / list 文件。

### [CRITICAL][FIXED] 热路径锁外准备的 `App` / `Domain` / `Host` 可能在 `RESETALL` 后继续使用

修复状态：已修复。

性质判断：实现问题触发的并发设计缺口。锁外做昂贵准备是正确方向，但原边界没有区分“可丢弃准备”和“发布到 manager / 参与判决”，导致 `RESETALL` 后仍可能发布 reset 前对象；因此需要把发布窗口显式纳入 reset epoch。

实际修复：

- 引入 reset epoch：热路径进入 phase 1 前读取 epoch，进入 `mutexListeners` shared lock 后重新校验；epoch 变化或 reset 进行中时丢弃本轮准备并重试。
- Packet 路径不再在锁外直接 `make()` 发布 manager 对象；锁外只做 `find()` 与可丢弃的 `prepare()`，锁内通过 `publishPrepared()` 发布当前 epoch 对象。
- Host reverse-DNS 仍在锁外执行，锁内只做 IP / host map 发布，避免把慢 DNS 反查放入全局共享锁窗口。
- DNS 路径将 `App` / `Domain` 发布和初始判决放入同一 epoch 校验窗口；后续 IP add、stats、vNext stream enqueue 在每个短锁窗口继续校验同一 epoch，跨 reset 则跳过 stale 写入。legacy stream 已冻结为 no-op。
- `App` 构造不再执行 `Settings::ensureUserDirs()`；目录创建延迟到 `App::save()` / rename 需要时，避免锁外 prepare 在 reset 期间重新创建 save tree。
- `PackageListener::updatePackages()` 在应用 install/remove 到 `AppManager` 时持有 `mutexListeners` shared lock，避免包更新绕过 reset 边界。
- 已验证：`cmake --build --preset dev-debug --target snort-build`、`cmake --build --preset dev-debug --target snort-host-tests`、`cmake --build --preset dev-debug --target snort-host-tests-asan` 通过。

修复后影响：

- 稳态 packet / DNS 路径新增一次 epoch atomic load，并在原本已有的 `mutexListeners` shared lock 窗口内做一次 epoch compare；预期接近噪声。
- 首次 UID / IP / domain 发布仍在短共享锁窗口内完成；慢 reverse-DNS、包解析、对象准备仍保留在锁外。
- 只有与 `RESETALL` 重叠时会丢弃准备对象并重试；该窗口本来就需要让 reset 独占完成，延迟尖峰应只出现在 reset 期间。
- 当前未写死百分比预算；后续应以 `nfq_total_us`、`dns_decision_us` 和 reset stress 数据确认是否可观测。

- 当前修复位置：`src/SnortRuntime.cpp:14`、`src/SnortRuntime.cpp:18`、`src/PacketListener.cpp:362`、`src/PacketListener.cpp:383`、`src/DnsListener.cpp:210`、`src/DnsListener.cpp:220`、`src/DnsListener.cpp:282`、`src/DnsListener.cpp:294`、`src/DnsListener.cpp:302`、`src/DnsListener.cpp:310`、`src/AppManager.cpp:61`、`src/AppManager.cpp:63`、`src/HostManager.hpp:108`、`src/HostManager.hpp:127`、`src/App.cpp:23`、`src/App.cpp:224`、`src/PackageListener.cpp:390`、`tests/host/reset_epoch_tests.cpp:5`。
- 原始代码事实：packet 与 DNS 路径会在取得 `mutexListeners` 之前创建或获取 `App`、`Domain`、`Host` 对象。`RESETALL` 的独占锁只排斥后续共享锁内的判决 / 更新窗口，不排斥前置对象获取窗口。
- 触发 interleaving：
  - Thread A：packet callback 执行 phase 1，拿到 `appManager.make(uid)` 和 `hostManager.make(remoteIp)`，但尚未取得 `mutexListeners`。
  - Thread B：`RESETALL` 取得独占 `mutexListeners`，清空 managers 并保存 reset 状态。
  - Thread A：reset 后取得共享 `mutexListeners`，继续使用 reset 前的 `shared_ptr` 做 policy / stats / streaming。
  - DNS 同样存在该形态：在共享锁前拿到 `app` 与 `domain`，reset 后仍可能调用 `domManager.addIPBoth(domain, ip)`。
- 失败模式：wrong verdict、旧状态污染状态表、可观测性撕裂。reset 前的 app / domain policy 可能在 reset 后继续参与判决；DNS 可能为 `_byName` 中已不存在的 domain 插入 IP 映射。
- 影响面：NFQUEUE verdict、DNS policy、domain/IP map、app stats、activity / stream 输出、reset 语义。
- 原始修复方向：引入 reset generation / epoch。phase 1 前捕获 generation，在 `mutexListeners` 内重新检查；如 generation 变化则丢弃并重新加载 phase-1 对象。或者只把昂贵 reverse-DNS / 文件探测留在锁外，manager 对象发布放进共享锁窗口。
- 验证建议：真机 stress：并发执行 `RESETALL`、DNS inject、IP traffic；断言 reset 后没有 packet / DNS event 引用 reset 前 app settings 或 domain，且不存在只残留在 IP map 中的 stale domain。

### [HIGH][FIXED] Legacy stream 同步写会阻塞热路径 verdict 并饿死 `RESETALL`

修复状态：已修复。

性质判断：设计问题。legacy `DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 把调试流输出设计成热路径内同步 socket write；即使具体实现正确处理 partial write，也无法避免慢消费者反压 `mutexListeners` shared lock 与 NFQUEUE verdict。

实际修复：

- 冻结 legacy `Streamable<T>`：`stream()` 不再保存事件或写 socket，`startStream()` 不再 replay 或注册订阅 socket。
- legacy control 命令名与既有 wire shape 保留；不新增错误格式，不把旧 START 改成新的 `NOK`/结构化错误。
- 实时观测支持路径统一到 vNext `STREAM.START(type=dns|pkt|activity)`，该路径使用有界 ring / pending queue 与 non-blocking writer。
- 已同步接口/设计文档，把 legacy stream 标记为 frozen/no-op。

修复后影响：

- packet / DNS / activity 热路径不再因为 legacy stream 慢读客户端进入阻塞式 `SocketIO::print()`。
- legacy stream 客户端将收不到旧事件流；这是冻结策略的预期兼容取舍。
- vNext stream 行为不变，仍是后续验证实时观测能力的唯一支持入口。

- 当前修复位置：`src/Streamable.cpp:25`、`src/Streamable.cpp:29`、`src/Control.cpp:2223`、`tests/host/host_gap_tests.cpp:265`、`tests/host/host_gap_tests.cpp:441`。

- 原始位置：`src/PacketManager.hpp:175`、`src/PacketManager.hpp:250`、`src/PacketManager.hpp:301`、`src/DnsListener.cpp:283`、`src/Streamable.cpp:29`、`src/Streamable.cpp:36`、`src/SocketIO.cpp:25`、`src/SocketIO.cpp:36`、`src/Control.cpp:1590`、`src/Control.cpp:1606`。
- 原始代码事实：tracked packet / DNS 路径在全局共享判决窗口内调用 legacy `Streamable::stream()`。旧实现持有 item / socket 锁，并对每个 legacy stream socket 调用阻塞式 `SocketIO::print()`。
- 原始触发 interleaving：
  - Thread A：legacy client 启动 `PKTSTREAM.START` 或 `DNSSTREAM.START` 后停止读取。
  - Thread B：tracked app 的 NFQUEUE packet 在共享 `mutexListeners` 下进入 `PacketManager::make()`，调用 `Streamable<Packet>::stream()`，并阻塞在 `SocketIO::print()`。
  - Thread C：`RESETALL` 或其他需要独占锁的命令无限等待共享 `mutexListeners` 释放。
- 原始失败模式：hot-path stall、`RESETALL` starvation、NFQUEUE backlog；最终表现取决于 kernel queue 状态，可能 fail-open 或 fail-closed。
- 原始影响面：NFQUEUE verdict 延迟、DNS stats streaming、legacy control stream client、reset 响应性。
- 当前验证口径：host test 断言 legacy `Streamable` 与 `ActivityManager` stream 不再 replay/输出消息；慢读 legacy stream client 不再能把热路径带入 socket write。

### [HIGH] vNext 独占命令在全局锁内执行大 CPU / 文件工作，会阻塞 packet 热路径

- 位置：`src/ControlVNextSession.cpp:426`、`src/ControlVNextSession.cpp:428`、`src/ControlVNextSessionCommandsDomain.cpp:1321`、`src/ControlVNextSessionCommandsDomain.cpp:1408`、`src/ControlVNextSessionCommandsDomain.cpp:1473`、`src/DomainList.cpp:187`、`src/DomainList.cpp:206`、`src/IpRulesEngine.cpp:998`、`src/IpRulesEngine.cpp:1001`、`src/ControlVNextSessionCommandsIpRules.cpp:945`。
- 当前代码事实：vNext dispatch 在运行 `DOMAINLISTS.IMPORT`、`DOMAINLISTS.APPLY`、`DOMAINPOLICY.APPLY`、`DOMAINRULES.APPLY`、`IPRULES.APPLY` 前先取得独占 `mutexListeners`。`DOMAINLISTS.IMPORT` 可校验最多 1,000,000 个 domain / 16 MiB payload，并在独占锁内写 temp file + rename。IPRULES apply 也在同一全局锁内 compile / replace rule snapshot。
- 触发 interleaving：
  - Thread A：vNext client 发送大 `DOMAINLISTS.IMPORT` 或大 `IPRULES.APPLY`。
  - Thread A：持有独占 `mutexListeners` 执行 parse、compile 或 list 文件写入。
  - Thread B：NFQUEUE callback 到达 `PacketListener.cpp:374`，等待共享 `mutexListeners` 才能发 verdict。
- 失败模式：hot-path stall、packet backlog、明显 tail latency spike；这不是 data race，但全局静默窗口过大。
- 影响面：NFQUEUE、DNS 判决窗口、vNext control 扩展性、大 domain / IP ruleset 操作。
- 最小修复方向：这些命令改成 two-phase：parse / validate / compile / temp-file write 在 `mutexListeners` 外完成，只在发布内存 snapshot 与更新 metadata 时短暂持有独占锁；内部一致性由 manager-local locks 保证。
- 验证建议：并发运行 `dx-casebook-other` 大 domain/import 与 IP ruleset sanity，以及 `tests/device/ip/run.sh --profile perf|stress`；断言 control-plane import 期间 `nfq_total_us` 不出现尖峰。

### [HIGH] SIGTERM / SIGINT 处理可能让退出延迟最长达到保存周期

- 位置：`src/sucre-snort.cpp:43`、`src/sucre-snort.cpp:122`、`src/sucre-snort.cpp:135`、`src/sucre-snort.cpp:149`。
- 当前代码事实：signal handler 只设置 `g_quit_flag`。main loop 只在 `snortSave()` 前后检查该 flag，随后调用 `std::this_thread::sleep_for(settings.saveInterval)`，当前保存间隔为 1 小时。信号可能投递到任意未屏蔽线程，不能保证唤醒正在 sleep 的 main thread。
- 触发 interleaving：
  - Thread A：main loop 完成 `snortSave()` 后进入 `sleep_for(saveInterval)`。
  - Thread B：某个 detached worker 收到 SIGTERM / SIGINT，并设置 `g_quit_flag`。
  - Thread A：直到实现主动唤醒或完整 sleep interval 结束前，都可能不执行最终保存 / 退出。
- 失败模式：退出卡住 / 长时间延迟；Android / service supervisor 升级终止前可能没有完成 final save。
- 影响面：daemon lifecycle、shutdown persistence、fd/socket 清理预期。
- 最小修复方向：用 `sigwait` / `signalfd` / self-pipe 配合 condition variable 或 eventfd 代替被动轮询；收到信号后立即唤醒 main loop 并执行一次 final save。
- 验证建议：真机 lifecycle 测试：在 save sleep 的不同时间点反复发送 SIGTERM，断言退出延迟有上界且 final save 完成。

### [MEDIUM] vNext suppressed stream counter 在 take-and-reset 时会丢增量

- 位置：`src/ControlVNextStreamManager.cpp:335`、`src/ControlVNextStreamManager.cpp:341`、`src/TrafficCounters.hpp:64`、`src/TrafficCounters.hpp:57`、`src/ControlVNextSession.cpp:463`。
- 当前代码事实：`takeSuppressedTraffic()` 先调用 `TrafficCounters::snapshot()`，再调用 `TrafficCounters::reset()`。热路径并发调用 `observeDnsSuppressed()` / `observePktSuppressed()`，计数使用 relaxed atomic increment。
- 触发 interleaving：
  - Thread A：stream session snapshot suppressed counters，读取某个 bucket 值为 `N`。
  - Thread B：packet / DNS 热路径把同一个 bucket 加到 `N+1`。
  - Thread A：调用 `reset()` store 0，擦掉 Thread B 的增量，且该增量未进入当前 notice。
- 失败模式：可观测性撕裂；并发负载下 suppressed traffic notice 低估。
- 影响面：vNext DNS / PKT stream suppressed notice；不影响 verdict。
- 最小修复方向：把 snapshot-then-reset 改为每个 counter 使用 `exchange(0)`，保证每个增量要么进入当前 notice，要么进入下一次 notice。
- 验证建议：增加 host 并发测试：`takeSuppressedTraffic()` 与 observe loop 并行；真机 stream stress 产生 untracked traffic 并检查 aggregate count 单调一致。

### [MEDIUM] `resetAll()` 返回 raw stream fd，缺少生命周期所有权

- 位置：`src/ControlVNextStreamManager.hpp:110`、`src/ControlVNextStreamManager.cpp:261`、`src/ControlVNextSessionCommandsDaemon.cpp:108`、`src/ControlVNextSessionCommandsDaemon.cpp:110`、`src/ControlVNextSession.cpp:150`、`src/ControlVNextSession.cpp:207`。
- 当前代码事实：stream manager 把 `subscriberFd` 保存为 raw int。`resetAll()` 把 fd 值复制到 vector，清空 subscriber 并释放 stream locks，调用方随后对这些 fd 执行 `shutdown(fd, SHUT_RDWR)`。真正拥有 fd 的 session 线程仍可能同时关闭该 fd。
- 触发 interleaving：
  - Thread A：`RESETALL` 调用 `controlVNextStream.resetAll()`，得到 fd `42`。
  - Thread B：stream session 并发退出并关闭 fd `42`。
  - Thread C：accept loop 接受新 client，OS 复用 fd `42`。
  - Thread A：对 `42` 调用 `shutdown()`，误伤不相关的新 client。
- 失败模式：fd lifetime race；错误断开 session；概率低但从当前 ownership 模型可静态推出。
- 影响面：vNext stream reset、control client 生命周期。
- 最小修复方向：不要返回 bare fd。可以在 stream mutex 下 `dup()` fd 后返回副本，或让 owning session 观察 cancellation flag 并由 session 自己执行 shutdown / close。
- 验证建议：高频 vNext stream connect / disconnect，同时反复执行 `RESETALL`；观察不相关 command session 是否出现 `POLLHUP` 或响应截断。

### [MEDIUM] detached client / listener 线程配合阻塞写，可能耗尽进程资源

- 位置：`src/DnsListener.cpp:26`、`src/DnsListener.cpp:53`、`src/DnsListener.cpp:147`、`src/Control.cpp:190`、`src/Control.cpp:226`、`src/Control.cpp:341`、`src/ControlVNext.cpp:48`、`src/ControlVNext.cpp:95`、`src/PacketListener.cpp:73`、`src/PackageListener.cpp:101`、`src/DnsListener.cpp:315`、`src/SocketIO.cpp:36`、`src/ControlVNextSession.cpp:181`。
- 当前代码事实：accept loop 为每个 client 创建 detached thread，除了 listen backlog 外没有全局 client / thread budget。legacy `SocketIO::print()` 与 DNS `clientWrite()` 使用阻塞写。vNext 命令响应虽然使用 non-blocking fd，但 `flushBlocking()` 在有 pending frame 时没有总 deadline。
- 触发 interleaving：
  - 大量 client 连接后不读响应，或保持 session idle 到超时。
  - daemon 积累 detached threads，这些线程阻塞在 write / read / poll 中；没有 owner 能 join 或 cancel 它们。
- 失败模式：thread / fd exhaustion、shutdown 变慢、control-plane DoS。
- 影响面：legacy control、vNext command client、DNS netd fallback client、daemon lifecycle。
- 最小修复方向：引入有界 worker / session accounting；为发送增加总 deadline；control client 更适合 event-loop 或 thread-pool ownership；暴露 active session 与 rejected client counters。
- 验证建议：host 或真机 socket stress：对 legacy / vNext / DNS socket 打开大量不读取 client，断言 threads / fds 有上界且 command latency 稳定。

### [LOW] `RESETALL` 没有重置 `ActivityManager`

- 位置：`src/ActivityManager.hpp:13`、`src/ActivityManager.cpp:13`、`src/ActivityManager.cpp:39`、`src/ControlVNextSessionCommandsDaemon.cpp:116`、`src/Control.cpp:1384`。
- 当前代码事实：`ActivityManager` 用 `shared_ptr<App>` 保存 `_topApp`，并继承 legacy `Streamable<Activity>`，但 legacy 与 vNext `RESETALL` 都没有调用 activity reset。`AppManager::reset()` 清空 manager map，但不能清空 `_topApp`。
- 触发 interleaving：
  - reset 前 activity tracking 保存了一个 top app。
  - `RESETALL` 清空 apps，但 `_topApp` 仍保留。
  - 后续 legacy activity stream start 会发出 reset 前 app 对应的 activity。
- 失败模式：reset 后 stale observability；旧 app 对象生命周期被意外延长。
- 影响面：legacy activity stream、reset 语义；未证明会直接影响 verdict。
- 最小修复方向：新增 `ActivityManager::reset()`，在自身锁下清空 `_topApp` 与继承的 stream items，并在两条 reset 路径中调用。
- 验证建议：host test 或 vNext / legacy control 场景：设置 top app，执行 `RESETALL`，启动 activity stream，断言不会输出 reset 前 app。

## Needs Dynamic Verification

- Conntrack lockless lookup / epoch reclaim：当前代码使用 epoch guard，且未静态证明存在 UAF；但仍应使用 TSan stress 覆盖并发 `inspectForPolicy()`、`commitAccepted()`、sweep、reclaim。
- Conntrack reset 边界：只有在所有生产调用都继续保证 reset 位于独占 `mutexListeners` 下时才静态安全；建议用 TSan 覆盖 `RESETALL` + 活跃 IPv4 traffic。
- Legacy stream 背压：用不读取的 client 复现，量化 NFQUEUE latency 与 reset starvation。
- vNext fd race：需要高 churn stream connect / disconnect / reset 测试，因为 fd reuse 依赖 OS 时序。
- Signal exit latency：需要真机测量，因为信号投递线程与 `sleep_for` 中断行为依赖运行时 / 实现。
- 大 control-plane 操作：并发运行 domain import / IPRULES apply 与 datapath perf，观察 `nfq_total_us` tail latency。

## No Finding Areas

- Conntrack 正常 update 路径：lockless bucket traversal 使用 atomic bucket / next 指针，结构性 mutation 由 shard lock 保护，并通过 epoch 延迟 free；在排除 reset 并发的前提下，未静态证明当前存在 UAF。
- IPRULES hot snapshot：packet decision 通过 `Decision::keepAlive` pin snapshot；per-rule stats 指针由 pinned snapshot 拥有，未证明 stats UAF。
- DomainList 热查询：`blockMask()` 使用 atomically published `shared_ptr` aggregate snapshot；rebuild 在 list mutex 下完成，hot reader 不会观察到 iterator invalidation。
- App / Host manager 基本 lookup：map lookup 在持有 manager lock 时复制 `shared_ptr`，普通 find / make 路径未发现 iterator UAF。
- vNext tracked stream event delivery：packet / DNS 热路径只入队到有界内存队列，不直接做 socket write；慢读 client 由 bounded pending queue 与 non-blocking session flush 处理。
- Packet verdict send path：`sendVerdict()` 发生在 policy 工作之后，未发现它在发 verdict 时持有 manager / global locks。
