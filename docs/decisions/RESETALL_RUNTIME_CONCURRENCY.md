# RESETALL 运行期并发边界

状态：已落地（2026-04-26）。

## 背景

`RESETALL` 的产品语义是回到干净基线：内存状态、stream/session 观测状态、持久化 save tree 都不能在 reset 完成后被 reset 前的热路径或周期保存重新污染。

原实现只有 `mutexListeners` 与 `snortSave()` 内部保存锁：

- `RESETALL` 的 reset / clear / final save 不是一个串行化事务。
- Packet / DNS 热路径会在进入 `mutexListeners` shared lock 前创建或获取 `App` / `Domain` / `Host`。
- 周期性 `snortSave()` 可与 reset / clear 阶段交错，把旧 snapshot 重新写回磁盘。

## 决策

采用 reset/save coordinator + control mutation coordinator + reset epoch 边界：

- `snortSave()` 与 `snortResetAll()` 共用同一把 `g_snortSaveResetMutex`。
- vNext 普通 mutation 共用 `mutexControlMutations`，用于串行化 control-plane apply/import/config/metrics reset，且不进入 packet / DNS 热路径。
- `snortResetAll()` 是唯一完整 reset pipeline，legacy / vNext `RESETALL` 都只调用该函数。
- `snortResetAll()` 的锁顺序固定为 `g_snortSaveResetMutex` → `mutexControlMutations` → `mutexListeners` 独占锁。
- reset epoch 是 seqlock 风格：
  - 偶数：系统处于稳定 epoch。
  - 奇数：`RESETALL` 正在执行，热路径不得发布 reset-sensitive 状态。
  - 热路径在锁外准备前读取 epoch，在 shared lock 内重新校验；不一致则丢弃准备对象并重试。

## 设计变更范围

这是运行期并发边界的设计变更，不是对外协议或产品语义变更：

- `RESETALL` 的外部语义保持不变：完成后应回到干净基线。
- 内部同步模型从“`mutexListeners` 排斥 reset 的主要 mutation”收敛为“save/reset coordinator 串行化持久化事务，reset epoch 约束热路径发布”。
- legacy control 与 vNext control 不再各自拼装 reset 流程，只进入统一的 `snortResetAll()`。
- manager 对象获取被拆成 `find()` / `prepare()` / `publishPrepared()`：锁外只允许可丢弃准备，发布必须处于当前 epoch 的共享锁窗口。
- legacy `DNSSTREAM` / `PKTSTREAM` / `ACTIVITYSTREAM` 冻结为 no-op；实时观测只支持 vNext `STREAM.START(type=dns|pkt|activity)`。
- vNext 普通 mutation 不再借用 `mutexListeners` 作为外层串行化；`mutexListeners` 收敛为启动、`RESETALL` 与 packet / DNS 短共享窗口。
- 该变更不新增配置项、不改变控制命令 schema、不改变 save 文件格式。

## 热路径边界

允许锁外执行的工作：

- 包解析、地址构造、接口 kind bit 读取。
- `AppManager::find()` / `HostManager::find()` 这类受 manager 自身锁保护的只读 lookup。
- 可丢弃的 `prepare()` 工作，例如 `Host` reverse-DNS。

必须在 `mutexListeners` shared lock 且 epoch 仍当前时执行的工作：

- 发布新 `App` / `Host` / `Domain` 到 manager map。
- Packet verdict 判决、stats 更新、reason / traffic counters 更新。
- DNS 初始 domain 判决、DNS IP map 发布、vNext stream 有界 enqueue。
- `PackageListener` 将 package install/remove 应用到 `AppManager`。

不得放入 `mutexListeners` 的工作：

- blocking socket write。
- reverse-DNS。
- save tree 清理之外的任意非 reset 期间目录重建。
- 大 JSON 构造、批量 parse / compile / file import。
- 普通 vNext `CONFIG.SET`、domain apply/import、`IPRULES.APPLY`、`METRICS.RESET` 的完整 handler。

## 持久化边界

- `snortResetAll()` 在同一个 save/reset mutex 临界区内执行 reset、save tree 清理和 final clean save。
- `Settings::reset()` 修改 `_password` / `_passState` 时必须持有 `_mutexPassword`，与 `Settings::save()` 的读锁配对。
- `App` 构造不得创建 save 目录；目录创建延迟到 `App::save()` 或匿名 app 升级 rename 需要时。

## 预期影响

- 稳态 packet / DNS 命中路径新增一个 epoch atomic load + shared-lock 内 compare，预期接近噪声。
- 首次 UID/IP/domain 发布仍可能分配对象和 map insert，但慢 reverse-DNS 保持在锁外。
- 大 vNext mutation 仍会与其他 vNext mutation 串行，但不再阻塞 packet / DNS 获取 `mutexListeners` shared lock。
- `RESETALL` 期间阻塞热路径是预期语义；性能尖峰应只出现在 reset 窗口。
- `snortSave()` 与 `snortResetAll()` 互斥只影响低频 save/reset 控制路径，不进入 packet / DNS verdict 热循环。
- 当前没有写死百分比预算；如果后续需要量化，应以 `nfq_total_us`、`dns_decision_us`、reset stress 和实际设备 perf 数据为准。

## 验证口径

- Host：`cmake --build --preset dev-debug --target snort-host-tests`。
- Host + ASAN：`cmake --build --preset dev-debug --target snort-host-tests-asan`。
- Android build：`cmake --build --preset dev-debug --target snort-build`。
- Device/DX 后续建议：并发 `RESETALL`、DNS inject、IP traffic，并观察 reset 后没有 stale app/domain/host event 或旧 save 文件回写。
- Device/DX 后续建议：并发大 `DOMAINLISTS.IMPORT` / `IPRULES.APPLY` 与 datapath perf，观察 `nfq_total_us` tail latency 不再因普通 vNext mutation 持有 `mutexListeners` 而尖峰。
