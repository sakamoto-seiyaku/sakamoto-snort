## Context

本 change 为 `IPRULES` 引入 stateful L4 语义，核心是引入 userspace conntrack core，并将其最小输出（`ct.state/ct.direction`）作为规则匹配维度。

设计纲领与边界的权威来源：
- `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`

## Goals

- **Correctness**：不依赖 NFQUEUE 拓扑（当前 `INPUT/OUTPUT split` 下也必须正确）。
- **Hot-path cost**：
  - lookup 不持有全局锁；
  - update 只在 entry 级短临界区内完成；
  - create/delete 才触及 shard 级结构锁；
  - 回收延迟进行，避免 UAF。
- **Semantics**：以 OVS userspace conntrack 语义为母本重实现；范围先收敛在 `TCP/UDP/ICMP/other`。
- **Integration**：将 `ct` 维度作为 IPRULES 的可选匹配维度，并可通过 preflight/编译期 flag 限制最坏成本。

## Non-Goals

- NAT/ALG/fragment；不引入系统 conntrack 依赖；不做 IPv6 stateful；不做 L7。

## High-level structure

- `ConnKey`：基于 IPv4 + L4 (ports/icmp id/type) + uid 构造双向 key（orig/reply），并按 OVS “首包创建方向”语义确定 orig/reply。
- `ConnEntry`：保存 immutable key 与 minimal mutable state：
  - `expiration`（atomic）
  - per-proto state（TCP/ICMP/other）
  - `seen_reply`/bidir 之类状态位
- Protocol trackers（对应 OVS 的 `ct_l4_proto` interface）：
  - `tcp`: handshake/state transitions + invalid detection（按 OVS 语义）
  - `icmp`: request/reply pseudo-state（按 OVS 语义）
  - `other`: 用于 UDP/other 的轻量 pseudo-state（按 OVS 语义）

## Concurrency model (recommended)

- **Shard table**：对连接表按 hash 分 shard；每 shard 独立 bucket/lock/sweep 队列。
- **Lookup**：read-mostly/lockless 读路径（或等价的轻量读侧保护），不拿 shard 结构锁。
- **Update**：命中后持有 entry 级短锁更新状态；`expiration` 优先 atomic 更新。
- **Create**：miss 后进入 create path，在 shard 结构锁下 double-check + insert（对齐 OVS：全局锁仅用于 create）。
- **Reclamation**：deferred reclamation（epoch/QSBR 同类），不在热路径 free；后台 sweep 负责 unlink + 延迟释放。

> 具体 SMR 选型（自研最小 epoch vs vendor `ck_epoch` vs `liburcu`）作为实现任务在 change 内收敛；默认优先最小依赖方案。

### Sweep scheduling (baseline)

第一阶段 baseline：**不引入专门 sweep 线程**，采用“预算化 + 节流触发”的方式回收过期 entry，避免把扫表成本塞进热路径。

- **Lazy expire on hit**：lookup 命中后先检查 `expiration`，若已过期则当场视为 miss，不进入协议状态机。
- **Budgeted sweep per shard**：每 shard 持有 `cursorBucketIndex`，每次 sweep 只扫描固定预算（N buckets 或 K entries），并推进 cursor。
- **Trigger**：
  - create-path 优先：miss 需要创建 entry、或接近/达到容量上限时，在 shard 结构锁下先跑一小段 sweepBudget 以回收过期 entry；
  - hot-path 可选：低频（interval + try_lock）best-effort sweepBudget；失败则跳过，不阻塞 verdict。

### QSBR / epoch reclamation placement (baseline)

第一阶段 baseline：最小化自研 epoch/QSBR（不引入依赖），并将 quiescent 的落点收敛到 conntrack update 的天然边界。

- **Read-side boundary**：进入 `conntrack.update(...)` → enter QSBR read-side；返回 → mark quiescent。
- **Delete**：unlink 后进入 shard `retireList`（记录 retireEpoch），不得立即 free。
- **Reclaim**：由 sweep/慢路径推进 epoch 并批量 free retireList 中满足 grace period 的 entry。
- **Thread registration**：参与 update 的线程首次调用时注册 epoch slot；测试中允许线程动态创建/退出，但退出前必须 quiescent。

## Gating / disable behavior

- `IPRULES=0` 时：保持现有 zero-cost disable。
- 当 active ruleset 中没有任何规则使用 `ct` 维度时：热路径 MUST 跳过 conntrack update（避免“无用的每包状态成本”）。
- 当仅部分 `uid` 的 ruleset 使用 `ct` 时：热路径 SHOULD 做到 **per-UID gating**，避免“少量 uid 开启 ct → 全局每包都做 conntrack”的最坏成本。

这里的 “uid 使用 `ct` / ct consumer” MUST 定义为：
- 仅当该 `uid` 的 active rules 中 **至少存在一条规则** 满足 `ct.state != any` 或 `ct.direction != any`，才需要 conntrack update。
- `ct.state=any` 且 `ct.direction=any`（或未声明 `ct.*`）等价于“不使用 ct”，不应触发 conntrack update。

### Gating 查询方式（热路径优化点）

为了做到 per-UID gating，热路径需要回答一个问题：**当前包所属 uid 的 active ruleset 是否使用 `ct.*`**。

需要明确：我们不希望为了回答这个问题，给每个包额外增加一次 “`uid → compiled view`” 的 map/hash 查找（因为 evaluate 本身已经要做一次 view 定位；重复查找会变成纯浪费）。

可选方案与取舍：

| 方案 | 热路径每包额外成本 | 规则更新时成本 | 实现复杂度 | 备注 |
|---|---:|---:|---:|---|
| A. 直接查 snapshot：`uidUsesCt(uid)` | 1 次 map/hash 查找（每包） | 无 | 低 | 仅作为最小 baseline |
| B. per-UID 缓存在 `App`（带 rulesEpoch） | 常态 2 个原子读（epoch+caps） | epoch 变化时刷新一次 | 中 | **默认推荐**：规则变更频率低，适合 amortize |
| C. 引擎 API 合并：evaluate 前返回 `UidView* + caps` 并复用 | 0 次额外查找 | 无 | 中/高 | 需要调整引擎对外 API 与 TLS cache 边界 |

本 change 的默认路线选择：
- 优先落地 **B（App+epoch 缓存）**，同时保留未来上升到 C 的空间（若 perf 剖析证明仍需要）。

## Semantics alignment (OVS)

- `ct.direction`：严格按 OVS 语义理解为 **first-packet-created direction**（首包创建方向）。不做“字典序归一化/端点排序”这类重新定义。
- `ct.state`：保持 OVS 原版 conntrack 状态机口径（`new/established/invalid` 等）。本 change 的实现目标是“移植/重实现”，不是重新设计语义。
- 注意：由于控制面最小枚举不暴露 OVS 的 `rel`，实现上 SHALL 将 OVS 的 `+rel` 折叠进 `ct.state=established`。
- TCP 采用 OVS 同级别的 **loose** 语义：不额外引入“必须从 SYN 开始”的 strict 模式；并保留 OVS 对 midstream/new 的接受边界。
- IPv4 fragment 本阶段不做重组；遇到分片时，conntrack 输出应按 OVS 语义等价的 “invalid/unknown” 口径处理（用于规则匹配与可观测性，不得崩溃）。

### Required packet inputs for OVS-grade TCP tracking

为了保持 OVS 级的 TCP conntrack 语义（尤其是 invalid 判定与状态迁移），仅解析端口是不够的。conntrack update 至少需要 TCP header 的关键字段：
- `flags`（SYN/ACK/FIN/RST/PSH/URG…）
- `seq/ack`
- `window`
- `dataOffset`（TCP header length）
- `wscale`（TCP option，按需解析；解析失败按 OVS 口径回落）
- `tcpPayloadLen`（用于状态机与 timeout 更新）

这些字段 SHOULD 在解析端口的同一阶段提取（目前在 `PacketListener`），并以“只读元数据”的形式传入 conntrack core（不把原始 seq/ack 等塞进规则匹配 key）。

## Decision-cache interaction

- 一旦规则允许匹配 `ct.*`，则 IPRULES 的 decision cache 不能再只依赖 “包头五元组”。原因：conntrack update 会让同一个五元组在不同时间对应不同 `ct.state`（例如 `new→established`），旧缓存会导致错误判决。
- 因此实现必须遵循：
  - **先做 conntrack preview/update** 拿到当前包的 `ct.state/ct.direction`
  - 把 `ct.state/ct.direction` **纳入 hot-path key**（例如扩展 `PacketKeyV4`），再查 decision cache / classifier snapshot
- 对 miss/new 的首包，preview 阶段 MUST NOT 在最终 verdict 未知时提前创建 entry；只有最终 verdict=ACCEPT 时才允许 commit 新 entry，避免 `ct.state=new` DROP 污染后续重传。

## UID-first partitioning (current engine)

- 当前 IPRULES classifier 的第一层就是 `uid`（`Snapshot::byUid`），即：先定位到该 UID 的 view，再按其它维度做 subtable/bucket 匹配。
- 因此 conntrack gating 可以做到按 UID 粒度：仅当该 UID 的 active rules 使用 `ct.*` 时才对该 UID 的包执行 conntrack update（否则跳过）。

## Persistence / compatibility note

- 本项目当前不需要对外版本兼容；本 change 在落地 `ct.*` 扩展后，可直接调整规则持久化格式（如 bump formatVersion），不要求兼容旧格式。

## SMR / RCU dependency note

- 默认优先最小依赖（自研最小 QSBR/epoch 或轻量 vendor），在确认需要更强的 userspace RCU 语义/更低工程风险时再引入 `liburcu`；引入动机不应仅是“更高性能”，而是“更低的 SMR 正确性与维护风险”（代价是 Android 构建/部署复杂度上升）。

## Testing strategy (minimum)

- Host gtest：
  - `ct.state`/`ct.direction` 的基本语义（TCP/UDP/ICMP/other）
  - 双向并发 update 的 correctness（split in/out 模拟）
  - 超时/回收不产生 UAF（可用 TSAN/压力测试）
- Integration（host-driven + device）：
  - 规则控制面新增 `ct` 维度的解析/拒绝/原子性
  - Tier-1 真机流量下 functional matrix 覆盖 `new/established` 典型策略

## Perf validation (minimum)

- 在现有 Tier-1 流量基线下，对比：
  - `IPRULES` 无 `ct` 规则（should skip conntrack）
  - `IPRULES` 启用 `ct` 规则（conntrack on）
  - 评估 pps/avg/p95/p99 与 CPU 占用变化

## Timeout / capacity defaults

### Timeout values

- 本 change 第一阶段实现的各协议/各状态 timeout **不重新发明**；
- timeout 数值 MUST 直接沿用 OVS userspace conntrack 的默认 timeout policy 表（loose 语义）。

### Capacity / overflow behavior

- conntrack table MUST 有硬上限（max entries）。
- overflow 时的行为必须明确且可测：
  - create path 先做受限预算的 expire reclaim；
  - 若仍无法创建 entry：返回 `ct.state=invalid`（并记指标），且不创建/不插入 entry（避免不可控 eviction 逻辑进热路径）。
