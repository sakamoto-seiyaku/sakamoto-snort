# NFQUEUE / DNS / Datapath 模块边界工作决策

更新时间：2026-06-19
状态：SNORT-10 架构讨论阶段的已确认边界；实现切片仍需后续 Plane work item 拆分
输入材料：
- `docs/reviews/NFQUEUE_PERFORMANCE_ARCHITECTURE_REVIEW.md`
- Plane `SNORT-10`：NFQUEUE / DNS / datapath performance architecture refactor discussion

## 0. 背景

当前 daemon 来自以 DNS/domain 拦截为主的历史系统，后续叠加了 IPRULES、Conntrack、Flow Telemetry、Debug Stream、Checkpoint、vNext control 等能力。功能本身有价值，但模块边界和热路径成本边界已经混在一起。

本文件记录当前讨论中已经确认的边界。它不是实现任务列表，也不替代接口规范。后续实现前应把每一块拆成独立 Plane work item，并补充对应测试与真机测量。

## 1. 总原则

首要目标是降低 packet hot path 成本。任何模块重组、抽象或新能力都必须证明它减少重复解析、重复查询、无条件状态更新或不必要的内存分配。

硬性原则：
- packet hot path 不得每包 heap allocation/free。
- packet hot path 的时间成本优先级最高；设计评估先看每包时间复杂度、锁争用、cache-line 争用、原子 RMW、分支和重复查询，而不是先看实现是否最简单。
- 在降低每包时间成本的前提下，可以接受更高的固定内存占用、预分配、分片状态、查询侧合并成本和更复杂的数据结构。
- 当两个方案产品语义等价时，若较复杂方案能更明确地降低 hot-path 时间成本，应优先选择较低 hot-path 成本的方案，而不是选择实现更简单但每包成本更高的方案。
- 不得因为未来高级能力存在，让普通路径承担 CT / DPI / association 等成本。
- 不得用无界 map / 无界 cache / 无界历史记录承载普通后台能力。
- 每个昂贵事实都必须 consumer-driven：没有明确 consumer 时不计算。
- 每个 packet stage 必须支持 short-circuit：前面已有明确 verdict 时，后面 stage 不评估、不查询、不构造额外事实。
- 当前尚未正式上架，SNORT-10 重构不为旧 stream / record / control ABI 背兼容成本；旧字段和旧语义可以直接删除或替换。除非明确用于临时迁移或测试，不因兼容旧模型引入额外 hot-path 成本或概念复杂度。
- 当前开发期接口、record layout、stream shape、metrics shape 与内部模型不承诺向前 / 向后兼容；若旧契约妨碍新的 hot-path 边界或模块语言，应直接替换并同步接口文档、测试和消费者。

## 2. Daemon lifecycle 与组件 gate

daemon lifecycle 由 Android-side `RuntimeService` / 前台服务负责。daemon 是否运行、是否绑定前台通知、何时终止，不由 `block.enabled` 表达。

`block.enabled` 是 daemon 内部的组件 / 策略 gate。它控制过滤类 policy 是否执行，不表示 native daemon 停止，也不表示 NFQUEUE hook 被移除。

Play-facing 前端初始化选择普通用户 / 高级用户，并通过启用 / 隐藏能力和写入配置形成默认能力矩阵；后端不承载 product profile enum。普通用户默认开启 packet datapath、PacketFacts、Traffic Windows basic tier、已收口的 Traffic Windows 配置与 Basic IPRULES 等常规能力。高级用户默认开启 CT / Stateful IPRULES 相关能力；这只改变发布的配置 / caps，不改变 CT hot-path 语义：CT 仍由 subject/app caps 与 active consumers 决定进入 packet path，普通用户路径不得为 CT 付费。

当前不引入 daemon 内部“空转但无 NFQUEUE hook”的产品语义。若进程运行且 dataplane 存在，NFQUEUE 仍可接收 packet；具体组件是否参与由各自 gate 和 hot-path capability summary 决定。

## 3. NFQUEUE copy 与基础字节口径

当前 `NFQNL_COPY_PACKET, 0xffff` 近似整包 copy，后续应改为 bounded prefix copy。第一版默认 copy prefix 先定为 `512` bytes。

边界：
- 不切到 `NFQNL_COPY_META`，因为 packet parser 仍需要 IP / L4 header。
- `512` 只是第一版默认值，后续由真机测量决定是否调整。
- copied prefix length 不能再作为 packet length / traffic bytes。
- baseline bytes 口径定义为 original IP packet bytes。
- IPv4 original IP packet bytes 来自 IPv4 total length。
- IPv6 original IP packet bytes 来自 IPv6 base header 的 payload length 加 40 bytes；该 payload length 包含 extension headers。
- L4 payload length、terminal proto、ports、`l4Status` 等仍必须由 IPv4 parser / IPv6 extension-header walker 解析。

## 4. 观测能力分层

### 4.1 Traffic Windows

状态：第一版设计已收口；本节可作为后续 Traffic Windows 实现拆分输入。其他模块仍按后续专题继续讨论。

Traffic Windows 是普通用户可以长期启用的 online 观测层，不是短诊断能力，也不是完整历史数据库。它使用同一组 device-scope trailing windows，但内部按成本分为两级：

- basic tier：日常常驻的低基数窗口计数，用于 device aggregate、per-app counters 与 app ranking。它只维护 app/device/window/direction 级 `acceptedPackets`、`acceptedBytes`、`blockedPackets`。
- detail tier：默认开启但可由用户/前端关闭的窗口明细，用于 remote IP、protocol、protocol-port Top-K。它必须被设计成适合长期常开，不能退化成诊断级高成本路径。

SNORT-10 后的新接口不保留旧 `METRICS.GET(name=traffic)` shape；Traffic Windows 使用一个独立命令族承载 basic tier 与 detail tier，避免把旧的 DNS / rxp / rxb / txp / txb / allow / block 混合口径带入新模型。
`HELLO.capabilities[]` 应加入 `traffic-windows`，前端据此发现 `TRAFFIC_WINDOWS.*` surface；旧 `METRICS.GET(name=traffic)` 能力应随新 surface 清理。
Traffic Windows 的目标之一是摆脱 Conntrack / Flow Telemetry consumer 聚合依赖；basic tier 与 detail tier 都必须基于 `PacketFacts` 与最终 verdict 更新，不得为了 Traffic Windows 启用 Conntrack。
Traffic Windows 不依赖 Domain-IP Association，也不存储或输出 domain hint。当前 Play-facing 第一轮不提供 IP→domain hint；未来如果前端需要把 remote IP 显示成域名，应走独立 Domain-IP Association batch lookup，而不是塞进 Traffic Windows。

时间语义：
- 只支持 relative trailing windows，例如 `last 15m`、`last 1h`、`last 5h`。
- 窗口右端固定为 `now`。
- Traffic Windows 的 `now`、bucket index、coveredSec 与 trailing window 判断都基于 monotonic time，不使用 wall-clock、本地时区或自然日边界；系统时间调整、NTP 校时或时区变化不影响窗口。
- 第一版默认 4 个 device-scope 窗口：`last 15m`、`last 1h`、`last 5h`、`last 24h`。
- 用户可以替换这 4 个窗口的 duration；第一版不支持超过 4 个 active Traffic Windows。
- Traffic Windows 配置始终保留 `1..4` 个 windows；第一版不支持 `windows=[]` 特殊状态。`enabled` 只控制是否更新 runtime state。
- 每个窗口 duration 的合法范围为 `60..86400` 秒，同一配置内不允许重复 duration。
- `last 24h` 是 trailing 24 小时语义；第一版不引入 `today` / 本地自然日窗口。
- 第一版所有 Traffic Windows 统一使用 `60s` bucket；查询结果为分钟级 trailing summary，窗口边界允许最多不足 60 秒的自然 bucket 误差。
- 更长 retention 或更细粒度窗口属于后续高级能力，不能反向污染第一版常驻数据结构。
- 窗口启用后，所有 app 都从启用时刻开始累计到该窗口；per-app 查询返回该 app 在同一窗口内的独立贡献，不是为该 app 单独启用窗口。
- Traffic Windows 配置支持 top-level partial patch；`enabled`、`detailEnabled` 与 `windows` 可单独提交。`windows` 字段一旦出现，按完整窗口数组替换处理，不支持 per-window merge patch。patch 先归一化和校验；只有归一化后的配置实际变化才 reset。完全 no-op patch 返回成功但不清空 runtime state。任何有效配置变更，包括 `enabled` / `detailEnabled` 切换或 duration 变化，都会清空当前 Traffic Windows 数据，并让新配置下的窗口从变更完成时重新开始累计。
- `enabled=0` 生效时同样立即清空 existing runtime state；它不是暂停并保留当前计数。之后 packet 不更新 Traffic Windows。后续 `enabled` 从 `0` 切回 `1` 时，按新的 `epochStartMonoSec` 从零重新累计。
- Traffic Windows 配置作为用户偏好持久化；Traffic Windows state 不持久化。daemon 重启、`RESETALL`、Traffic Windows 配置变更都会清空窗口计数和 Top-K，并按当前持久化配置重新累计。普通规则 / policy 变化不 reset Traffic Windows；已有窗口数据继续表示这些 packet 发生时的实际 verdict 与流量。
- Traffic Windows 使用独立控制命令族，不塞入 `METRICS.GET`。第一版命令名采用 `TRAFFIC_WINDOWS.CONFIG.GET`、`TRAFFIC_WINDOWS.CONFIG.SET`、`TRAFFIC_WINDOWS.GET`、`TRAFFIC_WINDOWS.APPS`、`TRAFFIC_WINDOWS.RESET`。`TRAFFIC_WINDOWS.GET` 必须用 `durationSec` 指定一个 active window，一次只返回该窗口的数据；第一版不引入独立 `windowId`。`TRAFFIC_WINDOWS.APPS` 用于首屏 app ranking，第一版只接受 `durationSec` 与 `limit`，固定按 total `acceptedBytes` 排序，并返回每个 app 的 in/out basic counters。
- Traffic Windows 接口不表达 daemon / dataplane lifecycle。若 daemon 未运行或控制平面连不上，则 `TRAFFIC_WINDOWS.*` surface 本身不可用；前端按 runtime / daemon 连接状态处理，不在 `TRAFFIC_WINDOWS.GET` / `APPS` response 中增加 lifecycle 字段。`TRAFFIC_WINDOWS.CONFIG.GET/SET` 也属于同一个 daemon control surface，不提供离线读写语义。
- Traffic Windows 配置只通过 `TRAFFIC_WINDOWS.CONFIG.GET/SET` 管理，不进入通用 `CONFIG.GET/SET`。
- `TRAFFIC_WINDOWS.CONFIG.GET/SET` 的 request / response 风格与通用 `CONFIG.GET/SET` 保持一致。`CONFIG.GET` args 使用 `keys:[...]`，response 使用 `values:{...}`；`keys:[]` 合法并返回 `values:{}`。`CONFIG.SET` args 使用 `set:{...}` 包一层，成功只返回 `ok`。`TRAFFIC_WINDOWS.CONFIG.SET` 是 Traffic Windows 专属 partial patch，不进入通用 `CONFIG.SET`。空 `set:{}` 合法，返回 `ok` 且不 reset；未出现字段保持原值。若 `set` 中出现 `windows[]`，则必须提交完整新窗口数组并按整组验证。response 不返回 `reset` 字段；是否 reset 是后端内部状态边界，不作为前端 contract。
- `TRAFFIC_WINDOWS.RESET` 只支持全局 reset，清空 device aggregate 与所有 per-app Traffic Windows runtime state，不修改持久化配置；reset 完成后按当前配置重新累计。不支持 per-app reset，避免 device aggregate 与 per-app contribution 不一致。
- `TRAFFIC_WINDOWS.APPS.limit` 默认 50，最大 200。
- `TRAFFIC_WINDOWS.APPS` 是 accepted traffic ranking，不是 inventory；只返回该 window 内 `totalAcceptedBytes > 0` 或 `totalAcceptedPackets > 0` 的 app。只有 blockedPackets、没有实际 accepted traffic 的 app 不进入 ranking。完整 app 清单仍使用 `APPS.LIST`。
- `TRAFFIC_WINDOWS.APPS` 排序 key 为 `totalAcceptedBytes = directions.in.acceptedBytes + directions.out.acceptedBytes`，response item 应返回该 total 以及 in/out basic counters。
- `TRAFFIC_WINDOWS.APPS` ranking 的排序必须稳定：先按 `totalAcceptedBytes` 降序，再按 `totalAcceptedPackets` 降序，最后按 `uid` 升序。
- `TRAFFIC_WINDOWS.APPS` 第一版只返回 total ranking，不提供 per-direction ranking。
- `TRAFFIC_WINDOWS.CONFIG.SET` 与 `TRAFFIC_WINDOWS.RESET` 必须提供严格边界：命令返回 `ok` 后，后续 packet 只能进入新 Traffic Windows state，不允许半旧半新。实现可采用 epoch/bank swap 并延迟释放旧 state，避免在 packet path 上持有长锁。
- Traffic Windows 配置包含 `enabled` 与 `detailEnabled`，二者与通用 `CONFIG.GET/SET` 的 toggle 类型保持一致，使用 `0|1`（u32）传输，默认均为 `1`。产品预期 basic tier 与 detail tier 都可以长期常开，但前端必须能分别关闭 Traffic Windows 整体或只关闭 detail tier；任一开关切换都按配置变更处理并 reset 全部 Traffic Windows state。`detailEnabled` 变化不只清 detail tier，basic counters 也一起清空，保持 basic/detail epoch 一致。
- 新窗口只从启用时开始累积，不回填历史。
- 第一版不支持“距现在 2h 到 1h”这种 relative interval。
- Traffic Windows 同时维护 device aggregate state 与 per-app state。device 查询读取全局窗口汇总；app 查询读取指定 app 在同一组窗口中的独立贡献，避免查询时扫描所有 app 再合并 Top-K。
- per-app Traffic Windows state 以 complete UID 为单位管理。Android 设备 app 数量本身是产品边界。第一版 per-app state pool 预分配 1024 个 complete UID slots，不作为用户可配置项。优先在配置启用、reset、package/user 变更等非 packet hot path 上准备 state；如果 pool 用尽，为保证 per-app 数据完整性允许扩容并创建新 state。扩容按固定 chunk 进行，每次增加 256 个 complete UID slots，不逐个 slot 分配，也不指数翻倍。触发扩容的 packet 等扩容完成后继续更新新 per-app state，不跳过统计。扩容属于 rare slow path，可以接受短暂阻塞，但正常 packet hot path 不应承担大对象分配。
- uid 到 per-app state 的热路径查找使用只读 `UidStateIndex` snapshot。packet worker 原子读取当前 snapshot，并执行无锁 UID -> `TrafficAppState*` lookup；不得在正常 packet hot path 上持有全局 map 锁、rehash、移动 vector 或分配大对象。package/user 变更、Traffic Windows reset、Traffic Windows config change、pool 扩容等慢路径构建完整新 snapshot 后原子发布；旧 snapshot 与旧 state 通过 epoch/RCU/quiescent 机制延迟释放，确保 worker 和查询线程不会读到半初始化或已释放对象。
- per-app Traffic Windows 的身份 key 必须是 complete Linux UID；同一个 appId 在不同 Android user/profile 下有独立窗口计数。

统计语义：
- Traffic Windows 是常态可观测能力，不依赖 `block.enabled` 或 `iprules.enabled`。只要 Traffic Windows 自身 `enabled=1` 且 packet 进入 dataplane，就按最终实际 verdict 更新；`block.enabled=0` 时仍统计流量，通常按实际 allow 计入 accepted traffic。
- `iprules.enabled=0` 同样不影响 Traffic Windows；它只影响规则评估，不影响窗口观测。
- 每个 packet 只在最终 verdict 确定后更新 Traffic Windows 一次：device aggregate state 与对应 complete UID 的 per-app state 各更新一次。不得在 policy stage 中间更新，避免 short-circuit、observe/enforce 或 future stages 造成重复计数。
- basic tier 在最终 verdict 后同步更新，且只能做固定维度、近似零额外成本的 counter 更新，用作首屏 app ranking 与 counters 的近实时基础。
- basic tier 采用 per-worker/per-shard `60s` bucket ring 的模型，而不是每个 active window 各写一份 counter，也不是所有 worker 共同争用同一组 atomic counters。packet hot path 只写当前 worker/shard 的当前 minute bucket；`15m`、`1h`、`5h`、`24h` 等窗口在查询时按 `durationSec` 合并相关 shard/bucket。这样 hot path 成本不随 active window 数量增长，也避免高流量下跨线程 atomic RMW 和 cache-line contention。
- basic tier bucket rollover 不依赖后台定时清理，也不维护 per-window sliding total。每个 bucket 存自己的 monotonic `bucketMinute` index；写当前 monotonic minute 时，如果目标 slot 的 `bucketMinute` 不是 current minute，先清空该 slot 并写入新的 `bucketMinute`。查询只汇总 `bucketMinute` 落在目标 trailing window 内的 buckets。
- Traffic Windows 不依赖 Conntrack，不需要 Flow Telemetry consumer active，也不使用 flow lifecycle records 作为输入。
- Traffic Windows 是 pull API，不向前端推送窗口更新；前端按页面需要主动查询，刷新可由前端以数秒级节奏控制。
- usage 只统计 accepted traffic。
- blocked 包只统计 packet count，不统计 blocked bytes。
- blocked bytes 不作为用户流量消耗，也没有稳定产品语义。
- Traffic Windows 的 `acceptedBytes` 使用 original IP packet bytes：IPv4 使用 IP total length，IPv6 使用 payload length + 40 bytes；不使用 NFQUEUE copied prefix length，也不使用 L4 payload-only bytes。
- 如果 original IP packet bytes 无法可靠取得，则该 packet 不更新 Traffic Windows。
- 第一版不暴露 Traffic Windows skip/drop health counters；这类实现健康信息不进入 `TRAFFIC_WINDOWS.GET` / `APPS` 产品结果。
- 基础窗口 counters 按 `direction=in|out` 分开，每个方向只保留 `acceptedPackets`、`acceptedBytes`、`blockedPackets`；`blockedPackets` 只是该 app/window/direction 下的总计数，不再细分 reason、rule、remote IP 或 port。
- `TRAFFIC_WINDOWS.GET` 的 device aggregate 与 app scope 都包含 `blockedPackets`；只有 `TRAFFIC_WINDOWS.APPS` ranking 排除 blocked-only app。
- Traffic Windows 不复用现有 `traffic{rxp,rxb,txp,txb}{allow,block}` 的完整 shape；特别是不输出或存储 `blockedBytes`。
- 第一版 Traffic Windows 不统计 DNS decision / DNS traffic；旧 `traffic.dns` 语义不迁入 Traffic Windows。

第一版 Top-K 边界：
- 基础分区：per app + direction + trailing window；基础 counters 与所有 Top-K 都按 direction 分开维护。
- remote IP Top-K：只统计 accepted traffic，按 accepted bytes。
- protocol Top-K：只统计 accepted traffic，按 accepted bytes / packets。
- protocol + remote port Top-K：key 为 `{protocol, remotePort}`，按 accepted bytes / packets；是否进入该 Top-K 由 parser facts 的 `portsAvailable` 决定，不硬编码 TCP/UDP 协议集合。无可用远端端口的包不进入该 Top-K。
- `remotePort` 永远表示对端端口：`direction=out` 时取 `dstPort`，`direction=in` 时取 `srcPort`。
- protocol-port heavy-hitter 的内部 key 使用固定二进制 struct：`{protocol:u8, remotePort:u16}`。`remotePort` 使用 parser 阶段归一化后的 host-order numeric value；Traffic Windows 不在后续更新或查询路径反复做 network/host byte-order 转换。对外输出同样使用这个 numeric value。
- blocked packet 不进入 accepted traffic Top-K；block 后没有有效流量。Traffic Windows 内 blocked 只保留 `blockedPackets` 总计数。
- 不做 `app + direction + proto + remote IP + port` 的完整组合 cube。

remote IP Top-K 可以使用 bounded approximate heavy-hitter。第一版可按 `displayK=10, capacity=64` 作为默认方向；尾部几十 KB 级别的排序误差可接受，但对外接口不暴露误差字段，前端只按展示型排行使用。
remote IP heavy-hitter 的内部 key 使用固定二进制 endpoint key：`ipVersion` / address family 加 16-byte address buffer。IPv4 与 IPv6 共用同一结构，IPv4 只填充约定的 4-byte 部分，其余部分必须归零；key 比较和 hashing 必须包含 family，避免 IPv4 与 IPv6 或 IPv4-mapped IPv6 产生歧义。地址字节保持 parser 得到的网络字节序；packet hot path 不构造 IP 字符串，输出阶段才格式化 `remoteIp` 与 `ipVersion`。
detail tier 内部 Top-K capacity 第一版固定为 64，不提供配置；后续根据性能数据再调整。
detail tier 的 shard bucket 内部不使用会扩容的 hash map 做精确统计。remote IP / protocol-port 的候选维护采用固定容量 heavy-hitter table；packet hot path 不做 heap allocation，不触发表扩容。新 key 只能在固定槽内命中、插入、竞争或替换；查询时合并各 shard/bucket 的候选再排序截断。
固定容量 heavy-hitter table 采用 Space-Saving / Metwally 风格替换规则：key 命中时累加 counters；存在空槽时插入；满表且新 key 未命中时，替换当前最小 counter 的槽，新 key 继承 `min + delta` 作为估计值，并在内部记录该 slot 的误差。remote IP 与 protocol-port heavy-hitter 的主权重是 `acceptedBytes`；替换最小槽和输出排序都按 bytes，`acceptedPackets` 只是随附展示 counter。误差不进入 `TRAFFIC_WINDOWS.GET` response；输出仍只暴露展示用 Top-K item。
`protocolTopK` 是 detail tier 的例外：公开 protocol 字段是 IP protocol / IPv6 terminal next-header 的 8-bit wire value，因此 shard bucket 内部使用固定 256-slot exact counter array，按 protocol 下标 O(1) 更新。`protocol=255` 仍按 Traffic Windows 输出约定保留为 unknown/error bucket；不尝试区分真实 header value 255。未来 DPI / L7 protocol ID 如果进入产品，应作为独立维度设计，不能复用 `protocolTopK.protocol`。
Traffic Windows 的对外接口保持 KISS，但内部设计的第一原则是最小化 packet hot path 的时间成本；这一原则同时适用于 basic tier 与 `detailEnabled=1` 的 detail tier。正常 packet hot path 的算法复杂度必须低且有明确上界，并且不得被查询、聚合、排序、维护、Traffic Windows reset 或 Traffic Windows config change 阻塞。可以接受更多内存占用、查询侧聚合成本、异步/延迟聚合、预分配 / memory pool 和更复杂的数据结构，以换取更低的每包时间成本。所有预分配 / pool 必须有明确的初始规模与扩容策略；正常路径依赖预分配，极少数扩容路径为数据完整性服务，可以比普通 packet path 慢。若两个实现方案在产品语义等价时，一个方案内部复杂度更高但热路径成本更低，应优先选择热路径成本更低的方案。
detail tier 采用 per-worker/per-shard staging + 查询/维护时合并的方向。`detailEnabled=1` 时，packet worker 只写自己 shard 的当前 `60s` bucket；不得在 packet hot path 维护全局 Top-K、执行全局排序、扫描全局 app state，或获取跨 worker 大锁。排序、Top-K 合并、过期 bucket 清理可放到查询时或 bounded maintenance 中完成。接口不承诺审计级实时性，只承诺 bounded 当前窗口摘要。
`TRAFFIC_WINDOWS.APPS` ranking 在查询时计算和排序；packet hot path 不维护 app ranking heap。查询线程可以扫描已有 app window state 并排序截断，但不得阻塞 packet worker。
查询线程读取 shard/bucket 时必须使用 best-effort snapshot 规则，不为强一致结果锁住 packet worker。实现可以使用 relaxed atomic counters、per-bucket sequence/version copy 或等价机制避免 C++ data race；如果读到 bucket 正在 rollover，可以跳过该 bucket 或重读一次。查询结果允许轻微并发误差。
Traffic Windows 查询返回 best-effort snapshot；允许数秒级陈旧或并发下的轻微不一致，不追求纳秒级一致性，也不承担运营商计费系统式精确审计语义。设计不得为了强一致查询引入会阻塞 packet worker 的复杂同步。
Hot-path capability summary 必须为 Traffic Windows 分配两个 primary bits：`needsTrafficWindowsBasic` 与 `needsTrafficWindowsDetail`。默认通常两者都开启，但 packet path 必须能在 `enabled=0` 或 `detailEnabled=0` 时按 bit 跳过对应更新。
`TRAFFIC_WINDOWS.GET` 可接受前端提供的 Top-K 返回数量参数 `topKLimit`；默认返回 10 个 leaders，最大 64，内部 capacity 与返回数量分开。
`topKLimit` 只是查询参数，不进入 Traffic Windows 持久化配置；后端实现只需要固定最大返回值与默认值。
第一版 `TRAFFIC_WINDOWS.GET` 不支持字段选择；一次返回该 window/scope 下的 counters、remote IP Top-K、protocol Top-K、protocol-port Top-K。
`TRAFFIC_WINDOWS.GET` 返回按 direction 固定对象分组：`directions.in` 与 `directions.out` 必须总是出现。
`TRAFFIC_WINDOWS.GET` 返回 `coveredSec`，表示当前结果实际覆盖的秒数；新启用或 reset 后未填满的窗口会小于 `durationSec`。每次 state reset / config effective 时记录 `epochStartMonoSec`；查询时 `coveredSec = min(durationSec, nowMonoSec - epochStartMonoSec)`，再按 bucket 实际可用范围聚合。`coveredSec` 使用 monotonic 秒级近似，范围为 `0..durationSec`，只是前端覆盖提示；counters 仍是 60s bucket summary，不承诺审计级时间边界。不返回 wall-clock `startedAt`，也不返回 snapshot/generated time。
`TRAFFIC_WINDOWS.APPS` 也返回同一语义的 `coveredSec`。
`TRAFFIC_WINDOWS.GET` 不传 `app` 时返回 device aggregate；传 vNext `app` selector 时返回该 complete UID 的 per-app state。
当 `detailEnabled=1` 时，device aggregate scope 与 app scope 都提供 detail Top-K；device scope 返回全局窗口 Top-K，app scope 返回该 app 的窗口 Top-K。
app scope response 返回 `uid`、`userId`、`app` identity fields；device aggregate response 不返回 app identity fields。
`TRAFFIC_WINDOWS.APPS` item 返回已有 app identity（`uid`、`userId`、`app` canonical/package name）即可；不返回 launcher label / displayName，前端自行按 UID/package join 本地 app label。
app selector 不存在时返回 vNext selector error；selector 成功解析但该 app 没有 Traffic Windows 数据时返回 ok + zero-filled window result，用于区分“app 没安装/不可解析”和“app 已存在但没有流量”。zero-filled result 仍返回固定 `directions.in/out`，counters 为 0，Top-K 数组为空。
当 Traffic Windows `enabled=0` 时，`TRAFFIC_WINDOWS.GET` 返回 `{"enabled":0}` 即可，不返回 zero-filled window result。
当 Traffic Windows `enabled=0` 时，`TRAFFIC_WINDOWS.APPS` 同样返回 `{"enabled":0}`，不返回空 ranking。
当 `enabled=1` 且 `detailEnabled=0` 时，`TRAFFIC_WINDOWS.GET` 正常返回 basic counters，并携带 `detailEnabled:0`；Top-K 数组返回空数组。
该规则同时适用于 device aggregate scope 与 app scope。
`detailEnabled` 只控制 detail tier 的 Top-K 更新与返回，不影响 basic counters，也不影响 `TRAFFIC_WINDOWS.APPS` app ranking。
当 `enabled=1` 但 `TRAFFIC_WINDOWS.GET.durationSec` 不属于当前 active windows 时，返回 `INVALID_ARGUMENT`。
当 `enabled=1` 但 `TRAFFIC_WINDOWS.APPS.durationSec` 不属于当前 active windows 时，同样返回 `INVALID_ARGUMENT`。
`remoteIpTopK[]` 使用统一字符串字段 `remoteIp`，并携带 `ipVersion=4|6` 供前端区分 IPv4/IPv6；不拆成 IPv4/IPv6 两套数组。
`remoteIp` 永远表示对端 IP：`direction=out` 时取 `dstIp`，`direction=in` 时取 `srcIp`。
Top-K item 都返回 `acceptedBytes` 与 `acceptedPackets`；remote IP 排名主权重为 accepted bytes，protocol 与 protocol-port 同时提供 bytes/packets 供前端展示。
Top-K 输出排序必须稳定：先按 `acceptedBytes` 降序，再按 `acceptedPackets` 降序，最后按 key 的稳定二进制顺序升序。这样同值项不会在多次查询之间随机抖动。
`protocolTopK[]` 和 `protocolPortTopK[]` 的 protocol 字段使用 IP header / terminal L4 protocol number，例如 TCP=6、UDP=17、ICMP=1、ICMPv6=58；不使用字符串 token，也不把 ICMPv4/ICMPv6 折叠为同一个公开值。对 L4 invalid/unavailable 但 IP envelope 和 remote IP 可用的 accepted packet，`protocolTopK[]` 使用 reserved sentinel `protocol=255` 归入 unknown/error bucket；Traffic Windows 输出里 `255` 一律表示 unknown/error bucket，不再区分真实 header value 255。这类 packet 不进入 `protocolPortTopK[]`。

Traffic Windows 不直接输出 domain hint。未来如果前端需要把 remote IP 显示成域名，应独立调用 Domain-IP Association 的 batch lookup；当前第一轮不实现该 lookup。

### 4.3 Packet diagnostics 与高级观测边界

常态 Flow/Fact Records 与用户显式诊断必须分开。

Packet diagnostics 第一版定位为用户主动开启的 IPRULES / packet policy 诊断模式：
- 使用 `DIAGNOSTICS.START` / `DIAGNOSTICS.STOP` 这类诊断语义接口，而不是继续扩展泛化 `STREAM.*`。
- 使用 vNext socket JSON event stream，不进入 Flow/Fact Record 的 shared-memory telemetry ABI。
- 由 session 持有单个 Diagnostic Focus；只诊断一个 app / UID；STOP、socket detach 或 session close 必须释放 focus。
- 不支持 replay；不保留 `horizonSec` / `minSize`；没有 active consumer 时不构造 explain 或维护诊断 replay ring。
- 不迁移旧 `wouldRuleId` / `wouldDrop` 平行归因模型；observe-mode winner 使用 `ruleId + reasonId + ruleMode + verdict` 的同一 winner 归因格式。
- 不输出 legacy `host` / domain 字段；IP 到域名展示由前端按需查询 Domain-IP Association。
- packet-side diagnostics 重构不保留旧兼容中间层：旧 `tracked` 持久状态、generic `STREAM.*` packet 模型、replay prebuffer、suppressed notice、legacy `host` / domain join、`wouldRuleId` / `wouldDrop` 平行归因与旧 activity stream 状态应在同一语义重构中直接删除或替换，而不是先桥接到新模型。

Packet diagnostics 是显式高成本模式，可以输出完整 explain、stage、skipped reason、rule snapshot 与候选路径；但它面向用户策略排查，不输出 raw hot-path capability mask、compiler table 等开发者内部结构。开发者性能 trace 后续走独立路径。

Try / Diagnose / Rescue 不作为三个 daemon 模块实现。它们组成前端主导的“安全修改策略”工作流，并复用已定后端原语：
- Try 使用真实 Authoring / Commit / Apply 流程，只是绑定使用 `bindingMode=observe`；它发布到 Runtime Snapshot，命中时记录归因和 rule hit，但实际 verdict 保持 allow。
- Diagnose 使用 Packet Diagnostics 和 Diagnostic Focus，为具体 app / UID 输出 Explain Evidence；它补解释，不改变 verdict，也不是 Try 的必要前置条件。
- Rescue 使用 component gates 与 Checkpoint Restore。恢复联网的短路径必须优先于排查路径，不能要求用户先打开诊断或理解 explain stream 才能恢复网络。

DNS stream 暂时冻结，不并入 `DIAGNOSTICS.*`，本轮不扩展、不删除、不桥接。当前前端不调用 DNS stream；只要它不被调用且不影响 packet hot path，就不把它纳入 packet-side 重构范围。后续 Domain/DNS 线单独整理时再决定替代模型。现有 activity stream 只输出 `blockEnabled` 状态，不迁移到新模型；前端需要状态时使用 `CONFIG.GET(block.enabled)`。

## 5. Conntrack、IPRULES 与未来 DPI

### 5.1 Conntrack 定位

L4 Conntrack 是高级 datapath primitive，不是普通用户默认路径能力。

它服务：
- Stateful IPRULES 的 `ct.*` 规则。
- 第三层完整流观测。
- 未来 DPI / L7 policy。
- 未来 FORWARD / hotspot gateway mode。

它不服务：
- Traffic Windows basic tier。
- Basic IPRULES。
- 普通用户默认 UI 卖点。

Conntrack 必须 consumer-driven。没有 `ct.*` policy consumer、完整流观测 consumer、DPI consumer 或未来 gateway consumer 时，不应进入对应 packet path。

启用 Conntrack 后，同一 flow/session 只能有一条统一 CT entry。Flow Telemetry counters / lifecycle state、DPI state / result 等 flow/session state 都作为该 CT entry 的 consumer-specific attachments 挂载；不得为 DPI、Flow Telemetry 或其它 consumer 各自维护独立 conntrack 表。Policy decision cache 的位置与 key 设计必须跟随 pipeline 层级和 facts 依赖单独确定，不能在 Conntrack 定位层提前固定。

CT acquisition 的 gate 是 subject/app 级高级能力 gate，不是同一 app 内按单条规则逐包细分的 gate。当前 local-device 形态下，只要某 app/subject 存在 active `ct.*` policy/observe rule 或 `dpi.*` policy/observe rule，该 app/subject 的 eligible packets 就进入 CT；不得再在该 app 内根据某条 CT 规则的 cheap precondition 决定这个 packet 是否进入 CT。普通用户 / 普通 app 不应为 CT 付费，但高级功能启用后的 CT 成本必须作为高级能力的基础成本处理，而不是通过过度细分 gate 回避。

CT 的热路径执行点必须区分两件事：是否需要进入 CT，以及进入 CT 后如何更新 flow/session state。CT 不是 verdict-gated 的 accepted-flow 账本；它是独立的 L4 flow/session 状态机。只要 packet path 决定进入 CT，CT 就按自身状态机执行 lookup / create / update，并产出 `CtFacts`。后续 Stateful / DPI policy 若基于这些 `CtFacts` 产生 block，block 只影响 packet verdict，不回滚 CT，也不要求 CT 做 preview / commit 两阶段提交；CT entry 由自身 timeout / eviction 机制清理。

对已启用 CT / DPI 高级能力的 app/subject，Interface policy 与 Basic IPRULES 仍先用 `PacketFacts` 评估。若 Basic enforce block 产生最终 block，则该 packet 可以在进入 CT 前被短路，避免不必要的 CT 状态更新。若 Basic enforce allow 或 Basic observe winner 产生最终 allow，则后续 Stateful / DPI policy 仍按 short-circuit 不再评估，但该 packet 仍应进入 CT 并更新统一 CT entry，保证同一 flow/session 的后续包、DPI state 与 flow attachments 不因 Basic allow 短路而断裂。

完整流观测 / Flow Telemetry 虽然是 CT observation consumer，但不覆盖上述 Base/Basic final block 边界。`IFACE_BLOCK` 或 Basic enforce block 已经产生 final block 的 packet 不为 telemetry 拉起 CT，不创建 block/deny-flow entry，也不生成 `FLOW` lifecycle record；blocked visibility 由 reason metrics、Traffic Windows `blockedPackets` 与 Packet Diagnostics 承担。

当 Basic IPRULES 没有产生 winner 且 subject/app 需要 Stateful / DPI 时，packet path 进入 CT 并取得 `CtFacts`，继续评估 Stateful IPRULES / DPI stage。此时 CT 状态更新与最终 verdict 解耦：CT 已经观察到这个 packet 并推进对应 flow/session 状态；如果后续 Stateful / DPI block 命中，直接执行 block verdict 即可。

CT runtime 的跨线程方案已在 `L4_CONNTRACK_WORKING_DECISIONS.md` 收口为 A 方案内的 A++ baseline：A 方案表示全局共享 authoritative CT table，不依赖 NFQUEUE 自带 fanout / queue balance 解决 flow ownership；C/owner handoff 仍是未来单独架构，不混入当前 baseline。A++ baseline 为：
- 自研专用 fixed-bucket intrusive CT table，而不是通用 map 或 `cds_lfht` 作为主表。
- 当前 specialized field-mix hash 作为默认 hash；VPP session manager 里的 CRC32 stacking 只能作为候选 benchmark，不直接照搬。
- `liburcu-qsbr` 负责 read-side lifetime / deferred reclamation；read hit 不取结构锁，create / delete / expire 只进入 shard lock。
- shard 与 bucket 使用 hash 的不重叠 bit slices，避免 powers-of-two 下 `shard = h % shardCount` 与 `bucket = h & bucketMask` 复用低位。
- per-shard pool/free-list、worker-local hot cache、hot/cold split attachments、coarse expiration refresh 与 out-of-hit-path GC 都是 CT A++ 的 baseline 约束。

启用 CT 不等于启用 Flow Telemetry。Flow Telemetry 是 CT 的一个 observation consumer；policy 因 `ct.*` / `dpi.*` 启用 CT 时，不应自动导出 flow records 或打开可观测性第三层。

### 5.2 IPRULES 分层

IPRULES 概念上拆成两层：
- Basic IPRULES：只使用 PacketFacts，不依赖 Conntrack。
- Stateful IPRULES：使用 CtFacts，例如 `ct.state` / `ct.direction`。

实现上可以继续共用同一个 engine / snapshot / compiler，但编译结果必须拆出独立 hot views，让没有 CT / DPI consumer 的 Basic 包不承担 Stateful / DPI 成本。第一版结构方向：
- `basicView`：只包含不依赖 CT / DPI 的 Basic IPRULES，直接产出 allow/block verdict。
- `statefulView`：包含完整 CT evaluator。`CtFacts` 是否取得由 subject/app 级 CT gate 决定，而不是由该 view 内的某条规则 projection 逐包决定。
- `dpiProjectionView` / `dpiView`：作为 DPI / L7 后续专题的架构占位和讨论基准。当前只确定 DPI 不混入 Basic / Stateful hot view，且 `dpi.*` 规则未来属于 DPI / L7 stage；projection 的具体字段、数据结构、classifier 触发时机、DPI result schema 与 cache 细节延后到 DPI 专题收口。

IPRULES compiler 第一版保留统一入口：一次 apply / restore 输入一组 rules，产出同一个 compiled snapshot epoch 下的多个 hot views 与 subject caps。不得把 Basic / Stateful / DPI 拆成多个独立 engine 或多个不同步发布的 snapshot。推荐口径：
- `RuleStore` / committed rules：慢路径权威集合，用于 `PRINT`、apply mapping、rule identity、stats lifetime 与 diagnostics attribution。
- `basicView4/6`：Basic IPRULES hot view。
- `statefulView4/6`：Stateful IPRULES hot view。
- `dpiProjectionView4/6` 与未来 `dpiView4/6`：DPI cheap projection 与完整 DPI policy hot view 的保留边界；它们是后续 DPI 实现的基准方向，不要求当前 IPRULES compiler 第一轮实现完整 DPI evaluator。
- `SubjectHotPathCaps` / subject caps index：和上述 views 同 epoch 发布，表达该 subject 是否可能需要 Basic / Stateful / DPI / Resolved-IP 等 stage 或 expensive facts。
- `preflight/costSummary`：慢路径成本摘要与前端提示输入。

一个 snapshot epoch 必须同时覆盖 hot views 与 subject caps，避免出现 gate 说需要 CT / DPI 但对应 view 尚未发布，或 view 已更新但 caps 仍旧的状态。

这些 hot views 可以复用当前 IPRULES 的 mask/subtable/bucket 编译技术，但只能复用技术和辅助代码，不复用同一个 compiled container。`basicView4/6` 与 `statefulView4/6` 必须是独立 hot views，分别拥有自己的 priority order、subtable order、bucket 集合与 scan 入口：
- `basicView4/6` 只编译不引用 CT / DPI 的规则；其 mask signature 不应包含 `ctState` / `ctDir`，Basic hot path 不扫描 Stateful bucket。
- `statefulView4/6` 只编译引用 `ct.*` 的规则；可继续使用相同的 mask/subtable/bucket 思路来组织 `PacketFacts + CtFacts` 条件。
- 当前实现里的 enforce / would 双通道候选组织不能作为 SNORT-10 最终语义照搬。SNORT-10 中 compiled `RuleRef.mode=enforce|observe` 来自 complete-Linux-UID direct binding mode，并在同一 stage 内按同一 `priority desc, ruleId asc` 竞争同一个 winner；实现可以保留 exact/range 等物理优化，但不能先扫 enforce 再扫 observe。
- bucket 内的第一版物理模型应改成 unified candidate model：`exactRules` 与 `rangeRules` 两类候选列表，`RuleRef` 携带 effective `mode=enforce|observe` 与 source rule `action=allow|block`，两类列表都按 `priority desc, ruleId asc` 排序。lookup 可以先取得 exact best candidate，再只扫描仍有可能打败 exact candidate 的 range candidates。
- 跨 subtable 剪枝不能只依赖 `maxPriority`。每个 subtable / view order 需要维护能表达 tie-break 的 best-possible key，例如 `{maxPriority, minRuleIdAtMaxPriority}`；当当前 best winner 已经不可能被后续 subtable 打败时才停止扫描。否则同 priority 下更小 `ruleId` 的 observe / enforce candidate 可能被错误跳过。

Rule stage 由 compiler 根据规则引用的 facts 自动决定，不由用户显式指定：
- 只引用 `PacketFacts` 的规则进入 Basic IPRULES。
- 引用 `ct.*` 的规则进入 Stateful IPRULES。
- 引用 `dpi.*` 的规则进入 DPI / L7 Policy；若同一规则同时引用 `ct.*` 与 `dpi.*`，仍归入 DPI stage，并在 DPI stage 内同时使用 `CtFacts` 与 `DpiFacts` 判断完整条件。

`compile-inactive` 只适用于规则本身已经通过 validation、且产品 / build / entitlement 支持该能力，但当前配置没有启用对应 runtime capability 的情况。例如用户下发包含 `dpi.*` 的规则组，但当前未开启 DPI，则这些合法 `dpi.*` 规则进入 per-rule compile-inactive 状态，而不是让整批 apply 失败。该规则可以保留在后端规则组 / committed `RuleStore` / checkpoint 中，但不得被降级编译进 Basic / Stateful view，不得参与 `SubjectHotPathCaps`，不得进入任何 hot view，也不得被 compiler 静默丢弃后让前端误以为已生效。控制面响应必须明确返回对应 `ruleId` / `clientRuleId`、compile status 与 reason，例如 DPI disabled，前端据此显示该规则当前未生效。其它可编译规则继续进入同一个新 snapshot epoch。

`compile-inactive` 规则只存在于配置 / 规则组 / 控制面展示层。runtime plane 必须等价于这条规则不存在：不分配 hot-path `RuleRef`，不分配或更新 runtime stats handle，不参与 hit / would-hit counters，不参与 diagnostics winner / candidate attribution，不参与 policy decision cache attribution，也不影响任何扫描、拦截或 verdict。

compiler / control plane 必须能为每条 committed rule 报告 compile status，但当前阶段只规定语义，不规定具体 API shape：
- `active`：规则已进入对应 hot view / caps，runtime 生效。
- `disabled`：用户显式关闭，不进入 runtime。
- `compile-inactive`：规则合法，但当前 runtime capability 未启用；不进入 runtime，但保留在规则组 / `RuleStore` / checkpoint 中。

compile status report 必须是结构化 per-rule 结果，而不是仅返回面向人读的文本摘要。每条结果至少要能稳定定位规则并让前端机器处理：`ruleId` 或 `clientRuleId`、compile status、稳定 reason code；human/debug message 可选，不能作为前端 contract。规则组生效后，control plane 应能返回所有 committed rules 的状态，而不只返回失败 / inactive 的规则。

validation failed、产品 / build / entitlement 不支持、付费能力未授权或 internal compile failure 不属于成功的 compile status，也不属于 compile-inactive；这些情况应使 apply / preflight 失败，而不是发布带错误配置的新 snapshot。

Domain-IP Association / Resolved-IP facts 不属于 IPRULES 条件字段，也不是 IPRULES compiler 的 stage 扩展。Resolved-IP Policy 属于 DNS / Domain-IP Association 线路的后置 fallback stage；它可以被 Hot-path capability summary gate，但不进入 `basicView` / `statefulView` / `dpiView`。

高级规则应拆成：
- cheap precondition：只用 PacketFacts，例如 family、direction、iface、proto、src/dst、port。
- expensive condition：CT、DPI 等 IPRULES 线路内的昂贵事实。

`ct.*` 规则的存在决定 subject/app 级 CT acquisition；不再用单条 CT 规则的 cheap precondition 在同一 app 内逐包决定是否计算 `CtFacts`。DPI 仍在已取得 CT / flow state 后使用 cheap precondition 与 CT 二级剪枝决定是否进入 DPI classifier。
当对应昂贵事实不可用时，高级条件视为输入不满足并 no-match，不产生特殊 fail-open / fail-closed verdict。Stateful IPRULES 的 `ct.*` 条件在没有 `CtFacts` 时 no-match；若后续 stage 也无 winner，则按 default allow。

### 5.3 IPRULES Authoring Layer / 生效模型

状态：v1 authoring / rule group / checkpoint 生效模型已收口；后续只拆具体 API schema、持久化格式与实现 work items，不再重新打开本节概念边界。本节是 SNORT-10 目标模型，supersedes pre-SNORT-10 direct `IPRULES.APPLY` mutation surface 与固定 `CHECKPOINT.*` slot surface；具体新 API schema 在 SNORT-17 implementation slice 中定义。

Authoring layer 只保留四个相互关联的状态点：
- `Draft`：草稿 / 工作区 Authoring Policy Bundle。它是 daemon control-plane / persisted store 中的可复用规则、规则组、规则组嵌套与 complete Linux UID 生效绑定；前端只通过 daemon 命令读取和修改它，不拥有独立规则数据库。v1 规则组嵌套上限固定为 3 层，后续高级 / 付费能力可以提高该限制，但不影响当前模型。Draft 可能包含未 commit 的修改；不影响 datapath。
- `Committed Policy Revision`：从 Draft commit 出来的全局已保存 Authoring Policy Bundle revision。它是 Apply 的输入；它本身不影响 datapath，也不是 Checkpoint。
- `Checkpoint`：每次 Apply 一个 committed revision 成功后产生并保留的全量 Authoring Policy Bundle 快照。它包含该时刻的 source rules、rule groups、complete Linux UID bindings，以及该次 Apply 当时的 active / disabled / compile-inactive 等 per-rule apply status；它不是草稿，也不是编译后的 runtime table。
- `Runtime Snapshot`：从 committed revision 或选中 checkpoint 的 Authoring Policy Bundle 编译出来的内存态 datapath 视图，包括 hot views、subject caps、policy cache epoch 等热路径输入。它可以从 source bundle 重建，不作为长期持久化对象。

状态流是 `Edit Draft -> Commit Draft -> Apply Commit -> Checkpoint + Runtime Snapshot`。Commit Draft 只更新全局已保存策略版本，不产生 Checkpoint，也不改变 Runtime Snapshot；Commit 不得自动触发 Apply。Apply 只作用于当前 committed revision；若 Draft 存在未 commit 修改，Apply 应拒绝并要求先 commit 或丢弃修改。

Commit 必须原子化。它先对 Draft 完成策略合法性校验，包括 schema / normalization / rule reference / rule-group cycle detection / v1 group nesting depth <= 3 / product-build support / entitlement / policy binding mode conflict 等控制面约束；只有全部成功后才替换当前 Committed Policy Revision，并让 Draft 回到 clean 状态。Commit 失败时不得更新 Committed Policy Revision，也不得清理 Draft 的未 commit 修改；用户仍可继续编辑或丢弃 Draft。当前 runtime capability 是否启用不属于 Commit 成败条件；stale UID binding 也不属于 Commit validation failure。例如合法且已授权的 `dpi.*` 规则可以 commit，即使当前 DPI runtime 未启用，后续 Apply / Restore 再把它报告为 `compile-inactive`。Commit / preflight 还必须返回 non-blocking warnings，例如 duplicate match warning；warning 必须明确给出可回溯 source refs 供前端提示用户，但不得把合法策略变成 commit failure，也不要求 `confirmWarnings` / confirmation token 之类的 daemon/control-plane 二次确认状态。

单条 rule 是可复用实体，允许被多个 rule group 引用，也允许被某个 complete Linux UID 直接绑定。只有 complete Linux UID 直接绑定到 rule 或 rule group 时携带 `bindingMode=enforce|observe`；rule group 内部的 `group -> rule` 与 `group -> subgroup` 引用只表达结构关系，不携带 observe/enforce mode。同一 complete Linux UID 展开后若让同一个 source `ruleId` 同时获得 `enforce` 与 `observe` effective mode，则这是 policy binding mode conflict，Commit / preflight 必须失败并返回冲突的 UID、ruleId 与 direct binding refs；不得自动选择 enforce、自动选择 observe，或在 runtime 中保留两个不同 mode 的同 rule occurrence。若同一 rule 经多个路径以相同 effective mode 到达同一 subject，则允许通过，Apply 编译时必须按 complete Linux UID 生效路径展开 group graph，并在同一 subject / stage / ruleId / effective mode 维度去重，只保留一个 runtime RuleRef，避免同一 rule 因多条引用路径重复进入同一个 runtime hot view 或被扫描多次。去重不改变 ruleId、priority、source rule action 或从 direct binding 继承的 effective mode。若同一 complete Linux UID 展开后存在多个不同 source `ruleId` 拥有相同 `matchKey`，包括 action / priority 也完全相同的情况，这只是 duplicate match warning，不是 source graph conflict；Commit 可以成功，但响应必须明确提示相关 UID、matchKey、ruleIds 与 source refs。runtime 不对这些不同 ruleId 做隐藏 dedupe，最终 winner 仍只由固定 pipeline、stage、`priority desc, ruleId asc` 决定。

rule group 也是可复用实体，允许被多个 complete Linux UID 绑定，也允许被其它 rule group 引用，受 v1 嵌套深度上限约束。Authoring / UI 可以保存并显示 package name、app label、user/profile 等辅助 metadata，但这些 metadata 不参与策略身份判断、编译去重或 hot-path key；daemon 策略生效 key 必须是 complete Linux UID，不能用 appId 或 packageName 作为 runtime identity。Apply 编译时每个 complete Linux UID subject 独立展开、独立去重、独立生成 hot views 与 `SubjectHotPathCaps`；同一个 group 被多个 complete Linux UID 使用不得造成跨 subject runtime coupling。

complete Linux UID 当前不存在时，对应绑定标记为 stale UID binding。stale binding 是合法保存配置，不自动删除，仍保留在 Draft / Committed Policy Revision / Checkpoint 中供控制面展示和用户清理；Apply 可在 per-binding / apply status 中报告 stale，但编译时该 binding 不展开 runtime rules，不生成 hot views，不贡献 `SubjectHotPathCaps`，也不影响 packet path。

KISS 原则下，runtime hit / diagnostics attribution 只需要输出足够稳定的回溯 ref，例如 snapshot / checkpoint identity、subject、stage、ruleId 或 ruleRefId；hot-path RuleRef 不携带完整 group path 列表。daemon control-plane 必须能基于这些 ref 与 Authoring Policy Bundle 重建完整 source chain，让前端可以追溯到 rule 本体、携带 binding mode 的直接 complete Linux UID 绑定、以及所有有效 rule group 路径。同一 rule 经多条路径到达同一 subject 时，前端应能看到完整路径集合；runtime 不需要为命中选择唯一 group 来源。

v1 固定保留最近 5 个 Checkpoints，数量不做用户配置。每个 Checkpoint 语义上都是可独立 restore 的 Authoring Policy Bundle full snapshot，而不是依赖 diff 链的增量记录；物理持久化可以选择压缩或内容去重，但 Restore 不得依赖重放历史 diff。当前生效 checkpoint 默认是最近一次成功 Apply 的 checkpoint，也可以由 restore 选中旧 checkpoint。packet hot path 只读取 Runtime Snapshot，不读取 Draft、Committed Policy Revision 或 Checkpoint。Checkpoint 里的规则 / 规则组数量和 Runtime Snapshot 里的 hot RuleRef 数量不要求一致；Runtime Snapshot 只包含当前 compile 后 active 的热路径规则。合法但 `compile-inactive` 的规则可以保留在 Checkpoint 的 per-rule status 中用于控制面展示，但 runtime plane 必须等价于不存在。Checkpoint 不包含 Runtime Snapshot hot views、policy caches、runtime counters 或 telemetry state。

Apply 只有成功时才切换 datapath 并产生新的 Checkpoint，且必须原子化：先基于当前 Committed Policy Revision 的 Authoring Policy Bundle 完成 validation / entitlement / compile，生成 Checkpoint source snapshot 与 Runtime Snapshot，只有全部成功后才写入新 Checkpoint、更新当前 Checkpoint 选择并切换 Runtime Snapshot。若 validation、entitlement、internal compile 等失败，Committed Policy Revision 保持当前 head，不回滚到旧 Checkpoint；失败只表示该 committed revision 当前未生效。不产生新的 Checkpoint，Runtime Snapshot 必须保持旧版本，packet hot path 完全不受失败 apply 影响。不得清空 runtime，不得发布部分 hot views，也不得让 hot views 与 subject caps 进入不同 epoch。

Restore Checkpoint 要求 Draft 没有未 commit 修改；若工作区不干净，应拒绝 restore，要求用户先 commit 或丢弃修改。Restore 不是新的 Apply：它不生成新 Checkpoint，不重新计算或覆盖 Checkpoint 中保存的 per-rule apply status。Restore 可以覆盖当前 committed-but-unapplied 的全局策略版本，但必须原子化：先确认选中 Checkpoint 的 Authoring Policy Bundle 可用于重建与其 apply-time result 一致的 Runtime Snapshot，只有成功后才把该 source snapshot 恢复为当前 Draft 与 Committed Policy Revision、更新当前 Checkpoint 选择并切换 Runtime Snapshot。Restore 成功后 `uncommitted changes=false`、`unapplied changes=false`。Restore 失败时，Draft、Committed Policy Revision、当前 Checkpoint 选择与 Runtime Snapshot 全部保持不变，并返回明确 restore failure；不得静默发布空策略，也不得进入半恢复状态。

daemon 的 control-plane / persisted store 必须持久化 Draft、当前 Committed Policy Revision 与最近 5 个 Checkpoints。Commit 成功后 Draft 与 Committed Policy Revision 对应，`uncommitted changes=false`；Commit 失败时 `uncommitted changes=true` 且 committed head 不变。Apply 成功后新的 Checkpoint 记录当前 committed revision 的 Authoring Policy Bundle 与应用结果；新 Checkpoint 持久化成功后才淘汰超过 5 个限制的最旧 Checkpoint。若当前 committed revision 与当前 Checkpoint 对应，`unapplied changes=false`。Apply 失败时不产生新的 Checkpoint，不回滚 Committed Policy Revision，Runtime Snapshot 继续指向旧成功版本，`unapplied changes=true`，并向前端返回 apply errors / per-rule status。

### 5.4 DPI / L7

未来 DPI / L7 policy 也必须 consumer-driven。没有相关规则或 observation consumer 的 app，不承担 DPI 输入成本。

针对 `libprotoident` 的初步调查结论：
- upstream active TCP/UDP classifier registration 约 516 个。
- public enum 数量更多且 numeric ordinal 不适合作为长期稳定 API。
- DPI 不应把每个 L7 protocol 塞进主 hot-path mask。

第一版原则：
- Hot-path primary mask 使用 `uint64_t`。
- DPI 在 primary mask 中只占一个粗粒度 `needsDpi` bit。
- DPI 模块内部使用二级 compiled matcher / protocol table。
- 第三方 DPI 库应 vendor/pin 版本，不能把 upstream implicit enum 当成跨版本稳定协议。
- DPI 依赖 Conntrack flow identity；`needsDpi` 隐含 `needsCt`。DPI state / result 绑定在统一 CT flow/session entry 上，不能做成 packet-local 结果缓存，也不能为了 DPI 维护独立 CT 表。
- 对同时包含 `ct.*` 与 `dpi.*` 的 DPI stage 规则，packet path 应在进入 DPI classifier 前先用已取得的 `CtFacts` 做二级剪枝；若 CT 条件已经证明该规则不可能命中，则不进入 DPI。事实计算按成本层级推进：`PacketFacts` projection -> `CtFacts` -> CT condition gate -> DPI state / classifier。
- DPI result 是 flow/session-level 终态事实。packet 关联到 CT flow/session 后，若该 entry 已有最终 DPI result，packet path 只读取该事实，不重复进入 DPI classifier。
- DPI result cache 只解决“不要重复识别同一 flow/session”的问题；它不是策略扫描缓存。Policy decision cache 属于后续需要重新设计的独立问题，不能从 DPI result cache 的位置直接推出。
- DPI 只在 gated flow 上维护最小状态，分类完成后停止重复跑 classifier。
- 当 CT / flow state 不可用时，DPI 所需输入不满足；DPI condition 视为 no-match，不产生特殊 fail-open / fail-closed verdict。若后续 stage 也无 winner，则按 default allow。

## 6. Hot-path capability summary

需要一个统一的 Hot-path capability summary，覆盖 policy 和 observation consumers。

目标：
- packet path 先读一个 `uint64_t primary` mask。
- primary mask 用于快速判断是否存在 CT / DPI / Traffic Windows / Domain-IP Association / Debug explain 等 consumer。
- primary mask 只表达 coarse `may need` gate，不是当前 packet 的最终执行计划；packet-specific 精确剪枝由 Advanced Prefilter 在 `PacketFacts` 已构造后完成。
- 使用更多 bit 换取更少后续流程是可以接受的；第一版可规划低 48 bit 给当前/近期 hot-path pruning，高 16 bit 保留。
- primary mask 低 48 bit 第一版按职责分区：
  - `0..15`：policy stage may-run bits：`hasIfaceBlock`、`hasBasicIprules`、`hasStatefulIprules`、`hasDpiPolicy`、`hasResolvedIpPolicy`。`defaultAllow` 是 fallback，不是 consumer，不分配 primary bit。
  - `16..31`：expensive fact bits，例如 CT facts、DPI facts、Association facts。fact bits 是跨 consumer 共享的输入需求，不按模块重复拆分。
  - `32..47`：observation/output bits，例如 Traffic Windows basic/detail、Flow Telemetry、Packet Diagnostics。
  - `48..63`：保留。
- 第一轮 implementation scope 必须覆盖当前已有的 CT / Stateful IPRULES 能力：仓库已经支持 `ct.*` 规则，因此 `needsCt` / CT acquisition / `CtFacts` / Stateful stage 不是 future placeholder。DPI / L7 相关 bit、view、secondary detail 只作为后续专题的预留边界；当前不要求实现 DPI classifier、DPI result schema 或 DPI policy evaluator。
- 第一版采用两层 capability 合成；这是已确认的 hot-path 合成模型，packet path 不再引入 `PacketPlan`、`globalEnableMask`、clear mask 或其它第三层热路径代数：
  - `GlobalHotPathCaps.primary` 表达全局 gate / 全局 consumer，例如 Traffic Windows、Flow Telemetry、active Packet Diagnostics session，以及由全局模块开关导致的全局需求。它不是用来逐包清除、重写或二次过滤 subject caps 的 enable mask。
  - `SubjectHotPathCaps.primary` 表达当前 packet subject 的 policy / observation consumer，例如该 subject 是否可能有 Basic IPRULES、Stateful IPRULES、Resolved-IP Policy 或 DPI Policy。
  - packet path 使用 `primary = global.primary | subject.primary`；这个 OR 是唯一的 hot-path 合成规则。
  - 当前 local-device 模式下，packet subject key 固定为 `{complete Linux UID, IP family}`；IPv4 与 IPv6 caps 分开生成和查询。未来 FORWARD / hotspot gateway mode 可扩展出 gateway client、source IP、MAC 或 ingress iface 等 subject，不把 summary 模型写死为 UID-only。
- `SubjectHotPathCaps` 只由 compiled-active rules 和 active observation consumers 贡献。用户 disabled rule、`compile-inactive` rule、validation-failed rule、entitlement-failed rule 都不得贡献 caps。特别是 compile-inactive `dpi.*` rule 不得让 subject 出现 `needsCt` / `needsDpi`。
- `block.enabled`、`iprules.enabled`、DPI enabled 等 component gates 的语义在 caps 生成 / 发布边界解决：disabled consumer 不贡献 bit；packet path 不再用额外 mask 对 `global | subject` 做二次过滤。
- `hasIfaceBlock` 归属 `GlobalHotPathCaps`：它表示全局 pipeline 中可能需要运行 Interface policy / `IFACE_BLOCK` stage。即使具体 stage evidence 需要使用 packet iface、direction、hook 或 app/interface 配置，它也不进入 `SubjectHotPathCaps`，不要求为了判断 stage 是否存在而先做 subject caps lookup。
- 除 `hasIfaceBlock` 外，policy stage bits 第一版归属 `SubjectHotPathCaps`：`hasBasicIprules` 来自该 subject/family 的 active `basicView` consumer；`hasStatefulIprules` 来自实际 CT-consuming active `statefulView` consumer；`hasDpiPolicy` 后续来自 active DPI / L7 policy consumer；`hasResolvedIpPolicy` 来自该 subject/family 的 active Resolved-IP Policy consumer。语法上等价 no-op 的 `ct.*` 条件不应制造 CT / Stateful caps。
- 当 global caps 已足以证明没有任何 subject-scoped policy / expensive fact consumer 时，packet path 可以跳过 subject caps lookup。
- `SubjectHotPathCaps` 由配置、policy、session 或 package/user 变化的慢路径预编译成只读 snapshot 后原子发布；packet path 不应让 IPRULES、Traffic Windows、Diagnostics、Association、DPI 等模块各自重复执行 gate 判断。
- 当前阶段只规定 `SubjectHotPathCaps` 的语义、epoch 边界与贡献来源，不规定物理存储形态。实现可沿用当前 `uid + family` gate/cache 方向并按测量决定 sparse table、dense index、app-local epoch cache 或其它布局。
- 预编译 / snapshot / 索引结构只有在降低每包时间成本、减少重复查询、避免锁/分配或改善 cache locality 时才成立；不能为了抽象本身增加普通 packet path 成本。
- 不把 500+ DPI protocol 直接放入 primary mask。
- 不把 DPI protocol、rule group、单条 rule 或 diagnostic field 放入 primary mask；这些属于 compiled view / secondary detail / diagnostics payload 的内部维度。
- 第一轮不实现 `ctDetail` secondary mask：当前 CT 对外策略事实只有 `ct.state` / `ct.direction`，`inspectForPolicy()` 一次产出完整 `CtFacts` / `PolicyView`，字段级 secondary 不能减少 CT acquisition 成本。`needsCt` primary bit 足够表达当前 CT / Stateful IPRULES 需求。
- lazy secondary masks 只保留后续能力边界。若后续引入 DPI、Association 等更昂贵事实，也只在能显著减少昂贵事实计算或候选扫描时引入，并且只按 expensive fact family 拆；不继续拆到单规则、单协议、单字段或过深层级，避免过多分支、指针跳转和 cache miss 吃掉剪枝收益。
- 只有 primary 对应 bit 命中时，未来 secondary mask 才允许被读取。
- 不在每包路径扫描规则列表。

Basic evaluator 和 advanced prefilter 可以共享编译结构，但概念上分开：
- Basic evaluator 直接产出 allow/block verdict。
- Advanced Prefilter 是现有 compiled classifier 的 `PacketFacts` projection view，不是第二套规则引擎，也不是独立规则列表。CT acquisition 不由 Advanced Prefilter 在同一 app 内逐包决定；当前 CT 由 subject/app 级 caps 决定。Advanced Prefilter 后续主要用于 DPI 等更高成本事实的 packet/flow-specific gate。
- UID / family subject caps 表达“这个 subject 是否启用 CT / DPI 等 advanced consumer”。如果 subject/app 启用 CT，eligible packets 取得 `CtFacts`；如果没有启用 CT，packet path 不得为了查询 CT/DPI cache 或高级规则而提前进入 CT。
- Would / observe 规则是正式 consumer，不是仅在 facts 已经存在时顺带评估的附属输出。Stateful / DPI 的 would / observe 规则必须参与 subject caps；DPI observe/enforce 规则还必须参与 DPI projection view。
- Advanced Prefilter 不产出 verdict，也不提前选择 rule winner。DPI projection 的当前结论只作为后续 DPI 专题的基准：它应去掉 DPI 条件，只用 cheap facts / 已有 flow facts 判断 packet/flow-specific `needsDpi`，并且不得替代完整 DPI policy evaluator。`needsDpi` 隐含 subject/app 需要 CT；packet path 必须先取得 CT / flow state，再读取或更新绑定在该 flow 上的 DPI state / result。最终 winner 与 allow/block/observe/default 仍由固定 verdict pipeline 中的各 stage evaluator 基于完整 facts 产出。
- Policy decision cache 与 DPI result cache 是两类不同问题。DPI result cache 存 flow/session-level 识别事实；policy decision cache 如何分层、放置、构造 key 与失效策略需要重新设计。当前 IPRULES TLS decision cache 只能作为既有参考，不能直接推广为 SNORT-10 advanced path 的最终模型。任何 cache lookup 都不得为了命中缓存而提前拉起本来不需要的 CT / DPI facts。
- Policy decision cache 必须被定义为 stage evaluator 的纯函数结果缓存，只能跳过重复 matcher scan，不能参与 datapath 控制流决策。Cache hit / miss 不得改变 stage order、projection gate、fact acquisition 顺序或最终语义；cache miss 只回到正常 evaluator。
- Policy decision cache 第一版采用两级模型：
  - L1 Base policy cache：缓存 Interface / Basic IPRULES 的 stage result。key 使用完整 normalized `PacketFacts` base projection 与 base policy epoch，不含 CT / DPI facts。L1 result 分为 `FinalBlock`、`FinalAllow` / observe-final-allow、`PassToAdvanced`。
  - L2 Post-CT policy cache：只在 L1 result 为 `PassToAdvanced` 且 subject/app 需要 CT / DPI / advanced policy 时启用。key 使用完整 normalized `PacketFacts` projection、完整 `CtFacts` projection、`DpiFacts` key（`unknown` 或具体识别结果）与 advanced policy epoch。
  - L1 `FinalBlock` 直接 block，不进入 CT，也不查 L2。
  - L1 `FinalAllow` / observe-final-allow 触发最终 allow；若 subject/app 需要 CT，则只更新 CT / flow attachments，不查 L2，不扫 Stateful / DPI。
  - L2 不是 CT entry 上的“永久 verdict”，也不替代 CT / DPI facts；它只缓存 post-CT stage scan result。
  - L2 可以缓存 no-winner / default allow。DPI 未识别时 `DpiFacts` key 为 `unknown`；识别出具体结果后 key 自然变化，旧 `unknown` cache entry 不再命中并回到正常 Stateful / DPI scan。
  - L1/L2 第一版物理形态均为 per-worker TLS fixed-size direct-mapped exact cache。它们不共享、不挂 CT entry、不做全局 hash table；L2 尤其不得把 policy scan result 写回 CT session / entry。若后续 measurement 证明 L2 冲突 miss 成本高，再单独评估 2-way / 4-way set-associative L2。
  - L1/L2 可复用同一个完整 base projection hash：先保留未截断的 `baseHash`，L2 在其基础上增量 mix CT / DPI / epoch 字段。cache index 可以截断 hash，但 cache entry 命中必须比较 epoch 与完整 logical key，不能只比较 hash 或截断 index。
  - 第一版继续使用当前 field-mix / `mixHash` 风格即可；CRC32C 只作为未来目标机 benchmark 后可能替换 mix 函数的实现细节，不改变 cache key 语义。
  - L1/L2 cache entry 的命中结果必须与重新扫描得到的 stage result 等价。entry 不能只保存 verdict；至少要保存 result kind、winning `ruleId`、rule mode、declared action、stats handle / stats pointer，以及保持对应 compiled snapshot / rule stats lifetime 的 handle。cache hit 后仍必须走正常 rule counter / attribution 更新路径。
  - 完整 diagnostics candidate list 不进入 cache entry。Diagnostic Focus / explain path 可以在 cache hit 后额外 reconstruct explain，或在 focused diagnostic path 暂时 bypass cache；普通 hot path cache 不为诊断输出膨胀。

## 7. PacketFacts / CtFacts / DpiFacts 分层

基础 packet 输入模型应拆成层级：
- `PacketFacts`：从 NFQUEUE metadata 和 bounded packet prefix 得到的基础事实，不依赖 CT。
- `CtFacts`：只有 Conntrack consumer 存在时计算。
- `DpiFacts`：未来只有 DPI consumer 存在时计算。
- `AssociationFacts` / domain hint：只有 Domain-IP Association consumer 存在时查询。

`PacketFacts` 应是栈上、轻量、一次解析、多 consumer 复用。它不包含 domain hint，不包含 CT 状态，不包含 DPI 识别结果。

`PacketFacts` 典型字段：
- uid / uidKnown。
- family。
- direction。
- src/dst IP。
- remote IP。
- proto / l4Status / portsAvailable。
- src/dst port。
- ifindex / ifaceKind。
- original IP packet bytes。
- timestamp。

`PacketFacts` 的 endpoint / numeric representation 作为 packet input 层的 canonical shape：
- IP endpoint 使用固定二进制 endpoint 表达：`family/ipVersion` 加 16-byte address buffer。IPv4 使用约定的前 4 bytes，其余 bytes 置 0；IPv6 使用完整 16 bytes。地址字节保持 parser 得到的 network byte order；key compare / hash 必须包含 family，避免 IPv4、IPv6 或 IPv4-mapped IPv6 混淆。
- `remote IP` / `remotePort` 在 `PacketFacts` 构造阶段按 packet direction 归一化：outbound 取 dst，inbound 取 src。
- ports / remotePort、uid / userId、ifindex、original IP packet bytes 等数值字段使用 host-order numeric value；protocol 使用 IP header / terminal L4 protocol number。
- IPRULES、Conntrack、Telemetry、Traffic Windows、Diagnostics 可以从 `PacketFacts` 投影出各自需要的 key 或 ABI shape，例如 IPRULES / Conntrack 的 IPv4 host-order `uint32_t` key，但这些 projection 不能反过来定义 packet input 层事实。

bounded copy / parser failure 的第一版降级保持 KISS：
- 如果连 IP envelope 都不能可靠解析，则不构造 `PacketFacts`，packet fail-open accept；不更新 Traffic Windows，不伪造 Flow Telemetry `FLOW` record。若有 active diagnostics，只能输出 parser failure / dropped 级别诊断。
- 如果 IP envelope 可解析，但 terminal L4 / ports 不完整或不可用，则仍构造 `PacketFacts`，但标记 `l4Status=INVALID_OR_UNAVAILABLE_L4` 或 `FRAGMENT`、`portsAvailable=false`、ports / remotePort 为 0，并保留 `originalIpBytes` 与 copied/truncated 诊断字段。
- 在 L4 不完整或不可用时，Interface policy 与不依赖 ports / CT / DPI 的 Basic IPRULES 仍可按已有 facts 工作；port 条件 no-match，CT / DPI 不创建正常 flow/session。Traffic Windows 只在 `originalIpBytes` 可信时更新 basic counters；detail tier 不进入 protocol-port Top-K。Flow Telemetry 使用 `L3_OBSERVATION`，不伪造正常 L4 lifecycle。

## 8. Verdict pipeline

目标 pipeline 顺序：
1. Interface policy / `IFACE_BLOCK`。
2. Basic IPRULES。
3. Stateful IPRULES。
4. Future DPI / L7 Policy。
5. Resolved-IP Policy。
6. Default allow。

任何 stage 产生 winner 后，后续 stage 必须 short-circuit。

Pipeline stage 顺序高于跨 stage rule priority。Rule priority 只在同一 stage 内决定 winner；各 stage 的 priority 空间独立解释，跨 stage priority 不比较。Basic IPRULES 一旦产出 winner，Stateful IPRULES、DPI / L7 Policy、Resolved-IP Policy 都不再评估。SNORT-10 不保留“Basic / Stateful / DPI 规则在一个全局 priority 空间竞争”的旧语义或潜在语义。

Runtime rule effect 拆成 `action` 与 effective `mode` 两个维度：`action=allow|block` 是 source rule 声明动作，`mode=enforce|observe` 是从 complete-Linux-UID direct binding 继承的执行模式。`mode=enforce` 与 `mode=observe` 不是两套规则类型；它们共享 matcher、priority、tie-break、projection、winner attribution 与 rule runtime 形态。二者唯一语义差异是 winner effect：命中后是否真正执行 declared action。`would-block`、`would-allow` 只是 `mode=observe` 下的派生解释，不是独立 action 或独立 matcher。

Observe-mode RuleRef 是正式 consumer，也是 short-circuit winner。前序 stage 已经产出任意 winner 后，后续 stage 的 enforce / observe 规则都不再评估，也不得为了后续规则继续计算 CT / DPI / Association facts。

同一 stage 内，`mode=enforce` 与 `mode=observe` 规则按同一 priority / tie-break 竞争同一个 winner；tie-break 固定为 `priority desc, ruleId asc`，不引入 specificity score。不存在“先扫 enforce，再扫 observe”的次级通道。任一模式的规则成为 winner 后，都停止该 stage 内后续候选评估并终止后续 stage。二者差异只在 winner effect：`mode=enforce` winner 应用 `action=allow|block` verdict；`mode=observe` winner 记录本次 observe 命中，不执行 declared action，最终 packet verdict 固定为 allow。

`reasonId` 表达 actual packet verdict 原因，不表达 observe winner 的 declared action。`mode=observe, action=block` 命中时，最终 verdict 仍是 allow，reasonId 使用现有 allow 语义；第一版不为 observe winner 新增 reasonId。Declared action、ruleId 与 mode 通过 rule attribution / diagnostics 字段表达，不复用实际 block reason。

Resolved-IP Policy 是很靠后的 fallback。它不应覆盖用户明确写的 IP / CT / DPI 策略。

## 9. DomainPolicy、Domain-IP Association 与 Resolved-IP Policy

当前 Play-facing 第一轮不实现 Domain-IP Association storage、batch lookup、Resolved-IP Policy enforcement 或 RDNS 后台化。本节只保留分层边界，避免 Host / packet path / Traffic Windows / IPRULES 在本轮继续耦合 domain hints；具体 store、API、diagnostic evidence 与 RDNS queue/cache/rate limit 等细节等 DNS / Domain line 重新打开后再设计，且优先级排在 DPI / L7 专题之后。

### 9.1 DomainPolicy

DomainPolicy 继续负责 domain-level allow/block policy 与 DNS verdict attribution。它不应和 IPRULES 合并成一个规则系统。

后端不引入 Google Play / full build 这种产品 profile 枚举。后端只提供独立模块和 gate；不同前端版本通过启用或隐藏不同能力形成产品形态。

### 9.2 Domain-IP Association

Domain-IP Association 是独立模块，不是 DomainPolicy 自身，也不是 Basic IPRULES matcher。

职责：
- 记录 DNS learned domain-to-IP relationships。
- 支持 UI enrichment / debug evidence。
- 支持 Resolved-IP Policy。
- 未来提供 batch lookup，让前端把 IP 转成 domain hint；当前 Play-facing 第一轮不实现该 API。

它必须有独立 enable gate，并与 DNS blocking / DomainPolicy 解耦：
- DNS blocking 可以关闭，association 仍可通过观察路径收集。
- DNS blocking 可以开启，association 也可以关闭。
- 关闭 association 时，packet path 不查 IP→domain，不创建 Host，不做 domain publish。

数据源拆分：
- 当前第一版 producer 可先接现有 DNS verdict path。
- 未来预留 DNS Observation Source，只观察 DNS query/response，不拦截 DNS 请求。
- DNS Observation Source 不进入当前第一轮实现，只作为 future producer contract。

### 9.3 Resolved-IP Policy

Resolved-IP Policy 是基于 DNS-learned Domain-IP Association 对 packet remote IP 施加 domain-derived policy 的可选能力。

它替代 legacy `ip-leak` / `IP link` 名称。旧名称不再作为新架构术语。

定位：
- 不是全功能版默认能力。
- 不是 L3/L4 firewall 主线。
- 是 Domain-IP Association 的可选 enforcement consumer。
- 可用于补足 DomainPolicy，也可用于没有 DNS blocking hook、但能观察 DNS 的 root 场景。
- Play 版本最多使用 association 做展示 enrichment，不启用 Resolved-IP enforcement。

### 9.4 RDNS

RDNS 是 reverse DNS / PTR lookup，即从 IP 反查域名。它不是 DNS learned domain→IP association。

RDNS 边界：
- 保留为诊断 enrichment。
- 不作为 Domain-IP Association 的主数据源。
- 不参与 DomainPolicy verdict。
- 不参与 IPRULES verdict。
- 不参与 Traffic Windows basic tier 或默认展示。
- 不得在 packet verdict path 同步执行。
- 如果保留实现，应放入 bounded background queue，并有 TTL/cache/rate limit。

## 10. Host / HostManager 重构方向

现有 `HostManager` / `Host` / `DomainManager::_byIP` 把 packet remote endpoint、domain-IP association、RDNS、debug hint 混在一起。

目标架构中，packet verdict hot path 不应为了每个 remote IP materialize `Host` 对象。

重构方向：
- Packet path 使用 `PacketFacts` / remote endpoint facts。
- Domain-IP Association 查询返回轻量 association result / domain hint。
- RDNS 不再写入 packet verdict path 的 Host。
- packet-side 重构不保留 Host-backed 兼容路径；`Host` 如保留，应只属于非热路径 debug/enrichment 层，而不是 verdict API、packet diagnostics、Traffic Windows、Flow Telemetry 或 IPRULES 的核心输入。

## 11. Future FORWARD / hotspot gateway mode

FORWARD / hotspot gateway mode 是未来方向，不进入当前第一轮实现。

它作为架构约束存在：
- Conntrack、DPI、Traffic Windows、policy pipeline 不应被写死成只能服务 local app UID。
- 当前实现仍聚焦 INPUT/OUTPUT + UID。
- 未来 gateway mode 需要新的 packet subject，例如 gateway client / source IP / MAC / ingress iface。

## 12. 已拒绝或暂缓的方向

已拒绝：
- 把 `block.enabled=0` 定义为 daemon lifecycle / daemon stop。
- 把 Traffic Windows 和 Domain-IP Association 混成一个输出接口。
- 在 Traffic Windows 中直接存 domain hint。
- 把 RDNS 作为普通 packet path enrichment。
- 把 legacy `ip-leak` / `IP link` 作为新架构术语。
- 把所有 DPI protocol 放进主 hot-path capability mask。

暂缓：
- DNS Observation Source 的实现。
- FORWARD / hotspot gateway mode。
- DPI 库选型与具体 adapter。

## 13. 后续实现拆分建议

SNORT-10 当前 Play-facing 第一轮应围绕已经收口的模块拆 Plane work item：
1. 修正 NFQUEUE bounded copy 与 original IP packet bytes 口径，并引入 `PacketFacts` 栈上输入模型。
2. 清理 packet hot path 的 legacy 状态与 per-packet allocation quick wins，例如旧 `tracked`、legacy Host/domain join、verdict buffer 复用等；DNS stream 暂时冻结不动，只要不被前端调用且不影响 packet hot path。
3. 实现 Hot-path capability summary、advanced prefilter 与 L1/L2 policy decision cache。
4. 按 `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md` 第 7.8 / 7.9 节实现 Conntrack A++ runtime：`liburcu-qsbr`、自研专用 CT hash table、分片 bit-slice、entry lifetime、attachment 更新、timeout / eviction 与 Stateful consumer 边界。
5. 拆分并实现 Traffic Windows 第一版闭环。
6. 拆分并实现 Packet Diagnostics / Diagnostic Focus 第一版边界。
7. 拆分并实现 IPRULES Authoring Layer v1、Apply / Restore / Checkpoint 与 Runtime Snapshot 生效模型。
8. 拆分并实现 PerfMetrics / datapath performance indicators 第一版。

不进入当前第一轮拆分：
- DPI adapter / classifier / result schema / protocol ID / category / rule matching schema。DPI 是后续独立专题。
- Domain-IP Association storage、batch lookup、Resolved-IP Policy enforcement、RDNS 后台化与 DNS Observation Source。DNS / Domain 线等 DPI / L7 之后再重新打开。
- 完整测试 / 发布 gate、版本间性能基准、power audit。第一版只沿用当前 unit / integration / Device smoke 测试层级，按风险补最小必要测试。
