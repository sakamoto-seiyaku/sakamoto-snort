# Review note

This is a point-in-time architecture/performance review, not the active tracker. Accepted follow-up work is tracked in Plane item `SNORT-8` or promoted into `docs/decisions/`.

# NFQUEUE 性能与架构审计报告

日期：2026-06-16
范围：静态审计 daemon 架构、RuntimeService 启动契约与产品层性能取舍。本报告不审前端 UI 代码，也没有执行真机 benchmark。

## 摘要结论

你观察到的空闲/日常电流从约 200 mA 增加到约 300 mA，在当前架构下是合理且需要严肃看待的现象，即使代码里没有一个明显的死循环。daemon 启动后会安装 IPv4/IPv6 NFQUEUE hook，所有未豁免的 INPUT/OUTPUT 包都可能先从内核进入用户态，再等 daemon 回写 verdict。这个基础成本发生在 IPRULES、Conntrack、Flow Telemetry、Debug Stream、Metrics 这些可选功能之前。

当前代码已经有一些正确的性能门控：

- `iprules.enabled` 默认关闭，关闭时跳过 IPRULES 评估（`src/Settings.hpp:209`、`src/PacketManager.hpp:495`）。
- Conntrack 按 UID/family 的规则使用情况门控，同时会被 Flow Telemetry consumer 激活（`src/PacketManager.hpp:509`、`src/PacketManager.hpp:517`）。
- 没有 active consumer 时不会生成 Flow Telemetry record（`src/PacketManager.hpp:198`、`src/PacketManager.hpp:407`）。
- Debug Stream packet explainability 绑定在 tracked app 上（`src/PacketManager.hpp:194`、`src/PacketManager.hpp:200`）。
- `perfmetrics.enabled` 默认关闭，只有开启时才采样（`src/PerfMetrics.hpp:38`、`src/PerfMetrics.hpp:226`）。

所以主要问题不是“所有可观测性都无条件打开”。主要风险是：daemon 的默认包拦截模型本身对手机很贵，包括 NFQUEUE 往返、整包 copy、大量 listener 线程、每包上下文构造，以及一些产品开关在打开后会变成热路径成本。

## 架构事实

- daemon 启动时并行启动 package restore、DNS listener、IPv4 packet listener、IPv6 packet listener、legacy control 和 vNext control（`src/sucre-snort.cpp:72`）。
- 每个 `PacketListener<IP>` 用 `std::thread::hardware_concurrency()` 计算 queue 数，每个 IP family 至少 4 个 queue，并为每个 queue 启动一个 detached listener thread（`src/PacketListener.cpp:30`、`src/PacketListener.cpp:82`）。
- IPv4 和 IPv6 分别有一组 listener。以 8 核手机为例，仅 NFQUEUE listener 就大约 16 个线程，尚未计算 DNS/control/package 线程。
- iptables 链先 return loopback 和 DNS 端口 53/853/5353，剩余流量进入带 `--queue-bypass` 的 NFQUEUE（`src/PacketListener.cpp:56`、`src/PacketListener.cpp:59`、`src/PacketListener.cpp:70`）。
- NFQUEUE 当前使用 `NFQNL_COPY_PACKET, 0xffff`，意味着内核最多把 65535 字节 packet prefix copy 到用户态；当前取值等同于近似整包 copy（`src/PacketListener.cpp:107`）。
- 包方向现在从 NFQUEUE hook 推导，而不是从 thread-local queue 分区推导；这是 `shared-flow-pool` 所必须的（`src/PacketListener.cpp:212`、`openspec/specs/nfqueue-topology-modes/spec.md:1`）。
- `block.enabled` 只是在 userspace callback 内门控 policy 工作；listener 启动后，它不会移除 iptables NFQUEUE hook（`src/PacketListener.cpp:443`）。
- RuntimeService 负责启动 staged NDK artifact 并校验 `HELLO`；`nfqueue.topology` 会持久化，但只在下一次 daemon 启动时生效（`docs/tooling/NDK_DAEMON_BUILD.md:72`、`docs/INTERFACE_SPECIFICATION.md:61`）。

## Findings

### Critical：关闭保护仍然要付 NFQUEUE 往返成本

`block.enabled=0` 只是在 `PacketListener::callback` 内绕过 policy，包仍然已经进入 userspace，并且仍然需要回写 verdict。对一个电量敏感的手机 daemon 来说，这是最大的架构错位：“过滤关闭”并不等价于“内核旁路”。

证据：

- listener 启动时无条件安装 NFQUEUE 规则（`src/PacketListener.cpp:48`、`src/PacketListener.cpp:70`）。
- `block.enabled` 的判断发生在包已被接收、已解析到足以判断 control traffic、且默认 accept verdict 已建立之后（`src/PacketListener.cpp:439`、`src/PacketListener.cpp:443`）。
- 包最终仍会调用 `sendVerdict()`（`src/PacketListener.cpp:518`）。

建议：

- 产品默认值：如果保护会关闭较长时间，RuntimeService 应停止 daemon，或启动一个不安装 NFQUEUE hook 的模式，而不是保持 hook 常驻。
- 职责边界：UI 前端只表达“保护开启/关闭”的用户意图；RuntimeService 负责 daemon stop/start、NFQUEUE hook 清理/重建、启动后的 `HELLO` 校验和配置同步。不要让 UI 直接 kill native daemon。
- 当前不建议优先在 native daemon 内实现热空转模式。`block.enabled=0` 只能视为 policy gate，不应作为产品级省电关闭语义。
- 后续 change：新增 next-start-only 的 datapath mode，例如 `nfqueue.enabled=0|1` 或 `datapath.mode=off|nfqueue`，语义类似 `nfqueue.topology`。
- 验收指标：对比 daemon 停止、daemon 运行但无 NFQUEUE hook、daemon 运行且 NFQUEUE hook 存在但 `block.enabled=0` 三种状态下的 idle current 和 packet samples。

### High：整包 NFQUEUE copy 很可能过度

callback 实际需要的是 L3/L4 header、UID/ifindex metadata、timestamp 和 packet length，并不检查应用层 payload。每包最多 copy 65535 字节会带来明显的内存带宽成本，尤其是下载、视频和大流量场景。

证据：

- NFQUEUE copy mode 使用 `NFQNL_COPY_PACKET` 和 `0xffff`（`src/PacketListener.cpp:107`）。
- callback 读取 IP/L4 header 和长度，policy 使用地址、端口、协议、UID、接口和 conntrack 字段（`src/PacketListener.cpp:233`、`src/PacketListener.cpp:306`、`src/PacketManager.hpp:577`）。

建议：

- 已确认方向：不切到 `NFQNL_COPY_META`，因为当前 contract 仍需要 L3/L4 header；继续使用 `NFQNL_COPY_PACKET`，但把 copy range 从 `0xffff` 降到有界 packet prefix，暂定 `512` 字节。
- 长度语义必须拆开：`NFQA_PAYLOAD` 长度只表示 copied prefix length，packet/original length 应优先来自 `NFQA_CAP_LEN` 或 IP header 字段，不能再依赖 copied payload length。
- 未来如果引入极轻量 DPI，应限制为 prefix DPI，例如每个 flow/packet 最多消费 L4 payload 前 20 字节；该需求可以纳入 `512` 字节 copy budget，不应回退到整包 copy。
- 这需要仔细验证 IPv6 extension header、fragment、GSO 和长度统计行为，应走独立 OpenSpec change，不应顺手改。
- 验收指标：full copy vs bounded copy，对比 `nfq_total_us`、`/proc/net/netfilter/nfnetlink_queue`、吞吐和电流。

### Resolved quick win：`sendVerdict()` 每包分配内存

`sendVerdict()` 每次 verdict 都构造一个 `std::vector<char>`。在 packet 热路径上，这会制造 allocator 流量和可避免的 cache churn。

证据：

- `sendVerdict()` 每次调用都构造 `std::vector<char> buffer(MNL_SOCKET_BUFFER_SIZE)`（`src/PacketListener.cpp:176`）。
- 正常 verdict 和 fail-open parse path 都会调用它（`src/PacketListener.cpp:206`、`src/PacketListener.cpp:518`）。

建议：

- 已确认采用 per-listener/thread-local fixed verdict buffer。verdict buffer 只用于构造回给 NFQUEUE 内核模块的 netlink verdict 消息，不承载 packet payload。
- 该 buffer 应按 listener thread 复用，避免每包 `std::vector` heap allocation/free；不同 listener 线程各自持有独立 buffer，不共享竞争。
- 这是语义风险较低且可直接解决的 hot-path quick win；落地后仍应用 host build 和 device smoke 验证。

### Guardrail checklist：RDNS 默认关闭且不得在普通路径启用

`rdns.enabled` 是 reverse DNS / PTR 反查开关，不等同于正常 DNS listener 或 domain policy。当前默认关闭，这是正确的。它不是当前电流问题的首要嫌疑；风险在于一旦被普通 UI、RuntimeService 或 checkpoint restore 打开，新 remote IP 可能在 `HostManager::prepare()` 里同步调用 `getnameinfo()`。这个调用虽然不在全局锁内，但仍发生在 NFQUEUE listener thread 内，且 packet verdict 还没回写。

证据：

- packet callback 会在进入 `mutexListeners` shared decision window 之前准备 missing host（`src/PacketListener.cpp:461`、`src/PacketListener.cpp:463`）。
- `HostManager::prepare()` 在 `settings.reverseDns()` 为 true 时调用 `getnameinfo()`（`src/HostManager.hpp:108`、`src/HostManager.hpp:113`、`src/HostManager.hpp:117`）。

建议：

- checklist：RuntimeService 普通启动必须保持 `rdns.enabled=0`。
- checklist：普通 UI 不应提供会长期打开 `rdns.enabled` 的路径；若保留入口，应标为显式诊断能力。
- checklist：checkpoint restore 或配置同步不得意外把 `reverseDns=true` 带入生产后台状态。
- 后续如果保留 RDNS，应移动到后台 resolver queue，绝不能从 verdict path 同步调用。

### Guardrail / design direction：观测能力需要分级

Flow Telemetry 在无 consumer 时确实很轻；但一旦 `level=flow` consumer active，它就是 conntrack observation consumer。这是有意设计且已文档化的行为，但对电量是一个重要产品开关。这里需要把“基础统计”和“全量 flow/conntrack 观测”分成不同等级，而不是让普通 UI 默认承担 full flow monitoring 成本。

证据：

- `PacketManager::make()` 采样 `flowTelemetry.hotPathFlow()` 并设置 `telemetryActive`（`src/PacketManager.hpp:198`）。
- IPRULES 的 Conntrack gating 会 OR 上 `telemetryActive`（`src/PacketManager.hpp:517`）。
- 接口规范明确 Flow Telemetry CT facts producer 与 `iprules.enabled` 解耦（`docs/INTERFACE_SPECIFICATION.md:209`）。

建议：

- 分级方向：默认层只维护必要且低成本的统计，例如 UID/app 维度的 packet/byte 计数，以及后续可讨论的 UID+remote IP 轻量聚合；不默认创建完整 flow lifecycle，也不默认要求 Conntrack facts。
- 分级方向：完整 Flow Telemetry / Conntrack facts 属于显式高成本观测层。只有用户进入实时流量、诊断、调试页面或短窗口采样任务时，才打开 `TELEMETRY.OPEN(level=flow)`。
- RuntimeService 不应在普通后台状态保持 Flow Telemetry consumer 常开，除非当前界面确实需要实时 flow records。
- Activity/diagnostic 场景应优先使用短窗口采集、sampling 或阈值触发模式。
- 增加真机测量 lane：`telemetry off`、`telemetry open but idle UI`、`telemetry active under traffic`。

### Measurement-gated experiment：NFQUEUE queue/thread topology 与 CPU placement

当前一个 queue 对一个 thread 的模型很简单，但 queue 数按 hardware concurrency 对每个 family 扩张。这里没有确认的 correctness bug，也不能直接假设“线程数多就是当前耗电主因”：listener 大多阻塞在 netlink receive 上，线程数量本身未必解释 idle current 增量。真正需要验证的是：`hardware_concurrency()` 是否是移动端 NFQUEUE queue 数的省电/延迟最优点，以及是否需要设备级 CPU placement 策略。

证据：

- 每个 family 的 queue count 来自 `hardware_concurrency()`，至少 4，且强制偶数（`src/PacketListener.cpp:30`）。
- listener thread 是 detached（`src/PacketListener.cpp:82`）。
- runtime topology change 明确是 next-start-only（`docs/INTERFACE_SPECIFICATION.md:61`）。

建议：

- 不把当前 topology 定性为已知问题；先作为测量驱动实验。
- queue count 实验：每个 family 2/4/6/8 queues，对比 idle current、吞吐、verdict p95/p99、queue drops、scheduler wakeups 和 CPU frequency residency。
- CPU placement 实验：默认 scheduler、Android task profile / background cpuset、little-only dogfood 三档；不要默认硬绑小核。
- 在没有电量与 queue distribution 数据前，`shared-flow-pool` 继续保持实验模式。
- detached thread 主要是未来 live rebuild / runtime reconfigure 的生命周期限制，不是当前功耗结论；只有需要运行中重建 NFQUEUE 时，才优先改 owned/joinable listener。

### Architecture TODO：梳理 DNS/domain、IPRULES 与 domain-IP link

packet path 会为 remote IP 准备并发布 `Host` 对象，除非 app 的 interface block mask 能让 host 完全不需要。这里不能简单定性为“删掉 Host cache”或“保留现状”：Host cache / domain-IP link 主要服务 DNS/domain policy 与 IP leak 语义，而 IPRULES 本身直接使用 packet header 构造 L3/L4 key，不依赖 Host 对象。需要把 DNS 域名拦截、DomainPolicy、IPRULES enforcement，以及横跨两者的 domain-IP link 数据结构与流程完整梳理一遍。

证据：

- missing host 在 verdict 前被 prepare（`src/PacketListener.cpp:459`、`src/PacketListener.cpp:463`）。
- `publishPrepared()` 会把 host 放进 `_hosts` 和 IP map，`HostManager` 中未见 eviction policy（`src/HostManager.hpp:127`）。

建议：

- TODO：绘制 DNS response -> DomainManager IP map -> HostManager Host/domain -> packet verdict/debug 输出的完整数据流。
- TODO：明确 IPRULES 与 domain/IP link 的边界：IPRULES enforcement 不应隐式依赖 Host；DomainPolicy/IP leak/debug domain hint 才需要该关联。
- TODO：在梳理完成前，不决定删除 Host cache、增加 anonymous fast path 或给 IP-only host 加 LRU/TTL。
- TODO：后续测量 host count、IPv4/IPv6 map size、named host count 和 RSS 增长，再决定是否需要 cap/TTL。

### Checklist / optimization backlog：IPRULES port-range bucket

IPRULES classifier 已经按 per-UID subtable 编译，并且有 thread-local decision cache；这些是有价值的 guardrail，但不代表当前结构已经是最佳实践。这里的 `range bucket` 主要指 `sport/dport` 端口范围候选，不是 IP/CIDR range：CIDR/IP 维度已经进入 masked key / subtable 结构，exact port 规则进入 exact candidate，端口范围规则才会在 bucket 命中后继续按优先级线性扫描。

证据：

- range candidate vector 按 priority 顺序扫描（`src/IpRulesEngine.cpp:657`、`src/IpRulesEngine.cpp:668`）。
- Preflight 有 recommended/hard cap，包括 5000 总规则和 64 range rules per bucket（`src/IpRulesEngine.hpp:379`、`src/IpRulesEngine.hpp:384`）。
- IPv4/IPv6 都有 thread-local decision cache（`src/IpRulesEngine.cpp:2658`、`src/IpRulesEngine.cpp:2718`）。

当前结论：

- 不能把这条判定为“已优化完成”；最多只能说现有实现有缓存和上限保护。
- 如果真实 ruleset 是 exact-heavy / CIDR-heavy，当前结构可能足够。
- 如果真实 ruleset 是 port-range-heavy，并且 decision cache miss 高，同 bucket 候选多，当前设计仍可能在热路径上退化为线性扫描。

Checklist / backlog：

- `RuntimeService` / 配置入口必须执行 preflight：hard cap 失败直接拒绝启用，recommended cap 超过时输出明确 warning。
- rule compiler 需要持续记录 ruleset shape：exact-heavy、CIDR-heavy、port-range-heavy、CT-consuming，以及 `maxRangeRulesPerBucket`。
- 若实测显示 port-range bucket 成为热点，再引入专门的端口范围索引，而不是继续调大 cap。

可选优化方向：

- 将 bucket 内候选拆成 `exact-exact`、`exact-range`、`range-exact`、`range-range` 四类；一侧端口 exact 时先按 exact 端口分组，减少进入 range 扫描的候选。
- 对真正 range-heavy 的 bucket 构建 priority-aware interval index，用查询端口快速得到候选，再保留当前优先级和 enforce/would 语义。
- 只有在测量证明需要时才上完整 interval tree / segment tree；两维端口、UID、方向、CT、优先级和 would/enforce 语义会让复杂度明显上升，提前做容易引入行为风险。

### Architecture TODO：Flow Telemetry、Debug Stream 与 would/shadow evaluation 边界重叠

Debug Stream 已经不再用 legacy socket 同步写热路径，这是好的；但它和 Flow Telemetry、IPRULES would/shadow evaluation 的产品权责需要重新梳理。当前 `tracked` packet 会构造 explain snapshots、IPRULES candidate snapshots，并分配 stream `Packet` 对象；这更像“短窗口诊断 / 策略解释”，不应该承担长期观测或普通 dashboard 数据源。

原始需求更接近：用户下发一条新策略后，希望知道它是否会命中；如果命中，需要有对应输出，但不真正执行阻断。这应被建模为 policy would/shadow evaluation，而不是默认打开全量 packet debug，也不应该依赖 Flow Telemetry full flow records。

证据：

- `buildExplain` 绑定 `trackedSnapshot`（`src/PacketManager.hpp:194`、`src/PacketManager.hpp:200`）。
- explain snapshot 可包含 IPRULES candidate snapshots（`src/PacketManager.hpp:545`、`src/PacketManager.hpp:560`）。
- tracked packet 会分配 stream packet object（`src/PacketManager.hpp:486`、`src/PacketManager.hpp:668`、`src/PacketManager.hpp:749`）。
- `observePktTracked()` 会持有 packet stream mutex 并写 bounded ring/pending events（`src/ControlVNextStreamManager.cpp:360`）。

当前结论：

- Flow Telemetry：负责 flow-level 可观测性、CT/flow lifecycle、聚合输出；必须 consumer-driven，默认关闭 full flow。
- Debug Packet Stream：负责 per-packet explain / 排障；必须短窗口、tracked UID 有上限，最好带 TTL 或随 session 关闭自动清理。
- IPRULES would/shadow evaluation：负责“新策略是否会命中”的 dry-run 语义；默认应优先输出规则命中计数、UID/方向/远端摘要等低成本结果，只有用户展开具体样本时才进入 packet explain。

Checklist / TODO：

- 梳理并文档化 Flow Telemetry、Debug Stream、IPRULES would/shadow evaluation 三者边界。
- packet debug 页面关闭时必须清理 tracked；tracked 状态不应作为长期后台配置常驻。
- 限制同时 tracked 的 UID 数量，超过时拒绝或自动过期。
- 如果只是验证新策略命中情况，优先使用 would/shadow counters 或 sampled examples，不打开长期 tracked packet stream。

### Architecture TODO：PerfMetrics 也应纳入诊断 / 可观测性边界整理

PerfMetrics 本身实现不算重：默认关闭时热路径只读一个 relaxed atomic 开关；开启后才会在每个采样包上做 monotonic clock read、bucket 计算和 atomic 更新。真正的问题是它现在像一个独立诊断开关，没有和 Flow Telemetry、Debug Stream、普通 dashboard 指标形成清晰边界。

因此这条不应单独理解为“PerfMetrics 要不要保留”，而应归入后续诊断 / 可观测性模块边界整理：哪些指标可以常驻、哪些只能短窗口诊断、哪些属于 full flow 观测、哪些属于 packet explain，都需要明确 contract。

证据：

- packet callback 只有在 `perfMetrics.enabled()` 为 true 时采样 start/end time（`src/PacketListener.cpp:190`、`src/PacketListener.cpp:520`）。
- Metrics 使用 sharded atomics 和 cache-line alignment，这是好的；但仍然是每样本工作（`src/PerfMetrics.hpp:62`、`src/PerfMetrics.hpp:90`、`src/PerfMetrics.hpp:153`）。

Checklist / TODO：

- 生产默认保持 `perfmetrics.enabled=0`；它不能悄悄成为普通 dashboard 的常驻数据源。
- RuntimeService 只应在短诊断窗口内打开它，最好带 TTL / session 生命周期。
- 后续边界整理时区分：常驻低成本 counters、短窗口 latency histogram、Flow Telemetry records、packet explain snapshots。
- 如果未来需要常驻健康指标，应设计更轻的 counters 或 sampling，而不是默认启用每包 latency histogram。

### Medium：现有性能记录缺少 idle power 口径

现有 perf 脚本适合吞吐和延迟，但用户症状是日常/空闲电流。这个问题需要 idle/low-traffic power lane。

证据：

- `docs/testing/PERFORMANCE_TEST_RECORD.md` 已把 IPRULES off/on、NFQUEUE backlog、CPU 采集列为后续 TODO（`docs/testing/PERFORMANCE_TEST_RECORD.md:93`）。
- 当前脚本采集 `nfq_total_us`、吞吐、连接率和 samples/sec，但不采集 battery current 或 wakeup rate（`tests/device/ip/perf_overnight_summarize.py:11`、`tests/device/ip/perf_overnight_matrix.sh:354`）。

建议：

- 增加 power audit 脚本，稳定窗口采样 current、per-thread CPU、NFQUEUE queue stats 和 vNext metrics。
- 不要把 `nfq_total_us` 单独当成功耗 proxy。它测的是 callback latency，不覆盖 wakeups、queue idle cost、kernel copy work 或调度行为。

## 产品默认值与取舍

低功耗生产默认建议：

- 只有保护确实 active 时才保持 daemon datapath running。保护关闭时，RuntimeService 应停止 daemon 并清理 NFQUEUE hooks；如果后续产品需要关闭保护但保留配置/control 能力，再引入不安装 NFQUEUE hook 的启动模式。
- 没有 active IP rules 时保持 `iprules.enabled=0`。
- `perfmetrics.enabled=0`，只在短诊断窗口开启。
- `rdns.enabled=0`，普通 UI 不应打开 RDNS。
- 观测能力分级：默认只保留低成本基础统计；Flow Telemetry `level=flow` 默认关闭，只有 consumer 页面/session 需要完整 flow/CT records 时才短窗口打开。
- Debug `tracked=0` 默认；tracked 应按 UID、临时、明确诊断用途。
- `nfqueue.topology=split-in-out` 继续保持默认，直到 `shared-flow-pool` 有稳定性和电量数据。

功能成本取舍：

- DomainPolicy 和 IPRULES 不是冗余关系。DomainPolicy 提供用户可理解的语义；IPRULES 提供 enforcement 和 L3/L4 fallback。性能目标应该是清晰门控，而不是删除某一层。
- Flow Telemetry 是长期可观测性的正确方向，但在移动端必须 consumer-driven，并采用窗口化或 sampling。
- Debug Stream explainability 对支持和排障有价值，但不应支撑普通 dashboard。

## 优化路线

### Quick wins

1. 已确认：复用 per-listener/thread-local verdict buffer，移除 `sendVerdict()` 的每包 `std::vector` 分配。
2. 对热路径高频错误日志加 rate limit。
3. 文档化 RuntimeService 默认值：telemetry closed、perfmetrics off、tracked off、rdns off。
4. 给 review 增加无设备静态 checklist：NFQUEUE callback 不新增 blocking I/O、allocation 或 mutex。

### 需要 OpenSpec 的中等改造

1. 增加 next-start-only datapath mode，用于保护关闭时避免 NFQUEUE hook。
2. 增加 bounded NFQUEUE copy range 实验：`NFQNL_COPY_PACKET` 保留，copy range 暂定 `512` 字节；packet/original length 从 `NFQA_CAP_LEN` 或 IP header 推导。
3. 把 RDNS 移出 packet callback，放入 bounded background work；或者从生产配置中移除。
4. 梳理 DNS/domain、IPRULES 与 domain-IP link 的数据结构和流程，再决定 Host cache / IP-only host 的优化边界。
5. 梳理 Flow Telemetry、Debug Packet Stream、PerfMetrics 与 IPRULES would/shadow evaluation 的模块边界，避免策略 dry-run、packet explain、latency histogram 和长期 flow 观测互相替代。

### 需要测量驱动的实验

1. `split-in-out` vs `shared-flow-pool`：对比 latency、queue skew 和 current。
2. 同一设备/workload 下每 family 2/4/6/8 queue count。
3. CPU placement 实验：默认 scheduler、Android task profile / background cpuset、little-only dogfood，对比 big-core wakeups、freq residency、queue drops、p99 和电流。
4. 观测分级实验：基础 UID/app 计数、UID+remote IP 轻量聚合、Flow Telemetry full records 三档，对比热路径成本、电流和 UI 可用性。
5. IPRULES ruleset shape：exact-heavy、CIDR-heavy、port-range-heavy、CT-consuming、background UID spread。

## 建议的真机测量矩阵

每个场景应运行到 DVFS 与热状态稳定。idle power 建议 cooldown 后至少 5-10 分钟窗口。traffic 场景复用 Tier-1 controlled topology 和现有 perf scripts。

场景：

- Baseline：daemon stopped。
- daemon running with no NFQUEUE hooks（如果先实现该模式）。
- NFQUEUE installed，`block.enabled=0`。
- `block.enabled=1`，`iprules.enabled=0`，telemetry closed。
- `iprules.enabled=1`，empty rules。
- `iprules.enabled=1`，representative rules。
- `iprules.enabled=1`，CT-consuming rule。
- Flow Telemetry open with low thresholds。
- Debug pkt stream active for one tracked UID。
- `rdns.enabled=1` with new remote IP churn。
- `nfqueue.topology=shared-flow-pool`，重复上述关键场景。

采集项：

- Battery/current：设备可用时采 `current_now`，长窗口辅以 `dumpsys batterystats`。
- CPU：`top -H -p <pid>`，或设备可用的 `pidstat` 等价工具。
- Wakeups/profile：短窗口用 `simpleperf` 或 Perfetto trace。
- NFQUEUE：`/proc/net/netfilter/nfnetlink_queue` sequence、queue drops、user drops、queue skew。
- Daemon metrics：`METRICS.GET(name=perf|conntrack|telemetry|reasons|traffic)`。
- Logcat：热路径错误日志频率。

## 后续修复验收标准

- protection-off mode 的 current 应接近 daemon stopped baseline。
- full-copy vs bounded-copy 实验不能回归 verdict correctness 或 IPv6 extension-header handling。
- queue-count 改动不能在现有 perf profiles 下增加 queue drops。
- Flow Telemetry active mode 应有明确吞吐/电流目标，例如 controlled load 下吞吐下降不超过 5-10%，并单独定义 idle current budget。
- Debug/tracked 模式必须从普通后台默认值中排除。

## 静态审计边界

本报告没有运行 device commands、ASAN/TSAN、perf scripts 或 power measurements。所有关于电流的解释都是基于代码证据的假设，不是最终实测结论。下一步应先做真机测量，再决定大架构改动。
