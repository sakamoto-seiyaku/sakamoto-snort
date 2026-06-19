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
- 不得因为未来高级能力存在，让普通路径承担 CT / DPI / association 等成本。
- 不得用无界 map / 无界 cache / 无界历史记录承载普通后台能力。
- 每个昂贵事实都必须 consumer-driven：没有明确 consumer 时不计算。
- 每个 packet stage 必须支持 short-circuit：前面已有明确 verdict 时，后面 stage 不评估、不查询、不构造额外事实。
- 当前尚未正式上架，SNORT-10 重构不为旧 stream / record / control ABI 背兼容成本；旧字段和旧语义可以直接删除或替换。除非明确用于临时迁移或测试，不因兼容旧模型引入额外 hot-path 成本或概念复杂度。

## 2. Daemon lifecycle 与组件 gate

daemon lifecycle 由 Android-side `RuntimeService` / 前台服务负责。daemon 是否运行、是否绑定前台通知、何时终止，不由 `block.enabled` 表达。

`block.enabled` 是 daemon 内部的组件 / 策略 gate。它控制过滤类 policy 是否执行，不表示 native daemon 停止，也不表示 NFQUEUE hook 被移除。

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

### 4.1 Baseline accounting

Baseline accounting 是 daemon/dataplane 运行时常驻的最低成本统计层。

范围：
- per app / UID 与 device 维度。
- rx/tx packet count。
- rx/tx original IP packet bytes。
- 不依赖 Conntrack。
- 不依赖 Domain-IP Association。
- 不依赖 Flow Telemetry 或 Debug Stream。
- 不维护 remote IP / port 分布。

Baseline accounting 不使用 copied prefix length，也不统计 L4 payload-only bytes。

### 4.2 Traffic Windows

Traffic Windows 是普通用户可以长期启用的 online 观测层，不是短诊断能力，也不是完整历史数据库。它比 baseline 更细，但必须继续以极低热路径成本为设计目标。

时间语义：
- 只支持 relative trailing windows，例如 `last 15m`、`last 1h`、`last 5h`。
- 窗口右端固定为 `now`。
- 前端可配置有限个窗口。
- 新窗口只从启用时开始累积，不回填历史。
- 第一版不支持“距现在 2h 到 1h”这种 relative interval。

统计语义：
- usage 只统计 accepted traffic。
- blocked 包只统计 packet count，不统计 blocked bytes。
- blocked bytes 不作为用户流量消耗，也没有稳定产品语义。

第一版 Top-K 边界：
- 基础分区：per app + direction + trailing window。
- remote IP Top-K：按 accepted bytes。
- protocol Top-K：按 accepted bytes / packets。
- protocol + remote port Top-K：按 accepted bytes / packets。
- blocked count 可按 reason / rule 做 bucket 或 Top-K。
- 不做 `app + direction + proto + remote IP + port` 的完整组合 cube。

remote IP Top-K 可以使用 bounded approximate heavy-hitter。第一版可按 `displayK=10, capacity=64` 作为默认方向；尾部几十 KB 级别的排序误差可接受，但实现应能暴露近似误差用于调试。

Traffic Windows 不直接输出 domain hint。前端如果需要把 remote IP 显示成域名，应独立调用 Domain-IP Association 的 batch lookup。

### 4.3 Packet diagnostics 与高级观测边界

常态 Flow/Fact Records 与用户显式诊断必须分开。

Packet diagnostics 第一版定位为用户主动开启的 IPRULES / packet policy 诊断模式：
- 使用 `DIAGNOSTICS.START` / `DIAGNOSTICS.STOP` 这类诊断语义接口，而不是继续扩展泛化 `STREAM.*`。
- 使用 vNext socket JSON event stream，不进入 Flow/Fact Record 的 shared-memory telemetry ABI。
- 由 session 持有单个 Diagnostic Focus；只诊断一个 app / UID；STOP、socket detach 或 session close 必须释放 focus。
- 不支持 replay；不保留 `horizonSec` / `minSize`；没有 active consumer 时不构造 explain 或维护诊断 replay ring。
- 不迁移旧 `wouldRuleId` / `wouldDrop` 平行归因模型；observe 规则使用 `ruleId + reasonId + ruleMode + verdict` 的同一 winner 归因格式。
- 不输出 legacy `host` / domain 字段；IP 到域名展示由前端按需查询 Domain-IP Association。

Packet diagnostics 是显式高成本模式，可以输出完整 explain、stage、skipped reason、rule snapshot 与候选路径；但它面向用户策略排查，不输出 raw hot-path capability mask、compiler table 等开发者内部结构。开发者性能 trace 后续走独立路径。

DNS stream 暂时冻结，不并入 `DIAGNOSTICS.*`，等 Domain/DNS 线单独整理。现有 activity stream 只输出 `blockEnabled` 状态，不迁移到新模型；前端需要状态时使用 `CONFIG.GET(block.enabled)`。

## 5. Conntrack、IPRULES 与未来 DPI

### 5.1 Conntrack 定位

L4 Conntrack 是高级 datapath primitive，不是普通用户默认路径能力。

它服务：
- Stateful IPRULES 的 `ct.*` 规则。
- 第三层完整流观测。
- 未来 DPI / L7 policy。
- 未来 FORWARD / hotspot gateway mode。

它不服务：
- Baseline accounting。
- Traffic Windows 第一版。
- Basic IPRULES。
- 普通用户默认 UI 卖点。

Conntrack 必须 consumer-driven。没有 `ct.*` policy consumer、完整流观测 consumer、DPI consumer 或未来 gateway consumer 时，不应进入对应 packet path。

### 5.2 IPRULES 分层

IPRULES 概念上拆成两层：
- Basic IPRULES：只使用 PacketFacts，不依赖 Conntrack。
- Stateful IPRULES：使用 CtFacts，例如 `ct.state` / `ct.direction`。

实现上可以继续共用同一个 engine / snapshot / compiler，但编译结果必须让 hot path 能避免 Basic 包承担 Stateful 成本。

高级规则应拆成：
- cheap precondition：只用 PacketFacts，例如 family、direction、iface、proto、src/dst、port。
- expensive condition：CT、DPI、Domain-IP Association 等昂贵事实。

只有 cheap precondition 命中候选时，才计算对应昂贵事实。

### 5.3 DPI / L7

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
- DPI 只在 gated flow 上维护最小状态，分类完成后停止重复跑 classifier。

## 6. Hot-path capability summary

需要一个统一的 Hot-path capability summary，覆盖 policy 和 observation consumers。

目标：
- packet path 先读一个 `uint64_t primary` mask。
- primary mask 用于快速判断是否存在 CT / DPI / Traffic Windows / Domain-IP Association / Debug explain 等 consumer。
- 使用更多 bit 换取更少后续流程是可以接受的；第一版可规划低 48 bit 给当前/近期 hot-path pruning，高 16 bit 保留。
- 不把 500+ DPI protocol 直接放入 primary mask。
- 允许 lazy secondary masks，例如 `ctDetail`、`dpiDetail`、`assocDetail`。
- 只有 primary 对应 bit 命中时，才读取 secondary mask。
- 不在每包路径扫描规则列表。

Basic evaluator 和 advanced prefilter 可以共享编译结构，但概念上分开：
- Basic evaluator 直接产出 allow/block verdict。
- Advanced prefilter 只产出本包可能需要哪些 expensive facts，以及候选高级规则集合。

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

## 8. Verdict pipeline

目标 pipeline 顺序：
1. Interface policy / `IFACE_BLOCK`。
2. Basic IPRULES。
3. Stateful IPRULES。
4. Future DPI / L7 Policy。
5. Resolved-IP Policy。
6. Default allow。

任何 enforce stage 明确命中 allow/block 后，后续 stage 必须 short-circuit。

Resolved-IP Policy 是很靠后的 fallback。它不应覆盖用户明确写的 IP / CT / DPI 策略。

## 9. DomainPolicy、Domain-IP Association 与 Resolved-IP Policy

### 9.1 DomainPolicy

DomainPolicy 继续负责 domain-level allow/block policy 与 DNS verdict attribution。它不应和 IPRULES 合并成一个规则系统。

后端不引入 Google Play / full build 这种产品 profile 枚举。后端只提供独立模块和 gate；不同前端版本通过启用或隐藏不同能力形成产品形态。

### 9.2 Domain-IP Association

Domain-IP Association 是独立模块，不是 DomainPolicy 自身，也不是 Basic IPRULES matcher。

职责：
- 记录 DNS learned domain-to-IP relationships。
- 支持 UI enrichment / debug evidence。
- 支持 Resolved-IP Policy。
- 提供 batch lookup，让前端把 IP 转成 domain hint。

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
- 不参与 baseline accounting 或 Traffic Windows 默认展示。
- 不得在 packet verdict path 同步执行。
- 如果保留实现，应放入 bounded background queue，并有 TTL/cache/rate limit。

## 10. Host / HostManager 重构方向

现有 `HostManager` / `Host` / `DomainManager::_byIP` 把 packet remote endpoint、domain-IP association、RDNS、debug hint 混在一起。

目标架构中，packet verdict hot path 不应为了每个 remote IP materialize `Host` 对象。

重构方向：
- Packet path 使用 `PacketFacts` / remote endpoint facts。
- Domain-IP Association 查询返回轻量 association result / domain hint。
- RDNS 不再写入 packet verdict path 的 Host。
- `Host` 如保留，应只属于 debug/enrichment 层，而不是 verdict API 的核心输入。

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
- 第三层高级观测的最终命名。
- Flow Telemetry / Debug Stream / shadow evaluation 是否共享统一 transport。
- DNS Observation Source 的实现。
- FORWARD / hotspot gateway mode。
- DPI 库选型与具体 adapter。
- Traffic Windows 的具体 heavy-hitter 数据结构。

## 13. 后续实现拆分建议

后续应按以下顺序拆 Plane work item：
1. 修正 NFQUEUE bounded copy 与 original IP packet bytes 口径。
2. 去除 packet hot path 的 per-packet allocation quick wins，例如 verdict buffer 复用。
3. 引入 `PacketFacts` 栈上输入模型，减少 Host / Domain 耦合。
4. 抽出 Domain-IP Association 模块与独立 gate。
5. 降级 RDNS 为后台诊断 enrichment。
6. 重新整理 Resolved-IP Policy stage。
7. 设计 Hot-path capability summary 与 advanced prefilter。
8. 设计 Traffic Windows 数据结构与接口。
9. 单独讨论 observability / Debug Stream / shadow evaluation 边界。
