# l4-conntrack-core Specification

## Purpose
Defines the minimal userspace L4 conntrack contract used by `IPRULES` to expose `ct.state` and `ct.direction` safely on Android.
## Requirements
### Requirement: Userspace L4 conntrack core exists and is thread-safe
系统 MUST 提供 userspace L4 conntrack core，用于在 IP（IPv4/IPv6）包级别计算最小 conntrack 视角元数据（例如 `ct.state` 与 `ct.direction`），并满足：
- 支持协议范围：`TCP / UDP / ICMP / other`（其中 `ICMP` 覆盖 ICMPv4 与 ICMPv6；UDP 可按轻量 pseudo-state 处理）。
- correctness MUST NOT 依赖 NFQUEUE worker 拓扑（例如 `INPUT/OUTPUT split` 或 future `shared pool`）。
- conntrack update API MUST 支持多线程并发调用；对同一 flow 的双向包在不同线程并发到达时，结果 MUST 仍一致且不发生内存不安全问题（UAF/数据竞争导致崩溃）。

#### Scenario: Concurrent bidirectional updates are safe
- **GIVEN** 同一条 flow（IPv4 或 IPv6）的 orig 与 reply 包在不同线程同时到达
- **WHEN** 两个线程并发调用 conntrack update
- **THEN** 系统 SHALL 不崩溃、不产生内存不安全问题
- **AND** 对后续相同 flow 的包，`ct.state/ct.direction` SHALL 保持自洽（不出现不可能组合）

### Requirement: Conntrack key is per-UID and excludes interface identity
系统 MUST 将 `uid` 纳入 conntrack key（per-app firewall 语义），并将 `family`（ipv4/ipv6）纳入 conntrack key，以避免 v4/v6 五元组发生碰撞；同时系统 MUST NOT 将接口身份（如 `ifindex/ifaceKind`）纳入 conntrack key。

说明：
- 同一条连接在接口切换（wifi/data/vpn）时不应被拆成多条 conntrack entry；
- 接口层面的策略属于 `IFACE_BLOCK` 或其它更高层策略，不属于 conntrack 自身的 flow identity；
- `family` 属于 L3 identity：同一 `uid` 下 IPv4 flow 与 IPv6 flow 必须被视为不同 entry 空间。

#### Scenario: Interface change does not split a flow
- **GIVEN** 同一 `uid` 的同一条 TCP flow（同 `family`、同 src/dst/proto/ports）
- **AND** 流量在连接生命周期内发生接口切换（例如 wifi → data）
- **WHEN** conntrack 分别处理切换前与切换后的数据包
- **THEN** 系统 SHALL 将其视为同一条 flow（不得因接口变化把其拆成新的 entry）

### Requirement: Conntrack output includes minimal state and direction
系统 MUST 至少输出以下维度，供上层规则引擎使用：
- `ct.state`：至少可区分 `new/established/invalid`
- `ct.direction`：至少可区分 `orig/reply`

其中：
- `ct.direction` MUST 由 conntrack 自身根据双向 key 判定，不得由调用方通过 “INPUT/OUTPUT” 或线程局部信息猜测。

#### Scenario: Direction is determined by conntrack, not call-site heuristics
- **GIVEN** 同一条连接的两个方向数据包
- **WHEN** conntrack 分别处理这两个方向的数据包
- **THEN** 两个方向的包 SHALL 被标记为不同的 `ct.direction`（`orig` vs `reply`）

### Requirement: TCP tracking uses OVS-grade loose semantics
系统 MUST 采用与 OVS conntrack 同级别的宽松（loose）语义追踪 TCP 连接；系统 MUST NOT 在第一阶段引入“必须从 SYN 开始/严格握手”的 strict 模式作为语义前提。

#### Scenario: Midstream TCP packet is not rejected solely for missing SYN
- **GIVEN** 一个此前未被 conntrack 见过的 TCP 五元组
- **AND** 首个到达的数据包不是 SYN（例如 ACK-only / midstream packet）
- **WHEN** conntrack 处理该数据包
- **THEN** 系统 SHALL 不得仅因“不是从 SYN 开始”而强制把该包判为 `ct.state=invalid`

### Requirement: TCP conntrack requires TCP header metadata beyond ports
为了实现 OVS 等价的 TCP conntrack 语义，conntrack core MUST 能获得 TCP header 的关键字段（至少包含）：
- `flags`
- `seq/ack`
- `window`
- `dataOffset`（header length）
- `tcpPayloadLen`

以及（按需）：
- `wscale`（TCP option；解析失败按 OVS 口径回落）

#### Scenario: TCP header length and payload length are computed from dataOffset
- **GIVEN** 一个 TCP 包其 `dataOffset > 5`（包含 TCP options）
- **WHEN** conntrack 处理该包并更新 TCP 状态
- **THEN** 系统 SHALL 使用 `dataOffset` 计算 `tcpPayloadLen`（不得把 options 误当成 payload）

### Requirement: IPv4 fragments are treated as invalid (no reassembly in phase 1)
本阶段系统 MUST NOT 尝试做 IP 分片重组：
- 当输入包为 IPv4 分片（MF 或 frag offset 非 0）时，conntrack 视角 MUST 以“无法建立可靠 L4 语义”的方式处理（例如 `ct.state=invalid`）。
- 当输入包为 IPv6 分片（存在 Fragment header）时，conntrack 视角同样 MUST 以“无法建立可靠 L4 语义”的方式处理（例如 `ct.state=invalid`）。

#### Scenario: IPv4 fragments map to ct.state=invalid
- **GIVEN** 一个 IPv4 分片包（MF=1 或 frag offset 非 0）
- **WHEN** conntrack 处理该包
- **THEN** 系统 SHALL 输出 `ct.state=invalid`

### Requirement: Conntrack can be gated to avoid unnecessary hot-path cost
当系统在某个 `uid+family` 上没有任何 active 规则/功能使用 conntrack 输出维度时，系统 MUST 避免在热路径对该 `uid+family` 的每包执行 conntrack update（或等价路径），以保持 near-zero overhead。

#### Scenario: No ct consumers implies no ct hot-path work
- **GIVEN** 当前 active ruleset 中没有任何规则使用 `ct` 维度（对目标 `uid+family`）
- **WHEN** NFQUEUE 持续处理该 `uid+family` 的流量
- **THEN** 系统 SHALL 不在热路径执行 conntrack update（或等价地做到可忽略开销）

