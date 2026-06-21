# VPP Core Datapath 可行性调查

日期：2026-06-21
状态：调查报告 / 讨论输入。本文不是 ADR，也不是实现任务列表。

## 1. 背景

这轮讨论从 Android VPN/TUN mode 触发，但真正扩展出来的问题是：

- Snort 是否可以不再只围绕 Android root / NFQUEUE 构建 datapath？
- 是否可以把不同平台的收包/发包隐藏在 Adapter 后面？
- 是否可以把统一 packet processing core 建在 VPP graph / feature arc / worker / buffer 机制上？
- NFQUEUE、Android VPN `tun-fd`、Linux TUN/AF_PACKET 等入口是否都能进入同一套 VPP core？
- HEV/tun2socks 这类组件应不应该占有 `tun-fd`，还是只作为 egress/proxy engine？

本文把当前调查沉淀下来，方便后续继续讨论或拆 POC。它只回答“可行性和边界”，不要求当前主线立刻切换到 VPP。

## 2. 简短结论

VPP 路线比预期更有潜力：它不只是高性能路由器，也可以作为跨平台 packet processing runtime。

合理形态是：

```text
Platform RX/TX Adapter
  - Android root: NFQUEUE
  - Android VPN: external tun-fd
  - Linux root: NFQUEUE / TUN / AF_PACKET
  - future macOS/iOS: utun / NetworkExtension, 需另查
        |
        v
Unified VPP graph
  - packet metadata sidecar
  - worker ownership / handoff
  - CT / session
  - policy
  - telemetry
  - drop / log / forward decision
        |
        v
Platform egress
  - NF_ACCEPT / NF_DROP
  - TUN write
  - HEV / socks / route / raw output
```

但是必须压住边界：

- 可跨平台的是 VPP graph 内的 dataplane core，不是整个 Android 产品语义原封不动跨平台。
- 平台 RX/TX Adapter 必然平台化。
- UID attribution 必然平台化。
- Android / mobile mode 不能默认 DPDK 式 polling。
- worker-local session/CT state 不能因为 VPP buffer 能 handoff 就自动变成全局正确。

因此建议把 VPP 放成高价值探索线，而不是立刻替换当前主线。

## 3. 本地 Git/vpp 证据

参考仓库为：

```text
/home/js/backup/backup/Git/vpp
```

不是 `POC/vpp`。

### 3.1 NFQUEUE 插件

本地已有 NFQUEUE -> VPP graph 的原型插件：

```text
/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/
```

它证明了 NFQUEUE packet 可以进入 VPP：

- `nfq_open()` / `nfq_create_queue()` 打开 queue。
- `nfq_set_mode(..., NFQNL_COPY_PACKET, 0xffff)` 获取完整 packet bytes。
- `nfq_fd()` 注册到 VPP `clib_file` / epoll。
- fd ready 后唤醒 `nf-queue-input`。
- input node `recv(nfq_fd)` 后调用 `nfq_handle_packet()`。
- callback 分配 `vlib_buffer_t`。
- 把 NFQUEUE 的 L3 IP payload copy 到 VPP buffer。
- 在 TX path 里用 `packet_id` 调 `nfq_set_verdict(..., NF_ACCEPT, ...)`。

关键文件：

- `/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/device.c`
- `/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/node.c`
- `/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/main.c`

当前插件是原型状态，不是可直接作为 Snort 生产 Adapter 的实现。

### 3.2 NFQUEUE 当前接入的元数据

当前插件只把极少 metadata 写到 VPP buffer：

```text
vnet_buffer(b0)->sw_if_index[VLIB_RX]
vnet_buffer(b0)->sw_if_index[VLIB_TX]
vnet_buffer3(b0)->netfilter_queue_packet_id
vnet_buffer3(b0)->netfilter_queue_queue_num
```

它只读取：

- `nfq_get_msg_packet_hdr()`，但只取 `packet_id`。
- `nfq_get_payload()`，取 packet bytes。

它没有读取或注入：

- `NFQA_UID`
- `NFQA_GID`
- `NFQA_IFINDEX_INDEV`
- `NFQA_IFINDEX_OUTDEV`
- `NFQA_MARK`
- `NFQA_TIMESTAMP`
- packet hook / direction
- skb info
- original length / copied length

所以当前答案是：UID 等 Snort 需要的事实不会自动存在于 VPP buffer metadata 中。需要我们自己补 Adapter metadata sidecar。

建议未来 Snort/VPP NFQUEUE Adapter 形成类似 sidecar：

```text
adapterKind = nfqueue
packetId
queueNum
hook / direction
uidKnown / uid
gidKnown / gid
ifindexKnown / indev / outdev
markKnown / mark
timestampKnown / timestamp
copiedLen / originalLen
```

packet bytes 放在 VPP buffer；packet facts 和 verdict handle 放在 sidecar / buffer opaque / session attachment，不应改 packet bytes。

### 3.3 NFQUEUE 插件的原型味

当前 `stellar_netfilter_queue_deprecated` 存在这些问题：

- 目录名标记为 `deprecated`。
- 只看到 `nfq_bind_pf(AF_INET)`，双栈支持不完整。
- 为了进入 VPP Ethernet path，在 L3 IP payload 前补 fake Ethernet header。
- VPP interface 被 L2 xconnect 到自己，TX 时发 `NF_ACCEPT`。
- TX path 目前只明确发送 `NF_ACCEPT`。
- free callback 里有 `NF_DROP` fallback，但依赖 `VNET_BUFFER_F_FROM_NETFILTER_QUEUE`，RX path 未看到稳定设置该 flag。
- open queue 后把指定 worker 上的 input node 改成 `VLIB_NODE_STATE_POLLING`，这在 mobile idle 场景不可接受。
- 没有 Snort 需要的 `PacketFacts` / Adapter-neutral metadata。

结论：它证明“NFQUEUE 能接进 VPP”，但不能证明“Snort 所需 NFQUEUE 语义已经完整可用”。

### 3.4 Session manager / security enforcer / telemetry

本地 VPP 有一套比较完整的 `stellar_*` 插件可参考：

- `stellar_session_manager`
- `stellar_security_enforcer`
- `stellar_acl`
- `stellar_telemetry`
- `stellar_interceptor`
- `stellar_feature_set`

其中 `stellar_session_manager` 的核心价值在于：

- 在 `ip4-unicast` / `ip6-unicast` / L2 arcs 前挂 session manager。
- 构造自定义 session feature arcs：
  - `stellar-tcp-session`
  - `stellar-udp-session`
  - `stellar-icmp-session`
- 后续 enforcer / scanner / exporter 挂到 session arc。
- buffer metadata 携带 session pointer、flow direction、feature arc 进度。
- timeout node 用 pseudo packet 触发 close 事件。

这说明 VPP graph / feature arc 足以承载 CT、stateful policy、telemetry 这类 Snort dataplane 能力。

但不能照搬：

- 当前 session runtime 是 per-worker runtime/table。
- Snort 已讨论的 CT A++ 方向要求 correctness 不依赖 NFQUEUE topology，也不应默认同 flow 同 worker。
- 如果使用 VPP worker-local session，必须先设计 flow owner / handoff / global correctness 边界。

## 4. VPN/TUN fd 接入

Android `VpnService.Builder.establish()` 返回的是 VPN interface fd。读这个 fd 得到 routed outbound IP packet，写这个 fd 等价于把 inbound packet 注入系统。

这和 Snort 需要的包层级匹配：它是 L3 IP packet，不是 Ethernet frame。

但 VPP 内置 tap/tun 并不天然适合这个模型。VPP tap/tun 通常自己 open `/dev/net/tun` 并配置 interface；Android VPN mode 是外部 App/VpnService 已经创建 fd，然后把 `tun-fd` 交给 native。

因此 VPN mode 合适的 VPP 接入是新写一个 fd/TUN plugin：

```text
external VpnService tun-fd
  -> VPP fd-tun input node
  -> alloc vlib_buffer_t
  -> direct ip4/ip6 path or Snort ingress arc
  -> CT / policy / telemetry
  -> VPP fd-tun output node
  -> write(tun_fd)
```

这个 plugin 应该：

- 接收外部传入 fd，不自行创建 Android VPN。
- 用 `clib_file` / epoll 监听 fd readiness。
- idle 时 sleep，不做常驻 polling。
- 读到 packet 后只 copy 一次到 VPP buffer。
- metadata 用 sidecar，不改 packet bytes。
- 输出方向通过 device output / custom output node 写回 fd。

## 5. HEV / tun2socks 的位置

HEV 可以用，但不应直接占有 Android 主 `tun-fd`。

如果 HEV 直接拿走 VPN fd：

```text
Android tun-fd -> HEV -> socks5
```

那么 VPP/Snort 不在每包路径上，无法做 CT、policy、drop、log、UID attribution。

如果 VPP 是 core，HEV 应该是 egress/proxy engine：

```text
Android tun-fd
  -> VPP fd-tun input
  -> CT / policy / log / drop
  -> allow packet enters HEV adapter
  -> HEV socks5 upstream
  -> HEV response returns into VPP packet path
  -> policy / log
  -> VPP fd-tun output writes to Android tun-fd
```

这里可能需要一点魔改：

- 让 HEV 暴露 packet I/O callback；
- 或用内部 fd/socketpair/TUN shim 把 VPP 和 HEV 连接起来；
- 或先在 POC 阶段接受一次额外 copy，验证流程正确性。

Android VPN 下 HEV 的 upstream socket 必须由 VPN owner 调 `protect()`，否则会回流进 VPN 造成环路。

## 6. Idle CPU / polling 风险

VPP 可以高性能到占满 core，但这不是所有 input mode 的必然行为。

需要区分：

- DPDK / 高性能路由：通常轮询 RX queue，没流量也可能一个 worker core 100%。
- fd / epoll / interrupt 型 input：没流量时可以 sleep。
- `af_packet`：本地代码有 adaptive 行为，有包时 polling，没包时 interrupt。
- 当前 `stellar_netfilter_queue_deprecated`：注册 node 时是 `INTERRUPT`，但 open queue 时把某个 worker 上的 node 改成 `POLLING`，所以原样照搬会有 idle CPU 风险。

Snort/VPP mobile mode 必须要求：

```text
fd ready -> epoll callback -> set_interrupt_pending
-> input node drain fd
-> no packet -> return to interrupt / epoll sleep
```

不应长期：

```text
while true:
  recv(fd, DONTWAIT)
```

这应作为 VPP POC 的第一类验收指标。

## 7. VPP buffer / worker / handoff

理论上，只要不同平台入口都能把 packet 变成 VPP buffer，后面的 VPP graph、feature arc、worker queue、handoff 都可以复用。

VPP 已有基础能力：

- packet 进入 VPP 后变成 `vlib_buffer_t`。
- graph 中传递的是 buffer index。
- node 之间通过 frame 批量传递。
- worker 之间可以通过 frame queue handoff。
- trace 也支持 handoff 场景。

但要分清：

- packet buffer 可以跨 worker；
- worker-local state 不会自动跨 worker 正确。

正确用法是尽早确定 flow owner：

```text
RX adapter
  -> parse flow key / subject metadata
  -> select owner worker
  -> handoff
  -> CT / session / policy all run on owner worker
```

危险用法是：

```text
worker A creates session pointer
  -> packet handoff to worker B
  -> worker B continues using worker A local session pointer
```

所以 VPP handoff 能帮我们，但不能替代 CT 并发语义设计。

## 8. Metadata / UID attribution

Snort 需要的 metadata 不能假设来自 VPP 或平台统一提供。

建议边界：

```text
Packet bytes:
  VPP buffer owns packet bytes

Packet metadata:
  Adapter-neutral sidecar or buffer opaque

Long-lived flow/session state:
  CT/session entry or attachments
```

NFQUEUE/root mode 可以从 NFQUEUE attr 获取 UID、ifindex、hook 等，但当前本地 VPP 插件没有实现。

VPN/TUN mode 的 fd 本身没有 per-packet UID。Android 下 UID attribution 应由 Snort-owned `UidAttributionProvider` 调 Java framework API，例如 `ConnectivityManager.getConnectionOwnerUid()`；Linux 下走 socket ownership 查询。失败时必须保持 `uidKnown=false`，不能伪造成 VPN app UID。

VPP core 不应硬编码 Android UID 语义；它应消费 normalized metadata：

```text
uidKnown
uid
direction
family
flowKey
adapterKind
ifindexKnown
ifindex
adapterHandle
```

平台 Adapter 或 platform attribution provider 负责产生这些事实。

## 9. 当前建议的架构切法

不要把 VPP 当作“外部高性能路由器”接到 Snort 后面。

如果探索 VPP，应该把它当成 dataplane runtime：

```text
Platform RX Adapter
  -> VPP ingress normalize node
  -> metadata sidecar / PacketFacts builder
  -> optional worker handoff by flow owner
  -> CT/session plugin
  -> Basic/Stateful policy plugins
  -> telemetry/log plugins
  -> platform egress adapter
```

其中：

- NFQUEUE Adapter 负责 packet id / verdict handle。
- TUN Adapter 负责 fd read/write。
- HEV Adapter 负责 socks/proxy egress。
- UID attribution 是 platform provider。
- CT/session ownership 是 core design，不由 Adapter 决定。

## 10. 建议 POC 顺序

### POC-A: NFQUEUE -> VPP -> ACCEPT/DROP

目标：验证 root mode 接入。

必须覆盖：

- NFQUEUE packet 进 VPP。
- `packet_id` 生命周期正确。
- allow 发送 `NF_ACCEPT`。
- drop 发送 `NF_DROP`。
- hook / UID / ifindex / mark 等 metadata 至少能进入 sidecar。
- idle CPU 不应 100%。

### POC-B: external tun-fd -> VPP -> write back

目标：验证 VPN fd 接入。

必须覆盖：

- 外部 fd 传入 native/VPP。
- fd readiness 唤醒 VPP input。
- 读 L3 IP packet。
- IPv4/IPv6 进入统一 graph。
- output 写回同一 tun fd。
- idle CPU 不应 100%。

### POC-C: VPP + HEV egress

目标：验证 HEV 不拥有主 `tun-fd` 时，是否仍能作为 egress/proxy engine。

可选实现：

- HEV packet I/O callback；
- VPP <-> HEV socketpair；
- internal shim fd；
- POC 阶段接受额外 copy。

必须验证：

- outbound allow packet 进入 HEV。
- HEV response 回到 VPP path。
- response 最终写回 Android tun fd。
- upstream socket 被 VPN owner protect，避免回环。

### POC-D: worker ownership skeleton

目标：验证跨入口统一 worker ownership。

必须覆盖：

- NFQUEUE/TUN packet 都能按同一 flow hash 选 owner worker。
- handoff 发生在 CT/session 前。
- CT/session pointer 不跨 worker 误用。
- per-worker counters 与 global metrics 能正确聚合。

## 11. 风险清单

- Android 上 VPP 编译和运行成本未知，需要实测。
- iOS/macOS 只属于未来可能性，不应基于当前结论承诺。
- DPDK/polling 模式不适合 mobile idle。
- 当前 `stellar_netfilter_queue_deprecated` 不能原样复用。
- VPP local session manager 的 per-worker model 与 Snort CT A++ 全局 correctness 目标有冲突。
- UID attribution 不是跨平台统一能力。
- HEV 直接占有主 `tun-fd` 会绕开 Snort/VPP packet path。
- VPP graph 化后，控制面热更新、snapshot epoch、policy stage order 都需要重新设计映射。

## 12. 当前判断

VPP core datapath 方向值得继续探索，因为它可能把项目从 Android-only root daemon 扩展为 portable packet engine：

```text
same VPP/Snort core
different platform RX/TX adapters
different platform UID attribution providers
```

但它现在仍是探索线。主线仍应保持当前 Snort 语义和 Android 交付路径，直到 NFQUEUE、external tun-fd、HEV egress、idle CPU、worker ownership 这些 POC 都跑通。
