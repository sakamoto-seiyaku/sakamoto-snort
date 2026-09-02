# Shared VPP Dataplane 恢复范围：KISS 与最佳实践研究

日期：2026-08-26  
状态：Wayfinder 决策输入；不是 ADR、规格或实现计划。

## 结论摘要

若目标是先恢复被 ADR-0008 清空后的产品级数据面基线，最小闭环应是：

```text
Root/NFQUEUE Adapter ─┐
                     ├─> 同一个 VPP-native C graph
VPN/TUN Adapter ─────┘     parse -> canonical owner -> Gate -> stateless L4
                                                    -> bounded FlowEntry
                     └─> 各自的 origin completion / VPN Flow Stack boundary
```

这个闭环恢复双 Profile 的共同 packet verdict 能力，但不把 full Conntrack、协议识别、
复杂 telemetry 或性能优化混进第一轮。S72--S81 足以支持 Root live-buffer ownership seam，
不足以证明 Gate/L4 产品切片、VPN parity、分片重组或任何 production capacity 常量。

## 证据边界

权威顺序采用仓库 active decisions，再用官方 VPP 文档/源码验证实现形状，最后用 POC
限定已证明范围：

- [ADR-0001](../adr/0001-policy-bundle-staged-enforcement.md)、
  [ADR-0003](../adr/0003-vpp-owned-packet-parsing.md)、
  [ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、
  [ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、
  [ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)；
- [Per-worker Flow Ownership](../decisions/PER_WORKER_FLOW_OWNERSHIP.md)；
- [S72--S81 ownership closure audit](../../experiments/vpp-nfq-poc/SAKAMOTO-81_HANDOFF.md)；
- FD.io/VPP 官方文档与 `FDio/vpp` 上游源码。

本报告不把历史 C++ PASS、archive-only 能力或 throwaway POC 当作 current-head 产品证明。

## 建议列为必须恢复

### 1. 一个产品级 VPP-native C build target

- 在 pinned VPP source overlay 中建立正式 `add_vpp_plugin()` target；只使用 C。
- KISS 默认是一枚 product plugin，内部按 Adapter、parse/steering、policy、flow、completion
  分 source/header；只有真实依赖隔离需求出现时才拆多个 `.so`。
- 一个版本化 `.api` 提供粗粒度 stage/apply/status/reset；不公开逐包 API。
- startup 使用 plugin allowlist；产品插件默认关闭，配置完成后才启用，不在 init 时提前创建
  worker queue、pool 或 process。
- 只有测得的热点 node 放入 `MULTIARCH_SOURCES`。

官方依据：VPP 插件模板把 source、multiarch node、`.api` 和 API test 统一放在
[`add_vpp_plugin()`](https://docs.fd.io/vpp/24.06/developer/plugindoc/add_plugin.html)；
startup 支持先禁用全部插件再逐项启用
([configuration reference](https://docs.fd.io/vpp/25.06/configuration/reference.html#the-plugins-section))。

### 2. Root/VPN 共用一个 graph，不建平行数据面

- Root 只替换入口/完成端：NFQUEUE lane 收包，origin lane 做唯一 verdict。
- VPN 只替换入口/完成端：TUN lane 收包/写回；允许包进入 ADR-0007 的 VPN Flow Stack
  Packet Boundary，回包带不可变 provenance 重新进入同一 graph。
- 两个 Profile 共用 parser、Canonical Flow Key、Worker Layout、Owner Guard、Gate、L4、
  FlowEntry、policy revision 和 reason vocabulary。
- VPN Userspace Flow Stack 的 PCB/socket/pbuf 实现属于 VPN Transport 域；Shared Dataplane
  这里只恢复清晰、bounded、exactly-once 的 packet boundary。

VPP 的 feature arc 是有序、可独立启停的 graph node 集；次序由依赖拓扑排序，适合表达共享
阶段而不是复制两条 pipeline
([Feature Arcs](https://docs.fd.io/vpp/24.06/developer/corearchitecture/featurearcs.html))。

### 3. VPP 拥有解析、live buffer 和 PacketFacts

- Adapter 将完整 L3 packet 直接 materialize 到 VPP-owned storage；正常路径不做
  Adapter-to-VPP full-packet copy。
- graph 内统一做一次 defensive IPv4/IPv6 + extension/L4 parsing；先校验 packet/chain/header
  长度，再构造 immutable PacketFacts。
- 不能假设 packet 从 `data[0]` 开始；必须从 `vlib_buffer_get_current()` 读取，并明确支持或
  拒绝 buffer chain envelope。
- normal parser、policy、flow 和 observation node 只读 packet bytes；只有明确命名的
  reassembly/synthesis node 有 mutation 权限。
- Adapter identity、generation、origin lane、completion obligation 使用固定 inline metadata；
  必须对 VPP opaque union 做 size/lifetime audit，不能假设跨任意 subgraph 都不会被覆盖。

官方依据：VPP 明确要求使用 `vlib_buffer_get_current()`，并说明 `opaque/opaque2` 是带
subgraph lifetime 约束的共享 metadata 区
([Buffer Metadata](https://docs.fd.io/vpp/25.02/developer/corearchitecture/buffer_metadata.html))。

### 4. canonical owner、handoff 与 origin completion

- runtime 启动前固定 Worker Layout；完整、direction-independent IPv4/IPv6 五元组包含
  IP protocol，UID/queue/Profile 不参与 owner key。
- primary distribution 直接到最终 owner；owner-local 原地继续。
- Owner Guard 在任何 worker-private mutation 前运行：只允许一次 corrective handoff；
  第二次 mismatch runtime-drop。拥塞不能改投别的 owner。
- Root：FlowOwner 只产生 terminal intent；原 NFQUEUE lane 用原 generation + packet ID
  做唯一物理 verdict，再走 native buffer return。
- VPN：FlowOwner 与 TUN completion owner/Flow Stack outcome 分离；provenance 防回流环。
- handoff 只移动 buffer index + bounded metadata，不复制 payload，不建第二份 Lease table。

VLIB 官方提供 per-worker frame queue 和 `vlib_buffer_enqueue_to_thread()`；queue 有界且会拥塞，
官方明确建议只有确认需要时才创建
([VLIB worker handoff](https://docs.fd.io/vpp/22.02/developer/corearchitecture/vlib.html#handing-off-buffers-between-threads))。

### 5. 最小 Network Gate + 双栈 stateless L4

这是恢复历史 L4 product capability 的最小 verdict slice：

- 一次 complete Linux UID SubjectView lookup；unknown UID 行为显式定义。
- 独立 Network Gate table。
- IPv4/IPv6 stateless L4 classifier：direction、network context、optional ifindex、protocol、
  CIDR、exact/wildcard/range ports。
- precedence 固定为 `priority -> explicit order -> stable rule ID`；编译后使用 bounded
  mask/hash/range probes，不能用 pool traversal 偶然决定胜者。
- `DROP` 在 FlowEntry allocation 前结束；`PASS_NEXT` 才进入 FlowEntry。
- policy snapshot immutable，整包 stage/validate/commit/rollback；同一 revision 贯穿 Gate/L4。

这里应新写 C/VPP Module；旧 C++ classifier、旧 VPP ACL/session plugin 和 POC 都只能提供
语义/失败事实，不能成为源码或对象模型。

### 6. bounded、worker-owned 最小 FlowEntry

- 每个 canonical owner 持有自己的 FlowEntry pool；不建立共享 authoritative table。
- 第一轮只保存恢复闭环所需的 canonical identity、ORIG/REPLY、first/last seen、packet/byte、
  policy revision、必要 activity facts。
- pool capacity、timeout、GC budget、高水位、capacity miss 必须从第一天存在。
- Gate/L4 drop 不创建 FlowEntry；查询从 worker snapshot 聚合，不直接读 mutable entries。

上游 VPP 也用 per-thread pool、owner handoff 和显式容量/timeout 管理 reassembly/session state；
例如 [`ip4_full_reass.c`](https://github.com/FDio/vpp/blob/master/src/vnet/ip/reass/ip4_full_reass.c)。
这支持这种 ownership 形状，但不替 Sakamoto 证明具体容量。

### 7. 有界资源、teardown 和最小 observability

必须有界：VPP buffers、ingress/reserve/completion credits、frame queues、FlowEntry、fragment
state（若启用）、ActivityAccumulator、diagnostic records。

最小 counters/status：

- receive/admit/pass/drop，按低基数 reason 分组；
- parse/unsupported/malformed；
- primary/local/remote/corrective/second-mismatch/congestion；
- Gate/L4 hit、FlowEntry active/create/expire/capacity miss；
- completion `SUCCEEDED/FAILED_DEFINITE/OUTCOME_UNKNOWN`、duplicate/stale/no-retry；
- buffer/credit high-watermark、native return、outstanding debt/residue；
- generation、adapter readiness、quiescing/draining/stopped/fault。

停止顺序固定且幂等：quiesce ingress -> 保持 completion/transport channel 存活并 bounded drain
-> barrier/quiescence -> 结算或明确分类剩余 obligation -> 关闭 fd/queue/hook -> 清 worker state
-> release buffers/credits。进程死亡必须记录为 generation fault，再由新 generation 重建，不能
伪报 clean teardown。

VPP 原生提供 per-node/error/performance counters 和只读 stats segment
([Statistics](https://docs.fd.io/vpp/22.02.0/developer/corefeatures/stats.html))；
这些适合承载 runtime facts，但产品 Activity 投影仍由控制面负责。

## 建议延后

- **Full stateful Conntrack**：现行 per-worker 决策已经取代 shared-CT baseline；第一轮只需
  bounded FlowEntry。TCP state machine、NAT、ALG、system conntrack、stream reassembly 均延后。
- **Protocol Recognition / libprotoident**：保留 FlowEntry attachment seam，但 recognizer、
  recognition budget、protocol policy 属于恢复后的阶段。
- **复杂 telemetry**：先保 exact low-cardinality counters + bounded activity facts；流式 export、
  packet diagnostics、丰富 UI projection 后置。
- **capacity/performance tuning**：queue/worker/buffer/credit/shard 常量、SIMD、multiarch、
  conditional wake、4-queue 拓扑、power/thermal/soak 由后续产品 seam 上的测量决定。
- **chain-aware jumbo/GSO 普适支持**：先定义并验证 Android Root/VPN 产品 packet envelope；
  不能把 host 9000-byte 与 Android 2048-byte POC 混成一个已证明常量。
- **复杂 policy families**：Domain、decoded metadata、protocol policy 不阻塞 Gate/L4 恢复。

## 建议拒绝

- 恢复、翻译或兼容旧 Snort C++ daemon、Flow/Adapter class topology、host model/test facade。
- 直接导入 S72--S81、OI1--OI5 或其他 throwaway POC source。
- Root/VPN 两套 parser、policy、FlowEntry 或 verdict runtime。
- Rust/Java 逐包处理、live `vlib_buffer_t` ownership 或逐包 FFI/IPC。
- 全局共享 mutable Conntrack/FlowEntry + locks；owner mismatch 时 spill 到任意 worker。
- shared NFQUEUE TX/trylock、自动 Root/VPN fallback、第二数据面或 compatibility daemon。
- 无界 pool/vec/queue、per-packet heap object、同步逐包日志、热路径动态字符串。
- 用 `data[0]` 盲读 packet，或未经 lifetime audit 复用 opaque metadata。
- conditional/per-packet persistent wake 进入恢复基线；当前 P6d evidence 不支持。

## 需要 HITL 明确的两个边界

### A. 分片

ADR-0001 要求 fragment co-location -> bounded reassembly -> final-owner handoff；但 S41/S42
未取得可观察的真机多分片证据，明确禁止把其 throwaway implementation 提升为产品路径。

因此不能写成“已验证必须直接实现”。可选口径只有两种：

1. 分片能力仍属恢复范围，但作为独立 blocking closure：新写 C/VPP 模块并补 controlled
   fragment evidence 后，Gate/L4 闭环才算完成；或
2. 第一恢复里显式把 fragments 作为 predictable runtime-drop/unsupported，延后 reassembly，
   同时修改 ADR/产品能力声明，承认暂时不具备 fragment-safe port policy。

### B. NFQUEUE multi-message datagram

S74 证明的是“多个 NFQ message 在一个 netlink datagram 中可在 admission 前逐个 bounded
reject 并结算”，不是多个 independent no-copy obligations。KISS 初版可以保留 safe rejection；
若产品流量证明确实会命中，则需单独设计 VPP chain/multi-buffer admission，不能悄悄 full-copy。

## Claim limits

- S72--S81 可支持 Root 单 message 的 direct materialization、buffer-index handoff、origin-only
  verdict、exactly-once outcome partition、native return 和 clean/fault teardown 形状。
- Android S80 只覆盖 2048-byte buffer 中 164/192-byte ICMP netlink envelope，不支持普适 payload
  或 9000-byte Android claim。
- S72--S81 不证明 Gate/L4、VPN/TUN product parity、fragment reassembly、production capacity、
  release APK 或 downstream delivery。
- VPP 官方文档证明机制存在和推荐使用方式，不证明 Sakamoto 的 product semantics 或容量。
- 本报告给出 KISS 范围建议；最终 recover/defer/reject 由 Wayfinder 会话决定。
