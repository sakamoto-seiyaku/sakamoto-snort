# L4 Conntrack：工作决策与原则

更新时间：2026-09-11

状态：当前决策；按 ADR-0006/0007/0008 与 per-worker single-owner 主线刷新。

本文替换原先关于 C++ daemon、全局 A++ authoritative CT table、shared-flow-pool、
QSBR 和跨线程共享 entry 的实施前提。那些方案不再是 Product baseline，也不能作为新 C
实现的源代码参考。历史讨论由版本历史保留，不在当前决策中维持第二套实现要求。

权威关系：

- [VPP-native packet I/O](../adr/0006-vpp-native-packet-io-adapters.md)
- [owner-local VPN Flow Stack](../adr/0007-owner-local-lwip-direct-egress.md)
- [移除旧 C++ 主线](../adr/0008-remove-snort-cpp-mainline.md)
- [Per-worker Flow Ownership](PER_WORKER_FLOW_OWNERSHIP.md)
- [stage-owned DROP / PASS_NEXT](../adr/0001-policy-bundle-staged-enforcement.md)
- [当前实施规格](../testing/2026-09-09_IMPLEMENTATION_SPEC.md)

## 1. 目标与协议范围

FlowRuntime 为 Android/Linux 本地端点提供共享的 flow identity、ORIG/REPLY、协议状态、
计数和结束生命周期；不是通用网关 session manager，也不是内核 conntrack 的包装器。

首轮 tracked identity 只有：

- 完整 IPv4/IPv6 TCP、UDP 的 `L4_PORTS`；
- 支持的 IPv4/IPv6 ICMP Echo request/reply 的 `ICMP_QUERY`。

其余合法流量可以有 `L3` ExecutionOwner，但不制造合成 FlowEntry、other tracker 或
CtFacts。ICMP error、embedded tuple 与 RELATED 不属于首轮 tracker。不得因 Root Echo
可放行而宣称 VPN 已有 ICMP transport。

分片先经过独立的 Product 重组，再进入共享 flow 路径。重组不属于协议 tracker；
不可把尚无可靠 L4 identity 的 fragment 硬塞入 TCP/UDP/ICMP 状态机，也不因重组资源不足
伪造 `ct.state=invalid`。

## 2. 一次身份分配、一个 owner

Product parser 产生 PacketFacts；唯一 OwnerAssignment 产生 typed canonical key、
canonical hash、source-is-A 和 ExecutionOwner。FlowRuntime 直接消费这些值：

- 不重新 canonicalize、重新 hash 或另选 owner；
- 当前 VPP worker 只访问自己的 table/pool，不用 packet 中的 owner 值远程取表；
- NFQUEUE queue-balance 只决定 Initial Execution Placement，不决定 FlowOwner；
- 候选命中须比较完整 typed identity；hash 相同不代表 flow 相同；
- key 不含 UID、ifindex、network context、Device Packet Direction 或 VPN provenance。

Endpoint A/B 是稳定的无方向索引投影，不是客户端/服务端，也不是 ORIG/REPLY。
第一个通过前序 Gate/L4 并创建 entry 的包定义 ORIG；反向先到或 midstream 也不另猜角色。
相同 endpoint 的退化投影保持 ORIG。Device Packet Direction 与 flow direction 独立。

## 3. 统一 FlowRuntime Interface

每个 owner 一套 FlowRuntime，内部只有一个 typed table 和一个总容量 pool。TCP、UDP、
ICMP_QUERY 共用容量，不预切协议配额，不建立三张平行 authoritative table。

table、bucket、slot、free-list 由 Module 隐藏。调用方跨越同一个 observe/decision seam；
诊断只能在 owner 上或控制面 worker barrier 下取得只读快照。借用 entry 不跨异步调用、
flush 或 generation。创建/销毁在停机或已 drain 的生命周期边界执行，报文路径不分配 heap。

entry 只承载需要的 key/hash、首包归属、方向、归属事实、计数、policy identity 与协议
tagged union。协议 tag 来自 typed key。UUID、格式化地址、NAT/translated tuple、zone、
OVS 管理对象、巨大 debug blob 不进热 entry。将来确有 consumer 时仍通过同一 FlowEntry
seam 组织 attachments，不为潜在扩展预建通用管理框架。

当前 S221 的 union 只是明确的承载位置，不代表 TCP/UDP/ICMP tracker 已实现。
S223、S222、S224 分别增加对应协议语义；不会以 `created=true` 冒充 `ct.state=new`。

## 4. 执行顺序与 policy cache

前序 Gate、L4 stateless stage 先执行。已有 DROP 时不查表、不建流、不更新已有 flow。
PASS_NEXT 才进入适用的 FlowRuntime/协议事实获取，之后的 stateful、DPI 等 stage 仍各自
决定 DROP 或 PASS_NEXT。Basic allow 不是跳过所有后续策略的 FinalAllow。

CT 状态更新与最终 Policy Verdict 分开：后续 stage 丢弃当前包，不回滚已经产生的协议
观察，也不将 FlowEntry 变成“最终获准连接账本”。Transport Outcome 同样独立。

一个报文持有同一份不可变 policy snapshot。Policy publication 不跨 worker 修改 entry；
下一个 owner-local observe 发现 identity 改变时，仅失效旧 policy decision，不清除 flow
identity、协议状态或计数。已经取得旧 snapshot 的包可以完成；其结果不能污染下一包的新
identity。跨 Adapter generation 的包不能更新新 runtime。

未来 decision cache 只能省去重复 matcher scan，不能控制 fact acquisition 或改变 stage
顺序。涉及 CtFacts/DpiFacts 的 cache 必须包含实际取得的相关 facts 与 snapshot identity，
并在命中时保留正常 attribution/counter 行为。旧 C++ TLS L1/L2 的具体容器、枚举和旁路
布局不是当前实现要求。

高级消费者的能力汇总由对应实施任务接入：用一次 subject/app capability 查询供 CT、
DPI 与 flow observation 复用；不用单条规则的 cheap predicate 决定同一 flow 的某个包
是否更新状态。启用 CT 不等于开启全部 telemetry/attachments。S221 不声称这一 gating
或 ct rule predicate 已经交付。

## 5. 容量与资源不足

容量是启动时的独立配置，先预分配，再接纳报文；运行中不扩容、不迁移、不 spill，
不 eviction 活跃 entry。正常 hit 与创建不做全表扫描；free-slot 管理有固定内存边界。
记录总量及 per-protocol create/hit/capacity-miss、active 与 high-watermark。

普通新流容量不足：

- 保留已执行的 Gate/L4 结果和全部原始 packet/Adapter obligation；
- 没有已有 DROP 时绕过缺失 entry 所依赖的后续处理，不伪造 FlowEntry 或 CtFacts；
- Root 回原 lane 执行 NF_ACCEPT；不是 Policy ALLOW，也不是 `DROP_FLOW_CAPACITY`；
- VPN 仍走其正常 transport/恢复职责，不将容量不足伪装成 Policy DROP；
- 已有 flow 继续 hit/update，其他 owner 的剩余空间不能被借用。

协议不合法、错误 owner、stale generation 和真实基础设施故障不是普通容量 miss；
不得借 processing bypass 掩盖它们。

旧实现的 64 项只是一项历史事实，不是正式默认容量。S221 接口显式接受容量；
当前 composition 的 1024/worker 是可由 VPP startup 配置替换的开发设置，不是发行默认。
正式容量需结合完整 entry、index、tracker、timer、attachments 的内存及目标端点实测选定；
不以百万级网关规模作为手机设计前提。

## 6. OVS 语义基线与许可

后续 tracker 共用 OVS userspace `v3.1.0` 的完整 commit：

`3c2bea086ef8912d57331173af266f21d36740a0`

[固定来源、源文件 SHA-256、许可与逐项映射](../reference/OVS_CONNTRACK_BASELINE.md)
记录了可复验的 baseline。它是协议语义证据，不授权导入 OVS 的并发表、锁、cleaner、
NAT/zone/helper 管理面，也不授权使用已移除 C++ 主线或直接导入 POC 源码。

实现目标是 VPP-native C。Tracker 只接受已解析的 PacketFacts、已有协议状态和 flow
direction，返回 CtFacts、timeout class 与必要的 close/reuse 意图；不自己解析 VPP
buffer、不访问 table/socket/clock，不拥有独立 expiry scheduler。

- UDP 保留 first、same-side multiple、bidirectional 语义。
- TCP 保留 pinned loose 路径需要的双方 peer、序列/window、flags、wscale 与状态迁移，
  不退化成只看 SYN 的 handshake 枚举，也不擅自增加 strict-only 模式。
- ICMP Echo 保留 query/reply 级别语义；identifier 在 key 中，sequence 不在。
- `UNKNOWN/NEW/ESTABLISHED/INVALID` 与 flow direction 是事实，不直接等于终结动作；
  对外规则形式仍服从当前控制面规格，不沿用旧 IPRULES 命令。

TCP 源文件带 BSD two-clause 条款与对应作者归属；其余已核查 conntrack 文件主要为
Apache-2.0。后续如发生源代码适配，须保留相应完整 notice/conditions/disclaimer，不能
把 TCP 文件一概标为 Apache-only。此处只固定来源，不移植状态机。

## 7. Timeout 与结束生命周期

采用同一 OVS pin 的默认 timeout policy 表，单位秒；不凭经验新造一组时长：

| 内部 class | 默认秒数 |
| --- | ---: |
| TCP_FIRST_PACKET / TCP_OPENING | 30 / 30 |
| TCP_ESTABLISHED | 86400 |
| TCP_CLOSING / TCP_FIN_WAIT / TCP_CLOSED | 900 / 45 / 30 |
| OTHER_FIRST / OTHER_MULTIPLE / OTHER_BIDIR（UDP） | 60 / 60 / 30 |
| ICMP_FIRST / ICMP_REPLY | 60 / 30 |

特别注意：内部 OTHER_MULTIPLE 对应 policy UDP_SINGLE，OTHER_BIDIR 对应 UDP_MULTIPLE。
TCP CLOSING、FIN_WAIT 的 policy 名称也不能按同名字面配对。是否刷新与协议路径有关；
不能把所有被接受的 TCP 包一概视为刷新。

Expiry 由 owner-local 统一调度负责，不是共享后台 cleaner、QSBR grace period 或每协议
一套 timer。Min-heap 是候选结构，不是必须照搬外部参考的既定实现；具体选择在 S225
结合实际容量、更新频率和真机预算确定。报文路径不承担无界 sweep 或等待其他线程。

结束顺序保持：从 table/timer 解除可见性，交付 FlowEndSignal 给本 owner 的共享 consumers，
最后在其 buffer/free 生命周期完成时回收 slot。未完成的 FlowEnd obligation 仍占容量。
不新增跨 owner 的引用计数/回收广播或另一套通用 token manager。

真实 allocation/infrastructure fault 不能按普通 full pool 处理；由 Product supervisor
先恢复连接可用性，再做有界重启。Stop/profile/generation 切换沿用 quiesce、drain、
close 的既有 Adapter 生命周期，旧报文、borrowed pointer、timer/callback 不进入新 generation。

S221 仅有 FREE/LINKED 与 stop 清空，不实施自动 expiry、正常 FlowEnd 或 timer。
有限流量与 stop 清理的证据不能被升级成 idle-expiry、长时间 soak 或发行容量结论。

## 8. 验收与边界

每个实现切片使用其实际 source 构建的 Product artifact，在 Linux NFQUEUE 与 Pixel Root
检验适用的协议/owner/原 lane 路径。报告 source/dirty diff、VPP/native/APK、helper、
node/thread、终结/释放与 stop residue；辅助 host vectors 不冒充真实端点证据。

S221 的共同存储要求包括完整 typed key、双向复用、受控 hash 碰撞、共享小容量、
已有 flow hit、新流 processing bypass、policy identity 与清理。完整 64-bit hash
碰撞向量和真实端点自然 bucket 碰撞是不同证据，报告必须分别说明。

后续协议、expiry、FlowEnd、stateful rules、VPN transport 与联合发布验收仍按 Plane
对应任务推进。本文件不建立独立的开放任务状态表，也不将当前内部能力宣传为已开放的
完整 stateful firewall 或 VPN forwarding readiness。
