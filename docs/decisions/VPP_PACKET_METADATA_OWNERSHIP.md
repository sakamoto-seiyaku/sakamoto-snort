# VPP packet metadata ownership

状态：accepted working decision，2026-09-04；首片事实、VPN 返回事实与 Linux 网络分类按 2026-09-05 KISS 共识更新。

## Scope

本决策适用于当前 Android 与 Linux 本地端点产品。Sakamoto 使用 VPP 作为共享 packet runtime，
但不是当前运营商路由器或多接口网关产品。`/home/js/backup/backup/Git/vpp` 的深改 VPP fork
处理高吞吐路由器流量，其扩大 `opaque2`、新增 `opaque3` 和 packet exdata 的做法只提供
metadata ownership 与 parse-once 的设计证据，不构成当前内存布局或容量基线。

未来路由器形态需要独立的部署范围、buffer-pool 内存、cache footprint、接口拓扑与吞吐证据；
当前实现不为它预留每包字段，也不把假想部署维度加入 Canonical Owner Key 或 Canonical Flow Key。

## Semantic ownership

每个 live packet 的 metadata 分为以下语义，不能用一个 untyped hints bag 混装：

- `PacketFacts`：共享 VPP parser 从完整 L3 packet 一次解析得到的事实；
- `Platform Packet Facts`：Adapter 从平台事件归一化的 UID evidence、Linux ifindex、
  NetworkContextId、Device Packet Direction 与 VPN Packet Provenance；
- `OwnerAssignment`：Canonical Owner Key、ExecutionOwner、generation 与 bounded handoff state；完整
  TCP/UDP 使用 `L4_PORTS`、受支持 ICMP Echo 使用 `ICMP_QUERY`，其 ExecutionOwner 同时提供
  FlowOwner/session identity；Echo sequence 不进入 identity，assignment 不代表已创建 ICMP FlowEntry；
- `AdapterObligation`：返回 Origin Adapter Lane 的 opaque completion obligation。

NFQUEUE queue、lane、fd、packet ID 和 queue generation 留在 Adapter completion ownership 中。
它们不进入 PacketFacts、policy matcher、Canonical Owner Key、Canonical Flow Key 或 Owner Selector。Runtime Profile
不是 packet direction；VPN provenance 不是 flow direction；Linux ifindex 与 VPP `sw_if_index`
不是同一标识。

所有可缺失的 Platform Packet Facts 都携带显式 availability。零是合法 UID、ifindex 或 context
数值时不能同时代表 unknown。VPN v1 的 Linux ifindex 明确为 unknown；Root/Linux NFQUEUE 的
Linux ifindex 只来自 `LOCAL_IN` 的 `NFQA_IFINDEX_INDEV` 或 `LOCAL_OUT` 的
`NFQA_IFINDEX_OUTDEV`，attribute 缺失时保持 unknown。

## Linux network context — 2026-09-05 KISS rule

Linux NetworkContextId 使用四个有界类别：有线网络（Wired）、Wi-Fi、移动网络（Mobile）和
VPN。类别来自平台可可靠确认的接入或 VPN 事实；unknown 表示事实不可用，不是第五个可配置
类别，也不以“有线”或“其他”兜底。具体接口匹配与网络类别保持分离。

每个 NFQUEUE packet 按其实际接口归类：`LOCAL_IN` 使用 `NFQA_IFINDEX_INDEV`，
`LOCAL_OUT` 使用 `NFQA_IFINDEX_OUTDEV`，再投影已有平台事件快照。多网络并存时分别使用
各接口的可靠分类，不拿当前默认网络覆盖所有包。接口事实或可靠分类缺失时保持 unknown；
虚拟接口本身不证明 VPN，不能将所有 TUN/TAP、bridge、veth 等接口直接归为 VPN。

unknown 沿用现有规则：依赖 NetworkContextId 的 Gate/L4 条件 no-match，其他可求值策略继续，
没有 stage DROP 时按正常默认放行。平台事件采集与归一化在 packet path 外完成，worker 读取
稳定快照，不逐包 RPC、等待分类或重新做平台探测；ifindex/context 不进入 canonical key。
共享 UI 按平台类别呈现，Apply 仍编译为有界 bit mask；本决策不冻结数值 ID 或新增 UI 工作。

SAKAMOTO-235 定义对应 Linux 真机验收。分类选择已收口；具体事件来源可复用可用的平台网络
管理信息，但不因本决策强制依赖 NetworkManager，也不新增通用 metadata service。

## Physical ownership

当前 pinned upstream VPP 的 `opaque` 与 `opaque2` 是按 subgraph 复用的有限 inline 空间，不是
跨任意 VPP node 永久有效的产品 property bag。产品 overlay 必须满足以下约束：

- 只在已审计的 graph 区间声明所有权，并以明确 accessor 和 compile-time size/offset guard 访问；
- 普通 graph 可在没有冲突消费者的区间内保存 compact PacketLease/PacketFacts 与 Platform Packet
  Facts；handoff 只移动 buffer index 和这些 inline facts；
- 进入产品重组区间时，`opaque2` 保存 bounded fragment envelope，原片各自的 obligation
  与 Platform Packet Facts 随 buffer 保留；不进入 upstream IP reassembly union 的生命周期。
  重组成功后恢复 offset-zero 首片事实及已保存的 OwnerAssignment，再进入最终
  ExecutionOwner、Network Gate、L4 policy 与可选 FlowEntry；
- 任何 node 若使用同一区域的其它 VPP overlay，必须在 wiring review 中被禁止或建立显式
  save/restore transition；静态结构体相等不证明跨 subgraph lifetime 安全；
- 当前不扩展 `vlib_buffer_t`，不新增 `opaque3`，不使用 packet exdata、每包 heap allocation或
  通用 side table。若固定 inline envelope 无法容纳必要的当前事实，应先去除重复状态并重新审视
  stage transition；不能用未来路由器需求为当前常驻成本辩护。

## Reassembled platform facts — 2026-09-05 KISS rule

重组后的 Platform Packet Facts 以 **fragment offset=0 首片**为准，不是最先到达片。
保存并恢复该片的 UID、Linux ifindex、NetworkContextId、Device Packet Direction、VPN Packet
Provenance 及对应 availability；首片缺失的字段保持 unknown，不从其他片拼补，不做投票、
最后到达覆盖、snapshot 合并或通用 metadata 冲突仲裁。乱序到达不改变这个基准。

该规则不覆盖 AdapterObligation：若 NFQUEUE 入口实际收到独立排队的分片，每片的
queue/generation/packet ID 都须独立保留并按适用终态分别结清，不能用首片身份代替其他片。
已有重组合法性检查与 Adapter generation 约束保持有效；其他片的缺失值或 snapshot revision
变化本身不通过整块 metadata 比较被误报为 malformed。没有 offset=0 首片不能产生成功重组结果。

2026-09-11 用户决定：产品使用独立的有界重组流程，替换 upstream full-reassembly 业务路径。
同一 datagram 先汇合到重组 worker；offset=0 首片通过现有唯一 owner assignment 确定并
保存流所属 worker，重组后沿用该结果交接，不重新计算归属。投递、失败收尾以及每片完成
和释放接入现有 NFQ/TUN 机制。此决定取代此前仅继承首片基准、不替换重组器的约束。
首片事实规则保持不变，不引入通用 metadata 合并模块。

默认每重组 worker 64 contexts、每 datagram 32 originals，两项都是启动配置默认值，
可调大或调小，不是编译期或隐藏上限。启动校验并按配置预分配，重启生效；运行中不自动
扩容，启动分配失败明确报错，不静默降容。重复片、重叠片、超时及普通 IPv6 扩展头处理
保持本轮已确认的设计语义，禁止以全重叠一律拒绝或只识别紧邻 IPv6 基础头的 Fragment
Header 缩减支持。接 L3 双栈，不加入 L2、隧道内层重组或出站重分片，观测复用现有机制。
纯资源不足按 processing fail-open 契约处理；成功、超时、拒绝、资源不足均须逐 original
恰好结清一次，既有策略 DROP 不得改为放行。

当前实现将 datagram 临时描述符保存在重组 worker 的预分配表中。detach 后只在当前同步
调用内借用描述符，把 originals 转为 buffer-index 链或完成消息后才能再次修改表；表指针
不跨 node/worker 传递。原片始终只有一个 buffer 引用，不借助 upstream consume pin。
正常 packet overlay 仍为 56 bytes：L3 header span 使用 16 bits，family 与 L3 validity 共用
一个 byte，容纳 IPv6 扩展头而不扩大 `vlib_buffer_t`。具体复验证据见
[独立重组实现记录](../testing/2026-09-11_S229_INDEPENDENT_REASSEMBLY.md)。

SAKAMOTO-219 的双栈真机矩阵核对首片晚到、首片 known/其他片 unknown、首片 unknown/其他片
known、其他片取值不同及 snapshot revision 变化，输出始终按首片恢复且缺失不拼补。真实 NFQ
原片不可达时明确使用真机 graph injection，不把注入的 UID/network facts 当作平台采集证明。
具体真机反例若要求改变该规则，先作最小修正审视，不提前扩展设计。

## VPN return facts — 2026-09-05 KISS rule

按 ADR-0007，copy 后两体系独立管理存储。已有 transport session 只携带必要的可靠应用身份与
known/unknown 状态，网络信息复用已有 underlay 绑定/epoch；不持有原输入 buffer、metadata
或 VPP FlowEntry 指针，不新增身份映射/订阅/广播/同步管理体系。缺失保持 unknown，不把
Direct socket 的 Sakamoto UID 误作原应用，也不拿当前全局网络覆盖旧 flow 的实际绑定。

返回时将少量平台事实按值填入新 VPP buffer，明确 `FLOW_STACK_RETURN` 与 `INPUT`；共享图为
新包生成 PacketFacts 并执行策略，不继承输入包的解析结果或 verdict。回调与清理复用现有
owner/generation；详细内存约定及实验边界见 ADR-0007 与 SAKAMOTO-237、245–247。

## Reference-fork boundary

参考 fork 把完整 `flow_dissector_result` 放入扩大的 `opaque2`，把 NFQUEUE completion identity、
原始 VPP `sw_if_index`、session 与 fragment 状态放入 `opaque3`。其中值得保留的是一次解析复用、
Adapter completion 与 policy facts 分离、以及 graph-stage metadata ownership；不继承的是扩大的
每包常驻布局、动态 exdata、把合成 VPP interface identity 当作 Linux ifindex，或其 tuple 中的
numeric domain。

## Acceptance boundary

Host tests验证结构、packing、known/unknown projection 和 node transition；它们不能替代产品
artifact 的真实流量证明。每个实现任务必须在其适用平台完成新的真机测试：Linux NFQUEUE
路径使用真实 Linux endpoint，Android Root/VPN 路径使用 Pixel，并记录 artifact、node、thread、
lane、metadata transition、completion obligation 和最终 residue。旧 POC、旧 APK 与旧 Host
fixture 只能作为辅助证据。
