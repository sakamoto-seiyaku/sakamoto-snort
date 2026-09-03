# VPP packet metadata ownership

状态：accepted working decision，2026-09-04。

## Scope

本决策适用于当前 Android 与 Linux 本地端点产品。Sakamoto 使用 VPP 作为共享 packet runtime，
但不是当前运营商路由器或多接口网关产品。`/home/js/backup/backup/Git/vpp` 的深改 VPP fork
处理高吞吐路由器流量，其扩大 `opaque2`、新增 `opaque3` 和 packet exdata 的做法只提供
metadata ownership 与 parse-once 的设计证据，不构成当前内存布局或容量基线。

未来路由器形态需要独立的部署范围、buffer-pool 内存、cache footprint、接口拓扑与吞吐证据；
当前实现不为它预留每包字段，也不把假想部署维度加入 Canonical Flow Key。

## Semantic ownership

每个 live packet 的 metadata 分为以下语义，不能用一个 untyped hints bag 混装：

- `PacketFacts`：共享 VPP parser 从完整 L3 packet 一次解析得到的事实；
- `Platform Packet Facts`：Adapter 从平台事件归一化的 UID evidence、Linux ifindex、
  NetworkContextId、Device Packet Direction 与 VPN Packet Provenance；
- `FlowAssignment`：Canonical FlowOwner、generation 与 bounded handoff state；
- `AdapterObligation`：返回 Origin Adapter Lane 的 opaque completion obligation。

NFQUEUE queue、lane、fd、packet ID 和 queue generation 留在 Adapter completion ownership 中。
它们不进入 PacketFacts、policy matcher、Canonical Flow Key 或 Owner Selector。Runtime Profile
不是 packet direction；VPN provenance 不是 flow direction；Linux ifindex 与 VPP `sw_if_index`
不是同一标识。

所有可缺失的 Platform Packet Facts 都携带显式 availability。零是合法 UID、ifindex 或 context
数值时不能同时代表 unknown。VPN v1 的 Linux ifindex 明确为 unknown；Root/Linux NFQUEUE 的
Linux ifindex 只来自 `LOCAL_IN` 的 `NFQA_IFINDEX_INDEV` 或 `LOCAL_OUT` 的
`NFQA_IFINDEX_OUTDEV`，attribute 缺失时保持 unknown。

## Physical ownership

当前 pinned upstream VPP 的 `opaque` 与 `opaque2` 是按 subgraph 复用的有限 inline 空间，不是
跨任意 VPP node 永久有效的产品 property bag。产品 overlay 必须满足以下约束：

- 只在已审计的 graph 区间声明所有权，并以明确 accessor 和 compile-time size/offset guard 访问；
- 普通 graph 可在没有冲突消费者的区间内保存 compact PacketLease/PacketFacts 与 Platform Packet
  Facts；handoff 只移动 buffer index 和这些 inline facts；
- 进入 full reassembly 时，VPP 拥有 `vnet_buffer_opaque_t` 的 IP reassembly union。仍需存活的
  Platform Packet Facts 必须先进入 bounded fragment envelope，重组完成后恢复，再进入最终
  Canonical FlowOwner、Network Gate、L4 policy 与 FlowEntry；
- 任何 node 若使用同一区域的其它 VPP overlay，必须在 wiring review 中被禁止或建立显式
  save/restore transition；静态结构体相等不证明跨 subgraph lifetime 安全；
- 当前不扩展 `vlib_buffer_t`，不新增 `opaque3`，不使用 packet exdata、每包 heap allocation或
  通用 side table。若固定 inline envelope 无法容纳必要的当前事实，应先去除重复状态并重新审视
  stage transition；不能用未来路由器需求为当前常驻成本辩护。

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
