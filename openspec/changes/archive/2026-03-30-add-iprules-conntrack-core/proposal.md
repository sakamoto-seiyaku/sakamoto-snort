# Change: Add userspace L4 conntrack core for IPRULES (stateful L4)

## Why
当前 `IPRULES v1` 仅支持基于单个数据包头部字段（L3/L4 header）的 stateless 匹配。对“专业意义上的 L4 防火墙语义”（`new/established/invalid`、orig/reply、TCP 基础状态机）来说，这还不够：
- 无法可靠表达 “只允许已建立连接的回包” 一类策略。
- 无法把 TCP/UDP/ICMP/other 的跨包状态纳入规则引擎，从而限制策略表达力与可解释性。

同时，当前 NFQUEUE worker 拓扑（`INPUT/OUTPUT` split）不能假设同一 flow 总被同一线程处理，因此 conntrack core 必须在多线程下 correctness 成立，且热路径开销要可控。

上位设计原则与边界收敛见：`docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`。

## What Changes
- 新增一个 **userspace conntrack core**（C++ 重实现，语义母本为 OVS userspace conntrack），支持协议范围：
  - `TCP / UDP / ICMP / other`
- conntrack core 为每个 IPv4 包计算最小必要的 conntrack 视角元数据（state + direction），并提供给 IPRULES 匹配引擎使用。
- 扩展 IPRULES 的 rule match 维度：允许规则声明最小 `ct` 条件（见本 change 的 spec delta），以实现 stateful L4 策略。
- conntrack correctness 不依赖 NFQUEUE 拓扑：无论 `split in/out queues` 还是 future `shared queue pool`，行为一致；差异仅体现在 contention/perf。

## Non-Goals (this change)
- 依赖系统 conntrack（内核 `NFQA_CT` / netlink 查询）作为 correctness 前提
- NAT / ALG / helper / expectation
- fragment reassembly
- IPv6 stateful conntrack（仅 IPv4 first）
- L7 / DPI / HTTP/HTTPS 语义识别

## Impact
- Affected OpenSpec specs:
  - `app-ip-l3l4-rules`（新增/修改 `ct` match 语义）
  - new: `l4-conntrack-core`（conntrack core 的最小契约）
- Affected code (non-exhaustive):
  - `src/PacketManager.*`（在 IPRULES evaluate 前获取 conntrack 视角）
  - `src/IpRulesEngine.*`（新增 `ct` 匹配维度与 preflight/accounting）
  - new module under `src/`（conntrack core + protocol trackers + sweep）
- Performance constraints:
  - 命中包的常态路径必须避免全局锁；允许 entry 级短临界区更新。
  - 当没有任何 active 规则使用 `ct` 维度时，系统 MUST 避免对每包执行 conntrack 更新（near-zero overhead）。
