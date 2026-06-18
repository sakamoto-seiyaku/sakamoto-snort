## Why

当前 IPRULES 规则引擎仍是 IPv4-only（IPv6 仅做基础解析且不进入 IPRULES fast path），但权威契约与纲领已经明确 IPRULES 必须升级为 IPv4/IPv6 同级模型（`family` 必填、mk2 `matchKey`、`l4Status`、conntrack `byFamily`）。在临近出版/发版窗口，如果不尽快把 IPv6 按“同级能力”落地，系统会被迫把 IPv6 做成 IPv4 主模型上的特例，导致控制面/观测/测试口径二次返工。

本 change 的目标是：把双栈纲领落实到 daemon 的 datapath/engine/conntrack 与测试体系上，形成可发布、可回归的 IPv6 IPRULES 能力闭环。

## What Changes

- IPRULES 规则模型与控制面落地双栈：实现 `family=ipv4|ipv6` 必填、IPv6 CIDR（`/0..128`）、`proto=other` 语义与 mk2 `matchKey` 计算；`IPRULES.PREFLIGHT` 输出 `byFamily` 并据此做复杂度/上限控制。
- datapath IPv6 进入 IPRULES：IPv6 包不再绕过 IPRULES；新增 IPv6 extension header walker（预算：最多 8 个 ext headers / 256 bytes），并产出稳定的 `l4Status`（`known-l4|other-terminal|fragment|invalid-or-unavailable-l4`）。
- 修正 listener 的“malformed L4 直接 DROP”策略：对 TCP/UDP 头过短、TCP doff 异常、IPv6 header chain 不可达/预算耗尽等，listener 不再 `NF_DROP`；而是 fail-open 继续进入策略链路，并以 `l4Status` + ports=0 + `ct=invalid`（按决策口径）参与判决/观测。
- pktstream 事件补齐 `l4Status`：对每条 `type="pkt"` 事件 always-present 输出 `l4Status`；当 `l4Status!=known-l4` 时强制 `srcPort/dstPort=0`（端口不可用）。
- conntrack 升级为双栈：新增 IPv6 conntrack，内部按 family 分表（IPv4/IPv6 两表，共享全局 maxEntries），并将热路径 gating 从 `uid` 扩展为 `uid+family`；对外 metrics 按既有契约输出 `byFamily.ipv4/ipv6`。
- 持久化：IPRULES 落盘格式升级为 v4（显式包含 `family`）；restore 不兼容旧 v1/v2/v3（视为 restore failure，daemon 仍启动并发布空规则集，记录日志）。
- 测试体系必须同步更新（本 change 的硬验收项）：
  - Host unit tests：vNext IPRULES surface（`family`/mk2/IPv6 CIDR）、IPv6 walker 的 KTV（Known Test Vectors）、pktstream `l4Status` 输出、conntrack IPv6/byFamily、`uid+family` gating。
  - Device smoke/matrix：更新 IP device module（Tier-1 netns/veth）为双栈环境，并扩展 smoke/matrix 覆盖 IPv6 的规则命中与 `l4Status` 行为。

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `app-ip-l3l4-rules`: IPRULES 从 IPv4-only 升级为 IPv4/IPv6 同级规则模型（新增 `family`、IPv6 CIDR、`proto=other`、`l4Status`/端口不可用口径、fragment/invalid 语义）。
- `l4-conntrack-core`: conntrack 从 IPv4-only 扩展到双栈（引入 `uid+family` 语义、IPv6 fragments/不可获得 L4 的 invalid 口径、并发/容量/观测维度按双栈约束收口）。

## Impact

- Affected code（实现阶段）：`PacketListener`（IPv6 walker + l4Status + fail-open）、`PacketManager`（IPv6 进入 IPRULES fast path + `uid+family` gating）、`IpRulesEngine`（family/CIDRv6/mk2/save v4）、`Conntrack`（IPv6 + byFamily）、vNext control 与 stream JSON（新增 `l4Status` 字段输出）。
- Affected tests：`tests/host/*`（新增/更新 unit tests 与 KTV），`tests/device/ip/*`（smoke/matrix/perf 口径更新），DX smoke datapath gate 随 IP 模组更新获益。
