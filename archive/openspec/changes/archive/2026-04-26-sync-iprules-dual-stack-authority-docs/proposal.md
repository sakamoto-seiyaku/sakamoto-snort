## Why

我们已经产出 IPRULES IPv4/IPv6 同级规则模型的纲领决策（`docs/decisions/IPRULES_DUAL_STACK_WORKING_DECISIONS.md`），但当前“权威契约文档”和 OpenSpec 主规格仍停留在 IPv4-only（例如 `matchKey=mk1`、无 `family`、无 `PREFLIGHT.byFamily`、pktstream 无 `l4Status`、conntrack metrics 无 `byFamily`）。如果继续让这些文件漂移，将在临近发布/出版前把 IPv6 逼成“IPv4 主模型上的特例”，并导致后续实现与测试口径二次返工。

本 change 的目标是：在动代码前，先把**权威文档/主规格**与纲领对齐，形成单一真相与可执行的任务清单，避免上下文压缩导致漏改或乱改。

## What Changes

- 同步权威契约文档：将 vNext IPRULES 契约从 IPv4-only 收口为 IPv4/IPv6 同级模型（`family` 必填、IPv6 CIDR、`proto=other`、`matchKey=mk2`、`PREFLIGHT.byFamily`）。
- 同步权威观测文档与 OpenSpec：vNext `STREAM.START(type=pkt)` 事件引入 `l4Status`（always-present）并固定枚举；端口不可用时 `srcPort/dstPort=0` 由 `l4Status` 解释。
- 同步 OpenSpec：`METRICS.GET(name=conntrack)` 增加 `byFamily.ipv4/ipv6` 维度并固定字段集合。
- 更新 checklist 中仍引用旧口径（例如 mk1/IPv6 defer 示例）的条目，使其与新的双栈纲领一致。
- 仅生成 change artifacts + delta specs + tasks；不在本 change 中实现任何 daemon 代码变更。

## Capabilities

### New Capabilities
- (none)

### Modified Capabilities
- `control-vnext-iprules-surface`: `matchKey` 从 mk1 升级为 mk2（包含 `family`），并新增/收口 `family`、`proto=other`、`IPRULES.PREFLIGHT.byFamily` 的稳定契约要求。
- `pktstream-observability`: vNext pkt 事件 schema 增加 `l4Status`（always-present）及其枚举/端口输出约束。
- `conntrack-observability`: `METRICS.GET(name=conntrack)` 输出 shape 增加 `byFamily.ipv4/ipv6`，并保证字段集合稳定。

## Impact

- 影响文件（权威文档/主规格）：  
  - `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`  
  - `openspec/specs/control-vnext-iprules-surface/spec.md`  
  - `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`  
  - `openspec/specs/pktstream-observability/spec.md`  
  - `openspec/specs/conntrack-observability/spec.md`  
  - `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`
- 下游影响：未来实现 `add-iprules-dual-stack-ipv6` 时，daemon/ctl/tests 必须按本 change 的权威契约与主规格落地。
