## Context

我们已经完成 IPRULES 双栈规则模型的纲领决策（`docs/decisions/IPRULES_DUAL_STACK_WORKING_DECISIONS.md`），并已将权威契约/主规格同步到“`family` 必填 + mk2 `matchKey` + `l4Status` + conntrack `byFamily`”口径（见 `docs/INTERFACE_SPECIFICATION.md` 与 `openspec/specs/*`）。

但当前实现仍存在关键缺口（均会影响发布级语义与测试口径）：
- datapath：`src/PacketManager.hpp` 的 IPRULES fast path 明确 IPv4-only（`if constexpr (IP==IPv4)`）；IPv6 包绕过 IPRULES。
- listener：`src/PacketListener.cpp` 对 TCP/UDP malformed 直接 `NF_DROP`；IPv6 仅 base header 解析，不具备 ext header walker，也无法产出稳定 `l4Status`。
- engine：`src/IpRulesEngine.*` 只有 `CidrV4/PacketKeyV4`，`Proto` 无 `OTHER`，持久化 formatVersion 仍为 1/2/3。
- stream：`ControlVNextStreamManager::PktEvent` 缺少 `l4Status` 字段，JSON 输出也未包含该字段。
- conntrack：`src/Conntrack.*` IPv4-only（`PacketV4`），metrics 也未按 family 细分（但主规格已要求 `byFamily`）。

约束（发布级不可破）：
- IPv4 热路径不得被迫走 128-bit 通用慢路径；不得新增锁、IO 或每包动态分配。
- `family` 必须是一等语义字段，不允许默认/推断/`family=any`。
- 不引入 reassembly；fragment 走稳定分类（`l4Status=fragment`、端口不可用、conntrack invalid）。
- 不改 LAS/legacy 控制接口返回样式；vNext wire shape 以现有契约为准。

## Goals / Non-Goals

**Goals:**
- IPRULES 规则模型升级为 IPv4/IPv6 同级（显式 `family`、IPv6 CIDR、`proto=other`、mk2 `matchKey`）。
- IPv6 datapath 进入 IPRULES 判决；产出稳定 `l4Status` 并与端口输出一致（非 `known-l4` 时 ports=0）。
- listener 修正 malformed L4 的 drop 策略：从 “reject+DROP” 改为 “fail-open 进入策略并可由规则接管”。
- conntrack 扩展到双栈，内部按 family 分表，并将 gating 扩展为 `uid+family`；观测输出 `byFamily`。
- 测试同步升级：host unit tests + device smoke/matrix 必须覆盖 IPv6（含 KTV 固定向量）。

**Non-Goals:**
- 不做 IPv4/IPv6 fragments reassembly；不引入更强的 L4/L7 深度解析。
- 不引入 `family` 省略/默认/推断；不支持 `family=any`。
- 不新增独立观测通路（仅按既有 vNext stream/metrics 契约补齐字段）。
- 不做 LAS/legacy 接口大改或返回 shape 变更。

## Decisions

1. **引擎内部“按 family 分离 compiled view”，对外维持单一 IPRULES 规则模型**
   - 选择：在 `IpRulesEngine` 内将 active ruleset 按 `family` 分区编译为两个子快照（v4/v6），分别使用 `PacketKeyV4` 与新增的 `PacketKeyV6`。
   - 理由：保持 IPv4 热路径与现有结构一致，避免 IPv4 被迫走 128-bit key/hashing。
   - 备选：统一一个通用 key（含 128-bit 地址）并运行时分支。拒绝原因：对 IPv4 hot path 风险大（key 变大、hash/compare 成本上升、cache 命中率/布局变化）。

2. **HotSnapshot API 扩展为 per-family evaluate 与 gating**
   - 选择：保留 `HotSnapshot::evaluate(PacketKeyV4)`；新增 `evaluate(PacketKeyV6)`；并将 `uidUsesCt(uid)` 扩展为 `uidUsesCt(uid,family)`（或等价两套 bitmap）。
   - 理由：让 `PacketManager` 的模板分派保持 compile-time family specialization，避免把 family 变成热路径的动态分支中心。

3. **datapath 解析输出统一为“可判决输入”，用 `l4Status` 钉死端口可用性**
   - 选择：引入一个栈上 `L4ParseResult`（或等价结构）统一承载：
     - `family` / `declaredOrTerminalProto`（用于规则 `proto=tcp|udp|icmp|other|any`）
     - `l4Status`（四态枚举）
     - `srcPort/dstPort`（不可用时为 0）
     - `isFragment`（或由 `l4Status=fragment` 表达）
   - IPv6：实现 ext header walker（预算：最多 8 个 ext headers / 256 bytes），跳过 HBH/DstOpts/Routing/AH；Fragment 单独分类；ESP/No Next Header/未知合法 terminal 归为 `other-terminal`；预算耗尽/长度异常归为 `invalid-or-unavailable-l4`。
   - IPv4：保留现有端口提取逻辑，但对 TCP/UDP malformed 不再 `NF_DROP`，改为 `invalid-or-unavailable-l4`（端口=0，conntrack invalid）。
   - 理由：与权威契约一致，且允许通过规则（例如 `ct.state=invalid`、`proto=any`）对异常输入做显式兜底。

4. **stream 事件 `l4Status` 用内部 enum 表达，JSON 序列化时输出 string**
   - 选择：在 `ControlVNextStreamManager::PktEvent` 增加轻量枚举字段（例如 `std::uint8_t l4Status`），并在 `ControlVNextStreamJson::makePktEvent()` 中转换为契约规定的 string。
   - 理由：避免热路径保存/拷贝 string；序列化线程承担 string 输出成本。

5. **conntrack 双栈实现采用“单实例 + 两张表”，共享容量上限**
   - 选择：在 `Conntrack` 内部维护 v4/v6 两张表（同一 Options.maxEntries 预算下做 family-aware 分配/回收策略），并统一对外 API（inspect/commit/update）按 family 分派。
   - gating：由 `App` 缓存从 “uid uses ct” 扩展为 “uid+family uses ct”，避免 IPv6 无 CT consumer 时对每包做 update。
   - 理由：符合双栈同级外部模型，同时允许内部优化降低互相影响（尤其保护 IPv4 路径）。

6. **IPRULES 持久化格式升级到 v4，restore 失败 fail-open**
   - 选择：bump `formatVersion=4`，落盘规则显式包含 `family` 与对应 CIDR；restore 只接受 v4，旧 v1/v2/v3 一律视为 restore failure（daemon 启动继续，发布空规则集并记录日志）。
   - 理由：当前尚无“已发布且需兼容”的历史包袱，复杂迁移收益低且容易引入隐式默认（与 `family` 一等原则冲突）。

## Risks / Trade-offs

- [Risk] IPv6 ext header walker 复杂度与性能风险 → Mitigation：固定预算（8 headers/256 bytes），仅实现必须跳过的 header 集合；保持 IPv4 fast path 完全不受影响。
- [Risk] fail-open 对 malformed L4 不再直接 DROP，可能被误解为“更宽松” → Mitigation：通过 `l4Status` + 端口不可用规则保证可解释；允许用 `ct.state=invalid`/`proto=any` 规则显式接管；同时保留 IFACE_BLOCK 最高优先级 hard-drop。
- [Risk] Android 真机环境对 IPv6 工具链支持不一致（`ping -6` vs `ping6`、`nc -6` 支持差异） → Mitigation：device 模组实现探测与 fallback；将 smoke/matrix 设计为“能力存在即测”，缺工具时明确 SKIP 而非 silent pass。

## Migration Plan

- 本 change 面向“发布前”收敛：升级 IPRULES save format 到 v4 后，旧格式 restore 失败不会阻断启动（按决议记录日志并以空规则集运行）。
- 风险回退：若 IPv6 路径引入性能/正确性回归，支持通过配置开关临时禁用 IPRULES 或在任务拆分中先落地“IPv6 进入 IPRULES + l4Status + tests”，再开启更完整的 conntrack v6（按 tasks 里阶段 gating）。

## Open Questions

- Tier‑1 netns/veth 在目标设备上的 `ip -6 route get ... uid <uid>` 支持程度需在实现时验证；若缺失，需要调整“路由注入有效性验证”策略（不改变目标语义，只改变测试探测方式）。
