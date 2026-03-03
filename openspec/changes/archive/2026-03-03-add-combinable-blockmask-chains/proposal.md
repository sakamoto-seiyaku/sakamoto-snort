# Change: Combinable blockmask chains for blocking lists

## Why
当前后端把“订阅列表/域名集合”折叠为 `domainMask`、把“每个 App 启用哪些能力”折叠为 `appMask`，并在兜底路径上以
`appMask & domainMask` 作出拦截判定（自定义白/黑名单与规则优先级保持更高）。

前端希望在保留“标准(1) / 增强(8)”全局能力的同时，利用剩余 bit 提供 5 条“可组合的额外链”，从而让某些订阅列表仅对选定
App 生效（例如仅对少数广告特别多的 App 开启）。

## What Changes
- 订阅列表（BlockingList/DomainList）的 `blockMask` 约束为 **单 bit**，且只允许：`1 / 2 / 4 / 8 / 16 / 32 / 64`。
  - 禁止 `0`、禁止多 bit（例如 `1|8`）、禁止使用 `128`（该 bit 保留给 App 的 custom list 行为开关）。
  - App 的 `BLOCKMASK` 仍可为上述 bit 的任意组合：
    - 标准模式：包含 `1`
    - 增强模式（包含标准）：包含 `1|8`（后端强制：只要设置了 `8` 就自动补齐 `1`）
    - 组合链：额外 OR `2/4/16/32/64`
- 移除 `DomainList::write` 的跨 listId “跳过写入式去重”逻辑：
  - 仅保留 **同一 list 内** 的去重；不同 listId 之间不去重。
  - 目的：避免组合链之间互相干扰，并保证“单个订阅 enable/disable/remove”始终自洽、不依赖其他订阅的内容。
- 查询策略保持不变（性能优先）：`DomainList::blockMask` 仍按“exact 优先 + suffix first-hit”返回聚合 mask。
 - 后端 `Stats::Color`/统计分组保持不变：新增 bit 可能在现有接口中落入 `GREY` 分组；前端可使用 `domMask/appMask` 做链与颜色映射。

## Impact
- Affected code:
  - `src/DomainList.cpp`：调整 `write()` 去重语义。
  - `src/Control.cpp` / `src/BlockingListManager.cpp`（或等价位置）：新增 `blockMask` 校验，拒绝非法 mask。
  - `docs/INTERFACE_SPECIFICATION.md` 与 Control HELP：同步 mask 约束与可用 bit。
- Behavior impact:
  - 引入组合链 bit 后，拦截判定仍是 `appMask & domainMask`，但新的 bit 只会影响选择了对应 bit 的 App。
  - 统计/颜色映射保持现状（仅识别 bit1/bit8）；新增 bit 的可视化分组由前端基于 `domMask/appMask` 计算（本变更不扩展后端颜色枚举）。
