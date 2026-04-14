# IPRULES：原子 apply 契约（rule group 展开 / matchKey / clientRuleId）

更新时间：2026-04-14  
状态：已收敛（AAA）

> 本文只定义“前后端约定/接口契约”，不涉及代码实现与 change 拆分。
> 本轮讨论只维护 `docs/decisions/DOMAIN_IP_FUSION/` 目录内文档，不外溢修改其它 docs 或代码。

---

## 0. 背景与范围

- IP “规则组”是**配置层概念**（前端/配置生成器）；后端不持久化 group/profile。
- 后端唯一可执行对象仍是：每个 app（per‑UID）的 `IPRULES` 规则集合（以及其 `ruleId/stats`）。
- 本文收敛并锁死：
  1) 原子 apply（路线 1，强一致）  
  2) `clientRuleId`：前端归因 token（必须在 `IPRULES.PRINT` 回显）  
  3) `matchKey`：后端归一化匹配条件集合的**可打印编码**  
  4) 冲突错误 shape（`error.code=INVALID_ARGUMENT`，不够再加）

非目标：

- 不讨论 UI 上 rule group 的展示优先级/排序（纯前端问题）。
- 不在本文定义具体命令名（例如 `IPRULES.APPLY` / `IPRULES.REPLACE` 等）；本文只定义语义与返回形态。

---

## 1. 原子 apply（路线 1，强一致）

对单个 `<uid>` 的规则集更新必须满足：

- **原子 replace**：一次 apply 要么整体成功、要么整体失败；禁止部分成功。
- **强一致可观察**：
  - apply 成功返回后，后续 `IPRULES.PRINT`/判决/统计必须看到新基线（旧基线不可再见）。
  - apply 失败时：现有规则集保持不变（不得“半更新成功”污染下一次下发）。
- **完整校验先于提交**：后端必须在提交前完成：
  - 语法/值域校验（例如 `proto=icmp` 时 `sport/dport` 必须为 `any`）
  - 冲突检测（见第 4 节）
  - 资源/复杂度检查（可复用 `IPRULES.PREFLIGHT` 的口径；具体门槛由实现阶段确定）

多 app 下发策略（契约层约束）：

- 不新增 “按 userId 批量 apply” 能力；前端需要批量时应枚举 app 并逐个 `<uid>` apply（可观测、可回滚）。

---

## 2. `clientRuleId`（前端归因 token）

定位：`clientRuleId` 是前端生成的稳定 token，用于把后端规则与 UI 侧的“某个 group/某条 rule”做 1:1 映射。

契约（v1）：

- 类型：string（区分大小写）。
- 格式：`[A-Za-z0-9._:-]{1,64}`（禁止空白/控制字符）。
- **唯一性**：同一次对某个 `<uid>` 的原子 apply payload 内，`clientRuleId` 必须唯一。
- **回显要求（强制）**：`IPRULES.PRINT` 的每条规则对象必须回显 `clientRuleId`。
- **错误归因（强制）**：冲突错误（第 4 节）必须在冲突规则条目中回显 `clientRuleId`。

注：

- 后端不解析 `clientRuleId` 的业务语义，只做格式校验 + 透传/持久化。
- 若配置层展开后出现完全相同规则的重复来源，应在前端先去重，再选择一个稳定的 `clientRuleId` 代表合并后的规则（如何合并属于前端实现细节）。

---

## 3. `matchKey`（归一化匹配条件集合编码）

定位：`matchKey` 由后端根据规则的 **match 维度字段**计算得到，用于：

- 在 apply 阶段检测冲突（同一 `matchKey` 不允许出现多条规则，见第 4 节）
- 在错误中回显“冲突发生在什么匹配集合上”，避免前端自行重新实现一套 canonicalizer

### 3.1 `matchKey` 字符串格式（mk1）

`matchKey` 必须是可打印、可复现、可比对的 canonical string，并且**版本化**：

```text
mk1|dir=<...>|iface=<...>|ifindex=<...>|proto=<...>|ctState=<...>|ctDir=<...>|src=<...>|dst=<...>|sport=<...>|dport=<...>
```

约束：

- 固定字段顺序（如上），固定分隔符（`|` 与 `=`），全小写，无空格。
- 取值口径必须与 `IPRULES.PRINT` 的字符串口径一致（`any/in/out`、`any/tcp/udp/icmp`、CIDR、port predicate 等）。

各字段取值：

- `dir`：`any|in|out`
- `iface`：`any|wifi|data|vpn|unmanaged`
- `ifindex`：`any|<decimal>`（`any` 表示不约束；数值为非负十进制）
- `proto`：`any|tcp|udp|icmp`
- `ctState`：`any|new|established|invalid`
- `ctDir`：`any|orig|reply`
- `src` / `dst`：`any|a.b.c.d/prefix`（IPv4；`prefix` 为 `0..32`）
- `sport` / `dport`：`any|N|lo-hi`（十进制；`N/lo/hi` 为 `0..65535`，且 `lo<=hi`）

### 3.2 规范化规则

为避免“看起来不同、实际上等价”的重复：

- CIDR 必须规范化为网络地址：`a.b.c.d/prefix` 中的 `a.b.c.d` 必须已经按 `prefix` mask 归零 host bits。  
  - 示例：`1.2.3.4/24` → `1.2.3.0/24`
- `ifindex=0` 视为 `ifindex=any`（不约束）。
- 若 `proto=icmp`：`sport/dport` 必须为 `any`（与引擎语义一致）。

---

## 4. 冲突检测与错误 shape

### 4.1 冲突检测（v1，强一致）

对某个 `<uid>` 的一次原子 apply：

- 后端必须对每条规则计算 `matchKey`。
- **`matchKey` 必须唯一**：同一 `<uid>` 的 apply payload 内，任何重复 `matchKey` 都必须拒绝 apply。  
  - 解释：重复 `matchKey` 会导致“同一匹配集合存在多条规则”，无论字段是否相同都会破坏可解释性与 1:1 归因（`clientRuleId`）。

### 4.2 错误 payload（`INVALID_ARGUMENT`）

冲突拒绝 apply 时，错误形态锁死为：

```json
{
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "iprules conflict: duplicated matchKey",
    "conflicts": [
      {
        "uid": 10123,
        "matchKey": "mk1|dir=out|iface=any|ifindex=any|proto=tcp|ctState=any|ctDir=any|src=any|dst=1.2.3.0/24|sport=any|dport=443",
        "rules": [
          {"clientRuleId": "g1:r12", "action": "block", "priority": 10, "enabled": true, "enforce": true, "log": false},
          {"clientRuleId": "g2:r7", "action": "allow", "priority": 10, "enabled": true, "enforce": true, "log": false}
        ]
      }
    ],
    "truncated": false
  }
}
```

字段约束：

- `error.code`：固定复用 `INVALID_ARGUMENT`（不够再新增枚举；不得改名/删值）。
- `conflicts[]`：
  - item 最小字段：`uid`、`matchKey`、`rules[]`
  - `rules[]` item 最小字段：`clientRuleId` + 会影响语义的关键字段（`action/priority/enabled/enforce/log`）
- `truncated`：若出于保护上限导致 `conflicts[]` 被截断，必须显式 `truncated=true`（避免前端误判“只有这些冲突”）。

