# IPRULES：原子 apply 契约（rule group 展开 / matchKey / clientRuleId）

更新时间：2026-04-20  
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
- 命令名与 envelope/selector 约束以 vNext 单一真相为准：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md` + `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`。  
  本文第 9 节会补齐 `IPRULES.PREFLIGHT/PRINT/APPLY` 的 JSON schema（字段全集/类型），用于避免实现期漂移（已确认；R-014=A）。

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
mk1|dir=<...>|iface=<...>|ifindex=<...>|proto=<...>|ctstate=<...>|ctdir=<...>|src=<...>|dst=<...>|sport=<...>|dport=<...>
```

约束：

- 固定字段顺序（如上），固定分隔符（`|` 与 `=`），全小写，无空格。
- 取值口径必须与 `IPRULES.PRINT` 的字符串口径一致（`any/in/out`、`any/tcp/udp/icmp`、CIDR、port predicate 等）。

各字段取值：

- `dir`：`any|in|out`
- `iface`：`any|wifi|data|vpn|unmanaged`
- `ifindex`：`0|<decimal>`（`0` 表示不约束；数值为非负十进制）
- `proto`：`any|tcp|udp|icmp`
- `ctstate`：`any|new|established|invalid`
- `ctdir`：`any|orig|reply`
- `src` / `dst`：`any|a.b.c.d/prefix`（IPv4；`prefix` 为 `0..32`）
- `sport` / `dport`：`any|N|lo-hi`（十进制；`N/lo/hi` 为 `0..65535`，且 `lo<=hi`）

### 3.2 规范化规则

为避免“看起来不同、实际上等价”的重复：

- CIDR 必须规范化为网络地址：`a.b.c.d/prefix` 中的 `a.b.c.d` 必须已经按 `prefix` mask 归零 host bits。  
  - 示例：`1.2.3.4/24` → `1.2.3.0/24`
- `ifindex` 归一化：`ifindex=0` 表示 any；canonical 输出为 `ifindex=0`。（若上层语法使用 `any`，CLI 必须在下发前归一化为 `0`。）
- 若 `proto=icmp`：`sport/dport` 必须为 `any`（与引擎语义一致）。

---

## 4. 冲突检测与错误 shape

### 4.1 冲突检测（v1，强一致）

对某个 `<uid>` 的一次原子 apply：

- 后端必须对每条规则计算 `matchKey`。
- **`matchKey` 必须唯一**：同一 `<uid>` 的 apply payload 内，任何重复 `matchKey` 都必须拒绝 apply。  
  - 解释：重复 `matchKey` 会导致“同一匹配集合存在多条规则”，无论字段是否相同都会破坏可解释性与 1:1 归因（`clientRuleId`）。

### 4.2 错误 payload（`INVALID_ARGUMENT`）

冲突拒绝 apply 时，错误形态锁死为（vNext response envelope；`id` 为示例）：

```json
{
  "id": 123,
  "ok": false,
  "error": {
    "code": "INVALID_ARGUMENT",
    "message": "iprules conflict: duplicated matchKey",
    "conflicts": [
      {
        "uid": 10123,
        "matchKey": "mk1|dir=out|iface=any|ifindex=0|proto=tcp|ctstate=any|ctdir=any|src=any|dst=1.2.3.0/24|sport=any|dport=443",
        "rules": [
          {"clientRuleId": "g1:r12", "action": "block", "priority": 10, "enabled": 1, "enforce": 1, "log": 0},
          {"clientRuleId": "g2:r7", "action": "allow", "priority": 10, "enabled": 1, "enforce": 1, "log": 0}
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

---

## 5. apply 成功响应：必须回传 `clientRuleId -> ruleId -> matchKey` 映射（已确认；2.13）

定位：
- apply 的输入是“配置层展开后的 rules（含 `clientRuleId`）”，但后续运行期与后端其它接口（`UPDATE/ENABLE/REMOVE`、`PKTSTREAM.ruleId`）依赖的是 `ruleId`。
- 因此 apply 成功时必须在响应中回传“这次生效基线里，每条 `clientRuleId` 对应哪个 `ruleId` 与 `matchKey`”，避免前端再额外 `IPRULES.PRINT` 扫一遍做 join。

成功响应 shape（建议；vNext response envelope；`id` 为示例）：

```json
{
  "id": 123,
  "ok": true,
  "result": {
    "uid": 10123,
    "rules": [
      {"clientRuleId": "g1:r12", "ruleId": 10, "matchKey": "mk1|dir=out|iface=any|ifindex=0|proto=tcp|ctstate=any|ctdir=any|src=any|dst=1.2.3.0/24|sport=any|dport=443"},
      {"clientRuleId": "g2:r7", "ruleId": 11, "matchKey": "mk1|dir=out|iface=any|ifindex=0|proto=tcp|ctstate=any|ctdir=any|src=any|dst=2.3.4.0/24|sport=any|dport=443"}
    ]
  }
}
```

字段约束：
- `result.uid`：本次 apply 的目标 UID（与请求一致）。
- `result.rules[]`：必须与提交后的新基线 1:1 对应（每条规则一项，不得缺失）。
- `result.rules[].clientRuleId`：与请求一致。
- `result.rules[].ruleId`：提交后生效的稳定标识（见第 6 节）。
- `result.rules[].matchKey`：提交后生效的 canonical 匹配集合编码（mk1）。

注：
- 若后续担心 payload 过大，可引入可选 `truncated`（默认 false），但 v1 推荐强制完整回传（与“强一致可观察”目标一致）。

---

## 6. `ruleId` 分配与稳定性：对 `clientRuleId` 稳定复用（已确认；2.13 B）

对同一 `<uid>` 的 apply：

- 若某条 `clientRuleId` 在“当前生效 ruleset”中已存在，则 apply 后必须**复用其原 `ruleId`**（即使该规则定义发生变化）。
- 若某条 `clientRuleId` 是新增，则必须分配新的 `ruleId`：
  - 分配器状态与 v1 `IPRULES.ADD` 一致：从 `0` 开始单调递增；
  - 已删除的 `ruleId` 不得复用；
  - `RESETALL` 清空规则集后，下一条新规则从初始 `ruleId = 0` 重新开始分配。

等价理解：
- `clientRuleId` 是前端的“稳定身份”；`ruleId` 是后端运行期句柄。
- apply 是 replace 语义，但“身份复用”必须以 `clientRuleId` 为准（避免 ruleId 来回漂移导致 PKTSTREAM 归因不稳定）。

实现侧要求（文档层约束）：
- 后端必须在规则持久化结构中保存 `clientRuleId`（否则无法在重启后做到稳定复用）。

---

## 7. apply 对 per-rule stats 的影响：幂等 apply 不清 stats（已确认；2.13 B）

apply 成功后，对每条规则的 per-rule stats 生命周期锁死为：

- 新增规则（新增 `clientRuleId` / 新分配 `ruleId`）：stats 归零（初始状态）。
- 删除规则（`clientRuleId` 不在新基线中）：stats 消失（不再可见）。
- 复用 `ruleId` 的规则：
  - 若“规则定义完全一致”则保留 stats；
  - 否则 reset stats（对齐 v1 `IPRULES.UPDATE` 的心智：定义变化即清零）。

“规则定义完全一致”的判据（v1）：
- `matchKey` 相同（mk1 canonical；覆盖所有 match 维度）
- 且 `action/priority/enabled/enforce/log` 全部相同

注：
- 该口径与现有引擎约束一致：`UPDATE` 必须 reset stats、`ENABLE 0->1` 必须 reset stats；apply 只是把“变化判定”提升到 replace 粒度。

---

## 8. PKTSTREAM 归因字段：继续只输出 `ruleId`（已确认；2.13 A）

- PKTSTREAM 事件继续只输出数值 `ruleId/wouldRuleId`（不回显 `clientRuleId`）。
- 前端如需把命中归因到配置来源（rule group / UI item），应通过 `ruleId -> clientRuleId` 做 join：
  - `IPRULES.PRINT` 必须回显 `clientRuleId`（第 2 节）
  - apply 成功响应必须回传 `clientRuleId -> ruleId` 映射（第 5 节）

该选择的核心理由：避免在高频 PKTSTREAM 上引入 per-event string 成本；以“稳定 ruleId + 可 join”为主。

---

## 9. vNext `IPRULES.*` JSON schema（字段全集/类型；已确认；R-014=A）

目标：在动代码前把 schema 写死，避免 daemon/CLI/tests 三方对字段名、类型、以及 `0|1` vs boolean 产生漂移。

通用约定（不在本文重复定义）：
- request/response envelope、selector、strict reject：见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
- toggle 类型统一为 `0|1`（numbers）：见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`

### 9.1 `IPRULES.PREFLIGHT`

request：

```json
{"id":1,"cmd":"IPRULES.PREFLIGHT","args":{}}
```

response：

```json
{"id":1,"ok":true,"result":{
  "summary":{
    "rulesTotal":0,"rangeRulesTotal":0,"ctRulesTotal":0,"ctUidsTotal":0,
    "subtablesTotal":0,"maxSubtablesPerUid":0,"maxRangeRulesPerBucket":0
  },
  "limits":{
    "recommended":{"maxRulesTotal":0,"maxSubtablesPerUid":0,"maxRangeRulesPerBucket":0},
    "hard":{"maxRulesTotal":0,"maxSubtablesPerUid":0,"maxRangeRulesPerBucket":0}
  },
  "warnings":[{"metric":"...","value":0,"limit":0,"message":"..."}],
  "violations":[{"metric":"...","value":0,"limit":0,"message":"..."}]
}}
```

类型约束：
- `summary.*`：u64
- `limits.*.*`：u64
- `warnings[]/violations[]` item：
  - `metric`：string
  - `value/limit`：u64
  - `message`：string

### 9.2 `IPRULES.PRINT`

request：

```json
{"id":2,"cmd":"IPRULES.PRINT","args":{"app":{"uid":10123}}}
```

response：

```json
{"id":2,"ok":true,"result":{"uid":10123,"rules":[
  {"ruleId":0,"clientRuleId":"g1:r12","matchKey":"mk1|...","action":"block","priority":10,
   "enabled":1,"enforce":1,"log":0,
   "dir":"out","iface":"any","ifindex":0,"proto":"tcp",
   "ct":{"state":"any","direction":"any"},
   "src":"any","dst":"1.2.3.0/24","sport":"any","dport":"443",
   "stats":{"hitPackets":0,"hitBytes":0,"lastHitTsNs":0,"wouldHitPackets":0,"wouldHitBytes":0,"lastWouldHitTsNs":0}}
]}}
```

`result` 字段：
- `uid`：u32（与 selector resolve 后的 uid 一致）
- `rules[]`：数组，每个 item 为 `Rule`（见 9.4）

`stats.*` 时间戳字段说明（v1）：
- `lastHitTsNs/lastWouldHitTsNs`：u64（ns）；可能超过 JS `Number` 的安全整数范围；JS 客户端应避免依赖其精确值。

### 9.3 `IPRULES.APPLY`

request：

```json
{"id":3,"cmd":"IPRULES.APPLY","args":{"app":{"uid":10123},"rules":[
  {"clientRuleId":"g1:r12","action":"block","priority":10,"enabled":1,"enforce":1,"log":0,
   "dir":"out","iface":"any","ifindex":0,"proto":"tcp",
   "ct":{"state":"any","direction":"any"},
   "src":"any","dst":"1.2.3.0/24","sport":"any","dport":"443"}
]}}
```

约束（schema）：
- `rules[]` 每个 item 必须包含：
  - 身份：`clientRuleId`
  - 行为：`action/priority/enabled/enforce/log`
  - 匹配：`dir/iface/ifindex/proto/ct/src/dst/sport/dport`
- 禁止客户端在 apply payload 中携带：
  - `ruleId`（由 daemon 分配/复用；见第 6 节）
  - `matchKey`（由 daemon 计算；见第 3 节）
  - `stats`（只在 `IPRULES.PRINT` 输出）

成功 response：
- 见第 5 节（必须回传 `clientRuleId -> ruleId -> matchKey` 映射）。

失败 response：
- 冲突：见第 4.2 节（`error.code=INVALID_ARGUMENT` + `conflicts[]`）。

### 9.4 `Rule` 对象字段与类型（v1）

`rules[]` item（`IPRULES.PRINT.result.rules[]`）字段全集：
- `ruleId`：u32
- `clientRuleId`：string（`[A-Za-z0-9._:-]{1,64}`）
- `matchKey`：string（`mk1|...`；见第 3 节）
- `action`：`"allow" | "block"`
- `priority`：i32
- `enabled/enforce/log`：`0|1`（numbers）
- `dir`：`"any" | "in" | "out"`
- `iface`：`"any" | "wifi" | "data" | "vpn" | "unmanaged"`
- `ifindex`：u32（`0` 表示 any；canonical 输出为 `0`）
- `proto`：`"any" | "tcp" | "udp" | "icmp"`
- `ct`：
  - `state`：`"any" | "new" | "established" | "invalid"`
  - `direction`：`"any" | "orig" | "reply"`
- `src/dst`：`"any"` 或 `"a.b.c.d/prefix"`（IPv4 CIDR；network address 已规范化）
- `sport/dport`：`"any"` 或 `"N"` 或 `"lo-hi"`（十进制；`0..65535`）
- `stats`：
  - `hitPackets/hitBytes/lastHitTsNs/wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`：u64

`IPRULES.APPLY.args.rules[]` 的 item 复用上述字段集合，但不包含：
- `ruleId/matchKey/stats`
