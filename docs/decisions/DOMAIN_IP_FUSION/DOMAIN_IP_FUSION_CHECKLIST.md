# Domain + IP Fusion Checklist

更新时间：2026-04-17  
状态：融合纲领（现状快照 + 目标状态 + 实现拆分）

---

## 0. 目的

这份文档把 `domain+IP fusion` 的工作收敛为三件事：

1. **现状快照**（第 1 节）：完全按代码事实陈述，不做推演。  
2. **目标状态**（第 2 节）：fusion 完成后，“用户应如何理解系统”的统一心智模型。  
3. **实现拆分**（第 3 节）：从现状走到目标，需要改哪些东西、如何拆 change、按什么顺序落地。

## 0.1 本目录文档索引（in-flight，避免与既有决策打架）

- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`：本 checklist（主入口）
- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_AUDIT_TMP.md`：临时审阅笔记/裁决日志（便于逐条回复；**非最终规格**）
- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_DESIGN_REVIEW_TMP.md`：临时“挑刺”审核意见（非规范性；用于去复杂化/找过度设计点）
- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_NITPICKS_TMP.md`：最终挑刺清单（临时；逐条回复用）
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`：control 协议 vNext（wire framing/JSON envelope/selector/错误模型/stream 状态机）
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`：vNext 命令目录（每个 `cmd` 的 args/result/errors；与协议文档解耦，便于挑刺与落地拆分）
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_VNEXT_SURFACE_SIMPLIFIED_TMP.md`：vNext 命令面重设计（简化提案；确认后回写命令目录）
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`：可观测性工作决策（stream vNext、`tracked` 统一语义、metrics name=`traffic`/`conntrack` 等）
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_IMPLEMENTATION_TASKS.md`：可观测性落地任务清单（从工作结论提炼为 change 切片）
- `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`：IP 规则组/原子 apply 契约（`matchKey/clientRuleId`、冲突错误 shape、`IPRULES.PRINT` 回显）

本目录内部的“落盘规则”（避免前后矛盾）：

- `DOMAIN_IP_FUSION_AUDIT_TMP.md` 负责记录讨论与裁决；但**裁决一旦确认**，必须同步写入对应的“单一真相”文档：
  - control 协议（wire framing/JSON envelope）/错误模型/selector：`CONTROL_PROTOCOL_VNEXT.md`
  - stream/metrics/tracked/drop/cap 等观测语义：`OBSERVABILITY_WORKING_DECISIONS.md`
  - implementation tasks：`OBSERVABILITY_IMPLEMENTATION_TASKS.md`（应当由 working decisions 派生，不应自创新语义）
  - IPRULES apply 契约：`IPRULES_APPLY_CONTRACT.md`
- 本 checklist 只做索引与摘要；如果 checklist 与上述单一真相发生冲突，应以单一真相为准并立即修正 checklist。

## 0.2 单一真相与同步策略（重要）

- 本目录文档用于收敛 **vNext 设计**；在“落盘到 change/实现”之前，它允许与仓库内既有“权威文档/规格”存在硬冲突（这是预期行为）。
- 在当前阶段（仅设计/审阅）：
  - `docs/INTERFACE_SPECIFICATION.md`、`openspec/specs/*` 继续描述 **当前代码现状**；
  - 本目录描述 **未来 vNext 目标**；不要把两者混用当作同一套接口承诺。
- 进入实现阶段时，至少需要同步更新（不在本目录内做）：
  - `docs/INTERFACE_SPECIFICATION.md`（control/stream vNext、selector、多用户语义）
  - `openspec/specs/multi-user-support/spec.md`（selector 语法/拒绝策略）
  - `openspec/specs/domain-policy-observability/spec.md`（`policySource` 枚举 rename）
  - `docs/decisions/DOMAIN_POLICY_OBSERVABILITY.md`（与 OpenSpec 对齐）

---

## 1. 当前系统快照（按代码事实）

### 1.1 DomainPolicy（域名侧）

- DomainPolicy 判决核心仍是 `App::blocked()` / `App::blockedWithSource()`，见 `src/App.cpp:90`
- device-wide 域名名单/规则由 `DomainManager::authorized()` / `DomainManager::blocked()` 提供，见 `src/DomainManager.cpp:78`
- `GLOBAL_AUTHORIZED` / `GLOBAL_BLOCKED` 当前**只表示 domain-only device-wide 层**，不是系统真正的“全局”，见 `src/DomainPolicySources.hpp:18`

### 1.2 Packet / IP（包级侧）

- 当前 packet 判决顺序已经是：

```text
IFACE_BLOCK
  -> IPRULES (IPv4 only)
  -> legacy domain path (DNS-learned Domain↔IP bridge)
  -> BLOCKIPLEAKS
```

- 该顺序直接体现在 `PacketManager::make()`，见 `src/PacketManager.hpp:112`
- `PacketListener` 已经做成 phase-1（锁外准备）/ phase-2（锁内纯判决）两段，见 `src/PacketListener.cpp:353`

### 1.3 作用域（scope）现状

- DomainPolicy 当前有三层“作用域/来源”：
  - per-app custom lists / custom rules
  - domain-only device-wide custom/global lists / rules
  - app `blockMask & domain.blockMask` fallback
- Packet 侧当前有三类能力：
  - `IFACE_BLOCK`（per-app + default mask）
  - `IPRULES`（**仅 per-UID**）
  - `BLOCKIPLEAKS`（legacy overlay）
- 也就是说：**DomainPolicy 有 device-wide + per-app 两层，而 IPRULES 当前只有 per-UID 一层**

### 1.4 可观测性现状

- DomainPolicy：`METRICS.DOMAIN.SOURCES*`（DNS verdict 来源），见 `src/DnsListener.cpp:202`
- DomainPolicy（调试事件）：`DNSSTREAM` 当前不包含 `policySource/useCustomList`，且 `domMask/appMask` 为“打印时读取”（非判决时快照），并受 `app->tracked()` gating 影响，见 `src/DnsRequest.cpp:30`、`src/DnsListener.cpp:241`
- Packet：`METRICS.REASONS*` + `PKTSTREAM(reasonId/ruleId/wouldRuleId)`，见 `src/PacketManager.hpp:174`、`src/Packet.cpp:66`
- IPRULES：`IPRULES.PRINT` per-rule stats + `IPRULES.PREFLIGHT`
- Perf：`PERFMETRICS` / `METRICS.PERF*`

### 1.5 已经能直接看出的不统一点

1. **“GLOBAL_*” 名不副实**  
   它只覆盖域名侧 device-wide 名单/规则，不覆盖 `IFACE_BLOCK` / `IPRULES` / `BLOCKIPLEAKS`

2. **作用域不对称**  
   DomainPolicy 有 device-wide / per-app 两层；IPRULES 没有 device-wide/global IP 规则

3. **DNS 与 Packet 叙事割裂**  
   DNS 只讲 `policySource`；packet 只讲 `reasonId/ruleId`

4. **`BLOCK=0` 语义不完全同构**  
   packet 路径整体 bypass；DNS 路径仍会走最小判决/映射流程，但常态 counters 不更新

5. **统计归因风格不一致**  
   Domain path 更新 app/domain stats 时带 domain color；IPRULES 命中目前按 `domain=null, color=GREY` 记账，见 `src/PacketManager.hpp:188`

---

## 2. 目标状态（fusion 完成后的统一心智模型）

> 本节描述的是“做完之后应该长什么样”。第 1 节是现状；不要混用。

本轮 fusion 的目标不是把 Domain 与 IP 的“匹配字段”强行对齐，而是让用户能用同一套模型理解系统，统一落在三个维度：

1. **规则优先级顺序**：谁覆盖谁、谁先谁后。  
2. **匹配条件集合**：每条腿各自如何命中（不同对象空间，不要求字段对等）。  
3. **规则组**：如何复用/组织规则集合（用户视角同构；后端实现允许不同）。  

### 2.1 规则优先级顺序（统一用户模型）

#### 2.1.1 共通原则

- **P1（scope）**：更窄的 scope 覆盖更宽的 scope。用户首先按 `per-app` / `device-wide` / `fallback` 来理解“谁赢”。  
- **P2（gate/template）**：gate 与 template 不参与仲裁：  
  - gate（`BLOCK/IPRULES/BLOCKIPLEAKS/CUSTOMLIST.ON` 等）决定某条路径是否参与或是否产生最终效果；  
  - template（`BLOCKMASKDEF/BLOCKIFACEDEF`）只影响新建 app 初始值，不应被解读成“设备级 live policy”。  
- **P3（确定性）**：如果某个 scope 内允许多条规则同时命中，必须保证“胜出规则”确定。  
  - 对 IP 规则：使用 `priority`（或等价确定性规则）决胜。  
  - 对配置展开引入的歧义：应在 apply 阶段拒绝（见 2.3.3）。  

#### 2.1.2 DomainPolicy（域名腿）

用户应按下面顺序理解 DomainPolicy 的生效层级（高 → 低）：

1. **per-app domain custom**（app 自定义域名名单/规则）  
2. **device-wide domain custom（domain-only）**（设备级域名自定义名单/规则）  
3. **fallback：mask 交叉层**（`app.blockMask & domain.blockMask`）  

关键 gate/template 语义（用户理解口径）：

- `CUSTOMLIST.OFF`：跳过 1/2，直接走 3。  
- `BLOCKMASKDEF`：只是新 app 的默认模板，不是 device-wide 的 domain policy。  

补充说明：

- DomainPolicy 的 verdict 是**域名语义判决/观测**；它常用于 DNS 侧观测。packet 侧存在 legacy bridge（DNS-learned Domain↔IP 映射）；本轮 fusion 已裁决：**保留映射但仅用于 observability/可读性**（例如 PKTSTREAM 的可选 `domain/host` 字段），最终 packet verdict/reasonId **不依赖** DomainPolicy；并把 DomainPolicy 判决从 packet 热路径里移出（仅在需要时计算，如 `tracked==true` 的观测路径），见 3.6/4.3。  

#### 2.1.3 packet policy / IPRULES（IP 腿）

用户应按下面顺序理解“最终传输 verdict（packet verdict）”的优先级（高 → 低）：

1. **`IFACE_BLOCK`（per-app packet hard gate）**：命中即 drop  
2. **`IPRULES`（per-UID IPv4 L3/L4）**：若启用且命中，按引擎决策 allow/block  
3. **默认允许（`ALLOW_DEFAULT`）**：未命中前述规则时（本轮 fusion 不把 legacy bridge / `BLOCKIPLEAKS` 纳入统一仲裁模型）  

关键 gate/template 语义（用户理解口径）：

- `BLOCK=0`：整体不产生最终 blocking 行为（packet verdict 直通）；但系统可能仍做最小映射/观测（以各自指标契约为准）。  
- `IPRULES=0`：IPRULES 不参与；不应被误读为“清空规则”。  
- `BLOCKIFACEDEF`：只是新 app 的默认模板，不是 device-wide 的 iface policy。  

补充说明：

- 当前目标状态仍**不引入 device-wide IP rules**（保持 IP 腿的 scope 边界清晰；规则复用通过“规则组（配置层）”完成，见 2.3）。  
- `BLOCKIPLEAKS` / `ip-leak` 与 legacy bridge 属于历史模块：本轮 fusion **冻结并强制关闭（无作用）**（见 3.6）；未来若要重新启用或彻底移除，必须另开 change（不在本轮 fusion 讨论）。  

### 2.2 匹配条件集合（两条腿不强行对齐）

统一点：两条腿都可以被同一套“优先级模型/规则组模型”包装；但它们匹配的对象不同，条件字段天然不对等。

#### 2.2.1 DomainPolicy 的匹配条件集合（域名对象空间）

- 输入对象：`(uid/app, domain)`  
- 条件集合（示例）：  
  - 精确域名 / 后缀（子域）  
  - 通配符 / 正则（取决于规则类型）  
  - 来自 blocking lists 的 `domain.blockMask`（由已导入的 domain lists 聚合得出）  

#### 2.2.2 IPRULES 的匹配条件集合（包/五元组对象空间）

- 输入对象：`(uid/app, packet-key)`  
- 条件集合（示例）：  
  - `dir`（in/out）  
  - `iface` / `ifindex`  
  - `proto`（tcp/udp/icmp/any）  
  - `src/dst IPv4 CIDR`  
  - `sport/dport`（TCP/UDP）  
  - `ct.state/ct.direction`（若启用 conntrack 维度）  

> 备注：`uid` 更准确地说是“ruleset 选择 scope”，不是 rule 的 match 字段；但对用户来说它仍是 per-app 生效边界的一部分。

### 2.3 规则组（配置复用的统一心智；后端实现允许不同）

#### 2.3.1 用户视角（统一）

用户应能用同一套方式理解两条腿的“规则组”：

- 规则组是为了**复用/组织**规则集合；可被多个 app 引用。  
- 每个 app 仍可以叠加自己的“本地规则”（scope 更窄，优先级更高）。  
- 对用户来说，Domain 规则组与 IP 规则组都只是“可复用的规则集合”；不需要理解后端如何存储。  

#### 2.3.2 Domain 侧规则组（后端原生能力）

- device-wide domain custom 本质上就是“被所有 app 引用的一组规则/名单”。  
- per-app domain custom 是“仅该 app 引用的一组规则/名单”。  
- blocking lists（标准/强化）则是另一类“可复用规则源”，其落地结果是 `domain.blockMask`。  

#### 2.3.3 IP 侧规则组（路线 A：配置展开；已确认决议）

IP 侧的“规则组”**只存在于配置层**（前端/配置生成器），后端不引入 group/profile 的持久化概念。落地规则如下：

- app 引用多个 IP 规则组时，最终都会展开成同一份 `<uid>` 的 `IPRULES` 规则集。  
- **允许去重**：完全相同的规则允许合并/去重。  
- **冲突拒绝 apply（已确认）**：同一 `<uid>` 的 apply payload 内，**匹配条件集合（`matchKey`）不允许重复**；一旦重复必须拒绝 apply（不进入运行期仲裁）。  
  - 目标：避免“同一匹配集合存在多条规则”的隐式仲裁/归因歧义（action/priority/enforce/log 乃至来源 token 不一致都会导致不可解释）。  
- 原子 apply（路线 1，强一致）、`matchKey/clientRuleId` 与冲突错误契约：见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`。

统计口径（同一决议的后半句）：

- 暂时只承诺 **per-app（UID）级别** stats/metrics；不承诺规则组级统计。  

### 2.4 可观测性（fusion 后的统一解释模型）

目标：当用户问“为什么这个请求被拦/放过？”时，两条腿给出的解释在结构上是同构的，且不会互相打架。

- **DNS 侧（DomainPolicy）**：以 `policySource` 为核心解释字段，配套 `METRICS.GET(name=domainSources)`（以及 `METRICS.RESET(name=domainSources)`）。  
- **packet 侧（最终传输 verdict）**：以 `reasonId` +（可选）`ruleId/wouldRuleId` 为核心解释字段，配套 `METRICS.GET(name=reasons)`、`IPRULES.PRINT stats`、`PKTSTREAM`。  
- **跨层一致性**：当 DNS verdict 与 packet verdict 不一致时（例如 `IFACE_BLOCK` 遮蔽了后续路径），对外解释必须明确“哪个是最终传输裁决、哪个只是语义观测”。  
- **调试事件（stream）**：`DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM` 属于“调试期开、短期开”（入口统一为 `STREAM.START(type=dns|pkt|activity)`），在开启时应尽量做到“单条事件可自解释”，不依赖额外查询/二次拼接。
  - stream vNext 统一增加事件 envelope：顶层字段 `type`（`dns|pkt|activity|notice`），并支持 `type="notice"` 的 suppressed 汇总事件（按秒聚合、仅实时，不持久化/不参与 horizon 回放；suppressed 仅对 dns/pkt 有意义）。详见 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`。
  - `DNSSTREAM` 应补齐 `policySource/useCustomList/scope` 三个字段（其中 `scope` 可由 `policySource` 派生；命名见下）。
  - `PKTSTREAM` 也应输出 `scope`（同一组取值：`APP|DEVICE_WIDE|FALLBACK`），用于解释 packet verdict 的“来源宽度”：
    - `IFACE_BLOCK` → `APP`
    - `IP_RULE_*` → `APP|DEVICE_WIDE`（取决于命中规则来源；未来支持 `IPRULES.GLOBAL.*` 时区分）
    - `ALLOW_DEFAULT` 等“无明确规则命中”的路径可以不输出 `scope`
  - `PKTSTREAM` 的接口维度建议输出 `ifindex`（唯一标识）与 `ifaceKindBit`（WiFi/Data/VPN/Unmanaged），`interface(name)` 仅作可读性补充（不得作为唯一标识）。
  - `domain`（可选）：来自 DNS‑learned Domain↔IP bridge 的 best‑effort 域名；仅用于可读性/排障（不得作为唯一标识或仲裁依据）。
    - 仅当 bridge 命中且 `domain.validIP()==true` 时输出（避免陈旧映射误导）。
  - `host`（可选）：来自 reverse‑dns 的 best‑effort host name；仅用于可读性/排障（不得作为唯一标识或仲裁依据）。
  - `ACTIVITYSTREAM`：
    - 用于“当前 top app/是否启用 BLOCK”等状态提示；事件 envelope 使用 `type="activity"`。
    - 最小字段建议：`type/blockEnabled`；可选附带 `uid/userId/app`（与其它事件回显风格一致）。
  - `policySource` 为 coarse attribution（不做 per-rule/listId 归因），但必须与 `METRICS.GET(name=domainSources)` 的枚举与优先级严格一致。
    - `policySource` 对外枚举（vNext；统一 allowed/blocked 口径）：`CUSTOM_LIST_ALLOWED/BLOCKED`、`CUSTOM_RULE_ALLOWED/BLOCKED`、`DOMAIN_DEVICE_WIDE_ALLOWED/BLOCKED`、`MASK_FALLBACK`（不做 alias/双写）。
  - `useCustomList` 必须在事件里显式输出，用于消除 `policySource=MASK_FALLBACK` 的歧义（`CUSTOMLIST.OFF` vs custom 分支未命中）。
  - `scope`（统一心智模型；跨 DNS/packet 通用宽度）：`APP` / `DEVICE_WIDE` / `FALLBACK`。
    - 派生规则：`CUSTOM_LIST_*`/`CUSTOM_RULE_*` → `APP`；`DOMAIN_DEVICE_WIDE_*`（domain-only device-wide；当前代码仍名为 `GLOBAL_*`）→ `DEVICE_WIDE`；`MASK_FALLBACK` → `FALLBACK`。
  - `getips` 必须在事件里显式输出：它是 DNS 判决链路的重要分岔（是否进入 IP 映射读回/写回路径），是排障“DNS verdict 正确但后续包未绑定域名”的关键线索。
    - 本轮已裁决冻结 `GETBLACKIPS/MAXAGEIP`（见 3.6）：强制 `GETBLACKIPS=0`，因此 `getips` 在 vNext 语义下等价于 `verdict`（`blocked=true` 时固定 `getips=false`）。
  - **回溯原则（DNSSTREAM）**：事件字段必须是“判决时快照”，避免打印时读取导致漂移；至少应快照 `policySource/useCustomList/scope/getips/domMask/appMask`。

### 2.5 控制面（control plane）与文档口径

目标：控制面命令与 HELP/接口文档能直接表达第 2 节的统一心智模型，避免“名字像全局、实际不是全局”的误导。

- 禁止在对外文档中使用裸 `global`；必须写清层名：`device-wide DomainPolicy ...` / `per-app (UID-scoped) ...` / `packet policy ...`。  
- `policySource` / `METRICS.GET(name=domainSources)` 对外枚举统一收敛为 `ALLOWED/BLOCKED` 叙事（禁止 white/black/global；不做 alias/双写）：
  - `CUSTOM_LIST_ALLOWED` / `CUSTOM_LIST_BLOCKED`
  - `CUSTOM_RULE_ALLOWED` / `CUSTOM_RULE_BLOCKED`
  - `DOMAIN_DEVICE_WIDE_ALLOWED` / `DOMAIN_DEVICE_WIDE_BLOCKED`（domain-only device-wide；当前代码仍名为 `GLOBAL_*`）
  - `MASK_FALLBACK`
- IP 规则组是配置概念：后端控制面仍以 `uid`（per‑UID）的 `IPRULES.*` 为准；规则组冲突/去重在 apply 语义中体现（2.3.3）。  
- 接口字段/枚举命名风格（已确认）：
  - JSON keys：统一 `camelCase`（例如 `userId/reasonId/policySource/ifaceKindBit/droppedEvents`）。
  - enum values：
    - “分类/归因”类：`scope/policySource/reasonId/error.code` 使用大写（如 `APP/IFACE_BLOCK/SELECTOR_AMBIGUOUS`）。
    - “事件 envelope”类：`type/notice` 使用小写（如 `dns|pkt|activity|notice`、`suppressed|dropped`）。
    - metrics 维度 key：保持小写（如 `dns/rxp/rxb/txp/txb`）。
- app selector（多用户语义；已确认）：
  - vNext 使用结构化 selector（见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`）：
    - `{"uid":10123}` 或 `{"pkg":"com.example","userId":0}`
    - 二选一：要么提供 `uid`，要么提供 `pkg+userId`；禁止混用。
  - 本文中 `per-app` **等价于 per-UID**（uid-scoped app instance）：同一 package 在不同 userId 下视为不同 app（分别统计/分别 state/分别规则）。
  - `uid` 本身已包含 userId（`uid/100000`），因此 `{"uid":...}` 跨用户唯一。
  - `pkg` **仅匹配 canonical `app`**（即对外回显的 `app` 字段）；`allNames` 仅用于输出展示/列表，不参与 selector resolve（2.19）。
  - 解析策略（严格拒绝）：
    - selector 无法唯一 resolve（不存在/歧义/userId 不存在）→ **一律拒绝**；不做 best-effort，不做隐式创建/占位。
    - 本轮先锁“拒绝策略”；边界异常在测试暴露后再补齐（但不得引入 silent 选错）。
  - 输出回显（强制；用于快速回溯）：凡是 app 相关 JSON 输出，必须回显 `uid/userId/app(canonical pkg)`。
    - 可选回显 `matchedName`（原输入）以便解释；但主展示/主键仍是 canonical `app`。
  - 错误形态（必须可修复；已确认）：
    - vNext response 统一 envelope：`{"id":...,"ok":true,"result":...}` / `{"id":...,"ok":true}` / `{"id":...,"ok":false,"error":{...}}`（见 `CONTROL_PROTOCOL_VNEXT.md`）。
    - `error` 最小字段：`code`（string enum）+ `message`；可选 `hint`、`candidates`、`matchedName` 与结构化详情（如 `conflicts[]`）。
    - `candidates[]` item（歧义时优先返回，可直接用 `{"uid":...}` selector）：`{uid, userId, app}`（其中 `app` 为 canonical pkg），并且 **按 `uid` 升序排序**（2.19）。
    - v1 `code`（允许未来新增，不得改名/删值）：
      - 通用：`SYNTAX_ERROR` / `MISSING_ARGUMENT` / `INVALID_ARGUMENT` / `UNSUPPORTED_COMMAND`
      - selector：`SELECTOR_NOT_FOUND` / `SELECTOR_AMBIGUOUS`
      - 状态：`STATE_CONFLICT`
      - 权限：`PERMISSION_DENIED`
      - 兜底：`INTERNAL_ERROR`
    - `INVALID_ARGUMENT` 在冲突类场景下允许携带结构化详情字段（例如 `conflicts[]`），用于前端定位问题；该 shape 的权威约定见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`。
  - 不提供 userId 级批量能力：不新增“对某个 userId 下所有 app 批量 track/reset/apply”的命令；需要批量由前端枚举并逐个调用（可观测、可回滚）。
  - 允许 userId 过滤（无 app selector）：采用白名单策略（2.20）：
    - 仅允许在明确标注支持的 device-wide list/stats 命令上作为可选 `args.userId`；
    - 其它命令若出现 `args.userId` 一律报错（`SYNTAX_ERROR`），禁止 silent ignore。
  - dual-form 命令（device-wide vs app-specific）消歧（D16；vNext 不背兼容包袱）：
    - 适用命令族：`BLACKLIST.* / WHITELIST.* / BLACKRULES.* / WHITERULES.*`
    - vNext 规则：通过 `args.selector` 是否存在显式区分（存在 = per-app；缺失 = device-wide）；不做 token 推断与缺参回退。

### 2.6 state / counters / lifecycle（统一边界）

目标：用户能区分“规则状态”“统计状态”“观测状态”，并能预期 reset/save/restore 的边界。

- 明确哪些是 since-boot，哪些持久化，哪些属于规则生命周期内有效。  
- 明确 `RESETALL` 与 layer-specific reset 的边界：DomainPolicy counters、packet reason counters、perf metrics、per-rule stats 的 reset 语义一致且可解释。  

### 2.7 测试与验收（fusion 后的基线）

目标：产出一套可反复运行的基线，后续任何大改都能完整重跑，用于评估 bug 与性能回归。

- host-side：引擎/解析/确定性单测（不替代真机验收）。  
- host-driven integration：控制面下发 + 事件流/metrics 验证。  
- device（Tier‑1 受控拓扑）：以稳定可复现的受控环境覆盖关键矩阵（DomainPolicy/IFACE_BLOCK/IPRULES/overlay + 并发/reset）。  
- fusion 阶段每个 change 的最低 gate（已确认；阶段定义见 `docs/IMPLEMENTATION_ROADMAP.md`）：
  - 默认必须跑：P0（host 单测）+ P1（host-driven integration）
  - 若 change 触及不可退化契约（hot path/stream/reset/apply/输出协议/多用户语义等），必须追加：P2（device Tier‑1）
  - P3（真机原生调试）仅用于问题定位，不作为 gate

### 2.8 性能与并发承诺（红线）

目标：fusion 不得把“可选成本”变成“每包必经成本”，并避免引入新的并发判决窗口不一致。

- 本轮收敛结论（ACA）：
  - **A：锁内只做纯判决**（NFQUEUE hot path / `mutexListeners` shared lock）  
    - 只允许：纯判决、固定维度 atomic counters、**有界 enqueue**（后续异步处理）  
    - 禁止：任何磁盘/网络 I/O、socket write、大 JSON 构造/pretty-format、无界分配、长时持锁  
  - **C：stream I/O 必须异步化**  
    - hot path 只 enqueue；由独立 writer 线程（或等价机制）写 socket  
    - 出现反压时允许 drop；必须通过 `type="notice"` 显式提示“事件被丢弃/反压中”（不新增独立 metrics；最小字段：`notice="dropped"` + `droppedEvents`）  
    - 目标：stream 不得影响 verdict latency，也不得阻塞 `RESETALL`（独占锁路径）  
  - **A：gate 必须是真 gate**  
    - `tracked` 是逐条事件的 gate：未 `tracked` 的 app 不构造逐条事件/不入 ring（无论是否订阅 stream）。  
    - stream 订阅只控制“是否输出到 socket”：无订阅者时仍允许对 tracked app 维护进程内 ring（用于 `*.START horizon/minSize` 回放），但不得做 socket I/O。  
    - app 未 `tracked` 时：不输出逐条事件；按 stream vNext 的 suppressed NOTICE 定位（见 observability working decisions）  
- `PacketListener phase-1/phase-2` 的边界必须保持：锁内只做纯判决与轻量计数；任何解析、I/O、重构造都必须锁外完成。  
- 控制面更新与流量并发时，对外承诺必须明确（严格/最终一致/best-effort），避免接口语义含糊。  

---

## 3. 实现拆分与落地顺序（从现状到目标）

本节回答“要改哪些东西，大概改成什么样”。建议按影响面拆分，避免把命名清理、语义变更、观测统一、结构重构混成一个大 change。

### 3.1 命名与文档收敛（低风险；先做）

- 将对外文档/HELP 中的裸 `global` 全部替换为带层名表述。  
- 将域名侧 `policySource` 对外枚举统一改名为 `ALLOWED/BLOCKED` 叙事（**不做 alias/双写**：当前未发正式版，不承担向后兼容包袱）：
  - `CUSTOM_WHITELIST` → `CUSTOM_LIST_ALLOWED`
  - `CUSTOM_BLACKLIST` → `CUSTOM_LIST_BLOCKED`
  - `CUSTOM_RULE_WHITE` → `CUSTOM_RULE_ALLOWED`
  - `CUSTOM_RULE_BLACK` → `CUSTOM_RULE_BLOCKED`
  - `GLOBAL_AUTHORIZED` → `DOMAIN_DEVICE_WIDE_ALLOWED`（domain-only device-wide）
  - `GLOBAL_BLOCKED` → `DOMAIN_DEVICE_WIDE_BLOCKED`（domain-only device-wide）
- 对齐 `docs/IMPLEMENTATION_ROADMAP.md`、`openspec/project.md`、各 `docs/decisions/*`：确保“现状/目标/已落地能力”不互相打架。  

### 3.2 IP 规则组“配置展开”语义补齐（确定性；可能涉及后端约束）

- 明确并实现 2.3.3 的 apply 语义：  
  - 完全相同规则可去重；  
  - 同一 `<uid>` 的 apply payload 内 `matchKey` 不允许重复；一旦重复必须拒绝 apply（必须有清晰错误原因，便于前端定位冲突来源）。  
- 统计先维持 per-app；不引入 group-level stats。  
- 原子 apply（路线 1）与前后端约定（`matchKey/clientRuleId`、冲突错误 shape、`IPRULES.PRINT` 回显）：见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`。

### 3.3 可观测性对齐（跨层解释）

- 固化一套对外解释结构：最终传输裁决（packet）与语义观测（DNS）如何同时呈现。  
- 对齐 `policySource` / `reasonId` / `ruleId` / `wouldRuleId` 的叙事：哪些是最终裁决依据、哪些只是来源/候选信息。  
- dns stream vNext（入口：`STREAM.START(type=dns)`）：补齐 `policySource/useCustomList/scope` + “判决时快照”字段口径；允许升级时丢弃历史 `dnsstream` 缓存文件（调试型产物不做严格兼容）。  
- stream pipeline 重构（见 2.8）：hot path / `mutexListeners` 锁内只做有界 enqueue；由独立 writer 线程异步写 socket；反压允许 drop，且必须通过 `type="notice"` 可定位。  
- 落地 task list：见 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_IMPLEMENTATION_TASKS.md`（含 metrics name=`traffic`/`conntrack`（`METRICS.GET`/`METRICS.RESET` 入口统一）、stream vNext、reset/selector/测试与推荐切片）。  

### 3.4 控制面与生命周期（reset/save/restore）

本节把“什么状态会跨重启/跨 reset 保留”说清楚，避免出现：
1) 前端看到的 counters 与 stream 不一致  
2) reset 之后仍然被旧状态污染  
3) 为了省事把 debug 开关做成常驻开销

#### 3.4.1 状态分类（用户可理解）

- **Policy 状态（规则与开关）**：决定 allow/drop，本质上是“配置”；允许持久化（save/restore）。
- **Observability config（观测配置）**：只影响“输出/统计是否产生”，不改变 verdict；其中 per-app `tracked` 需要持久化（D8），且前端需提示潜在性能影响。
- **Observability session state（观测会话态）**：stream 连接/ring/queue/horizon 回放缓存等；不落盘，重启归零。
- **Counters/Metrics（轻量）**：since-boot（进程内）；可 reset；不要求持久化。
- **Heavy stats（重型历史 stats）**：只在 `tracked=1` 时更新；是否持久化属于实现细节，但必须被 `RESETALL` 清空。

#### 3.4.2 `tracked` 的生命周期（已确认）

- 默认值：`tracked=false`（全新启动/RESETALL 后）。
- 后端 `tracked` **持久化**：daemon 重启后保持原值（D8）。
- 前端 UX 要求（D8）：用户显式开启 `tracked` 时必须提示“可能带来性能影响”（tracked 语义已覆盖更重的观测/统计维度，例如延迟相关统计）。
- `tracked` gating：
  - gate：`DNSSTREAM/PKTSTREAM` 逐条事件 + heavy stats
  - 不 gate：轻量 always-on counters（`METRICS.GET(name=reasons)` / `METRICS.GET(name=domainSources)` / `METRICS.GET(name=traffic)` / `METRICS.GET(name=conntrack)` 等）

#### 3.4.3 Streams（DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM）生命周期（已确认）

- 不做兼容：stream 是调试通道；允许升级时丢弃历史缓存文件。
- `type="notice"`（`notice="suppressed"|"dropped"|"started"`）只实时，不进入 ring，不参与 horizon，不落盘（suppressed/dropped 仅对 dns/pkt 有意义）。
- 线协议（vNext；为可靠解析与避免输出交织）：
  - framing 采用 netstring（见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`）：每条 response/event 都是一个 netstring frame，payload 为 UTF‑8 JSON object；不发送 NUL terminator。
    - 严格 JSON（2.10）：所有字符串字段必须正确 escape（至少处理 `\" \\ \n \r \t`；vNext 必须引入统一 JSON string encoder）。
  - stream events 与 control response 共享同一 framing，但 event 不得包含 `id/ok`（避免与 response 混淆）。
  - `*.STOP` 的 response frame 作为 ack barrier：成功为 `{"id":...,"ok":true}`；失败为 `{"id":...,"ok":false,"error":{...}}`（与错误模型一致）。
  - 进入 stream 模式后，禁止在同一连接上执行非 stream 控制命令（避免输出交织与心智分裂）；如需查询/配置请另开控制连接。
  - control 协议 vNext（除 streams 外的所有命令 framing/响应/错误约定）：见 `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`。
- `STREAM.STOP`：
  - 返回 response frame；停止该连接的 stream session；并清理该连接 pending queue（若有）。
  - **ack barrier（已确认；2.9-B）**：STOP 必须先禁用订阅并清空 pending queue（允许丢弃尾部未发送事件/notice），再输出该 STOP 的 response frame（`{"id":...,"ok":true}`）；该 response 必须是该 STOP 的最后一个输出 frame，ack 后不得再输出任何事件/notice，直到下一次 `STREAM.START`。
  - 若当前 type 为 `dns|pkt`：清空 ring buffer；下次 `STREAM.START` 视为全新 session。
- `STREAM.START(type=dns|pkt)`（回放参数；不影响已有流）：
  - request `args`：`horizonSec/minSize`（int；默认 `0/0` 表示不回放，只看实时）
  - 参数仅影响“本次连接启动时的回放（replay）”，不得改变 ring 的保留策略，也不得影响其它 stream 类型（dns/pkt/activity 之间互不影响）。
  - **单连接约束（已确认；2.8-A）**：同一时间每种 stream 只允许 1 条连接订阅；已有连接存在时，新的 `*.START` 返回 `STATE_CONFLICT`。
  - **连接拓扑（已确认；2.27-A）**：同一条 stream 连接同一时间只允许订阅一种 streamType；需要同时看 dns+pkt+activity 时，前端使用多条连接（每种 streamType 一条）。
  - 同一连接重复 `*.START`：报 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - `*.START` 成功：先返回 response frame（`{"id":...,"ok":true}`），并且必须先输出一次 `type="notice", notice="started"`（至少一条，避免“无流量=无反馈”；不进入 ring、不参与 horizon、不落盘），然后才开始回放（若有）与实时事件输出。
  - `*.STOP`：返回 response frame（`{"id":...,"ok":true}`），并且 **幂等**（未 started 时也返回 `{"id":...,"ok":true}`）。
  - 回放选择规则（已确认；v1）：
    - 回放集合 = “时间窗内事件” ∪ “最近 `minSize` 条事件”（两者取并集）。
    - `horizonSec=0` 时仅按 `minSize` 回放；`0/0` 表示不回放。
    - 若请求超出 ring 现存范围：尽力回放（最多回放 ring 中现存事件），不报错。
- `STREAM.START(type=activity)`（无回放；不影响已有流）：
  - request：`cmd="STREAM.START"`，`args={"type":"activity"}`
  - 同一连接重复 `STREAM.START`：报 `STATE_CONFLICT`（严格拒绝；不影响已有流）。
  - 成功：先返回 response frame（`{"id":...,"ok":true}`），并且必须先输出一次 `type="notice", notice="started"`，并且至少应输出一次当前状态快照。
- `type="dns"` / `type="pkt"` / `type="activity"`：
  - dns/pkt：ring buffer 对 **已 tracked 的 app** 持续维护（与是否订阅无关）；未 tracked 不入 ring（用于 `*.START horizon/minSize` 回放；不落盘）。
  - activity：不做 ring/horizon（仅实时状态提示；是否保留 ring 取决于实现阶段的成本评估）。
- 性能红线（见 2.8）：逐条事件不得在 `mutexListeners` 锁内同步写 socket；锁内只允许有界 enqueue；由独立 writer 线程（或等价机制）完成序列化与写 socket；反压允许 drop，并通过 `type="notice"` 可定位。
- `notice="dropped"` 口径（已确认；2.12-A）：pending queue/ring 满时 drop-oldest；`droppedEvents` 按“被丢弃的逐条事件条数”（不按 bytes）；最多 1 条/秒/streamType，并输出实际 `windowMs`。
- **有界 cap（已确认；2.31-A）**：ring 与 pending queue 必须有明确的事件条数上限（不锁具体数值但必须存在且可验证）；`STREAM.START(type=dns|pkt,horizonSec/minSize)` 必须 clamp 到能力上限，并在 `notice="started"` 中 echo 实际生效值（避免前端误解）。
- `RESETALL` 必须强制停止并断开所有 stream 连接（按 2.8-A：stream 订阅单连接约束；control 连接可并发），并清空 ring buffer/queue；同时删除历史遗留的落盘 stream 文件（若仍存在）。

#### 3.4.4 reset 语义（边界必须锁死）

- `RESETALL`：清空**所有**可观测性相关状态
  - 轻量 counters：`METRICS.GET(name=reasons|domainSources|perf|traffic|conntrack)` + `IPRULES` per-rule stats
  - 观测开关：`tracked=false`
  - streams：强制 stop 并断开连接；清空 ring buffer/queue（dns/pkt），并清理 activity stream 会话态
  - 以及既有：清空 settings/规则/列表/域名/统计并持久化（以 `RESETALL` 的既有契约为准）
- layer-specific reset（例如 `METRICS.RESET(name=domainSources)`）：
  - 只清其对应 counters，不应修改任何 policy 开关、tracked 或 stream 状态。

#### 3.4.5 开关关闭→再开启（清零/保留规则）

- `BLOCK=0`：dataplane bypass；metrics/counters 不更新（与现状一致）。
- `IPRULES 0→1`：不清零规则集合；per-rule stats 的清零规则按 IPRULES 既有契约执行（UPDATE/ENABLE 时清零）。
- `PERFMETRICS 0→1`：自动清零 perf 聚合；其余幂等不清零（保持既有契约）。

#### 3.4.6 save/restore（policy）持久化 key（多用户；已确认）

- `per-app` 的 policy（规则/开关）持久化 key 以 `pkg+userId` 为准；`uid` 仅作为运行时 resolve 结果（可选作为 hint/审计字段，但不得作为主键）。
- 持久化版本化（已确认）：
  - 落盘 payload 必须包含 `schemaVersion`（数字）；不认识的版本不得尝试 restore（避免读错导致 silent corruption），应以可定位错误记录/上报，并保持基线不变。
- restore（已确认；v1）：
  - **逐条 restore**：单条失败不影响其它条目；失败条目保持默认/原值，并返回/记录可定位的错误信息（汇总错误列表）。
  - orphan policy（`pkg+userId` 当前不存在/已卸载）：**直接清理该条持久化记录**（不允许出现“policy 存在但 app 不存在”的悬挂状态）。
  - 仍禁止隐式创建/占位 app：restore 不得触发创建匿名 app 或写入新的 app 状态。

### 3.5 测试补齐（以真机闭环为最终验收；本阶段仅 IP 线）

测试目标不是“模拟真实网络”，而是保证：
1) 优先级/仲裁确定性  
2) reset/重启边界不含糊  
3) 观测输出可回溯且口径一致  
4) 真机上能跑通闭环（最终验收）

每个 change 的最低 gate（已确认；阶段定义见 `docs/IMPLEMENTATION_ROADMAP.md`）：

- 默认必须跑：P0（host 单测）+ P1（host-driven integration）
- 若 change 触及不可退化契约（例如 hot path/stream/reset/save-restore/apply/输出协议/多用户语义），必须追加：P2（device Tier‑1）
- P3（真机原生调试）仅用于问题定位，不作为 gate

不可退化契约（已确认；只要 change 触及则必须有对应测试/验收点）：

1) 原子 apply（路线 1，强一致）：失败不改变现状；成功后新基线立即可见  
2) `matchKey` 规范化与冲突拒绝：错误为 `INVALID_ARGUMENT` 且携带 `conflicts[]`（见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`）  
3) `clientRuleId` 贯穿：apply/print/error 一致回显（见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`）  
4) stream vNext：netstring framing + 严格 JSON、START/STOP/RESETALL/`STATE_CONFLICT` 语义、STOP ack barrier、禁止输出交织（见 observability working decisions）  
5) reset/save/restore 边界：`RESETALL` 必须回到干净基线；layer reset 不得污染其它层（见 3.4）  
6) 多用户语义：`per-app == per-UID`、selector 严格拒绝 + 强制回显（见 2.5）  

范围约束（当前阶段锁死）：
- 域名侧“真机正确性测试”（真实 resolver / netd / DnsListener 链路）目前需要额外系统/PO 壳准备，尚未就绪；因此本阶段**不做域名真机测试**。
- 域名侧只保留既有 host/unit 与 host-driven integration（不新增、不作为 gate）；本阶段验收以 **IP 线 Tier‑1 真机闭环** 为准。

#### 3.5.1 host 单测（优先覆盖确定性与边界）

- DomainPolicy：
  - `DomainPolicySource` 枚举/顺序/快照稳定（sources keys 固定 7 个）（本阶段只做命名收敛见 3.1，不扩写、不作为 gate）
- IPRULES：
  - 原子 apply：失败不改变现状；成功后新基线立即可见（路线 1）
  - `matchKey` 规范化：CIDR 网络地址归一化、`ifindex=0` 视为 any、`proto=icmp` 端口约束等（见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`）
  - apply 冲突拒绝：同一 `<uid>` apply payload 内 `matchKey` 不允许重复；错误为 `INVALID_ARGUMENT + conflicts[]`（见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`）
  - `clientRuleId`：格式/唯一性校验与贯穿回显（见 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`）
  - per-rule stats 清零边界（UPDATE/ENABLE）
- Reset 边界（最小集合）：
  - `RESETALL` 会清空：reasons/domain-sources/perf/iprules-stats（以及未来 traffic/conntrack），并回到干净基线（不遗留旧 stream/ring/pending 状态污染下一次开启）

#### 3.5.2 integration（控制面下发 + 结构断言）

- metrics shape：`METRICS.GET(name=reasons)` / `METRICS.GET(name=domainSources)` / `METRICS.GET(name=traffic)` / `METRICS.GET(name=conntrack)` / `METRICS.GET(name=perf)`
- gating：`BLOCK=0` 下 counters 不更新
- 多用户 selector：严格拒绝与强制回显（见 2.5）
- stream schema vNext：
  - `DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM` 事件能被可靠解析（`type` + 最小字段集合）
  - netstring framing + 严格 JSON（见 `CONTROL_PROTOCOL_VNEXT.md`）：`STREAM.STOP` response 作为 ack barrier、禁止输出交织
  - suppressed notice（`type="notice"`) 的限频与 hint 文案（只需结构稳定，具体文案可后置）

#### 3.5.3 device Tier‑1（Pixel6a 真机闭环；最终验收）

- 最小闭环（IP 线；本阶段最终验收）：
  - app 下发配置 → 触发 packet（Tier‑1：netns+veth）→ 前端用 stream + metrics 能解释“为何 allow/drop”
  - 推荐入口：`docs/testing/ip/IP_TEST_MODULE.md`、`docs/testing/IPRULES_DEVICE_VERIFICATION.md`、`docs/testing/ip/CONNTRACK_CT_TIER1_VERIFICATION.md`
- 域名侧（DomainPolicy/DNS）：
  - 真机正确性测试 deferred（系统/PO 壳准备未就绪）；只保留既有 host/unit 与 host-driven integration，不新增、不作为 gate
- 并发窗口：
  - 流量进行中触发 `RESETALL`/更新规则/切换开关，保证不会死锁、不会出现明显不可解释状态
- 回归基线：
  - 同一套脚本/命令序列可重复跑出一致的结构结果（数值允许波动，但口径/shape 必须一致）
- 性能/反压 gate（只锁原则，不锁阈值；阈值与基线对比在 P2/perf 环节收敛）：
  - 慢消费者/反压不得拖死 hot path；允许 drop，但必须通过 `type="notice"` 可定位（见 observability working decisions）

### 3.6 延后项（明确不夹带进本轮 fusion）

- `BLOCKIPLEAKS` / `ip-leak`：本轮 **强制保持关闭并冻结不动（无作用）**；vNext 不提供开启/关闭接口；不改语义/优先级/接口口径。  
- `legacy domain path` / DNS‑learned Domain↔IP bridge：本轮裁决为“保留映射但降级为 observability/可读性”；packet verdict/reasonId 不依赖 DomainPolicy；实现上需把 DomainPolicy 判决从 packet 热路径移出（仅在需要时计算，如 `tracked==true`）。
  - 同期收敛：packet stats 不再做 domain/color 归因（先冻结该行为、不要求删代码；等其它能力稳定后再专题讨论颜色相关语义）。  
- 同上：`GETBLACKIPS/MAXAGEIP` 视为 legacy 链条一部分，**全部冻结**：
  - 强制 `GETBLACKIPS=0`（必须覆盖/忽略历史落盘值与 legacy 控制面设置，确保 `getips == verdict` 恒成立）
  - `MAXAGEIP` 固定为默认值（当前代码默认 `4h`），但不对外作为可调能力；vNext 不提供接口/HELP 不展示。  
- device-wide IP rules：除非出现明确产品需求与性能预算，否则保持不引入。  
- IPv6、域名 per-rule stats、更多 L4/L7 维度：按各自主线单独推进。  

---

## 4. 待继续讨论/收敛的章节（先占坑，避免遗漏）

> 注：第 2/3 节中已有部分“草案级”内容；本节用来明确接下来按章推进的讨论范围与落盘位置。  
> 本节 **按推荐讨论顺序编号**：`4.1 → 4.13` 即建议推进顺序。

### 4.1 延后项清单（明确不夹带，但要先锁边界）

- `ip-leak/BLOCKIPLEAKS`：本轮已锁死为“强制关闭且冻结无作用”。若未来要重新启用或彻底移除，必须另开 change（不在本轮 fusion 讨论）。
- `GETBLACKIPS/MAXAGEIP`：同属 legacy 链条，已锁死为“全部冻结”（强制 `GETBLACKIPS=0`；`MAXAGEIP` 不对外；vNext 不提供接口/HELP 不展示）。
- IPv6 新规则语义（与 IPRULES v1 的关系、默认行为、可观测性口径）。
- 域名规则 per-rule 级 observability / stats（regex/wildcard/listId 归因）及其对域名匹配结构的影响评估。
- “真实系统 resolver → netd socket → DnsListener” 平台闭环（真机 correctness gate 是否要回归；需要哪些系统/PO 壳准备）。
- 更强的 L4 stateful semantics（超出当前 `ct.state/ct.direction` 的扩展）与其热路径成本预算。
- L7/HTTP/HTTPS 识别是否进入产品主线（当前只作为可选方向评估，不预设承诺）。

### 4.2 命名与术语收敛（对外口径 + 内部枚举）

- 统一“全局/设备级/应用级”的术语与命名：禁止裸 `global`；明确 DomainPolicy 的 device-wide（domain-only）层命名（避免被误读为“全系统全局”）。
- 把 gate/template 的对外口径锁死并写进权威文档：`BLOCKMASKDEF/BLOCKIFACEDEF` 仅模板、`CUSTOMLIST.OFF` 的语义、`BLOCK/IPRULES/BLOCKIPLEAKS` 等开关的“是否参与判决/是否计数/是否输出”边界。
- 备注：`BLOCKIPLEAKS` 本轮已锁死为“强制关闭且冻结无作用”（见 3.6）；因此其边界在本轮等价于“不参与判决/不计数/不输出”。  
- 明确 “scope” 这组枚举在 DNS/packet 两条腿的统一取值与派生规则（`APP/DEVICE_WIDE/FALLBACK`），以及它是否进入 metrics/stream/interface spec。

### 4.3 融合仲裁与 legacy 路径（Domain↔IP map / ip-leak / fallback）

- `BLOCKIPLEAKS`（ip‑leak overlay）已锁死为“强制关闭且冻结无作用”（见 3.6/4.1）；本轮不再讨论其仲裁定位与解释口径。
- `GETBLACKIPS/MAXAGEIP` 已锁死为“全部冻结”（见 3.6/4.1）；`getips` 在 vNext 语义下等价于 `verdict`（见 2.4/3.6）。
- legacy domain path（DNS‑learned Domain↔IP bridge）定位已裁决：保留映射但仅用于 observability/可读性；packet verdict/reasonId 不依赖 DomainPolicy；实现上把 DomainPolicy 判决从 packet 热路径移出（仅在需要时计算，如 `tracked==true`），见 3.6。
- 仍需补齐：在 vNext 下，哪些观测路径“确实需要”读取 domain/host（以及缺失时如何解释）；以及如何确保这条路径不会让前端误解为“域名策略参与最终 packet 仲裁”。

### 4.4 热路径、锁与并发边界（性能红线落地）

- 结合第 2.8 的原则，把“哪些东西允许进 NFQUEUE 热路径 / 哪些必须 gating / 哪些必须固定维度原子计数”落到实现检查表。
- 需要额外明确：stream 写 socket 的反压风险，在融合改造中如何避免把 I/O 或大 JSON 构造塞进锁内关键段。

### 4.5 可观测性落地清单（从工作决策 → 实现任务）

- 把 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md` 中的 vNext 决策，提炼成“需要实现/需要改动/需要补测试/需要刷新接口文档”的 task list（见 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_IMPLEMENTATION_TASKS.md`）。
- 特别包括但不限于：`DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM` 的 `type` envelope、suppressed notice、`tracked` 统一语义、metrics name=`traffic`/`conntrack`（`METRICS.GET`/`METRICS.RESET` 入口统一）、以及与 `METRICS.GET(name=reasons)` / `METRICS.GET(name=domainSources)` 的跨层叙事对齐。

### 4.6 状态、持久化与 reset 边界（save/restore/versioning）

- 明确哪些属于 policy（应持久化），哪些属于 observability config（如 `tracked`，应持久化），哪些属于 observability session state（如 stream/ring/queue，不持久化），哪些属于 counters（since‑boot 可 reset）。
- 明确 stream 的 ring buffer / horizon / 落盘策略与升级策略（允许丢弃历史 debug 缓存的边界）。
- 明确 `RESETALL` 与 layer‑specific reset 的边界清单（必须清空哪些 counters/开关/stream 状态；哪些不得被误清）。

### 4.7 多用户与 selector 语义（uid/pkg/userId）

- 已收敛（不在本节重复）：selector JSON（`{"uid":...}` 或 `{"pkg":"...","userId":...}`）、歧义拒绝/严格拒绝策略/输出回显/错误提示/别名展示/不做批量/允许 `args.userId` 过滤（限明确支持的 list/stats 命令），见 2.5；save/restore key 见 3.4.6。
- 延后到 4.8（接口契约细节）：
  - selector 错误的 `code/hint/candidates` 字段名与枚举（保持可修复；优先推荐 `{"uid":...}`）。
  - restore 的返回 JSON shape（错误汇总列表字段名等；行为已定为“逐条 restore”，见 3.4.6）。

### 4.8 接口与对外契约（control plane / schema）

目标：把第 2.5/3.4 等已收敛口径，写成可落地的“接口契约”（命令名/字段名/JSON shape/错误形态/生命周期/兼容策略）。

#### 4.8.1 契约边界与兼容承诺

- 哪些接口/字段是强契约（必须长期稳定），哪些属于 debug 通道允许演进（例如 stream 缓存文件可丢弃）。
- “不做 alias/双写”的范围与例外（本轮原则：默认无 alias）。

#### 4.8.2 命令语法与 selector（规范化）

- `{"uid":...}` vs `{"pkg":"...","userId":...}`（语义已定在 2.5）；在接口契约中补齐：字段名保留、大小写、字符串转义与值域（若需要）。
- 所有命令是否统一支持两种 selector（或列出例外清单）。

#### 4.8.3 通用输出约定（identity echo + envelope）

- per-app 输出强制回显 `uid/userId/app(canonical)`（已定在 2.5）；是否补 `matchedName` 等辅助字段。
- 是否引入统一的顶层 `version` / `schema` 字段（尤其 stream vNext）。

#### 4.8.4 错误模型（必须可修复）

- selector/语法/状态错误的 `code/message/hint/candidates` 字段名与枚举。
- 歧义时 candidates 的最小信息集合（优先 `{"uid":...}`）。

#### 4.8.5 枚举与命名表（字段名/枚举的“单一真相”）

- `scope`、`policySource`、`reasonId`、`notice`、`ifaceKindBit` 等：最终对外名称、取值集合、是否允许新增。
- rename 相关：`GLOBAL_*` → `DOMAIN_DEVICE_WIDE_*` 的对外兼容策略（本轮无 alias）。

#### 4.8.6 Streams（DNSSTREAM/PKTSTREAM/ACTIVITYSTREAM）契约

- 命令：`STREAM.START/STREAM.STOP`（`type=dns|pkt|activity`）、horizon 参数、连接/断连、`RESETALL` 影响（3.4 已定部分，补齐接口字段）。
- schema vNext：`type=dns|pkt|activity|notice`，`notice=suppressed|dropped`，最小字段集合与快照原则。
- backpressure/drop 的对外表现（notice 字段）。

#### 4.8.7 Metrics 契约

- `METRICS.GET(name=reasons|domainSources|traffic|conntrack|perf)`（以及 `METRICS.RESET(...)`）：
  - JSON shape、gating（`BLOCK=0` 不更新）、reset 语义与返回字段。

#### 4.8.8 Reset / save / restore 契约

- `RESETALL` vs layer reset 的对外效果清单（3.4 已定部分，补齐“接口可观察”）。
- save/restore：key/批量失败策略/orphan 清理/schemaVersion 已定在 3.4.6；仅补齐接口可观察与返回 JSON shape。

#### 4.8.9 落盘位置与同步策略（当前只占坑）

- 在本目录形成 working contract，后续再同步到 `docs/INTERFACE_SPECIFICATION.md` 与 `openspec/specs/*`（不在本轮讨论中外溢改动）。

### 4.9 配置层/前端职责边界（已收敛；此处仅保留索引）

该话题已从“待讨论章节”迁移为可实现契约，权威约定见：

- `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`

### 4.10 基础数据结构与代码复用（后端实现骨架）

- 把“scope / attribution / explain envelope”的内部数据结构收敛清楚：DNS（`policySource`）与 packet（`reasonId/ruleId`）如何在代码层对齐，并避免重复造轮子。
- 明确哪些复用发生在配置层（rule group 展开/冲突拒绝），哪些需要后端提供最小硬约束（例如 apply 冲突错误形态）。

### 4.11 测试与验收（已收敛；此处仅保留索引）

本章已在第 2.7/3.5 收敛为可执行 gate 与不可退化契约（不再作为待讨论章节）：

- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`（2.7/3.5）
- `docs/IMPLEMENTATION_ROADMAP.md`（P0/P1/P2/P3 阶段定义）

### 4.12 落地拆分（change 切片与顺序）

- 把 fusion 阶段的工作拆成“低风险收敛（命名/文档/接口收敛）→ 观测对齐（stream/metrics）→ 融合仲裁（legacy/ip‑leak）→ 结构重构（若必要）”等可独立验收的 change 切片，避免一次性大爆炸合并。

### 4.13 文档清理与隔离策略（避免旧文档继续打架）

- 列出所有受 fusion 影响的权威文档与“历史讨论稿/过期提案”，明确处理方式：
  - 必须更新的：接口文档、help/对外口径、roadmap；
  - 需要迁移/隔离的：旧的 working decisions / checklist / 过时设计稿；
  - 只保留为回执的：已落地能力的设计/验收口径文档（避免被当作提案反复讨论）。
- 统一“单一真相”入口：`docs/IMPLEMENTATION_ROADMAP.md`（实现阶段/边界）+ `openspec/specs/*`（接口/语义权威）+ 本目录（融合阶段的讨论与收敛）。
