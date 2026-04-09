# Domain + IP Fusion Checklist

更新时间：2026-04-09  
状态：融合纲领（现状快照 + 目标状态 + 实现拆分）

---

## 0. 目的

这份文档把 `domain+IP fusion` 的工作收敛为三件事：

1. **现状快照**（第 1 节）：完全按代码事实陈述，不做推演。  
2. **目标状态**（第 2 节）：fusion 完成后，“用户应如何理解系统”的统一心智模型。  
3. **实现拆分**（第 3 节）：从现状走到目标，需要改哪些东西、如何拆 change、按什么顺序落地。

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
  -> legacy domain path
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

- DomainPolicy 的 verdict 是**域名语义判决/观测**；它常用于 DNS 侧观测，也可能通过 legacy bridge 影响 packet verdict。  

#### 2.1.3 packet policy / IPRULES（IP 腿）

用户应按下面顺序理解“最终传输 verdict（packet verdict）”的优先级（高 → 低）：

1. **`IFACE_BLOCK`（per-app packet hard gate）**：命中即 drop  
2. **`IPRULES`（per-UID IPv4 L3/L4）**：若启用且命中，按引擎决策 allow/block  
3. **legacy DomainPolicy bridge**：若能解析到 `host->domain()`，则可使用 DomainPolicy 结果影响 verdict  
4. **`BLOCKIPLEAKS` overlay**：对 legacy domain verdict 的附加裁决  

关键 gate/template 语义（用户理解口径）：

- `BLOCK=0`：整体不产生最终 blocking 行为（packet verdict 直通）；但系统可能仍做最小映射/观测（以各自指标契约为准）。  
- `IPRULES=0`：IPRULES 不参与；不应被误读为“清空规则”。  
- `BLOCKIFACEDEF`：只是新 app 的默认模板，不是 device-wide 的 iface policy。  

补充说明：

- 当前目标状态仍**不引入 device-wide IP rules**（保持 IP 腿的 scope 边界清晰；规则复用通过“规则组（配置层）”完成，见 2.3）。  

### 2.2 匹配条件集合（两条腿不强行对齐）

统一点：两条腿都可以被同一套“优先级模型/规则组模型”包装；但它们匹配的对象不同，条件字段天然不对等。

#### 2.2.1 DomainPolicy 的匹配条件集合（域名对象空间）

- 输入对象：`(uid/app, domain)`  
- 条件集合（示例）：  
  - 精确域名 / 后缀（子域）  
  - 通配符 / 正则（取决于规则类型）  
  - 来自 blocking lists 的 `domain.blockMask`（由订阅列表聚合得出）  

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
- **冲突拒绝 apply（已确认）**：只要出现两条规则的**匹配条件集合相同**，但**任意字段不同** → 直接拒绝 apply（不进入运行期仲裁）。  
  - 这条规则的目标是：避免出现“看似同一条规则，但不同来源给了不同 action/priority/归因字段”的隐式仲裁。  

统计口径（同一决议的后半句）：

- 暂时只承诺 **per-app（UID）级别** stats/metrics；不承诺规则组级统计。  

### 2.4 可观测性（fusion 后的统一解释模型）

目标：当用户问“为什么这个请求被拦/放过？”时，两条腿给出的解释在结构上是同构的，且不会互相打架。

- **DNS 侧（DomainPolicy）**：以 `policySource` 为核心解释字段，配套 `METRICS.DOMAIN.SOURCES*`。  
- **packet 侧（最终传输 verdict）**：以 `reasonId` +（可选）`ruleId/wouldRuleId` 为核心解释字段，配套 `METRICS.REASONS*`、`IPRULES.PRINT stats`、`PKTSTREAM`。  
- **跨层一致性**：当 DNS verdict 与 packet verdict 不一致时（例如 `IFACE_BLOCK` 遮蔽了后续路径），对外解释必须明确“哪个是最终传输裁决、哪个只是语义观测”。  

### 2.5 控制面（control plane）与文档口径

目标：控制面命令与 HELP/接口文档能直接表达第 2 节的统一心智模型，避免“名字像全局、实际不是全局”的误导。

- 禁止在对外文档中使用裸 `global`；必须写清层名：`device-wide DomainPolicy ...` / `per-app (UID-scoped) ...` / `packet policy ...`。  
- `GLOBAL_AUTHORIZED/GLOBAL_BLOCKED`（若仍存在）必须被明确为 **domain-only device-wide**；最终应改名为 `DOMAIN_DEVICE_*`。  
- IP 规则组是配置概念：后端控制面仍以 `<uid>` 的 `IPRULES.*` 为准；规则组冲突/去重在 apply 语义中体现（2.3.3）。  

### 2.6 state / counters / lifecycle（统一边界）

目标：用户能区分“规则状态”“统计状态”“观测状态”，并能预期 reset/save/restore 的边界。

- 明确哪些是 since-boot，哪些持久化，哪些属于规则生命周期内有效。  
- 明确 `RESETALL` 与 layer-specific reset 的边界：DomainPolicy counters、packet reason counters、perf metrics、per-rule stats 的 reset 语义一致且可解释。  

### 2.7 测试与验收（fusion 后的基线）

目标：产出一套可反复运行的基线，后续任何大改都能完整重跑，用于评估 bug 与性能回归。

- host-side：引擎/解析/确定性单测（不替代真机验收）。  
- host-driven integration：控制面下发 + 事件流/metrics 验证。  
- device（Tier‑1 受控拓扑）：以稳定可复现的受控环境覆盖关键矩阵（DomainPolicy/IFACE_BLOCK/IPRULES/overlay + 并发/reset）。  

### 2.8 性能与并发承诺（红线）

目标：fusion 不得把“可选成本”变成“每包必经成本”，并避免引入新的并发判决窗口不一致。

- 热路径不得新增磁盘/网络 I/O，不得长时间持锁；可选逻辑必须保持 gating。  
- `PacketListener phase-1/phase-2` 的边界必须保持：锁内只做纯判决与轻量计数。  
- 控制面更新与流量并发时，对外承诺必须明确（严格/最终一致/best-effort），避免接口语义含糊。  

---

## 3. 实现拆分与落地顺序（从现状到目标）

本节回答“要改哪些东西，大概改成什么样”。建议按影响面拆分，避免把命名清理、语义变更、观测统一、结构重构混成一个大 change。

### 3.1 命名与文档收敛（低风险；先做）

- 将对外文档/HELP 中的裸 `global` 全部替换为带层名表述。  
- 将 `GLOBAL_*` 改名为 `DOMAIN_DEVICE_*`（若涉及外部兼容，先做 alias/双写，再逐步迁移）。  
- 对齐 `docs/IMPLEMENTATION_ROADMAP.md`、`openspec/project.md`、各 `docs/decisions/*`：确保“现状/目标/已落地能力”不互相打架。  

### 3.2 IP 规则组“配置展开”语义补齐（确定性；可能涉及后端约束）

- 明确并实现 2.3.3 的 apply 语义：  
  - 完全相同规则可去重；  
  - 同一匹配条件集合、任意字段不同 → 拒绝 apply（必须有清晰错误原因，便于前端定位冲突来源）。  
- 统计先维持 per-app；不引入 group-level stats。  

### 3.3 可观测性对齐（跨层解释）

- 固化一套对外解释结构：最终传输裁决（packet）与语义观测（DNS）如何同时呈现。  
- 对齐 `policySource` / `reasonId` / `ruleId` / `wouldRuleId` 的叙事：哪些是最终裁决依据、哪些只是来源/候选信息。  

### 3.4 控制面与生命周期（reset/save/restore）

- 明确各类 counters/stats 的 reset 语义：`RESETALL` 与 layer-specific reset 的边界不含糊。  
- 明确开关关闭/再开启时：规则、缓存、统计是否保留/是否清零/是否重建。  

### 3.5 测试补齐（以真机闭环为最终验收）

- host 单测：覆盖 apply 冲突拒绝、确定性仲裁边界、序列化/反序列化一致性。  
- integration：覆盖控制面下发 + metrics/stream 断言。  
- device Tier‑1：覆盖关键矩阵与并发窗口（reset/update 与流量并发）。  

### 3.6 延后项（明确不夹带进本轮 fusion）

- `ip-leak` 重新收敛到统一仲裁之前，不在本轮先行改语义。  
- device-wide IP rules：除非出现明确产品需求与性能预算，否则保持不引入。  
- IPv6、域名 per-rule stats、更多 L4/L7 维度：按各自主线单独推进。  
