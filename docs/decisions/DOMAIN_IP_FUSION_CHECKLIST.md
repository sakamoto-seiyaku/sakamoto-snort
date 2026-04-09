# Domain + IP Fusion Checklist

更新时间：2026-04-09  
状态：pre-change 分析清单（先对齐现状与问题，再拆具体 change）

---

## 0. 目的

这份清单只做一件事：在开始 `domain+IP fusion` 之前，把**当前系统真实状态**、**需要统一的点**、以及**后续应拆成哪些 change**先钉住。

这不是实现方案，也不是接口文档；它是后续评审/拆任务的总 checklist。

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

## 2. fusion 前必须逐项检查的 checklist

> 用法：先逐项讨论并确认“目标口径”，再决定哪些项需要新 change，哪些只是文档/命名/重构。

### A. 术语与命名（按最新决议重写）

本轮 fusion 的目标是让“域名腿”和“IP 腿”在用户视角上**同构**：用户用同一套词理解优先级与复用方式；但两条腿的匹配字段不要求对齐。

- **规则优先级顺序**：当多条策略同时命中时，谁赢（统一口径）。
- **匹配条件集合**：一条规则用哪些条件命中（两条腿不同对象空间，不要求字段对等）。
- **规则组**：为了复用/组织规则集合的配置概念（domain 后端原生支持；IP 侧只做配置展开）。

#### A1. 命名约束（文档/HELP 必须执行）

- 新设计文档中禁止使用裸 `global`。
- 必须写清层名：`device-wide DomainPolicy ...` / `per-app (UID-scoped) ...` / `packet policy ...`。
- 代码枚举 `GLOBAL_AUTHORIZED/GLOBAL_BLOCKED` 当前应被解读为 **domain-only device-wide**（后续改名目标：`DOMAIN_DEVICE_*`）。

#### A2. 规则组（Domain vs IP）

- Domain 侧：后端已经存在可复用的规则集合（lists/rules/bits 等），并天然区分 per-app 与 device-wide 两个入口。
- IP 侧：后端不引入“规则组”概念；`规则组` 只存在于**配置层**（前端/配置生成器）。

#### A3. IP 规则组的配置展开与冲突规则（决议）

当某个 app 引用多个 IP 规则组时，最终都会被展开成同一份 `<uid>` 的 `IPRULES` 规则集。为保证确定性与可解释性：

- **允许去重**：完全相同的规则允许合并/去重。
- **冲突拒绝 apply（已确认）**：只要出现两条规则的**匹配条件集合相同**，但**任意字段不同** → 直接拒绝 apply（不进入运行期仲裁）。

> 说明：这里的“字段”按“规则规格字段”理解（例如 action/enforce、priority、reasonId/ruleId、would/enforce 相关字段等）。如果未来需要支持“同条件不同动作”的覆盖语义，应显式新增仲裁规则，而不是隐式容忍冲突。

- **统计口径（决议）**：暂时只承诺 per-app（UID）级别统计，不承诺规则组级统计。

- [ ] A4. 统一把接口/帮助文案里的 `global custom ...` 改为带层名的表述
- [ ] A5. 将 `GLOBAL_*` 改名为 `DOMAIN_DEVICE_*`（纯命名收敛 change）

### B. 作用域模型（scope lattice）（按最新决议重写）

本节只回答“谁对谁生效”。为避免混淆，必须区分三类东西：

- **scope**：真正参与判决的策略层
- **gate**：运行期开关（开/关整段逻辑）
- **template**：新建 app 默认模板（不会 retroactive 改写已有 app）

#### B1. gate / template / scope 速查（现状）

| 类别 | 项目 | 说明 |
|---|---|---|
| gate | `BLOCK` | blocking 总开关；`BLOCK=0` 时 packet path bypass |
| gate | `IPRULES` | 是否启用 IPRULES 引擎 |
| gate | `BLOCKIPLEAKS` | 是否启用 legacy overlay |
| template | `BLOCKMASKDEF` / `BLOCKIFACEDEF` | 新建 app 默认模板（决议：template default） |
| per-app gate | `CUSTOMLIST.ON/OFF` | 决议：保持现语义；同时 gate 掉 app custom 与 device-wide domain custom |
| scope | per-app domain custom | `BLACK*/WHITE*` 带 app 参数 |
| scope | device-wide domain custom | `BLACK*/WHITE*` 不带 app 参数（domain-only） |
| scope | mask fallback | `app.blockMask & domain.blockMask` |
| scope | per-app packet hard gate | `BLOCKIFACE` / `IFACE_BLOCK`（决议：hard gate） |
| scope | per-UID IP rules | `IPRULES.ADD <uid> ...`（当前仅 per-UID） |

#### B2. DomainPolicy（域名腿）scope（现状基线）

`App::blocked()` 的结构（省略 metrics 细节）：

```text
gate: BLOCK=0 -> allow
gate: CUSTOMLIST.OFF -> MASK_FALLBACK
CUSTOMLIST.ON ->
  per-app domain custom lists/rules
  -> device-wide domain custom lists/rules (domain-only)
  -> MASK_FALLBACK (app.blockMask & domain.blockMask)
```

#### B3. packet policy（包腿）scope（现状基线）

`PacketManager::make()` 的判决链路：

```text
gate: BLOCK=0 -> bypass
IFACE_BLOCK (per-app hard gate)
  -> IPRULES (per-UID rules; gated by IPRULES=1)
  -> legacy DomainPolicy bridge (host/domain -> App::blocked(domain))
  -> BLOCKIPLEAKS (global overlay; gated by BLOCKIPLEAKS=1)
```

边界说明（决议/现状）：

- 当前没有 device-wide IP rules（IP 腿 scope 不做强行对称）。
- IP 侧“规则组”只在配置层存在，不引入新的后端 scope。

#### B4. `IFACE_BLOCK` 与 DNS-side DomainPolicy 的关系（必须显式写清）

- `IFACE_BLOCK` 命中时会遮蔽后续 packet-layer 判决对“实际联网结果”的影响。
- 但 DNS-side DomainPolicy 仍可能运行并产出观测（当前 `DnsListener` 不检查 `blockIface()`）。
- 因此必须区分：DNS verdict/观测 与 最终传输 verdict 是两件事。

- [ ] B5. 将上述 scope/gate/template 速查同步到接口文档与 HELP（单独 change）

### C. 规则优先级顺序 / 仲裁口径（按最新决议重写）

统一原则：

- 统一的是“规则优先级顺序”（用户怎么理解谁覆盖谁），不是“匹配条件字段必须对齐”。
- 通过 A3 的“冲突拒绝 apply”规则，避免运行期出现“同条件不同动作”的隐式仲裁。

#### C1. packet verdict 优先级顺序（现状基线）

在 `BLOCK=1` 前提下，最终 packet verdict 的优先级顺序为：

1. `IFACE_BLOCK`：命中即 drop（最终）
2. `IPRULES`：若启用且命中，由 IPRULES 引擎给出 allow/block
3. legacy DomainPolicy bridge：当能解析出 `host->domain()` 时，按 DomainPolicy 结果影响 verdict
4. `BLOCKIPLEAKS`：对 legacy domain verdict 的全局 overlay

#### C2. DomainPolicy verdict 优先级顺序（现状基线）

在 `CUSTOMLIST.ON` 前提下：

1. per-app domain custom allow/block
2. device-wide domain custom allow/block（domain-only）
3. `MASK_FALLBACK`（`app.blockMask & domain.blockMask`）

`CUSTOMLIST.OFF`：跳过 1/2，直接走 3。

#### C3. DNS verdict vs packet verdict（对外解释必须分层）

- DNS-side verdict（`policySource`）是“域名语义判决/观测”。
- packet verdict 是“最终传输裁决”，可能被 `IFACE_BLOCK`/`IPRULES` 提前决定；因此对外解释时必须同时标注层名与优先级来源。

- [ ] C4. 在观测统一（D 组）里补齐：当 DNS verdict 与 packet verdict 不一致时，对外解释口径是什么
### D. 观测统一性

- [ ] D1. 定义一套统一的“为什么被拦/为什么放过”解释模型：
  - DNS 侧 `policySource`
  - Packet 侧 `reasonId`
  - IPRULES `ruleId/wouldRuleId`
- [ ] D2. 决定哪些信息是 layer-local 的，哪些应该作为跨层术语统一
- [ ] D3. 审核 `PKTSTREAM` / `METRICS.DOMAIN.SOURCES` / `METRICS.REASONS` / per-rule stats 是否已满足“同一系统、两边口径不打架”
- [ ] D4. 决定 app/domain 统计在 IPRULES 命中时是否继续保持 `domain=null, GREY`，还是后续要引入更明确的归因层

### E. 控制面与用户心智

- [ ] E1. 审核现有控制命令能否自然表达统一模型：
  - `BLOCK`
  - `BLOCKMASK*`
  - `BLOCKIFACE*`
  - `IPRULES*`
  - `BLACKLIST/WHITELIST`
  - `BLACKRULES/WHITERULES`
- [ ] E2. 决定“用户先配域名规则，再配 IP 规则”时，前端/文档应该如何解释两者关系
- [ ] E3. 决定哪些历史命令名保留，哪些只做文档层术语收敛，不做接口重命名
- [ ] E4. 列出所有“名字像全局、实际不是全局”的对外接口/帮助文案/JSON 字段，避免只清理一半
- [ ] E5. 明确哪些概念只允许出现在设计文档里，哪些会成为用户真正要理解和操作的控制面概念

### F. 数据结构与模块边界

- [ ] F1. 审核 `App` 是否承担了过多跨层职责：
  - DomainPolicy custom lists/rules
  - block masks
  - domain counters
  - iprules caps cache
- [ ] F2. 审核 `PacketManager` 是否已经变成 packet policy 的唯一仲裁入口；若是，fusion 后是否继续以它为中心
- [ ] F3. 审核 `DomainManager` / `HostManager` / `IpRulesEngine` 的边界是否清晰，哪些地方只是历史路径遗留
- [ ] F4. 识别纯命名重构、纯结构重构、纯语义变更三类工作，避免混在一个 change 里

### G. 生命周期 / reset / 持久化

- [ ] G1. 审核 `RESETALL` 的统一边界：哪些 domain/IP/metrics 状态会一起清掉，见 `src/Control.cpp:439`
- [ ] G2. 审核 layer-specific reset：
  - `METRICS.DOMAIN.SOURCES.RESET*`
  - `METRICS.REASONS.RESET`
  - `METRICS.PERF.RESET`
  - `IPRULES` rule stats reset semantics
- [ ] G3. 明确哪些是 since-boot、哪些持久化、哪些是规则生命周期内有效
- [ ] G4. 审核 restore/save 的权威来源：哪些状态在 `Settings/App/DomainManager/IpRulesEngine` 中持久化，哪些只是运行期派生态
- [ ] G5. 明确 rule/list/stats/metrics 在 “开关关闭 → 再开启” 时是否保留、是否清零、是否重建 snapshot/cache

### H. 测试与验收

- [ ] H1. 列出 fusion 本身要补的 host/integration/device 验收项
- [ ] H2. 明确哪些旧测试只覆盖 domain 或只覆盖 ip，无法证明“统一性”
- [ ] H3. 设计最小 fusion 回归矩阵：
  - 同 scope 下 domain / ip 语义一致性
  - 跨 scope 优先级一致性
  - 可观测性字段一致性
  - reset / since-boot / docs 对齐
- [ ] H4. 单独列出 negative / invalid / malformed case：
  - 非法控制参数
  - 空对象/无命中对象
  - 开关关闭时的 bypass 语义
  - 规则/列表冲突与幂等
- [ ] H5. 单独列出 concurrency / live-traffic case：
  - reset 与流量并发
  - rule/list update 与流量并发
  - stream/metrics 查询与流量并发

### I. 热路径 / 性能约束

- [ ] I1. 固化 fusion change 的性能红线：
  - 不得在已有 bypass 场景平白新增 host/domain 物化
  - 不得把原本可 snapshot/lock-free 的读路径退化成常态加锁
  - 不得把本可按需启用的逻辑变成每包必经重成本逻辑
- [ ] I2. 明确哪些额外判断属于可接受常数成本，哪些必须继续后置/按需 gating
- [ ] I3. 审核 domain+IP 统一后，`BLOCK=0` / `IPRULES=0` / 无 domain consumer / 无 ct consumer 等 bypass 路径是否仍然干净
- [ ] I4. 审核 observability/metrics 是否在默认关闭或常态开启下满足既定热路径约束

### J. 并发 / 原子性 / phase 边界

- [ ] J1. 审核 `PacketListener phase-1 / phase-2` 与 `PacketManager` 当前分层是否会在 fusion 后产生新的判决窗口不一致
- [ ] J2. 审核控制面修改（domain list/rules、`BLOCKMASK`、`BLOCKIFACE`、`IPRULES`）对热路径的可见性模型：
  - 何时生效
  - 是否需要 epoch/snapshot
  - 哪些允许 eventual consistency
- [ ] J3. 审核 metrics/reset/stream 在 live traffic 下的原子性口径，避免“接口看似严格 reset，实际只是 best effort”
- [ ] J4. 明确哪些并发语义是产品承诺，哪些只是实现细节（文档不承诺）

### K. 冲突样例矩阵（必须在设计阶段说清）

- [ ] K1. 列出最小冲突样例：
  - domain allow + ip block
  - domain block + ip allow
  - per-app allow + device-wide block
  - `IFACE_BLOCK` + 其它 allow
  - `BLOCKIPLEAKS` + IPRULES allow
- [ ] K2. 对每个冲突样例写出：
  - 最终 verdict
  - 对外解释口径（reason/source）
  - 哪些 stats/metrics 应增长
  - 哪些字段必须为空/不得出现
- [ ] K3. 单独确认“同一概念在 domain 与 ip 两边是否真的应该统一”，避免为了表面对称强行设计错误抽象

### L. 产物与拆分边界

- [ ] L1. 这轮 fusion 预研至少要产出哪些固定 artefact：
  - 术语表
  - scope / precedence 对照表
  - control surface inventory
  - observability 对照表
  - 测试缺口矩阵
- [ ] L2. 为每个 artefact 标明“只是审计结论”还是“会直接驱动代码 change”
- [ ] L3. 把“纯命名收敛 / 纯文档同步 / 真正语义变更 / 结构性重构”明确拆开，避免一次 change 混做

### M. 明确先不做的事

- [ ] M1. 是否继续把 `ip-leak` 放在 fusion 之后单独收敛
- [ ] M2. 是否继续把 “global IP rules” 放在 fusion 之后单独讨论
- [ ] M3. IPv6 / domain per-rule stats / 更强 L4 state 是否继续保持后置

---

## 3. 建议的拆分方式（先讨论，不立即创建）

如果上面的 checklist 基本认可，建议后续不要做一个超大 change，而是至少拆成下面几类：

1. **Fusion 现状审计 / 语义对照 change**
   - 只固化术语、scope、优先级、observability 对照表
   - 产出权威设计文档与验收 checklist
   - 同时明确性能红线、并发承诺、冲突样例矩阵

2. **命名/帮助文档/设计文档收敛 change**
   - 不改功能语义
   - 只清理 `GLOBAL_*`、help 文案、设计文档与 roadmap/project drift

3. **仲裁/边界统一 change**
   - 真正涉及 DomainPolicy / IPRULES / legacy path 的统一规则
   - 这是第一个真正可能改代码语义的 change

4. **观测统一 change**
   - 统一 reason / source / rule attribution 的用户心智与输出口径

5. **结构性重构 change**
   - 仅在前四项都钉死之后，再做模块边界/命名/数据结构重构

---

## 4. 当前建议

当前最合理的顺序不是直接改代码，而是：

1. 先逐项过完本清单  
2. 先产出一组最小 artefact：
   - **DomainPolicy / PacketPolicy / scope / precedence** 对照表
   - **observability（policySource / reasonId / ruleId）** 对照表
   - **冲突样例矩阵**
   - **测试缺口矩阵**
3. 再基于这些 artefact 创建第一个 `domain+IP fusion` change

如果第 2 步没有先做，后面的 change 很容易把“命名清理、语义收敛、性能边界、并发承诺、结构重构、观测统一”混成一团。
