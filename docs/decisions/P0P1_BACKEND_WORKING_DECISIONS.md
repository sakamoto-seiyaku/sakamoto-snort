# P0/P1 后端调研：工作决策记录（临时）

> 注：本文中历史使用的 “P0/P1” 仅指当时的**功能分批草案**，不对应当前测试 / 调试 roadmap 的 `P0/P1/P2/P3`。


> 范围：仅本仓库后端（Snort + iptables + NFQUEUE + control socket）。  
> 目标：把讨论中的“做什么/不做什么 + 为什么（关键原则）+ 现状事实语义”固化成可迭代的临时文档。  
> 备注：当前尚未发布正式版本，因此不需要预设“历史发布版本迁移/兼容”包袱；但接口与语义仍不得随意改动，只有在存在明确重大理由时才允许调整，并应同步更新权威文档。更精炼的可观测性上级决策见 `docs/decisions/OBSERVABILITY_WORKING_DECISIONS.md`；若与上位纲领或 OpenSpec change 冲突，以上位文档为准；本文件继续作为调研/工作记录持续更新。

---

## 0. 关键原则（用于决策取舍）

1. **NFQUEUE 热路径不引入新锁/重 IO**  
   热路径指 `PacketListener::callback` 及其调用链（含 `PacketManager::make`）；保持原有并发约束。
2. **不增加新的“观测通路”**  
   后端仅负责输出；前端负责采集/汇总/丢弃过期数据。观测通道复用 `PKTSTREAM`（以及已有 stats）。
3. **不做全局 safety-mode（现在不做、以后也不做）**  
   全局代价高且收益有限；用户更常见的工作流是“在一个 checkpoint 内批量变更若干规则”，对这批规则做逐条试运行即可；当前 dry-run 仅对 BLOCK 规则开放。
4. **不在 P0/P1 强行重构域名系统**  
   P0/P1 先把 IPv4 L3/L4 规则与最小可解释性落地；域名相关可观测性后置。
5. **IPv6 规则后置**  
   P0/P1 新规则语义先只覆盖 IPv4 地址；IPv6 暂默认放行且不提示，后续补齐。
6. **事实优先于规划**  
   以源码事实语义为准，规划随实现调整（双向过程）。
7. **未发正式版不等于接口可随意变化**  
   当前不需要为历史发布版本背迁移包袱；但凡改控制命令、字段或语义，必须能明确说明其必要性，并同步收敛权威文档，避免讨论稿与 change 漂移。

---

## 1. 术语约定（讨论对齐用）

- **reasonId**：一次判决“为什么允许/为什么拦截”的可解释标识；P0 以“粗粒度 +（新增 IPv4 规则精确到 ruleId）”为目标。
- **safety-mode**：仅针对“本次 checkpoint 批量变更的规则”的试运行机制：  
  - `action=BLOCK, enforce=0, log=1`：评估/命中/记录，但不实际 DROP；仅当该包未被任何 `enforce=1` 规则作为最终命中接管时，PKTSTREAM 才输出 `wouldRuleId` + `wouldDrop=1`，此时实际 `accepted` 仍为 1，`reasonId` 仍解释实际 verdict。  
  - `enforce=1, log=1`：实际执行策略，同时保留日志（观测是否误伤）。  
  - `enforce=1, log=0`：正常使用。  
  - `enforce=0` 的职责仅限调试/试运行，不承担“禁用规则”的职责；彻底禁用统一由 `enabled=0` 表达。  
  safety-mode **不覆盖全局**，也不尝试让所有系统（域名/IP/接口）统一进入 dry-run。
- **PKTSTREAM**：控制面流式输出网络包事件；被视为主要可观测性通道（非新增系统）。
- **checkpoint**：前端概念（批量变更与回滚）；后端不实现 checkpoint 机制本身，只提供必要的规则开关/统计/可解释输出。

---

## 2. 现状事实语义（Packet / DNS / Stream / 持久化）

### 2.1 dataplane：iptables → NFQUEUE（IPv4/IPv6）

- `PacketListener<IPv4>::start/PacketListener<IPv6>::start` 会创建并绑定链：`sucre-snort_INPUT`、`sucre-snort_OUTPUT`，通过 `NFQUEUE --queue-balance` 分流到多个线程队列。
- 现状明确 **不接管**：
  - `lo`：`-i lo/-o lo -j RETURN`
  - DNS 端口：`53/853/5353`（tcp/udp；IN 规则用 `--sport`，OUT 用 `--dport`）均 `RETURN`

### 2.2 Packet 判决链路（当前实现的“事实”）

**入口**：`PacketListener::callback`（NFQUEUE 线程）

1. 解析上下文：`uid/iface/timestamp/proto/srcPort/dstPort`（以及 `payloadLen`）。
2. 全局 gating：仅当 `settings.blockEnabled()==true` 才进入 `pktManager.make(...)`；否则直接 `NF_ACCEPT`。  
   结论：现状下 **无法** 通过 `BLOCK=0` 仍获取 pktstream/stats 来实现 dry-run。
3. Phase 1（不持 `mutexListeners`）：构建判决上下文
   - 对端 IP：`addr = input ? saddr : daddr`
   - `app = appManager.make(uid)`
   - `host = hostManager.make(addr)`（可能做 RDNS；并尝试 `host->domain(domManager.find(addr))`）
4. Phase 2（持 `mutexListeners` shared lock）：`pktManager.make(...)`  
   当前 `PacketManager::make` 的 verdict 只包含两类“硬原因”：
   - **IP 泄漏拦截**：`BLOCKIPLEAKS && blocked(domain) && domain->validIP()` → DROP
   - **接口拦截**：`app->blockIface()` 命中当前接口 bit → DROP
   其它情况 → ACCEPT

**统计与 stream（Packet）**
- stats：仅当 `app->tracked()==true` 才会调用 `appManager.updateStats(...)`（但这与 stream 独立）。
- PKTSTREAM：无论 `tracked` 是否开启，都会构造 `Packet` 并 push 到 `Streamable<Packet>::stream(...)`。

### 2.3 DNS 判决与 Domain↔IP 映射（IP leak 前提）

**入口**：`DnsListener::clientRun`（DNS listener 线程）

1. 读取 `(domain, uid)`，得到 `app` 与 `domain`。
2. 在 `mutexListeners` shared lock 内调用 `app->blocked(domain)`：输出 DNS verdict；并计算 `getips = verdict || GETBLACKIPS`。
3. 若 `getips==true`：清空旧映射后接收并写入 `Domain↔IP` 映射（IPv4/IPv6）。
4. 若 `BLOCK==1 && tracked==1`：更新 DNS stats 并输出 DNSSTREAM。

结论：Packet 的“域名维度判决”当前并非直接基于域名，而是依赖 DNS 建立映射后通过 `BLOCKIPLEAKS` 间接生效。

### 2.4 Stream 的事实语义与风险

- `PKTSTREAM/DNSSTREAM` 的实现是 `Streamable::stream()`：在调用线程内生成 JSON 并对每个订阅 socket **同步 write()**。
- 现状 `PacketManager::make` 在 `mutexListeners` shared lock 下执行，而 `Streamable::stream()` 也在该锁范围内。  
  结论：**PKTSTREAM 开启且输出变大/前端读慢时，可能阻塞 NFQUEUE 热路径，并延迟需要独占锁的 RESETALL 等操作。**
- 这是可观测性的代价：需要在产品/文档中明确告知用户（例如“调试时开、日常关；或限制订阅时长/数量/输出字段”）。

### 2.5 持久化点（现状）

- 周期性 `snortSave()`：保存 `settings/blockingList/rules/domains/apps/dnsstream`；**不保存 pktstream**（`Packet::save/restore` 当前为空）。
- `RESETALL`：清空 settings + save tree + 各 manager（含 `pktManager.reset()`、`dnsListener.reset()`）并触发保存。对于本轮新增的 IP 规则语义，这意味着整套规则集被彻底丢弃；后续新建规则从新的空规则集重新开始，`ruleId` 计数器也从初始值 `0` 重开。

---

## 3. P0/P1 结论：reasonId / safety-mode / observability

### 3.1 safety-mode（决策：仅逐条规则，不做全局）

- **不做**：全局 safety-mode（dry-run 整个系统）。  
  - 代价：需要拆分当前 `BLOCK` 的“评估 gating + enforce”双重语义；影响 Packet/DNS/stats/stream 全链路，风险过高。
  - 收益：对典型用户工作流（checkpoint 内增量改规则）不匹配。
- **做**：逐条规则（或批量变更的那批规则）支持 `enforce/log` 语义。  
  - 前端通过 checkpoint 选择“本批 BLOCK 规则”进入 `enforce=0, log=1`（would-block），观察后再切 `enforce=1`。
  - 后端只需在规则引擎里实现：命中时产生 reasonId + hit 统计 +（可选）PKTSTREAM 输出。

### 3.2 reasonId（决策：P0 粗粒度 + 新 IPv4 规则精确到 ruleId）

P0 仅保证以下最小集合能解释清楚：

- Packet（NFQUEUE）：
  - `IFACE_BLOCK`（且命中该原因时，不再附带更低优先级规则层的 `ruleId/wouldRuleId`）
  - `ALLOW_DEFAULT`
  - 以及新增 IPv4 L3/L4 规则的：`IP_RULE_ALLOW|IP_RULE_BLOCK`（enforce 命中时带 `ruleId`；BLOCK 规则的 log-only/would-match 通过 `wouldRuleId/wouldDrop=1` 表达，且仅在无 `enforce=1` 最终命中时出现，此时 `accepted` 仍为 1）
  - `IP_LEAK_BLOCK` 等域名系统附属原因留待最终融合阶段再决定，当前不作为本轮实现前提
- DNS：
  - 先只输出 `DNS_DOMAIN_DECISION`（blocked/allowed）+（可选）自定义名单/规则来源后置

域名系统内部的精细解释（例如命中 custom list / custom rule / blocking list / authorized / blocked 的具体来源）**后置**。

### 3.3 “可观测性”采用 PKTSTREAM（决策：不新增通路）

- 后端输出：PKTSTREAM 作为事件通道；stats 作为常驻轻量聚合通道。
- 前端采集：只保留“最近最有用的少量日志/窗口”，超出缓存期直接丢弃。
- 风险告知：PKTSTREAM 开启会增加热路径负担；属于可观测性成本，需对用户明确。

### 3.4 策略统计（决策：新增规则自带 per-rule runtime stats）

对新增 IPv4 L3/L4 规则，后端提供固定 v1 形态的 per-rule runtime stats（不依赖 PKTSTREAM 是否开启）：

- `hitPackets/hitBytes/lastHitTsNs`
- `wouldHitPackets/wouldHitBytes/lastWouldHitTsNs`

语义与边界：
- `hit*`：该规则作为最终 `enforce=1` 命中规则时更新（每包最多 1 条）。
- `wouldHit*`：该规则作为最终 would-match（`action=BLOCK, enforce=0, log=1`，且无 `enforce=1` 命中）规则时更新（每包最多 1 条）。
- `enabled=0` 的规则不得更新任何 runtime stats，也不得计入 active complexity。
- 规则层面不存在“同一条规则既 allow 又 block”的混合语义；每条规则只有一个 action（ALLOW 或 BLOCK），再叠加 `enforce/log`。
- 规则内容一旦被 UPDATE 改写并生效，其 runtime state/stats 直接清零；当前不需要为修改前的历史 state 保留兼容语义。
- 规则若从 `enabled=0` 再次切回 `enabled=1`，其 runtime state/stats 也直接清零，避免“禁用前（`enabled=1` 时）累计的历史命中”延续到重新启用后的观测（禁用后计数不再增长但仍会保留；重新启用必须从 0 开始）。

---

## 4. 待定项（明确标注 TBD，避免误当结论）

- `reasonId` / PKTSTREAM 当前最小字段集与最小 reason 集合已由现有 change 固化；仍待后续专题决定的是**未来扩展**（例如域名附属原因恢复后如何增量追加、是否引入更多 counters/聚合口径）。
- 新 IPv4 L3/L4 规则的**实现映射细节**仍可继续细化，但不得推翻已固定的 v1 控制面字段：
  - direction 下 `srcPort/dstPort` 与“local/remote port”视角的内部映射实现
  - `ifaceKind + ifindex` 在内部 classifier 中的编码与归一化
  - 其它上下文维度若未来扩展（例如 CT）如何进入字段全集与编译路径
- PKTSTREAM 的背压/采样/限速策略（是否需要避免长时间阻塞 `mutexListeners`）。

---

## 5. 与已存在 change 的关系（现状）

- 当前 OpenSpec change：`openspec/changes/add-app-ip-l3l4-rules-engine/`  
  用于本轮 IPv4 L3/L4 per-app 规则引擎的权威语义与任务拆分。
- 已归档参考：`openspec/changes/archive/2026-03-04-add-app-ip-blacklist/`  
  仅作为早期 per-app IP 黑名单方向的历史参考。
