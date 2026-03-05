# P0/P1 后端调研：工作决策记录（临时）

> 范围：仅本仓库后端（Snort + iptables + NFQUEUE + control socket）。  
> 目标：把讨论中的“做什么/不做什么 + 为什么（关键原则）+ 现状事实语义”固化成可迭代的临时文档。  
> 备注：无老客户端兼容包袱；更精炼的可观测性上级决策见 `docs/OBSERVABILITY_WORKING_DECISIONS.md`；后续讨论如有新结论，以本文件为准持续更新。

---

## 0. 关键原则（用于决策取舍）

1. **NFQUEUE 热路径不引入新锁/重 IO**  
   热路径指 `PacketListener::callback` 及其调用链（含 `PacketManager::make`）；保持原有并发约束。
2. **不增加新的“观测通路”**  
   后端仅负责输出；前端负责采集/汇总/丢弃过期数据。观测通道复用 `PKTSTREAM`（以及已有 stats）。
3. **不做全局 safety-mode（现在不做、以后也不做）**  
   全局代价高且收益有限；用户更常见的工作流是“在一个 checkpoint 内批量变更若干规则”，对这批规则做 log-only/试运行即可。
4. **不在 P0/P1 强行重构域名系统**  
   P0/P1 先把 IPv4 L3/L4 规则与最小可解释性落地；域名相关可观测性后置。
5. **IPv6 规则后置**  
   P0/P1 新规则语义先只覆盖 IPv4 地址；IPv6 暂默认放行且不提示，后续补齐。
6. **事实优先于规划**  
   以源码事实语义为准，规划随实现调整（双向过程）。

---

## 1. 术语约定（讨论对齐用）

- **reasonId**：一次判决“为什么允许/为什么拦截”的可解释标识；P0 以“粗粒度 +（新增 IPv4 规则精确到 ruleId）”为目标。
- **safety-mode**：仅针对“本次 checkpoint 批量变更的规则”的试运行机制：  
  - `enforce=0, log=1`：评估/命中/记录，但不实际 DROP（PKTSTREAM 输出 `wouldRuleId` + `wouldDrop=1`，实际 `accepted` 仍为 1，`reasonId` 仍解释实际 verdict）。  
  - `enforce=1, log=1`：实际执行策略，同时保留日志（观测是否误伤）。  
  - `enforce=1, log=0`：正常使用。  
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
- `RESETALL`：清空 settings + save tree + 各 manager（含 `pktManager.reset()`、`dnsListener.reset()`）并触发保存。

---

## 3. P0/P1 结论：reasonId / safety-mode / observability

### 3.1 safety-mode（决策：仅逐条规则，不做全局）

- **不做**：全局 safety-mode（dry-run 整个系统）。  
  - 代价：需要拆分当前 `BLOCK` 的“评估 gating + enforce”双重语义；影响 Packet/DNS/stats/stream 全链路，风险过高。
  - 收益：对典型用户工作流（checkpoint 内增量改规则）不匹配。
- **做**：逐条规则（或批量变更的那批规则）支持 `enforce/log` 语义。  
  - 前端通过 checkpoint 选择“本批规则”进入 `enforce=0, log=1`（would-block），观察后再切 `enforce=1`。
  - 后端只需在规则引擎里实现：命中时产生 reasonId + hit 统计 +（可选）PKTSTREAM 输出。

### 3.2 reasonId（决策：P0 粗粒度 + 新 IPv4 规则精确到 ruleId）

P0 仅保证以下最小集合能解释清楚：

- Packet（NFQUEUE）：
  - `IFACE_BLOCK`
  - `IP_LEAK_BLOCK`
  - `ALLOW_DEFAULT`
  - 以及新增 IPv4 L3/L4 规则的：`IP_RULE_ALLOW|IP_RULE_BLOCK`（enforce 命中时带 `ruleId`；log-only/would-match 通过 `wouldRuleId/wouldDrop=1` 表达，`accepted` 仍为 1）
- DNS：
  - 先只输出 `DNS_DOMAIN_DECISION`（blocked/allowed）+（可选）自定义名单/规则来源后置

域名系统内部的精细解释（例如命中 custom list / custom rule / blocking list / authorized / blocked 的具体来源）**后置**。

### 3.3 “可观测性”采用 PKTSTREAM（决策：不新增通路）

- 后端输出：PKTSTREAM 作为事件通道；stats 作为常驻轻量聚合通道。
- 前端采集：只保留“最近最有用的少量日志/窗口”，超出缓存期直接丢弃。
- 风险告知：PKTSTREAM 开启会增加热路径负担；属于可观测性成本，需对用户明确。

### 3.4 策略统计（决策：新增规则自带 hit/lastHit 等）

对新增 IPv4 L3/L4 规则，后端提供最小但实用的 per-rule 统计（不依赖 PKTSTREAM 是否开启）：

- `hitPackets` / `hitBytes`（或至少 `hitPackets`）
- `lastHitTimestamp`
- 可选：`firstHitTimestamp`、`lastVerdict`（would-block / blocked / allowed）

规则层面不存在“同一条规则既 allow 又 block”的混合语义；每条规则只有一个 action（ALLOW 或 BLOCK），再叠加 `enforce/log`。

---

## 4. 待定项（明确标注 TBD，避免误当结论）

- reasonId 枚举的最终命名/稳定性与对外协议字段（PKTSTREAM schema 如何演进）。
- 新 IPv4 L3/L4 规则的字段规范化：
  - direction 下 `srcPort/dstPort` 与“remote/local port”的语义映射
  - 接口维度（ifindex/name/bit）在规则中的表达
  - 上下文维度（例如 input/output、UID、协议、端口 ANY）与默认策略顺序
- PKTSTREAM 的背压/采样/限速策略（是否需要避免长时间阻塞 `mutexListeners`）。

---

## 5. 与已存在 change 的关系（现状）

- 已有 OpenSpec change：`openspec/changes/add-app-ip-blacklist/`  
  用于 per-app IP 黑名单（snapshot + 热路径查询）方向的落地参考与复用。
