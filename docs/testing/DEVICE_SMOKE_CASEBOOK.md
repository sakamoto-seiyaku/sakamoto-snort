# Device / DX 冒烟测试 Casebook（真机端到端；人话版）

更新时间：2026-04-24

这份文档是**调查输出**（不做实现）：把当前“真机端到端能不能用”的测试，按 **Case（下规则→触发→看输出）**写清楚：
- 哪些已经在 smoke 里测到了（现有覆盖）
- 哪些“看了但没看全”（需要完善断言/输出）
- 哪些“场景本身没覆盖”（需要新增 Case）
- 哪些现在挂在 diagnostics 但其实更像 smoke（功能可用性验证）

---

## 0) 入口速查（现在怎么跑）

Smoke（总入口，固定顺序 platform → control → datapath）：
- `tests/integration/dx-smoke.sh`

分段：
- platform：`tests/integration/dx-smoke-platform.sh`
- control：`tests/integration/dx-smoke-control.sh`（实际跑 `tests/integration/vnext-baseline.sh`）
- datapath：`tests/integration/dx-smoke-datapath.sh`（实际跑 `tests/device/ip/run.sh --profile smoke`）

Diagnostics（现在只有 1 条聚合脚本）：
- `tests/device/diagnostics/dx-diagnostics.sh`
- `tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`

---

## 1) Case 写法模板（每条都“人话”）

每条 Case 固定包含：
- **目的**：验证什么能力
- **Given（前置）**：需要什么环境/开关/基线
- **When（操作/触发）**：下什么规则、发什么流量、怎么触发
- **Then（期望输出）**：要看到哪些输出（连通性 / stream / metrics / stats）
- **现有覆盖**：现在脚本里哪里已经测了（脚本 + check id）
- **缺口**：还缺哪些输出没看 / 还缺哪些场景没测（只列，不实现）
- **编号规则**：每个模块内 Case 从 1 重新开始；跨模块引用用「模块 / Case N」。

---

## Platform：平台（保证后续 Case 可跑）

这一组 Case 的目标：先把“能不能测 / 能不能复位 / 能不能稳定触发”确认掉，避免后面的功能用例变成随机 BLOCKED/SKIP。

### Case 1：平台就绪（端到端前置检查）
**目的**
- 先排掉“环境/接线”问题，避免后面每条 Case 都变成随机失败。

**Given**
- rooted 真机、adb 可用；（可选）已 deploy。

**When**
- 跑 `dx-smoke-platform`。

**Then（期望输出）**
- daemon 进程存在（例如 `pidof sucre-snort-dev` 有值；或至少能确认服务已拉起）
- socket namespace 就绪（至少文件存在）：
  - `/dev/socket/sucre-snort-control-vnext`
  - `/dev/socket/sucre-snort-netd`
- iptables/ip6tables hooks + NFQUEUE 规则存在
- SELinux 无 AVC denials（至少针对 sucre 的）
- netd hook 状态必须“讲清楚”：
  - 有：OK
  - 没有：明确提示准备命令（而不是假装没看见）

**现有覆盖**
- `tests/integration/dx-smoke-platform.sh`

**缺口**
- （文档层面）把 netd hook 的“准备/确认”写成可执行步骤：
  - `bash dev/dev-netd-resolv.sh prepare`
  - `bash dev/dev-netd-resolv.sh status`
- （当前脚本层面）`dx-smoke-platform` 主要检查“socket 文件存在”，但不检查 daemon pid 或 socket 可连接性；真正的可连接性在 Case 2 才会暴露。

---
### Case 2：控制面 vNext 连通（HELLO/QUIT/reconnect）
**目的**
- 控制面通道能用，后续所有 Case 才能跑。

**Given**
- vNext adb forward 正常（脚本会自动 setup）。
- host 侧已具备 `sucre-snort-ctl` 与 `python3`（见 Case 6）。

**When**
- `HELLO` → `QUIT` → 再 `HELLO`。

**Then（期望输出）**
- `HELLO` 返回 `protocol=control-vnext`、`protocolVersion=1`、`framing=netstring` 等字段
- `QUIT` 后连接能干净关闭，重连后仍 OK
- （可选）当这次运行包含 deploy 时：`inetControl()` gating 相关检查应能跑到（当前在 `VNT-00`，`--skip-deploy` 时会跳过）

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-01/02/03`

**缺口**
- 无

---

### Case 3：Stream 基本机制可用（activity）
**目的**
- START 能收到 started notice + 至少 1 条事件；STOP 有 barrier（短窗口内不再有 frame）。
- 这条等价于“stream 框架 sanity”，后面 `dns/pkt` stream 都复用同一套 START/STOP/notice 语义。

**Given**
- 控制面可用。

**When**
- `STREAM.START(type=activity)` → 收事件 → `STREAM.STOP`。

**Then（期望输出）**
- 收到 `notice.started`（stream=activity）
- 收到 `type=activity` 事件（至少 `blockEnabled` 是 bool）
- STOP 后短窗口内无多余 frame（best-effort）

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-03b`

**缺口**
- 无

---

### Case 4：Inventory（APPS/IFACES）能列出来（用于后续 selector）
**目的**
- 后续很多 Case 需要 app uid / iface 信息作为前置。

**Given**
- 控制面可用。

**When**
- `APPS.LIST`、`IFACES.LIST`。

**Then（期望输出）**
- apps[] 可用且按 uid 升序；limit=1 的 truncated 行为合理
- ifaces[] 可用且按 ifindex 升序

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-04*`、`VNT-05*`

**缺口**
- （如果后续要用“真实 app uid 触发网络”（例如 DNS 真实解析）：需要额外筛选“可联网 uid”（IP 模组里有相应探测策略，但这条 inventory case 本身不保证）。

---

### Case 5：CONFIG 可用（device/app），非法输入会被拒绝，失败不应部分生效
**目的**
- “开关能开、非法输入会拒绝、失败不会半成功”。
- 同时明确：哪些 key 是后续冒烟 Case 的关键依赖（否则容易把“行为不符合预期”误判成“功能坏了”）。

**Given**
- 控制面可用；能拿到一个 app uid。

**When**
- device：GET/SET（幂等）、unknown key、atomic fail（混合法）
- app：GET/SET（tracked、domain.custom.enabled 等）

**Then（期望输出）**
- unknown key → `INVALID_ARGUMENT`
- 混合合法/非法 → 整体失败且状态不变
- 幂等 SET 不改变语义

**常用关键 keys（下游 Case 依赖；建议在每条 Case 里做到：读 orig → 修改 → 最后 restore）**
- device scope：
  - `block.enabled`（全局 gating：domain/ip/metrics/streams）
  - `iprules.enabled`（IPRULES 是否生效）
  - `rdns.enabled`（reverse dns；可能影响部分 DNS/域名相关行为）
  - `perfmetrics.enabled`（perf metrics 开关语义；见「其他 / Case 1」）
  - `block.mask.default`、`block.ifaceKindMask.default`（默认 mask；影响 fallback / iface block 默认值）
- app scope：
  - `tracked`（是否输出 stream；dns/pkt 都依赖）
  - `domain.custom.enabled`（是否参与 custom domain policy；影响 policySource/判决路径）
  - `block.mask`、`block.ifaceKindMask`（app 侧 mask；影响 MASK_FALLBACK / IFACE_BLOCK）

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-06~08d`、`VNT-09~10`

**缺口**
- （新增 Case）把 `domain.custom.enabled=0` 的端到端行为单独写成可验证场景（现在只是“配置能设”，但没形成“触发→输出”的可读用例）

---

### Case 6：Host 工具就绪（python3 / sucre-snort-ctl）
**目的**
- 提前把“host 侧工具没准备好”的问题暴露出来，避免后续 Case 误报为 daemon/设备问题。

**Given**
- 无（这是最前置的 host 环境检查）。

**When**
- 确认 host 侧具备：
  - `python3`（脚本里大量 JSON 断言依赖）
  - `sucre-snort-ctl`（vNext 控制面命令行工具，Case 2/3/4/5 及后续大量用例依赖）

**Then（期望输出）**
- `python3` 可运行
- `sucre-snort-ctl` 可执行（典型位置之一：`build-output/cmake/dev-debug/tests/host/sucre-snort-ctl`）
- 若缺失：明确写出需要构建的 target（例如：`cmake --build --preset dev-debug --target sucre-snort-ctl`）

**现有覆盖**
- 各脚本内部会探测/报错（例如 `find_snort_ctl()`），但没有一个“集中、可读”的前置 Case。

**缺口**
- 无（这是文档层面的补齐；实现可选）。

---

### Case 7：vNext 基线可复位（RESETALL + baseline config）
**目的**
- 确保“每条功能 Case 都能在干净基线下开始”，否则 smoke 变成依赖历史状态的随机回归。

**Given**
- Case 2 已确认 vNext 连通。

**When**
- 执行一次 `RESETALL`
- 建立最小 baseline（示例）：
  - device：`block.enabled=1`、`iprules.enabled=1`
  - app：对目标 uid 设 `tracked=1`（以及后续需要的 `domain.custom.enabled`/`block.ifaceKindMask` 等）

**Then（期望输出）**
- `RESETALL` 返回 ok
- baseline 的 `CONFIG.SET` 均 ack（必要时 `CONFIG.GET` 确认）

**现有覆盖**
- 多处用例都会做 `RESETALL`/baseline（例如 Tier‑1 datapath smoke `VNXDP-02~04`；control baseline 末尾 `VNT-23`）。

**缺口**
- 缺少一条“独立、可读”的基线复位 Case（文档已补；实现可选）。

---

### Case 8：Tier‑1 datapath 前置（netns+veth+路由对 uid 生效）
**目的**
- 如果后续要跑 datapath（IPRULES + pkt stream + traffic/reasons/stats），先确认 Tier‑1 受控网络环境能搭起来。

**Given**
- rooted 真机、adb 可用（Case 1）。

**When**
- 检查工具与能力（设备侧）：
  - `ip`、`ip netns` 可用
  - 能创建/删除 veth
  - `ping`、`nc/netcat` 可用
- 建立 Tier‑1（netns+veth+ip addr+policy route）并验证：
  - `ip route get <peer_ip> uid <target_uid>` 的路径确实走到 veth（否则后续“触发流量”不会进入受控路径）

**Then（期望输出）**
- 前置检查通过；Tier‑1 setup 成功；route 验证命中 veth
- teardown 后环境不残留（避免下一次运行被脏状态污染）

**现有覆盖**
- IP 模组里已有完整检查/搭建/teardown（例如 `tests/device/ip/lib.sh` 的 `iptest_require_tier1_prereqs`、`iptest_tier1_setup`、`iptest_tier1_teardown`）。

**缺口**
- 在 casebook 里需要把它提升为“先决条件 Case”（文档已补；实现可选）。

---

### Case 9：netd resolv hook 就绪（DNS 真实解析前置）
**目的**
- 如果 DNS 端到端冒烟要求“真实 resolver 链路触发”（而不是合成 inject），那必须先确认 netd hook 已激活；否则「域名 / Case 3」应直接 BLOCKED。

**Given**
- rooted 真机、adb 可用（Case 1）。

**When**
- 查看当前 hook 状态（任选其一）：
  - 走 `dx-smoke-platform` 的 Netd Prereq 输出
  - 或直接跑：`bash dev/dev-netd-resolv.sh status`
- 若未就绪：跑 `bash dev/dev-netd-resolv.sh prepare` 再确认

**Then（期望输出）**
- 能明确判断 hook 是否就绪（就绪才允许跑“DNS 真实解析触发”的 smoke Case）

**现有覆盖**
- `dx-smoke-platform` 会提示 hook 是否挂载，但目前语义偏“提示/skip”。

**缺口**
- 若将“DNS 真实解析端到端”视为 smoke gate，需要把 “hook 不活跃”从提示升级为明确 BLOCKED（文档先定口径；实现后续再做）。

---

## 域名

### Case 1：Domain surface（下规则/下策略/下 list）跑通（功能面基线）
**目的**
- 域名腿控制面可用：DOMAINRULES / DOMAINPOLICY / DOMAINLISTS / IMPORT。

**Given**
- 控制面可用。

**When**
1) `DOMAINRULES.APPLY` 下两条规则（domain + regex）
2) `DOMAINPOLICY.APPLY(scope=device)` 引用 ruleIds
3) `DOMAINLISTS.APPLY` upsert 一个 list 元数据
4) `DOMAINLISTS.IMPORT` 导入两条 domain

**Then（期望输出）**
- APPLY/GET 返回 shape 正确，排序/字段符合契约
- IMPORT 返回 imported==2，且 domainsCount 更新

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-15~22`

**缺口**
- 这条偏 “surface”；还缺一个真正的 “DNS 真实触发端到端”（见 Case 3）

---

### Case 2：DomainSources（可观测）能 reset、能增长、受 block.enabled gating
**目的**
- “触发一次判决 → domainSources 计数能增长；reset 能清零；block.enabled=0 时不增长”。

**Given**
- 能拿到 app uid；`block.enabled` 可控。

**When**
- reset → GET 为 0
- `block.enabled=0` → 触发判决 → GET 仍 0
- `block.enabled=1` → 触发判决 → GET 增长
- per-app reset/增长

**Then（期望输出）**
- reset 后 total==0
- gating 生效
- enabled 后 total>=1
- per-app 同理（tracked=0 也应增长）

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-22i3~VNT-22j7`
- 注意：当前“触发判决”使用 `DEV.DOMAIN.QUERY`（稳定，但不是系统真实 resolver 链路）

**缺口**
- （新增 Case）“真实 DNS 解析触发 domainSources/dns stream/traffic(dns)”的端到端（见 Case 3）

---

### Case 3：DNS 端到端（真实解析触发）= 下域名策略 → 解析域名 → 看 dns stream/traffic/domainSources
**目的**
- 你要的典型冒烟：真机上构造 DNS 场景，快速校验输出“对不对”。

**Given**
- `block.enabled=1`
- **netd resolv hook 已激活**（否则这条 Case 应该明确 BLOCKED，并提示如何 prepare）
- 对目标 uid：
- `tracked=1`（为了看到 dns stream）
- （建议）`domain.custom.enabled=1`（为了有更可解释的 policySource；否则常见落到 MASK_FALLBACK）

**When**
- 先把域名策略下到“可预期的 allow/block”
- 例如 `DOMAINPOLICY.APPLY` 把 `bad.com` 放进 block.domains（或通过 rules/lists 达到同等效果）
- 开始观测：
- `STREAM.START(type=dns)`
- `METRICS.RESET(name=traffic, app)`
- `METRICS.RESET(name=domainSources)`（device 或 app）
- 触发一次“真实解析”（避免缓存：用 unique 子域名）：
- 例：`dx-smoke-<ts>.bad.com`
- 在对应 uid 下执行一次会触发解析的命令（不要求最终连通成功，但要触发 resolver）
    - 例如：`nc dx-smoke-<ts>.bad.com 80` 或 `ping dx-smoke-<ts>.bad.com`
- 停止 stream：`STREAM.STOP`

**Then（期望输出）**
- dns stream 至少 1 条匹配 `uid+domain` 的 `type=dns` 事件，且：
- `blocked` 为 bool，并符合策略预期
- `policySource` 合理（不是只检查“是字符串”）
- per-app traffic：
- `dns.allow/dns.block` 至少一项增长
- domainSources：
- 对应 bucket 增长（device 或 app）

**现有覆盖（但不满足“真实解析”要求）**
- 当前 repo 里已经有 “dns stream 端到端”，但它是 **netd inject 合成请求**（不走真实 resolver）：
- `tests/integration/vnext-baseline.sh`：`VNT-10b*`

**缺口**
- （新增）需要把“真实解析触发”写成正式 smoke Case（并把“hook 不活跃”定义为 BLOCKED）
- （完善）dns 事件字段目前只检查少量字段：建议补齐字段覆盖（至少类型正确：`domMask/appMask/getips/useCustomList/
userId/app` 等）

---

## IP

### Case 1：IPRULES surface（能 preflight/apply/print，返回契约正确）
**目的**
- 验证 IPRULES 控制面功能可用（不做流量）。

**Given**
- 控制面可用；有 app uid。

**When**
- `IPRULES.PREFLIGHT` → `IPRULES.APPLY` → `IPRULES.PRINT`

**Then（期望输出）**
- preflight 有 summary/limits/warnings/violations
- apply 有 mapping
- print 排序稳定、CIDR canonical、stats 字段存在

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-22c~22f`
- `tests/device/ip/cases/14_iprules_vnext_smoke.sh`：`VNX-03~05`

**缺口**
- 无

---

### Case 2：Tier‑1 allow（规则生效 + 输出齐）
**目的**
- allow 真的生效（端到端），并且输出齐（stream/metrics/stats）。

**Given**
- Tier‑1 环境就绪（netns+veth），peer 起 TCP server（443）
- 目标 uid：shell 2000（稳定）

**When**
- `IPRULES.APPLY(action=allow,enforce=1,dst=peer/32,dport=443)`
- `STREAM.START(type=pkt)` 抓包事件
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- 功能面：`nc` 应该成功（这才是“人话冒烟”的核心）
- stream：`reasonId=IP_RULE_ALLOW` + `ruleId` 匹配
- metrics：
- `reasons.IP_RULE_ALLOW.packets/bytes` 增长（至少 packets）
- `traffic(app)` 里 `txp/txb` 的 allow 维度增长（不要只看 total）
- per-rule stats：`hitPackets/hitBytes` 增长（至少 hitPackets）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-05~07`

**缺口**
- （完善）当前 datapath smoke 会吞掉 `nc` 成败（`|| true`），缺“allow 就应该能通”的硬断言
- （完善）allow 路径目前没硬断言 `reasons.IP_RULE_ALLOW` 增长
- （完善）traffic 现在以 total 为主，需要补维度级断言
- （完善）per-rule stats 建议补 `hitBytes`

---

### Case 3：Tier‑1 block（规则拦截 + 输出齐）
**目的**
- block 真的拦截（端到端），并且输出齐。

**Given**
- 同 Case 2。

**When**
- `IPRULES.APPLY(action=block,enforce=1,...)`
- `STREAM.START(type=pkt)`
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- 功能面：`nc` 应该失败
- stream：`reasonId=IP_RULE_BLOCK`、`accepted=false`、`ruleId` 匹配
- metrics：`reasons.IP_RULE_BLOCK.packets` 增长
- per-rule stats：`hitPackets/hitBytes` 增长（至少 hitPackets）
- traffic：`txp/txb` 的 block 维度增长（建议）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-08*`

**缺口**
- （完善）同样缺 `nc` 失败的硬断言（当前吞错误）
- （完善）traffic(block 维度) 没看
- （完善）hitBytes 没看

---

### Case 4：Would‑match overlay（enforce=0）解释性闭环
**目的**
- 验证 wouldRuleId：最终 ACCEPT 但带 wouldRuleId（可解释）。

**Given**
- Tier‑1 就绪；最终应是 allow（基线默认允许或已有 allow rule）。

**When**
- 下发 `action=block,enforce=0,log=1` 的规则
- `STREAM.START(type=pkt)` → `nc -z peer_ip 443`

**Then（期望输出）**
- stream：`reasonId=ALLOW_DEFAULT`、`accepted=true`、无 `ruleId`、有 `wouldRuleId=<该规则>`
- metrics：`reasons.ALLOW_DEFAULT.packets` 增长
- per-rule stats：`wouldHitPackets/wouldHitBytes` 增长（至少 wouldHitPackets）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-09*`

**缺口**
- （完善）wouldHitBytes 没看
- （完善）可补“连通性应成功”的硬断言（当前吞错误）

---

### Case 5：IFACE_BLOCK（block.ifaceKindMask）端到端
**目的**
- 验证 iface block：reasonId=IFACE_BLOCK，且不应增长 rule stats。

**Given**
- Tier‑1 就绪；能推导当前 veth 的 iface kind（或 fallback）
- `block.ifaceKindMask` 覆盖当前 kind

**When**
- `CONFIG.SET(scope=app,set={"block.ifaceKindMask":<bit>})`
- `STREAM.START(type=pkt)` → `nc -z peer_ip 443`

**Then（期望输出）**
- stream：`reasonId=IFACE_BLOCK`、`accepted=false`、不含 `ruleId/wouldRuleId`
- metrics：`reasons.IFACE_BLOCK.packets` 增长
- per-rule stats：不因 IFACE_BLOCK 增长（证明“不是 rule 命中”）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-10*`

**缺口**
- （完善）缺“nc 应失败”的硬断言（当前吞错误）
- （完善）traffic(block 维度) 没看

---

### Case 6：block.enabled=0 的 gating（reasons 不应增长）
**目的**
- 验证全局关掉后 reasons 不增长，避免污染。

**Given**
- Tier‑1 就绪。

**When**
- reset reasons → `block.enabled=0` → 触发流量 → GET reasons

**Then（期望输出）**
- totalPackets==0

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-11*`

**缺口**
- 无

---

## IP - Conntrack

### Case 1：conntrack（ct.new / ct.established）最小闭环
**目的**
- 验证 L4 state 可用：能按 state/direction 区分，能形成明确“该通/该断”。

**Given**
- Tier‑1 就绪；peer 起 TCP server（默认 18081）
- 目标 uid 可联网（能真的建立 TCP 并传输字节）

**When**
- 下两条 allow（new+orig / established+reply）
- 触发一次 TCP 读写（读一定字节）
- 再下 `new+orig` 的 block
- 再触发一次 TCP（应被拦）

**Then（期望输出）**
- allow 阶段：两条规则 hitPackets 都增长
- block 阶段：读到字节数为 0（或连接失败）
- reasons：`IP_RULE_BLOCK.packets` 增长

**现有覆盖**
- `tests/device/ip/cases/22_conntrack_ct.sh`（当前在 profile=matrix，不在 dx-smoke 主链里）

**缺口**
- （新增）把这条作为 smoke 级用例纳入（或至少明确列为“第一阶段建议新增 smoke case”）

---

## 其他

Diagnostics 里“其实更像 smoke 的功能验证”（候选）

### Case 1：perfmetrics.enabled 功能语义（off 必须 0；on 必须增长）
**目的**
- 这是“功能可用性验证”（开关生效 + 输出存在），不一定要跑公网大下载。

**Given**
- 控制面可用；能触发一定量流量（理想是 Tier‑1 受控流量）。

**When**
- `perfmetrics.enabled=0` → 触发流量 → GET(perf)
- `perfmetrics.enabled=1` + RESET(perf) → 再触发流量 → GET(perf)
- 再测 1->1 不清空；非法值拒绝

**Then（期望输出）**
- off：`nfq_total_us.samples==0`
- on：`nfq_total_us.samples>=1`
- 1->1 不清空 aggregates
- 非法值拒绝

**现有覆盖**
- 目前在 diagnostics：`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
- 它混了“公网下载跑量”（更偏诊断/性能）

**缺口**
- （建议拆分，调查先记录）把“功能语义”提炼成 smoke 版本（用 Tier‑1 受控流量触发）；原脚本保留做 diagnostics/perf

---

## 7) 缺口清单（按你要的两类：完善已有 / 新增用例）

### A) 完善已有用例（同一场景，补“该看的输出”）
1) **IP allow/block/iface/would**：把 `nc` 成败变成硬断言（现在普遍 `|| true` 吞掉结果）
2) **traffic metrics**：从 “total>=1” 升级为“维度级增长”
    - IP：至少看 `txp/txb` 的 allow/block
    - DNS：看 `dns.allow/dns.block`
3) **reasons metrics**：补 allow 路径 `IP_RULE_ALLOW` 的 packets/bytes 增长断言
4) **per-rule stats**：补 `hitBytes / wouldHitBytes`（现在主要看 hitPackets/wouldHitPackets）
5) **dns stream 事件字段**：补更多字段类型/一致性校验（不只看 blocked/policySource）

### B) 新增用例（现在没有这个“人话场景”）
1) **DNS 真机真实解析端到端冒烟（强需求）**
    - 明确“netd hook 不活跃”= BLOCKED（给出 prepare 命令）
    - 同时覆盖 shell uid=2000 + 真实 app uid 两条触发路径
2) **conntrack（L4 state）最小闭环纳入 smoke**
3) **perfmetrics 功能语义 smoke 版本（从 diagnostics 提炼）**
    - 用 Tier‑1 受控流量触发，不依赖公网 URL

---

## 8) 附：脚本与 check id 回查索引
- platform：`tests/integration/dx-smoke-platform.sh`
- control baseline：`tests/integration/vnext-baseline.sh`
- stream dns（当前是 netd inject）：`VNT-10b*`
- domain surface：`VNT-15~22`
- domainSources 行为：`VNT-22i* / VNT-22j*`
- datapath（Tier‑1）：`tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`
- allow：`VNXDP-05~07`
- traffic reset/grow/reset：`VNXDP-05c~06d`
- block：`VNXDP-08*`
- would：`VNXDP-09*`
- iface：`VNXDP-10*`
- gating：`VNXDP-11*`
- conntrack（Tier‑1）：`tests/device/ip/cases/22_conntrack_ct.sh`
- diagnostics：`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
