# Device / DX 冒烟测试 Casebook（真机端到端；人话版）

更新时间：2026-06-18

这份文档是 **Device / DX active acceptance casebook**：把当前“真机端到端能不能用”的测试，按 **Case（下规则→触发→看输出）**写清楚：
- 哪些已经在 smoke 里测到了（现有覆盖）
- 哪些“看了但没看全”（需要完善断言/输出；开放工作以 Plane `SNORT` 为准）
- 哪些“场景本身没覆盖”（需要新增 Case；开放工作以 Plane `SNORT` 为准）
- 哪些现在挂在 diagnostics 但其实更像 smoke（功能可用性验证）

SNORT-10 一致性说明：
- 本文保留部分 pre-SNORT-10 current-head / frozen 测试证据；这些证据不能覆盖当前 SNORT-10 接口契约。
- packet-side 诊断目标是 session-owned Packet Diagnostics：`DIAGNOSTICS.START(channel=packet)`、`diagnostic.packet.final.{accepted,reasonId,ruleId?,ruleMode?}`。
- 旧 generic `STREAM.START(type=pkt|activity)`、持久 `tracked` gate、`wouldRuleId/wouldDrop`、suppressed notice、legacy `host/domain` packet join、旧 `METRICS.GET(name=traffic)` 和 `perfmetrics.enabled` bool 只作为 current-head / historical evidence，后续 issue 不得以它们为新目标。

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

可选 Casebook（非默认 gate；需要显式运行）：
- `tests/device/diagnostics/dx-casebook-other.sh`（`## 其他` Case 1–2；不进入默认 `dx-smoke` 主链）

---

## 1) Case 写法模板（每条都“人话”）

每条 Case 固定包含：
- **目的**：验证什么能力
- **Given（前置）**：需要什么环境/开关/基线
- **When（操作/触发）**：下什么规则、发什么流量、怎么触发
- **Then（期望输出）**：要看到哪些输出（连通性 / stream / metrics / stats）
- **现有覆盖**：现在脚本里哪里已经测了（脚本 + check id）
- **覆盖状态**：已覆盖 / 部分覆盖 / Plane follow-up
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
- host→device 的 vNext 控制面最小连通性成立（至少 `HELLO` 握手能成功；完整的 QUIT/reconnect 见 Case 2）
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

### Case 3：pre-SNORT-10 Stream 基本机制可用（activity；frozen current-head evidence）
**目的**
- START 能收到 started notice + 至少 1 条事件；STOP 有 barrier（短窗口内不再有 frame）。
- 这条只证明 legacy/generic stream current-head 能力；SNORT-10 packet-side 诊断不继续扩展 activity stream，而使用 Packet Diagnostics。

**Given**
- 控制面可用。

**When**
- legacy `STREAM.START(type=activity)` → 收事件 → `STREAM.STOP`。

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
  - `perfmetrics.level`（SNORT-10 perf metrics level；pre-SNORT-10 `perfmetrics.enabled` 仅作迁移 evidence，见「其他 / Case 1」）
  - `block.mask.default`、`block.ifaceKindMask.default`（默认 mask；影响 fallback / iface block 默认值）
- app scope：
  - `tracked`（pre-SNORT-10 DNS/packet stream gate；SNORT-10 packet diagnostics 不依赖它，DNS stream 暂时冻结）
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
- `tests/integration/dx-smoke-platform.sh`：集中检查 `python3` + `sucre-snort-ctl`，缺失时明确 `BLOCKED` 并给出 build hint
- 其他脚本也会二次探测/报错（例如 `tests/integration/vnext-baseline.sh` 的 `find_snort_ctl()`），但平台 gate 已把它前置化

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
- 如果 DNS 端到端冒烟要求“真实 resolver 链路触发”（而不是合成 inject），那必须先确认 netd hook 已激活；否则「域名 / Case 8」应直接 BLOCKED。

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

SNORT-10 说明：本章节保留 DNS/domain line 的 pre-SNORT-10 current-head / frozen evidence。这里的 `tracked`、DNS stream、suppressed notice、`traffic.dns` 与 resolver-hook case 只说明现有 DNS 线测试事实；SNORT-10 packet-side 重构不把这些能力迁入 Packet Diagnostics，也不实现 Domain-IP Association / Resolved-IP Policy / RDNS 联动。

### Case 1：Domain surface（下规则/下策略/下 list）跑通（功能面基线）
**目的**
- 域名腿控制面可用：DOMAINRULES / DOMAINPOLICY / DOMAINLISTS / IMPORT。
- 这条只覆盖“能下发/能回读/契约正确”；真正的“触发→可观测”见 Case 3/4/8。

**Given**
- 控制面可用。

**When**
1) `DOMAINRULES.APPLY` 下两条规则（domain + regex）
2) `DOMAINPOLICY.APPLY(scope=device)` 引用 ruleIds
3) `DOMAINLISTS.APPLY` upsert 一个 list 元数据 + remove 一个 unknown id
4) `DOMAINLISTS.IMPORT` 导入两条 domain

**Then（期望输出）**
- DOMAINRULES：APPLY/GET 返回 shape 正确，排序/字段符合契约
- DOMAINPOLICY：APPLY 为 ack-only；GET 能回读到 policy（domains/ruleIds）
- DOMAINLISTS：
  - APPLY/GET 返回 shape 正确；lists[] 排序稳定；remove unknown 走 notFound[]
  - IMPORT 返回 imported==2，且 domainsCount 更新（其他元数据不应被覆盖）

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-15~22`
- `tests/integration/vnext-domain-casebook.py`（经 `dx-smoke-control` 调用）：`VNT-DOM-01a~01b`

**缺口**
- 已补齐：`DOMAINLISTS.IMPORT` unknown listId → `INVALID_ARGUMENT` + hint；`DOMAINRULES.APPLY` 删除仍被 policy 引用的 ruleId → `INVALID_ARGUMENT` + conflicts[] + hint。

---

### Case 2：DomainSources（可观测）能 reset、能增长、受 block.enabled gating
**目的**
- “触发一次判决 → domainSources 计数能增长；reset 能清零；block.enabled=0 时不增长”。
- 明确一个关键点：`DEV.DOMAIN.QUERY` **只**影响 domainSources，不会推动 `traffic.dns`（`traffic.dns` 必须走 DnsListener：Case 3/4/8）。

**Given**
- 能拿到 app uid；`block.enabled` 可控。

**When**
- reset → GET 为 0
- `block.enabled=0` → 触发判决 → GET 仍 0
- `block.enabled=1` → 触发判决 → GET 增长
- per-app reset/增长

**Then（期望输出）**
- reset 后 total==0（对 `sources.*.(allow|block)` 求和）
- gating 生效（`block.enabled=0` 时不增长）
- enabled 后 total>=1
- per-app 同理（tracked=0 也应增长）

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-22i3~VNT-22j7`
- 注意：当前“触发判决”使用 `DEV.DOMAIN.QUERY`（稳定，但不是系统真实 resolver 链路）
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-02` 覆盖 APP / DEVICE_WIDE / FALLBACK bucket 级增长。

**缺口**
- 已补齐 bucket 级覆盖：APP=`CUSTOM_*`（Case 3/6）、DEVICE_WIDE=`DOMAIN_DEVICE_WIDE_*`（Case 6）、FALLBACK=`MASK_FALLBACK`（Case 7）。

---

### Case 3：DNS stream 端到端（netd inject；稳定触发）= 下策略 → inject → 看 dns stream/traffic/domainSources
**目的**
- 在真机上**稳定触发** DNS 事件（不依赖真实 resolver/hook），验证：
  - dns stream event 字段齐全且可解释
  - `traffic(dns)` / `domainSources` 稳定增长

**Given**
- `block.enabled=1`
- 有一个 app uid（建议来自 `APPS.LIST`）
- 对目标 uid：
  - `tracked=1`（为了看到 dns stream）
  - `domain.custom.enabled=1`（为了命中 `CUSTOM_*` policySource + `scope=APP`；否则这条 Case 的 Then 不可预测）
- 设备上有 `dx-netd-inject`（默认：`/data/local/tmp/dx-netd-inject`，root 可执行）
  - 若缺失：`bash dev/dev-build-dx-netd-inject.sh` 构建 + `adb push` 到设备 + `chmod 755`

**When**
- 准备两个域名（避免缓存/混淆）：
  - allow：`dx-inject-allow-<ts>.example.test`
  - block：`dx-inject-block-<ts>.example.test`
- 下策略（app scope，确保 policySource 可预期）：
  - `DOMAINPOLICY.APPLY(scope=app)`：allow.domains=[allow]、block.domains=[block]
- 开始观测：
  - `STREAM.START(type=dns)`
  - `METRICS.RESET(name=traffic, app)`
  - `METRICS.RESET(name=domainSources, app)`
- 触发两次 inject：
  - 例：`adb shell su -c "/data/local/tmp/dx-netd-inject --uid <uid> --domain <allow>"`
  - 例：`adb shell su -c "/data/local/tmp/dx-netd-inject --uid <uid> --domain <block>"`
- 停止 stream：`STREAM.STOP`

**Then（期望输出）**
- dns stream：
  - 有 `notice.started`
  - 至少 2 条 `type=dns` 事件（allow + block），且字段类型正确：
    - `uid/userId/app/domain/domMask/appMask/blocked/policySource/useCustomList/scope/getips`
  - allow 那条：`blocked=false`、`getips=true`、`policySource=CUSTOM_WHITELIST`、`scope=APP`、`useCustomList=true`
  - block 那条：`blocked=true`、`getips=false`、`policySource=CUSTOM_BLACKLIST`、`scope=APP`、`useCustomList=true`
- per-app traffic：`traffic.dns.allow>=1` 且 `traffic.dns.block>=1`
- domainSources(app)：`CUSTOM_WHITELIST.allow>=1` 且 `CUSTOM_BLACKLIST.block>=1`

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-10b*`（但目前只验证 start→event→stop，不看 metrics）
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-03`

**缺口**
- 已补齐：dns event 字段、`traffic.dns.allow/block`、`domainSources` `CUSTOM_WHITELIST.allow` / `CUSTOM_BLACKLIST.block`。

---

### Case 4：tracked=0 的可解释闭环（suppressed notice；metrics 仍增长）
**目的**
- 复现/验证“为什么我看不到 dns stream”：
  - tracked=0 时不应产生 dns event
  - 但应发 `notice.suppressed`（带 traffic snapshot + hint）
  - 同时 `traffic(dns)` / `domainSources` 仍增长（功能在跑，只是被 suppress）

**Given**
- 同 Case 3，但将目标 uid 设为 `tracked=0`
- 建议先确保 dns stream ring 清空（`STREAM.STOP` 或 `RESETALL`），否则 START 可能 replay 旧 event

**When**
- `STREAM.START(type=dns)` + RESET metrics（`traffic/domainSources`，app）
- 用 `dx-netd-inject` 触发 2~3 次（allow/block 任意）
- 等待 >=1s（suppressed notice 以 1s 粒度 best-effort 推送）
- `STREAM.STOP`

**Then（期望输出）**
- stream 中出现 `type=notice notice=suppressed stream=dns`
  - notice.traffic.dns.allow|block 至少一项 >0
  - 且有 hint 提示 tracked 的打开方式
- 不应出现“本次触发对应”的 `type=dns` 事件（tracked=0）
- `METRICS.GET(name=traffic, app)` 的 `traffic.dns.*` 增长
- `METRICS.GET(name=domainSources, app)` 的 `sources.*` 增长

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-22j2~22j5` 覆盖 “tracked=0 时 domainSources 仍增长”（但未覆盖 suppressed notice / traffic.dns）
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-04`

**缺口**
- 已补齐：`notice.suppressed`、notice traffic snapshot/hint、无本次 dns event、`traffic.dns` 与 `domainSources` 增长。

---

### Case 5：domain.custom.enabled 语义（0/1 必须改变判决路径）
**目的**
- 验证 app 的 custom 开关真正影响判决：
  - 1：custom/app/device policy 生效（`CUSTOM_* / DOMAIN_DEVICE_WIDE_*`）
  - 0：全部回落到 `MASK_FALLBACK`（`policySource=MASK_FALLBACK`，`scope=FALLBACK`）

**Given**
- 有 app uid；`block.enabled=1`
- 选择一个“尽量不在 blocking lists 里”的测试域名（避免 fallback 被 list 误伤）

**When**
- 准备域名：`dx-custom-<ts>.example.test`
- 下 app policy：`DOMAINPOLICY.APPLY(scope=app)` 把该域名放进 block.domains
- `METRICS.RESET(name=domainSources, app)`
- `CONFIG.SET(scope=app,set={"domain.custom.enabled":1})` → `DEV.DOMAIN.QUERY(domain=该域名)`
- `CONFIG.SET(scope=app,set={"domain.custom.enabled":0})` → `DEV.DOMAIN.QUERY(domain=该域名)`
- （最后）restore `domain.custom.enabled` + 清理 policy（建议：读 orig → 修改 → restore）

**Then（期望输出）**
- enabled=1：`DEV.DOMAIN.QUERY.result.policySource=="CUSTOM_BLACKLIST"` 且 `blocked==true`
- enabled=0：`policySource=="MASK_FALLBACK"`，且（若域名不在 list 里）`blocked==false`
- `METRICS.GET(name=domainSources, app)` 中：
  - `CUSTOM_BLACKLIST.block` 增长（enabled=1 的那次）
  - `MASK_FALLBACK.allow|block` 增长（enabled=0 的那次）

**现有覆盖**
- 配置可设：`tests/integration/vnext-baseline.sh`：`VNT-09~10`
- domainSources 基本增长：`tests/integration/vnext-baseline.sh`：`VNT-22i* / VNT-22j*`
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-05`

**缺口**
- 已补齐：`domain.custom.enabled=1` 命中 `CUSTOM_BLACKLIST`，`0` 回落 `MASK_FALLBACK`，并校验对应 `domainSources` bucket。

---

### Case 6：device vs app policy 优先级（APP 覆盖 DEVICE_WIDE；scope 必须可解释）
**目的**
- 验证优先级与输出解释一致：
  - APP 策略命中：`policySource=CUSTOM_*`，`scope=APP`
  - 仅 DEVICE 策略命中：`policySource=DOMAIN_DEVICE_WIDE_*`，`scope=DEVICE_WIDE`

**Given**
- `block.enabled=1`
- 对目标 uid：`tracked=1`、`domain.custom.enabled=1`（否则这条 Case 没意义）
- `dx-netd-inject` 就绪（见 Case 3）

**When**
- 准备域名：
  - d1：`dx-prio-1-<ts>.example.test`（device block + app allow）
  - d2：`dx-prio-2-<ts>.example.test`（device allow + app block）
  - d3：`dx-prio-3-<ts>.example.test`（device block only）
- 开始观测：`STREAM.START(type=dns)` + RESET metrics（`traffic/domainSources`，app）
- 场景 1（APP 覆盖 DEVICE_WIDE）：
  - device：block d1
  - app：allow d1
  - inject d1
- 场景 2（APP 覆盖 DEVICE_WIDE）：
  - device：allow d2
  - app：block d2
  - inject d2
- 场景 3（DEVICE_WIDE 生效）：
  - device：block d3
  - app：不配置 d3
  - inject d3
- `STREAM.STOP`（并建议 restore policy，避免污染后续 Case）

**Then（期望输出）**
- d1：`blocked=false`、`policySource=CUSTOM_WHITELIST`、`scope=APP`、`useCustomList=true`
- d2：`blocked=true`、`policySource=CUSTOM_BLACKLIST`、`scope=APP`、`useCustomList=true`
- d3：`blocked=true`、`policySource=DOMAIN_DEVICE_WIDE_BLOCKED`、`scope=DEVICE_WIDE`、`useCustomList=true`
- traffic(app)：`traffic.dns.allow` 与 `traffic.dns.block` 增长（至少各 1）
- domainSources(app)：对应 bucket 增长

**现有覆盖**
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-06`

**缺口**
- 已补齐：APP allow 覆盖 device block、APP block 覆盖 device allow、device-only block 三条路径。

---

### Case 7：DomainLists 的 enable/disable 与 allow 覆盖 block（mask fallback 可解释闭环）
**目的**
- 验证 blocking list 真正影响判决（`domMask/appMask`），且 allow list 能覆盖 block list。

**Given**
- `block.enabled=1`
- 对目标 uid：`tracked=1`
- `domain.custom.enabled=0`，避免 custom/global 干扰，让 `useCustomList=false`，并让判决稳定走 `MASK_FALLBACK`
- （建议）显式设置 `block.mask` 覆盖该 list 的 mask（例如设为 `1`），避免依赖 app 默认值
- `dx-netd-inject` 就绪（见 Case 3）

**When**
- 生成两个 listId（GUID）：
  - block list：Lb（`listKind=block`，`mask=1`，`enabled=1`）
  - allow list：La（`listKind=allow`，`mask=1`，`enabled=1`）
- 准备域名：`dx-list-<ts>.example.test`
- `DOMAINLISTS.APPLY` 创建/启用 Lb
- `DOMAINLISTS.IMPORT` 向 Lb 导入域名（clear=1）
- `STREAM.START(type=dns)` + RESET metrics（`traffic/domainSources`，app）
- inject 域名（block list 生效）
- `DOMAINLISTS.APPLY` 将 Lb `enabled=0`
- inject 域名（应变为 allow）
- `DOMAINLISTS.APPLY` 重新将 Lb `enabled=1`
- `DOMAINLISTS.APPLY` 创建/启用 La + `DOMAINLISTS.IMPORT` 导入同一域名
- inject 域名（allow 覆盖 block）
- `STREAM.STOP`
- （可选清理）`DOMAINLISTS.APPLY(remove=[Lb,La])`

**Then（期望输出）**
- block list 生效时 dns event：
  - `policySource=MASK_FALLBACK`、`scope=FALLBACK`、`blocked=true`、`useCustomList=false`
  - `domMask` 包含 bit1，`appMask` 包含 bit1
- disable Lb 后：
  - `blocked=false`，且 `domMask==0`（不再被 list 标记），并且 `useCustomList=false`
- La 开启时（同时 Lb 仍 enabled）：
  - `blocked=false`，且 `domMask==0`（whitelist override），并且 `useCustomList=false`
- `traffic/domainSources` 对应增长（至少 `MASK_FALLBACK` 的 allow/block 各增长一次）

**现有覆盖**
- list surface：`tests/integration/vnext-baseline.sh`：`VNT-19~22`
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-07`

**缺口**
- 已补齐：enabled block list、disabled block list、allow 覆盖 block 的 DNS verdict 与 metrics 闭环。

---

### Case 8：DNS 端到端（真实解析触发；依赖 netd hook）= 下域名策略 → 解析域名 → 看 dns stream/traffic/domainSources
**目的**
- 你要的典型冒烟：真机上走真实 resolver 链路触发 DNS 决策，快速校验输出“对不对”。

**Given**
- `block.enabled=1`
- **netd resolv hook 已激活**（否则这条 Case 应明确 BLOCKED；见「Platform / Case 9」）
- 目标 uid：
  - 最低保真：shell uid=2000（最容易构造）
  - 进阶：真实 app uid（如果设备支持 `run-as <pkg>` 或 `su -u <uid>`）
- `tracked=1`（为了看到 dns stream）
- （建议）`domain.custom.enabled=1`（为了有更可解释的 policySource；否则常见落到 `MASK_FALLBACK`）

**When**
- 选择一个“会被阻断”的测试域名（这样 `getips=false`，不依赖外网解析成功）：
  - 例：`dx-real-<ts>.blocked.example.test`
- 下策略让它必定 block（app 或 device 均可；建议用 app custom blacklist）
- 开始观测：
  - `STREAM.START(type=dns)`
  - `METRICS.RESET(name=traffic, app)`
  - `METRICS.RESET(name=domainSources, app)`
- 触发一次真实解析（避免缓存：用 unique 子域名）：
  - shell uid：执行一次会触发 getaddrinfo 的命令；smoke 优先用 `nc -z -w 1 <domain> 80`，无 `nc` 时再退回 `ping -c 1 -W 1 <domain>`
  - 真实 app uid：同上，但在该 uid 的进程上下文运行
- 停止 stream：`STREAM.STOP`

**Then（期望输出）**
- dns stream 至少 1 条匹配 `uid+domain` 的 `type=dns` 事件，且字段类型正确：
  - `uid/userId/app/domain/domMask/appMask/blocked/policySource/useCustomList/scope/getips`
- `blocked==true` 且 `getips==false`（按策略）
- （若按推荐：app custom blacklist + `domain.custom.enabled=1`）该事件应为：
  - `policySource=CUSTOM_BLACKLIST`、`scope=APP`、`useCustomList=true`
- per-app traffic：`traffic.dns.block` 增长
- domainSources(app)：对应 bucket 的 block 增长
- 若 hook 未激活：这条 Case 应直接 BLOCKED（而不是静默通过）

**现有覆盖（但不满足“真实解析”要求）**
- 当前已有 “dns stream 端到端”，但它是 **netd inject 合成请求**：
  - `tests/integration/vnext-baseline.sh`：`VNT-10b*`（见「本模块 / Case 3」）
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-08`（hook 就绪时执行真实 resolver；hook 不活跃时报 `BLOCKED` 并提示 `dev/dev-netd-resolv.sh status|prepare`）

**缺口**
- 已补齐 smoke 口径：优先用 shell uid=2000 + `nc` 做真实 resolver 触发；hook 未激活或 shell uid 无法建立可观测 app 时为明确 `BLOCKED`。

---

### Case 9：DOMAINRULES（ruleIds）端到端（CUSTOM_RULE_*；netd inject）
**目的**
- 验证 `DOMAINRULES + DOMAINPOLICY(ruleIds)` 路径能真正被 DNS 判决命中，并且在 dns stream / traffic / domainSources 上都可解释。
- 这条 Case 专门覆盖 `policySource=CUSTOM_RULE_WHITE/CUSTOM_RULE_BLACK` 两个 bucket（否则很容易长期无人触达）。

**Given**
- `block.enabled=1`
- 目标 uid：`tracked=1`、`domain.custom.enabled=1`
- `dx-netd-inject` 就绪（见 Case 3）

**When**
1) （建议）保存 baseline：`DOMAINRULES.GET`（用于最后 restore）
2) `DOMAINRULES.APPLY` 新增两条规则（命中方式用“精确 domain + regex”各覆盖一条）：
   - allow rule：`type=domain`，`pattern=dx-rule-allow-<ts>.example.test`
   - block rule：`type=regex`，`pattern=^dx-rule-block-<ts>\\.example\\.test$`
3) `DOMAINPOLICY.APPLY(scope=app)`：
   - allow.ruleIds=[<allowRuleId>]
   - block.ruleIds=[<blockRuleId>]
   - （建议）不要同时把这两个域名放进 allow.domains/block.domains，避免 policySource 被 `CUSTOM_(WHITE|BLACK)LIST` 抢走
4) 开始观测：`STREAM.START(type=dns)` + RESET metrics（`traffic/domainSources`，app）
5) inject 两次（使用同一个 `<ts>`，避免缓存/混淆）：
   - `dx-rule-allow-<ts>.example.test`
   - `dx-rule-block-<ts>.example.test`
6) `STREAM.STOP`
7) （建议）restore：回滚到 baseline rules / 清理 policy，避免污染后续 Case

**Then（期望输出）**
- dns stream 至少 2 条事件（allow + block），且字段类型正确
- allow 那条：
  - `blocked=false`、`getips=true`
  - `policySource=CUSTOM_RULE_WHITE`、`scope=APP`、`useCustomList=true`
- block 那条：
  - `blocked=true`、`getips=false`
  - `policySource=CUSTOM_RULE_BLACK`、`scope=APP`、`useCustomList=true`
- traffic(app)：`traffic.dns.allow>=1` 且 `traffic.dns.block>=1`
- domainSources(app)：`CUSTOM_RULE_WHITE.allow>=1` 且 `CUSTOM_RULE_BLACK.block>=1`

**现有覆盖**
- `tests/integration/vnext-domain-casebook.py`：`VNT-DOM-09`

**缺口**
- 已补齐：生成 exact-domain allow rule + regex block rule，app policy 引用 ruleIds，校验 `CUSTOM_RULE_WHITE/BLACK` stream 与 metrics，并在失败路径恢复 rules/policy。

---

## IP

这一组 Case 的目标：验证 `IPRULES/IFACE_BLOCK` 在真机 Tier‑1 受控拓扑下的端到端可用性（下规则→触发→看 verdict + 输出）。

SNORT-10 口径：下面直接 `IPRULES.PREFLIGHT/APPLY/PRINT` 的控制面步骤是 pre-SNORT-10 current-head evidence。SNORT-10 新目标应通过 Authoring Layer 的 Draft / Commit / Apply / Runtime Snapshot 生效模型表达；datapath 断言仍可复用 verdict、reason、rule stats、Packet Diagnostics、Traffic Windows 等语义。

关键口径/开关（避免“以为测了，其实没测到”）：
- `block.enabled`：全局 datapath gate；关掉后 NFQ 不介入，pkt stream / reasons / traffic 都不会增长（也不会产生 pkt suppressed）。
- `iprules.enabled`：IPRULES fast path gate（当前仅 IPv4）；关掉后即使 rules 存在也不会命中，reason 回落到 `ALLOW_DEFAULT`（除非走 legacy `IP_LEAK_BLOCK`）。
- **bytes 指标口径**：`traffic.*b` 与 per-rule `*Bytes` 统计的是 NFQUEUE 看到的 IP 包长度（包含 IP header；不包含 L2）。`nc -z` 也会增长 bytes，但量很小且波动；要做“稳定/有意义”的 bytes 断言，推荐固定读写 N bytes 的 payload 流量（见「IP / Case 8」）。

### Case 1：pre-SNORT-10 direct IPRULES surface（能 preflight/apply/print，返回契约正确）
**目的**
- 记录 current-head direct IPRULES 控制面功能可用（不做流量）。SNORT-10 新 mutation/checkpoint contract 以 Authoring Layer 为目标，不以这个 direct surface 继续扩展。

**Given**
- 控制面可用；有 app uid。

**When**
- pre-SNORT-10 direct `IPRULES.PREFLIGHT` → `IPRULES.APPLY` → `IPRULES.PRINT`

**Then（期望输出）**
- preflight 有 summary/limits/warnings/violations
- apply 有 mapping
- print 排序稳定、CIDR canonical、stats 字段存在

**现有覆盖**
- `tests/integration/vnext-baseline.sh`：`VNT-22c~22f`
- `tests/device/ip/cases/14_iprules_vnext_smoke.sh`：`VNX-03~05`（含 `IPRULES.PRINT` stats shape）

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
- pre-SNORT-10 direct `IPRULES.APPLY(action=allow,enforce=1,dst=peer/32,dport=443)`
- SNORT-10 target：`DIAGNOSTICS.START(channel=packet, app=...)` 抓 `diagnostic.packet`；pre-SNORT-10 current-head 可用 pkt stream 作为历史 evidence。
- （建议，为了确定性）`METRICS.RESET(name=reasons)`；Traffic Windows 可用时用 `TRAFFIC_WINDOWS.RESET` / `TRAFFIC_WINDOWS.GET` 验证 traffic window，旧 `METRICS.RESET(name=traffic, app)` 仅作 current-head evidence。
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- 功能面：`nc` 应该成功（这才是“人话冒烟”的核心）
- Packet Diagnostics：满足「可观测性 / Case 1」字段契约，且 `final.reasonId=IP_RULE_ALLOW`、`final.accepted=true`、`final.ruleId` 匹配、`final.ruleMode=enforce`
- metrics：
  - `reasons.IP_RULE_ALLOW.packets>=1`
  - Traffic Windows app scope `directions.out.acceptedPackets>=1`（旧 current-head evidence 可继续看 `traffic(app).txp.allow>=1`，不要只看 total）
  - （可选：若触发了 payload 流量）Traffic Windows `acceptedBytes>=1` 且 `reasons.IP_RULE_ALLOW.bytes>=1`
- per-rule stats：`hitPackets>=1`（可选：payload 时 `hitBytes>=1`）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-05~07`

**缺口**
- 已补齐：`VNXDP-06` 硬断言 TCP 成功；`VNXDP-06b~06d` 当前断言 pre-SNORT-10 pkt stream、`reasons.IP_RULE_ALLOW` 与旧 `traffic.txp.allow`；SNORT-10 后应迁移到 Packet Diagnostics 与 Traffic Windows；`VNXDP-07` 断言 rule `hitPackets`。
- bytes hard assert 归入「IP / Case 8」的 payload 流量闭环（`VNXDP-13*`），避免在短连接上做波动断言。

---

### Case 3：Tier‑1 block（规则拦截 + 输出齐）
**目的**
- block 真的拦截（端到端），并且输出齐。

**Given**
- 同 Case 2。

**When**
- pre-SNORT-10 direct `IPRULES.APPLY(action=block,enforce=1,...)`
- SNORT-10 target：`DIAGNOSTICS.START(channel=packet, app=...)`；pre-SNORT-10 current-head 可用 pkt stream 作为历史 evidence。
- （建议，为了确定性）`METRICS.RESET(name=reasons)`；Traffic Windows 可用时用 `TRAFFIC_WINDOWS.RESET` / `GET`，旧 `METRICS.RESET(name=traffic, app)` 仅作 current-head evidence。
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- 功能面：`nc` 应该失败
- Packet Diagnostics：满足「可观测性 / Case 1」字段契约，且 `final.reasonId=IP_RULE_BLOCK`、`final.accepted=false`、`final.ruleId` 匹配、`final.ruleMode=enforce`
- metrics：
  - `reasons.IP_RULE_BLOCK.packets>=1`
  - Traffic Windows app scope `directions.out.blockedPackets>=1`（旧 current-head evidence 可继续看 `traffic(app).txp.block>=1`）
- per-rule stats：`hitPackets>=1`

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-08*`

**缺口**
- 已补齐：`VNXDP-08f` 硬断言 TCP 失败；`VNXDP-08g~08j` 当前断言 pre-SNORT-10 pkt stream、`reasons.IP_RULE_BLOCK`、旧 `traffic.txp.block` 与 rule `hitPackets`；SNORT-10 后应迁移到 Packet Diagnostics 与 Traffic Windows。

---

### Case 4：Observe mode（pre-SNORT-10 enforce=0 / would-match evidence 的替代目标）
**目的**
- 验证 observe 规则：规则作为 winner 命中，但实际 verdict 仍按 observe 语义保持 allow，并通过 `ruleMode=observe` 解释。旧 `wouldRuleId/wouldDrop` 只作为 pre-SNORT-10 evidence，不作为 SNORT-10 目标。

**Given**
- Tier‑1 就绪；最终应是 allow（基线默认允许或已有 allow rule）。

**When**
- 下发 observe-mode 的 block rule（pre-SNORT-10 current-head 可对应 `action=block,enforce=0,log=1`）
- SNORT-10 target：`DIAGNOSTICS.START(channel=packet, app=...)`
- （建议，为了确定性）`METRICS.RESET(name=reasons)`；旧 `METRICS.RESET(name=traffic, app)` 仅作 current-head evidence。
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- Packet Diagnostics：满足「可观测性 / Case 1」字段契约，且 `final.accepted=true`、`final.ruleId=<该规则>`、`final.ruleMode=observe`；`reasonId` 跟随 actual verdict，不输出 `wouldRuleId/wouldDrop`
- metrics：
  - `reasons.ALLOW_DEFAULT.packets>=1`
  - Traffic Windows app scope `directions.out.acceptedPackets>=1`（旧 current-head evidence 可继续看 `traffic(app).txp.allow>=1`）
- per-rule stats：observe winner 仍计入该 rule 的 hit counters；旧 `wouldHitPackets/wouldHitBytes` 只作 pre-SNORT-10 evidence

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-09*`

**缺口**
- 已补齐：`VNXDP-09f` 硬断言 TCP 成功；`VNXDP-09g~09j` 当前断言 pre-SNORT-10 `ALLOW_DEFAULT + wouldRuleId`、`reasons.ALLOW_DEFAULT`、旧 `traffic.txp.allow` 与 `wouldHitPackets`；SNORT-10 后应迁移到 `ruleMode=observe` 与统一 winner attribution。
- bytes 口径统一由「IP / Case 8」payload 流量覆盖。

---

### Case 5：IFACE_BLOCK（block.ifaceKindMask）端到端
**目的**
- 验证 iface block：reasonId=IFACE_BLOCK，且不应增长 rule stats。

**Given**
- Tier‑1 就绪；能推导当前 veth 的 iface kind（或 fallback）
- `block.ifaceKindMask` 覆盖当前 kind

**When**
- `CONFIG.SET(scope=app,set={"block.ifaceKindMask":<bit>})`
- SNORT-10 target：`DIAGNOSTICS.START(channel=packet, app=...)`；pre-SNORT-10 current-head 可用 pkt stream 作为历史 evidence。
- （建议，为了确定性）`METRICS.RESET(name=reasons)`；Traffic Windows 可用时用 `TRAFFIC_WINDOWS.RESET` / `GET`，旧 `METRICS.RESET(name=traffic, app)` 仅作 current-head evidence。
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- Packet Diagnostics：满足「可观测性 / Case 1」字段契约，且 `final.reasonId=IFACE_BLOCK`、`final.accepted=false`、不含 `ruleId` / `ruleMode`
- metrics：
  - `reasons.IFACE_BLOCK.packets>=1`
  - Traffic Windows app scope `directions.out.blockedPackets>=1`（旧 current-head evidence 可继续看 `traffic(app).txp.block>=1`）
- per-rule stats：不因 IFACE_BLOCK 增长（证明“不是 rule 命中”）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-10*`

**缺口**
- 已补齐：`VNXDP-10g` 硬断言 TCP 失败；`VNXDP-10h~10k` 当前断言 pre-SNORT-10 `IFACE_BLOCK` pkt stream、`reasons.IFACE_BLOCK`、旧 `traffic.txp.block`，以及 shadow rule stats 不增长；SNORT-10 后应迁移到 Packet Diagnostics 与 Traffic Windows。

---

### Case 6：block.enabled=0 的 gating（reasons 不应增长）
**目的**
- 验证全局关掉后 reasons 不增长，避免污染。

**Given**
- Tier‑1 就绪。

**When**
- reset reasons / Traffic Windows（pre-SNORT-10 current-head 可 reset 旧 traffic metrics）→ `block.enabled=0` → 触发流量 → GET reasons / Traffic Windows

**Then（期望输出）**
- `METRICS.GET(name=reasons)`：totalPackets==0
- Traffic Windows app scope：accepted / blocked counters 不增长（pre-SNORT-10 current-head 可用旧 `METRICS.GET(name=traffic, app)` total==0 作为 evidence）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-11*`

**缺口**
- 已补齐：`VNXDP-11e~11h` 断言 `block.enabled=0` 时 TCP 仍可通、无匹配 pre-SNORT-10 pkt stream verdict、reasons 为 0、per-app legacy traffic 为 0；SNORT-10 后应迁移到 Traffic Windows。

---

### Case 7：iprules.enabled=0 的 gating（规则存在但不命中；回落 ALLOW_DEFAULT）
**目的**
- 验证 IPRULES 模块开关语义：`iprules.enabled=0` 时，即使 rules 存在也不应命中；应回落到 `ALLOW_DEFAULT`。
- （可选）在同一条 Case 里把 `iprules.enabled` 从 0 切回 1，证明同一条规则立即变成 enforce。

**Given**
- Tier‑1 环境就绪（netns+veth），peer 起 TCP server（443）
- `block.enabled=1`
- 目标 uid：shell 2000（稳定）；pre-SNORT-10 current-head 若要看 pkt stream 需要 `tracked=1`，SNORT-10 应使用 Packet Diagnostics。

**When**
1) 下发一条会命中的 block rule（`enforce=1`，dst=peer/32,dport=443）
2) `CONFIG.SET(scope=device,set={"iprules.enabled":0})`
3) SNORT-10 target：`DIAGNOSTICS.START(channel=packet, app=...)` + `METRICS.RESET(name=reasons)` + `TRAFFIC_WINDOWS.RESET`；pre-SNORT-10 current-head 可用 pkt stream + 旧 traffic reset 作为 evidence。
4) 触发：`nc -z peer_ip 443`（应允许连通）
5) （可选）`CONFIG.SET(scope=device,set={"iprules.enabled":1})` 后重复触发一次（应被拦截）

**Then（期望输出）**
- `iprules.enabled=0` 阶段：
  - 功能面：`nc` 应该成功
  - Packet Diagnostics：`final.reasonId=ALLOW_DEFAULT`、`final.accepted=true`，且不含 `ruleId`
  - metrics：`reasons.ALLOW_DEFAULT.packets>=1` 且 Traffic Windows app scope `directions.out.acceptedPackets>=1`
  - per-rule stats：该 rule 的 `hitPackets` 不应增长（或至少不因这次触发增长）
- （可选）`iprules.enabled=1` 阶段（回归到「IP / Case 3」预期）：
  - `nc` 应该失败；Packet Diagnostics 命中 `IP_RULE_BLOCK + ruleId`

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-12*`

**缺口**
- 已补齐：`VNXDP-12c~12m` 当前覆盖 pre-SNORT-10 correctness（TCP 成功、`ALLOW_DEFAULT`、legacy traffic/reasons allow bucket、rule stats 不增长、恢复 `iprules.enabled=1`）；SNORT-10 后应迁移到 Packet Diagnostics 与 Traffic Windows。

---

### Case 8：Tier‑1 allow（payload 版：稳定触发 Traffic Windows bytes + hitBytes）
**目的**
- 你提到的“稳定触发 traffic metrics”里，**bytes** 这一块最容易被 `nc -z` 的短连接/握手波动影响；SNORT-10 后应以 Traffic Windows accepted bytes 与 reasons/rule stats 作为稳定、可重复断言。
- 顺便补上 IPRULES `dir=in` 的最小覆盖（当前 smoke 主要是 `dir=out`）。

**Given**
- Tier‑1 环境就绪（netns+veth），peer 起 TCP zero server（443；见 `iptest_tier1_start_tcp_zero_server`）
- `block.enabled=1`、`iprules.enabled=1`
- 目标 uid：shell 2000（稳定）；pre-SNORT-10 current-head 若要看 pkt stream 可设 `tracked=1`，SNORT-10 应使用 Packet Diagnostics。

**When**
1) 下发两条 allow（覆盖 out + in；ct 都用 any，避免引入 CT 复杂度）：
   - r_out：`dir=out`、`dst=peer/32`、`dport=443`、`action=allow,enforce=1`
   - r_in：`dir=in`、`src=peer/32`、`sport=443`、`action=allow,enforce=1`
2) `TRAFFIC_WINDOWS.RESET`、`METRICS.RESET(name=reasons)`（pre-SNORT-10 current-head 可用旧 `METRICS.RESET(name=traffic, app)` 作为 evidence）
3) 触发 payload（固定读 N bytes）：
   - 脚本内推荐：`iptest_tier1_tcp_count_bytes 443 65536 2000`（期望输出 `65536`）
   - 手动等价：`nc -n -w 5 <peer_ip> 443 | head -c 65536 | wc -c`

**Then（期望输出）**
- 功能面：读到的 bytes **应等于** N（例如 `65536`）
- metrics（至少这些要增长）：
  - `reasons.IP_RULE_ALLOW.packets>=1` 且 `reasons.IP_RULE_ALLOW.bytes>=65536`
  - Traffic Windows app scope `directions.in.acceptedPackets>=1` 且 `directions.in.acceptedBytes>=65536`
  - Traffic Windows app scope `directions.out.acceptedPackets>=1`（client 侧握手/ACK，证明 out 方向也被观测到）
- per-rule stats（解释闭环）：
  - r_in：`hitPackets>=1` 且 `hitBytes>=65536`（主要 payload 在入站方向）
  - r_out：`hitPackets>=1`（握手/ACK；bytes 可不做阈值）
- （可选）Packet Diagnostics：能看到 `packetDirection=in/out` 的 `IP_RULE_ALLOW` 事件，并分别带对应 `ruleId`

**现有覆盖**
- payload 触发 + bytes 断言在 `tests/device/ip/cases/22_conntrack_ct.sh` 里已有（`iptest_tier1_tcp_count_bytes`），但它验证的是 CT，且不在 smoke profile。
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-13*`

**缺口**
- 已补齐：`VNXDP-13f~13n` 当前用固定 `65536` bytes payload 断言 pre-SNORT-10 `traffic.rxb.allow`、`traffic.txp.allow`、`reasons.IP_RULE_ALLOW.bytes`、inbound rule `hitBytes` 与 outbound rule `hitPackets`；SNORT-10 后应迁移到 Traffic Windows。
- 可选 Packet Diagnostics 的 in/out 双方向事件未作为 hard gate；当前 smoke 用 payload metrics + per-rule stats 完成 bytes 闭环，避免增加 flake。

---

## IP - Conntrack

> SNORT-10 note: this section records the pre-SNORT-10 current-head smoke casebook. New CT runtime semantics are defined by `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md`; `create-on-accept` and `block 不 create entry` are historical test expectations, not the post-SNORT-10 architecture rule.

### Case 1：conntrack（ct.new / ct.established）最小闭环
**目的**
- 验证 `ct.state/ct.direction` 语义可用：能按 state/direction 区分，能形成明确“该通/该断”，并且解释闭环（per-rule stats + reasons）。
- 记录历史 conntrack **create-on-accept** 语义：allow 会创建 entry；block 不会创建 entry（用 `METRICS.GET(name=conntrack)` 观察）。

**Given**
- Tier‑1 就绪；peer 起 TCP server（默认 18081）
- 目标 uid 可联网（能真的建立 TCP 并传输字节）
  - 推荐：用 IP 模组 runner 自动选择的 app uid（`tests/device/ip/run.sh` 会挑一个可 `su <uid>` 且具备网络权限的 uid）
  - 若不稳定：手动指定 `IPTEST_APP_UID=<uid>`（或 `IPTEST_UID=<uid>`）
- 注意：`METRICS.GET(name=conntrack)` 是**全局**指标；本 Case 建议在 `RESETALL` 后立刻读，减少背景噪声

**When**
1) `RESETALL`
2) （建议）`METRICS.GET(name=conntrack)`：确认 `totalEntries==0` 且 `creates==0`
3) 下两条 allow（同一个 uid；ct 维度必须非 any，才能确保 conntrack gating 真的启用）：
   - allow(new+orig)：`dir=out ct.state=new ct.direction=orig dst=peer/32 dport=18081`
   - allow(established+reply)：`dir=in ct.state=established ct.direction=reply src=peer/32 sport=18081`
4) （建议）`IPRULES.PREFLIGHT`：确认 `summary.ctRulesTotal>=1` 且 `summary.ctUidsTotal>=1`
5) 触发一次 TCP 读写（固定读 N bytes，推荐 65536）：
   - 脚本内推荐：`iptest_tier1_tcp_count_bytes 18081 65536 <uid>`
   - 手动等价：`nc -n -w 5 <peer_ip> 18081 | head -c 65536 | wc -c`
6) `IPRULES.PRINT`：读取两条 allow 规则的 `stats.hitPackets/hitBytes`
7) （建议）`METRICS.GET(name=conntrack)`：确认 `creates>=1` 且 `totalEntries>=1`
8) `RESETALL`（清空 conntrack table；`METRICS.RESET(name=conntrack)` 不支持）
9) 下 `new+orig` 的 block：
   - block(new+orig)：`dir=out ct.state=new ct.direction=orig action=block enforce=1 ...`
10) 再触发一次 TCP 读写（同样读 N bytes；应被拦）
11) `METRICS.GET(name=reasons)` + `IPRULES.PRINT`（确认 block 命中）
12) （建议）`METRICS.GET(name=conntrack)`：确认 `creates==0` 且 `totalEntries==0`（block 不应 create entry）

**Then（期望输出）**
- allow 阶段：
  - 功能面：读到的 bytes **等于** N（例如 `65536`）
  - per-rule stats：两条 allow 的 `hitPackets>=1`（可选：`hitBytes>0`）
  - （建议）conntrack metrics：`creates>=1` 且 `totalEntries>=1`
- block 阶段：
  - 功能面：读到字节数为 0（或连接失败）
  - reasons：`IP_RULE_BLOCK.packets>=1`
  - per-rule stats：block 规则 `hitPackets>=1`
  - （建议）conntrack metrics：`creates==0` 且 `totalEntries==0`

**现有覆盖**
- `tests/device/ip/cases/22_conntrack_ct.sh`（已纳入 `tests/device/ip/run.sh --profile smoke` / `dx-smoke-datapath`）：
  - `VNXCT-01~01c`：`RESETALL` 后 conntrack metrics shape 与 `totalEntries/creates==0`
  - `VNXCT-02~03`：allow 规则 apply + `IPRULES.PREFLIGHT` ct consumer
  - `VNXCT-04~06c`：固定 payload bytes、allow rule stats、create-on-accept metrics
  - `VNXCT-07~08b`：block 阶段 `RESETALL`、block rule apply、ct consumer
  - `VNXCT-09~12c`：block verdict、reasons、block rule stats、block 不 create conntrack entry

**缺口**
- 历史当前实现已补齐：该 Case 已作为 smoke 级用例纳入 active datapath gate。SNORT-10 后的 CT A++ runtime 需要按新语义重写/替换对应 smoke 断言。

---

## 可观测性

这一组 Case 的目标：把“我们已有的输出能不能稳定看到、字段/维度是不是对的”说清楚。SNORT-10 packet-side 以 Packet Diagnostics 为诊断入口；DNS↔IP/domain join 不属于当前 Play-facing 第一轮，后续 Domain/DNS line 单独设计。

### Case 1：Packet Diagnostics 基线（START response → diagnostic.packet event → owning session stop/close；字段契约）
**目的**
- Packet Diagnostics 能跑起来，并且 `diagnostic.packet` event 的字段 shape 稳定（方便后续用例复用，不用每条都猜字段）。

**Given**
- `block.enabled=1`
- `iprules.enabled=1`
- 目标 uid / app 由 `DIAGNOSTICS.START(channel=packet, app=...)` 显式指定；不依赖持久 `tracked`。
- 能稳定触发至少 1 个数据包（推荐用「IP / Case 2」的 Tier‑1 allow 场景触发 `nc -z peer_ip 443`）

**When**
- `DIAGNOSTICS.START(channel=packet, app=...)`，START response 返回 `{channel,uid,userId,app}` 后同一连接进入事件模式。
- 触发 1~3 个包（任意可控流量）
- 停止 owning diagnostics connection：关闭连接，或在同一连接支持交互控制时发送 `DIAGNOSTICS.STOP`；不要另开普通 control connection 停止别的 session。

**Then（期望输出）**
- 没有 started notice；START command response 即生效配置。
- 至少 1 条 `type=diagnostic.packet` 事件，且字段类型正确（最小集合）：
  - `timestamp`（string）、`uid`（int）、`userId`（int）、`app`（string）
  - `packet.packetDirection`、`packet.nfqueueHook`、`packet.ipVersion`、`packet.protocol`、`packet.l4Status`、`packet.portsAvailable`
  - `packet.srcIp/dstIp?`、`packet.srcPort/dstPort`、`packet.originalIpBytes`、`packet.copiedBytes`、`packet.truncated`
  - `packet.ifindex?`、`packet.ifaceKind?`
  - `final.accepted`、`final.reasonId`、`final.ruleId?`、`final.ruleMode?`
  - 不输出 `wouldRuleId` / `wouldDrop` / legacy `domain` / `host`
- stop / close 后 diagnostics focus 被释放；若通道丢事件，只能输出 dropped/stopped 类 notice，不输出 started/suppressed notice。

**现有覆盖**
- 多条 datapath smoke 当前仍在用 pre-SNORT-10 pkt stream（字段覆盖不系统，需要迁移）：
  - `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-05~10`

**缺口**
- （完善）补一条 Packet Diagnostics “字段契约”的集中断言（避免每条用例各写各的）

---

### Case 2：DNS→IP 绑定→packet domain hint（后置；不属于 SNORT-10 第一轮）
**目的**
- 这条记录的是旧设计里想验证的 DNS→IP→packet `domain` hint 闭环。
- SNORT-10 第一轮不实现 Domain-IP Association / Resolved-IP Policy / RDNS 联动；Packet Diagnostics 不输出 legacy `domain` / `host` 字段。

**Given**
- `block.enabled=1`
- **netd resolv hook 已激活**（否则这条 Case 应明确 BLOCKED；见「Platform / Case 9」）
- 目标 uid：旧 current-head 可用 `tracked=1`；SNORT-10 不依赖该持久配置。
- 选择一个“可稳定解析且可访问”的域名（建议 `example.com`；也可用内网环境的稳定域名）
- 需要让该域名走 allow（确保 `getips=1`）：
  - （推荐）对该 uid：`domain.custom.enabled=1` + 把 domain 放到 app policy allow.domains（custom whitelist）

**When**
- `RESETALL`（清理旧的 IP 绑定/stream ring，避免误判）
- 下发 allow 策略（确保 DNS verdict 为 allow）
- （建议）先用 `DEV.DOMAIN.QUERY(app,domain)` 确认该 domain 当前会判为 allow（`blocked=false`）
- 旧 `METRICS.RESET(name=traffic, app)`（仅用于 current-head DNS 决策 evidence）
- 开始观测：
  - legacy `STREAM.START(type=pkt)`（pre-SNORT-10 current-head evidence）
- 触发一次真实解析 + 随后产生到该解析 IP 的流量：
  - 例：`nc -z -w 2 example.com 80`（会先解析再发包；网络不通时可能失败，但应至少解析成功）
- legacy `STREAM.STOP`
- （可选）如果想同时看 dns stream：需要**另起一个 vNext 连接**跑 `STREAM.START(type=dns)`（同一连接不允许同时 start 两种 stream）

**Then（期望输出）**
- 旧 `METRICS.GET(name=traffic, app)` 的 `traffic.dns.allow>=1`（确认 DNS 决策发生；SNORT-10 不保留该 traffic shape）
- legacy pkt stream：若仍运行旧能力，可出现 `type=pkt` 事件带 `domain=="example.com"`（或你选的域名）；这不是 SNORT-10 packet diagnostics target。

**现有覆盖**
- 无；本条后置，不纳入 SNORT-10 第一轮。

**缺口**
- 后续 Domain/DNS line 若重新打开 Domain-IP Association / Resolved-IP Policy / RDNS，再重新定义测试目标；当前不补进 SNORT-10 packet-side smoke。

---

### Case 3：pre-SNORT-10 pkt stream 的 tracked=0 可解释闭环（suppressed notice；legacy evidence）
**目的**
- 这条只记录旧 tracked-stream 模型的 current-head evidence：当某个 uid/app `tracked=0` 时，pkt stream **不应**输出 `type=pkt` 事件；旧系统通过 `notice.suppressed` 给出汇总信号。
- SNORT-10 Packet Diagnostics 按 UID/app 显式开启当前 session，不输出 suppressed notice。
- 这条 Case 用来快速排除两类误判：
  1) “没看到 pkt event 就以为 datapath 没跑”（其实是 tracked=0）
  2) “开了 stream 但啥也没看到”（其实是没触发到流量 / block.enabled=0）

**Given**
- `block.enabled=1`
- 目标 uid：建议用 shell uid=2000（稳定，且便于构造 Tier‑1 流量）
- 确认该 uid 的 `tracked=0`（必要时显式 `CONFIG.SET(scope=app,set={tracked:0})`）
- 有一条可重复触发的流量（推荐复用 Tier‑1）：
  - peer 起 TCP server（例如 443）
  - 用一次固定读 N bytes（例如 4096/65536）触发明显的 `rxp/rxb/txp/txb`

**When**
1) `RESETALL`（清理旧状态，避免其他 uid 的 tracked 污染）
2) `CONFIG.SET(scope=device,set={block.enabled:1, iprules.enabled:1})`
3) `CONFIG.SET(scope=app,app={uid:<uid>},set={tracked:0})`
4) legacy `STREAM.START(type=pkt)`（等待 `notice.started`）
5) 触发一次 payload 流量（固定读 N bytes；例如 `iptest_tier1_tcp_count_bytes 443 65536 <uid>`）
6) 等待 >= 1s（suppressed notice 以 1s 粒度 best-effort 推送）
7) legacy `STREAM.STOP`

**Then（期望输出）**
- stream 中**不应**出现 `type=pkt` 事件（因为 tracked=0）
- stream 中应出现 `type=notice notice=suppressed stream=pkt`，且包含：
  - `windowMs`（约 1000ms）
  - `traffic`（至少 `rxp/rxb/txp/txb` 中某些维度的 allow/block 有非 0）
  - `hint`（提示如何启用 tracked 或改用 `METRICS.GET(name=traffic)`）
- （可选交叉验证）旧 `METRICS.GET(name=traffic, app)` 对该 uid 也应有增长（证明 datapath 真实跑过；SNORT-10 traffic 目标为 Traffic Windows）

**现有覆盖**
- 无（现有 smoke 主要都把目标 uid 设成 `tracked=1`，所以看不到 suppressed notice 行为）

**缺口**
- （新增）把这条纳入 smoke 的“可观测性 gate”（否则现场排障经常因为 tracked 配置不同导致误判）

---

## 其他

这一组 Case 的目标：把一些“开关语义/可用性验证”用 smoke 口径写清楚（不依赖公网大跑量）；对应的重负载/诊断脚本仍留在 diagnostics。

### Case 1：`perfmetrics.level` 功能语义（off 必须近似零成本；basic/detail 必须增长）
**目的**
- 验证 `perfmetrics.level` 开关真正生效：
  - `off`：`METRICS.GET(name=perf)` 只返回 `{level:"off"}`。
  - `basic`：以低扰动 sampling 方式输出 `packetVerdictLatencyUs`、`nfqueueHealth` 与 sampled counters。
  - `detail` / `profiling`：显式高成本测量模式，不作为普通 smoke 的常驻默认。
- 这条属于 smoke（功能能不能用），不是“测极限性能”。

**Given**
- 控制面可用。
- 有一条**可重复、非公网依赖**的流量触发方式（推荐复用「IP / Case 8」的 Tier‑1 payload 流量）。
- 注意：流量必须实际走到 datapath/NFQUEUE；否则 `sampledPackets` 可能一直为 0，容易误判成 “perfmetrics.level 没生效”。

**When**
（建议：整条 Case 先读 orig，最后 restore，避免污染其他 Case。）

1) 保存原值：
   - `CONFIG.GET(scope=device, keys=["perfmetrics.level"])`
2) 关闭采样窗口（off）：
   - `CONFIG.SET(scope=device, set={"perfmetrics.level":"off"})`
   - `METRICS.RESET(name=perf)`
   - 触发一次 payload 流量（固定读 N bytes；例如 65536；见「IP / Case 8」）
   - `METRICS.GET(name=perf)`
3) 开启 basic 采样窗口：
   - `CONFIG.SET(scope=device, set={"perfmetrics.level":"basic"})`
   - `METRICS.RESET(name=perf)`
   - 再触发一次 payload 流量（同样固定读 N bytes）
   - `METRICS.GET(name=perf)`
4) 幂等性（basic→basic 不清空 aggregates）：
   - `CONFIG.SET(scope=device, set={"perfmetrics.level":"basic"})`
   - `METRICS.GET(name=perf)`（不 reset）
5) 非法值拒绝：
   - `CONFIG.SET(scope=device, set={"perfmetrics.level":"invalid"})`
6) restore 原值：
   - `CONFIG.SET(scope=device, set={"perfmetrics.level":<orig>})`

**Then（期望输出）**
- off：只返回 `{level:"off"}`，不返回 latency histogram。
- basic：`packetVerdictLatencyUs.sampled=true` 且 `sampledPackets>=1`（在确有 eligible packet 的前提下）。
- basic→basic 幂等：第二次 GET 的 `packetVerdictLatencyUs.sampledPackets` 不应小于第一次 basic 后的 sampled packets。
- 非法值：应返回 `INVALID_ARGUMENT`（并且不应改变当前配置）
- （可选）`dns_decision_us.*`：
  - 只有当 netd resolv hook 活跃且你确实触发了 DNS 解析时才可能增长；
  - 不要把它作为这条 smoke 的硬 gate（避免把 netd 环境问题误判成 perfmetrics 功能坏了）。

**现有覆盖**
- optional casebook（非默认 gate）：`tests/device/diagnostics/dx-casebook-other.sh --case perfmetrics`
  - 当前 `VNXOTH-01*` 是 pre-SNORT-10 `perfmetrics.enabled` / `nfq_total_us` evidence；SNORT-10 后应迁移到 `perfmetrics.level` 与 `packetVerdictLatencyUs`。
  - 迁移后：保存 `perfmetrics.level` 原值；验证 `off` 只返回 `{level:"off"}`；验证 `basic` 下 `packetVerdictLatencyUs.sampledPackets>=1`；验证 `basic→basic` 不清空 sampled counters；验证非法 level 返回 `INVALID_ARGUMENT`。
  - `VNXOTH-01l`：旧 `dns_decision_us` 保持 pre-SNORT-10 optional/non-gate evidence（无 active netd resolver hook 时不硬断言）
- diagnostics（重负载/公网下载版）：`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
  - 里面已包含 off=0 / on=grow / 1→1 幂等 / 非法值拒绝 的验证，但它依赖设备侧 downloader + 公网 URL（更偏诊断/性能）。

**缺口**
- 已补齐为**可选** casebook runner；按 roadmap 约束不挂进 `dx-smoke.sh` 固定序列。
- 若 Tier‑1 前置不足，runner 会明确 `SKIP/BLOCKED`，不把环境问题误报为 perfmetrics 功能通过。

---

### Case 2：极端规模下的控制面下发（超多域名 / 超多 IPRULES；limits 必须可解释）
**目的**
- 这条不追求“真实流量端到端”，而是验证一个极端但现实的问题：**一次性下发大量随机生成的域名/规则**时，vNext 控制面与 host 侧 Linux 接口（`sucre-snort-ctl`）能不能扛住：
  - 能下得下去（under-limit 必须成功）
  - 下不下去时必须“讲人话”（over-limit 必须返回明确 `INVALID_ARGUMENT` + limits/hint，而不是崩溃/半成功）
- 这条更像 diagnostics/stress，但建议在 casebook 里明确口径，避免上线后才第一次撞到“下发规模”问题。

**Given**
- 控制面可用（`HELLO` OK），并能通过 `HELLO.result.maxRequestBytes` 确认本次会话请求上限（当前默认是 16MiB）。
- 有一个 app uid（用于 IPRULES）。
- `DOMAINLISTS.APPLY/IMPORT` 可用（用于域名 bulk import）。

**When**
（建议分两段做：DOMAINLISTS.IMPORT 的 payload limits；IPRULES 的 preflight hard limits。）

A) **DOMAINLISTS.IMPORT：超大 domains payload**
1) `DOMAINLISTS.APPLY` 创建一个 listId（例如 Lbig），建议先 `enabled=0`（避免影响真实判决）
2) 生成 domains 数组（随机、但必须是合法 domain string），并控制总字节数：
   - under-limit：总字节 `<= 16MiB` 且条目数 `<= 1,000,000`（应成功）
   - over-limit：总字节 `> 16MiB` 或条目数 `> 1,000,000`（应失败）
3) `DOMAINLISTS.IMPORT(listId=Lbig, listKind=..., mask=..., clear=1, domains=[...])`
4) （建议）`DOMAINLISTS.GET` 回查 domainsCount 是否更新；并确认控制面仍可继续 `HELLO`

B) **pre-SNORT-10 direct IPRULES.APPLY：超多规则 + preflight limits**
1) `RESETALL`，并确保 `block.enabled=1`、`iprules.enabled=1`
2) 生成一组规则（同一个 uid；保证 `matchKey` 唯一，例如固定 dst，递增 dport；全部 `enabled=1`）：
   - 先做 under-limit（例如 1100 条）：应成功，但 `IPRULES.PREFLIGHT` 应出现 `rulesTotal` 的 warning（recommended 上限为 1000）
   - 再做 over-limit（例如 5001 条）：应失败（hard 上限为 5000），并返回 `INVALID_ARGUMENT` + `error.preflight.violations`
3) 失败后仍应能继续执行 `HELLO` / `IPRULES.PREFLIGHT`（验证“失败可恢复”，不影响后续用例）

**Then（期望输出）**
- `DOMAINLISTS.IMPORT` over-limit 时：
  - 返回 `INVALID_ARGUMENT`，message 类似 `import payload too large`
  - `error.limits` 必须包含 `maxImportDomains=1000000`、`maxImportBytes=16777216`，并带 `hint`（chunk 导入）
- pre-SNORT-10 direct `IPRULES.APPLY` over-limit 时：
  - 返回 `INVALID_ARGUMENT`
  - `error.preflight.violations` 中应包含 `rulesTotal` 的 limit（hard=5000）
- 上述两类失败都不应导致 daemon crash/控制面不可用（失败后 `HELLO` 仍 OK）

**现有覆盖**
- optional casebook（非默认 gate）：`tests/device/diagnostics/dx-casebook-other.sh --case limits`
  - `VNXOTH-02a`：`HELLO` 可用并读取 `maxRequestBytes`
  - `VNXOTH-02b~02d`：创建 disabled test list、under-limit import 成功、`domainsCount` 回查正确
  - `VNXOTH-02e~02f`：over-limit `DOMAINLISTS.IMPORT` 返回 `INVALID_ARGUMENT` + `error.limits` + hint，且失败后 `HELLO` 仍 OK
  - `VNXOTH-02g~02j`：`RESETALL` 后 under-hard-limit IPRULES 大规则集 apply 成功，并通过 `IPRULES.PREFLIGHT` 看到 `rulesTotal` warning
  - `VNXOTH-02k~02n`：pre-SNORT-10 direct over-hard-limit `IPRULES.APPLY` 返回 `INVALID_ARGUMENT` + `error.preflight.violations.rulesTotal`，失败 all-or-nothing，且后续 `HELLO` / `IPRULES.PREFLIGHT` 仍 OK
- Host gtest：已覆盖 `DOMAINLISTS.IMPORT` limits 与 pre-SNORT-10 direct `IPRULES.APPLY` preflight hard-limit 的结构化错误（见 coverage matrix）。

**缺口**
- 已补齐为**可选** diagnostics/casebook runner；不进入默认 `dx-smoke` 主链。
- 若本机/daemon `maxRequestBytes` 无法承载 over-limit payload，runner 会明确 `SKIP`，避免把 transport 上限误报为 command-level limits 行为。

---

## 7) Coverage status and deferred notes

本节不作为本地 TODO tracker。当前架构重置阶段只有 Plane `SNORT-10` 是 active item；旧迁移项 `SNORT-5..7` 已取消。

已补齐的覆盖：
- IP allow/block/iface/would：`VNXDP-06/08f/09f/10g` 已把 `nc` 成败变成硬断言。
- IP traffic metrics：`VNXDP-06d/08i/09i/10j/11h/12j/13i~13k` 覆盖 `txp/rxp/rxb` 维度；bytes 走「IP / Case 8」固定读写 N bytes。
- IP reasons metrics：`VNXDP-06c/08h/09h/10i/11g/12i/13g~13h` 覆盖原因 bucket 与 payload bytes。
- IP per-rule stats bytes：`VNXDP-13l~13n` 覆盖 `hitBytes`；短连接 would case 不把 `wouldHitBytes` 作为 hard assert。
- 域名 Case 3-9、IP `iprules.enabled=0` gating、payload bytes、Conntrack 最小闭环、其他 Case 1-2 均已纳入相应 active 或 optional entrypoint。

Deferred notes for `SNORT-10`：
- packet-side 字段契约应迁移到 Packet Diagnostics / `diagnostic.packet`；legacy pkt stream 字段契约只保留 current-head evidence。
- DNS→IP 绑定→pkt stream 带 domain 的 Device / DX smoke 后置到 Domain/DNS line；SNORT-10 第一轮不实现 Domain-IP Association / Resolved-IP Policy / RDNS 联动。
- pkt stream `tracked=0` suppressed notice smoke 不作为 SNORT-10 packet-side 主线验收；Packet Diagnostics 是 session-owned 显式诊断，不输出 suppressed notice。

---

## 8) 附：脚本与 check id 回查索引
- platform：`tests/integration/dx-smoke-platform.sh`
- control baseline：`tests/integration/vnext-baseline.sh`
- stream dns（当前是 netd inject）：`VNT-10b*`
- domain surface：`VNT-15~22`
- domainSources 行为：`VNT-22i* / VNT-22j*`
- domain casebook：`VNT-DOM-01a~09`（`tests/integration/vnext-domain-casebook.py`，由 `dx-smoke-control` 调用）
- datapath（Tier‑1）：`tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`
- allow：`VNXDP-05~07`
- traffic reset/grow/reset：`VNXDP-05d~06d / VNXDP-08d~08i / VNXDP-09d~09i / VNXDP-10d~10j / VNXDP-11b~11h / VNXDP-12e~12j / VNXDP-13d~13k`
- block：`VNXDP-08*`
- would：`VNXDP-09*`
- iface：`VNXDP-10*`
- gating：`VNXDP-11*`
- `iprules.enabled=0` gating correctness：`VNXDP-12*`
- payload bytes 触发：`VNXDP-13*`（helper：`tests/device/ip/lib.sh` 的 `iptest_tier1_tcp_count_bytes`）
- conntrack（Tier‑1）：`tests/device/ip/cases/22_conntrack_ct.sh`（`VNXCT-01~12c`；已纳入 active smoke）
- diagnostics：`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
- optional other casebook：`tests/device/diagnostics/dx-casebook-other.sh`（`VNXOTH-01*` / `VNXOTH-02*`；非默认 gate）
