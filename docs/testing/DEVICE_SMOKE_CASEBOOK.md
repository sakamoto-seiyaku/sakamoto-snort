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

**缺口**
- （完善）补 1~2 条负向契约，避免“脚本能跑但状态已坏”：
  - `DOMAINLISTS.IMPORT` unknown listId → `INVALID_ARGUMENT` + hint（先 `DOMAINLISTS.APPLY`）
  - `DOMAINRULES.APPLY` 尝试删除仍被 policy 引用的 ruleId → `INVALID_ARGUMENT` + conflicts[] + hint

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

**缺口**
- （完善）目前只看 total，不看 bucket；建议至少把这三类 bucket 覆盖到：
  - APP：`CUSTOM_*`（见 Case 3/6）
  - DEVICE_WIDE：`GLOBAL_*`（见 Case 6）
  - FALLBACK：`MASK_FALLBACK`（见 Case 7）

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

**缺口**
- （完善）补齐 traffic/domainSources 断言；补齐 dns event 字段覆盖（目前只看少量字段）

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

**缺口**
- （新增）把 suppressed notice + traffic.dns 断言纳入 smoke

---

### Case 5：domain.custom.enabled 语义（0/1 必须改变判决路径）
**目的**
- 验证 app 的 custom 开关真正影响判决：
  - 1：custom/app/device policy 生效（`CUSTOM_* / GLOBAL_*`）
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

**缺口**
- （新增）把 `domain.custom.enabled=0/1` 的端到端行为固化成 smoke Case（当前只有“能设”，没有“触发→输出”）

---

### Case 6：device vs app policy 优先级（APP 覆盖 DEVICE_WIDE；scope 必须可解释）
**目的**
- 验证优先级与输出解释一致：
  - APP 策略命中：`policySource=CUSTOM_*`，`scope=APP`
  - 仅 DEVICE 策略命中：`policySource=GLOBAL_*`，`scope=DEVICE_WIDE`

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
- d3：`blocked=true`、`policySource=GLOBAL_BLOCKED`、`scope=DEVICE_WIDE`、`useCustomList=true`
- traffic(app)：`traffic.dns.allow` 与 `traffic.dns.block` 增长（至少各 1）
- domainSources(app)：对应 bucket 增长

**现有覆盖**
- 无

**缺口**
- （新增）需要把这条优先级闭环纳入 smoke；否则现场排障容易把 “scope 不对” 误判成系统 bug

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

**缺口**
- （新增）缺“list 影响判决”的端到端（现在只验证能 apply/get/import）

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
  - shell uid：执行一次会触发 getaddrinfo 的命令（例如 `ping -c 1 -W 1 <domain>` 或 `nc <domain> 80`）
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

**缺口**
- （新增）需要把“真实解析触发”写成正式 smoke gate（hook 不活跃 = BLOCKED）
- （完善）补 “shell uid=2000 + 真实 app uid” 两条触发路径的口径与工具说明

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
- 无（当前 smoke 只覆盖了 `CUSTOM_(WHITE|BLACK)LIST`、`GLOBAL_*`、`MASK_FALLBACK`；缺 `CUSTOM_RULE_*`）

**缺口**
- （自动化层面）若要把这条纳入 active smoke，需要补一个稳定的规则生成 + restore 策略（调查先记录，不做实现）

---

## IP

这一组 Case 的目标：验证 `IPRULES/IFACE_BLOCK` 在真机 Tier‑1 受控拓扑下的端到端可用性（下规则→触发→看 verdict + 输出）。

关键口径/开关（避免“以为测了，其实没测到”）：
- `block.enabled`：全局 datapath gate；关掉后 NFQ 不介入，pkt stream / reasons / traffic 都不会增长（也不会产生 pkt suppressed）。
- `iprules.enabled`：IPRULES fast path gate（当前仅 IPv4）；关掉后即使 rules 存在也不会命中，reason 回落到 `ALLOW_DEFAULT`（除非走 legacy `IP_LEAK_BLOCK`）。
- **bytes 指标口径**：`traffic.*b` 与 per-rule `*Bytes` 统计的是 NFQUEUE 看到的 IP 包长度（包含 IP header；不包含 L2）。`nc -z` 也会增长 bytes，但量很小且波动；要做“稳定/有意义”的 bytes 断言，推荐固定读写 N bytes 的 payload 流量（见「IP / Case 8」）。

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
- （建议，为了确定性）`METRICS.RESET(name=traffic, app)`、`METRICS.RESET(name=reasons)`
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- 功能面：`nc` 应该成功（这才是“人话冒烟”的核心）
- pkt stream：满足「可观测性 / Case 1」字段契约，且 `reasonId=IP_RULE_ALLOW`、`accepted=true`、`ruleId` 匹配
- metrics：
  - `reasons.IP_RULE_ALLOW.packets>=1`
  - `traffic(app).txp.allow>=1`（不要只看 total）
  - （可选：若触发了 payload 流量）`traffic(app).txb.allow>=1` 且 `reasons.IP_RULE_ALLOW.bytes>=1`
- per-rule stats：`hitPackets>=1`（可选：payload 时 `hitBytes>=1`）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-05~07`

**缺口**
- （完善）当前 datapath smoke 会吞掉 `nc` 成败（`|| true`），缺“allow 就应该能通”的硬断言
- （完善）allow 路径目前没硬断言 `reasons.IP_RULE_ALLOW` 增长
- （完善）traffic 现在以 total 为主，需要补维度级断言（至少 `traffic(app).txp.allow`）
- （完善）若要把 bytes 变成 hard assert，需要把触发从 `nc -z` 换成“真实读写”（例如 `iptest_tier1_tcp_count_bytes`），再断言 `txb/hitBytes/reasons.*.bytes`

---

### Case 3：Tier‑1 block（规则拦截 + 输出齐）
**目的**
- block 真的拦截（端到端），并且输出齐。

**Given**
- 同 Case 2。

**When**
- `IPRULES.APPLY(action=block,enforce=1,...)`
- `STREAM.START(type=pkt)`
- （建议，为了确定性）`METRICS.RESET(name=traffic, app)`、`METRICS.RESET(name=reasons)`
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- 功能面：`nc` 应该失败
- pkt stream：满足「可观测性 / Case 1」字段契约，且 `reasonId=IP_RULE_BLOCK`、`accepted=false`、`ruleId` 匹配
- metrics：
  - `reasons.IP_RULE_BLOCK.packets>=1`
  - `traffic(app).txp.block>=1`
- per-rule stats：`hitPackets>=1`

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-08*`

**缺口**
- （完善）同样缺 `nc` 失败的硬断言（当前吞错误）
- （完善）traffic(block 维度) 没看（至少 `traffic(app).txp.block`）

---

### Case 4：Would‑match overlay（enforce=0）解释性闭环
**目的**
- 验证 wouldRuleId：最终 ACCEPT 但带 wouldRuleId（可解释）。

**Given**
- Tier‑1 就绪；最终应是 allow（基线默认允许或已有 allow rule）。

**When**
- 下发 `action=block,enforce=0,log=1` 的规则
- `STREAM.START(type=pkt)`
- （建议，为了确定性）`METRICS.RESET(name=traffic, app)`、`METRICS.RESET(name=reasons)`
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- pkt stream：满足「可观测性 / Case 1」字段契约，且 `reasonId=ALLOW_DEFAULT`、`accepted=true`、无 `ruleId`、有 `wouldRuleId=<该规则>`、且 `wouldDrop=true`
- metrics：
  - `reasons.ALLOW_DEFAULT.packets>=1`
  - `traffic(app).txp.allow>=1`
- per-rule stats：`wouldHitPackets>=1`（可选：payload 时 `wouldHitBytes>=1`）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-09*`

**缺口**
- （完善）可补“连通性应成功”的硬断言（当前吞错误）
- （完善）若要断言 `wouldHitBytes`，同样需要把触发从 `nc -z` 换成“真实读写”

---

### Case 5：IFACE_BLOCK（block.ifaceKindMask）端到端
**目的**
- 验证 iface block：reasonId=IFACE_BLOCK，且不应增长 rule stats。

**Given**
- Tier‑1 就绪；能推导当前 veth 的 iface kind（或 fallback）
- `block.ifaceKindMask` 覆盖当前 kind

**When**
- `CONFIG.SET(scope=app,set={"block.ifaceKindMask":<bit>})`
- `STREAM.START(type=pkt)`
- （建议，为了确定性）`METRICS.RESET(name=traffic, app)`、`METRICS.RESET(name=reasons)`
- 触发：`nc -z peer_ip 443`

**Then（期望输出）**
- pkt stream：满足「可观测性 / Case 1」字段契约，且 `reasonId=IFACE_BLOCK`、`accepted=false`、不含 `ruleId/wouldRuleId`
- metrics：
  - `reasons.IFACE_BLOCK.packets>=1`
  - `traffic(app).txp.block>=1`
- per-rule stats：不因 IFACE_BLOCK 增长（证明“不是 rule 命中”）

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-10*`

**缺口**
- （完善）缺“nc 应失败”的硬断言（当前吞错误）
- （完善）traffic(block 维度) 没看（至少 `traffic(app).txp.block`）

---

### Case 6：block.enabled=0 的 gating（reasons 不应增长）
**目的**
- 验证全局关掉后 reasons 不增长，避免污染。

**Given**
- Tier‑1 就绪。

**When**
- reset reasons/traffic → `block.enabled=0` → 触发流量 → GET reasons/traffic

**Then（期望输出）**
- `METRICS.GET(name=reasons)`：totalPackets==0
- `METRICS.GET(name=traffic, app)`：total==0

**现有覆盖**
- `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-11*`

**缺口**
- （完善）当前只断言了 reasons；未断言 traffic 也被 gating（以及 pkt stream 不应产生 pkt frame）

---

### Case 7：iprules.enabled=0 的 gating（规则存在但不命中；回落 ALLOW_DEFAULT）
**目的**
- 验证 IPRULES 模块开关语义：`iprules.enabled=0` 时，即使 rules 存在也不应命中；应回落到 `ALLOW_DEFAULT`。
- （可选）在同一条 Case 里把 `iprules.enabled` 从 0 切回 1，证明同一条规则立即变成 enforce。

**Given**
- Tier‑1 环境就绪（netns+veth），peer 起 TCP server（443）
- `block.enabled=1`
- 目标 uid：shell 2000（稳定），且 `tracked=1`（为了看到 pkt stream）

**When**
1) 下发一条会命中的 block rule（`enforce=1`，dst=peer/32,dport=443）
2) `CONFIG.SET(scope=device,set={"iprules.enabled":0})`
3) `STREAM.START(type=pkt)` + `METRICS.RESET(name=reasons)` + `METRICS.RESET(name=traffic, app)`
4) 触发：`nc -z peer_ip 443`（应允许连通）
5) （可选）`CONFIG.SET(scope=device,set={"iprules.enabled":1})` 后重复触发一次（应被拦截）

**Then（期望输出）**
- `iprules.enabled=0` 阶段：
  - 功能面：`nc` 应该成功
  - pkt stream：`reasonId=ALLOW_DEFAULT`、`accepted=true`，且不含 `ruleId/wouldRuleId`
  - metrics：`reasons.ALLOW_DEFAULT.packets>=1` 且 `traffic(app).txp.allow>=1`
  - per-rule stats：该 rule 的 `hitPackets` 不应增长（或至少不因这次触发增长）
- （可选）`iprules.enabled=1` 阶段（回归到「IP / Case 3」预期）：
  - `nc` 应该失败；pkt stream 命中 `IP_RULE_BLOCK + ruleId`

**现有覆盖**
- 无（当前 smoke 未覆盖 `iprules.enabled=0` 的 correctness；perf 会切开关但不做 verdict 断言）

**缺口**
- （新增）建议把这条纳入 smoke：否则现场排障很容易把 “开关关着” 当成 “规则没生效”

---

### Case 8：Tier‑1 allow（payload 版：稳定触发 traffic.*b + hitBytes）
**目的**
- 你提到的“稳定触发 traffic metrics”里，**bytes** 这一块最容易被 `nc -z` 的短连接/握手波动影响；这条 Case 用固定读写 N bytes 的流量，把 bytes 断言做成稳定、可重复。
- 顺便补上 IPRULES `dir=in` 的最小覆盖（当前 smoke 主要是 `dir=out`）。

**Given**
- Tier‑1 环境就绪（netns+veth），peer 起 TCP zero server（443；见 `iptest_tier1_start_tcp_zero_server`）
- `block.enabled=1`、`iprules.enabled=1`
- 目标 uid：shell 2000（稳定），且 `tracked=1`（便于看 pkt stream；非必需）

**When**
1) 下发两条 allow（覆盖 out + in；ct 都用 any，避免引入 CT 复杂度）：
   - r_out：`dir=out`、`dst=peer/32`、`dport=443`、`action=allow,enforce=1`
   - r_in：`dir=in`、`src=peer/32`、`sport=443`、`action=allow,enforce=1`
2) `METRICS.RESET(name=traffic, app)`、`METRICS.RESET(name=reasons)`
3) 触发 payload（固定读 N bytes）：
   - 脚本内推荐：`iptest_tier1_tcp_count_bytes 443 65536 2000`（期望输出 `65536`）
   - 手动等价：`nc -n -w 5 <peer_ip> 443 | head -c 65536 | wc -c`

**Then（期望输出）**
- 功能面：读到的 bytes **应等于** N（例如 `65536`）
- metrics（至少这些要增长）：
  - `reasons.IP_RULE_ALLOW.packets>=1` 且 `reasons.IP_RULE_ALLOW.bytes>=65536`
  - `traffic(app).rxp.allow>=1` 且 `traffic(app).rxb.allow>=65536`
  - `traffic(app).txp.allow>=1`（client 侧握手/ACK，证明 out 方向也被观测到）
- per-rule stats（解释闭环）：
  - r_in：`hitPackets>=1` 且 `hitBytes>=65536`（主要 payload 在入站方向）
  - r_out：`hitPackets>=1`（握手/ACK；bytes 可不做阈值）
- （可选）pkt stream：能看到 `direction=in/out` 的 `IP_RULE_ALLOW` 事件，并分别带对应 `ruleId`

**现有覆盖**
- payload 触发 + bytes 断言在 `tests/device/ip/cases/22_conntrack_ct.sh` 里已有（`iptest_tier1_tcp_count_bytes`），但它验证的是 CT，且不在 smoke profile。

**缺口**
- （新增）把这条纳入 smoke（它是 bytes/traffic 维度断言最稳的触发方式）

---

## IP - Conntrack

### Case 1：conntrack（ct.new / ct.established）最小闭环
**目的**
- 验证 `ct.state/ct.direction` 语义可用：能按 state/direction 区分，能形成明确“该通/该断”，并且解释闭环（per-rule stats + reasons）。
- （建议同一条 Case 里顺手确认）conntrack **create-on-accept** 语义：allow 会创建 entry；block 不会创建 entry（用 `METRICS.GET(name=conntrack)` 观察）。

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
- `tests/device/ip/cases/22_conntrack_ct.sh`（当前在 profile=matrix，不在 dx-smoke 主链里）

**缺口**
- （新增）把这条作为 smoke 级用例纳入（或至少明确列为“第一阶段建议新增 smoke case”）

---

## 可观测性

这一组 Case 的目标：把“我们已有的输出能不能稳定看到、字段/维度是不是对的、能不能把 DNS 和 pkt 串起来”说清楚。

### Case 1：pkt stream 基线（started notice → pkt event → stop barrier；字段契约）
**目的**
- pkt stream 能跑起来，并且 event 的字段 shape 稳定（方便后续用例复用，不用每条都猜字段）。

**Given**
- `block.enabled=1`
- 目标 uid：`tracked=1`（否则会走 suppressed）
- 能稳定触发至少 1 个数据包（推荐用「IP / Case 2」的 Tier‑1 allow 场景触发 `nc -z peer_ip 443`）

**When**
- `STREAM.START(type=pkt)`（等待 `notice.started`）
- 触发 1~3 个包（任意可控流量）
- `STREAM.STOP`

**Then（期望输出）**
- 有 `type=notice notice=started stream=pkt`
- 至少 1 条 `type=pkt` 事件，且字段类型正确（最小集合）：
  - `timestamp`（string）、`uid`（int）、`userId`（int）、`app`（string）
  - `direction`（in/out）、`ipVersion`（4/6）、`protocol`（tcp/udp/icmp/other）
  - `srcIp/dstIp`（string）、`srcPort/dstPort`（int）、`length`（int）
  - `ifindex`（int）、`ifaceKindBit`（int）
  - `accepted`（bool）、`reasonId`（string）
  - 可选字段：`ruleId` / `wouldRuleId` / `wouldDrop` / `domain` / `host`（存在时类型必须正确）
  - 若存在 `wouldRuleId`，则必须同时存在 `wouldDrop=true`
  - `host` 仅在 `rdns.enabled=1` 且 PTR/反查成功时出现（best-effort；不建议硬断言）
- STOP 后短窗口内不应再收到 frame（best-effort barrier）

**现有覆盖**
- 多条 datapath smoke 已经在用 pkt stream（但字段覆盖不系统）：
  - `tests/device/ip/cases/16_iprules_vnext_datapath_smoke.sh`：`VNXDP-05~10`

**缺口**
- （完善）补一条“字段契约”的集中断言（避免每条用例各写各的）

---

### Case 2：DNS→IP 绑定→pkt stream 带 domain（跨域名/IP 的可观测闭环）
**目的**
- 走一条“真机真实解析 + 返回 IP（getips=1）”的路径，把 IP 绑定到 domain；
- 后续对该 IP 的请求应在 pkt stream 里带 `domain` 字段，完成 DNS→pkt 的关联闭环。

**Given**
- `block.enabled=1`
- **netd resolv hook 已激活**（否则这条 Case 应明确 BLOCKED；见「Platform / Case 9」）
- 目标 uid：`tracked=1`
- 选择一个“可稳定解析且可访问”的域名（建议 `example.com`；也可用内网环境的稳定域名）
- 需要让该域名走 allow（确保 `getips=1`）：
  - （推荐）对该 uid：`domain.custom.enabled=1` + 把 domain 放到 app policy allow.domains（custom whitelist）

**When**
- `RESETALL`（清理旧的 IP 绑定/stream ring，避免误判）
- 下发 allow 策略（确保 DNS verdict 为 allow）
- （建议）先用 `DEV.DOMAIN.QUERY(app,domain)` 确认该 domain 当前会判为 allow（`blocked=false`）
- `METRICS.RESET(name=traffic, app)`（用于确认 DNS 决策确实发生）
- 开始观测：
  - `STREAM.START(type=pkt)`
- 触发一次真实解析 + 随后产生到该解析 IP 的流量：
  - 例：`nc -z -w 2 example.com 80`（会先解析再发包；网络不通时可能失败，但应至少解析成功）
- `STREAM.STOP`
- （可选）如果想同时看 dns stream：需要**另起一个 vNext 连接**跑 `STREAM.START(type=dns)`（同一连接不允许同时 start 两种 stream）

**Then（期望输出）**
- `METRICS.GET(name=traffic, app)` 的 `traffic.dns.allow>=1`（确认 DNS 决策发生）
- pkt stream：出现至少 1 条 `type=pkt` 事件带 `domain=="example.com"`（或你选的域名）

**现有覆盖**
- 无（目前 smoke 里没有把 DNS 的 IP 绑定与 pkt stream 的 `domain` 字段关联起来）

**缺口**
- （新增）把这条闭环纳入 smoke，用来验证“端到端可观测性”而不仅是“单点输出存在”

---

### Case 3：pkt stream 的 tracked=0 可解释闭环（suppressed notice；不出 pkt event）
**目的**
- 你要的典型“人话冒烟”之一：当某个 uid/app `tracked=0` 时，pkt stream **不应**输出 `type=pkt` 事件（避免泄露）；但系统仍应通过 `notice.suppressed` 给出“确实有流量在跑”的汇总信号（带 traffic snapshot + hint）。
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
4) `STREAM.START(type=pkt)`（等待 `notice.started`）
5) 触发一次 payload 流量（固定读 N bytes；例如 `iptest_tier1_tcp_count_bytes 443 65536 <uid>`）
6) 等待 >= 1s（suppressed notice 以 1s 粒度 best-effort 推送）
7) `STREAM.STOP`

**Then（期望输出）**
- stream 中**不应**出现 `type=pkt` 事件（因为 tracked=0）
- stream 中应出现 `type=notice notice=suppressed stream=pkt`，且包含：
  - `windowMs`（约 1000ms）
  - `traffic`（至少 `rxp/rxb/txp/txb` 中某些维度的 allow/block 有非 0）
  - `hint`（提示如何启用 tracked 或改用 `METRICS.GET(name=traffic)`）
- （可选交叉验证）`METRICS.GET(name=traffic, app)` 对该 uid 也应有增长（证明 datapath 真实跑过）

**现有覆盖**
- 无（现有 smoke 主要都把目标 uid 设成 `tracked=1`，所以看不到 suppressed notice 行为）

**缺口**
- （新增）把这条纳入 smoke 的“可观测性 gate”（否则现场排障经常因为 tracked 配置不同导致误判）

---

## 其他

这一组 Case 的目标：把一些“开关语义/可用性验证”用 smoke 口径写清楚（不依赖公网大跑量）；对应的重负载/诊断脚本仍留在 diagnostics。

### Case 1：perfmetrics.enabled 功能语义（off 必须 0；on 必须增长）
**目的**
- 验证 `perfmetrics.enabled` 开关真正生效：
  - off：即使有流量，perf metrics 也不采样（samples 必须为 0）
  - on：有流量就应能采样到（samples 必须增长）
- 这条属于 smoke（功能能不能用），不是“测极限性能”。

**Given**
- 控制面可用。
- 有一条**可重复、非公网依赖**的流量触发方式（推荐复用「IP / Case 8」的 Tier‑1 payload 流量）。
- 注意：流量必须实际走到 datapath/NFQUEUE；否则 `samples` 可能一直为 0，容易误判成 “perfmetrics.enabled 没生效”。

**When**
（建议：整条 Case 先读 orig，最后 restore，避免污染其他 Case。）

1) 保存原值：
   - `CONFIG.GET(scope=device, keys=["perfmetrics.enabled"])`
2) 关闭采样窗口（off）：
   - `CONFIG.SET(scope=device, set={"perfmetrics.enabled":0})`
   - `METRICS.RESET(name=perf)`
   - 触发一次 payload 流量（固定读 N bytes；例如 65536；见「IP / Case 8」）
   - `METRICS.GET(name=perf)`
3) 开启采样窗口（on）：
   - `CONFIG.SET(scope=device, set={"perfmetrics.enabled":1})`
   - `METRICS.RESET(name=perf)`
   - 再触发一次 payload 流量（同样固定读 N bytes）
   - `METRICS.GET(name=perf)`
4) 幂等性（1→1 不清空 aggregates）：
   - `CONFIG.SET(scope=device, set={"perfmetrics.enabled":1})`
   - `METRICS.GET(name=perf)`（不 reset）
5) 非法值拒绝：
   - `CONFIG.SET(scope=device, set={"perfmetrics.enabled":2})`
6) restore 原值：
   - `CONFIG.SET(scope=device, set={"perfmetrics.enabled":<orig>})`

**Then（期望输出）**
- off：`nfq_total_us.samples==0`
- on：`nfq_total_us.samples>=1`
- 1→1 幂等：第二次 GET 的 `nfq_total_us.samples` 不应小于第一次 on 后的 samples
- 非法值：应返回 `INVALID_ARGUMENT`（并且不应改变当前配置）
- （可选）`dns_decision_us.*`：
  - 只有当 netd resolv hook 活跃且你确实触发了 DNS 解析时才可能增长；
  - 不要把它作为这条 smoke 的硬 gate（避免把 netd 环境问题误判成 perfmetrics 功能坏了）。

**现有覆盖**
- diagnostics（重负载/公网下载版）：`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
  - 里面已包含 off=0 / on=grow / 1→1 幂等 / 非法值拒绝 的验证，但它依赖设备侧 downloader + 公网 URL（更偏诊断/性能）。

**缺口**
- （自动化层面）这条 smoke 口径目前未挂进 `dx-smoke.sh` 的固定序列；如果要落地，应补一个独立 check id（不做实现，调查先记录）。

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

B) **IPRULES.APPLY：超多规则 + preflight limits**
1) `RESETALL`，并确保 `block.enabled=1`、`iprules.enabled=1`
2) 生成一组规则（同一个 uid；保证 `matchKey` 唯一，例如固定 dst，递增 dport；全部 `enabled=1`）：
   - 先做 under-limit（例如 1100 条）：应成功，但 `IPRULES.PREFLIGHT` 应出现 `rulesTotal` 的 warning（recommended 上限为 1000）
   - 再做 over-limit（例如 5001 条）：应失败（hard 上限为 5000），并返回 `INVALID_ARGUMENT` + `error.preflight.violations`
3) 失败后仍应能继续执行 `HELLO` / `IPRULES.PREFLIGHT`（验证“失败可恢复”，不影响后续用例）

**Then（期望输出）**
- `DOMAINLISTS.IMPORT` over-limit 时：
  - 返回 `INVALID_ARGUMENT`，message 类似 `import payload too large`
  - `error.limits` 必须包含 `maxImportDomains=1000000`、`maxImportBytes=16777216`，并带 `hint`（chunk 导入）
- `IPRULES.APPLY` over-limit 时：
  - 返回 `INVALID_ARGUMENT`
  - `error.preflight.violations` 中应包含 `rulesTotal` 的 limit（hard=5000）
- 上述两类失败都不应导致 daemon crash/控制面不可用（失败后 `HELLO` 仍 OK）

**现有覆盖**
- 无（当前 active smoke 不覆盖“下发规模/limits”）

**缺口**
- （自动化层面）更适合落到 diagnostics 脚本里（例如 `tests/device/diagnostics/`），并作为“上线前手工跑一次”的 checklist 项（调查先记录，不做实现）。

---

## 7) 缺口清单（按你要的两类：完善已有 / 新增用例）

### A) 完善已有用例（同一场景，补“该看的输出”）
1) **IP allow/block/iface/would**：把 `nc` 成败变成硬断言（现在普遍 `|| true` 吞掉结果）
2) **traffic metrics**：从 “total>=1” 升级为“维度级增长”
    - IP：至少看 `txp.allow/txp.block`；若要断言 bytes（`rxb/txb`、`hitBytes`）建议走「IP / Case 8」固定读写 N bytes
    - DNS：看 `dns.allow/dns.block`
3) **reasons metrics**：补 allow 路径 `IP_RULE_ALLOW.packets` 增长断言（bytes 仅在 payload 流量下断言）
4) **per-rule stats**：补 `hitBytes / wouldHitBytes`（需要 payload 流量；`nc -z` 不会稳定推动 bytes）
5) **dns stream 事件字段**：补更多字段类型/一致性校验（不只看 blocked/policySource）
6) **pkt stream 事件字段**：补“字段契约”的集中断言（见「可观测性 / Case 1」）

### B) 新增用例（现在没有这个“人话场景”）
1) **域名：DNS 真机真实解析端到端冒烟（强需求；域名 / Case 8）**
    - 明确“netd hook 不活跃”= BLOCKED（给出 prepare 命令）
    - 同时覆盖 shell uid=2000 + 真实 app uid 两条触发路径
2) **域名：DNS netd inject 端到端（稳定触发 metrics + 字段覆盖；域名 / Case 3）**
3) **域名：tracked=0 suppressed notice（域名 / Case 4）**
4) **域名：domain.custom.enabled 语义（域名 / Case 5）**
5) **域名：device vs app policy 优先级（域名 / Case 6）**
6) **域名：DomainLists enable/disable + allow 覆盖 block（域名 / Case 7）**
7) **可观测性：DNS→IP 绑定→pkt stream 带 domain（可观测性 / Case 2）**
8) **可观测性：pkt tracked=0 suppressed notice（可观测性 / Case 3）**
9) **IP：iprules.enabled=0 的 gating correctness（IP / Case 7）**
10) **IP：payload 读写稳定触发 bytes（IP / Case 8）**
11) **conntrack（L4 state）最小闭环纳入 smoke**
12) **域名：DOMAINRULES(ruleIds) 端到端（CUSTOM_RULE_*；域名 / Case 9）**
13) **其他：极端规模下的控制面下发/limits sanity（其他 / Case 2）**

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
- `iprules.enabled=0` gating correctness：暂无 smoke check id（文档见「IP / Case 7」；perf 会切开关但不做 verdict 断言：`tests/device/ip/cases/60_perf.sh`）
- payload bytes 触发（建议纳入 smoke）：文档见「IP / Case 8」；现有 helper：`tests/device/ip/lib.sh` 的 `iptest_tier1_tcp_count_bytes`；类似触发在 `tests/device/ip/cases/22_conntrack_ct.sh`（但该 case 不在 smoke profile）
- conntrack（Tier‑1）：`tests/device/ip/cases/22_conntrack_ct.sh`
- diagnostics：`tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`
