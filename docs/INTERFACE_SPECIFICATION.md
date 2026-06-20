# sucre-snort 接口规范

版本: v3.10
目标平台: Android 16, KernelSU
更新时间: 2026-06-20

---

## 1. 连接与协议

- 控制通道（vNext）: Android control socket 名称 `sucre-snort-control-vnext`（Unix Domain, SOCK_STREAM；netstring + JSON）。
- 可选 TCP 控制端口（vNext）: 60607（当存在 `/data/snort/telnet` 文件时开启；默认仅本地 Unix domain）。
- （DEV）adb forward（推荐）: `adb forward tcp:60607 localabstract:sucre-snort-control-vnext`
- DNS 监听通道: Android control socket 名称 `sucre-snort-netd`（Unix Domain, SOCK_SEQPACKET；内部二进制协议，见 §3）。

备注（Telemetry fd passing）:
- `TELEMETRY.OPEN(level=flow)` 需要通过 Unix domain socket 的 `SCM_RIGHTS` 传递 shared-memory fd。
- 因此：通过 TCP 60607 / adb forward 建立的连接**不能**打开 telemetry，只能查询 `METRICS.GET(name=telemetry)` 观察通道状态。

报文约定（control-vnext 控制通道）:
- framing: netstring `<len>:<payload>,`；`payload` 为 UTF-8 JSON object。
- request envelope：`{"id":1,"cmd":"...","args":{}}`（`args` 必须是 object）
- response envelope：`{"id":1,"ok":true,"result":{...}}` / `{"id":1,"ok":false,"error":{...}}`
- strict reject：顶层/args 出现未知 key → `SYNTAX_ERROR`；未知 `cmd` → `UNSUPPORTED_COMMAND`。
- event mode：`DIAGNOSTICS.START` 成功后该连接进入事件输出模式；事件 frame 为 JSON object（无 `id/ok`），顶层必须含 `type`。
- 备注：对外契约以本文为准；v3.7 及更早的协议/命令面设计材料已归档到 `docs/archived/`（非权威）。

vNext app selector（`args.app`）约定:
- `{"uid":10123}` 或 `{"pkg":"com.example","userId":0}`（二选一；禁止混用）。
- resolve 不存在/歧义 → `SELECTOR_NOT_FOUND` / `SELECTOR_AMBIGUOUS` + `candidates[]`（按 `uid` 升序；not found 时为空数组）。

---

## 2. 命令

说明格式: 命令 | 参数 | 返回 | 备注

2.1 通用（Meta）
- `HELLO` | `{}` | `result={protocol,protocolVersion,framing,maxRequestBytes,maxResponseBytes,daemonBuildId,artifactAbi,capabilities[]}` |
  - `protocol="control-vnext"`，`protocolVersion=1`，`framing="netstring"`。
  - `daemonBuildId` / `artifactAbi` 用于前端诊断当前 daemon 与 native artifact 身份。
  - `capabilities[]` 当前包含：`"control-vnext"`、`"nfqueue-datapath"`、`"apk-native-artifact"`、`"traffic-windows"`、`"packet-diagnostics"`。
- `QUIT` | `{}` | `ok` | response 写出后关闭连接
- `RESETALL` | `{}` | `ok` | 清空设置、统计、域名、规则、列表并持久化

2.2 清单（Inventory）
- `APPS.LIST` | `{"query"?:string,"userId"?:u32,"limit"?:u32}` | `result={apps[],truncated}` |
  - `limit` 默认 200；`0→200`；上限 1000。
  - `apps[]` item：`{uid:u32,userId:u32,app:string,allNames:string[]}`。
- `IFACES.LIST` | `{}` | `result={ifaces[]}` |
  - `ifaces[]` item：`{ifindex:u32,name:string,kind:"wifi"|"data"|"vpn"|"unmanaged",type?:u32}`（按 `ifindex` 升序）。

2.3 配置（Config）
- `CONFIG.GET` | `{"scope":"device"|"app","app"?:selector,"keys":string[]}` | `result={values:{k:v...}}` |
  - device scope keys：`block.enabled` / `iprules.enabled` / `rdns.enabled` / `perfmetrics.level` / `perfmetrics.samplePeriod` / `block.mask.default` / `block.ifaceKindMask.default` / `nfqueue.topology`
  - app scope keys：`block.mask` / `block.ifaceKindMask` / `domain.custom.enabled`
  - 所有 toggle 开关值为 `0|1`（u32）；mask 为 `u8`（用 u32 传输）。
  - `perfmetrics.level` 为 device-scope string enum：`"off"|"basic"|"detail"|"profiling"`；默认 `"basic"`。
  - `perfmetrics.samplePeriod` 为 power-of-two u32，合法范围 `256..65536`，basic 默认 `1024`；每包采样只属于 detail/profiling。
  - `nfqueue.topology` 为 device-scope string enum：`"split-in-out"`（默认）或 `"shared-flow-pool"`。
- `CONFIG.SET` | `{"scope":"device"|"app","app"?:selector,"set":{k:v...}}` | `ok` |
  - `set` key 集合与 `CONFIG.GET` 一致；不支持的 key → `INVALID_ARGUMENT`。
  - `nfqueue.topology` 会持久化到 settings，但只在 daemon 下次启动时用于安装 NFQUEUE rules；`CONFIG.SET` 不热重建当前 listener / iptables。UI 前端只表达用户意图，RuntimeService 负责 stop/start daemon、清理/重建 NFQUEUE hooks 并在启动后执行 `HELLO` 校验。

2.4 域名规则与策略（Domain）
- `DOMAINRULES.GET` | `{}` | `result={rules[]}` |
  - `rules[]` item：`{ruleId:u32,type:"domain"|"wildcard"|"regex",pattern:string}`（按 `ruleId` 升序）。
- `DOMAINRULES.APPLY` | `{"rules":rules[]}` | `result={rules[]}` |
  - `rules[]` item：`{ "ruleId"?:u32, "type":"domain"|"wildcard"|"regex", "pattern":string }`。
  - 语义为“整体对齐”：新增/更新/删除 baseline rules；删除受引用约束（见错误 `error.conflicts[]`）。
- `DOMAINPOLICY.GET` | `{"scope":"device"|"app","app"?:selector}` | `result={policy}` |
  - `policy={allow:{domains:string[],ruleIds:u32[]},block:{domains:string[],ruleIds:u32[]}}`。
- `DOMAINPOLICY.APPLY` | `{"scope":"device"|"app","app"?:selector,"policy":policy}` | `ok` |
  - 语义为“整体对齐”：分别对齐 allow/block 的 domains 与 ruleIds；未知 ruleId → `INVALID_ARGUMENT`（含 `error.hint`）。
- `DEV.DOMAIN.QUERY` | `{"app":selector,"domain":string}` | `result={uid,userId,app,domain,blocked,policySource,ruleId?}` |
  - DEV-only（用于调试一次 DomainPolicy 判决）；`blocked` 为 boolean。
  - `ruleId` 仅当 `policySource` 来自规则分支且该 decision 实际来自 rule（非名单）时出现。

2.5 域名清单（DomainLists）
- `DOMAINLISTS.GET` | `{}` | `result={lists[]}` |
  - `lists[]` item：`{listId:guid36,listKind:"block"|"allow",mask:u32,enabled:0|1,url:string,name:string,updatedAt:string,etag:string,outdated:0|1,domainsCount:u32}`
- `DOMAINLISTS.APPLY` | `{"upsert"?:list[],"remove"?:guid36[]}` | `result={removed:guid36[],notFound:guid36[]}` |
  - `upsert[]` item 关键字段：`{listId,listKind,mask,enabled}`（其余元数据字段可一并更新）。
- `DOMAINLISTS.IMPORT` | `{"listId":guid36,"listKind":"block"|"allow","mask":u32,"clear"?:0|1,"domains":string[]}` | `result={imported:u32}` |
  - 限制：`maxImportDomains=1,000,000`；`maxImportBytes=16MB`（超限 `error.limits + error.hint`）。
  - `listId` 必须已存在（用 `DOMAINLISTS.APPLY` 创建）；`listKind/mask` 必须与已存元数据一致。

2.6 IP 规则（IPRules；pre-SNORT-10 current-head direct mutation surface）

SNORT-10 Authoring Layer 一致性说明：下面 `IPRULES.PREFLIGHT/PRINT/APPLY`
是 pre-SNORT-10 current-head 的直接 per-app mutation surface 记录，不是
SNORT-10 新目标的权威 mutation contract。SNORT-10 新目标以 Authoring
Layer v1 为准：daemon 持有 Authoring Policy Bundle，状态点为 `Draft`、
`Committed Policy Revision`、最近 5 个 `Checkpoint` 与 `Runtime Snapshot`；
流程为 `Edit Draft -> Commit Draft -> Apply Commit -> Checkpoint + Runtime Snapshot`；
packet path 只读取 `Runtime Snapshot`。具体 command names / JSON schema / draft CRUD /
checkpoint id / persistence / migration 策略在 SNORT-17 implementation slice 中定义。

- `IPRULES.PREFLIGHT` | `{}` | `result={summary,byFamily,limits,warnings,violations}` |
- `IPRULES.PRINT` | `{"app":selector}` | `result={uid,rules[]}` |
  - `rules[]` item（只读快照，含统计）：`{ruleId:u32,clientRuleId:string,matchKey:string,action,priority,enabled,enforce,log,family,dir,iface,ifindex,proto,ct,src,dst,sport,dport,stats}`
- `IPRULES.APPLY` | `{"app":selector,"rules":applyRules[]}` | `result={uid,rules[]}` |
  - `applyRules[]` item（写入对象，不得包含 `ruleId/matchKey/stats`）：
    `{clientRuleId:string,action:"allow"|"block",priority:i32,enabled:0|1,enforce:0|1,log:0|1,family:"ipv4"|"ipv6",dir:"any"|"in"|"out",iface:"any"|"wifi"|"data"|"vpn"|"unmanaged",ifindex:u32,proto:"any"|"tcp"|"udp"|"icmp"|"other",ct:{state:"any"|"new"|"established"|"invalid",direction:"any"|"orig"|"reply"},src:string,dst:string,sport:string,dport:string}`
  - `src/dst`: `family=ipv4` 时为 `any` 或 `a.b.c.d/prefix`；`family=ipv6` 时为 `any` 或 IPv6 CIDR。
  - `sport/dport`: `any|N|lo-hi`；当 `proto=icmp|other` 时必须为 `any`。
  - 成功返回 committed mapping：`rules[]` item 为 `{clientRuleId,ruleId,matchKey}`（matchKey 为 mk2）。
  - `matchKey`（mk2；固定顺序、全小写、无空格）：
    - `mk2|family=<ipv4|ipv6>|dir=<...>|iface=<...>|ifindex=<...>|proto=<...>|ctstate=<...>|ctdir=<...>|src=<...>|dst=<...>|sport=<...>|dport=<...>`
    - CIDR 规范化为网络地址（host bits 清零）；`ifindex=0` 表示 any；`proto=icmp|other` 时 `sport/dport=any`。

2.7 策略检查点（Checkpoint；pre-SNORT-10 current-head）

SNORT-10 Authoring Layer 一致性说明：下面固定 slot 的 `CHECKPOINT.*` 是 pre-SNORT-10 current-head control surface 记录。SNORT-10 新目标以 IPRULES Authoring Layer v1 为准：`Draft -> Commit -> Apply -> Checkpoint + Runtime Snapshot`，checkpoint 为最近 5 个 full Authoring Policy Bundle snapshot，具体新 API schema 后续在 authoring/API 实现切片中定义。后续 issue 拆分不得把固定 `0..2` slot surface 当作 SNORT-10 新目标。

- `CHECKPOINT.LIST` | `{}` | `result={slots[],slotCount,maxSlotBytes}` |
  - pre-SNORT-10 slot surface 固定只暴露 3 个 slot：`0/1/2`；`slots[]` 必须按 `slot` 升序返回。
  - slot item：`{slot:u32,present:bool,formatVersion?:u32,sizeBytes?:u64,createdAt?:u64}`；后 3 项仅 `present=true` 时出现。
- `CHECKPOINT.SAVE` | `{"slot":0|1|2}` | `result={slot:{slot,present,formatVersion?,sizeBytes?,createdAt?},maxSlotBytes}` |
  - 原子替换所选 slot；bundle 超过 64 MiB 时返回 `CAPACITY_EXCEEDED`，旧 slot 内容保持可恢复。
- `CHECKPOINT.RESTORE` | `{"slot":0|1|2}` | `result={slot:{slot,present,formatVersion?,sizeBytes?,createdAt?},maxSlotBytes}` |
  - 空 slot 返回 `NOT_FOUND`。
  - restore 先完整解析/验证 bundle（版本、DomainPolicy rule 引用、DomainLists 元数据/内容、IPRULES preflight 等），失败时 live policy 不变。
  - 成功后开启新的 policy runtime epoch：清 conntrack、IPRULES cache、旧 policy epoch 的 metrics、active diagnostics session 与 telemetry session；客户端需要重新打开 diagnostics / telemetry consumer。Domain-IP Association 不属于当前 Play-facing 第一轮。
- `CHECKPOINT.CLEAR` | `{"slot":0|1|2}` | `result={slot:{slot,present,formatVersion?,sizeBytes?,createdAt?},maxSlotBytes}` |
  - 幂等删除所选 slot；空 slot 也返回 `ok=true` 且 `slot.present=false`。
- 所有 `CHECKPOINT.*` 命令 strict JSON；未知 `args` key 返回 `SYNTAX_ERROR`，缺少 `slot` 返回 `MISSING_ARGUMENT`，非法 slot 返回 `INVALID_ARGUMENT`。
- bundle 仅包含 verdict-affecting policy：device/app verdict config、DomainRules、DomainPolicy、DomainLists 元数据与内容、IPRULES rules/nextRuleId；不包含 frontend metadata、历史、统计、stream replay、Flow Telemetry records、Geo/ASN、health/billing/diagnostic export。

2.8 观测（Metrics / Telemetry / Traffic Windows / Diagnostics）
- `METRICS.GET` | `{"name":name,"app"?:selector}` | `result` |
  - `name=perf` → `result.perf`；shape 由 `perfmetrics.level` 决定：
    - `level="off"` 时只返回 `{level:"off"}`。
    - 非 off 时返回 `{level,epoch,windowStartMonoMs,nowMonoMs,packetVerdictLatencyUs,nfqueueHealth,profiling?}`。
    - `packetVerdictLatencyUs` 表示 NFQUEUE callback start 到 verdict send return 的 daemon-side 成本；不包含 kernel queue wait、kernel→userspace copy 前置成本、app RTT 或远端网络延迟。
    - `basic` 使用 sampled latency，必须返回 `sampled=true`、`eligiblePackets`、`sampledPackets`、`samplePeriod`；p50/p95/p99 为 bucket upper bound。
    - `profiling` 可额外返回 `profiling.perStageLatencyUs`，只供开发 / CI / 发版前测量，不作为普通用户 detail 面。
  - `name=reasons` → `result.reasons{IFACE_BLOCK,ALLOW_DEFAULT,IP_RULE_ALLOW,IP_RULE_BLOCK}`；每项为 `{packets,bytes}`。Resolved-IP / DPI 相关 reason 只在对应后续模块实现时新增。
  - `name=domainSources` → `result.sources{...}`（device 或 app 维度）；app 维度额外返回 `{uid,userId,app}`。
  - `name=conntrack` → `result.conntrack{totalEntries,creates,expiredRetires,overflowDrops,byFamily{ipv4,ipv6}}`。
  - `name=domainRuleStats` → `result.domainRuleStats{rules[]}`（device-only；禁止 `args.app`）：
    - `rules[]` item：`{ruleId:u32,allowHits:u64,blockHits:u64}`（按 `ruleId` 升序；baseline 全量覆盖）。
  - `name=telemetry` → `result.telemetry{enabled,consumerPresent,sessionId,slotBytes,slotCount,recordsWritten,recordsDropped,lastDropReason,lastError?}`（device-only；禁止 `args.app`）：
    - `enabled`: 当前是否存在 `level=flow` 的 telemetry session（boolean）。
    - `consumerPresent`: 当前是否存在 telemetry consumer session（boolean；`enabled=false` 时必为 false）。
    - `lastDropReason`: `"none"|"consumerAbsent"|"slotBusy"|"recordTooLarge"|"disabled"|"resourcePressure"`。
- `METRICS.RESET` | `{"name":name,"app"?:selector}` | `ok` |
  - 支持 reset：`perf` / `reasons` / `domainSources` / `domainRuleStats`。
  - `METRICS.RESET(name=perf)` 清当前 perf window / 切新 epoch，不改变 `perfmetrics.level`。
  - `METRICS.RESET(name=conntrack)`：不支持，返回 `INVALID_ARGUMENT`（提示使用 `RESETALL`）。
- `TELEMETRY.OPEN` | `{"level":"off"|"flow","config"?:{...}}` | `result={actualLevel,sessionId,abiVersion,slotBytes,slotCount,ringDataBytes,maxPayloadBytes,writeTicketSnapshot}` |
  - `level=off` 等价于关闭 telemetry（同 `TELEMETRY.CLOSE`）；返回 `actualLevel="off"`。
  - `level=flow` 仅支持 Unix domain vNext 连接；成功时服务端会在 response 的 ancillary data 中通过 `SCM_RIGHTS` 传递 shared-memory fd（response JSON 中不包含 fd 字段）。
  - 在 TCP/adb-forward 连接上调用 `TELEMETRY.OPEN(level=flow)` 必失败：`INVALID_ARGUMENT` + `error.hint="use vNext Unix domain socket (fd passing required)"`。
  - `config`（可选覆盖，未知 key → `SYNTAX_ERROR`）：
    - ring: `slotBytes(u32)`, `ringDataBytes(u64)`
    - poll/emit: `pollIntervalMs(u32)`, `bytesThreshold(u64)`, `packetsThreshold(u64)`, `maxExportIntervalMs(u32)`
    - TTL: `invalidTtlMs(u32)`
    - limits: `maxFlowEntries(u32)`, `maxEntriesPerUid(u32)`
  - records 通过 shared-memory ring 输出；二进制 ABI 见下方 “Flow Telemetry shared-memory ABI”。
- `TELEMETRY.CLOSE` | `{}` | `ok` |
  - idempotent；会作废旧 session（consumer 端需停止 ingest 并在需要时重新 OPEN）。
  - daemon 可在关闭前 bounded best-effort 导出 `FLOW END(endReason=TELEMETRY_DISABLED)`；cleanup 预算按 scanned bucket / entry 计算，ring write 失败也不能扩大扫描范围；consumer 仍必须把 session boundary 当作活跃状态截断点，不能要求每个 active flow 都有 disabled END。
- `TRAFFIC_WINDOWS.CONFIG.GET` | `{}` | `result={config}` |
  - `config={enabled:0|1,detailEnabled:0|1,windows:[{durationSec:u32}]}`；默认 windows 为 `900/3600/18000/86400`。
- `TRAFFIC_WINDOWS.CONFIG.SET` | `{"set":{enabled?:0|1,detailEnabled?:0|1,windows?:[{durationSec:u32}]}}` | `ok` |
  - `set:{}` 合法且 no-op；`windows` 一旦出现必须提交完整数组，数量 `1..4`，每个 duration `60..86400` 且不重复。
  - 任意有效配置变化都 reset 全部 Traffic Windows runtime state；response 不返回 `reset` 字段。
- `TRAFFIC_WINDOWS.GET` | `{"durationSec":u32,"app"?:selector,"topKLimit"?:u32}` | `result={enabled:0}` or `result={durationSec,coveredSec,scope,detailEnabled,directions,uid?,userId?,app?}` |
  - `durationSec` 必须匹配一个 active window；一次只返回一个 window。
  - `topKLimit` 默认 10，合法范围 `1..64`，只控制每个 Top-K array 的返回数量，不进入持久配置。
  - 当 Traffic Windows `enabled=0` 时只返回 `{enabled:0}`，不返回 zero-filled window。
  - 当 `enabled=1` 时，`directions.in/out` 必须固定出现；`scope="device"` 不返回 app identity，`scope="app"` 返回 `{uid,userId,app}`。
  - 每个 direction item 包含 `{acceptedPackets,acceptedBytes,blockedPackets,remoteIpTopK[],protocolTopK[],protocolPortTopK[]}`。
  - `detailEnabled=0` 时仍返回 basic counters，并把三个 Top-K array 返回为空数组；Top-K 只统计 accepted traffic。
  - 不返回 blocked bytes，不返回 DNS traffic，不返回 domain hint。
- `TRAFFIC_WINDOWS.APPS` | `{"durationSec":u32,"limit"?:u32}` | `result={enabled:0}` or `result={durationSec,coveredSec,apps[]}` |
  - `limit` 默认 50，上限 200。
  - 当 Traffic Windows `enabled=0` 时只返回 `{enabled:0}`，不返回空 ranking。
  - 只返回该 window 内有 accepted traffic 的 app；blocked-only app 不进入 ranking。
  - app item 至少包含 `{uid,userId,app,totalAcceptedBytes,totalAcceptedPackets,directions}`；`directions.in/out` 只包含 basic counters `{acceptedPackets,acceptedBytes,blockedPackets}`。
  - 排序为 `totalAcceptedBytes desc, totalAcceptedPackets desc, uid asc`。
- `TRAFFIC_WINDOWS.RESET` | `{}` | `ok` |
  - 清空 device aggregate 与所有 per-app Traffic Windows runtime state，不修改持久化配置。
- `DIAGNOSTICS.START` | `{"channel":"packet","app":selector}` | `result={channel,uid,userId,app}` |
  - 第一版只支持 `channel="packet"`，一次只允许一个 active Diagnostic Focus。
  - 需要 `block.enabled=1` 且 `iprules.enabled=1`；否则返回明确错误，不进入事件模式。
  - 成功后该连接进入 diagnostics event mode；同一连接除 `DIAGNOSTICS.STOP` 外的普通 command 返回 `STATE_CONFLICT`。
  - Focus 由 session 持有；`DIAGNOSTICS.STOP` 只接受 owning diagnostics connection 上的请求，socket detach 或连接关闭也会释放。已有 active session 时新的 START 返回 conflict；普通新 control connection 不能停止别的 session。
- `DIAGNOSTICS.STOP` | `{}` | `ok` |
  - ack 后服务端关闭该 diagnostics 连接，不回到普通 control mode。

Packet diagnostics event（JSON object，无 `id/ok`）：
- `diagnostic.packet`：`{type:"diagnostic.packet",timestamp,uid,userId,app,packet,inputs,gates,final,stages[]}`
  - `packet` 至少包含 `{packetDirection,nfqueueHook,ipVersion,protocol,l4Status,portsAvailable,srcIp?,dstIp?,srcPort,dstPort,originalIpBytes,copiedBytes,truncated,ifindex?,ifaceKind?}`。
  - `gates` 集中输出 `{blockEnabled,iprulesEnabled,resolvedIpPolicyEnabled?}`。
  - `final` 使用统一 winner 模型：`{accepted,reasonId,ruleId?,ruleMode?}`；不输出 `wouldRuleId` / `wouldDrop`。source rule 声明动作由 `ruleSnapshots[].action` 表达，不在 `final` 中重复输出。
  - `stages[]` 固定顺序：`ifaceBlock` → `basicIprules` → `statefulIprules` → `resolvedIpPolicy` → `defaultAllow`。未来 DPI 实现后在 `statefulIprules` 与 `resolvedIpPolicy` 之间加入 `dpiPolicy`。
  - 每个 stage 至少包含 `{name,enabled,evaluated,matched,outcome,winner?,skipReason?,ruleSnapshots?,candidates?}`。
  - 诊断事件不输出 legacy `host` / `domain` 字段；IP→domain 展示属于后续 Domain-IP Association 查询能力，当前 Play-facing 第一轮不实现。
- `diagnostic.notice`：`{type:"diagnostic.notice",notice:"dropped"|"stopped",channel:"packet",...}`。
  - 只保留 dropped/stopped 类保护性 notice；不输出 started notice 或 suppressed notice。

DNS stream 冻结说明：
- 旧 DNS debug stream 暂时冻结，不并入 `DIAGNOSTICS.*`，本轮不扩展、不删除、不桥接。当前前端不调用它；只要不影响 packet hot path，就不纳入 SNORT-10 packet-side 重构。
- packet-side `STREAM.START(type=pkt|activity)`、replay、`tracked` gate、suppressed notice、activity stream 不属于 SNORT-10 新接口 contract。

Flow Telemetry shared-memory ABI（`abiVersion=1`）:
- 默认 sizing：`slotBytes=1024`、`ringDataBytes=16777216`（16 MiB）、`slotCount=16384`、`slotHeaderBytes=24`、`maxPayloadBytes=1000`。
- 所有多字节整数均为 little-endian；offset 从 slot 或 payload 起点计算；不要依赖 C++ struct padding。
- producer 使用递增 `ticket` 写入固定 slot：`slotIndex = ticket % slotCount`。consumer 从 `TELEMETRY.OPEN.result.writeTicketSnapshot` 开始读，忽略更早 ticket，并按 ticket 去重；ticket gap 表示 producer drop、consumer 落后或 slot 被覆盖。
- 读取建议：以 acquire 语义读取 `state`；仅当 `state=Committed(2)` 时读取 header/payload；`payloadSize` 必须 `<= maxPayloadBytes`；未知 `recordType` 按 `payloadSize` 跳过。

slot header（offset from slot start）:

| Offset | Field | Type | 说明 |
| --- | --- | --- | --- |
| 0 | `state` | u32 | `0=Empty`, `1=Writing`, `2=Committed` |
| 4 | `recordType` | u16 | `1=FLOW`, `2=DNS_DECISION` |
| 6 | `reserved0` | bytes[2] | 保留；consumer 必须忽略 |
| 8 | `ticket` | u64 | producer 全局递增 ticket |
| 16 | `payloadSize` | u32 | payload 实际字节数 |
| 20 | `reserved1` | bytes[4] | 保留；consumer 必须忽略 |
| 24 | `payload` | bytes | 长度为 `payloadSize` |

`recordType=1` FLOW payload v1（fixed size `160` bytes）:

> 兼容性说明：本布局直接替换旧 102-byte `FLOW` payload v1；不提供 `FLOW v2`、双写或旧 offset 兼容窗口。consumer 必须按本表解码。

| Offset | Field | Type | 说明 |
| --- | --- | --- | --- |
| 0 | `payloadVersion` | u8 | 固定为 `1` |
| 1 | `kind` | u8 | `1=Begin`, `2=Update`, `3=End` |
| 2 | `observationKind` | u8 | `0=NORMAL`, `1=L3_OBSERVATION` |
| 3 | `ctState` | u8 | `0=ANY`, `1=NEW`, `2=ESTABLISHED`, `3=INVALID` |
| 4 | `ctDir` | u8 | `0=ANY`, `1=ORIG`, `2=REPLY` |
| 5 | `packetDir` | u8 | `0=unknown`, `1=in`, `2=out`；真实 packet 方向 |
| 6 | `flowOriginDir` | u8 | `0=unknown`, `1=in`, `2=out`；flow/observation 首包方向 |
| 7 | `verdict` | u8 | `0=unknown`, `1=allow`, `2=block` |
| 8 | `reasonId` | u8 | `0=IFACE_BLOCK`, `1=ALLOW_DEFAULT`, `2=IP_RULE_ALLOW`, `3=IP_RULE_BLOCK`, `4=RESERVED` |
| 9 | `ifaceKindBit` | u8 | 见 §4 `ifaceKind` 位 |
| 10 | `l4Status` | u8 | `0=KNOWN_L4`, `1=OTHER_TERMINAL`, `2=FRAGMENT`, `3=INVALID_OR_UNAVAILABLE_L4` |
| 11 | `flags` | u8 | bit0 `hasRuleId`, bit1 `isIpv6`, bit2 `pickedUpMidStream`, bit3 `uidKnown`, bit4 `ifindexKnown`, bit5 `portsAvailable` |
| 12 | `endReason` | u8 | `0=NONE`, `1=IDLE_TIMEOUT`, `2=TCP_END_DETECTED`, `3=RESOURCE_EVICTED`, `4=TELEMETRY_DISABLED` |
| 13 | `proto` | u8 | IP protocol number（例如 TCP=6, UDP=17, ICMP=1, ICMPv6=58） |
| 14 | `srcPort` | u16 | 仅当 `flags.portsAvailable=1` 时有效；否则为 0 |
| 16 | `dstPort` | u16 | 仅当 `flags.portsAvailable=1` 时有效；否则为 0 |
| 18 | `icmpType` | u8 | ICMP/ICMPv6 type；非 ICMP 为 0 |
| 19 | `icmpCode` | u8 | ICMP/ICMPv6 code；非 ICMP 为 0 |
| 20 | `icmpId` | u16 | ICMP/ICMPv6 id；不可用时为 0 |
| 22 | `ruleMode` | u8 | `0=none`, `1=enforce`, `2=observe`；无 rule winner 时为 `none` |
| 23 | `reserved0` | u8 | 保留 |
| 24 | `timestampNs` | u64 | record event/export monotonic timestamp |
| 32 | `firstSeenNs` | u64 | flow/observation 首个 packet monotonic timestamp |
| 40 | `lastSeenNs` | u64 | flow/observation 最近 packet monotonic timestamp；END 中不等同于 retire/export 时间 |
| 48 | `flowInstanceId` | u64 | flow/observation instance id |
| 56 | `recordSeq` | u64 | flow 内 record 序号；仅在成功写入 ring 后递增 |
| 64 | `uid` | u32 | Android uid；仅当 `flags.uidKnown=1` 时可解释为真实 uid |
| 68 | `userId` | u32 | Android user id |
| 72 | `ifindex` | u32 | observed interface index；仅当 `flags.ifindexKnown=1` 时有效 |
| 76 | `srcAddr` | bytes[16] | IPv4 使用前 4 bytes；IPv6 使用 16 bytes |
| 92 | `dstAddr` | bytes[16] | IPv4 使用前 4 bytes；IPv6 使用 16 bytes |
| 108 | `totalPackets` | u64 | cumulative packets；不是 since-last-export delta |
| 116 | `totalBytes` | u64 | cumulative bytes；不是 since-last-export delta |
| 124 | `inPackets` | u64 | cumulative inbound packets |
| 132 | `inBytes` | u64 | cumulative inbound bytes |
| 140 | `outPackets` | u64 | cumulative outbound packets |
| 148 | `outBytes` | u64 | cumulative outbound bytes |
| 156 | `ruleId` | u32 | 仅当 `flags.hasRuleId=1` 时有效 |

`observationKind=L3_OBSERVATION` 用于 fragment / invalid / unavailable L4 的 telemetry-only L3 observation：`portsAvailable=0`，`srcPort=dstPort=0`，不伪造正常 TCP/UDP/ICMP lifecycle。`DNS_DECISION` 仍是独立 blocked-only record，`FLOW` 不携带 DNS/IP join、domain hint、would-match 或 Packet Diagnostics explainability 字段。

`reasonId` 使用共享 packet verdict reason enum；SNORT-10 第一轮正常 `FLOW` records 不发出 `IFACE_BLOCK`，因为 Interface / Basic final block 会在 CT 前 short-circuit。该 enum value 仅保留为共享 reason id 的稳定值。

Flow Telemetry 是显式 CT observation consumer，与 `iprules.enabled` 解耦：当 `level=flow` consumer active 时，eligible 且未被 Base/Basic final block 短路的可追踪 L4 包会采集 `ctState/ctDir`，即使 IP rules policy evaluation 已关闭；该 telemetry-only observation 不改变 packet verdict。`IFACE_BLOCK` 或 Basic enforce block 已产生 final block 的 packet 不为 telemetry 拉起 CT，也不生成正常 `FLOW` record。资源驱逐会 best-effort 写 `FLOW END(endReason=RESOURCE_EVICTED)`，写失败只进入 telemetry drop/pressure 口径。

`recordType=2` DNS_DECISION payload v1（blocked-only；fixed header `32` bytes）:

| Offset | Field | Type | 说明 |
| --- | --- | --- | --- |
| 0 | `payloadVersion` | u8 | 固定为 `1` |
| 1 | `flags` | u8 | bit0 `hasRuleId`, bit1 `queryNameTruncated` |
| 2 | `policySource` | u8 | `0=CUSTOM_WHITELIST`, `1=CUSTOM_BLACKLIST`, `2=CUSTOM_RULE_WHITE`, `3=CUSTOM_RULE_BLACK`, `4=DOMAIN_DEVICE_WIDE_AUTHORIZED`, `5=DOMAIN_DEVICE_WIDE_BLOCKED`, `6=MASK_FALLBACK` |
| 3 | `reserved0` | u8 | 保留 |
| 4 | `queryNameLen` | u16 | `0..255` |
| 6 | `reserved1` | u16 | 保留 |
| 8 | `timestampNs` | u64 | monotonic timestamp |
| 16 | `uid` | u32 | Android uid |
| 20 | `userId` | u32 | Android user id |
| 24 | `ruleId` | u32 | 无 ruleId 时为 0；以 `flags.hasRuleId` 判断有效性 |
| 28 | `reserved2` | u32 | 保留 |
| 32 | `queryName` | bytes[`queryNameLen`] | 原始 bytes，非 NUL 结尾；超 255 bytes 时截断并置 `queryNameTruncated` |

payload 演进规则：每个 payload 自带 `payloadVersion`；consumer 必须先验证自身需要的最小长度，再用 `payloadSize` 跳过未知尾部。当前 `FLOW` v1 的 raw-facts completeness 是一次明确的 breaking replacement；后续非 breaking 字段才按 append-only 处理。

语义锁定参考: 本文（§2.6/§2.7/§2.8 的枚举、字段口径、Traffic Windows / Diagnostics 命令面与 telemetry ABI 即为锁定语义）。

---

## 3. DNS Listener（二进制协议）

说明：该通道为内部接口（Netd→snort），不作为前端对外契约；对外控制面以 vNext 为准（§1/§2）。

请求（客户端→服务端，按序）:
1) `uint32 len`（3..HOST_NAME_MAX）
2) `char[len] domain`（可含结尾 `\0`，服务端会截去）
3) `uint32 uid`

响应前置（服务端→客户端）:
1) `bool verdict`（1=允许，0=拦截）
2) `bool getips`（是否继续上传解析到的 IP）

若 `getips` 为 1，则随后循环上传 IP 集合:
- 重复: `int family`（`AF_INET`/`AF_INET6`；结束以 `-1`）
- 若 `AF_INET`: 读取一个 IPv4 地址
- 若 `AF_INET6`: 读取一个 IPv6 地址

域名变更时，服务端会先清空该域名旧 IP 再接收新 IP。

---

## 4. 关键常量

- vNext TCP 端口: `controlVNextPort=60607`（仅当存在 `/data/snort/telnet` 文件时开启）。
- vNext Unix socket: `sucre-snort-control-vnext`（Android abstract namespace；常见路径为 `/dev/socket/sucre-snort-control-vnext`）。
- vNext payload 限制: `controlVNextMaxRequestBytes=16MB`、`controlVNextMaxResponseBytes=16MB`。
- packet diagnostics caps：`maxDiagnosticPendingEvents=256`；诊断通道超出 bounded queue 后只输出 dropped notice，不阻塞 verdict。
- blockMask 位（u8）:
  - BlockingList/DomainList mask 必须是单 bit：`1/2/4/8/16/32/64`
  - App blockMask 可组合 `1/2/4/8/16/32/64` 与 `128(custom)`；若包含 `8(reinforced)` 则会隐式包含 `1(standard)`。
- ifaceKind 位（u8）: `1(wifi)` / `2(data)` / `4(vpn)` / `128(unmanaged)`（可组合；用于 `block.ifaceKindMask*` 与 `pkt.ifaceKindBit`）。

---

## 5. 参数与返回细节

协议与返回：
- vNext 仅支持 strict JSON；`request.args` 必须是 object。
- response:
  - `ok=true` 时可省略 `result`。
  - `ok=false` 时必含 `error` object；至少含 `{code,message}`，并可能附带 `hint/candidates/conflicts/limits/preflight/truncated` 等扩展字段。
- `DIAGNOSTICS.START` 后连接进入 diagnostics event mode：同一 owning diagnostics connection 除 `DIAGNOSTICS.STOP` 外其他命令均返回 `STATE_CONFLICT`；普通新 control connection 不能停止已有 diagnostics session。

开关与数值约定：
- 设备/应用配置的布尔开关统一使用 `0|1`（u32），不是 JSON boolean（例如 `block.enabled`）。
- diagnostics / telemetry / stream-like event 中的 `blocked/accepted/...` 为 JSON boolean（见 §2.8）。

容量与限制：
- 单帧最大请求/响应 payload：16MB（也会通过 `HELLO` 返回）。
- `DOMAINLISTS.IMPORT` 附加限制：`domains` 数量 ≤ 1,000,000；domain 字符串总字节数 ≤ 16MB。
- pre-SNORT-10 `CHECKPOINT.*` slot bundle 上限：64 MiB/slot；slot ID 固定为 `0..2`。SNORT-10 Authoring Layer checkpoint API 后续另定。

多用户支持：
- 多数 app 维度命令通过 `args.app` 明确指定 userId 或 uid；服务端在 `result` 中返回 `{uid,userId,app}` 以便客户端校验。

---

## 6. 索引

通用: HELLO, QUIT, RESETALL
清单: APPS.LIST, IFACES.LIST
配置: CONFIG.GET, CONFIG.SET
域名: DOMAINRULES.GET/APPLY, DOMAINPOLICY.GET/APPLY, DOMAINLISTS.GET/APPLY/IMPORT, DEV.DOMAIN.QUERY(dev)
IP: IPRULES.PREFLIGHT/PRINT/APPLY（pre-SNORT-10 current-head direct mutation surface）；SNORT-10 Authoring Layer API 待 SNORT-17 定义
检查点: CHECKPOINT.LIST/SAVE/RESTORE/CLEAR（pre-SNORT-10 fixed-slot surface）；SNORT-10 latest-five Authoring checkpoints API 待 SNORT-17 定义
观测: METRICS.GET, METRICS.RESET, TELEMETRY.OPEN, TELEMETRY.CLOSE, TRAFFIC_WINDOWS.CONFIG.GET/SET, TRAFFIC_WINDOWS.GET/APPS/RESET, DIAGNOSTICS.START/STOP

---

## 7. 文件路径（只列稳定项）

- 设置: `/data/snort/settings`
- TCP 暴露 gating: `/data/snort/telnet`
- 保存目录: `/data/snort/save/`
  - 应用（系统 UID，user 0）: `/data/snort/save/system/<appId>`
  - 应用（包名，user 0）: `/data/snort/save/packages/<package>`
  - 应用（系统 UID，非 0 用户）: `/data/snort/save/user<userId>/system/<appId>`
  - 应用（包名，非 0 用户）: `/data/snort/save/user<userId>/packages/<package>`
  - 域名统计: `/data/snort/save/stats_domains`
  - 规则: `/data/snort/save/rules`
  - 全局统计: `/data/snort/save/stats_total`
  - 拦截列表元数据: `/data/snort/save/blocking_lists`
  - 域名清单目录: `/data/snort/save/domains_lists/`
  - pre-SNORT-10 策略检查点目录: `/data/snort/save/policy_checkpoints/slot0.bundle` .. `slot2.bundle`
- 包清单: `/data/system/packages.list`

---

## 8. 接口快速校验清单（代表性用例）

说明：以下以 `sucre-snort-ctl` 为例（host 工具；默认目标 `127.0.0.1:60607`）。

- 连接/基础
  - `sucre-snort-ctl HELLO` → `protocol=control-vnext` + limits
  - `sucre-snort-ctl QUIT` → 连接关闭
- 全局清空
  - `sucre-snort-ctl RESETALL`
- 清单
  - `sucre-snort-ctl APPS.LIST '{\"query\":\"com.\",\"userId\":0,\"limit\":50}'` → `{apps[],truncated}`
  - `sucre-snort-ctl IFACES.LIST` → `{ifaces[]}`
- 配置
  - device: `sucre-snort-ctl CONFIG.GET '{\"scope\":\"device\",\"keys\":[\"block.enabled\",\"iprules.enabled\",\"rdns.enabled\"]}'`
  - device: `sucre-snort-ctl CONFIG.SET '{\"scope\":\"device\",\"set\":{\"block.enabled\":1}}'`
  - nfqueue topology: `sucre-snort-ctl CONFIG.GET '{\"scope\":\"device\",\"keys\":[\"nfqueue.topology\"]}'`
  - nfqueue topology next start: `sucre-snort-ctl CONFIG.SET '{\"scope\":\"device\",\"set\":{\"nfqueue.topology\":\"shared-flow-pool\"}}'`
  - perf level: `sucre-snort-ctl CONFIG.SET '{\"scope\":\"device\",\"set\":{\"perfmetrics.level\":\"basic\"}}'`
- 域名策略
  - `sucre-snort-ctl DOMAINRULES.GET`
  - `sucre-snort-ctl DOMAINPOLICY.GET '{\"scope\":\"device\"}'`
  - `sucre-snort-ctl DOMAINPOLICY.APPLY '{\"scope\":\"device\",\"policy\":{\"allow\":{\"domains\":[],\"ruleIds\":[]},\"block\":{\"domains\":[],\"ruleIds\":[]}}}'`
- 域名清单
  - `sucre-snort-ctl DOMAINLISTS.GET`
  - `sucre-snort-ctl DOMAINLISTS.APPLY '{\"upsert\":[{\"listId\":\"00000000-0000-0000-0000-000000000000\",\"listKind\":\"block\",\"mask\":1,\"enabled\":1,\"url\":\"\",\"name\":\"\",\"updatedAt\":\"\",\"etag\":\"\",\"outdated\":0,\"domainsCount\":0}]}'`
  - `sucre-snort-ctl DOMAINLISTS.IMPORT '{\"listId\":\"00000000-0000-0000-0000-000000000000\",\"listKind\":\"block\",\"mask\":1,\"clear\":1,\"domains\":[\"example.com\"]}'`
- IP 规则
  - 以下为 pre-SNORT-10 current-head direct mutation surface；SNORT-10 Authoring Layer 新 API 待 SNORT-17 定义。
  - `sucre-snort-ctl IPRULES.PREFLIGHT`
  - `sucre-snort-ctl IPRULES.PRINT '{\"app\":{\"uid\":10123}}'`
  - `sucre-snort-ctl IPRULES.APPLY @/tmp/iprules_apply.json` → `{uid,rules:[{clientRuleId,ruleId,matchKey}]}`（matchKey 为 mk2）
- 策略检查点
  - 以下为 pre-SNORT-10 current-head slot surface；SNORT-10 Authoring Layer 新 API 待单独定义。
  - `sucre-snort-ctl CHECKPOINT.LIST`
  - `sucre-snort-ctl CHECKPOINT.SAVE '{\"slot\":0}'`
  - `sucre-snort-ctl CHECKPOINT.RESTORE '{\"slot\":0}'`
  - `sucre-snort-ctl CHECKPOINT.CLEAR '{\"slot\":0}'`
- 统计
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"perf\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"domainRuleStats\"}'`
  - `sucre-snort-ctl METRICS.RESET '{\"name\":\"domainRuleStats\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"telemetry\"}'`
- Traffic Windows
  - `sucre-snort-ctl TRAFFIC_WINDOWS.CONFIG.GET`
  - `sucre-snort-ctl TRAFFIC_WINDOWS.GET '{\"durationSec\":900}'`
  - `sucre-snort-ctl TRAFFIC_WINDOWS.APPS '{\"durationSec\":900,\"limit\":20}'`
  - `sucre-snort-ctl TRAFFIC_WINDOWS.RESET`
- Packet diagnostics（运行 10 秒内）
  - `sucre-snort-ctl --follow DIAGNOSTICS.START '{\"channel\":\"packet\",\"app\":{\"uid\":10123}}'` → `type=diagnostic.packet` / `diagnostic.notice`
  - 停止方式：关闭该 `--follow` 连接，或在 CLI 支持同连接交互控制时在 owning diagnostics connection 上发送 `DIAGNOSTICS.STOP`；不要用新的普通 control 连接停止别的 diagnostics session。
