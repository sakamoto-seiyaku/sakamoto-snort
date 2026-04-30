# sucre-snort 接口规范

版本: v3.8
目标平台: Android 16, KernelSU
更新时间: 2026-04-30

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
- stream event：事件 frame 为 JSON object（无 `id/ok`），顶层必须含 `type`；见 `STREAM.*`。
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
  - `capabilities[]` 当前包含：`"control-vnext"`、`"nfqueue-datapath"`、`"apk-native-artifact"`。
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
  - device scope keys：`block.enabled` / `iprules.enabled` / `rdns.enabled` / `perfmetrics.enabled` / `block.mask.default` / `block.ifaceKindMask.default`
  - app scope keys：`tracked` / `block.mask` / `block.ifaceKindMask` / `domain.custom.enabled`
  - 所有开关值为 `0|1`（u32）；mask 为 `u8`（用 u32 传输）。
- `CONFIG.SET` | `{"scope":"device"|"app","app"?:selector,"set":{k:v...}}` | `ok` |
  - `set` key 集合与 `CONFIG.GET` 一致；不支持的 key → `INVALID_ARGUMENT`。

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

2.6 IP 规则（IPRules）
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

2.7 策略检查点（Checkpoint）
- `CHECKPOINT.LIST` | `{}` | `result={slots[],slotCount,maxSlotBytes}` |
  - 固定只暴露 3 个 slot：`0/1/2`；`slots[]` 必须按 `slot` 升序返回。
  - slot item：`{slot:u32,present:bool,formatVersion?:u32,sizeBytes?:u64,createdAt?:u64}`；后 3 项仅 `present=true` 时出现。
- `CHECKPOINT.SAVE` | `{"slot":0|1|2}` | `result={slot:{slot,present,formatVersion?,sizeBytes?,createdAt?},maxSlotBytes}` |
  - 原子替换所选 slot；bundle 超过 64 MiB 时返回 `CAPACITY_EXCEEDED`，旧 slot 内容保持可恢复。
- `CHECKPOINT.RESTORE` | `{"slot":0|1|2}` | `result={slot:{slot,present,formatVersion?,sizeBytes?,createdAt?},maxSlotBytes}` |
  - 空 slot 返回 `NOT_FOUND`。
  - restore 先完整解析/验证 bundle（版本、DomainPolicy rule 引用、DomainLists 元数据/内容、IPRULES preflight 等），失败时 live policy 不变。
  - 成功后开启新的 policy runtime epoch：清 conntrack、learned domain/IP/host 关联、IPRULES cache、旧 policy epoch 的 metrics、active stream state 与 telemetry session；客户端需要重新打开 stream/telemetry consumer。
- `CHECKPOINT.CLEAR` | `{"slot":0|1|2}` | `result={slot:{slot,present,formatVersion?,sizeBytes?,createdAt?},maxSlotBytes}` |
  - 幂等删除所选 slot；空 slot 也返回 `ok=true` 且 `slot.present=false`。
- 所有 `CHECKPOINT.*` 命令 strict JSON；未知 `args` key 返回 `SYNTAX_ERROR`，缺少 `slot` 返回 `MISSING_ARGUMENT`，非法 slot 返回 `INVALID_ARGUMENT`。
- bundle 仅包含 verdict-affecting policy：device/app verdict config、DomainRules、DomainPolicy、DomainLists 元数据与内容、IPRULES rules/nextRuleId；不包含 frontend metadata、历史、统计、stream replay、Flow Telemetry records、Geo/ASN、health/billing/diagnostic export。

2.8 观测（Metrics/Stream/Telemetry）
- `METRICS.GET` | `{"name":name,"app"?:selector}` | `result` |
  - `name=perf` → `result.perf{nfq_total_us,dns_decision_us}`；每项为 `{samples,min,avg,p50,p95,p99,max}`（单位 `us`）。
  - `name=reasons` → `result.reasons{IFACE_BLOCK,IP_LEAK_BLOCK,ALLOW_DEFAULT,IP_RULE_ALLOW,IP_RULE_BLOCK}`；每项为 `{packets,bytes}`。
  - `name=domainSources` → `result.sources{...}`（device 或 app 维度）；app 维度额外返回 `{uid,userId,app}`。
  - `name=traffic` → `result.traffic{dns,rxp,rxb,txp,txb}`；每项为 `{allow,block}`（device 或 app 维度）。
  - `name=conntrack` → `result.conntrack{totalEntries,creates,expiredRetires,overflowDrops,byFamily{ipv4,ipv6}}`。
  - `name=domainRuleStats` → `result.domainRuleStats{rules[]}`（device-only；禁止 `args.app`）：
    - `rules[]` item：`{ruleId:u32,allowHits:u64,blockHits:u64}`（按 `ruleId` 升序；baseline 全量覆盖）。
  - `name=telemetry` → `result.telemetry{enabled,consumerPresent,sessionId,slotBytes,slotCount,recordsWritten,recordsDropped,lastDropReason,lastError?}`（device-only；禁止 `args.app`）：
    - `enabled`: 当前是否存在 `level=flow` 的 telemetry session（boolean）。
    - `consumerPresent`: 当前是否存在 telemetry consumer session（boolean；`enabled=false` 时必为 false）。
    - `lastDropReason`: `"none"|"consumerAbsent"|"slotBusy"|"recordTooLarge"|"disabled"|"resourcePressure"`。
- `METRICS.RESET` | `{"name":name,"app"?:selector}` | `ok` |
  - 支持 reset：`perf` / `reasons` / `domainSources` / `traffic` / `domainRuleStats`。
  - `METRICS.RESET(name=conntrack)`：不支持，返回 `INVALID_ARGUMENT`（提示使用 `RESETALL`）。
- `TELEMETRY.OPEN` | `{"level":"off"|"flow","config"?:{...}}` | `result={actualLevel,sessionId,abiVersion,slotBytes,slotCount,ringDataBytes,maxPayloadBytes,writeTicketSnapshot}` |
  - `level=off` 等价于关闭 telemetry（同 `TELEMETRY.CLOSE`）；返回 `actualLevel="off"`。
  - `level=flow` 仅支持 Unix domain vNext 连接；成功时服务端会在 response 的 ancillary data 中通过 `SCM_RIGHTS` 传递 shared-memory fd（response JSON 中不包含 fd 字段）。
  - 在 TCP/adb-forward 连接上调用 `TELEMETRY.OPEN(level=flow)` 必失败：`INVALID_ARGUMENT` + `error.hint="use vNext Unix domain socket (fd passing required)"`。
  - `config`（可选覆盖，未知 key → `SYNTAX_ERROR`）：
    - ring: `slotBytes(u32)`, `ringDataBytes(u64)`
    - poll/emit: `pollIntervalMs(u32)`, `bytesThreshold(u64)`, `packetsThreshold(u64)`, `maxExportIntervalMs(u32)`
    - TTL: `blockTtlMs(u32)`, `pickupTtlMs(u32)`, `invalidTtlMs(u32)`
    - limits: `maxFlowEntries(u32)`, `maxEntriesPerUid(u32)`
  - records 通过 shared-memory ring 输出；二进制 ABI 见下方 “Flow Telemetry shared-memory ABI”。
- `TELEMETRY.CLOSE` | `{}` | `ok` |
  - idempotent；会作废旧 session（consumer 端需停止 ingest 并在需要时重新 OPEN）。

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

`recordType=1` FLOW payload v1（fixed size `102` bytes）:

| Offset | Field | Type | 说明 |
| --- | --- | --- | --- |
| 0 | `payloadVersion` | u8 | 固定为 `1` |
| 1 | `kind` | u8 | `1=Begin`, `2=Update`, `3=End` |
| 2 | `ctState` | u8 | `0=ANY`, `1=NEW`, `2=ESTABLISHED`, `3=INVALID` |
| 3 | `ctDir` | u8 | `0=ANY`, `1=ORIG`, `2=REPLY` |
| 4 | `reasonId` | u8 | `0=IFACE_BLOCK`, `1=IP_LEAK_BLOCK`, `2=ALLOW_DEFAULT`, `3=IP_RULE_ALLOW`, `4=IP_RULE_BLOCK` |
| 5 | `ifaceKindBit` | u8 | 见 §4 `ifaceKind` 位 |
| 6 | `flags` | u8 | bit0 `hasRuleId`, bit1 `isIpv6`, bit2 `pickedUpMidStream`（保留/未来） |
| 7 | `reserved0` | u8 | 保留 |
| 8 | `timestampNs` | u64 | monotonic timestamp |
| 16 | `flowInstanceId` | u64 | flow instance id |
| 24 | `recordSeq` | u64 | flow 内 record 序号 |
| 32 | `uid` | u32 | Android uid |
| 36 | `userId` | u32 | Android user id |
| 40 | `ifindex` | u32 | interface index |
| 44 | `proto` | u8 | IP protocol number（例如 TCP=6, UDP=17, ICMP=1, ICMPv6=58） |
| 45 | `reserved1` | u8 | 保留 |
| 46 | `srcPort` | u16 | TCP/UDP port；无 L4 port 时为 0 |
| 48 | `dstPort` | u16 | TCP/UDP port；无 L4 port 时为 0 |
| 50 | `srcAddr` | bytes[16] | IPv4 使用前 4 bytes；IPv6 使用 16 bytes |
| 66 | `dstAddr` | bytes[16] | IPv4 使用前 4 bytes；IPv6 使用 16 bytes |
| 82 | `totalPackets` | u64 | flow 累计 packets |
| 90 | `totalBytes` | u64 | flow 累计 bytes |
| 98 | `ruleId` | u32 | 仅当 `flags.hasRuleId` 时有效 |

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

payload 演进规则：每个 payload 自带 `payloadVersion`，新增字段只允许 append；旧 consumer 必须先验证自身需要的最小长度，再用 `payloadSize` 跳过未知尾部。
- `STREAM.START` | `{"type":"dns"|"pkt"|"activity","horizonSec"?:u32,"minSize"?:u32}` | `ok` |
  - `dns/pkt` 是 tracked Debug Stream surface：用于短时 per-event 取证，不是常态 records/history/timeline/Top-K API。
  - `dns/pkt` 支持 replay 参数（会被 clamp 到 caps）；replay 只读取 bounded in-process debug prebuffer，不查询 Flow Telemetry、Metrics 或持久化历史。
  - `activity` 禁止携带 `horizonSec/minSize`（否则 `SYNTAX_ERROR`），且不属于 Debug Stream explainability surface。
  - 进入 stream mode 后，除 `STREAM.START/STOP` 外的命令一律 `STATE_CONFLICT`。
  - 输出顺序：`STREAM.START` response → `notice.started` → replay/实时事件。
- `STREAM.STOP` | `{}` | `ok` |
  - ack barrier：服务端会先丢弃队列中尚未写出的事件/notice，再发送 STOP response。

vNext stream 事件（JSON object，无 `id/ok`）:
- `notice.started`：`{ "type":"notice", "notice":"started", "stream":"dns"|"pkt"|"activity", "horizonSec"?:u32, "minSize"?:u32 }`
- `notice.suppressed`：`{type:"notice",notice:"suppressed",stream,windowMs:u32,traffic:{dns|rxp|rxb|txp|txb:{allow,block}},hint:string}`
  - 仅说明 tracked gate 导致 debug event 未输出；不是 Metrics replacement。
- `notice.dropped`：`{type:"notice",notice:"dropped",stream,windowMs:u32,droppedEvents:u64}`
  - 仅说明 queued debug evidence 丢失；不是 Metrics replacement。
- `dns`：`{type:"dns",timestamp:string,uid:u32,userId:u32,app:string,domain:string,domMask:u32,appMask:u32,blocked:bool,policySource:string,useCustomList:bool,scope:"APP"|"DEVICE_WIDE"|"FALLBACK",getips:bool,ruleId?:u32,explain:object}`
  - 顶层字段是 compatibility summaries；`explain` 是权威 debug evidence。
  - `ruleId` 仅在 tracked app 且 `policySource` 来自规则分支且 decision 实际来自 rule（非名单）时出现。
  - `explain.version=1`，`explain.kind="dns-policy"`。
  - `explain.inputs={blockEnabled:bool,tracked:bool,domainCustomEnabled:bool,useCustomList:bool,domain:string,domMask:u32,appMask:u32}`。
  - `explain.final={blocked:bool,getips:bool,policySource:string,scope:"APP"|"DEVICE_WIDE"|"FALLBACK",ruleId?:u32}`。
  - `explain.stages[]` 固定顺序：
    `app.custom.allowList` → `app.custom.blockList` → `app.custom.allowRules` → `app.custom.blockRules` → `deviceWide.allow` → `deviceWide.block` → `maskFallback`。
  - 每个 DNS stage 至少包含 `{name,enabled,evaluated,matched,outcome,winner,truncated}`；跳过时含 `skipReason`。
  - `skipReason` 固定取值：`disabled` / `shortCircuited` / `noMatch` / `l4Unavailable` / `fragment` / `ctUnavailable`。
  - 规则 stage 可含 `ruleIds[]` 与 `ruleSnapshots[]`；rule snapshot 至少为 `{ruleId,type,pattern,scope,action}`。
  - 名单 stage 可含 `listEntrySnapshots[]`；list-entry snapshot 至少为 `{type,pattern,scope,action}`。
  - `maskFallback` stage 含 `maskFallback={domMask,appMask,effectiveMask,outcome}`，用于无需额外查询当前 mask 即可解释 fallback verdict。
- `pkt`：
  `{ "type":"pkt", "timestamp":string, "uid":u32, "userId":u32, "app":string, "direction":"in"|"out", "ipVersion":4|6, "protocol":"tcp"|"udp"|"icmp"|"other", "l4Status":"known-l4"|"other-terminal"|"fragment"|"invalid-or-unavailable-l4", "srcIp"?:string, "dstIp"?:string, "srcPort":u32, "dstPort":u32, "length":u32, "ifindex":u32, "ifaceKindBit":u32, "interface"?:string, "host"?:string, "domain"?:string, "accepted":bool, "reasonId":string, "ruleId"?:u32, "wouldRuleId"?:u32, "wouldDrop"?:bool, "explain":object }`
  - 顶层字段是 compatibility summaries；`explain` 是权威 debug evidence。
  - `l4Status` 恒存在；当 `l4Status!=known-l4` 时 `srcPort/dstPort=0`。
  - 顶层 `wouldDrop` 是 true-only optional：仅当 would-rule 命中 drop 时出现，consumer 不应期待显式 `false`。
  - `explain.version=1`，`explain.kind="packet-verdict"`。
  - `explain.inputs={blockEnabled:bool,iprulesEnabled:bool,direction:"in"|"out",ipVersion:4|6,protocol:string,l4Status:string,ifindex:u32,ifaceKindBit:u32,ifaceKind:string,conntrackEvaluated:bool,conntrack?:{state,direction}}`。
  - `explain.final={accepted:bool,reasonId:string,ruleId?:u32,wouldRuleId?:u32,wouldDrop?:bool}`。
  - `explain.final.wouldDrop` 同样为 true-only optional；缺省不表示 JSON boolean false 字段存在。
  - `explain.stages[]` 固定顺序：`ifaceBlock` → `iprules.enforce` → `domainIpLeak` → `iprules.would`。
  - 每个 packet stage 至少包含 `{name,enabled,evaluated,matched,outcome,winner,truncated}`；跳过时含 `skipReason`，取值同 DNS stage。
  - IPRULES stage 可含 `ruleIds[]` 与 `ruleSnapshots[]`；rule snapshot 至少为 `{ruleId,clientRuleId,matchKey,action,enforce,log,family,dir,iface,ifindex,proto,ct,src,dst,sport,dport,priority}`。
  - `ifaceBlock` stage 含 `ifaceBlock={appIfaceMask,packetIfaceKindBit,evaluatedIntersection,packetIfaceKind,outcome,shortCircuitReason?}`。
- `activity`：`{type:"activity",timestamp:string,blockEnabled:bool}`
  - `activity` 不输出 `explain`，不承载新 telemetry/history 语义。

Debug Stream explain candidate 限制:
- `maxExplainCandidatesPerStage=64`。
- Domain rule candidates 按 `ruleId` 升序；IPRULES candidates 按 effective evaluation order（`priority` 降序，`ruleId` 升序）。
- 超过上限时 stage 输出 `truncated=true`，可廉价得知时输出 `omittedCandidateCount`；winning rule snapshot 必须保留。
- `dns/pkt` Debug Stream 不新增 Flow Telemetry records、Metrics names、DEV query surface、persistent storage、Top-K、timeline/history 聚合、Geo/ASN 或 DNS-to-packet join。

语义锁定参考: 本文（§2.6/§2.7/§2.8 的枚举、字段口径与 telemetry ABI 即为锁定语义）。

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
- vNext stream caps：`maxHorizonSec=300`、`maxRingEvents=256`、`maxPendingEvents=256`。
- `activityNotificationIntervalMs=500`
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
- `STREAM.START` 后连接进入 stream mode：除 `STREAM.START/STOP` 外其他命令均返回 `STATE_CONFLICT`。

开关与数值约定：
- 设备/应用配置的布尔开关统一使用 `0|1`（u32），不是 JSON boolean（例如 `block.enabled`、`tracked`）。
- stream 事件中的 `blocked/accepted/...` 为 JSON boolean（见 §2.8）。

容量与限制：
- 单帧最大请求/响应 payload：16MB（也会通过 `HELLO` 返回）。
- `DOMAINLISTS.IMPORT` 附加限制：`domains` 数量 ≤ 1,000,000；domain 字符串总字节数 ≤ 16MB。
- `CHECKPOINT.*` slot bundle 上限：64 MiB/slot；slot ID 固定为 `0..2`。

多用户支持：
- 多数 app 维度命令通过 `args.app` 明确指定 userId 或 uid；服务端在 `result` 中返回 `{uid,userId,app}` 以便客户端校验。

---

## 6. 索引

通用: HELLO, QUIT, RESETALL
清单: APPS.LIST, IFACES.LIST
配置: CONFIG.GET, CONFIG.SET
域名: DOMAINRULES.GET/APPLY, DOMAINPOLICY.GET/APPLY, DOMAINLISTS.GET/APPLY/IMPORT, DEV.DOMAIN.QUERY(dev)
IP: IPRULES.PREFLIGHT/PRINT/APPLY
检查点: CHECKPOINT.LIST/SAVE/RESTORE/CLEAR
观测: METRICS.GET, METRICS.RESET, TELEMETRY.OPEN, TELEMETRY.CLOSE, STREAM.START, STREAM.STOP

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
  - 策略检查点目录: `/data/snort/save/policy_checkpoints/slot0.bundle` .. `slot2.bundle`
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
  - app: `sucre-snort-ctl CONFIG.SET '{\"scope\":\"app\",\"app\":{\"uid\":10123},\"set\":{\"tracked\":1}}'`
- 域名策略
  - `sucre-snort-ctl DOMAINRULES.GET`
  - `sucre-snort-ctl DOMAINPOLICY.GET '{\"scope\":\"device\"}'`
  - `sucre-snort-ctl DOMAINPOLICY.APPLY '{\"scope\":\"device\",\"policy\":{\"allow\":{\"domains\":[],\"ruleIds\":[]},\"block\":{\"domains\":[],\"ruleIds\":[]}}}'`
- 域名清单
  - `sucre-snort-ctl DOMAINLISTS.GET`
  - `sucre-snort-ctl DOMAINLISTS.APPLY '{\"upsert\":[{\"listId\":\"00000000-0000-0000-0000-000000000000\",\"listKind\":\"block\",\"mask\":1,\"enabled\":1,\"url\":\"\",\"name\":\"\",\"updatedAt\":\"\",\"etag\":\"\",\"outdated\":0,\"domainsCount\":0}]}'`
  - `sucre-snort-ctl DOMAINLISTS.IMPORT '{\"listId\":\"00000000-0000-0000-0000-000000000000\",\"listKind\":\"block\",\"mask\":1,\"clear\":1,\"domains\":[\"example.com\"]}'`
- IP 规则
  - `sucre-snort-ctl IPRULES.PREFLIGHT`
  - `sucre-snort-ctl IPRULES.PRINT '{\"app\":{\"uid\":10123}}'`
  - `sucre-snort-ctl IPRULES.APPLY @/tmp/iprules_apply.json` → `{uid,rules:[{clientRuleId,ruleId,matchKey}]}`（matchKey 为 mk2）
- 策略检查点
  - `sucre-snort-ctl CHECKPOINT.LIST`
  - `sucre-snort-ctl CHECKPOINT.SAVE '{\"slot\":0}'`
  - `sucre-snort-ctl CHECKPOINT.RESTORE '{\"slot\":0}'`
  - `sucre-snort-ctl CHECKPOINT.CLEAR '{\"slot\":0}'`
- 统计
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"perf\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"traffic\"}'`
  - `sucre-snort-ctl METRICS.RESET '{\"name\":\"traffic\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"domainRuleStats\"}'`
  - `sucre-snort-ctl METRICS.RESET '{\"name\":\"domainRuleStats\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"telemetry\"}'`
- 流（运行 10 秒内）
  - `sucre-snort-ctl --follow STREAM.START '{\"type\":\"dns\",\"horizonSec\":0,\"minSize\":0}'` → `notice.started` + `type=dns` 事件
  - `sucre-snort-ctl STREAM.STOP` → ack response
