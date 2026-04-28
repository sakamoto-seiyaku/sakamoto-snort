# sucre-snort 接口规范

版本: v3.7
目标平台: Android 16, KernelSU
更新时间: 2026-04-27

---

## 1. 连接与协议

- 控制通道（vNext）: Android control socket 名称 `sucre-snort-control-vnext`（Unix Domain, SOCK_STREAM；netstring + JSON）。
- 可选 TCP 控制端口（vNext）: 60607（当存在 `/data/snort/telnet` 文件时开启；默认仅本地 Unix domain）。
- （DEV）adb forward（推荐）: `adb forward tcp:60607 localabstract:sucre-snort-control-vnext`
- DNS 监听通道: Android control socket 名称 `sucre-snort-netd`（Unix Domain, SOCK_SEQPACKET；内部二进制协议，见 §3）。

报文约定（control-vnext 控制通道）:
- framing: netstring `<len>:<payload>,`；`payload` 为 UTF-8 JSON object。
- request envelope：`{"id":1,"cmd":"...","args":{}}`（`args` 必须是 object）
- response envelope：`{"id":1,"ok":true,"result":{...}}` / `{"id":1,"ok":false,"error":{...}}`
- strict reject：顶层/args 出现未知 key → `SYNTAX_ERROR`；未知 `cmd` → `UNSUPPORTED_COMMAND`。
- stream event：事件 frame 为 JSON object（无 `id/ok`），顶层必须含 `type`；见 `STREAM.*`。
- 备注：对外契约以本文为准；更早的协议/命令面设计材料已归档到 `docs/archived/DOMAIN_IP_FUSION/`（非权威）。

vNext app selector（`args.app`）约定:
- `{"uid":10123}` 或 `{"pkg":"com.example","userId":0}`（二选一；禁止混用）。
- resolve 不存在/歧义 → `SELECTOR_NOT_FOUND` / `SELECTOR_AMBIGUOUS` + `candidates[]`（按 `uid` 升序；not found 时为空数组）。

---

## 2. 命令

说明格式: 命令 | 参数 | 返回 | 备注

2.1 通用（Meta）
- `HELLO` | `{}` | `result={protocol,protocolVersion,framing,maxRequestBytes,maxResponseBytes}` |
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

2.7 观测（Metrics/Stream）
- `METRICS.GET` | `{"name":name,"app"?:selector}` | `result` |
  - `name=perf` → `result.perf{nfq_total_us,dns_decision_us}`；每项为 `{samples,min,avg,p50,p95,p99,max}`（单位 `us`）。
  - `name=reasons` → `result.reasons{IFACE_BLOCK,IP_LEAK_BLOCK,ALLOW_DEFAULT,IP_RULE_ALLOW,IP_RULE_BLOCK}`；每项为 `{packets,bytes}`。
  - `name=domainSources` → `result.sources{...}`（device 或 app 维度）；app 维度额外返回 `{uid,userId,app}`。
  - `name=traffic` → `result.traffic{dns,rxp,rxb,txp,txb}`；每项为 `{allow,block}`（device 或 app 维度）。
  - `name=conntrack` → `result.conntrack{totalEntries,creates,expiredRetires,overflowDrops,byFamily{ipv4,ipv6}}`。
  - `name=domainRuleStats` → `result.domainRuleStats{rules[]}`（device-only；禁止 `args.app`）：
    - `rules[]` item：`{ruleId:u32,allowHits:u64,blockHits:u64}`（按 `ruleId` 升序；baseline 全量覆盖）。
- `METRICS.RESET` | `{"name":name,"app"?:selector}` | `ok` |
  - 支持 reset：`perf` / `reasons` / `domainSources` / `traffic` / `domainRuleStats`。
  - `METRICS.RESET(name=conntrack)`：不支持，返回 `INVALID_ARGUMENT`（提示使用 `RESETALL`）。
- `STREAM.START` | `{"type":"dns"|"pkt"|"activity","horizonSec"?:u32,"minSize"?:u32}` | `ok` |
  - `dns/pkt` 支持 replay 参数（会被 clamp 到 caps）；`activity` 禁止携带 `horizonSec/minSize`（否则 `SYNTAX_ERROR`）。
  - 进入 stream mode 后，除 `STREAM.START/STOP` 外的命令一律 `STATE_CONFLICT`。
  - 输出顺序：`STREAM.START` response → `notice.started` → replay/实时事件。
- `STREAM.STOP` | `{}` | `ok` |
  - ack barrier：服务端会先丢弃队列中尚未写出的事件/notice，再发送 STOP response。

vNext stream 事件（JSON object，无 `id/ok`）:
- `notice.started`：`{ "type":"notice", "notice":"started", "stream":"dns"|"pkt"|"activity", "horizonSec"?:u32, "minSize"?:u32 }`
- `notice.suppressed`：`{type:"notice",notice:"suppressed",stream,windowMs:u32,traffic:{dns|rxp|rxb|txp|txb:{allow,block}},hint:string}`
- `notice.dropped`：`{type:"notice",notice:"dropped",stream,windowMs:u32,droppedEvents:u64}`
- `dns`：`{type:"dns",timestamp:string,uid:u32,userId:u32,app:string,domain:string,domMask:u32,appMask:u32,blocked:bool,policySource:string,useCustomList:bool,scope:"APP"|"DEVICE_WIDE"|"FALLBACK",getips:bool,ruleId?:u32}`
  - `ruleId` 仅在 tracked app 且 `policySource` 来自规则分支且 decision 实际来自 rule（非名单）时出现。
- `pkt`：
  `{ "type":"pkt", "timestamp":string, "uid":u32, "userId":u32, "app":string, "direction":"in"|"out", "ipVersion":4|6, "protocol":"tcp"|"udp"|"icmp"|"other", "l4Status":"known-l4"|"other-terminal"|"fragment"|"invalid-or-unavailable-l4", "srcIp"?:string, "dstIp"?:string, "srcPort":u32, "dstPort":u32, "length":u32, "ifindex":u32, "ifaceKindBit":u32, "interface"?:string, "host"?:string, "domain"?:string, "accepted":bool, "reasonId":string, "ruleId"?:u32, "wouldRuleId"?:u32, "wouldDrop"?:bool }`
  - `l4Status` 恒存在；当 `l4Status!=known-l4` 时 `srcPort/dstPort=0`。
- `activity`：`{type:"activity",timestamp:string,blockEnabled:bool}`

语义锁定参考: 本文（§2.6/§2.7 的枚举与字段口径即为锁定语义）。

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
- stream 事件中的 `blocked/accepted/...` 为 JSON boolean（见 §2.7）。

容量与限制：
- 单帧最大请求/响应 payload：16MB（也会通过 `HELLO` 返回）。
- `DOMAINLISTS.IMPORT` 附加限制：`domains` 数量 ≤ 1,000,000；domain 字符串总字节数 ≤ 16MB。

多用户支持：
- 多数 app 维度命令通过 `args.app` 明确指定 userId 或 uid；服务端在 `result` 中返回 `{uid,userId,app}` 以便客户端校验。

---

## 6. 索引

通用: HELLO, QUIT, RESETALL
清单: APPS.LIST, IFACES.LIST
配置: CONFIG.GET, CONFIG.SET
域名: DOMAINRULES.GET/APPLY, DOMAINPOLICY.GET/APPLY, DOMAINLISTS.GET/APPLY/IMPORT, DEV.DOMAIN.QUERY(dev)
IP: IPRULES.PREFLIGHT/PRINT/APPLY
观测: METRICS.GET, METRICS.RESET, STREAM.START, STREAM.STOP

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
- 统计
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"perf\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"traffic\"}'`
  - `sucre-snort-ctl METRICS.RESET '{\"name\":\"traffic\"}'`
  - `sucre-snort-ctl METRICS.GET '{\"name\":\"domainRuleStats\"}'`
  - `sucre-snort-ctl METRICS.RESET '{\"name\":\"domainRuleStats\"}'`
- 流（运行 10 秒内）
  - `sucre-snort-ctl --follow STREAM.START '{\"type\":\"dns\",\"horizonSec\":0,\"minSize\":0}'` → `notice.started` + `type=dns` 事件
  - `sucre-snort-ctl STREAM.STOP` → ack response
