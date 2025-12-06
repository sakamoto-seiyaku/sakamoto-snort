# sucre-snort 接口规范

版本: v3.3
目标平台: Android 16, KernelSU
更新时间: 2025-12-06

---

## 1. 连接与协议

- 控制通道: Android control socket 名称 `sucre-snort-control`（Unix Domain, SOCK_STREAM）。
- 可选 TCP 控制端口: 60606（当存在 `/data/snort/telnet` 文件时开启）。
- DNS 监听通道: Android control socket 名称 `sucre-snort-netd`（Unix Domain, SOCK_SEQPACKET）。

报文约定（控制通道）:
- 命令为 ASCII 文本，以空格分隔参数；请求报文以 NUL 结尾；响应在有内容时以 NUL 结尾（少数命令无任何响应）。
- 在命令名后加 `!` 开启美化输出（仅影响缩进与换行；内容不变）。
- 布尔参数为 `true`/`false`；纯数字串解析为整数；其余视为字符串。不要为字符串参数加引号（唯一例外：`PASSWORD`）。
- 成功无数据返回时回 `OK`；失败回 `NOK`；其余返回为 JSON 片段或原始数字/文本。

参数解析（严格按实现）：
- 令牌以空格分隔；仅纯数字串视为整数；`true|false`（小写）视为布尔；其他为字符串。
- 仅 `PASSWORD` 会去除首尾双引号后设置密码；其余命令不剥引号。
- 含空格名称的拼接：`BLOCKLIST.*.ADD/UPDATE` 将第 4 或第 9 个参数后所有 token 以空格拼接为 `<name>`；无需引号。
- 负数/带符号整数不被识别为整数。

多用户参数约定（`<uid|str>` 位置）:
- `<uid>`: 完整 Linux UID（含 userId 高位），例如 `10123`（user 0）或 `110123`（user 1）。
- `<str>`: 包名字符串，默认指向主用户（user 0）。
- `<str> USER <userId>`: 显式指定用户，适用于所有支持 `<uid|str>` 的命令。
- `<str> <userId>`: 仅限部分命令（见下文"支持简写的命令"）。

支持 `<str> <userId>` 简写的命令（在 `<uid|str>` 后不再接受其他整型参数）:
  `APP.UID`, `APP.NAME`, `APP<v>`, `APP.<TYPE><v>`, `<COLOR>.APP<v>`, `APP.RESET<v>`,
  `TRACK`, `UNTRACK`, `APP.CUSTOMLISTS`

仅支持 `<str> USER <userId>` 的命令（第二个整数参数有其他含义）:
  `BLOCKMASK`, `BLOCKIFACE`, `CUSTOMLIST.ON/OFF`, `BLACKLIST.*`, `WHITELIST.*`,
  `BLACKRULES.*`, `WHITERULES.*`

---

## 2. 命令

说明格式: 命令 | 参数 | 返回 | 备注

2.1 通用
- `HELLO` | - | `OK` |
- `HELP` | - | 文本 |
- `QUIT` | - | - | 关闭当前连接
- `PASSWORD [<str>]` | 查询/设置 | 当前密码或 `OK` | 设置时需双引号
- `PASSSTATE [<int>]` | 查询/设置 | 当前状态或 `OK` | `uint8` 状态值
- `RESETALL` | - | `OK` | 清空设置、统计、域名、规则、列表并持久化

2.2 应用
- `APP.UID [<uid|str>]` | 过滤可选 | App 数组 | 无参数列出所有用户的 App（按 UID 升序）；`USER <userId>` 仅该用户；`<uid>` 精确匹配；`<str>` 子串匹配（支持 `<str> <userId>` 简写）
- `APP.NAME [<uid|str>]` | 同上 | App 数组 | 按名称排序；其余同 `APP.UID`
- `APP.CUSTOMLISTS <uid|str>` | 必填 | 对象 | `{"blacklist":[...],"whitelist":[...]}`；支持 `<str> <userId>` 简写

App 对象字段:
- `name:string`, `uid:int`(完整 Linux UID), `userId:int`, `appId:int`, `blocked:int`(blockMask), `blockIface:int`, `tracked:0|1`, `useCustomList:0|1`
- 可选 `allNames:string[]`（共享 UID 多包时存在）
- UID 公式: `uid = userId * 100000 + appId`（user 0 下 `uid` 与 `appId` 数值相同）

2.3 拦截与网络
- `BLOCK [<0|1>]` | 查询/设置 | 当前值或 `OK` | 全局开关
- `BLOCKMASK <uid|str> [<mask>]` | 查询/设置 | 当前/`OK` | 应用拦截掩码；仅支持 `<str> USER <userId>`（不支持简写）
- `BLOCKMASKDEF [<mask>]` | 查询/设置 | 当前/`OK` | 新装应用默认拦截掩码
- `BLOCKIFACE <uid|str> [<mask>]` | 查询/设置 | 当前/`OK` | 接口拦截掩码；仅支持 `<str> USER <userId>`（不支持简写）
- `BLOCKIFACEDEF [<mask>]` | 查询/设置 | 当前/`OK` | 新装应用默认接口掩码
- `BLOCKIPLEAKS [<0|1>]` | 查询/设置 | 当前/`OK` | IP 泄漏拦截
- `GETBLACKIPS [<0|1>]` | 查询/设置 | 当前/`OK` | 对被拦截域是否仍获取 IP
- `MAXAGEIP [<int>]` | 查询/设置 | 当前/`OK` | IP 最大存活秒数

掩码定义:
- blockMask 位: `1`(standard), `8`(reinforced), `128`(custom)。默认: 系统 129；用户继承全局。
- blockIface 位: `1`(WiFi), `2`(Mobile Data), `4`(VPN)。

2.4 追踪与反解
- `TRACK <uid|str>` | - | `OK` | 置应用 tracked=1；支持 `<str> <userId>` 简写
- `UNTRACK <uid|str>` | - | `OK` | 置应用 tracked=0；支持 `<str> <userId>` 简写
- `RDNS.SET` | - | `OK` | 开启反向 DNS
- `RDNS.UNSET` | - | `OK` | 关闭反向 DNS

2.5 统计
后缀 `<v>`: `.0`~`.6`=DAY0..DAY6, `.W`=WEEK(7 天和), `.A`=ALL。

- 总览
  - `ALL<v>` -> 对象: 每个 type 一项，键为 `dns|rxp|rxb|txp|txb`，值为颜色对象
    - 颜色对象: `{"total":[all,blocked,auth],"black":[...],"white":[...],"grey":[...]}`
  - `<TYPE><v>` -> 数值: 单类型总数
- 应用
  - `APP<v> [<uid|str>]` -> App 数组，含 `stats`；无参数为所有用户的设备级统计；`USER <userId>` 仅该用户；支持 `<str> <userId>` 简写
  - `APP.<TYPE><v> [<uid|str>]` -> App 数组，`stats` 仅该 type；同上
  - `APP.RESET<v> <uid|str|ALL>` -> `OK`；`ALL` 重置所有用户；`ALL USER <userId>` 仅重置该用户；支持 `<str> <userId>` 简写
- 域名
  - `DOMAINS<v>` -> 对象: `{ "blocked":int, "stdLeaked":int, "rfcLeaked":int }`
  - `<BLACK|WHITE|GREY><v> [<str>]` -> Domain 数组
  - `<BLACK|WHITE|GREY>.APP<v> [<uid|str>]` -> Domain 数组（按应用）；支持 `USER <userId>` 和 `<str> <userId>` 简写
  - 上述命令可追加 `.DNS|.RXP|.RXB|.TXP|.TXB` 仅返回该类型

Domain 对象字段:
- `domain:string`, `blockMask:int`, `ipv4:string[]`, `ipv6:string[]`, `stats`: 与视图/类型一致的数组或对象

2.6 流式推送
- `DNSSTREAM.START [<horizon> [<minSize>]]` | 开始并回放窗口内历史 | 返回回放事件流（无 `OK`）
- `DNSSTREAM.STOP` | 停止 | `OK`
- `PKTSTREAM.START [<horizon> [<minSize>]]` | 开始并回放 | 返回回放事件流（无 `OK`）
- `PKTSTREAM.STOP` | 停止 | 无响应（不发送任何字节）
- `ACTIVITYSTREAM.START` | 开始 | 返回事件流（无 `OK`）
- `ACTIVITYSTREAM.STOP` | 停止 | 无响应（不发送任何字节）
- `TOPACTIVITY <uid>` | 触发一次前台活动推送 | 无响应；仅接受完整 UID，不支持包名

事件格式:
- DNS: `{ "app":string, "uid":int, "userId":int, "domain":string, "domMask":int, "appMask":int, "blocked":0|1, "timestamp":string }`
- Packet(IPv4/6): `{ "app":string, "uid":int, "userId":int, "direction":"in|out", "length":int, "interface":string, "protocol":"tcp|udp|icmp|n/a", "timestamp":string, "ipv4|ipv6":string, "host":string|"n/a", "srcPort":int, "dstPort":int, "accepted":0|1 }`
- Activity: `{ "blockEnabled":0|1, "uid":int, "userId":int, "app":{App 含 stats 通知视图} }`

流行为：
- `START` 先回放"时间窗口内或至少 minSize 条"，随后推送实时事件（每连接独立 pretty 偏好）。
- 保留上限：DNS 24h；包 2h；超限逐出旧事件。
- 流命令保持设备级视图，不支持 `USER <userId>` 子句；用户级过滤由客户端根据事件中的 `userId` 字段自行实现。

2.7 自定义黑白名单
- `CUSTOMLIST.ON <uid|str>` | - | `OK` | 该应用启用自定义列表；仅支持 `<str> USER <userId>`
- `CUSTOMLIST.OFF <uid|str>` | - | `OK` | 该应用停用自定义列表；仅支持 `<str> USER <userId>`
- `BLACKLIST.ADD [<uid|str>] <domain>` | - | `OK` | 若含应用则为应用级（仅支持 `<str> USER <userId>`）；否则全局
- `WHITELIST.ADD [<uid|str>] <domain>` | - | `OK` | 同上
- `BLACKLIST.REMOVE [<uid|str>] <domain>` | - | `OK` | 仅支持 `<str> USER <userId>`
- `WHITELIST.REMOVE [<uid|str>] <domain>` | - | `OK` | 同上
- `BLACKLIST.PRINT [<uid|str>]` | - | 字符串数组 | 仅支持 `<str> USER <userId>`
- `WHITELIST.PRINT [<uid|str>]` | - | 字符串数组 | 同上

规则: 添加到黑名单将从白名单移除（反之亦然）。全局 `BLACKLIST/WHITELIST` 命令可添加任意域名；应用级（带 `<uid|str>`）命令要求该域名已出现过。

2.8 规则管理
- `RULES.ADD <type:int> <pattern:str>` | 返回：规则 ID（字符串）
- `RULES.REMOVE <id:int>` | `OK`
- `RULES.UPDATE <id:int> <type:int> <pattern:str>` | `OK`（等价 `RULES.UPDATElist`）
- `RULES.PRINT` | 规则数组：`[{"id":int,"type":0|1|2,"rule":string,"status":"none|black|white","blacklist":[app...],"whitelist":[app...]}]`
- `BLACKRULES.ADD <id> | <uid|str> <id>` | `OK` | 全局或应用级启用规则；仅支持 `<str> USER <userId>`
- `WHITERULES.ADD <id> | <uid|str> <id>` | `OK` | 同上
- `BLACKRULES.REMOVE <id> | <uid|str> <id>` | `OK` | 仅支持 `<str> USER <userId>`
- `WHITERULES.REMOVE <id> | <uid|str> <id>` | `OK` | 同上
- `BLACKRULES.PRINT [<uid|str>]` | ID 数组或应用规则 ID 数组 | 仅支持 `<str> USER <userId>`
- `WHITERULES.PRINT [<uid|str>]` | 同上

规则类型: `0`=DOMAIN，`1`=WILDCARD（`*`→`.*`, `?`→`.` 并转义），`2`=REGEX。

返回约定：
- `RULES.ADD` 返回规则 ID（字符串形式）。
- `BLACKRULES.PRINT` / `WHITERULES.PRINT` 返回 ID 数组；带 `<uid|str>` 则返回该应用的 ID 数组。

2.9 拦截列表（第三方域名清单）
- `BLOCKLIST.BLACK.ADD <id> <url> <mask> <name...>` | `OK|NOK`
- `BLOCKLIST.WHITE.ADD <id> <url> <mask> <name...>` | `OK|NOK`
- `BLOCKLIST.BLACK.UPDATE <id> <url> <mask> <count> <time> <etag> <enabled> <outdated> <name...>` | `OK|NOK`
- `BLOCKLIST.WHITE.UPDATE <id> ...` | `OK|NOK`
- `BLOCKLIST.BLACK.REMOVE <id>` | `OK`
- `BLOCKLIST.WHITE.REMOVE <id>` | `OK`
- `BLOCKLIST.BLACK.ENABLE <id>` | `OK|NOK`
- `BLOCKLIST.WHITE.ENABLE <id>` | `OK|NOK`
- `BLOCKLIST.BLACK.DISABLE <id>` | `OK|NOK`
- `BLOCKLIST.WHITE.DISABLE <id>` | `OK|NOK`
- `BLOCKLIST.BLACK.OUTDATE <id>` | `OK|NOK`
- `BLOCKLIST.WHITE.OUTDATE <id>` | `OK|NOK`
- `BLOCKLIST.PRINT` | 对象: `{ "blockingLists":[{id,name,url,type:"BLACK|WHITE",blockMask:int,updatedAt:"YYYY-MM-DD_HH:MM:SS",outdated:0|1,etag:string,enabled:0|1,domainsCount:int}] }`
- `BLOCKLIST.SAVE` | `OK`
- `BLOCKLIST.CLEAR` | `OK`（逐个移除并保存）

注意:
- `<id>` 为 GUID 样式仅含十六进制与 `-`；`<time>` 必须为 `YYYY-MM-DD_HH:MM:SS`。
- `PRINT` 返回对象而非数组（键名 `blockingLists`）。

2.10 批量域名（按列表）
- `DOMAIN.BLACK.ADD.MANY <id> <mask:int> <clear:bool> <domains:str>` -> 返回新增数量
- `DOMAIN.WHITE.ADD.MANY <id> <mask:int> <clear:bool> <domains:str>` -> 同上
- `DOMAIN.BLACK.COUNT` -> 数量
- `DOMAIN.WHITE.COUNT` -> 数量
- `DOMAIN.BLACK.PRINT <id>` -> 文本: 每行 `domain<space>mask`
- `DOMAIN.WHITE.PRINT <id>` -> 同上

域名集合格式: 以 `;` 分隔（例如 `a.com;b.net;c.org`）。

2.11 主机
- `HOSTS [<str>]` -> Host 数组
- `HOSTS.NAME <str>` -> Host 数组

Host 对象字段:
- `name:string`, 可选 `domain:string`, 可选 `color:"black|white|grey"`, `ipv4:[string]`（注意：IPv4 元素为未加引号的裸字符串），`ipv6:[string]`

特例：
- `BLOCKMASK <uid|str>` / `BLOCKIFACE <uid|str>` 查询时，如未匹配应用，无响应（不发送任何字节）。
- `APP.CUSTOMLISTS <uid|str>` 查询时，如未匹配应用，无响应（不发送任何字节）。

---

## 3. DNS Listener（二进制协议）

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

- `controlCmdLen=20000`；`controlClients=1000`；`controlPort=60606`
- DNS 流: `max=86400`，`default=600`，`minSize=500`
- 包流: `max=7200`，`default=600`，`minSize=100`
- `activityNotificationIntervalMs=500`
- blockMask 位: `1|8|128`；blockIface 位: `1|2|4`
 - 颜色映射：域名若命中 `standardListBit` → `BLACK`；命中 `reinforcedListBit` → `WHITE`。

---

## 5. 参数与返回细节

- 除 `PASSWORD` 外不支持通用引号。除 `BLOCKLIST.*.ADD/UPDATE` 的 `<name>` 通过“余下 token 拼接”可包含空格外，其他字符串参数不应包含空格。
- 批量域名 `<domains>` 应传裸字符串（以 `;` 分隔，如 `a.com;b.net`），不要加引号。
- `RULES.ADD` 返回规则 ID 为字符串（例如 `"42"`）。
- `BLOCK`/`BLOCKIPLEAKS`/`GETBLACKIPS`/`MAXAGEIP` 等查询返回原始数字；设置成功返回 `OK`。
- `DOMAIN.*.PRINT` 返回纯文本（每行 `domain mask`），非 JSON。
- `HOSTS` 返回对象数组；其中 IPv4 列表元素为未加引号的字符串（与 IPv6 不一致，保持实现现状）。

错误与返回码：
- `OK`：状态变更成功（如 BLOCK=、PASSSTATE=、*_DEF=、RULES.UPDATE=、BLOCKLIST.*.UPDATE=）。
- `NOK`：参数数量错误、无效 ID、时间解析失败、列表不存在等。
- 查询：返回原始数字或 JSON；流 `START` 系列直接输出事件；部分 `STOP`/触发类命令为空响应（见上）。
- 少量查询类命令在未命中对象时无响应（如 `BLOCKMASK/BLOCKIFACE/APP.CUSTOMLISTS` 的查询）。

容量与限制：
- 最大命令长度 `< 20000` 字节（达到上限会被拒绝并断开）。
- 最大客户端连接数 1000；多连接并发。

版本与兼容：
- 数据保存版本 `savedVersion=7`；本规范 v3.3 对应当前实现。
- 兼容别名：`RULES.UPDATElist` ≡ `RULES.UPDATE`。

安全与暴露面：
- TCP 控制端口仅在存在 `/data/snort/telnet` 时开启；默认仅本地 Unix domain。

最小示例集：
- 统计：`ALL.A` → `{ "dns":{...}, ... }`；`APP.DNS.0 <uid>` → `[ {"name":...,"stats":{...}} ]`
- 流：`DNSSTREAM.START 60 1` → 连续事件；`DNSSTREAM.STOP` → `OK`
- 列表：`BLOCKLIST.BLACK.ADD <id> <url> 1 Ads List` → `OK`；`BLOCKLIST.PRINT` → `{ "blockingLists":[...] }`
- 批量：`DOMAIN.BLACK.ADD.MANY <id> 1 true a.com;b.net` → `2`
- 主机：`HOSTS namepart` → `[ {"name":...,"ipv4":[...],"ipv6":[...]} ]`

多用户支持：
- UID 公式: `完整 Linux UID = userId * 100000 + appId`（user 0 下 `uid` 与 `appId` 数值相同，向后兼容）。
- 支持 `USER <userId>` 子句的命令（App 级）:
  `APP.UID`, `APP.NAME`, `APP<v>`, `APP.<TYPE><v>`, `<COLOR>.APP<v>`, `APP.RESET<v>`,
  `BLOCKMASK`, `BLOCKIFACE`, `TRACK`, `UNTRACK`, `APP.CUSTOMLISTS`,
  `CUSTOMLIST.ON/OFF`, `BLACKLIST.*`, `WHITELIST.*`, `BLACKRULES.*`, `WHITERULES.*`
- 不支持 `USER` 子句的命令（设备级/全局）:
  `RESETALL`, `DNSSTREAM.*`, `PKTSTREAM.*`, `ACTIVITYSTREAM.*`,
  `TOPACTIVITY`（仅接受 `<uid>`，不接受 `<str>`）,
  `ALL<v>`, `<TYPE><v>`, `DOMAINS<v>`, `<COLOR><v>`,
  `BLOCKLIST.*`, `RULES.*`, `DOMAIN.*`, `HOSTS.*`

---

## 6. 索引

通用: HELLO, HELP, QUIT, PASSWORD, PASSSTATE, RESETALL
应用: APP.UID, APP.NAME, APP.CUSTOMLISTS
拦截: BLOCK, BLOCKMASK, BLOCKMASKDEF, BLOCKIFACE, BLOCKIFACEDEF, BLOCKIPLEAKS, GETBLACKIPS, MAXAGEIP
统计: ALL<v>, <TYPE><v>, APP<v>, APP.<TYPE><v>, APP.RESET<v>, DOMAINS<v>, <COLOR><v>, <COLOR>.APP<v>
流: DNSSTREAM.START/STOP, PKTSTREAM.START/STOP, ACTIVITYSTREAM.START/STOP, TOPACTIVITY, RDNS.SET/UNSET
黑白名单: CUSTOMLIST.ON/OFF, BLACKLIST.ADD/REMOVE/PRINT, WHITELIST.ADD/REMOVE/PRINT
规则: RULES.ADD/REMOVE/UPDATE(PRINT), BLACKRULES.* , WHITERULES.*
拦截列表: BLOCKLIST.*（ADD/UPDATE/REMOVE/ENABLE/DISABLE/OUTDATE/PRINT/SAVE/CLEAR）
域名列表: DOMAIN.*（ADD.MANY/COUNT/PRINT）
主机: HOSTS, HOSTS.NAME

---

## 7. 文件路径（只列稳定项）

- 设置: `/data/snort/settings`
- 保存目录: `/data/snort/save/`
  - 应用（系统 UID，user 0）: `/data/snort/save/system/<appId>`
  - 应用（包名，user 0）: `/data/snort/save/packages/<package>`
  - 应用（系统 UID，非 0 用户）: `/data/snort/save/user<userId>/system/<appId>`
  - 应用（包名，非 0 用户）: `/data/snort/save/user<userId>/packages/<package>`
  - 域名统计: `/data/snort/save/stats_domains`
  - DNS 流: `/data/snort/save/dnsstream`
  - 规则: `/data/snort/save/rules`
  - 全局统计: `/data/snort/save/stats_total`
  - 拦截列表: `/data/snort/save/blocking_lists`
  - 域名列表目录: `/data/snort/save/domains_lists/`
- 包清单: `/data/system/packages.list`

---

## 8. 接口快速校验清单（代表性用例）

- 连接/基础
  - `HELLO` → `OK`
  - `HELP` → 多行文本
  - `QUIT` → 连接关闭
- 密码/状态
  - `PASSWORD "p"` → `OK`；`PASSWORD` → `"p"`
  - `PASSSTATE 1` → `OK`；`PASSSTATE` → `0|1|...`
- 全局开关/参数
  - `BLOCK` → `0|1`；`BLOCK 0` → `OK`
  - `GETBLACKIPS` → `0|1`；`GETBLACKIPS 1` → `OK`
  - `MAXAGEIP` → 整数秒；`MAXAGEIP 7200` → `OK`
- 应用/掩码
  - `APP.UID 0` 或 `APP.NAME sys` → `[ {"name", "uid", ...} ]`
  - `BLOCKMASKDEF` → 整数；`BLOCKMASKDEF 129` → `OK`
  - `BLOCKMASK <uid>` → 整数；`BLOCKMASK <uid> 129` → `OK`
  - `BLOCKIFACEDEF` → 整数；`BLOCKIFACEDEF 0` → `OK`
  - `BLOCKIFACE <uid>` → 整数；`BLOCKIFACE <uid> 3` → `OK`
- 统计
  - `ALL.A` → 对象，含键 `dns|rxp|rxb|txp|txb`；每键为 `{total|black|white|grey:[int,int,int]}`
  - `DNS.W` → 整数
  - `APP.DNS.0 <uid>` → `[ {"name", "uid", "stats": {"dns": { ... }} } ]`
  - `APP.RESET.A ALL` → `OK`
- 域名
  - `DOMAINS.0` → `{ "blocked":int, "stdLeaked":int, "rfcLeaked":int }`
  - `BLACK.A` → `[ {"domain","blockMask","ipv4":[...],"ipv6":[...],"stats":...} ]`
  - `WHITE.APP.DNS.A <uid>` → `[]` 或域名对象数组
- 流（运行 10 秒内）
  - `DNSSTREAM.START 10 1` → 多条 `{ "app","domain","blocked",... }`；`DNSSTREAM.STOP` → `OK`
  - `PKTSTREAM.START 10 1` → 多条 `{ "app","direction","length","interface","protocol","timestamp","ipv4|ipv6","host","srcPort","dstPort","accepted" }`；`PKTSTREAM.STOP` → 无响应
  - `ACTIVITYSTREAM.START` → `{ "blockEnabled", "app":{...} }`；`ACTIVITYSTREAM.STOP` → 无响应
  - `TOPACTIVITY <uid>` → 无响应；后续 ACTIVITY 事件包含该 app
- 自定义黑白名单
  - `BLACKLIST.ADD example.com` → `OK`；`BLACKLIST.PRINT` → `["example.com", ...]`
  - `WHITELIST.ADD <uid> allow.com` → `OK`；`WHITELIST.PRINT <uid>` → `["allow.com", ...]`
- 规则
  - `RULES.ADD 1 *.ads.*` → `"<id>"`（字符串）
  - `BLACKRULES.ADD <id>` → `OK`；`RULES.PRINT` → `[ {"id":<id>,"type":1,"rule":"*.ads.*","status":"black",...} ]`
  - `BLACKRULES.ADD <uid> <id>` → `OK`；`BLACKRULES.PRINT <uid>` → `[ <id>, ... ]`
  - `RULES.UPDATE <id> 1 *.ads2.*` → `OK`；`RULES.REMOVE <id>` → `OK`
- 拦截列表（第三方清单）
  - `BLOCKLIST.BLACK.ADD <id> <url> 1 Ads List` → `OK`
  - `BLOCKLIST.BLACK.UPDATE <id> <url> 1 100 2025-01-01_00:00:00 etag1 true false Ads List v2` → `OK`
  - `BLOCKLIST.PRINT` → `{ "blockingLists":[ {"id","name","url","type","blockMask","updatedAt","outdated","etag","enabled","domainsCount"} ] }`
  - `BLOCKLIST.BLACK.ENABLE <id>` → `OK`；`BLOCKLIST.BLACK.DISABLE <id>` → `OK`
  - `BLOCKLIST.BLACK.OUTDATE <id>` → `OK`；`BLOCKLIST.BLACK.REMOVE <id>` → `OK`
  - `BLOCKLIST.SAVE` → `OK`；`BLOCKLIST.CLEAR` → `OK`
- 批量域名
  - `DOMAIN.BLACK.ADD.MANY <id> 1 true a.com;b.net` → `2`
  - `DOMAIN.BLACK.COUNT` → 整数；`DOMAIN.BLACK.PRINT <id>` → 纯文本多行（`domain<space>mask`）
- 主机
  - `HOSTS` 或 `HOSTS namepart` → `[ {"name", "domain"?, "color"?, "ipv4":[未加引号的 IP...], "ipv6":["..."]} ]`
- 多用户
  - `APP.UID` → 包含所有用户的 App 数组（`uid`/`userId`/`appId` 字段区分）
  - `APP.UID USER 10` → 仅 user 10 的 App 数组
  - `APP.NAME com.example USER 1` → user 1 下名称匹配的 App
  - `APP.NAME com.example 1` → 同上（简写形式）
  - `BLOCKMASK com.example USER 1` → user 1 下该包的掩码
  - `BLOCKMASK com.example USER 1 129` → 设置 user 1 下该包的掩码
  - `TRACK com.example USER 1` → 追踪 user 1 下的该包
  - `APP.RESET.A ALL` → 重置所有用户统计
  - `APP.RESET.A ALL USER 10` → 仅重置 user 10 的统计
  - `DNSSTREAM.START 60 1` → 事件含 `uid`/`userId` 字段，客户端按需过滤
