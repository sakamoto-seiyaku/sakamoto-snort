# Portmaster：DNS CNAME 过滤参考

研究日期：2026-10-08。用户要求参考 Safing Portmaster 的 CNAME 过滤。
以下源码核查记录官方事实与静态调用链发现；用户随后确认的功能方向另记文末，不继续关联使用范围讨论。
固定源码为 `13a86a43cc6cee592395fcddc8387178f290f144`。
本日复核官方主干 HEAD 为 `882d900dadb6df91150cf87f0a12706d29172586`（2026-10-06 提交）；
下面涉及的九个源码文件与固定快照逐字节一致。[当前源码][S11]

## 核心结论

Portmaster 配置上默认开启域名别名过滤，支持按应用覆盖；实现提供原域名与 CNAME 的匹配机制。
解析后检查先执行显式 endpoint 规则，再在没有匹配时检查订阅过滤列表。
因此不能将其概括为“任一 CNAME 命中阻断，就无条件阻断整个查询”。[配置][S1]、[解析后判断][S2]

但当前标准 nameserver 调用链存在两个静态缺口：CNAME 在检查后才赋值，
过滤列表数据在解析后被清空却没有重新加载。
这份源码不能证明普通新查询在回送答案前已按其真实 CNAME 完成阻断。[nameserver][S3]、[列表数据][S4]

## 默认设置与检查位置

配置项为 `filter/includeCNAMEs`，界面名为 Block Domain Aliases，默认值 `true`，
允许按应用设置。它不是替换查询名：`Entity.Domain` 仍是原域名，CNAME 保存在独立列表。[配置][S1]、[Entity][S4]

nameserver 先对查询执行 `FilterConnection`，允许后调用 resolver；取得上游或缓存答案后，
再次调用 `FilterResolvedDNS`，随后按 verdict 决定回送内容。[nameserver][S3]
这提供了查询前与取得答案后的两个判断位置；缓存复用不是复用其他查询的政策决定。

`FilterResolvedDNS` 在地址答案检查未阻断时，对非 system resolver 请求调用 `mayBlockCNAMEs`。
后者仅在开关开启时重置列表状态、开启 CNAME 匹配，再调用 endpoint／过滤列表匹配器。[解析后判断][S2]
这说明代码的过滤意图和入口位置，不等于这时已取得可供匹配的 CNAME 数据。

## 匹配规则：显式规则优先，保留原有顺序

`mayBlockCNAMEs` 对 `MatchEndpoint` 的结果分别处理：

| endpoint 结果 | 该 CNAME 检查分支的动作 |
| --- | --- |
| Denied | 设为 Block，并记录 CNAME 开关作为原因配置项 |
| NoMatch | 再调用 `MatchFilterLists`；其 Denied 才设为 Block |
| Permitted 等其他结果 | 不进入过滤列表检查，不在该分支新增阻断 |

所以显式允许原域名能使该分支跳过别名过滤列表；这不表示它能越过更早的地址或其他政策阻断。[解析后判断][S2]

域名 endpoint 先匹配 `Entity.Domain`；该条规则匹配原域名时直接返回。
原域名没有匹配且 CNAME 检查开启，才逐个匹配别名；**别名匹配只返回 Denied，别名 Allow 不返回允许决定**。[域名匹配][S5]
endpoint 列表按顺序取第一条非 NoMatch 的结果，profile 层也保留其匹配顺序。[规则顺序][S6]、[profile 匹配][S7]

以下例子假设匹配器已经持有 `shop.example → track.example` 的 CNAME，且无其他更早决定：

| 同一 endpoint 列表中的顺序 | 匹配器结果 |
| --- | --- |
| 先允许 `shop.example`，后拒绝 `track.example` | 原域名的允许先返回 |
| 先拒绝 `track.example`，后允许 `shop.example` | 第一条通过别名返回拒绝 |
| 仅允许 `track.example` | 不能仅凭别名得到允许；继续后续规则／判断 |

启用 CNAME 列表查询时，`getDomainLists` 将原域名与 CNAME 都纳入名单查询；
是否展开子域还受独立设置控制。它不把 CNAME 当作另一条新的用户 DNS 查询。[列表加载][S4]

## 实际调用链的两个缺口

**CNAME 数据到达过晚。** 标准本机查询创建全新的 DNS Connection，传入 `cnames=nil`；
构造器原样写入 `Entity.CNAME`。返回答案后的 `FilterResolvedDNS` 没有从 `rrCache` 提取别名。[nameserver][S3]、[构造器][S8]、[解析后判断][S2]
真正从 Answer／Extra 收集并串起别名、写入 `Entity.CNAME` 的是 `UpdateIPsAndCNAMEs`；
它在 nameserver 的 deferred、允许成功分支才执行，晚于解析后过滤和正常回复调用。[CNAME 赋值][S9]、[nameserver][S3]
因此，标准新查询到达 `mayBlockCNAMEs` 时别名仍为空；仅发现函数名称和开关不足以证明回答前覆盖。

**过滤列表没有重新加载。** `mayBlockCNAMEs` 调用 `ResetLists`，后者把 `ListOccurences` 清空。
随后 `MatchFilterLists` 调整开关并调用 `Entity.MatchLists`，但没有调用 `LoadLists`；
`MatchLists` 只遍历已经加载的 `ListOccurences`，不自行读取名单。[解析后判断][S2]、[profile 匹配][S7]、[列表数据][S4]
普通域名 endpoint 匹配也不会补这次加载，因此该分支不能据静态链路认定完成订阅名单的别名阻断。
主连接决策入口会先 `LoadLists`；这是另一条有完整预加载步骤的路径，不能填补上述解析后清空造成的缺口。[主决策][S10]

这些是固定及当前源码的静态发现；本轮没有安装或运行 Portmaster，未把它们扩大为所有版本／所有路径的运行结论。

## 特例与参考边界

system resolver 的解析后路径明确跳过 `mayBlockCNAMEs`。
主 DNS 决策对它也使用特殊 endpoint 检查，只查本地 resolver profile，不套用完整全局 endpoint 链。
因此不能承诺系统代查时在查询阶段按原调用 App 的别名政策阻断。[解析后判断][S2]、[系统请求特例][S10]

环境 resolver 答案，以及满足联网引导条件而获准的 connectivity 域名，直接提前返回。
connectivity 特准要求处于 Portal 或更受限状态、外发且应用未禁止 Internet；不是所有联网检测名永久免检。[解析后判断][S2]、[connectivity][S10]
Portmaster 自身流量在主决策有特准，地址答案过滤也跳过 own PID；
但后一个判断仅在 `filterDNSResponse` 中，不能单独解释成整个 CNAME 函数的 own PID 免检。[主决策][S10]、[解析后判断][S2]

可参考的是“取得答案后补充别名事实，再按现有规则顺序判断”的结构与按应用开关。
照搬前必须核实事实在判断前已就绪、列表已加载，并保留规则优先级；本次没有选择 Sakamoto 的 CNAME 拦截方式或修改现有规则语义。

## 用户随后确认功能方向

用户回答“参考其功能”，接受首版将实际返回、与原查询相连的CNAME链纳入DNS过滤，
仍由现有统一整条规则与Rank决定允许／拒绝；不照搬Portmaster的代码、设置默认值或endpoint／名单分层。
产品代理先准备别名事实再判断完整答复交付，缓存命中同样执行当前政策；拒绝沿已有DROP。
原转发路径保留No Recognition Hold与实际事实可得性的限制，系统代查原App不明的处理不变。
此确认不改写上文的源码缺口，也不声明功能已实现或验收。[正式功能记录](../adr/0011-application-dns-filtering-root-and-vpn.md#cname-response-domain-filtering-choice-2026-10-08)

## 2026-10-22：整条规则的逐名匹配补充核对

用户本轮确认“同一条规则的域名条件由同一个名字满足”，随后要求参考 Portmaster
补全执行细节。本次静态复核沿用上述固定提交；核对的本地源码与该提交无差异，
同时查看了官方公开源码入口。没有取得可信的新分支 HEAD，因此以下仍是固定版本的
源码结论，不将网页的不同抓取日期拼成当前版本证明。既有调用链缺口保留原范围。

以上是本日最初核查的版本边界。随后用户要求独立研究，已通过实际联网确认
`cc164c7df617ecdb41a766edf88f8bf3fd741a85`（10-21提交），并核对33个文件及哈希；
CNAME相关文件与上述旧pin仍一致。完整处理链的适配、证据与建议见
[10-22独立适配研究](2026-10-22_PORTMASTER_DNS_ADAPTATION_RESEARCH.md)，不再以最初未取得新HEAD
解释当前研究状态。

### 可借鉴的执行结构

- `Endpoints.MatchMulti` 将规则放在外层、目标放在内层；当前规则检查所有目标仍无匹配，
  才进入下一条。这为保留规则顺序提供了简单参考，但它是通用多目标函数，不能据此声称
  标准 DNS/CNAME 入口就是通过该函数执行。[规则顺序][S6]
- `EndpointDomain.Matches` 分别检查原域名和每个别名；实际匹配的是一个具体名字。
  其原名优先返回、别名仅返回拒绝的特殊语义已经在上文列出，不能直接代替 Sakamoto
  已选的统一整条规则与 Rank。[域名匹配][S5]
- 名单加载为各名字分别保留出现来源；`ListOccurences` 以具体域名等实体为键，
  `getDomainLists` 分别查询原名与启用的别名。这种保留命中名字与名单来源的方式可参考。
  [名单事实][S4]
- `ResolvedDomain.AddCNAMEs` 从原查询名沿 owner→target 关系追链，而非将答复内所有
  名字直接视为查询的别名；实现有 50 层上限及部分循环退出条件。可借鉴有界、从原名
  出发的追链方式，不因此选择同样层数或把其退出条件当作完整循环检测。[链构造][S14]

### 名单语义与我们的区别

`EndpointLists` 将所选名单集合交给 `Entity.MatchLists`；后者遍历已经加载的各实体／
名单来源，只要出现任一指定来源就返回命中。这是“任一名单命中”，不是通用的
“同一域名同时属于名单甲与乙”的 AND 表达式。它不能证明跨名字拼合 AND 条件是正确的。
[名单 endpoint][S12]、[名单事实][S4]

Portmaster 的 endpoint 还会检查其声明的协议与端口；源码没有把一条带端口条件的
规则简单裁掉端口后当作纯域名规则。其 DNS Connection 又有独立的事实构造方式，
不能将这种表示直接套给 Sakamoto 的 DNS 流或未来业务连接。[完整 endpoint][S13]、
[DNS 事实构造][S8]

### 对已确认 Sakamoto 合同的具体应用

下列是依据本次用户确认及现有 ADR 的落地推导，不是 Portmaster 的原样行为：

1. 查询阶段以原 QName 为候选；答复阶段补入与原查询实际相连的 CNAME，保留各自来源。
2. 在既有 Rank 顺序下，对每个候选名字分别检查同一条完整规则。所有域名条件绑定
   当前这一个名字；其余条件仍使用所属控制点的真实上下文及可用性。
3. 不合并不同名字的名单位图来制造 AND 命中；别名也没有独立的拒绝优先级。
4. 代理在交付完整答复前准备好本次别名和名单事实，再按当前政策判断，缓存答复亦然。
   原路径只使用实际可得事实，沿既定 No Recognition Hold 与 DROP 处理。
5. 记录胜出规则、实际命中名字及其查询名／CNAME 来源，复用既有观察通路。

第 4 项也避开上文固定源码的两处静态缺口：别名在检查后才赋值，以及名单清空后
没有在该分支重新加载。[nameserver 顺序][S3]、[解析后分支][S2]、[名单事实][S4]
本次没有运行 Portmaster、导入源码、创建实施任务或修改产品代码；正式行为以
[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md#same-name-whole-rule-evaluation-choice-2026-10-22)
和统一规则规格为准。

## 2026-10-22：用户后续选择 PM 优先

用户进一步明确：能参考 PM 的细节以 PM 的逻辑为默认依据，不应让用户扮演专业设计者，
也不应将对助手临时例子的回答当成必须优于成熟参考的定案。本节记录这一后续指示；
上节保留核查过程，其“Sakamoto 落地推导”不等于获得逐项照搬或优先于 PM 的依据。

| 细节 | 源码核对与采纳方式 |
| --- | --- |
| 查询与答复两个判断时点 | 沿用可参考的查询前检查、取得答案后复查结构；代理在复查前准备实际别名与名单事实，缓存答复同样检查当前政策。[S2][S3] |
| 同时选用多个过滤名单 | PM 对所选集合使用任一来源命中；按这一常规含义设计。显式写出的“甲 AND 乙”属于另一个操作，不把 AND 自动改成 OR。[S4][S12] |
| 保留命中名字与名单来源 | 参考逐名查询和按实体保存名单来源的结构，不只保留一个失去来源的最终布尔值。[S4] |
| 查询名与实际别名链 | 保留原名，从原名追踪相连的别名；采用有界处理，数字预算属于实现合同。[S5][S14] |
| 规则顺序 | 参考有序匹配；Sakamoto 继续使用既有整条规则 Rank。PM 的 profile/endpoint/过滤列表层次不是自动新增的另一套优先级。[S6][S7] |
| 别名允许与拒绝的不对称 | PM 的域名 endpoint 对原名可返回允许或拒绝，对别名只返回拒绝；名单 endpoint 则使用自己的名单集合匹配。这是实际差异，不能把某一个分支推广成所有域名条件的语义，或声称与统一 Rank 已经完全等价。[S5][S12] |
| 通用 AND／OR／NOT 规则 | 所核对的 endpoint/list 表示没有等价的任意多域名谓词表达式。此前“同一名字满足完整 AND”保留为统一规则扩展的明确来源，不冒称 PM 的既有行为。[S12][S13] |
| 事实准备与名单重载 | 固定源码中的时序／加载缺口是静态发现，不当作应当继承的成熟设计；保留上文证据边界。[S2][S3][S4] |

用户随后进一步澄清：目标是借鉴 PM 已有流程并因地制宜，不追求完全等价；此前通过
临时场景给出的技术选择可以基于研究重新评估。上表中的差异不是必须保持差异的理由，
也不能将用户当时的 yes 当作冻结实现的依据。

该指示使 PM 成为可比 DNS 细节的默认设计依据；保留 Root/VPN、UDP/TCP、
原解析器保留、统一规则等产品目标，继续尊重关联跨应用范围的明确暂缓。对于真正冲突，先给出
源码证据和适配方案；可沿现有架构处理的内部细节由设计者收敛，不继续逐项询问用户。
正式选择已同步到 [ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md#portmaster-first-dns-detail-policy-2026-10-22)。

[S1]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/config.go#L446-L466
[S2]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/dns.go#L105-L229
[S3]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/nameserver/nameserver.go#L164-L365
[S4]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/intel/entity.go#L148-L560
[S5]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/endpoints/endpoint-domain.go#L70-L90
[S6]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/endpoints/endpoints.go#L90-L104
[S7]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/profile-layered.go#L331-L455
[S8]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/network/connection.go#L346-L365
[S9]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/dns.go#L230-L305
[S10]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/master.go#L30-L342
[S11]: https://github.com/safing/portmaster/tree/882d900dadb6df91150cf87f0a12706d29172586/service
[S12]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/endpoints/endpoint-lists.go#L19-L40
[S13]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/endpoints/endpoint.go#L28-L101
[S14]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/resolver/ipinfo.go#L55-L75
