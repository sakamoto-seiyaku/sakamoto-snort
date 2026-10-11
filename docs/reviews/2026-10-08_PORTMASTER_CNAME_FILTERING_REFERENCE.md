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
