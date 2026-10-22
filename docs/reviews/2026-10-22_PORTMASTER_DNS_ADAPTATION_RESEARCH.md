# Portmaster DNS 行为到 Sakamoto 的适配研究

研究日期：2026-10-22。结论：**可以进入 `/to-spec` 编写正式规格；不能把现有补充 ADR 当成已经完成执行设计，更不能直接照搬 Portmaster 实现。** 原路径 Root/VPN、UDP/TCP 的过滤与观察闭环可以先推进；可选代理、答案缓存、普通 DNS/DoT/DoH 仍在完整首版范围。关联跨应用范围继续暂缓，不因此阻塞查询过滤和代理规格。

本报告仅静态研究官方源码与当前 VPP-native C 主线；没有构建、设备实验、性能采集或 Portmaster 运行验证，没有导入参考代码。以下“建议”是待规格采纳的设计建议，不是新增用户定案或功能验收。用户最新澄清：不追求完全等价，优先成熟流程并因地制宜；先前临时场景形成的技术选择可以修订，不能仅因已有yes便冻结。

## 版本和证据边界

- 本次实际联网 `git ls-remote` 得到官方 `HEAD = refs/heads/development = cc164c7df617ecdb41a766edf88f8bf3fd741a85`，提交时间 `2026-10-21T11:34:40Z`。[官方固定提交][P0] 这证明查询时的分支身份，不证明哪个发行版本已部署。
- 独立复核 `/tmp/sakamoto-portmaster-dns-adaptation-20261022/source-manifest.json` 中全部 **33 个文件的 SHA256**。原始文件位于该目录的 `upstream/`，manifest 保留固定 raw URL、字节数、哈希及旧版比较。30 个与本地旧快照 `13a86a43cc6cee592395fcddc8387178f290f144` 逐字节相同；仅 `packet_handler.go`、`resolve.go`、`failing.go` 不同，已逐项阅读 diff。
- 新变化：已完成 verdict 的队列包不再创建连接 worker；失败 resolver 稳定移到候选末尾，必要时仍询问；恢复探测以收到回答为准，不再要求特定测试 A 地址。CNAME、名单、nameserver、答案缓存、关联核心在上述两个版本间没有变化。[包入口][P1]、[最新解析循环][P2]、[失败恢复][P3]
- Sakamoto 源码基线为 `8214da97e690d974768809e8a829ebe320f502a9`；同时阅读工作树中尚未提交的 ADR-0011、统一规则规格、CONTEXT 与 CNAME 参考补充。它们是设计输入，不能扩张实际实现声明。[当前主线][K0]

下表的 PM 引用全部固定到本次新提交。标记含义：**沿用**＝可比行为直接参考；**适配**＝因既定产品合同或不同入口必须调整；**无对应**＝PM 没有同构能力；**证据不足**＝静态实现不能支持该覆盖承诺。几种标记可以并存。

## 可核验行为映射矩阵

| 范围 | PM 源码事实与接点 | Sakamoto 约束／分类 | 建议执行行为 | 对应验证场景 |
| --- | --- | --- | --- | --- |
| 本地入口／原解析器 | `filterHandler` 为外发53设置重定向；Linux mark1799 DNAT 仅 UDP；listener `Net:"udp"`，handler 仅接受 `UDPAddr`。[P1][P4][P5][P6] | **适配、无对应**：必须保留原解析器，并覆盖 UDP/TCP；PM不是该原路径实现 | 未启用替换时仅检查和记录，Root继续内核、VPN继续原 Direct；不要为过滤自动重定向。代理启用后才接本地服务 | Root/VPN × IPv4/6 × UDP/TCP53，App选择公网与自建LAN resolver；关闭替换时目的地不变 |
| TCP framing／DROP时点 | PM自己的 `TCPResolver` 用 DNS `ReadMsg/WriteMsg`，具有多在途ID；这不是本地TCP查询入口。[P7] | **无对应**：透明TCP与完整代理消息是两种控制点 | 两字节长度、拆段/合并帧、同连接连续查询都要处理；原路径首次取得足以证明拒绝的事实时DROP当前原包，并阻断该流后续；不回收已放行字节、不删除流中字节 | 长度头拆段、QName拆段、多个query同包、允许后再拒绝、双向乱序/重传、半途加入 |
| 原调用者／系统代查 | 根据原socket/保存的DNS连接取得进程；DNS实体不等于该socket的业务调用App。System Resolver只检查自身local endpoint，解析后跳过CNAME分支；Linux结果监听写global，没有原调用App。[P8][P10][P11][P27] | **适配**：原App不可靠时DNS应用政策允许；现有UID-known不是可靠原App的同义词 | 保留实际socket UID和系统代查来源，但DNS App可靠性单独判断；不猜测、不等候IPC调用者；独立通用规则仍执行 | 直接App查询、系统resolver代查、UID已知但原App未知、原App完全未知；后续业务连接使用自身App |
| 查询前与结果后次序 | 常规nameserver：`FilterConnection → Resolve → FilterResolvedDNS → reply → defer UpdateIPsAndCNAMEs/SaveOpenDNSRequest`；cache命中也经过本次查询过滤。[P6] | **沿用、适配**：复查当前政策，不复用allow | 两个政策点共用规则执行；代理取得完整结果后准备事实、复查、再交付；原路径按实际到达事实检查 | query允许后等待期间改规则；相同cache被不同App使用；缓存命中后CNAME被新规则拒绝 |
| CNAME事实准备 | 新DNS Connection以 `cnames=nil` 创建，标准response检查没有从RRCache提取；写CNAME发生在defer。`mayBlockCNAMEs` 又 `ResetLists`，未重新 `LoadLists`。[P6][P8][P11][P12] | **证据不足、适配**：不能把开关/函数名当回答前真实覆盖 | 在答复判断之前从本次答案追链并取得当前名单事实；不继承这两处缺口 | 新查询首次返回被拒CNAME；QName不在名单而alias在；名单热更新后cache hit |
| 名字与链 | `AddCNAMEs` 从QName沿owner→target追踪，最多50步；只检测回原名/自身，不是完整visited循环检测。域名endpoint独立检查原名/别名。[P13][P14] | **沿用、适配**：实际相连链、有界；不提升答案里任意名字 | 保存QName和各CNAME来源；从QName追链、显式去重/循环终止；不复制50这个数字为产品要求；无完整链时只发布已证实事实 | 无关CNAME/extra、分叉/重复owner、A→B→C→B、压缩指针循环、超预算、大小写/尾点 |
| 显式域名endpoint顺序 | 每条endpoint先QName；其匹配可Allow/Deny；QName没匹配才看CNAME，**alias只返回Denied**。endpoint按序第一非NoMatch；profile层再到global。[P14][P15][P16] | **适配**：不能宣称与现有统一Rank完全等价 | 当前单一 `DOMAIN_LIST` 不引入这一分支特有的alias-Allow抑制；使用下节映射，明确它是产品适配 | 高Rank允许QName/低Rank拒绝alias；反序；仅允许alias；同一名字由单项list与多项list表达 |
| 名单endpoint／订阅选择 | `EndpointLists` 调 `MatchLists`，任一所选来源命中即满足，再用本条endpoint action；可以Allow也可以Deny。默认订阅filter分支位于endpoint之后，但存在unbreak来源豁免；CNAME分支直接MatchFilterLists，没有走这一豁免封装。[P12][P16][P17][P18][P27] | **沿用、适配**：多个名单选择是OR；只有一套Rank | 选用多list编成同一完整规则中的any-match；不增加PM式独立endpoint/list优先级；保留命中名字和来源；兼容例外使用明确的高Rank普通ALLOW规则表达，不新增默认订阅/许可，不复制一个绕过统一Rank的unbreak分支 | list A或B命中；显式Allow与list拒绝按Rank交换顺序；观察模式记录拒绝但允许 |
| AND/OR/NOT与不可得事实 | PM endpoint具protocol/port检查，DNS实体本身未填业务协议/端口；`MatchError`还存在对部分缺失数据的拒绝处理。它没有等价任意布尔域名树。[P8][P19] | **无对应**：Sakamoto全表达式、三值可用性、同名绑定 | 逐候选名字执行完整表达式，跨名字不拼AND；未知不因NOT变真。真实DNS包UDP/TCP/53事实可用，未来业务443/SNI等不可从QName推得 | QName∈A、alias∈B，A AND B不成立；未知NOT不命中；可用true OR未知；domain AND未来业务443不能提前拒绝 |
| 结果地址过滤／提前返回 | PM按profile/resolver范围删除A/AAAA，所有允许地址被移除时Block；SVCB/HTTPS过滤仍TODO；own PID、env、受条件限制的connectivity有特殊处理。NXDOMAIN在nameserver提前返回。[P6][P11][P18] | **适配**：已选域名/CNAME过滤不自动加入答案IP重写或额外豁免 | 不导入这些未选设置和专门allow旁路；一般query/result观察保持真实，域名政策照统一Rank。保留返回RR内容；普通包IP规则不自动解释成对每个RDATA IP执行 | LAN答案来自公网resolver、env/connectivity、仅AAAA、SVCB hints；没有承诺的地址过滤不报已支持 |
| cache存储／政策拒绝 | `resolveAndCache` 在返回给response policy前先保存上游cache；之后按query verdict决定关联保存。失败query也有独立失败抑制，不是allow cache。[P2][P6] | **沿用、适配**：cache只存解析数据，不存权限 | 允许策略拒绝后的有效原始上游答案留在proxy cache；每个waiter仍复查当前政策。拒绝不写可执行关联、不驱逐其他独立有效关联 | App A拒绝alias后App B允许命中同cache；政策拒绝不当NXDOMAIN或transport故障缓存 |
| 答案保真／记录类型 | PM只收单IN question，后端用FQDN/QType重新造query；RRCache回包仅重建RCODE和三个section，持久化忽略OPT/NULL。[P6][P7][P20][P21] | **适配**：首版普通RR兼容、未知RR保留；原路径允许答复原样走 | 原路径保留原wire；代理共享完整消息codec，保留可转发语义，不用地址数组合成答案；不能照搬PM重新造query方式承诺EDNS/flags保真 | TXT/MX/SRV/HTTPS/未知RR、EDNS/DO/CD、TC、大答复；数据未提取仍可转发 |
| 正TTL／negative／stale | `Clean` 把所有RR输出TTL写17；内部通常原最小TTL限60秒～24h，错误10秒、空答案60秒；缓存成功/NXDOMAIN/REFUSED。过期成功cache可显式stale或失败时backup。[P2][P20] | **适配**：已选有效cache与独立关联2h；已有研究要求TTL递减 | 不复制17秒、最低60秒、stale/backup；有效正cache按剩余TTL，TTL0不延长；NXDOMAIN/NODATA按SOA负TTL，失败不冒充有效答案。[R1][R2] | TTL1/0、不同RR TTL、SOA MINIMUM与TTL不同、NODATA、cache过期上游全失败→SERVFAIL |
| DoH HTTP Age | PM HTTPS后端直接Unpack body，未读Age，再由通用Clean处理；也无response body上限检查。[P21] | **适配**：不能据PM缺口宣称成熟cache正确性 | DoH在插cache/交付前扣HTTP Age，再按经过时间递减；有界HTTP头/body与DNS长度校验，未知格式失败而非无限分配。[R3] | TTL600、Age250→剩350；Age≥TTL、过大body、错误媒体内容、截断HTTP body |
| resolver视图／cache key | PM NameRecord key是domain+QType；复用检查source resolver仍active及compliance。[P29]网络变更reload；配置上游变化异步清NameCache；并无网络epoch加入该key。[P2][P22][P23][P24] | **适配**：保留network/resolver view，不能串答案 | 缓存与同问题合并使用同一“网络代际＋解析路由/上游配置视图＋影响答案的query语义”；配置/换网直接切代际，旧结果不能回写新视图 | 同名公网/内网不同答案、同网络换上游、例外改路由、换网期间旧reply晚到 |
| 内网／mDNS | scope按最长匹配顺序优先本地范围；`.local`尝试local/system再mDNS，普通global还有配置和系统候选；PM自带mDNS resolver。[P23][P24] | **适配**：mDNS原路、不进入DNS查询过滤；普通DNS尊重已有resolver | 保留显式local DNS exceptions；最长label后缀优先、相同范围冲突在配置时拒绝；不要把看似公网名字等同公网视图；不新增mDNS resolver | `git.example.com`私有答案、嵌套例外、普通单播`.local`、UDP5353保留原处理 |
| 顺序主备／恢复 | 最新版先稳定排列健康再失败resolver，逐个查询；global `tryAll=false`，正常DNS结果不寻找正答案；特定local scope可 `tryAll=true`；失败项无人回答时仍尝试，周期探测任意回答可恢复。[P2][P3][P23] | **沿用、适配**：仅配置列表内加密主备、禁止降级 | 顺序尝试当前可用项，临时失败后备；失败标记不得永久饿死主项，可定时探测恢复后重回原顺序；不广播、不因NXDOMAIN/NODATA寻找正答案；不顺便加入系统/出厂resolver | 主超时备成功、主恢复、全部失败、NXDOMAIN不打备、网络换代清健康状态；cancel不算resolver故障 |
| bootstrap／TLS身份 | PM域名端点可带ip，独立verify身份；无IP时用hostname连接并避免用同一配置resolver解析自身初始化域。[P24][P7][P21] | **沿用、适配**：已选配置IP优先，否则系统/原网络引导 | bootstrap只供产品连接上游；保持TLS身份验证，结果按network代际有界刷新，不成为业务明文降级 | 只有hostname、配置IP+hostname、证书不符、bootstrap失败切备、换网后旧地址到达 |
| cancel／late reply／stop | TCP等待select支持ctx/module结束；无人等待的晚reply仍可写cache；ForceReconnect将旧连接abandoned但允许在途结束。nameserver shutdown有10秒上限。[P7][P25] | **沿用、适配**：当前owner、generation、无悬挂completion | 完成/取消/超时只终结一次；停止先停新入口，取消任务/等待者，再归还socket/buffer。旧代际reply不得交付/写cache/写关联；同代际shared query只服务仍活跃waiter，全部取消则丢弃晚结果 | cancel与response同轮、旧ID复用、停止中TLS握手、晚broker回调、stop后缓存/观察不复活 |
| 关联写入时机／拒绝答案 | nameserver仅Accept/Undecided且有RRCache的defer调用Update；Block/Drop/Failed仅保存观察。此处在reply调用后，但reply错误被记录后吞掉，不能证明App收到。[P6][P11] | **沿用、适配**：拒绝答案无可执行关联；政策允许不等于传输交付 | response政策允许后才准入关联；保留“允许交付”和实际return/completion结果，不能记“App已收到”。拒绝仅留解析/政策观察 | CNAME拒绝仍有解析成功观察，无关联刷新；TUN输出容量拒绝不冒充上游失败 |
| 地址来源 | PM从Answer+Extra收集所有A/AAAA，还收SVCB/HTTPS target和IP hints；链仅从原名追。未逐一证明每个IP owner属于此链。[P11] | **适配**：只从实际可靠地址记录提取，不能提升任意嵌入字段 | 关联地址owner必须能连回QName/所选真实CNAME链；无关glue、TXT字符串、HTTPS hints不自动成为可执行QName-IP关联 | MX/SRV额外地址、无关additional A、HTTPS hints、真实CNAME最终A/AAAA；未知RR仅转发 |
| 关联范围／歧义 | 普通来源写profile，system/unidentified写global；lookup自身profile失败才global；同IP取 `MostRecentDomain`，不合并候选、不逐条查Expires。[P26][P11][P13] | **适配、范围暂缓**：唯一有效候选；跨App未定 | 记录完整来源；保留唯一候选规则，零/多候选域名不可用；本报告不选择全局共享或仅本App，不让范围问题阻塞过滤闭环 | 同IP多域名、多来源、未知来源；范围未选部分明确未验收，不偷用PM fallback |
| 更新／旧地址／期限 | 每个IP的AddDomain替换同名并移末尾；新IP更新不删除旧IP。IPInfo数据库过期至少now+24h再加1h；不是逐pair严格TTL。[P13] | **部分沿用、适配**：有效答复刷新2h，每pair独立，业务不刷新 | 保留旧地址证据至各自2h/eviction；仅实际本次获准结果刷新返回的pair，有效cache亦然；不复制25h或按最新域名取值 | 09时旧IP→11时到期、10时新IP→12时；连接访问不续期；拒绝答案不续期 |
| 既有流保留／换网 | PM把选中Domain/CNAME/DNSContext复制到Connection，已有Domain跳过lookup；该路径没有因关联Expires清空。网络事件重载resolver，不等于全清IPInfo。[P26][P13][P22] | **部分沿用、适配**：同网络已取事实不随年龄清空；换网新lookup重置 | 保留流自己的DNS证据而非旧allow；当前规则重评；新流不能借过期pair。网络代际变化排除旧关联，不以本产品reset保证系统重新查询 | 关联到期后旧长连继续重评/新连无名；换网旧cache事件不得恢复可执行关联 |
| 观察 | PM成功cache通常不存独立open DNS请求；部分请求等待合并进业务连接。[P9] | **适配**：DNS政策、解析结果、连接裁决各自是真实事实 | 沿现有正常观察补DNS类型；记录阶段、可靠性、QName/alias命中、rule/snapshot、结果/交付/association资格，不抄隐藏cache-hit的UI收敛策略 | cache allow/deny可解释、未知App不虚构命中、解析失败与政策DROP分开、export背压不阻塞包 |

PM的常规处理顺序还存在提前返回：输入问题数/class/transport验证、localhost处理、重复失败抑制在原App政策之前；NXDOMAIN分支又早于FilterResolvedDNS。因此“query policy→cache/upstream→response policy”是可参考的主结构，不是所有PM路径都完整经过两个判断点的证明。[P6]

## 名单、别名与统一 Rank 的具体映射

**当前 `DOMAIN_LIST` 最直接对应 PM 的 `EndpointLists`，不是 `EndpointDomain`。** PM名单endpoint由任一已加载实体/所选list命中，再返回该规则Allow或Deny；它没有“只要来自alias就禁止Allow”的逻辑。Sakamoto已把每条表达式的域名事实绑定到一个候选名字，因此一个 `DOMAIN_LIST(A)` 的结果保持同构；多个list选择展开为 `A OR B`，显式写出的 `A AND B` 仍要求同一名字同时命中。[P12][P17][K1]

建议执行循环是“**Rank在外，名字在内**”：按既有Rank逐条取完整规则，对QName及实际CNAME各自执行；任一候选使完整规则成立，该规则成为本阶段赢家。每个候选的名单来源单独保留，其他事实保持原控制点的可用性；不得先把所有名字的位图OR到一起再运行任意AND树。此结构参考PM有序匹配，但标准nameserver并没有直接调用通用 `MatchMulti`，不能把后者说成已验证的DNS执行路径。[P15]

对PM直接域名endpoint的“alias只拒绝”，建议明确保留产品差异：**不为现有 `DOMAIN_LIST` 增加按action或域名内容猜测的alias特殊规则。** 当前精确域名/子域条目本来就属于DomainList；若因为list只剩一项便把它当另一种PM endpoint，同一政策会随配置表示方式改变行为。名单命中的高Rank ALLOW因此可以允许当前完整答案，包括只在alias命中的情况；低Rank拒绝不能另行覆盖。QName高Rank ALLOW压过低Rankalias DROP，与PM的常见允许例外效果相近；仅alias ALLOW的效果则明确不等价于PM直接域名endpoint。[P14][P17][K1]

这是由当前唯一规则模型和对应的PM名单操作收敛出的**适配建议**，不是用先前临时采访回答证明PM也如此，不是新增“DNS优先级”。若未来真要提供PM专用直接域名endpoint语义，应把它作为明确的新操作设计；本轮没有必要为它增加另一种matcher、配置或一次用户内部机制采访。

PM自身的两个准备缺口必须避开：别名和名单都要在本次判断之前就绪。名单加载失败或预算不足保留不可用/故障原因，不能当空名单，更不能让NOT产生伪命中。现有SNI predicate的TLS/QUIC适用性不因接入DNS被取消：DNS需要独立的域名来源/可用性输入，复用表达式执行器与Rank，不把QName假填成SNI。[P11][P12][K1]

## 原路径 TCP 的可执行边界

建议Root与VPN原路径都在现有FlowOwner上维护**有界、双向、可前移的DNS/TCP消息观察状态**，共享framing/codec与DNS政策代码；只复制协议所需字节，不扣留原NFQ/TUN包。连续消息结束后移动窗口，不把一次SNI前缀缓存原样扩成整条连接永不停止的字节存储。DNS/TCP两字节长度不是TCP包边界，允许分段和流水查询。[R4][K2]

原路径在QName或已证实相连CNAME足以让一条完整规则成立时，阻止携带当前可见事实的原包；同一TCP连接后续沿当前政策保持拒绝，以避免只丢一个片段后重传绕过。若该包还含其他允许查询，它们也受影响。已经转发的前缀不撤回，未就绪事实不产生拒绝；response检查亦如此。规则revision变化仍重评，不能保存永久deny位而绕过当前政策。midstream、缺段、冲突重叠、超预算须记录“无法完整观察”，不能报完整过滤成功或伪造NoMatch。其他独立可用规则正常执行。

透明路径因此不承诺“所有答案在任何字节交付前完成CNAME检查”。代理路径不同：Root socket或VPN本地HEV会话交给DNS核心完整消息，先准备完整事实、当前政策复查再交付；被拒query不派发，被拒response不交付原答案。建议用下节的REFUSED明确告知代理政策拒绝，不做TCP字节删除或主动RST。两条路径共享语义，控制点覆盖不同。该限制与既定No Recognition Hold一致，不能靠PM上游TCP客户端消除。[P5][P6][P7]

## 当前主线可复用接点与实际缺口

| 当前接点 | 真正已有的东西 | 接入仍需做的工作 |
| --- | --- | --- |
| graph规则／DomainLists | `product_packet_graph_policy_on_owner`保护snapshot、执行PRE/POST、记录Rank赢家；domain bitmap目前只来自SNI。表达式有三值AND/OR/NOT，但domain op依赖SNI/LPI。[K1][K9] | 新DNS事实/可用性输入与查询/答复控制点，逐名完整规则求值；不能仅把原SNI字段改名 |
| FlowOwner／生命周期 | 有generation、slot/incarnation、FlowEnd、owner-local状态和事件驱动。TCP byte cache/SNI producer是有界识别前缀，stop时清理。[K2][K3] | DNS连续TCP framing、query-response相关、超限原因、取消和旧token拒绝；复用所有权，不另建第二Runtime |
| 原路径DROP | Root当前verdict仅写NFQA_VERDICT_HDR；VPN当前原包策略与Direct桥接已有完成通路。[K4][K5] | 首个拒绝后的流后续处理、DNS observation与普通包裁决关联；Root代理接管mark/NAT/socket入口尚无 |
| HEV/lwIP | Product `create_session`/`create_tcp_session`直接建Direct会话，已有UDP/TCP封装、socket broker、protect/bind、owner调度与return。[K5][K6] | proxy模式需在Direct上游建立之前选择本地DNS会话；原路径第一步无需先改成proxy；共享核心不能藏成VPN独占实现 |
| codec/cache/TLS | `LWIP_DNS=0`；Mbed TLS当前target只有QUIC所需crypto原语。[K7][K8] | 完整DNS wire/TTL/negative、普通DNS/DoT/DoH客户端、CA/身份验证、HTTP、cache和有界事务都未接入；c-ares窄复用只是既有研究方向 |
| return／观察 | VPN return有原generation/信用/生命周期管理；正常观察接口已有bounded flow/blocked/end路径。[K3][K10][K11] | DNS事务/result/decision事实与return失败状态尚需扩展，不能宣称现有packet/flow记录已经是DNS记录 |

既有[HEV/c-ares研究][B1]已经给出wire/cache窄改、TTL/Age、owner/broker/return职责，后续按其边界实现；PM的Go resolver实现不决定C依赖选型。S290 resolver职责重构是用户暂缓事项，**不能升格为这条DNS线的既定前置**。本报告不重新打开已收口性能工作。

## 真实顺序与最小生命周期建议

代理建议顺序：`输入完整消息和可信上下文 → 当前query policy → 同视图有效cache/上游事务 → 校验并准备QName/CNAME/名单事实 → 当前response policy → 准入交付及关联 → 记录各自结果`。上游原始有效答案可以在response policy之前入数据cache；关联准入必须在允许交付之后。此“准入”不宣称App已经收到；输出失败有自己的真实结果。原路径复用对应事实与判断步骤，cache/upstream两步由原resolver承担。

对等待中的查询，policy更新不要求重新发上游，但必须在最终交付时复查当前完整规则。network/resolver路由视图变化则使旧事务结果失去当前准入资格；取消/stop同样阻止晚结果恢复状态。答案cache与同问题合并要共用视图和完整问题语义，不能只有QName/QType；App权限不进入解析数据共享的allow决定。关联的跨App使用范围仍然另行暂缓，不能用答案cache的共享方式替它定案。

主备建议参考最新版PM的顺序尝试和恢复，但只使用用户已配置的路由候选。有效DNS结果按其RCODE返回，不寻找另一个正答案；连接/TLS/HTTP故障、超时、无效DNS报文才尝试后备。取消/停止立即终止而不记故障。所有已配置加密候选均失败且无有效cache时按已选合同SERVFAIL；不复制PM旧成功cache救援、系统resolver或factory defaults fallback。重试/总deadline/资源上限由规格给出有限默认值和测例，无须让用户逐项选数字。[P2][P3][P23][P24]

## 重审临时技术选择：采用什么，为什么

用户要借鉴成熟流程，不是维护一张不可变的采访答案表。核心产品目标（Root/VPN共用、原解析器可保留、UDP/TCP、可选proxy、可靠原App、统一配置/Rank）继续作为约束；下面是可修订的技术选择，本报告给出建议，不再次逐项询问。

| 临时选择 | 对照PM后的建议 | 理由与验证 |
| --- | --- | --- |
| 所有DNS政策拒绝均静默DROP | **拆开控制点：原路径保留DROP；proxy改为REFUSED。** 已解析出的原始被拒答案不交付，回一个政策拒绝结果；解析运输失败仍SERVFAIL | PM的Block调用BlockIP生成响应，只有Drop才不回包，[P9]说明其常规阻断并非一律等待App超时。proxy已拥有完整消息和合法答复通路，应沿其及时反馈流程；PM的BlockIP对A/AAAA生成合成阻断地址，对其他类型默认NXDOMAIN。[P28] **REFUSED是本产品适配建议，并非PM默认行为**；保持本产品真实地址模型，也避免将政策拒绝伪装为名字不存在。[R5] 它会比静默DROP更快向App反馈；DROP减少主动答复但让App依赖超时，REFUSED也不能保证App不换resolver重试。验证query拒绝不出上游、CNAME拒绝无原答案、无成功关联、持续TCP的其他query可独立完成 |
| 原路径DNS/TCP拒绝影响同连接其他query | **保留**，同时覆盖response拒绝和revision重评 | PM没有本地TCP同构实现；选择性删除字节需要额外传输责任。现成DROP在首次可证明拒绝时执行最小；不承诺撤回过去字节 |
| 有效DNS/cache答复刷新2h，业务连接不刷新 | **保留职责划分，2h仍是临时参数** | PM关联由DNS结果写入，连接取得副本；没有逐次业务访问刷新所有关联的依据。2h不是PM值，不能宣传成熟算法证明；无需现在改为其至少25h且无逐pair过期的模型 |
| 新地址不删旧地址、每pair独立年龄 | **保留，写成简单的有界pair更新** | PM以IP为键，新IP不会顺带清旧IP，支持App仍使用旧答案的现实。Sakamoto逐pair期限比PM记录级续存更清楚；无需引入地址集合版本或强制整组替换 |
| 同网络旧流保留已取域名，不随关联年龄清空 | **保留** | PM将域名/CNAME/context复制到Connection，之后已有Domain不重查。[P26] 这是流事实与lookup生命周期分离；当前政策仍重评，不是永久allow。新流查不到过期pair |
| 拒绝答案不写/刷新可执行关联 | **保留并简化为response policy后的准入点** | PMdefer只对Accept/Undecided保存关联，[P6]与此方向一致；不必维护一套先写入再撤销机制 |
| 同一完整规则的域名条件同名满足 | **保留为布尔扩展** | PM的名单选择是any-match；它无同构AND树。保留一个候选输入最简单，避免跨名字制造用户未写出的匹配 |

因此，PM优先在这里实际改变了一项建议：proxy政策拒绝改为明确响应，原路径不额外承担注入。其余选择经核查有适用理由才保留，不以“用户曾回答yes”为理由。REFUSED是本报告建议修订项，当前ADR仍写silent DROP；应在正式规格中明确取代，不能同时声称两者都是最终行为。

## 此前文档应修正的位置

| 文档／段落 | 应修正或明确的内容 |
| --- | --- |
| [ADR-0011 CNAME、same-name、PM-first][D1]及[统一规格DNS段落][D2] | 将“同一完整规则、逐名字”与PM名单endpoint的直接对应写清；加入上面的alias ALLOW映射差异。不能由PM的直接域名endpoint推导现有 `DOMAIN_LIST` 别名一律deny-only，也不能声称PM本身支持通用AND树。现有PM-first补充已承认差异，接下来要写到执行行为，不能停在提示差异 |
| ADR-0011“Both paths update…actual observed or resolved answers” | 与后面的denied-answer资格段统一：实际结果可以观察，但只有当前允许交付、上下文有效的结果准入可执行关联；不是每个解析成功答案都写fallback。现有文案易被单段引用误读 |
| ADR-0011 original-path TCP denial及CNAME控制点 | 查询TCP的连接连带后果已有；把相同response拒绝的后续流处理、重传、事实未就绪/超限和revision重评写进正式规格。不得把“UDP/TCP均覆盖”扩写为透明TCP所有字节交付前完整检查 |
| ADR-0011结尾“refresh/fact lifetime仍待定义”等总括 | 2h刷新来源、旧地址独立保留、同网络旧流事实存续已在今天补充选择；只把尚缺的解析视图/网络换代、接口和资源合同列为待定，避免新旧段落相互取消 |
| [CNAME参考][B2]、[Linux PM参考][B3] | 保留其历史pin；引用本报告说明新HEAD33文件核对结果。两处CNAME缺口在最新pin仍成立。旧“skip failing resolver”细节不可当最新版，最新是健康优先、失败末尾且必要时仍询问 |
| [VPP DNS参考][B4]中10-05本地DNS路线／10-07草图与旧固定VPN入口 | 这些是分阶段历史讨论；执行入口应以10-22原解析器闭环优先及可选proxy为准。旧“阻止时本地答复”不是现有实现；按本报告建议将原路径DROP和proxy REFUSED分开记录，明确改动现有proxy silent DROP，而非让历史段落自动决定。固定VPN DNS地址仅proxy，不适用于未替换路径。源码行号3952等也已变化 |
| [HEV/c-ares研究][B1]、[关联范围比较][B5]、CONTEXT | 保留其“研究/未集成”与范围暂缓标识；不要把codec选型、PM profile/global或临时采访例子升级成已实现前置。2h、唯一候选、换网重置是本产品取舍，PM不提供同等证明 |

以上仅提出修订建议；本轮没有编辑这些文件。

## `/to-spec` 就绪判定

**就绪的是进入规格编写，尚未就绪的是声称完整执行合同已经冻结或开始验收。** 产品目标、入口范围、复用边界、Rank、原App未知行为、原路径先行和可选代理方向已足够，不需要再逐项采访内部技术细节。PM提供了查询前/结果后两点、名单any-match、原名追链、顺序上游、结果关联等直接参考；UDP-only入口、CNAME准备缺口、17秒TTL、stale、profile/global与最近域名算法都不能当成应继承的best practice。

正式规格应一次写出矩阵中的行为和验收边界，按两个交付阶段组织：先Root/VPN原路径UDP/TCP过滤、观察、stop闭环；再proxy/cache/普通DNS/DoT/DoH。对每个控制点说明事实何时可用、完整规则怎样求值、错误/超限怎样记录、哪些资源在结束后必须归零。HTTP/SOCKS/DTLS等已选连接域名来源继续保留其完整首版范围，不由这个实施顺序悄悄删去。

**本轮没有新增必须由用户先回答的产品级问题。** 关联跨App范围保留显式暂缓；规格可描述产生的证据、接口和已选唯一候选/期限，却不能替用户选择其使用范围，也不能提前宣称该部分fallback验收完成。alias名单映射、proxy REFUSED修订、TCP控制点、TTL/negative/Age与取消等执行合同按上述建议收敛；如果后续要更改原解析器保留、No Recognition Hold、统一Rank或明确暂缓范围，才是新的产品决策。

## 来源

[P0]: https://github.com/safing/portmaster/commit/cc164c7df617ecdb41a766edf88f8bf3fd741a85
[P1]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/firewall/packet_handler.go#L203-L527
[P4]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/firewall/interception/nfqueue_linux.go#L51-L147
[P5]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/nameserver/module.go#L118-L156
[P6]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/nameserver/nameserver.go#L36-L364
[P2]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/resolve.go#L166-L539
[P3]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/failing.go#L74-L138
[P7]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/resolver-tcp.go#L116-L519
[P8]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/network/connection.go#L295-L365
[P9]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/network/dns.go#L160-L228
[P10]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/firewall/interception/dnsmonitor/eventlistener_linux.go#L24-L145
[P11]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/firewall/dns.go#L20-L305
[P12]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/intel/entity.go#L149-L560
[P13]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/ipinfo.go#L33-L205
[P14]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/profile/endpoints/endpoint-domain.go#L38-L90
[P15]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/profile/endpoints/endpoints.go#L90-L130
[P16]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/profile/profile-layered.go#L331-L455
[P17]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/profile/endpoints/endpoint-lists.go#L19-L40
[P18]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/firewall/master.go#L30-L112
[P19]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/profile/endpoints/endpoint.go#L28-L125
[P20]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/rrcache.go#L16-L302
[P21]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/resolver-https.go#L59-L171
[P22]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/main.go#L80-L135
[P23]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/scopes.go#L163-L311
[P24]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/resolvers.go#L203-L468
[P25]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/nameserver/module.go#L268-L297
[P26]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/network/connection.go#L561-L609
[P27]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/firewall/master.go#L203-L449
[P28]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/nameserver/nsutil/nsutil.go#L53-L130
[P29]: https://github.com/safing/portmaster/blob/cc164c7df617ecdb41a766edf88f8bf3fd741a85/service/resolver/namerecord.go#L39-L70
[R1]: https://www.rfc-editor.org/rfc/rfc2181.html#section-8
[R2]: https://www.rfc-editor.org/rfc/rfc2308.html#section-5
[R3]: https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1
[R4]: https://www.rfc-editor.org/rfc/rfc7766.html#section-8
[R5]: https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1.1
[K0]: ../current/README.md
[K1]: ../../src/product/vpp/product_l4_policy.c#L739
[K2]: ../../src/product/vpp/product_flow_sni.c#L142
[K3]: ../../src/product/vpp/product_flow_end.c#L300
[K4]: ../../src/product/vpp/product_root_nfqueue_adapter.c#L765
[K5]: ../../src/product/vpp/product_vpn_flow_stack.c#L121
[K6]: ../../third_party/hev/product/hev-owner.c#L454
[K7]: ../../third_party/hev/product/lwipopts.h#L49
[K8]: ../../third_party/mbedtls/CMakeLists.txt
[K9]: ../../src/product/vpp/product_packet_graph.c#L4432
[K10]: ../../src/product/vpp/product_vpn_tun_adapter.c#L204
[K11]: ../../src/product/vpp/product_observation.h
[D1]: ../adr/0011-application-dns-filtering-root-and-vpn.md
[D2]: ../product/UNIFIED_RULE_ENGINE_SPEC.md
[B1]: 2026-10-03_HEV_DNS_REUSE_AND_CARES_FORK_RESEARCH.md
[B2]: 2026-10-08_PORTMASTER_CNAME_FILTERING_REFERENCE.md
[B3]: 2026-10-05_LINUX_PORTMASTER_DNS_REFERENCE_RESEARCH.md
[B4]: 2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md
[B5]: 2026-10-08_DNS_ASSOCIATION_SCOPE_COMPARISON.md
