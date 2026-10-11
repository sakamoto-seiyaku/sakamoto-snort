# Product Docs

状态：当前产品定义、UI/UX、内容与发布口径的权威入口。

本目录回答“要交付什么产品、用户怎样完成任务、界面和文字如何表达、什么才算完成”。
它不替代：

- `docs/decisions/` 中的数据面和跨线程架构决策；
- `docs/INTERFACE_SPECIFICATION.md` 中的控制面与数据契约；
- Plane 中的开放工作状态。

## 当前入口

- [2026-10-07 Root／VPN按应用DNS过滤正式决定](../adr/0011-application-dns-filtering-root-and-vpn.md)：
  首版范围为Root/NFQ与VPN，共用一套DNS处理实现；KSU/libnetd留作未来扩展，首版不实施。两种当前入口统一应用政策：原请求应用可靠时在查询阶段过滤，归属未知时允许解析、采集关联，后续连接按自身应用和可用证据判断。查询拒绝与连接拒绝分别记录；系统缓存和归属限制不因此消失。详细合同待定义，未实施。
- [2026-10-07 首版DNS模块方案](../reviews/2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md#2026-10-07首版范围与模块草图)：
  当前分为原DNS过滤／观察与用户启用的代理两条路径：未替换上游时Root内核／VPN既有HEV保持原DNS转发，允许答复原样通过；代理路径使用Root重定向／VPN本地会话和共用缓存／常规DNS或DoT／DoH客户端；启用加密DNS后，面向公网解析器的普通查询统一走该代理，App自选的其他公网DNS目的地也被替换；明确的内网主机名／域名及其子域例外走网络原DNS或指定局域网DNS，两条路径都过滤记录并保持缓存解析视图，用户可补充例外。首版mDNS继续原网络／系统流程，能观察到时识别和记录，不进加密DNS代理或DNS域名查询过滤，通用应用／IP规则照常执行。两条普通DNS路径共用DNS判断、报文及关联更新；原App明确且规则命中拒绝时直接DROP查询，系统代查原App不明时放行。TLS／QUIC／新增DTLS在SNI识别过程中不做域名处置，成功后使用SNI，结束无可用名才回退DNS关联；其他独立规则正常执行。HTTP按每条可见明文请求的有效目标名更新并重新判断，覆盖同一代理连接的不同目标请求，命中域名拒绝后沿既有DROP阻断该TCP连接后续流量，共用该连接的其他请求也受影响；SOCKS4a／SOCKS5可见目标域名已纳入设计，HTTP／SOCKS的请求IP目标按请求中的远端IP查有效DNS关联。10-08已确认KISS取舍：唯一有效候选才回退，零或多候选保持域名不可用，多候选只记录；关联采用独立于答案TTL的临时2小时（7200秒）过期窗口，后续可优化或重新设计，切换网络时重置当前关联缓存；加密上游全部失败且无有效缓存时报告解析失败，不自动切回常规DNS；SIP域名处理暂缓并保留识别。KSU未来扩展，关联有效范围与详细存续、多播运输兼容与其他局域网路由细节、其他详细失败行为及具体Interface后续展开，未开始代码实施。
  DoT／DoH上游支持域名与IP；IP直接使用，域名优先采用配置的连接IP，否则经系统／原网络DNS取得地址，TLS身份校验保留。此启动解析仅用于产品自身连接上游，业务查询保持既定加密／内网分流；具体地址更新、取消与平台接入后续定义。[启动解析记录](../adr/0011-application-dns-filtering-root-and-vpn.md#upstream-address-and-bootstrap-choice-2026-10-11)
  多个DoT／DoH上游按配置顺序使用主备，优先靠前可用项，连接失败／超时等故障后依序尝试后面的已配置加密项；正常DNS结果不当作运输失败，全部失败且无有效缓存时沿原失败行为。具体可用状态、恢复与超时／重试留到实现定义。[主备记录](../adr/0011-application-dns-filtering-root-and-vpn.md#encrypted-upstream-primarybackup-choice-2026-10-08)
  首版已纳入实际CNAME链的DNS过滤功能：原名／别名按当前统一规则优先级判断，产品代理交付完整答案前检查，缓存命中也检查；拒绝沿已有DROP，系统代查归属不明规则不变，原转发路径保留No Recognition Hold及透明TCP识别限制。功能已确认，具体接点尚未实现。[CNAME功能记录](../adr/0011-application-dns-filtering-root-and-vpn.md#cname-response-domain-filtering-choice-2026-10-08)
  关联的应用／profile分组与跨应用使用范围已按用户要求暂缓，待实际数据后再定，不选择同App专用或全部记录共享；其他已确认关联行为保留。[范围核对及暂缓](../reviews/2026-10-08_DNS_ASSOCIATION_SCOPE_COMPARISON.md)
  应用自带DoH／DoT不由产品替换或解密；须先完成产品自己的DoH／DoT并具备可用解析通路，才推荐用户自行开启外部加密DNS阻断规则。此前不主动增设／开启此类阻断，完成能力也不自动激活；显式通用规则正常执行。阻断对象与识别覆盖后续定义，连接阻断不等于查询级过滤或保证App切回产品DNS。
  10-11已确认普通DNS覆盖A／AAAA、TXT、MX、SRV、HTTPS等记录类型，按适用政策及选定解析路径处理并保留答复语义；无专用提取器的记录保留数据转发。关联从实际地址记录提取，CNAME继续既定过滤，其他字段不自动成为地址／SNI／新政策事实。功能范围已确认，尚未实现。[记录类型范围](../adr/0011-application-dns-filtering-root-and-vpn.md#ordinary-dns-query-type-compatibility-choice-2026-10-11)
- [2026-10-06 DNS架构复用与收敛](../reviews/2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md#2026-10-06复用职责与架构收敛)：
  用户要求域名比较、缓存、DoH／DoT避免重复实现。域名匹配／DNS判断三入口共用，Linux／VPN共用完整DNS处理，DoH／DoT共用缓存、查询管理与TLS基础，关系信息进入统一观察通路；平台／运输差异保留在Adapter。现有职责足以收敛架构，具体Interface、状态布局与行为细节后续定义，未实施。
- [未来扩展：KSU修改libnetd的DNS职责](../reviews/2026-10-05_KSU_LIBNETD_AND_SHARED_DNS_DISCUSSION.md#2026-10-06已确认设计)：
  2026-10-07已明确推迟到首版之后。此前确认的职责设计保留：系统入口负责解析拒绝判断和IP—域名关系采集，复用VPP权威DNS政策／匹配代码；解析、缓存与加密上游继续由Android系统负责。未来此路线NFQ放行53／5353，不重复DNS接管／过滤；该放行不适用于首版普通Root DNS入口，也不证明全部DNS经过hook。具体接入与生命周期合同尚未冻结，未实施或部署。
- [2026-10-05跨平台DNS开箱即用与查询阶段效果](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-05-跨平台dns开箱即用与查询阶段效果)：
  用户明确各平台DNS过滤正常使用不要求手动配置，并要求具有早于业务IP连接的实质过滤效果。以[Portmaster的Linux实现](../reviews/2026-10-05_LINUX_PORTMASTER_DNS_REFERENCE_RESEARCH.md)及[VPP fork的DNS能力核对](../reviews/2026-10-05_VPP_DNS_CAPABILITY_REFERENCE.md)为基础，已认可VPP内一份DNS处理代码、Linux内核socket与VPN现有HEV会话分别接入的推进方向；解析／过滤／响应缓存／加密上游复用，详细行为与实施合同继续定义。
- [2026-10-05 VPN DNS阶段讨论（已暂停）](../reviews/2026-10-05_VPN_DNS_BEHAVIOR_DISCUSSION.md)：
  保留原请求App归属未知时先允许解析、VPN内固定DNS服务地址等确认及兼容问题。用户最后纠正最终仍有缓存与加密上游、初期分步完成；该稿包含尚未修正的“纯过滤原DNS透传”推演，不能当作已确认架构。未更新正式合同或实施，本轮转入Linux研究。
- [2026-10-04 系统组件替换与iodé DNS参考研究](../reviews/2026-10-04_IODE_DNS_REFERENCE_ASSESSMENT.md)：
  用户明确源码修改后的KSU／Magisk整库挂载仍是系统组件替换，部署方案先记录并继续研究。两席已核查iodéOS、iodéSnort及相关组件，确认ROM内getaddrinfo同步判定、原resolver继续解析、daemon地址归因与App配置展示的分工；固定源码并区分ROM集成与普通Root设备模块适配，没有部署或改写已确认的VPN DNS路线。
- [2026-10-03标准／增强／自定义与后台守护场景](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-03-从标准防护与后台守护重新描述普通用户路径)：
  用户否定V4两案，随后大致确认首次授权、选择标准模式、后台守护，以及误伤时引导恢复并加例外的完整路径。标准是大多数用户的常用模式；标准／增强由产品维护，自定义／高级提供完整编写能力，默认任务与界面相应分层。具体名单、切换、第三种名称及排查步骤仍待讨论。
- [2026-10-03 Android标准模式DNS与域名过滤讨论](../reviews/2026-10-03_ANDROID_STANDARD_DNS_DISCUSSION.md)：
  接在已确认的普通使用方向之后，核查系统hook、Root解析事件、VPN明文DNS、53／5353、SNI及IP映射的不同作用。用户随后确认系统hook在libnetd，明确VPN DNS接管、记录过滤后转加密上游，并撤下Android资源开关；前文的可选建议及资源讨论保留为阶段记录。[平台接口证据](../reviews/2026-10-03_ANDROID_DNS_PLATFORM_RESEARCH.md)不等同于产品集成或设备验收。
- [2026-10-03 VPN DNS查询、缓存与上游](../reviews/2026-10-03_VPN_DNS_RELAY_DISCUSSION.md)：
  该阶段按用户明确的TUN查询入口、过滤、加密转发及常见外部加密DNS服务拦截继续推演；产品自身上游收窄为DoT／DoH，已排除DoQ。阻断推荐现以10-08确认的自有解析功能先完成、再由用户自行开启为准。响应缓存、应用归属、上游自身通路与失败处理继续细化。[轻量DNS客户端候选](../reviews/2026-10-03_VPN_DNS_CLIENT_LIBRARY_RESEARCH.md)区分发布版能力和未合入开发，尚未选库或实施。
- [2026-10-03 DNS库资源与libnetd／KernelSU专项研究](../reviews/2026-10-03_DNS_CLIENT_AND_SYSTEM_HOOK_ASSESSMENT.md)：
  按用户要求以资源占用、缓存及现有架构接入为先，并排除新增Rust运行时；[库报告](../reviews/2026-10-03_DNS_CLIENT_RESOURCE_INTEGRATION_RESEARCH.md)核查原C owner／reactor接入与真实缓存／传输缺口，明确getdns／libcurl等现成组件存在。[系统hook报告](../reviews/2026-10-03_LIBNETD_KSU_HOOK_RESEARCH.md)核查APEX／netd加载、同步callback、KSU阶段与启动失败恢复边界；用户接受App正常启动并就绪后才开始拦截，不要求此前所有请求受控。研究建议不等于已选库或模块部署。
- [2026-10-03 HEV DNS复用与c-ares集中改造](../reviews/2026-10-03_HEV_DNS_REUSE_AND_CARES_FORK_RESEARCH.md)：
  用户进一步要求少集成库、优先复用现有HEV，并已确认HEV原owner＋小型DNS模块＋同Mbed TLS补全＋c-ares有限报文／缓存改造的路线。此前c-ares＋TLS＋libcurl组合降为比较项；专项研究区分HEV现有I/O／会话基础、Fake-IP映射、系统名字解析，以及完整DNS缓存与加密上游真正需要补的职责。
- [2026-10-03 libnetd hook入口、晚挂与生命周期讨论](../reviews/2026-10-03_LIBNETD_HOOK_DESIGN_DISCUSSION.md)：
  DNS路线确认后转入系统hook：原系统许可后只做本地DNS判断，允许时继续系统resolver／缓存，App后台防护就绪后才启用。[晚安装接点研究](../reviews/2026-10-03_LIBNETD_LATE_HOOK_OPTIONS.md)区分晚开启与真正晚挂，说明没有公开setter、初始化重入不可当热更新，以及实际进程适配／失联回退的待验证边界。
- [2026-10-03 Xposed／LSPosed DNS hook候选](../reviews/2026-10-03_XPOSED_DNS_HOOK_OPTIONS.md)：
  用户希望减少不同Android系统／ROM的反编译和整库修改；可研究scope内App的Java解析入口，并补已验证的公共native入口。此路通常免APK／resolver改写，但不自动hook独立netd，system_server单点也不覆盖全部App；作用域、框架版本和Android16兼容尚未验证，没有替换已确认的VPN DNS路线。
- [交互原型 V4：改变结果／共用与差异](../../app/design/prototypes/2026-09-29-interaction-directions/v4/README.md)：
  **用户已否定两案，保留为探索记录。** 此前按要求提供两种规则Tab主操作及共有的情况核对工具，用同一内存状态比较误伤、优先级、共同更新、恢复当前来源、条件变化及应用往返；[交付记录](../reviews/2026-10-03_UI_PROTOTYPE_V4.md)保留制作与走查事实，不再作为待选主方案。
- [NETWORK_CONTROL_PRODUCT_VISION.md](NETWORK_CONTROL_PRODUCT_VISION.md)：2026-09-29产品愿景与[2026-10-01用户确认的交互基线及主导航](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-01-用户确认的交互基线)。
  当前三个Tab为首页、规则、设置，其他Tab后续讨论。用户补充应用组：规则或规则组可用于单个应用或应用组，成员变化、重叠及例外逻辑继续决定。应用以已有流为重点，默认显示取得的域名，无名称才显示IP，来源及拦截详情按需深入；控制覆盖域名及非域名规则。后端等价功能按既定设计前提处理，二次开发后续讨论。
  [本轮期望](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-01-从用户期望继续决定逻辑)：应用列表中的按网络条件快速联网设置，单条规则与应用／应用组的双向快速关联；Wi-Fi名称与信任程度的情景模式继续探索。只将用户明确确认的内容作为正式决定，代理提案保留为建议，整体逻辑尚未定稿。
  [2026-10-02确认](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-应用内修改与专属共用规则)：单个应用内修改只作用于它，随后才选择共用；应用专属、多个应用共用及应用组共用规则并存，两种操作起点不互斥。跨多个应用的规则或规则组，其共同内容须多走一步到规则Tab修改，不能在单个应用界面内修改；跳转后明确显示当前规则所作用的应用组和应用。
  [规则Tab当前主线](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-规则tab主视角与应用视角)：先以规则内容为主，并继续辩论其工作逻辑和代价；同Tab应用视角仅为后续可提供选项，现在无需决定，也非本轮主线。
  [用户接受的品味方向](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-接受规则tab的品味方向)：实际规则内容主位、同一内容直接操作、完成结果清楚；连续编写及整套工作不因每次保存强制退出编辑。具体布局与其他未决语义继续细化。
  [规则执行效果与组嵌套](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-规则执行效果与规则组嵌套)：用户接受应用与规则两端查看实际效果，区分规则组整体与成员规则结果，计数保留范围、单位和真实执行含义；组嵌套不超过三层。具体深入与返回路径继续辩论。
  [规则组公共条件与设计依据](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-规则组公共条件与设计依据)：用户确认组可以有公共条件，并提出编辑快捷方式的候选想法；持续组约束还是当前成员编辑尚未决定。当前后端实现不限制产品体验，需要时可以修改后端；乔布斯式品味持续反问所有决定。
  [从联网决定重思交互概念](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-从联网决定重思交互概念)：用户要求根本重思允许／禁止、任意条件组合与共同内容下个别调整的完整体验；应用本身也可以是条件，不从现有规则／组／名单类型预定操作结构。用户随后提醒规则具有优先级，最终处理必须保留匹配后的胜出关系，不能默认局部更具体便获胜。替代概念仍在研究。
  [从用户层表达方式重新开题](NETWORK_CONTROL_PRODUCT_VISION.md#用户进一步明确从用户层的表达方式重新开题)：用户要求三至四席从乔布斯设计实践独立探索核心交互概念，允许完全跳出规则思维，图形只是候选。重点是用户自然理解、表达和修改复杂控制，后端规则仅为最终承载；最终收敛至一两种主方案，必要时加半种补充，不要求唯一冠军。
- [2026-10-02核心交互的两种候选：范围表达与判断路线](../reviews/2026-10-02_INTERACTION_CORE_DIRECTIONS.md)：
  **2026-10-03用户已否定两案**，认为仍在拼凑功能、缺少所要求的乔布斯式品味；以下为探索过程，不再作为当前推荐或实施依据，见[反馈记录](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-03-用户否定两个核心交互候选)。
  四个全新设计席先独立，再完成八项真实主问及两项追问。承认四份选区稿属于同一家族，撤回照片隐喻和对图的过早淘汰；提出可直接修改的内容与可编辑判断路线，用相同复杂条件、优先、误伤和复用工作比较。应用×网络格仅作有条件的半种快捷补充；没有宣布唯一优胜或批准新模型，含具体操作草图。
- [2026-10-03相近论文与应用：已有控制交互思路](../reviews/2026-10-03_CONTROL_RESEARCH_SYNTHESIS.md)：
  按用户要求由四个GPT-6.1-sol研究席调查策略HCI、网络控制产品、终端用户表达、例子与渐进定义。汇总目标结果输入、有效政策操作、行为差异比较、请求推广与共同默认／局部差异；记录实验反证、产品语义和适用缺口。属于研究输入，不是新候选评选，也不恢复已否定两案。
  用户随后仍认为没有到点。补查[Figma](../reviews/2026-10-03_CONTROL_RESEARCH_SHARED_OBJECTS.md)与[Photoshop](../reviews/2026-10-03_CONTROL_RESEARCH_DIRECT_OBJECTS.md)检验可操作作品及共同／局部关系的类比，保留不适用边界；尚未找到用户认可的key。
- [2026-10-02公共条件与编辑捷径的品味辩论](../reviews/2026-10-02_GROUP_CONDITION_JOBS_DEBATE.md)：
  两席实际比较持续组约束与明确修改当前成员的快捷操作，承认它们改变不同对象；主代理有前提推荐持续条件，以保留组外共享内容，同时保留快捷编辑的独立价值。撤回未来继承已是需求、警告等于完成及必须分两次保存的假设；具体语义尚未确认。
- [2026-10-02规则与规则组执行效果品味取舍](../reviews/2026-10-02_RULE_EFFECTS_JOBS_DEBATE.md)：
  两席gpt-6-astra／low／priority（fast）实际互问后，建议效果接在原成员内容旁、数字直达对应活动；区分组内历史、规则全部效果和当前共同编辑影响，保持往返范围，具体说明三层上限反馈。删掉独立效果模式与重复成员榜；这些新交互仍为建议。
- [规则创建交互文字稿](RULE_CREATION_INTERACTION_DRAFT.md)：
  用户接受新建规则主流程后整理，逐步写明名单与UDP两案中看到的内容、实际操作和完成结果，覆盖保存待用、改错、复杂情况组合及连续工作。确认范围见[产品基线](NETWORK_CONTROL_PRODUCT_VISION.md#2026-10-02-接受新建规则主流程)，示例文案与控件形式继续细化。
- [2026-10-02从零创建规则的品味推演](../reviews/2026-10-02_RULE_CREATION_JOBS_WALKTHROUGH.md)：
  两个gpt-6-astra／low／priority（fast）席独立推演名单与UDP两案并实际互问；从可认动作起步，同一内容直接选择、限定网络、明确使用并完成，保留待用、改错及OR扩展。用户随后接受总结中的主流程并要求文字稿，范围见上项；其余案例细节保留为讨论，未触发条件性的第三席或改动原型。
- [2026-10-02 A/B重开与Jobs品味裁决](../reviews/2026-10-02_RULES_AB_REOPEN.md)：
  两个全新gpt-6.1-sol／high／priority（fast）席独立判断并实际互问；用户明确以Jobs品味作最终裁决。主代理撤回缺少真实差异的A/B二选一，选择实际规则内容主位、管理事实按需深入、同一内容直接操作与自然收尾；对保存后强制重进编辑作限定。用户随后接受总结中的设计方向，范围见上项；其他案例细节仍为建议，未改原型。
- [2026-10-02规则主线重新辩论：默认组织取舍](../reviews/2026-10-02_RULES_MAIN_REDEBATE.md)：
  内容库、完整工作台、用途规则组三个强版本用同样工作实际竞争；主代理建议默认先认保存内容及使用状态，已知规则直达完整编辑、整套任务保持组。保留作者和目的优先的优势及改选条件；这是新建议，未批准默认界面或共享合同。
- [2026-10-02规则主线辩论与主代理判断](../reviews/2026-10-02_RULES_MAIN_DEBATE.md)：
  同三席先读新的一手材料再实际互问，批评规则主线的作者门槛及库类比限度；收准即时采用、独立待用、继续整套三种完成，单条及规则组均可从零开始。保留完整条件工作台及用途组优先的强反案；具体组织仍为建议，应用第二视角暂缓。
- [2026-10-02规则Tab的Jobs灵感探索](../reviews/2026-10-02_RULES_TAB_JOBS_IDEAS.md)：
  用户要求暂不绝对化单App调整细节，转向整体思路。主代理借早期iTunes的库与组合关系，提出内容库、直接可发现的创作及同一内容深入／实际核对；附用户随后明确的规则主线和应用视角暂缓决定，具体提案仍为建议。
- [2026-10-02共同修改继续互辩与主代理取舍](../reviews/2026-10-02_SHARED_EDIT_BOUNDARY_DEBATE.md)：
  同三席实际互问，吸收跳转后的作用对象呈现确认；收准单条／整套进入、单项保存与连续维护、明确转换未完成工作。主代理支持共同编辑边界，反对局部调整默认复制整组；具体连续任务及局部内容语义仍为建议，未改原型。
- [2026-10-02对用户反馈的再辩与主代理意见](../reviews/2026-10-02_JOBS_FEEDBACK_DEBATE.md)：
  同三席先独立批评默认单应用修改及两种起点并存，再实际互问；主代理支持两点，首选持续共用同一内容、个人内容明确独立、共同任务直接进入准确规则对象。附用户随后确认的跨应用规则／规则组修改入口边界；持续共用等其余取舍仍为建议，保留长期个人差异的维护成本，未改原型。
- [2026-10-02乔布斯品味与整体用户操作逻辑互辩](../reviews/2026-10-02_JOBS_OPERATION_LOGIC_DEBATE.md)：
  三个全新gpt-6.1-sol／xhigh席分别从品味、交互、整体组合审视完整路线，实际互问后回看应用快设、已有流、精确决定、双向使用、共同维护与核对返回。附单应用范围及专属／共用并存的后续用户确认，其他选择继续讨论；未改原型。
- [2026-10-01访问意图辩论综合](../reviews/2026-10-01_ACCESS_INTENT_DEBATE.md)：
  五席交叉问答的阶段记录，附后续四项确认及应用主位修正；首次推荐、可选名单、能力变化、预设及专业深入仍为[设计建议](../reviews/2026-10-01_ACCESS_DESIGN_VERDICT.md)，平台事实见[研究](../reviews/2026-10-01_ACCESS_PLATFORM_RESEARCH.md)。V3尚未落实本轮变化。
- [交互原型 V3](../../app/design/prototypes/2026-09-29-interaction-directions/v3/README.md)：
  上轮体验裁决的可交互参考，保留V2首页与应用逻辑，落实长期联网规则、临时修改及上下文实际记录；覆盖Android手机/竖横平板与Linux桌面/触控/小窗口；附[三席答辩与收口](../reviews/2026-10-01_UI_PROTOTYPE_V3.md)。全部为前端样例；本轮访问意图变化见前项。
- [2026-10-01体验重思裁决](../reviews/2026-10-01_EXPERIENCE_DESIGN_VERDICT.md)：
  保留首页与应用内部逻辑，从完整使用推导我的网络、联网规则及实际记录动作；替代三抽象目的分箱，附长期维护、共享范围、健康Debug和真实反驳。仍为设计工作稿。
- [交互决策逻辑与取舍临时汇总](../reviews/2026-09-30_UI_INTERACTION_DECISIONS_TMP.md)：
  汇总首页授权裁定、各任务的当前首选、选择理由、承担代价、平台适配及保留异议；临时工作稿，不代表正式规格或实现完成。
- [联网决定的交互结构与品味取舍](../reviews/2026-09-30_NETWORK_DECISION_INTERACTION_DEBATE.md)：
  上一轮重审独立控制线，以网络、编写、深入检查组织能力；整体结构已由2026-10-01体验裁决续审替代，本文保留过程；附健康Debug、大量编写、整体兼容、等价反案、API边界与已核对参考板，当前产品原型未改版。
- [UNIFIED_RULE_ENGINE_SPEC.md](UNIFIED_RULE_ENGINE_SPEC.md)：2026-09-24 已确认的统一规则后端、
  VPP 在线配置管理与常态观测规格；取代旧计划中冲突的规则分阶段优先级、保存职责和观测存储口径。
  这是待实现的产品设计，具体 UI 与 debug 交互仍后置，Plane 管理工作与验收状态。
  已发布规格：[SAKAMOTO-251](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/28bb5f21-f21c-4018-a3c6-60a5dbfdb82e)。
- `ANDROID_L4_PRODUCT_PLAN.md`：Android L4 产品版、后续 libprotoident 阶段、UI 归属、
  信息架构、内容建设和发布完成标准。
- [2026-09-29 UI 原型审视与设计推进讨论](../reviews/2026-09-29_UI_PROTOTYPE_DESIGN_REVIEW.md)：
  旧原型的问题优先级、与当前功能的初步对应及设计推进建议；属于讨论记录，非最终 UI 规格。
- [2026-09-29 当前功能与旧 UI 原型对应清单](../reviews/2026-09-29_UI_FUNCTIONAL_INVENTORY.md)：
  按用户任务核对当前能力、已有入口、旧原型与双端差异；记录 checkpoint 首版暂缓，
  预演/debug/地图保留设计，以及 Android/Linux 共同设计方向。
- [2026-09-29 网络透视研究综合](../reviews/2026-09-29_NETWORK_VISIBILITY_RESEARCH_SYNTHESIS.md)：
  六款竞品、公开用户问题与认知研究，讨论应用中心如何连接设备整体变化；包含分报告和待验证的交互假设，非已确认 UI 规格。
- [2026-09-29 网络透视与直觉设计指导](../reviews/2026-09-29_NETWORK_VISIBILITY_DESIGN_GUIDANCE.md)：
  调研与乔布斯设计原则经过子代理互问后的收敛建议，明确首屏、观察范围、深入与反馈的取舍，供下一轮原型验证。
- [2026-09-29 完整原型设计评审](../reviews/2026-09-29_JOBS_FULL_PRODUCT_REVIEW.md)：
  先读乔布斯一手材料，再独立审视 46 个产品页面；附实际覆盖、截图证据及八项优先修整建议，属于评审意见，非已确认改版规格。
- [决定与结果 · 阶段四交互稿](../../app/design/prototypes/2026-09-29-interaction-directions/app-first/README.md)：
  用户授权落实八项评审后的可操作原型，包含订阅维护、行为差异审阅及定向复审的收口；附浏览器验证，仍为前端样例。
- [2026-09-30 功能组织与乔布斯设计研究辩论](../reviews/2026-09-30_JOBS_DESIGN_DEBATE.md)：
  三组先读一手材料，再实际观察与交换反方案；审查同页组合、作用范围和决定回路，保留实际改判、证据与未决选择，不预设功能完整。
- [2026-09-30 独立功能组织参考](../reviews/2026-09-30_JOBS_INDEPENDENT_DESIGN_REFERENCE.md)：
  先于现有页面提出的任务结构，经三组质询收窄；含功能归宿、两条逐屏情境和双平台取舍，属于参考方案，尚未改版或确认规格。
- [2026-09-30 第二轮品味辩论与取舍](../reviews/2026-09-30_JOBS_TASTE_DECISIONS_V2.md)：
  继续互相反驳并作明确形态选择；用户指定设计席裁定首页，保留反方意见和承担的代价，仍为参考。
- [功能组织与首屏设计参考 V2](../reviews/2026-09-30_JOBS_DESIGN_REFERENCE_V2.md)：
  时间变化与同段应用贡献、连续应用画布、名单日常与更新审阅的具体构图；含可切换场景参考板，当前产品原型未改版。
- [V2 平板与 Linux 构图补充](../reviews/2026-09-30_V2_TABLET_LINUX_REFERENCE.md)：
  Android 平板竖/横屏、Linux 桌面/触控竖屏/小窗口，五窗口各四视图；保留平台身份、并排关系及有限交互，原手机入口可切换。
- `ANDROID_L4_RELEASE_GATE.md`：SAKAMOTO-59 Android L4 Product Release Gate 的证据、
  预算、双语用户材料、隐私、已知限制、反馈入口和关单 checklist。
- `ANDROID_L4_RELEASE_NOTES_DRAFT.md`：SAKAMOTO-59 的仓库内 release notes 草案；
  final signed APK evidence 完成前不代表公开发布。

## UI 资料与实现归属

当前规划采用同仓库产品层，避免 UI、Rust 产品控制面和 VPP 数据面分别漂移：

- `docs/product/` 保存产品定位、用户流程、低保真线框、文案、帮助和发布标准；
- 未来顶层 `app/` 保存 Tauri UI、Rust 产品控制面、设计 tokens、可运行原型和 UI 测试；
- VPP plugin、Packet Capture Adapter 和 Android platform bridge 不拥有产品 UI；
- 外部设计工具可以辅助讨论，但不能成为唯一真相；关键流程、状态和文案必须回到仓库。

UI 实现尚未开始前，不在 `experiments/` 或 VPP plugin 目录散落临时产品页面。2026-09-29
用户确认以 mock product state 驱动的可交互 HTML 原型先完成本轮功能设计，同时覆盖 Android
与 Linux；以聚焦、直觉、精确、克制和完成度持续评审，原型确认后再接真实 Tauri/VPP Adapter。
