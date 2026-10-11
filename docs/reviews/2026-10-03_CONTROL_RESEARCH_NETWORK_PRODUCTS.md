# 终端网络控制产品：用户工作的对象、例外与维护

2026-10-03。研究对象为 Little Snitch 6（macOS）、LuLu、Portmaster、NetGuard、RethinkDNS，以及作为不同控制理念对照的 uBlock Origin。本文是来源阅读与界面资料分析，**没有安装运行这些产品，没有测量用户完成率、误操作率或学习成本**。官方功能、作者解释、源码语义与本文推论分别标明。未修改 Sakamoto 原型；本文不确认新的界面方案，也不替“范围表达编辑器”“判断路线图”背书。

## 最值得保留的三条证据

1. **uBO把“先试能否恢复工作，再决定长期保留”写进操作本身。** 动态修改默认临时，明确持久化后才留下；局部解除动态限制仍可保留静态名单。它有真实的作者教程故事，不只是一个抽象“例外”字段。此理念可研究，浏览器控制维度不能直接移植成终端防火墙能力。[官方快速指南](https://github.com/gorhill/uBlock/wiki/Dynamic-filtering:-quick-guide)
2. **Portmaster把共同行为作为仍然有效的默认值，应用修改可以是补充。** 源码先查询应用规则，未作决定才查询全局规则；删除局部差异可以重新遵循共同内容，不必复制全套。然而强制封禁属于更前面的检查，普通 allow 不能解除它。这比“应用页+规则表”更有实质内容。[规则分层源码](https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/profile-layered.go#L330)、[执行阶段](https://docs.safing.io/portmaster/architecture/core-service/privacy-filter/)
3. **Little Snitch把留下来的控制也当成需要维护的东西。** Insights可找重复、无必要的高优先级与久未使用规则；到期规则还能保留为建议模板。它不是靠不断新增条件完成整个生命周期。[Insights](https://help.obdev.at/littlesnitch6/lsc-insights)

这些是已存在产品里的具体思想，尚不构成“Sakamoto应当采用哪种用户层组织”的答案。

## 选择与相似度

筛选依据是有不同的工作起点、冲突契约或维护方法，不按支持字段数量排名。

| 产品 | 人首先面对什么 | 独立思想 | 对本题的相似度与缺口 |
| --- | --- | --- | --- |
| Little Snitch 6 | 正在发生的连接、应用及其域名，再到规则 | 观察层级可直接形成控制；主题组；维护建议 | 高：应用、端点、协议端口组合与冲突俱在；优先级主要由产品比较算法决定 |
| LuLu | 未获授权程序第一次尝试联网 | 程序信任、已安装程序基线；之后再细化 | 中：粗授权很明确；名单误伤不能用普通应用 allow 修复 |
| Portmaster | 应用的网络活动、继承的隐私设置 | 全局默认持续有效，应用局部差异 | 高：共享默认与局部例外接近；不是任意命名规则组分配给指定应用组的完整范例 |
| NetGuard | 每个应用在 Wi-Fi/移动网络的接入状态 | 以自动条件减少手动配置切换 | 中：日常动作简单而明确；删减了本题必需的表达力 |
| RethinkDNS | 应用、连接日志、Universal 与应用专属控制 | 改默认信任姿态；从被阻止连接回到责任对象 | 高：局部域名/IP规则与全局规则并存；多种绕过姿态的边界复杂 |
| uBlock Origin | 当前网页实际请求的第三方资源 | 默认临时试验；局部撤销某层控制，保留其他层 | 控制工作相似，技术对象不同：无终端 App UID、TCP/UDP端口控制 |

下文的“工作流程”是按文档还原的动作序列，不是亲自运行所得。

## Little Snitch：从实际连接形成决定，再维护决定

在 Alert Mode，未被规则覆盖的连接停下来询问。回答时可以选择持续时间、当前 profile 或所有 profiles、主机或域名等匹配范围；后续同类连接由已生成规则处理。在 Silent Mode，不弹出询问，由该模式的默认 allow/deny 处理未覆盖连接。[连接提示](https://help.obdev.at/littlesnitch6/alert-overview)、[运行模式](https://help.obdev.at/littlesnitch6/concepts-opmodes)

官方入门建议还有明确的完整故事：先silent allow收集Mail活动，允许所需邮件服务器，再禁止Mail的其他连接以限制邮件图片追踪，最后切回Alert Mode处理以后新出现的访问。这把“确定实际需要的通路”放在全面收紧之前；是建立政策的一段工作，不只是多一种弹窗模式。[官方Mail教程](https://help.obdev.at/littlesnitch6/concepts-opmodes)

另一条完整路径是在 Network Monitor 中先展开应用及端点，点击该层级的 allow/deny 控件。规则覆盖的是该行代表的连接集合；该行不是一个孤立数据包。误伤时回到活动，找对应规则或最近使用的规则，再调整。需要特别注意：灰色按钮表示现有控制覆盖更多或只覆盖部分，而不是“这里没有控制”。这是把实际观察与控制边界联在一起的思想；不能把一个好看的应用列表等同于此契约。[Network Monitor 中的规则操作](https://help.obdev.at/littlesnitch6/lsm-managing-rules)

冲突主要由内建的具体性顺序决定：高 Priority先胜，再比较端点类型/范围、端口、协议、进程等，后续才比较 deny/allow。**“更具体”不是单纯条件数量更多，也不是应用专属永远优先。** 例如端点类型比较先于进程比较。手册建议少用高优先级。本题若要求用户明确管理任意优先次序，不能把它冒充相同能力。[规则与比较顺序](https://help.obdev.at/littlesnitch6/concepts-rules)

本地规则组按主题开关，可同时开多个；profile至多激活一个，同时保留没有指定profile的规则，且可随网络自动切换。远程组是另一种“共享”：发布者持续维护，各机器订阅更新；可先停用审阅，新增 allow 可另作审阅处理。**主题组、网络情境与跨设备订阅是三种关系，不能混成“共用组”。**[管理规则组](https://help.obdev.at/littlesnitch6/lsc-rulegroups)、[profiles](https://help.obdev.at/littlesnitch6/concepts-profiles)

以后查找与维护有实质信息：Inspector记录使用次数、最近使用、来源与重复关系；Insights单列失效、冗余、久未使用等项。本文推论：创建动作与清理动作是不同任务；“能搜规则”不足以替代“找出现在应维护的决定”。[Inspector](https://help.obdev.at/littlesnitch6/lsc-inspector)、[Insights](https://help.obdev.at/littlesnitch6/lsc-insights)

**界面核对：**实际查看了官方[规则编辑截图](https://help.obdev.at/littlesnitch6/images/lsc-edit-rule%402x.png)。它仍是进程、action、direction、endpoint、protocol/port、profile/group表单；不能把渐进显示字段本身当成新的产品思想。更有价值的证据在观察到规则的范围契约及长期维护。

## LuLu：以新程序授权为中心，细规则是之后的工作

首次配置推荐允许Apple程序与已安装程序，重点拦住未经授权的新出站连接。提示的默认回答为整个程序建立长期allow/block；展开后可改为当前remote endpoint，或仅进程生命周期/一段时间。以后在按程序展开的Rules窗口查找、编辑；签名身份让程序移动或更新后仍能识别。[官方手册](https://objective-see.org/products/lulu.html)

普通规则源码区分地址+端口精确命中、只指定其一的部分命中、任意端点命中，再选择对应规则；本文未从这段代码得出一个用户可以拖动的任意排序模型，也不把同级重叠情况下的内部遍历行为美化成清楚的交互契约。[Rules.m，读取提交7d2669e](https://github.com/objective-see/LuLu/blob/7d2669ed32e5b195d5863dc9695441d3301ba7b0/LuLu/Extension/Rules.m#L818)

最强限制来自名单：allow/block名单超越普通规则，名单冲突由block名单获胜。若共享名单误伤应用A，增加A的普通allow不保证能恢复；全局allow名单也不是A专属例外。profiles则是互相独立的规则与设置，切换后只用当前那套。本文推论：这适合不同信任基线，但不能证明解决“同一共同内容供A/B/C持续维护，A只局部不同”。[名单与profiles说明](https://objective-see.org/products/lulu.html)

**界面核对：**实际查看[展开的提示](https://objective-see.org/images/LL/alert_3.png)与[规则窗口](https://objective-see.org/images/LL/rulesWindow.png)。前者保留醒目的程序和目的地、两种决定，将scope/duration放在展开区；后者是程序树与其端点条目。值得研究的是“先回答这个新程序可信不可信”的工作起点，不是照搬它的表格或所有身份信息。

## Portmaster：共同默认持续存在，应用只保存差异

官方设置区分Global、Per App以及Stackable。Per App具有全局默认；Stackable应用设置补充全局而非替换。Default Network Action是所有检查都未决定后的最后动作，手册默认allow，也可block/prompt。工作流程因此可以是：先选择共同隐私名单与默认行为；查看某应用活动；在该应用加入少量规则或修改一个设置；以后继续修全局内容，应用未覆盖的部分仍跟随。[Settings Handbook](https://docs.safing.io/portmaster/settings)

关键语义由源码支持：`MatchEndpoint`先遍历应用配置层，得到决定即返回，最后才匹配全局endpoint规则；布尔等设置则取第一层显式值，否则取全局。**列表补充与单值覆盖是两种维护关系，不能因为都叫“应用设置”就当成整套复制。**[profile-layered.go，读取提交13a86a4](https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/profile/profile-layered.go#L330)

规则内可以组合地址/域名与protocol/port，按从上到下第一个命中；应用身份由外层应用配置确定。更前面仍有force block类型/范围检查，然后才进入自定义规则，再进入过滤名单。误伤名单时可加入应用精确allow；若被强制禁止Internet或连接类型拦住，应修该应用相应设置，继续加allow无效。[执行阶段文档](https://docs.safing.io/portmaster/architecture/core-service/privacy-filter/)、[当前阶段顺序源码](https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/master.go#L30)

本文推论：真正可迁移的是“共同默认不会因一次局部修复被拆成多份”，以及“恢复继承”与“允许端点”不能混为一谈。限制：global影响所有相关应用，不等同于只把同一命名控制对象持续分配给任意A/B/C；上述资料没有证明任意布尔表达和用户自由总排序。旧官方文档正在迁移，本文用当前development源码核对了关键语义，源码行为不冒充最新稳定版实测。

**界面证据边界：**本项阅读官方设置/执行文档及源码，没有完成当前稳定版应用截图核对；不据营销图断言“继承很容易被看懂”。

## NetGuard：把“此应用何时接入哪种网络”作为主要工作

用户先开启防火墙，直接点应用旁Wi-Fi/移动图标。Defaults选择总体黑名单或白名单姿态；应用展开后可设置亮屏允许、漫游阻止等自动条件。作者明确拒绝profiles，理由是手动操作不如自动条件方便；这是作者主张，不是用户研究结论。[FAQ 0、33](https://github.com/M66B/NetGuard/blob/master/FAQ.md#faq33)

进一步细化需流量过滤/记录，在应用访问记录中调整单个地址；PRO提供应用专属地址allow/block。以后仍按应用维护。它刻意不提供地址/端口范围、通配符等更通用规则，不能借其较少的主控图标证明本题全能力也可以得到相同复杂度。[README](https://github.com/M66B/NetGuard)、[FAQ 41](https://github.com/M66B/NetGuard/blob/master/FAQ.md#faq41)

共享hosts名单的流程是安装支持版本、开启过滤和域名阻止、导入或下载名单；名单不能在应用中编辑，而且**不能对单个App豁免这种广告阻止**。因此“A受共享名单误伤，但B/C保持”正是它的明确缺口，不应写成已经解决。DNS加密等也使它看不到所需域名查询。[官方ADBLOCKING说明](https://github.com/M66B/NetGuard/blob/master/ADBLOCKING.md)

**界面核对：**查看了仓库[主列表截图](https://raw.githubusercontent.com/M66B/NetGuard/master/screenshots/01-main.png)及[访问记录截图](https://raw.githubusercontent.com/M66B/NetGuard/master/screenshots/03-main-access.png)。前者以App和网络图标承接最常见工作，后者显示端点、端口与allow/block结果；访问截图是独立页面，不能误写成已看到App内嵌展开操作。可研究其日常动作与深层细化的分工，不能直接迁移其表达力取舍。

## RethinkDNS：局部端点例外与改变默认姿态并存

官方文档将应用接入、域名DNS阻止与连接日志联系起来：整应用阻止适合无需联网的工具，通信App则可以继续使用而只阻止已知跟踪端点。支持按应用查连接及被阻止原因，再设置专属domain或IP/port规则。[产品说明](https://rethinkdns.com/app)、[Firewall文档](https://docs.rethinkdns.com/firewall/)

源码提供真实的返回路径文字，例如“this IP for this app”、专属Trusted Domain、全局Trusted Domain，并给出应回哪个对象修改。它让一次连接的处理结果与存储决定的地方连起来。本文未验证每条文案在最新安装版中是否都一致、跳转是否完整，也未据此推断易用性。[界面文案源码](https://github.com/celzero/rethink-app/blob/3d92d38268d6e1a76b4a6e9c4f6b4c6428b2721f/app/src/main/res/values/strings.xml#L394)

Isolate把该App变为只允许专属信任端点的姿态；这不是“整体block后给allow排序”同一种操作。当前`TunFirewallManager`先检查应用接入阻止，再专属domain/IP，再isolate和其他全局规则。因此专属信任可解决后续全局域名阻止，却不能自动穿越前面的应用封禁。[作者确认Isolate含义](https://github.com/celzero/rethink-app/discussions/1806)、[执行源码，读取提交3d92d38](https://github.com/celzero/rethink-app/blob/3d92d38268d6e1a76b4a6e9c4f6b4c6428b2721f/app/src/main/java/com/celzero/bravedns/service/TunFirewallManager.kt#L135)

绕过不能笼统解释为allow：作者2026-06说明Exclude使应用离开VPN隧道，Rethink看不到流量；Bypass Universal与Bypass DNS+Firewall涵盖不同控制。当前源码仍保留专属端点检查，并在Bypass Universal检查DNS名单阻止。**2025讨论、2026解释与当前源码之间存在措辞/版本差异**，本文以源码说明已读快照，不冻结所有绕过选项的稳定版合同。[作者答复](https://github.com/celzero/rethink-app/discussions/2542)、[当前源码](https://github.com/celzero/rethink-app/blob/3d92d38268d6e1a76b4a6e9c4f6b4c6428b2721f/app/src/main/java/com/celzero/bravedns/service/TunFirewallManager.kt#L214)

本文推论：改变默认姿态能帮助人表达“这个App只做我准许的连接”，但绕过开关过宽，不能替代一次精确误伤修复。没有证据证明它支持本题任意App集合×命名域名名单×协议端口的持续共享编辑。

**界面证据边界：**读了作者FOSDEM 2026演讲PDF，未能通过截图接口取得页面；因此本项不声称完成截图视觉核对。上述文案分析来自实际阅读的源码。[作者演讲资料](https://fosdem.org/2026/events/attachments/NPGR8K-boring_filter_the_anatomy_of_a_network_sandbox_for_android/slides/266960/boring_fi_znwu8rk.pdf)

## uBO：误伤恢复是一段可撤销的试验，而不是立即留下更多长期allow

官方教程给出完整例子：全局阻止第三方iframe；当前文章中的YouTube视频不能播；若给整个当前站第三方iframe做noop，会恢复过多内容；改为只给本站的youtube.com（例中还需要google.com）做noop。**noop只停止动态过滤在这里作决定，静态名单继续有效。** 与此不同，allow可以越过静态阻止，教程要求谨慎使用。[官方快速指南](https://github.com/gorhill/uBlock/wiki/Dynamic-filtering:-quick-guide)

局部规则优于全局；同层更具体覆盖更宽的动态规则。所有动态修改默认临时，用户明确持久化才能留下；可在My rules对比临时与永久并编辑。这改变了误伤调查到长期维护的关系，避免每次尝试都自动变成永久政策。教程描述“防止规则污染”是作者设计理由，本文没有把它当成测得的维护成本下降。[动态规则语法与noop定义](https://github.com/gorhill/uBlock/wiki/Dynamic-filtering:-rule-syntax)、[快速指南的临时/永久流程](https://github.com/gorhill/uBlock/wiki/Dynamic-filtering:-quick-guide)

**界面核对：**实际查看教程的[局部修改截图](https://user-images.githubusercontent.com/585534/87427192-68b69900-c5ae-11ea-9ffb-7ed5ff7bbc5b.png)与[My rules对照](https://user-images.githubusercontent.com/585534/87432792-72dc9580-c5b6-11ea-9898-039d9bfcaa5e.png)。矩阵与文本仍可能难学，独立思想在于上下文局部、层间保留和明确持久化；把二维表直接改名放进Sakamoto不自动继承这些价值。

强限制：uBO知道源网页与资源类型，这是终端流量中往往没有的语义；它不能替代App UID/协议端口控制，也不是本题任意组合通用编辑器。这是相近工作的方法对照，不是端点防火墙替代推荐。

## A/B/C共用内容，A误伤：同一故事逐项检查

为避免字母含义混淆，这里**A/B/C均指应用**，共用内容记为G。这个对照故事由本文构造，不是来源中的用户测试：三者共用域名阻止内容G，A的正常功能需要其中某域名d，B/C仍应阻止d；修复后G继续更新。

| 产品 | 有文档/源码根据的处理 | 剩余缺口 |
| --- | --- | --- |
| Little Snitch | 保留共同deny，给A到d建立足够高优先的特定allow；组和订阅仍存在 | 要按比较算法保证胜出；从共同名单停用d会扩大作用，不能冒充A例外 |
| LuLu | 若G是superseding blocklist，普通A allow不起作用 | 要更动名单或别的整体配置；没有已证据化的名单内A精确补洞 |
| Portmaster | 应用层精确allow在全局规则/过滤名单前得到决定；其余继续继承 | 若A被Force Block提前阻止，需先改那个设置；全局并非指定A/B/C的小组共享 |
| NetGuard | 应用地址规则可独立调整，但hosts广告名单明说不能对单App豁免 | 不能保证此故事局部修复；改共享hosts会波及B/C |
| RethinkDNS | A专属domain trust先于后续global domain block；仍保留共同规则 | 先前应用封禁仍胜；姿态与DNS名单要单独辨认，不能用大范围bypass替代精确修复 |
| uBO | 把A/B/C换成网页时，A源站到d局部规则可保留B/C及其他过滤层 | 浏览器有源站；终端App不能据此假定同等资源语义 |

表中是上文来源的受限推演。它揭示的不是哪个产品获胜，而是**“共享内容”“共同默认”“名单订阅”“主题开关”“配置副本”具有不同的持续维护合同**。

当G还含UDP/443等条件时，更不能据该表推断等价：Little Snitch/Portmaster可在endpoint规则中组合协议端口；LuLu的普通地址/端口规则与superseding名单分离；NetGuard主动削减范围/通配；Rethink专属domain与IP/port是不同对象；uBO资源类别不是网络协议。可表达的条件和共同修改的关系应分别核对。

## 哪些只是改进规则表，哪些改变了工作本身

表单渐进展开、按App树形显示、搜索排序、把规则放入有名称的组，都是有用手段；单独看时仍主要是规则呈现。它们不能回答“人为什么现在要做这件事”“局部恢复后留下什么”“几个月后的共同修正由谁维护”。

较独立的思想已有明确来源：LuLu选择新程序信任作为起点；NetGuard刻意以自动情境减少人工切换；Portmaster维持共同默认与局部差异；uBO把修复做成默认可撤销且分层保留的试验；Little Snitch保留创建到清理的生命周期。它们各自有真实取舍，不能合并成一个功能清单就声称找到了统一用户层key。

可迁移的具体研究对象因而是：一次误伤修复究竟应改变哪一份长期内容、局部差异能否随共同更新继续成立、试验何时变成承诺、以后能否找到已经无效或无必要的承诺。上述产品给了可检查的合同与反例，尚没有提供本题全约束下已验证易用的主组织方式。

## 证据强弱与本轮不能下的结论

- 最强证据：当前可定位的规则匹配代码、官方明确列出的限制、作者写明的完整误伤例子。它们证明语义/操作存在，不证明用户容易成功。
- 界面实读：Little Snitch编辑器、LuLu提示和规则窗口、NetGuard主列表与独立访问记录、uBO局部矩阵和临时/永久规则对照。只核对这些画面，未把所有官方截图均算作看过。
- 两个强反例尤其影响本题：**LuLu名单比普通规则强；NetGuard的hosts阻止不能单App豁免。** 因此“支持allow/deny、名单、应用”三项并存，不代表支持局部误伤修复。
- 全部产品均未在本轮证明：任意组合条件、指定多个应用持续共享命名内容、用户优先级、局部差异、长期维护能同时获得一个已验证易用的体验。不能宣布竞品已有完整答案，也不能把缺证据写成“这些产品都做不到”。
- 版本范围：Little Snitch 6 macOS手册；LuLu现行官网；Portmaster旧官方文档与development提交13a86a4；Rethink文档/作者答复与main提交3d92d38；NetGuard仓库文档；uBO官方wiki。源码快照不是已安装稳定版，历史截图不是本轮操作录像。

本轮产出是有来源的工作方法与边界。下一次判断候选理念时，最严的检验仍应使用同一个A/B/C误伤故事及日后G更新；不要通过舍弃任意组合或持续共用的要求来制造“简单”。
