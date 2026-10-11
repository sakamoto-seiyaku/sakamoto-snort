# 联网控制的用户层核心：已有思路、工作逻辑与证据

**后续用户反馈：本轮汇总仍未到点，用户仍不满意。** 下文保留已有工作的证据与限制；“值得深追”不代表已接近用户认可的核心概念。后续补查见本文的“研究单位反查”，没有产生新的已确认方案。

日期：2026-10-03。用户否定此前两个交互候选后，要求用GPT-6.1-sol子代理搜索相近论文与应用，汇总已有思路。本轮为定向研究，不是系统综述、新方案评选或产品决定。

四个GPT-6.1-sol研究席分别调查策略创作HCI、实际网络控制产品、终端用户逻辑表达、示例与渐进定义；主代理读完四份报告，并独立核查IAM、冲突语义实验、AuthzMap、SBAC及uBO关键材料。没有运行竞品或复现实验。
保留本题的困难：App只是条件之一；允许／禁止对等；任意条件组合、多规则优先、共同A/B/C控制与A局部调整、主动准备及长期维护。已有工作不覆盖的部分明确指出，不通过删减能力制造简单。
用户否定的范围表达与判断路线仍是被否定的阶段记录。本轮不因找到相似论文就恢复它们，也不宣布已经找到最终key。

## 先把已有思想分清

这批材料显示，改变用户工作的办法远不止改变规则的图形表示。下表是研究者按原始材料作的归纳，不是原论文共同提出的一套框架。

| 已有思路 | 用户主要决定什么 | 系统承担什么 | 代表证据 |
| --- | --- | --- | --- |
| 目标结果驱动 | 谁应当能／不能做什么 | 从当前状态推导配置改动、解释副作用 | IAM，SOUPS 2006 |
| 操作有效结果 | 某主体对某资源最终应有什么权限 | 合并规则、显示实际效果并实现修改 | Expandable Grids，CHI 2008／2011 |
| 比较行为变化 | 哪些情境中的结果应改变、哪些应保持 | 找出候选整体行为不同之处 | Program Differences，CHI 2021 |
| 具体请求形成持续决定 | 本次许可是否推广到今后同类请求 | 记录明确的推广范围 | Reactive Access Control，CHI 2011 |
| 例子预测与纠错 | 给情境标注结果、纠正不一致 | 推断未见情境，但结果带不确定性 | PyBE，2017 |
| 逐步形成偏好 | 对遗漏、歧义与边界情境作判断 | 提出具体问题，使尚未形成的意愿显现 | SBAC，2026探索原型 |
| 共同默认与局部差异 | 哪一处要偏离共同处理 | 维持继承、局部覆盖及恢复关系 | Portmaster；uBO分层过滤 |

这些方法改变的是人和系统各自承担的工作，不只是名称。它们也不是七个准备交付的Sakamoto方案；下面筛出最相关的逻辑与反证。

## 1. IAM：让人提出最终结果，把规则调整的推理交给系统

Cao与Iverson的 *Intentional Access Management*（SOUPS 2006）研究WebDAV权限。用户指定某人应当拥有或不拥有某权限；系统分析当前ACL、顺序与组关系，给出实现路径及连带影响，再反馈实际结果。原型界面见论文PDF第9页Figures 6–7；主代理实际查看了该页。[原论文](https://cups.cs.cmu.edu/soups/2006/proceedings/p20_cao.pdf#page=9)

关键区别是输入约束最终效果，而不是要求用户自己找出应改哪条ACL。论文另提出持久保存意图、关联其实现、撤回与处理冲突的Full IAM；**用户实验验证的是Wizard原型，不是完整持久意图系统**。
实验N=10、四任务，Wizard均完成正确；样本小，顺序不充分平衡，两项任务速度差异不显著，作者也将其定位为初步可行性研究。不能宣传为通用策略表达已经解决。
本题启发〔推论〕：把“A应允许d、B/C不变”当成系统必须达成并说明的修改目标，有原始研究基础；新增允许、移动顺序或改组只是可能实现。仍须明确目标范围、持久含义和相互冲突时由人决定的取舍，不能用AI猜测代替。

## 2. 有效结果视图：重要的不只是看见规则，还包括操作后真能改变什么

Expandable Grids把主体与资源的有效权限放在可展开网格里，点击个体或群体结果进行修改。2008研究同时改变了界面和冲突语义为最近创建优先，所以不能将实验收益全部归因于矩阵。[作者原文，PDF第4–5页](https://www.robreeder.com/pubs/xGridsCHI2008.pdf#page=4)

2011后续研究用相同Grid分离冲突语义因素：54名技术专业学生分三组。个体例外Jana任务，specificity与NTFS条件的正确率为89%与11%；但要求整组拒绝覆盖旧个体允许的Kent任务，结果为50%与88%。两种方向都有真实成本。[原文Table 2及讨论](https://www.robreeder.com/pubs/reederEtAl_MoreThanSkinDeep_CHI11.pdf#page=9)

本题启发〔推论〕：共同处理、个别不同、整组重设之间的修改含义，属于体验本身。该研究不支持直接把本产品改成“更具体永远优先”；树状用户／文件权限也没有覆盖任意网络谓词。

## 3. Outcome-Diff：修改时比较后果，而不是让人比较规则文本

CHI 2021的 *Understanding Trigger-Action Programs Through Novel Visualizations of Program Differences* 把整组程序候选之间的差异变成具体情境及不同结果，用户选择可接受结果。例如白天睡着、夜间醒着时，两个锁门方案分别做什么。[作者全文](https://www.blaseur.com/papers/chi21-diff.pdf)

107人、五种界面、六个候选选择任务；行为差异表示在部分复杂任务上优于原规则和文本差异。但27候选任务没有同样的显著优势，参与者没有从零创造这些候选；模型中的规则顺序也不是本题的优先序。实验附录还记录了一项情境展示错误。[作者附录](https://www.blaseur.com/papers/chi21-programdiff-appendix.pdf)
本题启发〔推论〕：针对“A修好而B/C不变”，系统可以帮助人判断具体差别，而不让人从几条修改自己推导后果。这是一种已有的修改／核对思路，不是完整创作核心已被验证。

## 4. “用例子”至少有三种不同逻辑

**回应当前请求，明确推广到以后。** Reactive Access Control让用户对人×文件请求选择本次允许／拒绝，或扩展到今后该文件／文件组。24人一周模拟研究中，多数偏好反应式与预先设置混用；持续回答未实际反馈到后续模拟请求，不能说已证明长期减少打扰。[CHI 2011原文](https://www.pdl.cmu.edu/PDL-FTP/Storage/mazurek-chi11-2.pdf)

**用标注推断未知情况。** PyBE让人给数据情境和输出目标标允许／拒绝，用标签权重和近邻预测新例，并提示可能错误。8名安全研究生的平均预测约76%，并非可执行规则的正确性保证。[2017原文](https://arxiv.org/html/1707.03967)

**让边界情境帮助形成尚未想清的偏好。** SBAC以表达—分析—测试推进：用户描述或画出场景，系统指出歧义、风险、冲突，再用具体情境供人修订。其形成研究与独立评价各14人；评价无对照、约60分钟、至多两设备两组、没有执行后端。主观意图对齐评分不能当政策正确率。[2026原文§4–6](https://arxiv.org/html/2605.10012v1)、[实际交互图](https://arxiv.org/html/2605.10012v1/flow.png)

本题启发〔推论〕：人有时缺少表达方式，有时还没形成完整偏好。这是两种不同困难。具体例子可以辅助澄清与核对，却不能自动界定所有未来连接；即使使用绘图或对话，也不意味着应采用用户已否定的判断路线。

## 5. 真实应用：最接近的思想在维护合同里

以下为官方资料与可定位源码支持的受限还原，不是用户实验。详细版本、代码快照、实际看过的截图及未核验部分见[产品分报告](2026-10-03_CONTROL_RESEARCH_NETWORK_PRODUCTS.md)。

| 应用 | 已有工作逻辑 | 与本题最相关的取舍 |
| --- | --- | --- |
| Little Snitch 6 | 从连接／应用观察建立控制，再用Insights清理冗余、过期及久未使用内容 | 维护贯穿控制生命周期；具体性比较算法不等同任意用户优先序 |
| Portmaster | 全局默认继续有效，应用保留局部设置与规则差异 | 修一个应用无需复制共同配置；强制封禁仍可先于局部allow |
| uBlock Origin | 当前站点局部修复、保留其他过滤层；动态修改默认临时，明确保留后持久化 | 撤回某层干预与强制允许不同；源站／资源类型不等于终端App／协议端口 |
| LuLu | 围绕新程序的首次联网授权，之后细化端点和持续时间 | 名单先于普通规则，普通App allow不能修复所有名单误伤 |
| NetGuard | 以应用×网络接入和自动情境作为日常主要动作 | 官方hosts广告阻止不能单App豁免；主界面简单包含能力取舍 |
| RethinkDNS | 从应用与被阻止连接找到责任控制，应用专属信任和不同接入姿态并存 | 信任、隔离、绕过VPN／过滤是不同含义；不能笼统当allow |

Little Snitch依据：[Monitor控制](https://help.obdev.at/littlesnitch6/lsm-managing-rules)、[Insights](https://help.obdev.at/littlesnitch6/lsc-insights)、[比较顺序](https://help.obdev.at/littlesnitch6/concepts-rules)。
Portmaster依据：[设置分层](https://docs.safing.io/portmaster/settings)、[执行阶段](https://docs.safing.io/portmaster/architecture/core-service/privacy-filter/)。
LuLu／NetGuard／Rethink依据：[LuLu官方手册](https://objective-see.org/products/lulu.html)、[NetGuard名单限制](https://github.com/M66B/NetGuard/blob/master/ADBLOCKING.md)、[Rethink Firewall文档](https://docs.rethinkdns.com/firewall/)。

uBO官方教程的完整误伤例子特别值得读：全局拦截第三方iframe导致本站YouTube不能播放；对本站的youtube.com作noop，撤掉此处的动态过滤，静态名单仍有效。allow则有更强含义，可越过静态阻止。动态修改先临时试验，再明确锁定保存。[官方故事与操作](https://github.com/gorhill/uBlock/wiki/Dynamic-filtering:-quick-guide)

这提供“共同默认—局部差异—试验—长期保留”的实际维护逻辑，但它属于高级用户功能，没有易学性实验；也不能用noop去承诺解除仍在生效的静态名单。

## 6. 对“找一个更自然的表示”的现有反证

**更容易写，不必然更容易读。** Match forms用槽位与并排表格代替显式AND/OR，33人实验创作更准，理解没有显著改善；整表NOT尚未进入实验。Filter/Flow对20名参与者的总体创作有收益，最复杂理解题却未优于SQL。[Match forms](https://john.pane.net/pdf/PaneMyersBooleanQueries.pdf)、[Filter/Flow](https://www.cs.umd.edu/~ben/papers/Young1993graphical.pdf)

**日常句子也依赖语义。** SPARCLE的自然语言输入仍产生共享名称与条件组合歧义；它本身是allow-only、默认deny。TAP研究则发现人会误把状态当事件，或以为动作在条件消失后自动反转。[SPARCLE](https://www.robreeder.com/pubs/SPARCLEINTERACT2007.pdf)、[TAP心智模型研究](https://hcrlab.cs.washington.edu/assets/pdfs/2015/huang2015ubicomp.pdf)

**优先说明不能替代行为理解。** Locked or Not给出精确的feature优先与持续规则，20人仍都至少错一个场景；用户会补入不存在的默认与回退。门锁持续状态不能直接迁移为网络包决策。[CHI 2017原文](https://www.pamelazave.com/yaroshCHI.pdf)

**分组存在，不代表人会按系统的分组方式工作。** Grey的11个月部署发现用户会按群体思考，却很少创建系统群组；同时使用即时与预先授权。它是物理门禁，未验证对等allow/deny优先规则。[CHI 2008原文](https://www.robreeder.com/pubs/greyCHI2008.pdf)

**熟悉比喻会遗漏真实能力。** 个人防火墙门锁比喻改善部分风险理解，但研究未覆盖出站流量，有人误读成聊天邀请；不能凭“像现实中的东西”判断核心概念成立。[SOUPS 2011原文](https://cups.cs.cmu.edu/soups/2011/proceedings/a1_Raja.pdf)

## 7. 长期维护与未核验线索

AuthzMap把当前权限、此前授权及用户岗位变化放在相连的层次与时间线上，支持理解“为什么现在有这个权限”。它研究组织访问审核，不是从零创作，且一些任务准确率下降。主代理读取方法、结果与限制；没有成功取得界面截图。原文摘要为340人，但§6.3及Table 2列430有效样本，保留这一内部不一致，不用单一N背书。[原文§5–7及Table 2](https://www.usenix.org/system/files/conference/soups2014/soups14-paper-jaferian.pdf)

Same-As Policy Management（*Policy-by-Example for Online Social Networks*，SACMAT 2012）是值得补原文的线索：搜索索引中的原文描述以熟悉的代表朋友建立政策，再关联相似朋友。本轮原文镜像失效，未核实全篇和界面，故不采用其统计，也不把实时引用／复制或例外语义写死。[会议记录](https://ww.sacmat.org/2012/advance.php)、[文献DOI](https://doi.org/10.1145/2295136.2295142)

Bonfire实际具有从发布对象逐步展开关系权限的界面，但官方合并规则为false优于true；Protune-X支持基于同一逻辑的how-to／what-if／why-not，但没有HCI效果证据。前者不能直接承载更高优先allow，后者不能独自解决人如何形成策略。[Bonfire语义](https://docs.bonfirenetworks.org/Bonfire.Boundaries.html)、[Protune演示原文](https://ceur-ws.org/Vol-401/iswc2008pd_submission_13.pdf)

## 本轮对寻找key的贡献

以下是主代理的研究判断，不是新的界面方案：

1. **最值得深追的是“最终效果作为输入”。** IAM与有效政策研究让系统承担从意图到配置的推理。我们的局部误伤故事可用于检验这种分工，但完整未来范围、持久目标和冲突取舍仍不能靠推断省略。
2. **第二条是“共同内容的持续维护关系”。** Portmaster与uBO显示，继承、补充、撤回本层干预、临时尝试、明确长期保留是不同承诺。共同与个别是否自然，可能首先取决于这些动作的含义，而非规则画成什么形状。
3. **第三条是“通过具体后果帮助形成和修正偏好”。** SBAC、Reactive与Outcome-Diff分别为形成、推广、比较提供证据；三者不能拼成一个已经验证的万能模式。

现有证据还不足以给出一个同时覆盖本题全部能力的成熟核心。已找到的是可追溯的思想来源、实际工作逻辑与会失败的边界；本轮没有用“再加功能”把它们拼成新候选。

## 分报告与复查入口

### 后续补查：研究单位反查

两席另短查[Figma共用对象与局部差异](2026-10-03_CONTROL_RESEARCH_SHARED_OBJECTS.md)和[Photoshop可编辑作品](2026-10-03_CONTROL_RESEARCH_DIRECT_OBJECTS.md)。主代理实际读完两份报告，并核对[Writer样式与直接格式](https://books.libreoffice.org/en/GS262/GS26204-StylesTemplatesHyperlinks.html)：这些产品把来源、使用点、可选中的材料和当前结果联系起来；恢复局部差异与改变共用定义各有具体含义。

主代理的方法反省〔建议，未获用户确认〕：此前把“保留完整表达能力”过度转化为“所有能力必须由一种默认操作语法自然长出”，因此不断回到条件编辑器及图形编程。可编辑作品可以贯通多种能力，却不要求图层、蒙版、实例覆盖、模式等都成为同一个操作。统一产品中心与统一全部操作语法应分别检验。

这些类比仍没有提供联网控制的key。图像和设计实例有既存、可选中的材料；未来访问及任意条件交集没有天然相同结构。局部覆盖、加工顺序也不等于策略优先裁决。补查的贡献是约束研究起点，不能把规则改名为组件或图层后宣布已得到新理念。

- [策略HCI与冲突语义](2026-10-03_CONTROL_RESEARCH_POLICY_HCI.md)：六篇，含对照、页码及正反任务结果。
- [真实网络控制产品](2026-10-03_CONTROL_RESEARCH_NETWORK_PRODUCTS.md)：六个产品，含实际流程、代码快照、界面证据和A/B/C误伤对照。
- [终端用户逻辑与行为理解](2026-10-03_CONTROL_RESEARCH_END_USER_LOGIC.md)：六篇，区分创作、阅读、优先预测和候选比较。
- [例子、请求、渐进定义与解释](2026-10-03_CONTROL_RESEARCH_ALTERNATIVES.md)：三项用户研究及两个产品／技术旁证，另列未核验Same-As线索。

研究未修改产品代码、原型、执行规格、ADR或已确认的导航与能力；本次材料供继续寻找核心概念使用。
