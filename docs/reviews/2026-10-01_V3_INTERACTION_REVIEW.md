# V3：从可辨认对象到完成与返回

2026-10-01，交互席，gpt-6.1-sol / high，全新评审。接受这三段原型工作在修正后的连续行动；不以入口数量裁胜，也不把可达证明成自然。
方法依据为[Jobs 方法复查](2026-10-01_JOBS_EXPERIENCE_METHOD_RETHINK.md)、[体验裁决](2026-10-01_EXPERIENCE_DESIGN_VERDICT.md)、[语义核对](2026-10-01_EXPERIENCE_SEMANTICS_CHECK.md)。对象→预期动作→可读结果→失败修正→复验与返回是研究者推导，不冒称 Jobs 原话。

## 实际审查范围

- 等 designer stable-ready 才读新 HTML、操作页面；未将未完成版当最终稿。所有 UI 源码修改由设计席完成，本席仅写本报告与截图。
- Chromium：`/home/js/.cache/ms-playwright/chromium-1223/chrome-linux64/chrome --no-sandbox`，Playwright；手机 context 393×852、hasTouch，Linux 1440×900。
- 入口：`http://127.0.0.1:4173/v3/index.html?mode=android-phone&view=overview&zoom=100`；Linux 使用 `mode=linux-wide&view=rules&zoom=100`。
- 实际 tap/click、键盘输入/方向键/Tab、容器滚动；只读 `window.v3.state` 核对来源与选择，未注入 state 替代操作。截图生成后实际打开查看。
- 首轮 hash：`8d50ef99d39da16d010c7ab4a82f1860c817e2bd97379432c3f1eaffe2c4ed39`；三题完整复核 hash：`5efa65d0f31d73c34ece2dc85766b3a2fa62f00ab8649979c2b531a10ce6e2b7`。
- 最后具名返回修正有限复核 hash：`841dbd6860a5621022143b86736d32141ef36f877a294d23ca397369de335f45`。
- 实际经过 overview、app、fact、basis、change、expression、review、result、verify、rules、rule、work-detail、authoring、work-review、record、record-start、deep、current-app。

## 三段完整工作

**1. 从同段天气贡献改变以后，再回旧查询。** 首页选择09:21–09:26→天气→查询→metrics.example.net的09:24记录。名称、身份、查询通道与旧v42阻止同时可认；字节不被说成查询造成。主动作直接是“调整以后的此名称查询”，默认精确名称，包含子域须另选。
保存失败保持saved43/active42及原metrics输入；保存未使用样例变成saved44/active42，正文不承诺已允许。修正名称、再次提交后使用45；核对同目标后续仍明确“尚无新查询”，没有用成功保存冒充执行验证。完成后旧09:24仍阻止/v42。
直接事实路径完成后顶部返回恢复app/query/weather-block/09:21–09:26。最后还实际重演fact→basis→具名回fact→修改/提交/完成→顶部返回；修正后同样直接app，栈只剩overview。
“查看当时依据”只给v42、赢家与D11缺失，不拿已保存43补史；它和从现在开始的新记录有不同开始与证据来源。

**2. 长期集合的选择、修改、取消与完成。** 1440集合可先读保存43、50条与8未分配项，实际42是另一条说明；搜索SSH后所选定义和用途在旁边展开。未分配SSH明确不参与设备判断，修改不是每次从新建引导开始。
改名字再取消仍回r5/SSH搜索，保存源未变。393不搜索，选择第40项目的地址规则；编辑直接进入同项work-detail，取消与完成均恢复同项、主滚动3276，屏内能认出第40项。完成后的新名称可读，未分配仍未分配。
Linux列表连续两次ArrowDown从SSH到new-1、new-2；焦点均落新选中行，3px可见轮廓。搜索输入ArrowLeft把光标3→2而不改视图；手机Tab落“全部”有可见轮廓。实际小触控主动作能一次启动、取消、完成。

**3. 健康实际记录贯穿编写，而非失败后的只读角落。** 从SSH本次修改开启D1，明确UID1000全部程序、开始时刻、起始42及5分钟/50条边界。回原输入继续改优先级、完整发布44；晚到事件仍标42，没有重标44。
发布前返回保未提交名称与输入；发布后返回已保存44的同r5，不复活已经提交的dirty候选。可继续第二次整理发布45，SSH搜索和选中项仍在。
结束只令D1 finished：实际按“播放事实”按钮后普通事实0→1，额外事件维持1。原规则仍可编辑；旧条件缺失和额外阶段未取得如实显示。
补用Music连接反例：media.example.org有TLS SNI、198.51.100.25:443及独立连接事实。新记录继承连接/目标/证据来源，结束返回同record/connection/09:21–09:26；当前09:41快照往返同样恢复这三者。Music没有被套成天气的查询样例。

## 真实答辩与落下的修正

| 实发问题与损失 | 设计席真实答复 | 本席最终实际复核 |
| --- | --- | --- |
| 393表达式输入名字后首tap返回仍在expression；blur同步render吃掉点击，第二tap才走。唯一反例跟进：Linux列表重绘令focus变BODY，第二ArrowDown不再选下一项。 | 接受“首击是实质行动失败”；文本/数值与树叶只同步模型，结构变化才重绘；列表重绘恢复对应行focus。 | 键盘End输入A后一次tap已到change；连续两键到new-2且focus同row。输入左右键仍用于编辑。 |
| verify完成回fact后顶部返回result，已完成的修改子栈未收口。唯一反例跟进：手机第40项取消保choice却main3276→0，原项跑到屏外。 | 接受来源history锚点与完成/取消收子栈；同时保存手机main scroll与桌面rows scroll。最后root推动具名basis返回也收口。 | 完成与取消均回第40项/3276；直接fact与basis具名返回两序列完成后back都回原app/query/时段/record，不经result。 |
| Music连接的“同类判断”正文写名称查询；原问题标题与预期采集动作矛盾。 | 接受按channel表达，连接列出SNI或IP来源和目标；deep同样表达，返回保连接选择。 | setup明确“连接 · media.example.org / TLS SNI / 198.51.100.25:443”，deep也是连接；返回仍music-media/connection/原时段。 |

三题均真实往返；前两题各一次反例跟进，没有无限追加审题。最后接受建立在实际修正和复核，不以设计意图或源码存在宣告成功。

## 证据与边界

- [天气完成后返回原应用](../../app/design/prototypes/2026-09-29-interaction-directions/v3/screenshots/interaction/final-phone-weather-return.png)、[手机集合完成后同项同位置](../../app/design/prototypes/2026-09-29-interaction-directions/v3/screenshots/interaction/final-phone-collection-complete.png)、[Music连接的记录范围](../../app/design/prototypes/2026-09-29-interaction-directions/v3/screenshots/interaction/final-phone-music-scope.png)。
- [Linux晚到42证据](../../app/design/prototypes/2026-09-29-interaction-directions/v3/screenshots/interaction/final-linux-debug-late42.png)、[发布后回同已保存项](../../app/design/prototypes/2026-09-29-interaction-directions/v3/screenshots/interaction/final-linux-return-saved.png)。同目录旧截图保留首轮问题，不代表最终状态。
- 外层save-error/unapplied/success与播放按钮是明确mock；本席证明了响应、输入、版本和回路的呈现，没有证明真实编译错误定位、通用表达式解释器、任意事实匹配或真实Debug采集。
- 没有真实设备、网络、后端调用或普通用户可用性研究；未穷举全部规则字段与六个窗口。健康深度和长期完整编写仍保留，但整套能力验收由整体席及后续产品验证承接。
- 在这三段工作中，人可以先认对象、预测动作、认出改变及缺证，再带原问题返回；这是有限实际走查支持的体验判断，不是因为只剩两个入口。
