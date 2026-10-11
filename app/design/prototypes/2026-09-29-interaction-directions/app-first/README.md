# 决定与结果 · 阶段四交互稿

本轮落实[完整原型评审](../../../../../docs/reviews/2026-09-29_JOBS_FULL_PRODUCT_REVIEW.md)的八项问题：让用户在确认变化前理解影响，并在操作后核对实际状态。应用中心、设备整体观察和连接透视继续作为主线。

## 直接体验

- [阶段四总览](http://127.0.0.1:4173/app-first/index.html)：12 个手机画面与 4 个平板/Linux 画面，可继续操作。
- [Android：我的网络](http://127.0.0.1:4173/app-first/home.html?platform=android&scope=trust4-live-home)
- [导入审阅样例](http://127.0.0.1:4173/app-first/config-review.html?configcase=expanded-scope&platform=android&scope=trust4-live-import)
- [订阅更新与本地修改](http://127.0.0.1:4173/app-first/domain-detail.html?id=d1&subscription=update&localcase=modified&review=update&platform=android&scope=trust4-live-subscription)
- [Linux：已有连接](http://127.0.0.1:4173/app-first/activity.html?app=s3&type=connection&platform=linux&scope=trust4-live-linux)

从仓库根目录启动，浏览器预览无需安装 npm 包：

```sh
rtk proxy python3 app/design/prototypes/2026-09-29-interaction-directions/serve.py --port 4173
```

共 47 个独立产品 HTML，另有 `index.html` 总览。样式、图标、图片、脚本均在本地；总览外的样例按钮用于制造明确标记的模拟响应。

## 已落实的交互

1. **导入前核对行为变化。** 按改变、新增、删除呈现规则、条件、分配、组和列表；作用范围包含规则组展开后的应用。原数量统计与完整 JSON 可展开。同名同数量的 `/16 → /0` 变化也有“目的地址条件扩大到所有 IPv4 地址”的说明；复杂否定或多条件变化不猜测整体效果。
2. **运行与恢复使用同一事实。** 待授权、暂停、配置待处理、恢复中、需处理、等待启动、旧设置运行分别说明当前影响及下一步。重新授权后仍需明确启动。徽标和配置反馈同步变化。
3. **先表达实际执行方式。** 规则卡、详情和应用设置展示命中后的执行或观察方式；规则定义保留在第二层。不同应用的方式不同时，明确逐项列出；未分配的规则不冒充正在执行。
4. **订阅有完整维护路径。** 来源、资料版本、检查状态、失败重试、更新审阅、暂停、停止与恢复均可操作。新页面 `domain-subscription.html` 管理地址、格式、频率和采用偏好。
5. **时段、最新快照、整条累计分层。** 贡献行先表达本时段事实；地区和所选时段中的连接行分别展示时段收发与最新快照。存续区间相交的长连接继续可见。
6. **两种筛选入口一致。** 独立筛选页与活动面板共用结果定义，类型、状态、应用和时间通过 URL 保留；返回仍能修改刚才的条件。
7. **平板指标保持完整。** 820px 下调整指标网格与间距，数值和单位不再拆行，继续支持整体活动与应用并排查看。
8. **导入错误可以定位。** 内置样例保留有效引用；缺失引用会指出分配身份、路径和目标，并可定位回保留的输入。完全相同的配置可直接保留，避免多做一次替换。

同一位 `gpt-6-sol / xhigh` 评审代理做了一次[定向复审](../../../../../docs/reviews/2026-09-29_JOBS_REFINEMENT_REVIEW.md)。随后落实了三处收口：把地址差异翻译成可理解的范围变化；压缩手机来源摘要并前置一条使用规则；切换自动采用时明确是否一并采用当前候选，采用后直接呈现使用状态。原始复审观察与主代理后续落实分别记录。

## 本轮订阅方案

这些是可操作的界面与样例数据方案，不提前冻结真实后端格式或调度合同。

- 来源条目、本地补充、本地排除分别保存。排除优先于本列表的正向条目，只影响本列表；其他列表和规则继续独立判断。条目行直接注明局部例外或完全排除。
- 默认先审阅新版本，也可明确选择自动采用。已有候选时切换自动采用，会先说明“保存并采用待更新版本”，再一次保存偏好与新资料。
- 修改来源后保留此前资料，直到新来源经过检查和采用。暂停检查保留现有资料；停止订阅仍保留来源记录和本地修改，可明确重新启用。编辑已停止的订阅不会偷偷重新启用。
- 资料保存与规则配置生效分开。生效失败时，详情同时说明已保存资料及当前仍使用的资料，并提供配置处理入口。
- 手机首屏保留订阅状态、最近检查、主要操作、一条使用规则和首条匹配目标；完整地址、检查安排与停止操作可展开，或进入管理来源。

## 文件职责

| 文件                                         | 职责                                         |
| -------------------------------------------- | -------------------------------------------- |
| `js/runtime-state.js`                        | 运行、恢复及状态徽标使用的共同事实           |
| `js/rule-use.js`                             | 按应用展开分配后的实际执行方式               |
| `js/config-changes.js`                       | 配置行为差异、受影响应用及保守的地址变化说明 |
| `js/domain-lists.js` / `js/domains.js`       | 名单匹配与本地排除、订阅维护及更新界面       |
| `domain-subscription.html`                   | 订阅来源、频率和采用偏好                     |
| `js/activity-filters.js`                     | 两种筛选入口的共同定义及独立筛选页           |
| `js/connection-view.js` / `js/visibility.js` | 时段事实与最新连接快照的分层                 |
| `js/model.js` / `js/seed.js`                 | 前端状态、配置校验与明确的样例状态           |
| `index.html` / `js/gallery.js`               | 可操作总览与画面外的样例工具                 |

## 模拟边界与入口

**全部数据和变更都是本地前端样例，没有连接真实后端或修改设备。** DNS/IP/应用信息按已确认的目标能力设计；配置 JSON 仍为 `sakamoto-ui-prototype-v1`，不是生产配置格式。

`sessionStorage` 使用 `sakamoto-trust-v4` 前缀，按平台、`scope` 和观察样例隔离。新的 `scope` 可开始独立会话。连接与资料时钟仍是样例 09:41。

| 参数或入口                                                                   | 样例内容                                   |
| ---------------------------------------------------------------------------- | ------------------------------------------ |
| `config-review.html?configcase=expanded-scope`                               | 同名同数量、地址范围扩大后的导入审阅       |
| `domain-detail.html?id=d1&subscription=failed`                               | 已检查失败，旧资料保留；可以重试           |
| `domain-detail.html?id=d1&subscription=update`                               | 已检查到待审新版本，尚未采用               |
| `localcase=modified`                                                         | 一项本地补充与一项本地排除；只初始化新会话 |
| `review=update`                                                              | 直接进入已有候选的审阅区                   |
| `scenario=save-error` / `unapplied`                                          | 保存失败 / 保存后尚未生效                  |
| `scenario=permission` / `paused` / `startup` / `recovering` / `intervention` | 运行与恢复状态                             |
| `window=15,20`                                                               | 09:21–09:26；长连接保留，时段收发另算      |

订阅 URL **不会被实际访问**，也没有真实后台定时器。总览中的“准备一次失败”“准备样例新版本”只准备本地响应，再由画面中的检查动作读取；“模拟到达检查时间”按已选择的暂停/审阅/自动采用偏好执行。查看和刷新不会制造新网络活动。原来的活动样例按钮仍在产品画面外。

验证及截图见 [QA.md](QA.md) 与 [screenshots/stage-four/](screenshots/stage-four/)。上一阶段记录保存在 [STAGE_THREE.md](STAGE_THREE.md)、[QA-stage-three.md](QA-stage-three.md) 和既有截图目录；历史文档中的实时链接会打开当前原型。图片来源仍见 [ASSET_SOURCES.md](ASSET_SOURCES.md)。
