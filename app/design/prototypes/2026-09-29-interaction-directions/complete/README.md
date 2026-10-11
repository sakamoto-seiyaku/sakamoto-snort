# Sakamoto · 完整交互原型（第二轮）

本轮问题：如何在 Android 手机、Android 平板与 Linux PC 上，把已有基础能力组织成连贯、直接、准确的用户任务？

这是设计交付物，不是正式产品前端。它替代上一版三个方向作为当前评审入口；上一版保留在父目录 `directions.html` / `gallery.html`，仅作历史设计材料。

## 本地预览

当前运行中的入口：

- [全部页面平铺总览](http://127.0.0.1:4173/complete/index.html)
- [Android 连续体验](http://127.0.0.1:4173/complete/home.html?platform=android)
- [Linux 桌面连续体验](http://127.0.0.1:4173/complete/home.html?platform=linux)

从仓库根目录启动同一服务：

```sh
rtk proxy python3 app/design/prototypes/2026-09-29-interaction-directions/serve.py --port 4173
```

所有 HTML、脚本、图标和底图均本地提供，预览无需 npm 安装，也不依赖 CDN。由于使用原生 ES modules，请通过 HTTP 预览。

`index.html` 以 iframe 平铺 **44 个独立页面**，加上 **6 个宽屏视图**与 **9 个关键状态**，共 59 个 iframe。每个手机视口保持 393 × 852；并列提供 Android 820 × 1180 / 1180 × 820 和 Linux 1440 × 900 / 900 × 760 / 640 × 760。平板和桌面总览有标注缩放，iframe 内部使用标注的真实视口。每个窗口都可以继续操作。

## 结构和布局

- `*.html`：独立页面，包含各自的页面结构；不是把全部页面塞进一个动态 HTML。
- `css/tailwind.css`：本地编译的 Tailwind 基础与工具样式；`css/input.css` 是输入。
- `css/app.css`：共享颜色、字体、间距、圆角、组件与响应布局。
- `css/gallery.css`、`js/gallery.js`：平铺总览及分组切换。
- `js/model.js`、`js/seed.js`：共享模拟配置、状态与样例；`js/ui.js`：导航、弹层、反馈、返回上下文。
- `js/apps.js`、`activity.js`、`rules.js`、`manage.js`、`explore.js`：按用户功能拆开的必要交互。
- `assets/`：本地图标与地图，来源见 [ASSET_SOURCES.md](ASSET_SOURCES.md)。
- `screenshots/`：手机、平板和桌面的代表性截图。

平台与布局分开：Android 决定应用身份和授权语义，Linux 决定系统用户 UID 与主机运行语义；窗口宽度决定单栏、触控导航栏、列表和详情并排。Linux 的同一 UID 不能被表达为可独立控制该用户下每个程序。桌面窄窗口会收起完整侧栏，不出现 Android 状态栏。

可选重新编译 Tailwind（只用于修改样式源文件后）：

```sh
cd app/design/prototypes/2026-09-29-interaction-directions/complete
rtk npm install
rtk npm run styles
```

## 连续任务

- 访问记录 → 访问详情 → 创建规则 → 选择对象与执行方式 → 保存结果 → 返回原记录；历史结果保持不变。
- 对象 → 快捷限制 / 网络限制 / 分配 → 保存 → 对象当前生效规则；开关开启表示添加限制，解除后仍由其他规则判断。
- 规则 → 规则组 / 域名列表 → 复用与分配 → 对象；规则组分配与直接分配都可见。
- 导入配置 → 检查 → 替换范围审阅 → 保存 / 生效结果 → 配置管理。
- 运行方式 → 授权或取消 → 清理旧方式 → 启动；启动配置修复后仍需显式启动。
- 设置 → 外观 / 数据 / 通知 → 可见反馈 → 返回；数据清空后的全部入口一致。
- 地图 → 地区 → 访问；从访问进入地区后可以返回原访问。
- 规则预演 → 调整合成输入 → 判断过程 / 事实不足 → 查看规则或继续调整。
- 诊断会话 → 选择范围和时限 → 观察 / 停止 → 检查报告 → 主动导出。

## 哪些交互属于模拟

**所有操作都是前端模拟**。不调用 VPP/Rust、Android 系统授权、Linux 管理员服务、真实通知、地图服务或流量采集。运行、模式切换、故障、恢复、配置编译与导出均只作用于样例状态。

为演示跨独立页面的连续操作，使用当前标签页的 `sessionStorage`。刷新保留本次状态；关闭浏览会话后不作为产品配置持久化。总览 iframe 用独立 `scope`，互不更改各自的样例。给 URL 加一个新的 `scope=your-review` 即可开始一份新样例。

配置 JSON 使用 `sakamoto-ui-prototype-v1`，不能导入正式产品。保存失败不改配置；保存成功但未生效时保留旧生效配置；“重试”演示恢复成功，不模拟真正的编译器。版本冲突演示保留输入与重试，不实现并发合并算法。

预演支持一部分前端可解释条件；未提供或未支持的事实返回未知，NOT 不把未知转成真。结果不能证明真实流量上的匹配。地图的底图是真实地理轮廓，地点、地址及流量关联均为示例；保留本地/未知位置。诊断只生成有时限的样例过程，不采集真实载荷、密钥或网络数据。

主题、启动偏好、通知与保留范围展示预期产品操作。规则组友好名称、正式偏好/数据管理、Linux 生命周期等仍需要产品契约与后端接入；原型可操作不代表这些已在产品实现。checkpoint、计费、限速、定时等未扩入本轮。

## 有限评审和验证

按用户指定使用两个 `gpt-6-sol / xhigh` 子代理，严格从聚焦、直觉、精确、克制、端到端连贯与完整性角度质疑设计；只进行了初稿和完成稿两轮。它们的意见作为设计原则推演，不代表对任何人物真实意见的声称。

完成稿采纳了：真实作用范围与组分配、快捷限制开关的准确方向、当前生效/已保存版本区分、手机先呈现条件、清空后的跨页一致性、SNI 事实适用边界、地图返回上下文、Linux 平台事实、独立结果页的明确示例状态。

浏览器验证结果另见 [QA.md](QA.md)。这些是原型检查，不是正式产品验收；没有操作设备或修改产品实现。

## 页面清单

| 文件                                         | 作用                                                          |
| -------------------------------------------- | ------------------------------------------------------------- |
| [home.html](home.html)                       | 当前保护结论、访问合计与最近连接；异常状态直接进入处理。      |
| [apps.html](apps.html)                       | 搜索与筛选控制对象；手机逐级进入，平板/桌面并排选择与详情。   |
| [app-detail.html](app-detail.html)           | 当前生效规则、快捷限制、分配与对应访问；明确配置版本。        |
| [app-networks.html](app-networks.html)       | 按网络类型添加或解除快捷限制；Linux 与 Android 条件分别适配。 |
| [app-selection.html](app-selection.html)     | 选择多个对象，逐项提交并显示成功或失败。                      |
| [activity.html](activity.html)               | 保留访问明细、搜索与结果筛选；宽屏提供选中记录旁栏。          |
| [activity-filter.html](activity-filter.html) | 对象、结果、记录类型和时间范围，返回后保留筛选。              |
| [connection.html](connection.html)           | 当时结果、协议/SNI事实、规则归属；从记录建规则或查看地图。    |
| [stats.html](stats.html)                     | 按时间查看计数、趋势、对象/规则/协议分布与覆盖边界。          |
| [protocols.html](protocols.html)             | 20 个协议标签及适用说明，可进入协议规则创建。                 |
| [rules.html](rules.html)                     | 已保存规则库及明确执行顺序；宽屏并排展示选中规则。            |
| [rule-detail.html](rule-detail.html)         | 查看条件、优先级、分配，编辑、复制、删除或进入预演。          |
| [rule-edit.html](rule-edit.html)             | 14 类条件、嵌套 AND/OR/NOT、名称/动作/来源；保留跨页草稿。    |
| [rule-scope.html](rule-scope.html)           | 选择直接分配对象与执行/仅观察；保留规则组分配的区别。         |
| [groups.html](groups.html)                   | 规则组列表与当前分配。                                        |
| [group-detail.html](group-detail.html)       | 成员、嵌套组、分配与删除；不删除底层规则资产。                |
| [group-edit.html](group-edit.html)           | 选择成员和嵌套组，保存时检查循环引用。                        |
| [binding-edit.html](binding-edit.html)       | 新增、修改、解除分配，并检查执行方式冲突。                    |
| [domains.html](domains.html)                 | 域名列表与引用概览。                                          |
| [domain-detail.html](domain-detail.html)     | 精确/含子域名条目、引用规则、删除保护与从列表建规则。         |
| [domain-edit.html](domain-edit.html)         | 增删条目、匹配范围与来源。                                    |
| [domain-import.html](domain-import.html)     | 限定格式解析、错误反馈、预览后保存。                          |
| [config.html](config.html)                   | 已保存/当前生效版本、失败重试、配置导入导出与清空。           |
| [config-import.html](config-import.html)     | 选择文件或粘贴 JSON，检查格式与平台身份。                     |
| [config-review.html](config-review.html)     | 导入前展示完整替换范围，可先导出现有配置。                    |
| [config-result.html](config-result.html)     | 保存、生效、修复后待启动分别表达，返回原任务。                |
| [runtime.html](runtime.html)                 | 实际与所选运行方式、暂停/启动和故障处理入口。                 |
| [setup.html](setup.html)                     | Android Root/VPN 或 Linux 主机运行方式选择。                  |
| [permissions.html](permissions.html)         | 授权确认/取消、通知条件，先清理旧方式再启动新方式。           |
| [recovery.html](recovery.html)               | 恢复进度、重试、取消恢复及诊断入口。                          |
| [network.html](network.html)                 | 当前网络、接口、DNS 状态与更新说明。                          |
| [settings.html](settings.html)               | 管理、偏好与深入工具的稳定入口。                              |
| [appearance.html](appearance.html)           | 浅色/深色/跟随系统、强调色和文字大小，跨页面保持。            |
| [storage.html](storage.html)                 | 保留范围、导出与清空；清空在列表、旁栏、首页和统计中一致。    |
| [notifications.html](notifications.html)     | 状态通知与启动偏好模拟，平台生命周期说明。                    |
| [about.html](about.html)                     | 版本、隐私、模拟范围与资源说明。                              |
| [extensions.html](extensions.html)           | 地图、规则预演、诊断会话的独立入口。                          |
| [map.html](map.html)                         | 真实底图上的样例地理信息；按时间筛选并进入地区。              |
| [location.html](location.html)               | 地区对应的访问；返回时保留来源页面。                          |
| [preview.html](preview.html)                 | 输入合成事实，不发送网络请求或改变配置。                      |
| [preview-result.html](preview-result.html)   | 预计动作、匹配过程、事实不足与当前规则的连接。                |
| [debug.html](debug.html)                     | 对象、问题和会话时限；单会话控制。                            |
| [debug-session.html](debug-session.html)     | 限时过程、停止与报告入口；离开页面保留会话。                  |
| [diagnostics.html](diagnostics.html)         | 报告范围、完整内容检查和主动导出。                            |
