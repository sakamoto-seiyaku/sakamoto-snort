# 本地资源来源

- Firefox 应用图标：[Firefox logo, 2019](https://commons.wikimedia.org/wiki/File:Firefox_logo,_2019.svg)，下载到 `assets/firefox.svg`，仅标识 Firefox 示例对象。商标属于 Mozilla。
- Signal 应用图标：[Signal Logo](https://commons.wikimedia.org/wiki/File:Signal-Logo.svg)，下载到 `assets/signal.svg`，仅标识 Signal 示例对象。商标属于 Signal。
- 统一界面图标：[Lucide](https://github.com/lucide-icons/lucide)，从 `lucide-static@0.468.0` 的本地 SVG 生成 `assets/icons.svg`。ISC 许可保存在 `assets/lucide-LICENSE`。
- 世界底图：[Natural Earth 1:110m admin-0 countries](https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_110m_admin_0_countries.geojson)，公有领域地理数据，经等距经纬投影生成 `assets/world.svg`。地图上的目标、城市和访问统计是前端示例。
- 保护状态的轨道/盾牌图形由本原型使用 SVG 绘制。
- [Tailwind CLI 官方说明](https://tailwindcss.com/docs/installation/tailwind-cli)用于本地编译；浏览器不加载远程样式或字体。

预览不需要外部图片网络请求。应用图标加载失败时以本地文字/图形后备呈现；此类网络管理页面不加入与用户任务无关的装饰照片。
