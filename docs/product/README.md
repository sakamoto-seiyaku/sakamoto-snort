# Product Docs

状态：当前产品定义、UI/UX、内容与发布口径的权威入口。

本目录回答“要交付什么产品、用户怎样完成任务、界面和文字如何表达、什么才算完成”。
它不替代：

- `docs/decisions/` 中的数据面和跨线程架构决策；
- `docs/INTERFACE_SPECIFICATION.md` 中的控制面与数据契约；
- Plane 中的开放工作状态。

## 当前入口

- `ANDROID_L4_PRODUCT_PLAN.md`：Android L4 产品版、后续 libprotoident 阶段、UI 归属、
  信息架构、内容建设和发布完成标准。
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

UI 实现尚未开始前，不在 `experiments/` 或 VPP plugin 目录散落临时产品页面。第一轮 UI
先使用 mock product state 做可点击原型，产品流程通过后再接真实 Tauri/VPP Adapter。
