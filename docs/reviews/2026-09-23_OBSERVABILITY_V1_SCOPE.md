# 首版常态可观测性：查询范围与现有基础

日期：2026-09-23。性质：用户已确认的首版范围及源码核对，不是接口冻结、实施授权或设备验收。

用户确认本清单作为初版起点；不足之处后续按实际需要添加。本轮不继续扩展指标范围，debug 的具体模式与交互设计保持后置。

用户将常态技术信息定位为 VPP 已维护的状态、计数和当前流表，通过 CLI / API 查询即可；debug 属于特殊调试模式，具体模式与交互后置。本清单据此围绕已有能力补查询，不引入独立健康服务。

源码核对基线：`e9356b1111c80ade013dc66052ba4cb28da91860`；VPP pin：`9258530f3804a152578ce11cc7c8a1e9eab88ed0`。本轮只读核对，未构建、运行设备或测量；“已有基础”不等于 Android UI 已接入或完整验收。

## 1. 已确认的首版常态查询范围

| 范围 | 首版回答什么 | 当前基础与待补项 |
| --- | --- | --- |
| 运行与策略状态 | 当前 Root / VPN 模式、运行代际、VPP / Adapter 是否就绪；实际策略版本、规则规模及最近发布结果 | typed status 已有核心就绪、generation、artifact、Adapter、worker 与策略 revision / hash / apply 结果；平台生命周期仍由 RuntimeService 提供。[状态 ABI](../../src/product/include/sakamoto_product_abi.h:170) |
| 基础收发统计 | 对本产品处理范围内的收 / 发或设备入 / 出流量，查包数、字节数；需要时由相同口径累计差值求速率 | Root / TUN / Flow Stack 已有多个处理边界的包数计数；Flow 有字节计数。统一的全局 / 接口字节与速率查询仍需补齐，不能把现有任一 `input/output` 字段直接当成同一口径 RX/TX。[Root 状态](../../src/product/vpp/product_root_nfqueue_adapter.c:1847)、[TUN 状态](../../src/product/vpp/product_vpn_tun_adapter.c:509)、[Flow Stack 状态](../../src/product/vpp/product_vpn_flow_stack.c:367) |
| 当前流表 | 活跃数量、协议状态、端点 / 端口、应用 / UID、网络上下文、首次 / 最近活动、分方向包数 / 字节、当前规则归因 | `show product flows` 已逐条输出上述多数信息，并输出容量、高水位、创建 / 复用及协议汇总；现有 typed API 没有对应的条目 dump。需补面向产品的有界查询，不能把“有 CLI”写成“Android API 已有”。[Flow 查询](../../src/product/vpp/product_packet_graph.c:4282) |
| 策略执行计数 | 允许 / 阻止量、逻辑规则获胜次数及对应包 / 字节，沿用已确认计量口径 | 现有 Gate / L4 累计 match / no-match / drop 与最近归因是基础；完整 per-rule / per-app 台账及新通用规则路径仍需接入。最近赢家不能代替全量规则统计。[状态 ABI](../../src/product/include/sakamoto_product_abi.h:254)、[已有计量共识](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md#2125-统一计量口径用户确认) |
| 丢包与处理异常 | 按发生模块和原因查看策略阻止、处理 / 资源异常、提交 / 转发失败及结果未知的次数和已有错误概况 | Root verdict、TUN、Flow Stack、reassembly 已有分类计数，部分进入 status，其余在 CLI。沿用各自结果含义，不把所有计数合成无口径的“总丢包”。[Root / TUN / 资源查询见下表](#2-已存在的只读查询入口) |
| 资源与容量 | Flow 池、接收缓冲、handoff / completion 队列、重组和 VPN Flow Stack 的当前占用、容量、高水位及容量不足计数 | 已有多处 CLI 和内存 snapshot；首版选可解释的用量与失败计数接入 API，保留底层技术细节供 CLI 查询。[Flow 池](../../src/product/vpp/product_packet_graph.c:4282)、[重组](../../src/product/vpp/product_packet_reassembly_graph.inc:551)、[Flow Stack](../../src/product/vpp/product_vpn_flow_stack.c:367) |
| 观测通道状态 | 常态记录是否在导出 / 消费，丢失多少，最近消费进度及保存是否失败 | 属于待实现的观测链配套状态；producer 与 Rust 各维护本侧事实，VPP 导出失败计数可经控制查询读取。不能从既有 `policy_drop_records` 等工程字段推定新的 record ring 已接通。[当前讨论](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md#2129-记录通道收敛为三项候选最终由实验选择用户确认) |

之前确认的四类历史窗口继续保留：总体流量、应用流量、应用 L4 / L7 协议分布、规则效果。这些由 Rust 根据常态记录增量维护，查询观测库；上表的当前运行状态 / Flow 表则查询运行时。两者职责不合并，也不依赖 debug 开启。[窗口归属](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md#2116-常态窗口由-rust-后台增量维护后续确认)

## 2. 已存在的只读查询入口

以下是当前产品源码注册的 CLI；是否可执行取决于实际 artifact、插件及对应 Runtime Profile 是否启用，本轮没有运行命令验证。

| 入口 | 源码直接提供的内容 |
| --- | --- |
| `product_core_status` / `sakamoto_product_core_query` | 核心及 Adapter 就绪、运行身份、部分 Root / VPN 计数、graph 状态、策略发布身份与 Gate / L4 证据。[VPP API](../../src/product/vpp/product_core.api:29)、[Rust/C 查询](../../src/product/include/sakamoto_product_core_ffi.h:19) |
| `show product flows` | 各 owner 的 Flow 池统计、容量 / 高水位、当前条目、分方向计量、TCP / UDP / ICMP 状态与 timeout 信息。[实现](../../src/product/vpp/product_packet_graph.c:4282) |
| `show product root lanes` | 各 Root lane 的 ready / draining、captured / submitted、verdict 成功 / 失败、pending 和 buffer return。[实现](../../src/product/vpp/product_root_nfqueue_adapter.c:1847) |
| `show product root receive` | NFQUEUE 接收池容量、free / loans、datagrams、reserve / identity losses。[实现](../../src/product/vpp/product_root_nfqueue_adapter.c:1735) |
| `show product tun` | TUN attach、captured / submitted / completed、policy / runtime drops、写入成功 / 失败、待处理和资源占用。[实现](../../src/product/vpp/product_vpn_tun_adapter.c:509) |
| `show product flow-stack` | VPN transport 的就绪、session / PCB / socket / pbuf 资源，按原因分类的失败与首次 / 最近错误信息。[实现](../../src/product/vpp/product_vpn_flow_stack.c:367) |
| `show product primary` / `show product completion` | owner handoff 与 origin completion 的有界队列、pending 和相关计数。[分流](../../src/product/vpp/product_packet_graph.c:4252)、[完成](../../src/product/vpp/product_root_nfqueue_adapter.c:1947) |
| `show product reassembly` | 重组输入 / 成功 / 异常、资源旁路、待处理上下文和 handoff 队列状态。[实现](../../src/product/vpp/product_packet_reassembly_graph.inc:551) |
| `show product expiry` / `show product flow-end` | 到期处理、timer / backlog / 回收及 END 生命周期计数。[expiry](../../src/product/vpp/product_flow_expiry.c:382)、[FlowEnd](../../src/product/vpp/product_flow_end.c:461) |

`show product flows` 目前在 CLI worker barrier 下遍历池；这证明有当前表读取基础，不等于已经具备适合 Android 自动刷新的分页 API。后续产品查询应有界，避免把全量技术 dump 当作高频统计刷新。

源码中还有故障注入、fixture、容量重配置等命令，它们不属于本清单的只读查询。例如 `show product packet-graph` 位于 host-evidence 条件编译分支，本轮没有将它列为 Android 产品入口。[条件编译入口](../../src/product/vpp/product_packet_graph.c:4197)

## 3. 读取与统计的简单边界

- VPP 拥有包域状态和技术计数；CLI 用于人工查看，Android 经 Rust / native typed API 读取相应状态。缺失项在现有查询面补齐，不让 App 解析 CLI 或日志文本来构造权威计数。[现行接口地图](../INTERFACE_SPECIFICATION.md)
- 日志可作底层故障排查补充，但日志路径、格式或文件是否存在不决定统计能力。平台权限 / 生命周期仍由 RuntimeService 提供，Rust 自身的消费 / 存储失败由 Rust 维护，不强行放回 VPP。
- RX/TX 需标明是在设备方向、捕获 / Adapter 边界还是 VPN transport 边界计量；Flow 的 ORIG / REPLY 不是设备 RX/TX。当前包没有真实物理接口信息时不能编造；Root hook 的 INPUT / OUTPUT 包数也不是已经完成发送的证明。
- 当前 Flow 表不包含前置 DROP 的正常 FlowEntry；对应阻止观测仍按既有独立轻量观测设计处理，不为了补流表而创建 CT。
- 策略 DROP、资源不足导致的旁路、明确发送失败、结果未知、观测记录丢失分别解释；字节和包数沿用现有业务计量合同，内部转移、重试通知及 END 信号不重复算业务流量。
- 保留计数原有语义。本轮不新增健康评分、告警平台或自动恢复状态机，也不把“本代曾失败”的锁存字段改说成“当前仍拥塞”。

## 4. debug 后置

用户举出的后续用途包括：预览 / 模拟新规则效果而不执行实际动作，以及在规则正常生效时追踪实际包经过的节点和规则判断、排查规则冲突。两者语义不同，暂不把模拟模式等同于现有 observe，也不在这里选择禁用缓存、重放或 shadow 执行方案。

debug 的具体模式、交互与覆盖合同，在界面及使用流程更明确后再设计；它不作为当前常态能力梳理的前置条件，也不据此决定是否排除在最终首版交付之外。已明确的单次调试、临时数据、实际追踪的真实性与正确性优先继续作为后续要求；先前关于“不重跑实际包”的约束适用于真实路径追踪，不能阻止将来独立定义模拟功能。
