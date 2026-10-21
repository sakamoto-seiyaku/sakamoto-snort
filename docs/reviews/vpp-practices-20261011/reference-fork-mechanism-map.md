# Reference fork：实际批执行机制与开发边界

日期：2026-10-11。参考 fork 确实用了当前产品尚未系统采用的 **x4 独立准备、向前预取、整 frame buffer-pointer 准备与整 frame 发布**。复杂识别和规则工作则大量保持逐包、逐 session 执行，配合停止条件和变化 guard；没有证据把它概括成已经成熟部署的多包 SIMD/DPI 系统。

本轮重新读实际源码，不以旧调查代替核对。fork `/home/js/backup/backup/Git/vpp` 的 HEAD 仍为 `837432be3b6cf496755cfa27b7cca439734eb726`，提交时间 `2026-04-07T15:49:22+08:00`；`git diff --name-only -- src` 为空，下面审查的 37 个源码、构建和配置文件逐字节等于该 HEAD 的 Git blob。另有 `build/external` 删除、`test` 修改及未跟踪内容，不参与结论。产品 HEAD 为 `54f2566f26cbbd2ae2cdfd3a1796e4e0f19041e6`，本轮引用的 9 个产品 C/patch 文件也逐字节等于 HEAD。官方对照来自 `build-output/pinned-vpp-clean` 的 `9258530f3804a152578ce11cc7c8a1e9eab88ed0`；其 `buffer_funcs.c` 已逐字节核对，blob 为 `ce09a51c600b30e3251bb2c657d67f636a21d58c`。

这里的“实际 caller”指已注册 node 中存在直接调用，并继续核对 feature 启用路径及 CMake 声明；它不能证明某部署 artifact 已编入、加载或启用。未运行 fork、未检查其部署 ELF/ISA、未测吞吐。产品边界仍是 [ADR-0006](../../adr/0006-vpp-native-packet-io-adapters.md)、[0007](../../adr/0007-owner-local-lwip-direct-egress.md)、[0008](../../adr/0008-remove-snort-cpp-mainline.md)：只讨论 C/VPP 执行组织，不导入 fork 实现或已删除 C++/POC 源码。

## 机制、调用和产品对照

| 机制 | 确切 caller、注册与构建入口 | 当前产品 | 应借鉴的设计 | 开发与证据边界 |
| --- | --- | --- | --- | --- |
| Parser：x4 独立包准备、未来四包 header/data 预取、frame 末计数 | 三个 `VLIB_NODE_FN` 调 [`flow_dissector_node_fn`:350](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:350)；[x4:117](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:117) 内四次 parser 调用；[arc:412](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:412)、[enable:134](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector.c:134)；[`MULTIARCH_SOURCES`:20](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/CMakeLists.txt:20) | [admit:1254](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1254) 逐包取 buffer，无该窗口预取；external 第一跳 [n=1:4089](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:4089) | 对已经取得的独立输入做短窗口准备，保留 scalar tail；可汇总的计数在 frame 末更新 | x4 要求剩余 **≥8** 且 next 空间≥4，4–7 包仍走 scalar；这是四次标量 parser，不是四 lane SIMD。multiarch 声明不证明部署选择 |
| Core handoff：整 frame pointers、x4 parser/hash、header/data/opaque2 预取、整 frame 发布 | [`worker_handoff_node`:439](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:439) 调 parser/hash，末尾 [enqueue:584](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:584)；[device-input:56](/home/js/backup/backup/Git/vpp/src/vnet/devices/devices.c:56)、[port-rx-eth:55](/home/js/backup/backup/Git/vpp/src/vnet/dev/port.c:55)；[software enable:1347](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:1347)；core [multiarch:64](/home/js/backup/backup/Git/vpp/src/vnet/CMakeLists.txt:64) | primary [count=1:1213](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1213) 与 completion-return [count=1:1865](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1865)；已有 retained rejection | 当前已有可转移项按目的 worker 一次发布，分别结清成功/失败项；保留 Canonical Owner 与 credit | x4 在≥4进入，≥8才预取；fork 的 `drop_on_congestion=1` 会 [free 拒绝包:343](/home/js/backup/backup/Git/vpp/src/vlib/buffer_funcs.c:343)，与产品 retained obligation 合同不同。只配置 hardware handoff 时软件 node 不启用 |
| 自定义 ACL：整 frame pointers 和 bulk next；tuple/matcher 单包调用 | [`acl_node_fn`:122](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:122) 每包 fill/search，末尾一次 `enqueue_to_next`；[L2/L3 arc:201](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:201)、[enable:357](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/acl.c:357)；[CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/CMakeLists.txt:15) | [policy:1596](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1596)、[consumer:1751](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1751)、[terminal:1964](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_packet_graph.c:1964) 逐包取 buffer；普通 enqueue count=1 | 将 pointers 与输出 indices 的准备/提交对齐 frame；可变 Flow/CT/身份事实仍按原顺序观察 | 无显式 x4/look-ahead；命中计数、trace 仍逐包。它是 `stellar_acl`，不能借上游 ACL pipeline 的证明为其背书 |
| ACL 单 key vector 比较与 hash 特殊指令 | 上述 node → [`acl_lc_search_by_pkt_info`:307](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/look_context.c:307) → 一次 `bihash_search_40_8`；[40B key compare:82](/home/js/backup/backup/Git/vpp/src/vppinfra/bihash_40_8.h:82) 有128/256/512位分支和 scalar fallback | 产品 [masked-key:953](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_l4_policy.c:953) 同样一查询一次准备；已有单查询 NEON 的历史 ELF 证据见 [10/08 调查 §2.2](../2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md#22-已有真实的单查询-neon) | 区分一个 key 内向量化与多个查询并行；先找到多查询独立工作窗口 | 此 header 与 fork history 的上游 `b9c8c57e983246ec034bc9059b1740558c951d51` 字节相同。本轮未验证实际 ISA，也未发现此 caller 的多 key scheduler |
| LPI：整 frame pointers、下一包 header/exdata 预取，payload/stop/max-detect guard | [`stellar_lpi_node`:676](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:676) → [单包 wrapper:574](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:574) → [`lpi_detect`:287](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_core.c:287)；[TCP/UDP arc:462](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:462)、[enable:190](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:190)；[CMake:19](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/CMakeLists.txt:19) 链 libprotoident、multiarch 区为空 | 已有 [LPI stop/no-payload:615](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_flow_lpi.c:615)，预算 [20次/32KiB:5](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_lpi.h:5)；[独立 SNI:157](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_flow_sni.c:157) | 输入准备与“少做检测”可互补；保持 LPI/SNI 不同完成条件 | 识别仍单 session；stop 后仍传播 tag、计 seen、处理 next。动态 exdata/懒分配不是产品有界资源布局模板 |
| Transaction：整 frame pointers、下一包 header/exdata 预取，HTTP tag guard | [`stellar_transaction_node_fn`:1028](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1028) → HTTP 包单次 transaction；[arc:954](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:954)、[enable:570](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:570)；[scanner CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/CMakeLists.txt:15) | 尚无与此业务相同的 node；共享 graph 仍逐包获取 pointers | 对明确相关输入才进入昂贵 consumer，预取对象要与实际下一次访存对应 | 此机制不代表主 scanner 已批量化；HTTP transaction 自身仍单包 |
| Scanner/mapper：first-packet、周期和 decoder/字段 guard | [主 node:1118](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1118) → [`scanner_on_vlib_buffer`:3752](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3752)；[mapper:1227](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1227) 只 first-packet tag 进入，已有 context [return:3993](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3993)；同一 [enable:551](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:551)/CMake | owner-local Flow 及 LPI/SNI 已避免部分重复工作；规则 facts/cache 需完整语义 guard | 用相关事实和变化条件省工作，保留当前包与同 flow 顺序 | 主 node 逐包 get-buffer，无显式窗口预取；[maat wrapper:1086](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_maat.c:1086) 是单字段/单 state API，不能推断外部 maatframe 有/无内部 SIMD |
| Enforcer/appsketch：allow/drop、epoch 与 payload 上限 | [enforcer node:412](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer_node.c:412) → [规则归约 epoch:2070](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:2070)；[enable/arc:177](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer_node.c:177)、[CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/CMakeLists.txt:15)。[appsketch node:978](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_node.c:978) → [signature epoch:136](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_scanner.c:136)；[enable:89](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_plugin.c:89)、[arc:434](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_plugin.c:434)、[CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/CMakeLists.txt:15) | 产品需按 snapshot、facts、winner/NoMatch 合同复用；无证据可复制 fork 永久 allow/drop 缓存 | 审查每项 guard 是否涵盖配置与事实变化；保持归因/计数 | 两个主 node 仍标量。appsketch [payload上限:946](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_node.c:946) 后仍执行 Lua/context/signature，并非整个 node 早退；链接 maatframe/Lua/PCRE 等不证明部署后端形态 |
| Deprecated NFQUEUE：单包分配，native next-frame 累积 | [input:32](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/node.c:32) `recv`→ callback→[alloc(1):133](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/device.c:133)→[set_next_frame_buffer:185](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/device.c:185)；[注册:151](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/node.c:151)、[open后node状态:319](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/device.c:319)、[CMake:1](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/CMakeLists.txt:1) | Root [callback预算64:1027](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_root_nfqueue_adapter.c:1027)，每包 [external submit:1275](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_root_nfqueue_adapter.c:1275) 创建 singleton | 仅说明 graph 聚合与 recv/allocation 粒度是不同问题；不作为产品实现参考 | 明确 deprecated；recv 逐 datagram、alloc count=1；有声明/可达路径，未证实部署启用，不能称当前 NFQUEUE 批 syscall |
| Core TUNTAP：reserve 批补充，但 readv 是一个包 | [`tuntap_rx`:239](/home/js/backup/backup/Git/vpp/src/vnet/unix/tuntap.c:239) 一次 readv，多个 iovec 拼一个 packet chain；[set-next/return1:368](/home/js/backup/backup/Git/vpp/src/vnet/unix/tuntap.c:368)、[node:387](/home/js/backup/backup/Git/vpp/src/vnet/unix/tuntap.c:387)；[Linux-only build:1099](/home/js/backup/backup/Git/vpp/src/vnet/CMakeLists.txt:1099) | TUN [read callback:317](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_vpn_tun_adapter.c:317) 单包 read/alloc，可循环64次；[submit:378](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/product_vpn_tun_adapter.c:378) 仍 singleton | 分开讨论 reserve、frame 与系统调用批次 | [默认未 enable:480](/home/js/backup/backup/Git/vpp/src/vnet/unix/tuntap.c:480)，未开启直接 return；不能把 NIC bulk RX 或 readv 名字当 Android 多包 TUN 接收证明 |

## 已有基础设施与真正缺口

当前 count=1 的普通 next helper 会追加现有 next frame，官方 [实现:187](/home/js/Git/sakamoto/sakamoto-snort/build-output/pinned-vpp-clean/src/vlib/buffer_funcs.c:187) 已有聚合；native queue 的 [receiver:476](/home/js/Git/sakamoto/sakamoto-snort/build-output/pinned-vpp-clean/src/vlib/buffer_funcs.c:476) 也能把多个 ring element 合并成 graph frame。所以“下游全部 singleton”不成立。真正结构差异是第一跳 external frame 每包新建，以及 sender 每次 [retained调用:78](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/patches/core/0001-vlib-nonblocking-retained-enqueue.patch:78) 重新分组、保留槽位和发布，未跨调用积累。接收端合并不能取消先前已发生的多次 publication。

产品还有 [eventfd pending latch:17](/home/js/Git/sakamoto/sakamoto-snort/src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch:17)，已合并冗余 write；每次 publication 仍参与通知协议。因此不能宣称现在每包必做一次 eventfd syscall，也不能为批处理削弱通知顺序。当前输入形状还限制 x4/未来包预取的机会：先保留一次 callback/当前 frame 中已经存在的有效项，再讨论短窗口；不能等未来包、跨 callback 保存借用对象。

fork 并未证明严格 parse-once：handoff 和 dissector node 都直接调用 `vnet_buffer_flow_dissector`，其 [入口:264](/home/js/backup/backup/Git/vpp/src/vnet/flow_dissector.c:264) 总会重新初始化结果。是否重复解析取决于启用图，不能只凭结果放入 metadata 推定。产品的同 flow 事实、generation、FlowEnd、partial transfer 与 AdapterObligation 仍是逐项合同；整 frame PRE→整 frame Flow/POST 的机械改写不由这些例子授权。

## 开发状态不能由注册宏替代

fork 的 [插件目录发现:22](/home/js/backup/backup/Git/vpp/src/plugins/CMakeLists.txt:22) 按目录排除：默认 `acl` 被排除，但 `stellar_acl` 不在表里，其 target 仍叫 `acl`。这证明自定义 ACL 有候选构建路径，不证明本次实际 build。dissector 与 core handoff 都显式列 multiarch；ACL/scanner/enforcer/appsketch 只列普通 SOURCES，LPI 的 multiarch 区为空。外部库、编译 flags、实际 variant 必须另有 artifact 证据。

也有具体过渡痕迹：[feature_set.h:60](/home/js/backup/backup/Git/vpp/src/plugins/stellar_feature_set/feature_set.h:60) 明称旧 API 改造前的中间方案；[CLI:62](/home/js/backup/backup/Git/vpp/src/plugins/stellar_feature_set/cli.c:62) 调 dispatcher，[dispatcher:127](/home/js/backup/backup/Git/vpp/src/plugins/stellar_feature_set/feature_set.c:127) 对启用 callback 的错误只记录日志，最后返回0。因此仅凭该 CLI 成功也不足以证明所有 feature 已启用。scanner 初始化仍依赖 [后端实例:916](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:916)，其 [默认配置:681](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:681) 开启 stat/perf/hit-path/hit-item，并选择 `/etc/vpp` JSON；这不是实际部署设置。仓库的 [startup.conf:191](/home/js/backup/backup/Git/vpp/src/vpp/conf/startup.conf:191) 只有注释中的 variant/plugin 例子，不提供运行图证明。

可保留的借鉴结论是执行组织：独立准备窗口、访存预取、按 frame 提交，以及完整变化条件下省去昂贵工作。源码不足以给这些方向排性能名次，也不足以称 reference fork 已完成端到端批量 DPI、批系统调用或 Android 性能成熟验证。

<details>
<summary>本轮 fork 文件字节核对清单（路径与 Git blob SHA-1）</summary>

以下每项都将工作树文件原始 bytes 与 `rtk proxy git show 837432be3b6cf496755cfa27b7cca439734eb726:<path>` 比较；37/37 相同。hash 是 Git blob 身份，不是性能或构建证明。

```text
src/plugins/CMakeLists.txt e00a226e59aa25b998b9aa9a63ce172bf5faf12d
src/vnet/CMakeLists.txt 6619c8898af544e810343991412cee6ebac18aba
src/vnet/handoff.c b07b32609756500b9b3ae74a3a66f57aa99ea708
src/vnet/devices/devices.c 4490e8ffa5cc35b01291d953759385053f26df2b
src/vnet/dev/port.c 94f150458655fa6d4d184fbbbf44e74584899cf1
src/vlib/buffer_funcs.c d910b25afacd98a0f8e4e8f22a8859d2410871fa
src/vnet/flow_dissector.c d42fe9e9f52fa73dcf008545a738c225f54aa11d
src/vnet/unix/tuntap.c 78b336f6bbd2db68bf4d9693ecf9971e60f3897b
src/vppinfra/bihash_40_8.h 27207a3a69c1a8b3b83a83e0bfad3abf16095c3b
src/vpp/conf/startup.conf 929106a4c8a6716b2ccf941a35bef39702cf7a49
src/plugins/stellar_dissector/dissector_node.c 107a541a7e4d634c253eb8aa4b12e71c4aa7dcec
src/plugins/stellar_dissector/dissector.c a7753548ceeb7339fc99a2df8ad27da25ab81958
src/plugins/stellar_dissector/CMakeLists.txt 6f9b791f88a24de2dcae00077fe8e68774607c33
src/plugins/stellar_acl/node.c 51ec0136195e641a251a807994d24fcfa35669e0
src/plugins/stellar_acl/look_context.c afcfeb93af4d4d18f27d77731fc82784c905b898
src/plugins/stellar_acl/acl.c 4eeccfe5f00db03c994d97c2c960ac2113b648d5
src/plugins/stellar_acl/CMakeLists.txt d8be91dbd7b74d66ba3c41b9f9650cf3fe3d416f
src/plugins/stellar_lpi/stellar_lpi_plugin.c 292d07f253897d9ee1b928304fb0d22b4c66543d
src/plugins/stellar_lpi/stellar_lpi_core.c faa45a9dc418059741981cd480a86aa322eb1ee7
src/plugins/stellar_lpi/CMakeLists.txt b3d64885b6e84b3e3a6c84ded7b4dd86d6397f8e
src/plugins/stellar_scanner/stellar_scanner_node.c d0a4b66c96337f2b838b6132d6a23c17414aafc9
src/plugins/stellar_scanner/stellar_scanner_plugin.c 10bcbbc993ec70828f37f92bfa520a4d929d4a0c
src/plugins/stellar_scanner/stellar_scanner_maat.c 70002f3898f99f383c3d6a0c873f81fef917c421
src/plugins/stellar_scanner/CMakeLists.txt bc19e96cfd71f3a22587b7832b4cc3a16f76619a
src/plugins/stellar_security_enforcer/stellar_security_enforcer_node.c aaae695cd47052e6bdb84219a688f92a46054280
src/plugins/stellar_security_enforcer/stellar_security_enforcer.c 156b54f2cc1c9e78cf5f90e1fb98fa2d9aa5f6b8
src/plugins/stellar_security_enforcer/CMakeLists.txt 1952d1aeb36695c7e363c6a8a3b21558e367046d
src/plugins/stellar_appsketch/stellar_appsketch_plugin.c 1ba9b87cb2062d77d2407c536594019f12ceed68
src/plugins/stellar_appsketch/stellar_appsketch_node.c 120182b1d843e26ffd532ff759f616b06c6b3409
src/plugins/stellar_appsketch/stellar_appsketch_scanner.c 5f6f878cfc41da60df38933acbb9dd49426b38bf
src/plugins/stellar_appsketch/CMakeLists.txt 8b48f0ffd088dd67c65fcf4532f3c893d860b042
src/plugins/stellar_netfilter_queue_deprecated/node.c 9c3126ef13204ff4b56f4d87cb8db51687ff570a
src/plugins/stellar_netfilter_queue_deprecated/device.c 57cff1adca8da09e4380bac38ee4469d41be4f5b
src/plugins/stellar_netfilter_queue_deprecated/CMakeLists.txt daa69ddb518515c2c166c8435bcfbf21e5eb9383
src/plugins/stellar_feature_set/feature_set.c f01c2588b2f6c3781be48f2b9285a4e5fa85e70c
src/plugins/stellar_feature_set/feature_set.h af0000f2f0dacd52aa57a6c7b6c1917f0d16ddaa
src/plugins/stellar_feature_set/cli.c 83fcfc0fa0e508326fa2d8a269894ecb6dfa6c88
```

</details>
