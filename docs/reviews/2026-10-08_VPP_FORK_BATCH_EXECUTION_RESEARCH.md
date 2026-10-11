# 参考 VPP fork：session 之外的批执行证据

日期：2026-10-08。问题：参考 fork 除了 session manager，是否有实际 packet-path 批处理优化，以及哪些执行组织值得 Sakamoto 借鉴。

## 1. 结论与证据范围

**有，但程度不均匀。** fork 的共享 parser 与 worker handoff 明确使用四包展开、向前预取、批量提交；自定义 ACL 使用整 frame 的 buffer 准备和 bulk enqueue。LPI、scanner、security enforcer、appsketch 的主要识别/规则工作仍按包、按 session 调用，没有证据支持“整个 fork 已实现批量 DPI/SIMD 分类”。它们另一类实际优化是让已完成、无相关事实或状态未变化的包少做昂贵工作。下面逐项引用真实入口和调用者，不能把未调用的库能力当作 packet-path 事实。

本次只读审查本地 `/home/js/backup/backup/Git/vpp`：HEAD 为 `837432be3b6cf496755cfa27b7cca439734eb726`，提交日期 2026-04-07；`git diff --name-only -- src` 为空，并逐字节确认下文引用的 28 个源码/构建文件与 `git show HEAD:<path>` 相同。checkout 另有 `build/external` 删除及 `test` 修改/未跟踪内容，不作为本次证据；没有修改外部 checkout。引用的绝对本地链接对应此固定 HEAD，便于当前工作区检查。

已读两个已有调查：[VPP 最佳实践与火焰图](2026-10-08_VPP_BEST_PRACTICES_AND_FLAMEGRAPH_AUDIT.md)、[规则编译器/SIMD 与 VPP batch](2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md)。本文新增的是 **fork 自定义 node 的实际执行路径审查**，没有重新 profiling、跑 foreign fork、构建其二进制或测量新性能。server/router fork 的 metadata、堆分配和依赖不能作为当前 endpoint 产品的布局或实现模板；产品边界仍是 ADR-0006/0007/0008。

## 2. 必须分开的执行机制

| 机制 | 本文判断标准 | 不能据此推出 |
| --- | --- | --- |
| VPP frame 调度与 next-frame 聚合 | node 接收 `frame->n_vectors`，在 frame 中依次处理并追加 next frame | matcher 已经跨包并行；`x1` 必然使下游收到 singleton |
| frame 准备/批量提交 | 一次 `vlib_get_buffers`，或用完整 indices/nexts/threads 数组提交 | 中间 parser、识别、lookup 已批量化 |
| x2/x4 标量展开及 prefetch | 在一个短窗口提前获取独立包、下一窗口访存，并重复调用标量函数 | 真正 SIMD lane 并行或已测到净收益 |
| 单查询 SIMD/特殊指令 | 一个固定长度 key 的 vector 比较，或 CRC 指令加速 hash | 多包 SIMD classifier |
| 条件执行/结果复用 | 没有相关输入、检测已完成、epoch 未变化等情况下跳过具体工作 | 跨包 batch；可以复制其缓存语义到 Sakamoto |

`vlib_get_buffers`、next-frame、bulk enqueue、bihash/vector 原语属于 VPP 基础设施。fork 自定义 node **如何调用它们**才是这次新增证据，不将基础 API 的存在记成 Stellar 独创算法。VPP 的 frame 基线见[官方 VLIB 架构](https://docs.fd.io/vpp/25.10/developer/corearchitecture/vlib.html)；Sakamoto 固定上游 ACL 的两阶段准备/预取及同 flow 修正，已在[已有 batch 调查 §3](2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md)引用固定源码。

## 3. 自定义 packet-path node 的证据表

| 实际节点 | frame 准备与访存 | 昂贵工作的执行粒度 | 提交、计数与冷分支 | 一手源码 |
| --- | --- | --- | --- | --- |
| `stellar-flow-dissector-{l2,ip4,ip6}` | x4；剩余输入 ≥8、next 空间 ≥4 时处理四包，预取后四包 header/data | 四次独立 `flow_dissector` 调用；没有多包 SIMD parser | x4 speculative enqueue，scalar tail；parsed/error 先累计局部值，frame 末更新两次 node counter；trace 条件仍逐包 | [dissector_node.c:103](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:103)，117–182、231–285、288–345 |
| `stellar-worker-handoff`（fork修改的core路径） | 整 frame `get_buffers`；x4；≥8 时预取后四包 header/data/opaque2 | 四次 parser、四次 ingress hash/owner 计算 | 正常一次整 frame `enqueue_to_thread`；trace node flag 在 frame 外提；可选 handoff 统计仍逐包 | [handoff.c:439](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:439)，456–525、558–590；统计398–427 |
| 自定义 `acl-l2-in` / `acl-l3-in` | 整 frame `get_buffers`；无显式 look-ahead prefetch/x2/x4 | 逐包填 tuple、调用一次 `acl_lc_search_by_pkt_info` | 最后一次 `enqueue_to_next`；命中规则的字节/包计数逐包，trace/telemetry 条件逐包 | [stellar_acl/node.c:122](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:122)，130–179 |
| `stellar-lpi` | 整 frame `get_buffers`；逐包预取下一包 header/exdata | 每包更新该 session 的检测上下文，必要时一次 `lpi_detect` | x1 speculative enqueue，已有 next frame 内追加；非 payload/pseudo、stop_detect/max_detect 条件保护识别工作 | [stellar_lpi_plugin.c:574](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:574)，601–637、676–726 |
| `stellar-transaction` | 整 frame `get_buffers`；下一包 header/exdata prefetch | 仅 HTTP tag 包调用单包 transaction 函数 | x1 speculative enqueue | [stellar_scanner_node.c:1028](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1028)，1035–1085 |
| 主 `stellar-scanner` | 逐包 `get_buffer`；该入口无显式 prefetch/x2/x4 | 单包 scanner；内部按当前 decoder/字段扫描 | x1 speculative enqueue；trace 条件逐包 | [stellar_scanner_node.c:1118](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1118)，1125–1163 |
| `stellar-mapper` | 整 frame `get_buffers`；无显式 prefetch/x2/x4 | 只在 c2s/s2c first-packet tag 调用 mapper；已有 context 再次 return | x1 speculative enqueue | [stellar_scanner_node.c:1195](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1195)，1202–1249；[plugin.c:3982](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3982) |
| `stellar-security-enforcer` | 逐包 `get_buffer`；无显式 prefetch/x2/x4 | 单包 enforcement；allow/drop fast path，epoch guard 保护规则归约 | x1 speculative enqueue；DROP event logger 与 trace 在对应分支；统计调用仍逐包/逐事件 | [enforcer_node.c:412](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer_node.c:412)，437–471；[enforcer.c:2017](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:2017)，2038–2097 |
| `appsketch` | 逐包 `get_buffer`；无显式 prefetch/x2/x4 | 单 session：appid 收集、Lua/context 提取、signature 处理 | x1 speculative enqueue；payload packet 上限只保护其中部分收集工作，不能称整 node 早退 | [appsketch_node.c:929](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_node.c:929)，946–975、978–1018 |

**这个表不覆盖全部 fork 插件或实际启用图。** feature 注册确定它们可进入哪些 arc，运行时是否开启及流量比例未测。这里的 dissector/handoff 是为解释共享 ingress 和 ACL 输入准备而补充的审查，不将上游 DPDK、ip-input、rewrite 等现成节点的展开代码归为 fork 新优化。

## 4. 最有借鉴意义的两条软件批执行路径

### 4.1 Parser：四包展开加计数外提，parser 本体仍独立

parser 主循环同时准备四个 buffer、四个结果位置和四个 next，预取未来四包，再依次调用四个 parser。因此“把独立工作放进同一个短窗口”是源码事实；是否编译器将函数内部操作向量化、访存并行增加多少、Android 上是否净获益，本文未测。[dissector_node.c:117](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:117)，126–182。

其 x4 入口要求 **8 个剩余输入**，不是见到4个包就进入 x4：需要留下4个可预取输入。剩余4..7也走 scalar while；不能从 `x4` 推定小 frame 的利用率。源码 tail 注释写“less than4”，实际条件仍以117行与289行为准。[同文件:288](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:288)。

parsed/error 在局部 `u32` 累计后，frame 末调用两个 node counter，这是确定的计数更新摊销。逐包 trace 分支没有被移出；frame 准备也不是完整“两阶段先 parse 整 frame、再全部执行状态工作”。[同文件:341](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:341)。

### 4.2 Handoff：整 frame 产生 destination 数组并提交

handoff 的正常路径先为当前 frame 准备 buffer pointers，按四包窗口解析/计算 owner，最后一次把原输入 index 数组与逐包 thread 数组交给 VPP。≥4的输入可进入 x4，只有≥8才预取后四包。这使准备和 queue publication 的调用粒度与 frame 对齐，不是每算出一个 owner 就提交一包。[handoff.c:454](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:454)，464–525、583–585。

并非全部工作均外提：统计开关保护的 counters 在每包 `handoff_statistic` 内更新；接口数据获取、parser 与 hash 也分别调用。frame 级 trace flag guard 与最后的 congestion counter 是可确认的外提项。错误分支仍明确处理其输入集合。[handoff.c:398](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:398)，482–519、558–590。

正常bulk调用最后参数为 `drop_on_congestion=1`，底层会free未进入queue的buffers，`n_enq`用于统计差额。这与Sakamoto retained rejection需保留buffer并结清AdapterObligation的合同不同；不能直接复用此调用模式处理产品partial transfer/overload。[handoff.c:583](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:583)；[buffer_funcs.c:343](/home/js/backup/backup/Git/vpp/src/vlib/buffer_funcs.c:343)。

源码会把解析结果存入 buffer，但**不能凭存储位置推定任意节点组合下严格 parse-once**：`vnet_buffer_flow_dissector` 本体一进入即重新初始化结果；handoff 与 dissector node 都有直接 caller。是否重复经过这些入口需要启用图/调用路径证明。[flow_dissector.c:264](/home/js/backup/backup/Git/vpp/src/vnet/flow_dissector.c:264)，268–272；[dissector_node.c:87](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/dissector_node.c:87)；[handoff.c:431](/home/js/backup/backup/Git/vpp/src/vnet/handoff.c:431)。

### 4.3 NFQUEUE/TUN入口不能拿NIC批收包来代替判断

fork里可定位的 `stellar_netfilter_queue_deprecated` input循环 `recv(...,MSG_DONTWAIT)` 直到无数据，再由callback每包分配一个buffer、填metadata、调用 `vlib_set_next_frame_buffer` 追加node的next frame；它没有每包创建独立external frame。这里接收系统调用仍单次逐message、buffer allocation仍count1，并非整个入口都已bulk。目录名带deprecated，本次未验证它是否在部署artifact编入、启用，不能以其存在宣称fork当前NFQUEUE性能。[NFQ node.c:32](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/node.c:32)，49–59；[device.c:130](/home/js/backup/backup/Git/vpp/src/plugins/stellar_netfilter_queue_deprecated/device.c:130)，133、185–188。

core `tuntap_rx` 每次node调用只 `readv` 一次、返回1个packet；其多个iovec是一个packet分布在多个VPP buffers的chain，不是多包批读。该路径有成批补充RX buffer reserve，末尾用 `vlib_set_next_frame_buffer` 提交一个packet。这说明参考fork也不能概括为“所有TUN入口天然读成大frame”，更不能把NIC路径的批量rx表现套到Android TUN。[tuntap.c:239](/home/js/backup/backup/Git/vpp/src/vnet/unix/tuntap.c:239)，247–288、297–325、368–377。

## 5. 规则/识别层做了什么，没证明什么

### 5.1 自定义 ACL 与上游 ACL 必须区分

本 fork 的 `stellar_acl` 是自定义 lookup-context matcher；不是前一调查引用的上游 `plugins/acl/dataplane_node.c` pipeline。其实际 node 一包一次调用，matcher 遍历 lookup contexts、mask pool，对当前包做五个 `u64` AND，然后单 key bihash，命中后遍历 collision rule indexes并做两个端口 range 检查。没有 frame 参数、短窗口独立 hash 状态或多包 lane scheduler。[look_context.c:294](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/look_context.c:294)，307–355。

**它确实间接使用单 key SIMD。** `bihash_40_8.h` 对一条40B key 的比较提供128/256/512-bit路径与scalar fallback，hash按编译能力选择CRC32c或XOR+xxhash。该文件与 fork history 中 FD.io 上游提交 `b9c8c57e983246ec034bc9059b1740558c951d51` 的文件字节相同；这属于继承的 VPP hash-table 原语，不是 fork 多包分类器。是否运行某个 vector 分支仍取决于实际 build/ISA，本文没有该fork ELF证据。[bihash_40_8.h:61](/home/js/backup/backup/Git/vpp/src/vppinfra/bihash_40_8.h:61)，82–100。

规则计数使用按 `thread_index` 的 VPP combined counter，不过 node 每个命中包仍调用一次、遍历 chain length；不能将 worker-local 自动等同于 frame 汇总。[node.c:170](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:170)；[counter.h:14](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/counter.h:14)。

### 5.2 LPI：明确的条件检测与停止检测

LPI先跳过无payload与pseudo包，读取/懒建 per-session context，复用累计protocol tags；只在 `stop_detect !=1` 且检测包数未到上限时更新上下文并调用 `lpi_detect`。core 再调用一次 `lpi_guess_protocol` 与可选 extended guess，对不需继续探测的类别设置 stop。这些是实际少做识别工作的机制，与 header/exdata prefetch互补，但都不是批量 LPI。[stellar_lpi_plugin.c:574](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:574)，601–637；[stellar_lpi_core.c:287](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_core.c:287)，290–309。

即使 stop_detect 已置位，payload/上下文读取、seen计数、tag传播及next处理仍可能发生；不能称“整个node零成本fast path”。源码懒分配策略也不是当前 Sakamoto 预分配/有界资源合同的直接模板。

### 5.3 Scanner/enforcer/appsketch：变化驱动与相关事实保护

scanner 静态 tunnel/VLAN/MPLS/L3/L4 与 mapping tag 扫描由首次/周期 guard 保护；decoder字段只对当前包的 decoded-as集合执行；FQDN有 `scanned_fqdn` 一次性 guard，negate更新也有已扫描状态与包数条件。这比“所有字段每包重新扫描”更克制，实际仍每包读取时钟/上下文并执行相关分支。[stellar_scanner_plugin.c:3752](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3752)，3771–3809、3810–3831、3867–3884。

scanner的字段调用链是单session `scanner_scan_fields` → 单字段包装器 → `maat_scan_string/integer/flag/ipv4_port/ipv6_port/stream`；string-array循环是**同输入的多个字段值**，不是多个packet lane。外部 `maatframe` 的实现和实际ISA没有在本次审查范围内，不能断言它没有内部SIMD，也不能反过来声称这里实际用了batch DPI。[plugin.c:536](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:536)，545–623；[stellar_scanner_maat.c:1086](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_maat.c:1086)，1096–1142、1166–1176；[scanner CMake:32](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/CMakeLists.txt:32)。

security enforcer有已有allow、drop_session的早退/动作路径；只有规则尚未选定或允许继续扫描、且maat epoch变化时才调用 `highest_priority_rule_get`，后者对该session的maat state取规则结果。fast path仍可能写telemetry、更新counter或发送reset，不能称完全绕过工作。其缓存终结条件与Sakamoto完整snapshot/事实guard不同，应借鉴“用正确变化条件消除工作”，不直接复制allow/drop永久缓存。[enforcer.c:2038](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:2038)，2048–2097；[同文件:1953](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:1953)。

appsketch对payload采集设置per-session上限，并用maat epoch保护signature结果提取、对新signature做set difference，随后处理新增appid/Lua字段；signature过程可能循环到没有新结果。达到payload上限后仍有context Lua提取和signature过程，不能报成“到上限整个node直接return”。这仍是单session增量执行。[appsketch_node.c:874](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_node.c:874)，882–916、929–975；[stellar_appsketch_scanner.c:136](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/stellar_appsketch_scanner.c:136)，143–147。

## 6. Build、trace和counter的判断边界

dissector的CMake明确把 `dissector_node.c` 放入 `MULTIARCH_SOURCES`；其余本次重点ACL/scanner/enforcer/appsketch仅列SOURCES，LPI的MULTIARCH区为空。**这不否认编译器autovectorization或链接库自身ISA选择，只说明这些文件没有在此CMake显式列成multiarch源。** 没有构建flags、compile_commands、node实际选择和fork binary，就不能声称其部署运行了AVX/NEON某路径。[dissector CMake:20](/home/js/backup/backup/Git/vpp/src/plugins/stellar_dissector/CMakeLists.txt:20)、[ACL CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/CMakeLists.txt:15)、[LPI CMake:25](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/CMakeLists.txt:25)、[scanner CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/CMakeLists.txt:15)、[enforcer CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/CMakeLists.txt:15)、[appsketch CMake:15](/home/js/backup/backup/Git/vpp/src/plugins/stellar_appsketch/CMakeLists.txt:15)。

明确外提的项目是parser的frame末node counters、handoff的frame级node trace guard与末尾拥塞counter，以及几个node的整framebuffer-pointer准备。并不存在“全fork所有诊断与配置检查都已移到frame外”的证据。ACLtrace/telemetry、LPItrace、主scannertrace、enforcertrace仍在逐包函数或loop内条件检查；handoff统计虽然关闭时有guard，启用时仍按包更新。[ACL node.c:69](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:69)、[LPI plugin.c:650](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:650)、[scanner node.c:1145](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_node.c:1145)、[enforcer node.c:453](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer_node.c:453)。

scanner/enforcer counters用thread-indexed VPPcounter，context也主要来自session；这是locality机制。它与“一个frame相同rule/action先汇总再更新”不同，后者不能从这些函数签名推定。[scanner_metrics.c:69](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_metrics.c:69)、[enforcer_metrics.c:129](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer_metrics.c:129)。

## 7. 对本产品讨论的具体含义

这次新增证据支持三个互补方向：**保住已经到达的frame输入与bulk提交机会；对纯输入/独立lookup使用短窗口准备、交错和有依据的prefetch；对不需要执行的工作使用完整语义guard消除。** 无需先将完整规则解释器改成跨包SIMD，才能体现VPP的批执行优势。fork本身也展示了bulknode外壳与逐包复杂状态工作的组合。

借鉴执行组织时仍必须保持Sakamoto每包AdapterObligation、generation、Canonical Owner、同flow事实更新和完整规则结果。pure packet准备可向前，Flow/CT/LPI/SNI与身份/配置有效性不能被盲目冻结为frame开始时的事实。不得把全frame PRE做完再全部Flow/POST当作机械优化；上游ACL对预测session的同flow修正，已在[已有调查§3/§5](2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md)记录。

现有有效产品吞吐采样的active rules为零，能支持空视图准备/入口提交等方向，不能拿来给一般DPI、规则SIMD或本fork优化贡献排性能名次。本文没有fork吞吐、frame-size分布、cycles/packet或ARM64实测；源码证明的是执行方式与可避免调用，不是速度提升百分比。产品端到端提交链、优先级与验收边界在下节单独交叉核对。

## 8. Sakamoto 的端到端批处理缺口与投入判断

以下复核基于当前工作树，不把 fork 的静态代码等同于 Android 上的速度优势。当前 `product_packet_graph.c`、`product_root_nfqueue_adapter.c`、`product_vpn_tun_adapter.c`、`product_l4_policy.c` 的 SHA-256 均与[已有性能审查 manifest](assets/2026-10-08-vpp-practice-audit/manifest.json)一致；此前源码发现仍适用。原始 perf 来自该审查固定的历史 artifact，源码身份相同不表示本轮跑过新的设备比较。

### 8.1 四层成本必须分别审查

| 层次 | 当前源码事实 | 可借鉴的组织方式 | 投入边界 |
| --- | --- | --- | --- |
| 入口形成 frame | Root/TUN 回调最多执行 64 次非阻塞接收；每个成功提交都创建单包 admit frame | 将本次回调已经取得并建立有效 obligation 的 native buffers 聚合提交 | 已有确定结构证据，适合第一批；不能等未来包、跨回调攒借用对象 |
| 节点处理与 next enqueue | policy、consumer、egress 每包取 buffer、判断并调用 count=1 helper | 整 frame 准备 buffer pointers；按原顺序处理状态；对实际存活输出批量 enqueue | next helper 已能聚合下游 frame，主要消除重复 helper 与准备；不能把 stale/free/FlowEnd 原样发出 |
| 跨 worker 发布及 completion return | primary handoff 与 return helper 也按 count=1 调 retained enqueue | 在当前节点已有工作内，将已准备且可转移的 indices 按目的线程一次发布 | 每项 credit、拒绝归属、generation 与恰好一次结清仍独立；结构值得投入，但不沿用 fork 的拥塞自动 free |
| 系统 I/O | TUN 每包 write，NFQUEUE 逐 obligation 发 verdict | 只有平台接口确实支持且保持逐消息语义时才评估系统调用聚合 | graph/frame batching 本身不会自动减少这些调用；本轮尚未评估合法 I/O batch 实现 |

源码入口：[Root 回调](../../src/product/vpp/product_root_nfqueue_adapter.c#L1027)、[TUN 回调](../../src/product/vpp/product_vpn_tun_adapter.c#L317)、[external 提交](../../src/product/vpp/product_packet_graph.c#L4043)、[policy](../../src/product/vpp/product_packet_graph.c#L1587)、[consumer](../../src/product/vpp/product_packet_graph.c#L1747)、[egress](../../src/product/vpp/product_packet_graph.c#L1790)、[primary handoff](../../src/product/vpp/product_packet_graph.c#L1185)、[completion return](../../src/product/vpp/product_packet_graph.c#L1851)。行号以本轮工作树为准。

批处理的第一层收益是摊薄 frame/dispatch、helper 与公共准备；第二层是用小窗口交错和预取隐藏独立访存延迟；第三层才是合适内核中的实际 SIMD。VPP 官方架构说明输入形成工作向量、dispatcher 将其沿 graph 推进，并解释同一节点后续元素复用已暖的指令缓存。[官方 VLIB](https://docs.fd.io/vpp/25.10/developer/corearchitecture/vlib.html#graph-node-dispatcher) 这不意味着调用 `VLIB_NODE_FN` 后所有单包成本都会由框架消失。

### 8.2 本轮新增：跨 worker 的 count=1 确实浪费 frame-queue 聚合机会

此前审查区分了 external singleton frame 与可聚合的 next frame。本轮又核实了第三种边界：native frame queue。

产品 [core patch 0001](../../src/product/vpp/patches/core/0001-vlib-nonblocking-retained-enqueue.patch#L78) 中 retained wrapper 按至多 `VLIB_FRAME_SIZE` 的工作组调用原生 inline helper，改变的是 nonblocking rejection 的归属，不增加跨调用合并。固定 pin 的 [buffer_funcs.c](https://github.com/FDio/vpp/blob/9258530f3804a152578ce11cc7c8a1e9eab88ed0/src/vlib/buffer_funcs.c#L257) 在每次、每个目的线程分配新的 ring element，通过 tail CAS 保留槽位；随后压缩该目的线程的 indices，设置 `n_vectors` 并 release 发布 `valid`。旧槽位不是可继续追加的 next-frame cache。

本轮从固定官方 raw URL 下载完整文件至 `/tmp/sakamoto-vpp-batch-buffer-funcs-9258530.c`；其 Git blob SHA-1 为 `ce09a51c600b30e3251bb2c657d67f636a21d58c`，与 core patch 0001 的 base blob 完全一致。因此这里不是用另一个 fork 的近似实现推定本产品行为。

当前 [primary_handoff](../../src/product/vpp/product_packet_graph.c#L1213) 和 [completion_return_try](../../src/product/vpp/product_packet_graph.c#L1865) 均传 count=1。条件化例子：在同一 source stage 已有 8 个可转移包，目的线程相同、容量足够且全部成功时，当前 8 次调用发布 8 个各含 1 个 index 的槽位；一次合法的 8 项调用可发布 1 个含 8 项的槽位。它减少的是发布次数及 ring 槽位需求，不减少 8 个包各自占用的 admission credit，也不是“性能提升 8 倍”。

Android [patch 0019](../../src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch#L122) 在每次成功发布后通知目标 worker；其 [wakeup latch](../../src/product/vpp/android/patches/0019-vpp-worker-notification-latch.patch#L17) 已合并 eventfd write，但每次 publication 仍参与顺序化 exchange。聚合 native publication 可以同时摊薄这一工作；不能宣称现在每包必有一次 eventfd 系统调用，也不能为省原子而弱化已接受的睡眠/通知协议。

该发现应纳入专项的独立项。实际 remote 比例、每目的线程 batch 大小、ring 饱和频率和 CPU 权重尚未从现有采样量化；它不取代先前已有证据支持的首批排序。实施 bulk retained 路径时，必须用返回的 failed indices 逐项恢复未转移所有权、释放对应 credit 并走原结果路径；成功转移后不能再读该 native buffer。部分成功不等于整个 batch 的共同终态。

### 8.3 当前已有的优化也要保留

不能把“尚未系统优化执行组织”解释为当前每包始终运行全部昂贵功能：

- `product_flow_entry_identify` 已有 LPI 停止条件；限制为 20 次、32 KiB，并在停止或无 payload 时跳过后续 guess。[实现](../../src/product/vpp/product_flow_lpi.c#L615)、[预算](../../src/product/vpp/product_lpi.h#L5)
- SNI 有独立 stop gate、时间与包数预算；LPI 停止不能阻止仍合法的 SNI 后续完成。[SNI gate](../../src/product/vpp/product_flow_sni.c#L157)、[独立观察顺序](../../src/product/vpp/product_flow_lpi.c#L607)
- Flow/cache/部分 observation 状态已按 owner 私有；observation 有有界 flush，不应笼统称为全部共享计数或同步逐包导出。[owner-local observation](../../src/product/vpp/product_observation.c#L118)、[flush](../../src/product/vpp/product_observation.c#L215)
- 单查询 masked-key 已出现编译器生成的 NEON；当前缺的是跨查询执行组织，不能声称完全没有 SIMD。[既有 ARM64 证据](2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md#22-已有真实的单查询-neon)

fork 的 first-packet、识别完成、HTTP 条件与 action 快路径适合作为审查问题；其具体业务语义不能直接套入我们的 CT/LPI/SNI、完整规则重求值和归因合同。

### 8.4 与现有火焰图合并后的判断

**“最初主要解决 VPP 跑通，执行组织优化欠缺”有源码依据；“这一缺口已证明是最大的端到端性能瓶颈”尚无依据。** 第一跳 singleton 与 native handoff singleton 是确定的组织缺口，x4/prefetch 缺失则仍需结合工作形状与热点判断。标量状态处理本身不是缺陷。

[已有审查](2026-10-08_VPP_BEST_PRACTICES_AND_FLAMEGRAPH_AUDIT.md#4-投入排序与证据强度)的证据仍决定近期顺序：

1. 空 view/无适用 subject 绕过没有收益的 cache guard 准备，保留完整 NoMatch 与后续 Flow 维护。匹配 ELF 中 128-byte FNV 循环占该 TCP 窗口 3.24% VPP 样本，是已发生工作的证据。
2. Root/TUN 本回调已有包形成 native frame；普通节点 bulk enqueue、重复准备去除、关闭诊断时避免无益 RMW。它们直接修补现有执行路径。
3. native primary handoff/completion return 的聚合单独审查与回归；HEV 重复 TLS/context 访问也可独立处理。后者互斥 self 合计 6.07% 属于特定窗口证据。
4. 在明确 kernel 上评估小窗口预取/交错。通用规则多查询 SIMD、批量 DPI 或整体数据布局改写，仍需含规则/对应识别负载的证据才能排高优先级。

这些百分比不是吞吐提升承诺。有效吞吐窗口均为零规则，不能量化大规则候选或 residual 表达式成本；inclusive 不能相加。VPN TCP 的 TUN completion、VPN UDP 的 protected socket send、Root UDP 的 verdict 路径都有较大 inclusive 权重，graph batch 不会消除对应 kernel/transport 工作。[已有 I/O 边界审查](2026-10-08_VPP_BEST_PRACTICES_AND_FLAMEGRAPH_AUDIT.md#11-io路径很热但不能用frame-batching解释全部成本)

### 8.5 后续改动的窄范围验收

现有证据足以决定投入，无需为了这个决定先建立新的大规模 benchmark campaign。若进入实施，应沿现有 seam 做完整语义及真实生命周期回归，再在同条件负载上作窄范围前后比较：

- 结构指标：入口 callback 的有效包数/提交 frame 数；各节点 calls、vectors/call；每目的 worker 的 publication 数、vectors/publication、拒绝及 credit 使用。CPU 采样或 sender send 次数不能替代实际 frame 指标。
- 成本指标：对应节点 clocks/vector 或 CPU/packet；同时保持相同 artifact、模式、规则数、包形状和计量区间。不能把更大的 vectors/call 本身当作速度证明。
- 有状态行为：同 flow 原包顺序、PRE/Flow/POST 和完整 winner/NoMatch/availability/归因；snapshot reader 保护和新旧 generation 不混用。不是先把整 frame 的可变 Flow facts 冻结成一份旧值。
- native 生命周期：partial enqueue、stale/free、fragment、FlowEnd、EAGAIN/fault、stop/restart、credit 及恰好一次 settlement。数组遵守 pinned helper 的可读 padding 要求；side-event 与数据包发布顺序有明确合同。
- 低负载边界：不等待未来包凑批、不跨 callback 保存借用对象；HEV return 在 callback 返回前完成 native scheduling；睡眠 worker 的孤立包、timer/return progress 与现有有界预算不退化。必要的 VPP/lwIP 两次所有权 copy 仍保留。

本轮完成静态源码核对与已有证据综合；没有产品修改、新设备负载、优化速度/功耗证明或正式实施状态变更。
