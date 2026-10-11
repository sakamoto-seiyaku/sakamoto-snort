# 域名匹配现成实现调查

日期：2026-09-15。用途：规则引擎设计讨论中的选型输入，不是最终规格、依赖接入、性能验收或实施授权。

本记录按用户要求持久保存在仓库，结论仍可修订。关联：[完整讨论记录](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)、[iodé 与旧版本调查](2026-09-15_DOMAIN_MATCHER_UPSTREAM_RESEARCH.md)。

**本轮收敛状态：用户接受以下暂定短名单；最终选型等待 ARM64 / 真机数据。实验可后续编排，本轮停止继续推演唯一赢家。**

2026-09-23 后续确认：初版匹配范围为精确名称与自身及子域，复杂 glob / regex 后置；基本名称规范化与不扩大条件的导入原则已确认，见[完整讨论第 23 节](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)。本报告的库候选与实验边界保持。

## 本轮问题与结论

用户已确认精确名称与域名及子域名必须区分；个人终端尤其移动设备优先查询效率和内存，可以减少复杂通配符/正则的功能覆盖。名单来源已有研究，本轮不重复来源调查。运行时保持 VPP-native C、共享不可变规则数据、owner-local 可变状态；域名谓词服务本版 SNI，未来独立 DNS 过滤复用其语义和索引。

**找到了可复用的小型 C 库和生产 C 实现，不必从零编写整个 trie。首轮建议比较 libdatrie 与维护中的 Valkey rax，并保留当前 VPP 字符串哈希作为基线；Knot QP trie 是值得保留的生产代码备选。** 这是能力与接入成本的筛选，不是已经测出的速度/内存排名。没有查到一个无需适配就完整包含我们的域名语义、名单归属、完整 Rank 和快照生命周期的成品。

证据范围：读取官方文档与固定版本源码；未编译 NDK、未在 Android 上运行、未做性能测量，未修改产品或正式规格文档。研究时下载的 libdatrie 源码未导入仓库；下文保留不可变的源码链接，调查结论不依赖临时下载目录存续。

## 必须按实际工作负载评估的要求

1. 精确与包含子域名是不同的终点标志；必须按标签边界匹配，不能让 example.com 命中 badexample.com。
2. 一个查询可命中多个祖先域名和多个名单。匹配器提供相应条件/名单命中，通用引擎仍按完整 Rank 和其他字段选择赢家。
3. 查询路径不做临时堆分配，不复制整份字典给每个 worker；构建/更新可以在配置侧完成。
4. 看完整运行内存：索引节点、名称数据、名单/规则引用、allocator 开销、worker 查询状态，以及更新时的旧版+新版+构建临时数据。
5. 允许功能子集，但必需匹配语义必须准确。仅用 Bloom/XOR 过滤器或短指纹不能成为最终域名判定。
6. 生产项目采用某结构是有价值的参考；其服务器吞吐、字典文件大小或泛型 key 微基准不是手机域名匹配的实测结果。

## 候选总表

| 候选 | 有用能力 | 必须处理的接入问题 | 本轮定位 |
|---|---|---|---|
| libdatrie | 小型 C 库；双数组 trie + tail；公开增量游标；可一趟取得标签边界上的祖先命中 | 域名编码和终点模式；worker 复用游标；tail 分配与更新峰值需要测 | 首轮完整库候选 |
| Valkey rax | 维护中的 C 压缩 radix tree；精确查询不分配；路径内保存 key 字节 | allocator/assertion 独立化；公开接口无一次性全部祖先查询 | 首轮可复用源码候选 |
| 独立 antirez/rax | 更方便直接嵌入，默认 libc allocator | 默认 head 较旧，不能等同当前 Valkey/Redis 的修复状态 | 版本/接入成本对照 |
| Knot DNS QP trie | 实际 DNS 项目使用的 C 实现；精确读无分配；可用简单 allocator | 小支持层提取；祖先迭代器会分配；DNS wildcard 语义不能代替后缀规则 | 生产代码备选 |
| BIND9 QP trie | 原生精确/祖先和所有祖先链能力 | ISC、URCU、内存/引用计数与多版本基础设施较重 | 设计参考 |
| armon/libart | C ART，精确查询轻量 | 完整 key 另存；一些构建分配失败路径需改；公开接口不是祖先查询 | 次选 |
| fanf2/qp | 简小通用 C 结构 | 较实验性；DNS 变体明确不建议使用；需要域名适配 | 算法参考 |
| CMPH | C 静态完美哈希，支持打包产物 | 仍需存储/验证真实 key 与结果；父域查找、构建成本另算 | 后备方向 |
| MARISA | 静态压缩字典、原生 common-prefix search | C++ 构建/ABI和运行时依赖；不能直接视作当前 C 主线的无成本依赖 | 空间优化参考 |
| 当前 VPP hash | 已有 C 基础设施，字符串查找可复用 | 逐后缀查询、名称存储和名单元数据仍需组织；未来独立 DNS 使用要考虑依赖 | 基线 |

## libdatrie：最贴近“小库加薄适配”的候选

固定源码：[665edc5ec1639a81df004d4f92f07a73d5b96aba](https://github.com/tlwg/libdatrie/commit/665edc5ec1639a81df004d4f92f07a73d5b96aba)，提交日期 2026-01-05。NEWS 所列最近发行版为 0.2.14（2025-11-25）。它是 C 实现，库目标由少量 C 文件组成；命令行工具的 locale/iconv 探测不能直接算作库热路径依赖。[README](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/README)、[NEWS](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/NEWS)、[库构建文件](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/Makefile.am)。

公开接口提供精确查询和 TrieState 增量行走。trie_retrieve、trie_state_walk、trie_state_get_data 不分配也不修改字典；root/clone 会分配小状态，但可以初始化时创建，并在每次查询时用 trie_state_copy 从所绑定快照的 root 复制到 worker 私有状态。不能每次查询重新调用 trie_root。[接口](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/trie.h)、[实现](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/trie.c)。

**适配推导**：把规范化名称反向编码/读取，沿 trie 前进，在名称结束或下一个字符是标签分隔符时检查终点。祖先处只接受“包含子域名”标志，完整名称终点也可接受“精确”标志。由公开增量接口即可收集所有相关祖先，不必修改私有树结构。普通 ASCII 主机名可逐字符转换给 AlphaChar，查询侧不必构造大块宽字符副本。具体名称规范化和名单 payload 仍是我们自己的语义。

其结构使用 base/check 两个 32 位索引，并压缩无分叉尾串；作者介绍了构建时的节点搬迁与空槽管理，因此“查询按名称长度”不等于构建成本也只与单个名称相关。[结构说明](https://linux.thai.net/~thep/datrie/datrie.html)。

内存不能仅看双数组：DACell 为 8 字节，但 TailBlock 还有 next_free、data 和 suffix 指针（常见 LP64 为 16 字节），尾串另有分配。save/serialize 可生成文件/字节数据；加载时会分配数组与每个尾串，未见直接 mmap 后原地查询的公开接口。原数据、构建树、加载树和旧快照同时存活时都要算峰值。[数组](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/darray.c)、[尾串](https://github.com/tlwg/libdatrie/blob/665edc5ec1639a81df004d4f92f07a73d5b96aba/datrie/tail.c)。

只读共享与 owner-local 游标从已检查源码看可行，前提是整个借用期间快照保持存活、没有并行写或序列化改 dirty 状态。Android ARM64 源级可移植性看起来良好，但本轮没有完成 NDK 验证。许可证元数据为 LGPL-2.1-or-later；这里不作法律兼容性结论。

## rax 与 QP：生产维护价值和真实代价

详细只读调查：

- [C radix 候选笔记](2026-09-15_DOMAIN_MATCHER_RADIX_RESEARCH.md)
- [DNS QP trie 笔记](2026-09-15_DOMAIN_MATCHER_DNS_TRIE_RESEARCH.md)

Valkey rax 固定到 [05a9c29c62538519d870d6512978f80ac58a758f](https://github.com/valkey-io/valkey/blob/05a9c29c62538519d870d6512978f80ac58a758f/src/rax.c)。与 2020 年独立 rax 相比，它有持续的修复、内存计量和查找优化。精确查询不分配；小支持层依赖 server assertion 与 zmalloc 接口，提取时需要处理。公开 exact lookup 可以按标签前缀重复查询；要一趟取得所有祖先，需要小范围维护适配。它没有现成可重定位的序列化索引格式。此处“维护中”不是直接选择开发 HEAD 交付的建议。

Knot 的 [QP trie](https://github.com/CZ-NIC/knot/blob/990a2430328a0f343b3a2130f801bb6a032a7378/src/contrib/qp-trie/trie.c) 在精确查询路径不分配，可用调用方 allocator，初版可私下构建整树后使用既有快照发布而不采用 COW。然而它的祖先迭代器会分配，库里的 DNS wildcard 查找也不是“覆盖这个名称及所有子域名”的同义操作。使用前者需处理查询状态，或先用多个精确查询适配。

BIND 的 [QP 接口](https://github.com/isc-projects/bind9/blob/c5b5313fc82e47db198d82b72c84aa3275013198/lib/dns/include/dns/qp.h) 很适合参考“返回全部祖先候选”，但其实现的运行时依赖和内存管理体系超过当前小型匹配模块需要。原 fanf2 项目的 [DNS 变体](https://github.com/fanf2/qp/blob/90fc7de8d0b3c9c1aaa5cd9d7b1765b122fad2e5/dns.h) 明确警告不要使用，不能因为文件名带 dns 就当作成熟组件。

这些候选的公开性能材料有各自限制：通用整数/字符串查找不等于祖先域名查询；M4/桌面测试不等于 Android Bionic；整个 DNS 服务吞吐不等于这一索引的开销。QP 文献中的“每项若干 word”经常只计结构开销，不能漏掉 key、payload 和 allocator。

## 其他方向为什么暂不作为首轮主角

**CMPH** 是可用的 C 静态完美哈希库，支持序列化和打包布局。[官方介绍](https://cmph.sourceforge.net/)、[概念](https://cmph.sourceforge.net/concepts.html)。但完美性针对建表集合内部；仅计算出索引不能证明一个未知查询属于名单。需要完整 key 验证及名单 payload，且子域名仍需构造相应祖先查询。因而官方约 2 bits/key 等数字只描述函数，不能当成完整域名库内存。构建复杂度与失败/重试也要预算。此轮只做概念/API筛选，未固定和审计运行时源码。

**MARISA** 的官方文档提供静态压缩字典与 common-prefix search；其维基百科标题数据上的空间结果有参考价值，但不是本产品名单 RSS。它是 C++ 库，需要额外的构建/ABI和运行时依赖安排，接入工作不能当作零成本；不代表 C 包域调用第三方 C++ 库在技术上绝对不可能。[官方仓库](https://github.com/s-yata/marisa-trie)。本轮不以此为理由修改当前 C 主线架构。

**VPP hash 基线**在本地 pinned VPP 的 vppinfra/hash.c/hash.h 中已经存在。字符串 key 有实际字符串比较，名称后缀可以用原字符串内的指针查询，构建在配置侧完成。它能避免新引入数据结构依赖，但不是现成的域名语义模块，也不是已经证实内存最优。bihash 的固定宽度 key 若改用域名摘要，也必须处理真实字符串验证和摘要碰撞。未来 DNS 独立运行的位置还影响其对 VPP 基础库的依赖成本。

TinyCDB 的官方站点在本轮访问失败，未深入核实源码，不进入短名单。通用正则引擎、完整广告过滤引擎和概率过滤器不是当前两项必需语义的首选实现范围。

## 推荐的下一步与判定依据

本轮完成“已有实现筛选”，不冻结最终库：

1. 先以 libdatrie 的公开游标适配和维护中的 rax 为两个主要候选，保留 VPP 字符串哈希基线。Knot QP 若显示接入/内存优势再进入同一轮比较。
2. 同一套规范化名称、精确/后缀标志和 payload 布局；查询必须包括全部相关祖先及名单归属，不能拿 exact-only 微基准比较完整查询。
3. 后续验证应比较：正确命中/未命中、平均与尾延迟、查询分配、运行字典内存、构建时间/峰值、旧新版本同时存活的更新峰值，以及 Android ARM64 构建和执行。
4. 覆盖同名不同名单、多个祖先同时命中、长名称、共享后缀、随机高熵名称、精确不覆盖子域、大小写/尾点规范化与无匹配。热点缓存命中和实际索引查询要分别看。
5. 遵守既定快照发布和完整 Rank；域名匹配模块不自行发放特殊 ALLOW/DROP，也不新增全局共享可变查询状态。
6. 精确/子域匹配是必需能力；2026-09-23 用户已确认初版将复杂 glob/regex 后置，不把它们列为本轮候选实现必须具备的能力。

本轮没有进行上述性能测量。候选缩小后再做有针对性的验证，才能给出“满足我们的效率和内存要求”的结论，不能用上游宣传或泛型数据结构复杂度替代。
