# nDPI 能力与 VPP 适配边界

研究日期：2026-09-25。仅为讨论材料；T12 后暂停实施，不改变正式规格、ADR、Plane 或 Goal。已确认保留启发式，本研究不重新收紧这一决定。

核对官方 `dev` 提交 **4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b**（提交时间 2026-09-24），不是浮动分支或营销能力列表。以下精确缓存大小、API 和状态仅对应此提交；未编译、未做 ARM64 性能验证。[固定源码](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c)

## 能做到什么，是否需要保留更多包

**nDPI 能提供更丰富的跨包检测、候选淘汰和 TLS/QUIC 解析；不要求扣住原包，但某些 detector 会复制并保留字节。** “多看几包”与“存下几包”应分开：

| 做法 | 需要保存什么 | 当前产品边界 |
| --- | --- | --- |
| 后续包到达时继续同步检查 | 阶段、方向、少量索引等状态 | 已有模式；不必提高预算 |
| 增加尝试包数 | 更多调用机会，未必更多常驻字节 | T12 为 20 次 payload 尝试／32 KiB 检查额度；调整须另决策 |
| 复制有限握手字节 | 自有有界缓存；原包可立即继续 | TCP 必须复用统一缓存，QUIC 独立有界组装 |
| 通用双向 TCP 重组 | 序列区间、缺口、去重及内存／工作／时间预算 | nDPI 不可直接当作这一层的替代品 |
| 扣住原包等待判定 | VPP buffer 所有权及待决 verdict | 正式规格不允许为 SNI 等待，也没有自动前 N 包放行 |

现有 56 字节是 **LPI 状态实测值**，不能套到 nDPI。额度耗尽保留已发布事实、停止生产者并记录原因，不能生成最终 Unknown 或无 SNI；识别与 SNI 的停止独立。本包截止前同步发布可影响本包，迟到结果只影响后续包。[T12](../interfaces/T12_PUBLISHED_PROTOCOL_FACTS.md)、[正式规格 §6](../product/UNIFIED_RULE_ENGINE_SPEC.md#6-lpi-sni-and-domain-matching)

三个源码例子说明实际差异：

- **WireGuard**：检查保留字节、148/92 字节握手及双向 index；transport 路径分阶段比对 index，只需记状态，不保存旧包。initiation 路径另有 `num_processed_pkts > 1` 即认可的分支，没有据此验证先前包也是 initiation；还有 204/100 字节变体路径，并非每次命中都经过完整双向握手验证。[wireguard.c](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/wireguard.c#L58-L198)
- **TLS/TCP**：每方向 `message` 懒分配 2048 字节并可扩容；仅在 `seq == next_seq` 时追加，解析后移走已消费 record，入口跳过标记为重传的包。它能拼接所需连续数据，却不是保存任意乱序段、补齐所有缺口的通用 TCP 引擎。不能说“完全无缓存”，也不能用它承诺完整乱序恢复。[追加](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/tls.c#L467-L532)、[消费](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/tls.c#L1440-L1643)
- **QUIC**：Initial 解密有临时明文分配；CRYPTO ClientHello 单片完整时直接解析，否则该提交分配 4096 字节及 512 字节接收 bitmap，处理乱序、重传和重叠后检查无缺口。这个局部容量不是每 Flow 总内存，也不等于完整 QUIC stream 重组。当前代码重叠字节会覆盖，不能直接继承为产品冲突策略；超过容量不能宣称 SNI 不存在。crypto 使用 libgcrypt 或内置 gcrypt_light 分支，须固定构建选项。[解密](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/quic.c#L460-L541)、[组装](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/quic.c#L719-L848)

HTTP 则保存请求／响应阶段和选择性复制 URL、Server 等元数据，处理当前包中的行；同向后续包可继续等响应，不表示拥有统一 HTTP TCP 流重组。可变更／重置分类与元数据的路径也说明其输出不是历史事实集合。[HTTP](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/http.c#L1683-L1735)、[元数据分配](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/http.c#L1080-L1158)

## 完整库接入必须适配的接口

`ndpi_detection_process_packet(module, flow, ip_packet, uint16_len, time_ms, input_info)` 要求 **从 IP 头开始的连续数据**，不是目前借用的 L4 payload。须校验实际可读长度、链式 VPP buffer、IPv4/IPv6 和分片可见性，不能伪造头部来冒充既有 ABI。方向及是否见到连接开头可通过 `ndpi_flow_input_info` 提供；产品方向应稳定映射，时间单位为毫秒。[API](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_api.h#L360-L378)、[输入](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_typedefs.h#L675-L691)

建议接口位置仅作研究：

```text
既有 owner-local Flow + 当前包
  → 私有 provider 适配器（预算、方向、同步借用）
  → worker 独占 module + Flow 所有的 detector 状态
  → 证据／输出映射 → 既有累积 catalog facts → 本包 post-flow 匹配
             ↘ 统一 TCP 字节缓存／独立 QUIC 握手组装（须解决重复持有）
```

module 内写当前 `packet`、时间和调度状态，不能让多个 worker 无锁共用；每 worker 独占 module 是与现有所有权一致的路线，但会增加规则表、自动机、缓存等成本。API 明确初始化多个 module 的调用不可并行，先配置、再 finalize；可选 global context／共享缓存另核同步，不能自动当成不可变注册表。[初始化](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_api.h#L278-L305)、[调用内部](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c#L10790-L10841)

Flow 状态由调用者分配并清零，示例使用 `ndpi_flow_malloc`；产品可研究嵌入／预分配、不能照搬示例的第二张流表。结束时先释放动态成员；`ndpi_free_flow_data` 与同时释放外壳的 `ndpi_free_flow` 不可混用。当前包指针是同步读取的借用，module 的临时 packet 字段可残留指针值，不能跨调用使用；需要跨包的字节由 detector 复制到自有空间。适配器不得延长 VPP buffer 生命周期，并须逐一审计启用 detector 的分配与释放。[示例](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/example/reader_util.c#L937-L943)、[释放接口](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_api.h#L307-L338)、[TLS 复制](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/tls.c#L508-L529)

直接启用原生 TLS buffer，再加产品 TCP 缓存，会重复持有同一握手字节，与“一份 TCP 字节缓存、解析器只留状态和小结果”冲突。可研究禁用重叠解析、共享缓存适配，或让某个实现成为唯一缓存所有者；每条路线都要证明序列／预算合同。没有证据表明换个配置就能零修改复用现有缓存。当前 T12 的“无逐包分配”也不能沿用为完整 nDPI 的既成性质。[正式规格 §6](../product/UNIFIED_RULE_ENGINE_SPEC.md#6-lpi-sni-and-domain-matching)

## 调度与发布语义，比多几条签名更值得参考

注册器按 IP／TCP／UDP／payload 等 selection mask 筛选，Flow 记录已排除 detector；可用 fast callback 优先检查候选。命中后仍可通过 `extra_packets_func` 继续有限包解析元数据。最终 `CLASSIFIED` 后继续喂包只返回已有结果；`PARTIAL` 结果允许变更，`MONITORING` 会持续收包。故不能把“多次调用完整库”直接等同于 T12 的多协议累积观察窗口，HTTP→TLS 等转变需要专门验证。[调度](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c#L9090-L9165)、[额外解析](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c#L10021-L10031)、[状态](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_typedefs.h#L1388-L1412)、[早停](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c#L11032-L11054)

confidence 区分端口、IP、部分 DPI、关联缓存、DPI、激进 DPI、自定义规则；它是证据类别，不是概率分值。hostname 可驱动子分类，而且“DPI”也可能同时包含 WireGuard 的 IP 品牌子分类，因此一个全局 confidence 不能证明每个标签都由 payload 确认。`giveup` 可归并／猜测剩余结果，不是单纯资源释放。应保留证据来源及停止原因，按已同意的启发式政策映射；**本研究既不默认启用端口／IP 品牌猜测，也不擅自禁止原有启发式。**[confidence](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_typedefs.h#L1116-L1138)、[品牌子分类](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/wireguard.c#L43-L54)、[giveup](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/ndpi_main.c#L9910-L10016)

当前输出有 `proto.master_protocol/app_protocol`、`protocol_stack`、独立 `protocol_by_ip`、状态及分类字段。需通过私有适配器映射项目稳定 catalog ID：TLS 品牌不自动推出 HTTP，类别不是协议事实，未映射结果保留原 facts。nDPI 的“当前协议栈”不是项目“已发布协议历史并集”；先解决候选冲突再发布，已发布错误不能靠追加正确协议撤销。需撤回时必须另改合同。[输出结构](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_typedefs.h#L1373-L1412)、[T12 累积合同](../interfaces/T12_PUBLISHED_PROTOCOL_FACTS.md)

## 三种路线和取舍

| 路线 | 收益 | 要付出的维护成本 |
| --- | --- | --- |
| 参考检测逻辑，独立实现 | 小状态跨包 detector 易贴合现有 seam | 依协议规范写实现和反例，自己维护版本变化 |
| 选择性复用源码 | 复用已存在的校验与状态机 | 依赖 helper、内部结构、注册／排除机制和测试，不能复制单个 `.c` 就结束 |
| 完整 nDPI 私有 provider | 获得调度、协议覆盖、TLS/QUIC 能力 | 输入 ABI、worker module、动态内存、缓存整合、输出语义及依赖都须适配；不接管 Flow 或 verdict |

源码核心与这里核对的 WireGuard 文件采用 LGPL-3.0-or-later；当前初始化还有 `license_type`，注册器记录 dissector 许可，所以完整闭包须按具体文件／依赖盘点，不能拿仓库根许可代替全部检查。已有 LPI 同属 LGPL 系列不是复制代码无需履约的理由；复用应保留来源、许可及发行所需材料。[许可](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/COPYING)、[文件与注册许可](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/lib/protocols/wireguard.c#L1-L21)、[初始化参数](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/src/include/ndpi_api.h#L288-L295)

可借鉴候选调度、早停、分开统计静态／动态状态、解析预算、稳定目录映射，以及按证据来源做准确率回归。上游有配置化 pcap／期望输出与 TLS、QUIC fuzz 入口；可选择相关样本并补随机／相似头负例、非标准端口、单向、分段、重传、乱序、预算结束和 Flow 复用。上游测试存在不代表本产品 PASS。[回归入口](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/tests/README.md)、[QUIC fuzz](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/fuzz/fuzz_quic_get_crypto_data.c)、[TLS fuzz](https://github.com/ntop/nDPI/blob/4aaa11c1c4bba0eff9fe7282cf6b2f3ea558ad2b/fuzz/fuzz_tls_client_server_hello.c)

风险评分、JA 指纹、应用品牌／类别库等虽是 nDPI 能力，不是此次识别事实适配自动获得的产品范围。ARM64 要测固定配置下的 `sizeof(flow/module)`、静态表成本、按协议动态峰值、临时解密内存、调用／detector 次数、首次结果包数、尾延迟及功耗；还要对照 20 包／32 KiB 下的误报、漏报与 Unknown。当前没有依据给出每 Flow 精确总成本或手机速度承诺。

## 后续讨论已确认的范围

用户明确：“肯定不是全部接入，我们还是借鉴，特别是其补充和规则。”
本轮以 nDPI 为检测逻辑和补充识别规则的参考，不接入完整 nDPI 引擎，
不引入其 module、第二套 Flow 管理或整套 TLS 字节缓存。
此前确认保留参考 fork 的启发式规则，不能因 nDPI 某个检测器更严格就
静默删除原有启发式。上文完整 provider 路线仅保留为研究比较，不是实施方向。

重叠检测规则的取舍、调用优先级、当前 QUIC 补充的归属及协议目录扩展
尚在讨论；本记录不替代正式规格，也不授权开始修改产品代码。

后续用户提出以 nDPI 规则为主，并说明 fork 启发式编写时的实际效果未获确认。
这是主要参考来源的调整提议，不能据此推断所有 nDPI 检测器已经验证优于 fork，
也不能把此前“保留启发式”解释成每条 fork 规则及其优先级永久冻结。
是否在 nDPI 风格的多包判断尚未完成时允许 fork 弱启发式提前发布，仍须明确。

最新范围确认：nDPI 检测逻辑作为主要参考，fork 仅选择性补充同协议识别特征
和有用标签粒度；用户以个人终端范围为由明确排除 GB/T 32960。
这不要求照搬每条旧启发式，也不把全部 nDPI 协议清单变成本轮实施承诺。
此前关于跨包撤回已发布事实的讨论未被采纳为新合同，不能据此实现复杂纠错状态机。
