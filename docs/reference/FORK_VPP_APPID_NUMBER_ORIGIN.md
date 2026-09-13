# Fork VPP AppID 编号来源调查

> 参考命名说明（2026-09-13）：本机参考仓库绝对路径已抽象；外部插件、API、CLI、环境变量和证据标识保留原名，仅用于溯源，不是 Sakamoto 领域术语。下文是标注日期的历史观察；命令能否重跑须核对现行入口，旧结果不证明当前 Product 实现。

日期：2026-07-22  
性质：背景与血统调查，不是当前产品协议或架构决议。

## 结论

fork VPP 中的 `DNS=32`、`HTTP=67`、`HTTPS=68`、`SSL/TLS=199`、
`QUIC=2521` 精确来自仓库内 vendored 的商业 **Enea Qosmos ixEngine**
`Q_PROTO_*` 协议目录。它们不是 libprotoident 的枚举值，也不是
RFC/IANA 通用应用协议编号。

因此，如果 Sakamoto 不使用 Qosmos/qDPI，也没有兼容原 MAAT 规则和
应用对象的要求，就不应把这组数字延续为新产品的稳定 AppID。
可以参考的是“多个识别器统一归一到一个协议目录”的结构，不是
Qosmos 的私有数值。

## 本地一手证据

### 1. vendored ixEngine 定义了完全相同的数值

fork 携带以下依赖包：

`src/plugins/stellar_qdpi_detector/vendor/libqmengine-5.11.0-21-LSB-SMP-NG.tar.gz`

其中 `include/dpi/protodef.h` 定义：

| ixEngine symbol | 数值 |
| --- | ---: |
| `Q_PROTO_DNS` | 32 |
| `Q_PROTO_HTTP` | 67 |
| `Q_PROTO_HTTPS` | 68 |
| `Q_PROTO_SSL` | 199 |
| `Q_PROTO_QUIC` | 2521 |

同一包的 `include/qmdpi.h` 和 `include/qmdpi_engine_info.h` 文件头明确写明
这是 Qosmos ixEngine，版权属于 ENEA SOFTWARE；后者记录 Engine
`5.11.0-21`、API `1.730.0`。这是依赖自己的定义，不是对 RFC 或
IANA 编号的引用。

### 2. qDPI 结果直接处于 Qosmos 编号空间

fork 的
`src/plugins/stellar_qdpi_detector/stellar_qdpi_detector_engine.cpp` 直接 include
`qmdpi.h`、`qmdpi_const.h` 和 `qmdpi_packet_helper.h`。
`src/plugins/stellar_qdpi_detector/stellar_qdpi_detector.cpp` 把 ixEngine 返回路径中的
`path->qp_value[i]` 直接写入 `context_message->appid[]`，并直接与
`Q_PROTO_HTTP`、`Q_PROTO_SOCKS5` 等常量比较。

所以 AppSketch 和原 MAAT 消费的数字本来就是 Qosmos qDPI 输出；
它们不是 fork 自行定义的 RFC 协议号。

### 3. libprotoident 是被映射到 Qosmos 目录，不是编号的来源

`src/plugins/stellar_lpi/stellar_lpi_core.c` 中的 `lpi_protocol_mappings[]`
手工把 libprotoident 名称转为上述数字，例如：

- `DNS` / `DNS_TCP` → `32`
- `HTTP` / `HTTP_443` / `HTTP_Tunnel` → `67`
- `SSL` / `SSL/TLS` → `199`
- `QUIC` → `2521`

vendored libprotoident 本身使用 `lpi_protocol_t` 枚举，没有这组
`Q_PROTO_*` 数值。因此是 fork 把 LPI 结果归一到已有的 Qosmos
应用目录，而不是 libprotoident 提供了这些编号。

### 4. Git 历史没有公共标准来源

- LPI 映射在首次集成提交
  `9420ed4fb2d569f6ee481517bbee3ad3cdfb526f` 中已带有这组数字，
  但没有 RFC、IANA 或 FCC 引用。
- qDPI vendor 依赖由提交
  `d77afd5a9fd20147faf7c3d3608fc85b8275cbe5` 引入，其当时携带的
  `protodef.h` 已有相同 `Q_PROTO_*` 值。
- AppSketch 首次提交
  `aa4c43e54017687174d49689338ac17d2556ff82` 也使用相同数值。
- `stellar_lpi_plugin.c` 在提交 `eb9d88f5a9` 中为 decoder tag
  再次复制这些常量。

这条历史链说明：数字是为了与 fork 里的 qDPI/Qosmos 生态互操，
后来被 LPI 和 decoder 复用。

## 与 RFC/IANA 的核对

如果口述的“FCC”实际指 **RFC**，结论是这些数字不来自 RFC。
IANA 的公开注册表反而清楚显示：

- DNS service name 使用 TCP/UDP port `53`；
- HTTP 使用 port `80`，HTTPS 使用 port `443`；
- port `67` 对应 Bootstrap Protocol Server，不是 HTTP；
- port `199` 对应 SMUX，port `2521` 对应 Adaptec Manager；
- IANA IP Protocol Numbers 中 `32` 是 MERIT-INP，`67` 是 IPPC，也不是
  DNS/HTTP。

来源：[IANA Service Name and Transport Protocol Port Number Registry](https://www.iana.org/assignments/service-names-port-numbers/)，
[IANA Protocol Numbers](https://www.iana.org/assignments/protocol-numbers/)，
[RFC 9000: QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)。RFC 9000 定义 QUIC
使用 UDP 传输和 QUIC version 字段，不定义 `QUIC=2521` 这种通用 AppID。

如果“FCC”是指某个特定商业分类目录，fork 内没有名为 FCC 的
来源。可证实的准确名称是 **Qosmos ixEngine `Q_PROTO_*` catalog**。
同样，当前一手证据不支持把这组值称为 Juniper/Junos 原生 AppID；
即使其它产品集成了 ixEngine，这份 vendored 定义的所有者仍是
Qosmos/ENEA。

## 对 Sakamoto 的建议

1. 保留统一 `Protocol/Application Catalog` 和 detector normalization seam。
2. 不延用 `32/67/68/199/2521` 等 Qosmos 数字，除非将来明确引入
   Qosmos/ixEngine 并需要与它的内容包互操。
3. 不把 port number、IP protocol number、libprotoident enum ordinal 当作产品
   AppID。三者都不能稳定表达本项目的应用协议语义。
4. 新产品目录的编号方案另行设计；若不存在已选定依赖的公共稳定
   ID，则由 Sakamoto 自有目录分配，并把 detector-specific name/ID 只作
   alias 和识别证据。
