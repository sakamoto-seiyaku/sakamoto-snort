# S229 独立有界重组：实现与验收

日期：2026-09-11。关联 Plane **SAKAMOTO-229**
（`979d06d5-26fa-4007-9837-dd1df48bbdb8`）。本文件记录实现与证据，不代替 tracker 状态。
[改造前取证与已撤回的豁免](2026-09-11_S229_CLOSURE_EVIDENCE.md) 单独保留，不能作为本实现的 PASS。

## 实现边界

- `product_fragment.c/.h` 管理 owner-local、启动预分配的 datagram 表、free-list 和有界原片描述符。
  `product_packet_reassembly_graph.inc` 接入 VPP buffers、两阶段 handoff、现有 completion 与 stop。
  Product plugin 不再调用 upstream full-reassembly custom nodes/hooks；最终 Linux plugin 的
  动态符号检查没有对应导入。历史 Host fixture 不作为当前产品实现或验收来源。
- 对称 L3 地址散列确定重组 worker R；offset-zero 首片调用唯一 owner assignment，保存 F。
  重组后完整包只解析一次，验证并恢复该 assignment；admit node 复用已保存事实与现有
  Primary Handoff，不再计算 owner。首片 UID/network/direction/provenance 缺失时不从其他片补齐。
- 首片/末片重复终结冲突 context；中间片从末端向前选取最新连续链。未选中的重复/重叠片
  仍保留独立 completion obligation。测试同时证明可接受的覆盖选择和不可连续拼接的冲突，
  不是“全重叠一律拒绝”。
- 原片各持有一个 VPP buffer 引用；没有 consume pin、每包 heap、payload 长期副本或重组回滚。
  detach 描述符只借用到下一次 table mutation 之前，跨 node/worker 的状态只使用 buffer index
  与 inline metadata。NFQ 仍按原 queue/generation/packet ID 逐片 verdict；TUN 不伪造正常出口。
- 完成复制使用固定临时 payload 区，packet overlay 保持 **56 bytes**。L3 header span 改为
  16 bits，family/L3 validity 共用一个 byte，能够保存 296-byte L3 span 而不增加 opaque 空间。
- 共享 IPv6 parser 支持 Hop-by-Hop、Routing、Destination Options、AH，预算为 8 headers /
  256 extension bytes。正常包预算不足不猜测 L4；重组的合法超预算链按 resource 收尾。
  不支持的封装不被伪装成 terminal TCP/UDP。无 L2、内层隧道重组或出站重分片。

## 配置与资源

VPP startup stanza：

```text
product-reassembly { contexts 64 originals 32 timeout-ms 500 }
```

64/32 是默认值，不是隐藏上限。每 worker 按配置分配 contexts、bucket heads 和
`(contexts + 1) × (originals + 1)` 个描述符，额外一行用于同步 detach，额外一个 original
槽用于保留触发容量失败的输入。初始化检查数值、索引表示和分配乘法溢出；分配失败报启动
失败，不静默缩容。生产配置重启生效；`product reassembly configure` 仅供空图诊断实验，
有 obligations/buffers 时拒绝，运行中没有自动扩容或驱逐旧 context。

核心测试实际填满 65 contexts、保留 33+1 个容量失败 originals，并检查超时、flush、槽复用。
两平台 `geometry` 运行图实际配置 65 contexts / 33 originals。超时从 context 创建时计，
worker 以 50ms 间隔检查；quiesce 在清空 contexts/completion 后才关闭 Adapter lanes。
保留的旧 `pins/retained` 观测字段在单引用实现中为零；`originals` 与 completion/Adapter
资源账仍分别校验，不拿进程退出代替正常排空。

`f-startup-b` 另行直接验证同一 Product artifact 的启动 stanza：65/33/750ms 实际生效，
零容量和溢出容量得到明确诊断并退出，三个进程均退场。VPP 对 configuration-parser error
可能返回 exit code 0，因此断言使用实际错误诊断和退出状态，不把零退出码等同于启动成功。

## 最终同源构建

构建时 HEAD `46235ce95765d4b2c1e5fd0bd60e894ed9a522c4` 加工作树中的本次修改；没有覆盖接手时的其它修改。
Linux 与 Pixel 的最终 **build-f** Product source closure 相同：

```text
2a009e6bef032640a71410a7eaf805ba32bcc4b6d049ece4e4af843c8d43ce05
```

以下路径相对 `build-output/s229-20260911/`：

- Linux：`independent-linux-build-f/build.json`；artifact 为
  `build-output/product-vpp-host-s229-independent-f`。
- Pixel：`independent-pixel-build-f/build.json` 与该目录的 `apk/sakamoto-runtime-debug.apk`。
  APK SHA-256：`a596519a153554be4473e7225d83326fb264ad0808538b151eb3611381e6219e`。
- 每个 witness 保存 Product 源副本、dirty diff、编译结果与 native closure；Pixel 部署后核对
  APK 和全部 native libraries。stage 分别为本机 verified Host / Android VPP stage。
- Linux helper 构建：`independent-control-f/helper-build.json`，记录实际源/header/compiler/依赖。
  NFQ helper 固定预期 L4 DROP reason=8；图注入 Gate 场景仍为 reason=7，不能互换。

## build-f 新复验

所有表内目录均相对上述证据根。GRAPH_INJECTED 使用真实 Product nodes，但不冒充平台捕获。
Pixel 仅使用设备 `28201JEGR0XPAJ`，所有设备操作走 `./dev/adb`。

| 范围 | Linux | Pixel |
| --- | --- | --- |
| 基础错误、重复片、容量、策略 DROP、stop | `f-basic`：PASS，32 originals | `fp-basic`：PASS，32，generation 986 |
| 入口 → R 真实 ring-full | `f-in`：PASS，18 | `fp-in`：PASS，18，generation 987 |
| 完成后 R → F 真实 ring-full | `f-out`：PASS，24 | `fp-out-b`：PASS，24，generation 989 |
| 已有 DROP 的 completion 延迟与重试 | `f-policy`：PASS，24 | `fp-policy`：PASS，24，generation 990 |
| 重叠、IPv4 options、IPv6 扩展链/预算 | `f-geometry`：PASS，29 | `fp-geometry`：PASS，29，generation 985 |
| 首片晚到/缺失、known/unknown、snapshot 变化 | `f-facts`：PASS，30 originals / 14 datagrams | `fp-facts`：PASS，30 / 14，generation 991 |

真实 Linux NFQUEUE：`f-nfq4` PASS，64 originals；`f-nfq6` PASS，128 originals，覆盖 INPUT
和 OUTPUT。逐片核对捕获字节、buffer allocation lifetime、origin lane/packet ID、实际 verdict、
peer-link 字节与停止残留；oversize、bundle/context capacity 的 NF_ACCEPT 不是伪造 policy ALLOW。

真实 Pixel TUN：`fp-tun-cap-b` PASS，40 originals / 28 fragment originals / 8 datagrams，
generations 994/995；`fp-tun-drop` PASS，46 / 32 / 16，generations 996/997。
分别验证 bundle capacity 与恢复，以及双栈 Gate/L4 DROP、两种最终 owner 和 restart。
TUN UID 来源仍明确为 controlled provider，不冒充平台 UID 自动归属证明。
最终设备 snapshot 为 `state=stopped, mayBeActive=false, pid=-1`；各 run 验证进程、接口、
reader、buffer/completion 和适用 NFQUEUE/hooks 清理，并恢复原 Wi-Fi 开关。

prepared rejection 在两个 IP family 都有 `prepared=1`、R != F、实际 queue ID、2 slots /
occupancy=1，以及对应的全部 originals。没有修改 enqueue 返回值，也没有使用不可达豁免。

## 回归与取证纪律

`tests/host/product_fragment_contract.sh`、S175 exceptional parser contract、S207 owner-assignment
contract 通过。核心还以 ASan/UBSan 运行；受当前 ptrace 环境限制关闭 LeakSanitizer，不能据此
声称 LSAN 通过。正常析构、资源满、flush、复用和真实资源账分别验证。

最终 Linux evidence mutations：basic 15 项、prepared-sendout 18 项，含缺记录、错误 source /
generation/helper、重复 free、DROP 改 bypass、缺 IPv6 prepared rejection、假 prepared、空 ring。
验证器遇不完整失败目录输出 HOLD，而不是依赖异常退出代替报告。首片事实的 12 个变异反例
也全部拒绝；NFQ 每族各 9 项、Pixel 首片事实 12 项、真实 TUN 6 项通过。
S219/S229 verifier 支持独立 verification 输出，使用独占创建；负例不覆盖正例报告。
所有失败原目录保留，正例与负例副本分离。

改造中保留的失败包括：重复 next-slot 导致 VPP 初始化崩溃（已修复）；共享 parser 未遍历
IPv6 扩展链（已用实际图反例修复）；旧 256-byte 注入边界（分片诊断入口改为既有 buffer 内
最多 2048 bytes）；测试 socket 路径过长、错误 capacity 参数和错误 TUN policy helper。
Pixel `fp-out` 未得到诊断 hold 重叠，保留失败，使用已有有界真实流量 helper 的 `fp-out-b`
重新取得实际拒收证据，没有放宽判定。

`fp-tun-cap` 的 collector 将 recovery 阶段传成 S218 的 mode=2（L4 DROP），与恢复放行
断言矛盾。采集输入改为两阶段均显式安装 mode=0 空/default-pass bundle 后重跑为
`fp-tun-cap-b`；独立的正常 TUN Gate/L4 DROP 矩阵仍严格要求 DROP，并由 `fp-tun-drop` 验证。
没有以更换预期或修改 Product policy 来使失败通过。

当前 VPN Flow Stack 未开放；TUN allow/recovery 只证明图和完成恢复，不声称流量成功送达。
FlowRuntime、ACL 重构、协议 tracker 和后续 VPN transport 不属于本次实现。
