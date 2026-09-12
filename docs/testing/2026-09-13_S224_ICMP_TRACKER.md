# S224 — 双栈 Echo session tracker

父任务 S199，执行状态由 Plane S224 跟踪。本文登记当前实现边界和真实端点验收；不是
VPN ICMP transport、ICMP error/RELATED、自动到期或发行 readiness 声明。

## 采集前固定的范围

在 S227 commit `d787a175da6ec550c8deb175ca85c3b6215b85ac` 上接入统一 FlowRuntime
的 ICMP_QUERY union 分支，不新增 table、pool、scheduler 或 PacketFacts parser。
沿用唯一 OwnerAssignment 的 family/protocol/归一化 address pair/query class/identifier，
sequence 不参与 identity/hash/owner。诊断中的 port_a/port_b 仅对 L4_PORTS 显示，Echo 不
以 identifier 或 sequence 伪造端口。

状态语义以现有 OVS pin `3c2bea086ef8912d57331173af266f21d36740a0` 为准：FIRST 中
ORIG 重复仍 FIRST，首次 flow REPLY 后保持 REPLY；分别输出 NEW/VALID_NEW/ICMP_FIRST
和 ESTABLISHED/VALID/ICMP_REPLY，每次合法 update 返回 refresh 意图。两个 class 对应
同一默认表 60/30 秒，但本切片不建立 ICMP timer，真实自动到期由 S236 接入。

request/reply 报文种类与 flow ORIG/REPLY 是不同事实：首个已接受 observation 固定 ORIG；
另记 `seen_request` / `seen_reply`，不得把首见 Echo reply 记为 request。允许 reply-first
是已定 Product midstream 范围，区别于 upstream 的新建请求限定；也不支持 upstream 的
information/timestamp query。相同地址的退化投影沿用既有 ORIG 契约，报文种类不能重选
方向；seen flags 如实记录，不能将单向状态伪造为验证过的 request/reply 往返。

纯 C tracker 只读 shared parser 的完整 L3、OTHER_TERMINAL Echo facts、type/code；
只处理 IPv4 type 8/0、IPv6 type 128/129、code 0。非法输入不提交 accepted state 或
refresh。已有 entry 可记录 invalid observation 计数；invalid-new 不分配 entry。
不重解析 bytes，不访问 socket/time/table；不增加 checksum offload 或 RELATED 承诺。

## 真实矩阵与判据

同一 Product source 分别构建 Linux VPP artifact 和 Pixel APK，记录 source/dirty diff、
VPP/native/APK、helper/compiler hashes。Linux 在独立 rootless user+net namespace；Pixel
使用实际安装的 VPP-native Product ELF、W2、四条 Root NFQUEUE 176–179，App 保持 stopped。
不切换 Wi-Fi，不依赖公网/远程服务；测试私有 loopback 地址、规则和进程结束后清理。

每平台两代，分别只在 OUTPUT、只在 INPUT 捕获测试 Echo，避免同包双重观察。每代覆盖：

- family 4/6 × canonical owner 0/1 × initial placement local/remote ×
  request-first/reply-first，共 16 个固定 identifier session；queue 选择只控制初始执行位置，
  不改变 canonical owner。原队列必须分别完成真实 verdict。
- request-first：仅捕获请求时先发 1 次，再同 identifier 发 2 次（sequence 65535→0）；
  tracker 保持 FIRST/seen_request。随后双向捕获并发 2 次，进入 REPLY/双 seen flags。
  物理 kernel reply 始终由端点验证；“未捕获”不冒称网络丢失或未实际发 reply。
- reply-first：真实 raw socket 发 2 个可校验 Echo reply，由目的 raw socket 证明收到；
  首见是 ORIG/FIRST、seen_reply=1/seen_request=0。再反向发 request 并收到 kernel reply，
  仍使用原 slot/incarnation，进入 REPLY，双 seen flags。
- 另外每 family 一次系统 ping（3 sequence），使用另一个私有地址，证明实际 ping 成功。
  从 raw 报文取得实际 identifier，不假定 ping 的 ID 或 canonical owner。

普通请求和 reply-first 均由独立 C raw socket 端点产生/接收，带唯一 nonce、identifier、
sequence、monotonic timestamps；IPv4 校验和及 IPv6 pseudo-header 校验和独立验证。
不 graph inject、改 flow state、用 VPP counters 冒充端点收到。每代每 lane 总报文限制在
既有 64 个 full raw capture 上限内，完整核对 capture/admit/shared consumer/verdict/free。

独立 verifier 从实际包重新计算 typed key/hash/owner，逐 flow 重放 FIRST/REPLY、方向、
seen flags、CtFacts/update/class/refresh 和双向 packet/byte 计数。每个 sequence 共享原
slot/incarnation，另一 identifier 为独立 entry。每次快照都与当时真实报文前缀对应。
错误 owner、stale generation、早于 Gate 的 mutation、伪造 CtFacts 和 port 编码不能通过。

最后 entries、timer、END、packet buffer/obligation、handoff/completion debt 全部归零；
Root 活跃时固定 receive reserve 288，关闭后为 0，四 timer FD 和四 queue FD 均撤销。
ICMP 没有自动 timer，所以正常结束为 drain 后管理清理，不冒称 idle expiry。
每 owner 的协议计数、总释放/管理释放须一致；没有 pending END 留到下一代。

Host 补充两 family 的 request/reply-first、invalid type/code/facts、policy identity、
sequence wrap、forced complete-hash collision、owner/generation、共享容量与 END 持槽。
同源码回归 UDP 默认到期及适用宿主/Android 生命周期；原始失败不覆盖或重标 PASS。

## 结果

2026-09-13：两平台完整矩阵均为 `PASS`，48 项语义负向/平台也均 PASS。登记内容已在
采集前冻结于各 run 的 `test-source/`，本节在核验后追加，不改变之前的输入或判据。

### Source 与 artifact

Product source SHA-256 为
`8132735e4f94ff253cd7b09d061c524d38bca03cc61e24595a7be51979dc1831`，
基线 commit `d787a175da6ec550c8deb175ca85c3b6215b85ac` 加本轮 ICMP dirty source。
源文件快照、dirty diff、编译命令和各 ELF/hash 均在 build manifest 中保留。

| 构建/运行 | 路径（均在 build-output/s224-20260913 下） | SHA-256 |
| --- | --- | --- |
| Linux build | `linux-build-a/build.json` | `3a9522778464add56e7b23de40e1106b79faff66fa52014a2e63c7304082dabb` |
| Pixel build | `pixel-build-a/build.json` | `d3de83c74d1edb6bf90376cb30930276723257c4cbab372ec3ae422ab98f3af7` |
| Linux result | `linux-a-full/result.json` | `76798ea2972678245d5d70d54ba3505077450e3f107ea5635fa968e83ea87238` |
| Pixel result | `pixel-a-full/result.json` | `66decabf3f62ba2abfbf8b1fa012fc2e547c6815e2d905a08370340c68e6dbfc` |

实际安装 APK：`b83afac36dc0506adfce290aa7765405988081e11c77a73bcccf5dfe135aeaf1`。
VPP stage：`02b29be6c7fd3922bfa050e43d87397c3a4beb698780ce3f3d62147b6bcf6ff8`。
Pixel bluejay、Android 16、kernel `6.1.134-android14`、serial `28201JEGR0XPAJ`。
Linux 使用实际 native plugin，不是 host fixture；本项不借 S226 的内存门槛宣称容量/功耗。

本轮重新读取 pinned upstream `lib/conntrack-icmp.c` 并核对完整 bytes SHA-256
`dae4df8530bfea21cfc0980e8bf75b245099f4d3b04d266081b38b1dd4448a5f`，与
[既定来源登记](../reference/OVS_CONNTRACK_BASELINE.md) 相同；没有使用已移除 C++ 或 POC 源码。

### 实际 Echo 证据

| 每个平台的 generation | hook | sessions | 捕获/最终归还包 | 受控 reply-first sessions | 系统 ping replies | drain 后管理释放 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 22410 | OUTPUT | 18 | 100 | 8 | 6 | 18 |
| 22411 | INPUT | 18 | 100 | 8 | 6 | 18 |

每代 16 个受控 identifier session 与两个独立 ping session，覆盖 8 个
family × owner × local/remote placement 组合。四队列每代分别 28/22/28/22 个 capture，
均低于每 lane 64 个全量 raw 上限，本轮 **200 包/平台全部**核对了 capture、parser
admit、owner-local observe/icmp_update、共享 consumer、原队列 verdict syscall 和 buffer free。
Admission/唯一 owner 分配发生在初始 lane worker；必要时 primary handoff 后才在 canonical
owner 更新 tracker，随后回原 lane completion。这两种 worker 角色没有混为一谈。

request-first 从 FIRST 单向三包开始，sequence 65535→0 仍复用同 slot/incarnation；
随后实际 request/reply 将 phase 推至 REPLY，最终 ORIG 5 包、REPLY 2 包。前期未捕获的
kernel reply 仍被两个独立 raw socket 端点和发起端证明实际收发；它不计入 Product observation。
reply-first 两个真实 reply 的首快照为 FIRST、seen_reply=1、seen_request=0；反向 request
及其 kernel reply 后双 flags 为 1，仍是原 slot/incarnation，最终 ORIG 3 包、REPLY 1 包。
两种模式的 CtFacts/update/timeout class/refresh 与每包字节累计由 verifier 独立重放。

两 family 的系统 ping 都成功收到各三次 reply；ID 从实际包中读取，同一次 ping 的三个
sequence 共享 entry。独立收包日志的 type/code/id/sequence/nonce、ICMPv4 checksum 和
ICMPv6 pseudo-header checksum 全部吻合；这不是只根据 sendto 成功作出的交付判断。

每个中间快照均绑定最终 native log 的不可变前缀；旧/new generation、phase、方向、
identifier 或 slot/incarnation 的矛盾不能被最终汇总掩盖。entry 为 232 bytes，每 owner
capacity 32、实际分配 8,392 bytes，共享 TCP/UDP/ICMP_QUERY 统计，没有独立 ICMP pool。
当前 Echo timer 为 0；正常 UDP driver 的两 owner 四个真实 one-shot timer FD 维持 disarm，
Root stop 后全部关闭。Flow/END/原包 obligation/primary handoff/completion debt 均清零，
固定 receive buffer 288→0，四 queue FD/inode 与 hooks/临时地址/六个 raw receiver 进程清理。
这里的 36 次 entry release/平台均是 drain 后管理清理，自动 ICMP expiry 为 0。

最终 verifier：`tests/device/verify-s224-icmp-tracker.py`，SHA-256
`46093652541b38e8902efe846b8a309caf9662e0007c37bcab6749d72eb6994c`；
collector SHA-256 `20f69554d91128c2817c868ad4612bce0bcd2aed8c96dfe566ae15d5df95f789`。
两平台 `negative.json` 各记录 48 项实际 raw evidence 语义破坏拒绝；变更后先重算 raw hash，
且 trace 变更同步作用于该代所有前缀副本，不以 hash mismatch 或陈旧前缀充当语义检查。
覆盖 tracker state/facts/owner/generation、sequence/identifier/incarnation、伪端口、真实端点
receipt/checksum、错 verdict/FD/lane、遗漏 consumer/free、假自动 END、timer/queue/entry
残留、管理释放、完整 handoff/completion 计数与缺失系统 ping。

### 同源码回归与工具修正

- `udp-linux-a-regression`、`udp-pixel-a-regression`：真实 FIRST 60 s 无新包到期和
  stale-wake/stop 两项均通过，verifier 正确报告 `VALID_PARTIAL`，没有冒充 S227 全七项重跑。
  每平台 4 次正常自动 END，Linux max 8.365 ms、Pixel max 100.747 ms；另 4 条未到期
  stop 管理清理，两个 owner 分别拒绝受控旧 generation 通知，最终资源清零。
- `vpn-a-regression`：S243 stop 1370→1371、crash 1372→1373 PASS，每代八条真实
  TCP/UDP IPv4/IPv6 active flow。正常 stop/replacement drain，crash 明确 OS reclaim；
  不含 underlay 或 ICMP transport。最后实际 app snapshot 为 generation 1373、stopped、
  pid=-1、mayBeActive=false、protectionRunning=false、error 为空。
- 34 项适用 CTest PASS（保留既有五项历史文本契约排除）；Clang ASan/UBSan non-PIE
  8 项 flow/timeout/hex C 测试及一个 flow-entry shell contract 各重复 3 次 PASS。
  `detect_leaks=0`，不作 LSAN 声明；Android runtime contract 和 seam PASS。
- 新宿主测试最初将总 release_count 误写为仅 END 数；既有 release_slot 同时计入管理释放，
  因而正确值为 2（一个 END、一个管理释放），管理子计数为 1。只修正该断言，回收代码未改。
- 新 verifier 初次将所有 terminal 日志都按 token 字段连接，但原生 `s203 verdict` 使用
  obligation 字段；现按已存在的日志类型严格映射。两平台原始 run 未重写，完整核验通过。
- 负向 runner 初次跨 `/tmp` 文件系统建立 hardlink 被 EXDEV 拒绝，尚未执行语义变更；
  临时副本改放证据同文件系统，改写前先 unlink，原始 raw 从未被原位修改。
  负向还发现无尾随字段的假 END event 被前缀过滤遗漏；改为解析 event 字段后拒绝任意
  自动 END，随后 48 项/平台全部通过。以上都不是新 Product artifact 的执行失败。

```sh
rtk proxy python tests/device/verify-s224-icmp-tracker.py --run build-output/s224-20260913/linux-a-full
rtk proxy python tests/device/verify-s224-icmp-tracker.py --run build-output/s224-20260913/pixel-a-full
rtk proxy python tests/evidence/test_s224_icmp_negatives.py --run build-output/s224-20260913/pixel-a-full
rtk proxy python tests/device/verify-s243-active.py --build build-output/s224-20260913/pixel-build-a/build.json --run build-output/s224-20260913/vpn-a-regression
```

当前源码必须与执行 build closure 相同才能宣称当前 artifact 通过；后续源码更改保留这些
冻结证据作历史审计，不能自动继承本轮 PASS。仍未证明 ICMP error/RELATED、VPN ICMP
transport、ICMP/TCP 默认自动到期、深度休眠、整机功耗、长时间 soak 或发行容量。
