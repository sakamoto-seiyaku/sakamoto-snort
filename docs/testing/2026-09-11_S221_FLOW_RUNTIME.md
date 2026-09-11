# S221：统一 owner-local FlowRuntime

证据状态：最终同源 Linux 与 Pixel 矩阵均 PASS。任务状态以 Plane SAKAMOTO-221 为准。

## 交付范围

`product_flow_entry.c/.h` 现在提供 opaque `product_flow_runtime_t`：每个 owner 一个统一
table/pool，启动预分配，运行期容量固定。TCP、UDP、ICMP_QUERY 共用容量和 free-list；
协议 union 只占位，不声称 tracker、CtFacts、自动 expiry 或 FlowEnd 已完成。

lookup 消费已有 OwnerAssignment/hash，以完整 typed identity 比较候选；不重做 owner
选择，不以结构 padding 作身份。bucket 使用已有 hash 折叠，free-slot 创建为 O(1)，
碰撞链最坏以容量为界。没有 eviction、spill、全局 entry 锁或逐 flow heap allocation。

首个通过 Gate/L4 的创建包确定 ORIG；计数包含两侧 packet/byte。policy identity 改变只
失效 decision，不清 flow facts。runtime generation 固定，旧 generation 不可更新新表。
flush 恢复整个 free-list，保留本 generation 的诊断计数与递增 incarnation；destroy/recreate
只在 drain 后执行。

新流满池保留 Gate/L4 结果，使用 `PRODUCT_PACKET_BYPASS_FLOW_CAPACITY`：Root 回原 lane
执行 NF_ACCEPT；已有 DROP 不被改写。已有 flow 仍可命中。VPN 继续如实报告正常 transport
不可用边界，不从这一改动推导 VPN forwarding readiness。历史 CLI `flow.pool capacity_drops`
字段仍保留旧名字，但计数含义是 capacity miss；`flow.runtime/flow.protocol capacity_misses`
是明确的新诊断字段，不是 policy/runtime DROP 数。

## 容量和内存口径

配置为 `product-flow-runtime { entries N }`。`product flow capacity N` 只允许
stopped/drained runtime，作用于下一次 start；live resize 被拒绝。非法零值、索引溢出和
预分配失败不静默缩小容量。

1024/worker 只是开发 composition 设置，不是正式发行默认。最终容量仍需完整 tracker、
timer、attachments 和目标端点预算。当前两个目标的 `sizeof(FlowEntry)` 为 184 bytes；
每槽连同 private next/alignment 为 192 bytes。128 项时 allocator-requested bytes 为
25,832/worker；3 项为 840/worker。这些数字包含本 runtime/table/pool 的请求字节，
不包含 malloc 管理开销、RSS、VPP buffers、future timers 或 Flow Stack。

## Source 与实际构建

构建基线 commit：`2bdf945` 加各 build witness 旁保存的 `dirty.diff` 和完整 Product source
快照；不是未提交源码已经存在于该 commit 的声明。

最终 Product source closure：

`6d9265ea3a457a2394e138856181a2b4699043c0ab3f4fbbca426b1da6019575`

证据根目录：`build-output/s221-20260911/`。

- Linux：`linux-build-d/build.json`，artifact `build-output/product-vpp-host-s221-d`。
- Pixel：`pixel-build-e/build.json`，APK 与 native hashes、stage identities 在该 witness 中。
- `tests/evidence/build_s221.py` 构建 Product，并分别编译有 source/compiler/hash 记录的
  `s221-flow-client`、`s207-echo` 和 `s217-policy`。独立 kernel endpoint 不包含 Product packet
  实现；policy helper 通过实际 Rust Product Core/generated VAPI apply。

VPP 仍是现有 pin、5 个 core patches 与 Android 18-patch stage。没有改 idle/wake profile。
OVS 后续共同母本固定为 `v3.1.0` / `3c2bea086ef8912d57331173af266f21d36740a0`，
源文件 hashes、timeout 表和 TCP BSD / 其他 Apache 归属见
[OVS baseline](../reference/OVS_CONNTRACK_BASELINE.md)。没有导入 OVS 工程或旧 C++/POC 源码。

## 已闭合的 Linux 证据

`linux-flow-f/verification.json` 为 PASS：

| 场景 | captured / completed / freed | 活跃 entry | Flow capacity bypass |
| --- | ---: | ---: | ---: |
| capacity 128/owner | 2113 | 192（96/owner） | 0 |
| capacity 3/owner | 437 | 6（3/owner） | 336 |
| 新 generation | 81 | 6 | 0 |

正常矩阵覆盖 IPv4/IPv6 TCP、UDP、Echo 在两个 owner 的创建与双向复用，超过历史 64 项。
35 条额外 entry 与该 owner 的已用 bucket 碰撞，仍保持不同 typed key/slot。小容量中每个 owner 各有一条 TCP、UDP、
ICMP entry，三协议的新流都产生容量 miss；旧 UDP 流继续 hit。满池后的 Gate/L4 DROP 不修改
已有 entry，也不变成 bypass。

另有明确标记为 `FLOW_RUNTIME_INJECTED` 的完整 64-bit hash 碰撞检查：在 Root stop 后，
control 预分配两个隔离 runtime，由两个真实 VPP owner node 分别执行八个同 hash、不同
typed key 的创建和反向命中，随后验证满池、早期 DROP、wrong-owner、flush/serial reuse。
每个 worker 的实际 VLIB vector 为 1；检查完成后两个 carrier 和隔离 runtime 都释放，
普通 flow table 仍为零。这是注入的 Interface 证据，不混入 NFQ_CAPTURED packet 账本。

独立 verifier 逐 token 对齐 admit facts、observe、completion publish/consume、原 lane
verdict 和 native free；比对实际 worker VLIB vectors、per-side/per-protocol counters，
并核对四条 queue lane、fd、stop entries 和所有 debt。Linux 在独立 rootless user/net
namespace 中运行；live queue 拒绝其他 socket 绑定，stop 后四条 queue 都可重新绑定。

`linux-startup-b/verification.json` 验证显式 65 项配置，以及零/索引溢出/解析窄化溢出拒绝，
同时核对 stopped CLI 的宽整数拒绝。
`linux-negatives-e/verification.json` 的 20 个破坏副本全部被判为 HOLD，包含源/build 错绑、
丢失/重复 completion、错误 owner/full-key、把 capacity 当 DROP、把 DROP 当 bypass、
缺失 VLIB/protocol/endpoint 证据、stop residue，以及伪造碰撞来源或未释放诊断资源。

## Pixel 口径与保留失败

最终 `pixel-flow-k/verification.json` 为 PASS，source closure 与 Linux 完全一致：

| 场景 | captured / completed / freed | 活跃 entry | Flow capacity bypass |
| --- | ---: | ---: | ---: |
| capacity 128/owner | 2515 | 192（96/owner） | 0 |
| capacity 3/owner | 547 | 6（3/owner） | 428 |
| 新 generation | 95 | 6 | 0 |

双栈三协议/两个 owner、完整 hash 碰撞的实际 owner-node 向量、per-side/per-protocol
账本与 stop 清理均通过。`pixel-negatives-a/verification.json` 的 20 个破坏副本全部为 HOLD。
独立 RuntimeService Root generation 1000 的 start/stop 与 residue projection 通过，
Wi-Fi 为 1 → 1。核查安装 APK/native 内容，不使用旧 native 文件替代。

- APK SHA-256：`5f6aeeeb9475f49cc4d335edd4c62f69bca9bd798c457329145feca8d618fa08`
- Product plugin：`83daa6f9c526c6d8734582b54d694557fa13a4e2377cd2ccb17d3cd393bdec5a`
- VPP runtime：`d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08`

Pixel Root 矩阵使用实际安装 APK 内的 Product ELF，通过独立 startup 配置选择 128/3/128
容量；只安装带 `SAKAMOTO_S221_` 标记的指定 loopback hooks，不替换普通网络规则。
另跑同一 APK 的 RuntimeService Root start/stop，核对 1024/owner 开发设置与 cleanup。
Wi-Fi 原状态保存并恢复；KernelSU grant 在这些安装中保持可用。

较早 `pixel-flow-f` 已完成普通、满池、重启及 RuntimeService generation 998 的功能矩阵，
但不含最后加入的 owner-node 碰撞诊断，不能替代最终构建验收。

保留的失败和限制：

- Linux 初版 runner 使用超出既有 policy API 范围的 generation；随后又错误地用 namespace
  UID 0 匹配初始 namespace 的 NFQA_UID 1000。均按实际接口/内核事实修正，未修改 Product
  来适配错误测试预期。
- 配置边界复核发现实际 Product 缺陷：VPP `%u` 将 `4294967297` 窄化成 1，绕过原先的
  32-bit 容量范围检查。`linux-startup-overflow-red` 复现非法配置被接受并保持运行；已改为
  startup/CLI 先用 64-bit 解析、校验后再收窄，`linux-startup-b` 覆盖该回归。
- Pixel runner 先后修正私有 upload directory 所有权、toybox `env` 对含 `=` APK 路径的
  解释，以及 foreground idle QUERY 服务的退休边界。失败目录未覆盖。
- 没有 Product hooks 时，app UID endpoint 在首次前台启动前也不可达；仅打开调试 Activity
  后同一 helper 恢复。runner 加入前台及挂钩前的 2 秒 kernel endpoint 检查。
- 有前台网络后，2 秒仍不足以覆盖既有 Android remote handoff。该 stage 的秒级延迟已由
  [S205](SAKAMOTO_205_PRIMARY_HANDOFF.md#latency-finding--functional-scope-only) 记录。
  正常 Pixel probe 使用明确 35 秒功能性 socket wait 和有界真实并发批次，DROP probe 为
  2 秒；没有增加 worker wake、关闭 idle profile 或把功能 PASS 解释为合格延迟。
- `pixel-flow-g` 在抓包前出现 VPP initial-barrier abort；`pixel-flow-h` 发生 CLI 连接拒绝。
  两次均未安装本轮 packet hooks。它们保留为失败记录，不与已完成 observation 合并。
- `pixel-flow-i` 的两个 pool 均报告 96 项，但大 CLI 输出只读到 owner 1 的前 47 项。
  runner 曾把 `quit` 与查询一起发送，可能在 pending output 排空前关闭 session；现改为
  保持 stdin 打开、读完唯一 echo marker 后才发送 quit。
- `pixel-flow-j` 完成正常/满池/碰撞检查，但重启尾部仍有 TCP close traffic 跨过多条状态
  查询，造成不同时间点的账本混合。现先撤销本轮 hooks、drain，再取 final snapshot。
  其进程扫描也把包含 ELF 路径的 Supervisor audit shell 误报为 VPP；现按实际 argv[0]
  匹配，并加入真假 process-row 向量。没有将这次 HOLD 改写为最终 PASS。

## 辅助验证及未证明范围

纯 C FlowRuntime、S207 单一 assignment、S174/S175 packet kernel、S210 bypass guards 与
Product fragment contracts 通过。FlowRuntime ASan/UBSan 通过；该执行环境的 LeakSanitizer
受 ptrace 限制，使用 `detect_leaks=0`，不把它报告为 LSAN 通过。
同一候选 Product 的 S229 basic native reassembly 回归另记于 `221-r2`，与 FlowRuntime
功能账本分开，不把 GRAPH_INJECTED 重组向量混为 NFQUEUE endpoint 流量。

旧 S192 Host fixture contract 在 S229 已移除的 `external_completion` callback source guard
处失败；本项只同步其必要的 Interface 名称/开发容量预期，没有用旧 fixture 代替真实
Product，也没有声称整套 legacy fixture 已通过。

本报告不证明 UDP/TCP/ICMP tracker、ct rule predicate、自动 expiry、FlowEnd、长期 soak、
发布容量/功耗/延迟预算或 VPN Flow Stack。它只闭合共享 storage、typed identity、owner
mutation、容量语义与有限流量/stop 生命周期；后续按已确认的任务顺序推进。
