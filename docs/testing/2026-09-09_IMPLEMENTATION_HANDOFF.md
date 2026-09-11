# 2026-09-09 实施交接：S229 现场与后续执行路线

本文是用户要求的日期化交接快照、证据索引和执行建议；不是第二个任务台账。
任务当前状态、正式验收条件与依赖以 Plane Sakamoto 为准。本文未修改 Plane、
未关闭任务、未部署设备、未运行新一轮产品验收。后续执行者应先核对现场是否变化。

**实施规格补充：** 用户随后要求进一步固定设计、模块、代码与验证步骤。
接手者必须接着阅读 [实施规格附录](2026-09-09_IMPLEMENTATION_SPEC.md)。
本文负责现场与证据索引，附录负责具体实施约束；其中新增方案明确标为本轮实施基线，
不冒充已实现代码或历史 ADR 决定。遇到真实冲突按附录的例外程序处理。

## 1. 接手结论

### 2026-09-11 讨论收口后的优先说明

本文下方为改造前现场快照，不能覆盖后续用户决定。先读实施规格 §1 及
`docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md`、`VPP_PACKET_METADATA_OWNERSHIP.md`。
重组将替换 upstream 业务路径，保留两阶段 worker 交接和每个 NFQ/TUN original 的统一完成。
默认每重组 worker 64 contexts、每组 32 originals 均可通过启动配置调大/调小，不是硬上限。
FlowEntry 容量独立配置，正式默认值待内存与流量验证，不能沿用旧 64 槽结论。
FlowRuntime 职责、FlowEnd 最终回收、普通满池 bypass 和 expiry 行为已收口；FlowEnd buffer
分配失败停止 VPP 接管并优先恢复系统联网，不能让联网等待功能重启。
ACL 结构重构仍独立延期，协议 tracker 继续使用 OVS 语义，timer 容器/调度留待验证选择。
prepared-sendout “当前 pin 不可达”的豁免提议已撤回，旧 PASS 不证明替换后的实现。
当前只同步文档；恢复工作先完成 S229，不顺带展开后续 FlowRuntime 实现。

当前不需要重新设计整体架构。应先收口已经开展的 **SAKAMOTO-229**，然后优先
推进 **S221 → S223**，建立统一 FlowRuntime 和 UDP tracker。这两个切片同时
解锁 FlowEnd/expiry 和真实 HEV/lwIP VPN UDP 产品化。

项目对象是用户自己的 Android/Linux 本地端点与受控测试环境。这里的分片、
NFQUEUE、策略 DROP、故障注入是本地流量控制与资源生命周期验证；不扩为网关、
第三方网络测试或对抗性部署。无需为交接改变技术名称或掩盖实际行为。
此前模型中断的具体原因无法由仓库证据确定；不要把模型停止直接当作产品故障。

最重要的四点：

1. 已提交的共享图、Root 多 lane、owner/completion、TUN DROP、双栈重组成功路径
   和平台事实基础，不应从零重做。
2. S229 有大量已保存的局部 PASS，但仍有明确验收缺口，尚未完成。
3. 真实 HEV/lwIP 的产品 Direct+return 仍属 S237–S243；历史 handcrafted bridge
   和实验 PASS 不构成该产品能力。
4. 每个切片完成自身错误清理和基本 stop，再推进下一项；不能把泄漏留给父任务。

## 2. 仓库现场与保护范围

检查时分支：`docs/s103-vpn-flow-stack-fixed-spec`。

HEAD：`46235ce95765d4b2c1e5fd0bd60e894ed9a522c4`
（`feat(s219): preserve first-fragment facts for native TUN reassembly`）。

已有 tracked 修改，全部保留：

| 文件 | 当前修改意图，尚非审核结论 |
| --- | --- |
| `src/product/vpp/product-vpp-artifact.properties` | artifact ID 改为 `sakamoto-product-vpp-s229-v1` |
| `src/product/vpp/product_packet_graph.c` | fragment-ingress trace；注入 CLI main-thread 检查及 `is_mp_safe` |
| `src/product/vpp/product_packet_reassembly_graph.inc` | originals 容量限制、native handoff ring 观测/受控容量、错误 trace 与 trace 初始化 |
| `tests/device/helpers/s219-tun-udp.c` | 可选 payload 长度，支持容量场景 |
| `tests/device/s219-pixel-tun-fragments.py` | 增加 `--capacity` 与容量后恢复场景 |
| `tests/device/verify-s219-tun-fragments.py` | 对应容量、original settlement 和恢复验证 |

已有 untracked 文件，不能遗漏或清理：

```text
tests/device/helpers/s229-local-activity.c
tests/device/helpers/s229-nfq-policy.c
tests/device/s229-linux-reassembly.py
tests/device/s229-pixel-reassembly.py
tests/device/s229-reassembly-scenarios.py
tests/device/verify-s229-reassembly.py
```

这些变更在本轮检查前已存在。不要 reset、checkout、clean 或批量覆盖。
仅 Git commit/patch 不足以转交：还要保留 untracked 脚本、构建 witness、实际 artifact
和 run 目录。`build-output/` 与 `/tmp/` 不保证随 Git 克隆携带。

### 已核对的构建身份

本轮用 `tests/evidence/product_chain.py` 的 `source_files()` / `encode()` 重算，
当前 Product 源码集合指纹为：

```text
39b5ab3433080407daa7b5235fe6f35bcb927edaa323aec2b27d150f94593d41
```

它与下列两个 `build-d` witness 相同：

| 项目 | 位置或身份 |
| --- | --- |
| Linux build | `build-output/s229-errors/linux-build-d/build.json` |
| Linux artifact | `build-output/product-vpp-host-s229-d` |
| Linux build.json SHA-256 | `2aedd485cb0028e66686434d75fa0a96405b5c87d0dfefab40a5c02204e1cc24`，来自已有 verifier 记录 |
| Pixel build | `build-output/s229-errors/pixel-build-d/build.json` |
| Pixel build.json SHA-256 | `0bf70d4c3de914cc1f564e55928ada96cbcf99e6362b49f031773b7480100500`，来自已有 verifier 记录 |
| APK | `build-output/s229-errors/pixel-build-d/apk/sakamoto-runtime-debug.apk` |
| APK SHA-256 | `6c212009fc8e70f29a5e75317a8ee56869e2f5c73f74383b00f8beac64380f80`，来自 build/run witness |
| Pixel product plugin SHA-256 | `80e62b9f58bd06193b8e452df06e4cb4d29a81ed382623ca0067255971d8e2ea` |
| 两 build 记录的 dirty diff SHA-256 | `e9ab10427473d33cb92a72c12355abc94d3352ec64a9e240a77898eb5baa71a0` |
| pinned VPP | `9258530f3804a152578ce11cc7c8a1e9eab88ed0` |

**核对范围限制：** 本轮重新计算了 Product 源码指纹，阅读了 witness/verification；
没有重新验证全部二进制 hash，也没有重新运行真机。该源码集合覆盖
`src/product`、`app/android-runtime`、`crates/product-core`、Cargo 文件与 `.cargo`，
不覆盖全部测试/helper/build tools。测试程序必须另存 source/hash/编译命令，
不能用 Product 指纹一致替代测试身份验证。

## 3. 架构约束与阅读顺序

先读 `AGENTS.md`、`/home/js/.codex/RTK.md`、`CONTEXT.md`、
`docs/agents/domain.md`、`docs/agents/issue-tracker.md`。
然后读 ADR-0006/0007/0008，以及对应切片决策和验收记录。

固定边界：

- 一个受 RuntimeService 监督的 VPP Runtime；Android Root/VPN 互斥，共享图与策略。
- packet domain 为 VPP-native C；Rust 负责粗粒度控制、策略、状态等，不拥有逐包 buffer。
- 不恢复、翻译或参考已删除的 C++ daemon/host model/测试/兼容层；不直接导入 POC 源码。
- Canonical OwnerAssignment 唯一；queue/CPU/ifindex/namespace/provenance 不成为第二套 owner key。
- 正常远程路径只有 Primary Handoff；terminal intent 回 origin lane，再进行唯一物理 completion。
- 区分 Policy Verdict、Adapter Completion、Transport Outcome 与 Runtime/Infrastructure Fault。
- 已确定 DROP 不因资源压力变 ACCEPT。检查资源不足能否交还，取决于原包、真实 identity
  和可用正常出口；不能把“尝试交还”写成“已送达”。
- S210 已有 bounded retained completion return；其 ring 再投递不能误解为重试
  `nfq_set_verdict` 物理操作，也不授权新增无限重试体系。
- VPN 采用 ADR-0007 已选 owner-inline HEV/lwIP；保留两次边界 copy，各自拥有内存。
  返回包标为 `FLOW_STACK_RETURN+INPUT`，重新经过共享图后才写 TUN。
- FlowEntry 与 transport PCB/session/socket 的状态和生命周期分开。
- 未知身份/网络事实保持 unknown；不等待、不猜测。缺事实 predicate no-match，
  其他可求值策略继续。
- stop 为 quiesce → bounded drain → close；正常清理与进程退出后的 OS reclaim 分开证明。

### 文档的时间陷阱

`docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md` 后段仍有从 S114–S117 开始的旧启动文字；
`docs/IMPLEMENTATION_ROADMAP.md` 保留多处 ADR-0008 前的历史完成清单。
不能照旧段落退回早期 POC。S195 dossier 也保留历史 PASS，其 VPN Card D 明确是
`NOT PROVEN for ADR-0007`。应结合最新 ADR、当前代码、具体 S203+ 验收记录与 Plane 正文。

Plane 某些旧依赖边因关系删除 API 不可用而保留。按任务正文末尾
“2026-09-05 当前执行依赖”执行，不按失效面板关系制造循环阻塞；不要继续排查删除 API。

## 4. 已建立的基础：本轮读取的 Plane 状态快照

下表的 Done 表示 tracker 状态，并不意味着本轮重新验收。

| 任务 | 已完成增量 | 仓库证据入口 |
| --- | --- | --- |
| S203–S206 | Root 真图、Completion Frame、remote Primary Handoff、双栈 Q2/W2 lanes | `docs/testing/SAKAMOTO_203_ROOT_GRAPH.md` 至 S206 对应文档 |
| S207–S209 | typed OwnerAssignment、owner-local FlowEntry/ORIG-REPLY、无全局热路径策略锁 | S207/S208/S209 对应文档 |
| S210 | Primary capacity bypass 与 retained completion | `docs/testing/SAKAMOTO_210_CAPACITY_BYPASS.md` |
| S216–S218、S232 | typed metadata、Root UID/hook/ifindex、Android 网络快照与 TUN facts | 对应 testing 文档 |
| S212、S228、S219 | IPv4/IPv6 native reassembly 成功路径与 offset-zero 首片事实 | 对应 testing 文档 |
| S213、S198、S214 | native TUN DROP、共享协议解析、remote completion | 对应 testing 文档与 Plane |
| S230、S231 | Linux 真 NFQUEUE 验收入口与实际分片可见性 | 对应 testing 文档 |
| S200 | handcrafted Direct bridge 已降级隔离为 POC | Plane；`experiments/handcrafted-direct-bridge/` |
| S244 | 窄范围 source/artifact/run 证据链及反例 | `tests/evidence/README.md`、S244 testing 文档 |
| S245–S247 | 真实 HEV/lwIP copy 输入、输出与同时占用实验 | `experiments/vpp-nfq-poc/s245-s246/README.md`、`s247/README.md` |

S211、S215 为 Cancelled，不复活为独立实现任务。
S199、S201、S202 是汇总父任务；不要把它们当成一次性大改，也不要求父任务先 Done 才做子任务。

## 5. S229 已有结果及真实缺口

正式题目：双栈重组错误、资源不足与 teardown 真机闭环。
Plane 当前为 In Progress，正式前置 S210、S219 均 Done；本轮读取 comments 返回空列表。

### 已保存的验证结果

以下目录均在 `build-output/s229-errors/` 下。PASS 为现有文件内容。

| 目录 | 记录 | 能支持的范围 |
| --- | --- | --- |
| `l-basic-d2` | PASS，26 originals | Linux native graph basic |
| `p-basic-d2` | PASS，26 originals，generation 956 | Pixel native graph basic |
| `l-in-d` | PASS，18 originals | Linux ingress-handoff rejection |
| `p-in-d` | PASS，18 originals，generation 957 | Pixel ingress-handoff rejection |
| `l-policy-d` | PASS，24 originals | Linux policy DROP retained return |
| `p-policy-d` | PASS，24 originals，generation 958 | Pixel policy DROP retained return |
| `p-tun-capacity-d` | PASS，40 originals、28 fragment originals、8 datagrams，generations 959/960 | 真实 TUN 容量失败与随后图/completion 恢复 |
| `nfq4-c` | PASS，65 originals，generation 21210 | 较早 c 产物的 `NFQ_CAPTURED`；不能替代 d 产物验收 |

前三组使用明确的 `GRAPH_INJECTED` 输入，实际经过目标 Product native 节点；
不构成真实 NFQUEUE 原片 ingress/completion E2E。

basic 当前场景包括双栈 timeout、malformed envelope、conflicting overlap、
byte-identical duplicate、context capacity、policy DROP 和 incomplete context stop。
verifier 逐原包核对 ingress/completion/release/free、generation、buffer identity、
origin worker、引用计数与 residue。

### 必须接着处理的缺口

**A. sendout-handoff 未形成有效验证闭环。**

`l-out-d/result.json` 是 `RAW_COMPLETE`，不是 PASS；该目录未找到 verification.json。
本轮在日志中未找到 verifier 要求的 `reason=8 prepared=1`。
不能从运行结束推出 prepared/sendout rejection 已覆盖。
先核对 native finalize→handoff 分支、worker/context placement、实际 ring occupancy，
再决定是场景没有命中还是实现缺陷。保留双栈、真实拒收和逐 original settlement 断言。
Pixel 对应成功证据也未在本轮定位到。

**B. 最新 NFQUEUE 双栈复验在策略安装处失败。**

`nfq4-d2/result.json` 与 `nfq6-d2/result.json` 均 HOLD：

```text
policy rc=12
detail=policy bundle L4 entry 0 contains invalid typed rule fields
```

IPv4 generation 21210/revision 2；IPv6 generation 22810/revision 4。
这证明对应 policy apply 失败，不足以归因为重组算法错误。
从以下位置检查：

- `tests/device/helpers/s229-nfq-policy.c`；
- `tests/device/s212-linux-reassembly.py`、`s228-linux-reassembly.py` 的 `--policy-client`；
- `src/product/include/sakamoto_product_core_ffi.h` 的 typed constants/ABI；
- `crates/product-core/src/lib.rs::validate_policy_rule_entry`；
- helper 实际编译的 header、链接的 cdylib、运行时 `LD_LIBRARY_PATH` 和 helper hash。

只读检查确认 helper 的 family=4/6、protocol=17 与当前 Rust 常量一致，
不能把这些数值直接当成根因。仍需核对完整 typed fields、ABI 布局与实际运行的 helper/cdylib；
本轮尚未运行证明具体哪字段有误。
先用最小合法 L4 bundle 和真实 apply/readback 定位，不能删规则、放宽校验或跳过 DROP 场景。
修改 helper 后重编并记录 hash；若 Product 源码不变，不必无理由重建所有产品 artifact。

**C. TUN “恢复”不能扩张为网络送达。**

`--capacity` 以 6000-byte UDP 和受控 originals limit=4 触发 bundle 容量边界，
随后用 1800-byte 流量验证正常路径恢复。当前 verifier 的 recovery 分支期待
Policy allow、intent=1，但 transport 为 `UNAVAILABLE/UNSUPPORTED`；这是共享图与
completion 的恢复，不是 HEV/lwIP Direct 网络恢复。
runner 中部分 help/comment 仍称 subsequent normal DROP，应对照实际 policy/readback
统一表述，并确认普通非 capacity 的 S219 DROP 矩阵仍有效。

**D. 证据与测试本身还需审视。**

- 审核 `is_mp_safe=1` 是否只改变预期的 CLI barrier 行为；main-thread-only 检查不等于
  自动证明全部共享状态读取/修改线程安全。
- ring 容量 seam 只应在空图/空 ring 受控生效，不能改变正常 enqueue/free 语义。
- `fprintf` trace 必须保持有界诊断范围，不引入常态逐包同步日志。
- verifier 不能因缺少 status 行而通过空集合检查；关键 residue/status 必须存在。
- 增加有意义的证据反例：缺 completion、重复 free、错误 generation/adapter kind、
  无真实 prepared rejection、source/artifact 错配应被拒绝。
- 保留失败目录，不覆盖原 verification；重复验证需要保存原记录或用独立副本。

### 分片入口不能混用

S231 已测得：Pixel 四个 Root hook 都看到 kernel-reassembled packet；Linux 测试 namespace
的 IPv4 raw OUTPUT、IPv6 INPUT/raw OUTPUT 能看到原片，IPv4 INPUT 看不到。
这是具体 kernel/hook/config 的测量，不是所有 Linux/Android 的永久结论。

因此 Pixel Root 的 native 原片错误场景用显式 GRAPH_INJECTED；Linux 可达分支用真实
NFQ identity；真实 TUN 分片另列。不能伪造 NFQ packet ID，也不能为了凑 PASS 改产品 hook。

## 6. S229 建议完成顺序与完成标准

1. 保存上述源码、untracked 文件、build-d witness/artifact、已通过和失败 run 的索引。
2. 核对 helper/ABI/动态库身份，修复 NFQ policy apply 的具体问题。
3. 在新目录完成同源 Linux IPv4/IPv6 可达原片复验，包含 DROP、allow recovery、
   每片唯一真实 verdict attempt、普通 TCP/UDP 回归与 stop residue。
4. 最小化 sendout 场景，证明双栈 `prepared=1` 的实际 native handoff rejection；
   再验证完成 obligations 不丢失。若遇不可达条件，记录具体控制流事实并对照 S229 正文
   审视覆盖缺口，不能降低断言冒充完成。
5. 审核 capacity/trace/CLI seam 和 verifier；补针对新断言的反例。
6. Product 变更则构建新 witness；仅测试变更则保留 Product 身份并记录新测试身份。
7. 复验受影响 S219/S229 路径，形成一份最终 evidence index，区分真实 ingress 与图注入。
8. 对照 S229 全部正文验收条件作逐条证据映射，记录 runtime fault、processing bypass、
   no-return、policy DROP 的真实物理结果，以及 stop/restart 后的资源归零。
9. 完成代码审核、适用检查、验收文档和实施提交后，再按授权更新 Plane。

单纯 `RAW_COMPLETE`、已有旧 PASS、脚本能运行、某类计数增加或进程退出，都不是关单标准。

## 7. 后续任务依赖与建议调度

下表依赖来自本轮读取的 Plane 正文。执行前刷新；建议顺序不修改正式依赖。

| 任务 | 正文前置 | 实施输出与边界 |
| --- | --- | --- |
| S220 | S207、S230 | worker→CPU 有序映射；反序/非连续真实 affinity；非自动优化 |
| S221 | S209、S207 | 每 owner 一套 typed table + fixed pool；完整 key 比较；固定 OVS 来源 |
| S222 | S221 | 完整 OVS-derived TCP tracker；不含 transport/NAT/独立 timer |
| S223 | S221 | UDP FIRST/MULTIPLE/BIDIR；为 FlowEnd 和 VPN 首片解锁 |
| S224 | S221、S207 | ICMP Echo session；sequence 不进 key；不含 RELATED 或 VPN ICMP transport |
| S225 | S223 | 无首包保留的 FlowEnd 空 buffer → consumer graph → free callback |
| S226 | S225、S223 | Pixel polling/deadline-wake 预注册 A/B，形成调度决定 |
| S233 | S206、S230 | 无监听/queue-full/ingress reserve 各自 fail-open 与恢复 |
| S234 | S225、S233 | FlowEnd alloc 耗尽退出、Root 恢复和资源边界 |
| S227 | S223、S225、S226、S234 | UDP 首个统一 expiry scheduler 真机闭环 |
| S235 | S217 | Linux 每接口网络快照，Wired/Wi-Fi/Mobile/VPN/unknown 投影 |
| S236 | S227、S222、S224 | TCP/ICMP timeout classes 接入同一 scheduler |
| S237 | S200、S198、S218、S209、S221、S223 | 单 owner UDP4，真实 HEV/lwIP Direct+return；消费 S245–247 证据 |
| S238 | S237、S207 | 真实 IPv6 UDP Direct+return |
| S239 | S238、S214、S209 | W2 shards 同时运行与跨 lane return |
| S240 | S239、S222 | 真实 lwIP 双栈 TCP；与 VPP CT 分域 |
| S241 | S240、S210 | policy capacity bypass 与 transport failure 分开验收 |
| S242 | S206、S209、S210、S233 | Root 非分片 lifecycle；父任务联合矩阵再纳入 S229 |
| S243 | S241 | 真 VPN underlay epoch、stop/crash/restart 与旧事件清理 |

### 推荐的连续执行批次

**批次一：S229 收口 → S221 → S223。**
先结束当前 dirty 现场，再建立后续共享数据结构与最小 UDP 状态。
S221 不要实现三套 table、不按协议预分容量、不做 eviction，不顺带实现 scheduler。
S223 使用 first-observed ORIG/REPLY，不按端口或 INPUT/OUTPUT 猜 client/server。

**批次二：按产品目标选择就绪分支。**

- 若优先获得真实 VPN：S237 → S238 → S239；在 S240 前补 S222。
- 若优先收敛生命周期：S233、S225 → S234；S225 后做 S226，随后 S227。
- S220、S235 为可独立安排的配置/平台切片，不必成为无关模块的人为前置。

这些是可独立实施的分支，不表示必须同时启动多个模型。共用 Pixel 时必须有唯一设备操作者；
共改 graph/metadata 头文件时避免多个实现者同时写同一区域。

**批次三：完成联合能力。**
补 S224/S236；VPN 走 S240 → S241 → S243；Root 走 S233 → S242。
S199/S201/S202 最后使用当时源码构建的产物复跑适用联合矩阵；子任务 Done 不自动替代集成。

### 两个不能提前决定的问题

- S226：约 1 秒清理是第一轮正常负载实验目标，不是硬实时承诺。必须预注册两臂、
  指标/阈值、热状态、batch 与 Doze 条件。不能把旧 Flow Stack wake 实验结果当 expiry 决策，
  也不能先做完整 S227 再补 A/B。
- S234：本阶段明确接受 FlowEnd 新 buffer 分配失败后 runtime 退出的简单方案，
  但必须用真实容量/恢复证据界定可接受性。不能暗加 emergency pool、pending/retry 系统。

## 8. 真实 VPN 首切片的交接要点

S237 开始前读 ADR-0007 的 2026-09-05 copy、output callback、return facts 小节与
S245–S247 实验 README/证据。实验已 Done，不从头重开 zero-copy 选择。

需要形成可审核的窄 C/VPP interface，并逐项回答：

1. 输入何时 copy 到 lwIP 自有存储；原 VPP buffer 在哪条既有 completion/free 路径结清。
2. 输出 callback 如何 copy 到新 VPP buffer、填 facts、交给同 owner 原生 graph scheduling。
3. 入图接受前失败由谁 free；入图后由谁负责；不得递归执行整个返回图或等待 TUN write。
4. session 只按值保留可靠应用身份和 availability，复用 underlay binding/epoch；
   不保存输入 metadata/FlowEntry 指针，不以 Direct socket 自身 UID 代替原应用。
5. bind/protect 必须在 connect/首发前完成，失败不做未保护 fallback。
6. 真实返回经过共享 parser/selector/policy；DROP 不写 TUN；provenance 防止回到 lwIP。
7. 单 owner UDP4 正常与最小故障/stop 证据闭合后，才扩大 IPv6、W2、TCP 和完整 lifecycle。

S243 还需保留 S198 的未定因观察：`build-output/s198-protocol/pixel-c/result.json`
与 `g0-running.poll` 中 generation 924 在矩阵前 `product_core_not_ready`，
inactive Stop 保留错误；当时启动前 native log 不完整，根因未确认。
同 APK 后续 925/926 PASS 不等于此启动问题已修复。不要把它推断成确定泄漏。

## 9. 构建、验证和环境入口

所有 shell 命令使用 `rtk` 前缀；Android 仅用 `./dev/adb`。
以下为接手者的命令模板，本轮没有执行 build/deploy/test。

只读起步：

```sh
rtk git status --short
rtk git log -12 --oneline
rtk git diff --stat
rtk git diff --check
rtk proxy /home/js/.agents/skills/plane-ops/scripts/plane-ops.sh work-item get SAKAMOTO-229
```

Linux 构建入口：

```sh
rtk proxy python -B tests/evidence/build_s230_linux.py \
  --output build-output/s229-next/linux-build \
  --artifact build-output/product-vpp-host-s229-next \
  --stage /tmp/sakamoto-s228-host-stage-v2
```

该 builder 显式关闭 Host evidence，使用真实 Product graph。不要只调用默认 Host builder
并假定它是产品真图。Linux stage manifest 为 `host-vpp-stage.properties`。

Android 构建入口：

```sh
rtk proxy python -B tests/evidence/product_chain.py build build-output/s229-next/pixel-build
```

builder 默认依赖 `/tmp/sakamoto-s181-clean-vpp-stage.current`、
`build-output/pinned-vpp-clean`、`/tmp/sakamoto-pydeps`。本轮观察到两个 stage 目录与
pydeps 目录存在，但没有重新证明其完整性。换机器时先恢复真实 pinned stage/patch 和工具链，
不能用任意 POC stage 替代。输出目录必须新建，不覆盖历史 witness。

S229 runner 参数：

```text
s229-linux-reassembly.py
  --output --artifact --vppctl --policy-client --control-dir
  --suite basic|ingress-handoff|sendout-handoff|policy-return
s229-pixel-reassembly.py
  --apk --policy-helper [--activity-helper] [--reference-run]
  --suite basic|ingress-handoff|sendout-handoff|policy-return --output
verify-s229-reassembly.py
  --build <build.json> --run <directory> --platform linux|pixel --suite <suite>
s219-pixel-tun-fragments.py
  --apk --policy-helper --endpoint --capacity --output
verify-s219-tun-fragments.py
  --build <build.json> --run <directory> --capacity
```

Linux runner 要求 isolated rootless user/network namespace，不能直接对宿主网络执行。
它检查 `getuid()==0` 且 uid_map 的宿主映射非 0；具体启动和 veth 操作复用 S230/S231 runbook。
图注入 collector 使用的 policy helper 参数与真实 NFQ helper 不同，不能只因文件名相近替换。
`build_s230_linux.py` 默认编译 `s230-policy.c`，不会自动编译所有 S229 helpers。

Pixel 已有 evidence serial 为 `28201JEGR0XPAJ`，包名
`com.sakamoto.snort.androidruntime`。这是记录中的设备，不代表本轮确认设备在线。
安装前检查脚本是否卸载、清除 policy、切 Wi-Fi 或设置诊断环境，保存待恢复状态。
uninstall/reinstall 可重置 KernelSU Superuser grant；遇 `root_authorization_required`
按 `dev/README.md` 用 wrapper 截图/UIAutomator 检查授权，不先改产品逻辑。

## 10. 验收记录格式与防止再次丢失进度

每个执行切片至少保留：

| 记录 | 必须说明 |
| --- | --- |
| scope | 任务号、实际证明的平台/协议/owner/故障，不声称尚未开放能力 |
| source | HEAD、dirty diff、含 untracked 的源码集合、构建前后身份 |
| artifact | VPP/native/APK、stage/patch、helper 与实际加载库 hash |
| environment | 设备/kernel、namespace、hook、网络、CPU/worker、generation |
| input | NFQ_CAPTURED / TUN_CAPTURED / GRAPH_INJECTED / Host/POC 的明确来源 |
| observations | 实际 node/thread、owner/lane、policy、completion、transport、endpoint |
| conservation | 每个 obligation 唯一结清、buffer/frame/credit/context/flow、stop residue |
| result | PASS/HOLD 与具体缺口，原始目录及 verifier/反例结果 |

S244 基础 checker 只认证其已实现的 Root/IPv4 UDP/单 lane owner-local 范围；
不能把它的 PASS 当全协议/全 VPN 通行证。新切片应扩展对应语义 verifier，保留缺证据即 HOLD。

长任务每完成一个可解释阶段，就更新短 checkpoint：当前源码、artifact、已通过 case、
最后失败命令/原始错误、是否存在活进程/设备状态、接下来一个具体动作。
设备安装、构建冻结、长测开始、失败退出和提交前都保留这个记录。
停止时区分：模型中断、工具权限、环境缺失、测试未命中、产品故障、验收尚未覆盖。
不能将它们统称“无法执行”或“安全问题”，也不能以换模型代替技术诊断。

## 11. 后续产品发布范围

共享图和真实 VPN transport 完成后，仍须依据
`docs/product/ANDROID_L4_PRODUCT_PLAN.md`、`ANDROID_L4_RELEASE_GATE.md`、
`docs/INTERFACE_SPECIFICATION.md` 和 Plane S59 等任务，重新核对实际产品 UI、
Activity/store、策略事务、初始化/通知/权限、支持设备矩阵、签名 APK、升级恢复、
性能/功耗/thermal/soak 与用户材料。

本轮没有完整审计这些发布项，不把旧任务 Done 推定为当前产物发版就绪，也不凭空创建
新的 backlog。Protocol Identification（S61–S63 等）、DNS/domain 后续能力按产品阶段推进，
不塞入 S229 或 FlowRuntime 基础切片。

## 12. 可直接交给下一模型的启动说明

```text
继续 /home/js/Git/sakamoto/sakamoto-snort。
先读 AGENTS.md、RTK.md 和 docs/testing/2026-09-09_IMPLEMENTATION_HANDOFF.md，
再读 ADR-0006/0007/0008、相关 decisions 与 Plane S229 正文。
用户要求接续现有实现；不要重新设计主线，也不要丢弃 dirty/untracked 文件。

快照 HEAD=46235ce95765d4b2c1e5fd0bd60e894ed9a522c4。
当前 S229 已有 build-d，Product 指纹为
39b5ab3433080407daa7b5235fe6f35bcb927edaa323aec2b27d150f94593d41。
先核对现场是否变化。Linux/Pixel basic、ingress-handoff、policy-return 有已有 PASS；
真实 TUN capacity 有 PASS，但只证明图/completion 恢复，transport 仍不可用。

下一具体动作：核对 nfq4-d2/nfq6-d2 的 policy rc=12 invalid typed rule fields，
检查 s229-nfq-policy helper 的 typed constants/ABI/实际链接库，不先改重组算法。
随后完成 sendout-handoff 双栈 prepared=1 真实拒收证据，审查 verifier 与测试 seam，
完成同源真实 NFQ/Pixel 适用矩阵、stop residue 和最终证据索引。
不要把 RAW_COMPLETE、graph injection 或旧 c 产物 PASS 当作本轮完整 PASS。

只用 repo ./dev/adb；Plane 用 plane-ops REST，不用 MCP。
测试仅作用于用户端点和隔离测试网络；保留原始错误与恢复状态。
S229 关闭后优先 S221→S223，随后按已就绪依赖推进 FlowEnd/expiry 或 S237 真实 VPN UDP4。
每次只完成一个主要切片，不等父任务整体 Done 才做子任务；不恢复 C++，不导入 POC，
不增加 Corrective Handoff/第二套 owner/共享 buffer 体系。
```
