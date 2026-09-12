# S229 后续实施规格附录

日期：2026-09-09。对应 [现场交接](2026-09-09_IMPLEMENTATION_HANDOFF.md)。
用户要求：尽量消除下一执行者在设计、模块划分、接口、编码顺序和验收上的自由解释空间。
本文只交付实施规格，没有产品代码修改、部署、测试 PASS 或任务状态变更。

## 1. 规格效力与执行纪律

### 2026-09-11 用户校准：参考来源与当前范围

- **分片重组**：使用产品自己的有界重组与两阶段 handoff 设计，
  替换当前 upstream full-reassembly 业务路径。保留分片聚合、offset=0 首片 owner、重组后
  转交、乱序/重复/重叠/超时及逐 original completion；不得将原生内部 sendout 分支不可达
  作为豁免重组后跨 owner 拒收验收的理由。下文 §3 原生节点、错误码及压力场景描述是
  改造前快照，需要随替换重新映射，旧 PASS 不证明新实现。
- **重组配置**：64 contexts 和每 datagram 32 originals 只作为默认值，不能写成编译时容量
  上限。通过启动配置调整容量，启动时校验数值、乘法溢出及内存预算并按配置预分配；
  修改配置后重启生效，运行中不自动扩容。分配失败明确启动失败，不暗中缩小容量。
  默认 context 配额为每重组 worker 64 个；配置键与内存校验范围在实现接口时记录，
  不得再用固定数组或隐藏的 64/32 上限限制调整。
- **重组支持范围**：当前接 L3 IPv4/IPv6，不增加 L2 入口和隧道内层重组；观测以产品现有
  trace/status/evidence 为主。普通 IPv6 扩展头处理、重复/重叠语义不能以“不做网关”为由
  隐式缩减；任何不同于参考行为的处理须单独说明。出站重分片及其无消费者的辅助信息
  不在当前范围。已有代码草稿中的硬编码容量和仅紧邻基础头的 IPv6 Fragment Header
  解析限制，不是已接受的实现。
- **ACL**：保留当前 UID 分组、按优先级有界扫描的静态规则实现；当前要求是规则匹配、
  precedence、快照发布和 stage 行为正确。mask/hash 等结构优化留待单独重新设计和重构，
  不加入本轮 S229/FlowRuntime 范围。可复用保留下来的历史设计讨论，不参考 ADR-0008
  已删除的 C++ 实现。
- **FlowRuntime**：使用本产品的职责划分、生命周期与 Interface，使用本产品
  的 FlowRuntime/FlowEntry 名称；按 Android/Linux 本地端点的实际规模裁剪，不照搬网关规模、
  NAT/多域索引、LRU/eviction、通用附件机制。§4 的具体布局是已有方案，需要在 S221 对照
  已确认的职责和生命周期核对是否足够；设计复用不等于代码导入，也不等于已完成实现。
- **协议 tracker**：TCP/UDP/ICMP 的状态与 timeout 语义继续以 OVS 为母本，
  不因本次设计校准重开协议母本选择。
- **Expiry**：使用独立 timer 封装和有界清理设计，以满足本产品需求为准。§7 的
  indexed min-heap 保留为候选方案，不视为必须采用或必须放弃的结构；不得将它宣称为
  既定唯一设计。owner-local、容量有界、deadline 语义及实验验证要求继续有效。

设计文档与代码描述产品自身的职责和行为，不保留参考项目名称或本机参考源码路径。
完整共识见 [owner/lifecycle 决策](../decisions/PER_WORKER_FLOW_OWNERSHIP.md#2026-09-11-flowruntime-参考范围)
及 [重组 metadata 决策](../decisions/VPP_PACKET_METADATA_OWNERSHIP.md#reassembled-platform-facts--2026-09-05-kiss-rule)。
本补充优先于下文对 FlowRuntime/expiry 具体物理布局的绝对化描述；其余契约保持有效。

使用三类标记：

- **[契约]** 已接受 ADR、领域决策或现有 Plane 正文中的要求。
- **[代码事实]** 本轮检查 HEAD `46235ce` 加既有 S229 dirty 内容所得事实。
- **[实施基线]** 本轮为减少实施分歧固定的具体方案；不是既往决策或已完成实现。

未标记的操作步骤属于实施基线。Plane 仍管理任务状态；本文不创建新的独立 backlog。
本规格不能覆盖 ADR-0006/0007/0008 或后续用户决定，也不能将历史文档中的 C++/全局 CT
段落重新解释为当前要求。

执行者只可自由决定局部变量、内部 helper 名称、代码格式和不影响 Interface 的局部拆分。
不得自行更改 owner/key、policy stage 顺序、内存转移、错误分类、重试语义、支持范围或验收门槛。
本文拟定的新函数名可因同名冲突调整，但调用语义、责任与返回值分区不变。
代码块为设计伪代码/目标声明，不能当成已经存在或可直接编译的头文件。

真实证据迫使偏离时，先写出四项：本规格条目、具体源码/日志证据、最小替代方案、受影响测试。
只暂停依赖该选择的路径；能独立完成的源码检查、构建准备和证据整理继续。
不得以“更现代”“更通用”“方便后续扩展”为理由替换已定方案。

默认连续实施顺序固定为：

```text
S229 → S221 → S223 → S237 → S238 → S239 → S222 → S240 → S241 → S243
随后：S233 → S242 → S225 → S234 → S226 → S227 → S224 → S236
最后：S220 → S235 → S199/S201/S202 联合验收 → 对照 S59 发布要求
```

这是优先打通真实 VPN 的工作顺序，不增加 Plane 依赖。遇真实 IPv6 环境缺失等阻塞，
只从尚未完成且正文前置已满足的任务中按上述顺序选下一项，不无限重试环境。
每完成一项就交付代码、证据、文档和适用提交；不累积十几个任务后才集中验证。

## 2. 当前代码地图与必须修改的位置

以下路径相对仓库根目录。

| Module | 现有位置/符号 | 责任和后续改动 |
| --- | --- | --- |
| Parser/Assignment | `src/product/vpp/product_packet.c/.h`，`product_owner_assign` | 唯一解析/typed key/owner；tracker 只消费事实 |
| FlowRuntime | `product_flow_entry.c/.h`，`product_flow_entry_observe` | S221 原地深化 table/pool/slot lifetime；不并排建立第二实现 |
| Graph wiring | `product_packet_graph.c`，`product_packet_graph_policy_on_owner`、`product_packet_graph_flow_observe` | 串接 policy、flow、tracker、consumer、transport；不拥有协议状态机细节 |
| Product reassembly | `product_fragment.c/.h`、`product_packet_reassembly_graph.inc` | 临时 datagram 表、首片 assignment、两阶段投递、original obligations 与完成回收 |
| Root I/O | `product_root_nfqueue_adapter.c/.h`，`product_root_nfqueue_complete_from_graph` | S233/S242 receive reserve、物理 verdict、lane 生命周期 |
| TUN I/O | `product_vpn_tun_adapter.c/.h`，`product_vpn_tun_complete_from_graph` | TUN fd 唯一读写 owner；S237 增加真实 return write |
| Network snapshot | `product_network_snapshot.c/.h`，`product_network_snapshot_publish/context` | S235 复用同一 bounded map 与 main-thread publish |
| Native control | `src/product/native/`，`src/product/include/`，`product_core.api` | typed control/status/启动配置，不能接入逐包 Rust callback |
| Rust Product Core | `crates/product-core/src/lib.rs` | bundle 校验、持久化、VAPI；S229 helper 失败定位处 |
| Android lifecycle | `app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java` | 监督、profile、恢复与状态展示 |
| Android fd/control | 同目录 `RuntimeControlFdClient.java`、`RuntimeControlNative.java`、`VpnHevTransportSession.java` | 现有能力需逐项核对可达性；不能按文件名推定真实 HEV 产品已接入 |
| Build | `src/product/vpp/CMakeLists.txt`、`tools/product/`、`app/android-runtime/scripts/` | 新 C Module 列入真实产品构建、源指纹、Android link closure |

新增文件范围固定如下；只在对应切片开始时创建：

```text
src/product/vpp/product_flow_tracker.h
src/product/vpp/product_flow_tracker_udp.c       # S223
src/product/vpp/product_flow_tracker_tcp.c       # S222
src/product/vpp/product_flow_tracker_icmp.c      # S224
src/product/vpp/product_flow_end.c/.h            # S225，VPP wiring/回调
src/product/vpp/product_flow_expiry.c/.h         # S226 最小实验，S227 生产调度
src/product/vpp/product_vpn_flow_stack.c/.h      # S237，产品 C Interface
src/product/vpp/product_vpn_flow_stack_hev.c    # S237，真实依赖适配 Implementation
```

表、free-list、bucket/hash 实现仍在 `product_flow_entry.c`；不再另加
FlowManager/SessionManager/Registry/Repository/通用事件总线。
`product_flow_tracker.h` 是内部 shared types，不公开到 Rust/Java ABI。
一个固定协议 switch 即可，不引入运行期 tracker 插件注册或虚函数表。

## 3. S229：按故障分支执行，不凭日志总数完成

### 3.0 2026-09-11 当前实现映射

产品独立重组节点为 `product-reassembly`，超时由 owner-local 的
`product-reassembly-expire` 处理；不调用 upstream full-reassembly custom 节点或 hooks。
对称 L3 地址散列确定临时重组 worker R，完整 datagram key 仍比较 family、协议、双地址和 ID。
offset-zero 首片调用唯一 `product_owner_assign` 保存 F；重组后
`product_packet_admit_selected` 验证完整包事实并恢复该 assignment，不重新散列。
R → F 复用现有 Primary Handoff；缺失首片不能产出成功包。

启动配置为 `product-reassembly { contexts 64 originals 32 timeout-ms 500 }`。
capacity 与 originals 按配置预分配 context/bucket/descriptor arena，包含一个同步 detach
暂存行；检查非零、索引表示与分配乘法溢出，不静默降容。运行图中的 configure CLI 只作
空图诊断容量实验，不改变启动默认值，也不允许有包时扩容。`geometry` 矩阵实际使用 65/33。

共享 IPv6 parser 跳过 Hop-by-Hop、Routing、Destination Options、AH，沿用有界
8 headers / 256 extension bytes 的预算，使用外层地址；不把 ESP/未知封装猜成 TCP/UDP。
正常 envelope 超出遍历预算保留 L4 unavailable；重组后无法完成已保存身份校验的合法
超预算扩展链按处理资源不足收尾，而不是捏造 protocol/policy DROP。短扩展链与 256-byte
边界均有实际 Product graph 字节重建验证；packet overlay 保持 56 bytes。

当前证据与改造前记录分开：[独立重组实现记录](2026-09-11_S229_INDEPENDENT_REASSEMBLY.md)。

### 3.1 policy rc=12 定位流程

[代码事实] Rust `validate_policy_rule_entry` 检查 subject UID sentinel、network_context、
kind/action/enabled/rule_id/reason_id/reserved、family/protocol/direction、prefix、port ranges。
family 4/6、UDP 17 是当前合法值；UID 0 也合法，不能将它改成 1000 来躲过错误。

固定定位顺序：

1. 从失败 collector 实际 argv 找到 `--policy-client`，不要使用猜测的同名二进制。
2. 记录该 ELF 的 hash、动态库依赖、实际 `LD_LIBRARY_PATH`、所加载 Product Core cdylib hash。
3. 用当前 header 编译仅打印 `sizeof`、相关 `offsetof`、每个 typed field 的 diagnostic helper；
   对照 Rust `repr(C)` 布局。不得打印 credential 或无关用户数据。
4. 在同一连接/generation 上先 apply 空 bundle，再 apply 单条 UID0/UDP4/OUTPUT DROP，
   再扩 UID、family、direction 组合；每步保存完整 rc/detail/readback。
5. 第一条失败时将全部校验字段与上面的 predicates 逐项对照；若 helper 值正确则继续核对
   实际加载旧库/ABI，不先修改 runtime 校验器。
6. 修复最小不一致，重新编译 helper，重跑原本失败的两个 collector，保留原 HOLD。

允许修复 helper 构造/编译链接/collector 调用；只有证明产品接受了错误字段或拒绝合法
字段时才修改产品校验。禁止删除 blocked 阶段、吞 rc、伪造 apply success。

### 3.2 reassembly disposition 表

| 条件 | policy | 终态与释放 |
| --- | --- | --- |
| malformed/conflicting overlap | 不生成 policy DROP | runtime fault，逐已知 original 结清 |
| timeout | 不推断恶意，不生成 policy DROP | incomplete datagram timeout，清 context，逐 original 完成 |
| duplicate | 首片/末片重复结束冲突 context；中间片按最新连续链重建 | 每个独立 obligation 都保留；不能按 payload 去重 completion |
| context/bundle/handoff 纯资源不足，NFQ identity/原片可交还 | 不伪造 ALLOW | processing bypass，origin lane 每片一次 NF_ACCEPT attempt |
| 同类资源不足，但没有安全正常出口 | 不伪造 ALLOW/DROP verdict | explicit no-return/transport failure，释放其拥有的资源 |
| policy 已 DROP，completion ring 满 | 保持原 DROP | 保留 carrier，走已有 bounded return；禁止丢 carrier 后补计数 |
| stop | 按已分类结果 | 先排 context/completion，再关 lane/channel |

在真实 NFQ 可达分支证明“可交还”；在 graph-injected/TUN 当前不具备正常出口的场景证明
“不可交还”。不能只测试后者便认为 processing fail-open 已覆盖。

### 3.3 sendout-handoff 场景约束

使用当前 `Scenarios.pressure('sendout-handoff')` 作起点。每个 family 独立重置为空图：
先建立不同产品 context，使首片确定的流所属 worker F 与完成重组的 worker R 不同；
读取 context/ring readiness 后，短暂 hold 目标 worker，分批完成多个 datagram。
必须在 hold 期间观察现有 VPP Primary Handoff retained enqueue rejection，而不是仅出现 context timeout。

每个 rejected output 关联：family、产品 handoff reason、`prepared=1`、queue ID、目标 thread、
当时容量/occupancy、bundle 全体 originals、最终 origin release。两族都必须命中。
允许调整流量顺序/诊断 hold；不允许修改 native enqueue 来主动制造假的返回值。
CLI worker barrier 会影响时序；压力窗口中不能用全局 barrier 查询“确认”并解除压力。
当前 `is_mp_safe` 更改必须检查访问的共享对象，不因避免 barrier 而假定整体线程安全。

### 3.4 verifier 必须拒绝的反例

对成功目录制作独立证据副本，逐项删除/改写一个事实，验证明确失败原因：

- 缺 `reassembly.status`、`completion.status`、必要 lane/stop 行。
- duplicate original 少一个 completion，或一个 buffer 多一次 free。
- 相同 buffer index 的不同 allocation lifetime 被合并。
- prepared rejection 没有双栈或 `prepared=0`。
- DROP carrier 被改成 bypass/ACCEPT。
- generation、origin、source/artifact、实际 helper hash 不一致。
- 只有 process_absent，但正常停止资源账仍非零。

判断必需 record 时先断言数量/存在性，再对字段 `all(...)`；禁止空集合真值通过。
保存结果到新的 verification 文件或副本，不覆盖已有正例。

## 4. S221：统一 owner-local FlowRuntime 的具体实现

### 4.1 已有状态与改造方式

[S221 前的代码事实，现已替换] 原 `product_flow_entry_pool_t` 含 64 个内联 entry，
lookup/free-slot 均线性扫描，只接纳 TCP/UDP；容量不足曾映射 runtime DROP。
[2026-09-11 实现] 现为 opaque `product_flow_runtime_t`，支持 TCP/UDP/ICMP_QUERY 共用
预分配 table/pool。graph 仍在 Gate/L4 后 observe；普通新流容量不足使用 processing bypass。
policy revision mismatch 只失效 decision，保留 identity/counters；runtime generation 不匹配则拒绝。

[实施基线；具体布局按 §1 的 2026-09-11 校准复核] 原地替换扫描实现，保留 `product_flow_entry` 文件和已有命名家族。
使用启动时一次分配的 entry array + fixed bucket-head array + index-based intrusive 链 + free-list。
不使用可增长 VPP pool 来暗中突破硬上限，不加入 LRU/eviction/跨 owner 借位。
bucket 个数取不小于 `2*entry_capacity` 的最小 2 次幂；启动校验乘法/round-up 溢出。
bucket 由现有 canonical hash 折叠选择，当前为 `(h ^ (h >> 32) ^ (h >> 16)) & mask`；
不重算 hash，不把它当第二次 owner selection。最坏 lookup 有 capacity 次遍历的硬界。

S221 的 FREE/LINKED 两态复用一个 private `next` 字段分别承载 free-list/bucket 链，
不用重复存储两套 link。entry 的只读 `incarnation` 记录 allocation serial，不是外部 flow identity。
invalid index 为 `UINT32_MAX`，0 是合法 slot。删除从 bucket unlink，不移动其他 entry。
池初始化失败整体启动失败，不以减小容量偷偷继续；destroy 只在图排空后执行。
FlowEntry 容量独立 startup-only 配置，重启生效；64/owner 仅为旧实现事实，不作为正式默认值。
正式默认值待完整 entry/索引/timer 内存、worker 数量与端点流量验证确定，须包含等待超时
及等待 FlowEnd 回收的占用。不得写成固定数组或隐藏硬上限；实验必须记录实际启动配置。
当前 VPP stanza 为 `product-flow-runtime { entries N }`；1024/worker 仅是开发 composition
设置。`product flow capacity N` 只接受 stopped/drained runtime，作用于下次 start。

full-key equality 必须比较 kind/family/protocol、两端地址以及相应 union 有效字段：
L4 比较两端 port；ICMP_QUERY 比较 query_class/identifier。不依赖结构体 padding 的 memcmp。
不同 kind 即使 hash 和 union bytes 相同也不相等。禁止用 hash 命中代替全 key 比较。

### 4.2 Interface 与生命周期

FlowRuntime 对调用方统一管理查找/创建/更新/结束；table/pool、协议 tracker、Expiry 和
FlowEnd 的内部职责见 owner/lifecycle 决策，调用方不分别操作索引、timer 和 pool 拼装关闭。

S221 已实现的内部 Interface（具体类型见 header）：

```c
/* names abbreviated; all packet mutation runs on this runtime's actual owner */
flow_status create(runtime**, owner, owner_count, generation, capacity);
flow_status observe(runtime*, const owner_assignment*, const packet_observation*,
                    early_stage_result, flow_observation* out);
flow_status set_decision(runtime*, entry*, const policy_identity*, decision, rule, reason);
void flush_after_graph_drain(runtime*);
void destroy_after_graph_drain(runtime*);
snapshot snapshot_under_barrier(const runtime*);
const entry* diagnostic_entry_under_barrier(const runtime*, slot);
```

`observe` 仅借用 assignment/packet，返回 entry 指针只允许本 owner 当前同步处理段使用；
不得保存到 Rust、platform broker、Flow Stack session 或 detached task。
图内跨 node 使用 owner-local flow_index，且生命周期要由正常 graph ordering/FlowEnd 保证，
不能通过扩大 pointer 可见范围解决。

S221 阶段状态只有 FREE 和 LINKED；S225 加入 UNLINKED_WITH_END_BUFFER。
统一 unlink/release 的使用也在 S225 增加，不在 S221 暴露空实现。
不得提前添加 RETIRING_PENDING、分配重试队列或共享引用计数。

```text
FREE --create--> LINKED --normal close--> UNLINKED_WITH_END_BUFFER --free callback--> FREE
                        --stop after drain-------------------------------> FREE
```

`allocated_count = linked_count + end_inflight_count`；free-list 数量加 allocated_count 等于 capacity。
复用对象前必须清协议状态、缓存、附件标识和旧方向；allocation_serial 递增用于证据区分，
不是新对外 identity 或每包 token 管理器。

### 4.3 数据内容与 packet 顺序

entry 保留现有 key/hash、首见 source_is_a、policy identity、UID/network availability、
first/last seen；增加 per-side packet/byte counters 和 tagged protocol union。
union 的 tag 为 TCP/UDP/ICMP_ECHO；只保留协议当前任务实际需要的字段，不预留巨大字节数组。
L3 fallback 不创建合成 flow。S221 可为可靠 ICMP_QUERY 建空协议槽；S224 才声称 tracker 完成。

packet 顺序固定：

```text
native reassembly(适用时) → shared parse/assignment → owner placement
→ acquire one policy snapshot → Network Gate → stateless L4
→ 若此前 DROP：completion（不建 entry）
→ FlowRuntime observe → 已实现 tracker → shared flow consumers
→ 正常终端/transport → origin completion
```

S221 不移动 Gate/L4 到 tracker 后，也不提前开放 ct rule predicate。
当之后另有 CT 规则需求，必须独立设计 stage；不在本系列里反转已定早期 DROP 行为。

pool capacity miss：新增明确 FLOW_CAPACITY processing bypass reason，保留已完成的 Gate/L4
事实，跳过依赖缺失 entry 的后续阶段；不制造 CtFacts 或假 entry；若已有 DROP 保持 DROP。
Root origin NF_ACCEPT attempt；VPN 只有正常 Flow Stack 出口，S237 前如实 transport unavailable。
graph 必须停止把该分支映射成 `PRODUCT_PACKET_DROP_FLOW_CAPACITY`；wrong-owner/非法 mutation
仍是内部错误，不伪装资源 bypass。

### 4.4 验证卡

- 同 owner 同 key 正反向复用；不同 family/protocol/kind/identifier 不混淆。
- 固定相同 hash 的 controlled Interface collision vectors 加真实图受控碰撞证据；明确标注注入。
- cap=小值，满池现有 flow 仍复用，新 flow bypass；不影响另一 owner 的 free-list。
- revision 更新只清 policy cache，不清 tracker/counters；一次 packet 不跨两个 snapshot。
- Linux/Pixel Root 双栈 TCP/UDP/ICMP 真实创建/复用；记录实际 worker，不只验证传入 owner 参数。
- stop 后 buckets 空、allocated/free 数量守恒、无 live pointers/obligations。

## 5. S223/S222/S224：协议 tracker 规格

### 5.1 共用 Interface

tracker 仅接收 `const product_packet_facts_t*`、ORIG/REPLY、当前协议 state；返回更新结果、
CtFacts、timeout class 和 close/reuse 意图。它不能访问 table、VPP buffer、socket、clock、
policy store 或其他 worker。

```c
typedef struct {
  ct_state state;              /* UNKNOWN/NEW/ESTABLISHED/INVALID */
  flow_direction direction;   /* UNKNOWN/ORIG/REPLY */
  timeout_class timeout;
  bool refresh_deadline;
  bool close_old_instance;
  bool create_replacement;
} tracker_result;
tracker_result udp_update(udp_state*, const packet_facts*, flow_direction);
tracker_result tcp_update(tcp_state*, const packet_facts*, flow_direction);
tracker_result icmp_update(icmp_state*, const packet_facts*, flow_direction);
```

bool/enum 只是内部 C 表达，不直接成为 wire ABI。INVALID 不自动执行 Policy DROP，
不续期；不得因部分窗口检查失败留下半更新 state。使用局部 candidate state 验证后提交。
packet counters 可以记录被观察的 invalid packet，protocol accepted-state/expiry 不随之续期。

**OVS pin（S221 已固定）：** upstream `v3.1.0` 对应完整 commit
`3c2bea086ef8912d57331173af266f21d36740a0`。
源文件 hashes、BSD/Apache 归属、timeout 默认表与类名映射见
[`OVS_CONNTRACK_BASELINE.md`](../reference/OVS_CONNTRACK_BASELINE.md)。
TCP/UDP/ICMP/timeout 共用此 pin，不跟随 latest，不凭记忆改写秒数或 TCP window 算法；
已核对内容与 tag/commit，未声称独立验证其 PGP 签名信任链。

### 5.2 UDP（S223，先做）

| 当前状态 | 合法包方向 | 下个状态 |
| --- | --- | --- |
| 新槽 | 首见包定义 ORIG | FIRST |
| FIRST | ORIG | MULTIPLE |
| FIRST | REPLY | BIDIR |
| MULTIPLE | ORIG | MULTIPLE |
| MULTIPLE | REPLY | BIDIR |
| BIDIR | 任一方向 | BIDIR |

首见 reply-looking 包同样定义 ORIG，不使用 server-port 猜测。
状态向 timeout class/CtFacts 的映射从同一 OVS pin 提取，建立逐行映射表并测试。
重传 UDP payload 没有“重复 packet 可不计数”的特权。
S223 不实现自动 expiry；以有限流量和 stop 回收验收。

[S223 实现] `product_flow_tracker.h` 定义内部 CtFacts/result 和单字节 UDP state；
`product_flow_udp.c::product_udp_update` 消费 parser facts 与 FlowRuntime 给出的方向。
`product_flow_entry_packet_t.facts` 仅在同步 observe 中借用，entry 不保存该指针。
UDP 必须具有完整 parser facts；缺失 facts 是 Interface error，不是容量 bypass。
S223 当时 TCP/ICMP 尚未接入 tracker；S222 现已接入 TCP，ICMP 的 result 仍保持 NONE/UNKNOWN。
状态仍在现有 tagged union 中，entry 大小未因本项增加；没有新增 table/timer。
逐分支映射与实际 Linux/Pixel 验收见
[`2026-09-11_S223_UDP_TRACKER.md`](2026-09-11_S223_UDP_TRACKER.md)。

### 5.3 TCP（S222，保持完整任务）

[代码事实] parser 已提供 seq/ack/window/flags/wscale-known、transport length/offset；
metadata 用 scale=255 保存 unknown。必须保留已存在的 parse-once pack/unpack 路径，
不能让 tracker 再扫 TCP option。payload length 使用已验证 transport_length-l4_header_length。

Implementation 包含两个 peer 的最小状态、窗口/序号边界、wscale 及 flags 历史。
禁止以一个 ESTABLISHED bool 或最近时间戳替代完整 tracker。
新建有效性、loose midstream、重传、窗口判断、FIN/RST、close/reuse 一项不少；
有符号序号比较按母本 wraparound 语义，不用普通 `<` 比较 32-bit sequence。

提交前必须填写映射表：OVS 函数/分支 → 本产品函数 → 输入字段 → state mutation → timeout class
→ 测试 ID。排除 dp_packet/NAT/ALG/zone/锁/管理字段，保留状态机本身。
正常 handshake/data、同向和反向重传、window scale 缺失/0/边界、32-bit wrap、midstream、
FIN 双向、RST、相同 tuple 新连接都要覆盖。Host vectors 辅助边界，Linux/Pixel 真包证明图接线。
S222 原始阶段的 slot reuse 使用同步清理；S225 已将它替换为统一 FlowEnd 关闭，
新实例使用另一 free slot，不能覆盖跨 node consumer 仍持有的旧槽。

[2026-09-12 S222 实现] `product_flow_tcp.c` 在上述固定 OVS pin 上适配完整协议核心，
双 peer 状态置于现有 union。INVALID 使用候选状态回滚；INVALID-new 不造 entry 或
隐式 DROP。双 peer closed 后的新 SYN 由 FlowRuntime 结束旧实例并新建 incarnation，重置
ORIG、policy cache 和 accounting。BSD two-clause notice 随 Linux/Android 产物分发。
逐分支映射、131,072 步差分、真实 Linux/Pixel Root 双栈握手/重传/midstream/非法窗口/
FIN/RST/reuse 与 stop/restart 证据见
[`2026-09-12_S222_TCP_TRACKER.md`](2026-09-12_S222_TCP_TRACKER.md)。
这是观测 tracker，不是 S240 的 lwIP TCP transport；TCP 默认自动 expiry 仍由 S236 接入。

### 5.4 ICMP Echo（S224）

只接收 shared parser 确认的 Echo query/reply；identifier 入 key，sequence 不入 key。
用首见 packet 固定 ORIG，同时保存是否见过 request/reply 两个事实，不能将首见 reply
错误地标成 request。连续 sequence 共用一个 entry；新 identifier 为新 entry。
不实施 ICMP error/embedded tuple/RELATED，不把 Root ICMP PASS 扩为 VPN transport 支持。

## 6. S225/S234：FlowEnd 与回收

### 6.1 存储与 graph 接线

[代码事实] 普通 packet `opaque2` 已用满 56 bytes，`opaque` 保存 24-byte obligation+
16-byte platform facts。不能在现有 packet struct 尾部直接塞 FlowEnd 指针。

[实施基线] FlowEnd 是独立无 payload buffer，使用独立 typed overlay；它不需要普通
packet 的 addresses/transport/obligation overlay。保留 `generation/flow_index/end_reason/owner`。
`is_flow_end` 使用 pinned VPP 中经核对可用的产品 user flag 或 buffer callback 可安全读取的
独立 discriminant；必须先列出 pinned flag 分配，不擅自占用已有 flag 位。
[代码事实] pinned VPP 已提供 `vlib_buffer_set_alloc_free_callback`，在 `buffer.c` 注册，
`buffer_funcs.h` 的 pool alloc/free 路径调用；回调参数为
`(vlib_main_t*, u8 pool_index, u32* buffers, u32 count)`，返回类型 u32。
优先复用这个现成 seam，不为 S225 重新增加 callback 框架或 core patch。
注册在已有 callback 非空时返回 1：必须检查返回值，不能覆盖另一消费者。启动时统一注册
一次，profile restart 只变 generation/state；不能每次 start 重复注册。
S225 已核对回调实际调用点与 ref_count/chain 路径，FlowEnd 仅允许独占单 buffer；
pool free callback 不是任意 `vlib_buffer_free` 调用都已完成最后引用释放的承诺。
`VLIB_BUFFER_FLAG_USER` 位同时被 VNET 使用，名字带 USER 不等于可以随意占位。
不扩大 buffer、加 opaque3 或引入全局 token table。

[S225 实现事实] native free 在 callback 前重置 64-byte template（含 flags/opaque），
所以采用 callback-safe 的 `opaque2[55]` bit 7，而非 USER flag。packet drop-reason、
fragment flags、completion overlay 保持此位不冲突；alloc 对所有 buffers 清位。
END 独立 56-byte overlay 另含 incarnation，free 验证当前 owner、generation、slot、
incarnation、allocated/unlinked 与 reason；完整审计与证据见
[S225](2026-09-12_S225_FLOW_END.md)。没有增加任何 upstream core patch。

`product_flow_end.c` 管理 allocation/free callbacks 和图入口；`product_flow_entry.c` 管理
unlink/release。common flow consumer 入口供 packet 和 FlowEnd 共用；初始没有消费者时
只做必要 branch/terminal，不搭通用订阅框架。packet-only 节点明确跳过 FlowEnd。
normal FlowEnd 最终 `vlib_buffer_free`，由 free callback 释放 entry；terminal 不另 release。

### 6.2 关闭算法

```text
owner_close(index, reason):
  assert entry is allocated and linked on current owner
  unlink from table; remove timer if attached
  keep entry allocated and immutable for final consumers
  allocate one native buffer, length=0, no AdapterObligation
  if allocation failed: report explicit fatal FlowEnd allocation failure; exit runtime
  set is_flow_end + index + owner + generation + reason
  enqueue to same owner's common flow-consumer entry

buffer_free_callback(buffer):
  if !is_flow_end: return
  validate generation, owner, index, allocated && !linked
  finalize existing attachments exactly once
  release slot; clear discriminant
```

alloc callback 对所有新 buffer 清 discriminant。重复 free、错误 owner/index 不能释放任意 slot。
FlowEnd 禁止 clone/handoff；没有 adapter verdict、TUN write、Flow Stack input、parser、selector。
同 tuple 可新建 entry，但必须使用 free-list 中另一个槽，旧 FlowEnd 引用槽不能提前复用。
管理 stop/clear 只有 graph 全排空后才直接清剩余 entries，不为每个剩余 flow 强制分配 signal。

### 6.3 S234 失败证据

分别采集正常 close、接近耗尽、确定 alloc failure、受监督新 generation 恢复。
失败点必须在实际 buffer allocator，不能仅抛一个测试异常冒充内存耗尽。
fatal 路径允许 OS reclaim，但不能伪称每个 free callback 或 NFQ verdict 都已执行。
验证 hooks/queues/FD 清理、保护状态撤销和新流量恢复；旧排队流量损失单列。
FlowEnd allocation failure 停止 VPP 功能，走现有监督层有界清理与退出，不在 worker 等待
资源恢复。NFQ 撤销本产品捕获规则并清理队列；VPN 撤销本产品 VPN/TUN 接管及路由。
系统联网恢复不得等待 VPP 重启，不能留下死队列或无人读取的 TUN。故障瞬间个别包损失
单列，不承诺零丢包；外部 VPN lockdown 等系统约束不得绕过，也不得误报联网恢复。
后续功能恢复使用新 generation，连续失败限制重启频率并明确报告保护停止。
此 fatal 策略不适用于普通 FlowEntry 满池；普通满池继续 capacity bypass，不驱逐已有流，
不跨 worker 借位，保留 Gate/L4 DROP。不得用“重启成功”替代“故障后及时撤销接管”的证据。
禁止专用 retry/pending/emergency pool，也不能以静态 free 内存估算替代压力证据。

## 7. S226/S227/S236：统一 expiry

### 7.1 数据结构与 Interface

[候选方案；2026-09-11 用户校准] 定时索引可采用每 owner 一个预分配 indexed binary min-heap。
heap 元素为 flow_index，entry 内保存 heap_position/deadline_us/timeout_class。
容量等于该 owner entry capacity，增删/重排 O(log N)，peek O(1)；不用每次续期 push
stale timer 的 lazy heap，不建每协议 heap，不开 timer thread 来修改 flow。
heap 尚未作为最终结构冻结；须对照 timer 职责、实际规模与本产品要求评估。
以下 heap 相关字段与伪代码仅描述候选方案，不要求机械采用或替换它。

```text
refresh(index, timeout_class, now_us):
  class → 同一 pinned OVS 默认 timeout_us
  deadline = checked/saturating(now_us + timeout_us)
  更新原 heap element，deadline 缩短同样 sift

run_due(now_us, budget):
  while processed < budget and min.deadline <= now_us:
    remove min; owner_close(index, EXPIRED)
  report remaining due/backlog and next deadline
```

使用 monotonic 微秒，复用当前 vlib time 单位转换；不混入 wall clock。
lookup 发现 deadline 已过，不能返回旧 entry；按正常 close unlink，再尝试新建。
新建时旧 slot 可能仍被 FlowEnd 占用，满池按 capacity bypass，不能抢用旧 slot。

### 7.2 S226 实验登记必须先完成

两臂仅 wake/驱动不同，选定的 timer 容器/timeout/flow set/FlowEnd/budget 相同：A 常驻 polling input node，
B nearest-deadline 事件通知目标 owner。main/wait helper 只能通知，不访问 mutable timer 状态。
没有新包也必须推进到期处理；大量同时到期分批清理，不以延后调度续期旧流。
每 worker 一次 bounded batch；backlog 由下一次有界调度推进，不持续 self-requeue 忙等。
S226 使用最小实验 driver，S227 才连接生产自动 expiry。

注册文件必须在结果采集前固定：artifact lineage、CPU affinity、充电/温度/屏幕状态、
空表/少量长 deadline/100/1000/可承受上限、每臂重复次数、运行时长、统计方法、
cleanup 延迟端点与容差、idle CPU/wakeup/延迟 GO 门槛。
约 1 秒指 deadline→FlowEnd entry release，不能以唤醒时刻替代。
具体预算数值尚未被当前契约完整选定：禁止本附录编造 release SLO。登记后不得看到结果再修改。
两臂都失败或证据不足时为 HOLD；不得按平均数挑一个“较好”的失败臂进入生产。

S227 验真实 UDP 默认 timeout、续期、缩短、无新包到期、W2/批量、stale generation wake。
S236 仅增加 TCP/ICMP class mapping，复用同一 scheduler；长 timeout 真机 case 单独运行，
不能以缩短配置或 fake clock 替代正式默认 timeout 证明。

## 8. S237：真实 Flow Stack 的窄产品 Interface

### 8.1 依赖来源与构建准入

[代码事实] 实验记录的 HEV lineage 为 `3911f79434d9a27c3ae4e6e07df5cefe2c3d5c70`，
`/tmp/hev-3911f79` 是 patched fixture，不是可当作干净 upstream 的 Git pin。
现有实验 RESULTS 明确限制为 single-owner UDP4、受控目的地址投影，不能直接复制进产品。

S237 先形成产品依赖 manifest：真实 upstream/submodule 完整 revision、许可证、源码 hash、
逐个本地修改的目的/文件/回归。从合法 upstream 构建产品 fork，依据实验结论重新实现必要
owner-context/external-driver/copy/failure 修正；不能导入实验整个 source tree 或直接链接
实验 `.so`。依赖不能从网络浮动 latest 或 `/tmp` 隐式寻找。
vendor 目录位置与 repository 现有 third_party 约定一致；若尚无目录，使用
`third_party/hev/`，保留 source/patch/manifest 的明确布局，不伪造已有 vendored 状态。

### 8.2 对外 Surface

`product_vpn_flow_stack.h` 不暴露 pbuf/PCB/HEV 内部类型。runtime 配置启动时固定。
以下 result 是 handoff 结果，绝不等于 delivery：

```c
enum fs_input_result {
  FS_INPUT_ACCEPTED, FS_INPUT_NO_CAPACITY, FS_INPUT_UNSUPPORTED,
  FS_INPUT_NOT_RUNNING, FS_INPUT_INVALID_GENERATION, FS_INPUT_FAILED
};
fs_input_result input_copy(shard*, const uint8_t* l3, size_t length,
                           const return_facts_by_value*, generation);
step_result step(shard*, const ready_events*, uint64_t now_us, step_budget);
void quiesce(shard*);
drain_result drain_step(shard*, uint64_t now_us, step_budget);
void close(shard*);  /* only after callback/drain barrier */
```

buffer index 不传到 HEV，输入字节指针仅在 call 内借用。`input_copy` 不 connect、等待 protect
或跑无限 task loop。接受后 HEV 只拥有 copy，原 VPP buffer 仍由既有 completion 路径结清。
具体 HEV 调用和 lwIP return mapping 在 Implementation 内，与封装后的 result 一一对应。
`step` 必须有 task/event/work budget；不得把实验的“32 次零进展”直接当生产预算。

### 8.3 packet routing 与 completion

| packet provenance | policy result | terminal destination |
| --- | --- | --- |
| TUN_ORIGIN | DROP | 原 obligation completion/free；不调用 Flow Stack |
| TUN_ORIGIN | 普通通过或合规 processing bypass | canonical owner 的 `input_copy`，随后原 obligation completion |
| FLOW_STACK_RETURN | DROP | 原生 return buffer completion/free；不写 TUN，不再 input_copy |
| FLOW_STACK_RETURN | 通过 | origin TUN lane 唯一一次 write attempt，随后 free |

Flow Stack input 必须在 canonical owner 执行，不能把允许包送回 TUN origin 再统一调用
一个全局 HEV 实例。新增 `product-vpn-egress` 为共享策略后的显式 graph node；只有
TUN_ORIGIN 才能进入。terminal/completion 记录 handoff outcome 但不再次执行 admission。

输出 callback 顺序固定：

```text
callback on canonical owner:
  reject stale/quiescing generation before allocation
  validate pbuf chain total length against chosen product packet envelope
  allocate independent VPP buffer
  copy entire pbuf chain into VPP storage (not a contiguous p->payload guess)
  fill FLOW_STACK_RETURN + INPUT + minimal known/unknown facts
  create normal TUN-return completion identity in existing Adapter lifecycle
  submit to same-owner native frame scheduling
  return submission result; never recursively run graph
later: shared parser → unique assignment → policy → TUN origin completion
```

metadata/pregraph admission 使用现有 graph Interface，并按 S216/214 区分 obligation kind、
provenance、owner；不得为输出增加独立 per-packet map。
原生 frame API 没有 rejection return 时不能伪造一个：所有可失败的检查/分配在 transfer 前完成，
实际 submit 即 ownership transfer；fault injection 标为 pre-accept rejection。
transfer 前失败由 callback 释放新 VPP buffer；之后 callback 不再访问/free 它。
原 pbuf 仍由 lwIP callback 契约释放，VPP 不擅自 free 或异步保存其指针。

S237 初始单 owner 不删除 S214 remote wiring；S239 才宣称 W2 transport 通过。
新输出无 incoming fragment bundle；入 Flow Stack 的重组输入按既有 bundle completion
结清全部 originals，不能只释放 survivor。

### 8.4 身份、网络、broker

session 保存 UID/known 和创建 transport 时的 underlay binding/epoch 必要值。
输入 unknown 时不猜测 UID；已有 reliable identity 不用 Direct socket 自身 UID 覆盖。
2026-09-11 用户确认：旧 UDP transport 尚存活时，同一 tuple 的后续输入若携带与 session
不同的已知 UID，记录身份冲突，立即禁止旧会话继续 forwarding，关闭旧 transport 并拒收
触发冲突的这一个包；后续包在旧会话清理完成后重新建会话并重新 bind/protect。
不得覆盖旧 UID、借用旧 socket 或在清理期间接受该 tuple 的新输入。该关闭不依赖
VPP FlowEntry 的生命周期，不新增 identity manager。unknown 不等同于一个不同的已知 UID。
其他未被契约解决的身份冲突仍先列最小案例审视，禁止静默 last-write-wins。

Android broker 处理 bind/protect，并返回同一 generation/session 请求的结果。
fd 经 SCM_RIGHTS 转交时区分原 fd/duplicate，close 每个拥有的引用一次。
在等待 broker 期间不阻塞 VPP owner，使用真实 HEV 已有 bounded admission/session state；
不保留输入 VPP buffer 等权限结果。失败或旧 generation reply 关闭其 fd，并结清请求资源。
禁止尝试 unprotected socket；bind/protect 完成前不 connect/首发。

### 8.5 必须继承为回归的实验发现

- F246-01：output ERR_MEM/ERR_IF 曾永久禁用 UDP receive，后续包全超时且 wake 空转。
  产品验收必须是同 session 的成功→单包失败→再次成功，不能新建 session 掩盖。
- F247-01：stop 时 drain 曾发送排队输入并在 residue 检查后新建 return frame。
  产品 quiesce 必须禁止新 forwarding，仍排空已接受 output；最后 callback/step 不可产生新输出
  后才检查最终零残留并关闭 TUN。
- 同一 pbuf/VPP 地址可多次合法分配，verifier 按 allocation interval 关联，不能按地址唯一。
- pbuf ceiling 过低可表现为 endpoint 已收到 input 但 app 无 reply；不能把资源结清 PASS
  改写成 delivery PASS。输入 credit 不代表全部 output/protocol pbuf 占用。

## 9. S238–S243：扩展只增加一维

| 任务 | 必做代码变化 | 必做真实验证 | 禁止顺带改变 |
| --- | --- | --- | --- |
| S238 | 同一 Interface 接 IPv6 UDP、地址/长度/return facts | IPv6 underlay/endpoint，UDP4 回归，return DROP | 第二套 owner/hash，loopback 冒充真实 underlay |
| S239 | 每个 owner 独立 shard，event routing 与 TUN origin return | 双 owner 同时双栈，实际 callback TLS，停止一条不影响另一条 | 全局 core lock、spill、迁移 |
| S240 | 真 HEV/lwIP TCP 接同一 copy/provenance Interface | TCP4/6 handshake/data/retransmit/FIN/RST/refusal，UDP 回归 | 自写 TCP bridge，CT tracker 代替 transport |
| S241 | 分类 capacity/bind/protect/connect 结果与 health | 新 flow capacity/current packet credit 分开，故障后恢复 | eviction、未保护 fallback、把 transport 错误写成 policy DROP |
| S243 | underlay invalidation、停止、旧 callback/broker reply 清理 | W2 TCP/UDP 活动时 switch/stop/crash/restart，同 tuple UDP 清理后新建，TUN/FD/pbuf/credits | TCP 字节流透明重连、UDP 旧队列重放或新旧有效会话并存 |

2026-09-12 S240 执行证据见
[`2026-09-12_S240_TCP_DIRECT.md`](2026-09-12_S240_TCP_DIRECT.md)：当前 APK 的双 owner
TCP4/6 handshake、字节流、真实重传、FIN/RST/refusal、return DROP 后同会话恢复与
stop/restart 已独立核验，并运行 UDP4/6 回归。该证据不替代 S241/S243/S248 的范围，
debug validation 仍不宣称 release protection readiness。

2026-09-12 S241 执行证据见
[`2026-09-12_S241_CAPACITY_AND_FAILURES.md`](2026-09-12_S241_CAPACITY_AND_FAILURES.md)：
当前 APK 的 W2 TCP/UDP 双栈 44 组真实 capacity/transport/DROP-completion 场景已独立核验，
保留既有 transport、未求值 bypass 不伪造 ALLOW、压力解除后新流恢复，全部 native 责任结清；
正常 TCP 全矩阵与 1,000 包双栈 UDP 回归通过。不替代 S243 lifecycle 或 S248 性能验收。

2026-09-12 S243 部分生命周期证据见
[`2026-09-12_S243_LIFECYCLE_CHECKPOINT.md`](2026-09-12_S243_LIFECYCLE_CHECKPOINT.md)：
当前 APK 的 W2 活动 TCP/UDP 双栈 Stop、两个 owner 的 broker channel failure、真实进程
crash、一次重启上限、取消重试与 VPN 撤销后的普通连通已核验。2026-09-12 已确认 UDP
旧 transport 清理后，同 tuple 的后续新包可经最新 underlay 新建 protected/bound socket；
不重放、不迁移，不联动结束 VPP FlowEntry，见 ADR-0007。当时的生命周期证据不含该切网
链路的实施/验收，**不能据此将 S243 标为完成**。

2026-09-12 S243 后续完整证据见
[`2026-09-12_S243_UNDERLAY.md`](2026-09-12_S243_UNDERLAY.md)：同一最终 artifact L
已验证真实 Wi-Fi Network 失效/新建、W2 双栈同应用 UDP socket 继续使用、新旧 transport
替换而 VPP FlowEntry incarnation 保持、无 underlay 明确失败、切网后 DROP/解除 DROP，
并重新通过活动 stop/crash/两 owner broker failure、一次重启上限/取消、VPN 撤销后的普通
连通及 12 组 protect/bind/DROP 回归。全部 native 资源责任核验完成；无 SIM，不声明
移动数据或公网 IPv6 实测。S243 的上述验收范围已闭合，不扩大对外 readiness。

生命周期固定为 RUNNING → QUIESCING → DRAINING → CLOSED；STARTING 失败也必须走已拥有
资源的清理。不要新建第二套全局 supervisor 状态机，映射到现有 RuntimeService 状态。
一次有界重启失败后撤销 unusable VPN 并报告停止；lockdown 是否允许普通联网由 Android 决定。
generation 校验失败仅拒绝对新状态操作，不免除旧事件自带 fd/buffer 的释放责任。

## 10. S233/S242：Root 资源与生命周期

S233 修改 Root Adapter receive/config 与现有规则安装者；三类入口要分开记录：

1. `--queue-bypass`：无监听的新匹配流量由 kernel bypass，不是用户态 verdict。
2. `NFQA_CFG_F_FAIL_OPEN`：已监听但 kernel queue 满，与无监听是不同 flag/场景。
3. userspace ingress pool/reserve 不足：已有 completion identity 时走既有 normal return，
   reserve 用完明确 loss，不能补写伪造 ACCEPT。

normal/reserve 都从既有 VPP pool 启动时固定划分到 lane，lane 独占；不运行时扩大、跨 lane 借用。
NFQ 包进入用户态前身份未知时，不能在临时 heap 接收再声称 single materialization。
实际 buffer/recv 形态沿当前 Adapter 核对，必要改动保持每 packet 一次用户态物化。

2026-09-12 S233 已由同一源码 artifact B 闭合，见
[`2026-09-12_S233_NFQUEUE_FAIL_OPEN.md`](2026-09-12_S233_NFQUEUE_FAIL_OPEN.md)。
每 lane 固定 64 normal + 8 reserve VPP buffer；双平台分别通过三种独立放行来源、
两种明确 loss、新流 policy 恢复和 queue/socket/hook/loan 清理核验。Linux/Pixel 主矩阵
94/76 个端点用例、各 14 个反向篡改检查，以及 120/114 个 native NFQ 分片回归包通过。
Pixel 普通 RuntimeService 四次安装的全部 16 条规则均核对含 `--queue-bypass`。
该证据不替代 S242 的完整生命周期范围，也不扩大 readiness 或声称零丢包。

S242 按四条 lane 记录 generation、fd、queue family/ID、pending、completion ledger；
部分 lane 打开失败要逆序撤销已经建立的本 runtime 资源，不清除系统其他规则。
stop 先撤 ingress/停止接收，保持 verdict channel 直到 bounded drain，再解绑/关 fd/移除私有 hook。
真实 syscall 非负只表示 terminal operation 成功，不等于 endpoint 收到；失败不再物理重试。
S210 的 return-ring retry 仍可使用，不新增 verdict retry。

2026-09-12 S242 当前产物验收完成：typed Root stop 从 RuntimeService/JNI 经
Rust/C/VAPI 到 VPP barrier 内的非阻塞 step；先 quiesce ingress，保留 completion
fd 排空，再释放 graph/flow/pool 与四条 lane。Linux/Pixel 各五阶段主矩阵、各
25 个语义反例，以及 Pixel 四代真实 supervisor/15 个反例通过；每 lane 的故障是
同一真实 fd 上 `sendto(MSG_OOB)=-1/EOPNOTSUPP`，没有物理 retry 或合成 unknown。
正常 native zero 与异常 OS reclaim 分列；内核延后回收旧 TCP 包的等待不计作
Product 成功 verdict，也不放宽 2 秒 native drain 预算。当前同源 S233/S231
回归通过；不扩大 readiness。完整 source/artifact/原始证据与保留失败见
[`2026-09-12_S242_ROOT_LIFECYCLE.md`](2026-09-12_S242_ROOT_LIFECYCLE.md)。

验证表包含：无监听、queue-full、normal pool 耗尽、reserve 耗尽、无 mandatory identity、
partial lane start failure、持续 local/remote 双栈 stop、definite verdict failure、
stale/duplicate completion、新 generation 恢复。fragment stop 单独归 S229，再参加联合回归。

## 11. S220/S235：启动配置与 Linux 网络事实

### S220 有序 CPU mapping

配置表达 `workerCpuIds[logical_worker] = Linux CPU ID`；不要变为 set 或排序后的 bitmap。
启动时检查数量=W、重复、online/allowed affinity、main-core 冲突；任何错误拒绝启动，
不能选择附近 CPU。生成 corelist 只解决 VPP 可用 CPU 集合，不证明顺序。
在实际 worker startup 接线明确绑定 logical worker 对应 CPU，并同时读取 VPP threads 与
OS affinity 验证。配置只在 clean restart 生效；CPU 不进入 canonical key。
验证正序、反序、非连续、重复/离线/不允许/数量错误，Pixel/Linux 分别使用本机可用 CPU。

### S235 Linux snapshots

[代码事实] 当前 snapshot 为最多 32 个 `(linux_ifindex, context)`，revision/event time，
280-byte ABI；context 当前编码 Wi-Fi=1、Mobile=2、VPN=4、Wired=8，unknown 为 map 中缺席。
`product_network_snapshot_publish` 在 main worker barrier 下发布整个 map，packet 只读。
延续该 Interface，不改为每包 RPC、不创建第二 snapshot。

平台采集在 packet path 外：link/address 变化负责触发刷新，可靠网络管理/设备元数据提供
类别。只凭 ARPHRD_ETHER 不能区分 Wi-Fi/有线，只凭 TUN/veth 不能证明 VPN。
允许用本机已有 NetworkManager/其他可信平台来源的窄 Adapter；无可靠来源保持 unknown，
不强制安装大型网络管理器或自建 metadata daemon。
接口删除应从 map 移除；ifindex 复用必须用新事件重新认证分类。超过 32 时不能截断后声称
全覆盖，报告明确 overflow/unknown，保留不依赖该事实的策略。
INPUT 按 INDEV、OUTPUT 按 OUTDEV 查 map；默认网络切换不覆盖其他接口实际类别。
真实类别缺硬件时单列未验证，controlled publish 只证明 matcher，不证明平台采集。

## 12. ABI、构建与测试集成规则

内部新 Module 不默认扩大 Product Core FFI、VAPI status 和 Java 全量 snapshot。
需要跨语言配置/状态时，必须同时更新 C layout、Rust repr(C)、generated VAPI、JNI/Java projection
及 size/version 校验；不能只改 C 结构后用旧 helper/旧 cdylib。优先保留窄 CLI 验收观测，
只有用户状态/控制需要才提升到产品公开契约。

所有新增 `.c` 纳入 `src/product/vpp/CMakeLists.txt` 的真实 SOURCES；Android plugin 仍是 C，
不能通过 C++ wrapper 解决依赖。Host evidence 继续独立，不能复用 fake implementation 验收。
新增 third_party/patch/build inputs 时扩展 `tests/evidence/product_chain.py` 的 source closure：
当前集合不自动包含 third_party，漏掉 HEV source 会使 S237 的同源声明无效。
同时记录 helper/verifier/compiler/加载库 hash 和部署后 native readback。

每切片按以下顺序验证，避免重复泛跑：

1. 新/改 Interface 的有意义边界 vectors；纯文案变化不增加测试。
2. 实际 C build + 适用 Rust/Java contract；metadata 有变化必须 size/offset/pack-unpack。
3. 新 artifact witness；真实 device 正例与所要求的 failure/recovery。
4. 对应语义 verifier 正例、反例；确认缺记录即失败。
5. 受影响已完成路径回归，source/artifact/runner/clean stop 统一索引。

每个新切片使用 `tests/device/sNNN-...py`、`verify-sNNN-...py`、
`tests/evidence/test_sNNN_..._negatives.py` 的现有风格；不要增加另一个测试框架。
公共 collector/helper 只有两个实际调用者共用相同语义才提取；禁止以通用 harness 吞并所有
不同来源测试，导致 GRAPH_INJECTED 和真实 NFQ/TUN 被归成一个 PASS。

## 13. 交付物与停止条件

每个任务交付四项：

- 实际修改文件/符号与本规格条目的映射，含任何最小偏离理由。
- source/artifact/helper/device 身份、原始 evidence index、成功与保留失败。
- 验收条件逐条对应 case/verifier assertion；明确未覆盖范围。
- 正常 stop 与异常回收区别、剩余现场、下一项已满足的前置。

完成定义必须同时满足行为、ownership、恢复、证据；不能以代码合入、编译成功或单元测试
通过代替设备要求。本规格的代码骨架、结构体字段和算法选择也不构成验收证据。

执行者不得擅自填写以下尚未证明的值：OVS 正式 pin/timeout 秒数、HEV 产品 patch closure、
release entry/pbuf/credit 容量、S226 wake winner/完整门槛、目标设备不存在的真实网络类别。
这些是明确列出的证据槽位，按对应任务规定的方法关闭；除此之外不重新讨论已固定设计。

## 14. 现有文字冲突清单：实施时明确消除

本轮仅修改交接文件，不偷偷重写领域权威。接手者在对应 Plane 切片内同步相关段落，
保留历史标签而不是删除所有旧证据。

| 当前位置 | 冲突/过时内容 | 当前执行口径 |
| --- | --- | --- |
| `CONTEXT.md` 的 Fragment Steering | capacity 一律 runtime-drop、禁止 fail-open fragment bypass | S229 区分协议故障与纯资源不足，有安全出口时 processing fail-open |
| `docs/decisions/L4_CONNTRACK_WORKING_DECISIONS.md` | C++、全局 A++/QSBR、other tracker、后台 sweep 等旧前提 | S221–236 的 owner-local C、TCP/UDP/ICMP Echo、统一 scheduler；旧段落标历史 |
| `product_flow_entry.h` 顶部与 observe contract | TCP/UDP-only、固定线性 pool 的阶段说明 | S221 扩可靠 ICMP_QUERY 与统一 fixed-capacity table，但不提前声称 tracker |
| `product_packet_graph_flow_observe` | capacity → runtime drop | S221 processing bypass；保持已确定 policy DROP |
| `product_vpn_tun_adapter.c::tun_status` | `tun_writes=0 flow_stack_admissions=0 direct_egress_ready=0` 固定字符串 | S237+ 改为实际计数与按范围发布 capability；不能只改 readiness 字符串 |
| S219 capacity runner help/comment | 称恢复到 DROP，但 verifier 期待正常 allow+transport unavailable | 按真实行为统一文案，普通 DROP 矩阵单独保留 |

处理优先级：用户当前指示 → accepted ADR/当前任务正文 → 本规格实施基线 → 旧描述/旧测试。
旧测试依赖被明确替换的语义时更新测试；不是让实现同时维护两个相反契约。

## 15. 可执行验收卡的最小字段和场景编号

每张验收卡使用下列固定字段；JSON 是格式示意，不能把占位值当实际结果：

```json
{
  "task": "SAKAMOTO-NNN",
  "case_id": "NNN-scenario-platform-family-owner",
  "source_kind": "NFQ_CAPTURED|TUN_CAPTURED|GRAPH_INJECTED",
  "build_witness": "relative/path/build.json",
  "artifact_sha256": "actual digest",
  "runner_sha256": "actual digest",
  "helper_sha256": {},
  "generation": 0,
  "expected": {},
  "observed": {},
  "raw_files": [],
  "verification": "PASS|HOLD",
  "non_claims": []
}
```

generation=0 只是占位，实际验收必须真实非零；source_kind 必须选择一个实际值。
脚本在开始采集前写 expected，结束后写 observed，不从 observed 自动生成 expected。
场景命名固定，允许扩充 case，不允许删除失败 case 后重新命名套件：

| 任务 | 最小场景族 |
| --- | --- |
| S229 | timeout、malformed、conflict、duplicate、context-capacity、bundle-capacity、ingress-reject、prepared-sendout-reject、retained-drop-return、stop-held、restart |
| S221 | create、same-key-reuse、reverse-reuse、typed-key-distinct、hash-collision、full-existing-hit、full-new-bypass、revision-invalidate、owner-isolation、clear |
| S223 | first、same-side-multiple、reverse-bidir、reply-looking-first、policy-revision、stop |
| S222 | syn、syn-retransmit、handshake、established-data、midstream、window-scale、seq-wrap、invalid-window、fin、rst、tuple-reuse |
| S224 | request-first、reply-first、multi-sequence、new-identifier、reverse-owner、stop |
| S225 | normal-end、early-buffer-free、same-tuple-new-slot、stale-signal、clear-after-drain、packet-buffer-reuse |
| S226/S227/S236 | empty-idle、long-deadline、renew、shorten、expired-lookup、no-new-packet、batch-expiry、mixed-protocol、stale-wake、screen-off |
| S237 | real-echo、input-reject、output-alloc-fail、pre-accept-reject、return-drop、tun-write-fail、chain-copy、sync-output、same-session-recovery、overlap-stop |
| S238/S239/S240 | ipv6-real-echo、dual-owner-simultaneous、cross-lane-return、independent-session-close、tcp-lifecycle、udp-regression |
| S241/S243 | flow-capacity、packet-credit、pbuf-capacity、bind-fail、protect-fail、connect-refusal、underlay-invalid、active-stop、crash、stale-broker-reply、restart |
| S233/S242 | no-listener、kernel-full、normal-pool-full、reserve-full、missing-identity、partial-start、verdict-fail、duplicate-completion、stale-completion、active-stop |
| S220 | forward-cpus、reversed-cpus、noncontiguous、duplicate、offline、not-allowed、main-conflict、wrong-count |
| S235 | each-real-network-class、two-interfaces、default-switch、interface-delete、ifindex-reuse、unclassified-virtual、snapshot-overflow、stop |

测试中的 controlled fault 必须记录注入点、作用对象/次数和解除时刻，不把它说成自然发生。
每个阶段资源守恒独立记账，不能把下列不同资源相加后用一个总数抵消：

```text
FlowRuntime: free_slots + linked_entries + end_inflight_entries = capacity
VPP allocation interval: allocations - physical_frees = live_buffers
Adapter: admitted_obligations - terminal_settlements = outstanding_obligations
Completion: created_carriers - consumed_carriers = live_carriers
Flow Stack: input_pbuf_live、output/protocol_pbuf_live、sessions、socket_fd_refs 分别守恒
Credits: acquired - returned = held，始终 0 <= held <= fixed_limit
```

正常终止各 outstanding/live 归零；pool 自身预分配存储仍存在与 entry 活跃不同。
quiesce 期间 admission 停止不意味着 completion/return 已关闭。
runtime 崩溃用 OS reclaim 证据单列，不能用该公式把缺失日志补成逐对象成功释放。
