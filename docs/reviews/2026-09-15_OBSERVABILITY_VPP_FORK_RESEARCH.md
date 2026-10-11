# VPP fork 可观测性调查：统计口径、规则执行证据与导出边界

日期：2026-09-15。状态：源码调查完成；未构建、未启动 fork、未执行其测试或连接 Kafka/MAAT 服务。本文是需求讨论的证据输入，不是当前产品的实施方案。

## 1. 调查对象与证据边界

调查工作树为 `/home/js/backup/backup/Git/vpp`，固定版本为 `837432be3b6cf496755cfa27b7cca439734eb726`；提交时间 `2026-04-07 15:49:22 +0800`，标题 `nat: Fix the issue where SNAT adding the bind-table causes a segmentation fault.`。

调查开始时工作树有 `build/external/` 文件删除、`test/Makefile` 修改和 `test/` 下未跟踪目录。开始与收尾检查未发现 `src/` 本地修改，因此以下源码定位针对该提交的受版本控制 `src/`。未使用未跟踪 `test/src/` 作为证据。fork 内未发现适用的 `AGENTS.md`。本轮只读 fork，没有复制产品代码。

本文的证据等级：

- **已见源码链路**：实际读取生产者、处理与消费代码，能说明“代码在何处写了什么”。
- **有配置/测试源码**：能说明入口或断言存在；不能说明当前部署启用或测试通过。
- **未验证**：运行负载、部署配置、外部服务、留存和 UI；不能从函数名或配置样例推导上线能力。
- **推断**：明确标注，对需求的启发不等于现有实现承诺。

文中 `src/...` 均相对于上述 fork；本地文件链接便于当前工作区查看，重定位以提交、相对路径、函数名为准。复查命令示例：

```sh
rtk git -C /home/js/backup/backup/Git/vpp rev-parse HEAD
rtk git -C /home/js/backup/backup/Git/vpp status --short
rtk git -C /home/js/backup/backup/Git/vpp diff --name-only -- src
rtk git -C /home/js/backup/backup/Git/vpp show 837432be3b6cf496755cfa27b7cca439734eb726:src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c
rtk proxy rg -n 'policy_sketch_update_rule_hits|STAT_RAW_PACKETS_RECEIVED' /home/js/backup/backup/Git/vpp/src/plugins
```

## 2. 最重要的发现

这个 fork 的可观测性由多条不同用途的链路组成：VPP 框架计数、Session Manager 状态、规则/对象聚合、会话/事务导出、主动逐包诊断。它们的计量点、时机、单位与丢失条件不同。**“有统计”不能等同于“能完整解释一次规则执行”。** 下列各节给出对应源码链路。

尤其不能把 `policy_sketch.hit_count` 当作逐包命中次数，或把规则聚合的字节数当作该规则实际丢弃的字节数：前者在同一 session context 内按 UUID 首次登记加一；后者取 Session Manager 的累计收包差值，并分配给 context 中所有已登记的规则。这与 ACL 的每包命中计数、security enforcer 的实际子动作计数是三种口径。[规则聚合生产者](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:262)、[差值分配](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:364)、[ACL 生产者](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:122)、[执行分支](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:2017)

另一条明显边界是：会话导出和 policy sketch 均依赖 `session`；主动 telemetry 从 Ethernet 输入处筛选包，不要求先产生 session。它可以提供另一种诊断证据，但它是按任务、采样与容量约束收集的逐包记录，不能直接替代“所有阻止尝试”的常驻活动账本。[policy sketch 入口](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_sketch_plugin.c:927)、[会话导出入口](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter.c:816)、[Ethernet telemetry 入口](/home/js/backup/backup/Git/vpp/src/vnet/ethernet/node.c:1219)、[筛选逻辑](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:197)

## 3. 能力地图与不能混用的口径

| 链路 | 生产/计量点 | 单位及关联 | 读取/导出 | 能回答及限制 |
|---|---|---|---|---|
| VPP 接口统计 | 输入驱动、interface-output 等节点 | 接口、线程，包/字节；另有 error/drop 简单计数 | stats segment、接口 CLI | 数据面接口活动；不代表远端收到，也不自动带应用或规则归因 |
| Session Manager | `session_update()`、状态迁移、超时/容量路径 | session、C2S/S2C、协议、worker；状态数量、RAW 包/字节、重组和卸载计数 | 每秒复制到 stats segment；专用 CLI | 跟踪器看到什么、资源是否饱和、当前会话详情；不覆盖未建 session 的流量 |
| Stellar ACL | 搜索到 rule 后的 action 分支 | rule ID、worker；每包加 1、链长字节 | `/extra/acl/<id>/hit`、规则 CLI | 该 ACL 规则被选中的包数；与 session rule hits 不同 |
| Policy rule hits | enforcer 登记规则；periodic/pseudo 刷新 | measurement、rule UUID、action；首次登记次数、session RAW 差值；目的 IP/FQDN HLL | fieldstat → Kafka/CSV，部分 CLI 可输出 | 哪些规则曾关联会话以及对应流量聚合；不是逐包赢家，也不是严格执行账本 |
| Policy object statistics | MAAT 的 hit objects 回调 | field/object UUID/item UUID 等对象维度 | fieldstat → Kafka/CSV | 条件对象被命中情况；不等于整条规则最终获胜 |
| Statistics enforcer | 规则选择的统计 chart，周期与 session 结束时更新 | 配置维度、counter/HLL/t-digest | fieldstat → Kafka/CSV | 规则配置的流量聚合；准确范围取决于 chart、字段来源、sampling 与外部库 |
| Stellar exporter | session 结束伪包或事务释放 | session/transaction record，时间、双向流量、解码字段与规则字段 | ringbuf → Kafka JSON；session 可发 IPFIX | 有条件的生命周期记录；最小包数、导出选项、队列失败会影响覆盖 |
| Telemetry | 主动任务筛选包，各节点追加说明，buffer 释放时送出 | job UUID、抓包与时间序列 module/comment | ringbuf → PCAPNG 或 Kafka MessagePack | 具体包经过哪些路径、某处为什么 drop；有采样、包数、内存、文件等界限 |

该表的具体链路证据见以下各节；没有将目录里的每个 `metrics`/`test` 文件都记作已验证功能。

## 4. VPP 原生统计与诊断设施

### 4.1 per-worker 计数不是天然的一致事务快照

`vlib_increment_combined_counter()` 写 `cm->counters[thread_index][index]` 的 packets/bytes；`vlib_get_combined_counter()` 遍历所有线程求和。源码注释明确说明，可能递增计数的 worker 未被屏障暂停时，结果不保证精确。stats client 的 `stat_segment_dump_r()` 检查 epoch、执行访问开始/结束校验，结构变化时丢弃本次读取。这能处理共享统计目录的并发变化，不能据此声称来自不同计量点的所有计数是在同一时刻采样。[counter.h:249、277](/home/js/backup/backup/Git/vpp/src/vlib/counter.h:249)、[stat_client.c:401](/home/js/backup/backup/Git/vpp/src/vpp-api/client/stat_client.c:401)

接口名称定义包含 RX/TX 的 unicast/multicast/broadcast 组合计数和多种简单错误计数；初始化为每个接口分配，并注册 stat segment 名称。AF_PACKET 输入节点在接收后批量累计 RX；interface-output 在向 TX/后续 feature 节点排队时累计 TX。因此此处 TX 表示进入该输出处理路径的包数，不是端到端投递确认；不同驱动、L2/L3、封装、分片时的字节含义还要追对应生产点，不能概括成“网络实际传输字节”。[interface.h:966](/home/js/backup/backup/Git/vpp/src/vnet/interface.h:966)、[interface.c:578、1437](/home/js/backup/backup/Git/vpp/src/vnet/interface.c:578)、[AF_PACKET RX](/home/js/backup/backup/Git/vpp/src/plugins/af_packet/node.c:549)、[interface-output TX](/home/js/backup/backup/Git/vpp/src/vnet/interface_output.c:640)

上游官方文档同样将接口/error 计数、节点性能统计和系统统计区分，并说明共享内存读取方式；本文关于 fork 的结论仍以其固定版本源码为准。[FD.io Statistics](https://docs.fd.io/vpp/19.08/stats_doc.html)

### 4.2 CLI、trace、elog 各自回答不同问题

fork 保留 `show runtime`、`show errors`、`trace add`/`show trace`、`event-logger save`/`show event-logger`。这些是运行性能、节点错误、选定包路径和事件环的读取入口，不能仅因存在就推出有常驻历史查询或规则级解释服务。[node_cli.c:653](/home/js/backup/backup/Git/vpp/src/vlib/node_cli.c:653)、[error.c:366](/home/js/backup/backup/Git/vpp/src/vlib/error.c:366)、[trace.c:357、469](/home/js/backup/backup/Git/vpp/src/vlib/trace.c:357)、[main.c:689、810](/home/js/backup/backup/Git/vpp/src/vlib/main.c:689)

上游官方将 elog 定位为共享、线程安全的事件环，适合稀有事件，并提醒高强度数据面不宜逐包使用。fork 的若干插件确实额外提供 datapath elog 开关，因而“能够打开”与“适合常驻开启”必须分开评价；本轮没有测量开销。[FD.io Event-logger](https://docs.fd.io/vpp/25.06/developer/corefeatures/eventviewer.html)、[security datapath elog](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:264)

## 5. Session Manager：状态、计量与结束信号

### 5.1 状态统计已经比流量包数更丰富

`session_manager_runtime.h` 的 `session_manager_stat`/`SESS_MGR_STAT_MAP` 包含 TCP/UDP/ICMP 状态、表容量、CPS 绕过、eviction、过期、重复包、session hit/miss、软硬卸载、TCP 重组，以及 feature arc 版本变化等类别。runtime 更新自身的 `rte->stat`；worker 的周期路径约每秒调用 `vlib_set_simple_counter()` 复制到 `/static/stellar-session-manager/simple/<name>`。因此 stats segment 中这些数值有独立刷新周期。[runtime.h:40–355](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_runtime.h:40)、[runtime.c:1887](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_runtime.c:1887)、[注册名称](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager.c:695)、[每秒复制](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_node.c:730)

`session_manager_observability.c` 实际读取这些值，提供 config、health、memory、stats（含 worker 筛选）、duration、session detail、session list。详情按 UUID 读取会话，展示方向统计及软硬 offload 状态；列表可筛选后展示。历史 duration 是结束会话的分桶计数；runtime duration 是扫描仍活跃会话形成的分布，二者不等于保存了每条历史会话。[health](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_observability.c:125)、[stats](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_observability.c:514)、[duration](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_observability.c:672)、[detail](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_observability.c:867)、[list](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_observability.c:1408)、[duration 生产者](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_runtime.c:1920)

### 5.2 RAW 的真实口径是 session_update 看见的 buffer

`session_update()` 每次调用给对应方向 `STAT_RAW_PACKETS_RECEIVED += 1`、`STAT_RAW_BYTES_RECEIVED += pkt->current_length`。对 IP 重组包还单独累加 `STAT_FRAG_PACKETS_RECEIVED`/`STAT_FRAG_BYTES_RECEIVED`。这说明 RAW 不是直接照搬网卡所有原始分片的计数；RAW 与 FRAG 也不能无条件相加。TCP segment/payload 的接收、缓存、乱序、重传、释放另有指标，不能加进流量总包数。[session_update](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_runtime.c:479)、[TCP 重组分支](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_runtime.c:237)

### 5.3 结束通知与真实流量分开，但结束路径也有失败边界

会话超时路径调用 `session_manager_notify_sess_closed_by_pseudo_pkt()`，将已保留的首包用于伪包通知，设置 `is_pseudo_packet=1`，送入 session feature arc。arc 版本检查失败时，它会直接释放伪包并累计 `PSEUDO_PKT_DROPPED_ARC_VERSION_CHANGED`。因此不能从“插件有 pseudo flush 分支”推导“所有 session 都一定发出最后一条完整记录”。[构造及失败路径](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_node.c:296)、[超时调用](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_node.c:709)

已查明的消费端：policy sketch 在 pseudo 时刷新 session RAW 差值；statistics 的包长直方图明确排除 pseudo；LPI 排除 pseudo；exporter 的普通包入口排除 pseudo，结束入口专门产生生命周期记录。这些路径避免把这类结束通知直接当作新网络包计入各自统计。本轮没有完成所有重入、重组、镜像、repair、硬卸载路径的全图去重证明，故不声称所有节点的“packet”都共享唯一包身份。[policy flush](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_sketch_plugin.c:948)、[hist 排除 pseudo](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_enforcer.c:237)、[LPI 排除](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:574)、[exporter](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter.c:816)

还需特别注意通用 drop 计数：session 结束伪包的末端路径设置 `SESSION_MANAGER_DROP_ERROR_PSEUDO_PACKET_DROPPED` 并送入 drop。因此“drop 节点处理了一个 buffer”可以只是内部结束通知的正常回收，不能直接解释为“又阻止了一次网络访问”。这也是必须区分错误原因和 buffer 来源的直接证据。[pseudo 末端处理](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/session_manager_node.c:642)

## 6. 规则执行可观测性：至少四个不同层次

### 6.1 ACL：逐包选中的规则和动作

`acl_node_fn()` 搜索到一个规则后选择 permit/drop/bypass，drop 设置 next 和 `ACL_ERROR_DROP`，随后无论哪种命中动作都按 1 包与 `vlib_buffer_length_in_chain()` 的结果计数。其局部变量 `n_bytes` 是 `u16`，因此不能忽略实现类型而承诺任意长链的精确字节统计。计数通过 per-worker combined counter 发布到 `/extra/acl/<rule-id>/hit`，CLI 的 formatter 使用 getter 求和展示。[node.c:122–179](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/node.c:122)、[counter.h:14](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/counter.h:14)、[counter.c:4、55](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/counter.c:4)、[format.c:181](/home/js/backup/backup/Git/vpp/src/plugins/stellar_acl/format.c:181)

这里的命中统计反映该 ACL 节点的判定。它没有借助 session 才计数，是 fork 中“前置处理仍可有规则统计”的直接证据；这并不意味着 fork 已实现当前产品所需的无 Flow 活动记录。

### 6.2 Policy sketch：规则曾关联过会话

完整链路为：

```text
security / mark / monitor / threshold / statistics enforcer
  → policy_sketch_update_rule_hits()
  → 获取或创建 session 的 rule_hits_context
  → 按 rule UUID 去重登记，首次 hit_count +1
  → 周期或 pseudo：取双向 session RAW 累计值的差值
  → 给 context 内已登记规则分别累加该差值
  → fieldstat 按 name / rule_uuid / action 聚合
  → 后台周期 export-and-reset → Kafka JSON 或 CSV 文件
```

调用方枚举可用 `rg -n policy_sketch_update_rule_hits src/plugins` 复查；核心链路在 [登记入口](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_sketch_plugin.c:984)、[去重及首次加一](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:262)、[差值循环](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:364)、[后台导出](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_sketch_plugin.c:586)。

该口径的具体后果：

- `hit_count` 不是“评估次数”，也不是每包命中次数；同一 context 已有 UUID 时不再次登记。
- 规则间流量不可求和得到唯一总流量：一个 context 内多个规则都可能得到同一段 RAW 差值。
- 规则开始/结束生效的精确包边界未保存在该聚合结构中。新增规则是否覆盖部分先前流量，取决于登记与上次刷新时间；此结构不是逐包决策时间线。
- action 是登记方提供的字符串，可为空；去重键只用 UUID。它不天然带规则版本、配置发布序列或执行阶段。
- `ip_unique_count`/`fqdn_unique_count` 使用 HLL 注册与添加接口（precision=12）；它们不能作为精确明细枚举。目的 FQDN 从 session 的 exporter itable 读取，而非此模块重新判定来源。

这些限制直接来自 [schema、counter 与 HLL 注册](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:10)、[UUID hash key](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:262)、[action 维度](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:285)、[HLL 数据来源](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:325)。

### 6.3 Security enforcer：选中规则、执行动作与实际包处理分开

`security_enforcer_on_vlib_buffer()` 在 MAAT epoch 变化时调用 `highest_priority_rule_get()`，选出规则并向 policy sketch 登记；随后才进入 allow/deny 的执行分支。allow 有 session 首次执行标志；drop 快路径设置 buffer 的 DROP tag 并递增实际 drop 子动作包计数，必要时另外执行 reset。metrics 模块分别注册 allow/deny/continue 会话计数，以及 drop/tamper/rate_limit/block/respond 子动作的会话与包计数。[选择及执行](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:2017)、[metrics](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer_metrics.c:74)

`security_enforcer_add_datapath_telemetry()` 同时写 rule UUID、action 字符串和当前 DROP tag 是否置位，因此在已采集的具体包上，可区分“关联规则动作”和“此处该包被标为 drop”。结束伪包阶段，满足 log option 的规则/动作会写入 session itable 并请求 exporter 的 events 模式。两条链路的采集条件不同。[逐包说明](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:264)、[结束写 record](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:1987)

**没有确认 fork 与当前产品 `observe` 含义相同。** 此处 security 有 allow 的 continue-scanning 标记，其他 enforcer 有各自 action；不能把名字相近的继续扫描、统计、监控都映射为当前规则引擎的 observe。`highest_priority_rule_get()` 实际拿 `maat_state_compile()` 返回的第一个有效规则；返回顺序正确性依赖 MAAT，调用端自身并没有实现当前产品的完整 Rank 排序。[continue 条件](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:142)、[选取函数](/home/js/backup/backup/Git/vpp/src/plugins/stellar_security_enforcer/stellar_security_enforcer.c:1953)

### 6.4 条件对象统计与通用流量统计是另一套需求

Policy object statistics 调用 `maat_state_iterate_hit_objects()`，以字段、object/item UUID 等信息登记对象，再用 session 统计更新它们。对象命中能辅助解释条件覆盖，但不会证明整条规则最终获胜。[对象回调入口](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_object_statistics.c:232)、[MAAT 遍历](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_object_statistics.c:325)、[对象维度/统计](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_object_statistics.c:375)

Statistics enforcer 则根据命中规则配置 chart/cube，注册 counter、HLL、t-digest，并调用 `fieldstat_set_cube_sampling()`；周期和 pseudo 更新统计。字段来源包括 session metadata、双向 RAW、exporter itable、TCP latency；包长直方图的输入是 `b0->current_length`，即使局部变量叫 payload_len，也不应把它写成 TLS/应用有效载荷长度。统计字段“session closed”和“duration”仅在 pseudo 阶段成立。[chart 注册](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_rule.c:422)、[更新触发](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_node.c:73)、[包长](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_enforcer.c:237)、[字段来源](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_field.c:528)

## 7. LPI、TLS/QUIC SNI 可看到什么

LPI 在 session context 中维护 seen packet 数、实际检测 packet 数、识别出的 app IDs、首次识别所在的检测包序号、protocol tags 和 stop_detect；只处理有 L4 payload 的真实包。packet trace 展示 seen/detected/l7 tags/app ID 等信息；debug 开启时，session exdata 释放阶段输出识别结果与会话方向到 elog。这里 app ID 指流量协议/业务识别，不是 Android UID/package。[检测及状态](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:574)、[packet trace](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:510)、[结束 elog](/home/js/backup/backup/Git/vpp/src/plugins/stellar_lpi/stellar_lpi_plugin.c:364)

TLS decoder 的 debug JSON 明确包含 `tls_sni`、JA3/JA4、ESNI/ECH 标记、malformed ClientHello 标记；decoder 在启用 event logger 后把该 JSON 写入 elog。开关默认 false。能确认这些诊断字段存在，不能据此保证所有 SNI 缺失都有完整且互斥的产品级原因。[debug 字段](/home/js/backup/backup/Git/vpp/src/plugins/stellar_tls_decoder/stellar_tls_decoder_debug.c:255)、[elog 消费](/home/js/backup/backup/Git/vpp/src/plugins/stellar_tls_decoder/stellar_tls_decoder.c:288)、[启用条件](/home/js/backup/backup/Git/vpp/src/plugins/stellar_tls_decoder/stellar_tls_decoder.c:821)、[默认关闭](/home/js/backup/backup/Git/vpp/src/plugins/stellar_tls_decoder/stellar_tls_decoder_node.c:458)

正常记录也有可跟踪的路径：scanner 将 ClientHello 的 SNI、no-SNI、ECH 等加入 field scratch；`scanner_scan_fields()` 依据 schema 的 log_name/itable_index 写入 exporter itable，TLS SNI 的日志名为 `tls_sni`。scanner 的 TLS 与 QUIC 域名提取路径还可把 SNI 选作 `destination_fqdn`；之后 exporter 在结束时导出 session record。这个最终 FQDN 字段融合了上游选择，不等于“来源、等待状态、失败原因、匹配规则”全部保留在单一字段里。[scan_fields](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:536)、[TLS 字段](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:1006)、[日志名](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_field_schema.c:977)、[TLS 域名](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:1263)、[QUIC 域名](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3397)、[FQDN 写入](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/stellar_scanner_plugin.c:3430)

未验证范围包括：全部 LPI 终止原因是否导出、SNI timeout/预算耗尽/不支持版本/解密失败是否形成统一原因集合、ECH 场景的产品展示、QUIC 全版本覆盖，以及 decoder 细节状态与规则执行记录间的稳定关联。当前产品的 TLS/QUIC 范围不能从 fork 更多的协议插件反向扩大。

## 8. 导出、丢失、容量和留存

### 8.1 Session exporter 是有条件的结束记录

`exporter_on_pseudo_buffer()` 根据 baseline/enforcer/flowsync 的 export option 决定是否导出；普通记录还受 minimum packets 限制，events 模式例外。通过检查后把 start/last/duration、C2S/S2C RAW 包字节等写入默认 itable，送 ringbuf，并清空 session context 的 itable 指针。这是“观察到的会话收包统计”，虽然日志字段叫 sent/received，也不代表操作系统 socket 的发送成功量。[导出决策](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter.c:550)、[结束导出](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter.c:816)、[时间及流量字段](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter.c:264)

队列的生产者按 worker 映射到配置数量的 ring；acquire 失败直接释放 itable，并增加 ringbuf produce error。消费者序列化 JSON，调用 Kafka producer，另将 session record 导出 IPFIX；随后释放 itable。消费者里的 `STATUS_OK` 是 Kafka 调用返回成功，不是已确认下游持久保存。本轮没有查证这条链路具有本地重试账本或跨进程恢复。[生产与满队列](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter_ringbuf.c:277)、[消费](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter_ringbuf.c:210)、[Kafka 调用](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter_kafka.c:14)

### 8.2 聚合导出先 reset，发送成功计数不能直接当作交付保证

Policy rule hits 导出调用 fieldstat 的 export-and-reset，然后 `rd_kafka_produce()`；返回失败增加 fail 计数并释放此次序列化数据。成功计数同样是进入 producer 的结果。Statistics enforcer 使用相同类型的 export-and-reset → sink callback 结构。调用端没有在失败分支把本批聚合加回去；外部库内部行为和端到端交付质量未验证。[policy 导出](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/stellar_policy_rule_hits.c:459)、[statistics 导出](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_enforcer.c:758)

CSV 写出利用临时路径、close 与 rename 发布文件；这能说明文件发布机制，不能推出总磁盘配额、保留天数、查询索引、崩溃恢复或 UI 导出权限都已完成。没有把“存在文件 sink”归类为完整历史存储。[file helper](/home/js/backup/backup/Git/vpp/src/plugins/stellar_exporter/stellar_exporter_file.c:19)

### 8.3 Telemetry 是受控逐包诊断

已确认的链路：

```text
Ethernet 输入 filter callback
  → 启用且运行中的 job，BPF 匹配，采样与 packet cap
  → 分配 telemetry buffer，拷贝 snaplen 范围抓包
  → 经过的模块追加 timestamp / module_name / comment
  → 原 buffer 释放 callback：完成记录并放入 ringbuf
  → 独立线程消费，按 job UUID 输出 PCAPNG 或 Kafka MessagePack
  → 释放诊断记录
```

可配置和有界项包括最多 8 个 job、默认 ring 元素数 65,535、每条记录固定 16 KiB 缓冲、默认 PCAPNG 文件上限 32 MiB，以及 BPF、sampling、pkt_cnt_max、snaplen。ring 中是指针，不能把 ring 元素数组的大小误认成诊断的总内存预算；单条记录另有分配，正在处理的记录也占内存。数字是源码默认值，不是当前部署配置。[限制定义](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.h:16)、[任务筛选](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:39)、[分配及复制触发](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:247)、[记录字段](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:109)、[文件上限](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry_output.c:22)

ring 满时释放记录并计失败；消费者分批取记录，繁忙时每批 sleep 10 ms，空闲时 sleep 300 ms。下游缓慢会积压，源码选择的是丢诊断记录并报告，而非等待把原数据包扣住。此处仅描述 fork 的可见行为，不是对当前产品作适配选择。[释放与队列失败](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:303)、[消费节奏](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry_output.c:488)

它分别累计 Kafka queue 接受/失败与 delivery callback 成功/失败，区分度比只看 producer 返回值更好；仍不能等同于 UI 查询成功或永久留存。还有 filter miss、采样未中、达到包数上限、分配失败、decode 失败、PCAPNG 成败、记录释放等计数。计数名本身仍需检查实现：例如 `RECORDS_DROPPED_FOR_JOB_DELETED` 在消费端每个现有 job 的 UUID 不匹配分支也会增加，不能未经验证直接当作唯一的“被删任务导致记录丢失数”。[queue 计数](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry_output.c:394)、[delivery callback](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry_kafka.c:8)、[完整 counter 列表](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.h:46)、[job 消费分支](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry_output.c:431)

部署条件也不能省略：telemetry 初始化在 Kafka 或 MAAT 配置未加载时提前返回，未启动输出线程/注册 callback；CMake 缺 libpcap 时会禁用插件。文件输出选项存在并不代表没有 Kafka/MAAT 配置也一定能直接工作。[初始化门槛](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:402)、[构建门槛](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/CMakeLists.txt:1)

## 9. 外部库、测试与 UI 的证据范围

MAAT 接口在该树中作为 include 和链接依赖使用；policy sketch 与 statistics enforcer 链接 `fieldstat4`、`maatframe`，scanner 也链接 `maatframe`。本轮在受版本控制 `src/` 中未找到对应 MAAT/fieldstat 核心实现，因此规则编译返回顺序、对象命中内部语义、fieldstat 多线程同步/采样/容量溢出机制均停留在调用方证据，不能虚构其实现。[policy CMake](/home/js/backup/backup/Git/vpp/src/plugins/stellar_policy_sketch/CMakeLists.txt:30)、[statistics CMake](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/CMakeLists.txt:31)、[scanner CMake](/home/js/backup/backup/Git/vpp/src/plugins/stellar_scanner/CMakeLists.txt:33)

可见测试源码确实有实际断言：Session Manager overload test 检查 used/opening/active/closed/evicted/bypass 等统计；statistics unit test 检查 telemetry 的 rule UUID 字符串。它们证明有人对部分行为编码了预期。本轮没有运行，也没有证明 exporter 断连、队列饱和、结束通知丢失、动态规则变更下的全部统计正确性。[overload 断言](/home/js/backup/backup/Git/vpp/src/plugins/stellar_session_manager/test/session_overload_test.c:26)、[telemetry 字符串测试](/home/js/backup/backup/Git/vpp/src/plugins/stellar_statistics_enforcer/stellar_statistics_unit_test.c:501)

本文已定位 CLI、API enable/disable 入口、Kafka/IPFIX/PCAPNG/CSV 输出；未调查外部 Web/桌面前端、数据库、Kafka consumer、OLAP 服务或集群运维仓库。telemetry 中“for use on the UI”的注册注释不能单独证明 UI 已有对应功能。故**“源码支持导出”与“用户能够按应用/规则查询历史、看到遗漏和执行解释”之间仍有未验证部分**。[telemetry 注册](/home/js/backup/backup/Git/vpp/src/plugins/stellar_telemetry/telemetry.c:407)

## 10. 对当前个人设备需求的启发：只归纳问题，不定方案

以下是基于上面源码与当前讨论边界的推断，待需求讨论确认：

1. **先区分用户要确认的状态。** 规则配置是否存在/成功发布、被评估、条件命中、胜出、实际执行、执行失败、持续影响现有流量，是不同问题。fork 主要提供其中若干运行时观测点；不能用一个 hit count 包办。
2. **统计必须写明分母与计量点。** 接口收到、session 看见、规则关联、动作处理和输出提交的包/字节都可能不同；不能仅靠同名 packets/bytes 做守恒校验。
3. **活动范围不能全依赖 Flow。** 当前已讨论的静态 pre-Flow DROP 不产生 Flow；fork 的 session 聚合与结束导出不能作为该类记录已覆盖的证据。主动 packet telemetry 也有选择与丢失条件。
4. **“按接口”与“按个人设备网络”需要不同定义。** fork 的 `sw_if_index`、channel、inbound/outbound 来源于转发路径和网关方向。不能直接当作 Android VPN 当前 Wi-Fi/蜂窝流量的归因，也不能将 LPI app ID 当作安装应用身份。具体 Android/root attachment 能提供什么，由当前主线调查确定。
5. **信息不齐全也是可观察状态。** LPI/SNI 等尚未识别、最终无法识别、未启用、未采集、诊断丢失和真实零命中不能都表现成空字符串或 0。fork 的分散诊断字段提示要先精确列出用户所需的区别。
6. **可观测性本身需要质量说明。** 最近更新时刻、采样、计数重置、容量淘汰、结束记录遗漏和导出失败影响用户能否信任结果。存在某个 fail counter 仍需要校验其分母及 UI 解释。
7. **历史与实时需求分开确认。** 当前 session list、聚合窗口、结束记录、逐包诊断、跨重启历史不是同一种产品能力。fork 展示了它们各自的代码成本，未提供把它们无条件合并的理由。

不能从本报告推出需要复用 fork 的 fieldstat、MAAT、Kafka、session 伪包或其线程模型。当前产品应先明确所需事实、精度、覆盖、延迟和留存，再讨论符合现有 C/VPP 主线的实现。
