## Context

`docs/decisions/FLOW_TELEMETRY_WORKING_DECISIONS.md` 已经把观测体系分成三层：

- Flow Telemetry records：常态业务事实，供前端/consumer 持久化、查询和派生聚合。
- Debug Stream：短时间深度取证，保留 `tracked` 门控。
- Metrics：后端低基数健康状态和固定维度 counters。

当前 vNext `METRICS.GET` 只能提供低基数聚合，`STREAM.START(type=dns|pkt|activity)` 是 Debug-only / tail-like 通道，不适合承载前端常态 Top-K、timeline、history、Geo/ASN 或任意窗口查询。新增 Flow Telemetry Plane 的核心约束是：dataplane 不得阻塞 verdict，不做 socket I/O / JSON / 动态分配 / DNS lookup / 全局重锁；导出允许丢弃，但必须可解释。

现有实现已经具备 vNext control session、metrics handler、stream manager、L4 conntrack core、IPv4/IPv6 packet parsing、DNS listener、RESETALL lifecycle 和 host/device 测试入口。这个 change 应在这些基础上新增 telemetry plane，而不是复用 Debug Stream 语义或扩大 daemon metrics 的业务统计职责。

## Goals / Non-Goals

**Goals:**

- 新增 vNext `TELEMETRY.OPEN/CLOSE`，建立单 consumer telemetry session 并通过 Unix domain socket 传递 shared-memory fd。
- 新增 fixed-size slot overwrite shared-memory ring，作为 `FLOW` / `DNS_DECISION` records 的唯一常态导出通道。
- 定义跨语言 binary ABI：little-endian、显式宽度、显式 offset，不依赖 C++ struct padding。
- 接入 packet/conntrack 与 DNS decision 路径，产生 `FLOW` / blocked-only `DNS_DECISION` records。
- 通过 `METRICS.GET(name="telemetry")` 暴露 minimal telemetry state，用于通道健康判断。
- 每个实现阶段都配套 host + integration/device 验证，第一阶段必须打通 fd+mmap/polling reader 真机通路。

**Non-Goals:**

- 不实现 Debug Stream explainability；它是后续独立 change。
- 不实现前端持久化、查询、Top-K、timeline、Geo/ASN、注释或数据库 schema。
- 不在常态 records 中做 DNS↔IP join，不把 domainRuleId 写入 FlowRecord。
- 不提供 Summary mode、TelemetryHealthRecord、TelemetryStatsRecord 或业务统计 records。
- 不重启 IP_LEAK 设计，不扩展 legacy stream，不保证长期全量零丢失交付。

## Decisions

1) **新增独立 vNext telemetry surface，而不是复用 STREAM**

- 选择：新增 `TELEMETRY.OPEN/CLOSE`，普通 telemetry payload 只走 shared memory ring。
- 理由：`STREAM.START` 是 JSON/netstring tail 通道，语义是 Debug-only；Flow Telemetry 需要高吞吐、binary、可丢弃、consumer 自行落盘。
- 备选：新增 `STREAM.START(type=flow)`。拒绝，因为会把常态业务 records 与 Debug Stream 的 tracked/replay/notice 语义混在一起。

2) **`TELEMETRY.OPEN` 只支持 Unix domain vNext socket**

- 选择：OPEN 成功必须通过 ancillary data 传递 shared-memory fd；TCP 60607 / adb-forward 连接上调用 OPEN 必须失败，返回 `INVALID_ARGUMENT` 并给出 hint。
- 理由：fd passing 是 Android/Kotlin consumer 不引入 NDK 的关键路径；TCP 无法承载 fd 语义。
- 备选：TCP 返回路径字符串或 base64。拒绝，因为会引入权限/生命周期/复制成本问题。

3) **单 consumer、全局 MPSC fixed-slot overwrite ring**

- 选择：同一时间只有一个有效 consumer；新 OPEN 抢占旧 session。producer 使用全局 `writeTicket.fetch_add(1)` 定位 `slotIndex=ticket % slotCount`。
- 理由：单 consumer 简化 ABI 和 RESETALL/抢占语义；固定 slot 让热路径写入是 bounded memcpy + commit，不需要动态分配。
- 备选：多 consumer 或 variable-length ring。拒绝，因为会显著增加同步、回收、gap 和内存管理复杂度。

4) **Ring ABI 固定发布基线**

- 默认值：`slotBytes=1024`、`ringDataBytes=16 MiB`、`slotCount=16384`。
- slot header 只放 transport/framing 元数据；`timestampNs` 属于 record payload。
- record 由 `recordType + payloadSize` 定界，payload 自带 `payloadVersion`；字段演进只允许 append。
- IP 地址固定 16 bytes；IPv4 写前 4 bytes，其余置 0。
- C++ 实现必须使用 RAII 管理 fd/shared memory/session ownership，wire layout 用 constexpr offsets/explicit serialization，不通过 `reinterpret_cast` 暴露 C++ struct padding。

5) **Consumer polling，不做 per-record wakeup**

- 选择：普通 records 不做逐条唤醒；consumer 默认 `pollIntervalMs=1000` 轮询。
- 理由：常态 UI 对 1s 级别延迟可接受，减少 hot path 信令成本。
- 备选：每条 record doorbell。拒绝，因为会把 producer 写 ring 变成高频跨线程/跨进程信令。

6) **FlowRecord 是最终执行事实，不是 Debug 证据链**

- `FLOW` payload 内部使用 `BEGIN / UPDATE / END`。
- `decisionKey = ctState + ctDir + reasonId + optional ruleId`；变化时切段并发 UPDATE。
- counters 只携带累计 `totalPackets/totalBytes`，不携带 delta；consumer 用前后累计值计算窗口增量。
- 不携带 `wouldRuleId`、候选规则、shadow/why-not、domainHint、domain name、domainRuleId 或 domain->IP 映射。

7) **DNS 常态 record 独立且 blocked-only**

- `DNS_DECISION` 用于“最近哪些域名被拦、为什么拦”的常态 timeline。
- 只记录 blocked DNS decision；可携带 bounded inline `queryName`，上限 255 bytes。
- 不携带解析返回 IP 明细/数量，不与 FlowRecord join。

8) **Flow Telemetry level 是 conntrack/flow observation consumer**

- `level=Flow` 且 session 有效时，可以驱动 conntrack/flow observation，即使当前 IPRULES 没有 ct 规则。
- `level=Off` 或 consumer absent 时，producer 直接 drop 或不写 ring；不应把 optional telemetry 成本变成默认每包成本。
- 每包最多一次读取 exporter/config 指针并向下传递，避免多层重复判断。

9) **RESETALL 是 telemetry session rebuild**

- RESETALL 必须作废旧 ring/session；不要求为每个 active flow 逐条发送 END。
- 前端必须在 RESETALL 前停止 ingest、清空 records DB 和 active assembly state；ACK 后重新 OPEN。
- daemon 在 RESETALL 后重新进入无 consumer baseline，old fd/mmap 即使仍存在也没有合法数据语义。

10) **Minimal telemetry state 走 metrics 查询，不走 records**

- 选择：扩展 `METRICS.GET(name="telemetry")` 返回 channel health。
- 理由：telemetry state 是 daemon health，不是业务事实；records DB 中只存 `FLOW` / `DNS_DECISION`。
- 备选：新增 TelemetryHealthRecord / TelemetryStatsRecord。拒绝，因为会污染 records 数据库语义。

## Risks / Trade-offs

- [Risk] Flow On 热路径成本超过预期 → Mitigation：固定 slot、无动态分配、无 JSON/socket I/O、每包一次 exporter 指针读取，并用 host/device perf 对比报告 Flow On vs Off。
- [Risk] 慢 consumer 导致 ring overwrite → Mitigation：transport ticket gap + per-flow recordSeq gap + dropped counters；目标是可解释丢失，不是零丢失。
- [Risk] 记录过大超出 1KiB slot → Mitigation：字段固定上限；`DNS_DECISION.queryName` 截断；超限 drop 并计入 `recordTooLarge`。
- [Risk] shared-memory fd 生命周期或抢占处理错误 → Mitigation：RAII fd/session owner、single consumer ownership、OPEN 抢占旧 session、RESETALL 作废旧 ring，并覆盖 host/device tests。
- [Risk] Android/TCP/adb-forward 使用者误以为能 OPEN → Mitigation：spec 和 interface doc 明确 OPEN 只支持 Unix domain fd passing；TCP 只能查询 `METRICS.GET(name=telemetry)`。

## Migration Plan

- 本 change 新增能力，不移除现有 `METRICS.*` 或 `STREAM.*`。
- Flow Telemetry 默认 Off / 无 consumer；未 OPEN 时不影响现有前端、脚本和 datapath 判决。
- `docs/INTERFACE_SPECIFICATION.md` 在实现阶段同步新增 `TELEMETRY.*` 和 `METRICS.GET(name=telemetry)`。
- 前端接入顺序建议：先接 OPEN + mmap reader + telemetry state，再接 records persistence/query。

## Open Questions

- 无阻塞实现的问题已在工作纲领中收口；实现阶段只允许在不改变语义的前提下细化 field offsets、enum numeric values、slot header checksum/magic 等 ABI 细节。
