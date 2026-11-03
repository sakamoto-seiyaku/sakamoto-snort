# Activity 数据通道断开：App 的 Activity／AppDetail 自 2026-09-08 起没有数据来源

记录日期：2026-11-01。来源：审计 SAKAMOTO-61（协议识别进入 Activity）时发现。本文只记录事实与待定选项，不代表已决定方案。

## 结论

App 有两套 Activity 通道。旧通道（`ProductNativeActivityIngestor` → `BoundedActivityStore` →
`ProductActivityProjectionStore` → AppDetail）读取 native 状态中的 `policyDropActivity` 与
`allowedFlowActivity`。当前 VPP-native 产品（`src/`、`crates/`）不产生这两个字段，因此 AppDetail 的拦截记录、
放行记录与协议识别状态一直为空。新通道（Rust product-core observation：history 与 current flows）由当前产品
产生，并已带有每个 Flow 的 UID、协议集合、`lpi_stop` 与 SNI 结果，但只在 App 的调试式按钮
“Query history”“Query health and flows”中以原始字段显示。

## 断开经过

| 日期 | 提交 | 事件 |
| --- | --- | --- |
| 2026-08-26 | `9e65745f` | 旧路径最后一次扩展：`policyDropActivity` 增加 tuple 证据 |
| 2026-08-26 | `291da697` | Snort C++ 主线退役 |
| 2026-09-01 | `0446128a` | `src/product/vpp/product_vpn_udp4_adapter.c`（handcrafted bridge）仍输出这两个字段 |
| 2026-09-08 | `f8b02499` | S200 把 handcrafted bridge 移到 `experiments/handcrafted-direct-bridge/`；此后产品中没有任何产生者 |

当前唯一的产生者是 `experiments/handcrafted-direct-bridge/source/product_vpn_udp4_adapter.c`，它不进入产品构建。

## 受影响的代码与证据

读取已不存在字段的产品代码：

- `RuntimeService.java`：`nativePolicyDropRecord`、`nativeAllowedFlowRecord` 及其 ingest 调用（约 7340–7442 行）。
- `ProductNativeActivityIngestor.java`、`BoundedActivityStore.java`、`ProductActivityProjectionStore.java`、
  `LocalProductBackend.java` 的 activity 部分、`AppDetail` 的 activity 部分、`ActivityItem.java`、
  `ProtocolRecognitionProjection.java`、`ProtocolRecognitionSequence.java`。
- `DebugControlActivity.java`：`formatPolicyDropActivity`、`formatAllowedFlowActivity` 及 AppDetail 显示。

仍以这两个字段为证据的测试（字段不存在时，设备脚本会失败或读到默认值；contract 脚本只做 `grep`，会继续误报通过）：

- 设备：`tests/device/root-nfqueue-device-matrix.sh`、`s51-root-network-gate-product-matrix.sh`、
  `s52-root-l4-product-matrix.sh`、`s55-product-vpn-transport-matrix.sh`、`s58-vpn-l4-product-workflow-matrix.sh`、
  `s59-release-budget-probe.sh`。
- contract：`tests/android/s51-…`、`s52-…`、`s55-…`、`s58-app-first-activity-ui-…`、`s58-vpn-l4-…`、
  `s59-release-budget-probe-contract-test.sh`，`AndroidRuntimeContractTest.java`、`android-runtime-contract-test.sh`。

以旧字段作为验收证据的文档：`docs/product/ANDROID_L4_RELEASE_GATE.md`（例如 192 行的
`policyDropActivity.uid=12546`）、`docs/reference/PROTOCOL_IDENTIFICATION_VPP_REFERENCE_INVENTORY.md`、
`docs/reviews/2026-09-15_OBSERVABILITY_REQUIREMENTS_REVIEW.md`。这些证据产生于旧路径，不能证明当前产品。

## 当前产品已有的数据（新通道）

- 已结束 Flow 记录与按分钟、按 layer／protocol_id 的历史窗口：`crates/product-core/src/observation.rs`、
  `observation_store.rs`，native 来源 `src/product/vpp/product_observation.c`。
- 当前 Flow 分页：`LiveFlowEntry`（`protocols` bitmask、`protocols_available`、`lpi_stop`、`sni_result`、
  `sni_stop`、UID、network、方向、包／字节计数、ORIG／REPLY attribution）。
- App 入口：`RuntimeControlBackend.observationQuery` → JNI `sakamoto_product_core_observation_page_query`，
  只有 `DebugControlActivity` 调用。

## 对 SAKAMOTO-61 的影响

61 要求的 detecting／identified／unidentified 可由新通道现有字段推导（`lpi_stop=running`；有 mapped 协议；
停止且无协议）。仍缺：

1. 首次出现顺序：native `product_lpi_state_t.protocols` 是 64 位 bitmask，顺序丢失；需要有界有序序列。
2. payload 包数：native 已有 `lpi.attempts`，未导出到 observation 记录。
3. 显示：history 与 current flows 只显示原始字段。

## 待定选项

- A：后续 Activity 工作（含 61）只建立在新通道上；旧通道及其测试、文档证据作为死代码与失效证据单独清理。
- B：把旧通道改为从 observation 取数，恢复 AppDetail 的拦截／放行／识别显示。
- C：在 native 状态中重新输出 `policyDropActivity`／`allowedFlowActivity`。会形成两套 Activity 数据源，不推荐。

用户方向（2026-11-01）：在做 UI 之前先对已有任务做全面清理，打好基础。

## 2026-11-02 访谈：已确认范围

用户确认 Q1、Q2、Q4、Q5、Q6、Q7、Q8，并要求 Q3 谨慎控制范围，不能无限追加要求。
访谈已确认设计共识，正式规格发布为
[SAKAMOTO-329：产品活动数据出口补全](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/6c736721-8779-4888-8853-d57881ac146d)，
状态 Todo、high、ready-for-agent，完整正文与元数据已回读。下文保留范围取舍，
不构成新实现或验收结果。[SAKAMOTO-61](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/c7e0c179-b64c-47d3-99b7-e0dd05bf2842)
保留其中识别事实的工作来源；后续拆票再明确任务归属，本次未修改其父项、状态或依赖。

- **交付终点**：补齐供未来正式 UI 使用的数据事实、保存与查询合同，通过现有调试入口验证
  当前连接、历史和重启后的结果，并准确表达未知、延迟和覆盖缺口。正式页面设计与 Tauri 接入后置；
  本轮完成条件相应调整为数据出口可用，原 S61 的 Activity/AppDetail 接通表述保留其阶段语境。
- **覆盖范围**：全部已交付能力的数据出口，包括当前连接、近期允许/阻止、DNS 查询决定/答复/代理结果、
  协议识别状态/首次顺序/实际识别包数、现有应用/规则/协议统计、采集/持久化/覆盖缺口健康。
  已接通部分直接复用；S61 的识别事实属于公共数据补全的一部分，实施规格与任务归属在设计闭合后收敛。
- **查询范围约束**：前轮 Q3 提出的整组筛选条件未获全量确认，不作为整组硬验收要求。
  新增查询能力以本轮用途的必要性和既有有界预算为依据；未来 UI 可能需要的条件不自动成为本轮要求。
- **连接名称事实**：补齐已经实际取得的 SNI、HTTP/SOCKS 目标名称及真实来源，进入当前连接和近期详情，
  保留不可用状态。DNS 记录保持自身身份，关联使用范围继续遵守此前暂缓决定。
- **失效旧链清理**：新查询通过验收后，退役无当前产品数据产生者的旧 Activity 采集、存储、投影路径，
  将有效测试迁移到当前查询合同。按实际调用关系保留启动、规则配置、诊断所需代码；
  历史验收记录和原始证据继续保存。
- **新增事实的留存**：用户接受新补齐的名称和识别序列随所属明细保留及淘汰，长期沿用现有统计分层。
  明细淘汰后不承诺还原该次访问详情；本轮未选择新的长期无损明细归档。
- **停止后的历史读取**：保护停止后仍可读取已保存记录及统计，当前连接明确表示已停止。
  读取历史与启动保护分开，继续遵守原有留存限制。
- **HTTP 多目标的有限事实**：可用版先提供最近识别到的有效目标及其当前可用性，
  同时保留导致连接被阻止的目标和规则归属。两者含义分别表达；完整逐请求目标历史后续再讨论。
- **访谈的取舍标准**：用户明确“先能用，随后再重构”是本轮 grill 的设计标准，
  不构成开始修改源码或测试的实施指令。优先复用已有能力与默认参数，新增要求须对应当前明确用途；
  结构优化与未来可能需要的查询条件后置。正确性和数据安全沿用已有约束。

沿用 ADR-0009/0010 的配置与观察存储权威、既有有界资源和前端生命周期独立性。
此范围没有改变 DNS 关联使用范围的暂缓决定，也没有选择新的识别算法、历史统计维度或数据保留预算。
