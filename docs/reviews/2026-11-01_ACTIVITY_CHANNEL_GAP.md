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
