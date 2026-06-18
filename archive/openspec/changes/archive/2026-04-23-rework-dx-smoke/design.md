## Context

当前仓库的 `Device / DX` 真机测试（host/WSL 通过 ADB 驱动 rooted Android 真机）存在以下现状：

- 入口命名与职责混杂：`p1/p2/ip-smoke` 等历史 lane 与 `vNext` 主线脚本并存，`baseline/smoke/perf` 等语义没有作为“对外入口职责”被收敛。
- active 主线与迁移源未分轨：部分 legacy 脚本仍承担有效覆盖，但在默认入口里“看起来像还在跑”或“跑不跑都没人确定”。
- 工具展示不可用：在 `CTest`/VS Code Testing 里无法按“平台 gate / 控制面基线 / datapath 闭环”进行分组与心智对齐。

本 change 以 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md` 的共识为上位约束，目标是把 active `smoke` 收敛为 `vNext` 主入口，并完成旧 smoke 覆盖责任的 vNext 迁移；`diagnostics` 将由后续独立 change 处理。

## Goals / Non-Goals

**Goals:**

- 定义并落地 DX `smoke` 的唯一主入口组：`dx-smoke` + `dx-smoke-platform` / `dx-smoke-control` / `dx-smoke-datapath`。
- 固化 `dx-smoke` 的执行顺序与 gate 语义：`platform -> control -> datapath`，fail-fast，并区分 `PASS/FAIL/BLOCKED`。
- 让 active `smoke` 的覆盖面一律以 `vNext` 为准；legacy 脚本只作为迁移源按需回查，不进入默认主入口。
- 让 active `smoke` 接住旧 smoke 中仍属于主功能 gate 的覆盖责任，而不是只跑最小 happy path。
- 让 `CTest`/VS Code Testing 中的测试名/标签可读、可分组、可作为后续真机测试重组的稳定锚点。

**Non-Goals:**

- 不在本 change 里设计/收敛 `diagnostics` 的最终命名体系与目录结构（仅 smoke）。
- 不追求把 DX 真机测试覆盖率“补到百分之百”；但旧 smoke 中属于主功能 gate 的责任必须在本 change 内被 vNext active smoke 接住。
- 不迁移 perf/stress/longrun/matrix 型 diagnostics；这些仍由后续 diagnostics change 处理。
- 不把 legacy/compat 命令继续塞进 active smoke。若某项 smoke 责任只能靠 legacy DEV 命令触发，本 change 应先明确是否需要 vNext DEV-only test seam，然后再实现。

## Decisions

1) **入口命名使用 `dx-smoke*`，不再延续 `p1/p2/ip-smoke/baseline`**
   - 选择：`dx-smoke`（总入口）+ `dx-smoke-platform/control/datapath`（子入口）。
   - 理由：用“职责切片”替代“历史阶段号”，且不把覆盖内容（domain/ip）误当入口职责。
   - 备选：保留 `p1/p2` 或新增长期 alias；拒绝（历史语义不清且会继续污染新的计划线）。

2) **`dx-smoke` 采用聚合脚本顺序执行（而非依赖 CTest 自身排序）**
   - 选择：新增一个聚合入口（例如脚本 `dx-smoke.sh`）内部顺序调用三个子入口，并实现 fail-fast。
   - 理由：CTest 本身不提供稳定的“依赖/顺序 gate”；用聚合脚本才能保证一致语义。
   - 备选：仅靠 label 分组，让用户手工按顺序跑；拒绝（主入口语义无法固化）。

3) **PASS/FAIL/BLOCKED 的落地方式以“退出码 + CTest 展示”实现**
   - 选择：约定 `BLOCKED` 使用一个固定退出码（建议 `77`），并在 CTest 层配置 `SKIP_RETURN_CODE`，使其在 UI 中明确显示为“未执行/被阻塞”，且不会被误认成 PASS。
   - 理由：`BLOCKED` 表示前置条件不满足（ADB/root/deploy 等），其信息价值与 FAIL 不同；需要在报告里显式区分。
   - 备选：把 BLOCKED 当 PASS 或直接当 FAIL；拒绝（前者会掩盖环境问题，后者会让真实失败信号被噪声淹没）。

4) **迁移源保持可回查，但默认不可见/不可被主入口引用**
   - 选择：把 legacy 脚本以“迁移源”身份保留：文档可见、可显式点名运行，但不进入 `dx-smoke` 与默认 quick start。
   - 理由：保证覆盖不丢失，同时避免继续把混合职责入口当主线。
   - 备选：直接归档/删除 legacy；拒绝（在 `vNext` 未完全承接前会造成覆盖缺口）。

5) **归档（archive）是物理迁移，且受硬门槛约束**
   - 选择：只有当 `vNext` 入口已真正接住 legacy 覆盖责任时，才允许把 legacy 脚本物理移动到 archive。
   - 理由：归档是“生命周期与位置”的同时变更；不能用来掩盖覆盖缺失。
   - 备选：先统一搬到 archive 再慢慢补；拒绝（等价于默认不跑，覆盖会静默流失）。

6) **`smoke` profile 本身必须成为 active vNext profile**
   - 选择：`tests/device-modules/ip/run.sh --profile smoke` 不再执行 legacy/mixed case，而是执行 active vNext datapath smoke；`dx-smoke-datapath` 应调用 active smoke profile。
   - 理由：如果 `--profile smoke` 仍是 legacy/mixed 语义，用户直接运行 IP 模组 smoke 时会绕过新的 DX 主线原则。
   - 备选：为 vNext 新增独立 profile（例如 `--profile vnext-smoke`），把 `--profile smoke` 留给旧 mixed case；拒绝（会保留两个“smoke”心智，且转换不完整）。

7) **完整 smoke 转换按责任矩阵验收**
   - 选择：以“旧 smoke 责任是否被 vNext active smoke 接住”为验收口径，而不是以“有没有一个新脚本”为验收口径。
   - 理由：入口重命名不能等价于覆盖迁移；否则 legacy 迁移源会长期携带真实 gate 责任。

## Smoke Conversion Matrix

| 迁移源 / 旧责任 | active 承接入口 | 本 change 验收口径 | 说明 |
| --- | --- | --- | --- |
| `tests/integration/device-smoke.sh` 平台 gate | `dx-smoke-platform` | root/preflight、socket、netd 前置、iptables/ip6tables、NFQUEUE、SELinux、lifecycle | 已属于入口重组核心内容 |
| `tests/integration/run.sh` core/config/app/streams/reset | `dx-smoke-control` | vNext HELLO/QUIT、inventory、device/app config、stream start/stop、metrics shape/reset、RESETALL | 不再跑 legacy baseline |
| `tests/integration/run.sh` `METRICS.DOMAIN.SOURCES` 行为 | `dx-smoke-control` | vNext domainSources reset、`block.enabled=0` gating、`block.enabled=1` 增长、per-app/tracked=0 不变式 | 需要 vNext deterministic DNS verdict trigger；不得调用 legacy 文本协议 |
| `tests/integration/full-smoke.sh` domain/list/rule 主功能面 | `dx-smoke-control` | vNext `DOMAINRULES` / `DOMAINPOLICY` / `DOMAINLISTS` apply/get/import 及排序/引用/计数字段 | legacy-only 黑白名单命令不作为 active smoke 入口 |
| `tests/integration/iprules.sh` IPRULES 控制面基础 | `dx-smoke-control` + `dx-smoke-datapath` | vNext `IPRULES.PREFLIGHT/APPLY/PRINT`、mapping、canonical CIDR、stats/ct 字段 | 纯控制面在 control，真实包路径在 datapath |
| `tests/integration/iprules.sh` IPRULES 真实 datapath smoke | `dx-smoke-datapath` | Tier-1 真实流量覆盖 allow、block、would-match overlay、per-rule stats、reason metrics | 不要求完整 L3/L4 matrix；matrix 属 diagnostics/专项 |
| `tests/integration/iprules.sh` IFACE_BLOCK / BLOCK=0 | `dx-smoke-datapath` | vNext config 设置 iface block；断言 `IFACE_BLOCK` 优先级、rule stats 不增长、`BLOCK=0` 下 reasons 不增长 | 属主 gate，不能只留在 legacy |
| `tests/device-modules/ip/run.sh --profile smoke` | `tests/device-modules/ip/run.sh --profile smoke` | 默认执行 active vNext smoke case | legacy/mixed case 只能显式回查，不得作为默认 smoke |
| `tests/integration/iprules-device-matrix.sh` / IP matrix | 后续 diagnostics / 专项迁移 | 本 change 不迁移 | 不属于 smoke gate |
| `tests/integration/perf-network-load.sh` / perf | 后续 diagnostics | 本 change 不迁移 | 不属于 smoke gate |

## Risks / Trade-offs

- [风险] 重命名/移除旧 `p1/p2/ip-smoke` 入口可能影响本地习惯与 CI 过滤规则 → [缓解] 在文档中提供“旧入口 → 新入口”对照表；迁移源保留可显式回查，但不作为长期 alias。
- [风险] `tests/device-modules/ip/run.sh` 现存 `smoke` profile 仍混合多职责，直接纳入主线会继续污染 gate 语义 → [缓解] 本 change 必须把 `--profile smoke` 改为 active vNext profile；旧 mixed case 只能显式回查。
- [风险] domainSources 行为测试目前依赖 legacy `DEV.DNSQUERY` seam → [缓解] 若需要保留该 smoke 责任，必须先落地 vNext DEV-only deterministic trigger 或等价机制；active smoke 不允许回退到 legacy 文本协议。
- [风险] `BLOCKED` 采用 CTest SKIP 展示后，某些 CI 可能把 skip 当“整体通过” → [缓解] 在本仓库默认 preset 仍保持 `SNORT_ENABLE_DEVICE_TESTS=OFF`；后续若在 CI 打开 DX gate，再单独定义“BLOCKED 的 CI 判定策略”。
- [权衡] 为保证最小改动，本阶段优先通过“入口脚本 + CTest 重命名/标签”完成收敛，目录层级的深度重排（如 `tests/device/smoke/`）只在确有必要时推进。

## Migration Plan

1. 在 `CTest` 中新增/改名为 `dx-smoke*` 的入口，并确保 `dx-smoke` 聚合入口按固定顺序调用子入口。
2. 按 Smoke Conversion Matrix 补齐 `dx-smoke-control` 与 `dx-smoke-datapath` 的 vNext 覆盖。
3. 把 `tests/device-modules/ip/run.sh --profile smoke` 收敛为 active vNext smoke profile，并让 `dx-smoke-datapath` 调用该 active smoke profile；旧 mixed case 只作为显式回查材料。
4. 把旧 `p1/p2/ip-smoke` 入口改为迁移源（仅显式运行），并从默认入口/文档 quick start 移除。
5. 仅对满足“已被 vNext 接住覆盖责任”的 legacy 入口执行物理归档；其余保持迁移源状态。
6. 更新 `docs/testing/*` 与路线图，确保入口名、职责、覆盖矩阵与边界一致。

## Open Questions

- `BLOCKED` 的退出码是否统一为 `77`，以及是否需要对 `dx-smoke` 总入口与子入口使用同一套返回码策略？
- VS Code Testing 侧对 CTest label 的展示能力是否足够；若不足，是否需要在 test name 前缀中编码（例如 `dx-smoke::platform`）？
