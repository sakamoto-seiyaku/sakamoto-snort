## Context

`dx-smoke` 当前固定执行 `platform -> control -> datapath`，其中 datapath 通过 `tests/device/ip/run.sh --profile smoke` 承接 IP Case 1–8 与 Conntrack Case 1。`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## 其他` 剩余两类口径不适合直接塞入默认主链：perfmetrics 可用性需要真实 NFQUEUE payload 触发，但不需要公网大下载；极端规模 limits sanity 可能耗时、耗内存，且更偏上线前/手工诊断。

本 change 的设计目标是给这些“其他”Case 建立可执行、可回查、可选运行的真机验收边界，同时保护现有 active smoke 的速度与稳定性。

## Goals / Non-Goals

**Goals:**
- 为 `## 其他` Case 1 提供非公网依赖的 `perfmetrics.enabled` smoke-style 验收：off 全 0、on 采样增长、1→1 不清零、非法值拒绝。
- 为 `## 其他` Case 2 提供可选 limits sanity：`DOMAINLISTS.IMPORT` 与 `IPRULES.APPLY` 的 under/over limit 行为可解释，失败后 daemon 仍可 `HELLO`。
- 所有新断言使用 vNext `CONFIG.*`、`METRICS.*`、`DOMAINLISTS.*`、`IPRULES.*` 与现有 Tier‑1 payload helper。
- 保持默认 `dx-smoke` 主链、`dx-smoke*` CTest 名称集合、`dx-diagnostics*` 主入口组稳定。
- 实现后同步 casebook、coverage matrix 与 roadmap，确保从人话 Case 能回查到 check id。

**Non-Goals:**
- 不新增 C++ 产品逻辑、不改变 vNext control schema、不改变持久化格式。
- 不把 casebook-other 默认纳入 `dx-smoke.sh` 或 `tests/device/ip/run.sh --profile smoke`。
- 不新增 `dx-smoke-other`、`dx-smoke-perfmetrics` 等 `dx-smoke*` 入口。
- 不替代 `dx-diagnostics-perf-network-load` 的公网下载/性能观测职责。
- 不做真实海量导入的性能 benchmark、stress、longrun 或设备容量测试。

## Decisions

1) **casebook-other 作为 opt-in 入口**
   - 选择：新增可直接运行的 optional runner/case，而不是修改 `dx-smoke` 默认顺序。
   - 理由：roadmap 明确“默认不进 `dx-smoke` 主链，可选运行”；极端规模 sanity 不适合高频 gate。
   - 备选：把 Case 1 接入 datapath smoke、Case 2 接入 diagnostics 总入口；拒绝，因为会扩大默认运行时间与 flake 面。

2) **perfmetrics 使用 Tier‑1 payload 触发**
   - 选择：复用 IP 模组 netns+veth + fixed TCP payload helper 触发 `nfq_total_us`。
   - 理由：Case 1 验证的是开关语义，不是公网下载能力；Tier‑1 payload 可重复、无公网依赖。
   - 备选：复用 `dx-diagnostics-perf-network-load.sh` 下载 URL；拒绝，公网/设备 downloader 会把环境问题混入 smoke 语义。

3) **DNS perf 只做可选观测**
   - 选择：Case 1 的 hard gate 只要求 `nfq_total_us.samples`，`dns_decision_us` 仅在 netd resolv hook 可用且真实触发 DNS 时断言。
   - 理由：casebook 已明确不要把 netd hook 环境问题误判为 perfmetrics 功能坏。
   - 备选：强制要求 DNS samples 增长；拒绝。

4) **极端规模 sanity 重点验证 limits 与恢复性**
   - 选择：under-limit 用受控小规模证明正常路径，over-limit 用最小可触发结构化错误的 payload/ruleset，随后立刻 `HELLO`。
   - 理由：本 change 的目标是“失败必须可解释 + daemon 仍可 HELLO”，不是压测最大吞吐或最大内存。
   - 备选：真实导入接近 16MiB/100万域名或长期保留 5000 条规则；拒绝，运行成本高且设备差异大。

5) **失败结果区分环境与产品断言**
   - 选择：ADB/root/vNext/Tier‑1 前置不足报告 `BLOCKED(77)` 或现有 IP 模组 `SKIP(10)`；前置满足后的契约不符报告 `FAIL`。
   - 理由：保持 DX smoke/diagnostics 已有可解释结果语义。
   - 备选：把所有不可运行都视为 skip/pass；拒绝。

6) **文档以 check id 对齐**
   - 选择：实现时为 Case 1/2 分配稳定 check id（建议 `VNXOTH-01*`、`VNXOTH-02*`），并同步 casebook、coverage matrix、roadmap。
   - 理由：casebook 是当前验收口径；必须能从文档回查到实际断言。
   - 备选：只新增脚本不更新文档；拒绝。

## Risks / Trade-offs

- [Tier‑1 前置不可用] → 沿用 IP 模组前置检查与 `BLOCKED/SKIP` 语义，输出 root/netns/veth/uid 提示。
- [background NFQUEUE 流量干扰 perf samples] → 每个窗口前 `METRICS.RESET(name=perf)`；off 阶段要求全 0，on 阶段只要求 samples 增长。
- [大 payload 导致 host/adb/daemon 内存压力] → over-limit payload 使用最小触发边界；Case 2 默认 optional，不进主链。
- [limits 断言过度绑定具体 message] → hard assert 绑定 `error.code` 与结构化 `error.limits/error.preflight`，message/hint 做包含性检查。
- [新入口命名制造 DX 心智分叉] → 不新增 `dx-smoke*`；文档中明确 optional casebook-other 与默认 smoke/diagnostics 的关系。
- [真机暴露产品行为偏差] → 记录到 `docs/testing/DEVICE_SMOKE_SNORT_BUGS.md`，不在测试 change 中隐式修改产品逻辑。

## Migration Plan

- 新增 optional casebook-other runner/case，先覆盖 `perfmetrics.enabled` Case 1，再覆盖 limits sanity Case 2。
- 如需 CTest 注册，使用非 `dx-smoke*` 名称，并保持 `dx-smoke` 与 `dx-diagnostics` 聚合入口不自动调用它。
- 同步 `DEVICE_SMOKE_CASEBOOK.md`、`DEVICE_TEST_COVERAGE_MATRIX.md` 与 `IMPLEMENTATION_ROADMAP.md`。
- 验证通过后再归档 change；若设备前置不足，记录 `BLOCKED/SKIP`，不将 optional case 误报为完成的 default gate。

## Open Questions

- 无。范围以 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 其他` Case 1–2 与 roadmap `complete-device-smoke-casebook-other` 为准。
