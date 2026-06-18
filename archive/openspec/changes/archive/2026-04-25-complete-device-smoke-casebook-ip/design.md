## Context

`dx-smoke-datapath` 当前通过 `tests/integration/dx-smoke-datapath.sh` 调用 `tests/device/ip/run.sh --profile smoke`，该 profile 已执行 vNext-only 的 `14_iprules_vnext_smoke.sh` 与 `16_iprules_vnext_datapath_smoke.sh`。现有脚本已经覆盖 IPRULES surface、Tier‑1 allow/block、would overlay、IFACE_BLOCK 与 `block.enabled=0` reasons gating。

`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## IP` 章节进一步要求这些 case 形成“真实流量 verdict → pkt stream → reasons/traffic → per-rule stats”的可解释闭环，并新增 `iprules.enabled=0` correctness 与 payload bytes 稳定触发。本 change 的设计目标是把这些口径落实到 active smoke，而不是新增入口或改产品语义。

## Goals / Non-Goals

**Goals:**
- `dx-smoke-datapath` 覆盖 IP Case 1–8，并为每条 case 输出可回查 check id。
- 所有新增/强化断言都走 vNext control path 与 Tier‑1 netns+veth 真实流量。
- 将 `nc -z` 触发的 allow/block/would/iface verdict 结果改为硬断言，不能再被 `|| true` 静默吞掉。
- 对 traffic/reasons 使用 reset + bucket 级断言，避免只看 total 导致归因漂移。
- 对 bytes 类断言使用固定 payload read，避免短连接握手字节数波动。

**Non-Goals:**
- 不新增 `dx-smoke*`、CTest target 或 IP profile 名称。
- 不修改 vNext 控制协议、产品 C++ 逻辑、C++ ABI 或持久化语义。
- 不把 `## IP - Conntrack` 纳入本 change；conntrack smoke 另行处理。
- 不把 matrix/stress/perf/longrun 责任混入 active smoke 的最小 gate。

## Decisions

1) **所有 IP case 落在现有 smoke profile**
   - 选择：继续使用 `tests/device/ip/run.sh --profile smoke`，由 `14_iprules_vnext_smoke.sh` 承接 Case 1，由 `16_iprules_vnext_datapath_smoke.sh` 承接 Case 2–8。
   - 理由：`dx-smoke-workflow` 已规定 datapath smoke 使用 active vNext IP smoke profile；新增入口会破坏当前主入口收敛。
   - 备选：新增 `dx-smoke-ip` 或新 profile；拒绝。

2) **`nc -z` verdict 必须变成硬断言**
   - 选择：allow/would 必须确认连接成功，block/IFACE_BLOCK 必须确认连接失败；只有前置缺失才报告 `BLOCKED(77)`。
   - 理由：casebook 的核心是“人话 verdict”，pkt stream 命中但真实连接结果不符时应判为 FAIL。
   - 备选：继续用 `|| true` 只依赖 stream；拒绝。

3) **metrics 断言从 total 升级到 bucket**
   - 选择：每个 case 在触发前 reset traffic/reasons，触发后断言具体 bucket，例如 `txp.allow`、`txp.block`、`ALLOW_DEFAULT.packets`、`IP_RULE_ALLOW.packets`。
   - 理由：total 增长无法证明 allow/block/reason 归因正确。
   - 备选：只记录 debug snapshot；拒绝。

4) **payload bytes 使用固定读 N bytes**
   - 选择：新增 Case 8 使用 `iptest_tier1_tcp_count_bytes 443 65536 2000` 或等价 helper，断言读到 N bytes 后再检查 `rxb/txb`、`hitBytes` 与 reasons bytes。
   - 理由：`nc -z` 只有握手，bytes 断言波动大；固定 payload 是当前仓库已有的稳定 Tier‑1 触发模式。
   - 备选：在 Case 2 的短连接上硬断言 bytes；拒绝。

5) **`iprules.enabled=0` 作为独立 correctness case**
   - 选择：Case 7 下发可命中的 block rule，关闭 `iprules.enabled` 后验证连接成功、`ALLOW_DEFAULT`、无 ruleId/wouldRuleId、rule stats 不增长；结束时恢复 `iprules.enabled=1`。
   - 理由：现场排障中“规则没生效”和“模块开关关闭”必须能通过 smoke 区分。
   - 备选：只依赖 perf profile 切开关；拒绝，因为 perf 不做 verdict correctness。

6) **stream helper 可局部抽取但不改变 wire shape**
   - 选择：若 `16_iprules_vnext_datapath_smoke.sh` 继续增长，可将重复的 pkt stream capture、metrics bucket 解析和 rule stats 读取抽成脚本内函数或 `tests/device/ip/lib.sh` helper。
   - 理由：减少重复 Python/netstring 片段，降低后续维护风险。
   - 备选：一次性重写整个 IP runner；拒绝，范围过大。

## Risks / Trade-offs

- [Payload read 在部分 uid 下无网络权限] → Mitigation：Case 8 默认沿用 smoke 的 shell uid=2000；若设备前置无法建立 Tier‑1 TCP，报告 `BLOCKED/SKIP` 提示而不是伪造 PASS。
- [短连接 verdict 硬断言暴露既有 flake] → Mitigation：在失败时输出 traffic/reasons/stream debug snapshot，便于判断是前置、路由还是产品行为问题。
- [脚本过长导致重复逻辑难维护] → Mitigation：只抽取 vNext/Tier‑1 通用 helper，不引入 legacy helper 或大规模 runner 重构。
- [bytes counters 包含 IP header，不等于应用 payload] → Mitigation：断言使用 `>= N`，并在 casebook 文档保留 NFQUEUE payload length 口径说明。
- [pkt stream 可能受后台包干扰] → Mitigation：stream capture 继续按 uid、direction、peer IP、port、reasonId 与 ruleId 过滤，并使用 `horizonSec=0`。

## Migration Plan

- 先补 helper 与 Case 1–6 的硬断言/metrics bucket，确保现有 smoke 责任不退化。
- 再新增 Case 7 与 Case 8，分别补 `iprules.enabled=0` correctness 与 payload bytes。
- 最后同步 `DEVICE_SMOKE_CASEBOOK.md`、`DEVICE_TEST_COVERAGE_MATRIX.md` 与 validation 记录。
- 若新增断言在前置不足设备上无法运行，保持 `BLOCKED(77)` / `SKIP` 语义；若前置满足但行为不符，报告 `FAIL`。

## Open Questions

- 无。范围以 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## IP` Case 1–8 为准，且明确不包含 `## IP - Conntrack`。
