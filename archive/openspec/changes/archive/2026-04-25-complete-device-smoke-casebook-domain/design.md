## Context

`dx-smoke-control` 当前通过 `tests/integration/vnext-baseline.sh` 承接 vNext 控制面 smoke，已有 Domain surface (`VNT-15~22`)、基础 DNS stream netd inject (`VNT-10b*`) 与基础 domainSources (`VNT-22i* / VNT-22j*`) 覆盖。

`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 的 `## 域名` 章节已经进一步定义了 Case 1–9：它们不只是“接口能调用”，而是要求 Domain 规则、策略、列表、stream、traffic、domainSources 与 resolver hook 在真机上形成可解释闭环。本 change 的设计目标是把这些 casebook 口径落实到 active smoke 测试中。

## Goals / Non-Goals

**Goals:**
- `dx-smoke-control` 覆盖 Domain Case 1–9，并为每条 case 输出可回查 check id。
- 使用 vNext 控制面与 DEV-only vNext trigger；active smoke 不调用 legacy 文本协议。
- 对所有会改变设备状态的测试执行 restore/cleanup，避免污染后续 case 与开发者设备。
- 对环境前置不足使用 `BLOCKED(77)`，对前置满足后的行为偏差使用 `FAIL`。

**Non-Goals:**
- 不新增 `dx-smoke*` / `dx-diagnostics*` 入口名。
- 不实现产品功能或修改控制协议语义。
- 不把 IP、Conntrack、pkt stream 可观测性章节混入本 change；本 change 只承接 `## 域名`。
- 不为测试做大规模 C++ 重构；如确需 test seam，必须独立说明并保持最小范围。

## Decisions

1) **所有 Domain case 落在 `dx-smoke-control`**
   - 选择：继续以 `tests/integration/dx-smoke-control.sh` → `tests/integration/vnext-baseline.sh` 为入口。
   - 理由：Domain 章节属于 vNext control + DNS decision 责任，不需要新增入口或挤入 datapath IP profile。
   - 备选：新增 `dx-smoke-domain`；拒绝（违背当前 `dx-smoke*` 主入口收敛规则）。

2) **netd inject 是默认稳定 DNS 触发机制**
   - 选择：Case 3/4/6/7/9 使用 `dx-netd-inject` 注入 DNS 请求，避免依赖公网、DNS 缓存或系统 resolver 状态。
   - 理由：这些 case 的目标是验证 Domain 判决与观测输出，不应被外部网络可达性干扰。
   - 备选：全部走真实解析；拒绝（会把稳定 smoke 变成平台环境测试）。

3) **Case 8 单独验证真实 resolver hook，并保留 BLOCKED 语义**
   - 选择：Case 8 在 hook 可用时执行真实 DNS 解析 e2e；hook 不活跃或无法确认时直接 `BLOCKED(77)`，并输出 `dev/dev-netd-resolv.sh status|prepare` 提示。
   - 理由：casebook 明确要求真实 resolver 触发路径；但 hook 是环境前置，不满足时不能误报 PASS 或产品 FAIL。
   - 备选：继续仅文档记录；拒绝（用户要求把 `## 域名` 下 case 完善补全落实到测试中）。

4) **以 unique test data + restore 代替全局 RESETALL**
   - 选择：每个 case 生成唯一 domain/listId/rule pattern，并保存原始 config/policy/rules，结束后恢复。
   - 理由：`RESETALL` 会影响脚本前后状态且可能掩盖 restore 问题；unique data 可减少历史状态干扰。
   - 备选：每条 case 前后 `RESETALL`；拒绝（破坏性更大，不利于定位污染来源）。

5) **stream 测试使用独立连接与严格事件过滤**
   - 选择：stream helper 在独立 vNext 连接中等待 `notice.started`，按 uid+domain+case token 过滤事件，并在 `STREAM.STOP` 后确认 stop 成功。
   - 理由：避免 ring replay 或后台 DNS 事件误判；也便于 Case 4 验证 suppressed notice。
   - 备选：复用普通 `sucre-snort-ctl` 单次命令；拒绝（无法稳定读取异步 stream frame）。

6) **bucket 级 metrics 作为核心断言**
   - 选择：新增 helper 对 `METRICS.GET(name=traffic, app)` 与 `METRICS.GET(name=domainSources, app)` 做 before/reset/after 校验，并断言具体 bucket。
   - 理由：casebook 的缺口集中在“只看 total，不知道命中哪条路径”；bucket 级断言能防止 scope/source 漂移。
   - 备选：只断言 total 增长；拒绝（无法证明 APP、DEVICE_WIDE、FALLBACK、CUSTOM_RULE 路径正确）。

## Risks / Trade-offs

- [Case 8 环境依赖强，可能频繁 BLOCKED] → Mitigation：将 hook 状态检查和修复提示做成前置；只有 hook 就绪后才执行行为断言。
- [Domain state 污染导致后续 case 误判] → Mitigation：每条 case 使用唯一域名/listId/rule pattern，并在 finally/cleanup 阶段恢复 config、policy、rules、lists。
- [后台 DNS 或 stream replay 干扰事件匹配] → Mitigation：使用 unique domain token、`horizonSec=0`、uid/domain 双过滤，并在必要时先 stop 旧 stream。
- [脚本过长、helper 重复] → Mitigation：只抽取 vNext smoke 通用 helper 到 `tests/integration/lib.sh`；不引入 legacy helper。
- [真实 resolver 触发命令在部分设备不可用] → Mitigation：明确 shell uid=2000 最小路径，并在无法启动解析命令时报告 `BLOCKED`，不伪造成功。

## Migration Plan

- 先补测试 helper，再按 Case 1–9 逐步接入 `vnext-baseline.sh`，每组 case 保持独立 check id。
- 文档更新必须和 check id 同步，确保 casebook 的“现有覆盖/缺口”能回查到测试。
- 若新增 case 导致设备前置不足，使用 `BLOCKED(77)` 保持与 DX smoke 语义一致。

## Open Questions

- 无。Case 1–9 的目标口径以 `docs/testing/DEVICE_SMOKE_CASEBOOK.md` `## 域名` 为准。
