## Context

- 已形成 IPRULES 双栈上位决策输入：`docs/decisions/IPRULES_DUAL_STACK_WORKING_DECISIONS.md`。
- 现状：权威契约文档与 OpenSpec 主规格仍为 IPv4-only（mk1 / 无 family / 无 `PREFLIGHT.byFamily` / pktstream 无 `l4Status` / conntrack metrics 无 byFamily）。
- 约束与偏好：
  - 不改 legacy/LAS 控制面；双栈只走 vNext IPRULES 面。
  - IPv4/IPv6 必须同级，不接受“IPv4 主模型 + IPv6 特例”。
  - 只同步与该议题直接相关的权威文档与 OpenSpec 主规格；无关 doc 不动。
  - 通过 OpenSpec change 固化任务，避免上下文压缩导致漏项；本 change 不实现代码变更。

## Goals / Non-Goals

**Goals:**
- 将“纲领决策”同步到权威契约文档与 OpenSpec 主规格，消除 mk1/IPv4-only 的残留口径。
- 用 delta specs 明确本次对既有 capabilities 的 requirement 变更（mk2/family/byFamily/l4Status）。
- 用 tasks.md 把需要改动的 6 个权威文件与验收自检写成可执行清单，后续按 change 执行。

**Non-Goals:**
- 不实现 `add-iprules-dual-stack-ipv6` 的任何 daemon/ctl/tests 代码变更。
- 不引入新的控制面命令或新的 observability 通道。
- 不做旧 save format 迁移/兼容策略实现（相关口径仅在决策文档中存在；本 change 不落代码）。

## Decisions

1. **单一输入真相**
   - 本 change 的所有同步内容只以 `docs/decisions/IPRULES_DUAL_STACK_WORKING_DECISIONS.md` 为上位输入；权威契约与主规格只做对齐，不重新发明语义。

2. **权威文档/主规格原地更新，不搞 v2 两套真相**
   - 选择直接更新：
     - `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`
     - `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`
     - `openspec/specs/{control-vnext-iprules-surface,pktstream-observability,conntrack-observability}/spec.md`
   - 不另起一套 “v2 contract/spec” 目录以免长期漂移。

3. **把破坏性改动在发布前一次性收口**
   - `family` 变为 IPRULES rule item 的必填字段、`matchKey` 升级为 mk2 属于接口破坏性变更；考虑当前未正式发布，允许在实现前通过文档/规格先行收口并驱动后续实现。

4. **最小 diff 策略**
   - 同步时只改与本议题直接相关的段落与示例（mk1→mk2、补 family/IPv6 CIDR/other/byFamily/l4Status），避免重排章节或改写无关措辞，降低 review 噪音。

5. **delta specs 表达“要求变化”，不复刻整份主规格**
   - change 内的 `specs/**/spec.md` 仅包含新增/修改的 requirements 与 scenarios（按 OpenSpec 的 delta 习惯写 “ADDED Requirements / MODIFIED Requirements”），不复制未变部分。

## Risks / Trade-offs

- [Risk] 权威契约/主规格仍残留 mk1 或 IPv4-only 例子，导致后续实现对错口径不一致  
  → Mitigation：任务中加入 `rg "\\bmk1\\b"` 自检（排除 archive）；并要求 `openspec validate --specs` 通过。

- [Risk] `family`（规则层）与 `ipVersion`（pktstream 事件）两个维度在文档中被混用  
  → Mitigation：在 IPRULES 契约文档只使用 `family=ipv4|ipv6`；pktstream 继续使用既有 `ipVersion:4|6`，并新增 `l4Status` 用于解释端口/协议可用性。

- [Risk] 变更被误扩散到无关 doc（违背“无关 doc 不要动”）  
  → Mitigation：任务中明确允许修改的文件白名单 + `git diff --name-only` 验收门槛。
