## 1. IPRULES 权威契约同步（mk2 / family / ipv6 / byFamily）

- [x] 1.1 更新 `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`：将 `matchKey` 从 mk1 升级为 mk2（mk2 含 `family`，字段顺序按双栈纲领固定），并更新所有示例中的 `matchKey`
- [x] 1.2 更新 `IPRULES.PRINT/APPLY` schema：Rule 增加 `family:"ipv4"|"ipv6"` 且必填；`proto` 扩展为 `any|tcp|udp|icmp|other`；`src/dst` 支持 IPv6 CIDR（拒绝 `%zone`）；`icmp/other` 强制 `sport/dport=any`
- [x] 1.3 更新 `IPRULES.PREFLIGHT` schema：增加 `result.byFamily.ipv4/ipv6`（两项都必须存在；字段集 mirror `summary`；并写清 `ctUidsTotal` 可能不满足简单相加）

## 2. Observability 权威文档同步（pkt l4Status）

- [x] 2.1 更新 `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`：为 `type="pkt"` 事件增加 `l4Status`（always-present）与枚举 `known-l4|other-terminal|fragment|invalid-or-unavailable-l4`
- [x] 2.2 更新 pkt 端口口径：端口不可用时 `srcPort/dstPort` 仍为 always-present number 但输出 `0`，并要求由 `l4Status` 解释（而非端口 0 规则命中）
- [x] 2.3 更新 `protocol=other` 解释口径：前端必须结合 `l4Status=other-terminal` 判断“合法 other terminal”，不得仅凭 `protocol=other` 推断

## 3. Checklist 对齐（最小改动）

- [x] 3.1 更新 `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`：将 checklist 内仍引用 `matchKey mk1` 的表述改为 mk2（仅做对齐，不扩写无关段落）

## 4. OpenSpec delta specs 自检（本 change 目录内）

- [x] 4.1 校对 `specs/control-vnext-iprules-surface/spec.md`：覆盖 `PREFLIGHT.byFamily`、Rule `family`、以及 mk2（含移除 mk1 requirement + 新增 mk2 requirement）
- [x] 4.2 校对 `specs/pktstream-observability/spec.md`：覆盖 `l4Status` always-present + 非 `known-l4` 时端口为 0
- [x] 4.3 校对 `specs/conntrack-observability/spec.md`：覆盖 `METRICS.GET(name=conntrack).byFamily.ipv4/ipv6` 形状与字段集合

## 5. 验收与护栏

- [x] 5.1 文件白名单检查：`git diff --name-only` 仅允许变更以下 6 个权威文件 + 本 change 目录文件  
       - `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`  
       - `openspec/specs/control-vnext-iprules-surface/spec.md`  
       - `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`  
       - `openspec/specs/pktstream-observability/spec.md`  
       - `openspec/specs/conntrack-observability/spec.md`  
       - `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`
- [x] 5.2 文档口径自检：`rg -n \"\\bmk1\\b\" docs/decisions/DOMAIN_IP_FUSION --glob '!docs/decisions/DOMAIN_IP_FUSION/archive/**'`（权威文件不得残留 mk1 口径）
- [x] 5.3 OpenSpec 校验：`openspec validate --type change sync-iprules-dual-stack-authority-docs` 通过；并分别 `openspec validate --type spec control-vnext-iprules-surface`、`openspec validate --type spec pktstream-observability`、`openspec validate --type spec conntrack-observability` 通过
