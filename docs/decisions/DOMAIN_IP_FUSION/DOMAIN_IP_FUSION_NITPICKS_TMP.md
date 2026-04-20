# Domain + IP Fusion：挑刺清单（仅保留未落盘项）

更新时间：2026-04-20  
状态：非规范性（仅用于找茬/去复杂化；逐条回复用）

> 规则（已确认）：本文件只列**尚未落盘**的 open issues。  
> 已确认裁决请以单一真相为准：
> - `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
> - `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
> - `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`
> - `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`

---

## 0. 提醒（不需要裁决，但实现期容易踩坑）

- strict reject 扩展性：全局 `args` 未知 key → `SYNTAX_ERROR` 很干净；未来若要灰度字段，可能需要一个明确的 `ext{}` 容器或版本协商规则。  
- stream：只限制订阅，不限制 control 并发连接（避免实现时偷懒成“整个 control socket 单连接”）。

---

## 1. Open issues（请逐条回复）

### 1.1 `DOMAINLISTS.APPLY`：订阅字段的更新语义（patch vs replace）

要写入的位置：
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md` → `DOMAINLISTS.APPLY`（`upsert[]` item 的订阅字段语义）

问题（必须钉死，否则实现/前端会互相踩）：
- `upsert[]` 中 `url/name/updatedAt/etag/outdated/domainsCount` 是否必填？
- 是否允许只更新其中部分字段（其余保持不变）？

选项（选一个并写死）：
- A（推荐）：**patch 语义**  
  - `listId/listKind/mask/enabled` 必填；订阅字段全可选，未提供=保持旧值。  
  - 创建新 list 时订阅字段默认：`url/name/etag/updatedAt=""`、`domainsCount=0`、`outdated=1`。  
- B：**replace 语义**  
  - upsert 时订阅字段必须全量携带；缺失即 `INVALID_ARGUMENT`（前端需先 GET 再完整回写）。  
- C：拆分命令  
  - `DOMAINLISTS.APPLY` 只管执行配置；新增 `DOMAINLISTS.META.SET` 专门更新订阅字段（命令面变多）。

