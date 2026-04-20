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

（当前为空：本文件只保留“未落盘 open issues”；已确认项已落盘到单一真相文档。）
