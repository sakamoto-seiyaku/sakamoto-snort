# DOMAIN_IP_FUSION 目录现状盘点（TMP）

更新时间：2026-04-20  
状态：临时盘点（先“止血”，让讨论重新可控；不直接改动既有规范文本）

> 目标：回答三件事  
> 1) 这个目录现在**到底有什么**（文件清单 + 角色）  
> 2) 哪些内容**重复/重叠**（为什么会失控）  
> 3) 若要“一个文件对应一块内容”，**下一步应如何收敛入口**（只给建议，不执行移动/删除）

---

## 1) 快照：当前文件清单（共 11 个）

> 说明：盘点开始时该目录在 git 上是干净的；当前因为新增本文件而出现 `?? docs/archived/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_FOLDER_INVENTORY_TMP.md`。

- `DOMAIN_IP_FUSION_CHECKLIST.md`（671 行）：主入口/总纲（现状快照 + 目标状态 + 实现拆分 + 索引）
- `CONTROL_PROTOCOL_VNEXT.md`（216 行）：**vNext wire 协议单一真相**（framing/envelope/errors/selector/stream 状态机）
- `CONTROL_COMMANDS_VNEXT.md`（475 行）：**vNext 命令面单一真相**（每个 `cmd` 的 args/result/errors）
- `IPRULES_APPLY_CONTRACT.md`（233 行）：**IPRULES 原子 apply 契约**（matchKey/clientRuleId/冲突错误 shape 等）
- `OBSERVABILITY_WORKING_DECISIONS.md`（512 行）：可观测性工作结论（stream/metrics/tracked 等“语义单一真相”）
- `OBSERVABILITY_IMPLEMENTATION_TASKS.md`（163 行）：可观测性落地任务清单（应当仅派生自 working decisions）
- `DESIGN_PHASE_REMAINING_WORK_TMP.md`（108 行）：设计阶段“还缺什么大块”（元文档/退出条件）
- `DOMAIN_IP_FUSION_NITPICKS_TMP.md`（306 行）：最终挑刺清单（逐条回复用；非规范）
- `DOMAIN_IP_FUSION_AUDIT_TMP.md`（1570 行）：临时审核笔记/裁决日志（含大量历史段落；非规范）
- `DOMAIN_IP_FUSION_DESIGN_REVIEW_TMP.md`（640 行）：方案挑刺/替代方案（含历史方案对比；非规范）
- `CONTROL_VNEXT_SURFACE_SIMPLIFIED_TMP.md`（241 行）：vNext 命令面简化提案（确认后应回写命令目录；非规范）

---

## 2) 现状的“角色分层”（为什么会出现重复）

### 2.1 目录内建议的“单一真相”（规范层）

这些文件应该被实现阶段视为“只认它”的规范来源（同主题别的文档只能当注释/讨论记录）：

- wire/错误模型/selector：`CONTROL_PROTOCOL_VNEXT.md`
- 命令列表/各命令 schema：`CONTROL_COMMANDS_VNEXT.md`
- IPRULES apply 语义：`IPRULES_APPLY_CONTRACT.md`
- stream/metrics/tracked 等观测语义：`OBSERVABILITY_WORKING_DECISIONS.md`

### 2.2 “入口/索引层”

- `DOMAIN_IP_FUSION_CHECKLIST.md` 现在承担了：索引 + 现状快照 + 目标模型 + 实现拆分。  
  这本身合理，但会导致它不可避免地“引用很多讨论文件”，从而让读者产生“好像每份都要读”的错觉。

### 2.3 “讨论/挑刺层”（重复的核心来源）

目前有 **3 份**都在做“挑刺/审阅/裁决记录”，且彼此覆盖面高度重叠：

- `DOMAIN_IP_FUSION_AUDIT_TMP.md`：最全、最大、最像“会议纪要 + 裁决日志”
- `DOMAIN_IP_FUSION_NITPICKS_TMP.md`：更偏“最终挑刺清单”（但里面也包含已吸收记录与部分规范性句子）
- `DOMAIN_IP_FUSION_DESIGN_REVIEW_TMP.md`：更偏“唱反调 + 替代方案”（其中大量内容已被后续裁决覆盖）

再加上 1 份命令面提案：

- `CONTROL_VNEXT_SURFACE_SIMPLIFIED_TMP.md`：与 `CONTROL_COMMANDS_VNEXT.md` 高度重叠（同一主题两份文档并行推进）

=> 这就是你直觉上的“讨论失控”的根因：**同一主题（挑刺/裁决/规范）被拆成多份文档同时承载**。

---

## 3) 重叠/重复点（按主题聚类）

### 3.1 Control vNext：`CONTROL_COMMANDS_VNEXT.md` vs `CONTROL_VNEXT_SURFACE_SIMPLIFIED_TMP.md`

- 重叠：都在描述“vNext 命令面长什么样/怎么简化/怎么分资源”。  
- 风险：实现期开发者/读者可能误把 TMP 当规范（尤其当两份对同一命令的字段细节描述不一致时）。  
- 建议：尽快把 TMP 中仍有价值但尚未回写的内容，合并进 `CONTROL_COMMANDS_VNEXT.md`；合并完成后将 TMP 明确标记为“历史草稿/停止更新”或移入 archive。

### 3.2 “挑刺/裁决记录”：`AUDIT_TMP` vs `NITPICKS_TMP` vs `DESIGN_REVIEW_TMP`

- 重叠：三份都包含（a）已确认裁决摘要、（b）仍需拍板事项、（c）对现有代码/规范的冲突提醒。  
- 风险：  
  - 同一个裁决会在多处出现，后续很容易“改了一处忘了另一处”，产生自相矛盾。  
  - 讨论越久，这三份会越来越像“并行版本”，读者无法判断哪份才是最新。  
- 建议：把“挑刺入口”收敛为 **1 份**（建议保留 `DOMAIN_IP_FUSION_NITPICKS_TMP.md` 作为唯一挑刺清单），其余两份要么：
  - 改成纯历史归档（不再承诺同步/不再出现规范性句子），要么
  - 彻底拆成“裁决日志（只记结论+时间）”和“历史讨论（自由文本）”，避免它们继续像规范。

### 3.3 Observability：`OBSERVABILITY_WORKING_DECISIONS.md` vs `OBSERVABILITY_IMPLEMENTATION_TASKS.md`

- 重叠：同主题（stream/metrics/tracked）。  
- 风险：任务清单如果开始自创新语义，会反向污染“单一真相”。  
- 建议：明确约束：`OBSERVABILITY_IMPLEMENTATION_TASKS.md` 只做“从 decisions 派生的任务切片”，不得新增协议字段/语义。

### 3.4 “设计阶段剩余工作”：`DESIGN_PHASE_REMAINING_WORK_TMP.md` vs checklist 第 3 节

- 重叠：都在回答“还剩哪些大块/如何落地拆分”。  
- 建议（可选）：最终只保留一处作为权威（更倾向 checklist），另一处改为 checklist 的摘录/链接（避免两处同时更新）。

---

## 4) 收敛到“一个主题一个文件”的最小目标形态（仅建议）

> 这里不做移动/删除，只给你一个“如果要收敛，应该长什么样”的目标集合。

### 4.1 必留（规范/主入口）

- `DOMAIN_IP_FUSION_CHECKLIST.md`（主入口/索引/拆分）
- `CONTROL_PROTOCOL_VNEXT.md`（规范）
- `CONTROL_COMMANDS_VNEXT.md`（规范）
- `IPRULES_APPLY_CONTRACT.md`（规范）
- `OBSERVABILITY_WORKING_DECISIONS.md`（规范）
- `OBSERVABILITY_IMPLEMENTATION_TASKS.md`（派生任务）

### 4.2 可留（元文档）

- `DESIGN_PHASE_REMAINING_WORK_TMP.md`（如果你希望“跳出细节”时有一张地图；否则可合并回 checklist）

### 4.3 建议收敛/归档（避免重复入口）

- 只保留 1 个“挑刺入口”（建议：`DOMAIN_IP_FUSION_NITPICKS_TMP.md`）
- 其余作为历史归档候选：
  - `DOMAIN_IP_FUSION_AUDIT_TMP.md`
  - `DOMAIN_IP_FUSION_DESIGN_REVIEW_TMP.md`
  - `CONTROL_VNEXT_SURFACE_SIMPLIFIED_TMP.md`（当其内容已被回写后）

---

## 5) 你接下来只需要确认的 3 个“目录治理”问题

1) **挑刺入口**：是否确认只保留 `DOMAIN_IP_FUSION_NITPICKS_TMP.md` 作为唯一挑刺清单？  
2) **历史归档**：是否接受把 `*_TMP.md` 中“已被裁决覆盖/已回写到单一真相”的部分视为历史，不再维护同步？  
3) **归档形式**：你更偏好哪种做法（只选一种即可）：
   - A：保留文件名不动，但在文件顶部加醒目声明“ARCHIVE/停止更新/不得当规范”；  
   - B：移动到 `docs/archived/DOMAIN_IP_FUSION/archive/`（更彻底，读者不容易误读）；  
   - C：把历史全部合并成一个 `HISTORY.md`，只保留单文件入口。
