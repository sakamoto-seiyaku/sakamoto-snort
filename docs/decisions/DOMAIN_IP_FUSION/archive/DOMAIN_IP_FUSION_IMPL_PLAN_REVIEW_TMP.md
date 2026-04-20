# domain+IP fusion：vNext control 落地计划审计（实现可行性 + Roadmap 对齐）

更新时间：2026-04-20  
状态：临时审计结论（归档目录；不作为“单一真相”）

> 目的：把 `docs/decisions/DOMAIN_IP_FUSION/*`（单一真相）与 `docs/IMPLEMENTATION_ROADMAP.md`（切片/gate）以及当前代码/测试基线对齐，提前指出“实现会卡死/测不了/会返工”的硬问题，并把修复动作落到 Roadmap 文本中。  
> 注意：本文不复审 `archive/` 下历史讨论；以本目录非归档文件为设计真相输入。

## 0. 输入材料（本次对齐用到的真相/事实）

设计真相（vNext 单一真相）：
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`
- `docs/decisions/DOMAIN_IP_FUSION/OBSERVABILITY_WORKING_DECISIONS.md`
- `docs/decisions/DOMAIN_IP_FUSION/IPRULES_APPLY_CONTRACT.md`
- `docs/decisions/DOMAIN_IP_FUSION/DOMAIN_IP_FUSION_CHECKLIST.md`

实现计划（切片与 gate）：
- `docs/IMPLEMENTATION_ROADMAP.md`（章节 `3.2.1`）

当前代码/测试基线事实（作为可落地性约束）：
- legacy control：token + NUL terminator：`src/Control.cpp:415` / `src/SocketIO.cpp:27`
- P1 集成测试当前只会发 legacy：`tests/integration/lib.sh:65`
- adb forward 当前硬编码到 legacy socket：`dev/dev-android-device-lib.sh:108`
- dataplane 控制面豁免当前只按 `controlPort=60606`：`src/PacketListener.cpp:351` / `src/Settings.hpp:133`
- init.rc 当前只声明 legacy socket：`sucre-snort.rc:9`

## 1. 结论（TL;DR）

- **设计侧自洽**：vNext 的 wire/envelope/errors/selector/命令面/可观测性边界，当前在 `docs/decisions/DOMAIN_IP_FUSION/` 内已形成单一真相；未发现“实现不了/实现后自相矛盾”的根本性问题。
- **实现计划侧需要补齐工程与测试底座**：目前 Roadmap 3.2.1 的切片描述与“单一真相”/现有测试基线存在几处硬冲突或缺口；若不先修正文档并把测试底座放进早期切片，实现会在 P1/P2 卡死或被迫返工。

本轮审计认为最关键的修订点如下（按严重度）：

### S5（必须修，不然做不下去/测不了）

1) **daemon v1 不提供 `HELP`（help 由 CLI 承担）**  
   - 设计真相：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md:73`  
   - 影响：Roadmap slice2 若仍以 `HELLO/HELP` 为最小集合，会把 P1 baseline 写死到一个不存在的命令上。

2) **缺少 vNext 的“真机可用发送栈”与 forward 机制**  
   - 事实：P1/P2 的 shell test 目前只支持 legacy NUL：`tests/integration/lib.sh:65`；forward 也固定到 legacy：`dev/dev-android-device-lib.sh:108`  
   - 影响：后续 domain/iprules/metrics/stream 任意切片都会被“无法稳定发 request/解析 response/event”卡住。

### S4（不修会出现“自锁/路径分叉/热路径遗漏”）

3) **60607（vNext TCP）与 dataplane 豁免必须联动**  
   - 设计真相：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md:20`（inetControl 开启时豁免 60606 + 60607）  
   - 事实：当前只豁免一个端口：`src/PacketListener.cpp:351`  
   - 影响：BLOCK=1 + inetControl=1 的环境里，vNext TCP 控制面可能被自己 blocking 干扰，导致“控制面不可用”。

4) **vNext unix socket 的生产路径需要 init.rc 或稳定 fallback**  
   - 设计真相：vNext unix socket 名称已锁死：`sucre-snort-control-vnext`（filesystem + abstract）。  
   - 事实：`sucre-snort.rc:9` 只声明 legacy socket。  
   - 影响：若只在 dev/test 下用 fallback 跑通，容易让“生产路径”与“开发路径”分叉（后续排障成本巨大）。

### S3（不修会导致形态漂移/返工）

5) **JSON parse/encode 的实现策略必须在最早切片锁死并复用**  
   - 设计真相：严格 JSON + strict reject + structured errors 是 vNext v1 的硬约束。  
   - 事实：repo 当前没有内置 JSON 库（`rg nlohmann|rapidjson|simdjson|yyjson` 为空）。  
   - 影响：若 daemon/ctl/tests 三方各自实现 encode/decode，必然漂移（尤其在 string escape 与 unknown-key strict reject 上）。

## 2. 本轮建议的 Roadmap 修订（落到 `docs/IMPLEMENTATION_ROADMAP.md`）

> 说明：下面各条均已作为“切片交付物/验收 gate”的**显式任务**回写到 Roadmap（见 `docs/IMPLEMENTATION_ROADMAP.md:82` 起的 3.2.1 小节），避免仅停留在审计文档里。

### 2.1 Slice2：从“daemon hello/help”改为“daemon 基座（Meta+Inventory+Config）”

原因：
- vNext v1 **不提供 daemon HELP**，help 属于工具人机工程，应在 `sucre-snort-ctl` 上提供（设计已确认）。  
- 仅做 `HELLO` 会导致后续切片在 P1/P2 无法建立“最低可用控制面”；Inventory/Config 是几乎所有后续功能（domain/iprules/observability）都需要的基础能力。

落地要求（最终应体现在切片交付物里）：
- 命令集最小闭环必须包含：
  - Meta：`HELLO/QUIT/RESETALL`
  - Inventory：`APPS.LIST/IFACES.LIST`
  - Config：`CONFIG.GET/CONFIG.SET`
- 仍然遵守：不讨论/不实现 `PASSWORD/PASSSTATE` 等健全项（defer）。

### 2.2 P1/P2：明确“两条连接路径都要测”

你已选择“两条都测”：
- P1 baseline：优先走 **unix abstract**（adb forward 到 `localabstract:sucre-snort-control-vnext`），覆盖 `HELLO + inventory/config`。
- P2：补齐 **tcp:60607** 覆盖（inetControl gating + dataplane 豁免），并在 `BLOCK=1` 场景下验证控制面不会自锁。

因此 Roadmap 需要明确把下列“工程底座”纳入早期切片：
- `dev/dev-android-device-lib.sh`：forward 目标需支持 vNext socket（而不是固定 legacy）。
- `tests/integration/lib.sh`：需要新增 vNext baseline 的发送/解析能力（推荐走 `sucre-snort-ctl`，避免另写一套 Python framing）。

### 2.3 JSON：选型 RapidJSON 并在 Slice1 锁死

你已裁决 vNext JSON 库选型为 RapidJSON。Roadmap 应把它写成实现约束：
- 使用成熟库（RapidJSON）完成严格 parse/encode；禁止手写拼接 JSON 字符串。
- JSON codec（parse/encode）与 netstring framing 必须抽成可复用模块，daemon/ctl/tests 共用，避免漂移。

### 2.3.1 RapidJSON 实现建议（最小且稳）

落地时建议把“协议要求”直接固化为 codec 层的约束（避免散落在各个 handler 里）：
- parse：基于 `(char*, len)` 解析（不要依赖 NUL）；解析后必须满足“顶层是 object”；必须拒绝尾随垃圾字节（trailing bytes）。
- strict reject：把“unknown key = `SYNTAX_ERROR`”做成通用逻辑（顶层/args 都一致），避免每个命令各写一份。
- 错误定位：parse/type error 时至少保留 error code + message；可选把 parse error offset 写进 hint（便于前端/CLI 定位输入问题）。
- encode：统一使用 RapidJSON writer 输出 compact JSON，确保字符串 escape 正确（禁止 `std::stringstream` 手拼）。
- 复用：把 `netstring + json` 的“读一帧/写一帧”封成一套接口，daemon/ctl/tests 共用同一实现与测试向量。

## 3. 额外一致性提醒（不阻塞，但应在实现期注意）

- 现有集成测试脚本（legacy）包含 `HELP` case：`tests/integration/run.sh` 的 `IT-02`。  
  vNext 落地后，P1 baseline 需要新增 vNext case（而不是复用 legacy case 的 `HELP` 语义）。
- dataplane 的 control 端口豁免目前只支持单端口常量；引入 60607 后建议把“豁免端口集合”显式化（例如 `{60606,60607}`），避免未来再次漏掉。

## 4. Defer（本审计明确不推进/不要求）

与“健全/安全/鉴权/发布 gate”相关的内容（包括 60607 暴露策略、token/password 等）在本阶段一律 defer：  
Roadmap 只需保留“defer 边界说明”，不应把它混入 vNext v1 的切片验收门槛。
