## Context

本 change 对应 `docs/IMPLEMENTATION_ROADMAP.md` 的切片 **3.2.1(1)**：`add-control-vnext-codec-ctl`。  
vNext control 的协议与命令面已经在 `docs/decisions/DOMAIN_IP_FUSION/` 内形成单一真相：

- wire framing / JSON envelope / strict reject / errors / selector：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
- 命令目录（v1）：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`

当前代码仍是 legacy control（token + NUL terminator + `OK/NOK`），并且 repo 内尚未有统一 JSON codec/netstring codec。  
如果在 daemon / ctl / tests 各自实现一套 framing/JSON，将极易在 string escape、unknown-key strict reject、以及边界行为上发生漂移。

本 change 的定位是：先落地一个**可复用、可单测**的 vNext codec，并提供 `sucre-snort-ctl` 作为统一的人机交互与脚本工具；daemon vNext listener/命令面落地在后续切片完成。

## Goals / Non-Goals

**Goals:**
- 提供可复用的 vNext codec（netstring + strict JSON + envelope helpers），供 daemon / `sucre-snort-ctl` / tests 共享。
- 以 RapidJSON 实现严格 JSON parse/encode，杜绝手写拼接字符串导致的 escape/一致性问题。
- 提供 host CLI：`sucre-snort-ctl`，负责 request/response/event 的打包解包与（可选）pretty 输出，并提供 `--help|help`。
- 提供 P0 host 单测覆盖 framing/JSON/envelope 的关键边界（partial read、多帧、错误分类、unknown-key strict reject、字符串 escape）。

**Non-Goals:**
- 不实现 vNext daemon listener / endpoints（unix socket / tcp:60607），不实现 vNext 命令 handlers（这些属于下一切片 `add-control-vnext-daemon-base`）。
- 不修改 legacy control 协议、legacy 命令面或其测试基线。
- 不引入鉴权/权限模型或发布 gate（设计已 defer）。

## Decisions

1) **Codec 以“纯 C++、无 Android 依赖”的方式实现**  
   - codec 必须能同时被 host 单测与未来 Android daemon 复用，因此避免依赖 `cutils`、`android_get_control_socket` 等 Android-only API。

2) **netstring parser 采用增量状态机 + 上限保护**  
   - 以内部 buffer + 状态机支持：
     - header 分片（digits/`:`）与 payload 分片（partial read）
     - 一次 feed 多帧
   - 由调用方传入 `maxFrameBytes`（或 request/response 的不同上限）以防止 OOM/DoS。

3) **JSON parse/encode 全部走 RapidJSON**  
   - parse：基于 `(char*, len)`，不依赖 NUL；拒绝非 object 顶层；拒绝 trailing garbage（允许末尾 whitespace）。
   - encode：统一走 Writer/PrettyWriter；严禁 `std::stringstream` 手拼 JSON。

4) **Envelope helpers 负责结构化校验与 strict reject**  
   - 提供 request/response/event 的：
     - 必选字段校验（`id/cmd/args`、`id/ok/result|error`、`type` 等）
     - 类型校验（u32/string/object/bool）
     - strict reject：unknown key → `SYNTAX_ERROR`
   - 目标是把“协议不变式”固化在 codec 层，避免未来各个 command handler 分散实现导致不一致。

5) **`sucre-snort-ctl` 是唯一的人机交互入口**  
   - vNext v1 不提供 daemon `HELP`；`sucre-snort-ctl --help|help` 必须能输出命令目录/示例与常见错误解释（至少覆盖 v1 命令集合）。
   - 连接方式支持 unix socket 与 tcp，便于 host/mock、以及后续真机/ADB 转发场景复用。
   - `sucre-snort-ctl` 主进程应忽略 `SIGPIPE`（与 daemon 保持一致），避免 peer 先断开时 `write()` 直接终止进程。

6) **测试策略：先把 codec 单测做扎实，再做最小 mock roundtrip**  
   - P0 单测覆盖所有“最容易漂移或踩坑”的不变式：netstring、JSON escape、strict reject、envelope 互斥规则。
   - 提供一个最小 mock server（host-only）用于验证 `sucre-snort-ctl` 的端到端 framing（构造 request → server 回 response → CLI 正确解包/pretty）。

## Risks / Trade-offs

- [Risk] framing/JSON 的边界行为一旦漂移会导致后续每个切片返工  
  → Mitigation：daemon/ctl/tests 强制复用同一 codec，并用 host P0 单测锁住边界与错误分类。

- [Risk] netstring len 上限若配置不当可能导致 OOM 或误杀正常大输出  
  → Mitigation：codec 强制 `maxFrameBytes` 硬上限；并在后续 daemon 切片通过 `HELLO` 回显上限以便客户端预检。

- [Risk] CLI 输出格式不稳定影响脚本与 diff  
  → Mitigation：提供 compact JSON（稳定机器读）与 pretty（人类读）两种输出模式，并在 help 中明确默认行为。
