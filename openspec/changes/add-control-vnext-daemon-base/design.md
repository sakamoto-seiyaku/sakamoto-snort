## Context

本 change 对应 `docs/IMPLEMENTATION_ROADMAP.md` 的切片 **3.2.1(2)**：`add-control-vnext-daemon-base`。  
vNext control 的协议/命令面单一真相已收敛于：

- endpoints / framing / envelope / errors / strict reject：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_PROTOCOL_VNEXT.md`
- v1 命令目录与契约：`docs/decisions/DOMAIN_IP_FUSION/CONTROL_COMMANDS_VNEXT.md`

上一切片已引入 shared codec（`src/ControlVNextCodec.*`）与 host CLI（`sucre-snort-ctl`），并用 host P0 单测锁住 netstring + strict JSON + envelope 边界。当前 daemon 仍只有 legacy control（NUL terminator + `OK/NOK`），因此真机上无法执行 vNext `HELLO/APPS.LIST/CONFIG.GET` 等最小闭环，也无法建立 vNext 的 integration 基线。

约束（来自 roadmap 与决策文档）：
- vNext 与 legacy control 必须并存；本切片不讨论下线与发布 gate。
- v1 阶段不引入鉴权/权限模型；安全边界先依赖现有 `inetControl()` gating 与部署策略。
- vNext I/O **不得**复用 legacy 的 `SocketIO::print()`（legacy 语义会写入 NUL terminator）。

## Goals / Non-Goals

**Goals:**
- 在 daemon 落地 vNext listener（unix socket + tcp 60607）与 v1 最小命令集（Meta/Inventory/Config）。
- daemon 侧强制复用 shared codec：netstring framing、strict JSON、envelope 校验与 strict reject。
- 明确并实现 vNext I/O 边界与硬上限：`maxRequestBytes/maxResponseBytes`，`len > maxRequestBytes` 立即断连。
- 建立可回归的工程底座：dev adb forward + integration baseline（复用 `sucre-snort-ctl`）。

**Non-Goals:**
- 不实现 vNext domain/iprules/metrics/stream handlers（这些属于后续切片）。
- 不变更 legacy control 协议/命令面或其 integration 基线。
- 不引入通用分页/分块/游标协议；超大 payload 由后续命令面定义命令级上限与分批策略。

## Decisions

1) **vNext daemon 与 legacy Control 分离为独立模块**
   - 选择：新增 `ControlVNext`（或同等命名）负责 vNext sockets + session loop + 命令 dispatch。
   - 理由：legacy I/O、命令解析与线程状态（NUL terminator、token/pretty `!`、stream 行为）与 vNext 的 netstring/JSON 完全不同；混在同一条 loop 极易引入“误写 NUL / framing 混淆”。
   - 备选：在 `Control::clientLoop()` 内按首字节/探测分流（拒绝：复杂且脆弱，错误时会产生不可调试的跨协议误判）。

2) **session I/O 全面复用 `ControlVNextCodec`，并以硬上限防止 OOM/DoS**
   - 选择：每个连接一个 `NetstringDecoder(maxRequestBytes)`；写出统一走 `encodeJson()` + `encodeNetstring()`；对 server→client 输出额外施加 `maxResponseBytes` 保护。
   - 理由：codec 已被 host 单测锁住边界；daemon 只需在其上构建“读帧→parse→dispatch→回帧”。
   - 约束：`len > maxRequestBytes` 必须立即断连（不保证返回 response）；此行为需有 P0 单测覆盖。

3) **Endpoints：production 继承 init socket；dev 模式自动创建 filesystem + abstract**
   - 选择：对 unix socket `sucre-snort-control-vnext`：
     - production：`sucre-snort.rc` 声明 socket，daemon 用 `android_get_control_socket()` 继承 FD
     - dev fallback：无 init socket 时，创建 `/dev/socket/sucre-snort-control-vnext` + `@sucre-snort-control-vnext` 并复用同一 session loop
   - 理由：避免 production/dev 路径分叉导致行为漂移；与 legacy 控制面既有策略一致。

4) **命令 dispatch：显式白名单 + 结构化错误**
   - 选择：对 `cmd` 建立显式 handler map（`HELLO/QUIT/RESETALL`、`APPS.LIST/IFACES.LIST`、`CONFIG.GET/CONFIG.SET`）。
   - 严格性：
     - request 顶层 unknown key：由 `parseRequestEnvelope()` 统一拒绝
     - `args` unknown key：由每个命令 handler 做 strict reject（默认 `SYNTAX_ERROR`）
     - unknown cmd：返回 `UNSUPPORTED_COMMAND`
   - 错误对象：构造 `{"code","message"}`，并按需要附加 `hint/candidates`（对齐 `CONTROL_PROTOCOL_VNEXT.md` 的 error model）。

5) **CONFIG.GET/SET：显式 keys 列表 + 先校验后应用（atomic-ish）**
   - 选择：实现 `key → getter/setter` 映射（仅 v1 keys），对输入做强校验：
     - device keys：`block.enabled/iprules.enabled/rdns.enabled/perfmetrics.enabled/block.mask.default/block.ifaceKindMask.default`
     - app keys：`tracked/block.mask/block.ifaceKindMask/domain.custom.enabled`
   - 行为：同一 `CONFIG.SET` 请求中，必须先校验全部 keys/value/selector；任何一个失败则整体失败（不部分写入）；成功时 last-write-wins（跨连接并发）。

6) **迁移期 dataplane 约束：PacketListener 端口豁免扩展到 60607**
   - 选择：当 `inetControl()` 开启时，PacketListener 同时豁免 `60606`（legacy）与 `60607`（vNext），避免控制流量被 blocking/干扰。
   - 理由：vNext TCP 与 legacy TCP 共存期间必须稳定可用；豁免逻辑属于迁移期硬约束。

## Risks / Trade-offs

- [Risk] vNext 与 legacy I/O 混用导致 framing 混淆（写入 NUL、读帧误判）  
  → Mitigation：模块/loop 分离；vNext 连接不经过 legacy `SocketIO::print()`。

- [Risk] `len > maxRequestBytes` 无法返回带 `id` 的结构化错误（协议限制）  
  → Mitigation：严格按决策文档“立即断连”；记录日志；可选未来增加 `type="notice"` 事件（不在本切片强制）。

- [Risk] CONFIG.SET / RESETALL 并发导致状态不可预期  
  → Mitigation：复用 `mutexListeners` 的 shared/exclusive 约束；对 mutating 命令持有 exclusive lock，语义明确为 last-write-wins。

- [Risk] integration 基线若另写 framing 工具，会与 shared codec 漂移  
  → Mitigation：integration 统一调用 `sucre-snort-ctl`（host C++）与 shared codec。

## Migration Plan

- 本切片只新增 vNext endpoints 与最小命令集；legacy endpoints 保持不变。
- rollout/rollback：可通过禁用/不启用 vNext sockets（或回滚二进制）恢复到 legacy-only 行为；对 dataplane 不引入新裁决链路。

## Open Questions

- `maxRequestBytes/maxResponseBytes` 默认值（实现常量）最终取值；本切片建议先与 `sucre-snort-ctl` 默认 `16MiB` 对齐，后续按真机输出体积再调。
- 是否在 `len > maxRequestBytes` 断连前输出可选 `type="notice"`（排障友好，但会引入“断连前多写一帧”的复杂度）。

