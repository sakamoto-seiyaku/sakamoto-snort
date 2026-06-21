# Base Runtime 状态报告讨论记录

状态：工作笔记，随 Base Runtime / HELLO health 讨论更新
最后更新：2026-06-21
范围：记录 pre-SNORT-12 base 的 control session、RESETALL、runtime readiness、HELLO capabilities 与 runtime health 语义；不作为实现任务队列
关联：
- `CONTEXT.md`
- `docs/INTERFACE_SPECIFICATION.md`
- `docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md`
- `docs/decisions/RESETALL_RUNTIME_CONCURRENCY.md`

## 使用规则

这份文档只记录当前讨论中已经澄清的语义，以及还没成熟到正式决策文档的中间结论。

约束：
- 不替代 Plane work item。
- 不直接规定 C++ 类图或具体函数签名。
- 不维护 TODO / backlog 队列。
- 已经稳定的术语同步到 `CONTEXT.md`。
- 已经稳定到接口层的内容，后续再同步到 `docs/INTERFACE_SPECIFICATION.md`。
- 未决问题必须标成“待讨论”，不能写成已经决定。

## 背景

`$improve-codebase-architecture` 报告指出 pre-SNORT-12 base 里存在一个 ownership 问题：base runtime readiness、control session 结束、RESETALL clean baseline、process lifecycle 与 HELLO capability 暴露目前混在一起。

当前代码事实：
- `daemon_main.cpp` 调用 `datapath.start()` 后丢弃返回值。
- `DualStackPassThroughRuntime::start()` 会记录 hook install 结果，但仍在启动 listener 后设置 `ready_ = true`。
- `ControlServer` 里的 `QUIT` 当前调用 `SnortRuntime::requestShutdown()`。
- `HELLO.capabilities[]` 当前使用 `"snort10-base"` 与 `"nfqueue-pass-through"`。
- `RESETALL` 当前主要通过 hook reinstall 表达 base reset。

讨论目标不是先做大重构，而是先把状态报告语义定清楚，避免后续实现把开发阶段名称、Implementation 细节或 daemon lifecycle 混进 control protocol。

## 已确认的语义

### `QUIT`

`QUIT` 只表示当前 vNext control session 在响应写出后关闭。

它不是：
- daemon shutdown。
- process stop。
- RuntimeService stop。
- RESETALL。

当前代码把 `QUIT` 用作 daemon shutdown 是语义偏差，后续实现应修正。

### daemon stop / start / restart

真正的 native daemon process stop / start / restart 归 `RuntimeService` 或外部 lifecycle owner 管。

pre-SNORT-12 base 不应新增普通 control command 来表达 shutdown / restart。若外部 owner 要重启 daemon，应直接停进程再启动。

这里的 `RuntimeService` 指 Android-side 前台服务 / app layer 的 daemon lifecycle owner。native daemon 内部的 runtime status report 不拥有 daemon lifecycle，只负责把当前 runtime readiness / error 状态暴露给 lifecycle owner 和 control clients。

### `RESETALL`

`RESETALL` 是状态清理，不是 daemon restart，也不是 process recycle。

长期语义：
- 清 daemon memory state。
- 清 observation/session state。
- 清 configuration state。
- 清 persisted save tree。
- 回到 clean baseline。

pre-SNORT-12 base 当前只有 packet pass-through 这一块 active owner，因此当前 `RESETALL` 只能 reset base-owned packet pass-through state。后续 Module 重新引入后，各自把自己的 reset behavior 挂入完整 reset pipeline。

如果 active runtime owner 不能回到 clean baseline，`RESETALL` response 必须失败，后续 `HELLO.runtimeHealth` 也应反映错误。

### `HELLO.capabilities[]`

`HELLO.capabilities[]` 表示当前可用 runtime capabilities。

它不是：
- build feature list。
- planned module list。
- error channel。
- 开发阶段 / milestone 名称列表。

因此 `"snort10-base"` 这种开发阶段名称不应成为长期 capability 名称。

### capability 名称

当前 base pass-through capability 的长期名称采用：

```text
packet-pass-through
```

不采用：

```text
nfqueue-pass-through
snort10-base
```

理由：
- `packet-pass-through` 是能力名。
- NFQUEUE 是当前 packet capture Adapter / Implementation。
- `snort10-base` 是工程阶段名，不应进入长期 protocol vocabulary。

### `runtimeHealth`

`HELLO` 应包含最小 runtime health。

不另起 `HEALTH.GET`，因为 RuntimeService 与 Device/DX 启动验收的第一步就是 `HELLO`。

第一版状态只使用二态：

```text
ok
error
```

不引入 `degraded` 中间态。

`runtimeHealth` 用于解释 active runtime capability 当前是否可用，以及失败原因。它不替代 metrics、telemetry、Packet Diagnostics 或 daemon lifecycle。

### health reason code

capability 名称应抽象，但 health reason code 可以具体到当前 failing Adapter。

例如：

```text
NFQUEUE_HOOK_INSTALL_FAILED
```

这是诊断信息，不是能力名。未来如果 packet capture Adapter 改变，可以新增新的 Adapter-specific reason。

### dual-stack health

`packet-pass-through` 是双栈能力。

runtime health 需要按 family 拆：

```json
{
  "packet-pass-through": {
    "status": "error",
    "families": {
      "ipv4": { "status": "ok" },
      "ipv6": {
        "status": "error",
        "reason": "NFQUEUE_HOOK_INSTALL_FAILED"
      }
    }
  }
}
```

IPv4 / IPv6 任一 family setup 不可用，整体 `packet-pass-through` 都不 ready，不能进入 `HELLO.capabilities[]`。

Device/DX 可以因为测试环境没有 IPv6 route 而 skip IPv6 traffic smoke；daemon 自己不能把 IPv6 setup 缺失静默当成 ok。

### startup failure behavior

如果 `packet-pass-through` startup 失败，daemon process 可以继续运行 Control Plane，用于报告 `runtimeHealth.error`。

这意味着：
- `HELLO` 可用。
- `HELLO.capabilities[]` 不包含 `packet-pass-through`。
- `HELLO.runtimeHealth.overall = "error"`。
- Device/DX gate fail。
- RuntimeService / 前端可以看到具体 reason。

## 推荐的 HELLO shape 草案

全部 ready：

```json
{
  "protocol": "control-vnext",
  "protocolVersion": 1,
  "capabilities": ["packet-pass-through"],
  "runtimeHealth": {
    "overall": "ok",
    "components": {
      "packet-pass-through": {
        "status": "ok",
        "families": {
          "ipv4": { "status": "ok" },
          "ipv6": { "status": "ok" }
        }
      }
    }
  }
}
```

IPv6 hook setup 失败：

```json
{
  "protocol": "control-vnext",
  "protocolVersion": 1,
  "capabilities": [],
  "runtimeHealth": {
    "overall": "error",
    "components": {
      "packet-pass-through": {
        "status": "error",
        "families": {
          "ipv4": { "status": "ok" },
          "ipv6": {
            "status": "error",
            "reason": "NFQUEUE_HOOK_INSTALL_FAILED"
          }
        }
      }
    }
  }
}
```

## 当前讨论对架构审核建议的修正

原报告中的 “Base Runtime Module” 不应理解成新增大型 framework。

更准确的下一步是：

- 不新增大 Module。
- 不新增 shutdown / restart control command。
- 不引入复杂 health framework。
- 先把现有 boolean readiness 提升为最小 runtime status report。
- ControlServer 只序列化 runtime status，不自己推断 packet pass-through readiness。

## 待讨论

### 0. Control Plane 拆分方向

已确认：不能只按 pre-SNORT-12 当前 3 个命令判断 `ControlServer` 是否需要拆分。后续 SNORT-13 / SNORT-14 / SNORT-15 / SNORT-16 等 Module 会继续把 command families 加回 Control Plane，架构正确性优先于当前代码规模。

方向：`ControlServer` 不应长期同时拥有 socket/session transport、request framing、base command semantics、runtime status serialization 和后续 command family dispatch。

已确认：拆分不采用动态 registry、插件式 command registration 或运行时 discoverable command model。本项目没有把 daemon control commands 做成插件的部署需求；动态注册只会增加复杂度。

方向：采用静态 dispatch。可以把 transport/session 与 command semantics 分开，但 command families 由编译期明确的 dispatcher / helper 组织。

第一步只拆当前真实存在的 meta command semantics 和 control transport：
- `ControlServer` 保留 socket / session / framing / response write。
- `ControlDispatch` 或等价 Module 负责静态 dispatch。
- `ControlMetaCommands` / `ControlBaseCommands` 或等价 helper 负责 `HELLO` / `RESETALL` / `QUIT` / unsupported command。命名不是当前重点。

不提前创建 future command family 空文件。Traffic Windows、Diagnostics、Authoring、Telemetry 等命令族等对应 SNORT Module 回来时再新增自己的静态 dispatch helper。

`QUIT` 分层：
- meta command semantics 决定 `QUIT` 的 session effect 是 `CloseAfterResponse`。
- transport/session 层在 response 写出后执行 close。
- command semantics 不直接 close fd，不触碰 socket。

可以用一个最小 `SessionEffect` 结果表达 `KeepOpen` / `CloseAfterResponse`。这是为当前 `QUIT` 服务，不是 dynamic command framework。

`RESETALL` 分层：
- `RESETALL` 是 Control Plane protocol command。
- command semantics 将 `RESETALL` 映射为“让 active runtime owners 回到 clean baseline”。
- runtime Interface 暴露 clean-baseline reset operation。
- concrete runtime owner 处理自己的 Implementation 细节，例如当前 packet pass-through hooks。
- command semantics 不知道 iptables / NFQUEUE / IPv4 / IPv6 hook 细节。

runtime status serialization：
- runtime owner 返回结构化 status，不返回 JSON。
- Control layer / protocol Adapter 负责把结构化 status 序列化进 `HELLO` JSON。
- runtime owner 不依赖 RapidJSON response shape。

status structure：
- 第一版 C++ 内部不做通用 component map / registry。
- 第一版只表达当前真实状态，例如 `PacketPassThroughStatus` 与 per-family status。
- `HELLO.runtimeHealth.components` 是 protocol JSON shape，不要求 C++ runtime 内部也建通用 registry。

### 1. native daemon 内部的状态报告由谁维护

已确认：daemon lifecycle 由 Android-side `RuntimeService` / 前台服务持有，不由 native daemon 内部状态报告持有。

暂定结论：native daemon 内部用于 `HELLO.runtimeHealth` 的最小 runtime status report 由 active runtime owner 维护。pre-SNORT-12 base 中，这意味着 `DualStackPassThroughRuntime` 维护 `packet-pass-through` 的 readiness / error snapshot，并通过 `RuntimeControl` 暴露给 `ControlServer` 序列化。

约束：限定为小 patch，扩展现有 `RuntimeControl` / `DualStackPassThroughRuntime`，避免新增大抽象。

### 2. listener startup 的 health 边界

已确认：第一版采用宽松 ready，不引入 listener 内部握手、跨线程状态机或 queue configure 成功确认。

第一版 `packet-pass-through` ready 只要求：
- IPv4 hook install ok。
- IPv6 hook install ok。
- listener threads successfully spawned。

第一版不等待 listener thread 内部第一次 queue configure 成功。listener 内部 socket bind / queue configure transient failure 仍由现有 retry / log 路径处理，不进入 `HELLO.runtimeHealth`。

后续如果真机证据证明 listener 内部失败需要进入 health，再另行讨论，不在第一版复杂化。

### 3. RESETALL 的 base-owned state 边界

已确认：第一版 pre-SNORT-12 base 的 `RESETALL` 只 reinstall hooks 并更新 runtime health，不重建 listener / socket state，不新增专门线程，不引入 listener lifecycle coordination。

第一版行为：
- hook reinstall 成功：`RESETALL` 返回 ok，并按 hook 结果更新 `packet-pass-through` health。
- hook reinstall 失败：`RESETALL` 返回 error，并让后续 `HELLO.runtimeHealth` 反映 error。
- listener threads 不 join、不重启、不 recreate。

如果后续真机证据证明 listener / socket state 需要进入 `RESETALL`，再另起讨论；不在第一版复杂化。

### 4. Device/DX gate 更新

已确认：Device/DX gate 仍保留系统侧 hook 规则检查，不只依赖 daemon 自报的 `HELLO.runtimeHealth`。

第一版 gate 应同时检查：
- `HELLO.capabilities[]` 包含 `packet-pass-through`。
- `HELLO.runtimeHealth.overall == "ok"`。
- `HELLO.runtimeHealth.components["packet-pass-through"]` 按 IPv4 / IPv6 family 报 ok。
- `iptables -S` / `ip6tables -S` 中实际存在预期 hook rules。
- traffic smoke 仍按设备环境能力执行；没有 IPv6 route 时可以 skip IPv6 traffic smoke，但不能把 daemon IPv6 setup error 当 ok。

迁移方向：
- 不再断言 `"snort10-base"`。
- 不再断言 `"nfqueue-pass-through"`。
- 改为断言 `"packet-pass-through"` 与 `runtimeHealth`。

### 5. Interface spec 同步

已确认：当前先不改 `docs/INTERFACE_SPECIFICATION.md`。先把其它语义讨论完，再决定何时同步正式接口文档。

后续待同步候选：
- `docs/INTERFACE_SPECIFICATION.md`
- `docs/decisions/SNORT_10_MAINLINE_RECONSTRUCTION.md`
- host control contract tests
- Device/DX base gate

## 已同步到 CONTEXT.md

已同步术语：
- `QUIT`
- `RESETALL`
- `packet-pass-through`
- `HELLO capabilities`
- `Runtime health`
