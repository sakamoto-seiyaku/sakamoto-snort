# Change: vNext control codec + `sucre-snort-ctl`

## Why

domain+IP fusion 已经在 `docs/decisions/DOMAIN_IP_FUSION/` 内收敛出 vNext control 的单一真相（netstring + JSON envelope + strict reject + structured errors），但现状控制面仍是 legacy token/NUL 协议（`src/Control.cpp` + `src/SocketIO.cpp`），难以：

- 在 daemon / CLI / tests 三方之间保持一致的 framing 与严格 JSON 语义（尤其是 string escape 与 unknown-key strict reject）。
- 在 vNext 下继续使用 `socat` 人肉调试（netstring 的 `len` 是 byte length，手敲易错且难复现）。

因此需要先落地一个**可复用、可测试**的 vNext codec 基座，并提供一个最小可用的 host CLI（`sucre-snort-ctl`）作为后续切片的统一发送/解析工具，避免后续每个切片各自实现一套 framing/JSON 导致漂移与返工。

## What Changes

- 引入并接入 **RapidJSON**（header-only）作为 vNext 严格 JSON parse/encode 的唯一实现（daemon/ctl/tests 共用；禁止手写拼接“看起来像 JSON”的字符串）。
- 新增 **vNext codec 模块**（可复用）：
  - netstring framing：roundtrip、partial read、多帧、header/terminator 校验与错误分类
  - JSON codec：严格 parse/encode（基于 `(char*, len)`；拒绝 trailing garbage；正确 escape 最小集）
  - envelope helpers：`request/response/event` 的结构化读写与 strict reject（unknown key）
- 新增 host C++ 二进制 **`sucre-snort-ctl`**：
  - `--help|help`：输出命令目录/示例（对应裁决：vNext daemon 不提供 `HELP`）
  - 负责打包/解包 netstring + JSON，并对 response/event 做（可选）pretty 输出
  - 支持 tcp 与 unix socket（便于后续 P1/P2 真机与 host 工具链复用）
- 新增 P0 host 单测覆盖 codec 的关键边界（netstring/JSON/envelope 的一致性与拒绝策略）。

## Capabilities

### New Capabilities

- `control-vnext-codec`: Control Protocol vNext 的 shared codec（netstring + strict JSON + envelope + strict reject），供 daemon/ctl/tests 复用。
- `sucre-snort-ctl`: 与 vNext control 协议交互的 host CLI（请求构造、framing、解析、pretty/help）。

### Modified Capabilities

_None._

## Impact

- Affected code (new):
  - vNext codec 新模块（供后续 daemon 切片复用）
  - `sucre-snort-ctl` host 工具
- Affected builds:
  - Android.bp 与 host CMake：接入 RapidJSON include 与新增 host binary/host tests
- Affected tests:
  - `tests/host/` 新增 P0 单测（codec / envelope / strict reject）
- Out of scope (this change):
  - 不实现 vNext daemon listener / endpoints / 命令面（见 Roadmap 下一切片 `add-control-vnext-daemon-base`）

