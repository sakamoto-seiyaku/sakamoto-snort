
## Roadmap Reference

- 当前实现顺序、阶段现状与边界说明统一记录在 `docs/IMPLEMENTATION_ROADMAP.md`

## Build Guardrails

- NDK daemon release / validation 使用 `bash dev/dev-build-ndk.sh` 或 CMake target
  `snort-build-ndk`；这条路径不依赖 Android source tree，也不需要 Soong graph rebuild。
- `snort-build-regen-graph` 只属于 legacy Soong/Blueprint 路径，仍然非常耗时
  （>= 50 分钟）。除非本次改动**包含** `Android.bp` / Soong graph 变更，或者用户明确要求验证
  legacy Soong 路径，否则不得运行该 target。
