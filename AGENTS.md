
## Roadmap Reference

- 当前实现顺序、阶段现状与边界说明统一记录在 `docs/IMPLEMENTATION_ROADMAP.md`

## Build Guardrails

- `snort-build-regen-graph`（Soong/Blueprint 全图重建）非常耗时（>= 50 分钟）。除非本次改动**包含** `Android.bp` 变更，否则不得运行该 target。
