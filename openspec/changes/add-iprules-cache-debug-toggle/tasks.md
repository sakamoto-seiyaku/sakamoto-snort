## 0. OpenSpec docs
- [ ] 0.1 写清 `proposal.md` / `tasks.md` /（可选）`design.md`
- [ ] 0.2 增加 capability spec delta：`specs/app-ip-l3l4-rules/spec.md`
- [ ] 0.3 `openspec validate add-iprules-cache-debug-toggle --strict` 通过

## 1. Control-plane command
- [ ] 1.1 新增命令 `DEV.IPRULES.CACHE [<0|1>]`（query/set；仅接受 `0|1`；幂等）
- [ ] 1.2 权限：仅 `root(0)` / `shell(2000)` 可调用；否则 `NOK`
- [ ] 1.3 文档：更新 `docs/INTERFACE_SPECIFICATION.md` 的命令表与解释

## 2. Engine behavior (IP only)
- [ ] 2.1 `IpRulesEngine` 增加“是否启用决策缓存”的运行时状态（默认 `1`）
- [ ] 2.2 `evaluate()`：cache=0 时 bypass thread-local cache（每次都走 `snap->evaluate()`）
- [ ] 2.3 cache toggle 的并发语义明确且安全（不崩溃、不悬空 stats 指针；允许边界上出现少量不确定性但不得破坏判决语义）
- [ ] 2.4 复核 hot-path 影响：cache=1 的情况下新增开销应尽量可忽略（例如固定分支预测）

## 3. Tests
- [ ] 3.1 新增/更新单元测试：命令解析与幂等语义（非法参数→`NOK`）
- [ ] 3.2 新增/更新单元测试：cache=0/1 两种模式下判决语义一致（同一组规则与输入 key）
- [ ] 3.3 （可选）增加回归测试：切换 cache 后仍能稳定 observe stats（不 crash）

## 4. Real-device module (optional wiring)
- [ ] 4.1 `tests/device-modules/ip/` 增加一个可选 knob（env/flag 均可），用于在 perf/profile 里设置 `DEV.IPRULES.CACHE=0`
- [ ] 4.2 `docs/testing/ip/IP_TEST_MODULE.md` 记录何时使用 cache-off（诊断）与默认 baseline（cache-on）的区别

