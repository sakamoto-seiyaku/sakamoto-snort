> 目标：落地 observability 的 B 层（DomainPolicy `policySource` counters），以可验收的 spec + tests 作为完成标准。

## 0. Spec & docs sync
- [x] 0.1 补齐/校验 OpenSpec delta：`specs/domain-policy-observability/spec.md`
- [x] 0.2 控制面 help 文本补齐（`HELP` 输出新增命令说明）

## 1. policySource 归因（保持与现状判决等价）
- [x] 1.1 引入 `policySource` 枚举与 string mapping（7 类，顺序固定）
- [x] 1.2 新增 `App::blockedWithSource(domain)`（或等价 API），返回 `{blocked,color,policySource}`，且与 `App::blocked()` 判决等价
- [x] 1.3 `_useCustomList=0` 时 `policySource` 恒为 `MASK_FALLBACK`（不访问其它分支）

## 2. Counters 数据结构（热路径约束）
- [x] 2.1 device-wide counters：固定维度数组（`[policySource][allow|block]`），热路径仅 `atomic++(relaxed)`
- [x] 2.2 per-app counters：固定维度挂在 `App` 生命周期对象上（无 map 插入/分配）
- [x] 2.3 snapshot → JSON 输出（固定 wrapper `{"sources":{...}}`，7 个 key 必须始终出现）

## 3. DNS listener 集成（不依赖 tracked）
- [x] 3.1 在 DNS verdict 已算出后更新 counters（仅 `BLOCK=1`）；不依赖 `DNSSTREAM` 开关与 `tracked`
- [x] 3.2 确认热路径无新增锁/重 IO/动态分配

## 4. 控制面命令（固定 shape + 无副作用读）
- [x] 4.1 新增命令：`METRICS.DOMAIN.SOURCES`
- [x] 4.2 新增命令：`METRICS.DOMAIN.SOURCES.APP <uid|str> [USER <userId>]`
- [x] 4.3 新增命令：`METRICS.DOMAIN.SOURCES.RESET`
- [x] 4.4 新增命令：`METRICS.DOMAIN.SOURCES.RESET.APP <uid|str> [USER <userId>]`
- [x] 4.5 参数非法 / app 不存在 → `NOK`；只读查询不得创建 app 或引入持久化副作用

## 5. RESET 语义（严格边界）
- [x] 5.1 `...RESET*` 在控制面使用 **exclusive** `mutexListeners` quiesce（或等价 epoch/bank swap）保证严格 reset 边界
- [x] 5.2 `RESETALL` 同时清空 domain sources counters

## 6. Tests（完成标准）
- [x] 6.1 host/unit：policySource 优先级与 `_useCustomList` 分支覆盖
- [x] 6.2 host/unit：device-wide/per-app JSON shape、keys 常驻、`tracked=0` 仍增长、`BLOCK=0` 不增长
- [x] 6.3 integration：控制命令闭环（触发 DNS 判决 → counters 增长 → RESET → 归零）

## 7. Validation
- [x] 7.1 `openspec validate add-domain-policy-observability --strict`
- [x] 7.2 `cmake --build` + `ctest`（host tests 全绿）
- [x] 7.3 运行必要的 `tests/integration/*`（至少覆盖新增命令）
