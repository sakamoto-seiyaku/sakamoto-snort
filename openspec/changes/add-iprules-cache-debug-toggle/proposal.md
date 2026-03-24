# Change: DEV-only toggle for IPRULES decision cache

## Why

我们需要一条“诊断通道”，用于在真机上把 rule-eval 的成本放大（尤其是评估规则规模 2K/4K 时），从而更容易观察到算法/数据结构/实现细节的改动对性能的影响。

同时我们也接受现实：当决策缓存有效时，cache-on 的 baseline 可能只差几个百分点，这是“真实热路径”正常现象；不应为了拉开差距而过度扭曲 baseline 的流量模型。

因此需要引入一个 **DEV-only** 的 debug 开关，用于对 **IPRULES**（当前阶段仅 IP）禁用/启用 hot-path 决策缓存，作为 perf 诊断手段。

## What Changes

- 新增控制命令：`DEV.IPRULES.CACHE [<0|1>]`
  - 无参数：查询当前值（`0|1`）
  - 有参数：设置开关；仅接受 `0|1`；`1→1/0→0` 幂等
  - 默认值：`1`（启用缓存）
  - **不持久化**（进程重启后回到默认值）
- 影响范围（当前）：仅影响 `IpRulesEngine::evaluate()` 内部的 per-thread 决策缓存（thread-local cache）
- 权限：DEV-only；仅 `root(0)` / `shell(2000)` 可调用（与 `DEV.SHUTDOWN` 同级约束）

## Non-Goals

- 不改变任何规则语义（ALLOW/BLOCK/WOULD_BLOCK/NOMATCH）与统计语义；只改变是否使用决策缓存。
- 不覆盖域名/DNS 相关缓存（后续整合 DomainPolicy 时再扩展为全局开关）。
- 不提供复杂参数（per-uid/per-rule/per-proto）——保持一个简单开关即可。

## Impact

- 影响文档：
  - `docs/INTERFACE_SPECIFICATION.md`（新增 DEV 命令说明）
  - `docs/testing/ip/IP_TEST_MODULE.md`（补充诊断用法，非 baseline 必跑）
- 影响代码（实现阶段）：
  - 控制面命令解析与权限检查
  - `IpRulesEngine` hot-path evaluate
  - 相关单元测试与真机测试模组脚本（可选）

