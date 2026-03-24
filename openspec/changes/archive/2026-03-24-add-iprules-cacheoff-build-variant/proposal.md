# Change: DEV-only cache-off build variant for IPRULES decision cache

## Why

我们需要一条“诊断通道”，用于在真机上把 rule-eval 的成本放大（尤其是评估规则规模 2K/4K 时），从而更容易观察到算法/数据结构/实现细节的改动对性能的影响。

同时我们也接受现实：当决策缓存有效时，cache-on 的 baseline 可能只差几个百分点，这是“真实热路径”正常现象；不应为了拉开差距而过度扭曲 baseline 的流量模型。

但我们也要坚持原则：**热路径上尽量不新增任何 per-packet 判断成本**。因此这里不做运行时 toggle，而是提供一个 **DEV-only 的 cache-off 二进制变体**，通过部署/重启切换二进制来选择模式。

## What Changes

- 构建系统一次产出两份二进制：
  - `sucre-snort`：默认产物（决策缓存启用；行为与当前一致）
  - `sucre-snort-iprules-nocache`：DEV-only 诊断产物（决策缓存禁用）
- 影响范围（当前）：仅影响 `IpRulesEngine::evaluate()` 内部的 per-thread 决策缓存（thread-local cache）
- 选择方式：由部署脚本选择推送哪份二进制并重启进程（无运行时开关；不持久化）

## Non-Goals

- 不改变任何规则语义（ALLOW/BLOCK/WOULD_BLOCK/NOMATCH）与统计语义；只改变是否使用决策缓存。
- 不覆盖域名/DNS 相关缓存（后续整合 DomainPolicy 时再扩展为全局开关）。
- 不提供复杂参数（per-uid/per-rule/per-proto）——保持一个简单的“二进制变体”即可。

## Impact

- 影响文档：
  - `docs/testing/ip/IP_TEST_MODULE.md`（补充 cache-off 诊断的使用方式；baseline v1 仍以 cache-on 为主）
- 影响代码（实现阶段）：
  - `IpRulesEngine`（以编译期宏禁用决策缓存）
  - `Android.bp`（新增 cache-off cc_binary module）
  - `dev/dev-build.sh`（构建并导出两份产物到 `build-output/`）
  - `dev/dev-deploy.sh`（支持选择部署哪份二进制）
  - 相关单元测试与真机测试模组脚本（可选）
