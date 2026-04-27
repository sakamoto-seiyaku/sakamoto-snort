## 1. Contract Rename (DomainPolicySource)

- [ ] 1.1 重命名 `src/DomainPolicySources.hpp`：`DomainPolicySource::{GLOBAL_AUTHORIZED,GLOBAL_BLOCKED}` → `{DOMAIN_DEVICE_WIDE_AUTHORIZED,DOMAIN_DEVICE_WIDE_BLOCKED}`（保持原 ordinal/value，不改索引语义）
- [ ] 1.2 更新 `domainPolicySourceStr()`（以及任何静态列表/迭代集合）输出字符串为 `DOMAIN_DEVICE_WIDE_*`

## 2. vNext Output Surfaces

- [ ] 2.1 更新 `src/ControlVNextStreamJson.cpp`：dns stream `policySource` 输出值切换到 `DOMAIN_DEVICE_WIDE_*`（`scope=DEVICE_WIDE` 语义不变）
- [ ] 2.2 更新 `src/ControlVNextSessionCommandsMetrics.cpp`：`METRICS.GET(name=domainSources)` 的 `sources{}` keys 切换到 `DOMAIN_DEVICE_WIDE_*`

## 3. Repo Consumers (Tests / Smoke)

- [ ] 3.1 更新 host tests：`tests/host/domain_policy_sources_tests.cpp` 使用新枚举名与新 key
- [ ] 3.2 更新 vNext integration：`tests/integration/vnext-domain-casebook.py`（含 `policySource` 与 `domainSources` buckets 的断言）
- [ ] 3.3 更新 smoke casebook 文档示例：`docs/testing/DEVICE_SMOKE_CASEBOOK.md` 中 `policySource=GLOBAL_*` → `policySource=DOMAIN_DEVICE_WIDE_*`

## 4. Spec / Docs Sync

- [ ] 4.1 确认本 change 的 delta specs 覆盖 `domain-policy-observability` 与 `dx-smoke-domain-casebook` 的全部 `GLOBAL_*` 引用（不修改 archived 文档）
- [ ] 4.2 运行 `openspec validate rename-domain-policy-global-to-domain-device-wide --strict` 通过（避免 `#### Scenario` 层级错误导致静默失败）

## 5. Verification

- [ ] 5.1 运行 P0：`cmake --build --preset dev-debug --target snort-host-tests`
- [ ] 5.2 运行 P1：`cmake --build --preset dev-debug --target snort-p1-tests`（覆盖 vNext domain casebook）
- [ ] 5.3 在真机 smoke 路径可用时，运行 P2：`cmake --build --preset dev-debug --target snort-p2-tests`（确保 device smoke 不因枚举改名失配）

