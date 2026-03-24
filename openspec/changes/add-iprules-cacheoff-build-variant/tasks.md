## 0. OpenSpec docs
- [ ] 0.1 写清 `proposal.md` / `tasks.md` /（可选）`design.md`
- [ ] 0.2 增加 capability spec delta：`specs/app-ip-l3l4-rules/spec.md`
- [ ] 0.3 `openspec validate add-iprules-cacheoff-build-variant --strict` 通过

## 1. Build variants (Soong + dev workflow)
- [ ] 1.1 `Android.bp` 新增一个 DEV-only 的 cache-off `cc_binary`（例如 module 名 `sucre-snort-iprules-nocache`）
- [ ] 1.2 `dev/dev-build.sh` 默认同时构建 `sucre-snort` 与 cache-off 变体，并把两份产物导出到 `build-output/`
- [ ] 1.3 `dev/dev-deploy.sh` 支持选择部署哪份二进制（例如 `--variant iprules-nocache` 或 `--binary <path>`）

## 2. Engine behavior (IP only; no hot-path overhead in default binary)
- [ ] 2.1 `IpRulesEngine::evaluate()` 的决策缓存用编译期宏控制（cache-off 变体直接 bypass；cache-on 产物保持当前实现，不新增 per-packet 分支）
- [ ] 2.2 复核两份二进制的判决语义一致（缓存仅影响性能，不影响 `Decision.kind/ruleId`）

## 3. Tests
- [ ] 3.1 新增/更新单元测试：cache-off 编译宏启用时仍能正确 evaluate（不依赖 cache）
- [ ] 3.2 新增/更新单元测试：cache-on 与 cache-off 语义一致（同一组规则与同一个 `PacketKeyV4`）

## 4. Real-device module (optional wiring)
- [ ] 4.1 `docs/testing/ip/IP_TEST_MODULE.md` 记录何时使用 cache-off 变体（诊断）与默认 baseline（cache-on）的区别
