> 状态对齐（2026-03-25）：
> - 本 change 是一个**延后执行的 backlog**：把“当前不适合立刻做”的验证/文档/真机长跑任务收敛到同一处追踪。
> - 触发时机：完成域名相关主线改动、并进入 “DomainPolicy 与 IP 融合/收尾” 阶段后，再集中回头跑完本清单。

## 0. Rollup bookkeeping
- [x] Archive `add-combinable-blockmask-chains` and promote its spec into `openspec/specs/`.
- [x] Archive `add-multi-user-support` and promote its spec into `openspec/specs/`.

## 1. Blockmask chains — remaining verification (from `add-combinable-blockmask-chains`)
- [ ] 1.1 手工回归：创建两个不同 listId、不同 bit 的黑名单列表，分别写入相同域名；disable/remove 任意一个不影响另一个仍启用的拦截效果。
- [ ] 1.2 兼容性：不使用新 bit 时，行为与当前版本一致（尤其是 `DOMAIN.*.ADD.MANY` 返回值与 `BLOCKLIST.*` enable/disable 流程）。
- [ ] 1.3 BLOCKMASK 归一化：对某个 app 执行 `BLOCKMASK <app> 8` 后，查询结果应包含 `1|8`（即返回 `9`）。

## 2. Multi-user support — remaining verification/docs (from `add-multi-user-support`)
- [ ] 2.1 单用户回归验证：在单用户设备上执行已有后端冒烟用例（HELLO/HELP/APP 查询/统计、DNS/PKT/ACTIVITY 流、RESETALL 等），确认输出与当前版本一致或仅在新增字段层面变化。
- [ ] 2.2 多用户场景验证：在存在多个 Android 用户的设备上，准备典型场景（同一包在不同用户下安装、不同用户下自定义黑白名单与 TRACK 设置），验证控制命令和流事件中 `uid/userId` 区分正确。
- [ ] 2.3 文档更新：在 `docs/archived/SNORT_MULTI_USER_REFACTOR.md` 中标记已实现部分，并根据最终实现细节更新或补充测试用例；确保 OpenSpec spec 与该设计文档保持一致。
- [ ] 2.4 阶段性验证用例补全：将多用户安装聚合相关用例沉淀到 `tests/integration/full-smoke.sh` 或等价文档用例集中（覆盖 user0/user10 安装、卸载、原子替换等场景）。

## 3. IP test module — deferred Tier-1 longrun/CI hook (from `add-ip-test-component`)
- [ ] 3.1 Tier-1 longrun 用例：新增 `tests/device-modules/ip/cases/70_longrun.sh`（veth+netns；控制面 churn + 真实流量并发；周期性健康断言；proc snapshot delta record-first）
- [ ] 3.2 文档补齐：在 `docs/testing/ip/IP_TEST_MODULE.md` 增加 `--profile longrun` 运行说明与产物口径
- [ ] 3.3 （可选）轻量 `ip-smoke` 入口接入现有 CTest/CI（从 `add-ip-test-component` 的 optional task 迁入）

## 4. Repo-wide docs sync
- [x] 4.1 Update `openspec/specs/*/spec.md` generated `Purpose` stubs to real descriptions.
- [x] 4.2 Update `openspec/project.md` to reflect current multi-user/blockmask-chains reality (remove stale “single-user only” statements).
