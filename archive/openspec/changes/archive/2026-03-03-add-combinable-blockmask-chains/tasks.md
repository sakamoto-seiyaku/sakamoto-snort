## 1. Mask 约束与校验
- [x] 1.1 定义“订阅列表 blockMask”的合法集合：`{1,2,4,8,16,32,64}`，且必须为单 bit（power-of-two）。
- [x] 1.2 在 `BLOCKLIST.*.ADD/UPDATE` 路径上校验并拒绝非法 mask（0、多 bit、128 或其他未知 bit）。
- [x] 1.3 在 `DOMAIN.*.ADD.MANY` 路径上同样校验 mask，避免绕过 BlockingList 元数据直接写入非法位。
- [x] 1.4 规范化 app `BLOCKMASK`：当设置的 mask 含 `8` 时，后端必须自动补齐 `1`（reinforced 包含 standard），覆盖 `BLOCKMASK` 与 `BLOCKMASKDEF` 两条设置路径。

## 2. 去除跨 listId 去重
- [x] 2.1 修改 `DomainList::write`：仅对同一 `listId` 做去重，不扫描/依赖其他 listId。
- [x] 2.2 保持 `clear=true` 时的行为一致：内存删除 + 文件 truncate 后再追加写入。

## 3. 文档与帮助
- [x] 3.1 更新 Control `HELP` 中 `BLOCKMASK` 的 mask bits 说明，补充 16/32/64 并说明 128 保留用途。
- [x] 3.2 更新 `docs/INTERFACE_SPECIFICATION.md`：说明 BlockingList/DomainList 的 `blockMask` 单 bit 约束与可用 bit。

## 4. 验证
- [ ] 4.1 手工回归：创建两个不同 listId、不同 bit 的黑名单列表，分别写入相同域名；disable/remove 任意一个不影响另一个仍启用的拦截效果。
- [ ] 4.2 兼容性：不使用新 bit 时，行为与当前版本一致（尤其是 `DOMAIN.*.ADD.MANY` 返回值与 `BLOCKLIST.*` enable/disable 流程）。
- [ ] 4.3 BLOCKMASK 归一化：对某个 app 执行 `BLOCKMASK <app> 8` 后，查询结果应包含 `1|8`（即返回 `9`）。
