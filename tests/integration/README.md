# Host-driven integration tests

这里是 `P1` / 后续 `P2` 真机测试的主入口目录。

- `P1`：host-driven 真机 baseline integration
- `P2`：真机平台专项 / compatibility / smoke

## 当前入口

- `tests/integration/run.sh`
  - P1 host-driven baseline
  - 支持 `--group` / `--case` / `--skip-deploy` / `--serial`
- `tests/integration/full-smoke.sh`
  - 更完整的真机冒烟回归
- `tests/integration/lib.sh`
  - integration 公共辅助函数

## 相关工具

- `dev/dev-deploy.sh`
  - 推送 + 启动 + 健康检查
- `dev/dev-android-device-lib.sh`
  - ADB / rooted device 公共辅助

## 示例

```bash
# baseline（推荐）
bash tests/integration/run.sh --skip-deploy --group core,config,app,streams

# 指定真机
bash tests/integration/run.sh --serial <serial>

# 先部署再跑
bash dev/dev-deploy.sh
bash tests/integration/run.sh --group core
```

## 边界

- 这里只做测试 / tooling，不推进产品逻辑实现。
- `RESETALL` 等破坏性 case 建议单独运行。
- 真机原生调试、LLDB、tombstone 仍属于 `P3`。
