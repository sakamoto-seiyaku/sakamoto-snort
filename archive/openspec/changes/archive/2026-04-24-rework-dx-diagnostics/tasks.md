> 执行约束：本文件用于追踪 `rework-dx-diagnostics` 的实现范围与完成度。本 change **不包含归档 change 的归档操作**（不做 openspec archive）；但实现内容本身包含“真机测试脚本的物理目录迁移（archive/migration-source 的物理搬迁）”。

## 1. DX diagnostics 主入口组（CTest/VS Code Testing）

- [x] 1.1 新增 `tests/device/diagnostics/dx-diagnostics.sh`：diagnostics 总入口（当前只顺序调用 perf-network-load；保留扩展点）
- [x] 1.2 新增 `tests/device/diagnostics/dx-diagnostics-perf-network-load.sh`：作为 `dx-diagnostics-perf-network-load` 的实现脚本
- [x] 1.3 更新 `tests/integration/CMakeLists.txt`：注册 `dx-diagnostics` 与 `dx-diagnostics-perf-network-load` 两个 tests + labels + skip/bocked 规则
- [x] 1.4 移除旧 `perf-network-load` 的 `CTest` 入口名（确保 `ctest -N` 不再可见）

## 2. perf-network-load 迁移为 vNext-only

- [x] 2.1 将 legacy `tests/integration/perf-network-load.sh` 迁移到新位置并改为 vNext-only（`60607 + sucre-snort-ctl`）；旧路径不保留兼容 wrapper
- [x] 2.2 用 vNext 命令替代 legacy latency/metrics 命令：
  - `PERFMETRICS` -> `CONFIG.SET(scope=device, perfmetrics.enabled)`
  - `METRICS.PERF` -> `METRICS.GET(name=perf)`
  - `METRICS.PERF.RESET` -> `METRICS.RESET(name=perf)`
- [x] 2.3 调整 JSON 断言路径为 vNext envelope（`result.perf.*`），并保留离线/URL 不可达的显式 `SKIP` 语义
- [x] 2.4 保持 `BLOCKED` 语义一致：ADB/真机/root/vNext forward/HELLO 不满足时 `exit 77` 且输出 `BLOCKED: ...`

## 3. 目录归位：IP 真机测试模组搬迁到最终位置（一步到位）

- [x] 3.1 物理迁移目录：`tests/device-modules/ip/` -> `tests/device/ip/`（包含 cases/tools/records/.gitignore 等）
- [x] 3.2 同步更新 `dx-smoke-datapath` wrapper：改为调用新路径的 IP 模组 active smoke（`tests/device/ip/run.sh --profile smoke`）
- [x] 3.3 全仓库更新引用路径（脚本/文档/CMake），确保不再引用 `tests/device-modules/ip/`
- [x] 3.4 清理空目录：若 `tests/device-modules/` 迁移后为空，则删除该目录

## 4. IP 模组：抽取 vNext helper + runner 基线收敛

- [x] 4.1 在 `tests/device/ip/` 引入共享 vNext helper（例如 `vnext_lib.sh`），封装 `find_snort_ctl/ctl_cmd` 与 vNext envelope JSON 取值
- [x] 4.2 修改 `tests/device/ip/run.sh`：`perf/matrix/stress/longrun` profiles 在 preflight 阶段确保 vNext forward（与 `smoke` 一致），并统一 BLOCKED=77
- [x] 4.3 将 `tests/device/ip/lib.sh` 中的 `iptest_reset_baseline` 从 legacy 命令切换到 vNext（`RESETALL + CONFIG.SET(device/app) + METRICS.RESET`）
- [x] 4.4 统一 app selector/UID 策略：在 runner 层确定 `IPTEST_APP_UID`（优先 `com.android.shell`，必要时用 `APPS.LIST` 回退），避免 case 内写死 UID

## 5. IP 模组：matrix 覆盖迁移为 vNext-only

- [x] 5.1 迁移 `tests/device/ip/cases/00_env.sh`：改为 vNext preflight（vNext forward + `HELLO`）与 Tier-1 prereqs 检查
- [x] 5.2 迁移 `tests/device/ip/cases/20_matrix_l3l4.sh`：用 `IPRULES.APPLY + IPRULES.PRINT + METRICS.GET/RESET(name=reasons) + IFACES.LIST + STREAM.START(type=pkt)` 替代 legacy 命令
- [x] 5.3 迁移 `tests/device/ip/cases/22_conntrack_ct.sh`：改为 vNext-only（规则通过 `ct.state/ct.direction` 字段表达）
- [x] 5.4 迁移 `tests/device/ip/cases/40_iface_block.sh`：用 `CONFIG.SET(app, block.ifaceKindMask)` 表达 IFACE_BLOCK；移除 legacy-only HOSTS cache 断言（无 vNext 等价）

## 6. IP 模组：stress/perf/longrun 覆盖迁移为 vNext-only

- [x] 6.1 迁移 `tests/device/ip/cases/50_stress.sh`：将控制面 churn/断言切换到 vNext（`RESETALL/CONFIG/METRICS/STREAM`）
- [x] 6.2 迁移 `tests/device/ip/cases/60_perf.sh`：perfmetrics toggle 与 perf metrics 采样改为 vNext（`CONFIG + METRICS.GET/RESET(name=perf)`）；ruleset 安装改为 `IPRULES.APPLY`
- [x] 6.3 迁移 `tests/device/ip/cases/62_perf_ct_compare.sh`：改为 vNext-only（ct consumer rule 通过 vNext IPRULES surface 安装）
- [x] 6.4 迁移 `tests/device/ip/cases/70_longrun.sh`：改为 vNext-only；保持 records 产物仍写入 `records/`（不进 git）

## 7. legacy-only 覆盖的归档/迁移源处置 + 文档同步

- [x] 7.1 将 `tests/device/ip/cases/30_ip_leak.sh` 移出 active profiles（冻结项无 vNext surface），并物理迁移到 `tests/archive/device/`（仅回查，不进入默认入口）
- [x] 7.2 更新 `docs/testing/DEVICE_TEST_REORGANIZATION_CHARTER.md`：补齐 diagnostics 主入口名、目录归位结论、迁移源/归档规则与总表
- [x] 7.3 更新 `docs/testing/README.md` 与 `tests/integration/README.md`：新增 `dx-diagnostics*` 的运行方式与定位
- [x] 7.4 更新 `docs/testing/ip/IP_TEST_MODULE.md`：入口路径切换为 `tests/device/ip/run.sh`；并明确 diagnostics profiles 已 vNext-only
- [x] 7.5 更新 `docs/IMPLEMENTATION_ROADMAP.md`：补记 diagnostics 重组 change 的状态与边界（与 `rework-dx-smoke` 对齐）
- [x] 7.6 更新 `dev/dev-diagnose.sh`：建议命令更新为 `dx-smoke*` / `dx-diagnostics*`，并优先诊断 vNext control socket

## 8. 验证

- [x] 8.1 `bash -n` 覆盖新增/修改的 diagnostics 与 IP 模组 shell 脚本
- [x] 8.2 `ctest -N -R '^dx-diagnostics'` 验证可发现性（且旧 `perf-network-load` 不再可见）
- [x] 8.3 在至少一台 rooted 真机上验证：
  - `ctest --output-on-failure -R ^dx-diagnostics-perf-network-load$`（PASS 或明确 SKIP）
  - `bash tests/device/ip/run.sh --profile matrix`（PASS 或明确 BLOCKED/SKIP）
  - `bash tests/device/ip/run.sh --profile perf`（PASS 或明确 BLOCKED/SKIP）
