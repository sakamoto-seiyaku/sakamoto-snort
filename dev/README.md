# Sucre-Snort 开发环境

## 目录结构

```
sucre/
├── scripts/
│   └── dev/
│       ├── dev-build.sh               # 增量编译
│       ├── dev-deploy.sh              # 推送 + 启动 + 健康检查
│       ├── dev-integration-tests.sh   # 兼容 wrapper → tests/integration/run.sh
│       ├── dev-device-smoke.sh        # 兼容 wrapper → tests/integration/device-smoke.sh
│       ├── dev-netd-resolv.sh         # 开发态推送/挂载 libnetd_resolv.so
│       ├── dev-diagnose.sh            # 诊断工具
│       ├── dev-android-device-lib.sh  # 真机/ADB 公共辅助
│       ├── dev-native-debug.sh        # P3 LLDB / VS Code 调试入口
│       ├── dev-tombstone.sh           # P3 tombstone / stack 符号化入口
│       └── README.md
├── tests/
│   ├── host/                          # P0 host-side gtest
│   └── integration/
│       ├── run.sh                     # P1 host-driven baseline 入口
│       ├── device-smoke.sh            # P2 rooted 真机平台 smoke 入口
│       ├── full-smoke.sh              # 更广的控制协议冒烟回归
│       └── lib.sh                     # integration 公共辅助
├── sucre-snort/               # 软链接 → ~/android/lineage/system/sucre-snort
├── sucre-android16-toolkit/   # 模块打包工具
│   └── scripts/
│       └── build-debug-base.sh  # 调试基础模块构建
└── sucre-build-output/        # 编译产物 (~/sucre-build-output/)
    └── sucre-snort            # 最新二进制
```

## 完整开发流程

### 首次设置（一次性）

#### 1. 构建调试基础模块

```bash
cd /home/js/Git/sucre/sucre-android16-toolkit/scripts
bash build-debug-base.sh
```

**产物**: `output/sucre-debug-base-{timestamp}.zip`

**包含**:
- libnetd_resolv.so (DNS 补丁)
- sucre.apk (控制 APP)
- SELinux 权限配置

**不包含**:
- sucre-snort 守护进程（手动推送）
- service.sh / init.rc（手动启动）

#### 2. 刷入调试基础模块

```bash
# 推送模块
adb.exe push output/sucre-debug-base-*.zip /sdcard/Download/

# 然后在 APatch / KernelSU Manager 中手动安装该 zip，并重启
```

**效果**: 设备重启后，依赖项（DNS 补丁、APP）已就位，无守护进程自动启动。

---

### 日常开发循环

#### 1. 修改代码

```bash
cd /home/js/Git/sucre/sucre-snort/src
vim Control.cpp  # 修改任意源文件
```

#### 2. 编译

```bash
cd /home/js/Git/sucre/scripts/dev

# 默认优先复用现有 combined ninja 图（WSL2 下最快）
bash dev-build.sh

# 强制重新编译（清掉 sucre-snort 相关中间产物）
bash dev-build.sh --clean

# 当 Android.bp / Soong 图发生变化时，强制重新生成 build graph
bash dev-build.sh --regen-graph
```

**验证**:
- 脚本自动检查二进制时间戳
- 默认优先走 direct-ninja，只编 `sucre-snort` 目标，避免 WSL2 下 Soong graph 生成带来的高内存换页
- 如果源码未修改，会警告使用缓存版本
- `--clean` 用于清掉 `sucre-snort` 中间产物；`--regen-graph` 用于 Android.bp / Soong 图变化场景

#### 3. 部署

```bash
bash dev-deploy.sh
```

**执行步骤**:
1. 优先通过 `DEV.SHUTDOWN` 请求守护进程保存后退出，必要时再强制终止
2. 推送二进制 → `/data/local/tmp/sucre-snort-dev`
3. 设置权限 (0755)
4. 清理旧日志
5. 启动守护进程
6. **健康检查**:
   - 进程状态 (PID)
   - 控制 Socket (`/dev/socket/sucre-snort-control`)
   - DNS Socket (`/dev/socket/sucre-snort-netd`)
   - SELinux 上下文
   - 最近日志 (10 行)

**结果**: 显示成功/失败状态 + 快速命令

#### 3.5 快速准备 netd / SELinux（开发态，无需刷模块）

```bash
# 推送并临时挂载 libnetd_resolv.so，同时切到 permissive
bash dev/dev-netd-resolv.sh prepare

# 只查看状态
bash dev/dev-netd-resolv.sh status

# 仅切换 SELinux
bash dev/dev-netd-resolv.sh permissive on
bash dev/dev-netd-resolv.sh permissive off
```

**适用场景**:
- 当前目标只是快速做真机联调 / 冒烟 / 集成验证
- 不想每次都重新生成并刷入完整模块
- 设备当前使用 APatch，且允许通过 `nsenter + busybox mount` 做开发态临时挂载

**说明**:
- 该脚本会把本地 `libnetd_resolv.so` 推到 `/data/local/tmp/`，再临时挂到 resolver APEX
- 该挂载是**开发态临时状态**，重启后需要重新执行
- 若只是为了跑 `P2`，优先走这条路；完整模块只作为更重的兜底方案

#### 4. 真机测试（P1 / P2）

```bash
# P1 baseline
bash tests/integration/run.sh

# P2 rooted 真机平台 smoke
bash tests/integration/device-smoke.sh
```

**特点**:
- 两条测试 lane 都运行在 host / WSL，由 host 驱动 Android 真机执行验证
- `P1` 只聚焦守护进程生命周期、控制面基线、stream 健康检查与 `RESETALL` 基线语义
- `P2` 聚焦 rooted 真机上的 socket、`netd` 前置、`iptables` / `ip6tables` / `NFQUEUE`、SELinux / AVC 与 lifecycle restart smoke
- 支持按 group / case 选择测试
- 支持通过 `--serial` 绑定指定真机

**常用示例**:

```bash
# 全量 P1 baseline
bash tests/integration/run.sh

# 只跑 P1 streams / reset
bash tests/integration/run.sh --group streams,reset

# 全量 P2 rooted 真机平台 smoke
bash tests/integration/device-smoke.sh --serial <serial>

# 只跑 P2 firewall / selinux
bash tests/integration/device-smoke.sh --skip-deploy --group firewall,selinux

# 只跑 P2 lifecycle case
bash tests/integration/device-smoke.sh --case P2-09
```

---

### 调试与排查

#### 诊断工具

```bash
bash dev-diagnose.sh
```

**检查项**:
1. 设备连接
2. 进程状态（开发 vs 生产冲突）
3. Socket 状态
4. 二进制文件信息
5. SELinux 状态和拒绝记录
6. 日志分析（错误/警告）

#### 真机原生调试（P3）

```bash
# attach 到当前 dev daemon
bash dev-native-debug.sh attach

# 以 LLDB 方式直接启动真机上的 dev binary
bash dev-native-debug.sh run

# 为 VS Code + CodeLLDB 生成连接准备
bash dev-native-debug.sh vscode-attach
```

#### tombstone / 符号化

```bash
# 查看最新 tombstone
bash dev-tombstone.sh latest

# 拉取最新 tombstone
bash dev-tombstone.sh pull

# 对 tombstone 做 stack 符号化
bash dev-tombstone.sh symbolize --path build-output/tombstones/tombstone_xx
```
7. 依赖检查（libnetd_resolv, APP）
8. iptables 规则
9. 操作建议（根据检查结果）

#### 常用命令

```bash
# 实时日志
adb.exe shell su -c "tail -f /data/local/tmp/sucre-snort-dev.log"

# 进程状态
adb.exe shell su -c "ps -AZ | grep sucre"

# Socket 状态
adb.exe shell su -c "ls -lZ /dev/socket/sucre*"

# 查看完整日志
adb.exe shell su -c "cat /data/local/tmp/sucre-snort-dev.log"

# SELinux 拒绝
adb.exe shell su -c "logcat -d -s AVC | grep sucre"

# 手动启动测试（调试启动失败）
adb.exe shell su -c "/data/local/tmp/sucre-snort-dev"
```

---

## 注意事项

### 环境隔离

- **调试环境**: `/data/local/tmp/sucre-snort-dev` (手动启动)
- **生产环境**: `/system/system_ext/bin/sucre-snort` (init.rc 启动)
- **日志隔离**: `/data/local/tmp/sucre-snort-dev.log` vs 生产环境自身日志路径

### 避免冲突

如果检测到生产模块，诊断工具会警告。建议：
1. 卸载生产模块
2. 刷入调试基础模块
3. 使用开发循环

### 重启后

- 调试基础模块保持激活（依赖项存在）
- 守护进程**不会**自动启动
- 重新运行 `bash dev-deploy.sh` 启动守护进程

---

## 故障排查

### 守护进程无法启动

```bash
# 1. 诊断
bash dev-diagnose.sh

# 2. 检查日志
adb.exe shell su -c "cat /data/local/tmp/sucre-snort-dev.log"

# 3. 手动启动查看错误
adb.exe shell su -c "/data/local/tmp/sucre-snort-dev"

# 4. 检查 SELinux 拒绝
adb.exe shell su -c "logcat -d -s AVC | grep sucre"
```

### Socket 未创建

**原因**: 守护进程启动失败或 fallback 机制未触发

**排查**:
1. 确认守护进程运行中
2. 检查日志中 "socket" 相关错误
3. 验证 `/dev/socket/` 权限

### 编译后二进制未更新

**症状**: `dev-build.sh` 显示 "WARNING: Binary timestamp not updated"

**解决**:
```bash
bash dev-build.sh --clean

# 如果是 Android.bp / Soong graph 变化导致的缓存不一致
bash dev-build.sh --regen-graph
```

### 依赖缺失

**症状**: libnetd_resolv.so 未挂载或 APP 未安装

**优先解决（开发态）**:
```bash
bash dev/dev-netd-resolv.sh prepare
```

**若仍不满足**: 再回退到完整调试基础模块方案（见"首次设置"）

---

## 开发循环示意图

```
[首次设置]
    ↓
build-debug-base.sh → 刷入设备 → 重启
    ↓
[开发循环] ←─────────────┐
    ↓                    │
修改代码                 │
    ↓                    │
dev-build.sh（默认 direct-ninja） │
    ↓                    │
dev-deploy.sh (10秒)     │
    ↓                    │
调试测试 ─────────────────┘
```

---

**最后更新**: 2026-03-14
**环境**: Android 16, APatch（当前开发机型）, Pixel 6a
