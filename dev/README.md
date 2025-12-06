# Sucre-Snort 开发环境

## 目录结构

```
sucre/
├── scripts/
│   └── dev/
│       ├── dev-build.sh       # 增量编译
│       ├── dev-deploy.sh      # 推送 + 启动 + 健康检查
│       ├── dev-diagnose.sh    # 诊断工具
│       └── README.md
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

# 安装并重启
adb.exe shell su -c "ksud module install /sdcard/Download/sucre-debug-base-*.zip && reboot"
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

# 增量编译 (2-5 分钟)
bash dev-build.sh

# 强制重新编译（如果缓存未更新）
bash dev-build.sh --clean
```

**验证**:
- 脚本自动检查二进制时间戳
- 如果源码未修改，会警告使用缓存版本
- 强制重新编译使用 `--clean` 参数

#### 3. 部署

```bash
bash dev-deploy.sh
```

**执行步骤**:
1. 停止现有进程（包含强制终止）
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
7. 依赖检查（libnetd_resolv, APP）
8. iptables 规则
9. 操作建议（根据检查结果）

#### 常用命令

```bash
# 实时日志
adb.exe shell su -c "tail -f /data/snort/dev.log"

# 进程状态
adb.exe shell su -c "ps -AZ | grep sucre"

# Socket 状态
adb.exe shell su -c "ls -lZ /dev/socket/sucre*"

# 查看完整日志
adb.exe shell su -c "cat /data/snort/dev.log"

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
- **日志隔离**: `/data/snort/dev.log` vs `/data/snort/sucre-snort.log`

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
adb.exe shell su -c "cat /data/snort/dev.log"

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
```

### 依赖缺失

**症状**: libnetd_resolv.so 未挂载或 APP 未安装

**解决**: 重新刷入调试基础模块（见"首次设置"）

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
dev-build.sh (2-5分钟)   │
    ↓                    │
dev-deploy.sh (10秒)     │
    ↓                    │
调试测试 ─────────────────┘
```

---

**最后更新**: 2025-11-22
**环境**: Android 16, KSU Next, Pixel 6a
