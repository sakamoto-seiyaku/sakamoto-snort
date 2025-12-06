#!/bin/bash

# Sucre-Snort Development Diagnostics Tool
# 快速诊断守护进程启动和运行状态

set -e

# Derive paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUCRE_TOOLKIT="${SUCRE_TOOLKIT:-}"

LOG=/data/snort/dev.log
PROD_LOG=/data/snort/sucre-snort.log

echo "╔═══════════════════════════════════════╗"
echo "║ Sucre-Snort 开发环境诊断工具         ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# ============================================================================
# 1. 设备连接状态
# ============================================================================

echo "【1. 设备连接】"
if adb.exe devices | tr -d '\r' | grep -q "device$"; then
    DEVICE=$(adb.exe devices | tr -d '\r' | grep "device$" | awk '{print $1}')
    echo "✓ 设备已连接: $DEVICE"
else
    echo "❌ 未检测到设备"
    exit 1
fi
echo ""

# ============================================================================
# 2. 进程状态
# ============================================================================

echo "【2. 进程状态】"

# Development daemon
echo "开发进程 (/data/local/tmp/sucre-snort-dev):"
if adb.exe shell su -c "pidof sucre-snort" >/dev/null 2>&1; then
    adb.exe shell su -c "ps -AZ | grep sucre-snort" | while IFS= read -r line; do
        echo "  $line"
    done
else
    echo "  ❌ 未运行"
fi

# Production daemon (if exists)
if adb.exe shell su -c "ls /system/system_ext/bin/sucre-snort" >/dev/null 2>&1; then
    echo ""
    echo "生产进程 (/system/system_ext/bin/sucre-snort):"
    PROD_PID=$(adb.exe shell su -c "pgrep -f /system/system_ext/bin/sucre-snort" 2>/dev/null || echo "")
    if [ -n "$PROD_PID" ]; then
        echo "  ⚠️  检测到生产进程运行 (PID: $PROD_PID)"
        echo "  建议: 卸载生产模块以避免冲突"
    else
        echo "  ✓ 未运行 (无冲突)"
    fi
fi
echo ""

# ============================================================================
# 3. Socket 状态
# ============================================================================

echo "【3. Socket 状态】"
SOCKETS=$(adb.exe shell su -c "ls -lZ /dev/socket/ 2>/dev/null | grep sucre" || echo "")
if [ -n "$SOCKETS" ]; then
    echo "$SOCKETS"
else
    echo "  ❌ 未创建 socket"
fi
echo ""

# ============================================================================
# 4. 二进制文件
# ============================================================================

echo "【4. 二进制文件】"

# Dev binary
echo "开发二进制:"
if adb.exe shell su -c "ls -l /data/local/tmp/sucre-snort-dev" >/dev/null 2>&1; then
    DEV_INFO=$(adb.exe shell su -c "ls -lh /data/local/tmp/sucre-snort-dev" | tr -d '\r')
    echo "  $DEV_INFO"
else
    echo "  ❌ 不存在"
fi

# Prod binary (if exists)
if adb.exe shell su -c "ls /system/system_ext/bin/sucre-snort" >/dev/null 2>&1; then
    echo ""
    echo "生产二进制:"
    PROD_INFO=$(adb.exe shell su -c "ls -lh /system/system_ext/bin/sucre-snort" | tr -d '\r')
    echo "  $PROD_INFO"
fi
echo ""

# ============================================================================
# 5. SELinux 状态
# ============================================================================

echo "【5. SELinux 状态】"
SELINUX=$(adb.exe shell su -c "getenforce" | tr -d '\r\n')
echo "模式: $SELINUX"

echo ""
echo "最近 SELinux 拒绝 (sucre 相关):"
DENIALS=$(adb.exe shell su -c "logcat -d -s 'AVC' 2>/dev/null | grep -i sucre | tail -5" || echo "")
if [ -n "$DENIALS" ]; then
    echo "$DENIALS"
else
    echo "  ✓ 无相关拒绝记录"
fi
echo ""

# ============================================================================
# 6. 日志分析
# ============================================================================

echo "【6. 日志分析】"

echo "开发日志 ($LOG):"
if adb.exe shell su -c "test -f $LOG" 2>/dev/null; then
    LOG_SIZE=$(adb.exe shell su -c "wc -c < $LOG" | tr -d '\r\n')
    LOG_LINES=$(adb.exe shell su -c "wc -l < $LOG" | tr -d '\r\n')
    echo "  大小: $LOG_SIZE bytes, 行数: $LOG_LINES"

    echo ""
    echo "  最后 20 行:"
    adb.exe shell su -c "tail -20 $LOG" | sed 's/^/    /'

    echo ""
    echo "  错误/警告:"
    ERRORS=$(adb.exe shell su -c "grep -iE 'error|fail|fatal|exception' $LOG | tail -5" || echo "")
    if [ -n "$ERRORS" ]; then
        echo "$ERRORS" | sed 's/^/    /'
    else
        echo "    ✓ 无明显错误"
    fi
else
    echo "  ❌ 日志文件不存在"
fi
echo ""

# ============================================================================
# 7. 依赖检查
# ============================================================================

echo "【7. 依赖检查】"

# libnetd_resolv.so
echo "libnetd_resolv.so:"
RESOLV_MOUNTED=$(adb.exe shell su -c "mount | grep libnetd_resolv.so" || echo "")
if [ -n "$RESOLV_MOUNTED" ]; then
    echo "  ✓ 已挂载"
    echo "$RESOLV_MOUNTED" | sed 's/^/    /'
else
    echo "  ❌ 未挂载 (需要调试基础模块)"
fi

echo ""
echo "Sucre APP:"
APP_INSTALLED=$(adb.exe shell su -c "pm list packages | grep -i sucre" || echo "")
if [ -n "$APP_INSTALLED" ]; then
    echo "  ✓ 已安装"
    echo "  $APP_INSTALLED"
else
    echo "  ❌ 未安装 (需要调试基础模块)"
fi
echo ""

# ============================================================================
# 8. 网络/防火墙状态
# ============================================================================

echo "【8. 网络/防火墙】"
echo "iptables 规则 (sucre 相关):"
IPTABLES=$(adb.exe shell su -c "iptables -L -n 2>/dev/null | grep -i sucre" || echo "")
if [ -n "$IPTABLES" ]; then
    echo "$IPTABLES" | sed 's/^/  /'
else
    echo "  ⚠️  无相关规则 (守护进程可能未初始化防火墙)"
fi
echo ""

# ============================================================================
# 9. 快速操作建议
# ============================================================================

echo "╔═══════════════════════════════════════╗"
echo "║ 快速操作                             ║"
echo "╚═══════════════════════════════════════╝"
echo ""

# 根据检查结果给出建议
if ! adb.exe shell su -c "pidof sucre-snort" >/dev/null 2>&1; then
    echo "⚠️  守护进程未运行"
    echo ""
    echo "排查步骤:"
    echo "  1. 检查编译是否成功: ls -lh ~/sucre-build-output/sucre-snort"
    echo "  2. 重新部署: bash dev-deploy.sh"
    echo "  3. 查看完整日志: adb.exe shell su -c \"cat $LOG\""
    echo "  4. 手动启动测试: adb.exe shell su -c \"/data/local/tmp/sucre-snort-dev\""
    echo ""
fi

if [ -z "$RESOLV_MOUNTED" ]; then
    echo "⚠️  libnetd_resolv.so 未挂载"
    echo ""
    echo "需要刷入调试基础模块:"
    if [ -n "$SUCRE_TOOLKIT" ]; then
        echo "  cd $SUCRE_TOOLKIT/scripts"
    else
        echo "  cd <sucre-android16-toolkit>/scripts"
        echo "  # 或设置环境变量: export SUCRE_TOOLKIT=/path/to/sucre-android16-toolkit"
    fi
    echo "  bash build-debug-base.sh"
    echo "  adb.exe push ../output/sucre-debug-base-*.zip /sdcard/Download/"
    echo "  adb.exe shell su -c \"ksud module install /sdcard/Download/sucre-debug-base-*.zip && reboot\""
    echo ""
fi

echo "常用命令:"
echo "  实时日志: adb.exe shell su -c \"tail -f $LOG\""
echo "  重启守护进程: bash dev-deploy.sh"
echo "  重新编译: bash dev-build.sh"
echo "  查看完整日志: adb.exe shell su -c \"cat $LOG | less\""
echo ""
