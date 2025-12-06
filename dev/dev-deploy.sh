#!/bin/bash

set -e

BINARY=~/sucre-build-output/sucre-snort
TARGET=/data/local/tmp/sucre-snort-dev
LOG=/data/snort/dev.log

echo "=== Sucre-Snort Development Deploy ==="
echo ""

# ============================================================================
# Pre-checks
# ============================================================================

if [ ! -f "$BINARY" ]; then
    echo "❌ 二进制文件不存在: $BINARY"
    echo "运行: bash dev-build.sh"
    exit 1
fi

# ============================================================================
# Stop existing process
# ============================================================================

echo "[1/6] 停止现有进程..."
adb.exe shell su -c "killall sucre-snort 2>/dev/null" || true
sleep 1

# Verify process stopped
if adb.exe shell su -c "pidof sucre-snort" >/dev/null 2>&1; then
    echo "⚠️  进程未能停止，强制终止..."
    adb.exe shell su -c "killall -9 sucre-snort" || true
    sleep 1
fi

# ============================================================================
# Push binary
# ============================================================================

echo "[2/6] 推送二进制文件..."
adb.exe push "$BINARY" "$TARGET" 2>&1 | grep -E "pushed|[0-9]+ KB/s" || true

# ============================================================================
# Set permissions
# ============================================================================

echo "[3/6] 设置权限..."
adb.exe shell su -c "chmod 755 $TARGET"

# ============================================================================
# Clear old log
# ============================================================================

echo "[4/6] 清理旧日志..."
adb.exe shell su -c "mkdir -p /data/snort && echo '' > $LOG"

# ============================================================================
# Start daemon
# ============================================================================

echo "[5/6] 启动守护进程..."
adb.exe shell su -c "cd /data/snort && nohup $TARGET >> $LOG 2>&1 &"

# ============================================================================
# Health check
# ============================================================================

echo "[6/6] 健康检查..."
sleep 2

ERRORS=0

# Check process
echo -n "  进程状态: "
if adb.exe shell su -c "pidof sucre-snort" >/dev/null 2>&1; then
    PID=$(adb.exe shell su -c "pidof sucre-snort" | tr -d '\r\n')
    echo "✓ 运行中 (PID: $PID)"
else
    echo "❌ 未运行"
    ((ERRORS++))
fi

# Check sockets
echo -n "  控制 Socket: "
if adb.exe shell su -c "ls /dev/socket/sucre-snort-control" >/dev/null 2>&1; then
    echo "✓ 已创建"
else
    echo "❌ 未创建"
    ((ERRORS++))
fi

echo -n "  DNS Socket: "
if adb.exe shell su -c "ls /dev/socket/sucre-snort-netd" >/dev/null 2>&1; then
    echo "✓ 已创建"
else
    echo "❌ 未创建"
    ((ERRORS++))
fi

# Check SELinux context
echo -n "  SELinux: "
CONTEXT=$(adb.exe shell su -c "ps -AZ" | grep sucre-snort | awk '{print $1}' | head -1 | tr -d '\r\n')
if [ -n "$CONTEXT" ]; then
    echo "$CONTEXT"
else
    echo "⚠️  无法获取"
fi

# Show log excerpt
echo ""
echo "=== 最近日志 (最后10行) ==="
adb.exe shell su -c "tail -10 $LOG" 2>/dev/null || echo "日志为空或无法读取"

# ============================================================================
# Summary
# ============================================================================

echo ""
if [ $ERRORS -eq 0 ]; then
    echo "✅ 部署成功"
else
    echo "⚠️  部署完成但有 $ERRORS 个检查失败"
fi

echo ""
echo "=== 快速命令 ==="
echo "实时日志:    adb.exe shell su -c \"tail -f $LOG\""
echo "进程状态:    adb.exe shell su -c \"ps -AZ | grep sucre\""
echo "Socket状态:  adb.exe shell su -c \"ls -lZ /dev/socket/sucre*\""
echo "诊断工具:    bash dev-diagnose.sh"
echo ""
